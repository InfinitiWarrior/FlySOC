//! One fly brain on the GPU.

use wgpu::util::DeviceExt;

pub const CLASSES: [&str; 11] = [
    "optic", "central", "sensory", "visual_projection", "ascending", "descending",
    "sensory_ascending", "visual_centrifugal", "motor", "endocrine", "unknown",
];
pub const STEPS_PER_MS: u32 = 10;
const CLOCK_START: u32 = 1000; // `last == 0` means never fired; start well past DELAY/REF
const RING: usize = 19; // must match sim.wgsl
const FIX: f32 = 16.0; // must match sim.wgsl
/// Most 1 ms bins of telemetry input uploaded at once, and most neurons to fire in them.
pub const BATCH_BINS: usize = 5;
pub const KICK_CAP: usize = 1 << 21;
/// Adaptation the whole brain needs to not lock up (mV per spike). The circuits run without.
pub const BRAIN_ADAPT: f32 = 10.0;

/// Per-neuron data the host keeps, as written by tools/convert.py.
pub struct Fly {
    pub n: u32,
    pub pos: Vec<f32>,
    pub class: Vec<u32>,
    pub cell_class: Vec<u32>,
    pub cell_type: Vec<u32>,
    pub names: Names,
}

/// fly.json, written next to fly.bin.
#[derive(serde::Deserialize, Default, Clone)]
pub struct Names {
    pub cell_class: Vec<String>,
    pub cell_type: Vec<String>,
}

/// Outgoing connections. Only the GPU needs them, so they are handed to `Sim::new` and dropped.
pub struct Synapses {
    pub row_ptr: Vec<u32>,
    /// post (low POST_BITS bits) | signed synapse count << POST_BITS
    pub syn: Vec<u32>,
}

/// Bits of a packed synapse that hold the target neuron: up to 2^19 = 524,288 neurons in one
/// simulation (56 circuits of 9,262). The other 13 hold the signed count; FlyWire's largest is 2405.
pub const POST_BITS: u32 = 19;
pub const POST: u32 = (1 << POST_BITS) - 1;

/// Learnable connections, kept apart from the packed fixed ones.
#[derive(Default, Clone)]
pub struct Plastic {
    pub row_ptr: Vec<u32>, // rows = presynaptic neuron
    pub pre: Vec<u32>,
    pub post: Vec<u32>,
    pub w: Vec<f32>, // in synapses
}

impl Plastic {
    /// `k` disjoint copies for a simulation of `k` circuits of `n` neurons each.
    pub fn replicate(&self, k: usize, n: u32) -> Self {
        let m = self.post.len() as u32;
        let shift = |v: &[u32], by: u32| v.iter().map(|x| x + by).collect::<Vec<_>>();
        let mut row_ptr = vec![0];
        (0..k as u32).for_each(|f| row_ptr.extend(shift(&self.row_ptr[1..], f * m)));
        Plastic {
            row_ptr,
            pre: (0..k as u32).flat_map(|f| shift(&self.pre, f * n)).collect(),
            post: (0..k as u32).flat_map(|f| shift(&self.post, f * n)).collect(),
            w: self.w.repeat(k),
        }
    }
}

impl Synapses {
    /// `k` disjoint copies: one simulation holding `k` independent circuits, fly f being
    /// neurons f*n .. (f+1)*n.
    pub fn replicate(&self, k: usize) -> Self {
        let (n, m) = (self.row_ptr.len() as u32 - 1, self.syn.len() as u32);
        assert!(k as u32 * n <= 1 << POST_BITS, "{k} copies of {n} neurons: packed post ids have {POST_BITS} bits");
        let mut row_ptr = vec![0];
        let mut syn = Vec::with_capacity(k * m as usize);
        for f in 0..k as u32 {
            row_ptr.extend(self.row_ptr[1..].iter().map(|r| r + f * m));
            syn.extend(self.syn.iter().map(|s| s + f * n)); // post is the low bits; no carry, checked above
        }
        Synapses { row_ptr, syn }
    }

    /// Moves the connections where `plastic(pre, post)` is true into a `Plastic` set.
    pub fn split(self, plastic: impl Fn(u32, u32) -> bool) -> (Synapses, Plastic) {
        let n = self.row_ptr.len() - 1;
        let (mut fixed, mut p) = (Synapses { row_ptr: vec![0], syn: Vec::new() }, Plastic::default());
        p.row_ptr.push(0);
        for i in 0..n {
            for &s in &self.syn[self.row_ptr[i] as usize..self.row_ptr[i + 1] as usize] {
                if plastic(i as u32, s & POST) {
                    p.pre.push(i as u32);
                    p.post.push(s & POST);
                    p.w.push((s as i32 >> POST_BITS) as f32);
                } else {
                    fixed.syn.push(s);
                }
            }
            fixed.row_ptr.push(fixed.syn.len() as u32);
            p.row_ptr.push(p.post.len() as u32);
        }
        (fixed, p)
    }
}

impl Fly {
    /// Reads each section straight into its own Vec, so the file is never in memory twice.
    pub fn load(path: &str) -> Result<(Self, Synapses), String> {
        use std::io::Read;
        let err = |e: std::io::Error| format!("{path}: {e} (run `uv run tools/convert.py`)");
        let mut file = std::fs::File::open(path).map_err(err)?;
        let mut read = |len: usize| -> Result<Vec<u32>, String> {
            let mut v = vec![0u32; len];
            file.read_exact(bytemuck::cast_slice_mut(&mut v)).map_err(err)?;
            Ok(v)
        };
        let head = read(2)?;
        let (n, m) = (head[0] as usize, head[1] as usize);
        let expected = 4 * (2 + 3 * n + n + (n + 1) + m + 2 * n) as u64;
        if std::fs::metadata(path).map_err(err)?.len() != expected {
            return Err(format!("{path}: size does not match header ({n} neurons, {m} synapses)"));
        }
        let (pos, class, row_ptr, syn, cell_class, cell_type) =
            (read(3 * n)?, read(n)?, read(n + 1)?, read(m)?, read(n)?, read(n)?);
        let json = std::path::Path::new(path).with_extension("json");
        let names = std::fs::read_to_string(&json)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            .map_err(|e| format!("{}: {e}", json.display()))?;
        // the file packs post in 18 bits (tools/convert.py); repack to POST_BITS
        let syn = syn.into_iter().map(|s| (((s as i32 >> 18) << POST_BITS) as u32) | (s & 0x3FFFF)).collect();
        let fly = Self { n: n as u32, pos: bytemuck::cast_vec(pos), class, cell_class, cell_type, names };
        Ok((fly, Synapses { row_ptr, syn }))
    }

    /// Subgraph on the neurons where `keep` is true, renumbered from 0, without the connections
    /// where `cut(pre, post, signed synapse count)` is true (neurons in original numbering).
    pub fn circuit(&self, syn: &Synapses, keep: impl Fn(u32) -> bool, cut: impl Fn(u32, u32, i32) -> bool) -> (Fly, Synapses) {
        let old: Vec<u32> = (0..self.n).filter(|&i| keep(i)).collect();
        let mut new = vec![u32::MAX; self.n as usize];
        old.iter().enumerate().for_each(|(k, &i)| new[i as usize] = k as u32);
        let mut row_ptr = vec![0u32];
        let mut packed = Vec::new();
        for &i in &old {
            for &s in &syn.syn[syn.row_ptr[i as usize] as usize..syn.row_ptr[i as usize + 1] as usize] {
                let post = new[(s & POST) as usize];
                if post != u32::MAX && !cut(i, s & POST, s as i32 >> POST_BITS) {
                    packed.push((s & !POST) | post);
                }
            }
            row_ptr.push(packed.len() as u32);
        }
        let pick = |v: &[u32]| old.iter().map(|&i| v[i as usize]).collect::<Vec<_>>();
        let fly = Fly {
            n: old.len() as u32,
            pos: old.iter().flat_map(|&i| self.pos[3 * i as usize..3 * i as usize + 3].to_vec()).collect(),
            class: pick(&self.class),
            cell_class: pick(&self.cell_class),
            cell_type: pick(&self.cell_type),
            names: Names { cell_class: self.names.cell_class.clone(), cell_type: self.names.cell_type.clone() },
        };
        (fly, Synapses { row_ptr, syn: packed })
    }

    /// Neurons whose cell_class has this name.
    pub fn of_class(&self, name: &str) -> Vec<u32> {
        let code = self.names.cell_class.iter().position(|c| c == name).map(|c| c as u32);
        (0..self.n).filter(|&i| Some(self.cell_class[i as usize]) == code).collect()
    }
}

pub struct Sim {
    pub n: u32,
    pub last: wgpu::Buffer,
    pub clock: wgpu::Buffer,
    stim: wgpu::Buffer,
    state: wgpu::Buffer,
    ring: wgpu::Buffer,
    counts: [wgpu::Buffer; 2], // spike counters, alternating between steps (see sim.wgsl)
    parity: std::cell::Cell<usize>,
    kick: wgpu::Buffer,
    fired: wgpu::Buffer,
    plastic_w: wgpu::Buffer,
    kick_list: wgpu::Buffer,
    kick_ptr: wgpu::Buffer,
    bin: wgpu::Buffer,
    readback: wgpu::Buffer,
    // (pipeline, its bind groups): step and deliver have one per counter parity
    step: (wgpu::ComputePipeline, [wgpu::BindGroup; 2]),
    deliver: (wgpu::ComputePipeline, [wgpu::BindGroup; 2]),
    inject: (wgpu::ComputePipeline, wgpu::BindGroup),
}

impl Sim {
    /// `adapt`: spike-frequency adaptation in mV per spike (BRAIN_ADAPT for the whole brain).
    pub fn new(device: &wgpu::Device, queue: &wgpu::Queue, n: u32, syn: Synapses, plastic: &Plastic, adapt: f32) -> Self {
        use wgpu::BufferUsages as U;
        let init = |label, contents: &[u8], usage| {
            device.create_buffer_init(&wgpu::util::BufferInitDescriptor { label: Some(label), contents, usage })
        };
        // wgpu zero-initializes new buffers, so zeroed ones cost no host memory.
        let zeroed = |label, bytes: usize, usage| {
            device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(label),
                size: bytes as u64,
                usage,
                mapped_at_creation: false,
            })
        };
        let nb = n as usize * 4;
        let params = init("params", bytemuck::cast_slice(&[n, adapt.to_bits(), 0, 0]), U::UNIFORM);
        let row_ptr = init("row_ptr", bytemuck::cast_slice(&syn.row_ptr), U::STORAGE);
        let synapses = init("syn", bytemuck::cast_slice(&syn.syn), U::STORAGE);
        drop(syn);
        let state = zeroed("state", nb * 4, U::STORAGE | U::COPY_DST);
        let last = zeroed("last", nb, U::STORAGE | U::COPY_DST | U::COPY_SRC);
        let stim = zeroed("stim", nb, U::STORAGE | U::COPY_DST);
        let clock = init("clock", bytemuck::cast_slice(&[CLOCK_START, 0]), U::STORAGE | U::COPY_DST | U::COPY_SRC);
        let ring = zeroed("ring", RING * nb, U::STORAGE | U::COPY_DST);
        let spikes = zeroed("spikes", nb + 4, U::STORAGE); // slot 0 is unused (bookkeeping workgroup)
        let counter = || init("count", bytemuck::cast_slice(&[1u32, 1, 1]), U::STORAGE | U::INDIRECT | U::COPY_DST);
        let counts = [counter(), counter()];
        let kick = zeroed("kick", nb, U::STORAGE | U::COPY_DST);
        let fired = zeroed("fired", nb, U::STORAGE | U::COPY_DST | U::COPY_SRC);
        let readback = zeroed("readback", nb + 8, U::MAP_READ | U::COPY_DST);
        // Storage bindings must not be empty, hence the padding element.
        let plastic_row = match plastic.row_ptr.is_empty() {
            true => zeroed("plastic_row", nb + 4, U::STORAGE),
            false => init("plastic_row", bytemuck::cast_slice(&plastic.row_ptr), U::STORAGE),
        };
        let plastic_post = init("plastic_post", bytemuck::cast_slice(&[&plastic.post[..], &[0]].concat()), U::STORAGE);
        let plastic_w = zeroed("plastic_w", (plastic.w.len() + 1) * 4, U::STORAGE | U::COPY_DST);
        let kick_list = zeroed("kick_list", KICK_CAP * 4, U::STORAGE | U::COPY_DST);
        let kick_ptr = zeroed("kick_ptr", (BATCH_BINS + 1) * 4, U::STORAGE | U::COPY_DST);
        let bin = zeroed("bin", 4, U::STORAGE | U::COPY_DST);

        let module = device.create_shader_module(wgpu::include_wgsl!("sim.wgsl"));
        // binding 9 is this step's counter, 18 the other one; parity p uses counts[p] as 9
        let all = |p: usize| {
            [
                &params, &row_ptr, &synapses, &state, &last, &stim, &clock, &ring, &spikes, &counts[p], &kick, &fired,
                &plastic_row, &plastic_post, &plastic_w, &kick_list, &kick_ptr, &bin, &counts[1 - p],
            ]
        };
        // Auto layouts only contain the bindings an entry point uses, so each gets its own group.
        let pipe = |entry, bindings: &[usize]| {
            let p = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some(entry),
                layout: None,
                module: &module,
                entry_point: Some(entry),
                compilation_options: Default::default(),
                cache: None,
            });
            let group = |par: usize| {
                let entries: Vec<_> = bindings
                    .iter()
                    .map(|&i| wgpu::BindGroupEntry { binding: i as u32, resource: all(par)[i].as_entire_binding() })
                    .collect();
                device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some(entry),
                    layout: &p.get_bind_group_layout(0),
                    entries: &entries,
                })
            };
            let groups = [group(0), group(1)];
            (p, groups)
        };
        let step = pipe("step", &[0, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let deliver = pipe("deliver", &[0, 1, 2, 4, 6, 7, 8, 12, 13, 14, 18]);
        let (inject_pipe, [inject_group, _]) = pipe("inject", &[10, 15, 16, 17]);
        let sim = Self {
            n, last, clock, stim, state, ring, counts, parity: std::cell::Cell::new(0), kick, fired, plastic_w,
            kick_list, kick_ptr, bin, readback, step, deliver, inject: (inject_pipe, inject_group),
        };
        sim.set_plastic(queue, &plastic.w);
        sim.reset(device, queue);
        sim
    }

    /// Poisson input rate per neuron, Hz.
    pub fn set_stim(&self, queue: &wgpu::Queue, rates: &[f32]) {
        queue.write_buffer(&self.stim, 0, bytemuck::cast_slice(rates));
    }

    /// Plastic weights, in synapses, in `Plastic` order.
    pub fn set_plastic(&self, queue: &wgpu::Queue, w: &[f32]) {
        if !w.is_empty() {
            let fixed: Vec<i32> = w.iter().map(|w| (w * FIX).round() as i32).collect();
            queue.write_buffer(&self.plastic_w, 0, bytemuck::cast_slice(&fixed));
        }
    }

    /// Uploads a batch of telemetry input for `encode_bins`: bin b fires the neurons
    /// `list[ptr[b]..ptr[b + 1]]`. Takes effect with the next submit.
    pub fn set_input(&self, queue: &wgpu::Queue, list: &[u32], ptr: &[u32]) {
        assert!(list.len() <= KICK_CAP && ptr.len() <= BATCH_BINS + 1, "input batch too large");
        queue.write_buffer(&self.bin, 0, bytemuck::bytes_of(&0u32));
        queue.write_buffer(&self.kick_ptr, 0, bytemuck::cast_slice(ptr));
        if !list.is_empty() {
            queue.write_buffer(&self.kick_list, 0, bytemuck::cast_slice(list));
        }
    }

    /// `bins` 1 ms bins: each injects its input from `set_input`, then runs STEPS_PER_MS steps.
    pub fn encode_bins(&self, enc: &mut wgpu::CommandEncoder, bins: usize) {
        let mut pass = enc.begin_compute_pass(&Default::default());
        for _ in 0..bins {
            pass.set_pipeline(&self.inject.0);
            pass.set_bind_group(0, &self.inject.1, &[]);
            pass.dispatch_workgroups(1, 1, 1);
            self.steps(&mut pass, STEPS_PER_MS);
        }
    }

    /// Spikes per neuron since the last call; resets the counts.
    pub fn take_fired(&self, device: &wgpu::Device, queue: &wgpu::Queue) -> Vec<u32> {
        let n = self.n as u64 * 4;
        let mut enc = device.create_command_encoder(&Default::default());
        enc.copy_buffer_to_buffer(&self.fired, 0, &self.readback, 8, n);
        enc.clear_buffer(&self.fired, 0, None);
        queue.submit([enc.finish()]);
        self.readback.map_async(wgpu::MapMode::Read, .., |r| r.unwrap());
        device.poll(wgpu::PollType::wait_indefinitely()).unwrap();
        let v: Vec<u32> = bytemuck::pod_collect_to_vec(&self.readback.get_mapped_range(8..8 + n).unwrap());
        self.readback.unmap();
        v
    }

    /// Silence every neuron; keeps the clock running.
    /// Membrane potentials are stored relative to rest (see sim.wgsl), so all-zero is silence.
    pub fn reset(&self, device: &wgpu::Device, queue: &wgpu::Queue) {
        let mut enc = device.create_command_encoder(&Default::default());
        for b in [&self.state, &self.last, &self.ring, &self.kick] {
            enc.clear_buffer(b, 0, None);
        }
        for c in &self.counts {
            queue.write_buffer(c, 0, bytemuck::cast_slice(&[1u32, 1, 1]));
        }
        self.parity.set(0);
        queue.submit([enc.finish()]);
    }

    pub fn encode(&self, enc: &mut wgpu::CommandEncoder, steps: u32) {
        self.steps(&mut enc.begin_compute_pass(&Default::default()), steps);
    }

    fn steps(&self, pass: &mut wgpu::ComputePass, steps: u32) {
        for _ in 0..steps {
            let p = self.parity.get();
            pass.set_pipeline(&self.step.0);
            pass.set_bind_group(0, &self.step.1[p], &[]);
            pass.dispatch_workgroups(self.n.div_ceil(256), 1, 1);
            pass.set_pipeline(&self.deliver.0);
            pass.set_bind_group(0, &self.deliver.1[p], &[]);
            pass.dispatch_workgroups_indirect(&self.counts[p], 0);
            self.parity.set(1 - p);
        }
    }


    /// Blocking read of (step, total spikes, last spike step per neuron).
    pub fn read(&self, device: &wgpu::Device, queue: &wgpu::Queue) -> (u32, u32, Vec<u32>) {
        let mut enc = device.create_command_encoder(&Default::default());
        enc.copy_buffer_to_buffer(&self.clock, 0, &self.readback, 0, 8);
        enc.copy_buffer_to_buffer(&self.last, 0, &self.readback, 8, self.n as u64 * 4);
        queue.submit([enc.finish()]);
        self.readback.map_async(wgpu::MapMode::Read, .., |r| r.unwrap());
        device.poll(wgpu::PollType::wait_indefinitely()).unwrap();
        let v: Vec<u32> = bytemuck::pod_collect_to_vec(&self.readback.get_mapped_range(..).unwrap());
        self.readback.unmap();
        (v[0], v[1], v[2..].to_vec())
    }
}

/// Primary backends only (Vulkan / Metal / DX12): enabling GL as well loads the OpenGL and Mesa
/// drivers into the process for nothing. WGPU_BACKEND still overrides.
pub fn instance(display: Option<Box<dyn wgpu::wgt::WgpuHasDisplayHandle>>) -> wgpu::Instance {
    let mut desc = wgpu::InstanceDescriptor::new_without_display_handle();
    desc.backends = wgpu::Backends::PRIMARY;
    desc.display = display;
    wgpu::Instance::new(desc.with_env())
}

pub fn device(instance: &wgpu::Instance, surface: Option<&wgpu::Surface>) -> (wgpu::Adapter, wgpu::Device, wgpu::Queue) {
    let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        compatible_surface: surface,
        force_fallback_adapter: false,
        apply_limit_buckets: false,
    }))
    .expect("no GPU adapter");
    eprintln!("gpu: {}", adapter.get_info().name);
    let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
        required_limits: adapter.limits(),
        ..Default::default()
    }))
    .expect("no GPU device");
    (adapter, device, queue)
}
