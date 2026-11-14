//! The 3D viewer: every neuron is a point at its real position, flashing when it spikes.
//!
//! Drag: orbit. Scroll: zoom. Space: pause. +/-: speed. Esc: quit.
//! What runs is up to the `Driver`: the whole brain (`Brain`, below) or the cluster
//! (`cluster::Watch`).

use crate::sim::{BRAIN_ADAPT, CLASSES, Fly, Plastic, STEPS_PER_MS, Sim, Synapses, device};
use glam::{Vec3, camera::rh};
use std::sync::Arc;
use std::time::Instant;
use winit::application::ApplicationHandler;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::keyboard::{Key, NamedKey};
use winit::window::{Window, WindowId};

/// Marks a context point in `Scene::index`: part of a fly's whole-brain outline, not simulated.
pub const GHOST: u32 = 0x8000_0000;

/// What the viewer draws: one point per entry.
pub struct Scene {
    pub pos: Vec<f32>,    // x, y, z per point
    pub colour: Vec<u32>, // palette index per point (see view.wgsl)
    pub index: Vec<u32>,  // simulated neuron shown, or GHOST | fly for a dim context point
    pub per_fly: u32,     // simulated neurons per fly, for the alarm tint
    pub dist: f32,        // initial camera distance
    pub speed: u32,       // initial speed, in the driver's units
}

/// Runs a simulation for the viewer.
pub trait Driver {
    fn scene(&self) -> Scene;
    /// Builds the simulation on the viewer's GPU. May take a while (training).
    fn start(&mut self, device: &wgpu::Device, queue: &wgpu::Queue);
    fn sim(&self) -> &Sim;
    /// Advances by `speed` units and returns how many 0.1 ms steps that was.
    fn frame(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, speed: u32) -> u32;
    /// Bit f set: fly f is raising an alarm (drawn red).
    fn alarm(&self) -> u32;
    /// Window title text.
    fn status(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, speed: u32) -> String;
    fn key(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, key: &str);
}

pub fn run(driver: Box<dyn Driver>) -> Result<(), String> {
    let el = EventLoop::new().map_err(|e| e.to_string())?;
    let instance = crate::sim::instance(Some(Box::new(el.owned_display_handle())));
    let scene = driver.scene();
    let mut app = App {
        instance,
        speed: scene.speed,
        dist: scene.dist,
        scene,
        driver,
        gpu: None,
        paused: false,
        yaw: 0.0,
        pitch: 0.0,
        drag: None,
        title: String::new(),
    };
    el.run_app(&mut app).map_err(|e| e.to_string())
}

struct Gpu {
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    config: wgpu::SurfaceConfiguration,
    device: wgpu::Device,
    queue: wgpu::Queue,
    renderer: Renderer,
}

/// Draws a scene's points into any texture: the window's, or an offscreen one for `snapshot`.
struct Renderer {
    cam: wgpu::Buffer,
    pipe: wgpu::RenderPipeline,
    bind: wgpu::BindGroup,
    points: u32,
    per_fly: u32,
}

/// Camera position on a sphere around the origin.
struct Camera {
    yaw: f32,
    pitch: f32,
    dist: f32,
}

impl Renderer {
    fn new(device: &wgpu::Device, scene: &Scene, sim: &Sim, format: wgpu::TextureFormat) -> Self {
        use wgpu::util::DeviceExt;
        use wgpu::BufferUsages as U;
        let init = |label, contents: &[u8], usage| {
            device.create_buffer_init(&wgpu::util::BufferInitDescriptor { label: Some(label), contents, usage })
        };
        let cam = init("cam", &[0; 96], U::UNIFORM | U::COPY_DST);
        let pos = init("pos", bytemuck::cast_slice(&scene.pos), U::STORAGE);
        let colour = init("colour", bytemuck::cast_slice(&scene.colour), U::STORAGE);
        let index = init("index", bytemuck::cast_slice(&scene.index), U::STORAGE);

        let module = device.create_shader_module(wgpu::include_wgsl!("view.wgsl"));
        let add = wgpu::BlendComponent {
            src_factor: wgpu::BlendFactor::One,
            dst_factor: wgpu::BlendFactor::One,
            operation: wgpu::BlendOperation::Add,
        };
        let pipe = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("neurons"),
            layout: None,
            vertex: wgpu::VertexState {
                module: &module,
                entry_point: Some("vs"),
                compilation_options: Default::default(),
                buffers: &[],
            },
            primitive: Default::default(),
            depth_stencil: None,
            multisample: Default::default(),
            fragment: Some(wgpu::FragmentState {
                module: &module,
                entry_point: Some("fs"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState { color: add, alpha: add }),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview_mask: None,
            cache: None,
        });
        let bind = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("view"),
            layout: &pipe.get_bind_group_layout(0),
            entries: &[&cam, &pos, &colour, &sim.last, &sim.clock, &index]
                .iter()
                .enumerate()
                .map(|(i, b)| wgpu::BindGroupEntry { binding: i as u32, resource: b.as_entire_binding() })
                .collect::<Vec<_>>(),
        });
        Self { cam, pipe, bind, points: scene.colour.len() as u32, per_fly: scene.per_fly }
    }

    /// `steps`: simulation steps since the last frame, which sets how long a flash lasts.
    fn draw(&self, device: &wgpu::Device, queue: &wgpu::Queue, target: &wgpu::TextureView, aspect: f32, c: &Camera, steps: u32, alarm: u32) {
        let eye = Vec3::new(c.yaw.sin() * c.pitch.cos(), c.pitch.sin(), c.yaw.cos() * c.pitch.cos()) * c.dist;
        let vp = rh::proj::directx::perspective(0.8, aspect, 0.01, 100.0) * rh::view::look_at_mat4(eye, Vec3::ZERO, Vec3::Y);
        let decay = (steps.max(STEPS_PER_MS) * 12) as f32; // a flash lasts ~12 frames at any speed
        let mut cam: Vec<u32> = vp.to_cols_array().iter().map(|x| x.to_bits()).collect();
        cam.extend([0.004f32.to_bits(), aspect.to_bits(), decay.to_bits(), self.per_fly]);
        cam.extend([alarm, 0, 0, 0]);
        queue.write_buffer(&self.cam, 0, bytemuck::cast_slice(&cam));

        let mut enc = device.create_command_encoder(&Default::default());
        {
            let mut pass = enc.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: None,
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: target,
                    depth_slice: None,
                    resolve_target: None,
                    ops: wgpu::Operations { load: wgpu::LoadOp::Clear(wgpu::Color::BLACK), store: wgpu::StoreOp::Store },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            });
            pass.set_pipeline(&self.pipe);
            pass.set_bind_group(0, &self.bind, &[]);
            pass.draw(0..6, 0..self.points);
        }
        queue.submit([enc.finish()]);
    }
}

/// Plays `driver` for `frames` frames at its default speed, then renders one frame offscreen and
/// writes it as a binary PPM image. No window: for previews and docs.
pub fn snapshot(mut driver: Box<dyn Driver>, frames: u32, out: &str, (w, h): (u32, u32)) -> Result<(), String> {
    let (_, device, queue) = device(&crate::sim::instance(None), None);
    driver.start(&device, &queue);
    let scene = driver.scene();
    let format = wgpu::TextureFormat::Rgba8UnormSrgb;
    let renderer = Renderer::new(&device, &scene, driver.sim(), format);
    let mut steps = 0;
    for _ in 0..frames {
        steps = driver.frame(&device, &queue, scene.speed);
    }
    let texture = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("snapshot"),
        size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format,
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
        view_formats: &[],
    });
    let camera = Camera { yaw: 0.0, pitch: 0.0, dist: scene.dist };
    renderer.draw(&device, &queue, &texture.create_view(&Default::default()), w as f32 / h as f32, &camera, steps, driver.alarm());

    let row = (4 * w).div_ceil(256) * 256; // copies need 256-byte aligned rows
    let buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("snapshot readback"),
        size: (row * h) as u64,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let mut enc = device.create_command_encoder(&Default::default());
    enc.copy_texture_to_buffer(
        texture.as_image_copy(),
        wgpu::TexelCopyBufferInfo {
            buffer: &buf,
            layout: wgpu::TexelCopyBufferLayout { offset: 0, bytes_per_row: Some(row), rows_per_image: None },
        },
        texture.size(),
    );
    queue.submit([enc.finish()]);
    buf.map_async(wgpu::MapMode::Read, .., |r| r.unwrap());
    device.poll(wgpu::PollType::wait_indefinitely()).map_err(|e| e.to_string())?;
    let data = buf.get_mapped_range(..).map_err(|e| e.to_string())?;
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    for y in 0..h as usize {
        for px in data[y * row as usize..][..4 * w as usize].chunks(4) {
            ppm.extend(&px[..3]);
        }
    }
    std::fs::write(out, ppm).map_err(|e| format!("{out}: {e}"))?;
    eprintln!("{out}: {}", driver.status(&device, &queue, scene.speed));
    Ok(())
}

struct App {
    instance: wgpu::Instance,
    scene: Scene,
    driver: Box<dyn Driver>,
    gpu: Option<Gpu>,
    paused: bool,
    speed: u32,
    yaw: f32,
    pitch: f32,
    dist: f32,
    drag: Option<(f64, f64)>,
    title: String,
}

impl App {
    fn redraw(&mut self) {
        let Some(g) = &mut self.gpu else { return };
        let frame = match g.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(f) | wgpu::CurrentSurfaceTexture::Suboptimal(f) => f,
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                g.surface.configure(&g.device, &g.config);
                return;
            }
            _ => return,
        };
        let steps = if self.paused { 0 } else { self.driver.frame(&g.device, &g.queue, self.speed) };
        let aspect = g.config.width as f32 / g.config.height.max(1) as f32;
        let view = frame.texture.create_view(&Default::default());
        let camera = Camera { yaw: self.yaw, pitch: self.pitch, dist: self.dist };
        g.renderer.draw(&g.device, &g.queue, &view, aspect, &camera, steps, self.driver.alarm());
        g.queue.present(frame);

        let title = self.driver.status(&g.device, &g.queue, self.speed) + if self.paused { "  |  paused" } else { "" };
        if title != self.title {
            g.window.set_title(&title);
            self.title = title;
        }
        g.window.request_redraw();
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.gpu.is_some() {
            return;
        }
        let window = Arc::new(el.create_window(Window::default_attributes().with_title("FlySOC")).unwrap());
        let surface = self.instance.create_surface(window.clone()).unwrap();
        let (adapter, device, queue) = device(&self.instance, Some(&surface));
        let size = window.inner_size();
        let config = surface.get_default_config(&adapter, size.width.max(1), size.height.max(1)).unwrap();
        surface.configure(&device, &config);
        self.driver.start(&device, &queue);
        let renderer = Renderer::new(&device, &self.scene, self.driver.sim(), config.format);
        self.gpu = Some(Gpu { window, surface, config, device, queue, renderer });
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => el.exit(),
            WindowEvent::RedrawRequested => self.redraw(),
            WindowEvent::Resized(s) => {
                if let Some(g) = &mut self.gpu {
                    g.config.width = s.width.max(1);
                    g.config.height = s.height.max(1);
                    g.surface.configure(&g.device, &g.config);
                }
            }
            WindowEvent::MouseInput { state, button: MouseButton::Left, .. } => {
                self.drag = (state == ElementState::Pressed).then_some((f64::NAN, f64::NAN));
            }
            WindowEvent::CursorMoved { position: p, .. } => {
                if let Some((x, y)) = self.drag {
                    if !x.is_nan() {
                        self.yaw -= (p.x - x) as f32 * 0.005;
                        self.pitch = (self.pitch + (p.y - y) as f32 * 0.005).clamp(-1.5, 1.5);
                    }
                    self.drag = Some((p.x, p.y));
                }
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let d = match delta {
                    MouseScrollDelta::LineDelta(_, y) => y,
                    MouseScrollDelta::PixelDelta(p) => p.y as f32 / 50.0,
                };
                self.dist = (self.dist * 0.9f32.powf(d)).clamp(0.2, 30.0);
            }
            WindowEvent::KeyboardInput { event, .. } if event.state == ElementState::Pressed => {
                match event.logical_key.as_ref() {
                    Key::Named(NamedKey::Space) => self.paused = !self.paused,
                    Key::Named(NamedKey::Escape) => el.exit(),
                    Key::Character("+" | "=") => self.speed = (self.speed * 2).min(self.scene.speed * 64),
                    Key::Character("-") => self.speed = (self.speed / 2).max(1),
                    Key::Character(c) => {
                        if let Some(g) = &self.gpu {
                            self.driver.key(&g.device, &g.queue, c);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

const STIM_HZ: f32 = 150.0;
// ponytail: every 10th neuron of a class gets input; real experiments target named cell types
// (e.g. sugar GRNs), which fly.bin now has (cell_type), if we want those.
const STIM_EVERY: usize = 10;

/// The whole brain with Poisson input. R: silence all neurons. 1-9, 0: toggle input into a
/// neuron super class (see sim::CLASSES). Speed is in 0.1 ms steps per frame.
pub struct Brain {
    fly: Fly,
    syn: Option<Synapses>, // moved to the GPU on start
    sim: Option<Sim>,
    stim_on: [bool; 11],
    stats: (Instant, u32, u32), // (when, step, spikes) at the last title update
    title: String,
}

impl Brain {
    pub fn new(fly: Fly, syn: Synapses) -> Self {
        let mut stim_on = [false; 11];
        stim_on[2] = true; // sensory
        Self { fly, syn: Some(syn), sim: None, stim_on, stats: (Instant::now(), 0, 0), title: "FlySOC".into() }
    }

    fn push_stim(&self, queue: &wgpu::Queue) {
        let rates: Vec<f32> = (0..self.fly.n as usize)
            .map(|i| if self.stim_on[self.fly.class[i] as usize] && i % STIM_EVERY == 0 { STIM_HZ } else { 0.0 })
            .collect();
        self.sim().set_stim(queue, &rates);
        let on: Vec<_> = CLASSES.iter().zip(self.stim_on).filter(|c| c.1).map(|c| *c.0).collect();
        eprintln!("input: {}", if on.is_empty() { "none".into() } else { on.join(", ") });
    }
}

impl Driver for Brain {
    fn scene(&self) -> Scene {
        Scene {
            pos: self.fly.pos.clone(),
            colour: self.fly.class.clone(),
            index: (0..self.fly.n).collect(),
            per_fly: self.fly.n,
            dist: 2.5,
            speed: STEPS_PER_MS,
        }
    }

    fn start(&mut self, device: &wgpu::Device, queue: &wgpu::Queue) {
        let syn = self.syn.take().expect("started once");
        self.sim = Some(Sim::new(device, queue, self.fly.n, syn, &Plastic::default(), BRAIN_ADAPT));
        self.push_stim(queue);
    }

    fn sim(&self) -> &Sim {
        self.sim.as_ref().expect("started")
    }

    fn frame(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, speed: u32) -> u32 {
        let mut enc = device.create_command_encoder(&Default::default());
        self.sim().encode(&mut enc, speed);
        queue.submit([enc.finish()]);
        speed
    }

    fn alarm(&self) -> u32 {
        0
    }

    fn status(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, _speed: u32) -> String {
        let (t0, step0, spikes0) = self.stats;
        if t0.elapsed().as_secs_f32() >= 1.0 {
            let (step, spikes, _) = self.sim().read(device, queue);
            let secs = t0.elapsed().as_secs_f32();
            let sim_ms = (step - step0) as f32 / STEPS_PER_MS as f32;
            let hz = (spikes - spikes0) as f32 / (sim_ms.max(1e-3) / 1000.0) / self.fly.n as f32;
            self.title = format!(
                "FlySOC brain  |  {:.0} ms simulated  |  {:.2}x real time  |  mean rate {hz:.2} Hz",
                step as f32 / STEPS_PER_MS as f32,
                sim_ms / 1000.0 / secs,
            );
            self.stats = (Instant::now(), step, spikes);
        }
        self.title.clone()
    }

    fn key(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, key: &str) {
        if key == "r" {
            self.sim().reset(device, queue);
        } else if let Some(d) = key.chars().next().and_then(|c| c.to_digit(10)) {
            let k = if d == 0 { 9 } else { d as usize - 1 };
            self.stim_on[k] = !self.stim_on[k];
            self.push_stim(queue);
        }
    }
}
