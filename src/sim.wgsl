// Leaky integrate-and-fire, whole-brain parameters from Shiu et al. 2024
// ("A Drosophila computational brain model reveals sensorimotor processing", Nature).
//
// Telemetry input arrives as a list of receptor neurons to fire per 1 ms bin (`inject`, one small
// dispatch per bin), so only the neurons that change are uploaded.
//
// Event driven, two dispatches per 0.1 ms step:
//   step     one thread per neuron: integrate, fire, append to the spike list
//   deliver  indirect, one workgroup per spike: add its outgoing weights DELAY steps ahead,
//            fixed connections first, then plastic ones (Kenyon cell -> output neuron).
//            Workgroup 0 is bookkeeping: it advances the clock and resets the *next* step's
//            spike counter. Two counters alternate between steps, because this step's counter is
//            the dispatch's indirect argument and cannot be written by it.

const DT: f32 = 0.1;        // ms per step
// Potentials are stored relative to rest (-52 mV), so a zeroed state buffer is a silent brain.
const VRESET: f32 = 0.0;    // -52 mV
const VTH: f32 = 7.0;       // -45 mV
const TAU_M: f32 = 20.0;    // ms
const TAU_S: f32 = 5.0;     // synaptic conductance decay, ms
const W_SYN: f32 = 0.275;   // mV per synapse
const F_POI: f32 = 250.0;   // Poisson input strength, in synapses (enough to fire a resting neuron)
const DELAY: u32 = 18u;     // 1.8 ms synaptic delay
const REF: u32 = 22u;       // 2.2 ms refractory
const RING: u32 = 19u;      // input ring slots, DELAY + 1 is the minimum
const KICK: i32 = 250;      // telemetry input, in synapses: like a Poisson spike, fires a resting neuron
const FIX: i32 = 16;        // ring and plastic weights count 1/16 synapses, so learning has resolution
// Spike-frequency adaptation (params.adapt mV per spike), NOT in Shiu et al. The whole brain
// needs it: without it ~2 s of sparse input locks ~9k central neurons into endless firing.
const TAU_A: f32 = 1000.0;  // ms

struct Params { n: u32, adapt: f32, _pad: vec2<u32> }
@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> row_ptr: array<u32>;   // outgoing CSR
@group(0) @binding(2) var<storage, read> syn: array<u32>;       // post (low 19 bits, sim.rs POST_BITS) | signed count << 19
@group(0) @binding(3) var<storage, read_write> state: array<vec4<f32>>; // (v, g, adaptation, unused)
@group(0) @binding(4) var<storage, read_write> last: array<u32>; // step of last spike, 0 = never
@group(0) @binding(5) var<storage, read> stim: array<f32>;      // Poisson input rate, Hz
@group(0) @binding(6) var<storage, read_write> clock: array<atomic<u32>, 2>; // (step, total spikes)
@group(0) @binding(7) var<storage, read_write> ring: array<atomic<i32>>;     // RING * n pending input
@group(0) @binding(8) var<storage, read_write> spikes: array<u32>;           // who fired this step
// this step's spike counter, also deliver's indirect args (x, 1, 1); x starts at 1: slot 0 is bookkeeping
@group(0) @binding(9) var<storage, read_write> count: array<atomic<u32>, 3>;
@group(0) @binding(10) var<storage, read_write> kick: array<i32>;   // one-shot input from telemetry, in synapses
@group(0) @binding(11) var<storage, read_write> fired: array<u32>;  // spikes per neuron since last reset
@group(0) @binding(12) var<storage, read> plastic_row: array<u32>; // plastic CSR, rows = presynaptic
@group(0) @binding(13) var<storage, read> plastic_post: array<u32>;
@group(0) @binding(14) var<storage, read> plastic_w: array<i32>;   // in 1/FIX synapses
@group(0) @binding(15) var<storage, read> kick_list: array<u32>;  // neurons to fire, bin after bin
@group(0) @binding(16) var<storage, read> kick_ptr: array<u32>;   // bin b's neurons: kick_ptr[b] .. kick_ptr[b + 1]
@group(0) @binding(17) var<storage, read_write> bin: array<atomic<u32>, 1>; // next bin of the batch
@group(0) @binding(18) var<storage, read_write> next_count: array<atomic<u32>, 3>; // the other counter

fn rand(a: u32, b: u32) -> f32 {
    var h = a * 747796405u + b * 2891336453u + 1u;
    h = ((h >> ((h >> 28u) + 4u)) ^ h) * 277803737u;
    h = (h >> 22u) ^ h;
    return f32(h) / 4294967296.0;
}

@compute @workgroup_size(256)
fn step(@builtin(global_invocation_id) id: vec3<u32>) {
    let i = id.x;
    let n = params.n;
    if i >= n { return; }
    let t = atomicLoad(&clock[0]);
    var s = state[i];

    s.y += f32(atomicExchange(&ring[(t % RING) * n + i], 0)) * (W_SYN / f32(FIX));
    if rand(i, t) < stim[i] * DT * 0.001 { s.y += F_POI * W_SYN; }
    let k = kick[i];
    if k != 0 {
        s.y += f32(k) * W_SYN;
        kick[i] = 0;
    }

    if t - last[i] >= REF { s.x += (s.y - s.x - s.z) * DT / TAU_M; }
    s.y -= s.y * DT / TAU_S;
    s.z -= s.z * DT / TAU_A;
    if s.x > VTH {
        s.x = VRESET;
        s.z += params.adapt;
        last[i] = t;
        spikes[atomicAdd(&count[0], 1u)] = i;
        atomicAdd(&clock[1], 1u);
        fired[i] += 1u;
    }
    state[i] = s;
}

@compute @workgroup_size(64)
fn deliver(@builtin(workgroup_id) wg: vec3<u32>, @builtin(local_invocation_index) lane: u32) {
    if wg.x == 0u {
        if lane == 0u {
            atomicAdd(&clock[0], 1u);
            atomicStore(&next_count[0], 1u);
        }
        return;
    }
    let src = spikes[wg.x];
    // src fired this step, so last[src] is this step's time; the clock may already have moved on
    let slot = ((last[src] + DELAY) % RING) * params.n;
    for (var k = row_ptr[src] + lane; k < row_ptr[src + 1u]; k += 64u) {
        let s = syn[k];
        atomicAdd(&ring[slot + (s & 0x7FFFFu)], (bitcast<i32>(s) >> 19u) * FIX); // >> keeps the sign
    }
    for (var k = plastic_row[src] + lane; k < plastic_row[src + 1u]; k += 64u) {
        atomicAdd(&ring[slot + plastic_post[k]], plastic_w[k]);
    }
}

@compute @workgroup_size(256)
fn inject(@builtin(local_invocation_index) lane: u32) {
    let b = atomicLoad(&bin[0]);
    for (var k = kick_ptr[b] + lane; k < kick_ptr[b + 1u]; k += 256u) {
        kick[kick_list[k]] = KICK;
    }
    workgroupBarrier();
    if lane == 0u { atomicAdd(&bin[0], 1u); }
}
