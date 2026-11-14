// One instance per drawn point. index[i] is the simulated neuron it shows, or GHOST | fly for a
// context point: part of a fly's whole-brain outline, drawn dim and never flashing.
// per_fly: simulated neurons per fly; alarm: bit f set = fly f is alarmed and drawn red.
struct Cam { vp: mat4x4<f32>, size: f32, aspect: f32, decay: f32, per_fly: u32, alarm: u32, _p0: u32, _p1: u32, _p2: u32 }

@group(0) @binding(0) var<uniform> cam: Cam;
@group(0) @binding(1) var<storage, read> pos: array<f32>;
@group(0) @binding(2) var<storage, read> cls: array<u32>;
@group(0) @binding(3) var<storage, read> last: array<u32>;
@group(0) @binding(4) var<storage, read> clock: array<u32, 2>;
@group(0) @binding(5) var<storage, read> index: array<u32>;

const GHOST: u32 = 0x80000000u;

const PALETTE = array(
    vec3(0.25, 0.45, 1.0),  // optic
    vec3(1.0, 0.75, 0.2),   // central
    vec3(0.2, 1.0, 0.45),   // sensory
    vec3(0.45, 0.7, 1.0),   // visual_projection
    vec3(0.9, 0.4, 1.0),    // ascending
    vec3(1.0, 0.35, 0.3),   // descending
    vec3(0.4, 1.0, 0.8),    // sensory_ascending
    vec3(0.6, 0.6, 1.0),    // visual_centrifugal
    vec3(1.0, 0.2, 0.2),    // motor
    vec3(1.0, 0.4, 0.7),    // endocrine
    vec3(0.6, 0.6, 0.6),    // unknown
);

struct Out {
    @builtin(position) p: vec4<f32>,
    @location(0) color: vec3<f32>,
    @location(1) uv: vec2<f32>,
}

@vertex
fn vs(@builtin(vertex_index) v: u32, @builtin(instance_index) i: u32) -> Out {
    var corners = array(vec2(-1.0, -1.0), vec2(1.0, -1.0), vec2(-1.0, 1.0),
                         vec2(-1.0, 1.0), vec2(1.0, -1.0), vec2(1.0, 1.0));
    let q = corners[v];
    let k = index[i];
    let ghost = (k & GHOST) != 0u;
    let fly = select(k / cam.per_fly, k & 0xFFu, ghost);
    let flash = select(exp(-f32(clock[0] - last[k]) / cam.decay), 0.0, ghost);
    let s = cam.size * select(1.0 + 2.0 * flash, 0.7, ghost);
    var o: Out;
    o.p = cam.vp * vec4(pos[3u * i], pos[3u * i + 1u], pos[3u * i + 2u], 1.0);
    o.p += vec4(q.x * s / cam.aspect, q.y * s, 0.0, 0.0);
    var palette = PALETTE;
    var base = palette[min(cls[i], 10u)];
    let alarmed = ((cam.alarm >> min(fly, 31u)) & 1u) == 1u;
    if alarmed { base = mix(base, vec3(1.0, 0.1, 0.05), 0.75); }
    let glow = select(select(0.03, 0.08, alarmed), select(0.03, 0.06, alarmed), ghost);
    o.color = base * (glow + 1.5 * flash);
    o.uv = q;
    return o;
}

@fragment
fn fs(in: Out) -> @location(0) vec4<f32> {
    let a = max(0.0, 1.0 - dot(in.uv, in.uv));
    return vec4(in.color * a * a, 1.0);
}
