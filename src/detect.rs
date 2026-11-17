//! Telemetry -> spikes -> alerts, on the network specialist circuit.
//!
//! Encoding: each event is an "odour" made of components, one per field (see `Event::features`),
//! plus summaries of recent history from `History`, e.g. how many distinct ports this source
//! touched in the last minute: attacks like scans and sprays are patterns across events.
//! Each feature maps through stable hashes to GLOMERULI_PER_FEATURE of the 53 olfactory glomeruli,
//! so an event activates a combination of glomeruli, like a real odour. Field-wise components let
//! the fly generalise: "the scanner, on some port" can become familiar, while "this workstation,
//! on a port it never uses" stays novel. The event's receptor neurons (ORNs) fire a short burst
//! (a puff). From there the fly's own wiring takes over: ORN -> projection neurons (ALPN) ->
//! Kenyon cells (sparse odour code) -> mushroom body output neurons (MBON). One second of
//! telemetry is played as WINDOW_MS of fly time.
//!
//! Learning (Phase 2) happens where flies learn: the Kenyon cell -> MBON synapses. The rule is
//! the fly's three-factor rule (Hige et al. 2015): dopamine arriving while a Kenyon cell is
//! active depresses that cell's output synapses. Here dopamine is the label: windows labelled
//! safe ("benign*") depress the synapses of the Kenyon cells that fired, attack windows let them
//! recover toward their initial weight. Every synapse also drifts back toward its initial weight
//! by RECOVERY per window, so "familiar" means "seen often", not "seen once". What is left
//! driving the MBONs is "not known safe".
//!
//! Readout: MBON spikes per window. An alert fires when that is more than Z_ALERT standard
//! deviations above a benign baseline, and at least MIN_ALERT spikes.

use crate::sim::{Fly, Plastic, Sim, Synapses};
use serde::Deserialize;
use std::io::BufRead;

pub const WINDOW_MS: u32 = 50;
const GLOMERULI_PER_FEATURE: u8 = 2;
/// History components get more glomeruli: they carry the pattern that tells an attack from a
/// look-alike, and with 2 they are drowned out by the event's own fields.
const GLOMERULI_PER_HISTORY: u8 = 4;
/// Glomeruli reserved for history components, at most half of a fly's; no field hashes into them.
/// A fly that smells a kind with a long-window count (all but processes) gets two ordinal codes of
/// 10, for the last minute and the long window; a processes-only fly keeps one code of 13, so its
/// fields keep 40 glomeruli.
const HISTORY_GLOMERULI: usize = 13;
const HISTORY_GLOMERULI_TWO_CODES: usize = 20;
/// Each event is a puff: its receptor neurons fire PUFF_SPIKES times, PUFF_GAP_MS apart, like a
/// real odour response (~250 Hz for ~20 ms). A single synchronous spike barely reaches Kenyon cells.
const PUFF_SPIKES: usize = 5;
const PUFF_GAP_MS: usize = 4;
const Z_ALERT: f64 = 4.0;
const MIN_ALERT: f64 = 20.0; // a few MBON spikes are noise; scans drive hundreds
/// Seconds ignored at the start of every run, while the circuit fills up from silence.
pub const WARMUP_S: usize = 2;
/// Kenyon cell -> MBON weights start at INIT_GAIN x their synapse count. The connectome counts
/// alone leave MBONs silent at ~1% Kenyon cell activity, and learning only ever lowers weights.
const INIT_GAIN: f32 = 16.0;
const LR_SAFE: f32 = 0.1; // fraction of a weight lost per Kenyon spike in a safe window
const LR_RECOVER: f32 = 0.05; // fraction of the way back to the initial weight, per spike
const RECOVERY: f32 = 0.002; // fraction of the way back to the initial weight, per window

/// The network specialist runs on the olfactory -> mushroom body / lateral horn pathway only,
/// as layers: receptors (ORN), antennal lobe, Kenyon cells and lateral horn, output neurons.
/// Dopamine neurons (DAN, DPM) are left out: in the fly they modulate learning rather than
/// excite, so they become the learning signal instead of simulated neurons.
pub const LAYERS: [&[&str]; 4] = [
    &["olfactory"],
    &["ALPN", "ALLN", "ALIN", "ALON"],
    &["Kenyon_Cell", "LHLN", "LHCENT"],
    &["MBON", "MBIN"],
];
const NOT_SIMULATED: [&str; 1] = ["DPM"]; // dopaminergic member of MBIN; APL (GABA) stays

/// Keeps every inhibitory connection and every excitatory one that goes forward a layer.
/// Excitatory connections within or back across layers are cut: most are axo-axonic (Kenyon
/// cell -> Kenyon cell alone is 40% of the circuit), and a point neuron model turns them into
/// loops that keep the circuit firing long after input stops.
pub fn circuit(fly: &Fly, syn: &Synapses) -> (Fly, Synapses) {
    let name = |list: &[String], code: u32| list.get(code as usize).map_or("", |s| s.as_str()).to_string();
    let layer = |i: u32| {
        let class = name(&fly.names.cell_class, fly.cell_class[i as usize]);
        if NOT_SIMULATED.contains(&name(&fly.names.cell_type, fly.cell_type[i as usize]).as_str()) {
            return None;
        }
        LAYERS.iter().position(|l| l.contains(&class.as_str()))
    };
    let layers: Vec<Option<usize>> = (0..fly.n).map(layer).collect();
    fly.circuit(
        syn,
        |i| layers[i as usize].is_some(),
        |pre, post, w| w > 0 && layers[post as usize] <= layers[pre as usize],
    )
}

/// The learnable part of the mushroom body: Kenyon cell -> MBON synapses and their initial weights.
#[derive(Clone)]
pub struct MushroomBody {
    pub plastic: Plastic,
    w0: Vec<f32>,
}

impl MushroomBody {
    pub fn split(fly: &Fly, syn: Synapses) -> (Synapses, Self) {
        let (kc, mbon) = (member(fly, "Kenyon_Cell"), member(fly, "MBON"));
        let (fixed, mut plastic) = syn.split(|pre, post| kc[pre as usize] && mbon[post as usize]);
        plastic.w.iter_mut().for_each(|w| *w *= INIT_GAIN);
        let w0 = plastic.w.clone();
        (fixed, Self { plastic, w0 })
    }

    /// `k` independent copies, one per fly, for a simulation holding `k` circuits of `n` neurons.
    pub fn replicate(&self, k: usize, n: u32) -> Self {
        Self { plastic: self.plastic.replicate(k, n), w0: self.w0.repeat(k) }
    }

    /// The plastic synapses of fly `f` (its Kenyon cells are neurons f*n .. (f+1)*n).
    fn of_fly(&self, f: usize, n: u32) -> std::ops::Range<usize> {
        let r = &self.plastic.row_ptr;
        r[f * n as usize] as usize..r[(f + 1) * n as usize] as usize
    }

    /// One window of the three-factor rule on the synapses in `range`. `fired` is spikes per
    /// neuron in the window.
    fn learn(&mut self, fired: &[u32], safe: bool, range: std::ops::Range<usize>) {
        let p = &mut self.plastic;
        for j in range {
            p.w[j] += (self.w0[j] - p.w[j]) * RECOVERY;
            let a = fired[p.pre[j] as usize] as f32;
            if a > 0.0 {
                p.w[j] = match safe {
                    true => p.w[j] * (1.0 - LR_SAFE).powf(a),
                    false => self.w0[j] + (p.w[j] - self.w0[j]) * (1.0 - LR_RECOVER).powf(a),
                };
            }
        }
    }
}


fn member(fly: &Fly, class: &str) -> Vec<bool> {
    let mut v = vec![false; fly.n as usize];
    fly.of_class(class).into_iter().for_each(|i| v[i as usize] = true);
    v
}

/// Populations traced per window; detection reads DETECT_ON.
pub const TRACED: [&str; 4] = ["ALPN", "Kenyon_Cell", "MBON", "LHLN"];
pub const DETECT_ON: usize = 2;

/// One line of JSON telemetry. `kind` says which fields are set; it defaults to "conn".
#[derive(Deserialize, Default)]
pub struct Event {
    pub ts: f64,
    #[serde(default = "conn")]
    pub kind: String,
    #[serde(default)]
    pub label: String,
    src: Option<String>,
    dst: Option<String>,
    dport: Option<u16>,
    user: Option<String>,
    result: Option<String>,
    host: Option<String>,
    process: Option<String>,
    parent: Option<String>,
    query: Option<String>,
}

fn conn() -> String {
    "conn".into()
}

impl Event {
    /// The hosts and users this event is about, for linking alarms across flies.
    fn entities(&self) -> Vec<String> {
        let all = match self.kind.as_str() {
            "conn" => vec![&self.src, &self.dst],
            "auth" => vec![&self.src, &self.dst, &self.user],
            "proc" | "dns" => vec![&self.host],
            _ => vec![],
        };
        all.into_iter().flatten().cloned().collect()
    }

    /// Where the event comes from: the source, or the host it ran on. Shards split by this.
    fn origin(&self) -> &str {
        self.src.as_deref().or(self.host.as_deref()).unwrap_or("")
    }

    /// The components of this event's odour, one per field. Same field value, same component.
    fn features(&self) -> Vec<String> {
        let f = |name: &str, o: &Option<String>| format!("{name}={}", o.as_deref().unwrap_or(""));
        match self.kind.as_str() {
            "conn" => vec![f("src", &self.src), format!("dport={}", self.dport.unwrap_or(0))],
            "auth" => vec![f("user", &self.user), f("src", &self.src), f("dst", &self.dst), f("result", &self.result)],
            "proc" => vec![f("host", &self.host), f("process", &self.process), f("parent", &self.parent)],
            "dns" => {
                // base domain, plus the shape of the first label: tunnels use long random ones
                let q = self.query.as_deref().unwrap_or("");
                let first = q.split('.').next().map_or(0, |l| l.len());
                vec![f("host", &self.host), format!("domain={}", base_domain(q)), format!("label_len={}", first / 8)]
            }
            other => vec![other.to_string()],
        }
    }
}

/// "a.b.example.com" -> "example.com".
fn base_domain(q: &str) -> String {
    let labels: Vec<&str> = q.split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

/// How far back `History` looks: every count over the last minute, and fan-out counts (ports,
/// failed users, DNS names) also over LONG_HISTORY_S, so a scan or spray spread over many minutes
/// (low and slow) still adds up. Processes stay short: benign hosts cycle through all of theirs
/// within minutes. (ISSUES E10)
const HISTORY_S: f64 = 60.0;
const LONG_HISTORY_S: f64 = 900.0;

/// Sliding-window summaries of the telemetry stream, added to each event's odour as extra
/// components. Single events of a scan or a password spray look ordinary; the pattern across
/// events does not. Counts are bucketed by powers of two (0, 1, 2-3, 4-7, ...).
#[derive(Default)]
pub struct History {
    seen: std::collections::HashMap<String, std::collections::VecDeque<(f64, String)>>,
}

impl History {
    /// Distinct values under `key` in the last HISTORY_S and the last `keep` seconds, after
    /// recording `value` at `ts` if given.
    fn distinct(&mut self, key: String, ts: f64, value: Option<String>, keep: f64) -> (usize, usize) {
        let q = self.seen.entry(key).or_default();
        if let Some(v) = value {
            q.push_back((ts, v));
        }
        while q.front().is_some_and(|(t, _)| *t < ts - keep) {
            q.pop_front();
        }
        let count = |span: f64| q.iter().filter(|(t, _)| *t >= ts - span).map(|(_, v)| v).collect::<std::collections::HashSet<_>>().len();
        (count(HISTORY_S), count(keep))
    }

    /// Updates the history with `e` and returns its history components, the raw count behind
    /// them (the longest window's), and the entities (hosts, users) the count is about.
    pub fn observe(&mut self, e: &Event) -> Seen {
        let f = |o: &Option<String>| o.clone().unwrap_or_default();
        let bucket = |n: usize| usize::BITS - n.leading_zeros();
        let (name, (short, long), slow) = match e.kind.as_str() {
            // distinct ports this source touched: a scan touches many
            "conn" => ("src_ports", self.distinct(format!("ports<{}", f(&e.src)), e.ts, Some(e.dport.unwrap_or(0).to_string()), LONG_HISTORY_S), true),
            // distinct users failing from this source: a spray fails many, a typo one
            "auth" => {
                let failed = (e.result.as_deref() == Some("fail")).then(|| f(&e.user));
                ("src_failed_users", self.distinct(format!("failed<{}", f(&e.src)), e.ts, failed, LONG_HISTORY_S), true)
            }
            // distinct processes started on this host: remote command sessions start several
            "proc" => ("host_processes", self.distinct(format!("procs<{}", f(&e.host)), e.ts, Some(f(&e.process)), HISTORY_S), false),
            // distinct names this host looked up under one base domain: tunnels use many
            "dns" => {
                let q = f(&e.query);
                ("names_per_domain", self.distinct(format!("names<{}|{}", f(&e.host), base_domain(&q)), e.ts, Some(q), LONG_HISTORY_S), true)
            }
            _ => return Seen::default(),
        };
        let mut components = vec![format!("{name}={}", bucket(short))];
        if slow {
            components.push(format!("{name}_long={}", bucket(long)));
        }
        Seen { components, count: long, entities: e.entities() }
    }
}

/// What `History` made of one event.
#[derive(Default)]
pub struct Seen {
    pub components: Vec<String>,
    pub count: usize,
    pub entities: Vec<String>,
}

pub fn read_events(path: &str) -> Result<Vec<Event>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut events = Vec::new();
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("{path}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str(&line).map_err(|e| format!("{path}:{}: {e}", i + 1))?);
    }
    events.sort_by(|a: &Event, b| a.ts.total_cmp(&b.ts));
    Ok(events)
}

/// FNV-1a; std's hasher is not guaranteed stable across Rust releases, and trained flies
/// will depend on the mapping staying put.
pub fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

pub struct Encoder {
    glomeruli: Vec<Vec<u32>>, // ORNs grouped by cell type
    kinds: Vec<String>,       // event kinds this fly smells; others pass it by
    salt: u8,                 // individual fly: which glomeruli each feature lands on (0 = the original)
    shard: (u64, u64),        // (k, n): smells only events whose source hashes to k of n (O15)
    fields: bool,             // false: smells only history components, not the event's fields (P9)
}

impl Encoder {
    pub fn new(fly: &Fly, kinds: &[&str]) -> Self {
        let mut by_type = std::collections::BTreeMap::<u32, Vec<u32>>::new();
        for i in fly.of_class("olfactory") {
            by_type.entry(fly.cell_type[i as usize]).or_default().push(i);
        }
        Self { glomeruli: by_type.into_values().collect(), kinds: kinds.iter().map(|k| k.to_string()).collect(), salt: 0, shard: (0, 1), fields: true }
    }

    /// Smells how many (history), not who (fields): names are novel everywhere on a big network.
    pub fn history_only(self) -> Self {
        Self { fields: false, ..self }
    }

    /// Watches one part of the network: events whose source (or host) hashes to `k` of `n`.
    pub fn shard(self, k: usize, n: usize) -> Self {
        Self { shard: (k as u64, n as u64), ..self }
    }

    /// The same fly's role in another individual: every feature lands on different glomeruli.
    pub fn individual(self, salt: u8) -> Self {
        Self { salt, ..self }
    }

    /// The receptor neurons this event fires, or None if it is not this fly's kind.
    /// `history`: the event's components from `History::observe`.
    pub fn neurons(&self, e: &Event, history: &[String]) -> Option<impl Iterator<Item = u32> + '_> {
        if !self.kinds.contains(&e.kind) {
            return None;
        }
        if self.shard.1 > 1 && fnv(e.origin().as_bytes()) % self.shard.1 != self.shard.0 {
            return None;
        }
        // Fields hash into the first glomeruli. History components get the last HISTORY_GLOMERULI,
        // which no field can reach, in an ordinal code: bucket b lights b .. b+3, so neighbouring
        // magnitudes overlap and distant ones never do, the same in every individual (O7).
        let two = self.kinds.iter().any(|k| k != "proc");
        let wanted = if two { HISTORY_GLOMERULI_TWO_CODES } else { HISTORY_GLOMERULI };
        let reserved = wanted.min(self.glomeruli.len() / 2) as u64;
        let fields = self.glomeruli.len() as u64 - reserved;
        let features = if self.fields { e.features() } else { vec![] };
        let hashed = features.into_iter().flat_map(move |feature| {
            (0..GLOMERULI_PER_FEATURE).map(move |k| {
                let salt: &[u8] = if self.salt == 0 { &[] } else { std::slice::from_ref(&self.salt) };
                fnv(&[feature.as_bytes(), &[k], salt].concat()) % fields
            })
        });
        // Two codes side by side: the last minute, and the long window ("_long" components).
        let codes = if two && reserved >= 2 { 2 } else { 1 };
        let size = reserved / codes;
        let ordinal = history.iter().flat_map(move |h| {
            let (name, bucket) = h.rsplit_once('=').unwrap_or((h, "0"));
            let bucket = bucket.parse::<u64>().unwrap_or(0);
            let offset = fields + if codes == 2 && name.ends_with("_long") { size } else { 0 };
            (0..GLOMERULI_PER_HISTORY as u64).map(move |k| offset + (bucket + k).min(size - 1))
        });
        let chosen: Vec<u64> = hashed.chain(ordinal).collect();
        Some(chosen.into_iter().flat_map(move |g| self.glomeruli[g as usize].iter().copied()))
    }
}

pub struct Window {
    pub spikes: [u32; TRACED.len()],
    pub labels: Vec<String>,
    /// Entities behind the most extreme history count among this fly's events in the last
    /// SUSPECT_S seconds: who to blame if the fly is alarmed.
    pub suspects: Vec<String>,
}

/// How far back a fly looks for its suspects.
const SUSPECT_S: f64 = 20.0;

/// Safe = only labels starting with "benign" (or no label at all).
pub fn is_safe(labels: &[String]) -> bool {
    labels.iter().all(|l| l.is_empty() || l.starts_with("benign"))
}

/// Plays telemetry into one or more flies sharing a simulation: fly f is neurons f*n .. (f+1)*n
/// and smells what its encoder accepts. Used by `play` and, a bin at a time, by the viewer.
pub struct Player<'a> {
    events: &'a [Event],
    encs: &'a [Encoder],
    n: u32,
    next: usize,
    bin: usize, // 1 ms bins played so far
    pending: Vec<Vec<u32>>, // receptor neurons to fire in upcoming bins, by bin modulo the puff length
    // input of the bins played but not yet sent to the GPU (see `flush`)
    list: Vec<u32>,
    ptr: Vec<u32>,
    labels: Vec<Vec<String>>, // per fly, this second
    history: History,
    recent: Vec<std::collections::VecDeque<(f64, usize, Vec<String>)>>, // per fly: (ts, count, entities)
}

impl<'a> Player<'a> {
    /// Resets the simulation and starts at second 0.
    pub fn new(device: &wgpu::Device, queue: &wgpu::Queue, sim: &Sim, n: u32, encs: &'a [Encoder], events: &'a [Event]) -> Self {
        assert_eq!(sim.n, n * encs.len() as u32, "one encoder per fly");
        sim.reset(device, queue);
        sim.take_fired(device, queue);
        Self {
            events,
            encs,
            n,
            next: 0,
            bin: 0,
            pending: vec![Vec::new(); PUFF_SPIKES * PUFF_GAP_MS],
            list: Vec::new(),
            ptr: vec![0],
            labels: vec![Vec::new(); encs.len()],
            history: History::default(),
            recent: vec![Default::default(); encs.len()],
        }
    }

    pub fn second(&self) -> usize {
        self.bin / WINDOW_MS as usize
    }

    /// Plays one 1 ms bin of fly time. Bins are batched and sent to the GPU at the end of each
    /// telemetry second (or by `flush`). At the end of a second, returns that second's labels per fly
    /// (only from events that fly smells); `Sim::take_fired` then holds its spikes.
    pub fn step(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, sim: &Sim) -> Option<Vec<Vec<String>>> {
        let slot = |bin: usize| bin % (PUFF_SPIKES * PUFF_GAP_MS);
        let end = (self.bin + 1) as f64 / WINDOW_MS as f64;
        let mut touched = std::mem::take(&mut self.pending[slot(self.bin)]);
        while self.next < self.events.len() && self.events[self.next].ts < end {
            let e = &self.events[self.next];
            self.next += 1;
            let seen = self.history.observe(e);
            for (f, enc) in self.encs.iter().enumerate() {
                let Some(neurons) = enc.neurons(e, &seen.components) else { continue };
                self.recent[f].push_back((e.ts, seen.count, seen.entities.clone()));
                if !self.labels[f].contains(&e.label) {
                    self.labels[f].push(e.label.clone());
                }
                let neurons: Vec<u32> = neurons.map(|i| i + f as u32 * self.n).collect();
                for k in 1..PUFF_SPIKES {
                    self.pending[slot(self.bin + k * PUFF_GAP_MS)].extend(&neurons);
                }
                touched.extend(neurons);
            }
        }
        if self.list.len() + touched.len() > crate::sim::KICK_CAP || self.ptr.len() > crate::sim::BATCH_BINS {
            self.flush(device, queue, sim);
        }
        self.list.extend(touched);
        self.ptr.push(self.list.len() as u32);
        self.bin += 1;
        let second_done = self.bin % WINDOW_MS as usize == 0;
        if second_done {
            self.flush(device, queue, sim);
        }
        second_done.then(|| std::mem::replace(&mut self.labels, vec![Vec::new(); self.encs.len()]))
    }

    /// Sends the bins played since the last flush to the GPU: one upload, one submit.
    pub fn flush(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, sim: &Sim) {
        let bins = self.ptr.len() - 1;
        if bins == 0 {
            return;
        }
        sim.set_input(queue, &self.list, &self.ptr);
        let mut c = device.create_command_encoder(&Default::default());
        sim.encode_bins(&mut c, bins);
        queue.submit([c.finish()]);
        self.list.clear();
        self.ptr.truncate(1);
    }

    /// Per fly: the entities of its recent event with the highest history count (latest wins ties).
    pub fn suspects(&mut self) -> Vec<Vec<String>> {
        let now = self.bin as f64 / WINDOW_MS as f64;
        self.recent
            .iter_mut()
            .map(|q| {
                while q.front().is_some_and(|(t, _, _)| *t < now - SUSPECT_S) {
                    q.pop_front();
                }
                q.iter().rev().max_by_key(|(_, count, _)| *count).map(|(_, _, e)| e.clone()).unwrap_or_default()
            })
            .collect()
    }
}

/// Spike counts of the TRACED populations per fly, from one second's `fired`.
pub fn windows(fly: &Fly, fired: &[u32], labels: Vec<Vec<String>>, mut suspects: Vec<Vec<String>>) -> Vec<Window> {
    let traced: Vec<Vec<u32>> = TRACED.iter().map(|c| fly.of_class(c)).collect();
    labels
        .into_iter()
        .enumerate()
        .map(|(f, labels)| {
            let at = |i: u32| fired[(i + f as u32 * fly.n) as usize];
            let spikes = std::array::from_fn(|k| traced[k].iter().map(|&i| at(i)).sum());
            Window { spikes, labels, suspects: std::mem::take(&mut suspects[f]) }
        })
        .collect()
}

/// Plays `seconds` of events through one fly per encoder, all at once. Returns windows as
/// [fly][second]. With `learn`, each fly's mushroom body learns from its own labels every second.
#[allow(clippy::too_many_arguments)]
pub fn play(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    sim: &Sim,
    fly: &Fly,
    encs: &[Encoder],
    events: &[Event],
    seconds: usize,
    mut learn: Option<&mut MushroomBody>,
) -> Vec<Vec<Window>> {
    let mut player = Player::new(device, queue, sim, fly.n, encs, events);
    let mut out: Vec<Vec<Window>> = (0..encs.len()).map(|_| Vec::with_capacity(seconds)).collect();
    while player.second() < seconds {
        let Some(labels) = player.step(device, queue, sim) else { continue };
        let fired = sim.take_fired(device, queue);
        if let Some(mb) = learn.as_deref_mut() {
            for (f, l) in labels.iter().enumerate() {
                let range = mb.of_fly(f, fly.n);
                mb.learn(&fired, is_safe(l), range);
            }
            sim.set_plastic(queue, &mb.plastic.w);
        }
        let suspects = player.suspects();
        for (f, w) in windows(fly, &fired, labels, suspects).into_iter().enumerate() {
            out[f].push(w);
        }
    }
    out
}

/// Colour class per circuit neuron for the viewer: receptors, antennal lobe, Kenyon cells,
/// lateral horn, output neurons (indices into the viewer's palette).
pub fn colours(fly: &Fly) -> Vec<u32> {
    let kc = member(fly, "Kenyon_Cell");
    let layer = |i: usize| {
        let class = fly.names.cell_class.get(fly.cell_class[i] as usize).map_or("", |s| s.as_str());
        LAYERS.iter().position(|l| l.contains(&class)).unwrap_or(0)
    };
    (0..fly.n as usize).map(|i| match (layer(i), kc[i]) {
        (0, _) => 2,     // receptors: green
        (1, _) => 4,     // antennal lobe: purple
        (2, true) => 1,  // Kenyon cells: orange
        (2, false) => 6, // lateral horn: teal
        _ => 9,          // output neurons and APL: pink
    }).collect()
}

/// Alert threshold from benign windows, in readout spikes.
pub fn threshold(benign: &[Window]) -> f64 {
    let xs: Vec<f64> = benign.iter().skip(WARMUP_S).map(|w| w.spikes[DETECT_ON] as f64).collect();
    let mean = xs.iter().sum::<f64>() / xs.len().max(1) as f64;
    let std = (xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / xs.len().max(1) as f64).sqrt();
    (mean + Z_ALERT * std).max(MIN_ALERT)
}

/// Seconds covered by a sorted event list.
pub fn duration(events: &[Event]) -> usize {
    events.last().map_or(0, |e| e.ts.ceil() as usize)
}

pub fn alerts(windows: &[Window], threshold: f64) -> Vec<usize> {
    (WARMUP_S..windows.len()).filter(|&s| windows[s].spikes[DETECT_ON] as f64 > threshold).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::Names;

    #[test]
    fn events_map_to_stable_glomerulus_combinations() {
        // neurons 0-2 are ORN type A, 3-4 type B, 5-6 type C, 7 is not olfactory
        let fly = Fly {
            n: 8,
            pos: vec![],
            class: vec![],
            cell_class: vec![0, 0, 0, 0, 0, 0, 0, 1],
            cell_type: vec![0, 0, 0, 1, 1, 2, 2, 3],
            names: Names { cell_class: vec!["olfactory".into(), "other".into()], cell_type: vec![] },
        };
        let enc = Encoder::new(&fly, &["conn"]);
        let ev = |port| Event { kind: "conn".into(), src: Some("10.0.0.1".into()), dport: Some(port), ..Default::default() };
        let fired = |e: &Event| enc.neurons(e, &[]).map(|n| n.collect::<Vec<u32>>());
        let a = fired(&ev(443)).unwrap();
        assert_eq!(Some(a.clone()), fired(&ev(443)), "same key, same odour");
        assert!(!a.contains(&7), "only receptor neurons");
        assert!(a.len() >= 2 && a.len() <= 12, "{a:?}: up to 2 fields x 2 whole glomeruli");
        assert!((0..50).any(|p| fired(&ev(p)).unwrap() != a), "different ports, different odours");
        assert!(fired(&Event { kind: "dns".into(), ..Default::default() }).is_none(), "other kinds pass by");
        // 3 glomeruli: 1 reserved for history (type C, neurons 5-6), fields hash into A and B
        assert!((0..50).all(|p| fired(&ev(p)).unwrap().iter().all(|&n| n < 5)), "fields never reach history glomeruli");
        let hist = enc.neurons(&ev(443), &["src_ports=6".into()]).unwrap().collect::<Vec<u32>>();
        assert!(hist.contains(&5) && hist.contains(&6), "history lights its reserved glomerulus");
    }

    #[test]
    fn history_counts_fan_out_over_a_minute_and_a_long_window() {
        let mut h = History::default();
        let fail = |ts: f64, user: &str| Event {
            ts,
            kind: "auth".into(),
            user: Some(user.into()),
            src: Some("10.0.0.7".into()),
            result: Some("fail".into()),
            ..Default::default()
        };
        // a typo: the same user failing again stays at 1 distinct user (bucket 1)
        assert_eq!(h.observe(&fail(0.0, "u01")).components, ["src_failed_users=1", "src_failed_users_long=1"]);
        assert_eq!(h.observe(&fail(5.0, "u01")).components, ["src_failed_users=1", "src_failed_users_long=1"]);
        // a spray: 8 distinct users -> bucket 4 (8..15)
        let mut last: Vec<String> = vec![];
        for (k, u) in ["u02", "u03", "u04", "u05", "u06", "u07", "u08"].iter().enumerate() {
            last = h.observe(&fail(10.0 + k as f64, u)).components;
        }
        assert_eq!(last, ["src_failed_users=4", "src_failed_users_long=4"]);
        // a minute later the short count has expired, the long one still sees all 9 users (a slow
        // spray adds up there); the suspect is the failing source and the user
        let seen = h.observe(&fail(100.0, "u09"));
        assert_eq!(seen.components, ["src_failed_users=1", "src_failed_users_long=4"]);
        assert_eq!(seen.count, 9);
        // 15 minutes later both have expired
        assert_eq!(h.observe(&fail(1100.0, "u01")).components, ["src_failed_users=1", "src_failed_users_long=1"]);
        assert_eq!(seen.entities, ["10.0.0.7", "u09"]);
        // a success adds nothing: u01 from 1100 s is still the only failed user (ISSUES R1)
        let ok = Event { result: Some("ok".into()), ..fail(1101.0, "u02") };
        assert_eq!(h.observe(&ok).components, ["src_failed_users=1", "src_failed_users_long=1"]);
    }

    #[test]
    fn safe_windows_depress_active_synapses_attacks_restore_them() {
        // neuron 0 is a Kenyon cell with one plastic synapse onto neuron 1
        let plastic = Plastic { row_ptr: vec![0, 1, 1], pre: vec![0], post: vec![1], w: vec![10.0] };
        let mut mb = MushroomBody { plastic, w0: vec![10.0] };
        mb.learn(&[0, 5], true, 0..1);
        assert!(mb.plastic.w[0] == 10.0, "a silent Kenyon cell learns nothing");
        mb.learn(&[5, 0], true, 0..1);
        let depressed = mb.plastic.w[0];
        assert!(depressed < 10.0);
        mb.learn(&[5, 0], false, 0..1);
        assert!(mb.plastic.w[0] > depressed && mb.plastic.w[0] <= 10.0);
        assert!(is_safe(&["benign".into(), "benign_burst@40".into()]));
        assert!(!is_safe(&["benign".into(), "portscan@60".into()]));
    }
}
