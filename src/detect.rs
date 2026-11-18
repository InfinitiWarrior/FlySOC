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
    /// Since the last sleep, per plastic synapse: safe windows seen, and those in which its
    /// Kenyon cell fired. Sleep turns them into a frequency (Phase 10).
    safe: Vec<u32>,
    seen: Vec<u32>,
}

/// Sleep's rarity scale: a Kenyon cell active in this fraction of safe windows is restored to at
/// least 1/e of its resting output weight; rarer cells to more, commoner ones to less. The
/// thresholds' calm quantile (cluster.rs CALM_QUANTILE 0.995) draws the same line: once in 200 s.
const RARE: f32 = 0.005;

impl MushroomBody {
    pub fn split(fly: &Fly, syn: Synapses) -> (Synapses, Self) {
        let (kc, mbon) = (member(fly, "Kenyon_Cell"), member(fly, "MBON"));
        let (fixed, mut plastic) = syn.split(|pre, post| kc[pre as usize] && mbon[post as usize]);
        plastic.w.iter_mut().for_each(|w| *w *= INIT_GAIN);
        let w0 = plastic.w.clone();
        let n = w0.len();
        (fixed, Self { plastic, w0, safe: vec![0; n], seen: vec![0; n] })
    }

    /// `k` independent copies, one per fly, for a simulation holding `k` circuits of `n` neurons.
    pub fn replicate(&self, k: usize, n: u32) -> Self {
        Self { plastic: self.plastic.replicate(k, n), w0: self.w0.repeat(k), safe: self.safe.repeat(k), seen: self.seen.repeat(k) }
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
            if safe {
                self.safe[j] += 1;
                self.seen[j] += (a > 0.0) as u32;
            }
            if a > 0.0 {
                p.w[j] = match safe {
                    true => p.w[j] * (1.0 - LR_SAFE).powf(a),
                    false => self.w0[j] + (p.w[j] - self.w0[j]) * (1.0 - LR_RECOVER).powf(a),
                };
            }
        }
    }
}


impl MushroomBody {
    /// Sleep (Phase 10): every output synapse is restored to at least w0 * exp(-f / RARE), f being
    /// how often its Kenyon cell fired in safe windows since the last sleep. It only gives weight
    /// back: what attacks and common patterns taught by day stays, while a pattern met harmlessly
    /// once or twice is no longer silenced for good. (Overwriting the day's weights instead
    /// destroyed what attacks taught: ISSUES O17.) Fruit fly synapses are rescaled in sleep (Bushey
    /// et al. 2011); restoring by rarity is our model of it, not a measured rule.
    pub fn sleep(&mut self) {
        for j in 0..self.w0.len() {
            let f = self.seen[j] as f32 / self.safe[j].max(1) as f32;
            self.plastic.w[j] = self.plastic.w[j].max(self.floor(j, f));
        }
        self.safe.iter_mut().for_each(|x| *x = 0);
        self.seen.iter_mut().for_each(|x| *x = 0);
    }

    /// The weight sleep restores synapse `j` to at least, for a safe-window frequency `f`.
    fn floor(&self, j: usize, f: f32) -> f32 {
        self.w0[j] * (-f / RARE).exp()
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
#[derive(Deserialize, Default, Clone)]
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
    /// Whether `who` (a host or user) takes part in this event.
    pub fn involves(&self, who: &str) -> bool {
        [&self.src, &self.dst, &self.user, &self.host].iter().any(|x| x.as_deref() == Some(who))
    }

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
pub const LONG_HISTORY_S: f64 = 900.0;

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
        Seen { components, count: long, entities: e.entities(), what: name }
    }
}

/// What `History` made of one event.
#[derive(Default)]
pub struct Seen {
    pub components: Vec<String>,
    pub count: usize,
    pub entities: Vec<String>,
    pub what: &'static str, // which count: "src_ports", "src_failed_users", ... ("" for none)
}

/// Why FlySOC suspects an entity when a fly fires: which history count was the most extreme among
/// the fly's recent events, and how high (the longest window's count). Bookkeeping, not the fly's
/// choice: whether the fly fired because of it is what `cluster::verify` tests. Phase 11.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reason {
    pub what: &'static str,
    pub count: usize,
}

/// One sentence an analyst can check against the logs, and the ATT&CK technique the behaviour is
/// consistent with (None when the count is no fan-out: the fly then reacted to the event itself).
/// `who` is the suspect's first entity: the source, or the host.
pub fn describe(r: Reason, who: &str) -> (String, Option<&'static str>) {
    let (text, technique) = match r.what {
        "src_ports" => (format!("{who} connected to {} distinct ports in 15 minutes", r.count), "T1046 Network Service Discovery"),
        "src_failed_users" => (format!("{} distinct users failed to log in from {who} in 15 minutes", r.count), "T1110.003 Password Spraying"),
        "host_processes" => (format!("{} distinct processes started on {who} in 1 minute", r.count), "T1569.002 Service Execution"),
        "names_per_domain" => (format!("{who} looked up {} distinct names under one domain in 15 minutes", r.count), "T1048 Exfiltration Over Alternative Protocol (DNS)"),
        _ => return (format!("unusual activity involving {who}"), None),
    };
    match r.count {
        0 | 1 => (format!("no fan-out behind {who} (count {}): the fly reacted to the event itself, a combination it has rarely smelled as safe", r.count), None),
        _ => (text, Some(technique)),
    }
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
    /// SUSPECT_S seconds: who FlySOC names if the fly is alarmed (bookkeeping, not the fly's choice).
    pub suspects: Vec<String>,
    /// Why they are suspected (Phase 11).
    pub reason: Option<Reason>,
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
    recent: Vec<std::collections::VecDeque<(f64, usize, Vec<String>, &'static str)>>, // per fly: (ts, count, entities, what)
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
                self.recent[f].push_back((e.ts, seen.count, seen.entities.clone(), seen.what));
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

    /// Per fly: the entities of its recent event with the highest history count (latest wins
    /// ties), and that count as the reason to blame them.
    pub fn suspects(&mut self) -> Vec<(Vec<String>, Option<Reason>)> {
        let now = self.bin as f64 / WINDOW_MS as f64;
        self.recent
            .iter_mut()
            .map(|q| {
                while q.front().is_some_and(|(t, ..)| *t < now - SUSPECT_S) {
                    q.pop_front();
                }
                match q.iter().rev().max_by_key(|(_, count, ..)| *count) {
                    Some((_, count, e, what)) => (e.clone(), Some(Reason { what, count: *count })),
                    None => (vec![], None),
                }
            })
            .collect()
    }
}

/// Spike counts of the TRACED populations per fly, from one second's `fired`.
pub fn windows(fly: &Fly, fired: &[u32], labels: Vec<Vec<String>>, mut suspects: Vec<(Vec<String>, Option<Reason>)>) -> Vec<Window> {
    let traced: Vec<Vec<u32>> = TRACED.iter().map(|c| fly.of_class(c)).collect();
    labels
        .into_iter()
        .enumerate()
        .map(|(f, labels)| {
            let at = |i: u32| fired[(i + f as u32 * fly.n) as usize];
            let spikes = std::array::from_fn(|k| traced[k].iter().map(|&i| at(i)).sum());
            let (suspects, reason) = std::mem::take(&mut suspects[f]);
            Window { spikes, labels, suspects, reason }
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
    learn: Option<&mut MushroomBody>,
) -> Vec<Vec<Window>> {
    play_primed(device, queue, sim, fly, encs, &[], events, seconds, learn)
}

/// `play`, after feeding `prime` (earlier events, negative times) to the history counts only, not
/// to the flies: a replay of a stretch in the middle of a file sees the counts it would have had,
/// without simulating everything before it (counterfactual attribution, `cluster::verify`).
#[allow(clippy::too_many_arguments)]
pub fn play_primed(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    sim: &Sim,
    fly: &Fly,
    encs: &[Encoder],
    prime: &[Event],
    events: &[Event],
    seconds: usize,
    mut learn: Option<&mut MushroomBody>,
) -> Vec<Vec<Window>> {
    let mut player = Player::new(device, queue, sim, fly.n, encs, events);
    prime.iter().for_each(|e| {
        player.history.observe(e);
    });
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
        assert_eq!(seen.what, "src_failed_users", "the reason names which count it is (Phase 11)");
        // a success adds nothing: u01 from 1100 s is still the only failed user (ISSUES R1)
        let ok = Event { result: Some("ok".into()), ..fail(1101.0, "u02") };
        assert_eq!(h.observe(&ok).components, ["src_failed_users=1", "src_failed_users_long=1"]);
    }

    #[test]
    fn every_kind_of_event_names_its_count() {
        // Phase 11: History reports which count it computed, so an alert can say what it saw
        let mut h = History::default();
        let ev = |kind: &str| Event { kind: kind.into(), src: Some("C1".into()), host: Some("C1".into()), ..Default::default() };
        for (kind, what) in [("conn", "src_ports"), ("auth", "src_failed_users"), ("proc", "host_processes"), ("dns", "names_per_domain"), ("other", "")] {
            assert_eq!(h.observe(&ev(kind)).what, what, "kind {kind}");
        }
    }

    #[test]
    fn alerts_describe_what_was_seen_and_the_technique() {
        // Phase 11: one checkable sentence per count, and the ATT&CK technique it is consistent with
        let cases = [
            ("src_ports", 40, "C17693 connected to 40 distinct ports in 15 minutes", "T1046"),
            ("src_failed_users", 6, "6 distinct users failed to log in from C17693 in 15 minutes", "T1110.003"),
            ("host_processes", 5, "5 distinct processes started on C17693 in 1 minute", "T1569.002"),
            ("names_per_domain", 120, "C17693 looked up 120 distinct names under one domain in 15 minutes", "T1048"),
        ];
        for (what, count, text, technique) in cases {
            let (got, t) = describe(Reason { what, count }, "C17693");
            assert_eq!(got, text, "{what}");
            assert!(t.is_some_and(|t| t.starts_with(technique)), "{what}: technique {t:?}, want {technique}");
        }
        // a count of 0 or 1 is no fan-out: say so, and claim no technique
        for count in [0, 1] {
            let (got, t) = describe(Reason { what: "src_failed_users", count }, "C5");
            assert!(got.starts_with("no fan-out") && got.contains("reacted to the event itself"), "count {count}: {got}");
            assert_eq!(t, None, "count {count}: no technique without fan-out");
        }
        // a kind without a count claims nothing either
        assert_eq!(describe(Reason { what: "", count: 9 }, "C5"), ("unusual activity involving C5".to_string(), None));
    }

    #[test]
    fn windows_carry_each_fly_s_suspects_and_reason() {
        // two flies of the tiny fly's 8 neurons; their reasons must come through untouched
        let fly = tiny_fly();
        let r = Reason { what: "src_ports", count: 40 };
        let w = windows(&fly, &[0; 16], vec![vec![], vec![]], vec![(vec!["C1".into()], Some(r)), (vec![], None)]);
        assert_eq!(w[0].suspects, ["C1"]);
        assert_eq!(w[0].reason, Some(r));
        assert_eq!(w[1].reason, None);
    }

    #[test]
    fn safe_windows_depress_active_synapses_attacks_restore_them() {
        // neuron 0 is a Kenyon cell with one plastic synapse onto neuron 1
        let plastic = Plastic { row_ptr: vec![0, 1, 1], pre: vec![0], post: vec![1], w: vec![10.0] };
        let mut mb = MushroomBody { plastic, w0: vec![10.0], safe: vec![0], seen: vec![0] };
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

    /// A tiny fly: neurons 0-2 are ORN type A, 3-4 type B, 5-6 type C, 7 is not olfactory. With
    /// three glomeruli one (C, neurons 5-6) is reserved for history, fields hash into A and B.
    fn tiny_fly() -> Fly {
        Fly {
            n: 8,
            pos: vec![],
            class: vec![],
            cell_class: vec![0, 0, 0, 0, 0, 0, 0, 1],
            cell_type: vec![0, 0, 0, 1, 1, 2, 2, 3],
            names: Names { cell_class: vec!["olfactory".into(), "other".into()], cell_type: vec![] },
        }
    }

    fn conn(src: &str, port: u16) -> Event {
        Event { kind: "conn".into(), src: Some(src.into()), dport: Some(port), ..Default::default() }
    }

    fn odour(enc: &Encoder, e: &Event, history: &[String]) -> Option<Vec<u32>> {
        enc.neurons(e, history).map(|n| n.collect())
    }

    #[test]
    fn shards_split_every_event_to_exactly_one_individual() {
        // O15: with n shards, each event is smelled by exactly one of them, chosen by its origin
        // (the source, or the host for process and DNS events), the same every time
        let fly = tiny_fly();
        for n in [2, 3, 10] {
            let shards: Vec<Encoder> = (0..n).map(|k| Encoder::new(&fly, &["conn", "proc"]).shard(k, n)).collect();
            for i in 0..200 {
                let e = conn(&format!("C{i}"), 445);
                let who: Vec<usize> = (0..n).filter(|&k| odour(&shards[k], &e, &[]).is_some()).collect();
                assert_eq!(who.len(), 1, "{n} shards, source C{i}: smelled by {who:?}, expected exactly one");
                let again: Vec<usize> = (0..n).filter(|&k| odour(&shards[k], &e, &[]).is_some()).collect();
                assert_eq!(who, again, "the same source always lands on the same shard");
                // a different port from the same source stays with that source's shard
                let other_port = conn(&format!("C{i}"), 22);
                assert!(odour(&shards[who[0]], &other_port, &[]).is_some(), "shards split by source, not by port");
                // a process event is split by its host
                let p = Event { kind: "proc".into(), host: Some(format!("C{i}")), process: Some("P1".into()), ..Default::default() };
                assert_eq!((0..n).filter(|&k| odour(&shards[k], &p, &[]).is_some()).count(), 1, "host C{i}: one shard");
            }
            // every shard gets some of 200 sources: the split is not degenerate
            for k in 0..n {
                assert!((0..200).any(|i| odour(&shards[k], &conn(&format!("C{i}"), 445), &[]).is_some()), "shard {k} of {n} smells nothing");
            }
        }
    }

    #[test]
    fn one_shard_is_the_unsharded_fly() {
        let fly = tiny_fly();
        let (plain, one) = (Encoder::new(&fly, &["conn"]), Encoder::new(&fly, &["conn"]).shard(0, 1));
        for i in 0..50 {
            let e = conn(&format!("10.0.0.{i}"), 80 + i as u16);
            assert_eq!(odour(&plain, &e, &[]), odour(&one, &e, &[]), "shard 0 of 1 must smell exactly like the plain fly");
        }
    }

    /// A fly with the real circuit's 53 glomeruli, one receptor neuron each (neuron i = glomerulus i).
    fn fly53() -> Fly {
        Fly {
            n: 53,
            pos: vec![],
            class: vec![],
            cell_class: vec![0; 53],
            cell_type: (0..53).collect(),
            names: Names { cell_class: vec!["olfactory".into()], cell_type: vec![] },
        }
    }

    fn lit(enc: &Encoder, e: &Event, history: &[String]) -> std::collections::BTreeSet<u32> {
        odour(enc, e, history).unwrap().into_iter().collect()
    }

    #[test]
    fn history_only_smells_how_many_not_who() {
        // Phase 9: the identity fly smells only history components. Different names with the same
        // counts must smell identical, and with no fields there is no odour without history.
        let fly = fly53();
        let enc = Encoder::new(&fly, &["auth"]).history_only();
        let auth = |src: &str, user: &str| Event { kind: "auth".into(), src: Some(src.into()), user: Some(user.into()), result: Some("fail".into()), ..Default::default() };
        let h = |short: u32, long: u32| vec![format!("src_failed_users={short}"), format!("src_failed_users_long={long}")];
        assert_eq!(odour(&enc, &auth("C1", "U1"), &[]), Some(vec![]), "no history, no odour: names alone smell of nothing");
        for (sh, lo) in [(0, 0), (1, 1), (1, 5), (3, 4)] {
            assert_eq!(lit(&enc, &auth("C1", "U1"), &h(sh, lo)), lit(&enc, &auth("C17693", "U8946"), &h(sh, lo)), "counts {sh}/{lo}: two different sources must smell the same");
        }
        // counts land only on the 20 reserved glomeruli (33..52), never on a field's
        for b in 0..8 {
            assert!(lit(&enc, &auth("C1", "U1"), &h(b, b)).iter().all(|&g| (33..53).contains(&g)), "bucket {b} leaves the reserved glomeruli");
        }
        // the full fly does tell the two apart, which is what drowned the counts (O16)
        let full = Encoder::new(&fly, &["auth"]);
        assert_ne!(lit(&full, &auth("C1", "U1"), &h(1, 1)), lit(&full, &auth("C17693", "U8946"), &h(1, 1)));
        // other kinds still pass by
        assert!(odour(&enc, &Event { kind: "dns".into(), ..Default::default() }, &h(1, 1)).is_none());
    }

    #[test]
    fn flies_with_fields_keep_the_overlapping_code() {
        // O7: 20 reserved glomeruli (33 for fields), 10 per code, where bucket b lights b .. b+3 and
        // neighbours share 3 of 4; pinned glomerulus for glomerulus (a disjoint code was tried, O16)
        let fly = fly53();
        let enc = Encoder::new(&fly, &["auth"]);
        let e = Event { kind: "auth".into(), src: Some("C1".into()), user: Some("U1".into()), result: Some("fail".into()), ..Default::default() };
        let fields = lit(&enc, &e, &[]);
        let hist = |c: &str| -> std::collections::BTreeSet<u32> { lit(&enc, &e, &[c.to_string()]).difference(&fields).copied().collect() };
        for b in 0..7u32 {
            let want: std::collections::BTreeSet<u32> = (33 + b..33 + b + 4).map(|g| g.min(42)).collect();
            assert_eq!(hist(&format!("src_failed_users={b}")), want, "short bucket {b}");
            let want_long: std::collections::BTreeSet<u32> = (43 + b..43 + b + 4).map(|g| g.min(52)).collect();
            assert_eq!(hist(&format!("src_failed_users_long={b}")), want_long, "long bucket {b}");
        }
    }

    /// `k` Kenyon cells (neurons 0..k), each with one plastic synapse onto neuron k, resting at `w0`.
    fn body(w0: &[f32]) -> MushroomBody {
        let k = w0.len() as u32;
        let mut row_ptr: Vec<u32> = (0..=k).collect();
        row_ptr.push(k);
        let plastic = Plastic { row_ptr, pre: (0..k).collect(), post: vec![k; k as usize], w: w0.to_vec() };
        MushroomBody { plastic, w0: w0.to_vec(), safe: vec![0; k as usize], seen: vec![0; k as usize] }
    }

    /// Spikes per neuron for one window: `cells` fire `spikes` each, everyone else is silent.
    fn spikes(n: usize, cells: &[usize], spikes: u32) -> Vec<u32> {
        let mut v = vec![0; n + 1];
        cells.iter().for_each(|&c| v[c] = spikes);
        v
    }

    /// The restore floor: w0 * exp(-(seen / safe) / RARE).
    fn floor(w0: f32, seen: u32, safe: u32) -> f32 {
        w0 * (-(seen as f32 / safe as f32) / RARE).exp()
    }

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() <= 1e-4 * b.abs().max(1e-6)
    }

    /// Sets a synapse's day by hand: its weight at nightfall and its counts.
    fn day(mb: &mut MushroomBody, j: usize, w: f32, seen: u32, safe: u32) {
        mb.plastic.w[j] = w;
        mb.seen[j] = seen;
        mb.safe[j] = safe;
    }

    #[test]
    fn sleep_restores_rare_patterns_and_leaves_common_ones_down() {
        // two Kenyon cells: cell 0 fires in 1 of 1000 safe windows, cell 1 in half of them
        let mut mb = body(&[10.0, 10.0]);
        for t in 0..1000 {
            let mut f = spikes(2, &[], 0);
            f[0] = (t == 999) as u32 * 5; // once, at the end of the day: no time to recover by day
            f[1] = (t % 2) as u32;
            mb.learn(&f, true, 0..2);
        }
        let (rare_day, common_day) = (mb.plastic.w[0], mb.plastic.w[1]);
        mb.sleep();
        let (rare, common) = (mb.plastic.w[0], mb.plastic.w[1]);
        assert!(rare > 8.0 && rare > rare_day, "seen once in 1000: restored from {rare_day} to most of its weight, got {rare}");
        // by day the per-window recovery holds a cell seen every other window near 0.35 (of 10);
        // sleep's floor for f = 0.5 is ~0, so it leaves it exactly where the day did
        assert!(common < 1.0 && common == common_day, "seen in half: stays where the day left it ({common_day} -> {common})");
        assert_eq!(mb.seen, [0, 0], "counts start again after sleep");
        assert_eq!(mb.safe, [0, 0], "safe-window counts start again after sleep");
    }

    #[test]
    fn sleep_is_the_max_of_the_day_and_the_floor() {
        // w <- max(w_day, w0 exp(-f / RARE)), for day weights below, at and above the floor
        let fs: [(u32, u32); 6] = [(0, 2000), (1, 2000), (5, 2000), (10, 2000), (100, 2000), (2000, 2000)];
        for &(seen, safe) in &fs {
            let fl = floor(7.5, seen, safe);
            for w_day in [0.0001, fl * 0.5, fl, (fl + 7.5) / 2.0, 7.5] {
                let mut mb = body(&[7.5]);
                day(&mut mb, 0, w_day, seen, safe);
                mb.sleep();
                let want = w_day.max(fl);
                assert!(close(mb.plastic.w[0], want), "seen {seen}/{safe}, day weight {w_day}: got {}, want {want}", mb.plastic.w[0]);
            }
        }
    }

    #[test]
    fn sleep_never_lowers_a_weight() {
        // pseudo-random days: random firing, spike counts, labels and resting weights; every weight
        // after sleep is at least its weight before, and finite in [0, w0]
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for d in 0..20 {
            let n = 40;
            let w0: Vec<f32> = (0..n).map(|_| 0.01 + (rnd() % 1000) as f32 / 10.0).collect();
            let mut mb = body(&w0);
            for _ in 0..(1 + rnd() % 3000) {
                let f: Vec<u32> = (0..=n).map(|_| if rnd() % 4 == 0 { (rnd() % 20) as u32 } else { 0 }).collect();
                mb.learn(&f, rnd() % 10 != 0, 0..n);
            }
            let before = mb.plastic.w.clone();
            mb.sleep();
            for c in 0..n {
                let w = mb.plastic.w[c];
                assert!(w >= before[c], "day {d}, cell {c}: sleep lowered {} to {w}", before[c]);
                assert!(w.is_finite() && w >= 0.0 && w <= w0[c], "day {d}, cell {c}: weight {w} outside [0, {}]", w0[c]);
            }
        }
    }

    #[test]
    fn a_cell_active_in_exactly_rare_of_safe_windows_is_restored_to_one_over_e() {
        let safe = (1.0 / RARE).round() as u32 * 10; // 2000 for RARE = 0.005
        let mut mb = body(&[1.0]);
        day(&mut mb, 0, 0.0, safe / 200, safe); // f = 1/200 = RARE, silenced by day
        mb.sleep();
        assert!(close(mb.plastic.w[0], (-1.0f32).exp()), "f = RARE should restore w0/e = 0.3679, got {}", mb.plastic.w[0]);
    }

    #[test]
    fn the_floor_falls_strictly_as_frequency_rises() {
        // every cell silenced by day: what sleep gives back falls strictly with frequency
        let n = 30;
        let mut mb = body(&vec![10.0; n]);
        for c in 0..n {
            day(&mut mb, c, 0.0, 3 * c as u32, 3000);
        }
        mb.sleep();
        let w = &mb.plastic.w;
        for c in 1..n {
            assert!(w[c] < w[c - 1], "cell {c} (more frequent) restored to {} not below cell {} ({})", w[c], c - 1, w[c - 1]);
        }
        assert_eq!(w[0], 10.0, "a cell never seen is restored to its resting weight exactly");
    }

    #[test]
    fn sleep_leaves_what_attacks_taught() {
        // the O17 lesson: a cell restored by day during attacks but common in safe seconds keeps
        // its day weight; the overwrite version silenced it
        let mut mb = body(&[10.0]);
        day(&mut mb, 0, 9.0, 500, 1000); // f = 0.5: floor ~0, but the day left it at 9
        mb.sleep();
        assert_eq!(mb.plastic.w[0], 9.0, "sleep must not take away weight the day left");
    }

    #[test]
    fn attack_windows_do_not_count_as_harmless() {
        // cell 0 fires only during attacks, cell 1 only in safe windows (half of them)
        let mut mb = body(&[10.0, 10.0]);
        for t in 0..1000 {
            let safe = t % 10 != 0; // 100 attack windows, 900 safe
            let cells: Vec<usize> = if safe { if t % 2 == 1 { vec![1] } else { vec![] } } else { vec![0] };
            mb.learn(&spikes(2, &cells, 4), safe, 0..2);
        }
        assert_eq!(mb.safe, [900, 900], "only the 900 safe windows are counted, for every synapse");
        assert_eq!(mb.seen[0], 0, "firing in attack windows is not a harmless sighting");
        mb.sleep();
        assert_eq!(mb.plastic.w[0], 10.0, "a cell only ever active during attacks keeps its full weight");
        assert!(mb.plastic.w[1] < 1.0, "a cell active in half the safe windows stays far below rest: {}", mb.plastic.w[1]);
    }

    #[test]
    fn several_spikes_in_one_window_are_one_sighting() {
        // frequency is over windows, not spikes: 1 spike or 50 in a window count the same
        let mut mb = body(&[10.0, 10.0]);
        for t in 0..1000 {
            let mut f = spikes(2, &[], 0);
            if t < 3 {
                f[0] = 1;
                f[1] = 50;
            }
            mb.learn(&f, true, 0..2);
        }
        assert_eq!(mb.seen, [3, 3]);
        assert_eq!(mb.safe, [1000, 1000]);
        // same counts, so the same floor: silence both by hand and compare what sleep restores
        mb.plastic.w = vec![0.0, 0.0];
        mb.sleep();
        assert_eq!(mb.plastic.w[0], mb.plastic.w[1], "spike counts within a window must not change the floor");
        assert!(close(mb.plastic.w[0], floor(10.0, 3, 1000)));
    }

    #[test]
    fn one_harmless_sighting_no_longer_blinds_the_fly() {
        // the bug sleep fixes (O16): by day, a single harmless sighting with several spikes cuts a
        // synapse by (1 - LR_SAFE)^spikes at once; at night that pattern is rare, so it is restored
        let mut mb = body(&[10.0]);
        for _ in 0..999 {
            mb.learn(&spikes(1, &[], 0), true, 0..1);
        }
        mb.learn(&spikes(1, &[0], 5), true, 0..1); // seen once, at the end of the day
        let awake = mb.plastic.w[0];
        assert!(awake < 6.0, "by day one sighting of 5 spikes leaves {awake} (10 x 0.9^5 = 5.9)");
        mb.sleep();
        let slept = mb.plastic.w[0];
        assert!(close(slept, floor(10.0, 1, 1000)), "after sleep: {slept}, want {}", floor(10.0, 1, 1000));
        assert!(slept > awake + 2.0, "sleep must give the rare pattern back most of its weight: {awake} -> {slept}");
    }

    #[test]
    fn a_pattern_absent_today_is_fully_restored_tonight() {
        // day 1: cell 0 common (stays down). Day 2: cell 0 silent, cell 1 common. The second night
        // sees only day 2: cell 0 was never seen, so it is restored to rest; cell 1 stays down.
        let mut mb = body(&[10.0, 10.0]);
        for t in 0..1000 {
            mb.learn(&spikes(2, if t % 2 == 0 { &[0] } else { &[] }, 1), true, 0..2);
        }
        mb.sleep();
        assert!(mb.plastic.w[0] < 1.0 && mb.plastic.w[1] == 10.0, "after day 1: {:?}", mb.plastic.w);
        for t in 0..1000 {
            mb.learn(&spikes(2, if t % 2 == 0 { &[1] } else { &[] }, 1), true, 0..2);
        }
        mb.sleep();
        assert!(mb.plastic.w[0] == 10.0 && mb.plastic.w[1] < 1.0, "after day 2: {:?}", mb.plastic.w);
    }

    #[test]
    fn a_day_without_harmless_windows_leaves_every_weight_at_rest() {
        // no safe window at all (everything labelled attack): no frequency, no division by zero
        let mut mb = body(&[3.0, 4.0]);
        for _ in 0..100 {
            mb.learn(&spikes(2, &[0, 1], 2), false, 0..2);
        }
        mb.sleep();
        assert_eq!(mb.plastic.w, [3.0, 4.0]);
        // and sleeping twice in a row, with nothing in between, changes nothing
        mb.sleep();
        assert_eq!(mb.plastic.w, [3.0, 4.0]);
    }

    #[test]
    fn the_floor_scales_with_each_synapse_s_resting_weight() {
        // three cells with the same counts but resting weights 1, 10, 100, all silenced by day:
        // each is restored to the same fraction of its own resting weight
        let mut mb = body(&[1.0, 10.0, 100.0]);
        for c in 0..3 {
            day(&mut mb, c, 0.0, 4, 1000);
        }
        mb.sleep();
        let kept: Vec<f32> = (0..3).map(|c| mb.plastic.w[c] / mb.w0[c]).collect();
        assert!(close(kept[0], kept[1]) && close(kept[1], kept[2]), "fractions restored differ: {kept:?}");
    }

    #[test]
    fn replicated_flies_count_and_sleep_independently() {
        // two flies of 3 neurons each (2 Kenyon cells onto neuron 2); only fly 0 lives a day
        let one = body(&[10.0, 10.0]);
        let mut mb = one.replicate(2, 3);
        assert_eq!(mb.w0.len(), 4);
        let r0 = mb.of_fly(0, 3);
        assert_eq!(r0, 0..2);
        for t in 0..1000 {
            let mut f = vec![0u32; 6];
            f[0] = (t % 2) as u32; // fly 0, cell 0: common
            f[3] = (t % 2) as u32; // fly 1, cell 0 fires too, but fly 1 does not learn
            mb.learn(&f, true, r0.clone());
        }
        assert_eq!(&mb.safe[2..], [0, 0], "fly 1 counted windows it never learned from");
        mb.sleep();
        assert!(mb.plastic.w[0] < 1.0, "fly 0's common cell stays far below rest: {}", mb.plastic.w[0]);
        assert_eq!(mb.plastic.w[1], 10.0, "fly 0's silent cell kept");
        assert_eq!(&mb.plastic.w[2..], [10.0, 10.0], "fly 1 had no day: its weights stay at rest");
    }

    #[test]
    fn learning_still_works_the_morning_after() {
        // after sleep the ordinary rule runs again from the slept weights
        let mut mb = body(&[10.0]);
        mb.sleep();
        mb.learn(&spikes(1, &[0], 2), true, 0..1);
        assert!(mb.plastic.w[0] < 10.0, "a safe sighting still depresses by day");
        let low = mb.plastic.w[0];
        mb.learn(&spikes(1, &[0], 2), false, 0..1);
        assert!(mb.plastic.w[0] > low, "an attack still restores by day");
        assert_eq!(mb.seen, [1], "and the new day is being counted");
    }
}
