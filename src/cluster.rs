//! Phase 3: a team of specialist flies plus a consensus coordinator, against one fly that
//! smells everything.
//!
//! All flies are the same network specialist circuit; they differ in which telemetry kinds they
//! smell and in what their mushroom body has learned. They run together in one simulation as
//! disjoint copies of the circuit (~2 MB of GPU memory each), so the whole team costs about as
//! much time as one fly: the simulation is bound by dispatches per step, not by neurons.
//!
//! Each fly's evidence is its MBON readout averaged over the last ~EVIDENCE_S seconds (an
//! exponential moving average): intrusion stages last minutes, single seconds are noisy. After
//! training, each fly replays its training data without learning, and fires from then on only
//! above the 99.9th percentile of the evidence it showed on traffic labelled safe (look-alikes
//! included): "never alert on anything as harmless-looking as what you were taught is safe".
//!
//! Coordinator: the cluster raises an incident when at least QUORUM different specialists have
//! fired within the last HORIZON_S seconds about the same entity (host or user), one of them now.
//! Each fly names its suspects: the entities behind its most extreme recent history count (e.g.
//! the source fanning out over ports). Stages of one intrusion share entities (the scan and the
//! spray come from the same workstation); unrelated look-alikes rarely do.
//! Confidence = share of specialists agreeing about that entity.

use crate::detect::{self, Encoder, Event, MushroomBody, Player};
use crate::sim::{Fly, STEPS_PER_MS, Sim, Synapses};
use crate::view::{Driver, Scene};

/// (name, telemetry kinds it smells). The last one is the single-fly baseline.
pub const FLIES: [(&str, &[&str]); 5] = [
    ("network", &["conn"]),
    ("identity", &["auth"]),
    ("endpoint", &["proc"]),
    ("dns", &["dns"]),
    ("single fly", &["conn", "auth", "proc", "dns"]),
];
const SPECIALISTS: usize = 4;
/// A fly fires above this quantile of its evidence on calm training seconds. The maximum (1.0) grew
/// with the length of the training file and hung on one odd second (ISSUES O9).
const CALM_QUANTILE: f64 = 0.999;
/// Individual flies per role. Each smells the same kinds through different glomeruli; their
/// output spikes are summed into one voter, so the coordinator still sees five roles.
pub fn replicas() -> usize {
    std::env::var("FLYSOC_REPLICAS").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}
const EVIDENCE_S: f64 = 20.0;
const MEMORY_S: usize = 3 * EVIDENCE_S as usize; // how long the evidence average remembers
const QUORUM: usize = 2;
const HORIZON_S: usize = 300;
/// Alerts this soon after an incident's last event still belong to it: the evidence average
/// remembers about 3 x EVIDENCE_S seconds.
const TAIL_S: usize = 60;

/// A trained team, ready to play telemetry.
pub struct Cluster {
    pub circuit: Fly, // one fly's circuit; fly f is neurons f*n .. (f+1)*n of `sim`
    pub sim: Sim,
    pub encs: Vec<Encoder>,
    pub thresholds: Vec<f64>,
}

/// Puts one copy of the circuit per fly into a single simulation, trains every fly on its own
/// slice of `train` at once, then calibrates each fly's threshold on a replay without learning.
/// The result is cached in data/cache/, keyed on the training file and the FlySOC binary, so a
/// rebuild or different training data retrains, and anything else loads in a moment.
pub fn build(device: &wgpu::Device, queue: &wgpu::Queue, circuit: Fly, syn: Synapses, train_path: &str) -> Result<Cluster, String> {
    let (syn, one) = MushroomBody::split(&circuit, syn);
    let (k, n) = (FLIES.len() * replicas(), circuit.n);
    let mut mb = one.replicate(k, n);
    let sim = Sim::new(device, queue, n * k as u32, syn.replicate(k), &mb.plastic, 0.0);
    let encs: Vec<Encoder> = FLIES
        .iter()
        .flat_map(|(_, kinds)| (0..replicas()).map(|r| Encoder::new(&circuit, kinds).individual(r as u8)))
        .collect();

    let train_bytes = std::fs::read(train_path).map_err(|e| format!("{train_path}: {e}"))?;
    let exe = std::env::current_exe().and_then(std::fs::read).unwrap_or_default();
    let cache = format!("data/cache/cluster{k}-{:016x}.bin", detect::fnv(&train_bytes) ^ detect::fnv(&exe).rotate_left(1));
    if let Some((w, thresholds)) = load_cache(&cache, mb.plastic.w.len(), FLIES.len()) {
        sim.set_plastic(queue, &w);
        eprintln!("loaded the trained cluster from {cache}");
        return Ok(Cluster { circuit, sim, encs, thresholds });
    }

    let train = detect::read_events(train_path)?;
    let secs = detect::duration(&train);
    let t = std::time::Instant::now();
    eprintln!("training {k} flies ({n} neurons each) on {secs} s of telemetry (cached afterwards)...");
    detect::play(device, queue, &sim, &circuit, &encs, &train, secs, Some(&mut mb));
    eprintln!("  trained in {:.1} s; calibrating thresholds on a replay...", t.elapsed().as_secs_f32());
    let t = std::time::Instant::now();
    let replay = pool(detect::play(device, queue, &sim, &circuit, &encs, &train, secs, None));
    eprintln!("  calibrated in {:.1} s", t.elapsed().as_secs_f32());

    // Training seconds that are safe to calibrate on: no intrusion in them or in the evidence
    // average's memory before them.
    let mut calm = vec![true; secs];
    for (s, ls) in labels_per_second(&train, secs).iter().enumerate() {
        if s < MEMORY_S || ls.iter().any(|l| l.starts_with("intrusion")) {
            (s..(s + MEMORY_S).min(secs)).for_each(|t| calm[t] = false);
        }
    }
    let thresholds = replay
        .iter()
        .map(|w| {
            let ev = evidence(w);
            let mut c: Vec<f64> = (0..secs).filter(|&s| calm[s]).map(|s| ev[s]).collect();
            c.sort_by(f64::total_cmp);
            c.get(((c.len() as f64 - 1.0) * CALM_QUANTILE).round() as usize).copied().unwrap_or(0.0)
        })
        .collect::<Vec<f64>>();
    if let Err(e) = save_cache(&cache, &mb.plastic.w, &thresholds) {
        eprintln!("could not cache the trained cluster: {e}");
    }
    Ok(Cluster { circuit, sim, encs, thresholds })
}

/// Cache file: u32 fly count, u32 weight count, f64 threshold per fly, f32 plastic weights.
fn save_cache(path: &str, w: &[f32], thresholds: &[f64]) -> std::io::Result<()> {
    std::fs::create_dir_all("data/cache")?;
    let mut out: Vec<u8> = Vec::new();
    out.extend((thresholds.len() as u32).to_le_bytes());
    out.extend((w.len() as u32).to_le_bytes());
    thresholds.iter().for_each(|t| out.extend(t.to_le_bytes()));
    w.iter().for_each(|x| out.extend(x.to_le_bytes()));
    std::fs::write(path, out)
}

fn load_cache(path: &str, weights: usize, flies: usize) -> Option<(Vec<f32>, Vec<f64>)> {
    let b = std::fs::read(path).ok()?;
    let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
    if b.len() != 8 + 8 * flies + 4 * weights || u32_at(0) != flies || u32_at(4) != weights {
        return None;
    }
    let thresholds = b[8..8 + 8 * flies].chunks(8).map(|c| f64::from_le_bytes(c.try_into().unwrap())).collect();
    let w = b[8 + 8 * flies..].chunks(4).map(|c| f32::from_le_bytes(c.try_into().unwrap())).collect();
    Some((w, thresholds))
}

/// When the cluster raises an incident. Every rule needs agreement about the same entity within
/// HORIZON_S seconds, except the single fly's own alarm in `TeamOrSingle`.
#[derive(Clone, Copy, PartialEq)]
pub enum Rule {
    /// QUORUM specialists agree.
    Team,
    /// The single fly fires, or `Team`.
    TeamOrSingle,
    /// QUORUM of all five flies agree; the single fly is a fifth voter.
    AllVote,
    /// The single fly fires and at least one specialist agrees: the team confirms the generalist.
    Confirmed,
}

pub const RULES: [(Rule, &str); 4] = [
    (Rule::Team, "A team"),
    (Rule::TeamOrSingle, "B team|single"),
    (Rule::AllVote, "C all vote"),
    (Rule::Confirmed, "D confirmed"),
];
/// The rule `watch` and the JSON incidents use.
pub const RULE: Rule = Rule::Confirmed;

/// Turns each second's MBON spikes and suspects per fly into fly alarms, one second at a time,
/// and answers whether a `Rule` raises an incident.
pub struct Coordinator {
    thresholds: Vec<f64>,
    ema: Vec<f64>,
    fired: Vec<Option<(usize, Vec<String>)>>, // per fly: last second it fired, and its suspects then
}

impl Coordinator {
    pub fn new(thresholds: &[f64]) -> Self {
        Self { thresholds: thresholds.to_vec(), ema: vec![0.0; thresholds.len()], fired: vec![None; thresholds.len()] }
    }

    /// Feeds second `s`; returns which flies fire now.
    pub fn second(&mut self, s: usize, mbon: &[u32], suspects: &[Vec<String>]) -> Vec<bool> {
        let mut now = vec![false; mbon.len()];
        for f in 0..mbon.len() {
            self.ema[f] += (mbon[f] as f64 - self.ema[f]) / EVIDENCE_S;
            now[f] = s >= detect::WARMUP_S && self.ema[f] > self.thresholds[f];
            if now[f] {
                self.fired[f] = Some((s, suspects[f].clone()));
            }
        }
        now
    }

    /// The incident `rule` raises in second `s`, if any: (confidence, entity). Call after `second`.
    pub fn incident(&self, s: usize, now: &[bool], suspects: &[Vec<String>], rule: Rule) -> Option<(f32, String)> {
        let single = SPECIALISTS;
        let recent = |f: usize| self.fired[f].as_ref().filter(|(t, _)| s - t <= HORIZON_S).map(|(_, e)| e);
        // the entity named now by one of `from` that most of `voters` agree about recently
        let agree = |voters: &[usize], from: &[usize]| {
            from.iter()
                .filter(|&&f| now[f])
                .flat_map(|&f| suspects[f].iter())
                .map(|e| (voters.iter().filter(|&&g| recent(g).is_some_and(|r| r.contains(e))).count(), e.clone()))
                .max_by_key(|x| x.0)
        };
        let (team, all): (Vec<usize>, Vec<usize>) = ((0..SPECIALISTS).collect(), (0..=SPECIALISTS).collect());
        let quorum = |voters: &[usize], from: &[usize]| {
            agree(voters, from).filter(|(n, _)| *n >= QUORUM).map(|(n, e)| (n as f32 / voters.len() as f32, e))
        };
        match rule {
            Rule::Team => quorum(&team, &team),
            Rule::TeamOrSingle => quorum(&team, &team).or_else(|| {
                now[single].then(|| (1.0 / all.len() as f32, suspects[single].first().cloned().unwrap_or_default()))
            }),
            Rule::AllVote => quorum(&all, &all),
            Rule::Confirmed => quorum(&all, &[single]),
        }
    }
}

pub fn run(fly: &Fly, syn: Synapses, train: &str, events: &str) -> Result<(), String> {
    let events = detect::read_events(events)?;
    let (circuit, syn) = detect::circuit(fly, &syn); // the full connectome is dropped here
    let (_, device, queue) = crate::sim::device(&crate::sim::instance(None), None);
    let c = build(&device, &queue, circuit, syn, train)?;
    for (f, (name, _)) in FLIES.iter().enumerate() {
        eprintln!("{name:>10}: fires above {:.1} MBON spikes/s ({EVIDENCE_S} s average)", c.thresholds[f]);
    }
    let seconds = detect::duration(&events);
    let windows = pool(detect::play(&device, &queue, &c.sim, &c.circuit, &c.encs, &events, seconds, None));
    let labels = labels_per_second(&events, seconds);

    let mut coord = Coordinator::new(&c.thresholds);
    let mut fired = vec![vec![false; seconds]; FLIES.len()]; // [fly][second]
    let mut cluster = vec![vec![false; seconds]; RULES.len()]; // [rule][second]
    for s in 0..seconds {
        let mbon: Vec<u32> = windows.iter().map(|w| w[s].spikes[detect::DETECT_ON]).collect();
        let suspects: Vec<Vec<String>> = windows.iter().map(|w| w[s].suspects.clone()).collect();
        let now = coord.second(s, &mbon, &suspects);
        now.iter().enumerate().for_each(|(f, &x)| fired[f][s] = x);
        for (r, (rule, _)) in RULES.iter().enumerate() {
            cluster[r][s] = coord.incident(s, &now, &suspects, *rule).is_some();
        }
        if let Some((confidence, entity)) = coord.incident(s, &now, &suspects, RULE) {
            let truth: Vec<&String> = labels[s].iter().filter(|l| *l != "benign").collect();
            let who: Vec<&str> = (0..SPECIALISTS).filter(|&f| now[f]).map(|f| FLIES[f].0).collect();
            println!(r#"{{"ts_start":{s},"ts_end":{},"kind":"incident","entity":"{entity}","confidence":{confidence:.2},"flies":{who:?},"truth":{truth:?}}}"#, s + 1);
        }
    }
    if let Ok(path) = std::env::var("FLYSOC_TRACE") {
        let mut out = format!("sec\t{}\tlabels\n", FLIES.map(|f| f.0).join("\t"));
        for s in 0..seconds {
            let row: Vec<String> = windows.iter().map(|w| w[s].spikes[detect::DETECT_ON].to_string()).collect();
            out += &format!("{s}\t{}\t{}\n", row.join("\t"), labels[s].join(","));
        }
        std::fs::write(&path, out).map_err(|e| format!("{path}: {e}"))?;
    }

    eprintln!("\n{:>13}  {:<28}  {:<36}  {}", "", "intrusions caught (first alert)", "look-alikes alerted", "false alert seconds");
    for (f, (name, _)) in FLIES.iter().enumerate() {
        eprintln!("{name:>13}  {}", score(&labels, &fired[f]));
    }
    for (r, (_, name)) in RULES.iter().enumerate() {
        eprintln!("{:>13}  {}", format!("cluster {name}"), score(&labels, &cluster[r]));
    }
    Ok(())
}

/// Per-individual windows [fly][..] -> per-role windows: spikes summed over a role's individuals,
/// suspects and labels from its first individual (they all see the same events).
fn pool(flies: Vec<Vec<detect::Window>>) -> Vec<Vec<detect::Window>> {
    let mut flies = flies.into_iter();
    (0..FLIES.len())
        .map(|_| {
            let mut role: Vec<Vec<detect::Window>> = flies.by_ref().take(replicas()).collect();
            let first = role.remove(0);
            first
                .into_iter()
                .enumerate()
                .map(|(t, mut w)| {
                    for other in &role {
                        w.spikes.iter_mut().zip(other[t].spikes).for_each(|(a, b)| *a += b);
                    }
                    w
                })
                .collect()
        })
        .collect()
}

/// MBON spikes per second, exponentially averaged over ~EVIDENCE_S seconds.
fn evidence(windows: &[detect::Window]) -> Vec<f64> {
    let a = 1.0 / EVIDENCE_S;
    let mut ema = 0.0;
    windows.iter().map(|w| { ema += a * (w.spikes[detect::DETECT_ON] as f64 - ema); ema }).collect()
}

/// Labels of all events in each second, whatever their kind.
pub fn labels_per_second(events: &[Event], seconds: usize) -> Vec<Vec<String>> {
    let mut out = vec![Vec::<String>::new(); seconds];
    for e in events {
        let s = (e.ts as usize).min(seconds - 1);
        if !out[s].contains(&e.label) {
            out[s].push(e.label.clone());
        }
    }
    out
}

/// "intrusion@200:recon" -> "intrusion@200"; "benign" -> None.
fn incident(label: &str) -> Option<&str> {
    (label != "benign" && !label.is_empty()).then(|| label.split(':').next().unwrap())
}

/// One scorecard line: intrusions caught and how fast, look-alike incidents that raised any alert,
/// and alerted seconds that hold only plain benign traffic (outside incidents and their tails).
fn score(labels: &[Vec<String>], alert: &[bool]) -> String {
    let mut spans: Vec<(&str, usize, usize)> = Vec::new(); // (incident, first, last second)
    for (s, ls) in labels.iter().enumerate() {
        for id in ls.iter().filter_map(|l| incident(l)) {
            match spans.iter_mut().find(|x| x.0 == id) {
                Some(x) => x.2 = s,
                None => spans.push((id, s, s)),
            }
        }
    }
    let mut busy = vec![false; labels.len()];
    for &(_, a, b) in &spans {
        (a..=(b + TAIL_S).min(labels.len() - 1)).for_each(|s| busy[s] = true);
    }
    let first_alert = |a: usize, b: usize| (a..=(b + TAIL_S).min(labels.len() - 1)).find(|&s| alert[s]).map(|s| s - a);
    let intrusions: Vec<_> = spans.iter().filter(|x| x.0.starts_with("intrusion")).collect();
    let caught: Vec<String> = intrusions.iter().filter_map(|x| first_alert(x.1, x.2).map(|d| format!("+{d}s"))).collect();
    let lookalikes: Vec<_> = spans.iter().filter(|x| x.0.starts_with("benign")).collect();
    let alerted: Vec<&str> = lookalikes
        .iter()
        .filter(|x| first_alert(x.1, x.2).is_some())
        .map(|x| x.0.trim_start_matches("benign_").split('@').next().unwrap())
        .collect();
    let plain = (detect::WARMUP_S..labels.len()).filter(|&s| !busy[s]);
    let false_alerts = plain.clone().filter(|&s| alert[s]).count();
    format!(
        "{:<28}  {:<36}  {false_alerts}/{}",
        format!("{}/{} ({})", caught.len(), intrusions.len(), caught.join(" ")),
        format!("{}/{} {}", alerted.len(), lookalikes.len(), alerted.join(" ")),
        plain.count()
    )
}

/// The cluster in the viewer: specialists in a row on top, the single fly below, all playing
/// `events` live. An alarmed fly turns red. The window title and a terminal log line (printed
/// whenever it changes; some compositors show no titles) say what is really happening, which flies
/// are red and any cluster incident. R: restart. Speed is in 1 ms bins of fly time per frame
/// (50 = one second of telemetry).
pub struct Watch {
    circuit: Option<(Fly, Synapses)>, // moved into the cluster on start
    scene: Scene,
    train: String,
    events: &'static [Event], // leaked: the Player borrows them for the life of the window
    labels: Vec<Vec<String>>,
    cluster: Option<&'static Cluster>,
    player: Option<Player<'static>>,
    coord: Coordinator,
    now: usize,
    alarm: u32,
    incident: Option<(f32, String)>, // confidence, entity
    logged: String, // last terminal log line, minus the time
    loop_started: Option<std::time::Instant>,
}

/// How long a label stays "happening" after its last event: stages like the slow scan only
/// have an event every few seconds.
const HAPPENING_S: usize = 10;

impl Watch {
    pub fn new(fly: &Fly, syn: Synapses, train: &str, events: &str) -> Result<Self, String> {
        let events = detect::read_events(events)?;
        let t = std::time::Instant::now();
        let (circuit, syn) = detect::circuit(fly, &syn);
        eprintln!("pruned to the network specialist circuit in {:.1} s", t.elapsed().as_secs_f32());
        let labels = labels_per_second(&events, detect::duration(&events));
        let scene = layout(fly, &circuit);
        Ok(Self {
            circuit: Some((circuit, syn)),
            scene,
            train: train.to_string(),
            events: Box::leak(events.into_boxed_slice()),
            labels,
            cluster: None,
            player: None,
            coord: Coordinator::new(&[]),
            now: 0,
            alarm: 0,
            incident: None,
            logged: String::new(),
            loop_started: None,
        })
    }

    /// Incident labels with an event in the last HAPPENING_S seconds.
    fn happening(&self, s: usize) -> String {
        let mut now: Vec<&str> = Vec::new();
        for t in s.saturating_sub(HAPPENING_S)..=s.min(self.labels.len() - 1) {
            for l in self.labels[t].iter().filter(|l| *l != "benign") {
                if !now.contains(&l.as_str()) {
                    now.push(l);
                }
            }
        }
        if now.is_empty() { "normal traffic".into() } else { now.join(", ") }
    }

    /// One line describing the current second, without the time.
    fn describe(&self) -> String {
        let red: Vec<&str> = (0..FLIES.len()).filter(|f| self.alarm >> f & 1 == 1).map(|f| FLIES[f].0).collect();
        format!(
            "happening: {}  |  red: {}  |  {}",
            self.happening(self.now),
            if red.is_empty() { "none".into() } else { red.join(", ") },
            self.incident.as_ref().map_or("no incident".into(), |(c, e)| format!("CLUSTER INCIDENT about {e}, {:.0}% of specialists agree", c * 100.0)),
        )
    }

    fn restart(&mut self, device: &wgpu::Device, queue: &wgpu::Queue) {
        let c = self.cluster.expect("started");
        self.player = Some(Player::new(device, queue, &c.sim, c.circuit.n, &c.encs, self.events));
        self.coord = Coordinator::new(&c.thresholds);
        (self.now, self.alarm, self.incident) = (0, 0, None);
        self.logged.clear();
        if let Some(t) = self.loop_started {
            eprintln!("--- played {} s of telemetry in {:.1} s ---", self.labels.len(), t.elapsed().as_secs_f32());
        }
        eprintln!("--- playing {} s of telemetry from the start ---", self.labels.len());
        self.loop_started = Some(std::time::Instant::now());
    }
}

/// One whole brain per fly, drawn dim for context, with its simulated circuit lit inside it in
/// its real position. One individual per role: the four specialists as a 2x2 grid on the left, the
/// single fly on the right. Several: one row per role (specialists on top, the single fly at the
/// bottom after a gap), one column per individual. A role's alarm turns its whole row red: the
/// viewer's "fly" is a role (per_fly = neurons of all its individuals, ghosts carry the role).
fn layout(brain: &Fly, circuit: &Fly) -> Scene {
    let axis = |a: usize| brain.pos.iter().skip(a).step_by(3).copied();
    let mid = |a: usize| (axis(a).fold(f32::MAX, f32::min) + axis(a).fold(f32::MIN, f32::max)) / 2.0;
    let size = |a: usize| axis(a).fold(f32::MIN, f32::max) - axis(a).fold(f32::MAX, f32::min);
    let (c, w, h) = ([mid(0), mid(1), mid(2)], size(0) * 1.08, size(1) * 1.25);
    let colours = detect::colours(circuit);
    let r = replicas();
    let (n, total) = (circuit.n as usize, (brain.n + circuit.n) as usize * FLIES.len() * r);
    let (mut pos, mut colour, mut index) = (Vec::with_capacity(3 * total), Vec::with_capacity(total), Vec::with_capacity(total));
    let mut place = |p: &[f32], d: [f32; 2]| pos.extend([p[0] - c[0] + d[0], p[1] - c[1] + d[1], p[2] - c[2]]);
    for f in 0..FLIES.len() {
        for i in 0..r {
            let d = match (r, f < SPECIALISTS) {
                // team grid: columns at -1.15w and -0.15w, rows at +-h/2; single fly at +1.15w after a gap
                (1, true) => [((f % 2) as f32 - 1.15) * w, if f < 2 { h / 2.0 } else { -h / 2.0 }],
                (1, false) => [1.15 * w, 0.0],
                _ => [(i as f32 - (r - 1) as f32 / 2.0) * w, (2.0 - f as f32 - if f < SPECIALISTS { 0.0 } else { 0.4 }) * h],
            };
            for k in 0..brain.n as usize {
                place(&brain.pos[3 * k..3 * k + 3], d);
            }
            colour.extend(&brain.class);
            index.extend(std::iter::repeat_n(crate::view::GHOST | f as u32, brain.n as usize));
            for k in 0..n {
                place(&circuit.pos[3 * k..3 * k + 3], d);
            }
            colour.extend(&colours);
            let fly = (f * r + i) as u32;
            index.extend((0..n as u32).map(|k| fly * n as u32 + k));
        }
    }
    let dist = if r == 1 { w * 2.4 } else { (r as f32 * w * 0.68).max(5.4 * h * 1.2) };
    Scene { pos, colour, index, per_fly: (n * r) as u32, dist, speed: detect::WINDOW_MS }
}

impl Driver for Watch {
    fn scene(&self) -> Scene {
        Scene {
            pos: self.scene.pos.clone(),
            colour: self.scene.colour.clone(),
            index: self.scene.index.clone(),
            ..self.scene
        }
    }

    fn start(&mut self, device: &wgpu::Device, queue: &wgpu::Queue) {
        let (circuit, syn) = self.circuit.take().expect("started once");
        let c = build(device, queue, circuit, syn, &self.train).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1)
        });
        let c: &'static Cluster = Box::leak(Box::new(c));
        self.cluster = Some(c);
        self.restart(device, queue);
        let names = |r: std::ops::Range<usize>| FLIES[r].iter().map(|f| f.0).collect::<Vec<_>>().join(", ");
        match replicas() {
            1 => eprintln!("\nleft, 2x2 team: {} (top), {} (bottom); right: {}", names(0..2), names(2..SPECIALISTS), names(SPECIALISTS..FLIES.len())),
            r => eprintln!("\n{r} individuals per row, rows top to bottom: {}", names(0..FLIES.len())),
        }
        eprintln!("colours: receptors green, antennal lobe purple, Kenyon cells orange, lateral horn teal,");
        eprintln!("         output neurons pink. A fly turns red while it raises an alarm.");
    }

    fn sim(&self) -> &Sim {
        &self.cluster.expect("started").sim
    }

    fn frame(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, speed: u32) -> u32 {
        let c = self.cluster.expect("started");
        for _ in 0..speed {
            if self.player.as_ref().is_some_and(|p| p.second() >= self.labels.len()) {
                self.restart(device, queue);
            }
            let Some(labels) = self.player.as_mut().unwrap().step(device, queue, &c.sim) else { continue };
            let s = self.player.as_ref().unwrap().second() - 1;
            let fired = c.sim.take_fired(device, queue);
            let suspects = self.player.as_mut().unwrap().suspects();
            let windows = detect::windows(&c.circuit, &fired, labels, suspects).into_iter().map(|w| vec![w]).collect();
            let windows: Vec<detect::Window> = pool(windows).into_iter().map(|mut w| w.remove(0)).collect();
            let mbon: Vec<u32> = windows.iter().map(|w| w.spikes[detect::DETECT_ON]).collect();
            let suspects: Vec<Vec<String>> = windows.into_iter().map(|w| w.suspects).collect();
            let now = self.coord.second(s, &mbon, &suspects);
            let incident = self.coord.incident(s, &now, &suspects, RULE);
            self.alarm = now.iter().enumerate().fold(0, |m, (f, &x)| m | (x as u32) << f);
            (self.now, self.incident) = (s, incident);
            let line = self.describe();
            if line != self.logged {
                eprintln!("[{s:>4} / {} s]  {line}", self.labels.len());
                self.logged = line;
            }
        }
        // send any bins of an unfinished second, so slow speeds still move every frame
        self.player.as_mut().unwrap().flush(device, queue, &c.sim);
        speed * STEPS_PER_MS
    }

    fn alarm(&self) -> u32 {
        self.alarm
    }

    fn status(&mut self, _: &wgpu::Device, _: &wgpu::Queue, speed: u32) -> String {
        format!(
            "FlySOC cluster  |  {} / {} s  |  {}  |  {:.2} s per frame",
            self.now,
            self.labels.len(),
            self.describe(),
            speed as f32 / detect::WINDOW_MS as f32,
        )
    }

    fn key(&mut self, device: &wgpu::Device, queue: &wgpu::Queue, key: &str) {
        if key == "r" {
            self.restart(device, queue);
        }
    }
}
