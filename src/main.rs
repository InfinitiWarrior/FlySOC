mod cluster;
mod detect;
mod relations;
mod sim;
mod view;

use sim::{BRAIN_ADAPT, Fly, Plastic, STEPS_PER_MS, Sim, Synapses};
use std::time::Instant;

const USAGE: &str = "usage: flysoc [view | bench | detect [--train <labelled.jsonl>] <baseline.jsonl> <events.jsonl>
              | cluster <labelled.jsonl> <events.jsonl> | cover <labelled.jsonl> <events.jsonl>
              | watch <labelled.jsonl> <events.jsonl>
              | snapshot <labelled.jsonl> <events.jsonl> <second> <out.ppm>
              | relations < events.jsonl]
fly brain is read from $FLYSOC_FLY, default data/fly.bin";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["relations"] {
        // no fly involved: skip loading the connectome
        return relations::run().unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1)
        });
    }
    let path = std::env::var("FLYSOC_FLY").unwrap_or("data/fly.bin".into());
    let t = std::time::Instant::now();
    let (fly, syn) = Fly::load(&path).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    eprintln!("{path}: {} neurons, {} synapses, loaded in {:.1} s", fly.n, syn.syn.len(), t.elapsed().as_secs_f32());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = match args[..] {
        [] | ["view"] => view::run(Box::new(view::Brain::new(fly, syn))),
        ["snapshot", train, events, second, out] => second
            .parse::<u32>()
            .map_err(|e| format!("second: {e}"))
            .and_then(|s| cluster::Watch::new(&fly, syn, train, events).map(|w| (s, w)))
            .and_then(|(s, w)| view::snapshot(Box::new(w), s + 1, out, (1920, 1080))),
        ["watch", train, events] => cluster::Watch::new(&fly, syn, train, events).and_then(|w| view::run(Box::new(w))),
        ["bench"] => Ok(bench(&fly, syn)),
        ["detect", base, events] => detect(&fly, syn, None, base, events),
        ["detect", "--train", train, base, events] => detect(&fly, syn, Some(train), base, events),
        ["cluster", train, events] => cluster::run(&fly, syn, train, events),
        ["cover", train, events] => cluster::cover(&fly, syn, train, events),
        _ => Err(USAGE.into()),
    };
    if let Err(e) = r {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// Optionally train on labelled telemetry, calibrate on benign telemetry, then print one JSON
/// alert per anomalous second of `events` to stdout and a scorecard against `label` to stderr.
fn detect(fly: &Fly, syn: Synapses, train: Option<&str>, base: &str, events: &str) -> Result<(), String> {
    let train = train.map(detect::read_events).transpose()?;
    let (base, events) = (detect::read_events(base)?, detect::read_events(events)?);
    let (circuit, syn) = detect::circuit(fly, &syn); // the full connectome is dropped here
    let fly = &circuit;
    let (syn, mut mb) = detect::MushroomBody::split(fly, syn);
    eprintln!(
        "network specialist circuit: {} neurons, {} fixed + {} plastic synapses",
        fly.n,
        syn.syn.len(),
        mb.plastic.w.len()
    );
    let (_, device, queue) = sim::device(&sim::instance(None), None);
    let sim = Sim::new(&device, &queue, fly.n, syn, &mb.plastic, 0.0);
    let enc = [detect::Encoder::new(fly, &["conn"])];
    let play = |events: &[detect::Event], learn| {
        detect::play(&device, &queue, &sim, fly, &enc, events, detect::duration(events), learn).swap_remove(0)
    };
    if let Some(train) = &train {
        let windows = play(train, Some(&mut mb));
        let safe = windows.iter().filter(|w| detect::is_safe(&w.labels)).count();
        eprintln!("trained on {} windows ({safe} safe, {} attack)", windows.len(), windows.len() - safe);
    }
    let threshold = detect::threshold(&play(&base, None));
    eprintln!("alert threshold: {threshold:.1} MBON spikes per window");

    let windows = play(&events, None);
    let alerts = detect::alerts(&windows, threshold);
    for &s in &alerts {
        let w = &windows[s];
        println!(
            r#"{{"ts_start":{s},"ts_end":{},"kind":"anomaly","mbon_spikes":{},"threshold":{threshold:.1},"truth":{:?}}}"#,
            s + 1,
            w.spikes[detect::DETECT_ON],
            w.labels,
        );
    }
    if std::env::var("FLYSOC_TRACE").is_ok() {
        eprintln!("sec  {}  labels", detect::TRACED.map(|c| format!("{c:>12}")).join(""));
        for (s, w) in windows.iter().enumerate() {
            eprintln!("{s:>3}  {}  {:?}", w.spikes.map(|x| format!("{x:>12}")).join(""), w.labels);
        }
    }

    // Scorecard: each non-benign label is one incident. A window within TAIL_S after an incident
    // still carries its response (1 s of telemetry is only 50 ms of fly time), so it is neither
    // counted as a false alert nor as benign.
    const TAIL_S: usize = 2;
    let mut incidents: Vec<&String> = windows.iter().flat_map(|w| &w.labels).filter(|l| *l != "benign").collect();
    incidents.dedup();
    let mut tail = vec![false; windows.len()];
    for label in incidents {
        let span: Vec<usize> = (0..windows.len()).filter(|&s| windows[s].labels.contains(label)).collect();
        let (start, end) = (span[0], *span.last().unwrap());
        (end + 1..(end + 1 + TAIL_S).min(windows.len())).for_each(|s| tail[s] = true);
        let hit = span.iter().filter(|s| alerts.contains(s)).count();
        match span.iter().find(|s| alerts.contains(s)) {
            Some(s) => eprintln!("{label:>18}: alerted {hit:>2}/{} windows, first {} s in", span.len(), s - start),
            None => eprintln!("{label:>18}: alerted  0/{} windows", span.len()),
        }
    }
    let benign = (detect::WARMUP_S..windows.len()).filter(|&s| !tail[s] && windows[s].labels.iter().all(|l| l == "benign"));
    let false_alerts = benign.clone().filter(|s| alerts.contains(s)).count();
    eprintln!("{:>18}: {false_alerts} false alerts in {} benign-only windows", "benign", benign.count());
    Ok(())
}

/// Stimulate every 10th sensory neuron at 150 Hz for 1 s of fly time.
fn bench(fly: &Fly, syn: Synapses) {
    let (_, device, queue) = sim::device(&sim::instance(None), None);
    let sim = Sim::new(&device, &queue, fly.n, syn, &Plastic::default(), BRAIN_ADAPT);
    let rates: Vec<f32> = (0..fly.n as usize).map(|i| if fly.class[i] == 2 && i % 10 == 0 { 150.0 } else { 0.0 }).collect();
    sim.set_stim(&queue, &rates);
    let steps = 1000 * STEPS_PER_MS;
    let t = Instant::now();
    for _ in 0..steps / 500 {
        let mut enc = device.create_command_encoder(&Default::default());
        sim.encode(&mut enc, 500);
        queue.submit([enc.finish()]);
    }
    let (_, spikes, last) = sim.read(&device, &queue);
    let secs = t.elapsed().as_secs_f64();
    let active = last.iter().filter(|&&l| l != 0).count();
    println!("1000 ms of fly time in {secs:.2} s ({:.2}x real time)", 1.0 / secs);
    println!("{spikes} spikes, {active} of {} neurons fired at least once", fly.n);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Silence stays silent; input into sensory neurons propagates to neurons that got no input.
    #[test]
    fn spikes_propagate() {
        let Ok((fly, syn)) = Fly::load("data/fly.bin") else { return eprintln!("no data/fly.bin, skipping") };
        let (_, device, queue) = sim::device(&sim::instance(None), None);
        let sim = Sim::new(&device, &queue, fly.n, syn, &Plastic::default(), BRAIN_ADAPT);
        let run = |steps| {
            let mut enc = device.create_command_encoder(&Default::default());
            sim.encode(&mut enc, steps);
            queue.submit([enc.finish()]);
            sim.read(&device, &queue)
        };

        let (_, spikes, _) = run(1000);
        assert_eq!(spikes, 0, "no input should mean no spikes");

        let rates: Vec<f32> = (0..fly.n as usize).map(|i| if fly.class[i] == 2 && i % 10 == 0 { 150.0 } else { 0.0 }).collect();
        sim.set_stim(&queue, &rates);
        let (_, spikes, last) = run(2000);
        let downstream = last.iter().enumerate().filter(|&(i, &l)| l != 0 && rates[i] == 0.0).count();
        assert!(spikes > 0);
        assert!(downstream > 100, "only {downstream} unstimulated neurons fired");
    }
}

#[cfg(test)]
mod memory {
    use super::*;

    /// Phase 9 probe (ISSUES O29): do the neurons the MBONs excite hold activity after the MBONs
    /// stop? The 20 s evidence average spans 1 s of fly time. MBONs are driven for 100 ms, then
    /// silent; prints spikes per 50 ms bin of the downstream neurons, all their connections kept.
    /// `cargo test --release memory -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn downstream_memory() {
        let Ok((fly, syn)) = Fly::load("data/fly.bin") else { return eprintln!("no data/fly.bin, skipping") };
        let mbon: Vec<bool> = { let mut v = vec![false; fly.n as usize]; fly.of_class("MBON").into_iter().for_each(|i| v[i as usize] = true); v };
        // excitatory synapses each neuron receives from MBONs, and its strongest-fed rank
        let mut from_mbon = vec![0i64; fly.n as usize];
        for pre in (0..fly.n as usize).filter(|&i| mbon[i]) {
            for &s in &syn.syn[syn.row_ptr[pre] as usize..syn.row_ptr[pre + 1] as usize] {
                let w = s as i32 >> sim::POST_BITS;
                if w > 0 { from_mbon[(s & sim::POST) as usize] += w as i64; }
            }
        }
        let (_, device, queue) = sim::device(&sim::instance(None), None);
        for (min, adapt) in [(20, 0.0), (20, 0.5), (20, 1.0), (20, 2.0), (20, 4.0), (20, BRAIN_ADAPT), (5, BRAIN_ADAPT)] {
            let keep = |i: u32| mbon[i as usize] || from_mbon[i as usize] >= min;
            let (sub, ssyn) = fly.circuit(&syn, keep, |_, _, _| false);
            let is_mbon: Vec<bool> = (0..sub.n as usize).map(|k| sub.names.cell_class.get(sub.cell_class[k] as usize).is_some_and(|c| c == "MBON")).collect();
            let sim = Sim::new(&device, &queue, sub.n, ssyn, &Plastic::default(), adapt);
            for rate in [5.0f32, 100.0] {
                sim.reset(&device, &queue);
                sim.take_fired(&device, &queue);
                let mut row = Vec::new();
                for bin in 0..30 {
                    let r: Vec<f32> = is_mbon.iter().map(|&m| if m && bin < 2 { rate } else { 0.0 }).collect();
                    sim.set_stim(&queue, &r);
                    let mut enc = device.create_command_encoder(&Default::default());
                    sim.encode(&mut enc, 50 * STEPS_PER_MS);
                    queue.submit([enc.finish()]);
                    let f = sim.take_fired(&device, &queue);
                    row.push(f.iter().zip(&is_mbon).filter(|(_, m)| !**m).map(|(x, _)| *x as u64).sum::<u64>());
                }
                println!("adapt {adapt:2} mV, downstream >= {min:2} MBON synapses ({} neurons), MBONs at {rate} Hz for 100 ms: {row:?}", sub.n as usize - is_mbon.iter().filter(|&&m| m).count());
            }
        }
    }
}
