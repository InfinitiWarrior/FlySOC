//! A plain logon-relationship detector, beside the flies (ISSUES O25-O27). No fly involved; a port
//! of `tools/lanl_relations.py`, which stays the reference.
//!
//! Three signals per source computer, each a count of distinct things over the last hour:
//!   new3    (user, dst) logons whose user-source, source-dst and user-dst pairs were all never seen
//!   fail    users that failed to log on from it
//!   newdst  destinations it never logged on to before
//! A signal counts only above both its line and the source's own highest count so far. A source
//! alerts when two signals count within an hour, once the stream holds ARMED_S of history. It then
//! stays on a watchlist until an analyst clears it, and every later successful logon from it is a lead.
//!
//!     python3 -I tools/lanl.py --logons <end_s> | flysoc relations > alerts.jsonl

use crate::detect::Event;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::BufRead;

const H: f64 = 3600.0;
/// Before this much history every logon looks new (O26).
const ARMED_S: f64 = 5.0 * 86400.0;
/// (name, line, what it counts): lines are the highest counts on LANL's red-free days 3-4 (O25).
const SIGNALS: [(&str, usize, &str); 3] = [
    ("new3", 1, "logons whose user, source and destination were never seen in pairs"),
    ("fail", 2, "users failing to log on"),
    ("newdst", 10, "destinations never logged on to before"),
];

#[derive(Default)]
pub struct Relations {
    us: HashSet<(String, String)>,
    sd: HashSet<(String, String)>,
    ud: HashSet<(String, String)>,
    q: HashMap<(usize, String), VecDeque<(f64, String)>>,
    peak: HashMap<(usize, String), usize>,
    fired: HashMap<String, [(f64, usize); 3]>, // per source and signal: when it last counted, and how high
    pub watched: HashMap<String, f64>,          // listed sources, and when
    start: Option<f64>,
}

impl Relations {
    /// Records `value` for signal k; true if it is a new value that takes s above the line.
    fn crossed(&mut self, k: usize, t: f64, s: &str, value: String) -> bool {
        let q = self.q.entry((k, s.to_string())).or_default();
        let distinct = |q: &VecDeque<(f64, String)>| q.iter().map(|(_, v)| v).collect::<HashSet<_>>().len();
        let before = distinct(q);
        q.push_back((t, value));
        while q.front().is_some_and(|(x, _)| *x < t - H) {
            q.pop_front();
        }
        let n = distinct(q);
        let peak = self.peak.entry((k, s.to_string())).or_default();
        let own = std::mem::replace(peak, (*peak).max(n));
        if n > SIGNALS[k].1.max(own) && n > before {
            self.fired.entry(s.to_string()).or_insert([(f64::NEG_INFINITY, 0); 3])[k] = (t, n);
            return true;
        }
        false
    }

    /// One event, in time order. Returns why it alerts, or None. Only remote logons count.
    pub fn see(&mut self, e: &Event) -> Option<String> {
        let (Some(u), Some(s), Some(d)) = (&e.user, &e.src, &e.dst) else { return None };
        if e.kind != "auth" || s == d {
            return None;
        }
        let (t, ok) = (e.ts, e.result.as_deref() == Some("ok"));
        let start = *self.start.get_or_insert(t);
        let pair = |a: &String, b: &String| (a.clone(), b.clone());
        let (new_us, new_sd, new_ud) = (!self.us.contains(&pair(u, s)), !self.sd.contains(&pair(s, d)), !self.ud.contains(&pair(u, d)));
        let mut crossed = false;
        if ok && new_us && new_sd && new_ud {
            crossed |= self.crossed(0, t, s, format!("{u}|{d}"));
        }
        if !ok {
            crossed |= self.crossed(1, t, s, u.clone());
        }
        if ok && new_sd {
            crossed |= self.crossed(2, t, s, d.clone());
        }
        if ok {
            self.us.insert(pair(u, s));
            self.sd.insert(pair(s, d));
            self.ud.insert(pair(u, d));
        }
        if crossed && t - start >= ARMED_S {
            let recent: Vec<String> = (0..3)
                .filter_map(|k| self.fired[s].get(k).filter(|(v, _)| t - v <= H).map(|(_, n)| format!("{n} {}", SIGNALS[k].2)))
                .collect();
            if recent.len() >= 2 {
                self.watched.entry(s.clone()).or_insert(t);
                return Some(format!("{s}: {} in the last hour, each above its line and {s}'s own past peak; listed until an analyst clears it", recent.join(" and ")));
            }
        }
        match self.watched.get(s) {
            Some(since) if ok => Some(format!("{s} is on the watchlist since day {:.2}: {u} logged on from it to {d}", since / 86400.0)),
            _ => None,
        }
    }
}

/// `flysoc relations`: JSON events on stdin, one alert per line on stdout.
pub fn run() -> Result<(), String> {
    let mut r = Relations::default();
    for (i, line) in std::io::stdin().lock().lines().enumerate() {
        let line = line.map_err(|e| format!("stdin: {e}"))?;
        let e: Event = serde_json::from_str(&line).map_err(|err| format!("stdin line {}: {err}", i + 1))?;
        if let Some(why) = r.see(&e) {
            let kind = if why.contains("listed until") { "two signals" } else { "watchlist" };
            let (entity, user, dst) = (e.src.as_deref().unwrap_or(""), e.user.as_deref().unwrap_or(""), e.dst.as_deref().unwrap_or(""));
            println!(
                "{}",
                serde_json::json!({"ts_start": e.ts, "ts_end": e.ts + 1.0, "kind": kind, "entity": entity, "user": user, "dst": dst, "why": [why], "truth": [e.label]})
            );
        }
    }
    eprintln!("watchlist: {:?}", r.watched);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logon(t: f64, u: &str, s: &str, d: &str, ok: bool) -> Event {
        let result = if ok { "ok" } else { "fail" };
        serde_json::from_value(serde_json::json!({"ts": t, "kind": "auth", "user": u, "src": s, "dst": d, "result": result})).unwrap()
    }

    /// The cases of `tools/lanl_relations.py check`.
    #[test]
    fn relations() {
        let t0 = ARMED_S;
        let mut r = Relations::default();
        r.see(&logon(0.0, "U", "first", "D", true)); // the stream starts at 0
        for i in 0..3 {
            r.see(&logon(t0 + i as f64, &format!("U{i}"), "known", "D", true));
        }
        assert_eq!(r.see(&logon(t0 + 10.0, "U0", "known", "D", true)), None, "a known logon is quiet");
        for i in 0..6 {
            assert_eq!(r.see(&logon(t0 + 100.0 + i as f64, &format!("V{i}"), "A", "B", false)), None, "failures alone never alert");
        }
        assert_eq!(r.see(&logon(t0 + 200.0, "X", "A", "T1", true)), None, "one new relationship is not above the new3 line");
        let why = r.see(&logon(t0 + 201.0, "Y", "A", "T2", true)).expect("fail and new3 within the hour");
        assert!(why.contains("6 users failing") && why.contains("2 logons whose"), "{why}");
        assert!(r.see(&logon(t0 + 90000.0, "U1", "A", "T1", true)).unwrap().contains("watchlist"), "a listed source stays listed, days later");
        assert_eq!(r.see(&logon(t0 + 90002.0, "U9", "other", "T1", false)), None, "another source is not listed");
        assert_eq!(r.see(&logon(t0 + 90003.0, "U1", "A", "A", true)), None, "a local logon is not remote");

        let mut early = Relations::default(); // the same pattern during warm-up lists nobody
        for i in 0..6 {
            early.see(&logon(100.0 + i as f64, &format!("V{i}"), "A", "B", false));
        }
        early.see(&logon(200.0, "X", "A", "T1", true));
        assert_eq!(early.see(&logon(201.0, "Y", "A", "T2", true)), None);
        assert!(early.watched.is_empty(), "not armed before ARMED_S of history");

        let mut busy = Relations::default(); // a source that failed with 6 users before must beat 6
        busy.see(&logon(0.0, "U", "first", "D", true));
        for i in 0..6 {
            busy.see(&logon(t0 + i as f64, &format!("V{i}"), "S", "B", false));
        }
        for i in 0..6 {
            busy.see(&logon(t0 + 2.0 * H + i as f64, &format!("W{i}"), "S", "B", false));
        }
        assert!(busy.fired["S"][1].0 < t0 + H, "its own past peak raises the bar");
    }
}
