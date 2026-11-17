# /// script
# dependencies = ["numpy", "scikit-learn"]
# ///
"""Phase 8: plain baselines for the flies, on the same telemetry and scored the same way.

    uv run tools/baselines.py <train.jsonl> <calib.jsonl> <events.jsonl> <alarms.tsv>
    python3 tools/lanl_score.py <events.jsonl> <alarms.tsv>

Writes every alarmed second as "second, detector, suspects" (the FLYSOC_FLY_LOG format). Each
detector's threshold is the flies' rule: the CALM_QUANTILE of its per-second score over the benign
calibration file. Detectors:

  count:failed_users  distinct users failing from a source in 15 min (the identity fly's history)
  count:users         distinct users logging on from a source in 15 min, failed or not (ISSUES R1)
  count:dsts          distinct computers a source logs on to in 15 min
  count:ports         distinct destination ports a source connects to in 15 min (network fly's)
  count:procs         distinct processes started on a host in 60 s (endpoint fly's)
  iforest             isolation forest over per-source, per-minute activity (counts of logons,
                      users, destinations, failures, flows, ports, flow destinations, bytes,
                      processes), fitted on the training file; the minute's most anomalous source

Count detectors score a second by its most extreme event and blame that event's source and user.
"""
import json
import sys
from collections import Counter, defaultdict, deque

import numpy as np
from sklearn.ensemble import IsolationForest

CALM_QUANTILE = 0.995  # cluster.rs
LONG_S, SHORT_S = 900.0, 60.0

COUNTS = {  # name: (kind, key field, value field, window, only failures)
    "count:failed_users": ("auth", "src", "user", LONG_S, True),
    "count:users": ("auth", "src", "user", LONG_S, False),
    "count:dsts": ("auth", "src", "dst", LONG_S, False),
    "count:ports": ("conn", "src", "dport", LONG_S, False),
    "count:procs": ("proc", "host", "process", SHORT_S, False),
}


def read(path):
    with open(path) as f:
        for line in f:
            yield json.loads(line)


class Distinct:
    """Distinct values per key over a sliding window, O(1) amortised per event."""

    def __init__(self, window):
        self.window, self.q, self.c = window, defaultdict(deque), defaultdict(Counter)

    def add(self, key, ts, value):
        q, c = self.q[key], self.c[key]
        if value is not None:
            q.append((ts, value))
            c[value] += 1
        while q and q[0][0] < ts - self.window:
            _, v = q.popleft()
            c[v] -= 1
            if not c[v]:
                del c[v]
        return len(c)


def count_scores(path):
    """{detector: {second: (score, suspects)}}, the most extreme event per second."""
    state = {n: Distinct(w) for n, (_, _, _, w, _) in COUNTS.items()}
    out = {n: {} for n in COUNTS}
    for e in read(path):
        s = int(e["ts"])
        for n, (kind, key, val, _, fails) in COUNTS.items():
            if e["kind"] != kind:
                continue
            v = e.get(val)
            if fails and e.get("result") != "fail":
                v = None
            score = state[n].add(e[key], e["ts"], None if v is None else str(v))
            if score > out[n].get(s, (0,))[0]:
                out[n][s] = (score, [e[key]] + ([e["user"]] if "user" in e else []))
    return out


def minute_rows(path):
    """{(minute, source): feature vector} of per-source activity per minute."""
    rows = defaultdict(lambda: [0.0] * 9)
    sets = defaultdict(lambda: (set(), set(), set(), set()))  # users, auth dsts, ports, flow dsts
    for e in read(path):
        m = int(e["ts"]) // 60
        src = e.get("src") or e.get("host")
        r, (us, ds, ps, fs) = rows[(m, src)], sets[(m, src)]
        if e["kind"] == "auth":
            r[0] += 1
            us.add(e["user"]); ds.add(e["dst"])
            r[3] += e.get("result") == "fail"
        elif e["kind"] == "conn":
            r[4] += 1
            ps.add(e.get("dport")); fs.add(e["dst"])
        elif e["kind"] == "proc":
            r[8] += 1
    for k, (us, ds, ps, fs) in sets.items():
        r = rows[k]
        r[1], r[2], r[5], r[6] = len(us), len(ds), len(ps), len(fs)
    return rows


def features(rows):
    keys = list(rows)
    return keys, np.log1p(np.array([rows[k] for k in keys]))


def per_minute_max(keys, scores):
    best = {}
    for (m, src), sc in zip(keys, scores):
        if sc > best.get(m, (-1e9,))[0]:
            best[m] = (sc, [src])
    return best


def threshold(scores):
    xs = sorted(scores)
    return xs[round((len(xs) - 1) * CALM_QUANTILE)] if xs else 0


def main():
    train, calib, events, out = sys.argv[1:5]
    lines = []

    cal, ev = count_scores(calib), count_scores(events)
    cal_secs = max((s for d in cal.values() for s in d), default=0) + 1
    for n in COUNTS:
        thr = threshold([cal[n].get(s, (0,))[0] for s in range(cal_secs)])
        print(f"{n:>20}: alarm above {thr}", file=sys.stderr)
        lines += [(s, n, sus) for s, (sc, sus) in ev[n].items() if sc > thr]

    tk, tx = features(minute_rows(train))
    forest = IsolationForest(n_estimators=200, random_state=0).fit(tx)
    ck, cx = features(minute_rows(calib))
    thr = threshold([sc for sc, _ in per_minute_max(ck, -forest.score_samples(cx)).values()])
    ek, ex = features(minute_rows(events))
    print(f"{'iforest':>20}: alarm above {thr:.3f} (fitted on {len(tk)} source-minutes)", file=sys.stderr)
    for m, (sc, sus) in per_minute_max(ek, -forest.score_samples(ex)).items():
        if sc > thr:
            lines += [(m * 60 + k, "iforest", sus) for k in range(60)]

    with open(out, "w") as f:
        for s, n, sus in sorted(lines):
            f.write(f"{s}\t{n}\t{','.join(sus)}\n")


if __name__ == "__main__":
    main()
