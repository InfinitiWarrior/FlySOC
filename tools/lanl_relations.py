#!/usr/bin/env python3
"""A plain logon-relationship detector for LANL, beside the flies (ISSUES O25). No fly involved.

Three signals per source computer, each a count of distinct things over the last hour:
  new3    (user, dst) logons whose user-source, source-dst and user-dst pairs were all never seen
  fail    users that failed to log on from it
  newdst  destinations it never logged on to before
A signal counts only above both its line and the source's own highest count so far. A source alerts
when two signals count within an hour, from day 5 on (before that, history is too short for "new"
to mean anything). It then stays on a watchlist until an analyst clears it, and every later
successful remote logon from it is a lead.

    python3 -I tools/lanl_relations.py check
    python3 -I tools/lanl_relations.py dev|held|final out.jsonl [fly_alerts.json ...]   (one per slice)

Lines: the highest count any source reached on days 3-4, which hold no red team and come before
every scored slice. Lines from days 16-19 looked far better (75% on final) but used the future (O25).
"""
import json
import sys
from collections import defaultdict, deque

D, H = 86400, 3600
LINES = {"new3": 1, "fail": 2, "newdst": 10}
ARMED_S = 5 * D
SLICES = {
    "held": [(12 * D + 8 * H, "final_1"), (13 * D + 11 * H, "final_2"), (14 * D + 6 * H, "final_3")],
    "dev": [(8 * D + 9 * H, "eval_1"), (8 * D + 19 * H, "eval_2"), (15 * D + 15 * H, "eval_3"),
            (20 * D + 5 * H, "eval_4"), (21 * D + 7 * H, "eval_5"), (22 * D + 5 * H, "eval_6")],
    "final": [(26 * D + 13 * H, "final_4"), (27 * D + 8 * H, "final_5"), (28 * D + 10 * H, "final_6"),
              (29 * D + 11 * H, "final_7")],
}
SLICE_S = 4 * H
INCIDENT_GAP_S = 1800  # tools/lanl.py GAP_S
TAIL_S = 60  # tools/attribution.py


class Relations:
    def __init__(self):
        self.us, self.sd, self.ud = set(), set(), set()
        self.q = {k: defaultdict(deque) for k in LINES}
        self.peak = {k: defaultdict(int) for k in LINES}
        self.fired = defaultdict(dict)
        self.watched = set()

    def crossed(self, k, t, s, value):
        """Records `value` for signal k; True if it is a new value that takes s above the line."""
        q = self.q[k][s]
        before = len({v for _, v in q})
        q.append((t, value))
        while q[0][0] < t - H:
            q.popleft()
        n = len({v for _, v in q})
        own, self.peak[k][s] = self.peak[k][s], max(self.peak[k][s], n)
        if n > max(LINES[k], own) and n > before:
            self.fired[s][k] = t
            return True
        return False

    def see(self, t, u, s, d, ok):
        """One remote logon, in time order. Returns why it alerts, or None."""
        new_us, new_sd, new_ud = (u, s) not in self.us, (s, d) not in self.sd, (u, d) not in self.ud
        crossed = False
        if ok and new_us and new_sd and new_ud:
            crossed |= self.crossed("new3", t, s, (u, d))
        if not ok:
            crossed |= self.crossed("fail", t, s, u)
        if ok and new_sd:
            crossed |= self.crossed("newdst", t, s, d)
        if ok:
            self.us.add((u, s)), self.sd.add((s, d)), self.ud.add((u, d))
        if crossed and t >= ARMED_S and sum(t - v <= H for v in self.fired[s].values()) >= 2:
            self.watched.add(s)
            return "two signals"
        return "watchlist" if ok and s in self.watched else None


def incidents(slices, end):
    """Red-team incidents per slice: logons less than INCIDENT_GAP_S apart."""
    out = defaultdict(list)
    for t, u, s, d in sorted((int(a), b, c, e) for a, b, c, e in (l.strip().split(",") for l in open("data/lanl/redteam.txt"))):
        if t >= end:
            continue
        for a, name in slices:
            if a <= t < a + SLICE_S:
                x = out[name]
                if x and t - x[-1]["b"] < INCIDENT_GAP_S:
                    x[-1]["b"] = t
                    x[-1]["ents"] |= {u, s, d}
                else:
                    x.append({"a": t, "b": t, "ents": {u, s, d}})
    return out


def score(name, alerts, inc):
    """Alerts about one entity less than an hour apart are one queue entry."""
    tp, fp, caught, last = 0, 0, set(), {}
    for slice_name, t, who in sorted(alerts, key=lambda x: (x[0], x[1])):
        about = [i for i, x in enumerate(inc[slice_name]) if x["a"] <= t <= x["b"] + TAIL_S and who in x["ents"]]
        caught |= {(slice_name, i) for i in about}
        if t - last.get((slice_name, who), -1e12) >= H:
            tp, fp = tp + bool(about), fp + (not about)
        last[(slice_name, who)] = t
    total = sum(len(v) for v in inc.values())
    print(f"{name:26} queue {tp + fp:3}  about the attack {tp:3}  false {fp:3}  precision {tp / max(tp + fp, 1):4.0%}  incidents {len(caught)}/{total}")


def main(mode, out, flies):
    slices = SLICES[mode]
    end = max(a for a, _ in slices) + SLICE_S  # never reads past the last slice
    inc = incidents(slices, end)
    r, alerts = Relations(), []
    with open(out, "w") as f:
        for raw in open("data/lanl/auth.txt", "rb"):
            p = raw.rstrip().split(b",")
            t = int(p[0])
            if t >= end:
                break
            if p[7] != b"LogOn" or p[3] == p[4]:
                continue
            u = p[1].decode()
            if u.startswith("ANONYMOUS") or "$@" in u:
                continue
            s, d = p[3].decode(), p[4].decode()
            why = r.see(t, u, s, d, p[8] == b"Success")
            where = next((n for a, n in slices if a <= t < a + SLICE_S), None)
            if why and where:
                alerts.append((where, t, s))
                f.write(json.dumps({"slice": where, "ts": t, "entity": s, "why": why, "user": u, "dst": d}) + "\n")
    print("watchlist:", sorted(r.watched))
    score("relations", alerts, inc)
    if flies:
        rebased = []
        for (a, name), path in zip(slices, flies):
            rebased += [(name, json.loads(l)["ts_start"] + a, json.loads(l)["entity"]) for l in open(path)]
        score("identity fly", rebased, inc)


def check():
    T = ARMED_S
    r = Relations()
    for i in range(3):
        r.see(T + i, f"U{i}", "known", "D", True)
    assert r.see(T + 10, "U0", "known", "D", True) is None, "a known logon is quiet"
    for i in range(6):
        assert r.see(T + 100 + i, f"V{i}", "A", "B", False) is None, "failures alone never alert"
    assert r.see(T + 200, "X", "A", "T1", True) is None, "one new relationship is not above the new3 line"
    assert r.see(T + 201, "Y", "A", "T2", True) == "two signals", "fail and new3 within the hour"
    assert r.see(T + 90000, "U1", "A", "T1", True) == "watchlist", "a listed source stays listed, days later"
    assert r.see(T + 90002, "U9", "other", "T1", False) is None, "another source is not listed"

    early = Relations()  # the same pattern during warm-up lists nobody
    for i in range(6):
        early.see(100 + i, f"V{i}", "A", "B", False)
    early.see(200, "X", "A", "T1", True)
    assert early.see(201, "Y", "A", "T2", True) is None and not early.watched, "not armed before day 5"

    busy = Relations()  # a source that has failed with 6 users before must beat 6, not the line
    for i in range(6):
        busy.see(T + i, f"V{i}", "S", "B", False)
    for i in range(6):
        busy.see(T + 2 * H + i, f"W{i}", "S", "B", False)
    assert "fail" not in busy.fired["S"] or busy.fired["S"]["fail"] < T + H, "its own past peak raises the bar"
    print("ok")


if __name__ == "__main__":
    if sys.argv[1] == "check":
        check()
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3:])
