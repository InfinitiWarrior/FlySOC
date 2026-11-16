"""Scores the cases `flysoc cluster` assigns to its alerts (JSON field "case", ISSUES O14).

Per case, its queue entries (attribution.py: alerts about one entity less than GAP_S apart) are
attributed to an intrusion, a look-alike or nothing. Reported for incident cases (holding at least
one rule D incident) and for all cases (leads too): how many cases, how many hold an intrusion,
how many mix one with entries about something else, how many hold two intrusions, and how many
cases each intrusion is split into.

Run: python3 tools/cases.py <file> <alerts.jsonl> [<file> <alerts.jsonl> ...]
"""
import json, sys
from collections import defaultdict
from attribution import episodes, GAP_S, TAIL_S


def main(pairs):
    for name, keep in (("incident cases", lambda c: "incident" in c["kinds"]), ("all cases", lambda c: True)):
        tot, split = defaultdict(int), []
        for data, alerts in pairs:
            ep = episodes(data)
            cases, last = defaultdict(lambda: dict(tags=[], kinds=set())), {}
            for line in open(alerts):
                x = json.loads(line)
                s, ent, c = x["ts_start"], x["entity"], cases[x["case"]]
                c["kinds"].add(x["kind"])
                if s - last.get(ent, -1e9) >= GAP_S:
                    about = [lab for lab, (a, b, e) in ep.items() if a <= s <= b + TAIL_S and ent in e]
                    intr = [lab for lab in about if lab.startswith("intrusion")]
                    c["tags"].append(intr[0] if intr else about[0].split("@")[0] if about else "nothing")
                last[ent] = s
            cs = [c for c in cases.values() if keep(c)]
            has = lambda c: {t for t in c["tags"] if t.startswith("intrusion")}
            tot["cases"] += len(cs)
            tot["with an intrusion"] += sum(bool(has(c)) for c in cs)
            tot["mixed"] += sum(bool(has(c)) and any(not t.startswith("intrusion") for t in c["tags"]) for c in cs)
            tot["two intrusions"] += sum(len(has(c)) > 1 for c in cs)
            tot["without an intrusion"] += sum(not has(c) for c in cs)
            split += [sum(lab in has(c) for c in cs) for lab in ep if lab.startswith("intrusion")]
        print(f"{name:15} " + "  ".join(f"{k}: {v}" for k, v in tot.items()), f"  cases per intrusion: {sorted(split)}")


if __name__ == "__main__":
    a = sys.argv[1:]
    main(list(zip(a[::2], a[1::2])))
