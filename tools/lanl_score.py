#!/usr/bin/env python3
"""Score per-fly alarms on a LANL slice by who they blame (LANL incidents last hours, so "an alarm
fired during the incident" means nothing).

    FLYSOC_FLY_LOG=fly.tsv flysoc cluster <train> <slice.jsonl>
    python3 tools/lanl_score.py <slice.jsonl> <fly.tsv>

An alarm episode is a fly's alarmed seconds less than GAP_S apart. It is about the attack if one
of its suspects (computer or account) took part in a red-team logon from BEFORE_S before the
episode to AFTER_S after its start; otherwise it is a false episode.
"""
import bisect
import json
import sys
from collections import defaultdict

GAP_S, BEFORE_S, AFTER_S = 60, 600, 60


def main():
    slice_, log = sys.argv[1], sys.argv[2]
    red = defaultdict(list)  # entity -> red-team logon times
    incidents = {}  # label -> first ts
    for line in open(slice_):
        if '"intrusion' not in line:
            continue
        e = json.loads(line)
        for k in ("src", "dst", "user"):
            red[e[k]].append(e["ts"])
        incidents.setdefault(e["label"], e["ts"])
    for v in red.values():
        v.sort()

    eps = defaultdict(list)  # fly -> [start, last, suspects]
    for line in open(log):
        s, fly, sus = line.rstrip("\n").split("\t")
        s, sus = int(s), set(filter(None, sus.split(",")))
        if eps[fly] and s - eps[fly][-1][1] < GAP_S:
            eps[fly][-1][1] = s
            eps[fly][-1][2] |= sus
        else:
            eps[fly].append([s, s, sus])

    def about(ep):
        start, _, sus = ep
        for x in sus & red.keys():
            i = bisect.bisect_left(red[x], start - BEFORE_S)
            if i < len(red[x]) and red[x][i] <= start + AFTER_S:
                return x
        return None

    print(f"{slice_}: {len(incidents)} incidents, attacker entities {sorted(red)[:6]}{'...' if len(red) > 6 else ''}")
    print(f"{'fly':>11}  {'episodes':>8}  {'about attack':>12}  {'false':>5}  first naming of the attack (s after incident start)")
    for fly, ep in eps.items():
        hits = [(e[0], about(e)) for e in ep if about(e)]
        first = {}
        for s, x in hits:
            lab = max((l for l, t in incidents.items() if t <= s), key=lambda l: incidents[l], default=None)
            if lab and lab not in first:
                first[lab] = f"+{s - int(incidents[lab])}s ({x})"
        print(f"{fly:>11}  {len(ep):>8}  {len(hits):>12}  {len(ep) - len(hits):>5}  {', '.join(first.values())}")


if __name__ == "__main__":
    main()
