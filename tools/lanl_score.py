#!/usr/bin/env python3
"""Score per-fly alarms on a LANL slice (or any labelled telemetry) by who they blame (LANL incidents last hours, so "an alarm
fired during the incident" means nothing).

    FLYSOC_FLY_LOG=fly.tsv flysoc cluster <train> <slice.jsonl>
    python3 tools/lanl_score.py <slice.jsonl> <fly.tsv> [<slice.jsonl> <fly.tsv> ...]

With several pairs it prints each, then totals per fly: episodes, about the attack, false,
incidents named and the median first naming.

An alarm episode is a fly's alarmed seconds less than GAP_S apart. It is about the attack if one
of its suspects (computer or account) took part in a red-team logon from BEFORE_S before the
episode to AFTER_S after its start; otherwise it is a false episode.
"""
import bisect
import json
import statistics
import sys
from collections import defaultdict

GAP_S, BEFORE_S, AFTER_S = 60, 600, 60


def score(slice_, log):
    """Prints one file's table; returns {fly: (episodes, about the attack, [first naming s])}."""
    red = defaultdict(list)  # entity -> red-team logon times
    incidents = {}  # label -> first ts
    for line in open(slice_):
        if '"intrusion' not in line:
            continue
        e = json.loads(line)
        for k in ("src", "dst", "user", "host"):
            if k in e:
                red[e[k]].append(e["ts"])
        incidents.setdefault(e["label"].rsplit(":", 1)[0], e["ts"])  # synthetic: intrusion@T:<stage>
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
    print(f"{'fly':>20}  {'episodes':>8}  {'about attack':>12}  {'false':>5}  first naming of the attack (s after incident start)")
    out = {}
    for fly, ep in eps.items():
        hits = [(e[0], about(e)) for e in ep if about(e)]
        first = {}
        for s, x in hits:
            lab = max((l for l, t in incidents.items() if t <= s), key=lambda l: incidents[l], default=None)
            if lab and lab not in first:
                first[lab] = (s - int(incidents[lab]), x)
        print(f"{fly:>20}  {len(ep):>8}  {len(hits):>12}  {len(ep) - len(hits):>5}  {', '.join(f'+{d}s ({x})' for d, x in first.values())}")
        out[fly] = (len(ep), len(hits), [d for d, _ in first.values()])
    return out, len(incidents)


def main():
    args = sys.argv[1:]
    total, incidents = {}, 0
    for slice_, log in zip(args[::2], args[1::2]):
        res, n = score(slice_, log)
        incidents += n
        for fly, (e, a, first) in res.items():
            t = total.setdefault(fly, [0, 0, []])
            t[0] += e; t[1] += a; t[2] += first
    if len(args) > 2:
        print(f"\ntotal over {len(args) // 2} files, {incidents} incidents")
        print(f"{'fly':>20}  {'episodes':>8}  {'about attack':>12}  {'false':>5}  {'named':>5}  median first naming")
        for fly, (e, a, first) in sorted(total.items(), key=lambda x: x[1][0] - x[1][1]):
            med = f"+{statistics.median(first):.0f} s" if first else "-"
            print(f"{fly:>20}  {e:>8}  {a:>12}  {e - a:>5}  {len(first):>5}  {med}")


if __name__ == "__main__":
    main()
