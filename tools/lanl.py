#!/usr/bin/env python3
"""Cut a time slice of the LANL "Comprehensive, Multi-Source Cyber-Security Events" data
(Kent 2015, https://csr.lanl.gov/data/cyber1/) into FlySOC JSON telemetry.

    python3 tools/lanl.py <start_s> <hours> <out.jsonl>     (reads data/lanl/*.txt, unpacked)

Times are rebased so the slice starts at 0. What each fly smells:
  auth  remote logons by human accounts: LogOn, src != dst, not a machine (C123$) or ANONYMOUS
        account. LogOffs repeat the logon; local and machine logons are 7 in 8 auth lines and say
        nothing about lateral movement. Every red-team line is a human remote NTLM LogOn.
  conn  flows; dport is the destination port when it is a number, 0 when LANL anonymised it (N123)
  proc  process starts (Ends dropped); there is no parent in this data
  dns   "computer resolved computer": the query is the resolved computer's name
Labels: an auth line whose (time, user, src, dst) is in redteam.txt is the intrusion; red-team
lines less than GAP_S apart share one incident "intrusion@<first ts>:lateral". Everything else,
including the red team's unlabelled flows and processes, is "benign": LANL only labels logons.
"""
import json
import os
import sys

DIR = "data/lanl"
GAP_S = 1800


def seek(f, t):
    """Byte offset of the first line with time >= t in a file sorted by its first column."""
    lo, hi = 0, os.fstat(f.fileno()).st_size
    while hi - lo > 1 << 16:
        mid = (lo + hi) // 2
        f.seek(mid)
        f.readline()
        line = f.readline()
        if line and int(line.split(b",", 1)[0]) < t:
            lo = mid
        else:
            hi = mid
    f.seek(lo)
    if lo:
        f.readline()
    while True:
        pos = f.tell()
        line = f.readline()
        if not line or int(line.split(b",", 1)[0]) >= t:
            f.seek(pos)
            return


def rows(name, start, end):
    with open(f"{DIR}/{name}.txt", "rb") as f:
        seek(f, start)
        for line in f:
            r = line.decode().rstrip("\n").split(",")
            if int(r[0]) >= end:
                return
            yield r


def human(user):
    return not user.split("@")[0].endswith("$") and not user.startswith("ANONYMOUS")


def events(start, end):
    red = sorted(tuple(r) for r in rows("redteam", start, end))
    incident, last = {}, None
    for t, user, src, dst in red:
        if last is None or int(t) - last > GAP_S:
            first = int(t) - start
        incident[(t, user, src, dst)] = f"intrusion@{first}:lateral"
        last = int(t)
    ts = lambda t: int(t) - start
    for t, su, du, src, dst, _atype, _ltype, orient, result in rows("auth", start, end):
        if orient == "LogOn" and src != dst and human(su):
            label = incident.get((t, su, src, dst), "benign")
            yield {"ts": ts(t), "kind": "auth", "src": src, "dst": dst, "user": su, "result": "ok" if result == "Success" else "fail", "label": label}
    for t, _dur, src, _sport, dst, dport, *_ in rows("flows", start, end):
        yield {"ts": ts(t), "kind": "conn", "src": src, "dst": dst, "dport": int(dport) if dport.isdigit() else 0, "label": "benign"}
    for t, _user, host, proc, what in rows("proc", start, end):
        if what == "Start":
            yield {"ts": ts(t), "kind": "proc", "host": host, "process": proc, "label": "benign"}
    for t, host, resolved in rows("dns", start, end):
        yield {"ts": ts(t), "kind": "dns", "host": host, "query": resolved, "label": "benign"}


def main():
    start, hours, out = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
    evs = list(events(start, start + int(hours * 3600)))
    # LANL times are whole seconds: spread each second's events over it so puffs don't all land in one bin
    evs.sort(key=lambda e: e["ts"])
    i = 0
    while i < len(evs):
        j = i
        while j < len(evs) and evs[j]["ts"] == evs[i]["ts"]:
            j += 1
        for k in range(i, j):
            evs[k]["ts"] = round(evs[k]["ts"] + (k - i) / (j - i), 3)
        i = j
    with open(out, "w") as f:
        for e in evs:
            f.write(json.dumps(e) + "\n")
    red = {e["label"] for e in evs if e["label"] != "benign"}
    print(f"{out}: {len(evs)} events, {sum(e['label'] != 'benign' for e in evs)} red-team logons in {len(red)} incidents", file=sys.stderr)


if __name__ == "__main__":
    main()
