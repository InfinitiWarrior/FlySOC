"""ISSUES L8 (was O9): why blue retrained on red's intrusions (red.py harden) caught fewer of them.

Run: python3 tools/o9.py <out_dir> <train.jsonl>...   (out_dir is a red.py evolve run)
Replays the harden duel (red's 3 best + baseline on backgrounds 7001-7003) against each blue with
FLYSOC_TRACE, then prints per fly: its threshold, and per stage the peak evidence (the coordinator's
EVIDENCE_S average of MBON spikes) during that stage, divided by the threshold (>1 = the fly fires).
"""
import os, re, subprocess, sys, json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from red import baseline, best, scenario  # noqa: E402

EVIDENCE_S = 20.0
STAGES = ["recon", "spray", "lateral", "exfil"]


def trace(train, path):
    tr = path + ".tsv"
    r = subprocess.run(["./target/release/flysoc", "cluster", train, path], capture_output=True, text=True,
                       env=dict(os.environ, FLYSOC_TRACE=tr))
    th = {m[1]: float(m[2]) for m in re.finditer(r"(\w+): fires above ([\d.]+)", r.stderr)}
    rows = [line.rstrip("\n").split("\t") for line in open(tr)][1:]
    os.remove(tr)
    return th, rows


def main(out, trains):
    genomes = best(out, 3) + [baseline()]
    files = []
    for i, g in enumerate(genomes):
        for s in (7001, 7002, 7003):
            ev, _ = scenario(g, s)
            p = f"{out}/o9_{i}_{s}.jsonl"
            with open(p, "w") as f:
                f.writelines(json.dumps(dict(e, ts=round(e["ts"], 3))) + "\n" for e in sorted(ev, key=lambda e: e["ts"]))
            files.append(p)
    for train in trains:
        peaks = defaultdict(list)  # (fly, stage) -> peak/threshold per file
        for p in files:
            th, rows = trace(train, p)
            flies = list(th)
            ema = [0.0] * len(flies)
            peak = defaultdict(float)
            for r in rows:
                for f in range(len(flies)):
                    ema[f] += (int(r[1 + f]) - ema[f]) / EVIDENCE_S
                for st in STAGES:
                    if f":{st}" in r[-1]:
                        for f, name in enumerate(flies):
                            peak[name, st] = max(peak[name, st], ema[f] / th[name])
            for k, v in peak.items():
                peaks[k].append(v)
        print(f"\n{train}")
        print(f"{'fly':>10} {'threshold':>9}  " + "  ".join(f"{s:>14}" for s in STAGES))
        for name in flies:
            cells = []
            for st in STAGES:
                v = sorted(peaks[name, st])
                cells.append(f"{v[len(v) // 2]:.2f} ({sum(x > 1 for x in v):>2}/{len(v)})")
            print(f"{name:>10} {th[name]:>9.1f}  " + "  ".join(f"{c:>14}" for c in cells))
    for p in files:
        os.remove(p)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
