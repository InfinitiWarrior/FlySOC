"""Sums `flysoc cluster` scorecards (its stderr) over several files.

Run: python3 tools/scorecards.py run_21.txt run_22.txt ...
Prints one line per fly and rule: intrusions caught, median first alert, look-alikes alerted and
false-alert seconds, over all files together.
"""
import re, statistics, sys

LINE = re.compile(r"^\s*(.+?)\s{2,}(\d+)/(\d+) \(([^)]*)\)\s+(\d+)/(\d+).*?\s(\d+)/(\d+)\s*$")


def totals(paths):
    rows = {}
    for path in paths:
        for line in open(path):
            m = LINE.match(line)
            if not m:
                continue
            r = rows.setdefault(m[1], dict(caught=0, intr=0, lat=[], look=0, looks=0, fa=0, plain=0))
            r["caught"] += int(m[2]); r["intr"] += int(m[3])
            r["lat"] += [int(x) for x in re.findall(r"\+(\d+)s", m[4])]
            r["look"] += int(m[5]); r["looks"] += int(m[6]); r["fa"] += int(m[7]); r["plain"] += int(m[8])
    return rows


if __name__ == "__main__":
    print(f"{'':22} {'caught':>7} {'median first alert':>19} {'look-alikes':>12} {'false alert s':>14}")
    for name, r in totals(sys.argv[1:]).items():
        med = f"+{statistics.median(r['lat']):.0f} s" if r["lat"] else "-"
        print(f"{name:22} {r['caught']:>3}/{r['intr']:<3} {med:>19} {r['look']:>5}/{r['looks']:<6} {r['fa']:>6}/{r['plain']}")
