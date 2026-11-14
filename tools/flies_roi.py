"""Plots docs/flies_roi.png: what more individual flies per role buy, on cluster_eval_21..25.

Run: python3 tools/flies_roi.py   (after the sweep below; needs matplotlib, e.g. via uv run --with)
  for R in 1 2 3 4 6 10; do s=$(date +%s); for i in 21 22 23 24 25; do
    FLYSOC_REPLICAS=$R ./target/release/flysoc cluster data/telemetry/cluster_train.jsonl \
      data/telemetry/cluster_eval_$i.jsonl >/dev/null 2>data/runs/flies${R}_eval_$i.txt; done
    echo "$R $(( $(date +%s)-s ))" >> data/runs/flies_time.txt; done
"""
import glob, os, statistics, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scorecards import totals  # noqa: E402

SERIES = {"single fly": ("#2a78d6", "single fly"), "cluster D confirmed": ("#eb6834", "cluster D (default)")}
times = dict(tuple(map(int, line.split())) for line in open("data/runs/flies_time.txt"))
Rs = sorted(times)
rows = {R: totals(sorted(glob.glob(f"data/runs/flies{R}_eval_*.txt"))) for R in Rs}
value = {"fa": lambda r: r["fa"], "look": lambda r: r["look"], "caught": lambda r: r["caught"],
         "lat": lambda r: statistics.median(r["lat"]) if r["lat"] else 0}
flies = [5 * R for R in Rs]
panels = [("fa", "False-alert seconds (of 2809)  ↓ better"), ("look", "Look-alikes alerted (of 50)  ↓ better"),
          ("lat", "Median first alert (s)  ↓ better"), ("caught", "Intrusions caught (of 10)  ↑ better")]
ink, muted, surface = "#0b0b0b", "#52514e", "#fcfcfb"
fig, axes = plt.subplots(1, 5, figsize=(19, 4.2), facecolor=surface)
for ax, (key, title) in zip(axes, panels):
    for name, (colour, label) in SERIES.items():
        ys = [value[key](rows[R][name]) for R in Rs]
        ax.plot(flies, ys, color=colour, lw=2, marker="o", ms=8, mec=surface, mew=2, label=label)
        ax.annotate(f"{ys[-1]:g}", (flies[-1], ys[-1]), xytext=(6, 0), textcoords="offset points", color=ink, va="center", fontsize=9)
    ax.set_title(title, color=ink, fontsize=11, loc="left")
axes[4].plot(flies, [times[R] for R in Rs], color=muted, lw=2, marker="o", ms=8, mec=surface, mew=2)
axes[4].set_title("Cost: wall time, train + 5 files (s)", color=ink, fontsize=11, loc="left")
for ax in axes:
    ax.set_facecolor(surface); ax.set_xticks(flies); ax.set_xlabel("flies in the cluster (5 roles × individuals)", color=muted)
    ax.grid(axis="y", color="#e6e5e0", lw=0.8); ax.tick_params(colors=muted); ax.set_ylim(bottom=0)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    for s in ("left", "bottom"): ax.spines[s].set_color("#c9c8c2")
axes[0].legend(frameon=False, labelcolor=ink)
fig.suptitle("How many flies are worth it?  Eval set cluster_eval_21–25 (10 intrusions, 50 look-alikes)", color=ink, x=0.01, ha="left", fontsize=13)
fig.tight_layout()
fig.savefig("docs/flies_roi.png", dpi=110)
print("wrote docs/flies_roi.png")
