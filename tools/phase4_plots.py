"""Plots docs/calibration.png (ISSUES L8) and docs/red_vs_blue.png (E10, O12).

Run: uv run --with matplotlib tools/phase4_plots.py
The numbers are copied from the runs documented in docs/ISSUES.md (raw output in data/runs/calib/,
data/runs/two/), so the graphs can be redrawn without rerunning hours of simulation.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ink, muted, grid, edge, surface = "#0b0b0b", "#52514e", "#e6e5e0", "#c9c8c2", "#fcfcfb"
blue, orange = "#2a78d6", "#eb6834"


def style(ax, title):
    ax.set_facecolor(surface)
    ax.set_title(title, color=ink, fontsize=11, loc="left")
    ax.grid(axis="y", color=grid, lw=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=muted)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(edge)


# L8: calm quantile sweep on the eval set, thresholds from training + calibration replay, rule D
q = ["99th", "99.5th\n(chosen)", "99.8th", "99.9th", "99.95th"]
first = [64, 88, 107, 372, 612]
looks = [26, 22, 20, 19, 17]
fig, axes = plt.subplots(1, 2, figsize=(12, 4.2), facecolor=surface)
for ax, ys, title in [(axes[0], first, "Median first alert (s)  ↓ better"), (axes[1], looks, "Look-alikes alerted (of 50)  ↓ better")]:
    bars = ax.bar(q, ys, color=[orange if "chosen" in x else blue for x in q], width=0.6, edgecolor=surface, linewidth=2)
    for b, y in zip(bars, ys):
        ax.annotate(f"{y}", (b.get_x() + b.get_width() / 2, y), xytext=(0, 4), textcoords="offset points", ha="center", color=ink, fontsize=9)
    style(ax, title)
    ax.set_xlabel("calm quantile the threshold sits at (0 false-alert seconds at every one)", color=muted)
fig.suptitle("Threshold calibration on ~14,000 calm seconds: eval set, rule D", color=ink, fontsize=12, x=0.01, ha="left")
fig.tight_layout()
fig.savefig("docs/calibration.png", dpi=110, facecolor=surface)

# E10 / O12: red progress on 20 fresh backgrounds (9001-9020), and which fly sees the slow scan
fig, axes = plt.subplots(1, 2, figsize=(13, 4.4), facecolor=surface, gridspec_kw=dict(width_ratios=[1.3, 1]))
genomes = ["red #1", "red #2\n(slow scan)", "red #3\n(slow scan)", "baseline\nintrusion"]
old, new = [0.60, 0.83, 0.83, 0.53], [0.58, 0.79, 0.79, 0.33]
x = range(len(genomes))
w = 0.38
ax = axes[0]
for off, ys, colour, label in [(-w / 2, old, blue, "history over 60 s"), (w / 2, new, orange, "+ 15-minute counts (E10)")]:
    bars = ax.bar([i + off for i in x], ys, w, color=colour, edgecolor=surface, linewidth=2, label=label)
    for b, y in zip(bars, ys):
        ax.annotate(f"{y:.2f}", (b.get_x() + b.get_width() / 2, y), xytext=(0, 4), textcoords="offset points", ha="center", color=ink, fontsize=9)
ax.set_xticks(list(x), genomes)
ax.set_ylim(0, 1.05)
style(ax, "Red's kill-chain progress before rule D fires  ↓ better for blue")
ax.legend(frameon=False, labelcolor=ink, loc="upper right")
ax = axes[1]
flies = ["network", "identity", "endpoint", "dns", "single fly"]
seen = [12, 2, 3, 0, 5]
bars = ax.bar(flies, seen, color=[orange if f == "single fly" else blue for f in flies], width=0.6, edgecolor=surface, linewidth=2)
for b, y in zip(bars, seen):
    ax.annotate(f"{y}/12", (b.get_x() + b.get_width() / 2, y), xytext=(0, 4), textcoords="offset points", ha="center", color=ink, fontsize=9)
ax.set_ylim(0, 13.5)
style(ax, "Replays whose slow scan crosses the fly's threshold")
ax.set_xlabel("rule D needs the single fly (O12)", color=muted)
fig.tight_layout()
fig.savefig("docs/red_vs_blue.png", dpi=110, facecolor=surface)
print("wrote docs/calibration.png, docs/red_vs_blue.png")
