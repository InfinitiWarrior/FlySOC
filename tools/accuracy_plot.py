"""Plots docs/accuracy.png: flies against Phase 8's baselines on the final sets, scored alike.

Run: uv run --with matplotlib tools/accuracy_plot.py
The numbers are README "Baselines (Phase 8)" (tools/lanl_score.py over data/runs/p8/ and the
latest flies runs); update both together.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# detector: (about the attack, false, named, of)
SYNTHETIC = {
    "single fly": (21, 0, 10, 10), "network fly": (22, 5, 9, 10), "identity fly": (18, 0, 10, 10),
    "dns fly": (10, 3, 10, 10), "endpoint fly": (8, 10, 6, 10),
    "count: processes": (10, 0, 10, 10), "count: failed users": (37, 7, 10, 10),
    "count: logon dsts": (0, 8, 0, 10), "count: ports": (0, 1, 0, 10), "isolation forest": (1, 2, 1, 10),
}
LANL = {
    "identity fly": (19, 7, 2, 6), "dns fly": (0, 0, 0, 6), "single fly": (0, 33, 0, 6), "endpoint fly": (0, 44, 0, 6),
    "count: failed users": (33, 12, 2, 6), "count: users": (2, 3, 1, 6), "count: logon dsts": (2, 10, 1, 6),
    "count: processes": (0, 43, 0, 6), "isolation forest": (0, 9, 0, 6),
}
ink, muted, surface, grid = "#0b0b0b", "#52514e", "#fcfcfb", "#e6e5e0"
good, bad = "#2a78d6", "#eb6834"

fig, axes = plt.subplots(1, 2, figsize=(15, 5.6), facecolor=surface)
for ax, (title, rows) in zip(axes, [("Synthetic final (cluster_final_31-35): 10 intrusions", SYNTHETIC),
                                    ("LANL final (days 12-14, 12 h): 6 red-team incidents", LANL)]):
    names = list(rows)[::-1]
    att = [rows[n][0] for n in names]
    fal = [rows[n][1] for n in names]
    ax.barh(names, att, color=good, label="episodes about the attack")
    ax.barh(names, fal, left=att, color=bad, label="false episodes")
    for y, n in enumerate(names):
        a, f, named, of = rows[n]
        ax.annotate(f"named {named}/{of}" + (f"  ·  {a / (a + f):.0%} precise" if a + f else "  ·  silent"),
                    (a + f, y), xytext=(6, 0), textcoords="offset points", va="center", fontsize=9, color=ink)
    ax.set_title(title, color=ink, fontsize=11, loc="left")
    ax.set_xlabel("alarm episodes", color=muted)
    ax.set_facecolor(surface)
    ax.grid(axis="x", color=grid, lw=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=muted)
    ax.set_xlim(0, max(a + f for a, f, _, _ in rows.values()) * 1.45)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#c9c8c2")
    for lab in ax.get_yticklabels():
        lab.set_color(ink if lab.get_text().endswith("fly") else muted)
axes[0].legend(frameon=False, loc="lower right", fontsize=9)
fig.suptitle("Flies (dark labels) against plain baselines, same telemetry, same scoring", color=ink, fontsize=12, x=0.01, ha="left")
fig.tight_layout()
fig.savefig("docs/accuracy.png", dpi=110, facecolor=surface)
