"""Render the completed collector measurements; no processes are sampled here.

Development-only dependency: matplotlib. The application does not use Python.
"""
import csv
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

root = Path(__file__).resolve().parents[1] / "docs/benchmarks"
prefix = root / "2026-11-04-linux-capture"
data = json.loads(prefix.with_suffix(".json").read_text())
samples = list(csv.DictReader(prefix.with_suffix(".csv").open()))
paper, panel, text, line = "#f4f3ef", "#fffefa", "#282a29", "#d5d6ce"
colours = {"python": "#707b73", "rust": "#a58b5e"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
fig, axes = plt.subplots(2, 2, figsize=(11, 7), facecolor=paper)
fig.subplots_adjust(top=.79, bottom=.14, hspace=.55, wspace=.28)
fig.text(.07, .945, "GENYRA  /  SNITCH", color=text, fontsize=19, weight="bold")
fig.text(.07, .90, "Linux collector comparison · 4 November 2026", color=text, fontsize=13)
fig.text(.07, .865, "300 seconds of concurrent real traffic after 45 seconds of warm-up · no frontends attached", color="#62685e", fontsize=10)
for axis in axes.flat:
    axis.set_facecolor(panel)
    axis.tick_params(colors=text)
    axis.spines["left"].set_color(line)
    axis.spines["bottom"].set_color(line)
    axis.grid(axis="y", color=line, linewidth=.6, alpha=.6, zorder=0)

for axis, key, heading, unit in [
    (axes[0, 0], "cpu_one_core_percent", "Average CPU", "% of one logical core"),
    (axes[0, 1], "rss_mean_mib", "Mean resident memory", "MiB RSS"),
]:
    values = [data["collectors"][name][key] for name in ("python", "rust")]
    bars = axis.bar(["Python", "Current Rust"], values, width=.46, color=[colours["python"], colours["rust"]], zorder=3)
    axis.set_title(heading, loc="left", color=text, weight="bold", pad=12)
    axis.set_ylabel(unit, color=text)
    axis.set_ylim(0, max(values)*1.23)
    for bar, value in zip(bars, values):
        axis.text(bar.get_x()+bar.get_width()/2, bar.get_height()+max(values)*.035, f"{value:.2f}", ha="center", color=text, weight="bold")

for name in ("python", "rust"):
    rows = [row for row in samples if row["collector"] == name]
    seconds = [float(row["elapsed_s"]) for row in rows]
    axes[1, 0].plot(seconds, [float(row["cpu_one_core_percent"]) for row in rows], color=colours[name], linewidth=1.1, label="Python" if name=="python" else "Current Rust")
    axes[1, 1].plot(seconds, [int(row["rss_bytes"])/1048576 for row in rows], color=colours[name], linewidth=1.7)
for axis, heading, unit in [(axes[1,0], "CPU over time", "% of one logical core"), (axes[1,1], "Resident memory over time", "MiB RSS")]:
    axis.set_title(heading, loc="left", color=text, weight="bold", pad=12)
    axis.set_xlabel("Seconds", color=text)
    axis.set_ylabel(unit, color=text)
    axis.set_xlim(0, 300)
    axis.set_ylim(bottom=0)
axes[1, 0].legend(frameon=False, loc="upper right", fontsize=9)
fig.text(.07,.065,"Collector processes only. Capture defaults differ; this is not a complete-app or feature-parity benchmark.",color="#62685e",fontsize=9)
fig.text(.07,.035,"100% CPU = one logical core. Source values, build identities and scope are in the accompanying CSV, JSON and report.",color="#62685e",fontsize=9)
fig.savefig(prefix.with_suffix(".png"), dpi=170, facecolor=paper)
fig.savefig(prefix.with_suffix(".svg"), facecolor=paper)
svg = prefix.with_suffix(".svg")
svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
