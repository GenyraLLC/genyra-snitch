"""Plot recorded application data only; never reruns a resource measurement."""
import csv
import gzip
import io
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

root = Path(__file__).resolve().parents[1] / "docs/benchmarks"
background = json.loads((root / "2026-11-04-linux-capture.json").read_text())
application = json.loads((root / "2026-11-04-linux-application.json").read_text())
paper, panel, text, line = "#f4f3ef", "#fffefa", "#282a29", "#d5d6ce"
colours = {"python": "#707b73", "rust": "#a58b5e"}
plt.rcParams.update({"font.family":"DejaVu Sans", "font.size":10, "axes.spines.top":False, "axes.spines.right":False})

def style(axis):
    axis.set_facecolor(panel)
    axis.tick_params(colors=text)
    for side in ("left", "bottom"): axis.spines[side].set_color(line)
    axis.grid(axis="y",color=line,linewidth=.6,alpha=.6,zorder=0)

def save(fig, name):
    fig.savefig(root / (name+".png"),dpi=170,facecolor=paper)
    svg=root / (name+".svg")
    fig.savefig(svg,facecolor=paper)
    svg.write_text("\n".join(row.rstrip() for row in svg.read_text().splitlines())+"\n")
    plt.close(fig)

fig,axes=plt.subplots(2,2,figsize=(11,8),facecolor=paper)
fig.subplots_adjust(top=.78,bottom=.15,hspace=.65,wspace=.3)
fig.text(.07,.945,"GENYRA SNITCH  /  LINUX ALPHA",color=text,fontsize=18,weight="bold")
fig.text(.07,.90,"Background and complete-application resource measurements",color=text,fontsize=12)
fig.text(.07,.86,"Separate five-minute real-traffic cohorts · 4 November 2026 · mean process measurements",color="#62685e",fontsize=10)
for row,(mode,data) in enumerate((("Background collectors",background["collectors"]),("Applications open",application["applications"]))):
    for column,(key,unit) in enumerate((("cpu_one_core_percent","CPU · one logical core = 100%"),("rss_mean_mib","Mean summed RSS · MiB"))):
        axis=axes[row,column];style(axis)
        values=[data[name][key] for name in ("python","rust")]
        bars=axis.bar(["Original","Genyra"],values,width=.46,color=[colours["python"],colours["rust"]],zorder=3)
        axis.set_title(mode+"\n"+unit,loc="left",color=text,weight="bold",fontsize=11,pad=12)
        axis.set_ylim(0,max(values)*1.22)
        for bar,value in zip(bars,values):axis.text(bar.get_x()+bar.get_width()/2,bar.get_height()+max(values)*.04,f"{value:,.2f}",ha="center",weight="bold",color=text)
fig.text(.07,.075,"Application PSS (shared pages apportioned): original 755.24 MiB → native 113.77 MiB.",fontsize=10,color=text)
fig.text(.07,.045,"Capture policies, UI layouts and animation cadences differ; not equal-cadence rendering or full feature parity.",fontsize=9,color="#62685e")
fig.text(.07,.02,"Native application RSS grew 18.44 MiB during its run. These are workload-specific samples, not long-term guarantees.",fontsize=9,color="#62685e")
save(fig,"2026-11-04-resource-modes")

samples=list(csv.DictReader((root/"2026-11-04-linux-application.csv").open()))
fig,axes=plt.subplots(3,1,figsize=(11,8),facecolor=paper)
fig.subplots_adjust(top=.82,bottom=.14,hspace=.48,left=.1,right=.95)
fig.text(.1,.945,"APPLICATION RUN  /  LINUX ALPHA",color=text,fontsize=18,weight="bold")
fig.text(.1,.90,"All collector, renderer, GPU and helper processes included",color=text,fontsize=12)
for axis,(key,unit,title) in zip(axes,(("cpu_one_core_percent",1,"CPU · % of one logical core"),("rss_bytes",1048576,"Summed RSS · MiB"),("pss_bytes",1048576,"Summed PSS · MiB"))):
    style(axis)
    for name in ("python","rust"):
        rows=[r for r in samples if r["application"]==name]
        axis.plot([float(r["elapsed_s"]) for r in rows],[float(r[key])/unit for r in rows],color=colours[name],linewidth=1.4,label="Original Python / Electron" if name=="python" else "Native Rust")
    axis.set_title(title,loc="left",fontsize=11,weight="bold",color=text)
    axis.set_xlim(0,300);axis.set_ylim(bottom=0)
axes[0].legend(frameon=False,fontsize=9,loc="upper right")
axes[-1].set_xlabel("Seconds")
fig.text(.1,.055,"45-second warm-up; 300-second measurement. Both RSS values grew; no multi-hour stability claim.",color="#62685e",fontsize=9)
fig.text(.1,.025,"Linux x86-64, 1440 × 1040 windows, dark / English graph views; configured implementations and cadences differ.",color="#62685e",fontsize=9)
save(fig,"2026-11-04-application-timeseries")

fig,axes=plt.subplots(1,2,figsize=(12,5.5),facecolor=paper)
fig.subplots_adjust(top=.69,bottom=.27,wspace=.3)
fig.text(.08,.94,"VISUAL SCHEDULING  /  LINUX ALPHA",color=text,fontsize=18,weight="bold")
fig.text(.08,.86,"Native: 38.16 update callbacks/s · Electron: 116.39 rAF callbacks/s",color=text,fontsize=12)
fig.text(.08,.80,"Different mechanisms and cadence — not presented FPS or directly comparable input latency",color="#62685e",fontsize=10)
for name,colour in (("electron",colours["python"]),("native",colours["rust"])):
    rows=list(csv.DictReader(io.StringIO(gzip.decompress((root/f"2026-11-04-{name}-callbacks.csv.gz").read_bytes()).decode())))
    for axis,key in zip(axes,("frame_interval_ms","repaint_latency_ms")):
        values=[r for r in rows if r[key]]
        if key=="frame_interval_ms":
            buckets={}
            for row in values:buckets.setdefault(int(float(row["elapsed_s"])),[]).append(float(row[key]))
            seconds=sorted(buckets)
            def quantile(numbers,f):
                numbers=sorted(numbers);i=(len(numbers)-1)*f;a=int(i);b=min(a+1,len(numbers)-1);return numbers[a]*(1-i+a)+numbers[b]*(i-a)
            median=[quantile(buckets[t],.5) for t in seconds];p95=[quantile(buckets[t],.95) for t in seconds]
            axis.plot(seconds,median,color=colour,linewidth=1.2,label="Electron" if name=="electron" else "Native")
            axis.fill_between(seconds,median,p95,color=colour,alpha=.15)
        else:
            axis.plot([float(r["elapsed_s"]) for r in values],[float(r[key]) for r in values],color=colour,linewidth=.7,alpha=.9,label="Electron" if name=="electron" else "Native")
for axis,title in zip(axes,("Callback intervals · per-second median / p95","Repaint-watchdog response")):
    style(axis);axis.set_title(title,loc="left",weight="bold",fontsize=11,color=text);axis.set_xlabel("Seconds");axis.set_ylabel("Milliseconds");axis.set_xlim(0,300);axis.set_ylim(bottom=0)
axes[0].legend(frameon=False,fontsize=9)
fig.text(.08,.14,"Native records egui update callbacks and worker-thread repaint acknowledgements.",fontsize=9,color="#62685e")
fig.text(.08,.10,"Electron records requestAnimationFrame and an IPC → next-rAF round trip. Both had no watchdog responses above 100 ms.",fontsize=9,color="#62685e")
fig.text(.08,.055,"No GPU-present, dropped-display-frame or input-to-photon measurement was made. The native app used a lower update cadence.",fontsize=9,color="#62685e")
save(fig,"2026-11-04-visual-timing")
