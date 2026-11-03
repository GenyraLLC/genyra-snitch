# Understanding resource usage

## The measured capture sample

A paired Linux x86-64 run observed the same active network interface with the original Python collector and the native implementation. After 15 seconds of startup settling, CPU time was sampled from `/proc/<pid>/stat` over **20 seconds**. RSS was sampled from `/proc/<pid>/statm`. Percentages use **one CPU core as 100%**, not the whole machine.

| Measurement | Python backend | Native backend |
| --- | ---: | ---: |
| CPU during the measured window | 15.3% | 2.4% |
| Process RSS at the end of the window | 144.93 MiB | 168.82 MiB |
| Native packets captured in the window | — | 16,057 |
| Native capture drops reported by libpcap | — | 0 |

This was measured on the validated native port before the Genyra branding pass; it is not a standardized benchmark of every release.

The native process used about **84% less CPU in this sample**, with **about 24 MiB more RSS**. It is incorrect to describe this as a memory reduction. The run measured the Linux capture backend, not a complete Electron application, and did not exercise active Frida inspection or local-model inference. It is one workload, not an average across machines or proof of maximum throughput. The original packet data and connection information are not distributed.

## What is bounded

- Live host graph: 4,096 nodes; name cache: 8,192 entries.
- Forensic packet ring: about 4 MiB of captured frame bytes, plus metadata.
- TLS certificate reassembly: 256 flows, up to 16 KiB per flow.
- Coalesced WebSocket updates: four times per second, with bounded event queues and subscriber limits.
- SQLite writes are batched; traffic/history retention is 24 hours. Stored alert history is preserved rather than silently discarded.
- Process attribution uses periodic socket-table scans. Native reverse-DNS lookup has bounded concurrency and retry handling.
- Integrity hashing uses a single worker and a bounded file cache. Expensive checks have time limits; incomplete module snapshots do not establish false Merkle baselines.
- NFQUEUE pending decisions and inspection outputs have explicit capacities and timeouts.

These bounds constrain collector buffers, not every allocation in a full system. SQLite files, alert history and downloaded databases occupy disk. Repeated exports and configured integrations also require work.

## RSS, file cache and service totals differ

RSS is memory currently resident in one process. Linux also caches files read by the application; those pages can be charged to a systemd cgroup. `MemoryCurrent` can therefore exceed the process RSS substantially. Reclaimable file cache is not equivalent to a Python heap leak. Inspect `/proc/<pid>/status`, the service's `memory.stat`, and disk usage separately before comparing numbers.

The desktop application adds Chromium/Electron renderer processes. Count the whole application tree when evaluating desktop memory; the table above is collector-only.

## Optional operations change the budget

Frida attaches to a selected process for a bounded interval. Integrity hashing can read many executable pages. eBPF/NFQUEUE have kernel-side buffers. Peer exchange, threat checks and exports consume additional CPU and I/O when enabled.

Native GGUF inference launches llama.cpp with two CPU threads and a bounded generation request. A 5 GiB model can still need several GiB of resident memory: removing Python does not make model weights small. External Ollama memory belongs to its own server process and is not included in the collector RSS. Keep model inference separate when benchmarking capture.

## Reproducing a useful comparison

Use an equivalent interface, traffic workload, GeoIP data and enabled settings. Allow startup to settle, record CPU time and RSS over a stated window, and record libpcap drops. Compare active capture with active capture. For the desktop, include all renderer processes. For models or inspection, report those jobs separately. Never substitute a synthetic demo's resource use for live-capture measurements.
