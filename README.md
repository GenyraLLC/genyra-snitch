<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="ui/public/brand/genyra-light.png"><img src="ui/public/brand/genyra-dark.png" width="300" alt="Genyra LLC"></picture></p>
<h1 align="center">Genyra Snitch</h1>
<p align="center"><strong>Know what your apps connect to.</strong><br>Network visibility, application firewall controls and local investigation tools — by Genyra LLC.</p>
<p align="center"><a href="https://github.com/GenyraLLC/genyra-snitch/actions">Builds</a> · <a href="docs/FEATURES.md">Feature coverage</a> · <a href="docs/PERFORMANCE.md">Resource usage</a> · <a href="docs/BUILD.md">Build &amp; run</a></p>

Genyra Snitch is a Rust fork of [Snitch by aiXis Studio](https://github.com/aixisstudio/Snitch), with a native desktop and collector for network visibility, application controls and local investigation. The native application requires no Python, Node or browser runtime.

This is a **Linux x86-64 alpha**. Windows and macOS adapters, native builds and synthetic service-lifecycle tests are available, while live capture and privileged feature parity on those platforms remain under validation. Native detection algorithms can produce different scores from Python. [Feature coverage and limits](docs/FEATURES.md) distinguish implementation from validation.

All current development is on **`main`**, including the native desktop. Full application and cross-platform parity remain in progress; see [current work and outstanding gaps](docs/NATIVE-REWRITE.md). The earlier React interface is retained for compatibility checks and reference.

The native desktop also has an optional **background monitoring** mode and native
startup-service controls. See [setup, privileges and lifecycle](docs/BACKGROUND-SERVICE.md).

### What you get

- A live connection graph and map, per-process attribution, LAN device discovery, offline GeoIP/ASN, traffic history and a bounded forensic packet buffer.
- IP/CIDR/domain/port/process firewall rules, throttling, sinkholes, lockdown and first-connection decisions through native NFQUEUE.
- Heuristic and statistical alerts, watchlists, suppressions, combined custom rules, Sigma import and YARA-L export.
- Native eBPF hooks, Frida inspection, integrity and memory checks, hardware counters, process controls and an isolated execution tool.
- Agent enrollment, remote sensor ingestion, peer IOC exchange, fleet views and JSON/CSV/STIX/ECS/PCAP investigation exports.
- Optional threat providers, webhooks/syslog, local Ollama explanations and user-supplied GGUF models through native llama.cpp.

Administrator-only tools still require administrator privileges. Missing permissions are reported; a configured rule is not described as enforced when the OS rejected it. The application starts on loopback and requires its local API token.

### Build and try

On Linux, install the native dependencies listed in [the build guide](docs/BUILD.md), then:

```sh
cargo build --release --locked
cargo build --release --locked --manifest-path desktop/Cargo.toml
cp target/release/genyra-snitch desktop/target/release/
./desktop/target/release/genyra-snitch-desktop --demo
```

This opens the native desktop with synthetic connections. Demo mode never captures or enforces host policy. For a Linux app-menu entry, run the desktop binary with `--install`; see [native desktop setup](docs/NATIVE-REWRITE.md#linux-app-menu-installation).

For live capture, run the binary with the required privileges; see [live capture and desktop usage](docs/BUILD.md). To migrate an existing installation, stop the old collector, back up its data and token, then point `SNITCH_DATA_DIR` at that directory. Never run two collectors against the same database.

### Resource usage, without the marketing shortcuts

In one **20-second Linux capture comparison**, the native collector used **2.4% of one CPU core**, compared with **15.3%** for the Python backend. Native RSS was **168.82 MiB**, compared with **144.93 MiB** for Python: **this sample demonstrated lower CPU use, not lower memory use**. Both collectors observed the same interface; the native collector captured 16,057 packets during the window and reported zero capture drops.

Those numbers are a sample, not a universal benchmark. Traffic, process count, GeoIP data, inspection jobs and optional models change the result. [The resource guide](docs/PERFORMANCE.md) explains what was measured, bounded buffers, RSS versus file cache, and the additional cost of local inference.

### Privacy and provenance

No connection captures, host databases, API keys, desktop integrations or workstation configuration are included in this repository. The test harness creates synthetic traffic in temporary directories. Vendor telemetry is absent. Reverse DNS may use the system resolver; downloads and external integrations require explicit configuration or consent. Recent packet bytes can be retained locally for protocol inspection and PCAP export — this is not a “payloads are never read” promise.

The software remains **AGPL-3.0**. Upstream authorship is preserved in [LICENSE](LICENSE), [NOTICE](NOTICE) and [UPSTREAM.json](UPSTREAM.json). Genyra Snitch is maintained independently by Genyra LLC; it is not an official upstream release.
