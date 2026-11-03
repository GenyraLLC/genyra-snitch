<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="ui/public/brand/genyra-light.png"><img src="ui/public/brand/genyra-dark.png" width="300" alt="Genyra LLC"></picture></p>
<h1 align="center">Genyra Snitch</h1>
<p align="center"><strong>Know what your apps connect to.</strong><br>Network visibility, application firewall controls and local investigation tools — by Genyra LLC.</p>
<p align="center"><a href="https://github.com/GenyraLLC/genyra-snitch/actions">Builds</a> · <a href="docs/FEATURES.md">Feature coverage</a> · <a href="docs/PERFORMANCE.md">Resource usage</a> · <a href="docs/BUILD.md">Build &amp; run</a></p>

Genyra Snitch is a native Rust fork of [Snitch by aiXis Studio](https://github.com/aixisstudio/Snitch). It preserves the familiar React interface, desktop shell, REST/WebSocket contracts and Linux security tools while replacing the Python backend with one native collector. There is no Python interpreter in the deployed application.

This is a **Linux x86-64 alpha**, not a claim of cross-platform parity. The 77 upstream API routes are implemented; Windows and macOS backends have not been ported. Native detection algorithms can produce different scores from Python. [Feature coverage and limits](docs/FEATURES.md) distinguish implementation from validation.

The **full native desktop and cross-platform rewrite is in progress**, on the
`native-desktop` branch. See [current work and outstanding gaps](docs/NATIVE-REWRITE.md).
The existing alpha does not establish full application or cross-platform parity.

### What you get

- A live connection graph and map, per-process attribution, LAN device discovery, offline GeoIP/ASN, traffic history and a bounded forensic packet buffer.
- IP/CIDR/domain/port/process firewall rules, throttling, sinkholes, lockdown and first-connection decisions through native NFQUEUE.
- Heuristic and statistical alerts, watchlists, suppressions, combined custom rules, Sigma import and YARA-L export.
- Native eBPF hooks, Frida inspection, integrity and memory checks, hardware counters, process controls and an isolated execution tool.
- Agent enrollment, remote sensor ingestion, peer IOC exchange, fleet views and JSON/CSV/STIX/ECS/PCAP investigation exports.
- Optional threat providers, webhooks/syslog, local Ollama explanations and user-supplied GGUF models through native llama.cpp.

Administrator-only tools still require administrator privileges. Missing permissions are reported; a configured rule is not described as enforced when the OS rejected it. The application starts on loopback and requires its local API token.

### Build and try

Install the dependencies listed in [the build guide](docs/BUILD.md), then:

```sh
npm --prefix ui ci
npm --prefix ui run build
cargo build --release --locked
./target/release/genyra-snitch --demo --port 8000
```

Open **http://127.0.0.1:8000**. The browser asks for the token saved in `$XDG_DATA_HOME/genyra-snitch/api_token.txt` (normally `~/.local/share/genyra-snitch/api_token.txt`). Demo mode generates synthetic connections and never captures or enforces host policy.

For live capture, run the binary with the required privileges; see [live capture and desktop usage](docs/BUILD.md). To migrate an existing installation, stop the old collector, back up its data and token, then point `SNITCH_DATA_DIR` at that directory. Never run two collectors against the same database.

### Resource usage, without the marketing shortcuts

In one **20-second Linux capture comparison**, the native collector used **2.4% of one CPU core**, compared with **15.3%** for the Python backend. Native RSS was **168.82 MiB**, compared with **144.93 MiB** for Python: **this sample demonstrated lower CPU use, not lower memory use**. Both collectors observed the same interface; the native collector captured 16,057 packets during the window and reported zero capture drops.

Those numbers are a sample, not a universal benchmark. Traffic, process count, GeoIP data, inspection jobs and optional models change the result. [The resource guide](docs/PERFORMANCE.md) explains what was measured, bounded buffers, RSS versus file cache, and the additional cost of local inference.

### Privacy and provenance

No connection captures, host databases, API keys, desktop integrations or workstation configuration are included in this repository. The test harness creates synthetic traffic in temporary directories. Vendor telemetry is absent. Reverse DNS may use the system resolver; downloads and external integrations require explicit configuration or consent. Recent packet bytes can be retained locally for protocol inspection and PCAP export — this is not a “payloads are never read” promise.

The software remains **AGPL-3.0**. Upstream authorship is preserved in [LICENSE](LICENSE), [NOTICE](NOTICE) and [UPSTREAM.json](UPSTREAM.json). Genyra Snitch is maintained independently by Genyra LLC; it is not an official upstream release.
