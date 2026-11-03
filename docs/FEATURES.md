# Upstream coverage and validation

Genyra Snitch preserves Snitch's application structure and **77-route API contract** while replacing the backend with Rust. The API reference is upstream 1.6.4 at `062f2a8c3ba95ac811988710579874100d667956`; the UI also includes upstream fixes through `9fb255745eaf3f587911c78b95111dad898df7df`. The machine-readable route list is [`compatibility.json`](../compatibility.json).

“One-for-one” describes the Linux feature and API coverage. It does not mean every internal algorithm is identical or every platform is supported. The statistical detector uses a native deterministic implementation; its scores can differ from Python. TLS 1.3 certificates are encrypted and cannot be inspected passively.

| Upstream area | Native implementation | Validation |
| --- | --- | --- |
| Capture, graph, process attribution, history and timeline | libpcap + bounded Rust parsers, `/proc` attribution and SQLite | Unit tests, generated PCAP replay, WebSocket/auth tests, live capture |
| DNS/SNI, passive TLS 1.2 leaf checks, GeoIP/ASN | Native parsing, bounded PTR queries, offline MMDB | Malformed input and reassembly tests; real database loading |
| LAN identity and media observation | ARP, DHCP, NetBIOS/mDNS, vendor data and Linux device handles | Parser fixtures; runtime observation is permissions-dependent |
| Heuristics, baselines, isolation forest | Native bounded detection | Beacon/DGA fixtures, warmup and learned-outlier tests |
| Custom/combined rules, Sigma and YARA-L | Native compiled rules and format conversion | Rule semantics and rejection tests; agent-event rule integration |
| Firewall, throttle, sinkhole and lockdown | nftables transactions + scoped process cgroups | Actual IPv4/IPv6 drops, throttle counters, sinkhole replies and restoration in disposable namespaces |
| Ask mode | Native libnetfilter_queue | Real allow/deny decisions and timeout action tests |
| eBPF connect and egress controls | libbpf hooks and bounded maps | Real connect events and cgroup-scoped egress drops |
| Frida, perf, memory/integrity and process controls | Native Frida core, Linux syscalls and streamed hashes | Real attach/event/detach and memory checks on an owned fixture; perf API and hash tests |
| Isolated execution | Bounded network/user namespace subprocess | Disposable execution and cleanup checks |
| Exports and IOC exchange | JSON/CSV/STIX/ECS/PCAP, Bloom/noise and salted proofs | Export checks, tamper rejection and local peer fixtures |
| Agent enrollment, ingestion and fleet | Retained Rust agent + native collector endpoints | Agent unit tests, token revoke/auth and local fleet fixtures |
| Notifications and local models | Configured webhooks/syslog, loopback Ollama and native llama.cpp | Local webhook/syslog/model-cache fixtures; real GGUF inference exercised separately |
| React/Electron interface | Preserved feature panels with Genyra branding | Frontend tests/build and desktop packaging; GUI visual review is tracked separately |

The validation baseline includes 39 collector unit tests, 6 agent unit tests, 13 frontend tests, all 77 route requests and separate integration fixtures. A route that rejects an invalid request is evidence of request validation, not proof that its privileged operation ran; the kernel fixtures provide that evidence for the controls above.

Linux x86-64 is tested. Windows and macOS backends are not ported. Camera/audio and process-memory visibility depend on Linux services and permissions. External provider accounts, every hardware configuration and every application payload are not validated by local fixtures. Privilege failures are returned explicitly.

No production database, packet recording, workstation service file, personal desktop integration or authentication material is part of this fork.
