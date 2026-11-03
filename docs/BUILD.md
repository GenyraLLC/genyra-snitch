# Build and run Genyra Snitch

## Supported build

Linux x86-64 is the tested native target. Use Rust stable, Node.js 24+, a C compiler, pkg-config, clang/libclang, libpcap, SQLite, libbpf and libnetfilter_queue development headers. The first Cargo build downloads the pinned Frida devkit from the official Frida release repository. Python 3 is required only for development integration checks.

Debian/Ubuntu prerequisites:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config clang libclang-dev \
  libpcap-dev libsqlite3-dev libbpf-dev libnetfilter-queue-dev libelf-dev zlib1g-dev
```

On Arch Linux, install the corresponding `base-devel`, `clang`, `libpcap`, `sqlite`, `libbpf` and `libnetfilter_queue` packages.

```sh
git clone https://github.com/GenyraLLC/genyra-snitch.git
cd genyra-snitch
npm --prefix ui ci
npm --prefix ui run build
cargo build --release --locked
```

## Synthetic preview

```sh
./target/release/genyra-snitch --demo --port 8000
```

Visit `http://127.0.0.1:8000` and paste the token from `~/.local/share/genyra-snitch/api_token.txt`. If `XDG_DATA_HOME` is set, the directory is `$XDG_DATA_HOME/genyra-snitch` instead. A custom `SNITCH_DATA_DIR` takes precedence. The token file is created with mode 0600; do not post it in an issue or commit it.

Demo mode uses synthetic traffic. Process mutation and kernel enforcement are disabled there. Ctrl+C shuts down the collector and flushes its database.

## Live capture

Capture requires `CAP_NET_RAW` or administrator privileges. For an isolated data directory and an explicit interface:

```sh
sudo env SNITCH_DATA_DIR="$PWD/data" SNITCH_BIND=127.0.0.1 \
  ./target/release/genyra-snitch --interface eth0 --port 8000
```

Replace `eth0` with your interface name. Running elevated can create root-owned data; use a dedicated directory. For a persistent unprivileged service with capture only, adapt the example below and grant only CAP_NET_RAW. Firewall/NFQUEUE require CAP_NET_ADMIN; eBPF, process memory access and cgroup controls may require root or additional kernel capabilities. These are separate privileges, not an automatic consequence of capture access.

[`packaging/genyra-snitch@.service`](../packaging/genyra-snitch@.service) is a capture-only service template for an existing Linux user. Install the binary as `/usr/local/bin/genyra-snitch`, the built UI as `/usr/local/share/genyra-snitch/ui`, then install and adapt the template. It stores service data in `/var/lib/genyra-snitch-USERNAME` and does not grant firewall, BPF or debugging privileges.

## Desktop application

```sh
npm --prefix electron ci
npm --prefix electron start
```

The development shell runs the backend without elevation. To package the full Linux desktop application:

```sh
npm --prefix electron run build:dir
# or build Linux distribution packages:
npm --prefix electron run build:linux
```

Packaged mode requests elevation for its own native backend. The renderer stays unprivileged. The shell chooses a free loopback port and passes the token through its preload bridge. It stops only the backend it launched. Automatic upstream update installation is disabled; use this fork's releases or rebuild from source.

## Compatibility and configuration

Existing `SNITCH_*` environment names, API paths and `X-Snitch-Token` / `X-Snitch-Agent` headers are retained for compatibility. Common settings:

| Setting | Purpose |
| --- | --- |
| `SNITCH_DATA_DIR` | Database, token and downloaded GeoIP directory |
| `SNITCH_IFACE` / `--interface` | Capture interface |
| `SNITCH_PORT` / `--port` | HTTP port; 0 requests a free port |
| `SNITCH_BIND` / `--bind` | Bind address; loopback by default |
| `SNITCH_FRONTEND_DIR` | Built UI directory override |
| `SNITCH_TLS_CERT` + `SNITCH_TLS_KEY` | Optional PEM certificate and key for HTTPS |
| `SNITCH_DEMO=1` / `--demo` | Synthetic preview without capture/enforcement |
| `SNITCH_LLAMA_CLI` | Path to native `llama-completion` or `llama-cli` |

`--help`, `--version`, `--check` and `--no-browser` are also accepted. LAN pairing is opt-in and takes effect after restart. Authentication remains required. TLS certificates and keys must be configured together.

## Local models

Ollama-compatible endpoints are limited to loopback. Embedded mode requires a native llama.cpp completion executable and a user-provided GGUF file; no Python model runtime is used. Models can require several gigabytes of RAM and substantial CPU. They are optional and are not part of the collector benchmark.

## Test and package

```sh
./scripts/check.sh
# Kernel integration tests: disposable namespaces only, with administrator approval
sudo ./scripts/privileged-check.sh
# After building the native agent as well:
cargo build --release --locked --manifest-path agent/Cargo.toml
./scripts/bundle.sh
```

The privileged harness refuses the host network namespace. It tests real drops, verdicts and cgroup restoration using disposable fixtures. `dist/` contains local builds and is ignored by Git. Binary names record their build architecture and glibc version; build from source for a different ABI.
