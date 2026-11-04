# Build and run Genyra Snitch

## Native Linux build

Linux x86-64 is the live-capture-tested alpha target. Use Rust stable, a C compiler, pkg-config, clang/libclang, libpcap, SQLite, libbpf and libnetfilter_queue development headers. The native desktop also needs a graphical session and an OpenGL-capable driver, with Wayland or X11 on Linux. The first Cargo build downloads the pinned Frida devkit from the official Frida release repository. Node.js is needed only for the optional earlier React/Electron frontend; Python 3 is used only by development checks. Neither is needed to run the native application.

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
cargo build --release --locked
cargo build --release --locked --manifest-path desktop/Cargo.toml
cp target/release/genyra-snitch desktop/target/release/
```

## Synthetic preview

```sh
./desktop/target/release/genyra-snitch-desktop --demo
```

The native desktop starts a synthetic collector, reads its local identity and opens a native window. The default Linux data directory is `~/.local/share/genyra-snitch`. If `XDG_DATA_HOME` is set, it is `$XDG_DATA_HOME/genyra-snitch` instead. A custom `SNITCH_DATA_DIR` takes precedence, and explicit `--data-dir` takes precedence over that. The token file is created with mode 0600 on Unix; do not post it in an issue or commit it.

Demo mode uses synthetic traffic. Process mutation and kernel enforcement are disabled there. With background monitoring off, closing a desktop-owned session stops its collector and flushes the database. An independently running collector is left running when an attached desktop closes.

## Live capture

Capture requires `CAP_NET_RAW` or administrator privileges. For an isolated data directory and an explicit interface:

```sh
sudo env SNITCH_DATA_DIR="$PWD/data" SNITCH_BIND=127.0.0.1 \
  ./target/release/genyra-snitch --interface eth0 --port 8000
```

Replace `eth0` with your interface name. Running elevated can create root-owned data; use a dedicated directory. For a persistent unprivileged service with capture only, adapt the example below and grant only CAP_NET_RAW. Firewall/NFQUEUE require CAP_NET_ADMIN; eBPF, process memory access and cgroup controls may require root or additional kernel capabilities. These are separate privileges, not an automatic consequence of capture access.

[`packaging/genyra-snitch@.service`](../packaging/genyra-snitch@.service) is a capture-only service template for an existing Linux user. Install the binary as `/usr/local/bin/genyra-snitch`, then install and adapt the template. If using the optional web frontend, also install its built files as `/usr/local/share/genyra-snitch/ui`. The service stores data in `/var/lib/genyra-snitch-USERNAME` and does not grant firewall, BPF or debugging privileges.

To attach the native desktop to that collector, run as your desktop user:

```sh
./desktop/target/release/genyra-snitch-desktop \
  --connect http://127.0.0.1:8000 --token-file /absolute/path/to/data/api_token.txt
```

The desktop user must be able to read the token. Do not launch the graphical desktop as root. For a native Linux app-menu entry, place the collector beside the desktop and run `genyra-snitch-desktop --install`. See [desktop installation](NATIVE-REWRITE.md#linux-app-menu-installation) and [optional background/startup services](BACKGROUND-SERVICE.md).

## Experimental Windows and macOS builds

CI builds the collector and native desktop on Windows Server 2022 x86-64 and macOS 14 ARM64. These are validation environments, not minimum OS versions. Native runtime and privileged-feature parity are incomplete; see [platform limitations](NATIVE-REWRITE.md#experimental-platform-adapters).

On macOS, install Xcode command-line tools, Rust stable and libpcap (`brew install libpcap`), then build both Cargo manifests as above. Put the collector beside the desktop. Live capture needs access to `/dev/bpf`; a user LaunchAgent does not grant that permission.

On Windows, use Rust stable with the MSVC toolchain, Visual Studio C++ build tools, LLVM/libclang, the Npcap development SDK and shared SQLite development libraries. CI records the exact library setup in [the platform workflow](../.github/workflows/platforms.yml). Build the root and desktop manifests, then put `genyra-snitch.exe` and `sqlite3.dll` beside `genyra-snitch-desktop.exe`. Install Npcap separately for live capture; the driver is not redistributed. Demo mode and synthetic service tests do not establish live capture support.

## Optional compatibility frontend

The earlier React web UI and Electron shell are retained for compatibility and reference. These commands are separate from the native desktop build and require Node.js 24+:

```sh
npm --prefix ui ci
npm --prefix ui run build
# Web UI: start the collector, open its loopback URL and supply its local token.
npm --prefix electron ci
npm --prefix electron start
```

The development shell runs the backend without elevation. To package this compatibility Electron frontend on Linux:

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
# Full checks also cover the optional React/Electron frontend and use Node/Python:
./scripts/check.sh
# Kernel integration tests: disposable namespaces only, with administrator approval
sudo ./scripts/privileged-check.sh
# Optional legacy web-UI/agent bundle (requires ui/dist from the frontend build):
cargo build --release --locked --manifest-path agent/Cargo.toml
./scripts/bundle.sh
```

The privileged harness refuses the host network namespace. It tests real drops, verdicts and cgroup restoration using disposable fixtures. `dist/` contains local builds and is ignored by Git. Binary names record their build architecture and glibc version; build from source for a different ABI.
