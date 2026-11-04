# Native Rust rewrite — work in progress

The target is a Rust desktop and collector for Linux, Windows and macOS, with
the original feature set and sustained resource measurements. The existing
Linux alpha and React/Electron UI remain while the replacement is verified.

The experimental `desktop` crate uses egui/eframe. No Electron, Chromium, Node
or Python runtime is required. One bounded I/O worker handles actions and
active-view reads; a bounded WebSocket receiver handles live traffic and alerts.
Minimized windows suspend their polling and stream. Traffic pulses are driven by
measured byte increases; the renderer sleeps when the scene settles. Desktop
feature parity is not yet complete.

On Wayland, frame presentation does not wait for vblank. This prevents a
reproduced NVIDIA EGL stall when the window moves to an inactive workspace,
which previously blocked the UI thread and compositor ping replies. Traffic
animations remain paced by the application's repaint requests.

The opt-in `wayland_occlusion` test requires an active Lua Hyprland session.
It moves only its own synthetic test window off-screen for eight seconds,
then verifies a normal Wayland close request still works and its owned
collector flushes and stops:

```sh
cargo test --manifest-path desktop/Cargo.toml --test wayland_occlusion -- --ignored
```

```sh
cargo build --release --locked --manifest-path desktop/Cargo.toml
```

Place the collector beside the desktop and run `genyra-snitch-desktop --demo`
for synthetic data. Live capture requires OS capture permissions. To attach
to a local collector use `--connect http://127.0.0.1:PORT --token-file PATH`.
Credentials are read locally and never placed in URLs. Personal connections
and data are not included in the repository.

### Linux app-menu installation

With the collector binary beside the native desktop binary, run:

```sh
./genyra-snitch-desktop --install
```

This installs the native binaries for your user, the official Genyra icon and
the **Genyra Snitch** desktop entry. It appears in desktop application menus,
including Omarchy's Apps list. No browser or Python launcher is involved.
For an existing local collector, supply `--connect`, `--token-file` and
`--data-dir` with the installation command; those arguments are retained only
in your local desktop entry. Capture permissions still apply to a newly
started collector. Startup connection failures display an error window and
save the last error privately in the chosen data directory.

Settings now includes [optional background monitoring and startup services](BACKGROUND-SERVICE.md).
The desktop reconnects to a shared collector using persistent local identity;
an exclusive data-directory lock prevents duplicate collectors. Linux systemd
user units, macOS LaunchAgents and Windows SCM registration are implemented.

## Experimental platform adapters

- Windows: Npcap capture, native socket ownership through netstat2, sysinfo
  process metadata, process control and Windows Firewall block rules.
- macOS: libpcap capture, native socket ownership through netstat2, sysinfo
  metadata, POSIX process control and a scoped PF block-rule anchor. PF must
  already be enabled with a `com.apple/*` root anchor; host policy is not replaced.
- Linux: existing capture, attribution, nftables, NFQUEUE and eBPF providers.

Native CI checks builds on Windows and macOS. Compilation does not establish
runtime support. Windows collector tests need Npcap runtime DLLs and driver;
CI only links them against the development SDK. Users install Npcap separately
from https://npcap.com/. No Npcap driver is redistributed.

Outstanding Windows/macOS gaps: first-flow decisions, sinkhole/throttle,
executable memory comparison, hardware counters, media observation, isolated
execution and macOS process firewall enforcement. Unimplemented providers
report their actual limitations. Linux eBPF/cgroups retain Linux-only status.

Outstanding desktop work: full action workflows, editable array settings,
exports, enrollment, peer exchange, accessibility/localization and visual/runtime
review. These gaps prevent any claim of one-for-one cross-platform parity.

## Resource verification

The collector now discards transient delivery queues without serializing UI
events when no WebSocket clients are attached. History, alerts and the graph
remain intact; reconnect gets a full snapshot. A regression test checks this.
It is an optimization, not a measured performance claim.

Measure collector and desktop separately over sustained real traffic, including
visible, minimized and closed UI phases. Record hardware, duration, traffic,
capture loss and optional jobs. Short idle samples do not establish stability.
