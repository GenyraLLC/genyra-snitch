# Optional background monitoring

In the native desktop, open **Settings → Background monitoring** and enable
**Keep monitoring when I close this window**. Closing the window then releases
the renderer and leaves only the Rust collector running. Reopening the desktop
with the same data directory reconnects to it. This preference is off initially.
An attached desktop always leaves an independent collector running when closed.

Capture, configured rule evaluation, alert generation and history continue in
the collector. Notifications drawn by the desktop require an open desktop.
Local inference, GeoIP, inspection and enabled integrations still have resource
costs; background mode does not make those features free. No Electron, browser,
Python interpreter, hidden renderer, or persistent service-control helper is
started by this option.

The collector locks its data directory to prevent duplicate processes. Its
private `collector.json` records the current loopback endpoint and PID. The API
token remains in `api_token.txt`, is reused on restart and is never put in an OS
service registration. Local identity files use mode 0600 on Unix. Use a private
directory protected by your account's ACL on Windows. Do not share a data
directory between users or start a service against a running foreground copy.

## Startup service

Put both native binaries in a permanent application directory first. Startup
registration stores the absolute collector executable and data directory; moving
them requires removing and reinstalling the registration. Use the same absolute
data directory for the collector, desktop and service commands.

```sh
genyra-snitch service config --data-dir /absolute/private/data
genyra-snitch service install --data-dir /absolute/private/data
genyra-snitch service start --data-dir /absolute/private/data
genyra-snitch service status --data-dir /absolute/private/data
genyra-snitch service stop --data-dir /absolute/private/data
genyra-snitch service uninstall --data-dir /absolute/private/data
```

`config` shows the proposed registration without changing the system. Installation
registers startup; `start` loads it now. In Settings, install first, then choose
**Switch to installed service**: the foreground collector flushes and stops,
then the service starts and the window reconnects automatically. A failed service
start is reported and does not leave a duplicate foreground collector running.
For a command-line handoff, close the foreground collector before `service start`.
Open the desktop with `--data-dir` pointing at the same directory. The Settings
page exposes installation, start, stop, status and removal.
Removal preserves history and the token. Stop and removal controls affect the
registered service, not unrelated collector instances.

### Linux

Uses `systemd --user` and installs
`$XDG_CONFIG_HOME/systemd/user/genyra-snitch.service` (normally
`~/.config/systemd/user/`). It starts at login. It does not enable lingering or
claim to run before login. Journald receives errors; restart failures are rate
limited. Shutdown allows the collector to flush SQLite before systemd's timeout.

The user service needs permission to capture. A trusted, permanently installed
binary may be granted `CAP_NET_RAW` by the administrator, or an administrator
can provide a system unit under the organization's policy. Changing that binary
normally removes file capabilities, so upgrades must restore them. Firewall,
eBPF and other privileged tools need their additional permissions; this user
service does not silently grant them. Service controls report native manager
errors when a user systemd session is unavailable.

### macOS

Uses a launchd LaunchAgent at
`~/Library/LaunchAgents/com.genyra.snitch.plist`, running as the signed-in user.
Capture requires the user's access to `/dev/bpf` (for example, an installed BPF
permission helper). This is a login service, not a root LaunchDaemon. Privileged
firewall operations retain their normal OS permission requirements.

### Windows

Registers **GenyraSnitch** with the native Service Control Manager and automatic
startup. The collector implements SCM start, stop and shutdown callbacks itself;
there is no wrapper process. Install and control it from an Administrator session.
Use an administrator-protected install location such as Program Files: the
service runs as **LocalSystem**, so its executable and libraries must not be
writable by untrusted users. Npcap must be installed separately for live capture.
Keep `sqlite3.dll` with the collector in the installed distribution.

Pass the intended desktop user's absolute data directory when installing from an
elevated session. Reopen the desktop with that same directory; the administrator
profile's default directory is often different. The API remains authenticated and
bound to loopback. The default service is not a promise of per-user privilege
isolation; use it only where LocalSystem operation is appropriate.

## Validation scope

The Rust integration test exercises the actual collector's discovery, token
reuse, duplicate rejection, graceful shutdown and persisted settings on restart.
Registration tests check native service path escaping and reject control-character
injection. Platform builds and tests are separate from installing a privileged
service and validating live capture on each operating system. Do not interpret a
successful cross-platform build as proof of those runtime checks.
