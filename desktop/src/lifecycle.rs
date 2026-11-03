use super::*;
use std::{
    path::Path,
    process::{Command, Stdio},
};

pub(super) fn backend() -> Result<PathBuf, String> {
    let name = if cfg!(windows) {
        "genyra-snitch.exe"
    } else {
        "genyra-snitch"
    };
    let path = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("Executable directory missing")?
        .join(name);
    if !path.is_file() {
        return Err("Place the collector binary beside the native desktop, or use --connect and --token-file".into());
    }
    Ok(path)
}
pub(super) fn discover(data: &Path, token: &str) -> Result<(Connection, u32), String> {
    let endpoint = genyra_common::endpoint(data).map_err(|e| e.to_string())?;
    let connection = Connection::new(endpoint.url, token.into())?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(750))
        .connect_timeout(Duration::from_millis(300))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(format!("{}/diagnostics", connection.base))
        .header("X-Snitch-Token", token)
        .send()
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err("Collector authentication failed".into());
    }
    let mut bytes = vec![];
    response
        .take(MAX_REPLY + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_REPLY {
        return Err("Collector discovery response is too large".into());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value["product"] != "Genyra Snitch" || value["native_backend"] != true {
        return Err("The local endpoint is not a native Genyra Snitch collector".into());
    }
    Ok((connection, endpoint.pid))
}
pub(super) fn connect_or_start(demo: bool) -> Result<(Connection, Option<OwnedCollector>), String> {
    let data = data_dir();
    let token = genyra_common::token(&data).map_err(|e| e.to_string())?;
    if let Ok((connection, _)) = discover(&data, &token) {
        return Ok((connection, None));
    }
    // Distinguish a stale discovery file from a running collector which is
    // temporarily starting, busy, or configured for a different transport.
    match genyra_common::Instance::acquire(&data) {
        Ok(lock) => drop(lock),
        Err(error) => {
            let deadline = Instant::now() + Duration::from_secs(8);
            while Instant::now() < deadline {
                if let Ok((connection, _)) = discover(&data, &token) {
                    return Ok((connection, None));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            return Err(format!("A collector owns this data directory but could not be reached. Check its service status and TLS configuration. {error}"));
        }
    }
    let mut command = Command::new(backend()?);
    command
        .args([
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--no-browser",
            "--data-dir",
        ])
        .arg(&data)
        .env_remove("SNITCH_PORT")
        .env_remove("SNITCH_BIND")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000 | 0x00000200);
    }
    if demo {
        command.arg("--demo");
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok((connection, pid)) = discover(&data, &token) {
            if pid == child.id() {
                return Ok((
                    connection.clone(),
                    Some(OwnedCollector {
                        child,
                        connection,
                        keep_running: false,
                    }),
                ));
            }
            // Another window won the startup race. Only stop our losing child.
            let _ = child.kill();
            let _ = child.wait();
            return Ok((connection, None));
        }
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            // A competing desktop may have acquired the lock first.
            if let Ok((connection, _)) = discover(&data, &token) {
                return Ok((connection, None));
            }
            return Err("Collector exited during startup. Check capture permissions and install the platform's capture library (Npcap on Windows). Use the collector command directly for diagnostics.".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("Collector startup timed out; no duplicate collector was left running".into())
}
pub(super) fn service_action(action: &str) -> Result<String, String> {
    genyra_common::service::manage(&backend()?, &data_dir(), action).map_err(|e| e.to_string())
}
impl Desktop {
    pub(super) fn background_service(&mut self, ui: &mut egui::Ui) {
        ui.heading("Background monitoring");
        ui.label("Keep capture, configured rules and alerts running while the desktop is closed. The next window reconnects to the same collector.");
        ui.add_enabled_ui(!self.read_only && self.local_service_controls, |ui| {
            if ui
                .checkbox(
                    &mut self.keep_monitoring,
                    "Keep monitoring when I close this window",
                )
                .changed()
            {
                let preferences = genyra_common::DesktopPreferences {
                    keep_monitoring: self.keep_monitoring,
                };
                if let Err(error) = preferences.save(&data_dir()) {
                    self.keep_monitoring = !self.keep_monitoring;
                    self.failure = true;
                    self.message = format!("Could not save background preference: {error}");
                }
            }
        });
        if self.child.is_none() {
            ui.label(
                RichText::new(
                    "Attached to an independent collector. Closing this window leaves it running.",
                )
                .color(GOLD),
            );
        } else {
            ui.label(if self.keep_monitoring {
                "This collector will continue after the window closes."
            } else {
                "This window's collector will stop and flush its history when the window closes."
            });
        }
        ui.add_space(10.);
        if !self.local_service_controls {
            ui.label("This window uses an explicitly supplied connection. Open the desktop with the collector's --data-dir to manage its local startup service.");
        }
        ui.strong(if cfg!(windows) {
            "Windows service — automatic startup"
        } else {
            "Start monitoring at login"
        });
        ui.label(if cfg!(windows){"Windows Services controls require Administrator privileges. Install from a permanent, protected application directory; Npcap is required for live capture."}else if cfg!(target_os="macos"){"Uses a native launchd LaunchAgent for your account. Packet capture requires access to /dev/bpf. It runs during your login session."}else{"Uses your systemd user service. Packet capture requires capture permission. It starts at login; enabling user lingering is a separate administrator choice."});
        ui.add_enabled_ui(
            !self.worker.busy && !self.read_only && self.local_service_controls,
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (label, action) in [
                        ("Install startup service", "install"),
                        ("Service status", "status"),
                        ("Start service", "start"),
                        ("Stop service", "stop"),
                        ("Remove startup service", "uninstall"),
                    ] {
                        if ui
                            .add_enabled(
                                action != "start"
                                    || self.child.is_none()
                                    || self.service_registration_present,
                                egui::Button::new(if action == "start" && self.child.is_some() {
                                    "Switch to installed service"
                                } else {
                                    label
                                }),
                            )
                            .clicked()
                        {
                            let foreground = if action == "start" {
                                self.child.take()
                            } else {
                                None
                            };
                            self.worker.send(Job::Service(action.into(), foreground));
                        }
                    }
                });
            },
        );
        if self.child.is_some() {
            ui.small("Install first, then choose Switch to installed service. Your foreground collector flushes and stops before the service starts; the desktop reconnects automatically.");
        }
        if self.last_action_path == "service" {
            if let Some(message) = self
                .values
                .get("last_action")
                .and_then(|v| v["message"].as_str())
            {
                ui.label(message);
            }
        }
        ui.small("The service runs only the Rust collector. No desktop renderer stays running. Optional model inference and enabled security features have their own resource costs.");
    }
}
