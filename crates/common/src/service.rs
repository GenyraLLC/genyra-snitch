//! Native OS startup registration. Installation is explicit; closing a window
//! alone never creates an autostart entry or enables a system service.
use std::{io, path::Path};
pub const NAME: &str = "GenyraSnitch";
pub const ACTIONS: &[&str] = &["config", "install", "start", "stop", "status", "uninstall"];

fn valid_path(path: &Path) -> io::Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::other("Service paths must be valid Unicode"))?;
    if !path.is_absolute() || text.chars().any(char::is_control) {
        return Err(io::Error::other(
            "Service paths must be absolute and contain no control characters",
        ));
    }
    Ok(text)
}
// ExecStart has systemd specifier and environment expansion even without a shell.
fn systemd_quote(path: &Path) -> io::Result<String> {
    Ok(format!(
        "\"{}\"",
        valid_path(path)?
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}
pub fn linux_unit(binary: &Path, data: &Path) -> io::Result<String> {
    Ok(format!("[Unit]\nDescription=Genyra Snitch background network monitor\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=simple\nExecStart={} --data-dir {} --bind 127.0.0.1 --port 0 --no-browser\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=20\nUMask=0077\nStandardOutput=null\nStandardError=journal\n\n[Install]\nWantedBy=default.target\n",systemd_quote(binary)?,systemd_quote(data)?))
}
fn xml(path: &Path) -> io::Result<String> {
    Ok(valid_path(path)?
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}
pub fn macos_plist(binary: &Path, data: &Path) -> io::Result<String> {
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.genyra.snitch</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--data-dir</string><string>{}</string><string>--bind</string><string>127.0.0.1</string><string>--port</string><string>0</string><string>--no-browser</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>5</integer>\n<key>ExitTimeOut</key><integer>20</integer>\n<key>ProcessType</key><string>Background</string>\n<key>Umask</key><integer>63</integer>\n</dict></plist>\n",xml(binary)?,xml(data)?))
}

#[cfg(unix)]
fn command(program: &str, args: &[&std::ffi::OsStr]) -> io::Result<String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    // Native service tools write to a bounded readback rather than an unbounded
    // in-memory pipe; no shell, Python, or persistent helper process is involved.
    let mut output = tempfile::tempfile()?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(25) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Service manager timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    use std::io::{Seek, SeekFrom};
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![];
    output.take(65536).read_to_end(&mut bytes)?;
    let message = String::from_utf8_lossy(&bytes).trim().to_string();
    if !status.success() {
        return Err(io::Error::other(format!("{program}: {message}")));
    }
    Ok(message)
}
#[cfg(unix)]
fn write_registration(path: &Path, contents: &str) -> io::Result<()> {
    // Refuse to silently replace another installation's service registration.
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing service directory"))?;
    std::fs::create_dir_all(parent)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}
pub fn manage(binary: &Path, data: &Path, action: &str) -> io::Result<String> {
    if !ACTIONS.contains(&action) {
        return Err(io::Error::other(
            "Use service install, start, stop, status or uninstall",
        ));
    }
    valid_path(binary)?;
    valid_path(data)?;
    if action == "config" {
        return if cfg!(target_os = "macos") {
            macos_plist(binary, data)
        } else if cfg!(windows) {
            Ok(format!("Windows SCM: {NAME}\nExecutable: {}\nData directory: {}\nAccount: LocalSystem\nStartup: Automatic\nNo API token is stored in the registration.\n",valid_path(binary)?,valid_path(data)?))
        } else {
            linux_unit(binary, data)
        };
    }
    if action == "install" {
        if !binary.is_file() {
            return Err(io::Error::other("Collector executable is missing"));
        }
        crate::ensure_data_dir(data)?;
        crate::token(data)?;
    }
    platform_manage(binary, data, action)
}
#[cfg(target_os = "linux")]
fn platform_manage(binary: &Path, data: &Path, action: &str) -> io::Result<String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config")))
        .ok_or_else(|| io::Error::other("No user configuration directory"))?;
    let path = base.join("systemd/user/genyra-snitch.service");
    let run = |args: &[&str]| {
        command(
            "systemctl",
            &args.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>(),
        )
    };
    match action {
        "install" => {
            write_registration(&path, &linux_unit(binary, data)?)?;
            if let Err(error) = run(&["--user", "daemon-reload"])
                .and_then(|_| run(&["--user", "enable", "genyra-snitch.service"]))
            {
                let _ = std::fs::remove_file(&path);
                let _ = run(&["--user", "daemon-reload"]);
                return Err(error);
            }
            Ok("Installed for this user's login. Start it after stopping the foreground collector. Packet capture requires capture permission; system firewall controls require additional OS privileges.".into())
        }
        "uninstall" => {
            run(&["--user", "disable", "--now", "genyra-snitch.service"])?;
            std::fs::remove_file(path)?;
            run(&["--user", "daemon-reload"])?;
            Ok("Startup service removed; monitoring history was retained".into())
        }
        "status" => run(&[
            "--user",
            "show",
            "genyra-snitch.service",
            "--property=LoadState,ActiveState,SubState,MainPID,UnitFileState",
        ]),
        "start" | "stop" => run(&["--user", action, "genyra-snitch.service"])
            .map(|_| format!("Service {action} requested")),
        _ => unreachable!(),
    }
}
#[cfg(target_os = "macos")]
fn platform_manage(binary: &Path, data: &Path, action: &str) -> io::Result<String> {
    let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("No home directory"))?;
    let path = std::path::PathBuf::from(home).join("Library/LaunchAgents/com.genyra.snitch.plist");
    let domain = format!("gui/{}", unsafe { libc::geteuid() });
    let target = format!("{domain}/com.genyra.snitch");
    match action {
        "install" => {
            write_registration(&path, &macos_plist(binary, data)?)?;
            Ok("Installed for this user's login. Choose Start to load it now. Capture requires access to /dev/bpf; firewall changes require additional privileges.".into())
        }
        "start" => command(
            "/bin/launchctl",
            &["bootstrap".as_ref(), domain.as_ref(), path.as_os_str()],
        ),
        "stop" => command("/bin/launchctl", &["bootout".as_ref(), target.as_ref()]),
        "status" => command("/bin/launchctl", &["print".as_ref(), target.as_ref()]),
        "uninstall" => {
            // A stopped LaunchAgent has no loaded job to boot out.
            if command("/bin/launchctl", &["print".as_ref(), target.as_ref()]).is_ok() {
                command("/bin/launchctl", &["bootout".as_ref(), target.as_ref()])?;
            }
            std::fs::remove_file(path)?;
            Ok("Startup service removed; monitoring history was retained".into())
        }
        _ => unreachable!(),
    }
}
#[cfg(windows)]
fn platform_manage(binary: &Path, data: &Path, action: &str) -> io::Result<String> {
    use windows_service::{
        service::*,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let convert = |e| {
        io::Error::other(format!("Windows service manager: {e}. Installation and control require Administrator privileges."))
    };
    let access = if action == "install" {
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE
    } else {
        ServiceManagerAccess::CONNECT
    };
    let manager = ServiceManager::local_computer(None::<&str>, access).map_err(convert)?;
    if action == "install" {
        manager
            .create_service(
                &ServiceInfo {
                    name: NAME.into(),
                    display_name: "Genyra Snitch".into(),
                    service_type: ServiceType::OWN_PROCESS,
                    start_type: ServiceStartType::AutoStart,
                    error_control: ServiceErrorControl::Normal,
                    executable_path: binary.into(),
                    launch_arguments: vec![
                        "--service-run".into(),
                        "--data-dir".into(),
                        data.into(),
                        "--bind".into(),
                        "127.0.0.1".into(),
                        "--port".into(),
                        "0".into(),
                        "--no-browser".into(),
                    ],
                    dependencies: vec![],
                    account_name: None,
                    account_password: None,
                },
                ServiceAccess::QUERY_STATUS,
            )
            .map_err(convert)?;
        return Ok("Installed Windows service (LocalSystem), automatic startup. Choose Start after stopping the foreground collector. Npcap must be installed.".into());
    }
    let access = match action {
        "start" => ServiceAccess::START,
        "stop" => ServiceAccess::STOP,
        "uninstall" => ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        _ => ServiceAccess::QUERY_STATUS,
    };
    let service = manager.open_service(NAME, access).map_err(convert)?;
    match action {
        "start" => {
            service.start::<&str>(&[]).map_err(convert)?;
        }
        "stop" => {
            service.stop().map_err(convert)?;
        }
        "status" => return Ok(format!("{:?}", service.query_status().map_err(convert)?)),
        "uninstall" => {
            if service.query_status().map_err(convert)?.current_state != ServiceState::Stopped {
                service.stop().map_err(convert)?;
            }
            service.delete().map_err(convert)?;
        }
        _ => unreachable!(),
    }
    Ok(format!("Service {action} requested"))
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_manage(_: &Path, _: &Path, _: &str) -> io::Result<String> {
    Err(io::Error::other(
        "No native service manager for this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn registrations_preserve_paths_without_shell_or_secret_expansion() {
        let unit = linux_unit(
            Path::new("/opt/Genyra % apps/$snitch"),
            Path::new("/home/test/A \"B\"\\C"),
        )
        .unwrap();
        assert!(unit.contains("/opt/Genyra %% apps/$$snitch"));
        assert!(unit.contains("A \\\"B\\\"\\\\C"));
        assert!(!unit.contains("TOKEN"));
        let plist = macos_plist(
            Path::new("/Applications/A&B<app>"),
            Path::new("/Users/test/data"),
        )
        .unwrap();
        assert!(plist.contains("A&amp;B&lt;app&gt;"));
        assert!(linux_unit(Path::new("/tmp/a\nExecStart=evil"), Path::new("/tmp/data")).is_err());
        assert!(linux_unit(Path::new("relative"), Path::new("/tmp/data")).is_err());
    }
}
