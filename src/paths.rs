#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
pub fn data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("SNITCH_DATA_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "windows")]
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());
    #[cfg(target_os = "macos")]
    let base = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        });
    base.join("genyra-snitch")
}
pub fn token(data: &Path) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(token) = std::env::var("SNITCH_TOKEN") {
        if token.trim().len() < 16 {
            return Err("SNITCH_TOKEN must contain at least 16 characters".into());
        }
        return Ok(token.trim().to_string());
    }
    let path = data.join("api_token.txt");
    if !path.exists() {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| format!("OS random generator: {e}"))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(token.as_bytes())?;
                file.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let value = fs::read_to_string(path)?.trim().to_string();
    if value.len() < 16 {
        return Err("Stored API token is missing or too short".into());
    }
    Ok(value)
}
pub fn frontend() -> PathBuf {
    if let Some(path) = std::env::var_os("SNITCH_FRONTEND_DIR") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().unwrap_or_default();
    let bundled = exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("../share/genyra-snitch/ui");
    if bundled.is_dir() {
        return bundled;
    }
    // Cargo's target/{debug,release} layout, without a build-machine path.
    exe.ancestors()
        .nth(3)
        .unwrap_or_else(|| Path::new("."))
        .join("ui/dist")
}
/// Return newly created root-owned data files to the explicit desktop owner.
/// No symlinks are followed, and the data directory must already belong to uid.
#[cfg(unix)]
pub fn restore_owner(data: &Path) {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some((uid, gid)) = std::env::var("SNITCH_OWNER_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .zip(
            std::env::var("SNITCH_OWNER_GID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok()),
        )
    else {
        return;
    };
    if uid == 0 || !fs::symlink_metadata(data).is_ok_and(|m| m.is_dir() && m.uid() == uid) {
        return;
    }
    for name in [
        "snitch.db",
        "snitch.db-wal",
        "snitch.db-shm",
        "api_token.txt",
        "geo",
        "geo/dbip-city-lite.mmdb",
        "geo/dbip-asn-lite.mmdb",
    ] {
        if let Ok(file) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(data.join(name))
        {
            if file
                .metadata()
                .is_ok_and(|m| m.uid() == 0 && (m.is_file() || m.is_dir()))
            {
                unsafe {
                    libc::fchown(file.as_raw_fd(), uid, gid);
                }
            }
        }
    }
}
#[cfg(not(unix))]
pub fn restore_owner(_data: &Path) {}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_token_is_generated_once() {
        let dir =
            std::env::temp_dir().join(format!("genyra-snitch-token-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let a = token(&dir).unwrap();
        let b = token(&dir).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join("api_token.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
