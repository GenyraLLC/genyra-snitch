pub use genyra_common::{data_dir, token};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
};
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
        "collector.lock",
        "collector.json",
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
