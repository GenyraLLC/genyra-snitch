//! Shared local identity and single-collector ownership. The desktop and OS
//! service use the same secret and endpoint; opening a window never needs a
//! second collector. No connection or credential is compiled into the product.
pub mod service;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
pub fn data_dir() -> PathBuf {
    let args: Vec<_> = std::env::args_os().collect();
    if let Some(pair) = args.windows(2).find(|pair| pair[0] == "--data-dir") {
        return PathBuf::from(&pair[1]);
    }
    if let Some(path) = std::env::var_os("SNITCH_DATA_DIR") {
        return path.into();
    }
    #[cfg(windows)]
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());
    #[cfg(target_os = "macos")]
    let base = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support");
    #[cfg(not(any(windows, target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        });
    base.join("genyra-snitch")
}
pub fn ensure_data_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}
pub fn save_private(data: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    if Path::new(name).components().count() != 1 || name.starts_with('.') {
        return Err(io::Error::other("Invalid private settings filename"));
    }
    ensure_data_dir(data)?;
    let mut staged = tempfile::NamedTempFile::new_in(data)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(data.join(name)).map_err(|e| e.error)?;
    Ok(())
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct DesktopPreferences {
    pub keep_monitoring: bool,
}
impl DesktopPreferences {
    pub fn load(data: &Path) -> Self {
        small_file(&data.join("desktop.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, data: &Path) -> io::Result<()> {
        save_private(
            data,
            "desktop.json",
            &serde_json::to_vec(self).map_err(io::Error::other)?,
        )
    }
}
fn small_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = options().read(true).open(path)?;
    let mut bytes = vec![];
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Local identity file exceeds 4 KiB",
        ));
    }
    Ok(bytes)
}
pub fn token(data: &Path) -> io::Result<String> {
    if let Ok(value) = std::env::var("SNITCH_TOKEN") {
        return validate_token(value);
    }
    ensure_data_dir(data)?;
    let path = data.join("api_token.txt");
    if !path.exists() {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let value: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut staged = tempfile::NamedTempFile::new_in(data)?;
        staged.write_all(value.as_bytes())?;
        staged.as_file().sync_all()?;
        match staged.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error),
        }
    }
    validate_token(
        String::from_utf8(small_file(&path)?).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "API token is not valid text")
        })?,
    )
}
fn validate_token(value: String) -> io::Result<String> {
    let value = value.trim();
    if !(16..=4096).contains(&value.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "API token must contain 16–4096 characters",
        ));
    }
    Ok(value.to_string())
}
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Endpoint {
    pub url: String,
    pub pid: u32,
}
pub fn endpoint(data: &Path) -> io::Result<Endpoint> {
    serde_json::from_slice(&small_file(&data.join("collector.json"))?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
pub struct Instance {
    _file: File,
    data: PathBuf,
    published: bool,
}
impl Instance {
    pub fn acquire(data: &Path) -> io::Result<Self> {
        ensure_data_dir(data)?;
        let file = options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data.join("collector.lock"))?;
        file.try_lock().map_err(|error|match error {
            fs::TryLockError::WouldBlock=>io::Error::new(io::ErrorKind::AlreadyExists,"A collector is already using this data directory; attach to it instead of starting another"),
            fs::TryLockError::Error(error)=>error,
        })?;
        Ok(Self {
            _file: file,
            data: data.into(),
            published: false,
        })
    }
    pub fn publish(&mut self, url: &str) -> io::Result<()> {
        if ![
            "http://127.0.0.1:",
            "https://127.0.0.1:",
            "http://[::1]:",
            "https://[::1]:",
        ]
        .iter()
        .any(|prefix| url.starts_with(prefix))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Collector discovery must use loopback",
            ));
        }
        let value = Endpoint {
            url: url.into(),
            pid: std::process::id(),
        };
        let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let staged = self.data.join(format!(".collector-{suffix}.json"));
        let result = (|| {
            let mut file = options().write(true).create_new(true).open(&staged)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&staged, self.data.join("collector.json"))
        })(); // atomic publish, never truncate live discovery metadata
        if result.is_err() {
            let _ = fs::remove_file(&staged);
        }
        result?;
        self.published = true;
        Ok(())
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        if self.published && endpoint(&self.data).is_ok_and(|e| e.pid == std::process::id()) {
            let _ = fs::remove_file(self.data.join("collector.json"));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_second_collector_cannot_own_the_same_data() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = Instance::acquire(dir.path()).unwrap();
        assert!(Instance::acquire(dir.path()).is_err());
        first.publish("http://127.0.0.1:12345").unwrap();
        assert_eq!(endpoint(dir.path()).unwrap().pid, std::process::id());
        drop(first);
        assert!(endpoint(dir.path()).is_err());
        assert!(Instance::acquire(dir.path()).is_ok());
    }
    #[test]
    fn persistent_token_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let first = token(dir.path()).unwrap();
        assert_eq!(token(dir.path()).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.path().join("api_token.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn simultaneous_windows_never_observe_a_partly_written_token() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| token(dir.path()).unwrap()))
                .collect();
            let tokens: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(tokens.iter().all(|token| token == &tokens[0]));
        });
    }
}
