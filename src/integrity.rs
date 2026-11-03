//! One bounded worker and a metadata-keyed file hash cache. No executor fanout.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::Read,
    time::Instant,
};

type FileIdentity = (u64, u64, i64, i64);
#[derive(Default)]
pub struct Integrity {
    pub baselines: HashMap<String, String>,
    pub findings: VecDeque<Value>,
    checked: HashSet<(u32, String)>,
    checked_order: VecDeque<(u32, String)>,
    cache: HashMap<String, (FileIdentity, String)>,
    cache_order: VecDeque<String>,
    cache_hits: u64,
    bytes_hashed: u64,
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
pub fn sha(bytes: impl AsRef<[u8]>) -> String {
    hex(Sha256::digest(bytes.as_ref()))
}
pub fn merkle(mut leaves: Vec<String>) -> String {
    leaves.sort();
    if leaves.is_empty() {
        return String::new();
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(leaves.last().unwrap().clone());
        }
        leaves = leaves
            .chunks(2)
            .map(|pair| sha(format!("{}{}", pair[0], pair[1])))
            .collect();
    }
    leaves.pop().unwrap()
}
impl Integrity {
    fn remember_process(&mut self, identity: (u32, String)) {
        if self.checked.contains(&identity) {
            return;
        }
        if self.checked.len() >= 4000 {
            if let Some(old) = self.checked_order.pop_front() {
                self.checked.remove(&old);
            }
        }
        self.checked.insert(identity.clone());
        self.checked_order.push_back(identity);
    }
    pub fn load(v: &Value) -> Self {
        let mut s = Self::default();
        if let Some(m) = v.as_object() {
            for (k, v) in m {
                if let Some(v) = v.as_str() {
                    s.baselines.insert(k.clone(), v.into());
                }
            }
        }
        s
    }
    pub(crate) fn hash_file(&mut self, path: &str) -> Option<String> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        #[cfg(unix)]
        let key = (meta.dev(), meta.ino(), meta.mtime(), meta.mtime_nsec());
        #[cfg(windows)]
        let key = {
            use std::os::windows::fs::MetadataExt;
            (
                meta.file_size(),
                meta.creation_time(),
                meta.last_write_time() as i64,
                0,
            )
        };
        if let Some((old, hash)) = self.cache.get(path) {
            if *old == key {
                self.cache_hits = self.cache_hits.saturating_add(1);
                return Some(hash.clone());
            }
        }
        let mut file = fs::File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        let start = Instant::now();
        loop {
            let n = file.read(&mut buffer).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            self.bytes_hashed = self.bytes_hashed.saturating_add(n as u64);
            if start.elapsed().as_secs() > 5 {
                return None;
            }
        }
        let hash = hex(hasher.finalize());
        if !self.cache.contains_key(path) {
            if self.cache.len() >= 2048 {
                if let Some(old) = self.cache_order.pop_front() {
                    self.cache.remove(&old);
                }
            }
            self.cache_order.push_back(path.into());
        }
        self.cache.insert(path.into(), (key, hash.clone()));
        Some(hash)
    }
    pub fn status(&self, enabled: bool) -> Value {
        let linux = cfg!(target_os = "linux");
        json!({"enabled":enabled,"platform":std::env::consts::OS,"capabilities":{"exe_hash_watch":true,"name_mismatch":true,"rwx_scan":linux,"module_paths":true,"merkle_modules":true},"checked":self.checked.len(),"baselines":self.baselines.len(),"findings":self.findings,"hash_cache":self.cache.len(),"cache_hits":self.cache_hits,"bytes_hashed":self.bytes_hashed})
    }
    #[cfg(target_os = "linux")]
    pub fn check(&mut self, pid: u32, force: bool) -> Vec<Value> {
        let proc = format!("/proc/{pid}");
        let stat = fs::read_to_string(format!("{proc}/stat")).unwrap_or_default();
        let start = stat
            .rsplit_once(')')
            .map(|(_, v)| v.split_whitespace().nth(19).unwrap_or("").to_string())
            .unwrap_or_default();
        if !force && self.checked.contains(&(pid, start.clone())) {
            return vec![];
        }
        self.remember_process((pid, start));
        let Ok(exe) = fs::read_link(format!("{proc}/exe")) else {
            return vec![];
        };
        let exe = exe.to_string_lossy().into_owned();
        let name = fs::read_to_string(format!("{proc}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let mut out = Vec::new();
        let base = Path::new(&exe)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        fn norm(s: &str) -> String {
            s.to_lowercase()
                .trim_end_matches(".exe")
                .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-')
                .to_string()
        }
        if norm(&name) != norm(base) && !base.starts_with(&name) {
            out.push(json!({"type":"NAME_MISMATCH","severity":"warning","pid":pid,"exe":exe,"detail":format!("process name {name} differs from executable {base}")}));
        }
        if let Some(hash) = self.hash_file(&exe) {
            if let Some(old) = self.baselines.get(&exe) {
                if old != &hash {
                    out.push(json!({"type":"BINARY_CHANGED","severity":"critical","pid":pid,"exe":exe,"detail":"Executable file changed on disk","expected":old,"actual":hash}));
                }
            } else if self.baselines.len() < 2000 {
                self.baselines.insert(exe.clone(), hash);
            }
        }
        if let Ok(maps) = fs::read_to_string(format!("{proc}/maps")) {
            let mut modules = HashSet::new();
            let mut rwx = Vec::new();
            let mut paths = Vec::new();
            for line in maps.lines().take(50000) {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 5 {
                    continue;
                }
                if fields[1].starts_with("rwx") && rwx.len() < 10 {
                    rwx.push(fields[0].to_string());
                }
                if fields.len() > 5 && fields[5].starts_with('/') {
                    let path = fields[5];
                    if modules.len() < 200 {
                        modules.insert(path.to_string());
                    }
                    if [
                        "/tmp/",
                        "/var/tmp/",
                        "/dev/shm/",
                        "/Downloads/",
                        "/.cache/",
                        "memfd:",
                    ]
                    .iter()
                    .any(|m| path.contains(m))
                        && paths.len() < 20
                    {
                        paths.push(path.to_string());
                    }
                }
            }
            if !rwx.is_empty() {
                let jit = [
                    "brave", "chrome", "chromium", "firefox", "node", "java", "electron",
                    "spotify", "ChatGPT",
                ]
                .iter()
                .any(|s| name.contains(s));
                out.push(json!({"type":"MEM_RWX","severity":if jit{"info"}else{"warning"},"pid":pid,"exe":exe,"detail":"Executable writable memory mappings","regions":rwx}));
            }
            if !paths.is_empty() {
                out.push(json!({"type":"MODULE_SUSPECT","severity":"warning","pid":pid,"exe":exe,"detail":"Mapped modules in staging paths","paths":paths}));
            }
            let mut hashes = Vec::new();
            let module_start = std::time::Instant::now();
            let mut complete = true;
            for path in modules {
                if module_start.elapsed() > std::time::Duration::from_millis(500) {
                    complete = false;
                    break;
                }
                if let Some(hash) = self.hash_file(&path) {
                    hashes.push(hash);
                } else {
                    complete = false;
                }
            }
            let root = merkle(hashes);
            let key = format!("merkle:{exe}");
            if !complete { /* Partial snapshots cannot establish or compare a Merkle baseline. */
            } else if let Some(old) = self.baselines.get(&key) {
                if old != &root {
                    out.push(json!({"type":"MODULE_CHANGED","severity":"critical","pid":pid,"exe":exe,"detail":"Mapped-module Merkle root changed","expected":old,"actual":root}));
                }
            } else if self.baselines.len() < 2000 {
                self.baselines.insert(key, root);
            }
        }
        for finding in &mut out {
            finding["ts"] = json!(chrono::Utc::now().timestamp_millis() as f64 / 1000.);
            if self.findings.len() >= 200 {
                self.findings.pop_front();
            }
            self.findings.push_back(finding.clone());
        }
        out
    }
    #[cfg(not(target_os = "linux"))]
    pub fn check(&mut self, pid: u32, force: bool) -> Vec<Value> {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
        let mut system = System::new();
        let id = Pid::from_u32(pid);
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[id]),
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
        );
        let Some(process) = system.process(id) else {
            return vec![];
        };
        let identity = (pid, process.start_time().to_string());
        if !force && self.checked.contains(&identity) {
            return vec![];
        }
        // A bounded cache of process identities, not just PIDs (which recycle).
        self.remember_process(identity);
        let Some(exe) = process.exe() else {
            return vec![];
        };
        let exe = exe.to_string_lossy().into_owned();
        let Some(hash) = self.hash_file(&exe) else {
            return vec![];
        };
        let mut out = vec![];
        if let Some(old) = self.baselines.get(&exe) {
            if old != &hash {
                out.push(json!({"type":"BINARY_CHANGED","severity":"critical","pid":pid,"exe":exe,"expected":old,"actual":hash,"ts":chrono::Utc::now().timestamp_millis() as f64/1000.}));
            }
        } else if self.baselines.len() < 2000 {
            self.baselines.insert(exe.clone(), hash);
        }
        let name = process.name().to_string_lossy();
        let base = std::path::Path::new(&exe)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        if !name.is_empty()
            && !base.to_lowercase().starts_with(&name.to_lowercase())
            && !name.eq_ignore_ascii_case(&base)
        {
            out.push(json!({"type":"NAME_MISMATCH","severity":"warning","pid":pid,"exe":exe,"detail":format!("Process name {name} differs from executable {base}")}));
        }
        if let Ok(modules) = crate::platform::modules::paths(pid) {
            let suspicious: Vec<_> = modules
                .iter()
                .filter(|path| {
                    let path = path.to_lowercase().replace('\\', "/");
                    [
                        "/tmp/",
                        "/var/tmp/",
                        "/dev/shm/",
                        "/appdata/local/temp/",
                        "/downloads/",
                    ]
                    .iter()
                    .any(|marker| path.contains(marker))
                })
                .take(10)
                .cloned()
                .collect();
            if !suspicious.is_empty() {
                out.push(json!({"type":"MODULE_SUSPECT","severity":"warning","pid":pid,"exe":exe,"detail":"Mapped modules loaded from staging locations","modules":suspicious}));
            }
            let started = Instant::now();
            let mut complete = true;
            let mut hashes = vec![];
            for path in modules {
                if started.elapsed() > std::time::Duration::from_millis(500) {
                    complete = false;
                    break;
                }
                if let Some(hash) = self.hash_file(&path) {
                    hashes.push(hash);
                } else {
                    complete = false;
                }
            }
            if complete && !hashes.is_empty() {
                let root = merkle(hashes);
                let key = format!("merkle:{exe}");
                if let Some(old) = self.baselines.get(&key) {
                    if old != &root {
                        out.push(json!({"type":"MODULE_CHANGED","severity":"critical","pid":pid,"exe":exe,"detail":"Mapped-module Merkle root changed","expected":old,"actual":root}));
                    }
                } else if self.baselines.len() < 2000 {
                    self.baselines.insert(key, root);
                }
            }
        }
        for finding in &mut out {
            finding["ts"] = json!(chrono::Utc::now().timestamp_millis() as f64 / 1000.);
        }
        for finding in &out {
            if self.findings.len() >= 200 {
                self.findings.pop_front();
            }
            self.findings.push_back(finding.clone());
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exceeding_hash_capacity_does_not_rehash_the_whole_working_set() {
        let dir =
            std::env::temp_dir().join(format!("genyra-integrity-cache-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let mut watch = Integrity::default();
        for i in 0..2049 {
            let path = dir.join(i.to_string());
            fs::write(&path, b"x").unwrap();
            assert!(watch.hash_file(path.to_str().unwrap()).is_some());
        }
        let bytes = watch.bytes_hashed;
        for i in 1000..2049 {
            assert!(watch
                .hash_file(dir.join(i.to_string()).to_str().unwrap())
                .is_some());
        }
        assert_eq!(
            watch.bytes_hashed, bytes,
            "overflow must not invalidate the entire cache"
        );
        assert_eq!(watch.cache_hits, 1049);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn known_hash_and_order_independent_merkle() {
        assert_eq!(
            sha("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let a = vec![sha("a"), sha("b"), sha("c")];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(merkle(a), merkle(b));
    }
}
