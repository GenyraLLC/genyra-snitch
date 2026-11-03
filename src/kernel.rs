//! Native libbpf lifecycle. Kernel objects are scoped to this process and
//! detached on shutdown; egress policy is limited to our dedicated cgroup.
use crate::{process::Owner, App};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::{c_char, c_int, c_void, CStr},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
    ptr::NonNull,
    sync::{atomic::Ordering, Mutex},
    time::{Duration, Instant},
};

unsafe extern "C" {
    fn bpf_object__open_mem(data: *const c_void, size: usize, opts: *const c_void) -> *mut c_void;
    fn bpf_object__close(object: *mut c_void);
    fn bpf_object__load(object: *mut c_void) -> c_int;
    fn bpf_object__find_program_by_name(object: *const c_void, name: *const c_char) -> *mut c_void;
    fn bpf_program__set_autoload(program: *mut c_void, enabled: bool) -> c_int;
    fn bpf_program__attach_tracepoint(
        program: *const c_void,
        category: *const c_char,
        name: *const c_char,
    ) -> *mut c_void;
    fn bpf_program__attach_cgroup(program: *const c_void, cgroup_fd: c_int) -> *mut c_void;
    fn bpf_object__find_map_fd_by_name(object: *const c_void, name: *const c_char) -> c_int;
    fn bpf_link__destroy(link: *mut c_void) -> c_int;
    fn libbpf_get_error(ptr: *const c_void) -> libc::c_long;
    fn ring_buffer__new(
        fd: c_int,
        callback: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int,
        context: *mut c_void,
        opts: *const c_void,
    ) -> *mut c_void;
    fn ring_buffer__poll(buffer: *mut c_void, timeout: c_int) -> c_int;
    fn ring_buffer__free(buffer: *mut c_void);
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
}
fn checked(ptr: *mut c_void) -> Result<NonNull<c_void>, String> {
    let ptr = NonNull::new(ptr).ok_or_else(|| std::io::Error::last_os_error().to_string())?;
    let error = unsafe { libbpf_get_error(ptr.as_ptr()) };
    if error < 0 {
        Err(std::io::Error::from_raw_os_error(-error as i32).to_string())
    } else {
        Ok(ptr)
    }
}
fn code(value: c_int) -> Result<(), String> {
    if value < 0 {
        Err(std::io::Error::from_raw_os_error(-value).to_string())
    } else {
        Ok(())
    }
}
struct Object(NonNull<c_void>);
// Every Object is accessed under Enforcer's mutex or owned by one probe
// thread. Moving ownership does not introduce concurrent libbpf access.
unsafe impl Send for Object {}
impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            bpf_object__close(self.0.as_ptr());
        }
    }
}
struct Link(NonNull<c_void>);
unsafe impl Send for Link {}
impl Drop for Link {
    fn drop(&mut self) {
        unsafe {
            bpf_link__destroy(self.0.as_ptr());
        }
    }
}
impl Object {
    fn open(probe: bool) -> Result<Self, String> {
        Self::open_mode(probe, false)
    }
    fn open_mode(probe: bool, deny: bool) -> Result<Self, String> {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/snitch.bpf.o"));
        let object = Self(checked(unsafe {
            bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len(), std::ptr::null())
        })?);
        for (name, enabled) in [
            (c"trace_connect", probe),
            (c"filter_egress", !probe && !deny),
            (c"isolate_egress", deny),
        ] {
            let program = object.program(name)?;
            code(unsafe { bpf_program__set_autoload(program, enabled) })?;
        }
        code(unsafe { bpf_object__load(object.0.as_ptr()) })?;
        Ok(object)
    }
    fn program(&self, name: &CStr) -> Result<*mut c_void, String> {
        NonNull::new(unsafe { bpf_object__find_program_by_name(self.0.as_ptr(), name.as_ptr()) })
            .map(NonNull::as_ptr)
            .ok_or_else(|| "Embedded BPF program missing".into())
    }
    fn map(&self, name: &CStr) -> Result<c_int, String> {
        let fd = unsafe { bpf_object__find_map_fd_by_name(self.0.as_ptr(), name.as_ptr()) };
        if fd < 0 {
            Err("Embedded BPF map missing".into())
        } else {
            Ok(fd)
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    timestamp: u64,
    pid: u32,
    fd: i32,
    family: u16,
    port: u16,
    address: [u8; 16],
    command: [u8; 16],
    padding: u32,
}
#[derive(Default)]
struct Probe {
    active: bool,
    error: Option<String>,
    events: u64,
    recent: VecDeque<Value>,
    owners: HashMap<(IpAddr, u16), (Instant, Owner, bool)>,
}
struct Enforcer {
    object: Object,
    _link: Link,
    _cgroup: fs::File,
    blocked: HashSet<String>,
    isolated: HashMap<u32, (String, String)>,
}
impl Drop for Enforcer {
    fn drop(&mut self) {
        for (pid, (original, start)) in &self.isolated {
            if process_start(*pid).as_deref() == Some(start.as_str()) {
                let current = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
                if current.contains("/genyra-snitch") {
                    let path = std::path::Path::new("/sys/fs/cgroup")
                        .join(original.trim_start_matches('/'))
                        .join("cgroup.procs");
                    let _ = fs::write(path, format!("{pid}\n"));
                }
            }
        }
    }
}
// Each denied process gets a scoped cgroup. Descendants inherit the denial;
// removing the rule returns all surviving members to the original cgroup.
struct DeniedGroup {
    _link: Link,
    _file: fs::File,
    path: std::path::PathBuf,
    original: std::path::PathBuf,
    start: String,
}
impl Drop for DeniedGroup {
    fn drop(&mut self) {
        if let Ok(members) = fs::read_to_string(self.path.join("cgroup.procs")) {
            for pid in members.lines().filter(|s| s.parse::<u32>().is_ok()) {
                let _ = fs::write(self.original.join("cgroup.procs"), format!("{pid}\n"));
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}
struct ProcessPolicy {
    object: Object,
    groups: HashMap<u32, DeniedGroup>,
}
#[derive(Default)]
pub struct Kernel {
    probe: Mutex<Probe>,
    enforcer: Mutex<Option<Enforcer>>,
    process_policy: Mutex<Option<ProcessPolicy>>,
}
fn process_start(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(')')
                .and_then(|(_, s)| s.split_whitespace().nth(19))
                .map(str::to_string)
        })
}
fn available(enforce: bool) -> Result<(), String> {
    if crate::demo::enabled() {
        return Err("disabled in demo mode".into());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("requires root for native BPF loading and cgroup management".into());
    }
    if enforce && !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err("cgroup v2 is not mounted".into());
    }
    Ok(())
}
impl Kernel {
    pub fn sync_process_policy(&self, names: &HashSet<String>) -> Result<(), String> {
        let mut guard = self.process_policy.lock().unwrap();
        if names.is_empty() {
            *guard = None;
            return Ok(());
        }
        available(true)?;
        if guard.is_none() {
            *guard = Some(ProcessPolicy {
                object: Object::open_mode(false, true)?,
                groups: HashMap::new(),
            });
        }
        let policy = guard.as_mut().unwrap();
        let mut matches = HashMap::new();
        for entry in fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid <= 3 || pid == std::process::id() {
                continue;
            }
            let name = fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            if names.contains(name.trim()) {
                if let Some(start) = process_start(pid) {
                    matches.insert(pid, start);
                }
            }
        }
        policy
            .groups
            .retain(|pid, g| matches.get(pid) == Some(&g.start));
        for (pid, start) in matches {
            if policy.groups.contains_key(&pid) {
                continue;
            }
            if policy.groups.len() >= 512 {
                return Err("Process firewall capacity reached (512 processes)".into());
            }
            let membership =
                fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| e.to_string())?;
            let original = membership
                .lines()
                .find_map(|l| l.strip_prefix("0::"))
                .ok_or("Cannot resolve original cgroup")?;
            let original =
                std::path::Path::new("/sys/fs/cgroup").join(original.trim_start_matches('/'));
            let path = std::path::PathBuf::from(format!("/sys/fs/cgroup/genyra-snitch-deny-{pid}"));
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            let file = fs::File::open(&path).map_err(|e| e.to_string())?;
            let link = Link(checked(unsafe {
                bpf_program__attach_cgroup(
                    policy.object.program(c"isolate_egress")?,
                    file.as_raw_fd(),
                )
            })?);
            let group = DeniedGroup {
                _link: link,
                _file: file,
                path,
                original,
                start,
            };
            if process_start(pid).as_deref() != Some(group.start.as_str()) {
                continue;
            }
            fs::write(group.path.join("cgroup.procs"), format!("{pid}\n"))
                .map_err(|e| e.to_string())?;
            policy.groups.insert(pid, group);
        }
        Ok(())
    }
    pub fn probe_status(&self) -> Value {
        let capability = available(false);
        let p = self.probe.lock().unwrap();
        json!({"available":capability.is_ok(),"reason":capability.err().unwrap_or_default(),"active":p.active,"events_buffered":p.recent.len(),"events_total":p.events,"error":p.error,"implementation":"libbpf"})
    }
    pub fn enforcer_status(&self) -> Value {
        let capability = available(true);
        let e = self.enforcer.lock().unwrap();
        json!({"available":capability.is_ok(),"reason":capability.err().unwrap_or_default(),"attached":e.is_some(),"cgroup":"/sys/fs/cgroup/genyra-snitch","blocked":e.as_ref().map(|e|e.blocked.iter().collect::<Vec<_>>()).unwrap_or_default(),"isolated_pids":e.as_ref().map(|e|e.isolated.keys().collect::<Vec<_>>()).unwrap_or_default()})
    }
    pub fn owner(&self, ip: IpAddr, port: u16) -> Option<Owner> {
        let p = self.probe.lock().unwrap();
        p.owners
            .get(&(ip, port))
            .filter(|(at, _, ambiguous)| !ambiguous && at.elapsed() < Duration::from_secs(30))
            .map(|(_, owner, _)| owner.clone())
    }
    fn ensure_enforcer<'a>(
        &self,
        guard: &'a mut Option<Enforcer>,
    ) -> Result<&'a mut Enforcer, String> {
        available(true)?;
        if guard.is_none() {
            let path = std::path::Path::new("/sys/fs/cgroup/genyra-snitch");
            fs::create_dir_all(path).map_err(|e| e.to_string())?;
            let cgroup = fs::File::open(path).map_err(|e| e.to_string())?;
            let object = Object::open(false)?;
            let link = Link(checked(unsafe {
                bpf_program__attach_cgroup(object.program(c"filter_egress")?, cgroup.as_raw_fd())
            })?);
            *guard = Some(Enforcer {
                object,
                _link: link,
                _cgroup: cgroup,
                blocked: HashSet::new(),
                isolated: HashMap::new(),
            });
        }
        Ok(guard.as_mut().unwrap())
    }
    pub fn block(&self, ip: IpAddr) -> Result<(), String> {
        let mut guard = self.enforcer.lock().unwrap();
        let e = self.ensure_enforcer(&mut guard)?;
        if e.blocked.len() >= 4096 && !e.blocked.contains(&ip.to_string()) {
            return Err("BPF block map capacity reached".into());
        }
        let value = 1u8;
        let rc = match ip {
            IpAddr::V4(ip) => unsafe {
                bpf_map_update_elem(
                    e.object.map(c"blocked_v4")?,
                    ip.octets().as_ptr().cast(),
                    (&value as *const u8).cast(),
                    0,
                )
            },
            IpAddr::V6(ip) => unsafe {
                bpf_map_update_elem(
                    e.object.map(c"blocked_v6")?,
                    ip.octets().as_ptr().cast(),
                    (&value as *const u8).cast(),
                    0,
                )
            },
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        e.blocked.insert(ip.to_string());
        Ok(())
    }
    pub fn isolate(&self, pid: u32) -> Result<(), String> {
        let mut guard = self.enforcer.lock().unwrap();
        let e = self.ensure_enforcer(&mut guard)?;
        let start = process_start(pid).ok_or("Process exited")?;
        let original = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|e| e.to_string())?
            .lines()
            .find_map(|l| l.strip_prefix("0::").map(str::to_string))
            .ok_or("Cannot resolve cgroup v2 membership")?;
        fs::write(
            "/sys/fs/cgroup/genyra-snitch/cgroup.procs",
            format!("{pid}\n"),
        )
        .map_err(|e| e.to_string())?;
        e.isolated.insert(pid, (original, start));
        Ok(())
    }
}
unsafe extern "C" fn receive(context: *mut c_void, data: *mut c_void, len: usize) -> c_int {
    if len < std::mem::size_of::<Event>() || context.is_null() || data.is_null() {
        return 0;
    }
    let event = unsafe { std::ptr::read_unaligned(data.cast::<Event>()) };
    let probe = unsafe { &*context.cast::<Mutex<Probe>>() };
    let ip = match event.family {
        2 => IpAddr::V4(Ipv4Addr::new(
            event.address[0],
            event.address[1],
            event.address[2],
            event.address[3],
        )),
        10 => IpAddr::V6(Ipv6Addr::from(event.address)),
        _ => return 0,
    };
    let name = String::from_utf8_lossy(&event.command)
        .trim_end_matches('\0')
        .to_string();
    let owner = Owner {
        pid: event.pid,
        name: name.clone(),
        ..Owner::default()
    };
    if let Ok(mut p) = probe.lock() {
        p.events += 1;
        if p.recent.len() >= 256 {
            p.recent.pop_front();
        }
        p.recent.push_back(json!({"pid":event.pid,"name":name,"remote_ip":ip,"remote_port":event.port,"fd":event.fd}));
        let key = (ip, event.port);
        if p.owners.len() >= 4096 && !p.owners.contains_key(&key) {
            p.owners
                .retain(|_, (at, _, _)| at.elapsed() < Duration::from_secs(30));
        }
        if p.owners.len() < 4096 {
            let ambiguous = p.owners.get(&key).is_some_and(|(at, o, amb)| {
                at.elapsed() < Duration::from_secs(30) && (o.pid != event.pid || *amb)
            });
            p.owners.insert(key, (Instant::now(), owner, ambiguous));
        }
    }
    0
}
struct Ring(NonNull<c_void>);
impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            ring_buffer__free(self.0.as_ptr());
        }
    }
}
pub fn run(a: App) {
    if crate::demo::enabled() {
        return;
    }
    while !a.stop.load(Ordering::Relaxed) {
        let enabled = a.engine.lock().unwrap().settings["ebpf_probe"] == true;
        if !enabled {
            crate::interruptible_sleep(&a.stop, Duration::from_millis(500));
            continue;
        }
        let result = (|| -> Result<(), String> {
            available(false)?;
            let object = Object::open(true)?;
            let _link = Link(checked(unsafe {
                bpf_program__attach_tracepoint(
                    object.program(c"trace_connect")?,
                    c"syscalls".as_ptr(),
                    c"sys_enter_connect".as_ptr(),
                )
            })?);
            // The callback context outlives Ring, and poll is the only caller.
            let context = (&a.kernel.probe as *const Mutex<Probe>).cast_mut().cast();
            let ring = Ring(checked(unsafe {
                ring_buffer__new(
                    object.map(c"connect_events")?,
                    receive,
                    context,
                    std::ptr::null(),
                )
            })?);
            {
                let mut p = a.kernel.probe.lock().unwrap();
                p.active = true;
                p.error = None;
            }
            while !a.stop.load(Ordering::Relaxed)
                && a.engine.lock().unwrap().settings["ebpf_probe"] == true
            {
                let rc = unsafe { ring_buffer__poll(ring.0.as_ptr(), 100) };
                if rc < 0 && rc != -libc::EINTR {
                    return Err(std::io::Error::from_raw_os_error(-rc).to_string());
                }
            }
            Ok(())
        })();
        {
            let mut p = a.kernel.probe.lock().unwrap();
            p.active = false;
            if let Err(error) = result {
                p.error = Some(error);
            }
        }
        crate::interruptible_sleep(&a.stop, Duration::from_secs(3));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_layout_matches_embedded_c_abi() {
        assert_eq!(std::mem::size_of::<Event>(), 56);
        assert!(include_bytes!(concat!(env!("OUT_DIR"), "/snitch.bpf.o")).starts_with(b"\x7fELF"));
    }
    #[test]
    fn callback_is_bounded_and_rejects_ambiguous_owners() {
        let probe = Mutex::new(Probe::default());
        let mut event = Event {
            timestamp: 0,
            pid: 123,
            fd: 4,
            family: 2,
            port: 443,
            address: [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            command: [0; 16],
            padding: 0,
        };
        unsafe {
            receive(
                (&probe as *const Mutex<Probe>).cast_mut().cast(),
                (&mut event as *mut Event).cast(),
                56,
            );
        }
        assert_eq!(probe.lock().unwrap().events, 1);
        event.pid = 456;
        unsafe {
            receive(
                (&probe as *const Mutex<Probe>).cast_mut().cast(),
                (&mut event as *mut Event).cast(),
                56,
            );
        }
        assert!(probe
            .lock()
            .unwrap()
            .owners
            .values()
            .all(|(_, _, ambiguous)| *ambiguous));
    }
}
