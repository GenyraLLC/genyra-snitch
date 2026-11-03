//! Native NFQUEUE first-flow decisions, using one bounded polling thread.
use crate::App;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    ffi::{c_int, c_void},
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
    sync::{atomic::Ordering, Mutex},
    time::{Duration, Instant},
};

#[link(name = "netfilter_queue")]
unsafe extern "C" {
    fn nfq_open() -> *mut c_void;
    fn nfq_close(handle: *mut c_void) -> c_int;
    fn nfq_bind_pf(handle: *mut c_void, family: u16) -> c_int;
    fn nfq_create_queue(
        handle: *mut c_void,
        number: u16,
        callback: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> c_int,
        context: *mut c_void,
    ) -> *mut c_void;
    fn nfq_destroy_queue(queue: *mut c_void) -> c_int;
    fn nfq_set_mode(queue: *mut c_void, mode: u8, len: u32) -> c_int;
    fn nfq_set_queue_maxlen(queue: *mut c_void, len: u32) -> c_int;
    fn nfq_set_queue_flags(queue: *mut c_void, mask: u32, flags: u32) -> c_int;
    fn nfq_fd(handle: *mut c_void) -> c_int;
    fn nfq_handle_packet(handle: *mut c_void, buffer: *mut libc::c_char, len: c_int) -> c_int;
    fn nfq_get_msg_packet_hdr(data: *mut c_void) -> *mut c_void;
    fn nfq_get_payload(data: *mut c_void, output: *mut *mut u8) -> c_int;
    fn nfq_set_verdict(
        queue: *mut c_void,
        id: u32,
        verdict: u32,
        len: u32,
        data: *const u8,
    ) -> c_int;
}
#[derive(Clone, Hash, Eq, PartialEq)]
struct Key {
    ip: IpAddr,
    port: u16,
    proto: String,
}
struct Pending {
    ids: Vec<u32>,
    at: Instant,
    decision: Option<bool>,
}
#[derive(Default)]
struct Inner {
    running: bool,
    error: Option<String>,
    pending: HashMap<Key, Pending>,
    decided: HashMap<Key, bool>,
    order: VecDeque<Key>,
    overflow: u64,
}
#[derive(Default)]
pub struct Ask {
    inner: Mutex<Inner>,
}
fn available() -> Result<(), String> {
    if crate::demo::enabled() {
        return Err("disabled in demo mode".into());
    }
    let caps = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("CapEff:")
                    .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
            })
        })
        .unwrap_or(0);
    if caps & (1 << 12) == 0 {
        return Err("needs CAP_NET_ADMIN for nftables and NFQUEUE".into());
    }
    if !std::path::Path::new("/usr/bin/nft").is_file()
        && !std::path::Path::new("/usr/sbin/nft").is_file()
    {
        return Err("nft executable not found".into());
    }
    Ok(())
}
impl Ask {
    pub fn status(&self, settings: &Value) -> Value {
        let capability = available();
        let inner = self.inner.lock().unwrap();
        json!({"available":capability.is_ok(),"reason":capability.err().unwrap_or_default(),"running":inner.running,"queue":if inner.running{Some(7)}else{None},"pending":inner.pending.len(),"decided":inner.decided.len(),"timeout_s":settings["ask_timeout"].as_f64().unwrap_or(15.).clamp(3.,120.),"failopen":settings["ask_failopen"]==true,"error":inner.error,"capacity_overflow":inner.overflow,"implementation":"libnetfilter_queue"})
    }
    pub fn decide(&self, ip: IpAddr, port: u16, proto: &str, allow: bool) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if let Some(pending) = inner.pending.get_mut(&Key {
            ip,
            port,
            proto: proto.to_uppercase(),
        }) {
            pending.decision = Some(allow);
            true
        } else {
            false
        }
    }
    fn actions(&self, timeout: Duration, failopen: bool, force: bool) -> Vec<(u32, bool)> {
        let mut inner = self.inner.lock().unwrap();
        let ready: Vec<_> = inner
            .pending
            .iter()
            .filter(|(_, p)| force || p.decision.is_some() || p.at.elapsed() >= timeout)
            .map(|(key, _)| key.clone())
            .collect();
        let mut actions = Vec::new();
        for key in ready {
            if let Some(p) = inner.pending.remove(&key) {
                let allow = p.decision.unwrap_or(failopen);
                actions.extend(p.ids.into_iter().map(|id| (id, allow)));
                if inner.decided.len() >= 65536 {
                    if let Some(old) = inner.order.pop_front() {
                        inner.decided.remove(&old);
                    }
                }
                if !inner.decided.contains_key(&key) {
                    inner.order.push_back(key.clone());
                }
                inner.decided.insert(key, allow);
            }
        }
        actions
    }
}
struct Queue {
    handle: *mut c_void,
    queue: *mut c_void,
}
impl Drop for Queue {
    fn drop(&mut self) {
        unsafe {
            if !self.queue.is_null() {
                nfq_destroy_queue(self.queue);
            }
            if !self.handle.is_null() {
                nfq_close(self.handle);
            }
        }
    }
}
impl Queue {
    fn open(a: &App) -> Result<Self, String> {
        let handle = unsafe { nfq_open() };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut queue = Self {
            handle,
            queue: std::ptr::null_mut(),
        };
        unsafe {
            nfq_bind_pf(handle, libc::AF_INET as u16);
            nfq_bind_pf(handle, libc::AF_INET6 as u16);
        }
        queue.queue =
            unsafe { nfq_create_queue(handle, 7, receive, (a as *const App).cast_mut().cast()) };
        if queue.queue.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if unsafe { nfq_set_mode(queue.queue, 2, 65535) } < 0 {
            return Err("NFQUEUE copy-mode setup failed".into());
        }
        unsafe {
            nfq_set_queue_maxlen(queue.queue, 1024);
        };
        Ok(queue)
    }
    fn verdict(&self, id: u32, allow: bool) {
        unsafe {
            nfq_set_verdict(self.queue, id, u32::from(allow), 0, std::ptr::null());
        }
    }
}
unsafe extern "C" fn receive(
    queue: *mut c_void,
    _msg: *mut c_void,
    data: *mut c_void,
    context: *mut c_void,
) -> c_int {
    if queue.is_null() || data.is_null() || context.is_null() {
        return 0;
    }
    let header = unsafe { nfq_get_msg_packet_hdr(data) };
    if header.is_null() {
        return 0;
    }
    let id = u32::from_be(unsafe { std::ptr::read_unaligned(header.cast::<u32>()) });
    let mut payload = std::ptr::null_mut();
    let len = unsafe { nfq_get_payload(data, &mut payload) };
    let a = unsafe { &*context.cast::<App>() };
    let bytes = if len > 0 && !payload.is_null() {
        unsafe { std::slice::from_raw_parts(payload, len as usize) }
    } else {
        &[]
    };
    let parsed = crate::packet::parse(bytes, 101);
    let key = parsed
        .as_ref()
        .filter(|p| ["TCP", "UDP"].contains(&p.proto) && (p.proto != "TCP" || p.flags & 2 != 0))
        .map(|p| Key {
            ip: p.dst,
            port: p.dport,
            proto: p.proto.into(),
        });
    let Some(key) = key else {
        unsafe {
            nfq_set_verdict(queue, id, 1, 0, std::ptr::null());
        }
        return 0;
    };
    if a.engine.lock().unwrap().settings["whitelisted_ips"]
        .as_array()
        .is_some_and(|ips| {
            ips.iter()
                .any(|ip| ip.as_str() == Some(key.ip.to_string().as_str()))
        })
    {
        unsafe {
            nfq_set_verdict(queue, id, 1, 0, std::ptr::null());
        }
        return 0;
    }
    let mut inner = a.ask.inner.lock().unwrap();
    if let Some(allow) = inner.decided.get(&key) {
        unsafe {
            nfq_set_verdict(queue, id, u32::from(*allow), 0, std::ptr::null());
        }
        return 0;
    }
    if let Some(pending) = inner.pending.get_mut(&key) {
        if pending.ids.len() < 16 {
            pending.ids.push(id);
        } else {
            unsafe {
                nfq_set_verdict(queue, id, 0, 0, std::ptr::null());
            }
        }
        return 0;
    }
    if inner.pending.len() >= 512 {
        inner.overflow += 1;
        unsafe {
            nfq_set_verdict(queue, id, 1, 0, std::ptr::null());
        }
        return 0;
    }
    inner.pending.insert(
        key.clone(),
        Pending {
            ids: vec![id],
            at: Instant::now(),
            decision: None,
        },
    );
    drop(inner);
    let mut e = a.engine.lock().unwrap();
    let timeout = e.settings["ask_timeout"]
        .as_f64()
        .unwrap_or(15.)
        .clamp(3., 120.);
    e.alert(
        "ASK_VERDICT",
        &key.ip.to_string(),
        "warning",
        format!(
            "New outbound flow needs a verdict: {}:{}/{}",
            key.ip, key.port, key.proto
        ),
        json!({"remote_ip":key.ip,"remote_port":key.port,"proto":key.proto,"timeout_s":timeout}),
    );
    0
}
struct Policy;
impl Drop for Policy {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "genyra_snitch_ask"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
fn install(settings: &Value) -> Result<Policy, String> {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "genyra_snitch_ask"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let mut script="add table inet genyra_snitch_ask\nadd chain inet genyra_snitch_ask output { type filter hook output priority -5; policy accept; }\nadd rule inet genyra_snitch_ask output oifname lo return\nadd rule inet genyra_snitch_ask output ct state established,related return\n".to_string();
    for net in [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    ] {
        script.push_str(&format!(
            "add rule inet genyra_snitch_ask output ip daddr {net} return\n"
        ));
    }
    for net in ["::1/128", "fc00::/7", "fe80::/10"] {
        script.push_str(&format!(
            "add rule inet genyra_snitch_ask output ip6 daddr {net} return\n"
        ));
    }
    for ip in settings["whitelisted_ips"]
        .as_array()
        .into_iter()
        .flatten()
        .take(512)
        .filter_map(Value::as_str)
        .filter_map(|s| s.parse::<IpAddr>().ok())
    {
        script.push_str(&format!(
            "add rule inet genyra_snitch_ask output {} daddr {ip} return\n",
            if ip.is_ipv4() { "ip" } else { "ip6" }
        ));
    }
    script.push_str(&format!(
        "add rule inet genyra_snitch_ask output meta l4proto {{ tcp, udp }} queue num 7{}\n",
        if settings["ask_failopen"] == true {
            " bypass"
        } else {
            ""
        }
    ));
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(500)
            .collect());
    }
    Ok(Policy)
}
pub fn run(a: App) {
    if crate::demo::enabled() {
        return;
    }
    while !a.stop.load(Ordering::Relaxed) {
        if a.engine.lock().unwrap().settings["ask_enabled"] != true {
            crate::interruptible_sleep(&a.stop, Duration::from_millis(300));
            continue;
        }
        let result = (|| -> Result<(), String> {
            available()?;
            let queue = Queue::open(&a)?;
            let settings = a.engine.lock().unwrap().settings.clone();
            let _policy = install(&settings)?;
            {
                let mut i = a.ask.inner.lock().unwrap();
                i.running = true;
                i.error = None;
            }
            let fd = unsafe { nfq_fd(queue.handle) };
            let mut buffer = vec![0u8; 131072];
            while !a.stop.load(Ordering::Relaxed) {
                let settings = a.engine.lock().unwrap().settings.clone();
                if settings["ask_enabled"] != true {
                    break;
                }
                let failopen = settings["ask_failopen"] == true;
                unsafe {
                    nfq_set_queue_flags(queue.queue, 1, u32::from(failopen));
                }
                for (id, allow) in a.ask.actions(
                    Duration::from_secs_f64(
                        settings["ask_timeout"]
                            .as_f64()
                            .unwrap_or(15.)
                            .clamp(3., 120.),
                    ),
                    failopen,
                    false,
                ) {
                    queue.verdict(id, allow);
                }
                let mut pollfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut pollfd, 1, 100) } > 0 {
                    let len = unsafe {
                        libc::recv(
                            fd,
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if len > 0 {
                        unsafe {
                            nfq_handle_packet(queue.handle, buffer.as_mut_ptr().cast(), len as i32);
                        }
                    }
                }
            }
            let failopen = a.engine.lock().unwrap().settings["ask_failopen"] == true;
            for (id, allow) in a.ask.actions(Duration::ZERO, failopen, true) {
                queue.verdict(id, allow);
            }
            Ok(())
        })();
        {
            let mut inner = a.ask.inner.lock().unwrap();
            inner.running = false;
            if let Err(error) = result {
                inner.error = Some(error);
            }
        }
        crate::interruptible_sleep(&a.stop, Duration::from_secs(3));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decisions_and_timeouts_are_real_verdict_actions() {
        let ask = Ask::default();
        let key = Key {
            ip: "198.51.100.1".parse().unwrap(),
            port: 443,
            proto: "TCP".into(),
        };
        ask.inner.lock().unwrap().pending.insert(
            key.clone(),
            Pending {
                ids: vec![10, 11],
                at: Instant::now(),
                decision: None,
            },
        );
        assert!(ask.decide(key.ip, 443, "tcp", true));
        assert_eq!(
            ask.actions(Duration::from_secs(15), false, false),
            vec![(10, true), (11, true)]
        );
        ask.inner.lock().unwrap().pending.insert(
            key,
            Pending {
                ids: vec![12],
                at: Instant::now() - Duration::from_secs(16),
                decision: None,
            },
        );
        assert_eq!(
            ask.actions(Duration::from_secs(15), false, false),
            vec![(12, false)]
        );
    }
}
