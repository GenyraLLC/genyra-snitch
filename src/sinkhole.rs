use crate::App;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
#[derive(Default)]
pub struct Sinkhole {
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    listening: HashMap<String, bool>,
    errors: HashMap<String, String>,
    hits: VecDeque<Value>,
}
impl Sinkhole {
    pub fn status(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({"listening":{"80":s.listening.get("v4:80").copied().unwrap_or(false)||s.listening.get("v6:80").copied().unwrap_or(false),"443":s.listening.get("v4:443").copied().unwrap_or(false)||s.listening.get("v6:443").copied().unwrap_or(false)},"listeners":s.listening,"hits":s.hits,"errors":s.errors})
    }
}
fn original_destination(
    socket: &tokio::net::TcpStream,
    ipv6: bool,
) -> Option<std::net::SocketAddr> {
    use std::os::fd::AsRawFd;
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            if ipv6 { libc::SOL_IPV6 } else { libc::SOL_IP },
            80,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    if addr.ss_family as i32 == libc::AF_INET
        && len as usize >= std::mem::size_of::<libc::sockaddr_in>()
    {
        let v = unsafe {
            std::ptr::read((&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
        };
        Some(std::net::SocketAddr::new(
            std::net::Ipv4Addr::from(v.sin_addr.s_addr.to_ne_bytes()).into(),
            u16::from_be(v.sin_port),
        ))
    } else if addr.ss_family as i32 == libc::AF_INET6
        && len as usize >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        let v = unsafe {
            std::ptr::read((&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
        };
        Some(std::net::SocketAddr::new(
            std::net::Ipv6Addr::from(v.sin6_addr.s6_addr).into(),
            u16::from_be(v.sin6_port),
        ))
    } else {
        None
    }
}
async fn connection(
    a: App,
    mut socket: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    port: u16,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let destination = original_destination(&socket, peer.is_ipv6());
    let owner = destination.and_then(|remote| {
        a.owners.read().unwrap().lookup(&crate::process::Key {
            proto: "TCP",
            local: peer.ip(),
            port: peer.port(),
            remote: remote.ip(),
            rport: remote.port(),
        })
    });
    let mut bytes = Vec::with_capacity(4096);
    let mut block = [0u8; 1024];
    let read = async {
        while bytes.len() < 4096 {
            let n = socket.read(&mut block).await.ok()?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&block[..n]);
            if port == 80 && bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if port == 443 && bytes.len() >= 5 {
                let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
                if bytes.len() >= 5 + len {
                    break;
                }
            }
        }
        Some(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), read).await;
    let host = if port == 80 {
        String::from_utf8_lossy(&bytes).lines().find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim().chars().take(253).collect::<String>())
        })
    } else {
        crate::packet::sni(&bytes)
    };
    let hit = json!({"kind":if port==80{"http"}else{"tls"},"host":host,"src_ip":peer.ip(),"src_port":peer.port(),"ts":chrono::Utc::now().timestamp_millis()as f64/1000.,"process":owner.as_ref().map(|o|&o.name),"pid":owner.as_ref().map(|o|o.pid),"original_dst":destination});
    {
        let mut state = a.sinkhole.state.lock().unwrap();
        if state.hits.len() >= 200 {
            state.hits.pop_front();
        }
        state.hits.push_back(hit.clone());
    }
    a.engine.lock().unwrap().alert(
        "SINKHOLE_HIT",
        "",
        "warning",
        format!(
            "Sinkholed connection observed: {}",
            host.as_deref().unwrap_or("unknown host")
        ),
        hit,
    );
    if port == 80 {
        let _ = socket
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await;
    }
    let _ = socket.shutdown().await;
}
async fn listen(a: App, port: u16, ipv6: bool) {
    let key = format!("{}:{port}", if ipv6 { "v6" } else { "v4" });
    let ip: std::net::IpAddr = if ipv6 {
        std::net::Ipv6Addr::LOCALHOST.into()
    } else {
        std::net::Ipv4Addr::LOCALHOST.into()
    };
    let socket = match tokio::net::TcpListener::bind(std::net::SocketAddr::new(ip, port)).await {
        Ok(s) => s,
        Err(e) => {
            a.sinkhole
                .state
                .lock()
                .unwrap()
                .errors
                .insert(key, e.to_string());
            return;
        }
    };
    {
        let mut s = a.sinkhole.state.lock().unwrap();
        s.listening.insert(key.clone(), true);
        s.errors.remove(&key);
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {accepted=socket.accept()=>{if let Ok((socket,peer))=accepted{if let Ok(permit)=slots.clone().try_acquire_owned(){let a=a.clone();tasks.spawn(async move{let _permit=permit;let _=tokio::time::timeout(Duration::from_secs(3),connection(a,socket,peer,port)).await;});}}},_=tokio::time::sleep(Duration::from_millis(200))=>{if a.stop.load(Ordering::Relaxed){break;}}};
        while tasks.try_join_next().is_some() {}
    }
}
pub async fn run(a: App) {
    if crate::demo::enabled() {
        return;
    }
    let mut listeners = Vec::new();
    let mut enabled = false;
    while !a.stop.load(Ordering::Relaxed) {
        let want = {
            let e = a.engine.lock().unwrap();
            e.settings["firewall_rules"].as_array().is_some_and(|r| {
                r.iter()
                    .any(|r| r["enabled"] != false && r["action"] == "sinkhole")
            })
        };
        if want && !enabled {
            for port in [80, 443] {
                for ipv6 in [false, true] {
                    let a = a.clone();
                    listeners.push(tokio::spawn(async move { listen(a, port, ipv6).await }));
                }
            }
            enabled = true;
        }
        if !want && enabled {
            for task in listeners.drain(..) {
                task.abort();
            }
            let mut s = a.sinkhole.state.lock().unwrap();
            s.listening.clear();
            enabled = false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    for task in listeners {
        task.abort();
    }
    a.sinkhole.state.lock().unwrap().listening.clear();
}
