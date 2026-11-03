use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Default)]
pub struct Owner {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub ppid: Option<u32>,
    pub parent_name: Option<String>,
}
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct Key {
    pub proto: &'static str,
    pub local: IpAddr,
    pub port: u16,
    pub remote: IpAddr,
    pub rport: u16,
}
#[derive(Default, Clone)]
pub struct Table {
    sockets: HashMap<Key, Owner>,
    cached: HashMap<u64, Owner>,
    pub incomplete: bool,
}

fn endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(addr, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut b = [0; 16];
            for (i, chunk) in b.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(
                    &u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16)
                        .ok()?
                        .to_ne_bytes(),
                );
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    // Linux IPv6 dual-stack sockets may own IPv4 packets.
    let ip = match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    Some((ip, port))
}

impl Table {
    pub fn refresh(&mut self) {
        let start = Instant::now();
        let mut rows = Vec::new();
        self.incomplete = false;
        for (name, proto) in [
            ("tcp", "TCP"),
            ("tcp6", "TCP"),
            ("udp", "UDP"),
            ("udp6", "UDP"),
        ] {
            let Ok(text) = fs::read_to_string(format!("/proc/net/{name}")) else {
                self.incomplete = true;
                continue;
            };
            for line in text.lines().skip(1).take(100_000) {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() < 10 {
                    continue;
                }
                let (Some((local, port)), Some((remote, rport)), Ok(inode)) =
                    (endpoint(f[1]), endpoint(f[2]), f[9].parse::<u64>())
                else {
                    continue;
                };
                if inode != 0 {
                    rows.push((
                        Key {
                            proto,
                            local,
                            port,
                            remote,
                            rport,
                        },
                        inode,
                    ));
                }
            }
        }
        let live: HashSet<_> = rows.iter().map(|(_, i)| *i).collect();
        self.cached.retain(|inode, owner| {
            live.contains(inode)
                && fs::read_to_string(format!("/proc/{}/comm", owner.pid))
                    .is_ok_and(|n| n.trim() == owner.name)
        });
        let mut missing: HashSet<_> = live
            .difference(&self.cached.keys().copied().collect())
            .copied()
            .collect();
        let Ok(procs) = fs::read_dir("/proc") else {
            self.incomplete = true;
            return;
        };
        'outer: for entry in procs.flatten() {
            if missing.is_empty() {
                break;
            }
            if start.elapsed() > Duration::from_millis(350) {
                self.incomplete = true;
                break;
            }
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            let mut owner = None;
            for (index, fd) in fds.flatten().enumerate() {
                if index % 256 == 0 && start.elapsed() > Duration::from_millis(350) {
                    self.incomplete = true;
                    break 'outer;
                }
                let Ok(target) = fs::read_link(fd.path()) else {
                    continue;
                };
                let target = target.to_string_lossy();
                let Some(inode) = target
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<u64>().ok())
                else {
                    continue;
                };
                if missing.remove(&inode) {
                    if owner.is_none() {
                        owner = fs::read_to_string(entry.path().join("comm"))
                            .ok()
                            .map(|s| Owner {
                                pid,
                                name: s.trim().to_string(),
                                cmdline: fs::read(entry.path().join("cmdline"))
                                    .ok()
                                    .map(|b| {
                                        String::from_utf8_lossy(&b)
                                            .replace('\0', " ")
                                            .chars()
                                            .take(4096)
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                ppid: fs::read_to_string(entry.path().join("stat")).ok().and_then(
                                    |s| {
                                        s.rsplit_once(')')
                                            .and_then(|(_, s)| s.split_whitespace().nth(1))
                                            .and_then(|s| s.parse().ok())
                                    },
                                ),
                                parent_name: None,
                            });
                        if let Some(owner) = &mut owner {
                            owner.parent_name = owner
                                .ppid
                                .and_then(|pid| {
                                    fs::read_to_string(format!("/proc/{pid}/comm")).ok()
                                })
                                .map(|s| s.trim().to_string());
                        }
                    }
                    if let Some(owner) = &owner {
                        self.cached.insert(inode, owner.clone());
                    }
                }
            }
        }
        self.incomplete |= !missing.is_empty();
        self.sockets = rows
            .into_iter()
            .filter_map(|(k, i)| self.cached.get(&i).cloned().map(|o| (k, o)))
            .collect();
    }
    pub fn lookup(&self, key: &Key) -> Option<Owner> {
        if let Some(o) = self.sockets.get(key) {
            return Some(o.clone());
        }
        let unspecified = if key.local.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        for local in [key.local, unspecified] {
            let k = Key {
                local,
                remote: unspecified,
                rport: 0,
                ..key.clone()
            };
            if let Some(o) = self.sockets.get(&k) {
                return Some(o.clone());
            }
        }
        // Do not guess between unrelated sockets sharing a local port.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proc_endianness() {
        assert_eq!(
            endpoint("0100007F:01BB"),
            Some(("127.0.0.1".parse().unwrap(), 443))
        );
        assert_eq!(
            endpoint("00000000000000000000000001000000:0016"),
            Some(("::1".parse().unwrap(), 22))
        );
        assert!(endpoint("x:bad").is_none());
    }
    #[test]
    fn exact_socket_attribution() {
        let mut t = Table::default();
        let k = Key {
            proto: "TCP",
            local: "10.0.0.1".parse().unwrap(),
            port: 1234,
            remote: "8.8.8.8".parse().unwrap(),
            rport: 443,
        };
        t.sockets.insert(
            k.clone(),
            Owner {
                pid: 42,
                name: "browser".into(),
                ..Owner::default()
            },
        );
        assert_eq!(t.lookup(&k).unwrap().pid, 42);
        assert!(t
            .lookup(&Key {
                remote: "1.1.1.1".parse().unwrap(),
                ..k
            })
            .is_none());
    }
}
