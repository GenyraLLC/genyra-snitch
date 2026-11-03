//! Linux LAN and media observation without Python or per-packet syscalls.
use crate::{state::Engine, App};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::BufRead,
    net::{IpAddr, Ipv4Addr},
    sync::{atomic::Ordering, OnceLock},
    time::{Duration, Instant},
};

fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
pub fn vendor(mac: &str) -> (Option<String>, Option<String>) {
    static BUNDLED: OnceLock<Value> = OnceLock::new();
    static IEEE: OnceLock<HashMap<String, String>> = OnceLock::new();
    let compact = mac.replace(':', "").to_uppercase();
    let key = compact.get(..6).unwrap_or("");
    let bundled = BUNDLED
        .get_or_init(|| serde_json::from_str(include_str!("../resources/oui.json")).unwrap());
    if let Some(v) = bundled["OUI_TABLE"].get(key) {
        return (
            v[0].as_str().map(str::to_string),
            v[1].as_str().map(str::to_string),
        );
    }
    let ieee = IEEE.get_or_init(|| {
        let gz = flate2::read::GzDecoder::new(
            include_bytes!("../resources/oui_table.txt.gz").as_slice(),
        );
        std::io::BufReader::new(gz)
            .lines()
            .take(200000)
            .map_while(Result::ok)
            .filter_map(|line| line.split_once('|').map(|(k, v)| (k.into(), v.into())))
            .collect()
    });
    (ieee.get(key).cloned(), None)
}
pub fn learn_frame(e: &mut Engine, frame: &[u8], link: i32) -> bool {
    if link != 1 || frame.len() < 14 {
        return false;
    }
    let kind = u16::from_be_bytes([frame[12], frame[13]]);
    if kind == 0x806 {
        if frame.len() < 42 || frame[14..20] != [0, 1, 8, 0, 6, 4] {
            return true;
        }
        let ip = IpAddr::V4(Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]));
        if crate::state::private(ip) && !e.local_ips.contains(&ip) && !ip.is_unspecified() {
            e.learn_device(ip, Some(mac(&frame[22..28])), None);
        }
        return true;
    }
    let Some(p) = crate::packet::parse(frame, link) else {
        return false;
    };
    if !crate::state::private(p.src) || p.src.is_unspecified() {
        return false;
    }
    let sender_mac = mac(&frame[6..12]);
    if !e.local_ips.contains(&p.src) {
        e.learn_device(p.src, Some(sender_mac.clone()), None);
    }
    if p.proto == "UDP" && [53, 5353, 5355].contains(&p.sport) {
        for (ip, name, _) in crate::packet::dns(p.payload) {
            if crate::state::private(ip) && !e.local_ips.contains(&ip) {
                e.learn_device(ip, None, Some(name.trim_end_matches(".local").to_string()));
            }
        }
    }
    if p.proto == "UDP" && p.sport == 137 && p.payload.len() >= 45 {
        let bytes = &p.payload[13..45];
        let mut decoded = Vec::new();
        if p.payload[12] == 32 && bytes.iter().all(|b| (b'A'..=b'P').contains(b)) {
            for pair in bytes.as_chunks::<2>().0 {
                decoded.push((pair[0] - b'A') * 16 + pair[1] - b'A');
            }
            let name = String::from_utf8_lossy(&decoded[..15]).trim().to_string();
            if !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_ ".contains(&b))
            {
                e.learn_device(p.src, Some(sender_mac), Some(name));
            }
        }
    }
    if p.proto == "UDP" && [67, 68].contains(&p.dport) {
        if let Some((ip, hostname, mac)) = dhcp(p.payload, p.src) {
            if !e.local_ips.contains(&ip) {
                e.learn_device(ip, Some(mac), Some(hostname));
            }
        }
    }
    false
}
fn dhcp(b: &[u8], src: IpAddr) -> Option<(IpAddr, String, String)> {
    if b.len() < 240 || b[236..240] != [99, 130, 83, 99] || b[1] != 1 || b[2] != 6 {
        return None;
    }
    let mut hostname = None;
    let mut requested = None;
    let mut p = 240;
    for _ in 0..256 {
        let kind = *b.get(p)?;
        p += 1;
        if kind == 255 {
            break;
        }
        if kind == 0 {
            continue;
        }
        let len = *b.get(p)? as usize;
        p += 1;
        let value = b.get(p..p + len)?;
        p += len;
        if kind == 12 && len <= 253 {
            hostname = std::str::from_utf8(value)
                .ok()
                .filter(|s| {
                    s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b".-_ ".contains(&c))
                })
                .map(str::to_string);
        }
        if kind == 50 && len == 4 {
            requested = Some(IpAddr::V4(Ipv4Addr::new(
                value[0], value[1], value[2], value[3],
            )));
        }
    }
    let ip = requested.or_else(|| {
        if !src.is_unspecified() {
            Some(src)
        } else {
            None
        }
    })?;
    Some((ip, hostname?, mac(&b[28..34])))
}
#[cfg(not(target_os = "linux"))]
fn media() -> Value {
    json!({"mic":[],"camera":[],"supported":false,"reason":"Native media access provider has not been ported"})
}
#[cfg(target_os = "linux")]
fn media() -> Value {
    let start = Instant::now();
    let mut mic = BTreeSet::new();
    let mut camera = BTreeSet::new();
    let mut incomplete = false;
    let mut denied = 0;
    if let Ok(entries) = fs::read_dir("/proc") {
        'outer: for entry in entries.flatten() {
            if start.elapsed() > Duration::from_millis(500) {
                incomplete = true;
                break;
            }
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                denied += 1;
                continue;
            };
            let mut sound = false;
            let mut video = false;
            for (index, fd) in fds.flatten().enumerate() {
                if index % 256 == 0 && start.elapsed() > Duration::from_millis(500) {
                    incomplete = true;
                    break 'outer;
                }
                let Ok(path) = fs::read_link(fd.path()) else {
                    continue;
                };
                let path = path.to_string_lossy();
                sound |= path.starts_with("/dev/snd/") || path.starts_with("/dev/audio");
                video |= path.starts_with("/dev/video");
            }
            if sound || video {
                let name = fs::read_to_string(entry.path().join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if !name.is_empty() {
                    if sound {
                        mic.insert(name.clone());
                    }
                    if video {
                        camera.insert(name);
                    }
                }
            }
        }
    }
    json!({"mic":mic,"camera":camera,"supported":true,"scan_incomplete":incomplete,"access_denied":denied})
}
fn kernel_neighbors(e: &mut Engine) {
    if let Ok(arp) = fs::read_to_string("/proc/net/arp") {
        for line in arp.lines().skip(1).take(4096) {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 6 || f[3] == "00:00:00:00:00:00" {
                continue;
            }
            if let Ok(ip) = f[0].parse::<IpAddr>() {
                if !e.local_ips.contains(&ip) {
                    e.learn_device(ip, Some(f[3].into()), None);
                }
            }
        }
    }
}
fn arp_probe(iface: &str) -> Result<usize, String> {
    let device = pcap::Device::list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or("Interface missing")?;
    let Some(address) = device
        .addresses
        .iter()
        .find(|a| a.addr.is_ipv4() && a.netmask.is_some())
    else {
        return Ok(0);
    };
    let (IpAddr::V4(ip), Some(IpAddr::V4(mask))) = (address.addr, address.netmask) else {
        return Ok(0);
    };
    let mac_text =
        fs::read_to_string(format!("/sys/class/net/{iface}/address")).map_err(|e| e.to_string())?;
    let parts: Option<Vec<u8>> = mac_text
        .trim()
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    let Some(mac) = parts.filter(|v| v.len() == 6) else {
        return Err("Invalid interface MAC".into());
    };
    let base = u32::from(ip) & u32::from(mask);
    let hosts = (!u32::from(mask)).saturating_sub(1);
    if hosts > 1024 {
        return Ok(0);
    }
    let mut cap = pcap::Capture::from_device(iface)
        .map_err(|e| e.to_string())?
        .timeout(1)
        .snaplen(64)
        .open()
        .map_err(|e| e.to_string())?;
    let mut sent = 0;
    for host in 1..=hosts {
        let target = Ipv4Addr::from(base + host);
        if target == ip {
            continue;
        }
        let mut packet = vec![255; 6];
        packet.extend_from_slice(&mac);
        packet.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
        packet.extend_from_slice(&mac);
        packet.extend_from_slice(&ip.octets());
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(&target.octets());
        cap.sendpacket(packet.as_slice())
            .map_err(|e| e.to_string())?;
        sent += 1;
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(sent)
}
pub fn run(a: App) {
    if crate::demo::enabled() {
        return;
    }
    let mut arp_at = Instant::now() - Duration::from_secs(30);
    while !a.stop.load(Ordering::Relaxed) {
        let actions = {
            let mut e = a.engine.lock().unwrap();
            let n = e.firewall_actions.len().min(16);
            e.firewall_actions.drain(..n).collect::<Vec<_>>()
        };
        for action in actions {
            let _guard = a.mutations.lock().unwrap();
            match crate::security::add_firewall_rule(&a, &action) {
                Ok(result) if result["rule"]["applied"] == true => {}
                other => {
                    let ip = action["value"].as_str().unwrap_or("");
                    a.engine.lock().unwrap().alert(
                        "FIREWALL_ERROR",
                        ip,
                        "warning",
                        "Firewall block could not be applied".into(),
                        json!({"ip":ip,"result":format!("{other:?}")}),
                    );
                }
            }
        }
        let observed = media();
        let (changed, iface, active) = {
            let mut e = a.engine.lock().unwrap();
            let changed = e.media != observed;
            e.media = observed.clone();
            if e.capturing {
                kernel_neighbors(&mut e);
            }
            (changed, e.iface.clone(), e.capturing)
        };
        if changed {
            let mut message = observed;
            message["type"] = json!("media");
            let _ = a.events.send(message);
        }
        if active && arp_at.elapsed() >= Duration::from_secs(30) {
            if let Err(error) = arp_probe(&iface) {
                eprintln!("LAN probe unavailable: {error}");
            }
            arp_at = Instant::now();
        }
        crate::interruptible_sleep(&a.stop, Duration::from_secs(3));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    #[test]
    fn learns_arp_identity() {
        let mut e = Engine::new(
            std::path::Path::new("/nonexistent"),
            "test".into(),
            json!({}),
            vec![],
            HashSet::new(),
        );
        let mut frame = vec![0; 42];
        frame[12..20].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4]);
        frame[22..28].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        frame[28..32].copy_from_slice(&[192, 168, 1, 20]);
        assert!(learn_frame(&mut e, &frame, 1));
        assert_eq!(e.nodes["192.168.1.20"].extra["mac"], "02:03:04:05:06:07");
    }
    #[test]
    fn dhcp_name_and_requested_address() {
        let mut b = vec![0; 240];
        b[1] = 1;
        b[2] = 6;
        b[28..34].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend_from_slice(&[12, 4, b'h', b'o', b's', b't', 50, 4, 192, 168, 1, 4, 255]);
        let (ip, name, _) = dhcp(&b, "0.0.0.0".parse().unwrap()).unwrap();
        assert_eq!(name, "host");
        assert_eq!(ip.to_string(), "192.168.1.4");
    }
}
