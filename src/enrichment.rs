//! Bounded DNS PTR lookup and explicit-consent offline GeoIP updates.
use crate::{
    web::{bad, ApiResult},
    App,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering,
    time::Duration,
};
pub fn ptr_question(ip: IpAddr, id: u16) -> Vec<u8> {
    let name = match ip {
        IpAddr::V4(v) => {
            v.octets()
                .iter()
                .rev()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".")
                + ".in-addr.arpa"
        }
        IpAddr::V6(v) => {
            let mut labels = Vec::new();
            for b in v.octets().iter().rev() {
                labels.push(format!("{:x}", b & 15));
                labels.push(format!("{:x}", b >> 4));
            }
            labels.join(".") + ".ip6.arpa"
        }
    };
    let mut b = Vec::new();
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.extend_from_slice(&[0, 0, 12, 0, 1]);
    b
}
fn u16at(b: &[u8], n: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(n..n + 2)?.try_into().ok()?))
}
fn ptr_answer(b: &[u8], id: u16) -> Option<String> {
    if u16at(b, 0)? != id || u16at(b, 2)? & 0xf80f != 0x8000 {
        return None;
    }
    let q = u16at(b, 4)?;
    let a = u16at(b, 6)?;
    if q > 8 || a > 128 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..q {
        crate::packet::dns_name(b, &mut pos)?;
        pos += 4;
    }
    for _ in 0..a {
        crate::packet::dns_name(b, &mut pos)?;
        let kind = u16at(b, pos)?;
        let class = u16at(b, pos + 2)?;
        let len = u16at(b, pos + 8)? as usize;
        pos += 10;
        if pos + len > b.len() {
            return None;
        }
        if kind == 12 && class == 1 {
            let mut cursor = pos;
            return crate::packet::dns_name(b, &mut cursor);
        }
        pos += len;
    }
    None
}
fn resolvers() -> Vec<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            if parts.next()? != "nameserver" {
                return None;
            }
            let ip = parts.next()?.parse::<IpAddr>().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .take(3)
        .collect()
}
async fn reverse(ip: IpAddr, servers: Vec<SocketAddr>) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let uuid = uuid::Uuid::new_v4();
    let id = u16::from_ne_bytes(uuid.as_bytes()[..2].try_into().ok()?);
    let query = ptr_question(ip, id);
    for server in servers {
        let attempt = async {
            let socket = tokio::net::UdpSocket::bind(if server.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })
            .await
            .ok()?;
            socket.connect(server).await.ok()?;
            socket.send(&query).await.ok()?;
            let mut response = vec![0u8; 4096];
            let len = socket.recv(&mut response).await.ok()?;
            response.truncate(len);
            if u16at(&response, 2)? & 0x0200 != 0 {
                let mut socket = tokio::net::TcpStream::connect(server).await.ok()?;
                socket
                    .write_all(&(query.len() as u16).to_be_bytes())
                    .await
                    .ok()?;
                socket.write_all(&query).await.ok()?;
                let len = socket.read_u16().await.ok()? as usize;
                if len > 4096 {
                    return None;
                }
                response.resize(len, 0);
                socket.read_exact(&mut response).await.ok()?;
            }
            ptr_answer(&response, id)
        };
        if let Ok(Some(name)) = tokio::time::timeout(Duration::from_secs(2), attempt).await {
            return Some(name);
        }
    }
    None
}
pub async fn run(a: App) {
    let servers = resolvers();
    let mut tasks = tokio::task::JoinSet::new();
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    while !a.stop.load(Ordering::Relaxed) {
        interval.tick().await;
        while tasks.len() < 4 {
            let next = a.engine.lock().unwrap().ptr_queue.pop_front();
            let Some((ip, port, proto)) = next else {
                break;
            };
            let servers = servers.clone();
            let a = a.clone();
            tasks.spawn(async move {
                let hostname = reverse(ip, servers).await;
                a.engine
                    .lock()
                    .unwrap()
                    .learn_ptr(ip, port, proto, hostname);
            });
        }
        while tasks.try_join_next().is_some() {}
    }
    tasks.abort_all();
}
pub fn download_geo(a: &App, body: &Value) -> ApiResult {
    if body["consent"] != true {
        return Err(bad(
            "Explicit consent is required to download GeoIP databases",
        ));
    }
    a.runtime.block_on(async {
        let geo = a.data.join("geo");
        std::fs::create_dir_all(&geo).map_err(|e| bad(e.to_string()))?;
        let date = chrono::Utc::now().format("%Y-%m").to_string();
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| bad("GeoIP download client unavailable"))?;
        let mut installed = Vec::new();
        for kind in ["city", "asn"] {
            let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{date}.mmdb.gz");
            let mut response = http
                .get(url)
                .timeout(Duration::from_secs(120))
                .send()
                .await
                .map_err(|_| bad("GeoIP download failed"))?
                .error_for_status()
                .map_err(|_| bad("GeoIP database is unavailable"))?;
            let compressed = geo.join(format!(".dbip-{kind}-{}.gz", uuid::Uuid::new_v4()));
            let staged = geo.join(format!(".dbip-{kind}-{}.mmdb", uuid::Uuid::new_v4()));
            let result = async {
                let mut file =
                    std::fs::File::create(&compressed).map_err(|e| bad(e.to_string()))?;
                let mut total = 0;
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| bad("GeoIP transfer failed"))?
                {
                    total += chunk.len();
                    if total > 150 * 1024 * 1024 {
                        return Err(bad("GeoIP archive exceeds 150 MiB"));
                    }
                    file.write_all(&chunk).map_err(|e| bad(e.to_string()))?;
                }
                file.sync_all().map_err(|e| bad(e.to_string()))?;
                drop(file);
                let decoder = flate2::read::GzDecoder::new(
                    std::fs::File::open(&compressed).map_err(|e| bad(e.to_string()))?,
                );
                let mut output = std::fs::File::create(&staged).map_err(|e| bad(e.to_string()))?;
                let count = std::io::copy(&mut decoder.take(512 * 1024 * 1024 + 1), &mut output)
                    .map_err(|_| bad("Invalid compressed GeoIP archive"))?;
                if count > 512 * 1024 * 1024 {
                    return Err(bad("GeoIP database exceeds 512 MiB"));
                }
                output.sync_all().map_err(|e| bad(e.to_string()))?;
                drop(output);
                let _reader =
                    crate::geodb::open(&staged).map_err(|_| bad("Invalid GeoIP database"))?;
                let name = format!("dbip-{kind}-lite.mmdb");
                std::fs::rename(&staged, geo.join(&name)).map_err(|e| bad(e.to_string()))?;
                Ok(name)
            }
            .await;
            let _ = std::fs::remove_file(&compressed);
            let _ = std::fs::remove_file(&staged);
            installed.push(result?);
            crate::paths::restore_owner(&a.data);
            a.engine.lock().unwrap().reload_geo(&a.data);
        }
        a.engine.lock().unwrap().reload_geo(&a.data);
        Ok(json!({"ok":true,"downloaded":installed}))
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverse_question_matches_ipv4_and_ipv6_dns_names() {
        let a = ptr_question("1.2.3.4".parse().unwrap(), 0x1234);
        let mut p = 12;
        assert_eq!(
            crate::packet::dns_name(&a, &mut p).unwrap(),
            "4.3.2.1.in-addr.arpa"
        );
        let a = ptr_question("::1".parse().unwrap(), 1);
        let mut p = 12;
        let n = crate::packet::dns_name(&a, &mut p).unwrap();
        assert!(n.starts_with("1.0.0.0."));
        assert!(n.ends_with("ip6.arpa"));
    }
    #[test]
    fn ptr_response_checks_transaction_id_and_compression() {
        let mut b = ptr_question("8.8.8.8".parse().unwrap(), 123);
        b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(
            b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x0c\x03dns\x06google\x00",
        );
        assert_eq!(ptr_answer(&b, 123), Some("dns.google".into()));
        assert!(ptr_answer(&b, 124).is_none());
    }
}
