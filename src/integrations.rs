//! Explicitly configured outbound integrations; bounded concurrency and bodies.
use crate::App;
use serde_json::{json, Value};
use std::{sync::atomic::Ordering, time::Duration};

async fn json_response(mut response: reqwest::Response) -> Result<Value, String> {
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "Response read failed")? {
        if body.len() + chunk.len() > 1024 * 1024 {
            return Err("Response exceeds 1 MiB".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "Invalid JSON response".into())
}
fn peers(a: &App) -> Vec<String> {
    let settings = a.engine.lock().unwrap().settings.clone();
    let mut out = Vec::new();
    for p in settings["gossip_peers"]
        .as_array()
        .into_iter()
        .flatten()
        .take(32)
        .filter_map(Value::as_str)
    {
        let p = p.trim().trim_end_matches('/');
        let p = if p.starts_with("http://") || p.starts_with("https://") {
            p.into()
        } else {
            format!("http://{p}")
        };
        if let Ok(url) = reqwest::Url::parse(&p) {
            if ["http", "https"].contains(&url.scheme())
                && url.username().is_empty()
                && url.password().is_none()
                && !out.contains(&p)
            {
                out.push(p);
            }
        }
    }
    out
}
pub fn status(a: &App) -> Value {
    json!({"peers":peers(a),"last":a.peer_state.lock().unwrap().clone()})
}
pub async fn sync(a: App, pack: Value) -> Value {
    let peers = peers(&a);
    if peers.is_empty() {
        return json!({"ok":false,"error":"no peers configured"});
    }
    let mut tasks = tokio::task::JoinSet::new();
    for peer in peers {
        let a = a.clone();
        let pack = pack.clone();
        tasks.spawn(async move{let result=a.http.post(format!("{peer}/security/iocpack/import")).header("X-Snitch-Token",a.token.as_str()).json(&json!({"pack":pack})).send().await;let state=match result{Ok(r)=>json!({"ok":r.status().is_success(),"code":r.status().as_u16(),"ts":chrono::Utc::now().timestamp()}),Err(_)=>json!({"ok":false,"error":"Peer request failed","ts":chrono::Utc::now().timestamp()})};(peer,state)});
    }
    let mut results = json!({});
    while let Some(Ok((peer, state))) = tasks.join_next().await {
        results[peer] = state;
    }
    *a.peer_state.lock().unwrap() = results.clone();
    let ok = results
        .as_object()
        .is_some_and(|m| m.values().all(|v| v["ok"] == true));
    json!({"ok":ok,"results":results})
}
pub async fn fleet(a: App) -> Value {
    let peers = peers(&a);
    let mut tasks = tokio::task::JoinSet::new();
    for peer in &peers {
        let peer = peer.clone();
        let a = a.clone();
        tasks.spawn(async move {
            let result = match a
                .http
                .get(format!("{peer}/security/audit"))
                .header("X-Snitch-Token", a.token.as_str())
                .send()
                .await
            {
                Ok(r) => json_response(r).await,
                Err(_) => Err("Peer request failed".into()),
            };
            match result {
                Ok(mut v) => {
                    v["peer"] = json!(peer);
                    v["reachable"] = json!(true);
                    v
                }
                Err(error) => json!({"peer":peer,"reachable":false,"error":error}),
            }
        });
    }
    let mut agents = Vec::new();
    while let Some(Ok(v)) = tasks.join_next().await {
        agents.push(v);
    }
    let scores: Vec<_> = agents
        .iter()
        .filter(|v| v["reachable"] == true)
        .filter_map(|v| v["score"].as_f64())
        .collect();
    json!({"agent_count":peers.len(),"reachable":scores.len(),"worst_score":scores.iter().copied().reduce(f64::min),"mean_score":if scores.is_empty(){None}else{Some(scores.iter().sum::<f64>()/scores.len()as f64)},"agents":agents})
}
fn escaped(value: &str, header: bool) -> String {
    let s = value.replace('\\', "\\\\");
    if header {
        s.replace('|', "\\|")
    } else {
        s.replace('=', "\\=").replace('\n', "\\n").replace('\r', "")
    }
}
pub fn cef(alert: &Value) -> String {
    let severity = if alert["severity"] == "critical" {
        8
    } else if alert["severity"] == "warning" {
        5
    } else {
        3
    };
    let mut extensions = Vec::new();
    for (key, value) in [
        ("rt", alert["timestamp"].as_str()),
        (
            "dst",
            alert["details"]["ip"]
                .as_str()
                .or_else(|| alert["node_id"].as_str()),
        ),
        ("sproc", alert["details"]["process"].as_str()),
        ("cs1", alert["type"].as_str()),
    ] {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            extensions.push(format!("{key}={}", escaped(v, false)));
        }
    }
    format!(
        "CEF:0|Genyra LLC|Genyra Snitch|{}|{}|{}|{severity}|{}",
        env!("CARGO_PKG_VERSION"),
        escaped(alert["type"].as_str().unwrap_or("?"), true),
        escaped(alert["message"].as_str().unwrap_or(""), true),
        extensions.join(" ")
    )
}
async fn notify(a: &App, settings: &Value, alert: &Value) -> Result<(), String> {
    let message = format!(
        "[{}] {} — {}",
        alert["severity"].as_str().unwrap_or("info"),
        alert["type"].as_str().unwrap_or("?"),
        alert["message"].as_str().unwrap_or("")
    )
    .chars()
    .take(3000)
    .collect::<String>();
    if settings["webhook_enabled"] == true {
        if let Some(url) = settings["webhook_url"].as_str().filter(|s| !s.is_empty()) {
            let parsed = reqwest::Url::parse(url).map_err(|_| "Invalid webhook URL")?;
            if !["https", "http"].contains(&parsed.scheme()) {
                return Err("Webhook requires HTTP(S)".into());
            }
            let host = parsed.host_str().unwrap_or("");
            let payload = if host == "api.telegram.org" {
                json!({"chat_id":settings["telegram_chat_id"],"text":message})
            } else if host == "hooks.slack.com" {
                json!({"text":message})
            } else if host.ends_with("discord.com") || host.ends_with("discordapp.com") {
                json!({"content":message})
            } else {
                json!({"source":"snitch","alert":alert})
            };
            let response = a
                .http
                .post(parsed)
                .json(&payload)
                .send()
                .await
                .map_err(|_| "Webhook request failed")?;
            if !response.status().is_success() {
                return Err(format!(
                    "Webhook returned HTTP {}",
                    response.status().as_u16()
                ));
            }
        }
    }
    if let Some(addr) = settings["syslog_addr"].as_str().filter(|s| !s.is_empty()) {
        let body = if settings["syslog_format"] == "cef" {
            cef(alert)
        } else {
            let priority = 19 * 8
                + if alert["severity"] == "critical" {
                    2
                } else {
                    4
                };
            format!(
                "<{priority}>{} {} snitch: {message}",
                chrono::Local::now().format("%b %e %T"),
                std::fs::read_to_string("/etc/hostname")
                    .unwrap_or_else(|_| "localhost".into())
                    .trim()
            )
        };
        if let Some(addr) = addr.strip_prefix("tcp://") {
            use tokio::io::AsyncWriteExt;
            let mut socket = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|_| "Syslog connection failed")?;
            socket
                .write_all(format!("{body}\n").as_bytes())
                .await
                .map_err(|_| "Syslog write failed")?;
        } else {
            let addr = addr.trim_start_matches("udp://");
            let dest = tokio::net::lookup_host(addr)
                .await
                .map_err(|_| "Syslog address lookup failed")?
                .next()
                .ok_or("Syslog address is empty")?;
            let socket = tokio::net::UdpSocket::bind(if dest.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })
            .await
            .map_err(|_| "Syslog socket unavailable")?;
            socket
                .send_to(body.as_bytes(), dest)
                .await
                .map_err(|_| "Syslog send failed")?;
        }
    }
    Ok(())
}
pub async fn run(a: App) {
    if crate::demo::enabled() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let mut sync_at = tokio::time::Instant::now();
    while !a.stop.load(Ordering::Relaxed) {
        interval.tick().await;
        let (alerts, settings) = {
            let mut e = a.engine.lock().unwrap();
            let n = e.notifications.len().min(4);
            (
                e.notifications.drain(..n).collect::<Vec<_>>(),
                e.settings.clone(),
            )
        };
        let mut tasks = tokio::task::JoinSet::new();
        for alert in alerts {
            let a = a.clone();
            let settings = settings.clone();
            tasks.spawn(async move {
                let result =
                    tokio::time::timeout(Duration::from_secs(8), notify(&a, &settings, &alert))
                        .await;
                if !matches!(result, Ok(Ok(()))) {
                    a.engine.lock().unwrap().stats.notification_failures += 1;
                }
            });
        }
        while tasks.join_next().await.is_some() {}
        if settings["gossip_enabled"] == true && sync_at.elapsed() >= Duration::from_secs(300) {
            let pack = crate::security::ioc_pack(&a, true);
            let _ = sync(a.clone(), pack).await;
            sync_at = tokio::time::Instant::now();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cef_escape_separates_header_and_extension() {
        let s = cef(
            &json!({"severity":"warning","type":"A|B","message":"message|next","details":{"process":"x=y\nz"}}),
        );
        assert!(s.contains("A\\|B"));
        assert!(s.contains("sproc=x\\=y\\nz"));
    }
}
