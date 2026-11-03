//! Browser and REST compatibility for the existing Snitch React client.
use crate::App;
use axum::{
    body::{to_bytes, Body},
    extract::{
        ws::{Message, WebSocket},
        Request, State, WebSocketUpgrade,
    },
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::{collections::HashMap, fs, net::IpAddr, sync::atomic::Ordering, time::Duration};

pub type ApiResult = Result<Value, (StatusCode, String)>;
pub fn error(status: StatusCode, message: impl Into<String>) -> (StatusCode, String) {
    (status, message.into())
}
pub fn bad(message: impl Into<String>) -> (StatusCode, String) {
    error(StatusCode::BAD_REQUEST, message)
}
pub fn save(a: &App, key: &str, value: Value) -> ApiResult {
    a.db.lock().unwrap().execute("INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",rusqlite::params![key,value.to_string()]).map_err(|e|{eprintln!("settings write: {e}");error(StatusCode::INTERNAL_SERVER_ERROR,"Settings could not be saved")})?;
    a.engine.lock().unwrap().apply_setting(key, value);
    Ok(json!({"ok":true}))
}
pub async fn websocket(State(a): State<App>, ws: WebSocketUpgrade) -> Response {
    let Ok(permit) = a.ws_slots.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket client limit reached",
        )
            .into_response();
    };
    ws.max_message_size(4096)
        .max_frame_size(4096)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            session(a, socket).await
        })
}
async fn session(a: App, mut socket: WebSocket) {
    let mut events = a.events.subscribe();
    let snapshot = a.engine.lock().unwrap().init();
    if socket
        .send(Message::Text(snapshot.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            msg=socket.recv()=>if !matches!(msg,Some(Ok(Message::Text(_)|Message::Ping(_)|Message::Pong(_)))){break;},
            event=events.recv()=>{
                let event=match event {Ok(v)=>v,Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>a.engine.lock().unwrap().init(),Err(_)=>break};
                if !matches!(tokio::time::timeout(Duration::from_secs(2),socket.send(Message::Text(event.to_string().into()))).await,Ok(Ok(()))){break;}
            }
        }
    }
}
pub(crate) fn public_asset(path: &str) -> bool {
    matches!(
        path,
        "/" | "/index.html" | "/favicon.ico" | "/favicon.png" | "/logo.png" | "/logo-180.png"
    ) || path.starts_with("/assets/")
        || path.starts_with("/brand/")
}
pub async fn dispatch(State(a): State<App>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if method == Method::GET && public_asset(&path) {
        let root = a.frontend.clone();
        let file = root.join(if path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        });
        if let (Ok(root), Ok(file)) = (root.canonicalize(), file.canonicalize()) {
            if file.starts_with(root) {
                if let Ok(bytes) = fs::read(&file) {
                    let mime = match file.extension().and_then(|s| s.to_str()).unwrap_or("") {
                        "html" => "text/html; charset=utf-8",
                        "js" => "application/javascript",
                        "css" => "text/css",
                        "svg" => "image/svg+xml",
                        "png" => "image/png",
                        "ico" => "image/x-icon",
                        "woff2" => "font/woff2",
                        _ => "application/octet-stream",
                    };
                    return ([(header::CONTENT_TYPE, mime)], bytes).into_response();
                }
            }
        }
        return (StatusCode::NOT_FOUND, "Snitch frontend build not found").into_response();
    }
    let q = crate::serde_urlencoded_query(req.uri().query().unwrap_or("")).unwrap_or_default();
    let trusted_agent = req.extensions().get::<crate::AgentName>().cloned();
    let mut body: Value = match to_bytes(req.into_body(), 2 * 1024 * 1024).await {
        Ok(b) if b.is_empty() => json!({}),
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"detail":"Invalid JSON"})),
                )
                    .into_response()
            }
        },
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail":"Body exceeds 2 MiB"})),
            )
                .into_response()
        }
    };
    if let Some(object) = body.as_object_mut() {
        object.remove("_trusted_agent");
        if let Some(name) = trusted_agent {
            object.insert("_trusted_agent".into(), json!(name.0));
        }
    }
    if path == "/forensics/pcap" && method == Method::GET {
        return pcap(&a, &q);
    }
    let Ok(permit) = a.api_slots.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "API concurrency limit reached",
        )
            .into_response();
    };
    let a2 = a.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _mutation = if method != Method::GET
            && ![
                "/security/deep_inspect",
                "/security/perf",
                "/security/hollow",
                "/security/sandbox",
                "/security/explain",
                "/security/threat_check",
                "/geo/download",
                "/remote/ioc_sync",
            ]
            .contains(&path.as_str())
        {
            Some(a2.mutations.lock().unwrap())
        } else {
            None
        };
        api(&a2, &method, &path, &q, &body)
    })
    .await;
    match result {
        Ok(Ok(value)) => {
            if let (Some(body), Some(mime)) =
                (value["_body"].as_str(), value["_content_type"].as_str())
            {
                let mut response = body.to_string().into_response();
                if let Ok(mime) = header::HeaderValue::from_str(mime) {
                    response.headers_mut().insert(header::CONTENT_TYPE, mime);
                }
                if let Some(name) = value["_filename"].as_str() {
                    if let Ok(h) =
                        header::HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
                    {
                        response
                            .headers_mut()
                            .insert(header::CONTENT_DISPOSITION, h);
                    }
                }
                response
            } else {
                Json(value).into_response()
            }
        }
        Ok(Err((status, message))) => (status, Json(json!({"detail":message}))).into_response(),
        Err(e) => {
            eprintln!("API task error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail":"Internal error"})),
            )
                .into_response()
        }
    }
}
fn minutes(q: &HashMap<String, String>) -> i64 {
    q.get("minutes")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(60)
        .clamp(1, 10080)
}
fn api(
    a: &App,
    method: &Method,
    path: &str,
    q: &HashMap<String, String>,
    body: &Value,
) -> ApiResult {
    let get = method == Method::GET;
    let post = method == Method::POST;
    let delete = method == Method::DELETE;
    match (path, get, post) {
        ("/media", true, _) => Ok(a.engine.lock().unwrap().media.clone()),
        ("/settings", _, true) => {
            let settings = body["settings"]
                .as_object()
                .ok_or_else(|| bad("settings must be an object"))?;
            if settings.len() > 256 {
                return Err(bad("Too many settings keys"));
            }
            for (k, v) in settings {
                save(a, k, v.clone())?;
            }
            Ok(json!({"ok":true}))
        }
        ("/watchlist", true, _) => Ok(
            json!({"items":a.engine.lock().unwrap().settings.get("watchlist").cloned().unwrap_or(json!([]))}),
        ),
        ("/watchlist", _, true) => {
            let items = strings(body, "items", 1024)?;
            save(a, "watchlist", json!(items))?;
            capture_event(a);
            Ok(json!({"items":items}))
        }
        ("/capture/ports", _, true) => {
            let ports: Vec<u16> = body["ports"]
                .as_array()
                .ok_or_else(|| bad("ports must be an array"))?
                .iter()
                .take(512)
                .filter_map(Value::as_u64)
                .filter_map(|n| u16::try_from(n).ok())
                .filter(|p| *p > 0)
                .collect();
            save(a, "ports", json!(ports))?;
            let mut reset = a.engine.lock().unwrap().graph();
            reset["type"] = json!("reset");
            reset["ports"] = json!(ports);
            let _ = a.events.send(reset);
            Ok(json!({"ports":ports}))
        }
        ("/capture/processes", _, true) => {
            let items = strings(body, "excluded", 512)?;
            save(a, "excluded_processes", json!(items))?;
            capture_event(a);
            Ok(json!({"excluded_processes":items}))
        }
        ("/capture/whitelist", _, true) => {
            let items: Vec<String> = strings(body, "ips", 512)?
                .iter()
                .map(|s| {
                    s.parse::<IpAddr>()
                        .map(|ip| ip.to_string())
                        .map_err(|_| bad("Whitelist entries must be valid IP addresses"))
                })
                .collect::<Result<_, _>>()?;
            let before: Vec<_> = a.engine.lock().unwrap().nodes.keys().cloned().collect();
            save(a, "whitelisted_ips", json!(items))?;
            capture_event(a);
            let _=a.events.send(json!({"type":"nodes_removed","ids":before.into_iter().filter(|ip|items.contains(ip)).collect::<Vec<_>>()}));
            Ok(json!({"whitelisted_ips":items}))
        }
        ("/capture/interfaces", true, _) => {
            if crate::demo::enabled() {
                return Ok(
                    json!({"interfaces":[{"name":"demo","description":"Synthetic traffic; no capture device","addresses":[],"loopback":false}],"current":"demo","configured":"demo"}),
                );
            }
            let list = pcap::Device::list().map_err(|e| bad(e.to_string()))?;
            Ok(
                json!({"interfaces":list.into_iter().map(|d|json!({"loopback":d.flags.is_loopback(),"name":d.name,"description":d.desc,"addresses":d.addresses.iter().map(|a|a.addr).collect::<Vec<_>>()})).collect::<Vec<_>>(),"current":a.engine.lock().unwrap().iface,"configured":a.engine.lock().unwrap().settings["interface"]}),
            )
        }
        ("/capture/interface", _, true) => {
            if crate::demo::enabled() {
                return Err(bad("Live interfaces are unavailable in demo mode"));
            }
            let list = pcap::Device::list().map_err(|e| bad(e.to_string()))?;
            let selected = body["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    list.iter()
                        .find(|d| d.flags.is_up() && !d.flags.is_loopback())
                        .map(|d| d.name.clone())
                })
                .ok_or_else(|| bad("No interface available"))?;
            if !list.iter().any(|d| d.name == selected) {
                return Err(bad("Unknown capture interface"));
            }
            save(a, "interface", json!(selected))?;
            capture_event(a);
            Ok(json!({"interface":body["name"],"current":selected}))
        }
        ("/alerts/ignore", true, _) => Ok(
            json!({"suppressions":a.engine.lock().unwrap().settings.get("suppressions").cloned().unwrap_or(json!([]))}),
        ),
        ("/alerts/ignore", _, _) if post || delete => {
            let kind = body["type"].as_str().unwrap_or("");
            let ip = body["ip"].as_str().unwrap_or("");
            if kind.len() > 80 || ip.len() > 253 {
                return Err(bad("Invalid suppression"));
            }
            let mut rules = a.engine.lock().unwrap().settings["suppressions"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            rules.retain(|r| r["type"] != kind || r["ip"] != ip);
            if post && (!kind.is_empty() || !ip.is_empty()) && rules.len() < 4096 {
                rules.push(json!({"type":kind,"ip":ip}));
            }
            save(a, "suppressions", json!(rules))?;
            Ok(json!({"suppressions":rules}))
        }
        ("/geo/status", true, _) => Ok(
            json!({"databases":fs::read_dir(a.data.join("geo")).into_iter().flatten().flatten().filter_map(|e|e.file_name().to_str().map(str::to_string)).filter(|s|s.ends_with(".mmdb")).collect::<Vec<_>>(),"dir":a.data.join("geo")}),
        ),
        ("/remote/pairing", true, _) => {
            let e = a.engine.lock().unwrap();
            let bind = a.bind.to_string();
            let persisted = e.settings["lan_bind"].as_str().unwrap_or("");
            Ok(
                json!({"active":!a.bind.is_loopback(),"bind":bind,"bind_source":a.bind_source,"port":a.port,"lan_ips":e.local_ips.iter().filter(|ip|ip.is_ipv4()&&!ip.is_loopback()).collect::<Vec<_>>(),"persisted_bind":persisted,"token_required":true,"restart_required":!persisted.is_empty()&&persisted!=bind}),
            )
        }
        ("/remote/pairing", _, true) => {
            let bind = if body["enabled"] == true {
                body["bind"].as_str().unwrap_or("0.0.0.0")
            } else {
                ""
            };
            if !bind.is_empty()
                && bind != "0.0.0.0"
                && !bind
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| a.engine.lock().unwrap().local_ips.contains(&ip))
            {
                return Err(bad("bind must be 0.0.0.0 or a local LAN address"));
            }
            save(a, "lan_bind", json!(bind))?;
            Ok(json!({"ok":true,"lan_bind":bind,"restart_required":true}))
        }
        ("/shutdown", _, true) => {
            a.stop.store(true, Ordering::Relaxed);
            Ok(json!({"ok":true}))
        }
        _ if get && path.starts_with("/history/") => history(a, path, q),
        _ => crate::security::api(a, method, path, q, body),
    }
}
pub fn strings(body: &Value, key: &str, max: usize) -> Result<Vec<String>, (StatusCode, String)> {
    let items = body[key]
        .as_array()
        .ok_or_else(|| bad(format!("{key} must be an array")))?;
    items
        .iter()
        .take(max)
        .map(|v| {
            v.as_str()
                .filter(|s| s.len() <= 256)
                .map(str::to_string)
                .ok_or_else(|| bad("Expected string of at most 256 characters"))
        })
        .collect()
}
pub fn capture_event(a: &App) {
    let mut event = a.engine.lock().unwrap().status();
    event["type"] = json!("capture_status");
    let _ = a.events.send(event);
}
fn history(a: &App, path: &str, q: &HashMap<String, String>) -> ApiResult {
    let cutoff = (chrono::Utc::now() - chrono::Duration::minutes(minutes(q)))
        .format("%Y-%m-%dT%H:%M")
        .to_string();
    let c = a.db.lock().unwrap();
    if path == "/history/top_processes" {
        let mut stmt=c.prepare("SELECT key,SUM(packets),SUM(bytes) FROM history WHERE dim='process' AND minute>=? GROUP BY key ORDER BY SUM(bytes) DESC LIMIT 50").map_err(|e|bad(e.to_string()))?;
        let rows=stmt.query_map([cutoff],|r|Ok(json!({"process":r.get::<_,String>(0)?,"packets":r.get::<_,i64>(1)?,"bytes":r.get::<_,i64>(2)?}))).map_err(|e|bad(e.to_string()))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|bad(e.to_string()))?;
        return Ok(json!({"processes":rows}));
    }
    let rest = path.trim_start_matches("/history/");
    let (dim, key) = rest
        .split_once('/')
        .ok_or_else(|| bad("Invalid history path"))?;
    if !["host", "process"].contains(&dim) {
        return Err(error(StatusCode::NOT_FOUND, "Unknown history dimension"));
    }
    let key = crate::serde_urlencoded_query(&format!("key={}", key.replace('+', "%2B")))
        .and_then(|mut q| q.remove("key"))
        .ok_or_else(|| bad("Invalid history key"))?;
    let mut stmt=c.prepare("SELECT minute,packets,bytes FROM history WHERE dim=?1 AND key=?2 AND minute>=?3 ORDER BY minute").map_err(|e|bad(e.to_string()))?;
    let rows=stmt.query_map(rusqlite::params![dim,key,cutoff],|r|Ok(json!({"minute":r.get::<_,String>(0)?,"packets":r.get::<_,i64>(1)?,"bytes":r.get::<_,i64>(2)?}))).map_err(|e|bad(e.to_string()))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|bad(e.to_string()))?;
    Ok(
        json!({"history":rows,"ip":if dim=="host"{Some(&key)}else{None},"process":if dim=="process"{Some(&key)}else{None}}),
    )
}
fn pcap(a: &App, q: &HashMap<String, String>) -> Response {
    let e = a.engine.lock().unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&4096u32.to_le_bytes());
    out.extend_from_slice(&(e.linktype as u32).to_le_bytes());
    let seconds = q
        .get("seconds")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(300)
        .clamp(1, 3600);
    let cutoff = chrono::Utc::now().timestamp() as f64 - seconds as f64;
    for (ts, b, wirelen, ip, process) in &e.raw_frames {
        if *ts < cutoff
            || q.get("ip").is_some_and(|v| v != ip)
            || q.get("process").is_some_and(|v| !process.contains(v))
        {
            continue;
        }
        out.extend_from_slice(&(*ts as u32).to_le_bytes());
        out.extend_from_slice(&((ts.fract() * 1e6) as u32).to_le_bytes());
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(&wirelen.to_le_bytes());
        out.extend_from_slice(b);
    }
    if out.len() == 24 {
        return StatusCode::NO_CONTENT.into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/vnd.tcpdump.pcap"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=snitch-forensics.pcap",
            ),
        ],
        Body::from(out),
    )
        .into_response()
}
