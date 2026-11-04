//! Fictional data for native UI screenshots. No capture, OS inspection, policy
//! changes, DNS, external requests, or host data. Loopback + private token only.
use axum::{
    extract::{
        ws::{Message, WebSocketUpgrade},
        Request, State,
    },
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
struct App {
    token: Arc<String>,
    graph: Arc<Mutex<Value>>,
}

fn graph() -> Value {
    let mut nodes =
        vec![json!({"id":"local","label":"This device","category":"local","bytes":0,"packets":0})];
    let devices = [
        ("Demo gateway", "router"),
        ("Design laptop", "pc"),
        ("Demo phone", "phone"),
        ("Studio workstation", "pc"),
        ("Test machine", "pc"),
        ("Demo storage", "iot"),
        ("Demo display", "iot"),
        ("Demo tablet", "phone"),
    ];
    for (i, (name, kind)) in devices.iter().enumerate() {
        nodes.push(json!({"id":format!("192.0.2.{}",i+1),"ip":format!("192.0.2.{}",i+1),"label":name,"hostname":name,"device_type":kind,"vendor":"Example Hardware","mac":format!("02:00:00:00:00:{:02x}",i+1),"category":"lan_device","private":true,"online":true,"bytes":(i+1)*4500000,"packets":(i+1)*3000,"color":"#65b8d3"}));
    }
    let roles = [
        "workspace-api",
        "content-cache",
        "mail-gateway",
        "sync-service",
        "backup-demo",
        "media-cache",
        "package-mirror",
        "metrics-demo",
    ];
    let categories = [
        ("https", "#48c990"),
        ("cdn", "#8799e7"),
        ("dns", "#65b8d3"),
        ("https", "#48c990"),
        ("cdn", "#8799e7"),
        ("https", "#48c990"),
        ("tracking", "#d7aa58"),
        ("unknown", "#9aa5a1"),
    ];
    let mut edges = vec![];
    for i in 0..64 {
        let ip = format!("198.51.100.{}", i + 1);
        let (category, color) = categories[i % categories.len()];
        let bytes = ((64 - i) as u64 * 31000000) + 800000;
        nodes.push(json!({"id":ip,"ip":ip,"label":format!("{}-{:02}.example",roles[i%roles.len()],i+1),"hostname":format!("{}-{:02}.example",roles[i%roles.len()],i+1),"category":category,"color":color,"bytes":bytes,"packets":bytes/1200,"private":false,"country":"Example location","country_code":"XX","org":"Fictional demonstration network","processes":{"Demo Browser":{"bytes":bytes,"packets":bytes/1200,"pid":null}}}));
        edges.push(json!({"id":format!("local:{ip}:443"),"source":"local","target":ip,"protocol":"TCP","label":"HTTPS","color":color,"bytes":bytes,"packets":bytes/1200}));
    }
    for i in 0..8 {
        edges.push(json!({"id":format!("demo-lan-{i}"),"source":"local","target":format!("192.0.2.{}",i+1),"protocol":"LAN","bytes":(i+1)*4500000,"color":"#65b8d3"}));
    }
    json!({"nodes":nodes,"edges":edges})
}
fn alerts() -> Value {
    json!([
        {"id":"example-alert-1","type":"UPLOAD_SPIKE","severity":"warning","message":"Example: unusual upload rate from Demo Sync","timestamp":"2025-01-01T12:00:00Z","node_id":"198.51.100.5"},
        {"id":"example-alert-2","type":"NEW_LAN_DEVICE","severity":"warning","message":"Example: a new fictional device joined the demo network","timestamp":"2025-01-01T11:59:00Z","node_id":"192.0.2.8"},
        {"id":"example-alert-3","type":"SUSPICIOUS_PORT","severity":"warning","message":"Example: review a connection in this fictional dataset","timestamp":"2025-01-01T11:58:00Z","node_id":"198.51.100.23"}
    ])
}
fn packets() -> Value {
    json!([
        {"src_ip":"192.0.2.2","dst_ip":"198.51.100.5","src_port":52000,"dst_port":443,"protocol":"TCP","direction":"out","size":1450,"process_name":"Demo Sync","timestamp":"2025-01-01T12:00:00Z"},
        {"src_ip":"198.51.100.12","dst_ip":"192.0.2.2","src_port":443,"dst_port":52001,"protocol":"TCP","direction":"in","size":1448,"process_name":"Demo Browser","timestamp":"2025-01-01T12:00:00Z"},
        {"src_ip":"192.0.2.2","dst_ip":"198.51.100.3","src_port":52002,"dst_port":443,"protocol":"TCP","direction":"out","size":728,"process_name":"Demo Mail","timestamp":"2025-01-01T12:00:00Z"},
        {"src_ip":"198.51.100.8","dst_ip":"192.0.2.2","src_port":443,"dst_port":52003,"protocol":"TCP","direction":"in","size":1420,"process_name":"Demo Updates","timestamp":"2025-01-01T12:00:00Z"}
    ])
}
fn status() -> Value {
    json!({"capturing":true,"capture_error":null,"interface":"SYNTHETIC DEMO · fictional traffic","demo":true})
}
async fn auth(State(app): State<App>, req: Request, next: Next) -> Response {
    if req
        .headers()
        .get("X-Snitch-Token")
        .and_then(|v| v.to_str().ok())
        != Some(app.token.as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}
async fn route(State(app): State<App>, req: Request) -> Response {
    if req.method() != Method::GET {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"detail":"Fictional gallery fixture: actions are disabled"})),
        )
            .into_response();
    }
    let value = match req.uri().path() {
        "/graph" => app.graph.lock().unwrap().clone(),
        "/capture/status" => status(),
        "/alerts" => json!({"alerts":alerts()}),
        "/security/audit" => {
            json!({"score":78,"critical":0,"warning":3,"period":"fictional gallery data"})
        }
        "/timeline" => {
            let volume = [4, 7, 5, 13, 21, 17, 9, 14, 27, 19, 11, 23, 17, 12, 18];
            json!({"timeline":volume.iter().enumerate().map(|(i,n)|json!({"minute":format!("2025-01-01T11:{:02}",45+i),"bytes":n*1048576,"packets":n*800,"alerts":0})).collect::<Vec<_>>()})
        }
        "/settings" => {
            json!({"settings":{"retention_hours":24,"ports":[],"excluded_processes":[],"whitelisted_ips":[],"watchlist":[]}})
        }
        _ => json!({"demo":true,"supported":false}),
    };
    Json(value).into_response()
}
async fn websocket(upgrade: WebSocketUpgrade, State(app): State<App>) -> Response {
    upgrade.on_upgrade(move|mut socket|async move {
        let mut initial=app.graph.lock().unwrap().clone();
        initial["type"]=json!("init");initial["capturing"]=json!(true);initial["interface"]=json!("SYNTHETIC DEMO · fictional traffic");initial["alerts"]=alerts();initial["packets"]=packets();
        if socket.send(Message::Text(initial.to_string().into())).await.is_err(){return;}
        let mut tick=tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select!{
                _=tick.tick()=>{
                    let batch={
                        let mut graph=app.graph.lock().unwrap();
                        for (i,node) in graph["nodes"].as_array_mut().unwrap().iter_mut().enumerate().skip(1){node["bytes"]=json!(node["bytes"].as_u64().unwrap()+18000*(1+(i%8)as u64));node["packets"]=json!(node["packets"].as_u64().unwrap()+40);}
                        for edge in graph["edges"].as_array_mut().unwrap(){edge["bytes"]=json!(edge["bytes"].as_u64().unwrap()+94000);}
                        json!({"type":"batch","nodes":graph["nodes"],"edges":graph["edges"],"packets":packets(),"alerts":[]})
                    };
                    if socket.send(Message::Text(batch.to_string().into())).await.is_err(){break;}
                },
                message=socket.recv()=>{
                    match message {
                        Some(Ok(Message::Ping(value)))=>{if socket.send(Message::Pong(value)).await.is_err(){break;}},
                        None|Some(Err(_))|Some(Ok(Message::Close(_)))=>break,
                        _=>{},
                    }
                }
            }
        }
    })
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let option = |name: &str| args.windows(2).find(|p| p[0] == name).map(|p| p[1].clone());
    let data = PathBuf::from(
        option("--data-dir")
            .ok_or("Usage: gallery_fixture --data-dir PRIVATE_DIRECTORY [--port PORT]")?,
    );
    let token = Arc::new(genyra_common::token(&data)?);
    let app = App {
        token,
        graph: Arc::new(Mutex::new(graph())),
    };
    let router = Router::new()
        .route("/ws", get(websocket))
        .fallback(route)
        .layer(middleware::from_fn_with_state(app.clone(), auth))
        .with_state(app);
    let port = option("--port").unwrap_or("18987".into()).parse::<u16>()?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    eprintln!("Fictional gallery data only; no capture or host inspection. Loopback port {port}.");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gallery_uses_only_fictional_documentation_namespaces() {
        let graph = graph();
        let nodes = graph["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 73);
        for node in nodes {
            if node["id"] == "local" {
                continue;
            }
            let ip = node["ip"].as_str().unwrap();
            assert!(ip.starts_with("192.0.2.") || ip.starts_with("198.51.100."));
            if node["private"] != true {
                assert!(node["hostname"].as_str().unwrap().ends_with(".example"));
            }
        }
        assert!(status()["interface"]
            .as_str()
            .unwrap()
            .contains("SYNTHETIC DEMO"));
    }
}
