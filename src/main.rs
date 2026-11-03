mod anomaly;
#[cfg(target_os = "linux")]
mod ask;
#[cfg(not(target_os = "linux"))]
#[path = "platform/ask.rs"]
mod ask;
mod blocklist;
mod deep;
mod demo;
mod enrichment;
mod firewall;
mod forensics;
mod geodb;
mod integrations;
mod integrity;
#[cfg(target_os = "linux")]
mod kernel;
#[cfg(not(target_os = "linux"))]
#[path = "platform/kernel.rs"]
mod kernel;
mod observer;
mod packet;
mod paths;
mod platform;
mod process;
mod rules;
mod security;
#[cfg(windows)]
mod service_host;
mod sinkhole;
mod slm;
mod state;
mod storage;
mod tlscert;
mod web;

use axum::{
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use state::Engine;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    collections::HashMap,
    env, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct App {
    engine: Arc<Mutex<Engine>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    token: Arc<String>,
    port: u16,
    bind: IpAddr,
    bind_source: String,
    data: PathBuf,
    frontend: PathBuf,
    events: tokio::sync::broadcast::Sender<Value>,
    stop: Arc<AtomicBool>,
    integrity: Arc<Mutex<integrity::Integrity>>,
    http: reqwest::Client,
    mutations: Arc<Mutex<()>>,
    runtime: tokio::runtime::Handle,
    peer_state: Arc<Mutex<Value>>,
    kernel: Arc<kernel::Kernel>,
    ask: Arc<ask::Ask>,
    deep_busy: Arc<Mutex<()>>,
    slm: Arc<slm::Slm>,
    sinkhole: Arc<sinkhole::Sinkhole>,
    ti_cache: Arc<Mutex<HashMap<String, (Instant, Value)>>>,
    owners: Arc<RwLock<process::Table>>,
    api_slots: Arc<tokio::sync::Semaphore>,
    ws_slots: Arc<tokio::sync::Semaphore>,
}
#[derive(Clone)]
struct AgentName(String);
fn same_token(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
async fn auth(State(app): State<App>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if web::public_asset(path) {
        return next.run(req).await;
    }
    let expected_host = format!("127.0.0.1:{}", app.port);
    let expected_localhost = format!("localhost:{}", app.port);
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let lan_host = !app.bind.is_loopback()
        && host.parse::<SocketAddr>().ok().is_some_and(|sa| {
            sa.port() == app.port && app.engine.lock().unwrap().local_ips.contains(&sa.ip())
        });
    if host != expected_host
        && host != expected_localhost
        && host != format!("[::1]:{}", app.port)
        && !lan_host
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"detail":"Invalid host"})),
        )
            .into_response();
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let origin = origin.to_str().unwrap_or("");
        if origin != format!("http://{expected_host}")
            && origin != format!("http://{expected_localhost}")
            && origin != format!("http://{host}")
            && origin != format!("https://{host}")
            && ![
                "null",
                "file://",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
            .contains(&origin)
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"detail":"Origin not allowed"})),
            )
                .into_response();
        }
    }
    let origin = req.headers().get(header::ORIGIN).cloned();
    if req.method() == axum::http::Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        if let Some(origin) = origin {
            response
                .headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        }
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            header::HeaderValue::from_static(
                "X-Snitch-Token, X-Snitch-Agent, Authorization, Content-Type",
            ),
        );
        return response;
    }
    let query: HashMap<String, String> = req
        .uri()
        .query()
        .and_then(serde_urlencoded_query)
        .unwrap_or_default();
    let token = req
        .headers()
        .get("X-Snitch-Token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .unwrap_or_else(|| query.get("token").map(String::as_str).unwrap_or(""));
    let master = same_token(token, &app.token);
    let agent = if !master && req.uri().path() == "/ingest/events" {
        req.headers()
            .get("X-Snitch-Agent")
            .and_then(|v| v.to_str().ok())
            .and_then(|token| {
                let hash = integrity::sha(token);
                app.engine.lock().unwrap().settings["agent_tokens"]
                    .get(&hash)
                    .and_then(|v| v["name"].as_str())
                    .map(str::to_string)
            })
    } else {
        None
    };
    if !master && agent.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail":"Invalid API token"})),
        )
            .into_response();
    }
    if let Some(name) = agent {
        req.extensions_mut().insert(AgentName(name));
    }
    let mut response = next.run(req).await;
    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response
            .headers_mut()
            .insert(header::VARY, header::HeaderValue::from_static("Origin"));
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
async fn graph(State(a): State<App>) -> Json<Value> {
    Json(a.engine.lock().unwrap().graph())
}
async fn status(State(a): State<App>) -> Json<Value> {
    Json(a.engine.lock().unwrap().status())
}
async fn alerts(State(a): State<App>) -> Json<Value> {
    Json(json!({"alerts":a.engine.lock().unwrap().alerts}))
}
async fn diagnostics(State(a): State<App>) -> Json<Value> {
    Json(a.engine.lock().unwrap().diagnostics())
}
async fn devices(State(a): State<App>) -> Json<Value> {
    Json(
        json!({"devices":a.engine.lock().unwrap().nodes.values().filter(|n|n.private).collect::<Vec<_>>()}),
    )
}
async fn settings(State(a): State<App>) -> Json<Value> {
    Json(json!({"settings":a.engine.lock().unwrap().settings}))
}
async fn capture_stop(State(a): State<App>) -> Json<Value> {
    let mut e = a.engine.lock().unwrap();
    e.capturing = false;
    let status = e.status();
    drop(e);
    web::capture_event(&a);
    Json(status)
}
async fn capture_start(State(a): State<App>) -> Json<Value> {
    let mut e = a.engine.lock().unwrap();
    e.capturing = true;
    let status = e.status();
    drop(e);
    web::capture_event(&a);
    Json(status)
}
async fn timeline(State(a): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    let minutes = q.get("minutes").and_then(|s| s.parse().ok()).unwrap_or(60);
    match tokio::task::spawn_blocking(move || storage::timeline(&a.db.lock().unwrap(), minutes))
        .await
    {
        Ok(Ok(v)) => Json(v).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"detail":"Database read failed"})),
        )
            .into_response(),
    }
}
fn router(a: App) -> Router {
    Router::new()
        .route("/graph", get(graph))
        .route("/capture/status", get(status))
        .route("/alerts", get(alerts))
        .route("/diagnostics", get(diagnostics))
        .route("/devices", get(devices))
        .route("/settings", get(settings).post(web::dispatch))
        .route("/timeline", get(timeline))
        .route("/capture/start", post(capture_start))
        .route("/capture/stop", post(capture_stop))
        .route("/ws", get(web::websocket))
        .fallback(web::dispatch)
        .layer(middleware::from_fn_with_state(a.clone(), auth))
        .with_state(a)
}

fn fail(engine: &Mutex<Engine>, err: String) {
    eprintln!("capture failed: {err}");
    let mut e = engine.lock().unwrap();
    e.error = Some(err);
    e.capturing = false;
}
fn capture(engine: Arc<Mutex<Engine>>, owners: Arc<RwLock<process::Table>>, stop: Arc<AtomicBool>) {
    if demo::enabled() {
        demo::run(engine, stop);
        return;
    }
    if let Ok(path) = env::var("SNITCH_REPLAY_PCAP") {
        replay(&engine, &owners, &path);
        return;
    }
    let iface = engine.lock().unwrap().iface.clone();
    let opened = pcap::Capture::from_device(iface.as_str())
        .and_then(|c| {
            c.promisc(false)
                .snaplen(4096)
                .buffer_size(4 * 1024 * 1024)
                .timeout(100)
                .open()
        })
        .and_then(|mut c| {
            c.filter("ip or ip6 or arp", true)?;
            c.setnonblock()
        });
    let mut cap = match opened {
        Ok(c) => c,
        Err(e) => {
            fail(&engine, e.to_string());
            return;
        }
    };
    let link = cap.get_datalink().0;
    engine.lock().unwrap().linktype = link;
    if ![0, 1, 108, 113, 276, 12, 101].contains(&link) {
        fail(&engine, format!("Unsupported link type {link}"));
        return;
    }
    eprintln!("capture ready: {iface}, link={link}");
    engine.lock().unwrap().error = None;
    let mut last_tick = Instant::now();
    let mut frames: Vec<(Vec<u8>, u32)> = Vec::with_capacity(1024);
    while !stop.load(Ordering::Relaxed) {
        {
            let e = engine.lock().unwrap();
            if !e.capturing || e.iface != iface {
                return;
            }
        }
        // libpcap nonblocking reads plus poll: idle interfaces never spin.
        #[cfg(unix)]
        let ready = {
            let mut fd = libc::pollfd {
                fd: cap.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut fd, 1, 100) }
        };
        // Npcap does not expose a POSIX fd. Nonblocking reads plus a short
        // sleep after an empty batch bound CPU and shutdown latency.
        #[cfg(windows)]
        let ready = 0;
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                fail(&engine, e.to_string());
                return;
            }
        }
        frames.clear();
        for _ in 0..4096 {
            match cap.next_packet() {
                Ok(p) => frames.push((p.data.to_vec(), p.header.len)),
                Err(pcap::Error::TimeoutExpired) => break,
                Err(e) => {
                    fail(&engine, e.to_string());
                    return;
                }
            }
        }
        if !frames.is_empty() {
            let table = owners.read().unwrap();
            let mut e = engine.lock().unwrap();
            for (b, len) in &frames {
                e.packet(b, *len, link, &table);
            }
        }
        #[cfg(windows)]
        if frames.is_empty() {
            thread::sleep(Duration::from_millis(25));
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            let mut e = engine.lock().unwrap();
            e.tick();
            e.stats.attribution_incomplete = owners.read().unwrap().incomplete;
            if let Ok(stats) = cap.stats() {
                e.stats.pcap_dropped = stats.dropped;
                e.stats.pcap_if_dropped = stats.if_dropped;
            }
            last_tick = Instant::now();
        }
    }
}
fn replay(engine: &Mutex<Engine>, owners: &RwLock<process::Table>, path: &str) {
    let mut cap = match pcap::Capture::from_file(path) {
        Ok(cap) => cap,
        Err(e) => {
            fail(engine, e.to_string());
            return;
        }
    };
    let link = cap.get_datalink().0;
    let table = owners.read().unwrap();
    let mut engine = engine.lock().unwrap();
    engine.linktype = link;
    engine.error = None;
    while let Ok(p) = cap.next_packet() {
        engine.packet(p.data, p.header.len, link, &table);
    }
    engine.capturing = false;
    eprintln!("offline replay complete: {} frames", engine.stats.captured);
}
fn interruptible_sleep(stop: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
}
fn write_pending(a: &App, p: &state::Pending) -> rusqlite::Result<()> {
    let result = storage::flush(&mut a.db.lock().unwrap(), p);
    paths::restore_owner(&a.data);
    result
}
fn writer(a: App, stop: Arc<AtomicBool>) {
    let mut cleanup = Instant::now();
    let mut retry: Option<state::Pending> = None;
    loop {
        interruptible_sleep(&stop, Duration::from_secs(10));
        let p = retry
            .take()
            .unwrap_or_else(|| std::mem::take(&mut a.engine.lock().unwrap().pending));
        if let Err(err) = write_pending(&a, &p) {
            eprintln!("database flush failed (retaining batch for retry): {err}");
            retry = Some(p);
            a.engine.lock().unwrap().storage_error =
                Some(format!("Database persistence failed: {err}"));
        } else {
            a.engine.lock().unwrap().storage_error = None;
        }
        if cleanup.elapsed() > Duration::from_secs(3600) {
            if let Err(e) = storage::cleanup(&mut a.db.lock().unwrap()) {
                eprintln!("history cleanup failed: {e}");
            }
            cleanup = Instant::now();
        }
        if stop.load(Ordering::Relaxed) {
            if let Some(p) = retry {
                if let Err(e) = write_pending(&a, &p) {
                    eprintln!("final retry failed: {e}");
                }
            }
            let p = std::mem::take(&mut a.engine.lock().unwrap().pending);
            if let Err(e) = write_pending(&a, &p) {
                eprintln!("final flush failed: {e}");
            }
            break;
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().any(|arg| arg == "--version") {
        println!("Genyra Snitch {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let data = paths::data_dir();
    if !data.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&data)?;
    }
    if env::args().any(|arg| arg == "--check") {
        let db = storage::open(&data)?;
        let _ = storage::settings(&db)?;
        let _ = storage::alerts(&db)?;
        let _ = storage::devices(&db)?;
        println!("database and native libraries ready");
        return Ok(());
    }
    let mut instance = genyra_common::Instance::acquire(&data)?;
    if !demo::enabled() {
        platform::init_capture_runtime()?;
    }
    // Reuse the established secret. Never generate a replacement or print it.
    let token = paths::token(&data)?;
    let conn = storage::open(&data)?;
    let settings = storage::settings(&conn)?;
    let args: Vec<String> = env::args().skip(1).collect();
    let mut options = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--port" | "--bind" | "--interface" | "--data-dir" => {
                let value = args
                    .get(index + 1)
                    .ok_or("Missing command-line option value")?;
                options.insert(args[index].clone(), value.clone());
                index += 2;
            }
            "--demo" | "--no-browser" | "--service-run" => {
                index += 1;
            }
            "--help" | "-h" => {
                println!("Genyra Snitch {}\nUsage: genyra-snitch [--port PORT] [--bind IP] [--interface NAME] [--check] [--version]\nEnvironment: SNITCH_DATA_DIR, SNITCH_TOKEN, SNITCH_IFACE, SNITCH_FRONTEND_DIR, SNITCH_TLS_CERT, SNITCH_TLS_KEY", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => return Err(format!("Unknown option: {}", args[index]).into()),
        }
    }
    let (bind_text, bind_source) = if let Ok(bind) = env::var("SNITCH_BIND") {
        (bind, "env")
    } else if let Some(bind) = options.get("--bind") {
        (bind.clone(), "argv")
    } else if let Some(bind) = settings["lan_bind"].as_str().filter(|s| !s.is_empty()) {
        (bind.to_string(), "setting")
    } else {
        ("127.0.0.1".into(), "default")
    };
    let bind: IpAddr = if bind_text == "localhost" {
        "127.0.0.1".parse()?
    } else {
        bind_text.parse()?
    };
    let mut port: u16 = env::var("SNITCH_PORT")
        .ok()
        .or_else(|| options.get("--port").cloned())
        .unwrap_or_else(|| "8000".into())
        .parse()?;
    let interfaces = if demo::enabled() {
        vec![]
    } else {
        pcap::Device::list()?
    };
    let iface = if demo::enabled() {
        "demo".to_owned()
    } else {
        env::var("SNITCH_IFACE")
            .ok()
            .or_else(|| options.get("--interface").cloned())
            .or_else(|| {
                settings["interface"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .or_else(|| {
                interfaces
                    .iter()
                    .find(|d| !d.flags.is_loopback() && d.flags.is_up() && !d.addresses.is_empty())
                    .map(|d| d.name.clone())
            })
            .ok_or("No capture interface found")?
    };
    if !demo::enabled() && !interfaces.iter().any(|d| d.name == iface) {
        return Err(format!("Interface {iface} does not exist").into());
    }
    let ips = interfaces
        .iter()
        .flat_map(|d| d.addresses.iter().map(|a| a.addr))
        .collect();
    paths::restore_owner(&data);
    let alerts = storage::alerts(&conn)?;
    let engine = Arc::new(Mutex::new(Engine::new(&data, iface, settings, alerts, ips)));
    engine
        .lock()
        .unwrap()
        .restore_devices(storage::devices(&conn)?);
    engine.lock().unwrap().error = Some("Starting packet capture".into());
    let integrity = Arc::new(Mutex::new(integrity::Integrity::load(
        &engine.lock().unwrap().settings["integrity_baselines"],
    )));
    let kernel = engine.lock().unwrap().kernel.clone();
    let mut a = App {
        engine: engine.clone(),
        db: Arc::new(Mutex::new(conn)),
        token: Arc::new(token),
        port,
        bind,
        bind_source: bind_source.into(),
        data: data.clone(),
        frontend: paths::frontend(),
        events: tokio::sync::broadcast::channel(16).0,
        stop: Arc::new(AtomicBool::new(false)),
        integrity,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        mutations: Arc::new(Mutex::new(())),
        runtime: tokio::runtime::Handle::current(),
        peer_state: Arc::new(Mutex::new(json!({}))),
        kernel,
        ask: Arc::new(ask::Ask::default()),
        deep_busy: Arc::new(Mutex::new(())),
        slm: Arc::new(slm::Slm::default()),
        sinkhole: Arc::new(sinkhole::Sinkhole::default()),
        ti_cache: Arc::new(Mutex::new(HashMap::new())),
        owners: Arc::new(RwLock::new(process::Table::default())),
        api_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        ws_slots: Arc::new(tokio::sync::Semaphore::new(32)),
    };
    let tls_cert = env::var_os("SNITCH_TLS_CERT");
    let tls_key = env::var_os("SNITCH_TLS_KEY");
    let tls = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
        }
        (None, None) => None,
        _ => return Err("SNITCH_TLS_CERT and SNITCH_TLS_KEY must be supplied together".into()),
    };
    let listener = std::net::TcpListener::bind(SocketAddr::new(bind, port))?;
    listener.set_nonblocking(true)?;
    port = listener.local_addr()?.port();
    a.port = port;
    let loopback = if bind.is_ipv6() { "[::1]" } else { "127.0.0.1" };
    instance.publish(&format!(
        "{}://{loopback}:{port}",
        if tls.is_some() { "https" } else { "http" }
    ))?;
    paths::restore_owner(&data);
    #[cfg(windows)]
    service_host::started()?;
    let stop = a.stop.clone();
    let owners = a.owners.clone();
    let table_thread = {
        let stop = stop.clone();
        let owners = owners.clone();
        thread::Builder::new()
            .name("socket-owners".into())
            .spawn(move || {
                let mut table = process::Table::default();
                while !stop.load(Ordering::Relaxed) {
                    table.refresh();
                    *owners.write().unwrap() = table.clone();
                    interruptible_sleep(&stop, Duration::from_secs(3));
                }
            })?
    };
    let capture_thread = {
        let stop = stop.clone();
        thread::Builder::new().name("pcap".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if !engine.lock().unwrap().capturing {
                    interruptible_sleep(&stop, Duration::from_millis(100));
                    continue;
                }
                capture(engine.clone(), owners.clone(), stop.clone());
            }
        })?
    };
    let writer_thread = {
        let stop = stop.clone();
        let a = a.clone();
        thread::Builder::new()
            .name("sqlite".into())
            .spawn(move || writer(a, stop))?
    };
    let integrity_thread = {
        let a = a.clone();
        thread::Builder::new()
            .name("integrity".into())
            .spawn(move || {
                let mut last_save = Instant::now();
                while !a.stop.load(Ordering::Relaxed) {
                    let (enabled, pids) = {
                        let e = a.engine.lock().unwrap();
                        (
                            e.settings["integrity_watch"] != false && !demo::enabled(),
                            e.nodes
                                .values()
                                .flat_map(|n| n.processes.values().filter_map(|p| p.pid))
                                .take(4000)
                                .collect::<std::collections::HashSet<_>>(),
                        )
                    };
                    if enabled {
                        let start = Instant::now();
                        for pid in pids {
                            if a.stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let findings = a.integrity.lock().unwrap().check(pid, false);
                            security::record_findings(&a, &findings);
                            if start.elapsed() > Duration::from_millis(500) {
                                break;
                            }
                        }
                    }
                    if last_save.elapsed() > Duration::from_secs(60) {
                        let baseline = json!(a.integrity.lock().unwrap().baselines);
                        let _ = web::save(&a, "integrity_baselines", baseline);
                        let baseline = json!(a.engine.lock().unwrap().detector.baselines);
                        let _ = web::save(&a, "app_baselines", baseline);
                        last_save = Instant::now();
                    }
                    interruptible_sleep(&a.stop, Duration::from_secs(3));
                }
            })?
    };
    let observer_thread = {
        let a = a.clone();
        thread::Builder::new()
            .name("lan-media".into())
            .spawn(move || observer::run(a))?
    };
    let kernel_thread = {
        let a = a.clone();
        thread::Builder::new()
            .name("bpf-probe".into())
            .spawn(move || kernel::run(a))?
    };
    let policy_thread = {
        let a = a.clone();
        thread::Builder::new()
            .name("firewall".into())
            .spawn(move || security::policy_worker(a))?
    };
    let threat_thread = {
        let a = a.clone();
        thread::Builder::new()
            .name("threat-intel".into())
            .spawn(move || security::threat_worker(a))?
    };
    let ask_thread = {
        let a = a.clone();
        thread::Builder::new()
            .name("nfqueue".into())
            .spawn(move || ask::run(a))?
    };
    eprintln!("Genyra Snitch API listening on {bind}:{port}");
    let updates = {
        let a = a.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            while !a.stop.load(Ordering::Relaxed) {
                tick.tick().await;
                if a.events.receiver_count() > 0 {
                    let event = a.engine.lock().unwrap().drain_events();
                    if event["removed"]
                        .as_array()
                        .is_some_and(|ids| !ids.is_empty())
                    {
                        let _ = a
                            .events
                            .send(json!({"type":"nodes_removed","ids":event["removed"]}));
                    }
                    let _ = a.events.send(event);
                } else {
                    a.engine.lock().unwrap().discard_events();
                }
            }
        })
    };
    let integrations_task = {
        let a = a.clone();
        tokio::spawn(async move { integrations::run(a).await })
    };
    let enrichment_task = {
        let a = a.clone();
        tokio::spawn(async move { enrichment::run(a).await })
    };
    let sinkhole_task = {
        let a = a.clone();
        tokio::spawn(async move { sinkhole::run(a).await })
    };
    let shutdown = {
        let stop = stop.clone();
        async move {
            #[cfg(unix)]
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            #[cfg(unix)]
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{},_=async {while !stop.load(Ordering::Relaxed){tokio::time::sleep(Duration::from_millis(100)).await;}}=>{}}
            #[cfg(windows)]
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=async {while !stop.load(Ordering::Relaxed)&&!service_host::stopping(){tokio::time::sleep(Duration::from_millis(100)).await;}}=>{}}
            stop.store(true, Ordering::Relaxed);
        }
    };
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown_task = tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    let result = if let Some(tls) = tls {
        axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle)
            .serve(router(a.clone()).into_make_service())
            .await
    } else {
        axum_server::from_tcp(listener)?
            .handle(handle)
            .serve(router(a.clone()).into_make_service())
            .await
    };
    shutdown_task.abort();
    stop.store(true, Ordering::Relaxed);
    integrations_task.abort();
    enrichment_task.abort();
    sinkhole_task.abort();
    let _ = capture_thread.join();
    let _ = table_thread.join();
    let _ = writer_thread.join();
    let _ = integrity_thread.join();
    let _ = observer_thread.join();
    let _ = kernel_thread.join();
    let _ = ask_thread.join();
    let _ = policy_thread.join();
    let _ = threat_thread.join();
    updates.abort();
    let p = std::mem::take(&mut a.engine.lock().unwrap().pending);
    write_pending(&a, &p)?;
    result?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.get(1).is_some_and(|s| s == "service") {
        let action = args.get(2).ok_or(
            "Usage: genyra-snitch service install|start|stop|status|uninstall [--data-dir PATH]",
        )?;
        println!(
            "{}",
            genyra_common::service::manage(&env::current_exe()?, &paths::data_dir(), action)?
        );
        return Ok(());
    }
    #[cfg(windows)]
    if args.iter().any(|s| s == "--service-run") {
        service_host::dispatch()?;
        return Ok(());
    }
    run()
}

fn serde_urlencoded_query(query: &str) -> Option<HashMap<String, String>> {
    // axum's Query extractor validates and percent-decodes query values.
    let uri: axum::http::Uri = format!("/?{query}").parse().ok()?;
    axum::extract::Query::<HashMap<String, String>>::try_from_uri(&uri)
        .ok()
        .map(|q| q.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_comparison() {
        assert!(same_token("secret", "secret"));
        assert!(!same_token("secret", "secrex"));
        assert!(!same_token("secret", ""));
    }
}
