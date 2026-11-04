//! Native desktop: one window, one bounded I/O worker, no browser runtime.
//! A hidden/minimized window suspends polling; only the active view refreshes.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod feed;
mod install;
mod lifecycle;
mod performance;
mod scene;
mod views;
mod workflows;
use eframe::egui::{self, Color32, RichText, Vec2};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Read,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
const GOLD: Color32 = Color32::from_rgb(219, 184, 101);
const MUTED: Color32 = Color32::from_rgb(145, 153, 168);
const MAX_REPLY: u64 = 16 * 1024 * 1024;
const PANELS: &[(&str, &str)] = &[
    ("Network", "/graph"),
    ("World map", "/graph"),
    ("Applications", "/graph"),
    ("LAN devices", "/devices"),
    ("Alerts", "/alerts"),
    ("Timeline", "/timeline"),
    ("Firewall", "/firewall/status"),
    ("Rules", "/alerts/rules"),
    ("Investigation", "/security/integrity"),
    ("Security audit", "/security/audit"),
    ("Agents", "/ingest/agents"),
    ("Settings", "/settings"),
    ("Diagnostics", "/diagnostics"),
    ("Tools & integrations", "/security/ti"),
    ("Exports", "/capture/status"),
    ("Live packets", "/graph"),
];

#[derive(Clone)]
struct Connection {
    base: String,
    token: String,
    read_only: bool,
}
impl Connection {
    fn new(base: String, token: String) -> Result<Self, String> {
        let url = reqwest::Url::parse(&base).map_err(|e| e.to_string())?;
        // Local API tokens never leave loopback, including through redirects.
        if url.scheme() != "http"
            || ![Some("127.0.0.1"), Some("localhost"), Some("[::1]")].contains(&url.host_str())
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || token.len() < 16
        {
            return Err("Use a loopback HTTP address and a valid local API token".into());
        }
        Ok(Self {
            base: base.trim_end_matches('/').into(),
            token,
            read_only: false,
        })
    }
    fn request(&self, client: &reqwest::blocking::Client, job: &Job) -> Result<Value, String> {
        if self.read_only && matches!(job, Job::Write(method,..) if *method!=reqwest::Method::GET) {
            return Err("This preview is read-only; no collector settings were changed".into());
        }
        let (method, path, body) = match job {
            Job::Read(path) => (reqwest::Method::GET, path.as_str(), None),
            Job::Write(method, path, body) => (
                method.clone(),
                path.as_str(),
                if *method == reqwest::Method::GET {
                    None
                } else {
                    Some(body)
                },
            ),
            _ => return Err("Internal request type mismatch".into()),
        };
        if !path.starts_with('/') || path.starts_with("//") {
            return Err("Invalid local resource".into());
        }
        let mut request = client
            .request(method, format!("{}{path}", self.base))
            .header("X-Snitch-Token", &self.token);
        request = request.timeout(if matches!(job, Job::Read(_)) {
            Duration::from_secs(8)
        } else {
            Duration::from_secs(75)
        });
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|e| format!("Collector unavailable: {e}"))?;
        let status = response.status();
        let mut bytes = vec![];
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_REPLY {
            return Err("Collector response exceeds the desktop memory limit".into());
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "Collector returned an invalid response".to_string())?;
        if !status.is_success() {
            return Err(value["detail"]
                .as_str()
                .unwrap_or("Request rejected")
                .into());
        }
        Ok(value)
    }
    fn download(
        &self,
        client: &reqwest::blocking::Client,
        path: &str,
        destination: &std::path::Path,
    ) -> Result<Value, String> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err("Invalid local export resource".into());
        }
        let parent = destination.parent().ok_or("Choose an export directory")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let response = client
            .get(format!("{}{path}", self.base))
            .header("X-Snitch-Token", &self.token)
            .timeout(Duration::from_secs(30))
            .send()
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Export rejected ({})", response.status()));
        }
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        let bytes = std::io::copy(&mut response.take(64 * 1024 * 1024 + 1), &mut file)
            .map_err(|e| e.to_string())?;
        if bytes > 64 * 1024 * 1024 {
            return Err("Export exceeds the desktop's 64 MiB file limit".into());
        }
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist_noclobber(destination)
            .map_err(|e| e.error.to_string())?;
        Ok(json!({"ok":true,"saved_to":destination,"bytes":bytes}))
    }
}
enum Job {
    Read(String),
    Write(reqwest::Method, String, Value),
    ReadMany(Vec<String>),
    Download(String, PathBuf),
    Service(String, Option<OwnedCollector>),
}
struct Reply {
    path: String,
    result: Result<Value, String>,
    mutation: bool,
    connection: Option<Connection>,
}
struct Worker {
    jobs: mpsc::SyncSender<Job>,
    replies: mpsc::Receiver<Reply>,
    busy: bool,
}
impl Worker {
    fn new(mut connection: Connection, ctx: egui::Context) -> Self {
        let (jobs, pending) = mpsc::sync_channel::<Job>(1);
        let (completed, replies) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("desktop-io".into())
            .spawn(move || {
                let client = match reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(75))
                    .connect_timeout(Duration::from_secs(3))
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .build()
                {
                    Ok(client) => client,
                    Err(_) => return,
                };
                while let Ok(job) = pending.recv() {
                    let (path, mutation) = match &job {
                        Job::Read(path) => (path.clone(), false),
                        Job::Write(_, path, _) => (path.clone(), true),
                        Job::ReadMany(_) => ("bundle".into(), false),
                        Job::Download(_, _) => ("export".into(), true),
                        Job::Service(_, _) => ("service".into(), true),
                    };
                    let mut reconnect=None;
                    let result = match job {
                        Job::Download(path, file) => connection.download(&client, &path, &file),
                        Job::Service(action, foreground) => {
                            if connection.read_only {
                                Err("Service controls are disabled in this read-only preview"
                                    .into())
                            } else {
                                drop(foreground);
                                lifecycle::service_action(&action).and_then(|message|{
                                    if action=="start" {
                                        let deadline=Instant::now()+Duration::from_secs(10);
                                        loop {
                                            if let Ok((new_connection,_))=lifecycle::discover(&data_dir(),&connection.token) {
                                                connection=new_connection.clone();reconnect=Some(new_connection);break;
                                            }
                                            if Instant::now()>deadline{return Err("The service start was requested but the collector did not become reachable. Check Service status and capture permissions.".into());}
                                            std::thread::sleep(Duration::from_millis(100));
                                        }
                                    }
                                    let installed=action!="uninstall"&&!message.contains("LoadState=not-found");
                                    Ok(json!({"ok":true,"message":message,"installed":installed}))
                                })
                            }
                        }
                        Job::ReadMany(paths) => {
                            let mut values = serde_json::Map::new();
                            for path in paths.iter().take(8) {
                                let result = connection
                                    .request(&client, &Job::Read(path.clone()))
                                    .unwrap_or_else(|error| json!({"error":error}));
                                values.insert(path.clone(), result);
                            }
                            Ok(Value::Object(values))
                        }
                        job => connection.request(&client, &job),
                    };
                    if completed
                        .send(Reply {
                            path,
                            result,
                            mutation,
                            connection: reconnect,
                        })
                        .is_err()
                    {
                        break;
                    }
                    ctx.request_repaint();
                }
            })
            .expect("desktop I/O worker");
        Self {
            jobs,
            replies,
            busy: false,
        }
    }
    fn send(&mut self, job: Job) {
        if !self.busy && self.jobs.try_send(job).is_ok() {
            self.busy = true;
        }
    }
    fn write(&mut self, path: &str, body: Value) {
        self.send(Job::Write(reqwest::Method::POST, path.into(), body));
    }
}

struct Desktop {
    feed: feed::Feed,
    live: feed::State,
    feed_connected: bool,
    worker: Worker,
    scene: scene::Scene,
    workflows: workflows::Workflows,
    views: views::Views,
    panel: usize,
    values: BTreeMap<String, Value>,
    refresh: Instant,
    paused: bool,
    filter: String,
    selected: Option<Value>,
    message: String,
    failure: bool,
    last_action_path: String,
    background_error: bool,
    kind: String,
    target: String,
    action: String,
    rate: u64,
    pid: u32,
    seconds: u64,
    rule: Value,
    settings: Value,
    settings_dirty: bool,
    preferences_saving: bool,
    read_only: bool,
    last_capture_check: Instant,
    capture_path: Option<PathBuf>,
    capture_after: Instant,
    capture_requested: bool,
    quit_after_capture: bool,
    child: Option<OwnedCollector>,
    keep_monitoring: bool,
    local_service_controls: bool,
    service_registration_present: bool,
    stop: Arc<AtomicBool>,
    performance: Option<performance::Probe>,
}
impl Desktop {
    fn new(
        cc: &eframe::CreationContext<'_>,
        connection: Connection,
        child: Option<OwnedCollector>,
    ) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(15, 18, 24);
        visuals.window_fill = Color32::from_rgb(22, 26, 34);
        visuals.selection.bg_fill = Color32::from_rgb(77, 64, 38);
        visuals.selection.stroke.color = GOLD;
        cc.egui_ctx.set_visuals(visuals);
        let mut style = (*cc.egui_ctx.style()).clone();
        for (kind, size) in [
            (egui::TextStyle::Heading, 24.),
            (egui::TextStyle::Body, 16.),
            (egui::TextStyle::Button, 15.),
            (egui::TextStyle::Small, 12.),
        ] {
            style
                .text_styles
                .insert(kind, egui::FontId::proportional(size));
        }
        style.spacing.item_spacing = Vec2::new(10., 7.);
        cc.egui_ctx.set_style(style);
        let read_only = connection.read_only;
        let local_service_controls = child.is_some()
            || genyra_common::endpoint(&data_dir())
                .is_ok_and(|endpoint| endpoint.url == connection.base);
        Self {
            feed: feed::Feed::new(connection.clone(), cc.egui_ctx.clone()),
            live: feed::State::default(),
            feed_connected: false,
            performance: None,
            worker: Worker::new(connection, cc.egui_ctx.clone()),
            scene: scene::Scene::default(),
            workflows: workflows::Workflows::default(),
            views: views::Views::default(),
            panel: 0,
            values: BTreeMap::new(),
            refresh: Instant::now() - Duration::from_secs(10),
            paused: false,
            filter: String::new(),
            selected: None,
            message: String::new(),
            failure: false,
            last_action_path: String::new(),
            background_error: false,
            kind: "ip".into(),
            target: String::new(),
            action: "block".into(),
            rate: 64,
            pid: 0,
            seconds: 5,
            rule: json!({"name":"New rule","field":"remote_ip","op":"cidr","value":"","severity":"warning","action":"alert","enabled":true}),
            settings: workflows::preferences(&Value::Null),
            settings_dirty: false,
            preferences_saving: false,
            read_only,
            last_capture_check: Instant::now() - Duration::from_secs(15),
            capture_path: None,
            capture_after: Instant::now() + Duration::from_secs(5),
            capture_requested: false,
            quit_after_capture: false,
            child,
            keep_monitoring: genyra_common::DesktopPreferences::load(&data_dir()).keep_monitoring,
            local_service_controls,
            service_registration_present: false,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
    fn current(&self) -> Value {
        self.values
            .get(PANELS[self.panel].1)
            .cloned()
            .unwrap_or(Value::Null)
    }
    fn accept_data(&mut self, path: String, value: Value) {
        let path = path.split('?').next().unwrap_or(&path).to_string();
        if path == "/settings" && value["settings"].is_object() {
            self.workflows.load_settings(&value["settings"]);
            if !self.settings_dirty {
                self.settings = workflows::preferences(&value["settings"]);
            }
        }
        if path == "/graph" {
            self.scene.ingest(&value);
            self.views.update_graph(&value);
        }
        self.values.insert(path, value);
    }
    fn read_job(&self) -> Job {
        match self.panel {
            5 => Job::Read(format!("/timeline?minutes={}", self.views.minutes)),
            10 => Job::ReadMany(vec!["/ingest/agents".into(), "/remote/fleet".into()]),
            11 => Job::ReadMany(vec![
                "/settings".into(),
                "/capture/interfaces".into(),
                "/geo/status".into(),
                "/media".into(),
            ]),
            13 => self.workflows.read_job(),
            _ => Job::Read(PANELS[self.panel].1.into()),
        }
    }
    fn graph(&mut self, ui: &mut egui::Ui, map: bool) {
        if let Some(id) = self.scene.show(ui, map, &self.filter, !self.paused) {
            self.selected = self
                .values
                .get("/graph")
                .and_then(|graph| graph["nodes"].as_array())
                .and_then(|nodes| nodes.iter().find(|node| node["id"] == id))
                .cloned();
        }
    }
    fn connections(&mut self, ui: &mut egui::Ui) {
        self.native_apps(ui);
    }
    fn firewall(&mut self, ui: &mut egui::Ui) {
        let value = self.current();
        if value["supported"] == false {
            ui.colored_label(
                Color32::LIGHT_RED,
                "The operating system firewall provider is unavailable.",
            );
        }
        ui.horizontal(|ui| {
            ui.label("New rule");choice(ui,"kind",&mut self.kind,&["ip","cidr","domain","port","process"]);
            ui.text_edit_singleline(&mut self.target);
            choice(ui,"action",&mut self.action,&["block","throttle","sinkhole"]);
            if self.action == "throttle" {ui.add(egui::DragValue::new(&mut self.rate).range(1..=10000000).suffix(" kbit/s"));}
            if ui.add_enabled(!self.worker.busy&&!self.target.trim().is_empty(),egui::Button::new("Add rule")).clicked() {
                self.worker.write("/firewall/rules",json!({"kind":self.kind,"value":self.target.trim(),"action":self.action,"rate":self.rate}));
            }
        });
        ui.horizontal(|ui| {
            let mut lockdown = value["lockdown"] == true;
            if ui
                .checkbox(&mut lockdown, "Lockdown: block external connections")
                .changed()
            {
                self.worker
                    .write("/firewall/lockdown", json!({"on":lockdown}));
            }
            for profile in ["balanced", "strict", "permissive"] {
                if ui.button(format!("Apply {profile}")).clicked() {
                    self.worker
                        .write("/firewall/profile", json!({"name":profile}));
                }
            }
        });
        ui.separator();
        for rule in value["rules"].as_array().into_iter().flatten() {
            ui.horizontal(|ui| {
                let mut enabled = rule["enabled"] != false;
                let id = rule["id"].as_str().unwrap_or("");
                if ui.checkbox(&mut enabled, "").changed() {
                    self.worker.write(
                        &format!("/firewall/rules/{id}/toggle"),
                        json!({"enabled":enabled}),
                    );
                }
                ui.label(format!(
                    "{} {} · {}",
                    text(&rule["kind"]),
                    text(&rule["value"]),
                    text(&rule["action"])
                ));
                if rule["applied"] == false {
                    ui.colored_label(Color32::LIGHT_RED, "Not enforced")
                        .on_hover_text(text(&rule["error"]));
                }
                if ui.small_button("Remove").clicked() {
                    self.worker.send(Job::Write(
                        reqwest::Method::DELETE,
                        format!("/firewall/rules/{id}"),
                        json!({}),
                    ));
                }
            });
        }
    }
    fn investigation(&mut self, ui: &mut egui::Ui) {
        ui.label("Inspect a process you own. OS permissions apply to memory and instrumentation.");
        ui.horizontal(|ui| {
            ui.label("Process ID");
            ui.add(egui::DragValue::new(&mut self.pid).range(1..=u32::MAX));
            ui.label("Duration");
            ui.add(
                egui::DragValue::new(&mut self.seconds)
                    .range(1..=60)
                    .suffix(" s"),
            );
        });
        ui.add_enabled_ui(self.pid > 0 && !self.worker.busy, |ui| {
            ui.horizontal_wrapped(|ui| {
                for (label, path) in [
                    ("Check integrity", "/security/integrity/check"),
                    ("Inspect calls", "/security/deep_inspect"),
                    ("Compare memory", "/security/hollow"),
                    ("Hardware counters", "/security/perf"),
                ] {
                    if ui.button(label).clicked() {
                        self.worker
                            .write(path, json!({"pid":self.pid,"seconds":self.seconds}));
                    }
                }
            });
        });
        ui.separator();
        show_value(ui, "integrity", &self.current());
        if let Some(value) = self.values.get("last_action") {
            ui.separator();
            show_value(ui, "Inspection result", value);
        }
    }
}

impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if let Some(probe) = &mut self.performance {
            probe.frame(frame.info().cpu_usage);
        }
        while let Ok(value) = self.feed.messages.try_recv() {
            let kind = value["type"].as_str().unwrap_or("");
            if kind == "feed_error" {
                self.feed_connected = false;
                continue;
            }
            if ["init", "reset"].contains(&kind) {
                self.scene.reset_traffic();
                self.feed_connected = true;
            }
            if self.live.apply(&value) {
                if self.panel < 3 || !self.values.contains_key("/graph") {
                    self.accept_data("/graph".into(), self.live.graph());
                }
                self.values
                    .insert("/alerts".into(), json!({"alerts":self.live.alerts}));
            }
            if kind == "capture_status" || kind == "init" {
                self.values.insert("/capture/status".into(), value);
            }
        }
        if self.capture_path.is_some() {
            for event in ctx.input(|i| i.events.clone()) {
                if let egui::Event::Screenshot { image, .. } = event {
                    let path = self.capture_path.take().unwrap();
                    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                        use image::ImageEncoder;
                        let mut options = std::fs::OpenOptions::new();
                        options.write(true).create_new(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            options.mode(0o600);
                        }
                        let file = options.open(path)?;
                        let bytes: Vec<u8> =
                            image.pixels.iter().flat_map(|p| p.to_array()).collect();
                        image::codecs::png::PngEncoder::new(file).write_image(
                            &bytes,
                            image.width() as u32,
                            image.height() as u32,
                            image::ExtendedColorType::Rgba8,
                        )?;
                        Ok(())
                    })();
                    if let Err(error) = result {
                        eprintln!("Renderer capture: {error}");
                    }
                    if self.quit_after_capture {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            if !self.capture_requested
                && self.values.contains_key(PANELS[self.panel].1)
                && Instant::now() > self.capture_after
            {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
                self.capture_requested = true;
            }
        }
        while let Ok(reply) = self.worker.replies.try_recv() {
            self.worker.busy = false;
            if let Some(connection) = reply.connection {
                self.feed = feed::Feed::new(connection, ctx.clone());
                self.live = feed::State::default();
                self.feed_connected = false;
                self.scene.reset_traffic();
            }
            match reply.result {
                Ok(value) => {
                    if reply.mutation {
                        if reply.path == "service" && value["ok"] == true {
                            self.service_registration_present = value["installed"] == true;
                        }
                        self.background_error = false;
                        self.last_action_path = reply.path.clone();
                        // Semantic failures can be HTTP 200. Surface them.
                        self.failure = value["ok"] == false || value["rule"]["applied"] == false;
                        self.message = if self.failure {
                            value["error"]
                                .as_str()
                                .or(value["rule"]["error"].as_str())
                                .unwrap_or("The operation did not complete")
                                .into()
                        } else {
                            "Complete".into()
                        };
                        self.values.insert("last_action".into(), value);
                        if reply.path == "/settings" && self.preferences_saving {
                            if !self.failure {
                                self.settings_dirty = false;
                            }
                            self.preferences_saving = false;
                        }
                        self.refresh = Instant::now() - Duration::from_secs(10);
                    } else {
                        if self.background_error {
                            self.failure = false;
                            self.message = "Connected to collector".into();
                            self.background_error = false;
                        }
                        if reply.path == "bundle" {
                            if let Value::Object(values) = value {
                                for (path, value) in values {
                                    self.accept_data(path, value);
                                }
                            }
                        } else {
                            self.accept_data(reply.path, value);
                        }
                    }
                }
                Err(error) => {
                    self.message = error;
                    self.failure = true;
                    self.background_error = !reply.mutation;
                    if reply.path == "/settings" {
                        self.preferences_saving = false;
                    }
                }
            }
        }
        let hidden = ctx.input(|i| i.viewport().minimized.unwrap_or(false));
        self.feed.set_active(!hidden && !self.paused);
        if hidden {
            return;
        }
        if !hidden
            && !self.paused
            && !self.worker.busy
            && self.refresh.elapsed() >= Duration::from_secs(if self.panel < 3 { 1 } else { 2 })
        {
            if self.last_capture_check.elapsed() >= Duration::from_secs(10) {
                self.worker.send(Job::Read("/capture/status".into()));
                self.last_capture_check = Instant::now();
            } else {
                if !(self.feed_connected && matches!(self.panel, 0..=2 | 15)) {
                    self.worker.send(self.read_job());
                }
            }
            self.refresh = Instant::now();
        }
        // No continuously running animation or redraw loop. Visible views
        // wake at the chosen polling rate; worker replies wake immediately.
        if !hidden && !self.paused {
            ctx.request_repaint_after(Duration::from_secs(if self.panel < 3 { 1 } else { 2 }));
        }
        egui::TopBottomPanel::top("header")
            .exact_height(78.)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add(
                        egui::Image::new(egui::include_image!(
                            "../../ui/public/brand/genyra-light.png"
                        ))
                        .fit_to_exact_size(Vec2::new(188., 30.)),
                    );
                    ui.separator();
                    ui.heading(RichText::new("Snitch").color(GOLD));
                    if let Some(status) = self.values.get("/capture/status") {
                        let capturing = status["capturing"] == true;
                        ui.colored_label(
                            if capturing {
                                Color32::from_rgb(99, 193, 143)
                            } else {
                                MUTED
                            },
                            if capturing {
                                "Capturing"
                            } else {
                                "Capture stopped"
                            },
                        );
                        ui.label(
                            RichText::new(status["interface"].as_str().unwrap_or(""))
                                .small()
                                .color(MUTED),
                        );
                        if !self.read_only
                            && ui
                                .add_enabled(
                                    !self.worker.busy,
                                    egui::Button::new(if capturing {
                                        "Stop capture"
                                    } else {
                                        "Start capture"
                                    }),
                                )
                                .clicked()
                        {
                            self.worker.write(
                                if capturing {
                                    "/capture/stop"
                                } else {
                                    "/capture/start"
                                },
                                json!({}),
                            );
                            self.last_capture_check = Instant::now() - Duration::from_secs(15);
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.checkbox(&mut self.paused, "Pause live view");
                        ui.label(
                            RichText::new(if self.read_only {
                                "READ-ONLY PREVIEW"
                            } else {
                                "NATIVE RUST · PREVIEW"
                            })
                            .small()
                            .color(MUTED),
                        );
                    });
                });
            });
        egui::SidePanel::left("navigation")
            .exact_width(185.)
            .resizable(false)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("navigation-scroll")
                    .show(ui, |ui| {
                        ui.add_space(12.);
                        for (index, (name, _)) in PANELS.iter().enumerate() {
                            if [0, 4, 10].contains(&index) {
                                ui.add_space(12.);
                                ui.label(
                                    RichText::new(match index {
                                        0 => "VISIBILITY",
                                        4 => "SECURITY",
                                        _ => "WORKSPACE",
                                    })
                                    .size(10.)
                                    .color(MUTED),
                                );
                                ui.add_space(5.);
                            }
                            if ui
                                .add_sized(
                                    [162., 29.],
                                    egui::Button::new(*name)
                                        .selected(self.panel == index)
                                        .frame(self.panel == index),
                                )
                                .clicked()
                            {
                                self.panel = index;
                                if index < 3 && self.feed_connected {
                                    self.accept_data("/graph".into(), self.live.graph());
                                }
                                self.filter.clear();
                                self.refresh = Instant::now() - Duration::from_secs(10);
                            }
                        }
                        ui.add_space(18.);
                        ui.label(
                            RichText::new("Genyra LLC\nLocal traffic stays local")
                                .small()
                                .color(MUTED),
                        );
                    });
            });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.worker.busy {
                    ui.label("Working…");
                }
                ui.colored_label(
                    if self.failure {
                        Color32::LIGHT_RED
                    } else {
                        MUTED
                    },
                    &self.message,
                );
            });
        });
        if let Some(node) = self.selected.clone() {
            egui::SidePanel::right("details")
                .exact_width(300.)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Destination");
                        if ui.small_button("Close").clicked() {
                            self.selected = None;
                        }
                    });
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        show_value(ui, "destination", &node);
                        if ui
                            .add_enabled(!self.worker.busy, egui::Button::new("Block this IP"))
                            .clicked()
                        {
                            self.worker.write(
                                "/firewall/rules",
                                json!({"kind":"ip","value":node["ip"],"action":"block"}),
                            );
                        }
                    });
                });
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(PANELS[self.panel].0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter).hint_text("Filter this view"),
                    );
                });
            });
            ui.separator();
            match self.panel {
                0 => self.graph(ui, false),
                1 => self.graph(ui, true),
                2 => self.connections(ui),
                3 => self.native_devices(ui),
                4 => self.native_alerts(ui),
                5 => self.native_timeline(ui),
                6 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.firewall(ui));
                }
                7 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.native_rules(ui));
                }
                8 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.investigation(ui));
                }
                10 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.native_agents(ui));
                }
                11 => {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.background_service(ui);
                        ui.separator();
                        if ui
                            .add_enabled(
                                self.settings_dirty && !self.worker.busy && !self.read_only,
                                egui::Button::new("Save settings"),
                            )
                            .clicked()
                        {
                            self.worker
                                .write("/settings", json!({"settings":self.settings}));
                            self.preferences_saving = true;
                        }
                        ui.add_enabled_ui(
                            !self.read_only
                                && self
                                    .values
                                    .get("/settings")
                                    .is_some_and(|v| v["settings"].is_object()),
                            |ui| {
                                self.native_preferences(ui);
                            },
                        );
                    });
                }
                13 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.native_tasks(ui));
                }
                14 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.native_exports(ui));
                }
                15 => {
                    ui.label("Recent packet metadata from the live collector. This view keeps the latest 128 samples.");
                    egui::ScrollArea::vertical().show(ui,|ui|{
                        for packet in self.live.packets.iter().rev() {
                            let line=format!("{}  {}:{} → {}:{}  {}  {} B",packet["process_name"].as_str().unwrap_or("Unattributed"),text(&packet["src_ip"]),text(&packet["src_port"]),text(&packet["dst_ip"]),text(&packet["dst_port"]),text(&packet["protocol"]),text(&packet["size"]));
                            if self.filter.is_empty()||line.to_lowercase().contains(&self.filter.to_lowercase()) {ui.monospace(line);}
                        }
                    });
                }
                _ => {
                    let value = self.current();
                    egui::ScrollArea::vertical().show(ui, |ui| show_value(ui, "view", &value));
                }
            }
        });
    }
    fn on_exit(&mut self, _: Option<&eframe::glow::Context>) {
        self.stop.store(true, Ordering::Relaxed);
        // Only our own backend child is stopped. Attached collectors continue.
        if let Some(mut child) = self.child.take() {
            child.keep_running = self.keep_monitoring;
            drop(child);
        }
    }
}

fn choice(ui: &mut egui::Ui, id: &str, value: &mut String, choices: &[&str]) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.as_str())
        .show_ui(ui, |ui| {
            for option in choices {
                ui.selectable_value(value, (*option).into(), *option);
            }
        });
}
fn text(v: &Value) -> String {
    v.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}
fn human_bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / 1048576.)
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.)
    } else {
        format!("{n} B")
    }
}
fn title(s: &str) -> String {
    match s {
        "retention_hours" => "History retention (hours)",
        "upload_threshold_mb" => "Upload alert threshold (MiB)",
        "integrity_watch" => "Monitor executable integrity",
        "kill_switch_enabled" => "Automatically block apps after an upload alert",
        "ports" => "Ports to monitor (empty means all)",
        "excluded_processes" => "Apps to exclude from capture",
        "whitelisted_ips" => "IP addresses to exclude from capture",
        "watchlist" => "Watched hosts and addresses",
        "ti_provider" => "Threat provider",
        "ti_api_key" => "Provider API key",
        "webhook_enabled" => "Enable webhook notifications",
        "webhook_url" => "Webhook address",
        "telegram_chat_id" => "Telegram chat ID",
        "syslog_addr" => "Syslog destination",
        "syslog_format" => "Syslog format",
        "ask_enabled" => "Ask before allowing a new connection",
        "ask_timeout" => "Decision timeout (seconds)",
        "ask_failopen" => "Allow the connection if no decision arrives",
        "ebpf_probe" => "Trace connections in the kernel (Linux)",
        "gossip_enabled" => "Enable peer indicator synchronization",
        "gossip_peers" => "Peer collector addresses",
        "slm_enabled" => "Enable local model explanations",
        "slm_mode" => "Local model engine",
        "slm_endpoint" => "Ollama address (loopback only)",
        "slm_model" => "Model name",
        "slm_model_path" => "GGUF model file",
        "conds" => "Conditions",
        "mac" => "MAC address",
        "ip" => "IP address",
        "pid" => "Process ID",
        "asn" => "Network ASN",
        _ => {
            return {
                let mut text = s.replace('_', " ");
                if let Some(first) = text.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                text
            }
        }
    }
    .into()
}
fn show_value(ui: &mut egui::Ui, label: &str, value: &Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if value.is_object() || value.is_array() {
                    egui::CollapsingHeader::new(title(key))
                        .id_salt((label, key))
                        .show(ui, |ui| show_value(ui, key, value));
                } else {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(title(key)).color(MUTED));
                        ui.label(text(value));
                    });
                }
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().take(500).enumerate() {
                egui::CollapsingHeader::new(
                    value["label"]
                        .as_str()
                        .or(value["message"].as_str())
                        .or(value["name"].as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{} {}", title(label), i + 1)),
                )
                .id_salt((label, i))
                .show(ui, |ui| show_value(ui, &i.to_string(), value));
            }
            if items.len() > 500 {
                ui.label(format!("Showing 500 of {} entries", items.len()));
            }
        }
        Value::Null => {
            ui.label("Waiting for collector…");
        }
        _ => {
            ui.label(text(value));
        }
    }
}
fn edit_value(ui: &mut egui::Ui, label: &str, value: &mut Value) -> bool {
    let mut changed = false;
    ui.push_id(label, |ui| match value {
        Value::Object(map) => {
            for (key, value) in map {
                if value.is_object() || value.is_array() {
                    egui::CollapsingHeader::new(title(key)).show(ui, |ui| {
                        changed |= edit_value(ui, key, value);
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.label(title(key));
                        changed |= edit_value(ui, key, value);
                    });
                }
            }
        }
        Value::Array(items) => {
            let mut remove = None;
            for (i, value) in items.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    changed |= edit_value(ui, &i.to_string(), value);
                    if ui.small_button("Remove").clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(index) = remove {
                items.remove(index);
                changed = true;
            }
            let limit = if label == "args" { 8 } else { 1024 };
            if ui
                .add_enabled(items.len() < limit, egui::Button::new("Add entry"))
                .clicked()
            {
                items.push(match label {
                    "ports" => json!(443),
                    "conds" => json!({"field":"remote_ip","op":"eq","value":""}),
                    _ => json!(""),
                });
                changed = true;
            }
        }
        Value::Bool(v) => changed = ui.checkbox(v, "").changed(),
        Value::String(v) => {
            let options: &[&str] = match label {
                "ti_provider" => &["none", "abuseipdb", "otx", "virustotal"],
                "slm_mode" => &["ollama", "embedded"],
                "syslog_format" => &["json", "cef"],
                "field" => &[
                    "remote_ip",
                    "host",
                    "process_name",
                    "cmdline",
                    "parent_name",
                    "remote_port",
                    "protocol",
                    "direction",
                    "size",
                    "asn",
                    "country",
                ],
                "op" => &["eq", "ne", "contains", "regex", "gt", "lt", "cidr"],
                "severity" => &["info", "warning", "critical"],
                "action" => &["alert", "block"],
                _ => &[],
            };
            if !options.is_empty() {
                let before = v.clone();
                choice(ui, label, v, options);
                changed = *v != before;
            } else if ["yaml", "text"].contains(&label) {
                changed = ui
                    .add(
                        egui::TextEdit::multiline(v)
                            .desired_rows(10)
                            .desired_width(f32::INFINITY)
                            .code_editor(),
                    )
                    .changed();
            } else {
                changed = ui
                    .add(egui::TextEdit::singleline(v).password(
                        label.contains("key")
                            || label.contains("token")
                            || label.contains("secret"),
                    ))
                    .changed();
            }
        }
        Value::Number(v) => {
            if let Some(mut n) = v.as_i64() {
                if ui.add(egui::DragValue::new(&mut n)).changed() {
                    *value = json!(n);
                    changed = true;
                }
            } else if let Some(mut n) = v.as_f64() {
                if ui.add(egui::DragValue::new(&mut n)).changed() {
                    *value = json!(n);
                    changed = true;
                }
            }
        }
        Value::Null => {
            ui.label("Not configured");
        }
    });
    changed
}
fn data_dir() -> PathBuf {
    genyra_common::data_dir()
}
struct OwnedCollector {
    child: std::process::Child,
    connection: Connection,
    keep_running: bool,
}
impl Drop for OwnedCollector {
    fn drop(&mut self) {
        if self.keep_running || self.child.try_wait().is_ok_and(|s| s.is_some()) {
            return;
        }
        if let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            let _ = client
                .post(format!("{}/shutdown", self.connection.base))
                .header("X-Snitch-Token", &self.connection.token)
                .json(&json!({}))
                .send();
        }
        // Allow the collector to flush pending SQLite history before fallback.
        for _ in 0..50 {
            if self.child.try_wait().is_ok_and(|status| status.is_some()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|a| a == "--install") {
        return install::desktop(&args).map_err(Into::into);
    }
    if args.iter().any(|a| a == "--version") {
        println!("Genyra Snitch native desktop {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let arg = |name: &str| args.windows(2).find(|a| a[0] == name).map(|a| a[1].clone());
    let connected: Result<_, Box<dyn std::error::Error>> = (|| {
        Ok(if let Some(base) = arg("--connect") {
            let token_path = arg("--token-file")
                .map(PathBuf::from)
                .unwrap_or_else(|| data_dir().join("api_token.txt"));
            (
                Connection::new(base, std::fs::read_to_string(token_path)?.trim().into())?,
                None,
            )
        } else {
            lifecycle::connect_or_start(args.iter().any(|a| a == "--demo"))?
        })
    })();
    let (mut connection, child) = match connected {
        Ok(connected) => connected,
        Err(error) => return install::startup_error(error.to_string()),
    };
    connection.read_only = args.iter().any(|arg| arg == "--read-only");
    let capture = arg("--render-check")
        .or_else(|| arg("--screenshot"))
        .map(PathBuf::from);
    let render_check = arg("--render-check").is_some();
    let performance_log = arg("--performance-log");
    let initial_panel = match arg("--view").as_deref() {
        Some("map") => 1,
        Some("apps") => 2,
        Some("devices") => 3,
        Some("alerts") => 4,
        Some("timeline") => 5,
        Some("settings") => 11,
        Some("packets") => 15,
        _ => 0,
    };
    let icon =
        eframe::icon_data::from_png_bytes(include_bytes!("../../ui/public/brand/genyra-icon.png"))?;
    let options = eframe::NativeOptions {
        // Wayland may withhold frame callbacks while a workspace is hidden.
        // NVIDIA EGL can then wait inside SwapBuffers on the UI thread,
        // preventing xdg_wm_base ping replies. Our repaint requests already
        // pace active traffic at 20 Hz; never wait for vblank on Wayland.
        vsync: desktop_vsync(render_check),
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320., 850.])
            .with_min_inner_size([960., 640.])
            .with_visible(!render_check)
            .with_app_id("com.genyra.snitch")
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "Genyra Snitch",
        options,
        Box::new(move |cc| {
            let mut app = Desktop::new(cc, connection, child);
            if let Some(path) = performance_log {
                app.performance = Some(performance::Probe::new(
                    std::path::Path::new(&path),
                    cc.egui_ctx.clone(),
                )?);
            }
            if args.iter().any(|a| a == "--background") {
                app.keep_monitoring = true;
            }
            app.panel = initial_panel;
            app.capture_path = capture;
            app.quit_after_capture = render_check;
            Ok(Box::new(app))
        }),
    )?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Genyra Snitch: {error}");
        std::process::exit(1);
    }
}

fn desktop_vsync(render_check: bool) -> bool {
    !render_check && !(cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_tokens_cannot_be_sent_to_remote_or_embedded_credentials() {
        let token = "fixture-token-long-enough".to_string();
        for url in [
            "https://example.com",
            "http://example.com",
            "http://127.0.0.1@example.com",
            "http://user@localhost:8000",
            "http://localhost:8000/?redirect=x",
            "file:///tmp/socket",
        ] {
            assert!(Connection::new(url.into(), token.clone()).is_err(), "{url}");
        }
        assert!(Connection::new("http://127.0.0.1:8000".into(), token).is_ok());
    }
    #[test]
    fn paused_or_failed_requests_do_not_accumulate_jobs() {
        let (jobs, queue) = mpsc::sync_channel(1);
        let (_reply, replies) = mpsc::sync_channel(1);
        let mut worker = Worker {
            jobs,
            replies,
            busy: false,
        };
        worker.send(Job::Read("/graph".into()));
        worker.send(Job::Read("/alerts".into()));
        assert!(matches!(queue.try_recv(),Ok(Job::Read(path)) if path=="/graph"));
        assert!(queue.try_recv().is_err());
    }
}
