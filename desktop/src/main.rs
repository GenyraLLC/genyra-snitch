//! Native desktop: one window, one bounded I/O worker, no browser runtime.
//! A hidden/minimized window suspends polling; only the active view refreshes.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
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
        if self.read_only && matches!(job, Job::Write(..)) {
            return Err("This preview is read-only; no collector settings were changed".into());
        }
        let (method, path, body) = match job {
            Job::Read(path) => (reqwest::Method::GET, path.as_str(), None),
            Job::Write(method, path, body) => (method.clone(), path.as_str(), Some(body)),
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
}
enum Job {
    Read(String),
    Write(reqwest::Method, String, Value),
}
struct Reply {
    path: String,
    result: Result<Value, String>,
    mutation: bool,
}
struct Worker {
    jobs: mpsc::SyncSender<Job>,
    replies: mpsc::Receiver<Reply>,
    busy: bool,
}
impl Worker {
    fn new(connection: Connection, ctx: egui::Context) -> Self {
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
                    };
                    let result = connection.request(&client, &job);
                    if completed
                        .send(Reply {
                            path,
                            result,
                            mutation,
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
    worker: Worker,
    panel: usize,
    values: BTreeMap<String, Value>,
    refresh: Instant,
    paused: bool,
    filter: String,
    selected: Option<Value>,
    message: String,
    failure: bool,
    kind: String,
    target: String,
    action: String,
    rate: u64,
    pid: u32,
    seconds: u64,
    rule: Value,
    settings: Value,
    settings_dirty: bool,
    child: Option<OwnedCollector>,
    stop: Arc<AtomicBool>,
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
        Self {
            worker: Worker::new(connection, cc.egui_ctx.clone()),
            panel: 0,
            values: BTreeMap::new(),
            refresh: Instant::now() - Duration::from_secs(10),
            paused: false,
            filter: String::new(),
            selected: None,
            message: String::new(),
            failure: false,
            kind: "ip".into(),
            target: String::new(),
            action: "block".into(),
            rate: 64,
            pid: 0,
            seconds: 5,
            rule: json!({"name":"New rule","field":"remote_ip","op":"cidr","value":"","severity":"warning","enabled":true}),
            settings: json!({}),
            settings_dirty: false,
            child,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
    fn current(&self) -> Value {
        self.values
            .get(PANELS[self.panel].1)
            .cloned()
            .unwrap_or(Value::Null)
    }
    fn matches(&self, value: &Value) -> bool {
        self.filter.is_empty()
            || value
                .to_string()
                .to_lowercase()
                .contains(&self.filter.to_lowercase())
    }
    fn graph(&mut self, ui: &mut egui::Ui, map: bool) {
        let value = self.current();
        let nodes: Vec<_> = value["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|n| n["id"] != "local" && self.matches(n))
            .collect();
        ui.label(
            RichText::new(format!(
                "{} connections · click a destination to investigate",
                nodes.len()
            ))
            .color(MUTED),
        );
        let (response, painter) = ui.allocate_painter(
            Vec2::new(ui.available_width(), ui.available_height().max(240.)),
            egui::Sense::click(),
        );
        let rect = response.rect.shrink(28.);
        let center = rect.center();
        if map {
            for i in 0..=6 {
                let x = egui::lerp(rect.x_range(), i as f32 / 6.);
                painter.line_segment(
                    [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
                    egui::Stroke::new(1_f32, Color32::from_gray(35)),
                );
            }
            for i in 0..=4 {
                let y = egui::lerp(rect.y_range(), i as f32 / 4.);
                painter.line_segment(
                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                    egui::Stroke::new(1_f32, Color32::from_gray(35)),
                );
            }
        } else {
            painter.circle_filled(center, 26., Color32::from_rgb(49, 43, 29));
            painter.text(
                center,
                egui::Align2::CENTER_CENTER,
                "LOCAL",
                egui::FontId::proportional(12.),
                GOLD,
            );
        }
        let shown = nodes.len().min(256);
        for (index, node) in nodes.into_iter().take(shown).enumerate() {
            let point = if map {
                let (Some(lon), Some(lat)) = (node["lon"].as_f64(), node["lat"].as_f64()) else {
                    continue;
                };
                egui::pos2(
                    rect.left() + (lon as f32 + 180.) / 360. * rect.width(),
                    rect.top() + (90. - lat as f32) / 180. * rect.height(),
                )
            } else {
                let angle = index as f32 * std::f32::consts::TAU / shown.max(1) as f32;
                let radius = rect.width().min(rect.height()) * 0.42;
                center + Vec2::new(angle.cos(), angle.sin()) * radius
            };
            let color = match node["category"].as_str().unwrap_or("") {
                "tracking" => Color32::from_rgb(234, 112, 96),
                "local" => MUTED,
                _ => GOLD,
            };
            if !map {
                painter.line_segment(
                    [center, point],
                    egui::Stroke::new(1_f32, Color32::from_gray(48)),
                );
            }
            painter.circle_filled(point, 5., color);
            let hit = egui::Rect::from_center_size(point, Vec2::splat(18.));
            let item = ui.interact(hit, response.id.with(index), egui::Sense::click());
            item.clone().on_hover_text(format!(
                "{}\n{} · {}",
                node["label"].as_str().unwrap_or(""),
                node["ip"].as_str().unwrap_or(""),
                human_bytes(node["bytes"].as_u64().unwrap_or(0))
            ));
            if item.clicked() {
                self.selected = Some(node.clone());
            }
        }
    }
    fn connections(&mut self, ui: &mut egui::Ui) {
        let value = self.current();
        let mut apps: BTreeMap<String, (u64, usize)> = BTreeMap::new();
        for node in value["nodes"].as_array().into_iter().flatten() {
            for (name, counts) in node["processes"].as_object().into_iter().flatten() {
                let app = apps.entry(name.clone()).or_default();
                app.0 += counts["bytes"].as_u64().unwrap_or(0);
                app.1 += 1;
            }
        }
        let entries: Vec<_> = apps
            .into_iter()
            .filter(|(name, _)| name.to_lowercase().contains(&self.filter.to_lowercase()))
            .collect();
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::remainder())
            .column(egui_extras::Column::auto())
            .column(egui_extras::Column::auto())
            .header(28., |mut row| {
                for label in ["Application", "Destinations", "Transferred"] {
                    row.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|body| {
                body.rows(30., entries.len(), |mut row| {
                    let (name, (bytes, count)) = &entries[row.index()];
                    row.col(|ui| {
                        ui.label(name);
                    });
                    row.col(|ui| {
                        ui.label(count.to_string());
                    });
                    row.col(|ui| {
                        ui.label(human_bytes(*bytes));
                    });
                })
            });
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
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        while let Ok(reply) = self.worker.replies.try_recv() {
            self.worker.busy = false;
            match reply.result {
                Ok(value) => {
                    self.failure = false;
                    if reply.mutation {
                        // Semantic failures can be HTTP 200. Surface them.
                        self.failure = value["ok"] == false || value["rule"]["applied"] == false;
                        self.message = if self.failure {
                            value["error"]
                                .as_str()
                                .or(value["rule"]["error"].as_str())
                                .unwrap_or("The operation did not complete")
                                .into()
                        } else {
                            "Saved locally".into()
                        };
                        self.values.insert("last_action".into(), value);
                        self.refresh = Instant::now() - Duration::from_secs(10);
                    } else {
                        if reply.path == "/settings" && !self.settings_dirty {
                            self.settings = value.clone();
                        }
                        self.values.insert(reply.path, value);
                    }
                }
                Err(error) => {
                    self.message = error;
                    self.failure = true;
                }
            }
        }
        let hidden = ctx.input(|i| i.viewport().minimized.unwrap_or(false));
        if !hidden
            && !self.paused
            && !self.worker.busy
            && self.refresh.elapsed() >= Duration::from_secs(2)
        {
            self.worker.send(Job::Read(PANELS[self.panel].1.into()));
            self.refresh = Instant::now();
        }
        // No continuously running animation or redraw loop. Visible views
        // wake at the chosen polling rate; worker replies wake immediately.
        if !hidden && !self.paused {
            ctx.request_repaint_after(Duration::from_secs(2));
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
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.checkbox(&mut self.paused, "Pause refresh");
                        ui.label(RichText::new("NATIVE RUST · PREVIEW").small().color(MUTED));
                    });
                });
            });
        egui::SidePanel::left("navigation")
            .exact_width(185.)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(12.);
                for (index, (name, _)) in PANELS.iter().enumerate() {
                    if ui.selectable_label(self.panel == index, *name).clicked() {
                        self.panel = index;
                        self.filter.clear();
                        self.refresh = Instant::now() - Duration::from_secs(10);
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
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
                    ui.spinner();
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
                6 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.firewall(ui));
                }
                7 => {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        edit_value(ui, "New alert rule", &mut self.rule);
                        if ui
                            .add_enabled(!self.worker.busy, egui::Button::new("Add alert rule"))
                            .clicked()
                        {
                            self.worker.write("/alerts/rules", self.rule.clone());
                        }
                        show_value(ui, "Existing rules", &self.current());
                    });
                }
                8 => {
                    egui::ScrollArea::vertical().show(ui, |ui| self.investigation(ui));
                }
                11 => {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if ui
                            .add_enabled(
                                self.settings_dirty && !self.worker.busy,
                                egui::Button::new("Save settings"),
                            )
                            .clicked()
                        {
                            self.worker.write("/settings", self.settings.clone());
                            self.settings_dirty = false;
                        }
                        self.settings_dirty |= edit_value(ui, "Preferences", &mut self.settings);
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
        self.child.take();
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
    s.replace('_', " ")
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
            for (i, value) in items.iter_mut().enumerate() {
                changed |= edit_value(ui, &i.to_string(), value);
            }
        }
        Value::Bool(v) => changed = ui.checkbox(v, "").changed(),
        Value::String(v) => {
            changed = ui
                .add(egui::TextEdit::singleline(v).password(
                    label.contains("key") || label.contains("token") || label.contains("secret"),
                ))
                .changed()
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
    if let Some(path) = std::env::var_os("SNITCH_DATA_DIR") {
        return path.into();
    }
    #[cfg(windows)]
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default());
    #[cfg(target_os = "macos")]
    let base = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support");
    #[cfg(not(any(windows, target_os = "macos")))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        });
    base.join("genyra-snitch")
}
struct OwnedCollector {
    child: std::process::Child,
    connection: Connection,
}
impl Drop for OwnedCollector {
    fn drop(&mut self) {
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
    if args.iter().any(|a| a == "--version") {
        println!("Genyra Snitch native desktop {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let arg = |name: &str| args.windows(2).find(|a| a[0] == name).map(|a| a[1].clone());
    let (mut connection, child) = if let Some(base) = arg("--connect") {
        let token_path = arg("--token-file")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir().join("api_token.txt"));
        (
            Connection::new(base, std::fs::read_to_string(token_path)?.trim().into())?,
            None,
        )
    } else {
        // Random loopback port and ephemeral token; no desktop machine settings
        // are compiled into or published with the application.
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let name = if cfg!(windows) {
            "genyra-snitch.exe"
        } else {
            "genyra-snitch"
        };
        let backend = std::env::current_exe()?
            .parent()
            .ok_or("Executable directory missing")?
            .join(name);
        if !backend.is_file() {
            return Err("Place the collector binary beside the native desktop, or use --connect and --token-file".into());
        }
        let mut command = std::process::Command::new(backend);
        command
            .env("SNITCH_PORT", port.to_string())
            .env("SNITCH_TOKEN", &token)
            .env("SNITCH_DATA_DIR", data_dir());
        if args.iter().any(|a| a == "--demo") {
            command.arg("--demo");
        }
        let child = command.spawn()?;
        let connection = Connection::new(format!("http://127.0.0.1:{port}"), token)?;
        let owned = OwnedCollector {
            child,
            connection: connection.clone(),
        };
        (connection, Some(owned))
    };
    connection.read_only = args.iter().any(|arg| arg == "--read-only");
    let icon =
        eframe::icon_data::from_png_bytes(include_bytes!("../../ui/public/brand/genyra-icon.png"))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320., 850.])
            .with_min_inner_size([960., 640.])
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "Genyra Snitch",
        options,
        Box::new(move |cc| Ok(Box::new(Desktop::new(cc, connection, child)))),
    )?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Genyra Snitch: {error}");
        std::process::exit(1);
    }
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
