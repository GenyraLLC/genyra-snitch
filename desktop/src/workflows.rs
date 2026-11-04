//! Native controls for investigation, integrations and collection. Endpoint
//! details stay here; the interface presents named tasks and typed fields.
use super::{edit_value, show_value, Desktop, Job};
use eframe::egui;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, Instant},
};

struct Task {
    name: &'static str,
    description: &'static str,
    path: &'static str,
    status: &'static [&'static str],
    defaults: Value,
    options: &'static [(&'static str, &'static [&'static str])],
    get: bool,
    settings: bool,
}
fn tasks() -> &'static [Task] {
    static TASKS: OnceLock<Vec<Task>> = OnceLock::new();
    TASKS.get_or_init(||vec![
        Task{name:"Threat intelligence",description:"Check an address with the threat provider you configured in Preferences.",path:"/security/threat_check",status:&["/security/ti"],defaults:json!({"ip":"","force":false}),options:&[],get:false,settings:false},
        Task{name:"Local model",description:"Optional local explanations. Models can use several gigabytes of memory; disabled by default.",path:"/settings",status:&["/security/slm","/settings"],defaults:json!({"slm_enabled":false,"slm_mode":"ollama","slm_endpoint":"http://127.0.0.1:11434","slm_model":"","slm_model_path":""}),options:&[("slm_mode",&["ollama","embedded"])],get:false,settings:true},
        Task{name:"Explain an alert",description:"Get the built-in explanation, with optional enrichment from your configured local model.",path:"/security/explain",status:&[],defaults:json!({"type":"NEW_HOST","detail":{},"lang":"en"}),options:&[("type",&["NEW_HOST","NEW_LAN_DEVICE","SUSPICIOUS_PORT","PORT_SCAN","UPLOAD_SPIKE","WATCHLIST_HIT","CUSTOM_RULE","BEACON","VOLUME_SPIKE","ICMP_TUNNEL","DGA_SUSPECT","SUSPICIOUS_PROCESS","MEDIA_EXFIL","CLEARTEXT","DNS_TUNNEL","HIGH_ENTROPY","PROTO_MISMATCH","MINING_SUSPECT","BASELINE_DEVIATION","ML_ANOMALY","TLS_CERT","BLOCKED_ATTEMPT"]),("lang",&["en","fr","es","de","ru","ja","pt-BR","zh-CN"])],get:false,settings:false},
        Task{name:"GeoIP databases",description:"Download public city and ASN databases for the map. Downloads require your explicit consent.",path:"/geo/download",status:&["/geo/status"],defaults:json!({"consent":false}),options:&[],get:false,settings:false},
        Task{name:"Import a blocklist",description:"Import a hosts file, domain list or IP list from a local file or a URL.",path:"/firewall/blocklist",status:&["/firewall/status"],defaults:json!({"source":"file","location":"","kind":"domain","action":"block","max_entries":500}),options:&[("source",&["file","url"]),("kind",&["domain","ip"]),("action",&["block","sinkhole"])],get:false,settings:false},
        Task{name:"Import Sigma rules",description:"Convert supported Sigma selections into native alert rules. Unsupported clauses are reported.",path:"/alerts/rules/sigma",status:&[],defaults:json!({"yaml":""}),options:&[],get:false,settings:false},
        Task{name:"Import indicators",description:"Compare an exported indicator pack against local observations.",path:"/security/iocpack/import",status:&[],defaults:json!({"pack":{}}),options:&[],get:false,settings:false},
        Task{name:"Synchronize peers",description:"Synchronize indicators with the peer addresses you explicitly configured in Preferences.",path:"/remote/ioc_sync",status:&["/remote/ioc_sync"],defaults:json!({}),options:&[],get:false,settings:false},
        Task{name:"Remote pairing",description:"Enable or disable LAN access to this collector. A bind-address change takes effect after a restart.",path:"/remote/pairing",status:&["/remote/pairing"],defaults:json!({"enabled":false,"bind":"0.0.0.0"}),options:&[],get:false,settings:false},
        Task{name:"First-connection decisions",description:"Apply a decision to a pending flow. Permanent decisions also update OS policy.",path:"/security/ask/verdict",status:&["/security/ask","/alerts"],defaults:json!({"remote_ip":"","remote_port":443,"proto":"TCP","allow":false,"permanent":false}),options:&[("proto",&["TCP","UDP"])],get:false,settings:false},
        Task{name:"Kernel destination block",description:"Block a destination for processes placed in the collector's dedicated cgroup. Linux eBPF privileges are required.",path:"/security/ebpf/block",status:&["/security/ebpf","/security/ebpf_enforce"],defaults:json!({"ip":""}),options:&[],get:false,settings:false},
        Task{name:"Kernel process isolation",description:"Place a process in the cgroup that enforces the configured eBPF destination blocks. This does not deny every connection.",path:"/security/ebpf/isolate",status:&["/security/ebpf_enforce"],defaults:json!({"pid":0}),options:&[],get:false,settings:false},
        Task{name:"Suspend or resume a process",description:"Toggle suspension for a process you own or can administer.",path:"/processes/suspend",status:&[],defaults:json!({"pid":0}),options:&[],get:false,settings:false},
        Task{name:"Terminate a process",description:"End the selected process. Unsaved work in that process can be lost.",path:"/processes/kill",status:&[],defaults:json!({"pid":0,"confirm":false}),options:&[],get:false,settings:false},
        Task{name:"Isolated execution",description:"Run an executable with network access denied by the OS sandbox. Each argument is a separate entry.",path:"/security/sandbox",status:&[],defaults:json!({"path":"","args":[],"seconds":10}),options:&[],get:false,settings:false},
        Task{name:"Traffic history",description:"Read traffic history for a host IP address or application name.",path:"history",status:&[],defaults:json!({"target":"host","value":"","minutes":60}),options:&[("target",&["host","process"])],get:true,settings:false},
    ])
}
pub(super) struct Workflows {
    selected: usize,
    drafts: BTreeMap<usize, Value>,
    dirty: std::collections::HashSet<usize>,
    json_input: String,
    pub(super) agent_name: String,
    export_format: String,
    export_path: String,
}
impl Default for Workflows {
    fn default() -> Self {
        Self {
            selected: 0,
            drafts: BTreeMap::new(),
            dirty: Default::default(),
            json_input: String::new(),
            agent_name: String::new(),
            export_format: "json".into(),
            export_path: super::data_dir()
                .join("exports")
                .to_string_lossy()
                .into_owned(),
        }
    }
}
impl Workflows {
    pub(super) fn read_job(&self) -> Job {
        let mut paths: Vec<_> = tasks()[self.selected]
            .status
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        if paths.is_empty() {
            paths.push("/capture/status".into());
        }
        Job::ReadMany(paths)
    }
    pub(super) fn load_settings(&mut self, settings: &Value) {
        for (index, task) in tasks().iter().enumerate().filter(|(_, t)| t.settings) {
            if self.dirty.contains(&index) {
                continue;
            }
            let mut draft = task.defaults.clone();
            for (key, value) in draft.as_object_mut().unwrap() {
                if let Some(saved) = settings.get(key) {
                    *value = saved.clone();
                }
            }
            self.drafts.insert(index, draft);
        }
    }
}
impl Desktop {
    pub(super) fn native_tasks(&mut self, ui: &mut egui::Ui) {
        egui::ComboBox::from_id_salt("native-task")
            .selected_text(tasks()[self.workflows.selected].name)
            .width(290.)
            .show_ui(ui, |ui| {
                for (index, task) in tasks().iter().enumerate() {
                    if ui
                        .selectable_value(&mut self.workflows.selected, index, task.name)
                        .changed()
                    {
                        self.refresh = Instant::now() - Duration::from_secs(10);
                    }
                }
            });
        let task = &tasks()[self.workflows.selected];
        ui.add_space(12.);
        ui.label(task.description);
        ui.add_space(12.);
        let draft = self
            .workflows
            .drafts
            .entry(self.workflows.selected)
            .or_insert_with(|| task.defaults.clone());
        ui.add_enabled_ui(!self.read_only && !self.worker.busy || task.get, |ui| {
            for (key, value) in draft.as_object_mut().unwrap() {
                if key == "pack" {
                    continue;
                }
                if let Some((_, choices)) = task.options.iter().find(|(name, _)| name == key) {
                    ui.horizontal(|ui| {
                        ui.label(super::title(key));
                        let old = value.clone();
                        let mut text = value.as_str().unwrap_or("").to_string();
                        super::choice(ui, key, &mut text, choices);
                        *value = json!(text);
                        if *value != old {
                            self.workflows.dirty.insert(self.workflows.selected);
                        }
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.label(super::title(key));
                        if edit_value(ui, key, value) {
                            self.workflows.dirty.insert(self.workflows.selected);
                        }
                    });
                }
            }
        });
        if task.path == "/security/iocpack/import" {
            ui.label(crate::i18n::tr("Indicator pack (JSON)"));
            ui.add(
                egui::TextEdit::multiline(&mut self.workflows.json_input)
                    .desired_rows(12)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            );
        }
        let enabled = (!self.read_only || task.get)
            && !self.worker.busy
            && (task.path != "/geo/download" || draft["consent"] == true)
            && (task.path != "/processes/kill" || draft["confirm"] == true);
        if ui
            .add_enabled(
                enabled,
                egui::Button::new(if task.settings {
                    "Save model preferences"
                } else if task.get {
                    "Load history"
                } else {
                    "Run task"
                }),
            )
            .clicked()
        {
            let mut body = draft.clone();
            let mut path = task.path.to_string();
            if task.settings {
                body = json!({"settings":body});
            }
            if task.path == "/firewall/blocklist" {
                let key = if body["source"] == "url" {
                    "url"
                } else {
                    "path"
                };
                let location = body["location"].clone();
                body.as_object_mut().unwrap().remove("source");
                body.as_object_mut().unwrap().remove("location");
                body[key] = location;
            }
            if task.path == "/security/iocpack/import" {
                match serde_json::from_str::<Value>(&self.workflows.json_input) {
                    Ok(pack) => body["pack"] = pack,
                    Err(error) => {
                        self.failure = true;
                        self.message = format!("Indicator pack is not valid JSON: {error}");
                        return;
                    }
                }
            }
            if task.path == "history" {
                path = format!(
                    "/history/{}/{}?minutes={}",
                    body["target"].as_str().unwrap_or("host"),
                    component(body["value"].as_str().unwrap_or("")),
                    body["minutes"].as_u64().unwrap_or(60)
                );
            }
            if let Some(object) = body.as_object_mut() {
                object.remove("confirm");
            }
            self.worker.send(Job::Write(
                if task.get {
                    reqwest::Method::GET
                } else {
                    reqwest::Method::POST
                },
                path,
                body,
            ));
        }
        ui.add_space(15.);
        for path in task.status {
            if let Some(value) = self.values.get(*path) {
                egui::CollapsingHeader::new("Current status")
                    .default_open(true)
                    .id_salt(path)
                    .show(ui, |ui| show_value(ui, path, value));
            }
        }
        if let Some(value) = self.values.get("last_action") {
            ui.separator();
            ui.heading(crate::i18n::tr("Result"));
            show_value(ui, "task-result", value);
        }
    }
    pub(super) fn native_exports(&mut self, ui: &mut egui::Ui) {
        ui.label(crate::i18n::tr(
            "Save an investigation report or the recent packet buffer to your computer.",
        ));
        ui.horizontal(|ui| {
            ui.label(crate::i18n::tr("Format"));
            super::choice(
                ui,
                "export-format",
                &mut self.workflows.export_format,
                &[
                    "json", "csv", "ecs", "stix", "pcap", "ioc", "proof", "yaral",
                ],
            );
        });
        ui.horizontal(|ui| {
            ui.label(crate::i18n::tr("Directory"));
            ui.text_edit_singleline(&mut self.workflows.export_path);
        });
        if ui
            .add_enabled(
                !self.worker.busy && !self.workflows.export_path.is_empty(),
                egui::Button::new(crate::i18n::tr("Save export")),
            )
            .clicked()
        {
            let format = &self.workflows.export_format;
            let (path, extension) = match format.as_str() {
                "pcap" => ("/forensics/pcap".into(), "pcap"),
                "ioc" => ("/security/iocpack".into(), "json"),
                "proof" => ("/security/iocpack?format=proof".into(), "json"),
                "yaral" => ("/alerts/rules/yaral".into(), "yaral"),
                other => (
                    format!("/forensics/export?format={other}"),
                    if other == "csv" { "csv" } else { "json" },
                ),
            };
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let file = PathBuf::from(&self.workflows.export_path)
                .join(format!("genyra-snitch-{stamp}.{extension}"));
            self.worker.send(Job::Download(path, file));
        }
        if let Some(value) = self.values.get("last_action") {
            ui.separator();
            show_value(ui, "export-result", value);
        }
    }
    pub(super) fn native_agents(&mut self, ui: &mut egui::Ui) {
        ui.label(crate::i18n::tr(
            "Enroll a sensor to send observations to this collector.",
        ));
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.workflows.agent_name);
            if ui
                .add_enabled(
                    !self.read_only
                        && !self.worker.busy
                        && !self.workflows.agent_name.trim().is_empty(),
                    egui::Button::new(crate::i18n::tr("Enroll sensor")),
                )
                .clicked()
            {
                self.worker.write(
                    "/ingest/enroll",
                    json!({"name":self.workflows.agent_name.trim()}),
                );
            }
        });
        if let Some(value) = self.values.get("last_action").cloned() {
            if let Some(token) = value["token"].as_str() {
                ui.group(|ui| {
                    ui.label(crate::i18n::tr("New sensor token — keep it private"));
                    let mut display = token.to_string();
                    ui.add(egui::TextEdit::singleline(&mut display).password(true));
                    if ui.button(crate::i18n::tr("Copy token")).clicked() {
                        ui.ctx().copy_text(token.into());
                    }
                });
            }
        }
        let agents = self
            .values
            .get("/ingest/agents")
            .cloned()
            .unwrap_or(Value::Null);
        for agent in agents["agents"].as_array().into_iter().flatten() {
            ui.horizontal(|ui| {
                ui.label(agent.as_str().unwrap_or(""));
                if ui
                    .add_enabled(
                        !self.read_only && !self.worker.busy,
                        egui::Button::new(crate::i18n::tr("Revoke sensor")),
                    )
                    .clicked()
                {
                    self.worker.write("/ingest/revoke", json!({"name":agent}));
                }
            });
        }
        if let Some(fleet) = self.values.get("/remote/fleet") {
            ui.separator();
            ui.heading(crate::i18n::tr("Fleet"));
            show_value(ui, "fleet", fleet);
        }
    }
}
pub(super) fn component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub(super) fn preferences(saved: &Value) -> Value {
    let mut defaults = json!({"retention_hours":24,"upload_threshold_mb":50,"integrity_watch":true,"kill_switch_enabled":false,"ports":[],"excluded_processes":[],"whitelisted_ips":[],"watchlist":[],"ti_provider":"none","ti_api_key":"","webhook_enabled":false,"webhook_url":"","telegram_chat_id":"","syslog_addr":"","syslog_format":"json","ask_enabled":false,"ask_timeout":15,"ask_failopen":false,"ebpf_probe":false,"gossip_enabled":false,"gossip_peers":[],"slm_enabled":false,"slm_mode":"ollama","slm_endpoint":"http://127.0.0.1:11434","slm_model":"","slm_model_path":""});
    for (key, value) in defaults.as_object_mut().unwrap() {
        if let Some(stored) = saved.get(key) {
            *value = stored.clone();
        }
    }
    defaults
}

#[cfg(test)]
mod tests {
    #[test]
    fn parameter_encoding_cannot_change_the_requested_route() {
        assert_eq!(
            super::component("app/path?token=x#frag"),
            "app%2Fpath%3Ftoken%3Dx%23frag"
        );
    }
    #[test]
    fn task_definitions_use_real_compatibility_routes() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../compatibility.json")).unwrap();
        for task in super::tasks() {
            if task.path == "history" {
                continue;
            }
            assert!(
                manifest["routes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["path"] == task.path),
                "{}",
                task.path
            );
        }
    }
}
