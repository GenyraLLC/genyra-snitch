//! Native tables and action views. Expensive application aggregation happens
//! once per collector snapshot, not once per painted animation frame.
use super::{human_bytes, show_value, Desktop, Job, GOLD, MUTED};
use eframe::egui::{self, Color32, RichText, Vec2};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
#[derive(Default)]
pub(super) struct Application {
    name: String,
    bytes: u64,
    destinations: usize,
    pids: BTreeSet<u32>,
}
pub(super) struct Views {
    apps: Vec<Application>,
    pub(super) minutes: u32,
    pub(super) combined_rule: bool,
}
impl Default for Views {
    fn default() -> Self {
        Self {
            apps: vec![],
            minutes: 60,
            combined_rule: false,
        }
    }
}
impl Views {
    pub(super) fn update_graph(&mut self, value: &Value) {
        let mut apps: BTreeMap<String, Application> = BTreeMap::new();
        for node in value["nodes"].as_array().into_iter().flatten() {
            for (name, counts) in node["processes"].as_object().into_iter().flatten() {
                let app = apps.entry(name.clone()).or_insert_with(|| Application {
                    name: name.clone(),
                    ..Default::default()
                });
                app.bytes = app
                    .bytes
                    .saturating_add(counts["bytes"].as_u64().unwrap_or(0));
                app.destinations += 1;
                if let Some(pid) = counts["pid"].as_u64().and_then(|p| u32::try_from(p).ok()) {
                    app.pids.insert(pid);
                }
            }
        }
        self.apps = apps.into_values().collect();
        self.apps.sort_by_key(|app| std::cmp::Reverse(app.bytes));
    }
}
impl Desktop {
    pub(super) fn native_apps(&mut self, ui: &mut egui::Ui) {
        let filter = self.filter.to_lowercase();
        let entries: Vec<_> = self
            .views
            .apps
            .iter()
            .filter(|a| filter.is_empty() || a.name.to_lowercase().contains(&filter))
            .collect();
        ui.label(
            RichText::new(format!(
                "{} applications · select a process to inspect it",
                entries.len()
            ))
            .color(MUTED),
        );
        let mut job = None;
        let mut inspect = None;
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::remainder())
            .column(egui_extras::Column::auto())
            .column(egui_extras::Column::auto())
            .column(egui_extras::Column::auto())
            .column(egui_extras::Column::auto())
            .header(32., |mut row| {
                for heading in [
                    "Application",
                    "Processes",
                    "Destinations",
                    "Transferred",
                    "Actions",
                ] {
                    row.col(|ui| {
                        ui.strong(heading);
                    });
                }
            })
            .body(|body| {
                body.rows(34., entries.len(), |mut row| {
                    let app = entries[row.index()];
                    row.col(|ui| {
                        if ui.selectable_label(false, &app.name).clicked() {
                            inspect = app.pids.iter().next().copied();
                        }
                    });
                    row.col(|ui| {
                        ui.label(
                            app.pids
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                    });
                    row.col(|ui| {
                        ui.label(app.destinations.to_string());
                    });
                    row.col(|ui| {
                        ui.label(human_bytes(app.bytes));
                    });
                    row.col(|ui| {
                        if ui
                            .add_enabled(!self.worker.busy, egui::Button::new("History"))
                            .clicked()
                        {
                            job = Some(Job::Write(
                                reqwest::Method::GET,
                                format!(
                                    "/history/process/{}",
                                    super::workflows::component(&app.name)
                                ),
                                json!({}),
                            ));
                        }
                    });
                })
            });
        if let Some(pid) = inspect {
            self.pid = pid;
            self.panel = 8;
            self.refresh = Instant::now() - Duration::from_secs(10);
        }
        if let Some(job) = job {
            self.worker.send(job);
        }
        if self.last_action_path.starts_with("/history/process/") {
            if let Some(result) = self.values.get("last_action") {
                egui::CollapsingHeader::new("Application history")
                    .default_open(true)
                    .show(ui, |ui| show_value(ui, "app-history", result));
            }
        }
    }
    pub(super) fn native_devices(&mut self, ui: &mut egui::Ui) {
        let value = self.current();
        let filter = self.filter.to_lowercase();
        let devices: Vec<_> = value["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| filter.is_empty() || v.to_string().to_lowercase().contains(&filter))
            .collect();
        ui.label(format!("{} observed LAN devices", devices.len()));
        let mut selected = None;
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::remainder())
            .column(egui_extras::Column::auto())
            .column(egui_extras::Column::auto())
            .column(egui_extras::Column::remainder())
            .column(egui_extras::Column::auto())
            .header(32., |mut row| {
                for label in ["Device", "Address", "MAC", "Vendor", "Traffic"] {
                    row.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|body| {
                body.rows(34., devices.len(), |mut row| {
                    let device = devices[row.index()];
                    row.col(|ui| {
                        if ui
                            .selectable_label(
                                false,
                                device["label"].as_str().unwrap_or("Unknown device"),
                            )
                            .clicked()
                        {
                            selected = Some(device.clone());
                        }
                    });
                    for key in ["ip", "mac", "vendor"] {
                        row.col(|ui| {
                            ui.label(device[key].as_str().unwrap_or("—"));
                        });
                    }
                    row.col(|ui| {
                        ui.label(human_bytes(device["bytes"].as_u64().unwrap_or(0)));
                    });
                })
            });
        if let Some(selected) = selected {
            self.selected = Some(selected);
        }
    }
    pub(super) fn native_alerts(&mut self, ui: &mut egui::Ui) {
        let value = self.current();
        let filter = self.filter.to_lowercase();
        let alerts: Vec<_> = value["alerts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| filter.is_empty() || v.to_string().to_lowercase().contains(&filter))
            .collect();
        ui.label(format!("{} recent alerts", alerts.len()));
        egui::ScrollArea::vertical().show(ui, |ui| {
            for alert in alerts {
                let severity = alert["severity"].as_str().unwrap_or("info");
                let color = match severity {
                    "critical" => Color32::from_rgb(240, 114, 113),
                    "warning" => GOLD,
                    _ => Color32::from_rgb(131, 166, 196),
                };
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(color, RichText::new(severity.to_uppercase()).strong());
                        ui.strong(alert["type"].as_str().unwrap_or("Alert"));
                        ui.label(
                            RichText::new(alert["timestamp"].as_str().unwrap_or(""))
                                .small()
                                .color(MUTED),
                        );
                    });
                    ui.label(alert["message"].as_str().unwrap_or(""));
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(
                                !self.worker.busy && !self.read_only,
                                egui::Button::new("Explain"),
                            )
                            .clicked()
                        {
                            self.worker.write(
                                "/security/explain",
                                json!({"type":alert["type"],"detail":alert["details"],"lang":"en"}),
                            );
                        }
                        if ui
                            .add_enabled(
                                !self.worker.busy && !self.read_only,
                                egui::Button::new("Mute this type"),
                            )
                            .clicked()
                        {
                            self.worker
                                .write("/alerts/ignore", json!({"type":alert["type"]}));
                        }
                        if let Some(ip) = alert["node_id"].as_str().filter(|s| !s.is_empty()) {
                            if ui
                                .add_enabled(
                                    !self.worker.busy && !self.read_only,
                                    egui::Button::new("Mute this host"),
                                )
                                .clicked()
                            {
                                self.worker.write("/alerts/ignore", json!({"ip":ip}));
                            }
                        }
                    });
                    egui::CollapsingHeader::new("Details")
                        .id_salt(alert["id"].as_str().unwrap_or(""))
                        .show(ui, |ui| show_value(ui, "alert-details", &alert["details"]));
                });
                ui.add_space(6.);
            }
            if self.last_action_path == "/security/explain" {
                if let Some(result) = self.values.get("last_action") {
                    ui.separator();
                    ui.heading("Explanation");
                    show_value(ui, "explanation", result);
                }
            }
        });
    }
    pub(super) fn native_timeline(&mut self, ui: &mut egui::Ui) {
        let mut minutes = self.views.minutes;
        ui.horizontal(|ui| {
            ui.label("Period");
            egui::ComboBox::from_id_salt("timeline-range")
                .selected_text(format!("{minutes} minutes"))
                .show_ui(ui, |ui| {
                    for period in [30, 60, 120, 240, 1440, 10080] {
                        if ui
                            .selectable_value(&mut minutes, period, format!("{period} minutes"))
                            .changed()
                        {
                            self.views.minutes = minutes;
                            self.refresh = Instant::now() - Duration::from_secs(10);
                        }
                    }
                });
        });
        let value = self.current();
        let rows = value["timeline"].as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
            ui.label(
                "No persisted traffic in this period yet. Live traffic is written in batches.",
            );
            return;
        }
        ui.label(RichText::new("Transferred bytes per minute").color(MUTED));
        let (response, painter) =
            ui.allocate_painter(Vec2::new(ui.available_width(), 230.), egui::Sense::hover());
        let rect = response.rect.shrink(14.);
        let max = rows
            .iter()
            .filter_map(|r| r["bytes"].as_f64())
            .fold(1., f64::max);
        let points: Vec<_> = rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                egui::pos2(
                    rect.left()
                        + i as f32 / rows.len().saturating_sub(1).max(1) as f32 * rect.width(),
                    rect.bottom()
                        - (row["bytes"].as_f64().unwrap_or(0.) / max) as f32 * rect.height(),
                )
            })
            .collect();
        for fraction in [0., 0.5, 1.] {
            let y = rect.bottom() - fraction * rect.height();
            painter.line_segment(
                [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                egui::Stroke::new(0.6_f32, Color32::from_gray(45)),
            );
        }
        painter.add(egui::epaint::PathShape::line(
            points.clone(),
            egui::Stroke::new(2_f32, GOLD),
        ));
        if let Some(pointer) = response.hover_pos() {
            let index = (((pointer.x - rect.left()) / rect.width()).clamp(0., 1.)
                * (rows.len() - 1) as f32)
                .round() as usize;
            let row = &rows[index];
            painter.circle_filled(points[index], 4., GOLD);
            response.on_hover_text(format!(
                "{}\n{} · {} packets",
                row["minute"].as_str().unwrap_or(""),
                human_bytes(row["bytes"].as_u64().unwrap_or(0)),
                row["packets"]
            ));
        }
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::remainder())
            .columns(egui_extras::Column::auto(), 3)
            .header(32., |mut row| {
                for label in ["Minute (UTC)", "Transferred", "Packets", "Alerts"] {
                    row.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|body| {
                body.rows(30., rows.len(), |mut row| {
                    let record = &rows[rows.len() - 1 - row.index()];
                    row.col(|ui| {
                        ui.label(record["minute"].as_str().unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(human_bytes(record["bytes"].as_u64().unwrap_or(0)));
                    });
                    for key in ["packets", "alerts"] {
                        row.col(|ui| {
                            ui.label(record[key].to_string());
                        });
                    }
                })
            });
    }
    pub(super) fn native_rules(&mut self, ui: &mut egui::Ui) {
        ui.add_enabled_ui(!self.read_only,|ui|{
            if ui.checkbox(&mut self.views.combined_rule,"Match all conditions").changed(){
                if self.views.combined_rule {
                    let clause=json!({"field":self.rule["field"],"op":self.rule["op"],"value":self.rule["value"]});
                    let map=self.rule.as_object_mut().unwrap();for key in ["field","op","value"]{map.remove(key);}map.insert("conds".into(),json!([clause]));
                }else {
                    let clause=self.rule["conds"][0].clone();self.rule.as_object_mut().unwrap().remove("conds");
                    for key in ["field","op","value"]{self.rule[key]=clause[key].clone();}
                }
            }
            super::edit_value(ui,"New rule",&mut self.rule);
            if ui.add_enabled(!self.worker.busy,egui::Button::new("Add alert rule")).clicked(){self.worker.write("/alerts/rules",self.rule.clone());}
        });
        ui.separator();
        ui.heading("Existing rules");
        let value = self.current();
        for rule in value["rules"].as_array().into_iter().flatten() {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    let mut enabled = rule["enabled"] != false;
                    let id = rule["id"].as_str().unwrap_or("");
                    if ui
                        .add_enabled(
                            !self.read_only && !self.worker.busy,
                            egui::Checkbox::new(
                                &mut enabled,
                                rule["name"].as_str().unwrap_or("Rule"),
                            ),
                        )
                        .changed()
                    {
                        self.worker.write(
                            &format!("/alerts/rules/{id}/toggle"),
                            json!({"enabled":enabled}),
                        );
                    }
                    if ui
                        .add_enabled(
                            !self.read_only && !self.worker.busy,
                            egui::Button::new("Remove rule"),
                        )
                        .clicked()
                    {
                        self.worker.send(Job::Write(
                            reqwest::Method::DELETE,
                            format!("/alerts/rules/{id}"),
                            json!({}),
                        ));
                    }
                });
                egui::CollapsingHeader::new("Conditions")
                    .id_salt(rule["id"].as_str().unwrap_or(""))
                    .show(ui, |ui| show_value(ui, "rule", rule));
            });
        }
    }
}
