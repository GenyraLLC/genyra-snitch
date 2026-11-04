//! Native tables and action views. Expensive application aggregation happens
//! once per collector snapshot, not once per painted animation frame.
use super::{human_bytes, show_value, Desktop, Job};
use eframe::egui::{self, Color32, RichText, Vec2};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
fn device_table(ui: &mut egui::Ui, devices: &[&Value]) -> Option<Value> {
    let mut selected = None;
    let table_width = ui.available_width().max(1000.);
    // A table must own its column state. Sharing the default table ID with
    // Applications recycled incompatible widths when switching pages.
    egui::ScrollArea::horizontal()
        .id_salt("devices-horizontal")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(table_width);
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            egui_extras::TableBuilder::new(ui)
                .id_salt("lan-devices-table-v2")
                .striped(true)
                .resizable(true)
                .column(egui_extras::Column::initial(190.).at_least(140.).clip(true))
                .column(egui_extras::Column::initial(310.).at_least(200.).clip(true))
                .column(egui_extras::Column::initial(175.).at_least(165.).clip(true))
                .column(
                    egui_extras::Column::remainder()
                        .resizable(false)
                        .at_least(160.)
                        .clip(true),
                )
                .column(egui_extras::Column::exact(100.).clip(true))
                .header(36., |mut row| {
                    for label in ["Device", "Address", "MAC address", "Vendor", "Status"] {
                        row.col(|ui| {
                            ui.strong(label);
                        });
                    }
                })
                .body(|body| {
                    body.rows(42., devices.len(), |mut row| {
                        let device = devices[row.index()];
                        let label = ["hostname", "label", "device_type"]
                            .iter()
                            .find_map(|key| device[*key].as_str().filter(|s| !s.is_empty()))
                            .unwrap_or("Unnamed device");
                        row.col(|ui| {
                            if ui
                                .selectable_label(false, label)
                                .on_hover_text(label)
                                .clicked()
                            {
                                selected = Some(device.clone());
                            }
                        });
                        for key in ["ip", "mac", "vendor"] {
                            let text = device[key]
                                .as_str()
                                .filter(|s| !s.is_empty())
                                .unwrap_or("—");
                            row.col(|ui| {
                                let label = if key == "vendor" {
                                    RichText::new(text)
                                } else {
                                    RichText::new(text).monospace()
                                };
                                ui.add(egui::Label::new(label).truncate())
                                    .on_hover_text(text);
                            });
                        }
                        row.col(|ui| {
                            let online = device["online"] == true;
                            ui.colored_label(
                                if online {
                                    Color32::from_rgb(99, 193, 143)
                                } else {
                                    crate::appearance::palette(ui.ctx()).muted
                                },
                                if online { "Online" } else { "Last seen" },
                            );
                        });
                    });
                });
        });
    selected
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn device_identifiers_remain_on_one_line_at_narrow_and_wide_sizes() {
        let ip = "2001:db8:1234:5678:90ab:cdef:1234:5678";
        let mac = "b2:aa:bb:cc:dd:ee";
        let device = json!({"hostname":"Test workstation","ip":ip,"mac":mac,"vendor":"A long manufacturer name for layout verification","online":true});
        let ctx = egui::Context::default();
        for width in [640., 960., 1320., 1920.] {
            let mut output = None;
            for _ in 0..2 {
                output = Some(ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 650.),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            device_table(ui, &[&device]);
                        });
                    },
                ));
            }
            fn inspect(shape: &egui::Shape, ip: &str, mac: &str, found: &mut usize) {
                match shape {
                    egui::Shape::Text(text)
                        if [ip, mac, "Test workstation"].contains(&text.galley.text()) =>
                    {
                        assert_eq!(
                            text.galley.rows.len(),
                            1,
                            "device identifier wrapped across rows"
                        );
                        *found += 1;
                    }
                    egui::Shape::Vec(shapes) => {
                        for shape in shapes {
                            inspect(shape, ip, mac, found);
                        }
                    }
                    _ => {}
                }
            }
            let mut found = 0;
            for shape in output.unwrap().shapes {
                inspect(&shape.shape, ip, mac, &mut found);
            }
            assert_eq!(found, 3, "device cells disappeared at width {width}");
        }
    }
}
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
    pub(super) fn native_preferences(&mut self, ui: &mut egui::Ui) {
        for (heading, keys) in [
            (
                "Traffic and history",
                &[
                    "ports",
                    "excluded_processes",
                    "whitelisted_ips",
                    "watchlist",
                    "retention_hours",
                    "upload_threshold_mb",
                ][..],
            ),
            (
                "Protection",
                &[
                    "integrity_watch",
                    "kill_switch_enabled",
                    "ask_enabled",
                    "ask_timeout",
                    "ask_failopen",
                    "ebpf_probe",
                ][..],
            ),
            (
                "Local explanations",
                &[
                    "slm_enabled",
                    "slm_mode",
                    "slm_endpoint",
                    "slm_model",
                    "slm_model_path",
                ][..],
            ),
            (
                "Notifications and threat intelligence",
                &[
                    "ti_provider",
                    "ti_api_key",
                    "webhook_enabled",
                    "webhook_url",
                    "telegram_chat_id",
                    "syslog_addr",
                    "syslog_format",
                ][..],
            ),
            ("Peer collectors", &["gossip_enabled", "gossip_peers"][..]),
        ] {
            ui.add_space(12.);
            ui.group(|ui| {
                ui.set_width(ui.available_width().min(1050.));
                ui.strong(heading);
                ui.add_space(8.);
                egui::Grid::new(("preferences", heading))
                    .num_columns(2)
                    .min_col_width(250.)
                    .spacing([24., 12.])
                    .show(ui, |ui| {
                        for key in keys {
                            if let Some(value) = self.settings.get_mut(*key) {
                                ui.label(super::title(key));
                                self.settings_dirty |= super::edit_value(ui, key, value);
                                ui.end_row();
                            }
                        }
                    });
            });
        }
    }
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
            .color(crate::appearance::palette(ui.ctx()).muted),
        );
        let mut job = None;
        let mut inspect = None;
        egui_extras::TableBuilder::new(ui)
            .id_salt("applications-table-v2")
            .striped(true)
            .resizable(true)
            .column(
                egui_extras::Column::remainder()
                    .resizable(false)
                    .at_least(160.)
                    .clip(true),
            )
            .column(egui_extras::Column::initial(180.).at_least(100.).clip(true))
            .column(egui_extras::Column::initial(115.).at_least(100.).clip(true))
            .column(egui_extras::Column::initial(125.).at_least(100.).clip(true))
            .column(egui_extras::Column::exact(95.))
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
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
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
                        )
                        .on_hover_text(
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
                            .add_enabled(
                                !self.worker.busy,
                                egui::Button::new(crate::i18n::tr("History")),
                            )
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
        let selected = device_table(ui, &devices);
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
                    "warning" => crate::appearance::palette(ui.ctx()).accent,
                    _ => Color32::from_rgb(131, 166, 196),
                };
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(color, RichText::new(severity.to_uppercase()).strong());
                        ui.strong(alert["type"].as_str().unwrap_or("Alert"));
                        ui.label(
                            RichText::new(alert["timestamp"].as_str().unwrap_or(""))
                                .small()
                                .color(crate::appearance::palette(ui.ctx()).muted),
                        );
                    });
                    ui.label(alert["message"].as_str().unwrap_or(""));
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(
                                !self.worker.busy && !self.read_only,
                                egui::Button::new(crate::i18n::tr("Explain")),
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
                                egui::Button::new(crate::i18n::tr("Mute this type")),
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
                                    egui::Button::new(crate::i18n::tr("Mute this host")),
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
                    ui.heading(crate::i18n::tr("Explanation"));
                    show_value(ui, "explanation", result);
                }
            }
        });
    }
    pub(super) fn native_timeline(&mut self, ui: &mut egui::Ui) {
        let mut minutes = self.views.minutes;
        ui.horizontal(|ui| {
            ui.label(crate::i18n::tr("Period"));
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
        ui.label(
            RichText::new(crate::i18n::tr("Transferred bytes per minute"))
                .color(crate::appearance::palette(ui.ctx()).muted),
        );
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
            egui::Stroke::new(2_f32, crate::appearance::palette(ui.ctx()).accent),
        ));
        if let Some(pointer) = response.hover_pos() {
            let index = (((pointer.x - rect.left()) / rect.width()).clamp(0., 1.)
                * (rows.len() - 1) as f32)
                .round() as usize;
            let row = &rows[index];
            painter.circle_filled(
                points[index],
                4.,
                crate::appearance::palette(ui.ctx()).accent,
            );
            response.on_hover_text(format!(
                "{}\n{} · {} packets",
                row["minute"].as_str().unwrap_or(""),
                human_bytes(row["bytes"].as_u64().unwrap_or(0)),
                row["packets"]
            ));
        }
        egui_extras::TableBuilder::new(ui)
            .id_salt("timeline-table-v2")
            .striped(true)
            .column(egui_extras::Column::remainder().at_least(200.).clip(true))
            .columns(
                egui_extras::Column::initial(130.).at_least(90.).clip(true),
                3,
            )
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
            if ui.add_enabled(!self.worker.busy,egui::Button::new(crate::i18n::tr("Add alert rule"))).clicked(){self.worker.write("/alerts/rules",self.rule.clone());}
        });
        ui.separator();
        ui.heading(crate::i18n::tr("Existing rules"));
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
                            egui::Button::new(crate::i18n::tr("Remove rule")),
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
