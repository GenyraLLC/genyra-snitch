//! Native live overview. All figures come from collector data; summaries are
//! cached on snapshots, and visible lists and live samples have fixed bounds.
use crate::{appearance::palette, human_bytes, i18n::tr, Desktop, PANELS};
use eframe::egui::{self, RichText, Stroke, Vec2};
use serde_json::Value;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub(super) struct Overview {
    devices: Vec<Value>,
    hosts: Vec<Value>,
    device_count: usize,
    host_count: usize,
    observed: bool,
    pub bytes: u64,
    packets: u64,
    rate: f64,
    previous_bytes: u64,
    sampled: Instant,
    samples: VecDeque<f64>,
    pub minutes: u32,
    pub audit_received: Instant,
}

impl Default for Overview {
    fn default() -> Self {
        Self {
            devices: vec![],
            hosts: vec![],
            device_count: 0,
            host_count: 0,
            observed: false,
            bytes: 0,
            packets: 0,
            rate: 0.,
            previous_bytes: 0,
            sampled: Instant::now(),
            samples: VecDeque::new(),
            minutes: 15,
            audit_received: Instant::now() - Duration::from_secs(30),
        }
    }
}
impl Overview {
    pub fn ingest(&mut self, graph: &Value) {
        let mut devices = vec![];
        let mut hosts = vec![];
        self.bytes = 0;
        self.packets = 0;
        for node in graph["nodes"].as_array().into_iter().flatten().take(4097) {
            if node["id"] == "local" {
                continue;
            }
            self.bytes = self
                .bytes
                .saturating_add(node["bytes"].as_u64().unwrap_or(0));
            self.packets = self
                .packets
                .saturating_add(node["packets"].as_u64().unwrap_or(0));
            if node["category"] == "lan_device" || node["private"] == true {
                devices.push(node);
            } else {
                hosts.push(node);
            }
        }
        self.device_count = devices.len();
        self.host_count = hosts.len();
        hosts.sort_by_key(|n| std::cmp::Reverse(n["bytes"].as_u64().unwrap_or(0)));
        devices.sort_by(|a, b| label(a).cmp(label(b)));
        self.devices = devices.into_iter().take(8).cloned().collect();
        self.hosts = hosts.into_iter().take(8).cloned().collect();
        if !self.observed {
            self.previous_bytes = self.bytes;
            self.sampled = Instant::now();
            self.observed = true;
        }
    }
    pub fn tick(&mut self) {
        let elapsed = self.sampled.elapsed().as_secs_f64();
        if self.observed && elapsed >= 1. {
            self.rate = self.bytes.saturating_sub(self.previous_bytes) as f64 / elapsed;
            self.previous_bytes = self.bytes;
            self.sampled = Instant::now();
            if self.samples.len() >= 120 {
                self.samples.pop_front();
            }
            self.samples.push_back(self.rate);
        }
    }
}
fn label(node: &Value) -> &str {
    ["hostname", "label", "ip", "id"]
        .into_iter()
        .find_map(|k| node[k].as_str().filter(|s| !s.is_empty()))
        .unwrap_or("—")
}
fn card(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    let p = palette(ui.ctx());
    egui::Frame::new()
        .fill(p.panel)
        .stroke(Stroke::new(1_f32, p.line))
        .corner_radius(9)
        .inner_margin(if ui.ctx().content_rect().height() < 1000. {
            10
        } else {
            14
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(tr(title)).size(10.).strong().color(p.muted));
            ui.add_space(if ui.ctx().content_rect().height() < 1000. {
                5.
            } else {
                8.
            });
            add(ui);
        });
    ui.add_space(if ui.ctx().content_rect().height() < 1000. {
        6.
    } else {
        9.
    });
}
fn chart(ui: &mut egui::Ui, points: &[f64], height: f32, filled: bool) {
    let p = palette(ui.ctx());
    let (response, painter) = ui.allocate_painter(
        Vec2::new(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let rect = response.rect.shrink2(egui::vec2(1., 5.));
    for fraction in [0., 0.5, 1.] {
        let y = rect.bottom() - fraction * rect.height();
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(0.6_f32, p.line),
        );
    }
    if points.len() < 2 {
        return;
    }
    let max = points.iter().copied().fold(1., f64::max);
    let positions: Vec<_> = points
        .iter()
        .enumerate()
        .map(|(i, v)| {
            egui::pos2(
                rect.left() + i as f32 / (points.len() - 1) as f32 * rect.width(),
                rect.bottom() - (*v / max) as f32 * rect.height(),
            )
        })
        .collect();
    if filled {
        let mut mesh = egui::Mesh::default();
        for position in &positions {
            mesh.colored_vertex(*position, p.accent.gamma_multiply(0.18));
            mesh.colored_vertex(
                egui::pos2(position.x, rect.bottom()),
                p.accent.gamma_multiply(0.02),
            );
        }
        for i in 0..positions.len() - 1 {
            let k = (i * 2) as u32;
            mesh.add_triangle(k, k + 1, k + 2);
            mesh.add_triangle(k + 1, k + 3, k + 2);
        }
        painter.add(egui::Shape::mesh(mesh));
    }
    painter.add(egui::Shape::line(positions, Stroke::new(1.8_f32, p.accent)));
}
impl Desktop {
    pub(super) fn navigate(&mut self, index: usize) {
        self.panel = index;
        self.filter.clear();
        if index < 3 && self.feed_connected {
            self.accept_data("/graph".into(), self.live.graph());
        }
        self.refresh = Instant::now() - Duration::from_secs(20);
    }
    pub(super) fn overview_shell(&mut self, ctx: &egui::Context) {
        if !self.paused {
            self.overview.tick();
        }
        let p = palette(ctx);
        egui::TopBottomPanel::top("genyra-brand-header")
            .exact_height(64.)
            .frame(
                egui::Frame::new()
                    .fill(p.panel)
                    .inner_margin(egui::Margin::symmetric(18, 9)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    crate::appearance::wordmark(ui, self.appearance.dark);
                    ui.add_space(8.);
                    ui.separator();
                    ui.label(RichText::new("Snitch").size(21.).color(p.text));
                    ui.add_space(10.);
                    let status = self.values.get("/capture/status");
                    let live = status.is_some_and(|s| s["capturing"] == true);
                    ui.colored_label(
                        if live { p.success } else { p.muted },
                        format!(
                            "● {}",
                            tr(if live {
                                "Capturing"
                            } else if status.is_some() {
                                "Capture stopped"
                            } else {
                                "Connecting"
                            })
                        ),
                    );
                    if let Some(interface) = status.and_then(|s| s["interface"].as_str()) {
                        ui.label(RichText::new(interface).small().color(p.muted));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if crate::appearance::icon_button(
                            ui,
                            "theme",
                            self.appearance.dark,
                            &tr(if self.appearance.dark {
                                "Light mode"
                            } else {
                                "Dark mode"
                            }),
                        )
                        .clicked()
                        {
                            self.appearance.dark = !self.appearance.dark;
                            self.appearance.apply(ctx);
                            self.save_appearance();
                        }
                        let old = self.appearance.language.clone();
                        crate::appearance::language_button(ui, &mut self.appearance.language);
                        if old != self.appearance.language {
                            self.appearance.apply(ctx);
                            self.save_appearance();
                        }
                        if crate::appearance::icon_button(
                            ui,
                            "settings",
                            self.appearance.dark,
                            &tr("Settings"),
                        )
                        .clicked()
                        {
                            self.navigate(11);
                        }
                        if self.read_only {
                            ui.label(RichText::new(tr("Read only")).small().color(p.muted));
                        }
                    });
                });
            });
        egui::TopBottomPanel::top("workspace-tabs")
            .exact_height(49.)
            .frame(
                egui::Frame::new()
                    .fill(p.panel)
                    .stroke(Stroke::new(1_f32, p.line))
                    .inner_margin(egui::Margin::symmetric(18, 7)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    let compact = ui.available_width() < 1120.;
                    for (index, key) in [
                        (0, "nav_graph"),
                        (1, "nav_map"),
                        (2, "Applications"),
                        (3, "LAN devices"),
                        (4, "Alerts"),
                    ] {
                        if compact && index >= 3 {
                            continue;
                        }
                        let label = if index == 4 && !self.live.alerts.is_empty() {
                            format!("{}  {}", tr(key), self.live.alerts.len())
                        } else {
                            tr(key)
                        };
                        if ui
                            .add(egui::Button::new(label).selected(self.panel == index))
                            .clicked()
                        {
                            self.navigate(index);
                        }
                    }
                    ui.menu_button(tr("More"), |ui| {
                        for (index, (name, _)) in
                            PANELS.iter().enumerate().skip(if compact { 3 } else { 5 })
                        {
                            if ui.selectable_label(self.panel == index, tr(name)).clicked() {
                                self.navigate(index);
                                ui.close();
                            }
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button(tr(if self.paused {
                                "Resume live view"
                            } else {
                                "Pause live view"
                            }))
                            .clicked()
                        {
                            self.paused = !self.paused;
                        }
                        if ui.button(tr("export_btn")).clicked() {
                            self.navigate(14);
                        }
                        let capturing = self
                            .values
                            .get("/capture/status")
                            .is_some_and(|s| s["capturing"] == true);
                        if !self.read_only
                            && ui
                                .add_enabled(
                                    !self.worker.busy,
                                    egui::Button::new(tr(if capturing {
                                        "capture_stop"
                                    } else {
                                        "capture_start"
                                    })),
                                )
                                .clicked()
                        {
                            self.worker.write(
                                if capturing {
                                    "/capture/stop"
                                } else {
                                    "/capture/start"
                                },
                                serde_json::json!({}),
                            );
                            self.last_capture_check = Instant::now() - Duration::from_secs(15);
                        }
                    });
                });
            });
        if self.panel <= 1 {
            egui::SidePanel::left("live-overview-rail")
                .exact_width(278.)
                .resizable(false)
                .frame(egui::Frame::new().fill(p.background).inner_margin(12))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("overview-scroll")
                        .show(ui, |ui| {
                            self.score_card(ui);
                            self.traffic_card(ui);
                            self.destination_card(ui, true);
                            self.destination_card(ui, false);
                            self.packet_card(ui);
                            ui.label(
                                RichText::new(format!("Genyra LLC  ·  {}", tr("Local monitoring")))
                                    .size(10.)
                                    .color(p.muted),
                            );
                        });
                });
        }
    }
    fn save_appearance(&mut self) {
        if let Err(error) = self.appearance.save(&crate::data_dir()) {
            self.failure = true;
            self.message = format!("Could not save display preferences: {error}");
        }
    }
    fn score_card(&self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        let audit = self
            .values
            .get("/security/audit")
            .filter(|a| a["score"].is_number());
        card(ui, "Security score", |ui| {
            ui.horizontal(|ui| {
                let (r, paint) = ui.allocate_painter(
                    if ui.ctx().content_rect().height() < 1000. {
                        egui::vec2(72., 72.)
                    } else {
                        egui::vec2(86., 86.)
                    },
                    egui::Sense::hover(),
                );
                let center = r.rect.center();
                paint.circle_stroke(center, 33., Stroke::new(7_f32, p.soft));
                if let Some(score) = audit.and_then(|a| a["score"].as_f64()) {
                    let colour = if score >= 75. {
                        p.success
                    } else if score >= 45. {
                        p.accent
                    } else {
                        p.danger
                    };
                    let points = (0..=64)
                        .map(|i| {
                            let angle = -std::f32::consts::FRAC_PI_2
                                + i as f32 / 64. * std::f32::consts::TAU * (score as f32 / 100.);
                            center + egui::vec2(angle.cos(), angle.sin()) * 33.
                        })
                        .collect();
                    paint.add(egui::Shape::line(points, Stroke::new(7_f32, colour)));
                    paint.text(
                        center,
                        egui::Align2::CENTER_CENTER,
                        format!("{score:.0}"),
                        egui::FontId::proportional(27.),
                        p.text,
                    );
                } else {
                    paint.text(
                        center,
                        egui::Align2::CENTER_CENTER,
                        "—",
                        egui::FontId::proportional(27.),
                        p.muted,
                    );
                }
                ui.vertical(|ui| {
                    if let Some(a) = audit {
                        let score = a["score"].as_u64().unwrap_or(0);
                        ui.label(
                            RichText::new(tr(if score >= 85 {
                                "privacy_label_excellent"
                            } else if score >= 65 {
                                "privacy_label_good"
                            } else if score >= 40 {
                                "privacy_label_average"
                            } else {
                                "privacy_label_weak"
                            }))
                            .strong()
                            .color(p.accent),
                        );
                        ui.label(
                            RichText::new(format!(
                                "{}  {}",
                                a["critical"].as_u64().unwrap_or(0),
                                tr("Critical alerts")
                            ))
                            .small(),
                        );
                        ui.label(
                            RichText::new(format!(
                                "{}  {}",
                                a["warning"].as_u64().unwrap_or(0),
                                tr("Warnings")
                            ))
                            .small()
                            .color(p.muted),
                        );
                    } else {
                        ui.label(
                            RichText::new(tr("Loading assessment"))
                                .small()
                                .color(p.muted),
                        );
                    }
                });
            });
        });
    }
    fn traffic_card(&self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        card(ui, "Captured traffic", |ui| {
            ui.horizontal(|ui| {
                for (value, key) in [
                    (self.overview.device_count, "stat_lan"),
                    (self.overview.host_count, "stat_ext"),
                ] {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(value.to_string()).size(24.).color(p.text));
                        ui.label(RichText::new(tr(key)).small().color(p.muted));
                    });
                    ui.add_space(15.);
                }
            });
            chart(
                ui,
                &self.overview.samples.iter().copied().collect::<Vec<_>>(),
                if ui.ctx().content_rect().height() < 1000. {
                    18.
                } else {
                    28.
                },
                false,
            );
            ui.horizontal(|ui| {
                ui.strong(human_bytes(self.overview.bytes));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.colored_label(
                        p.accent,
                        format!("{}/s", human_bytes(self.overview.rate as u64)),
                    );
                });
            });
        });
    }
    fn destination_card(&mut self, ui: &mut egui::Ui, devices: bool) {
        let p = palette(ui.ctx());
        let mut selected = None;
        let nodes = if devices {
            &self.overview.devices
        } else {
            &self.overview.hosts
        };
        card(
            ui,
            if devices {
                "LAN devices"
            } else {
                "External hosts"
            },
            |ui| {
                if nodes.is_empty() {
                    ui.label(
                        RichText::new(tr(if devices {
                            "No devices observed yet"
                        } else {
                            "Waiting for live traffic"
                        }))
                        .small()
                        .color(p.muted),
                    );
                }
                let count = if ui.ctx().content_rect().height() < 850. {
                    1
                } else if ui.ctx().content_rect().height() < 1000. {
                    2
                } else {
                    3
                };
                for node in nodes.iter().take(count) {
                    ui.horizontal(|ui| {
                        let (response, painter) =
                            ui.allocate_painter(egui::vec2(24., 25.), egui::Sense::hover());
                        crate::scene::paint_node_icon(
                            &painter,
                            response.rect.center(),
                            if devices {
                                node["device_type"].as_str().unwrap_or("computer")
                            } else {
                                node["category"].as_str().unwrap_or("unknown")
                            },
                            p.accent,
                            8.,
                        );
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.;
                            if ui
                                .add(
                                    egui::Label::new(RichText::new(label(node)).size(12.))
                                        .truncate()
                                        .sense(egui::Sense::click()),
                                )
                                .on_hover_text(label(node))
                                .clicked()
                            {
                                selected = Some(node.clone());
                            }
                            ui.label(
                                RichText::new(if devices {
                                    node["ip"].as_str().unwrap_or("—").to_string()
                                } else {
                                    human_bytes(node["bytes"].as_u64().unwrap_or(0))
                                })
                                .size(10.)
                                .color(p.muted),
                            );
                        });
                    });
                }
                if ui.small_button(tr("View all")).clicked() {
                    selected = Some(Value::Null);
                }
            },
        );
        if let Some(node) = selected {
            if node.is_null() {
                self.navigate(if devices { 3 } else { 2 });
            } else {
                self.selected = Some(node);
            }
        }
    }
    fn packet_card(&self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        card(ui, "Recent traffic", |ui| {
            if self.live.packets.is_empty() {
                ui.label(
                    RichText::new(tr("Waiting for live traffic"))
                        .small()
                        .color(p.muted),
                );
            }
            let count = if ui.ctx().content_rect().height() < 850. {
                2
            } else if ui.ctx().content_rect().height() < 1000. {
                3
            } else {
                4
            };
            for packet in self.live.packets.iter().rev().take(count) {
                let app = packet["process_name"].as_str().unwrap_or("—");
                let target = if packet["direction"] == "in" {
                    &packet["src_ip"]
                } else {
                    &packet["dst_ip"]
                };
                let text = format!(
                    "{}  {}  {}",
                    if packet["direction"] == "in" {
                        "↓"
                    } else {
                        "↑"
                    },
                    app,
                    target.as_str().unwrap_or("—")
                );
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(text).size(11.).color(p.muted)).truncate(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(human_bytes(packet["size"].as_u64().unwrap_or(0)))
                                .size(10.),
                        );
                    });
                });
            }
        });
    }
    pub(super) fn overview_canvas(&mut self, ui: &mut egui::Ui, map: bool) {
        let p = palette(ui.ctx());
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(tr(if map { "World map" } else { "Live connections" }))
                    .size(18.)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_sized(
                    [240., 30.],
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text(tr("Filter destinations")),
                );
            });
        });
        ui.add_space(8.);
        let timeline_height = if ui.available_height() > 460. {
            155.
        } else {
            110.
        };
        egui::TopBottomPanel::bottom("live-timeline-panel")
            .exact_height(timeline_height)
            .resizable(false)
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(0, 5)))
            .show_inside(ui, |ui| self.overview_timeline(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(p.canvas)
                    .corner_radius(10)
                    .stroke(Stroke::new(1_f32, p.line))
                    .inner_margin(12),
            )
            .show_inside(ui, |ui| {
                let canvas = ui.available_rect_before_wrap();
                self.graph(ui, map);
                self.overview_alert_overlay(ui.ctx(), canvas);
            });
    }
    fn overview_alert_overlay(&self, ctx: &egui::Context, canvas: egui::Rect) {
        let alerts: Vec<_> = self
            .live
            .alerts
            .iter()
            .filter(|a| matches!(a["severity"].as_str(), Some("critical" | "warning")))
            .take(if canvas.height() < 420. { 2 } else { 3 })
            .collect();
        if alerts.is_empty() || canvas.width() < 460. {
            return;
        }
        let p = palette(ctx);
        let width = 285.;
        let height = 24. + alerts.len() as f32 * 57.;
        egui::Area::new(egui::Id::new("recent-live-alerts"))
            .fixed_pos(egui::pos2(
                canvas.right() - width - 12.,
                canvas.bottom() - height - 20.,
            ))
            .movable(false)
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.label(
                    RichText::new(tr("Recent alerts"))
                        .size(10.)
                        .strong()
                        .color(p.muted),
                );
                for alert in alerts {
                    let color = if alert["severity"] == "critical" {
                        p.danger
                    } else {
                        p.accent
                    };
                    egui::Frame::new()
                        .fill(p.panel)
                        .stroke(Stroke::new(1_f32, color.gamma_multiply(0.65)))
                        .corner_radius(7)
                        .inner_margin(9)
                        .show(ui, |ui| {
                            ui.set_width(width - 20.);
                            let kind = alert["type"].as_str().unwrap_or("Alert");
                            let key = format!("alert_{kind}");
                            let mut heading = tr(&key);
                            if heading == key {
                                heading = kind.replace('_', " ");
                            }
                            ui.label(RichText::new(heading).size(11.).strong().color(color));
                            let message = alert["message"].as_str().unwrap_or("");
                            ui.add(
                                egui::Label::new(RichText::new(message).size(10.).color(p.muted))
                                    .truncate(),
                            )
                            .on_hover_text(message);
                        });
                    ui.add_space(5.);
                }
            });
    }
    fn overview_timeline(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui.ctx());
        egui::Frame::new()
            .fill(p.panel)
            .stroke(Stroke::new(1_f32, p.line))
            .corner_radius(9)
            .inner_margin(12)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.strong(tr("Traffic history"));
                    ui.label(RichText::new(tr("bytes / minute")).small().color(p.muted));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        for period in [60, 30, 15] {
                            if ui
                                .selectable_label(
                                    self.overview.minutes == period,
                                    format!("{period}m"),
                                )
                                .clicked()
                            {
                                self.overview.minutes = period;
                                self.refresh = Instant::now() - Duration::from_secs(20);
                            }
                        }
                    });
                });
                let rows = self
                    .values
                    .get("/timeline")
                    .and_then(|v| v["timeline"].as_array());
                let points: Vec<f64> = rows
                    .into_iter()
                    .flatten()
                    .map(|v| v["bytes"].as_f64().unwrap_or(0.))
                    .collect();
                if points.len() > 1 {
                    chart(ui, &points, ui.available_height().clamp(35., 92.), true);
                } else {
                    ui.add_space(10.);
                    ui.label(
                        RichText::new(tr("Waiting for live traffic"))
                            .small()
                            .color(p.muted),
                    );
                }
            });
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn logo_activation_requests_the_genyra_website() {
        let ctx = egui::Context::default();
        egui_extras::install_image_loaders(&ctx);
        let mut position = egui::pos2(80., 32.);
        let mut opened = false;
        for pressed in [None, None, Some(true), Some(false)] {
            let mut events = vec![egui::Event::PointerMoved(position)];
            if let Some(pressed) = pressed {
                events.push(egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                });
            }
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1400., 900.),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        position = crate::appearance::wordmark(ui, false).rect.center();
                    });
                },
            );
            opened|=output.platform_output.commands.iter().any(|command|matches!(command,egui::OutputCommand::OpenUrl(url) if url.url=="https://genyra.com"));
        }
        assert!(opened);
    }
    #[test]
    fn overview_fits_compact_and_wide_windows_in_both_themes() {
        for (width, height, language, dark) in [
            (960., 640., "en", false),
            (960., 640., "de", true),
            (1400., 900., "en", false),
            (1400., 900., "ja", true),
            (1320., 850., "zh-CN", false),
            (1440., 1040., "en", true),
        ] {
            let ctx = egui::Context::default();
            let connection = crate::Connection::new(
                "http://127.0.0.1:9".into(),
                "synthetic-layout-token".into(),
            )
            .unwrap();
            let mut app = Desktop::with_context(&ctx, connection, None);
            app.appearance = crate::appearance::Appearance {
                dark,
                language: language.into(),
            };
            app.appearance.apply(&ctx);
            let nodes:Vec<_>=(0..80).map(|index|serde_json::json!({"id":format!("host-{index}"),"label":format!("test-{index}.invalid"),"bytes":index*1000,"category":if index%4==0{"lan_device"}else{"https"},"private":index%4==0})).collect();
            app.accept_data(
                "/graph".into(),
                serde_json::json!({"nodes":nodes,"edges":[]}),
            );
            let packets:Vec<_>=(0..8).map(|index|serde_json::json!({"process_name":"test-app","dst_ip":format!("198.51.100.{}",index+1),"direction":"out","size":1024})).collect();
            app.live
                .apply(&serde_json::json!({"type":"batch","packets":packets}));
            app.values.insert(
                "/security/audit".into(),
                serde_json::json!({"score":65,"critical":2,"warning":6}),
            );
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, height));
            let mut footer_visible = false;
            for _ in 0..3 {
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(screen),
                        ..Default::default()
                    },
                    |ctx| {
                        app.overview_shell(ctx);
                        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
                            ui.label("");
                        });
                        egui::CentralPanel::default().show(ctx, |ui| {
                            app.overview_canvas(ui, false);
                        });
                    },
                );
                footer_visible = output.shapes.iter().any(|shape| {
                    if let egui::Shape::Text(text) = &shape.shape {
                        text.galley.text().contains("Genyra LLC")
                            && shape.clip_rect.contains_rect(egui::Rect::from_min_size(
                                text.pos,
                                text.galley.size(),
                            ))
                    } else {
                        false
                    }
                });
            }
            let used = ctx.used_rect();
            assert!(
                used.max.x <= width + 1. && used.max.y <= height + 1.,
                "{language} {width}x{height}: {used:?}"
            );
            if height >= 850. {
                assert!(
                    footer_visible,
                    "overview footer was clipped: {language} {width}x{height}"
                );
            }
            app.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    #[test]
    fn overview_does_not_replay_historical_bytes_as_live_activity() {
        let mut overview = Overview {
            sampled: Instant::now() - Duration::from_secs(2),
            ..Default::default()
        };
        overview.tick();
        overview.ingest(&serde_json::json!({"nodes":[{"id":"existing","bytes":1000000000}]}));
        assert_eq!(overview.previous_bytes, 1000000000);
        assert_eq!(overview.rate, 0.);
        assert!(overview.samples.is_empty());
    }
}
