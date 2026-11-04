//! Traffic visualization. Topology is static between snapshots; particles are
//! emitted only for measured byte increases. Physics sleeps after settling.
use eframe::egui::{self, epaint, Color32, Pos2, Sense, Stroke, Vec2};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

const GOLD: Color32 = Color32::from_rgb(219, 184, 101);
const MAX_NODES: usize = 4096;
const PHYSICS_NODES: usize = 384;
#[derive(Clone)]
struct Body {
    id: String,
    label: String,
    search: String,
    position: Vec2,
    velocity: Vec2,
    anchor: Vec2,
    color: Color32,
    bytes: u64,
    geo: Option<Vec2>,
    kind: String,
}
#[derive(Clone)]
struct Link {
    id: String,
    source: String,
    target: String,
    protocol: String,
    bytes: u64,
    color: Color32,
}
struct Pulse {
    source: String,
    target: String,
    started: Instant,
    weight: f32,
    color: Color32,
}
pub struct Scene {
    bodies: Vec<Body>,
    links: Vec<Link>,
    previous: HashMap<String, u64>,
    pulses: Vec<Pulse>,
    world: World,
    origin: Option<(String, Vec2)>,
    pan: Vec2,
    zoom: f32,
    map_pan: Vec2,
    map_zoom: f32,
    dragged: Option<String>,
    settle_until: Instant,
    last_step: Instant,
    hovered: Option<String>,
    total: usize,
    geo_count: usize,
    active_edges: usize,
    bytes_per_second: u64,
    last_snapshot: Option<Instant>,
    graph_bounds: egui::Rect,
    fit_after: Option<Instant>,
}
impl Default for Scene {
    fn default() -> Self {
        Self {
            bodies: vec![],
            links: vec![],
            previous: HashMap::new(),
            pulses: vec![],
            world: World::load(),
            origin: timezone_origin(),
            pan: Vec2::ZERO,
            zoom: 1.,
            map_pan: Vec2::ZERO,
            map_zoom: 1.,
            dragged: None,
            settle_until: Instant::now(),
            last_step: Instant::now(),
            hovered: None,
            total: 0,
            geo_count: 0,
            active_edges: 0,
            bytes_per_second: 0,
            last_snapshot: None,
            graph_bounds: egui::Rect::from_min_max(
                egui::pos2(-550., -425.),
                egui::pos2(550., 425.),
            ),
            fit_after: None,
        }
    }
}
fn hash(s: &str) -> u64 {
    s.bytes().fold(14695981039346656037, |a, b| {
        (a ^ b as u64).wrapping_mul(1099511628211)
    })
}
fn color(value: &Value) -> Color32 {
    value
        .as_str()
        .and_then(|s| u32::from_str_radix(s.trim_start_matches('#'), 16).ok())
        .map(|n| Color32::from_rgb((n >> 16) as u8, (n >> 8) as u8, n as u8))
        .unwrap_or(GOLD)
}
fn direction(h: u64) -> Vec2 {
    let a = (h % 100000) as f32 / 100000. * std::f32::consts::TAU;
    Vec2::new(a.cos(), a.sin())
}
impl Scene {
    pub fn reset_traffic(&mut self) {
        self.previous.clear();
        self.pulses.clear();
        self.last_snapshot = None;
        self.active_edges = 0;
        self.bytes_per_second = 0;
    }
    pub fn ingest(&mut self, value: &Value) {
        let now = Instant::now();
        if self.last_snapshot.is_none() {
            self.fit_after = Some(now + Duration::from_secs(3));
        }
        let interval = self
            .last_snapshot
            .map(|t| now.duration_since(t).as_secs_f64().max(0.1));
        let mut nodes: Vec<_> = value["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|n| n["id"] != "local")
            .collect();
        self.total = nodes.len();
        self.geo_count = nodes
            .iter()
            .filter(|n| n["lat"].is_number() && n["lon"].is_number())
            .count();
        nodes.sort_by(|a, b| {
            b["bytes"]
                .as_u64()
                .cmp(&a["bytes"].as_u64())
                .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
        });
        let old: HashMap<_, _> = std::mem::take(&mut self.bodies)
            .into_iter()
            .map(|b| (b.id.clone(), b))
            .collect();
        let mut added = false;
        for node in nodes.into_iter().take(MAX_NODES) {
            let Some(id) = node["id"].as_str() else {
                continue;
            };
            let h = hash(id);
            let unit = direction(h);
            // Stable, two-dimensional initial placement keeps dense captures
            // legible without continuously running a force simulation.
            let anchor = Vec2::new(
                (h % 10000) as f32 / 10000. * 1040. - 520.,
                ((h >> 20) % 10000) as f32 / 10000. * 680. - 340.,
            );
            let (position, velocity) = old
                .get(id)
                .map(|b| (b.position, b.velocity))
                .unwrap_or_else(|| {
                    added = true;
                    (anchor + unit * 24., Vec2::ZERO)
                });
            let geo = node["lon"]
                .as_f64()
                .zip(node["lat"].as_f64())
                .map(|(lon, lat)| project(lon, lat) + direction(h) * 0.014);
            self.bodies.push(Body {
                id: id.into(),
                label: node["label"].as_str().unwrap_or(id).into(),
                search: node.to_string().to_lowercase(),
                position,
                velocity,
                anchor,
                color: color(&node["color"]),
                bytes: node["bytes"].as_u64().unwrap_or(0),
                geo,
                kind: node["device_type"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or_else(|| node["category"].as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
        let ids: HashSet<_> = self.bodies.iter().map(|b| b.id.as_str()).collect();
        let mut links = vec![];
        let mut deltas = vec![];
        let mut total_delta = 0u64;
        let mut next = HashMap::new();
        for edge in value["edges"].as_array().into_iter().flatten() {
            let (Some(id), Some(source), Some(target)) = (
                edge["id"].as_str(),
                edge["source"].as_str(),
                edge["target"].as_str(),
            ) else {
                continue;
            };
            let bytes = edge["bytes"].as_u64().unwrap_or(0);
            next.insert(id.to_string(), bytes);
            let delta = self
                .previous
                .get(id)
                .map(|old| bytes.saturating_sub(*old))
                .unwrap_or(0);
            total_delta = total_delta.saturating_add(delta);
            if !ids.contains(target) || (source != "local" && !ids.contains(source)) {
                continue;
            }
            let link = Link {
                id: id.into(),
                source: source.into(),
                target: target.into(),
                protocol: edge["protocol"].as_str().unwrap_or("").into(),
                bytes,
                color: color(&edge["color"]),
            };
            if delta > 0 {
                deltas.push((delta, link.clone()));
            }
            links.push(link);
        }
        self.active_edges = deltas.len();
        self.bytes_per_second = interval
            .map(|secs| (total_delta as f64 / secs) as u64)
            .unwrap_or(0);
        deltas.sort_by_key(|(bytes, _)| std::cmp::Reverse(*bytes));
        self.pulses
            .retain(|p| p.started.elapsed() < Duration::from_millis(1250));
        for (delta, link) in deltas.into_iter().take(96) {
            if self.pulses.len() >= 192 {
                break;
            }
            self.pulses.push(Pulse {
                source: link.source,
                target: link.target,
                started: now,
                weight: ((delta as f32).log2() / 5.).clamp(1., 3.),
                color: link.color,
            });
        }
        self.previous = next;
        self.links = links;
        self.last_snapshot = Some(now);
        if added {
            self.settle_until = now + Duration::from_secs(3);
        }
    }
    fn step(&mut self) {
        if Instant::now() > self.settle_until {
            return;
        }
        let dt = self.last_step.elapsed().as_secs_f32().clamp(0.005, 0.05);
        self.last_step = Instant::now();
        let simulated = self.bodies.len().min(PHYSICS_NODES);
        let mut forces = vec![Vec2::ZERO; simulated];
        for (i, a) in self.bodies.iter().take(simulated).enumerate() {
            forces[i] += (a.anchor - a.position) * 0.18;
            // Keep the central device clear without pulling every destination
            // onto one circular rail.
            let distance = a.position.length().max(1.);
            if distance < 90. {
                forces[i] += a.position / distance * (90. - distance) * 0.4;
            }
            for j in i + 1..simulated {
                let delta = a.position - self.bodies[j].position;
                let squared = delta.length_sq().max(100.);
                let repulsion = delta / squared.sqrt() * (17000. / squared).min(40.);
                forces[i] += repulsion;
                forces[j] -= repulsion;
            }
        }
        for (body, force) in self.bodies.iter_mut().zip(forces) {
            if self.dragged.as_deref() == Some(body.id.as_str()) {
                continue;
            }
            body.velocity = (body.velocity + force * dt) * 0.86;
            body.position += body.velocity * dt * 24.;
        }
    }
    fn fit_graph(&mut self) {
        if self.bodies.is_empty() {
            return;
        }
        let mut bounds = egui::Rect::from_min_max(Pos2::ZERO, Pos2::ZERO);
        for body in &self.bodies {
            bounds.extend_with(body.position.to_pos2());
        }
        self.graph_bounds = bounds.expand(100.);
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        map: bool,
        filter: &str,
        animate: bool,
    ) -> Option<String> {
        let theme = crate::appearance::palette(ui.ctx());
        let mut clicked = None;
        if self
            .fit_after
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.fit_graph();
            self.fit_after = None;
        }
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "{} {}",
                    self.total,
                    crate::i18n::tr("Destinations")
                ))
                .strong()
                .color(theme.accent),
            );
            ui.separator();
            ui.label(format!(
                "{} {}",
                self.active_edges,
                crate::i18n::tr("Active paths")
            ));
            ui.separator();
            ui.label(format!("{}/s", super::human_bytes(self.bytes_per_second)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(crate::i18n::tr("Fit view")).clicked() {
                    if map {
                        self.map_pan = Vec2::ZERO;
                        self.map_zoom = 1.;
                    } else {
                        self.pan = Vec2::ZERO;
                        self.zoom = 1.;
                        self.fit_graph();
                    }
                }
                if ui.small_button("−").clicked() {
                    if map {
                        self.map_zoom = (self.map_zoom / 1.25).max(0.5);
                    } else {
                        self.zoom = (self.zoom / 1.25).max(0.2);
                    }
                }
                if ui.small_button("+").clicked() {
                    if map {
                        self.map_zoom = (self.map_zoom * 1.25).min(8.);
                    } else {
                        self.zoom = (self.zoom * 1.25).min(5.);
                    }
                }
            });
        });
        if map {
            ui.label(
                egui::RichText::new(format!(
                    "{} {} · {} {} · {}",
                    self.geo_count,
                    crate::i18n::tr("Located"),
                    self.total - self.geo_count,
                    crate::i18n::tr("Without coordinates"),
                    self.origin
                        .as_ref()
                        .map(|(name, _)| format!(
                            "{} ({name})",
                            crate::i18n::tr("Timezone estimate")
                        ))
                        .unwrap_or_else(|| { crate::i18n::tr("Origin unavailable") })
                ))
                .small()
                .color(theme.muted),
            );
        } else {
            ui.label(
                egui::RichText::new(crate::i18n::tr("Measured traffic"))
                    .small()
                    .color(theme.muted),
            );
        }
        let size = ui.available_size().max(Vec2::new(40., 40.));
        let (response, painter) = ui.allocate_painter(size, Sense::click_and_drag());
        let rect = response.rect.shrink(26.);
        if response.hovered() {
            let scroll = ui.ctx().input(|i| i.smooth_scroll_delta.y);
            if scroll != 0. {
                let factor = (scroll * 0.002).exp();
                if map {
                    self.map_zoom = (self.map_zoom * factor).clamp(0.5, 8.);
                } else {
                    self.zoom = (self.zoom * factor).clamp(0.2, 5.);
                }
            }
        }
        let zoom = if map { self.map_zoom } else { self.zoom };
        let base = if map {
            (rect.width() / 5.5).min(rect.height() / 2.9)
        } else {
            (rect.width() / self.graph_bounds.width())
                .min(rect.height() / self.graph_bounds.height())
        };
        let scale = base * zoom;
        let axes = if map {
            Vec2::splat(scale)
        } else {
            Vec2::new(
                rect.width() / self.graph_bounds.width(),
                rect.height() / self.graph_bounds.height(),
            ) * zoom
        };
        let pan = if map { self.map_pan } else { self.pan };
        let center = rect.center() + pan
            - if map {
                Vec2::ZERO
            } else {
                self.graph_bounds.center().to_vec2() * axes
            };
        let screen = |v: Vec2| center + v * axes;
        if animate && !map {
            self.step();
        }
        if map {
            self.world.paint(&painter, center, scale);
        } else {
            for x in -12..=12 {
                for y in -10..=10 {
                    let p = screen(Vec2::new(x as f32 * 55., y as f32 * 55.));
                    if rect.contains(p) {
                        painter.circle_filled(p, 0.8, theme.line.gamma_multiply(0.45));
                    }
                }
            }
        }
        let body_positions: HashMap<_, _> = self
            .bodies
            .iter()
            .filter_map(|b| {
                if map {
                    b.geo.map(|p| (b.id.as_str(), p))
                } else {
                    Some((b.id.as_str(), b.position))
                }
            })
            .collect();
        let origin = if map {
            self.origin.as_ref().map(|(_, p)| *p)
        } else {
            Some(Vec2::ZERO)
        };
        let lookup = |id: &str| {
            if id == "local" {
                origin
            } else {
                body_positions.get(id).copied()
            }
        };
        let filter = filter.to_lowercase();
        let visible: HashSet<_> = self
            .bodies
            .iter()
            .filter(|b| filter.is_empty() || b.search.contains(&filter))
            .map(|b| b.id.as_str())
            .collect();
        for link in &self.links {
            if !visible.contains(link.target.as_str()) {
                continue;
            }
            let (Some(from), Some(to)) = (lookup(&link.source), lookup(&link.target)) else {
                continue;
            };
            let (a, b) = (screen(from), screen(to));
            let bend = if map {
                0.16
            } else {
                ((hash(&link.id) % 7) as f32 - 3.) * 0.025
            };
            let control = curve_control(a, b, bend);
            painter.add(epaint::QuadraticBezierShape::from_points_stroke(
                [a, control, b],
                false,
                Color32::TRANSPARENT,
                Stroke::new(
                    (0.8 + (link.bytes as f32 + 1.).log10() * 0.14).clamp(1., 2.2),
                    link.color.gamma_multiply(if map { 0.50 } else { 0.32 }),
                ),
            ));
            if !map && self.hovered.as_deref() == Some(link.target.as_str()) {
                let p = quadratic(a, control, b, 0.55);
                painter.text(
                    p,
                    egui::Align2::CENTER_CENTER,
                    format!("{} · {}", link.protocol, super::human_bytes(link.bytes)),
                    egui::FontId::proportional(10.),
                    link.color,
                );
            }
        }
        let mut animating = false;
        if animate {
            for pulse in &self.pulses {
                if !visible.contains(pulse.target.as_str()) {
                    continue;
                }
                let t = pulse.started.elapsed().as_secs_f32() / 1.25;
                if t >= 1. {
                    continue;
                }
                let (Some(from), Some(to)) = (lookup(&pulse.source), lookup(&pulse.target)) else {
                    continue;
                };
                let (a, b) = (screen(from), screen(to));
                let control = curve_control(a, b, if map { 0.16 } else { 0. });
                let p = quadratic(a, control, b, t);
                let tail = quadratic(a, control, b, (t - 0.05).max(0.));
                painter.line_segment([tail, p], Stroke::new(pulse.weight, pulse.color));
                painter.circle_filled(p, 2. + pulse.weight * 0.5, pulse.color);
                animating = true;
            }
        }
        self.hovered = None;
        let pointer = response.hover_pos();
        let mut nearest = None;
        let mut nearest_dist = 22.;
        let fitted_radius = if map {
            6.5
        } else {
            (rect.area() / visible.len().max(1) as f32)
                .sqrt()
                .mul_add(0.33, 0.)
                .clamp(8., 24.)
        };
        let mut label_bounds: Vec<egui::Rect> = vec![];
        if let Some(origin) = origin {
            label_bounds.push(egui::Rect::from_center_size(
                screen(origin) + Vec2::new(0., 18.),
                Vec2::new(130., 26.),
            ));
        }
        for (index, body) in self.bodies.iter().enumerate() {
            if !visible.contains(body.id.as_str()) {
                continue;
            }
            let Some(position) = lookup(&body.id) else {
                continue;
            };
            let point = screen(position);
            if !response.rect.contains(point) {
                continue;
            }
            let radius = if map {
                6.5
            } else {
                (fitted_radius + (body.bytes as f32 + 1.).log10() * 0.35).min(24.)
            };
            let node_colour = if ui.visuals().dark_mode {
                body.color
            } else {
                Color32::from_rgb(
                    (body.color.r() as f32 * 0.55) as u8,
                    (body.color.g() as f32 * 0.55) as u8,
                    (body.color.b() as f32 * 0.55) as u8,
                )
            };
            painter.circle_filled(point, radius + 6., node_colour.gamma_multiply(0.09));
            painter.circle_filled(point, radius, theme.panel);
            painter.circle_stroke(point, radius, Stroke::new(1.7_f32, node_colour));
            if !map {
                paint_node_icon(&painter, point, &body.kind, node_colour, radius * 0.48);
            }
            if let Some(pointer) = pointer {
                let distance = point.distance(pointer);
                if distance < nearest_dist {
                    nearest_dist = distance;
                    nearest = Some(index);
                }
            }
            if index < 32 || zoom > 1.3 {
                let label: String = body.label.chars().take(27).collect();
                let text_point = point + Vec2::new(0., radius + 7.);
                let bounds = egui::Rect::from_center_size(
                    text_point + Vec2::new(0., 7.),
                    Vec2::new(label.chars().count() as f32 * 6.6, 15.),
                )
                .expand(3.);
                if label_bounds.iter().any(|old| old.intersects(bounds)) {
                    continue;
                }
                label_bounds.push(bounds);
                painter.text(
                    text_point,
                    egui::Align2::CENTER_TOP,
                    label,
                    egui::FontId::proportional(12.),
                    theme.text,
                );
            }
        }
        if let Some(index) = nearest {
            let body = &self.bodies[index];
            self.hovered = Some(body.id.clone());
            response.clone().on_hover_ui(|ui| {
                ui.strong(&body.label);
                ui.label(&body.id);
                ui.label(super::human_bytes(body.bytes));
            });
            if response.clicked() {
                clicked = Some(body.id.clone());
            }
        }
        if let Some(origin) = origin {
            let center = screen(origin);
            painter.circle_filled(center, if map { 9. } else { 35. }, theme.selected);
            painter.circle_stroke(
                center,
                if map { 9. } else { 35. },
                Stroke::new(2_f32, theme.accent),
            );
            painter.text(
                center + Vec2::new(0., if map { 21. } else { 49. }),
                egui::Align2::CENTER_CENTER,
                crate::i18n::tr(if map {
                    "LOCAL · ESTIMATE"
                } else {
                    "This device"
                }),
                egui::FontId::proportional(if map { 9. } else { 11. }),
                theme.accent,
            );
            if !map {
                paint_node_icon(&painter, center, "computer", theme.accent, 17.);
            }
        }
        if response.drag_started() && !map {
            self.dragged = nearest.map(|i| self.bodies[i].id.clone());
        }
        if response.dragged() {
            let delta = ui.ctx().input(|i| i.pointer.delta());
            if let Some(id) = &self.dragged {
                if let Some(body) = self.bodies.iter_mut().find(|b| &b.id == id) {
                    body.position += delta / axes;
                    body.velocity = Vec2::ZERO;
                }
            } else if map {
                self.map_pan += delta;
            } else {
                self.pan += delta;
            }
        }
        if response.drag_stopped() {
            self.dragged = None;
        }
        painter.text(
            response.rect.left_bottom() + Vec2::new(12., -12.),
            egui::Align2::LEFT_BOTTOM,
            crate::i18n::tr("Measured traffic"),
            egui::FontId::proportional(10.),
            theme.muted,
        );
        if animate && (animating || (!map && Instant::now() < self.settle_until)) {
            ui.ctx().request_repaint_after(Duration::from_millis(50));
        }
        clicked
    }
}
fn curve_control(a: Pos2, b: Pos2, bend: f32) -> Pos2 {
    let d = b - a;
    a + d * 0.5 + Vec2::new(-d.y, d.x) * bend
}
pub(super) fn paint_node_icon(
    painter: &egui::Painter,
    center: Pos2,
    kind: &str,
    colour: Color32,
    size: f32,
) {
    let stroke = Stroke::new(1.5_f32, colour);
    let p = |x: f32, y: f32| center + Vec2::new(x, y) * size;
    let line = |a: (f32, f32), b: (f32, f32)| {
        painter.line_segment([p(a.0, a.1), p(b.0, b.1)], stroke);
    };
    match kind.to_ascii_lowercase().as_str() {
        "phone" | "mobile" => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(-0.5, -0.9), p(0.5, 0.9)),
                2,
                stroke,
                egui::StrokeKind::Inside,
            );
            line((-0.14, 0.6), (0.14, 0.6));
        }
        "router" | "iot" | "lan_device" => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(-0.85, -0.05), p(0.85, 0.6)),
                2,
                stroke,
                egui::StrokeKind::Inside,
            );
            line((-0.55, -0.05), (-0.75, -0.8));
            line((0.55, -0.05), (0.75, -0.8));
            painter.circle_filled(p(0.5, 0.28), 1.3, colour);
            line((-0.5, 0.28), (-0.15, 0.28));
        }
        "pc" | "computer" | "local" => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(-0.9, -0.7), p(0.9, 0.45)),
                2,
                stroke,
                egui::StrokeKind::Inside,
            );
            line((0., 0.45), (0., 0.85));
            line((-0.5, 0.85), (0.5, 0.85));
        }
        "https" | "tracking" | "admin" => {
            let points = vec![
                p(0., -0.95),
                p(0.8, -0.6),
                p(0.65, 0.45),
                p(0., 0.95),
                p(-0.65, 0.45),
                p(-0.8, -0.6),
                p(0., -0.95),
            ];
            painter.add(egui::Shape::line(points, stroke));
            line((-0.35, 0.), (-0.05, 0.3));
            line((-0.05, 0.3), (0.4, -0.3));
        }
        "cdn" | "server" => {
            for y in [-0.7, 0., 0.7] {
                painter.rect_stroke(
                    egui::Rect::from_min_max(p(-0.85, y - 0.23), p(0.85, y + 0.23)),
                    1,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                painter.circle_filled(p(0.5, y), 1., colour);
            }
        }
        "unknown" | "other" => {
            painter.text(
                center,
                egui::Align2::CENTER_CENTER,
                "?",
                egui::FontId::proportional(size * 1.65),
                colour,
            );
        }
        _ => {
            painter.circle_stroke(center, size * 0.88, stroke);
            line((-0.88, 0.), (0.88, 0.));
            painter.add(egui::Shape::line(
                (0..=16)
                    .map(|i| {
                        let a = i as f32 / 16. * std::f32::consts::TAU;
                        p(a.cos() * 0.4, a.sin() * 0.88)
                    })
                    .collect(),
                stroke,
            ));
        }
    }
}
fn quadratic(a: Pos2, c: Pos2, b: Pos2, t: f32) -> Pos2 {
    let d = 1. - t;
    Pos2::new(
        d * d * a.x + 2. * d * t * c.x + t * t * b.x,
        d * d * a.y + 2. * d * t * c.y + t * t * b.y,
    )
}

// Natural Earth I coefficients adapted from retained d3-geo (ISC). Upstream
// third-party attribution remains in docs/UPSTREAM_NOTICES.md.
fn project(lon: f64, lat: f64) -> Vec2 {
    let l = lon.to_radians();
    let p = lat.clamp(-90., 90.).to_radians();
    let p2 = p * p;
    let p4 = p2 * p2;
    Vec2::new(
        (l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4))))
            as f32,
        -(p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4))))
            as f32,
    )
}
// Split geometry at the antimeridian before triangulation. A line between
// +180 and -180 must follow the map boundary, not cross the continents.
fn unwrap_ring(ring: &mut Vec<[f64; 2]>) {
    for i in 1..ring.len() {
        while ring[i][0] - ring[i - 1][0] > 180. {
            ring[i][0] -= 360.;
        }
        while ring[i][0] - ring[i - 1][0] < -180. {
            ring[i][0] += 360.;
        }
    }
    if let (Some(first), Some(last)) = (ring.first().copied(), ring.last().copied()) {
        if (last[0] - first[0]).abs() > 180. {
            let pole = if first[1] < 0. { -90. } else { 90. };
            ring.push([last[0], pole]);
            ring.push([first[0], pole]);
        }
    }
}
fn clip_ring(ring: &[[f64; 2]]) -> Vec<[f64; 2]> {
    let mut output = ring.to_vec();
    for (boundary, greater) in [(-180., true), (180., false)] {
        let input = std::mem::take(&mut output);
        let Some(mut previous) = input.last().copied() else {
            break;
        };
        for current in input {
            let inside = if greater {
                current[0] >= boundary
            } else {
                current[0] <= boundary
            };
            let previous_inside = if greater {
                previous[0] >= boundary
            } else {
                previous[0] <= boundary
            };
            if inside != previous_inside {
                let t = (boundary - previous[0]) / (current[0] - previous[0]);
                output.push([boundary, previous[1] + t * (current[1] - previous[1])]);
            }
            if inside {
                output.push(current);
            }
            previous = current;
        }
    }
    output
}
struct World {
    mesh: epaint::Mesh,
    borders: Vec<Vec<Pos2>>,
    graticules: Vec<Vec<Pos2>>,
}
impl World {
    fn load() -> Self {
        let topology: Value =
            serde_json::from_str(include_str!("../../ui/src/map/countries-110m.json"))
                .expect("bundled world topology");
        let scale = &topology["transform"]["scale"];
        let translate = &topology["transform"]["translate"];
        let arcs: Vec<Vec<[f64; 2]>> = topology["arcs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arc| {
                let mut x = 0.;
                let mut y = 0.;
                arc.as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        x += p[0].as_f64().unwrap();
                        y += p[1].as_f64().unwrap();
                        [
                            x * scale[0].as_f64().unwrap() + translate[0].as_f64().unwrap(),
                            y * scale[1].as_f64().unwrap() + translate[1].as_f64().unwrap(),
                        ]
                    })
                    .collect()
            })
            .collect();
        let mut mesh = epaint::Mesh::default();
        let mut borders = vec![];
        for country in topology["objects"]["countries"]["geometries"]
            .as_array()
            .unwrap()
        {
            let polygons: Vec<&Value> = if country["type"] == "Polygon" {
                vec![&country["arcs"]]
            } else {
                country["arcs"].as_array().unwrap().iter().collect()
            };
            for polygon in polygons {
                let mut rings = vec![];
                for ring in polygon.as_array().unwrap() {
                    let mut boundary = vec![];
                    for reference in ring.as_array().unwrap() {
                        let reference = reference.as_i64().unwrap();
                        let index = if reference < 0 { !reference } else { reference } as usize;
                        let mut arc = arcs[index].clone();
                        if reference < 0 {
                            arc.reverse();
                        }
                        if !boundary.is_empty() {
                            arc.remove(0);
                        }
                        boundary.extend(arc);
                    }
                    if boundary.len() > 1 && boundary.first() == boundary.last() {
                        boundary.pop();
                    }
                    unwrap_ring(&mut boundary);
                    rings.push(boundary);
                }
                for shift in [-360., 0., 360.] {
                    let mut points = vec![];
                    let mut holes = vec![];
                    for (index, ring) in rings.iter().enumerate() {
                        let shifted: Vec<_> = ring.iter().map(|p| [p[0] + shift, p[1]]).collect();
                        let clipped = clip_ring(&shifted);
                        if clipped.len() < 3 {
                            if index == 0 {
                                break;
                            } else {
                                continue;
                            }
                        }
                        if index > 0 {
                            holes.push(points.len() / 2);
                        }
                        let mut border = vec![];
                        for p in clipped {
                            let p = project(p[0], p[1]).to_pos2();
                            points.extend([p.x as f64, p.y as f64]);
                            border.push(p);
                        }
                        border.push(border[0]);
                        borders.push(border);
                    }
                    if points.len() < 6 {
                        continue;
                    }
                    if let Ok(indices) = earcutr::earcut(&points, &holes, 2) {
                        let base = mesh.vertices.len() as u32;
                        for point in points.as_chunks::<2>().0 {
                            mesh.colored_vertex(
                                Pos2::new(point[0] as f32, point[1] as f32),
                                Color32::from_rgb(37, 45, 54),
                            );
                        }
                        mesh.indices
                            .extend(indices.into_iter().map(|i| base + i as u32));
                    }
                }
            }
        }
        let mut graticules = vec![];
        for lon in (-180..=180).step_by(30) {
            graticules.push(
                (-85..=85)
                    .step_by(5)
                    .map(|lat| project(lon as f64, lat as f64).to_pos2())
                    .collect(),
            );
        }
        for lat in (-60..=60).step_by(30) {
            graticules.push(
                (-180..=180)
                    .step_by(5)
                    .map(|lon| project(lon as f64, lat as f64).to_pos2())
                    .collect(),
            );
        }
        Self {
            mesh,
            borders,
            graticules,
        }
    }
    fn paint(&self, painter: &egui::Painter, center: Pos2, scale: f32) {
        let theme = crate::appearance::palette(painter.ctx());
        let transform = |p: Pos2| center + p.to_vec2() * scale;
        for line in &self.graticules {
            painter.add(epaint::PathShape::line(
                line.iter().copied().map(transform).collect(),
                Stroke::new(0.6_f32, theme.line.gamma_multiply(0.5)),
            ));
        }
        let mut mesh = self.mesh.clone();
        for v in &mut mesh.vertices {
            v.pos = transform(v.pos);
            v.color = theme.land;
        }
        painter.add(mesh);
        for line in &self.borders {
            painter.add(epaint::PathShape::line(
                line.iter().copied().map(transform).collect(),
                Stroke::new(0.65_f32, theme.line),
            ));
        }
    }
}
fn timezone_origin() -> Option<(String, Vec2)> {
    let zone = iana_time_zone::get_timezone().ok()?;
    let (lon, lat) = match zone.as_str() {
        "Europe/Chisinau" | "Europe/Bucharest" => (28.8, 47.),
        "Europe/London" => (-0.1, 51.5),
        "Europe/Paris" => (2.35, 48.85),
        "Europe/Berlin" => (13.4, 52.5),
        "Europe/Kyiv" => (30.5, 50.4),
        "Europe/Moscow" => (37.6, 55.8),
        "America/New_York" | "America/Toronto" => (-74., 40.7),
        "America/Chicago" => (-87.6, 41.9),
        "America/Denver" => (-105., 39.7),
        "America/Los_Angeles" | "America/Vancouver" => (-118.2, 34.),
        "America/Sao_Paulo" => (-46.6, -23.5),
        "Asia/Tokyo" => (139.7, 35.7),
        "Asia/Singapore" => (103.8, 1.35),
        "Asia/Shanghai" => (121.5, 31.2),
        "Asia/Kolkata" => (77.2, 28.6),
        "Asia/Dubai" => (55.3, 25.2),
        "Australia/Sydney" => (151.2, -33.9),
        _ => return None,
    };
    Some((zone, project(lon, lat)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundled_map_contains_real_country_geometry() {
        let world = World::load();
        assert!(world.borders.len() > 150);
        assert!(world.mesh.vertices.len() > 5000);
        assert!(world.mesh.indices.len() > 15000);
        assert!(world.mesh.is_valid());
    }
    #[test]
    fn historical_snapshot_does_not_fabricate_live_traffic() {
        let mut scene = Scene::default();
        let mut graph = serde_json::json!({"nodes":[{"id":"host","bytes":100,"label":"fixture","lat":48.,"lon":2.}],"edges":[{"id":"flow","source":"local","target":"host","bytes":100}]});
        scene.ingest(&graph);
        assert!(scene.pulses.is_empty());
        scene.ingest(&graph);
        assert!(scene.pulses.is_empty());
        graph["edges"][0]["bytes"] = serde_json::json!(150);
        scene.ingest(&graph);
        assert_eq!(scene.pulses.len(), 1);
        graph["edges"][0]["bytes"] = serde_json::json!(1);
        scene.ingest(&graph);
        assert_eq!(scene.pulses.len(), 1);
    }
}
