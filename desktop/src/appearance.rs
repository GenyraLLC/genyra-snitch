//! Genyra's paper/charcoal and warm-gold palette, shared with the hosting panel.
use eframe::egui::{self, Color32, Stroke};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct Appearance {
    pub dark: bool,
    pub language: String,
}
impl Default for Appearance {
    fn default() -> Self {
        Self {
            dark: false,
            language: "en".into(),
        }
    }
}
impl Appearance {
    pub fn load(data: &Path) -> Self {
        let mut bytes = vec![];
        std::fs::File::open(data.join("appearance.json"))
            .ok()
            .and_then(|f| f.take(4097).read_to_end(&mut bytes).ok());
        if bytes.len() > 4096 {
            return Self::default();
        }
        serde_json::from_slice(&bytes).unwrap_or_default()
    }
    pub fn save(&self, data: &Path) -> std::io::Result<()> {
        genyra_common::save_private(
            data,
            "appearance.json",
            &serde_json::to_vec(self).map_err(std::io::Error::other)?,
        )
    }
    pub fn apply(&self, ctx: &egui::Context) {
        crate::i18n::set_language(&self.language);
        let p = Palette::new(self.dark);
        let mut visuals = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        visuals.panel_fill = p.background;
        visuals.window_fill = p.panel;
        visuals.extreme_bg_color = p.input;
        visuals.faint_bg_color = p.soft;
        visuals.override_text_color = Some(p.text);
        visuals.selection.bg_fill = p.selected;
        visuals.selection.stroke = Stroke::new(1_f32, p.accent);
        for widget in [
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.noninteractive,
        ] {
            widget.bg_fill = p.panel;
            widget.weak_bg_fill = p.panel;
            widget.bg_stroke = Stroke::new(1_f32, p.line);
            widget.fg_stroke = Stroke::new(1_f32, p.text);
            widget.corner_radius = egui::CornerRadius::same(6);
        }
        visuals.widgets.hovered.bg_fill = p.soft;
        visuals.widgets.hovered.weak_bg_fill = p.soft;
        visuals.widgets.hovered.fg_stroke = Stroke::new(1_f32, p.text);
        visuals.widgets.active.bg_fill = p.selected;
        visuals.widgets.active.weak_bg_fill = p.selected;
        visuals.widgets.active.fg_stroke = Stroke::new(1_f32, p.text);
        ctx.set_visuals(visuals);
        let mut style = (*ctx.style()).clone();
        for (kind, size) in [
            (egui::TextStyle::Heading, 20.),
            (egui::TextStyle::Body, 13.),
            (egui::TextStyle::Button, 13.),
            (egui::TextStyle::Small, 11.),
            (egui::TextStyle::Monospace, 12.),
        ] {
            style
                .text_styles
                .insert(kind, egui::FontId::proportional(size));
        }
        style.spacing.item_spacing = egui::vec2(9., 7.);
        style.spacing.button_padding = egui::vec2(12., 7.);
        ctx.set_style(style);
        ctx.request_repaint();
    }
}

#[derive(Clone, Copy)]
pub(super) struct Palette {
    pub background: Color32,
    pub panel: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub line: Color32,
    pub soft: Color32,
    pub input: Color32,
    pub accent: Color32,
    pub selected: Color32,
    pub success: Color32,
    pub danger: Color32,
    pub canvas: Color32,
    pub land: Color32,
}
impl Palette {
    pub fn new(dark: bool) -> Self {
        let c = |v: u32| Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8);
        if dark {
            Self {
                background: c(0x202423),
                panel: c(0x2b302e),
                text: c(0xf1f0e9),
                muted: c(0xb5bbb2),
                line: c(0x51584f),
                soft: c(0x323831),
                input: c(0x252a27),
                accent: c(0xddc594),
                selected: c(0x464030),
                success: c(0xabd3b2),
                danger: c(0xf0aaa0),
                canvas: c(0x1b201e),
                land: c(0x303b34),
            }
        } else {
            Self {
                background: c(0xf4f3ef),
                panel: c(0xfffefa),
                text: c(0x282a29),
                muted: c(0x62685e),
                line: c(0xd5d6ce),
                soft: c(0xeeeae1),
                input: c(0xfffefa),
                accent: c(0x765b2d),
                selected: c(0xe9dfcb),
                success: c(0x28634b),
                danger: c(0xa13f39),
                canvas: c(0xf7f7f2),
                land: c(0xdfe5d9),
            }
        }
    }
}
pub(super) fn palette(ctx: &egui::Context) -> Palette {
    Palette::new(ctx.style().visuals.dark_mode)
}

pub(super) fn control(ui: &mut egui::Ui, size: egui::Vec2, label: &str) -> egui::Response {
    let p = palette(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let fill = if response.hovered() { p.soft } else { p.panel };
    ui.painter().rect_filled(rect, 6, fill);
    ui.painter().rect_stroke(
        rect,
        6,
        Stroke::new(1_f32, p.line),
        egui::StrokeKind::Inside,
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
    });
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub(super) fn icon_button(
    ui: &mut egui::Ui,
    kind: &str,
    dark: bool,
    label: &str,
) -> egui::Response {
    let p = palette(ui.ctx());
    let response = control(ui, egui::vec2(34., 32.), label);
    let center = response.rect.center();
    let painter = ui.painter();
    let stroke = Stroke::new(1.5_f32, p.text);
    if kind == "theme" && !dark {
        painter.circle_filled(center, 8., p.text);
        painter.circle_filled(
            center + egui::vec2(4., -3.),
            7.5,
            if response.hovered() { p.soft } else { p.panel },
        );
    } else if kind == "settings" {
        let points = (0..32)
            .map(|i| {
                let angle = i as f32 * std::f32::consts::TAU / 32.;
                let radius = if i % 4 < 2 { 10. } else { 7.5 };
                center + egui::vec2(angle.cos(), angle.sin()) * radius
            })
            .collect();
        painter.add(egui::Shape::closed_line(points, stroke));
        painter.circle_stroke(center, 3., stroke);
    } else {
        painter.circle_stroke(center, 4., stroke);
        for i in 0..8 {
            let angle = i as f32 * std::f32::consts::TAU / 8.;
            let v = egui::vec2(angle.cos(), angle.sin());
            painter.line_segment([center + v * 8., center + v * 10.5], stroke);
        }
    }
    response.on_hover_text(label)
}

pub(super) fn language_button(ui: &mut egui::Ui, language: &mut String) -> egui::Response {
    let p = palette(ui.ctx());
    let selected = crate::i18n::LANGUAGES
        .iter()
        .find(|(code, _)| *code == language.as_str())
        .map(|(_, name)| *name)
        .unwrap_or("English");
    let response = control(ui, egui::vec2(124., 32.), &crate::i18n::tr("Language"));
    let center = response.rect.center();
    ui.painter().text(
        egui::pos2(response.rect.left() + 12., center.y),
        egui::Align2::LEFT_CENTER,
        selected,
        egui::FontId::proportional(13.),
        p.text,
    );
    let arrow = egui::pos2(response.rect.right() - 14., center.y);
    ui.painter().add(egui::Shape::convex_polygon(
        vec![
            arrow + egui::vec2(-4., -2.),
            arrow + egui::vec2(4., -2.),
            arrow + egui::vec2(0., 3.),
        ],
        p.muted,
        Stroke::NONE,
    ));
    egui::Popup::menu(&response).show(|ui| {
        for (code, name) in crate::i18n::LANGUAGES {
            if ui
                .selectable_value(language, code.to_string(), *name)
                .clicked()
            {
                ui.close();
            }
        }
    });
    response
}

pub(super) fn wordmark(ui: &mut egui::Ui, dark: bool) -> egui::Response {
    let image = if dark {
        egui::include_image!("../../ui/public/brand/genyra-light.png")
    } else {
        egui::include_image!("../../ui/public/brand/genyra-dark.png")
    };
    let response = ui
        .add(
            egui::Image::new(image)
                .fit_to_exact_size(egui::vec2(152., 25.))
                .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("Genyra.com");
    if response.clicked() {
        ui.ctx()
            .open_url(egui::OpenUrl::new_tab("https://genyra.com"));
    }
    response
}

pub(super) fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "genyra-language-fallback".into(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/GenyraUIFallback.otf")).into(),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("genyra-language-fallback".into());
    }
    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_controls_share_a_baseline_and_theme_icons_need_no_glyph() {
        for dark in [false, true] {
            let ctx = egui::Context::default();
            Appearance {
                dark,
                language: "en".into(),
            }
            .apply(&ctx);
            let mut boxes = vec![];
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(600., 64.),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal_centered(|ui| {
                            boxes.push(icon_button(ui, "theme", dark, "Theme").rect);
                            boxes.push(language_button(ui, &mut "en".to_string()).rect);
                            boxes.push(icon_button(ui, "settings", dark, "Settings").rect);
                        });
                    });
                },
            );
            assert_eq!(boxes.len(), 3);
            for rect in &boxes {
                assert_eq!(rect.height(), 32.);
                assert!((rect.center().y - boxes[0].center().y).abs() < 0.1);
            }
        }
    }
    #[test]
    fn display_preferences_do_not_replace_background_preferences() {
        let dir = tempfile::tempdir().unwrap();
        genyra_common::DesktopPreferences {
            keep_monitoring: true,
        }
        .save(dir.path())
        .unwrap();
        Appearance {
            dark: true,
            language: "ja".into(),
        }
        .save(dir.path())
        .unwrap();
        assert!(Appearance::load(dir.path()).dark);
        assert_eq!(Appearance::load(dir.path()).language, "ja");
        assert!(genyra_common::DesktopPreferences::load(dir.path()).keep_monitoring);
    }
    #[test]
    fn bundled_fallback_can_draw_every_language_name() {
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let _ = ctx.run(Default::default(), |ctx| {
            ctx.fonts_mut(|fonts| {
                for (_, name) in crate::i18n::LANGUAGES {
                    assert!(
                        fonts.has_glyphs(&egui::FontId::proportional(13.), name),
                        "missing glyph in {name}"
                    );
                }
            });
        });
    }
}
