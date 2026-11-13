//! Colours and shared widgets. Palettes come from the original's theme files
//! UI color swatch definitions; swatch index n = shades[n-1], 0 = core.
//! The dark palette was checked against the person's screenshots (reference/picture-8..26).

use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, RichText, Stroke, Ui};
use std::sync::Arc;

const fn c(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Look {
    Dark,
    Light,
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub deep: Color32,      // background 1: editors, tab row, side panels
    pub panel: Color32,     // background 2: body, title and status bars
    pub header: Color32,    // background 3: table headers, buttons
    pub hover: Color32,     // background 4
    pub banner: Color32,    // background 5: info banners, task cards
    pub selection: Color32, // background 6: selected rows
    pub text: Color32,
    pub strong: Color32,
    pub disabled: Color32,
    pub link: Color32,
    pub accent: Color32, // orange underline / primary buttons
    pub get: Color32,
    pub post: Color32,
    pub other_method: Color32,
    pub high: Color32,
    pub medium: Color32,
    pub low: Color32,
    pub info: Color32,
    pub ed_text: Color32,
    pub ed_header_name: Color32,
    pub ed_header_value: Color32,
    pub ed_first_line: Color32,
    pub ed_line_numbers: Color32,
    pub ed_param_name: Color32,
    pub ed_param_value: Color32,
    /// Pretty view syntax colours: JSON keys / XML tag names, strings / attribute values,
    /// numbers / attribute names, and true / false / null.
    pub syn_key: Color32,
    pub syn_string: Color32,
    pub syn_number: Color32,
    pub syn_literal: Color32,
    pub ed_gutter: Color32,
    pub ed_lozenge: Color32,
    pub st_new: Color32,
    pub st_progress: Color32,
    pub st_postponed: Color32,
    pub st_done: Color32,
    pub st_ignored: Color32,
}

pub const DARK: Palette = Palette {
    deep: c(0x2B2B2B),
    panel: c(0x323334),
    header: c(0x424244),
    hover: c(0x525255),
    banner: c(0x323945),
    selection: c(0x2C5175),
    text: c(0xC5C7C8),
    strong: c(0xFFFFFF),
    disabled: c(0x818181),
    link: c(0xFF9E7A),
    accent: c(0xDB612F),
    get: c(0xBB608D),
    post: c(0x786FFF),
    other_method: c(0x5FBAC2),
    high: c(0xD6213F),
    medium: c(0xFF6633),
    low: c(0x26649D),
    info: c(0x818181),
    ed_text: c(0xCECECE),
    ed_header_name: c(0xD1E8F9),
    ed_header_value: c(0xBABABA),
    ed_first_line: c(0xD1E8F9),
    ed_line_numbers: c(0xA0A0A0),
    ed_param_name: c(0xBBCDFF),
    ed_param_value: c(0xA5C35B),
    syn_key: c(0x9CDCFE),
    syn_string: c(0xA5C35B),
    syn_number: c(0xD7BA7D),
    syn_literal: c(0xC586C0),
    ed_gutter: c(0x555555),
    ed_lozenge: c(0x484C53),
    st_new: c(0xCADAF0),
    st_progress: c(0x786FFF),
    st_postponed: c(0xFF9E7A),
    st_done: c(0x7DC164),
    st_ignored: c(0xEE95A1),
};

pub const LIGHT: Palette = Palette {
    deep: c(0xFFFFFF),
    panel: c(0xFBFBFB),
    header: c(0xEEEEEE),
    hover: c(0xDFDFDF),
    banner: c(0xEBF1F6),
    selection: c(0xCADAF0),
    text: c(0x2B2B2B),
    strong: c(0x000000),
    disabled: c(0x4B4B4B),
    link: c(0xAD5B28),
    accent: c(0xDB612F),
    get: c(0x87486F),
    post: c(0x4B44AE),
    other_method: c(0x2A828E),
    high: c(0xD6213F),
    medium: c(0xFF6633),
    low: c(0x26649D),
    info: c(0x818181),
    ed_text: c(0x141414),
    ed_header_name: c(0x000075),
    ed_header_value: c(0x202020),
    ed_first_line: c(0x141414),
    ed_line_numbers: c(0x787878),
    ed_param_name: c(0x0000C0),
    ed_param_value: c(0xA01010),
    syn_key: c(0x0451A5),
    syn_string: c(0xA31515),
    syn_number: c(0x098658),
    syn_literal: c(0x7A1FA2),
    ed_gutter: c(0xDDDDDD),
    ed_lozenge: c(0xE1E0E0),
    st_new: c(0x5384B2),
    st_progress: c(0x5B4FFF),
    st_postponed: c(0xFF7B4E),
    st_done: c(0x5FB441),
    st_ignored: c(0xDF4C63),
};

/// Highlight colours (ui.highlight.0..8, same in both themes).
pub const HIGHLIGHTS: [(&str, Color32); 9] = [
    ("Red", c(0xFF6464)),
    ("Orange", c(0xFFC864)),
    ("Yellow", c(0xFFFF64)),
    ("Green", c(0x64FF64)),
    ("Cyan", c(0x64FFFF)),
    ("Blue", c(0x6464FF)),
    ("Pink", c(0xFFC8C8)),
    ("Magenta", c(0xFF64FF)),
    ("Gray", c(0xB4B4B4)),
];

pub fn palette(look: Look) -> Palette {
    match look {
        Look::Dark => DARK,
        Look::Light => LIGHT,
    }
}

/// Noto Sans (the original's UI font on Linux) at 13 px, Noto Sans Mono for messages.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "noto".into(),
        Arc::new(FontData::from_static(include_bytes!("../assets/fonts/NotoSans-Regular.ttf"))),
    );
    fonts.font_data.insert(
        "noto-bold".into(),
        Arc::new(FontData::from_static(include_bytes!("../assets/fonts/NotoSans-Bold.ttf"))),
    );
    fonts.font_data.insert(
        "noto-mono".into(),
        Arc::new(FontData::from_static(include_bytes!("../assets/fonts/NotoSansMono-Regular.ttf"))),
    );
    fonts.families.get_mut(&FontFamily::Proportional).unwrap().insert(0, "noto".into());
    fonts.families.get_mut(&FontFamily::Monospace).unwrap().insert(0, "noto-mono".into());
    fonts.families.insert(FontFamily::Name("bold".into()), vec!["noto-bold".into(), "noto".into()]);
    ctx.set_fonts(fonts);
}

pub fn apply(ctx: &egui::Context, look: Look) {
    let p = palette(look);
    let mut style = (*ctx.style()).clone();
    style.visuals = if look == Look::Dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    let v = &mut style.visuals;
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.deep;
    v.faint_bg_color = if look == Look::Dark { c(0x333333) } else { c(0xF6F6F6) };
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.link;
    v.selection.bg_fill = p.selection;
    v.selection.stroke = Stroke::new(1.0_f32, p.strong);
    v.window_stroke = Stroke::new(1.0_f32, p.header);
    for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        w.fg_stroke.color = p.text;
        w.corner_radius = egui::CornerRadius::same(2);
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.deep);
    v.widgets.inactive.weak_bg_fill = p.header;
    v.widgets.inactive.bg_fill = p.header;
    v.widgets.hovered.weak_bg_fill = p.hover;
    v.widgets.hovered.bg_fill = p.hover;
    v.widgets.active.weak_bg_fill = p.hover;
    v.widgets.open.weak_bg_fill = p.header;
    v.widgets.inactive.bg_stroke = Stroke::NONE;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.hover);
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    style.spacing.button_padding = egui::vec2(10.0, 3.0);
    style.spacing.interact_size.y = 20.0;
    style.text_styles.insert(egui::TextStyle::Body, FontId::proportional(13.0));
    style.text_styles.insert(egui::TextStyle::Button, FontId::proportional(13.0));
    style.text_styles.insert(egui::TextStyle::Monospace, FontId::monospace(12.5));
    style.text_styles.insert(egui::TextStyle::Small, FontId::proportional(11.0));
    style.text_styles.insert(egui::TextStyle::Heading, FontId::new(15.0, FontFamily::Name("bold".into())));
    ctx.set_style(style);
}

pub fn bold(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(FontId::new(size, FontFamily::Name("bold".into())))
}

/// Primary (orange) button, as "Start attack", "Open browser", "Next".
pub fn primary_button(ui: &mut Ui, p: &Palette, label: &str) -> egui::Response {
    ui.add(egui::Button::new(bold(label, 13.0).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(0.0, 22.0)))
}

/// Grey button with bold label, as "Add", "Edit".
pub fn plain_button(ui: &mut Ui, p: &Palette, label: &str, enabled: bool) -> egui::Response {
    let txt = bold(label, 13.0).color(if enabled { p.text } else { p.disabled });
    ui.add_enabled(enabled, egui::Button::new(txt).fill(p.header).min_size(egui::vec2(0.0, 22.0)))
}

/// Fixed-width stacked button for the left-of-table button columns.
pub fn side_button(ui: &mut Ui, p: &Palette, label: &str, enabled: bool) -> egui::Response {
    let txt = bold(label, 12.5).color(if enabled { p.text } else { p.disabled });
    ui.add_enabled(enabled, egui::Button::new(txt).fill(p.header).min_size(egui::vec2(74.0, 20.0)))
}

/// Text tabs with an orange underline under the selected one (main and sub tabs).
pub fn underline_tabs<T: Copy + PartialEq>(ui: &mut Ui, p: &Palette, items: &[(T, &str)], selected: &mut T, height: f32) {
    for (value, label) in items {
        let is_sel = *selected == *value;
        let galley = ui.painter().layout_no_wrap(
            label.to_string(),
            FontId::proportional(13.0),
            if is_sel { p.strong } else { p.text },
        );
        let w = galley.size().x + 20.0;
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, height), egui::Sense::click());
        if resp.hovered() && !is_sel {
            ui.painter().rect_filled(rect, 0.0, p.hover.gamma_multiply(0.35));
        }
        let pos = egui::pos2(rect.center().x - galley.size().x / 2.0, rect.center().y - galley.size().y / 2.0);
        ui.painter().galley(pos, galley, p.text);
        if is_sel {
            let r = egui::Rect::from_min_max(egui::pos2(rect.left(), rect.bottom() - 3.0), rect.right_bottom());
            ui.painter().rect_filled(r, 0.0, p.accent);
        }
        if resp.clicked() {
            *selected = *value;
        }
    }
}

/// Bold section title with the round "?" and gear icons on its left, as in the settings panes.
pub fn section_title(ui: &mut Ui, p: &Palette, title: &str, description: &str) {
    ui.horizontal(|ui| {
        icon_help(ui, p);
        ui.label(bold(title, 14.0).color(p.strong));
    });
    ui.horizontal(|ui| {
        icon_gear(ui, p);
        ui.label(RichText::new(description).color(p.text));
    });
}

pub fn icon_help(ui: &mut Ui, p: &Palette) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
    ui.painter().circle_stroke(r.center(), 7.5, Stroke::new(1.3_f32, p.text));
    ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "?", FontId::proportional(11.0), p.text);
    resp
}

pub fn icon_gear(ui: &mut Ui, p: &Palette) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
    paint_gear(ui.painter(), r.center(), 7.0, p.text);
    resp
}

pub fn paint_gear(painter: &egui::Painter, c0: egui::Pos2, rad: f32, col: Color32) {
    for i in 0..8 {
        let a = i as f32 * std::f32::consts::TAU / 8.0;
        let d = egui::vec2(a.cos(), a.sin());
        painter.line_segment([c0 + d * (rad - 2.0), c0 + d * (rad + 0.5)], Stroke::new(2.2_f32, col));
    }
    painter.circle_stroke(c0, rad - 2.0, Stroke::new(1.4_f32, col));
    painter.circle_stroke(c0, 2.2, Stroke::new(1.2_f32, col));
}

pub fn paint_globe(painter: &egui::Painter, c0: egui::Pos2, rad: f32, col: Color32) {
    let s = Stroke::new(1.2_f32, col);
    painter.circle_stroke(c0, rad, s);
    painter.line_segment([c0 - egui::vec2(rad, 0.0), c0 + egui::vec2(rad, 0.0)], s);
    painter.line_segment([c0 - egui::vec2(0.0, rad), c0 + egui::vec2(0.0, rad)], s);
    painter.add(egui::Shape::ellipse_stroke(c0, egui::vec2(rad * 0.45, rad), s));
}

/// Small toggle switch (blue when on), as "Capturing".
pub fn toggle(ui: &mut Ui, on: &mut bool) -> egui::Response {
    let (rect, mut resp) = ui.allocate_exact_size(egui::vec2(28.0, 15.0), egui::Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *on, "Capturing"));
    let bg = if *on { c(0x2F6EB5) } else { c(0x6A6A6C) };
    ui.painter().rect_filled(rect, 7.5, bg);
    let x = if *on { rect.right() - 7.5 } else { rect.left() + 7.5 };
    ui.painter().circle_filled(egui::pos2(x, rect.center().y), 5.0, Color32::WHITE);
    resp
}

#[derive(Clone, Copy)]
pub enum EmptyIcon {
    SiteMap,
    History,
    Intercept,
    Logger,
    Organizer,
    Radar,
    Repeater,
}

impl EmptyIcon {
    /// The drawn icon for a name used with `empty_state_card` ("repeater", "sitemap", ...).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "sitemap" => EmptyIcon::SiteMap,
            "history" => EmptyIcon::History,
            "intercept" => EmptyIcon::Intercept,
            "logger" => EmptyIcon::Logger,
            "organizer" => EmptyIcon::Organizer,
            "radar" => EmptyIcon::Radar,
            "repeater" => EmptyIcon::Repeater,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            EmptyIcon::SiteMap => "sitemap",
            EmptyIcon::History => "history",
            EmptyIcon::Intercept => "intercept",
            EmptyIcon::Logger => "logger",
            EmptyIcon::Organizer => "organizer",
            EmptyIcon::Radar => "radar",
            EmptyIcon::Repeater => "repeater",
        }
    }
}

const EMPTY_ICON: egui::Vec2 = egui::vec2(110.0, 80.0);
const EMPTY_MAX_WIDTH: f32 = 400.0;

/// "Nothing here yet" card, centred horizontally and vertically in the space left in `ui`
/// (which it then fills): an icon (a drawn illustration named as in `EmptyIcon::from_name`,
/// or any other text as a glyph), a bold title, a dimmed wrapped subtitle, and an optional
/// button. Returns the button's response.
pub fn empty_state_card(ui: &mut Ui, icon: Option<&str>, title: &str, subtitle: &str, action_label: Option<&str>) -> Option<egui::Response> {
    let p = palette(if ui.visuals().dark_mode { Look::Dark } else { Look::Light });
    let avail = ui.available_rect_before_wrap();
    let width = EMPTY_MAX_WIDTH.min(avail.width() - 32.0).max(120.0);
    // measure first, so the whole card (not just its top) sits in the middle
    let title_font = FontId::new(17.0, egui::FontFamily::Name("bold".into()));
    let sub_font = FontId::proportional(12.5);
    let title_h = ui.fonts(|f| f.row_height(&title_font));
    let sub_h = ui.fonts(|f| f.layout(subtitle.to_string(), sub_font.clone(), p.disabled, width).size().y);
    let (gap_icon, gap_title, gap_button, button_h) = (16.0, 8.0, 16.0, 26.0);
    let height = icon.map_or(0.0, |_| EMPTY_ICON.y + gap_icon) + title_h + gap_title + sub_h
        + action_label.map_or(0.0, |_| gap_button + button_h);
    let top = (avail.center().y - height / 2.0).max(avail.top() + 12.0);
    let card = egui::Rect::from_min_size(egui::pos2(avail.center().x - width / 2.0, top), egui::vec2(width, height));
    let mut clicked = None;
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(card), |ui| {
        ui.vertical_centered(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            if let Some(name) = icon {
                let (r, _) = ui.allocate_exact_size(EMPTY_ICON, egui::Sense::hover());
                match EmptyIcon::from_name(name) {
                    Some(drawn) => paint_empty_icon(ui.painter(), r, drawn),
                    None => { ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, name, FontId::proportional(44.0), p.text); }
                }
                ui.add_space(gap_icon);
            }
            ui.label(RichText::new(title).font(title_font.clone()).color(p.strong));
            ui.add_space(gap_title);
            ui.add(egui::Label::new(RichText::new(subtitle).font(sub_font.clone()).color(p.disabled)).wrap());
            if let Some(label) = action_label {
                ui.add_space(gap_button);
                let b = egui::Button::new(bold(label, 12.5).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(110.0, button_h));
                clicked = Some(ui.add(b));
            }
        });
    });
    // the card owns the rest of this area
    ui.allocate_rect(avail, egui::Sense::hover());
    clicked
}

/// `empty_state_card` with one of the drawn icons. Returns (learn_more_clicked, primary_clicked);
/// the first is always false (there is no "Learn more" link).
pub fn empty_state(
    ui: &mut Ui,
    _p: &Palette,
    icon: EmptyIcon,
    title: &str,
    text: &str,
    primary: Option<&str>,
) -> (bool, bool) {
    let r = empty_state_card(ui, Some(icon.name()), title, text, primary);
    (false, r.is_some_and(|r| r.clicked()))
}

/// Simple flat isometric-style illustrations in the original's blue (shapes only).
pub fn paint_empty_icon(painter: &egui::Painter, r: egui::Rect, icon: EmptyIcon) {
    let blue = c(0x2C64A8);
    let blue2 = c(0x3B7BC8);
    let side = c(0x1E4677);
    let tile = |center: egui::Pos2, w: f32, h: f32, top: Color32| {
        let pts = vec![
            center + egui::vec2(-w / 2.0, 0.0),
            center + egui::vec2(0.0, -h / 2.0),
            center + egui::vec2(w / 2.0, 0.0),
            center + egui::vec2(0.0, h / 2.0),
        ];
        let low: Vec<egui::Pos2> = pts.iter().map(|q| *q + egui::vec2(0.0, 4.0)).collect();
        painter.add(egui::Shape::convex_polygon(low, side, Stroke::NONE));
        painter.add(egui::Shape::convex_polygon(pts, top, Stroke::NONE));
        for k in 0..2 {
            let o = egui::vec2(-w * 0.18 + k as f32 * 4.0, -h * 0.05 + k as f32 * 4.0);
            painter.line_segment([center + o, center + o + egui::vec2(w * 0.22, -h * 0.11)], Stroke::new(1.5_f32, Color32::from_white_alpha(170)));
        }
    };
    let cc = r.center();
    match icon {
        EmptyIcon::SiteMap => {
            painter.line_segment([cc + egui::vec2(-24.0, -4.0), cc + egui::vec2(0.0, 6.0)], Stroke::new(1.5_f32, c(0xC8C8C8)));
            painter.line_segment([cc + egui::vec2(24.0, -14.0), cc + egui::vec2(0.0, 6.0)], Stroke::new(1.5_f32, c(0xC8C8C8)));
            tile(cc + egui::vec2(-26.0, -4.0), 40.0, 22.0, blue);
            tile(cc + egui::vec2(26.0, -16.0), 40.0, 22.0, blue2);
            tile(cc + egui::vec2(8.0, 16.0), 40.0, 22.0, blue);
        }
        EmptyIcon::History | EmptyIcon::Logger => {
            tile(cc, 82.0, 46.0, blue);
            let dot = cc + egui::vec2(12.0, -10.0);
            painter.circle_filled(dot, 8.0, c(0x23558F));
            painter.circle_stroke(dot, 5.0, Stroke::new(1.2_f32, Color32::from_white_alpha(200)));
        }
        EmptyIcon::Organizer => {
            tile(cc, 110.0, 60.0, blue);
            painter.rect_filled(egui::Rect::from_center_size(cc + egui::vec2(24.0, -22.0), egui::vec2(22.0, 8.0)), 2.0, c(0x5C8FD0));
        }
        EmptyIcon::Intercept => {
            painter.line_segment([cc + egui::vec2(-40.0, -26.0), cc + egui::vec2(-18.0, -10.0)], Stroke::new(2.0_f32, c(0x4A4A4A)));
            painter.line_segment([cc + egui::vec2(40.0, -26.0), cc + egui::vec2(18.0, -10.0)], Stroke::new(2.0_f32, c(0x4A4A4A)));
            painter.line_segment([cc + egui::vec2(-40.0, 26.0), cc + egui::vec2(-18.0, 10.0)], Stroke::new(2.0_f32, c(0x4A4A4A)));
            painter.line_segment([cc + egui::vec2(40.0, 26.0), cc + egui::vec2(18.0, 10.0)], Stroke::new(2.0_f32, c(0x4A4A4A)));
            let body = egui::Rect::from_center_size(cc + egui::vec2(0.0, -4.0), egui::vec2(20.0, 50.0));
            painter.rect_filled(body, 6.0, blue);
            painter.circle_filled(cc + egui::vec2(0.0, -16.0), 5.0, c(0x1E4677));
            painter.circle_filled(cc + egui::vec2(0.0, 6.0), 5.0, c(0xB5D35B));
            painter.line_segment([cc + egui::vec2(0.0, 21.0), cc + egui::vec2(0.0, 36.0)], Stroke::new(3.0_f32, c(0x555555)));
        }
        EmptyIcon::Radar => {
            painter.add(egui::Shape::ellipse_filled(cc + egui::vec2(0.0, 6.0), egui::vec2(52.0, 30.0), c(0x222222)));
            painter.add(egui::Shape::ellipse_filled(cc, egui::vec2(52.0, 30.0), blue));
            for k in 1..4 {
                painter.add(egui::Shape::ellipse_stroke(cc, egui::vec2(13.0 * k as f32, 7.5 * k as f32), Stroke::new(1.2_f32, c(0x6FA0DA))));
            }
            for q in [egui::vec2(-2.0, -20.0), egui::vec2(-46.0, 10.0), egui::vec2(8.0, 10.0)] {
                painter.circle_filled(cc + q, 4.5, c(0xE1632F));
            }
        }
        EmptyIcon::Repeater => {
            let a = [cc + egui::vec2(-28.0, 4.0), cc + egui::vec2(18.0, -18.0)];
            painter.line_segment(a, Stroke::new(9.0_f32, blue2));
            painter.add(egui::Shape::convex_polygon(
                vec![cc + egui::vec2(16.0, -28.0), cc + egui::vec2(32.0, -24.0), cc + egui::vec2(22.0, -10.0)],
                blue2,
                Stroke::NONE,
            ));
            let b = [cc + egui::vec2(28.0, 0.0), cc + egui::vec2(-18.0, 22.0)];
            painter.line_segment(b, Stroke::new(9.0_f32, c(0x3E4A86)));
            painter.add(egui::Shape::convex_polygon(
                vec![cc + egui::vec2(-16.0, 32.0), cc + egui::vec2(-32.0, 28.0), cc + egui::vec2(-22.0, 14.0)],
                c(0x3E4A86),
                Stroke::NONE,
            ));
        }
    }
}

/// Table header row: grey bar with column titles at given widths.
pub fn table_header(ui: &mut Ui, p: &Palette, cols: &[(&str, f32)]) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 21.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, p.header);
    let mut x = rect.left() + 6.0;
    for (i, (name, w)) in cols.iter().enumerate() {
        ui.painter().text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, *name, FontId::proportional(12.5), p.text);
        x += w;
        if i + 1 < cols.len() {
            ui.painter().line_segment([egui::pos2(x - 4.0, rect.top() + 2.0), egui::pos2(x - 4.0, rect.bottom() - 2.0)], Stroke::new(1.0_f32, p.deep));
        }
    }
}

/// How tall a table row is when it holds nothing but text.
pub const ROW_HEIGHT: f32 = 19.0;

/// How tall a table row is when it holds widgets of its own -- a dropdown, an editor --
/// rather than text alone: enough room for the controls to sit in.
pub const WIDGET_ROW_HEIGHT: f32 = 24.0;

/// A table row the caller fills in: the background is painted here and the rectangle of each
/// column comes back, for text to be drawn in with [`cell_text`] or a widget to be put in
/// with `Ui::put`.
///
/// The background is the selection colour, else a wash of `tint` over the row -- a
/// highlighted item, kept faint enough to read dark text or light text on -- else the stripe.
/// The row senses clicks, as [`table_row`] does, and anything the caller puts in it is added
/// afterwards and so lies on top: a click on a dropdown in a cell goes to the dropdown, and a
/// click anywhere else in the row goes to the row.
pub fn table_row_cells(
    ui: &mut Ui,
    p: &Palette,
    id_salt: impl std::hash::Hash,
    widths: &[f32],
    height: f32,
    selected: bool,
    stripe: bool,
    tint: Option<Color32>,
) -> (egui::Response, Vec<egui::Rect>) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), egui::Sense::hover());
    // the row is interacted with under an id of its own, from what the row stands for rather
    // than from where it is in the table. egui keeps a context menu, and the hover and drag
    // it tracks, against that id: a row identified by its place loses them the moment the
    // table is re-sorted or the panel above it changes height, which closes an open menu
    // under the pointer.
    let resp = ui.interact(rect, ui.id().with(id_salt), egui::Sense::click());
    let base = if selected { p.selection } else if stripe { ui.visuals().faint_bg_color } else { p.deep };
    // a selected row keeps the selection colour: of the two things a row can be, which one is
    // being read matters more than which colour it was marked with
    let bg = match tint {
        Some(highlight) if !selected => row_tint(base, highlight),
        _ => base,
    };
    ui.painter().rect_filled(rect, 0.0, bg);
    if let Some(highlight) = tint {
        // the bar is what does the work: solid, the full height of the row, and at the very
        // edge the eye runs down
        let bar = egui::Rect::from_min_max(rect.left_top(), egui::pos2(rect.left() + ROW_ACCENT, rect.bottom()));
        ui.painter().rect_filled(bar, 0.0, highlight);
    }
    let mut x = rect.left() + 6.0;
    let cells = widths
        .iter()
        .map(|w| {
            let cell = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2((x + w - 8.0).max(x), rect.bottom()));
            x += w;
            cell
        })
        .collect();
    (resp, cells)
}

/// How much of a highlight colour is mixed into the row that carries it: about an alpha of
/// 31 in 255, were it painted as a translucent wash.
const ROW_TINT: f32 = 0.12;

/// A row's background with a wash of its highlight colour mixed into it.
///
/// Faint on purpose: what marks a highlighted row out is the bar down its left edge, and the
/// wash only has to say which colour it is. Any heavier and the coloured text in the row --
/// the method, the status, the status code -- would be read against a different background
/// from every other row's and lose its contrast.
///
/// The mixing is done here and the result painted once, opaque, rather than laying a
/// translucent rectangle over the row: a translucent paint comes out as many times heavier as
/// the row happens to be painted, and a row is painted more than once per frame.
pub fn row_tint(base: Color32, highlight: Color32) -> Color32 {
    blend(base, highlight, ROW_TINT)
}

/// `over` mixed into `under` by `amount` of its strength, as an opaque colour.
fn blend(under: Color32, over: Color32, amount: f32) -> Color32 {
    let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * amount).round().clamp(0.0, 255.0) as u8;
    Color32::from_rgb(mix(under.r(), over.r()), mix(under.g(), over.g()), mix(under.b(), over.b()))
}

/// How wide the bar down the left edge of a highlighted row is.
const ROW_ACCENT: f32 = 3.0;

/// A small triangle pointing down, drawn rather than written: the bundled fonts have no
/// such glyph. It marks something that opens when it is clicked.
pub fn caret(ui: &Ui, center: egui::Pos2, color: Color32) {
    let pts = vec![
        center + egui::vec2(-3.5, -1.75),
        center + egui::vec2(3.5, -1.75),
        center + egui::vec2(0.0, 2.25),
    ];
    ui.painter().add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
}

/// Draw one cell's text, clipped to the cell so a long value cannot run into the next column.
pub fn cell_text(ui: &Ui, cell: egui::Rect, text: &str, color: Color32) {
    ui.painter().with_clip_rect(cell).text(
        egui::pos2(cell.left(), cell.center().y),
        egui::Align2::LEFT_CENTER,
        text,
        FontId::proportional(12.5),
        color,
    );
}

/// The table header with each column a button: click to sort by it, again to reverse.
/// The column currently sorted on shows a triangle (up: ascending). Returns the column that
/// was clicked, if any; the caller owns the sort state, so every sortable table shares this.
pub fn sort_header<C: Copy + PartialEq>(ui: &mut Ui, p: &Palette, cols: &[(&str, f32, C)], active: Option<C>, ascending: bool) -> Option<C> {
    let mut clicked = None;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 21.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, p.header);
    let mut x = rect.left();
    for (i, (name, w, col)) in cols.iter().enumerate() {
        let cell = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2((x + w).min(rect.right()).max(x), rect.bottom()));
        let r = ui.interact(cell, ui.id().with(("sort_col", i)), egui::Sense::click());
        r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, *name));
        if r.hovered() {
            ui.painter().rect_filled(cell, 0.0, p.hover);
        }
        let label = ui.painter().text(egui::pos2(x + 6.0, rect.center().y), egui::Align2::LEFT_CENTER, *name, FontId::proportional(12.5), p.text);
        if active == Some(*col) {
            // drawn, not a glyph: the bundled fonts have no triangles
            let c = egui::pos2(label.right() + 8.0, rect.center().y);
            let pts = if ascending {
                vec![c + egui::vec2(-4.0, 2.5), c + egui::vec2(4.0, 2.5), c + egui::vec2(0.0, -3.0)]
            } else {
                vec![c + egui::vec2(-4.0, -2.5), c + egui::vec2(4.0, -2.5), c + egui::vec2(0.0, 3.0)]
            };
            ui.painter().add(egui::Shape::convex_polygon(pts, p.strong, Stroke::NONE));
        }
        if r.on_hover_text(format!("Sort by {name}")).clicked() {
            clicked = Some(*col);
        }
        x += w;
        if i + 1 < cols.len() {
            ui.painter().line_segment([egui::pos2(x - 4.0, rect.top() + 2.0), egui::pos2(x - 4.0, rect.bottom() - 2.0)], Stroke::new(1.0_f32, p.deep));
        }
    }
    clicked
}

/// One table row (text cells at the same widths). Returns the click response.
pub fn table_row(ui: &mut Ui, p: &Palette, cells: &[(String, f32, Option<Color32>)], selected: bool, stripe: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), ROW_HEIGHT), egui::Sense::click());
    let bg = if selected { p.selection } else if stripe { ui.visuals().faint_bg_color } else { p.deep };
    ui.painter().rect_filled(rect, 0.0, bg);
    let mut x = rect.left() + 6.0;
    for (text, w, col) in cells {
        let clip = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(x + w - 8.0, rect.bottom()));
        ui.painter().with_clip_rect(clip).text(
            egui::pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            FontId::proportional(12.5),
            if selected { p.strong } else { col.unwrap_or(p.text) },
        );
        x += w;
    }
    resp
}

/// Side-by-side columns, with the check egui's own `Ui::columns` is missing. It divides the
/// space left by the number of columns without making sure there is any ("TODO: ensure there
/// is space", says its source) and hands the result to `set_width`, which panics on a negative
/// width -- so a window dragged narrow enough takes the app with it. Below the width the
/// columns need, they are laid out at that width inside a sideways scroll area instead.
pub fn columns<R>(ui: &mut Ui, count: usize, add: impl FnOnce(&mut [Ui]) -> R) -> R {
    /// Narrower than this a column has nothing left to show.
    const MIN_COLUMN: f32 = 40.0;
    let count = count.max(1);
    let needed = MIN_COLUMN * count as f32 + ui.spacing().item_spacing.x * (count as f32 - 1.0);
    if ui.available_width() >= needed {
        return ui.columns(count, |columns| {
            // a column is whatever width it was handed: nothing inside one may decide that
            // the window has to stay wider than it is
            for column in columns.iter_mut() {
                column.set_min_width(0.0);
            }
            add(columns)
        });
    }
    egui::ScrollArea::horizontal().show(ui, |ui| {
        ui.set_max_width(needed);
        ui.columns(count, add)
    }).inner
}

/// Space left around a resizable window when it first opens, so no border of it is flush
/// against the edge of the screen and every one can be taken hold of.
const WINDOW_MARGIN: f32 = 48.0;
/// The smallest a resizable window's contents may be squeezed to. Small enough that the
/// window is never held open by what is inside it.
const WINDOW_MIN: egui::Vec2 = egui::vec2(360.0, 240.0);
/// Kept clear between the largest a window may grow to and the edge of the screen.
const WINDOW_SLACK: f32 = 16.0;

/// What a window adds around the area its contents are given: the frame's margins and
/// outline, and across the top the title bar and the hairline under it.
///
/// Every bound a window is given -- the minimum, the maximum -- applies to its contents, and
/// the chrome is added outside them. egui works this sum out for itself when it caps a window
/// to the screen, but leaves the frame's margins out of that one, so a window held back by
/// egui's cap alone still comes out a little larger than the display it is on. Taking the
/// chrome off here is what keeps the whole of the window inside the screen.
///
/// It is measured from the window itself, by [`show_resizable_window`], since only the window
/// knows how tall its own title bar came out. Until it has been drawn once, a deliberate
/// over-estimate stands in: a window a few pixels smaller than it could be, and never one too
/// large to fit.
fn window_chrome(ctx: &egui::Context, id: egui::Id) -> egui::Vec2 {
    ctx.data(|d| d.get_temp(chrome_id(id))).unwrap_or_else(|| {
        let style = ctx.style();
        let frame = egui::Frame::window(&style);
        // a row of text in the frame's margins, with the frame's hairline under it
        let title_bar = style.spacing.interact_size.y.max(24.0) + frame.inner_margin.sum().y + frame.stroke.width;
        frame.total_margin().sum() + egui::vec2(0.0, title_bar)
    })
}

/// Where a window's measured chrome is kept between frames.
fn chrome_id(id: egui::Id) -> egui::Id {
    id.with("window_chrome")
}

/// The smallest the contents of a resizable window may be on this screen.
fn window_min(ctx: &egui::Context) -> egui::Vec2 {
    // never negative: a window can be asked for on a screen smaller than the margins
    let room = (ctx.screen_rect().size() - egui::Vec2::splat(WINDOW_MARGIN * 2.0)).max(egui::Vec2::splat(80.0));
    WINDOW_MIN.min(room)
}

/// A floating window the user can resize, with bounds worked out from the screen it opens on:
/// about 85% of it, centred, leaving a margin on every side so all four resize borders are on
/// screen and can be taken hold of. The minimum is small and does not depend on what is inside,
/// so dragging the left or top border shrinks the window instead of pushing it sideways. The
/// maximum is the screen less the chrome and a hair, worked out again on every frame, so no
/// sequence of drags can leave a window larger than the display it is on.
///
/// No anchor is set, on purpose. An anchor pins one corner every frame, so dragging the
/// opposite border moves the whole window rather than resizing it. `constrain` takes its
/// place: it keeps the window inside the screen, and egui also uses it to cap a window that
/// was left larger than the screen it now opens on, which is what brings a window saved on a
/// bigger display back into view.
pub fn resizable_window<'a>(ctx: &egui::Context, id: egui::Id, title: impl Into<egui::WidgetText>) -> egui::Window<'a> {
    let screen = ctx.screen_rect();
    let min = window_min(ctx);
    let room = (screen.size() - egui::Vec2::splat(WINDOW_MARGIN * 2.0)).max(egui::Vec2::splat(80.0));
    let size = (screen.size() * 0.85).min(room);
    // the room left for the contents once the chrome has taken its share, less a hair so the
    // window is never flush with the edge of the screen. The floor wins on a screen too
    // small to hold even that: a maximum below the minimum is not a size at all.
    let max = (screen.size() - window_chrome(ctx, id) - egui::Vec2::splat(WINDOW_SLACK)).max(min);
    egui::Window::new(title)
        .id(id)
        .default_rect(egui::Rect::from_center_size(screen.center(), size))
        .min_width(min.x)
        .min_height(min.y)
        .max_width(max.x)
        .max_height(max.y)
        .resizable(true)
        .constrain(true)
}

/// Show a window built by [`resizable_window`], keeping the far border still when the near
/// one is dragged past a size the window cannot be drawn at.
///
/// A border drag puts the dragged edge under the pointer and leaves the opposite one where it
/// is, which is right for as long as the size between them is one the window can take. Once
/// it is not -- smaller than the window can shrink to, or larger than the screen allows --
/// the size stops following the pointer and the position does not: egui puts the near edge
/// under the pointer anyway, the far edge travels with it, and the window walks off across
/// the screen. Dragging the near border inwards walks the far one out of the far side of the
/// screen; carrying on outwards walks the near one off its own side, title bar and all.
///
/// So on those frames the window is held where it stood on the last frame that still resized
/// it, and taken out of the drag for as long as the pointer stays past the border. What does
/// the taking out is `movable`: it is what decides whether the left and top borders can be
/// dragged at all -- the right and bottom ones stay live either way -- and, unlike the
/// resizable flag, it belongs to the window's position and not to the state that remembers
/// the size a drag is asking for. That state is left alone, so letting the border go, or
/// dragging it back the other way, carries on from the size that is on screen rather than
/// from one the window had several frames ago.
///
/// Where the drag has got to is worked out before the window is drawn, so there is no frame
/// on which the window is drawn slid over and put back afterwards.
pub fn show_resizable_window<R>(
    ctx: &egui::Context,
    id: egui::Id,
    title: impl Into<egui::WidgetText>,
    open: &mut bool,
    add: impl FnOnce(&mut Ui) -> R,
) -> Option<egui::InnerResponse<Option<R>>> {
    let previous_id = id.with("previous_rect");
    let previous: Option<egui::Rect> = ctx.data(|d| d.get_temp(previous_id));
    let pointer = ctx.input(|i| i.pointer.interact_pos());

    // Which border the pointer has hold of. The ids are the ones egui gives a window's resize
    // borders, and which one is being dragged is read from the pointer rather than from the
    // borders themselves, so it is still there to be read on the frames when the near
    // borders are not registered at all. A drag of the title bar is neither of them, and
    // moves the whole window as it should.
    let border = egui::Id::new(egui::LayerId::new(egui::Order::Middle, id)).with("edge_drag");
    let dragged = ctx.dragged_id();
    let dragging = |names: [&str; 3]| {
        dragged.is_some_and(|held| names.iter().any(|name| held == border.with(name)))
    };
    let from_left = dragging(["left", "left_top", "left_bottom"]);
    let from_top = dragging(["top", "left_top", "right_top"]);

    // The smallest and largest the window is ever drawn at, chrome and all.
    let chrome = window_chrome(ctx, id);
    let floor = window_min(ctx) + chrome;
    let ceiling = (ctx.screen_rect().size() - egui::Vec2::splat(WINDOW_SLACK)).max(floor);
    // Keeping the far edge where it is, the near one can be put anywhere between the two: no
    // closer than the floor leaves it, no further than the ceiling allows. A pointer outside
    // that is asking for a window that cannot be drawn, so the window is held still instead.
    let hold = previous
        .zip(pointer)
        .filter(|(was, at)| {
            (from_left && (at.x < was.right() - ceiling.x || at.x > was.right() - floor.x))
                || (from_top && (at.y < was.bottom() - ceiling.y || at.y > was.bottom() - floor.y))
        })
        .map(|(was, _)| was);

    let mut window = resizable_window(ctx, id, title).open(open);
    if let Some(was) = hold {
        window = window.current_pos(was.left_top()).movable(false);
    }
    // what the contents took, which is what the window was drawn around: the difference
    // between the two is the chrome, for the next frame to work its bounds out from
    let mut content = None;
    let shown = window.show(ctx, |ui| {
        let inner = add(ui);
        content = Some(ui.min_rect().size());
        inner
    });
    match (shown.as_ref(), content) {
        (Some(response), Some(content)) => ctx.data_mut(|d| {
            let rect = response.response.rect;
            d.insert_temp(previous_id, rect);
            d.insert_temp(chrome_id(id), (rect.size() - content).max(egui::Vec2::ZERO));
        }),
        // closed, or collapsed, or faded out: nothing to measure, and nowhere it has to stay
        _ => ctx.data_mut(|d| d.remove::<egui::Rect>(previous_id)),
    }
    shown
}

/// Dark well behind a table body, filling the given height and the available width.
pub fn table_well(ui: &mut Ui, p: &Palette, height: f32, add: impl FnOnce(&mut Ui)) {
    let width = ui.available_width();
    table_well_sized(ui, p, width, height, add);
}

/// Table well of an exact width. Its contents always stack top to bottom, even when the
/// well sits in a horizontal row (next to a button column, say); otherwise the header and
/// the rows would be laid out side by side.
///
/// The width and height are floored at zero: a window dragged narrower than the panels
/// inside it leaves negative space over, and egui asserts on a negative size.
pub fn table_well_sized(ui: &mut Ui, p: &Palette, width: f32, height: f32, add: impl FnOnce(&mut Ui)) {
    egui::Frame::new().fill(p.deep).stroke(Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
        ui.set_min_height(height.max(0.0));
        ui.set_width((width - 2.0).max(0.0));
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            add(ui);
        });
    });
}

/// Column widths for a table `avail` wide: every column gets its minimum, and what's left
/// is shared out by weight. Columns with weight 0 stay at their minimum.
pub fn fit_columns(avail: f32, cols: &[(f32, f32)]) -> Vec<f32> {
    let min_total: f32 = cols.iter().map(|c| c.0).sum();
    let weights: f32 = cols.iter().map(|c| c.1).sum();
    let spare = (avail - min_total).max(0.0);
    cols.iter().map(|&(min, w)| if weights > 0.0 { min + spare * w / weights } else { min }).collect()
}

/// A table that fits the available width while its columns' minimums fit, and otherwise
/// scrolls sideways inside its own area (never widening its container). `add` gets the
/// column widths to use.
pub fn fitted_table(ui: &mut Ui, p: &Palette, id: impl std::hash::Hash, height: f32, cols: &[(f32, f32)], add: impl FnOnce(&mut Ui, &[f32])) {
    // never negative: a squeezed window can leave a panel with less than no room
    let avail = ui.available_width().max(0.0);
    let min_total: f32 = cols.iter().map(|c| c.0).sum::<f32>() + 12.0;
    if min_total <= avail {
        let widths = fit_columns((avail - 12.0).max(0.0), cols);
        table_well(ui, p, height, |ui| add(ui, &widths));
    } else {
        let widths = fit_columns((min_total - 12.0).max(0.0), cols);
        egui::ScrollArea::horizontal().id_salt(id).auto_shrink([false, true]).max_width(avail).show(ui, |ui| {
            table_well_sized(ui, p, min_total, height, |ui| add(ui, &widths));
        });
    }
}

/// Small rounded on/off toggle (the Settings scope filter, the history filter ribbon).
pub fn pill(ui: &mut Ui, p: &Palette, label: &str, on: bool) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(label.to_string(), FontId::proportional(11.5), if on { p.strong } else { p.text });
    let size = galley.size() + egui::vec2(14.0, 6.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, on, label));
    let fill = if on { p.selection } else if resp.hovered() { p.hover } else { p.header };
    ui.painter().rect_filled(rect, rect.height() / 2.0, fill);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, p.text);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    /// Draw `add` in a ui `width` wide, however little that is.
    fn in_a_ui_of(width: f32, add: impl FnOnce(&mut Ui)) {
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, 200.0));
        // `run` wants an FnMut, and this closure draws exactly once
        let mut add = Some(add);
        let _ = ctx.run(egui::RawInput { screen_rect: Some(screen), ..Default::default() }, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                // margins wider than the window itself: what is left inside the frame is less
                // than nothing, which is how a squeezed window comes by a negative width
                egui::Frame::new().inner_margin(egui::Margin::same(40)).show(ui, |ui| {
                    if let Some(add) = add.take() {
                        add(ui);
                    }
                });
            });
        });
    }

    /// egui asserts on a negative width or height, and a window dragged narrower than the
    /// margins inside it leaves exactly that. These are the helpers every screen lays out
    /// through, so each one has to cope with being handed nothing at all -- including the
    /// column layout, whose egui original divides the space left without checking there is any.
    #[test]
    fn the_layout_helpers_cope_with_no_room_at_all() {
        let p = &DARK;
        let widths: [f32; 5] = [800.0, 100.0, 10.0, 1.0, 0.0];
        assert_table!(widths, |idx, width| {
            // the width a table well subtracts its border from, and the width the columns
            // divide, are both worked out from this
            in_a_ui_of(width, |ui| {
                assert!(width > 80.0 || ui.available_width() < 2.0, "case #{idx} ({width}px): nothing to lay out in");
            });
            in_a_ui_of(width, |ui| table_well(ui, p, 40.0, |ui| { ui.label("row"); }));
            in_a_ui_of(width, |ui| table_well_sized(ui, p, ui.available_width(), 40.0, |ui| { ui.label("row"); }));
            in_a_ui_of(width, |ui| {
                fitted_table(ui, p, ("t", idx), 40.0, &[(120.0, 1.0), (80.0, 0.0)], |ui, w| {
                    table_header(ui, p, &[("A", w[0]), ("B", w[1])]);
                });
            });
            in_a_ui_of(width, |ui| columns(ui, 4, |cols| for c in cols.iter_mut() { c.label("x"); }));
        });
    }
}
