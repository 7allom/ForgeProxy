//! The ForgeProxy design system: the surface ladder and accent tokens, the typography and
//! geometry every control is laid out to, and the shared widgets built on them -- tables,
//! pills, header strips and empty states.
//!
//! Swatch index n = shades[n-1], 0 = core. The dark palette was checked against the
//! reference screenshots (reference/picture-8..26).

use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, RichText, Stroke, Ui};
use std::sync::Arc;

const fn c(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// The interface theme the whole app is painted in. Two readings of one design: the same
/// surface ladder, geometry and accent family, once on dark slate and once on cool daylight
/// grey. `DarkWorkstation` is the default.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    #[default]
    DarkWorkstation,
    /// The daylight reading. `classic98` is accepted when reading older settings files, which
    /// is what this slot used to hold.
    #[serde(alias = "classic98")]
    LightWorkstation,
}

impl ThemeMode {
    pub const ALL: [ThemeMode; 2] = [ThemeMode::DarkWorkstation, ThemeMode::LightWorkstation];

    /// The name shown in the Settings theme selector.
    pub fn label(&self) -> &'static str {
        match self {
            ThemeMode::DarkWorkstation => "Dark Workstation",
            ThemeMode::LightWorkstation => "Light Workstation",
        }
    }

    /// Whether this theme paints on dark surfaces. Drives egui's base `Visuals` and the few
    /// places that still choose a colour by light-or-dark.
    pub fn is_dark(&self) -> bool {
        matches!(self, ThemeMode::DarkWorkstation)
    }
}

#[derive(Clone, Copy)]
pub struct Palette {
    /// The corner radius every control and framed surface rounds to. Both themes share it:
    /// they are one design read twice, and geometry is not what tells them apart.
    pub corner: u8,
    // The surface ladder, deepest first. Each step is a clear luminance apart, so a pane
    // sitting on another reads as raised without needing a border to say so.
    /// The canvas behind every panel: editors, the tab strip, side panels.
    pub deep: Color32,
    /// The primary workspace surface: tab bodies, the title and status bars.
    pub panel: Color32,
    /// Raised chrome: toolbars, table headers, editor bars, buttons.
    pub header: Color32,
    /// What a raised surface becomes under the pointer.
    pub hover: Color32,
    /// Informational banners and task cards.
    pub banner: Color32,
    /// The tinted fill of a selected row.
    pub selection: Color32,
    /// The text drawn on that fill, which has to stay legible against it.
    pub selection_text: Color32,
    /// The softer selected fill, for the rows and chips whose foreground belongs to egui or
    /// to the caller and so cannot be recoloured with it: a tint the ordinary text colour is
    /// still readable on. egui's own selected labels and in-field text selection use this.
    pub selection_soft: Color32,
    /// Recessed text fields, which sit *below* the canvas so an input reads as a well.
    pub bg_input: Color32,
    /// The surface a list or table row is drawn on, and the stripe every other row takes.
    pub row_bg: Color32,
    pub row_stripe: Color32,
    /// A 1px divider or frame: visible, never loud.
    pub border_subtle: Color32,
    /// The 1px frame around whatever has the keyboard.
    pub border_focus: Color32,
    pub text: Color32,
    pub strong: Color32,
    pub disabled: Color32,
    pub link: Color32,
    /// The primary action fill: warm amber-orange, with [`Palette::accent_text`] over it.
    pub accent: Color32,
    /// The primary action under the pointer, and while it is being pressed.
    pub accent_hover: Color32,
    pub accent_active: Color32,
    /// Text and icons drawn on top of an accent fill, kept at high contrast against it.
    pub accent_text: Color32,
    /// Status tokens for badges and pills. These say what a thing *is* -- running, finished,
    /// gone wrong -- and are separate from the severity colours below, which grade a finding.
    pub badge_info: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub error: Color32,
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

/// Dark Workstation: cool dark slate with steel-blue and cyan accents, a touch of rounding,
/// and not a trace of orange.
pub const DARK_WORKSTATION: Palette = Palette {
    corner: 2,
    deep: c(0x181C24),
    panel: c(0x202632),
    header: c(0x2A313F),
    hover: c(0x333C4C),
    banner: c(0x1C2838),
    selection: c(0x1E4258),
    selection_text: c(0xFFFFFF),
    selection_soft: c(0x1E4258),
    bg_input: c(0x121620),
    row_bg: c(0x181C24),
    row_stripe: c(0x262D3A),
    border_subtle: c(0x333B49),
    border_focus: c(0x38BDF8),
    text: c(0xC8CED8),
    strong: c(0xFFFFFF),
    disabled: c(0x7C838F),
    link: c(0x38BDF8),
    // a bright cyan primary action with dark text over it, hovering lighter and pressing deeper
    accent: c(0x38BDF8),
    accent_hover: c(0x6FD0FF),
    accent_active: c(0x1BA0E0),
    accent_text: c(0x07283A),
    badge_info: c(0x38BDF8),
    success: c(0x4CBE80),
    warning: c(0xE0C24C),
    error: c(0xE4596E),
    get: c(0x5BC0DE),
    post: c(0x7E8AF0),
    other_method: c(0x5FBAC2),
    high: c(0xE8556A),
    medium: c(0xE0B84C),
    low: c(0x6AA8E0),
    info: c(0x9DA2A7),
    ed_text: c(0xCECECE),
    ed_header_name: c(0xD1E8F9),
    ed_header_value: c(0xBABABA),
    ed_first_line: c(0xD1E8F9),
    ed_line_numbers: c(0xBDBDBD),
    ed_param_name: c(0xBBCDFF),
    ed_param_value: c(0xA5C35B),
    syn_key: c(0x9CDCFE),
    syn_string: c(0xA5C35B),
    syn_number: c(0xD7BA7D),
    syn_literal: c(0xC586C0),
    ed_gutter: c(0x555555),
    ed_lozenge: c(0x333C4C),
    st_new: c(0xCADAF0),
    st_progress: c(0x7E8AF0),
    st_postponed: c(0x38BDF8),
    st_done: c(0x7DC164),
    st_ignored: c(0xEE95A1),
};

/// Light Workstation: the dark theme read in daylight. The same cool slate family and the
/// same cyan accent, turned over -- panels in a low-chroma blue-grey so the eye rests on
/// them, and white kept for the wells where text is actually read, which is what keeps the
/// screen's overall brightness down.
pub const LIGHT_WORKSTATION: Palette = Palette {
    corner: 2,
    // the surface ladder, deepest first, mirroring the dark theme step for step
    deep: c(0xDFE4EB),
    panel: c(0xEAEEF3),
    header: c(0xF2F5F8),
    hover: c(0xFBFCFD),
    banner: c(0xE3EDF6),
    selection: c(0xCFE0EF),
    selection_text: c(0x11202B),
    selection_soft: c(0xCFE0EF),
    // white is reserved for what is read: fields, editors and list rows
    bg_input: c(0xFFFFFF),
    row_bg: c(0xFFFFFF),
    row_stripe: c(0xF5F7FA),
    border_subtle: c(0xC3CCD8),
    border_focus: c(0x0A6C9B),
    text: c(0x2A3340),
    strong: c(0x111820),
    disabled: c(0x626D7C),
    link: c(0x0A6C9B),
    // the dark theme's cyan, taken down until white text sits safely on it
    accent: c(0x0A6C9B),
    accent_hover: c(0x0A77AC),
    accent_active: c(0x07557A),
    accent_text: c(0xFFFFFF),
    badge_info: c(0x0A6C9B),
    success: c(0x18703F),
    warning: c(0x855C00),
    error: c(0xAE2531),
    get: c(0x18703F),
    post: c(0x5347B8),
    other_method: c(0x0A6C9B),
    high: c(0xAE2531),
    medium: c(0x855C00),
    low: c(0x2A6098),
    info: c(0x5A6472),
    ed_text: c(0x2A3340),
    ed_header_name: c(0x0A6C9B),
    ed_header_value: c(0x3B4654),
    ed_first_line: c(0x111820),
    ed_line_numbers: c(0x6D7988),
    ed_param_name: c(0x5347B8),
    ed_param_value: c(0x18703F),
    syn_key: c(0x0A5C94),
    syn_string: c(0x9B2A2A),
    syn_number: c(0x15664A),
    syn_literal: c(0x7B3193),
    ed_gutter: c(0xDDE3EA),
    ed_lozenge: c(0xE6EBF1),
    st_new: c(0x2A6098),
    st_progress: c(0x5347B8),
    st_postponed: c(0x855C00),
    st_done: c(0x18703F),
    st_ignored: c(0xAE2531),
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

pub fn palette(mode: ThemeMode) -> Palette {
    match mode {
        ThemeMode::DarkWorkstation => DARK_WORKSTATION,
        ThemeMode::LightWorkstation => LIGHT_WORKSTATION,
    }
}

/// Noto Sans for the interface, Noto Sans Mono for messages and metrics.
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

/// Configure egui's `Visuals` and `Style` for `mode`: surfaces, strokes, geometry and the
/// typography split that keeps HTTP panes monospace while the chrome follows the theme. This is
/// the one entry point; everything the app paints reads from the palette it installs.
pub fn apply_theme(ctx: &egui::Context, mode: ThemeMode) {
    let p = palette(mode);
    let mut style = (*ctx.style()).clone();
    style.visuals = if mode.is_dark() { egui::Visuals::dark() } else { egui::Visuals::light() };
    let v = &mut style.visuals;
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    // a text field is a well: it sits below the canvas rather than on it
    v.extreme_bg_color = p.bg_input;
    // the stripe on every other table row, a hair away from the surface under it
    v.faint_bg_color = p.row_stripe;
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.link;
    v.selection.bg_fill = p.selection_soft;
    v.selection.stroke = Stroke::new(1.0_f32, p.text);
    v.window_stroke = Stroke::new(1.0_f32, p.border_subtle);
    let corner = egui::CornerRadius::same(p.corner);
    for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        w.fg_stroke.color = p.text;
        w.corner_radius = corner;
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border_subtle);
    v.widgets.inactive.weak_bg_fill = p.header;
    v.widgets.inactive.bg_fill = p.header;
    v.widgets.hovered.weak_bg_fill = p.hover;
    v.widgets.hovered.bg_fill = p.hover;
    v.widgets.active.weak_bg_fill = p.hover;
    v.widgets.open.weak_bg_fill = p.header;
    // every control carries the same 1px frame, which brightens on hover and again for focus
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border_subtle);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.border_subtle);
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, p.border_focus);
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, p.border_subtle);
    // a menu, a dropdown list or a tooltip floats over the work: a soft shadow is what says so
    let shade = if mode.is_dark() { Color32::from_black_alpha(96) } else { Color32::from_black_alpha(40) };
    v.popup_shadow = egui::epaint::Shadow { offset: [0, 3], blur: 10, spread: 0, color: shade };
    v.window_shadow = egui::epaint::Shadow { offset: [0, 6], blur: 18, spread: 0, color: shade };
    // the surface those float on, and the frame around it
    v.window_fill = p.panel;
    v.widgets.open.bg_fill = p.header;
    // text the user has selected inside a field, which must not vanish into the selection.
    // egui keeps drawing it in the ordinary text colour, so the fill behind it has to be one
    // that colour still reads on.
    v.selection.bg_fill = p.selection_soft;
    v.selection.stroke = Stroke::new(1.0_f32, p.text);
    // menus, dropdown lists and dialogs carry the same corner as everything else
    v.menu_corner_radius = corner;
    v.window_corner_radius = corner;
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    // one height for every button, field and dropdown, so a toolbar row lines up
    style.spacing.interact_size.y = CONTROL_H;
    style.text_styles.insert(egui::TextStyle::Body, FontId::proportional(FONT_UI));
    style.text_styles.insert(egui::TextStyle::Button, FontId::proportional(FONT_UI));
    style.text_styles.insert(egui::TextStyle::Monospace, FontId::monospace(FONT_CODE));
    style.text_styles.insert(egui::TextStyle::Small, FontId::proportional(FONT_CAPTION));
    style.text_styles.insert(egui::TextStyle::Heading, FontId::new(FONT_TITLE, FontFamily::Name("bold".into())));
    ctx.set_style(style);
}

/// The one control height every button, text field, dropdown and toolbar control is laid out
/// at, so a row of mixed controls shares a baseline and a centre line.
pub const CONTROL_H: f32 = 26.0;

/// The one corner radius, on every control and every framed surface.
pub const CORNER: u8 = 4;

/// Muted captions, badge text and column counts.
pub const FONT_CAPTION: f32 = 11.0;
/// Dense table text and UI controls: the size most of the app is written in.
pub const FONT_UI: f32 = 12.5;
/// Message bodies, hex, and any figure meant to line up under another.
pub const FONT_CODE: f32 = 13.0;
/// Section titles.
pub const FONT_TITLE: f32 = 14.0;

pub fn bold(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(FontId::new(size, FontFamily::Name("bold".into())))
}

/// The primary action, as "Start attack", "Open browser", "Next": the accent as a fill, with
/// [`Palette::accent_text`] over it.
pub fn primary_button(ui: &mut Ui, p: &Palette, label: &str) -> egui::Response {
    // drawn twice: once to learn whether the pointer is on it, then again in the shade that
    // answers. egui settles on the second frame, which is the frame anyone can see.
    let id = ui.next_auto_id();
    let fill = match ui.ctx().read_response(id) {
        Some(r) if r.is_pointer_button_down_on() => p.accent_active,
        Some(r) if r.hovered() => p.accent_hover,
        _ => p.accent,
    };
    ui.add(
        egui::Button::new(bold(label, FONT_UI).color(p.accent_text))
            .fill(fill)
            .corner_radius(egui::CornerRadius::same(p.corner))
            .min_size(egui::vec2(0.0, CONTROL_H)),
    )
}

/// A named action sized by the caller ("Send", "Start attack", "Compare words"). The same
/// face as [`primary_button`], with a width and height the caller fixes.
pub fn action_button(ui: &mut Ui, p: &Palette, label: &str, enabled: bool, min_size: egui::Vec2) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(bold(label, 13.0).color(if enabled { p.accent_text } else { p.disabled }))
            .fill(p.accent)
            .corner_radius(egui::CornerRadius::same(p.corner))
            .min_size(min_size),
    )
}

/// Grey button with bold label, as "Add", "Edit".
pub fn plain_button(ui: &mut Ui, p: &Palette, label: &str, enabled: bool) -> egui::Response {
    let txt = bold(label, 13.0).color(if enabled { p.text } else { p.disabled });
    ui.add_enabled(enabled, egui::Button::new(txt).fill(p.header).corner_radius(egui::CornerRadius::same(p.corner)).min_size(egui::vec2(0.0, 22.0)))
}

/// Fixed-width stacked button for the left-of-table button columns.
pub fn side_button(ui: &mut Ui, p: &Palette, label: &str, enabled: bool) -> egui::Response {
    let txt = bold(label, 12.5).color(if enabled { p.text } else { p.disabled });
    ui.add_enabled(enabled, egui::Button::new(txt).fill(p.header).min_size(egui::vec2(74.0, 20.0)))
}

/// Text tabs with an accent underline under the selected one (main and sub tabs).
pub fn underline_tabs<T: Copy + PartialEq>(ui: &mut Ui, p: &Palette, items: &[(T, &str)], selected: &mut T, height: f32) {
    for (value, label) in items {
        let is_sel = *selected == *value;
        let galley = ui.painter().layout_no_wrap(
            label.to_string(),
            FontId::proportional(FONT_UI),
            if is_sel { p.strong } else { p.text },
        );
        let w = galley.size().x + 22.0;
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, height), egui::Sense::click());
        resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, is_sel, *label));
        // the tab being read is a surface of its own; one not being read lifts only under the
        // pointer, as a rounded pill inset from the strip
        if is_sel {
            ui.painter().rect_filled(rect, egui::CornerRadius { nw: p.corner, ne: p.corner, sw: 0, se: 0 }, p.panel);
        } else if resp.hovered() {
            let pill = rect.shrink2(egui::vec2(2.0, 4.0));
            ui.painter().rect_filled(pill, egui::CornerRadius::same(p.corner), p.hover);
        }
        let pos = egui::pos2(rect.center().x - galley.size().x / 2.0, rect.center().y - galley.size().y / 2.0);
        ui.painter().galley(pos, galley, p.text);
        if is_sel {
            let r = egui::Rect::from_min_max(egui::pos2(rect.left(), rect.bottom() - 2.0), rect.right_bottom());
            ui.painter().rect_filled(r, 0.0, p.accent);
        }
        if resp.clicked() {
            *selected = *value;
        }
    }
}

/// Bold section title with the round "?" and gear icons on its left, as in the settings panes.
/// One compact strip per tool: the name, and a `?` that explains it on hover.
///
/// The explanation used to sit under the title as a paragraph of its own, on every tab, with a
/// gear beside it that did nothing. A tool is used far more often than it is read about, so
/// the words move into the tooltip and the vertical space goes to the work.
pub fn section_title(ui: &mut Ui, p: &Palette, title: &str, description: &str) {
    ui.horizontal(|ui| {
        ui.label(bold(title, FONT_TITLE).color(p.strong));
        if !description.is_empty() {
            icon_help(ui, p).on_hover_text(description);
        }
    });
}

/// The round `?` that carries a tooltip: a 1px circle with the glyph dead-centre in it.
///
/// Centred on the glyph's *ink*. A galley's `rect` is its line box, which carries the room the
/// font leaves below the baseline for descenders; "?" has none, so centring on the line box
/// leaves the glyph sitting visibly high in the circle. `mesh_bounds` is the rectangle the
/// glyph actually covers, which is what the eye judges the centre by.
pub fn icon_help(ui: &mut Ui, p: &Palette) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::click());
    let centre = rect.center();
    let lit = resp.hovered();
    if lit {
        ui.painter().circle_filled(centre, 8.0, p.hover);
    }
    ui.painter().circle_stroke(centre, 7.5, Stroke::new(1.0_f32, if lit { p.strong } else { p.disabled }));
    let colour = if lit { p.strong } else { p.text };
    let galley = ui.painter().layout_no_wrap("?".to_string(), FontId::proportional(11.0), colour);
    ui.painter().galley(centre - glyph_ink(&galley).center().to_vec2(), galley, colour);
    resp
}

/// The rectangle a laid-out glyph's ink covers, for placing it by eye rather than by line box.
/// Falls back to the line box when there is no ink to measure -- whitespace, or a font that
/// reported nothing.
fn glyph_ink(galley: &egui::Galley) -> egui::Rect {
    let ink = galley.mesh_bounds;
    if ink.is_positive() && ink.is_finite() {
        ink
    } else {
        galley.rect
    }
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

/// Small toggle switch, filled in the accent when on, as "Capturing".
pub fn toggle(ui: &mut Ui, on: &mut bool) -> egui::Response {
    let p = palette(if ui.visuals().dark_mode { ThemeMode::DarkWorkstation } else { ThemeMode::LightWorkstation });
    let p = &p;
    let (rect, mut resp) = ui.allocate_exact_size(egui::vec2(28.0, 15.0), egui::Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *on, "Capturing"));
    let bg = if *on { p.accent } else { p.hover };
    ui.painter().rect_filled(rect, 7.5, bg);
    let x = if *on { rect.right() - 7.5 } else { rect.left() + 7.5 };
    ui.painter().circle_filled(egui::pos2(x, rect.center().y), 5.0, text_on(bg));
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

const EMPTY_ICON: egui::Vec2 = egui::vec2(40.0, 40.0);
const EMPTY_MAX_WIDTH: f32 = 340.0;

/// "Nothing here yet" card, centred horizontally and vertically in the space left in `ui`
/// (which it then fills): an icon (a drawn illustration named as in `EmptyIcon::from_name`,
/// or any other text as a glyph), a bold title, a dimmed wrapped subtitle, and an optional
/// button. Returns the button's response.
pub fn empty_state_card(ui: &mut Ui, icon: Option<&str>, title: &str, subtitle: &str, action_label: Option<&str>) -> Option<egui::Response> {
    let p = palette(if ui.visuals().dark_mode { ThemeMode::DarkWorkstation } else { ThemeMode::LightWorkstation });
    let avail = ui.available_rect_before_wrap();
    let width = EMPTY_MAX_WIDTH.min(avail.width() - 32.0).max(120.0);
    // measure first, so the whole card (not just its top) sits in the middle
    let title_font = FontId::new(FONT_TITLE, egui::FontFamily::Name("bold".into()));
    let sub_font = FontId::proportional(12.0);
    let title_h = ui.fonts(|f| f.row_height(&title_font));
    let sub_h = ui.fonts(|f| f.layout(subtitle.to_string(), sub_font.clone(), p.disabled, width).size().y);
    let (gap_icon, gap_title, gap_button, button_h) = (16.0, 8.0, 16.0, 26.0);
    let height = icon.map_or(0.0, |_| EMPTY_ICON.y + gap_icon) + title_h + gap_title + sub_h
        + action_label.map_or(0.0, |_| gap_button + button_h);
    let top = (avail.center().y - height / 2.0).max(avail.top() + 12.0);
    let card = egui::Rect::from_min_size(egui::pos2(avail.center().x - width / 2.0, top), egui::vec2(width, height));
    let mut clicked = None;
    // a quiet container behind it, so the icon and its words read as one placed object rather
    // than as text adrift in an empty panel
    let container = card.expand2(egui::vec2(24.0, 20.0));
    ui.painter().rect_filled(container, egui::CornerRadius::same(CORNER * 2), p.deep);
    ui.painter().rect_stroke(
        container,
        egui::CornerRadius::same(CORNER * 2),
        Stroke::new(1.0_f32, p.border_subtle),
        egui::StrokeKind::Inside,
    );
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(card), |ui| {
        ui.vertical_centered(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            if let Some(name) = icon {
                let (r, _) = ui.allocate_exact_size(EMPTY_ICON, egui::Sense::hover());
                match EmptyIcon::from_name(name) {
                    Some(drawn) => paint_empty_icon(ui.painter(), r, drawn, &p),
                    None => { ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, name, FontId::proportional(44.0), p.text); }
                }
                ui.add_space(gap_icon);
            }
            ui.label(RichText::new(title).font(title_font.clone()).color(p.strong));
            ui.add_space(gap_title);
            ui.add(egui::Label::new(RichText::new(subtitle).font(sub_font.clone()).color(p.disabled)).wrap());
            if let Some(label) = action_label {
                ui.add_space(gap_button);
                let b = egui::Button::new(bold(label, FONT_UI).color(p.accent_text))
                    .fill(p.accent)
                    .corner_radius(egui::CornerRadius::same(CORNER))
                    .min_size(egui::vec2(110.0, button_h));
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

/// One quiet monochrome line icon, drawn inside a rounded badge.
///
/// These used to be multi-coloured isometric illustrations the width of the card. An empty
/// state is a thing the eye should pass over on its way to the words that say what to do, so
/// the drawing is now a single-weight outline in the muted text colour, sitting in a badge the
/// size of a large glyph.
pub fn paint_empty_icon(painter: &egui::Painter, r: egui::Rect, icon: EmptyIcon, p: &Palette) {
    let badge = egui::Rect::from_center_size(r.center(), EMPTY_ICON);
    painter.rect_filled(badge, egui::CornerRadius::same(CORNER * 2), p.header);
    painter.rect_stroke(
        badge,
        egui::CornerRadius::same(CORNER * 2),
        Stroke::new(1.0_f32, p.border_subtle),
        egui::StrokeKind::Inside,
    );
    let cc = badge.center();
    let ink = Stroke::new(1.5_f32, p.disabled);
    let at = |dx: f32, dy: f32| cc + egui::vec2(dx, dy);
    let line = |a: egui::Pos2, b: egui::Pos2| painter.line_segment([a, b], ink);
    // every icon is drawn inside the same 22x22 box in the middle of the badge
    match icon {
        // three nodes joined by the branches between them
        EmptyIcon::SiteMap => {
            line(at(-7.0, -7.0), at(-7.0, 7.0));
            line(at(-7.0, -7.0), at(5.0, -7.0));
            line(at(-7.0, 0.0), at(5.0, 0.0));
            line(at(-7.0, 7.0), at(5.0, 7.0));
            for dy in [-7.0, 0.0, 7.0] {
                painter.circle_stroke(at(7.5, dy), 2.5, ink);
            }
        }
        // a sheet of paper with lines of text on it
        EmptyIcon::History | EmptyIcon::Logger => {
            let page = egui::Rect::from_min_max(at(-7.0, -9.0), at(7.0, 9.0));
            painter.rect_stroke(page, egui::CornerRadius::same(2), ink, egui::StrokeKind::Inside);
            for dy in [-4.0, 0.0, 4.0] {
                line(at(-4.0, dy), at(4.0, dy));
            }
        }
        // a tray with a tab above it
        EmptyIcon::Organizer => {
            line(at(-8.0, -6.0), at(-1.0, -6.0));
            let body = egui::Rect::from_min_max(at(-9.0, -2.0), at(9.0, 8.0));
            painter.rect_stroke(body, egui::CornerRadius::same(2), ink, egui::StrokeKind::Inside);
            line(at(-9.0, 3.0), at(9.0, 3.0));
        }
        // two bars: traffic held rather than passed
        EmptyIcon::Intercept => {
            for dx in [-4.0, 4.0] {
                line(at(dx, -8.0), at(dx, 8.0));
            }
            painter.circle_stroke(cc, 11.0, Stroke::new(1.0_f32, p.border_subtle));
        }
        // pulse rings going out from a point, and one return
        EmptyIcon::Radar => {
            for k in 1..=3 {
                painter.circle_stroke(cc, 3.5 * k as f32, ink);
            }
            painter.circle_filled(at(7.0, -7.0), 2.0, p.accent);
        }
        // a packet out and a packet back
        EmptyIcon::Repeater => {
            line(at(-8.0, -5.0), at(6.0, -5.0));
            line(at(2.0, -9.0), at(7.0, -5.0));
            line(at(2.0, -1.0), at(7.0, -5.0));
            line(at(8.0, 5.0), at(-6.0, 5.0));
            line(at(-2.0, 1.0), at(-7.0, 5.0));
            line(at(-2.0, 9.0), at(-7.0, 5.0));
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
pub const ROW_HEIGHT: f32 = 23.0;

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
    let base = if selected {
        p.selection
    } else if resp.hovered() {
        p.hover
    } else if stripe {
        p.row_stripe
    } else {
        p.row_bg
    };
    // a selected row keeps the selection colour: of the two things a row can be, which one is
    // being read matters more than which colour it was marked with
    let bg = match tint {
        Some(highlight) if !selected => row_tint(base, highlight),
        _ => base,
    };
    ui.painter().rect_filled(rect, 0.0, bg);
    // the bar is what does the work: solid, the full height of the row, and at the very edge
    // the eye runs down. The row being read claims it in the accent; otherwise it shows
    // whichever colour the row was marked with.
    let edge = match (selected, tint) {
        (true, _) => Some(p.accent),
        (false, Some(highlight)) => Some(highlight),
        (false, None) => None,
    };
    if let Some(colour) = edge {
        let bar = egui::Rect::from_min_max(rect.left_top(), egui::pos2(rect.left() + ROW_ACCENT, rect.bottom()));
        ui.painter().rect_filled(bar, 0.0, colour);
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
    let bg = if selected {
        p.selection
    } else if resp.hovered() {
        p.hover
    } else if stripe {
        p.row_stripe
    } else {
        p.row_bg
    };
    ui.painter().rect_filled(rect, 0.0, bg);
    if selected {
        let bar = egui::Rect::from_min_max(rect.left_top(), egui::pos2(rect.left() + ROW_ACCENT, rect.bottom()));
        ui.painter().rect_filled(bar, 0.0, p.accent);
    }
    let mut x = rect.left() + 6.0;
    for (text, w, col) in cells {
        let clip = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(x + w - 8.0, rect.bottom()));
        ui.painter().with_clip_rect(clip).text(
            egui::pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            FontId::proportional(12.5),
            if selected { p.selection_text } else { col.unwrap_or(p.text) },
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
        // there is no roll-up caret on a dialog of this era: it is closed, not collapsed
        .collapsible(false)
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
    let r = egui::Frame::new().fill(p.row_bg).stroke(Stroke::new(1.0_f32, p.border_subtle)).show(ui, |ui| {
        ui.set_min_height(height.max(0.0));
        ui.set_width((width - 2.0).max(0.0));
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            add(ui);
        });
    });
    let _ = r;
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

/// Whichever of the palette's near-black and near-white reads better on `fill`.
///
/// For text on a coloured fill that is neither of the theme's surfaces nor the accent -- a
/// destructive action's crimson, a highlight swatch. The answer depends on the fill alone, so
/// it is the same in either theme.
pub fn text_on(fill: Color32) -> Color32 {
    // the WCAG relative luminance, which is what decides legibility here
    let channel = |v: u8| {
        let v = f32::from(v) / 255.0;
        if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
    };
    let l = 0.2126 * channel(fill.r()) + 0.7152 * channel(fill.g()) + 0.0722 * channel(fill.b());
    // 0.18 is where white text and black text are about equally readable
    if l > 0.18 { DARK_WORKSTATION.bg_input } else { LIGHT_WORKSTATION.bg_input }
}

/// A status pill for the chrome: a filled dot in `colour` and a word beside it, on a raised
/// rounded fill. Hoverable, so the caller can hang a tooltip or a click on what comes back.
pub fn status_pill(ui: &mut Ui, p: &Palette, text: &str, colour: Color32) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::proportional(FONT_CAPTION), p.text);
    let size = egui::vec2(galley.size().x + 24.0, (galley.size().y + 7.0).max(18.0));
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, text));
    let fill = if resp.hovered() { p.hover } else { p.header };
    ui.painter().rect_filled(rect, egui::CornerRadius::same(CORNER), fill);
    ui.painter().circle_filled(egui::pos2(rect.left() + 9.0, rect.center().y), 3.5, colour);
    ui.painter().galley(egui::pos2(rect.left() + 17.0, rect.center().y - galley.size().y / 2.0), galley, p.text);
    resp
}

/// A thin upright divider between two groups of chrome.
pub fn chrome_divider(ui: &mut Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(9.0, 16.0), egui::Sense::hover());
    let x = rect.center().x;
    ui.painter().line_segment(
        [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
        Stroke::new(1.0_f32, p.border_subtle),
    );
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
        // the bold family the titles are set in is bound by the app's own font setup
        install_fonts(&ctx);
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
        let p = &DARK_WORKSTATION;
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

    /// Every empty state draws its badge and its words, at any width, and the one that has an
    /// action hands the caller something to act on.
    #[test]
    fn every_empty_state_icon_draws_matrix() {
        let icons = ["sitemap", "history", "intercept", "logger", "organizer", "radar", "repeater"];
        assert_table!(icons, |idx, name| {
            for width in [1200.0_f32, 420.0, 90.0] {
                in_a_ui_of(width, |ui| {
                    let r = empty_state_card(ui, Some(name), "Nothing here yet", "A short line about what would fill this.", None);
                    assert!(r.is_none(), "case #{idx} ({name}): no action was asked for, so none came back");
                });
            }
            in_a_ui_of(900.0, |ui| {
                let r = empty_state_card(ui, Some(name), "Nothing here yet", "A short line.", Some("Do the thing"));
                assert!(r.is_some(), "case #{idx} ({name}): the action is there to click");
            });
        });
        // a name no icon answers to falls back to drawing the name, rather than drawing nothing
        in_a_ui_of(900.0, |ui| {
            let _ = empty_state_card(ui, Some("no-such-icon"), "Title", "Text", None);
        });
    }

    /// The WCAG relative luminance of a colour, on the 0..1 scale the contrast formula wants.
    fn luminance(col: Color32) -> f64 {
        let channel = |v: u8| {
            let v = f64::from(v) / 255.0;
            if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * channel(col.r()) + 0.7152 * channel(col.g()) + 0.0722 * channel(col.b())
    }

    /// The WCAG contrast ratio between two colours, 1.0 (identical) to 21.0 (black on white).
    fn contrast(fg: Color32, bg: Color32) -> f64 {
        let (a, b) = (luminance(fg), luminance(bg));
        let (hi, lo) = if a > b { (a, b) } else { (b, a) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Every colour the app writes text or a badge in, against the surface it is drawn on, in
    /// both themes.
    ///
    /// Body text is held to the WCAG AA ratio of 4.5. Deliberately quiet text and the coloured
    /// badges, methods and syntax tones are held to 3.0, the ratio AA asks of large text and of
    /// user interface components: these carry a word or two at a time, and pushing them to 4.5
    /// would flatten the hues they exist to tell apart.
    #[test]
    fn every_foreground_is_legible_on_its_surface_in_both_themes() {
        let mut bad: Vec<String> = Vec::new();
        for (theme, p) in [("dark", &DARK_WORKSTATION), ("light", &LIGHT_WORKSTATION)] {
            // the surfaces text is read on
            let body: [(&str, Color32, &str, Color32); 11] = [
                ("text on the canvas", p.text, "deep", p.deep),
                ("text on a panel", p.text, "panel", p.panel),
                ("text on raised chrome", p.text, "header", p.header),
                ("text in an input", p.text, "bg_input", p.bg_input),
                ("text under the pointer", p.text, "hover", p.hover),
                ("text on a selected row", p.selection_text, "selection", p.selection),
                ("emphasis on a panel", p.strong, "panel", p.panel),
                ("emphasis on the canvas", p.strong, "deep", p.deep),
                ("a banner's text", p.text, "banner", p.banner),
                // the menu titles, which are drawn straight onto the menu strip
                ("the top menu's titles", p.text, "the menu strip", p.panel),
                // the label on the primary action, which is the one place accent is a fill
                ("the primary action's label", p.accent_text, "accent", p.accent),
            ];
            for (what, fg, surface, bg) in body {
                let r = contrast(fg, bg);
                if r < 4.5 { bad.push(format!("{theme}: {what} on {surface} is {r:.2}:1 (needs 4.5)")); }
            }

            // the primary action also has a hover and a pressed shade to stay readable on
            for (name, fill) in [("hovered", p.accent_hover), ("pressed", p.accent_active)] {
                let r = contrast(p.accent_text, fill);
                if r < 4.5 { bad.push(format!("{theme}: primary label on accent_{name} is {r:.2}:1 (needs 4.5)")); }
            }

            // badges, methods, severities and syntax: a word at a time, on panel and canvas
            let accents: [(&str, Color32); 16] = [
                ("badge_info", p.badge_info),
                ("success", p.success),
                ("warning", p.warning),
                ("error", p.error),
                ("high severity", p.high),
                ("medium severity", p.medium),
                ("low severity", p.low),
                ("link", p.link),
                ("GET", p.get),
                ("POST", p.post),
                ("other methods", p.other_method),
                ("quiet text", p.disabled),
                ("syntax keys", p.syn_key),
                ("syntax strings", p.syn_string),
                ("syntax numbers", p.syn_number),
                ("syntax literals", p.syn_literal),
            ];
            for (what, fg) in accents {
                for (surface, bg) in [("panel", p.panel), ("deep", p.deep), ("header", p.header)] {
                    let r = contrast(fg, bg);
                    if r < 3.0 { bad.push(format!("{theme}: {what} on {surface} is {r:.2}:1 (needs 3.0)")); }
                }
            }

            // the message editors draw their own text on the recessed input surface
            let editor: [(&str, Color32); 6] = [
                ("message text", p.ed_text),
                ("header names", p.ed_header_name),
                ("header values", p.ed_header_value),
                ("first lines", p.ed_first_line),
                ("parameter names", p.ed_param_name),
                ("parameter values", p.ed_param_value),
            ];
            for (what, fg) in editor {
                for (surface, bg) in [("bg_input", p.bg_input), ("deep", p.deep)] {
                    let r = contrast(fg, bg);
                    if r < 3.0 { bad.push(format!("{theme}: {what} on {surface} is {r:.2}:1 (needs 3.0)")); }
                }
            }
            // the gutter's line numbers are read against the gutter itself
            let r = contrast(p.ed_line_numbers, p.ed_gutter);
            if r < 3.0 { bad.push(format!("{theme}: line numbers on the gutter are {r:.2}:1 (needs 3.0)")); }

            // and the surfaces have to be told apart from one another at all
            for (a_name, a, b_name, b) in [
                ("deep", p.deep, "panel", p.panel),
                ("panel", p.panel, "header", p.header),
                ("header", p.header, "hover", p.hover),
            ] {
                let step = (luminance(a) - luminance(b)).abs();
                if step <= 0.0008 { bad.push(format!("{theme}: {a_name} and {b_name} are the same surface ({step:.5})")); }
            }
        }
        assert!(bad.is_empty(), "{} contrast shortfalls:\n  {}", bad.len(), bad.join("\n  "));
    }

    /// The dark theme is the default, both readings share one geometry, and the mode
    /// round-trips through its settings form -- including the name the light slot used to be
    /// saved under, which older settings files still hold.
    #[test]
    fn the_theme_mode_defaults_geometry_and_serde() {
        assert_eq!(ThemeMode::default(), ThemeMode::DarkWorkstation, "the dark theme is the default");
        assert!(ThemeMode::DarkWorkstation.is_dark());
        assert!(!ThemeMode::LightWorkstation.is_dark());

        assert_eq!(palette(ThemeMode::LightWorkstation).corner, palette(ThemeMode::DarkWorkstation).corner,
            "one geometry, read twice: the themes differ in colour alone");

        for m in ThemeMode::ALL {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ThemeMode>(&json).unwrap(), m, "{m:?} round-trips as {json}");
            assert!(!m.label().is_empty());
        }
        assert_eq!(serde_json::to_string(&ThemeMode::LightWorkstation).unwrap(), "\"light_workstation\"");
        assert_eq!(serde_json::to_string(&ThemeMode::DarkWorkstation).unwrap(), "\"dark_workstation\"");
        // a settings file written before the light theme was reworked still loads
        assert_eq!(serde_json::from_str::<ThemeMode>("\"classic98\"").unwrap(), ThemeMode::LightWorkstation);
    }

    /// `apply_theme` installs each theme's surfaces and geometry onto a live context: the panel
    /// fill, the widget corner radius and egui's own dark-mode flag all follow the mode.
    #[test]
    fn apply_theme_installs_the_palette_and_geometry() {
        let ctx = egui::Context::default();
        for mode in ThemeMode::ALL {
            apply_theme(&ctx, mode);
            let v = ctx.style().visuals.clone();
            let p = palette(mode);
            assert_eq!(v.panel_fill, p.panel, "{mode:?}: the panel fill is the palette's");
            assert_eq!(v.extreme_bg_color, p.bg_input, "{mode:?}: the editor well is the palette's input");
            assert_eq!(v.dark_mode, mode.is_dark(), "{mode:?}: egui's dark-mode flag follows the theme");
            assert_eq!(v.widgets.inactive.corner_radius, egui::CornerRadius::same(p.corner), "{mode:?}: widgets round to the palette corner");
        }
    }
}

// ---- the outer shell -----------------------------------------------------------------------
//
// The workstation shell is a navigation rail down the left, one slim command bar across the
// top, and the open tool as an inset card on the canvas. The geometry it is laid out to lives
// here with everything else, so the shell and the tools round, inset and shade alike.

/// The rail with room for a group caption and a label beside every icon.
pub const RAIL_W: f32 = 200.0;
/// The rail with room for the icons alone, each carrying its name as a tooltip.
pub const RAIL_W_COLLAPSED: f32 = 52.0;
/// At or above this window width the rail may show labels.
pub const RAIL_LABELS_MIN: f32 = 1200.0;
/// Below this window width the rail has no column of its own and opens over the work.
pub const RAIL_OVERLAY_MAX: f32 = 820.0;
/// One rail row, tall enough to hit comfortably without spreading twelve of them off-screen.
pub const RAIL_ROW_H: f32 = 28.0;
/// The gutter of canvas left around the tool card on every side.
pub const CARD_GUTTER: i8 = 10;
/// The command bar's height, which is the whole of the chrome above the work.
pub const COMMAND_BAR_H: f32 = 34.0;

/// The glyph a tool is known by in the rail. Drawn in code rather than set as text: the
/// interface font is not guaranteed to carry any particular symbol, and a missing glyph in
/// the only label a collapsed rail has would leave a tool unreachable by eye.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToolIcon {
    /// Dashboard: a dial with its needle.
    Gauge,
    /// Target: a crosshair over a ring.
    Crosshair,
    /// Proxy: traffic passing through a point in the middle.
    Relay,
    /// Intruder: a grid of positions to substitute at.
    Grid,
    /// Repeater: one request going round again.
    Loop,
    /// Interactor: a signal arriving from outside.
    Waves,
    /// Sequencer: sampled tokens as columns of differing height.
    Bars,
    /// Decoder: a transformation, written as brackets.
    Braces,
    /// Comparer: two panes side by side.
    Columns,
    /// Logger: a page of recorded lines.
    Lines,
    /// Organizer: a tray things are filed into.
    Tray,
    /// Automation: two cogs, one driving the other.
    Cogs,
}

/// Draw `icon` centred on `centre`, inside a 16x16 box, in `col`.
pub fn paint_tool_icon(painter: &egui::Painter, centre: egui::Pos2, icon: ToolIcon, col: Color32) {
    let s = Stroke::new(1.4_f32, col);
    let thin = Stroke::new(1.0_f32, col);
    let at = |dx: f32, dy: f32| centre + egui::vec2(dx, dy);
    let line = |a: egui::Pos2, b: egui::Pos2| painter.line_segment([a, b], s);
    let box_of = |a: egui::Pos2, b: egui::Pos2, stroke: Stroke| {
        painter.rect_stroke(egui::Rect::from_min_max(a, b), egui::CornerRadius::same(1), stroke, egui::StrokeKind::Inside);
    };
    match icon {
        ToolIcon::Gauge => {
            painter.add(egui::Shape::Path(egui::epaint::PathShape {
                points: (0..=12).map(|k| {
                    let t = std::f32::consts::PI * (1.0 + k as f32 / 12.0);
                    at(6.5 * t.cos(), 6.5 * t.sin())
                }).collect(),
                closed: false,
                fill: Color32::TRANSPARENT,
                stroke: s.into(),
            }));
            line(centre, at(4.0, -4.5));
        }
        ToolIcon::Crosshair => {
            painter.circle_stroke(centre, 5.5, s);
            for (dx, dy) in [(0.0, -8.0), (0.0, 8.0), (-8.0, 0.0), (8.0, 0.0)] {
                line(at(dx * 0.7, dy * 0.7), at(dx, dy));
            }
        }
        ToolIcon::Relay => {
            line(at(-8.0, -4.0), at(-2.5, -4.0));
            line(at(2.5, -4.0), at(8.0, -4.0));
            line(at(-8.0, 4.0), at(-2.5, 4.0));
            line(at(2.5, 4.0), at(8.0, 4.0));
            painter.circle_stroke(centre, 2.5, s);
        }
        ToolIcon::Grid => {
            box_of(at(-7.0, -7.0), at(7.0, 7.0), s);
            line(at(-7.0, -2.0), at(7.0, -2.0));
            line(at(-7.0, 3.0), at(7.0, 3.0));
            line(at(-2.0, -7.0), at(-2.0, 7.0));
        }
        ToolIcon::Loop => {
            painter.add(egui::Shape::Path(egui::epaint::PathShape {
                points: (0..=16).map(|k| {
                    let t = std::f32::consts::PI * (0.35 + 1.5 * k as f32 / 16.0);
                    at(6.5 * t.cos(), 6.5 * t.sin())
                }).collect(),
                closed: false,
                fill: Color32::TRANSPARENT,
                stroke: s.into(),
            }));
            // the arrow head that says which way round it goes
            line(at(2.0, -7.5), at(6.0, -4.5));
            line(at(1.5, -1.5), at(6.0, -4.5));
        }
        ToolIcon::Waves => {
            for r in [2.5_f32, 5.5, 8.0] {
                painter.add(egui::Shape::Path(egui::epaint::PathShape {
                    points: (0..=10).map(|k| {
                        let t = std::f32::consts::PI * (-0.4 + 0.8 * k as f32 / 10.0);
                        at(-5.0 + r * t.cos(), r * t.sin())
                    }).collect(),
                    closed: false,
                    fill: Color32::TRANSPARENT,
                    stroke: thin.into(),
                }));
            }
            painter.circle_filled(at(-6.5, 0.0), 1.8, col);
        }
        ToolIcon::Bars => {
            for (dx, h) in [(-5.5_f32, 4.0_f32), (-1.8, 7.5), (1.8, 2.5), (5.5, 6.0)] {
                line(at(dx, 7.0), at(dx, 7.0 - h * 2.0));
            }
        }
        ToolIcon::Braces => {
            for dir in [-1.0_f32, 1.0] {
                painter.add(egui::Shape::Path(egui::epaint::PathShape {
                    points: vec![
                        at(dir * 3.0, -7.0), at(dir * 6.5, -7.0), at(dir * 6.5, -2.0),
                        at(dir * 8.5, 0.0), at(dir * 6.5, 2.0), at(dir * 6.5, 7.0),
                        at(dir * 3.0, 7.0),
                    ],
                    closed: false,
                    fill: Color32::TRANSPARENT,
                    stroke: thin.into(),
                }));
            }
        }
        ToolIcon::Columns => {
            box_of(at(-8.0, -6.5), at(-1.0, 6.5), s);
            box_of(at(1.0, -6.5), at(8.0, 6.5), s);
            line(at(-6.0, -3.0), at(-3.0, -3.0));
            line(at(3.0, 1.0), at(6.0, 1.0));
        }
        ToolIcon::Lines => {
            box_of(at(-6.5, -8.0), at(6.5, 8.0), thin);
            for dy in [-4.0, 0.0, 4.0] {
                line(at(-3.5, dy), at(3.5, dy));
            }
        }
        ToolIcon::Tray => {
            line(at(-7.0, -6.5), at(-1.0, -6.5));
            box_of(at(-8.0, -3.0), at(8.0, 7.5), s);
            line(at(-8.0, 1.5), at(8.0, 1.5));
        }
        ToolIcon::Cogs => {
            painter.circle_stroke(at(-2.5, -2.0), 4.5, s);
            painter.circle_stroke(at(4.0, 4.5), 3.0, thin);
            for k in 0..6 {
                let t = std::f32::consts::TAU * k as f32 / 6.0;
                let (cs, sn) = (t.cos(), t.sin());
                painter.line_segment(
                    [at(-2.5 + 4.5 * cs, -2.0 + 4.5 * sn), at(-2.5 + 7.0 * cs, -2.0 + 7.0 * sn)],
                    thin,
                );
            }
        }
    }
}

/// The app's own mark: a diamond of the accent inside a square of the raised surface. The
/// window icon is the same shape, so the mark in the bar and the one in the task bar agree.
pub fn paint_app_mark(painter: &egui::Painter, rect: egui::Rect, p: &Palette) {
    painter.rect_filled(rect, egui::CornerRadius::same(CORNER), p.header);
    let c0 = rect.center();
    let r = rect.width() * 0.26;
    painter.add(egui::Shape::convex_polygon(
        vec![c0 - egui::vec2(0.0, r), c0 + egui::vec2(r, 0.0), c0 + egui::vec2(0.0, r), c0 - egui::vec2(r, 0.0)],
        p.accent,
        Stroke::NONE,
    ));
}

/// A magnifier, for the command bar's search affordance.
pub fn paint_search(painter: &egui::Painter, centre: egui::Pos2, rad: f32, col: Color32) {
    let s = Stroke::new(1.3_f32, col);
    painter.circle_stroke(centre - egui::vec2(rad * 0.2, rad * 0.2), rad * 0.7, s);
    painter.line_segment([centre + egui::vec2(rad * 0.25, rad * 0.25), centre + egui::vec2(rad, rad)], s);
}

/// The three dots of an overflow menu.
pub fn paint_overflow(painter: &egui::Painter, centre: egui::Pos2, col: Color32) {
    for dx in [-4.5_f32, 0.0, 4.5] {
        painter.circle_filled(centre + egui::vec2(dx, 0.0), 1.5, col);
    }
}

/// The three bars that open the rail when it has no column of its own.
pub fn paint_rail_handle(painter: &egui::Painter, centre: egui::Pos2, col: Color32) {
    let s = Stroke::new(1.4_f32, col);
    for dy in [-4.0_f32, 0.0, 4.0] {
        painter.line_segment([centre + egui::vec2(-6.0, dy), centre + egui::vec2(6.0, dy)], s);
    }
}

/// A pair of chevrons, pointing left to collapse the rail or right to open it again.
pub fn paint_chevrons(painter: &egui::Painter, centre: egui::Pos2, left: bool, col: Color32) {
    let s = Stroke::new(1.3_f32, col);
    let dir = if left { -1.0_f32 } else { 1.0 };
    for dx in [-3.0_f32, 1.5] {
        let tip = centre + egui::vec2(dx + dir * 1.5, 0.0);
        painter.line_segment([tip + egui::vec2(-dir * 3.0, -3.5), tip], s);
        painter.line_segment([tip + egui::vec2(-dir * 3.0, 3.5), tip], s);
    }
}

/// The frame the open tool is drawn in: the workspace surface, inset from the canvas on every
/// side, with one hairline around it and the shared corner.
///
/// This is what replaced a full-bleed pane meeting the chrome with no edge at all. The canvas
/// showing around it is [`Palette::deep`], so the card reads as a sheet laid on the desk.
pub fn tool_card(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.panel)
        .stroke(Stroke::new(1.0_f32, p.border_subtle))
        .corner_radius(egui::CornerRadius::same(CORNER))
        .inner_margin(egui::Margin { left: 8, right: 8, top: 6, bottom: 8 })
}

/// One row of the navigation rail: the tool's icon, its name when there is room for one, and
/// an accent bar down the left of whichever row is open.
///
/// Collapsed, the name becomes the row's tooltip and its accessibility label, so the tool is
/// still named to a screen reader and to the tests.
pub fn rail_item(
    ui: &mut Ui,
    p: &Palette,
    icon: ToolIcon,
    label: &str,
    shortcut: &str,
    selected: bool,
    collapsed: bool,
) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, RAIL_ROW_H), egui::Sense::click());
    resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, selected, label));
    // the row being read is a raised surface; one not being read lifts only under the pointer
    let body = rect.shrink2(egui::vec2(3.0, 1.0));
    if selected {
        ui.painter().rect_filled(body, egui::CornerRadius::same(CORNER), p.header);
    } else if resp.hovered() {
        ui.painter().rect_filled(body, egui::CornerRadius::same(CORNER), p.hover);
    }
    // the accent is a bar down the open row's left edge, where the old strip put an underline:
    // it is what tells one level of navigation from the other at a glance
    if selected {
        let bar = egui::Rect::from_min_max(
            egui::pos2(body.left(), body.top() + 4.0),
            egui::pos2(body.left() + 2.0, body.bottom() - 4.0),
        );
        ui.painter().rect_filled(bar, egui::CornerRadius::same(1), p.accent);
    }
    let ink = if selected { p.strong } else if resp.hovered() { p.strong } else { p.text };
    paint_tool_icon(ui.painter(), egui::pos2(body.left() + 18.0, body.center().y), icon, ink);
    if collapsed {
        return resp.on_hover_text(format!("{label}   {shortcut}"));
    }
    let galley = ui.painter().layout_no_wrap(label.to_string(), FontId::proportional(FONT_UI), ink);
    let pos = egui::pos2(body.left() + 34.0, body.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, ink);
    resp.on_hover_text(format!("{label}   {shortcut}"))
}

/// A group caption in the rail: small, dimmed and letter-spaced by the eye rather than the
/// font, because it is a divider that happens to have a name and not something to read.
pub fn rail_caption(ui: &mut Ui, p: &Palette, text: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 22.0), egui::Sense::hover());
    let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::proportional(FONT_CAPTION), p.disabled);
    ui.painter().galley(
        egui::pos2(rect.left() + 11.0, rect.bottom() - galley.size().y - 4.0),
        galley,
        p.disabled,
    );
}

/// A hairline across the rail, standing in for a caption there is no room to write.
pub fn rail_rule(ui: &mut Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 11.0), egui::Sense::hover());
    let y = rect.center().y;
    ui.painter().line_segment(
        [egui::pos2(rect.left() + 10.0, y), egui::pos2(rect.right() - 10.0, y)],
        Stroke::new(1.0_f32, p.border_subtle),
    );
}

/// The segmented bar a tool's sub-views are chosen with: one track of the recessed surface,
/// with the open view as a raised pill inside it.
///
/// This is deliberately not [`underline_tabs`]. The rail now carries the accent for choosing a
/// *tool*, so choosing a *view within* one had to look like something else or the two levels
/// would read as the same control at two sizes.
pub fn segmented(ui: &mut Ui, p: &Palette, labels: &[&str], sel: &mut u8) {
    if labels.is_empty() {
        return;
    }
    const PAD: f32 = 13.0;
    const H: f32 = 23.0;
    let widths: Vec<f32> = labels
        .iter()
        .map(|l| ui.painter().layout_no_wrap((*l).to_string(), FontId::proportional(FONT_UI), p.text).size().x + PAD * 2.0)
        .collect();
    let total: f32 = widths.iter().sum::<f32>() + 4.0;
    let (track, _) = ui.allocate_exact_size(egui::vec2(total.min(ui.available_width()), H + 4.0), egui::Sense::hover());
    ui.painter().rect_filled(track, egui::CornerRadius::same(CORNER), p.bg_input);
    ui.painter().rect_stroke(
        track,
        egui::CornerRadius::same(CORNER),
        Stroke::new(1.0_f32, p.border_subtle),
        egui::StrokeKind::Inside,
    );
    let mut x = track.left() + 2.0;
    for (i, label) in labels.iter().enumerate() {
        let is_sel = *sel as usize == i;
        let seg = egui::Rect::from_min_size(egui::pos2(x, track.top() + 2.0), egui::vec2(widths[i], H));
        x += widths[i];
        let resp = ui.interact(seg, ui.id().with(("segment", i, *label)), egui::Sense::click());
        resp.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, is_sel, *label));
        if is_sel {
            ui.painter().rect_filled(seg.shrink(1.0), egui::CornerRadius::same(CORNER), p.header);
            ui.painter().rect_stroke(
                seg.shrink(1.0),
                egui::CornerRadius::same(CORNER),
                Stroke::new(1.0_f32, p.accent),
                egui::StrokeKind::Inside,
            );
        } else if resp.hovered() {
            ui.painter().rect_filled(seg.shrink(1.0), egui::CornerRadius::same(CORNER), p.hover);
        }
        let ink = if is_sel { p.strong } else { p.text };
        let galley = ui.painter().layout_no_wrap((*label).to_string(), FontId::proportional(FONT_UI), ink);
        ui.painter().galley(
            egui::pos2(seg.center().x - galley.size().x / 2.0, seg.center().y - galley.size().y / 2.0),
            galley,
            ink,
        );
        if resp.clicked() {
            *sel = i as u8;
        }
    }
}

/// A read-only chip in the command bar -- the project, the listener -- as a dot of `colour`,
/// a label, and the raised surface behind both. Clickable, so every chip can lead somewhere.
pub fn bar_chip(ui: &mut Ui, p: &Palette, text: &str, colour: Option<Color32>) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::proportional(FONT_UI), p.text);
    let dot = if colour.is_some() { 14.0 } else { 0.0 };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(galley.size().x + 18.0 + dot, 22.0), egui::Sense::click());
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, text));
    let fill = if resp.hovered() { p.hover } else { p.header };
    ui.painter().rect_filled(rect, egui::CornerRadius::same(CORNER), fill);
    let mut x = rect.left() + 9.0;
    if let Some(c0) = colour {
        ui.painter().circle_filled(egui::pos2(x + 2.0, rect.center().y), 3.5, c0);
        x += dot;
    }
    ui.painter().galley(egui::pos2(x, rect.center().y - galley.size().y / 2.0), galley, p.text);
    resp
}
