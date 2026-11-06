//! HTTP message editor: line numbers, the theme's message colours (first line, header
//! name/value, parameter name/value) and § payload positions drawn as lozenges.

use crate::theme::Palette;
use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId, Ui};

/// The editor's selected text, if any (the selection survives losing focus, so this still
/// works while its right-click menu is open).
pub fn selected_text(out: &egui::text_edit::TextEditOutput, text: &str) -> Option<String> {
    let range = out.state.cursor.char_range()?;
    let [a, b] = range.sorted();
    let (a, b) = (a.index, b.index);
    (a != b).then(|| text.chars().skip(a).take(b - a).collect())
}

/// egui collapses a text selection on any pointer press over the editor, the right button
/// included, so right-clicking selected text would lose it. Remember the selection each
/// frame and put it back in the frame a right-click lands.
fn keep_selection_on_right_click(out: &egui::text_edit::TextEditOutput) {
    let ctx = &out.response.ctx;
    let key = out.response.id.with("selection_before_right_click");
    let right_press = out.response.hovered() && ctx.input(|i| i.pointer.button_pressed(egui::PointerButton::Secondary));
    if right_press {
        if let Some(previous) = ctx.data(|d| d.get_temp::<egui::text::CCursorRange>(key)) {
            let mut state = out.state.clone();
            state.cursor.set_char_range(Some(previous));
            state.store(ctx, out.response.id);
        }
    } else if let Some(range) = out.state.cursor.char_range() {
        ctx.data_mut(|d| d.insert_temp(key, range));
    }
}

/// Where a message editor's right-click menu sends text.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SendText { Decoder, Comparer }

/// What was picked in a message editor's right-click menu: the destination, the text, and
/// whether it was a selection (rather than the whole message).
pub struct MenuPick {
    pub to: SendText,
    pub text: String,
    pub selection: bool,
}

impl MenuPick {
    /// Comparer item label: "Repeater response" or "Repeater response selection (142 bytes)".
    pub fn label(&self, what: &str) -> String {
        if self.selection { format!("{what} selection ({} bytes)", self.text.len()) } else { what.to_string() }
    }
}

/// Right-click menu on a message editor: send the selection (or the whole message when
/// nothing is selected) to the Decoder or the Comparer, or copy the selection.
pub fn message_menu(out: &egui::text_edit::TextEditOutput, text: &str) -> Option<MenuPick> {
    menu_for(out, text, text, "message")
}

/// The menu for a view showing `shown` (Pretty or Hex text) of the message `raw`: a
/// selection is taken from what's shown; "the message" is always the original.
/// `noun` names the whole message in the menu ("message", "response").
fn menu_for(out: &egui::text_edit::TextEditOutput, shown: &str, raw: &str, noun: &str) -> Option<MenuPick> {
    keep_selection_on_right_click(out);
    let selection = selected_text(out, shown);
    // only the pane being worked in feeds the Auto-Decoder: a selection left behind in a
    // pane that has lost focus mustn't keep replacing what was picked since
    if let Some(sel) = selection.as_ref().filter(|_| out.response.has_focus()) {
        offer_to_decoder(&out.response.ctx, "Selection", sel);
    }
    let mut pick = None;
    out.response.context_menu(|ui| {
        let what = if selection.is_some() { "selection" } else { noun };
        for (to, name) in [(SendText::Decoder, "Decoder"), (SendText::Comparer, "Comparer")] {
            if ui.button(format!("Send {what} to {name}")).clicked() {
                pick = Some(MenuPick { to, text: selection.clone().unwrap_or_else(|| raw.to_string()), selection: selection.is_some() });
                ui.close_menu();
            }
        }
        if let Some(sel) = &selection {
            if ui.button("Copy selection").clicked() {
                ui.ctx().copy_text(sel.clone());
                ui.close_menu();
            }
        }
        if ui.button(format!("Copy whole {noun}")).on_hover_text("Exactly as received, whatever the view").clicked() {
            ui.ctx().copy_text(raw.to_string());
            ui.close_menu();
        }
    });
    pick
}

/// What the Inspector's Auto-Decoder looks at: the last Inspector row clicked or text
/// selected in a message (`source` says which).
#[derive(Clone, Debug, PartialEq)]
pub struct DecodePick {
    pub source: String,
    pub text: String,
}

fn decode_pick_id() -> egui::Id {
    egui::Id::new("auto_decoder_pick")
}

/// Give the Auto-Decoder something to decode (large text is cut to its first 64 KiB).
pub fn offer_to_decoder(ctx: &egui::Context, source: &str, text: &str) {
    let text = capped(text, crate::autodecode::MAX_INPUT);
    let same = ctx.data(|d| d.get_temp::<DecodePick>(decode_pick_id())).is_some_and(|p| p.text == text);
    if !same {
        ctx.data_mut(|d| d.insert_temp(decode_pick_id(), DecodePick { source: source.to_string(), text: text.to_string() }));
        // the Inspector was drawn before this pane: show the new input straight away
        ctx.request_repaint();
    }
}

/// Clear the Auto-Decoder's input when what's on screen changes. `slot` is what's being
/// tracked ("view": the tab and sub-tab; "message": the message the Inspector shows) and
/// `key` its current value; a change from the last frame's value clears the input. Text
/// still selected in the focused pane comes straight back (see `menu_for`), so an active
/// highlight survives.
pub fn decoder_context(ctx: &egui::Context, slot: &'static str, key: String) {
    let id = egui::Id::new("auto_decoder_context").with(slot);
    let changed = ctx.data(|d| d.get_temp::<String>(id)).is_none_or(|old| old != key);
    if changed {
        ctx.data_mut(|d| d.insert_temp(id, key));
        clear_decoder_pick(ctx);
    }
}

/// The Auto-Decoder's current input, if any.
pub fn decoder_pick(ctx: &egui::Context) -> Option<DecodePick> {
    ctx.data(|d| d.get_temp(decode_pick_id()))
}

/// The last key `decoder_context` saw for `slot`.
#[cfg(test)]
pub fn decoder_context_key(ctx: &egui::Context, slot: &'static str) -> Option<String> {
    ctx.data(|d| d.get_temp(egui::Id::new("auto_decoder_context").with(slot)))
}

pub fn clear_decoder_pick(ctx: &egui::Context) {
    ctx.data_mut(|d| d.remove::<DecodePick>(decode_pick_id()));
}

/// Default size of the monospace HTTP message editors.
pub const DEFAULT_FONT: f32 = 12.5;

/// Editor font size for this frame (Settings > Display > Editor font size).
pub fn set_font_size(ctx: &egui::Context, size: f32) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new("editor_font_size"), size));
}

fn font_size(ctx: &egui::Context) -> f32 {
    ctx.data(|d| d.get_temp(egui::Id::new("editor_font_size"))).unwrap_or(DEFAULT_FONT)
}

fn fmt(color: Color32) -> TextFormat {
    TextFormat { font_id: FontId::monospace(DEFAULT_FONT), color, ..Default::default() }
}

/// Colour one message. `positions` = draw §…§ segments as lozenges.
pub fn highlight(p: &Palette, text: &str, positions: bool) -> LayoutJob {
    let mut job = LayoutJob::default();
    let mut in_body = false;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let bare = line.trim_end_matches(['\n', '\r']);
        let nl = &line[bare.len()..];
        if i == 0 {
            push_params(&mut job, p, bare, p.ed_first_line, positions);
        } else if !in_body && bare.is_empty() {
            in_body = true;
        } else if !in_body {
            match bare.split_once(':') {
                Some((name, value)) => {
                    job.append(name, 0.0, fmt(p.ed_header_name));
                    job.append(":", 0.0, fmt(p.ed_header_name));
                    let cookie = name.eq_ignore_ascii_case("cookie");
                    if cookie {
                        push_params(&mut job, p, value, p.ed_header_value, positions);
                    } else {
                        push_marked(&mut job, p, value, p.ed_header_value, positions);
                    }
                }
                None => push_marked(&mut job, p, bare, p.ed_text, positions),
            }
        } else {
            push_params(&mut job, p, bare, p.ed_text, positions);
        }
        if !nl.is_empty() {
            job.append(nl, 0.0, fmt(p.ed_text));
        }
    }
    if text.is_empty() {
        job.append("", 0.0, fmt(p.ed_text));
    }
    job
}

/// Colour `name=value` pairs (query string, cookie, body); other text in `base`.
fn push_params(job: &mut LayoutJob, p: &Palette, s: &str, base: Color32, positions: bool) {
    // split into segments at separators; a segment "name=value" gets name/value colours
    let mut seg_text = String::new();
    let emit = |job: &mut LayoutJob, seg_text: &str| {
        match seg_text.split_once('=') {
            Some((n, v)) if !n.is_empty() && !n.contains('/') => {
                push_marked(job, p, n, p.ed_param_name, positions);
                push_marked(job, p, "=", base, positions);
                push_marked(job, p, v, p.ed_param_value, positions);
            }
            _ => push_marked(job, p, seg_text, base, positions),
        }
    };
    for ch in s.chars() {
        if matches!(ch, '?' | '&' | ';' | ' ') {
            emit(job, &seg_text);
            seg_text.clear();
            push_marked(job, p, &ch.to_string(), base, positions);
        } else {
            seg_text.push(ch);
        }
    }
    emit(job, &seg_text);
}

/// Append text; §…§ ranges get the lozenge background when `positions` is on.
fn push_marked(job: &mut LayoutJob, p: &Palette, s: &str, col: Color32, positions: bool) {
    if !positions || !s.contains('§') {
        job.append(s, 0.0, fmt(col));
        return;
    }
    let mut inside = job_inside(job);
    let mut buf = String::new();
    for ch in s.chars() {
        if ch == '§' {
            if !buf.is_empty() {
                job.append(&buf, 0.0, seg(p, col, inside));
                buf.clear();
            }
            job.append("§", 0.0, TextFormat { background: p.ed_lozenge, ..fmt(p.accent) });
            inside = !inside;
        } else {
            buf.push(ch);
        }
    }
    if !buf.is_empty() {
        job.append(&buf, 0.0, seg(p, col, inside));
    }
}

fn job_inside(job: &LayoutJob) -> bool {
    job.text.matches('§').count() % 2 == 1
}

fn seg(p: &Palette, col: Color32, inside: bool) -> TextFormat {
    if inside {
        TextFormat { background: p.ed_lozenge, ..fmt(p.ed_param_value) }
    } else {
        fmt(col)
    }
}

/// Messages longer than this are shown cut to their first `DISPLAY_LIMIT` bytes (read-only)
/// until "Show full message" is pressed: laying out multi-megabyte text every frame would
/// freeze the window.
pub const DISPLAY_LIMIT: usize = 256 * 1024;

/// The start of `s`, at most `limit` bytes, ending on a character boundary.
pub fn capped(s: &str, limit: usize) -> &str {
    if s.len() <= limit {
        return s;
    }
    let mut end = limit;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// "12.3 MiB", "512 KiB", "900 bytes".
pub fn human_size(n: usize) -> String {
    match n {
        n if n >= 1 << 20 => format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{} KiB", n >> 10),
        n => format!("{n} bytes"),
    }
}

enum Buffer<'a> {
    Edit(&'a mut String),
    View(&'a str),
}

/// Editable (or read-only) message with a line-number gutter. Returns the TextEdit output.
/// A message over `DISPLAY_LIMIT` is shown cut short and read-only, with a note and a
/// button to show (and edit) all of it.
pub fn message_editor(
    ui: &mut Ui,
    p: &Palette,
    id: &str,
    text: &mut String,
    editable: bool,
    positions: bool,
    min_height: f32,
) -> egui::text_edit::TextEditOutput {
    let buf = if editable { Buffer::Edit(text) } else { Buffer::View(text.as_str()) };
    show_message(ui, p, id, buf, positions, min_height)
}

pub use crate::viewer::MessageViewMode;

/// A read-only message view as drawn: the TextEdit output and the text it showed (the
/// Pretty or Hex rendering; None in Raw, where it's the message itself).
pub struct MessageView {
    pub out: egui::text_edit::TextEditOutput,
    shown: Option<String>,
}

impl MessageView {
    /// The right-click menu (see `message_menu`): selections come from what's shown, the
    /// whole message is always `raw`, the original.
    pub fn menu(&self, raw: &str) -> Option<MenuPick> {
        self.menu_named(raw, "message")
    }

    /// `menu`, with the whole message called `noun` ("Send response to Comparer").
    pub fn menu_named(&self, raw: &str, noun: &str) -> Option<MenuPick> {
        menu_for(&self.out, self.shown.as_deref().unwrap_or(raw), raw, noun)
    }
}

/// The view mode of the message view `id` (kept for the session, per view).
pub fn view_mode(ctx: &egui::Context, id: &str) -> MessageViewMode {
    ctx.data(|d| d.get_temp(egui::Id::new(id).with("view_mode"))).unwrap_or_default()
}

pub fn set_view_mode(ctx: &egui::Context, id: &str, mode: MessageViewMode) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new(id).with("view_mode"), mode));
}

/// The [ Raw | Pretty | Hex ] switch.
fn mode_switch(ui: &mut Ui, p: &Palette, id: &str) -> MessageViewMode {
    let mut mode = view_mode(ui.ctx(), id);
    ui.horizontal(|ui| {
        egui::Frame::new().stroke(egui::Stroke::new(1.0_f32, p.ed_gutter)).corner_radius(4.0).inner_margin(egui::Margin::same(1)).show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for m in MessageViewMode::ALL {
                let tip = match m {
                    MessageViewMode::Raw => "The message as received",
                    MessageViewMode::Pretty => "JSON re-indented and coloured; XML and HTML tags indented",
                    MessageViewMode::Hex => "Every byte, 16 per row, with an ASCII column",
                };
                if ui.add(egui::Button::new(egui::RichText::new(m.label()).size(11.5)).selected(mode == m).min_size(egui::vec2(48.0, 18.0))).on_hover_text(tip).clicked() {
                    mode = m;
                }
            }
        });
    });
    set_view_mode(ui.ctx(), id, mode);
    mode
}

#[derive(Default)]
struct PrettyComputer;

impl egui::cache::ComputerMut<(&str,), (String, crate::viewer::BodyKind)> for PrettyComputer {
    fn compute(&mut self, (s,): (&str,)) -> (String, crate::viewer::BodyKind) {
        crate::viewer::pretty_message(s)
    }
}

/// Pretty renderings, computed once per message rather than every frame.
type PrettyCache = egui::cache::FrameCache<(String, crate::viewer::BodyKind), PrettyComputer>;

/// "Large message" note with its "Show full message" button; true when the whole message
/// should be shown (it's under `limit`, or the button was pressed for this message).
fn large_note(ui: &mut Ui, p: &Palette, id: &str, full_len: usize, limit: usize) -> bool {
    // "show full" lasts for this message (by its length), so the next big one is cut again
    let full_key = egui::Id::new(id).with("show_full");
    if full_len <= limit || ui.ctx().data(|d| d.get_temp::<usize>(full_key)) == Some(full_len) {
        return true;
    }
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("Large message: showing the first {} of {} (read-only).", human_size(limit), human_size(full_len))).size(12.0).color(p.text));
        if ui.small_button("Show full message").on_hover_text("Lay out the whole message; this can make the window slow").clicked() {
            ui.ctx().data_mut(|d| d.insert_temp(full_key, full_len));
        }
    });
    false
}

/// Read-only message view of borrowed text (no copy is made to show it in Raw), with the
/// [ Raw | Pretty | Hex ] switch above it. Only the display changes: copying, sending and
/// forwarding always use `text` itself.
pub fn message_view(ui: &mut Ui, p: &Palette, id: &str, text: &str, min_height: f32) -> MessageView {
    let before = ui.cursor().top();
    let mode = mode_switch(ui, p, id);
    let min_height = (min_height - (ui.cursor().top() - before)).max(40.0);
    // each mode has its own text widget state (cursor positions don't carry over)
    let wid = format!("{id}:{}", mode.label());
    match mode {
        MessageViewMode::Raw => MessageView { out: show_message(ui, p, &wid, Buffer::View(text), false, min_height), shown: None },
        MessageViewMode::Pretty => {
            let full = large_note(ui, p, &wid, text.len(), DISPLAY_LIMIT);
            let src = if full { text } else { capped(text, DISPLAY_LIMIT) };
            let (pretty, kind) = ui.ctx().memory_mut(|m| m.caches.cache::<PrettyCache>().get((src,)));
            let out = show_text(ui, p, &wid, Buffer::View(&pretty), Style::Pretty(kind), min_height);
            MessageView { out, shown: Some(pretty) }
        }
        MessageViewMode::Hex => {
            let full = large_note(ui, p, &wid, text.len(), crate::viewer::HEX_LIMIT);
            let bytes = text.as_bytes();
            let src = if full { bytes } else { &bytes[..crate::viewer::HEX_LIMIT.min(bytes.len())] };
            let dump = crate::viewer::hex_dump(src);
            let out = show_text(ui, p, &wid, Buffer::View(&dump), Style::Hex, min_height);
            MessageView { out, shown: Some(dump) }
        }
    }
}

fn show_message(ui: &mut Ui, p: &Palette, id: &str, buf: Buffer, positions: bool, min_height: f32) -> egui::text_edit::TextEditOutput {
    let full_len = match &buf { Buffer::Edit(t) => t.len(), Buffer::View(t) => t.len() };
    let buf = if large_note(ui, p, id, full_len, DISPLAY_LIMIT) {
        buf
    } else {
        // only the start is laid out, read-only; the text itself is untouched
        let all: &str = match buf { Buffer::Edit(t) => t.as_str(), Buffer::View(t) => t };
        Buffer::View(capped(all, DISPLAY_LIMIT))
    };
    show_text(ui, p, id, buf, Style::Http { positions }, min_height)
}

/// How `show_text` colours its text.
#[derive(Clone, Copy)]
enum Style {
    Http { positions: bool },
    Pretty(crate::viewer::BodyKind),
    Hex,
}

fn show_text(ui: &mut Ui, p: &Palette, id: &str, buf: Buffer, style: Style, min_height: f32) -> egui::text_edit::TextEditOutput {
    let pal = *p;
    let size = font_size(ui.ctx());
    let mut layouter = move |ui: &Ui, s: &str, wrap: f32| {
        let mut job = match style {
            Style::Http { positions } => highlight(&pal, s, positions),
            Style::Pretty(kind) => crate::viewer::pretty_job(&pal, s, kind, size),
            Style::Hex => crate::viewer::hex_job(&pal, s, size),
        };
        for section in &mut job.sections {
            section.format.font_id.size = size;
        }
        // hex rows never wrap (the columns would fall apart)
        job.wrap.max_width = if matches!(style, Style::Hex) { f32::INFINITY } else { wrap };
        ui.fonts(|f| f.layout_job(job))
    };
    let gutter = !matches!(style, Style::Hex); // the offsets are the hex view's line numbers
    // a hex row is 78 characters wide: room for exactly that, scrolling sideways if narrower
    let hex_width = if gutter { f32::INFINITY } else { ui.fonts(|f| f.glyph_width(&FontId::monospace(size), '0')) * 80.0 };
    let text_now: &str = match &buf { Buffer::Edit(t) => t.as_str(), Buffer::View(t) => t };
    let lines = text_now.lines().count().max(1) + usize::from(text_now.ends_with('\n'));
    let mut out = None;
    let mut buf = buf;
    egui::Frame::new().fill(p.deep).show(ui, |ui| {
        ui.set_min_height(min_height);
        let scroll = if gutter { egui::ScrollArea::vertical() } else { egui::ScrollArea::both() };
        scroll.id_salt(id).show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if gutter {
                    let nums: String = (1..=lines).map(|n| format!("{n}\n")).collect();
                    ui.add(egui::Label::new(egui::RichText::new(nums.trim_end()).font(FontId::monospace(size)).color(p.ed_line_numbers)).selectable(false));
                    let (r, _) = ui.allocate_exact_size(egui::vec2(1.0, (lines as f32) * 16.0 * size / DEFAULT_FONT), egui::Sense::hover());
                    ui.painter().rect_filled(r, 0.0, p.ed_gutter);
                }
                let rows = ((min_height / 16.0) as usize).max(3);
                // read-only views use a &str buffer: selectable and copyable, not editable
                let te = match &mut buf {
                    Buffer::Edit(t) => egui::TextEdit::multiline(*t),
                    Buffer::View(t) => egui::TextEdit::multiline(t),
                };
                out = Some(te
                    .id_salt(id)
                    .frame(false)
                    .desired_width(hex_width)
                    .desired_rows(rows)
                    .font(FontId::monospace(size))
                    .layouter(&mut layouter)
                    .show(ui));
            });
        });
    });
    out.unwrap()
}

#[cfg(test)]
mod tests {
    #[test]
    fn display_cap_cuts_on_a_char_boundary() {
        assert_eq!(super::capped("short", 10), "short");
        assert_eq!(super::capped("abcdef", 3), "abc");
        // "é" is two bytes: a cut in its middle steps back before it
        assert_eq!(super::capped("aé", 2), "a");
        let big = "x".repeat(super::DISPLAY_LIMIT + 100);
        assert_eq!(super::capped(&big, super::DISPLAY_LIMIT).len(), super::DISPLAY_LIMIT);
        assert_eq!(super::human_size(900), "900 bytes");
        assert_eq!(super::human_size(256 * 1024), "256 KiB");
        assert_eq!(super::human_size(12 * 1024 * 1024 + 300 * 1024), "12.3 MiB");
    }
}
