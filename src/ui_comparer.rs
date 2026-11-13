//! Comparer tab: pick Item 1 and Item 2 from the captured items, then compare them by words
//! or bytes in a side-by-side window whose two panes scroll together.

use crate::comparer::{self, Change, DiffMode, Row, BYTES_PER_ROW};
use crate::state::App;
use crate::theme::{self, bold, Look, Palette};
use crate::ui_core::c;
use eframe::egui;
use egui::{Color32, FontId, RichText, Ui};

/// Highlight backgrounds: (inserted, deleted, modified), and the text colour drawn on them.
fn diff_colors(look: Look) -> ([Color32; 3], Color32) {
    match look {
        // green/cyan, red/orange, yellow/amber
        Look::Dark => ([c(0x1F7A63), c(0x9A3B2A), c(0x8C6B12)], Color32::WHITE),
        Look::Light => ([c(0xA6E8D0), c(0xF6B7A4), c(0xF5DA82)], Color32::BLACK),
    }
}

fn background(change: Change, colors: [Color32; 3]) -> Color32 {
    match change {
        Change::Same => Color32::TRANSPARENT,
        Change::Inserted => colors[0],
        Change::Deleted => colors[1],
        Change::Modified => colors[2],
    }
}

pub fn comparer(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.add_space(6.0);
    theme::section_title(ui, p, "Comparer", "Compare two items word by word or byte by byte. Send requests, responses or selections here from Proxy history, Repeater or Intruder (right-click), or add text below.");
    ui.add_space(6.0);
    let list_h = (ui.available_height() * 0.5).clamp(140.0, 360.0);
    theme::columns(ui, 2, |cols| {
        item_list(app, &mut cols[0], p, false, list_h);
        item_list(app, &mut cols[1], p, true, list_h);
    });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let ready = matches!((app.comparer_sel_a, app.comparer_sel_b), (Some(a), Some(b)) if a != b);
        let why = "Select two different items, one in each list";
        if ui.add_enabled(ready, egui::Button::new(bold("Compare words", 13.0).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(130.0, 26.0)))
            .on_disabled_hover_text(why).clicked() {
            comparer::compare_selected(app, DiffMode::Words);
        }
        if ui.add_enabled(ready, egui::Button::new(bold("Compare bytes", 13.0).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(130.0, 26.0)))
            .on_disabled_hover_text(why).clicked() {
            comparer::compare_selected(app, DiffMode::Bytes);
        }
        ui.add_space(16.0);
        let can_remove = app.comparer_sel_a.is_some() || app.comparer_sel_b.is_some();
        if theme::plain_button(ui, p, "Remove", can_remove).on_hover_text("Remove the selected item").clicked() {
            comparer::remove_selected(app);
        }
        if theme::plain_button(ui, p, "Clear", !app.comparer_items.is_empty()).clicked() {
            app.comparer_items.clear();
            app.comparer_sel_a = None;
            app.comparer_sel_b = None;
            app.comparer_active_pane = 0;
        }
    });
    ui.add_space(10.0);
    ui.label(bold("Add an item", 13.0).color(p.strong));
    egui::Frame::new().fill(p.deep).stroke(egui::Stroke::new(1.0_f32, p.header)).inner_margin(egui::Margin::same(6)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::vertical().id_salt("cmp_paste").max_height(110.0).show(ui, |ui| {
            ui.add(egui::TextEdit::multiline(&mut app.comparer_paste).font(FontId::monospace(12.5)).frame(false)
                .desired_width(f32::INFINITY).desired_rows(4).hint_text("Paste or type text to compare"));
        });
    });
    ui.horizontal(|ui| {
        if theme::plain_button(ui, p, "Add", !app.comparer_paste.is_empty()).clicked() {
            let text = std::mem::take(&mut app.comparer_paste);
            let label = format!("Manual item ({} bytes)", text.len());
            comparer::add_text(app, label, &text);
        }
    });
}

/// One of the two item lists (Item 1 on the left, Item 2 on the right).
fn item_list(app: &mut App, ui: &mut Ui, p: &Palette, second: bool, h: f32) {
    ui.label(bold(if second { "Item 2" } else { "Item 1" }, 13.0).color(p.strong));
    const COLS: [(f32, f32); 3] = [(40.0, 0.0), (160.0, 1.0), (70.0, 0.0)];
    theme::fitted_table(ui, p, ("cmp_items", second), h, &COLS, |ui, w| {
        theme::table_header(ui, p, &[("#", w[0]), ("Label", w[1]), ("Length", w[2])]);
        egui::ScrollArea::vertical().id_salt(("cmp_rows", second)).auto_shrink([false, true]).show(ui, |ui| {
            if app.comparer_items.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("  No items yet.").size(12.0).color(p.disabled));
            }
            for i in 0..app.comparer_items.len() {
                let it = &app.comparer_items[i];
                let sel = if second { app.comparer_sel_b } else { app.comparer_sel_a } == Some(i);
                let kind = if it.is_text { "" } else { "  (binary)" };
                let cells = [(it.id.to_string(), w[0], None), (format!("{}{kind}", it.label), w[1], None), (it.length.to_string(), w[2], None)];
                let row = theme::table_row(ui, p, &cells, sel, i % 2 == 1);
                if row.clicked() {
                    if second {
                        app.comparer_sel_b = Some(i);
                        app.comparer_active_pane = 1;
                    } else {
                        app.comparer_sel_a = Some(i);
                        app.comparer_active_pane = 0;
                    }
                }
                if row.double_clicked() {
                    comparer::compare_selected(app, DiffMode::Words);
                }
            }
        });
    });
}

/// One fixed height for every row the window draws. The panes use the Monospace text style,
/// so measuring that style measures the font actually on screen; it is then rounded to whole
/// pixels because that is what the text layout does to each row, and scrolling by the
/// unrounded height would drift a fraction of a pixel a row and miss by whole lines far down.
fn row_height(ui: &Ui) -> f32 {
    use egui::emath::GuiRounding as _;
    ui.text_style_height(&egui::TextStyle::Monospace).round_to_pixels(ui.pixels_per_point())
}

/// The height of the "Item A" / "Item B" bar above each pane. Both are allocated exactly this
/// tall, so the two panes' boxes start at the same y and their rows stay on the same planes.
const PANE_TITLE_H: f32 = 22.0;

/// What both panes draw with: the font, its row height, and the three highlight colours.
struct PaneStyle<'a> {
    font: &'a FontId,
    /// One fixed height for every row drawn, filler rows included.
    row_h: f32,
    colors: [Color32; 3],
    on_color: Color32,
}

/// An item's label with its size, unless the label already ends with it: a manual item is
/// named "Manual item (142 bytes)" when it is created, and saying so twice reads as a bug.
fn labelled(label: &str, length: usize) -> String {
    let size = format!("({length} bytes)");
    if label.trim_end().ends_with(&size) {
        label.to_string()
    } else {
        format!("{label} {size}")
    }
}

/// The comparison window: summary bar, mode switch, difference navigation and the two panes.
pub fn diff_window(app: &mut App, ctx: &egui::Context, p: &Palette) {
    let theme = app.eff().theme;
    let Some(view) = app.comparer_active_diff.as_mut() else { return };
    // a word comparison runs in the background: keep repainting until it lands
    if view.poll() {
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
    }
    let (colors, on_color) = diff_colors(theme);
    let mut open = true;
    let title = match view.mode { DiffMode::Words => "Word comparison", DiffMode::Bytes => "Byte comparison" };
    theme::show_resizable_window(ctx, egui::Id::new("comparer_diff"), bold(format!("Comparer: {title}"), 14.0).color(p.strong), &mut open, |ui| {
            // one row height for the whole window: every row -- content, modified or filler,
            // text or line number, in either pane -- is exactly this tall
            let font = egui::TextStyle::Monospace.resolve(ui.style());
            let row_h = row_height(ui);
            let st = PaneStyle { font: &font, row_h, colors, on_color };
            let offset_id = egui::Id::new("comparer_scroll_y");
            let mut jump_to: Option<f32> = None;
            // the line to put in the middle of both panes, resolved to an offset below, once
            // the height left for them is known
            let mut centre_on: Option<f32> = None;
            // summary bar
            // truncating labels: an item with a long name shortens instead of holding the
            // window open at the width of its own name
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("A:").color(p.disabled));
                ui.add(egui::Label::new(RichText::new(labelled(&view.a.label, view.a.length)).color(p.strong)).truncate());
                ui.add_space(10.0);
                ui.label(RichText::new("B:").color(p.disabled));
                ui.add(egui::Label::new(RichText::new(labelled(&view.b.label, view.b.length)).color(p.strong)).truncate());
            });
            // wrapped, so the strip folds onto a second line in a narrow window instead of
            // running under the legend on the right -- and so it can never be what decides
            // how narrow the window is allowed to get
            ui.horizontal_wrapped(|ui| {
                for (mode, label) in [(DiffMode::Words, "Words"), (DiffMode::Bytes, "Bytes")] {
                    if ui.selectable_label(view.mode == mode, label).clicked() && view.mode != mode {
                        view.set_mode(mode);
                        jump_to = Some(0.0);
                    }
                }
                ui.add_space(12.0);
                let targets = view.jump_targets();
                let any = !targets.is_empty();
                // the differences are a ring: Next from the last one comes back to the first
                let step = |cur: Option<usize>, fwd: bool| -> usize {
                    match (cur, fwd) {
                        (None, true) => 0,
                        (None, false) => targets.len() - 1,
                        (Some(i), true) => (i + 1) % targets.len(),
                        (Some(i), false) => (i + targets.len() - 1) % targets.len(),
                    }
                };
                let mut moved = None;
                if theme::plain_button(ui, p, "Previous", any).on_hover_text("Go to the previous difference (wraps round)").clicked() {
                    moved = Some(step(view.active_diff_index, false));
                }
                if theme::plain_button(ui, p, "Next", any).on_hover_text("Go to the next difference (wraps round)").clicked() {
                    moved = Some(step(view.active_diff_index, true));
                }
                if let Some(i) = moved {
                    view.active_diff_index = Some(i);
                }
                let active = view.active_diff_index.filter(|&i| i < targets.len());
                // a button press scrolls even when it lands on the difference the view was
                // already on (one difference, pressed twice), and so does the active one being
                // set from elsewhere, which is what `jumped` catches
                let jumped_id = egui::Id::new("comparer_jumped");
                let key = active.map(|i| (view.mode == DiffMode::Bytes, i));
                let settled = ui.ctx().data(|d| d.get_temp::<Option<(bool, usize)>>(jumped_id)).flatten();
                if moved.is_some() || key != settled {
                    // the lower of the two rows: a difference at the end of one item sits one
                    // line past it, and that row is in view on both sides
                    centre_on = active.map(|i| targets[i] as f32);
                    ui.ctx().data_mut(|d| d.insert_temp(jumped_id, key));
                }
                let n = view.difference_count();
                ui.add_space(8.0);
                // which difference the view is on, or how many there are when it is on none
                let counter = match (active, view.mode) {
                    (Some(i), DiffMode::Words) => format!("Difference {} of {}", i + 1, targets.len()),
                    (Some(i), DiffMode::Bytes) => format!("Row {} of {} with differences", i + 1, targets.len()),
                    (None, DiffMode::Words) => format!("{n} difference{}", if n == 1 { "" } else { "s" }),
                    (None, DiffMode::Bytes) => format!("{n} differing byte{}", if n == 1 { "" } else { "s" }),
                };
                ui.label(bold(counter, 13.0).color(if n == 0 { p.st_done } else { p.strong }));
                if let Some(note) = &view.fallback_note {
                    ui.add_space(8.0);
                    ui.label(RichText::new(note).size(12.0).color(p.medium));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    for (name, col) in [("Modified", colors[2]), ("Deleted (A only)", colors[1]), ("Added (B only)", colors[0])] {
                        ui.label(RichText::new(format!(" {name} ")).size(11.5).color(on_color).background_color(col));
                    }
                });
            });
            ui.separator();
            // the two panes share one vertical offset; whichever the user scrolled wins
            let mut shared: f32 = ui.data(|d| d.get_temp(offset_id)).unwrap_or(0.0);
            if let Some(y) = jump_to { shared = y; }
            // put the active difference in the middle of the panes rather than barely in view.
            // Their height is what is left here, less the "Item A" label above each of them.
            if let Some(row) = centre_on {
                let pane_h = (ui.available_height() - PANE_TITLE_H).max(0.0);
                shared = ((row + 0.5) * row_h - pane_h * 0.5).max(0.0);
            }
            let mut offsets = [shared, shared];
            let targets = view.jump_targets();
            let active = view.active_diff_index.filter(|&i| i < targets.len());
            match view.mode {
                DiffMode::Words => match view.words.as_ref() {
                    Some(Ok(w)) => {
                        // the two sides are padded to the same length, so one row number is
                        // the active difference's place in both panes
                        let mark = active.map(|i| targets[i]);
                        let (a, b) = (&w.a, &w.b);
                        debug_assert_eq!(a.len(), b.len(), "the panes show the same number of rows");
                        theme::columns(ui, 2, |cols| {
                            offsets[0] = word_pane(&mut cols[0], p, "cmp_pane_a", "Item A", a, &st, active, mark, shared);
                            offsets[1] = word_pane(&mut cols[1], p, "cmp_pane_b", "Item B", b, &st, active, mark, shared);
                        });
                    }
                    Some(Err(msg)) => {
                        let note = msg.clone();
                        view.fallback_note = Some(note.clone());
                        view.set_mode(DiffMode::Bytes);
                        ui.label(RichText::new(note).color(p.medium));
                    }
                    None => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new("Comparing words...").color(p.text));
                        });
                    }
                },
                DiffMode::Bytes => if let Some(bd) = view.bytes.as_ref() {
                    let rows = view.a.length.max(view.b.length).div_ceil(BYTES_PER_ROW).max(1);
                    let mark = active.map(|i| targets[i]);
                    theme::columns(ui, 2, |cols| {
                        offsets[0] = byte_pane(&mut cols[0], p, "cmp_bytes_a", "Item A", &view.a.data, &bd.a, rows, mark, &st, shared);
                        offsets[1] = byte_pane(&mut cols[1], p, "cmp_bytes_b", "Item B", &view.b.data, &bd.b, rows, mark, &st, shared);
                    });
                },
            }
            let next = if (offsets[0] - shared).abs() > 0.5 { offsets[0] } else if (offsets[1] - shared).abs() > 0.5 { offsets[1] } else { shared };
            ui.data_mut(|d| d.insert_temp(offset_id, next));
        });
    if !open {
        app.comparer_active_diff = None;
        ctx.data_mut(|d| {
            d.remove::<f32>(egui::Id::new("comparer_scroll_y"));
            d.remove::<Option<(bool, usize)>>(egui::Id::new("comparer_jumped"));
        });
    }
}

/// Line numbers and the highlighted text of one side: one row of the pane per entry of `rows`,
/// a filler row drawing blank so the line facing it in the other pane sits on the same plane.
/// `active` is the difference the view is on, underlined, and `mark` the row it starts on,
/// called out in the gutter of both panes. Returns the pane's scroll offset.
#[allow(clippy::too_many_arguments)]
fn word_pane(ui: &mut Ui, p: &Palette, id: &str, title: &str, rows: &[Row], st: &PaneStyle,
             active: Option<usize>, mark: Option<usize>, offset: f32) -> f32 {
    // no gap under the title: the pane's box then starts exactly PANE_TITLE_H down, in both
    // panes, which is what the jump arithmetic assumes when it centres a difference
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), PANE_TITLE_H), egui::Layout::left_to_right(egui::Align::Center), |ui| {
        ui.label(bold(title, 12.5).color(p.strong));
    });
    let numbers = gutter_job(rows, st, p, mark);
    let text = text_job(rows, st, p, active);
    let out = egui::Frame::new().fill(p.deep).stroke(egui::Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).vertical_scroll_offset(offset).show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.add(egui::Label::new(numbers).selectable(false));
                ui.add(egui::Label::new(text).extend());
            });
        })
    });
    out.inner.state.offset.y
}

/// One side's text, one galley row per row of the side. Nothing wraps and no span carries a
/// line terminator, so a row is always exactly one row high, which is what keeps the two panes
/// level; a row with nothing to draw -- a filler, or a blank line -- is held open by a space,
/// since a galley row with no glyphs in it is not guaranteed the font's height.
fn text_job(rows: &[Row], st: &PaneStyle, p: &Palette, active: Option<usize>) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    let plain = egui::TextFormat { font_id: st.font.clone(), color: p.text, ..Default::default() };
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            job.append("\n", 0.0, plain.clone());
        }
        let mut drawn = false;
        let mut first: Option<egui::TextFormat> = None;
        for s in &row.spans {
            let changed = s.change != Change::Same;
            // the one difference the view is on: underlined, so it is told apart from the
            // others of its own colour without changing what that colour means
            let live = s.hunk.is_some() && s.hunk == active;
            let format = egui::TextFormat {
                font_id: st.font.clone(),
                color: if changed { st.on_color } else { p.text },
                background: background(s.change, st.colors),
                underline: if live { egui::Stroke::new(2.0_f32, p.strong) } else { egui::Stroke::NONE },
                ..Default::default()
            };
            first.get_or_insert_with(|| format.clone());
            let text = comparer::shown(s);
            drawn |= !text.is_empty();
            job.append(text, 0.0, format);
        }
        if !drawn {
            // a deleted or added blank line keeps its colour here, so it is still visible
            job.append(" ", 0.0, first.unwrap_or_else(|| plain.clone()));
        }
    }
    job
}

/// The line numbers beside one side: the item's own numbering, blank against a filler row, and
/// the active difference's row called out -- the same row in both panes.
fn gutter_job(rows: &[Row], st: &PaneStyle, p: &Palette, mark: Option<usize>) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    for (i, row) in rows.iter().enumerate() {
        let here = mark == Some(i);
        let number = match row.line {
            Some(n) => format!("{:>4}", n + 1),
            None => "    ".to_string(),
        };
        let text = format!("{}{number}{}", if i == 0 { "" } else { "\n" }, if here { " >" } else { "  " });
        job.append(&text, 0.0, egui::TextFormat {
            font_id: st.font.clone(),
            color: if here { p.accent } else { p.ed_line_numbers },
            ..Default::default()
        });
    }
    job
}

/// Hex dump rows of one side, the differing bytes highlighted; `mark` is the row the active
/// difference is on. Returns the pane's scroll offset.
#[allow(clippy::too_many_arguments)]
fn byte_pane(ui: &mut Ui, p: &Palette, id: &str, title: &str, data: &[u8], changes: &[Change], rows: usize,
             mark: Option<usize>, st: &PaneStyle, offset: f32) -> f32 {
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), PANE_TITLE_H), egui::Layout::left_to_right(egui::Align::Center), |ui| {
        ui.label(bold(title, 12.5).color(p.strong));
    });
    let out = egui::Frame::new().fill(p.deep).stroke(egui::Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).vertical_scroll_offset(offset).show_rows(ui, st.row_h, rows, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for row in range {
                ui.add(egui::Label::new(byte_row_job(p, data, changes, row, mark == Some(row), st)).extend());
            }
        })
    });
    out.inner.state.offset.y
}

/// "00000010: 48 65 ... |He...|" with each differing byte highlighted in hex and ASCII, and the
/// row the view is on marked in the offset and underlined where it differs.
fn byte_row_job(p: &Palette, data: &[u8], changes: &[Change], row: usize, live: bool, st: &PaneStyle) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    let plain = |col: Color32| egui::TextFormat { font_id: st.font.clone(), color: col, ..Default::default() };
    let marked = |ch: Change| {
        let changed = ch != Change::Same;
        egui::TextFormat {
            font_id: st.font.clone(),
            color: if changed { st.on_color } else { p.text },
            background: background(ch, st.colors),
            underline: if live && changed { egui::Stroke::new(2.0_f32, p.strong) } else { egui::Stroke::NONE },
            ..Default::default()
        }
    };
    let start = row * BYTES_PER_ROW;
    let at = |i: usize| changes.get(start + i).copied().unwrap_or(Change::Same);
    job.append(&format!("{start:08x}{} ", if live { ">" } else { ":" }), 0.0, plain(if live { p.accent } else { p.ed_line_numbers }));
    for i in 0..BYTES_PER_ROW {
        match data.get(start + i) {
            Some(b) => job.append(&format!("{b:02x}"), 0.0, marked(at(i))),
            None => job.append("  ", 0.0, plain(p.text)),
        }
        job.append(" ", 0.0, plain(p.text));
    }
    job.append(" |", 0.0, plain(p.disabled));
    for i in 0..BYTES_PER_ROW {
        match data.get(start + i) {
            Some(&b) => {
                let ch = if (0x20..0x7f).contains(&b) { (b as char).to_string() } else { ".".to_string() };
                job.append(&ch, 0.0, marked(at(i)));
            }
            None => job.append(" ", 0.0, plain(p.text)),
        }
    }
    job.append("|", 0.0, plain(p.disabled));
    job
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparer::compute_patience_word_diff;
    use crate::test_utils::assert_table;

    /// Lay the panes out for real and report, for each of the four galleys (the two gutters
    /// and the two texts), how many rows it has and where each row starts.
    fn planes(a: &str, b: &str, active: Option<usize>, mark: Option<usize>) -> (f32, Vec<Vec<f32>>) {
        let d = compute_patience_word_diff(a, b).unwrap();
        let ctx = egui::Context::default();
        let (mut row_h, mut out) = (0.0, Vec::new());
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            crate::theme::apply(ctx, crate::theme::Look::Dark);
            egui::CentralPanel::default().show(ctx, |ui| {
                let font = egui::TextStyle::Monospace.resolve(ui.style());
                row_h = row_height(ui);
                let st = PaneStyle { font: &font, row_h, colors: [Color32::RED; 3], on_color: Color32::WHITE };
                let p = &crate::theme::DARK;
                let jobs = [
                    gutter_job(&d.a, &st, p, mark),
                    text_job(&d.a, &st, p, active),
                    gutter_job(&d.b, &st, p, mark),
                    text_job(&d.b, &st, p, active),
                ];
                out = jobs
                    .into_iter()
                    .map(|job| ui.fonts(|f| f.layout_job(job)).rows.iter().map(|r| r.rect.min.y).collect())
                    .collect();
            });
        });
        (row_h, out)
    }

    /// Row *i* of Item A and row *i* of Item B must start at exactly the same y, and so must
    /// each pane's line numbers: that is the whole point of the filler rows. Every row is one
    /// monospace row high -- a blank line and a filler included, which is why they are held
    /// open by a space rather than left empty.
    #[test]
    fn every_row_of_both_panes_sits_on_the_same_plane() {
        let cases: [(&str, &str, &str); 6] = [
            ("identical items", "GET / HTTP/1.1\r\nHost: a.test\r\n", "GET / HTTP/1.1\r\nHost: a.test\r\n"),
            ("a multi-line insertion in the middle", "a\nz\n", "a\nb\nc\nd\nz\n"),
            ("a multi-line deletion in the middle", "a\nb\nc\nd\nz\n", "a\nz\n"),
            (
                "a request gaining headers and a body",
                "GET /users/42 HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                "POST /orders HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/json\r\nContent-Length: 48\r\n\r\n{\"sku\":\"A-1\",\"qty\":2}",
            ),
            ("blank lines on both sides", "a\n\n\nb\n", "a\n\n\nc\n"),
            ("one item empty", "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", ""),
        ];

        assert_table!(cases, |idx, (name, a, b)| {
            let rows = compute_patience_word_diff(a, b).unwrap().a.len();
            let (row_h, galleys) = planes(a, b, Some(0), Some(1));
            assert!(row_h > 0.0, "case #{idx} ({name}) the monospace row height is known");
            // the gutter and the text of each pane, and both panes, all have the same rows
            assert_table!(&galleys, |g, tops| {
                assert_eq!(tops.len(), rows, "case #{idx} ({name}) galley {g} has one row per row of the model");
                assert_eq!(tops, &galleys[0], "case #{idx} ({name}) galley {g} is on the same planes as Item A's gutter");
            });
            // and every one of those rows is exactly one monospace row high
            assert_table!(galleys[0].windows(2).collect::<Vec<_>>(), |r, pair| {
                let step = pair[1] - pair[0];
                assert!((step - row_h).abs() < 0.01, "case #{idx} ({name}) row {r} is {step} tall, not {row_h}");
            });
        });
    }
}
