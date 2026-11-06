//! Comparer tab: pick Item 1 and Item 2 from the captured items, then compare them by words
//! or bytes in a side-by-side window whose two panes scroll together.

use crate::comparer::{self, Change, DiffMode, Span, BYTES_PER_ROW};
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
    ui.columns(2, |cols| {
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
    egui::Window::new(bold(format!("Comparer: {title}"), 14.0).color(p.strong))
        .id(egui::Id::new("comparer_diff"))
        .open(&mut open)
        .default_size([1100.0, 620.0])
        .min_size([600.0, 300.0])
        .show(ctx, |ui| {
            let font = FontId::monospace(12.5);
            let row_h = ui.fonts(|f| f.row_height(&font));
            let offset_id = egui::Id::new("comparer_scroll_y");
            let mut jump_to: Option<f32> = None;
            // summary bar
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("A:").color(p.disabled));
                ui.label(RichText::new(format!("{} ({} bytes)", view.a.label, view.a.length)).color(p.strong));
                ui.add_space(10.0);
                ui.label(RichText::new("B:").color(p.disabled));
                ui.label(RichText::new(format!("{} ({} bytes)", view.b.label, view.b.length)).color(p.strong));
            });
            ui.horizontal(|ui| {
                for (mode, label) in [(DiffMode::Words, "Words"), (DiffMode::Bytes, "Bytes")] {
                    if ui.selectable_label(view.mode == mode, label).clicked() && view.mode != mode {
                        view.set_mode(mode);
                        jump_to = Some(0.0);
                    }
                }
                ui.add_space(12.0);
                let n = view.difference_count();
                let unit = match view.mode { DiffMode::Words if n == 1 => "difference", DiffMode::Words => "differences",
                                             DiffMode::Bytes if n == 1 => "differing byte", DiffMode::Bytes => "differing bytes" };
                ui.label(bold(format!("{n} {unit}"), 13.0).color(if n == 0 { p.st_done } else { p.strong }));
                let targets = view.jump_targets();
                ui.add_space(8.0);
                let step = |cur: Option<usize>, fwd: bool| -> usize {
                    match (cur, fwd) {
                        (None, true) => 0,
                        (None, false) => targets.len() - 1,
                        (Some(i), true) => (i + 1) % targets.len(),
                        (Some(i), false) => (i + targets.len() - 1) % targets.len(),
                    }
                };
                let any = !targets.is_empty();
                if theme::plain_button(ui, p, "Previous", any).clicked() { view.current = Some(step(view.current, false)); }
                if theme::plain_button(ui, p, "Next", any).clicked() { view.current = Some(step(view.current, true)); }
                if let Some(i) = view.current.filter(|&i| i < targets.len()) {
                    ui.label(RichText::new(format!("{} of {}", i + 1, targets.len())).color(p.text));
                }
                if let Some(note) = &view.fallback_note {
                    ui.add_space(8.0);
                    ui.label(RichText::new(note).size(12.0).color(p.medium));
                }
                // scroll once per jump, to a few rows above the difference (whichever side
                // has it higher up, so it's in view on both)
                let jumped_id = egui::Id::new("comparer_jumped");
                let key = view.current.map(|i| (view.mode == DiffMode::Bytes, i));
                if key != ui.ctx().data(|d| d.get_temp::<Option<(bool, usize)>>(jumped_id)).flatten() {
                    if let Some((_, i)) = key.filter(|k| k.1 < targets.len()) {
                        let row = targets[i].0.min(targets[i].1);
                        jump_to = Some(((row as f32 - 3.0) * row_h).max(0.0));
                    }
                    ui.ctx().data_mut(|d| d.insert_temp(jumped_id, key));
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
            let mut offsets = [shared, shared];
            match view.mode {
                DiffMode::Words => match view.words.as_ref() {
                    Some(Ok(w)) => {
                        let (a, b) = (&w.a, &w.b);
                        ui.columns(2, |cols| {
                            offsets[0] = word_pane(&mut cols[0], p, "cmp_pane_a", "Item A", a, shared, &font, colors, on_color);
                            offsets[1] = word_pane(&mut cols[1], p, "cmp_pane_b", "Item B", b, shared, &font, colors, on_color);
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
                    ui.columns(2, |cols| {
                        offsets[0] = byte_pane(&mut cols[0], p, "cmp_bytes_a", "Item A", &view.a.data, &bd.a, rows, shared, &font, row_h, colors, on_color);
                        offsets[1] = byte_pane(&mut cols[1], p, "cmp_bytes_b", "Item B", &view.b.data, &bd.b, rows, shared, &font, row_h, colors, on_color);
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

/// Line numbers and the highlighted text of one side; returns its scroll offset.
#[allow(clippy::too_many_arguments)]
fn word_pane(ui: &mut Ui, p: &Palette, id: &str, title: &str, spans: &[Span], offset: f32, font: &FontId, colors: [Color32; 3], on_color: Color32) -> f32 {
    ui.label(bold(title, 12.5).color(p.strong));
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    for s in spans {
        let changed = s.change != Change::Same;
        job.append(&s.text, 0.0, egui::TextFormat {
            font_id: font.clone(),
            color: if changed { on_color } else { p.text },
            background: background(s.change, colors),
            ..Default::default()
        });
    }
    let lines = spans.iter().map(|s| s.text.matches('\n').count()).sum::<usize>() + 1;
    let numbers: String = (1..=lines).map(|n| format!("{n:>4}\n")).collect();
    let out = egui::Frame::new().fill(p.deep).stroke(egui::Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).vertical_scroll_offset(offset).show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.add(egui::Label::new(RichText::new(numbers.trim_end()).font(font.clone()).color(p.ed_line_numbers)).selectable(false));
                ui.add(egui::Label::new(job).extend());
            });
        })
    });
    out.inner.state.offset.y
}

/// Hex dump rows of one side, the differing bytes highlighted; returns its scroll offset.
#[allow(clippy::too_many_arguments)]
fn byte_pane(ui: &mut Ui, p: &Palette, id: &str, title: &str, data: &[u8], changes: &[Change], rows: usize, offset: f32,
             font: &FontId, row_h: f32, colors: [Color32; 3], on_color: Color32) -> f32 {
    ui.label(bold(title, 12.5).color(p.strong));
    let out = egui::Frame::new().fill(p.deep).stroke(egui::Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).vertical_scroll_offset(offset).show_rows(ui, row_h, rows, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for row in range {
                ui.add(egui::Label::new(byte_row_job(p, data, changes, row, font, colors, on_color)).extend());
            }
        })
    });
    out.inner.state.offset.y
}

/// "00000010: 48 65 ... |He...|" with each differing byte highlighted in hex and ASCII.
fn byte_row_job(p: &Palette, data: &[u8], changes: &[Change], row: usize, font: &FontId, colors: [Color32; 3], on_color: Color32) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    let plain = |col: Color32| egui::TextFormat { font_id: font.clone(), color: col, ..Default::default() };
    let marked = |ch: Change| {
        let changed = ch != Change::Same;
        egui::TextFormat { font_id: font.clone(), color: if changed { on_color } else { p.text }, background: background(ch, colors), ..Default::default() }
    };
    let start = row * BYTES_PER_ROW;
    job.append(&format!("{start:08x}: "), 0.0, plain(p.ed_line_numbers));
    for i in 0..BYTES_PER_ROW {
        match data.get(start + i) {
            Some(b) => job.append(&format!("{b:02x}"), 0.0, marked(changes.get(start + i).copied().unwrap_or(Change::Same))),
            None => job.append("  ", 0.0, plain(p.text)),
        }
        job.append(" ", 0.0, plain(p.text));
    }
    job.append(" |", 0.0, plain(p.disabled));
    for i in 0..BYTES_PER_ROW {
        match data.get(start + i) {
            Some(&b) => {
                let ch = if (0x20..0x7f).contains(&b) { (b as char).to_string() } else { ".".to_string() };
                job.append(&ch, 0.0, marked(changes.get(start + i).copied().unwrap_or(Change::Same)));
            }
            None => job.append(" ", 0.0, plain(p.text)),
        }
    }
    job.append("|", 0.0, plain(p.disabled));
    job
}
