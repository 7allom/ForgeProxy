//! The Organizer: a table of saved messages to work through, the collections they are filed
//! in, and the message under the one being read.
//!
//! The table is built from [`crate::organizer::rows`], which decides what is shown and in
//! what order; every row here stands for one item and carries its id, so an edit, a click or
//! a row action lands on that item however the table is sorted or filtered.

use crate::state::{App, OrgStatus, Tab};
use crate::theme::{self, bold, EmptyIcon, Palette, HIGHLIGHTS};
use crate::organizer::{self, OrgSortColumn};
use crate::ui_core::method_color;
use crate::{actions, editor};
use eframe::egui::{self, Color32, RichText, Ui};

/// Minimum width and share of the leftover space for each column of the table. Path and
/// Notes take the slack: an address and a note are the two that are never long enough.
const COLS: [(f32, f32); 9] = [
    (44.0, 0.0),  // #
    (110.0, 0.0), // Status
    (64.0, 0.0),  // Highlight
    (70.0, 0.0),  // Method
    (160.0, 0.0), // Host
    (200.0, 1.0), // Path
    (110.0, 0.0), // Status code
    (70.0, 0.0),  // Length
    (220.0, 1.0), // Notes
];

/// What a row of the table asked to have done to its item, collected while it is drawn and
/// applied once the table has been: the row borrows the item it is drawing, so nothing can be
/// changed until it has let go.
enum RowAction {
    Select(usize),
    Status(usize, OrgStatus),
    Highlight(usize, Option<usize>),
    Note(usize, String),
    MoveTo(usize, usize),
    Remove(usize),
}

pub fn organizer(app: &mut App, ui: &mut Ui, p: &Palette) {
    let mut action = None;
    collections_sidebar(app, ui, p);
    detail_pane(app, ui, p, &mut action);
    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(10)))
        .show_inside(ui, |ui| {
            let rows = organizer::rows(&app.organizer, app.org_collection, &app.org_view);
            let held = organizer::count_in(&app.organizer, app.org_collection);
            header_and_filters(app, ui, p, rows.len(), held);
            if held == 0 {
                let title = if app.org_collection == organizer::INBOX { "Organizer inbox is empty" } else { "This collection is empty" };
                let _ = theme::empty_state(ui, p, EmptyIcon::Organizer, title,
                    "To get started, send a message to Organizer from anywhere in the suite. Ctrl+O sends the message you are looking at.", None);
                return;
            }
            table(app, ui, p, &rows, &mut action);
            keyboard_navigation(app, ui, &rows);
        });
    if let Some(action) = action {
        apply(app, action);
    }
}

/// The collections, their counts, and the making, renaming and deleting of them.
fn collections_sidebar(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::SidePanel::left("org_collections")
        .resizable(true)
        .default_width(248.0)
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(8)))
        .show_inside(ui, |ui| {
            // the title on the left, the button hard against the right edge, and a gap
            // between them that holds however narrow the panel is dragged: the button is
            // placed first and the title takes what is left, shortened rather than running
            // underneath it
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::plain_button(ui, p, "+ New collection", app.org_new_collection.is_none()).clicked() {
                        app.org_new_collection = Some(String::new());
                    }
                    ui.add_space(8.0);
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(egui::Label::new(bold("Collections", 14.0).color(p.strong)).truncate());
                    });
                });
            });
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(2.0);

            // the name being typed for a new collection: Enter or Add makes it, Escape or
            // Cancel leaves things as they were
            if let Some(mut name) = app.org_new_collection.clone() {
                let edit = ui.add(egui::TextEdit::singleline(&mut name).desired_width(f32::INFINITY).hint_text("Collection name"));
                edit.request_focus();
                app.org_new_collection = Some(name.clone());
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.horizontal(|ui| {
                    if theme::plain_button(ui, p, "Add", true).clicked() || enter {
                        let id = organizer::add_collection(&mut app.org_collections, &name);
                        app.org_collection = id;
                        app.org_new_collection = None;
                    }
                    if theme::plain_button(ui, p, "Cancel", true).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        app.org_new_collection = None;
                    }
                });
                ui.add_space(6.0);
            }

            let collections = app.org_collections.clone();
            for c in &collections {
                if let Some((id, mut name)) = app.org_renaming.clone().filter(|(id, _)| *id == c.id) {
                    let edit = ui.add(egui::TextEdit::singleline(&mut name).desired_width(f32::INFINITY));
                    edit.request_focus();
                    app.org_renaming = Some((id, name.clone()));
                    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.horizontal(|ui| {
                        if theme::plain_button(ui, p, "Rename", true).clicked() || enter {
                            organizer::rename_collection(&mut app.org_collections, id, &name);
                            app.org_renaming = None;
                        }
                        if theme::plain_button(ui, p, "Cancel", true).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            app.org_renaming = None;
                        }
                    });
                    continue;
                }
                let count = organizer::count_in(&app.organizer, c.id);
                let selected = app.org_collection == c.id;
                let (row, cells) = theme::table_row_cells(ui, p, ("org_collection", c.id), &[ui.available_width() - 44.0, 40.0], theme::WIDGET_ROW_HEIGHT, selected, false, None);
                theme::cell_text(ui, cells[0], &c.name, if selected { p.strong } else { p.text });
                theme::cell_text(ui, cells[1], &count.to_string(), p.disabled);
                row.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, selected, format!("{} ({count})", c.name)));
                if row.clicked() {
                    app.org_collection = c.id;
                }
                // the inbox is where everything arrives: it is not ours to rename or delete
                if c.id != organizer::INBOX {
                    row.context_menu(|ui| {
                        if ui.button("Rename collection").clicked() {
                            app.org_renaming = Some((c.id, c.name.clone()));
                            ui.close_menu();
                        }
                        if ui.button("Delete collection").on_hover_text("Its items go back to the inbox").clicked() {
                            if let Some(moved) = organizer::delete_collection(&mut app.organizer, &mut app.org_collections, c.id) {
                                app.org_message = match moved {
                                    0 => format!("Deleted \u{201c}{}\u{201d}.", c.name),
                                    1 => format!("Deleted \u{201c}{}\u{201d}; its item is back in the inbox.", c.name),
                                    n => format!("Deleted \u{201c}{}\u{201d}; its {n} items are back in the inbox.", c.name),
                                };
                                if app.org_collection == c.id {
                                    app.org_collection = organizer::INBOX;
                                }
                            }
                            ui.close_menu();
                        }
                    });
                }
            }
            if !app.org_message.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new(&app.org_message).size(11.5).color(p.disabled));
                if theme::plain_button(ui, p, "Dismiss", true).clicked() {
                    app.org_message.clear();
                }
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Right-click a collection to rename or delete it.").size(11.0).color(p.disabled));
        });
}

/// The collection's name, how much of it is showing, and the filters.
fn header_and_filters(app: &mut App, ui: &mut Ui, p: &Palette, showing: usize, held: usize) {
    let name = app
        .org_collections
        .iter()
        .find(|c| c.id == app.org_collection)
        .map(|c| c.name.clone())
        .unwrap_or_else(|| organizer::INBOX_NAME.to_string());
    ui.horizontal(|ui| {
        ui.label(bold(name, 14.0).color(p.strong));
        ui.label(RichText::new(format!("Showing {showing} of {held} items")).size(11.5).color(p.disabled));
    });
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.org_view.search).desired_width(240.0).hint_text("Search address or notes"));
        ui.checkbox(&mut app.org_view.only_highlighted, "Only highlighted");
        ui.checkbox(&mut app.org_view.only_notes, "Only items with notes");
    });
    ui.add_space(2.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Status").size(11.5).color(p.disabled));
        if theme::pill(ui, p, "All", app.org_view.status.is_none()).clicked() {
            app.org_view.status = None;
        }
        for st in OrgStatus::ALL {
            // the same pill as the traffic ribbon's, and clicking the one already on puts the
            // filter back to showing every status
            if theme::pill(ui, p, st.label(), app.org_view.status == Some(st)).clicked() {
                app.org_view.status = (app.org_view.status != Some(st)).then_some(st);
            }
        }
    });
    if showing == 0 && held > 0 && app.org_view.is_filtering() {
        ui.label(RichText::new(format!("No item here matches the filters ({held} hidden).")).size(11.5).color(p.disabled));
    }
    ui.add_space(6.0);
}

/// The table: a sortable header, then one row per item in view.
fn table(app: &mut App, ui: &mut Ui, p: &Palette, rows: &[usize], action: &mut Option<RowAction>) {
    let height = ui.available_height().max(120.0);
    let sel = app.org_sel;
    let collections = app.org_collections.clone();
    let items = app.organizer.clone();
    let mut sort_click = None;
    theme::fitted_table(ui, p, "org_table", height, &COLS, |ui, w| {
        // Notes has no column of its own to sort by -- a note is not an order -- so it is
        // the one header whose click sorts nothing
        let cols: &[(&str, f32, Option<OrgSortColumn>)] = &[
            ("#", w[0], Some(OrgSortColumn::Index)),
            ("Status", w[1], Some(OrgSortColumn::Status)),
            ("Highlight", w[2], Some(OrgSortColumn::Highlight)),
            ("Method", w[3], Some(OrgSortColumn::Method)),
            ("Host", w[4], Some(OrgSortColumn::Host)),
            ("Path", w[5], Some(OrgSortColumn::Path)),
            ("Status code", w[6], Some(OrgSortColumn::StatusCode)),
            ("Length", w[7], Some(OrgSortColumn::Length)),
            ("Notes", w[8], None),
        ];
        if let Some(Some(col)) = theme::sort_header(ui, p, cols, app.org_view.sort_column.map(Some), app.org_view.sort_ascending) {
            sort_click = Some(col);
        }
        egui::ScrollArea::vertical().id_salt("org_rows").show_rows(ui, theme::WIDGET_ROW_HEIGHT, rows.len(), |ui, range| {
            for (nth, &i) in rows.iter().enumerate().skip(range.start).take(range.len()) {
                let it = &items[i];
                let selected = sel == Some(it.id);
                let tint = it.highlight.and_then(|h| HIGHLIGHTS.get(h)).map(|(_, c)| *c);
                let (row, cells) = theme::table_row_cells(ui, p, ("org_row", it.id), w, theme::WIDGET_ROW_HEIGHT, selected, nth % 2 == 1, tint);
                let fg = if selected { p.strong } else { p.text };
                theme::cell_text(ui, cells[0], &it.id.to_string(), fg);
                theme::cell_text(ui, cells[3], &it.method, if selected { p.strong } else { method_color(p, &it.method) });
                theme::cell_text(ui, cells[4], &it.host, fg);
                theme::cell_text(ui, cells[5], &it.path, fg);
                theme::cell_text(ui, cells[6], &organizer::status_text(&it.response), fg);
                theme::cell_text(ui, cells[7], &organizer::body_length(&it.response).to_string(), fg);

                // The two cells that are chosen from rather than typed in. Both are drawn
                // after the row, so the pointer finds them first: a click here opens the
                // chooser and leaves the row's own selection alone.
                let status_id = ui.id().with(("org_status", it.id));
                let status_cell = chooser(ui, p, cells[1], status_id, &format!("Status of #{}: {}", it.id, it.status.label()), |ui, area| {
                    let colour = it.status.color(p);
                    ui.painter().circle_filled(egui::pos2(area.left() + 4.0, area.center().y), 3.5, colour);
                    let text = egui::Rect::from_min_max(egui::pos2(area.left() + 13.0, area.top()), area.max);
                    theme::cell_text(ui, text, it.status.label(), colour);
                });
                if status_cell.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(status_id.with("popup")));
                }
                egui::popup::popup_below_widget(
                    ui,
                    status_id.with("popup"),
                    &status_cell,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(124.0);
                        for st in OrgStatus::ALL {
                            if menu_entry(ui, p, Mark::Dot(st.color(p)), st.label(), st.color(p), st == it.status) {
                                *action = Some(RowAction::Status(it.id, st));
                            }
                        }
                    },
                );

                let highlight_id = ui.id().with(("org_highlight", it.id));
                let highlight_label = format!("Highlight of #{}: {}", it.id, organizer::highlight_name(it.highlight));
                let highlight_cell = chooser(ui, p, cells[2], highlight_id, &highlight_label, |ui, area| {
                    swatch(ui, p, egui::Rect::from_center_size(egui::pos2(area.left() + 9.0, area.center().y), egui::Vec2::splat(14.0)), tint);
                })
                .on_hover_text(organizer::highlight_name(it.highlight));
                if highlight_cell.clicked() {
                    ui.memory_mut(|m| m.toggle_popup(highlight_id.with("popup")));
                }
                egui::popup::popup_below_widget(
                    ui,
                    highlight_id.with("popup"),
                    &highlight_cell,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(124.0);
                        if menu_entry(ui, p, Mark::Swatch(None), "None", p.text, it.highlight.is_none()) {
                            *action = Some(RowAction::Highlight(it.id, None));
                        }
                        for (h, (name, colour)) in HIGHLIGHTS.iter().enumerate() {
                            if menu_entry(ui, p, Mark::Swatch(Some(*colour)), name, p.text, it.highlight == Some(h)) {
                                *action = Some(RowAction::Highlight(it.id, Some(h)));
                            }
                        }
                    },
                );

                // A note of one line is edited where it is. One of several is shown as its
                // first line instead: a single-line editor draws the line breaks in it as
                // empty boxes, and typing in one would throw away everything after the first
                // line. The pane below has room for the whole of it.
                if let Some((first, _)) = it.note.split_once('\n') {
                    theme::cell_text(ui, cells[8], &format!("{first} \u{2026}"), fg);
                } else {
                    let mut note = it.note.clone();
                    let note_edit = ui.put(
                        cells[8],
                        egui::TextEdit::singleline(&mut note).id_salt(("org_note", it.id)).hint_text("Add a note").frame(false),
                    );
                    if note_edit.changed() {
                        *action = Some(RowAction::Note(it.id, note.clone()));
                    }
                }

                let url = actions::org_item_url(it);
                let request = actions::org_item_request(it);
                let label = format!("Organizer #{} ({} {}{})", it.id, it.method, it.host, it.path);
                // the row itself is what is selected, so it is the row that announces itself
                row.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, selected, &label));
                if row.clicked() || row.secondary_clicked() {
                    *action = Some(RowAction::Select(it.id));
                }
                row.context_menu(|ui| {
                    crate::ui_tools::show_traffic_context_menu(ui, app, Tab::Organizer, &url, &request, Some(&it.response), &request, None, &label);
                    ui.separator();
                    ui.menu_button("Status", |ui| {
                        for st in OrgStatus::ALL {
                            if ui.selectable_label(it.status == st, RichText::new(st.label()).color(st.color(p))).clicked() {
                                *action = Some(RowAction::Status(it.id, st));
                                ui.close_menu();
                            }
                        }
                    });
                    ui.menu_button("Highlight", |ui| {
                        if ui.selectable_label(it.highlight.is_none(), "None").clicked() {
                            *action = Some(RowAction::Highlight(it.id, None));
                            ui.close_menu();
                        }
                        for (h, (name, col)) in HIGHLIGHTS.iter().enumerate() {
                            if ui.selectable_label(it.highlight == Some(h), RichText::new(*name).background_color(*col).color(Color32::BLACK)).clicked() {
                                *action = Some(RowAction::Highlight(it.id, Some(h)));
                                ui.close_menu();
                            }
                        }
                    });
                    move_to_menu(ui, &collections, it.collection, it.id, action);
                    ui.separator();
                    if ui.button("Remove from Organizer").clicked() {
                        *action = Some(RowAction::Remove(it.id));
                        ui.close_menu();
                    }
                });
            }
        });
    });
    if let Some(col) = sort_click {
        app.org_view.click_column(col);
    }
}

/// What stands in front of a chooser's entry: a dot for a status, a swatch for a highlight.
enum Mark {
    Dot(Color32),
    /// The colour, or none at all -- an empty square with a dash through it.
    Swatch(Option<Color32>),
}

/// A cell that opens a chooser when it is clicked: no frame and no border of its own, a soft
/// fill under the pointer, and a small caret at its right edge to say there is something
/// behind it. `paint` draws what the cell shows, in the room left to the left of the caret.
///
/// It is registered after the row it sits in, so the pointer finds it first and a click on it
/// opens the chooser instead of selecting the row underneath.
fn chooser(ui: &mut Ui, p: &Palette, cell: egui::Rect, id: egui::Id, label: &str, paint: impl FnOnce(&mut Ui, egui::Rect)) -> egui::Response {
    let rect = cell.shrink2(egui::vec2(0.0, 3.0));
    let r = ui.interact(rect, id, egui::Sense::click());
    r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, true, label));
    if r.hovered() {
        ui.painter().rect_filled(rect, 4.0, p.hover);
        theme::caret(ui, egui::pos2(rect.right() - 7.0, rect.center().y), p.disabled);
    }
    paint(ui, egui::Rect::from_min_max(rect.min, egui::pos2((rect.right() - 14.0).max(rect.left()), rect.max.y)));
    r
}

/// A highlight's colour as a rounded square, or, for an item with no highlight, an outlined
/// square with a dash through it -- an empty colour has to look deliberately empty rather
/// than like a swatch that failed to draw.
fn swatch(ui: &Ui, p: &Palette, rect: egui::Rect, colour: Option<Color32>) {
    match colour {
        Some(c) => {
            ui.painter().rect_filled(rect, 3.0, c);
        }
        None => {
            ui.painter().rect_stroke(rect, 3.0, egui::Stroke::new(1.0_f32, p.disabled), egui::StrokeKind::Inside);
            let y = rect.center().y;
            ui.painter().line_segment(
                [egui::pos2(rect.left() + 3.5, y), egui::pos2(rect.right() - 3.5, y)],
                egui::Stroke::new(1.0_f32, p.disabled),
            );
        }
    }
}

/// One line of a chooser's menu: its mark, then its name. Returns whether it was picked.
fn menu_entry(ui: &mut Ui, p: &Palette, mark: Mark, label: &str, colour: Color32, current: bool) -> bool {
    let width = ui.available_width().max(110.0);
    let (rect, r) = ui.allocate_exact_size(egui::vec2(width, 20.0), egui::Sense::click());
    r.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, current, label));
    if current || r.hovered() {
        ui.painter().rect_filled(rect, 4.0, if current { p.selection } else { p.hover });
    }
    match mark {
        Mark::Dot(c) => {
            ui.painter().circle_filled(egui::pos2(rect.left() + 10.0, rect.center().y), 3.5, c);
        }
        Mark::Swatch(c) => swatch(ui, p, egui::Rect::from_center_size(egui::pos2(rect.left() + 11.0, rect.center().y), egui::Vec2::splat(13.0)), c),
    }
    theme::cell_text(ui, egui::Rect::from_min_max(egui::pos2(rect.left() + 24.0, rect.top()), rect.max), label, colour);
    r.clicked()
}

/// "Move to collection", listing every collection but the one the item is already in.
fn move_to_menu(ui: &mut Ui, collections: &[organizer::OrgCollection], from: usize, id: usize, action: &mut Option<RowAction>) {
    ui.menu_button("Move to collection", |ui| {
        let mut any = false;
        for c in collections.iter().filter(|c| c.id != from) {
            any = true;
            if ui.button(&c.name).clicked() {
                *action = Some(RowAction::MoveTo(id, c.id));
                ui.close_menu();
            }
        }
        if !any {
            ui.label("No other collection yet");
        }
    });
}

/// Up and Down move the selection through the rows as they are shown -- sorted and filtered
/// as they are, which is the order the eye is following. Held back while something has the
/// keyboard, so an arrow key in the search box or a note moves the cursor and not the row.
fn keyboard_navigation(app: &mut App, ui: &mut Ui, rows: &[usize]) {
    if rows.is_empty() || ui.memory(|m| m.focused()).is_some() {
        return;
    }
    let (down, up) = ui.input(|i| (i.key_pressed(egui::Key::ArrowDown), i.key_pressed(egui::Key::ArrowUp)));
    if !down && !up {
        return;
    }
    let ids: Vec<usize> = rows.iter().map(|&i| app.organizer[i].id).collect();
    let at = app.org_sel.and_then(|id| ids.iter().position(|&x| x == id));
    let next = match (at, down) {
        // nothing selected yet: Down takes the first row, Up the last
        (None, true) => 0,
        (None, false) => ids.len() - 1,
        (Some(i), true) => (i + 1).min(ids.len() - 1),
        (Some(i), false) => i.saturating_sub(1),
    };
    app.org_sel = Some(ids[next]);
}

/// The selected item: what can be done with it, the message itself, and its notes.
fn detail_pane(app: &mut App, ui: &mut Ui, p: &Palette, action: &mut Option<RowAction>) {
    // the selection only shows while the item it names is in the collection on screen: an
    // item moved elsewhere is no longer one of these rows, so the pane under them closes
    let Some(it) = app
        .org_sel
        .and_then(|id| app.organizer.iter().find(|it| it.id == id && it.collection == app.org_collection))
        .cloned()
    else {
        return;
    };
    let url = actions::org_item_url(&it);
    let request = actions::org_item_request(&it);
    let response = it.response.clone();
    let collections = app.org_collections.clone();
    let name = format!("Organizer #{}", it.id);
    let avail = ui.available_height();
    egui::TopBottomPanel::bottom("org_detail")
        .resizable(true)
        .default_height(300.0)
        .min_height(120.0)
        // as in the traffic tables: the pane can never grow over the table above it
        .max_height((avail - 120.0).max(120.0))
        .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { top: 6, ..Default::default() }))
        .show_inside(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(bold(format!("{} {}{}", it.method, it.host, it.path), 12.5).color(p.strong));
                if theme::plain_button(ui, p, "Send to Repeater", true).clicked() {
                    actions::send_to_repeater(app, &it.method, &url, &request);
                }
                if theme::plain_button(ui, p, "Send to Intruder", true).clicked() {
                    actions::send_to_intruder(app, &url, &request);
                }
                if theme::plain_button(ui, p, "Send to Sequencer", true).clicked() {
                    actions::send_to_sequencer(app, &url, &request);
                }
                if theme::plain_button(ui, p, "Send to Comparer", true)
                    .on_hover_text("Adds the response; right-click a message for the request or a selection")
                    .clicked()
                {
                    let data = if response.is_empty() { request.as_bytes() } else { response.as_bytes() };
                    crate::comparer::add(app, name.clone(), data);
                    app.tab = Tab::Comparer;
                }
                if theme::plain_button(ui, p, "Send to Decoder", true).clicked() {
                    actions::send_text_to_decoder(app, request.clone());
                }
                ui.menu_button("Move to collection", |ui| {
                    let mut any = false;
                    for c in collections.iter().filter(|c| c.id != it.collection) {
                        any = true;
                        if ui.button(&c.name).clicked() {
                            *action = Some(RowAction::MoveTo(it.id, c.id));
                            ui.close_menu();
                        }
                    }
                    if !any {
                        ui.label("No other collection yet");
                    }
                });
                if theme::plain_button(ui, p, "Remove", true).clicked() {
                    *action = Some(RowAction::Remove(it.id));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    crate::ui_inspector::toggle_button(ui, &mut app.inspector)
                });
            });
            // the editors and the Inspector scroll inside the pane rather than pushing it
            // taller than it was dragged
            egui::ScrollArea::vertical().id_salt("org_detail_scroll").auto_shrink([false, false]).show(ui, |ui| {
                crate::ui_inspector::inspector_panel(ui, p, &mut app.inspector, "organizer", &it.id.to_string(), &request, Some(&response));
                let h = (ui.available_height() - 22.0).max(100.0);
                let (out_req, out_resp, note) = theme::columns(ui, 3, |cols| {
                    cols[0].label(bold("Request", 12.5).color(p.strong));
                    let req_v = editor::message_view(&mut cols[0], p, "org_req", &request, h);
                    cols[1].label(bold("Response", 12.5).color(p.strong));
                    let resp_v = editor::message_view(&mut cols[1], p, "org_resp", &response, h);
                    cols[2].label(bold("Notes", 12.5).color(p.strong));
                    let mut note = it.note.clone();
                    let edit = cols[2].add(
                        egui::TextEdit::multiline(&mut note)
                            .id_salt("org_notes")
                            .desired_width(f32::INFINITY)
                            .desired_rows(4)
                            .hint_text("What is worth remembering about this message"),
                    );
                    (req_v, resp_v, edit.changed().then_some(note))
                });
                if let Some(note) = note {
                    *action = Some(RowAction::Note(it.id, note));
                }
                crate::ui_tools::attach_view_context_menu(&out_req, &request, app, Tab::Organizer, &url, &request, Some(&response), &format!("{name} request"));
                crate::ui_tools::attach_view_context_menu(&out_resp, &response, app, Tab::Organizer, &url, &request, Some(&response), &format!("{name} response"));
            });
        });
}

/// Carry out what a row or the detail pane asked for. Everything addresses its item by id, so
/// it reaches the same item whatever the table was showing at the time.
fn apply(app: &mut App, action: RowAction) {
    let find = |app: &App, id: usize| app.organizer.iter().position(|it| it.id == id);
    match action {
        RowAction::Select(id) => app.org_sel = (app.org_sel != Some(id)).then_some(id),
        RowAction::Status(id, st) => {
            if let Some(i) = find(app, id) {
                app.organizer[i].status = st;
            }
        }
        RowAction::Highlight(id, h) => {
            if let Some(i) = find(app, id) {
                app.organizer[i].highlight = h;
            }
        }
        RowAction::Note(id, note) => {
            if let Some(i) = find(app, id) {
                app.organizer[i].note = note;
            }
        }
        RowAction::MoveTo(id, to) => {
            let collections = app.org_collections.clone();
            organizer::move_to(&mut app.organizer, id, to, &collections);
        }
        RowAction::Remove(id) => {
            app.organizer.retain(|it| it.id != id);
            if app.org_sel == Some(id) {
                app.org_sel = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::organizer::{self, OrgSortColumn, INBOX};
    use crate::state::OrgStatus;
    use crate::test_utils::{assert_table, MockAppBuilder};

    /// The Organizer with three items in the inbox, each with a response of its own.
    fn org_app() -> (egui::Context, App) {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Organizer).build_with_ctx();
        ctx.enable_accesskit();
        for (host, path, method, body, body_text, status) in [
            ("shop.test", "/cart?id=2", "GET", "", "one", "200 OK"),
            ("api.test", "/v1/users", "POST", "name=x", "", "404 Not Found"),
            ("shop.test", "/pay", "GET", "", "a longer body", "200 OK"),
        ] {
            let request = format!("{method} {path} HTTP/1.1\nHost: {host}\n\n{body}");
            let response = format!("HTTP/1.1 {status}\ncontent-length: {}\n\n{body_text}", body_text.len());
            actions::send_to_organizer(&mut app, &format!("http://{host}{path}"), &request, &response);
        }
        app.tab = Tab::Organizer;
        app.org_sel = None;
        (ctx, app)
    }

    /// One full frame of the app with these input events; returns the accessibility update.
    fn frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1500.0, 900.0))),
            events,
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    /// Everything in a frame labelled `label`, with its rectangle. A button carries its text
    /// as the node's label and a plain label carries it as the node's value, so both count --
    /// and text that is painted rather than laid out as a widget is in neither.
    fn find_all(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> Vec<egui::Rect> {
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        nodes
            .iter()
            .filter(|(_, n)| n.label().as_deref() == Some(label) || n.value().as_deref() == Some(label))
            .filter_map(|(_, n)| n.bounds())
            .map(|r| egui::Rect::from_min_max(egui::pos2(r.x0 as f32, r.y0 as f32), egui::pos2(r.x1 as f32, r.y1 as f32)))
            .collect()
    }

    /// Where the one widget labelled `label` is.
    fn find(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> egui::Rect {
        let found = find_all(update, label);
        assert!(!found.is_empty(), "no widget labelled {label:?}");
        found[0]
    }

    fn button(pos: egui::Pos2, pressed: bool, secondary: bool) -> egui::Event {
        egui::Event::PointerButton {
            pos,
            button: if secondary { egui::PointerButton::Secondary } else { egui::PointerButton::Primary },
            pressed,
            modifiers: Default::default(),
        }
    }

    /// Click a point, press and release over a frame each, the way a user would.
    fn click_at(ctx: &egui::Context, app: &mut App, at: egui::Pos2, secondary: bool) {
        frame(ctx, app, vec![egui::Event::PointerMoved(at)]);
        frame(ctx, app, vec![button(at, true, secondary)]);
        frame(ctx, app, vec![button(at, false, secondary)]);
        frame(ctx, app, vec![]);
    }

    /// Click the widget labelled `label`, settling the layout first.
    fn click(ctx: &egui::Context, app: &mut App, label: &str) {
        frame(ctx, app, vec![]);
        let at = find(&frame(ctx, app, vec![]), label).center();
        click_at(ctx, app, at, false);
    }

    /// The row of the item with this id, as the table announces it.
    fn row_label(app: &App, id: usize) -> String {
        let it = app.organizer.iter().find(|it| it.id == id).expect("the item");
        format!("Organizer #{} ({} {}{})", it.id, it.method, it.host, it.path)
    }

    /// Where that row is drawn.
    fn row_rect(ctx: &egui::Context, app: &mut App, id: usize) -> egui::Rect {
        let label = row_label(app, id);
        frame(ctx, app, vec![]);
        find(&frame(ctx, app, vec![]), &label)
    }

    /// The ids the table is showing, in the order it shows them.
    fn shown(app: &App) -> Vec<usize> {
        organizer::rows(&app.organizer, app.org_collection, &app.org_view).iter().map(|&i| app.organizer[i].id).collect()
    }

    /// Clicking a row selects that item, and clicking it again lets it go. What the detail
    /// pane shows follows the selection, so the message under the table is the row's own.
    #[test]
    fn clicking_a_row_selects_that_item_and_opens_its_message() {
        let (ctx, mut app) = org_app();
        assert_eq!(app.org_sel, None, "nothing is selected to begin with");

        let at = row_rect(&ctx, &mut app, 2).center();
        click_at(&ctx, &mut app, at, false);
        assert_eq!(app.org_sel, Some(2), "the row that was clicked");
        // the detail pane names the item it is showing, which is that row's
        let update = frame(&ctx, &mut app, vec![]);
        assert!(!find_all(&update, "Send to Repeater").is_empty(), "the action bar is open");
        assert!(!find_all(&update, "POST api.test/v1/users").is_empty(), "showing the selected item's own message");

        click_at(&ctx, &mut app, at, false);
        assert_eq!(app.org_sel, None, "clicking the selected row again lets it go");
        assert!(find_all(&frame(&ctx, &mut app, vec![]), "Send to Repeater").is_empty(), "and the pane closes");
    }

    /// Clicking a column header sorts the table by it, and again reverses it -- and a row still
    /// stands for its own item once the order has changed under it.
    #[test]
    fn clicking_a_header_sorts_the_table_and_rows_keep_their_items() {
        let (ctx, mut app) = org_app();
        assert_eq!(shown(&app), [1, 2, 3], "the order they arrived in");

        click(&ctx, &mut app, "Host");
        assert_eq!(app.org_view.sort_column, Some(OrgSortColumn::Host));
        assert!(app.org_view.sort_ascending);
        assert_eq!(shown(&app), [2, 1, 3], "api.test first");

        // the top row is now item 2, which was the second row before the sort: clicking it
        // selects item 2 and not whatever used to be in that place
        let at = row_rect(&ctx, &mut app, 2).center();
        click_at(&ctx, &mut app, at, false);
        assert_eq!(app.org_sel, Some(2), "the row points at the item the sort put there");

        click(&ctx, &mut app, "Host");
        assert!(!app.org_view.sort_ascending, "the same column again reverses it");
        // the two items on the same host keep the order they arrived in, as in the traffic
        // tables: reversing a column reverses the column, not the tie-break under it
        assert_eq!(shown(&app), [1, 3, 2]);

        click(&ctx, &mut app, "Length");
        assert_eq!(app.org_view.sort_column, Some(OrgSortColumn::Length));
        assert_eq!(app.org_sel, Some(2), "and sorting does not disturb what is selected");

        // Notes is drawn with the other headers but sorts nothing
        let before = app.org_view.sort_column;
        click(&ctx, &mut app, "Notes");
        assert_eq!(app.org_view.sort_column, before, "the Notes header sorts nothing");
    }

    /// The filters narrow the table, and what is selected stays itself while they do.
    #[test]
    fn the_filters_narrow_the_table_matrix() {
        struct Case {
            name: &'static str,
            apply: fn(&mut App),
            want: Vec<usize>,
        }
        let cases = [
            Case { name: "searching the address", apply: |a| a.org_view.search = "api".into(), want: vec![2] },
            Case { name: "searching a note", apply: |a| a.org_view.search = "look".into(), want: vec![3] },
            Case { name: "only highlighted", apply: |a| a.org_view.only_highlighted = true, want: vec![1] },
            Case { name: "only with notes", apply: |a| a.org_view.only_notes = true, want: vec![3] },
            Case { name: "one status", apply: |a| a.org_view.status = Some(OrgStatus::Done), want: vec![2] },
            Case { name: "a status nothing is in", apply: |a| a.org_view.status = Some(OrgStatus::Ignored), want: vec![] },
        ];
        assert_table!(cases, |idx, case| {
            let (ctx, mut app) = org_app();
            app.organizer[0].highlight = Some(2);
            app.organizer[1].status = OrgStatus::Done;
            app.organizer[2].note = "another look".into();
            app.org_sel = Some(1);
            (case.apply)(&mut app);
            frame(&ctx, &mut app, vec![]);
            assert_eq!(shown(&app), case.want, "case #{idx} ({})", case.name);
            assert_eq!(app.org_sel, Some(1), "case #{idx} ({}): the selection is left alone", case.name);
            // every row the table draws is really on screen
            for id in shown(&app) {
                assert!(!find_all(&frame(&ctx, &mut app, vec![]), &row_label(&app, id)).is_empty(), "case #{idx}: row {id} is drawn");
            }
        });
    }

    /// The status pills filter by one status, and the one already on puts the filter back.
    #[test]
    fn the_status_pills_filter_by_status() {
        let (ctx, mut app) = org_app();
        app.organizer[1].status = OrgStatus::Postponed;
        click(&ctx, &mut app, "Postponed");
        assert_eq!(app.org_view.status, Some(OrgStatus::Postponed));
        assert_eq!(shown(&app), [2]);
        click(&ctx, &mut app, "Postponed");
        assert_eq!(app.org_view.status, None, "the pill that was on puts the filter back");
        assert_eq!(shown(&app), [1, 2, 3]);
        app.org_view.status = Some(OrgStatus::Done);
        click(&ctx, &mut app, "All");
        assert_eq!(app.org_view.status, None, "and so does All");
    }

    /// Up and Down walk the selection through the rows in the order they are shown, which is
    /// the order the sort put them in -- not the order the items are stored in.
    #[test]
    fn the_arrow_keys_walk_the_rows_in_the_order_they_are_shown() {
        let (ctx, mut app) = org_app();
        let key = |k: egui::Key| vec![egui::Event::Key { key: k, physical_key: None, pressed: true, repeat: false, modifiers: Default::default() }];
        frame(&ctx, &mut app, vec![]);

        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.org_sel, Some(1), "Down with nothing selected takes the first row");
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.org_sel, Some(2));
        frame(&ctx, &mut app, key(egui::Key::ArrowUp));
        assert_eq!(app.org_sel, Some(1));
        frame(&ctx, &mut app, key(egui::Key::ArrowUp));
        assert_eq!(app.org_sel, Some(1), "and stops at the top rather than wrapping");

        // sorted the other way, Down goes to what is now the next row down
        app.org_view.sort_ascending = false;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(shown(&app), [3, 2, 1]);
        app.org_sel = Some(3);
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.org_sel, Some(2), "the row under it on screen");

        // a filter that hides the selected row leaves the arrows working on what is left
        app.org_view.search = "shop".into();
        app.org_sel = None;
        frame(&ctx, &mut app, vec![]);
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert!(shown(&app).contains(&app.org_sel.unwrap()), "the selection is one of the rows shown");
    }

    /// Status, highlight and notes belong to one item each: changing one row leaves every
    /// other row as it was, whichever row is where after a sort.
    #[test]
    fn an_edit_lands_on_one_item_and_leaves_the_others_alone_matrix() {
        enum Edit {
            Status(OrgStatus),
            Highlight(Option<usize>),
            Note(&'static str),
        }
        struct Case {
            name: &'static str,
            /// Which item is edited, by id.
            id: usize,
            edit: Edit,
        }
        let cases = [
            Case { name: "a status", id: 2, edit: Edit::Status(OrgStatus::Done) },
            Case { name: "a highlight", id: 3, edit: Edit::Highlight(Some(4)) },
            Case { name: "a note of several lines", id: 1, edit: Edit::Note("first line\nsecond line\n") },
            Case { name: "a highlight taken off again", id: 1, edit: Edit::Highlight(None) },
        ];
        assert_table!(cases, |idx, case| {
            let (_ctx, mut app) = org_app();
            // sorted the other way round, so a row's place is not its item's place
            app.org_view.sort_ascending = false;
            let before: Vec<(OrgStatus, Option<usize>, String)> =
                app.organizer.iter().map(|it| (it.status, it.highlight, it.note.clone())).collect();
            let action = match case.edit {
                Edit::Status(st) => RowAction::Status(case.id, st),
                Edit::Highlight(h) => RowAction::Highlight(case.id, h),
                Edit::Note(n) => RowAction::Note(case.id, n.to_string()),
            };
            apply(&mut app, action);
            for (i, it) in app.organizer.iter().enumerate() {
                let what = format!("case #{idx} ({}): item {}", case.name, it.id);
                let now = (it.status, it.highlight, it.note.clone());
                if it.id == case.id {
                    match case.edit {
                        Edit::Status(st) => assert_eq!(it.status, st, "{what} took the new status"),
                        Edit::Highlight(h) => assert_eq!(it.highlight, h, "{what} took the new highlight"),
                        Edit::Note(n) => {
                            assert_eq!(it.note, n, "{what} took the new note");
                            assert_eq!(it.note.lines().count(), 2, "{what} kept both its lines");
                        }
                    }
                } else {
                    assert_eq!(now, before[i], "{what} was left exactly as it was");
                }
            }
        });
    }

    /// The lowest thing in a frame labelled `label` -- the one in a chooser's menu rather
    /// than the filter pill of the same name above the table.
    fn find_lowest(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> egui::Rect {
        let mut found = find_all(update, label);
        found.sort_by(|a, b| a.top().total_cmp(&b.top()));
        *found.last().unwrap_or_else(|| panic!("nothing labelled {label:?}"))
    }

    /// The inline choosers open on a click, and the click that opens one does not also select
    /// the row it sits in -- the chooser is in front of the row and takes the click whole.
    /// Picking from the menu sets that one item and closes the menu.
    #[test]
    fn the_inline_choosers_open_without_disturbing_the_row_matrix() {
        struct Case {
            name: &'static str,
            /// The trigger to click, and the entry to pick from the menu it opens.
            trigger: &'static str,
            pick: &'static str,
            check: fn(&App),
        }
        let cases = [
            Case {
                name: "the status chooser",
                trigger: "Status of #2: New",
                pick: "Postponed",
                check: |a| assert_eq!(a.organizer[1].status, OrgStatus::Postponed),
            },
            Case {
                name: "the highlight chooser",
                trigger: "Highlight of #2: None",
                pick: "Cyan",
                check: |a| assert_eq!(a.organizer[1].highlight, Some(4)),
            },
        ];
        assert_table!(cases, |idx, case| {
            let (ctx, mut app) = org_app();
            frame(&ctx, &mut app, vec![]);
            let at = find(&frame(&ctx, &mut app, vec![]), case.trigger).center();
            click_at(&ctx, &mut app, at, false);
            let what = format!("case #{idx} ({})", case.name);

            assert_eq!(app.org_sel, None, "{what}: the row underneath was not selected by the click");
            let update = frame(&ctx, &mut app, vec![]);
            let entry = find_lowest(&update, case.pick);
            assert!(entry.top() > at.y, "{what}: the menu is open under the trigger ({entry:?})");

            click_at(&ctx, &mut app, entry.center(), false);
            (case.check)(&app);
            assert_eq!(app.org_sel, None, "{what}: and picking from it still leaves the row unselected");
            // the others are untouched, and the menu has closed behind it
            assert_eq!(app.organizer[0].status, OrgStatus::New, "{what}: the row above");
            assert_eq!(app.organizer[2].highlight, None, "{what}: and the row below");
            let after = frame(&ctx, &mut app, vec![]);
            assert!(find_all(&after, "Ignored").len() <= 1, "{what}: the menu closed (only the filter pill is left)");
        });
    }

    /// The inline note editor in a row writes to that row's item. The cell is found from where
    /// the row is drawn, so this is the editor a user would click into.
    #[test]
    fn typing_in_a_rows_note_cell_writes_to_that_rows_item() {
        let (ctx, mut app) = org_app();
        let rect = row_rect(&ctx, &mut app, 2);
        // the Notes column is the last one, at the right-hand end of the row
        let at = egui::pos2(rect.right() - 60.0, rect.center().y);
        click_at(&ctx, &mut app, at, false);
        frame(&ctx, &mut app, vec![egui::Event::Text("check the 404".into())]);
        frame(&ctx, &mut app, vec![]);
        assert_eq!(app.organizer[1].note, "check the 404", "the note went to the row that was clicked");
        assert!(app.organizer[0].note.is_empty() && app.organizer[2].note.is_empty(), "and to no other row");
    }

    /// Right-clicking a row opens the row's own menu, and what it offers acts on that item.
    /// "Remove" is the one that must be exact: it throws the item away.
    #[test]
    fn the_row_menu_acts_on_the_row_it_was_opened_on() {
        let (ctx, mut app) = org_app();
        let at = row_rect(&ctx, &mut app, 2).center();
        click_at(&ctx, &mut app, at, true);
        let update = frame(&ctx, &mut app, vec![]);
        // "Remove from Organizer" is the row menu's own wording: the action bar's button is
        // just "Remove", so finding this one means the menu really is open
        assert!(!find_all(&update, "Remove from Organizer").is_empty(), "the row menu is open");
        assert!(!find_all(&update, "Status").is_empty(), "with the status submenu on it");
        assert!(!find_all(&update, "Highlight").is_empty(), "and the highlight one");
        assert!(find_all(&update, "Send to Organizer").is_empty(), "but no way back to where it already is");

        let remove = find(&update, "Remove from Organizer").center();
        click_at(&ctx, &mut app, remove, false);
        assert_eq!(app.organizer.iter().map(|it| it.id).collect::<Vec<_>>(), [1, 3], "that item and no other was removed");
        assert_eq!(app.org_sel, None, "and nothing is left selected");
    }

    /// The outbound actions in the detail pane hand the selected item's own message to the
    /// tool they name.
    #[test]
    fn the_action_bar_sends_the_selected_item_onward_matrix() {
        struct Case {
            name: &'static str,
            button: &'static str,
            tab: Tab,
            check: fn(&App),
        }
        let cases = [
            Case {
                name: "Repeater",
                button: "Send to Repeater",
                tab: Tab::Repeater,
                check: |a| assert!(a.rep().request.contains("/v1/users"), "the request is in the tab: {:?}", a.rep().request),
            },
            Case {
                name: "Intruder",
                button: "Send to Intruder",
                tab: Tab::Intruder,
                check: |a| assert!(a.int_template.contains("/v1/users"), "the template: {:?}", a.int_template),
            },
            Case {
                name: "Sequencer",
                button: "Send to Sequencer",
                tab: Tab::Sequencer,
                check: |a| assert!(a.seq_template.contains("/v1/users"), "the template: {:?}", a.seq_template),
            },
            Case {
                name: "Comparer",
                button: "Send to Comparer",
                tab: Tab::Comparer,
                check: |a| {
                    assert_eq!(a.comparer_items.len(), 1, "one item was added");
                    assert_eq!(a.comparer_items[0].label, "Organizer #2");
                },
            },
            Case {
                name: "Decoder",
                button: "Send to Decoder",
                tab: Tab::Decoder,
                check: |a| assert!(a.dec_blocks[0].text.contains("/v1/users"), "the text: {:?}", a.dec_blocks[0].text),
            },
        ];
        assert_table!(cases, |idx, case| {
            let (ctx, mut app) = org_app();
            app.org_sel = Some(2);
            click(&ctx, &mut app, case.button);
            assert_eq!(app.tab, case.tab, "case #{idx} ({}): the tool it was sent to is showing", case.name);
            (case.check)(&app);
            assert_eq!(app.organizer.len(), 3, "case #{idx} ({}): and the item stays in the Organizer", case.name);
        });
    }

    /// Collections are made from the sidebar, items are moved into them, and the table shows
    /// one collection at a time.
    #[test]
    fn collections_are_made_from_the_sidebar_and_items_move_between_them() {
        let (ctx, mut app) = org_app();
        assert_eq!(app.org_collections.len(), 1, "the inbox alone to begin with");

        click(&ctx, &mut app, "+ New collection");
        frame(&ctx, &mut app, vec![egui::Event::Text("Auth flows".into())]);
        click(&ctx, &mut app, "Add");
        assert_eq!(app.org_collections.len(), 2);
        let auth = app.org_collections[1].id;
        assert_eq!(app.org_collections[1].name, "Auth flows");
        assert_eq!(app.org_collection, auth, "the new collection is the one showing");
        assert!(shown(&app).is_empty(), "which has nothing in it yet");

        // move an item into it, by the action every route funnels through
        apply(&mut app, RowAction::MoveTo(2, auth));
        frame(&ctx, &mut app, vec![]);
        assert_eq!(shown(&app), [2], "it is in this collection now");
        assert_eq!(organizer::count_in(&app.organizer, INBOX), 2, "and no longer in the inbox");

        // the sidebar counts what each collection holds
        let update = frame(&ctx, &mut app, vec![]);
        assert!(!find_all(&update, "Inbox (2)").is_empty(), "the inbox count");
        assert!(!find_all(&update, "Auth flows (1)").is_empty(), "and this one's");

        // back to the inbox: the table follows the sidebar
        click(&ctx, &mut app, "Inbox (2)");
        assert_eq!(app.org_collection, INBOX);
        assert_eq!(shown(&app), [1, 3]);

        // renaming keeps the items where they are
        app.org_renaming = Some((auth, "Login".into()));
        click(&ctx, &mut app, "Rename");
        assert_eq!(app.org_collections[1].name, "Login");
        assert_eq!(app.org_renaming, None, "and the editor closes");
        assert_eq!(organizer::count_in(&app.organizer, auth), 1, "the item is still in it");

        // and a selected item that moves out of the collection on screen closes the pane
        app.org_sel = Some(2);
        frame(&ctx, &mut app, vec![]);
        assert!(find_all(&frame(&ctx, &mut app, vec![]), "Send to Repeater").is_empty(), "the inbox is showing, and item 2 is not in it");
        app.org_collection = auth;
        frame(&ctx, &mut app, vec![]);
        assert!(!find_all(&frame(&ctx, &mut app, vec![]), "Send to Repeater").is_empty(), "its own collection shows it again");
    }

    /// Ctrl+O and every other route into the Organizer files the item in the inbox and
    /// selects it, whichever collection was on screen at the time.
    #[test]
    fn an_item_sent_to_the_organizer_arrives_in_the_inbox() {
        let (ctx, mut app) = org_app();
        let other = organizer::add_collection(&mut app.org_collections, "Later");
        app.org_collection = other;
        frame(&ctx, &mut app, vec![]);
        actions::send_to_organizer(&mut app, "http://new.test/x", "GET /x HTTP/1.1\nHost: new.test\n\n", "HTTP/1.1 200 OK\n\nhi");
        assert_eq!(app.tab, Tab::Organizer);
        assert_eq!(app.org_collection, INBOX, "the inbox is brought forward, so the item is not filed out of sight");
        let it = app.organizer.last().unwrap();
        assert_eq!((it.collection, it.id), (INBOX, 4));
        assert_eq!(app.org_sel, Some(4), "and it is the one selected");
        frame(&ctx, &mut app, vec![]);
        assert!(!find_all(&frame(&ctx, &mut app, vec![]), "GET new.test/x").is_empty(), "with its message open");
    }
}
