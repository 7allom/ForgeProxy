//! The thirteen tool screens, each matching its reference screenshot's default state.

use crate::actions;
use crate::decoder_ops;
use crate::editor;
use crate::intruder::{self, AttackType};
use crate::issue_defs;
use crate::rules;
use crate::state::{App, DecBlock, Tab};
use crate::theme::{self, bold, EmptyIcon, Palette, HIGHLIGHTS};
use crate::ui_core::{c, method_color, sub_tabs};
use eframe::egui;
use egui::{Color32, FontId, RichText, Stroke, Ui};

fn sev_color(p: &Palette, s: &str) -> Color32 {
    match s { "High" => p.high, "Medium" => p.medium, "Low" => p.low, _ => p.info }
}

// ---- Target (picture-9, 10, 11) -----------------------------------------
pub fn target(app: &mut App, ui: &mut Ui, p: &Palette) {
    sub_tabs(ui, p, &["Site map", "Scope", "Issues"], &mut app.target_sub);
    match app.target_sub {
        1 => target_scope(app, ui, p),
        2 => target_issues(app, ui, p),
        _ => {
            if app.history.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                let (_, open) = theme::empty_state(ui, p, EmptyIcon::SiteMap, "Site map URL view is empty",
                    "The site map shows the contents of your target applications and any issues found. \
                     Run a scan from the Dashboard or send requests from Repeater to populate it.", Some("New scan"));
                if open { app.tab = Tab::Dashboard; app.show_new_scan = true; }
            } else {
                crate::ui_target::site_map(app, ui, p);
            }
        }
    }
}

fn target_scope(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::ScrollArea::vertical().id_salt("scope_page").auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(ui.available_width());
        ui.add_space(6.0);
        theme::section_title(ui, p, "Target scope", "Define exactly which hosts and URLs count as the target. HTTP history, the site map and Logger can show only in-scope items, and scope actions are on every row's right-click menu.");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.target_scope.advanced, "Use advanced scope control");
            ui.label(RichText::new(if app.target_scope.advanced {
                "entries are regular expressions matched against the full URL"
            } else {
                "entries are URL prefixes (https://host:port/path), hostnames, or domains (*.example.com)"
            }).size(11.5).color(p.disabled));
        });
        for exclude in [false, true] {
            let (title, desc) = if exclude {
                ("Target Scope: Exclude from scope", "Anything matching an exclusion is out of scope, even if an include rule matches it.")
            } else {
                ("Target Scope: Include in scope", "With no include rules, everything is in scope. Otherwise an item must match one of them.")
            };
            crate::ui_settings::setting_card(ui, title, desc, Some("Project setting"), |ui| scope_list(app, ui, p, exclude));
        }
        // quick check of the rules above
        let test_id = egui::Id::new("scope_test_url");
        let mut test: String = ui.data(|d| d.get_temp(test_id)).unwrap_or_default();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Check a URL:").color(p.text));
            ui.add(egui::TextEdit::singleline(&mut test).desired_width(360.0).hint_text("https://example.com/path"));
            if !test.trim().is_empty() {
                let (txt, col) = if app.target_scope.is_in_scope(test.trim()) { ("In scope", p.st_done) } else { ("Out of scope", p.high) };
                ui.label(RichText::new(txt).color(col));
            }
        });
        ui.data_mut(|d| d.insert_temp(test_id, test));
    });
}

/// Inline editor for adding (index None) or editing a scope rule.
#[derive(Clone, Default)]
struct ScopeEdit {
    index: Option<usize>,
    text: String,
    subdomains: bool,
    error: String,
}

/// One scope list: Add/Edit/Remove strip, the rule table, and the inline editor.
fn scope_list(app: &mut App, ui: &mut Ui, p: &Palette, exclude: bool) {
    let edit_id = egui::Id::new(("scope_edit", exclude));
    let mut edit: Option<ScopeEdit> = ui.data(|d| d.get_temp(edit_id));
    let len = if exclude { app.target_scope.exclude.len() } else { app.target_scope.include.len() };
    let sel = app.scope_sel.filter(|s| s.0 == exclude && s.1 < len).map(|s| s.1);
    let mut remove = None;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            if theme::side_button(ui, p, "Add", true).clicked() {
                edit = Some(ScopeEdit::default());
            }
            if theme::side_button(ui, p, "Edit", sel.is_some()).clicked() {
                if let Some(i) = sel {
                    let list = if exclude { &app.target_scope.exclude } else { &app.target_scope.include };
                    edit = Some(ScopeEdit { index: Some(i), text: list[i].prefix.clone(), subdomains: list[i].subdomains, error: String::new() });
                }
            }
            if theme::side_button(ui, p, "Remove", sel.is_some()).clicked() { remove = sel; }
        });
        const COLS: [(f32, f32); 3] = [(70.0, 0.0), (220.0, 1.0), (100.0, 0.0)];
        theme::fitted_table(ui, p, ("scope_table", exclude), 19.0 * 5.0 + 6.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Enabled", w[0]), ("Prefix / Host / URL", w[1]), ("Subdomains", w[2])]);
            let list = if exclude { &mut app.target_scope.exclude } else { &mut app.target_scope.include };
            if list.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new(if exclude { "  No exclusions." } else { "  No include rules: everything is in scope." }).size(12.0).color(p.disabled));
            }
            for i in 0..list.len() {
                let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 19.0), egui::Sense::click());
                if sel == Some(i) { ui.painter().rect_filled(rect, 0.0, p.selection); }
                else if i % 2 == 1 { ui.painter().rect_filled(rect, 0.0, ui.visuals().faint_bg_color); }
                let mut en = list[i].enabled;
                if ui.put(egui::Rect::from_min_size(egui::pos2(rect.left() + 8.0, rect.center().y - 7.0), egui::vec2(14.0, 14.0)), egui::Checkbox::without_text(&mut en)).changed() { list[i].enabled = en; }
                let x = rect.left() + 6.0 + w[0];
                let clip = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(x + w[1] - 8.0, rect.bottom()));
                ui.painter().with_clip_rect(clip).text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, &list[i].prefix, egui::FontId::monospace(12.0), p.text);
                let mut sub = list[i].subdomains;
                if ui.put(egui::Rect::from_min_size(egui::pos2(x + w[1] + 8.0, rect.center().y - 7.0), egui::vec2(14.0, 14.0)), egui::Checkbox::without_text(&mut sub)).changed() { list[i].subdomains = sub; }
                if resp.clicked() { app.scope_sel = Some((exclude, i)); }
                if resp.double_clicked() {
                    edit = Some(ScopeEdit { index: Some(i), text: list[i].prefix.clone(), subdomains: list[i].subdomains, error: String::new() });
                }
            }
        });
    });
    if let Some(i) = remove {
        if exclude { app.target_scope.exclude.remove(i); } else { app.target_scope.include.remove(i); }
        app.scope_sel = None;
        edit = edit.filter(|e| e.index.is_none());
    }
    let mut close = false;
    if let Some(e) = edit.as_mut() {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(if e.index.is_some() { "Edit rule:" } else { "New rule:" }).color(p.text));
            let field = ui.add(egui::TextEdit::singleline(&mut e.text).desired_width(320.0).font(egui::FontId::monospace(12.5))
                .hint_text(if app.target_scope.advanced { "^https://([a-z]+\\.)?example\\.com/" } else { "https://example.com/  or  *.example.com" }));
            if field.changed() { e.error.clear(); }
            ui.checkbox(&mut e.subdomains, "Include subdomains");
            let submit = theme::primary_button(ui, p, "OK").clicked() || (field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if theme::plain_button(ui, p, "Cancel", true).clicked() { close = true; }
            if submit {
                let text = e.text.trim().to_string();
                if text.is_empty() {
                    e.error = "Enter a prefix, host or URL.".into();
                } else if app.target_scope.advanced && crate::regex_cache::get(&text).is_none() {
                    e.error = "Not a valid regular expression.".into();
                } else {
                    let list = if exclude { &mut app.target_scope.exclude } else { &mut app.target_scope.include };
                    match e.index.filter(|&i| i < list.len()) {
                        Some(i) => { list[i].prefix = text; list[i].subdomains = e.subdomains; }
                        None => {
                            list.push(crate::scope::ScopeRule { enabled: true, prefix: text, subdomains: e.subdomains });
                            app.scope_sel = Some((exclude, list.len() - 1));
                        }
                    }
                    close = true;
                }
            }
        });
        if !e.error.is_empty() {
            ui.label(RichText::new(&e.error).size(12.0).color(p.high));
        }
    }
    if close { edit = None; }
    ui.data_mut(|d| match edit {
        Some(e) => d.insert_temp(edit_id, e),
        None => d.remove::<ScopeEdit>(edit_id),
    });
}

fn target_issues(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(bold("Issue definitions", 14.0).color(p.strong));
    });
    ui.label(RichText::new("This listing contains the definitions of all issues that can be detected by the scanner.").size(12.0).color(p.text));
    ui.add_space(6.0);
    let defs = issue_defs::ISSUE_DEFS;
    egui::SidePanel::left("issuelist").resizable(true).default_width(470.0)
        .frame(egui::Frame::new().fill(p.deep)).show_inside(ui, |ui| {
            theme::table_header(ui, p, &[("Name", 290.0), ("Typical severity", 100.0), ("Type index", 90.0)]);
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, (idx, name, sev)) in defs.iter().enumerate() {
                    let sel = app.issue_sel == i;
                    let r = theme::table_row(ui, p, &[
                        ((*name).into(), 290.0, None),
                        ((*sev).into(), 100.0, Some(sev_color(p, sev))),
                        (format!("0x{idx:08x}"), 90.0, None),
                    ], sel, i % 2 == 1);
                    if r.clicked() { app.issue_sel = i; }
                }
            });
        });
    egui::CentralPanel::default().frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(14))).show_inside(ui, |ui| {
        let (idx, name, sev) = defs[app.issue_sel.min(defs.len() - 1)];
        ui.label(bold(name, 15.0).color(p.strong));
        ui.add_space(8.0);
        ui.label(bold("Description", 13.0).color(p.strong));
        ui.add(egui::Label::new(RichText::new(describe(name)).color(p.text)).wrap());
        ui.add_space(10.0);
        ui.label(bold("Typical severity", 13.0).color(p.strong));
        ui.colored_label(sev_color(p, sev), sev);
        ui.add_space(10.0);
        ui.label(bold("Type index", 13.0).color(p.strong));
        ui.label(RichText::new(format!("0x{idx:08x}")).color(p.text));
    });
}

fn describe(name: &str) -> String {
    format!("This issue type covers {}. The scanner reports it when the relevant conditions are \
             observed in a response or confirmed by an active check. Review the affected request and \
             response, confirm the finding, and apply the appropriate remediation for this class of \
             vulnerability.", name.to_ascii_lowercase())
}

// ---- Intruder (picture-16) ----------------------------------------------
pub fn intruder(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        theme::icon_help(ui, p);
        egui::ComboBox::from_id_salt("attack").width(300.0)
            .selected_text(format!("{} attack", app.int_attack.label()))
            .show_ui(ui, |ui| { for t in AttackType::ALL { ui.selectable_value(&mut app.int_attack, t, format!("{} attack", t.label())); } });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let running = app.int_running;
            let problem = actions::attack_problem(app);
            let start = ui.add_enabled(!running && problem.is_none(), egui::Button::new(bold("Start attack", 13.0).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(120.0, 24.0)));
            if start.clicked() {
                actions::start_attack(app);
            }
            if running || !app.int_results.is_empty() {
                let label = if running { "Show attack".to_string() } else { format!("Show results ({})", app.int_results.len()) };
                if theme::plain_button(ui, p, &label, true).clicked() { app.show_attack = true; }
            }
            // why the attack can't start (or why it didn't)
            let note = if running { None } else { problem.or_else(|| (!app.int_msg.is_empty()).then(|| app.int_msg.clone())) };
            if let Some(note) = note {
                ui.label(RichText::new(note).size(12.0).color(p.medium));
            }
        });
    });
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Target").color(p.text));
        ui.add(egui::TextEdit::singleline(&mut app.int_target).desired_width(ui.available_width() - 240.0));
        ui.checkbox(&mut app.int_update_host, "")
            .on_hover_text("Off: send the Host header written in the request below (payload positions in it are filled in)");
        ui.label(RichText::new("Update Host header to match target").size(12.0).color(p.text));
    });
    ui.add_space(4.0);
    egui::SidePanel::right("payloads").resizable(true).default_width(370.0).width_range(300.0..=640.0)
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(10))).show_inside(ui, |ui| {
            ui.label(bold("Payloads", 14.0).color(p.strong));
            ui.add_space(6.0);
            let two = matches!(app.int_attack, AttackType::Pitchfork | AttackType::ClusterBomb);
            let count = actions::payload_lines(&app.int_payloads).len();
            let count_b = actions::payload_lines(&app.int_payloads_b).len();
            let positions = intruder::count_positions(&app.int_template);
            ui.horizontal(|ui| { ui.label(RichText::new("Payload set:").color(p.text)); ui.label(RichText::new(if two { "1" } else { "All positions" }).color(p.text)); });
            ui.horizontal(|ui| { ui.label(RichText::new("Payload type:").color(p.text)); ui.label(RichText::new("Simple list").color(p.text)); });
            ui.horizontal(|ui| { ui.label(RichText::new("Payload count:").color(p.text)); ui.label(RichText::new(count.to_string()).color(p.text)); });
            let total = intruder::request_count(app.int_attack, positions, count, count_b);
            ui.horizontal(|ui| { ui.label(RichText::new("Request count:").color(p.text)); ui.label(RichText::new(total.to_string()).color(p.text)); });
            ui.add_space(8.0);
            ui.label(bold("Payload settings", 13.0).color(p.strong));
            ui.label(RichText::new("One payload per line. These strings are used as payloads.").size(11.5).color(p.text));
            ui.add_space(4.0);
            // framed so the box reads as an input on the panel's dark background
            let payload_box = |ui: &mut Ui, text: &mut String, rows: usize, salt: &str| {
                egui::Frame::new().fill(p.panel).stroke(Stroke::new(1.0_f32, p.header)).inner_margin(egui::Margin::same(4)).show(ui, |ui| {
                    let width = ui.available_width();
                    egui::ScrollArea::vertical().id_salt(salt).max_height(rows as f32 * 18.0).auto_shrink([false, true]).show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(text).id_salt(salt).desired_rows(rows).desired_width(width)
                            .font(FontId::monospace(12.5)).frame(false).hint_text("Enter payloads, one per line"));
                    });
                });
            };
            payload_box(ui, &mut app.int_payloads, 8, "int_payloads_a");
            payload_controls(ui, p, &mut app.int_payloads, &mut app.int_msg, "a");
            if two {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(bold("Payload set 2", 13.0).color(p.strong));
                    ui.label(RichText::new(format!("({count_b} payloads)")).size(12.0).color(p.text));
                });
                payload_box(ui, &mut app.int_payloads_b, 5, "int_payloads_b");
                payload_controls(ui, p, &mut app.int_payloads_b, &mut app.int_msg, "b");
            }
        });
    egui::CentralPanel::default().frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(6))).show_inside(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(bold("Positions", 13.0).color(p.strong));
            if theme::plain_button(ui, p, "Add §", app.int_sel.is_some()).on_hover_text("Select text in the request, then press to mark it as a payload position").clicked() {
                if let Some((a, b)) = app.int_sel {
                    let chars: Vec<char> = app.int_template.chars().collect();
                    let (a, b) = (a.min(chars.len()), b.min(chars.len()));
                    let mut out: String = chars[..a].iter().collect();
                    out.push('§');
                    out.extend(&chars[a..b]);
                    out.push('§');
                    out.extend(&chars[b..]);
                    app.int_template = out;
                    app.int_sel = None;
                }
            }
            if theme::plain_button(ui, p, "Clear §", true).clicked() { app.int_template = app.int_template.replace('§', ""); }
            if theme::plain_button(ui, p, "Auto §", true).clicked() { app.int_template = crate::intruder::auto_positions(&app.int_template); }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(format!("{} payload positions", intruder::count_positions(&app.int_template))).size(11.5).color(p.text));
            });
        });
        let out = editor::message_editor(ui, p, "int_pos", &mut app.int_template, true, true, 240.0);
        if let Some(r) = out.cursor_range {
            let (a, b) = (r.primary.ccursor.index, r.secondary.ccursor.index);
            app.int_sel = if a != b { Some((a.min(b), a.max(b))) } else { app.int_sel.filter(|_| !out.response.has_focus()) };
        }
    });
}

/// Append `lines` to a payload list (one per line), keeping a newline between what's there
/// and what's added.
fn append_payloads(target: &mut String, lines: &str) {
    let add = lines.trim_end_matches('\n');
    if add.is_empty() {
        return;
    }
    if !target.is_empty() && !target.ends_with('\n') {
        target.push('\n');
    }
    target.push_str(add);
}

/// A payload list's controls: a presets dropdown, a native "Load file..." picker and Clear.
/// `salt` keeps the two lists' widgets apart.
fn payload_controls(ui: &mut Ui, p: &Palette, list: &mut String, msg: &mut String, salt: &str) {
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt(("int_preset", salt)).selected_text("Presets").width(130.0)
            .show_ui(ui, |ui| {
                for (name, _) in intruder::PRESETS {
                    if ui.selectable_label(false, *name).clicked() {
                        if let Some(lines) = intruder::preset_lines(name) {
                            *list = lines;
                            *msg = format!("Loaded the {name} preset");
                        }
                    }
                }
            });
        if theme::plain_button(ui, p, "Load file...", true).on_hover_text("Add every line of a text file to this list").clicked() {
            if let Some(path) = rfd::FileDialog::new().add_filter("Wordlist", &["txt", "lst", "csv"]).add_filter("All files", &["*"]).pick_file() {
                *msg = match std::fs::read_to_string(&path) {
                    Ok(text) => {
                        let n = actions::payload_lines(&text).len();
                        append_payloads(list, &text);
                        format!("Loaded {n} payloads from {}", path.display())
                    }
                    Err(e) => format!("Couldn't read {}: {e}", path.display()),
                };
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::plain_button(ui, p, "Clear", !list.is_empty()).clicked() {
                list.clear();
            }
        });
    });
}

/// "Intruder attack" window: progress and one row per request as results come in.
pub fn attack_window(app: &mut App, ctx: &egui::Context, p: &Palette) {
    if !app.show_attack {
        return;
    }
    let mut open = true;
    let done = app.int_results.len();
    let total = app.int_total.max(done);
    // a row's right-click choice: (history id, where to send it)
    let mut attack_pick: Option<(usize, actions::SendTo)> = None;
    egui::Window::new(bold(format!("Intruder attack — {}", app.int_target.trim()), 14.0).color(p.strong))
        .id(egui::Id::new("intruder_attack"))
        .open(&mut open)
        .default_size([820.0, 480.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let state = if app.int_running { "Running" } else if done < total { "Stopped" } else { "Finished" };
                ui.label(bold(format!("{} attack: {state}", app.int_attack.label()), 13.0).color(p.strong));
                let errors = app.int_results.iter().filter(|r| !r.error.is_empty()).count();
                if errors > 0 {
                    ui.label(RichText::new(format!("{errors} errors")).size(12.0).color(p.high));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::plain_button(ui, p, "Stop", app.int_running).clicked() {
                        app.int_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            });
            let frac = if total == 0 { 0.0 } else { done as f32 / total as f32 };
            ui.add(egui::ProgressBar::new(frac).text(format!("{done} of {total} requests")).animate(app.int_running));
            ui.add_space(4.0);
            let cols: [(&str, f32); 5] = [("Request", 70.0), ("Payload", 220.0), ("Status code", 130.0), ("Length", 80.0), ("Error", 280.0)];
            let mut row_click = None;
            // a selected row's request and response are shown in a resizable pane below
            let detail = app.int_result_sel.map(|id| {
                (id, app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|e| e.id == id).cloned())
            });
            if let Some((id, entry)) = detail {
                egui::TopBottomPanel::bottom("int_detail").resizable(true).default_height(240.0).min_height(90.0)
                    .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { top: 6, ..Default::default() }))
                    .show_inside(ui, |ui| match entry {
                        Some(e) => {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("#{}", e.id)).color(p.text));
                                if theme::plain_button(ui, p, "Copy as cURL", true).on_hover_text("Copy the request as a curl command").clicked() {
                                    ui.ctx().copy_text(actions::entry_as_curl(&e));
                                }
                            });
                            let h = (ui.available_height() - 22.0).max(60.0);
                            ui.columns(2, |cols| {
                                cols[0].label(bold("Request", 12.5).color(p.strong));
                                editor::message_view(&mut cols[0], p, &format!("int_req_{id}"), &e.request, h);
                                cols[1].label(bold("Response", 12.5).color(p.strong));
                                editor::message_view(&mut cols[1], p, &format!("int_resp_{id}"), &e.response, h);
                            });
                        }
                        None => { ui.label(RichText::new("This request is no longer in history.").size(12.0).color(p.disabled)); }
                    });
            }
            egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
                theme::table_well(ui, p, (ui.available_height() - 4.0).max(60.0), |ui| {
                    theme::table_header(ui, p, &cols);
                    egui::ScrollArea::vertical().id_salt("int_results").auto_shrink([false, false]).show(ui, |ui| {
                        if app.int_results.is_empty() {
                            ui.label(RichText::new("Waiting for the first response...").color(p.disabled));
                        }
                        for (i, r) in app.int_results.iter().enumerate() {
                            let cells = [
                                (r.request.to_string(), cols[0].1, None),
                                (r.payload.clone(), cols[1].1, None),
                                (r.status.clone(), cols[2].1, None),
                                (r.length.to_string(), cols[3].1, None),
                                (r.error.clone(), cols[4].1, Some(p.high)),
                            ];
                            let id = r.history_id;
                            let row = theme::table_row(ui, p, &cells, app.int_result_sel == Some(id), i % 2 == 1);
                            if row.clicked() {
                                row_click = Some(id);
                            }
                            row.context_menu(|ui| {
                                for (label, to) in [("Send request to Comparer", actions::SendTo::ComparerRequest), ("Send response to Comparer", actions::SendTo::Comparer),
                                                    ("Send to Repeater", actions::SendTo::Repeater)] {
                                    if ui.button(label).clicked() {
                                        attack_pick = Some((id, to));
                                        ui.close_menu();
                                    }
                                }
                            });
                        }
                    });
                });
            });
            // clicking a row opens its detail pane (clicking it again closes it)
            if let Some(id) = row_click {
                app.int_result_sel = (app.int_result_sel != Some(id)).then_some(id);
            }
        });
    if let Some((id, to)) = attack_pick {
        let entry = app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|e| e.id == id).cloned();
        if let Some(e) = entry {
            actions::send_to(app, &e, to);
        }
    }
    if !open {
        app.show_attack = false;
    }
}

// ---- Repeater (picture-17) ----------------------------------------------
/// Extra Repeater padding on top of the tab margin (16px from the window edge in all).
const REPEATER_PAD: i8 = 6;

pub fn repeater(app: &mut App, ui: &mut Ui, p: &Palette) {
    let mut send = false;
    let mut to_sequencer: Option<(String, String)> = None;
    let mut pick = None;
    egui::Frame::new().inner_margin(egui::Margin::same(REPEATER_PAD)).show(ui, |ui| {
        repeater_tab_strip(app, ui, p);
        ui.add_space(6.0);
        let i = app.active_repeater_tab.min(app.repeater_tabs.len() - 1);
        app.active_repeater_tab = i;
        let tab_id = app.repeater_tabs[i].id;
        let url_before = app.repeater_tabs[i].url.clone();
        let request_before = app.repeater_tabs[i].request.clone();
        ui.horizontal(|ui| {
            let tab = &mut app.repeater_tabs[i];
            // the dropdown mirrors the request line's method (including ones not in the list);
            // picking one rewrites the request line
            if let Some(m) = actions::request_method(&tab.request) { tab.method = m; }
            let shown = tab.method.clone();
            egui::ComboBox::from_id_salt(("rep_m", tab_id)).width(90.0).selected_text(&shown)
                .show_ui(ui, |ui| { for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] { ui.selectable_value(&mut tab.method, m.to_string(), m); } });
            if tab.method != shown {
                tab.request = actions::set_request_method(&tab.request, &tab.method);
            }
            ui.add(egui::TextEdit::singleline(&mut tab.url).id_salt(("rep_url", tab_id)).hint_text("https://target.example/").desired_width(ui.available_width() - 200.0));
            let can_send = tab.can_send();
            let why = if tab.waiting { "Waiting for the response" } else { "Write a request first" };
            if ui.add_enabled(can_send, egui::Button::new(bold("Send", 13.0).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(80.0, 24.0)))
                .on_disabled_hover_text(why).clicked() {
                send = true;
            }
            if theme::plain_button(ui, p, "Copy as cURL", tab.can_send()).on_hover_text("Copy the request as a curl command").clicked() {
                ui.ctx().copy_text(crate::export::to_curl(&tab.request, &actions::origin_of(&tab.url)));
            }
            if theme::plain_button(ui, p, "Send to Sequencer", tab.can_send()).on_hover_text("Analyse the randomness of a token in this response").clicked() {
                to_sequencer = Some((tab.request.clone(), actions::origin_of(&tab.url)));
            }
            crate::ui_inspector::toggle_button(ui, &mut app.inspector);
        });
        ui.add_space(8.0);
        {
            let tab = &app.repeater_tabs[i];
            // each tab is its own message: switching tabs starts the Auto-Decoder afresh
            crate::ui_inspector::inspector_panel(ui, p, &mut app.inspector, "repeater", &tab_id.to_string(), &tab.request, tab.response.as_deref());
        }
        // Request | Response, split 50/50 by a draggable divider; each pane is padded 8px on
        // the divider side and draws its header at the same height
        let width = ui.available_width();
        const GAP: i8 = 8;
        // fixed-height header row, left-aligned, so both panes' editors start at the same y
        let header = |ui: &mut Ui, text: String| {
            ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 20.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.label(bold(text, 13.0).color(p.strong));
            });
            ui.add_space(4.0);
        };
        egui::SidePanel::right("rep_response_pane").resizable(true).default_width(width / 2.0)
            .width_range((width * 0.25)..=(width * 0.75))
            .frame(egui::Frame::new().inner_margin(egui::Margin { left: GAP, ..Default::default() }))
            .show_inside(ui, |ui| {
                let tab = &mut app.repeater_tabs[i];
                header(ui, format!("Response{}", response_summary(tab)));
                let h = ui.available_height() - 2.0;
                // each tab keeps its own Raw / Pretty / Hex choice
                let view_id = format!("rep_resp:{tab_id}");
                editor::set_view_mode(ui.ctx(), &view_id, tab.view_mode);
                let text = tab.response.as_deref().unwrap_or("");
                let out = editor::message_view(ui, p, &view_id, text, h);
                pick = out.menu_named(text, "response").map(|m| (m, format!("Repeater tab {} response", tab.title)));
                tab.view_mode = editor::view_mode(ui.ctx(), &view_id);
            });
        egui::CentralPanel::default().frame(egui::Frame::new().inner_margin(egui::Margin { right: GAP, ..Default::default() }))
            .show_inside(ui, |ui| {
                header(ui, "Request".into());
                let h = ui.available_height() - 2.0;
                let tab = &mut app.repeater_tabs[i];
                // per-tab editor state: cursor and undo history don't leak between tabs
                let out = editor::message_editor(ui, p, &format!("rep_req:{tab_id}"), &mut tab.request, true, false, h);
                let what = format!("Repeater tab {} request", tab.title);
                pick = pick.take().or_else(|| editor::message_menu(&out, &tab.request).map(|m| (m, what)));
            });
        sync_repeater_target(&mut app.repeater_tabs[i], &url_before, &request_before);
    });
    if let Some((m, what)) = pick {
        apply_menu_pick(app, m, &what);
        return;
    }
    if let Some((template, origin)) = to_sequencer {
        app.seq_template = template;
        app.seq_origin = origin;
        app.seq_samples.clear();
        app.seq_analysis = None;
        app.seq_message.clear();
        app.seq_sub = 0;
        app.tab = Tab::Sequencer;
        return;
    }
    if send {
        actions::send_repeater(app);
    }
}

/// "   200 OK · 143 ms · 1.2 KiB" after "Response" (or the error / "Sending...").
fn response_summary(tab: &crate::repeater::RepeaterTab) -> String {
    if tab.status_text.is_empty() {
        return String::new();
    }
    let mut s = format!("   {}", tab.status_text);
    if !tab.waiting {
        if let Some(ms) = tab.response_time_ms {
            s.push_str(&format!(" · {ms} ms"));
        }
        if let Some(b) = tab.response_bytes {
            s.push_str(&format!(" · {}", editor::human_size(b)));
        }
    }
    s
}

/// What a click in the tab strip asks for (applied after drawing it).
enum TabAction { Select(usize), New, Close(usize), CloseOthers(usize), Duplicate(usize), Rename(usize), Compare(usize, usize) }

/// The tab strip: one button per tab (active highlighted, "…" while sending), scrolling
/// sideways when they don't fit, and "+" for a new tab. Middle-click closes a tab;
/// right-click has Rename, Duplicate, Compare response with..., Close and Close others.
fn repeater_tab_strip(app: &mut App, ui: &mut Ui, p: &Palette) {
    let mut action = None;
    let active = app.active_repeater_tab;
    ui.horizontal(|ui| {
        let room = (ui.available_width() - 34.0).max(60.0);
        egui::ScrollArea::horizontal().id_salt("rep_tab_strip").max_width(room).auto_shrink([true, true]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (i, t) in app.repeater_tabs.iter().enumerate() {
                    // renaming: an inline field in the tab's place
                    if let Some((id, name)) = app.rep_renaming.as_mut().filter(|(id, _)| *id == t.id) {
                        let r = ui.add(egui::TextEdit::singleline(name).id_salt(("rep_rename", *id)).desired_width(90.0));
                        if !r.has_focus() && !r.lost_focus() {
                            r.request_focus();
                        }
                        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            app.rep_renaming = None;
                        } else if r.lost_focus() {
                            action = Some(TabAction::Rename(i));
                        }
                        continue;
                    }
                    let label = if t.waiting { format!("{} …", t.title) } else { t.title.clone() };
                    let r = ui.add(egui::Button::new(RichText::new(label).size(12.5)).selected(i == active).min_size(egui::vec2(34.0, 22.0)))
                        .on_hover_text(if t.url.is_empty() { "Empty tab".to_string() } else { format!("{} {}", t.method, t.url) });
                    if r.clicked() {
                        action = Some(TabAction::Select(i));
                    }
                    if r.middle_clicked() {
                        action = Some(TabAction::Close(i));
                    }
                    r.context_menu(|ui| {
                        if ui.button("Rename").clicked() {
                            app.rep_renaming = Some((t.id, t.title.clone()));
                            ui.close_menu();
                        }
                        if ui.button("Duplicate").clicked() {
                            action = Some(TabAction::Duplicate(i));
                            ui.close_menu();
                        }
                        let others: Vec<(usize, &str)> = app.repeater_tabs.iter().enumerate()
                            .filter(|(j, o)| *j != i && o.response.is_some()).map(|(j, o)| (j, o.title.as_str())).collect();
                        let can = t.response.is_some() && !others.is_empty();
                        ui.add_enabled_ui(can, |ui| {
                            ui.menu_button("Compare response with...", |ui| {
                                for (j, title) in &others {
                                    if ui.button(format!("Tab {title}")).clicked() {
                                        action = Some(TabAction::Compare(i, *j));
                                        ui.close_menu();
                                    }
                                }
                            });
                        }).response.on_disabled_hover_text("Both tabs need a response: send their requests first");
                        ui.separator();
                        if ui.button("Close").clicked() {
                            action = Some(TabAction::Close(i));
                            ui.close_menu();
                        }
                        if ui.add_enabled(app.repeater_tabs.len() > 1, egui::Button::new("Close others")).clicked() {
                            action = Some(TabAction::CloseOthers(i));
                            ui.close_menu();
                        }
                    });
                }
            });
        });
        if ui.add(egui::Button::new(RichText::new("+").size(14.0).color(p.strong)).min_size(egui::vec2(26.0, 22.0))).on_hover_text("New tab").clicked() {
            action = Some(TabAction::New);
        }
    });
    match action {
        Some(TabAction::Select(i)) => app.active_repeater_tab = i,
        Some(TabAction::New) => { app.add_blank_repeater_tab(); }
        Some(TabAction::Close(i)) => app.close_repeater_tab(i),
        Some(TabAction::CloseOthers(i)) => app.close_other_repeater_tabs(i),
        Some(TabAction::Duplicate(i)) => app.duplicate_repeater_tab(i),
        Some(TabAction::Rename(i)) => {
            if let Some((_, name)) = app.rep_renaming.take() {
                app.rename_repeater_tab(i, &name);
            }
        }
        Some(TabAction::Compare(a, b)) => { app.compare_repeater_responses(a, b); }
        None => {}
    }
}

/// Keep the address bar and the raw request pointing at the same place. Editing the URL
/// rewrites the Host header and request-line path; editing the request (Host header or
/// request line) rewrites the URL. Only one side changes per frame, so they can't fight.
fn sync_repeater_target(tab: &mut crate::repeater::RepeaterTab, url_before: &str, request_before: &str) {
    if tab.url != url_before {
        let (_, authority, path) = actions::url_parts(&tab.url);
        if !authority.is_empty() {
            let request = actions::set_host_header(&tab.request, &authority);
            tab.request = actions::set_request_target(&request, &path);
        }
    } else if tab.request != request_before {
        tab.url = actions::repeater_target(&tab.request, &tab.url);
    }
}

// ---- Collaborator (picture-18) ------------------------------------------
pub fn collaborator(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.add_space(10.0);
    theme::section_title(ui, p, "Collaborator",
        "Test whether an application can be made to contact an external service via DNS, HTTP, or SMTP. \
         Put a payload in a request; if the target looks it up, the interaction shows below.");
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Collaborator server:").color(p.text));
        ui.add(egui::TextEdit::singleline(&mut app.collab_server).desired_width(320.0).hint_text("your-server.example.net (self-hosted)"));
    });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Custom data (optional):").color(p.text));
        ui.add(egui::TextEdit::singleline(&mut app.collab_custom).desired_width(170.0).char_limit(crate::collab::CUSTOM_DATA_MAX).hint_text("letters and digits"));
        ui.checkbox(&mut app.collab_with_server, "Include server location");
    });
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        if theme::primary_button(ui, p, "Copy to clipboard").clicked() {
            let server = app.collab_server.trim().to_string();
            if app.collab_with_server && server.is_empty() {
                app.collab_msg = "Enter your Collaborator server's address first, or untick \"Include server location\".".into();
            } else if !crate::collab::valid_custom_data(&app.collab_custom) {
                app.collab_msg = "Custom data must be letters and digits only, up to 16 characters.".into();
            } else {
                let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
                let payload = crate::collab::generate(seed, app.collab_counter, &app.collab_custom,
                    if app.collab_with_server { Some(server.as_str()) } else { None });
                app.collab_counter += 1;
                ui.ctx().copy_text(payload.clone());
                app.collab_msg = format!("Copied {payload}");
                app.collab_payloads.push(payload);
            }
        }
        if theme::plain_button(ui, p, "Poll now", !app.collab_polling).clicked() {
            crate::actions::poll_collaborator(app);
        }
        if !app.collab_msg.is_empty() {
            let is_err = app.collab_msg.starts_with("Poll failed:")
                || app.collab_msg.starts_with("No Collaborator")
                || app.collab_msg.starts_with("Enter your")
                || app.collab_msg.starts_with("Custom data");
            let col = if is_err { p.high } else { p.text };
            ui.label(RichText::new(&app.collab_msg).size(12.0).color(col));
        }
    });
    ui.add_space(8.0);
    theme::table_well(ui, p, (ui.available_height() - 20.0).max(120.0), |ui| {
        theme::table_header(ui, p, &[("#", 50.0), ("Time", 150.0), ("Type", 80.0), ("Payload", 420.0), ("Source IP address", 160.0), ("Comment", 200.0)]);
        if app.collab_interactions.is_empty() {
            let _ = theme::empty_state(ui, p, EmptyIcon::Radar, "No interactions",
                "Generate a payload with \"Copy to clipboard\", use it in a request, then poll for DNS, HTTP, or SMTP interactions.", None);
        } else {
            for (i, hit) in app.collab_interactions.iter().enumerate() {
                let comment = if !hit.comment.is_empty() {
                    hit.comment.clone()
                } else if !hit.protocol_details.is_empty() {
                    hit.protocol_details.clone()
                } else {
                    crate::collab::decode(&hit.payload)
                        .filter(|d| !d.1.is_empty())
                        .map(|d| format!("Custom data: {}", d.1))
                        .unwrap_or_default()
                };
                let _ = theme::table_row(
                    ui,
                    p,
                    &[
                        ((i + 1).to_string(), 50.0, None),
                        (hit.timestamp.clone(), 150.0, None),
                        (hit.interaction_type.clone(), 80.0, None),
                        (hit.payload.clone(), 420.0, None),
                        (hit.client_ip.clone(), 160.0, None),
                        (comment, 200.0, None),
                    ],
                    false,
                    i % 2 == 1,
                );
            }
        }
    });
}

// ---- Decoder (picture-20) -----------------------------------------------
/// Raw bytes behind the Decoder blocks. A block's text is a `String`, so binary results
/// (GZIP) don't survive being stored there; the exact bytes are kept here, in egui memory,
/// next to `app.dec_blocks`. A cached entry is only used while its block's text is still
/// the text it produced, so editing a block by hand falls back to the typed text.
#[derive(Clone, Default)]
struct DecRaw {
    bytes: Vec<Option<Vec<u8>>>,
    /// Block index and message of the last action that produced nothing.
    error: Option<(usize, String)>,
}

impl DecRaw {
    fn data(&self, i: usize, block: &DecBlock) -> Vec<u8> {
        match self.bytes.get(i) {
            Some(Some(raw)) if String::from_utf8_lossy(raw) == block.text => raw.clone(),
            _ => block.text.as_bytes().to_vec(),
        }
    }
}

/// A new output block; results that aren't valid UTF-8 open in the Hex view.
fn dec_output(out: Vec<u8>, label: String, color: Color32) -> (DecBlock, Vec<u8>) {
    let binary = std::str::from_utf8(&out).is_err();
    let block = DecBlock { text: String::from_utf8_lossy(&out).into_owned(), hex: binary, label: Some(label), color };
    (block, out)
}

fn hex_dump(data: &[u8]) -> String {
    data.chunks(16).enumerate()
        .map(|(n, c)| format!("{:08x}  {}", n * 16, c.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
        .collect::<Vec<_>>().join("\n")
}

pub fn decoder(app: &mut App, ui: &mut Ui, p: &Palette) {
    sub_tabs(ui, p, &["Transform", "JWT Inspector"], &mut app.dec_view);
    if app.dec_view == 1 {
        jwt_inspector(app, ui, p);
        return;
    }
    ui.add_space(4.0);
    // a JWT in any block: offer the inspector
    if let Some(token) = app.dec_blocks.iter().map(|b| b.text.trim()).find(|t| crate::codec::is_jwt(t)).map(String::from) {
        egui::Frame::new().fill(p.banner).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("This looks like a JSON Web Token.").color(p.text));
                if theme::primary_button(ui, p, "Inspect JWT").clicked() {
                    app.jwt_input = token;
                    app.dec_view = 1;
                }
            });
        });
        ui.add_space(4.0);
    }
    let raw_id = egui::Id::new("decoder_raw");
    let mut raw: DecRaw = ui.data(|d| d.get_temp(raw_id)).unwrap_or_default();
    // (block whose output layers are replaced, result: new layers or why nothing came out)
    let mut action: Option<(usize, Result<Vec<(DecBlock, Vec<u8>)>, String>)> = None;
    let mut open_jwt: Option<String> = None;
    let n = app.dec_blocks.len();
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for i in 0..n {
            let is_last = i + 1 == n;
            let data = raw.data(i, &app.dec_blocks[i]);
            let has_input = !data.is_empty();
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - 230.0).max(200.0));
                    if let Some(lbl) = app.dec_blocks[i].label.clone() {
                        ui.label(RichText::new(lbl).size(11.0).color(app.dec_blocks[i].color));
                    }
                    egui::Frame::new().fill(p.deep).stroke(Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
                        if app.dec_blocks[i].hex {
                            let mut hex = hex_dump(&data);
                            ui.add(egui::TextEdit::multiline(&mut hex).desired_rows(4).desired_width(f32::INFINITY).font(FontId::monospace(12.5)).frame(false).interactive(false));
                        } else {
                            ui.add(egui::TextEdit::multiline(&mut app.dec_blocks[i].text).desired_rows(4).desired_width(f32::INFINITY).font(FontId::monospace(12.5)).frame(false));
                        }
                    });
                });
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut app.dec_blocks[i].hex, false, "Text");
                        ui.radio_value(&mut app.dec_blocks[i].hex, true, "Hex");
                        theme::icon_help(ui, p);
                    });
                    ui.add_enabled_ui(has_input, |ui| {
                        egui::ComboBox::from_id_salt(("dec", i)).width(190.0).height(f32::INFINITY).selected_text("Decode as ...").show_ui(ui, |ui| {
                            for cc in decoder_ops::Codec::ALL {
                                if ui.selectable_label(false, cc.label()).clicked() {
                                    let result = match decoder_ops::decode(cc, &data) {
                                        Some(out) => Ok(vec![dec_output(out, format!("Decoded as {}", cc.label()), p.ed_param_value)]),
                                        None if cc == decoder_ops::Codec::Gzip => Err("Not valid GZIP input, or it decompresses to more than 32 MiB.".to_string()),
                                        None => Err(format!("Not valid {} input.", cc.label())),
                                    };
                                    action = Some((i, result));
                                }
                            }
                            ui.separator();
                            if ui.selectable_label(false, "JWT").on_hover_text("Open in the JWT Inspector").clicked() {
                                let text = String::from_utf8_lossy(&data).trim().to_string();
                                match crate::codec::parse_jwt_detailed(&text) {
                                    Ok(_) => open_jwt = Some(text),
                                    Err(e) => action = Some((i, Err(format!("Not a JWT: {e}")))),
                                }
                            }
                        });
                        egui::ComboBox::from_id_salt(("enc", i)).width(190.0).height(f32::INFINITY).selected_text("Encode as ...").show_ui(ui, |ui| {
                            for cc in decoder_ops::Codec::ALL {
                                if ui.selectable_label(false, cc.label()).clicked() {
                                    let out = decoder_ops::encode(cc, &data);
                                    action = Some((i, Ok(vec![dec_output(out, format!("Encoded as {}", cc.label()), p.ed_header_name)])));
                                }
                            }
                        });
                        egui::ComboBox::from_id_salt(("hash", i)).width(190.0).height(f32::INFINITY).selected_text("Hash ...").show_ui(ui, |ui| {
                            for h in decoder_ops::Hash::ALL {
                                if ui.selectable_label(false, h.label()).clicked() {
                                    let out = decoder_ops::hash(h, &data);
                                    action = Some((i, Ok(vec![dec_output(out, format!("{} hash", h.label()), p.ed_param_name)])));
                                }
                            }
                        });
                        if is_last && ui.add(egui::Button::new(bold("Smart decode", 12.5).color(p.text)).fill(p.header).min_size(egui::vec2(190.0, 22.0))).clicked() {
                            // one output block per decoded layer, outermost first
                            let layers: Vec<_> = decoder_ops::smart_decode(&data)
                                .into_iter()
                                .map(|(cc, out)| dec_output(out, format!("Smart decode: {}", cc.label()), p.ed_param_value))
                                .collect();
                            let result = if layers.is_empty() { Err("No encoding recognised.".to_string()) } else { Ok(layers) };
                            action = Some((i, result));
                        }
                    });
                    if let Some((at, msg)) = &raw.error {
                        if *at == i {
                            ui.label(RichText::new(msg).size(11.5).color(p.high));
                        }
                    }
                });
            });
            ui.add_space(2.0);
        }
    });
    if let Some((i, result)) = action {
        raw.bytes.resize(app.dec_blocks.len(), None);
        match result {
            Ok(layers) => {
                // keep block i's exact bytes so the next layer works on them, not on lossy text
                let input = raw.data(i, &app.dec_blocks[i]);
                raw.bytes[i] = Some(input);
                app.dec_blocks.truncate(i + 1);
                raw.bytes.truncate(i + 1);
                for (block, bytes) in layers {
                    app.dec_blocks.push(block);
                    raw.bytes.push(Some(bytes));
                }
                raw.error = None;
            }
            Err(msg) => raw.error = Some((i, msg)),
        }
    }
    ui.data_mut(|d| d.insert_temp(raw_id, raw));
    if let Some(token) = open_jwt {
        app.jwt_input = token;
        app.dec_view = 1;
    }
}

/// Colours of the three JWT parts (header, payload, signature) for the current theme.
fn jwt_colors(look: theme::Look) -> [Color32; 3] {
    match look {
        theme::Look::Dark => [c(0xF07FA8), c(0x5BC0DE), c(0xA89BC8)],
        theme::Look::Light => [c(0xC2185B), c(0x00838F), c(0x6E5F96)],
    }
}

/// Token text coloured by part; the dots stay in the normal text colour.
fn jwt_layout(text: &str, colors: [Color32; 3], dot: Color32, size: f32) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let fmt = |c: Color32| egui::TextFormat { font_id: FontId::monospace(size), color: c, ..Default::default() };
    for (i, part) in text.split('.').enumerate() {
        if i > 0 {
            job.append(".", 0.0, fmt(dot));
        }
        job.append(part, 0.0, fmt(colors[i.min(2)]));
    }
    job
}

/// Read-only, selectable JSON viewer.
fn json_view(ui: &mut Ui, p: &Palette, id: &str, title: &str, color: Color32, json: &str) {
    ui.label(bold(title, 13.0).color(color));
    egui::Frame::new().fill(p.deep).stroke(Stroke::new(1.0_f32, p.header)).inner_margin(egui::Margin::same(6)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let mut text: &str = json;
        ui.add(egui::TextEdit::multiline(&mut text).id_salt(id).font(FontId::monospace(12.5)).frame(false)
            .desired_width(f32::INFINITY).desired_rows(8));
    });
}

fn jwt_inspector(app: &mut App, ui: &mut Ui, p: &Palette) {
    let colors = jwt_colors(app.eff().theme);
    egui::ScrollArea::vertical().id_salt("jwt_page").auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(ui.available_width());
        ui.add_space(6.0);
        theme::section_title(ui, p, "JWT Inspector", "Paste a JSON Web Token (header.payload.signature). It is decoded here, locally; the signature is not verified.");
        ui.add_space(6.0);
        egui::Frame::new().fill(p.deep).stroke(Stroke::new(1.0_f32, p.header)).inner_margin(egui::Margin::same(6)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let dot = p.text;
            let mut layouter = |ui: &Ui, s: &str, wrap: f32| {
                let mut job = jwt_layout(s, colors, dot, 12.5);
                job.wrap.max_width = wrap;
                ui.fonts(|f| f.layout_job(job))
            };
            ui.add(egui::TextEdit::multiline(&mut app.jwt_input).id_salt("jwt_input").frame(false).desired_width(f32::INFINITY)
                .desired_rows(3).hint_text("eyJhbGciOi...").layouter(&mut layouter));
        });
        ui.horizontal(|ui| {
            for (name, c) in ["Header", "Payload", "Signature"].iter().zip(colors) {
                ui.label(RichText::new(format!("■ {name}")).size(11.5).color(c));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::plain_button(ui, p, "Clear", !app.jwt_input.is_empty()).clicked() { app.jwt_input.clear(); }
                let input = app.dec_blocks.first().map(|b| b.text.trim().to_string()).unwrap_or_default();
                if theme::plain_button(ui, p, "Use Transform input", !input.is_empty() && input != app.jwt_input.trim())
                    .on_hover_text("Inspect the text in the Transform view's first box").clicked() {
                    app.jwt_input = input;
                }
            });
        });
        ui.add_space(4.0);
        if app.jwt_input.trim().is_empty() {
            ui.label(RichText::new("No token yet. Paste one above, or right-click a request or response and choose \"Send selection to Decoder\".").color(p.disabled));
            return;
        }
        let j = match crate::codec::parse_jwt_detailed(&app.jwt_input) {
            Ok(j) => j,
            Err(e) => {
                ui.label(RichText::new(format!("Not a JWT: {e}")).color(p.high));
                return;
            }
        };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        crate::ui_settings::setting_card(ui, "Token summary", "Read from the token's header and claims. Nothing here is verified.", None, |ui| {
            egui::Grid::new("jwt_summary").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                let key = |ui: &mut Ui, k: &str| { ui.label(RichText::new(k).color(p.strong)); };
                key(ui, "Algorithm");
                match j.alg.as_deref() {
                    Some(a) if a.eq_ignore_ascii_case("none") => { ui.label(RichText::new(format!("{a} (unsigned token)")).color(p.high)); }
                    Some(a) => { ui.label(RichText::new(a).monospace().color(p.text)); }
                    None => { ui.label(RichText::new("missing").color(p.high)); }
                }
                ui.end_row();
                if let Some(t) = &j.typ { key(ui, "Type"); ui.label(RichText::new(t).color(p.text)); ui.end_row(); }
                if let Some(k) = &j.kid { key(ui, "Key ID"); ui.label(RichText::new(k).monospace().color(p.text)); ui.end_row(); }
                for (k, v) in &j.claims {
                    let name = match *k { "iss" => "Issuer (iss)", "sub" => "Subject (sub)", "aud" => "Audience (aud)", _ => "Token ID (jti)" };
                    key(ui, name);
                    ui.label(RichText::new(v).color(p.text));
                    ui.end_row();
                }
                key(ui, "Expires (exp)");
                match j.exp {
                    Some(exp) => {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(crate::codec::format_unix_utc(exp)).color(p.text));
                            let col = if exp <= now { p.high } else { p.st_done };
                            ui.label(RichText::new(crate::codec::expiry_status(exp, now)).color(col));
                        });
                    }
                    None => { ui.label(RichText::new("no expiry").color(p.disabled)); }
                }
                ui.end_row();
                if let Some(iat) = j.iat {
                    key(ui, "Issued at (iat)");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(crate::codec::format_unix_utc(iat)).color(p.text));
                        let when = if iat <= now { format!("{} ago", crate::codec::duration_words(now - iat)) } else { format!("in {} (issued in the future)", crate::codec::duration_words(iat - now)) };
                        ui.label(RichText::new(when).color(p.disabled));
                    });
                    ui.end_row();
                }
                if let Some(nbf) = j.nbf {
                    key(ui, "Not before (nbf)");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(crate::codec::format_unix_utc(nbf)).color(p.text));
                        if nbf > now {
                            ui.label(RichText::new(format!("Not valid yet (in {})", crate::codec::duration_words(nbf - now))).color(p.high));
                        }
                    });
                    ui.end_row();
                }
                key(ui, "Signature");
                let sig = if j.signature_len == 0 { "none".to_string() } else { format!("{} bytes, not verified", j.signature_len) };
                ui.label(RichText::new(sig).color(colors[2]));
                ui.end_row();
            });
        });
        ui.add_space(6.0);
        ui.columns(2, |cols| {
            json_view(&mut cols[0], p, "jwt_header", "Header", colors[0], &j.header_json);
            json_view(&mut cols[1], p, "jwt_payload", "Payload", colors[1], &j.payload_json);
        });
    });
}

// ---- Logger (picture-22) ------------------------------------------------
pub fn logger(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(8, 5)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            let mib = |n: u64| n >> 20;
            ui.label(RichText::new(format!(
                "Everything is kept in memory. Proxy: request bodies up to {} MiB; responses over {} MiB reach the browser but are recorded cut short. Tools read responses up to {} MiB.",
                mib(crate::proxy::MAX_REQUEST_BODY), mib(crate::proxy::MAX_BUFFERED), mib(crate::http::MAX_BODY))).size(11.5).color(p.text));
        });
    });
    if app.history.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
        let _ = theme::empty_state(ui, p, EmptyIcon::Logger, "Logger is empty",
            "Logger shows every HTTP request sent by the suite's tools (Proxy, Repeater, Intruder, Scanner, Sequencer) and the responses.", None);
    } else {
        traffic_view(app, ui, p, View::Logger);
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum View { SiteMap, Logger, ProxyHistory }

#[derive(Clone, Copy)]
enum ExportFormat {
    Har,
    Csv,
}

/// Pick a file and write the chosen rows to it, returning a status line to show. `None` when
/// the save dialog is dismissed.
fn run_export(fmt: ExportFormat, rows: &[crate::http::HttpEntry]) -> Option<String> {
    let (ext, name) = match fmt {
        ExportFormat::Har => ("har", "history.har"),
        ExportFormat::Csv => ("csv", "history.csv"),
    };
    let path = rfd::FileDialog::new().add_filter(ext.to_uppercase(), &[ext]).set_file_name(name).save_file()?;
    let contents = match fmt {
        ExportFormat::Har => match crate::export::to_har(rows) {
            Ok(s) => s,
            Err(e) => return Some(format!("Couldn't build HAR: {e}")),
        },
        ExportFormat::Csv => crate::export::to_csv(rows),
    };
    Some(match std::fs::write(&path, contents) {
        Ok(()) => format!("Exported {} requests to {}", rows.len(), path.display()),
        Err(e) => format!("Couldn't write {}: {e}", path.display()),
    })
}

/// The HTTP history "Export" dropdown: HAR or CSV, of the filtered rows or of everything.
fn export_bar(ui: &mut Ui, p: &Palette, filtered: &[std::sync::Arc<crate::http::HttpEntry>], all: &[std::sync::Arc<crate::http::HttpEntry>]) {
    let msg_id = egui::Id::new("history_export_msg");
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("history_export").selected_text("Export").width(90.0).show_ui(ui, |ui| {
            let options = [
                ("HAR — filtered rows...", ExportFormat::Har, false),
                ("HAR — all requests...", ExportFormat::Har, true),
                ("CSV — filtered rows...", ExportFormat::Csv, false),
                ("CSV — all requests...", ExportFormat::Csv, true),
            ];
            for (label, fmt, use_all) in options {
                if ui.selectable_label(false, label).clicked() {
                    let src = if use_all { all } else { filtered };
                    let rows: Vec<crate::http::HttpEntry> = src.iter().map(|e| (**e).clone()).collect();
                    if let Some(m) = run_export(fmt, &rows) {
                        ui.data_mut(|d| d.insert_temp(msg_id, m));
                    }
                    ui.close_menu();
                }
            }
        });
        let msg: String = ui.data(|d| d.get_temp(msg_id)).unwrap_or_default();
        if !msg.is_empty() {
            ui.label(RichText::new(msg).size(12.0).color(p.disabled));
        }
    });
}

/// Recorded traffic: a host tree + table (site map), all tools (Logger) or Proxy only
/// (HTTP history), with a search box, the selected request/response, and "Send to" actions.
pub fn traffic_view(app: &mut App, ui: &mut Ui, p: &Palette, view: View) {
    let all = app.history.lock().unwrap_or_else(|e| e.into_inner()).clone();
    // the view's rows, then those passing the ribbon's filters, sorted for display (the
    // recorded history is only read)
    let in_view: Vec<std::sync::Arc<crate::http::HttpEntry>> = all.iter().filter(|e| {
        (view != View::ProxyHistory || e.tool == "Proxy")
            && (view != View::SiteMap || app.sitemap_path.as_ref().map_or(true, |hp| &format!("{}{}", e.host, e.path) == hp))
    }).cloned().collect();
    let mut hist: Vec<std::sync::Arc<crate::http::HttpEntry>> = in_view.iter()
        .filter(|e| app.history_filter.matches(e, &app.target_scope, &app.skip_extensions)).cloned().collect();
    app.history_filter.sort(&mut hist);
    crate::ui_proxy::filter_ribbon(app, ui, p, hist.len(), in_view.len());
    if view == View::ProxyHistory {
        export_bar(ui, p, &hist, &all);
    }
    if view == View::SiteMap {
        if let Some(path) = app.sitemap_path.clone() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Showing {path}")).size(12.0).color(p.text));
                if theme::plain_button(ui, p, "Show all", true).clicked() { app.sitemap_path = None; }
            });
        }
    }
    ui.add_space(2.0);
    // right-click actions run after drawing: (entry, scope prefix)
    let mut menu_pick: Option<(std::sync::Arc<crate::http::HttpEntry>, String, crate::ui_proxy::RowAction)> = None;
    let sel_id = app.history_sel;
    let mut clicked = None;
    let selected = app.history_sel.and_then(|id| all.iter().find(|e| e.id == id)).cloned();

    // When an entry is selected, a resizable bottom pane holds the Request/Response inspector;
    // egui's resizable panel is the draggable splitter (with persisted height), and min_height
    // clamps it so neither it nor the table above can collapse. With nothing selected the table
    // fills the whole view.
    let avail = ui.available_height();
    if let Some(e) = selected {
        let mut pick = None;
        egui::TopBottomPanel::bottom(egui::Id::new(("traffic_detail", view as u8)))
            .resizable(true)
            .default_height(300.0)
            .min_height(120.0)
            // cap the panel so it can never expand past the top boundary (the table above always
            // keeps >= 120px); this also stops the inspector creeping/snapping upward when its
            // inner widgets report a larger minimum height than the dragged size
            .max_height((avail - 120.0).max(120.0))
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { top: 6, ..Default::default() }))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("#{}", e.id)).color(p.text));
                    if theme::plain_button(ui, p, "Send to Repeater", true).clicked() { actions::send_to(app, &e, actions::SendTo::Repeater); }
                    if theme::plain_button(ui, p, "Send to Intruder", true).clicked() { actions::send_to(app, &e, actions::SendTo::Intruder); }
                    if theme::plain_button(ui, p, "Send to Sequencer", true).clicked() { actions::send_to(app, &e, actions::SendTo::Sequencer); }
                    if theme::plain_button(ui, p, "Send to Comparer", true).on_hover_text("Adds the response; right-click the row or a message for the request or a selection").clicked() { actions::send_to(app, &e, actions::SendTo::Comparer); }
                    if theme::plain_button(ui, p, "Send to Organizer", true).clicked() { actions::send_to(app, &e, actions::SendTo::Organizer); }
                    if theme::plain_button(ui, p, "Copy as cURL", true).on_hover_text("Copy the request as a curl command").clicked() { ui.ctx().copy_text(actions::entry_as_curl(&e)); }
                    if theme::plain_button(ui, p, "Add host to scope", true).clicked() { actions::send_to(app, &e, actions::SendTo::Scope); }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| crate::ui_inspector::toggle_button(ui, &mut app.inspector));
                });
                let name = format!("{} #{}", actions::history_name(&e), e.id);
                // A scroll area bounds the inner available height to the panel's actual (dragged)
                // size, so the editors and the collapsible Inspector pane can't report a minimum
                // taller than the panel and force it to grow; any overflow scrolls instead.
                egui::ScrollArea::vertical().id_salt(("traffic_detail_scroll", view as u8)).auto_shrink([false, false]).show(ui, |ui| {
                    crate::ui_inspector::inspector_panel(ui, p, &mut app.inspector, "history", &e.id.to_string(), &e.request, Some(&e.response));
                    let h = (ui.available_height() - 22.0).max(120.0);
                    ui.columns(2, |cols| {
                        cols[0].label(bold("Request", 13.0).color(p.strong));
                        let out = editor::message_view(&mut cols[0], p, "tv_req", &e.request, h);
                        pick = out.menu(&e.request).map(|m| (m, format!("{name} request")));
                        cols[1].label(bold("Response", 13.0).color(p.strong));
                        let out = editor::message_view(&mut cols[1], p, "tv_resp", &e.response, h);
                        pick = pick.take().or_else(|| out.menu(&e.response).map(|m| (m, format!("{name} response"))));
                    });
                });
            });
        if let Some((m, what)) = pick {
            apply_menu_pick(app, m, &what);
        }
    }

    egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
    let table_h = ui.available_height().max(120.0);
    ui.horizontal_top(|ui| {
        if view == View::SiteMap {
            ui.vertical(|ui| {
                ui.set_width(260.0);
                theme::table_well(ui, p, table_h, |ui| {
                    let mut hosts: Vec<String> = all.iter().map(|e| e.host.clone()).collect();
                    hosts.sort();
                    hosts.dedup();
                    egui::ScrollArea::vertical().id_salt("tree").show(ui, |ui| {
                        for h in hosts {
                            let first = all.iter().find(|e| e.host == h).cloned();
                            let in_scope = first.as_ref().is_some_and(|e| app.target_scope.is_in_scope(&actions::entry_url(e)));
                            let host_col = if in_scope { p.strong } else { p.disabled };
                            let header = egui::CollapsingHeader::new(RichText::new(&h).color(host_col)).default_open(true).show(ui, |ui| {
                                let mut paths: Vec<&str> = all.iter().filter(|e| e.host == h).map(|e| e.path.as_str()).collect();
                                paths.sort();
                                paths.dedup();
                                for path in paths {
                                    let label = if path.is_empty() { "/" } else { path };
                                    let item = ui.selectable_label(app.sitemap_path.as_deref() == Some(&format!("{h}{path}")), RichText::new(label).size(12.0));
                                    if item.clicked() {
                                        app.sitemap_path = Some(format!("{h}{path}"));
                                    }
                                    if let Some(e) = all.iter().find(|e| e.host == h && e.path == path) {
                                        // a path item's scope prefix is its URL without the query
                                        let url = actions::entry_url(e);
                                        let prefix = url.split(['?', '#']).next().unwrap_or(&url).to_string();
                                        item.context_menu(|ui| {
                                            if let Some(a) = crate::ui_proxy::scope_menu_pick(ui, &app.target_scope, e, &prefix) { menu_pick = Some((e.clone(), prefix.clone(), a)); }
                                        });
                                    }
                                }
                            });
                            if let Some(e) = first {
                                let prefix = actions::scope_prefix(&e);
                                header.header_response.context_menu(|ui| {
                                    if let Some(a) = crate::ui_proxy::scope_menu_pick(ui, &app.target_scope, &e, &prefix) { menu_pick = Some((e.clone(), prefix.clone(), a)); }
                                });
                            }
                        }
                    });
                });
            });
        }
        ui.vertical(|ui| {
            theme::table_well(ui, p, table_h, |ui| {
                use crate::history::HistorySortColumn as C;
                let cols: &[(&str, f32, C)] = &[("#", 50.0, C::Id), ("Time", 72.0, C::Time), ("Tool", 80.0, C::Tool), ("Method", 70.0, C::Method), ("Host", 200.0, C::Host),
                    ("Path", 300.0, C::Path), ("Status code", 130.0, C::Status), ("Length", 80.0, C::Length), ("MIME type", 120.0, C::Mime)];
                sort_header(ui, p, cols, &mut app.history_filter);
                // only the rows in view are drawn (history can hold thousands)
                egui::ScrollArea::vertical().id_salt(("traffic", view as u8)).show_rows(ui, 19.0, hist.len(), |ui, range| {
                    for (i, e) in hist.iter().enumerate().skip(range.start).take(range.len()) {
                        let cells = [
                            (e.id.to_string(), 50.0, None),
                            (crate::history::time_of_day(e.time), 72.0, Some(p.disabled)),
                            (e.tool.clone(), 80.0, None),
                            (e.method.clone(), 70.0, Some(method_color(p, &e.method))),
                            (e.host.clone(), 200.0, None),
                            (e.path.clone(), 300.0, None),
                            (e.status.clone(), 130.0, None),
                            (e.length.to_string(), 80.0, None),
                            (e.mime.clone(), 120.0, None),
                        ];
                        let row = theme::table_row(ui, p, &cells, sel_id == Some(e.id), i % 2 == 1);
                        if row.clicked() { clicked = Some(e.id); }
                        if row.secondary_clicked() { clicked = Some(e.id); }
                        let prefix = actions::scope_prefix(e);
                        row.context_menu(|ui| {
                            if let Some(a) = crate::ui_proxy::scope_menu_pick(ui, &app.target_scope, e, &prefix) { menu_pick = Some((e.clone(), prefix.clone(), a)); }
                        });
                    }
                });
            });
        });
    });
    });
    if clicked.is_some() { app.history_sel = clicked; }
    if let Some((e, prefix, action)) = menu_pick {
        crate::ui_proxy::scope_menu_apply(app, &e, &prefix, action);
    }
}

/// The table header with each column a button: click to sort by it, again to reverse.
/// The sorted column shows a triangle (up: ascending).
fn sort_header(ui: &mut Ui, p: &Palette, cols: &[(&str, f32, crate::history::HistorySortColumn)], filter: &mut crate::history::HistoryFilter) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 21.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, p.header);
    let mut x = rect.left();
    for (i, (name, w, col)) in cols.iter().enumerate() {
        let cell = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2((x + w).min(rect.right()), rect.bottom()));
        let r = ui.interact(cell, ui.id().with(("sort_col", i)), egui::Sense::click());
        r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, *name));
        if r.hovered() {
            ui.painter().rect_filled(cell, 0.0, p.hover);
        }
        let label = ui.painter().text(egui::pos2(x + 6.0, rect.center().y), egui::Align2::LEFT_CENTER, *name, FontId::proportional(12.5), p.text);
        if filter.sort_column == Some(*col) {
            // drawn, not a glyph: the bundled fonts have no triangles
            let c = egui::pos2(label.right() + 8.0, rect.center().y);
            let pts = if filter.sort_ascending {
                vec![c + egui::vec2(-4.0, 2.5), c + egui::vec2(4.0, 2.5), c + egui::vec2(0.0, -3.0)]
            } else {
                vec![c + egui::vec2(-4.0, -2.5), c + egui::vec2(4.0, -2.5), c + egui::vec2(0.0, 3.0)]
            };
            ui.painter().add(egui::Shape::convex_polygon(pts, p.strong, egui::Stroke::NONE));
        }
        if r.on_hover_text(format!("Sort by {name}")).clicked() {
            filter.click_column(*col);
        }
        x += w;
        if i + 1 < cols.len() {
            ui.painter().line_segment([egui::pos2(x - 4.0, rect.top() + 2.0), egui::pos2(x - 4.0, rect.bottom() - 2.0)], egui::Stroke::new(1.0_f32, p.deep));
        }
    }
}

/// Carry out a message editor's right-click choice. `what` names the message for a
/// Comparer item's label ("Repeater response", "Proxy history #3 request").
pub(crate) fn apply_menu_pick(app: &mut App, m: editor::MenuPick, what: &str) {
    match m.to {
        editor::SendText::Decoder => actions::send_text_to_decoder(app, m.text),
        editor::SendText::Comparer => {
            crate::comparer::add_text(app, m.label(what), &m.text);
            app.tab = Tab::Comparer;
        }
    }
}

// ---- Organizer (picture-23) ---------------------------------------------
pub fn organizer(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::SidePanel::left("collections").resizable(true).default_width(220.0)
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(8))).show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(bold("Collections", 14.0).color(p.strong));
            });
            ui.add_space(6.0);
            ui.add(egui::TextEdit::singleline(&mut app.org_search).desired_width(f32::INFINITY).hint_text("Search address or notes"));
            ui.add_space(6.0);
            egui::Frame::new().fill(p.selection).inner_margin(egui::Margin::symmetric(8, 5)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Inbox").color(p.strong));
            });
        });
    egui::CentralPanel::default().frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(10))).show_inside(ui, |ui| {
        ui.horizontal(|ui| { ui.label(bold("Inbox", 14.0).color(p.strong)); });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut app.org_only_highlighted, "Only highlighted");
            ui.checkbox(&mut app.org_only_notes, "Only items with notes");
        });
        ui.add_space(6.0);
        if app.organizer.is_empty() {
            let _ = theme::empty_state(ui, p, EmptyIcon::Organizer, "Organizer inbox is empty",
                "To get started, send a message to Organizer from anywhere in the suite.", None);
        } else {
            let q = app.org_search.to_ascii_lowercase();
            let mut remove = None;
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("org").striped(true).num_columns(6).spacing([10.0, 4.0]).show(ui, |ui| {
                    for h in ["Status", "Highlight", "Method", "Address", "Notes", ""] {
                        ui.label(bold(h, 12.5).color(p.strong));
                    }
                    ui.end_row();
                    for (i, it) in app.organizer.iter_mut().enumerate() {
                        let ext_hidden = it.path.contains('.')
                            && it.path.rsplit('.').next().is_some_and(|e| rules::ORGANIZER_HIDE_EXTENSIONS.contains(&e));
                        if ext_hidden
                            || (!q.is_empty() && !format!("{}{} {}", it.host, it.path, it.note).to_ascii_lowercase().contains(&q))
                            || (app.org_only_highlighted && it.highlight.is_none())
                            || (app.org_only_notes && it.note.trim().is_empty())
                        {
                            continue;
                        }
                        egui::ComboBox::from_id_salt(("orgst", i)).width(100.0)
                            .selected_text(RichText::new(it.status.label()).color(it.status.color(p)))
                            .show_ui(ui, |ui| {
                                for st in crate::state::OrgStatus::ALL {
                                    ui.selectable_value(&mut it.status, st, RichText::new(st.label()).color(st.color(p)));
                                }
                            });
                        egui::ComboBox::from_id_salt(("orghl", i)).width(80.0)
                            .selected_text(it.highlight.map(|h| HIGHLIGHTS[h].0).unwrap_or("None"))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut it.highlight, None, "None");
                                for (h, (name, col)) in HIGHLIGHTS.iter().enumerate() {
                                    ui.selectable_value(&mut it.highlight, Some(h), RichText::new(*name).background_color(*col).color(Color32::BLACK));
                                }
                            });
                        ui.colored_label(method_color(p, &it.method), &it.method);
                        let addr = RichText::new(format!("{}{}", it.host, it.path));
                        ui.label(match it.highlight { Some(h) => addr.background_color(HIGHLIGHTS[h].1).color(Color32::BLACK), None => addr });
                        ui.add_sized([320.0, 20.0], egui::TextEdit::singleline(&mut it.note).hint_text("Add a note"));
                        if ui.small_button("Remove").clicked() { remove = Some(i); }
                        ui.end_row();
                    }
                });
            });
            if let Some(i) = remove { app.organizer.remove(i); }
        }
    });
}

// ---- Discover (picture-25, 26) ------------------------------------------
pub fn discover(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Frame::new().fill(p.banner).inner_margin(egui::Margin::symmetric(20, 24)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| { ui.label(bold("Getting started with ForgeProxy", 22.0).color(p.strong)); });
            ui.add_space(16.0);
            ui.columns(4, |cols| {
                let cards = [
                    ("Set the target scope", "Choose which URLs to include or ignore so testing is focused on the right parts of your application.", "1. Target > Scope: add your site's address."),
                    ("Map the website", "Open the proxy browser and click through the site; every request lands in HTTP history and the site map.", "2. Open browser, then browse the site."),
                    ("Analyze the attack surface", "Review what you've discovered: parameters, cookies, forms and the issues a scan reports.", "3. Dashboard > New scan, or read the site map."),
                    ("Test for vulnerabilities", "Send interesting requests to Repeater to change and resend them, or to Intruder to try many values.", "4. Select a request > Send to Repeater."),
                ];
                for (i, (title, body, step)) in cards.iter().enumerate() {
                    egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(12)).corner_radius(3).show(&mut cols[i], |ui| {
                        ui.set_min_height(90.0);
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(*step).monospace().size(12.0).color(p.ed_param_value));
                    });
                    cols[i].add_space(8.0);
                    cols[i].label(bold(*title, 15.0).color(p.strong));
                    cols[i].add_space(4.0);
                    cols[i].add(egui::Label::new(RichText::new(*body).size(12.0).color(p.text)).wrap());
                    cols[i].add_space(4.0);
                    if theme::plain_button(&mut cols[i], p, "Take me there", true).clicked() {
                        match i {
                            0 => { app.tab = Tab::Target; app.target_sub = 1; }
                            1 => { crate::ui_proxy::open_browser(app); app.tab = Tab::Proxy; app.proxy_sub = 1; }
                            2 => { app.tab = Tab::Dashboard; app.show_new_scan = true; }
                            _ => { app.tab = Tab::Proxy; app.proxy_sub = 1; }
                        }
                    }
                }
            });
        });
        egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(20, 14)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(bold("Keyboard shortcuts", 15.0).color(p.strong));
            egui::Grid::new("discover_keys").num_columns(4).spacing([24.0, 4.0]).show(ui, |ui| {
                for (n, (action, key)) in crate::hotkeys::LIST.iter().enumerate() {
                    ui.label(RichText::new(*action).color(p.text));
                    ui.label(RichText::new(*key).monospace().color(p.ed_header_name));
                    if n % 2 == 1 { ui.end_row(); }
                }
            });
        });
    });
}
