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
    // the two sides of the target/Host sync as they stood before this frame's edits
    let (target_before, template_before) = (app.int_target.clone(), app.int_template.clone());
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
    if intruder::host_marked(&app.int_template) {
        ui.horizontal(|ui| {
            ui.add_space(46.0);
            ui.label(RichText::new("The Host header holds payload positions, so editing the target leaves it as written.")
                .size(11.5).color(p.medium));
        });
    }
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
        let int_url = app.int_target.clone();
        let int_req = app.int_template.clone();
        attach_editor_context_menu(&out, &int_req, &int_req, app, Tab::Intruder, &int_url, &int_req, None, "Intruder request");
    });
    sync_intruder_target(app, &target_before, &template_before);
}

/// Keep the Intruder target and the request template pointing at the same host. Editing the
/// target writes the Host header; editing the template's Host header (or putting an absolute
/// URL on the request line) rewrites the target. Only one side changes per frame, so they
/// can't fight, and the target never touches a Host header carrying payload positions.
fn sync_intruder_target(app: &mut App, target_before: &str, template_before: &str) {
    if app.int_target != target_before {
        let (scheme, authority, _) = actions::url_parts(&app.int_target);
        if authority.is_empty() || intruder::host_marked(&app.int_template) {
            return;
        }
        let want = actions::host_header_value(&scheme, &authority);
        // only write when the header really says something else: rewriting it every frame
        // would fight the editor and move the caret
        if actions::host_header(&app.int_template).as_deref() != Some(want.as_str()) {
            app.int_template = actions::set_host_header(&app.int_template, &want);
        }
    } else if app.int_template != template_before {
        let clean = app.int_template.replace('§', "");
        if actions::host_header(&clean).is_some()
            || actions::request_target(&clean)
                .is_some_and(|t| t.starts_with("http://") || t.starts_with("https://"))
        {
            app.int_target = actions::resolve_target_origin(app, "", &app.int_template);
        }
    }
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
        .default_size([880.0, 480.0])
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
            use crate::intruder::IntruderSortColumn as C;
            // 150px of status: "500 Internal Server Error" fits without being cut short
            let cols: [(&str, f32, C); 5] = [("Request", 70.0, C::Request), ("Payload", 220.0, C::Payload),
                ("Status code", 170.0, C::StatusCode), ("Length", 80.0, C::Length), ("Error", 280.0, C::Error)];
            let mut row_click = None;
            let mut sort_click = None;
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
                            let (out_req, out_resp) = theme::columns(ui, 2, |cols| {
                                cols[0].label(bold("Request", 12.5).color(p.strong));
                                let req_v = editor::message_view(&mut cols[0], p, &format!("int_req_{id}"), &e.request, h);
                                cols[1].label(bold("Response", 12.5).color(p.strong));
                                let resp_v = editor::message_view(&mut cols[1], p, &format!("int_resp_{id}"), &e.response, h);
                                (req_v, resp_v)
                            });
                            let e_url = actions::entry_url(&e);
                            let e_req = actions::raw_request(&e);
                            attach_view_context_menu(&out_req, &e.request, app, Tab::Intruder, &e_url, &e_req, Some(&e.response), &format!("Intruder #{} request", e.id));
                            attach_view_context_menu(&out_resp, &e.response, app, Tab::Intruder, &e_url, &e_req, Some(&e.response), &format!("Intruder #{} response", e.id));
                        }
                        None => { ui.label(RichText::new("This request is no longer in history.").size(12.0).color(p.disabled)); }
                    });
            }
            egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
                // the results keep the order they were recorded in; only the view is sorted
                let order = app.int_sort.order(&app.int_results);
                theme::table_well(ui, p, (ui.available_height() - 4.0).max(60.0), |ui| {
                    sort_click = sort_header(ui, p, &cols, app.int_sort.sort_column, !app.int_sort.sort_desc);
                    egui::ScrollArea::vertical().id_salt("int_results").auto_shrink([false, false]).show(ui, |ui| {
                        if app.int_results.is_empty() {
                            ui.label(RichText::new("Waiting for the first response...").color(p.disabled));
                        }
                        for (i, r) in order.iter().map(|&k| &app.int_results[k]).enumerate() {
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
                                for (label, to) in traffic_context_menu_targets(Tab::Intruder) {
                                    if ui.button(label).clicked() {
                                        attack_pick = Some((id, to));
                                        ui.close_menu();
                                    }
                                    if to == actions::SendTo::Comparer {
                                        if ui.button("Send request to Comparer").clicked() {
                                            attack_pick = Some((id, actions::SendTo::ComparerRequest));
                                            ui.close_menu();
                                        }
                                        if ui.button("Send response to Comparer").clicked() {
                                            attack_pick = Some((id, actions::SendTo::Comparer));
                                            ui.close_menu();
                                        }
                                    }
                                }
                            });
                        }
                    });
                });
            });
            // clicking a row opens its detail pane (clicking it again closes it). The pane
            // follows the row's history id, so re-sorting leaves the same request open.
            if let Some(id) = row_click {
                app.int_result_sel = (app.int_result_sel != Some(id)).then_some(id);
            }
            if let Some(col) = sort_click {
                app.int_sort.click_column(col);
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
            // the buttons are laid out from the right first, so the address bar takes exactly
            // the width that is left: a fixed reservation would overflow the row, and an
            // overflowing row widens this whole Ui (pushing the Inspector off the window).
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                crate::ui_inspector::toggle_button(ui, &mut app.inspector);
                if theme::plain_button(ui, p, "Send to Sequencer", tab.can_send()).on_hover_text("Analyse the randomness of a token in this response").clicked() {
                    to_sequencer = Some((tab.url.clone(), tab.request.clone()));
                }
                if theme::plain_button(ui, p, "Copy as cURL", tab.can_send()).on_hover_text("Copy the request as a curl command").clicked() {
                    ui.ctx().copy_text(crate::export::to_curl(&tab.request, &actions::origin_of(&tab.url)));
                }
                let can_send = tab.can_send();
                let why = if tab.waiting { "Waiting for the response" } else { "Write a request first" };
                if ui.add_enabled(can_send, egui::Button::new(bold("Send", 13.0).color(Color32::WHITE)).fill(p.accent).min_size(egui::vec2(80.0, 24.0)))
                    .on_disabled_hover_text(why).clicked() {
                    send = true;
                }
                let room = (ui.available_width() - ui.spacing().item_spacing.x).max(80.0);
                ui.add(egui::TextEdit::singleline(&mut tab.url).id_salt(("rep_url", tab_id)).hint_text("https://target.example/").desired_width(room))
                    .on_hover_text(&tab.url);
            });
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
        // fixed-height header row, left-aligned, so both panes' editors start at the same y.
        // `status` (a status line or a transport error, which can be far wider than the pane)
        // is truncated to the room left over, with the whole of it on hover; `badges` (the
        // latency and the size) are laid out from the right first, so they stay visible.
        let header = |ui: &mut Ui, title: &str, status: &str, badges: &[String]| {
            ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 20.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.label(bold(title, 13.0).color(p.strong));
                if status.is_empty() {
                    return;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    for b in badges.iter().rev() {
                        ui.label(egui::RichText::new(b).size(12.0).color(p.disabled));
                    }
                    ui.add(egui::Label::new(bold(status, 13.0).color(p.strong)).truncate())
                        .on_hover_text(status);
                });
            });
            ui.add_space(4.0);
        };
        if app.repeater_tabs.get(i).is_some_and(|t| t.id == tab_id) && app.repeater_tabs[i].url != url_before {
            sync_repeater_target(&mut app.repeater_tabs[i], &url_before, &request_before);
        }
        let url_after_bar = app.repeater_tabs[i].url.clone();
        let req_after_bar = app.repeater_tabs[i].request.clone();
        let tab_url = url_after_bar.clone();
        let tab_req = req_after_bar.clone();
        let tab_resp = app.repeater_tabs[i].response.clone();
        let tab_title = app.repeater_tabs[i].title.clone();
        egui::SidePanel::right("rep_response_pane").resizable(true).default_width(width / 2.0)
            .width_range((width * 0.25)..=(width * 0.75))
            .frame(egui::Frame::new().inner_margin(egui::Margin { left: GAP, ..Default::default() }))
            .show_inside(ui, |ui| {
                let (status, badges) = response_summary(&app.repeater_tabs[i]);
                header(ui, "Response", &status, &badges);
                let h = ui.available_height() - 2.0;
                // each tab keeps its own Raw / Pretty / Hex choice
                let view_id = format!("rep_resp:{tab_id}");
                editor::set_view_mode(ui.ctx(), &view_id, app.repeater_tabs[i].view_mode);
                let text = tab_resp.as_deref().unwrap_or("");
                let out = editor::message_view(ui, p, &view_id, text, h);
                app.repeater_tabs[i].view_mode = editor::view_mode(ui.ctx(), &view_id);
                let what = format!("Repeater tab {tab_title} response");
                attach_view_context_menu(&out, text, app, Tab::Repeater, &tab_url, &tab_req, tab_resp.as_deref(), &what);
            });
        egui::CentralPanel::default().frame(egui::Frame::new().inner_margin(egui::Margin { right: GAP, ..Default::default() }))
            .show_inside(ui, |ui| {
                header(ui, "Request", "", &[]);
                let h = ui.available_height() - 2.0;
                // per-tab editor state: cursor and undo history don't leak between tabs
                let out = editor::message_editor(ui, p, &format!("rep_req:{tab_id}"), &mut app.repeater_tabs[i].request, true, false, h);
                if app.repeater_tabs.get(i).is_some_and(|t| t.id == tab_id) {
                    sync_repeater_target(&mut app.repeater_tabs[i], &url_after_bar, &req_after_bar);
                }
                let cur_url = app.repeater_tabs[i].url.clone();
                let cur_req = app.repeater_tabs[i].request.clone();
                let what = format!("Repeater tab {tab_title} request");
                attach_editor_context_menu(&out, &cur_req, &cur_req, app, Tab::Repeater, &cur_url, &cur_req, tab_resp.as_deref(), &what);
            });
    });
    if let Some((url, template)) = to_sequencer {
        actions::send_to_sequencer(app, &url, &template);
        return;
    }
    if send {
        actions::send_repeater(app);
    }
}

/// What goes next to "Response": the status line ("200 OK", "Sending...", or a transport
/// error, which can run to several hundred characters) and the badges after it ("143 ms",
/// "1.2 KiB"). They are returned apart because the header strip truncates the first and
/// keeps the others against the right edge.
fn response_summary(tab: &crate::repeater::RepeaterTab) -> (String, Vec<String>) {
    if tab.status_text.is_empty() {
        return (String::new(), Vec::new());
    }
    let mut badges = Vec::new();
    if !tab.waiting {
        if let Some(ms) = tab.response_time_ms {
            badges.push(format!("· {ms} ms"));
        }
        if let Some(b) = tab.response_bytes {
            badges.push(format!("· {}", editor::human_size(b)));
        }
    }
    (tab.status_text.clone(), badges)
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
        let (scheme, authority, path) = actions::url_parts(&tab.url);
        if !authority.is_empty() {
            let host = actions::host_header_value(&scheme, &authority);
            let request = actions::set_host_header(&tab.request, &host);
            tab.request = actions::set_request_target(&request, &path);
        }
    } else if tab.request != request_before {
        let (_, bar_auth, _) = actions::url_parts(&tab.url);
        let same_host = actions::host_header(&tab.request).is_none_or(|rh| {
            let (rh_name, _) = actions::split_host_port(&rh);
            let (bar_name, _) = actions::split_host_port(&bar_auth);
            !bar_name.is_empty()
                && rh_name.eq_ignore_ascii_case(bar_name)
                && tab.url.trim() != crate::state::DEFAULT_REP_URL
        });
        let ref_url = if same_host { tab.url.as_str() } else { "" };
        tab.url = actions::repeater_target(&tab.request, ref_url);
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

/// Format raw bytes as space-separated hex pairs (for Box 1's editable Hex view).
pub fn format_hex_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Parse formatted or unformatted hex text (e.g. `"61 64 6d"`, `"61646d"`, or hex dump lines) into bytes.
pub fn parse_hex_input(input: &str) -> Result<Vec<u8>, String> {
    let mut cleaned = String::with_capacity(input.len());
    for line in input.lines() {
        let rest = if line.len() >= 10
            && line.as_bytes()[..8].iter().all(|b| b.is_ascii_hexdigit())
            && &line[8..10] == "  "
        {
            &line[10..]
        } else {
            line
        };
        for ch in rest.chars() {
            if !ch.is_whitespace() {
                cleaned.push(ch);
            }
        }
    }
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid hex sequence".into());
    }
    if cleaned.len() % 2 != 0 {
        return Err("Invalid hex sequence (odd number of hex digits)".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut k = 0;
    while k < bytes.len() {
        let pair = std::str::from_utf8(&bytes[k..k + 2]).map_err(|_| "Invalid hex sequence".to_string())?;
        let val = u8::from_str_radix(pair, 16).map_err(|_| "Invalid hex sequence".to_string())?;
        out.push(val);
        k += 2;
    }
    Ok(out)
}

/// Re-run existing downstream Decoder stages (`1..N`) from `app.dec_raw[0]` so edits in Box 1 update live.
pub fn recompute_decoder_pipeline(app: &mut App) {
    let n = app.dec_blocks.len();
    if app.dec_raw.len() < n {
        app.dec_raw.resize(n, Vec::new());
    }
    for j in 1..n {
        let prev = app.dec_raw[j - 1].clone();
        let Some(lbl) = app.dec_blocks[j].label.clone() else { continue };
        let computed = if let Some(name) = lbl.strip_prefix("Decoded as ") {
            decoder_ops::Codec::ALL
                .iter()
                .find(|c| c.label() == name)
                .and_then(|&c| decoder_ops::decode(c, &prev))
        } else if let Some(name) = lbl.strip_prefix("Encoded as ") {
            decoder_ops::Codec::ALL
                .iter()
                .find(|c| c.label() == name)
                .map(|&c| decoder_ops::encode(c, &prev))
        } else if let Some(name) = lbl.strip_suffix(" hash") {
            decoder_ops::Hash::ALL
                .iter()
                .find(|h| h.label() == name)
                .map(|&h| decoder_ops::hash(h, &prev))
        } else if let Some(name) = lbl.strip_prefix("Smart decode: ") {
            decoder_ops::Codec::ALL
                .iter()
                .find(|c| c.label() == name)
                .and_then(|&c| decoder_ops::decode(c, &prev))
        } else {
            None
        };
        if let Some(out) = computed {
            app.dec_blocks[j].hex = std::str::from_utf8(&out).is_err();
            app.dec_blocks[j].text = String::from_utf8_lossy(&out).into_owned();
            app.dec_raw[j] = out;
        }
    }
}

/// Apply an edit to Box 1's hex input, updating `app.dec_raw[0]` and live downstream stages when valid.
pub fn apply_box1_hex_edit(app: &mut App) {
    match parse_hex_input(&app.dec_hex_input) {
        Ok(bytes) => {
            app.dec_hex_error = None;
            if app.dec_raw.is_empty() {
                app.dec_raw.push(Vec::new());
            }
            app.dec_raw[0] = bytes.clone();
            if !app.dec_blocks.is_empty() {
                app.dec_blocks[0].text = String::from_utf8_lossy(&bytes).into_owned();
            }
            recompute_decoder_pipeline(app);
        }
        Err(err) => {
            app.dec_hex_error = Some(err);
        }
    }
}

/// Confirmation message for deleting Decoder stage `idx` out of `total_stages`.
pub fn decoder_delete_message(idx: usize, total_stages: usize) -> String {
    let count = total_stages.saturating_sub(idx);
    if idx == 0 {
        "Reset Decoder? This will clear all input and remove all transformation stages.".into()
    } else if count > 1 {
        format!(
            "Delete this stage? This will also remove the {} subsequent transformation(s) below it.",
            count - 1
        )
    } else {
        "Remove this transformation stage?".into()
    }
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
    if app.dec_raw.len() < app.dec_blocks.len() {
        app.dec_raw.resize(app.dec_blocks.len(), Vec::new());
    }
    // (block whose output layers are replaced, result: new layers or why nothing came out)
    let mut action: Option<(usize, Result<Vec<(DecBlock, Vec<u8>)>, String>)> = None;
    let mut open_jwt: Option<String> = None;
    let n = app.dec_blocks.len();
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for i in 0..n {
            let is_last = i + 1 == n;
            let data = if i == 0 && !app.dec_raw[0].is_empty() && (app.dec_blocks[0].hex || String::from_utf8_lossy(&app.dec_raw[0]) == app.dec_blocks[0].text) {
                app.dec_raw[0].clone()
            } else {
                raw.data(i, &app.dec_blocks[i])
            };
            let has_input = !data.is_empty();
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - 230.0).max(200.0));
                    ui.horizontal(|ui| {
                        if let Some(lbl) = app.dec_blocks[i].label.clone() {
                            ui.label(RichText::new(lbl).size(11.0).color(app.dec_blocks[i].color));
                        } else {
                            ui.label(RichText::new("Input").size(11.0).color(p.disabled));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (btn_label, hover) = if i == 0 {
                                ("×", "Reset Decoder pipeline")
                            } else {
                                ("×", "Delete this transformation stage")
                            };
                            if ui
                                .add(
                                    egui::Button::new(RichText::new(btn_label).size(12.5).color(p.disabled))
                                        .fill(Color32::TRANSPARENT)
                                        .frame(false),
                                )
                                .on_hover_text(hover)
                                .clicked()
                            {
                                app.decoder_pending_delete = Some(i);
                            }
                        });
                    });
                    egui::Frame::new().fill(p.deep).stroke(Stroke::new(1.0_f32, p.header)).show(ui, |ui| {
                        if app.dec_blocks[i].hex {
                            if i == 0 {
                                if app.dec_hex_input.is_empty() && !data.is_empty() && app.dec_hex_error.is_none() {
                                    app.dec_hex_input = format_hex_bytes(&data);
                                }
                                if ui
                                    .add(
                                        egui::TextEdit::multiline(&mut app.dec_hex_input)
                                            .desired_rows(4)
                                            .desired_width(f32::INFINITY)
                                            .font(FontId::monospace(12.5))
                                            .frame(false)
                                            .hint_text("61 64 6d 69 6e"),
                                    )
                                    .changed()
                                {
                                    apply_box1_hex_edit(app);
                                    if app.dec_hex_error.is_none() {
                                        raw.bytes.resize(app.dec_blocks.len(), None);
                                        for (idx, b) in app.dec_raw.iter().enumerate().take(app.dec_blocks.len()) {
                                            raw.bytes[idx] = Some(b.clone());
                                        }
                                    }
                                }
                            } else {
                                let hex = hex_dump(&data);
                                let mut hex_view: &str = &hex;
                                ui.add(
                                    egui::TextEdit::multiline(&mut hex_view)
                                        .desired_rows(4)
                                        .desired_width(f32::INFINITY)
                                        .font(FontId::monospace(12.5))
                                        .frame(false),
                                );
                            }
                        } else {
                            let resp = ui.add(
                                egui::TextEdit::multiline(&mut app.dec_blocks[i].text)
                                    .desired_rows(4)
                                    .desired_width(f32::INFINITY)
                                    .font(FontId::monospace(12.5))
                                    .frame(false),
                            );
                            if i == 0 && resp.changed() {
                                let bytes = app.dec_blocks[0].text.as_bytes().to_vec();
                                app.dec_raw[0] = bytes.clone();
                                app.dec_hex_input = format_hex_bytes(&bytes);
                                app.dec_hex_error = None;
                                recompute_decoder_pipeline(app);
                                raw.bytes.resize(app.dec_blocks.len(), None);
                                for (idx, b) in app.dec_raw.iter().enumerate().take(app.dec_blocks.len()) {
                                    raw.bytes[idx] = Some(b.clone());
                                }
                            }
                        }
                    });
                    if i == 0 && app.dec_blocks[0].hex {
                        if let Some(err) = &app.dec_hex_error {
                            ui.label(RichText::new(err).size(11.5).color(p.high));
                        }
                    }
                });
                ui.vertical(|ui| {
                    let was_hex = app.dec_blocks[i].hex;
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut app.dec_blocks[i].hex, false, "Text");
                        ui.radio_value(&mut app.dec_blocks[i].hex, true, "Hex");
                    });
                    if i == 0 && !was_hex && app.dec_blocks[0].hex {
                        app.dec_hex_input = format_hex_bytes(&data);
                        app.dec_hex_error = None;
                    } else if i == 0 && was_hex && !app.dec_blocks[0].hex {
                        app.dec_hex_error = None;
                    }
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
        app.dec_raw.resize(app.dec_blocks.len(), Vec::new());
        match result {
            Ok(layers) => {
                // keep block i's exact bytes so the next layer works on them, not on lossy text
                let input = if i == 0 && !app.dec_raw[0].is_empty() && (app.dec_blocks[0].hex || String::from_utf8_lossy(&app.dec_raw[0]) == app.dec_blocks[0].text) {
                    app.dec_raw[0].clone()
                } else {
                    raw.data(i, &app.dec_blocks[i])
                };
                raw.bytes[i] = Some(input.clone());
                app.dec_raw[i] = input;
                app.dec_blocks.truncate(i + 1);
                raw.bytes.truncate(i + 1);
                app.dec_raw.truncate(i + 1);
                for (block, bytes) in layers {
                    app.dec_blocks.push(block);
                    raw.bytes.push(Some(bytes.clone()));
                    app.dec_raw.push(bytes);
                }
                raw.error = None;
            }
            Err(msg) => raw.error = Some((i, msg)),
        }
    }
    if let Some(idx) = app.decoder_pending_delete {
        let total_stages = app.dec_blocks.len();
        if idx >= total_stages {
            app.decoder_pending_delete = None;
        } else {
            let title = if idx == 0 { "Reset Decoder" } else { "Delete Transformation Stage" };
            let msg = decoder_delete_message(idx, total_stages);
            let cancel_key = ui.input(|i| i.key_pressed(egui::Key::Escape));
            let confirm_key = ui.input(|i| i.key_pressed(egui::Key::Enter));
            let mut do_cancel = cancel_key;
            let mut do_delete = confirm_key;
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ui.ctx(), |ui| {
                    ui.set_max_width(380.0);
                    ui.label(RichText::new(msg).color(p.text));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if theme::plain_button(ui, p, "Cancel", true).clicked() {
                            do_cancel = true;
                        }
                        let del_btn = egui::Button::new(bold("Delete", 12.5).color(Color32::WHITE))
                            .fill(p.high)
                            .min_size(egui::vec2(72.0, 24.0));
                        if ui.add(del_btn).clicked() {
                            do_delete = true;
                        }
                    });
                });
            if do_cancel {
                app.decoder_pending_delete = None;
            } else if do_delete {
                if idx == 0 {
                    raw.bytes.clear();
                    raw.error = None;
                } else {
                    raw.bytes.truncate(idx);
                    if raw.error.as_ref().is_some_and(|(at, _)| *at >= idx) {
                        raw.error = None;
                    }
                }
                app.confirm_decoder_delete(idx);
            }
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
        theme::columns(ui, 2, |cols| {
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
    let source_tab = match view {
        View::ProxyHistory => Tab::Proxy,
        View::Logger => Tab::Logger,
        View::SiteMap => Tab::Target,
    };
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
                    if theme::plain_button(ui, p, "Send to Decoder", true).clicked() { actions::send_to(app, &e, actions::SendTo::Decoder); }
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
                    let (out_req, out_resp) = theme::columns(ui, 2, |cols| {
                        cols[0].label(bold("Request", 13.0).color(p.strong));
                        let req_v = editor::message_view(&mut cols[0], p, "tv_req", &e.request, h);
                        cols[1].label(bold("Response", 13.0).color(p.strong));
                        let resp_v = editor::message_view(&mut cols[1], p, "tv_resp", &e.response, h);
                        (req_v, resp_v)
                    });
                    let e_url = actions::entry_url(&e);
                    let e_req = actions::raw_request(&e);
                    attach_view_context_menu(&out_req, &e.request, app, source_tab, &e_url, &e_req, Some(&e.response), &format!("{name} request"));
                    attach_view_context_menu(&out_resp, &e.response, app, source_tab, &e_url, &e_req, Some(&e.response), &format!("{name} response"));
                });
            });
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
                                            if let Some(a) = crate::ui_proxy::scope_menu_pick_for(ui, &app.target_scope, e, &prefix, source_tab) { menu_pick = Some((e.clone(), prefix.clone(), a)); }
                                        });
                                    }
                                }
                            });
                            if let Some(e) = first {
                                let prefix = actions::scope_prefix(&e);
                                header.header_response.context_menu(|ui| {
                                    if let Some(a) = crate::ui_proxy::scope_menu_pick_for(ui, &app.target_scope, &e, &prefix, source_tab) { menu_pick = Some((e.clone(), prefix.clone(), a)); }
                                });
                            }
                        }
                    });
                });
            });
        }
        ui.vertical(|ui| {
            theme::fitted_table(ui, p, ("traffic_table", view as u8), table_h, &HISTORY_COLS, |ui, w| {
                use crate::history::HistorySortColumn as C;
                let cols: &[(&str, f32, C)] = &[("#", w[0], C::Id), ("Time", w[1], C::Time), ("Tool", w[2], C::Tool), ("Method", w[3], C::Method), ("Host", w[4], C::Host),
                    ("Path", w[5], C::Path), ("Status code", w[6], C::Status), ("Length", w[7], C::Length), ("MIME type", w[8], C::Mime)];
                if let Some(col) = sort_header(ui, p, cols, app.history_filter.sort_column, app.history_filter.sort_ascending) {
                    app.history_filter.click_column(col);
                }
                // only the rows in view are drawn (history can hold thousands)
                egui::ScrollArea::vertical().id_salt(("traffic", view as u8)).show_rows(ui, 19.0, hist.len(), |ui, range| {
                    for (i, e) in hist.iter().enumerate().skip(range.start).take(range.len()) {
                        let cells = [
                            (e.id.to_string(), w[0], None),
                            (crate::history::time_of_day(e.time), w[1], Some(p.disabled)),
                            (e.tool.clone(), w[2], None),
                            (e.method.clone(), w[3], Some(method_color(p, &e.method))),
                            (e.host.clone(), w[4], None),
                            (e.path.clone(), w[5], None),
                            (e.status.clone(), w[6], None),
                            (e.length.to_string(), w[7], None),
                            (e.mime.clone(), w[8], None),
                        ];
                        let row = theme::table_row(ui, p, &cells, sel_id == Some(e.id), i % 2 == 1);
                        if row.clicked() { clicked = Some(e.id); }
                        if row.secondary_clicked() { clicked = Some(e.id); }
                        let prefix = actions::scope_prefix(e);
                        row.context_menu(|ui| {
                            if let Some(a) = crate::ui_proxy::scope_menu_pick_for(ui, &app.target_scope, e, &prefix, source_tab) { menu_pick = Some((e.clone(), prefix.clone(), a)); }
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

/// HTTP history columns, as (minimum width, share of the spare width): #, Time, Tool, Method,
/// Host, Path, Status code, Length, MIME type. Path takes all of the slack, so the row reaches
/// the right edge instead of stopping short of it and leaving the MIME column marooned in blank
/// space; below the minimums the table scrolls sideways rather than cutting the last column off.
/// Status code is wide enough for "405 Method Not Allowed", as in the Intruder results table.
const HISTORY_COLS: [(f32, f32); 9] = [(50.0, 0.0), (72.0, 0.0), (80.0, 0.0), (70.0, 0.0), (200.0, 0.0),
    (220.0, 1.0), (170.0, 0.0), (80.0, 0.0), (150.0, 0.0)];

/// The table header with each column a button: click to sort by it, again to reverse.
/// The column currently sorted on shows a triangle (up: ascending). Returns the column that
/// was clicked, if any; the caller owns the sort state, so history and Intruder share this.
fn sort_header<C: Copy + PartialEq>(ui: &mut Ui, p: &Palette, cols: &[(&str, f32, C)], active: Option<C>, ascending: bool) -> Option<C> {
    let mut clicked = None;
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
        if active == Some(*col) {
            // drawn, not a glyph: the bundled fonts have no triangles
            let c = egui::pos2(label.right() + 8.0, rect.center().y);
            let pts = if ascending {
                vec![c + egui::vec2(-4.0, 2.5), c + egui::vec2(4.0, 2.5), c + egui::vec2(0.0, -3.0)]
            } else {
                vec![c + egui::vec2(-4.0, -2.5), c + egui::vec2(4.0, -2.5), c + egui::vec2(0.0, 3.0)]
            };
            ui.painter().add(egui::Shape::convex_polygon(pts, p.strong, egui::Stroke::NONE));
        }
        if r.on_hover_text(format!("Sort by {name}")).clicked() {
            clicked = Some(*col);
        }
        x += w;
        if i + 1 < cols.len() {
            ui.painter().line_segment([egui::pos2(x - 4.0, rect.top() + 2.0), egui::pos2(x - 4.0, rect.bottom() - 2.0)], egui::Stroke::new(1.0_f32, p.deep));
        }
    }
    clicked
}

/// Carry out a message editor's right-click choice. `what` names the message for a
/// Comparer item's label ("Repeater response", "Proxy history #3 request").
#[allow(dead_code)]
pub(crate) fn apply_menu_pick(app: &mut App, m: editor::MenuPick, what: &str) {
    match m.to {
        editor::SendText::Decoder => actions::send_text_to_decoder(app, m.text),
        editor::SendText::Comparer => {
            crate::comparer::add_text(app, m.label(what), &m.text);
            app.tab = Tab::Comparer;
        }
    }
}

/// Standard inter-tool routing targets offered in traffic context menus, excluding the calling tool (`source_tab`).
pub fn traffic_context_menu_targets(source_tab: Tab) -> Vec<(&'static str, actions::SendTo)> {
    use actions::SendTo;
    let all = [
        ("Send to Repeater", Tab::Repeater, SendTo::Repeater),
        ("Send to Intruder", Tab::Intruder, SendTo::Intruder),
        ("Send to Sequencer", Tab::Sequencer, SendTo::Sequencer),
        ("Send to Comparer", Tab::Comparer, SendTo::Comparer),
        ("Send to Decoder", Tab::Decoder, SendTo::Decoder),
        ("Send to Organizer", Tab::Organizer, SendTo::Organizer),
    ];
    all.into_iter()
        .filter(|(_, tab, _)| *tab != source_tab)
        .map(|(label, _, to)| (label, to))
        .collect()
}

/// Centralized traffic context menu for HTTP message editors, viewers, and traffic rows.
/// Hides any redundant link to `source_tab` (e.g. hides "Send to Repeater" when inside Repeater).
#[allow(clippy::too_many_arguments)]
pub fn show_traffic_context_menu(
    ui: &mut Ui,
    app: &mut App,
    source_tab: Tab,
    url: &str,
    request: &str,
    response: Option<&str>,
    active_text: &str,
    selection: Option<&str>,
    label: &str,
) {
    let sel = selection.filter(|s| !s.is_empty());
    let has_req = !request.trim().is_empty();
    let payload_text = sel.unwrap_or(if !active_text.is_empty() { active_text } else { request });

    for (btn_label, to) in traffic_context_menu_targets(source_tab) {
        match to {
            actions::SendTo::Repeater => {
                if ui.add_enabled(has_req, egui::Button::new(btn_label)).clicked() {
                    let method = actions::request_method(request).unwrap_or_else(|| "GET".to_string());
                    actions::send_to_repeater(app, &method, url, request);
                    ui.close_menu();
                }
            }
            actions::SendTo::Intruder => {
                if ui.add_enabled(has_req, egui::Button::new(btn_label)).clicked() {
                    actions::send_to_intruder(app, url, request);
                    ui.close_menu();
                }
            }
            actions::SendTo::Sequencer => {
                if ui.add_enabled(has_req, egui::Button::new(btn_label)).clicked() {
                    actions::send_to_sequencer(app, url, request);
                    ui.close_menu();
                }
            }
            actions::SendTo::Comparer => {
                if ui.button(btn_label).clicked() {
                    let item_label = match sel {
                        Some(s) => format!("{label} selection ({} bytes)", s.len()),
                        None => label.to_string(),
                    };
                    crate::comparer::add(app, item_label, payload_text.as_bytes());
                    app.tab = Tab::Comparer;
                    ui.close_menu();
                }
            }
            actions::SendTo::Decoder => {
                if ui.button(btn_label).clicked() {
                    actions::send_text_to_decoder(app, payload_text.to_string());
                    ui.close_menu();
                }
            }
            actions::SendTo::Organizer => {
                if ui.add_enabled(has_req, egui::Button::new(btn_label)).clicked() {
                    actions::send_to_organizer(app, url, request, response.unwrap_or(""));
                    ui.close_menu();
                }
            }
            _ => {}
        }
    }
    ui.separator();
    if let Some(s) = sel {
        if ui.button("Copy selection").clicked() {
            ui.ctx().copy_text(s.to_string());
            ui.close_menu();
        }
    }
    if !active_text.is_empty() && ui.button("Copy message").on_hover_text("Exactly as received, whatever the view").clicked() {
        ui.ctx().copy_text(active_text.to_string());
        ui.close_menu();
    }
    if has_req && ui.button("Copy as cURL").on_hover_text("Copy the request as a curl command").clicked() {
        let full_url = actions::repeater_target(request, url);
        ui.ctx().copy_text(crate::export::to_curl(request, &actions::origin_of(&full_url)));
        ui.close_menu();
    }
}

/// Attach [`show_traffic_context_menu`] to an [`editor::message_editor`] output while preserving
/// right-click text selections and feeding the Inspector's Auto-Decoder.
#[allow(clippy::too_many_arguments)]
pub fn attach_editor_context_menu(
    out: &egui::text_edit::TextEditOutput,
    shown: &str,
    raw_active: &str,
    app: &mut App,
    source_tab: Tab,
    url: &str,
    request: &str,
    response: Option<&str>,
    label: &str,
) {
    let selection = editor::prepare_context_menu(out, shown);
    out.response.context_menu(|ui| {
        show_traffic_context_menu(ui, app, source_tab, url, request, response, raw_active, selection.as_deref(), label);
    });
}

/// Attach [`show_traffic_context_menu`] to an [`editor::MessageView`] output while preserving
/// right-click text selections in Raw, Pretty, or Hex mode.
#[allow(clippy::too_many_arguments)]
pub fn attach_view_context_menu(
    view: &editor::MessageView,
    raw_active: &str,
    app: &mut App,
    source_tab: Tab,
    url: &str,
    request: &str,
    response: Option<&str>,
    label: &str,
) {
    attach_editor_context_menu(&view.out, view.shown_text(raw_active), raw_active, app, source_tab, url, request, response, label);
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
    let sel_item = app.org_sel.and_then(|i| app.organizer.get(i).cloned().map(|it| (i, it)));
    if let Some((sel_idx, it)) = sel_item {
        let item_url = actions::org_item_url(&it);
        let item_req = actions::org_item_request(&it);
        let item_resp = it.response.clone();
        egui::TopBottomPanel::bottom("org_detail")
            .resizable(true)
            .default_height(240.0)
            .min_height(100.0)
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { top: 6, ..Default::default() }))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(bold(format!("{} {}{}", it.method, it.host, it.path), 12.5).color(p.strong));
                    if theme::plain_button(ui, p, "Send to Repeater", true).clicked() {
                        actions::send_to_repeater(app, &it.method, &item_url, &item_req);
                    }
                    if theme::plain_button(ui, p, "Send to Intruder", true).clicked() {
                        actions::send_to_intruder(app, &item_url, &item_req);
                    }
                    if theme::plain_button(ui, p, "Send to Sequencer", true).clicked() {
                        actions::send_to_sequencer(app, &item_url, &item_req);
                    }
                    if theme::plain_button(ui, p, "Send to Comparer", true).clicked() {
                        let data = if !item_resp.is_empty() { item_resp.as_bytes() } else { item_req.as_bytes() };
                        crate::comparer::add(app, format!("Organizer #{sel_idx}"), data);
                        app.tab = Tab::Comparer;
                    }
                    if theme::plain_button(ui, p, "Send to Decoder", true).clicked() {
                        actions::send_text_to_decoder(app, item_req.clone());
                    }
                });
                let h = (ui.available_height() - 22.0).max(80.0);
                let (out_req, out_resp) = theme::columns(ui, 2, |cols| {
                    cols[0].label(bold("Request", 12.5).color(p.strong));
                    let req_v = editor::message_view(&mut cols[0], p, &format!("org_req_{sel_idx}"), &item_req, h);
                    cols[1].label(bold("Response", 12.5).color(p.strong));
                    let resp_v = editor::message_view(&mut cols[1], p, &format!("org_resp_{sel_idx}"), &item_resp, h);
                    (req_v, resp_v)
                });
                attach_view_context_menu(&out_req, &item_req, app, Tab::Organizer, &item_url, &item_req, Some(&item_resp), &format!("Organizer #{sel_idx} request"));
                attach_view_context_menu(&out_resp, &item_resp, app, Tab::Organizer, &item_url, &item_req, Some(&item_resp), &format!("Organizer #{sel_idx} response"));
            });
    }
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
                    let len = app.organizer.len();
                    for i in 0..len {
                        let (ext_hidden, matches_filter, item_url, item_req, item_resp, method, host, path, highlight) = {
                            let it = &app.organizer[i];
                            let ext_hidden = it.path.contains('.')
                                && it.path.rsplit('.').next().is_some_and(|e| rules::ORGANIZER_HIDE_EXTENSIONS.contains(&e));
                            let matches_filter = (q.is_empty() || format!("{}{} {}", it.host, it.path, it.note).to_ascii_lowercase().contains(&q))
                                && (!app.org_only_highlighted || it.highlight.is_some())
                                && (!app.org_only_notes || !it.note.trim().is_empty());
                            (
                                ext_hidden,
                                matches_filter,
                                actions::org_item_url(it),
                                actions::org_item_request(it),
                                it.response.clone(),
                                it.method.clone(),
                                it.host.clone(),
                                it.path.clone(),
                                it.highlight,
                            )
                        };
                        if ext_hidden || !matches_filter {
                            continue;
                        }
                        {
                            let it = &mut app.organizer[i];
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
                        }
                        let m_resp = ui.add(egui::Label::new(RichText::new(&method).color(method_color(p, &method))).sense(egui::Sense::click()));
                        let addr = RichText::new(format!("{host}{path}"));
                        let addr_styled = match highlight { Some(h) => addr.background_color(HIGHLIGHTS[h].1).color(Color32::BLACK), None => addr };
                        let a_resp = ui.add(egui::Label::new(addr_styled).sense(egui::Sense::click()));
                        if m_resp.clicked() || a_resp.clicked() {
                            app.org_sel = if app.org_sel == Some(i) { None } else { Some(i) };
                        }
                        let row_label = format!("Organizer #{i} ({method} {host}{path})");
                        m_resp.context_menu(|ui| {
                            show_traffic_context_menu(ui, app, Tab::Organizer, &item_url, &item_req, Some(&item_resp), &item_req, None, &row_label);
                        });
                        a_resp.context_menu(|ui| {
                            show_traffic_context_menu(ui, app, Tab::Organizer, &item_url, &item_req, Some(&item_resp), &item_req, None, &row_label);
                        });
                        ui.add_sized([320.0, 20.0], egui::TextEdit::singleline(&mut app.organizer[i].note).hint_text("Add a note"));
                        if ui.small_button("Remove").clicked() { remove = Some(i); }
                        ui.end_row();
                    }
                });
            });
            if let Some(i) = remove {
                app.organizer.remove(i);
                if app.org_sel == Some(i) {
                    app.org_sel = None;
                } else if let Some(sel) = app.org_sel {
                    if sel > i {
                        app.org_sel = Some(sel - 1);
                    }
                }
            }
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
            theme::columns(ui, 4, |cols| {
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
        let items: Vec<std::sync::Arc<crate::http::HttpEntry>> = app.history.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if !items.is_empty() {
            let mut menu_pick: Option<(std::sync::Arc<crate::http::HttpEntry>, String, crate::ui_proxy::RowAction)> = None;
            egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(20, 14)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(bold("Discovered items", 15.0).color(p.strong));
                ui.add_space(6.0);
                theme::table_well(ui, p, 180.0, |ui| {
                    theme::table_header(ui, p, &[("#", 50.0), ("Method", 70.0), ("Host", 200.0), ("Path", 300.0), ("Status", 120.0)]);
                    egui::ScrollArea::vertical().id_salt("discover_items").show(ui, |ui| {
                        for (i, e) in items.iter().enumerate() {
                            let cells = [
                                (e.id.to_string(), 50.0, None),
                                (e.method.clone(), 70.0, Some(method_color(p, &e.method))),
                                (e.host.clone(), 200.0, None),
                                (e.path.clone(), 300.0, None),
                                (e.status.clone(), 120.0, None),
                            ];
                            let row = theme::table_row(ui, p, &cells, app.discover_sel == Some(e.id), i % 2 == 1);
                            if row.clicked() || row.secondary_clicked() {
                                app.discover_sel = Some(e.id);
                            }
                            let prefix = actions::scope_prefix(e);
                            row.context_menu(|ui| {
                                if let Some(a) = crate::ui_proxy::scope_menu_pick_for(ui, &app.target_scope, e, &prefix, Tab::Discover) {
                                    menu_pick = Some((e.clone(), prefix.clone(), a));
                                }
                            });
                        }
                    });
                });
                if let Some(e) = app.discover_sel.and_then(|id| items.iter().find(|e| e.id == id)).cloned() {
                    ui.add_space(8.0);
                    let (out_req, out_resp) = theme::columns(ui, 2, |cols| {
                        cols[0].label(bold("Request", 12.5).color(p.strong));
                        let req_v = editor::message_view(&mut cols[0], p, "disc_req", &e.request, 140.0);
                        cols[1].label(bold("Response", 12.5).color(p.strong));
                        let resp_v = editor::message_view(&mut cols[1], p, "disc_resp", &e.response, 140.0);
                        (req_v, resp_v)
                    });
                    let e_url = actions::entry_url(&e);
                    let e_req = actions::raw_request(&e);
                    attach_view_context_menu(&out_req, &e.request, app, Tab::Discover, &e_url, &e_req, Some(&e.response), &format!("Discovered #{} request", e.id));
                    attach_view_context_menu(&out_resp, &e.response, app, Tab::Discover, &e_url, &e_req, Some(&e.response), &format!("Discovered #{} response", e.id));
                }
            });
            if let Some((e, prefix, action)) = menu_pick {
                crate::ui_proxy::scope_menu_apply(app, &e, &prefix, action);
            }
        }
    });
}

#[cfg(test)]
mod intruder_sync_tests {
    use super::sync_intruder_target;
    use crate::state::App;
    use crate::test_utils::{assert_table, MockAppBuilder};

    const REQ: &str = "GET /a HTTP/1.1\r\nHost: shop.test\r\nAccept: */*\r\n\r\n";

    fn app(target: &str, template: &str) -> App {
        MockAppBuilder::default()
            .with_intruder_target(target)
            .with_intruder_template(template)
            .build_with_ctx()
            .1
    }

    struct SyncCase<'a> {
        name: &'a str,
        /// What the two sides said before this frame...
        target_before: &'a str,
        template_before: &'a str,
        /// ...and what they say after the user typed in one of them.
        target: &'a str,
        template: &'a str,
        want_target: &'a str,
        want_template: &'a str,
    }

    /// The target and the Host header follow each other both ways. Each case edits one side
    /// and says what both should read afterwards.
    #[test]
    fn target_and_host_header_follow_each_other_matrix() {
        let no_host = "GET /a HTTP/1.1\r\nAccept: */*\r\n\r\nbody";
        let marked = "GET /a HTTP/1.1\r\nHost: §shop.test§\r\nAccept: */*\r\n\r\n";
        let part_marked = "GET /a HTTP/1.1\r\nHost: §sub§.shop.test\r\nAccept: */*\r\n\r\n";
        let marked_name = "GET /a HTTP/1.1\r\n§Host§: shop.test\r\nAccept: */*\r\n\r\n";

        let cases = [
            SyncCase {
                name: "a new target host rewrites the Host header",
                target_before: "http://shop.test", template_before: REQ,
                target: "http://api.shop.test", template: REQ,
                want_target: "http://api.shop.test",
                want_template: "GET /a HTTP/1.1\r\nHost: api.shop.test\r\nAccept: */*\r\n\r\n",
            },
            SyncCase {
                name: "a non-standard port joins the Host header",
                target_before: "http://shop.test", template_before: REQ,
                target: "http://shop.test:8080", template: REQ,
                want_target: "http://shop.test:8080",
                want_template: "GET /a HTTP/1.1\r\nHost: shop.test:8080\r\nAccept: */*\r\n\r\n",
            },
            SyncCase {
                name: "8443 over https joins it too",
                target_before: "http://shop.test", template_before: REQ,
                target: "https://shop.test:8443", template: REQ,
                want_target: "https://shop.test:8443",
                want_template: "GET /a HTTP/1.1\r\nHost: shop.test:8443\r\nAccept: */*\r\n\r\n",
            },
            SyncCase {
                name: "the default port for the scheme is left off (https:443)",
                target_before: "http://shop.test", template_before: REQ,
                target: "https://other.test:443", template: REQ,
                want_target: "https://other.test:443",
                want_template: "GET /a HTTP/1.1\r\nHost: other.test\r\nAccept: */*\r\n\r\n",
            },
            SyncCase {
                name: "and for http:80, which the header already says, so nothing is written",
                target_before: "http://shop.test", template_before: REQ,
                target: "http://shop.test:80", template: REQ,
                want_target: "http://shop.test:80",
                want_template: REQ,
            },
            SyncCase {
                name: "a template with no Host header gains one after the request line",
                target_before: "http://shop.test", template_before: no_host,
                target: "http://api.shop.test:8080", template: no_host,
                want_target: "http://api.shop.test:8080",
                want_template: "GET /a HTTP/1.1\r\nHost: api.shop.test:8080\r\nAccept: */*\r\n\r\nbody",
            },
            SyncCase {
                name: "an emptied target is not written into the Host header",
                target_before: "http://shop.test", template_before: REQ,
                target: "", template: REQ,
                want_target: "", want_template: REQ,
            },
            SyncCase {
                name: "editing the Host header moves the target",
                target_before: "http://shop.test", template_before: REQ,
                target: "http://shop.test",
                template: "GET /a HTTP/1.1\r\nHost: other.test\r\nAccept: */*\r\n\r\n",
                want_target: "http://other.test",
                want_template: "GET /a HTTP/1.1\r\nHost: other.test\r\nAccept: */*\r\n\r\n",
            },
            SyncCase {
                name: "a port in the Host header moves the target to it",
                target_before: "http://shop.test", template_before: REQ,
                target: "http://shop.test",
                template: "GET /a HTTP/1.1\r\nHost: other.test:8443\r\nAccept: */*\r\n\r\n",
                want_target: "http://other.test:8443",
                want_template: "GET /a HTTP/1.1\r\nHost: other.test:8443\r\nAccept: */*\r\n\r\n",
            },
            SyncCase {
                name: "a Host header that is one payload position is left as written",
                target_before: "http://shop.test", template_before: marked,
                target: "http://api.shop.test", template: marked,
                want_target: "http://api.shop.test", want_template: marked,
            },
            SyncCase {
                name: "so is one that is only partly marked",
                target_before: "http://shop.test", template_before: part_marked,
                target: "http://api.shop.test", template: part_marked,
                want_target: "http://api.shop.test", want_template: part_marked,
            },
            SyncCase {
                name: "and one whose field name is the position",
                target_before: "http://shop.test", template_before: marked_name,
                target: "http://api.shop.test", template: marked_name,
                want_target: "http://api.shop.test", want_template: marked_name,
            },
            SyncCase {
                name: "with neither side edited, neither side moves",
                target_before: "http://shop.test", template_before: REQ,
                target: "http://shop.test", template: REQ,
                want_target: "http://shop.test", want_template: REQ,
            },
        ];

        assert_table!(cases, |idx, case| {
            let mut app = app(case.target, case.template);
            sync_intruder_target(&mut app, case.target_before, case.template_before);
            assert_eq!(app.int_target, case.want_target, "case #{idx} ({}) target", case.name);
            assert_eq!(app.int_template, case.want_template, "case #{idx} ({}) template", case.name);
        });
    }

    /// A target edit must not disturb the payload positions: not their number, and not where
    /// they sit, since every position after a moved marker would be filled from the wrong text.
    #[test]
    fn a_target_edit_leaves_payload_positions_where_they_were() {
        let templates = [
            "GET /a?id=§1§ HTTP/1.1\r\nHost: §shop.test§\r\nAccept: */*\r\n\r\n",
            "GET /a?id=§1§ HTTP/1.1\r\nHost: §sub§.shop.test\r\nCookie: s=§abc§\r\n\r\n",
            "POST /a HTTP/1.1\r\n§Host§: shop.test\r\n\r\nname=§v§",
        ];

        assert_table!(templates, |idx, template| {
            let before: Vec<usize> = template.char_indices().filter(|(_, c)| *c == '§').map(|(i, _)| i).collect();
            let mut app = app("https://moved.test:8443", template);
            sync_intruder_target(&mut app, "http://shop.test", template);
            let after: Vec<usize> = app.int_template.char_indices().filter(|(_, c)| *c == '§').map(|(i, _)| i).collect();
            assert_eq!(app.int_template, template, "case #{idx}: the template is untouched");
            assert_eq!(before, after, "case #{idx}: every marker is still at the same byte offset");
            assert_eq!(
                crate::intruder::count_positions(&app.int_template),
                crate::intruder::count_positions(template),
                "case #{idx}: the same number of payload positions"
            );
        });
    }

    /// Repeater writes the Host header by the same rule, so the two tools agree about ports.
    #[test]
    fn repeater_host_header_follows_the_same_port_rule() {
        let cases: [(&str, &str, &str, &str); 4] = [
            ("a non-standard port is sent", "http://shop.test:8080/a", "shop.test:8080", "/a"),
            ("http on 80 sends the bare host", "http://shop.test:80/a", "shop.test", "/a"),
            ("https on 443 sends the bare host", "https://shop.test:443/b", "shop.test", "/b"),
            ("no port at all sends the bare host", "https://shop.test/b", "shop.test", "/b"),
        ];

        assert_table!(cases, |idx, (name, url, want_host, want_path)| {
            let (_ctx, mut app) = MockAppBuilder::default()
                .with_repeater_tab("GET", "http://shop.test/a", "GET /a HTTP/1.1\r\nHost: shop.test\r\n\r\n")
                .build_with_ctx();
            let before = app.repeater_tabs[0].clone();
            app.repeater_tabs[0].url = url.to_string();
            super::sync_repeater_target(&mut app.repeater_tabs[0], &before.url, &before.request);
            let req = &app.repeater_tabs[0].request;
            assert_eq!(crate::actions::host_header(req).as_deref(), Some(want_host), "case #{idx} ({name}) Host header");
            assert_eq!(crate::actions::request_target(req).as_deref(), Some(want_path), "case #{idx} ({name}) request line");
        });
    }
}

#[cfg(test)]
mod sort_header_tests {
    use super::*;
    use crate::intruder::IntruderSortColumn as C;
    use crate::test_utils::assert_table;

    /// The Intruder results header, as the attack window lays it out.
    const COLS: [(&str, f32, C); 5] = [("Request", 70.0, C::Request), ("Payload", 220.0, C::Payload),
        ("Status code", 170.0, C::StatusCode), ("Length", 80.0, C::Length), ("Error", 280.0, C::Error)];

    /// Draw the header twice and click `x` pixels into it on the second pass: the first pass
    /// registers the column rects, the second lands a press and a release on them. Returns the
    /// column `sort_header` reports as clicked.
    fn click_header(x: f32) -> Option<C> {
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1000.0, 600.0));
        // (where the header was drawn, which column the click landed on)
        let frame = |events: Vec<egui::Event>| {
            let (mut origin, mut clicked) = (egui::Pos2::ZERO, None);
            let input = egui::RawInput { screen_rect: Some(screen), events, ..Default::default() };
            let _ = ctx.run(input, |ctx| {
                crate::theme::apply(ctx, crate::theme::Look::Dark);
                egui::CentralPanel::default().show(ctx, |ui| {
                    origin = ui.cursor().min;
                    clicked = sort_header(ui, &crate::theme::DARK, &COLS, Some(C::Request), true);
                });
            });
            (origin, clicked)
        };
        let (origin, _) = frame(Vec::new());
        let pos = origin + egui::vec2(x, 10.0);
        let (_, clicked) = frame(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed: true, modifiers: egui::Modifiers::NONE },
            egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed: false, modifiers: egui::Modifiers::NONE },
        ]);
        clicked
    }

    /// A status cell draws its text into `width - 8` pixels and clips the rest, so the column
    /// has to be wider than the longest phrase that routinely lands in it. The two in the brief
    /// ("405 Method Not Allowed", "500 Internal Server Error") are the widest of them. All
    /// three tables that show a status -- Intruder results, HTTP history and the site map --
    /// are checked against the same phrases.
    #[test]
    fn standard_status_phrases_fit_the_status_column() {
        let width = COLS[2].1.min(HISTORY_COLS[6].0).min(crate::ui_target::SITE_MAP_COLS[5].0) - 8.0;
        let ctx = egui::Context::default();
        // fonts installed by a pass of their own: a new set only takes effect the pass after
        let _ = ctx.run(egui::RawInput::default(), |ctx| crate::theme::install_fonts(ctx));
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            let phrases = ["200 OK", "404 Not Found", "403 Forbidden", "301 Moved Permanently",
                "405 Method Not Allowed", "500 Internal Server Error", "503 Service Unavailable", "Status code"];
            assert_table!(phrases, |idx, phrase| {
                let drawn = ctx.fonts(|f| f.layout_no_wrap(phrase.to_string(), FontId::proportional(12.5), Color32::WHITE).rect.width());
                assert!(drawn <= width, "case #{idx} ({phrase}): {drawn:.1}px of text in a {width:.1}px cell");
            });
        });
    }

    /// The last column has no slack to grow into, so it carries its own room: "application/
    /// javascript" has to read in full rather than stopping mid-word at the table's edge.
    #[test]
    fn common_mime_types_fit_the_last_history_column() {
        let width = HISTORY_COLS[8].0 - 8.0;
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| crate::theme::install_fonts(ctx));
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            let types = ["text/html", "application/json", "application/javascript", "image/svg+xml", "text/css", "MIME type"];
            assert_table!(types, |idx, mime| {
                let drawn = ctx.fonts(|f| f.layout_no_wrap(mime.to_string(), FontId::proportional(12.5), Color32::WHITE).rect.width());
                assert!(drawn <= width, "case #{idx} ({mime}): {drawn:.1}px of text in a {width:.1}px cell");
            });
        });
    }

    /// Every header cell is a button, and it is the column under the pointer that gets sorted:
    /// the cells are laid out end to end at their declared widths, so a click is placed by
    /// adding them up.
    #[test]
    fn clicking_a_header_cell_reports_that_column() {
        let cases: [(&str, f32, Option<C>); 7] = [
            ("the first column starts at the left edge", 10.0, Some(C::Request)),
            ("Payload spans 70..290", 100.0, Some(C::Payload)),
            ("Status code spans 290..460", 300.0, Some(C::StatusCode)),
            ("its widened right edge is still Status code", 455.0, Some(C::StatusCode)),
            ("Length spans 460..540", 480.0, Some(C::Length)),
            ("Error spans 540..820", 600.0, Some(C::Error)),
            ("past the last column nothing is sorted", 900.0, None),
        ];
        assert_table!(cases, |idx, (what, x, want)| {
            assert_eq!(click_header(x), want, "case #{idx} ({what})");
        });
    }
}
