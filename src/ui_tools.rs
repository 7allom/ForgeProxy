//! The thirteen tool screens, each matching its reference screenshot's default state.

use crate::actions;
use crate::decoder_ops;
use crate::editor;
use crate::intruder::{self, AttackType};
use crate::issue_defs;
use crate::state::{App, DecBlock, Tab};
use crate::theme::{self, bold, EmptyIcon, Palette};
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
                "rules match on protocol, host, port and file; host, port and file are regular expressions, and an empty one matches anything"
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
            let advanced = app.target_scope.advanced;
            crate::ui_settings::setting_card(ui, title, desc, Some("Project setting"), |ui| {
                if advanced { advanced_scope_list(app, ui, p, exclude) } else { scope_list(app, ui, p, exclude) }
            });
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

/// Inline editor for adding (index None) or editing an advanced scope rule.
#[derive(Clone, Default)]
struct AdvancedScopeEdit {
    index: Option<usize>,
    protocol: crate::scope::ScopeProtocol,
    host: String,
    port: String,
    file: String,
    error: String,
}

/// One advanced scope list: Add/Edit/Remove strip, the four-part rule table, and the editor.
/// Each of Host, Port and File is a regular expression, and an empty one matches anything.
fn advanced_scope_list(app: &mut App, ui: &mut Ui, p: &Palette, exclude: bool) {
    use crate::scope::{ScopeProtocol, ScopeRule};
    let edit_id = egui::Id::new(("scope_edit_advanced", exclude));
    let mut edit: Option<AdvancedScopeEdit> = ui.data(|d| d.get_temp(edit_id));
    let len = if exclude { app.target_scope.exclude.len() } else { app.target_scope.include.len() };
    let sel = app.scope_sel.filter(|s| s.0 == exclude && s.1 < len).map(|s| s.1);
    let mut remove = None;
    let of = |r: &ScopeRule| AdvancedScopeEdit {
        index: None,
        protocol: r.protocol,
        host: r.host.clone(),
        port: r.port.clone(),
        file: r.file.clone(),
        error: String::new(),
    };
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            if theme::side_button(ui, p, "Add", true).clicked() {
                edit = Some(AdvancedScopeEdit::default());
            }
            if theme::side_button(ui, p, "Edit", sel.is_some()).clicked() {
                if let Some(i) = sel {
                    let list = if exclude { &app.target_scope.exclude } else { &app.target_scope.include };
                    edit = Some(AdvancedScopeEdit { index: Some(i), ..of(&list[i]) });
                }
            }
            if theme::side_button(ui, p, "Remove", sel.is_some()).clicked() { remove = sel; }
        });
        // Enabled, Protocol, Host, Port, File
        const COLS: [(f32, f32); 5] = [(70.0, 0.0), (80.0, 0.0), (180.0, 0.4), (70.0, 0.0), (180.0, 0.6)];
        theme::fitted_table(ui, p, ("scope_table_advanced", exclude), 19.0 * 5.0 + 6.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Enabled", w[0]), ("Protocol", w[1]), ("Host", w[2]), ("Port", w[3]), ("File", w[4])]);
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
                if ui.put(egui::Rect::from_min_size(egui::pos2(rect.left() + 8.0, rect.center().y - 7.0), egui::vec2(14.0, 14.0)), egui::Checkbox::without_text(&mut en)).changed() {
                    list[i].enabled = en;
                }
                let bad = list[i].bad_patterns();
                // a rule that names no part at all still matches on its prefix, the way
                // advanced rules did before they had parts; the table says so rather than
                // showing four empty cells that look like "matches everything"
                let fallback = (!list[i].has_parts()).then(|| list[i].prefix.clone());
                let cells: [(String, Option<&str>); 4] = match &fallback {
                    Some(prefix) => [(format!("whole URL: {prefix}"), None), (String::new(), None), (String::new(), None), (String::new(), None)],
                    None => [
                        (list[i].protocol.label().to_string(), None),
                        (list[i].host.clone(), Some("Host")),
                        (list[i].port.clone(), Some("Port")),
                        (list[i].file.clone(), Some("File")),
                    ],
                };
                let mut x = rect.left() + 6.0 + w[0];
                for (cell, (text, field)) in cells.iter().enumerate() {
                    let width = if fallback.is_some() && cell == 0 { w[1] + w[2] + w[3] + w[4] } else { w[cell + 1] };
                    let shown = if text.is_empty() && fallback.is_none() && cell > 0 { "any" } else { text.as_str() };
                    let colour = match field {
                        // an expression that will not compile matches nothing: say so in red
                        Some(name) if bad.contains(name) => p.high,
                        _ if shown == "any" => p.disabled,
                        _ => p.text,
                    };
                    let clip = egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(x + width - 8.0, rect.bottom()));
                    ui.painter().with_clip_rect(clip).text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, shown, egui::FontId::monospace(12.0), colour);
                    x += width;
                }
                if resp.clicked() { app.scope_sel = Some((exclude, i)); }
                if resp.double_clicked() { edit = Some(AdvancedScopeEdit { index: Some(i), ..of(&list[i]) }); }
            }
        });
    });
    // one line naming every rule the engine cannot use, so a typo is not silently inert
    let list = if exclude { &app.target_scope.exclude } else { &app.target_scope.include };
    let broken: Vec<String> = list
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            let bad = r.bad_patterns();
            (!bad.is_empty()).then(|| format!("rule {} ({})", i + 1, bad.join(", ")))
        })
        .collect();
    if !broken.is_empty() {
        ui.label(RichText::new(format!("Not a valid regular expression in {}. A pattern that will not compile matches nothing.", broken.join("; ")))
            .size(12.0).color(p.high));
    }
    if let Some(i) = remove {
        if exclude { app.target_scope.exclude.remove(i); } else { app.target_scope.include.remove(i); }
        app.scope_sel = None;
        edit = edit.filter(|e| e.index.is_none());
    }
    let mut close = false;
    if let Some(e) = edit.as_mut() {
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(if e.index.is_some() { "Edit rule:" } else { "New rule:" }).color(p.text));
            egui::ComboBox::from_id_salt(("scope_protocol", exclude)).width(90.0).selected_text(e.protocol.label()).show_ui(ui, |ui| {
                for t in ScopeProtocol::ALL { ui.selectable_value(&mut e.protocol, t, t.label()); }
            });
            let field = |ui: &mut Ui, label: &str, text: &mut String, width: f32, hint: &str| {
                ui.label(RichText::new(label).size(12.0).color(p.text));
                ui.add(egui::TextEdit::singleline(text).desired_width(width).font(egui::FontId::monospace(12.5)).hint_text(hint))
            };
            let h = field(ui, "Host:", &mut e.host, 180.0, "^example\\.com$");
            let pt = field(ui, "Port:", &mut e.port, 70.0, "^8443$");
            let f = field(ui, "File:", &mut e.file, 180.0, "^/api/");
            if h.changed() || pt.changed() || f.changed() {
                e.error.clear();
            }
            let submit = theme::primary_button(ui, p, "OK").clicked();
            if theme::plain_button(ui, p, "Cancel", true).clicked() { close = true; }
            if submit {
                let candidate = ScopeRule {
                    protocol: e.protocol,
                    host: e.host.trim().to_string(),
                    port: e.port.trim().to_string(),
                    file: e.file.trim().to_string(),
                    ..ScopeRule::new("")
                };
                let bad = candidate.bad_patterns();
                if !bad.is_empty() {
                    e.error = format!("Not a valid regular expression: {}.", bad.join(", "));
                } else if !candidate.has_parts() {
                    e.error = "Set a protocol, host, port or file; a rule matching every part would match everything.".into();
                } else {
                    let list = if exclude { &mut app.target_scope.exclude } else { &mut app.target_scope.include };
                    match e.index.filter(|&i| i < list.len()) {
                        Some(i) => {
                            let kept = list[i].prefix.clone();
                            list[i] = ScopeRule { prefix: kept, ..candidate };
                        }
                        None => {
                            list.push(candidate);
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
    // removed, not stored as a default: a stored default would reopen the editor every frame
    ui.data_mut(|d| match edit {
        Some(e) => d.insert_temp(edit_id, e),
        None => d.remove::<AdvancedScopeEdit>(edit_id),
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
                            list.push(crate::scope::ScopeRule { subdomains: e.subdomains, ..crate::scope::ScopeRule::new(text) });
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
    theme::show_resizable_window(ctx, egui::Id::new("intruder_attack"), bold(format!("Intruder attack — {}", app.int_target.trim()), 14.0).color(p.strong), &mut open, |ui| {
            // the area the window gives its contents. The panels below lay out inside it but
            // do not report it back, so the window would otherwise shrink to the few rows
            // above them and open far smaller than it was asked to; claiming it at the end
            // keeps the window the size it was given and leaves it free to be resized.
            let window_area = ui.available_rect_before_wrap();
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
                    sort_click = theme::sort_header(ui, p, &cols, app.int_sort.sort_column, !app.int_sort.sort_desc);
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
                            // 0 when capture was paused and the exchange was not recorded:
                            // there is no entry to show for that row, so it does not select
                            let id = r.history_id;
                            let row = theme::table_row(ui, p, &cells, id != 0 && app.int_result_sel == Some(id), i % 2 == 1);
                            if row.clicked() && id != 0 {
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
            ui.allocate_rect(window_area, egui::Sense::hover());
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
/// What the interactions table shows about each interaction, and how wide each column is.
/// Payload and Comment take the room left over; the rest hold what they hold.
const COLLAB_COLS: [(f32, f32); 7] =
    [(46.0, 0.0), (162.0, 0.0), (78.0, 0.0), (240.0, 1.0), (120.0, 0.0), (128.0, 0.0), (190.0, 1.0)];

/// What a right-click on a row asked for, named by the interaction's stable id and carried
/// out once the table has finished drawing -- a row cannot be removed from inside the loop
/// that is still walking the rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CollabRowAction {
    Remove(usize),
    Repeater(usize),
    Organizer(usize),
    Decoder(usize),
}

/// The `Time` cell's text: an ISO-8601 timestamp cut down to the date, the time and
/// milliseconds, which is what the column has room for. A relay may send anything from whole
/// seconds to nanoseconds, so the fraction is always written as exactly three digits and the
/// zone is left off -- a relay reports in UTC, and the full string is still there to be read
/// in the Details pane and to sort by.
///
/// Anything that is not shaped like an ISO-8601 timestamp is passed through exactly as it
/// arrived, rather than mangled into something that only looks like one.
fn collab_time_text(raw: &str) -> String {
    let s = raw.trim();
    let b = s.as_bytes();
    // `YYYY-MM-DD?HH:MM:SS` is the shortest thing worth reformatting, where the separator is
    // the `T` of ISO-8601 or the space some relays write in its place
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let shaped = b.len() >= 19
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && matches!(b[10], b'T' | b't' | b' ')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    if !shaped {
        return s.to_string();
    }
    // a fraction of a second, however many places the relay gave it: ".5" is 500ms, and
    // anything finer than a millisecond is simply not shown
    let mut millis = *b"000";
    if b.len() > 19 && b[19] == b'.' {
        for (i, place) in millis.iter_mut().enumerate() {
            match b.get(20 + i) {
                Some(d) if d.is_ascii_digit() => *place = *d,
                _ => break,
            }
        }
    }
    // every byte read above was checked, so these are char boundaries
    format!("{} {}.{}", &s[0..10], &s[11..19], String::from_utf8_lossy(&millis))
}

/// How a row announces itself, which is also how a test finds it.
fn collab_row_label(hit: &crate::collab::CollabInteraction) -> String {
    format!("Interaction #{} ({} {})", hit.id, hit.interaction_type, hit.payload)
}

pub fn collaborator(app: &mut App, ui: &mut Ui, p: &Palette) {
    // the poll timer belongs to this tab: it runs while the tab is drawing and no longer
    actions::collab_auto_poll_tick(app, ui.ctx());
    // a protocol filter whose protocol is no longer here would leave the table showing
    // nothing at all, so it is dropped before any of it is measured or drawn
    app.collab_view.reconcile(&app.collab_interactions);

    let mut action = None;
    theme::section_title(ui, p, "Collaborator",
        "Test whether an application can be made to contact an external service via DNS, HTTP, or SMTP. \
         Put a payload in a request; if the target looks it up, the interaction shows below.");
    ui.add_space(8.0);
    collab_toolbar(app, ui, p);
    ui.add_space(5.0);
    collab_filter_bar(app, ui, p);
    ui.add_space(6.0);

    let rows = crate::collab::rows(&app.collab_interactions, app.collab_session.as_ref(), &app.collab_view);
    // how much of the table the filters are hiding, which is worth saying plainly:
    // an empty-looking table is otherwise hard to tell from one that collected nothing
    if app.collab_view.is_filtering() && !app.collab_interactions.is_empty() {
        ui.add_space(2.0);
        ui.label(
            RichText::new(format!("Showing {} of {}", rows.len(), app.collab_interactions.len()))
                .size(11.0)
                .color(p.disabled),
        );
        ui.add_space(2.0);
    }
    if app.collab_interactions.is_empty() {
        let _ = theme::empty_state(ui, p, EmptyIcon::Radar, "No interactions",
            "Generate a payload with \"Copy to clipboard\", use it in a request, then poll for DNS, HTTP, or SMTP interactions.", None);
        return;
    }
    // The pane is registered after the bars above and before the table, so the height
    // it may be dragged to is measured from the room those bars left rather than from
    // the whole tab -- otherwise the clamp meant to keep a table's worth of space
    // above it reserves room the bars have already taken, and dragging up far enough
    // leaves no table at all. The traffic tables place theirs the same way.
    collab_detail_pane(app, ui, p);
    collab_table(app, ui, p, &rows, &mut action);
    collab_keyboard_navigation(app, ui, &rows);
    if let Some(action) = action {
        collab_apply(app, action);
    }
}

/// Row one: the payload being handed out, the polling, and the relay it all goes to.
fn collab_toolbar(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.horizontal_wrapped(|ui| {
        if theme::primary_button(ui, p, "Copy to clipboard").clicked() {
            if app.collab_server.trim().is_empty() {
                // nothing to collect against without a relay, and nothing is sent until one is named
                app.collab_msg = "Enter a Collaborator server address first.".into();
            } else {
                let with_server = app.collab_with_server;
                let custom = app.collab_custom.clone();
                let payload = actions::collab_session(app).new_payload(&custom, with_server);
                ui.ctx().copy_text(payload.clone());
                app.collab_msg = format!("Copied {payload}");
                app.collab_payloads.push(payload);
                // the relay has to know the session before it can collect anything for it,
                // and the key that makes that possible takes a moment to generate
                actions::register_collaborator(app);
            }
        }
        ui.label(RichText::new("Custom data:").size(12.0).color(p.text));
        ui.add(
            egui::TextEdit::singleline(&mut app.collab_custom)
                .desired_width(118.0)
                .char_limit(crate::collab::CUSTOM_DATA_MAX)
                .hint_text("optional tag"),
        )
        .on_hover_text("Goes into the payload's hostname, so it comes back on the interaction it caused.");
        ui.checkbox(&mut app.collab_with_server, "Include server location");

        ui.separator();

        if theme::plain_button(ui, p, "Poll now", !app.collab_polling).clicked() {
            actions::poll_collaborator(app);
        }
        if theme::pill(ui, p, "Auto-poll", app.collab_auto_poll)
            .on_hover_text("Poll every ten seconds while this tab is open. Stops on its own if a poll or registration fails.")
            .clicked()
        {
            if app.collab_auto_poll {
                app.collab_auto_poll = false;
                app.collab_last_poll = None;
            } else if app.collab_server.trim().is_empty() {
                app.collab_msg = "Enter a Collaborator server address first.".into();
            } else {
                app.collab_auto_poll = true;
                // due at once, so turning it on polls rather than waiting ten seconds first
                app.collab_last_poll = None;
            }
        }
        if theme::plain_button(ui, p, "Clear", !app.collab_interactions.is_empty())
            .on_hover_text("Forget the interactions collected so far. The session and its payloads stay.")
            .clicked()
        {
            app.collab_interactions.clear();
            app.collab_sel = None;
            // the pill that was on may have been the only one of its kind
            app.collab_view.reconcile(&app.collab_interactions);
            app.collab_msg = "Interactions cleared.".into();
        }

        ui.separator();

        ui.label(RichText::new("Server:").size(12.0).color(p.text));
        let server = ui.add(
            egui::TextEdit::singleline(&mut app.collab_server)
                .desired_width(168.0)
                .hint_text("relay.example.com"),
        );
        if server.changed() {
            // a session belongs to the relay it was registered with; the next payload or
            // poll starts one on whichever server is named now
            app.collab_session = None;
            app.collab_registering = false;
        }
        ui.label(RichText::new("Token:").size(12.0).color(p.text));
        ui.add(
            egui::TextEdit::singleline(&mut app.collab_token)
                .desired_width(104.0)
                .password(true)
                .hint_text("if asked"),
        )
        .on_hover_text("Sent as the Authorization header. A public relay needs none.");
        collab_session_badge(app, ui, p);
    });
    if !app.collab_msg.is_empty() {
        let is_err = app.collab_msg.starts_with("Poll failed:")
            || app.collab_msg.starts_with("Registration failed:")
            || app.collab_msg.starts_with("Enter a")
            || app.collab_msg.starts_with("Custom data");
        let col = if is_err { p.high } else { p.disabled };
        ui.add_space(3.0);
        ui.label(RichText::new(&app.collab_msg).size(11.5).color(col));
    }
}

/// Where the session stands, in the few words there is room for at the end of the row.
fn collab_session_badge(app: &App, ui: &mut Ui, p: &Palette) {
    let (text, colour) = match (&app.collab_session, app.collab_registering) {
        (_, true) => ("Registering…".to_string(), p.disabled),
        (Some(s), _) if s.registered => {
            // the whole correlation id is twenty characters, which is more than a badge wants
            let short: String = s.correlation_id.chars().take(8).collect();
            (format!("Session {short} on {}", crate::collab::server_host(&s.server)), p.low)
        }
        _ => ("Not registered".to_string(), p.disabled),
    };
    ui.label(RichText::new(text).size(11.5).color(colour));
}

/// Row two: one pill per protocol that actually came in, and the search box.
///
/// The pills are built from the interactions rather than from a fixed list, so a relay that
/// reports something no one has seen before gets a pill of its own with no code to change.
fn collab_filter_bar(app: &mut App, ui: &mut Ui, p: &Palette) {
    let total = app.collab_interactions.len();
    let counts: Vec<(String, usize)> = crate::collab::protocols(&app.collab_interactions)
        .into_iter()
        .map(|name| {
            let n = crate::collab::protocol_count(&app.collab_interactions, &name);
            (name, n)
        })
        .collect();
    let active = app.collab_view.protocol.clone();
    let mut pick: Option<Option<String>> = None;
    let mut clear_search = false;
    ui.horizontal_wrapped(|ui| {
        if theme::pill(ui, p, &format!("All ({total})"), active.is_none()).clicked() {
            pick = Some(None);
        }
        for (name, count) in &counts {
            let on = active.as_deref() == Some(name.as_str());
            if theme::pill(ui, p, &format!("{name} ({count})"), on).clicked() {
                // clicking the pill that is on takes the filter off again
                pick = Some(if on { None } else { Some(name.clone()) });
            }
        }
        ui.add_space(10.0);
        ui.add(
            egui::TextEdit::singleline(&mut app.collab_view.search)
                .desired_width(228.0)
                .hint_text("Filter payload, label, IP, or comment..."),
        );
        if !app.collab_view.search.is_empty() && theme::plain_button(ui, p, "\u{00d7}", true).on_hover_text("Clear the search").clicked() {
            clear_search = true;
        }
    });
    if let Some(protocol) = pick {
        app.collab_view.protocol = protocol;
    }
    if clear_search {
        app.collab_view.search.clear();
    }
}

/// The interactions, sorted and filtered as the bars above ask for.
fn collab_table(app: &mut App, ui: &mut Ui, p: &Palette, rows: &[usize], action: &mut Option<CollabRowAction>) {
    use crate::collab::CollabSortColumn as C;
    let height = ui.available_height().max(120.0);
    let sel = app.collab_sel;
    let hits = app.collab_interactions.clone();
    let session = app.collab_session.clone();
    let (sort_col, ascending) = (app.collab_view.sort_column, app.collab_view.sort_ascending);
    let mut sort_click = None;
    let mut clicked = None;
    theme::fitted_table(ui, p, "collab_table", height, &COLLAB_COLS, |ui, w| {
        let cols: &[(&str, f32, C)] = &[
            ("#", w[0], C::Index),
            ("Time", w[1], C::Time),
            ("Type", w[2], C::Type),
            ("Payload", w[3], C::Payload),
            ("Label", w[4], C::Label),
            ("Source IP", w[5], C::SourceIp),
            ("Comment", w[6], C::Comment),
        ];
        if let Some(col) = theme::sort_header(ui, p, cols, sort_col, ascending) {
            sort_click = Some(col);
        }
        if rows.is_empty() {
            let _ = theme::empty_state(ui, p, EmptyIcon::Radar, "Nothing matches",
                "No interaction matches the protocol or the text being searched for.", None);
            return;
        }
        egui::ScrollArea::vertical().id_salt("collab_rows").show_rows(ui, theme::ROW_HEIGHT, rows.len(), |ui, range| {
            for (nth, &i) in rows.iter().enumerate().skip(range.start).take(range.len()) {
                let hit = &hits[i];
                let selected = sel == Some(hit.id);
                let (row, cells) =
                    theme::table_row_cells(ui, p, ("collab_row", hit.id), w, theme::ROW_HEIGHT, selected, nth % 2 == 1, None);
                let fg = if selected { p.strong } else { p.text };
                let comment = if hit.comment.trim().is_empty() { hit.summary() } else { hit.comment.clone() };
                theme::cell_text(ui, cells[0], &hit.id.to_string(), fg);
                theme::cell_text(ui, cells[1], &collab_time_text(&hit.timestamp), fg);
                theme::cell_text(ui, cells[2], &hit.interaction_type,
                    if selected { p.strong } else { crate::ui_core::protocol_color(p, &hit.interaction_type) });
                theme::cell_text(ui, cells[3], &hit.payload, fg);
                theme::cell_text(ui, cells[4], &crate::collab::label_of(session.as_ref(), hit), fg);
                theme::cell_text(ui, cells[5], &hit.client_ip, fg);
                theme::cell_text(ui, cells[6], &comment, fg);
                row.widget_info(|| {
                    egui::WidgetInfo::selected(egui::WidgetType::Button, true, selected, collab_row_label(hit))
                });
                if row.clicked() {
                    clicked = Some(hit.id);
                }
                let has_req = !hit.raw_request.trim().is_empty();
                row.context_menu(|ui| {
                    if ui.button("Copy payload").clicked() {
                        ui.ctx().copy_text(hit.payload.clone());
                        ui.close_menu();
                    }
                    if ui.add_enabled(has_req, egui::Button::new("Copy raw request")).clicked() {
                        ui.ctx().copy_text(hit.raw_request.clone());
                        ui.close_menu();
                    }
                    ui.separator();
                    // the tools that work on a request need one: a lookup carries none
                    if ui.add_enabled(has_req, egui::Button::new("Send to Repeater")).clicked() {
                        *action = Some(CollabRowAction::Repeater(hit.id));
                        ui.close_menu();
                    }
                    if ui.add_enabled(has_req, egui::Button::new("Send to Organizer")).clicked() {
                        *action = Some(CollabRowAction::Organizer(hit.id));
                        ui.close_menu();
                    }
                    // the Decoder takes the transcript when there is one and the payload
                    // otherwise, so it is worth offering either way
                    if ui.button("Send to Decoder").clicked() {
                        *action = Some(CollabRowAction::Decoder(hit.id));
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Remove").clicked() {
                        *action = Some(CollabRowAction::Remove(hit.id));
                        ui.close_menu();
                    }
                });
            }
        });
    });
    if let Some(col) = sort_click {
        app.collab_view.click_column(col);
    }
    if let Some(id) = clicked {
        // clicking the row that is open closes it again
        app.collab_sel = (app.collab_sel != Some(id)).then_some(id);
    }
}

/// Carry out what a row's context menu asked for.
fn collab_apply(app: &mut App, action: CollabRowAction) {
    let id = match action {
        CollabRowAction::Remove(id) | CollabRowAction::Repeater(id) | CollabRowAction::Organizer(id) | CollabRowAction::Decoder(id) => id,
    };
    let Some(hit) = app.collab_interactions.iter().find(|h| h.id == id).cloned() else {
        return;
    };
    match action {
        CollabRowAction::Remove(_) => {
            app.collab_interactions.retain(|h| h.id != id);
            if app.collab_sel == Some(id) {
                app.collab_sel = None;
            }
            // that may have been the last interaction of its protocol
            app.collab_view.reconcile(&app.collab_interactions);
        }
        CollabRowAction::Repeater(_) => actions::send_collab_to_repeater(app, &hit),
        CollabRowAction::Organizer(_) => actions::send_collab_to_organizer(app, &hit),
        CollabRowAction::Decoder(_) => actions::send_collab_to_decoder(app, &hit),
    }
}

/// Up and Down move the selection through the rows as they are shown -- sorted and filtered
/// as they are, which is the order the eye is following. Held back while something has the
/// keyboard, so an arrow key in the search box moves the cursor and not the row.
fn collab_keyboard_navigation(app: &mut App, ui: &mut Ui, rows: &[usize]) {
    if rows.is_empty() || ui.memory(|m| m.focused()).is_some() {
        return;
    }
    let (down, up) = ui.input(|i| (i.key_pressed(egui::Key::ArrowDown), i.key_pressed(egui::Key::ArrowUp)));
    if !down && !up {
        return;
    }
    let ids: Vec<usize> = rows.iter().map(|&i| app.collab_interactions[i].id).collect();
    let at = app.collab_sel.and_then(|id| ids.iter().position(|&x| x == id));
    let next = match (at, down) {
        // nothing selected yet: Down takes the first row, Up the last
        (None, true) => 0,
        (None, false) => ids.len() - 1,
        (Some(i), true) => (i + 1).min(ids.len() - 1),
        (Some(i), false) => i.saturating_sub(1),
    };
    app.collab_sel = Some(ids[next]);
}

/// What the selected interaction carried, in a pane that can be dragged taller or shorter.
/// Nothing is registered at all when no row is open, so the table has the whole tab to itself.
fn collab_detail_pane(app: &mut App, ui: &mut Ui, p: &Palette) {
    let Some(hit) = app.collab_sel.and_then(|id| app.collab_interactions.iter().find(|h| h.id == id)).cloned() else {
        return;
    };
    let label = crate::collab::label_of(app.collab_session.as_ref(), &hit);
    let avail = ui.available_height();
    egui::TopBottomPanel::bottom("collab_detail")
        .resizable(true)
        .default_height(280.0)
        .min_height(120.0)
        // as in the traffic tables: the pane can never grow over the table above it
        .max_height((avail - 120.0).max(120.0))
        .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { top: 6, ..Default::default() }))
        .show_inside(ui, |ui| {
            if hit.has_message() {
                collab_transcript(app, ui, p, &hit, &label);
            } else {
                collab_callback_details(ui, p, &hit, &label);
            }
        });
}

/// One name and its value, selectable so it can be copied out.
fn collab_field(ui: &mut Ui, p: &Palette, name: &str, value: &str) {
    if value.trim().is_empty() {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{name}:")).size(12.0).color(p.disabled));
        ui.add(egui::Label::new(RichText::new(value).size(12.0).color(p.text)).selectable(true).wrap());
    });
}

/// An interaction that carried a message: what came in, what was answered, and the rest of
/// what the relay said about it.
fn collab_transcript(app: &mut App, ui: &mut Ui, p: &Palette, hit: &crate::collab::CollabInteraction, label: &str) {
    let has_response = !hit.raw_response.trim().is_empty();
    // a lookup's transcript is not a request and a response, so the pane says "Transcript"
    let request_title = if crate::collab::normalize_protocol(&hit.interaction_type).starts_with("HTTP") { "Request" } else { "Transcript" };
    let columns = if has_response { 3 } else { 2 };
    // The editors go inside a scroll area, which bounds the height they are offered to the
    // pane's actual (dragged) size. A panel stores the rect of its *contents*, so editors
    // allowed to ask for more than the pane has would drive its height instead of the drag:
    // the pane then creeps a little on every idle frame and never settles, and the clamp that
    // keeps at least a table's worth of room above it is bypassed, letting the table collapse.
    // Anything that does not fit scrolls instead. The traffic tables do the same, for the same
    // reason.
    egui::ScrollArea::vertical().id_salt("collab_detail_scroll").auto_shrink([false, false]).show(ui, |ui| {
        let h = (ui.available_height() - 24.0).max(90.0);
        let (out_req, out_resp) = theme::columns(ui, columns, |cols| {
            cols[0].label(bold(request_title, 12.5).color(p.strong));
            let req = editor::message_view(&mut cols[0], p, "collab_req", &hit.raw_request, h);
            let resp = has_response.then(|| {
                cols[1].label(bold("Response", 12.5).color(p.strong));
                editor::message_view(&mut cols[1], p, "collab_resp", &hit.raw_response, h)
            });
            let last = columns - 1;
            cols[last].label(bold("Details", 12.5).color(p.strong));
            egui::ScrollArea::vertical().id_salt("collab_details").max_height(h).show(&mut cols[last], |ui| {
                collab_field(ui, p, "Type", &hit.interaction_type);
                collab_field(ui, p, "Query type", &hit.query_type);
                collab_field(ui, p, "Full payload", &hit.payload);
                collab_field(ui, p, "Label", label);
                collab_field(ui, p, "Session ID", &hit.unique_id);
                collab_field(ui, p, "Client IP", &hit.client_ip);
                collab_field(ui, p, "Timestamp", &hit.timestamp);
                if !hit.comment.trim().is_empty() {
                    ui.add_space(4.0);
                    ui.add(egui::Label::new(RichText::new(&hit.comment).size(12.0).color(p.text)).selectable(true).wrap());
                }
            });
            (req, resp)
        });
        let name = format!("Interaction {}", hit.payload);
        attach_view_context_menu(&out_req, &hit.raw_request, app, Tab::Collaborator, "", &hit.raw_request, Some(&hit.raw_response), &format!("{name} request"));
        if let Some(out_resp) = out_resp {
            attach_view_context_menu(&out_resp, &hit.raw_response, app, Tab::Collaborator, "", &hit.raw_request, Some(&hit.raw_response), &format!("{name} response"));
        }
    });
}

/// An interaction that carried no message of its own -- a name lookup, a connection that was
/// made and nothing more. There is no request to show, so the pane shows what there is in two
/// columns rather than leaving two empty editors taking up the room.
fn collab_callback_details(ui: &mut Ui, p: &Palette, hit: &crate::collab::CollabInteraction, label: &str) {
    ui.label(bold("Callback details", 12.5).color(p.strong));
    ui.add_space(4.0);
    egui::ScrollArea::vertical().id_salt("collab_callback").auto_shrink([false, false]).show(ui, |ui| {
        theme::columns(ui, 2, |cols| {
            collab_field(&mut cols[0], p, "Full payload", &hit.payload);
            collab_field(&mut cols[0], p, "Type", &hit.interaction_type);
            collab_field(&mut cols[0], p, "Query type", &hit.query_type);
            collab_field(&mut cols[0], p, "Event", &hit.summary());
            collab_field(&mut cols[1], p, "Label", label);
            collab_field(&mut cols[1], p, "Client IP", &hit.client_ip);
            collab_field(&mut cols[1], p, "Timestamp", &hit.timestamp);
            collab_field(&mut cols[1], p, "Session ID", &hit.unique_id);
        });
        if !hit.comment.trim().is_empty() {
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(&hit.comment).size(12.0).color(p.text)).selectable(true).wrap());
        }
        ui.add_space(6.0);
        ui.label(RichText::new("This interaction carried no message of its own.").size(11.5).color(p.disabled));
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
    let paused = app.capture_paused.load(std::sync::atomic::Ordering::Relaxed);
    egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(8, 5)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            // one switch for every tool: while it is off nothing new is recorded, and the
            // tools go on sending exactly as they were
            if theme::plain_button(ui, p, if paused { "Resume capture" } else { "Pause capture" }, true).clicked() {
                app.capture_paused.store(!paused, std::sync::atomic::Ordering::Relaxed);
            }
            ui.add_space(6.0);
            let mib = |n: u64| n >> 20;
            let state = if paused {
                "Capture is paused: requests are still being sent, and none of them are being recorded. ".to_string()
            } else {
                format!("The last {} requests are kept in memory. ", crate::rules::MAX_RECORDED_REQUESTS)
            };
            ui.label(RichText::new(format!(
                "{state}Proxy: request bodies up to {} MiB; responses over {} MiB reach the browser but are recorded cut short. Tools read responses up to {} MiB.",
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
                if let Some(col) = theme::sort_header(ui, p, cols, app.history_filter.sort_column, app.history_filter.sort_ascending) {
                    app.history_filter.click_column(col);
                }
                // only the rows in view are drawn (history can hold thousands)
                egui::ScrollArea::vertical().id_salt(("traffic", view as u8)).show_rows(ui, theme::ROW_HEIGHT, hist.len(), |ui, range| {
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
                    clicked = crate::theme::sort_header(ui, &crate::theme::DARK, &COLS, Some(C::Request), true);
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

#[cfg(test)]
mod logger_tests {
    use crate::state::{App, Tab};
    use crate::test_utils::MockAppBuilder;
    use eframe::egui;
    use std::sync::atomic::Ordering;

    /// One full frame of the app with these input events; returns the accessibility update.
    fn frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 800.0))),
            events,
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    /// Centre of the widget labelled `label`, from a frame's accessibility tree.
    fn find(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> egui::Pos2 {
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        let r = nodes.iter().find(|(_, n)| n.label() == Some(label)).and_then(|(_, n)| n.bounds())
            .unwrap_or_else(|| panic!("no widget labelled {label:?}"));
        egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32)
    }

    /// Click `label` (press and release over a frame each), the way a user would.
    fn click(ctx: &egui::Context, app: &mut App, label: &str) {
        frame(ctx, app, vec![]);
        let at = find(&frame(ctx, app, vec![]), label);
        let button = |pressed| egui::Event::PointerButton { pos: at, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        frame(ctx, app, vec![egui::Event::PointerMoved(at), button(true)]);
        frame(ctx, app, vec![button(false)]);
        frame(ctx, app, vec![]);
    }

    /// The capture switch is one button over the whole store, and the button says which way
    /// round it is. Nothing else in the app reads a copy of the flag, so what the tools' own
    /// threads see is what this toggles.
    #[test]
    fn the_capture_switch_pauses_and_resumes_recording() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Logger).build_with_ctx();
        ctx.enable_accesskit();
        assert!(!app.capture_paused.load(Ordering::Relaxed), "recording out of the box");

        click(&ctx, &mut app, "Pause capture");
        assert!(app.capture_paused.load(Ordering::Relaxed), "the switch is on");
        assert!(app.recorder().paused(), "and the store the tools record through is paused");

        click(&ctx, &mut app, "Resume capture");
        assert!(!app.capture_paused.load(Ordering::Relaxed), "and off again");
        assert!(!app.recorder().paused());
    }
}

#[cfg(test)]
mod collab_tests {
    use super::collab_time_text;
    use crate::collab::{CollabInteraction, OastSession};
    use crate::state::{App, Tab};
    use crate::test_utils::{assert_table, MockAppBuilder};
    use eframe::egui;

    /// The Collaborator tab with a session that handed out six labelled payloads and seven
    /// interactions collected against them: one of every protocol the filter bar knows a
    /// colour for, one protocol it has never heard of, and two lookups for the same payload.
    ///
    /// The payload hostnames deliberately carry none of the labels, so a search that matches a
    /// label can only have matched through the session.
    fn collab_app() -> (egui::Context, App) {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Collaborator).build_with_ctx();
        ctx.enable_accesskit();
        let mut session = OastSession::begin("relay.test");
        session.registered = true;
        for custom in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
            session.new_payload(custom, false);
        }
        let ids: Vec<String> = session.payloads.iter().map(|p| p.unique_id.clone()).collect();
        let hit = |id: usize, kind: &str, host: &str, ip: &str, unique: &str| CollabInteraction {
            id,
            interaction_type: kind.into(),
            timestamp: format!("2026-11-14T09:0{id}:00Z"),
            payload: host.into(),
            client_ip: ip.into(),
            unique_id: unique.into(),
            ..Default::default()
        };
        app.collab_interactions = vec![
            CollabInteraction { query_type: "A".into(), ..hit(1, "DNS", "r1.relay.test", "203.0.113.11", &ids[0]) },
            CollabInteraction {
                raw_request: "GET /hook?x=1 HTTP/1.1\nHost: r2.relay.test\n\n".into(),
                raw_response: "HTTP/1.1 200 OK\ncontent-length: 2\n\nok".into(),
                ..hit(2, "HTTP", "r2.relay.test", "203.0.113.22", &ids[1])
            },
            hit(3, "LDAP", "r3.relay.test", "203.0.113.33", &ids[2]),
            CollabInteraction {
                raw_request: "RCPT TO:<root@r4.relay.test>".into(),
                ..hit(4, "SMTP", "r4.relay.test", "203.0.113.44", &ids[3])
            },
            hit(5, "SMB", "r5.relay.test", "203.0.113.55", &ids[4]),
            hit(6, "QUIC-ODDITY", "r6.relay.test", "203.0.113.66", &ids[5]),
            CollabInteraction { query_type: "AAAA".into(), ..hit(7, "DNS", "r1.relay.test", "203.0.113.77", &ids[0]) },
        ];
        app.collab_session = Some(session);
        app.collab_server = "relay.test".into();
        app.collab_sel = None;
        app.tab = Tab::Collaborator;
        (ctx, app)
    }

    /// One full frame of the app with these input events; returns the accessibility update.
    fn frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1600.0, 1000.0))),
            events,
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    /// Everything in a frame labelled `label`, with its rectangle.
    fn find_all(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> Vec<egui::Rect> {
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        nodes
            .iter()
            .filter(|(_, n)| n.label().as_deref() == Some(label) || n.value().as_deref() == Some(label))
            .filter_map(|(_, n)| n.bounds())
            .map(|r| egui::Rect::from_min_max(egui::pos2(r.x0 as f32, r.y0 as f32), egui::pos2(r.x1 as f32, r.y1 as f32)))
            .collect()
    }

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

    fn key(k: egui::Key) -> Vec<egui::Event> {
        vec![egui::Event::Key { key: k, physical_key: None, pressed: true, repeat: false, modifiers: Default::default() }]
    }

    /// How the row for this interaction announces itself.
    fn row_label(app: &App, id: usize) -> String {
        let hit = app.collab_interactions.iter().find(|h| h.id == id).expect("the interaction");
        format!("Interaction #{} ({} {})", hit.id, hit.interaction_type, hit.payload)
    }

    /// Where that row is drawn.
    fn row_rect(ctx: &egui::Context, app: &mut App, id: usize) -> egui::Rect {
        let label = row_label(app, id);
        frame(ctx, app, vec![]);
        find(&frame(ctx, app, vec![]), &label)
    }

    /// The ids the table is showing, in the order it shows them.
    fn shown(app: &App) -> Vec<usize> {
        crate::collab::rows(&app.collab_interactions, app.collab_session.as_ref(), &app.collab_view)
            .iter()
            .map(|&i| app.collab_interactions[i].id)
            .collect()
    }

    /// The filter bar offers a pill per protocol that actually came in, counted, and filters
    /// by whichever one is clicked -- including a protocol the app has never heard of.
    #[test]
    fn the_protocol_pills_are_built_from_what_came_in_and_filter_by_it() {
        let (ctx, mut app) = collab_app();
        let update = frame(&ctx, &mut app, vec![]);
        // the known protocols in the bar's own order, then the one the relay invented
        for want in ["All (7)", "DNS (2)", "HTTP (1)", "SMTP (1)", "LDAP (1)", "SMB (1)", "QUIC-ODDITY (1)"] {
            assert!(!find_all(&update, want).is_empty(), "the bar offers {want:?}");
        }
        for missing in ["FTP (0)", "HTTPS (0)", "FTP (1)"] {
            assert!(find_all(&update, missing).is_empty(), "but nothing for {missing:?}, which never came in");
        }

        click(&ctx, &mut app, "LDAP (1)");
        assert_eq!(app.collab_view.protocol.as_deref(), Some("LDAP"));
        assert_eq!(shown(&app), [3], "only the one interaction of that protocol");

        click(&ctx, &mut app, "LDAP (1)");
        assert_eq!(app.collab_view.protocol, None, "the pill that is on puts the filter back");
        assert_eq!(shown(&app), [1, 2, 3, 4, 5, 6, 7]);

        // a protocol no one has heard of filters exactly like the ones that are known
        click(&ctx, &mut app, "QUIC-ODDITY (1)");
        assert_eq!(shown(&app), [6]);
        click(&ctx, &mut app, "All (7)");
        assert_eq!(app.collab_view.protocol, None, "and All takes any filter off");
        assert_eq!(shown(&app), [1, 2, 3, 4, 5, 6, 7]);
    }

    /// The search box matches what a row shows, the label included -- which it can only know
    /// through the session that handed the payload out.
    #[test]
    fn the_search_box_matches_what_a_row_shows_matrix() {
        let cases: [(&str, &str, Vec<usize>); 6] = [
            ("the payload", "r3.relay", vec![3]),
            ("the label, which is not in the payload", "gamma", vec![3]),
            ("a label two lookups share", "alpha", vec![1, 7]),
            ("the address", "203.0.113.44", vec![4]),
            ("nothing at all", "", vec![1, 2, 3, 4, 5, 6, 7]),
            ("something no row has", "nothing-here", vec![]),
        ];
        assert_table!(cases, |idx, (what, search, want)| {
            let (ctx, mut app) = collab_app();
            app.collab_view.search = search.to_string();
            frame(&ctx, &mut app, vec![]);
            assert_eq!(shown(&app), want, "case #{idx} ({what})");
            // every row the table says it is showing is really drawn
            for id in shown(&app) {
                assert!(!find_all(&frame(&ctx, &mut app, vec![]), &row_label(&app, id)).is_empty(), "case #{idx}: row {id} is drawn");
            }
        });
    }

    /// A protocol pill and the search box narrow the table together, and the arrow keys walk
    /// only the rows that survive both -- in the order they are shown.
    #[test]
    fn the_arrow_keys_walk_the_rows_that_are_shown() {
        let (ctx, mut app) = collab_app();
        app.collab_view.search = "alpha".into();
        frame(&ctx, &mut app, vec![]);
        assert_eq!(shown(&app), [1, 7]);

        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.collab_sel, Some(1), "Down with nothing selected takes the first row");
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.collab_sel, Some(7), "straight past the rows the search is hiding");
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.collab_sel, Some(7), "and stops at the bottom rather than wrapping");
        frame(&ctx, &mut app, key(egui::Key::ArrowUp));
        assert_eq!(app.collab_sel, Some(1));
        frame(&ctx, &mut app, key(egui::Key::ArrowUp));
        assert_eq!(app.collab_sel, Some(1), "and at the top");

        // sorted the other way, Down goes to what is now the next row down
        app.collab_view.sort_ascending = false;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(shown(&app), [7, 1]);
        app.collab_sel = Some(7);
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert_eq!(app.collab_sel, Some(1), "the row under it on screen, not the next one stored");

        // and with a protocol pill on as well, only what passes both is walked
        app.collab_view.search.clear();
        app.collab_view.protocol = Some("DNS".into());
        app.collab_view.sort_ascending = true;
        app.collab_sel = None;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(shown(&app), [1, 7]);
        frame(&ctx, &mut app, key(egui::Key::ArrowDown));
        assert!(shown(&app).contains(&app.collab_sel.expect("a row")), "the selection is one of the rows shown");
    }

    /// Clicking a row opens that interaction below the table, and clicking it again closes it.
    /// What the pane shows follows the selection by id, so re-sorting cannot move it.
    #[test]
    fn clicking_a_row_opens_that_interaction_and_the_selection_survives_a_re_sort() {
        let (ctx, mut app) = collab_app();
        let at = row_rect(&ctx, &mut app, 4).center();
        click_at(&ctx, &mut app, at, false);
        assert_eq!(app.collab_sel, Some(4), "the row that was clicked");

        // the same row again lets it go
        let at = row_rect(&ctx, &mut app, 4).center();
        click_at(&ctx, &mut app, at, false);
        assert_eq!(app.collab_sel, None);

        // a selection follows its interaction through a re-sort rather than staying on a row
        app.collab_sel = Some(4);
        app.collab_view.sort_column = Some(crate::collab::CollabSortColumn::Payload);
        app.collab_view.sort_ascending = false;
        frame(&ctx, &mut app, vec![]);
        // r6 down to r2, then the two lookups that share r1: equal values keep the order they
        // arrived in whichever way the column is sorted, so #1 still comes before #7
        assert_eq!(shown(&app), [6, 5, 4, 3, 2, 1, 7], "sorted by payload, descending");
        assert_eq!(app.collab_sel, Some(4), "and the open interaction is still #4");
    }

    /// An interaction that carried a message shows it, with the Raw / Pretty / Hex switch over
    /// it; one that carried none shows its callback details instead of two empty editors.
    #[test]
    fn the_detail_pane_shows_a_transcript_or_callback_details_matrix() {
        struct Case {
            name: &'static str,
            id: usize,
            present: &'static [&'static str],
            absent: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "a request and what was answered",
                id: 2,
                present: &["Request", "Response", "Details", "Raw", "Pretty", "Hex"],
                absent: &["Callback details"],
            },
            Case {
                name: "a conversation with nothing answered",
                id: 4,
                // not an HTTP request, so the pane calls it a transcript
                present: &["Transcript", "Details", "Raw"],
                absent: &["Callback details", "Response"],
            },
            Case {
                name: "a lookup, which carried no message at all",
                id: 1,
                present: &["Callback details"],
                absent: &["Request", "Transcript", "Response"],
            },
            Case {
                name: "a connection on a protocol the app has never heard of, and no message",
                id: 6,
                present: &["Callback details"],
                absent: &["Request", "Transcript", "Response"],
            },
        ];
        assert_table!(cases, |idx, case| {
            let (ctx, mut app) = collab_app();
            let at = row_rect(&ctx, &mut app, case.id).center();
            click_at(&ctx, &mut app, at, false);
            let update = frame(&ctx, &mut app, vec![]);
            assert_eq!(app.collab_sel, Some(case.id), "case #{idx} ({})", case.name);
            for want in case.present {
                assert!(!find_all(&update, want).is_empty(), "case #{idx} ({}): {want:?} is shown", case.name);
            }
            for gone in case.absent {
                assert!(find_all(&update, gone).is_empty(), "case #{idx} ({}): {gone:?} is not", case.name);
            }
        });
    }

    /// A row's own menu hands that interaction to the tool it names, carrying its message.
    #[test]
    fn the_row_menu_sends_the_row_it_was_opened_on_onward_matrix() {
        struct Case {
            name: &'static str,
            item: &'static str,
            tab: Tab,
            check: fn(&App) -> bool,
        }
        let cases = [
            Case {
                name: "to the Repeater",
                item: "Send to Repeater",
                tab: Tab::Repeater,
                check: |a| a.repeater_tabs.iter().any(|t| t.request.contains("/hook?x=1")),
            },
            Case {
                name: "to the Organizer",
                item: "Send to Organizer",
                tab: Tab::Organizer,
                check: |a| a.organizer.iter().any(|it| it.path.contains("/hook")),
            },
            Case {
                name: "to the Decoder",
                item: "Send to Decoder",
                tab: Tab::Decoder,
                check: |a| a.dec_blocks.iter().any(|b| b.text.contains("/hook?x=1")),
            },
        ];
        assert_table!(cases, |idx, case| {
            let (ctx, mut app) = collab_app();
            // interaction #2 is the one with a request on it
            let at = row_rect(&ctx, &mut app, 2).center();
            click_at(&ctx, &mut app, at, true);
            let update = frame(&ctx, &mut app, vec![]);
            assert!(!find_all(&update, case.item).is_empty(), "case #{idx} ({}): the row menu is open", case.name);
            let item = find(&update, case.item).center();
            click_at(&ctx, &mut app, item, false);
            assert_eq!(app.tab, case.tab, "case #{idx} ({}): it opened the tool", case.name);
            assert!((case.check)(&app), "case #{idx} ({}): carrying the row's own message", case.name);
        });
    }

    /// "Remove" throws away the interaction the menu was opened on and nothing else, and a
    /// protocol filter left pointing at a protocol that has gone with it comes off.
    #[test]
    fn the_row_menu_removes_the_row_it_was_opened_on() {
        let (ctx, mut app) = collab_app();
        app.collab_view.protocol = Some("LDAP".into());
        app.collab_sel = Some(3);
        frame(&ctx, &mut app, vec![]);
        assert_eq!(shown(&app), [3]);

        let at = row_rect(&ctx, &mut app, 3).center();
        click_at(&ctx, &mut app, at, true);
        let update = frame(&ctx, &mut app, vec![]);
        assert!(!find_all(&update, "Remove").is_empty(), "the row menu is open");
        let remove = find(&update, "Remove").center();
        click_at(&ctx, &mut app, remove, false);

        assert_eq!(
            app.collab_interactions.iter().map(|h| h.id).collect::<Vec<_>>(),
            [1, 2, 4, 5, 6, 7],
            "that interaction and no other was removed"
        );
        assert_eq!(app.collab_sel, None, "and nothing is left selected");
        assert_eq!(app.collab_view.protocol, None, "the pill it was the last of took the filter with it");
        assert_eq!(shown(&app), [1, 2, 4, 5, 6, 7], "so the table is not left showing nothing");
    }

    /// "Clear" forgets the interactions and leaves the session and its payloads alone, so the
    /// payloads already out in the world go on being collected for.
    #[test]
    fn clear_forgets_the_interactions_and_keeps_the_session() {
        let (ctx, mut app) = collab_app();
        app.collab_sel = Some(2);
        app.collab_view.protocol = Some("DNS".into());
        let payloads = app.collab_session.as_ref().expect("a session").payloads.clone();

        click(&ctx, &mut app, "Clear");
        assert!(app.collab_interactions.is_empty(), "the interactions are gone");
        assert_eq!(app.collab_sel, None, "nothing is selected any more");
        assert_eq!(app.collab_view.protocol, None, "and no filter is left pointing at a protocol that is gone");
        let session = app.collab_session.as_ref().expect("the session stays");
        assert_eq!(session.payloads, payloads, "with every payload it handed out");
    }

    /// The poll timer runs on its own tab only, and says so rather than polling a relay that
    /// has not been named.
    #[test]
    fn the_auto_poll_toggle_needs_a_relay_to_poll() {
        let (ctx, mut app) = collab_app();
        app.collab_server.clear();
        click(&ctx, &mut app, "Auto-poll");
        assert!(!app.collab_auto_poll, "nothing to poll, so the timer does not start");
        assert_eq!(app.collab_msg, "Enter a Collaborator server address first.");
        assert!(!app.collab_polling, "and no request went out");

        // with a relay named it turns on, and turning it off again stops it
        app.collab_server = "relay.example.com".into();
        click(&ctx, &mut app, "Auto-poll");
        assert!(app.collab_auto_poll, "the timer is on");
        app.collab_polling = false;
        click(&ctx, &mut app, "Auto-poll");
        assert!(!app.collab_auto_poll, "and off again");
        assert_eq!(app.collab_last_poll, None);
    }

    /// The Time column shows the date, the time and milliseconds, whatever precision the relay
    /// reported in -- and leaves anything that is not an ISO-8601 timestamp alone.
    #[test]
    fn the_time_cell_is_cut_down_to_milliseconds_matrix() {
        let cases: [(&str, &str, &str); 12] = [
            ("nanoseconds, as a relay usually reports", "2026-11-14T11:06:18.237456789Z", "2026-11-14 11:06:18.237"),
            ("exactly milliseconds", "2026-11-14T11:06:18.237Z", "2026-11-14 11:06:18.237"),
            ("whole seconds", "2026-11-14T09:30:00Z", "2026-11-14 09:30:00.000"),
            ("a tenth of a second is 100ms, not 1ms", "2026-11-14T09:30:00.5Z", "2026-11-14 09:30:00.500"),
            ("two places", "2026-11-14T09:30:00.25Z", "2026-11-14 09:30:00.250"),
            ("an offset instead of a zone letter", "2026-11-14T09:30:00+02:00", "2026-11-14 09:30:00.000"),
            ("no zone at all", "2026-11-14T09:30:00", "2026-11-14 09:30:00.000"),
            ("a space where the T should be", "2026-11-14 09:30:00.237Z", "2026-11-14 09:30:00.237"),
            ("a lower-case separator", "2026-11-14t09:30:00Z", "2026-11-14 09:30:00.000"),
            // not ISO-8601: passed through rather than reshaped into something that looks like it
            ("words", "just now", "just now"),
            ("another order entirely", "14/11/2026 11:06", "14/11/2026 11:06"),
            ("nothing at all", "", ""),
        ];
        assert_table!(cases, |idx, (what, raw, want)| {
            assert_eq!(collab_time_text(raw), want, "case #{idx} ({what})");
        });

        // a trailing dot with no digits after it, and text that is not even ASCII: neither is
        // allowed to panic on a byte index
        assert_eq!(collab_time_text("2026-11-14T09:30:00."), "2026-11-14 09:30:00.000");
        assert_eq!(collab_time_text("2026-11-14T09:30:00.\u{00e9}Z"), "2026-11-14 09:30:00.000");
        assert_eq!(collab_time_text("\u{00e9}\u{00e9}\u{00e9}"), "\u{00e9}\u{00e9}\u{00e9}");
        assert_eq!(collab_time_text("  2026-11-14T09:30:00Z  "), "2026-11-14 09:30:00.000", "surrounding space is trimmed");
    }

    /// Shortening the cell is a matter of drawing only: the interaction keeps the timestamp the
    /// relay sent, which is what the table sorts by and what the Details pane shows.
    #[test]
    fn the_full_timestamp_is_kept_for_sorting_and_for_the_details_pane() {
        let (ctx, mut app) = collab_app();
        // two interactions a third of a second apart: the same cell text, a different order
        app.collab_interactions[0].timestamp = "2026-11-14T11:06:18.237456789Z".into();
        app.collab_interactions[1].timestamp = "2026-11-14T11:06:18.237111111Z".into();
        assert_eq!(
            collab_time_text(&app.collab_interactions[0].timestamp),
            collab_time_text(&app.collab_interactions[1].timestamp),
            "the cells read the same to a millisecond"
        );

        app.collab_view.sort_column = Some(crate::collab::CollabSortColumn::Time);
        app.collab_view.sort_ascending = true;
        frame(&ctx, &mut app, vec![]);
        let order = shown(&app);
        let (first, second) = (order.iter().position(|&id| id == 2), order.iter().position(|&id| id == 1));
        assert!(first < second, "but the finer digits still decide the order: {order:?}");

        // and the Details pane shows the timestamp whole, not the shortened cell
        let at = row_rect(&ctx, &mut app, 1).center();
        click_at(&ctx, &mut app, at, false);
        let update = frame(&ctx, &mut app, vec![]);
        assert_eq!(app.collab_sel, Some(1));
        assert!(!find_all(&update, "2026-11-14T11:06:18.237456789Z").is_empty(), "the full timestamp is there to read");
    }

    /// The detail pane's rect as egui last laid it out.
    fn detail_rect(ctx: &egui::Context) -> egui::Rect {
        egui::containers::panel::PanelState::load(ctx, egui::Id::new("collab_detail"))
            .map(|s| s.rect)
            .expect("the detail pane is on screen")
    }

    /// The table's height: from the top of its header down to the splitter above the pane.
    fn table_height(ctx: &egui::Context, app: &mut App) -> f32 {
        let update = frame(ctx, app, vec![]);
        let header_top = find(&update, "#").top();
        detail_rect(ctx).top() - header_top
    }

    /// Drag the splitter by `dy` (negative is upward), a frame at a time as a hand would, and
    /// give back the detail pane's height afterwards.
    fn drag_splitter(ctx: &egui::Context, app: &mut App, dy: f32) -> f32 {
        frame(ctx, app, vec![]);
        let grip = egui::pos2(detail_rect(ctx).center().x, detail_rect(ctx).top());
        frame(ctx, app, vec![egui::Event::PointerMoved(grip)]);
        frame(ctx, app, vec![button(grip, true, false)]);
        let to = egui::pos2(grip.x, grip.y + dy);
        // egui reads the resize drag from the frame before, so the move is held for two
        frame(ctx, app, vec![egui::Event::PointerMoved(to)]);
        frame(ctx, app, vec![]);
        frame(ctx, app, vec![button(to, false, false)]);
        frame(ctx, app, vec![]);
        detail_rect(ctx).height()
    }

    /// Dragging the splitter upward gives the detail pane the room and takes it from the table;
    /// dragging it back down returns it. The pane has to follow the pointer in both directions:
    /// contents allowed to insist on their own height would stop it shrinking.
    #[test]
    fn dragging_the_splitter_trades_height_between_the_table_and_the_detail_pane() {
        let (ctx, mut app) = collab_app();
        // interaction #2 carries a request and a response, so the pane is at its fullest
        app.collab_sel = Some(2);
        frame(&ctx, &mut app, vec![]);

        let (h0, t0) = (detail_rect(&ctx).height(), table_height(&ctx, &mut app));
        let grown = drag_splitter(&ctx, &mut app, -90.0);
        let t1 = table_height(&ctx, &mut app);
        assert!(grown > h0 + 60.0, "dragging up grew the pane: {h0} -> {grown}");
        assert!(t1 < t0 - 60.0, "and took it from the table: {t0} -> {t1}");

        // and back down again, which is the direction contents can fight
        let shrunk = drag_splitter(&ctx, &mut app, 70.0);
        let t2 = table_height(&ctx, &mut app);
        assert!(shrunk < grown - 50.0, "dragging down shrank the pane: {grown} -> {shrunk}");
        assert!(t2 > t1 + 50.0, "and gave it back to the table: {t1} -> {t2}");
    }

    /// Where the splitter was let go is where it stays. The pane holds the height it was
    /// dragged to over idle frames instead of drifting a little on each one, which is what a
    /// pane whose height is decided by its contents rather than by the drag does.
    #[test]
    fn the_pane_holds_the_height_it_was_dragged_to_matrix() {
        let cases: [(&str, usize, f32); 4] = [
            ("a transcript dragged taller", 2, -120.0),
            ("a transcript dragged shorter", 2, 90.0),
            ("a transcript squeezed to the floor", 2, 400.0),
            ("callback details, which have no editors in them", 1, -120.0),
        ];
        assert_table!(cases, |idx, (what, id, dy)| {
            let (ctx, mut app) = collab_app();
            app.collab_sel = Some(id);
            let settled = drag_splitter(&ctx, &mut app, dy);
            for n in 0..5 {
                let now = detail_rect(&ctx).height();
                assert!(
                    (now - settled).abs() < 0.5,
                    "case #{idx} ({what}): idle frame {n} moved it from {settled} to {now}"
                );
                frame(&ctx, &mut app, vec![]);
            }
            // and never past the floor it is clamped to
            assert!(settled >= 119.5, "case #{idx} ({what}): {settled} is under the minimum");
        });
    }

    /// However far the splitter is dragged upward, a table's worth of room is kept above it.
    /// The pane is registered after the bars for exactly this reason: a clamp measured against
    /// the whole tab would reserve height the bars have already spent, and the table would be
    /// left with nothing.
    #[test]
    fn dragging_the_splitter_to_the_top_still_leaves_a_table() {
        let (ctx, mut app) = collab_app();
        app.collab_sel = Some(2);
        frame(&ctx, &mut app, vec![]);
        drag_splitter(&ctx, &mut app, -2000.0);
        let table = table_height(&ctx, &mut app);
        assert!(table > 100.0, "the table keeps its own room: {table}");

        // the rows are still there to be read and clicked, not squeezed out of sight
        let update = frame(&ctx, &mut app, vec![]);
        assert!(!find_all(&update, "#").is_empty(), "the header is on screen");
        assert!(!find_all(&update, &row_label(&app, 1)).is_empty(), "and so is a row");
    }

    /// With no row open there is no pane and no splitter: the table has the whole tab, so a
    /// table with only a few rows in it is not left sitting above an empty strip.
    #[test]
    fn nothing_selected_leaves_no_pane_and_no_gap_under_the_table() {
        let (ctx, mut app) = collab_app();
        app.collab_sel = None;
        let update = frame(&ctx, &mut app, vec![]);
        for pane in ["Request", "Response", "Transcript", "Details", "Callback details"] {
            assert!(find_all(&update, pane).is_empty(), "nothing is open, so {pane:?} is not drawn");
        }
        let header_top = find(&update, "#").top();
        let whole = table_height_to(&ctx, &mut app, header_top);

        // opening a row takes that room for the pane, and closing it gives it all back
        app.collab_sel = Some(2);
        frame(&ctx, &mut app, vec![]);
        let shared = table_height(&ctx, &mut app);
        assert!(shared < whole - 100.0, "the open pane takes its room from the table: {whole} -> {shared}");

        app.collab_sel = None;
        let update = frame(&ctx, &mut app, vec![]);
        assert!(find_all(&update, "Request").is_empty(), "closing it puts the pane away again");
        let back = table_height_to(&ctx, &mut app, find(&update, "#").top());
        assert!((back - whole).abs() < 1.0, "and the table has the whole tab once more: {whole} -> {back}");
    }

    /// The table's height when there is no pane below it: from its header down to the bottom
    /// of the tab, since nothing else is competing for the room.
    fn table_height_to(ctx: &egui::Context, app: &mut App, header_top: f32) -> f32 {
        let _ = frame(ctx, app, vec![]);
        ctx.screen_rect().bottom() - header_top
    }
}
