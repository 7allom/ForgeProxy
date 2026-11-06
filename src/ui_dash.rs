//! Dashboard (picture-8): task list, live passive crawl, scans started with "New scan",
//! their issues and reports, and the "All issues" window.

use crate::actions;
use crate::rules;
use crate::scan::{Finding, Severity};
use crate::state::{App, Tab, Task, TaskKind};
use crate::theme::{self, bold, EmptyIcon, Palette};
use crate::ui_core::sub_tabs;
use eframe::egui;
use egui::{Color32, RichText, Stroke, Ui};

fn sev_color(p: &Palette, s: Severity) -> Color32 {
    match s {
        Severity::High => p.high,
        Severity::Medium => p.medium,
        Severity::Low => p.low,
        Severity::Info => p.info,
        Severity::FalsePositive => p.disabled,
    }
}

pub fn dashboard(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::SidePanel::left("tasks").resizable(false).exact_width(214.0)
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(10)))
        .show_inside(ui, |ui| {
            ui.label(bold("Tasks", 14.0).color(p.strong));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if theme::plain_button(ui, p, "New scan", true).clicked() {
                    app.show_new_scan = true;
                }
                if theme::primary_button(ui, p, "Open browser").clicked() {
                    crate::ui_proxy::open_browser(app);
                }
            });
            ui.add_space(10.0);
            egui::ScrollArea::vertical().show(ui, |ui| {
                for i in 0..app.tasks.len() {
                    task_card(app, ui, p, i);
                    ui.add_space(6.0);
                }
            });
        });
    egui::CentralPanel::default().frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(12))).show_inside(ui, |ui| {
        let i = app.task_sel.min(app.tasks.len().saturating_sub(1));
        let Some(task) = app.tasks.get(i).cloned() else { return };
        ui.label(bold(format!("{}. {}", i + 1, task.title()), 14.0).color(p.strong));
        ui.add_space(4.0);
        match task.kind {
            TaskKind::LiveCrawl => {
                let items: Vec<std::sync::Arc<crate::http::HttpEntry>> = if task.capturing {
                    app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|e| e.tool == "Proxy").cloned().collect()
                } else { Vec::new() };
                live_task(app, ui, p, &task, &items)
            }
            TaskKind::Scan { .. } => {
                sub_tabs(ui, p, &["Summary", "Issues", "Event log"], &mut app.task_sub);
                ui.add_space(8.0);
                match app.task_sub {
                    1 => issues_view(app, ui, p, Some(i)),
                    2 => {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for line in &task.log {
                                ui.label(RichText::new(line).size(12.0).color(p.text));
                            }
                        });
                    }
                    _ => scan_summary(ui, p, &task),
                }
            }
        }
    });
}

fn task_card(app: &mut App, ui: &mut Ui, p: &Palette, i: usize) {
    let sel = app.task_sel == i;
    let mut toggle_rect = None;
    let inner = egui::Frame::new()
        .fill(p.banner)
        .stroke(if sel { Stroke::new(1.5_f32, p.selection) } else { Stroke::NONE })
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let t = &mut app.tasks[i];
            ui.label(bold(format!("{}. {}", i + 1, t.title()), 12.0).color(p.strong));
            match t.kind {
                TaskKind::LiveCrawl => {
                    ui.label(RichText::new("Add links. Add item itself, same domain and URLs in suite scope.").size(11.0).color(p.text));
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Capturing").size(11.0).color(p.text));
                        toggle_rect = Some(theme::toggle(ui, &mut t.capturing).rect);
                    });
                }
                TaskKind::Scan { .. } => {
                    let status = if t.running { format!("Running — {} requests", t.requests) } else { format!("Finished — {} requests", t.requests) };
                    ui.label(RichText::new(status).size(11.0).color(p.text));
                    ui.horizontal(|ui| {
                        for s in [Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
                            let n = t.findings.iter().filter(|f| f.severity == s).count();
                            ui.label(RichText::new(n.to_string()).size(11.0).color(sev_color(p, s)));
                        }
                    });
                }
            }
        });
    let card_rect = inner.response.rect;
    let clicked_card = ui.input(|inp| {
        inp.pointer.primary_clicked()
            && inp.pointer.interact_pos().is_some_and(|pos| {
                card_rect.contains(pos) && !toggle_rect.is_some_and(|r| r.contains(pos))
            })
    });
    if clicked_card {
        app.task_sel = i;
        app.task_sub = 0;
        app.finding_sel = 0;
    }
}

/// Width of the task details card on the right of a task.
const DETAILS_W: f32 = 230.0;

/// The task's details card: a side panel with its own fill and a divider on its left edge,
/// holding sections of label/value pairs.
fn details_card(ui: &mut Ui, p: &Palette, id: &str, sections: &[(&str, Vec<(&str, String)>)], extra: impl FnOnce(&mut Ui)) {
    egui::SidePanel::right(id.to_owned()).resizable(false).exact_width(DETAILS_W)
        .frame(egui::Frame::new().fill(p.deep).stroke(Stroke::new(1.0_f32, p.header)).inner_margin(egui::Margin::same(12)))
        .show_inside(ui, |ui| {
            egui::ScrollArea::vertical().id_salt((id, "scroll")).auto_shrink([false, false]).show(ui, |ui| {
                for (n, (title, rows)) in sections.iter().enumerate() {
                    if n > 0 {
                        ui.add_space(10.0);
                        ui.separator();
                        ui.add_space(6.0);
                    }
                    ui.label(bold(*title, 13.0).color(p.strong));
                    ui.add_space(6.0);
                    for (k, v) in rows {
                        // label above value: long values wrap within the card
                        ui.label(RichText::new(*k).size(11.5).color(p.disabled));
                        ui.add(egui::Label::new(RichText::new(v).size(12.5).color(p.text)).wrap());
                        ui.add_space(6.0);
                    }
                }
                extra(ui);
            });
        });
}

fn live_task(app: &mut App, ui: &mut Ui, p: &Palette, task: &Task, items: &[std::sync::Arc<crate::http::HttpEntry>]) {
    ui.add_space(6.0);
    let mut open_browser = false;
    let mut picked: Option<&crate::http::HttpEntry> = None;
    let added = items.iter().map(|e| (e.host.clone(), e.path.clone())).collect::<std::collections::HashSet<_>>().len();
    details_card(ui, p, "live_task_details", &[
        ("Task configuration", vec![
            ("Task type", "Live passive crawl".to_string()),
            ("Scope", "Proxy (all traffic)".to_string()),
            ("Configuration", "Add links. Add item itself, same domain and URLs in suite scope.".to_string()),
            ("Capturing", if task.capturing { "On" } else { "Off" }.to_string()),
        ]),
        ("Task progress", vec![
            ("Site map items added", added.to_string()),
            ("Responses processed", items.len().to_string()),
            ("Responses queued", "0".to_string()),
        ]),
    ], |_| {});
    egui::CentralPanel::default().frame(egui::Frame::new().inner_margin(egui::Margin { right: 12, ..Default::default() })).show_inside(ui, |ui| {
        ui.label(bold("Items added to site map", 13.0).color(p.strong));
        ui.add_space(4.0);
        // the table fills whatever space the panel has
        const COLS: [(f32, f32); 5] = [(120.0, 0.25), (60.0, 0.0), (140.0, 0.45), (80.0, 0.0), (90.0, 0.3)];
        let h = ui.available_height().max(120.0);
        theme::fitted_table(ui, p, "live_items_table", h, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Host", w[0]), ("Method", w[1]), ("URL", w[2]), ("Status code", w[3]), ("MIME type", w[4])]);
            if items.is_empty() {
                let (_, open) = theme::empty_state(ui, p, EmptyIcon::SiteMap, "No items to show", "Pages you visit in the proxy browser will display here.", Some("Open browser"));
                open_browser = open;
            } else {
                egui::ScrollArea::vertical().id_salt("live_items").auto_shrink([false, false]).show(ui, |ui| {
                    for (i, e) in items.iter().enumerate() {
                        let cells = [(e.host.clone(), w[0], None), (e.method.clone(), w[1], None), (e.path.clone(), w[2], None), (e.status.clone(), w[3], None), (e.mime.clone(), w[4], None)];
                        if theme::table_row(ui, p, &cells, false, i % 2 == 1).clicked() {
                            picked = Some(e);
                        }
                    }
                });
            }
        });
    });
    if open_browser {
        crate::ui_proxy::open_browser(app);
    }
    if let Some(e) = picked {
        // show the item in Target > Site map: its host/path selected in the tree, its request below
        app.tab = Tab::Target;
        app.target_sub = 0;
        app.sitemap_path = Some(format!("{}{}", e.host, e.path));
        app.history_sel = Some(e.id);
    }
}

fn scan_summary(ui: &mut Ui, p: &Palette, task: &Task) {
    let kind = match task.kind { TaskKind::Scan { crawl: true } => "Crawl and audit", _ => "Audit" };
    let limits = format!("Link depth {}, up to {} locations, {} minutes", rules::CRAWL_MAX_LINK_DEPTH, rules::CRAWL_MAX_UNIQUE_LOCATIONS, rules::CRAWL_MAX_TIME_MIN);
    let state = if task.running { "Running" } else { "Finished" };
    details_card(ui, p, "scan_task_details", &[
        ("Task configuration", vec![("Task type", kind.to_string()), ("Scope", task.url.clone()), ("Configuration", limits)]),
        ("Task progress", vec![("Status", state.to_string()), ("Requests made", task.requests.to_string()), ("Issues found", task.findings.len().to_string())]),
    ], |ui| { if task.running { ui.spinner(); } });
    egui::CentralPanel::default().frame(egui::Frame::new().inner_margin(egui::Margin { right: 12, ..Default::default() })).show_inside(ui, |ui| {
        ui.label(bold("Issues", 13.0).color(p.strong));
        ui.add_space(6.0);
        let max = task.findings.len().max(1) as f32;
        for s in [Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
            let n = task.findings.iter().filter(|f| f.severity == s).count();
            ui.horizontal(|ui| {
                ui.add_sized([90.0, 18.0], egui::Label::new(RichText::new(s.label()).color(p.text)));
                let bar_w = (ui.available_width() - 40.0).clamp(80.0, 360.0);
                let (r, _) = ui.allocate_exact_size(egui::vec2(bar_w, 12.0), egui::Sense::hover());
                ui.painter().rect_filled(r, 2.0, p.deep);
                let w = r.width() * (n as f32 / max);
                ui.painter().rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(w, r.height())), 2.0, sev_color(p, s));
                ui.label(RichText::new(n.to_string()).color(p.text));
            });
        }
    });
}

/// Issue list + detail. `task` = one scan task, or None for every task ("All issues").
pub(crate) fn issues_view(app: &mut App, ui: &mut Ui, p: &Palette, task: Option<usize>) {
    let mut list: Vec<(usize, usize, Finding)> = Vec::new();
    for (ti, t) in app.tasks.iter().enumerate() {
        if task.is_some_and(|x| x != ti) { continue; }
        for (fi, f) in t.findings.iter().enumerate() {
            list.push((ti, fi, f.clone()));
        }
    }
    ui.horizontal(|ui| {
        for fmt in ["HTML", "XML"] {
            if theme::plain_button(ui, p, &format!("Export report ({fmt})"), !list.is_empty()).clicked() {
                let findings: Vec<Finding> = list.iter().map(|x| x.2.clone()).collect();
                app.report_msg = export_report(&findings, &fmt.to_ascii_lowercase());
            }
        }
        if !app.report_msg.is_empty() {
            ui.label(RichText::new(&app.report_msg).size(12.0).color(p.text));
        }
    });
    ui.add_space(4.0);
    if list.is_empty() {
        let _ = theme::empty_state(ui, p, EmptyIcon::SiteMap, "No issues yet", "Issues found by your scans will display here.", None);
        return;
    }
    let sel = app.finding_sel.min(list.len() - 1);
    ui.columns(2, |cols| {
        theme::table_well(&mut cols[0], p, 420.0, |ui| {
            theme::table_header(ui, p, &[("Issue", 260.0), ("Host", 150.0), ("Severity", 90.0)]);
            egui::ScrollArea::vertical().id_salt(("issues", task)).show(ui, |ui| {
                for (k, (_, _, f)) in list.iter().enumerate() {
                    let r = theme::table_row(ui, p, &[
                        (f.name.clone(), 260.0, None),
                        (format!("{}{}", f.host, f.path), 150.0, None),
                        (f.severity.label().into(), 90.0, Some(sev_color(p, f.severity))),
                    ], k == sel, k % 2 == 1);
                    if r.clicked() { app.finding_sel = k; }
                }
            });
        });
        let (ti, fi, f) = list[sel].clone();
        let ui = &mut cols[1];
        ui.label(bold(&f.name, 15.0).color(p.strong));
        ui.horizontal(|ui| {
            ui.colored_label(sev_color(p, f.severity), format!("Severity: {}", f.severity.label()));
            ui.label(RichText::new(format!("Confidence: {}", f.confidence.label())).color(p.text));
        });
        ui.label(RichText::new(format!("{}{}", f.host, f.path)).monospace().color(p.disabled));
        ui.label(RichText::new(format!("Type index 0x{:08x}", f.type_index)).size(11.0).color(p.disabled));
        let fp = f.severity == Severity::FalsePositive;
        if theme::plain_button(ui, p, if fp { "Undo false positive" } else { "Mark as false positive" }, true).clicked() {
            let typical = crate::issue_defs::ISSUE_DEFS.iter().find(|d| d.0 == f.type_index).map(|d| d.2).unwrap_or("Information");
            app.tasks[ti].findings[fi].severity = if fp {
                match typical { "High" => Severity::High, "Medium" => Severity::Medium, "Low" => Severity::Low, _ => Severity::Info }
            } else { Severity::FalsePositive };
        }
        ui.separator();
        ui.label(bold("Issue detail", 13.0).color(p.strong));
        ui.add(egui::Label::new(RichText::new(&f.detail).color(p.text)).wrap());
    });
}

/// Floating windows: "New scan" and "All issues".
pub fn windows(app: &mut App, ctx: &egui::Context, p: &Palette) {
    if app.show_new_scan {
        let mut open = true;
        let mut start = false;
        egui::Window::new(bold("New scan", 14.0).color(p.strong))
            .open(&mut open).collapsible(false).resizable(false).default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(bold("Scan type", 13.0).color(p.strong));
                ui.radio_value(&mut app.new_scan_crawl, true, "Crawl and audit");
                ui.radio_value(&mut app.new_scan_crawl, false, "Audit only (no crawl)");
                ui.add_space(8.0);
                ui.label(bold("URLs to scan", 13.0).color(p.strong));
                ui.add(egui::TextEdit::multiline(&mut app.new_scan_urls).desired_rows(4).desired_width(f32::INFINITY).hint_text("https://example.com/  (one per line)"));
                ui.add_space(6.0);
                ui.label(RichText::new(format!(
                    "Configuration: crawl up to {} links deep and {} locations, {} minutes at most; repeated issues are merged.",
                    rules::CRAWL_MAX_LINK_DEPTH, rules::CRAWL_MAX_UNIQUE_LOCATIONS, rules::CRAWL_MAX_TIME_MIN)).size(11.5).color(p.disabled));
                ui.label(RichText::new("Only scan sites you own or have permission to test.").size(11.5).color(p.disabled));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::primary_button(ui, p, "OK").clicked() { start = true; }
                        if theme::plain_button(ui, p, "Cancel", true).clicked() { app.show_new_scan = false; }
                    });
                });
            });
        if start {
            let urls: Vec<String> = app.new_scan_urls.lines().map(|l| l.trim().to_string()).filter(|l| l.starts_with("http://") || l.starts_with("https://")).collect();
            let crawl = app.new_scan_crawl;
            for u in urls {
                actions::start_scan(app, u, crawl);
            }
            app.show_new_scan = false;
        }
        if !open { app.show_new_scan = false; }
    }
}

fn export_report(findings: &[Finding], fmt: &str) -> String {
    let path = crate::paths::documents_dir().join(format!("forgeproxy-report.{fmt}")).display().to_string();
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let body = if fmt == "xml" {
        let mut s = String::from("<?xml version=\"1.0\"?>\n<issues>\n");
        for f in findings {
            s.push_str(&format!(
                "  <issue>\n    <type>{}</type>\n    <name>{}</name>\n    <severity>{}</severity>\n    <confidence>{}</confidence>\n    <host>{}</host>\n    <path>{}</path>\n  </issue>\n",
                f.type_index, esc(&f.name), f.severity.label(), f.confidence.label(), esc(&f.host), esc(&f.path)));
        }
        s.push_str("</issues>\n");
        s
    } else {
        let mut s = String::from("<!doctype html><html><head><meta charset=\"utf-8\"><title>Scan report</title></head><body><h1>Scan report</h1>\n");
        for f in findings {
            let (r, g, b) = f.severity.rgb();
            s.push_str(&format!(
                "<h2 style=\"color:#{r:02x}{g:02x}{b:02x}\">{} — {}</h2><p><b>Host:</b> {}{}<br><b>Confidence:</b> {}</p><p>{}</p>\n",
                esc(&f.name), f.severity.label(), esc(&f.host), esc(&f.path), f.confidence.label(), esc(&f.detail)));
        }
        s.push_str("</body></html>\n");
        s
    };
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&path, body) {
        Ok(_) => format!("Saved {} issues to {path}", findings.len()),
        Err(e) => format!("Couldn't save the report: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dash_app() -> (egui::Context, App) {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = App::new(&cc, Some("/dev/null".into()), Some(Tab::Dashboard), false);
        app.force_exit = false;
        (ctx, app)
    }

    fn frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 800.0))),
            events,
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    fn click_at(ctx: &egui::Context, app: &mut App, at: egui::Pos2) {
        let button = |pressed| egui::Event::PointerButton { pos: at, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        frame(ctx, app, vec![egui::Event::PointerMoved(at), button(true)]);
        frame(ctx, app, vec![button(false)]);
        frame(ctx, app, vec![]);
    }

    fn find_rect(update: &Option<egui::accesskit::TreeUpdate>, label: &str, role: Option<egui::accesskit::Role>) -> egui::accesskit::Rect {
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        nodes
            .iter()
            .find(|(_, n)| (n.label() == Some(label) || n.value() == Some(label)) && role.is_none_or(|r| n.role() == r))
            .and_then(|(_, n)| n.bounds())
            .unwrap_or_else(|| panic!("no widget labelled {label:?} with role {role:?}"))
    }

    fn center(r: egui::accesskit::Rect) -> egui::Pos2 {
        egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32)
    }

    #[test]
    fn capturing_toggle_flips_and_persists_state() {
        let (ctx, mut app) = dash_app();
        assert!(app.tasks[0].capturing, "Live crawl starts with capturing on");

        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let toggle_pos = center(find_rect(&update, "Capturing", Some(egui::accesskit::Role::CheckBox)));

        click_at(&ctx, &mut app, toggle_pos);
        assert!(!app.tasks[0].capturing, "Clicking toggle turns capturing off");

        click_at(&ctx, &mut app, toggle_pos);
        assert!(app.tasks[0].capturing, "Clicking toggle again turns capturing back on");
    }

    #[test]
    fn clicking_task_card_selects_task() {
        let (ctx, mut app) = dash_app();
        app.tasks.push(Task {
            kind: TaskKind::Scan { crawl: false },
            url: "http://example.com/".into(),
            capturing: false,
            running: false,
            requests: 3,
            findings: Vec::new(),
            log: Vec::new(),
        });
        assert_eq!(app.task_sel, 0);

        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let card2_pos = center(find_rect(&update, "2. Audit of example.com", None));

        click_at(&ctx, &mut app, card2_pos);
        assert_eq!(app.task_sel, 1, "Clicking second task card selects it");
    }

    #[test]
    fn new_scan_modal_url_input_defaults_to_empty() {
        let (ctx, mut app) = dash_app();
        assert!(app.new_scan_urls.is_empty(), "new_scan_urls starts empty");
        app.show_new_scan = true;
        frame(&ctx, &mut app, vec![]);
        assert!(app.new_scan_urls.is_empty(), "opening New scan keeps URL buffer empty");
    }
}
