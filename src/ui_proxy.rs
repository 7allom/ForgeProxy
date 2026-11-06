//! Proxy screens (picture-12..15, 27, 58): Intercept, HTTP history, Match and replace, Proxy settings.

use crate::editor;
use crate::proxy::{self, Decision};
use crate::rewrite::{self, RuleType};
use crate::rules;
use crate::state::App;
use crate::theme::{self, bold, EmptyIcon, Palette};
use crate::ui_core::sub_tabs;
use eframe::egui;
use egui::{Color32, FontId, RichText, Ui};
use std::sync::atomic::Ordering;

pub fn proxy(app: &mut App, ui: &mut Ui, p: &Palette) {
    sub_tabs(ui, p, &["Intercept", "HTTP history", "Match and replace", "Proxy settings"], &mut app.proxy_sub);
    match app.proxy_sub {
        1 => history(app, ui, p),
        2 => match_replace(app, ui, p),
        3 => settings(app, ui, p),
        _ => intercept(app, ui, p),
    }
}

/// Open the proxy browser (used by every "Open browser" button and the globe icon).
pub fn open_browser(app: &mut App) {
    if !app.proxy.running.load(Ordering::SeqCst) {
        start_listener(app);
    }
    let port: u16 = app.proxy_port.trim().parse().unwrap_or(rules::PROXY_PORT);
    // with HTTPS interception on, let a Chromium-family browser trust the root CA by its key
    let decrypting = app.proxy.decrypt_https.load(Ordering::SeqCst);
    let pin = app.ca.as_ref()
        .filter(|_| decrypting)
        .and_then(|ca| ca.spki_sha256_base64().ok());
    let unencrypted_warning = launch_warning(decrypting, pin.is_some());
    // the full message (browser, pin, restart note) goes to the Event log; the toolbar gets
    // a short status
    app.proxy_msg = match crate::browser::open(app.proxy_host.trim(), port, "about:blank", pin.as_deref()) {
        Ok(m) => {
            proxy::log(&app.proxy.events, m);
            match unencrypted_warning {
                Some(w) => {
                    proxy::log_warning(&app.proxy.events, w);
                    "Browser opened: HTTPS not intercepted (see Event log)".to_string()
                }
                None => "Browser opened (isolated profile)".to_string(),
            }
        }
        Err(e) => { proxy::log_error(&app.proxy.events, e); "Couldn't open a browser (see Event log)".to_string() }
    };
}

/// The Event log warning for "Open browser" when the launched browser's HTTPS won't be
/// intercepted: interception switched off, or on but without a root CA to pin.
fn launch_warning(decrypting: bool, have_pin: bool) -> Option<&'static str> {
    if !decrypting {
        Some("Browser launched with HTTPS interception disabled; HTTPS traffic will pass through uninspected.")
    } else if !have_pin {
        Some("Browser launched without a root CA (see Settings > Proxy > Root CA certificate); HTTPS traffic will pass through uninspected.")
    } else {
        None
    }
}

pub fn start_listener(app: &mut App) {
    let addr = format!("{}:{}", app.proxy_host.trim(), app.proxy_port.trim());
    if let Err(e) = proxy::start(app.proxy.clone(), addr) {
        proxy::log_error(&app.proxy.events, e.clone());
        app.proxy_msg = e;
    } else {
        app.proxy_msg.clear();
        if !proxy::is_loopback_interface(&app.proxy_host) {
            proxy::log_warning(&app.proxy.events, proxy::exposed_listener_warning(&app.proxy_host));
        }
    }
}

/// Load the front of the Intercept queue into the editor when it isn't there yet (a new
/// request reached the front); clear the editor when the queue is empty. Returns the
/// front request's URL, or None when nothing is held.
fn sync_held(app: &mut App) -> Option<String> {
    let held = app.proxy.held.lock().unwrap_or_else(|e| e.into_inner());
    match held.first() {
        Some(h) => {
            if app.held_loaded != Some(h.id) {
                app.held_edit = h.raw.clone();
                app.held_loaded = Some(h.id);
            }
            Some(h.url.clone())
        }
        None => {
            if app.held_loaded.take().is_some() {
                app.held_edit.clear();
            }
            None
        }
    }
}

fn intercept(app: &mut App, ui: &mut Ui, p: &Palette) {
    let held_count = app.proxy.held.lock().unwrap_or_else(|e| e.into_inner()).len();
    sync_held(app);
    egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(8, 6)).show(ui, |ui| {
        ui.horizontal(|ui| {
            let on = app.proxy.intercept.load(Ordering::SeqCst);
            let (txt, col, tc) = if on { ("Intercept on", p.accent, Color32::WHITE) } else { ("Intercept off", p.header, p.text) };
            if ui.add(egui::Button::new(bold(txt, 12.5).color(tc)).fill(col).min_size(egui::vec2(0.0, 22.0))).clicked() {
                toggle_intercept(app);
            }
            if theme::plain_button(ui, p, "Forward", held_count > 0).clicked() { forward(app); }
            if theme::plain_button(ui, p, "Drop", held_count > 0).clicked() { drop_held(app); }
            ui.add_space(8.0);
            ui.checkbox(&mut app.intercept_only_in_scope, "Only in scope")
                .on_hover_text("Hold only requests inside Target > Scope; everything else is forwarded straight away (and still recorded in HTTP history)");
            if app.intercept_only_in_scope && !app.target_scope.include.iter().any(|r| r.enabled && !r.prefix.trim().is_empty()) {
                ui.label(RichText::new("(scope is empty: every request counts as in scope)").size(11.5).color(p.disabled))
                    .on_hover_text("Add include rules in Target > Scope to narrow it");
            }
            if held_count > 1 {
                ui.label(RichText::new(format!("{held_count} requests waiting")).size(12.0).color(p.text));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if held_count > 0 {
                    crate::ui_inspector::toggle_button(ui, &mut app.inspector);
                }
                if theme::plain_button(ui, p, "Open browser", true).clicked() { open_browser(app); }
                if !app.proxy_msg.is_empty() {
                    // only the space the buttons leave; truncated with "…" (full text on hover)
                    // so it can never run over Forward, Drop or Only in scope
                    let room = (ui.available_width() - 8.0).clamp(0.0, 320.0);
                    if room > 40.0 {
                        ui.allocate_ui_with_layout(egui::vec2(room, 22.0), egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add(egui::Label::new(RichText::new(&app.proxy_msg).size(12.0).color(p.disabled)).truncate())
                                .on_hover_text(&app.proxy_msg);
                        });
                    }
                }
            });
        });
    });
    // the toolbar may just have forwarded, dropped or released requests (Intercept off), so
    // look at the queue again rather than trusting `held_count`
    if let Some(url) = sync_held(app) {
        ui.label(RichText::new(format!("Request to {url}")).size(12.5).color(p.text));
        // the Inspector follows the edits: it parses the held request as it stands
        let held = app.held_loaded.map_or(String::new(), |id| id.to_string());
        crate::ui_inspector::inspector_panel(ui, p, &mut app.inspector, "intercept", &held, &app.held_edit, None);
        editor::message_editor(ui, p, "held", &mut app.held_edit, true, false, ui.available_height() - 10.0);
        return;
    }
    let on = app.proxy.intercept.load(Ordering::SeqCst);
    let (title, text) = if on {
        ("Intercept is on", "Requests from the proxy browser stop here so you can change them, then Forward or Drop them. Images, scripts and style sheets pass straight through.")
    } else {
        ("Intercept is off", "If you turn Intercept on, requests between the browser and your target servers are held here. This lets you view and change them before they are forwarded.")
    };
    let (_, open) = theme::empty_state(ui, p, EmptyIcon::Intercept, title, text, Some("Open browser"));
    if open { open_browser(app); }
}

pub fn toggle_intercept(app: &mut App) {
    let on = !app.proxy.intercept.load(Ordering::SeqCst);
    app.proxy.intercept.store(on, Ordering::SeqCst);
    if !on {
        // release everything that was waiting, unchanged
        for h in app.proxy.held.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            let _ = h.reply.send(Decision::Forward(h.raw));
        }
        app.held_loaded = None;
        app.held_edit.clear();
    }
}

/// Forward the front request: as edited when the editor holds it, otherwise unchanged (say,
/// Ctrl+F from another tab before it was ever shown).
pub fn forward(app: &mut App) {
    let mut held = app.proxy.held.lock().unwrap_or_else(|e| e.into_inner());
    if !held.is_empty() {
        let h = held.remove(0);
        let text = if app.held_loaded == Some(h.id) { app.held_edit.clone() } else { h.raw };
        let _ = h.reply.send(Decision::Forward(text));
    }
    app.held_loaded = None;
}

pub fn drop_held(app: &mut App) {
    let mut held = app.proxy.held.lock().unwrap_or_else(|e| e.into_inner());
    if !held.is_empty() {
        let h = held.remove(0);
        let _ = h.reply.send(Decision::Drop);
    }
    app.held_loaded = None;
}

fn history(app: &mut App, ui: &mut Ui, p: &Palette) {
    let has = app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|e| e.tool == "Proxy");
    if !has {
        let (_, open) = theme::empty_state(ui, p, EmptyIcon::History, "HTTP history is empty",
            "This shows all HTTP traffic between the proxy browser and your target applications, even while intercept is off.", Some("Open browser"));
        if open { open_browser(app); }
        return;
    }
    crate::ui_tools::traffic_view(app, ui, p, crate::ui_tools::View::ProxyHistory);
}

fn match_replace(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.add_space(8.0);
    theme::section_title(ui, p, "HTTP match and replace rules", "Use these settings to automatically replace parts of HTTP requests and responses passing through the Proxy (and sent from Repeater).");
    ui.add_space(6.0);
    rules_editor(app, ui, p, "mr_tab", false);
}

/// Match-and-replace rules: side buttons, the rule table and an editor for the selected
/// rule. Used by Proxy > Match and replace and by Settings > Proxy. With `edit_button`
/// the editor opens from an "Edit" button (or "Add"); without it, selecting a rule opens it.
pub fn rules_editor(app: &mut App, ui: &mut Ui, p: &Palette, id: &str, edit_button: bool) {
    let editing_id = egui::Id::new(("mr_editing", id));
    let mut editing: bool = ui.data(|d| d.get_temp(editing_id)).unwrap_or(false);
    let n = app.mr_rules.len();
    let sel = app.mr_sel.filter(|&i| i < n);
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            if theme::side_button(ui, p, "Add", true).clicked() {
                app.mr_rules.push(rewrite::Rule { enabled: true, kind: RuleType::RequestHeader, regex: false, match_text: String::new(), replace_text: String::new(), comment: String::new() });
                app.mr_sel = Some(app.mr_rules.len() - 1);
                editing = true;
            }
            if edit_button && theme::side_button(ui, p, "Edit", sel.is_some()).clicked() {
                editing = !editing;
            }
            if theme::side_button(ui, p, "Remove", sel.is_some()).clicked() {
                if let Some(i) = sel { app.mr_rules.remove(i); app.mr_sel = None; editing = false; }
            }
            if theme::side_button(ui, p, "Up", sel.is_some_and(|i| i > 0)).clicked() {
                if let Some(i) = sel { app.mr_rules.swap(i, i - 1); app.mr_sel = Some(i - 1); }
            }
            if theme::side_button(ui, p, "Down", sel.is_some_and(|i| i + 1 < n)).clicked() {
                if let Some(i) = sel { app.mr_rules.swap(i, i + 1); app.mr_sel = Some(i + 1); }
            }
        });
        // (minimum width, share of the spare width) for Enabled, Item, Match, Replace, Type, Comment
        const COLS: [(f32, f32); 6] = [(64.0, 0.0), (110.0, 0.16), (120.0, 0.26), (140.0, 0.34), (60.0, 0.0), (100.0, 0.24)];
        theme::fitted_table(ui, p, ("mr_table", id), 230.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Enabled", w[0]), ("Item", w[1]), ("Match", w[2]), ("Replace", w[3]), ("Type", w[4]), ("Comment", w[5])]);
            egui::ScrollArea::vertical().id_salt(("mr_rows", id)).auto_shrink([false, true]).show(ui, |ui| {
                for i in 0..app.mr_rules.len() {
                    let r = &app.mr_rules[i];
                    let cells = [
                        (if r.enabled { "Yes" } else { "" }.to_string(), w[0], None),
                        (r.kind.label().to_string(), w[1], None),
                        (r.match_text.clone(), w[2], None),
                        (r.replace_text.clone(), w[3], None),
                        (if r.regex { "Regex" } else { "Literal" }.to_string(), w[4], None),
                        (r.comment.clone(), w[5], None),
                    ];
                    let row = theme::table_row(ui, p, &cells, sel == Some(i), i % 2 == 1);
                    if row.clicked() { app.mr_sel = Some(i); }
                    if row.double_clicked() { editing = true; }
                }
            });
        });
    });
    let show_editor = if edit_button { editing } else { true };
    if let Some(i) = app.mr_sel.filter(|&i| show_editor && i < app.mr_rules.len()) {
        ui.add_space(8.0);
        ui.label(bold("Edit selected rule", 13.0).color(p.strong));
        let r = &mut app.mr_rules[i];
        egui::Grid::new(("mr_edit", id)).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.label("Enabled:"); ui.checkbox(&mut r.enabled, ""); ui.end_row();
            ui.label("Type:");
            egui::ComboBox::from_id_salt(("mr_type", id)).selected_text(r.kind.label()).show_ui(ui, |ui| {
                for t in RuleType::ALL { ui.selectable_value(&mut r.kind, t, t.label()); }
            });
            ui.end_row();
            ui.label("Match:"); ui.add(egui::TextEdit::singleline(&mut r.match_text).desired_width(460.0).font(FontId::monospace(12.5))); ui.end_row();
            ui.label("Replace:"); ui.add(egui::TextEdit::singleline(&mut r.replace_text).desired_width(460.0).font(FontId::monospace(12.5))); ui.end_row();
            ui.label("Regex match:"); ui.checkbox(&mut r.regex, ""); ui.end_row();
            ui.label("Comment:"); ui.add(egui::TextEdit::singleline(&mut r.comment).desired_width(460.0)); ui.end_row();
        });
        ui.label(RichText::new("Header rules work line by line: a blank match adds the replacement as a new header; a blank replacement removes matching headers.").size(11.5).color(p.disabled));
    }
    ui.data_mut(|d| d.insert_temp(editing_id, editing));
}

fn settings(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.add_space(8.0);
    theme::section_title(ui, p, "Proxy listener", "The proxy receives requests from your browser here. \"Open browser\" starts a browser already set to use it.");
    ui.add_space(8.0);
    let running = app.proxy.running.load(Ordering::SeqCst);
    ui.horizontal(|ui| {
        ui.label("Interface:");
        ui.add_enabled(!running, egui::TextEdit::singleline(&mut app.proxy_host).desired_width(130.0));
        ui.label(":");
        ui.add_enabled(!running, egui::TextEdit::singleline(&mut app.proxy_port).desired_width(60.0));
        if running {
            if theme::plain_button(ui, p, "Stop", true).clicked() { app.proxy.stop.store(true, Ordering::SeqCst); }
            ui.label(RichText::new("Running").color(p.st_done));
        } else {
            if theme::primary_button(ui, p, "Start").clicked() { start_listener(app); }
            ui.label(RichText::new("Stopped").color(p.disabled));
        }
        if theme::plain_button(ui, p, "Open browser", true).clicked() { open_browser(app); }
    });
    if !app.proxy_msg.is_empty() {
        ui.label(RichText::new(&app.proxy_msg).size(12.0).color(p.text));
    }
    ui.add_space(14.0);
    theme::section_title(ui, p, "Request interception rule", "Which requests Intercept holds.");
    let skipped = if app.skip_extensions.is_empty() { "none".to_string() } else { app.skip_extensions.iter().map(|e| format!(".{e}")).collect::<Vec<_>>().join(", ") };
    ui.label(RichText::new(format!("Requests for files ending in {skipped} pass through without stopping (edit the list in Settings > Proxy > Skipped file extensions).")).size(12.0).color(p.text));
    ui.add_space(14.0);
    theme::section_title(ui, p, "HTTPS", "How encrypted traffic is handled.");
    let decrypting = app.proxy.decrypt_https.load(Ordering::SeqCst) && app.tls_cache.is_some();
    let text = if decrypting {
        "HTTPS is intercepted: each site gets a certificate signed by the root CA, and decrypted requests appear in HTTP history and go through Intercept and match-and-replace. Turn it off in Settings > Proxy."
    } else {
        "HTTPS is passed through unopened and appears in HTTP history as one tunnel per connection. To see inside it, turn on Intercept HTTPS in Settings > Proxy and install the root CA in your browser."
    };
    ui.label(RichText::new(text).size(12.0).color(p.text));
}

// ---- Traffic filter ribbon (HTTP history, and the site map and Logger tables) ---------

/// The filter ribbon: search (with clear and Regex), Scope only, Hide static, Hide failed,
/// the status-class pills and "Showing X of Y requests". `shown` and `total` are the rows
/// left after filtering and the rows the view has.
pub fn filter_ribbon(app: &mut App, ui: &mut Ui, p: &Palette, shown: usize, total: usize) {
    let f = &mut app.history_filter;
    egui::Frame::new().fill(p.header).corner_radius(4.0).inner_margin(egui::Margin::symmetric(8, 4)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            // search, with an "×" to clear it; red while a regex doesn't compile
            let bad = f.regex_error();
            let hint = if f.is_regex { "Regex search" } else { "Search host, path, status..." };
            let mut edit = egui::TextEdit::singleline(&mut f.search_term).id_salt("history_search").hint_text(hint).desired_width(230.0);
            let tip = "Matches method, host, path, status code or MIME type (ignoring case)";
            if bad {
                edit = edit.text_color(p.high);
            }
            let r = ui.add(edit).on_hover_text(tip);
            if bad {
                r.on_hover_text("This regular expression doesn't compile, so nothing is filtered by it");
            }
            if ui.add_enabled(!f.search_term.is_empty(), egui::Button::new("×").frame(false)).on_hover_text("Clear the search").clicked() {
                f.search_term.clear();
            }
            if pill(ui, p, ".* Regex", f.is_regex).on_hover_text("Treat the search as a regular expression (case-insensitive)").clicked() {
                f.is_regex = !f.is_regex;
            }
            ui.separator();
            if pill(ui, p, "Scope only", f.only_in_scope).on_hover_text("Only requests inside Target > Scope").clicked() {
                f.only_in_scope = !f.only_in_scope;
            }
            if pill(ui, p, "Hide static", f.hide_static_assets).on_hover_text("Hide requests for the file types in Settings > Proxy > Skipped file extensions (images, scripts, styles, fonts...)").clicked() {
                f.hide_static_assets = !f.hide_static_assets;
            }
            if pill(ui, p, "Hide failed", f.hide_no_response).on_hover_text("Hide requests that got no HTTP response (connection failed, or still waiting)").clicked() {
                f.hide_no_response = !f.hide_no_response;
            }
            ui.separator();
            for (label, on) in [("2xx", &mut f.show_2xx), ("3xx", &mut f.show_3xx), ("4xx", &mut f.show_4xx), ("5xx", &mut f.show_5xx)] {
                if pill(ui, p, label, *on).on_hover_text(format!("Show {label} responses")).clicked() {
                    *on = !*on;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !f.is_default_filter() && theme::plain_button(ui, p, "Reset", true).on_hover_text("Show everything again").clicked() {
                    f.reset_filter();
                }
                let col = if shown < total { p.accent } else { p.text };
                ui.label(RichText::new(format!("Showing {shown} of {total} requests")).size(12.0).color(col));
            });
        });
    });
}

fn pill(ui: &mut Ui, p: &Palette, label: &str, on: bool) -> egui::Response {
    theme::pill(ui, p, label, on)
}

/// What was chosen in a row's right-click menu.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RowAction { AddToScope, RemoveFromScope, Send(crate::actions::SendTo) }

/// Right-click menu for a history row or site map item. Drawing can't change the app, so
/// it returns the choice; `scope_menu_apply` carries it out.
pub fn scope_menu_pick(ui: &mut Ui, scope: &crate::scope::TargetScope, e: &crate::http::HttpEntry, prefix: &str) -> Option<RowAction> {
    use crate::actions::SendTo;
    let in_scope = scope.is_in_scope(&crate::actions::entry_url(e));
    let mut pick = None;
    ui.label(RichText::new(prefix).monospace().size(11.5));
    ui.separator();
    if ui.button("Add to scope").clicked() { pick = Some(RowAction::AddToScope); }
    if ui.add_enabled(in_scope, egui::Button::new("Remove from scope")).on_disabled_hover_text("Already out of scope").clicked() {
        pick = Some(RowAction::RemoveFromScope);
    }
    ui.separator();
    for (label, to) in [("Send to Repeater", SendTo::Repeater), ("Send to Intruder", SendTo::Intruder), ("Send to Sequencer", SendTo::Sequencer),
                        ("Send to Organizer", SendTo::Organizer), ("Send request to Comparer", SendTo::ComparerRequest), ("Send response to Comparer", SendTo::Comparer)] {
        if ui.button(label).clicked() { pick = Some(RowAction::Send(to)); }
    }
    ui.separator();
    if ui.button("Copy as cURL").on_hover_text("Copy the request as a curl command").clicked() {
        ui.ctx().copy_text(crate::actions::entry_as_curl(e));
        ui.close_menu();
    }
    if pick.is_some() { ui.close_menu(); }
    pick
}

pub fn scope_menu_apply(app: &mut App, e: &crate::http::HttpEntry, prefix: &str, action: RowAction) {
    match action {
        RowAction::AddToScope => app.target_scope.add(prefix),
        RowAction::RemoveFromScope => app.target_scope.remove(prefix, &crate::actions::entry_url(e)),
        RowAction::Send(to) => crate::actions::send_to(app, e, to),
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn browser_launch_warnings() {
        assert_eq!(launch_warning(true, true), None, "the default: intercepted, nothing to warn about");
        assert_eq!(launch_warning(false, false), Some("Browser launched with HTTPS interception disabled; HTTPS traffic will pass through uninspected."));
        assert_eq!(launch_warning(false, true), launch_warning(false, false), "the pin isn't used when interception is off");
        assert!(launch_warning(true, false).unwrap().contains("without a root CA"));
    }
    use crate::history::{status_class, HistoryFilter};
    use crate::http::HttpEntry;

    fn entry(url: &str, status: &str) -> HttpEntry {
        let (host, path) = crate::http::split_url(url);
        HttpEntry { id: 0, tool: "Proxy".into(), method: "GET".into(), host, path, status: status.into(), length: 0,
            mime: "text/html".into(), request: String::new(), response: String::new(), url: url.into(), truncated: false, time: 0 }
    }

    #[test]
    fn status_classes() {
        let class = |s: &str| status_class(&entry("http://a.test/", s));
        assert_eq!(class("200 OK"), Some(2));
        assert_eq!(class("404 Not Found"), Some(4));
        // CONNECT tunnels: the handshake answered 200 (and so did older recordings)
        assert_eq!(class("200 (Tunnel)"), Some(2));
        assert_eq!(class("Tunnel (encrypted)"), Some(2));
        // no response at all
        assert_eq!(class(crate::http::CONNECTION_FAILED), None);
        assert_eq!(class("— (transport error)"), None);
        assert_eq!(class(""), None);
    }

    #[test]
    fn connect_tunnels_are_2xx_responses() {
        let scope = crate::scope::TargetScope::default();
        let skip = crate::rules::default_skip_extensions();
        let tunnel = entry("https://a.test/", "200 (Tunnel)");
        let failed = entry("https://c.test/", crate::http::CONNECTION_FAILED);
        let hide_failed = HistoryFilter { hide_no_response: true, ..Default::default() };
        assert!(hide_failed.matches(&tunnel, &scope, &skip));
        assert!(!hide_failed.matches(&failed, &scope, &skip));
        let no_2xx = HistoryFilter { show_2xx: false, ..Default::default() };
        assert!(!no_2xx.matches(&tunnel, &scope, &skip));
        assert!(no_2xx.matches(&failed, &scope, &skip), "rows without a status aren't affected by the status pills");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Held;
    use std::sync::mpsc::{channel, Receiver};

    /// An app on Proxy > Intercept with Intercept on (no listener, no real config).
    fn intercept_app() -> (egui::Context, App) {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = App::new(&cc, Some("/dev/null".into()), None, false);
        app.tab = crate::state::Tab::Proxy;
        app.proxy_sub = 0;
        app.proxy.intercept.store(true, Ordering::SeqCst);
        (ctx, app)
    }

    fn hold(app: &App, path: &str) -> Receiver<Decision> {
        let (tx, rx) = channel();
        let raw = format!("GET {path} HTTP/1.1\nHost: shop.test\n\n");
        app.proxy.held.lock().unwrap().push(Held { id: crate::proxy::next_held_id(), raw, url: format!("http://shop.test{path}"), reply: tx });
        rx
    }

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
        // settle the layout, then find the button where it's drawn
        frame(ctx, app, vec![]);
        let at = find(&frame(ctx, app, vec![]), label);
        let button = |pressed| egui::Event::PointerButton { pos: at, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        frame(ctx, app, vec![egui::Event::PointerMoved(at), button(true)]);
        frame(ctx, app, vec![button(false)]);
        frame(ctx, app, vec![]);
    }

    #[test]
    fn turning_intercept_off_with_a_held_request_does_not_panic() {
        let (ctx, mut app) = intercept_app();
        let rx = hold(&app, "/cart");
        frame(&ctx, &mut app, vec![]);
        assert!(app.held_edit.contains("/cart"), "the held request is shown");
        // the toolbar button empties the queue mid-frame; the view below must cope
        click(&ctx, &mut app, "Intercept on");
        assert!(!app.proxy.intercept.load(Ordering::SeqCst));
        assert!(app.proxy.held.lock().unwrap().is_empty());
        assert!(matches!(rx.try_recv(), Ok(Decision::Forward(raw)) if raw.contains("/cart")), "released unchanged");
        assert_eq!(app.held_loaded, None);
        assert!(app.held_edit.is_empty());
    }

    #[test]
    fn forwarding_or_dropping_the_last_request_does_not_panic() {
        let (ctx, mut app) = intercept_app();
        let rx = hold(&app, "/one");
        click(&ctx, &mut app, "Forward");
        assert!(matches!(rx.try_recv(), Ok(Decision::Forward(_))));
        let rx = hold(&app, "/two");
        click(&ctx, &mut app, "Drop");
        assert!(matches!(rx.try_recv(), Ok(Decision::Drop)));
        assert!(app.proxy.held.lock().unwrap().is_empty());
        assert_eq!(app.held_loaded, None);
    }

    #[test]
    fn queue_emptied_between_frames_shows_the_idle_view() {
        let (ctx, mut app) = intercept_app();
        let _rx = hold(&app, "/a");
        frame(&ctx, &mut app, vec![]);
        assert!(app.held_loaded.is_some());
        app.proxy.held.lock().unwrap().clear();
        frame(&ctx, &mut app, vec![]);
        assert_eq!(app.held_loaded, None);
        assert!(app.held_edit.is_empty());
    }

    #[test]
    fn forward_sends_the_edit_only_for_the_request_it_belongs_to() {
        let (ctx, mut app) = intercept_app();
        let rx1 = hold(&app, "/first");
        frame(&ctx, &mut app, vec![]);
        app.held_edit = app.held_edit.replace("/first", "/edited");
        forward(&mut app);
        assert!(matches!(rx1.try_recv(), Ok(Decision::Forward(raw)) if raw.contains("/edited")));
        // the next request was never shown (e.g. Ctrl+F from another tab): forwarded as is
        let rx2 = hold(&app, "/second");
        forward(&mut app);
        assert!(matches!(rx2.try_recv(), Ok(Decision::Forward(raw)) if raw.contains("/second") && !raw.contains("/edited")));
    }

    /// Centre of the node labelled `label`, if there is one.
    fn try_find(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> Option<egui::Pos2> {
        let nodes = &update.as_ref()?.nodes;
        let r = nodes.iter().find(|(_, n)| n.label() == Some(label) || n.value() == Some(label)).and_then(|(_, n)| n.bounds())?;
        Some(egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32))
    }

    #[test]
    fn ribbon_and_sortable_headers() {
        let (ctx, mut app) = intercept_app();
        app.proxy_sub = 1; // HTTP history
        for (id, path, status, length) in [(1, "/a", "404 Not Found", 30), (2, "/logo.png", "200 OK", 500), (3, "/b", "200 OK", 10)] {
            let (host, path) = ("shop.test".to_string(), path.to_string());
            app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
                id, tool: "Proxy".into(), method: "GET".into(), url: format!("http://{host}{path}"), host, path, status: status.into(), length,
                mime: "HTML".into(), request: String::new(), response: String::new(), truncated: false, time: id as u64 * 1000,
            }));
        }
        frame(&ctx, &mut app, vec![]);
        assert!(try_find(&frame(&ctx, &mut app, vec![]), "Showing 3 of 3 requests").is_some());
        // header clicks: Length ascending, then descending
        click(&ctx, &mut app, "Length");
        assert_eq!((app.history_filter.sort_column, app.history_filter.sort_ascending), (Some(crate::history::HistorySortColumn::Length), true));
        click(&ctx, &mut app, "Length");
        assert!(!app.history_filter.sort_ascending);
        let ids: Vec<usize> = app.history.lock().unwrap().iter().map(|e| e.id).collect();
        assert_eq!(ids, [1, 2, 3], "sorting the table never reorders the recorded history");
        // pills: hide 4xx, hide static assets
        click(&ctx, &mut app, "4xx");
        assert!(!app.history_filter.show_4xx);
        assert!(try_find(&frame(&ctx, &mut app, vec![]), "Showing 2 of 3 requests").is_some());
        click(&ctx, &mut app, "Hide static");
        assert!(app.history_filter.hide_static_assets);
        assert!(try_find(&frame(&ctx, &mut app, vec![]), "Showing 1 of 3 requests").is_some());
        click(&ctx, &mut app, "Reset");
        assert!(app.history_filter.is_default_filter());
        assert_eq!(app.history_filter.sort_column, Some(crate::history::HistorySortColumn::Length), "Reset keeps the sort");
    }
}
