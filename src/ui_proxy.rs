//! Proxy screens (picture-12..15, 27, 58): Intercept, HTTP history, Match and replace, Proxy settings.

use crate::editor;
use crate::proxy::{self, Decision};
use crate::rewrite::{self, RuleAction, RuleType};
use crate::rules;
use crate::state::{App, Tab};
use crate::theme::{self, bold, EmptyIcon, Palette};
use crate::ui_core::sub_tabs;
use eframe::egui;
use egui::{FontId, RichText, Ui};
use std::sync::atomic::Ordering;

pub fn proxy(app: &mut App, ui: &mut Ui, p: &Palette) {
    sub_tabs(ui, p, Tab::Proxy.sub_views(), &mut app.proxy_sub);
    match app.proxy_sub {
        1 => history(app, ui, p),
        2 => websockets(app, ui, p),
        3 => match_replace(app, ui, p),
        4 => settings(app, ui, p),
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
    // Settings > Proxy > Browser: the binary, the profile, the extra flags and the page
    let profile = crate::browser::BrowserProfile {
        binary: app.settings.browser_binary.clone(),
        profile_dir: app.settings.browser_profile_dir.clone(),
        extra_args: app.settings.browser_extra_args.clone(),
        start_url: app.settings.browser_start_url.clone(),
    };
    let start = profile.url().to_string();
    app.proxy_msg = match crate::browser::open_with(app.proxy_host.trim(), port, &start, pin.as_deref(), &profile) {
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
            // every control in the row -- buttons, the checkbox, the Inspector toggle -- is one
            // toolbar height, so they share a top, a bottom and a centreline
            ui.spacing_mut().interact_size.y = theme::TOOLBAR_H;
            // the bold labels' line box plus the default padding would come to a pixel over
            ui.spacing_mut().button_padding.y = 3.0;
            let on = app.proxy.intercept.load(Ordering::SeqCst);
            let (txt, col, tc) = if on { ("Intercept on", p.accent, p.accent_text) } else { ("Intercept off", p.header, p.text) };
            let toggle = egui::Button::new(bold(txt, theme::FONT_UI).color(tc))
                .fill(col)
                .corner_radius(egui::CornerRadius::same(p.corner))
                .min_size(egui::vec2(0.0, theme::TOOLBAR_H));
            if ui.add(toggle).clicked() {
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
                        ui.allocate_ui_with_layout(egui::vec2(room, theme::TOOLBAR_H), egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
        let out = editor::message_editor(ui, p, "held", &mut app.held_edit, true, false, ui.available_height() - 10.0);
        let cur_req = app.held_edit.clone();
        crate::ui_tools::attach_editor_context_menu(&out, &cur_req, &cur_req, app, crate::state::Tab::Proxy, &url, &cur_req, None, "Intercepted request");
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

/// Proxy > WebSockets: the frames captured on upgraded connections, and the payload of the
/// one picked.
///
/// Columns, as (minimum width, share of the spare width): #, Time, Host, Path, Direction,
/// Opcode, Length, Payload. The payload takes the slack, as the path does in HTTP history.
const WS_COLS: [(f32, f32); 8] = [(50.0, 0.0), (72.0, 0.0), (150.0, 0.0), (150.0, 0.0),
    (90.0, 0.0), (90.0, 0.0), (70.0, 0.0), (220.0, 1.0)];

fn websockets(app: &mut App, ui: &mut Ui, p: &Palette) {
    let messages = app.proxy.ws_messages.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let any_open = !app.proxy.ws_live.lock().unwrap_or_else(|e| e.into_inner()).is_empty();
    // a connection that has opened but said nothing yet is still worth a composer
    if messages.is_empty() && !any_open {
        let (_, open) = theme::empty_state(
            ui,
            p,
            EmptyIcon::History,
            "No WebSocket messages yet",
            "Frames sent over connections the proxy has upgraded will display here, both ways.",
            Some("Open browser"),
        );
        if open {
            open_browser(app);
        }
        return;
    }

    // registered first, so it keeps the bottom of the tab and the detail pane sits above it
    compose_bar(app, ui, p);

    // the message being read, and the handshake it belongs to
    let selected = app.ws_sel.and_then(|id| messages.iter().find(|m| m.id == id)).cloned();
    let mut clicked = None;
    let avail = ui.available_height();
    if let Some(m) = &selected {
        egui::TopBottomPanel::bottom("ws_detail")
            .resizable(true)
            .default_height(260.0)
            .min_height(120.0)
            // the table above always keeps a usable height, however far this is dragged
            .max_height((avail - 120.0).max(120.0))
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { top: 6, ..Default::default() }))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("#{}", m.id)).color(p.text));
                    ui.label(RichText::new(m.direction.label()).color(p.strong));
                    ui.label(RichText::new(m.opcode.label()).color(p.text));
                    ui.label(RichText::new(format!("{} bytes in {} frame(s)", m.length, m.frames)).size(11.5).color(p.disabled));
                    if m.compressed {
                        ui.label(RichText::new("compressed").size(11.5).color(p.badge_info));
                    }
                    if m.truncated {
                        ui.label(RichText::new("kept in part").size(11.5).color(p.warning));
                    }
                });
                // a scroll area inside, so the payload cannot drive the height the pane was
                // dragged to
                egui::ScrollArea::vertical().id_salt("ws_detail_scroll").auto_shrink([false, false]).show(ui, |ui| {
                    let h = (ui.available_height() - 10.0).max(80.0);
                    let _ = crate::editor::message_view(ui, p, "ws_payload", &m.payload, h);
                });
            });
    }

    egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
        let table_h = ui.available_height().max(120.0);
        theme::fitted_table(ui, p, "ws_table", table_h, &WS_COLS, |ui, w| {
            theme::table_header(ui, p, &[("#", w[0]), ("Time", w[1]), ("Host", w[2]), ("Path", w[3]),
                ("Direction", w[4]), ("Opcode", w[5]), ("Length", w[6]), ("Payload", w[7])]);
            let sel = app.ws_sel;
            egui::ScrollArea::vertical().id_salt("ws_rows").show_rows(ui, theme::ROW_HEIGHT, messages.len(), |ui, range| {
                for (i, m) in messages.iter().enumerate().skip(range.start).take(range.len()) {
                    let direction = m.direction.label();
                    let opcode = m.opcode.label();
                    // one line of the payload: a message with newlines in it must not make
                    // the row taller than every other one
                    let preview: String = m.payload.lines().next().unwrap_or("").chars().take(200).collect();
                    let cells = [
                        (m.id.to_string(), w[0], None),
                        (crate::history::time_of_day(m.time), w[1], Some(p.disabled)),
                        (m.host.clone(), w[2], None),
                        (m.path.clone(), w[3], None),
                        (direction.to_string(), w[4], Some(direction_color(p, m.direction))),
                        (opcode.clone(), w[5], None),
                        (m.length.to_string(), w[6], None),
                        (preview, w[7], None),
                    ];
                    let row = theme::table_row(ui, p, &cells, sel == Some(m.id), i % 2 == 1);
                    // named, so a row can be found by what it stands for rather than by where
                    // it happens to be drawn
                    row.widget_info(|| {
                        egui::WidgetInfo::selected(
                            egui::WidgetType::Button,
                            true,
                            sel == Some(m.id),
                            format!("Message #{} {direction} {opcode}", m.id),
                        )
                    });
                    if row.clicked() {
                        clicked = Some(m.id);
                    }
                }
            });
        });
    });
    // applied after the drawing, which borrows the app
    if let Some(id) = clicked {
        app.ws_sel = Some(id);
    }
}

/// The bar for sending a message of your own on a connection that is still open.
///
/// Only the thread relaying a connection may write to it, so what is composed here is handed
/// to that thread rather than sent from the interface.
fn compose_bar(app: &mut App, ui: &mut Ui, p: &Palette) {
    let links = app.proxy.ws_live.lock().unwrap_or_else(|e| e.into_inner()).clone();
    // the connection the message goes on: the one the picked message belongs to when it is
    // still open, else whichever is
    let on = app
        .ws_sel
        .and_then(|id| {
            let messages = app.proxy.ws_messages.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let entry = messages.iter().find(|m| m.id == id)?.entry_id;
            links.iter().find(|l| l.entry_id == entry).cloned()
        })
        .or_else(|| links.first().cloned());

    egui::TopBottomPanel::bottom("ws_compose")
        .resizable(false)
        .frame(egui::Frame::new().fill(p.header).inner_margin(egui::Margin::symmetric(8, 6)))
        .show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().interact_size.y = theme::TOOLBAR_H;
                match &on {
                    Some(l) => {
                        let since = crate::history::time_of_day(l.opened);
                        let label = if since.is_empty() {
                            format!("{}{} open", l.host, l.path)
                        } else {
                            format!("{}{} open since {since}", l.host, l.path)
                        };
                        theme::status_pill(ui, p, &label, p.success)
                    }
                    None => theme::status_pill(ui, p, "No connection open", p.disabled),
                };
                ui.selectable_value(&mut app.ws_compose_binary, false, "Text");
                ui.selectable_value(&mut app.ws_compose_binary, true, "Binary");
                let mut send = false;
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // in binary the box holds hex; anything else would be filtered away by
                    // the decoder and go out as an empty frame, which reads as "it sent"
                    let typed = app.ws_compose.trim();
                    let usable = if app.ws_compose_binary { is_hex(typed) } else { !typed.is_empty() };
                    let ready = on.is_some() && usable;
                    if theme::action_button(ui, p, "Send", ready, egui::vec2(80.0, 24.0))
                        .on_disabled_hover_text(if on.is_none() {
                            "No upgraded connection is open to send on"
                        } else if app.ws_compose_binary {
                            "Binary takes hex: pairs of 0-9 and a-f, spaces allowed"
                        } else {
                            "Nothing to send yet"
                        })
                        .clicked()
                    {
                        send = true;
                    }
                    if !app.ws_compose_msg.is_empty() {
                        ui.label(RichText::new(&app.ws_compose_msg).size(11.5).color(p.warning));
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut app.ws_compose)
                            .desired_width(ui.available_width())
                            .hint_text("A message to send on this connection"),
                    );
                });
                if send {
                    if let Some(l) = &on {
                        let opcode = if app.ws_compose_binary {
                            crate::websocket::Opcode::Binary
                        } else {
                            crate::websocket::Opcode::Text
                        };
                        // bytes when it is meant as bytes and reads as hex, else the text itself
                        let payload = if app.ws_compose_binary {
                            crate::codec::hex_decode(&app.ws_compose)
                        } else {
                            app.ws_compose.as_bytes().to_vec()
                        };
                        let frame = crate::websocket::encode(opcode, &payload, Some(crate::websocket::masking_key()));
                        // a connection that has closed since the list was taken simply refuses
                        if l.send.send(frame).is_ok() {
                            app.ws_compose.clear();
                            app.ws_compose_msg.clear();
                        } else {
                            // said here, where it happened: `proxy_msg` is drawn by other
                            // sub-tabs and would never be seen from this one
                            app.ws_compose_msg = "That connection has closed.".into();
                        }
                    }
                }
            });
        });
}

/// Is this text a run of hex byte pairs, spaces allowed? The decoder drops anything else
/// without a word, so what it would make of the text is not a fair test of what was meant.
fn is_hex(s: &str) -> bool {
    let digits: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    !digits.is_empty() && digits.len() % 2 == 0 && digits.iter().all(char::is_ascii_hexdigit)
}

/// Which way a message went, in the colours the methods use: out and back.
fn direction_color(p: &Palette, d: crate::websocket::Direction) -> egui::Color32 {
    match d {
        crate::websocket::Direction::ClientToServer => p.post,
        crate::websocket::Direction::ServerToClient => p.get,
    }
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
                app.mr_rules.push(rewrite::Rule::new(RuleType::RequestHeader));
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
        // (minimum width, share of the spare width) for Enabled, Item, Match, Replace, Type,
        // Case, Comment. "Item" holds the longest label, "Request first line".
        const COLS: [(f32, f32); 7] = [(64.0, 0.0), (124.0, 0.16), (120.0, 0.26), (140.0, 0.34), (60.0, 0.0), (44.0, 0.0), (100.0, 0.24)];
        theme::fitted_table(ui, p, ("mr_table", id), 230.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Enabled", w[0]), ("Item", w[1]), ("Match", w[2]), ("Replace", w[3]), ("Type", w[4]), ("Case", w[5]), ("Comment", w[6])]);
            egui::ScrollArea::vertical().id_salt(("mr_rows", id)).auto_shrink([false, true]).show(ui, |ui| {
                for i in 0..app.mr_rules.len() {
                    let r = &app.mr_rules[i];
                    let cells = [
                        (if r.enabled { "Yes" } else { "" }.to_string(), w[0], None),
                        (r.kind.label().to_string(), w[1], None),
                        (r.match_text.clone(), w[2], None),
                        (r.replace_text.clone(), w[3], None),
                        (if r.regex { "Regex" } else { "Literal" }.to_string(), w[4], None),
                        // "Aa" for a rule that matches the text exactly as typed
                        (if r.case_sensitive { "Aa" } else { "" }.to_string(), w[5], None),
                        (r.comment.clone(), w[6], None),
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
        // the registered programs an External command rule can name
        let names: Vec<String> = app.settings.external_tools.iter().filter(|t| t.is_runnable()).map(|t| t.name.trim().to_string()).collect();
        let r = &mut app.mr_rules[i];
        egui::Grid::new(("mr_edit", id)).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.label("Enabled:"); ui.checkbox(&mut r.enabled, ""); ui.end_row();
            ui.label("Type:");
            egui::ComboBox::from_id_salt(("mr_type", id)).selected_text(r.kind.label()).show_ui(ui, |ui| {
                for t in RuleType::ALL {
                    // a kind the user picks brings the case sensitivity that suits it, until
                    // they say otherwise with the checkbox below
                    if ui.selectable_value(&mut r.kind, t, t.label()).clicked() {
                        r.case_sensitive = t.starts_case_sensitive();
                    }
                }
            });
            ui.end_row();
            ui.label("Action:");
            egui::ComboBox::from_id_salt(("mr_action", id)).selected_text(r.action.label()).show_ui(ui, |ui| {
                for a in RuleAction::ALL {
                    ui.selectable_value(&mut r.action, a, a.label());
                }
            });
            ui.end_row();
            let command = r.action == RuleAction::TransformCommand;
            let match_hint = if command { "Match (gate, blank runs always):" } else { "Match:" };
            ui.label(match_hint); ui.add(egui::TextEdit::singleline(&mut r.match_text).desired_width(460.0).font(FontId::monospace(12.5))); ui.end_row();
            if command {
                // a rule names one of the user's registered programs; the command line itself
                // stays in their settings and never travels in the project
                ui.label("Program:");
                let shown = if r.program.trim().is_empty() {
                    "Choose a registered program".to_string()
                } else if names.contains(&r.program.trim().to_string()) {
                    r.program.clone()
                } else {
                    format!("{} (not registered)", r.program)
                };
                egui::ComboBox::from_id_salt(("mr_program", id)).selected_text(shown).width(300.0).show_ui(ui, |ui| {
                    for n in &names {
                        ui.selectable_value(&mut r.program, n.clone(), n);
                    }
                    if names.is_empty() {
                        ui.label(RichText::new("No programs registered. Add one under Settings > External tools.").color(p.disabled));
                    }
                });
                ui.end_row();
                ui.label("Timeout (ms):");
                ui.add(egui::DragValue::new(&mut r.timeout_ms).range(1..=600_000).speed(10));
                ui.end_row();
            } else {
                ui.label("Replace:"); ui.add(egui::TextEdit::singleline(&mut r.replace_text).desired_width(460.0).font(FontId::monospace(12.5))); ui.end_row();
            }
            ui.label("Regex match:"); ui.add_enabled(!command, egui::Checkbox::new(&mut r.regex, "")); ui.end_row();
            ui.label("Case sensitive:");
            ui.checkbox(&mut r.case_sensitive, "")
                .on_hover_text("Off: the match ignores capitals, so user-agent matches User-Agent");
            ui.end_row();
            ui.label("Comment:"); ui.add(egui::TextEdit::singleline(&mut r.comment).desired_width(460.0)); ui.end_row();
        });
        ui.label(RichText::new("Header rules work line by line: a blank match adds the replacement as a new header; a blank replacement removes matching headers.").size(11.5).color(p.disabled));
        ui.label(RichText::new("A request first line rule sees only the line itself, such as \"GET /api/v1/users HTTP/1.1\".").size(11.5).color(p.disabled));
        ui.label(RichText::new("External command: the matched header block or body is piped to a program registered under Settings > External tools (its command and arguments, as registered) and replaced by what it prints. On a timeout, a non-zero exit, or a program that cannot start, the original bytes are kept. A project stores only the program's name.").size(11.5).color(p.disabled));
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

/// Right-click menu for a history row or site map item. The scope and routing choices can't
/// change the app while it is drawing, so they are returned for `scope_menu_apply` to carry
/// out; a registered program is started where it is picked, which needs nothing undrawn.
#[allow(dead_code)]
pub fn scope_menu_pick(ui: &mut Ui, app: &mut App, e: &crate::http::HttpEntry, prefix: &str) -> Option<RowAction> {
    scope_menu_pick_for(ui, app, e, prefix, crate::state::Tab::Proxy)
}

/// Right-click menu for a traffic row in `source_tab`, hiding any redundant link to `source_tab`.
pub fn scope_menu_pick_for(
    ui: &mut Ui,
    app: &mut App,
    e: &crate::http::HttpEntry,
    prefix: &str,
    source_tab: crate::state::Tab,
) -> Option<RowAction> {
    use crate::actions::SendTo;
    let in_scope = app.target_scope.is_in_scope(&crate::actions::entry_url(e));
    let mut pick = None;
    ui.label(RichText::new(prefix).monospace().size(11.5));
    ui.separator();
    if ui.button("Add to scope").clicked() { pick = Some(RowAction::AddToScope); }
    if ui.add_enabled(in_scope, egui::Button::new("Remove from scope")).on_disabled_hover_text("Already out of scope").clicked() {
        pick = Some(RowAction::RemoveFromScope);
    }
    ui.separator();
    for (label, to) in crate::ui_tools::traffic_context_menu_targets(source_tab) {
        if ui.button(label).clicked() { pick = Some(RowAction::Send(to)); }
        if to == SendTo::Comparer {
            if ui.button("Send request to Comparer").clicked() { pick = Some(RowAction::Send(SendTo::ComparerRequest)); }
            if ui.button("Send response to Comparer").clicked() { pick = Some(RowAction::Send(SendTo::Comparer)); }
        }
    }
    ui.separator();
    if ui.button("Copy as cURL").on_hover_text("Copy the request as a curl command").clicked() {
        ui.ctx().copy_text(crate::actions::entry_as_curl(e));
        ui.close_menu();
    }
    // the same programs the editors and viewers offer, so a row's menu is not the poorer for
    // being a row's menu
    crate::ui_tools::append_external_tools_menu(
        ui,
        app,
        &crate::actions::entry_url(e),
        &crate::actions::raw_request(e),
        &e.response,
    );
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
            mime: "text/html".into(), request: String::new(), response: String::new(), url: url.into(), truncated: false, time: 0, elapsed_ms: 0, graphql: String::new() }
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
    use crate::test_utils::assert_table;
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

    /// Every label a frame's accessibility tree carries, menus included.
    fn labels(update: &Option<egui::accesskit::TreeUpdate>) -> Vec<String> {
        update
            .as_ref()
            .expect("accesskit output")
            .nodes
            .iter()
            .filter_map(|(_, n)| n.label().map(str::to_string))
            .collect()
    }

    /// Centre of the first row of the table whose header holds `column`. Table cells are
    /// painted rather than laid out, so there is no node of their own to find: inside a table
    /// well the rows follow the header with no spacing between them, so the first one sits one
    /// half-row below the header's bottom edge.
    fn first_row_under(update: &Option<egui::accesskit::TreeUpdate>, column: &str) -> egui::Pos2 {
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        let r = nodes
            .iter()
            .find(|(_, n)| n.label() == Some(column))
            .and_then(|(_, n)| n.bounds())
            .unwrap_or_else(|| panic!("no column header labelled {column:?}"));
        egui::pos2(((r.x0 + r.x1) / 2.0) as f32, r.y1 as f32 + theme::ROW_HEIGHT / 2.0)
    }

    /// An app on Proxy > HTTP history with one recorded exchange to right-click.
    fn history_app() -> (egui::Context, App) {
        let (ctx, mut app) = intercept_app();
        app.proxy_sub = 1; // HTTP history
        let entry = crate::test_utils::HttpFixture::get("shop.test", "/orders")
            .with_response("200 OK", "{\"orders\":[]}")
            .into_history_entry(1, "Proxy");
        app.history.lock().unwrap().push(std::sync::Arc::new(entry));
        (ctx, app)
    }

    /// A registered program that can run, by the name its menu entry carries.
    fn tool(name: &str) -> crate::tooling::ExternalTool {
        crate::tooling::ExternalTool { name: name.into(), command: "/bin/echo".into(), ..Default::default() }
    }

    /// Right-click at `at` and return the labels of the frame the menu goes up in.
    ///
    /// That frame is the one the click completes in, which for a traffic row is also the frame
    /// it is selected in: the detail pane the selection opens moves the table out from under
    /// the menu and closes it again, so there is no later frame to read it from.
    fn right_click_labels(ctx: &egui::Context, app: &mut App, at: egui::Pos2) -> Vec<String> {
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Secondary,
            pressed,
            modifiers: Default::default(),
        };
        frame(ctx, app, vec![egui::Event::PointerMoved(at), button(true)]);
        labels(&frame(ctx, app, vec![button(false)]))
    }

    /// Right-click the first row of HTTP history and return what the menu offers.
    fn history_row_menu(ctx: &egui::Context, app: &mut App) -> Vec<String> {
        frame(ctx, app, vec![]);
        let at = first_row_under(&frame(ctx, app, vec![]), "Host");
        let open = right_click_labels(ctx, app, at);
        assert_eq!(app.history_sel, Some(1), "the right-click landed on the history row");
        assert!(open.iter().any(|l| l == "Add to scope"), "the row's menu is open: {open:?}");
        open
    }

    /// A program registered in the Automation tab belongs on a history row's right-click menu,
    /// not only on the menus the message editors and viewers put up -- and one the user has
    /// kept off the menus stays off this one too.
    #[test]
    fn a_history_row_offers_the_programs_the_user_registered() {
        let (ctx, mut app) = history_app();
        app.settings.external_tools = vec![
            tool("Header survey"),
            crate::tooling::ExternalTool { show_in_menu: false, ..tool("Pipeline helper") },
            crate::tooling::ExternalTool { command: String::new(), ..tool("Unfinished") },
        ];
        let open = history_row_menu(&ctx, &mut app);
        assert!(
            open.iter().any(|l| l == "Header survey"),
            "the registered program is offered on the row's menu: {open:?}"
        );
        assert!(
            !open.iter().any(|l| l == "Pipeline helper"),
            "a program kept off the menus is not offered: {open:?}"
        );
        assert!(!open.iter().any(|l| l == "Unfinished"), "nor one that cannot run: {open:?}");
        assert!(
            !open.iter().any(|l| l == crate::ui_tools::MENU_TOOLS_SUBMENU),
            "and one program needs no submenu to hold it: {open:?}"
        );
    }

    /// A registry too long to list is grouped behind a submenu, so a row's menu cannot grow
    /// taller than the screen it is drawn on.
    #[test]
    fn a_large_registry_is_grouped_behind_one_submenu() {
        let inline_max = crate::ui_tools::MENU_TOOLS_INLINE_MAX;
        assert_table!([inline_max, inline_max + 1], |idx, count| {
            let (ctx, mut app) = history_app();
            app.settings.external_tools = (1..=count).map(|n| tool(&format!("Survey {n}"))).collect();
            let open = history_row_menu(&ctx, &mut app);
            let grouped = open.iter().any(|l| l == crate::ui_tools::MENU_TOOLS_SUBMENU);
            let listed = open.iter().filter(|l| l.starts_with("Survey ")).count();
            if count <= inline_max {
                assert!(!grouped, "case #{idx}: {count} programs are listed outright: {open:?}");
                assert_eq!(listed, count, "case #{idx}: all {count} of them: {open:?}");
            } else {
                assert!(grouped, "case #{idx}: {count} programs go behind the submenu: {open:?}");
                assert_eq!(listed, 0, "case #{idx}: and none of them is listed beside it: {open:?}");
            }
        });
    }

    /// Centre of the node labelled `label`, if there is one.
    fn try_find(update: &Option<egui::accesskit::TreeUpdate>, label: &str) -> Option<egui::Pos2> {
        let nodes = &update.as_ref()?.nodes;
        let r = nodes.iter().find(|(_, n)| n.label() == Some(label) || n.value() == Some(label)).and_then(|(_, n)| n.bounds())?;
        Some(egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32))
    }

    /// Put two messages on a captured connection, with the WebSockets view open.
    fn ws_app() -> (egui::Context, App) {
        let (ctx, mut app) = intercept_app();
        app.proxy_sub = 2; // WebSockets
        app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
            id: 1, tool: "Proxy".into(), method: "GET".into(), host: "shop.test".into(), path: "/socket".into(),
            status: "101 Switching Protocols".into(), length: 0, mime: String::new(),
            request: "GET /socket HTTP/1.1\nHost: shop.test\n\n".into(), response: String::new(),
            url: "http://shop.test/socket".into(), truncated: false, time: 1000, elapsed_ms: 1, graphql: String::new(),
        }));
        for (id, direction, payload) in [
            (1usize, crate::websocket::Direction::ClientToServer, "{\"type\":\"subscribe\"}"),
            (2, crate::websocket::Direction::ServerToClient, "{\"type\":\"data\"}"),
        ] {
            app.proxy.ws_messages.lock().unwrap().push(std::sync::Arc::new(crate::websocket::WsMessage {
                id, entry_id: 1, host: "shop.test".into(), path: "/socket".into(), direction,
                opcode: crate::websocket::Opcode::Text, frames: 1, compressed: false, truncated: false,
                length: payload.len(), payload: payload.into(), time: 1000 + id as u64, 
            }));
        }
        (ctx, app)
    }

    /// The frame stream needs a place of its own: a sub-tab under Proxy, listing what went
    /// each way with the payload of whichever message is picked.
    #[test]
    fn the_websockets_view_lists_messages_and_shows_the_one_picked() {
        let (ctx, mut app) = ws_app();
        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let nodes = &update.as_ref().expect("accesskit").nodes;
        let has = |text: &str| nodes.iter().any(|(_, n)| n.label() == Some(text) || n.value() == Some(text));
        assert!(has("WebSockets"), "the sub-tab is there");
        // the table's headings are painted rather than laid out, as the site map's are, so
        // what a reader can be shown to see is the rows: each says which way it went and what
        // kind of frame carried it
        assert!(has("Message #1 To server Text"), "the client's message is listed");
        assert!(has("Message #2 To client Text"), "and so is the server's");

        // picking a message shows its payload
        click(&ctx, &mut app, "Message #2 To client Text");
        assert_eq!(app.ws_sel, Some(2), "clicking a row selects that message");
        let update = frame(&ctx, &mut app, vec![]);
        let nodes = &update.as_ref().expect("accesskit").nodes;
        assert!(
            nodes.iter().any(|(_, n)| n.value().is_some_and(|v| v.contains("\"type\":\"data\""))),
            "and its payload is shown",
        );
    }

    /// A composer is only useful while there is something to send on. With a connection open
    /// it sends what was typed; with none it says so rather than pretending.
    #[test]
    fn the_composer_sends_on_a_live_connection_and_is_disabled_without_one() {
        let (ctx, mut app) = ws_app();
        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let nodes = &update.as_ref().expect("accesskit").nodes;
        let send = nodes
            .iter()
            .find(|(_, n)| n.label() == Some("Send"))
            .expect("the composer has a Send");
        assert!(send.1.is_disabled(), "with nothing open there is nothing to send on");

        // a connection opens
        let (tx, rx) = std::sync::mpsc::channel();
        app.proxy.ws_live.lock().unwrap().push(crate::websocket::LiveLink {
            entry_id: 1, host: "shop.test".into(), path: "/socket".into(), opened: 1000, send: tx,
        });
        app.ws_compose = "{\"type\":\"ping\"}".into();
        click(&ctx, &mut app, "Send");

        let sent = rx.try_recv().expect("the connection was given a frame");
        let (parsed, _) = crate::websocket::next_frame(&sent).expect("it is a frame").expect("whole");
        assert_eq!(parsed.payload, b"{\"type\":\"ping\"}".to_vec(), "with what was typed in it");
        assert_eq!(parsed.opcode, crate::websocket::Opcode::Text);
        assert!(sent[1] & 0x80 != 0, "and masked, as anything a client sends must be");
        assert!(app.ws_compose.is_empty(), "the box is cleared once it has gone");
    }

    /// Binary mode takes hex. Text that is not hex would be silently thrown away by the
    /// decoder and sent as an empty frame, which looks like the message went.
    #[test]
    fn the_composer_will_not_send_text_that_is_not_hex_as_binary() {
        let (ctx, mut app) = ws_app();
        let (tx, rx) = std::sync::mpsc::channel();
        app.proxy.ws_live.lock().unwrap().push(crate::websocket::LiveLink {
            entry_id: 1, host: "shop.test".into(), path: "/socket".into(), opened: 1000, send: tx,
        });
        app.ws_compose_binary = true;
        app.ws_compose = "hello".into();
        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let send = update.as_ref().expect("accesskit").nodes.iter().find(|(_, n)| n.label() == Some("Send")).expect("a Send");
        assert!(send.1.is_disabled(), "\"hello\" is not hex, so there is nothing to send");
        assert!(rx.try_recv().is_err(), "and nothing went");

        app.ws_compose = "48 65 6c 6c 6f".into();
        click(&ctx, &mut app, "Send");
        let sent = rx.try_recv().expect("hex does go");
        let (parsed, _) = crate::websocket::next_frame(&sent).expect("a frame").expect("whole");
        assert_eq!(parsed.payload, b"Hello".to_vec());
        assert_eq!(parsed.opcode, crate::websocket::Opcode::Binary);
    }

    /// The other sub-tabs still answer to their names after one was added before them.
    #[test]
    fn the_proxy_sub_tabs_still_reach_what_they_name() {
        let (ctx, mut app) = intercept_app();
        for (label, want) in [("HTTP history", 1u8), ("WebSockets", 2), ("Match and replace", 3), ("Proxy settings", 4), ("Intercept", 0)] {
            frame(&ctx, &mut app, vec![]);
            click(&ctx, &mut app, label);
            assert_eq!(app.proxy_sub, want, "{label}");
        }
    }

    /// Every GraphQL request is the same method on the same path. The Operation column is what
    /// tells them apart, so it has to be in the header and has to sort like the rest.
    #[test]
    fn the_history_table_sorts_by_operation() {
        let (ctx, mut app) = intercept_app();
        app.proxy_sub = 1; // HTTP history
        for (id, op) in [(1, "query Me"), (2, "mutation SignIn")] {
            app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
                id, tool: "Proxy".into(), method: "POST".into(), url: "http://shop.test/graphql".into(),
                host: "shop.test".into(), path: "/graphql".into(), status: "200 OK".into(), length: 0,
                mime: "application/json".into(), request: String::new(), response: String::new(),
                truncated: false, time: id as u64 * 1000, elapsed_ms: 0, graphql: op.into(),
            }));
        }
        frame(&ctx, &mut app, vec![]);
        frame(&ctx, &mut app, vec![]);

        click(&ctx, &mut app, "Operation");
        assert_eq!(
            (app.history_filter.sort_column, app.history_filter.sort_ascending),
            (Some(crate::history::HistorySortColumn::Operation), true),
        );
    }

    #[test]
    fn ribbon_and_sortable_headers() {
        let (ctx, mut app) = intercept_app();
        app.proxy_sub = 1; // HTTP history
        for (id, path, status, length) in [(1, "/a", "404 Not Found", 30), (2, "/logo.png", "200 OK", 500), (3, "/b", "200 OK", 10)] {
            let (host, path) = ("shop.test".to_string(), path.to_string());
            app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
                id, tool: "Proxy".into(), method: "GET".into(), url: format!("http://{host}{path}"), host, path, status: status.into(), length,
                mime: "HTML".into(), request: String::new(), response: String::new(), truncated: false, time: id as u64 * 1000, elapsed_ms: 0, graphql: String::new(),
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

    /// The Intercept toolbar's controls are one toolbar height and share a centreline, so the
    /// buttons and the checkbox line up along the top and the bottom alike.
    #[test]
    fn the_intercept_toolbar_controls_share_one_height_and_centreline() {
        let (ctx, mut app) = intercept_app();
        let _rx = hold(&app, "/cart");
        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        let rect = |label: &str| {
            let r = nodes.iter().find(|(_, n)| n.label() == Some(label)).and_then(|(_, n)| n.bounds())
                .unwrap_or_else(|| panic!("no widget labelled {label:?}"));
            egui::Rect::from_min_max(egui::pos2(r.x0 as f32, r.y0 as f32), egui::pos2(r.x1 as f32, r.y1 as f32))
        };
        let first = rect("Intercept on");
        for label in ["Intercept on", "Forward", "Drop", "Only in scope"] {
            let r = rect(label);
            assert!((r.height() - theme::TOOLBAR_H).abs() < 0.5, "{label:?} is one toolbar height: {:.1}", r.height());
            assert!((r.center().y - first.center().y).abs() < 0.5, "{label:?} shares the row's centreline");
        }
    }

}
