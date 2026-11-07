//! Default hotkeys (from UserDefaults.json user_options.misc.hotkeys) that this app handles.

use crate::actions::{self, SendTo};
use crate::state::{App, Tab};
use crate::ui_proxy;
use eframe::egui;
use egui::{Key, KeyboardShortcut, Modifiers};

pub const LIST: [(&str, &str); 18] = [
    ("Send to Repeater", "Ctrl+R"),
    ("Send to Intruder", "Ctrl+I"),
    ("Send to Organizer", "Ctrl+O"),
    ("Send request (Repeater)", "Ctrl+Space"),
    ("Toggle Proxy interception", "Ctrl+T"),
    ("Forward intercepted message", "Ctrl+F"),
    ("Drop intercepted message", "Ctrl+D"),
    ("Open command palette", "Ctrl+K"),
    ("Go to next tab", "Ctrl+="),
    ("Go to previous tab", "Ctrl+-"),
    ("Switch to Dashboard", "Ctrl+Shift+D"),
    ("Switch to Target", "Ctrl+Shift+T"),
    ("Switch to Proxy", "Ctrl+Shift+P"),
    ("Switch to Intruder", "Ctrl+Shift+I"),
    ("Switch to Repeater", "Ctrl+Shift+R"),
    ("Switch to Logger", "Ctrl+Shift+L"),
    ("Switch to Organizer", "Ctrl+Shift+O"),
    ("Toggle Inspector panel", "Ctrl+Shift+N"),
];

fn sc(shift: bool, k: Key) -> KeyboardShortcut {
    let m = if shift { Modifiers::COMMAND | Modifiers::SHIFT } else { Modifiers::COMMAND };
    KeyboardShortcut::new(m, k)
}

fn selected(app: &App) -> Option<std::sync::Arc<crate::http::HttpEntry>> {
    let id = match app.tab {
        Tab::Target => app.target_selected_history_id.or(app.history_sel)?,
        Tab::Discover => app.discover_sel.or(app.history_sel)?,
        _ => app.history_sel?,
    };
    app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|e| e.id == id).cloned()
}

pub fn handle(app: &mut App, ctx: &egui::Context) {
    let hit = |k: Key, shift: bool| ctx.input_mut(|i| i.consume_shortcut(&sc(shift, k)));
    for (k, t) in [(Key::D, Tab::Dashboard), (Key::T, Tab::Target), (Key::P, Tab::Proxy), (Key::I, Tab::Intruder), (Key::R, Tab::Repeater), (Key::L, Tab::Logger), (Key::O, Tab::Organizer)] {
        if hit(k, true) {
            app.tab = t;
        }
    }
    for (k, to) in [(Key::R, SendTo::Repeater), (Key::I, SendTo::Intruder), (Key::O, SendTo::Organizer)] {
        if hit(k, false) {
            if app.tab == Tab::Repeater {
                let tab = app.rep().clone();
                if !tab.request.trim().is_empty() {
                    match to {
                        SendTo::Repeater => actions::send_to_repeater(app, &tab.method, &tab.url, &tab.request),
                        SendTo::Intruder => actions::send_to_intruder(app, &tab.url, &tab.request),
                        SendTo::Organizer => actions::send_to_organizer(app, &tab.url, &tab.request, tab.response.as_deref().unwrap_or("")),
                        _ => {}
                    }
                }
            } else if app.tab == Tab::Proxy && app.proxy_sub == 0 {
                let held_req = app.proxy.held.lock().unwrap_or_else(|e| e.into_inner()).first().map(|h| (h.id, h.url.clone(), h.raw.clone()));
                if let Some((id, url, raw)) = held_req {
                    let req = if app.held_loaded == Some(id) && !app.held_edit.trim().is_empty() {
                        app.held_edit.clone()
                    } else {
                        raw
                    };
                    let method = actions::request_method(&req).unwrap_or_else(|| "GET".to_string());
                    match to {
                        SendTo::Repeater => actions::send_to_repeater(app, &method, &url, &req),
                        SendTo::Intruder => actions::send_to_intruder(app, &url, &req),
                        SendTo::Organizer => actions::send_to_organizer(app, &url, &req, ""),
                        _ => {}
                    }
                } else if let Some(e) = selected(app) {
                    actions::send_to(app, &e, to);
                }
            } else if let Some(e) = selected(app) {
                actions::send_to(app, &e, to);
            }
        }
    }
    if hit(Key::T, false) {
        ui_proxy::toggle_intercept(app);
    }
    if hit(Key::F, false) {
        ui_proxy::forward(app);
    }
    if hit(Key::D, false) {
        ui_proxy::drop_held(app);
    }
    if hit(Key::N, true) {
        app.inspector.show_inspector = !app.inspector.show_inspector;
    }
    if hit(Key::K, false) {
        app.show_palette = !app.show_palette;
        app.palette_query.clear();
    }
    if hit(Key::Space, false) && app.tab == Tab::Repeater && app.rep().can_send() {
        actions::send_repeater(app);
    }
    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    if hit(Key::Equals, false) || hit(Key::Plus, false) {
        app.tab = Tab::ALL[(idx + 1) % Tab::ALL.len()];
    }
    if hit(Key::Minus, false) {
        app.tab = Tab::ALL[(idx + Tab::ALL.len() - 1) % Tab::ALL.len()];
    }
}
