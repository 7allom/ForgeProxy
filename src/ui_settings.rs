//! Settings window: a sidebar (search, User/Project scope, page tree) and a page of
//! setting cards with a breadcrumb header. Only settings this app honours are interactive;
//! behaviour the app can't change is shown disabled, in its fixed state, with the reason.
//!
//! "Project setting" cards are saved in the project file; "User setting" cards are saved in
//! settings.json for every project; "Session setting" cards apply to the running session.

use crate::state::{App, SettingsPage};
use crate::theme::{self, bold, Look, Palette};
use crate::ui_proxy;
use eframe::egui;
use egui::{Align2, FontId, RichText, Sense, Ui};
use std::sync::atomic::Ordering;

/// Where a setting lives. `User` persists globally to settings.json; `Project` lives in the
/// project file; `Override` lives globally but a project can override it (shown as a
/// [User | Project] toggle, the others as a fixed label).
#[derive(Clone, Copy, PartialEq)]
enum Home { User, Project, Override }

struct Card { title: &'static str, description: &'static str, home: Home }

struct PageInfo {
    page: SettingsPage,
    group: Option<&'static str>,
    name: &'static str,
    cards: &'static [Card],
}

const fn card(title: &'static str, description: &'static str, home: Home) -> Card {
    Card { title, description, home }
}

/// Every page and its cards, in sidebar order. The single source for the sidebar, search,
/// breadcrumb and the cards each page draws.
const PAGES: &[PageInfo] = &[
    PageInfo { page: SettingsPage::Proxy, group: Some("Tools"), name: "Proxy", cards: &[
        card("Proxy listeners", "The proxy receives requests from your browser on this interface and port.", Home::User),
        card("Connection timeouts", "How long the proxy waits for data from the browser or the target before closing the connection.", Home::Override),
        card("TLS pass-through", "Hosts in this list will be tunneled directly as opaque TCP without TLS decryption (useful for services with certificate pinning).", Home::Project),
        card("Request interception rules", "Which requests Intercept holds, and how forwarded requests are fixed up.", Home::User),
        card("Skipped file extensions", "Requests for files with these extensions pass through Intercept without being held.", Home::Project),
        card("HTTP match and replace rules", "Automatically replace parts of requests and responses passing through the Proxy (and sent from Repeater).", Home::Project),
        card("Default Proxy interception state", "Whether Intercept is on when this project is opened.", Home::Project),
    ]},
    PageInfo { page: SettingsPage::Intruder, group: Some("Tools"), name: "Intruder", cards: &[
        card("Attack execution", "How many requests an attack sends at once, and the pause between them.", Home::User),
        card("Automatic payload placement", "How each filled-in request is addressed.", Home::User),
    ]},
    PageInfo { page: SettingsPage::Repeater, group: Some("Tools"), name: "Repeater", cards: &[
        card("Connections", "How long requests sent by the tools (Repeater, Intruder, Scanner, Sequencer) wait for the target.", Home::Override),
        card("Message modification", "Changes made to requests before sending and to responses before showing them.", Home::User),
        card("Redirects", "Whether Repeater follows redirect responses.", Home::User),
    ]},
    PageInfo { page: SettingsPage::Sequencer, group: Some("Tools"), name: "Sequencer", cards: &[
        card("Live capture", "How many requests live capture sends at once.", Home::User),
    ]},
    PageInfo { page: SettingsPage::NetworkConnections, group: Some("Network"), name: "Connections", cards: &[
        card("Upstream proxy", "Send outgoing traffic through another proxy: the Proxy's connections to targets (including HTTPS and pass-through tunnels) and requests from Repeater, Intruder, Scanner and Sequencer.", Home::Override),
    ]},
    PageInfo { page: SettingsPage::NetworkTls, group: Some("Network"), name: "TLS / Protocols", cards: &[
        card("Upstream TLS", "How ForgeProxy treats the certificates of the servers it connects to.", Home::Override),
    ]},
    PageInfo { page: SettingsPage::Display, group: Some("User interface"), name: "Display", cards: &[
        card("Display scaling", "Zoom the whole interface.", Home::User),
        card("Editor font size", "Text size in the HTTP request and response editors.", Home::User),
        card("Theme", "Light or dark colours.", Home::Override),
    ]},
    PageInfo { page: SettingsPage::Hotkeys, group: None, name: "Hotkeys", cards: &[
        card("Keyboard shortcuts", "Keys for the actions this app supports. Copy, paste, undo, redo and select-all also work in every text box.", Home::User),
    ]},
];

fn info(page: SettingsPage) -> &'static PageInfo {
    PAGES.iter().find(|i| i.page == page).unwrap_or(&PAGES[0])
}

/// Does the sidebar show this page for the current search text? With no search every page is
/// shown (the tree is static — there is no scope filter that can hide pages).
fn page_visible(info: &PageInfo, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    q.is_empty()
        || info.name.to_lowercase().contains(&q)
        || info.group.is_some_and(|g| g.to_lowercase().contains(&q))
        || info.cards.iter().any(|c| c.title.to_lowercase().contains(&q) || c.description.to_lowercase().contains(&q))
}

const SIDEBAR_W: f32 = 170.0;

pub fn show(app: &mut App, ctx: &egui::Context, p: &Palette) {
    if !app.show_settings {
        return;
    }
    let search_id = egui::Id::new("settings_search");
    let mut search: String = ctx.data(|d| d.get_temp(search_id)).unwrap_or_default();
    let mut open = true;
    theme::show_resizable_window(ctx, egui::Id::new("settings_window"), bold("Settings", 14.0).color(p.strong), &mut open, |ui| {
            // Fixed rectangles for the two panes, then claim exactly the window's area: the
            // window keeps its size (and can be resized) instead of growing with its content.
            let rect = ui.available_rect_before_wrap();
            let side = egui::Rect::from_min_size(rect.min, egui::vec2(SIDEBAR_W, rect.height()));
            let main = egui::Rect::from_min_max(egui::pos2(side.right() + 14.0, rect.top() + 4.0), rect.max);
            ui.painter().rect_filled(side, 0.0, p.deep);
            // detached child UIs: whatever the panes lay out, the window's size is `rect`
            let mut side_ui = ui.new_child(egui::UiBuilder::new().max_rect(side.shrink(8.0)));
            side_ui.set_clip_rect(side.intersect(ui.clip_rect()));
            sidebar(app, &mut side_ui, p, &mut search);
            let mut main_ui = ui.new_child(egui::UiBuilder::new().max_rect(main));
            main_ui.set_clip_rect(main.intersect(ui.clip_rect()));
            main_area(app, &mut main_ui, p);
            ui.allocate_rect(rect, Sense::hover());
        });
    ctx.data_mut(|d| {
        d.insert_temp(search_id, search);
    });
    if !open {
        app.show_settings = false;
    }
}

fn sidebar(app: &mut App, ui: &mut Ui, p: &Palette, search: &mut String) {
    ui.add(egui::TextEdit::singleline(search).desired_width(f32::INFINITY).hint_text("🔍 Search"));
    ui.add_space(8.0);
    let mut groups: Vec<Option<&str>> = Vec::new();
    for i in PAGES {
        if !groups.contains(&i.group) { groups.push(i.group); }
    }
    for group in groups {
        let pages: Vec<&PageInfo> = PAGES.iter().filter(|i| i.group == group && page_visible(i, search)).collect();
        if pages.is_empty() {
            continue;
        }
        match group {
            Some(g) => {
                egui::CollapsingHeader::new(RichText::new(g).size(12.5).color(p.strong)).id_salt(g).default_open(true).show(ui, |ui| {
                    for i in pages { nav_item(app, ui, p, i); }
                });
            }
            None => for i in pages { nav_item(app, ui, p, i); },
        }
    }
}

/// Sidebar row with the blue highlight pill when it's the open page.
fn nav_item(app: &mut App, ui: &mut Ui, p: &Palette, info: &PageInfo) {
    let selected = app.settings_page == info.page;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 22.0), Sense::click());
    if selected {
        ui.painter().rect_filled(rect, 4.0, p.selection);
    } else if resp.hovered() {
        ui.painter().rect_filled(rect, 4.0, p.hover);
    }
    let col = if selected { p.strong } else { p.text };
    ui.painter().text(egui::pos2(rect.left() + 8.0, rect.center().y), Align2::LEFT_CENTER, info.name, FontId::proportional(12.5), col);
    if resp.clicked() {
        app.settings_page = info.page;
    }
}

use theme::pill;

/// Is this Override card currently overridden by the project?
fn card_overridden(app: &App, title: &str) -> bool {
    let o = &app.overrides;
    match title {
        "Theme" => o.theme.is_some(),
        "Connection timeouts" => o.proxy_read_timeout_secs.is_some(),
        "Connections" => o.http_timeout_secs.is_some(),
        "Upstream proxy" => o.upstream_proxy.is_some(),
        "Upstream TLS" => o.verify_upstream_tls.is_some(),
        _ => false,
    }
}

/// Flip an Override card between Project (copy the current global value into the project) and
/// User (drop the override so it inherits the global value again).
fn set_override(app: &mut App, title: &str, project: bool) {
    match title {
        "Theme" => app.overrides.theme = project.then_some(app.settings.theme),
        "Connection timeouts" => app.overrides.proxy_read_timeout_secs = project.then_some(app.settings.proxy_read_timeout_secs),
        "Connections" => app.overrides.http_timeout_secs = project.then_some(app.settings.http_timeout_secs),
        "Upstream proxy" => app.overrides.upstream_proxy = project.then(|| app.settings.upstream_proxy.clone()),
        "Upstream TLS" => app.overrides.verify_upstream_tls = project.then_some(app.settings.protocol.verify_upstream_tls),
        _ => {}
    }
}

fn main_area(app: &mut App, ui: &mut Ui, p: &Palette) {
    let info = info(app.settings_page);
    ui.horizontal(|ui| {
        let crumb = match info.group { Some(g) => format!("{g}  >  {}", info.name), None => info.name.to_string() };
        ui.label(bold(crumb, 15.0).color(p.strong));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.menu_button(RichText::new("Manage settings").size(12.0).color(p.text), |ui| {
                if ui.button("Load settings from a configuration file...").clicked() {
                    ui.close_menu();
                    crate::ui_core::load_config_native(app);
                }
                if ui.button("Save project (includes project settings)").clicked() {
                    ui.close_menu();
                    crate::ui_core::save_project(app);
                }
            });
        });
    });
    ui.separator();
    let focus = app.settings_focus.take();
    // vertical only: cards fit the pane's width (wide tables scroll inside their own area)
    egui::ScrollArea::vertical().hscroll(false).auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(ui.available_width());
        for c in info.cards.iter() {
            let top = ui.cursor().min;
            match c.home {
                Home::Override => {
                    let mut project = card_overridden(app, c.title);
                    let before = project;
                    setting_card_toggle(ui, p, c.title, c.description, &mut project, |ui| card_body(app, ui, p, info.page, c.title));
                    if project != before {
                        set_override(app, c.title, project);
                    }
                }
                home => {
                    let label = if home == Home::Project { "Project" } else { "User" };
                    setting_card(ui, c.title, c.description, Some(label), |ui| card_body(app, ui, p, info.page, c.title));
                }
            }
            if focus == Some(c.title) {
                ui.scroll_to_rect(egui::Rect::from_min_size(top, egui::vec2(10.0, 60.0)), Some(egui::Align::TOP));
            }
        }
    });
}

/// Draw a fixed, non-interactive badge pill (for User- and Project-fixed cards).
fn label_badge(ui: &mut Ui, text: &str) {
    let strong = ui.visuals().strong_text_color();
    let blue = ui.visuals().selection.bg_fill;
    let tip = if text.contains("Project") { "Saved in the project file (.forge)." } else { "Saved on this computer (settings.json) and used by every project." };
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::proportional(11.0), strong);
        let (rect, resp) = ui.allocate_exact_size(galley.size() + egui::vec2(14.0, 4.0), Sense::hover());
        ui.painter().rect_filled(rect, rect.height() / 2.0, blue.gamma_multiply(0.55));
        ui.painter().galley(rect.center() - galley.size() / 2.0, galley, strong);
        resp.on_hover_text(tip);
    });
}

/// Draw the interactive `[ User | Project ]` segmented toggle. Flips `project` on click.
fn toggle_badge(ui: &mut Ui, p: &Palette, project: &mut bool) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.spacing_mut().item_spacing.x = 3.0;
        if pill(ui, p, "Project", *project).on_hover_text("Override this setting for the current project (saved in the .forge file)").clicked() {
            *project = true;
        }
        if pill(ui, p, "User", !*project).on_hover_text("Use the global value from settings.json (no project override)").clicked() {
            *project = false;
        }
    });
}

/// The shared card frame: "(?)" icon, bold title, a header control drawn on the right, a "⚙"
/// description line, the padded body, and a separator underneath.
fn card_shell<R>(ui: &mut Ui, title: &str, description: &str, header: impl FnOnce(&mut Ui), add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    let strong = ui.visuals().strong_text_color();
    let weak = ui.visuals().weak_text_color();
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), Sense::hover());
        ui.painter().circle_stroke(r.center(), 6.5, egui::Stroke::new(1.2_f32, weak));
        ui.painter().text(r.center(), Align2::CENTER_CENTER, "?", FontId::proportional(10.5), weak);
        ui.label(RichText::new(title).font(FontId::new(14.0, egui::FontFamily::Name("bold".into()))).color(strong));
        header(ui);
    });
    egui::Frame::new().inner_margin(egui::Margin { left: 22, right: 8, top: 2, bottom: 0 }).show(ui, |ui| {
        ui.add(egui::Label::new(RichText::new(format!("⚙  {description}")).size(12.0).color(weak)).wrap());
    });
    ui.add_space(6.0);
    let r = egui::Frame::new().inner_margin(egui::Margin { left: 22, right: 8, top: 0, bottom: 4 }).show(ui, add_contents).inner;
    ui.add_space(10.0);
    ui.separator();
    r
}

/// One settings card with a fixed badge label (or none). Used for User/Project-fixed cards and
/// by the Target > Scope view.
pub(crate) fn setting_card<R>(
    ui: &mut Ui,
    title: &str,
    description: &str,
    scope_badge: Option<&str>,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> R {
    card_shell(ui, title, description, |ui| {
        if let Some(badge) = scope_badge {
            label_badge(ui, badge);
        }
    }, add_contents)
}

/// One settings card whose header is the interactive `[ User | Project ]` override toggle.
fn setting_card_toggle<R>(ui: &mut Ui, p: &Palette, title: &str, description: &str, project: &mut bool, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    card_shell(ui, title, description, |ui| toggle_badge(ui, p, project), add_contents)
}


fn card_body(app: &mut App, ui: &mut Ui, p: &Palette, page: SettingsPage, title: &str) {
    match (page, title) {
        (SettingsPage::Proxy, "Proxy listeners") => proxy_listeners(app, ui, p),
        (SettingsPage::Proxy, "Request interception rules") => {
            let mut rules = app.proxy.use_rules.load(Ordering::SeqCst);
            if ui.checkbox(&mut rules, "Intercept requests based on the following rules").changed() {
                app.proxy.use_rules.store(rules, Ordering::SeqCst);
            }
            ui.add_enabled_ui(rules, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(24.0);
                    ui.label(RichText::new("Hold a request unless its file extension is listed under Skipped file extensions below.").size(12.0).color(p.text));
                });
            });
            if !rules {
                ui.label(RichText::new("Rules off: Intercept holds every request.").size(11.5).color(p.disabled));
            }
            let mut fix = app.proxy.fix_length.load(Ordering::SeqCst);
            if ui.checkbox(&mut fix, "Automatically update Content-Length header").on_hover_text("Recalculate Content-Length from the body of each forwarded request (for example after editing it in Intercept)").changed() {
                app.proxy.fix_length.store(fix, Ordering::SeqCst);
            }
        }
        (SettingsPage::Proxy, "HTTP match and replace rules") => ui_proxy::rules_editor(app, ui, p, "mr_settings", true),
        (SettingsPage::Proxy, "TLS pass-through") => tls_passthrough(app, ui, p),
        (SettingsPage::Proxy, "Skipped file extensions") => skip_extensions(app, ui, p),
        (SettingsPage::Proxy, "Connection timeouts") => {
            let timeout = match &mut app.overrides.proxy_read_timeout_secs {
                Some(v) => v,
                None => &mut app.settings.proxy_read_timeout_secs,
            };
            ui.horizontal(|ui| {
                ui.label("Proxy read timeout:");
                ui.add(egui::DragValue::new(timeout).range(crate::state::UserSettings::PROXY_TIMEOUT_RANGE).speed(1.0).suffix(" s"));
                if theme::plain_button(ui, p, "Reset", *timeout != crate::state::DEFAULT_PROXY_READ_TIMEOUT).clicked() {
                    *timeout = crate::state::DEFAULT_PROXY_READ_TIMEOUT;
                }
            });
            ui.label(RichText::new("Applies to connections opened from now on. Raise it for slow targets or long-polling pages.").size(11.5).color(p.disabled));
        }
        (SettingsPage::Proxy, "Default Proxy interception state") => {
            ui.radio_value(&mut app.intercept_default, true, "Enable interception");
            ui.radio_value(&mut app.intercept_default, false, "Disable interception");
            ui.label(RichText::new("Applied when this project is opened. Turn Intercept on or off for now in Proxy > Intercept.").size(11.5).color(p.disabled));
        }
        (SettingsPage::Intruder, "Attack execution") => {
            ui.horizontal(|ui| {
                ui.label("Concurrent connection limit:");
                ui.add(egui::Slider::new(&mut app.int_concurrency, 1..=50));
            });
            ui.horizontal(|ui| {
                ui.label("Delay between requests:");
                ui.add(egui::DragValue::new(&mut app.int_delay_ms).range(0..=60000).suffix(" ms"));
            });
        }
        (SettingsPage::Intruder, "Automatic payload placement") => {
            ui.checkbox(&mut app.int_update_host, "Update Host header to match target")
                .on_hover_text("Off: send the Host header written in the request template");
        }
        (SettingsPage::Repeater, "Connections") => {
            let timeout = match &mut app.overrides.http_timeout_secs {
                Some(v) => v,
                None => &mut app.settings.http_timeout_secs,
            };
            ui.horizontal(|ui| {
                ui.label("HTTP client timeout (seconds):");
                ui.add(egui::DragValue::new(timeout).range(crate::state::UserSettings::HTTP_TIMEOUT_RANGE).speed(0.5).suffix(" s"));
                if theme::plain_button(ui, p, "Reset", *timeout != crate::state::DEFAULT_HTTP_TIMEOUT).clicked() {
                    *timeout = crate::state::DEFAULT_HTTP_TIMEOUT;
                }
            });
            ui.label(RichText::new("Each request opens a new connection. Raise the timeout for time-based tests (a delayed response counts as no response once it passes).").size(11.5).color(p.disabled));
        }
        (SettingsPage::Repeater, "Message modification") => {
            ui.checkbox(&mut app.rep_unpack, "Unpack compressed responses")
                .on_hover_text("Decompress gzip and deflate response bodies (Content-Encoding). Brotli is shown as received.");
            ui.label(RichText::new("Content-Length is always set from the body, and requests are sent with CRLF line endings.").size(11.5).color(p.disabled));
        }
        (SettingsPage::Repeater, "Redirects") => {
            ui.radio_value(&mut app.rep_follow, false, "Never");
            ui.radio_value(&mut app.rep_follow, true, "Always").on_hover_text("Follow up to 5 redirects");
        }
        (SettingsPage::Sequencer, "Live capture") => {
            ui.add(egui::Slider::new(&mut app.sequencer_threads, 1..=20).text("Capture threads"));
            ui.label(RichText::new("Used by the next capture started.").size(11.5).color(p.disabled));
        }
        (SettingsPage::NetworkConnections, "Upstream proxy") => upstream_proxy(app, ui, p),
        (SettingsPage::NetworkTls, "Upstream TLS") => {
            let verify = match &mut app.overrides.verify_upstream_tls {
                Some(v) => v,
                None => &mut app.settings.protocol.verify_upstream_tls,
            };
            ui.checkbox(verify, "Verify upstream server certificates")
                .on_hover_text("On: a server must present a certificate from a trusted authority (Mozilla's list) for its name, or the connection fails. Off: any certificate is accepted, for internal and self-signed test targets.");
            let (text, col) = if *verify {
                ("Servers with self-signed, expired or mismatched certificates are refused (the browser gets 502 Bad Gateway).", p.disabled)
            } else {
                ("Off: any certificate is accepted, so internal and self-signed test servers work. Connections are still encrypted, but you won't notice if something between you and the server intercepts them.", p.medium)
            };
            ui.add(egui::Label::new(RichText::new(text).size(11.5).color(col)).wrap());
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new("HTTP versions: HTTP/1.1 only. The proxy offers browsers HTTP/1.1 (ALPN), so they don't use HTTP/2 through it, and it speaks HTTP/1.1 to servers, as do Repeater, Intruder, Scanner and Sequencer.").size(11.5).color(p.disabled)).wrap());
        }
        (SettingsPage::Display, "Display scaling") => {
            let zoom = ui.ctx().zoom_factor();
            ui.horizontal(|ui| {
                ui.label("Zoom:");
                for z in [0.8_f32, 1.0, 1.25, 1.5] {
                    let on = (zoom - z).abs() < 0.01;
                    if pill(ui, p, &format!("{z}x"), on).clicked() {
                        ui.ctx().set_zoom_factor(z);
                    }
                }
            });
        }
        (SettingsPage::Display, "Editor font size") => {
            ui.horizontal(|ui| {
                ui.label("Font size:");
                ui.add(egui::DragValue::new(&mut app.settings.editor_font_size).range(crate::state::UserSettings::FONT_RANGE).speed(0.25).fixed_decimals(1).suffix(" pt"));
                if theme::plain_button(ui, p, "Reset", (app.settings.editor_font_size - crate::editor::DEFAULT_FONT).abs() > 0.01).clicked() {
                    app.settings.editor_font_size = crate::editor::DEFAULT_FONT;
                }
            });
        }
        (SettingsPage::Display, "Theme") => {
            let mut look = app.eff().theme;
            ui.horizontal(|ui| {
                ui.radio_value(&mut look, Look::Light, "Light");
                ui.radio_value(&mut look, Look::Dark, "Dark");
            });
            if look != app.eff().theme {
                app.set_theme(look);
                theme::apply(ui.ctx(), look);
            }
        }
        (SettingsPage::Hotkeys, _) => {
            const COLS: [(f32, f32); 2] = [(200.0, 0.6), (120.0, 0.4)];
            theme::fitted_table(ui, p, "hotkeys_table", (crate::hotkeys::LIST.len() as f32 + 1.0) * 19.0 + 6.0, &COLS, |ui, w| {
                theme::table_header(ui, p, &[("Action", w[0]), ("Shortcut", w[1])]);
                for (i, (action, key)) in crate::hotkeys::LIST.iter().enumerate() {
                    let _ = theme::table_row(ui, p, &[(action.to_string(), w[0], None), (key.to_string(), w[1], Some(p.strong))], false, i % 2 == 1);
                }
            });
        }
        _ => {}
    }
}

fn proxy_listeners(app: &mut App, ui: &mut Ui, p: &Palette) {
    let edit_id = egui::Id::new("listener_edit");
    let mut editing: bool = ui.data(|d| d.get_temp(edit_id)).unwrap_or(false);
    let running = app.proxy.running.load(Ordering::SeqCst);
    let single = "This app runs a single listener; use Edit to change its address.";
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            let _ = theme::side_button(ui, p, "Add", false).on_disabled_hover_text(single);
            if theme::side_button(ui, p, "Edit", true).clicked() { editing = !editing; }
            let _ = theme::side_button(ui, p, "Remove", false).on_disabled_hover_text(single);
        });
        // (minimum width, share of the spare width) for Running, Interface, Status
        const COLS: [(f32, f32); 3] = [(70.0, 0.0), (160.0, 0.6), (100.0, 0.4)];
        theme::fitted_table(ui, p, "listener_table", 19.0 * 2.0 + 6.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Running", w[0]), ("Interface", w[1]), ("Status", w[2])]);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 19.0), Sense::hover());
            ui.painter().rect_filled(rect, 0.0, p.deep);
            let mut on = running;
            let cb = egui::Rect::from_min_size(rect.min + egui::vec2(6.0, 1.0), egui::vec2(w[0] - 10.0, 17.0));
            if ui.put(cb, egui::Checkbox::without_text(&mut on)).changed() {
                if on { ui_proxy::start_listener(app); } else { app.proxy.stop.store(true, Ordering::SeqCst); }
            }
            let iface = format!("{}:{}", app.proxy_host.trim(), app.proxy_port.trim());
            let status = if running { "Running" } else { "Stopped" };
            let clip = |x: f32, cw: f32| egui::Rect::from_min_max(egui::pos2(x, rect.top()), egui::pos2(x + cw - 8.0, rect.bottom()));
            let x1 = rect.left() + 6.0 + w[0];
            ui.painter().with_clip_rect(clip(x1, w[1])).text(egui::pos2(x1, rect.center().y), Align2::LEFT_CENTER, iface, FontId::proportional(12.5), p.text);
            let x2 = x1 + w[1];
            ui.painter().with_clip_rect(clip(x2, w[2])).text(egui::pos2(x2, rect.center().y), Align2::LEFT_CENTER, status,
                FontId::proportional(12.5), if running { p.st_done } else { p.disabled });
        });
    });
    if editing {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Interface:");
            ui.add_enabled(!running, egui::TextEdit::singleline(&mut app.proxy_host).desired_width(130.0));
            ui.label("Port:");
            ui.add_enabled(!running, egui::TextEdit::singleline(&mut app.proxy_port).desired_width(60.0));
        });
        if running {
            ui.label(RichText::new("Stop the listener (untick Running) to change its address.").size(11.5).color(p.disabled));
        }
    }
    if !app.proxy_msg.is_empty() {
        ui.label(RichText::new(&app.proxy_msg).size(12.0).color(p.text));
    }
    // a listener other machines can reach: say so plainly, whether or not it's running
    if !crate::proxy::is_loopback_interface(&app.proxy_host) {
        ui.add_space(6.0);
        egui::Frame::new().fill(p.high.gamma_multiply(0.18)).stroke(egui::Stroke::new(1.0_f32, p.high))
            .corner_radius(4.0).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("⚠ Listening beyond this machine").strong().size(12.5).color(p.high));
                ui.add(egui::Label::new(RichText::new(crate::proxy::exposed_listener_warning(&app.proxy_host)).size(12.0).color(p.strong)).wrap());
            });
    }
    ui.data_mut(|d| d.insert_temp(edit_id, editing));
    ui.add_space(10.0);
    ca_controls(app, ui, p);
}

/// Upstream proxy: on/off, HTTP CONNECT or SOCKS5, host and port, and what's wrong if it
/// can't be used.
fn upstream_proxy(app: &mut App, ui: &mut Ui, p: &Palette) {
    use crate::state::UpstreamProxyType;
    let up = match &mut app.overrides.upstream_proxy {
        Some(v) => v,
        None => &mut app.settings.upstream_proxy,
    };
    ui.checkbox(&mut up.enabled, "Use an upstream proxy");
    ui.add_enabled_ui(up.enabled, |ui| {
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            // "Direct" means off; the radios pick between the two kinds of proxy
            if up.proxy_type == UpstreamProxyType::Direct {
                up.proxy_type = UpstreamProxyType::HttpConnect;
            }
            ui.radio_value(&mut up.proxy_type, UpstreamProxyType::HttpConnect, "HTTP (CONNECT)")
                .on_hover_text("HTTPS and tunnels: CONNECT host:port. Plain HTTP: the request is sent to the proxy with its full URL, as browsers do");
            ui.radio_value(&mut up.proxy_type, UpstreamProxyType::Socks5, "SOCKS5")
                .on_hover_text("No authentication; host names are resolved by the proxy");
        });
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.label("Host:");
            ui.add(egui::TextEdit::singleline(&mut up.host).desired_width(200.0).hint_text("127.0.0.1"));
            ui.label("Port:");
            ui.add(egui::DragValue::new(&mut up.port).range(1..=65535));
        });
    });
    match up.route() {
        Err(e) => { ui.label(RichText::new(e).size(11.5).color(p.high)); }
        Ok(Some(r)) => {
            let kind = if r.kind == UpstreamProxyType::Socks5 { "SOCKS5" } else { "HTTP" };
            ui.label(RichText::new(format!("Outgoing connections go through the {kind} proxy at {}. If it can't be reached, they fail.", crate::upstream::authority(&r.host, r.port))).size(11.5).color(p.disabled));
        }
        Ok(None) => { ui.label(RichText::new("Off: ForgeProxy connects to targets directly.").size(11.5).color(p.disabled)); }
    }
}

/// Skipped file extensions: Add / Remove beside the list, and the new-extension field (the
/// TLS pass-through table's layout).
fn skip_extensions(app: &mut App, ui: &mut Ui, p: &Palette) {
    let n = app.skip_extensions.len();
    let sel = app.skip_extensions_sel.filter(|&i| i < n);
    let ext = app.skip_extensions_new.trim().trim_start_matches('.').to_ascii_lowercase();
    let valid = !ext.is_empty() && ext.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let duplicate = app.skip_extensions.iter().any(|e| e.eq_ignore_ascii_case(&ext));
    let mut add = false;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            add = theme::side_button(ui, p, "Add", valid && !duplicate).on_disabled_hover_text("Type an extension below, such as png or .woff2").clicked();
            if theme::side_button(ui, p, "Remove", sel.is_some()).clicked() {
                if let Some(i) = sel {
                    app.skip_extensions.remove(i);
                    app.skip_extensions_sel = None;
                }
            }
            if theme::side_button(ui, p, "Defaults", app.skip_extensions != crate::rules::default_skip_extensions())
                .on_hover_text("Restore the default list").clicked() {
                app.skip_extensions = crate::rules::default_skip_extensions();
                app.skip_extensions_sel = None;
            }
        });
        const COLS: [(f32, f32); 1] = [(200.0, 1.0)];
        theme::fitted_table(ui, p, "skip_extensions_table", 19.0 * 6.0 + 6.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Extension", w[0])]);
            egui::ScrollArea::vertical().id_salt("skip_extensions_rows").auto_shrink([false, true]).show(ui, |ui| {
                if app.skip_extensions.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new("  No extensions: with the rules on, Intercept holds every request.").size(12.0).color(p.disabled));
                }
                for (i, e) in app.skip_extensions.iter().enumerate() {
                    if theme::table_row(ui, p, &[(format!(".{e}"), w[0], None)], sel == Some(i), i % 2 == 1).clicked() {
                        app.skip_extensions_sel = Some(i);
                    }
                }
            });
        });
    });
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Extension:");
        let field = ui.add(egui::TextEdit::singleline(&mut app.skip_extensions_new).desired_width(160.0).hint_text("png  or  .woff2"));
        if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && valid && !duplicate {
            add = true;
        }
        if duplicate {
            ui.label(RichText::new("already in the list").size(11.5).color(p.disabled));
        }
    });
    if !app.proxy.use_rules.load(Ordering::SeqCst) {
        ui.label(RichText::new("Request interception rules are off, so this list isn't used right now.").size(11.5).color(p.disabled));
    }
    if add {
        app.skip_extensions.push(ext);
        app.skip_extensions_new.clear();
        app.skip_extensions_sel = Some(app.skip_extensions.len() - 1);
    }
}

/// TLS pass-through: Add / Remove beside the list of host patterns, and the new-pattern field.
fn tls_passthrough(app: &mut App, ui: &mut Ui, p: &Palette) {
    let n = app.tls_passthrough.len();
    let sel = app.tls_passthrough_sel.filter(|&i| i < n);
    let pattern = app.tls_passthrough_new.trim().to_ascii_lowercase();
    let valid = !pattern.is_empty() && !pattern.contains(char::is_whitespace) && !pattern.contains('/')
        && pattern != "*." && pattern != ".";
    let duplicate = app.tls_passthrough.iter().any(|r| r.eq_ignore_ascii_case(&pattern));
    let mut add = false;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            add = theme::side_button(ui, p, "Add", valid && !duplicate).on_disabled_hover_text("Type a host name or *.domain below").clicked();
            if theme::side_button(ui, p, "Remove", sel.is_some()).clicked() {
                if let Some(i) = sel {
                    app.tls_passthrough.remove(i);
                    app.tls_passthrough_sel = None;
                }
            }
        });
        const COLS: [(f32, f32); 1] = [(200.0, 1.0)];
        theme::fitted_table(ui, p, "tls_passthrough_table", 19.0 * 5.0 + 6.0, &COLS, |ui, w| {
            theme::table_header(ui, p, &[("Host pattern", w[0])]);
            egui::ScrollArea::vertical().id_salt("tls_passthrough_rows").auto_shrink([false, true]).show(ui, |ui| {
                if app.tls_passthrough.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new("  No hosts: every HTTPS host is decrypted while Intercept HTTPS is on.").size(12.0).color(p.disabled));
                }
                for (i, rule) in app.tls_passthrough.iter().enumerate() {
                    if theme::table_row(ui, p, &[(rule.clone(), w[0], None)], sel == Some(i), i % 2 == 1).clicked() {
                        app.tls_passthrough_sel = Some(i);
                    }
                }
            });
        });
    });
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Host:");
        let field = ui.add(egui::TextEdit::singleline(&mut app.tls_passthrough_new).desired_width(260.0).hint_text("api.example.com  or  *.example.com"));
        if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && valid && !duplicate {
            add = true;
        }
        if duplicate {
            ui.label(RichText::new("already in the list").size(11.5).color(p.disabled));
        }
    });
    ui.label(RichText::new("\"*.example.com\" and \".example.com\" match its subdomains, not example.com itself: add that separately if needed.").size(11.5).color(p.disabled));
    if add {
        app.tls_passthrough.push(pattern);
        app.tls_passthrough_new.clear();
        app.tls_passthrough_sel = Some(app.tls_passthrough.len() - 1);
    }
}

/// Root CA: status, export (certificate only) and regenerate, under the listener table.
fn ca_controls(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.label(bold("Root CA certificate", 13.0).color(p.strong));
    match (&app.ca, &app.ca_error) {
        (Some(ca), _) => {
            ui.label(RichText::new(format!("CN={} · SHA-256 {}", crate::ca::COMMON_NAME, ca.fingerprint())).size(11.5).monospace().color(p.text));
            ui.label(RichText::new(format!("Stored in {}", crate::ca::config_dir().display())).size(11.5).color(p.disabled));
            if let Some(cache) = &app.tls_cache {
                ui.label(RichText::new(format!("Host certificates issued this session: {}", cache.len())).size(11.5).color(p.disabled));
            }
        }
        (None, Some(e)) => { ui.label(RichText::new(format!("Unavailable: {e}")).size(12.0).color(p.high)); }
        (None, None) => { ui.label(RichText::new("Not loaded.").size(12.0).color(p.disabled)); }
    }
    let have = app.ca.is_some();
    ui.add_space(4.0);
    let mut on = app.proxy.decrypt_https.load(Ordering::SeqCst);
    let cb = ui.add_enabled(have, egui::Checkbox::new(&mut on, "Intercept HTTPS (decrypt it with this root CA)"))
        .on_hover_text("On: HTTPS requests appear in HTTP history in full and go through Intercept and match-and-replace. Off: HTTPS is passed through unopened.")
        .on_disabled_hover_text("Needs a root CA certificate");
    if cb.changed() {
        app.proxy.decrypt_https.store(on, Ordering::SeqCst);
        crate::proxy::log(&app.proxy.events, if on { "HTTPS interception turned on" } else { "HTTPS interception turned off" });
    }
    let note = if on && have {
        "Browsers must trust this certificate, or every HTTPS site shows a certificate error: export it and install it as a trusted root in the browser you use with the proxy."
    } else {
        "With interception off, HTTPS is passed through unopened and nothing is signed with this certificate."
    };
    ui.label(RichText::new(format!("{note} A trusted root lets whoever holds its key impersonate any site to that browser: only install it when you need it, and remove it afterwards.")).size(11.5).color(p.medium));
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Export to folder:");
        ui.add(egui::TextEdit::singleline(&mut app.ca_export_dir).desired_width((ui.available_width() - 250.0).max(160.0)));
        for (label, ext) in [("Export DER", "der"), ("Export PEM", "pem")] {
            if theme::plain_button(ui, p, label, have).on_hover_text(format!("Writes forgeproxy-ca.{ext} (the certificate only, never the private key)")).clicked() {
                if let Some(ca) = app.ca.clone() {
                    let dest = std::path::Path::new(app.ca_export_dir.trim()).join(format!("forgeproxy-ca.{ext}"));
                    let result = if ext == "der" { ca.export_cert_der(&dest) } else { ca.export_cert_pem(&dest) };
                    app.ca_msg = match result {
                        Ok(()) => { let m = format!("Exported the CA certificate to {}", dest.display()); crate::proxy::log(&app.proxy.events, m.clone()); m }
                        Err(e) => { let m = format!("Couldn't export to {}: {e}", dest.display()); crate::proxy::log_error(&app.proxy.events, m.clone()); m }
                    };
                }
            }
        }
    });
    ui.horizontal(|ui| {
        let label = if have { "Regenerate CA certificate" } else { "Create a new CA certificate" };
        if theme::plain_button(ui, p, label, true).clicked() {
            app.ca_confirm_regenerate = true;
        }
        if !app.ca_msg.is_empty() {
            ui.label(RichText::new(&app.ca_msg).size(12.0).color(p.text));
        }
    });
    if app.ca_confirm_regenerate {
        let modal = egui::Modal::new(egui::Id::new("ca_regenerate_confirm")).show(ui.ctx(), |ui| {
            ui.set_width(420.0);
            ui.label(bold("Regenerate the root CA certificate?", 14.0).color(p.strong));
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new("Regenerating will invalidate the previously trusted certificate in browsers. Continue?").color(p.text)).wrap());
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(format!("The current certificate and key in {} are overwritten.", crate::ca::config_dir().display())).size(11.5).color(p.disabled)).wrap());
            ui.add_space(10.0);
            let mut choice = None;
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::primary_button(ui, p, "Regenerate").clicked() { choice = Some(true); }
                if theme::plain_button(ui, p, "Cancel", true).clicked() { choice = Some(false); }
            });
            choice
        });
        match modal.inner {
            Some(true) => { app.ca_confirm_regenerate = false; app.regenerate_ca(); }
            Some(false) => app.ca_confirm_regenerate = false,
            None if modal.should_close() => app.ca_confirm_regenerate = false,
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_is_listed_once() {
        for page in [SettingsPage::Proxy, SettingsPage::Intruder, SettingsPage::Repeater, SettingsPage::Sequencer, SettingsPage::NetworkConnections, SettingsPage::NetworkTls, SettingsPage::Display, SettingsPage::Hotkeys] {
            assert_eq!(PAGES.iter().filter(|i| i.page == page).count(), 1, "{page:?}");
        }
    }

    #[test]
        fn search_pages() {
            let proxy = info(SettingsPage::Proxy);
            assert!(page_visible(proxy, ""));
            assert!(page_visible(proxy, "match and replace")); // card title
            assert!(page_visible(proxy, "tools")); // group
            assert!(!page_visible(proxy, "zoom"));
            assert!(page_visible(info(SettingsPage::Hotkeys), ""));
        }

    #[test]
    fn columns_fit_or_keep_their_minimums() {
        let cols = [(64.0, 0.0), (100.0, 1.0), (100.0, 3.0)];
        // room to spare: fixed column stays, the rest is shared 1:3
        assert_eq!(theme::fit_columns(664.0, &cols), vec![64.0, 200.0, 400.0]);
        // too narrow: minimums (the table then scrolls inside its own area)
        assert_eq!(theme::fit_columns(100.0, &cols), vec![64.0, 100.0, 100.0]);
    }

    #[test]
    fn deep_link_targets_exist() {
        // the command palette scrolls to these cards
        for (page, title) in crate::ui_palette::SETTINGS_LINKS {
            assert!(info(*page).cards.iter().any(|c| c.title == *title), "{title}");
        }
    }
}
