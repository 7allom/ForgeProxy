//! Window chrome: top menu, tab row, status bar, project dialogs; and shared row helpers.

use crate::state::{App, DrawerTab, ProjectDialog, Tab};
use crate::theme::{self, bold, Palette};
use eframe::egui;
use egui::{Color32, FontId, RichText, Ui};

/// Outer padding of every tab's content, so text and buttons never touch the window edges.
pub const TAB_MARGIN: egui::Margin = egui::Margin { left: 10, right: 10, top: 6, bottom: 10 };

pub fn c(hex: u32) -> Color32 { Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8) }

pub fn frame(app: &mut App, ctx: &egui::Context) {
    let p = app.p();
    crate::editor::set_font_size(ctx, app.settings.editor_font_size);
    crate::editor::set_default_view_mode(ctx, app.settings.default_message_view);
    crate::editor::set_display_limit(ctx, app.settings.display_limit_kib.saturating_mul(1024));
    // another tab or sub-tab: the Auto-Decoder starts empty there
    crate::editor::decoder_context(ctx, "view", format!("{}/{}/{}", app.tab.label(), app.proxy_sub, app.target_sub));
    top_menu(app, ctx, &p);
    crate::hotkeys::handle(app, ctx);
    tab_bar(app, ctx, &p);
    status_bar(app, ctx, &p);
    drawer(app, ctx, &p);
    crate::ui_dash::windows(app, ctx, &p);
    crate::windows::show(app, ctx, &p);
    crate::ui_tools::attack_window(app, ctx, &p);
    project_dialog(app, ctx, &p);
    new_project_dialog(app, ctx, &p);
    exit_dialog(app, ctx, &p);
    egui::CentralPanel::default().frame(egui::Frame::new().fill(p.panel).inner_margin(TAB_MARGIN)).show(ctx, |ui| {
        match app.tab {
            Tab::Dashboard => crate::ui_dash::dashboard(app, ui, &p),
            Tab::Target => crate::ui_tools::target(app, ui, &p),
            Tab::Proxy => crate::ui_proxy::proxy(app, ui, &p),
            Tab::Intruder => crate::ui_tools::intruder(app, ui, &p),
            Tab::Repeater => crate::ui_tools::repeater(app, ui, &p),
            Tab::Interactor => crate::ui_tools::interactor(app, ui, &p),
            Tab::Sequencer => crate::ui_sequencer::sequencer(app, ui, &p),
            Tab::Decoder => crate::ui_tools::decoder(app, ui, &p),
            Tab::Comparer => crate::ui_comparer::comparer(app, ui, &p),
            Tab::Logger => crate::ui_tools::logger(app, ui, &p),
            Tab::Organizer => crate::ui_organizer::organizer(app, ui, &p),
            Tab::Automation => crate::ui_automation::automation(app, ui, &p),
        }
    });
}

fn top_menu(app: &mut App, ctx: &egui::Context, p: &Palette) {
    egui::TopBottomPanel::top("menu")
        .frame(
            egui::Frame::new()
                .fill(p.panel)
                .inner_margin(egui::Margin::symmetric(8, 4))
                // the strip is closed off from the tab row below it by one crisp line
                .stroke(egui::Stroke::NONE),
        )
        .show_separator_line(false)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                // "Suite" starts the row, flush with the Dashboard tab under it
                crate::menus::bar(app, ui);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let title = match &app.project_path {
                        Some(_) if !app.project_name.is_empty() => format!("ForgeProxy — {}", app.project_name),
                        Some(path) => format!("ForgeProxy — {path}"),
                        None => "ForgeProxy — Temporary Project".to_string(),
                    };
                    ui.label(RichText::new(title).size(theme::FONT_UI).color(p.disabled));
                });
            });
        });
}

fn tab_bar(app: &mut App, ctx: &egui::Context, p: &Palette) {
    egui::TopBottomPanel::top("tabs")
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin { left: 4, right: 8, top: 0, bottom: 0 }))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let items: Vec<(Tab, &str)> = Tab::ALL.iter().map(|t| (*t, t.label())).collect();
                theme::underline_tabs(ui, p, &items, &mut app.tab, 30.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(2.0);
                    let (g, gs) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::click());
                    theme::paint_gear(ui.painter(), g.center(), 7.0, p.text);
                    if gs.on_hover_text("Settings").clicked() { app.show_settings = true; }
                    let (cr, cs) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::click());
                    ui.painter().text(cr.center(), egui::Align2::CENTER_CENTER, ">_", FontId::monospace(11.0), p.text);
                    if cs.on_hover_text("Command palette (Ctrl+K)").clicked() { app.show_palette = true; app.palette_query.clear(); }
                    let (gr, bs) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::click());
                    theme::paint_globe(ui.painter(), gr.center(), 7.5, p.text);
                    if bs.on_hover_text("Open browser").clicked() { crate::ui_proxy::open_browser(app); }
                });
            });
        });
}

fn status_bar(app: &mut App, ctx: &egui::Context, p: &Palette) {
    use std::sync::atomic::Ordering;
    egui::TopBottomPanel::bottom("status")
        .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::symmetric(8, 3)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                // each pill opens its drawer tab, or closes the drawer if that tab is showing
                for (tab, name) in [(DrawerTab::EventLog, "Event log"), (DrawerTab::AllIssues, "All issues")] {
                    let open = app.drawer == Some(tab);
                    let colour = if open { p.accent } else { p.disabled };
                    let hint = if open { format!("Hide {name}") } else { format!("Show {name}") };
                    if theme::status_pill(ui, p, name, colour).on_hover_text(hint).clicked() {
                        app.drawer = if open { None } else { Some(tab) };
                    }
                }
                theme::chrome_divider(ui, p);

                // the listener, which is the one thing worth seeing at a glance from anywhere
                let (running, intercept) =
                    (app.proxy.running.load(Ordering::SeqCst), app.proxy.intercept.load(Ordering::SeqCst));
                let (badge, colour, hint) = match (running, intercept) {
                    (false, _) => ("Listener off".to_string(), p.error, "The proxy listener is not running. Proxy > Intercept starts it.".to_string()),
                    (true, true) => (format!("Intercepting :{}", app.proxy_port), p.warning, "Requests are being held for review in Proxy > Intercept.".to_string()),
                    (true, false) => (format!("Listening :{}", app.proxy_port), p.success, "The proxy is passing traffic and recording it.".to_string()),
                };
                if theme::status_pill(ui, p, &badge, colour).on_hover_text(hint).clicked() {
                    app.tab = Tab::Proxy;
                }
                theme::chrome_divider(ui, p);

                // the project this work belongs to, shortened from the left so the file shows
                let project = match &app.project_path {
                    Some(path) => path.clone(),
                    None => "Temporary project".to_string(),
                };
                ui.label(RichText::new(ellipsize_left(&project, 52)).size(11.0).color(p.disabled))
                    .on_hover_text(&project);

                if !app.project_msg.is_empty() {
                    theme::chrome_divider(ui, p);
                    ui.label(RichText::new(&app.project_msg).size(11.0).color(p.text));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // monospace, so the figure does not jiggle as it changes
                    ui.label(RichText::new(memory_text()).size(11.0).monospace().color(p.disabled));
                });
            });
        });
}

/// Keep the last `max` characters of a path, with a leading ellipsis when it was longer: the
/// end of a path says which project this is, the start rarely does.
fn ellipsize_left(text: &str, max: usize) -> String {
    let n = text.chars().count();
    if n <= max {
        return text.to_string();
    }
    let tail: String = text.chars().skip(n - max).collect();
    format!("\u{2026}{tail}")
}

/// The bottom drawer: Event log and All issues, docked above the status bar, resizable by
/// dragging its top edge.
fn drawer(app: &mut App, ctx: &egui::Context, p: &Palette) {
    let Some(mut tab) = app.drawer else { return };
    let mut close = false;
    egui::TopBottomPanel::bottom("drawer")
        .resizable(true)
        .default_height(180.0)
        .height_range(120.0..=350.0)
        .frame(egui::Frame::new().fill(p.panel).stroke(egui::Stroke::new(1.0_f32, p.header)).inner_margin(egui::Margin::symmetric(10, 4)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                theme::underline_tabs(ui, p, &[(DrawerTab::EventLog, "Event log"), (DrawerTab::AllIssues, "All issues")], &mut tab, 26.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(egui::Button::new(RichText::new("×").size(15.0).color(p.text)).frame(false)).on_hover_text("Close").clicked() {
                        close = true;
                    }
                    if tab == DrawerTab::EventLog {
                        let n = app.proxy.events.lock().unwrap_or_else(|e| e.into_inner()).len();
                        if theme::plain_button(ui, p, "Clear", n > 0).clicked() {
                            app.proxy.events.lock().unwrap_or_else(|e| e.into_inner()).clear();
                        }
                    }
                });
            });
            ui.add_space(4.0);
            match tab {
                DrawerTab::EventLog => event_log(app, ui, p),
                DrawerTab::AllIssues => {
                    egui::ScrollArea::vertical().id_salt("drawer_issues").auto_shrink([false, false]).show(ui, |ui| {
                        crate::ui_dash::issues_view(app, ui, p, None);
                    });
                }
            }
        });
    app.drawer = if close { None } else { Some(tab) };
}

fn event_log(app: &mut App, ui: &mut Ui, p: &Palette) {
    let count = app.proxy.events.lock().unwrap_or_else(|e| e.into_inner()).len();
    if count == 0 {
        let _ = theme::empty_state_card(ui, None, "No events yet", "Proxy listener starts and stops, browser launches and connection failures are logged here.", None);
        return;
    }
    // (minimum width, share of the spare width): Time, Level, Message
    const COLS: [(f32, f32); 3] = [(80.0, 0.0), (60.0, 0.0), (200.0, 1.0)];
    // a little under the space left: asking for all of it (plus the well's border) would
    // grow the resizable drawer every frame
    let h = (ui.available_height() - 6.0).max(40.0);
    theme::fitted_table(ui, p, "event_log_table", h, &COLS, |ui, w| {
        theme::table_header(ui, p, &[("Time (UTC)", w[0]), ("Level", w[1]), ("Message", w[2])]);
        // only the rows in view are copied out of the log and drawn (it holds up to 10,000)
        egui::ScrollArea::vertical().id_salt("event_rows").auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, 19.0, count, |ui, range| {
            let first = range.start;
            let events: Vec<crate::proxy::Event> = {
                let log = app.proxy.events.lock().unwrap_or_else(|e| e.into_inner());
                let end = range.end.min(log.len());
                log.range(first.min(end)..end).cloned().collect()
            };
            for (k, e) in events.iter().enumerate() {
                let i = first + k;
                let level_col = match e.level { crate::proxy::Level::Error => p.high, crate::proxy::Level::Warning => p.medium, crate::proxy::Level::Info => p.text };
                let cells = [(e.time.clone(), w[0], Some(p.disabled)), (e.level.label().to_string(), w[1], Some(level_col)), (e.message.clone(), w[2], None)];
                let _ = theme::table_row(ui, p, &cells, false, i % 2 == 1);
            }
        });
    });
}

/// "Memory: <this process> of <total RAM>", read from /proc on Linux.
fn memory_text() -> String {
    let rss_kb = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| {
        s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
    });
    let total_kb = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
        s.lines().find(|l| l.starts_with("MemTotal:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
    });
    match (rss_kb, total_kb) {
        (Some(r), Some(t)) => format!("Memory: {:.1}MB of {:.2}GB", r / 1024.0, t / 1024.0 / 1024.0),
        _ => "Memory: -".into(),
    }
}

/// "Save Project Before Exiting?": shown when the window is closed on a temporary project
/// that has data in it.
fn exit_dialog(app: &mut App, ctx: &egui::Context, p: &Palette) {
    if !app.show_exit_save_dialog {
        return;
    }
    let modal = egui::Modal::new(egui::Id::new("exit_save_dialog")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.label(bold("Save Project Before Exiting?", 15.0).color(p.strong));
        ui.add_space(8.0);
        ui.add(egui::Label::new(RichText::new("You are currently running on a temporary in-memory project. All captured HTTP history, Repeater tabs, and session state will be lost.").color(p.text)).wrap());
        ui.add_space(14.0);
        let mut choice = None;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::primary_button(ui, p, "Save Project").clicked() { choice = Some(ExitChoice::Save); }
            if theme::plain_button(ui, p, "Discard & Exit", true).clicked() { choice = Some(ExitChoice::Discard); }
            if theme::plain_button(ui, p, "Cancel", true).clicked() { choice = Some(ExitChoice::Cancel); }
        });
        choice
    });
    let choice = modal.inner.or_else(|| modal.should_close().then_some(ExitChoice::Cancel));
    match choice {
        Some(ExitChoice::Save) => {
            // the usual "Save project as" dialog; App::handle_close exits once it has saved
            app.show_exit_save_dialog = false;
            app.exit_after_save = true;
            open_project_dialog(app, ProjectDialog::SaveAs);
        }
        Some(ExitChoice::Discard) => {
            app.show_exit_save_dialog = false;
            app.force_exit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        Some(ExitChoice::Cancel) => app.show_exit_save_dialog = false,
        None => {}
    }
}

#[derive(Clone, Copy)]
enum ExitChoice { Save, Discard, Cancel }

/// Opens a Project menu dialog with its path field pre-filled.
pub fn open_project_dialog(app: &mut App, d: ProjectDialog) {
    app.project_file = match d {
        ProjectDialog::New => String::new(),
        _ => app.project_path.clone().unwrap_or_else(|| crate::project::default_path(&app.project_name)),
    };
    if d == ProjectDialog::New {
        app.project_name.clear();
    }
    app.project_msg.clear();
    app.project_dialog = Some(d);
}

// ---- native file dialogs -------------------------------------------------------------------

/// A native dialog starting where the current project file is (else in Documents), with the
/// project's file name suggested.
fn native_dialog(app: &App) -> rfd::FileDialog {
    let current = app.project_path.as_deref().map(std::path::Path::new);
    let dir = current.and_then(|p| p.parent()).filter(|d| d.is_dir()).map(|d| d.to_path_buf()).unwrap_or_else(crate::paths::documents_dir);
    let name = current.and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| crate::project::default_file_name(&app.project_name));
    rfd::FileDialog::new().set_directory(dir).set_file_name(name)
}

/// The native "open" dialog: a project file (.forge, or .json) chosen by the user.
fn native_pick(app: &App) -> Option<String> {
    native_dialog(app)
        .add_filter("ForgeProxy Project", &["forge", "json"])
        .add_filter("All files", &["*"])
        .pick_file()
        .map(|p| p.display().to_string())
}

/// The native "save" dialog: where to save the project (.forge added when no extension).
fn native_save(app: &App) -> Option<String> {
    native_dialog(app)
        .add_filter("ForgeProxy Project", &[crate::project::EXTENSION])
        .save_file()
        .map(|p| crate::project::with_extension(p).display().to_string())
}

/// A dialog that closed (with nothing chosen) faster than anyone could cancel one most
/// likely couldn't be shown at all (no file-dialog portal on Linux, say).
fn dialog_failed(started: std::time::Instant) -> bool {
    started.elapsed() < std::time::Duration::from_millis(300)
}

/// Project > Open project...: the native dialog, then the file is opened straight away. If
/// it fails to open, or no native dialog could be shown, the in-app dialog takes over (with
/// the path and the error).
pub fn open_project_native(app: &mut App) {
    let started = std::time::Instant::now();
    match native_pick(app) {
        Some(path) => {
            app.project_file = path;
            app.project_dialog = Some(ProjectDialog::Open);
            submit_project_dialog(app, ProjectDialog::Open);
        }
        None if dialog_failed(started) => open_project_dialog(app, ProjectDialog::Open),
        None => {}
    }
}

/// Project > Load configuration file...: the native dialog (JSON configuration, or a
/// project file), then its scope and rules are applied at once. A file that won't load
/// opens the in-app dialog with the error.
pub fn load_config_native(app: &mut App) {
    let started = std::time::Instant::now();
    let picked = native_dialog(app)
        .add_filter("JSON Configuration", &["json"])
        .add_filter("ForgeProxy Project", &[crate::project::EXTENSION])
        .pick_file()
        .map(|p| p.display().to_string());
    match picked {
        Some(path) => {
            app.project_file = path;
            app.project_dialog = Some(ProjectDialog::LoadConfig);
            submit_project_dialog(app, ProjectDialog::LoadConfig);
        }
        None if dialog_failed(started) => open_project_dialog(app, ProjectDialog::LoadConfig),
        None => {}
    }
}

/// "New project" > "Save new project as...": choose its file, then start the empty project
/// there (named after the file). Cancelling keeps the current project as it is.
fn new_project_native(app: &mut App) {
    let started = std::time::Instant::now();
    // suggest a fresh name, not the current project's file
    let dialog = rfd::FileDialog::new()
        .set_directory(crate::paths::documents_dir())
        .set_file_name(crate::project::default_file_name(""))
        .add_filter("ForgeProxy Project", &[crate::project::EXTENSION]);
    match dialog.save_file() {
        Some(path) => {
            let path = crate::project::with_extension(path);
            let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            app.project_file = path.display().to_string();
            app.project_name = name;
            app.project_dialog = Some(ProjectDialog::New);
            submit_project_dialog(app, ProjectDialog::New);
        }
        None if dialog_failed(started) => open_project_dialog(app, ProjectDialog::New),
        None => {}
    }
}

/// Project > New project...: asks how to start (warning first when the current project has
/// data in it): a new project file, or a clean temporary project.
fn new_project_dialog(app: &mut App, ctx: &egui::Context, p: &Palette) {
    if !app.show_new_project_dialog {
        return;
    }
    let has_data = app.has_project_data();
    let modal = egui::Modal::new(egui::Id::new("new_project_dialog")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(bold("New project", 15.0).color(p.strong));
        ui.add_space(8.0);
        let text = match (&app.project_path, has_data) {
            (None, true) => "The current temporary project has data in it (HTTP history, Repeater, scope or other work). Starting a new project discards it.".to_string(),
            (Some(path), true) => format!("Changes to {path} since it was last saved will be lost. Use Project > Save project first to keep them."),
            (_, false) => "Save the new project to a file, or start a temporary project in memory.".to_string(),
        };
        ui.add(egui::Label::new(RichText::new(text).color(if has_data { p.medium } else { p.text })).wrap());
        ui.add_space(14.0);
        let mut choice = None;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::primary_button(ui, p, "Save new project as...").clicked() { choice = Some(NewChoice::File); }
            if theme::plain_button(ui, p, "New temporary project", true).clicked() { choice = Some(NewChoice::Temporary); }
            if theme::plain_button(ui, p, "Cancel", true).clicked() { choice = Some(NewChoice::Cancel); }
        });
        choice
    });
    let choice = modal.inner.or_else(|| modal.should_close().then_some(NewChoice::Cancel));
    match choice {
        Some(NewChoice::File) => {
            app.show_new_project_dialog = false;
            new_project_native(app);
        }
        Some(NewChoice::Temporary) => {
            app.show_new_project_dialog = false;
            crate::project::reset(app);
            crate::proxy::log(&app.proxy.events, "Started a new temporary project");
        }
        Some(NewChoice::Cancel) => app.show_new_project_dialog = false,
        None => {}
    }
}

#[derive(Clone, Copy)]
enum NewChoice { File, Temporary, Cancel }

/// Project > Save project as...: the native dialog, then the project is saved there (with
/// the same fallback as `open_project_native`).
pub fn save_project_as_native(app: &mut App) {
    let started = std::time::Instant::now();
    match native_save(app) {
        Some(path) => {
            app.project_file = path;
            app.project_dialog = Some(ProjectDialog::SaveAs);
            submit_project_dialog(app, ProjectDialog::SaveAs);
        }
        None if dialog_failed(started) => open_project_dialog(app, ProjectDialog::SaveAs),
        None => {}
    }
}

/// Save to the current project file, or ask for one if the project is temporary.
pub fn save_project(app: &mut App) {
    match app.project_path.clone() {
        Some(path) => {
            app.project_msg = match crate::project::save(app, &path) {
                Ok(()) => format!("Saved to {path}"),
                Err(e) => format!("Couldn't save: {e}"),
            };
        }
        // a temporary project: the same native picker as "Save project as..."
        None => save_project_as_native(app),
    }
}

fn project_dialog(app: &mut App, ctx: &egui::Context, p: &Palette) {
    let Some(d) = app.project_dialog else { return };
    let (title, action) = match d {
        ProjectDialog::New => ("New project on disk", "Create"),
        ProjectDialog::Open => ("Open project", "Open"),
        ProjectDialog::SaveAs => ("Save project as", "Save"),
        ProjectDialog::LoadConfig => ("Load configuration file", "Load"),
    };
    let mut open = true;
    let mut submit = false;
    let mut cancel = false;
    egui::Window::new(bold(title, 14.0).color(p.strong))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .default_width(520.0)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui| {
            egui::Grid::new("project_dialog").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
                if matches!(d, ProjectDialog::New | ProjectDialog::SaveAs) {
                    ui.label(RichText::new("Name:").color(p.text));
                    let r = ui.add(egui::TextEdit::singleline(&mut app.project_name).desired_width(420.0));
                    if r.changed() && d == ProjectDialog::New {
                        app.project_file = crate::project::default_path(&app.project_name);
                    }
                    ui.end_row();
                }
                ui.label(RichText::new("File:").color(p.text));
                ui.horizontal(|ui| {
                    let r = ui.add(egui::TextEdit::singleline(&mut app.project_file).desired_width(340.0));
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit = true;
                    }
                    if theme::plain_button(ui, p, "Browse...", true).on_hover_text("Choose the file in your system's file dialog").clicked() {
                        let chosen = match d {
                            ProjectDialog::New | ProjectDialog::SaveAs => native_save(app),
                            ProjectDialog::Open | ProjectDialog::LoadConfig => native_pick(app),
                        };
                        if let Some(path) = chosen {
                            app.project_file = path;
                            app.project_msg.clear();
                        }
                    }
                });
                ui.end_row();
            });
            if d == ProjectDialog::LoadConfig {
                ui.label(RichText::new("Applies only scope and match-and-replace rules from the file.").size(11.5).color(p.disabled));
            }
            if !app.project_msg.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new(&app.project_msg).color(p.high));
            }
            ui.add_space(8.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::primary_button(ui, p, action).clicked() { submit = true; }
                if theme::plain_button(ui, p, "Cancel", true).clicked() { cancel = true; }
            });
        });
    if submit {
        submit_project_dialog(app, d);
    }
    if !open || cancel {
        app.project_dialog = None;
        app.project_msg.clear();
    }
}

fn submit_project_dialog(app: &mut App, d: ProjectDialog) {
    app.project_msg.clear();
    let path = app.project_file.trim().to_string();
    if path.is_empty() {
        app.project_msg = "Enter a file path.".into();
        return;
    }
    let result = match d {
        ProjectDialog::New | ProjectDialog::SaveAs => {
            if d == ProjectDialog::New {
                // an empty project, keeping the name it was given
                let name = std::mem::take(&mut app.project_name);
                crate::project::reset(app);
                app.project_name = name;
            }
            crate::project::save(app, &path).map(|()| format!("Saved to {path}")).map_err(|e| format!("Couldn't save: {e}"))
        }
        ProjectDialog::Open => crate::project::read(&path).map(|f| {
            crate::project::apply_all(app, f);
            format!("Opened {path}")
        }),
        ProjectDialog::LoadConfig => crate::project::read(&path).map(|f| {
            crate::project::apply_settings(app, &f);
            format!("Loaded configuration from {path}")
        }),
    };
    match result {
        Ok(msg) => {
            crate::proxy::log(&app.proxy.events, msg.clone());
            if d != ProjectDialog::LoadConfig {
                app.project_path = Some(path);
            }
            app.project_dialog = None;
            app.project_msg = msg;
        }
        Err(e) => app.project_msg = e,
    }
}

/// Second-level tab row with the orange underline.
pub fn sub_tabs(ui: &mut Ui, p: &Palette, labels: &[&str], sel: &mut u8) {
    egui::Frame::new().fill(p.panel).inner_margin(egui::Margin { left: 4, right: 4, top: 0, bottom: 0 }).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let items: Vec<(u8, &str)> = labels.iter().enumerate().map(|(i, l)| (i as u8, *l)).collect();
            theme::underline_tabs(ui, p, &items, sel, 28.0);
        });
        ui.add(egui::Separator::default().horizontal().spacing(0.0));
    });
}

pub fn method_color(p: &Palette, m: &str) -> Color32 {
    match m { "GET" | "OPTIONS" => p.get, "POST" => p.post, _ => p.other_method }
}

/// The colour a response's status is written in: a class at a glance, from the palette's own
/// status tokens, so it reads in either theme. A row with no status to show -- a request still
/// in flight, a connection that failed -- is left in the ordinary text colour.
pub fn status_color(p: &Palette, status: &str) -> Color32 {
    match crate::http::status_code(status) {
        Some(200..=299) => p.success,
        Some(300..=399) => p.badge_info,
        Some(400..=499) => p.warning,
        Some(500..=599) => p.error,
        _ => p.text,
    }
}

/// The colour an out-of-band interaction's protocol is written in. A relay may report any
/// protocol at all, so anything not named here is drawn in the neutral colour the tables use
/// for a method they do not know either -- readable, and plainly not one of the named ones.
pub fn protocol_color(p: &Palette, protocol: &str) -> Color32 {
    match crate::interactor::normalize_protocol(protocol).as_str() {
        // a name lookup is the one almost every payload fires first
        "DNS" => p.get,
        "HTTP" | "HTTPS" => p.post,
        "SMTP" | "SMTPS" => p.medium,
        "LDAP" => p.link,
        "FTP" | "FTPS" => p.info,
        "SMB" => p.low,
        _ => p.other_method,
    }
}

#[cfg(test)]
mod window_tests {
    use crate::state::{App, Tab};
    use crate::test_utils::{assert_table, MockAppBuilder};
    use eframe::egui;

    const VIEWPORT: egui::Vec2 = egui::vec2(1400.0, 900.0);

    /// Which border of a window is being dragged.
    #[derive(Clone, Copy, Debug)]
    enum Edge {
        Left,
        Right,
        Top,
        Bottom,
    }

    impl Edge {
        /// A point on this border of `rect`, halfway along it.
        fn grip(self, rect: egui::Rect) -> egui::Pos2 {
            match self {
                Edge::Left => egui::pos2(rect.left(), rect.center().y),
                Edge::Right => egui::pos2(rect.right(), rect.center().y),
                Edge::Top => egui::pos2(rect.center().x, rect.top()),
                Edge::Bottom => egui::pos2(rect.center().x, rect.bottom()),
            }
        }

        /// Dragging this border inwards by `d`, which shrinks the window.
        fn inwards(self, d: f32) -> egui::Vec2 {
            match self {
                Edge::Left => egui::vec2(d, 0.0),
                Edge::Right => egui::vec2(-d, 0.0),
                Edge::Top => egui::vec2(0.0, d),
                Edge::Bottom => egui::vec2(0.0, -d),
            }
        }
    }

    /// One frame of the whole app with these input events.
    fn frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, VIEWPORT)),
            events,
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| crate::ui_core::frame(app, ctx));
    }

    /// Where the window `id` is drawn, as of the last frame.
    fn window_rect(ctx: &egui::Context, id: egui::Id) -> egui::Rect {
        egui::AreaState::load(ctx, id).map(|s| s.rect()).unwrap_or_else(|| panic!("no window {id:?} on screen"))
    }

    /// Run frames until the window has reached the size it is going to keep, and give back
    /// that size.
    ///
    /// A comparison window works its word diff out on a worker thread and shows a short
    /// placeholder body until the result lands, so the first frame is not the size the window
    /// will settle at. Measuring then races that worker: under load the body arrives partway
    /// through a drag and the window grows, which reads as a drag that resized a window it
    /// should only have moved. Waiting on the work itself, rather than on a count of frames or
    /// a stretch of wall clock, makes every one of these drags measure the same thing whatever
    /// else the machine is busy with.
    fn settle(ctx: &egui::Context, app: &mut App, id: egui::Id) -> egui::Rect {
        let mut last = None;
        for _ in 0..2000 {
            frame(ctx, app, vec![]);
            // a comparison still being computed will change the body's height when it arrives,
            // so there is no point reading a size yet
            if app.comparer_active_diff.as_ref().is_some_and(|d| d.words_job.is_some()) {
                std::thread::yield_now();
                continue;
            }
            let now = egui::AreaState::load(ctx, id).map(|s| s.rect());
            // the same size twice over means nothing is still growing into place
            if now.is_some() && now == last {
                return now.expect("the window is on screen");
            }
            last = now;
        }
        panic!("the window {id:?} never settled at one size");
    }

    /// Press `edge`, drag it by `delta` and let go, a frame at a time as a hand would.
    fn drag_edge(ctx: &egui::Context, app: &mut App, id: egui::Id, edge: Edge, delta: egui::Vec2) -> egui::Rect {
        let from = edge.grip(settle(ctx, app, id));
        let button = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        frame(ctx, app, vec![egui::Event::PointerMoved(from)]);
        frame(ctx, app, vec![button(from, true)]);
        // in steps, so the drag reads as a drag rather than a jump
        for step in 1..=4 {
            let to = from + delta * (step as f32 / 4.0);
            frame(ctx, app, vec![egui::Event::PointerMoved(to)]);
        }
        frame(ctx, app, vec![button(from + delta, false)]);
        frame(ctx, app, vec![]);
        window_rect(ctx, id)
    }

    /// The app with one of the resizable windows open.
    fn app_with(window: &str) -> (egui::Context, App) {
        let (ctx, mut app) = MockAppBuilder::new().with_light_theme(true).build_with_ctx();
        match window {
            "intruder_attack" => {
                app.tab = Tab::Intruder;
                app.show_attack = true;
                app.int_total = 3;
                // an attack window is only ever open with results in it
                app.int_results = (1..=3)
                    .map(|request| crate::state::IntResult {
                        request,
                        payload: format!("value-{request}"),
                        status: "200 OK".into(),
                        length: 128,
                        error: String::new(),
                        history_id: request,
                    })
                    .collect();
            }
            "comparer_diff" => {
                app.tab = Tab::Comparer;
                let item = |id: usize, text: &str| crate::comparer::ComparerItem::from_text(id, format!("Item {id}"), text);
                app.comparer_active_diff = Some(crate::comparer::DiffView::new(
                    item(1, "GET /api/v1/users HTTP/1.1\nHost: shop.internal\n\n"),
                    item(2, "GET /api/v1/users/42?role=admin HTTP/1.1\nHost: shop.internal\n\n"),
                    crate::comparer::DiffMode::Words,
                ));
            }
            "settings_window" => app.show_settings = true,
            other => panic!("no such window: {other}"),
        }
        (ctx, app)
    }


    /// Any border dragged all the way in, past the size the window can shrink to, and then
    /// dragged straight back out past the edge of the screen must leave the window on the
    /// screen at every frame of both halves of that drag -- and must still have shrunk the
    /// window on the way in and grown it again on the way out.
    ///
    /// Both halves have their own way of going wrong. On the way in, the size stops following
    /// the pointer at the window's own floor while the position carries on, so the far border
    /// is pushed out of the far side of the screen. On the way out, a window is held back only
    /// by a cap egui works out from the screen, and that one is the size of the contents, with
    /// the frame's margins and the title bar still to be added outside it -- so a border
    /// dragged past the edge of the screen leaves the window larger than the display.
    #[test]
    fn a_window_dragged_in_to_its_minimum_and_back_out_stays_on_screen_matrix() {
        /// How far each step of the drag moves the pointer.
        const STEP: f32 = 25.0;
        /// How close to the opposite border the inward drag goes, and how far past the edge
        /// of the screen the outward drag carries on.
        const STOP_SHORT: f32 = 20.0;
        const OVERSHOOT: f32 = 40.0;
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, VIEWPORT);
        let windows = ["intruder_attack", "comparer_diff", "settings_window"];
        assert_table!(windows, |idx, name| {
            for edge in [Edge::Left, Edge::Top, Edge::Right, Edge::Bottom] {
                let (ctx, mut app) = app_with(name);
                let id = egui::Id::new(name);
                let start = settle(&ctx, &mut app, id);
                let grip = edge.grip(start);
                let vertical = matches!(edge, Edge::Top | Edge::Bottom);
                // the one coordinate the drag moves along, and a pointer position on it
                let along = |p: egui::Pos2| if vertical { p.y } else { p.x };
                let at = |v: f32| if vertical { egui::pos2(grip.x, v) } else { egui::pos2(v, grip.y) };
                // which way along it is inwards, towards the border opposite
                let inwards = if matches!(edge, Edge::Left | Edge::Top) { 1.0 } else { -1.0 };

                // all the way in to the opposite border, which is far past the size the
                // window can shrink to, then all the way back out past the edge of the screen
                let far = if inwards > 0.0 { along(start.max) } else { along(start.min) };
                let inward_to = far - inwards * STOP_SHORT;
                let outward_to = if inwards > 0.0 { -OVERSHOOT } else { along(screen.max) + OVERSHOOT };
                let mut path = Vec::new();
                let mut cursor = along(grip);
                // a step of the drag, stopping exactly on the far end rather than past it
                let advance = |cursor: f32, to: f32| {
                    if (to - cursor).abs() < STEP { to } else { cursor + STEP * (to - cursor).signum() }
                };
                while cursor != inward_to {
                    cursor = advance(cursor, inward_to);
                    path.push(cursor);
                }
                let shrinking = path.len();
                while cursor != outward_to {
                    cursor = advance(cursor, outward_to);
                    path.push(cursor);
                }

                let button = |pos, pressed| egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                };
                let check = |ctx: &egui::Context, what: &str| -> egui::Rect {
                    let now = window_rect(ctx, id);
                    let case = format!("case #{idx} ({name}, {edge:?} edge), {what}");
                    assert!(
                        now.width() <= screen.width(),
                        "{case}: {}px wide on a {}px screen ({now:?})",
                        now.width(), screen.width()
                    );
                    assert!(
                        now.height() <= screen.height(),
                        "{case}: {}px tall on a {}px screen ({now:?})",
                        now.height(), screen.height()
                    );
                    assert!(
                        screen.contains_rect(now),
                        "{case}: the window is off the screen ({now:?} is not inside {screen:?})"
                    );
                    now
                };
                // the side the drag is pulling on, which is the one that should be changing
                let span = |r: egui::Rect| if vertical { r.height() } else { r.width() };

                frame(&ctx, &mut app, vec![egui::Event::PointerMoved(grip)]);
                frame(&ctx, &mut app, vec![button(grip, true)]);
                let mut shrunk = start;
                for (step, &to) in path.iter().enumerate() {
                    frame(&ctx, &mut app, vec![egui::Event::PointerMoved(at(to))]);
                    let half = if step < shrinking { "shrinking" } else { "expanding" };
                    let now = check(&ctx, &format!("{half}, pointer at {to}"));
                    if step + 1 == shrinking {
                        shrunk = now;
                    }
                }
                frame(&ctx, &mut app, vec![button(at(cursor), false)]);
                check(&ctx, "the moment the border is let go");
                frame(&ctx, &mut app, vec![]);
                let grown = check(&ctx, "the frame after the border is let go");

                // and holding the window still where a drag asks for a size it cannot be
                // drawn at must not hold it still anywhere else: it shrank, and it grew again
                let case = format!("case #{idx} ({name}, {edge:?} edge)");
                assert!(
                    span(shrunk) <= span(start) / 2.0,
                    "{case}: dragged all the way in and still {} of its {} ({shrunk:?})",
                    span(shrunk), span(start)
                );
                assert!(
                    span(grown) >= span(shrunk) + 200.0,
                    "{case}: dragged back out from {} and only reached {} ({grown:?})",
                    span(shrunk), span(grown)
                );
            }
        });
    }

    /// The title bar moves the whole window: both edges travel the same way and the size is
    /// left alone. Nothing put in the way of a border drag may cost the window that.
    #[test]
    fn the_title_bar_still_moves_the_whole_window_matrix() {
        let windows = ["intruder_attack", "comparer_diff", "settings_window"];
        assert_table!(windows, |idx, name| {
            let (ctx, mut app) = app_with(name);
            let id = egui::Id::new(name);
            let before = settle(&ctx, &mut app, id);
            // a point on the title bar, clear of the close button and of either border
            let grip = egui::pos2(before.center().x, before.top() + 12.0);
            let button = |pos, pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            frame(&ctx, &mut app, vec![egui::Event::PointerMoved(grip)]);
            frame(&ctx, &mut app, vec![button(grip, true)]);
            let shift = egui::vec2(40.0, 25.0);
            for step in 1..=4 {
                frame(&ctx, &mut app, vec![egui::Event::PointerMoved(grip + shift * (step as f32 / 4.0))]);
            }
            frame(&ctx, &mut app, vec![button(grip + shift, false)]);
            frame(&ctx, &mut app, vec![]);
            let after = window_rect(&ctx, id);
            assert!(
                (after.min - before.min).length() > 20.0,
                "case #{idx} ({name}): the window moved with the title bar ({before:?} -> {after:?})"
            );
            assert!(
                (after.size() - before.size()).length() <= 1.0,
                "case #{idx} ({name}): and kept its size ({before:?} -> {after:?})"
            );
        });
    }

    /// A window has to be able to shrink to its own small minimum. egui will not let a window
    /// become narrower than the widest child that cannot scroll, so a toolbar or a pane laid
    /// out at its natural width silently pins the window open -- and then dragging the left or
    /// top border pushes the window sideways instead of resizing it.
    #[test]
    fn every_resizable_window_shrinks_to_its_own_minimum_matrix() {
        /// What the windows are asked to shrink to, and the slack allowed for frame chrome.
        const SMALL: egui::Vec2 = egui::vec2(380.0, 280.0);
        const SLACK: f32 = 60.0;
        let windows = ["intruder_attack", "comparer_diff", "settings_window"];
        assert_table!(windows, |idx, name| {
            let (ctx, mut app) = app_with(name);
            let id = egui::Id::new(name);
            let before = settle(&ctx, &mut app, id);
            let narrow = drag_edge(&ctx, &mut app, id, Edge::Right, egui::vec2(SMALL.x - before.width(), 0.0));
            assert!(
                narrow.width() <= SMALL.x + SLACK,
                "case #{idx} ({name}): {}px wide after being dragged in to {}px -- something inside is holding it open",
                narrow.width(), SMALL.x
            );
            let short = drag_edge(&ctx, &mut app, id, Edge::Bottom, egui::vec2(0.0, SMALL.y - narrow.height()));
            assert!(
                short.height() <= SMALL.y + SLACK,
                "case #{idx} ({name}): {}px tall after being dragged in to {}px",
                short.height(), SMALL.y
            );
        });
    }

    /// Every resizable window has to resize from the border the pointer takes hold of, and
    /// only from that border: dragging the right edge moves the right edge and leaves the
    /// top-left corner where it was, and dragging the left or top edge moves that edge and
    /// leaves the opposite corner where it was. A window pinned to a wide child widget, or
    /// held by an anchor, fails this by sliding the whole window instead.
    #[test]
    fn every_resizable_window_resizes_from_the_edge_that_is_dragged_matrix() {
        let windows = ["intruder_attack", "comparer_diff", "settings_window"];
        assert_table!(windows, |idx, name| {
            for edge in [Edge::Right, Edge::Bottom, Edge::Left, Edge::Top] {
                let (ctx, mut app) = app_with(name);
                let id = egui::Id::new(name);
                let before = settle(&ctx, &mut app, id);
                let after = drag_edge(&ctx, &mut app, id, edge, edge.inwards(60.0));
                let what = format!("case #{idx} ({name}, {edge:?} edge)");
                let moved = |a: f32, b: f32| (a - b).abs() > 1.0;
                match edge {
                    Edge::Right => {
                        assert!(moved(after.max.x, before.max.x), "{what}: the right edge moved ({before:?} -> {after:?})");
                        assert!(!moved(after.min.x, before.min.x), "{what}: the left edge stayed ({before:?} -> {after:?})");
                        assert!(!moved(after.min.y, before.min.y), "{what}: the top stayed");
                    }
                    Edge::Left => {
                        assert!(moved(after.min.x, before.min.x), "{what}: the left edge moved ({before:?} -> {after:?})");
                        assert!(!moved(after.max.x, before.max.x), "{what}: the right edge stayed ({before:?} -> {after:?})");
                        assert!(!moved(after.max.y, before.max.y), "{what}: the bottom stayed");
                    }
                    Edge::Top => {
                        assert!(moved(after.min.y, before.min.y), "{what}: the top moved ({before:?} -> {after:?})");
                        assert!(!moved(after.max.y, before.max.y), "{what}: the bottom stayed ({before:?} -> {after:?})");
                        assert!(!moved(after.max.x, before.max.x), "{what}: the right edge stayed");
                    }
                    Edge::Bottom => {
                        assert!(moved(after.max.y, before.max.y), "{what}: the bottom moved ({before:?} -> {after:?})");
                        assert!(!moved(after.min.y, before.min.y), "{what}: the top stayed ({before:?} -> {after:?})");
                        assert!(!moved(after.min.x, before.min.x), "{what}: the left edge stayed");
                    }
                }
            }
        });
    }

}

#[cfg(test)]
mod chrome_tests {
    use crate::state::{App, Tab};
    use crate::test_utils::{assert_table, MockAppBuilder};
    use eframe::egui;

    fn frame(ctx: &egui::Context, app: &mut App) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1500.0, 950.0))),
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    /// One frame with input events.
    fn events(ctx: &egui::Context, app: &mut App, evts: Vec<egui::Event>) {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1500.0, 950.0))),
            events: evts,
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| crate::ui_core::frame(app, ctx));
    }

    fn labels(update: &Option<egui::accesskit::TreeUpdate>) -> Vec<String> {
        update
            .as_ref()
            .expect("accesskit output")
            .nodes
            .iter()
            .filter_map(|(_, n)| n.label().or_else(|| n.value()).map(|s| s.to_string()))
            .collect()
    }

    /// Every tool draws, on the shared chrome and the shared table and pane primitives. This is
    /// the net under a change to any of them: a palette token, a row height or a header strip
    /// that one tab disagrees with shows up here as a panic rather than in a screenshot.
    #[test]
    fn every_tool_tab_draws_matrix() {
        assert_table!(Tab::ALL, |idx, tab| {
            let (ctx, mut app) = MockAppBuilder::new().with_tab(tab).build_with_ctx();
            ctx.enable_accesskit();
            // twice: the second frame is the one that reads back the first frame's responses,
            // which is where a hover shade or a settled pane height is decided
            frame(&ctx, &mut app);
            let seen = labels(&frame(&ctx, &mut app));
            assert!(!seen.is_empty(), "case #{idx} ({}): the tab drew nothing", tab.label());
            // the chrome is there whichever tool is open
            for want in ["Event log", "All issues"] {
                assert!(seen.iter().any(|l| l == want), "case #{idx} ({}): the status bar kept {want:?}", tab.label());
            }
        });
    }

    /// A tool's explanation lives behind the `?` on its header strip, not in a paragraph under
    /// the title: the words are still reachable, but they cost no height.
    #[test]
    fn a_tool_header_is_one_strip_with_its_words_behind_the_question_mark() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Interactor).build_with_ctx();
        ctx.enable_accesskit();
        frame(&ctx, &mut app);
        let seen = labels(&frame(&ctx, &mut app));
        assert!(seen.iter().any(|l| l == "Interactor"), "the tool is named");
        // the sentence that used to sit under the title is no longer laid out as a label
        assert!(
            !seen.iter().any(|l| l.starts_with("Test whether an application can be made")),
            "the description is no longer a paragraph on the page: {seen:?}"
        );
    }

    /// The listener badge says what the proxy is actually doing, and changes when it changes.
    #[test]
    fn the_status_bar_badge_follows_the_listener_matrix() {
        use std::sync::atomic::Ordering;
        let cases: [(&str, bool, bool, &str); 3] = [
            ("not running", false, false, "Listener off"),
            ("passing traffic", true, false, "Listening :8080"),
            ("holding requests", true, true, "Intercepting :8080"),
        ];
        assert_table!(cases, |idx, (what, running, intercept, want)| {
            let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Dashboard).build_with_ctx();
            ctx.enable_accesskit();
            app.proxy_port = "8080".into();
            app.proxy.running.store(running, Ordering::SeqCst);
            app.proxy.intercept.store(intercept, Ordering::SeqCst);
            frame(&ctx, &mut app);
            let seen = labels(&frame(&ctx, &mut app));
            assert!(seen.iter().any(|l| l == want), "case #{idx} ({what}): expected {want:?} in {seen:?}");
        });
    }

    /// Where the one widget labelled `want` is drawn.
    fn find(update: &Option<egui::accesskit::TreeUpdate>, want: &str) -> egui::Rect {
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        let found = nodes
            .iter()
            .filter(|(_, n)| n.label().as_deref() == Some(want) || n.value().as_deref() == Some(want))
            .find_map(|(_, n)| n.bounds());
        let b = found.unwrap_or_else(|| panic!("no widget labelled {want:?}"));
        egui::Rect::from_min_max(egui::pos2(b.x0 as f32, b.y0 as f32), egui::pos2(b.x1 as f32, b.y1 as f32))
    }

    fn panel_rect(ctx: &egui::Context, id: &str) -> egui::Rect {
        egui::containers::panel::PanelState::load(ctx, egui::Id::new(id))
            .map(|s| s.rect)
            .unwrap_or_else(|| panic!("no panel {id:?} on screen"))
    }

    /// The issue listing's header spans the tab above a split that is fixed: the listing is
    /// wide enough for all three of its columns and its border is not a handle, so there is
    /// nothing to drag the Name column narrower than the names in it.
    #[test]
    fn the_issue_listing_header_spans_the_tab_above_a_split_that_cannot_be_dragged() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Target).build_with_ctx();
        ctx.enable_accesskit();
        app.target_sub = 2;
        frame(&ctx, &mut app);
        let seen = labels(&frame(&ctx, &mut app));
        assert!(seen.iter().any(|l| l == "Issue definitions"), "the header is drawn: {seen:?}");
        assert!(
            !seen.iter().any(|l| l.starts_with("This listing contains")),
            "and its sentence is behind the ? rather than a second line: {seen:?}"
        );

        let header = panel_rect(&ctx, "issues_header");
        let list = panel_rect(&ctx, "issuelist");
        // the header spans the whole tab, not just the column the table sits in
        assert!(
            header.width() > list.width() * 1.5,
            "the header spans the tab, not one side of the split (header {:.0}, list {:.0})",
            header.width(),
            list.width()
        );
        // and the split begins strictly under it, so the divider never has the header to drag
        assert!(
            list.top() >= header.bottom() - 0.5,
            "the split starts below the header (header {header:?}, list {list:?})"
        );
        assert!(header.height() > 10.0 && header.height() < 60.0, "the header is one compact strip: {header:?}");

        // all three columns fit, so there is a Name column worth reading
        assert!(list.width() >= 540.0, "the listing is wide enough for its three columns: {:.0}", list.width());

        // the first definition is drawn, whole, inside the listing and below the header
        let row = find(&frame(&ctx, &mut app), "OS command injection (High)");
        assert!(row.top() >= header.bottom() - 0.5, "the first row is not under the header ({row:?})");
        assert!(row.right() <= list.right() + 0.5, "nor past the edge of the listing ({row:?})");
        assert!(row.width() > 400.0, "and it has the width of the listing to write in: {:.0}", row.width());

        // the border is not a divider: dragging across it changes nothing
        let grip = egui::pos2(list.right(), list.center().y);
        let button = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        events(&ctx, &mut app, vec![egui::Event::PointerMoved(grip)]);
        events(&ctx, &mut app, vec![button(grip, true)]);
        for step in 1..=4 {
            let to = egui::pos2(grip.x - 30.0 * step as f32, grip.y);
            events(&ctx, &mut app, vec![egui::Event::PointerMoved(to)]);
        }
        events(&ctx, &mut app, vec![button(egui::pos2(grip.x - 120.0, grip.y), false)]);
        frame(&ctx, &mut app);

        let (header_after, list_after) = (panel_rect(&ctx, "issues_header"), panel_rect(&ctx, "issuelist"));
        assert!(
            (list_after.width() - list.width()).abs() < 0.5,
            "the listing kept its width through the drag ({:.0} -> {:.0})",
            list.width(),
            list_after.width()
        );
        assert!(
            (header_after.height() - header.height()).abs() < 0.5 && (header_after.top() - header.top()).abs() < 0.5,
            "and the header was left alone ({header:?} -> {header_after:?})"
        );
        assert!(list_after.top() >= header_after.bottom() - 0.5, "the first row stays whole after the drag");
    }

    /// A window too narrow for the listing at its full width gives it less rather than taking
    /// the definition pane's room away entirely -- and never a width below zero, which is what
    /// a squeezed layout hands an unguarded `set_width`.
    #[test]
    fn the_issue_listing_gives_way_on_a_narrow_window_matrix() {
        let widths: [f32; 4] = [1500.0, 820.0, 520.0, 360.0];
        assert_table!(widths, |idx, width| {
            let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Target).build_with_ctx();
            ctx.enable_accesskit();
            app.target_sub = 2;
            let input = |events: Vec<egui::Event>| egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, 900.0))),
                events,
                ..Default::default()
            };
            for _ in 0..2 {
                let _ = ctx.run(input(vec![]), |ctx| crate::ui_core::frame(&mut app, ctx));
            }
            let list = panel_rect(&ctx, "issuelist");
            assert!(list.width() > 0.0, "case #{idx} (window {width}): the listing has a width at all");
            assert!(list.width() <= 560.5, "case #{idx} (window {width}): and never more than its fixed width");
            // whatever is left over is the definition's, and it is never nothing
            let left_over = width - list.width();
            assert!(left_over >= 60.0, "case #{idx} (window {width}): the definition keeps room ({left_over:.0})");
        });
    }


    /// The menu row starts with "Suite" itself: the orange square that used to sit before it
    /// was not a control, and it pushed the whole row out of line with the tabs underneath.
    #[test]
    fn the_menu_row_starts_with_suite_in_line_with_the_first_tab() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Dashboard).build_with_ctx();
        ctx.enable_accesskit();
        frame(&ctx, &mut app);
        let update = frame(&ctx, &mut app);
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        let left_of = |want: &str| {
            nodes
                .iter()
                .filter(|(_, n)| n.label().as_deref() == Some(want) || n.value().as_deref() == Some(want))
                .filter_map(|(_, n)| n.bounds())
                .map(|b| b.x0 as f32)
                .fold(f32::INFINITY, f32::min)
        };
        let (suite, dashboard) = (left_of("Suite"), left_of("Dashboard"));
        assert!(suite.is_finite(), "the Suite menu is there");
        assert!(dashboard.is_finite(), "and the Dashboard tab under it");
        // both start at the window's left edge, give or take each one's own padding
        assert!(suite < 40.0, "Suite sits at the left edge, not pushed in by a badge: x {suite}");
        assert!(
            (suite - dashboard).abs() < 16.0,
            "and lines up with the first tab (Suite x {suite}, Dashboard x {dashboard})"
        );
    }

    /// Every tool draws under both themes. The palette is swapped underneath a live app rather
    /// than only at startup, which is what the View menu's theme switch does, so anything that
    /// cached a colour or a measurement from the other theme shows up here.
    #[test]
    fn every_tool_tab_draws_under_both_themes_matrix() {
        assert_table!(Tab::ALL, |idx, tab| {
            for look in [crate::theme::ThemeMode::DarkWorkstation, crate::theme::ThemeMode::LightWorkstation] {
                let (ctx, mut app) = MockAppBuilder::new()
                    .with_tab(tab)
                    .with_light_theme(look == crate::theme::ThemeMode::LightWorkstation)
                    .build_with_ctx();
                ctx.enable_accesskit();
                app.set_theme(look);
                crate::theme::apply_theme(&ctx, look);
                frame(&ctx, &mut app);
                let seen = labels(&frame(&ctx, &mut app));
                assert!(!seen.is_empty(), "case #{idx} ({}, {look:?}): the tab drew nothing", tab.label());
                assert!(
                    seen.iter().any(|l| l == "Event log"),
                    "case #{idx} ({}, {look:?}): the chrome drew too",
                    tab.label()
                );
                // the visuals really are the ones asked for, not left over from the other theme
                assert_eq!(
                    ctx.style().visuals.dark_mode,
                    look == crate::theme::ThemeMode::DarkWorkstation,
                    "case #{idx} ({}, {look:?}): the theme took effect",
                    tab.label()
                );
            }
        });
    }

    /// Switching theme on a running app repaints every tab in the new palette, with no stale
    /// surface left behind from the one before.
    #[test]
    fn switching_theme_on_a_live_app_takes_effect_everywhere() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Proxy).build_with_ctx();
        ctx.enable_accesskit();
        for tab in Tab::ALL {
            app.tab = tab;
            for look in [crate::theme::ThemeMode::LightWorkstation, crate::theme::ThemeMode::DarkWorkstation, crate::theme::ThemeMode::LightWorkstation] {
                app.set_theme(look);
                crate::theme::apply_theme(&ctx, look);
                frame(&ctx, &mut app);
                let v = &ctx.style().visuals;
                let p = crate::theme::palette(look);
                assert_eq!(v.panel_fill, p.panel, "{:?} on {look:?}: the panel surface", tab.label());
                assert_eq!(v.extreme_bg_color, p.bg_input, "{:?} on {look:?}: the recessed surface", tab.label());
                assert_eq!(v.override_text_color, Some(p.text), "{:?} on {look:?}: the text colour", tab.label());
            }
        }
    }

    /// Put some recorded traffic in the store, as every one of these panes needs.
    fn with_traffic(app: &mut App) {
        for (i, path) in ["/", "/cart", "/pay"].iter().enumerate() {
            let id = i + 1;
            app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
                id,
                tool: "Proxy".into(),
                method: "GET".into(),
                host: "shop.test".into(),
                path: (*path).into(),
                status: "200 OK".into(),
                length: 2,
                mime: "text/html".into(),
                request: format!("GET {path} HTTP/1.1\nHost: shop.test\n\n"),
                response: "HTTP/1.1 200 OK\ncontent-length: 2\n\nok".into(),
                url: format!("http://shop.test{path}"),
                truncated: false,
                time: 0,
                elapsed_ms: 1,
            }));
        }
        *app.next_id.lock().unwrap() = 3;
    }

    /// Drag a bottom pane's splitter by `dy` and give back the height it was left at, having
    /// let five idle frames pass -- which is where a pane that does not hold its height snaps
    /// back to its default, or walks off on its own.
    fn drag_bottom_splitter(ctx: &egui::Context, app: &mut App, id: &str, dy: f32) -> (f32, f32) {
        let before = panel_rect(ctx, id).height();
        let r = panel_rect(ctx, id);
        let grip = egui::pos2(r.center().x, r.top());
        let button = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        events(ctx, app, vec![egui::Event::PointerMoved(grip)]);
        events(ctx, app, vec![button(grip, true)]);
        // in steps, so it reads as a drag and not as a jump
        for step in 1..=4 {
            let to = egui::pos2(grip.x, grip.y + dy * (step as f32 / 4.0));
            events(ctx, app, vec![egui::Event::PointerMoved(to)]);
        }
        events(ctx, app, vec![button(egui::pos2(grip.x, grip.y + dy), false)]);
        let released = panel_rect(ctx, id).height();
        for _ in 0..5 {
            frame(ctx, app);
        }
        (before, released)
    }

    /// Every bottom detail pane keeps the height it was dragged to, in both directions, once
    /// the pointer is let go.
    ///
    /// The pane's own contents are what used to decide this. A panel keeps the height of what
    /// is inside it, so message viewers given the run of the place asked for a little more
    /// room every frame and the panel grew to match -- and because the pane's ceiling was
    /// worked out from the height still unspent in its container, the ceiling rose along with
    /// it. The pane walked down the screen on its own after the pointer was released.
    #[test]
    fn every_bottom_detail_pane_keeps_the_height_it_was_dragged_to_matrix() {
        struct Case {
            name: &'static str,
            panel: &'static str,
            open: fn(&mut App),
        }
        let cases = [
            Case {
                name: "the site map's request and response",
                panel: "site_map_detail",
                open: |app| {
                    app.tab = Tab::Target;
                    app.target_sub = 0;
                    with_traffic(app);
                    crate::actions::sync_site_map(app);
                    app.target_selected_node = app.site_map.roots.keys().next().cloned();
                    app.target_selected_history_id = Some(2);
                },
            },
            Case {
                name: "the Organizer's message",
                panel: "org_detail",
                open: |app| {
                    app.tab = Tab::Organizer;
                    let request = "GET /cart HTTP/1.1\nHost: shop.test\n\n";
                    crate::actions::send_to_organizer(app, "http://shop.test/cart", request, "HTTP/1.1 200 OK\n\nok");
                    app.tab = Tab::Organizer;
                    app.org_sel = Some(1);
                },
            },
        ];
        assert_table!(cases, |idx, case| {
            for (direction, dy) in [("shrinking it", 120.0_f32), ("growing it", -120.0)] {
                let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Dashboard).build_with_ctx();
                ctx.enable_accesskit();
                (case.open)(&mut app);
                frame(&ctx, &mut app);
                frame(&ctx, &mut app);

                let what = format!("case #{idx} ({}, {direction})", case.name);
                let (before, released) = drag_bottom_splitter(&ctx, &mut app, case.panel, dy);
                let settled = panel_rect(&ctx, case.panel).height();

                // it moved the way it was dragged, and by something like the distance asked for
                if dy > 0.0 {
                    assert!(released < before - 60.0, "{what}: the drag shrank it ({before} -> {released})");
                } else {
                    assert!(released > before + 60.0, "{what}: the drag grew it ({before} -> {released})");
                }
                // and five idle frames later it is exactly where it was left: no snapping back
                // to the default, and no drifting on from it
                assert!(
                    (settled - released).abs() < 0.5,
                    "{what}: it did not hold ({released} on release, {settled} five frames later)"
                );
                assert!(
                    (settled - before).abs() > 50.0,
                    "{what}: it snapped back to where it started ({before} -> {settled})"
                );
            }
        });
    }
}
