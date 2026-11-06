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
            Tab::Collaborator => crate::ui_tools::collaborator(app, ui, &p),
            Tab::Sequencer => crate::ui_sequencer::sequencer(app, ui, &p),
            Tab::Decoder => crate::ui_tools::decoder(app, ui, &p),
            Tab::Comparer => crate::ui_comparer::comparer(app, ui, &p),
            Tab::Logger => crate::ui_tools::logger(app, ui, &p),
            Tab::Organizer => crate::ui_tools::organizer(app, ui, &p),
            Tab::Discover => crate::ui_tools::discover(app, ui, &p),
        }
    });
}

fn top_menu(app: &mut App, ctx: &egui::Context, p: &Palette) {
    egui::TopBottomPanel::top("menu")
        .frame(egui::Frame::new().fill(c(0x323334)).inner_margin(egui::Margin::symmetric(8, 3)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().rect_filled(r, 2.0, p.accent);
                ui.painter().circle_filled(r.center(), 3.0, Color32::WHITE);
                crate::menus::bar(app, ui);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let title = match &app.project_path {
                        Some(_) if !app.project_name.is_empty() => format!("ForgeProxy — {}", app.project_name),
                        Some(path) => format!("ForgeProxy — {path}"),
                        None => "ForgeProxy — Temporary Project".to_string(),
                    };
                    ui.label(RichText::new(title).size(12.5).color(c(0x9A9A9A)));
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

fn status_bar(app: &mut App, ctx: &egui::Context, _p: &Palette) {
    egui::TopBottomPanel::bottom("status")
        .frame(egui::Frame::new().fill(c(0x323334)).inner_margin(egui::Margin::symmetric(8, 3)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                // each label opens its drawer tab, or closes the drawer if that tab is showing
                for (tab, name) in [(DrawerTab::EventLog, "Event log"), (DrawerTab::AllIssues, "All issues")] {
                    let open = app.drawer == Some(tab);
                    let text = RichText::new(name).size(11.5).color(if open { Color32::WHITE } else { c(0xC5C7C8) });
                    let text = if open { text.underline() } else { text };
                    let hint = if open { format!("Hide {name}") } else { format!("Show {name}") };
                    if ui.add(egui::Label::new(text).sense(egui::Sense::click())).on_hover_text(hint).clicked() {
                        app.drawer = if open { None } else { Some(tab) };
                    }
                    ui.add_space(8.0);
                }
                if !app.project_msg.is_empty() {
                    ui.add_space(16.0);
                    ui.label(RichText::new(&app.project_msg).size(11.5).color(c(0x9A9A9A)));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(memory_text()).size(11.5).color(c(0x9A9A9A)));
                });
            });
        });
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
