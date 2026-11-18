//! The shell's menus: only items that do something in this app.
//!
//! There is no longer a strip of menu titles across the window. The workstation shell has one
//! command bar, so every menu is reached through the `...` overflow on it ([`overflow`]) or,
//! for the project, through the chip that names the open project ([`project_items`]).
//!
//! Both are single-level popups opened by a click (see [`theme::bar_popup`]): the overflow's
//! groups are flat sections under a caption, never submenus that open on hover. Nothing here
//! repeats a control the command bar already shows -- Settings, the browser, the project and
//! the command palette each have their own place on the bar.

use crate::actions;
use crate::state::{App, Tab};
use crate::theme::{self, ThemeMode};
use eframe::egui;
use egui::Ui;

/// An item has done what it was chosen for: close the popup it was chosen from.
fn close(ui: &Ui) {
    theme::close_bar_popup(ui);
}

/// Everything the shell's `...` overflow holds, as flat sections, one level deep.
pub fn overflow(app: &mut App, ui: &mut Ui) {
    let look = if ui.visuals().dark_mode { ThemeMode::DarkWorkstation } else { ThemeMode::LightWorkstation };
    let p = &theme::palette(look);
    theme::menu_section(ui, p, "Intruder", true);
    intruder_items(app, ui);
    theme::menu_section(ui, p, "Repeater", false);
    repeater_items(app, ui);
    theme::menu_section(ui, p, "View", false);
    view_items(app, ui);
    theme::menu_section(ui, p, "Help", false);
    help_items(app, ui);
    ui.add_space(4.0);
    ui.separator();
    if ui.button("Exit").clicked() {
        close(ui);
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

/// The Project menu: what the chip naming the open project opens.
pub fn project_items(app: &mut App, ui: &mut Ui) {
    {
        use crate::ui_core::{load_config_native, open_project_native, save_project, save_project_as_native};
        if ui.button("New project...").clicked() {
            close(ui);
            app.show_new_project_dialog = true;
        }
        if ui.button("Open project...").clicked() {
            close(ui);
            open_project_native(app);
        }
        if ui.button("Save project").clicked() {
            close(ui);
            save_project(app);
        }
        if ui.button("Save project as...").clicked() {
            close(ui);
            save_project_as_native(app);
        }
        if ui.button("Load configuration file...").clicked() {
            close(ui);
            load_config_native(app);
        }
        ui.separator();
        if ui.button("Scope").clicked() {
            app.tab = Tab::Target;
            app.target_sub = 1;
            close(ui);
        }
    }
}

pub fn intruder_items(app: &mut App, ui: &mut Ui) {
    {
        if ui.add_enabled(!app.int_running, egui::Button::new("Start attack")).clicked() {
            actions::start_attack(app);
            app.tab = Tab::Intruder;
            close(ui);
        }
        if ui.button("Send to Repeater").clicked() {
            let request = app.int_template.replace('§', "");
            let target = app.int_target.clone();
            actions::send_to_repeater(app, "GET", &target, &request);
            close(ui);
        }
        if ui.button("Automatic payload positions").clicked() {
            app.int_template = crate::intruder::auto_positions(&app.int_template);
            app.tab = Tab::Intruder;
            close(ui);
        }
        if ui.button("Clear payload positions").clicked() {
            app.int_template = app.int_template.replace('§', "");
            close(ui);
        }
    }
}

pub fn repeater_items(app: &mut App, ui: &mut Ui) {
    {
        ui.checkbox(&mut app.rep_follow, "Follow redirections");
        ui.separator();
        if ui.add_enabled(app.rep().can_send(), egui::Button::new("Send request   Ctrl+Space")).clicked() {
            actions::send_repeater(app);
            close(ui);
        }
    }
}

/// The View menu. The twelve tools are not listed: the rail shows every one of them, and the
/// command palette finds them by name.
pub fn view_items(app: &mut App, ui: &mut Ui) {
    {
        ui.checkbox(&mut app.inspector.show_inspector, "Inspector panel   Ctrl+Shift+N")
            .on_hover_text("The request/response Inspector in Repeater, Intercept and HTTP history");
        let collapsed = app.rail_collapsed;
        if ui.button(if collapsed { "Expand navigation rail" } else { "Collapse navigation rail" }).clicked() {
            app.rail_collapsed = !collapsed;
            close(ui);
        }
        let current = app.eff().theme;
        let other = if current == ThemeMode::DarkWorkstation { "Light theme" } else { "Dark theme" };
        if ui.button(other).clicked() {
            app.set_theme(if current == ThemeMode::DarkWorkstation { ThemeMode::LightWorkstation } else { ThemeMode::DarkWorkstation });
            theme::apply_theme(ui.ctx(), app.eff().theme);
            close(ui);
        }
    }
}

pub fn help_items(app: &mut App, ui: &mut Ui) {
    {
        if ui.button("Keyboard shortcuts").clicked() {
            app.show_settings = true;
            app.settings_page = crate::state::SettingsPage::Hotkeys;
            close(ui);
        }
        if ui.button("Event log").clicked() {
            app.drawer = Some(crate::state::DrawerTab::EventLog);
            close(ui);
        }
    }
}
