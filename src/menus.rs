//! The shell's menus: only items that do something in this app.
//!
//! There is no longer a strip of menu titles across the window. The workstation shell has one
//! command bar, so every menu is reached through the `...` overflow on it ([`overflow`]) or,
//! for the project, through the chip that names the open project ([`project_items`]).
//!
//! Each menu's items are a function of their own, so the same items can be a submenu of the
//! overflow and the whole of a chip's menu without being written twice.

use crate::actions;
use crate::state::{App, Tab};
use crate::theme::{self, ThemeMode};
use crate::ui_proxy;
use eframe::egui;
use egui::{RichText, Ui};

/// A menu title, in the primary text colour of whichever theme is on.
///
/// This used to be fixed to the dark palette's text, which is a pale grey: on the light
/// theme's near-white menu strip the titles were barely there.
fn label(t: &str, p: &theme::Palette) -> RichText {
    RichText::new(t).size(theme::FONT_UI).color(p.text)
}

/// Everything the shell's `...` overflow holds: the five menus that are not the project's, as
/// submenus, over the handful of actions worth reaching in one click.
pub fn overflow(app: &mut App, ui: &mut Ui) {
    let look = if ui.visuals().dark_mode { ThemeMode::DarkWorkstation } else { ThemeMode::LightWorkstation };
    let p = &theme::palette(look);
    if ui.button("Settings").clicked() {
        app.show_settings = true;
        ui.close_menu();
    }
    if ui.button("Open browser").clicked() {
        ui_proxy::open_browser(app);
        ui.close_menu();
    }
    if ui.button("Event log").clicked() {
        app.drawer = Some(crate::state::DrawerTab::EventLog);
        ui.close_menu();
    }
    ui.separator();
    ui.menu_button(label("Project", p), |ui| project_items(app, ui));
    ui.menu_button(label("Intruder", p), |ui| intruder_items(app, ui));
    ui.menu_button(label("Repeater", p), |ui| repeater_items(app, ui));
    ui.menu_button(label("View", p), |ui| view_items(app, ui));
    ui.menu_button(label("Help", p), |ui| help_items(app, ui));
    ui.separator();
    if ui.button("Exit").clicked() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

/// The Project menu: what the chip naming the open project opens, and a submenu of the
/// overflow.
pub fn project_items(app: &mut App, ui: &mut Ui) {
    {
        use crate::ui_core::{load_config_native, open_project_native, save_project, save_project_as_native};
        if ui.button("New project...").clicked() {
            ui.close_menu();
            app.show_new_project_dialog = true;
        }
        if ui.button("Open project...").clicked() {
            ui.close_menu();
            open_project_native(app);
        }
        if ui.button("Save project").clicked() {
            ui.close_menu();
            save_project(app);
        }
        if ui.button("Save project as...").clicked() {
            ui.close_menu();
            save_project_as_native(app);
        }
        if ui.button("Load configuration file...").clicked() {
            ui.close_menu();
            load_config_native(app);
        }
        ui.separator();
        if ui.button("Scope").clicked() {
            app.tab = Tab::Target;
            app.target_sub = 1;
            ui.close_menu();
        }
    }
}

pub fn intruder_items(app: &mut App, ui: &mut Ui) {
    {
        if ui.add_enabled(!app.int_running, egui::Button::new("Start attack")).clicked() {
            actions::start_attack(app);
            app.tab = Tab::Intruder;
            ui.close_menu();
        }
        if ui.button("Send to Repeater").clicked() {
            let request = app.int_template.replace('§', "");
            let target = app.int_target.clone();
            actions::send_to_repeater(app, "GET", &target, &request);
            ui.close_menu();
        }
        if ui.button("Automatic payload positions").clicked() {
            app.int_template = crate::intruder::auto_positions(&app.int_template);
            app.tab = Tab::Intruder;
            ui.close_menu();
        }
        if ui.button("Clear payload positions").clicked() {
            app.int_template = app.int_template.replace('§', "");
            ui.close_menu();
        }
    }
}

pub fn repeater_items(app: &mut App, ui: &mut Ui) {
    {
        ui.checkbox(&mut app.rep_follow, "Follow redirections");
        ui.separator();
        if ui.add_enabled(app.rep().can_send(), egui::Button::new("Send request   Ctrl+Space")).clicked() {
            actions::send_repeater(app);
            ui.close_menu();
        }
    }
}

/// The View menu. The twelve tools are listed here as well as on the rail: the rail is the
/// place to go, and this is the place to find out that the place exists.
pub fn view_items(app: &mut App, ui: &mut Ui) {
    {
        ui.checkbox(&mut app.inspector.show_inspector, "Inspector panel   Ctrl+Shift+N")
            .on_hover_text("The request/response Inspector in Repeater, Intercept and HTTP history");
        ui.separator();
        // the same dispatch the rail and the shortcuts use, so a tool is only ever switched to
        // in one place
        for t in Tab::ALL {
            if ui.button(t.label()).clicked() {
                crate::hotkeys::perform(app, crate::hotkeys::Action::GoTo(t));
                ui.close_menu();
            }
        }
        ui.separator();
        let collapsed = app.rail_collapsed;
        if ui.button(if collapsed { "Expand navigation rail" } else { "Collapse navigation rail" }).clicked() {
            app.rail_collapsed = !collapsed;
            ui.close_menu();
        }
        ui.separator();
        let current = app.eff().theme;
        let other = if current == ThemeMode::DarkWorkstation { "Light theme" } else { "Dark theme" };
        if ui.button(other).clicked() {
            app.set_theme(if current == ThemeMode::DarkWorkstation { ThemeMode::LightWorkstation } else { ThemeMode::DarkWorkstation });
            theme::apply_theme(ui.ctx(), app.eff().theme);
            ui.close_menu();
        }
    }
}

pub fn help_items(app: &mut App, ui: &mut Ui) {
    {
        if ui.button("Keyboard shortcuts").clicked() {
            app.show_settings = true;
            app.settings_page = crate::state::SettingsPage::Hotkeys;
            ui.close_menu();
        }
        if ui.button("Command palette   Ctrl+K").clicked() {
            app.show_palette = true;
            ui.close_menu();
        }
    }
}
