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
//!
//! The overflow holds global workspace actions only. What belongs to one tool lives in that
//! tool, and what the rail or the status bar already offers (collapsing the rail, the Event
//! log) is not offered twice.

use crate::state::{App, Tab};
use crate::theme::{self, ThemeMode};
use eframe::egui;
use egui::Ui;

/// An item has done what it was chosen for: close the popup it was chosen from.
fn close(ui: &Ui) {
    theme::close_bar_popup(ui);
}

/// Everything the shell's `...` overflow holds, as flat sections, one level deep: View, Help
/// and Session.
pub fn overflow(app: &mut App, ui: &mut Ui) {
    let look = if ui.visuals().dark_mode { ThemeMode::DarkWorkstation } else { ThemeMode::LightWorkstation };
    let p = &theme::palette(look);
    theme::menu_section(ui, p, "View", true);
    view_items(app, ui);
    theme::menu_section(ui, p, "Help", false);
    help_items(app, ui, p);
    theme::menu_section(ui, p, "Session", false);
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

/// The View menu. The twelve tools are not listed: the rail shows every one of them, and the
/// command palette finds them by name.
pub fn view_items(app: &mut App, ui: &mut Ui) {
    {
        let label = format!("Inspector panel   {}", crate::hotkeys::command_chord("Shift+N"));
        ui.checkbox(&mut app.inspector.show_inspector, label)
            .on_hover_text("The request/response Inspector in Repeater, Intercept and HTTP history");
        let current = app.eff().theme;
        let other = if current == ThemeMode::DarkWorkstation { "Light theme" } else { "Dark theme" };
        if ui.button(other).clicked() {
            app.set_theme(if current == ThemeMode::DarkWorkstation { ThemeMode::LightWorkstation } else { ThemeMode::DarkWorkstation });
            theme::apply_theme(ui.ctx(), app.eff().theme);
            close(ui);
        }
    }
}

pub fn help_items(app: &mut App, ui: &mut Ui, p: &theme::Palette) {
    {
        if ui.button("Keyboard shortcuts").clicked() {
            app.show_settings = true;
            app.settings_page = crate::state::SettingsPage::Hotkeys;
            close(ui);
        }
        // the build this is, stated rather than linked: there is no page of its own to open
        ui.label(egui::RichText::new(about_line()).size(theme::FONT_CAPTION).color(p.text));
    }
}

/// "About ForgeProxy v1.0.0": the name and version this binary was built as.
pub fn about_line() -> String {
    format!("About ForgeProxy v{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_about_line_names_this_build() {
        assert_eq!(super::about_line(), format!("About ForgeProxy v{}", env!("CARGO_PKG_VERSION")));
        assert!(super::about_line().ends_with("v1.0.0"), "{}", super::about_line());
    }
}
