//! Menu bar (reference picture-80..84): only items that do something in this app.

use crate::actions;
use crate::state::{App, Tab};
use crate::theme::{self, Look};
use crate::ui_proxy;
use eframe::egui;
use egui::{RichText, Ui};

fn label(t: &str) -> RichText {
    RichText::new(t).size(12.5).color(theme::DARK.text)
}

pub fn bar(app: &mut App, ui: &mut Ui) {
    // plain-text menu titles, like the original's menu bar
    ui.visuals_mut().widgets.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
    ui.visuals_mut().widgets.inactive.bg_stroke = egui::Stroke::NONE;
    ui.menu_button(label("Suite"), |ui| {
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
        if ui.button("Exit").clicked() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    });
    ui.menu_button(label("Project"), |ui| {
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
    });
    ui.menu_button(label("Intruder"), |ui| {
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
    });
    ui.menu_button(label("Repeater"), |ui| {
        ui.checkbox(&mut app.rep_follow, "Follow redirections");
        ui.separator();
        if ui.add_enabled(app.rep().can_send(), egui::Button::new("Send request   Ctrl+Space")).clicked() {
            actions::send_repeater(app);
            ui.close_menu();
        }
    });
    ui.menu_button(label("View"), |ui| {
        ui.checkbox(&mut app.inspector.show_inspector, "Inspector panel   Ctrl+Shift+N")
            .on_hover_text("The request/response Inspector in Repeater, Intercept and HTTP history");
        ui.separator();
        for t in Tab::ALL {
            if ui.button(t.label()).clicked() {
                app.tab = t;
                ui.close_menu();
            }
        }
        ui.separator();
        let current = app.eff().theme;
        let other = if current == Look::Dark { "Light theme" } else { "Dark theme" };
        if ui.button(other).clicked() {
            app.set_theme(if current == Look::Dark { Look::Light } else { Look::Dark });
            theme::apply(ui.ctx(), app.eff().theme);
            ui.close_menu();
        }
    });
    ui.menu_button(label("Help"), |ui| {
        if ui.button("Getting started").clicked() {
            app.tab = Tab::Discover;
            ui.close_menu();
        }
        if ui.button("Keyboard shortcuts").clicked() {
            app.show_settings = true;
            app.settings_page = crate::state::SettingsPage::Hotkeys;
            ui.close_menu();
        }
        if ui.button("Command palette   Ctrl+K").clicked() {
            app.show_palette = true;
            ui.close_menu();
        }
    });
}
