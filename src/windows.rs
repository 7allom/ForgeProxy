//! Floating windows: the Settings window (ui_settings.rs), the command palette
//! (ui_palette.rs, Ctrl+K) and the Comparer's comparison window. The Event log and All
//! issues are in the bottom drawer (ui_core.rs).

use crate::state::App;
use crate::theme::Palette;
use eframe::egui;

pub fn show(app: &mut App, ctx: &egui::Context, p: &Palette) {
    crate::ui_settings::show(app, ctx, p);
    crate::ui_palette::show(app, ctx, p);
    crate::ui_comparer::diff_window(app, ctx, p);
}
