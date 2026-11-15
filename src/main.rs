#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! ForgeProxy: a desktop web-testing workbench in Rust + egui.
//! Layout and colours follow the reference screenshots; see MECHANICS.md for sources.

mod actions;
mod autodecode;
mod cli;
mod codec;
mod collab;
mod comparer;
mod decoder_ops;
mod editor;
mod export;
mod http;
mod intruder;
mod organizer;
mod paths;
mod project;
mod history;
mod hotkeys;
mod menus;
mod windows;
mod proxy;
mod browser;
mod ca;
mod issue_defs;
mod regex_cache;
mod repeater;
mod rewrite;
mod rules;
mod scan;
mod scope;
mod sequencer;
mod state;
mod target;
mod theme;
mod tooling;
mod ui_automation;
mod ui_core;
mod ui_comparer;
mod ui_dash;
mod ui_inspector;
mod ui_organizer;
mod ui_palette;
mod ui_sequencer;
mod ui_settings;
mod ui_proxy;
mod ui_target;
mod ui_tools;
mod upstream;
mod viewer;
#[cfg(test)]
pub mod test_utils;

use eframe::egui;
use state::{App, Tab};

fn main() -> eframe::Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    // a subcommand (scan, intruder, repeat, proxy, sequence, decode) runs its own engine and
    // ends the process; anything else is the flat flags, exactly as before
    if let Some(code) = cli::run_subcommand(&raw_args, &mut std::io::stdout(), &mut std::io::stderr()) {
        std::process::exit(code);
    }
    let opts = match cli::parse(raw_args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("Run with --help for the flags there are.");
            std::process::exit(cli::EXIT_FAILED);
        }
    };
    // settings.json is found through this, by the app and by an unattended run alike, so it is
    // set before anything reads it
    if let Some(dir) = &opts.config {
        std::env::set_var("FORGEPROXY_CONFIG_DIR", dir);
    }
    // whatever needs no window is done here, and the process ends with what it came to
    if let Some(code) = cli::run(&opts, &mut std::io::stdout(), &mut std::io::stderr()) {
        std::process::exit(code);
    }

    let shot_path = opts.screenshot.clone();
    let start_tab = opts
        .tab
        .as_deref()
        .and_then(|n| Tab::ALL.into_iter().find(|t| t.label().eq_ignore_ascii_case(n)));
    let light = opts.light;
    let startup = opts.startup();
    if let Some(p) = &shot_path {
        if let Some(parent) = std::path::Path::new(p).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // A Wayland window that isn't visible (locked or hidden screen) gets no frame
        // callbacks, so the 120-frame capture would stall. Use X11 when it's available.
        if std::env::var_os("DISPLAY").is_some() {
            std::env::remove_var("WAYLAND_DISPLAY");
        }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1460.0, 800.0])
            .with_title("ForgeProxy"),
        vsync: shot_path.is_none(),
        ..Default::default()
    };
    eframe::run_native(
        "ForgeProxy",
        options,
        Box::new(move |cc| Ok(Box::new(App::new_with(cc, shot_path, start_tab, light, &startup)))),
    )
}
