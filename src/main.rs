#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! ForgeProxy: a desktop web-testing workbench in Rust + egui.
//! Layout and colours follow the reference screenshots; see MECHANICS.md for sources.

mod actions;
mod autodecode;
mod cli;
mod codec;
mod interactor;
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
mod cwe_catalog;
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

/// The window icon: the bundled logo when it decodes, otherwise a drawn fallback in the
/// theme's own colours — a cyan square on dark slate.
fn window_icon() -> egui::IconData {
    // the shipped logo, embedded so a moved binary still finds it
    if let Ok(img) = image::load_from_memory(include_bytes!("../assets/logo.png")) {
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        return egui::IconData { rgba: rgba.into_raw(), width: w, height: h };
    }
    fallback_icon()
}

/// A 32x32 icon drawn in code, in the theme's own colours: the dark canvas, a one-pixel
/// border a shade above it, and the cyan accent as a square at the centre. Used only when the
/// bundled logo cannot be decoded, so it needs no outside asset of its own.
fn fallback_icon() -> egui::IconData {
    const N: usize = 32;
    const CANVAS: [u8; 3] = [0x18, 0x1C, 0x24];
    const EDGE: [u8; 3] = [0x33, 0x3B, 0x49];
    const ACCENT: [u8; 3] = [0x38, 0xBD, 0xF8];
    let mut rgba = Vec::with_capacity(N * N * 4);
    for y in 0..N {
        for x in 0..N {
            let rgb = if x == 0 || y == 0 || x == N - 1 || y == N - 1 {
                EDGE
            } else if (9..N - 9).contains(&x) && (9..N - 9).contains(&y) {
                ACCENT
            } else {
                CANVAS
            };
            rgba.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 0xFF]);
        }
    }
    egui::IconData { rgba, width: N as u32, height: N as u32 }
}

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
            .with_title("ForgeProxy")
            .with_icon(window_icon()),
        vsync: shot_path.is_none(),
        ..Default::default()
    };
    eframe::run_native(
        "ForgeProxy",
        options,
        Box::new(move |cc| Ok(Box::new(App::new_with(cc, shot_path, start_tab, light, &startup)))),
    )
}
