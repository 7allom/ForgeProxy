//! Sequencer: two tabs. "Capture" sends a request repeatedly and collects a token from each
//! response; "Analysis" scores how random the collected tokens are. The statistics engine and
//! the detailed FIPS report are in [`crate::sequencer`].

use crate::editor;
use crate::sequencer::{self, TokenFormat, TokenLocation};
use crate::state::App;
use crate::theme::{self, bold, Palette};
use crate::ui_core::sub_tabs;
use eframe::egui;
use egui::{FontId, RichText, Ui};

pub fn sequencer(app: &mut App, ui: &mut Ui, p: &Palette) {
    sub_tabs(ui, p, &["Capture", "Analysis"], &mut app.seq_sub);
    ui.add_space(8.0);
    if app.seq_sub == 1 {
        analysis(app, ui, p);
    } else {
        capture(app, ui, p);
    }
}

fn capture(app: &mut App, ui: &mut Ui, p: &Palette) {
    theme::section_title(ui, p, "Live capture request", "Send a request here from HTTP history, the site map or Repeater (\"Send to Sequencer\"), then edit it directly below — strip cookies or adjust headers before capturing. It is sent repeatedly and a token is taken from each response.");
    ui.add_space(6.0);
    if app.seq_template.trim().is_empty() {
        ui.label(RichText::new("No request yet: right-click a request in Proxy > HTTP history, the site map or Repeater and choose \"Send to Sequencer\".").color(p.disabled));
    } else {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Target: {}", app.seq_origin)).monospace().size(12.0).color(p.disabled));
            if theme::plain_button(ui, p, "Remove", !app.seq_running).clicked() {
                app.seq_template.clear();
                app.seq_origin.clear();
            }
        });
        ui.add_space(4.0);
        // the raw request is editable (monospace, multiline) until a capture is running, so
        // headers/cookies can be tweaked here before Start
        let out = editor::message_editor(ui, p, "seq_template", &mut app.seq_template, !app.seq_running, false, 150.0);
        let seq_url = app.seq_origin.clone();
        let seq_req = app.seq_template.clone();
        crate::ui_tools::attach_editor_context_menu(&out, &seq_req, &seq_req, app, crate::state::Tab::Sequencer, &seq_url, &seq_req, None, "Sequencer request");
    }

    ui.add_space(10.0);
    theme::section_title(ui, p, "Token location within response", "Where the token appears in each response.");
    // the radio set switches the variant while carrying the text across
    let (mut kind, mut text) = match &app.seq_location {
        TokenLocation::Cookie(s) => (0u8, s.clone()),
        TokenLocation::Header(s) => (1u8, s.clone()),
        TokenLocation::Regex(s) => (2u8, s.clone()),
    };
    ui.horizontal(|ui| {
        ui.radio_value(&mut kind, 0, "Cookie");
        ui.radio_value(&mut kind, 1, "Header");
        ui.radio_value(&mut kind, 2, "Regex");
        let hint = match kind {
            0 => "cookie name (blank = first Set-Cookie)",
            1 => "header name (e.g. X-Token)",
            _ => "regex with one capture group",
        };
        ui.add(egui::TextEdit::singleline(&mut text).desired_width(280.0).hint_text(hint));
    });
    app.seq_location = match kind {
        0 => TokenLocation::Cookie(text),
        1 => TokenLocation::Header(text),
        _ => TokenLocation::Regex(text),
    };
    ui.add_space(6.0);
    let prev_format = app.seq_format;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Token format:").color(p.text));
        egui::ComboBox::from_id_salt("seq_token_format")
            .selected_text(app.seq_format.label())
            .width(140.0)
            .show_ui(ui, |ui| {
                for fmt in TokenFormat::ALL {
                    ui.selectable_value(&mut app.seq_format, fmt, fmt.label());
                }
            });
    });
    if app.seq_format != prev_format && !app.seq_samples.is_empty() {
        app.seq_analysis = sequencer::analyze_tokens_with_format(&app.seq_samples, app.seq_format);
    }

    ui.add_space(10.0);
    theme::section_title(ui, p, "Sample size", "How many tokens to collect before stopping.");
    ui.horizontal(|ui| {
        ui.add_enabled(!app.seq_running, egui::DragValue::new(&mut app.seq_target_samples).range(1..=sequencer::MAX_TOKENS).speed(10.0));
        for n in [500usize, 1000, 5000] {
            if ui.add_enabled(!app.seq_running, egui::SelectableLabel::new(app.seq_target_samples == n, n.to_string())).clicked() {
                app.seq_target_samples = n;
            }
        }
    });

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        if !app.seq_running {
            if theme::primary_button(ui, p, "Start").clicked() && !app.seq_template.trim().is_empty() {
                crate::actions::start_sequencer(app);
            }
        } else if theme::plain_button(ui, p, "Stop", true).clicked() {
            app.seq_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let can_clear = !app.seq_samples.is_empty() && !app.seq_running;
        if theme::plain_button(ui, p, "Clear", can_clear).clicked() {
            app.seq_samples.clear();
            app.seq_analysis = None;
            app.seq_message.clear();
        }
        if app.seq_running {
            ui.spinner();
        }
    });

    // live progress
    ui.add_space(8.0);
    let collected = app.seq_samples.len();
    let target = app.seq_target_samples.max(1);
    let frac = (collected as f32 / target as f32).clamp(0.0, 1.0);
    ui.add(egui::ProgressBar::new(frac).desired_width(ui.available_width().min(520.0)).text(format!("{collected} / {target} tokens collected")));
    if !app.seq_message.is_empty() {
        ui.label(RichText::new(&app.seq_message).size(12.0).color(p.high));
    }

    ui.add_space(8.0);
    ui.label(bold("Captured tokens", 13.0).color(p.strong));
    theme::table_well(ui, p, (ui.available_height() - 4.0).max(80.0), |ui| {
        theme::table_header(ui, p, &[("#", 60.0), ("Token", 420.0)]);
        egui::ScrollArea::vertical().id_salt("seq_tokens").auto_shrink([false, false]).show_rows(ui, 18.0, collected, |ui, range| {
            for i in range {
                let cells = [((i + 1).to_string(), 60.0, None), (app.seq_samples[i].clone(), 420.0, None)];
                theme::table_row(ui, p, &cells, false, i % 2 == 1);
            }
        });
    });
}

fn analysis(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.horizontal(|ui| {
        theme::section_title(ui, p, "Analysis", "Randomness statistics for the captured tokens.");
        if theme::plain_button(ui, p, "Analyse now", !app.seq_samples.is_empty()).clicked() {
            app.seq_analysis = sequencer::analyze_tokens_with_format(&app.seq_samples, app.seq_format);
        }
    });
    ui.add_space(6.0);
    let Some(a) = app.seq_analysis.clone() else {
        ui.label(RichText::new("No analysis yet. Capture tokens, then press \"Analyse now\" (analysis also runs automatically when a capture finishes).").color(p.disabled));
        return;
    };

    // scorecard
    let rating = sequencer::entropy_rating(a.overall_entropy, a.max_possible_entropy);
    let rating_col = match rating {
        "Excellent" => p.st_done,
        "Moderate" => p.medium,
        _ => p.high,
    };
    let len_text = if a.min_len == a.max_len { format!("{} chars (consistent)", a.min_len) } else { format!("{}–{} chars (varies)", a.min_len, a.max_len) };
    egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(10)).corner_radius(4.0).show(ui, |ui| {
        ui.horizontal(|ui| {
            scorecard(ui, p, "Samples", &a.sample_count.to_string(), p.text);
            scorecard(ui, p, "Token length", &len_text, p.text);
            scorecard(ui, p, "Shannon entropy", &format!("{:.2} / {:.2} bits  ({rating})", a.overall_entropy, a.max_possible_entropy), rating_col);
            if a.fips_applicable {
                let (mono, mono_col) = if a.fips_monobit_passed { ("Passed", p.st_done) } else { ("Failed", p.high) };
                scorecard(ui, p, "FIPS monobit", &format!("{mono}  ({:.3})", a.monobit_ratio), mono_col);
            } else {
                scorecard(ui, p, "FIPS monobit", "N/A (ASCII text - rely on Shannon entropy)", p.disabled);
            }
        });
    });
    if !a.fips_applicable {
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(p.banner)
            .inner_margin(egui::Margin::symmetric(10, 6))
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "FIPS bitstream tests require decoded binary/hex tokens. Character entropy: {:.2} bits (Max)",
                        a.max_possible_entropy
                    ))
                    .size(12.0)
                    .color(p.info),
                );
            });
    }

    ui.add_space(10.0);
    ui.columns(2, |cols| {
        // per-position entropy
        cols[0].label(bold("Per-position entropy", 13.0).color(cols[0].style().visuals.strong_text_color()));
        cols[0].label(RichText::new("Low bars mark fixed prefixes or timestamp digits.").size(11.5).color(p.disabled));
        cols[0].add_space(4.0);
        let max_bits = a.per_char_entropy.iter().cloned().fold(0.0_f64, f64::max).max(1.0);
        egui::ScrollArea::vertical().id_salt("seq_pos").max_height(260.0).show(&mut cols[0], |ui| {
            for (i, &e) in a.per_char_entropy.iter().enumerate() {
                // avoid "-0.00": a zero entropy can arrive as a negative zero from the sum
                let e = if e.abs() < 1e-4 { 0.0 } else { e };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{i:>3}")).monospace().size(11.5).color(p.disabled));
                    let frac = (e / max_bits) as f32;
                    ui.add(egui::ProgressBar::new(frac).desired_width(220.0).text(format!("{e:.2}")));
                });
            }
        });

        // character frequency
        cols[1].label(bold("Character distribution", 13.0).color(cols[1].style().visuals.strong_text_color()));
        cols[1].add_space(4.0);
        let total: usize = a.char_distribution.values().sum();
        theme::table_well(&mut cols[1], p, 280.0, |ui| {
            theme::table_header(ui, p, &[("Char", 60.0), ("Count", 80.0), ("%", 70.0)]);
            egui::ScrollArea::vertical().id_salt("seq_chars").auto_shrink([false, false]).show(ui, |ui| {
                for (i, (c, n)) in a.char_distribution.iter().enumerate() {
                    let shown = match c {
                        ' ' => "· (space)".to_string(),
                        '\t' => "\\t".to_string(),
                        '\n' => "\\n".to_string(),
                        '\r' => "\\r".to_string(),
                        c if c.is_control() => format!("0x{:02x}", *c as u32),
                        c => c.to_string(),
                    };
                    let pct = if total > 0 { *n as f64 / total as f64 * 100.0 } else { 0.0 };
                    let cells = [(shown, 60.0, None), (n.to_string(), 80.0, None), (format!("{pct:.1}"), 70.0, None)];
                    theme::table_row(ui, p, &cells, false, i % 2 == 1);
                }
            });
        });
    });

    // the detailed bit-level FIPS report from the original engine
    if app.seq_samples.len() >= sequencer::MIN_TOKENS {
        ui.add_space(10.0);
        egui::CollapsingHeader::new(bold("Detailed FIPS report", 13.0).color(p.strong)).id_salt("seq_fips").show(ui, |ui| {
            ui.label(RichText::new(sequencer::analyse_with_format(&app.seq_samples, app.seq_format)).monospace().size(12.0).color(p.text));
        });
    }
}

/// One labelled figure in the Analysis scorecard.
fn scorecard(ui: &mut Ui, p: &Palette, label: &str, value: &str, value_col: egui::Color32) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).size(11.0).color(p.disabled));
        ui.label(RichText::new(value).font(FontId::proportional(13.5)).color(value_col));
    });
    ui.add_space(18.0);
}
