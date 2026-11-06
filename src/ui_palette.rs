//! Command palette (Ctrl+K, or the ">_" icon): a drop-down under the tab row with a search
//! field and one row per command: icon, title, shortcut, category. With an empty query it
//! lists the action commands sorted by category; navigation ("Switch tab") and settings
//! deep links appear once you type. Up/Down move, Enter runs, Escape or a click outside closes.

use crate::actions;
use crate::state::{App, SettingsPage, Tab};
use crate::theme::Palette;
use crate::ui_proxy;
use eframe::egui;
use egui::{Align2, FontId, Key, Modifiers, Sense};

pub struct PaletteCommand {
    pub title: &'static str,
    pub category: &'static str,
    pub shortcut: Option<&'static str>,
    pub icon: &'static str,
    pub action: fn(&mut App),
    pub is_available: fn(&App) -> bool,
}

const SWITCH_TAB: &str = "Switch tab";
const WIDTH: f32 = 520.0;
const ROW_H: f32 = 22.0;
const MAX_ROWS: usize = 14;

fn always(_: &App) -> bool { true }
fn has_held(a: &App) -> bool { !a.proxy.held.lock().unwrap_or_else(|e| e.into_inner()).is_empty() }

/// Settings deep links: the page to open and the card to scroll to.
pub const SETTINGS_LINKS: &[(SettingsPage, &str)] = &[
    (SettingsPage::Proxy, "Proxy listeners"),
    (SettingsPage::Proxy, "HTTP match and replace rules"),
    (SettingsPage::Display, "Display scaling"),
    (SettingsPage::Hotkeys, "Keyboard shortcuts"),
];

fn settings(a: &mut App, link: usize) {
    let (page, card) = SETTINGS_LINKS[link];
    a.show_settings = true;
    a.settings_page = page;
    a.settings_focus = Some(card);
}

/// Every command, in no particular order (the palette sorts them).
pub fn default_commands() -> Vec<PaletteCommand> {
    let cmd = |title, category, shortcut, icon, action: fn(&mut App), is_available: fn(&App) -> bool| PaletteCommand { title, category, shortcut, icon, action, is_available };
    let go = |title, shortcut, action: fn(&mut App)| cmd(title, SWITCH_TAB, shortcut, "⇄", action, always);
    vec![
        go("Go to Dashboard", Some("Ctrl+Shift+D"), |a| a.tab = Tab::Dashboard),
        go("Go to Target > Site map", None, |a| { a.tab = Tab::Target; a.target_sub = 0; }),
        go("Go to Target > Scope", None, |a| { a.tab = Tab::Target; a.target_sub = 1; }),
        go("Go to Proxy", Some("Ctrl+Shift+P"), |a| a.tab = Tab::Proxy),
        go("Go to Proxy > Intercept", None, |a| { a.tab = Tab::Proxy; a.proxy_sub = 0; }),
        go("Go to Proxy > HTTP history", None, |a| { a.tab = Tab::Proxy; a.proxy_sub = 1; }),
        go("Go to Proxy > Match and replace", None, |a| { a.tab = Tab::Proxy; a.proxy_sub = 2; }),
        go("Go to Intruder", Some("Ctrl+Shift+I"), |a| a.tab = Tab::Intruder),
        go("Go to Repeater", Some("Ctrl+Shift+R"), |a| a.tab = Tab::Repeater),
        go("Go to Collaborator", None, |a| a.tab = Tab::Collaborator),
        go("Go to Sequencer", None, |a| a.tab = Tab::Sequencer),
        go("Go to Decoder", None, |a| { a.tab = Tab::Decoder; a.dec_view = 0; }),
        go("Go to Decoder > JWT Inspector", None, |a| { a.tab = Tab::Decoder; a.dec_view = 1; }),
        go("Go to Comparer", None, |a| a.tab = Tab::Comparer),
        go("Go to Logger", Some("Ctrl+Shift+L"), |a| a.tab = Tab::Logger),
        go("Go to Organizer", Some("Ctrl+Shift+O"), |a| a.tab = Tab::Organizer),
        cmd("Forward intercepted message", "Intercept", Some("Ctrl+F"), "→", ui_proxy::forward, has_held),
        cmd("Drop intercepted message", "Intercept", Some("Ctrl+D"), "↓", ui_proxy::drop_held, has_held),
        cmd("Toggle interception on/off", "Intercept", Some("Ctrl+T"), "👁", ui_proxy::toggle_intercept, always),
        cmd("Send Repeater request", "Repeater", Some("Ctrl+Space"), "→",
            |a| { a.tab = Tab::Repeater; actions::send_repeater(a); },
            |a| a.rep().can_send()),
        cmd("Start Intruder attack", "Intruder", None, "▷", actions::start_attack,
            |a| !a.int_running && actions::attack_problem(a).is_none()),
        cmd("Auto-add § payload positions", "Intruder", None, "§",
            |a| { a.int_template = crate::intruder::auto_positions(&a.int_template); a.tab = Tab::Intruder; },
            |a| !a.int_template.trim().is_empty()),
        cmd("Clear § payload positions", "Intruder", None, "§",
            |a| { a.int_template = a.int_template.replace('§', ""); a.tab = Tab::Intruder; },
            |a| a.int_template.contains('§')),
        cmd("Proxy listener", "Settings > Proxy", None, "⚙", |a| settings(a, 0), always),
        cmd("Match and replace rules", "Settings > Proxy", None, "⚙", |a| settings(a, 1), always),
        cmd("Display & scaling", "Settings > Display", None, "⚙", |a| settings(a, 2), always),
        cmd("Hotkeys", "Settings > Hotkeys", None, "⚙", |a| settings(a, 3), always),
        cmd("Compare last two items", "Comparer", None, "⇄",
            |a| {
                let n = a.comparer_items.len();
                a.comparer_sel_a = Some(n - 2);
                a.comparer_sel_b = Some(n - 1);
                crate::comparer::compare_selected(a, crate::comparer::DiffMode::Words);
                a.tab = Tab::Comparer;
            },
            |a| a.comparer_items.len() >= 2),
        cmd("Open settings window", "Open", None, "⚙", |a| a.show_settings = true, always),
        cmd("Open Event log panel", "Open", None, "📋", |a| a.drawer = Some(crate::state::DrawerTab::EventLog), always),
        cmd("Open All issues panel", "Open", None, "⚠", |a| a.drawer = Some(crate::state::DrawerTab::AllIssues), always),
        cmd("Toggle Inspector panel", "View", Some("Ctrl+Shift+N"), "☰",
            |a| a.inspector.show_inspector = !a.inspector.show_inspector, always),
        cmd("Open browser", "Open in browser", None, "🌐", ui_proxy::open_browser, always),
        cmd("New scan", "Scan", None, "+", |a| { a.tab = Tab::Dashboard; a.show_new_scan = true; }, always),
    ]
}

/// Commands shown for `query`, sorted by category then title. An empty query hides
/// navigation and settings entries; otherwise every word must appear in the title or category.
pub fn matching(commands: Vec<PaletteCommand>, query: &str) -> Vec<PaletteCommand> {
    let words: Vec<String> = query.split_whitespace().map(|w| w.to_lowercase()).collect();
    let mut out: Vec<PaletteCommand> = commands
        .into_iter()
        .filter(|c| {
            if words.is_empty() {
                return c.category != SWITCH_TAB && !c.category.starts_with("Settings");
            }
            let hay = format!("{} {}", c.title, c.category).to_lowercase();
            words.iter().all(|w| hay.contains(w.as_str()))
        })
        .collect();
    out.sort_by_key(|c| (c.category.to_lowercase(), c.title.to_lowercase()));
    out
}

/// Next available row from `from` in direction `step` (wrapping), or `from` if none is.
fn step_selection(avail: &[bool], from: usize, step: isize) -> usize {
    let n = avail.len() as isize;
    for k in 1..=n {
        let i = ((from as isize + step * k) % n + n) % n;
        if avail[i as usize] {
            return i as usize;
        }
    }
    from
}

pub fn show(app: &mut App, ctx: &egui::Context, p: &Palette) {
    if !app.show_palette {
        return;
    }
    let opened_id = egui::Id::new("palette_opened_pass");
    let pass = ctx.cumulative_pass_nr();
    let opened = ctx.data(|d| d.get_temp::<u64>(opened_id));
    let first_frame = opened.is_none();
    if first_frame {
        ctx.data_mut(|d| d.insert_temp(opened_id, pass));
        app.palette_query.clear();
    }

    // keys the search field must not see
    let (up, down, enter, escape) = ctx.input_mut(|i| (
        i.consume_key(Modifiers::NONE, Key::ArrowUp),
        i.consume_key(Modifiers::NONE, Key::ArrowDown),
        i.consume_key(Modifiers::NONE, Key::Enter),
        i.consume_key(Modifiers::NONE, Key::Escape),
    ));

    let mut commands = matching(default_commands(), &app.palette_query);
    let mut avail: Vec<bool> = commands.iter().map(|c| (c.is_available)(app)).collect();
    let first_available = |avail: &[bool]| avail.iter().position(|a| *a).unwrap_or(0);
    if first_frame {
        app.palette_sel = first_available(&avail);
    }
    let mut keyed = false;
    if !commands.is_empty() {
        app.palette_sel = app.palette_sel.min(commands.len() - 1);
        if down { app.palette_sel = step_selection(&avail, app.palette_sel, 1); keyed = true; }
        if up { app.palette_sel = step_selection(&avail, app.palette_sel, -1); keyed = true; }
    }

    let screen = ctx.screen_rect();
    let top = ctx.available_rect().top(); // just under the menu and tab rows
    let left = (screen.center().x - WIDTH / 2.0).max(screen.left());
    let mut run: Option<usize> = if enter { Some(app.palette_sel) } else { None };
    let mut close = escape;

    let area = egui::Area::new(egui::Id::new("command_palette"))
        .order(egui::Order::Foreground)
        .fixed_pos(egui::pos2(left, top))
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(p.panel)
                .stroke(egui::Stroke::new(1.0_f32, p.header))
                .shadow(ui.visuals().popup_shadow)
                .show(ui, |ui| {
                    ui.set_width(WIDTH);
                    ui.spacing_mut().item_spacing.y = 0.0;
                    // search row: input, magnifier, close
                    egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::symmetric(8, 4)).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let edit = ui.add(egui::TextEdit::singleline(&mut app.palette_query)
                                .desired_width(WIDTH - 60.0)
                                .frame(false)
                                .hint_text("Type a command..."));
                            edit.request_focus();
                            if edit.changed() {
                                commands = matching(default_commands(), &app.palette_query);
                                avail = commands.iter().map(|c| (c.is_available)(app)).collect();
                                app.palette_sel = first_available(&avail);
                                run = None;
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let (xr, xs) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), Sense::click());
                                let xcol = if xs.hovered() { p.strong } else { p.disabled };
                                ui.painter().text(xr.center(), Align2::CENTER_CENTER, "×", FontId::proportional(15.0), xcol);
                                if xs.on_hover_text("Close (Esc)").clicked() { close = true; }
                                let (mr, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), Sense::hover());
                                paint_magnifier(ui.painter(), mr.center(), p.text);
                            });
                        });
                    });
                    if commands.is_empty() {
                        egui::Frame::new().inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
                            ui.label(egui::RichText::new("No matching commands").size(12.5).color(p.disabled));
                        });
                        return;
                    }
                    egui::ScrollArea::vertical().max_height(ROW_H * MAX_ROWS as f32).auto_shrink([false, true]).show(ui, |ui| {
                        for (i, c) in commands.iter().enumerate() {
                            let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), ROW_H), Sense::click());
                            let moved = ui.input(|inp| inp.pointer.delta() != egui::Vec2::ZERO);
                            if resp.hovered() && moved && avail[i] { app.palette_sel = i; }
                            if resp.clicked() && avail[i] { run = Some(i); }
                            let sel = i == app.palette_sel && avail[i];
                            if sel {
                                ui.painter().rect_filled(rect, 0.0, p.selection);
                                if keyed { resp.scroll_to_me(None); }
                            }
                            draw_row(ui, p, rect, c, avail[i], sel);
                        }
                    });
                });
        });

    // a click outside closes it (but not the click that opened it this frame)
    let clicked_outside = ctx.input(|i| {
        i.pointer.any_click() && i.pointer.interact_pos().is_some_and(|pos| !area.response.rect.contains(pos))
    });
    if clicked_outside && opened.is_some_and(|o| o != pass) {
        close = true;
    }
    if let Some(i) = run {
        if let Some(c) = commands.get(i).filter(|_| avail.get(i) == Some(&true)) {
            (c.action)(app);
            close = true;
        }
    }
    if close || !app.show_palette {
        app.show_palette = false;
        ctx.data_mut(|d| d.remove::<u64>(opened_id));
    }
}

/// Icon, title, shortcut right after the title, category right-aligned.
fn draw_row(ui: &egui::Ui, p: &Palette, rect: egui::Rect, c: &PaletteCommand, available: bool, selected: bool) {
    let painter = ui.painter();
    let y = rect.center().y;
    let main = if !available { p.disabled } else if selected { p.strong } else { p.text };
    let dim = if selected { p.text } else { p.disabled };
    paint_icon(painter, egui::pos2(rect.left() + 16.0, y), c.icon, main);
    let title = painter.text(egui::pos2(rect.left() + 32.0, y), Align2::LEFT_CENTER, c.title, FontId::proportional(13.0), main);
    if let Some(sc) = c.shortcut {
        painter.text(egui::pos2(title.right() + 8.0, y), Align2::LEFT_CENTER, sc, FontId::proportional(11.5), dim);
    }
    painter.text(egui::pos2(rect.right() - 10.0, y), Align2::RIGHT_CENTER, c.category, FontId::proportional(12.0), dim);
}

/// The icon glyph, except arrows and the play triangle: the bundled fonts don't have
/// them, so those are drawn as thin line icons.
fn paint_icon(painter: &egui::Painter, c: egui::Pos2, icon: &str, col: egui::Color32) {
    let s = egui::Stroke::new(1.3_f32, col);
    let v = egui::vec2;
    let arrow = |from: egui::Pos2, to: egui::Pos2| {
        let dir = (to - from).normalized();
        let back = to - dir * 3.5;
        let side = v(-dir.y, dir.x) * 3.5;
        painter.line_segment([from, to], s);
        painter.line_segment([to, back + side], s);
        painter.line_segment([to, back - side], s);
    };
    match icon {
        "→" => arrow(c + v(-5.0, 0.0), c + v(5.0, 0.0)),
        "↓" => arrow(c + v(0.0, -5.0), c + v(0.0, 5.0)),
        "⇄" => {
            arrow(c + v(-5.0, -2.5), c + v(5.0, -2.5));
            arrow(c + v(5.0, 2.5), c + v(-5.0, 2.5));
        }
        "▷" => {
            painter.circle_stroke(c, 6.0, s);
            painter.add(egui::Shape::closed_line(vec![c + v(-1.8, -3.0), c + v(3.0, 0.0), c + v(-1.8, 3.0)], s));
        }
        _ => { painter.text(c, Align2::CENTER_CENTER, icon, FontId::proportional(13.0), col); }
    }
}

fn paint_magnifier(painter: &egui::Painter, c: egui::Pos2, col: egui::Color32) {
    let stroke = egui::Stroke::new(1.4_f32, col);
    painter.circle_stroke(c + egui::vec2(-1.5, -1.5), 4.5, stroke);
    painter.line_segment([c + egui::vec2(1.8, 1.8), c + egui::vec2(6.0, 6.0)], stroke);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn titles(q: &str) -> Vec<&'static str> {
        matching(default_commands(), q).iter().map(|c| c.title).collect()
    }

    #[test]
    fn empty_query_lists_actions_by_category() {
        let cmds = matching(default_commands(), "");
        assert!(cmds.iter().all(|c| c.category != SWITCH_TAB && !c.category.starts_with("Settings")));
        let cats: Vec<&str> = cmds.iter().map(|c| c.category).collect();
        let mut sorted = cats.clone();
        sorted.sort_by_key(|c| c.to_lowercase());
        assert_eq!(cats, sorted);
        assert_eq!(cmds[0].category, "Comparer"); // alphabetical: Comparer, Intercept, Intruder, ...
    }

    #[test]
    fn every_word_must_match() {
        assert_eq!(titles("go proxy history"), ["Go to Proxy > HTTP history"]);
        // category text matches too
        assert!(titles("settings proxy").contains(&"Proxy listener"));
        assert!(titles("zzz").is_empty());
    }

    #[test]
    fn selection_skips_unavailable_and_wraps() {
        let avail = [true, false, true, false];
        assert_eq!(step_selection(&avail, 0, 1), 2);
        assert_eq!(step_selection(&avail, 2, 1), 0);
        assert_eq!(step_selection(&avail, 0, -1), 2);
        assert_eq!(step_selection(&[false, false], 0, 1), 0);
    }

    #[test]
    fn listed_shortcuts_are_real_hotkeys() {
        for c in default_commands() {
            if let Some(sc) = c.shortcut {
                assert!(crate::hotkeys::LIST.iter().any(|(_, k)| *k == sc), "{} advertises {sc}", c.title);
            }
        }
    }
}
