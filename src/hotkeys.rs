//! Keyboard shortcuts: the actions the app binds keys to, the keys each one is bound to, and
//! the dispatch that runs them.
//!
//! One table, [`ACTIONS`], is the single source for all three. Settings draws the table, the
//! dispatch walks it, and a binding the user has changed is read from
//! [`crate::state::UserSettings::hotkeys`] by the action's id. There is no second list to
//! drift out of step with this one.

use crate::actions::{self, SendTo};
use crate::state::{App, Tab};
use crate::ui_proxy;
use eframe::egui;
use egui::{Key, KeyboardShortcut, Modifiers};

/// Something a key can be bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    SendToRepeater,
    SendToIntruder,
    SendToOrganizer,
    SendRequest,
    ToggleIntercept,
    ForwardHeld,
    DropHeld,
    CommandPalette,
    NextTab,
    PreviousTab,
    ToggleInspector,
    GoTo(Tab),
}

/// A key and the modifiers held with it.
///
/// Kept as its own type rather than egui's shortcut so it can be written to and read back
/// from a settings file as a phrase a person can edit, like `Ctrl+Shift+R`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Binding {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub key: Key,
}

/// The command modifier as this platform names it: `Cmd` on macOS, `Ctrl` elsewhere.
pub const COMMAND_KEY: &str = if cfg!(target_os = "macos") { "Cmd" } else { "Ctrl" };

/// A chord on the command modifier as shown to the user, as "Ctrl+K" or, on macOS, "Cmd+K".
/// `rest` is what follows the modifier ("K", "Shift+N").
pub fn command_chord(rest: &str) -> String {
    format!("{COMMAND_KEY}+{rest}")
}

impl Binding {
    pub const fn ctrl(key: Key) -> Self {
        Binding { ctrl: true, alt: false, shift: false, key }
    }

    pub const fn ctrl_shift(key: Key) -> Self {
        Binding { ctrl: true, alt: false, shift: true, key }
    }

    /// `Ctrl+Shift+R`: how the binding is shown, and how it is written to the settings file.
    pub fn label(&self) -> String {
        let mut out = String::new();
        for (on, name) in [(self.ctrl, "Ctrl"), (self.alt, "Alt"), (self.shift, "Shift")] {
            if on {
                out.push_str(name);
                out.push('+');
            }
        }
        out.push_str(self.key.name());
        out
    }

    /// Read a binding back from its phrase. `None` for anything that is not one, so a
    /// hand-edited settings file cannot stop the app starting.
    pub fn parse(text: &str) -> Option<Self> {
        let mut out = Binding { ctrl: false, alt: false, shift: false, key: Key::Space };
        let mut key = None;
        for part in text.split('+').map(str::trim).filter(|s| !s.is_empty()) {
            match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" | "cmd" | "command" => out.ctrl = true,
                "alt" | "option" => out.alt = true,
                "shift" => out.shift = true,
                _ => {
                    // the key itself, and only one of them
                    if key.is_some() {
                        return None;
                    }
                    key = key_from_name(part);
                    key?;
                }
            }
        }
        out.key = key?;
        Some(out)
    }

    /// What egui matches a key press against.
    pub fn shortcut(&self) -> KeyboardShortcut {
        let mut m = Modifiers::NONE;
        if self.ctrl {
            // the platform's own command modifier: Ctrl on Windows and Linux, Cmd on macOS
            m |= Modifiers::COMMAND;
        }
        if self.alt {
            m |= Modifiers::ALT;
        }
        if self.shift {
            m |= Modifiers::SHIFT;
        }
        KeyboardShortcut::new(m, self.key)
    }

    /// Why this binding cannot be used, or `None` when it can.
    ///
    /// Two things are turned down. A binding with no command or alt modifier would swallow
    /// ordinary typing, and the handful of combinations every text box needs -- copy, cut,
    /// paste, undo, redo, select-all -- belong to the text box, whatever the app would rather
    /// do with them.
    pub fn refusal(&self) -> Option<&'static str> {
        if !self.ctrl && !self.alt {
            return Some("Needs Ctrl or Alt: a key on its own would be caught instead of typed.");
        }
        let editing = matches!(self.key, Key::C | Key::X | Key::V | Key::Z | Key::Y | Key::A);
        if self.ctrl && !self.shift && !self.alt && editing {
            return Some("Belongs to the text boxes: copy, cut, paste, undo, redo and select-all.");
        }
        if matches!(self.key, Key::Backspace | Key::Delete | Key::Enter | Key::Escape | Key::Tab) {
            return Some("Belongs to the text boxes and the dialogs.");
        }
        None
    }
}

/// A key by name, spelled as the label writes it or as a person would type it by hand:
/// `Space`, `space`, `BACKSPACE`. Names with a capital inside them, such as `ArrowLeft`, are
/// matched as written.
fn key_from_name(name: &str) -> Option<Key> {
    if let Some(k) = Key::from_name(name) {
        return Some(k);
    }
    let mut chars = name.chars();
    let titled: String = match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase(),
        None => return None,
    };
    Key::from_name(&titled)
}

/// An action, how it is named, and the keys it carries unless the user says otherwise.
pub struct ActionInfo {
    pub action: Action,
    /// The name this action is saved under. Never shown, and never changed once in use: a
    /// settings file written by an older build is read by it.
    pub id: &'static str,
    pub label: &'static str,
    pub default: Binding,
}

const fn info(action: Action, id: &'static str, label: &'static str, default: Binding) -> ActionInfo {
    ActionInfo { action, id, label, default }
}

/// Every action, in the order Settings lists them.
pub const ACTIONS: &[ActionInfo] = &[
    info(Action::SendToRepeater, "send_to_repeater", "Send to Repeater", Binding::ctrl(Key::R)),
    info(Action::SendToIntruder, "send_to_intruder", "Send to Intruder", Binding::ctrl(Key::I)),
    info(Action::SendToOrganizer, "send_to_organizer", "Send to Organizer", Binding::ctrl(Key::O)),
    info(Action::SendRequest, "send_request", "Send request (Repeater)", Binding::ctrl(Key::Space)),
    info(Action::ToggleIntercept, "toggle_intercept", "Toggle Proxy interception", Binding::ctrl(Key::T)),
    info(Action::ForwardHeld, "forward_held", "Forward intercepted message", Binding::ctrl(Key::F)),
    info(Action::DropHeld, "drop_held", "Drop intercepted message", Binding::ctrl(Key::D)),
    info(Action::CommandPalette, "command_palette", "Open command palette", Binding::ctrl(Key::K)),
    info(Action::ToggleInspector, "toggle_inspector", "Toggle Inspector panel", Binding::ctrl_shift(Key::N)),
    info(Action::NextTab, "next_tab", "Go to next tab", Binding::ctrl(Key::Equals)),
    info(Action::PreviousTab, "previous_tab", "Go to previous tab", Binding::ctrl(Key::Minus)),
    info(Action::GoTo(Tab::Dashboard), "go_dashboard", "Switch to Dashboard", Binding::ctrl_shift(Key::D)),
    info(Action::GoTo(Tab::Target), "go_target", "Switch to Target", Binding::ctrl_shift(Key::T)),
    info(Action::GoTo(Tab::Proxy), "go_proxy", "Switch to Proxy", Binding::ctrl_shift(Key::P)),
    info(Action::GoTo(Tab::Intruder), "go_intruder", "Switch to Intruder", Binding::ctrl_shift(Key::I)),
    info(Action::GoTo(Tab::Repeater), "go_repeater", "Switch to Repeater", Binding::ctrl_shift(Key::R)),
    info(Action::GoTo(Tab::Interactor), "go_interactor", "Switch to Interactor", Binding::ctrl_shift(Key::C)),
    info(Action::GoTo(Tab::Sequencer), "go_sequencer", "Switch to Sequencer", Binding::ctrl_shift(Key::S)),
    info(Action::GoTo(Tab::Decoder), "go_decoder", "Switch to Decoder", Binding::ctrl_shift(Key::E)),
    info(Action::GoTo(Tab::Comparer), "go_comparer", "Switch to Comparer", Binding::ctrl_shift(Key::M)),
    info(Action::GoTo(Tab::Logger), "go_logger", "Switch to Logger", Binding::ctrl_shift(Key::L)),
    info(Action::GoTo(Tab::Organizer), "go_organizer", "Switch to Organizer", Binding::ctrl_shift(Key::O)),
    info(Action::GoTo(Tab::Automation), "go_automation", "Switch to Automation", Binding::ctrl_shift(Key::A)),
];

/// The binding in force for every action: its default, unless the settings hold an override
/// that reads back as a usable binding.
///
/// An override naming an action this build does not have, or a phrase that is not a binding,
/// is passed over and the default stands. A settings file is hand-editable, and one bad line
/// in it must cost at most the one shortcut.
pub fn bindings(overrides: &std::collections::BTreeMap<String, String>) -> Vec<(&'static ActionInfo, Binding)> {
    ACTIONS
        .iter()
        .map(|a| {
            let chosen = overrides
                .get(a.id)
                .and_then(|text| Binding::parse(text))
                .filter(|b| b.refusal().is_none());
            (a, chosen.unwrap_or(a.default))
        })
        .collect()
}

/// The actions whose bindings are the same key as another's. Both sides of a clash are
/// named, so the table can mark each of them.
pub fn clashes(overrides: &std::collections::BTreeMap<String, String>) -> Vec<&'static str> {
    let all = bindings(overrides);
    let mut out = Vec::new();
    for (a, binding) in &all {
        if all.iter().any(|(b, other)| b.id != a.id && other == binding) {
            out.push(a.id);
        }
    }
    out
}

fn selected(app: &App) -> Option<std::sync::Arc<crate::http::HttpEntry>> {
    let id = match app.tab {
        Tab::Target => app.target_selected_history_id.or(app.history_sel)?,
        _ => app.history_sel?,
    };
    app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|e| e.id == id).cloned()
}

pub fn handle(app: &mut App, ctx: &egui::Context) {
    // the shortcut editor is waiting for keys: they are being offered as a binding, not
    // pressed to do something, and consuming them here would make a shortcut that is already
    // in use impossible to move
    if app.hotkey_capturing.is_some() {
        return;
    }
    // which shortcuts were pressed, read before anything acts: running an action can change
    // the tab, and the rest of this frame's keys belong to the tab they were pressed on
    let fired: Vec<Action> = bindings(&app.settings.hotkeys)
        .into_iter()
        .filter(|(_, b)| ctx.input_mut(|i| i.consume_shortcut(&b.shortcut())))
        .map(|(a, _)| a.action)
        .collect();
    for action in fired {
        perform(app, action);
    }
}

/// Carry out one action.
///
/// Public because the shell's navigation rail, the View menu and the command palette all
/// switch tools by asking for the same action a shortcut would, rather than each assigning
/// `app.tab` for itself. There is one dispatch, and this is it.
pub fn perform(app: &mut App, action: Action) {
    match action {
        Action::GoTo(tab) => app.tab = tab,
        Action::SendToRepeater => send_somewhere(app, SendTo::Repeater),
        Action::SendToIntruder => send_somewhere(app, SendTo::Intruder),
        Action::SendToOrganizer => send_somewhere(app, SendTo::Organizer),
        Action::ToggleIntercept => ui_proxy::toggle_intercept(app),
        Action::ForwardHeld => ui_proxy::forward(app),
        Action::DropHeld => ui_proxy::drop_held(app),
        Action::ToggleInspector => app.inspector.show_inspector = !app.inspector.show_inspector,
        Action::CommandPalette => {
            app.show_palette = !app.show_palette;
            app.palette_query.clear();
        }
        Action::SendRequest => {
            if app.tab == Tab::Repeater && app.rep().can_send() {
                actions::send_repeater(app);
            }
        }
        Action::NextTab | Action::PreviousTab => {
            let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
            let step = if action == Action::NextTab { 1 } else { Tab::ALL.len() - 1 };
            app.tab = Tab::ALL[(idx + step) % Tab::ALL.len()];
        }
    }
}

/// Hand whatever the current tab counts as "the message" to another tool: the Repeater tab's
/// own request, the request Intercept is holding, or the selected row of a traffic table.
fn send_somewhere(app: &mut App, to: SendTo) {
    if app.tab == Tab::Repeater {
        let tab = app.rep().clone();
        if tab.request.trim().is_empty() {
            return;
        }
        match to {
            SendTo::Repeater => actions::send_to_repeater(app, &tab.method, &tab.url, &tab.request),
            SendTo::Intruder => actions::send_to_intruder(app, &tab.url, &tab.request),
            SendTo::Organizer => actions::send_to_organizer(app, &tab.url, &tab.request, tab.response.as_deref().unwrap_or("")),
            _ => {}
        }
        return;
    }
    if app.tab == Tab::Proxy && app.proxy_sub == 0 {
        let held_req = app.proxy.held.lock().unwrap_or_else(|e| e.into_inner()).first().map(|h| (h.id, h.url.clone(), h.raw.clone()));
        if let Some((id, url, raw)) = held_req {
            let req = if app.held_loaded == Some(id) && !app.held_edit.trim().is_empty() {
                app.held_edit.clone()
            } else {
                raw
            };
            let method = actions::request_method(&req).unwrap_or_else(|| "GET".to_string());
            match to {
                SendTo::Repeater => actions::send_to_repeater(app, &method, &url, &req),
                SendTo::Intruder => actions::send_to_intruder(app, &url, &req),
                SendTo::Organizer => actions::send_to_organizer(app, &url, &req, ""),
                _ => {}
            }
            return;
        }
    }
    if let Some(e) = selected(app) {
        actions::send_to(app, &e, to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;
    use std::collections::BTreeMap;

    /// A binding writes itself as a phrase and reads back as itself, which is what lets the
    /// settings file be edited by hand.
    #[test]
    fn a_binding_survives_being_written_and_read_matrix() {
        let cases: [(&str, Binding); 5] = [
            ("Ctrl+R", Binding::ctrl(Key::R)),
            ("Ctrl+Shift+R", Binding::ctrl_shift(Key::R)),
            ("Ctrl+Space", Binding::ctrl(Key::Space)),
            ("Ctrl+Equals", Binding::ctrl(Key::Equals)),
            ("Ctrl+Alt+Shift+F", Binding { ctrl: true, alt: true, shift: true, key: Key::F }),
        ];
        assert_table!(cases, |idx, (phrase, binding)| {
            assert_eq!(binding.label(), phrase, "case #{idx}: written");
            assert_eq!(Binding::parse(phrase), Some(binding), "case #{idx}: read back");
            // and the phrase a person is likely to type by hand
            assert_eq!(Binding::parse(&phrase.to_lowercase()), Some(binding), "case #{idx}: lower case");
        });
    }

    /// Anything that is not a binding is turned down rather than guessed at.
    #[test]
    fn what_is_not_a_binding_is_refused_matrix() {
        let bad = ["", "Ctrl", "Ctrl+", "Ctrl+Nonsense", "Ctrl+R+T", "Shift", "++", "Ctrl Shift R"];
        assert_table!(bad, |idx, text| {
            assert_eq!(Binding::parse(text), None, "case #{idx}: {text:?} is not a binding");
        });
    }

    /// The combinations that belong to the text boxes, and keys with no modifier at all, are
    /// refused with a reason.
    #[test]
    fn bindings_that_would_break_typing_are_refused_matrix() {
        let refused: [Binding; 10] = [
            Binding { ctrl: false, alt: false, shift: false, key: Key::R },
            Binding { ctrl: false, alt: false, shift: true, key: Key::R },
            Binding::ctrl(Key::C),
            Binding::ctrl(Key::X),
            Binding::ctrl(Key::V),
            Binding::ctrl(Key::Z),
            Binding::ctrl(Key::Y),
            Binding::ctrl(Key::A),
            Binding::ctrl(Key::Backspace),
            Binding::ctrl(Key::Enter),
        ];
        assert_table!(refused, |idx, binding| {
            assert!(binding.refusal().is_some(), "case #{idx}: {} should be refused", binding.label());
        });

        // the same letters are free again once Shift is held: the text box only owns the plain ones
        for key in [Key::C, Key::X, Key::V, Key::Z, Key::A] {
            let with_shift = Binding::ctrl_shift(key);
            assert!(with_shift.refusal().is_none(), "{} is the app's to bind", with_shift.label());
        }
    }

    /// Every action ships with a usable binding, no two of them collide, and every tab can be
    /// reached by one.
    #[test]
    fn the_default_bindings_are_usable_and_distinct() {
        for a in ACTIONS {
            assert!(a.default.refusal().is_none(), "{} ships with {}, which is refused", a.id, a.default.label());
        }
        for a in ACTIONS {
            let same: Vec<&str> = ACTIONS.iter().filter(|b| b.id != a.id && b.default == a.default).map(|b| b.id).collect();
            assert!(same.is_empty(), "{} shares {} with {same:?}", a.id, a.default.label());
        }
        assert!(clashes(&BTreeMap::new()).is_empty(), "the defaults do not clash with each other");

        // every tab is reachable, including the four that had no shortcut before
        for tab in Tab::ALL {
            assert!(
                ACTIONS.iter().any(|a| a.action == Action::GoTo(tab)),
                "{} has no shortcut",
                tab.label()
            );
        }
        // and every id is written once
        for a in ACTIONS {
            assert_eq!(ACTIONS.iter().filter(|b| b.id == a.id).count(), 1, "{} is listed twice", a.id);
        }
    }

    /// An override is honoured; one that cannot be used, or names something this build does
    /// not have, is passed over and the default stands. One bad line costs one shortcut.
    #[test]
    fn overrides_are_honoured_and_bad_ones_are_passed_over_matrix() {
        struct Case {
            name: &'static str,
            id: &'static str,
            phrase: &'static str,
            want: Option<Binding>,
        }
        let cases = [
            Case { name: "a usable override", id: "send_to_repeater", phrase: "Ctrl+Alt+R", want: Some(Binding { ctrl: true, alt: true, shift: false, key: Key::R }) },
            Case { name: "a phrase that is not a binding", id: "send_to_repeater", phrase: "Ctrl+Nonsense", want: None },
            Case { name: "one that belongs to the text boxes", id: "send_to_repeater", phrase: "Ctrl+C", want: None },
            Case { name: "one with no modifier", id: "send_to_repeater", phrase: "R", want: None },
            Case { name: "an action this build does not have", id: "go_somewhere_removed", phrase: "Ctrl+Alt+Q", want: None },
        ];
        assert_table!(cases, |idx, case| {
            let mut overrides = BTreeMap::new();
            overrides.insert(case.id.to_string(), case.phrase.to_string());
            let all = bindings(&overrides);
            // nothing is ever lost: every action still has a binding
            assert_eq!(all.len(), ACTIONS.len(), "case #{idx} ({})", case.name);
            let repeater = all.iter().find(|(a, _)| a.id == "send_to_repeater").expect("the action");
            let expected = case.want.unwrap_or(Binding::ctrl(Key::R));
            assert_eq!(repeater.1, expected, "case #{idx} ({})", case.name);
        });
    }

    /// Two actions given the same keys are both reported, so the table can mark each of them
    /// rather than leaving the user to guess which one wins.
    #[test]
    fn both_sides_of_a_clash_are_reported() {
        let mut overrides = BTreeMap::new();
        // the Repeater's send-to put onto the keys that forward a held message
        overrides.insert("send_to_repeater".to_string(), "Ctrl+F".to_string());
        let clashing = clashes(&overrides);
        assert!(clashing.contains(&"send_to_repeater"), "the one that moved: {clashing:?}");
        assert!(clashing.contains(&"forward_held"), "and the one it landed on: {clashing:?}");
        assert_eq!(clashing.len(), 2, "and nothing else: {clashing:?}");
    }

    /// Modifiers tell bindings apart: the keys that drop a held message and the keys that
    /// switch to the Dashboard share a letter and must not be read as the same shortcut.
    #[test]
    fn a_shift_makes_a_different_shortcut() {
        let plain = Binding::ctrl(Key::D);
        let shifted = Binding::ctrl_shift(Key::D);
        assert_ne!(plain, shifted);
        assert_ne!(plain.label(), shifted.label());
        assert!(clashes(&BTreeMap::new()).is_empty(), "both ship by default and do not clash");
    }

    /// The command chord is named the way this platform names its command key.
    #[test]
    fn the_command_chord_follows_the_platform() {
        let want = if cfg!(target_os = "macos") { "Cmd+K" } else { "Ctrl+K" };
        assert_eq!(command_chord("K"), want);
        assert_eq!(command_chord("Shift+N"), format!("{COMMAND_KEY}+Shift+N"));
        // and a label written either way reads back as the same binding
        assert_eq!(Binding::parse(&command_chord("K")), Some(Binding::ctrl(Key::K)));
    }
}
