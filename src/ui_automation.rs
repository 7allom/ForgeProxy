//! The Automation tab: the program registry, the pipelines built from it, the target a run is
//! started on, and the console the run writes into while it works.
//!
//! Three panes, two splitters. The sidebar lists what can be run; the editor above the fold
//! sets up whichever of those is selected; the console below it holds the run history and the
//! output. Both splitters are bounded against the region the tab was given -- never against
//! the height still unspent in it, which falls as a pane grows and so would let a pane chase
//! its own ceiling down the screen.

use crate::state::{App, Tab};
use crate::theme::{self, bold, Palette};
use crate::tooling::{
    AutomationBundle, AutomationPlan, ConflictPolicy, ExternalTool, PipelineStep, StepFailurePolicy,
    ToolRun, ToolStdinMode,
};
use eframe::egui;
use egui::{RichText, Ui};

/// What the editor is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutomationSel {
    None,
    /// A registered program, by its place in the registry.
    Program(usize),
    /// A pipeline, by its place in the plan list.
    Pipeline(usize),
}

/// Which of the console's tabs is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleTab {
    Stdout,
    Stderr,
    Imported,
}

impl ConsoleTab {
    pub const ALL: [ConsoleTab; 3] = [ConsoleTab::Stdout, ConsoleTab::Stderr, ConsoleTab::Imported];
    pub fn label(self) -> &'static str {
        match self {
            ConsoleTab::Stdout => "Standard output",
            ConsoleTab::Stderr => "Standard error",
            ConsoleTab::Imported => "Imported issues",
        }
    }
}

/// How wide the sidebar may be: never more than this share of the tab, so the editor beside
/// it always has room and the splitter cannot be dragged past either edge.
const SIDEBAR_SHARE: f32 = 0.45;
const SIDEBAR_MIN: f32 = 170.0;
const SIDEBAR_DEFAULT: f32 = 240.0;
/// The same again downwards for the console.
const CONSOLE_SHARE: f32 = 0.7;
const CONSOLE_MIN: f32 = 120.0;
const CONSOLE_DEFAULT: f32 = 260.0;
/// How many recent exchanges the target bar offers to pick from.
const QUICK_PICK_ROWS: usize = 20;
/// What the program editor's menu-visibility checkbox says.
pub const MENU_VISIBILITY_LABEL: &str = "Show in right-click menus";

/// One edit the sidebar's buttons ask for, carried out after the lists have been drawn (a
/// list cannot be added to or removed from while it is being walked).
enum SidebarEdit {
    NewProgram,
    NewPipeline,
    Duplicate,
    Delete,
    /// Choose a bundle file and put its contents up for review.
    Import,
    /// Write whatever is selected -- or the whole registry -- out as a bundle file.
    Export,
}

/// A bundle chosen for import, held while the user looks over what is in it.
///
/// Nothing is registered until they say so: a bundle is a file from somewhere else naming
/// programs to run on this machine, so what it holds is shown first and imported second.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportPreview {
    /// Where it was read from, to show which file is being considered.
    pub path: String,
    pub bundle: AutomationBundle,
    /// How names already registered are to be settled.
    pub policy: ConflictPolicy,
}

/// What the preview dialog warns about. A bundle is someone else's list of programs to start.
const IMPORT_WARNING: &str = "This file came from somewhere else and names programs to run on \
     this machine, with the arguments below. Read them over before importing, and import only \
     from someone you trust.";

pub fn automation(app: &mut App, ui: &mut Ui, p: &Palette) {
    header(app, ui, p);

    let avail_w = ui.available_width().max(0.0);
    let widest = (avail_w * SIDEBAR_SHARE).max(0.0);
    let narrowest = SIDEBAR_MIN.min(widest);
    egui::SidePanel::left("automation_sidebar")
        .resizable(true)
        .default_width(SIDEBAR_DEFAULT)
        .width_range(narrowest..=widest.max(narrowest))
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(6)))
        .show_inside(ui, |ui| sidebar(app, ui, p));

    egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
        // measured from the region this panel was given, not from what is left unspent in it
        let container_h = ui.max_rect().height().max(0.0);
        let tallest = (container_h * CONSOLE_SHARE).max(0.0);
        let shortest = CONSOLE_MIN.min(tallest);
        egui::TopBottomPanel::bottom("automation_console")
            .resizable(true)
            .default_height(CONSOLE_DEFAULT)
            .height_range(shortest..=tallest.max(shortest))
            .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(6)))
            .show_inside(ui, |ui| console(app, ui, p));
        egui::ScrollArea::vertical().id_salt("automation_editor_scroll").auto_shrink([false, false]).show(
            ui,
            |ui| editor(app, ui, p),
        );
    });
    import_dialog(app, ui, p);
}

/// Column widths in the preview dialog's tables: name, program or steps, arguments, input,
/// and whether that name is already registered.
const PREVIEW_COLS: [f32; 5] = [150.0, 160.0, 180.0, 95.0, 70.0];
/// What the dialog is called, and what its two buttons say.
pub const IMPORT_TITLE: &str = "Import Automation Bundle";
pub const IMPORT_CONFIRM: &str = "Import";

/// What a painted table row says about itself: its cells, in order, with the empty ones left
/// out so a row reads as a sentence rather than as a run of separators.
fn row_label(cells: &[(String, f32, Option<egui::Color32>)]) -> String {
    let said: Vec<&str> = cells.iter().map(|(text, _, _)| text.trim()).filter(|t| !t.is_empty()).collect();
    said.join(" — ")
}

/// The review dialog for a bundle chosen with "Import...": what is in the file, how names
/// already registered are to be settled, and nothing registered until it is confirmed.
fn import_dialog(app: &mut App, ui: &mut Ui, p: &Palette) {
    let Some(preview) = app.automation_import.clone() else { return };
    /// What the dialog was closed with.
    enum Choice {
        Import(ConflictPolicy),
        Cancel,
    }
    let mut policy = preview.policy;
    let modal = egui::Modal::new(egui::Id::new("automation_import_preview")).show(ui.ctx(), |ui| {
        ui.set_width(760.0);
        ui.label(bold(IMPORT_TITLE, 15.0).color(p.strong));
        ui.label(RichText::new(&preview.path).size(11.0).monospace().color(p.disabled));
        ui.add_space(6.0);

        // what the file says about itself
        let b = &preview.bundle;
        egui::Grid::new("automation_import_about").num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
            for (label, text) in [
                ("Bundle:", b.name.trim()),
                ("Description:", b.description.trim()),
                ("Author:", b.author.trim()),
            ] {
                ui.label(RichText::new(label).size(11.5).color(p.disabled));
                let (text, colour) = match text.is_empty() {
                    true => ("not given", p.disabled),
                    false => (text, p.text),
                };
                ui.add(egui::Label::new(RichText::new(text).size(11.5).color(colour)).wrap());
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        // the banner: this is someone else's list of programs to start
        egui::Frame::new()
            .fill(p.banner)
            .stroke(egui::Stroke::new(1.0_f32, p.warning))
            .corner_radius(theme::CORNER)
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.set_width((ui.available_width() - 16.0).max(0.0));
                ui.add(egui::Label::new(RichText::new(IMPORT_WARNING).size(11.5).color(p.medium)).wrap());
            });
        ui.add_space(8.0);

        let w = PREVIEW_COLS;
        let badge = |exists: bool| if exists { ("Exists", p.warning) } else { ("New", p.success) };
        egui::ScrollArea::vertical().id_salt("automation_import_rows").max_height(280.0).show(ui, |ui| {
            if !b.tools.is_empty() {
                ui.label(bold("Programs", 12.5).color(p.strong));
                theme::table_well(ui, p, ((b.tools.len() + 1) as f32) * theme::ROW_HEIGHT + 6.0, |ui| {
                    theme::table_header(
                        ui,
                        p,
                        &[("Name", w[0]), ("Program", w[1]), ("Arguments", w[2]), ("Given on input", w[3]), ("", w[4])],
                    );
                    for (n, tool) in b.tools.iter().enumerate() {
                        let (word, colour) = badge(AutomationBundle::tool_is_registered(&app.settings, &tool.name));
                        let cells = [
                            (tool.display_name(), w[0], None),
                            (tool.command.clone(), w[1], None),
                            (tool.args.clone(), w[2], None),
                            (tool.stdin_mode.label().to_string(), w[3], None),
                            (word.to_string(), w[4], Some(colour)),
                        ];
                        // a painted row announces itself whole, so what is on offer can be
                        // read out as well as looked at
                        let said = row_label(&cells);
                        theme::table_row(ui, p, &cells, false, n % 2 == 1)
                            .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, &said));
                    }
                });
                ui.add_space(6.0);
            }
            if !b.plans.is_empty() {
                ui.label(bold("Pipelines", 12.5).color(p.strong));
                theme::table_well(ui, p, ((b.plans.len() + 1) as f32) * theme::ROW_HEIGHT + 6.0, |ui| {
                    theme::table_header(ui, p, &[("Name", w[0]), ("Steps", w[1]), ("Runs", w[2] + w[3]), ("", w[4])]);
                    for (n, plan) in b.plans.iter().enumerate() {
                        let (word, colour) = badge(AutomationBundle::plan_is_registered(&app.settings, &plan.name));
                        let steps = match plan.steps.len() {
                            1 => "1 step".to_string(),
                            k => format!("{k} steps"),
                        };
                        let runs: Vec<String> = plan.steps.iter().map(|s| s.display_target()).collect();
                        let cells = [
                            (plan.display_name(), w[0], None),
                            (steps, w[1], None),
                            (runs.join(", "), w[2] + w[3], None),
                            (word.to_string(), w[4], Some(colour)),
                        ];
                        let said = row_label(&cells);
                        theme::table_row(ui, p, &cells, false, n % 2 == 1)
                            .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, &said));
                    }
                });
            }
        });

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("A name already registered:").size(11.5).color(p.text));
            for choice in ConflictPolicy::ALL {
                if theme::pill(ui, p, choice.label(), policy == choice).clicked() {
                    policy = choice;
                }
            }
        });
        ui.add_space(10.0);
        let mut chosen = None;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::primary_button(ui, p, IMPORT_CONFIRM).clicked() {
                chosen = Some(Choice::Import(policy));
            }
            if theme::plain_button(ui, p, "Cancel", true).clicked() {
                chosen = Some(Choice::Cancel);
            }
        });
        chosen
    });

    let closed = modal.should_close();
    match modal.inner.or_else(|| closed.then_some(Choice::Cancel)) {
        Some(Choice::Import(policy)) => {
            let report = preview.bundle.merge_into(&mut app.settings, policy);
            app.automation_import = None;
            app.automation_sel = AutomationSel::None;
            app.automation_msg = format!(
                "Imported {} of {} from {}: {}",
                report.taken(),
                report.tools.len() + report.plans.len(),
                preview.path,
                report.lines().join("; ")
            );
        }
        Some(Choice::Cancel) => {
            app.automation_import = None;
            app.automation_msg = "Nothing was imported.".into();
        }
        // still open: keep whichever policy is showing
        None => {
            if let Some(open) = &mut app.automation_import {
                open.policy = policy;
            }
        }
    }
}

fn header(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.horizontal(|ui| {
        ui.label(bold("Automation", theme::FONT_TITLE).color(p.strong));
        theme::icon_help(ui, p).on_hover_text(
            "Register a program, or chain several into a pipeline, and run it on a recorded \
             exchange. A program is started directly with its arguments -- there is no shell \
             between this and it. One that writes a findings document on its standard output \
             can have what it reports taken straight into the issue store.",
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let going = app.runs.running();
            let (badge, colour) = match going {
                0 => ("Idle".to_string(), p.disabled),
                1 => ("1 run in progress".to_string(), p.badge_info),
                n => (format!("{n} runs in progress"), p.badge_info),
            };
            theme::status_pill(ui, p, &badge, colour);
        });
    });
    ui.add_space(4.0);
}

// ---------------------------------------------------------------- sidebar

fn sidebar(app: &mut App, ui: &mut Ui, p: &Palette) {
    let mut edit: Option<SidebarEdit> = None;
    let mut pick: Option<AutomationSel> = None;

    ui.horizontal_wrapped(|ui| {
        if theme::plain_button(ui, p, "+ New tool", true).clicked() {
            edit = Some(SidebarEdit::NewProgram);
        }
        if theme::plain_button(ui, p, "+ New pipeline", true).clicked() {
            edit = Some(SidebarEdit::NewPipeline);
        }
    });
    ui.horizontal_wrapped(|ui| {
        let chosen = app.automation_sel != AutomationSel::None;
        if theme::plain_button(ui, p, "Duplicate", chosen).clicked() {
            edit = Some(SidebarEdit::Duplicate);
        }
        if theme::plain_button(ui, p, "Delete", chosen).clicked() {
            edit = Some(SidebarEdit::Delete);
        }
    });
    ui.horizontal_wrapped(|ui| {
        if theme::plain_button(ui, p, "Import...", true)
            .on_hover_text("Read a bundle file someone sent you. What is in it is shown before anything is registered.")
            .clicked()
        {
            edit = Some(SidebarEdit::Import);
        }
        let what = match app.automation_sel {
            AutomationSel::Program(_) => "Write the selected program out as a bundle file.",
            AutomationSel::Pipeline(_) => {
                "Write the selected pipeline out as a bundle file, with every program its steps run."
            }
            AutomationSel::None => "Write every program and pipeline out as one bundle file.",
        };
        if theme::plain_button(ui, p, "Export...", true).on_hover_text(what).clicked() {
            edit = Some(SidebarEdit::Export);
        }
    });
    search_box(app, ui);
    ui.add_space(6.0);

    let query = app.automation_filter.trim().to_lowercase();
    egui::ScrollArea::vertical().id_salt("automation_sidebar_scroll").auto_shrink([false, false]).show(ui, |ui| {
        // the places in the registry and the plan list are kept with the rows, so what the
        // search leaves out never shifts what a visible row selects
        let programs: Vec<(usize, &ExternalTool)> = app
            .settings
            .external_tools
            .iter()
            .enumerate()
            .filter(|(_, t)| program_matches(t, &query))
            .collect();
        let plans: Vec<(usize, &AutomationPlan)> = app
            .settings
            .automation_plans
            .iter()
            .enumerate()
            .filter(|(_, pl)| plan_matches(pl, &app.settings.external_tools, &query))
            .collect();

        ui.label(bold("Registered programs", 12.5).color(p.strong));
        if app.settings.external_tools.is_empty() {
            ui.label(RichText::new("None yet. \"+ New tool\" adds one.").size(11.5).color(p.disabled));
        } else if programs.is_empty() {
            ui.label(RichText::new("No program matches the search.").size(11.5).color(p.disabled));
        }
        for (nth, (i, tool)) in programs.into_iter().enumerate() {
            let sel = app.automation_sel == AutomationSel::Program(i);
            let colour = if tool.is_runnable() { p.text } else { p.disabled };
            if list_row(ui, p, &tool.display_name(), &tool.command, sel, colour, nth).clicked() {
                pick = Some(AutomationSel::Program(i));
            }
        }
        ui.add_space(8.0);
        ui.label(bold("Pipelines", 12.5).color(p.strong));
        if app.settings.automation_plans.is_empty() {
            ui.label(RichText::new("None yet. \"+ New pipeline\" adds one.").size(11.5).color(p.disabled));
        } else if plans.is_empty() {
            ui.label(RichText::new("No pipeline matches the search.").size(11.5).color(p.disabled));
        }
        for (nth, (i, plan)) in plans.into_iter().enumerate() {
            let sel = app.automation_sel == AutomationSel::Pipeline(i);
            let colour = if plan.is_runnable() { p.text } else { p.disabled };
            let steps = match plan.steps.len() {
                1 => "1 step".to_string(),
                n => format!("{n} steps"),
            };
            if list_row(ui, p, &plan.display_name(), &steps, sel, colour, nth).clicked() {
                pick = Some(AutomationSel::Pipeline(i));
            }
        }
    });

    if let Some(sel) = pick {
        app.automation_sel = sel;
    }
    if let Some(edit) = edit {
        apply_sidebar_edit(app, edit);
    }
}

/// The sidebar's search box: one line, with a button to empty it again. It narrows both
/// lists below and changes nothing that is registered.
fn search_box(app: &mut App, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        let room = (ui.available_width() - 26.0).max(60.0);
        ui.add(
            egui::TextEdit::singleline(&mut app.automation_filter)
                .id_salt("automation_sidebar_search")
                .hint_text("Search…")
                .desired_width(room),
        )
        .on_hover_text("Matches a name or a program, ignoring case; a pipeline also matches the programs its steps run");
        if ui
            .add_enabled(!app.automation_filter.is_empty(), egui::Button::new("×").frame(false))
            .on_hover_text("Clear the search")
            .clicked()
        {
            app.automation_filter.clear();
        }
    });
}

/// Does `text` hold `query`, ignoring case? `query` is already folded by the caller, which
/// does it once for the whole list rather than once per row. An empty query matches
/// everything, so an empty search box hides nothing.
fn holds(text: &str, query: &str) -> bool {
    query.is_empty() || text.to_lowercase().contains(query)
}

/// Is this program one the search is looking for: by the name on its menu entry, or by the
/// program it runs?
fn program_matches(tool: &ExternalTool, query: &str) -> bool {
    holds(&tool.name, query) || holds(&tool.command, query)
}

/// Is this pipeline one the search is looking for: by its own name, or by any program its
/// steps run -- which is what answers "what uses this script?".
fn plan_matches(plan: &AutomationPlan, tools: &[ExternalTool], query: &str) -> bool {
    holds(&plan.name, query)
        || plan
            .steps
            .iter()
            .filter_map(|s| tools.get(s.tool_index))
            .any(|t| program_matches(t, query))
}

/// One row of a sidebar list: a name, and under it the one thing worth knowing at a glance.
fn list_row(
    ui: &mut Ui,
    p: &Palette,
    name: &str,
    sub: &str,
    selected: bool,
    colour: egui::Color32,
    index: usize,
) -> egui::Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 34.0), egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let fill = if selected {
            p.selection_soft
        } else if response.hovered() {
            p.hover
        } else if index % 2 == 1 {
            p.panel
        } else {
            egui::Color32::TRANSPARENT
        };
        if fill != egui::Color32::TRANSPARENT {
            ui.painter().rect_filled(rect, theme::CORNER as f32, fill);
        }
        let painter = ui.painter();
        let left = rect.left() + 6.0;
        painter.text(
            egui::pos2(left, rect.top() + 9.0),
            egui::Align2::LEFT_CENTER,
            name,
            egui::FontId::proportional(theme::FONT_UI),
            colour,
        );
        painter.text(
            egui::pos2(left, rect.top() + 24.0),
            egui::Align2::LEFT_CENTER,
            sub,
            egui::FontId::monospace(theme::FONT_CAPTION - 0.5),
            p.disabled,
        );
    }
    let label = name.to_string();
    response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Button, true, selected, label.clone()));
    response
}

fn apply_sidebar_edit(app: &mut App, edit: SidebarEdit) {
    match edit {
        SidebarEdit::NewProgram => {
            app.settings.external_tools.push(ExternalTool { name: "New tool".into(), ..Default::default() });
            app.automation_sel = AutomationSel::Program(app.settings.external_tools.len() - 1);
        }
        SidebarEdit::NewPipeline => {
            app.settings
                .automation_plans
                .push(AutomationPlan { name: "New pipeline".into(), steps: Vec::new(), ..Default::default() });
            app.automation_sel = AutomationSel::Pipeline(app.settings.automation_plans.len() - 1);
        }
        SidebarEdit::Duplicate => match app.automation_sel {
            AutomationSel::Program(i) => {
                if let Some(tool) = app.settings.external_tools.get(i).cloned() {
                    let copy = ExternalTool { name: format!("{} copy", tool.display_name()), ..tool };
                    app.settings.external_tools.insert(i + 1, copy);
                    app.automation_sel = AutomationSel::Program(i + 1);
                }
            }
            AutomationSel::Pipeline(i) => {
                if let Some(plan) = app.settings.automation_plans.get(i).cloned() {
                    let copy = AutomationPlan { name: format!("{} copy", plan.display_name()), ..plan };
                    app.settings.automation_plans.insert(i + 1, copy);
                    app.automation_sel = AutomationSel::Pipeline(i + 1);
                }
            }
            AutomationSel::None => {}
        },
        SidebarEdit::Delete => match app.automation_sel {
            AutomationSel::Program(i) if i < app.settings.external_tools.len() => {
                app.settings.external_tools.remove(i);
                // a pipeline step pointing past the end of the registry is caught when it
                // runs, but the ones that pointed *after* the removed program would silently
                // move onto their neighbour, so they are followed down with it
                for plan in &mut app.settings.automation_plans {
                    for step in &mut plan.steps {
                        if step.tool_index > i {
                            step.tool_index -= 1;
                        }
                    }
                }
                app.automation_sel = AutomationSel::None;
            }
            AutomationSel::Pipeline(i) if i < app.settings.automation_plans.len() => {
                app.settings.automation_plans.remove(i);
                app.automation_sel = AutomationSel::None;
            }
            _ => app.automation_sel = AutomationSel::None,
        },
        SidebarEdit::Import => choose_bundle_to_import(app),
        SidebarEdit::Export => export_selection(app),
    }
    // either list may have changed; every step is pointed back at the program it names
    let tools = app.settings.external_tools.clone();
    crate::tooling::bind_steps(&tools, &mut app.settings.automation_plans);
}

/// What the selected program or pipeline -- or the whole registry -- looks like as a bundle,
/// and the file name to offer for it.
fn selection_as_bundle(app: &App) -> (AutomationBundle, String) {
    // the author is left for whoever shares the file to fill in: nothing here puts a name to
    // it on their behalf
    let tools = &app.settings.external_tools;
    match app.automation_sel {
        AutomationSel::Program(i) if i < tools.len() => {
            (AutomationBundle::from_tool(&tools[i], ""), bundle_file_name(&tools[i].display_name()))
        }
        AutomationSel::Pipeline(i) if i < app.settings.automation_plans.len() => {
            let plan = &app.settings.automation_plans[i];
            (AutomationBundle::from_plan(plan, tools, ""), bundle_file_name(&plan.display_name()))
        }
        _ => (
            AutomationBundle::from_all(tools, &app.settings.automation_plans, ""),
            "forgeproxy-automation.json".to_string(),
        ),
    }
}

/// A file name for a bundle of this name: its words joined with underscores, as project files
/// are named.
fn bundle_file_name(name: &str) -> String {
    let stem: String = name
        .trim()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    let stem = if stem.is_empty() { "automation".to_string() } else { stem };
    format!("{stem}.json")
}

/// "Export...": the native dialog, then the bundle is written there.
fn export_selection(app: &mut App) {
    let (bundle, suggested) = selection_as_bundle(app);
    let Some(path) = rfd::FileDialog::new()
        .set_title("Export an automation bundle")
        .add_filter("Automation bundle", &["json"])
        .set_file_name(&suggested)
        .save_file()
    else {
        return;
    };
    app.automation_msg = match crate::tooling::write_bundle(&bundle, &path) {
        Ok(()) => format!(
            "Wrote {} {} and {} {} to {}.",
            bundle.tools.len(),
            if bundle.tools.len() == 1 { "program" } else { "programs" },
            bundle.plans.len(),
            if bundle.plans.len() == 1 { "pipeline" } else { "pipelines" },
            path.display()
        ),
        Err(e) => e,
    };
}

/// "Import...": the native dialog, then what the file holds goes up for review.
fn choose_bundle_to_import(app: &mut App) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Import an automation bundle")
        .add_filter("Automation bundle", &["json"])
        .pick_file()
    else {
        return;
    };
    match crate::tooling::read_bundle(&path) {
        Ok(bundle) => {
            app.automation_msg.clear();
            app.automation_import = Some(ImportPreview {
                path: path.display().to_string(),
                bundle,
                policy: ConflictPolicy::default(),
            });
        }
        Err(e) => app.automation_msg = e,
    }
}

// ---------------------------------------------------------------- editor

fn editor(app: &mut App, ui: &mut Ui, p: &Palette) {
    match app.automation_sel {
        AutomationSel::Program(i) if i < app.settings.external_tools.len() => program_editor(app, ui, p, i),
        AutomationSel::Pipeline(i) if i < app.settings.automation_plans.len() => pipeline_editor(app, ui, p, i),
        _ => {
            // an index left behind by a deletion counts as nothing selected
            app.automation_sel = AutomationSel::None;
            // a notice of its own height rather than one of the cards that claim the rest of
            // the pane, so the target bar below it stays where it always is
            egui::Frame::new()
                .fill(p.deep)
                .stroke(egui::Stroke::new(1.0_f32, p.border_subtle))
                .corner_radius(theme::CORNER * 2)
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.set_width((ui.available_width() - 24.0).max(0.0));
                    ui.label(bold("Nothing selected", theme::FONT_TITLE).color(p.strong));
                    ui.label(
                        RichText::new(
                            "Choose a program or a pipeline on the left, or add one, to set it up and run it.",
                        )
                        .size(12.0)
                        .color(p.disabled),
                    );
                });
        }
    }
    // the target bar stays whatever is selected, so the Run button is always where it was
    // and says why it did nothing rather than disappearing
    ui.add_space(6.0);
    target_bar(app, ui, p);
}

fn program_editor(app: &mut App, ui: &mut Ui, p: &Palette, index: usize) {
    ui.label(bold("Program", theme::FONT_TITLE - 1.0).color(p.strong));
    let mut browse = false;
    let mut copy_schema = false;
    // the name before this frame's editing, so a rename can be followed into the pipelines
    // whose steps name this program
    let was_called = app.settings.external_tools[index].name.clone();
    {
        let tool = &mut app.settings.external_tools[index];
        egui::Grid::new("automation_tool_edit").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            ui.label("Menu label:");
            ui.add(egui::TextEdit::singleline(&mut tool.name).desired_width(320.0).hint_text("Inspect in script"));
            ui.end_row();

            ui.label("Description:");
            ui.add(
                egui::TextEdit::singleline(&mut tool.description)
                    .desired_width(400.0)
                    .hint_text("what it does, for whoever you share it with"),
            )
            .on_hover_text("Carried in an exported bundle, so whoever receives it can see what it is for.");
            ui.end_row();

            ui.label("Program:");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut tool.command)
                        .desired_width(250.0)
                        .hint_text("a name on the path, or a full path"),
                );
                if theme::plain_button(ui, p, "Browse…", true).clicked() {
                    browse = true;
                }
            });
            ui.end_row();

            ui.label("Arguments:");
            ui.add(
                egui::TextEdit::singleline(&mut tool.args)
                    .desired_width(400.0)
                    .hint_text("-r --url {url} {req_file}"),
            );
            ui.end_row();

            ui.label("Give it on input:");
            egui::ComboBox::from_id_salt("automation_tool_stdin")
                .selected_text(tool.stdin_mode.label())
                .show_ui(ui, |ui| {
                    for mode in ToolStdinMode::ALL {
                        ui.selectable_value(&mut tool.stdin_mode, mode, mode.label());
                    }
                });
            ui.end_row();

            ui.label("Timeout (seconds):");
            ui.add(egui::DragValue::new(&mut tool.timeout_secs).range(crate::tooling::TIMEOUT_RANGE).speed(1.0))
                .on_hover_text("How long it is given before it is stopped.");
            ui.end_row();

            ui.label("Findings:");
            ui.checkbox(&mut tool.import_findings, "Import JSON findings from standard output")
                .on_hover_text("Read what it writes as a findings document and add the issues it reports.");
            ui.end_row();

            ui.label("Menus:");
            ui.checkbox(&mut tool.show_in_menu, MENU_VISIBILITY_LABEL).on_hover_text(
                "Offer this program when a request or response is right-clicked. Turn it off \
                 for a helper only meant to run as a pipeline step: it stays registered and \
                 runnable from here, and leaves the traffic menus shorter.",
            );
            ui.end_row();
        });
    }
    if browse {
        if let Some(path) = rfd::FileDialog::new().set_title("Choose a program").pick_file() {
            app.settings.external_tools[index].command = path.display().to_string();
        }
    }
    // a program renamed here keeps the pipelines that run it: their steps hold its name, so
    // the new one is carried into them rather than leaving them naming something gone
    let now_called = app.settings.external_tools[index].name.clone();
    if now_called.trim() != was_called.trim() {
        crate::tooling::rename_in_steps(&mut app.settings.automation_plans, &was_called, &now_called);
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Placeholders").size(11.5).color(p.strong));
        if theme::plain_button(ui, p, "Copy sample JSON schema", true)
            .on_hover_text("A findings document in the shape the import expects.")
            .clicked()
        {
            copy_schema = true;
        }
    });
    if copy_schema {
        ui.ctx().copy_text(crate::tooling::SAMPLE_FINDINGS_JSON.to_string());
        app.automation_msg = "A sample findings document is on the clipboard.".into();
    }
    egui::Grid::new("automation_placeholders").num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
        for (token, meaning) in crate::tooling::PLACEHOLDERS {
            ui.label(RichText::new(token).size(11.0).monospace().color(p.badge_info));
            ui.label(RichText::new(meaning).size(11.0).color(p.disabled));
            ui.end_row();
        }
    });
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "The program is started directly, so an address carrying ; or $( ) reaches it as text and is \
             never run. Temporary files are written for your account only and removed when the run ends.",
        )
        .size(11.5)
        .color(p.disabled),
    );
}

/// One change to a step list, carried out once the list has been drawn.
enum StepEdit {
    Add,
    Remove(usize),
    Up(usize),
    Down(usize),
}

fn pipeline_editor(app: &mut App, ui: &mut Ui, p: &Palette, index: usize) {
    ui.label(bold("Pipeline", theme::FONT_TITLE - 1.0).color(p.strong));
    let names: Vec<String> = app
        .settings
        .external_tools
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{}. {}", i + 1, t.display_name()))
        .collect();
    // the registered names as they are, for the step that is picked to hold
    let raw_names: Vec<String> =
        app.settings.external_tools.iter().map(|t| t.name.trim().to_string()).collect();
    let mut edit: Option<StepEdit> = None;
    {
        let plan = &mut app.settings.automation_plans[index];
        ui.horizontal(|ui| {
            ui.label("Pipeline name:");
            ui.add(egui::TextEdit::singleline(&mut plan.name).desired_width(320.0).hint_text("Collect and report"));
        });
        ui.horizontal(|ui| {
            ui.label("Description:");
            ui.add(
                egui::TextEdit::singleline(&mut plan.description)
                    .desired_width(400.0)
                    .hint_text("what this pipeline is for"),
            )
            .on_hover_text("Carried in an exported bundle, beside the programs its steps run.");
        });
        ui.add_space(6.0);
        if plan.steps.is_empty() {
            ui.label(
                RichText::new("No steps yet. Each step runs one registered program, in order.")
                    .size(11.5)
                    .color(p.disabled),
            );
        }
        let last = plan.steps.len().saturating_sub(1);
        for (n, step) in plan.steps.iter_mut().enumerate() {
            egui::Frame::new()
                .fill(p.banner)
                .stroke(egui::Stroke::new(1.0_f32, p.border_subtle))
                .corner_radius(theme::CORNER)
                .inner_margin(egui::Margin::same(6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(bold(format!("Step {}", n + 1), 12.5).color(p.strong));
                        // the step names its program, so what is showing is whichever entry
                        // answers to that name, and the place is only the fallback
                        let at = raw_names
                            .iter()
                            .position(|known| !step.tool_name.trim().is_empty() && known == step.tool_name.trim())
                            .or(Some(step.tool_index).filter(|i| *i < names.len()));
                        let selected = match at {
                            Some(i) => names[i].clone(),
                            None => format!("{} (not registered here)", step.display_target()),
                        };
                        egui::ComboBox::from_id_salt(("automation_step_tool", index, n))
                            .selected_text(selected)
                            .width(220.0)
                            .show_ui(ui, |ui| {
                                for (i, name) in names.iter().enumerate() {
                                    if ui.selectable_label(at == Some(i), name).clicked() {
                                        // both are set together: the name is what binds, the
                                        // place is kept beside it and in step with it
                                        step.tool_index = i;
                                        step.tool_name = raw_names[i].clone();
                                    }
                                }
                            });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if theme::plain_button(ui, p, "Remove", true).clicked() {
                                edit = Some(StepEdit::Remove(n));
                            }
                            if theme::plain_button(ui, p, "Down", n < last).clicked() {
                                edit = Some(StepEdit::Down(n));
                            }
                            if theme::plain_button(ui, p, "Up", n > 0).clicked() {
                                edit = Some(StepEdit::Up(n));
                            }
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Arguments for this step:").size(11.5).color(p.text));
                        ui.add(
                            egui::TextEdit::singleline(&mut step.args_override)
                                .desired_width(300.0)
                                .hint_text("blank: use the program's own template"),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("On failure:").size(11.5).color(p.text));
                        for policy in StepFailurePolicy::ALL {
                            if theme::pill(ui, p, policy.label(), step.on_failure == policy).clicked() {
                                step.on_failure = policy;
                            }
                        }
                        ui.add_space(10.0);
                        ui.checkbox(&mut step.import_findings, "Import findings");
                    });
                });
            ui.add_space(4.0);
        }
        if theme::plain_button(ui, p, "+ Add step", !names.is_empty())
            .on_hover_text("Register a program first; a step runs one of them.")
            .clicked()
        {
            edit = Some(StepEdit::Add);
        }
    }
    if let Some(edit) = edit {
        let first = app.settings.external_tools.first().map(|t| t.name.trim().to_string());
        let steps = &mut app.settings.automation_plans[index].steps;
        match edit {
            // a new step runs the first registered program until it is pointed at another
            StepEdit::Add => steps.push(PipelineStep { tool_name: first.unwrap_or_default(), ..Default::default() }),
            StepEdit::Remove(n) if n < steps.len() => {
                steps.remove(n);
            }
            StepEdit::Up(n) if n > 0 && n < steps.len() => steps.swap(n, n - 1),
            StepEdit::Down(n) if n + 1 < steps.len() => steps.swap(n, n + 1),
            _ => {}
        }
    }
    // the name is what binds a step; the place beside it is brought back into line here
    let tools = app.settings.external_tools.clone();
    crate::tooling::bind_steps(&tools, &mut app.settings.automation_plans);
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Each step's output is written to a file only you can read, which the next step reaches through \
             {prev_out_file}. Every one of those files is removed when the pipeline ends.",
        )
        .size(11.5)
        .color(p.disabled),
    );
}

// ---------------------------------------------------------------- target and run

fn target_bar(app: &mut App, ui: &mut Ui, p: &Palette) {
    ui.separator();
    let recent = recent_targets(app);
    let mut run = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(bold("Target", 12.5).color(p.strong));
        let typed = ui.add(
            egui::TextEdit::singleline(&mut app.automation_target)
                .desired_width(300.0)
                .hint_text("https://shop.test/cart"),
        );
        if typed.changed() {
            // an address typed by hand is no longer the exchange that was picked
            app.automation_source = None;
        }
        let picked = recent
            .iter()
            .find(|(id, _)| Some(*id) == app.automation_source)
            .map(|(_, label)| label.clone())
            .unwrap_or_else(|| "Recent exchanges…".to_string());
        egui::ComboBox::from_id_salt("automation_quick_pick").selected_text(picked).width(260.0).show_ui(
            ui,
            |ui| {
                if recent.is_empty() {
                    ui.label(RichText::new("Nothing recorded yet.").size(11.5).color(p.disabled));
                }
                for (id, label) in &recent {
                    if ui.selectable_label(app.automation_source == Some(*id), label).clicked() {
                        app.automation_source = Some(*id);
                        if let Some(url) = target_url_of(app, *id) {
                            app.automation_target = url;
                        }
                    }
                }
            },
        );
        if theme::primary_button(ui, p, "Run").clicked() {
            run = true;
        }
    });
    if !app.automation_msg.is_empty() {
        ui.label(RichText::new(&app.automation_msg).size(11.5).color(p.text));
    }
    if run {
        crate::actions::run_automation_selection(app);
    }
}

/// The last few recorded exchanges, newest first, as (history id, label).
fn recent_targets(app: &App) -> Vec<(usize, String)> {
    let history = app.history.lock().unwrap_or_else(|e| e.into_inner());
    history
        .iter()
        .rev()
        .take(QUICK_PICK_ROWS)
        .map(|e| (e.id, format!("#{} {} {}", e.id, e.method, crate::actions::entry_url(e))))
        .collect()
}

fn target_url_of(app: &App, id: usize) -> Option<String> {
    let history = app.history.lock().unwrap_or_else(|e| e.into_inner());
    history.iter().find(|e| e.id == id).map(|e| crate::actions::entry_url(e))
}

// ---------------------------------------------------------------- console

fn console(app: &mut App, ui: &mut Ui, p: &Palette) {
    let runs = app.runs.snapshot();
    // the newest run is the one being watched, so the history reads top-down from it
    let rows: Vec<ToolRun> = runs.into_iter().rev().collect();
    let selected = app
        .automation_run_sel
        .and_then(|id| rows.iter().find(|r| r.id == id).cloned())
        .or_else(|| rows.first().cloned());

    let mut cancel: Option<u64> = None;
    let mut rerun: Option<u64> = None;
    let mut clear = false;
    let mut pick: Option<u64> = None;

    ui.horizontal(|ui| {
        ui.label(bold("Run history", 12.5).color(p.strong));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let running = selected.as_ref().is_some_and(|r| !r.status.finished());
            if theme::plain_button(ui, p, "Clear", rows.iter().any(|r| r.status.finished()))
                .on_hover_text("Drop the runs that have finished.")
                .clicked()
            {
                clear = true;
            }
            if theme::plain_button(ui, p, "Re-run", selected.is_some()).clicked() {
                rerun = selected.as_ref().map(|r| r.id);
            }
            if theme::plain_button(ui, p, "Cancel", running).clicked() {
                cancel = selected.as_ref().map(|r| r.id);
            }
        });
    });
    ui.add_space(2.0);

    // the two halves of the console: what has been run, and what the selected run said
    let pane_h = (ui.available_height() - 4.0).max(40.0);
    theme::columns(ui, 2, |cols| {
        run_history(&mut cols[0], p, &rows, selected.as_ref().map(|r| r.id), pane_h, &mut pick);
        output_pane(app, &mut cols[1], p, selected.as_ref(), pane_h);
    });

    if let Some(id) = pick {
        app.automation_run_sel = Some(id);
    }
    if let Some(id) = cancel {
        app.runs.request_cancel(id);
    }
    if clear {
        app.runs.clear_finished();
        app.automation_run_sel = None;
    }
    if let Some(id) = rerun {
        crate::actions::rerun_automation(app, id);
    }
}

fn run_history(
    ui: &mut Ui,
    p: &Palette,
    rows: &[ToolRun],
    selected: Option<u64>,
    height: f32,
    pick: &mut Option<u64>,
) {
    // (minimum width, share of the spare width): Status, What, Target, Took, Issues
    const COLS: [(f32, f32); 5] = [(80.0, 0.0), (120.0, 0.35), (150.0, 0.65), (60.0, 0.0), (50.0, 0.0)];
    theme::fitted_table(ui, p, "automation_runs", height, &COLS, |ui, w| {
        theme::table_header(
            ui,
            p,
            &[("Status", w[0]), ("What", w[1]), ("Target", w[2]), ("Took", w[3]), ("Issues", w[4])],
        );
        if rows.is_empty() {
            ui.label(RichText::new("  Nothing has been run yet.").size(11.5).color(p.disabled));
            return;
        }
        egui::ScrollArea::vertical().id_salt("automation_runs_scroll").auto_shrink([false, false]).show(ui, |ui| {
            for (k, run) in rows.iter().enumerate() {
                let open = selected == Some(run.id);
                let row = theme::table_row(
                    ui,
                    p,
                    &[
                        (run.status_text(), w[0], Some(run.status.colour(p))),
                        (run.label.clone(), w[1], None),
                        (run.target_url.clone(), w[2], Some(p.disabled)),
                        (run.elapsed_text(), w[3], Some(p.disabled)),
                        (run.imported_count.to_string(), w[4], Some(p.disabled)),
                    ],
                    open,
                    k % 2 == 1,
                );
                let label = format!("Run {} {}", run.label, run.status.label());
                row.widget_info(|| {
                    egui::WidgetInfo::selected(egui::WidgetType::Button, true, open, label.clone())
                });
                if row.clicked() {
                    *pick = Some(run.id);
                }
            }
        });
    });
}

fn output_pane(app: &mut App, ui: &mut Ui, p: &Palette, run: Option<&ToolRun>, height: f32) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let items: Vec<(ConsoleTab, &str)> = ConsoleTab::ALL.iter().map(|t| (*t, t.label())).collect();
        theme::underline_tabs(ui, p, &items, &mut app.automation_console, 24.0);
    });
    let body_h = (height - 30.0).max(30.0);
    let Some(run) = run else {
        let _ = theme::empty_state_card(
            ui,
            None,
            "No run selected",
            "Run a program or a pipeline, and its output appears here as it arrives.",
            None,
        );
        return;
    };
    let text = match app.automation_console {
        ConsoleTab::Stdout => run.stdout.clone(),
        ConsoleTab::Stderr => run.stderr.clone(),
        ConsoleTab::Imported => {
            if run.imported.is_empty() {
                String::new()
            } else {
                run.imported.join("\n")
            }
        }
    };
    let empty = match app.automation_console {
        ConsoleTab::Stdout => "Nothing on standard output yet.",
        ConsoleTab::Stderr => "Nothing on standard error.",
        ConsoleTab::Imported => "No issues were imported by this run.",
    };
    theme::table_well(ui, p, body_h, |ui| {
        egui::ScrollArea::both().id_salt("automation_output_scroll").auto_shrink([false, false]).show(ui, |ui| {
            if text.trim().is_empty() {
                ui.label(RichText::new(empty).size(11.5).color(p.disabled));
            } else {
                ui.add(
                    egui::Label::new(RichText::new(&text).size(theme::FONT_CODE - 1.0).monospace().color(p.ed_text))
                        .wrap(),
                );
            }
        });
    });
}

/// Open the Automation tab, from wherever asked (Settings, the command palette).
pub fn open(app: &mut App) {
    app.tab = Tab::Automation;
    app.show_settings = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_table, MockAppBuilder};
    use crate::theme::ThemeMode;
    use crate::tooling::{AutomationPlan, PipelineStep};

    fn frame(ctx: &egui::Context, app: &mut App) -> Option<egui::accesskit::TreeUpdate> {
        frame_with(ctx, app, Vec::new())
    }

    /// One full frame of the app with these input events.
    fn frame_with(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1500.0, 950.0))),
            events,
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    /// Click the widget labelled `label`, press and release over a frame each, the way a user
    /// would; the layout is settled first so the widget is found where it is drawn.
    fn click(ctx: &egui::Context, app: &mut App, label: &str) {
        frame(ctx, app);
        let update = frame(ctx, app);
        let nodes = &update.as_ref().expect("accesskit output").nodes;
        let r = nodes
            .iter()
            .find(|(_, n)| n.label() == Some(label))
            .and_then(|(_, n)| n.bounds())
            .unwrap_or_else(|| panic!("no widget labelled {label:?}"));
        let at = egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32);
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame_with(ctx, app, vec![egui::Event::PointerMoved(at), button(true)]);
        frame_with(ctx, app, vec![button(false)]);
        frame_with(ctx, app, Vec::new());
    }

    fn labels(update: &Option<egui::accesskit::TreeUpdate>) -> Vec<String> {
        update
            .as_ref()
            .expect("accesskit output")
            .nodes
            .iter()
            .filter_map(|(_, n)| n.label().or_else(|| n.value()).map(|s| s.to_string()))
            .collect()
    }

    fn panel_rect(ctx: &egui::Context, id: &str) -> egui::Rect {
        egui::containers::panel::PanelState::load(ctx, egui::Id::new(id))
            .map(|s| s.rect)
            .unwrap_or_else(|| panic!("no panel {id:?} on screen"))
    }

    /// The tab draws under both themes, with nothing selected, with a program selected and
    /// with a pipeline selected, and each of the three console tabs draws too.
    #[test]
    fn the_automation_tab_draws_in_both_themes_matrix() {
        struct Case {
            name: &'static str,
            open: fn(&mut App),
            wants: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "nothing selected yet",
                open: |_| {},
                wants: &["Automation", "+ New tool", "+ New pipeline", "Import...", "Export...", "Nothing selected"],
            },
            Case {
                name: "a program selected",
                open: |app| {
                    app.settings.external_tools = vec![ExternalTool {
                        name: "Inspect in script".into(),
                        command: "python3".into(),
                        args: "-u check.py {url}".into(),
                        ..Default::default()
                    }];
                    app.automation_sel = AutomationSel::Program(0);
                },
                wants: &[
                    "Menu label:",
                    "Description:",
                    "Arguments:",
                    "Timeout (seconds):",
                    "{prev_out_file}",
                    "{var:KEY}",
                    "Copy sample JSON schema",
                    MENU_VISIBILITY_LABEL,
                ],
            },
            Case {
                name: "a pipeline selected",
                open: |app| {
                    app.settings.external_tools =
                        vec![ExternalTool { name: "one".into(), command: "true".into(), ..Default::default() }];
                    app.settings.automation_plans = vec![AutomationPlan {
                        name: "Collect and report".into(),
                        steps: vec![PipelineStep::default(), PipelineStep::default()],
                        ..Default::default()
                    }];
                    app.automation_sel = AutomationSel::Pipeline(0);
                },
                wants: &["Pipeline name:", "Description:", "Step 1", "Step 2", "+ Add step", "Import findings"],
            },
        ];
        assert_table!(cases, |idx, case| {
            for look in [ThemeMode::DarkWorkstation, ThemeMode::LightWorkstation] {
                let (ctx, mut app) = MockAppBuilder::new()
                    .with_tab(Tab::Automation)
                    .with_light_theme(look == ThemeMode::LightWorkstation)
                    .build_with_ctx();
                ctx.enable_accesskit();
                app.set_theme(look);
                crate::theme::apply_theme(&ctx, look);
                (case.open)(&mut app);
                for console in ConsoleTab::ALL {
                    app.automation_console = console;
                    frame(&ctx, &mut app);
                    let seen = labels(&frame(&ctx, &mut app));
                    assert!(
                        seen.iter().any(|l| l == console.label()),
                        "case #{idx} ({}, {look:?}, {console:?}): the console tab is there: {seen:?}",
                        case.name
                    );
                    for want in case.wants {
                        assert!(
                            seen.iter().any(|l| l == want),
                            "case #{idx} ({}, {look:?}, {console:?}): {want:?} is missing from {seen:?}",
                            case.name
                        );
                    }
                }
            }
        });
    }

    /// The sidebar's search narrows both lists -- by a name, by the program a row runs, and
    /// for a pipeline by the programs its steps run -- and a row it leaves showing still
    /// selects the entry it stands for, not the one at that place in the shortened list.
    #[test]
    fn the_sidebar_search_narrows_both_lists() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Automation).build_with_ctx();
        ctx.enable_accesskit();
        app.settings.external_tools = vec![
            ExternalTool { name: "Header survey".into(), command: "/opt/survey".into(), ..Default::default() },
            ExternalTool { name: "Token report".into(), command: "python3".into(), ..Default::default() },
        ];
        app.settings.automation_plans = vec![
            AutomationPlan {
                name: "Collect and report".into(),
                steps: vec![PipelineStep { tool_index: 1, ..Default::default() }],
                ..Default::default()
            },
            AutomationPlan {
                name: "Headers only".into(),
                steps: vec![PipelineStep { tool_index: 0, ..Default::default() }],
                ..Default::default()
            },
        ];
        // nothing is selected while the lists are read, so the editor's own text boxes are
        // not on the screen holding a program's name: a name found here is a row's
        let listed = |ctx: &egui::Context, app: &mut App| {
            frame(ctx, app);
            labels(&frame(ctx, app))
        };

        let all = listed(&ctx, &mut app);
        for want in ["Header survey", "Token report", "Collect and report", "Headers only"] {
            assert!(all.iter().any(|l| l == want), "{want:?} is listed when nothing is searched for: {all:?}");
        }

        // by name, ignoring case; the pipeline comes with it because its step runs that program
        app.automation_filter = "token".into();
        let seen = listed(&ctx, &mut app);
        assert!(seen.iter().any(|l| l == "Token report"), "the program searched for: {seen:?}");
        assert!(!seen.iter().any(|l| l == "Header survey"), "and not the one beside it: {seen:?}");
        assert!(
            seen.iter().any(|l| l == "Collect and report"),
            "a pipeline matches through the programs its steps run: {seen:?}"
        );
        assert!(!seen.iter().any(|l| l == "Headers only"), "but not one that runs something else: {seen:?}");

        // by the program itself, which is what answers "what runs this?"
        app.automation_filter = "/opt/survey".into();
        let seen = listed(&ctx, &mut app);
        assert!(seen.iter().any(|l| l == "Header survey"), "matched by its program: {seen:?}");
        assert!(seen.iter().any(|l| l == "Headers only"), "and the pipeline that runs it: {seen:?}");
        assert!(!seen.iter().any(|l| l == "Token report"), "{seen:?}");

        // a search that matches nothing says so, rather than looking like an empty registry
        app.automation_filter = "no such thing".into();
        let seen = listed(&ctx, &mut app);
        assert!(seen.iter().any(|l| l == "No program matches the search."), "{seen:?}");
        assert!(seen.iter().any(|l| l == "No pipeline matches the search."), "{seen:?}");
        for gone in ["Header survey", "Token report", "Collect and report", "Headers only"] {
            assert!(!seen.iter().any(|l| l == gone), "{gone:?} is hidden: {seen:?}");
        }
        assert_eq!(app.settings.external_tools.len(), 2, "and nothing was unregistered by searching");
        assert_eq!(app.settings.automation_plans.len(), 2);

        // the one row a search leaves showing still stands for the second entry in the
        // registry, not for the first place in the shortened list
        app.automation_filter = "token".into();
        click(&ctx, &mut app, "Token report");
        assert_eq!(app.automation_sel, AutomationSel::Program(1), "the place in the registry travels with the row");
    }

    /// The import dialog shows what a bundle holds -- what it says about itself, every program
    /// with its arguments, every pipeline with what its steps run, and which names are already
    /// registered -- and registers nothing until it is confirmed.
    #[test]
    fn the_import_dialog_shows_a_bundle_and_registers_it_only_when_confirmed() {
        let bundle = || AutomationBundle {
            format_version: crate::tooling::BUNDLE_FORMAT_VERSION,
            name: "Nightly sweep".into(),
            description: "Looks over a response, then reports.".into(),
            author: "a colleague".into(),
            tools: vec![
                ExternalTool {
                    name: "Collect".into(),
                    command: "/opt/collect".into(),
                    args: "--url {url} --token {var:TOKEN}".into(),
                    stdin_mode: ToolStdinMode::RawResponse,
                    ..Default::default()
                },
                ExternalTool { name: "Report".into(), command: "/opt/report".into(), ..Default::default() },
            ],
            plans: vec![AutomationPlan {
                name: "Nightly".into(),
                steps: vec![
                    PipelineStep { tool_name: "Collect".into(), ..Default::default() },
                    PipelineStep { tool_name: "Report".into(), ..Default::default() },
                ],
                ..Default::default()
            }],
        };
        let opened = |app: &mut App| {
            app.automation_import = Some(ImportPreview {
                path: "/tmp/nightly.json".into(),
                bundle: bundle(),
                policy: ConflictPolicy::default(),
            });
        };

        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Automation).build_with_ctx();
        ctx.enable_accesskit();
        // one of the names is already registered, so the dialog has both badges to show
        app.settings.external_tools =
            vec![ExternalTool { name: "Report".into(), command: "/usr/bin/mine".into(), ..Default::default() }];
        opened(&mut app);
        frame(&ctx, &mut app);
        let seen = labels(&frame(&ctx, &mut app));

        for want in [
            IMPORT_TITLE,
            "/tmp/nightly.json",
            "Nightly sweep",
            "Looks over a response, then reports.",
            "a colleague",
            IMPORT_CONFIRM,
            "Cancel",
        ] {
            assert!(seen.iter().any(|l| l == want), "the dialog shows {want:?}: {seen:?}");
        }
        assert!(
            seen.iter().any(|l| l.contains("came from somewhere else")),
            "and warns about what it is: {seen:?}"
        );
        for choice in ConflictPolicy::ALL {
            assert!(seen.iter().any(|l| l == choice.label()), "{:?} is on offer: {seen:?}", choice.label());
        }
        // the programs, with their arguments and whether the name is taken
        let row = |part: &str| seen.iter().find(|l| l.contains(part)).cloned();
        let collect = row("/opt/collect").unwrap_or_else(|| panic!("no row for the first program: {seen:?}"));
        for part in ["Collect", "/opt/collect", "--url {url} --token {var:TOKEN}", "Raw response", "New"] {
            assert!(collect.contains(part), "the row says {part:?}: {collect:?}");
        }
        let report = row("/opt/report").expect("a row for the second program");
        assert!(report.contains("Exists"), "the name already registered is marked: {report:?}");
        // and the pipeline, with what its steps run
        let pipeline = row("2 steps").expect("a row for the pipeline");
        for part in ["Nightly", "Collect, Report", "New"] {
            assert!(pipeline.contains(part), "the pipeline row says {part:?}: {pipeline:?}");
        }
        // nothing has been registered by looking at it
        assert_eq!(app.settings.external_tools.len(), 1, "still only ours");
        assert!(app.settings.automation_plans.is_empty());

        // cancelling leaves the registry alone and closes the dialog
        click(&ctx, &mut app, "Cancel");
        assert!(app.automation_import.is_none(), "the dialog closed");
        assert_eq!(app.settings.external_tools.len(), 1, "and registered nothing");
        assert_eq!(app.automation_msg, "Nothing was imported.");

        // confirming registers it, keeping both where a name was taken
        opened(&mut app);
        click(&ctx, &mut app, IMPORT_CONFIRM);
        assert!(app.automation_import.is_none(), "the dialog closed");
        let names: Vec<&str> = app.settings.external_tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Report", "Collect", "Report (2)"], "the taken name was kept and theirs renamed");
        assert_eq!(app.settings.automation_plans.len(), 1);
        // and the imported pipeline runs the programs it arrived with, not ours
        let runs: Vec<String> = app.settings.automation_plans[0]
            .steps
            .iter()
            .map(|s| s.resolve(&app.settings.external_tools).map(|t| t.command.clone()).unwrap_or_default())
            .collect();
        assert_eq!(runs, ["/opt/collect", "/opt/report"], "{:?}", app.settings.automation_plans[0].steps);
        assert!(app.automation_msg.contains("Imported 3 of 3"), "{}", app.automation_msg);
        assert!(app.automation_msg.contains("registered as \"Report (2)\""), "{}", app.automation_msg);
    }

    /// Both of the tab's splitters hold where they were let go, and neither can be dragged
    /// past the edge of the region the tab was given.
    #[test]
    fn the_automation_splitters_are_bounded_and_hold_matrix() {
        struct Case {
            name: &'static str,
            panel: &'static str,
            /// Which way the grip is dragged, and which measurement of the panel it changes.
            horizontal: bool,
        }
        let cases = [
            Case { name: "the sidebar", panel: "automation_sidebar", horizontal: true },
            Case { name: "the console", panel: "automation_console", horizontal: false },
        ];
        assert_table!(cases, |idx, case| {
            for (direction, delta) in [("growing it", 160.0_f32), ("shrinking it", -160.0)] {
                let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Automation).build_with_ctx();
                ctx.enable_accesskit();
                frame(&ctx, &mut app);
                frame(&ctx, &mut app);
                let what = format!("case #{idx} ({}, {direction})", case.name);

                let size = |ctx: &egui::Context| {
                    let r = panel_rect(ctx, case.panel);
                    if case.horizontal { r.width() } else { r.height() }
                };
                let before = size(&ctx);
                // the grip: the sidebar's right edge, or the console's top edge
                let r = panel_rect(&ctx, case.panel);
                let grip = if case.horizontal {
                    egui::pos2(r.right(), r.center().y)
                } else {
                    egui::pos2(r.center().x, r.top())
                };
                // the console grows upward and the sidebar rightward, so the pointer moves
                // the other way to grow the console
                let step = if case.horizontal { delta } else { -delta };
                let button = |pos, pressed| egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                };
                let at = |n: f32| {
                    if case.horizontal {
                        egui::pos2(grip.x + n, grip.y)
                    } else {
                        egui::pos2(grip.x, grip.y + n)
                    }
                };
                let send = |app: &mut App, events: Vec<egui::Event>| {
                    let input = egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1500.0, 950.0),
                        )),
                        events,
                        ..Default::default()
                    };
                    let _ = ctx.run(input, |ctx| crate::ui_core::frame(app, ctx));
                };
                send(&mut app, vec![egui::Event::PointerMoved(grip)]);
                send(&mut app, vec![button(grip, true)]);
                for n in 1..=4 {
                    send(&mut app, vec![egui::Event::PointerMoved(at(step * (n as f32 / 4.0)))]);
                }
                send(&mut app, vec![button(at(step), false)]);
                let released = size(&ctx);
                for _ in 0..5 {
                    frame(&ctx, &mut app);
                }
                let settled = size(&ctx);

                assert!(
                    (settled - released).abs() < 0.5,
                    "{what}: it did not hold ({released} on release, {settled} five frames later)"
                );
                if delta > 0.0 {
                    assert!(released > before + 60.0, "{what}: the drag grew it ({before} -> {released})");
                } else {
                    assert!(released < before - 40.0, "{what}: the drag shrank it ({before} -> {released})");
                }
            }
        });
    }

    /// Dragged as far as it will go, each splitter still leaves the pane beside it on screen:
    /// the bound is taken from the tab's own region, so neither pane can swallow the other.
    #[test]
    fn a_splitter_dragged_to_the_edge_leaves_the_other_pane_standing() {
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Automation).build_with_ctx();
        ctx.enable_accesskit();
        frame(&ctx, &mut app);
        frame(&ctx, &mut app);
        let tab_w = panel_rect(&ctx, "automation_sidebar").width() + panel_rect(&ctx, "automation_console").width();

        let send = |app: &mut App, events: Vec<egui::Event>| {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1500.0, 950.0))),
                events,
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| crate::ui_core::frame(app, ctx));
        };
        let button = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        // the sidebar, dragged right across the window
        let r = panel_rect(&ctx, "automation_sidebar");
        let grip = egui::pos2(r.right(), r.center().y);
        send(&mut app, vec![egui::Event::PointerMoved(grip)]);
        send(&mut app, vec![button(grip, true)]);
        send(&mut app, vec![egui::Event::PointerMoved(egui::pos2(grip.x + 4000.0, grip.y))]);
        send(&mut app, vec![button(egui::pos2(grip.x + 4000.0, grip.y), false)]);
        frame(&ctx, &mut app);
        let sidebar = panel_rect(&ctx, "automation_sidebar").width();
        assert!(
            sidebar <= tab_w * SIDEBAR_SHARE + 2.0,
            "the sidebar stopped at its share of the tab ({sidebar:.0} of {tab_w:.0})"
        );

        // the console, dragged to the top of the window
        let r = panel_rect(&ctx, "automation_console");
        let grip = egui::pos2(r.center().x, r.top());
        send(&mut app, vec![egui::Event::PointerMoved(grip)]);
        send(&mut app, vec![button(grip, true)]);
        send(&mut app, vec![egui::Event::PointerMoved(egui::pos2(grip.x, grip.y - 4000.0))]);
        send(&mut app, vec![button(egui::pos2(grip.x, grip.y - 4000.0), false)]);
        frame(&ctx, &mut app);
        let console = panel_rect(&ctx, "automation_console");
        assert!(console.top() > 60.0, "the editor above the console is still on screen (top {:.0})", console.top());
    }

    /// Adding, duplicating and deleting from the sidebar does what it says, and deleting a
    /// program carries the steps that pointed past it down with it.
    #[test]
    fn the_sidebar_edits_the_registry_and_the_plans() {
        let mut app = MockAppBuilder::new().with_tab(Tab::Automation).build();

        apply_sidebar_edit(&mut app, SidebarEdit::NewProgram);
        apply_sidebar_edit(&mut app, SidebarEdit::NewProgram);
        assert_eq!(app.settings.external_tools.len(), 2);
        assert_eq!(app.automation_sel, AutomationSel::Program(1), "the new one is the one being edited");

        app.settings.external_tools[0].name = "first".into();
        app.settings.external_tools[1].name = "second".into();
        app.automation_sel = AutomationSel::Program(0);
        apply_sidebar_edit(&mut app, SidebarEdit::Duplicate);
        assert_eq!(app.settings.external_tools.len(), 3);
        assert_eq!(app.settings.external_tools[1].name, "first copy", "the copy sits next to its original");
        assert_eq!(app.automation_sel, AutomationSel::Program(1));

        apply_sidebar_edit(&mut app, SidebarEdit::NewPipeline);
        let plan = AutomationPlan {
            name: "p".into(),
            steps: vec![
                PipelineStep { tool_index: 0, ..Default::default() },
                PipelineStep { tool_index: 2, ..Default::default() },
            ],
            ..Default::default()
        };
        app.settings.automation_plans = vec![plan];

        // the first program goes: the step that ran it is left pointing at slot 0, and the
        // step that ran the third program follows it down to slot 1
        app.automation_sel = AutomationSel::Program(0);
        apply_sidebar_edit(&mut app, SidebarEdit::Delete);
        assert_eq!(app.settings.external_tools.len(), 2);
        let steps = &app.settings.automation_plans[0].steps;
        assert_eq!((steps[0].tool_index, steps[1].tool_index), (0, 1), "the later step came with it");
        assert_eq!(app.automation_sel, AutomationSel::None, "and nothing is selected afterwards");

        app.automation_sel = AutomationSel::Pipeline(0);
        apply_sidebar_edit(&mut app, SidebarEdit::Delete);
        assert!(app.settings.automation_plans.is_empty());
    }
}
