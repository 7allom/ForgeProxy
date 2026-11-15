//! The command line: the flags, the usage text, and everything the app can be asked to do
//! without opening a window.
//!
//! Two of those things need no display server at all -- listing the saved pipelines, and
//! running one unattended -- so a container or a build agent can run a pipeline over a target
//! and act on what it reports. The engine that runs it is the same one the Automation tab
//! drives, and the report it writes is the same document the Dashboard's buttons write; only
//! the way in is different.

use crate::tooling::{
    AutomationBundle, AutomationPlan, ConflictPolicy, ExternalTool, HeadlessOutcome, RunStatus, ToolContext,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Everything asked for went as it should.
pub const EXIT_OK: i32 = 0;
/// The command line was wrong, or the run did not finish: a missing pipeline, a step that
/// failed or ran out of time, a file that could not be read or written.
pub const EXIT_FAILED: i32 = 1;
/// The run finished and reported issues, with `--fail-on-findings` asked for.
pub const EXIT_FINDINGS: i32 = 2;

/// What `--help` prints. Written out in full rather than generated, so the wording is the
/// wording and not a side effect of the parser's shape.
pub const USAGE: &str = "\
ForgeProxy -- a web-testing workbench.

Usage:
  forgeproxy [options] [<project.forge>]

Opening:
  <project.forge>        Open this project (the same as --project).
  --project <path>       Open this project. With --run-plan it is written back when the run
                         ends, and created if it is not there yet.
  --config <dir>         Read and write settings.json in this folder instead of the usual
                         one. For an isolated run on a build agent or in a container.
  --bind <host>          Listen for proxy traffic on this address instead of the saved one.
  --port <1-65535>       Listen on this port instead of the saved one.
  --target <url>         The address a run is made against. Without a run it is filled into
                         the Automation tab's target bar.

Running without a window:
  --list-plans           Print each saved pipeline with its number of steps, and exit.
  --run-plan <name>      Run this saved pipeline and exit. No display server is needed. The
                         name is matched exactly first, then ignoring capitals.
  --run-file <path>      Run the pipeline in this bundle file, using the programs the bundle
                         carries and falling back to the registered ones for any it does not.
                         Nothing has to be imported first. With --run-plan, that names which
                         of the bundle's pipelines to run.
  --tool <name>          Run one registered program and exit.
  --req <path>           A file holding the raw request the run is about, for {req_file} and
                         for a program given the request on its input.
  --res <path>           The same for the raw response, and for {res_file}.
  --var KEY=VALUE        A value the templates reach as {var:KEY}. May be given more than
                         once, and applies to --run-plan, --run-file and --tool alike.
  --report <path>        Write the issues the run ends with to this file. A .xml path writes
                         the XML report; anything else writes HTML.
  --fail-on-findings     Exit 2 when the run finishes having reported one issue or more.

Sharing programs and pipelines:
  --import <path>        Register what a bundle file holds, and exit.
  --on-conflict <word>   What to do with a name already registered, when importing: rename
                         (the default), replace, or skip.
  --export <name>        Write the pipeline or program of this name out as a bundle, and exit.
                         A pipeline takes every program its steps run with it, so the file
                         stands on its own.
  --export-all           Write every program and pipeline out as one bundle, and exit.
  --out <path>           Where --export and --export-all write to.

Other:
  --tab <name>           Open on this tab.
  --light                Open in the light theme.
  --screenshot <path>    Draw a few frames, save a picture of the window, and exit.
  -h, --help             Print this and exit.
  -V, --version          Print the version and exit.

Flags take their value either way round: --port 8080 and --port=8080 are the same.

Exit codes:
  0  Everything asked for went as it should.
  1  The command line was wrong, or the run did not finish.
  2  --fail-on-findings was given and the run reported at least one issue.
";

/// The command line, parsed. Every field is what was asked for, not what will be done with
/// it: [`run`] decides that.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub help: bool,
    pub version: bool,
    pub config: Option<PathBuf>,
    pub project: Option<String>,
    pub bind: Option<String>,
    pub port: Option<u16>,
    pub list_plans: bool,
    pub run_plan: Option<String>,
    /// A bundle file to run the pipeline out of, without registering anything.
    pub run_file: Option<PathBuf>,
    /// One registered program to run on its own.
    pub tool: Option<String>,
    /// Files holding the raw request and response a run is about.
    pub req: Option<PathBuf>,
    pub res: Option<PathBuf>,
    pub target: Option<String>,
    pub report: Option<PathBuf>,
    pub fail_on_findings: bool,
    /// Values the templates reach as `{var:KEY}`.
    pub vars: BTreeMap<String, String>,
    /// A bundle file to register what is in.
    pub import: Option<PathBuf>,
    /// How a name already registered is settled on import. `None` leaves it to the default.
    pub on_conflict: Option<ConflictPolicy>,
    /// The pipeline or program to write out as a bundle.
    pub export: Option<String>,
    pub export_all: bool,
    /// Where a bundle is written.
    pub out: Option<PathBuf>,
    pub screenshot: Option<String>,
    pub tab: Option<String>,
    pub light: bool,
}

/// The part of the command line the app has to know about as it starts, before the proxy
/// listener is up and before anything is drawn.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Startup {
    pub bind: Option<String>,
    pub port: Option<u16>,
    pub target: Option<String>,
    pub project: Option<String>,
}

impl Options {
    /// Where settings.json is read from and written to for this run.
    pub fn config_dir(&self) -> PathBuf {
        self.config.clone().unwrap_or_else(crate::ca::config_dir)
    }

    /// How a name already registered is settled on import: what was asked for, else a
    /// rename, which is the one answer that loses nothing.
    pub fn conflict_policy(&self) -> ConflictPolicy {
        self.on_conflict.unwrap_or(ConflictPolicy::KeepBoth)
    }

    /// What the app itself needs from the command line at startup.
    pub fn startup(&self) -> Startup {
        Startup {
            bind: self.bind.clone(),
            port: self.port,
            target: self.target.clone(),
            project: self.project.clone(),
        }
    }
}

/// Does this argument read as a flag rather than as a value? Only a double dash counts, so a
/// value may still begin with a single one.
fn is_flag(arg: &str) -> bool {
    arg.starts_with("--")
}

fn needs_value(name: &str, what: &str) -> String {
    format!("{name} needs {what} after it.")
}

fn only_one_project(first: &str) -> String {
    format!("Only one project can be opened; {first:?} was already given.")
}

/// Read the command line. `args` is what follows the program's own name.
///
/// A flag's value may follow it (`--port 8080`) or be joined to it (`--port=8080`). One
/// argument that is not a flag is the project to open, the same as `--project`. Anything else
/// is an error, with a line saying what was wrong; nothing is guessed at.
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Options, String> {
    let argv: Vec<String> = args.into_iter().collect();
    let mut o = Options::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].clone();
        // `--flag=value` carries its own value; `--flag value` takes the argument after it
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if is_flag(n) => (n.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        // the value for a flag that takes one, from whichever form it came in
        let next = argv.get(i + 1).filter(|v| !is_flag(v)).cloned();
        let value = |what: &str| -> Result<String, String> {
            match &inline {
                Some(v) if !v.is_empty() => Ok(v.clone()),
                Some(_) => Err(needs_value(&name, what)),
                None => next.clone().ok_or_else(|| needs_value(&name, what)),
            }
        };
        // a flag whose value followed it rather than being joined to it used two arguments
        let with_value = if inline.is_some() { 1 } else { 2 };
        // and one that takes no value must not be given one
        let no_value = || -> Result<(), String> {
            match inline.is_some() {
                true => Err(format!("{name} takes no value.")),
                false => Ok(()),
            }
        };
        let mut step = 1;
        match name.as_str() {
            "-h" | "--help" => {
                no_value()?;
                o.help = true;
            }
            "-V" | "--version" => {
                no_value()?;
                o.version = true;
            }
            "--config" => {
                o.config = Some(PathBuf::from(value("a directory")?));
                step = with_value;
            }
            "--project" => {
                let path = value("a project path")?;
                if let Some(first) = &o.project {
                    return Err(only_one_project(first));
                }
                o.project = Some(path);
                step = with_value;
            }
            "--bind" => {
                o.bind = Some(value("an address")?);
                step = with_value;
            }
            "--port" => {
                let raw = value("a port number")?;
                let port: u16 = raw
                    .trim()
                    .parse()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| format!("{raw:?} is not a port number; give one from 1 to 65535."))?;
                o.port = Some(port);
                step = with_value;
            }
            "--list-plans" => {
                no_value()?;
                o.list_plans = true;
            }
            "--run-plan" => {
                o.run_plan = Some(value("a pipeline name")?);
                step = with_value;
            }
            "--run-file" => {
                o.run_file = Some(PathBuf::from(value("a bundle path")?));
                step = with_value;
            }
            "--tool" => {
                o.tool = Some(value("a program name")?);
                step = with_value;
            }
            "--req" => {
                o.req = Some(PathBuf::from(value("a file path")?));
                step = with_value;
            }
            "--res" => {
                o.res = Some(PathBuf::from(value("a file path")?));
                step = with_value;
            }
            "--var" => {
                let pair = value("KEY=VALUE")?;
                let (key, val) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("--var takes KEY=VALUE; {pair:?} has no equals sign in it."))?;
                if key.trim().is_empty() {
                    return Err(format!("--var takes KEY=VALUE; {pair:?} names no key."));
                }
                o.vars.insert(key.trim().to_string(), val.to_string());
                step = with_value;
            }
            "--import" => {
                o.import = Some(PathBuf::from(value("a bundle path")?));
                step = with_value;
            }
            "--on-conflict" => {
                let word = value("rename, replace or skip")?;
                o.on_conflict = Some(ConflictPolicy::from_word(&word).ok_or_else(|| {
                    format!("{word:?} is not one of rename, replace or skip.")
                })?);
                step = with_value;
            }
            "--export" => {
                o.export = Some(value("a pipeline or program name")?);
                step = with_value;
            }
            "--export-all" => {
                no_value()?;
                o.export_all = true;
            }
            "--out" => {
                o.out = Some(PathBuf::from(value("a file path")?));
                step = with_value;
            }
            "--target" => {
                o.target = Some(value("an address")?);
                step = with_value;
            }
            "--report" => {
                o.report = Some(PathBuf::from(value("a file path")?));
                step = with_value;
            }
            "--fail-on-findings" => {
                no_value()?;
                o.fail_on_findings = true;
            }
            "--screenshot" => {
                o.screenshot = Some(value("a file path")?);
                step = with_value;
            }
            "--tab" => {
                o.tab = Some(value("a tab name")?);
                step = with_value;
            }
            "--light" => {
                no_value()?;
                o.light = true;
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("{other} is not a flag this build knows."));
            }
            _ => match &o.project {
                Some(first) => return Err(only_one_project(first)),
                None => o.project = Some(arg),
            },
        }
        i += step;
    }
    Ok(o)
}

/// The pipeline `name` asks for: the one of that exact name, or, failing that, the one whose
/// name differs only in its capitals. A name that matches several that way is refused rather
/// than picked between.
pub fn find_plan<'a>(plans: &'a [AutomationPlan], name: &str) -> Result<&'a AutomationPlan, String> {
    let wanted = name.trim();
    if let Some(p) = plans.iter().find(|p| p.name.trim() == wanted) {
        return Ok(p);
    }
    let mut folded = plans.iter().filter(|p| p.name.trim().eq_ignore_ascii_case(wanted));
    match (folded.next(), folded.next()) {
        (Some(p), None) => Ok(p),
        (Some(_), Some(_)) => Err(format!(
            "More than one pipeline is called {wanted:?} but for its capitals. Ask for one of them exactly.{}",
            plan_list(plans)
        )),
        _ => Err(format!("No pipeline is called {wanted:?}.{}", plan_list(plans))),
    }
}

/// The saved pipelines, for an error that has to say what there is instead.
fn plan_list(plans: &[AutomationPlan]) -> String {
    if plans.is_empty() {
        return " No pipelines are saved; the Automation tab builds them.".to_string();
    }
    let names: Vec<String> = plans.iter().map(|p| format!("  {}", p.display_name())).collect();
    format!("\nThe pipelines saved are:\n{}", names.join("\n"))
}

/// The registered program `name` asks for: exactly, else but for its capitals, and never
/// guessed at between two that both answer to it.
pub fn find_tool<'a>(tools: &'a [ExternalTool], name: &str) -> Result<&'a ExternalTool, String> {
    let wanted = name.trim();
    if let Some(t) = tools.iter().find(|t| t.name.trim() == wanted) {
        return Ok(t);
    }
    let mut folded = tools.iter().filter(|t| t.name.trim().eq_ignore_ascii_case(wanted));
    match (folded.next(), folded.next()) {
        (Some(t), None) => Ok(t),
        (Some(_), Some(_)) => Err(format!(
            "More than one program is called {wanted:?} but for its capitals. Ask for one of them exactly.{}",
            tool_list(tools)
        )),
        _ => Err(format!("No program is called {wanted:?}.{}", tool_list(tools))),
    }
}

/// The registered programs, for an error that has to say what there is instead.
fn tool_list(tools: &[ExternalTool]) -> String {
    if tools.is_empty() {
        return " No programs are registered; the Automation tab registers them.".to_string();
    }
    let names: Vec<String> = tools.iter().map(|t| format!("  {}", t.display_name())).collect();
    format!("\nThe programs registered are:\n{}", names.join("\n"))
}

/// The settings for this run, saying on `err` when the file could not be read (the defaults
/// stand in that case, exactly as they do for the app).
fn settings_of(opts: &Options, err: &mut dyn Write) -> crate::state::UserSettings {
    match crate::state::UserSettings::load(&opts.config_dir()) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            crate::state::UserSettings::default()
        }
    }
}

/// Carry out whatever the command line asked for that opens no window, and give back the exit
/// code for it. `None` means there is nothing to do out here and the app should open as usual.
pub fn run(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> Option<i32> {
    if opts.help {
        let _ = write!(out, "{USAGE}");
        return Some(EXIT_OK);
    }
    if opts.version {
        let _ = writeln!(out, "{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Some(EXIT_OK);
    }
    if opts.list_plans {
        return Some(list_plans(opts, out, err));
    }
    if opts.import.is_some() {
        return Some(import_bundle(opts, out, err));
    }
    if opts.export.is_some() || opts.export_all {
        return Some(export_bundle(opts, out, err));
    }
    // a bundle file is run from where it is; --run-plan beside it names which of its pipelines
    if opts.run_file.is_some() {
        return Some(run_file(opts, out, err));
    }
    if opts.tool.is_some() {
        return Some(run_one_tool(opts, out, err));
    }
    if opts.run_plan.is_some() {
        return Some(run_plan(opts, out, err));
    }
    None
}

/// `--import`: register what a bundle holds, settling any name already taken.
fn import_bundle(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = &opts.import else { return EXIT_FAILED };
    let bundle = match crate::tooling::read_bundle(path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return EXIT_FAILED;
        }
    };
    let mut settings = settings_of(opts, err);
    let policy = opts.conflict_policy();
    let report = bundle.merge_into(&mut settings, policy);
    let dir = opts.config_dir();
    if let Err(e) = settings.save(&dir) {
        let _ = writeln!(err, "Couldn't save the settings in {}: {e}", dir.display());
        return EXIT_FAILED;
    }
    let name = match bundle.name.trim() {
        "" => path.display().to_string(),
        named => named.to_string(),
    };
    let _ = writeln!(out, "{name}: a name already registered was set to {}.", policy.word());
    for line in report.lines() {
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(
        out,
        "{} of {} registered in {}.",
        report.taken(),
        report.tools.len() + report.plans.len(),
        dir.join(crate::state::SETTINGS_FILE).display()
    );
    EXIT_OK
}

/// `--export` and `--export-all`: write a bundle out to `--out`.
fn export_bundle(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = &opts.out else {
        let _ = writeln!(err, "--export needs --out <path.json>: there is nowhere to write it otherwise.");
        return EXIT_FAILED;
    };
    let settings = settings_of(opts, err);
    // the author is left for whoever shares the file to fill in; nothing here signs it for them
    let bundle = match &opts.export {
        None => AutomationBundle::from_all(&settings.external_tools, &settings.automation_plans, ""),
        Some(name) => match find_plan(&settings.automation_plans, name) {
            Ok(plan) => AutomationBundle::from_plan(plan, &settings.external_tools, ""),
            // a name that is no pipeline may still be a program
            Err(no_plan) => match find_tool(&settings.external_tools, name) {
                Ok(tool) => AutomationBundle::from_tool(tool, ""),
                Err(no_tool) => {
                    let _ = writeln!(err, "{no_plan}\n{no_tool}");
                    return EXIT_FAILED;
                }
            },
        },
    };
    if let Err(e) = crate::tooling::write_bundle(&bundle, path) {
        let _ = writeln!(err, "{e}");
        return EXIT_FAILED;
    }
    let _ = writeln!(
        out,
        "Wrote {} {} and {} {} to {}.",
        bundle.tools.len(),
        if bundle.tools.len() == 1 { "program" } else { "programs" },
        bundle.plans.len(),
        if bundle.plans.len() == 1 { "pipeline" } else { "pipelines" },
        path.display()
    );
    EXIT_OK
}

/// `--list-plans`: every saved pipeline with how many steps it has.
fn list_plans(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let settings = settings_of(opts, err);
    if settings.automation_plans.is_empty() {
        let _ = writeln!(
            out,
            "No pipelines are saved in {}.",
            opts.config_dir().join(crate::state::SETTINGS_FILE).display()
        );
        return EXIT_OK;
    }
    for plan in &settings.automation_plans {
        let n = plan.steps.len();
        let _ = writeln!(out, "{}\t{n} {}", plan.display_name(), if n == 1 { "step" } else { "steps" });
    }
    EXIT_OK
}

/// One finding as a line of the run's account of itself.
fn finding_line(f: &crate::scan::Finding) -> String {
    format!("[{}] {} — {}{}", f.severity.label(), f.name, f.host, f.path)
}

/// What the three ways of running something unattended all need: where it is pointed, the
/// message it is about, and the project that is to carry what it finds.
struct RunSetup {
    target: String,
    ctx: ToolContext,
    /// The project to write back, when one was named, and what it already held.
    project: Option<(String, crate::project::ProjectFile)>,
    prior: Vec<crate::scan::Finding>,
}

/// Work out what a run is pointed at, from `--target`, `--var`, `--req`, `--res` and
/// `--project`. `Err` is the exit code to end with, the reason having been said on `err`.
fn setup(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> Result<RunSetup, i32> {
    let target = opts.target.as_deref().unwrap_or_default().trim().to_string();
    if target.is_empty() {
        let _ = writeln!(err, "A run needs --target <url>: something is run against an address.");
        return Err(EXIT_FAILED);
    }
    // the raw request and response, when files for them were given: a program is handed these
    // on its input and through {req_file} and {res_file}
    let mut read = |what: &str, path: Option<&PathBuf>| -> Result<String, i32> {
        let Some(path) = path else { return Ok(String::new()) };
        std::fs::read_to_string(path).map_err(|e| {
            let _ = writeln!(err, "Couldn't read the {what} from {}: {e}", path.display());
            EXIT_FAILED
        })
    };
    let request = read("request", opts.req.as_ref())?;
    let response = read("response", opts.res.as_ref())?;
    let mut ctx = crate::actions::tool_context(&target, &request, &response);
    ctx.vars = opts.vars.clone();

    let mut project: Option<(String, crate::project::ProjectFile)> = None;
    if let Some(path) = &opts.project {
        if Path::new(path).exists() {
            match crate::project::read(path) {
                Ok(f) => project = Some((path.clone(), f)),
                Err(e) => {
                    let _ = writeln!(err, "{e}");
                    return Err(EXIT_FAILED);
                }
            }
        } else {
            let _ = writeln!(out, "{path} is not there yet; it will be written when the run ends.");
            project = Some((path.clone(), crate::project::ProjectFile::fresh(&target)));
        }
    }
    let prior = project.as_ref().map(|(_, f)| f.imported_findings.clone()).unwrap_or_default();
    Ok(RunSetup { target, ctx, project, prior })
}

/// Say how a run ended, keep what it found, and give back the exit code for it.
///
/// The findings go through the same consolidation the app uses, against what the project
/// already held, so a run repeated on the same project does not list everything twice.
fn settle(opts: &Options, out: &mut dyn Write, err: &mut dyn Write, outcome: HeadlessOutcome, setup: RunSetup) -> i32 {
    // with the exit status when the run did not succeed, which is worth knowing without
    // reading back through the output; a run that did succeed says only that, as the run
    // history in the app does
    let ended = match (outcome.status, outcome.exit_code) {
        (RunStatus::Succeeded, _) => RunStatus::Succeeded.label().to_string(),
        (status, Some(code)) => format!("{} (exit status {code})", status.label()),
        (status, None) => status.label().to_string(),
    };
    let _ = writeln!(out, "\n{ended} after {} ms.", outcome.elapsed_ms);

    let reported = outcome.findings.len();
    let before = setup.prior.len();
    let mut all = setup.prior;
    all.extend(outcome.findings.iter().cloned());
    let kept = crate::scan::consolidate(all);
    let added = kept.len().saturating_sub(before);
    for f in &outcome.findings {
        let _ = writeln!(out, "{}", finding_line(f));
    }
    let _ = writeln!(out, "{reported} reported, {added} new.");

    if let Some((path, mut file)) = setup.project {
        file.imported_findings = kept.clone();
        match crate::project::write(&file, &path) {
            Ok(()) => {
                let _ = writeln!(out, "Saved {path}.");
            }
            Err(e) => {
                let _ = writeln!(err, "Couldn't save {path}: {e}");
                return EXIT_FAILED;
            }
        }
    }
    if let Some(path) = &opts.report {
        match crate::export::write_report(&kept, path) {
            Ok(fmt) => {
                let _ = writeln!(
                    out,
                    "Wrote the {} report to {}.",
                    fmt.extension().to_ascii_uppercase(),
                    path.display()
                );
            }
            Err(e) => {
                let _ = writeln!(err, "Couldn't write {}: {e}", path.display());
                return EXIT_FAILED;
            }
        }
    }

    match outcome.status {
        RunStatus::Failed | RunStatus::TimedOut => EXIT_FAILED,
        _ if opts.fail_on_findings && reported >= 1 => EXIT_FINDINGS,
        _ => EXIT_OK,
    }
}

/// The line a run opens with, saying what is about to be run on what.
fn announce(out: &mut dyn Write, what: &str, target: &str, steps: Option<usize>, vars: &BTreeMap<String, String>) {
    match steps {
        Some(1) => {
            let _ = writeln!(out, "{what} on {target}: 1 step.");
        }
        Some(n) => {
            let _ = writeln!(out, "{what} on {target}: {n} steps.");
        }
        None => {
            let _ = writeln!(out, "{what} on {target}.");
        }
    }
    if !vars.is_empty() {
        let given: Vec<String> = vars.keys().map(|k| format!("{{var:{k}}}")).collect();
        let _ = writeln!(out, "Values given for {}.", given.join(", "));
    }
}

/// `--run-plan`: run one saved pipeline unattended, from the settings in `--config`.
fn run_plan(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let wanted = opts.run_plan.clone().unwrap_or_default();
    let settings = settings_of(opts, err);
    let plan = match find_plan(&settings.automation_plans, &wanted) {
        Ok(p) => p.clone(),
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return EXIT_FAILED;
        }
    };
    let setup = match setup(opts, out, err) {
        Ok(s) => s,
        Err(code) => return code,
    };
    announce(out, &plan.display_name(), &setup.target, Some(plan.steps.len()), &opts.vars);
    let outcome = crate::tooling::run_plan_streaming(&plan, &settings.external_tools, &setup.ctx, out);
    settle(opts, out, err, outcome, setup)
}

/// `--run-file`: run a pipeline straight out of a bundle, with the programs the bundle carries.
///
/// Nothing is registered: the file is read, the pipeline in it is run, and the settings are
/// left exactly as they were. Programs the bundle does not carry are looked for among the
/// registered ones, so a bundle holding only a pipeline still works for whoever has the
/// programs it names.
fn run_file(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = &opts.run_file else { return EXIT_FAILED };
    let bundle = match crate::tooling::read_bundle(path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return EXIT_FAILED;
        }
    };
    let plan = match (&opts.run_plan, bundle.plans.len()) {
        // --run-plan beside --run-file names which of the bundle's pipelines is meant
        (Some(name), _) => match find_plan(&bundle.plans, name) {
            Ok(p) => p.clone(),
            Err(e) => {
                let _ = writeln!(err, "{} holds no such pipeline. {e}", path.display());
                return EXIT_FAILED;
            }
        },
        (None, 1) => bundle.plans[0].clone(),
        (None, 0) => {
            let _ = writeln!(err, "{} holds no pipeline to run; --tool runs a single program.", path.display());
            return EXIT_FAILED;
        }
        (None, _) => {
            let names: Vec<String> = bundle.plans.iter().map(|p| format!("  {}", p.display_name())).collect();
            let _ = writeln!(
                err,
                "{} holds more than one pipeline; name the one to run with --run-plan.\nThe pipelines in it are:\n{}",
                path.display(),
                names.join("\n")
            );
            return EXIT_FAILED;
        }
    };
    let settings = settings_of(opts, err);
    // the bundle's own programs first; anything it did not carry falls back to the registry
    let mut tools = bundle.tools.clone();
    for registered in &settings.external_tools {
        if !tools.iter().any(|t| t.name.trim() == registered.name.trim()) {
            tools.push(registered.clone());
        }
    }
    let mut plan = plan;
    crate::tooling::bind_steps(&tools, std::slice::from_mut(&mut plan));
    let setup = match setup(opts, out, err) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let _ = writeln!(
        out,
        "From {}: {} {} carried, {} registered.",
        path.display(),
        bundle.tools.len(),
        if bundle.tools.len() == 1 { "program" } else { "programs" },
        settings.external_tools.len()
    );
    announce(out, &plan.display_name(), &setup.target, Some(plan.steps.len()), &opts.vars);
    let outcome = crate::tooling::run_plan_streaming(&plan, &tools, &setup.ctx, out);
    settle(opts, out, err, outcome, setup)
}

/// `--tool`: run one registered program on its own.
fn run_one_tool(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let wanted = opts.tool.clone().unwrap_or_default();
    let settings = settings_of(opts, err);
    let tool = match find_tool(&settings.external_tools, &wanted) {
        Ok(t) if t.is_runnable() => t.clone(),
        Ok(t) => {
            let _ = writeln!(
                err,
                "{:?} is registered but cannot be run: it names {}.",
                t.display_name(),
                if t.command.trim().is_empty() { "no program" } else { "no menu label" }
            );
            return EXIT_FAILED;
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return EXIT_FAILED;
        }
    };
    let setup = match setup(opts, out, err) {
        Ok(s) => s,
        Err(code) => return code,
    };
    announce(out, &tool.display_name(), &setup.target, None, &opts.vars);
    let outcome = crate::tooling::run_tool_streaming(&tool, &setup.ctx, out);
    settle(opts, out, err, outcome, setup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;
    use crate::tooling::{ExternalTool, PipelineStep, StepFailurePolicy};

    /// A command line written as it would be typed.
    fn line(text: &str) -> Vec<String> {
        text.split_whitespace().map(String::from).collect()
    }

    fn parsed(text: &str) -> Options {
        parse(line(text)).unwrap_or_else(|e| panic!("{text:?} should read: {e}"))
    }

    fn refused(text: &str) -> String {
        parse(line(text)).expect_err(&format!("{text:?} should be refused"))
    }

    /// Every flag that takes a value reads the same whether the value follows it or is joined
    /// to it with an equals sign.
    #[test]
    fn a_value_may_follow_its_flag_or_be_joined_to_it_matrix() {
        struct Case {
            apart: &'static str,
            joined: &'static str,
            want: fn(&Options) -> bool,
        }
        let cases = [
            Case {
                apart: "--config /tmp/cfg",
                joined: "--config=/tmp/cfg",
                want: |o| o.config.as_deref() == Some(Path::new("/tmp/cfg")),
            },
            Case {
                apart: "--project /tmp/a.forge",
                joined: "--project=/tmp/a.forge",
                want: |o| o.project.as_deref() == Some("/tmp/a.forge"),
            },
            Case {
                apart: "--bind 127.0.0.1",
                joined: "--bind=127.0.0.1",
                want: |o| o.bind.as_deref() == Some("127.0.0.1"),
            },
            Case { apart: "--port 9090", joined: "--port=9090", want: |o| o.port == Some(9090) },
            Case {
                apart: "--run-plan Nightly",
                joined: "--run-plan=Nightly",
                want: |o| o.run_plan.as_deref() == Some("Nightly"),
            },
            Case {
                apart: "--target http://shop.test/",
                joined: "--target=http://shop.test/",
                want: |o| o.target.as_deref() == Some("http://shop.test/"),
            },
            Case {
                apart: "--report /tmp/r.xml",
                joined: "--report=/tmp/r.xml",
                want: |o| o.report.as_deref() == Some(Path::new("/tmp/r.xml")),
            },
            Case { apart: "--tab Proxy", joined: "--tab=Proxy", want: |o| o.tab.as_deref() == Some("Proxy") },
            Case {
                apart: "--screenshot /tmp/s.png",
                joined: "--screenshot=/tmp/s.png",
                want: |o| o.screenshot.as_deref() == Some("/tmp/s.png"),
            },
        ];
        assert_table!(cases, |idx, case| {
            let apart = parsed(case.apart);
            let joined = parsed(case.joined);
            assert!((case.want)(&apart), "case #{idx}: {:?} did not land", case.apart);
            assert_eq!(apart, joined, "case #{idx}: {:?} and {:?} read the same", case.apart, case.joined);
        });
    }

    /// The flags that carry no value, and the short forms beside their long ones.
    #[test]
    fn the_flags_that_carry_no_value() {
        assert!(parsed("--light").light);
        assert!(parsed("--fail-on-findings").fail_on_findings);
        assert!(parsed("--list-plans").list_plans);
        assert_eq!(parsed("-h"), parsed("--help"));
        assert!(parsed("-h").help);
        assert_eq!(parsed("-V"), parsed("--version"));
        assert!(parsed("-V").version);
        // and one of them given a value is a mistake worth saying so about
        assert!(refused("--light=yes").contains("takes no value"), "{}", refused("--light=yes"));
    }

    /// A bare argument is the project to open, which is what a file manager hands over.
    #[test]
    fn a_bare_argument_is_the_project_to_open() {
        assert_eq!(parsed("/tmp/triage.forge").project.as_deref(), Some("/tmp/triage.forge"));
        // beside other flags, in any order
        let mixed = parsed("--light /tmp/triage.forge --port 8081");
        assert_eq!(mixed.project.as_deref(), Some("/tmp/triage.forge"));
        assert_eq!((mixed.light, mixed.port), (true, Some(8081)));
        // and it is the same thing as the flag
        assert_eq!(parsed("/tmp/triage.forge").project, parsed("--project /tmp/triage.forge").project);
    }

    /// Everything the command line can get wrong is refused with a line saying what, rather
    /// than guessed at.
    #[test]
    fn a_command_line_that_cannot_be_read_is_refused_matrix() {
        let cases: [(&str, &str); 11] = [
            ("--nope", "is not a flag"),
            ("-x", "is not a flag"),
            ("--port", "needs a port number"),
            ("--port=", "needs a port number"),
            ("--port eighty", "is not a port number"),
            ("--port 70000", "is not a port number"),
            ("--port 0", "is not a port number"),
            ("--bind --light", "needs an address"),
            ("--config", "needs a directory"),
            ("a.forge b.forge", "Only one project"),
            ("a.forge --project b.forge", "Only one project"),
        ];
        assert_table!(cases, |idx, (text, want)| {
            let got = refused(text);
            assert!(got.contains(want), "case #{idx}: {text:?} should mention {want:?}, said {got:?}");
        });
    }

    /// `--help` and `--version` print and stop, touching nothing else.
    #[test]
    fn help_and_version_print_and_stop() {
        for (text, want) in [("--help", "--run-plan"), ("--version", env!("CARGO_PKG_NAME"))] {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(&parsed(text), &mut out, &mut err);
            let printed = String::from_utf8(out).expect("text");
            assert_eq!(code, Some(EXIT_OK), "{text} ends well");
            assert!(printed.contains(want), "{text} prints {want:?}: {printed}");
            assert!(err.is_empty(), "{text} says nothing on the error stream");
        }
        // the usage text accounts for every exit code it can end with
        for code in ["0", "1", "2"] {
            assert!(USAGE.contains(&format!("  {code}  ")), "the usage text explains exit code {code}");
        }
        // and the version is the build's own
        let (mut out, mut err) = (Vec::new(), Vec::new());
        run(&parsed("-V"), &mut out, &mut err);
        assert_eq!(
            String::from_utf8(out).unwrap().trim(),
            format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        );
    }

    /// Nothing to do without a window means the app opens as usual.
    #[test]
    fn an_ordinary_command_line_opens_the_app() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&parsed("--light --port 8081"), &mut out, &mut err), None);
        assert!(out.is_empty() && err.is_empty(), "and says nothing while doing it");
        // what the app itself is told, from the same command line
        let s = parsed("--bind 0.0.0.0 --port 8081 --target http://shop.test/ --project /tmp/a.forge").startup();
        assert_eq!(s.bind.as_deref(), Some("0.0.0.0"));
        assert_eq!(s.port, Some(8081));
        assert_eq!(s.target.as_deref(), Some("http://shop.test/"));
        assert_eq!(s.project.as_deref(), Some("/tmp/a.forge"));
    }

    fn plan(name: &str, steps: usize) -> AutomationPlan {
        AutomationPlan { name: name.into(), steps: vec![PipelineStep::default(); steps], ..Default::default() }
    }

    /// The pipeline a name asks for: exactly, else but for its capitals, and never guessed at
    /// between two that both answer to it.
    #[test]
    fn the_pipeline_asked_for_is_found_by_name_matrix() {
        let plans = [plan("Nightly sweep", 2), plan("Header survey", 1)];
        let cases: [(&str, Result<&str, &str>); 6] = [
            ("Nightly sweep", Ok("Nightly sweep")),
            ("  Nightly sweep  ", Ok("Nightly sweep")),
            ("nightly SWEEP", Ok("Nightly sweep")),
            ("header survey", Ok("Header survey")),
            ("Nothing like it", Err("No pipeline is called")),
            ("", Err("No pipeline is called")),
        ];
        assert_table!(cases, |idx, (asked, want)| {
            match (find_plan(&plans, asked), want) {
                (Ok(p), Ok(name)) => assert_eq!(p.name, name, "case #{idx}: {asked:?}"),
                (Err(e), Err(part)) => {
                    assert!(e.contains(part), "case #{idx}: {asked:?} said {e:?}");
                    assert!(e.contains("Nightly sweep"), "case #{idx}: and listed what there is: {e:?}");
                }
                (got, want) => panic!("case #{idx}: {asked:?} gave {got:?}, wanted {want:?}"),
            }
        });
        // two that differ only in their capitals are not picked between
        let twins = [plan("Sweep", 1), plan("SWEEP", 1)];
        let e = find_plan(&twins, "sweep").expect_err("ambiguous");
        assert!(e.contains("More than one"), "{e}");
        // the exact name still reaches its own
        assert_eq!(find_plan(&twins, "SWEEP").expect("exact").name, "SWEEP");
        // and an empty registry says where pipelines come from
        let e = find_plan(&[], "anything").expect_err("none saved");
        assert!(e.contains("Automation tab"), "{e}");
    }

    // ---- an unattended run, end to end ---------------------------------
    // The steps are shell scripts handed to the interpreter rather than executed themselves,
    // for the reason given in `tooling`'s own tests: a file this process has only just written
    // cannot reliably be executed while sibling tests are starting programs of their own.

    #[cfg(unix)]
    const SHELL: &str = "/bin/sh";

    /// A findings document naming two issues, as a program that audits something would write.
    #[cfg(unix)]
    const TWO_FINDINGS: &str = r#"{"findings":[
      {"title":"Transport protection not enforced","severity":"medium","confidence":"certain",
       "url":"http://shop.test/account","detail":"The response left the setting off."},
      {"title":"Folder contents listed","severity":"low","url":"http://shop.test/files/"}
    ]}"#;

    /// A directory of this test's own.
    #[cfg(unix)]
    fn work_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("forge-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a place to work");
        dir
    }

    /// A registered program that runs `body` as a script, with `args` after the script's path.
    #[cfg(unix)]
    fn shell_tool(dir: &Path, name: &str, body: &str, args: &str) -> ExternalTool {
        let path = dir.join(format!("{name}.sh"));
        std::fs::write(&path, body).expect("the script");
        ExternalTool {
            name: name.to_string(),
            command: SHELL.to_string(),
            args: format!("{} {args}", path.display()).trim_end().to_string(),
            ..Default::default()
        }
    }

    /// Settings saved in `dir`, holding `tools` and `plans`, as `--config` would find them.
    #[cfg(unix)]
    fn saved_settings(dir: &Path, tools: Vec<ExternalTool>, plans: Vec<AutomationPlan>) {
        let settings = crate::state::UserSettings {
            external_tools: tools,
            automation_plans: plans,
            ..Default::default()
        };
        settings.save(dir).expect("settings.json");
    }

    /// Run a command line as `main` would, giving back (exit code, what was printed, what was
    /// said on the error stream).
    #[cfg(unix)]
    fn headless(text: &str) -> (Option<i32>, String, String) {
        let opts = parse(line(text)).unwrap_or_else(|e| panic!("{text:?} should read: {e}"));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&opts, &mut out, &mut err);
        (code, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
    }

    /// A two-step pipeline, run with no window and no display server: the placeholders reach
    /// the steps, the output of each reaches the terminal, the findings the second reports are
    /// taken in, the project is written with them, and the report is written beside it.
    #[cfg(unix)]
    #[test]
    fn an_unattended_run_keeps_what_it_finds_in_the_project_and_the_report() {
        let dir = work_dir("whole-run");
        let cfg = dir.join("config");
        let note = shell_tool(&dir, "note", "echo \"looked at $1 over $2\"\n", "{url} {scheme}");
        let mut survey = shell_tool(&dir, "survey", &format!("cat <<'DOC'\n{TWO_FINDINGS}\nDOC\n"), "");
        survey.import_findings = true;
        saved_settings(
            &cfg,
            vec![note, survey],
            vec![AutomationPlan {
                name: "Nightly".into(),
                steps: vec![
                    PipelineStep { tool_index: 0, ..Default::default() },
                    PipelineStep { tool_index: 1, ..Default::default() },
                ],
                ..Default::default()
            }],
        );

        let project = dir.join("triage.forge");
        let report = dir.join("out").join("report.html");
        // asked for in lower case, to prove the fold reaches through the whole path
        let (code, out, err) = headless(&format!(
            "--config {} --run-plan nightly --target http://shop.test/account --project {} --report {}",
            cfg.display(),
            project.display(),
            report.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "a clean run ends well. out: {out}\nerr: {err}");
        assert!(out.contains("Nightly on http://shop.test/account: 2 steps"), "{out}");
        assert!(out.contains("looked at http://shop.test/account over http"), "the placeholders reached step 1: {out}");
        assert!(out.contains("Step 1 of 2") && out.contains("Step 2 of 2"), "each step said where it was: {out}");
        assert!(out.contains("Succeeded after"), "{out}");
        assert!(out.contains("[Medium] Transport protection not enforced"), "{out}");
        assert!(out.contains("2 reported, 2 new."), "{out}");

        // the project was created and holds the findings, highest severity first
        let saved = crate::project::read(&project.display().to_string()).expect("the project was written");
        let names: Vec<&str> = saved.imported_findings.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Transport protection not enforced", "Folder contents listed"], "{names:?}");
        assert_eq!(saved.version, 1, "written as the app writes a new project");
        assert!(!saved.skip_extensions.is_empty(), "with the lists that have defaults of their own");

        // and so does the report, in the format the path asked for
        let html = std::fs::read_to_string(&report).expect("the report was written");
        assert!(html.starts_with("<!doctype html>"), "{html}");
        assert!(html.contains("Transport protection not enforced"), "{html}");
        assert!(out.contains("Wrote the HTML report"), "{out}");

        // run again on the same project: the same findings are merged, not listed twice
        let (code, out, _) = headless(&format!(
            "--config {} --run-plan Nightly --target http://shop.test/account --project {}",
            cfg.display(),
            project.display()
        ));
        assert_eq!(code, Some(EXIT_OK));
        assert!(out.contains("2 reported, 0 new."), "the repeat was merged: {out}");
        let again = crate::project::read(&project.display().to_string()).expect("still a project");
        assert_eq!(again.imported_findings.len(), 2, "and the project still holds two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An `.xml` report path writes the XML report instead, from the same findings.
    #[cfg(unix)]
    #[test]
    fn a_report_path_ending_in_xml_writes_the_xml_report() {
        let dir = work_dir("xml-report");
        let cfg = dir.join("config");
        let mut survey = shell_tool(&dir, "survey", &format!("cat <<'DOC'\n{TWO_FINDINGS}\nDOC\n"), "");
        survey.import_findings = true;
        saved_settings(
            &cfg,
            vec![survey],
            vec![AutomationPlan { name: "Survey".into(), steps: vec![PipelineStep::default()], ..Default::default() }],
        );
        let report = dir.join("report.xml");
        let (code, out, err) = headless(&format!(
            "--config {} --run-plan Survey --target http://shop.test/ --report {}",
            cfg.display(),
            report.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        let xml = std::fs::read_to_string(&report).expect("the report was written");
        assert!(xml.starts_with("<?xml version=\"1.0\"?>"), "{xml}");
        assert!(xml.contains("<severity>Medium</severity>"), "{xml}");
        assert!(out.contains("Wrote the XML report"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--fail-on-findings` turns a clean run that reported something into exit code 2, and
    /// leaves one that reported nothing at 0.
    #[cfg(unix)]
    #[test]
    fn fail_on_findings_reports_through_the_exit_code_matrix() {
        let dir = work_dir("fail-on-findings");
        let cfg = dir.join("config");
        let quiet = shell_tool(&dir, "quiet", "echo '{\"findings\":[]}'\n", "");
        let mut noisy = shell_tool(&dir, "noisy", &format!("cat <<'DOC'\n{TWO_FINDINGS}\nDOC\n"), "");
        noisy.import_findings = true;
        let mut quiet = quiet;
        quiet.import_findings = true;
        saved_settings(
            &cfg,
            vec![quiet, noisy],
            vec![
                AutomationPlan { name: "Quiet".into(), steps: vec![PipelineStep { tool_index: 0, ..Default::default() }], ..Default::default() },
                AutomationPlan { name: "Noisy".into(), steps: vec![PipelineStep { tool_index: 1, ..Default::default() }], ..Default::default() },
            ],
        );
        let cases: [(&str, bool, Option<i32>); 4] = [
            ("Quiet", false, Some(EXIT_OK)),
            ("Quiet", true, Some(EXIT_OK)),
            ("Noisy", false, Some(EXIT_OK)),
            ("Noisy", true, Some(EXIT_FINDINGS)),
        ];
        assert_table!(cases, |idx, (name, strict, want)| {
            let flag = if strict { " --fail-on-findings" } else { "" };
            let (code, out, err) = headless(&format!(
                "--config {} --run-plan {name} --target http://shop.test/{flag}",
                cfg.display()
            ));
            assert_eq!(code, want, "case #{idx}: {name}{flag}\nout: {out}\nerr: {err}");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Everything an unattended run can refuse to do, and what it says about it.
    #[cfg(unix)]
    #[test]
    fn an_unattended_run_that_cannot_finish_ends_with_one_matrix() {
        let dir = work_dir("failures");
        let cfg = dir.join("config");
        let refuse = shell_tool(&dir, "refuse", "echo 'it would not start' >&2\nexit 3\n", "");
        let note = shell_tool(&dir, "note", "echo 'this one is fine'\n", "");
        saved_settings(
            &cfg,
            vec![refuse, note],
            vec![
                AutomationPlan { name: "Broken".into(), steps: vec![PipelineStep { tool_index: 0, ..Default::default() }], ..Default::default() },
                AutomationPlan {
                    name: "Broken then on".into(),
                    steps: vec![
                        PipelineStep { tool_index: 0, on_failure: StepFailurePolicy::Continue, ..Default::default() },
                        PipelineStep { tool_index: 1, ..Default::default() },
                    ],
                    ..Default::default()
                },
                AutomationPlan { name: "Fine".into(), steps: vec![PipelineStep { tool_index: 1, ..Default::default() }], ..Default::default() },
            ],
        );
        struct Case {
            name: &'static str,
            line: String,
            want: Option<i32>,
            says: &'static str,
            /// Is that said on the error stream rather than printed?
            on_err: bool,
        }
        let cases = [
            Case {
                name: "no pipeline of that name",
                line: format!("--config {} --run-plan Nothing --target http://shop.test/", cfg.display()),
                want: Some(EXIT_FAILED),
                says: "No pipeline is called",
                on_err: true,
            },
            Case {
                name: "no address to run it on",
                line: format!("--config {} --run-plan Fine", cfg.display()),
                want: Some(EXIT_FAILED),
                says: "needs --target",
                on_err: true,
            },
            Case {
                name: "a step that failed",
                line: format!("--config {} --run-plan Broken --target http://shop.test/", cfg.display()),
                want: Some(EXIT_FAILED),
                says: "Failed (exit status 3)",
                on_err: false,
            },
            Case {
                name: "a step that failed, carried on past",
                line: format!("--config {} --run-plan \"Broken then on\" --target http://shop.test/", cfg.display()),
                want: Some(EXIT_FAILED),
                says: "this one is fine",
                on_err: false,
            },
            Case {
                name: "a project that is not a project",
                line: format!(
                    "--config {} --run-plan Fine --target http://shop.test/ --project {}",
                    cfg.display(),
                    dir.join("refuse.sh").display()
                ),
                want: Some(EXIT_FAILED),
                says: "Not a project file",
                on_err: true,
            },
        ];
        assert_table!(cases, |idx, case| {
            // the pipeline whose name has a space in it is given as one argument
            let opts = match case.line.contains('"') {
                false => parse(line(&case.line)).expect("it reads"),
                true => {
                    let mut o = parse(line(&case.line.replace("\"Broken then on\"", "placeholder"))).expect("it reads");
                    o.run_plan = Some("Broken then on".to_string());
                    o
                }
            };
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(&opts, &mut out, &mut err);
            let (out, err) = (String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned());
            assert_eq!(code, case.want, "case #{idx} ({}):\nout: {out}\nerr: {err}", case.name);
            let looked_in = if case.on_err { &err } else { &out };
            assert!(
                looked_in.contains(case.says),
                "case #{idx} ({}): expected {:?}\nout: {out}\nerr: {err}",
                case.name,
                case.says
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The flags that came with bundles and variables read the same both ways round, and
    /// `--var` may be given more than once.
    #[test]
    fn the_bundle_and_variable_flags_read_both_ways_round() {
        for (apart, joined) in [
            ("--run-file /tmp/b.json", "--run-file=/tmp/b.json"),
            ("--tool Survey", "--tool=Survey"),
            ("--req /tmp/req.txt", "--req=/tmp/req.txt"),
            ("--res /tmp/res.txt", "--res=/tmp/res.txt"),
            ("--import /tmp/b.json", "--import=/tmp/b.json"),
            ("--on-conflict replace", "--on-conflict=replace"),
            ("--export Nightly", "--export=Nightly"),
            ("--out /tmp/b.json", "--out=/tmp/b.json"),
            ("--var KEY=VALUE", "--var=KEY=VALUE"),
        ] {
            assert_eq!(parsed(apart), parsed(joined), "{apart:?} and {joined:?} read the same");
        }
        let o = parsed("--run-file /tmp/b.json --tool Survey --req /tmp/q --res /tmp/s --export-all --out /tmp/o.json");
        assert_eq!(o.run_file.as_deref(), Some(Path::new("/tmp/b.json")));
        assert_eq!(o.tool.as_deref(), Some("Survey"));
        assert_eq!(o.req.as_deref(), Some(Path::new("/tmp/q")));
        assert_eq!(o.res.as_deref(), Some(Path::new("/tmp/s")));
        assert!(o.export_all);
        assert_eq!(o.out.as_deref(), Some(Path::new("/tmp/o.json")));

        // --var carries a value with anything in it, equals signs included, and stacks up
        let o = parsed("--var ONE=first --var TWO=a=b --var THREE=");
        assert_eq!(o.vars.get("ONE").map(String::as_str), Some("first"));
        assert_eq!(o.vars.get("TWO").map(String::as_str), Some("a=b"), "only the first equals sign separates");
        assert_eq!(o.vars.get("THREE").map(String::as_str), Some(""), "and a key may be given as nothing");
        assert_eq!(o.vars.len(), 3);
        // the later of two for the same key wins, as an assignment does
        assert_eq!(parsed("--var K=one --var K=two").vars.get("K").map(String::as_str), Some("two"));

        // how a name already registered is settled, and its default
        assert_eq!(parsed("--on-conflict skip").conflict_policy(), crate::tooling::ConflictPolicy::Skip);
        assert_eq!(parsed("--on-conflict rename").conflict_policy(), crate::tooling::ConflictPolicy::KeepBoth);
        assert_eq!(parsed("--import /tmp/b.json").conflict_policy(), crate::tooling::ConflictPolicy::KeepBoth);

        // and what these can get wrong
        for (text, want) in [
            ("--var", "needs KEY=VALUE"),
            ("--var NOEQUALS", "no equals sign"),
            ("--var =value", "names no key"),
            ("--on-conflict sideways", "not one of rename, replace or skip"),
            ("--export-all=yes", "takes no value"),
            ("--run-file", "needs a bundle path"),
        ] {
            let got = refused(text);
            assert!(got.contains(want), "{text:?} should mention {want:?}, said {got:?}");
        }
        // every flag the usage text advertises is one the parser knows
        for word in USAGE.split_whitespace().filter(|w| w.starts_with("--") && w.len() > 2) {
            let flag = word.trim_end_matches(|c: char| !c.is_alphanumeric());
            let e = parse(vec![flag.to_string()]).err().unwrap_or_default();
            assert!(!e.contains("is not a flag"), "{flag:?} is in the usage text but not in the parser");
        }
    }

    /// A bundle exported from one registry runs on a workstation with nothing registered at
    /// all, straight out of the file: the programs it carries are enough.
    #[cfg(unix)]
    #[test]
    fn a_bundle_is_exported_and_then_run_from_the_file_it_was_written_to() {
        let dir = work_dir("bundle-round-trip");
        let (theirs, mine) = (dir.join("theirs"), dir.join("mine"));
        let note = shell_tool(&dir, "note", "echo \"step one saw $1\"\n", "{url}");
        let mut survey = shell_tool(&dir, "survey", &format!("cat <<'DOC'\n{TWO_FINDINGS}\nDOC\n"), "");
        survey.import_findings = true;
        // their registry: two programs, a pipeline over both, and one program it never runs
        saved_settings(
            &theirs,
            vec![note.clone(), survey.clone(), shell_tool(&dir, "unrelated", "true\n", "")],
            vec![AutomationPlan {
                name: "Nightly".into(),
                description: "Looks, then reports.".into(),
                steps: vec![
                    PipelineStep { tool_name: "note".into(), ..Default::default() },
                    PipelineStep { tool_name: "survey".into(), ..Default::default() },
                ],
            }],
        );

        // exported by name, with the programs its steps run and nothing else
        let bundle_path = dir.join("nightly.json");
        let (code, out, err) = headless(&format!(
            "--config {} --export Nightly --out {}",
            theirs.display(),
            bundle_path.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("Wrote 2 programs and 1 pipeline"), "{out}");
        let written = std::fs::read_to_string(&bundle_path).expect("the bundle");
        assert!(written.contains("\"name\": \"Nightly\""), "{written}");
        assert!(!written.contains("unrelated"), "only what the steps run: {written}");

        // and run from the file, against a config directory with nothing registered in it
        let project = dir.join("triage.forge");
        let (code, out, err) = headless(&format!(
            "--config {} --run-file {} --target http://shop.test/account --project {}",
            mine.display(),
            bundle_path.display(),
            project.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("2 programs carried, 0 registered"), "{out}");
        assert!(out.contains("step one saw http://shop.test/account"), "the carried program ran: {out}");
        assert!(out.contains("2 reported, 2 new."), "{out}");
        let saved = crate::project::read(&project.display().to_string()).expect("the project");
        assert_eq!(saved.imported_findings.len(), 2);
        // nothing was registered by running it
        let after = crate::state::UserSettings::load(&mine).expect("still readable");
        assert!(after.external_tools.is_empty() && after.automation_plans.is_empty(), "a run registers nothing");

        // the same bundle imported, and then the pipeline run by name from the registry
        let (code, out, err) = headless(&format!("--config {} --import {}", mine.display(), bundle_path.display()));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("Program \"note\": added"), "{out}");
        assert!(out.contains("Pipeline \"Nightly\": added"), "{out}");
        assert!(out.contains("3 of 3 registered in"), "{out}");
        let after = crate::state::UserSettings::load(&mine).expect("the settings were written");
        assert_eq!(after.external_tools.len(), 2);
        assert_eq!(after.automation_plans.len(), 1);
        assert_eq!(after.automation_plans[0].description, "Looks, then reports.", "the words came with it");
        let (code, out, err) = headless(&format!(
            "--config {} --run-plan Nightly --target http://shop.test/",
            mine.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("step one saw http://shop.test/"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--export-all` writes the whole registry, and importing it a second time settles the
    /// names already there the way `--on-conflict` says.
    #[cfg(unix)]
    #[test]
    fn export_all_writes_the_registry_and_on_conflict_settles_a_second_import_matrix() {
        let dir = work_dir("export-all");
        let cfg = dir.join("config");
        let note = shell_tool(&dir, "note", "echo first\n", "");
        saved_settings(
            &cfg,
            vec![note],
            vec![AutomationPlan {
                name: "Nightly".into(),
                steps: vec![PipelineStep { tool_name: "note".into(), ..Default::default() }],
                ..Default::default()
            }],
        );
        let whole = dir.join("all.json");
        let (code, out, err) = headless(&format!("--config {} --export-all --out {}", cfg.display(), whole.display()));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("Wrote 1 program and 1 pipeline"), "{out}");

        let cases: [(&str, usize, usize, &str); 3] = [
            ("rename", 2, 2, "already taken, registered as"),
            ("replace", 1, 1, "replaced the one already registered"),
            ("skip", 1, 1, "skipped: already registered"),
        ];
        assert_table!(cases, |idx, (word, tools, plans, says)| {
            // a fresh copy of the registry each time, so the cases do not build on each other
            let into = dir.join(format!("into-{word}"));
            let _ = std::fs::remove_dir_all(&into);
            std::fs::create_dir_all(&into).expect("a place to work");
            std::fs::copy(cfg.join(crate::state::SETTINGS_FILE), into.join(crate::state::SETTINGS_FILE))
                .expect("the settings");
            let (code, out, err) = headless(&format!(
                "--config {} --import {} --on-conflict {word}",
                into.display(),
                whole.display()
            ));
            assert_eq!(code, Some(EXIT_OK), "case #{idx} ({word}): out: {out}\nerr: {err}");
            assert!(out.contains(says), "case #{idx} ({word}): {out}");
            let after = crate::state::UserSettings::load(&into).expect("readable");
            assert_eq!(after.external_tools.len(), tools, "case #{idx} ({word}): programs");
            assert_eq!(after.automation_plans.len(), plans, "case #{idx} ({word}): pipelines");
            // whatever happened, every step still runs a program that is there
            for plan in &after.automation_plans {
                for step in &plan.steps {
                    assert!(
                        step.resolve(&after.external_tools).is_some(),
                        "case #{idx} ({word}): {:?} runs nothing",
                        step.display_target()
                    );
                }
            }
        });

        // --export needs somewhere to write, and says so
        let e = headless(&format!("--config {} --export-all", cfg.display())).2;
        assert!(e.contains("needs --out"), "{e}");
        // and a name that is neither a pipeline nor a program says both
        let e = headless(&format!("--config {} --export Nothing --out {}", cfg.display(), whole.display())).2;
        assert!(e.contains("No pipeline is called") && e.contains("No program is called"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--tool` runs one registered program, given the request and the response from files and
    /// a value for a template variable.
    #[cfg(unix)]
    #[test]
    fn a_single_program_runs_with_the_files_and_values_it_was_given() {
        let dir = work_dir("single-tool");
        let cfg = dir.join("config");
        // it reads the request file it was handed, and echoes the value it was given
        let mut survey = shell_tool(
            &dir,
            "survey",
            "echo \"token=$1\"\nhead -n 1 \"$2\"\nhead -n 1 \"$3\"\n",
            "{var:TOKEN} {req_file} {res_file}",
        );
        survey.stdin_mode = crate::tooling::ToolStdinMode::RawRequest;
        // and one entry too unfinished to run: a name, but no program named
        let unfinished = ExternalTool { name: "unfinished".into(), ..Default::default() };
        saved_settings(&cfg, vec![survey, unfinished], Vec::new());
        let req = dir.join("request.txt");
        let res = dir.join("response.txt");
        std::fs::write(&req, "GET /account HTTP/1.1\r\nHost: shop.test\r\n\r\n").expect("a request");
        std::fs::write(&res, "HTTP/1.1 200 OK\r\n\r\nok").expect("a response");

        let (code, out, err) = headless(&format!(
            "--config {} --tool survey --target http://shop.test/account --req {} --res {} --var TOKEN=a-b-c",
            cfg.display(),
            req.display(),
            res.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("survey on http://shop.test/account."), "{out}");
        assert!(out.contains("Values given for {var:TOKEN}."), "it says what it was given: {out}");
        assert!(out.contains("token=a-b-c"), "the value reached the template: {out}");
        assert!(out.contains("GET /account HTTP/1.1"), "{{req_file}} held the request: {out}");
        assert!(out.contains("HTTP/1.1 200 OK"), "{{res_file}} held the response: {out}");
        assert!(out.contains("0 reported, 0 new."), "{out}");

        // a program not registered, one that cannot run, and a file that is not there
        let cases: [(String, &str); 3] = [
            (format!("--config {} --tool nothing --target http://shop.test/", cfg.display()), "No program is called"),
            (
                format!("--config {} --tool unfinished --target http://shop.test/", cfg.display()),
                "cannot be run",
            ),
            (
                format!(
                    "--config {} --tool survey --target http://shop.test/ --req {}",
                    cfg.display(),
                    dir.join("not-there.txt").display()
                ),
                "Couldn't read the request",
            ),
        ];
        assert_table!(cases, |idx, (text, says)| {
            let (code, out, err) = headless(&text);
            assert_eq!(code, Some(EXIT_FAILED), "case #{idx}: out: {out}\nerr: {err}");
            assert!(err.contains(says), "case #{idx}: wanted {says:?}, said {err:?}");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bundle holding more than one pipeline is not picked between, and `--run-plan` beside
    /// `--run-file` names which one is meant.
    #[cfg(unix)]
    #[test]
    fn a_bundle_of_several_pipelines_is_run_by_name() {
        let dir = work_dir("several-pipelines");
        let cfg = dir.join("config");
        let first = shell_tool(&dir, "first", "echo 'the first one'\n", "");
        let second = shell_tool(&dir, "second", "echo 'the second one'\n", "");
        let bundle = crate::tooling::AutomationBundle {
            format_version: crate::tooling::BUNDLE_FORMAT_VERSION,
            name: "Two of them".into(),
            tools: vec![first, second],
            plans: vec![
                AutomationPlan {
                    name: "One".into(),
                    steps: vec![PipelineStep { tool_name: "first".into(), ..Default::default() }],
                    ..Default::default()
                },
                AutomationPlan {
                    name: "Two".into(),
                    steps: vec![PipelineStep { tool_name: "second".into(), ..Default::default() }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let path = dir.join("two.json");
        crate::tooling::write_bundle(&bundle, &path).expect("the bundle");

        // without a name it will not choose for you, and says what there is
        let (code, _, err) = headless(&format!(
            "--config {} --run-file {} --target http://shop.test/",
            cfg.display(),
            path.display()
        ));
        assert_eq!(code, Some(EXIT_FAILED));
        assert!(err.contains("more than one pipeline") && err.contains("One") && err.contains("Two"), "{err}");

        // with one, that is the one that runs
        let (code, out, err) = headless(&format!(
            "--config {} --run-file {} --run-plan two --target http://shop.test/",
            cfg.display(),
            path.display()
        ));
        assert_eq!(code, Some(EXIT_OK), "out: {out}\nerr: {err}");
        assert!(out.contains("the second one") && !out.contains("the first one"), "{out}");

        // a name that is in no pipeline of the bundle's
        let (code, _, err) = headless(&format!(
            "--config {} --run-file {} --run-plan three --target http://shop.test/",
            cfg.display(),
            path.display()
        ));
        assert_eq!(code, Some(EXIT_FAILED));
        assert!(err.contains("holds no such pipeline"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--list-plans` prints each saved pipeline with how many steps it has, and says so
    /// plainly when there are none.
    #[cfg(unix)]
    #[test]
    fn list_plans_prints_each_pipeline_with_its_steps() {
        let dir = work_dir("list-plans");
        let cfg = dir.join("config");
        // nothing saved yet
        let (code, out, _) = headless(&format!("--config {} --list-plans", cfg.display()));
        assert_eq!(code, Some(EXIT_OK));
        assert!(out.contains("No pipelines are saved in"), "{out}");
        assert!(out.contains("settings.json"), "and says where it looked: {out}");

        saved_settings(&cfg, Vec::new(), vec![plan("Nightly sweep", 2), plan("Header survey", 1)]);
        let (code, out, err) = headless(&format!("--config {} --list-plans", cfg.display()));
        assert_eq!(code, Some(EXIT_OK), "err: {err}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines, ["Nightly sweep\t2 steps", "Header survey\t1 step"], "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
