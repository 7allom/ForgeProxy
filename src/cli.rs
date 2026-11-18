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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
  forgeproxy [<subcommand>] [options] [<project.forge>]

Subcommands (each takes --help of its own):
  scan       Crawl and audit a URL for issues.
  intruder   Replay a request with a wordlist in its marked positions.
  repeat     Send one raw request and show the response.
  proxy      Run the intercepting proxy with no window, into a project.
  sequence   Measure the randomness of a set of tokens.
  decode     Run text through a chain of decoder transforms.

With no subcommand, the flags below open the app or run an automation, as before:

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

// ======================================================================
// Subcommands: the core engines, each runnable with no window.
//
// A subcommand is the first argument when it names one of the engines below; everything after
// it is that engine's own flags. With no subcommand the flat flags above still do exactly what
// they did, so nothing that worked before this stops working.
// ======================================================================

/// The subcommand names this build knows.
pub const SUBCOMMANDS: [&str; 6] = ["scan", "intruder", "repeat", "proxy", "sequence", "decode"];

/// The subcommand `args` names, if its first argument is one. The caller runs it with
/// [`run_subcommand`]; a first argument that is a flag or a bare path is not a subcommand, so
/// the flat flags take it instead.
pub fn subcommand_of(args: &[String]) -> Option<&str> {
    args.first().and_then(|a| SUBCOMMANDS.into_iter().find(|s| s == a))
}

/// Run the subcommand `args` names, or return `None` when it names none (so the flat flags
/// run instead). The config directory, when one is given, is set before the engine reads any
/// settings, exactly as it is for the flat flags.
pub fn run_subcommand(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> Option<i32> {
    let name = subcommand_of(args)?;
    let rest = &args[1..];
    // --config on a subcommand points settings.json the same way --config does at the top
    if let Some(dir) = sub_config_dir(rest) {
        std::env::set_var("FORGEPROXY_CONFIG_DIR", dir);
    }
    let code = match name {
        "scan" => sub_scan(rest, out, err),
        "intruder" => sub_intruder(rest, out, err),
        "repeat" => sub_repeat(rest, out, err),
        "proxy" => sub_proxy(rest, out, err),
        "sequence" => sub_sequence(rest, out, err),
        "decode" => sub_decode(rest, out, err),
        _ => unreachable!("subcommand_of only returns a known name"),
    };
    Some(code)
}

/// The `--config` value among a subcommand's arguments, read on its own so it can be set
/// before the engine starts. Either form of the flag is accepted.
fn sub_config_dir(argv: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(v) = a.strip_prefix("--config=") {
            return (!v.is_empty()).then(|| PathBuf::from(v));
        }
        if a == "--config" {
            return argv.get(i + 1).filter(|v| !v.starts_with("--")).map(PathBuf::from);
        }
        i += 1;
    }
    None
}

/// A subcommand's arguments, read once: valued flags, boolean flags, repeatable valued flags,
/// and the bare arguments. An unknown flag or a missing value is refused, with a line saying
/// which. Flag names are given with their `--` so error messages read as the user typed them.
#[derive(Default)]
struct SubArgs {
    values: std::collections::HashMap<String, String>,
    multi: std::collections::HashMap<String, Vec<String>>,
    flags: std::collections::HashSet<String>,
    positionals: Vec<String>,
    help: bool,
}

impl SubArgs {
    fn parse(argv: &[String], valued: &[&str], boolean: &[&str], repeatable: &[&str]) -> Result<Self, String> {
        let mut me = SubArgs::default();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            if arg == "-h" || arg == "--help" {
                me.help = true;
                i += 1;
                continue;
            }
            if !arg.starts_with("--") {
                me.positionals.push(arg.clone());
                i += 1;
                continue;
            }
            let (name, inline) = match arg.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (arg.clone(), None),
            };
            let takes_value = valued.contains(&name.as_str()) || repeatable.contains(&name.as_str());
            if takes_value {
                let val = match inline {
                    Some(v) => v,
                    None => match argv.get(i + 1).filter(|v| !v.starts_with("--")) {
                        Some(v) => {
                            i += 1;
                            v.clone()
                        }
                        None => return Err(needs_value(&name, "a value")),
                    },
                };
                if repeatable.contains(&name.as_str()) {
                    me.multi.entry(name).or_default().push(val);
                } else {
                    me.values.insert(name, val);
                }
            } else if boolean.contains(&name.as_str()) {
                if inline.is_some() {
                    return Err(format!("{name} takes no value."));
                }
                me.flags.insert(name);
            } else {
                return Err(format!("{name} is not a flag this subcommand knows."));
            }
            i += 1;
        }
        Ok(me)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
    fn has(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
    /// A `usize` flag, or the fallback when it was not given; `Err` when it was given as
    /// something that is not a number.
    fn number(&self, name: &str, fallback: usize) -> Result<usize, String> {
        match self.value(name) {
            None => Ok(fallback),
            Some(v) => v.trim().parse().map_err(|_| format!("{name} wants a whole number, not {v:?}.")),
        }
    }
}

/// Read a raw request file, saying plainly when it cannot be read.
fn read_text_file(path: &str, what: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Couldn't read the {what} from {path}: {e}"))
}

/// Read a raw request from a file, with its line endings brought to `\n`.
///
/// The request parser and the section-sign markers both read `\n`, as the editor holds a
/// request; a file saved with `\r\n` would otherwise leave the head and body joined (the
/// blank line between them is not seen) and the body lost.
fn read_request_file(path: &str) -> Result<String, String> {
    read_text_file(path, "request").map(|t| t.replace("\r\n", "\n"))
}

/// The origin (`scheme://host[:port]`) a raw request is sent to: the one `--target` names, or
/// the one the request's own Host header implies over plain HTTP.
fn request_origin(raw: &str, target: Option<&str>) -> Result<String, String> {
    if let Some(t) = target.map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(crate::actions::origin_of(t));
    }
    match crate::actions::host_header(raw) {
        Some(host) => Ok(format!("http://{}", host.trim())),
        None => Err("No --target was given and the request has no Host header to take one from.".to_string()),
    }
}

/// The full URL a raw request is sent to: its origin and the path on its request line.
fn request_url(raw: &str, target: Option<&str>) -> Result<String, String> {
    let origin = request_origin(raw, target)?;
    let (_, path, _, _) = crate::actions::parse_raw_request(raw);
    let path = if path.starts_with('/') { path } else { format!("/{path}") };
    Ok(format!("{origin}{path}"))
}

/// A project to keep a run's traffic in: the one at `path` when it is there, else a new one.
fn open_or_new_project(path: &str, name: &str) -> Result<crate::project::ProjectFile, String> {
    if Path::new(path).exists() {
        crate::project::read(path)
    } else {
        Ok(crate::project::ProjectFile::fresh(name))
    }
}

/// Add captured exchanges to a project, numbering them after the ones already in it.
fn append_history(file: &mut crate::project::ProjectFile, entries: Vec<crate::http::HttpEntry>) {
    let mut next = file.history.iter().map(|e| e.id).max().unwrap_or(0);
    for mut e in entries {
        next += 1;
        e.id = next;
        file.history.push(e);
    }
}

/// One exchange as a history entry, for keeping in a project.
fn entry_of(tool: &str, method: &str, url: &str, request: String, r: &crate::http::SendResult) -> crate::http::HttpEntry {
    let (host, path) = crate::http::split_url(url);
    crate::http::HttpEntry {
        id: 0,
        tool: tool.into(),
        method: method.into(),
        host,
        path,
        status: r.status.clone(),
        length: r.length,
        mime: r.mime.clone(),
        request,
        response: r.raw_response(),
        url: url.to_string(),
        truncated: false,
        time: crate::http::now_ms(),
        elapsed_ms: 0,
    }
}

// ---- scan ----------------------------------------------------------------

const SCAN_USAGE: &str = "\
forgeproxy scan <url> [options]

Crawl and audit a URL, and report the issues found.

Options:
  --crawl                Follow same-site links, not just the one page.
  --depth <n>            How far to follow links when crawling (default 4).
  --max-pages <n>        Stop after this many pages (default 1500).
  --project <path>       Keep the findings and the traffic in this .forge file.
  --report <path>        Write the issues to this file (.xml for XML, else HTML).
  --fail-on-findings     Exit 2 when the scan reports one issue or more.
  --json                 Print the findings as JSON instead of a table.
  --interactor <server>  Interactor relay for out-of-band (blind) checks. Defaults to the one
                         set in settings.json.
  --interactor-token <t> Authorization token for a relay that requires one.
  --oast-settle-ms <n>   Wait this long after the out-of-band probes before polling the relay
                         (default 2000).
  --config <dir>         Read settings.json from here.
";

fn sub_scan(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let parsed = match SubArgs::parse(
        argv,
        &["--depth", "--max-pages", "--project", "--report", "--config", "--interactor", "--interactor-token", "--oast-settle-ms"],
        &["--crawl", "--fail-on-findings", "--json"],
        &[],
    ) {
        Ok(p) => p,
        Err(e) => return refuse(err, &e),
    };
    if parsed.help {
        let _ = write!(out, "{SCAN_USAGE}");
        return EXIT_OK;
    }
    let Some(url) = parsed.positionals.first() else {
        let _ = writeln!(err, "scan needs a URL: forgeproxy scan <url>.");
        return EXIT_FAILED;
    };
    let limits = crate::scan::ScanLimits {
        depth: match parsed.number("--depth", crate::scan::ScanLimits::default().depth) {
            Ok(n) => n,
            Err(e) => return refuse(err, &e),
        },
        max_pages: match parsed.number("--max-pages", crate::scan::ScanLimits::default().max_pages) {
            Ok(n) => n.max(1),
            Err(e) => return refuse(err, &e),
        },
        oast_settle: match parsed.number("--oast-settle-ms", crate::scan::ScanLimits::default().oast_settle.as_millis() as usize) {
            Ok(n) => std::time::Duration::from_millis(n as u64),
            Err(e) => return refuse(err, &e),
        },
    };
    let settings = settings_of_config(&parsed, err);
    let opts = settings.send_options();
    let crawl = parsed.has("--crawl");
    // An Interactor relay from the flag, else the one settings name; absent means no out-of-band
    // probing at all.
    let relay = parsed.value("--interactor").map(str::to_string).unwrap_or_else(|| settings.interactor_default_server.clone());
    let token = parsed.value("--interactor-token").unwrap_or("");
    let oast = crate::scan::ScanInteractor::configure(&relay, token);
    if oast.is_some() {
        let _ = writeln!(err, "Out-of-band checks via {}...", crate::interactor::server_host(&relay));
    }
    let _ = writeln!(err, "{} {url}...", if crawl { "Crawling and auditing" } else { "Auditing" });
    let outcome = crate::scan::run_scan(url, crawl, limits, oast, &opts, &mut |line| {
        let _ = writeln!(err, "  {line}");
    });

    if parsed.has("--json") {
        let _ = writeln!(out, "{}", findings_json(&outcome.findings));
    } else {
        print_findings(out, &outcome.findings);
    }

    if let Some(path) = parsed.value("--project") {
        let mut file = match open_or_new_project(path, url) {
            Ok(f) => f,
            Err(e) => return refuse(err, &e),
        };
        let mut all = file.imported_findings.clone();
        all.extend(outcome.findings.iter().cloned());
        file.imported_findings = crate::scan::consolidate(all);
        append_history(&mut file, outcome.history);
        if let Err(e) = crate::project::write(&file, path) {
            return refuse(err, &format!("Couldn't save {path}: {e}"));
        }
        let _ = writeln!(err, "Saved {path}.");
    }
    if let Some(path) = parsed.value("--report") {
        match crate::export::write_report(&outcome.findings, Path::new(path)) {
            Ok(fmt) => {
                let _ = writeln!(err, "Wrote the {} report to {path}.", fmt.extension().to_ascii_uppercase());
            }
            Err(e) => return refuse(err, &format!("Couldn't write {path}: {e}")),
        }
    }

    if parsed.has("--fail-on-findings") && !outcome.findings.is_empty() {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    }
}

/// The findings, as a plain table on stdout.
fn print_findings(out: &mut dyn Write, findings: &[crate::scan::Finding]) {
    if findings.is_empty() {
        let _ = writeln!(out, "No issues found.");
        return;
    }
    for f in findings {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}{}",
            f.severity.label(),
            f.confidence.label(),
            f.name,
            f.host,
            f.path
        );
    }
    let _ = writeln!(out, "{} {} found.", findings.len(), if findings.len() == 1 { "issue" } else { "issues" });
}

/// The findings as a JSON array.
fn findings_json(findings: &[crate::scan::Finding]) -> String {
    let items: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "severity": f.severity.label(),
                "confidence": f.confidence.label(),
                "name": f.name,
                "host": f.host,
                "path": f.path,
                "type_index": f.type_index,
                "detail": f.detail,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "findings": items })).unwrap_or_else(|_| "{}".into())
}

// ---- repeat --------------------------------------------------------------

const REPEAT_USAGE: &str = "\
forgeproxy repeat --req <file> [options]

Send one raw HTTP request and show the response.

Options:
  --req <path>           The file holding the raw request to send. Required.
  --target <url>         Where to send it; its path comes from the request line. Without
                         this the request's Host header is used, over plain HTTP.
  --follow-redirects     Follow 3xx responses to where they point.
  --project <path>       Apply the project's Match & Replace rules, and keep the exchange in it.
  --json                 Print a JSON envelope instead of the raw response.
  --config <dir>         Read settings.json from here.
";

fn sub_repeat(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let parsed = match SubArgs::parse(
        argv,
        &["--req", "--target", "--project", "--config"],
        &["--follow-redirects", "--json"],
        &[],
    ) {
        Ok(p) => p,
        Err(e) => return refuse(err, &e),
    };
    if parsed.help {
        let _ = write!(out, "{REPEAT_USAGE}");
        return EXIT_OK;
    }
    let Some(req_path) = parsed.value("--req") else {
        let _ = writeln!(err, "repeat needs --req <file>: the raw request to send.");
        return EXIT_FAILED;
    };
    let raw = match read_request_file(req_path) {
        Ok(t) => t,
        Err(e) => return refuse(err, &e),
    };
    let settings = settings_of_config(&parsed, err);

    // the project, when one is named, supplies the Match & Replace rules and keeps the exchange
    let mut project = match parsed.value("--project") {
        Some(path) => match open_or_new_project(path, "Repeater run") {
            Ok(f) => Some((path.to_string(), f)),
            Err(e) => return refuse(err, &e),
        },
        None => None,
    };
    // External command rules run only programs registered in this machine's settings
    let rules = crate::rewrite::resolve(
        &project.as_ref().map(|(_, f)| f.match_replace.clone()).unwrap_or_default(),
        &settings.external_tools,
    );

    // the request as it is sent, after any rewrite rules act on it
    let sent = crate::rewrite::apply_first_line_of(&rules, &raw);
    let (method, _, headers, body) = crate::actions::parse_raw_request(&sent);
    let htext = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n");
    let (htext, body) = crate::rewrite::apply(&rules, true, &htext, &body);
    let hv: Vec<(String, String)> = htext
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let url = match request_url(&sent, parsed.value("--target")) {
        Ok(u) => u,
        Err(e) => return refuse(err, &e),
    };

    let _ = writeln!(err, "{method} {url}");
    let started = std::time::Instant::now();
    let mut r = crate::http::send(&method, &url, &hv, &body, parsed.has("--follow-redirects"), true, &settings.send_options());
    let elapsed_ms = started.elapsed().as_millis();
    if !rules.is_empty() {
        let (rh, rb) = crate::rewrite::apply(&rules, false, &r.headers, &r.body);
        r.headers = rh;
        r.body = rb;
    }

    if parsed.has("--json") {
        let env = serde_json::json!({
            "status": r.status,
            "status_code": crate::http::status_code(&r.status),
            "length": r.length,
            "mime": r.mime,
            "elapsed_ms": elapsed_ms,
            "error": r.error,
            "response": r.raw_response(),
        });
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".into()));
    } else {
        let _ = writeln!(out, "{}", r.raw_response());
    }

    if let Some((path, file)) = project.as_mut() {
        append_history(file, vec![entry_of("Repeater", &method, &url, sent, &r)]);
        if let Err(e) = crate::project::write(file, path) {
            return refuse(err, &format!("Couldn't save {path}: {e}"));
        }
        let _ = writeln!(err, "Saved {path}.");
    }
    if r.error.is_some() {
        EXIT_FAILED
    } else {
        EXIT_OK
    }
}

// ---- intruder ------------------------------------------------------------

const INTRUDER_USAGE: &str = "\
forgeproxy intruder --req <file> --wordlist <file> [options]

Replay a request with each word of a wordlist in its marked positions. Mark a position by
wrapping it in section signs, like id=\u{00a7}1\u{00a7}.

Options:
  --req <path>           The raw request, with \u{00a7}\u{00a7} marks. Required.
  --wordlist <path>      One payload per line. Required.
  --target <url>         Where to send the requests. Without this the request's Host is used.
  --battering-ram        Put the same word in every position at once, rather than one at a time.
  --threads <n>          How many requests to keep in flight (default 10).
  --match-status <csv>   Keep only these status codes or classes (e.g. 200,3xx).
  --hide-length <csv>    Drop results whose length is one of these.
  --project <path>       Keep the exchanges in this .forge file.
  --json                 Print the results as JSON instead of a table.
  --config <dir>         Read settings.json from here.
";

fn sub_intruder(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let parsed = match SubArgs::parse(
        argv,
        &["--req", "--wordlist", "--target", "--threads", "--match-status", "--hide-length", "--project", "--config"],
        &["--battering-ram", "--json"],
        &[],
    ) {
        Ok(p) => p,
        Err(e) => return refuse(err, &e),
    };
    if parsed.help {
        let _ = write!(out, "{INTRUDER_USAGE}");
        return EXIT_OK;
    }
    let (Some(req_path), Some(list_path)) = (parsed.value("--req"), parsed.value("--wordlist")) else {
        let _ = writeln!(err, "intruder needs --req <file> and --wordlist <file>.");
        return EXIT_FAILED;
    };
    let template = match read_request_file(req_path) {
        Ok(t) => t,
        Err(e) => return refuse(err, &e),
    };
    if crate::intruder::count_positions(&template) == 0 {
        let _ = writeln!(err, "The request has no \u{00a7}\u{00a7} marks, so there is nothing to vary.");
        return EXIT_FAILED;
    }
    let words: Vec<String> = match read_text_file(list_path, "wordlist") {
        Ok(t) => t.lines().map(|l| l.to_string()).filter(|l| !l.is_empty()).collect(),
        Err(e) => return refuse(err, &e),
    };
    if words.is_empty() {
        let _ = writeln!(err, "The wordlist is empty.");
        return EXIT_FAILED;
    }
    let kind = if parsed.has("--battering-ram") {
        crate::intruder::AttackType::BatteringRam
    } else {
        crate::intruder::AttackType::Sniper
    };
    let threads = match parsed.number("--threads", 10) {
        Ok(n) => n.max(1),
        Err(e) => return refuse(err, &e),
    };
    let keep = match parse_status_filter(parsed.value("--match-status")) {
        Ok(f) => f,
        Err(e) => return refuse(err, &e),
    };
    let hide_len = match parse_len_filter(parsed.value("--hide-length")) {
        Ok(f) => f,
        Err(e) => return refuse(err, &e),
    };

    // the origin every request connects to, taken once from the target or the first request
    let origin = match request_origin(&template, parsed.value("--target")) {
        Ok(o) => o,
        Err(e) => return refuse(err, &e),
    };
    let settings = settings_of_config(&parsed, err);
    let plan = std::sync::Arc::new(crate::intruder::AttackPlan::new(kind, &template, &[words]));
    let total = plan.len();
    if total == 0 {
        let _ = writeln!(err, "These payloads produce no requests for this attack type.");
        return EXIT_FAILED;
    }
    let _ = writeln!(err, "{} requests against {origin}...", total);

    // one row per request, gathered off the worker threads and then put back in order
    let rows = std::sync::Arc::new(std::sync::Mutex::new(Vec::<IntruderRow>::new()));
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let opts = settings.send_options();
    let mut handles = Vec::new();
    for _ in 0..threads.min(total) {
        let (plan, rows, next, origin, opts) = (plan.clone(), rows.clone(), next.clone(), origin.clone(), opts.clone());
        handles.push(std::thread::spawn(move || loop {
            let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if i >= total {
                break;
            }
            let (payload, raw) = plan.request(i);
            let (method, path, _, body) = crate::actions::parse_raw_request(&raw);
            let headers = crate::intruder::dispatch_headers(&raw, false);
            let path = if path.starts_with('/') { path } else { format!("/{path}") };
            let full = format!("{origin}{path}");
            let started = std::time::Instant::now();
            let r = crate::http::send(&method, &full, &headers, &body, false, true, &opts);
            let elapsed_ms = started.elapsed().as_millis();
            rows.lock().unwrap_or_else(|e| e.into_inner()).push(IntruderRow {
                index: i + 1,
                payload,
                status: r.status.clone(),
                status_code: crate::http::status_code(&r.status),
                length: r.length,
                elapsed_ms,
                error: r.error.clone(),
                method,
                url: full,
                request: raw,
                result: r,
            });
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut rows = std::sync::Arc::try_unwrap(rows).map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner())).unwrap_or_default();
    rows.sort_by_key(|r| r.index);

    let shown: Vec<&IntruderRow> = rows
        .iter()
        .filter(|r| keep.as_ref().map_or(true, |f| f.allows(r.status_code)))
        .filter(|r| !hide_len.contains(&r.length))
        .collect();

    if parsed.has("--json") {
        let items: Vec<serde_json::Value> = shown
            .iter()
            .map(|r| {
                serde_json::json!({
                    "index": r.index,
                    "payload": r.payload,
                    "status": r.status,
                    "status_code": r.status_code,
                    "length": r.length,
                    "elapsed_ms": r.elapsed_ms,
                    "error": r.error,
                })
            })
            .collect();
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&serde_json::json!({ "results": items })).unwrap_or_else(|_| "{}".into()));
    } else {
        for r in &shown {
            let _ = writeln!(out, "{}\t{}\t{}\t{}\t{} ms", r.index, r.payload, r.status, r.length, r.elapsed_ms);
        }
        let _ = writeln!(err, "{} of {} results shown.", shown.len(), rows.len());
    }

    if let Some(path) = parsed.value("--project") {
        let mut file = match open_or_new_project(path, "Intruder run") {
            Ok(f) => f,
            Err(e) => return refuse(err, &e),
        };
        let entries = rows
            .iter()
            .map(|r| entry_of("Intruder", &r.method, &r.url, r.request.clone(), &r.result))
            .collect();
        append_history(&mut file, entries);
        if let Err(e) = crate::project::write(&file, path) {
            return refuse(err, &format!("Couldn't save {path}: {e}"));
        }
        let _ = writeln!(err, "Saved {path}.");
    }
    EXIT_OK
}

/// One finished Intruder request, before filtering.
struct IntruderRow {
    index: usize,
    payload: String,
    status: String,
    status_code: Option<u16>,
    length: usize,
    elapsed_ms: u128,
    error: Option<String>,
    method: String,
    url: String,
    request: String,
    result: crate::http::SendResult,
}

/// Which status codes a `--match-status` list keeps: exact codes and `Nxx` classes.
struct StatusFilter {
    codes: std::collections::HashSet<u16>,
    classes: std::collections::HashSet<u16>,
}

impl StatusFilter {
    fn allows(&self, code: Option<u16>) -> bool {
        match code {
            Some(c) => self.codes.contains(&c) || self.classes.contains(&(c / 100)),
            // a request that never answered is kept only when nothing specific was asked for
            None => self.codes.is_empty() && self.classes.is_empty(),
        }
    }
}

fn parse_status_filter(csv: Option<&str>) -> Result<Option<StatusFilter>, String> {
    let Some(csv) = csv else { return Ok(None) };
    let mut codes = std::collections::HashSet::new();
    let mut classes = std::collections::HashSet::new();
    for token in csv.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let lower = token.to_ascii_lowercase();
        if let Some(digit) = lower.strip_suffix("xx") {
            match digit.parse::<u16>() {
                Ok(n) if (1..=5).contains(&n) => {
                    classes.insert(n);
                }
                _ => return Err(format!("--match-status: {token:?} is not a status class like 2xx.")),
            }
        } else {
            match token.parse::<u16>() {
                Ok(n) => {
                    codes.insert(n);
                }
                Err(_) => return Err(format!("--match-status: {token:?} is not a status code.")),
            }
        }
    }
    Ok(Some(StatusFilter { codes, classes }))
}

fn parse_len_filter(csv: Option<&str>) -> Result<std::collections::HashSet<usize>, String> {
    let mut set = std::collections::HashSet::new();
    if let Some(csv) = csv {
        for token in csv.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match token.parse::<usize>() {
                Ok(n) => {
                    set.insert(n);
                }
                Err(_) => return Err(format!("--hide-length: {token:?} is not a length.")),
            }
        }
    }
    Ok(set)
}

// ---- proxy ---------------------------------------------------------------

const PROXY_USAGE: &str = "\
forgeproxy proxy --project <file> [options]

Run the intercepting proxy with no window, writing what it captures to a project.

Options:
  --project <path>       The .forge file the captured traffic is written to. Required.
  --bind <host>          The address to listen on (default from settings).
  --port <n>             The port to listen on (default from settings).
  --duration <secs>      Stop after this many seconds. Without it, runs until interrupted.

Ctrl+C or a termination request stops the listener, writes the project one last time and
exits 0. A snapshot is also written every couple of seconds in case the process is killed.
  --config <dir>         Read settings.json from here.
";

fn sub_proxy(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    sub_proxy_until(argv, out, err, None)
}

/// A flag that turns true when the process is asked to stop (Ctrl+C, or a termination
/// request), set up once per process; later calls hand back the same flag. When the handler
/// cannot be set up, the flag still works for `--duration` and the process can be ended as before.
fn interrupt_flag(err: &mut dyn Write) -> Arc<AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    let mut failure = None;
    let flag = FLAG.get_or_init(|| {
        let flag = Arc::new(AtomicBool::new(false));
        let raised = flag.clone();
        match ctrlc::set_handler(move || raised.store(true, Ordering::SeqCst)) {
            // something else in the process already listens for it; carry on without ours
            Ok(()) | Err(ctrlc::Error::MultipleHandlers) => {}
            Err(e) => failure = Some(e.to_string()),
        }
        flag
    });
    if let Some(e) = failure {
        let _ = writeln!(err, "Couldn't listen for Ctrl+C ({e}); ending the process still keeps the last snapshot.");
    }
    flag.clone()
}

/// How long a stopping proxy waits for connections it already accepted to finish.
const PROXY_DRAIN: std::time::Duration = std::time::Duration::from_secs(3);
/// How often the headless proxy checks whether it should stop.
const PROXY_WAKE: std::time::Duration = std::time::Duration::from_millis(50);
/// How often the headless proxy writes a snapshot of the capture while it runs.
const PROXY_SNAPSHOT: std::time::Duration = std::time::Duration::from_secs(2);

/// The `proxy` subcommand, stopping when `shutdown` turns true or `--duration` runs out,
/// whichever comes first. Either way the listener is closed, open connections get a moment to
/// finish, and the project is written one last time. With `shutdown` left `None`, the
/// process-wide Ctrl+C flag is set up just before listening; tests pass a flag of their own.
fn sub_proxy_until(
    argv: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
    shutdown: Option<Arc<AtomicBool>>,
) -> i32 {
    let parsed = match SubArgs::parse(
        argv,
        &["--project", "--bind", "--port", "--duration", "--config"],
        &[],
        &[],
    ) {
        Ok(p) => p,
        Err(e) => return refuse(err, &e),
    };
    if parsed.help {
        let _ = write!(out, "{PROXY_USAGE}");
        return EXIT_OK;
    }
    let Some(project_path) = parsed.value("--project").map(str::to_string) else {
        let _ = writeln!(err, "proxy needs --project <file>: where the captured traffic is written.");
        return EXIT_FAILED;
    };
    let settings = settings_of_config(&parsed, err);
    let host = parsed.value("--bind").map(str::trim).filter(|h| !h.is_empty()).unwrap_or(settings.proxy_host.trim());
    let port = match parsed.value("--port") {
        None => settings.proxy_port.trim().to_string(),
        Some(v) => match v.trim().parse::<u16>().ok().filter(|p| *p > 0) {
            Some(p) => p.to_string(),
            None => return refuse(err, &format!("--port wants a number from 1 to 65535, not {v:?}.")),
        },
    };
    let duration = match parsed.value("--duration") {
        None => None,
        Some(v) => match v.trim().parse::<u64>() {
            Ok(s) => Some(std::time::Duration::from_secs(s)),
            Err(_) => return refuse(err, &format!("--duration wants a number of seconds, not {v:?}.")),
        },
    };

    // a store the listener records into and the flush reads out of
    let history: crate::http::History = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let next_id = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    // the project may already exist; its rules drive Match & Replace and its traffic is kept
    let mut file = match open_or_new_project(&project_path, "Proxy capture") {
        Ok(f) => f,
        Err(e) => return refuse(err, &e),
    };
    let rules = if file.match_replace.is_empty() { crate::rewrite::defaults() } else { file.match_replace.clone() };
    // External command rules run only programs registered in this machine's settings
    let rules = crate::rewrite::resolve(&rules, &settings.external_tools);
    let tls = load_ca_cache(&config_dir_of(&parsed));
    let shared = crate::proxy::Shared::headless(history.clone(), next_id.clone(), rules, &settings, tls);
    let addr = format!("{host}:{port}");
    let shutdown = match shutdown {
        Some(flag) => flag,
        None => interrupt_flag(err),
    };
    let listener = match crate::proxy::listen(shared, addr.clone()) {
        Ok(l) => l,
        Err(e) => return refuse(err, &e),
    };
    match &duration {
        Some(d) => {
            let _ = writeln!(err, "Listening on {addr} for {} s. Point a browser's proxy at it.", d.as_secs());
        }
        None => {
            let _ = writeln!(err, "Listening on {addr}. Press Ctrl+C to stop; progress is saved as it arrives.");
        }
    }

    // flush what has been captured into the project, so an ended process still leaves a file
    let flush = |file: &mut crate::project::ProjectFile| -> Result<usize, String> {
        let captured: Vec<crate::http::HttpEntry> =
            history.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|e| (**e).clone()).collect();
        let n = captured.len();
        file.history = captured;
        crate::project::write(file, &project_path).map(|()| n)
    };

    let started = std::time::Instant::now();
    let mut last_flush = started;
    let interrupted = loop {
        if shutdown.load(Ordering::SeqCst) {
            break true;
        }
        if duration.map_or(false, |d| started.elapsed() >= d) {
            break false;
        }
        // a snapshot every couple of seconds, so a process that is killed outright loses little
        if last_flush.elapsed() >= PROXY_SNAPSHOT {
            if let Err(e) = flush(&mut file) {
                let _ = writeln!(err, "Couldn't write a snapshot of {project_path}: {e}");
            }
            last_flush = std::time::Instant::now();
        }
        std::thread::sleep(PROXY_WAKE);
    };
    if interrupted {
        let _ = writeln!(err, "Stopping: closing the listener and saving the capture.");
    }
    // no new connections from here; the ones already open get a moment to record what they carry
    let still_open = listener.shutdown(PROXY_DRAIN);
    if still_open > 0 {
        let _ = writeln!(err, "{still_open} connection(s) still open after {} s; saving without them.", PROXY_DRAIN.as_secs());
    }
    match flush(&mut file) {
        Ok(n) => {
            let _ = writeln!(
                err,
                "Captured {n} {}; wrote {project_path} after {:.1} s.",
                if n == 1 { "request" } else { "requests" },
                started.elapsed().as_secs_f64()
            );
            EXIT_OK
        }
        Err(e) => refuse(err, &format!("Couldn't save {project_path}: {e}")),
    }
}

/// The root CA's per-host certificate cache, when a CA is set up, so the headless proxy can
/// open intercepted HTTPS. `None` when none is set up, which leaves HTTPS tunnelled unopened.
fn load_ca_cache(dir: &Path) -> Option<std::sync::Arc<crate::ca::TlsConfigCache>> {
    let ca = crate::ca::CertificateAuthority::load_saved(dir).ok()??;
    Some(std::sync::Arc::new(crate::ca::TlsConfigCache::new(std::sync::Arc::new(ca))))
}

// ---- sequence ------------------------------------------------------------

const SEQUENCE_USAGE: &str = "\
forgeproxy sequence (--file <tokens> | --url <url> --extract <what> --count <n>) [options]

Measure the randomness of a set of tokens.

Options:
  --file <path>          A file of tokens, one per line.
  --url <url>            Collect tokens by requesting this address repeatedly.
  --extract <what>       Where the token is in each response: a header name, or a regular
                         expression with one capture group.
  --count <n>            How many tokens to collect from --url.
  --json                 Print the analysis as JSON instead of a summary.
  --config <dir>         Read settings.json from here.
";

fn sub_sequence(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let parsed = match SubArgs::parse(
        argv,
        &["--file", "--url", "--extract", "--count", "--config"],
        &["--json"],
        &[],
    ) {
        Ok(p) => p,
        Err(e) => return refuse(err, &e),
    };
    if parsed.help {
        let _ = write!(out, "{SEQUENCE_USAGE}");
        return EXIT_OK;
    }
    let tokens: Vec<String> = if let Some(path) = parsed.value("--file") {
        match read_text_file(path, "tokens") {
            Ok(t) => crate::sequencer::tokens_from_text(&t),
            Err(e) => return refuse(err, &e),
        }
    } else if let Some(url) = parsed.value("--url") {
        let Some(extract) = parsed.value("--extract") else {
            let _ = writeln!(err, "sequence --url needs --extract <header-or-regex> to find the token.");
            return EXIT_FAILED;
        };
        let count = match parsed.number("--count", 0) {
            Ok(0) => {
                let _ = writeln!(err, "sequence --url needs --count <n>: how many tokens to collect.");
                return EXIT_FAILED;
            }
            Ok(n) => n,
            Err(e) => return refuse(err, &e),
        };
        match collect_tokens(url, extract, count, &settings_of_config(&parsed, err), err) {
            Ok(t) => t,
            Err(e) => return refuse(err, &e),
        }
    } else {
        let _ = writeln!(err, "sequence needs either --file <tokens> or --url with --extract and --count.");
        return EXIT_FAILED;
    };

    let Some(analysis) = crate::sequencer::analyze_tokens(&tokens) else {
        let _ = writeln!(err, "No tokens to analyse ({} collected).", tokens.len());
        return EXIT_FAILED;
    };
    if parsed.has("--json") {
        let effective: f64 = analysis.per_char_entropy.iter().sum();
        let env = serde_json::json!({
            "sample_count": analysis.sample_count,
            "min_len": analysis.min_len,
            "max_len": analysis.max_len,
            "entropy_bits_per_char": analysis.overall_entropy,
            "max_possible_bits_per_char": analysis.max_possible_entropy,
            "effective_entropy_bits": effective,
            "fips_monobit_passed": analysis.fips_monobit_passed,
            "fips_applicable": analysis.fips_applicable,
            "detected_format": format!("{:?}", analysis.detected_format),
        });
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".into()));
    } else {
        let _ = write!(out, "{}", crate::sequencer::analyse(&tokens));
    }
    EXIT_OK
}

/// Collect `count` tokens from `url`, pulling one out of each response by `extract` -- a header
/// name, or a regular expression (anything with a capture group) read against the whole
/// response.
fn collect_tokens(
    url: &str,
    extract: &str,
    count: usize,
    settings: &crate::state::UserSettings,
    err: &mut dyn Write,
) -> Result<Vec<String>, String> {
    let location = if extract.contains('(') {
        crate::sequencer::TokenLocation::Regex(extract.to_string())
    } else {
        crate::sequencer::TokenLocation::Header(extract.to_string())
    };
    let opts = settings.send_options();
    let mut tokens = Vec::new();
    for n in 0..count {
        let r = crate::http::send("GET", url, &[], "", false, true, &opts);
        if let Some(tok) = crate::sequencer::extract_token(&location, &r.raw_response()) {
            tokens.push(tok);
        }
        if (n + 1) % 25 == 0 || n + 1 == count {
            let _ = writeln!(err, "  collected {} of {count}...", tokens.len());
        }
    }
    if tokens.is_empty() {
        return Err(format!("No token matched {extract:?} in any of the {count} responses."));
    }
    Ok(tokens)
}

// ---- decode --------------------------------------------------------------

const DECODE_USAGE: &str = "\
forgeproxy decode <transforms> [options]

Run text through a comma-separated chain of transforms, left to right.

Transforms: for each of url, html, base64, base64url, ascii-hex, hex, octal, binary, gzip
there is a <name>-encode and a <name>-decode; and jwt-decode reads a JWT as JSON. For example:
  url-decode,base64-decode,jwt-decode
  gzip-encode,base64-encode,url-encode

Options:
  --input <text>         The text to transform. Without --input or --file, reads stdin.
  --file <path>          Read the input from this file instead.
  --json                 Wrap the result in a JSON envelope.
";

fn sub_decode(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let parsed = match SubArgs::parse(argv, &["--input", "--file"], &["--json"], &[]) {
        Ok(p) => p,
        Err(e) => return refuse(err, &e),
    };
    if parsed.help {
        let _ = write!(out, "{DECODE_USAGE}");
        return EXIT_OK;
    }
    let Some(chain) = parsed.positionals.first() else {
        let _ = writeln!(err, "decode needs a transform chain: forgeproxy decode url-decode,base64-decode.");
        return EXIT_FAILED;
    };
    let transforms = match parse_transforms(chain) {
        Ok(t) => t,
        Err(e) => return refuse(err, &e),
    };
    let input: Vec<u8> = if let Some(text) = parsed.value("--input") {
        text.as_bytes().to_vec()
    } else if let Some(path) = parsed.value("--file") {
        match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return refuse(err, &format!("Couldn't read {path}: {e}")),
        }
    } else {
        let mut buf = Vec::new();
        if let Err(e) = std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf) {
            return refuse(err, &format!("Couldn't read the input: {e}"));
        }
        buf
    };

    let data = match run_chain(&transforms, input) {
        Ok(d) => d,
        Err(e) => return refuse(err, &e),
    };

    if parsed.has("--json") {
        let env = serde_json::json!({
            "transforms": transforms.iter().map(|t| t.name()).collect::<Vec<_>>(),
            "output": String::from_utf8_lossy(&data),
            "output_base64": crate::codec::base64_encode(&data, false, true),
        });
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".into()));
    } else {
        let _ = out.write_all(&data);
    }
    EXIT_OK
}

/// One step of a decode chain.
#[derive(Clone, Copy)]
enum Transform {
    /// A codec, run forwards (encode) or backwards (decode).
    Codec(crate::decoder_ops::Codec, bool),
    /// A JWT read into its header and payload JSON.
    JwtDecode,
}

impl Transform {
    fn name(self) -> String {
        match self {
            Transform::Codec(c, encode) => format!("{}-{}", codec_slug(c), if encode { "encode" } else { "decode" }),
            Transform::JwtDecode => "jwt-decode".to_string(),
        }
    }
}

/// The command-line slug for a codec: its label, lowered, with the spaces gone.
fn codec_slug(c: crate::decoder_ops::Codec) -> &'static str {
    use crate::decoder_ops::Codec;
    match c {
        Codec::Url => "url",
        Codec::Html => "html",
        Codec::Base64 => "base64",
        Codec::Base64Url => "base64url",
        Codec::AsciiHex => "ascii-hex",
        Codec::Hex => "hex",
        Codec::Octal => "octal",
        Codec::Binary => "binary",
        Codec::Gzip => "gzip",
    }
}

/// Read a comma-separated chain into transforms, naming the first one that is not a transform.
fn parse_transforms(chain: &str) -> Result<Vec<Transform>, String> {
    let mut out = Vec::new();
    for raw in chain.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        out.push(transform_of(raw).ok_or_else(|| {
            format!("{raw:?} is not a transform. Each is a <codec>-encode or <codec>-decode, or jwt-decode.")
        })?);
    }
    if out.is_empty() {
        return Err("the transform chain is empty.".to_string());
    }
    Ok(out)
}

/// Run `input` through a chain of transforms, naming the step that could not be done.
fn run_chain(transforms: &[Transform], input: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut data = input;
    for (n, t) in transforms.iter().enumerate() {
        data = apply_transform(*t, &data).map_err(|e| format!("step {} ({}): {e}", n + 1, t.name()))?;
    }
    Ok(data)
}

fn transform_of(name: &str) -> Option<Transform> {
    if name == "jwt-decode" {
        return Some(Transform::JwtDecode);
    }
    let (slug, encode) = if let Some(s) = name.strip_suffix("-encode") {
        (s, true)
    } else {
        (name.strip_suffix("-decode")?, false)
    };
    let codec = crate::decoder_ops::Codec::ALL.into_iter().find(|c| codec_slug(*c) == slug)?;
    Some(Transform::Codec(codec, encode))
}

fn apply_transform(t: Transform, data: &[u8]) -> Result<Vec<u8>, String> {
    match t {
        Transform::Codec(c, true) => Ok(crate::decoder_ops::encode(c, data)),
        Transform::Codec(c, false) => {
            crate::decoder_ops::decode(c, data).ok_or_else(|| format!("the input is not valid {}", c.label()))
        }
        Transform::JwtDecode => {
            let token = String::from_utf8_lossy(data);
            let parts = crate::codec::parse_jwt_detailed(&token)?;
            let value = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap_or(serde_json::Value::Null);
            let combined = serde_json::json!({ "header": value(&parts.header_json), "payload": value(&parts.payload_json) });
            Ok(serde_json::to_string_pretty(&combined).unwrap_or_default().into_bytes())
        }
    }
}

/// Settings for a subcommand, from `--config` (already set into the environment) or the usual
/// place, warning on `err` if the file could not be read.
fn settings_of_config(parsed: &SubArgs, err: &mut dyn Write) -> crate::state::UserSettings {
    match crate::state::UserSettings::load(&config_dir_of(parsed)) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            crate::state::UserSettings::default()
        }
    }
}

/// The configuration directory a subcommand uses: the one `--config` names, else the usual
/// one. Read from the parsed flags rather than the environment, so a run acts on exactly the
/// directory it was told to whatever else shares the process.
fn config_dir_of(parsed: &SubArgs) -> PathBuf {
    parsed.value("--config").map(PathBuf::from).unwrap_or_else(crate::ca::config_dir)
}

/// Say why a subcommand could not do what was asked, and give back the failure code.
fn refuse(err: &mut dyn Write, message: &str) -> i32 {
    let _ = writeln!(err, "{message}");
    EXIT_FAILED
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

#[cfg(test)]
mod subcommand_tests {
    use super::*;
    use crate::test_utils::assert_table;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// Run a subcommand engine with these argument strings, returning (exit, stdout, stderr).
    fn run(f: fn(&[String], &mut dyn Write, &mut dyn Write) -> i32, args: &[&str]) -> (i32, String, String) {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = f(&argv, &mut out, &mut err);
        (code, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
    }

    /// A directory of this test's own.
    fn work_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("forge-sub-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a place to work");
        dir
    }

    /// A local HTTP server that answers each request with `handler(path, body) -> (code, body)`,
    /// serving on a loopback port for the life of the test. Returns its origin URL.
    fn serve(handler: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let origin = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let Ok(peek) = stream.try_clone() else { continue };
                let mut reader = BufReader::new(peek);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let path = head.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
                let clen = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; clen];
                let _ = reader.read_exact(&mut body);
                let (code, rbody) = handler(&path, &String::from_utf8_lossy(&body));
                let reason = if code == 200 { "OK" } else { "Not Found" };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                    rbody.len(),
                    rbody
                );
                let mut stream = stream;
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        origin
    }

    // ---- parsing and routing --------------------------------------------

    /// A subcommand is the first argument when it names one; a flag or a path is not one, so
    /// the flat flags keep it.
    #[test]
    fn a_leading_subcommand_name_routes_and_nothing_else_does() {
        for name in SUBCOMMANDS {
            assert_eq!(subcommand_of(&[name.to_string()]), Some(name));
            assert_eq!(subcommand_of(&[name.to_string(), "--help".into()]), Some(name));
        }
        for not_a_sub in [vec!["--light"], vec!["triage.forge"], vec!["--run-plan", "scan"], vec![]] {
            let argv: Vec<String> = not_a_sub.iter().map(|s| s.to_string()).collect();
            assert_eq!(subcommand_of(&argv), None, "{not_a_sub:?} is not a subcommand");
        }
        // the top-level usage names every subcommand it routes
        for name in SUBCOMMANDS {
            assert!(USAGE.contains(name), "the usage text lists {name:?}");
        }
    }

    /// Every subcommand prints its own help and stops, touching no network.
    #[test]
    fn each_subcommand_has_its_own_help() {
        let subs: [(&str, fn(&[String], &mut dyn Write, &mut dyn Write) -> i32); 6] = [
            ("scan", sub_scan),
            ("intruder", sub_intruder),
            ("repeat", sub_repeat),
            ("proxy", sub_proxy),
            ("sequence", sub_sequence),
            ("decode", sub_decode),
        ];
        assert_table!(subs, |idx, (name, f)| {
            let (code, out, err) = run(f, &["--help"]);
            assert_eq!(code, EXIT_OK, "case #{idx}: {name} --help ends well");
            assert!(out.contains(&format!("forgeproxy {name}")), "case #{idx}: {name} prints its own usage: {out}");
            assert!(err.is_empty(), "case #{idx}: {name} --help says nothing on the error stream");
        });
        // an unknown flag on a subcommand is refused, naming it
        let (code, _, err) = run(sub_decode, &["url-decode", "--nope"]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("--nope is not a flag"), "{err}");
    }

    /// The flat flags still parse exactly as before, subcommands or no subcommands.
    #[test]
    fn the_flat_flags_are_untouched() {
        // a positional project path is still that, and is not mistaken for a subcommand
        let o = parse(vec!["triage.forge".into()]).expect("reads");
        assert_eq!(o.project.as_deref(), Some("triage.forge"));
        // every top-level flag the earlier work added still reads
        let o = parse(vec!["--run-plan".into(), "Nightly".into(), "--target".into(), "http://h/".into()]).expect("reads");
        assert_eq!(o.run_plan.as_deref(), Some("Nightly"));
        assert_eq!(o.target.as_deref(), Some("http://h/"));
    }

    // ---- decode ---------------------------------------------------------

    /// Transform chains run left to right, encode and decode are inverses, and an unknown
    /// transform (or a decode of input that does not fit) is reported with the step.
    #[test]
    fn decode_runs_transform_chains_matrix() {
        let chain = |c: &str, input: &str| -> Result<String, String> {
            let ts = parse_transforms(c)?;
            run_chain(&ts, input.as_bytes().to_vec()).map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        // base64 of "hello" is "aGVsbG8="; url-decode first turns %3D into =
        assert_eq!(chain("url-decode,base64-decode", "aGVsbG8%3D").unwrap(), "hello");
        // a round trip returns the input
        assert_eq!(chain("base64-encode,base64-decode", "round trip").unwrap(), "round trip");
        assert_eq!(chain("url-encode,url-decode", "a b&c=d").unwrap(), "a b&c=d");
        // gzip-encode then base64-encode is a pipeline that reverses cleanly
        let packed = chain("gzip-encode,base64-encode", "compress me").unwrap();
        assert_eq!(chain("base64-decode,gzip-decode", &packed).unwrap(), "compress me");
        // an unknown transform is refused, naming it
        let e = chain("url-decode,frobnicate", "x").unwrap_err();
        assert!(e.contains("\"frobnicate\" is not a transform"), "{e}");
        // a decode that cannot be done names the step and what it expected (plain text is
        // not a gzip stream, so gzip-decode cannot make anything of it)
        let e = chain("gzip-decode", "not compressed").unwrap_err();
        assert!(e.contains("step 1") && e.to_lowercase().contains("gzip"), "{e}");
    }

    /// decode reads its input from --input or --file, and writes the result to stdout; --json
    /// wraps it with the chain that produced it.
    #[test]
    fn decode_reads_input_and_writes_output() {
        let (code, out, _) = run(sub_decode, &["base64-decode", "--input", "aGVsbG8="]);
        assert_eq!(code, EXIT_OK);
        assert_eq!(out, "hello");

        let dir = work_dir("decode-file");
        let path = dir.join("in.txt");
        std::fs::write(&path, "aGVsbG8=").unwrap();
        let (code, out, _) = run(sub_decode, &["base64-decode", "--file", path.to_str().unwrap()]);
        assert_eq!(code, EXIT_OK);
        assert_eq!(out, "hello");

        let (code, out, _) = run(sub_decode, &["base64-decode", "--input", "aGVsbG8=", "--json"]);
        assert_eq!(code, EXIT_OK);
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["output"], "hello");
        assert_eq!(v["transforms"][0], "base64-decode");

        // a JWT is read into its header and payload
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiQSJ9.sig";
        let (code, out, _) = run(sub_decode, &["jwt-decode", "--input", jwt]);
        assert_eq!(code, EXIT_OK, "{out}");
        assert!(out.contains("\"sub\": \"123\"") && out.contains("HS256"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- sequence -------------------------------------------------------

    /// A predictable set of tokens measures as low entropy and fails the bitstream test; a
    /// high-entropy set measures near the maximum and passes.
    #[test]
    fn sequence_tells_predictable_tokens_from_random_ones() {
        let dir = work_dir("sequence");
        let low = dir.join("low.txt");
        let high = dir.join("high.txt");
        // counting in hex: each token differs from the last in only its lowest digits
        std::fs::write(&low, (0..200).map(|i| format!("{i:032x}")).collect::<Vec<_>>().join("\n")).unwrap();
        // a cheap but well-mixed sequence: a linear congruential generator, hex-encoded
        let mut x: u128 = 0x1234_5678_9abc_def0;
        let hi: Vec<String> = (0..200)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                format!("{x:032x}")
            })
            .collect();
        std::fs::write(&high, hi.join("\n")).unwrap();

        let analyse = |p: &std::path::Path| -> serde_json::Value {
            let (code, out, _) = run(sub_sequence, &["--file", p.to_str().unwrap(), "--json"]);
            assert_eq!(code, EXIT_OK, "{out}");
            serde_json::from_str(&out).expect("json")
        };
        let lo = analyse(&low);
        let hi = analyse(&high);
        assert_eq!(lo["sample_count"], 200);
        let lo_bits = lo["entropy_bits_per_char"].as_f64().unwrap();
        let hi_bits = hi["entropy_bits_per_char"].as_f64().unwrap();
        assert!(lo_bits < hi_bits, "predictable ({lo_bits}) is less random than mixed ({hi_bits})");
        assert!(hi_bits > 3.5, "a well-mixed hex sample is near 4 bits per character: {hi_bits}");

        // the text summary is served too
        let (code, out, _) = run(sub_sequence, &["--file", high.to_str().unwrap()]);
        assert_eq!(code, EXIT_OK);
        assert!(out.contains("Tokens analysed: 200"), "{out}");

        // neither source given is an error that says what is needed
        let (code, _, err) = run(sub_sequence, &[]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("--file") && err.contains("--url"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- repeat ---------------------------------------------------------

    /// repeat sends a raw request and shows the response, as text and as a JSON envelope, and
    /// keeps the exchange in a project when one is named.
    #[test]
    fn repeat_sends_a_request_and_persists_it() {
        let origin = serve(|path, _| (200, format!("you asked for {path}")));
        let dir = work_dir("repeat");
        let req = dir.join("req.txt");
        std::fs::write(&req, "GET /hello HTTP/1.1\r\nHost: h.test\r\n\r\n").unwrap();

        let (code, out, _) = run(sub_repeat, &["--req", req.to_str().unwrap(), "--target", &origin]);
        assert_eq!(code, EXIT_OK, "{out}");
        assert!(out.contains("200 OK") && out.contains("you asked for /hello"), "{out}");

        let project = dir.join("r.forge");
        let (code, out, _) = run(
            sub_repeat,
            &["--req", req.to_str().unwrap(), "--target", &origin, "--json", "--project", project.to_str().unwrap()],
        );
        assert_eq!(code, EXIT_OK);
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["status_code"], 200);
        assert!(v["response"].as_str().unwrap().contains("you asked for /hello"));
        let saved = crate::project::read(&project.display().to_string()).expect("the project");
        assert_eq!(saved.history.len(), 1);
        assert_eq!(saved.history[0].tool, "Repeater");
        assert_eq!(saved.history[0].path, "/hello");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- intruder -------------------------------------------------------

    /// intruder substitutes each word into the marked position, filters by status and length,
    /// and records the exchanges.
    #[test]
    fn intruder_replays_filters_and_persists() {
        // the server says 200 for the word "admin", 404 for anything else, echoing the body
        let origin = serve(|_, body| if body.contains("admin") { (200, "welcome".into()) } else { (404, "no".into()) });
        let dir = work_dir("intruder");
        let req = dir.join("req.txt");
        // the body is exactly the marked position, so each word becomes the whole body
        std::fs::write(&req, "POST /login HTTP/1.1\r\nHost: h.test\r\nContent-Length: 1\r\n\r\n\u{00a7}x\u{00a7}").unwrap();
        let words = dir.join("words.txt");
        std::fs::write(&words, "admin\nguest\nroot\n").unwrap();

        // all three, as JSON
        let (code, out, _) = run(
            sub_intruder,
            &["--req", req.to_str().unwrap(), "--wordlist", words.to_str().unwrap(), "--target", &origin, "--json"],
        );
        assert_eq!(code, EXIT_OK, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");
        let results = v["results"].as_array().unwrap();
        assert_eq!(results.len(), 3, "one per word");
        let admin = results.iter().find(|r| r["payload"] == "admin").unwrap();
        assert_eq!(admin["status_code"], 200, "the substitution reached the body");
        assert!(results.iter().any(|r| r["payload"] == "guest" && r["status_code"] == 404));

        // keep only the 200s
        let (code, out, _) = run(
            sub_intruder,
            &["--req", req.to_str().unwrap(), "--wordlist", words.to_str().unwrap(), "--target", &origin, "--match-status", "200"],
        );
        assert_eq!(code, EXIT_OK);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "only the matching one: {out}");
        assert!(lines[0].contains("admin") && lines[0].contains("200 OK"), "{out}");

        // hide the length the 404s share ("no" -> 2)
        let (code, out, _) = run(
            sub_intruder,
            &["--req", req.to_str().unwrap(), "--wordlist", words.to_str().unwrap(), "--target", &origin, "--hide-length", "2"],
        );
        assert_eq!(code, EXIT_OK);
        assert!(out.lines().all(|l| l.contains("admin")), "the 404s were hidden by length: {out}");

        // and the exchanges are kept
        let project = dir.join("i.forge");
        let (code, _, _) = run(
            sub_intruder,
            &["--req", req.to_str().unwrap(), "--wordlist", words.to_str().unwrap(), "--target", &origin, "--project", project.to_str().unwrap()],
        );
        assert_eq!(code, EXIT_OK);
        let saved = crate::project::read(&project.display().to_string()).expect("the project");
        assert_eq!(saved.history.len(), 3);
        assert!(saved.history.iter().all(|e| e.tool == "Intruder"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- scan -----------------------------------------------------------

    /// scan audits a page, reporting the issues it finds, writing a report and a project, and
    /// ending with code 2 when asked to fail on findings.
    #[test]
    fn scan_detects_reports_and_sets_the_exit_code() {
        // a directory-listing page that reflects the query value: two findings at least
        let origin = serve(|path, _| {
            let q = path.split("q=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
            (200, format!("<title>Index of /files</title>reflected:{q}"))
        });
        let dir = work_dir("scan");
        let report = dir.join("out").join("report.xml");
        let project = dir.join("s.forge");
        let url = format!("{origin}/files/");

        let (code, out, _) = run(
            sub_scan,
            &[&url, "--report", report.to_str().unwrap(), "--project", project.to_str().unwrap()],
        );
        assert_eq!(code, EXIT_OK, "without --fail-on-findings a scan that found things still ends 0: {out}");
        assert!(out.contains("Directory listing"), "{out}");
        assert!(out.contains("reflected") || out.contains("Input returned"), "{out}");

        let xml = std::fs::read_to_string(&report).expect("the report");
        assert!(xml.starts_with("<?xml") && xml.contains("Directory listing"), "{xml}");
        let saved = crate::project::read(&project.display().to_string()).expect("the project");
        assert!(!saved.imported_findings.is_empty(), "findings kept");
        assert!(!saved.history.is_empty(), "traffic kept");

        // the JSON shape, and the exit code when told to fail on findings
        let (code, out, _) = run(sub_scan, &[&url, "--json", "--fail-on-findings"]);
        assert_eq!(code, EXIT_FINDINGS, "fail-on-findings turns a finding into exit 2");
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");
        assert!(v["findings"].as_array().unwrap().iter().any(|f| f["name"] == "Directory listing"), "{out}");

        // a scan with no URL says so
        let (code, _, err) = run(sub_scan, &["--json"]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("needs a URL"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// scan given an Interactor relay plants out-of-band canaries, polls the relay, and turns a
    /// callback into a reported finding that drives the --fail-on-findings exit code to 2.
    #[test]
    fn scan_reports_out_of_band_callbacks_and_fails_on_them() {
        let mocks = crate::test_utils::OastMocks::start();
        let url = format!("{}/app", mocks.target);

        let (code, out, _) = run(
            sub_scan,
            &[&url, "--json", "--fail-on-findings", "--interactor", &mocks.relay, "--oast-settle-ms", "150"],
        );
        assert_eq!(code, EXIT_FINDINGS, "an out-of-band callback is a finding, so --fail-on-findings exits 2: {out}");
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");
        let names: Vec<&str> = v["findings"].as_array().unwrap().iter().filter_map(|f| f["name"].as_str()).collect();
        assert!(names.iter().any(|n| n.contains("SSRF")), "the SSRF callback is reported: {names:?}");
        assert!(!mocks.seen.lock().unwrap().is_empty(), "canaries reached the target");
    }

    // ---- proxy ----------------------------------------------------------

    /// proxy runs for its duration with no window, forwards a request to a real server, and
    /// writes what it captured to the project.
    #[test]
    fn proxy_captures_a_request_and_writes_the_project() {
        let origin = serve(|path, _| (200, format!("served {path}")));
        let host_port = origin.trim_start_matches("http://").to_string();
        let dir = work_dir("proxy");
        let project = dir.join("cap.forge");

        // the proxy runs on its own thread so this one can drive a request through it
        let proxy_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let project_arg = project.display().to_string();
        let handle = std::thread::spawn(move || {
            let argv: Vec<String> = ["--port", &proxy_port.to_string(), "--project", &project_arg, "--duration", "2"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            // a flag of its own, so the test process's Ctrl+C is left alone
            sub_proxy_until(&argv, &mut out, &mut err, Some(Arc::new(AtomicBool::new(false))))
        });

        // give the listener a moment, then send an absolute-form request as a browser's proxy would
        std::thread::sleep(std::time::Duration::from_millis(400));
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", proxy_port)) {
            let req = format!("GET http://{host_port}/proxied HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(req.as_bytes());
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
        }

        let code = handle.join().expect("the proxy thread");
        assert_eq!(code, EXIT_OK);
        let saved = crate::project::read(&project.display().to_string()).expect("the project was written");
        assert!(saved.history.iter().any(|e| e.path == "/proxied"), "the proxied request was captured: {:?}",
            saved.history.iter().map(|e| e.path.clone()).collect::<Vec<_>>());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A free loopback port, released for the proxy to take.
    fn free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// Send one absolute-form request through the proxy on `proxy_port`, retrying while the
    /// listener comes up, and read the whole answer.
    fn through_proxy(proxy_port: u16, host_port: &str, path: &str) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match std::net::TcpStream::connect(("127.0.0.1", proxy_port)) {
                Ok(mut stream) => {
                    let req = format!("GET http://{host_port}{path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
                    stream.write_all(req.as_bytes()).expect("the request is sent");
                    let mut answer = String::new();
                    let _ = stream.read_to_string(&mut answer);
                    return answer;
                }
                Err(_) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(e) => panic!("the proxy never listened on {proxy_port}: {e}"),
            }
        }
    }

    /// Raising the shutdown flag ends a long --duration run within moments: the listener closes,
    /// everything captured is in the project, and the exit code is 0.
    #[test]
    fn proxy_stops_at_once_when_the_shutdown_flag_is_raised() {
        let origin = serve(|path, _| (200, format!("served {path}")));
        let host_port = origin.trim_start_matches("http://").to_string();
        let dir = work_dir("proxy-stop");
        let project = dir.join("stop.forge");
        let proxy_port = free_port();
        let project_arg = project.display().to_string();
        let shutdown = Arc::new(AtomicBool::new(false));
        let raised = shutdown.clone();
        let handle = std::thread::spawn(move || {
            let argv: Vec<String> = ["--bind", "127.0.0.1", "--port", &proxy_port.to_string(), "--project", &project_arg, "--duration", "600"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = sub_proxy_until(&argv, &mut out, &mut err, Some(raised));
            (code, String::from_utf8_lossy(&err).into_owned())
        });

        for path in ["/first", "/second"] {
            let answer = through_proxy(proxy_port, &host_port, path);
            assert!(answer.contains(&format!("served {path}")), "the proxy forwarded {path}: {answer:?}");
        }

        let asked = std::time::Instant::now();
        shutdown.store(true, Ordering::SeqCst);
        let (code, err) = handle.join().expect("the proxy thread");
        let took = asked.elapsed();
        assert_eq!(code, EXIT_OK, "{err}");
        assert!(took < std::time::Duration::from_secs(2), "stopped in {took:?}, not at the 600 s deadline");
        assert!(err.contains("Captured 2 requests") && err.contains(&project.display().to_string()), "{err}");

        // the listener is closed: nothing answers on its port any more
        assert!(std::net::TcpStream::connect(("127.0.0.1", proxy_port)).is_err(), "the port was released");

        let saved = crate::project::read(&project.display().to_string()).expect("the project was written");
        let mut paths: Vec<String> = saved.history.iter().map(|e| e.path.clone()).collect();
        paths.sort();
        assert_eq!(paths, ["/first", "/second"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
