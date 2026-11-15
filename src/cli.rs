//! The command line: the flags, the usage text, and everything the app can be asked to do
//! without opening a window.
//!
//! Two of those things need no display server at all -- listing the saved pipelines, and
//! running one unattended -- so a container or a build agent can run a pipeline over a target
//! and act on what it reports. The engine that runs it is the same one the Automation tab
//! drives, and the report it writes is the same document the Dashboard's buttons write; only
//! the way in is different.

use crate::tooling::{AutomationPlan, RunStatus};
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
  --target <url>         The address a pipeline runs on. Without --run-plan it is filled into
                         the Automation tab's target bar.

Running without a window:
  --list-plans           Print each saved pipeline with its number of steps, and exit.
  --run-plan <name>      Run this pipeline and exit. No display server is needed. The name is
                         matched exactly first, then ignoring capitals.
  --report <path>        Write the issues the run ends with to this file. A .xml path writes
                         the XML report; anything else writes HTML.
  --fail-on-findings     Exit 2 when the run finishes having reported one issue or more.

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
    pub target: Option<String>,
    pub report: Option<PathBuf>,
    pub fail_on_findings: bool,
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
    if opts.run_plan.is_some() {
        return Some(run_plan(opts, out, err));
    }
    None
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

/// `--run-plan`: run one pipeline unattended, from the settings in `--config`, over the
/// address in `--target`, keeping what it reports in `--project` and `--report`.
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
    let target = opts.target.as_deref().unwrap_or_default().trim().to_string();
    if target.is_empty() {
        let _ = writeln!(err, "--run-plan needs --target <url>: a pipeline is run on an address.");
        return EXIT_FAILED;
    }

    // the project the findings are to be kept in, read first so they can be merged with what
    // is already there; a path that is not there yet becomes a new project when the run ends
    let mut project: Option<(String, crate::project::ProjectFile)> = None;
    if let Some(path) = &opts.project {
        if Path::new(path).exists() {
            match crate::project::read(path) {
                Ok(f) => project = Some((path.clone(), f)),
                Err(e) => {
                    let _ = writeln!(err, "{e}");
                    return EXIT_FAILED;
                }
            }
        } else {
            let _ = writeln!(out, "{path} is not there yet; it will be written when the run ends.");
            project = Some((path.clone(), crate::project::ProjectFile::fresh(&plan.display_name())));
        }
    }
    let prior: Vec<crate::scan::Finding> =
        project.as_ref().map(|(_, f)| f.imported_findings.clone()).unwrap_or_default();

    let steps = plan.steps.len();
    let _ = writeln!(
        out,
        "{} on {target}: {steps} {}",
        plan.display_name(),
        if steps == 1 { "step." } else { "steps." }
    );
    let ctx = crate::actions::tool_context(&target, "", "");
    let outcome = crate::tooling::run_plan_streaming(&plan, &settings.external_tools, &ctx, out);
    // with the exit status when the run did not succeed, which is worth knowing without
    // reading back through the output; a run that did succeed says only that, as the run
    // history in the app does
    let ended = match (outcome.status, outcome.exit_code) {
        (RunStatus::Succeeded, _) => RunStatus::Succeeded.label().to_string(),
        (status, Some(code)) => format!("{} (exit status {code})", status.label()),
        (status, None) => status.label().to_string(),
    };
    let _ = writeln!(out, "\n{ended} after {} ms.", outcome.elapsed_ms);

    // through the same consolidation the app uses, against what the project already held, so
    // a run repeated on the same project does not list everything twice
    let reported = outcome.findings.len();
    let before = prior.len();
    let mut all = prior;
    all.extend(outcome.findings.iter().cloned());
    let kept = crate::scan::consolidate(all);
    let added = kept.len().saturating_sub(before);
    for f in &outcome.findings {
        let _ = writeln!(out, "{}", finding_line(f));
    }
    let _ = writeln!(out, "{reported} reported, {added} new.");

    if let Some((path, mut file)) = project {
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
        AutomationPlan { name: name.into(), steps: vec![PipelineStep::default(); steps] }
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
            vec![AutomationPlan { name: "Survey".into(), steps: vec![PipelineStep::default()] }],
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
                AutomationPlan { name: "Quiet".into(), steps: vec![PipelineStep { tool_index: 0, ..Default::default() }] },
                AutomationPlan { name: "Noisy".into(), steps: vec![PipelineStep { tool_index: 1, ..Default::default() }] },
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
                AutomationPlan { name: "Broken".into(), steps: vec![PipelineStep { tool_index: 0, ..Default::default() }] },
                AutomationPlan {
                    name: "Broken then on".into(),
                    steps: vec![
                        PipelineStep { tool_index: 0, on_failure: StepFailurePolicy::Continue, ..Default::default() },
                        PipelineStep { tool_index: 1, ..Default::default() },
                    ],
                },
                AutomationPlan { name: "Fine".into(), steps: vec![PipelineStep { tool_index: 1, ..Default::default() }] },
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
