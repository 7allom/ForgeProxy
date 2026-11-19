//! Automation: the program registry, multi-step pipelines, the record of what has been run,
//! and the findings a program reports.
//!
//! Nothing here goes through a shell. An argument template is split into separate arguments
//! first, and a placeholder is then replaced *inside* one of them, so a URL carrying `;`,
//! backticks or `$(...)` stays one argument and is handed to the program as text. There is no
//! interpreter between this and the program to interpret it.
//!
//! A program runs on a thread of its own. Its output is read as it arrives and appended to
//! the run record the Automation tab is drawing, so the console fills while the program is
//! still working; the record is bounded, and so is what is kept of each stream, because a
//! session must not grow without limit on the strength of one talkative program.

use crate::scan::{Confidence, Finding, Severity};
use eframe::egui;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// What the tool is given on its standard input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStdinMode {
    /// Nothing: the tool works from its arguments alone.
    #[default]
    None,
    /// The request exactly as it went out.
    RawRequest,
    /// The response exactly as it came back.
    RawResponse,
    /// One JSON object describing the exchange, for a script that would rather not parse HTTP.
    JsonEnvelope,
}

impl ToolStdinMode {
    pub const ALL: [ToolStdinMode; 4] =
        [ToolStdinMode::None, ToolStdinMode::RawRequest, ToolStdinMode::RawResponse, ToolStdinMode::JsonEnvelope];
    pub fn label(self) -> &'static str {
        match self {
            ToolStdinMode::None => "Nothing",
            ToolStdinMode::RawRequest => "Raw request",
            ToolStdinMode::RawResponse => "Raw response",
            ToolStdinMode::JsonEnvelope => "JSON envelope",
        }
    }
}

/// How long a program is given before it is stopped, unless the entry says otherwise.
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// What a timeout may be set to. A second is the shortest worth offering; an hour is longer
/// than any single program on one message has business taking.
pub const TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=3600;

/// The default for a flag that is on unless a settings file says otherwise. A field-level
/// `serde(default = ...)` needs a function to call, so this is one.
fn default_true() -> bool {
    true
}

/// A program the user has registered, as it appears in the Automation tab and on the
/// "Send to" menus.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ExternalTool {
    /// What the menu item says.
    pub name: String,
    /// The program to run. Looked up on the path, or an absolute path to a script.
    pub command: String,
    /// The arguments, as a template. Split on whitespace, with quoted runs kept together.
    pub args: String,
    pub stdin_mode: ToolStdinMode,
    /// How long it is given before it is stopped, in seconds.
    pub timeout_secs: u64,
    /// Read its standard output as a findings document and take what it reports into the
    /// issue store.
    pub import_findings: bool,
    /// Offer this program on the right-click menus. A helper only ever meant to run as a
    /// pipeline step can be kept off them without being unregistered. Settings files written
    /// before this existed have no such field, and every program in them was on the menus, so
    /// a missing one reads as on.
    #[serde(default = "default_true")]
    pub show_in_menu: bool,
    /// What this program is for, in the author's own words. Carried in a bundle so whoever
    /// receives one can see what they are being offered before they register it.
    #[serde(default)]
    pub description: String,
}

impl Default for ExternalTool {
    fn default() -> Self {
        ExternalTool {
            name: String::new(),
            command: String::new(),
            args: String::new(),
            stdin_mode: ToolStdinMode::None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            import_findings: false,
            show_in_menu: true,
            description: String::new(),
        }
    }
}

impl ExternalTool {
    /// Is this entry worth offering? A tool with no name or no program cannot be run, and an
    /// unfinished row in the registry should not appear on a menu.
    pub fn is_runnable(&self) -> bool {
        !self.name.trim().is_empty() && !self.command.trim().is_empty()
    }

    /// Is this entry offered on the right-click menus? It has to be runnable, and not one the
    /// user has kept off them.
    pub fn on_menus(&self) -> bool {
        self.is_runnable() && self.show_in_menu
    }

    /// The timeout in force. A settings file is hand-editable and can hold anything, so the
    /// figure is brought into range here as well as on load.
    pub fn timeout(&self) -> std::time::Duration {
        let secs = self.timeout_secs.clamp(*TIMEOUT_RANGE.start(), *TIMEOUT_RANGE.end());
        std::time::Duration::from_secs(secs)
    }

    /// The name to show for an entry, including one still being filled in.
    pub fn display_name(&self) -> String {
        let name = self.name.trim();
        if name.is_empty() { "Unnamed program".to_string() } else { name.to_string() }
    }
}

/// What a step does when the program before it did not succeed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepFailurePolicy {
    /// Give up: the steps after this one are not run.
    #[default]
    Stop,
    /// Carry on with the next step anyway.
    Continue,
}

impl StepFailurePolicy {
    pub const ALL: [StepFailurePolicy; 2] = [StepFailurePolicy::Stop, StepFailurePolicy::Continue];
    pub fn label(self) -> &'static str {
        match self {
            StepFailurePolicy::Stop => "Stop",
            StepFailurePolicy::Continue => "Continue",
        }
    }
}

/// One program in a pipeline, and what to do if it fails.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct PipelineStep {
    /// Which registered program, by its place in the registry. Kept beside `tool_name` and
    /// brought back into line with it whenever the registry changes.
    pub tool_index: usize,
    /// Which registered program, by name. A name survives the registry being reordered, a
    /// program being added above this one, or a pipeline travelling to another workstation in
    /// a bundle, none of which a place in a list survives. Blank in a plan saved before names
    /// were kept, which is read by its place instead.
    pub tool_name: String,
    /// Arguments for this step only. Blank leaves the program's own template in place.
    pub args_override: String,
    pub on_failure: StepFailurePolicy,
    /// Read this step's output as a findings document, whatever the program itself says.
    pub import_findings: bool,
}

impl PipelineStep {
    /// The program this step runs, out of `tools`: the one it names, else the one at the place
    /// it holds.
    ///
    /// The name comes first, so a pipeline keeps working when the registry is reordered. The
    /// place is the fallback for a step that names nothing (a plan saved before names were
    /// kept) and for one whose program has since been renamed, which is better than a step
    /// that suddenly runs nothing at all.
    pub fn resolve<'a>(&self, tools: &'a [ExternalTool]) -> Option<&'a ExternalTool> {
        let wanted = self.tool_name.trim();
        if !wanted.is_empty() {
            if let Some(found) = tools.iter().find(|t| t.name.trim() == wanted) {
                return Some(found);
            }
        }
        tools.get(self.tool_index)
    }

    /// What this step says it runs, for a message about it: the name it holds, else the place.
    pub fn display_target(&self) -> String {
        match self.tool_name.trim() {
            "" => format!("the program in slot {}", self.tool_index + 1),
            name => name.to_string(),
        }
    }
}

/// A run of registered programs, one after another.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AutomationPlan {
    pub name: String,
    /// What this pipeline is for, in the author's own words.
    #[serde(default)]
    pub description: String,
    pub steps: Vec<PipelineStep>,
}

impl AutomationPlan {
    /// Is this plan worth running? A plan with no steps does nothing, and one with no name
    /// cannot be told from another in a list.
    pub fn is_runnable(&self) -> bool {
        !self.name.trim().is_empty() && !self.steps.is_empty()
    }

    pub fn display_name(&self) -> String {
        let name = self.name.trim();
        if name.is_empty() { "Unnamed pipeline".to_string() } else { name.to_string() }
    }
}

/// Bring every step back into line with the registry, both ways round.
///
/// A step that names a program is pointed at wherever that program now is; one that names
/// none takes the name of the program its place holds, which is how a plan saved before names
/// were kept gains them. Run whenever either list changes -- on load, after an edit, and after
/// a bundle is merged -- so the name and the place never disagree about which program is meant.
pub fn bind_steps(tools: &[ExternalTool], plans: &mut [AutomationPlan]) {
    for plan in plans {
        for step in &mut plan.steps {
            let named = step.tool_name.trim();
            if named.is_empty() {
                if let Some(tool) = tools.get(step.tool_index) {
                    step.tool_name = tool.name.trim().to_string();
                }
            } else if let Some(at) = tools.iter().position(|t| t.name.trim() == named) {
                step.tool_index = at;
            }
        }
    }
}

/// Follow a program's new name into every step that named its old one, so renaming a program
/// does not quietly leave the pipelines that use it pointing at nothing.
pub fn rename_in_steps(plans: &mut [AutomationPlan], from: &str, to: &str) {
    let (from, to) = (from.trim(), to.trim());
    if from.is_empty() || from == to {
        return;
    }
    for plan in plans {
        for step in &mut plan.steps {
            if step.tool_name.trim() == from {
                step.tool_name = to.to_string();
            }
        }
    }
}

/// Every placeholder an argument template may carry, with what each one stands for.
///
/// Shown on the Settings page, and held by a test to matching what [`fill`] replaces.
pub const PLACEHOLDERS: [(&str, &str); 10] = [
    ("{url}", "the whole address"),
    ("{scheme}", "http or https"),
    ("{host}", "host name, with the port when there is one"),
    ("{port}", "port number"),
    ("{method}", "request method"),
    ("{path}", "path and query"),
    ("{req_file}", "a temporary file holding the raw request"),
    ("{res_file}", "a temporary file holding the raw response"),
    ("{prev_out_file}", "a temporary file holding the previous pipeline step's output"),
    ("{var:KEY}", "a value given for KEY when the run was started"),
];

/// What one message is, for filling a template in.
#[derive(Clone, Debug, Default)]
pub struct ToolContext {
    pub url: String,
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub method: String,
    pub path: String,
    pub request: String,
    pub response: String,
    /// The file holding the output of the step before this one, while a pipeline is running.
    /// Blank for a program run on its own, which has no step before it.
    pub prev_out_file: String,
    /// Values given for this run, reached from a template as `{var:KEY}`. Ordered, so a
    /// message about them reads the same every time.
    pub vars: std::collections::BTreeMap<String, String>,
}

/// Split an argument template into separate arguments.
///
/// Whitespace separates, and a run inside single or double quotes is kept together so a
/// template can pass an argument that has a space in it. Nothing else is interpreted: no
/// variables, no globbing, no command substitution, because nothing here is a shell.
pub fn tokenize(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    for ch in template.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                // an empty quoted run is still an argument
                started = true;
            }
            None if ch.is_whitespace() => {
                if started || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None => current.push(ch),
        }
    }
    if started || !current.is_empty() {
        out.push(current);
    }
    out
}

/// Replace every `{var:KEY}` in one argument with the value given for `KEY`, or with nothing
/// when none was given.
///
/// Scanned once from the left, so a value that itself looks like a placeholder is left as the
/// text it is rather than being filled in again. Like every other substitution here this
/// happens inside one argument and cannot split it, so a value carrying spaces, quotes or
/// shell metacharacters reaches the program as the single argument it was written as.
fn fill_vars(arg: &str, vars: &std::collections::BTreeMap<String, String>) -> String {
    const OPEN: &str = "{var:";
    if !arg.contains(OPEN) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(at) = rest.find(OPEN) {
        out.push_str(&rest[..at]);
        let after = &rest[at + OPEN.len()..];
        let Some(end) = after.find('}') else {
            // an opening with no closing brace is not a placeholder; it is text
            out.push_str(&rest[at..]);
            return out;
        };
        out.push_str(vars.get(after[..end].trim()).map(String::as_str).unwrap_or(""));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Fill the placeholders in each argument, leaving the arguments themselves as they were.
///
/// Substitution is per argument, never across them: whatever a placeholder stands for becomes
/// part of one argument however many spaces or metacharacters it contains.
pub fn fill(args: &[String], ctx: &ToolContext, req_file: Option<&str>, res_file: Option<&str>) -> Vec<String> {
    args.iter()
        .map(|arg| {
            let mut out = fill_vars(arg, &ctx.vars);
            for (token, value) in [
                ("{url}", ctx.url.as_str()),
                ("{scheme}", ctx.scheme.as_str()),
                ("{host}", ctx.host.as_str()),
                ("{port}", ctx.port.as_str()),
                ("{method}", ctx.method.as_str()),
                ("{path}", ctx.path.as_str()),
                ("{req_file}", req_file.unwrap_or("")),
                ("{res_file}", res_file.unwrap_or("")),
                ("{prev_out_file}", ctx.prev_out_file.as_str()),
            ] {
                if out.contains(token) {
                    out = out.replace(token, value);
                }
            }
            out
        })
        .collect()
}

/// Does this template ask for the request or the response as a file?
pub fn wants_files(args: &str) -> (bool, bool) {
    (args.contains("{req_file}"), args.contains("{res_file}"))
}

/// The head and body of a raw message, split at the blank line between them.
fn split_message(raw: &str) -> (&str, &str) {
    match raw.find("\r\n\r\n") {
        Some(i) => (&raw[..i], &raw[i + 4..]),
        None => match raw.find("\n\n") {
            Some(i) => (&raw[..i], &raw[i + 2..]),
            None => (raw, ""),
        },
    }
}

/// The header lines of a message, as name and value pairs. The first line is the request or
/// status line and is not a header, so it is left out.
fn headers_of(raw: &str) -> Vec<(String, String)> {
    let (head, _) = split_message(raw);
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// The JSON a tool is given on its standard input in [`ToolStdinMode::JsonEnvelope`].
///
/// A body that is text is given as text. One that is not is given as base64 with a flag
/// saying so, because a JSON string cannot hold arbitrary bytes.
pub fn json_envelope(ctx: &ToolContext) -> String {
    let part = |raw: &str| {
        let (_, body) = split_message(raw);
        let headers: Vec<serde_json::Value> =
            headers_of(raw).into_iter().map(|(k, v)| serde_json::json!([k, v])).collect();
        // the body is already a Rust string, so it is text by construction; the flag is here
        // for a tool to rely on rather than having to guess
        serde_json::json!({ "headers": headers, "body": body, "body_base64": false })
    };
    let envelope = serde_json::json!({
        "method": ctx.method,
        "url": ctx.url,
        "scheme": ctx.scheme,
        "host": ctx.host,
        "port": ctx.port,
        "path": ctx.path,
        "request": part(&ctx.request),
        "response": part(&ctx.response),
    });
    serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string())
}

/// What goes on the tool's standard input, if anything.
fn stdin_bytes(tool: &ExternalTool, ctx: &ToolContext) -> Option<Vec<u8>> {
    match tool.stdin_mode {
        ToolStdinMode::None => None,
        ToolStdinMode::RawRequest => Some(ctx.request.clone().into_bytes()),
        ToolStdinMode::RawResponse => Some(ctx.response.clone().into_bytes()),
        ToolStdinMode::JsonEnvelope => Some(json_envelope(ctx).into_bytes()),
    }
}

/// A file only its owner can read, somewhere temporary, holding `contents`.
fn temp_file(tag: &str, contents: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join("forgeproxy-tools");
    crate::paths::create_private_dir(&dir)?;
    // the clock tells one run from another, the counter tells apart two files made inside
    // the same tick -- which two steps of a pipeline, or two threads, really can be
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let path = dir.join(format!("{tag}-{stamp}-{}", unique_tag()));
    crate::paths::write_private(&path, contents.as_bytes())?;
    Ok(path)
}

/// A unique, monotonically increasing suffix, so two files made in the same nanosecond on two
/// threads cannot land on the same name.
fn unique_tag() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// How a run ended, or that it has not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RunStatus {
    #[default]
    Running,
    Succeeded,
    /// The program started and finished with something other than success, or could not be
    /// started at all.
    Failed,
    /// It was still going when its timeout ran out, and was stopped.
    TimedOut,
    /// The user stopped it.
    Cancelled,
}

impl RunStatus {
    pub fn label(self) -> &'static str {
        match self {
            RunStatus::Running => "Running",
            RunStatus::Succeeded => "Succeeded",
            RunStatus::Failed => "Failed",
            RunStatus::TimedOut => "Timed out",
            RunStatus::Cancelled => "Cancelled",
        }
    }

    pub fn finished(self) -> bool {
        self != RunStatus::Running
    }

    /// The status colour, from the palette's own tokens: nothing here is a raw value.
    pub fn colour(self, p: &crate::theme::Palette) -> egui::Color32 {
        match self {
            RunStatus::Running => p.badge_info,
            RunStatus::Succeeded => p.success,
            RunStatus::Failed => p.error,
            RunStatus::TimedOut => p.warning,
            RunStatus::Cancelled => p.disabled,
        }
    }
}

/// What a run was started from, so it can be started again. Held by name rather than by
/// index: the registry can be reordered between a run and a re-run of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOrigin {
    Program(String),
    Pipeline(String),
}

/// One execution, as the Automation tab's run history shows it.
#[derive(Clone, Debug)]
pub struct ToolRun {
    pub id: u64,
    /// The program or the pipeline this run is of.
    pub label: String,
    pub target_url: String,
    pub status: RunStatus,
    /// The program's exit status, when it had one. `None` for a program that could not be
    /// started, or that was stopped before it finished.
    pub exit_code: Option<i32>,
    pub elapsed_ms: u128,
    pub stdout: String,
    pub stderr: String,
    /// How many findings this run put into the issue store.
    pub imported_count: usize,
    /// One line per finding taken in, for the console's third tab.
    pub imported: Vec<String>,
    /// Findings parsed from the output and not yet taken into the issue store. The worker
    /// thread cannot reach the store, so it leaves them here and the drawing thread takes
    /// them ([`crate::actions::drain_tool_findings`]).
    pub pending_findings: Vec<Finding>,
    /// Set when the user asks for the run to stop. The worker sees it and stops the program.
    pub cancel: Arc<AtomicBool>,
    pub origin: RunOrigin,
    /// The message this run was started on, to start it again on the same one.
    pub context: ToolContext,
}

impl ToolRun {
    /// How long this run took, or has been going.
    pub fn elapsed_text(&self) -> String {
        let ms = self.elapsed_ms;
        if ms < 1000 {
            format!("{ms} ms")
        } else {
            format!("{:.1} s", ms as f64 / 1000.0)
        }
    }

    /// The run's own account of itself for the history row: the exit status, when it has one.
    pub fn status_text(&self) -> String {
        match (self.status, self.exit_code) {
            (RunStatus::Succeeded, _) => RunStatus::Succeeded.label().to_string(),
            (s, Some(code)) if s.finished() => format!("{} ({code})", s.label()),
            (s, _) => s.label().to_string(),
        }
    }
}

/// Runs this session keeps. The oldest give way once the buffer is full, so a long session
/// holds a bounded amount however many programs are run in it.
pub const MAX_RUNS: usize = 200;
/// How much of one stream a run record keeps for the console. What is read past this is still
/// given to the findings parser and to the next step of a pipeline; it is only the record
/// shown on screen that stops growing.
pub const MAX_STREAM_KEPT: usize = 32 * 1024;
/// How much of a program's output is read in full, for the findings parser and the handoff to
/// the next step. Past this the program is still waited for, but nothing more is kept.
pub const MAX_OUTPUT_READ: usize = 4 * 1024 * 1024;
/// How much of the triggering message a run keeps, so it can be started again.
const MAX_CONTEXT_KEPT: usize = 16 * 1024;
/// How often a worker looks at the program it is waiting for. Short, so a cancellation is
/// acted on while the pointer is still on the button.
const POLL: std::time::Duration = std::time::Duration::from_millis(25);
/// How often the figure in a running row's "Took" column is moved on. Far less often than
/// the program is looked at: a time that is a fifth of a second out of date reads the same
/// as one that is not, and each change asks the window to draw itself again.
const TICK: std::time::Duration = std::time::Duration::from_millis(200);
/// How long the output pipes are given to end after the program has, before the worker
/// finishes the run with whatever arrived.
///
/// They usually end the moment the program does. They do not when the program left a child
/// of its own behind holding the same pipe -- a script that ran something in the background,
/// or one that was stopped while a program it started carried on. Waiting for the pipe in
/// that case is waiting for the stranger, which may be minutes or hours; the run is finished
/// with what it has instead, and the reading is left to end in its own time.
const READER_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Keep at most `max` bytes of `text`, cut on a character boundary, saying so when it was cut.
fn keep_within(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    const NOTE: &str = "\n[output truncated]\n";
    let mut cut = max.saturating_sub(NOTE.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str(NOTE);
}

/// The runs of this session, shared between the drawing thread and every worker.
#[derive(Clone)]
pub struct RunLog {
    runs: Arc<Mutex<VecDeque<ToolRun>>>,
    next: Arc<AtomicU64>,
    /// Asked for a repaint whenever a run changes, so the console fills while a program is
    /// still working. `None` outside a drawn app (unit tests).
    repaint: Option<egui::Context>,
}

impl RunLog {
    pub fn new(repaint: Option<egui::Context>) -> Self {
        RunLog { runs: Arc::new(Mutex::new(VecDeque::new())), next: Arc::new(AtomicU64::new(1)), repaint }
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, VecDeque<ToolRun>> {
        // a worker that panicked holding the store must not take the console down with it
        self.runs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn woken(&self) {
        if let Some(ctx) = &self.repaint {
            ctx.request_repaint();
        }
    }

    /// Open a record for a run about to start, and give back its id.
    pub fn begin(&self, label: &str, origin: RunOrigin, ctx: &ToolContext) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut context = ctx.clone();
        keep_within(&mut context.request, MAX_CONTEXT_KEPT);
        keep_within(&mut context.response, MAX_CONTEXT_KEPT);
        context.prev_out_file.clear();
        let run = ToolRun {
            id,
            label: label.to_string(),
            target_url: ctx.url.clone(),
            status: RunStatus::Running,
            exit_code: None,
            elapsed_ms: 0,
            stdout: String::new(),
            stderr: String::new(),
            imported_count: 0,
            imported: Vec::new(),
            pending_findings: Vec::new(),
            cancel: Arc::new(AtomicBool::new(false)),
            origin,
            context,
        };
        {
            let mut runs = self.guard();
            while runs.len() >= MAX_RUNS {
                runs.pop_front();
            }
            runs.push_back(run);
        }
        self.woken();
        id
    }

    fn with(&self, id: u64, edit: impl FnOnce(&mut ToolRun)) {
        {
            let mut runs = self.guard();
            if let Some(run) = runs.iter_mut().find(|r| r.id == id) {
                edit(run);
            }
        }
        self.woken();
    }

    /// Every run, oldest first.
    pub fn snapshot(&self) -> Vec<ToolRun> {
        self.guard().iter().cloned().collect()
    }

    pub fn get(&self, id: u64) -> Option<ToolRun> {
        self.guard().iter().find(|r| r.id == id).cloned()
    }

    /// How many runs are still going.
    pub fn running(&self) -> usize {
        self.guard().iter().filter(|r| r.status == RunStatus::Running).count()
    }

    pub fn append_stdout(&self, id: u64, text: &str) {
        self.with(id, |run| {
            run.stdout.push_str(text);
            keep_within(&mut run.stdout, MAX_STREAM_KEPT);
        });
    }

    pub fn append_stderr(&self, id: u64, text: &str) {
        self.with(id, |run| {
            run.stderr.push_str(text);
            keep_within(&mut run.stderr, MAX_STREAM_KEPT);
        });
    }

    /// A line the run itself has to say -- a step starting or ending -- into the output the
    /// console shows, so the console reads as an account of the whole run rather than of
    /// whichever program happened to be talking.
    pub fn note(&self, id: u64, line: &str) {
        self.append_stdout(id, &format!("\n{line}\n"));
    }

    /// Record how a run ended. A run already finished is left as it was: the first ending is
    /// the true one, and a reader thread arriving late must not undo it.
    pub fn finish(&self, id: u64, status: RunStatus, exit_code: Option<i32>, elapsed_ms: u128) {
        self.with(id, |run| {
            if run.status.finished() {
                return;
            }
            run.status = status;
            run.exit_code = exit_code;
            run.elapsed_ms = elapsed_ms;
        });
    }

    /// How long a run has been going, for the row that is still counting.
    pub fn tick(&self, id: u64, elapsed_ms: u128) {
        self.with(id, |run| {
            if !run.status.finished() {
                run.elapsed_ms = elapsed_ms;
            }
        });
    }

    /// Leave findings for the drawing thread to take into the issue store.
    pub fn offer_findings(&self, id: u64, findings: Vec<Finding>) {
        self.with(id, |run| run.pending_findings.extend(findings));
    }

    /// Take everything waiting, as (run id, findings). Called from the drawing thread.
    pub fn take_findings(&self) -> Vec<(u64, Vec<Finding>)> {
        let mut out = Vec::new();
        for run in self.guard().iter_mut() {
            if !run.pending_findings.is_empty() {
                out.push((run.id, std::mem::take(&mut run.pending_findings)));
            }
        }
        out
    }

    /// Note what reached the issue store, once the drawing thread has put it there.
    pub fn record_imported(&self, id: u64, added: usize, lines: Vec<String>) {
        self.with(id, |run| {
            run.imported_count += added;
            run.imported.extend(lines);
        });
    }

    /// Ask a run to stop. The worker notices within one poll and stops the program.
    pub fn request_cancel(&self, id: u64) {
        let flag = self.guard().iter().find(|r| r.id == id).map(|r| r.cancel.clone());
        if let Some(flag) = flag {
            flag.store(true, Ordering::SeqCst);
        }
        self.woken();
    }

    fn cancel_flag(&self, id: u64) -> Arc<AtomicBool> {
        self.guard()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.cancel.clone())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
    }

    /// Drop the runs that have finished, leaving anything still going.
    pub fn clear_finished(&self) {
        self.guard().retain(|r| !r.status.finished());
        self.woken();
    }
}

impl Default for RunLog {
    fn default() -> Self {
        Self::new(None)
    }
}

/// What became of one program.
struct StepOutcome {
    status: RunStatus,
    exit_code: Option<i32>,
    /// Everything the program wrote on its standard output, up to [`MAX_OUTPUT_READ`].
    stdout: String,
}

/// The temporary files one step asked for, removed when this goes out of scope.
struct StepFiles(Vec<std::path::PathBuf>);

impl Drop for StepFiles {
    fn drop(&mut self) {
        // the messages a step was given do not outlive it, however the step ended
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Read `pipe` to its end, appending what arrives to `kept` and to the run record as it
/// arrives, so the console fills while the program is still working.
fn drain_pipe(
    mut pipe: impl Read + Send + 'static,
    kept: Arc<Mutex<String>>,
    runs: Option<RunLog>,
    id: u64,
    is_stderr: bool,
    // held, never sent on: the channel closes when every reader has ended, which is how the
    // worker waits for them without being able to hang on one
    done: std::sync::mpsc::Sender<()>,
) {
    std::thread::spawn(move || {
        let _done = done;
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // a program's output is bytes; whatever is not text is shown as the
                    // replacement character rather than dropping the run's whole output
                    let chunk = String::from_utf8_lossy(&buf[..n]).into_owned();
                    {
                        let mut kept = kept.lock().unwrap_or_else(|e| e.into_inner());
                        if kept.len() < MAX_OUTPUT_READ {
                            kept.push_str(&chunk);
                        }
                    }
                    if let Some(runs) = &runs {
                        if is_stderr {
                            runs.append_stderr(id, &chunk);
                        } else {
                            runs.append_stdout(id, &chunk);
                        }
                    }
                }
            }
        }
    });
}

/// Run one program and wait for it, enforcing its timeout and honouring `cancel`.
///
/// The program is started directly with its arguments. Any temporary files the template asked
/// for are written for its owner only and removed once the program has finished, whether it
/// succeeded or not.
fn execute(
    tool: &ExternalTool,
    ctx: &ToolContext,
    runs: Option<&RunLog>,
    id: u64,
    cancel: &AtomicBool,
) -> StepOutcome {
    let failed = |message: String| {
        if let Some(runs) = runs {
            runs.append_stderr(id, &format!("{message}\n"));
        }
        StepOutcome { status: RunStatus::Failed, exit_code: None, stdout: String::new() }
    };

    let (wants_req, wants_res) = wants_files(&tool.args);
    let mut temps = StepFiles(Vec::new());
    let mut path_of = |tag: &str, body: &str| -> Result<String, String> {
        let path = temp_file(tag, body).map_err(|e| e.to_string())?;
        let text = path.to_string_lossy().into_owned();
        temps.0.push(path);
        Ok(text)
    };
    let req_file = match wants_req.then(|| path_of("request", &ctx.request)) {
        Some(Ok(path)) => Some(path),
        Some(Err(e)) => return failed(format!("{}: couldn't write the request to a file: {e}", tool.name)),
        None => None,
    };
    let res_file = match wants_res.then(|| path_of("response", &ctx.response)) {
        Some(Ok(path)) => Some(path),
        Some(Err(e)) => return failed(format!("{}: couldn't write the response to a file: {e}", tool.name)),
        None => None,
    };

    let argv = fill(&tokenize(&tool.args), ctx, req_file.as_deref(), res_file.as_deref());
    let feed = stdin_bytes(tool, ctx);
    let program = tool.command.trim().to_string();
    let mut child = match Command::new(&program)
        .args(&argv)
        .stdin(if feed.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return failed(format!("{}: couldn't start {program}: {e}", tool.name)),
    };

    // written on a thread of its own: a program that does not read its input while filling
    // its output pipe would otherwise have both sides waiting on each other
    if let (Some(bytes), Some(mut pipe)) = (feed, child.stdin.take()) {
        std::thread::spawn(move || {
            // a tool that stops reading early is not an error: it has what it wanted. The
            // pipe is dropped here, which is what gives the program its end of input.
            let _ = pipe.write_all(&bytes);
        });
    }
    let out_kept = Arc::new(Mutex::new(String::new()));
    let (reading, read_done) = std::sync::mpsc::channel::<()>();
    if let Some(pipe) = child.stdout.take() {
        drain_pipe(pipe, out_kept.clone(), runs.cloned(), id, false, reading.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        let discard = Arc::new(Mutex::new(String::new()));
        drain_pipe(pipe, discard, runs.cloned(), id, true, reading.clone());
    }
    // the worker's own end of the channel: only the readers' ends are left to close
    drop(reading);

    let started = std::time::Instant::now();
    let timeout = tool.timeout();
    let mut stopped: Option<RunStatus> = None;
    let mut ticked = started;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(_) => break None,
            Ok(None) => {}
        }
        if cancel.load(Ordering::SeqCst) {
            stopped = Some(RunStatus::Cancelled);
        } else if started.elapsed() >= timeout {
            stopped = Some(RunStatus::TimedOut);
        }
        if stopped.is_some() {
            let _ = child.kill();
            // reaped so the program does not stay about as a zombie
            let _ = child.wait();
            break None;
        }
        if let Some(runs) = runs {
            if ticked.elapsed() >= TICK {
                ticked = std::time::Instant::now();
                runs.tick(id, started.elapsed().as_millis());
            }
        }
        std::thread::sleep(POLL);
    };

    // the pipes end when the program does, which is where the output is complete -- unless
    // something it left behind is still holding them, which is what the grace period is for
    let _ = read_done.recv_timeout(READER_GRACE);
    let stdout = out_kept.lock().unwrap_or_else(|e| e.into_inner()).clone();

    if let Some(status) = stopped {
        // what is stopped is the program this started; anything it started itself is its
        // own business, and is left to finish or to be stopped by whatever started it
        let note = match status {
            RunStatus::Cancelled => format!("{}: stopped at your request.", tool.display_name()),
            _ => format!("{}: stopped after {} second(s).", tool.display_name(), timeout.as_secs()),
        };
        if let Some(runs) = runs {
            runs.append_stderr(id, &format!("{note}\n"));
        }
        return StepOutcome { status, exit_code: None, stdout };
    }
    match exit {
        Some(status) if status.success() => {
            StepOutcome { status: RunStatus::Succeeded, exit_code: status.code(), stdout }
        }
        Some(status) => {
            if let Some(runs) = runs {
                let how = match status.code() {
                    Some(code) => format!("{} exited with status {code}", tool.name),
                    None => format!("{} was stopped before it finished", tool.name),
                };
                runs.append_stderr(id, &format!("{how}\n"));
            }
            StepOutcome { status: RunStatus::Failed, exit_code: status.code(), stdout }
        }
        None => StepOutcome { status: RunStatus::Failed, exit_code: None, stdout },
    }
}

/// Read a step's output as a findings document and leave what it reports for the issue store.
fn import_step_findings(outcome: &StepOutcome, ctx: &ToolContext, runs: &RunLog, id: u64) {
    match parse_findings(&outcome.stdout, ctx) {
        Ok(findings) if findings.is_empty() => {
            runs.append_stderr(id, "Findings import: the output named no findings.\n");
        }
        Ok(findings) => runs.offer_findings(id, findings),
        Err(e) => runs.append_stderr(id, &format!("Findings import: {e}\n")),
    }
}

/// Run one registered program on `ctx`, off the drawing thread, tracked in `runs`.
pub fn run_tracked(tool: &ExternalTool, ctx: &ToolContext, runs: &RunLog, events: &crate::proxy::Events) -> u64 {
    let id = runs.begin(&tool.display_name(), RunOrigin::Program(tool.name.trim().to_string()), ctx);
    let (tool, ctx, runs, events) = (tool.clone(), ctx.clone(), runs.clone(), events.clone());
    std::thread::spawn(move || {
        run_tool_blocking(&tool, &ctx, &runs, id, &events);
    });
    id
}

/// The body of [`run_tracked`], on whichever thread calls it. Separated so a test can wait
/// for it.
pub fn run_tool_blocking(
    tool: &ExternalTool,
    ctx: &ToolContext,
    runs: &RunLog,
    id: u64,
    events: &crate::proxy::Events,
) {
    let started = std::time::Instant::now();
    let cancel = runs.cancel_flag(id);
    let outcome = execute(tool, ctx, Some(runs), id, &cancel);
    if tool.import_findings {
        import_step_findings(&outcome, ctx, runs, id);
    }
    runs.finish(id, outcome.status, outcome.exit_code, started.elapsed().as_millis());
    report(events, &tool.display_name(), outcome.status, outcome.exit_code);
}

/// Run `plan`'s steps one after another, off the drawing thread, tracked in `runs`.
pub fn run_plan(
    plan: &AutomationPlan,
    tools: &[ExternalTool],
    ctx: &ToolContext,
    runs: &RunLog,
    events: &crate::proxy::Events,
) -> u64 {
    let id = runs.begin(&plan.display_name(), RunOrigin::Pipeline(plan.name.trim().to_string()), ctx);
    let (plan, tools, ctx, runs, events) =
        (plan.clone(), tools.to_vec(), ctx.clone(), runs.clone(), events.clone());
    std::thread::spawn(move || {
        run_plan_blocking(&plan, &tools, &ctx, &runs, id, &events);
    });
    id
}

/// The body of [`run_plan`], on whichever thread calls it.
///
/// Each step's output is written to a file only its owner can read, which the next step
/// reaches through `{prev_out_file}`. Every one of those files is removed when the pipeline
/// ends, however it ends.
pub fn run_plan_blocking(
    plan: &AutomationPlan,
    tools: &[ExternalTool],
    ctx: &ToolContext,
    runs: &RunLog,
    id: u64,
    events: &crate::proxy::Events,
) {
    let started = std::time::Instant::now();
    let cancel = runs.cancel_flag(id);
    // removed together when the pipeline ends, so no step's output outlives the run
    let mut handoffs = StepFiles(Vec::new());
    let mut prev_out = String::new();
    let mut outcome_status = RunStatus::Succeeded;
    let mut last_code = None;
    let total = plan.steps.len();
    if total == 0 {
        runs.append_stderr(id, "This pipeline has no steps.\n");
    }

    for (n, step) in plan.steps.iter().enumerate() {
        let step_no = n + 1;
        if cancel.load(Ordering::SeqCst) {
            outcome_status = RunStatus::Cancelled;
            runs.note(id, &format!("Stopped at your request before step {step_no}."));
            break;
        }
        let Some(base) = step.resolve(tools).filter(|t| t.is_runnable()) else {
            runs.append_stderr(
                id,
                &format!("Step {step_no}: there is no finished program for {}.\n", step.display_target()),
            );
            outcome_status = RunStatus::Failed;
            if step.on_failure == StepFailurePolicy::Stop {
                break;
            }
            continue;
        };
        // the step's own arguments win over the program's template; its import switch adds
        // to the program's rather than replacing it
        let mut tool = base.clone();
        if !step.args_override.trim().is_empty() {
            tool.args = step.args_override.clone();
        }
        tool.import_findings = tool.import_findings || step.import_findings;

        let mut step_ctx = ctx.clone();
        step_ctx.prev_out_file = prev_out.clone();
        runs.note(id, &format!("Step {step_no} of {total}: {}", tool.display_name()));
        let outcome = execute(&tool, &step_ctx, Some(runs), id, &cancel);
        last_code = outcome.exit_code;
        if tool.import_findings {
            import_step_findings(&outcome, &step_ctx, runs, id);
        }
        runs.note(id, &format!("Step {step_no} {}", outcome.status.label().to_lowercase()));

        // what it wrote becomes the next step's `{prev_out_file}`
        match temp_file(&format!("step{step_no}"), &outcome.stdout) {
            Ok(path) => {
                prev_out = path.to_string_lossy().into_owned();
                handoffs.0.push(path);
            }
            Err(e) => {
                runs.append_stderr(id, &format!("Step {step_no}: couldn't keep its output for the next step: {e}\n"));
                prev_out.clear();
            }
        }

        if outcome.status != RunStatus::Succeeded {
            outcome_status = outcome.status;
            if outcome.status == RunStatus::Cancelled || step.on_failure == StepFailurePolicy::Stop {
                break;
            }
        }
    }
    drop(handoffs);
    runs.finish(id, outcome_status, last_code, started.elapsed().as_millis());
    report(events, &plan.display_name(), outcome_status, last_code);
}

// ---- shareable bundles ---------------------------------------------------

/// The bundle format this build writes. A bundle naming a later one is refused rather than
/// read as far as it goes: a pipeline half understood is worse than one not imported.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// What becomes of one entry arriving in a bundle when something is already registered under
/// its name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Register the arriving one under a name of its own, keeping both.
    #[default]
    KeepBoth,
    /// Let the arriving one take the place of the one already registered.
    Replace,
    /// Leave the one already registered and pass the arriving one over.
    Skip,
}

impl ConflictPolicy {
    pub const ALL: [ConflictPolicy; 3] = [ConflictPolicy::KeepBoth, ConflictPolicy::Replace, ConflictPolicy::Skip];

    pub fn label(self) -> &'static str {
        match self {
            ConflictPolicy::KeepBoth => "Keep both (rename)",
            ConflictPolicy::Replace => "Replace existing",
            ConflictPolicy::Skip => "Skip existing",
        }
    }

    /// The word for this policy on a command line.
    pub fn word(self) -> &'static str {
        match self {
            ConflictPolicy::KeepBoth => "rename",
            ConflictPolicy::Replace => "replace",
            ConflictPolicy::Skip => "skip",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.word().eq_ignore_ascii_case(word.trim()))
    }
}

/// What became of one entry that arrived in a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Nothing was registered under that name, so it was registered as it came.
    Added,
    /// It took the place of the one already registered under that name.
    Replaced,
    /// Something was already registered under that name, so it was registered under this one.
    Renamed(String),
    /// Something was already registered under that name and was left alone.
    Skipped,
}

impl MergeOutcome {
    /// How this reads in the line that says what an import did.
    pub fn describe(&self) -> String {
        match self {
            MergeOutcome::Added => "added".to_string(),
            MergeOutcome::Replaced => "replaced the one already registered".to_string(),
            MergeOutcome::Renamed(to) => format!("already taken, registered as {to:?}"),
            MergeOutcome::Skipped => "skipped: already registered".to_string(),
        }
    }
}

/// What one import did, entry by entry, so it can be printed or shown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Each program that arrived, by the name it arrived under, and what became of it.
    pub tools: Vec<(String, MergeOutcome)>,
    pub plans: Vec<(String, MergeOutcome)>,
}

impl MergeReport {
    /// How many entries actually reached the registry.
    pub fn taken(&self) -> usize {
        self.tools.iter().chain(self.plans.iter()).filter(|(_, o)| *o != MergeOutcome::Skipped).count()
    }

    /// One line per entry, for a terminal or a status line.
    pub fn lines(&self) -> Vec<String> {
        let one = |kind: &str, (name, outcome): &(String, MergeOutcome)| {
            format!("{kind} {name:?}: {}", outcome.describe())
        };
        self.tools
            .iter()
            .map(|e| one("Program", e))
            .chain(self.plans.iter().map(|e| one("Pipeline", e)))
            .collect()
    }
}

/// Programs and pipelines as one file, to be sent to someone else and registered by them.
///
/// A bundle holding a pipeline carries the programs its steps run, so the file is enough on
/// its own: nothing has to be registered beforehand for it to work. Steps are bound by the
/// program's name rather than its place in a registry, which is what lets a pipeline arrive
/// into a registry that already has programs of its own.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AutomationBundle {
    pub format_version: u32,
    pub name: String,
    pub description: String,
    /// Whoever put the bundle together, as they chose to be named. Never filled in from the
    /// account this is running as.
    pub author: String,
    pub tools: Vec<ExternalTool>,
    pub plans: Vec<AutomationPlan>,
}

impl AutomationBundle {
    /// A bundle holding one program.
    pub fn from_tool(tool: &ExternalTool, author: &str) -> Self {
        AutomationBundle {
            format_version: BUNDLE_FORMAT_VERSION,
            name: tool.display_name(),
            description: tool.description.clone(),
            author: author.trim().to_string(),
            tools: vec![tool.clone()],
            plans: Vec::new(),
        }
    }

    /// A bundle holding one pipeline and every program its steps run.
    ///
    /// The programs are gathered from `all_tools` as the steps are walked, so the bundle is
    /// self-contained: whoever imports it needs nothing registered beforehand. A step whose
    /// program is not in `all_tools` any more is carried as it is, and binds to a program of
    /// that name wherever it lands.
    pub fn from_plan(plan: &AutomationPlan, all_tools: &[ExternalTool], author: &str) -> Self {
        let mut tools: Vec<ExternalTool> = Vec::new();
        let mut plan = plan.clone();
        for step in &mut plan.steps {
            let Some(tool) = step.resolve(all_tools) else { continue };
            // bound by name from here on, so the place it had in this registry means nothing
            // to whoever receives it
            step.tool_name = tool.name.trim().to_string();
            if !tools.iter().any(|t| t.name.trim() == tool.name.trim()) {
                tools.push(tool.clone());
            }
        }
        // the places in the bundle's own, smaller list
        bind_steps(&tools, std::slice::from_mut(&mut plan));
        AutomationBundle {
            format_version: BUNDLE_FORMAT_VERSION,
            name: plan.display_name(),
            description: plan.description.clone(),
            author: author.trim().to_string(),
            tools,
            plans: vec![plan],
        }
    }

    /// A bundle holding a whole registry.
    pub fn from_all(tools: &[ExternalTool], plans: &[AutomationPlan], author: &str) -> Self {
        let mut plans = plans.to_vec();
        bind_steps(tools, &mut plans);
        AutomationBundle {
            format_version: BUNDLE_FORMAT_VERSION,
            name: "Automation registry".to_string(),
            description: String::new(),
            author: author.trim().to_string(),
            tools: tools.to_vec(),
            plans,
        }
    }

    /// Read a bundle from JSON.
    ///
    /// A whole bundle is read as one. So is a bare program or a bare pipeline, which is what
    /// someone pasting a single entry out of a settings file will have: either is wrapped in a
    /// bundle of its own rather than refused on a technicality.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let doc: serde_json::Value =
            serde_json::from_str(text.trim()).map_err(|e| format!("this is not JSON ({e})."))?;
        let fields = doc.as_object().ok_or("a bundle is a JSON object, and this is not one.")?;
        let named = |key: &str| fields.contains_key(key);
        if named("steps") && !named("plans") {
            let plan: AutomationPlan =
                serde_json::from_value(doc).map_err(|e| format!("this is not a pipeline ({e})."))?;
            return Ok(AutomationBundle {
                format_version: BUNDLE_FORMAT_VERSION,
                name: plan.display_name(),
                description: plan.description.clone(),
                plans: vec![plan],
                ..Default::default()
            });
        }
        if named("command") && !named("tools") {
            let tool: ExternalTool =
                serde_json::from_value(doc).map_err(|e| format!("this is not a program ({e})."))?;
            return Ok(Self::from_tool(&tool, ""));
        }
        let mut bundle: Self =
            serde_json::from_value(doc).map_err(|e| format!("this is not a bundle ({e})."))?;
        if bundle.format_version > BUNDLE_FORMAT_VERSION {
            return Err(format!(
                "this bundle is in format {}, which this build does not read; it understands up to {BUNDLE_FORMAT_VERSION}.",
                bundle.format_version
            ));
        }
        if bundle.tools.is_empty() && bundle.plans.is_empty() {
            return Err("this bundle holds no programs and no pipelines.".to_string());
        }
        bundle.format_version = BUNDLE_FORMAT_VERSION;
        Ok(bundle)
    }

    /// The bundle as the file that is sent: laid out to be read and reviewed before it is
    /// trusted, not packed as small as it will go.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map(|mut s| {
            s.push('\n');
            s
        })
        .map_err(|e| e.to_string())
    }

    /// Is a program of this name already registered?
    pub fn tool_is_registered(settings: &crate::state::UserSettings, name: &str) -> bool {
        settings.external_tools.iter().any(|t| t.name.trim() == name.trim())
    }

    /// Is a pipeline of this name already saved?
    pub fn plan_is_registered(settings: &crate::state::UserSettings, name: &str) -> bool {
        settings.automation_plans.iter().any(|p| p.name.trim() == name.trim())
    }

    /// Register everything in this bundle, settling each name that is already taken the way
    /// `policy` says.
    ///
    /// Each step is then pointed at whatever the program it named actually became: renamed if
    /// it had to be, left where it was if the arriving one was skipped. Every step's place in
    /// the registry is worked out again at the end, so the merged settings are consistent
    /// however the two lists happened to be ordered.
    pub fn merge_into(&self, settings: &mut crate::state::UserSettings, policy: ConflictPolicy) -> MergeReport {
        let mut report = MergeReport::default();
        // what each program in the bundle is called once it is registered, so the steps that
        // name it can be pointed at the right one
        let mut landed: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        for tool in &self.tools {
            let arrived = tool.name.trim().to_string();
            let at = settings.external_tools.iter().position(|t| t.name.trim() == arrived);
            let outcome = match (at, policy) {
                (None, _) => {
                    settings.external_tools.push(tool.clone());
                    MergeOutcome::Added
                }
                (Some(i), ConflictPolicy::Replace) => {
                    settings.external_tools[i] = tool.clone();
                    MergeOutcome::Replaced
                }
                (Some(_), ConflictPolicy::Skip) => MergeOutcome::Skipped,
                (Some(_), ConflictPolicy::KeepBoth) => {
                    let taken: Vec<String> =
                        settings.external_tools.iter().map(|t| t.name.trim().to_string()).collect();
                    let free = free_name(&arrived, &taken);
                    settings.external_tools.push(ExternalTool { name: free.clone(), ..tool.clone() });
                    MergeOutcome::Renamed(free)
                }
            };
            let now = match &outcome {
                MergeOutcome::Renamed(to) => to.clone(),
                _ => arrived.clone(),
            };
            landed.insert(arrived.clone(), now);
            report.tools.push((arrived, outcome));
        }

        for plan in &self.plans {
            let mut plan = plan.clone();
            // each step follows the program it named to wherever that program ended up; a step
            // naming one the bundle did not carry is left to bind against what is registered
            for step in &mut plan.steps {
                let named = match step.resolve(&self.tools) {
                    Some(tool) => tool.name.trim().to_string(),
                    None => step.tool_name.trim().to_string(),
                };
                if let Some(now) = landed.get(&named) {
                    step.tool_name = now.clone();
                } else if !named.is_empty() {
                    step.tool_name = named;
                }
            }
            let arrived = plan.name.trim().to_string();
            let at = settings.automation_plans.iter().position(|p| p.name.trim() == arrived);
            let outcome = match (at, policy) {
                (None, _) => {
                    settings.automation_plans.push(plan);
                    MergeOutcome::Added
                }
                (Some(i), ConflictPolicy::Replace) => {
                    settings.automation_plans[i] = plan;
                    MergeOutcome::Replaced
                }
                (Some(_), ConflictPolicy::Skip) => MergeOutcome::Skipped,
                (Some(_), ConflictPolicy::KeepBoth) => {
                    let taken: Vec<String> =
                        settings.automation_plans.iter().map(|p| p.name.trim().to_string()).collect();
                    let free = free_name(&arrived, &taken);
                    plan.name = free.clone();
                    settings.automation_plans.push(plan);
                    MergeOutcome::Renamed(free)
                }
            };
            report.plans.push((arrived, outcome));
        }

        let tools = settings.external_tools.clone();
        bind_steps(&tools, &mut settings.automation_plans);
        report
    }
}

/// A name like `base` that nothing in `taken` already answers to, by numbering it.
fn free_name(base: &str, taken: &[String]) -> String {
    let base = base.trim();
    let free = |candidate: &str| !taken.iter().any(|t| t.trim() == candidate);
    if free(base) {
        return base.to_string();
    }
    // `taken` is finite, so some number is free
    (2..).map(|n| format!("{base} ({n})")).find(|c| free(c)).unwrap_or_else(|| base.to_string())
}

/// Read a bundle from a file.
pub fn read_bundle(path: &std::path::Path) -> Result<AutomationBundle, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("Couldn't read {}: {e}", path.display()))?;
    AutomationBundle::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Write a bundle to a file, making the folder above it if it is not there yet.
pub fn write_bundle(bundle: &AutomationBundle, path: &std::path::Path) -> Result<(), String> {
    let json = bundle.to_json()?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("Couldn't make {}: {e}", parent.display()))?;
    }
    std::fs::write(path, json).map_err(|e| format!("Couldn't write {}: {e}", path.display()))
}

/// What a pipeline run with no window behind it came to.
#[derive(Clone, Debug)]
pub struct HeadlessOutcome {
    pub status: RunStatus,
    /// The exit status of the last step that had one.
    pub exit_code: Option<i32>,
    pub elapsed_ms: u128,
    /// Findings the steps reported, as parsed, before consolidation.
    pub findings: Vec<Finding>,
}

/// How often an unattended run looks for more output to pass on to the terminal. Short enough
/// that a step's output reads as it arrives, long enough not to spin.
const STREAM_POLL: std::time::Duration = std::time::Duration::from_millis(40);

/// Run one registered program to completion with no drawn app behind it, writing the account
/// of it to `out` as it arrives. The pipeline runner's own account of itself, for one program.
pub fn run_tool_streaming(tool: &ExternalTool, ctx: &ToolContext, out: &mut dyn std::io::Write) -> HeadlessOutcome {
    let runs = RunLog::new(None);
    let events: crate::proxy::Events = Default::default();
    let id = runs.begin(&tool.display_name(), RunOrigin::Program(tool.name.trim().to_string()), ctx);
    let worker = {
        let (tool, ctx, runs, events) = (tool.clone(), ctx.clone(), runs.clone(), events.clone());
        std::thread::spawn(move || run_tool_blocking(&tool, &ctx, &runs, id, &events))
    };
    stream_until_done(&runs, id, worker, out)
}

/// Run `plan` to completion with no drawn app behind it, writing the account of it to `out`
/// as it arrives.
///
/// The engine is the same one the Automation tab uses -- [`run_plan_blocking`], with its
/// placeholders, timeouts, failure policies and owner-only temporary files -- run on a worker
/// here so this thread can pass the output on while it is still being produced. The findings
/// the steps reported come back rather than being filed: there is no issue store out here, and
/// the caller knows where they are to go.
///
/// A run record keeps at most [`MAX_STREAM_KEPT`] of each stream, so that is also as much of
/// each as reaches the terminal; the whole of a step's output still goes to the findings
/// parser and on to the next step.
pub fn run_plan_streaming(
    plan: &AutomationPlan,
    tools: &[ExternalTool],
    ctx: &ToolContext,
    out: &mut dyn std::io::Write,
) -> HeadlessOutcome {
    let runs = RunLog::new(None);
    let events: crate::proxy::Events = Default::default();
    let id = runs.begin(&plan.display_name(), RunOrigin::Pipeline(plan.name.trim().to_string()), ctx);
    let worker = {
        let (plan, tools, ctx, runs, events) =
            (plan.clone(), tools.to_vec(), ctx.clone(), runs.clone(), events.clone());
        std::thread::spawn(move || run_plan_blocking(&plan, &tools, &ctx, &runs, id, &events))
    };
    stream_until_done(&runs, id, worker, out)
}

/// Pass run `id`'s output on to `out` until it has finished, then say what it came to.
fn stream_until_done(
    runs: &RunLog,
    id: u64,
    worker: std::thread::JoinHandle<()>,
    out: &mut dyn std::io::Write,
) -> HeadlessOutcome {
    // what has already been passed on, so each look only writes what is new
    let (mut sent_out, mut sent_err) = (0usize, 0usize);
    let mut pass_on = |run: &ToolRun, out: &mut dyn std::io::Write| {
        // a stream that was truncated is shorter than what went before it; start again from
        // the end of what it holds now rather than writing it a second time
        for (text, sent) in [(&run.stdout, &mut sent_out), (&run.stderr, &mut sent_err)] {
            if text.len() < *sent {
                *sent = text.len();
            }
            if text.len() > *sent {
                let _ = out.write_all(text[*sent..].as_bytes());
                let _ = out.flush();
                *sent = text.len();
            }
        }
    };
    loop {
        let Some(run) = runs.get(id) else { break };
        pass_on(&run, out);
        if run.status.finished() {
            break;
        }
        std::thread::sleep(STREAM_POLL);
    }
    // the worker finishes the record before it returns, so joining it settles any last write
    let _ = worker.join();
    let run = runs.get(id);
    if let Some(run) = &run {
        pass_on(run, out);
    }
    let findings = runs.take_findings().into_iter().flat_map(|(_, f)| f).collect();
    match run {
        Some(run) => HeadlessOutcome {
            status: run.status,
            exit_code: run.exit_code,
            elapsed_ms: run.elapsed_ms,
            findings,
        },
        // the record cannot go missing (nothing clears it here), but a lost run is a failed
        // one rather than a silent success
        None => HeadlessOutcome { status: RunStatus::Failed, exit_code: None, elapsed_ms: 0, findings },
    }
}

/// Say in the event log how a run went, as the "Send to" menus always did.
fn report(events: &crate::proxy::Events, label: &str, status: RunStatus, exit_code: Option<i32>) {
    let note = match (status, exit_code) {
        (RunStatus::Succeeded, _) => format!("{label} finished"),
        (RunStatus::TimedOut, _) => format!("{label} was stopped: it ran out of time"),
        (RunStatus::Cancelled, _) => format!("{label} was stopped"),
        (_, Some(code)) => format!("{label} exited with status {code}"),
        (_, None) => format!("{label} did not run"),
    };
    match status {
        RunStatus::Succeeded => crate::proxy::log(events, note),
        RunStatus::Cancelled => crate::proxy::log_warning(events, note),
        _ => crate::proxy::log_error(events, note),
    }
}

/// A finding's CWE as a program writes it: a number (`79`) or a label (`"CWE-79"`, any case).
/// Anything else, or nothing, means the program named no weakness class.
fn cwe_of(v: &serde_json::Value) -> Option<u32> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        serde_json::Value::String(s) => {
            let s = s.trim();
            let digits = if s.len() > 4 && s[..4].eq_ignore_ascii_case("cwe-") { &s[4..] } else { s };
            digits.parse().ok()
        }
        _ => None,
    }
}

/// A findings document, as a sample for the Automation tab's "Copy sample schema" button.
pub const SAMPLE_FINDINGS_JSON: &str = r#"{
  "findings": [
    {
      "title": "Session cookie is not marked HttpOnly",
      "severity": "medium",
      "confidence": "certain",
      "url": "https://shop.test/account",
      "detail": "The session cookie can be read by page scripts.",
      "remediation": "Set the HttpOnly attribute when the cookie is issued.",
      "cwe": "CWE-1004",
      "request": "GET /account HTTP/1.1\r\nHost: shop.test\r\n\r\n",
      "response": "HTTP/1.1 200 OK\r\n\r\n"
    }
  ]
}
"#;

/// Read a program's output as a findings document.
///
/// Two shapes are accepted: an object with a `findings` list, and a bare list of the same
/// objects. Within one finding only the title is required; anything else missing is taken
/// from `ctx` or from the defaults an imported finding starts with. An entry with no title
/// is passed over rather than failing the whole document, because one bad entry in a long
/// report should cost that entry alone.
pub fn parse_findings(text: &str, ctx: &ToolContext) -> Result<Vec<Finding>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("the program wrote nothing on its standard output".to_string());
    }
    let doc: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("the output is not JSON ({e})"))?;
    let items: &Vec<serde_json::Value> = match &doc {
        serde_json::Value::Array(list) => list,
        serde_json::Value::Object(map) => match map.get("findings") {
            Some(serde_json::Value::Array(list)) => list,
            Some(_) => return Err("\"findings\" is there, but it is not a list".to_string()),
            None => return Err("the object has no \"findings\" list".to_string()),
        },
        _ => return Err("the JSON is neither a list of findings nor an object holding one".to_string()),
    };

    let fallback_url = ctx.url.trim();
    let mut out = Vec::new();
    for item in items {
        let Some(fields) = item.as_object() else { continue };
        let text_of = |key: &str| {
            fields.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())
        };
        let Some(title) = text_of("title").or_else(|| text_of("name")) else { continue };
        let url = text_of("url").unwrap_or(fallback_url);
        let (host, path) = crate::http::split_url(url);
        out.push(Finding {
            // "type_index" is what documents written for ForgeProxy 1.0.x called it
            cwe: match fields.get("cwe") {
                Some(v) => cwe_of(v).unwrap_or(crate::scan::NO_CWE),
                None => fields.get("type_index").and_then(cwe_of).map_or(crate::scan::NO_CWE, crate::scan::cwe_from_legacy),
            },
            name: title.to_string(),
            severity: text_of("severity").map_or(Severity::Info, Severity::from_name),
            confidence: text_of("confidence").map_or(Confidence::Firm, Confidence::from_name),
            host,
            path,
            detail: text_of("detail").or_else(|| text_of("description")).unwrap_or_default().to_string(),
            remediation: text_of("remediation").unwrap_or_default().to_string(),
            // a finding that names no exchange of its own belongs to the one the run was
            // started on, which is the only one it can have been about
            request: text_of("request").unwrap_or(ctx.request.as_str()).to_string(),
            response: text_of("response").unwrap_or(ctx.response.as_str()).to_string(),
            point: text_of("point").unwrap_or_default().to_string(),
            payload: text_of("payload").unwrap_or_default().to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    /// A run store and an event log, as a drawn app would hand to a worker -- without the
    /// egui context, so nothing here asks for a repaint.
    fn harness() -> (RunLog, crate::proxy::Events) {
        (RunLog::new(None), Arc::new(Mutex::new(Default::default())))
    }

    /// The interpreter the test scripts are handed to. They are *read* by it rather than
    /// executed themselves, which matters: a file this process has only just written cannot
    /// reliably be executed while sibling tests are starting programs of their own. Any one
    /// of their forks inherits the write handle for the moment before it execs, and the
    /// kernel refuses to execute a file another process holds open for writing ("text file
    /// busy"). Nothing here needs the file to be executable, so nothing here asks it to be.
    const SHELL: &str = "/bin/sh";

    /// A shell script in a directory of this test's own, as arguments for [`SHELL`]: the
    /// script's path, and whatever else is given after it.
    fn script(dir: &std::path::Path, name: &str, body: &str) -> String {
        std::fs::create_dir_all(dir).expect("a place to work");
        let path = dir.join(name);
        std::fs::write(&path, body).expect("the script");
        path.to_string_lossy().into_owned()
    }

    /// A program entry that runs `body` as a script, with `args` after the script's path.
    fn shell_tool(dir: &std::path::Path, name: &str, body: &str, args: &str) -> ExternalTool {
        let path = script(dir, &format!("{name}.sh"), body);
        ExternalTool {
            name: name.to_string(),
            command: SHELL.to_string(),
            args: format!("{path} {args}").trim_end().to_string(),
            ..Default::default()
        }
    }

    /// A directory of this test's own, named for the test using it.
    fn work_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("forge-automation-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a place to work");
        dir
    }

    /// An argument template splits the way a person expects: on whitespace, with a quoted run
    /// kept together, and nothing else read into it.
    #[test]
    fn a_template_splits_into_arguments_matrix() {
        let cases: [(&str, Vec<&str>); 7] = [
            ("", vec![]),
            ("--json", vec!["--json"]),
            ("-a -b -c", vec!["-a", "-b", "-c"]),
            ("  spaced   out  ", vec!["spaced", "out"]),
            (r#"--note "two words" --flag"#, vec!["--note", "two words", "--flag"]),
            (r#"--note 'two words'"#, vec!["--note", "two words"]),
            (r#"--empty "" --after"#, vec!["--empty", "", "--after"]),
        ];
        assert_table!(cases, |idx, (template, want)| {
            assert_eq!(tokenize(template), want, "case #{idx}: {template:?}");
        });
    }

    /// The point of the whole design: whatever a placeholder stands for becomes part of one
    /// argument, however it is punctuated. A shell's metacharacters are just characters here,
    /// because the program is started directly and there is no shell to read them.
    #[test]
    fn what_a_placeholder_stands_for_stays_one_argument_matrix() {
        let nasty: [&str; 7] = [
            "http://h.test/?q=1;rm -rf /",
            "http://h.test/$(id)",
            "http://h.test/`id`",
            "http://h.test/?a=1&&b=2|c",
            r#"http://h.test/?q="quoted" 'and' more"#,
            "http://h.test/?q=$HOME\n--extra-flag",
            "http://h.test/?q=>out <in",
        ];
        assert_table!(nasty, |idx, url| {
            let ctx = ToolContext { url: url.to_string(), ..Default::default() };
            let argv = fill(&tokenize("--target {url} --done"), &ctx, None, None);
            assert_eq!(argv.len(), 3, "case #{idx}: still three arguments, got {argv:?}");
            assert_eq!(argv[0], "--target", "case #{idx}");
            assert_eq!(argv[1], url, "case #{idx}: the address arrived whole and unaltered");
            assert_eq!(argv[2], "--done", "case #{idx}: and nothing leaked into what follows");
        });
    }

    /// Every placeholder the Settings page advertises is one `fill` actually replaces, so the
    /// list shown to the user cannot drift from what works.
    #[test]
    fn every_advertised_placeholder_is_filled_in() {
        let ctx = ToolContext {
            prev_out_file: "/tmp/prev".into(),
            url: "https://shop.test:8443/cart?a=1".into(),
            scheme: "https".into(),
            host: "shop.test:8443".into(),
            port: "8443".into(),
            method: "POST".into(),
            path: "/cart?a=1".into(),
            request: "POST /cart?a=1 HTTP/1.1\r\nHost: shop.test\r\n\r\nx=1".into(),
            response: "HTTP/1.1 200 OK\r\n\r\nok".into(),
            // `{var:KEY}` is advertised like the rest, so a value for KEY is part of the
            // message this is filled from
            vars: [("KEY".to_string(), "given".to_string())].into_iter().collect(),
        };
        for (token, _) in PLACEHOLDERS {
            let argv = fill(&tokenize(token), &ctx, Some("/tmp/req"), Some("/tmp/res"));
            assert_eq!(argv.len(), 1, "{token} is one argument");
            assert!(!argv[0].contains('{'), "{token} was left unfilled: {:?}", argv[0]);
            assert!(!argv[0].is_empty(), "{token} filled in as nothing");
        }
        // and one not on the list is left exactly as written, rather than silently blanked
        let argv = fill(&tokenize("{not_a_placeholder}"), &ctx, None, None);
        assert_eq!(argv[0], "{not_a_placeholder}");
    }

    /// Each way of feeding a tool is named once and gives it what it says.
    #[test]
    fn the_stdin_modes_are_distinct_and_give_what_they_name() {
        let labels: Vec<&str> = ToolStdinMode::ALL.iter().map(|m| m.label()).collect();
        assert_eq!(labels.len(), 4);
        for m in ToolStdinMode::ALL {
            assert_eq!(ToolStdinMode::ALL.iter().filter(|o| o.label() == m.label()).count(), 1, "{:?}", m);
        }
        assert_eq!(ToolStdinMode::default(), ToolStdinMode::None, "a new tool is given nothing until asked");

        let ctx = ToolContext {
            method: "GET".into(),
            url: "http://h.test/a".into(),
            request: "GET /a HTTP/1.1\r\nHost: h.test\r\nX-Tag: one\r\n\r\nbody-in".into(),
            response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody-out".into(),
            ..Default::default()
        };
        let feed = |mode| {
            let tool = ExternalTool { name: "t".into(), command: "true".into(), stdin_mode: mode, ..Default::default() };
            stdin_bytes(&tool, &ctx).map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        assert_eq!(feed(ToolStdinMode::None), None);
        assert_eq!(feed(ToolStdinMode::RawRequest).as_deref(), Some(ctx.request.as_str()));
        assert_eq!(feed(ToolStdinMode::RawResponse).as_deref(), Some(ctx.response.as_str()));

        // the envelope describes the exchange without the tool having to parse HTTP
        let json: serde_json::Value = serde_json::from_str(&json_envelope(&ctx)).expect("the envelope is JSON");
        assert_eq!(json["method"], "GET");
        assert_eq!(json["url"], "http://h.test/a");
        assert_eq!(json["request"]["body"], "body-in");
        assert_eq!(json["response"]["body"], "body-out");
        assert_eq!(json["request"]["headers"][1][0], "X-Tag", "the headers come through as pairs");
        assert_eq!(json["request"]["headers"][1][1], "one");
        assert_eq!(json["request"]["body_base64"], false);
        // the first line is not a header
        assert_eq!(json["request"]["headers"][0][0], "Host");
    }

    /// A tool with nothing to run is not offered, so an unfinished row in Settings cannot
    /// reach a menu.
    #[test]
    fn only_a_finished_tool_is_offered_matrix() {
        let cases: [(&str, &str, bool); 5] = [
            ("named and runnable", "jq", true),
            ("", "jq", false),
            ("named", "", false),
            ("   ", "jq", false),
            ("named", "   ", false),
        ];
        assert_table!(cases, |idx, (name, command, want)| {
            let tool = ExternalTool { name: name.into(), command: command.into(), ..Default::default() };
            assert_eq!(tool.is_runnable(), want, "case #{idx}: {name:?} / {command:?}");
        });
    }

    /// End to end against a real program: the raw request arrives on its standard input, the
    /// temporary file the template asked for exists while it runs, and is gone afterwards.
    #[test]
    fn a_tool_is_run_with_its_file_and_its_input_and_the_file_is_cleaned_up() {
        // a tiny script that proves what it was given: it copies stdin and the file it was
        // pointed at into an output path, so the test can read both back
        let dir = work_dir("probe");
        let out = dir.join("seen.txt");

        // the request carries a marker of this run's own, because the temporary directory is
        // shared: another copy of this suite running beside it has files in there too, and
        // "nothing was left behind" has to mean *this* message, not any message
        let marker = format!("X-Probe: {}-{}", std::process::id(), unique_tag());
        let ctx = ToolContext {
            url: "http://h.test/a".into(),
            request: format!("GET /a HTTP/1.1\r\nHost: h.test\r\n{marker}\r\n\r\n"),
            response: "HTTP/1.1 200 OK\r\n\r\nok".into(),
            ..Default::default()
        };
        let tool = ExternalTool {
            stdin_mode: ToolStdinMode::RawRequest,
            ..shell_tool(
                &dir,
                "probe",
                "# $1 is where to write, $2 is the request file\ncat > \"$1.stdin\"\ncp \"$2\" \"$1.file\"\n",
                &format!("{} {{req_file}}", out.display()),
            )
        };
        let (runs, events) = harness();
        let id = runs.begin("probe", RunOrigin::Program("probe".into()), &ctx);
        run_tool_blocking(&tool, &ctx, &runs, id, &events);
        let run = runs.get(id).expect("the run was recorded");
        assert_eq!(run.status, RunStatus::Succeeded, "it ran: {}", run.stderr);
        assert_eq!(run.exit_code, Some(0));

        let from_stdin = std::fs::read_to_string(format!("{}.stdin", out.display())).expect("stdin reached it");
        assert_eq!(from_stdin, ctx.request, "the raw request arrived on standard input");
        let from_file = std::fs::read_to_string(format!("{}.file", out.display())).expect("the file reached it");
        assert_eq!(from_file, ctx.request, "and the same message was in the file");

        // and nothing holding it is left behind in the temporary directory
        let leftovers: Vec<std::path::PathBuf> = std::fs::read_dir(std::env::temp_dir().join("forgeproxy-tools"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| std::fs::read_to_string(p).is_ok_and(|held| held.contains(&marker)))
                    .collect()
            })
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "the request file was removed: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A program that is not there, and one that fails, are both recorded as having failed
    /// and say so on the run's standard error rather than being passed over in silence.
    #[test]
    fn a_tool_that_cannot_run_or_fails_is_reported_matrix() {
        let cases: [(&str, &str, &str, Option<i32>); 2] = [
            ("missing", "forgeproxy-no-such-program", "couldn't start", None),
            ("failing", "false", "status 1", Some(1)),
        ];
        assert_table!(cases, |idx, (name, command, says, code)| {
            let ctx = ToolContext::default();
            let tool = ExternalTool { name: name.into(), command: command.into(), ..Default::default() };
            let (runs, events) = harness();
            let id = runs.begin(name, RunOrigin::Program(name.into()), &ctx);
            run_tool_blocking(&tool, &ctx, &runs, id, &events);
            let run = runs.get(id).expect("the run was recorded");
            assert_eq!(run.status, RunStatus::Failed, "case #{idx} ({name})");
            assert_eq!(run.exit_code, code, "case #{idx} ({name})");
            assert!(run.stderr.contains(name), "case #{idx} ({name}): named in {:?}", run.stderr);
            assert!(run.stderr.contains(says), "case #{idx} ({name}): said why in {:?}", run.stderr);
            // and the event log heard about it too
            let log = events.lock().unwrap();
            assert!(log.iter().any(|e| e.message.contains(name)), "case #{idx} ({name}): {:?}", log);
        });
    }

    /// A findings document is read in both shapes, and each field falls back to what the run
    /// was started on when the document does not name it.
    #[test]
    fn a_findings_document_is_read_in_both_shapes_matrix() {
        let ctx = ToolContext {
            url: "https://shop.test/cart".into(),
            request: "GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n".into(),
            response: "HTTP/1.1 200 OK\r\n\r\nok".into(),
            ..Default::default()
        };
        let one = r#"{"title":"Session fixation","severity":"HIGH","confidence":"Certain",
                      "url":"https://shop.test/login","detail":"d","remediation":"r",
                      "cwe":"cwe-384","request":"GET /login HTTP/1.1\r\n\r\n","response":"HTTP/1.1 302\r\n\r\n"}"#;
        let cases: [(&str, String); 2] = [
            ("an object with a findings list", format!(r#"{{"findings":[{one}]}}"#)),
            ("a bare list", format!("[{one}]")),
        ];
        assert_table!(cases, |idx, (what, doc)| {
            let found = parse_findings(&doc, &ctx).unwrap_or_else(|e| panic!("case #{idx} ({what}): {e}"));
            assert_eq!(found.len(), 1, "case #{idx} ({what})");
            let f = &found[0];
            assert_eq!(f.name, "Session fixation", "case #{idx} ({what})");
            assert_eq!(f.severity, Severity::High, "case #{idx} ({what}): however it was cased");
            assert_eq!(f.confidence, Confidence::Certain, "case #{idx} ({what})");
            assert_eq!((f.host.as_str(), f.path.as_str()), ("shop.test", "/login"), "case #{idx} ({what})");
            assert_eq!((f.detail.as_str(), f.remediation.as_str()), ("d", "r"), "case #{idx} ({what})");
            assert_eq!(f.cwe, 384, "case #{idx} ({what}): a CWE label, however it was cased");
            assert!(f.request.contains("/login") && f.response.contains("302"), "case #{idx} ({what})");
        });

        // every field but the title left out: the run's own address and exchange stand in,
        // and the defaults an imported finding starts with apply
        let bare = parse_findings(r#"[{"name":"Only a name"}]"#, &ctx).expect("it reads");
        assert_eq!(bare.len(), 1);
        let f = &bare[0];
        assert_eq!(f.name, "Only a name", "\"name\" is accepted in place of \"title\"");
        assert_eq!(f.severity, Severity::Info, "an unsaid severity is informational");
        assert_eq!(f.confidence, Confidence::Firm, "an unsaid confidence is firm");
        assert_eq!((f.host.as_str(), f.path.as_str()), ("shop.test", "/cart"), "the run's own address");
        assert_eq!(f.request, ctx.request, "and the exchange it was started on");
        assert_eq!(f.response, ctx.response);
        assert_eq!(f.cwe, crate::scan::NO_CWE, "with no weakness class named");

        // a plain number is a CWE too, and the 1.0.x "type_index" still reads
        let numbered = parse_findings(r#"[{"title":"t","cwe":89},{"title":"u","type_index":1049088}]"#, &ctx).expect("reads");
        assert_eq!((numbered[0].cwe, numbered[1].cwe), (89, crate::scan::SQL_INJECTION.0));
        assert!(f.detail.is_empty() && f.remediation.is_empty());

        // "description" is read where "detail" is absent
        let described = parse_findings(r#"[{"title":"t","description":"from description"}]"#, &ctx).expect("reads");
        assert_eq!(described[0].detail, "from description");

        // the sample the Automation tab offers is itself a document this parser accepts
        let sample = parse_findings(SAMPLE_FINDINGS_JSON, &ctx).expect("the sample is valid");
        assert_eq!(sample.len(), 1, "the sample holds one finding");
        assert_eq!(sample[0].severity, Severity::Medium);
    }

    /// Severity and confidence names are read whatever their case, and a word this build does
    /// not know falls back rather than costing the finding.
    #[test]
    fn severity_and_confidence_names_are_normalised_matrix() {
        let severities: [(&str, Severity); 9] = [
            ("high", Severity::High),
            ("HIGH", Severity::High),
            ("  High  ", Severity::High),
            ("medium", Severity::Medium),
            ("Medium", Severity::Medium),
            ("low", Severity::Low),
            ("information", Severity::Info),
            ("INFORMATION", Severity::Info),
            ("something else entirely", Severity::Info),
        ];
        assert_table!(severities, |idx, (name, want)| {
            assert_eq!(Severity::from_name(name), want, "case #{idx}: {name:?}");
        });
        let confidences: [(&str, Confidence); 6] = [
            ("certain", Confidence::Certain),
            ("CERTAIN", Confidence::Certain),
            ("firm", Confidence::Firm),
            ("tentative", Confidence::Tentative),
            ("Tentative", Confidence::Tentative),
            ("anything else", Confidence::Firm),
        ];
        assert_table!(confidences, |idx, (name, want)| {
            assert_eq!(Confidence::from_name(name), want, "case #{idx}: {name:?}");
        });
    }

    /// Output that is not a findings document is turned down with a reason, and an entry with
    /// no title is passed over without costing the rest of the document.
    #[test]
    fn malformed_findings_output_is_turned_down_with_a_reason_matrix() {
        let ctx = ToolContext { url: "http://h.test/".into(), ..Default::default() };
        let cases: [(&str, &str, &str); 6] = [
            ("nothing at all", "", "nothing on its standard output"),
            ("white space only", "   \n  ", "nothing on its standard output"),
            ("not JSON", "I had a look and it seemed fine", "not JSON"),
            ("JSON cut short", r#"{"findings":[{"title":"a"}"#, "not JSON"),
            ("an object with no findings list", r#"{"issues":[]}"#, "no \"findings\" list"),
            ("findings that is not a list", r#"{"findings":"lots"}"#, "not a list"),
        ];
        assert_table!(cases, |idx, (what, doc, says)| {
            let err = parse_findings(doc, &ctx).expect_err(&format!("case #{idx} ({what}) should be refused"));
            assert!(err.contains(says), "case #{idx} ({what}): expected {says:?} in {err:?}");
        });

        // a document that is a list of something other than findings reads as no findings
        assert!(parse_findings("[1, 2, 3]", &ctx).expect("a list is a shape it accepts").is_empty());
        // one bad entry costs that entry alone
        let mixed = parse_findings(r#"[{"title":"kept"},{"severity":"high"},{"title":"  "},{"name":"also kept"}]"#, &ctx)
            .expect("it reads");
        let names: Vec<&str> = mixed.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["kept", "also kept"], "the entries with no title were passed over");
    }

    /// A program whose output is a findings document has what it reports left on the run for
    /// the issue store, counted and listed.
    #[test]
    fn a_program_that_reports_findings_has_them_taken_from_its_output() {
        let dir = work_dir("import");
        let tool = ExternalTool {
            import_findings: true,
            ..shell_tool(
                &dir,
                "reporter",
                "cat <<'END'\n{\"findings\":[{\"title\":\"Reported issue\",\"severity\":\"low\"}]}\nEND\n",
                "",
            )
        };
        let ctx = ToolContext { url: "http://h.test/a".into(), ..Default::default() };
        let (runs, events) = harness();
        let id = runs.begin("reporter", RunOrigin::Program("reporter".into()), &ctx);
        run_tool_blocking(&tool, &ctx, &runs, id, &events);

        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::Succeeded, "{}", run.stderr);
        assert!(run.stdout.contains("Reported issue"), "the output was kept: {:?}", run.stdout);
        let waiting = runs.take_findings();
        assert_eq!(waiting.len(), 1, "one run has findings waiting");
        assert_eq!(waiting[0].0, id);
        assert_eq!(waiting[0].1.len(), 1);
        assert_eq!(waiting[0].1[0].severity, Severity::Low);
        // and taking them leaves nothing waiting a second time
        assert!(runs.take_findings().is_empty(), "they are handed over once");

        // a program told to report findings that writes something else says so on its own
        // standard error rather than failing the run
        let tool = ExternalTool {
            import_findings: true,
            ..shell_tool(&dir, "chatty", "echo not a findings document\n", "")
        };
        let id = runs.begin("chatty", RunOrigin::Program("chatty".into()), &ctx);
        run_tool_blocking(&tool, &ctx, &runs, id, &events);
        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::Succeeded, "the program itself was fine");
        assert!(run.stderr.contains("Findings import"), "but the import is reported: {:?}", run.stderr);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pipeline runs its steps in order, hands each step's output to the next through
    /// `{prev_out_file}`, and removes every one of those files when it ends.
    #[test]
    fn a_pipeline_runs_in_order_and_hands_its_output_on() {
        let dir = work_dir("pipeline");
        let trace = dir.join("trace.txt");
        // step one says who it is; step two copies what step one wrote, and the file's own
        // path, so the test can see both the handoff and that the file was there
        let tools = vec![
            shell_tool(&dir, "first", "echo from-step-one\n", ""),
            shell_tool(
                &dir,
                "second",
                "printf 'saw:%s\\n' \"$(cat \"$1\")\" >> \"$2\"\nprintf 'path:%s\\n' \"$1\" >> \"$2\"\necho from-step-two\n",
                &format!("{{prev_out_file}} {}", trace.display()),
            ),
        ];
        let plan = AutomationPlan {
            name: "two steps".into(),
            steps: vec![
                PipelineStep { tool_index: 0, ..Default::default() },
                PipelineStep { tool_index: 1, ..Default::default() },
            ],
            ..Default::default()
        };
        let ctx = ToolContext { url: "http://h.test/a".into(), ..Default::default() };
        let (runs, events) = harness();
        let id = runs.begin("two steps", RunOrigin::Pipeline("two steps".into()), &ctx);
        run_plan_blocking(&plan, &tools, &ctx, &runs, id, &events);

        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::Succeeded, "{}", run.stderr);
        let seen = std::fs::read_to_string(&trace).expect("step two wrote its trace");
        assert!(seen.contains("saw:from-step-one"), "step two was given step one's output: {seen:?}");
        let handoff = seen
            .lines()
            .find_map(|l| l.strip_prefix("path:"))
            .expect("step two was told the file's path");
        assert!(!handoff.is_empty(), "the placeholder was filled in, not left blank");
        assert!(!std::path::Path::new(handoff).exists(), "and the handoff file was removed: {handoff}");

        // both steps are in the run's own account of itself, in order, with their output
        let (one, two) = (run.stdout.find("Step 1 of 2"), run.stdout.find("Step 2 of 2"));
        assert!(one.is_some() && two.is_some() && one < two, "the steps are logged in order: {:?}", run.stdout);
        assert!(run.stdout.contains("from-step-one") && run.stdout.contains("from-step-two"), "{:?}", run.stdout);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a failing step does to the steps after it is the step's own business: Stop gives
    /// up, Continue carries on, and either way the run says it did not succeed.
    #[test]
    fn a_failing_step_stops_or_continues_as_told_matrix() {
        let dir = work_dir("policy");
        let marker = dir.join("reached.txt");
        let tools = vec![
            ExternalTool { name: "fails".into(), command: "false".into(), ..Default::default() },
            shell_tool(&dir, "marks", "echo reached >> \"$1\"\n", &marker.display().to_string()),
        ];
        let cases: [(&str, StepFailurePolicy, bool); 2] = [
            ("Stop", StepFailurePolicy::Stop, false),
            ("Continue", StepFailurePolicy::Continue, true),
        ];
        assert_table!(cases, |idx, (what, policy, reached)| {
            let _ = std::fs::remove_file(&marker);
            let plan = AutomationPlan {
                name: "p".into(),
                steps: vec![
                    PipelineStep { tool_index: 0, on_failure: policy, ..Default::default() },
                    PipelineStep { tool_index: 1, ..Default::default() },
                ],
                ..Default::default()
            };
            let ctx = ToolContext { url: "http://h.test/a".into(), ..Default::default() };
            let (runs, events) = harness();
            let id = runs.begin("p", RunOrigin::Pipeline("p".into()), &ctx);
            run_plan_blocking(&plan, &tools, &ctx, &runs, id, &events);
            let run = runs.get(id).expect("recorded");
            assert_eq!(run.status, RunStatus::Failed, "case #{idx} ({what}): the run did not succeed");
            assert_eq!(
                marker.exists(),
                reached,
                "case #{idx} ({what}): the step after the failure {}",
                if reached { "ran" } else { "did not run" }
            );
        });

        // a step pointing at a registry slot with nothing in it is a failure of that step,
        // and the policy applies to it as it would to any other
        let plan = AutomationPlan {
            name: "p".into(),
            steps: vec![PipelineStep { tool_index: 9, ..Default::default() }],
            ..Default::default()
        };
        let ctx = ToolContext::default();
        let (runs, events) = harness();
        let id = runs.begin("p", RunOrigin::Pipeline("p".into()), &ctx);
        run_plan_blocking(&plan, &tools, &ctx, &runs, id, &events);
        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.stderr.contains("slot 10"), "it says which slot: {:?}", run.stderr);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A program that will not finish is stopped when its time is up, and one that is
    /// cancelled is stopped there and then. Neither leaves the run saying it is still going.
    #[test]
    fn a_long_program_is_stopped_by_its_timeout_and_by_a_cancellation() {
        let dir = work_dir("timeout");
        // a program that would sit there for an hour, which neither of these waits for
        let sleeper = shell_tool(&dir, "sleeper", "sleep 3600\n", "");
        let ctx = ToolContext { url: "http://h.test/a".into(), ..Default::default() };

        // its timeout runs out
        let tool = ExternalTool { timeout_secs: 1, ..sleeper.clone() };
        let (runs, events) = harness();
        let id = runs.begin("sleeper", RunOrigin::Program("sleeper".into()), &ctx);
        let started = std::time::Instant::now();
        run_tool_blocking(&tool, &ctx, &runs, id, &events);
        let waited = started.elapsed();
        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::TimedOut, "it was stopped: {:?}", run.stderr);
        assert!(run.stderr.contains("1 second"), "and says why: {:?}", run.stderr);
        assert!(waited < std::time::Duration::from_secs(20), "it did not wait for the program ({waited:?})");
        assert!(run.elapsed_ms >= 900, "and the run was timed: {} ms", run.elapsed_ms);

        // it is cancelled while it is going
        let tool = ExternalTool { timeout_secs: 3600, ..sleeper };
        let id = runs.begin("sleeper", RunOrigin::Program("sleeper".into()), &ctx);
        let worker = {
            let (tool, ctx, runs, events) = (tool.clone(), ctx.clone(), runs.clone(), events.clone());
            std::thread::spawn(move || run_tool_blocking(&tool, &ctx, &runs, id, &events))
        };
        // wait for it to be running, then ask it to stop
        let started = std::time::Instant::now();
        while runs.get(id).is_some_and(|r| r.elapsed_ms == 0) && started.elapsed() < std::time::Duration::from_secs(10) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        runs.request_cancel(id);
        worker.join().expect("the worker finished");
        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::Cancelled, "it was stopped at our request: {:?}", run.stderr);
        assert!(started.elapsed() < std::time::Duration::from_secs(30), "and stopped promptly");
        assert!(run.status.finished(), "the history no longer shows it as going");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The run store is bounded, hands over its findings once, keeps a finished run until it
    /// is cleared, and keeps one still going even then.
    #[test]
    fn the_run_store_is_bounded_and_clears_only_what_has_finished() {
        let runs = RunLog::new(None);
        let ctx = ToolContext { url: "http://h.test/a".into(), ..Default::default() };
        for n in 0..MAX_RUNS + 25 {
            let id = runs.begin(&format!("run {n}"), RunOrigin::Program("p".into()), &ctx);
            runs.finish(id, RunStatus::Succeeded, Some(0), 1);
        }
        let kept = runs.snapshot();
        assert_eq!(kept.len(), MAX_RUNS, "the buffer holds no more than it says");
        assert_eq!(kept[0].label, "run 25", "and it is the oldest that gave way");

        // a run already finished keeps the ending it had: a reader arriving late cannot undo it
        let id = runs.begin("one", RunOrigin::Program("p".into()), &ctx);
        runs.finish(id, RunStatus::Failed, Some(2), 10);
        runs.finish(id, RunStatus::Succeeded, Some(0), 99);
        let run = runs.get(id).expect("recorded");
        assert_eq!((run.status, run.exit_code, run.elapsed_ms), (RunStatus::Failed, Some(2), 10));

        // clearing drops what has finished and leaves what has not
        let going = runs.begin("going", RunOrigin::Program("p".into()), &ctx);
        assert_eq!(runs.running(), 1);
        runs.clear_finished();
        let left = runs.snapshot();
        assert_eq!(left.len(), 1, "only the run still going is left");
        assert_eq!(left[0].id, going);

        // what a run keeps of its triggering message is bounded, so the history cannot grow
        // without limit on the strength of one enormous exchange
        let big = ToolContext {
            url: "http://h.test/a".into(),
            request: "x".repeat(MAX_STREAM_KEPT * 4),
            response: "y".repeat(MAX_STREAM_KEPT * 4),
            ..Default::default()
        };
        let id = runs.begin("big", RunOrigin::Program("p".into()), &big);
        let run = runs.get(id).expect("recorded");
        assert!(run.context.request.len() < big.request.len(), "the request was cut down");
        assert!(run.context.request.contains("[output truncated]"), "and says so");
    }

    /// Output arriving from a program is appended to the run as it comes, and what the run
    /// keeps for the console stops growing however much is written.
    #[test]
    fn a_runs_output_is_kept_and_bounded() {
        let dir = work_dir("stream");
        // writes a great deal more than the console keeps, on both streams
        // the padding is built once rather than per line: this is about how much output the
        // console keeps, not about how many programs a test can start
        let tool = shell_tool(
            &dir,
            "loud",
            "pad=$(printf 'x%.0s' $(seq 1 200))\ni=0\nwhile [ $i -lt 400 ]; do\n  printf 'out %s %s\\n' \"$i\" \"$pad\"\n  printf 'err %s\\n' \"$i\" >&2\n  i=$((i+1))\ndone\n",
            "",
        );
        let ctx = ToolContext { url: "http://h.test/a".into(), ..Default::default() };
        let (runs, events) = harness();
        let id = runs.begin("loud", RunOrigin::Program("loud".into()), &ctx);
        run_tool_blocking(&tool, &ctx, &runs, id, &events);
        let run = runs.get(id).expect("recorded");
        assert_eq!(run.status, RunStatus::Succeeded, "{}", run.stderr);
        assert!(run.stdout.len() <= MAX_STREAM_KEPT, "the kept output is bounded: {} bytes", run.stdout.len());
        assert!(run.stdout.contains("[output truncated]"), "and says it was cut");
        assert!(run.stderr.contains("err "), "standard error was kept separately: {:?}", run.stderr);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A timeout out of range in a hand-edited settings file is brought back into it before
    /// it is used, rather than giving a program no time at all or all day.
    #[test]
    fn a_timeout_is_brought_into_range_matrix() {
        let cases: [(&str, u64, u64); 5] = [
            ("the default", DEFAULT_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS),
            ("zero", 0, *TIMEOUT_RANGE.start()),
            ("one second", 1, 1),
            ("an hour", 3600, 3600),
            ("longer than an hour", 99_999, *TIMEOUT_RANGE.end()),
        ];
        assert_table!(cases, |idx, (what, set, want)| {
            let tool = ExternalTool { timeout_secs: set, ..Default::default() };
            assert_eq!(tool.timeout().as_secs(), want, "case #{idx} ({what})");
        });
        assert_eq!(ExternalTool::default().timeout_secs, DEFAULT_TIMEOUT_SECS, "a new entry starts in range");
        assert!(!ExternalTool::default().import_findings, "and does not read its output as findings");
    }

    /// A pipeline and its steps round-trip through the settings file, and a step written by a
    /// build that knew fewer of its fields reads back with the defaults for the rest.
    #[test]
    fn a_pipeline_survives_being_written_and_read() {
        let plan = AutomationPlan {
            name: "Collect and report".into(),
            steps: vec![
                PipelineStep { tool_index: 0, tool_name: String::new(), args_override: "--first {url}".into(), on_failure: StepFailurePolicy::Continue, import_findings: false },
                PipelineStep { tool_index: 1, tool_name: String::new(), args_override: String::new(), on_failure: StepFailurePolicy::Stop, import_findings: true },
            ],
            ..Default::default()
        };
        let json = serde_json::to_string(&plan).expect("it writes");
        assert_eq!(serde_json::from_str::<AutomationPlan>(&json).expect("it reads"), plan);

        // a step that says only which program to run
        let partial: AutomationPlan =
            serde_json::from_str(r#"{"name":"p","steps":[{"tool_index":2}]}"#).expect("a partial step still reads");
        assert_eq!(partial.steps[0].tool_index, 2);
        assert_eq!(partial.steps[0].on_failure, StepFailurePolicy::Stop, "giving up is the safer default");
        assert!(!partial.steps[0].import_findings);
        assert!(partial.steps[0].args_override.is_empty());

        // and what is worth running
        assert!(plan.is_runnable());
        assert!(!AutomationPlan { name: "named".into(), steps: Vec::new(), ..Default::default() }.is_runnable(), "no steps, nothing to do");
        assert!(!AutomationPlan { name: "  ".into(), steps: plan.steps.clone(), ..Default::default() }.is_runnable(), "and it needs a name");
    }
}

#[cfg(test)]
mod bundle_tests {
    use super::*;
    use crate::state::UserSettings;
    use crate::test_utils::assert_table;

    fn tool(name: &str, command: &str) -> ExternalTool {
        ExternalTool { name: name.into(), command: command.into(), ..Default::default() }
    }

    /// A pipeline whose steps name their programs, as one built in the app does.
    fn plan(name: &str, runs: &[&str]) -> AutomationPlan {
        AutomationPlan {
            name: name.into(),
            steps: runs
                .iter()
                .map(|n| PipelineStep { tool_name: (*n).to_string(), ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    fn registry(tools: &[ExternalTool], plans: &[AutomationPlan]) -> UserSettings {
        let mut settings = UserSettings { external_tools: tools.to_vec(), automation_plans: plans.to_vec(), ..Default::default() };
        let known = settings.external_tools.clone();
        bind_steps(&known, &mut settings.automation_plans);
        settings
    }

    /// What each step of each plan in `settings` actually runs, by name.
    fn runs_of(settings: &UserSettings) -> Vec<(String, Vec<String>)> {
        settings
            .automation_plans
            .iter()
            .map(|p| {
                let steps = p
                    .steps
                    .iter()
                    .map(|s| match s.resolve(&settings.external_tools) {
                        Some(t) => t.name.trim().to_string(),
                        None => format!("<nothing: {}>", s.display_target()),
                    })
                    .collect();
                (p.name.clone(), steps)
            })
            .collect()
    }

    /// Exporting a pipeline carries every program its steps run, so the file stands on its
    /// own, and carries them once however many steps share one.
    #[test]
    fn exporting_a_pipeline_carries_the_programs_its_steps_run() {
        let tools = [tool("Collect", "/bin/collect"), tool("Report", "/bin/report"), tool("Unrelated", "/bin/other")];
        let settings = registry(&tools, &[plan("Nightly", &["Collect", "Report", "Collect"])]);
        let bundle = AutomationBundle::from_plan(&settings.automation_plans[0], &settings.external_tools, "a colleague");

        assert_eq!(bundle.format_version, BUNDLE_FORMAT_VERSION);
        assert_eq!(bundle.author, "a colleague");
        let carried: Vec<&str> = bundle.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(carried, ["Collect", "Report"], "each one once, and nothing the steps do not run");
        assert_eq!(bundle.plans.len(), 1);
        // the places in the bundle's own list, and the names that bind wherever it lands
        let steps = &bundle.plans[0].steps;
        assert_eq!(steps.iter().map(|s| s.tool_name.as_str()).collect::<Vec<_>>(), ["Collect", "Report", "Collect"]);
        assert_eq!(steps.iter().map(|s| s.tool_index).collect::<Vec<_>>(), [0, 1, 0]);
        // and it survives being written and read back
        let json = bundle.to_json().expect("the bundle as JSON");
        assert_eq!(AutomationBundle::from_json(&json).expect("read back"), bundle);
        assert!(json.contains("\n  \"format_version\""), "laid out to be read: {json}");
    }

    /// A pipeline imported into a registry that already has programs of its own runs the
    /// programs it came with, not whatever happens to sit at the places its steps once held.
    #[test]
    fn a_pipeline_imported_into_a_full_registry_still_runs_its_own_programs() {
        let theirs = registry(
            &[tool("Collect", "/bin/collect"), tool("Report", "/bin/report")],
            &[plan("Nightly", &["Collect", "Report"])],
        );
        let bundle = AutomationBundle::from_plan(&theirs.automation_plans[0], &theirs.external_tools, "");

        // a registry of our own, with three programs already in it and none of them theirs
        let mut mine = registry(
            &[tool("Mine one", "/bin/one"), tool("Mine two", "/bin/two"), tool("Mine three", "/bin/three")],
            &[plan("Ours", &["Mine two"])],
        );
        let report = bundle.merge_into(&mut mine, ConflictPolicy::KeepBoth);

        assert_eq!(report.taken(), 3, "two programs and the pipeline: {:?}", report.lines());
        let names: Vec<&str> = mine.external_tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Mine one", "Mine two", "Mine three", "Collect", "Report"]);
        assert_eq!(
            runs_of(&mine),
            vec![
                ("Ours".to_string(), vec!["Mine two".to_string()]),
                ("Nightly".to_string(), vec!["Collect".to_string(), "Report".to_string()]),
            ],
            "every step runs what it names, ours and theirs alike"
        );
        // the places were worked out again for where the programs actually landed
        let arrived = mine.automation_plans.iter().find(|p| p.name == "Nightly").expect("the pipeline");
        assert_eq!(arrived.steps.iter().map(|s| s.tool_index).collect::<Vec<_>>(), [3, 4]);
    }

    /// The three ways a name already registered can be settled.
    #[test]
    fn the_conflict_policies_settle_a_name_already_taken_matrix() {
        struct Case {
            policy: ConflictPolicy,
            /// The programs registered afterwards, in order.
            tools: &'static [&'static str],
            /// What the program called "Collect" runs afterwards.
            collect_runs: &'static str,
            /// What the arriving pipeline's one step runs.
            step_runs: &'static str,
            outcome: fn(&MergeOutcome) -> bool,
        }
        let cases = [
            Case {
                policy: ConflictPolicy::Replace,
                tools: &["Collect"],
                collect_runs: "/bin/theirs",
                step_runs: "Collect",
                outcome: |o| *o == MergeOutcome::Replaced,
            },
            Case {
                policy: ConflictPolicy::Skip,
                tools: &["Collect"],
                collect_runs: "/bin/mine",
                step_runs: "Collect",
                outcome: |o| *o == MergeOutcome::Skipped,
            },
            Case {
                policy: ConflictPolicy::KeepBoth,
                tools: &["Collect", "Collect (2)"],
                collect_runs: "/bin/mine",
                step_runs: "Collect (2)",
                outcome: |o| matches!(o, MergeOutcome::Renamed(to) if to == "Collect (2)"),
            },
        ];
        assert_table!(cases, |idx, case| {
            let theirs = registry(&[tool("Collect", "/bin/theirs")], &[plan("Nightly", &["Collect"])]);
            let bundle = AutomationBundle::from_plan(&theirs.automation_plans[0], &theirs.external_tools, "");
            let mut mine = registry(&[tool("Collect", "/bin/mine")], &[]);
            let report = bundle.merge_into(&mut mine, case.policy);

            let names: Vec<&str> = mine.external_tools.iter().map(|t| t.name.as_str()).collect();
            assert_eq!(names, case.tools, "case #{idx} ({}): the registry afterwards", case.policy.label());
            let collect = mine.external_tools.iter().find(|t| t.name == "Collect").expect("the one named");
            assert_eq!(collect.command, case.collect_runs, "case #{idx} ({})", case.policy.label());
            assert_eq!(
                runs_of(&mine),
                vec![("Nightly".to_string(), vec![case.step_runs.to_string()])],
                "case #{idx} ({}): the arriving step runs the program it arrived with",
                case.policy.label()
            );
            assert!(
                (case.outcome)(&report.tools[0].1),
                "case #{idx} ({}): {:?}",
                case.policy.label(),
                report.lines()
            );
            // the policy words a command line uses are the same three, and read back
            assert_eq!(ConflictPolicy::from_word(case.policy.word()), Some(case.policy));
        });
        assert_eq!(ConflictPolicy::from_word("  REPLACE "), Some(ConflictPolicy::Replace), "and ignore capitals");
        assert_eq!(ConflictPolicy::from_word("something else"), None);
        // a pipeline whose name is taken is settled the same way
        let theirs = registry(&[tool("Collect", "/bin/theirs")], &[plan("Nightly", &["Collect"])]);
        let bundle = AutomationBundle::from_plan(&theirs.automation_plans[0], &theirs.external_tools, "");
        let mut mine = registry(&[], &[plan("Nightly", &[])]);
        bundle.merge_into(&mut mine, ConflictPolicy::KeepBoth);
        let plans: Vec<&str> = mine.automation_plans.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(plans, ["Nightly", "Nightly (2)"]);
    }

    /// A single program or a single pipeline, pasted out of a settings file, is read as a
    /// bundle of its own rather than refused on a technicality.
    #[test]
    fn a_bare_program_or_pipeline_is_read_as_a_bundle_of_its_own() {
        let one = tool("Collect", "/bin/collect");
        let json = serde_json::to_string(&one).expect("a program as JSON");
        let bundle = AutomationBundle::from_json(&json).expect("a program alone reads");
        assert_eq!(bundle.tools, [one]);
        assert!(bundle.plans.is_empty());
        assert_eq!(bundle.name, "Collect", "named after what it holds");

        let p = plan("Nightly", &["Collect"]);
        let json = serde_json::to_string(&p).expect("a pipeline as JSON");
        let bundle = AutomationBundle::from_json(&json).expect("a pipeline alone reads");
        assert_eq!(bundle.plans, [p]);
        assert!(bundle.tools.is_empty(), "it carries no programs, so its steps bind to registered ones");

        // and what is not a bundle at all says so
        let cases: [(&str, &str); 5] = [
            ("not json at all", "not JSON"),
            ("[1, 2, 3]", "a JSON object"),
            ("{}", "no programs and no pipelines"),
            (r#"{"tools":[],"plans":[]}"#, "no programs and no pipelines"),
            (r#"{"format_version":99,"tools":[{"name":"a","command":"b"}]}"#, "does not read"),
        ];
        assert_table!(cases, |idx, (text, says)| {
            let e = AutomationBundle::from_json(text).expect_err(&format!("case #{idx}: {text:?} is no bundle"));
            assert!(e.contains(says), "case #{idx}: {text:?} said {e:?}, wanted {says:?}");
        });
    }

    /// A step holds the name of the program it runs, so it survives the registry being
    /// reordered and follows that program when it is renamed.
    #[test]
    fn a_step_follows_the_program_it_names() {
        let mut settings = registry(
            &[tool("Collect", "/bin/collect"), tool("Report", "/bin/report")],
            &[plan("Nightly", &["Report"])],
        );
        assert_eq!(settings.automation_plans[0].steps[0].tool_index, 1, "bound to where it sits now");

        // the registry is reordered: the step still runs what it named
        settings.external_tools.swap(0, 1);
        let tools = settings.external_tools.clone();
        bind_steps(&tools, &mut settings.automation_plans);
        assert_eq!(settings.automation_plans[0].steps[0].tool_index, 0, "pointed at where it moved to");
        assert_eq!(runs_of(&settings), vec![("Nightly".to_string(), vec!["Report".to_string()])]);

        // the program is renamed: the step is carried with it
        rename_in_steps(&mut settings.automation_plans, "Report", "Write the report");
        settings.external_tools[0].name = "Write the report".into();
        let tools = settings.external_tools.clone();
        bind_steps(&tools, &mut settings.automation_plans);
        assert_eq!(runs_of(&settings), vec![("Nightly".to_string(), vec!["Write the report".to_string()])]);
        // renaming to the same thing, or from nothing, changes nothing
        let before = settings.automation_plans.clone();
        rename_in_steps(&mut settings.automation_plans, "Write the report", "Write the report");
        rename_in_steps(&mut settings.automation_plans, "", "Something");
        assert_eq!(settings.automation_plans, before);

        // a step that names nothing -- a plan saved before names were kept -- is read by its
        // place, and gains the name from it
        let mut old = UserSettings {
            external_tools: vec![tool("Collect", "/bin/collect"), tool("Report", "/bin/report")],
            automation_plans: vec![AutomationPlan {
                name: "Older".into(),
                steps: vec![PipelineStep { tool_index: 1, ..Default::default() }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let tools = old.external_tools.clone();
        bind_steps(&tools, &mut old.automation_plans);
        assert_eq!(old.automation_plans[0].steps[0].tool_name, "Report", "named from where it pointed");
    }

    /// A value given for a run reaches the template as exactly one argument, whatever is in it.
    #[test]
    fn a_value_given_for_a_run_fills_one_argument_matrix() {
        let ctx = ToolContext {
            vars: [
                ("TOKEN".to_string(), "a b & c; d | e > f".to_string()),
                ("BLANK".to_string(), String::new()),
                ("LOOKS_LIKE_ONE".to_string(), "{var:TOKEN}".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let cases: [(&str, &[&str]); 8] = [
            // the value becomes one argument, spaces, semicolons, pipes and all
            ("--token {var:TOKEN}", &["--token", "a b & c; d | e > f"]),
            // joined to text around it, still one argument
            ("prefix-{var:TOKEN}-suffix", &["prefix-a b & c; d | e > f-suffix"]),
            // twice in one argument
            ("{var:TOKEN}/{var:TOKEN}", &["a b & c; d | e > f/a b & c; d | e > f"]),
            // a key given as nothing is nothing, and the argument stays an argument
            ("--blank={var:BLANK}", &["--blank="]),
            // a key never given is nothing too, rather than left as a brace
            ("--missing={var:NEVER_GIVEN}", &["--missing="]),
            // a value that looks like a placeholder is the text it is, not filled again
            ("{var:LOOKS_LIKE_ONE}", &["{var:TOKEN}"]),
            // an opening with no closing brace is text
            ("{var:TOKEN --next", &["{var:TOKEN", "--next"]),
            // and the other placeholders still work beside it
            ("{var:TOKEN} {url}", &["a b & c; d | e > f", ""]),
        ];
        assert_table!(cases, |idx, (template, want)| {
            let argv = fill(&tokenize(template), &ctx, None, None);
            assert_eq!(argv, want, "case #{idx}: {template:?}");
        });
        // the value is never split into arguments of its own, however it is written
        let argv = fill(&tokenize("{var:TOKEN}"), &ctx, None, None);
        assert_eq!(argv.len(), 1, "one argument: {argv:?}");
        // and a template with no variable in it is untouched
        assert_eq!(fill(&tokenize("--plain value"), &ctx, None, None), ["--plain", "value"]);
    }
}
