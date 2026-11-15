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
    /// Which registered program, by its place in the registry.
    pub tool_index: usize,
    /// Arguments for this step only. Blank leaves the program's own template in place.
    pub args_override: String,
    pub on_failure: StepFailurePolicy,
    /// Read this step's output as a findings document, whatever the program itself says.
    pub import_findings: bool,
}

/// A run of registered programs, one after another.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AutomationPlan {
    pub name: String,
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

/// Every placeholder an argument template may carry, with what each one stands for.
///
/// Shown on the Settings page, and held by a test to matching what [`fill`] replaces.
pub const PLACEHOLDERS: [(&str, &str); 9] = [
    ("{url}", "the whole address"),
    ("{scheme}", "http or https"),
    ("{host}", "host name, with the port when there is one"),
    ("{port}", "port number"),
    ("{method}", "request method"),
    ("{path}", "path and query"),
    ("{req_file}", "a temporary file holding the raw request"),
    ("{res_file}", "a temporary file holding the raw response"),
    ("{prev_out_file}", "a temporary file holding the previous pipeline step's output"),
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

/// Fill the placeholders in each argument, leaving the arguments themselves as they were.
///
/// Substitution is per argument, never across them: whatever a placeholder stands for becomes
/// part of one argument however many spaces or metacharacters it contains.
pub fn fill(args: &[String], ctx: &ToolContext, req_file: Option<&str>, res_file: Option<&str>) -> Vec<String> {
    args.iter()
        .map(|arg| {
            let mut out = arg.clone();
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
        let Some(base) = tools.get(step.tool_index).filter(|t| t.is_runnable()) else {
            runs.append_stderr(
                id,
                &format!("Step {step_no}: there is no finished program in registry slot {}.\n", step.tool_index + 1),
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

/// The type number an imported finding carries when it names none of its own.
pub const IMPORTED_TYPE_INDEX: u32 = 0x0080_0000;

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
      "type_index": 8388608,
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
            type_index: fields
                .get("type_index")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(IMPORTED_TYPE_INDEX),
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
                      "type_index":42,"request":"GET /login HTTP/1.1\r\n\r\n","response":"HTTP/1.1 302\r\n\r\n"}"#;
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
            assert_eq!(f.type_index, 42, "case #{idx} ({what})");
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
        assert_eq!(f.type_index, IMPORTED_TYPE_INDEX, "with the type number for an import");
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
                PipelineStep { tool_index: 0, args_override: "--first {url}".into(), on_failure: StepFailurePolicy::Continue, import_findings: false },
                PipelineStep { tool_index: 1, args_override: String::new(), on_failure: StepFailurePolicy::Stop, import_findings: true },
            ],
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
        assert!(!AutomationPlan { name: "named".into(), steps: Vec::new() }.is_runnable(), "no steps, nothing to do");
        assert!(!AutomationPlan { name: "  ".into(), steps: plan.steps.clone() }.is_runnable(), "and it needs a name");
    }
}
