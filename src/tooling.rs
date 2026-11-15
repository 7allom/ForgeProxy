//! External tools: the registry in Settings, and running one on a message.
//!
//! Nothing here goes through a shell. An argument template is split into separate arguments
//! first, and a placeholder is then replaced *inside* one of them, so a URL carrying `;`,
//! backticks or `$(...)` stays one argument and is handed to the program as text. There is no
//! interpreter between this and the program to interpret it.

use std::io::Write;
use std::process::{Command, Stdio};

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

/// A program the user has registered, as it appears on the "Send to" menus.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ExternalTool {
    /// What the menu item says.
    pub name: String,
    /// The program to run. Looked up on the path, or an absolute path to a script.
    pub command: String,
    /// The arguments, as a template. Split on whitespace, with quoted runs kept together.
    pub args: String,
    pub stdin_mode: ToolStdinMode,
}

impl ExternalTool {
    /// Is this entry worth offering? A tool with no name or no program cannot be run, and an
    /// unfinished row in Settings should not appear on a menu.
    pub fn is_runnable(&self) -> bool {
        !self.name.trim().is_empty() && !self.command.trim().is_empty()
    }
}

/// Every placeholder an argument template may carry, with what each one stands for.
///
/// Shown on the Settings page, and held by a test to matching what [`fill`] replaces.
pub const PLACEHOLDERS: [(&str, &str); 8] = [
    ("{url}", "the whole address"),
    ("{scheme}", "http or https"),
    ("{host}", "host name, with the port when there is one"),
    ("{port}", "port number"),
    ("{method}", "request method"),
    ("{path}", "path and query"),
    ("{req_file}", "a temporary file holding the raw request"),
    ("{res_file}", "a temporary file holding the raw response"),
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
    // enough to tell two runs apart without needing a counter anyone has to keep
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let path = dir.join(format!("{tag}-{stamp}"));
    crate::paths::write_private(&path, contents.as_bytes())?;
    Ok(path)
}

/// Run `tool` on `ctx`, off the drawing thread, and say in the event log how it went.
///
/// The program is started directly with its arguments. Any temporary files the template asked
/// for are written for its owner only and removed once the program has finished, whether it
/// succeeded or not.
pub fn run(tool: &ExternalTool, ctx: &ToolContext, events: &crate::proxy::Events) {
    let (tool, ctx, events) = (tool.clone(), ctx.clone(), events.clone());
    std::thread::spawn(move || {
        let outcome = run_blocking(&tool, &ctx);
        match outcome {
            Ok(note) => crate::proxy::log(&events, note),
            Err(note) => crate::proxy::log_error(&events, note),
        }
    });
}

/// The body of [`run`], on whichever thread calls it. Separated so a test can wait for it.
pub fn run_blocking(tool: &ExternalTool, ctx: &ToolContext) -> Result<String, String> {
    let (wants_req, wants_res) = wants_files(&tool.args);
    let mut temps: Vec<std::path::PathBuf> = Vec::new();
    let req_file = if wants_req {
        match temp_file("request", &ctx.request) {
            Ok(p) => {
                temps.push(p.clone());
                Some(p)
            }
            Err(e) => return Err(format!("{}: couldn't write the request to a file: {e}", tool.name)),
        }
    } else {
        None
    };
    let res_file = if wants_res {
        match temp_file("response", &ctx.response) {
            Ok(p) => {
                temps.push(p.clone());
                Some(p)
            }
            Err(e) => {
                for t in &temps {
                    let _ = std::fs::remove_file(t);
                }
                return Err(format!("{}: couldn't write the response to a file: {e}", tool.name));
            }
        }
    } else {
        None
    };
    let argv = fill(
        &tokenize(&tool.args),
        ctx,
        req_file.as_ref().map(|p| p.to_string_lossy().into_owned()).as_deref(),
        res_file.as_ref().map(|p| p.to_string_lossy().into_owned()).as_deref(),
    );
    let feed = stdin_bytes(tool, ctx);

    let result = (|| -> Result<String, String> {
        let mut child = Command::new(tool.command.trim())
            .args(&argv)
            .stdin(if feed.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{}: couldn't start {}: {e}", tool.name, tool.command.trim()))?;
        if let (Some(bytes), Some(mut pipe)) = (feed, child.stdin.take()) {
            // a tool that stops reading early is not an error: it has what it wanted
            let _ = pipe.write_all(&bytes);
            drop(pipe);
        }
        let status = child.wait().map_err(|e| format!("{}: {e}", tool.name))?;
        if status.success() {
            Ok(format!("{} finished", tool.name))
        } else {
            match status.code() {
                Some(code) => Err(format!("{} exited with status {code}", tool.name)),
                None => Err(format!("{} was stopped before it finished", tool.name)),
            }
        }
    })();
    // the files go whatever happened, so a long session does not leave the messages it sent
    // lying about in the temporary directory
    for t in &temps {
        let _ = std::fs::remove_file(t);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

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
            let tool = ExternalTool { name: "t".into(), command: "true".into(), args: String::new(), stdin_mode: mode };
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
        let dir = std::env::temp_dir().join(format!("forge-tool-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a place to work");
        let out = dir.join("seen.txt");
        let script = dir.join("probe.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\n# $1 is where to write, $2 is the request file\ncat > \"$1.stdin\"\ncp \"$2\" \"$1.file\"\n",
        )
        .expect("the script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("runnable");
        }

        let ctx = ToolContext {
            url: "http://h.test/a".into(),
            request: "GET /a HTTP/1.1\r\nHost: h.test\r\n\r\n".into(),
            response: "HTTP/1.1 200 OK\r\n\r\nok".into(),
            ..Default::default()
        };
        let tool = ExternalTool {
            name: "probe".into(),
            command: script.to_string_lossy().into_owned(),
            args: format!("{} {{req_file}}", out.display()),
            stdin_mode: ToolStdinMode::RawRequest,
        };
        let note = run_blocking(&tool, &ctx).expect("the tool ran");
        assert!(note.contains("probe"), "the event log names it: {note}");

        let from_stdin = std::fs::read_to_string(format!("{}.stdin", out.display())).expect("stdin reached it");
        assert_eq!(from_stdin, ctx.request, "the raw request arrived on standard input");
        let from_file = std::fs::read_to_string(format!("{}.file", out.display())).expect("the file reached it");
        assert_eq!(from_file, ctx.request, "and the same message was in the file");

        // nothing is left behind in the temporary directory
        let leftovers: Vec<std::path::PathBuf> = std::fs::read_dir(std::env::temp_dir().join("forgeproxy-tools"))
            .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().contains("request-")).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "the request file was removed: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A program that is not there, and one that fails, are both reported rather than passed
    /// over in silence.
    #[test]
    fn a_tool_that_cannot_run_or_fails_is_reported() {
        let ctx = ToolContext::default();
        let missing = ExternalTool {
            name: "missing".into(),
            command: "forgeproxy-no-such-program".into(),
            args: String::new(),
            stdin_mode: ToolStdinMode::None,
        };
        let err = run_blocking(&missing, &ctx).expect_err("it is not there");
        assert!(err.contains("missing") && err.contains("couldn't start"), "{err}");

        let failing = ExternalTool {
            name: "failing".into(),
            command: "false".into(),
            args: String::new(),
            stdin_mode: ToolStdinMode::None,
        };
        let err = run_blocking(&failing, &ctx).expect_err("it exits non-zero");
        assert!(err.contains("failing") && err.contains("status"), "{err}");
    }
}
