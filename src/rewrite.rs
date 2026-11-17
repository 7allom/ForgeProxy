//! Proxy match-and-replace rules, following the original's documented rules
//! (resources/Documentation/.../proxy/match-and-replace/creating.html) and its
//! 12 shipped default rules (ProjectDefaults.json proxy.match_replace_rules).
//!
//! - Header rules work on one header line at a time.
//! - Blank match on a header rule: the replacement is added as a new header.
//! - Blank replace on a header rule: every matching header is removed.
//! - "Regex match" treats the match as a regular expression; otherwise plain text.
//! - A request first line rule works on the request line alone ("GET /a HTTP/1.1"), so a
//!   method or path can be rewritten without touching a header that reads the same.
//! - "Case sensitive" decides how the match is compared, for regular expressions and plain
//!   text alike.

use regex::Regex;
use std::time::{Duration, Instant};

/// What a matching rule does to the text it matched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    /// Literal or regular-expression replacement, the long-standing behaviour.
    #[default]
    Replace,
    /// Pipe the matched header block or body through an external command and take its output
    /// in their place. The command is named by [`Rule::command`] and stopped after
    /// [`Rule::timeout_ms`].
    TransformCommand,
}

impl RuleAction {
    pub const ALL: [RuleAction; 2] = [RuleAction::Replace, RuleAction::TransformCommand];
    pub fn label(&self) -> &'static str {
        match self {
            RuleAction::Replace => "Replace",
            RuleAction::TransformCommand => "External command",
        }
    }
}

/// How long an External Command transform may run before it is stopped, when a rule names no
/// timeout of its own.
pub const DEFAULT_TRANSFORM_TIMEOUT_MS: u64 = 1000;

/// The most output one External Command transform may return. A process that writes more than
/// this is stopped and its output discarded, so a runaway filter cannot exhaust memory.
pub const MAX_TRANSFORM_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RuleType {
    RequestFirstLine,
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

impl RuleType {
    pub const ALL: [RuleType; 5] = [RuleType::RequestFirstLine, RuleType::RequestHeader,
        RuleType::RequestBody, RuleType::ResponseHeader, RuleType::ResponseBody];
    pub fn label(&self) -> &'static str {
        match self {
            RuleType::RequestFirstLine => "Request first line",
            RuleType::RequestHeader => "Request header",
            RuleType::RequestBody => "Request body",
            RuleType::ResponseHeader => "Response header",
            RuleType::ResponseBody => "Response body",
        }
    }
    fn is_header(&self) -> bool {
        matches!(self, RuleType::RequestHeader | RuleType::ResponseHeader)
    }
    pub fn is_first_line(&self) -> bool {
        matches!(self, RuleType::RequestFirstLine)
    }
    fn is_request(&self) -> bool {
        matches!(self, RuleType::RequestFirstLine | RuleType::RequestHeader | RuleType::RequestBody)
    }
    /// Whether a new rule of this kind starts out case sensitive. A header is matched loosely:
    /// field names are case-insensitive by definition (RFC 9110 5.1), and a request that
    /// reached the proxy over HTTP/2 has had its names lower-cased on the way. A first line or
    /// a body is matched exactly as it was typed.
    pub fn starts_case_sensitive(&self) -> bool {
        !self.is_header()
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub enabled: bool,
    pub kind: RuleType,
    pub regex: bool,
    pub match_text: String,
    pub replace_text: String,
    pub comment: String,
    /// Match the text exactly as typed. Rules saved before this setting existed are read as
    /// case sensitive, which is how they behaved when they were saved.
    #[serde(default = "case_sensitive_default")]
    pub case_sensitive: bool,
    /// What the rule does when it matches: a replacement, or an external command transform.
    /// Rules saved before this setting existed read back as [`RuleAction::Replace`].
    #[serde(default)]
    pub action: RuleAction,
    /// The command line an [`RuleAction::TransformCommand`] rule runs: the first word is the
    /// program, the rest its arguments. Empty for a replacement rule.
    #[serde(default)]
    pub command: String,
    /// How long that command may run, in milliseconds, before it is stopped and the original
    /// bytes are kept. Rules saved before this setting existed read back at the default.
    #[serde(default = "transform_timeout_default")]
    pub timeout_ms: u64,
}

fn case_sensitive_default() -> bool {
    true
}

fn transform_timeout_default() -> u64 {
    DEFAULT_TRANSFORM_TIMEOUT_MS
}

impl Default for Rule {
    fn default() -> Self {
        Rule::new(RuleType::RequestHeader)
    }
}

impl Rule {
    /// A blank rule of this kind, with the case sensitivity that suits it.
    pub fn new(kind: RuleType) -> Rule {
        Rule {
            enabled: true,
            kind,
            regex: false,
            match_text: String::new(),
            replace_text: String::new(),
            comment: String::new(),
            case_sensitive: kind.starts_case_sensitive(),
            action: RuleAction::Replace,
            command: String::new(),
            timeout_ms: DEFAULT_TRANSFORM_TIMEOUT_MS,
        }
    }

    /// The transform timeout as a [`Duration`], never zero so a rule cannot ask for a command
    /// that is killed before it can start.
    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.max(1))
    }

    /// Does this rule's match gate let its command run against `slice`? An empty match always
    /// does; otherwise the pattern must be found somewhere in the slice. An invalid pattern
    /// matches nothing, so the command is skipped rather than run on everything.
    fn command_gate_open(&self, slice: &str) -> bool {
        if self.match_text.is_empty() {
            return true;
        }
        matcher(self).is_some_and(|re| re.is_match(slice))
    }
}

/// Run `command` as a child process, write `input` to its stdin, and return what it writes to
/// stdout. Stdin and stdout are each drained on their own thread so a filter that writes a lot
/// before reading all of its input cannot deadlock against a full pipe.
///
/// The guardrails are strict: the child is killed if it outlives `timeout`, its output is
/// capped at [`MAX_TRANSFORM_OUTPUT`], and a failure to spawn, an over-cap, a timeout or a
/// non-zero exit all return `Err` so the caller can keep the original bytes.
fn run_transform(command: &str, timeout: Duration, input: &[u8]) -> Result<Vec<u8>, String> {
    use std::process::{Command, Stdio};
    let mut parts = command.split_whitespace();
    let program = parts.next().ok_or_else(|| "the command is empty".to_string())?;
    let args: Vec<&str> = parts.collect();
    let mut child = Command::new(program)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {program:?}: {e}"))?;

    let mut stdin = child.stdin.take().ok_or_else(|| "the command took no input".to_string())?;
    let input_owned = input.to_vec();
    // dropping `stdin` at the end of the closure sends EOF; a broken pipe (the child read none
    // of it) is not an error here
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(&input_owned);
    });

    let mut stdout = child.stdout.take().ok_or_else(|| "the command gave no output".to_string())?;
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        // one byte past the cap, so going over it can be told apart from landing exactly on it
        let _ = stdout.by_ref().take((MAX_TRANSFORM_OUTPUT as u64) + 1).read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                let _ = reader.join();
                return Err(format!("{program:?} could not be waited on: {e}"));
            }
        }
    };
    let Some(status) = status else {
        // over its time: stop it, let the pipe close, and abandon whatever it produced
        let _ = child.kill();
        let _ = child.wait();
        let _ = writer.join();
        let _ = reader.join();
        return Err(format!("{program:?} ran longer than {} ms and was stopped", timeout.as_millis()));
    };
    let _ = writer.join();
    let out = reader.join().map_err(|_| "the command output could not be read".to_string())?;
    if out.len() > MAX_TRANSFORM_OUTPUT {
        return Err(format!("{program:?} wrote more than {} MiB", MAX_TRANSFORM_OUTPUT >> 20));
    }
    if !status.success() {
        let how = status.code().map(|c| format!("code {c}")).unwrap_or_else(|| "a signal".into());
        return Err(format!("{program:?} exited with {how}"));
    }
    Ok(out)
}

fn matcher(rule: &Rule) -> Option<Regex> {
    let pattern = if rule.regex { rule.match_text.clone() } else { regex::escape(&rule.match_text) };
    crate::regex_cache::get_with(&pattern, !rule.case_sensitive)
}

/// Run a header or body slice through a [`RuleAction::TransformCommand`] rule's command,
/// returning the transformed text. When the gate is closed the slice is returned unchanged;
/// when the command fails, times out or over-runs its cap, the slice is kept and a concise
/// warning is pushed for the caller to log, so a bad command never drops the exchange.
fn apply_command(rule: &Rule, slice: &str, warnings: &mut Vec<String>) -> String {
    if rule.command.trim().is_empty() || !rule.command_gate_open(slice) {
        return slice.to_string();
    }
    match run_transform(&rule.command, rule.timeout(), slice.as_bytes()) {
        Ok(out) => String::from_utf8_lossy(&out).into_owned(),
        Err(why) => {
            warnings.push(format!("the {} command was kept out ({why})", rule.kind.label().to_lowercase()));
            slice.to_string()
        }
    }
}

fn apply_headers(rule: &Rule, headers: &str, warnings: &mut Vec<String>) -> String {
    if rule.action == RuleAction::TransformCommand {
        return apply_command(rule, headers, warnings);
    }
    if rule.match_text.is_empty() {
        if rule.replace_text.is_empty() {
            return headers.to_string();
        }
        let mut h = headers.trim_end_matches('\n').to_string();
        if !h.is_empty() {
            h.push('\n');
        }
        h.push_str(&rule.replace_text);
        return h;
    }
    let Some(re) = matcher(rule) else { return headers.to_string() };
    let mut out = Vec::new();
    for line in headers.lines() {
        if re.is_match(line) {
            if !rule.replace_text.is_empty() {
                let replaced = if rule.regex {
                    re.replace_all(line, rule.replace_text.as_str()).into_owned()
                } else {
                    re.replace_all(line, regex::NoExpand(&rule.replace_text)).into_owned()
                };
                out.push(replaced);
            } // blank replacement: the header is removed
        } else {
            out.push(line.to_string());
        }
    }
    out.join("\n")
}

fn apply_body(rule: &Rule, body: &str, warnings: &mut Vec<String>) -> String {
    if rule.action == RuleAction::TransformCommand {
        return apply_command(rule, body, warnings);
    }
    if rule.match_text.is_empty() {
        return body.to_string();
    }
    match matcher(rule) {
        Some(re) => {
            if rule.regex {
                re.replace_all(body, rule.replace_text.as_str()).into_owned()
            } else {
                re.replace_all(body, regex::NoExpand(&rule.replace_text)).into_owned()
            }
        }
        None => body.to_string(),
    }
}

/// Update a header block to frame a body of `body_len` bytes: an existing `Content-Length` is
/// corrected, and a chunked `Transfer-Encoding` is dropped (the body has been buffered and
/// transformed, so it is now framed by length). A block that named neither is left untouched
/// but for a length added when a chunked encoding was stripped.
fn reconcile_content_length(headers: &str, body_len: usize) -> String {
    let mut out = Vec::new();
    let mut had_length = false;
    let mut stripped_chunked = false;
    for line in headers.lines() {
        let key = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if key == "content-length" {
            had_length = true;
            out.push(format!("Content-Length: {body_len}"));
        } else if key == "transfer-encoding" && line.to_ascii_lowercase().contains("chunked") {
            stripped_chunked = true;
        } else {
            out.push(line.to_string());
        }
    }
    if stripped_chunked && !had_length {
        out.push(format!("Content-Length: {body_len}"));
    }
    out.join("\n")
}

/// Apply enabled request (or response) rules to (headers, body), discarding any warnings. The
/// request line is not part of either: [`apply_first_line`] handles the rules that work on it.
pub fn apply(rules: &[Rule], request: bool, headers: &str, body: &str) -> (String, String) {
    let (h, b, _) = apply_collecting(rules, request, headers, body);
    (h, b)
}

/// As [`apply`], but also returning a concise warning for each external-command transform that
/// could not run, so a caller that forwards live traffic can log them rather than lose them.
///
/// When a body command transform changes the body's byte length, the returned header block is
/// reconciled so its `Content-Length` frames the body the function returns.
pub fn apply_collecting(rules: &[Rule], request: bool, headers: &str, body: &str) -> (String, String, Vec<String>) {
    let mut h = headers.to_string();
    let mut b = body.to_string();
    let mut warnings = Vec::new();
    for r in rules.iter().filter(|r| r.enabled && r.kind.is_request() == request && !r.kind.is_first_line()) {
        if r.kind.is_header() {
            h = apply_headers(r, &h, &mut warnings);
        } else {
            b = apply_body(r, &b, &mut warnings);
        }
    }
    // a body rule (a command especially) may have changed the body's length; keep the headers
    // it is framed by honest
    if b.len() != body.len() {
        h = reconcile_content_length(&h, b.len());
    }
    (h, b, warnings)
}

/// Apply the enabled "Request first line" rules to a request line ("GET /a?b=1 HTTP/1.1").
/// Only that line is offered to them, so a path can be rewritten without a rule reaching the
/// same text in a header or in the body. External-command rules never run on the request line;
/// a command transforms a header block or a body, never the one line a method and path live on.
pub fn apply_first_line(rules: &[Rule], line: &str) -> String {
    let mut sink = Vec::new();
    let mut out = line.to_string();
    for r in rules.iter().filter(|r| r.enabled && r.kind.is_first_line() && r.action == RuleAction::Replace) {
        out = apply_body(r, &out, &mut sink);
    }
    out
}

/// `raw` with its first line rewritten by the enabled "Request first line" rules; the headers
/// and the body are left exactly as they are. Used where a whole request is in hand.
pub fn apply_first_line_of(rules: &[Rule], raw: &str) -> String {
    if !rules.iter().any(|r| r.enabled && r.kind.is_first_line()) {
        return raw.to_string();
    }
    match raw.split_once('\n') {
        Some((first, rest)) => {
            // a CR belongs to the line ending, not to the HTTP version
            let (line, cr) = match first.strip_suffix('\r') {
                Some(l) => (l, "\r"),
                None => (first, ""),
            };
            format!("{}{cr}\n{rest}", apply_first_line(rules, line))
        }
        None => apply_first_line(rules, raw),
    }
}

/// The original's 12 default rules, all disabled.
pub fn defaults() -> Vec<Rule> {
    let rule = |kind: RuleType, m: &str, r: &str, c: &str| Rule {
        enabled: false,
        regex: true,
        match_text: m.into(),
        replace_text: r.into(),
        comment: c.into(),
        case_sensitive: kind.starts_case_sensitive(),
        kind,
        ..Rule::new(kind)
    };
    use RuleType::*;
    vec![
        rule(RequestHeader, "^User-Agent.*$", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0", "Emulate Edge"),
        rule(RequestHeader, "^User-Agent.*$", "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1", "Emulate iOS"),
        rule(RequestHeader, "^User-Agent.*$", "User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36", "Emulate Android"),
        rule(RequestHeader, "^If-Modified-Since.*$", "", "Require non-cached response"),
        rule(RequestHeader, "^If-None-Match.*$", "", "Require non-cached response"),
        rule(RequestHeader, "^Referer.*$", "", "Hide Referer header"),
        rule(RequestHeader, "^Accept-Encoding.*$", "", "Require non-compressed responses"),
        rule(ResponseHeader, "^Set-Cookie.*$", "", "Ignore cookies"),
        rule(RequestHeader, "^Host: foo.example.org$", "Host: bar.example.org", "Rewrite Host header"),
        rule(RequestHeader, "", "Origin: foo.example.org", "Add spoofed CORS origin"),
        rule(ResponseHeader, "^Strict\\-Transport\\-Security.*$", "", "Remove HSTS headers"),
        rule(ResponseHeader, "", "X-XSS-Protection: 0", "Disable browser XSS protection"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn r(kind: RuleType, regex: bool, m: &str, rep: &str) -> Rule {
        Rule { enabled: true, kind, regex, match_text: m.into(), replace_text: rep.into(), comment: String::new(), case_sensitive: true, ..Rule::new(kind) }
    }

    /// The same rule, matched loosely.
    fn ci(mut rule: Rule) -> Rule {
        rule.case_sensitive = false;
        rule
    }

    /// A first line rule sees the request line and nothing else, and every rule compares its
    /// match the way its "Case sensitive" setting says. Each case runs the rules over a line,
    /// a header block and a body at once, so a rule reaching text it has no business touching
    /// shows up as a failure on the other two.
    #[test]
    fn first_line_rules_and_case_sensitivity_matrix() {
        struct Case<'a> {
            name: &'a str,
            rules: Vec<Rule>,
            want_line: &'a str,
            want_headers: &'a str,
            want_body: &'a str,
        }
        // the same text appears in all three places, so an over-reaching rule is visible
        const LINE: &str = "GET /api/v1/users HTTP/1.1";
        const HEADERS: &str = "user-agent: curl/8.5\nReferer: https://host/api/v1/users";
        const BODY: &str = "next=/api/v1/users&role=Admin";

        let cases = [
            Case {
                name: "a first line rule rewrites the path and nothing else",
                rules: vec![r(RuleType::RequestFirstLine, false, "/api/v1/", "/api/v2/")],
                want_line: "GET /api/v2/users HTTP/1.1",
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "and can rewrite the method",
                rules: vec![r(RuleType::RequestFirstLine, true, "^GET\\b", "POST")],
                want_line: "POST /api/v1/users HTTP/1.1",
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "a header rule never reaches the first line",
                rules: vec![r(RuleType::RequestHeader, true, "^Referer.*$", "")],
                want_line: LINE,
                want_headers: "user-agent: curl/8.5",
                want_body: BODY,
            },
            Case {
                name: "a body rule never reaches it either",
                rules: vec![r(RuleType::RequestBody, false, "/api/v1/users", "/api/v2/users")],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: "next=/api/v2/users&role=Admin",
            },
            // header field names are case-insensitive, and an HTTP/2 downgrade lower-cases them
            Case {
                name: "a loose header rule matches a lower-cased field name",
                rules: vec![ci(r(RuleType::RequestHeader, true, "^User-Agent:.*$", "User-Agent: ForgeProxy"))],
                want_line: LINE,
                want_headers: "User-Agent: ForgeProxy\nReferer: https://host/api/v1/users",
                want_body: BODY,
            },
            Case {
                name: "an exact one does not",
                rules: vec![r(RuleType::RequestHeader, true, "^User-Agent:.*$", "User-Agent: ForgeProxy")],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "an exact body rule leaves mismatched capitals alone",
                rules: vec![r(RuleType::RequestBody, false, "admin", "guest")],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "a loose one catches them",
                rules: vec![ci(r(RuleType::RequestBody, false, "admin", "guest"))],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: "next=/api/v1/users&role=guest",
            },
            Case {
                name: "an exact first line rule leaves a mismatched path alone",
                rules: vec![r(RuleType::RequestFirstLine, false, "/API/V1/", "/api/v2/")],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "a loose one rewrites it",
                rules: vec![ci(r(RuleType::RequestFirstLine, false, "/API/V1/", "/api/v2/"))],
                want_line: "GET /api/v2/users HTTP/1.1",
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "a disabled first line rule does nothing",
                rules: vec![Rule { enabled: false, ..r(RuleType::RequestFirstLine, false, "/api/v1/", "/api/v2/") }],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: BODY,
            },
            Case {
                name: "response rules are left out of a request entirely",
                rules: vec![r(RuleType::ResponseBody, false, "/api/v1/users", "/gone")],
                want_line: LINE,
                want_headers: HEADERS,
                want_body: BODY,
            },
        ];

        assert_table!(cases, |idx, Case { name, rules, want_line, want_headers, want_body }| {
            let (headers, body) = apply(&rules, true, HEADERS, BODY);
            assert_eq!(apply_first_line(&rules, LINE), want_line, "case #{idx} ({name}): first line");
            assert_eq!(headers, want_headers, "case #{idx} ({name}): headers");
            assert_eq!(body, want_body, "case #{idx} ({name}): body");
        });
    }

    /// `apply_first_line_of` rewrites line one of a whole request and leaves every byte after
    /// it where it was, whichever line ending the request uses.
    #[test]
    fn rewriting_the_first_line_of_a_whole_request_matrix() {
        let rules = vec![r(RuleType::RequestFirstLine, false, "/api/v1/", "/api/v2/")];
        let cases: [(&str, &str, &str); 4] = [
            ("LF, with a header and a body that read the same",
                "GET /api/v1/users HTTP/1.1\nReferer: /api/v1/users\n\nnext=/api/v1/users",
                "GET /api/v2/users HTTP/1.1\nReferer: /api/v1/users\n\nnext=/api/v1/users"),
            ("CRLF keeps its carriage returns",
                "GET /api/v1/users HTTP/1.1\r\nHost: a.test\r\n\r\n",
                "GET /api/v2/users HTTP/1.1\r\nHost: a.test\r\n\r\n"),
            ("a request line on its own", "GET /api/v1/users HTTP/1.1", "GET /api/v2/users HTTP/1.1"),
            ("nothing to match", "GET /other HTTP/1.1\nHost: a.test\n\n", "GET /other HTTP/1.1\nHost: a.test\n\n"),
        ];
        assert_table!(cases, |idx, (what, raw, want)| {
            assert_eq!(apply_first_line_of(&rules, raw), want, "case #{idx} ({what})");
        });
    }

    /// Rules saved before "Case sensitive" existed are read back matching exactly as typed,
    /// which is how they behaved when they were saved.
    #[test]
    fn a_rule_saved_without_case_sensitivity_stays_exact() {
        let json = r#"{"enabled":true,"kind":"RequestHeader","regex":true,"match_text":"^Referer.*$","replace_text":"","comment":"old"}"#;
        let old: Rule = serde_json::from_str(json).unwrap();
        assert!(old.case_sensitive, "an older rule keeps the matching it was written for");
        // while a new rule of that kind is offered the setting that suits it
        assert!(!Rule::new(RuleType::RequestHeader).case_sensitive, "header names are matched loosely");
        assert!(Rule::new(RuleType::RequestFirstLine).case_sensitive, "a request line exactly");
        assert!(Rule::new(RuleType::RequestBody).case_sensitive, "a body exactly");
    }

    #[test]
    fn request_response_rewrite_matrix() {
        struct RewriteCase<'a> {
            name: &'a str,
            rules: Vec<Rule>,
            is_request: bool,
            headers_in: &'a str,
            body_in: &'a str,
            expected_headers: &'a str,
            expected_body: &'a str,
        }

        let cases = [
            RewriteCase {
                name: "blank match on RequestHeader appends new header",
                rules: vec![r(RuleType::RequestHeader, false, "", "X-Test: 1")],
                is_request: true,
                headers_in: "Accept: */*",
                body_in: "",
                expected_headers: "Accept: */*\nX-Test: 1",
                expected_body: "",
            },
            RewriteCase {
                name: "blank replace on RequestHeader removes matching header line",
                rules: vec![r(RuleType::RequestHeader, true, "^Referer.*$", "")],
                is_request: true,
                headers_in: "Referer: https://old.test\nAccept: */*",
                body_in: "",
                expected_headers: "Accept: */*",
                expected_body: "",
            },
            RewriteCase {
                name: "regex RequestHeader rewrites User-Agent line",
                rules: vec![r(RuleType::RequestHeader, true, "^User-Agent.*$", "User-Agent: Custom/2.0")],
                is_request: true,
                headers_in: "User-Agent: Mozilla/5.0\nAccept: */*",
                body_in: "",
                expected_headers: "User-Agent: Custom/2.0\nAccept: */*",
                expected_body: "",
            },
            RewriteCase {
                name: "request-line URL path rewrite via RequestHeader rule",
                rules: vec![r(RuleType::RequestHeader, false, "/v1/legacy", "/v2/modern")],
                is_request: true,
                headers_in: "GET /v1/legacy?id=1 HTTP/1.1\nHost: api.example.com",
                body_in: "",
                expected_headers: "GET /v2/modern?id=1 HTTP/1.1\nHost: api.example.com",
                expected_body: "",
            },
            RewriteCase {
                name: "ResponseHeader rule is skipped when evaluating a request",
                rules: vec![r(RuleType::ResponseHeader, true, "^Set-Cookie.*$", "")],
                is_request: true,
                headers_in: "Set-Cookie: a=b",
                body_in: "",
                expected_headers: "Set-Cookie: a=b",
                expected_body: "",
            },
            RewriteCase {
                name: "ResponseHeader rule removes HSTS and appends X-XSS-Protection on response",
                rules: vec![
                    r(RuleType::ResponseHeader, true, r"^Strict-Transport-Security.*$", ""),
                    r(RuleType::ResponseHeader, false, "", "X-XSS-Protection: 0"),
                ],
                is_request: false,
                headers_in: "Content-Type: text/html\nStrict-Transport-Security: max-age=31536000",
                body_in: "ok",
                expected_headers: "Content-Type: text/html\nX-XSS-Protection: 0",
                expected_body: "ok",
            },
            RewriteCase {
                name: "literal RequestBody replacement escapes regex metacharacters",
                rules: vec![r(RuleType::RequestBody, false, "a.b", "X")],
                is_request: true,
                headers_in: "",
                body_in: "a.b axb",
                expected_headers: "",
                expected_body: "X axb",
            },
            RewriteCase {
                name: "regex ResponseBody replacement updates matching tokens",
                rules: vec![r(RuleType::ResponseBody, true, r#""role"\s*:\s*"user""#, r#""role":"admin""#)],
                is_request: false,
                headers_in: "Content-Type: application/json",
                body_in: r#"{"user":"alice","role": "user"}"#,
                expected_headers: "Content-Type: application/json",
                expected_body: r#"{"user":"alice","role":"admin"}"#,
            },
        ];

        assert_table!(cases, |idx, case| {
            let (got_h, got_b) = apply(&case.rules, case.is_request, case.headers_in, case.body_in);
            assert_eq!(got_h, case.expected_headers, "case #{idx} ({}) headers", case.name);
            assert_eq!(got_b, case.expected_body, "case #{idx} ({}) body", case.name);
        });
    }

    #[test]
    fn rewrite_edge_cases_matrix() {
        let mut disabled_rule = r(RuleType::RequestHeader, false, "Host: a", "Host: b");
        disabled_rule.enabled = false;

        let binary_lossy = String::from_utf8_lossy(b"\x1f\x8b\x08\x00binary_payload_token\xff").into_owned();
        let binary_expected = binary_lossy.replace("binary_payload_token", "patched_token");

        let cases: Vec<(&str, Vec<Rule>, bool, String, String, String, String)> = vec![
            (
                "regex capture group references ($1, $2) in header rewrite",
                vec![r(RuleType::RequestHeader, true, r"^X-Env:\s*(\w+)-(\d+)$", "X-Env: $2/$1")],
                true,
                "X-Env: prod-42\nAccept: */*".into(),
                "".into(),
                "X-Env: 42/prod\nAccept: */*".into(),
                "".into(),
            ),
            (
                "regex capture group references ($1, $2) in body rewrite",
                vec![r(RuleType::RequestBody, true, r"(\w+)=(\d+)", "$1:[$2]")],
                true,
                "".into(),
                "a=10&b=20".into(),
                "".into(),
                "a:[10]&b:[20]".into(),
            ),
            (
                "literal mode preserves '$1' verbatim without capture expansion",
                vec![r(RuleType::RequestBody, false, "PRICE", "$100")],
                true,
                "".into(),
                "cost is PRICE".into(),
                "".into(),
                "cost is $100".into(),
            ),
            (
                "empty match and empty replace on header is a no-op",
                vec![r(RuleType::RequestHeader, false, "", "")],
                true,
                "Host: example.com".into(),
                "body".into(),
                "Host: example.com".into(),
                "body".into(),
            ),
            (
                "empty match on body is a no-op (never inserts between every char)",
                vec![r(RuleType::RequestBody, false, "", "INJECT")],
                true,
                "".into(),
                "body".into(),
                "".into(),
                "body".into(),
            ),
            (
                "empty replace on body deletes matched substring",
                vec![r(RuleType::RequestBody, false, "SECRET", "")],
                true,
                "".into(),
                "a=SECRET&b=1".into(),
                "".into(),
                "a=&b=1".into(),
            ),
            (
                "missing target header leaves existing headers unchanged",
                vec![r(RuleType::RequestHeader, true, "^X-NonExistent:.*$", "X-NonExistent: 1")],
                true,
                "Host: example.com\nAccept: */*".into(),
                "".into(),
                "Host: example.com\nAccept: */*".into(),
                "".into(),
            ),
            (
                "invalid regex pattern is safely ignored without panic",
                vec![r(RuleType::RequestBody, true, "(unclosed_group", "X")],
                true,
                "".into(),
                "original body".into(),
                "".into(),
                "original body".into(),
            ),
            (
                "disabled rule is skipped",
                vec![disabled_rule],
                true,
                "Host: a".into(),
                "".into(),
                "Host: a".into(),
                "".into(),
            ),
            (
                "non-UTF8 / binary lossy payload rewrites ASCII marker without panicking",
                vec![r(RuleType::RequestBody, false, "binary_payload_token", "patched_token")],
                true,
                "".into(),
                binary_lossy,
                "".into(),
                binary_expected,
            ),
        ];

        assert_table!(cases, |idx, (name, rules, is_req, h_in, b_in, exp_h, exp_b)| {
            let (got_h, got_b) = apply(&rules, is_req, &h_in, &b_in);
            assert_eq!(got_h, exp_h, "case #{idx} ({name}) headers");
            assert_eq!(got_b, exp_b, "case #{idx} ({name}) body");
        });

        // Verify shipped defaults() count and labels
        let defs = defaults();
        assert_eq!(defs.len(), 12);
        assert!(defs.iter().all(|d| !d.enabled));
        for kind in RuleType::ALL {
            assert!(!kind.label().is_empty());
        }
    }

    /// Build an enabled External Command rule of `kind` with the given command line.
    fn cmd(kind: RuleType, command: &str, timeout_ms: u64) -> Rule {
        Rule { action: RuleAction::TransformCommand, command: command.into(), timeout_ms, ..Rule::new(kind) }
    }

    /// A rule saved before the action model existed reads back as a plain replacement with an
    /// empty command and the default timeout, so old projects behave exactly as they did.
    #[test]
    fn a_rule_saved_before_external_commands_reads_as_a_replacement() {
        let json = r#"{"enabled":true,"kind":"RequestBody","regex":false,"match_text":"a","replace_text":"b","comment":"","case_sensitive":true}"#;
        let old: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(old.action, RuleAction::Replace);
        assert!(old.command.is_empty());
        assert_eq!(old.timeout_ms, DEFAULT_TRANSFORM_TIMEOUT_MS);
        // and the default timeout on a fresh rule is the documented 1000 ms
        assert_eq!(Rule::new(RuleType::RequestBody).timeout_ms, 1000);
    }

    /// A fast local filter transforms the body and the returned headers are reframed: the
    /// Content-Length follows the new byte length, for a request and a response alike.
    #[cfg(unix)]
    #[test]
    fn a_command_transform_updates_the_body_and_content_length() {
        // `tr -d x` removes every 'x', so the body shrinks and its length must follow
        for request in [true, false] {
            let kind = if request { RuleType::RequestBody } else { RuleType::ResponseBody };
            let rule = cmd(kind, "tr -d x", 2000);
            let headers = "Content-Type: text/plain\nContent-Length: 7";
            let (h, b, warns) = apply_collecting(&[rule], request, headers, "xaxbxcx");
            assert_eq!(b, "abc", "the filter's output replaces the body (request={request})");
            assert!(h.contains("Content-Length: 3"), "the length was reframed: {h}");
            assert!(!h.contains("Content-Length: 7"), "the stale length is gone: {h}");
            assert!(warns.is_empty(), "a clean run warns about nothing: {warns:?}");
        }
    }

    /// A chunked response body transformed whole is reframed by length, the stale chunked
    /// Transfer-Encoding removed, when the command changes the byte count.
    #[cfg(unix)]
    #[test]
    fn a_command_transform_strips_chunked_encoding_when_it_reframes() {
        let rule = cmd(RuleType::ResponseBody, "tr -d x", 2000);
        let headers = "Content-Type: text/plain\nTransfer-Encoding: chunked";
        let (h, b, _) = apply_collecting(&[rule], false, headers, "xxhixx");
        assert_eq!(b, "hi");
        assert!(!h.to_ascii_lowercase().contains("transfer-encoding"), "chunked framing is gone: {h}");
        assert!(h.contains("Content-Length: 2"), "a length frames it instead: {h}");
    }

    /// A command that outruns its timeout is stopped promptly, the original body is kept, and a
    /// warning is recorded rather than the exchange being dropped.
    #[cfg(unix)]
    #[test]
    fn a_slow_command_times_out_and_keeps_the_original() {
        let rule = cmd(RuleType::RequestBody, "sleep 5", 120);
        let started = std::time::Instant::now();
        let (h, b, warns) = apply_collecting(&[rule], true, "Content-Length: 8", "original");
        assert!(started.elapsed() < Duration::from_secs(2), "the slow command was stopped near its timeout, not waited out");
        assert_eq!(b, "original", "the body is untouched when the command is stopped");
        assert!(h.contains("Content-Length: 8"), "and so the length header stands: {h}");
        assert_eq!(warns.len(), 1, "one warning explains the fallback");
        assert!(warns[0].contains("stopped") || warns[0].to_lowercase().contains("longer"), "{:?}", warns);
    }

    /// A command that exits non-zero, and one whose program does not exist, both fall back to
    /// the original bytes without breaking the message, each with a warning.
    #[cfg(unix)]
    #[test]
    fn a_failing_or_missing_command_falls_back_cleanly() {
        let cases: [(&str, &str); 2] = [
            ("non-zero exit", "false"),
            ("missing program", "forgeproxy_no_such_program_42"),
        ];
        assert_table!(cases, |idx, (name, command)| {
            let rule = cmd(RuleType::ResponseBody, command, 1000);
            let (h, b, warns) = apply_collecting(&[rule], false, "Content-Length: 4", "keep");
            assert_eq!(b, "keep", "case #{idx} ({name}): the body survives");
            assert!(h.contains("Content-Length: 4"), "case #{idx} ({name}): the headers survive: {h}");
            assert_eq!(warns.len(), 1, "case #{idx} ({name}): the fallback is noted, not silent");
        });
    }

    /// The match text gates a command: a non-matching gate leaves the slice alone and never
    /// starts the process, while a matching or blank gate lets it run. A header block is piped
    /// and replaced whole.
    #[cfg(unix)]
    #[test]
    fn a_command_gate_decides_whether_the_process_runs() {
        // gate matches: the whole header block is upper-cased by `tr`
        let run = cmd(RuleType::RequestHeader, "tr a-z A-Z", 2000);
        let run = Rule { match_text: "accept".into(), ..run };
        let (h, _, warns) = apply_collecting(&[run], true, "Accept: text/html\nHost: a.test", "");
        assert_eq!(h, "ACCEPT: TEXT/HTML\nHOST: A.TEST", "a matched gate runs the command on the block");
        assert!(warns.is_empty());

        // gate does not match: the command never runs, the block is untouched
        let skip = Rule { match_text: "x-absent".into(), ..cmd(RuleType::RequestHeader, "tr a-z A-Z", 2000) };
        let (h, _, _) = apply_collecting(&[skip], true, "Accept: text/html", "");
        assert_eq!(h, "Accept: text/html", "a closed gate leaves the block as it was");
    }
}
