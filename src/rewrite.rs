//! Proxy match-and-replace rules, following the original's documented rules
//! (resources/Documentation/.../proxy/match-and-replace/creating.html) and its
//! 12 shipped default rules (ProjectDefaults.json proxy.match_replace_rules).
//!
//! - Header rules work on one header line at a time.
//! - Blank match on a header rule: the replacement is added as a new header.
//! - Blank replace on a header rule: every matching header is removed.
//! - "Regex match" treats the match as a regular expression; otherwise plain text.

use regex::Regex;

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RuleType {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

impl RuleType {
    pub const ALL: [RuleType; 4] =
        [RuleType::RequestHeader, RuleType::RequestBody, RuleType::ResponseHeader, RuleType::ResponseBody];
    pub fn label(&self) -> &'static str {
        match self {
            RuleType::RequestHeader => "Request header",
            RuleType::RequestBody => "Request body",
            RuleType::ResponseHeader => "Response header",
            RuleType::ResponseBody => "Response body",
        }
    }
    fn is_header(&self) -> bool {
        matches!(self, RuleType::RequestHeader | RuleType::ResponseHeader)
    }
    fn is_request(&self) -> bool {
        matches!(self, RuleType::RequestHeader | RuleType::RequestBody)
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
}

fn matcher(rule: &Rule) -> Option<Regex> {
    if rule.regex { crate::regex_cache::get(&rule.match_text) } else { crate::regex_cache::get(&regex::escape(&rule.match_text)) }
}

fn apply_headers(rule: &Rule, headers: &str) -> String {
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

fn apply_body(rule: &Rule, body: &str) -> String {
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

/// Apply enabled request (or response) rules to (headers, body).
pub fn apply(rules: &[Rule], request: bool, headers: &str, body: &str) -> (String, String) {
    let mut h = headers.to_string();
    let mut b = body.to_string();
    for r in rules.iter().filter(|r| r.enabled && r.kind.is_request() == request) {
        if r.kind.is_header() {
            h = apply_headers(r, &h);
        } else {
            b = apply_body(r, &b);
        }
    }
    (h, b)
}

/// The original's 12 default rules, all disabled.
pub fn defaults() -> Vec<Rule> {
    let rule = |kind, m: &str, r: &str, c: &str| Rule {
        enabled: false,
        kind,
        regex: true,
        match_text: m.into(),
        replace_text: r.into(),
        comment: c.into(),
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
        Rule { enabled: true, kind, regex, match_text: m.into(), replace_text: rep.into(), comment: String::new() }
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
}
