//! Proxy match-and-replace rules, following the original's documented rules
//! (resources/Documentation/.../proxy/match-and-replace/creating.html) and its
//! 12 shipped default rules (ProjectDefaults.json proxy.match_replace_rules).
//!
//! - Header rules work on one header line at a time.
//! - Blank match on a header rule: the replacement is added as a new header.
//! - Blank replace on a header rule: every matching header is removed.
//! - "Regex match" treats the match as a regular expression; otherwise plain text.

use regex::Regex;

#[derive(Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
                out.push(re.replace_all(line, regex::NoExpand(&rule.replace_text)).into_owned());
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
        Some(re) => re.replace_all(body, regex::NoExpand(&rule.replace_text)).into_owned(),
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
    fn r(kind: RuleType, regex: bool, m: &str, rep: &str) -> Rule {
        Rule { enabled: true, kind, regex, match_text: m.into(), replace_text: rep.into(), comment: String::new() }
    }
    #[test]
    fn blank_match_adds_header() {
        let (h, _) = apply(&[r(RuleType::RequestHeader, false, "", "X-Test: 1")], true, "Accept: */*", "");
        assert_eq!(h, "Accept: */*\nX-Test: 1");
    }
    #[test]
    fn blank_replace_removes_header() {
        let (h, _) = apply(&[r(RuleType::RequestHeader, true, "^Referer.*$", "")], true, "Referer: x\nAccept: */*", "");
        assert_eq!(h, "Accept: */*");
    }
    #[test]
    fn regex_rewrites_user_agent() {
        let (h, _) = apply(&[r(RuleType::RequestHeader, true, "^User-Agent.*$", "User-Agent: X")], true, "User-Agent: abc", "");
        assert_eq!(h, "User-Agent: X");
    }
    #[test]
    fn response_rules_skip_requests() {
        let (h, _) = apply(&[r(RuleType::ResponseHeader, true, "^Set-Cookie.*$", "")], true, "Set-Cookie: a=b", "");
        assert_eq!(h, "Set-Cookie: a=b");
    }
    #[test]
    fn literal_body_replace() {
        let (_, b) = apply(&[r(RuleType::RequestBody, false, "a.b", "X")], true, "", "a.b axb");
        assert_eq!(b, "X axb");
    }
}
