//! Target scope: include and exclude rules, and the in-scope test every tool uses.
//!
//! Simple rules match on a prefix: a full URL prefix (`https://example.com/app`), an origin
//! (`http://127.0.0.1:8080`), a hostname (`example.com`, any scheme and port) or a domain
//! (`*.example.com` / `.example.com`, the domain and its subdomains). Matching compares scheme,
//! host, port and path separately, so `https://example.com` does not match
//! `https://example.com.evil.net`.
//!
//! Advanced rules match on four parts of the address instead -- protocol, host, port and file
//! (the path with its query) -- the last three as regular expressions, each one empty to match
//! anything. The expressions are searched, not anchored, so `example` matches anywhere in the
//! host unless the pattern says `^example$`. A rule that sets none of the four but carries a
//! prefix is matched the way advanced rules worked before they had parts: the prefix as one
//! regular expression over the whole URL. That keeps scopes saved by earlier versions doing
//! what they did.
//!
//! An unparseable expression matches nothing, so a broken include rule includes nothing and a
//! broken exclude rule excludes nothing. Patterns are compiled through [`crate::regex_cache`],
//! so filtering a table per frame recompiles nothing.

use serde::{Deserialize, Serialize};

/// The protocol an advanced rule asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeProtocol {
    #[default]
    Any,
    Http,
    Https,
}

impl ScopeProtocol {
    pub const ALL: [ScopeProtocol; 3] = [ScopeProtocol::Any, ScopeProtocol::Http, ScopeProtocol::Https];

    pub fn label(&self) -> &'static str {
        match self {
            ScopeProtocol::Any => "Any",
            ScopeProtocol::Http => "HTTP",
            ScopeProtocol::Https => "HTTPS",
        }
    }

    /// The scheme this asks for, or `None` for any.
    fn scheme(&self) -> Option<&'static str> {
        match self {
            ScopeProtocol::Any => None,
            ScopeProtocol::Http => Some("http"),
            ScopeProtocol::Https => Some("https"),
        }
    }
}

/// One scope rule. It carries both shapes: `prefix` (and `subdomains`) are what a simple rule
/// matches on, `protocol`/`host`/`port`/`file` what an advanced one does, and
/// [`TargetScope::advanced`] decides which of the two is read. Every field added after the
/// first release defaults, so a scope written by an earlier version loads unchanged.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScopeRule {
    pub enabled: bool,
    pub prefix: String,
    /// Also match subdomains of the rule's host.
    #[serde(default)]
    pub subdomains: bool,
    #[serde(default)]
    pub protocol: ScopeProtocol,
    /// Host pattern; empty matches any host.
    #[serde(default)]
    pub host: String,
    /// Port pattern, matched against the port in digits; empty matches any port.
    #[serde(default)]
    pub port: String,
    /// Pattern for the path and query together; empty matches any.
    #[serde(default)]
    pub file: String,
}

impl ScopeRule {
    /// A simple rule matching `prefix`.
    pub fn new(prefix: impl Into<String>) -> Self {
        ScopeRule {
            enabled: true,
            prefix: prefix.into(),
            subdomains: false,
            protocol: ScopeProtocol::default(),
            host: String::new(),
            port: String::new(),
            file: String::new(),
        }
    }

    /// Does this rule name any of the four parts an advanced rule matches on?
    pub fn has_parts(&self) -> bool {
        self.protocol != ScopeProtocol::Any
            || !self.host.trim().is_empty()
            || !self.port.trim().is_empty()
            || !self.file.trim().is_empty()
    }

    /// The patterns on this rule that are not valid regular expressions, named for the UI.
    pub fn bad_patterns(&self) -> Vec<&'static str> {
        [("Host", &self.host), ("Port", &self.port), ("File", &self.file)]
            .into_iter()
            .filter(|(_, pattern)| !pattern.trim().is_empty() && crate::regex_cache::get(pattern.trim()).is_none())
            .map(|(name, _)| name)
            .collect()
    }
}

/// Does `pattern` match `text`? An empty pattern matches anything; one that will not compile
/// matches nothing.
fn pattern_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.trim();
    pattern.is_empty() || crate::regex_cache::get(pattern).is_some_and(|re| re.is_match(text))
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TargetScope {
    pub include: Vec<ScopeRule>,
    pub exclude: Vec<ScopeRule>,
    /// "Use advanced scope control": prefixes are regular expressions over the full URL.
    #[serde(default)]
    pub advanced: bool,
}

/// A URL (or bare host) split for matching. `port` is the explicit or scheme-default port,
/// None when neither is known (a bare host).
#[derive(Debug, PartialEq)]
struct Target {
    scheme: Option<String>,
    host: String,
    port: Option<u16>,
    path: String,
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme { "http" => Some(80), "https" => Some(443), _ => None }
}

/// Parse "scheme://host:port/path", "host:port/path" or "host".
fn parse(s: &str) -> Target {
    let s = s.trim();
    let (scheme, rest) = match s.find("://") {
        Some(i) => (Some(s[..i].to_ascii_lowercase()), &s[i + 3..]),
        None => (None, s),
    };
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(cut);
    let authority = authority.rsplit('@').next().unwrap_or(authority); // drop user:pass@
    // [v6]:port, host:port, host
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        let host = &authority[1..=end];
        let port = authority[end + 2..].strip_prefix(':').and_then(|p| p.parse().ok());
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h.to_string(), p.parse().ok()),
            _ => (authority.to_string(), None),
        }
    };
    let port = port.or_else(|| scheme.as_deref().and_then(default_port));
    let path = path.split('#').next().unwrap_or("").to_string();
    Target { scheme, host: host.trim_end_matches('.').to_ascii_lowercase(), port, path }
}

impl ScopeRule {
    fn matches(&self, url: &str, advanced: bool) -> bool {
        if !self.enabled {
            return false;
        }
        if advanced {
            return self.matches_parts(url);
        }
        let prefix = self.prefix.trim();
        if prefix.is_empty() {
            return false;
        }
        let rule = parse(prefix);
        let t = parse(url);
        // host: exact, or the domain and its subdomains for "*.d" / ".d" / the subdomains flag
        let (domain, wildcard) = match rule.host.strip_prefix("*.").or_else(|| rule.host.strip_prefix('.')) {
            Some(d) => (d, true),
            None => (rule.host.as_str(), self.subdomains),
        };
        let host_ok = t.host == domain || (wildcard && t.host.ends_with(&format!(".{domain}")));
        // a scheme or port in the rule must match; a bare-host rule matches any
        let scheme_ok = match (&rule.scheme, &t.scheme) {
            (Some(r), Some(u)) => r == u,
            (Some(_), None) => true, // bare-host target: scheme unknown
            (None, _) => true,
        };
        let port_ok = match (rule.port, t.port) {
            (Some(r), Some(u)) => r == u,
            (Some(_), None) => false, // the rule names a port the target doesn't have
            (None, _) => true,
        };
        let path_ok = rule.path.is_empty() || rule.path == "/" || t.path.starts_with(&rule.path);
        host_ok && scheme_ok && port_ok && path_ok
    }

    /// Advanced matching: protocol, host, port and file, each part that the rule leaves empty
    /// matching anything. A rule that names no part at all falls back to its prefix as one
    /// expression over the whole URL, which is what advanced rules meant before they had parts.
    fn matches_parts(&self, url: &str) -> bool {
        if !self.has_parts() {
            let prefix = self.prefix.trim();
            return !prefix.is_empty() && crate::regex_cache::get(prefix).is_some_and(|re| re.is_match(url));
        }
        let t = parse(url);
        // an address with no scheme of its own (a bare host) cannot contradict the rule
        let protocol_ok = match (self.protocol.scheme(), t.scheme.as_deref()) {
            (Some(want), Some(have)) => want == have,
            (Some(_), None) | (None, _) => true,
        };
        let port = t.port.map(|p| p.to_string()).unwrap_or_default();
        protocol_ok
            && pattern_matches(&self.host, &t.host)
            && pattern_matches(&self.port, &port)
            && pattern_matches(&self.file, &t.path)
    }
}

impl TargetScope {
    /// In scope: matches an enabled include rule (or there are none) and no enabled exclude
    /// rule. Exclusions always win.
    pub fn is_in_scope(&self, url_or_host: &str) -> bool {
        let any_include = self
            .include
            .iter()
            .any(|r| r.enabled && (!r.prefix.trim().is_empty() || (self.advanced && r.has_parts())));
        let included = !any_include || self.include.iter().any(|r| r.matches(url_or_host, self.advanced));
        included && !self.exclude.iter().any(|r| r.matches(url_or_host, self.advanced))
    }

    /// "Add to scope": include `prefix` (unless an identical rule exists) and drop any
    /// identical exclusion. The rule is filled in for both ways of matching, so the same
    /// right-click action does what it says whichever mode the scope is in.
    pub fn add(&mut self, prefix: &str) {
        self.exclude.retain(|r| r.prefix.trim() != prefix);
        if !self.include.iter().any(|r| r.prefix.trim() == prefix) {
            self.include.push(rule_for(prefix));
        }
    }

    /// "Remove from scope": drop identical include rules; if `url` is still in scope after
    /// that (a broader rule, or no include rules at all), exclude `prefix`.
    pub fn remove(&mut self, prefix: &str, url: &str) {
        self.include.retain(|r| r.prefix.trim() != prefix);
        if self.is_in_scope(url) && !self.exclude.iter().any(|r| r.prefix.trim() == prefix) {
            self.exclude.push(rule_for(prefix));
        }
    }
}

/// A rule covering `prefix` both ways: the prefix as written for simple matching, and the
/// parts read out of it for advanced matching. The host and file are escaped, so a dot in a
/// host name stays a dot rather than becoming "any character".
fn rule_for(prefix: &str) -> ScopeRule {
    let t = parse(prefix);
    let protocol = match t.scheme.as_deref() {
        Some("http") => ScopeProtocol::Http,
        Some("https") => ScopeProtocol::Https,
        _ => ScopeProtocol::Any,
    };
    let host = match t.host.strip_prefix("*.").or_else(|| t.host.strip_prefix('.')) {
        // the domain and its subdomains
        Some(domain) => format!(r"(^|\.){}$", regex::escape(domain)),
        None if t.host.is_empty() => String::new(),
        None => format!("^{}$", regex::escape(&t.host)),
    };
    let file = match t.path.as_str() {
        "" | "/" => String::new(),
        path => format!("^{}", regex::escape(path)),
    };
    ScopeRule {
        protocol,
        host,
        port: t.port.map(|p| format!("^{p}$")).unwrap_or_default(),
        file,
        ..ScopeRule::new(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn scope(include: &[&str], exclude: &[&str]) -> TargetScope {
        TargetScope {
            include: include.iter().map(|p| ScopeRule::new(*p)).collect(),
            exclude: exclude.iter().map(|p| ScopeRule::new(*p)).collect(),
            advanced: false,
        }
    }

    /// An advanced rule built from its four parts.
    fn part_rule(protocol: ScopeProtocol, host: &str, port: &str, file: &str) -> ScopeRule {
        ScopeRule { protocol, host: host.into(), port: port.into(), file: file.into(), ..ScopeRule::new("") }
    }

    /// An advanced scope with these include and exclude rules.
    fn part_scope(include: Vec<ScopeRule>, exclude: Vec<ScopeRule>) -> TargetScope {
        TargetScope { include, exclude, advanced: true }
    }

    /// Advanced rules match on protocol, host, port and file. A part the rule leaves empty
    /// matches anything, the three patterns are regular expressions, and an exclusion still
    /// beats every inclusion.
    #[test]
    fn advanced_scope_part_matching_matrix() {
        use ScopeProtocol::{Any, Http, Https};
        struct Case<'a> {
            name: &'a str,
            scope: TargetScope,
            url: &'a str,
            expected: bool,
        }
        let only_http = || part_scope(vec![part_rule(Http, "", "", "")], vec![]);
        let only_8443 = || part_scope(vec![part_rule(Any, "", "^8443$", "")], vec![]);
        let api_of_corp = || {
            part_scope(
                vec![part_rule(Https, r"^([a-z]+\.)?corp\.test$", "", "^/api/")],
                vec![part_rule(Any, "", "", "^/api/internal")],
            )
        };

        let cases = [
            // protocol
            Case { name: "an HTTP rule takes a plaintext address", scope: only_http(), url: "http://example.com/", expected: true },
            Case { name: "and turns away an encrypted one", scope: only_http(), url: "https://example.com/", expected: false },
            Case { name: "an address with no scheme of its own cannot contradict it", scope: only_http(), url: "example.com", expected: true },
            Case { name: "Any takes either", scope: part_scope(vec![part_rule(Any, "^example\\.com$", "", "")], vec![]), url: "https://example.com/", expected: true },
            // port, as digits rather than text
            Case { name: "a port rule matches the port named", scope: only_8443(), url: "https://a.test:8443/x", expected: true },
            Case { name: "and not the scheme's default", scope: only_8443(), url: "https://a.test/x", expected: false },
            Case { name: "nor a port it merely ends with", scope: only_8443(), url: "https://a.test:18443/x", expected: false },
            Case { name: "a plaintext default port is 80", scope: part_scope(vec![part_rule(Any, "", "^80$", "")], vec![]), url: "http://a.test/", expected: true },
            // host
            Case { name: "a host pattern matches the host", scope: api_of_corp(), url: "https://corp.test/api/orders", expected: true },
            Case { name: "and a subdomain the pattern allows for", scope: api_of_corp(), url: "https://shop.corp.test/api/orders", expected: true },
            Case { name: "but not a lookalike domain", scope: api_of_corp(), url: "https://corp.test.evil.net/api/orders", expected: false },
            // file: the path and its query together
            Case { name: "a file pattern matches the path", scope: api_of_corp(), url: "https://corp.test/api/orders?page=2", expected: true },
            Case { name: "and turns away a path it does not cover", scope: api_of_corp(), url: "https://corp.test/admin", expected: false },
            Case { name: "a query-only pattern reaches the query", scope: part_scope(vec![part_rule(Any, "", "", r"\?page=")], vec![]), url: "https://a.test/x?page=2", expected: true },
            // exclusions win
            Case { name: "an exclusion beats the include that matched", scope: api_of_corp(), url: "https://corp.test/api/internal/keys", expected: false },
            Case { name: "the protocol is checked on exclusions too", scope: part_scope(vec![], vec![part_rule(Https, "", "", "")]), url: "http://a.test/", expected: true },
            Case { name: "and an exclusion alone leaves everything else in", scope: part_scope(vec![], vec![part_rule(Https, "", "", "")]), url: "https://a.test/", expected: false },
            // a rule naming no part at all
            Case { name: "an empty advanced rule leaves the scope open", scope: part_scope(vec![part_rule(Any, "", "", "")], vec![]), url: "https://anything.test/", expected: true },
            // a pattern that will not compile matches nothing, rather than panicking
            Case { name: "a broken include pattern includes nothing", scope: part_scope(vec![part_rule(Any, "^(unclosed", "", "")], vec![]), url: "https://a.test/", expected: false },
            Case { name: "a broken exclude pattern excludes nothing", scope: part_scope(vec![], vec![part_rule(Any, "^(unclosed", "", "")]), url: "https://a.test/", expected: true },
            // a disabled rule is not a rule
            Case {
                name: "a disabled include rule leaves the scope open",
                scope: part_scope(vec![ScopeRule { enabled: false, ..part_rule(Https, "^corp\\.test$", "", "") }], vec![]),
                url: "https://elsewhere.test/",
                expected: true,
            },
        ];

        assert_table!(cases, |idx, Case { name, scope, url, expected }| {
            assert_eq!(scope.is_in_scope(url), expected, "case #{idx} ({name}): {url}");
        });
    }

    /// A scope written by a version that had no parts still works: its rules match the way
    /// they did, as one expression over the whole URL, and simple rules are untouched.
    #[test]
    fn scopes_from_earlier_versions_still_match_as_they_did_matrix() {
        let old_advanced = r#"{"include":[{"enabled":true,"prefix":"^https://[a-z]+\\.corp\\.test/"}],
            "exclude":[{"enabled":true,"prefix":"/logout"}],"advanced":true}"#;
        let old_simple = r#"{"include":[{"enabled":true,"prefix":"https://a.test/","subdomains":true}],"exclude":[]}"#;

        let cases: [(&str, &str, &str, bool); 7] = [
            ("the whole-URL expression still includes", old_advanced, "https://shop.corp.test/orders", true),
            ("and still turns away what it never matched", old_advanced, "https://other.test/orders", false),
            ("its exclusion still wins", old_advanced, "https://shop.corp.test/logout", false),
            ("a simple rule is unaffected", old_simple, "https://a.test/x", true),
            ("including its subdomains flag", old_simple, "https://www.a.test/x", true),
            ("and what it leaves out", old_simple, "https://b.test/x", false),
            ("a rule stored without the new fields reads as an empty one", old_simple, "https://a.test/", true),
        ];
        assert_table!(cases, |idx, (what, raw_json, url, expected)| {
            let scope: TargetScope = serde_json::from_str(raw_json).unwrap();
            assert_eq!(scope.is_in_scope(url), expected, "case #{idx} ({what})");
        });

        // the fields a rule gains default, and a rule round-trips through the project file
        let rule: ScopeRule = serde_json::from_str(r#"{"enabled":true,"prefix":"a.test"}"#).unwrap();
        assert_eq!((rule.protocol, rule.host.as_str(), rule.port.as_str(), rule.file.as_str()), (ScopeProtocol::Any, "", "", ""));
        assert!(!rule.has_parts(), "so it is matched on its prefix, not as four empty patterns");
        let back: ScopeRule = serde_json::from_str(&serde_json::to_string(&part_rule(ScopeProtocol::Https, "^a$", "^443$", "^/x")).unwrap()).unwrap();
        assert_eq!(back, part_rule(ScopeProtocol::Https, "^a$", "^443$", "^/x"));
    }

    /// "Add host to scope" has to mean the same thing in either mode, so the rule it leaves
    /// behind carries both the prefix and the parts read out of it.
    #[test]
    fn a_scope_action_fills_in_both_ways_of_matching_matrix() {
        let cases: [(&str, &str, &str, bool); 8] = [
            ("the host it was given", "https://shop.test", "https://shop.test/cart", true),
            ("not another host", "https://shop.test", "https://other.test/cart", false),
            ("not a lookalike of it", "https://shop.test", "https://shop.test.evil.net/", false),
            ("the protocol it was given", "https://shop.test", "http://shop.test/cart", false),
            ("a port it was given", "http://127.0.0.1:8080", "http://127.0.0.1:8080/x", true),
            ("and not another port", "http://127.0.0.1:8080", "http://127.0.0.1:9090/x", false),
            ("a path prefix it was given", "https://shop.test/api", "https://shop.test/api/orders", true),
            ("and not a path outside it", "https://shop.test/api", "https://shop.test/admin", false),
        ];
        assert_table!(cases, |idx, (what, added, url, expected)| {
            for advanced in [false, true] {
                let mut s = TargetScope { advanced, ..TargetScope::default() };
                s.add(added);
                assert_eq!(s.is_in_scope(url), expected, "case #{idx} ({what}), advanced {advanced}");
            }
        });

        // a domain rule covers the domain and its subdomains in both modes
        for advanced in [false, true] {
            let mut s = TargetScope { advanced, ..TargetScope::default() };
            s.add("*.corp.test");
            assert!(s.is_in_scope("https://shop.corp.test/"), "subdomain, advanced {advanced}");
            assert!(s.is_in_scope("https://corp.test/"), "the domain itself, advanced {advanced}");
            assert!(!s.is_in_scope("https://corp.test.evil.net/"), "a lookalike, advanced {advanced}");
        }
    }

    #[test]
    fn scope_evaluation_matrix() {
        struct ScopeCase {
            name: &'static str,
            scope: TargetScope,
            test_url: &'static str,
            expected: bool,
        }

        let mut disabled_rule_scope = scope(&["https://a.test"], &[]);
        disabled_rule_scope.include[0].enabled = false;

        let mut subdomain_flag_scope = scope(&["https://corp.test/"], &[]);
        subdomain_flag_scope.include[0].subdomains = true;

        let mut advanced_regex_scope = scope(&[r"^https://[a-z]+\.corp\.test/"], &[r"/logout"]);
        advanced_regex_scope.advanced = true;

        let cases = [
            // Empty & disabled scope rules
            ScopeCase {
                name: "empty scope includes full URL",
                scope: TargetScope::default(),
                test_url: "https://anything.test/x",
                expected: true,
            },
            ScopeCase {
                name: "empty scope includes bare host",
                scope: TargetScope::default(),
                test_url: "anything.test",
                expected: true,
            },
            ScopeCase {
                name: "disabled include rule leaves scope open for other hosts",
                scope: disabled_rule_scope,
                test_url: "https://b.test/",
                expected: true,
            },
            // URL prefixes & scheme/host boundaries
            ScopeCase {
                name: "URL prefix matches deeper sub-path with query",
                scope: scope(&["https://shop.test/app"], &[]),
                test_url: "https://shop.test/app/cart?id=1",
                expected: true,
            },
            ScopeCase {
                name: "URL prefix rejects sibling path",
                scope: scope(&["https://shop.test/app"], &[]),
                test_url: "https://shop.test/other",
                expected: false,
            },
            ScopeCase {
                name: "URL prefix rejects mismatched scheme",
                scope: scope(&["https://shop.test/app"], &[]),
                test_url: "http://shop.test/app",
                expected: false,
            },
            ScopeCase {
                name: "URL prefix rejects suffix lookalike host",
                scope: scope(&["https://shop.test/app"], &[]),
                test_url: "https://shop.test.evil.net/app",
                expected: false,
            },
            ScopeCase {
                name: "URL prefix rejects prefix lookalike host",
                scope: scope(&["https://shop.test/app"], &[]),
                test_url: "https://evilshop.test/app",
                expected: false,
            },
            ScopeCase {
                name: "URL prefix matches uppercase host case-insensitively",
                scope: scope(&["https://shop.test/app"], &[]),
                test_url: "https://SHOP.test/app",
                expected: true,
            },
            // Ports, bare hosts, IPv4 & IPv6
            ScopeCase {
                name: "explicit port 8080 matches port 8080",
                scope: scope(&["http://127.0.0.1:8080"], &[]),
                test_url: "http://127.0.0.1:8080/login",
                expected: true,
            },
            ScopeCase {
                name: "explicit port 8080 rejects port 8081",
                scope: scope(&["http://127.0.0.1:8080"], &[]),
                test_url: "http://127.0.0.1:8081/login",
                expected: false,
            },
            ScopeCase {
                name: "explicit port 8080 rejects default port 80",
                scope: scope(&["http://127.0.0.1:8080"], &[]),
                test_url: "http://127.0.0.1/login",
                expected: false,
            },
            ScopeCase {
                name: "scheme without port matches explicit default port 443",
                scope: scope(&["https://a.test"], &[]),
                test_url: "https://a.test:443/",
                expected: true,
            },
            ScopeCase {
                name: "scheme without port rejects non-default port 8443",
                scope: scope(&["https://a.test"], &[]),
                test_url: "https://a.test:8443/",
                expected: false,
            },
            ScopeCase {
                name: "bare host matches HTTPS with non-standard port",
                scope: scope(&["a.test"], &[]),
                test_url: "https://a.test:8443/x",
                expected: true,
            },
            ScopeCase {
                name: "bare host matches plain HTTP",
                scope: scope(&["a.test"], &[]),
                test_url: "http://a.test/",
                expected: true,
            },
            ScopeCase {
                name: "bare host matches bare host target",
                scope: scope(&["a.test"], &[]),
                test_url: "a.test",
                expected: true,
            },
            ScopeCase {
                name: "IPv6 origin with port matches exact IPv6 port",
                scope: scope(&["http://[::1]:9000"], &[]),
                test_url: "http://[::1]:9000/",
                expected: true,
            },
            ScopeCase {
                name: "IPv6 origin with port rejects different IPv6 port",
                scope: scope(&["http://[::1]:9000"], &[]),
                test_url: "http://[::1]:9001/",
                expected: false,
            },
            // Wildcard domains & subdomains flag
            ScopeCase {
                name: "wildcard *.corp.test matches apex domain",
                scope: scope(&["*.corp.test"], &[]),
                test_url: "https://corp.test/",
                expected: true,
            },
            ScopeCase {
                name: "wildcard *.corp.test matches first-level subdomain",
                scope: scope(&["*.corp.test"], &[]),
                test_url: "https://api.corp.test/v1",
                expected: true,
            },
            ScopeCase {
                name: "wildcard *.corp.test matches multi-level bare subdomain",
                scope: scope(&["*.corp.test"], &[]),
                test_url: "deep.api.corp.test",
                expected: true,
            },
            ScopeCase {
                name: "wildcard *.corp.test rejects suffix lookalike",
                scope: scope(&["*.corp.test"], &[]),
                test_url: "https://corp.test.evil/",
                expected: false,
            },
            ScopeCase {
                name: "wildcard *.corp.test rejects prefix lookalike",
                scope: scope(&["*.corp.test"], &[]),
                test_url: "https://notcorp.test/",
                expected: false,
            },
            ScopeCase {
                name: "exact host rule without subdomains flag rejects subdomain",
                scope: scope(&["https://corp.test/"], &[]),
                test_url: "https://api.corp.test/",
                expected: false,
            },
            ScopeCase {
                name: "host rule with subdomains flag enabled matches subdomain",
                scope: subdomain_flag_scope,
                test_url: "https://api.corp.test/",
                expected: true,
            },
            // Exclusions overriding inclusions
            ScopeCase {
                name: "included subdomain not matching exclusion stays in scope",
                scope: scope(&["*.corp.test"], &["https://admin.corp.test", "https://corp.test/logout"]),
                test_url: "https://www.corp.test/",
                expected: true,
            },
            ScopeCase {
                name: "excluded subdomain overrides broader wildcard inclusion",
                scope: scope(&["*.corp.test"], &["https://admin.corp.test", "https://corp.test/logout"]),
                test_url: "https://admin.corp.test/panel",
                expected: false,
            },
            ScopeCase {
                name: "excluded path prefix overrides host inclusion",
                scope: scope(&["*.corp.test"], &["https://admin.corp.test", "https://corp.test/logout"]),
                test_url: "https://corp.test/logout?next=/",
                expected: false,
            },
            ScopeCase {
                name: "non-excluded path on included host stays in scope",
                scope: scope(&["*.corp.test"], &["https://admin.corp.test", "https://corp.test/logout"]),
                test_url: "https://corp.test/login",
                expected: true,
            },
            ScopeCase {
                name: "exclusion with no include rules allows non-excluded host",
                scope: scope(&[], &["tracker.test"]),
                test_url: "https://site.test/",
                expected: true,
            },
            ScopeCase {
                name: "exclusion with no include rules blocks excluded host",
                scope: scope(&[], &["tracker.test"]),
                test_url: "https://tracker.test/pixel",
                expected: false,
            },
            // Advanced regex mode
            ScopeCase {
                name: "advanced regex mode matches URL satisfying include and not exclude",
                scope: advanced_regex_scope.clone(),
                test_url: "https://api.corp.test/x",
                expected: true,
            },
            ScopeCase {
                name: "advanced regex mode blocks URL matching exclude regex",
                scope: advanced_regex_scope.clone(),
                test_url: "https://api.corp.test/logout",
                expected: false,
            },
            ScopeCase {
                name: "advanced regex mode rejects URL failing include regex",
                scope: advanced_regex_scope,
                test_url: "http://api.corp.test/x",
                expected: false,
            },
        ];

        assert_table!(cases, |case| {
            assert_eq!(
                case.scope.is_in_scope(case.test_url),
                case.expected,
                "case '{}' for '{}'",
                case.name,
                case.test_url
            );
        });
    }

    #[test]
    fn scope_mutation_and_serialization_matrix() {
        let mut s = TargetScope::default();
        s.add("https://a.test/");
        s.add("https://a.test/");
        assert_eq!(s.include.len(), 1);
        assert!(!s.is_in_scope("https://b.test/"));

        // removing the only include rule reopens the scope, and excludes the removed prefix explicitly
        s.remove("https://a.test/", "https://a.test/x");
        assert!(s.include.is_empty());
        assert!(!s.is_in_scope("https://a.test/x"));

        // adding it again lifts the exclusion
        s.add("https://a.test/");
        assert!(s.exclude.is_empty());
        assert!(s.is_in_scope("https://a.test/x"));

        // removing a URL covered by a broader rule excludes just that prefix
        let mut s = scope(&["*.corp.test"], &[]);
        s.remove("https://admin.corp.test/", "https://admin.corp.test/");
        assert!(!s.is_in_scope("https://admin.corp.test/"));
        assert!(s.is_in_scope("https://www.corp.test/"));

        // backward-compatible deserialization with and without `subdomains`
        let serde_cases = [
            (r#"{"enabled":true,"prefix":"https://a.test/","subdomains":true}"#, true),
            (r#"{"enabled":true,"prefix":"a.test"}"#, false),
        ];
        assert_table!(serde_cases, |(raw_json, expected_subdomains)| {
            let rule: ScopeRule = serde_json::from_str(raw_json).unwrap();
            assert_eq!(rule.subdomains, expected_subdomains, "{raw_json}");
        });
    }
}
