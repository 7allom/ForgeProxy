//! Target scope: include and exclude rules, and the in-scope test every tool uses.
//!
//! A rule's prefix can be a full URL prefix (`https://example.com/app`), an origin
//! (`http://127.0.0.1:8080`), a hostname (`example.com`, any scheme and port) or a domain
//! (`*.example.com` / `.example.com`, the domain and its subdomains). Matching compares scheme,
//! host, port and path separately, so `https://example.com` does not match
//! `https://example.com.evil.net`. In advanced mode each prefix is a regular expression tested
//! against the whole URL instead.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScopeRule {
    pub enabled: bool,
    pub prefix: String,
    /// Also match subdomains of the rule's host.
    #[serde(default)]
    pub subdomains: bool,
}

impl ScopeRule {
    pub fn new(prefix: impl Into<String>) -> Self {
        ScopeRule { enabled: true, prefix: prefix.into(), subdomains: false }
    }
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
        let prefix = self.prefix.trim();
        if !self.enabled || prefix.is_empty() {
            return false;
        }
        if advanced {
            return crate::regex_cache::get(prefix).is_some_and(|re| re.is_match(url));
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
}

impl TargetScope {
    /// In scope: matches an enabled include rule (or there are none) and no enabled exclude
    /// rule. Exclusions always win.
    pub fn is_in_scope(&self, url_or_host: &str) -> bool {
        let any_include = self.include.iter().any(|r| r.enabled && !r.prefix.trim().is_empty());
        let included = !any_include || self.include.iter().any(|r| r.matches(url_or_host, self.advanced));
        included && !self.exclude.iter().any(|r| r.matches(url_or_host, self.advanced))
    }

    /// "Add to scope": include `prefix` (unless an identical rule exists) and drop any
    /// identical exclusion.
    pub fn add(&mut self, prefix: &str) {
        self.exclude.retain(|r| r.prefix.trim() != prefix);
        if !self.include.iter().any(|r| r.prefix.trim() == prefix) {
            self.include.push(ScopeRule::new(prefix));
        }
    }

    /// "Remove from scope": drop identical include rules; if `url` is still in scope after
    /// that (a broader rule, or no include rules at all), exclude `prefix`.
    pub fn remove(&mut self, prefix: &str, url: &str) {
        self.include.retain(|r| r.prefix.trim() != prefix);
        if self.is_in_scope(url) && !self.exclude.iter().any(|r| r.prefix.trim() == prefix) {
            self.exclude.push(ScopeRule::new(prefix));
        }
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
