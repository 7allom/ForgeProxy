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

    fn scope(include: &[&str], exclude: &[&str]) -> TargetScope {
        TargetScope {
            include: include.iter().map(|p| ScopeRule::new(*p)).collect(),
            exclude: exclude.iter().map(|p| ScopeRule::new(*p)).collect(),
            advanced: false,
        }
    }

    #[test]
    fn empty_scope_includes_everything() {
        let s = TargetScope::default();
        assert!(s.is_in_scope("https://anything.test/x"));
        assert!(s.is_in_scope("anything.test"));
        // a disabled include rule doesn't close the scope
        let mut s = scope(&["https://a.test"], &[]);
        s.include[0].enabled = false;
        assert!(s.is_in_scope("https://b.test/"));
    }

    #[test]
    fn url_prefixes() {
        let s = scope(&["https://shop.test/app"], &[]);
        assert!(s.is_in_scope("https://shop.test/app/cart?id=1"));
        assert!(!s.is_in_scope("https://shop.test/other"));
        assert!(!s.is_in_scope("http://shop.test/app")); // scheme differs
        // no lookalike hosts
        assert!(!s.is_in_scope("https://shop.test.evil.net/app"));
        assert!(!s.is_in_scope("https://evilshop.test/app"));
        // case-insensitive host
        assert!(s.is_in_scope("https://SHOP.test/app"));
    }

    #[test]
    fn ports() {
        let s = scope(&["http://127.0.0.1:8080"], &[]);
        assert!(s.is_in_scope("http://127.0.0.1:8080/login"));
        assert!(!s.is_in_scope("http://127.0.0.1:8081/login"));
        assert!(!s.is_in_scope("http://127.0.0.1/login")); // default port 80
        // scheme without a port means the scheme's default port
        let s = scope(&["https://a.test"], &[]);
        assert!(s.is_in_scope("https://a.test:443/"));
        assert!(!s.is_in_scope("https://a.test:8443/"));
        // a bare host matches any port and scheme
        let s = scope(&["a.test"], &[]);
        assert!(s.is_in_scope("https://a.test:8443/x"));
        assert!(s.is_in_scope("http://a.test/"));
        assert!(s.is_in_scope("a.test"));
        // IPv6
        let s = scope(&["http://[::1]:9000"], &[]);
        assert!(s.is_in_scope("http://[::1]:9000/"));
        assert!(!s.is_in_scope("http://[::1]:9001/"));
    }

    #[test]
    fn domains_and_subdomains() {
        let s = scope(&["*.corp.test"], &[]);
        assert!(s.is_in_scope("https://corp.test/"));
        assert!(s.is_in_scope("https://api.corp.test/v1"));
        assert!(s.is_in_scope("deep.api.corp.test"));
        assert!(!s.is_in_scope("https://corp.test.evil/"));
        assert!(!s.is_in_scope("https://notcorp.test/"));
        let mut s = scope(&["https://corp.test/"], &[]);
        assert!(!s.is_in_scope("https://api.corp.test/"));
        s.include[0].subdomains = true;
        assert!(s.is_in_scope("https://api.corp.test/"));
    }

    #[test]
    fn exclusions_override_inclusions() {
        let s = scope(&["*.corp.test"], &["https://admin.corp.test", "https://corp.test/logout"]);
        assert!(s.is_in_scope("https://www.corp.test/"));
        assert!(!s.is_in_scope("https://admin.corp.test/panel"));
        assert!(!s.is_in_scope("https://corp.test/logout?next=/"));
        assert!(s.is_in_scope("https://corp.test/login"));
        // exclusion with no include rules
        let s = scope(&[], &["tracker.test"]);
        assert!(s.is_in_scope("https://site.test/"));
        assert!(!s.is_in_scope("https://tracker.test/pixel"));
    }

    #[test]
    fn advanced_mode_uses_regexes() {
        let mut s = scope(&[r"^https://[a-z]+\.corp\.test/"], &[r"/logout"]);
        s.advanced = true;
        assert!(s.is_in_scope("https://api.corp.test/x"));
        assert!(!s.is_in_scope("https://api.corp.test/logout"));
        assert!(!s.is_in_scope("http://api.corp.test/x"));
    }

    #[test]
    fn add_and_remove() {
        let mut s = TargetScope::default();
        s.add("https://a.test/");
        s.add("https://a.test/");
        assert_eq!(s.include.len(), 1);
        assert!(!s.is_in_scope("https://b.test/"));
        // removing the only include rule reopens the scope, so b.test-style URLs are back in,
        // and the removed prefix is excluded explicitly
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
    }

    #[test]
    fn old_project_rules_still_load() {
        // rules saved before `subdomains` was optional, and without it
        let r: ScopeRule = serde_json::from_str(r#"{"enabled":true,"prefix":"https://a.test/","subdomains":true}"#).unwrap();
        assert!(r.subdomains);
        let r: ScopeRule = serde_json::from_str(r#"{"enabled":true,"prefix":"a.test"}"#).unwrap();
        assert!(!r.subdomains);
    }
}
