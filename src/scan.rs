//! Audit engine behind Dashboard > New scan.
//! Issue names, type numbers and typical severities come from the original's shipped
//! catalogue (resources/KnowledgeBase/Issues/*, 380 types); severity/confidence levels from
//! Standard vulnerability audit issue taxonomy and scanner definitions.

/// AuditIssueSeverity: HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    FalsePositive,
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Information",
            Severity::FalsePositive => "False positive",
        }
    }
    /// Colors from LightTheme.json ui.issue.* (see MECHANICS.md).
    pub fn rgb(&self) -> (u8, u8, u8) {
        match self {
            Severity::High => (0xD6, 0x21, 0x3F),   // @red[0]
            Severity::Medium => (0xFF, 0x66, 0x33), // @orange[0]
            Severity::Low => (0x26, 0x64, 0x9D),    // @blue[0]
            Severity::Info => (0x81, 0x81, 0x81),   // $mono[6]
            Severity::FalsePositive => (0xB0, 0xAF, 0xAF),
        }
    }
}

/// AuditIssueConfidence: CERTAIN, FIRM, TENTATIVE.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Confidence {
    Certain,
    Firm,
    Tentative,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Certain => "Certain",
            Confidence::Firm => "Firm",
            Confidence::Tentative => "Tentative",
        }
    }
}

/// Catalogue entries this build can report: (type index, name, typical severity).
pub const SQL_INJECTION: (u32, &str, Severity) = (0x0010_0200, "SQL injection", Severity::High);
pub const CSP_NOT_ENFORCED: (u32, &str, Severity) =
    (0x0020_0509, "Content security policy: not enforced", Severity::Info);
pub const CLEARTEXT_PASSWORD: (u32, &str, Severity) =
    (0x0030_0100, "Cleartext submission of password", Severity::High);
pub const INPUT_REFLECTED: (u32, &str, Severity) =
    (0x0040_0c00, "Input returned in response (reflected)", Severity::Info);
pub const TLS_COOKIE_NO_SECURE: (u32, &str, Severity) =
    (0x0050_0200, "TLS cookie without secure flag set", Severity::Medium);
pub const COOKIE_NO_HTTPONLY: (u32, &str, Severity) =
    (0x0050_0600, "Cookie without HttpOnly flag set", Severity::Low);
pub const PASSWORD_AUTOCOMPLETE: (u32, &str, Severity) =
    (0x0050_0800, "Password field with autocomplete enabled", Severity::Low);
pub const FRAMEABLE: (u32, &str, Severity) =
    (0x0050_09a0, "Frameable response (potential Clickjacking)", Severity::Info);
pub const DIRECTORY_LISTING: (u32, &str, Severity) = (0x0060_0100, "Directory listing", Severity::Info);
pub const EMAIL_DISCLOSED: (u32, &str, Severity) =
    (0x0060_0200, "Email addresses disclosed", Severity::Info);
pub const PRIVATE_IP_DISCLOSED: (u32, &str, Severity) =
    (0x0060_0300, "Private IP addresses disclosed", Severity::Info);
pub const CACHEABLE_HTTPS: (u32, &str, Severity) = (0x0070_0100, "Cacheable HTTPS response", Severity::Info);
pub const HSTS_NOT_ENFORCED: (u32, &str, Severity) =
    (0x0100_0300, "Strict transport security not enforced", Severity::Low);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub type_index: u32,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host: String,
    pub path: String,
    pub detail: String,
}

impl Finding {
    pub fn new(
        def: (u32, &str, Severity),
        confidence: Confidence,
        host: &str,
        path: &str,
        detail: &str,
    ) -> Self {
        Finding {
            type_index: def.0,
            name: def.1.into(),
            severity: def.2,
            confidence,
            host: host.into(),
            path: path.into(),
            detail: detail.into(),
        }
    }
}

/// consolidate_passive_issues = true: one issue per (type, host, path).
pub fn consolidate(mut fs: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    fs.retain(|f| seen.insert((f.type_index, f.host.clone(), f.path.clone())));
    fs.sort_by(|a, b| b.severity.cmp(&a.severity));
    fs
}

fn header_present(headers: &str, name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    headers.lines().any(|l| l.to_ascii_lowercase().trim_start().starts_with(&lname))
}

fn header_lines<'a>(headers: &'a str, name: &str) -> Vec<&'a str> {
    let lname = name.to_ascii_lowercase();
    headers
        .lines()
        .filter(|l| l.to_ascii_lowercase().trim_start().starts_with(&lname))
        .collect()
}

/// Passive audit of one request/response pair. `secure` = request was over HTTPS.
pub fn passive_checks(host: &str, path: &str, secure: bool, headers: &str, body: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |def, conf, detail: &str| out.push(Finding::new(def, conf, host, path, detail));
    let lbody = body.to_ascii_lowercase();

    if secure && !header_present(headers, "strict-transport-security") {
        push(HSTS_NOT_ENFORCED, Confidence::Certain,
            "The HTTPS response did not set a Strict-Transport-Security header, so a browser may be \
             downgraded to plain HTTP by a network attacker.");
    }
    if !header_present(headers, "content-security-policy") {
        push(CSP_NOT_ENFORCED, Confidence::Certain,
            "No Content-Security-Policy header was present. A policy limits the damage of \
             cross-site scripting by restricting where scripts may load from.");
    }
    let framed = header_present(headers, "x-frame-options")
        || headers.to_ascii_lowercase().contains("frame-ancestors");
    if !framed {
        push(FRAMEABLE, Confidence::Firm,
            "The response can be shown inside a frame on another site, so it may be open to \
             clickjacking unless framing is restricted.");
    }
    for cookie in header_lines(headers, "set-cookie") {
        let low = cookie.to_ascii_lowercase();
        if secure && !low.contains("secure") {
            push(TLS_COOKIE_NO_SECURE, Confidence::Firm,
                "A cookie was set over HTTPS without the Secure flag, so it may also be sent over \
                 an unencrypted connection.");
        }
        if !low.contains("httponly") {
            push(COOKIE_NO_HTTPONLY, Confidence::Firm,
                "A cookie was set without the HttpOnly flag, so page scripts can read it, which \
                 makes it easier to steal through cross-site scripting.");
        }
    }
    if secure {
        let cc = header_lines(headers, "cache-control").join(" ").to_ascii_lowercase();
        if !cc.contains("no-store") {
            push(CACHEABLE_HTTPS, Confidence::Certain,
                "The HTTPS response may be kept by caches because Cache-Control: no-store was not \
                 set, so sensitive content could be left on disk.");
        }
    }
    if body.contains("Index of /") {
        push(DIRECTORY_LISTING, Confidence::Firm,
            "The response looks like an automatic directory listing, which can reveal files that \
             were not meant to be public.");
    }
    if lbody.contains("type=\"password\"") {
        if !lbody.contains("autocomplete=\"off\"") {
            push(PASSWORD_AUTOCOMPLETE, Confidence::Certain,
                "A password box did not turn off autocomplete, so the browser may store the value.");
        }
        if !secure {
            push(CLEARTEXT_PASSWORD, Confidence::Certain,
                "A page served over plain HTTP contains a password box, so the password would be \
                 sent unencrypted.");
        }
    }
    if contains_email(body) {
        push(EMAIL_DISCLOSED, Confidence::Firm,
            "The response contained one or more email addresses, which can help an attacker with \
             phishing or password guessing.");
    }
    if contains_private_ip(body) {
        push(PRIVATE_IP_DISCLOSED, Confidence::Firm,
            "The response mentioned a private (internal) IP address, which leaks network layout.");
    }
    out
}

/// Active signal: did a benign unique marker come back unchanged in the body?
pub fn reflects_marker(body: &str, marker: &str) -> bool {
    body.contains(marker)
}

/// Database error signatures; seeing one is a tentative SQL-injection signal.
pub fn sql_error_signature(body: &str) -> Option<&'static str> {
    const SIGS: [&str; 6] = [
        "You have an error in your SQL syntax",
        "Unclosed quotation mark after the character string",
        "ORA-00933",
        "SQLSTATE[",
        "PostgreSQL query failed",
        "SQLite3::query",
    ];
    SIGS.into_iter().find(|s| body.contains(s))
}

/// A URL's origin for comparison: (scheme, host, port). The host is lower-cased with any
/// `user:pass@` removed and the port filled in from the scheme; None for anything that isn't
/// an absolute http(s) URL with a host.
pub fn origin_of_url(url: &str) -> Option<(String, String, u16)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default = match scheme.as_str() { "http" => 80, "https" => 443, _ => return None };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, tail) = v6.split_once(']')?;
        let port = match tail.strip_prefix(':') { Some(p) => p.parse().ok()?, None if tail.is_empty() => default, None => return None };
        (h.to_ascii_lowercase(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), if p.is_empty() { default } else { p.parse().ok()? }),
            None => (hostport.to_ascii_lowercase(), default),
        }
    };
    let host = host.trim_end_matches('.').to_string();
    (!host.is_empty()).then_some((scheme, host, port))
}

/// Links (href / src) in a page, resolved against `base` and kept only when they have the
/// same scheme, host and port as `base` (compared parsed, not as text: a look-alike host or
/// a `user@` prefix doesn't count).
pub fn extract_links(base: &str, body: &str) -> Vec<String> {
    let Some(base_origin) = origin_of_url(base) else { return Vec::new() };
    let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
    let origin_end = base[scheme_end..].find('/').map(|i| i + scheme_end).unwrap_or(base.len());
    let origin = &base[..origin_end];
    let dir = match base.rfind('/') {
        Some(i) if i >= origin_end => &base[..=i],
        _ => "",
    };
    let mut out = Vec::new();
    for attr in ["href=\"", "src=\"", "href='", "src='"] {
        let quote = attr.chars().last().unwrap();
        let mut rest = body;
        while let Some(i) = rest.find(attr) {
            rest = &rest[i + attr.len()..];
            let Some(end) = rest.find(quote) else { break };
            let link = rest[..end].trim();
            rest = &rest[end..];
            let link = link.split('#').next().unwrap_or("");
            if link.is_empty() || link.starts_with("javascript:") || link.starts_with("mailto:") {
                continue;
            }
            let abs = if link.starts_with("http://") || link.starts_with("https://") {
                link.to_string()
            } else if let Some(stripped) = link.strip_prefix("//") {
                format!("{}{}", &base[..scheme_end], stripped)
            } else if link.starts_with('/') {
                format!("{origin}{link}")
            } else if !dir.is_empty() {
                format!("{dir}{link}")
            } else {
                format!("{origin}/{link}")
            };
            if origin_of_url(&abs).as_ref() == Some(&base_origin) && !out.contains(&abs) {
                out.push(abs);
            }
        }
    }
    out
}

fn contains_email(s: &str) -> bool {
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'@' && i > 0 && i + 3 < b.len() && b[i - 1].is_ascii_alphanumeric() {
            let after = &s[i + 1..];
            let domain = after.split(['/', ' ', '"', '<', ')', '\n', ',']).next().unwrap_or("");
            if domain.contains('.') && domain.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) {
                return true;
            }
        }
    }
    false
}

fn contains_private_ip(s: &str) -> bool {
    for tok in s.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            let a: u8 = parts[0].parse().unwrap();
            let b: u8 = parts[1].parse().unwrap();
            if a == 10 || (a == 192 && b == 168) || (a == 172 && (16..=31).contains(&b)) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_header_and_cookie_issues() {
        let f = passive_checks("a.test", "/", true, "Content-Type: text/html\nSet-Cookie: s=1; Path=/", "<p>hi</p>");
        let names: Vec<&str> = f.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"Strict transport security not enforced"));
        assert!(names.contains(&"TLS cookie without secure flag set"));
        assert!(names.contains(&"Cookie without HttpOnly flag set"));
    }
    #[test]
    fn crawl_links_stay_on_site() {
        let links = extract_links("https://a.test/dir/page", r#"<a href="/x">x</a><a href="y.html">y</a><a href="https://other.test/">o</a>"#);
        assert_eq!(links, vec!["https://a.test/x".to_string(), "https://a.test/dir/y.html".to_string()]);
    }
    #[test]
    fn crawler_stays_on_the_exact_origin() {
        let page = r#"
            <a href="/ok1">same, absolute path</a>
            <a href="https://shop.test/ok2">same origin</a>
            <a href="https://SHOP.test:443/ok3">same, other spelling</a>
            <a href="//shop.test/ok4">protocol-relative</a>
            <a href="https://shop.test.evil.example/x">look-alike host</a>
            <a href="https://shop.testing.example/x">longer name</a>
            <a href="https://shop.test@evil.example/x">user@ prefix</a>
            <a href="https://shop.test:8443/x">other port</a>
            <a href="http://shop.test/x">other scheme</a>
            <a href="https://api.shop.test/x">subdomain</a>"#;
        let links = extract_links("https://shop.test/start", page);
        assert_eq!(links, ["https://shop.test/ok1", "https://shop.test/ok2", "https://SHOP.test:443/ok3", "https://shop.test/ok4"]);
        assert!(links.iter().all(|l| !l.contains("evil") && !l.contains(":8443") && !l.starts_with("http:")));
        // a base that isn't an http(s) URL yields nothing rather than guessing
        assert!(extract_links("not a url", page).is_empty());
    }

    #[test]
    fn origins() {
        assert_eq!(origin_of_url("https://A.Test/x"), Some(("https".into(), "a.test".into(), 443)));
        assert_eq!(origin_of_url("http://a.test:8080"), Some(("http".into(), "a.test".into(), 8080)));
        assert_eq!(origin_of_url("https://u:p@b.test/"), Some(("https".into(), "b.test".into(), 443)));
        assert_eq!(origin_of_url("http://[::1]:9000/p"), Some(("http".into(), "::1".into(), 9000)));
        assert_eq!(origin_of_url("http://a.test:notaport/"), None);
        assert_eq!(origin_of_url("ftp://a.test/"), None);
        assert_eq!(origin_of_url("https:///nohost"), None);
    }

    #[test]
    fn duplicates_are_merged() {
        let one = passive_checks("a.test", "/", true, "", "");
        let mut twice = one.clone();
        twice.extend(one.clone());
        assert_eq!(consolidate(twice).len(), one.len());
    }
}
