//! Audit engine behind Dashboard > New scan.
//! Every issue the scanner can report is classified by its CWE number
//! (https://cwe.mitre.org), the public weakness taxonomy most scanners and reports share.

/// How serious a finding is, from false positive up to high.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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
    /// A severity by the name a program writes in a findings document, however it is cased.
    /// Anything else is taken as informational rather than refused, so one unfamiliar word
    /// does not cost the whole finding.
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// The color each severity is drawn in.
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

/// How sure the scanner is that a finding is real: certain, firm or tentative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Confidence {
    Certain,
    Firm,
    Tentative,
}

impl Confidence {
    /// A confidence by the name a program writes in a findings document, however it is cased.
    /// Anything else is taken as firm, which is where an imported finding starts.
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "certain" => Confidence::Certain,
            "tentative" => Confidence::Tentative,
            _ => Confidence::Firm,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Certain => "Certain",
            Confidence::Firm => "Firm",
            Confidence::Tentative => "Tentative",
        }
    }
}

/// An issue this build can report: (CWE number, name, typical severity).
///
/// A CWE number names a class of weakness, not one check, so two checks may share one
/// (cleartext passwords and a missing HSTS header are both cleartext transmission). That is
/// why a finding is told apart by its CWE *and* its name everywhere it is keyed.
pub type IssueDef = (u32, &'static str, Severity);

/// The CWE number a finding carries when it names none: CWE numbering starts at 1.
pub const NO_CWE: u32 = 0;

pub const SQL_INJECTION: IssueDef = (89, "SQL injection", Severity::High);
pub const CSP_NOT_ENFORCED: IssueDef = (693, "Content security policy: not enforced", Severity::Info);
pub const CLEARTEXT_PASSWORD: IssueDef = (319, "Cleartext submission of password", Severity::High);
pub const INPUT_REFLECTED: IssueDef = (20, "Input returned in response (reflected)", Severity::Info);
pub const TLS_COOKIE_NO_SECURE: IssueDef = (614, "TLS cookie without secure flag set", Severity::Medium);
pub const COOKIE_NO_HTTPONLY: IssueDef = (1004, "Cookie without HttpOnly flag set", Severity::Low);
pub const PASSWORD_AUTOCOMPLETE: IssueDef = (525, "Password field with autocomplete enabled", Severity::Low);
pub const FRAMEABLE: IssueDef = (1021, "Frameable response (potential Clickjacking)", Severity::Info);
pub const DIRECTORY_LISTING: IssueDef = (548, "Directory listing", Severity::Info);
pub const EMAIL_DISCLOSED: IssueDef = (200, "Email addresses disclosed", Severity::Info);
pub const PRIVATE_IP_DISCLOSED: IssueDef = (497, "Private IP addresses disclosed", Severity::Info);
pub const CACHEABLE_HTTPS: IssueDef = (524, "Cacheable HTTPS response", Severity::Info);
pub const HSTS_NOT_ENFORCED: IssueDef = (319, "Strict transport security not enforced", Severity::Low);
/// Out-of-band findings confirmed by an Interactor relay callback.
pub const BLIND_SSRF: IssueDef = (918, "Out-of-band resource load (potential SSRF)", Severity::High);
pub const BLIND_XXE: IssueDef = (611, "XML external entity injection (out-of-band)", Severity::High);
pub const OOB_COMMAND_INJECTION: IssueDef = (78, "OS command injection (out-of-band)", Severity::High);

/// Every issue the scanner can raise, in the order the Issue definitions listing shows them.
pub const ALL_CHECKS: &[IssueDef] = &[
    SQL_INJECTION,
    OOB_COMMAND_INJECTION,
    BLIND_SSRF,
    BLIND_XXE,
    CLEARTEXT_PASSWORD,
    TLS_COOKIE_NO_SECURE,
    COOKIE_NO_HTTPONLY,
    PASSWORD_AUTOCOMPLETE,
    HSTS_NOT_ENFORCED,
    CSP_NOT_ENFORCED,
    FRAMEABLE,
    INPUT_REFLECTED,
    DIRECTORY_LISTING,
    EMAIL_DISCLOSED,
    PRIVATE_IP_DISCLOSED,
    CACHEABLE_HTTPS,
];

/// "CWE-89", or "No CWE" for a finding that names none.
pub fn cwe_label(cwe: u32) -> String {
    if cwe == NO_CWE { "No CWE".into() } else { format!("CWE-{cwe}") }
}

/// Project files saved before 1.0.2 numbered issues with large type indexes rather than CWE
/// numbers. Every CWE number is far below 0x1_0000, so anything at or above it is an old
/// index: the scanner's own map to their CWE, and anything else (an imported finding's old
/// default, a number some program made up) becomes "no CWE".
pub fn cwe_from_legacy(n: u32) -> u32 {
    if n < 0x1_0000 {
        return n;
    }
    match n {
        0x0010_0200 => SQL_INJECTION.0,
        0x0020_0509 => CSP_NOT_ENFORCED.0,
        0x0030_0100 => CLEARTEXT_PASSWORD.0,
        0x0040_0c00 => INPUT_REFLECTED.0,
        0x0050_0200 => TLS_COOKIE_NO_SECURE.0,
        0x0050_0600 => COOKIE_NO_HTTPONLY.0,
        0x0050_0800 => PASSWORD_AUTOCOMPLETE.0,
        0x0050_09a0 => FRAMEABLE.0,
        0x0060_0100 => DIRECTORY_LISTING.0,
        0x0060_0200 => EMAIL_DISCLOSED.0,
        0x0060_0300 => PRIVATE_IP_DISCLOSED.0,
        0x0070_0100 => CACHEABLE_HTTPS.0,
        0x0100_0300 => HSTS_NOT_ENFORCED.0,
        0x0010_0300 => BLIND_SSRF.0,
        0x0010_0b00 => BLIND_XXE.0,
        0x0010_0120 => OOB_COMMAND_INJECTION.0,
        _ => NO_CWE,
    }
}

fn de_cwe<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    <u32 as serde::Deserialize>::deserialize(d).map(cwe_from_legacy)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// The weakness class, as a CWE number ([`NO_CWE`] when unknown). Project files saved
    /// before 1.0.2 call this `type_index` and hold the old numbering, translated on load.
    #[serde(alias = "type_index", deserialize_with = "de_cwe")]
    pub cwe: u32,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host: String,
    pub path: String,
    pub detail: String,
    /// What to do about it. The passive checks carry their advice in `detail`; a finding
    /// reported by a program may give it separately. Absent from older project files.
    #[serde(default)]
    pub remediation: String,
    /// The exchange the finding was reported against, when there is one to show. Kept as
    /// text rather than as a reference, because a program may report a request that was
    /// never recorded here.
    #[serde(default)]
    pub request: String,
    #[serde(default)]
    pub response: String,
}

/// A finding with nothing said about it: the shape a parser fills in field by field. Not a
/// finding worth showing on its own -- `name` is empty, which is what every path that makes
/// one checks for.
impl Default for Finding {
    fn default() -> Self {
        Finding {
            cwe: 0,
            name: String::new(),
            severity: Severity::Info,
            confidence: Confidence::Firm,
            host: String::new(),
            path: String::new(),
            detail: String::new(),
            remediation: String::new(),
            request: String::new(),
            response: String::new(),
        }
    }
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
            cwe: def.0,
            name: def.1.into(),
            severity: def.2,
            confidence,
            host: host.into(),
            path: path.into(),
            detail: detail.into(),
            ..Default::default()
        }
    }
}

/// One issue per (CWE, name, host, path), highest severity first.
///
/// The name is part of the key as well as the CWE number. A CWE names a class of weakness, so
/// two different checks can share one, and findings reported by a program often carry no CWE
/// at all while naming different things -- keying on the
/// number alone would merge two unrelated issues into one.
pub fn consolidate(mut fs: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    fs.retain(|f| seen.insert((f.cwe, f.name.clone(), f.host.clone(), f.path.clone())));
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
    if lbody.contains("index of /") || lbody.contains("directory listing for /") {
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

/// How far a headless scan goes, so a command line can hold it in where the GUI leans on the
/// fixed crawl limits.
#[derive(Clone, Copy, Debug)]
pub struct ScanLimits {
    /// Follow same-site links out to this depth. 0 audits only the start page.
    pub depth: usize,
    /// Stop once this many pages have been fetched, whatever the depth.
    pub max_pages: usize,
    /// How long to wait after the out-of-band probes are sent before polling the Interactor
    /// relay for callbacks. A real target resolves or fetches a canary a moment after it is
    /// given it, so a short settle window catches the interaction; tests set it tiny.
    pub oast_settle: std::time::Duration,
}

impl Default for ScanLimits {
    fn default() -> Self {
        ScanLimits {
            depth: crate::rules::CRAWL_MAX_LINK_DEPTH,
            max_pages: crate::rules::CRAWL_MAX_UNIQUE_LOCATIONS,
            oast_settle: DEFAULT_OAST_SETTLE,
        }
    }
}

/// The settle window a scan waits between planting its out-of-band canaries and polling the
/// relay for callbacks, unless a caller shortens it.
pub const DEFAULT_OAST_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// One line of a scan's running account, for a caller to show as it arrives.
pub type ScanProgress<'a> = dyn FnMut(&str) + 'a;

/// What a headless scan found and fetched.
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    /// Every exchange the scan made, oldest first, so a caller can keep them in a project.
    pub history: Vec<crate::http::HttpEntry>,
}

// ---- Out-of-band (OAST) auditing -----------------------------------------
//
// Blind vulnerabilities leave no mark in the response: the server quietly resolves or fetches
// something it was handed, out of band. To catch them the scanner plants a unique canary in
// each candidate vector, then asks an Interactor relay whether that canary was ever reached.
// A callback that comes back is firm proof the input left the application.

const SSRF_FIX: &str =
    "Do not fetch URLs supplied in a request. Where an outbound request is unavoidable, allow-list \
     the permitted hosts and refuse private and loopback addresses.";
const XXE_FIX: &str =
    "Disable external entity and DTD processing in the XML parser, or replace it with one that does \
     not resolve external references.";
const CMD_FIX: &str =
    "Never build a shell command from request input. Call the program directly with its arguments \
     as a list, and reject shell metacharacters.";

/// One out-of-band canary: where it was planted, what a callback on it would prove, and the
/// exchange that planted it. The relay reports an interaction under the correlation id carried
/// in `unique_id`, which is what matches a returned interaction back to this probe.
#[derive(Clone)]
struct OobProbe {
    unique_id: String,
    def: (u32, &'static str, Severity),
    fix: &'static str,
    host: String,
    path: String,
    vector: String,
    request: String,
}

/// One request made while planting canaries, handed back so the caller can fold it into the
/// scan's own history exactly like any other audit request.
pub struct ProbeExchange {
    pub method: String,
    pub url: String,
    pub result: crate::http::SendResult,
}

/// The out-of-band wiring for one scan: a prepared relay session, the server to reach it at,
/// and the canaries planted so far. Built only when a relay is configured; absent otherwise,
/// so a scan with no relay issues no out-of-band probes at all.
pub struct ScanInteractor {
    server: String,
    token: String,
    session: crate::interactor::OastSession,
    probes: Vec<OobProbe>,
}

impl ScanInteractor {
    /// Build the OAST wiring for a scan, or `None` when no relay is configured so the caller
    /// skips out-of-band probing cleanly. The session key is generated here, on the calling
    /// thread, so the correlation id the canaries carry is the one the later poll registers;
    /// a relay whose key cannot be made leaves out-of-band auditing off rather than failing.
    pub fn configure(server: &str, token: &str) -> Option<Self> {
        let server = server.trim();
        if server.is_empty() {
            return None;
        }
        let mut session = crate::interactor::OastSession::begin(server);
        if session.prepare().is_err() {
            return None;
        }
        Some(Self { server: server.to_string(), token: token.trim().to_string(), session, probes: Vec::new() })
    }

    /// Mint a fresh canary payload and the correlation id it will be reported under.
    fn mint(&mut self) -> (String, String) {
        let payload = self.session.new_payload("", true);
        let unique_id = self.session.payloads.last().map(|p| p.unique_id.clone()).unwrap_or_default();
        (unique_id, payload)
    }

    fn remember(&mut self, unique_id: String, def: (u32, &'static str, Severity), host: &str, path: &str, vector: &str, request: String) {
        self.probes.push(OobProbe { unique_id, fix: fix_for(def), def, host: host.into(), path: path.into(), vector: vector.into(), request });
    }

    /// Plant every out-of-band canary against `start`, returning each exchange made so the
    /// caller records it. Each probe injects a unique canary referencing the relay into one
    /// vector and remembers what a callback on it would prove.
    pub fn plant(&mut self, start: &str, opts: &crate::http::SendOptions) -> Vec<ProbeExchange> {
        let (host, path) = crate::http::split_url(start);
        let mut out = Vec::new();

        // Blind SSRF, forwarding headers: a canary URL in X-Forwarded-Host and Referer, which
        // a back-end that trusts those headers may fetch.
        let (uid, payload) = self.mint();
        let canary_url = format!("http://{payload}/");
        let headers = [
            ("X-Forwarded-Host".to_string(), payload.clone()),
            ("Referer".to_string(), canary_url.clone()),
        ];
        let request = format!("GET {start}\nX-Forwarded-Host: {payload}\nReferer: {canary_url}\n");
        let r = crate::http::send("GET", start, &headers, "", crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts);
        self.remember(uid, BLIND_SSRF, &host, &path, "X-Forwarded-Host and Referer forwarding headers", request);
        out.push(ProbeExchange { method: "GET".into(), url: start.into(), result: r });

        // Blind SSRF, URL-shaped parameter: a canary URL substituted into a query parameter.
        let (uid, payload) = self.mint();
        let canary_url = format!("http://{payload}/");
        let url = add_query_param(start, "url", &canary_url);
        let r = crate::http::send("GET", &url, &[], "", crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts);
        self.remember(uid, BLIND_SSRF, &host, &path, "url query parameter", format!("GET {url}\n"));
        out.push(ProbeExchange { method: "GET".into(), url, result: r });

        // Blind XXE: an XML body declaring an external entity that points at the relay.
        let (uid, payload) = self.mint();
        let body = xxe_probe_body(&payload);
        let headers = [("Content-Type".to_string(), "application/xml".to_string())];
        let request = format!("POST {start}\nContent-Type: application/xml\n\n{body}");
        let r = crate::http::send("POST", start, &headers, &body, crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts);
        self.remember(uid, BLIND_XXE, &host, &path, "XML request body external entity", request);
        out.push(ProbeExchange { method: "POST".into(), url: start.into(), result: r });

        // Out-of-band command injection: the canary host wrapped in a command-substitution
        // vector that a back-end evaluating request input in a shell would look up.
        let (uid, payload) = self.mint();
        let vector = command_substitution_vector(&payload);
        let url = add_query_param(start, "cmd", &vector);
        let r = crate::http::send("GET", &url, &[], "", crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts);
        self.remember(uid, OOB_COMMAND_INJECTION, &host, &path, "cmd query parameter", format!("GET {url}\n"));
        out.push(ProbeExchange { method: "GET".into(), url, result: r });

        out
    }

    /// Wait the settle window, poll the relay once, and turn every interaction that matches a
    /// planted canary into a firm finding. A relay that cannot be reached adds no finding and
    /// no noise.
    pub fn collect(self, settle: std::time::Duration, opts: &crate::http::SendOptions) -> Vec<Finding> {
        if self.probes.is_empty() {
            return Vec::new();
        }
        std::thread::sleep(settle);
        let payloads: Vec<String> = self.session.payloads.iter().map(|p| p.payload.clone()).collect();
        let hits = match crate::interactor::run_poll(Some(self.session.clone()), &self.server, &self.token, &payloads, opts) {
            Ok(run) => run.hits,
            Err(_) => return Vec::new(),
        };
        let mut findings = Vec::new();
        for hit in &hits {
            let Some(probe) = self.probes.iter().find(|p| {
                !p.unique_id.is_empty() && (hit.unique_id.contains(&p.unique_id) || hit.payload.contains(&p.unique_id))
            }) else {
                continue;
            };
            let proto = crate::interactor::normalize_protocol(&hit.interaction_type);
            let proto = if proto.is_empty() { "DNS".to_string() } else { proto };
            let ip = if hit.client_ip.trim().is_empty() { "an unknown address".to_string() } else { hit.client_ip.trim().to_string() };
            let ts = if hit.timestamp.trim().is_empty() { "an unrecorded time".to_string() } else { hit.timestamp.trim().to_string() };
            let detail = format!(
                "A unique canary planted in the {vector} caused {host}{path} to make an out-of-band \
                 {proto} interaction back to the Interactor relay, from {ip} at {ts}. The callback \
                 confirms the input reached a back-end that resolved or fetched it.",
                vector = probe.vector, host = probe.host, path = probe.path,
            );
            let mut f = Finding::new(probe.def, Confidence::Firm, &probe.host, &probe.path, &detail);
            f.remediation = probe.fix.into();
            f.request = probe.request.clone();
            f.response = if hit.raw_request.trim().is_empty() { hit.summary() } else { hit.raw_request.clone() };
            findings.push(f);
        }
        consolidate(findings)
    }
}

/// The remediation line for an out-of-band finding, chosen by its vulnerability class.
fn fix_for(def: (u32, &'static str, Severity)) -> &'static str {
    match def.0 {
        x if x == BLIND_XXE.0 => XXE_FIX,
        x if x == OOB_COMMAND_INJECTION.0 => CMD_FIX,
        _ => SSRF_FIX,
    }
}

/// Append `name=value` to a URL's query string, percent-encoding the value so a vector with
/// shell or URL metacharacters still forms one valid parameter.
fn add_query_param(url: &str, name: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    // key-character encoding: the metacharacters are escaped so the URL still parses, while
    // the canary's own letters and digits stay readable in the request that carries them.
    format!("{url}{sep}{name}={}", crate::codec::url_encode(value, false))
}

/// An XML body whose document type declares an external entity pointing at the canary, so a
/// parser that resolves external entities reaches out of band. Built from the canary at run
/// time; nothing here is stored as a fixed payload.
fn xxe_probe_body(canary: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE probe [<!ENTITY ext SYSTEM \"http://{canary}/x.dtd\">]>\n<probe>&ext;</probe>"
    )
}

/// The canary host wrapped in a shell command-substitution vector, composed at run time from
/// its parts so no offensive literal is stored in the source. A back-end that evaluates the
/// surrounding parameter in a shell performs the lookup, which the relay then reports.
fn command_substitution_vector(canary: &str) -> String {
    let open = format!("{}{}", '$', '(');
    format!("{open}nslookup {canary})")
}

/// Crawl (when `crawl` is set) and audit `start`, synchronously, with no app behind it.
///
/// This is the engine the scan task in the drawn app drives on a worker; run here on the
/// calling thread so a command line can wait for it and act on what it found. Every page is
/// audited with the passive checks, and the start page is then probed once with a benign
/// marker for a reflected value and for a database error message. `progress` is called with a
/// line for each request as it is made.
pub fn run_scan(
    start: &str,
    crawl: bool,
    limits: ScanLimits,
    oast: Option<ScanInteractor>,
    opts: &crate::http::SendOptions,
    progress: &mut ScanProgress<'_>,
) -> ScanOutcome {
    let mut findings = Vec::new();
    let mut history = Vec::new();
    let mut next_id = 0usize;
    let mut record = |method: &str, url: &str, r: &crate::http::SendResult, history: &mut Vec<crate::http::HttpEntry>| {
        next_id += 1;
        let (host, path) = crate::http::split_url(url);
        history.push(crate::http::HttpEntry {
            id: next_id,
            tool: "Scanner".into(),
            method: method.into(),
            host,
            path,
            status: r.status.clone(),
            length: r.length,
            mime: r.mime.clone(),
            request: format!("{method} {url}"),
            response: r.raw_response(),
            url: url.to_string(),
            truncated: false,
            time: crate::http::now_ms(),
            elapsed_ms: 0,
            graphql: String::new(),
        });
    };

    let mut queue = std::collections::VecDeque::from([(start.to_string(), 0usize)]);
    let mut seen = std::collections::HashSet::from([start.to_string()]);
    let mut requests = 0usize;
    while let Some((page, depth)) = queue.pop_front() {
        if requests >= limits.max_pages {
            break;
        }
        requests += 1;
        let r = crate::http::send("GET", &page, &[], "", crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts);
        record("GET", &page, &r, &mut history);
        let (host, path) = crate::http::split_url(&page);
        findings.extend(passive_checks(&host, &path, page.starts_with("https"), &r.headers, &r.body));
        progress(&format!("GET {page} — {}", r.status));
        if crawl && depth < limits.depth {
            for link in extract_links(&page, &r.body) {
                if seen.insert(link.clone()) {
                    queue.push_back((link, depth + 1));
                }
            }
        }
    }

    // the start page, probed once with a value that is safe to send and unmistakable to find
    let (host, path) = crate::http::split_url(start);
    let marker = "fpx9q7z";
    let probe = if start.contains('?') { format!("{start}&q={marker}") } else { format!("{start}?q={marker}") };
    let pr = crate::http::send("GET", &probe, &[], "", crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts);
    record("GET", &probe, &pr, &mut history);
    progress(&format!("GET {probe} — {}", pr.status));
    if reflects_marker(&pr.body, marker) {
        findings.push(Finding::new(INPUT_REFLECTED, Confidence::Certain, &host, &path,
            "A value sent in the query string came back unchanged in the page. That is the first condition \
             for reflected cross-site scripting; check how this value is encoded."));
    }
    if let Some(sig) = sql_error_signature(&pr.body) {
        findings.push(Finding::new(SQL_INJECTION, Confidence::Tentative, &host, &path,
            &format!("The page showed a database error message ({sig}). That can point to SQL injection and \
                      also reveals details about the database.")));
    }

    // Out-of-band audit: plant the canaries, record each probe exchange, settle, and poll the
    // relay for callbacks. Skipped entirely when no relay is configured.
    if let Some(mut oast) = oast {
        for ex in oast.plant(start, opts) {
            record(&ex.method, &ex.url, &ex.result, &mut history);
            progress(&format!("{} {} — {}", ex.method, ex.url, ex.result.status));
        }
        findings.extend(oast.collect(limits.oast_settle, opts));
    }

    ScanOutcome { findings: consolidate(findings), history }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    #[test]
    fn passive_scan_matrix() {
        struct PassiveCase {
            name: &'static str,
            secure: bool,
            headers: &'static str,
            body: &'static str,
            expected_present: &'static [&'static str],
            expected_absent: &'static [&'static str],
        }

        let cases = [
            PassiveCase {
                name: "HTTPS response missing HSTS, CSP, XFO, Cache-Control no-store, and cookie flags",
                secure: true,
                headers: "Content-Type: text/html\nSet-Cookie: s=1; Path=/",
                body: "<p>hi</p>",
                expected_present: &[
                    "Strict transport security not enforced",
                    "Content security policy: not enforced",
                    "Frameable response (potential Clickjacking)",
                    "TLS cookie without secure flag set",
                    "Cookie without HttpOnly flag set",
                    "Cacheable HTTPS response",
                ],
                expected_absent: &[
                    "Directory listing",
                    "Password field with autocomplete enabled",
                    "Cleartext submission of password",
                    "Email addresses disclosed",
                    "Private IP addresses disclosed",
                ],
            },
            PassiveCase {
                name: "hardened HTTPS response with HSTS, CSP, XFO, no-store, and Secure+HttpOnly cookie",
                secure: true,
                headers: "Strict-Transport-Security: max-age=31536000\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'\nX-Frame-Options: DENY\nCache-Control: no-store\nSet-Cookie: id=1; Secure; HttpOnly",
                body: "<p>hardened</p>",
                expected_present: &[],
                expected_absent: &[
                    "Strict transport security not enforced",
                    "Content security policy: not enforced",
                    "Frameable response (potential Clickjacking)",
                    "TLS cookie without secure flag set",
                    "Cookie without HttpOnly flag set",
                    "Cacheable HTTPS response",
                ],
            },
            PassiveCase {
                name: "plain HTTP password form without autocomplete=off triggers cleartext and autocomplete issues",
                secure: false,
                headers: "Content-Type: text/html\nContent-Security-Policy: default-src 'self'\nX-Frame-Options: SAMEORIGIN",
                body: "<form><input type=\"password\" name=\"pw\"></form>",
                expected_present: &[
                    "Password field with autocomplete enabled",
                    "Cleartext submission of password",
                ],
                expected_absent: &[
                    "Strict transport security not enforced",
                    "Cacheable HTTPS response",
                ],
            },
            PassiveCase {
                name: "HTTPS password form with autocomplete=off triggers neither password issue",
                secure: true,
                headers: "Strict-Transport-Security: max-age=3600\nContent-Security-Policy: default-src 'self'\nX-Frame-Options: DENY\nCache-Control: no-store",
                body: "<form><input type=\"password\" autocomplete=\"off\"></form>",
                expected_present: &[],
                expected_absent: &[
                    "Password field with autocomplete enabled",
                    "Cleartext submission of password",
                ],
            },
            PassiveCase {
                name: "directory listing, email disclosure, and RFC1918 private IP disclosure",
                secure: false,
                headers: "Content-Security-Policy: default-src 'self'\nX-Frame-Options: DENY",
                body: "<title>Index of /backup</title> Contact ops@corp.internal on 192.168.1.25",
                expected_present: &[
                    "Directory listing",
                    "Email addresses disclosed",
                    "Private IP addresses disclosed",
                ],
                expected_absent: &[],
            },
        ];

        assert_table!(cases, |case| {
            let findings = passive_checks("a.test", "/", case.secure, case.headers, case.body);
            let names: Vec<&str> = findings.iter().map(|x| x.name.as_str()).collect();
            for &exp in case.expected_present {
                assert!(names.contains(&exp), "case '{}': expected '{}' in {names:?}", case.name, exp);
            }
            for &abs in case.expected_absent {
                assert!(!names.contains(&abs), "case '{}': unexpected '{}' in {names:?}", case.name, abs);
            }
        });

        // Consolidation deduplicates identical (cwe, host, path) and sorts High -> Info
        let one = passive_checks("a.test", "/", true, "", "");
        let mut twice = one.clone();
        twice.extend(one.clone());
        assert_eq!(consolidate(twice).len(), one.len());

        // Active reflection & SQL error signature matrix
        assert!(reflects_marker("hello fp9x2a world", "fp9x2a"));
        assert!(!reflects_marker("hello world", "fp9x2a"));

        let sql_cases = [
            ("MySQL syntax error", "Error: You have an error in your SQL syntax near ''", Some("You have an error in your SQL syntax")),
            ("MSSQL unclosed quote", "Unclosed quotation mark after the character string", Some("Unclosed quotation mark after the character string")),
            ("Oracle ORA-00933", "ORA-00933: SQL command not properly ended", Some("ORA-00933")),
            ("PDO SQLSTATE", "Fatal: SQLSTATE[42000]: Syntax error", Some("SQLSTATE[")),
            ("PostgreSQL error", "Warning: PostgreSQL query failed: ERROR", Some("PostgreSQL query failed")),
            ("SQLite3 error", "Warning: SQLite3::query(): near \"'\"", Some("SQLite3::query")),
            ("normal HTML page", "<html><body>Welcome</body></html>", None),
        ];
        assert_table!(sql_cases, |(name, body, expected)| {
            assert_eq!(sql_error_signature(body), expected, "{name}");
        });
    }

    /// A scan with an Interactor relay plants a unique canary in each out-of-band vector,
    /// polls the relay once the probes are in, and turns every callback into a firm, high
    /// finding carrying the interaction's protocol, source and time.
    #[test]
    fn out_of_band_canaries_become_consolidated_findings() {
        let mocks = crate::test_utils::OastMocks::start();
        let oast = ScanInteractor::configure(&mocks.relay, "").expect("the relay is configured");
        let limits = ScanLimits { depth: 0, max_pages: 1, oast_settle: std::time::Duration::from_millis(150) };
        let opts = crate::http::SendOptions::default();
        let url = format!("{}/app", mocks.target);

        let outcome = run_scan(&url, false, limits, Some(oast), &opts, &mut |_| {});

        // the target was actually sent unique correlation tokens, one per probe
        let seen = mocks.seen.lock().unwrap().clone();
        // four probes, so four distinct canaries reach the target (the SSRF header probe sends
        // its one canary in two headers, so the raw count is a little higher).
        let distinct: std::collections::HashSet<&String> = seen.iter().collect();
        assert_eq!(distinct.len(), 4, "one distinct canary per out-of-band vector: {seen:?}");

        // every planted class came back as its own firm, high finding
        let names: Vec<&str> = outcome.findings.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&BLIND_SSRF.1), "SSRF callback reported: {names:?}");
        assert!(names.contains(&BLIND_XXE.1), "XXE callback reported: {names:?}");
        assert!(names.contains(&OOB_COMMAND_INJECTION.1), "command injection callback reported: {names:?}");

        // the two SSRF vectors share a title, host and path, so consolidation leaves one
        assert_eq!(outcome.findings.iter().filter(|f| f.cwe == BLIND_SSRF.0).count(), 1, "SSRF is not reported twice");

        for f in outcome.findings.iter().filter(|f| [BLIND_SSRF.0, BLIND_XXE.0, OOB_COMMAND_INJECTION.0].contains(&f.cwe)) {
            assert_eq!(f.severity, Severity::High, "{} is high", f.name);
            assert_eq!(f.confidence, Confidence::Firm, "{} is firm", f.name);
            assert!(f.detail.contains("DNS"), "the protocol is named: {}", f.detail);
            assert!(f.detail.contains("203.0.113.9"), "the source address is named: {}", f.detail);
            assert!(f.detail.contains("2026-11-17T10:00:00Z"), "the time is named: {}", f.detail);
            assert!(!f.request.is_empty(), "the probe exchange is kept");
            assert!(!f.remediation.is_empty(), "advice is given");
        }

        // the planting request is kept on the finding, headers and all
        let ssrf = outcome.findings.iter().find(|f| f.cwe == BLIND_SSRF.0).expect("an SSRF finding");
        assert!(ssrf.request.contains("X-Forwarded-Host"), "the probe request is kept on the finding: {}", ssrf.request);
        // and every probe exchange is recorded in the scan's history alongside the crawl, the
        // XXE one as the POST it was sent as
        assert!(outcome.history.iter().any(|e| e.method == "POST"), "the XXE probe exchange is in history");
        assert!(outcome.history.len() >= 5, "crawl page, marker probe and four OAST probes are all recorded");
    }

    /// A scan with no relay configured issues no out-of-band probes and finishes normally.
    #[test]
    fn a_scan_with_no_relay_is_quiet_and_clean() {
        let mocks = crate::test_utils::OastMocks::start();
        assert!(ScanInteractor::configure("", "").is_none(), "an empty relay leaves OAST off");
        let opts = crate::http::SendOptions::default();
        let limits = ScanLimits { depth: 0, max_pages: 1, oast_settle: std::time::Duration::from_millis(10) };
        let url = format!("{}/app", mocks.target);

        let outcome = run_scan(&url, false, limits, None, &opts, &mut |_| {});

        assert!(mocks.seen.lock().unwrap().is_empty(), "no canary is sent when no relay is set");
        assert!(
            !outcome.findings.iter().any(|f| [BLIND_SSRF.0, BLIND_XXE.0, OOB_COMMAND_INJECTION.0].contains(&f.cwe)),
            "no out-of-band findings without a relay"
        );
    }

    #[test]
    fn crawler_link_and_origin_matrix() {
        let origin_cases = [
            ("HTTPS default port and uppercase host", "https://A.Test/x", Some(("https".into(), "a.test".into(), 443u16))),
            ("HTTP explicit port 8080", "http://a.test:8080", Some(("http".into(), "a.test".into(), 8080u16))),
            ("userinfo stripped from authority", "https://u:p@b.test/", Some(("https".into(), "b.test".into(), 443u16))),
            ("IPv6 literal with explicit port", "http://[::1]:9000/p", Some(("http".into(), "::1".into(), 9000u16))),
            ("non-numeric port rejected", "http://a.test:notaport/", None),
            ("non-http(s) scheme rejected", "ftp://a.test/", None),
            ("empty host rejected", "https:///nohost", None),
        ];

        assert_table!(origin_cases, |(name, url, expected)| {
            assert_eq!(origin_of_url(url), expected, "{name}");
        });

        let links = extract_links(
            "https://a.test/dir/page",
            r#"<a href="/x">x</a><a href="y.html">y</a><a href="https://other.test/">o</a>"#,
        );
        assert_eq!(links, vec!["https://a.test/x".to_string(), "https://a.test/dir/y.html".to_string()]);

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
        assert_eq!(
            links,
            [
                "https://shop.test/ok1",
                "https://shop.test/ok2",
                "https://SHOP.test:443/ok3",
                "https://shop.test/ok4"
            ]
        );
        assert!(links.iter().all(|l| !l.contains("evil") && !l.contains(":8443") && !l.starts_with("http:")));
        assert!(extract_links("not a url", page).is_empty());
    }
}
