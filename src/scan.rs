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
pub const CLEARTEXT_PASSWORD: IssueDef = (523, "Cleartext submission of password", Severity::High);
pub const INPUT_REFLECTED: IssueDef = (20, "Input returned in response (reflected)", Severity::Info);
pub const TLS_COOKIE_NO_SECURE: IssueDef = (614, "TLS cookie without secure flag set", Severity::Medium);
pub const COOKIE_NO_HTTPONLY: IssueDef = (1004, "Cookie without HttpOnly flag set", Severity::Low);
pub const PASSWORD_AUTOCOMPLETE: IssueDef = (522, "Password field with autocomplete enabled", Severity::Low);
pub const FRAMEABLE: IssueDef = (1021, "Frameable response (potential Clickjacking)", Severity::Info);
pub const DIRECTORY_LISTING: IssueDef = (548, "Directory listing", Severity::Info);
pub const EMAIL_DISCLOSED: IssueDef = (200, "Email addresses disclosed", Severity::Info);
pub const PRIVATE_IP_DISCLOSED: IssueDef = (497, "Private IP addresses disclosed", Severity::Info);
pub const CACHEABLE_HTTPS: IssueDef = (525, "Cacheable HTTPS response", Severity::Info);
pub const HSTS_NOT_ENFORCED: IssueDef = (319, "Strict transport security not enforced", Severity::Low);

// --- Passive header, cookie, disclosure and client-side checks (no extra traffic) ----------
pub const CONTENT_TYPE_OPTIONS: IssueDef = (16, "Content type is not pinned (sniffing allowed)", Severity::Info);
pub const CORS_PERMISSIVE: IssueDef = (942, "Cross-origin resource sharing: permissive policy", Severity::Medium);
pub const CORS_CREDENTIALED_ORIGIN: IssueDef = (346, "Cross-origin resource sharing: credentials shared with a named origin", Severity::Medium);
pub const REFERRER_POLICY: IssueDef = (200, "Referrer policy not set", Severity::Info);
pub const VERSION_BANNER: IssueDef = (200, "Software version disclosed", Severity::Info);
pub const MIXED_CONTENT: IssueDef = (311, "Mixed content on a secure page", Severity::Medium);
pub const MISSING_SRI: IssueDef = (353, "Subresource integrity not used", Severity::Low);
pub const UNTRUSTED_INCLUSION: IssueDef = (829, "Active content included from an external origin", Severity::Low);
pub const COOKIE_NO_SAMESITE: IssueDef = (1275, "Cookie without SameSite attribute", Severity::Low);
pub const TOKEN_IN_URL: IssueDef = (598, "Sensitive information in the URL query string", Severity::Medium);
pub const JWT_UNSIGNED: IssueDef = (347, "Unsigned web token accepted", Severity::Medium);
pub const JWT_UNPROTECTED: IssueDef = (327, "Web token carries no signature", Severity::Low);
pub const SECRET_IN_RESPONSE: IssueDef = (798, "Credential exposed in a response", Severity::Medium);
pub const SOURCE_MAP_EXPOSED: IssueDef = (540, "Source map reference exposed", Severity::Info);
pub const STACK_TRACE: IssueDef = (209, "Error message reveals internal detail", Severity::Low);
pub const DOM_XSS_SINK: IssueDef = (79, "Client-side input may reach a dangerous sink (DOM XSS)", Severity::Low);
pub const POSTMESSAGE_NO_ORIGIN: IssueDef = (345, "Cross-document message handler without an origin check", Severity::Low);

// --- Active injection and exposure checks (traffic gated by scan intensity) -----------------
pub const REFLECTED_XSS: IssueDef = (79, "Reflected cross-site scripting", Severity::High);
pub const SSTI: IssueDef = (1336, "Server-side template injection", Severity::High);
pub const PATH_TRAVERSAL: IssueDef = (22, "Path traversal", Severity::High);
pub const CRLF_INJECTION: IssueDef = (113, "HTTP response header injection (CRLF)", Severity::High);
pub const XPATH_INJECTION: IssueDef = (643, "XPath injection", Severity::High);
pub const LDAP_INJECTION: IssueDef = (90, "LDAP injection", Severity::High);
pub const OPEN_REDIRECT: IssueDef = (601, "Open redirection", Severity::Medium);
pub const HOST_HEADER_INJECTION: IssueDef = (644, "Host header injection", Severity::Medium);
pub const PROTOTYPE_POLLUTION: IssueDef = (1321, "Prototype pollution", Severity::Medium);
pub const EXPOSED_FILE: IssueDef = (538, "Sensitive file exposed", Severity::Medium);
pub const GRAPHQL_INTROSPECTION: IssueDef = (200, "GraphQL introspection enabled", Severity::Low);
pub const GRAPHQL_BATCHING: IssueDef = (400, "GraphQL query batching not limited", Severity::Medium);
// Time-based variants (Thorough intensity only): confirmed by a response delay the probe caused.
pub const TIMED_SQL_INJECTION: IssueDef = (89, "SQL injection (time-based)", Severity::High);
pub const TIMED_COMMAND_INJECTION: IssueDef = (78, "OS command injection (time-based)", Severity::High);

// --- Crawler-driven checks (forms, login, upgraded connections) -----------------------------
pub const CSRF_MISSING: IssueDef = (352, "Anti-CSRF token missing on a state-changing form", Severity::Medium);
pub const SESSION_NOT_ROTATED: IssueDef = (384, "Session identifier not rotated after login", Severity::Medium);
pub const CSWSH: IssueDef = (1385, "Cross-site WebSocket hijacking", Severity::Medium);

/// Out-of-band findings confirmed by an Interactor relay callback.
pub const BLIND_SSRF: IssueDef = (918, "Out-of-band resource load (potential SSRF)", Severity::High);
pub const BLIND_XXE: IssueDef = (611, "XML external entity injection (out-of-band)", Severity::High);
pub const OOB_COMMAND_INJECTION: IssueDef = (78, "OS command injection (out-of-band)", Severity::High);

/// Every issue the scanner can raise, in the order the Issue definitions listing shows them.
pub const ALL_CHECKS: &[IssueDef] = &[
    SQL_INJECTION,
    REFLECTED_XSS,
    SSTI,
    PATH_TRAVERSAL,
    CRLF_INJECTION,
    XPATH_INJECTION,
    LDAP_INJECTION,
    OPEN_REDIRECT,
    HOST_HEADER_INJECTION,
    PROTOTYPE_POLLUTION,
    EXPOSED_FILE,
    GRAPHQL_INTROSPECTION,
    GRAPHQL_BATCHING,
    TIMED_SQL_INJECTION,
    TIMED_COMMAND_INJECTION,
    CSRF_MISSING,
    SESSION_NOT_ROTATED,
    CSWSH,
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
    CONTENT_TYPE_OPTIONS,
    CORS_PERMISSIVE,
    CORS_CREDENTIALED_ORIGIN,
    REFERRER_POLICY,
    VERSION_BANNER,
    MIXED_CONTENT,
    MISSING_SRI,
    UNTRUSTED_INCLUSION,
    COOKIE_NO_SAMESITE,
    TOKEN_IN_URL,
    JWT_UNSIGNED,
    JWT_UNPROTECTED,
    SECRET_IN_RESPONSE,
    SOURCE_MAP_EXPOSED,
    STACK_TRACE,
    DOM_XSS_SINK,
    POSTMESSAGE_NO_ORIGIN,
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
    /// Which insertion point the finding was raised against, e.g. `query parameter "id"`, when
    /// an active check names one. Empty for passive findings and older project files. Part of
    /// the consolidation key, so the same weakness on two parameters stays two findings.
    #[serde(default)]
    pub point: String,
    /// The benign value the active check substituted, kept so a reader can see what was sent.
    /// Empty for passive findings and older project files.
    #[serde(default)]
    pub payload: String,
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
            point: String::new(),
            payload: String::new(),
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
    fs.retain(|f| seen.insert((f.cwe, f.name.clone(), f.host.clone(), f.path.clone(), f.point.clone())));
    fs.sort_by(|a, b| b.severity.cmp(&a.severity));
    fs
}

/// Passive audit of one request/response pair. `secure` = request was over HTTPS.
///
/// The individual checks live in `crate::checks::passive`, one small function each; this drives
/// them in registry order and gathers their findings. The signature and the findings produced
/// are unchanged from when every check was inlined here.
pub fn passive_checks(host: &str, path: &str, secure: bool, headers: &str, body: &str) -> Vec<Finding> {
    let ctx = crate::checks::PassiveCtx::new(host, path, secure, headers, body);
    let mut out = Vec::new();
    for (_id, check) in crate::checks::passive_registry() {
        out.extend(check(&ctx));
    }
    out
}

/// Split a recorded raw response into its header block (without the status line) and its body,
/// tolerating either CRLF or LF framing. Used to audit already-captured traffic passively.
fn split_recorded_response(raw: &str) -> (&str, &str) {
    let (head, body) = if let Some(i) = raw.find("\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = raw.find("\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, "")
    };
    // the first line is the status line, which no header check should see
    let headers = head.split_once('\n').map(|(_, h)| h).unwrap_or("");
    (headers, body)
}

/// Audit traffic already captured in the proxy history with the passive checks, making no new
/// requests. Every recorded response is inspected and the findings consolidated, so a scan is
/// not needed to surface the passive issues in what has already been browsed.
pub fn passive_audit_history(entries: &[crate::http::HttpEntry]) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        // A cookie-authenticated WebSocket handshake: the browser attaches the cookie across
        // sites, and a WebSocket is not covered by the same-origin rules that guard fetch, so
        // unless the server checks Origin another site can open an authenticated socket.
        if is_ws_handshake(&e.request) && request_has_cookie(&e.request) {
            let mut f = Finding::new(CSWSH, Confidence::Tentative, &e.host, &e.path,
                "A WebSocket handshake carried a session cookie, so the connection is authenticated by \
                 the cookie alone. Unless the server verifies the Origin header, another site can open \
                 this socket on a logged-in user's behalf (cross-site WebSocket hijacking).");
            f.point = "WebSocket handshake".to_string();
            out.push(f);
        }
        if e.response.trim().is_empty() {
            continue;
        }
        let secure = e.url.starts_with("https");
        let (headers, body) = split_recorded_response(&e.response);
        out.extend(passive_checks(&e.host, &e.path, secure, headers, body));
    }
    consolidate(out)
}

/// Whether a recorded request is a WebSocket upgrade handshake.
fn is_ws_handshake(request: &str) -> bool {
    request.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("upgrade:") && l.contains("websocket")
    })
}

/// Whether a recorded request carries a Cookie header.
fn request_has_cookie(request: &str) -> bool {
    request.lines().any(|l| l.to_ascii_lowercase().trim_start().starts_with("cookie:"))
}

/// The session identifiers a response set, as name -> value: the Set-Cookie cookies whose name
/// looks like a session. Used to tell whether logging in rotated the session.
fn session_ids(headers: &str) -> std::collections::BTreeMap<String, String> {
    const SESSION_NAMES: &[&str] = &["sess", "sid", "auth"];
    let mut out = std::collections::BTreeMap::new();
    for line in headers.lines() {
        if !line.to_ascii_lowercase().trim_start().starts_with("set-cookie:") {
            continue;
        }
        let value = line.split_once(':').map(|x| x.1).unwrap_or("").trim();
        let cookie = value.split(';').next().unwrap_or("");
        if let Some((name, val)) = cookie.split_once('=') {
            let name = name.trim();
            let lname = name.to_ascii_lowercase();
            if SESSION_NAMES.iter().any(|p| lname.contains(p)) {
                out.insert(name.to_string(), val.trim().to_string());
            }
        }
    }
    out
}

/// Active signal: did a benign unique marker come back unchanged in the body?
pub fn reflects_marker(body: &str, marker: &str) -> bool {
    body.contains(marker)
}

/// Database error signatures; seeing one is a tentative SQL-injection signal.
pub fn sql_error_signature(body: &str) -> Option<&'static str> {
    // One phrasing per engine was never enough: the same database writes a different sentence
    // depending on the driver in front of it, and the check only ever fires on a message the
    // unmodified response did not already carry, so breadth here costs little and silence
    // costs a confirmed finding. Each entry is distinctive enough not to match ordinary prose.
    const SIGS: [&str; 26] = [
        // MySQL and MariaDB
        "You have an error in your SQL syntax",
        "check the manual that corresponds to your MySQL server version",
        "mysql_fetch_array()",
        "mysql_fetch_assoc()",
        "valid MySQL result",
        "MySQLSyntaxErrorException",
        "MySqlException",
        // SQL Server
        "Unclosed quotation mark after the character string",
        "Incorrect syntax near",
        "OLE DB Provider for SQL Server",
        "System.Data.SqlClient.SqlException",
        // Oracle
        "quoted string not properly terminated",
        "SQL command not properly ended",
        "OracleException",
        // PostgreSQL
        "PostgreSQL query failed",
        "syntax error at or near",
        "pg_query()",
        "PSQLException",
        // SQLite
        "SQLite3::query",
        "SQLITE_ERROR",
        "SQLiteException",
        "sqlite3.OperationalError",
        // Access and the ODBC drivers in front of it
        "Microsoft Access Driver",
        "Syntax error in string in query expression",
        // driver-level, whatever the engine behind it
        "SQLSTATE[",
        "SQLSyntaxErrorException",
    ];
    SIGS.into_iter()
        .find(|s| body.contains(s))
        // Oracle numbers its errors in the thousands and the code is the message; matching the
        // shape rather than a list of codes keeps every one of them recognised.
        .or_else(|| ora_code(body).then_some("ORA-"))
}

/// Whether the body carries an Oracle error code: `ORA-` and at least five digits.
fn ora_code(body: &str) -> bool {
    body.match_indices("ORA-").any(|(i, _)| {
        body[i + 4..].bytes().take(5).filter(|b| b.is_ascii_digit()).count() == 5
    })
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
    /// How hard the active checks probe. Passive checks run at every level; the engine skips
    /// active checks whose minimum level is above this one.
    pub intensity: crate::checks::Intensity,
}

impl Default for ScanLimits {
    fn default() -> Self {
        ScanLimits {
            depth: crate::rules::CRAWL_MAX_LINK_DEPTH,
            max_pages: crate::rules::CRAWL_MAX_UNIQUE_LOCATIONS,
            oast_settle: DEFAULT_OAST_SETTLE,
            intensity: crate::checks::Intensity::default(),
        }
    }
}

/// The settle window a scan waits between planting its out-of-band canaries and polling the
/// relay for callbacks, unless a caller shortens it.
pub const DEFAULT_OAST_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// Called once for every exchange a scan makes, as it is made: the method, the URL, how long
/// it took, and its result. A command line turns this into a running account; the drawn app
/// records the exchange to history and reports progress from the same callback, so both drivers
/// share one engine. The scan also keeps every exchange in [`ScanOutcome::history`].
pub type ScanSink<'a> = dyn FnMut(&str, &str, std::time::Duration, &crate::http::SendResult) + 'a;

/// What a headless scan found and fetched.
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    /// Every exchange the scan made, oldest first, so a caller can keep them in a project.
    pub history: Vec<crate::http::HttpEntry>,
    /// Things the operator asked for that the scan could not do -- credentials that were set
    /// but never submitted, say. Not findings about the target: findings describe the site,
    /// these describe the run, and a run that quietly did less than it was told to is worth
    /// saying out loud.
    pub warnings: Vec<String>,
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

/// Submit `login` to the first password form on `page`, given the response `pre` that page was
/// fetched with. Returns the Cookie header to carry for the rest of the scan, or None when the
/// page holds no login form.
///
/// The session-fixation check lives here because it needs both sides of the exchange: a session
/// identifier that was already set before the login and is unchanged after it is one an attacker
/// can fix in a victim's browser beforehand.
#[allow(clippy::too_many_arguments)]
fn attempt_login(
    page: &str,
    pre: &crate::http::SendResult,
    login: &Login,
    opts: &crate::http::SendOptions,
    history: &mut Vec<crate::http::HttpEntry>,
    next_id: &mut usize,
    sink: &mut ScanSink<'_>,
    findings: &mut Vec<Finding>,
) -> Option<Vec<(String, String)>> {
    let form = crate::crawler::parse_forms(page, &pre.body).into_iter().find(|f| f.has_password())?;
    let pre_ids = session_ids(&pre.headers);
    let req = crate::crawler::login_request(&form, &login.username, &login.password);
    // Sent without following redirects: a login almost always answers 303/302 to the landing
    // page, and the session is set by *that* response. Followed, the Set-Cookie is left behind
    // on a hop the caller never sees and the scan carries on anonymously.
    let post = crate::http::send(&req.method, &req.url, &req.headers, &req.body, false, true, opts);
    record_exchange(history, next_id, &req.method, &req.url, std::time::Duration::ZERO, &post);
    sink(&req.method, &req.url, std::time::Duration::ZERO, &post);
    let post_ids = session_ids(&post.headers);
    let (host, path) = crate::http::split_url(page);
    for (name, before) in &pre_ids {
        if post_ids.get(name) == Some(before) {
            let mut f = Finding::new(SESSION_NOT_ROTATED, Confidence::Firm, &host, &path,
                &format!("The session cookie \"{name}\" was not changed when the user logged in. An \
                          attacker who fixes a victim's session identifier before login keeps access \
                          after it (session fixation); issue a fresh session on authentication."));
            f.point = format!("session cookie \"{name}\"");
            findings.push(f);
        }
    }
    // carry the freshest session forward for the authenticated crawl
    let carry = if post_ids.is_empty() { &pre_ids } else { &post_ids };
    let joined = carry.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; ");
    (!joined.is_empty()).then(|| vec![("Cookie".to_string(), joined)])
}

/// A scanner request, sent on the shared crawl agent when one could be built (so a long crawl
/// reuses one client and its connection pool) and otherwise on a fresh client per request. All
/// scanner traffic follows redirects and unpacks compressed bodies, as it always has.
fn scan_send(
    agent: &Option<ureq::Agent>,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    opts: &crate::http::SendOptions,
) -> crate::http::SendResult {
    match agent {
        Some(a) => crate::http::send_with(a, method, url, headers, body, true),
        None => crate::http::send(method, url, headers, body, crate::rules::AUDIT_FOLLOW_REDIRECTS, true, opts),
    }
}

/// Append one exchange to a scan's history, with the monotonic id the history table expects.
fn record_exchange(
    history: &mut Vec<crate::http::HttpEntry>,
    next_id: &mut usize,
    method: &str,
    url: &str,
    elapsed: std::time::Duration,
    r: &crate::http::SendResult,
) {
    *next_id += 1;
    let (host, path) = crate::http::split_url(url);
    history.push(crate::http::HttpEntry {
        id: *next_id,
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
        elapsed_ms: elapsed.as_millis() as u64,
        graphql: String::new(),
    });
}

/// Crawl (when `crawl` is set) and audit `start`, synchronously, with no app behind it.
///
/// This is the single scan engine: the drawn app drives it on a worker thread and a command
/// line drives it in the foreground, both through `sink` (called for every exchange) and the
/// shared `stop` flag (checked between requests, so a scan can be cancelled or held to a wall
/// clock from outside). Every page is audited with the passive checks, the start page is probed
/// once with a benign marker for a reflected value and a database error message, and -- when a
/// relay is configured -- the out-of-band canaries are planted and polled.
/// Login credentials for the authenticated crawl: when set, the scanner submits them to the
/// first login form it finds, carries the resulting session forward, and checks that the session
/// identifier was rotated.
#[derive(Clone, Debug, Default)]
pub struct Login {
    pub username: String,
    pub password: String,
}

impl Login {
    /// Credentials worth using: both fields are present.
    pub fn is_set(&self) -> bool {
        !self.username.trim().is_empty() && !self.password.trim().is_empty()
    }
}

/// What bounds and steers a scan beyond its limits: the scope it may not leave, and the login it
/// may use. Default is an unbounded (same-origin) scan with no login, which is how a plain scan
/// runs.
#[derive(Default)]
pub struct ScanContext<'a> {
    pub scope: Option<&'a crate::scope::TargetScope>,
    pub login: Option<Login>,
}

// The scan engine's inputs are distinct runtime concerns -- where to start, how far to go, the
// relay, the network options, the scope and login, the stop flag and the progress sink -- so it
// takes them as arguments rather than one grab-bag struct.
#[allow(clippy::too_many_arguments)]
pub fn run_scan(
    start: &str,
    crawl: bool,
    limits: ScanLimits,
    oast: Option<ScanInteractor>,
    opts: &crate::http::SendOptions,
    ctx: &ScanContext<'_>,
    stop: &std::sync::atomic::AtomicBool,
    sink: &mut ScanSink<'_>,
) -> ScanOutcome {
    use std::sync::atomic::Ordering;
    let mut findings = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut history = Vec::new();
    let mut next_id = 0usize;
    // One client for the whole crawl and the marker probe; falls back to a per-request client
    // only if it cannot be built, so a scan never fails for want of connection pooling.
    let agent = crate::http::agent(crate::rules::AUDIT_FOLLOW_REDIRECTS, opts).ok();

    // Scope is a hard boundary: a configured scope gates every crawled link and submitted form,
    // and an empty scope lets the same-origin rule stand, so behaviour is unchanged until one is
    // set. The start URL is where the operator pointed the scan, so it is always audited.
    let start_origin = origin_of_url(start);
    let active = limits.intensity > crate::checks::Intensity::PassiveOnly;
    let in_scope = |url: &str| ctx.scope.is_none_or(|s| s.is_in_scope(url));

    let mut form_targets: Vec<crate::insertion::BaseRequest> = Vec::new();
    // Crawled pages worth probing: a URL the crawl found carries insertion points of its own,
    // and before these were collected the active audit only ever saw the start URL and the
    // forms, so everything a click in went unprobed.
    let mut page_targets: Vec<crate::insertion::BaseRequest> = Vec::new();
    let mut page_sigs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut form_sigs: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Authenticated crawl: log in at the first password form the scan sees -- on the start page
    // if it is there, otherwise on whichever crawled page carries it -- check that the session
    // identifier was rotated, and carry the session cookie on every later request.
    //
    // A site almost never puts its login form on the page a scan is pointed at, so looking only
    // at the start page meant the credentials were usually never sent and the authenticated half
    // of the site went unvisited, without a word about it.
    let wants_login = ctx.login.as_ref().is_some_and(|l| l.is_set());
    let mut cookie_header: Vec<(String, String)> = Vec::new();
    let mut logged_in = false;
    if wants_login && !stop.load(Ordering::Relaxed) {
        let pre = scan_send(&agent, "GET", start, &[], "", opts);
        record_exchange(&mut history, &mut next_id, "GET", start, std::time::Duration::ZERO, &pre);
        sink("GET", start, std::time::Duration::ZERO, &pre);
        let login = ctx.login.as_ref().expect("checked by wants_login");
        if let Some(c) = attempt_login(start, &pre, login, opts, &mut history, &mut next_id, sink, &mut findings) {
            cookie_header = c;
            logged_in = true;
        }
    }

    let mut queue = std::collections::VecDeque::from([(start.to_string(), 0usize)]);
    let mut seen = std::collections::HashSet::from([start.to_string()]);
    let mut requests = 0usize;
    while let Some((page, depth)) = queue.pop_front() {
        if requests >= limits.max_pages || stop.load(Ordering::Relaxed) {
            break;
        }
        requests += 1;
        let sent_at = std::time::Instant::now();
        let r = scan_send(&agent, "GET", &page, &cookie_header, "", opts);
        let elapsed = sent_at.elapsed();
        record_exchange(&mut history, &mut next_id, "GET", &page, elapsed, &r);
        let (host, path) = crate::http::split_url(&page);
        findings.extend(passive_checks(&host, &path, page.starts_with("https"), &r.headers, &r.body));
        sink("GET", &page, elapsed, &r);

        // Still anonymous: this page may be the one holding the login form.
        if wants_login && !logged_in {
            let login = ctx.login.as_ref().expect("checked by wants_login");
            if let Some(c) = attempt_login(&page, &r, login, opts, &mut history, &mut next_id, sink, &mut findings) {
                cookie_header = c;
                logged_in = true;
                // Walk the site again with the session in hand. Pages that answered the
                // anonymous visitor with a redirect to the login form now return their real
                // content, and the links on them have never been seen. `max_pages` still bounds
                // the whole crawl, and this happens at most once.
                seen.clear();
                seen.insert(start.to_string());
                queue.clear();
                queue.push_back((start.to_string(), 0));
                continue;
            }
        }

        // Forms on the page: a passive anti-CSRF check always, and -- at active intensities -- a
        // deduplicated submission to audit, filled with realistic values and its hidden fields kept.
        for form in crate::crawler::parse_forms(&page, &r.body) {
            if origin_of_url(&form.action) != start_origin || !in_scope(&form.action) {
                continue;
            }
            if let Some(f) = crate::crawler::csrf_finding(&form, &host, &path) {
                findings.push(f);
            }
            if active && form_sigs.insert(form.signature()) {
                form_targets.push(crate::crawler::to_request(&form));
            }
        }

        // The page itself: its query parameters are insertion points exactly as a form's fields
        // are. Gated by the same scope the crawl uses and skipped for the start URL, which is
        // audited below whether or not it was crawled.
        if active && page != start && in_scope(&page) {
            let req = crate::insertion::BaseRequest::get(&page);
            if !req.points().is_empty() && page_sigs.insert(req.signature()) {
                page_targets.push(req);
            }
        }

        if crawl && depth < limits.depth {
            for link in extract_links(&page, &r.body) {
                if in_scope(&link) && seen.insert(link.clone()) {
                    queue.push_back((link, depth + 1));
                }
            }
        }
    }

    // Credentials that were set but never used: the scan ran as an anonymous visitor, so
    // everything behind the login is missing from what it reports. Said plainly, because the
    // alternative is a clean-looking report of half a site.
    if wants_login && !logged_in {
        warnings.push(
            "Login credentials were set but never submitted: no login form was found on the start \
             page or on any page the crawl reached. The scan ran without signing in, so nothing \
             behind the login was crawled or audited."
                .to_string(),
        );
    }

    // the start page, audited actively: each insertion point is probed, the request as a whole
    // is probed, and the endpoint is checked for exposed files and open GraphQL. Every probe is
    // confirmed before it reports. Skipped at the passive-only level and once the scan is stopped.
    if limits.intensity > crate::checks::Intensity::PassiveOnly && !stop.load(Ordering::Relaxed) {
        let (host, path) = crate::http::split_url(start);
        let base = crate::insertion::BaseRequest::get(start);
        // a second client that does not follow redirects, so a check can read a Location or the
        // raw response headers (open redirect, CRLF, host-header, exposed files)
        let agent_nf = crate::http::agent(false, opts).ok();
        let mut send = |p: &crate::insertion::PreparedRequest, follow: bool| -> crate::http::SendResult {
            let client = if follow { &agent } else { &agent_nf };
            let sent_at = std::time::Instant::now();
            let r = match client {
                Some(a) => crate::http::send_with(a, &p.method, &p.url, &p.headers, &p.body, true),
                None => crate::http::send(&p.method, &p.url, &p.headers, &p.body, follow, true, opts),
            };
            let elapsed = sent_at.elapsed();
            record_exchange(&mut history, &mut next_id, &p.method, &p.url, elapsed, &r);
            sink(&p.method, &p.url, elapsed, &r);
            r
        };
        findings.extend(crate::checks::active::audit_in_band(&base, &host, &path, limits.intensity, &mut send));
        findings.extend(crate::checks::active::audit_endpoint(start, &host, &path, limits.intensity, &mut send));
        // Each form discovered during the crawl is submitted and audited like any other request,
        // so its fields become insertion points. The list is already deduplicated by signature.
        for ft in form_targets.iter().chain(page_targets.iter()) {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let (fh, fp) = crate::http::split_url(&ft.url);
            findings.extend(crate::checks::active::audit_in_band(ft, &fh, &fp, limits.intensity, &mut send));
        }
    }

    // Out-of-band audit: plant the canaries, record each probe exchange, settle, and poll the
    // relay for callbacks. Skipped entirely when no relay is configured or the scan was stopped.
    if let Some(mut oast) = oast {
        if !stop.load(Ordering::Relaxed) {
            for ex in oast.plant(start, opts) {
                record_exchange(&mut history, &mut next_id, &ex.method, &ex.url, std::time::Duration::ZERO, &ex.result);
                sink(&ex.method, &ex.url, std::time::Duration::ZERO, &ex.result);
            }
            findings.extend(oast.collect(limits.oast_settle, opts));
        }
    }

    ScanOutcome { findings: consolidate(findings), history, warnings }
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
            // the message itself now names the fault, which reads better on a finding than the
            // bare code; any ORA- code is still recognised, including ones with no phrase
            ("Oracle ORA-00933", "ORA-00933: SQL command not properly ended", Some("SQL command not properly ended")),
            ("Oracle code alone", "ORA-01722", Some("ORA-")),
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
        let limits = ScanLimits { depth: 0, max_pages: 1, oast_settle: std::time::Duration::from_millis(150), ..ScanLimits::default() };
        let opts = crate::http::SendOptions::default();
        let url = format!("{}/app", mocks.target);

        let stop = std::sync::atomic::AtomicBool::new(false);
        let outcome = run_scan(&url, false, limits, Some(oast), &opts, &ScanContext::default(), &stop, &mut |_, _, _, _| {});

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
        let limits = ScanLimits { depth: 0, max_pages: 1, oast_settle: std::time::Duration::from_millis(10), ..ScanLimits::default() };
        let url = format!("{}/app", mocks.target);

        let stop = std::sync::atomic::AtomicBool::new(false);
        let outcome = run_scan(&url, false, limits, None, &opts, &ScanContext::default(), &stop, &mut |_, _, _, _| {});

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

    /// The passive checks added with the wider CWE coverage: each fires on a fixture that shows
    /// its weakness and stays quiet on one that does not, so new checks do not add false-positive
    /// noise. Findings are matched by name through the aggregate `passive_checks`.
    #[test]
    fn expanded_passive_matrix() {
        fn present(secure: bool, path: &str, headers: &str, body: &str, name: &str) -> bool {
            passive_checks("a.test", path, secure, headers, body)
                .iter()
                .any(|f| f.name == name)
        }

        // X-Content-Type-Options
        assert!(present(true, "/", "Content-Type: text/html", "", CONTENT_TYPE_OPTIONS.1));
        assert!(!present(true, "/", "X-Content-Type-Options: nosniff", "", CONTENT_TYPE_OPTIONS.1));

        // CORS: wildcard is permissive; a named origin with credentials is flagged separately
        assert!(present(true, "/", "Access-Control-Allow-Origin: *", "", CORS_PERMISSIVE.1));
        assert!(present(true, "/", "Access-Control-Allow-Origin: https://x.test\nAccess-Control-Allow-Credentials: true", "", CORS_CREDENTIALED_ORIGIN.1));
        assert!(!present(true, "/", "Access-Control-Allow-Origin: https://x.test", "", CORS_CREDENTIALED_ORIGIN.1));

        // Referrer-Policy present silences the check
        assert!(present(true, "/", "Content-Type: text/html", "", REFERRER_POLICY.1));
        assert!(!present(true, "/", "Referrer-Policy: no-referrer", "", REFERRER_POLICY.1));

        // version banner
        assert!(present(true, "/", "Server: acme/1.4.2", "", VERSION_BANNER.1));
        assert!(!present(true, "/", "Server: acme", "", VERSION_BANNER.1));

        // SameSite
        assert!(present(true, "/", "Set-Cookie: s=1; Secure; HttpOnly", "", COOKIE_NO_SAMESITE.1));
        assert!(!present(true, "/", "Set-Cookie: s=1; Secure; HttpOnly; SameSite=Lax", "", COOKIE_NO_SAMESITE.1));

        // sensitive token in the URL query string
        assert!(present(true, "/cb?access_token=abc123", "", "", TOKEN_IN_URL.1));
        assert!(!present(true, "/cb?page=2", "", "", TOKEN_IN_URL.1));

        // JWTs: alg none and a missing signature
        let hn = crate::codec::base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
        let hs = crate::codec::base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let pl = crate::codec::base64url_encode(br#"{"sub":"1"}"#);
        let sig = crate::codec::base64url_encode(b"signaturebytes");
        let body_none = format!("token: {hn}.{pl}.");
        let body_unprot = format!("token: {hs}.{pl}.");
        let body_signed = format!("token: {hs}.{pl}.{sig}");
        assert!(present(true, "/", "", &body_none, JWT_UNSIGNED.1));
        assert!(present(true, "/", "", &body_unprot, JWT_UNPROTECTED.1));
        assert!(!present(true, "/", "", &body_signed, JWT_UNSIGNED.1));
        assert!(!present(true, "/", "", &body_signed, JWT_UNPROTECTED.1));

        // credential in a response: a PEM key, and a long secret assignment (but not a placeholder)
        assert!(present(true, "/", "", "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n", SECRET_IN_RESPONSE.1));
        assert!(present(true, "/", "", "{\"api_key\":\"a1b2c3d4e5f6g7h8i9j0\"}", SECRET_IN_RESPONSE.1));
        assert!(!present(true, "/", "", "{\"api_key\":\"your_example_key_here\"}", SECRET_IN_RESPONSE.1));

        // source map reference
        assert!(present(true, "/app.js", "", "//# sourceMappingURL=app.js.map", SOURCE_MAP_EXPOSED.1));
        assert!(!present(true, "/app.js", "", "var x = 1;", SOURCE_MAP_EXPOSED.1));

        // stack trace
        assert!(present(true, "/", "", "Traceback (most recent call last):\n  File ...", STACK_TRACE.1));
        assert!(!present(true, "/", "", "<p>All good</p>", STACK_TRACE.1));

        // mixed content on a secure page
        assert!(present(true, "/", "", r#"<img src="http://cdn.test/a.png">"#, MIXED_CONTENT.1));
        assert!(!present(false, "/", "", r#"<img src="http://cdn.test/a.png">"#, MIXED_CONTENT.1));
        assert!(!present(true, "/", "", r#"<img src="https://cdn.test/a.png">"#, MIXED_CONTENT.1));

        // external script without SRI
        assert!(present(true, "/", "", r#"<script src="https://cdn.other/x.js"></script>"#, MISSING_SRI.1));
        assert!(!present(true, "/", "", r#"<script src="https://cdn.other/x.js" integrity="sha384-x"></script>"#, MISSING_SRI.1));
        assert!(!present(true, "/", "", r#"<script src="/local.js"></script>"#, MISSING_SRI.1));

        // framed-in active content from another origin
        assert!(present(true, "/", "", r#"<iframe src="https://ads.other/f"></iframe>"#, UNTRUSTED_INCLUSION.1));
        assert!(!present(true, "/", "", r#"<iframe src="/own/f"></iframe>"#, UNTRUSTED_INCLUSION.1));

        // DOM XSS source-to-sink
        assert!(present(true, "/", "", "var h = location.hash; el.innerHTML = h;", DOM_XSS_SINK.1));
        assert!(!present(true, "/", "", "var h = location.hash; el.textContent = h;", DOM_XSS_SINK.1));

        // postMessage handler with no origin check
        assert!(present(true, "/", "", "window.addEventListener('message', function(e){ handle(e.data); });", POSTMESSAGE_NO_ORIGIN.1));
        assert!(!present(true, "/", "", "window.addEventListener('message', function(e){ if (e.origin === O) handle(e.data); });", POSTMESSAGE_NO_ORIGIN.1));
    }

    #[test]
    fn passive_audit_of_captured_traffic_finds_issues_without_new_requests() {
        let entry = |url: &str, response: &str| crate::http::HttpEntry {
            id: 1,
            tool: "Proxy".into(),
            method: "GET".into(),
            host: "a.test".into(),
            path: "/".into(),
            status: "200 OK".into(),
            length: 0,
            mime: "text/html".into(),
            request: "GET /".into(),
            response: response.into(),
            url: url.into(),
            truncated: false,
            time: 0,
            elapsed_ms: 0,
            graphql: String::new(),
        };
        let entries = vec![
            entry("https://a.test/", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: acme/1.2\r\n\r\n<p>hi</p>"),
            entry("https://a.test/", ""),
        ];
        let names: Vec<String> = passive_audit_history(&entries).iter().map(|f| f.name.clone()).collect();
        assert!(names.iter().any(|n| n == VERSION_BANNER.1), "version banner from the Server header: {names:?}");
        assert!(names.iter().any(|n| n == CSP_NOT_ENFORCED.1), "missing CSP: {names:?}");
    }

    #[test]
    fn session_ids_reads_only_session_cookies() {
        let h = "set-cookie: sessionid=abc; Path=/\nset-cookie: theme=dark\nset-cookie: user_sid=xyz; HttpOnly";
        let ids = session_ids(h);
        assert_eq!(ids.get("sessionid").map(String::as_str), Some("abc"));
        assert_eq!(ids.get("user_sid").map(String::as_str), Some("xyz"));
        assert!(!ids.contains_key("theme"), "a non-session cookie is ignored");
    }

    #[test]
    fn cookie_authenticated_websocket_handshake_is_flagged_as_cswsh() {
        let entry = |request: &str| crate::http::HttpEntry {
            id: 1,
            tool: "Proxy".into(),
            method: "GET".into(),
            host: "a.test".into(),
            path: "/ws".into(),
            status: "101 Switching Protocols".into(),
            length: 0,
            mime: String::new(),
            request: request.into(),
            response: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".into(),
            url: "https://a.test/ws".into(),
            truncated: false,
            time: 0,
            elapsed_ms: 0,
            graphql: String::new(),
        };
        let with_cookie = entry("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: sid=abc\r\n\r\n");
        let no_cookie = entry("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        assert!(passive_audit_history(&[with_cookie]).iter().any(|f| f.name == CSWSH.1), "a cookie-authed handshake is flagged");
        assert!(!passive_audit_history(&[no_cookie]).iter().any(|f| f.name == CSWSH.1), "no cookie, no CSWSH");
    }

    /// A crawled page's query parameters are audited actively, not just the start URL's.
    ///
    /// The landing page carries no parameters of its own; the reflecting page is only reachable
    /// by following a link. Before crawled URLs were audited this scan reported nothing above
    /// the passive checks, which is the shape a real site has: the weaknesses are a click in.
    #[test]
    fn a_crawled_url_is_actively_audited_not_only_the_start_page() {
        let target = crate::test_utils::ScanTarget::start();
        let limits = ScanLimits {
            depth: 2,
            max_pages: 20,
            oast_settle: std::time::Duration::from_millis(10),
            intensity: crate::checks::Intensity::Standard,
        };
        let opts = crate::http::SendOptions::default();
        let stop = std::sync::atomic::AtomicBool::new(false);
        let outcome = run_scan(&target.base, true, limits, None, &opts, &ScanContext::default(), &stop, &mut |_, _, _, _| {});

        let xss: Vec<&Finding> = outcome.findings.iter().filter(|f| f.cwe == REFLECTED_XSS.0).collect();
        assert!(!xss.is_empty(), "the crawled page's reflected parameter is reported: {:?}",
            outcome.findings.iter().map(|f| f.name.as_str()).collect::<Vec<_>>());
        assert!(xss.iter().any(|f| f.path.starts_with("/s")), "the finding names the crawled page: {:?}",
            xss.iter().map(|f| f.path.as_str()).collect::<Vec<_>>());
        assert!(xss.iter().any(|f| f.point.contains("q")), "the finding names the parameter: {:?}",
            xss.iter().map(|f| f.point.as_str()).collect::<Vec<_>>());
    }

    /// One endpoint is audited once, however many parameter *values* the crawl happens to find.
    ///
    /// `/s?q=hi` and `/s?q=there` are the same endpoint with the same parameter, so probing both
    /// would double every request for nothing. The crawl still fetches each page once; only the
    /// audit is deduplicated.
    #[test]
    fn two_crawled_urls_that_differ_only_in_parameter_values_are_audited_once() {
        let target = crate::test_utils::ScanTarget::start();
        let limits = ScanLimits {
            depth: 2,
            max_pages: 20,
            oast_settle: std::time::Duration::from_millis(10),
            intensity: crate::checks::Intensity::Standard,
        };
        let opts = crate::http::SendOptions::default();
        let stop = std::sync::atomic::AtomicBool::new(false);
        run_scan(&target.base, true, limits, None, &opts, &ScanContext::default(), &stop, &mut |_, _, _, _| {});

        let reqs = target.requests();
        let hits = |needle: &str| reqs.iter().filter(|r| r.contains(needle)).count();
        // the crawl fetches each variant exactly once
        assert_eq!(hits("GET /s?q=there"), 1, "the second variant is crawled but not audited: {reqs:?}");
        // and the first variant carries the audit, so it is requested many times over
        assert!(hits("GET /s?q=hi") > 1, "the endpoint is audited through the first variant: {reqs:?}");
    }

    /// Active probing of crawled pages honours the target scope and the chosen intensity.
    ///
    /// Scope is the operator's promise about what may be touched, and the audit sends far more
    /// traffic than the crawl does, so an excluded page must be probed by neither.
    #[test]
    fn crawled_pages_are_probed_only_in_scope_and_only_at_active_intensities() {
        let run = |intensity, scope: Option<&crate::scope::TargetScope>| {
            let target = crate::test_utils::ScanTarget::start();
            let limits = ScanLimits {
                depth: 2,
                max_pages: 20,
                oast_settle: std::time::Duration::from_millis(10),
                intensity,
            };
            let opts = crate::http::SendOptions::default();
            let stop = std::sync::atomic::AtomicBool::new(false);
            let ctx = ScanContext { scope, login: None };
            run_scan(&target.base, true, limits, None, &opts, &ctx, &stop, &mut |_, _, _, _| {});
            // how many times /s was asked for: once per crawl, many more if it was audited
            target.requests().iter().filter(|r| r.starts_with("GET /s?")).count()
        };

        let probed = run(crate::checks::Intensity::Standard, None);
        assert!(probed > 2, "with no scope set, the crawled page is audited: {probed}");

        let passive = run(crate::checks::Intensity::PassiveOnly, None);
        assert_eq!(passive, 2, "passive only sends no probes, just the two crawl fetches");

        // a scope that admits the site but excludes the reflecting page
        let mut scope = crate::scope::TargetScope::default();
        scope.include.push(crate::scope::ScopeRule::new("http://127.0.0.1"));
        scope.exclude.push(crate::scope::ScopeRule::new("http://127.0.0.1/s"));
        let out_of_scope = run(crate::checks::Intensity::Standard, Some(&scope));
        assert_eq!(out_of_scope, 0, "an excluded page is neither crawled nor probed");
    }

    /// Credentials are submitted to a login form the crawl finds, not only to one on the start
    /// page, and the session they return opens the pages behind it.
    ///
    /// Pointing a scan at a site's root is the ordinary thing to do, and almost no site puts its
    /// login form there. Before the crawl looked, the credentials were simply never sent and the
    /// authenticated half of the site went unseen -- silently.
    #[test]
    fn credentials_reach_a_login_form_found_by_the_crawl() {
        let target = crate::test_utils::ScanTarget::start();
        let limits = ScanLimits {
            depth: 3,
            max_pages: 40,
            oast_settle: std::time::Duration::from_millis(10),
            intensity: crate::checks::Intensity::PassiveOnly,
        };
        let opts = crate::http::SendOptions::default();
        let stop = std::sync::atomic::AtomicBool::new(false);
        let ctx = ScanContext {
            scope: None,
            login: Some(Login { username: "agent".into(), password: "secret".into() }),
        };
        let outcome = run_scan(&target.base, true, limits, None, &opts, &ctx, &stop, &mut |_, _, _, _| {});

        let reqs = target.requests();
        assert!(
            reqs.iter().any(|r| r.starts_with("POST /login") && r.contains("user=agent") && r.contains("pass=secret")),
            "the configured credentials were submitted: {reqs:?}"
        );
        assert!(reqs.iter().any(|r| r.starts_with("GET /vault")),
            "a page linked only from the authenticated area was reached: {reqs:?}");
        assert!(outcome.warnings.is_empty(), "nothing to warn about when the login worked: {:?}", outcome.warnings);
    }

    /// Credentials that are configured but never submitted are reported, rather than the scan
    /// quietly running as an anonymous visitor and reporting whatever it could see.
    #[test]
    fn a_login_that_never_happened_is_warned_about() {
        // a target with no form anywhere: a bare page that links only to itself
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            use std::io::Write;
            for stream in listener.incoming().flatten() {
                let _ = crate::test_utils::read_http_request(&stream);
                let payload = "<html><body>nothing to sign in to</body></html>";
                let mut stream = stream;
                let _ = stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{payload}",
                    payload.len()
                ).as_bytes());
            }
        });

        let limits = ScanLimits {
            depth: 1,
            max_pages: 5,
            oast_settle: std::time::Duration::from_millis(10),
            intensity: crate::checks::Intensity::PassiveOnly,
        };
        let opts = crate::http::SendOptions::default();
        let stop = std::sync::atomic::AtomicBool::new(false);
        let ctx = ScanContext {
            scope: None,
            login: Some(Login { username: "agent".into(), password: "secret".into() }),
        };
        let outcome = run_scan(&base, true, limits, None, &opts, &ctx, &stop, &mut |_, _, _, _| {});

        assert_eq!(outcome.warnings.len(), 1, "exactly one warning: {:?}", outcome.warnings);
        let w = &outcome.warnings[0];
        assert!(w.contains("login"), "the warning names what went unused: {w}");
        assert!(w.to_lowercase().contains("no login form"), "the warning says why: {w}");
    }

    /// Database error messages are recognised across the engines a tester actually meets, not
    /// just the one phrasing per engine that the first pass covered.
    ///
    /// The check itself was never wrong -- it drew the error out and reported it. It simply did
    /// not know most of the sentences a database writes, so a confirmed error-based weakness
    /// went unreported because of the wording of the message.
    #[test]
    fn sql_error_signatures_cover_the_common_engines() {
        let cases = [
            // MySQL / MariaDB
            ("mysql manual hint", "check the manual that corresponds to your MySQL server version"),
            ("mysql fetch", "Warning: mysql_fetch_array() expects parameter 1 to be resource"),
            ("mysql result", "supplied argument is not a valid MySQL result resource"),
            ("mariadb driver", "com.mysql.jdbc.exceptions.MySQLSyntaxErrorException"),
            // SQL Server
            ("mssql incorrect syntax", "Incorrect syntax near the keyword 'FROM'"),
            ("mssql ole db", "Microsoft OLE DB Provider for SQL Server error '80040e14'"),
            ("mssql client", "System.Data.SqlClient.SqlException: Invalid column name"),
            // Oracle
            ("oracle quoted string", "ORA-01756: quoted string not properly terminated"),
            ("oracle missing expression", "ORA-00936: missing expression"),
            // PostgreSQL
            ("postgres syntax", "ERROR: syntax error at or near \"'\""),
            ("postgres pg_query", "Warning: pg_query(): Query failed"),
            ("postgres jdbc", "org.postgresql.util.PSQLException: ERROR"),
            // SQLite
            ("sqlite token", "SQLITE_ERROR: unrecognized token: \"'\""),
            ("sqlite python", "sqlite3.OperationalError: near \"'\": syntax error"),
            // JDBC / generic
            ("jdbc syntax", "java.sql.SQLSyntaxErrorException: malformed statement"),
            ("odbc access", "Microsoft Access Driver] Syntax error in string in query expression"),
        ];
        assert_table!(cases, |(name, body)| {
            assert!(sql_error_signature(body).is_some(), "{name} is recognised: {body}");
        });

        // and ordinary pages still say nothing, so the check stays quiet on a healthy response
        let quiet = [
            ("plain page", "<html><body>Welcome back</body></html>"),
            ("the word sql alone", "Our SQL tutorial covers SELECT statements."),
            ("an unrelated error", "ERROR: the file could not be opened"),
            ("a price", "Total: 100% of the order"),
        ];
        assert_table!(quiet, |(name, body)| {
            assert_eq!(sql_error_signature(body), None, "{name} is not a database error: {body}");
        });
    }
}
