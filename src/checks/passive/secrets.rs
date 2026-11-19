//! Passive checks for information left in a response body: directory listings, password
//! fields, and disclosed email addresses or private IP addresses.

use crate::checks::PassiveCtx;
use crate::scan::{
    Confidence, Finding, CLEARTEXT_PASSWORD, DIRECTORY_LISTING, EMAIL_DISCLOSED,
    PASSWORD_AUTOCOMPLETE, PRIVATE_IP_DISCLOSED,
};

/// A body that reads like an automatic directory index.
pub fn directory_listing(ctx: &PassiveCtx) -> Vec<Finding> {
    if ctx.lbody.contains("index of /") || ctx.lbody.contains("directory listing for /") {
        return vec![Finding::new(
            DIRECTORY_LISTING,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "The response looks like an automatic directory listing, which can reveal files that \
             were not meant to be public.",
        )];
    }
    Vec::new()
}

/// A password field that lets the browser store the value, or that is served over plain HTTP so
/// the value would travel unencrypted. Both are reported for one field when both apply, in that
/// order.
pub fn password_fields(ctx: &PassiveCtx) -> Vec<Finding> {
    let mut out = Vec::new();
    if ctx.lbody.contains("type=\"password\"") {
        if !ctx.lbody.contains("autocomplete=\"off\"") {
            out.push(Finding::new(
                PASSWORD_AUTOCOMPLETE,
                Confidence::Certain,
                ctx.host,
                ctx.path,
                "A password box did not turn off autocomplete, so the browser may store the value.",
            ));
        }
        if !ctx.secure {
            out.push(Finding::new(
                CLEARTEXT_PASSWORD,
                Confidence::Certain,
                ctx.host,
                ctx.path,
                "A page served over plain HTTP contains a password box, so the password would be \
                 sent unencrypted.",
            ));
        }
    }
    out
}

/// Email addresses disclosed in the body.
pub fn email_disclosed(ctx: &PassiveCtx) -> Vec<Finding> {
    if contains_email(ctx.body) {
        return vec![Finding::new(
            EMAIL_DISCLOSED,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "The response contained one or more email addresses, which can help an attacker with \
             phishing or password guessing.",
        )];
    }
    Vec::new()
}

/// A private (RFC 1918) IP address disclosed in the body.
pub fn private_ip_disclosed(ctx: &PassiveCtx) -> Vec<Finding> {
    if contains_private_ip(ctx.body) {
        return vec![Finding::new(
            PRIVATE_IP_DISCLOSED,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "The response mentioned a private (internal) IP address, which leaks network layout.",
        )];
    }
    Vec::new()
}

/// A cheap scan for something that reads like an email address: an `@` with an alphanumeric
/// character before it and a dotted domain after it. Kept deliberately simple rather than a
/// full address grammar.
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

/// Whether the text mentions an RFC 1918 private IPv4 address (10/8, 192.168/16, 172.16/12).
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

use crate::scan::{
    JWT_UNPROTECTED, JWT_UNSIGNED, SECRET_IN_RESPONSE, SOURCE_MAP_EXPOSED, STACK_TRACE, TOKEN_IN_URL,
};

/// Parameter names that should never travel in a URL, where they are logged and leak in Referer.
const SENSITIVE_PARAMS: &[&str] = &[
    "token", "access_token", "id_token", "refresh_token", "apikey", "api_key", "session",
    "sessionid", "sid", "password", "passwd", "pwd", "secret", "otp",
];

/// A sensitive-looking parameter carried in the query string rather than the body or a header.
pub fn token_in_url(ctx: &PassiveCtx) -> Vec<Finding> {
    let Some((_, query)) = ctx.path.split_once('?') else { return Vec::new() };
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !value.is_empty() && SENSITIVE_PARAMS.contains(&name.to_ascii_lowercase().as_str()) {
            return vec![Finding::new(
                TOKEN_IN_URL,
                Confidence::Firm,
                ctx.host,
                ctx.path,
                "A sensitive-looking parameter was carried in the URL query string, where servers and \
                 proxies log it and it leaks to other sites in the Referer header. Send such values in \
                 the request body or a header instead.",
            )];
        }
    }
    Vec::new()
}

/// Candidate JSON Web Tokens in a block of text: runs that start `eyJ` (the Base64URL of `{"`),
/// which every JWT header begins with, kept whole through their dot-separated segments.
fn find_jwts(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = text[i..].find("eyJ") {
        let start = i + rel;
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.' {
                end += 1;
            } else {
                break;
            }
        }
        out.push(&text[start..end]);
        i = end.max(start + 1);
    }
    out
}

/// A web token whose header says it is unsigned (`alg: none`) or that carries an empty signature,
/// found in the body or a Set-Cookie value -- a token a server accepting it would trust without
/// verifying who issued it.
pub fn jwt_weakness(ctx: &PassiveCtx) -> Vec<Finding> {
    let mut haystack = ctx.body.to_string();
    for line in crate::checks::header_lines(ctx.headers, "set-cookie") {
        haystack.push('\n');
        haystack.push_str(line);
    }
    let mut out = Vec::new();
    let (mut unsigned, mut unprotected) = (false, false);
    for tok in find_jwts(&haystack) {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        let Some(raw) = crate::codec::base64url_decode(parts[0]) else { continue };
        let Ok(hdr) = serde_json::from_slice::<serde_json::Value>(&raw) else { continue };
        let alg = hdr.get("alg").and_then(|a| a.as_str()).unwrap_or_default();
        if alg.eq_ignore_ascii_case("none") {
            if !unsigned {
                unsigned = true;
                out.push(Finding::new(
                    JWT_UNSIGNED,
                    Confidence::Firm,
                    ctx.host,
                    ctx.path,
                    "A web token declaring alg: none (no signature) was present. A server that accepts it \
                     trusts the token's contents without checking who issued them.",
                ));
            }
        } else if parts.len() == 3 && parts[2].is_empty() && !unprotected {
            unprotected = true;
            out.push(Finding::new(
                JWT_UNPROTECTED,
                Confidence::Firm,
                ctx.host,
                ctx.path,
                "A web token names a signature algorithm but carries no signature. Its contents are not \
                 protected against tampering.",
            ));
        }
    }
    out
}

/// A credential left in a response: a PEM private-key block, or a secret-named field assigned a
/// long, non-placeholder value.
pub fn secret_in_response(ctx: &PassiveCtx) -> Vec<Finding> {
    if ctx.lbody.contains("-----begin") && ctx.lbody.contains("private key-----") {
        return vec![Finding::new(
            SECRET_IN_RESPONSE,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "A PEM private-key block was present in the response. A private key must never be served to \
             clients; rotate it and remove it from the response.",
        )];
    }
    let pattern = r#"(?:password|passwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9+/_\-]{16,})["']"#;
    if let Some(re) = crate::regex_cache::get_with(pattern, true) {
        if let Some(caps) = re.captures(ctx.body) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or_default().to_ascii_lowercase();
            let placeholder = ["example", "changeme", "your", "xxxx", "placeholder", "redacted", "dummy", "test", "none", "null"]
                .iter()
                .any(|p| value.contains(p));
            if !placeholder {
                return vec![Finding::new(
                    SECRET_IN_RESPONSE,
                    Confidence::Tentative,
                    ctx.host,
                    ctx.path,
                    "A secret-named field in the response was assigned a long, credential-shaped value. If \
                     it is a real key or password, move it server-side and rotate it.",
                )];
            }
        }
    }
    Vec::new()
}

/// A reference to a JavaScript source map, which can hand an attacker the original source.
pub fn source_map(ctx: &PassiveCtx) -> Vec<Finding> {
    if ctx.lbody.contains("sourcemappingurl=") {
        return vec![Finding::new(
            SOURCE_MAP_EXPOSED,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "The response referenced a source map. If the .map file is reachable it reveals the original, \
             unminified source; do not ship source maps to production clients.",
        )];
    }
    Vec::new()
}

/// A stack trace or debug error in the body, which leaks internal paths, versions and logic.
// Brand-neutral markers of a stack trace or debug error, naming no language or framework.
const TRACE_SIGNATURES: &[&str] = &[
    "traceback (most recent call last)",
    "exception in thread \"",
    "stack trace:",
    "nullreferenceexception",
    "fatal error: uncaught",
    "unhandled exception at",
    "\n    at ",
];

pub fn stack_trace(ctx: &PassiveCtx) -> Vec<Finding> {
    if TRACE_SIGNATURES.iter().any(|s| ctx.lbody.contains(s)) {
        return vec![Finding::new(
            STACK_TRACE,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "The response contained a stack trace or debug error message, which leaks internal file paths, \
             software versions and application logic. Return a generic error page instead.",
        )];
    }
    Vec::new()
}
