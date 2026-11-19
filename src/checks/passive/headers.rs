//! Passive checks on transport, framing and caching response headers.

use crate::checks::{header_lines, header_present, PassiveCtx};
use crate::scan::{
    Confidence, Finding, CACHEABLE_HTTPS, CSP_NOT_ENFORCED, FRAMEABLE, HSTS_NOT_ENFORCED,
};

/// An HTTPS response that does not pin itself to HTTPS with Strict-Transport-Security.
pub fn hsts(ctx: &PassiveCtx) -> Vec<Finding> {
    if ctx.secure && !header_present(ctx.headers, "strict-transport-security") {
        return vec![Finding::new(
            HSTS_NOT_ENFORCED,
            Confidence::Certain,
            ctx.host,
            ctx.path,
            "The HTTPS response did not set a Strict-Transport-Security header, so a browser may be \
             downgraded to plain HTTP by a network attacker.",
        )];
    }
    Vec::new()
}

/// A response with no Content-Security-Policy to limit where scripts load from.
pub fn csp(ctx: &PassiveCtx) -> Vec<Finding> {
    if !header_present(ctx.headers, "content-security-policy") {
        return vec![Finding::new(
            CSP_NOT_ENFORCED,
            Confidence::Certain,
            ctx.host,
            ctx.path,
            "No Content-Security-Policy header was present. A policy limits the damage of \
             cross-site scripting by restricting where scripts may load from.",
        )];
    }
    Vec::new()
}

/// A response that may be framed by another site, with neither X-Frame-Options nor a
/// frame-ancestors directive to stop it.
pub fn frameable(ctx: &PassiveCtx) -> Vec<Finding> {
    let framed = header_present(ctx.headers, "x-frame-options")
        || ctx.headers.to_ascii_lowercase().contains("frame-ancestors");
    if !framed {
        return vec![Finding::new(
            FRAMEABLE,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "The response can be shown inside a frame on another site, so it may be open to \
             clickjacking unless framing is restricted.",
        )];
    }
    Vec::new()
}

/// An HTTPS response that caches may keep because Cache-Control: no-store was not set.
pub fn cacheable_https(ctx: &PassiveCtx) -> Vec<Finding> {
    if ctx.secure {
        let cc = header_lines(ctx.headers, "cache-control").join(" ").to_ascii_lowercase();
        if !cc.contains("no-store") {
            return vec![Finding::new(
                CACHEABLE_HTTPS,
                Confidence::Certain,
                ctx.host,
                ctx.path,
                "The HTTPS response may be kept by caches because Cache-Control: no-store was not \
                 set, so sensitive content could be left on disk.",
            )];
        }
    }
    Vec::new()
}

use crate::checks::{has_version_number, header_value};
use crate::scan::{
    CONTENT_TYPE_OPTIONS, CORS_CREDENTIALED_ORIGIN, CORS_PERMISSIVE, REFERRER_POLICY, VERSION_BANNER,
};

/// A response that does not pin its declared content type, so a browser may sniff a different
/// one and, for example, run an uploaded file as script.
pub fn content_type_options(ctx: &PassiveCtx) -> Vec<Finding> {
    match header_value(ctx.headers, "x-content-type-options") {
        Some(v) if v.eq_ignore_ascii_case("nosniff") => Vec::new(),
        _ => vec![Finding::new(
            CONTENT_TYPE_OPTIONS,
            Confidence::Certain,
            ctx.host,
            ctx.path,
            "The response did not send X-Content-Type-Options: nosniff, so a browser may ignore the \
             declared type and sniff another, which can turn a benign file into executable script.",
        )],
    }
}

/// A cross-origin resource sharing policy that is open to any site, or that shares credentialed
/// responses with a named origin.
pub fn cors(ctx: &PassiveCtx) -> Vec<Finding> {
    let Some(acao) = header_value(ctx.headers, "access-control-allow-origin") else {
        return Vec::new();
    };
    let credentials = header_value(ctx.headers, "access-control-allow-credentials")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let acao = acao.trim();
    if acao == "*" || acao.eq_ignore_ascii_case("null") {
        return vec![Finding::new(
            CORS_PERMISSIVE,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "Access-Control-Allow-Origin is open to any site, so a page on another origin can read \
             this response. Restrict it to the origins that need access.",
        )];
    }
    if credentials {
        return vec![Finding::new(
            CORS_CREDENTIALED_ORIGIN,
            Confidence::Tentative,
            ctx.host,
            ctx.path,
            "The response shares a credentialed body across origins with a named origin. Confirm the \
             allowed origin is fixed and trusted, not reflected from the request.",
        )];
    }
    Vec::new()
}

/// A response with no Referrer-Policy, so the full URL (which may hold identifiers) can leak to
/// other sites in the Referer header.
pub fn referrer_policy(ctx: &PassiveCtx) -> Vec<Finding> {
    if header_value(ctx.headers, "referrer-policy").is_none() {
        return vec![Finding::new(
            REFERRER_POLICY,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "No Referrer-Policy header was set, so the browser may send the full URL of this page to \
             other sites in the Referer header, leaking anything the URL contains.",
        )];
    }
    Vec::new()
}

/// A Server or framework header that names a software version, which helps an attacker match
/// the target to known weaknesses.
pub fn version_banner(ctx: &PassiveCtx) -> Vec<Finding> {
    for name in ["server", "x-powered-by", "x-aspnet-version", "x-runtime"] {
        if let Some(v) = header_value(ctx.headers, name) {
            if has_version_number(&v) {
                return vec![Finding::new(
                    VERSION_BANNER,
                    Confidence::Firm,
                    ctx.host,
                    ctx.path,
                    "A response header named a software version. Removing version numbers from banners \
                     makes it harder to match the server to published weaknesses.",
                )];
            }
        }
    }
    Vec::new()
}
