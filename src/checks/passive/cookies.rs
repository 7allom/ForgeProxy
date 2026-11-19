//! Passive checks on the flags carried by Set-Cookie headers.

use crate::checks::{header_lines, PassiveCtx};
use crate::scan::{Confidence, Finding, COOKIE_NO_HTTPONLY, TLS_COOKIE_NO_SECURE};

/// Each Set-Cookie line is checked for the Secure flag (over HTTPS) and the HttpOnly flag, in
/// that order, so a cookie missing both raises both findings as it did before the checks split.
pub fn cookie_flags(ctx: &PassiveCtx) -> Vec<Finding> {
    let mut out = Vec::new();
    for cookie in header_lines(ctx.headers, "set-cookie") {
        let low = cookie.to_ascii_lowercase();
        if ctx.secure && !low.contains("secure") {
            out.push(Finding::new(
                TLS_COOKIE_NO_SECURE,
                Confidence::Firm,
                ctx.host,
                ctx.path,
                "A cookie was set over HTTPS without the Secure flag, so it may also be sent over \
                 an unencrypted connection.",
            ));
        }
        if !low.contains("httponly") {
            out.push(Finding::new(
                COOKIE_NO_HTTPONLY,
                Confidence::Firm,
                ctx.host,
                ctx.path,
                "A cookie was set without the HttpOnly flag, so page scripts can read it, which \
                 makes it easier to steal through cross-site scripting.",
            ));
        }
    }
    out
}

/// A cookie set without a SameSite attribute, so a browser's default may still attach it to
/// cross-site requests, which helps cross-site request forgery.
pub fn cookie_samesite(ctx: &PassiveCtx) -> Vec<crate::scan::Finding> {
    let mut out = Vec::new();
    for cookie in crate::checks::header_lines(ctx.headers, "set-cookie") {
        if !cookie.to_ascii_lowercase().contains("samesite") {
            out.push(crate::scan::Finding::new(
                crate::scan::COOKIE_NO_SAMESITE,
                crate::scan::Confidence::Firm,
                ctx.host,
                ctx.path,
                "A cookie was set without a SameSite attribute. Setting SameSite=Lax or Strict stops \
                 the cookie riding along on cross-site requests, which blunts cross-site request forgery.",
            ));
        }
    }
    out
}
