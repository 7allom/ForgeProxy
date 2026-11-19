//! Routing and request-shaping checks: a redirect that will send a user to any host, a Host
//! header the back end echoes into links, and a parameter that pollutes a shared object. Each
//! uses a fresh canary host or marker so a match is unmistakable.

use crate::checks::active::Sender;
use crate::checks::header_value;
use crate::insertion::{BaseRequest, InsertionPoint, PreparedRequest};
use crate::scan::{Confidence, Finding, HOST_HEADER_INJECTION, OPEN_REDIRECT, PROTOTYPE_POLLUTION};

/// The authority (host[:port]) a redirect Location points at, ignoring a query that merely
/// contains a URL. `None` when the Location is not absolute or protocol-relative.
fn redirect_host(loc: &str) -> Option<String> {
    let loc = loc.trim();
    let rest = loc
        .strip_prefix("https://")
        .or_else(|| loc.strip_prefix("http://"))
        .or_else(|| loc.strip_prefix("//"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    Some(authority.to_ascii_lowercase())
}

/// A parameter whose value becomes a redirect target for any host: the response redirects to a
/// canary host the probe supplied.
pub fn open_redirect(base: &BaseRequest, point: &InsertionPoint, send: &mut Sender) -> Vec<Finding> {
    let canary = format!("{}.example", crate::insertion::nonce());
    let target = format!("https://{canary}/");
    let r = send(&base.apply(point, &target), false);
    if let Some(loc) = header_value(&r.headers, "location") {
        if redirect_host(&loc).as_deref() == Some(canary.as_str()) {
            let mut f = Finding::new(
                OPEN_REDIRECT,
                Confidence::Firm,
                "",
                "",
                &format!(
                    "The {} is used as a redirect target without restriction: the response redirected to \
                     a host the request supplied. An attacker can send a user from this site to any host, \
                     which aids phishing.",
                    point.label()
                ),
            );
            f.point = point.label();
            f.payload = target;
            return vec![f];
        }
    }
    Vec::new()
}

/// A Host (or forwarded-host) header the back end trusts to build absolute URLs: the canary host
/// the probe supplied comes back in a redirect Location or a link in the body.
pub fn host_header(base: &BaseRequest, send: &mut Sender) -> Vec<Finding> {
    let canary = format!("{}.example", crate::insertion::nonce());
    let hp = base.header_point("Host");
    let mut req: PreparedRequest = base.apply(&hp, &canary);
    req.headers.push(("X-Forwarded-Host".into(), canary.clone()));
    let r = send(&req, false);
    let in_location = header_value(&r.headers, "location").is_some_and(|l| l.contains(&canary));
    let in_body = r.body.contains(&canary);
    if in_location || in_body {
        let mut f = Finding::new(
            HOST_HEADER_INJECTION,
            if in_location { Confidence::Firm } else { Confidence::Tentative },
            "",
            "",
            "The server reflected a Host (or X-Forwarded-Host) value the request supplied into a \
             redirect or a link. A back end that trusts the Host header to build absolute URLs can be \
             made to point password-reset and other links at an attacker's host.",
        );
        f.point = "\"Host\" header".to_string();
        f.payload = canary;
        return vec![f];
    }
    Vec::new()
}

/// A parameter that pollutes a shared object's prototype: after a request carrying a
/// `__proto__` entry with a canary value, a fresh request to the same page reflects that value,
/// which it did not before.
pub fn prototype_pollution(base: &BaseRequest, send: &mut Sender) -> Vec<Finding> {
    let marker = crate::insertion::nonce();
    // __proto__[<marker>]=<marker>, appended raw so the brackets reach the parser
    let sep = if base.url.contains('?') { '&' } else { '?' };
    let poisoned = PreparedRequest {
        method: base.method.clone(),
        url: format!("{}{sep}__proto__[{marker}]={marker}", base.url),
        headers: base.headers.clone(),
        body: base.body.clone(),
    };
    send(&poisoned, true);
    // a clean request afterwards: if the canary now appears, a shared prototype was polluted
    let clean = PreparedRequest {
        method: base.method.clone(),
        url: base.url.clone(),
        headers: base.headers.clone(),
        body: base.body.clone(),
    };
    let after = send(&clean, true);
    if after.body.contains(&marker) {
        let mut f = Finding::new(
            PROTOTYPE_POLLUTION,
            Confidence::Tentative,
            "",
            "",
            "After a request carrying a __proto__ entry, a later clean request reflected the value it \
             set. That suggests request input is merged into a shared object's prototype (prototype \
             pollution), which can change application behaviour for every request.",
        );
        f.payload = format!("__proto__[{marker}]={marker}");
        return vec![f];
    }
    Vec::new()
}
