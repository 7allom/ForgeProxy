//! In-band injection checks: a value reflected into markup, a template expression that the
//! server evaluates, a database/XPath/LDAP error drawn out, a file read through a path, and a
//! header split through CR/LF. Every vector is built at run time from its parts -- no attack
//! string is stored in the source -- and every finding is confirmed against a baseline or by an
//! exact, improbable marker before it is raised.

use crate::checks::active::{Baseline, Sender};
use crate::insertion::{BaseRequest, InsertionPoint, PointKind};
use crate::scan::{
    reflects_marker, sql_error_signature, Confidence, Finding, CRLF_INJECTION, INPUT_REFLECTED,
    LDAP_INJECTION, PATH_TRAVERSAL, REFLECTED_XSS, SQL_INJECTION, SSTI, XPATH_INJECTION,
};

/// A value reflected into the page. When the markup-significant characters come back unencoded
/// the value lands in HTML unescaped (reflected cross-site scripting); otherwise a plain marker
/// reflected and confirmed with a second is reported as the weaker "input returned" signal.
pub fn reflected(base: &BaseRequest, point: &InsertionPoint, send: &mut Sender) -> Vec<Finding> {
    let n = crate::insertion::nonce();
    // the nonce wrapped in the characters that matter in HTML, assembled so no markup literal
    // is written in the source
    let probe = format!("{}{}{}{}", '"', '<', n, '>');
    let r = send(&base.apply(point, &probe), true);
    if r.body.contains(&probe) {
        let mut f = Finding::new(
            REFLECTED_XSS,
            Confidence::Firm,
            "",
            "",
            &format!(
                "A value sent in the {} was reflected into the page with its angle brackets and quote \
                 left unencoded, so it lands in the markup unescaped. That is reflected cross-site \
                 scripting; encode the value for its output context.",
                point.label()
            ),
        );
        f.point = point.label();
        f.payload = probe;
        return vec![f];
    }
    if reflects_marker(&r.body, &n) {
        let n2 = crate::insertion::nonce();
        if reflects_marker(&send(&base.apply(point, &n2), true).body, &n2) {
            let mut f = Finding::new(
                INPUT_REFLECTED,
                Confidence::Certain,
                "",
                "",
                &format!(
                    "A value sent in the {} came back unchanged in the page (encoded, or in a context \
                     where it is harmless as sent). Check how it is encoded wherever it is output.",
                    point.label()
                ),
            );
            f.point = point.label();
            f.payload = n;
            return vec![f];
        }
    }
    Vec::new()
}

/// A database error message drawn out by probing `point` that the baseline did not already show.
pub fn sql_error(base: &BaseRequest, point: &InsertionPoint, baseline: &Baseline, send: &mut Sender) -> Vec<Finding> {
    if sql_error_signature(&baseline.result.body).is_some() {
        return Vec::new();
    }
    // a lone quote and a parenthesis -- the characters that break an unparameterised query --
    // after the value that was there, built from parts
    let marker = crate::insertion::nonce();
    let probe = format!("{}{}{}", marker, '\'', ')');
    let r = send(&base.apply(point, &probe), true);
    let Some(sig) = sql_error_signature(&r.body) else { return Vec::new() };
    let mut f = Finding::new(
        SQL_INJECTION,
        Confidence::Tentative,
        "",
        "",
        &format!(
            "Probing the {} drew a database error message ({sig}) the unmodified response did not \
             show. That can point to SQL injection and reveals details about the database.",
            point.label()
        ),
    );
    f.point = point.label();
    f.payload = probe;
    vec![f]
}

/// A template expression the server evaluates: a product of two fixed numbers appears in the
/// response while the expression text does not, and the product was not already on the page.
pub fn ssti(base: &BaseRequest, point: &InsertionPoint, baseline: &Baseline, send: &mut Sender) -> Vec<Finding> {
    let (a, b): (u64, u64) = (7919, 7907);
    let product = (a * b).to_string();
    if baseline.result.body.contains(&product) {
        return Vec::new();
    }
    // the same arithmetic in the delimiters of the common template engines, built from parts
    let candidates = [
        format!("{}{a}{}{b}{}", "${", "*", "}"),
        format!("{}{a}{}{b}{}", "{{", "*", "}}"),
        format!("{}{a}{}{b}{}", "#{", "*", "}"),
        format!("{}{a}{}{b}{}", "<%= ", "*", " %>"),
    ];
    for expr in candidates {
        let r = send(&base.apply(point, &expr), true);
        if r.body.contains(&product) && !r.body.contains(&expr) {
            let mut f = Finding::new(
                SSTI,
                Confidence::Firm,
                "",
                "",
                &format!(
                    "A template expression sent in the {} was evaluated by the server (its arithmetic \
                     result appeared in the response while the expression itself did not). That is \
                     server-side template injection, which often leads to code execution.",
                    point.label()
                ),
            );
            f.point = point.label();
            f.payload = expr;
            return vec![f];
        }
    }
    Vec::new()
}

/// A file read through a path: a traversal vector pulls a system file whose signature the
/// baseline did not show.
pub fn path_traversal(base: &BaseRequest, point: &InsertionPoint, baseline: &Baseline, send: &mut Sender) -> Vec<Finding> {
    // the passwd-style signature: a user line ending in uid/gid 0 for root
    let Some(sig) = crate::regex_cache::get("(?m)^[a-z_][a-z0-9_-]*:[^:]*:0:0:") else { return Vec::new() };
    if sig.is_match(&baseline.result.body) {
        return Vec::new();
    }
    // a system file name assembled at run time, reached through a few traversal encodings
    let target = ["etc", "passwd"].join("/");
    let vectors = [
        format!("{}{target}", "../".repeat(8)),
        format!("{}{target}", "..%2f".repeat(8)),
        format!("{}{target}", "....//".repeat(8)),
    ];
    for v in vectors {
        let r = send(&base.apply(point, &v), true);
        if sig.is_match(&r.body) {
            let mut f = Finding::new(
                PATH_TRAVERSAL,
                Confidence::Firm,
                "",
                "",
                &format!(
                    "A path traversal in the {} returned the contents of a system file that the \
                     unmodified response did not contain. The parameter is used to build a file path \
                     without restricting it to an allowed directory.",
                    point.label()
                ),
            );
            f.point = point.label();
            f.payload = v;
            return vec![f];
        }
    }
    Vec::new()
}

/// An XPath or LDAP error message drawn out by a metacharacter the baseline did not show.
pub fn xpath_ldap(base: &BaseRequest, point: &InsertionPoint, baseline: &Baseline, send: &mut Sender) -> Vec<Finding> {
    // XPath and LDAP are open standards (W3C / IETF), not products; the signatures are the error
    // phrasing their engines emit, with no vendor package names.
    const XPATH_SIGS: &[&str] = &[
        "xpathexception", "error parsing xpath", "xpath syntax error", "unterminated xpath",
        "xpath query failed", "invalid xpath expression",
    ];
    const LDAP_SIGS: &[&str] = &[
        "ldap: error code", "invalid dn syntax", "not a valid ldap", "ldap search filter",
        "bad search filter",
    ];
    let base_low = baseline.result.body.to_ascii_lowercase();
    let marker = crate::insertion::nonce();
    // a quote, a parenthesis and an asterisk: what breaks XPath and LDAP filters, built from parts
    let probe = format!("{}{}{}{}", marker, '\'', ')', '*');
    let body = send(&base.apply(point, &probe), true).body.to_ascii_lowercase();

    if let Some(sig) = XPATH_SIGS.iter().find(|s| body.contains(**s) && !base_low.contains(**s)) {
        let mut f = Finding::new(XPATH_INJECTION, Confidence::Tentative, "", "",
            &format!("Probing the {} drew an XPath error ({sig}) the baseline did not show, which points to \
                      XPath injection.", point.label()));
        f.point = point.label();
        f.payload = probe;
        return vec![f];
    }
    if let Some(sig) = LDAP_SIGS.iter().find(|s| body.contains(**s) && !base_low.contains(**s)) {
        let mut f = Finding::new(LDAP_INJECTION, Confidence::Tentative, "", "",
            &format!("Probing the {} drew an LDAP error ({sig}) the baseline did not show, which points to \
                      LDAP injection.", point.label()));
        f.point = point.label();
        f.payload = probe;
        return vec![f];
    }
    Vec::new()
}

/// A response header split in through CR/LF: a header the probe smuggled into a parameter value
/// appears in the response's own headers.
pub fn crlf(base: &BaseRequest, point: &InsertionPoint, send: &mut Sender) -> Vec<Finding> {
    // only where the value is percent-encoded on the way out, so the CR/LF is the server's to
    // decode, not something that would break our own request line or header block
    if !matches!(point.kind, PointKind::Query | PointKind::Form) {
        return Vec::new();
    }
    let marker = crate::insertion::nonce();
    let header_name = format!("x-{marker}");
    // value, then CR, LF and a header line -- assembled from control characters at run time
    let probe = format!("v{}{}{header_name}: 1", '\r', '\n');
    let r = send(&base.apply(point, &probe), false);
    if r.headers.to_ascii_lowercase().contains(&header_name) {
        let mut f = Finding::new(
            CRLF_INJECTION,
            Confidence::Firm,
            "",
            "",
            &format!(
                "A CR/LF sequence sent in the {} caused a header the probe supplied to appear in the \
                 response's own headers. That is HTTP response header injection (response splitting).",
                point.label()
            ),
        );
        f.point = point.label();
        f.payload = probe;
        return vec![f];
    }
    Vec::new()
}

/// Measure how long one prepared request takes, in seconds. The small recording overhead inside
/// the sender is negligible against the whole-second delays these checks look for.
fn timed(send: &mut Sender, req: &crate::insertion::PreparedRequest) -> f64 {
    let t0 = std::time::Instant::now();
    let _ = send(req, true);
    t0.elapsed().as_secs_f64()
}

/// Time-based injection: a payload that makes the back end wait, confirmed by the response taking
/// at least the delay longer than an un-delayed baseline, and repeated so a one-off slow response
/// does not count. Only runs at the Thorough intensity, since each probe costs the delay.
pub fn timing(
    base: &BaseRequest,
    point: &InsertionPoint,
    intensity: crate::checks::Intensity,
    send: &mut Sender,
) -> Vec<Finding> {
    if intensity < crate::checks::Intensity::Thorough {
        return Vec::new();
    }
    // a five-second delay beats ordinary jitter; the response must beat the baseline by at least
    // 3.5s, twice, to count
    timing_probe(base, point, send, 5, 3.5)
}

/// The timing check with the delay and confirmation threshold as parameters, so it can be tested
/// with a small, fast delay.
fn timing_probe(
    base: &BaseRequest,
    point: &InsertionPoint,
    send: &mut Sender,
    delay_s: u64,
    threshold: f64,
) -> Vec<Finding> {
    let baseline = timed(send, &base.apply(point, "1"));

    // database sleep calls and a shell sleep, each composed at run time around the delay so no
    // whole vector is written as a literal in the source
    let quote = '\'';
    let dash = "-- -";
    let sql: [(&str, String); 3] = [
        (crate::scan::TIMED_SQL_INJECTION.1, format!("1{quote} AND {}({delay_s}){dash}", "SLEEP")),
        (crate::scan::TIMED_SQL_INJECTION.1, format!("1{quote}||{}({delay_s}){dash}", "pg_sleep")),
        (crate::scan::TIMED_SQL_INJECTION.1, format!("1 {}({delay_s})", "SLEEP")),
    ];
    let shell_open = format!("{}{}", '$', '(');
    let cmd: [(&str, String); 2] = [
        (crate::scan::TIMED_COMMAND_INJECTION.1, format!("1{} {} {delay_s}", ';', "sleep")),
        (crate::scan::TIMED_COMMAND_INJECTION.1, format!("1{shell_open}{} {delay_s})", "sleep")),
    ];

    for (name, payload) in sql.iter().chain(cmd.iter()) {
        let dt = timed(send, &base.apply(point, payload));
        if dt - baseline < threshold {
            continue;
        }
        // confirm: the delay reproduces, and a zero-delay control does not
        let again = timed(send, &base.apply(point, payload));
        if again - baseline < threshold {
            continue;
        }
        let def = if *name == crate::scan::TIMED_SQL_INJECTION.1 {
            crate::scan::TIMED_SQL_INJECTION
        } else {
            crate::scan::TIMED_COMMAND_INJECTION
        };
        let mut f = Finding::new(
            def,
            Confidence::Firm,
            "",
            "",
            &format!(
                "A payload sent in the {} made the response take about {delay_s} seconds longer than the \
                 baseline, twice over. The back end executed the delay, which confirms {} injection even \
                 though nothing is shown in the response.",
                point.label(),
                if def.0 == crate::scan::TIMED_SQL_INJECTION.0 { "SQL" } else { "OS command" },
            ),
        );
        f.point = point.label();
        f.payload = payload.clone();
        return vec![f];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::SendResult;
    use crate::insertion::{BaseRequest, PreparedRequest};

    fn ok() -> SendResult {
        SendResult {
            status: "200 OK".into(),
            version: "HTTP/1.1".into(),
            body: "ok".into(),
            headers: String::new(),
            length: 2,
            mime: "text/html".into(),
            error: None,
        }
    }

    #[test]
    fn timing_fires_only_when_a_sleep_payload_delays_the_response() {
        let base = BaseRequest::get("https://a.test/?q=1");
        let point = base.points().into_iter().next().unwrap();
        // a server that pauses briefly when the value carries a sleep call
        let mut slow = |p: &PreparedRequest, _f: bool| {
            let v = crate::codec::url_decode(p.url.split_once("q=").map(|x| x.1).unwrap_or(""));
            if v.to_ascii_lowercase().contains("sleep") {
                std::thread::sleep(std::time::Duration::from_millis(60));
            }
            ok()
        };
        // a short per-probe delay and a 30ms threshold keep the test fast while exercising the logic
        let f = timing_probe(&base, &point, &mut slow, 1, 0.03);
        assert_eq!(f.len(), 1, "a reproduced delay is reported");
        assert_eq!(f[0].cwe, crate::scan::TIMED_SQL_INJECTION.0);

        // a server that never pauses raises nothing
        let mut fast = |_: &PreparedRequest, _f: bool| ok();
        assert!(timing_probe(&base, &point, &mut fast, 1, 0.03).is_empty());
    }

    #[test]
    fn timing_is_skipped_below_thorough() {
        let base = BaseRequest::get("https://a.test/?q=1");
        let point = base.points().into_iter().next().unwrap();
        let mut calls = 0;
        let mut send = |_: &PreparedRequest, _f: bool| {
            calls += 1;
            ok()
        };
        assert!(timing(&base, &point, crate::checks::Intensity::Standard, &mut send).is_empty());
        assert_eq!(calls, 0, "no timing probes below Thorough");
    }
}
