//! Active checks: they probe a target by substituting values into a request's insertion points
//! (`crate::insertion`) and reading what comes back, or by requesting well-known endpoints. Each
//! makes traffic, so the engine gates them by scan [`Intensity`](crate::checks::Intensity) and
//! every check confirms a signal -- against a baseline, with a second probe, or by an exact,
//! unmistakable marker -- before it reports, to keep the noise low.

pub mod injection;
pub mod files;
pub mod routing;
pub mod apis;

use crate::insertion::{BaseRequest, PreparedRequest};
use crate::scan::Finding;

/// How a check sends a prepared request: the engine records the exchange, applies any rate
/// limit, and returns the response. `follow` chooses whether redirects are followed -- a check
/// that needs to read a Location or the raw response headers asks for `false`. A check calls
/// this and reads the result; it never builds a client of its own.
pub type Sender<'a> = dyn FnMut(&PreparedRequest, bool) -> crate::http::SendResult + 'a;

/// The unmodified request's response, so a check can tell a signal its probe caused from one the
/// page always shows.
pub struct Baseline {
    pub result: crate::http::SendResult,
}

impl Baseline {
    /// Fetch the base request once, unmodified, following redirects as a browser would.
    pub fn capture(base: &BaseRequest, send: &mut Sender) -> Self {
        let req = PreparedRequest {
            method: base.method.clone(),
            url: base.url.clone(),
            headers: base.headers.clone(),
            body: base.body.clone(),
        };
        Baseline { result: send(&req, true) }
    }
}

/// Probe one captured request at the given intensity: every insertion point is fuzzed by the
/// in-band checks, and the request as a whole by the checks that target a header. `host`/`path`
/// locate the findings. Returns findings; the caller consolidates.
pub fn audit_in_band(
    base: &BaseRequest,
    host: &str,
    path: &str,
    intensity: crate::checks::Intensity,
    send: &mut Sender,
) -> Vec<Finding> {
    if intensity <= crate::checks::Intensity::PassiveOnly {
        return Vec::new();
    }
    // A request with no insertion point of its own is still probed through one appended query
    // parameter, so a parameterless page is audited as it was before the point model.
    let owned;
    let target = if base.points().is_empty() {
        let url = if base.url.contains('?') { format!("{}&q=1", base.url) } else { format!("{}?q=1", base.url) };
        owned = BaseRequest { method: base.method.clone(), url, headers: base.headers.clone(), body: base.body.clone() };
        &owned
    } else {
        base
    };

    let baseline = Baseline::capture(target, send);
    let mut out = Vec::new();
    for point in target.points() {
        out.extend(injection::reflected(target, &point, send));
        out.extend(injection::sql_error(target, &point, &baseline, send));
        out.extend(injection::ssti(target, &point, &baseline, send));
        out.extend(injection::path_traversal(target, &point, &baseline, send));
        out.extend(injection::xpath_ldap(target, &point, &baseline, send));
        out.extend(injection::crlf(target, &point, send));
        out.extend(routing::open_redirect(target, &point, send));
        out.extend(injection::timing(target, &point, intensity, send));
    }
    // Request-wide checks: the Host header a back end may trust, and a prototype-polluting
    // parameter whose effect shows on a later request.
    out.extend(routing::host_header(target, send));
    out.extend(routing::prototype_pollution(target, send));

    for f in out.iter_mut() {
        f.host = host.to_string();
        f.path = path.to_string();
    }
    out
}

/// Probe the target as an endpoint, not through its parameters: look for sensitive files served
/// near its path, and -- when it looks like a GraphQL endpoint -- whether introspection and
/// query batching are open. Runs once per scanned start URL.
pub fn audit_endpoint(
    start: &str,
    host: &str,
    path: &str,
    intensity: crate::checks::Intensity,
    send: &mut Sender,
) -> Vec<Finding> {
    if intensity <= crate::checks::Intensity::PassiveOnly {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.extend(files::exposed_files(start, send));
    out.extend(apis::graphql(start, send));
    for f in out.iter_mut() {
        if f.host.is_empty() {
            f.host = host.to_string();
        }
        if f.path.is_empty() {
            f.path = path.to_string();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::SendResult;
    use crate::insertion::BaseRequest;

    /// Build a response with the given status line, header block and body.
    fn resp(status: &str, headers: &str, body: &str) -> SendResult {
        SendResult {
            status: status.into(),
            version: "HTTP/1.1".into(),
            body: body.into(),
            headers: headers.into(),
            length: body.len(),
            mime: "text/html".into(),
            error: None,
        }
    }

    /// The decoded value a prepared request carries for query parameter `name`.
    fn query_value(p: &PreparedRequest, name: &str) -> String {
        let Some((_, q)) = p.url.split_once('?') else { return String::new() };
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == name {
                    return crate::codec::url_decode(v);
                }
            }
        }
        String::new()
    }

    fn one_query_point(url: &str) -> (BaseRequest, crate::insertion::InsertionPoint) {
        let base = BaseRequest::get(url);
        let point = base.points().into_iter().next().expect("a query point");
        (base, point)
    }

    #[test]
    fn reflected_xss_fires_only_when_markup_comes_back_unencoded() {
        let (base, point) = one_query_point("https://a.test/s?q=x");
        // a server that echoes the value verbatim into the page
        let mut raw = |p: &PreparedRequest, _f: bool| resp("200 OK", "", &format!("<p>{}</p>", query_value(p, "q")));
        let f = injection::reflected(&base, &point, &mut raw);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe, crate::scan::REFLECTED_XSS.0, "verbatim reflection is XSS");

        // a server that HTML-encodes the value falls back to the weaker reflection signal
        let mut enc = |p: &PreparedRequest, _f: bool| {
            let v = query_value(p, "q").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
            resp("200 OK", "", &format!("<p>{v}</p>"))
        };
        let f = injection::reflected(&base, &point, &mut enc);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe, crate::scan::INPUT_REFLECTED.0, "encoded reflection is the weaker signal");

        // a server that does not reflect at all reports nothing
        let mut none = |_: &PreparedRequest, _f: bool| resp("200 OK", "", "<p>static</p>");
        assert!(injection::reflected(&base, &point, &mut none).is_empty());
    }

    #[test]
    fn ssti_fires_when_the_expression_is_evaluated() {
        let (base, point) = one_query_point("https://a.test/s?q=x");
        let baseline = Baseline { result: resp("200 OK", "", "hello") };
        let product = (7919u64 * 7907).to_string();
        // a server that evaluates a template expression returns the product, not the expression
        let mut evalr = |p: &PreparedRequest, _f: bool| {
            let v = query_value(p, "q");
            if v.contains('*') && (v.contains("${") || v.contains("{{") || v.contains("#{") || v.contains("<%")) {
                resp("200 OK", "", &format!("result {product}"))
            } else {
                resp("200 OK", "", "no")
            }
        };
        let f = injection::ssti(&base, &point, &baseline, &mut evalr);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe, crate::scan::SSTI.0);

        // a server that echoes the expression unchanged did not evaluate it: no finding
        let mut echo = |p: &PreparedRequest, _f: bool| resp("200 OK", "", &query_value(p, "q"));
        assert!(injection::ssti(&base, &point, &baseline, &mut echo).is_empty());
    }

    #[test]
    fn path_traversal_fires_on_a_passwd_signature_absent_from_baseline() {
        let (base, point) = one_query_point("https://a.test/file?q=home");
        let baseline = Baseline { result: resp("200 OK", "", "a normal page") };
        let mut server = |p: &PreparedRequest, _f: bool| {
            if query_value(p, "q").contains("etc/passwd") {
                resp("200 OK", "", "root:x:0:0:root:/root:/bin/bash\n")
            } else {
                resp("200 OK", "", "a normal page")
            }
        };
        let f = injection::path_traversal(&base, &point, &baseline, &mut server);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe, crate::scan::PATH_TRAVERSAL.0);
    }

    #[test]
    fn crlf_fires_when_the_smuggled_header_appears_in_the_response() {
        let (base, point) = one_query_point("https://a.test/r?q=x");
        // a server that decodes CR/LF in the value into its own response headers
        let mut server = |p: &PreparedRequest, _f: bool| {
            let v = query_value(p, "q");
            // the smuggled header is everything after the CR/LF
            let header_echo = v.split("\r\n").nth(1).unwrap_or("");
            resp("200 OK", &format!("content-type: text/html\n{header_echo}\n"), "ok")
        };
        let f = injection::crlf(&base, &point, &mut server);
        assert_eq!(f.len(), 1, "a reflected injected header is response splitting");
        assert_eq!(f[0].cwe, crate::scan::CRLF_INJECTION.0);
    }

    #[test]
    fn open_redirect_fires_when_location_points_at_the_canary_host() {
        let (base, point) = one_query_point("https://a.test/go?q=home");
        let mut server = |p: &PreparedRequest, _f: bool| {
            let v = query_value(p, "q");
            // redirect straight to whatever host the value named
            if v.starts_with("https://") {
                resp("302 Found", &format!("location: {v}\n"), "")
            } else {
                resp("200 OK", "", "ok")
            }
        };
        let f = routing::open_redirect(&base, &point, &mut server);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe, crate::scan::OPEN_REDIRECT.0);

        // a redirect that stays on the site is not an open redirect
        let mut safe = |_: &PreparedRequest, _f: bool| resp("302 Found", "location: /home\n", "");
        assert!(routing::open_redirect(&base, &point, &mut safe).is_empty());
    }

    #[test]
    fn host_header_injection_fires_when_the_forwarded_host_is_reflected() {
        let base = BaseRequest::get("https://a.test/reset");
        let mut server = |p: &PreparedRequest, _f: bool| {
            let fwd = p.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-host")).map(|(_, v)| v.clone()).unwrap_or_default();
            resp("200 OK", "", &format!("<a href=\"https://{fwd}/next\">continue</a>"))
        };
        let f = routing::host_header(&base, &mut server);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cwe, crate::scan::HOST_HEADER_INJECTION.0);
    }

    #[test]
    fn exposed_files_fire_on_signature_not_on_a_soft_error_page() {
        let mut server = |p: &PreparedRequest, _f: bool| {
            if p.url.ends_with("/.git/HEAD") {
                resp("200 OK", "", "ref: refs/heads/main\n")
            } else if p.url.ends_with("/.env") {
                // a soft-404 HTML page must not count
                resp("200 OK", "", "<html><body>Not found</body></html>")
            } else {
                resp("404 Not Found", "", "nope")
            }
        };
        let f = files::exposed_files("https://a.test/app", &mut server);
        assert_eq!(f.len(), 1, "only the real metadata file, not the HTML soft error");
        assert_eq!(f[0].cwe, crate::scan::EXPOSED_FILE.0);
    }

    #[test]
    fn graphql_checks_only_run_on_a_graphql_endpoint() {
        // not a GraphQL path: nothing is sent
        let mut never = |_: &PreparedRequest, _f: bool| resp("200 OK", "", "{}");
        assert!(apis::graphql("https://a.test/api/users", &mut never).is_empty());

        // introspection open and batching honoured
        let mut server = |p: &PreparedRequest, _f: bool| {
            if p.body.contains("__schema") {
                resp("200 OK", "", r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#)
            } else if p.body.trim_start().starts_with('[') {
                resp("200 OK", "", r#"[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]"#)
            } else {
                resp("200 OK", "", "{}")
            }
        };
        let f = apis::graphql("https://a.test/graphql", &mut server);
        let cwes: Vec<u32> = f.iter().map(|x| x.cwe).collect();
        assert!(cwes.contains(&crate::scan::GRAPHQL_INTROSPECTION.0), "introspection reported: {cwes:?}");
        assert!(cwes.contains(&crate::scan::GRAPHQL_BATCHING.0), "batching reported: {cwes:?}");
    }

    #[test]
    fn passive_only_intensity_sends_no_active_probes() {
        let base = BaseRequest::get("https://a.test/?q=1");
        let mut calls = 0;
        let mut send = |_: &PreparedRequest, _f: bool| {
            calls += 1;
            resp("200 OK", "", "x")
        };
        let f = audit_in_band(&base, "a.test", "/", crate::checks::Intensity::PassiveOnly, &mut send);
        assert!(f.is_empty());
        assert_eq!(calls, 0, "passive-only makes no active requests");
    }
}
