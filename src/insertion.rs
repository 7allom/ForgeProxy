//! Insertion points: the places in a request where an active check substitutes a value.
//!
//! A [`BaseRequest`] is one request the crawler captured or built; [`BaseRequest::points`]
//! enumerates the query parameters, URL-encoded form fields, JSON values and cookies it carries,
//! and [`BaseRequest::apply`] rebuilds the request with one point's value replaced and every
//! other byte left intact. Active checks iterate the points and send prepared requests through
//! the engine, so a real `?id=5` is fuzzed in place rather than a parameter being appended.

/// How a request's body is structured, read from its Content-Type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyKind {
    /// `application/x-www-form-urlencoded`: `a=1&b=2`.
    Form,
    /// `application/json` (including GraphQL, whose variables are JSON).
    Json,
    /// Anything else: the body is not taken apart.
    Opaque,
}

/// What kind of place a point is, for its label and for dedup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointKind {
    Query,
    Form,
    Json,
    Cookie,
    Header,
}

/// Where in the request a point lives, enough to rebuild the request around a new value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Location {
    /// The nth `name=value` pair of the URL query string.
    Query(usize),
    /// The nth `name=value` pair of a form-encoded body.
    Form(usize),
    /// A JSON value at this pointer (RFC 6901), e.g. `/variables/id`.
    Json(String),
    /// The nth cookie in the `Cookie` request header.
    Cookie(usize),
    /// A whole request header value, by header name.
    Header(String),
}

/// One place a value can be substituted, with its display name and original value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertionPoint {
    pub kind: PointKind,
    /// The parameter, field, key, cookie or header name.
    pub name: String,
    /// The value that was there, decoded where that is meaningful.
    pub base_value: String,
    loc: Location,
}

impl InsertionPoint {
    /// A short phrase naming this point for a finding, e.g. `query parameter "id"`.
    pub fn label(&self) -> String {
        match self.kind {
            PointKind::Query => format!("query parameter \"{}\"", self.name),
            PointKind::Form => format!("form field \"{}\"", self.name),
            PointKind::Json => format!("JSON value {}", self.name),
            PointKind::Cookie => format!("cookie \"{}\"", self.name),
            PointKind::Header => format!("\"{}\" header", self.name),
        }
    }
}

/// One request built from a base request with a single point substituted, ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// A captured request an active check probes.
#[derive(Clone, Debug)]
pub struct BaseRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl BaseRequest {
    /// A simple GET of a URL, the shape the start-page audit uses.
    pub fn get(url: &str) -> Self {
        BaseRequest { method: "GET".into(), url: url.to_string(), headers: Vec::new(), body: String::new() }
    }

    /// What makes this request the same *endpoint* as another: its method, its path, and the
    /// names of its insertion points -- never their values. A crawl turns up the same endpoint
    /// under many values (`/s?q=hi`, `/s?q=there`), and auditing each of them repeats every
    /// probe for nothing, so the audit deduplicates on this. It mirrors `Form::signature`, so a
    /// form and a link to the same endpoint collapse together.
    pub fn signature(&self) -> String {
        let path = self.url.split(['?', '#']).next().unwrap_or(&self.url);
        let mut names: Vec<String> = self.points().into_iter().map(|p| p.name).collect();
        names.sort_unstable();
        format!("{} {} [{}]", self.method, path, names.join(","))
    }

    /// The body structure named by the Content-Type header.
    pub fn body_kind(&self) -> BodyKind {
        let ct = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        if ct.contains("application/json") || ct.contains("+json") {
            BodyKind::Json
        } else if ct.contains("application/x-www-form-urlencoded") {
            BodyKind::Form
        } else if self.body.is_empty() {
            BodyKind::Opaque
        } else {
            // A body with no (or an unknown) content type that still looks like a form is taken
            // as one, matching how the intruder marks bodies.
            let t = self.body.trim_start();
            if t.starts_with('{') || t.starts_with('[') {
                BodyKind::Json
            } else if self.body.contains('=') {
                BodyKind::Form
            } else {
                BodyKind::Opaque
            }
        }
    }

    /// Every insertion point in the request: query parameters, then body fields (form or JSON),
    /// then cookies. Individual request headers are not enumerated here; the checks that probe a
    /// header (added in a later phase) ask for it by name, since fuzzing every header is noise.
    pub fn points(&self) -> Vec<InsertionPoint> {
        let mut out = Vec::new();
        for (i, (name, raw)) in query_pairs(&self.url).into_iter().enumerate() {
            out.push(InsertionPoint {
                kind: PointKind::Query,
                name,
                base_value: crate::codec::url_decode(&raw),
                loc: Location::Query(i),
            });
        }
        match self.body_kind() {
            BodyKind::Form => {
                for (i, (name, raw)) in form_pairs(&self.body).into_iter().enumerate() {
                    out.push(InsertionPoint {
                        kind: PointKind::Form,
                        name,
                        base_value: crate::codec::url_decode(&raw),
                        loc: Location::Form(i),
                    });
                }
            }
            BodyKind::Json => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&self.body) {
                    for (ptr, val) in json_leaves(&v) {
                        out.push(InsertionPoint {
                            kind: PointKind::Json,
                            name: ptr.clone(),
                            base_value: val,
                            loc: Location::Json(ptr),
                        });
                    }
                }
            }
            BodyKind::Opaque => {}
        }
        for (i, (name, val)) in cookie_pairs(&self.headers).into_iter().enumerate() {
            out.push(InsertionPoint {
                kind: PointKind::Cookie,
                name,
                base_value: val,
                loc: Location::Cookie(i),
            });
        }
        out
    }

    /// A point on a named request header (present or not), for the checks that probe a header
    /// such as Host. The base value is the header's current value, or empty when it is absent.
    pub fn header_point(&self, name: &str) -> InsertionPoint {
        let base_value = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        InsertionPoint {
            kind: PointKind::Header,
            name: name.to_string(),
            base_value,
            loc: Location::Header(name.to_string()),
        }
    }

    /// Rebuild the request with `point`'s value replaced by `value`, every other byte unchanged.
    pub fn apply(&self, point: &InsertionPoint, value: &str) -> PreparedRequest {
        let mut req = PreparedRequest {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        };
        match &point.loc {
            Location::Query(i) => {
                req.url = rebuild_query(&self.url, *i, value);
            }
            Location::Form(i) => {
                req.body = rebuild_form(&self.body, *i, value);
                sync_len(&mut req);
            }
            Location::Json(ptr) => {
                if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&self.body) {
                    if let Some(slot) = v.pointer_mut(ptr) {
                        *slot = serde_json::Value::String(value.to_string());
                    }
                    req.body = v.to_string();
                    sync_len(&mut req);
                }
            }
            Location::Cookie(i) => {
                rebuild_cookie(&mut req.headers, *i, value);
            }
            Location::Header(name) => {
                set_header(&mut req.headers, name, value);
            }
        }
        req
    }
}

/// Set a request header to `value`, adding it when it is not already present.
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    for (k, v) in headers.iter_mut() {
        if k.eq_ignore_ascii_case(name) {
            *v = value.to_string();
            return;
        }
    }
    headers.push((name.to_string(), value.to_string()));
}

/// Keep a prepared request's Content-Length header, if it has one, matching its body.
fn sync_len(req: &mut PreparedRequest) {
    for (k, v) in req.headers.iter_mut() {
        if k.eq_ignore_ascii_case("content-length") {
            *v = req.body.len().to_string();
        }
    }
}

/// The `name=value` pairs of a URL's query string, values still percent-encoded. A pair with no
/// `=` is kept with an empty value so its position is preserved.
fn query_pairs(url: &str) -> Vec<(String, String)> {
    let Some((_, q)) = url.split_once('?') else { return Vec::new() };
    let q = q.split('#').next().unwrap_or(q);
    pairs(q)
}

/// The `name=value` pairs of a form-encoded body.
fn form_pairs(body: &str) -> Vec<(String, String)> {
    pairs(body)
}

fn pairs(s: &str) -> Vec<(String, String)> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (kv.to_string(), String::new()),
        })
        .collect()
}

/// Rebuild a URL's query string with the nth pair's value set to `value` (percent-encoded).
fn rebuild_query(url: &str, index: usize, value: &str) -> String {
    let (base, q) = match url.split_once('?') {
        Some((b, q)) => (b, q),
        None => return url.to_string(),
    };
    let (q, frag) = match q.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (q, None),
    };
    let mut parts = pairs(q);
    if let Some(slot) = parts.get_mut(index) {
        slot.1 = crate::codec::url_encode(value, false);
    }
    let rebuilt = parts
        .iter()
        .map(|(k, v)| if v.is_empty() && !k.is_empty() { k.clone() } else { format!("{k}={v}") })
        .collect::<Vec<_>>()
        .join("&");
    match frag {
        Some(f) => format!("{base}?{rebuilt}#{f}"),
        None => format!("{base}?{rebuilt}"),
    }
}

/// Rebuild a form body with the nth field's value set to `value` (percent-encoded).
fn rebuild_form(body: &str, index: usize, value: &str) -> String {
    let mut parts = pairs(body);
    if let Some(slot) = parts.get_mut(index) {
        slot.1 = crate::codec::url_encode(value, false);
    }
    parts
        .iter()
        .map(|(k, v)| if v.is_empty() && !k.is_empty() { k.clone() } else { format!("{k}={v}") })
        .collect::<Vec<_>>()
        .join("&")
}

/// The cookies carried in a `Cookie` request header, decoded, in order.
fn cookie_pairs(headers: &[(String, String)]) -> Vec<(String, String)> {
    let Some((_, v)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("cookie")) else {
        return Vec::new();
    };
    v.split(';')
        .filter_map(|c| {
            let c = c.trim();
            if c.is_empty() {
                return None;
            }
            match c.split_once('=') {
                Some((n, val)) => Some((n.trim().to_string(), val.to_string())),
                None => Some((c.to_string(), String::new())),
            }
        })
        .collect()
}

/// Rebuild the `Cookie` header with the nth cookie's value set to `value`.
fn rebuild_cookie(headers: &mut [(String, String)], index: usize, value: &str) {
    for (k, v) in headers.iter_mut() {
        if k.eq_ignore_ascii_case("cookie") {
            let mut cookies: Vec<(String, String)> = v
                .split(';')
                .map(|c| {
                    let lead: String = c.chars().take_while(|ch| ch.is_whitespace()).collect();
                    let body = c[lead.len()..].to_string();
                    (lead, body)
                })
                .collect();
            if let Some((lead, body)) = cookies.get_mut(index) {
                *body = match body.split_once('=') {
                    Some((n, _)) => format!("{n}={value}"),
                    None => format!("{body}={value}"),
                };
                let _ = lead;
            }
            *v = cookies.iter().map(|(lead, body)| format!("{lead}{body}")).collect::<Vec<_>>().join(";");
            return;
        }
    }
}

/// Every scalar leaf (string, number, bool) of a JSON value, as `(pointer, value-as-text)`.
/// Objects, arrays and null are walked but not themselves offered as points.
fn json_leaves(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    walk_json("", v, &mut out);
    out
}

fn walk_json(prefix: &str, v: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        serde_json::Value::Number(n) => out.push((prefix.to_string(), n.to_string())),
        serde_json::Value::Bool(b) => out.push((prefix.to_string(), b.to_string())),
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk_json(&format!("{prefix}/{i}"), item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let esc = k.replace('~', "~0").replace('/', "~1");
                walk_json(&format!("{prefix}/{esc}"), val, out);
            }
        }
        serde_json::Value::Null => {}
    }
}

/// A fresh, unmistakable marker for one scan: lower-case letters and digits with a short fixed
/// prefix, random so a page that happens to echo an unrelated literal cannot trip a check and
/// two scans running at once never collide. Not a secret; it only has to be unlikely.
pub fn nonce() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let tail: String = (0..9)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect();
    format!("fpz{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn names(points: &[InsertionPoint]) -> Vec<String> {
        points.iter().map(|p| format!("{:?}:{}", p.kind, p.name)).collect()
    }

    #[test]
    fn points_enumerate_query_form_json_and_cookies() {
        // query parameters
        let req = BaseRequest::get("https://a.test/search?q=hi&id=5");
        let pts = req.points();
        assert_eq!(names(&pts), ["Query:q", "Query:id"]);
        assert_eq!(pts[1].base_value, "5");
        assert_eq!(req.apply(&pts[1], "9' OR 1").url, "https://a.test/search?q=hi&id=9%27%20OR%201");

        // the fragment and the untouched parameter survive
        let req = BaseRequest::get("https://a.test/p?a=1&b=2#frag");
        let pts = req.points();
        assert_eq!(req.apply(&pts[0], "X").url, "https://a.test/p?a=X&b=2#frag");

        // form body
        let mut req = BaseRequest::get("https://a.test/login");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
        req.headers.push(("Content-Length".into(), "11".into()));
        req.body = "user=a&pw=b".into();
        let pts = req.points();
        assert_eq!(names(&pts), ["Form:user", "Form:pw"]);
        let prepared = req.apply(&pts[0], "x y");
        assert_eq!(prepared.body, "user=x%20y&pw=b");
        assert_eq!(prepared.headers.iter().find(|(k, _)| k == "Content-Length").unwrap().1, prepared.body.len().to_string());

        // json body, nested
        let mut req = BaseRequest::get("https://a.test/graphql");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), "application/json".into()));
        req.body = r#"{"variables":{"id":7,"name":"bob"},"ok":true}"#.into();
        let pts = req.points();
        assert_eq!(names(&pts), ["Json:/variables/id", "Json:/variables/name", "Json:/ok"]);
        let prepared = req.apply(&pts[1], "zz");
        let back: serde_json::Value = serde_json::from_str(&prepared.body).unwrap();
        assert_eq!(back["variables"]["name"], "zz");

        // cookies
        let mut req = BaseRequest::get("https://a.test/");
        req.headers.push(("Cookie".into(), "sid=abc; theme=dark".into()));
        let pts = req.points();
        assert_eq!(names(&pts), ["Cookie:sid", "Cookie:theme"]);
        let prepared = req.apply(&pts[0], "NEW");
        assert_eq!(prepared.headers.iter().find(|(k, _)| k == "Cookie").unwrap().1, "sid=NEW; theme=dark");
    }

    #[test]
    fn body_kind_matrix() {
        let cases = [
            ("explicit json", "application/json", "{}", BodyKind::Json),
            ("explicit form", "application/x-www-form-urlencoded", "a=1", BodyKind::Form),
            ("graphql +json", "application/graphql+json", "{}", BodyKind::Json),
            ("sniffed json", "", "{\"a\":1}", BodyKind::Json),
            ("sniffed form", "", "a=1&b=2", BodyKind::Form),
            ("opaque text", "text/plain", "hello", BodyKind::Opaque),
        ];
        assert_table!(cases, |(name, ct, body, want)| {
            let mut req = BaseRequest::get("https://a.test/");
            if !ct.is_empty() {
                req.headers.push(("Content-Type".into(), ct.to_string()));
            }
            req.body = body.to_string();
            assert_eq!(req.body_kind(), want, "{name}");
        });
    }

    #[test]
    fn a_nonce_is_fresh_and_well_formed() {
        let a = nonce();
        let b = nonce();
        assert_ne!(a, b, "two nonces differ");
        assert!(a.starts_with("fpz") && a.len() == 12);
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }
}
