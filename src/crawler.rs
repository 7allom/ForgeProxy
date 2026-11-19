//! The smart crawler: it reads the HTML `<form>` elements on a page, fills each field with a
//! realistic, constraint-aware value (keeping hidden fields such as anti-CSRF tokens and view
//! state exactly as they were), and turns the form into a request the scanner can submit and
//! audit. Repeated forms are recognised by a signature so a crawl does not loop, and a
//! state-changing form with no anti-CSRF token is reported.

use crate::insertion::BaseRequest;
use crate::scan::{Confidence, Finding, CSRF_MISSING};

/// One field of a form, enough to synthesise a value and to keep hidden fields verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    /// Lower-cased input type (`text`, `email`, `password`, `hidden`, `number`, ...), or
    /// `select`/`textarea` for those elements.
    pub kind: String,
    /// The value the markup gave (kept verbatim for hidden fields; a seed for others).
    pub value: String,
    pub required: bool,
    pub min: Option<String>,
    pub max: Option<String>,
    /// For a `select`, the first non-empty option value.
    pub option: Option<String>,
}

/// A parsed HTML form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    /// Absolute action URL, resolved against the page.
    pub action: String,
    /// Upper-cased method, `GET` or `POST`.
    pub method: String,
    pub fields: Vec<Field>,
}

impl Form {
    /// A form carries a password field (a login or credential form).
    pub fn has_password(&self) -> bool {
        self.fields.iter().any(|f| f.kind == "password")
    }

    /// A stable signature so the same form on different pages is crawled once: method, action
    /// path (without query) and the sorted field names.
    pub fn signature(&self) -> String {
        let path = self.action.split(['?', '#']).next().unwrap_or(&self.action);
        let mut names: Vec<&str> = self.fields.iter().map(|f| f.name.as_str()).collect();
        names.sort_unstable();
        format!("{} {} [{}]", self.method, path, names.join(","))
    }

    /// Whether this form changes state (a POST), the kind an anti-CSRF token should protect.
    pub fn is_state_changing(&self) -> bool {
        self.method == "POST"
    }

    /// Whether a field looks like an anti-CSRF token (so a missing one is worth reporting).
    pub fn has_csrf_token(&self) -> bool {
        self.fields.iter().any(|f| {
            let n = f.name.to_ascii_lowercase();
            n.contains("csrf") || n.contains("xsrf") || n.contains("authenticity")
                || n.contains("requestverificationtoken") || n == "_token" || n.contains("nonce")
        })
    }
}

/// Synthesise a value for one field: realistic, honouring the obvious constraints, and leaving
/// hidden fields exactly as the markup had them.
fn fill(field: &Field) -> String {
    match field.kind.as_str() {
        "hidden" => field.value.clone(),
        "email" => "test.user@example.com".to_string(),
        // a value that satisfies the usual "upper, lower, digit, symbol, length" rules
        "password" => format!("Aa1!{}", crate::insertion::nonce()),
        "number" | "range" => field
            .min
            .clone()
            .or_else(|| field.max.clone())
            .unwrap_or_else(|| "1".to_string()),
        "tel" => "5551234567".to_string(),
        "url" => "https://example.com/".to_string(),
        "date" => "2020-01-01".to_string(),
        "month" => "2020-01".to_string(),
        "week" => "2020-W01".to_string(),
        "time" => "12:00".to_string(),
        "color" => "#336699".to_string(),
        "checkbox" | "radio" => {
            if field.value.is_empty() { "on".to_string() } else { field.value.clone() }
        }
        "select" => field.option.clone().unwrap_or_default(),
        _ => {
            if !field.value.is_empty() {
                field.value.clone()
            } else {
                "test".to_string()
            }
        }
    }
}

/// Turn a form into a request the scanner can submit: a GET carries the fields in the query, a
/// POST in a URL-encoded body. Submit buttons with no name are dropped; every other field is
/// filled.
pub fn to_request(form: &Form) -> BaseRequest {
    assemble(form, fill)
}

/// The field that most looks like the username box of a login form: a text or email field whose
/// name hints at an identity, else the first non-password text/email field.
fn username_field(form: &Form) -> Option<&str> {
    let is_texty = |f: &&Field| matches!(f.kind.as_str(), "text" | "email" | "tel") ;
    form.fields
        .iter()
        .filter(is_texty)
        .find(|f| {
            let n = f.name.to_ascii_lowercase();
            n.contains("user") || n.contains("email") || n.contains("login") || n.contains("name")
        })
        .or_else(|| form.fields.iter().find(is_texty))
        .map(|f| f.name.as_str())
}

/// A submission of a login form carrying the given credentials: the password field gets the
/// password, the best username field gets the username, and every other field (hidden tokens and
/// all) is filled as usual.
pub fn login_request(form: &Form, username: &str, password: &str) -> BaseRequest {
    let user = username_field(form).map(str::to_string);
    assemble(form, |f| {
        if f.kind == "password" {
            password.to_string()
        } else if user.as_deref() == Some(f.name.as_str()) {
            username.to_string()
        } else {
            fill(f)
        }
    })
}

/// Build a GET or POST request from a form, taking each named field's value from `value`.
fn assemble(form: &Form, mut value: impl FnMut(&Field) -> String) -> BaseRequest {
    let pairs: Vec<String> = form
        .fields
        .iter()
        .filter(|f| !f.name.is_empty())
        .map(|f| format!("{}={}", crate::codec::url_encode(&f.name, false), crate::codec::url_encode(&value(f), false)))
        .collect();
    let body = pairs.join("&");
    if form.method == "POST" {
        BaseRequest {
            method: "POST".into(),
            url: form.action.clone(),
            headers: vec![
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
                ("Content-Length".into(), body.len().to_string()),
            ],
            body,
        }
    } else {
        let sep = if form.action.contains('?') { '&' } else { '?' };
        let url = if body.is_empty() { form.action.clone() } else { format!("{}{sep}{body}", form.action) };
        BaseRequest::get(&url)
    }
}

/// A finding for a state-changing form that carries no anti-CSRF token.
pub fn csrf_finding(form: &Form, host: &str, path: &str) -> Option<Finding> {
    if form.is_state_changing() && !form.has_csrf_token() && !form.has_password() {
        let mut f = Finding::new(
            CSRF_MISSING,
            Confidence::Tentative,
            host,
            path,
            "A form that changes state (an HTTP POST) carried no anti-CSRF token field. Unless the \
             server protects it another way (such as a SameSite cookie checked on the server), another \
             site may be able to submit it on a logged-in user's behalf.",
        );
        f.point = "form without an anti-CSRF token".to_string();
        Some(f)
    } else {
        None
    }
}

/// Resolve a form action against the page URL, as [`crate::scan::extract_links`] resolves links.
fn resolve(base: &str, action: &str) -> String {
    let action = action.trim();
    if action.is_empty() {
        return base.to_string();
    }
    if action.starts_with("http://") || action.starts_with("https://") {
        return action.to_string();
    }
    let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
    let origin_end = base[scheme_end..].find('/').map(|i| i + scheme_end).unwrap_or(base.len());
    let origin = &base[..origin_end];
    if let Some(rest) = action.strip_prefix("//") {
        return format!("{}{}", &base[..scheme_end], rest);
    }
    if action.starts_with('/') {
        return format!("{origin}{action}");
    }
    let dir = match base.rfind('/') {
        Some(i) if i >= origin_end => &base[..=i],
        _ => "",
    };
    if dir.is_empty() { format!("{origin}/{action}") } else { format!("{dir}{action}") }
}

/// Every `<form>` on a page, with its action resolved and its fields read.
pub fn parse_forms(base_url: &str, html: &str) -> Vec<Form> {
    let low = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = low[i..].find("<form") {
        let start = i + rel;
        let end = low[start..].find("</form>").map(|e| start + e).unwrap_or(html.len());
        let form_html = &html[start..end];
        i = end + 1;

        let open_end = form_html.find('>').unwrap_or(form_html.len());
        let open_tag = &form_html[..open_end];
        let action = resolve(base_url, &tag_attr(open_tag, "action").unwrap_or_default());
        let method = tag_attr(open_tag, "method").unwrap_or_default().to_ascii_uppercase();
        let method = if method == "POST" { "POST".to_string() } else { "GET".to_string() };

        let fields = parse_fields(form_html);
        if !fields.is_empty() {
            out.push(Form { action, method, fields });
        }
    }
    out
}

fn parse_fields(form_html: &str) -> Vec<Field> {
    let low = form_html.to_ascii_lowercase();
    let mut fields = Vec::new();
    // <input ...> and <textarea ...>
    for tag_name in ["<input", "<textarea", "<select"] {
        let mut i = 0;
        while let Some(rel) = low[i..].find(tag_name) {
            let start = i + rel;
            let end = low[start..].find('>').map(|e| start + e + 1).unwrap_or(form_html.len());
            let tag = &form_html[start..end];
            i = end;
            let Some(name) = tag_attr(tag, "name") else { continue };
            if name.is_empty() {
                continue;
            }
            let kind = match tag_name {
                "<textarea" => "textarea".to_string(),
                "<select" => "select".to_string(),
                _ => tag_attr(tag, "type").unwrap_or_else(|| "text".to_string()).to_ascii_lowercase(),
            };
            if kind == "submit" || kind == "button" || kind == "reset" || kind == "image" || kind == "file" {
                continue;
            }
            let option = if tag_name == "<select" {
                // the first option value in the remaining form html after this select opens
                select_first_option(&form_html[start..])
            } else {
                None
            };
            fields.push(Field {
                name,
                kind,
                value: tag_attr(tag, "value").unwrap_or_default(),
                required: low[start..end.min(low.len())].contains("required"),
                min: tag_attr(tag, "min"),
                max: tag_attr(tag, "max"),
                option,
            });
        }
    }
    fields
}

/// The first non-empty option value of a `<select>` whose text starts at `s`.
fn select_first_option(s: &str) -> Option<String> {
    let low = s.to_ascii_lowercase();
    let close = low.find("</select>").unwrap_or(s.len());
    let inner = &s[..close];
    let low_inner = &low[..close];
    let mut i = 0;
    while let Some(rel) = low_inner[i..].find("<option") {
        let start = i + rel;
        let end = low_inner[start..].find('>').map(|e| start + e + 1).unwrap_or(inner.len());
        let tag = &inner[start..end];
        i = end;
        if let Some(v) = tag_attr(tag, "value") {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// The value of an attribute in a single tag's text, quoted or unquoted.
fn tag_attr(tag: &str, name: &str) -> Option<String> {
    let low = tag.to_ascii_lowercase();
    // match the attribute name at a word boundary (preceded by whitespace or the tag opener)
    let key = format!("{name}=");
    let mut from = 0;
    loop {
        let at = low[from..].find(&key)? + from;
        let before = tag[..at].chars().last();
        if at == 0 || before.is_some_and(|c| c.is_whitespace()) {
            let rest = &tag[at + key.len()..];
            let rest = rest.trim_start();
            let (quote, body) = match rest.chars().next() {
                Some(q @ ('"' | '\'')) => (Some(q), &rest[1..]),
                _ => (None, rest),
            };
            let stop = match quote {
                Some(q) => body.find(q).unwrap_or(body.len()),
                None => body.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(body.len()),
            };
            return Some(body[..stop].to_string());
        }
        from = at + key.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_login_form_and_keeps_hidden_fields() {
        let html = r#"
            <form action="/login" method="post">
              <input type="hidden" name="csrf" value="abc123">
              <input type="email" name="email" required>
              <input type="password" name="password">
              <input type="submit" value="Go">
            </form>"#;
        let forms = parse_forms("https://a.test/account", html);
        assert_eq!(forms.len(), 1);
        let form = &forms[0];
        assert_eq!(form.action, "https://a.test/login");
        assert_eq!(form.method, "POST");
        assert!(form.has_password());
        assert!(form.has_csrf_token());
        // submit button is dropped; the three real fields remain
        assert_eq!(form.fields.len(), 3);

        let req = to_request(form);
        assert_eq!(req.method, "POST");
        assert!(req.body.contains("csrf=abc123"), "hidden token kept verbatim: {}", req.body);
        assert!(req.body.contains("email=test.user%40example.com"), "email synthesised: {}", req.body);
        assert!(req.body.contains("password="), "password filled: {}", req.body);
    }

    #[test]
    fn get_form_values_go_in_the_query_and_constraints_are_honoured() {
        let html = r#"
            <form action="/search">
              <input type="text" name="q" value="seed">
              <input type="number" name="age" min="18" max="99">
              <select name="country"><option value="">pick</option><option value="GB">UK</option></select>
            </form>"#;
        let forms = parse_forms("https://a.test/", html);
        let req = to_request(&forms[0]);
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("q=seed"));
        assert!(req.url.contains("age=18"), "min honoured: {}", req.url);
        assert!(req.url.contains("country=GB"), "first non-empty option chosen: {}", req.url);
    }

    #[test]
    fn signature_is_stable_across_pages_and_csrf_is_flagged_when_missing() {
        let a = &parse_forms("https://a.test/p1", r#"<form action="/do" method="post"><input name="x"><input name="y"></form>"#)[0];
        let b = &parse_forms("https://a.test/p2", r#"<form action="/do" method="post"><input name="y"><input name="x"></form>"#)[0];
        assert_eq!(a.signature(), b.signature(), "same form, field order aside");

        assert!(csrf_finding(a, "a.test", "/do").is_some(), "a state-changing form with no token is flagged");
        let safe = &parse_forms("https://a.test/", r#"<form action="/do" method="post"><input type="hidden" name="csrf_token" value="t"><input name="x"></form>"#)[0];
        assert!(csrf_finding(safe, "a.test", "/do").is_none(), "a token silences it");
        let readonly = &parse_forms("https://a.test/", r#"<form action="/s" method="get"><input name="q"></form>"#)[0];
        assert!(csrf_finding(readonly, "a.test", "/s").is_none(), "a GET form is not state-changing");
    }

    #[test]
    fn login_request_places_the_credentials_in_the_right_fields() {
        let form = &parse_forms("https://a.test/", r#"<form action="/login" method="post"><input type="hidden" name="csrf" value="t"><input type="text" name="username"><input type="password" name="pass"></form>"#)[0];
        let req = login_request(form, "alice", "s3cret");
        assert!(req.body.contains("csrf=t"), "hidden kept: {}", req.body);
        assert!(req.body.contains("username=alice"), "username placed: {}", req.body);
        assert!(req.body.contains("pass=s3cret"), "password placed: {}", req.body);
    }
}
