//! Traffic export and clipboard interop: a recorded request as a `curl` command, and history
//! as HAR 1.2 or CSV. These are pure serializers over [`HttpEntry`]; the UI picks files (via
//! `rfd`) and copies text to the clipboard.

use crate::http::HttpEntry;

/// Headers a `curl` command (or HAR url) sets for itself, so repeating them is redundant or
/// wrong. `host` and `content-length` are already dropped by `parse_raw_request`.
const SKIP_HEADERS: &[&str] = &["content-length", "connection", "host", "accept-encoding"];

/// Wrap a string so a POSIX shell passes it through verbatim: single quotes, with any inner
/// single quote written as `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A recorded request as a runnable `curl` command. `target_origin` ("https://host:port")
/// supplies the scheme and authority when the request line carries only a path.
pub fn to_curl(raw_request: &str, target_origin: &str) -> String {
    let (method, path, headers, body) = crate::actions::parse_raw_request(raw_request);
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path
    } else {
        format!("{}{}", target_origin.trim_end_matches('/'), if path.is_empty() { "/" } else { &path })
    };
    let mut out = format!("curl -X {} {}", method, shell_quote(&url));
    for (k, v) in &headers {
        if SKIP_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)) {
            continue;
        }
        out.push_str(&format!(" \\\n  -H {}", shell_quote(&format!("{k}: {v}"))));
    }
    // let curl request and transparently decode compression itself (the dropped
    // Accept-Encoding header otherwise asks for bytes curl wouldn't decode)
    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding")) {
        out.push_str(" \\\n  --compressed");
    }
    if !body.is_empty() {
        out.push_str(&format!(" \\\n  --data-raw {}", shell_quote(&body)));
    }
    out
}

/// A millisecond Unix time as an ISO-8601 instant for HAR ("1970-01-01T00:00:00.000Z").
fn iso_8601(ms: u64) -> String {
    let base = crate::codec::format_unix_utc((ms / 1000) as i64); // "YYYY-MM-DD HH:MM:SS UTC"
    let date_time = base.trim_end_matches(" UTC").replacen(' ', "T", 1);
    format!("{date_time}.{:03}Z", ms % 1000)
}

/// Headers as HAR `[{ "name", "value" }]`.
fn har_headers(headers: &[(String, String)]) -> Vec<serde_json::Value> {
    headers.iter().map(|(k, v)| serde_json::json!({ "name": k, "value": v })).collect()
}

/// A byte allowed in an HTTP header field name (an RFC 7230 token character).
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A line of the form `Field-Name: value`, where the name is a valid header token (no spaces,
/// quotes or braces). Body lines such as `  "basePath": "/"` or `{"a":1}` do not qualify.
fn is_header_line(line: &str) -> bool {
    match line.split_once(':') {
        Some((name, _)) => !name.is_empty() && name.bytes().all(is_token_byte),
        None => false,
    }
}

/// Split a recorded response into (headers, body). Lines are split on `\n` (trailing `\r`
/// trimmed, so CRLF/LF/mixed all work). After the status line, consecutive `Field: value`
/// lines are headers; the first blank line, or the first line that is not a valid header,
/// ends the headers and everything from there on is the body.
///
/// The non-header stop matters because proxy-recorded responses (see `proxy.rs`) have their
/// blank separator trimmed away, so the body butts directly against the headers — without the
/// token check, body lines like `"basePath": "/"` would be mis-parsed as headers.
fn split_response(response: &str) -> (Vec<(String, String)>, String) {
    let lines: Vec<&str> = response.split('\n').collect();
    let mut headers = Vec::new();
    let mut body_start = lines.len(); // no body unless a boundary is found
    let mut i = 1; // skip the status line
    while i < lines.len() {
        let line = lines[i].trim_end_matches('\r');
        if line.is_empty() {
            body_start = i + 1; // body begins after the blank line
            break;
        }
        if is_header_line(line) {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            i += 1;
        } else {
            body_start = i; // this line is the first of the body
            break;
        }
    }
    let body = if body_start < lines.len() { lines[body_start..].join("\n") } else { String::new() };
    (headers, body)
}

/// History as a HAR 1.2 archive (pretty-printed JSON).
pub fn to_har(entries: &[HttpEntry]) -> Result<String, serde_json::Error> {
    let har_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let (method, _path, req_headers, req_body) = crate::actions::parse_raw_request(&e.request);
            let url = crate::actions::entry_url(e);
            // the status comes from the recorded status line ("200 OK"), not the response text
            let status: i32 = e.status.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(200);
            let status_text: String = e.status.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
            let (resp_headers, resp_body) = split_response(&e.response);
            // the stored body is lossy UTF-8; a replacement character marks bytes that were
            // binary, so flag the content as base64 per the HAR 1.2 spec rather than emitting
            // mojibake as plain text
            let binary = resp_body.contains('\u{FFFD}');
            let (content_text, content_encoding): (String, Option<&str>) = if binary {
                (crate::codec::base64_encode(resp_body.as_bytes(), false, true), Some("base64"))
            } else {
                (resp_body.clone(), None)
            };
            let mut content = serde_json::json!({
                "size": resp_body.len(),
                "mimeType": e.mime,
                "text": content_text,
            });
            if let Some(enc) = content_encoding {
                content["encoding"] = serde_json::json!(enc);
            }
            let mut request = serde_json::json!({
                "method": method,
                "url": url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": har_headers(&req_headers),
                "queryString": [],
                "headersSize": -1,
                "bodySize": req_body.len(),
            });
            if !req_body.is_empty() {
                let mime = req_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_default();
                request["postData"] = serde_json::json!({ "mimeType": mime, "text": req_body });
            }
            serde_json::json!({
                "startedDateTime": iso_8601(e.time),
                "time": 0,
                "request": request,
                "response": {
                    "status": status,
                    "statusText": status_text,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": har_headers(&resp_headers),
                    "content": content,
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": e.length,
                },
                "cache": {},
                "timings": { "send": 0, "wait": 0, "receive": 0 },
            })
        })
        .collect();
    let har = serde_json::json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "ForgeProxy", "version": env!("CARGO_PKG_VERSION") },
            "entries": har_entries,
        }
    });
    serde_json::to_string_pretty(&har)
}

/// Escape one CSV field per RFC 4180: wrap in quotes (doubling inner quotes) when it holds a
/// comma, quote, CR or LF.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// History as CSV: `#,Time,Method,URL,Status,Length,MIME,Note`. `Note` is always empty (history
/// rows carry no note), kept so the columns line up with the Organizer's export.
pub fn to_csv(entries: &[HttpEntry]) -> String {
    let mut out = String::from("#,Time,Method,URL,Status,Length,MIME,Note\r\n");
    for e in entries {
        let cells = [
            e.id.to_string(),
            crate::codec::format_unix_utc((e.time / 1000) as i64),
            e.method.clone(),
            crate::actions::entry_url(e),
            e.status.clone(),
            e.length.to_string(),
            e.mime.clone(),
            String::new(),
        ];
        let row: Vec<String> = cells.iter().map(|c| csv_field(c)).collect();
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: usize, method: &str, url: &str, status: &str) -> HttpEntry {
        let (host, path) = crate::http::split_url(url);
        HttpEntry {
            id,
            tool: "Proxy".into(),
            method: method.into(),
            host,
            path,
            status: status.into(),
            length: 0,
            mime: "text/html".into(),
            request: String::new(),
            response: String::new(),
            url: url.into(),
            truncated: false,
            time: 1_700_000_000_000,
        }
    }

    #[test]
    fn curl_get_is_minimal() {
        let raw = "GET /search?q=1 HTTP/1.1\nHost: example.com\nAccept: */*\n\n";
        let cmd = to_curl(raw, "https://example.com");
        assert!(cmd.starts_with("curl -X GET 'https://example.com/search?q=1'"), "{cmd}");
        assert!(cmd.contains("-H 'Accept: */*'"));
        assert!(!cmd.contains("--data-raw"), "a GET has no body: {cmd}");
        assert!(!cmd.contains("Host:"), "Host comes from the URL");
    }

    #[test]
    fn curl_post_has_body_and_headers() {
        let raw = "POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\nX-Token: abc\nContent-Length: 17\n\n{\"user\":\"root\"}";
        let cmd = to_curl(raw, "https://example.com");
        assert!(cmd.contains("-X POST"));
        assert!(cmd.contains("-H 'Content-Type: application/json'"));
        assert!(cmd.contains("-H 'X-Token: abc'"));
        assert!(cmd.contains("--data-raw '{\"user\":\"root\"}'"));
        assert!(!cmd.contains("Content-Length"), "curl sets Content-Length itself");
    }

    #[test]
    fn curl_accept_encoding_becomes_compressed() {
        let raw = "GET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, deflate, br\nAccept: */*\n\n";
        let cmd = to_curl(raw, "https://example.com");
        assert!(cmd.contains("--compressed"), "{cmd}");
        assert!(!cmd.contains("Accept-Encoding"), "the header is dropped in favour of --compressed: {cmd}");
        assert!(cmd.contains("-H 'Accept: */*'"), "other headers are kept: {cmd}");
    }

    #[test]
    fn curl_without_accept_encoding_has_no_compressed() {
        let raw = "GET /a HTTP/1.1\nHost: example.com\nAccept: */*\n\n";
        let cmd = to_curl(raw, "https://example.com");
        assert!(!cmd.contains("--compressed"), "{cmd}");
    }

    #[test]
    fn curl_escapes_single_quotes() {
        let raw = "POST / HTTP/1.1\nHost: a.test\n\nname=O'Brien";
        let cmd = to_curl(raw, "http://a.test");
        assert!(cmd.contains("--data-raw 'name=O'\\''Brien'"), "{cmd}");
    }

    #[test]
    fn har_is_valid_json_with_the_shape() {
        let mut e = entry(1, "GET", "https://example.com/a", "200 OK");
        e.request = "GET /a HTTP/1.1\nHost: example.com\nAccept: */*\n\n".into();
        e.response = "200 OK\nContent-Type: text/html\n\n<html></html>".into();
        e.length = 13;
        let json = to_har(&[e]).expect("HAR serializes");
        let v: serde_json::Value = serde_json::from_str(&json).expect("HAR parses");
        assert_eq!(v["log"]["version"], "1.2");
        assert_eq!(v["log"]["creator"]["name"], "ForgeProxy");
        let entry0 = &v["log"]["entries"][0];
        assert_eq!(entry0["request"]["method"], "GET");
        assert_eq!(entry0["request"]["url"], "https://example.com/a");
        assert_eq!(entry0["response"]["status"], 200);
        assert_eq!(entry0["response"]["statusText"], "OK");
        assert_eq!(entry0["response"]["content"]["text"], "<html></html>");
        assert!(entry0["startedDateTime"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn split_response_handles_every_line_ending() {
        let cases = [
            ("CRLF", "200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"),
            ("LF", "200 OK\nContent-Type: application/json\n\n{\"a\":1}"),
            ("mixed \\n\\r\\n", "200 OK\nContent-Type: application/json\n\r\n{\"a\":1}"),
            ("mixed \\r\\n\\n", "200 OK\r\nContent-Type: application/json\r\n\n{\"a\":1}"),
        ];
        for (name, raw) in cases {
            let (headers, body) = split_response(raw);
            assert_eq!(headers, vec![("Content-Type".to_string(), "application/json".to_string())], "{name}");
            assert_eq!(body, "{\"a\":1}", "{name}");
        }
    }

    #[test]
    fn split_response_keeps_multiline_json_with_colons() {
        let raw = "200 OK\r\nContent-Type: application/json\r\n\r\n{\n  \"user\": \"root\",\n  \"role\": \"admin\"\n}";
        let (headers, body) = split_response(raw);
        assert_eq!(headers.len(), 1, "colon lines in the body are not headers: {headers:?}");
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(body, "{\n  \"user\": \"root\",\n  \"role\": \"admin\"\n}");
    }

    #[test]
    fn split_response_stops_at_body_without_a_blank_line() {
        // a proxy-recorded response: the blank separator was trimmed, so the JSON body butts
        // directly against the headers (as for http://httpbin.org/spec.json)
        let raw = "200 OK\nserver: gunicorn\nconnection: close\n{\"basePath\": \"/\", \"host\": \"httpbin.org\"}";
        let (headers, body) = split_response(raw);
        assert_eq!(headers, vec![
            ("server".to_string(), "gunicorn".to_string()),
            ("connection".to_string(), "close".to_string()),
        ]);
        assert_eq!(body, "{\"basePath\": \"/\", \"host\": \"httpbin.org\"}");
    }

    #[test]
    fn har_base64_encodes_binary_body() {
        let mut e = entry(1, "GET", "https://example.com/img", "200 OK");
        e.mime = "image/png".into();
        // a replacement char marks bytes that were binary in the lossy-UTF-8 recording
        e.response = "200 OK\nContent-Type: image/png\n\nPNG\u{FFFD}\u{FFFD}data".into();
        let json = to_har(&[e]).expect("HAR serializes");
        let v: serde_json::Value = serde_json::from_str(&json).expect("HAR parses");
        let content = &v["log"]["entries"][0]["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        let body = "PNG\u{FFFD}\u{FFFD}data";
        assert_eq!(content["text"], crate::codec::base64_encode(body.as_bytes(), false, true));
        assert_eq!(content["size"], body.len());
    }

    #[test]
    fn har_text_body_has_no_encoding() {
        let mut e = entry(1, "GET", "https://example.com/a", "200 OK");
        e.response = "200 OK\nContent-Type: text/plain\n\nhello".into();
        let json = to_har(&[e]).expect("HAR serializes");
        let v: serde_json::Value = serde_json::from_str(&json).expect("HAR parses");
        let content = &v["log"]["entries"][0]["response"]["content"];
        assert_eq!(content["text"], "hello");
        assert!(content.get("encoding").is_none(), "plain text carries no encoding field");
    }

    #[test]
    fn split_response_without_a_blank_line_has_no_body() {
        let (headers, body) = split_response("200 OK\r\nContent-Type: text/html");
        assert_eq!(headers, vec![("Content-Type".to_string(), "text/html".to_string())]);
        assert!(body.is_empty());
    }

    #[test]
    fn har_status_from_entry_and_body_is_not_parsed_as_headers() {
        let mut e = entry(1, "GET", "https://example.com/a", "404 Not Found");
        e.request = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".into();
        // CRLF response whose body contains a colon line that must NOT become a header
        e.response = "404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\": \"missing: nope\"}".into();
        e.length = 24;
        let json = to_har(&[e]).expect("HAR serializes");
        let v: serde_json::Value = serde_json::from_str(&json).expect("HAR parses");
        let resp = &v["log"]["entries"][0]["response"];
        assert_eq!(resp["status"], 404);
        assert_eq!(resp["statusText"], "Not Found");
        assert_eq!(resp["content"]["text"], "{\"error\": \"missing: nope\"}");
        // exactly one header (Content-Type) — the body's "error"/"missing" lines are excluded
        let headers = resp["headers"].as_array().unwrap();
        assert_eq!(headers.len(), 1, "{headers:?}");
        assert_eq!(headers[0]["name"], "Content-Type");
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        let mut e = entry(1, "GET", "https://example.com/a?x=1,2", "200 \"OK\", really");
        e.mime = "text/plain".into();
        let csv = to_csv(&[e]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "#,Time,Method,URL,Status,Length,MIME,Note");
        // the URL (comma) and status (comma + quotes) are quoted; the quote is doubled
        assert!(lines[1].contains("\"https://example.com/a?x=1,2\""), "{}", lines[1]);
        assert!(lines[1].contains("\"200 \"\"OK\"\", really\""), "{}", lines[1]);
        // round-trips to 8 fields when parsed by a quote-aware reader
        assert!(lines[1].ends_with(",")); // empty trailing Note field
    }
}
