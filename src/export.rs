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
                // how long the request took, which is 0 for an entry that was never timed
                "time": e.elapsed_ms,
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
                // the whole exchange is one span here: the tools time the send and the read
                // together, and splitting that into three made-up numbers would say more
                // than is known
                "timings": { "send": -1, "wait": e.elapsed_ms, "receive": -1 },
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
    use crate::test_utils::{assert_table, HttpFixture};

    fn entry(id: usize, method: &str, url: &str, status: &str) -> HttpEntry {
        let is_tls = url.starts_with("https://");
        let (host, path) = crate::http::split_url(url);
        let mut e = HttpFixture::get(host, path)
            .with_method(method)
            .with_tls(is_tls)
            .with_response(status, "")
            .into_history_entry(id, "Proxy");
        e.url = url.into();
        e.mime = "text/html".into();
        e.time = 1_700_000_000_000;
        e
    }

    #[test]
    fn curl_generation_matrix() {
        struct CurlCase {
            name: &'static str,
            raw_request: String,
            target_origin: &'static str,
            must_contain: Vec<&'static str>,
            must_not_contain: Vec<&'static str>,
        }

        let post_json_fixture = HttpFixture::post("example.com", "/api/login", "{\"user\":\"root\"}")
            .with_tls(true)
            .with_header("Content-Type", "application/json")
            .with_header("X-Token", "abc");

        let cases = [
            CurlCase {
                name: "minimal GET with query params omits --data-raw and Host header",
                raw_request: "GET /search?q=1 HTTP/1.1\nHost: example.com\nAccept: */*\n\n".into(),
                target_origin: "https://example.com",
                must_contain: vec![
                    "curl -X GET 'https://example.com/search?q=1'",
                    "-H 'Accept: */*'",
                ],
                must_not_contain: vec!["--data-raw", "Host:", "--compressed"],
            },
            CurlCase {
                name: "POST with JSON body and custom headers drops Content-Length",
                raw_request: post_json_fixture.raw_request(),
                target_origin: "https://example.com",
                must_contain: vec![
                    "-X POST 'https://example.com/api/login'",
                    "-H 'Content-Type: application/json'",
                    "-H 'X-Token: abc'",
                    "--data-raw '{\"user\":\"root\"}'",
                ],
                must_not_contain: vec!["Content-Length"],
            },
            CurlCase {
                name: "Accept-Encoding header is replaced with --compressed flag",
                raw_request: "GET /a HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, deflate, br\nAccept: */*\n\n".into(),
                target_origin: "https://example.com",
                must_contain: vec!["--compressed", "-H 'Accept: */*'"],
                must_not_contain: vec!["Accept-Encoding"],
            },
            CurlCase {
                name: "request without Accept-Encoding omits --compressed flag",
                raw_request: "GET /a HTTP/1.1\nHost: example.com\nAccept: */*\n\n".into(),
                target_origin: "https://example.com",
                must_contain: vec!["-H 'Accept: */*'"],
                must_not_contain: vec!["--compressed"],
            },
            CurlCase {
                name: "POSIX shell escaping for single quotes in form body",
                raw_request: "POST / HTTP/1.1\nHost: a.test\n\nname=O'Brien".into(),
                target_origin: "http://a.test",
                must_contain: vec!["--data-raw 'name=O'\\''Brien'"],
                must_not_contain: vec![],
            },
        ];

        assert_table!(cases, |case| {
            let cmd = to_curl(&case.raw_request, case.target_origin);
            for expected in &case.must_contain {
                assert!(cmd.contains(expected), "case '{}': expected {expected:?} in:\n{cmd}", case.name);
            }
            for forbidden in &case.must_not_contain {
                assert!(!cmd.contains(forbidden), "case '{}': unexpected {forbidden:?} in:\n{cmd}", case.name);
            }
        });
    }

    #[test]
    fn response_splitting_and_har_csv_export_matrix() {
        // 1. split_response matrix across line endings, multiline JSON, and missing blank lines
        let split_cases = [
            (
                "CRLF line endings",
                "200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}",
                vec![("Content-Type".to_string(), "application/json".to_string())],
                "{\"a\":1}",
            ),
            (
                "LF line endings",
                "200 OK\nContent-Type: application/json\n\n{\"a\":1}",
                vec![("Content-Type".to_string(), "application/json".to_string())],
                "{\"a\":1}",
            ),
            (
                "mixed \\n\\r\\n line endings",
                "200 OK\nContent-Type: application/json\n\r\n{\"a\":1}",
                vec![("Content-Type".to_string(), "application/json".to_string())],
                "{\"a\":1}",
            ),
            (
                "mixed \\r\\n\\n line endings",
                "200 OK\r\nContent-Type: application/json\r\n\n{\"a\":1}",
                vec![("Content-Type".to_string(), "application/json".to_string())],
                "{\"a\":1}",
            ),
            (
                "multiline JSON with colons is not mis-parsed as headers",
                "200 OK\r\nContent-Type: application/json\r\n\r\n{\n  \"user\": \"root\",\n  \"role\": \"admin\"\n}",
                vec![("Content-Type".to_string(), "application/json".to_string())],
                "{\n  \"user\": \"root\",\n  \"role\": \"admin\"\n}",
            ),
            (
                "proxy-trimmed response without blank separator stops at non-header JSON line",
                "200 OK\nserver: gunicorn\nconnection: close\n{\"basePath\": \"/\", \"host\": \"httpbin.org\"}",
                vec![
                    ("server".to_string(), "gunicorn".to_string()),
                    ("connection".to_string(), "close".to_string()),
                ],
                "{\"basePath\": \"/\", \"host\": \"httpbin.org\"}",
            ),
            (
                "header-only response without blank line has empty body",
                "200 OK\r\nContent-Type: text/html",
                vec![("Content-Type".to_string(), "text/html".to_string())],
                "",
            ),
        ];

        assert_table!(split_cases, |(name, raw, expected_headers, expected_body)| {
            let (headers, body) = split_response(raw);
            assert_eq!(headers, expected_headers, "{name}");
            assert_eq!(body, expected_body, "{name}");
        });

        // 2. HAR 1.2 serialization matrix (HTML text, binary base64, and 404 JSON body with colons)
        let mut html_entry = entry(1, "GET", "https://example.com/a", "200 OK");
        html_entry.request = "GET /a HTTP/1.1\nHost: example.com\nAccept: */*\n\n".into();
        html_entry.response = "200 OK\nContent-Type: text/html\n\n<html></html>".into();
        html_entry.length = 13;

        let mut bin_entry = entry(2, "GET", "https://example.com/img", "200 OK");
        bin_entry.mime = "image/png".into();
        bin_entry.response = "200 OK\nContent-Type: image/png\n\nPNG\u{FFFD}\u{FFFD}data".into();

        let mut json_404_entry = entry(3, "GET", "https://example.com/a", "404 Not Found");
        json_404_entry.request = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".into();
        json_404_entry.response = "404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\": \"missing: nope\"}".into();
        json_404_entry.length = 24;

        let har_json = to_har(&[html_entry, bin_entry, json_404_entry]).expect("HAR serializes");
        let v: serde_json::Value = serde_json::from_str(&har_json).expect("HAR parses");
        assert_eq!(v["log"]["version"], "1.2");
        assert_eq!(v["log"]["creator"]["name"], "ForgeProxy");

        let entries = v["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);

        // Entry 0: plain text HTML
        assert_eq!(entries[0]["request"]["method"], "GET");
        assert_eq!(entries[0]["request"]["url"], "https://example.com/a");
        assert_eq!(entries[0]["response"]["status"], 200);
        assert_eq!(entries[0]["response"]["statusText"], "OK");
        assert_eq!(entries[0]["response"]["content"]["text"], "<html></html>");
        assert!(entries[0]["response"]["content"].get("encoding").is_none());
        assert!(entries[0]["startedDateTime"].as_str().unwrap().contains('T'));

        // Entry 1: binary body with replacement char -> base64
        let bin_body = "PNG\u{FFFD}\u{FFFD}data";
        assert_eq!(entries[1]["response"]["content"]["encoding"], "base64");
        assert_eq!(
            entries[1]["response"]["content"]["text"],
            crate::codec::base64_encode(bin_body.as_bytes(), false, true)
        );
        assert_eq!(entries[1]["response"]["content"]["size"], bin_body.len());

        // Entry 2: 404 Not Found with colon in JSON body
        assert_eq!(entries[2]["response"]["status"], 404);
        assert_eq!(entries[2]["response"]["statusText"], "Not Found");
        assert_eq!(entries[2]["response"]["content"]["text"], "{\"error\": \"missing: nope\"}");
        let resp_headers = entries[2]["response"]["headers"].as_array().unwrap();
        assert_eq!(resp_headers.len(), 1);
        assert_eq!(resp_headers[0]["name"], "Content-Type");

        // 3. RFC 4180 CSV export escaping
        let mut csv_entry = entry(1, "GET", "https://example.com/a?x=1,2", "200 \"OK\", really");
        csv_entry.mime = "text/plain".into();
        let csv = to_csv(&[csv_entry]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "#,Time,Method,URL,Status,Length,MIME,Note");
        assert!(lines[1].contains("\"https://example.com/a?x=1,2\""), "{}", lines[1]);
        assert!(lines[1].contains("\"200 \"\"OK\"\", really\""), "{}", lines[1]);
        assert!(lines[1].ends_with(','));
    }
}
