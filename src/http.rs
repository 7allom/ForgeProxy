//! Shared HTTP history and a small blocking sender used by Repeater/Intruder.

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpEntry {
    pub id: usize,
    pub tool: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: String,
    pub length: usize,
    pub mime: String,
    pub request: String,
    pub response: String,
    /// Full address of the request (scheme, host, path).
    #[serde(default)]
    pub url: String,
    /// The response was too large to keep (over the proxy's 32 MiB buffer): it was streamed
    /// to the client, and `response` holds only its head and a note.
    #[serde(default)]
    pub truncated: bool,
    /// When it was recorded: Unix time in milliseconds (0 in projects saved before this).
    #[serde(default)]
    pub time: u64,
    /// How long the request took, from the moment it was sent to the last byte of the
    /// response, in milliseconds. 0 when it was not timed: entries recorded by a tunnel,
    /// and those read from a project saved before this was kept.
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// Now, as Unix time in milliseconds (an `HttpEntry::time`).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// User-Agent of requests the app builds itself (Repeater's default, "Send to Repeater"
/// from a site map path): "ForgeProxy/<crate version>".
pub const USER_AGENT: &str = concat!("ForgeProxy/", env!("CARGO_PKG_VERSION"));

/// Recorded status of a request whose connection failed (no HTTP response at all).
pub const CONNECTION_FAILED: &str = "— (connection failed)";

impl HttpEntry {
    /// The HTTP status code, or None when no response came back (connection or transport
    /// failure, or still pending). HTTPS tunnels count as 200: the proxy answered the
    /// CONNECT with "200 Connection established".
    pub fn status_code(&self) -> Option<u16> {
        let s = self.status.trim();
        // tunnels recorded by older versions (project files)
        if s == "Tunnel (encrypted)" {
            return Some(200);
        }
        status_code(s)
    }
}

/// The code a recorded status line starts with ("404 Not Found" -> 404), or `None` when the
/// line holds no response at all (an error note, or nothing yet). Shared with Intruder, whose
/// results carry the same status strings without being history entries.
pub fn status_code(status: &str) -> Option<u16> {
    let digits: String = status.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() == 3 { digits.parse().ok() } else { None }
}

/// What a raw request says about itself. A request held by Intercept is recorded from this
/// after the user has had their hands on it, so the history table, the site map and the entry's
/// URL show what was really sent rather than what first arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestFacts {
    pub method: String,
    /// The request target, reduced to its path and query: an absolute target
    /// (`GET http://host/p?q`, the form a browser sends a proxy) keeps only `/p?q`.
    pub path: String,
    /// The authority the request names: an absolute target's, else the Host header's. Empty
    /// when it names neither, which leaves the caller on the host it connected to.
    pub host: String,
}

/// Read a raw request's own account of itself, or `None` when its first line is not a request
/// line (no method and target). Header parsing stops at the blank line, so a Host written in
/// the body is not mistaken for the real one.
pub fn request_facts(raw: &str) -> Option<RequestFacts> {
    let head = raw.split("\r\n\r\n").next().and_then(|h| h.split("\n\n").next()).unwrap_or(raw);
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?;
    let host_header = lines
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_string())
        })
        .unwrap_or_default();
    // absolute form: the target's own authority is what the request is addressed to, and it
    // wins over a Host header that disagrees with it (RFC 9112 3.2.2)
    let absolute = target
        .split_once("://")
        .filter(|(s, _)| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
        .map(|(_, rest)| rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}"))));
    let (host, path) = match absolute {
        Some((authority, path)) => (authority.to_string(), path),
        None => (host_header, target.to_string()),
    };
    Some(RequestFacts { method, path, host })
}

/// An authority split into its host and port: `a.test:8080` is ("a.test", Some(8080)) and
/// `[::1]:443` is ("[::1]", Some(443)). A port is only read after the closing bracket of an
/// IPv6 literal, so `[::1]` keeps all of its colons.
pub fn split_authority(authority: &str) -> (&str, Option<u16>) {
    let after_brackets = authority.rsplit_once(']').map_or(authority, |(_, rest)| rest);
    match after_brackets.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (&authority[..authority.len() - port.len() - 1], port.parse().ok())
        }
        _ => (authority, None),
    }
}

/// `raw` with its `Content-Length` header set to the byte length of its body. A request
/// without that header, or without a body at all, is returned unchanged: the header is
/// corrected, never added, so a request that deliberately carries none keeps none.
pub fn sync_content_length(raw: String) -> String {
    let (sep, split_idx) = if let Some(idx) = raw.find("\r\n\r\n") {
        ("\r\n\r\n", idx)
    } else if let Some(idx) = raw.find("\n\n") {
        ("\n\n", idx)
    } else {
        return raw;
    };
    let head = &raw[..split_idx];
    let body = &raw[split_idx + sep.len()..];
    let has_cl = head.lines().skip(1).any(|l| {
        l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
    });
    if !has_cl {
        return raw;
    }
    let line_sep = if sep == "\r\n\r\n" { "\r\n" } else { "\n" };
    let updated_head: Vec<String> = head
        .split('\n')
        .enumerate()
        .map(|(i, raw_line)| {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if i > 0 {
                if let Some((k, _)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        return format!("{}: {}", k.trim(), body.len());
                    }
                }
            }
            line.to_string()
        })
        .collect();
    format!("{}{sep}{body}", updated_head.join(line_sep))
}

/// Recorded traffic. Entries are shared (`Arc`): the UI takes a snapshot each frame by
/// copying pointers, never request or response bodies.
pub type History = Arc<Mutex<Vec<Arc<HttpEntry>>>>;

/// The traffic store every tool records into -- Proxy, Repeater, Intruder, Scanner and
/// Sequencer -- with the ids it hands out and the switch that pauses recording. Workers are
/// given a clone of it and keep it for as long as they run.
#[derive(Clone)]
pub struct Recorder {
    pub history: History,
    /// Hands out entry ids, counting up for the life of the project.
    pub next_id: Arc<Mutex<usize>>,
    /// Logger's capture switch. While it is set nothing is recorded at all, and every tool
    /// goes on sending exactly as it was: pausing stops the record, not the work.
    pub paused: Arc<std::sync::atomic::AtomicBool>,
    /// How many entries the store keeps before the oldest are dropped.
    pub limit: usize,
}

impl Recorder {
    /// A store nothing else can reach, for a tool that is being tested on its own.
    #[cfg(test)]
    pub fn new(limit: usize) -> Self {
        Self {
            history: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(Mutex::new(0)),
            paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            limit,
        }
    }

    /// Is recording paused?
    pub fn paused(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record one request and whatever came back, if anything. The entry is built with the id
    /// it is given, so a paused store spends none, and the oldest entry is dropped once the
    /// store is full. Returns the id the entry was recorded under, or `None` when it was not
    /// recorded at all.
    pub fn record(&self, entry: impl FnOnce(usize) -> HttpEntry) -> Option<usize> {
        if self.paused() {
            return None;
        }
        let id = {
            let mut next = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
            *next += 1;
            *next
        };
        let mut kept = self.history.lock().unwrap_or_else(|e| e.into_inner());
        // a ring buffer by index: the oldest entries go first, and only once the store is
        // full, so an ordinary session never copies the whole of it
        if kept.len() >= self.limit {
            let over = kept.len() + 1 - self.limit;
            kept.drain(..over);
        }
        kept.push(Arc::new(entry(id)));
        Some(id)
    }
}

pub struct SendResult {
    /// The status line without its version -- "404 Not Found" -- which is the form the
    /// history table, the result rows and [`status_code`] all read.
    pub status: String,
    /// The version the response named itself by, as its status line spells it ("HTTP/1.1",
    /// "HTTP/1.0"). Empty when no response came back at all.
    pub version: String,
    pub body: String,
    /// The response's header block, one `name: value` line each, as the response is recorded
    /// rather than as it arrived: see [`SendResult::raw_response`] for what that means.
    pub headers: String,
    pub length: usize,
    pub mime: String,
    /// Set when no response came back (connection, TLS or timeout failure).
    pub error: Option<String>,
}

impl SendResult {
    /// The response as one message, which is how every tool records and shows it: the status
    /// line, the header block, a blank line, then the body.
    ///
    /// It is the response as it was read rather than byte for byte as it arrived. The body
    /// has been de-chunked, and unpacked if it was compressed, so the header block is made
    /// to agree with the body that follows it: a `transfer-encoding` that framed the body in
    /// chunks is gone, since there are no chunks left to frame, and a `content-length` that
    /// counts the body as it stands is there in its place. A message that says one thing and
    /// carries another cannot be read, replayed or compared with any confidence.
    ///
    /// A failed connection has no version and no headers, and its "body" is the note
    /// [`send`] leaves in place of a response.
    pub fn raw_response(&self) -> String {
        let mut head = if self.version.is_empty() {
            self.status.clone()
        } else {
            format!("{} {}", self.version, self.status)
        };
        // the header block keeps a newline after its last line; the blank line that ends the
        // head is added here, so the body starts on the line straight after it
        let headers = self.headers.trim_end_matches('\n');
        if !headers.is_empty() {
            head.push('\n');
            head.push_str(headers);
        }
        format!("{head}\n\n{}", self.body)
    }
}

/// Largest response body read (10 MiB, the same cap ureq's into_string uses).
pub const MAX_BODY: u64 = 10 * 1024 * 1024;

/// Most bytes any decompression may produce (32 MiB): a tiny compressed "bomb" can't make
/// the app allocate gigabytes.
pub const MAX_DECODED: u64 = 32 * 1024 * 1024;

/// Decompress `reader` into memory, refusing (None) output larger than `cap` bytes.
pub fn read_capped(reader: impl std::io::Read, cap: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    reader.take(cap + 1).read_to_end(&mut out).ok()?;
    (out.len() as u64 <= cap).then_some(out)
}

/// Decompress a gzip or deflate body; None for other encodings, a body that won't decode,
/// or one that would decompress to more than `MAX_DECODED` (the caller keeps it compressed).
pub fn unpack_body(encoding: &str, data: &[u8]) -> Option<Vec<u8>> {
    unpack_body_capped(encoding, data, MAX_DECODED)
}

fn unpack_body_capped(encoding: &str, data: &[u8], cap: u64) -> Option<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => read_capped(flate2::read::GzDecoder::new(data), cap),
        // "deflate" is meant to be zlib-wrapped, but some servers send raw deflate
        "deflate" => read_capped(flate2::read::ZlibDecoder::new(data), cap)
            .or_else(|| read_capped(flate2::read::DeflateDecoder::new(data), cap)),
        _ => None,
    }
}

/// How a tool's request is sent: its timeout, the upstream proxy and certificate checking.
#[derive(Clone, Debug, PartialEq)]
pub struct SendOptions {
    pub timeout: Duration,
    pub net: crate::upstream::NetConfig,
}

impl Default for SendOptions {
    fn default() -> Self {
        SendOptions { timeout: Duration::from_secs(15), net: Default::default() }
    }
}

/// The HTTP client for one request: HTTP/1.1 (the only version this client speaks),
/// redirects followed or not, the upstream proxy when one is on, and certificates checked
/// against Mozilla's roots or not checked at all. Err when the upstream proxy is on but
/// unusable (no address), so nothing goes out directly by mistake.
pub fn agent(follow_redirects: bool, opts: &SendOptions) -> Result<ureq::Agent, String> {
    let mut b = ureq::AgentBuilder::new()
        .timeout(opts.timeout)
        .redirects(if follow_redirects { 5 } else { 0 });
    if !opts.net.verify_tls {
        b = b.tls_config(crate::upstream::insecure_client_config());
    }
    if let Some(route) = opts.net.upstream.route()? {
        b = b.proxy(crate::upstream::ureq_proxy(&route)?);
    }
    Ok(b.build())
}

/// Perform a blocking HTTP request. Returns a human-readable result even on error.
/// `follow_redirects = false` matches Repeater's `follow_redirections = never`.
/// `unpack`: decompress gzip/deflate response bodies (Content-Encoding) before returning them.
pub fn send(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    follow_redirects: bool,
    unpack: bool,
    opts: &SendOptions,
) -> SendResult {
    let agent = match agent(follow_redirects, opts) {
        Ok(a) => a,
        Err(e) => return SendResult {
            status: "— (transport error)".into(),
            version: String::new(),
            body: format!("Request not sent: {e}"),
            headers: String::new(),
            length: 0,
            mime: String::new(),
            error: Some(e),
        },
    };
    let mut req = agent.request(method, url);
    for (k, v) in headers {
        if !k.trim().is_empty() {
            req = req.set(k.trim(), v.trim());
        }
    }
    let resp = if body.is_empty() {
        req.call()
    } else {
        req.send_string(body)
    };
    match resp {
        Ok(r) | Err(ureq::Error::Status(_, r)) => {
            let status = format!("{} {}", r.status(), r.status_text());
            let version = r.http_version().to_string();
            let mime = r.content_type().to_string();
            // The header block as the response is recorded. A `transfer-encoding` that framed
            // the body in chunks is left out: the body is read whole and de-chunked below, so
            // there are no chunks left for it to describe, and a reader told to expect them
            // would look for a length in front of the body and find none. Any other
            // `transfer-encoding` is kept -- it says something about the body that is still
            // true. Header names arrive from the client lowercased, so they compare as they
            // are and the block reads in one case throughout.
            let mut hdr = String::new();
            let mut has_length = false;
            for name in r.headers_names() {
                let Some(v) = r.header(&name) else { continue };
                if name == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                    continue;
                }
                has_length |= name == "content-length";
                hdr.push_str(&format!("{name}: {v}\n"));
            }
            let encoding = r.header("content-encoding").unwrap_or("").trim().to_ascii_lowercase();
            let mut raw = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::Read::take(r.into_reader(), MAX_BODY), &mut raw);
            if unpack {
                if let Some(plain) = unpack_body(&encoding, &raw) {
                    raw = plain;
                }
            }
            let text = String::from_utf8_lossy(&raw).into_owned();
            let length = raw.len();
            if !has_length {
                // the body as this message carries it, which is the text above: bytes that
                // were not UTF-8 stand in it as the replacement character, while `length`
                // keeps the count of what actually came off the wire
                hdr.push_str(&format!("content-length: {}\n", text.len()));
            }
            SendResult { status, version, body: text, headers: hdr, length, mime, error: None }
        }
        Err(e) => SendResult {
            status: "— (transport error)".into(),
            version: String::new(),
            body: format!("Request failed: {e}"),
            headers: String::new(),
            length: 0,
            mime: String::new(),
            error: Some(e.to_string()),
        },
    }
}

/// Split a URL into (host, path) for the history table.
pub fn split_url(url: &str) -> (String, String) {
    let rest = url.split("://").nth(1).unwrap_or(url);
    match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_table, HttpFixture};
    use std::io::Write;

    /// What a request held by Intercept says about itself once the user has edited it. The
    /// method, path and host recorded in history all come from here, so a tampered request
    /// line or Host header has to come back out intact.
    #[test]
    fn a_request_describes_itself_matrix() {
        let cases: [(&str, &str, Option<(&str, &str, &str)>); 10] = [
            ("origin form with a Host header",
                "GET /cart?id=2 HTTP/1.1\nHost: shop.test\nAccept: */*\n\n", Some(("GET", "/cart?id=2", "shop.test"))),
            ("an edited method and path",
                "DELETE /admin/users/7 HTTP/1.1\nHost: shop.test\n\n", Some(("DELETE", "/admin/users/7", "shop.test"))),
            ("an edited Host header",
                "GET / HTTP/1.1\nHost: internal.test:8080\n\n", Some(("GET", "/", "internal.test:8080"))),
            ("CRLF line endings",
                "POST /pay HTTP/1.1\r\nHost: shop.test\r\n\r\namount=1", Some(("POST", "/pay", "shop.test"))),
            // the form a browser sends a proxy: its own authority is what the request is for
            ("absolute form outranks the Host header",
                "GET http://real.test/a?b=1 HTTP/1.1\nHost: stale.test\n\n", Some(("GET", "/a?b=1", "real.test"))),
            ("absolute form with no path at all",
                "GET https://real.test HTTP/1.1\n\n", Some(("GET", "/", "real.test"))),
            ("no Host header leaves the host to the caller",
                "GET /x HTTP/1.0\n\n", Some(("GET", "/x", ""))),
            // a Host line below the blank line is body text, not a header
            ("a Host written in the body is not a header",
                "POST /echo HTTP/1.1\nHost: shop.test\n\nHost: body.test\n", Some(("POST", "/echo", "shop.test"))),
            ("a first line with no target is not a request line", "GET\nHost: shop.test\n\n", None),
            ("and neither is an empty buffer", "", None),
        ];
        assert_table!(cases, |idx, (what, raw, want)| {
            let got = request_facts(raw);
            let want = want.map(|(method, path, host)| RequestFacts {
                method: method.into(), path: path.into(), host: host.into(),
            });
            assert_eq!(got, want, "case #{idx} ({what})");
        });
    }

    #[test]
    fn an_authority_splits_into_host_and_port_matrix() {
        let cases: [(&str, &str, (&str, Option<u16>)); 6] = [
            ("a bare name", "shop.test", ("shop.test", None)),
            ("a name and a port", "shop.test:8080", ("shop.test", Some(8080))),
            ("an IPv4 address and a port", "127.0.0.1:3000", ("127.0.0.1", Some(3000))),
            ("an IPv6 literal keeps its colons", "[::1]", ("[::1]", None)),
            ("an IPv6 literal with a port", "[::1]:443", ("[::1]", Some(443))),
            ("something that is not a port is part of the host", "shop.test:api", ("shop.test:api", None)),
        ];
        assert_table!(cases, |idx, (what, authority, want)| {
            assert_eq!(split_authority(authority), want, "case #{idx} ({what})");
        });
    }

    /// An edited body leaves the recorded request's own Content-Length stale, which is what
    /// this corrects. The header is only ever corrected, never added or removed.
    #[test]
    fn content_length_follows_an_edited_body_matrix() {
        let cases: [(&str, &str, &str); 5] = [
            ("a body edited longer", "POST /p HTTP/1.1\nContent-Length: 2\n\nhello", "POST /p HTTP/1.1\nContent-Length: 5\n\nhello"),
            ("a body edited away", "POST /p HTTP/1.1\nContent-Length: 9\n\n", "POST /p HTTP/1.1\nContent-Length: 0\n\n"),
            ("CRLF endings are kept", "POST /p HTTP/1.1\r\nContent-Length: 1\r\n\r\nabc", "POST /p HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"),
            ("a request with no such header gains none", "GET /p HTTP/1.1\nHost: a\n\n", "GET /p HTTP/1.1\nHost: a\n\n"),
            ("a request with no body at all is left alone", "GET /p HTTP/1.1\nContent-Length: 4", "GET /p HTTP/1.1\nContent-Length: 4"),
        ];
        assert_table!(cases, |idx, (what, raw, want)| {
            assert_eq!(sync_content_length(raw.to_string()), want, "case #{idx} ({what})");
        });
    }

    #[test]
    fn request_response_parsing_matrix() {
        // 1. Raw HTTP request parsing across HTTP/1.0 and HTTP/1.1
        let req_cases: [(&str, &str, &str, &str, Vec<(&str, &str)>, &str); 4] = [
            (
                "HTTP/1.1 GET with headers and empty body",
                "GET /v1/items?limit=10 HTTP/1.1\nHost: api.example.com\nAccept: application/json\n\n",
                "GET",
                "/v1/items?limit=10",
                vec![("Accept", "application/json")],
                "",
            ),
            (
                "HTTP/1.0 POST with form body and Content-Length stripped from extra headers",
                "POST /submit HTTP/1.0\nHost: legacy.example.com\nContent-Type: text/plain\nContent-Length: 9\n\nuser=root",
                "POST",
                "/submit",
                vec![("Content-Type", "text/plain")],
                "user=root",
            ),
            (
                "HTTP/1.1 PUT with custom headers and JSON body",
                "PUT /items/42 HTTP/1.1\nHost: internal.corp:8080\nX-Trace: abc\nX-Mode: fast\n\n{\"ok\":true}",
                "PUT",
                "/items/42",
                vec![("X-Trace", "abc"), ("X-Mode", "fast")],
                "{\"ok\":true}",
            ),
            (
                "request without blank line separator treats entire input as head",
                "DELETE /session HTTP/1.1\nX-Token: t1",
                "DELETE",
                "/session",
                vec![("X-Token", "t1")],
                "",
            ),
        ];

        assert_table!(req_cases, |idx, (name, raw, exp_method, exp_path, exp_headers, exp_body)| {
            let (method, path, headers, body) = crate::actions::parse_raw_request(raw);
            assert_eq!(method, exp_method, "req case #{idx} ({name}) method");
            assert_eq!(path, exp_path, "req case #{idx} ({name}) path");
            let exp_h: Vec<(String, String)> = exp_headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            assert_eq!(headers, exp_h, "req case #{idx} ({name}) headers");
            assert_eq!(body, exp_body, "req case #{idx} ({name}) body");
        });

        // 2. Raw HTTP response parsing across HTTP/1.0 and HTTP/1.1 (CRLF and LF)
        let resp_cases: [(&str, &[u8], &str, Option<u16>, Vec<(&str, &str)>, &[u8]); 4] = [
            (
                "HTTP/1.1 200 OK with CRLF line endings",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Id: 7\r\n\r\nhello world",
                "HTTP/1.1 200 OK",
                Some(200),
                vec![("Content-Type", "text/plain"), ("X-Id", "7")],
                b"hello world",
            ),
            (
                "HTTP/1.0 302 Found with LF line endings",
                b"HTTP/1.0 302 Found\nLocation: /login\n\nredirecting",
                "HTTP/1.0 302 Found",
                Some(302),
                vec![("Location", "/login")],
                b"redirecting",
            ),
            (
                "HTTP/1.1 204 No Content with empty body",
                b"HTTP/1.1 204 No Content\r\nServer: edge\r\n\r\n",
                "HTTP/1.1 204 No Content",
                Some(204),
                vec![("Server", "edge")],
                b"",
            ),
            (
                "Legacy tunnel status string maps to status_code 200",
                b"Tunnel (encrypted)\r\n\r\n",
                "Tunnel (encrypted)",
                Some(200),
                vec![],
                b"",
            ),
        ];

        assert_table!(resp_cases, |idx, (name, raw, exp_status_line, exp_code, exp_headers, exp_body)| {
            let parsed = crate::codec::HttpResponse::parse(raw);
            assert_eq!(parsed.status_line, exp_status_line, "resp case #{idx} ({name}) status_line");
            let exp_h: Vec<(String, String)> = exp_headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            assert_eq!(parsed.headers, exp_h, "resp case #{idx} ({name}) headers");
            assert_eq!(parsed.body, exp_body, "resp case #{idx} ({name}) body");

            let mut entry = HttpFixture::get("example.com", "/").into_history_entry(idx + 1, "Proxy");
            entry.status = exp_status_line.strip_prefix("HTTP/1.1 ").or_else(|| exp_status_line.strip_prefix("HTTP/1.0 ")).unwrap_or(exp_status_line).to_string();
            assert_eq!(entry.status_code(), exp_code, "resp case #{idx} ({name}) status_code");
        });

        // 3. URL splitting & Content-Encoding decompression table
        let url_cases = [
            ("https://example.com/a/b?c=1", ("example.com", "/a/b?c=1")),
            ("http://127.0.0.1:8080", ("127.0.0.1:8080", "/")),
            ("bare.host/path", ("bare.host", "/path")),
        ];
        assert_table!(url_cases, |idx, (url, (exp_host, exp_path))| {
            assert_eq!(split_url(url), (exp_host.to_string(), exp_path.to_string()), "url case #{idx}");
        });

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello gzip").unwrap();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"hello zlib").unwrap();
        let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(b"raw deflate").unwrap();

        let unpack_cases: Vec<(&str, &str, Vec<u8>, Option<&[u8]>)> = vec![
            ("gzip stream", "gzip", gz.finish().unwrap(), Some(b"hello gzip")),
            ("x-gzip stream", "x-gzip", {
                let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                g.write_all(b"x-gzip").unwrap();
                g.finish().unwrap()
            }, Some(b"x-gzip")),
            ("zlib-wrapped deflate", "deflate", z.finish().unwrap(), Some(b"hello zlib")),
            ("raw deflate stream", "deflate", d.finish().unwrap(), Some(b"raw deflate")),
            ("unsupported br encoding", "br", b"x".to_vec(), None),
            ("corrupt gzip bytes", "gzip", b"not gzip".to_vec(), None),
        ];
        assert_table!(unpack_cases, |idx, (name, enc, data, expected)| {
            assert_eq!(unpack_body(enc, &data).as_deref(), expected, "unpack case #{idx} ({name})");
        });

        assert_eq!(super::USER_AGENT, format!("ForgeProxy/{}", env!("CARGO_PKG_VERSION")));
        assert!(crate::state::DEFAULT_REP_REQUEST.contains(&format!("\nUser-Agent: {}\n", super::USER_AGENT)));
    }

    fn gzip_of_zeros(n: usize) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = vec![0u8; 1 << 20];
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len());
            gz.write_all(&chunk[..k]).unwrap();
            left -= k;
        }
        gz.finish().unwrap()
    }

    #[test]
    fn edge_cases_and_malformed_inputs_matrix() {
        // 1. Malformed start lines, missing headers, CRLF vs LF, and status_code edge cases
        let malformed_cases: [(&str, &[u8], &str, usize, &[u8], Option<u16>); 6] = [
            ("empty byte slice", b"", "", 0, b"", None),
            ("start line only without CRLF", b"GET /only", "GET /only", 0, b"", None),
            ("header line without colon is ignored", b"HTTP/1.1 200 OK\r\nMalformedHeaderLine\r\nX-Ok: 1\r\n\r\nhi", "HTTP/1.1 200 OK", 1, b"hi", Some(200)),
            ("mixed LF blank line with colons in JSON body", b"HTTP/1.1 400 Bad Request\nContent-Type: application/json\n\n{\"err\":\"bad:colon\"}", "HTTP/1.1 400 Bad Request", 1, b"{\"err\":\"bad:colon\"}", Some(400)),
            ("connection failed status has no numeric status code", b"\xE2\x80\x94 (connection failed)\r\n\r\n", "— (connection failed)", 0, b"", None),
            ("2-digit number is not a valid 3-digit HTTP status code", b"99 Invalid\r\n\r\n", "99 Invalid", 0, b"", None),
        ];

        assert_table!(malformed_cases, |idx, (name, raw, exp_status_line, exp_hdr_count, exp_body, exp_code)| {
            let parsed = crate::codec::HttpResponse::parse(raw);
            assert_eq!(parsed.status_line, exp_status_line, "case #{idx} ({name}) status_line");
            assert_eq!(parsed.headers.len(), exp_hdr_count, "case #{idx} ({name}) header count");
            assert_eq!(parsed.body, exp_body, "case #{idx} ({name}) body");
            let mut e = HttpFixture::get("h.test", "/").into_history_entry(1, "Proxy");
            e.status = exp_status_line.strip_prefix("HTTP/1.1 ").unwrap_or(exp_status_line).to_string();
            assert_eq!(e.status_code(), exp_code, "case #{idx} ({name}) status_code");
        });

        // 2. Decompression ceiling boundary matrix
        let small = gzip_of_zeros(1000);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&[7u8; 5000]).unwrap();
        let z_bytes = z.finish().unwrap();
        let bomb = gzip_of_zeros(MAX_DECODED as usize + 1024 * 1024);
        assert!(bomb.len() < 200 * 1024);
        let legit_4mb = gzip_of_zeros(4 * 1024 * 1024);

        let cap_cases: [(&str, &str, &[u8], u64, Option<usize>); 5] = [
            ("gzip exact cap (1000 == 1000) succeeds", "gzip", &small, 1000, Some(1000)),
            ("gzip 1 byte over cap (1000 > 999) refused", "gzip", &small, 999, None),
            ("deflate 1 byte over cap (5000 > 4999) refused on both zlib and raw paths", "deflate", &z_bytes, 4999, None),
            ("33 MiB gzip bomb over MAX_DECODED refused", "gzip", &bomb, MAX_DECODED, None),
            ("4 MiB gzip payload under MAX_DECODED unpacks", "gzip", &legit_4mb, MAX_DECODED, Some(4 * 1024 * 1024)),
        ];
        assert_table!(cap_cases, |idx, (name, enc, data, cap, expected_len)| {
            assert_eq!(unpack_body_capped(enc, data, cap).map(|v| v.len()), expected_len, "cap case #{idx} ({name})");
        });
    }

    #[test]
    fn header_manipulation_matrix() {
        // Case-insensitive lookup, insertion, update, and removal preserving raw header order
        let raw_resp = b"HTTP/1.1 200 OK\r\nX-First: 1\r\nContent-Type: text/html; charset=utf-8\r\nX-Last: 9\r\n\r\nbody";
        let res = crate::codec::HttpResponse::parse(raw_resp);

        let lookup_cases = [
            ("exact case match", "Content-Type", Some("text/html; charset=utf-8")),
            ("lowercase match", "content-type", Some("text/html; charset=utf-8")),
            ("uppercase match", "X-FIRST", Some("1")),
            ("missing header", "X-Missing", None),
        ];
        assert_table!(lookup_cases, |idx, (name, key, expected)| {
            assert_eq!(res.header(key), expected, "lookup case #{idx} ({name})");
        });

        // Host header insertion, update, and order preservation
        let host_cases: [(&str, &str, &str, &str); 3] = [
            (
                "updates existing Host header in-place preserving order and body",
                "GET / HTTP/1.1\nAccept: */*\nHost: old.test:8080\nX-After: 1\n\nhost: body",
                "new.test:9000",
                "GET / HTTP/1.1\nAccept: */*\nHost: new.test:9000\nX-After: 1\n\nhost: body",
            ),
            (
                "inserts Host header immediately after request line when absent (CRLF kept)",
                "GET / HTTP/1.1\r\nAccept: */*\r\nX-After: 1\r\n\r\n",
                "added.test",
                "GET / HTTP/1.1\r\nHost: added.test\r\nAccept: */*\r\nX-After: 1\r\n\r\n",
            ),
            (
                "replaces only the first Host header when multiple exist",
                "GET / HTTP/1.1\nHost: first.test\nX-Mid: 1\n\n",
                "updated.test",
                "GET / HTTP/1.1\nHost: updated.test\nX-Mid: 1\n\n",
            ),
        ];
        assert_table!(host_cases, |idx, (name, raw, new_host, expected)| {
            let updated = crate::actions::set_host_header(raw, new_host);
            assert_eq!(updated, expected, "host case #{idx} ({name})");
            assert_eq!(crate::actions::host_header(&updated).as_deref(), Some(new_host), "host case #{idx} ({name}) readback");
        });
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use crate::test_utils::assert_table;
    use crate::upstream::{mock, NetConfig, UpstreamProxyConfig, UpstreamProxyType};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Plain HTTP server: records each request line, answers "ok".
    fn http_server() -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                let _ = r.read_line(&mut first);
                let mut line = String::new();
                while r.read_line(&mut line).is_ok_and(|n| n > 2) { line.clear(); }
                seen.lock().unwrap().push(first.trim_end().to_string());
                let mut s = s;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
        });
        (port, lines)
    }

    /// HTTPS server with a certificate from a CA nobody trusts; answers "secure".
    fn untrusted_https_server() -> u16 {
        let ca = Arc::new(crate::ca::CertificateAuthority::generate().unwrap());
        let cfg = crate::ca::TlsConfigCache::new(ca).get_server_config("127.0.0.1").unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let Ok(conn) = rustls::ServerConnection::new(cfg.clone()) else { continue };
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut r = BufReader::new(&mut tls);
                let mut line = String::new();
                while r.read_line(&mut line).is_ok_and(|n| n > 2) { line.clear(); }
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure");
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        port
    }

    fn opts(verify_tls: bool, upstream: UpstreamProxyConfig) -> SendOptions {
        SendOptions { timeout: Duration::from_secs(5), net: NetConfig { upstream, verify_tls } }
    }

    fn proxy(kind: UpstreamProxyType, port: u16) -> UpstreamProxyConfig {
        UpstreamProxyConfig { enabled: true, proxy_type: kind, host: "127.0.0.1".into(), port }
    }

    #[test]
    fn requests_are_http_1_1() {
        let (port, lines) = http_server();
        let r = send("GET", &format!("http://127.0.0.1:{port}/v"), &[], "", false, false, &opts(true, Default::default()));
        assert_eq!((r.status.as_str(), r.body.as_str()), ("200 OK", "ok"));
        assert_eq!(*lines.lock().unwrap(), ["GET /v HTTP/1.1"]);
    }

    #[test]
    fn certificate_checking_switch() {
        let port = untrusted_https_server();
        let url = format!("https://127.0.0.1:{port}/");
        let off = send("GET", &url, &[], "", false, false, &opts(false, Default::default()));
        assert_eq!((off.error, off.body.as_str()), (None, "secure"), "off: any certificate is accepted");
        let on = send("GET", &url, &[], "", false, false, &opts(true, Default::default()));
        let err = on.error.expect("on: an untrusted certificate is refused");
        assert!(err.to_lowercase().contains("certificate") || err.to_lowercase().contains("issuer"), "{err}");
    }

    #[test]
    fn requests_go_through_an_http_connect_proxy() {
        let (port, lines) = http_server();
        let (pp, targets) = mock::http_proxy();
        let r = send("GET", &format!("http://127.0.0.1:{port}/via"), &[], "", false, false, &opts(true, proxy(UpstreamProxyType::HttpConnect, pp)));
        assert_eq!(r.body, "ok", "{:?} {} {:?}", r.error, r.status, targets.lock().unwrap());
        // plain HTTP is forwarded to the proxy with an absolute URL (no CONNECT)
        assert_eq!(*targets.lock().unwrap(), [format!("http://127.0.0.1:{port}/via")]);
        assert_eq!(*lines.lock().unwrap(), ["GET /via HTTP/1.1"]);
        // and HTTPS (with checking off: the test server's certificate isn't trusted)
        let tls = untrusted_https_server();
        let r = send("GET", &format!("https://127.0.0.1:{tls}/"), &[], "", false, false, &opts(false, proxy(UpstreamProxyType::HttpConnect, pp)));
        assert_eq!(r.body, "secure", "{:?}", r.error);
        assert_eq!(targets.lock().unwrap().last().unwrap(), &format!("127.0.0.1:{tls}"));
    }

    #[test]
    fn requests_go_through_a_socks5_proxy() {
        let (port, lines) = http_server();
        let (pp, targets) = mock::socks5_proxy();
        let r = send("GET", &format!("http://127.0.0.1:{port}/socks"), &[], "", false, false, &opts(true, proxy(UpstreamProxyType::Socks5, pp)));
        assert_eq!(r.body, "ok", "{:?}", r.error);
        assert_eq!(*targets.lock().unwrap(), [format!("127.0.0.1:{port}")]);
        assert_eq!(*lines.lock().unwrap(), ["GET /socks HTTP/1.1"]);
    }

    #[test]
    fn an_unusable_upstream_proxy_sends_nothing() {
        let (port, lines) = http_server();
        let broken = UpstreamProxyConfig { enabled: true, host: String::new(), ..Default::default() };
        assert!(agent(false, &opts(true, broken.clone())).is_err());
        let r = send("GET", &format!("http://127.0.0.1:{port}/"), &[], "", false, false, &opts(true, broken));
        assert!(r.error.unwrap().contains("no host"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(lines.lock().unwrap().is_empty(), "not sent directly instead");
        // proxy off, or "Direct": a plain agent
        assert!(agent(false, &opts(true, UpstreamProxyConfig { enabled: true, proxy_type: UpstreamProxyType::Direct, ..Default::default() })).is_ok());
    }

    /// Answers every request with exactly these bytes, whatever they are. It is the only way
    /// to put a response of a chosen shape in front of the client: a version of its own, a
    /// body framed in chunks, a header block with or without a length.
    fn raw_response_server(response: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                while r.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let mut s = s;
                let _ = s.write_all(response.as_bytes());
            }
        });
        port
    }

    /// The value of one header of a reconstructed message's head, and how many lines name it.
    fn header_of(head: &str, name: &str) -> (Option<String>, usize) {
        let named: Vec<String> = head
            .lines()
            .skip(1) // the status line
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
            .collect();
        (named.first().cloned(), named.len())
    }

    /// A reconstructed response has to read as an HTTP message. Its first line is a status
    /// line naming the version the response gave itself, and its header block describes the
    /// body printed under it -- which is the body as it was read, not as it was framed. The
    /// client reads a chunked body whole and de-chunks it on the way in, so a
    /// `transfer-encoding: chunked` left in the block would frame chunks that are no longer
    /// there and leave the message with no length at all; an accurate `content-length` takes
    /// its place.
    #[test]
    fn a_reconstructed_response_reads_as_an_http_message_matrix() {
        struct Case {
            name: &'static str,
            /// The response the server puts on the wire, byte for byte.
            response: &'static str,
            first_line: &'static str,
            body: &'static str,
        }
        let cases = [
            Case {
                name: "a chunked body is de-chunked and given a length of its own",
                response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n\
                           5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                first_line: "HTTP/1.1 200 OK",
                body: "hello world",
            },
            Case {
                name: "an error response says so on its status line",
                response: "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot there",
                first_line: "HTTP/1.1 404 Not Found",
                body: "not there",
            },
            Case {
                name: "the version is the response's own, not one assumed for it",
                response: "HTTP/1.0 203 Non-Authoritative Information\r\nContent-Length: 4\r\nConnection: close\r\n\r\nmeh!",
                first_line: "HTTP/1.0 203 Non-Authoritative Information",
                body: "meh!",
            },
            Case {
                name: "a chunked response with nothing in it still gets a length",
                response: "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                first_line: "HTTP/1.1 204 No Content",
                body: "",
            },
        ];
        assert_table!(cases, |idx, case| {
            let port = raw_response_server(case.response);
            let r = send("GET", &format!("http://127.0.0.1:{port}/p"), &[], "", false, true, &opts(true, Default::default()));
            let message = r.raw_response();
            let what = format!("case #{idx} ({})", case.name);
            assert_eq!(r.error, None, "{what}: {message:?}");

            assert_eq!(message.lines().next(), Some(case.first_line), "{what}: the status line ({message:?})");
            let (head, body) = message.split_once("\n\n").unwrap_or_else(|| panic!("{what}: head and body are separated by a blank line ({message:?})"));
            assert_eq!(body, case.body, "{what}: the body ({message:?})");

            assert_eq!(header_of(head, "transfer-encoding").0, None, "{what}: the chunked framing is gone ({head:?})");
            assert_eq!(
                header_of(head, "content-length"),
                (Some(case.body.len().to_string()), 1),
                "{what}: one accurate length, counting the body that is there ({head:?})"
            );

            // and what the rest of the app reads of the same response is unchanged: the
            // status without its version, for the tables and for `status_code`
            assert_eq!(r.status, case.first_line.split_once(' ').map(|(_, rest)| rest).unwrap_or_default(), "{what}: the status field");
            assert_eq!(r.version, case.first_line.split_once(' ').map(|(v, _)| v).unwrap_or_default(), "{what}: the version field");
            assert_eq!(r.length, case.body.len(), "{what}: the recorded byte count");
            assert_eq!(status_code(&r.status), Some(case.first_line.split_whitespace().nth(1).unwrap().parse().unwrap()), "{what}: and the code read back out of it");
        });
    }

    /// A request that never got a response has no status line to print and no headers to
    /// print either: what stands in its place is the note saying what went wrong, on its own
    /// first line, with the detail under it.
    #[test]
    fn a_failed_connection_reconstructs_as_the_note_in_its_place() {
        // a port nothing is listening on: bound, read for its number, then dropped
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let r = send("GET", &format!("http://127.0.0.1:{dead}/p"), &[], "", false, true, &opts(true, Default::default()));
        assert!(r.error.is_some(), "the connection failed");
        let message = r.raw_response();
        assert!(!message.starts_with("HTTP/"), "no version is invented for a response that never came: {message:?}");
        let (head, body) = message.split_once("\n\n").expect("head and body are still separated");
        assert_eq!(head, "— (transport error)", "the head is the note alone, with no empty header line under it");
        assert!(body.starts_with("Request failed:"), "and the detail is the body: {body:?}");
    }
}
