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
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.len() == 3 { digits.parse().ok() } else { None }
    }
}

/// Recorded traffic. Entries are shared (`Arc`): the UI takes a snapshot each frame by
/// copying pointers, never request or response bodies.
pub type History = Arc<Mutex<Vec<Arc<HttpEntry>>>>;

pub struct SendResult {
    pub status: String,
    pub body: String,
    pub headers: String,
    pub length: usize,
    pub mime: String,
    /// Set when no response came back (connection, TLS or timeout failure).
    pub error: Option<String>,
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
            let mime = r.content_type().to_string();
            let mut hdr = String::new();
            for name in r.headers_names() {
                if let Some(v) = r.header(&name) {
                    hdr.push_str(&format!("{}: {}\n", name, v));
                }
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
            SendResult { status, body: text, headers: hdr, length, mime, error: None }
        }
        Err(e) => SendResult {
            status: "— (transport error)".into(),
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
    use std::io::Write;

    #[test]
    fn unpacks_gzip_and_deflate() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello gzip").unwrap();
        assert_eq!(unpack_body("gzip", &gz.finish().unwrap()).as_deref(), Some(&b"hello gzip"[..]));
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"hello zlib").unwrap();
        assert_eq!(unpack_body("deflate", &z.finish().unwrap()).as_deref(), Some(&b"hello zlib"[..]));
        let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(b"raw deflate").unwrap();
        assert_eq!(unpack_body("deflate", &d.finish().unwrap()).as_deref(), Some(&b"raw deflate"[..]));
        assert_eq!(unpack_body("br", b"x"), None);
        assert_eq!(unpack_body("gzip", b"not gzip"), None);
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
    fn decompression_is_bounded() {
        // the cap itself: up to it is fine, one byte over is refused
        let small = gzip_of_zeros(1000);
        assert_eq!(unpack_body_capped("gzip", &small, 1000).map(|v| v.len()), Some(1000));
        assert_eq!(unpack_body_capped("gzip", &small, 999), None);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(&[7u8; 5000]).unwrap();
        let z = z.finish().unwrap();
        assert_eq!(unpack_body_capped("deflate", &z, 4999), None, "zlib and raw-deflate fallbacks are both capped");
        // a real bomb: ~33 KiB of gzip that expands past MAX_DECODED is refused, not allocated
        let bomb = gzip_of_zeros(MAX_DECODED as usize + 1024 * 1024);
        assert!(bomb.len() < 200 * 1024, "compressed size {}", bomb.len());
        assert_eq!(unpack_body("gzip", &bomb), None);
        // a large but legitimate body under the cap still unpacks
        assert_eq!(unpack_body("gzip", &gzip_of_zeros(4 * 1024 * 1024)).map(|v| v.len()), Some(4 * 1024 * 1024));
    }

    #[test]
    fn user_agent_names_forgeproxy_and_its_version() {
        assert_eq!(super::USER_AGENT, format!("ForgeProxy/{}", env!("CARGO_PKG_VERSION")));
        assert!(crate::state::DEFAULT_REP_REQUEST.contains(&format!("\nUser-Agent: {}\n", super::USER_AGENT)));
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
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
}
