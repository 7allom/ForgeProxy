//! The local proxy listener (default 127.0.0.1:8080, loopback only).
//! - Plain HTTP requests are read, optionally held for interception (Forward / Drop),
//!   passed through the match-and-replace rules, sent on, and recorded in HTTP history.
//! - HTTPS (CONNECT): with "Intercept HTTPS" on and a root CA loaded, the proxy completes TLS
//!   with the browser using a certificate for the host signed by the root CA, opens its own
//!   verified TLS connection to the server, and puts each decrypted request through the same
//!   steps as plain HTTP (rules, Intercept, history). Otherwise the tunnel is passed through
//!   unchanged and recorded as one CONNECT entry.

use crate::http::{HttpEntry, History};
use crate::rewrite::{self, Rule};
use crate::rules;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub enum Decision {
    Forward(String),
    Drop,
}

/// A request held by Intercept until the user forwards or drops it.
pub struct Held {
    /// Unique per held request, so the UI knows which one its editor holds.
    pub id: u64,
    pub raw: String,
    /// Where the request is going: "https://host/path" when it came through decrypted TLS,
    /// "http://host:8080/path" for plain HTTP (default ports left out).
    pub url: String,
    pub reply: Sender<Decision>,
}

/// A fresh `Held::id`.
pub fn next_held_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone)]
pub struct Shared {
    pub history: History,
    pub next_id: Arc<Mutex<usize>>,
    /// Logger's capture switch, shared with the rest of the app: while it is set the proxy
    /// forwards traffic as usual and records none of it.
    pub capture_paused: Arc<AtomicBool>,
    /// Settings > Proxy > Storage and limits (kept current by the UI each frame).
    pub entry_limit: Arc<std::sync::atomic::AtomicUsize>,
    pub pause_when_full: Arc<AtomicBool>,
    pub intercept: Arc<AtomicBool>,
    pub held: Arc<Mutex<Vec<Held>>>,
    pub rules: Arc<Mutex<Vec<Rule>>>,
    pub events: Events,
    pub running: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    /// "Intercept requests based on the following rules": off holds every request.
    pub use_rules: Arc<AtomicBool>,
    /// "Automatically update Content-Length header" on forwarded requests.
    pub fix_length: Arc<AtomicBool>,
    /// "Intercept HTTPS": decrypt CONNECT tunnels (needs `tls`).
    pub decrypt_https: Arc<AtomicBool>,
    /// "Only in scope": Intercept holds only requests inside `scope`.
    pub intercept_only_in_scope: Arc<AtomicBool>,
    /// The proxy's copy of Target > Scope (kept current by the UI each frame).
    pub scope: Arc<Mutex<crate::scope::TargetScope>>,
    /// Host patterns whose HTTPS is tunnelled unopened even with "Intercept HTTPS" on
    /// (kept current by the UI each frame).
    pub tls_passthrough: Arc<Mutex<Vec<String>>>,
    /// File extensions Intercept lets through (kept current by the UI each frame).
    pub skip_extensions: Arc<Mutex<Vec<String>>>,
    /// Read timeout for browser and target connections, in seconds (kept current by the UI).
    pub read_timeout_secs: Arc<std::sync::atomic::AtomicU64>,
    /// Settings > Network > Connections: every connection to a target goes through this
    /// proxy when it's on (kept current by the UI).
    pub upstream_proxy: Arc<Mutex<crate::upstream::UpstreamProxyConfig>>,
    /// Settings > Network > TLS / Protocols: check real servers' certificates (`upstream_tls`)
    /// or accept any (kept current by the UI).
    pub verify_upstream_tls: Arc<AtomicBool>,
    /// Per-host certificates from the root CA; None when no CA is loaded.
    pub tls: Arc<Mutex<Option<Arc<crate::ca::TlsConfigCache>>>>,
    /// How the proxy verifies real servers when it intercepts HTTPS.
    pub upstream_tls: Arc<rustls::ClientConfig>,
    /// WebSocket messages captured so far, on the same storage budget as the history.
    pub ws_messages: crate::websocket::MessageLog,
    /// Hands out message ids, counting up for the life of the project.
    pub ws_next_id: Arc<Mutex<usize>>,
    /// The upgraded connections open right now, so the app can send a frame on one.
    pub ws_live: crate::websocket::LiveLinks,
}

/// TLS client settings for connections to real servers: Mozilla's root certificates
/// (webpki-roots), ALPN http/1.1.
pub fn upstream_client_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config_with(roots)
}

pub fn client_config_with(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level { Info, Warning, Error }

impl Level {
    pub fn label(self) -> &'static str {
        match self { Level::Info => "Info", Level::Warning => "Warning", Level::Error => "Error" }
    }
}

/// One Event log line.
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    /// "HH:MM:SS", UTC.
    pub time: String,
    pub level: Level,
    pub message: String,
}

/// True when the listener interface only accepts connections from this machine: a loopback
/// address (127.0.0.0/8, ::1) or "localhost". Anything else (0.0.0.0, ::, a LAN address, a
/// host name) lets other machines use the proxy, and through it reach anything it can.
pub fn is_loopback_interface(host: &str) -> bool {
    let h = host.trim();
    let bare = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
    bare.eq_ignore_ascii_case("localhost") || bare.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The warning shown and logged for a listener that isn't on loopback.
pub fn exposed_listener_warning(host: &str) -> String {
    format!("The proxy listens on {}, not only on this machine: other devices on the network can send traffic through it and see what it records. Use 127.0.0.1 unless you need this.", host.trim())
}

/// The Event log: the newest `MAX_EVENTS` entries (oldest dropped first).
pub type Events = Arc<Mutex<std::collections::VecDeque<Event>>>;

/// Entries the Event log keeps, so a long session can't grow it without bound.
pub const MAX_EVENTS: usize = 10_000;

pub fn log(events: &Events, msg: impl Into<String>) {
    log_level(events, Level::Info, msg);
}

pub fn log_warning(events: &Events, msg: impl Into<String>) {
    log_level(events, Level::Warning, msg);
}

pub fn log_error(events: &Events, msg: impl Into<String>) {
    log_level(events, Level::Error, msg);
}

fn log_level(events: &Events, level: Level, msg: impl Into<String>) {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (h, m, s) = ((t / 3600) % 24, (t / 60) % 60, t % 60);
    // a thread that panicked holding the log mustn't take logging down with it
    let mut log = events.lock().unwrap_or_else(|e| e.into_inner());
    while log.len() >= MAX_EVENTS {
        log.pop_front();
    }
    log.push_back(Event { time: format!("{h:02}:{m:02}:{s:02}"), level, message: msg.into() });
}

/// Start listening on `addr`. Returns an error text if the port can't be opened.
pub fn start(shared: Shared, addr: String) -> Result<(), String> {
    // the app stops the listener through `shared.stop`; the handle is not needed here
    listen(shared, addr).map(drop)
}

/// A running listener: what is needed to stop it and wait for the traffic it let in.
pub struct Listener {
    stop: Arc<AtomicBool>,
    accept_loop: std::thread::JoinHandle<()>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

impl Listener {
    /// Stop taking new connections, close the listening socket, and wait up to `grace` for the
    /// connections already accepted to finish, so what they record lands in the history.
    /// Returns how many were still open when the grace ran out (0 when all finished).
    pub fn shutdown(self, grace: Duration) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        // the accept loop polls the flag every few milliseconds; joining it drops the socket
        let _ = self.accept_loop.join();
        let deadline = std::time::Instant::now() + grace;
        loop {
            let open = self.in_flight.load(Ordering::SeqCst);
            if open == 0 || std::time::Instant::now() >= deadline {
                return open;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Counts a connection as open for as long as it lives, even if its handler panics.
struct InFlight(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Start listening on `addr` and return the handle that stops it. Setting `shared.stop` stops
/// it as well; the handle adds a join of the accept loop and a wait for open connections.
pub fn listen(shared: Shared, addr: String) -> Result<Listener, String> {
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Proxy could not listen on {addr}: {e}"))?;
    listener.set_nonblocking(true).ok();
    shared.running.store(true, Ordering::SeqCst);
    shared.stop.store(false, Ordering::SeqCst);
    log(&shared.events, format!("Proxy service started on {addr}"));
    let stop = shared.stop.clone();
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let open = in_flight.clone();
    let accept_loop = std::thread::spawn(move || {
        while !shared.stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let sh = shared.clone();
                    open.fetch_add(1, Ordering::SeqCst);
                    let guard = InFlight(open.clone());
                    std::thread::spawn(move || {
                        let _guard = guard;
                        let _ = stream.set_nonblocking(false);
                        handle(sh, stream);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(30)),
            }
        }
        drop(listener);
        shared.running.store(false, Ordering::SeqCst);
        log(&shared.events, "Proxy service stopped");
    });
    Ok(Listener { stop, accept_loop, in_flight })
}

impl Shared {
    /// A proxy to run with no window behind it, from the saved settings.
    ///
    /// The listener, the Match & Replace rules and the capture all work exactly as they do in
    /// the app; what the app keeps current each frame -- scope, limits, upstream proxy -- is set
    /// once here from `settings` instead. Interception is left off, since there is no one to
    /// release a held request. `history`/`next_id` are shared so the caller can keep what was
    /// captured. The CA cache, when one is loaded, lets it open intercepted HTTPS.
    pub fn headless(
        history: History,
        next_id: Arc<Mutex<usize>>,
        rules: Vec<Rule>,
        settings: &crate::state::UserSettings,
        tls: Option<Arc<crate::ca::TlsConfigCache>>,
        ws_messages: crate::websocket::MessageLog,
    ) -> Self {
        Shared {
            history,
            next_id,
            ws_messages,
            ws_next_id: Arc::new(Mutex::new(0)),
            ws_live: Arc::new(Mutex::new(Vec::new())),
            capture_paused: Arc::new(AtomicBool::new(false)),
            entry_limit: Arc::new(std::sync::atomic::AtomicUsize::new(settings.max_entries.max(1))),
            pause_when_full: Arc::new(AtomicBool::new(settings.pause_when_full)),
            intercept: Arc::new(AtomicBool::new(false)),
            held: Arc::new(Mutex::new(Vec::new())),
            rules: Arc::new(Mutex::new(rules)),
            events: Arc::new(Mutex::new(Default::default())),
            running: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            use_rules: Arc::new(AtomicBool::new(settings.intercept_rules)),
            fix_length: Arc::new(AtomicBool::new(settings.fix_length)),
            decrypt_https: Arc::new(AtomicBool::new(tls.is_some())),
            intercept_only_in_scope: Arc::new(AtomicBool::new(false)),
            scope: Arc::new(Mutex::new(crate::scope::TargetScope::default())),
            tls_passthrough: Arc::new(Mutex::new(Vec::new())),
            skip_extensions: Arc::new(Mutex::new(crate::rules::default_skip_extensions())),
            read_timeout_secs: Arc::new(std::sync::atomic::AtomicU64::new(settings.proxy_read_timeout_secs)),
            upstream_proxy: Arc::new(Mutex::new(settings.upstream_proxy.clone())),
            verify_upstream_tls: Arc::new(AtomicBool::new(settings.protocol.verify_upstream_tls)),
            tls: Arc::new(Mutex::new(tls)),
            upstream_tls: upstream_client_config(),
        }
    }

    /// The traffic store, as the recording path takes it.
    fn recorder(&self) -> crate::http::Recorder {
        crate::http::Recorder {
            history: self.history.clone(),
            next_id: self.next_id.clone(),
            paused: self.capture_paused.clone(),
            limit: self.entry_limit.clone(),
            pause_when_full: self.pause_when_full.clone(),
        }
    }
}

/// Largest request/response head the proxy reads (all header lines together).
pub const MAX_HEAD: usize = 256 * 1024;
/// Largest single header line after the request line (the request line may use the whole
/// `MAX_HEAD`, for long URLs).
pub const MAX_HEADER_LINE: usize = 64 * 1024;
/// Largest request body the proxy accepts (larger ones get 413).
pub const MAX_REQUEST_BODY: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq)]
enum HeadError {
    /// The connection ended (or failed) before a head arrived.
    Closed,
    /// A line or the whole head is over the limits.
    TooLarge,
}

/// Read a head (up to the blank line) as bytes, without ever holding more than the limits:
/// each line is read through a bounded reader, so a line that never ends can't grow memory.
fn read_head_bytes(r: &mut impl BufRead) -> Result<Vec<u8>, HeadError> {
    let mut head = Vec::new();
    let mut first = true;
    loop {
        let room = MAX_HEAD - head.len();
        let cap = if first { room } else { room.min(MAX_HEADER_LINE) };
        let mut line = Vec::new();
        let n = r.by_ref().take(cap as u64 + 1).read_until(b'\n', &mut line).map_err(|_| HeadError::Closed)?;
        if n == 0 {
            return if head.is_empty() { Err(HeadError::Closed) } else { Ok(head) };
        }
        if line.len() > cap {
            return Err(HeadError::TooLarge);
        }
        if line == b"\r\n" || line == b"\n" {
            return Ok(head);
        }
        head.extend_from_slice(&line);
        first = false;
    }
}

/// `read_head_bytes` as text (UTF-8, or Latin-1 for other bytes); None if none arrived or
/// it was too large.
#[cfg(test)]
fn read_head(r: &mut impl BufRead) -> Option<String> {
    read_head_bytes(r).ok().map(|b| crate::codec::decode_header_bytes(&b).0)
}

/// Answer the client with an error and end the connection (nothing more is read from it, so
/// no leftover request bytes can be taken for another request).
fn reject(sh: &Shared, client: &mut impl Write, code: u16, reason: &str, msg: &str) {
    log_warning(&sh.events, format!("Rejected a request ({code} {reason}): {msg}"));
    let _ = client.write_all(format!("HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes());
    let _ = client.flush();
}

/// How long a request's body is, by strict rules (desync prevention): at most one
/// Content-Length, made of digits only; no Transfer-Encoding (chunked request bodies aren't
/// supported, and with a Content-Length too the two could be read differently upstream);
/// no more than `MAX_REQUEST_BODY`. Err: (status, reason, message) for the client.
fn request_body_length(head: &str) -> Result<u64, (u16, &'static str, String)> {
    let mut lengths = Vec::new();
    let mut transfer_encoding = false;
    for line in head.lines().skip(1) {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim();
        if k.eq_ignore_ascii_case("content-length") {
            lengths.push(v.trim().to_string());
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = true;
        }
    }
    if transfer_encoding {
        return Err(if lengths.is_empty() {
            (411, "Length Required", "Requests with a Transfer-Encoding (chunked bodies) aren't supported: send a Content-Length.".into())
        } else {
            (400, "Bad Request", "The request has both Content-Length and Transfer-Encoding.".into())
        });
    }
    match lengths.as_slice() {
        [] => Ok(0),
        [one] => {
            if one.is_empty() || one.len() > 19 || !one.bytes().all(|b| b.is_ascii_digit()) {
                return Err((400, "Bad Request", format!("Invalid Content-Length {one:?}: it must be digits only.")));
            }
            let n: u64 = one.parse().map_err(|_| (400, "Bad Request", format!("Invalid Content-Length {one:?}.")))?;
            if n > MAX_REQUEST_BODY {
                return Err((413, "Payload Too Large", format!("The request body is {n} bytes; the proxy accepts up to {} MiB.", MAX_REQUEST_BODY >> 20)));
            }
            Ok(n)
        }
        _ => Err((400, "Bad Request", "The request has more than one Content-Length.".into())),
    }
}

/// A header line made safe to forward: None when there's no valid header name (a field name
/// is a token: letters, digits and !#$%&'*+-.^_`|~, directly followed by ':'); otherwise the
/// line with control characters (bare CR, LF, NUL and the like, but not tab) removed from
/// the value, so nothing can start a new line upstream.
fn sanitize_header_line(line: &str) -> Option<String> {
    let (name, value) = line.split_once(':')?;
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.is_empty() || !name.chars().all(token) {
        return None;
    }
    Some(format!("{name}:{}", strip_controls(value)))
}

/// `s` without ASCII control characters other than tab. (Bytes 0x80..=0xFF, kept as Latin-1
/// characters, are left alone.)
fn strip_controls(s: &str) -> String {
    s.chars().filter(|&c| c == '\t' || !((c as u32) < 0x20 || c == '\u{7f}')).collect()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

impl Shared {
    fn read_timeout(&self) -> Duration {
        Duration::from_secs(self.read_timeout_secs.load(Ordering::SeqCst).max(1))
    }

    /// The upstream proxy route now (None: direct; Err: switched on but unusable).
    fn route(&self) -> Result<Option<crate::upstream::Route>, String> {
        self.upstream_proxy.lock().unwrap_or_else(|e| e.into_inner()).route()
    }

    /// A connection to the target, directly or through the upstream proxy.
    fn connect_target(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        let route = self.route()?;
        crate::upstream::connect(route.as_ref(), host, port, self.read_timeout()).map_err(|e| e.to_string())
    }

    /// TLS settings for connections to real servers: verifying, or accepting any certificate.
    fn target_tls(&self) -> Arc<rustls::ClientConfig> {
        if self.verify_upstream_tls.load(Ordering::SeqCst) { self.upstream_tls.clone() } else { crate::upstream::insecure_client_config() }
    }
}

fn handle(sh: Shared, client: TcpStream) {
    let _ = client.set_read_timeout(Some(sh.read_timeout()));
    let Ok(client_w) = client.try_clone() else { return };
    let mut reader = BufReader::new(client);
    let head_bytes = match read_head_bytes(&mut reader) {
        Ok(b) => b,
        Err(HeadError::TooLarge) => {
            let mut w = client_w;
            reject(&sh, &mut w, 431, "Request Header Fields Too Large", &format!("A header line is over {} KiB, or the head is over {} KiB.", MAX_HEADER_LINE >> 10, MAX_HEAD >> 10));
            return;
        }
        Err(HeadError::Closed) => return,
    };
    let (head, latin1) = crate::codec::decode_header_bytes(&head_bytes);
    let first = head.lines().next().unwrap_or("").to_string();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.eq_ignore_ascii_case("CONNECT") {
        let tls = sh.tls.lock().unwrap_or_else(|e| e.into_inner()).clone().filter(|_| sh.decrypt_https.load(Ordering::SeqCst));
        match tls {
            Some(cache) => {
                let (host, _) = split_authority(&target);
                if should_passthrough_tls(&host, &sh.tls_passthrough.lock().unwrap_or_else(|e| e.into_inner())) {
                    // no certificate, no handshake: the same opaque tunnel as with interception off
                    log(&sh.events, format!("TLS passthrough enabled for {host}; tunneling opaque TCP"));
                    tunnel(sh, reader, client_w, target);
                } else {
                    mitm(sh, reader, client_w, target, cache);
                }
            }
            None => tunnel(sh, reader, client_w, target),
        }
    } else {
        drop(client_w);
        plain(sh, reader, head, latin1, method, target);
    }
}

/// Is `host` on the TLS pass-through list? Rules are exact host names ("api.example.com"),
/// or "*.example.com" / ".example.com" for any subdomain (not example.com itself, as with
/// a wildcard certificate). Case-insensitive; a trailing dot and IPv6 brackets are ignored.
pub fn should_passthrough_tls(host: &str, rules: &[String]) -> bool {
    let norm = |s: &str| s.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    let host = norm(host);
    if host.is_empty() {
        return false;
    }
    rules.iter().any(|rule| {
        let rule = rule.trim().to_ascii_lowercase();
        match rule.strip_prefix("*.").or_else(|| rule.strip_prefix('.')) {
            Some(domain) => {
                let domain = norm(domain);
                !domain.is_empty() && host.len() > domain.len() + 1 && host.ends_with(&format!(".{domain}"))
            }
            None => !rule.is_empty() && norm(&rule) == host,
        }
    })
}

/// "host:443", "[::1]:8443" or "host" (port 443) → (host, port).
fn split_authority(target: &str) -> (String, u16) {
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            return (h.to_string(), tail.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(443));
        }
    }
    match target.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(443)),
        _ => (target.to_string(), 443),
    }
}

/// HTTPS, decrypted: TLS with the browser as `host` (certificate from the root CA), then
/// each request in turn through `exchange`, upstream over verified TLS, until either side
/// closes.
fn mitm(sh: Shared, reader: BufReader<TcpStream>, mut client: TcpStream, target: String, cache: Arc<crate::ca::TlsConfigCache>) {
    let (host, port) = split_authority(&target);
    if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return;
    }
    let cfg = match cache.get_server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            log_error(&sh.events, format!("No certificate for {host}: {e}"));
            return;
        }
    };
    let Ok(mut conn) = rustls::ServerConnection::new(cfg) else { return };
    // the browser may have sent its ClientHello along with the CONNECT
    let early = reader.buffer().to_vec();
    let mut sock = reader.into_inner();
    if !early.is_empty() && (conn.read_tls(&mut early.as_slice()).is_err() || conn.process_new_packets().is_err()) {
        return;
    }
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut sock) {
            log_error(&sh.events, format!("TLS handshake with the client failed for {host}: {e}. If the browser reported a certificate \
                error, it doesn't trust the ForgeProxy root CA (Settings > Proxy > Root CA certificate)."));
            return;
        }
    }
    let at = Target { https: true, host, port };
    let mut io = BufReader::new(rustls::StreamOwned::new(conn, sock));
    loop {
        let head_bytes = match read_head_bytes(&mut io) {
            Ok(b) => b,
            Err(HeadError::TooLarge) => {
                reject(&sh, io.get_mut(), 431, "Request Header Fields Too Large", &format!("A header line is over {} KiB, or the head is over {} KiB.", MAX_HEADER_LINE >> 10, MAX_HEAD >> 10));
                break;
            }
            Err(HeadError::Closed) => break,
        };
        let (head, latin1) = crate::codec::decode_header_bytes(&head_bytes);
        let first = head.lines().next().unwrap_or("").to_string();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let raw_target = parts.next().unwrap_or("/").to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        // origin-form normally; absolute-form ("https://host/p") is allowed too
        let path = match raw_target.find("://") {
            Some(i) => raw_target[i + 3..].find('/').map_or("/".to_string(), |j| raw_target[i + 3 + j..].to_string()),
            None => raw_target,
        };
        // an upgrade takes the connection over for good: there is no request after it
        if wants_websocket(&head) {
            websocket_exchange(&sh, &mut io, &head, &path, &at);
            break;
        }
        let wants_close = version == "HTTP/1.0" || header(&head, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
        if !exchange(&sh, &mut io, &head, latin1, method, path, &at, !wants_close) || wants_close {
            break;
        }
    }
    let _ = io.get_mut().flush();
    io.get_mut().conn.send_close_notify();
    let _ = io.get_mut().flush();
}

/// Where a request goes.
struct Target {
    https: bool,
    host: String,
    port: u16,
}

impl Target {
    fn url(&self, path: &str) -> String {
        let (scheme, default) = if self.https { ("https", 443) } else { ("http", 80) };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default { format!("{scheme}://{host}{path}") } else { format!("{scheme}://{host}:{}{path}", self.port) }
    }
}

/// Send `wire` to the target and read the whole response (the request says Connection: close).
/// Most of an upstream response the proxy holds in memory (32 MiB). Beyond that the rest is
/// streamed to the client as it arrives and the history entry is marked truncated.
pub const MAX_BUFFERED: u64 = 32 * 1024 * 1024;

/// An upstream response: all of it, or (when it's larger than `MAX_BUFFERED`) the first
/// `MAX_BUFFERED + 1` bytes and the connection the rest is still coming from.
enum Upstream {
    Complete(Vec<u8>),
    Large(Vec<u8>, Box<dyn Read + Send>),
}

/// Read up to `MAX_BUFFERED + 1` bytes; a read error after some data (many servers end TLS
/// without close_notify) just ends the response.
fn read_response(mut r: impl Read + Send + 'static, at: &Target) -> Result<Upstream, String> {
    let mut buf = Vec::new();
    if let Err(e) = Read::take(&mut r, MAX_BUFFERED + 1).read_to_end(&mut buf) {
        if buf.is_empty() {
            return Err(format!("No response from {}:{}: {e}", at.host, at.port));
        }
    }
    Ok(if buf.len() as u64 > MAX_BUFFERED { Upstream::Large(buf, Box::new(r)) } else { Upstream::Complete(buf) })
}

/// Send `wire` to the target and read its response (the request says Connection: close).
fn send_upstream(sh: &Shared, at: &Target, wire: &[u8]) -> Result<Upstream, String> {
    // plain HTTP through an HTTP upstream proxy is forwarded to it with an absolute URL, the
    // way browsers do (many proxies refuse CONNECT to ports other than 443); everything
    // else goes through a tunnel (CONNECT or SOCKS5) or directly
    let route = sh.route().map_err(|e| format!("Could not connect to {}:{}: {e}", at.host, at.port))?;
    if let Some(r) = route.as_ref().filter(|r| !at.https && r.kind == crate::upstream::UpstreamProxyType::HttpConnect) {
        let proxy = crate::upstream::authority(&r.host, r.port);
        let mut tcp = TcpStream::connect((r.host.as_str(), r.port)).map_err(|e| format!("Could not connect to the upstream proxy {proxy}: {e}"))?;
        let _ = tcp.set_read_timeout(Some(sh.read_timeout()));
        tcp.write_all(&absolute_form(wire, at)).map_err(|e| format!("Could not send to the upstream proxy {proxy}: {e}"))?;
        return read_response(tcp, at);
    }
    let tcp = sh.connect_target(&at.host, at.port).map_err(|e| format!("Could not connect to {}:{}: {e}", at.host, at.port))?;
    let _ = tcp.set_read_timeout(Some(sh.read_timeout()));
    if at.https {
        let name = rustls_pki_types::ServerName::try_from(at.host.clone()).map_err(|_| format!("{} isn't a valid server name", at.host))?;
        let conn = rustls::ClientConnection::new(sh.target_tls(), name).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        tls.write_all(wire).map_err(|e| format!("TLS connection to {}:{} failed: {e}", at.host, at.port))?;
        read_response(tls, at)
    } else {
        let mut tcp = tcp;
        tcp.write_all(wire).map_err(|e| format!("Could not send to {}:{}: {e}", at.host, at.port))?;
        read_response(tcp, at)
    }
}

/// Copy the rest of a large response to the client in 64 KiB pieces, without keeping it.
/// Returns how many bytes went through.
fn stream_rest(mut from: Box<dyn Read + Send>, to: &mut impl Write) -> u64 {
    let mut chunk = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match from.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&chunk[..n]).is_err() {
                    break;
                }
                total += n as u64;
            }
        }
    }
    let _ = to.flush();
    total
}

/// `wire` with its request line's target made absolute ("GET /a" -> "GET http://host:81/a"),
/// for sending to an HTTP proxy.
fn absolute_form(wire: &[u8], at: &Target) -> Vec<u8> {
    let end = wire.windows(2).position(|w| w == b"\r\n").unwrap_or(wire.len());
    let line = String::from_utf8_lossy(&wire[..end]);
    let mut parts = line.splitn(3, ' ');
    let (method, target, version) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"), parts.next().unwrap_or("HTTP/1.1"));
    let mut out = format!("{method} http://{}{target} {version}", crate::upstream::authority(&at.host, at.port)).into_bytes();
    out.extend_from_slice(&wire[end..]);
    out
}

/// HTTPS: relay bytes both ways without reading them.
fn tunnel(sh: Shared, reader: BufReader<TcpStream>, mut client: TcpStream, target: String) {
    let host = target.split(':').next().unwrap_or(&target).to_string();
    let (h, port) = split_authority(&target);
    let upstream = match sh.connect_target(&h, port) {
        Ok(u) => u,
        Err(e) => {
            let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").as_bytes());
            log_error(&sh.events, format!("Tunnel to {target} failed: {e}"));
            // recorded without a status: the target never answered (the 502 is ours)
            sh.recorder().record(|id| HttpEntry {
                id,
                tool: "Proxy".into(),
                method: "CONNECT".into(),
                host: host.clone(),
                path: String::new(),
                status: crate::http::CONNECTION_FAILED.into(),
                length: 0,
                mime: String::new(),
                request: format!("CONNECT {target} HTTP/1.1\nHost: {target}"),
                response: format!("Could not connect to {target}: {e}\n\n(The browser was sent 502 Bad Gateway.)"),
                url: format!("https://{host}/"),
                truncated: false,
                time: crate::http::now_ms(),
                // the connection failed: there was nothing to time
                elapsed_ms: 0,
                graphql: String::new(),
            });
            return;
        }
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    sh.recorder().record(|id| HttpEntry {
        id,
        tool: "Proxy".into(),
        method: "CONNECT".into(),
        host: host.clone(),
        path: String::new(),
        // the CONNECT handshake's answer; the HTTPS inside stays encrypted
        status: "200 (Tunnel)".into(),
        length: 0,
        mime: String::new(),
        request: format!("CONNECT {target} HTTP/1.1\nHost: {target}"),
        response: "HTTP/1.1 200 Connection established\n\nThe HTTPS traffic inside this tunnel is passed through unchanged.".into(),
        url: format!("https://{host}/"),
        truncated: false,
        time: crate::http::now_ms(),
        // the tunnel stays open after this: what it carries is not one exchange to time
        elapsed_ms: 0,
        graphql: String::new(),
    });
    let (Ok(mut up_r), Ok(mut up_w)) = (upstream.try_clone(), upstream.try_clone()) else { return };
    let mut client_r = reader.into_inner();
    let mut client_w2 = client.try_clone().ok();
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut up_w);
        let _ = up_w.shutdown(Shutdown::Write);
    });
    if let Some(cw) = client_w2.as_mut() {
        let _ = std::io::copy(&mut up_r, cw);
        let _ = cw.shutdown(Shutdown::Write);
    }
    let _ = t.join();
}

/// Split "http://host:port/path?q" into (host, port, origin-form path).
fn split_target(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), 80),
    };
    Some((host, port, path))
}

/// Does Intercept hold this request? Intercept is on, the request rule allows it (unless
/// rules are off) and, with "Only in scope", the URL is in scope. Anything else is forwarded
/// straight away (and still recorded).
fn should_hold(sh: &Shared, path: &str, url: &str) -> bool {
    sh.intercept.load(Ordering::SeqCst)
        && (!sh.use_rules.load(Ordering::SeqCst) || rules::would_intercept(path, &sh.skip_extensions.lock().unwrap_or_else(|e| e.into_inner())))
        && (!sh.intercept_only_in_scope.load(Ordering::SeqCst) || sh.scope.lock().unwrap_or_else(|e| e.into_inner()).is_in_scope(url))
}


fn plain(sh: Shared, mut io: BufReader<TcpStream>, head: String, latin1: bool, method: String, target: String) {
    let Some((host, port, path)) = split_target(&target) else {
        let msg = "This proxy expects absolute http:// addresses. Point your browser's proxy setting here.";
        let _ = io.get_mut().write_all(format!("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{msg}", msg.len()).as_bytes());
        return;
    };
    let at = Target { https: false, host, port };
    if wants_websocket(&head) {
        websocket_exchange(&sh, &mut io, &head, &path, &at);
        return;
    }
    exchange(&sh, &mut io, &head, latin1, method, path, &at, false);
}

/// How often the relay looks at each side of a connection while nothing is arriving. Short,
/// because one thread watches both: a long wait on one side would hold up the other.
const WS_POLL: Duration = Duration::from_millis(50);

/// How long to wait on a quiet side while the connection is busy. One thread serves both
/// directions, so whatever it spends waiting on the silent one is taken from the other; while
/// anything is moving that wait is kept short, and it goes back to `WS_POLL` once both have
/// been quiet for a turn.
const WS_POLL_BUSY: Duration = Duration::from_millis(1);

/// How many buffers one direction may take in a turn before the other gets a look in. At the
/// 16 KiB buffer below that is a megabyte, which is plenty for a burst and still bounded.
const MAX_DRAIN: usize = 64;

/// A stream whose socket's read timeout the relay can set, so one thread can watch both ends
/// of a connection without splitting either of them in two.
///
/// A connection cannot simply be cloned and handed to two threads the way an opaque tunnel is:
/// a decrypted one is a TLS session, and its two directions share the keys and the sequence
/// numbers, so only one thread may hold it. Short timeouts on both ends let one thread take
/// turns instead.
trait PollTimeout {
    fn set_poll_timeout(&mut self, d: Duration);
}

impl PollTimeout for TcpStream {
    fn set_poll_timeout(&mut self, d: Duration) {
        let _ = self.set_read_timeout(Some(d));
    }
}

impl<C, T> PollTimeout for rustls::StreamOwned<C, T>
where
    C: std::ops::DerefMut + std::ops::Deref,
    T: Read + Write + PollTimeout,
{
    fn set_poll_timeout(&mut self, d: Duration) {
        self.sock.set_poll_timeout(d);
    }
}

/// Is this request asking to leave HTTP behind for the WebSocket protocol? RFC 6455 §4.1: a
/// GET whose `Upgrade` names the protocol and whose `Connection` carries the `upgrade` token.
fn wants_websocket(head: &str) -> bool {
    let first = head.lines().next().unwrap_or("");
    if !first.split_whitespace().next().is_some_and(|m| m.eq_ignore_ascii_case("GET")) {
        return false;
    }
    let upgrade = header(head, "upgrade").is_some_and(|v| {
        v.split(',').any(|t| t.trim().eq_ignore_ascii_case("websocket"))
    });
    let connection = header(head, "connection").is_some_and(|v| {
        v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    });
    upgrade && connection
}

/// An error that only means "nothing arrived in the time allowed". A quiet connection is
/// ordinary, so these are not a reason to end one.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted)
}

/// The handshake, and the frames that follow when the server agrees to it.
///
/// This is deliberately beside `exchange` rather than inside it. `exchange` rewrites the head
/// it forwards -- dropping `Connection` and forcing `Connection: close` -- and then reads the
/// answer to end of file, neither of which an upgrade survives. Nothing here changes what
/// `exchange` does for every ordinary request.
///
/// Two things that apply to an ordinary request therefore do not apply here, and both are on
/// purpose. Match and replace is not run, because rewriting `Sec-WebSocket-Key` would make
/// the server's answer fail its own check. Intercept does not hold a handshake either: it
/// holds requests, and a handshake is the start of a connection rather than one request to
/// forward or drop. Somebody watching a queue that never fills is told so in the event log.
fn websocket_exchange<S: Read + Write + PollTimeout>(sh: &Shared, io: &mut BufReader<S>, head: &str, path: &str, at: &Target) {
    let url = at.url(path);
    let started = crate::http::now_ms();
    if sh.intercept.load(Ordering::SeqCst) {
        log(&sh.events, format!("Upgrade to {url} was forwarded without being held: Intercept holds requests, not connections."));
    }
    // the handshake goes up as it came down, less the headers that are between browser and
    // proxy alone. Match and replace is not applied: an edited key fails the answer check.
    let mut wire = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            wire.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());
            continue;
        }
        let k = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if k.starts_with("proxy-") {
            continue;
        }
        wire.extend_from_slice(line.trim_end().as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");

    let upstream = match sh.connect_target(&at.host, at.port) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Could not reach {}: {e}", at.host);
            let _ = io.get_mut().write_all(
                format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes(),
            );
            log_error(&sh.events, format!("WebSocket upgrade to {url} failed: {e}"));
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(sh.read_timeout()));
    if at.https {
        let Ok(name) = rustls_pki_types::ServerName::try_from(at.host.clone()) else { return };
        let Ok(conn) = rustls::ClientConnection::new(sh.target_tls(), name) else { return };
        relay_handshake(sh, io, &mut BufReader::new(rustls::StreamOwned::new(conn, upstream)), &wire, head, path, at, &url, started);
    } else {
        relay_handshake(sh, io, &mut BufReader::new(upstream), &wire, head, path, at, &url, started);
    }
}

/// Send the handshake, read the answer's head alone, and -- when it is a 101 -- relay.
#[allow(clippy::too_many_arguments)]
fn relay_handshake<S, U>(
    sh: &Shared,
    io: &mut BufReader<S>,
    up: &mut BufReader<U>,
    wire: &[u8],
    head: &str,
    path: &str,
    at: &Target,
    url: &str,
    started: u64,
) where
    S: Read + Write + PollTimeout,
    U: Read + Write + PollTimeout,
{
    if up.get_mut().write_all(wire).is_err() {
        return;
    }
    // only the head: a server that agrees never closes, so reading to end of file would wait
    // for the read timeout and then throw the whole connection away
    let answer = match read_head_bytes(up) {
        Ok(b) => b,
        Err(_) => return,
    };
    // `read_head_bytes` stops at the blank line and does not keep it, so the head has to be
    // closed again before it goes on: without it the browser reads the first frames as more
    // headers and the handshake never finishes.
    let mut answer = answer;
    answer.extend_from_slice(b"\r\n");
    let (answer_head, _) = crate::codec::decode_header_bytes(&answer);
    let status_line = answer_head.lines().next().unwrap_or("").trim().to_string();
    // recorded the way every other status is: the code and its reason, without the version
    let status_text = status_line.split_once(' ').map_or(status_line.clone(), |(_, rest)| rest.to_string());
    let code = crate::http::status_code(&status_text).unwrap_or(0);
    if io.get_mut().write_all(&answer).is_err() {
        return;
    }

    if code != 101 {
        // The server would not switch protocols, so this is an ordinary response and the
        // browser needs all of it: a head promising a body followed by nothing is a network
        // error, and the reason it refused is the one thing worth reading. Only the head was
        // read above, so the body is still coming.
        let body = read_refusal_body(up, &answer_head);
        let written = io.get_mut().write_all(&body).is_ok();
        let shown = if written { String::from_utf8_lossy(&body).into_owned() } else { String::new() };
        let full = if shown.is_empty() { answer_head.clone() } else { format!("{}\n\n{shown}", answer_head.replace("\r\n", "\n").trim_end()) };
        record_handshake(sh, head, &full, path, at, url, &status_text, started, body.len());
        return;
    }
    if let Some(key) = header(head, "sec-websocket-key") {
        let expected = crate::websocket::accept_key(key);
        let given = header(&answer_head, "sec-websocket-accept").unwrap_or("");
        if given != expected {
            log_warning(&sh.events, format!("{url} answered the WebSocket handshake with an accept key that does not match the one offered."));
        }
    }
    let entry_id = record_handshake(sh, head, &answer_head, path, at, url, &status_text, started, 0);
    log(&sh.events, format!("WebSocket open: {url}"));
    let negotiated = crate::websocket::negotiated(&answer_head);
    // the app may want to put a frame on this connection; only this thread may write to it,
    // so it is reached through a channel and listed while it lasts
    let (tx, outbox) = channel();
    sh.ws_live.lock().unwrap_or_else(|e| e.into_inner()).push(crate::websocket::LiveLink {
        entry_id,
        host: at.host.clone(),
        path: path.to_string(),
        opened: started,
        send: tx,
    });
    let listed = Listed { links: sh.ws_live.clone(), entry_id };
    relay(sh, io, up, entry_id, at, path, &negotiated, &outbox);
    drop(listed);
    log(&sh.events, format!("WebSocket closed: {url}"));
}

/// The body of a response that refused an upgrade. Framed by `Content-Length` when it says
/// one, and otherwise read until the connection closes, which is what a refusal does.
/// Bounded by the same ceiling as any other response the proxy holds.
fn read_refusal_body<U: Read + Write>(up: &mut BufReader<U>, answer_head: &str) -> Vec<u8> {
    let mut body = Vec::new();
    match header(answer_head, "content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(n) => {
            let _ = up.take(n.min(MAX_BUFFERED)).read_to_end(&mut body);
        }
        None => {
            let _ = up.take(MAX_BUFFERED).read_to_end(&mut body);
        }
    }
    body
}

/// Record the handshake as a history entry, so the connection can be found among the traffic
/// and the messages have something to point back at.
#[allow(clippy::too_many_arguments)]
fn record_handshake(sh: &Shared, head: &str, answer_head: &str, path: &str, at: &Target, url: &str, status: &str, started: u64, length: usize) -> usize {
    let request = format!("{}\n\n", head.replace("\r\n", "\n").trim_end());
    let response = if answer_head.contains("\n\n") {
        answer_head.replace("\r\n", "\n")
    } else {
        format!("{}\n\n", answer_head.replace("\r\n", "\n").trim_end())
    };
    sh.recorder()
        .record(|id| HttpEntry {
            id,
            tool: "Proxy".into(),
            method: "GET".into(),
            host: at.host.clone(),
            path: path.to_string(),
            status: status.to_string(),
            length,
            mime: String::new(),
            request,
            response,
            url: url.to_string(),
            truncated: false,
            time: started,
            elapsed_ms: crate::http::now_ms().saturating_sub(started),
            graphql: String::new(),
        })
        .unwrap_or(0)
}

/// Carry frames both ways until one side goes away, reading a copy of each as it passes.
///
/// What goes on the wire is always the bytes that arrived, mask and all. The copy that is
/// taken apart for reading is exactly that -- a copy -- so nothing here can change what the
/// two ends of the connection say to each other.
/// Takes a connection off the live list however the relay ends, including on a panic.
struct Listed {
    links: crate::websocket::LiveLinks,
    entry_id: usize,
}

impl Drop for Listed {
    fn drop(&mut self) {
        self.links.lock().unwrap_or_else(|e| e.into_inner()).retain(|l| l.entry_id != self.entry_id);
    }
}

#[allow(clippy::too_many_arguments)]
fn relay<S, U>(sh: &Shared, io: &mut BufReader<S>, up: &mut BufReader<U>, entry_id: usize, at: &Target, path: &str, negotiated: &crate::websocket::Negotiated, outbox: &std::sync::mpsc::Receiver<Vec<u8>>)
where
    S: Read + Write + PollTimeout,
    U: Read + Write + PollTimeout,
{
    io.get_mut().set_poll_timeout(WS_POLL);
    up.get_mut().set_poll_timeout(WS_POLL);

    // Whatever the buffered readers took along with the handshake heads is already off the
    // sockets and is really the first frames. It has to be forwarded here: no later read will
    // return it, and dropping it is the bug an opaque tunnel has.
    let from_client = io.buffer().to_vec();
    io.consume(from_client.len());
    if !from_client.is_empty() && up.get_mut().write_all(&from_client).is_err() {
        return;
    }
    let from_server = up.buffer().to_vec();
    up.consume(from_server.len());
    if !from_server.is_empty() && io.get_mut().write_all(&from_server).is_err() {
        return;
    }

    // each direction compresses against a window of its own, kept for the connection unless
    // the handshake said to start afresh each message
    let mut client_side = Decoding {
        bytes: from_client,
        joiner: crate::websocket::Reassembler::new(negotiated.deflate, negotiated.client_no_context_takeover),
        lost: false,
    };
    let mut server_side = Decoding {
        bytes: from_server,
        joiner: crate::websocket::Reassembler::new(negotiated.deflate, negotiated.server_no_context_takeover),
        lost: false,
    };
    drain(sh, &mut client_side, crate::websocket::Direction::ClientToServer, entry_id, at, path);
    drain(sh, &mut server_side, crate::websocket::Direction::ServerToClient, entry_id, at, path);
    let mut buf = vec![0u8; 16 * 1024];
    let mut busy = false;

    loop {
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        let moved_before = busy;
        busy = false;
        // Each side is emptied while it still has something ready, rather than a buffer per
        // turn: one thread watches both, so a side read only once per poll would hold a
        // stream to a few hundred KB a second. The cap is what stops a busy direction
        // starving the other one.
        for _ in 0..MAX_DRAIN {
            match io.get_mut().read(&mut buf) {
                // the browser closed: nothing more will come, and the target is told by the
                // connection going down with this thread
                Ok(0) => return,
                Ok(n) => {
                    if up.get_mut().write_all(&buf[..n]).is_err() {
                        return;
                    }
                    client_side.bytes.extend_from_slice(&buf[..n]);
                    drain(sh, &mut client_side, crate::websocket::Direction::ClientToServer, entry_id, at, path);
                    busy = true;
                    // a read that did not fill the buffer has emptied the socket; asking
                    // again would only wait out the poll
                    if n < buf.len() {
                        break;
                    }
                }
                Err(e) if is_timeout(&e) => break,
                Err(_) => return,
            }
        }
        for _ in 0..MAX_DRAIN {
            match up.get_mut().read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    if io.get_mut().write_all(&buf[..n]).is_err() {
                        return;
                    }
                    server_side.bytes.extend_from_slice(&buf[..n]);
                    drain(sh, &mut server_side, crate::websocket::Direction::ServerToClient, entry_id, at, path);
                    busy = true;
                    if n < buf.len() {
                        break;
                    }
                }
                Err(e) if is_timeout(&e) => break,
                Err(_) => return,
            }
        }
        // Anything the app has composed goes out as if the browser had sent it, and is read
        // back the same way so the stream shows it -- but only between frames. Whatever is
        // left in `from_client` has already been forwarded, so it is a frame the browser is
        // still part-way through: putting another frame out now would splice it into that
        // payload and desync the connection for good. The channel holds it until the turn
        // after the frame finishes.
        while client_side.bytes.is_empty() {
            let Ok(composed) = outbox.try_recv() else { break };
            if up.get_mut().write_all(&composed).is_err() {
                return;
            }
            client_side.bytes.extend_from_slice(&composed);
            drain(sh, &mut client_side, crate::websocket::Direction::ClientToServer, entry_id, at, path);
            busy = true;
        }
        // only when it changes, so a quiet connection costs nothing to keep open
        if busy != moved_before {
            let wait = if busy { WS_POLL_BUSY } else { WS_POLL };
            io.get_mut().set_poll_timeout(wait);
            up.get_mut().set_poll_timeout(wait);
        }
    }
}

/// One direction of a connection, as it is being read.
struct Decoding {
    /// Bytes seen but not yet made into a whole frame. Everything here has already been
    /// forwarded; this is only the copy being taken apart.
    bytes: Vec<u8>,
    joiner: crate::websocket::Reassembler,
    /// Set once the thread of this direction has been lost. The relay carries on either way;
    /// what stops is reading a copy of it.
    lost: bool,
}

/// The most a direction may be sitting on before it is given up as unreadable: one frame of
/// the largest size followed, and room for the start of the next.
const MAX_PENDING: usize = crate::websocket::MAX_FRAME as usize + 64 * 1024;

/// Past this, a buffer that grew for one big frame gives the room back rather than holding it
/// for the life of the connection.
const KEEP_CAPACITY: usize = 256 * 1024;

/// Take every whole frame out of `d.bytes`, keeping the tail of a frame still arriving.
fn drain(
    sh: &Shared,
    d: &mut Decoding,
    direction: crate::websocket::Direction,
    entry_id: usize,
    at: &Target,
    path: &str,
) {
    if d.lost {
        d.bytes.clear();
        return;
    }
    // what a direction that cannot be followed any further does: say so once, and stop
    let give_up = |d: &mut Decoding, why: String| {
        log_warning(
            &sh.events,
            format!("WebSocket messages on {}{path} can no longer be followed ({why}); the connection carries on, but what it says is no longer recorded.", at.host),
        );
        d.lost = true;
        d.bytes = Vec::new();
    };
    loop {
        match crate::websocket::next_frame(&d.bytes) {
            Ok(Some((frame, used))) => {
                d.bytes.drain(..used);
                if let Some(message) = d.joiner.push(frame) {
                    record_message(sh, message, direction, entry_id, at, path);
                }
            }
            Ok(None) => {
                // a frame still arriving -- unless there is more waiting than any frame this
                // build follows could be, in which case the reading is out of step
                if d.bytes.len() > MAX_PENDING {
                    give_up(d, format!("{} bytes with no whole frame in them", d.bytes.len()));
                } else if d.bytes.is_empty() && d.bytes.capacity() > KEEP_CAPACITY {
                    d.bytes.shrink_to(KEEP_CAPACITY);
                }
                return;
            }
            Err(e) => {
                // The rest of this frame's payload is still coming and there is no way to
                // tell it from the frames after it: carrying on would read that payload as
                // headers and invent a message out of every few bytes of it.
                give_up(d, format!("{e:?}"));
                return;
            }
        }
    }
}

fn record_message(sh: &Shared, m: crate::websocket::Message, direction: crate::websocket::Direction, entry_id: usize, at: &Target, path: &str) {
    if sh.capture_paused.load(Ordering::SeqCst) {
        return;
    }
    // Everything expensive happens before the lock: rendering a megabyte of binary as hex is
    // an allocation per byte, and the window reads this store on every frame it draws.
    let length = m.payload.len();
    // text when it is text, and hex when it is not, so a reader always has something to see
    let payload = match std::str::from_utf8(&m.payload) {
        Ok(t) => t.to_string(),
        Err(_) => crate::codec::hex_encode(&m.payload),
    };
    let message = crate::websocket::WsMessage {
        id: 0,
        entry_id,
        host: at.host.clone(),
        path: path.to_string(),
        direction,
        opcode: m.opcode,
        frames: m.frames,
        compressed: m.compressed,
        truncated: m.truncated,
        length,
        payload,
        time: crate::http::now_ms(),
    };

    let limit = sh.entry_limit.load(Ordering::Relaxed).max(1);
    let mut kept = sh.ws_messages.lock().unwrap_or_else(|e| e.into_inner());
    if kept.len() >= limit {
        if sh.pause_when_full.load(Ordering::Relaxed) {
            return;
        }
        let over = kept.len() + 1 - limit;
        kept.drain(..over);
    }
    let id = {
        let mut next = sh.ws_next_id.lock().unwrap_or_else(|e| e.into_inner());
        *next += 1;
        *next
    };
    kept.push(Arc::new(crate::websocket::WsMessage { id, ..message }));
}

/// One request (its head already read from `io`): read the body, rebuild it without proxy
/// headers, apply request rules, hold it for Intercept, send it upstream, apply response
/// rules, answer the client and record it in history. With `keep_alive` the response is
/// framed (Content-Length) so the client connection can carry more requests. Returns false
/// when the connection should end.
#[allow(clippy::too_many_arguments)]
fn exchange<S: Read + Write>(sh: &Shared, io: &mut BufReader<S>, head: &str, latin1: bool, mut method: String, mut path: String, at: &Target, keep_alive: bool) -> bool {
    // what history records: the request as it is finally sent, which Intercept may have had
    // the user rewrite. The connection itself stays with `at`, which it was opened to.
    let mut host = at.host.clone();
    // a port an edited Host header carries, for the recorded URL
    let mut edited_port: Option<u16> = None;
    // body: strict Content-Length framing; read as it arrives (no allocation up front)
    let len = match request_body_length(head) {
        Ok(n) => n,
        Err((code, reason, msg)) => {
            reject(sh, io.get_mut(), code, reason, &msg);
            return false;
        }
    };
    let mut body = Vec::new();
    if io.by_ref().take(len).read_to_end(&mut body).is_err() || (body.len() as u64) < len {
        return false;
    }
    // a body that isn't UTF-8 (an upload, protobuf...) is forwarded byte for byte: the rules
    // don't touch it, and Intercept shows a placeholder in its place
    let text_body = std::str::from_utf8(&body).ok().map(String::from);
    let placeholder = format!("[binary body: {} bytes, forwarded unchanged; edits here are ignored]", body.len());
    // rebuild the request in origin form, without proxy headers, with Connection: close
    let mut lines: Vec<String> = Vec::new();
    for l in head.lines().skip(1) {
        let k = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if k.starts_with("proxy-") || k == "connection" || k == "keep-alive" {
            continue;
        }
        lines.push(l.trim_end().to_string());
    }
    lines.push("Connection: close".into());
    let headers_text = lines.join("\n");
    let rules_now = sh.rules.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (headers_text, body_text, req_warnings) = match &text_body {
        Some(t) => rewrite::apply_collecting(&rules_now, true, &headers_text, t),
        None => {
            let (h, _, w) = rewrite::apply_collecting(&rules_now, true, &headers_text, "");
            (h, placeholder.clone(), w)
        }
    };
    for w in &req_warnings {
        log_warning(&sh.events, format!("Match & Replace: {w} on {method} {}", at.url(&path)));
    }
    // the request line gets its own rules, so a path or a method can be rewritten without a
    // rule reaching the same text in a header; history then follows what the rule produced
    let first_line = rewrite::apply_first_line(&rules_now, &format!("{method} {path} HTTP/1.1"));
    let mut raw = format!("{first_line}\n{headers_text}\n\n{body_text}");
    if let Some(f) = crate::http::request_facts(&raw) {
        (method, path) = (f.method, f.path);
    }

    if should_hold(sh, &path, &at.url(&path)) {
        let (tx, rx) = channel();
        sh.held.lock().unwrap_or_else(|e| e.into_inner()).push(Held { id: next_held_id(), raw: raw.clone(), url: at.url(&path), reply: tx });
        match rx.recv() {
            Ok(Decision::Forward(edited)) => {
                raw = edited;
                // a hand-edited request line or Host header is what goes on the wire, so the
                // history row, the site map and the entry's URL follow it rather than the
                // method, path and host the request first arrived with
                if let Some(f) = crate::http::request_facts(&raw) {
                    (method, path) = (f.method, f.path);
                    if !f.host.is_empty() {
                        let (h, p) = crate::http::split_authority(&f.host);
                        host = h.trim_start_matches('[').trim_end_matches(']').to_string();
                        edited_port = p;
                    }
                }
                // the body may have been edited too. The wire gets a corrected Content-Length
                // below; this keeps the recorded request saying the same thing. A body that
                // isn't text is forwarded byte for byte, and `raw` holds only a note about it.
                if sh.fix_length.load(Ordering::SeqCst) && text_body.is_some() {
                    raw = crate::http::sync_content_length(raw);
                }
            }
            _ => {
                let msg = "Request dropped by the proxy.";
                let _ = io.get_mut().write_all(format!("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes());
                let _ = io.get_mut().flush();
                log(&sh.events, format!("Dropped {method} {}", at.url(&path)));
                return false;
            }
        }
    }

    // send upstream: CRLF line endings, header lines checked (no invalid names, no control
    // characters that could start a new line), Content-Length fixed (unless that's switched
    // off, in which case the request's own goes out as written)
    let (rhead, rbody) = raw.split_once("\n\n").unwrap_or((raw.as_str(), ""));
    let body_bytes: Vec<u8> = if text_body.is_some() { rbody.as_bytes().to_vec() } else { body.clone() };
    let fix_length = sh.fix_length.load(Ordering::SeqCst);
    let mut head_lines = rhead.lines().map(|l| l.trim_end_matches('\r'));
    let request_line = strip_controls(head_lines.next().unwrap_or(""));
    let mut out_head = vec![request_line];
    for l in head_lines {
        if fix_length && l.to_ascii_lowercase().starts_with("content-length:") {
            continue;
        }
        match sanitize_header_line(l) {
            Some(clean) => {
                if clean != l {
                    log_warning(&sh.events, format!("Removed control characters from a header of {method} {}", at.url(&path)));
                }
                out_head.push(clean);
            }
            None => log_warning(&sh.events, format!("Dropped a malformed header line from {method} {}: {:?}", at.url(&path), l.chars().take(80).collect::<String>())),
        }
    }
    if fix_length && (!body_bytes.is_empty() || len > 0) {
        out_head.push(format!("Content-Length: {}", body_bytes.len()));
    }
    let mut wire = crate::codec::encode_header_text(&out_head.join("\r\n"), latin1);
    wire.extend_from_slice(b"\r\n\r\n");
    wire.extend_from_slice(&body_bytes);
    let fail = |msg: String| {
        log_error(&sh.events, msg.clone());
        let h = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n", msg.len());
        // the browser gets our 502; history records that the target never answered
        (crate::http::CONNECTION_FAILED.to_string(), h, msg.into_bytes(), "text/plain".to_string(), None, false)
    };
    let describe = |head_s: &str| {
        let status = head_s.lines().next().unwrap_or("").splitn(2, ' ').nth(1).unwrap_or("").to_string();
        let mime = header(head_s, "content-type").unwrap_or("").split(';').next().unwrap_or("").to_string();
        (status, mime)
    };
    // `remainder`: the unread rest of a response too large to buffer
    // `resp_latin1`: the response head wasn't UTF-8 and is held as Latin-1 (sent back as the same bytes)
    #[allow(clippy::type_complexity)]
    let sent_at = std::time::Instant::now();
    let (status, resp_head, resp_body, mime, remainder, resp_latin1): (String, String, Vec<u8>, String, Option<Box<dyn Read + Send>>, bool) =
        match send_upstream(sh, at, &wire) {
            Ok(Upstream::Complete(text)) => {
                // de-chunk first: history, the rules and the client all get the plain body,
                // framed by Content-Length
                let res = crate::codec::normalize_response(crate::codec::HttpResponse::parse(&text));
                let head_s = res.head_text();
                let (status, mime) = describe(&head_s);
                (status, head_s, res.body, mime, None, res.latin1)
            }
            Ok(Upstream::Large(prefix, unread)) => match prefix.windows(4).position(|w| w == b"\r\n\r\n") {
                // forwarded as it comes (chunked or not): it can't be de-chunked or framed whole
                Some(i) => {
                    let (head_s, latin1) = crate::codec::decode_header_bytes(&prefix[..i + 4]);
                    let (status, mime) = describe(&head_s);
                    (status, head_s, prefix[i + 4..].to_vec(), mime, Some(unread), latin1)
                }
                None => fail(format!("The response head from {}:{} is larger than {} MiB", at.host, at.port, MAX_BUFFERED >> 20)),
            },
            Err(msg) => fail(msg),
        };
    let truncated = remainder.is_some();
    // response rules apply to the headers, and to a body that was buffered whole and is text;
    // a streamed (truncated) or binary body passes through unchanged, since it cannot be
    // transformed as one piece. apply_collecting keeps Content-Length honest when a body rule
    // changes the body's length.
    let resp_head_lf = resp_head.replace("\r\n", "\n");
    let (first, rest) = resp_head_lf.trim_end().split_once('\n').unwrap_or((resp_head_lf.trim_end(), ""));
    let resp_is_text = !truncated && std::str::from_utf8(&resp_body).is_ok();
    let (mut rest2, resp_body) = if resp_is_text {
        let text = String::from_utf8(resp_body).expect("checked as UTF-8 just above");
        let (h, b, warns) = rewrite::apply_collecting(&rules_now, false, rest, &text);
        for w in &warns {
            log_warning(&sh.events, format!("Match & Replace: {w} on the response to {method} {}", at.url(&path)));
        }
        (h, b.into_bytes())
    } else {
        let (h, _, warns) = rewrite::apply_collecting(&rules_now, false, rest, "");
        for w in &warns {
            log_warning(&sh.events, format!("Match & Replace: {w} on the response to {method} {}", at.url(&path)));
        }
        (h, resp_body)
    };
    if truncated {
        // the total length isn't known yet: the response ends when the connection does
        let kept: Vec<String> = rest2.lines().filter(|l| !l.to_ascii_lowercase().starts_with("connection:")).map(String::from).collect();
        rest2 = kept.join("\n") + "\nConnection: close";
    } else if keep_alive {
        // frame the body ourselves so the connection can be reused
        let has = |name: &str| rest2.lines().any(|l| l.split(':').next().is_some_and(|k| k.trim().eq_ignore_ascii_case(name)));
        let chunked = rest2.lines().any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
        let code: u16 = status.split_whitespace().next().and_then(|c| c.parse().ok()).unwrap_or(0);
        let bodyless = method.eq_ignore_ascii_case("HEAD") || code / 100 == 1 || code == 204 || code == 304;
        let mut kept: Vec<String> = rest2.lines().filter(|l| !l.to_ascii_lowercase().starts_with("connection:")).map(String::from).collect();
        if !has("content-length") && !chunked && !bodyless {
            kept.push(format!("Content-Length: {}", resp_body.len()));
        }
        kept.push("Connection: keep-alive".into());
        rest2 = kept.join("\n");
    }
    let final_head = format!("{first}\r\n{}\r\n\r\n", rest2.lines().collect::<Vec<_>>().join("\r\n")).replace("\r\n\r\n\r\n", "\r\n\r\n");
    let client = io.get_mut();
    let written = client.write_all(&crate::codec::encode_header_text(&final_head, resp_latin1)).is_ok()
        && client.write_all(&resp_body).is_ok() && client.flush().is_ok();
    let streamed = match remainder {
        Some(r) if written => stream_rest(r, client),
        _ => 0,
    };
    let length = resp_body.len() + streamed as usize;

    let shown_body = if truncated {
        format!("[Response truncated: {length} bytes, more than {} MiB, were streamed to the client but not kept]", MAX_BUFFERED >> 20)
    } else if resp_body.len() > 1024 * 1024 {
        format!("[{} bytes]", resp_body.len())
    } else {
        String::from_utf8_lossy(&resp_body).into_owned()
    };
    // `at.url` spells the authority the socket went to; an edited Host header replaces it
    let url = if host == at.host && edited_port.is_none() {
        at.url(&path)
    } else {
        Target { https: at.https, host: host.clone(), port: edited_port.unwrap_or(at.port) }.url(&path)
    };
    // the whole exchange with the target, up to the last byte of the response the proxy read
    let elapsed_ms = sent_at.elapsed().as_millis() as u64;
    // worked out here, with the request as it was finally sent, so the table can filter and
    // sort on it without re-reading every body each frame
    let graphql = crate::graphql::operation_label(&raw);
    sh.recorder().record(|id| HttpEntry {
        id,
        tool: "Proxy".into(),
        method,
        host: host.clone(),
        path: path.clone(),
        status,
        length,
        mime,
        request: raw,
        // head and body separated by a blank line, as every other tool records them: the
        // Pretty view, the Inspector and the Sequencer all find a response's body by it
        response: format!("{}\n\n{}", final_head.replace("\r\n", "\n").trim_end(), shown_body),
        url,
        truncated,
        time: crate::http::now_ms(),
        elapsed_ms,
        graphql,
    });
    // a streamed response ended the connection (it had no length to frame it by)
    written && !truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_table, MockAppBuilder};

    fn shared() -> Shared {
        Shared {
            history: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(Mutex::new(0)),
            capture_paused: Arc::new(AtomicBool::new(false)),
            entry_limit: Arc::new(std::sync::atomic::AtomicUsize::new(crate::rules::MAX_RECORDED_REQUESTS)),
            pause_when_full: Arc::new(AtomicBool::new(false)),
            intercept: Arc::new(AtomicBool::new(false)),
            held: Arc::new(Mutex::new(Vec::new())),
            rules: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(Default::default())),
            running: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            use_rules: Arc::new(AtomicBool::new(true)),
            fix_length: Arc::new(AtomicBool::new(true)),
            decrypt_https: Arc::new(AtomicBool::new(true)), // as in the app
            intercept_only_in_scope: Arc::new(AtomicBool::new(false)),
            scope: Arc::new(Mutex::new(crate::scope::TargetScope::default())),
            tls_passthrough: Arc::new(Mutex::new(Vec::new())),
            skip_extensions: Arc::new(Mutex::new(crate::rules::default_skip_extensions())),
            read_timeout_secs: Arc::new(std::sync::atomic::AtomicU64::new(120)),
            upstream_proxy: Arc::new(Mutex::new(Default::default())),
            // strict in tests, so certificate failures stay visible (the app's default is off)
            verify_upstream_tls: Arc::new(AtomicBool::new(true)),
            tls: Arc::new(Mutex::new(None)),
            upstream_tls: upstream_client_config(),
            ws_messages: Arc::new(Mutex::new(Vec::new())),
            ws_next_id: Arc::new(Mutex::new(0)),
            ws_live: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[test]
    fn interception_decision_matrix() {
        let app = MockAppBuilder::new().with_tab(crate::state::Tab::Proxy).build();
        assert_eq!(app.tab, crate::state::Tab::Proxy);

        struct HoldCase {
            name: &'static str,
            intercept: bool,
            use_rules: bool,
            skip_ext: Vec<&'static str>,
            only_in_scope: bool,
            scope_include: Vec<&'static str>,
            path: &'static str,
            url: &'static str,
            expected_hold: bool,
        }

        let default_skip: Vec<&'static str> = vec!["png", "js", "css"];
        let cases = [
            HoldCase {
                name: "master intercept off never holds",
                intercept: false,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: false,
                scope_include: vec![],
                path: "/api/login",
                url: "http://shop.test/api/login",
                expected_hold: false,
            },
            HoldCase {
                name: "intercept on holds standard API endpoint",
                intercept: true,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: false,
                scope_include: vec![],
                path: "/api/login",
                url: "http://shop.test/api/login",
                expected_hold: true,
            },
            HoldCase {
                name: "intercept on with use_rules true skips static .png extension",
                intercept: true,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: false,
                scope_include: vec![],
                path: "/logo.png",
                url: "http://shop.test/logo.png",
                expected_hold: false,
            },
            HoldCase {
                name: "intercept on with use_rules false holds static .png extension",
                intercept: true,
                use_rules: false,
                skip_ext: default_skip.clone(),
                only_in_scope: false,
                scope_include: vec![],
                path: "/logo.png",
                url: "http://shop.test/logo.png",
                expected_hold: true,
            },
            HoldCase {
                name: "custom skip list skips .json and holds .png",
                intercept: true,
                use_rules: true,
                skip_ext: vec!["json"],
                only_in_scope: false,
                scope_include: vec![],
                path: "/data.json",
                url: "http://shop.test/data.json",
                expected_hold: false,
            },
            HoldCase {
                name: "custom skip list without png holds .png",
                intercept: true,
                use_rules: true,
                skip_ext: vec!["json"],
                only_in_scope: false,
                scope_include: vec![],
                path: "/logo.png",
                url: "http://shop.test/logo.png",
                expected_hold: true,
            },
            HoldCase {
                name: "only_in_scope holds matching in-scope URL",
                intercept: true,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: true,
                scope_include: vec!["http://shop.test/in"],
                path: "/in/page",
                url: "http://shop.test/in/page",
                expected_hold: true,
            },
            HoldCase {
                name: "only_in_scope forwards out-of-scope URL without holding",
                intercept: true,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: true,
                scope_include: vec!["http://shop.test/in"],
                path: "/out",
                url: "http://shop.test/out",
                expected_hold: false,
            },
            HoldCase {
                name: "only_in_scope disabled holds out-of-scope URL",
                intercept: true,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: false,
                scope_include: vec!["http://shop.test/in"],
                path: "/out",
                url: "http://shop.test/out",
                expected_hold: true,
            },
            HoldCase {
                name: "only_in_scope with empty scope holds everything",
                intercept: true,
                use_rules: true,
                skip_ext: default_skip.clone(),
                only_in_scope: true,
                scope_include: vec![],
                path: "/anything",
                url: "http://shop.test/anything",
                expected_hold: true,
            },
        ];

        assert_table!(cases, |case| {
            let sh = shared();
            sh.intercept.store(case.intercept, Ordering::SeqCst);
            sh.use_rules.store(case.use_rules, Ordering::SeqCst);
            *sh.skip_extensions.lock().unwrap() = case.skip_ext.iter().map(|s| s.to_string()).collect();
            sh.intercept_only_in_scope.store(case.only_in_scope, Ordering::SeqCst);
            for rule in &case.scope_include {
                sh.scope.lock().unwrap().include.push(crate::scope::ScopeRule::new(*rule));
            }
            assert_eq!(
                should_hold(&sh, case.path, case.url),
                case.expected_hold,
                "case '{}'",
                case.name
            );
        });
    }

    /// One-shot upstream server that echoes the request line back in the body.
    fn upstream() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let head = read_head(&mut r).unwrap_or_default();
                let first = head.lines().next().unwrap_or("").to_string();
                let body = format!("got {first}");
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        port
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn through_proxy(proxy_port: u16, target: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        c.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\nProxy-Connection: keep-alive\r\n\r\n").as_bytes()).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    }

    #[test]
    fn forwards_and_records_traffic() {
        let up = upstream();
        let sh = shared();
        sh.rules.lock().unwrap().push(crate::rewrite::Rule {
            enabled: true, case_sensitive: true, kind: crate::rewrite::RuleType::ResponseHeader, regex: true,
            match_text: "^Set-Cookie.*$".into(), replace_text: String::new(), comment: String::new(),
            ..Default::default()
        });
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/hello?x=1"));
        assert!(resp.contains("got GET /hello?x=1 HTTP/1.1"), "{resp}");
        assert!(!resp.contains("Set-Cookie"), "response rule should remove the cookie header");
        let h = sh.history.lock().unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].status, "200 OK");
        assert_eq!(h[0].path, "/hello?x=1");
        assert!(!h[0].request.to_ascii_lowercase().contains("proxy-connection"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// Logger's capture switch holds for the proxy as it does for the tools: while it is on,
    /// traffic is forwarded exactly as before and none of it is recorded. `upstream` answers
    /// two requests, which is one paused and one recorded.
    #[test]
    fn paused_capture_forwards_traffic_without_recording_it() {
        let up = upstream();
        let sh = shared();
        sh.capture_paused.store(true, Ordering::SeqCst);
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/while-paused"));
        assert!(resp.contains("got GET /while-paused HTTP/1.1"), "the browser still got its response: {resp}");
        assert!(sh.history.lock().unwrap().is_empty(), "and nothing was recorded");
        assert_eq!(*sh.next_id.lock().unwrap(), 0, "nor was an entry id spent");

        sh.capture_paused.store(false, Ordering::SeqCst);
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/after-resuming"));
        assert!(resp.contains("got GET /after-resuming HTTP/1.1"), "{resp}");
        let h = sh.history.lock().unwrap();
        assert_eq!(h.len(), 1, "recording picked up again");
        assert_eq!(h[0].path, "/after-resuming");
        drop(h);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn intercept_holds_then_forwards_edited_request() {
        let up = upstream();
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let target = format!("http://127.0.0.1:{up}/original");
        let t = std::thread::spawn(move || through_proxy(pp, &target));
        let mut waited = 0;
        while sh.held.lock().unwrap().is_empty() && waited < 200 {
            std::thread::sleep(Duration::from_millis(20));
            waited += 1;
        }
        let h = sh.held.lock().unwrap().remove(0);
        assert_eq!(h.url, format!("http://127.0.0.1:{up}/original"));
        let edited = h.raw.replace("/original", "/edited");
        h.reply.send(Decision::Forward(edited)).unwrap();
        let resp = t.join().unwrap();
        assert!(resp.contains("got GET /edited HTTP/1.1"), "{resp}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// An upstream that keeps the whole request it was sent, head and body, so a test can see
    /// exactly what the proxy put on the wire.
    fn recording_upstream() -> (u16, Arc<Mutex<String>>) {
        let seen = Arc::new(Mutex::new(String::new()));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let out = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let head = read_head(&mut r).unwrap_or_default();
                let len: usize = header(&head, "content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                *out.lock().unwrap_or_else(|e| e.into_inner()) = format!("{head}\n{}", String::from_utf8_lossy(&body));
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");
            }
        });
        (port, seen)
    }

    /// Hold `request` for Intercept, hand `edit` the held text and forward what it returns.
    /// Gives back the recorded history entry.
    fn forward_edited(request: impl FnOnce(u16, u16) -> std::thread::JoinHandle<String>, edit: impl FnOnce(String) -> String, up: u16) -> HttpEntry {
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let t = request(pp, up);
        assert!(gets_held(&sh), "the request was held");
        let h = sh.held.lock().unwrap().remove(0);
        h.reply.send(Decision::Forward(edit(h.raw))).unwrap();
        let _ = t.join().unwrap();
        sh.stop.store(true, Ordering::SeqCst);
        let entry = sh.history.lock().unwrap().first().map(|e| (**e).clone());
        entry.expect("the forwarded request was recorded")
    }

    /// A request rewritten while it was held is recorded as it was sent, not as it arrived:
    /// the history table, the site map and the entry's URL all follow the edited request line
    /// and Host header. Before this, a request tampered into `/admin` still read `/original`.
    #[test]
    fn forwarding_an_edited_request_records_its_new_method_path_and_host() {
        let up = upstream();
        let entry = forward_edited(
            |pp, up| send_async(pp, up, "/original"),
            |raw| raw.replace("GET /original HTTP/1.1", "DELETE /admin/users/7?force=1 HTTP/1.1").replace("Host: x", "Host: shop.internal:8080"),
            up,
        );
        assert_eq!(entry.method, "DELETE", "the method the table shows");
        assert_eq!(entry.path, "/admin/users/7?force=1", "the path the table shows");
        assert_eq!(entry.host, "shop.internal", "the host the table and the site map group it under");
        assert_eq!(entry.url, "http://shop.internal:8080/admin/users/7?force=1", "and the URL built from both");
    }

    /// An edited body goes upstream with a Content-Length that matches it, and the request
    /// kept in history says the same thing rather than the length the browser first sent.
    #[test]
    fn forwarding_an_edited_body_corrects_content_length_on_the_wire_and_in_history() {
        let (up, seen) = recording_upstream();
        let longer = "the body this request was edited to carry";
        let entry = forward_edited(
            |pp, up| {
                let target = format!("http://127.0.0.1:{up}/pay");
                let body = "short".to_string();
                std::thread::spawn(move || post_through_proxy(pp, &target, &body))
            },
            |raw| raw.replace("short", longer),
            up,
        );
        let want = format!("Content-Length: {}", longer.len());
        let sent = seen.lock().unwrap().clone();
        assert!(sent.contains(&want), "the wire carries the corrected length: {sent:?}");
        assert!(sent.ends_with(longer), "and the edited body in full: {sent:?}");
        assert!(entry.request.contains(&want), "history agrees with it: {:?}", entry.request);
        assert!(entry.request.ends_with(longer), "and keeps the edited body: {:?}", entry.request);
    }

    /// POST `body` to `target` through the proxy on another thread.
    fn post_through_proxy(proxy_port: u16, target: &str, body: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        let head = format!("POST {target} HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n", body.len());
        c.write_all(head.as_bytes()).unwrap();
        c.write_all(body.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    }

    /// A recorded response has to be a message: head, blank line, body. Everything that reads
    /// one back finds the body by that blank line -- the Pretty view, the Inspector's body
    /// parameters, the Sequencer's token extraction -- so a response recorded without it reads
    /// as one long head with no body at all, and Pretty leaves it exactly as it found it.
    #[test]
    fn a_recorded_response_keeps_the_blank_line_before_its_body() {
        let body = r#"{"order":8821,"items":[{"sku":"A-1"}]}"#;
        let up = json_upstream(body);
        let sh = shared();
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let _ = through_proxy(pp, &format!("http://127.0.0.1:{up}/v1/orders"));
        let entry = sh.history.lock().unwrap().first().cloned().expect("the exchange was recorded");
        sh.stop.store(true, Ordering::SeqCst);

        let (head, found) = entry.response.split_once("\n\n").expect("head and body are separated");
        assert!(head.starts_with("HTTP/1.1 200 OK"), "the head is the response head: {head:?}");
        assert_eq!(found, body, "and the body is the body");
        // which is what lets Pretty recognise it and lay it out
        let (pretty, kind) = crate::viewer::pretty_message(&entry.response);
        assert_eq!(kind, crate::viewer::BodyKind::Json, "Pretty sees JSON: {:?}", entry.response);
        assert!(pretty.contains("\n  \"order\": 8821,"), "and indents it: {pretty:?}");
        // the request side has always been a whole message; it stays one
        assert!(entry.request.contains("\n\n"), "the request too: {:?}", entry.request);
    }

    /// An upstream that answers every request with the same JSON body.
    fn json_upstream(body: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let _ = read_head(&mut r);
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        port
    }

    /// A "Request first line" rule rewrites the line that goes upstream, and the history row
    /// and site map follow it: the entry's method, path and URL are re-read from the request
    /// as the rule left it, not as the browser sent it.
    #[test]
    fn a_first_line_rule_rewrites_the_wire_and_the_recorded_metadata() {
        let (up, seen) = recording_upstream();
        let sh = shared();
        sh.rules.lock().unwrap().push(crate::rewrite::Rule {
            enabled: true, case_sensitive: true, kind: crate::rewrite::RuleType::RequestFirstLine,
            regex: true, match_text: "^GET /api/v1/".into(), replace_text: "POST /api/v2/".into(),
            comment: String::new(),
            ..Default::default()
        });
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let _ = through_proxy(pp, &format!("http://127.0.0.1:{up}/api/v1/users?page=2"));
        let entry = sh.history.lock().unwrap().first().cloned().expect("the exchange was recorded");
        sh.stop.store(true, Ordering::SeqCst);

        let sent = seen.lock().unwrap().clone();
        assert!(sent.starts_with("POST /api/v2/users?page=2 HTTP/1.1"), "the wire carries the rewritten line: {sent:?}");
        // `through_proxy` sends "Host: x"; the rule had no business touching it
        assert!(sent.contains("\r\nHost: x\r\n"), "and the headers it always had: {sent:?}");
        assert_eq!(entry.method, "POST", "the table shows the method the rule produced");
        assert_eq!(entry.path, "/api/v2/users?page=2", "and the path");
        assert_eq!(entry.url, format!("http://127.0.0.1:{up}/api/v2/users?page=2"), "and the URL built from it");
        assert!(entry.request.starts_with("POST /api/v2/users?page=2 HTTP/1.1"), "as does the request kept with it");
    }

    /// Send `path` through the proxy on another thread; returns its join handle.
    fn send_async(pp: u16, up: u16, path: &str) -> std::thread::JoinHandle<String> {
        let target = format!("http://127.0.0.1:{up}{path}");
        std::thread::spawn(move || through_proxy(pp, &target))
    }

    /// Wait up to ~1s for a request to be held; true if one was.
    fn gets_held(sh: &Shared) -> bool {
        for _ in 0..50 {
            if !sh.held.lock().unwrap().is_empty() { return true; }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn intercepting_proxy(only_in_scope: bool, include: Option<String>) -> (Shared, u16) {
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        sh.intercept_only_in_scope.store(only_in_scope, Ordering::SeqCst);
        if let Some(prefix) = include {
            sh.scope.lock().unwrap().include.push(crate::scope::ScopeRule::new(prefix));
        }
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        (sh, pp)
    }

    #[test]
    fn only_in_scope_holds_in_scope_and_forwards_the_rest() {
        let up = upstream();
        let (sh, pp) = intercepting_proxy(true, Some(format!("http://127.0.0.1:{}/in", up)));
        // out of scope: answered without being held, and still recorded
        let out = send_async(pp, up, "/out");
        assert!(!gets_held(&sh), "an out-of-scope request must not be held");
        assert!(out.join().unwrap().contains("got GET /out HTTP/1.1"));
        // in scope: held until forwarded
        let inside = send_async(pp, up, "/in/page");
        assert!(gets_held(&sh), "an in-scope request is held");
        let h = sh.held.lock().unwrap().remove(0);
        assert!(h.raw.starts_with("GET /in/page HTTP/1.1"));
        h.reply.send(Decision::Forward(h.raw.clone())).unwrap();
        assert!(inside.join().unwrap().contains("got GET /in/page HTTP/1.1"));
        let paths: Vec<String> = sh.history.lock().unwrap().iter().map(|e| e.path.clone()).collect();
        assert_eq!(paths, ["/out", "/in/page"]);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn without_only_in_scope_everything_is_held() {
        let up = upstream();
        let (sh, pp) = intercepting_proxy(false, Some(format!("http://127.0.0.1:{}/in", up)));
        let out = send_async(pp, up, "/out");
        assert!(gets_held(&sh), "out of scope, but the switch is off: held");
        let h = sh.held.lock().unwrap().remove(0);
        h.reply.send(Decision::Forward(h.raw.clone())).unwrap();
        assert!(out.join().unwrap().contains("got GET /out"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn only_in_scope_with_an_empty_scope_holds_everything() {
        let up = upstream();
        let (sh, pp) = intercepting_proxy(true, None);
        let any = send_async(pp, up, "/anything");
        assert!(gets_held(&sh), "an empty scope includes everything");
        let h = sh.held.lock().unwrap().remove(0);
        h.reply.send(Decision::Drop).unwrap();
        assert!(any.join().unwrap().starts_with("HTTP/1.1 403"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn interception_rules_switch() {
        let up = upstream();
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // rules on: an image passes straight through
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/logo.png"));
        assert!(resp.contains("got GET /logo.png"), "{resp}");
        assert!(sh.held.lock().unwrap().is_empty());
        // rules off: the same request is held
        sh.use_rules.store(false, Ordering::SeqCst);
        let target = format!("http://127.0.0.1:{up}/logo.png");
        let t = std::thread::spawn(move || through_proxy(pp, &target));
        let mut waited = 0;
        while sh.held.lock().unwrap().is_empty() && waited < 200 {
            std::thread::sleep(Duration::from_millis(20));
            waited += 1;
        }
        let h = sh.held.lock().unwrap().remove(0);
        h.reply.send(Decision::Forward(h.raw.clone())).unwrap();
        assert!(t.join().unwrap().contains("got GET /logo.png"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// Upstream that answers with the Content-Length header it received.
    fn length_echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let head = read_head(&mut r).unwrap_or_default();
                let body = format!("len={}", header(&head, "content-length").unwrap_or("none"));
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        port
    }

    #[test]
    fn content_length_switch() {
        let up = length_echo();
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        sh.use_rules.store(false, Ordering::SeqCst);
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // the held request's body is edited from "ab" to "abcd" while its header still says 2
        let send = |sh: &Shared| {
            let target = format!("http://127.0.0.1:{up}/p");
            let t = std::thread::spawn(move || {
                let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
                c.write_all(format!("POST {target} HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nab").as_bytes()).unwrap();
                let mut out = String::new();
                let _ = c.read_to_string(&mut out);
                out
            });
            let mut waited = 0;
            while sh.held.lock().unwrap().is_empty() && waited < 200 {
                std::thread::sleep(Duration::from_millis(20));
                waited += 1;
            }
            let h = sh.held.lock().unwrap().remove(0);
            let edited = h.raw.replace("\n\nab", "\n\nabcd");
            h.reply.send(Decision::Forward(edited)).unwrap();
            t.join().unwrap()
        };
        assert!(send(&sh).contains("len=4"), "on: recalculated from the edited body");
        sh.fix_length.store(false, Ordering::SeqCst);
        assert!(send(&sh).contains("len=2"), "off: the header goes out as written");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// Send `head` through the proxy and return what came back.
    fn raw_through(proxy_port: u16, head: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(head.as_bytes()).unwrap();
        let mut buf = [0u8; 256];
        let n = c.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn connect_tunnels_record_their_200() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let tport = target.local_addr().unwrap().port();
        let sh = shared();
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let reply = raw_through(pp, &format!("CONNECT 127.0.0.1:{tport} HTTP/1.1\r\nHost: 127.0.0.1:{tport}\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 200 Connection established"), "{reply}");
        let mut waited = 0;
        while sh.history.lock().unwrap().is_empty() && waited < 100 {
            std::thread::sleep(Duration::from_millis(20));
            waited += 1;
        }
        let h = sh.history.lock().unwrap();
        assert_eq!(h[0].method, "CONNECT");
        assert_eq!(h[0].status, "200 (Tunnel)");
        assert_eq!(h[0].status_code(), Some(200));
        drop(h);
        drop(target);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn failed_connections_record_no_status() {
        let dead = free_port(); // nothing listens here
        let sh = shared();
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // the browser still gets a 502 from the proxy...
        let reply = raw_through(pp, &format!("CONNECT 127.0.0.1:{dead} HTTP/1.1\r\nHost: 127.0.0.1:{dead}\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{dead}/x"));
        assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
        // ...but history records that the target never answered
        let mut waited = 0;
        while sh.history.lock().unwrap().len() < 2 && waited < 100 {
            std::thread::sleep(Duration::from_millis(20));
            waited += 1;
        }
        let h = sh.history.lock().unwrap();
        assert_eq!(h.len(), 2);
        for e in h.iter() {
            assert_eq!(e.status, crate::http::CONNECTION_FAILED, "{} {}", e.method, e.url);
            assert_eq!(e.status_code(), None);
        }
        drop(h);
        sh.stop.store(true, Ordering::SeqCst);
    }

    // ---- HTTPS interception ----

    use crate::ca::{CertificateAuthority, TlsConfigCache};

    /// A local HTTPS server (certificate for 127.0.0.1 from `ca`) answering each request
    /// with "got <request line>" and closing, without Content-Length: the proxy must frame it.
    fn mock_https(ca: Arc<CertificateAuthority>, connections: usize) -> u16 {
        mock_https_with(ca, connections, false)
    }

    /// `mock_https`, optionally answering with a chunked body.
    fn mock_https_with(ca: Arc<CertificateAuthority>, connections: usize, chunked: bool) -> u16 {
        let cfg = TlsConfigCache::new(ca).get_server_config("127.0.0.1").unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(connections) {
                let Ok(s) = s else { continue };
                let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                let mut io = BufReader::new(rustls::StreamOwned::new(conn, s));
                let Some(head) = read_head(&mut io) else { continue };
                let len: usize = header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                let mut body = vec![0u8; len];
                let _ = io.read_exact(&mut body);
                let first = head.lines().next().unwrap_or("").to_string();
                let reply = format!("got {first} body={}", String::from_utf8_lossy(&body));
                let tls = io.get_mut();
                let resp = if chunked {
                    let (a, b) = reply.split_at(reply.len() / 2);
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x};ext=1\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n", a.len(), b.len())
                } else {
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{reply}")
                };
                let _ = tls.write_all(resp.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        port
    }

    /// CONNECT through the proxy, then TLS as `name` with a client trusting only `root`.
    fn https_client(proxy_port: u16, target: &str, name: &str, root: &CertificateAuthority) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
        let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).unwrap();
        // read exactly the CONNECT reply, byte by byte, so no TLS bytes are swallowed
        let mut reply = Vec::new();
        let mut b = [0u8; 1];
        while !reply.ends_with(b"\r\n\r\n") {
            if c.read(&mut b).unwrap_or(0) == 0 { return Err("proxy closed".into()); }
            reply.push(b[0]);
        }
        assert!(reply.starts_with(b"HTTP/1.1 200 Connection established"), "{}", String::from_utf8_lossy(&reply));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls_pki_types::CertificateDer::from(root.ca_cert_der.clone())).unwrap();
        let conn = rustls::ClientConnection::new(client_config_with(roots), rustls_pki_types::ServerName::try_from(name.to_string()).unwrap()).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, c);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(|e| e.to_string())?;
        }
        Ok(tls)
    }

    /// Send one request over `tls` and read one Content-Length-framed response.
    fn https_round_trip(tls: &mut BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>, req: &str) -> (String, String) {
        tls.get_mut().write_all(req.as_bytes()).unwrap();
        tls.get_mut().flush().unwrap();
        let head = read_head(tls).expect("response head");
        let len: usize = header(&head, "content-length").and_then(|v| v.parse().ok()).expect("framed with Content-Length");
        let mut body = vec![0u8; len];
        tls.read_exact(&mut body).unwrap();
        (head, String::from_utf8(body).unwrap())
    }

    fn wait_for(cond: impl Fn() -> bool) {
        for _ in 0..250 {
            if cond() { return; }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out");
    }

    /// A proxy that intercepts HTTPS with `ca`, trusting `upstream_root` for real servers.
    fn mitm_proxy(ca: Arc<CertificateAuthority>, upstream_root: Option<&CertificateAuthority>) -> (Shared, u16) {
        let mut sh = shared();
        sh.decrypt_https.store(true, Ordering::SeqCst);
        *sh.tls.lock().unwrap() = Some(Arc::new(TlsConfigCache::new(ca)));
        if let Some(root) = upstream_root {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls_pki_types::CertificateDer::from(root.ca_cert_der.clone())).unwrap();
            sh.upstream_tls = client_config_with(roots);
        }
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        (sh, pp)
    }

    /// A WebSocket target that speaks TLS: the same mock, behind a certificate.
    fn ws_target_https(ca: Arc<CertificateAuthority>) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        let cfg = TlsConfigCache::new(ca).get_server_config("127.0.0.1").unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let Some(Ok(s)) = l.incoming().next() else { return };
            let Ok(conn) = rustls::ServerConnection::new(cfg) else { return };
            let mut io = BufReader::new(rustls::StreamOwned::new(conn, s));
            let Some(head) = read_head(&mut io) else { return };
            let _ = tx.send(head.clone().into_bytes());
            let key = head
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-key")))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let accept = crate::websocket::accept_key(&key);
            let tls = io.get_mut();
            let _ = tls.write_all(
                format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes(),
            );
            let _ = tls.write_all(&ws_frame(0x1, b"over tls", None));
            let _ = tls.flush();
            let mut buf = [0u8; 1024];
            loop {
                match io.get_mut().read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (port, rx)
    }

    /// The same upgrade, inside a decrypted tunnel. A TLS connection cannot be split between
    /// two threads, so this is the path the relay's one-thread design exists for.
    #[test]
    fn a_websocket_upgrade_inside_a_decrypted_tunnel_is_relayed_and_recorded() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let (target, received) = ws_target_https(server_ca.clone());
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), Some(&server_ca));

        let mut tls = https_client(pp, &format!("127.0.0.1:{target}"), "127.0.0.1", &proxy_ca).expect("tunnel");
        tls.write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        tls.flush().unwrap();

        let mut head = Vec::new();
        let mut one = [0u8; 1];
        while tls.read_exact(&mut one).is_ok() {
            head.push(one[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{:?}", String::from_utf8_lossy(&head));

        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], ws_frame(0x1, b"over tls", None).as_slice(), "the target's frame came through the tunnel byte for byte");

        let client_frame = ws_frame(0x1, b"browser inside tls", Some([4, 3, 2, 1]));
        tls.write_all(&client_frame).unwrap();
        tls.flush().unwrap();
        let _handshake = received.recv_timeout(Duration::from_secs(5)).unwrap();
        let got = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, client_frame, "and the browser's went the other way, mask and all");

        wait_for(|| sh.ws_messages.lock().unwrap().len() >= 2);
        let payloads: Vec<String> = sh.ws_messages.lock().unwrap().iter().map(|m| m.payload.clone()).collect();
        assert!(payloads.contains(&"over tls".to_string()), "{payloads:?}");
        assert!(payloads.contains(&"browser inside tls".to_string()), "{payloads:?}");
        let hist = sh.history.lock().unwrap().clone();
        assert!(hist.iter().any(|e| e.status.starts_with("101") && e.url.starts_with("https://")), "recorded as an https handshake");
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn https_is_decrypted_forwarded_and_recorded() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let up = mock_https(server_ca.clone(), 2);
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), Some(&server_ca));
        // a request rule: add a header to every request
        sh.rules.lock().unwrap().push(crate::rewrite::Rule {
            enabled: true, case_sensitive: true, kind: crate::rewrite::RuleType::RequestHeader, regex: false,
            match_text: String::new(), replace_text: "X-Forge: yes".into(), comment: String::new(),
            ..Default::default()
        });
        let tls = https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).expect("client trusts the proxy's certificate");
        let mut io = BufReader::new(tls);
        // two requests on one connection (keep-alive through the proxy)
        let (h1, b1) = https_round_trip(&mut io, &format!("GET /one?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\n\r\n"));
        assert!(h1.starts_with("HTTP/1.1 200 OK"), "{h1}");
        assert!(h1.to_ascii_lowercase().contains("connection: keep-alive"));
        assert_eq!(b1, "got GET /one?x=1 HTTP/1.1 body=");
        let (_, b2) = https_round_trip(&mut io, &format!("POST /two HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\nContent-Length: 5\r\n\r\nhello"));
        assert_eq!(b2, "got POST /two HTTP/1.1 body=hello");
        wait_for(|| sh.history.lock().unwrap().len() == 2);
        let h = sh.history.lock().unwrap();
        assert_eq!(h[0].url, format!("https://127.0.0.1:{up}/one?x=1"));
        assert_eq!((h[0].method.as_str(), h[0].status.as_str(), h[0].mime.as_str()), ("GET", "200 OK", "text/plain"));
        assert_eq!(h[1].url, format!("https://127.0.0.1:{up}/two"));
        assert_eq!(h[1].length, b2.len());
        assert!(h[1].request.contains("hello"), "decrypted body recorded");
        assert!(h[0].request.contains("X-Forge: yes"), "request rules apply to HTTPS too");
        assert!(h.iter().all(|e| e.method != "CONNECT"), "no opaque tunnel entry");
        drop(h);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn chunked_https_responses_are_dechunked() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let up = mock_https_with(server_ca.clone(), 2, true);
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), Some(&server_ca));
        let mut io = BufReader::new(https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).unwrap());
        // two requests on the kept-alive connection: each answer is framed by Content-Length
        for path in ["/a", "/b"] {
            let (head, body) = https_round_trip(&mut io, &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
            assert!(!head.to_ascii_lowercase().contains("transfer-encoding"), "{head}");
            assert_eq!(body, format!("got GET {path} HTTP/1.1 body="));
        }
        wait_for(|| sh.history.lock().unwrap().len() == 2);
        let h = sh.history.lock().unwrap();
        assert!(h[0].response.ends_with("got GET /a HTTP/1.1 body="), "history keeps the plain body: {}", h[0].response);
        assert_eq!(h[0].length, "got GET /a HTTP/1.1 body=".len());
        drop(h);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn chunked_http_responses_are_dechunked() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let up = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = l.incoming().next() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let _ = read_head(&mut r);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
            }
        });
        let sh = shared();
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/w"));
        assert!(resp.contains("Content-Length: 9\r\n") && resp.ends_with("\r\n\r\nWikipedia"), "{resp}");
        assert!(!resp.to_ascii_lowercase().contains("transfer-encoding"));
        wait_for(|| !sh.history.lock().unwrap().is_empty());
        let h = sh.history.lock().unwrap();
        assert_eq!(h[0].length, 9);
        assert!(h[0].response.ends_with("\nWikipedia"));
        drop(h);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn held_https_requests_show_their_https_url() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let up = mock_https(server_ca.clone(), 1);
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), Some(&server_ca));
        sh.intercept.store(true, Ordering::SeqCst);
        let t = std::thread::spawn(move || {
            let mut io = BufReader::new(https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).unwrap());
            https_round_trip(&mut io, "GET /account?id=7 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").1
        });
        wait_for(|| !sh.held.lock().unwrap().is_empty());
        let h = sh.held.lock().unwrap().remove(0);
        assert_eq!(h.url, format!("https://127.0.0.1:{up}/account?id=7"), "the decrypted request's real scheme");
        h.reply.send(Decision::Forward(h.raw.clone())).unwrap();
        assert!(t.join().unwrap().starts_with("got GET /account?id=7"));
        // and on the default port the port is left out
        assert_eq!(Target { https: true, host: "shop.test".into(), port: 443 }.url("/cart"), "https://shop.test/cart");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A response body of `n` bytes of a repeating pattern (so corruption would show).
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn huge_responses_are_streamed_not_buffered() {
        let size = MAX_BUFFERED as usize + 8 * 1024 * 1024;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let up = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = l.incoming().next() {
                let _ = read_head(&mut BufReader::new(s.try_clone().unwrap()));
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n").as_bytes());
                let _ = s.write_all(&pattern(size));
            }
        });
        let sh = shared();
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        c.write_all(format!("GET http://127.0.0.1:{up}/big HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        let split = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&got[..split]).to_ascii_lowercase();
        assert!(head.contains(&format!("content-length: {size}")) && head.contains("connection: close"), "{head}");
        assert!(got[split..] == pattern(size)[..], "every byte arrives, in order");
        wait_for(|| !sh.history.lock().unwrap().is_empty());
        let h = sh.history.lock().unwrap();
        assert!(h[0].truncated);
        assert_eq!(h[0].length, size);
        assert!(h[0].response.contains("[Response truncated:") && h[0].response.len() < 4096, "history keeps the head and a note, not the body");
        drop(h);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn huge_https_response_ends_the_kept_alive_connection() {
        let size = MAX_BUFFERED as usize + 1024 * 1024;
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let cfg = TlsConfigCache::new(server_ca.clone()).get_server_config("127.0.0.1").unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let up = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(s)) = l.incoming().next() {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut io = BufReader::new(rustls::StreamOwned::new(conn, s));
                let _ = read_head(&mut io);
                // close-delimited: no Content-Length
                let tls = io.get_mut();
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n");
                let _ = tls.write_all(&pattern(size));
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), Some(&server_ca));
        let mut tls = https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).unwrap();
        tls.sock.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        tls.write_all(b"GET /big HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut got = Vec::new();
        // the proxy ends the connection after the stream (with or without close_notify)
        let _ = tls.read_to_end(&mut got);
        let split = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(String::from_utf8_lossy(&got[..split]).to_ascii_lowercase().contains("connection: close"));
        assert_eq!(got.len() - split, size);
        assert!(got[split..] == pattern(size)[..]);
        wait_for(|| !sh.history.lock().unwrap().is_empty());
        assert!(sh.history.lock().unwrap()[0].truncated);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn untrusted_proxy_certificate_is_logged() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let other = CertificateAuthority::generate().unwrap();
        let (sh, pp) = mitm_proxy(proxy_ca, None);
        // the client trusts a different root: it rejects the proxy's certificate
        assert!(https_client(pp, "127.0.0.1:9", "127.0.0.1", &other).is_err());
        wait_for(|| sh.events.lock().unwrap().iter().any(|e| e.level == Level::Error && e.message.contains("TLS handshake with the client failed")));
        assert!(sh.history.lock().unwrap().is_empty());
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn unverifiable_server_gets_502() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let up = mock_https(server_ca, 1);
        // the proxy verifies servers with the real web roots, which don't include server_ca
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), None);
        let tls = https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).unwrap();
        let mut io = BufReader::new(tls);
        let (head, body) = https_round_trip(&mut io, "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 502 Bad Gateway"), "{head}");
        assert!(body.contains("TLS connection to 127.0.0.1"), "{body}");
        wait_for(|| sh.history.lock().unwrap().len() == 1);
        assert_eq!(sh.history.lock().unwrap()[0].status, crate::http::CONNECTION_FAILED);
        assert!(sh.events.lock().unwrap().iter().any(|e| e.level == Level::Error && e.message.contains("TLS connection to")));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn https_passes_through_when_interception_is_off() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let tport = target.local_addr().unwrap().port();
        let (sh, pp) = mitm_proxy(Arc::new(CertificateAuthority::generate().unwrap()), None);
        sh.decrypt_https.store(false, Ordering::SeqCst);
        let reply = raw_through(pp, &format!("CONNECT 127.0.0.1:{tport} HTTP/1.1\r\nHost: 127.0.0.1:{tport}\r\n\r\n"));
        assert!(reply.starts_with("HTTP/1.1 200 Connection established"));
        wait_for(|| !sh.history.lock().unwrap().is_empty());
        assert_eq!(sh.history.lock().unwrap()[0].status, "200 (Tunnel)");
        drop(target);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn connect_and_tunneling_matrix() {
        // 1. CONNECT Authority Extraction & Target URL Formatting Matrix
        struct AuthorityCase {
            name: &'static str,
            raw_authority: &'static str,
            https: bool,
            path: &'static str,
            expected_host: &'static str,
            expected_port: u16,
            expected_url: &'static str,
        }

        let auth_cases = [
            AuthorityCase {
                name: "explicit non-standard HTTPS port",
                raw_authority: "shop.test:8443",
                https: true,
                path: "/",
                expected_host: "shop.test",
                expected_port: 8443,
                expected_url: "https://shop.test:8443/",
            },
            AuthorityCase {
                name: "implicit default HTTPS port 443 omitted in URL",
                raw_authority: "shop.test",
                https: true,
                path: "/cart",
                expected_host: "shop.test",
                expected_port: 443,
                expected_url: "https://shop.test/cart",
            },
            AuthorityCase {
                name: "IPv6 authority with explicit port",
                raw_authority: "[::1]:9000",
                https: true,
                path: "/a",
                expected_host: "::1",
                expected_port: 9000,
                expected_url: "https://[::1]:9000/a",
            },
            AuthorityCase {
                name: "IPv6 authority on default HTTPS port 443",
                raw_authority: "[::1]:443",
                https: true,
                path: "/a",
                expected_host: "::1",
                expected_port: 443,
                expected_url: "https://[::1]/a",
            },
        ];

        assert_table!(auth_cases, |case| {
            let (host, port) = split_authority(case.raw_authority);
            assert_eq!(host, case.expected_host, "case '{}' host", case.name);
            assert_eq!(port, case.expected_port, "case '{}' port", case.name);
            let target = Target { https: case.https, host, port };
            assert_eq!(target.url(case.path), case.expected_url, "case '{}' url", case.name);
        });

        // 2. Absolute HTTP Target Splitting & Upstream Absolute-Form Rewriting Matrix
        let split_cases = [
            ("explicit port and query", "http://a.test:8000/x?y=1", Some(("a.test".into(), 8000u16, "/x?y=1".into()))),
            ("default port 80 and bare host", "http://a.test", Some(("a.test".into(), 80u16, "/".into()))),
            ("relative origin-form path returns None", "/relative", None),
        ];
        assert_table!(split_cases, |(name, input, expected)| {
            assert_eq!(split_target(input), expected, "{name}");
        });

        let abs_cases = [
            (
                "IPv4 target rewrites origin-form GET into absolute-form for upstream proxy",
                Target { https: false, host: "a.test".into(), port: 8081 },
                &b"GET /x?y=1 HTTP/1.1\r\nHost: a.test\r\n\r\n"[..],
                &b"GET http://a.test:8081/x?y=1 HTTP/1.1\r\nHost: a.test\r\n\r\n"[..],
            ),
            (
                "IPv6 target wraps host in brackets in absolute-form request line",
                Target { https: false, host: "::1".into(), port: 80 },
                &b"POST / HTTP/1.1\r\n\r\nbody"[..],
                &b"POST http://[::1]:80/ HTTP/1.1\r\n\r\nbody"[..],
            ),
        ];
        assert_table!(abs_cases, |(name, target, wire, expected)| {
            assert_eq!(absolute_form(wire, &target), expected, "{name}");
        });

        // 3. TLS Passthrough Host Matching Matrix
        let std_rules: Vec<String> = ["api.example.com", "*.pinned.test", ".bank.test", "  Mixed.Case.Test "]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let passthrough_cases = [
            ("exact host match", "api.example.com", std_rules.clone(), true),
            ("case-insensitive host match", "API.Example.COM", std_rules.clone(), true),
            ("trailing DNS dot normalized", "api.example.com.", std_rules.clone(), true),
            ("trimmed mixed-case rule match", "mixed.case.test", std_rules.clone(), true),
            ("unlisted sibling subdomain does not match exact rule", "www.example.com", std_rules.clone(), false),
            ("parent apex domain does not match subdomain rule", "example.com", std_rules.clone(), false),
            ("prefix lookalike host does not match", "xapi.example.com", std_rules.clone(), false),
            ("single-level subdomain matches *.wildcard", "a.pinned.test", std_rules.clone(), true),
            ("multi-level nested subdomain matches *.wildcard", "deep.a.pinned.test", std_rules.clone(), true),
            ("subdomain matches leading-dot .bank.test rule", "x.bank.test", std_rules.clone(), true),
            ("bare domain does not match *.pinned.test", "pinned.test", std_rules.clone(), false),
            ("bare domain does not match .bank.test", "bank.test", std_rules.clone(), false),
            ("prefix lookalike does not match wildcard", "evilpinned.test", std_rules.clone(), false),
            ("suffix lookalike does not match wildcard", "pinned.test.evil", std_rules.clone(), false),
            ("IPv6 bracketed host matches unbracketed rule", "[::1]", vec!["::1".to_string()], true),
            ("degenerate empty or bare-wildcard rules never match", "a.test", vec!["".into(), "*.".into(), ".".into()], false),
            ("empty host never matches", "", std_rules.clone(), false),
            ("empty rule list never matches", "a.test", vec![], false),
        ];

        assert_table!(passthrough_cases, |(name, host, rules, expected)| {
            assert_eq!(should_passthrough_tls(host, &rules), expected, "{name}");
        });
    }

    /// A plain TCP server that echoes the first bytes it receives.
    fn tcp_echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = l.incoming().next() {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            }
        });
        port
    }

    #[test]
    fn passthrough_hosts_are_tunnelled_even_with_interception_on() {
        let (sh, pp) = mitm_proxy(Arc::new(CertificateAuthority::generate().unwrap()), None);
        *sh.tls_passthrough.lock().unwrap() = vec!["127.0.0.1".to_string()];
        let echo = tcp_echo();
        let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n").as_bytes()).unwrap();
        let mut reply = Vec::new();
        let mut b = [0u8; 1];
        while !reply.ends_with(b"\r\n\r\n") {
            assert_eq!(c.read(&mut b).unwrap(), 1);
            reply.push(b[0]);
        }
        assert!(reply.starts_with(b"HTTP/1.1 200 Connection established"));
        // raw, non-TLS bytes come back unchanged: nothing terminated TLS in between
        c.write_all(b"not a TLS record").unwrap();
        let mut echoed = [0u8; 16];
        c.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"not a TLS record");
        wait_for(|| !sh.history.lock().unwrap().is_empty());
        assert_eq!(sh.history.lock().unwrap()[0].status, "200 (Tunnel)");
        assert!(sh.events.lock().unwrap().iter().any(|e| e.level == Level::Info && e.message == "TLS passthrough enabled for 127.0.0.1; tunneling opaque TCP"));
        assert!(sh.tls.lock().unwrap().as_ref().unwrap().len() == 0, "no certificate was issued");
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn unlisted_hosts_are_still_decrypted() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), None);
        *sh.tls_passthrough.lock().unwrap() = vec!["*.example.com".to_string(), "other.test".to_string()];
        assert!(https_client(pp, "127.0.0.1:9", "127.0.0.1", &proxy_ca).is_ok(), "127.0.0.1 isn't listed: the proxy completes TLS itself");
        sh.stop.store(true, Ordering::SeqCst);
    }

    // ---- Batch 2: request framing, byte-exact bodies, header checks ----

    /// Upstream that records each request exactly as received (head bytes + Content-Length
    /// body) and answers with `response`.
    fn capture_upstream(response: Vec<u8>) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for s in l.incoming().take(4) {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let Ok(head) = read_head_bytes(&mut r) else { continue };
                let text = crate::codec::decode_header_bytes(&head).0;
                let n: u64 = header(&text, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                let mut req = head;
                req.extend_from_slice(b"\r\n");
                let _ = r.by_ref().take(n).read_to_end(&mut req);
                let _ = tx.send(req);
                let _ = s.write_all(&response);
            }
        });
        (port, rx)
    }

    /// Build one frame the way a peer would send it.
    fn ws_frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = vec![0x80 | opcode];
        let masked = u8::from(mask.is_some()) << 7;
        assert!(payload.len() <= 125, "the test frames are small on purpose");
        out.push(masked | payload.len() as u8);
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    /// A target that accepts one upgrade, reports every byte it then receives, and sends one
    /// frame of its own. Returns its port and the channel the received bytes arrive on.
    fn ws_target() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        ws_target_with(false, true)
    }

    /// `pipelined`: send the answer and the first frame in one write, so the proxy's buffered
    /// reader takes the frame along with the head. `upgrade`: answer 101, or refuse.
    fn ws_target_with(pipelined: bool, upgrade: bool) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let Some(Ok(mut s)) = l.incoming().next() else { return };
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            // the handshake head, read byte by byte so no frame bytes are swallowed with it
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            while s.read_exact(&mut one).is_ok() {
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head_text = String::from_utf8_lossy(&head).into_owned();
            let _ = tx.send(head.clone());
            let key = head_text
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-key")))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let accept = crate::websocket::accept_key(&key);
            if !upgrade {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno");
                return;
            }
            let answer = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            let first = ws_frame(0x1, b"from the target", None);
            if pipelined {
                // one write, so the two land in the proxy's reader together
                let mut both = answer.into_bytes();
                both.extend_from_slice(&first);
                let _ = s.write_all(&both);
            } else {
                let _ = s.write_all(answer.as_bytes());
                let _ = s.write_all(&first);
            }
            let mut buf = [0u8; 1024];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        (port, rx)
    }

    /// The client half of an upgrade through the proxy: the handshake, then the 101 head read
    /// one byte at a time so none of the frames behind it are consumed with it.
    fn ws_through_proxy(pp: u16, target_port: u16) -> (TcpStream, String) {
        let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(
            format!(
                "GET http://127.0.0.1:{target_port}/socket HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n                 Upgrade: websocket\r\nConnection: Upgrade\r\n                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut head = Vec::new();
        let mut one = [0u8; 1];
        while c.read_exact(&mut one).is_ok() {
            head.push(one[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        (c, String::from_utf8_lossy(&head).into_owned())
    }

    /// An upgrade has to reach the target with its handshake headers intact, the answer has to
    /// reach the browser, and the frames that follow have to go both ways byte for byte while
    /// a readable copy of each is recorded.
    #[test]
    fn a_websocket_upgrade_is_relayed_and_its_messages_recorded() {
        let sh = shared();
        let (target, received) = ws_target();
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"), "the browser was told the upgrade happened: {head:?}");
        assert!(head.to_lowercase().contains("upgrade: websocket"), "{head:?}");

        // what the target was sent: the handshake, with the headers that make it one
        let sent_head = String::from_utf8_lossy(&received.recv_timeout(Duration::from_secs(5)).unwrap()).into_owned();
        let low = sent_head.to_lowercase();
        assert!(low.contains("upgrade: websocket"), "the upgrade header survived: {sent_head:?}");
        assert!(low.contains("connection: upgrade"), "and so did the connection header: {sent_head:?}");
        assert!(!low.contains("connection: close"), "the proxy did not force the connection shut: {sent_head:?}");
        assert!(low.contains("sec-websocket-key: dghlihnhbxbszsbub25jzq=="), "the key was passed through: {sent_head:?}");

        // the target's own frame reaches the browser
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], ws_frame(0x1, b"from the target", None).as_slice(), "byte for byte");

        // and the browser's frame reaches the target, mask and all
        let client_frame = ws_frame(0x1, b"from the browser", Some([0x37, 0xfa, 0x21, 0x3d]));
        c.write_all(&client_frame).unwrap();
        let got = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, client_frame, "the frame was forwarded exactly, mask included");

        // both directions were recorded, readable
        wait_for(|| sh.ws_messages.lock().unwrap().len() >= 2);
        let kept = sh.ws_messages.lock().unwrap().clone();
        let payloads: Vec<(crate::websocket::Direction, String)> =
            kept.iter().map(|m| (m.direction, m.payload.clone())).collect();
        assert!(
            payloads.contains(&(crate::websocket::Direction::ServerToClient, "from the target".to_string())),
            "{payloads:?}"
        );
        assert!(
            payloads.contains(&(crate::websocket::Direction::ClientToServer, "from the browser".to_string())),
            "the client's payload was unmasked for reading: {payloads:?}"
        );

        // and the handshake itself is in history, so the connection can be found
        let hist = sh.history.lock().unwrap().clone();
        assert_eq!(hist.len(), 1, "one entry for the handshake");
        assert!(hist[0].status.starts_with("101"), "{:?}", hist[0].status);
        assert_eq!(kept[0].entry_id, hist[0].id, "the messages point back at it");

        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A buffered reader takes whatever arrived with the head it was asked for, so the first
    /// frames of a connection are routinely already off the socket by the time the handshake
    /// is done with. They have to be forwarded from there: no later read will return them.
    /// This is the bug an opaque tunnel has, and it is why this is its own test.
    #[test]
    fn frames_arriving_with_the_handshake_are_not_lost() {
        let sh = shared();
        let (target, received) = ws_target_with(true, true);
        let pp = running_proxy(&sh);

        // the browser's first frame goes out in the same write as its handshake
        let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = format!(
            "GET http://127.0.0.1:{target}/socket HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n             Upgrade: websocket\r\nConnection: Upgrade\r\n             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .into_bytes();
        let early = ws_frame(0x1, b"early", Some([9, 8, 7, 6]));
        request.extend_from_slice(&early);
        c.write_all(&request).unwrap();

        // the head, then the target's frame, which came in the same write as the answer
        let mut head = Vec::new();
        let mut one = [0u8; 1];
        while c.read_exact(&mut one).is_ok() {
            head.push(one[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], ws_frame(0x1, b"from the target", None).as_slice(), "the target's first frame was not dropped");

        // and the browser's first frame reached the target
        let _handshake = received.recv_timeout(Duration::from_secs(5)).unwrap();
        let got = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, early, "the browser's first frame was not dropped either");

        wait_for(|| sh.ws_messages.lock().unwrap().len() >= 2);
        let payloads: Vec<String> = sh.ws_messages.lock().unwrap().iter().map(|m| m.payload.clone()).collect();
        assert!(payloads.contains(&"early".to_string()), "and both were read: {payloads:?}");
        assert!(payloads.contains(&"from the target".to_string()), "{payloads:?}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A WebSocket that says nothing for a while is ordinary -- that is what they are for.
    /// The read timeout that bounds an HTTP exchange must not be allowed to end one.
    #[test]
    fn a_quiet_connection_outlives_the_read_timeout() {
        let sh = shared();
        // far shorter than the wait below, so a connection bounded by it would be gone
        sh.read_timeout_secs.store(1, Ordering::SeqCst);
        let (target, received) = ws_target();
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"));
        let mut buf = [0u8; 64];
        let _ = c.read(&mut buf).unwrap();
        let _handshake = received.recv_timeout(Duration::from_secs(5)).unwrap();

        std::thread::sleep(Duration::from_millis(2500));

        let late = ws_frame(0x1, b"still here", Some([1, 1, 1, 1]));
        c.write_all(&late).unwrap();
        let got = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, late, "the connection was still carrying frames after the timeout had passed");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A server is free to refuse an upgrade. The browser has to be told what it said, and the
    /// exchange belongs in the history like any other.
    #[test]
    fn a_refused_upgrade_is_passed_back_and_recorded() {
        let sh = shared();
        let (target, _received) = ws_target_with(false, false);
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 400"), "the browser was told: {head:?}");
        // a head promising a body and then nothing is a network error to the browser, and
        // the server's reason for refusing is exactly what the reader needs
        let mut body = Vec::new();
        let _ = c.read_to_end(&mut body);
        assert_eq!(String::from_utf8_lossy(&body), "no", "the refusal's body reached the browser");

        wait_for(|| !sh.history.lock().unwrap().is_empty());
        let hist = sh.history.lock().unwrap().clone();
        assert_eq!(hist[0].status, "400 Bad Request");
        assert!(hist[0].response.ends_with("no"), "and was recorded with it: {:?}", hist[0].response);
        assert_eq!(hist[0].length, 2, "with the length of what came back");
        assert!(sh.ws_messages.lock().unwrap().is_empty(), "and nothing was captured for a connection that never opened");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A message composed in the app has to reach a connection that is still open, go out as
    /// a client frame (masked, as the protocol requires of one), and be recorded like any
    /// other so the stream shows what was sent.
    #[test]
    fn a_composed_message_is_sent_on_a_live_connection_and_recorded() {
        let sh = shared();
        let (target, received) = ws_target();
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"));
        let mut buf = [0u8; 64];
        let _ = c.read(&mut buf).unwrap();
        let _handshake = received.recv_timeout(Duration::from_secs(5)).unwrap();

        // the open connection is listed, with the handshake it belongs to
        wait_for(|| !sh.ws_live.lock().unwrap().is_empty());
        let link = sh.ws_live.lock().unwrap().first().cloned().expect("a live connection");
        assert_eq!((link.host.as_str(), link.path.as_str()), ("127.0.0.1", "/socket"));

        let composed = crate::websocket::encode(
            crate::websocket::Opcode::Text,
            b"composed",
            Some(crate::websocket::masking_key()),
        );
        link.send.send(composed.clone()).expect("the connection takes it");

        let got = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, composed, "it went out exactly as built, masked");

        wait_for(|| sh.ws_messages.lock().unwrap().iter().any(|m| m.payload == "composed"));
        let sent = sh.ws_messages.lock().unwrap().iter().find(|m| m.payload == "composed").cloned().expect("recorded");
        assert_eq!(sent.direction, crate::websocket::Direction::ClientToServer, "recorded as going out");

        // and once the connection is gone it is no longer offered
        drop(c);
        wait_for(|| sh.ws_live.lock().unwrap().is_empty());
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A connection that agreed to compress its payloads: the relay has to read what the
    /// handshake settled and inflate with it, or the stream is unreadable hex.
    #[test]
    fn a_compressed_connection_is_recorded_readable() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Some(Ok(mut s)) = l.incoming().next() else { return };
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            while s.read_exact(&mut one).is_ok() {
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let key = text
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-key")))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let accept = crate::websocket::accept_key(&key);
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n                     Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
                )
                .as_bytes(),
            );
            // one compressed message, framed with RSV1 set
            let mut deflater = flate2::Compress::new(flate2::Compression::default(), false);
            let body = b"{\"ticks\":[1,2,3,4,5]}";
            let mut squashed = Vec::with_capacity(body.len() + 64);
            deflater.compress_vec(body, &mut squashed, flate2::FlushCompress::Sync).unwrap();
            squashed.truncate(squashed.len() - 4);
            let mut frame = vec![0xC1, squashed.len() as u8]; // FIN + RSV1 + text
            frame.extend_from_slice(&squashed);
            let _ = s.write_all(&frame);
            std::thread::sleep(Duration::from_secs(2));
        });

        let sh = shared();
        let pp = running_proxy(&sh);
        let (_c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"), "{head:?}");

        wait_for(|| !sh.ws_messages.lock().unwrap().is_empty());
        let m = sh.ws_messages.lock().unwrap()[0].clone();
        assert_eq!(m.payload, "{\"ticks\":[1,2,3,4,5]}", "the compressed payload was inflated for reading");
        assert!(m.compressed, "and it still says it arrived compressed");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A busy connection must not be rate-limited by the interval the relay polls a quiet
    /// side at. Reading one buffer per poll would hold a stream to a few hundred KB a second,
    /// which is no use for anything that actually sends data.
    #[test]
    fn a_one_way_stream_is_not_held_back_by_the_poll_interval() {
        const FRAMES: usize = 40;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Some(Ok(mut s)) = l.incoming().next() else { return };
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            while s.read_exact(&mut one).is_ok() {
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let key = text
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-key")))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let accept = crate::websocket::accept_key(&key);
            let _ = s.write_all(
                format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes(),
            );
            // one burst, all at once
            let payload = vec![b'x'; 8192];
            let mut burst = Vec::new();
            for _ in 0..FRAMES {
                burst.extend_from_slice(&[0x82, 126]);
                burst.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                burst.extend_from_slice(&payload);
            }
            let _ = s.write_all(&burst);
            std::thread::sleep(Duration::from_secs(3));
        });

        let sh = shared();
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"), "{head:?}");

        let want = FRAMES * (4 + 8192);
        let started = std::time::Instant::now();
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while got < want {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        let took = started.elapsed();
        assert_eq!(got, want, "all of it arrived");
        // one read per poll would need FRAMES * WS_POLL, two seconds of it; draining a side
        // that has more ready costs a fraction of that
        assert!(
            took < Duration::from_millis(600),
            "{} KB took {took:?}: the relay is reading one buffer per poll instead of draining what is ready",
            want / 1024,
        );
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A frame the browser is still in the middle of sending has already had its first bytes
    /// forwarded. Putting a composed frame out at that moment would splice it into the middle
    /// of the browser's payload: the target would read the composed bytes as payload and the
    /// rest of the browser's payload as frame headers, and never recover. Anything composed
    /// has to wait for the boundary.
    #[test]
    fn a_composed_message_never_cuts_into_a_frame_still_arriving() {
        let sh = shared();
        let (target, received) = ws_target();
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"));
        let mut buf = [0u8; 64];
        let _ = c.read(&mut buf).unwrap();
        let handshake = received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(handshake.starts_with(b"GET "), "the first thing through is the handshake");

        wait_for(|| !sh.ws_live.lock().unwrap().is_empty());
        let link = sh.ws_live.lock().unwrap().first().cloned().expect("a live connection");

        // half a frame, so the relay has forwarded its start and is waiting for the rest
        let partial = ws_frame(0x1, b"the browser is still talking", Some([5, 6, 7, 8]));
        let (first, second) = partial.split_at(10);
        c.write_all(first).unwrap();
        std::thread::sleep(Duration::from_millis(150));

        // composed while that frame is half-sent
        let composed = crate::websocket::encode(
            crate::websocket::Opcode::Text,
            b"composed",
            Some(crate::websocket::masking_key()),
        );
        link.send.send(composed.clone()).expect("taken");
        std::thread::sleep(Duration::from_millis(150));

        c.write_all(second).unwrap();

        // everything the target was sent after the handshake, in order
        let mut stream = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while stream.len() < partial.len() + composed.len() && std::time::Instant::now() < deadline {
            if let Ok(chunk) = received.recv_timeout(Duration::from_millis(200)) {
                stream.extend_from_slice(&chunk);
            }
        }
        let mut want = partial.clone();
        want.extend_from_slice(&composed);
        assert_eq!(
            stream, want,
            "the browser's frame went out whole and the composed one followed it, rather than being cut into it",
        );
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// A frame too large to read leaves the rest of its payload in the stream. Carrying on
    /// decoding would read that payload as frame headers: invented messages for the rest of
    /// the connection, each one evicting a real one, and a buffer that grows to whatever a
    /// length field happens to claim. Once a direction cannot be followed, it is left alone.
    #[test]
    fn a_direction_that_cannot_be_followed_stops_being_decoded() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Some(Ok(mut s)) = l.incoming().next() else { return };
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut one = [0u8; 1];
            while s.read_exact(&mut one).is_ok() {
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let key = text
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-key")))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            let accept = crate::websocket::accept_key(&key);
            let _ = s.write_all(
                format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes(),
            );
            // a frame declaring far more than this build will read, then a lot of payload
            let mut header = vec![0x82u8, 127];
            header.extend_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
            let _ = s.write_all(&header);
            let chunk = vec![0x81u8; 32 * 1024]; // bytes that look like frame headers
            for _ in 0..8 {
                if s.write_all(&chunk).is_err() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        });

        let sh = shared();
        let pp = running_proxy(&sh);
        let (mut c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"), "{head:?}");

        // let the payload flow through
        let mut sink = vec![0u8; 64 * 1024];
        let deadline = std::time::Instant::now() + Duration::from_millis(1500);
        let mut seen = 0usize;
        while std::time::Instant::now() < deadline {
            match c.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen += n,
            }
        }
        assert!(seen > 100_000, "the connection kept carrying traffic ({seen} bytes)");
        assert!(
            sh.ws_messages.lock().unwrap().is_empty(),
            "nothing was invented out of a payload that could not be followed: {:?}",
            sh.ws_messages.lock().unwrap().iter().map(|m| m.length).collect::<Vec<_>>(),
        );
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// Intercept holds requests; a handshake is not one of them, and is forwarded whatever
    /// Intercept says. Somebody watching a held queue that never fills needs to be told why.
    #[test]
    fn an_upgrade_forwarded_past_intercept_says_so_in_the_event_log() {
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        let (target, _received) = ws_target();
        let pp = running_proxy(&sh);
        let (_c, head) = ws_through_proxy(pp, target);
        assert!(head.starts_with("HTTP/1.1 101"), "it was forwarded rather than held: {head:?}");
        assert!(sh.held.lock().unwrap().is_empty(), "and nothing is waiting to be let through");

        wait_for(|| {
            sh.events.lock().unwrap().iter().any(|e| e.message.contains("without being held"))
        });
        sh.stop.store(true, Ordering::SeqCst);
    }

    fn running_proxy(sh: &Shared) -> u16 {
        let pp = free_port();
        start(sh.clone(), format!("127.0.0.1:{pp}")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        pp
    }

    /// Send raw bytes through the proxy; everything that comes back until it closes.
    fn bytes_through(pp: u16, req: &[u8]) -> Vec<u8> {
        let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(req).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    }

    fn ok_response() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()
    }

    fn body_rule(from: &str, to: &str) -> crate::rewrite::Rule {
        crate::rewrite::Rule {
            enabled: true, case_sensitive: true, kind: crate::rewrite::RuleType::RequestBody, regex: false,
            match_text: from.into(), replace_text: to.into(), comment: String::new(),
            ..Default::default()
        }
    }

    #[test]
    fn binary_request_bodies_are_forwarded_byte_exact() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        // a rule that would match the body's text if it were decoded lossily
        sh.rules.lock().unwrap().push(body_rule("A", "B"));
        let pp = running_proxy(&sh);
        let body: Vec<u8> = vec![0x00, 0xff, b'A', 0xfe, 0x80, b'\r', b'\n', b'A', 0xc3];
        let mut req = format!("POST http://127.0.0.1:{up}/up HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        req.extend_from_slice(&body);
        let resp = bytes_through(pp, &req);
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"), "{}", String::from_utf8_lossy(&resp));
        let sent = got.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(sent.ends_with(&body), "body changed in transit");
        let text = String::from_utf8_lossy(&sent);
        assert!(text.contains(&format!("Content-Length: {}\r\n", body.len())), "{text}");
        assert!(sh.history.lock().unwrap()[0].request.contains("[binary body: 9 bytes"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn text_request_bodies_still_get_rules() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        sh.rules.lock().unwrap().push(body_rule("cat", "lion"));
        let pp = running_proxy(&sh);
        let req = format!("POST http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\ncat=café");
        bytes_through(pp, req.as_bytes());
        let sent = got.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(sent.ends_with("lion=café".as_bytes()), "{}", String::from_utf8_lossy(&sent));
        assert!(String::from_utf8_lossy(&sent).contains("Content-Length: 10\r\n"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// An External Command rule transforms a request body before it is forwarded, and the
    /// forwarded Content-Length matches what the command produced.
    #[cfg(unix)]
    #[test]
    fn a_command_rule_transforms_a_request_body_on_the_wire() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        let mut rule = crate::rewrite::Rule::new(crate::rewrite::RuleType::RequestBody);
        rule.action = crate::rewrite::RuleAction::TransformCommand;
        rule.program = "strip".into();
        // drop every hyphen, shrinking the body
        let tools = [crate::tooling::ExternalTool { name: "strip".into(), command: "tr".into(), args: "-d -".into(), ..Default::default() }];
        sh.rules.lock().unwrap().extend(crate::rewrite::resolve(&[rule], &tools));
        let pp = running_proxy(&sh);
        let req = format!("POST http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\na-b-c-d");
        bytes_through(pp, req.as_bytes());
        let sent = got.recv_timeout(Duration::from_secs(5)).unwrap();
        let text = String::from_utf8_lossy(&sent);
        assert!(text.ends_with("abcd"), "the command's output was forwarded: {text}");
        assert!(text.contains("Content-Length: 4\r\n"), "the length followed the shorter body: {text}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    /// An External Command rule transforms a buffered response body on its way to the client.
    #[cfg(unix)]
    #[test]
    fn a_command_rule_transforms_a_response_body_to_the_client() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        let (up, _got) = capture_upstream(resp);
        let sh = shared();
        let mut rule = crate::rewrite::Rule::new(crate::rewrite::RuleType::ResponseBody);
        rule.action = crate::rewrite::RuleAction::TransformCommand;
        rule.program = "upper".into();
        // upper-case, same length
        let tools = [crate::tooling::ExternalTool { name: "upper".into(), command: "tr".into(), args: "a-z A-Z".into(), ..Default::default() }];
        sh.rules.lock().unwrap().extend(crate::rewrite::resolve(&[rule], &tools));
        let pp = running_proxy(&sh);
        let req = format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n");
        let back = bytes_through(pp, req.as_bytes());
        let text = String::from_utf8_lossy(&back);
        assert!(text.ends_with("HELLO"), "the response body reached the client transformed: {text}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn binary_body_survives_an_intercept_edit_of_the_head() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        let pp = running_proxy(&sh);
        let body = vec![0xffu8, 0x00, 0xfe];
        let mut req = format!("POST http://127.0.0.1:{up}/a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n").into_bytes();
        req.extend_from_slice(&body);
        let t = std::thread::spawn(move || bytes_through(pp, &req));
        assert!(gets_held(&sh));
        let h = sh.held.lock().unwrap().remove(0);
        assert!(h.raw.contains("[binary body: 3 bytes"), "{}", h.raw);
        h.reply.send(Decision::Forward(h.raw.replace("POST /a", "POST /b") + "typed over")).unwrap();
        t.join().unwrap();
        let sent = got.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(sent.starts_with(b"POST /b HTTP/1.1\r\n"));
        assert!(sent.ends_with(b"\r\n\r\n\xff\x00\xfe"), "{:?}", String::from_utf8_lossy(&sent));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn non_utf8_header_bytes_pass_both_ways() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=r\xe9sum\xe9.pdf\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let (up, got) = capture_upstream(resp);
        let sh = shared();
        let pp = running_proxy(&sh);
        let mut req = format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n").into_bytes();
        req.extend_from_slice(b"X-Name: Jos\xe9\r\n\r\n");
        let back = bytes_through(pp, &req);
        let sent = got.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(sent.windows(14).any(|w| w == b"X-Name: Jos\xe9\r\n"), "{:?}", String::from_utf8_lossy(&sent));
        assert!(back.windows(19).any(|w| w == b"filename=r\xe9sum\xe9.pdf"), "{:?}", String::from_utf8_lossy(&back));
        assert!(back.ends_with(b"\r\n\r\nok"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn proxy_framing_and_sanitization_matrix() {
        // 1. Request Body Framing & Smuggling Guard Matrix
        let framing_cases: Vec<(&str, String, Result<u64, u16>)> = vec![
            ("no Content-Length defaults to 0", "Host: x\r\n".into(), Ok(0)),
            ("valid Content-Length parsed", "Content-Length: 12\r\n".into(), Ok(12)),
            ("case-insensitive trimmed Content-Length: 0", "content-length:  0 \r\n".into(), Ok(0)),
            ("leading plus sign rejected with 400", "Content-Length: +5\r\n".into(), Err(400)),
            ("negative Content-Length rejected with 400", "Content-Length: -1\r\n".into(), Err(400)),
            ("comma-separated Content-Length rejected with 400", "Content-Length: 5, 5\r\n".into(), Err(400)),
            ("hex Content-Length rejected with 400", "Content-Length: 0x10\r\n".into(), Err(400)),
            ("alphabetic Content-Length rejected with 400", "Content-Length: abc\r\n".into(), Err(400)),
            ("empty Content-Length rejected with 400", "Content-Length: \r\n".into(), Err(400)),
            ("space-separated digits rejected with 400", "Content-Length: 1 2\r\n".into(), Err(400)),
            ("u64 overflow Content-Length rejected with 400", "Content-Length: 99999999999999999999\r\n".into(), Err(400)),
            ("duplicate Content-Length headers rejected with 400", "Content-Length: 3\r\nContent-Length: 3\r\n".into(), Err(400)),
            ("CL + Transfer-Encoding smuggling attempt rejected with 400", "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n".into(), Err(400)),
            ("chunked request body without CL rejected with 411", "Transfer-Encoding: chunked\r\n".into(), Err(411)),
            ("exact MAX_REQUEST_BODY boundary accepted", format!("Content-Length: {}\r\n", MAX_REQUEST_BODY), Ok(MAX_REQUEST_BODY)),
            ("MAX_REQUEST_BODY + 1 rejected with 413", format!("Content-Length: {}\r\n", MAX_REQUEST_BODY + 1), Err(413)),
        ];

        assert_table!(framing_cases, |(name, headers, expected)| {
            let actual = request_body_length(&format!("POST / HTTP/1.1\r\n{headers}")).map_err(|e| e.0);
            assert_eq!(actual, expected, "{name}");
        });

        // 2. Head Reading Size & Line Limit Matrix
        let mut endless = b"GET / HTTP/1.1\r\nX: ".to_vec();
        endless.extend(std::iter::repeat_n(b'a', 10 * 1024 * 1024));

        let head_cases: Vec<(&str, Vec<u8>, Result<(), HeadError>)> = vec![
            (
                "200 KiB request-line URL within total head limit succeeds",
                format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(200 * 1024)).into_bytes(),
                Ok(()),
            ),
            (
                "single header line exceeding 64 KiB MAX_HEADER_LINE returns TooLarge",
                format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEADER_LINE)).into_bytes(),
                Err(HeadError::TooLarge),
            ),
            (
                "unterminated 10 MiB header line cuts off at limit with TooLarge",
                endless,
                Err(HeadError::TooLarge),
            ),
            (
                "many valid lines exceeding total MAX_HEAD block limit returns TooLarge",
                format!("GET / HTTP/1.1\r\n{}\r\n", format!("X: {}\r\n", "a".repeat(1000)).repeat(300)).into_bytes(),
                Err(HeadError::TooLarge),
            ),
            (
                "empty stream returns HeadError::Closed",
                Vec::new(),
                Err(HeadError::Closed),
            ),
        ];

        assert_table!(head_cases, |(name, bytes, expected)| {
            let res = read_head_bytes(&mut BufReader::new(std::io::Cursor::new(bytes))).map(|_| ());
            assert_eq!(res, expected, "{name}");
        });

        // 3. Header Line Sanitization Matrix
        let sanitize_cases: [(&str, &str, Option<&str>); 11] = [
            ("tab in value preserved", "X-A: b\tc", Some("X-A: b\tc")),
            ("bare CR in value stripped to prevent header injection", "X-A: b\rInjected: 1", Some("X-A: bInjected: 1")),
            ("NUL and DEL control chars stripped from value", "X-A: \u{0}b\u{7f}", Some("X-A: b")),
            ("non-ASCII obs-text in value preserved", "X-A: caf\u{e9}", Some("X-A: caf\u{e9}")),
            ("line without colon rejected", "no colon", None),
            ("empty header name rejected", ": empty name", None),
            ("space inside header name rejected", "Bad Name: x", None),
            ("trailing space after header name rejected", "X-A : x", None),
            ("obs-fold leading space rejected", " folded: x", None),
            ("CR inside header name rejected", "Na\rme: x", None),
            ("non-ASCII character in header name rejected", "Ünï: x", None),
        ];

        assert_table!(sanitize_cases, |(name, line, expected)| {
            assert_eq!(sanitize_header_line(line).as_deref(), expected, "{name}");
        });

        // 4. Loopback Interface Classification Matrix
        let loopback_cases = [
            ("IPv4 loopback 127.0.0.1", "127.0.0.1", true),
            ("trimmed IPv4 loopback", " 127.0.0.1 ", true),
            ("127.0.0.0/8 subnet address", "127.1.2.3", true),
            ("IPv6 loopback ::1", "::1", true),
            ("bracketed IPv6 loopback [::1]", "[::1]", true),
            ("localhost lowercase", "localhost", true),
            ("LOCALHOST uppercase", "LOCALHOST", true),
            ("all-interfaces IPv4 0.0.0.0 is not loopback", "0.0.0.0", false),
            ("unspecified IPv6 :: is not loopback", "::", false),
            ("bracketed unspecified IPv6 [::] is not loopback", "[::]", false),
            ("LAN IPv4 192.168.1.5 is not loopback", "192.168.1.5", false),
            ("private IPv4 10.0.0.1 is not loopback", "10.0.0.1", false),
            ("external hostname is not loopback", "example.com", false),
            ("empty host is not loopback", "", false),
            ("lookalike hostname 127.0.0.1.evil is not loopback", "127.0.0.1.evil", false),
        ];

        assert_table!(loopback_cases, |(name, host, expected)| {
            assert_eq!(is_loopback_interface(host), expected, "{name}");
        });

        // 5. Event Log Ring Buffer & Poisoned Lock Resilience
        let events: Events = Default::default();
        for i in 0..(MAX_EVENTS + 25) {
            log(&events, format!("event {i}"));
        }
        {
            let guard = events.lock().unwrap();
            assert_eq!(guard.len(), MAX_EVENTS);
            assert_eq!(guard.front().unwrap().message, "event 25");
            assert_eq!(guard.back().unwrap().message, format!("event {}", MAX_EVENTS + 24));
        }

        let poisoned: Events = Default::default();
        let p2 = poisoned.clone();
        let _ = std::thread::spawn(move || {
            let _guard = p2.lock().unwrap();
            panic!("a thread dies holding the log");
        })
        .join();
        assert!(poisoned.is_poisoned());
        log(&poisoned, "still works");
        assert_eq!(
            poisoned.lock().unwrap_or_else(|e| e.into_inner()).back().unwrap().message,
            "still works"
        );
    }

    #[test]
    fn badly_framed_requests_are_refused_and_never_forwarded() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        let pp = running_proxy(&sh);
        let cases = [
            ("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "400 Bad Request"),
            ("Content-Length: 4\r\nContent-Length: 5\r\n", "400 Bad Request"),
            ("Content-Length: +4\r\n", "400 Bad Request"),
            ("Transfer-Encoding: chunked\r\n", "411 Length Required"),
            ("Content-Length: 999999999999\r\n", "413 Payload Too Large"),
        ];
        for (headers, status) in cases {
            let req = format!("POST http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n{headers}\r\n4\r\nbody\r\n0\r\n\r\n");
            let resp = String::from_utf8_lossy(&bytes_through(pp, req.as_bytes())).into_owned();
            assert!(resp.starts_with(&format!("HTTP/1.1 {status}\r\n")), "{headers:?}: {resp}");
            assert!(resp.contains("Connection: close\r\n"));
        }
        assert!(got.recv_timeout(Duration::from_millis(300)).is_err(), "nothing reaches the server");
        assert!(sh.history.lock().unwrap().is_empty());
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn oversized_header_lines_get_431() {
        let sh = shared();
        let pp = running_proxy(&sh);
        let req = format!("GET http://127.0.0.1:1/ HTTP/1.1\r\nX-Big: {}\r\n\r\n", "a".repeat(MAX_HEADER_LINE + 10));
        let resp = String::from_utf8_lossy(&bytes_through(pp, req.as_bytes())).into_owned();
        assert!(resp.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"), "{resp}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn intercept_edits_cannot_inject_header_lines() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        let pp = running_proxy(&sh);
        let req = format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes();
        let t = std::thread::spawn(move || bytes_through(pp, &req));
        assert!(gets_held(&sh));
        let h = sh.held.lock().unwrap().remove(0);
        let edited = h.raw.replacen("Host: x", "Host: x\nX-Note: a\rX-Evil: 1\nBad Header: 2\nX-Ok: 3", 1);
        h.reply.send(Decision::Forward(edited)).unwrap();
        t.join().unwrap();
        let sent = String::from_utf8_lossy(&got.recv_timeout(Duration::from_secs(5)).unwrap()).into_owned();
        assert!(sent.contains("\r\nX-Note: aX-Evil: 1\r\n"), "{sent:?}");
        assert!(!sent.contains("\r\nX-Evil"), "{sent:?}");
        assert!(!sent.contains("Bad Header"), "{sent:?}");
        assert!(sent.contains("\r\nX-Ok: 3\r\n"), "{sent:?}");
        assert!(!sent.replace("\r\n", "").contains('\r'), "no bare CR: {sent:?}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn edited_skip_list_changes_what_is_held() {
        let up = upstream();
        let sh = shared();
        sh.intercept.store(true, Ordering::SeqCst);
        // .png is no longer skipped; .json now is
        *sh.skip_extensions.lock().unwrap() = vec!["json".into()];
        let pp = running_proxy(&sh);
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/data.json"));
        assert!(resp.contains("got GET /data.json"), "{resp}");
        assert!(sh.held.lock().unwrap().is_empty());
        let t = send_async(pp, up, "/logo.png");
        assert!(gets_held(&sh), "png is held now");
        let h = sh.held.lock().unwrap().remove(0);
        h.reply.send(Decision::Forward(h.raw.clone())).unwrap();
        assert!(t.join().unwrap().contains("got GET /logo.png"));
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn unchecked_certificates_are_accepted_when_verification_is_off() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let up = mock_https(server_ca, 1);
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), None);
        sh.verify_upstream_tls.store(false, Ordering::SeqCst);
        let tls = https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).unwrap();
        let mut io = BufReader::new(tls);
        let (head, body) = https_round_trip(&mut io, "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(body.contains("got GET /x"), "{body}");
        sh.stop.store(true, Ordering::SeqCst);
    }

    fn via(kind: crate::upstream::UpstreamProxyType, port: u16) -> crate::upstream::UpstreamProxyConfig {
        crate::upstream::UpstreamProxyConfig { enabled: true, proxy_type: kind, host: "127.0.0.1".into(), port }
    }

    #[test]
    fn plain_http_goes_through_the_upstream_proxy() {
        let up = upstream();
        let (http_proxy, targets) = crate::upstream::mock::http_proxy();
        let sh = shared();
        *sh.upstream_proxy.lock().unwrap() = via(crate::upstream::UpstreamProxyType::HttpConnect, http_proxy);
        let pp = running_proxy(&sh);
        let resp = through_proxy(pp, &format!("http://127.0.0.1:{up}/routed"));
        assert!(resp.contains("got GET /routed"), "{resp}");
        // forwarded with an absolute URL, as the tools do (no CONNECT for plain HTTP)
        assert_eq!(*targets.lock().unwrap(), [format!("http://127.0.0.1:{up}/routed")]);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn decrypted_https_goes_through_a_socks5_upstream() {
        let proxy_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let server_ca = Arc::new(CertificateAuthority::generate().unwrap());
        let up = mock_https(server_ca.clone(), 1);
        let (socks, targets) = crate::upstream::mock::socks5_proxy();
        let (sh, pp) = mitm_proxy(proxy_ca.clone(), Some(&server_ca));
        *sh.upstream_proxy.lock().unwrap() = via(crate::upstream::UpstreamProxyType::Socks5, socks);
        let tls = https_client(pp, &format!("127.0.0.1:{up}"), "127.0.0.1", &proxy_ca).unwrap();
        let mut io = BufReader::new(tls);
        let (head, body) = https_round_trip(&mut io, "GET /s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(body.contains("got GET /s"), "{body}");
        assert_eq!(*targets.lock().unwrap(), [format!("127.0.0.1:{up}")]);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn opaque_tunnels_go_through_the_upstream_proxy() {
        let echo = tcp_echo();
        let (http_proxy, targets) = crate::upstream::mock::http_proxy();
        let sh = shared();
        sh.decrypt_https.store(false, Ordering::SeqCst);
        *sh.upstream_proxy.lock().unwrap() = via(crate::upstream::UpstreamProxyType::HttpConnect, http_proxy);
        let pp = running_proxy(&sh);
        let mut c = TcpStream::connect(("127.0.0.1", pp)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n").as_bytes()).unwrap();
        let mut r = BufReader::new(c.try_clone().unwrap());
        let head = read_head(&mut r).unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        c.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(*targets.lock().unwrap(), [format!("127.0.0.1:{echo}")]);
        sh.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn a_misconfigured_upstream_proxy_never_connects_directly() {
        let (up, got) = capture_upstream(ok_response());
        let sh = shared();
        *sh.upstream_proxy.lock().unwrap() = crate::upstream::UpstreamProxyConfig { enabled: true, host: String::new(), ..Default::default() };
        let pp = running_proxy(&sh);
        let resp = String::from_utf8_lossy(&bytes_through(pp, format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())).into_owned();
        assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
        assert!(resp.contains("no host"), "{resp}");
        assert!(got.recv_timeout(Duration::from_millis(300)).is_err(), "the target was never contacted");
        sh.stop.store(true, Ordering::SeqCst);
    }
}
