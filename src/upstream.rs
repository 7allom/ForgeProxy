//! Outgoing connections: directly, or through an upstream proxy (HTTP CONNECT or SOCKS5),
//! and whether real servers' certificates are checked. Used by the proxy (every connection
//! it opens to a target) and by the tools' HTTP client (`http::send`).

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProxyType {
    /// No upstream proxy (the same as switched off).
    Direct,
    /// An HTTP proxy: every connection is opened with `CONNECT host:port`.
    #[default]
    HttpConnect,
    /// A SOCKS5 proxy (no authentication); host names are resolved by the proxy.
    Socks5,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub proxy_type: UpstreamProxyType,
    pub host: String,
    pub port: u16,
}

impl Default for UpstreamProxyConfig {
    fn default() -> Self {
        UpstreamProxyConfig { enabled: false, proxy_type: UpstreamProxyType::HttpConnect, host: String::new(), port: 8080 }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolSettings {
    /// Check real servers' certificates against Mozilla's roots. Off (the default) accepts
    /// any certificate, for internal and self-signed test targets.
    pub verify_upstream_tls: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for ProtocolSettings {
    fn default() -> Self {
        ProtocolSettings { verify_upstream_tls: false }
    }
}

/// Where connections go when an upstream proxy is in use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub kind: UpstreamProxyType,
    pub host: String,
    pub port: u16,
}

impl UpstreamProxyConfig {
    /// The route to use: None for direct connections; Err when the upstream proxy is on
    /// but has no address. Connections then fail rather than quietly going direct (traffic
    /// meant for the proxy mustn't leak past it).
    pub fn route(&self) -> Result<Option<Route>, String> {
        if !self.enabled || self.proxy_type == UpstreamProxyType::Direct {
            return Ok(None);
        }
        let host = self.host.trim();
        if host.is_empty() || self.port == 0 {
            return Err("The upstream proxy is switched on but has no host or port (Settings > Network > Connections).".into());
        }
        Ok(Some(Route { kind: self.proxy_type, host: host.to_string(), port: self.port }))
    }
}

/// Everything about outgoing connections a request needs (copied into worker threads).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetConfig {
    pub upstream: UpstreamProxyConfig,
    pub verify_tls: bool,
}

/// "host:port", with IPv6 addresses in brackets.
pub fn authority(host: &str, port: u16) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.contains(':') { format!("[{bare}]:{port}") } else { format!("{bare}:{port}") }
}

/// Open a TCP connection to `host:port`, directly or through `route`. `timeout` bounds the
/// proxy handshake (and is left on the stream as its read timeout).
pub fn connect(route: Option<&Route>, host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let Some(r) = route else {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        return TcpStream::connect((bare, port));
    };
    let mut s = TcpStream::connect((r.host.as_str(), r.port))
        .map_err(|e| io::Error::new(e.kind(), format!("upstream proxy {}: {e}", authority(&r.host, r.port))))?;
    let _ = s.set_read_timeout(Some(timeout));
    let _ = s.set_write_timeout(Some(timeout));
    match r.kind {
        UpstreamProxyType::HttpConnect => http_connect(&mut s, host, port)?,
        UpstreamProxyType::Socks5 => socks5_connect(&mut s, host, port)?,
        UpstreamProxyType::Direct => {}
    }
    Ok(s)
}

/// `CONNECT host:port`, then read the proxy's answer head byte by byte (so nothing after
/// it, the tunnel's first bytes, is consumed). Any 2xx opens the tunnel.
fn http_connect(s: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    let target = authority(host, port);
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "upstream proxy closed the connection during CONNECT"));
        }
        head.push(b[0]);
        if head.len() > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "upstream proxy sent an oversized CONNECT response"));
        }
    }
    let status = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code.starts_with('2') && code.len() == 3 {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("upstream proxy refused CONNECT {target}: {status}")))
    }
}

/// SOCKS5 (RFC 1928), no authentication: CONNECT to the host by name (or IP literal).
fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    let fail = |msg: String| io::Error::new(io::ErrorKind::ConnectionRefused, msg);
    s.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply != [5, 0] {
        return Err(fail("SOCKS5 proxy wants authentication, which isn't supported".into()));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let mut req = vec![5, 1, 0];
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => { req.push(1); req.extend_from_slice(&ip.octets()); }
        Ok(std::net::IpAddr::V6(ip)) => { req.push(4); req.extend_from_slice(&ip.octets()); }
        Err(_) => {
            let name = bare.as_bytes();
            if name.len() > 255 {
                return Err(fail(format!("host name too long for SOCKS5: {bare}")));
            }
            req.push(3);
            req.push(name.len() as u8);
            req.extend_from_slice(name);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 5 || head[1] != 0 {
        let why = match head[1] {
            1 => "general failure", 2 => "not allowed by its rules", 3 => "network unreachable", 4 => "host unreachable",
            5 => "connection refused", 6 => "TTL expired", 7 => "command not supported", 8 => "address type not supported", _ => "unknown error",
        };
        return Err(fail(format!("SOCKS5 proxy couldn't reach {}: {why}", authority(host, port))));
    }
    // the bound address the proxy reports (unused), then the port
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => { let mut n = [0u8; 1]; s.read_exact(&mut n)?; n[0] as usize }
        _ => return Err(fail("SOCKS5 proxy sent an invalid reply".into())),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest)?;
    Ok(())
}

/// The route as a ureq proxy ("http://host:port" or "socks5://host:port"; ureq resolves
/// names through a SOCKS proxy, like socks5h).
pub fn ureq_proxy(route: &Route) -> Result<ureq::Proxy, String> {
    let scheme = match route.kind {
        UpstreamProxyType::Socks5 => "socks5",
        _ => "http",
    };
    ureq::Proxy::new(format!("{scheme}://{}", authority(&route.host, route.port))).map_err(|e| e.to_string())
}

/// Accepts any server certificate, but still checks the handshake signatures (so the
/// connection is encrypted to whoever holds the certificate's key).
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
        -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct)
        -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS client config that doesn't verify server certificates ("Verify upstream server
/// certificates" off). ALPN http/1.1, like the verifying one.
pub fn insecure_client_config() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    }).clone()
}

#[cfg(test)]
pub mod mock {
    //! Local upstream proxies for tests: each records the targets it was asked for.
    use super::*;
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// Relay bytes both ways until either side closes.
    fn relay(a: TcpStream, b: TcpStream) {
        let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
        let t = std::thread::spawn(move || { let mut a = a; let mut b = b; let _ = io::copy(&mut a, &mut b); let _ = b.shutdown(std::net::Shutdown::Write); });
        let _ = io::copy(&mut b2, &mut a2);
        let _ = a2.shutdown(std::net::Shutdown::Write);
        let _ = t.join();
    }

    /// An HTTP proxy: CONNECT tunnels, and absolute-URL requests ("GET http://h:p/x")
    /// forwarded as plain ones. `targets` collects each CONNECT's "host:port", or the
    /// absolute URL of a forwarded request.
    pub fn http_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let seen = targets.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                        head.push(b[0]);
                    }
                    let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
                    let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    seen.lock().unwrap().push(target.clone());
                    if let Some(rest) = target.strip_prefix("http://") {
                        // forward: origin-form request line, the rest of the head, then relay
                        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
                        let Ok(mut up) = TcpStream::connect(authority) else { return };
                        let method = line.split_whitespace().next().unwrap_or("GET");
                        let tail = &head[line.len()..];
                        let _ = up.write_all(format!("{method} {} HTTP/1.1", if path.is_empty() { "/" } else { path }).as_bytes());
                        let _ = up.write_all(tail);
                        relay(s, up);
                        return;
                    }
                    if target.starts_with("blocked") {
                        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    let Ok(up) = TcpStream::connect(target.as_str()) else {
                        let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                        return;
                    };
                    let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    relay(s, up);
                });
            }
        });
        (port, targets)
    }

    /// A SOCKS5 proxy (no auth); `targets` collects "host:port" with the host as sent (a
    /// name stays a name).
    pub fn socks5_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let targets = Arc::new(Mutex::new(Vec::new()));
        let seen = targets.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut g = [0u8; 2];
                    if s.read_exact(&mut g).is_err() { return; }
                    let mut methods = vec![0u8; g[1] as usize];
                    let _ = s.read_exact(&mut methods);
                    let _ = s.write_all(&[5, 0]);
                    let mut h = [0u8; 4];
                    if s.read_exact(&mut h).is_err() { return; }
                    let host = match h[3] {
                        1 => { let mut a = [0u8; 4]; s.read_exact(&mut a).unwrap(); std::net::Ipv4Addr::from(a).to_string() }
                        3 => { let mut n = [0u8; 1]; s.read_exact(&mut n).unwrap(); let mut name = vec![0u8; n[0] as usize]; s.read_exact(&mut name).unwrap(); String::from_utf8(name).unwrap() }
                        _ => return,
                    };
                    let mut p = [0u8; 2];
                    s.read_exact(&mut p).unwrap();
                    let port = u16::from_be_bytes(p);
                    seen.lock().unwrap().push(format!("{host}:{port}"));
                    // "localhost.test" stands for 127.0.0.1: proves the name reached the proxy
                    let connect_host = if host == "localhost.test" { "127.0.0.1".to_string() } else { host };
                    match TcpStream::connect((connect_host.as_str(), port)) {
                        Ok(up) => { let _ = s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]); relay(s, up); }
                        Err(_) => { let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]); }
                    }
                });
            }
        });
        (port, targets)
    }

    /// A server that answers one line ("hello\n") to each connection and closes.
    pub fn hello_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let _ = s.write_all(b"hello\n");
            }
        });
        port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn route(kind: UpstreamProxyType, port: u16) -> Route {
        Route { kind, host: "127.0.0.1".into(), port }
    }

    fn read_all(mut s: TcpStream) -> String {
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn upstream_proxy_routing_matrix() {
        // 1. Route resolution matrix across Direct, HttpConnect, Socks5, disabled, and invalid configs
        struct RouteCase {
            name: &'static str,
            config: UpstreamProxyConfig,
            expected: Result<Option<Route>, bool>, // Ok(route) or Err(true)
        }

        let route_cases = [
            RouteCase {
                name: "default disabled config routes directly (None)",
                config: UpstreamProxyConfig::default(),
                expected: Ok(None),
            },
            RouteCase {
                name: "enabled config with empty host fails closed with Err",
                config: UpstreamProxyConfig {
                    enabled: true,
                    proxy_type: UpstreamProxyType::HttpConnect,
                    host: String::new(),
                    port: 8080,
                },
                expected: Err(true),
            },
            RouteCase {
                name: "enabled config with whitespace-only host fails closed with Err",
                config: UpstreamProxyConfig {
                    enabled: true,
                    proxy_type: UpstreamProxyType::HttpConnect,
                    host: "   ".into(),
                    port: 8080,
                },
                expected: Err(true),
            },
            RouteCase {
                name: "enabled HttpConnect trims host and resolves Route",
                config: UpstreamProxyConfig {
                    enabled: true,
                    proxy_type: UpstreamProxyType::HttpConnect,
                    host: " proxy.lan ".into(),
                    port: 8080,
                },
                expected: Ok(Some(Route {
                    kind: UpstreamProxyType::HttpConnect,
                    host: "proxy.lan".into(),
                    port: 8080,
                })),
            },
            RouteCase {
                name: "enabled Direct proxy_type routes directly (None)",
                config: UpstreamProxyConfig {
                    enabled: true,
                    proxy_type: UpstreamProxyType::Direct,
                    host: "proxy.lan".into(),
                    port: 8080,
                },
                expected: Ok(None),
            },
            RouteCase {
                name: "enabled Socks5 on localhost:1080 resolves Socks5 Route",
                config: UpstreamProxyConfig {
                    enabled: true,
                    proxy_type: UpstreamProxyType::Socks5,
                    host: "127.0.0.1".into(),
                    port: 1080,
                },
                expected: Ok(Some(Route {
                    kind: UpstreamProxyType::Socks5,
                    host: "127.0.0.1".into(),
                    port: 1080,
                })),
            },
            RouteCase {
                name: "enabled Socks5 with port 0 fails closed with Err",
                config: UpstreamProxyConfig {
                    enabled: true,
                    proxy_type: UpstreamProxyType::Socks5,
                    host: "proxy.lan".into(),
                    port: 0,
                },
                expected: Err(true),
            },
        ];

        assert_table!(route_cases, |case| {
            let actual = case.config.route().map_err(|_| true);
            assert_eq!(actual, case.expected, "case '{}'", case.name);
        });

        // 2. Authority formatting & ureq proxy construction matrix
        let auth_cases = [
            ("unbracketed IPv6 literal wrapped in brackets", "::1", 80u16, "[::1]:80"),
            ("bracketed IPv6 literal avoids double brackets", "[::1]", 80u16, "[::1]:80"),
            ("domain host and TLS port", "a.test", 443u16, "a.test:443"),
            ("localhost and custom port", "localhost", 8888u16, "localhost:8888"),
            ("internal wildcard-style subdomain host", "app.internal", 8080u16, "app.internal:8080"),
        ];

        assert_table!(auth_cases, |(name, host, port, expected)| {
            assert_eq!(authority(host, port), expected, "{name}");
        });

        assert!(ureq_proxy(&route(UpstreamProxyType::HttpConnect, 8080)).is_ok());
        assert!(ureq_proxy(&route(UpstreamProxyType::Socks5, 1080)).is_ok());

        // 3. Settings serde round-trip
        let c = UpstreamProxyConfig {
            enabled: true,
            proxy_type: UpstreamProxyType::Socks5,
            host: "10.0.0.2".into(),
            port: 1080,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"socks5\""), "{json}");
        assert_eq!(serde_json::from_str::<UpstreamProxyConfig>(&json).unwrap(), c);
        assert_eq!(serde_json::from_str::<UpstreamProxyConfig>("{}").unwrap(), UpstreamProxyConfig::default());
        assert!(!ProtocolSettings::default().verify_upstream_tls);
    }

    #[test]
    fn connects_through_an_http_connect_proxy() {
        let target = mock::hello_server();
        let (proxy, seen) = mock::http_proxy();
        let s = connect(Some(&route(UpstreamProxyType::HttpConnect, proxy)), "127.0.0.1", target, Duration::from_secs(5)).unwrap();
        assert_eq!(read_all(s), "hello\n");
        assert_eq!(*seen.lock().unwrap(), [format!("127.0.0.1:{target}")]);
        // a refusal is an error that says so
        let e = connect(Some(&route(UpstreamProxyType::HttpConnect, proxy)), "blocked.test", 443, Duration::from_secs(5)).unwrap_err();
        assert!(e.to_string().contains("403"), "{e}");
    }

    #[test]
    fn connects_through_a_socks5_proxy_by_name() {
        let target = mock::hello_server();
        let (proxy, seen) = mock::socks5_proxy();
        let s = connect(Some(&route(UpstreamProxyType::Socks5, proxy)), "localhost.test", target, Duration::from_secs(5)).unwrap();
        assert_eq!(read_all(s), "hello\n");
        assert_eq!(*seen.lock().unwrap(), [format!("localhost.test:{target}")], "the name is resolved by the proxy");
        let s = connect(Some(&route(UpstreamProxyType::Socks5, proxy)), "127.0.0.1", target, Duration::from_secs(5)).unwrap();
        assert_eq!(read_all(s), "hello\n");
        // nothing listening there: the proxy's failure comes back as an error
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = connect(Some(&route(UpstreamProxyType::Socks5, proxy)), "127.0.0.1", closed, Duration::from_secs(5)).unwrap_err();
        assert!(e.to_string().contains("connection refused"), "{e}");
    }

    #[test]
    fn unreachable_proxy_is_named_in_the_error() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = connect(Some(&route(UpstreamProxyType::HttpConnect, closed)), "a.test", 80, Duration::from_secs(5)).unwrap_err();
        assert!(e.to_string().contains(&format!("upstream proxy 127.0.0.1:{closed}")), "{e}");
    }
}
