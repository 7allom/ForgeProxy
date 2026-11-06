//! Root certificate authority: an ECDSA P-256 self-signed CA certificate, kept as
//! `ca.crt` (PEM) and `ca.key` (PEM, private, mode 0600 on Unix) in the app's config
//! directory, and exportable (certificate only) as DER or PEM.
//!
//! It also mints short-lived per-host leaf certificates and caches a rustls `ServerConfig`
//! per host (`TlsConfigCache`), which the proxy uses to decrypt HTTPS when "Intercept HTTPS"
//! is on (proxy.rs).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const CERT_FILE: &str = "ca.crt";
pub const KEY_FILE: &str = "ca.key";
pub const COMMON_NAME: &str = "ForgeProxy Root CA";
const VALID_YEARS: i32 = 10;
/// Leaf certificates: valid from yesterday for this many days.
const LEAF_DAYS: i64 = 30;
/// Cached server configs kept before the cache starts over.
const CACHE_LIMIT: usize = 1000;

pub struct CertificateAuthority {
    pub ca_cert_pem: String,
    /// Never shown or exported; written only to `ca.key`.
    pub ca_key_pem: String,
    pub ca_cert_der: Vec<u8>,
}

#[derive(Debug)]
pub enum CaError {
    Io(std::io::Error),
    Generate(rcgen::Error),
    /// A file is there but isn't a usable certificate or key.
    Invalid(String),
    /// Not a hostname or IP address a certificate can be issued for.
    InvalidHost(String),
    Tls(rustls::Error),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaError::Io(e) => write!(f, "{e}"),
            CaError::Generate(e) => write!(f, "couldn't create the certificate: {e}"),
            CaError::Invalid(why) => write!(f, "{why}"),
            CaError::InvalidHost(h) => write!(f, "can't issue a certificate for {h:?}"),
            CaError::Tls(e) => write!(f, "TLS setup failed: {e}"),
        }
    }
}

impl From<std::io::Error> for CaError {
    fn from(e: std::io::Error) -> Self { CaError::Io(e) }
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self { CaError::Generate(e) }
}

impl From<rustls::Error> for CaError {
    fn from(e: rustls::Error) -> Self { CaError::Tls(e) }
}

/// A Subject Alternative Name for `host`: an IP address (IPv6 with or without brackets)
/// or a DNS name (lower-cased, trailing dot dropped). A name with a `*` is refused: the host
/// comes from a client's CONNECT, and a wildcard leaf (`*.example.com`, or `*` and `*.com`)
/// would be a certificate good for far more than the one site asked for.
fn san_for(host: &str) -> Result<(String, rcgen::SanType), CaError> {
    let h = host.trim().trim_end_matches('.');
    let bare = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok((ip.to_string(), rcgen::SanType::IpAddress(ip)));
    }
    let name = h.to_ascii_lowercase();
    let valid = !name.is_empty() && name.len() <= 253
        && name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    if !valid {
        return Err(CaError::InvalidHost(host.to_string()));
    }
    let dns = name.as_str().try_into().map_err(|_| CaError::InvalidHost(host.to_string()))?;
    Ok((name, rcgen::SanType::DnsName(dns)))
}

/// Where the CA lives: `$FORGEPROXY_CONFIG_DIR`, else the platform's per-user config
/// directory (`~/.config/forgeproxy`, `~/Library/Application Support/ForgeProxy`,
/// `%APPDATA%\ForgeProxy`).
pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("FORGEPROXY_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    crate::paths::config_with(&crate::paths::env, std::env::consts::OS)
}

/// The base64 body of the first `-----BEGIN CERTIFICATE-----` block, decoded.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")? + "-----BEGIN CERTIFICATE-----".len();
    let end = start + pem[start..].find("-----END CERTIFICATE-----")?;
    let body: String = pem[start..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = crate::codec::base64_decode(&body);
    (!der.is_empty()).then_some(der)
}

impl CertificateAuthority {
    /// A new CA: fresh P-256 key, subject CN=ForgeProxy Root CA, O=ForgeProxy,
    /// OU=Security Workbench, CA:TRUE, keyCertSign + cRLSign, valid 10 years from today.
    pub fn generate() -> Result<Self, CaError> {
        use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
        let key = KeyPair::generate()?; // ECDSA P-256 with SHA-256
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, COMMON_NAME);
        dn.push(DnType::OrganizationName, "ForgeProxy");
        dn.push(DnType::OrganizationalUnitName, "Security Workbench");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let (y, m, d) = crate::codec::unix_to_date(now);
        // from yesterday, so a clock slightly behind still accepts it
        let (py, pm, pd) = crate::codec::unix_to_date(now - 86_400);
        params.not_before = rcgen::date_time_ymd(py as i32, pm as u8, pd as u8);
        params.not_after = rcgen::date_time_ymd(y as i32 + VALID_YEARS, m as u8, d.min(28) as u8);
        let cert = params.self_signed(&key)?;
        Ok(CertificateAuthority { ca_cert_pem: cert.pem(), ca_key_pem: key.serialize_pem(), ca_cert_der: cert.der().to_vec() })
    }

    /// Load `ca.crt` and `ca.key` from `dir`, or generate and save a new CA when neither
    /// exists. A pair that exists but doesn't load (or doesn't match) is an error, not
    /// silently replaced: browsers may already trust it.
    pub fn load_or_generate(dir: &Path) -> Result<(Self, bool), CaError> {
        let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
        match (cert_path.exists(), key_path.exists()) {
            (false, false) => {
                let ca = Self::generate()?;
                ca.save(dir)?;
                Ok((ca, true))
            }
            (true, true) => Ok((Self::load(&cert_path, &key_path)?, false)),
            (true, false) => Err(CaError::Invalid(format!("{} exists but {} is missing", cert_path.display(), key_path.display()))),
            (false, true) => Err(CaError::Invalid(format!("{} exists but {} is missing", key_path.display(), cert_path.display()))),
        }
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        let ca_cert_pem = std::fs::read_to_string(cert_path)?;
        let ca_key_pem = std::fs::read_to_string(key_path)?;
        let ca_cert_der = pem_to_der(&ca_cert_pem).ok_or_else(|| CaError::Invalid(format!("{} isn't a PEM certificate", cert_path.display())))?;
        let key = rcgen::KeyPair::from_pem(&ca_key_pem).map_err(|e| CaError::Invalid(format!("{} isn't a usable private key: {e}", key_path.display())))?;
        // the certificate carries the key's public half verbatim
        let public = key.public_key_raw();
        if !ca_cert_der.windows(public.len()).any(|w| w == public) {
            return Err(CaError::Invalid(format!("{} and {} don't belong together", cert_path.display(), key_path.display())));
        }
        Ok(CertificateAuthority { ca_cert_pem, ca_key_pem, ca_cert_der })
    }

    /// Write `ca.crt` and `ca.key` into `dir` (created 0700); the key is 0600 on Unix.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        crate::paths::create_private_dir(dir)?;
        crate::paths::write_private(&dir.join(KEY_FILE), self.ca_key_pem.as_bytes())?;
        crate::paths::refuse_symlink(&dir.join(CERT_FILE))?;
        std::fs::write(dir.join(CERT_FILE), &self.ca_cert_pem)
    }

    pub fn export_cert_der(&self, dest: &Path) -> std::io::Result<()> {
        write_public(dest, &self.ca_cert_der)
    }

    pub fn export_cert_pem(&self, dest: &Path) -> std::io::Result<()> {
        write_public(dest, self.ca_cert_pem.as_bytes())
    }

    /// A leaf certificate for `host` (a DNS name or IP address), signed by this CA: CN and
    /// SAN are the host, digitalSignature + keyEncipherment, serverAuth, valid from yesterday
    /// for 30 days. Returns the certificate and its new private key.
    pub fn mint_leaf_cert(&self, host: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CaError> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
        let (name, san) = san_for(host)?;
        let ca_key = KeyPair::from_pem(&self.ca_key_pem)?;
        let issuer = rcgen::Issuer::from_ca_cert_der(&CertificateDer::from(self.ca_cert_der.as_slice()), ca_key)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![san];
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let date = |ts: i64| { let (y, m, d) = crate::codec::unix_to_date(ts); rcgen::date_time_ymd(y as i32, m as u8, d as u8) };
        params.not_before = date(now - 86_400);
        params.not_after = date(now + LEAF_DAYS * 86_400);
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &issuer)?;
        Ok((cert.der().clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))))
    }

    /// Base64 SHA-256 of the certificate's SubjectPublicKeyInfo: the pin Chromium's
    /// `--ignore-certificate-errors-spki-list` takes.
    pub fn spki_sha256_base64(&self) -> Result<String, CaError> {
        use sha2::Digest;
        let (_, cert) = x509_parser::parse_x509_certificate(&self.ca_cert_der)
            .map_err(|e| CaError::Invalid(format!("can't read the root CA certificate: {e}")))?;
        let spki = cert.tbs_certificate.subject_pki.raw;
        Ok(crate::codec::base64_encode(&sha2::Sha256::digest(spki), false, true))
    }

    /// The certificate's SHA-256 fingerprint, "AB:CD:...", as browsers show it.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(&self.ca_cert_der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
    }
}

/// A rustls server configuration per host, built from a freshly minted leaf certificate the
/// first time a host is seen and reused after that (signing is the slow part).
pub struct TlsConfigCache {
    ca: Arc<CertificateAuthority>,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl TlsConfigCache {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        TlsConfigCache { ca, cache: Mutex::new(HashMap::new()) }
    }

    /// Hosts with a cached configuration.
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// The server config for `host` (case-insensitive), minting its certificate on first use.
    /// It offers ALPN "http/1.1" and presents the leaf certificate followed by the root.
    pub fn get_server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, CaError> {
        let (key, _) = san_for(host)?;
        if let Some(cfg) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            return Ok(cfg.clone());
        }
        // mint outside the lock; if another thread got there first, keep its config
        let (cert, private) = self.ca.mint_leaf_cert(host)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // the chain includes the root: a browser launched with the root's SPKI pin only
        // accepts the connection if that key is among the certificates the server presents
        let chain = vec![cert, CertificateDer::from(self.ca.ca_cert_der.clone())];
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, private)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= CACHE_LIMIT && !cache.contains_key(&key) {
            cache.clear();
        }
        Ok(cache.entry(key).or_insert_with(|| Arc::new(cfg)).clone())
    }
}

fn write_public(dest: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, data)
}

/// A warning when `dir`'s `ca.key` can be read or written by other users (any of the
/// group/other permission bits set), which would let them impersonate sites to browsers
/// that trust the CA. None when the key is owner-only, missing, or not on Unix.
pub fn key_permission_warning(dir: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(KEY_FILE);
        let mode = std::fs::metadata(&path).ok()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!("The root CA private key {} is accessible to other users (mode {mode:o}). \
                Restrict it with: chmod 600 \"{}\"", path.display(), path.display()));
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

/// Default export location: `~/Downloads` if it exists, else the home directory.
pub fn default_export_dir() -> PathBuf {
    let home = crate::paths::home_dir();
    let downloads = home.join("Downloads");
    if downloads.is_dir() { downloads } else { home }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("forgeproxy-ca-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn generates_pem_and_der() {
        let ca = CertificateAuthority::generate().unwrap();
        assert!(ca.ca_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca.ca_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(pem_to_der(&ca.ca_cert_pem).unwrap(), ca.ca_cert_der);
        assert_eq!(ca.ca_cert_der[0], 0x30, "DER SEQUENCE");
        assert_eq!(ca.fingerprint().len(), 32 * 3 - 1);
        // subject names in the certificate
        for name in ["ForgeProxy Root CA", "ForgeProxy", "Security Workbench"] {
            assert!(contains(&ca.ca_cert_der, name.as_bytes()), "{name}");
        }
        // two CAs have different keys (and so different serials)
        assert_ne!(ca.ca_cert_der, CertificateAuthority::generate().unwrap().ca_cert_der);
    }

    #[test]
    fn has_ca_constraints_and_signing_usages() {
        let der = CertificateAuthority::generate().unwrap().ca_cert_der;
        // basicConstraints (2.5.29.19), critical, value SEQUENCE { cA TRUE }
        assert!(contains(&der, &[0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff]), "CA:TRUE");
        // keyUsage (2.5.29.15), critical, BIT STRING with keyCertSign (bit 5) and cRLSign (bit 6)
        assert!(contains(&der, &[0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06]), "keyCertSign + cRLSign");
        // ecdsa-with-SHA256 signature algorithm (1.2.840.10045.4.3.2)
        assert!(contains(&der, &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]));
    }

    #[test]
    fn validity_is_about_ten_years() {
        let der = CertificateAuthority::generate().unwrap().ca_cert_der;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let (y, _, _) = crate::codec::unix_to_date(now);
        // UTCTime "YYMMDD000000Z" for notAfter: two-digit year y+10
        let after = format!("{:02}", (y + 10) % 100);
        let times: Vec<String> = der.windows(15).filter(|w| w[0] == 0x17 && w[1] == 13).map(|w| String::from_utf8_lossy(&w[2..15]).into_owned()).collect();
        assert_eq!(times.len(), 2, "notBefore and notAfter");
        assert!(times[1].starts_with(&after), "{times:?}");
    }

    #[test]
    fn save_and_reload_keeps_the_certificate() {
        let dir = temp_dir("roundtrip");
        let (ca, created) = CertificateAuthority::load_or_generate(&dir).unwrap();
        assert!(created);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(KEY_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let (again, created) = CertificateAuthority::load_or_generate(&dir).unwrap();
        assert!(!created);
        assert_eq!(again.ca_cert_der, ca.ca_cert_der);
        assert_eq!(again.ca_key_pem, ca.ca_key_pem);
        // exports: DER bytes and PEM text, never the key
        ca.export_cert_der(&dir.join("out/ca.der")).unwrap();
        ca.export_cert_pem(&dir.join("out/ca.pem")).unwrap();
        assert_eq!(std::fs::read(dir.join("out/ca.der")).unwrap(), ca.ca_cert_der);
        let pem = std::fs::read_to_string(dir.join("out/ca.pem")).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE") && !pem.contains("PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_write_the_key_through_a_symlink() {
        let dir = temp_dir("keylink");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = temp_dir("keylink-target");
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("stolen.pem");
        std::os::unix::fs::symlink(&target, dir.join(KEY_FILE)).unwrap();
        let ca = CertificateAuthority::generate().unwrap();
        assert!(ca.save(&dir).is_err());
        assert!(!target.exists(), "the key wasn't written through the link");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn warns_about_a_key_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("keyperms");
        CertificateAuthority::generate().unwrap().save(&dir).unwrap();
        assert_eq!(key_permission_warning(&dir), None, "saved owner-only");
        std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        let w = key_permission_warning(&dir).expect("0644 is readable by others");
        assert!(w.contains("mode 644") && w.contains("chmod 600"), "{w}");
        std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(key_permission_warning(&dir).is_some(), "group-readable counts too");
        assert_eq!(key_permission_warning(&temp_dir("nokey")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_or_mismatched_files_are_not_replaced() {
        let dir = temp_dir("broken");
        let a = CertificateAuthority::generate().unwrap();
        a.save(&dir).unwrap();
        // a key from another CA
        let b = CertificateAuthority::generate().unwrap();
        std::fs::write(dir.join(KEY_FILE), &b.ca_key_pem).unwrap();
        assert!(matches!(CertificateAuthority::load_or_generate(&dir), Err(CaError::Invalid(m)) if m.contains("don't belong together")));
        std::fs::write(dir.join(CERT_FILE), "garbage").unwrap();
        assert!(matches!(CertificateAuthority::load_or_generate(&dir), Err(CaError::Invalid(_))));
        std::fs::remove_file(dir.join(KEY_FILE)).unwrap();
        assert!(matches!(CertificateAuthority::load_or_generate(&dir), Err(CaError::Invalid(m)) if m.contains("missing")));
        // the broken certificate is still there, untouched
        assert_eq!(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "garbage");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- leaf certificates ----

    /// TLS handshake in memory: a client trusting only `ca` connects to `server` as `name`.
    /// Ok(negotiated ALPN) when the server's certificate verifies for that name.
    fn handshake(ca: &CertificateAuthority, server: Arc<rustls::ServerConfig>, name: &str) -> Result<Option<Vec<u8>>, rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca.ca_cert_der.clone())).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions().unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name = rustls_pki_types::ServerName::try_from(name.to_string()).unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
        let mut srv = rustls::ServerConnection::new(server).unwrap();
        for _ in 0..20 {
            let mut buf = Vec::new();
            while client.wants_write() { client.write_tls(&mut buf).unwrap(); }
            if !buf.is_empty() { srv.read_tls(&mut buf.as_slice()).unwrap(); srv.process_new_packets()?; }
            let mut buf = Vec::new();
            while srv.wants_write() { srv.write_tls(&mut buf).unwrap(); }
            if !buf.is_empty() { client.read_tls(&mut buf.as_slice()).unwrap(); client.process_new_packets()?; }
            if !client.is_handshaking() && !srv.is_handshaking() {
                return Ok(client.alpn_protocol().map(|p| p.to_vec()));
            }
        }
        panic!("handshake didn't finish");
    }

    #[test]
    fn leaf_for_a_domain_chains_to_the_root() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let (cert, _) = ca.mint_leaf_cert("example.com").unwrap();
        assert!(contains(&cert, b"example.com"), "CN/SAN carry the host");
        // SAN: dNSName [2] "example.com"
        assert!(contains(&cert, &[&[0x82u8, 11][..], b"example.com"].concat()));
        // serverAuth EKU (1.3.6.1.5.5.7.3.1), not a CA
        assert!(contains(&cert, &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]));
        let cache = TlsConfigCache::new(ca.clone());
        let cfg = cache.get_server_config("example.com").unwrap();
        // a client trusting only the root accepts it for example.com, and agrees on http/1.1
        assert_eq!(handshake(&ca, cfg.clone(), "example.com").unwrap(), Some(b"http/1.1".to_vec()));
        // ...but not for another name, and not when it trusts a different root
        assert!(handshake(&ca, cfg.clone(), "other.example").is_err());
        let stranger = CertificateAuthority::generate().unwrap();
        assert!(handshake(&stranger, cfg, "example.com").is_err());
    }

    #[test]
    fn leaf_for_ip_addresses() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let (cert, _) = ca.mint_leaf_cert("127.0.0.1").unwrap();
        // SAN: iPAddress [7] 127.0.0.1
        assert!(contains(&cert, &[0x87, 0x04, 127, 0, 0, 1]));
        let cache = TlsConfigCache::new(ca.clone());
        assert!(handshake(&ca, cache.get_server_config("127.0.0.1").unwrap(), "127.0.0.1").is_ok());
        assert!(handshake(&ca, cache.get_server_config("127.0.0.1").unwrap(), "127.0.0.2").is_err());
        // IPv6, bracketed as in a URL
        let (cert, _) = ca.mint_leaf_cert("[::1]").unwrap();
        assert!(contains(&cert, &[&[0x87u8, 16][..], &[0; 15], &[1]].concat()));
        assert!(handshake(&ca, cache.get_server_config("::1").unwrap(), "::1").is_ok());
    }

    #[test]
    fn leaf_validity_and_bad_hosts() {
        let ca = CertificateAuthority::generate().unwrap();
        let (cert, _) = ca.mint_leaf_cert("Shop.Example.COM.").unwrap();
        assert!(contains(&cert, b"shop.example.com"), "lower-cased, trailing dot dropped");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let ymd = |ts: i64| { let (y, m, d) = crate::codec::unix_to_date(ts); format!("{:02}{m:02}{d:02}000000Z", y % 100) };
        let times: Vec<String> = cert.windows(15).filter(|w| w[0] == 0x17 && w[1] == 13).map(|w| String::from_utf8_lossy(&w[2..15]).into_owned()).collect();
        assert_eq!(times, [ymd(now - 86_400), ymd(now + LEAF_DAYS * 86_400)]);
        for bad in ["", "bad host", "a..b", "exa$mple.com", &"x".repeat(64), "*", "*.com", "*.example.com", "a*.example.com", "shop.*.example.com"] {
            assert!(matches!(ca.mint_leaf_cert(bad), Err(CaError::InvalidHost(_))), "{bad:?}");
        }
    }

    #[test]
    fn spki_pin() {
        use rcgen::PublicKeyData;
        let ca = CertificateAuthority::generate().unwrap();
        let pin = ca.spki_sha256_base64().unwrap();
        // 32 bytes of SHA-256 in standard Base64: 43 characters and one '='
        assert_eq!(pin.len(), 44);
        assert!(pin.ends_with('=') && !pin[..43].contains('='));
        assert!(pin[..43].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'));
        assert_eq!(ca.spki_sha256_base64().unwrap(), pin, "stable for one CA");
        // the same hash computed from the private key's public half
        use sha2::Digest;
        let spki = rcgen::KeyPair::from_pem(&ca.ca_key_pem).unwrap().subject_public_key_info();
        assert_eq!(crate::codec::base64_encode(&sha2::Sha256::digest(&spki), false, true), pin);
        // a regenerated CA has a new key, so a new pin
        assert_ne!(CertificateAuthority::generate().unwrap().spki_sha256_base64().unwrap(), pin);
        let broken = CertificateAuthority { ca_cert_pem: String::new(), ca_key_pem: String::new(), ca_cert_der: vec![1, 2, 3] };
        assert!(broken.spki_sha256_base64().is_err());
    }

    #[test]
    fn server_presents_the_root_after_the_leaf() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let cfg = TlsConfigCache::new(ca.clone()).get_server_config("example.com").unwrap();
        // run a handshake and look at what the client was shown
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca.ca_cert_der.clone())).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ccfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        let mut client = rustls::ClientConnection::new(Arc::new(ccfg), "example.com".try_into().unwrap()).unwrap();
        let mut srv = rustls::ServerConnection::new(cfg).unwrap();
        while client.is_handshaking() || srv.is_handshaking() {
            let mut b = Vec::new();
            while client.wants_write() { client.write_tls(&mut b).unwrap(); }
            if !b.is_empty() { srv.read_tls(&mut b.as_slice()).unwrap(); srv.process_new_packets().unwrap(); }
            let mut b = Vec::new();
            while srv.wants_write() { srv.write_tls(&mut b).unwrap(); }
            if !b.is_empty() { client.read_tls(&mut b.as_slice()).unwrap(); client.process_new_packets().unwrap(); }
        }
        let chain = client.peer_certificates().unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].as_ref(), ca.ca_cert_der.as_slice(), "the root, whose key the browser pin names");
    }

    #[test]
    fn cache_returns_the_same_config() {
        let cache = TlsConfigCache::new(Arc::new(CertificateAuthority::generate().unwrap()));
        let a = cache.get_server_config("example.com").unwrap();
        let b = cache.get_server_config("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        // same host in other spellings
        assert!(Arc::ptr_eq(&a, &cache.get_server_config("EXAMPLE.com.").unwrap()));
        let c = cache.get_server_config("other.com").unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(cache.len(), 2);
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
