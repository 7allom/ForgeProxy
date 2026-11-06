//! Offline encoders/decoders for the Decoder tool.
//! Standard encoding and decoding modes (see MECHANICS.md → Decoder).

const B64_STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64EncodingOptions: URL (URL-safe alphabet) and NO_PADDING.
pub fn base64_encode(data: &[u8], url_safe: bool, padding: bool) -> String {
    let table = if url_safe { B64_URL } else { B64_STD };
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(table[((n >> 6) & 63) as usize] as char);
        } else if padding {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[(n & 63) as usize] as char);
        } else if padding {
            out.push('=');
        }
    }
    out
}

/// Accepts both the standard and URL-safe alphabets, with or without padding.
pub fn base64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> i32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i32,
            b'a'..=b'z' => (c - b'a' + 26) as i32,
            b'0'..=b'9' => (c - b'0' + 52) as i32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => -1,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| val(*b) >= 0).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= (val(c) as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out
}

/// URLEncoding::KEY_CHARACTERS (estimated set) or ALL_CHARACTERS.
pub fn url_encode(s: &str, all: bool) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        let plain = matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~');
        if plain && !all {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02x}", b));
        }
    }
    out
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let pair = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(pair, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Copy, PartialEq)]
// the encoder supports every mode; the Decoder currently offers only AllHex
#[allow(dead_code)]
pub enum HtmlMode {
    /// Encode only HTML special characters.
    Standard,
    /// Specials as STANDARD, every other character as a decimal entity.
    AllCharacters,
    /// Every character as a decimal entity.
    AllDecimal,
    /// Every character as a hex entity.
    AllHex,
}

fn html_special(c: char) -> Option<&'static str> {
    match c {
        '&' => Some("&amp;"),
        '<' => Some("&lt;"),
        '>' => Some("&gt;"),
        '"' => Some("&quot;"),
        '\'' => Some("&#39;"),
        _ => None,
    }
}

pub fn html_encode(s: &str, mode: HtmlMode) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match mode {
            HtmlMode::Standard => match html_special(c) {
                Some(e) => out.push_str(e),
                None => out.push(c),
            },
            HtmlMode::AllCharacters => match html_special(c) {
                Some(e) => out.push_str(e),
                None => out.push_str(&format!("&#{};", c as u32)),
            },
            HtmlMode::AllDecimal => out.push_str(&format!("&#{};", c as u32)),
            HtmlMode::AllHex => out.push_str(&format!("&#x{:x};", c as u32)),
        }
    }
    out
}

/// Decodes named specials plus decimal (&#65;) and hex (&#x41;) entities.
pub fn html_decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let Some(end) = tail.find(';').filter(|&e| e <= 10) {
            let ent = &tail[1..end];
            let decoded = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
                _ => None,
            };
            if let Some(c) = decoded {
                out.push(c);
                rest = &tail[end + 1..];
                continue;
            }
        }
        out.push('&');
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    digits
        .chunks(2)
        .filter(|c| c.len() == 2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

/// Lower-case hex, no separators ("4869").
pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Base64URL as used by JWTs: URL-safe alphabet, no padding.
pub fn base64url_encode(data: &[u8]) -> String {
    base64_encode(data, true, false)
}

/// Strict Base64URL: only `A-Z a-z 0-9 - _`, optional trailing `=` padding, and a length
/// that a real encoding can have. None for anything else (unlike `base64_decode`, which
/// skips characters it doesn't know).
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || body.len() % 4 == 1 {
        return None;
    }
    if !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    Some(base64_decode(body))
}

// ---- JWT ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct JwtParts {
    pub header_raw: String,
    pub payload_raw: String,
    pub signature_raw: String,
    /// Pretty-printed header JSON.
    pub header_json: String,
    /// Pretty-printed payload (claims) JSON.
    pub payload_json: String,
    pub alg: Option<String>,
    pub typ: Option<String>,
    pub kid: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    /// Registered claims present in the payload, as text: iss, sub, aud, jti.
    pub claims: Vec<(&'static str, String)>,
    /// Decoded signature length in bytes (0 for an unsigned token).
    pub signature_len: usize,
}

/// Does this look like a JWT (three dot-separated Base64URL parts whose first two are
/// JSON objects)?
pub fn is_jwt(s: &str) -> bool {
    s.len() < 64 * 1024 && parse_jwt(s).is_some()
}

pub fn parse_jwt(token: &str) -> Option<JwtParts> {
    parse_jwt_detailed(token).ok()
}

/// `parse_jwt` with the reason a token was rejected. Accepts surrounding whitespace and a
/// leading "Bearer ".
pub fn parse_jwt_detailed(token: &str) -> Result<JwtParts, String> {
    let t = token.trim();
    let t = t.strip_prefix("Bearer ").or_else(|| t.strip_prefix("bearer ")).unwrap_or(t).trim();
    let parts: Vec<&str> = t.split('.').collect();
    match parts.len() {
        3 => {}
        5 => return Err("Five parts: this is an encrypted JWT (JWE), which can't be read without the key.".into()),
        n => return Err(format!("A JWT has 3 parts separated by dots (header.payload.signature); this has {n}.")),
    }
    let json = |raw: &str, what: &str| -> Result<serde_json::Value, String> {
        if raw.is_empty() {
            return Err(format!("The {what} is empty."));
        }
        let bytes = base64url_decode(raw).ok_or_else(|| format!("The {what} isn't valid Base64URL."))?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| format!("The {what} isn't JSON."))?;
        if !v.is_object() {
            return Err(format!("The {what} must be a JSON object."));
        }
        Ok(v)
    };
    let header = json(parts[0], "header")?;
    let payload = json(parts[1], "payload")?;
    let signature = base64url_decode(parts[2]).ok_or("The signature isn't valid Base64URL.")?;
    let text = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    // NumericDate: seconds since the epoch; tolerate fractional values
    let time = |k: &str| payload.get(k).and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)));
    let mut claims = Vec::new();
    for k in ["iss", "sub", "aud", "jti"] {
        if let Some(v) = payload.get(k) {
            let shown = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(a) => a.iter().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(", "),
                other => other.to_string(),
            };
            claims.push((k, shown));
        }
    }
    Ok(JwtParts {
        header_raw: parts[0].to_string(),
        payload_raw: parts[1].to_string(),
        signature_raw: parts[2].to_string(),
        header_json: serde_json::to_string_pretty(&header).unwrap_or_default(),
        payload_json: serde_json::to_string_pretty(&payload).unwrap_or_default(),
        alg: text(&header, "alg"),
        typ: text(&header, "typ"),
        kid: text(&header, "kid"),
        exp: time("exp"),
        iat: time("iat"),
        nbf: time("nbf"),
        claims,
        signature_len: signature.len(),
    })
}

/// A Unix timestamp's UTC date: (year, month 1-12, day 1-31).
pub fn unix_to_date(ts: i64) -> (i64, i64, i64) {
    let days = ts.div_euclid(86_400);
    // civil-from-days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// A Unix timestamp as "2026-11-03 14:05:09 UTC".
pub fn format_unix_utc(ts: i64) -> String {
    let (year, month, day) = unix_to_date(ts);
    let secs = ts.rem_euclid(86_400);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// A length of time in its largest whole unit: "45 seconds", "12 minutes", "1 hour".
pub fn duration_words(secs: i64) -> String {
    let s = secs.unsigned_abs();
    let (n, unit) = match s {
        0..=59 => (s, "second"),
        60..=3599 => (s / 60, "minute"),
        3600..=86_399 => (s / 3600, "hour"),
        86_400..=2_591_999 => (s / 86_400, "day"),
        2_592_000..=31_535_999 => (s / 2_592_000, "month"),
        _ => (s / 31_536_000, "year"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// Expiry status at `now`: "Expired 12 minutes ago" or "Valid for 2 hours".
pub fn expiry_status(exp: i64, now: i64) -> String {
    if exp <= now {
        format!("Expired {} ago", duration_words(now - exp))
    } else {
        format!("Valid for {}", duration_words(exp - now))
    }
}

// ---- HTTP/1.1 chunked transfer coding ---------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum CodecError {
    /// A chunk-size line that isn't hexadecimal (or is too large).
    BadChunkSize(String),
    /// A chunk isn't followed by CRLF.
    MissingCrlf,
    /// The data ends before the last (zero-size) chunk.
    Truncated,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::BadChunkSize(l) => write!(f, "bad chunk size line {l:?}"),
            CodecError::MissingCrlf => write!(f, "chunk data isn't followed by CRLF"),
            CodecError::Truncated => write!(f, "chunked body ends early"),
        }
    }
}

/// Index of the next CRLF at or after `from`.
fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?.windows(2).position(|w| w == b"\r\n").map(|i| from + i)
}

/// Decode a chunked body: `<hex size>[;ext]\r\n<data>\r\n` ... `0\r\n[trailers]\r\n`.
/// Chunk extensions and trailer fields are dropped.
pub fn decode_chunked_body(raw_chunks: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let eol = find_crlf(raw_chunks, pos).ok_or(CodecError::Truncated)?;
        let line = String::from_utf8_lossy(&raw_chunks[pos..eol]).into_owned();
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || size_text.len() > 16 || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CodecError::BadChunkSize(line));
        }
        let size = usize::from_str_radix(size_text, 16).map_err(|_| CodecError::BadChunkSize(line.clone()))?;
        pos = eol + 2;
        if size == 0 {
            // trailer fields (if any), then the final empty line
            loop {
                let end = find_crlf(raw_chunks, pos).ok_or(CodecError::Truncated)?;
                let empty = end == pos;
                pos = end + 2;
                if empty {
                    return Ok(out);
                }
            }
        }
        let end = pos.checked_add(size).filter(|&e| e <= raw_chunks.len()).ok_or(CodecError::Truncated)?;
        out.extend_from_slice(&raw_chunks[pos..end]);
        match raw_chunks.get(end..end + 2) {
            Some(b"\r\n") => pos = end + 2,
            Some(_) => return Err(CodecError::MissingCrlf),
            None => return Err(CodecError::Truncated),
        }
    }
}

/// Header bytes as text: UTF-8 when they are valid UTF-8, otherwise Latin-1 (one char per
/// byte, so every byte comes back unchanged). The bool says Latin-1 was used.
pub fn decode_header_bytes(b: &[u8]) -> (String, bool) {
    match std::str::from_utf8(b) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (b.iter().map(|&c| c as char).collect(), true),
    }
}

/// Header text back to bytes: UTF-8, or for Latin-1 text one byte per char (a char past
/// U+00FF, typed in Intercept say, is written as UTF-8).
pub fn encode_header_text(s: &str, latin1: bool) -> Vec<u8> {
    if !latin1 {
        return s.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match u8::try_from(c as u32) {
            Ok(b) => out.push(b),
            Err(_) => out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
        }
    }
    out
}

/// An HTTP response split into its status line, headers (in order) and body bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The head wasn't UTF-8 and is held as Latin-1 (see `decode_header_bytes`).
    pub latin1: bool,
}

impl HttpResponse {
    /// Split a raw response at the first blank line (CRLF or LF line endings).
    pub fn parse(raw: &[u8]) -> Self {
        let (split, gap) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(i) => (i, 4),
            None => match raw.windows(2).position(|w| w == b"\n\n") { Some(i) => (i, 2), None => (raw.len(), 0) },
        };
        let (head, latin1) = decode_header_bytes(&raw[..split]);
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or("").trim_end().to_string();
        let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
        HttpResponse { status_line, headers, body: raw[(split + gap).min(raw.len())..].to_vec(), latin1 }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// `head_text` as the bytes to send (the original bytes for a Latin-1 head).
    #[cfg(test)]
    pub fn head_bytes(&self) -> Vec<u8> {
        encode_header_text(&self.head_text(), self.latin1)
    }

    /// Status line and headers with CRLFs, ending in the blank line.
    pub fn head_text(&self) -> String {
        let mut s = format!("{}\r\n", self.status_line);
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str("\r\n");
        s
    }
}

/// De-chunk a `Transfer-Encoding: chunked` response: decode the body, drop
/// Transfer-Encoding and any Content-Length, add `Content-Length: <decoded length>`.
/// Anything else, a body that doesn't decode (it's forwarded as it came), or a
/// Transfer-Encoding with codings besides chunked is returned unchanged.
pub fn normalize_response(mut res: HttpResponse) -> HttpResponse {
    let Some(te) = res.header("transfer-encoding") else { return res };
    let codings: Vec<String> = te.split(',').map(|c| c.trim().to_ascii_lowercase()).filter(|c| !c.is_empty()).collect();
    if codings != ["chunked"] {
        return res;
    }
    let Ok(body) = decode_chunked_body(&res.body) else { return res };
    res.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding") && !k.eq_ignore_ascii_case("content-length"));
    res.headers.push(("Content-Length".to_string(), body.len().to_string()));
    res.body = body;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        let e = base64_encode(b"hello?", true, false);
        assert_eq!(String::from_utf8(base64_decode(&e)).unwrap(), "hello?");
    }

    #[test]
    fn codec_round_trips() {
        let samples: [&[u8]; 4] = [b"", b"a", b"hello world?&=/", "üñí <tag> \"q\"".as_bytes()];
        for s in samples {
            let text = String::from_utf8(s.to_vec()).unwrap();
            assert_eq!(url_decode(&url_encode(&text, false)), text);
            assert_eq!(url_decode(&url_encode(&text, true)), text);
            assert_eq!(base64_decode(&base64_encode(s, false, true)), s);
            assert_eq!(base64url_decode(&base64url_encode(s)).unwrap(), s);
            assert_eq!(hex_decode(&hex_encode(s)), s);
            for mode in [HtmlMode::Standard, HtmlMode::AllCharacters, HtmlMode::AllDecimal, HtmlMode::AllHex] {
                assert_eq!(html_decode(&html_encode(&text, mode)), text);
            }
        }
        assert_eq!(hex_encode(b"Hi"), "4869");
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn strict_base64url() {
        assert_eq!(base64url_decode("SGk").unwrap(), b"Hi"); // unpadded
        assert_eq!(base64url_decode("SGk=").unwrap(), b"Hi"); // padded
        assert_eq!(base64url_decode("-_8").unwrap(), [0xfb, 0xff]);
        assert!(base64url_decode("SGk+").is_none()); // standard alphabet
        assert!(base64url_decode("S").is_none()); // impossible length
        assert!(base64url_decode("SG k").is_none());
        assert!(base64url_decode("SGk===").is_none());
    }

    // header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234567890","name":"John Doe","iat":1516239022}
    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn decodes_a_standard_jwt() {
        let j = parse_jwt(JWT).unwrap();
        assert_eq!(j.alg.as_deref(), Some("HS256"));
        assert_eq!(j.typ.as_deref(), Some("JWT"));
        assert_eq!(j.iat, Some(1_516_239_022));
        assert_eq!(j.exp, None);
        assert_eq!(j.claims, vec![("sub", "1234567890".to_string())]);
        assert_eq!(j.signature_len, 32);
        assert_eq!(j.header_json, "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}");
        assert!(j.payload_json.contains("\n  \"name\": \"John Doe\""));
        // keys stay in the token's order (serde_json preserve_order), not sorted
        let keys: Vec<&str> = j.payload_json.lines().filter_map(|l| l.trim().strip_prefix('"')?.split('"').next()).collect();
        assert_eq!(keys, ["sub", "name", "iat"]);
        assert_eq!(format!("{}.{}.{}", j.header_raw, j.payload_raw, j.signature_raw), JWT);
        // "Bearer " and whitespace are accepted
        assert_eq!(parse_jwt(&format!("  Bearer {JWT}\n")).unwrap(), j);
        assert!(is_jwt(JWT));
    }

    #[test]
    fn unpadded_segments_of_every_length() {
        // payload lengths that leave 0, 1 and 2 bytes over: unpadded segments of every shape
        for payload in [r#"{"a":1}"#, r#"{"ab":1}"#, r#"{"abc":1}"#] {
            let tok = format!("{}.{}.", base64url_encode(br#"{"alg":"none"}"#), base64url_encode(payload.as_bytes()));
            let j = parse_jwt(&tok).unwrap_or_else(|| panic!("{tok}"));
            assert_eq!(j.alg.as_deref(), Some("none"));
            assert_eq!(j.signature_len, 0, "unsigned token");
            // and with padding added back
            let padded = format!("{}=.{}.", base64url_encode(br#"{"alg":"none"}"#), base64url_encode(payload.as_bytes()));
            if base64url_encode(br#"{"alg":"none"}"#).len() % 4 != 0 {
                assert!(parse_jwt(&padded).is_some());
            }
        }
    }

    #[test]
    fn timestamps_and_claims() {
        let payload = r#"{"iss":"https://idp.test","aud":["api","web"],"exp":1700003600,"iat":1700000000,"nbf":1699999990.5,"jti":7}"#;
        let tok = format!("{}.{}.c2ln", base64url_encode(br#"{"alg":"RS256","kid":"k1"}"#), base64url_encode(payload.as_bytes()));
        let j = parse_jwt(&tok).unwrap();
        assert_eq!((j.exp, j.iat, j.nbf), (Some(1_700_003_600), Some(1_700_000_000), Some(1_699_999_990)));
        assert_eq!(j.kid.as_deref(), Some("k1"));
        assert_eq!(j.claims, vec![("iss", "https://idp.test".to_string()), ("aud", "api, web".to_string()), ("jti", "7".to_string())]);
        assert_eq!(format_unix_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_unix_utc(951_782_400), "2000-02-29 00:00:00 UTC"); // leap day
        assert_eq!(expiry_status(1_700_003_600, 1_700_004_320), "Expired 12 minutes ago");
        assert_eq!(expiry_status(1_700_003_600, 1_699_996_400), "Valid for 2 hours");
        assert_eq!(duration_words(1), "1 second");
        assert_eq!(duration_words(86_400 * 3), "3 days");
    }

    #[test]
    fn rejects_malformed_tokens() {
        let h = base64url_encode(br#"{"alg":"HS256"}"#);
        let p = base64url_encode(br#"{"sub":"x"}"#);
        let err = |t: &str| parse_jwt_detailed(t).unwrap_err();
        assert!(err("abc").contains("this has 1"));
        assert!(err(&format!("{h}.{p}")).contains("this has 2"));
        assert!(err(&format!("{h}.{p}.s.e.t")).contains("JWE"));
        assert!(err(&format!(".{p}.sig")).contains("header is empty"));
        assert!(err(&format!("{h}.{p}+.sig")).contains("payload isn't valid Base64URL"));
        assert!(err(&format!("{}.{p}.sig", base64url_encode(b"not json"))).contains("header isn't JSON"));
        assert!(err(&format!("{}.{p}.sig", base64url_encode(b"[1,2]"))).contains("JSON object"));
        assert!(err(&format!("{h}.{}.sig", base64url_encode(b"\"just a string\""))).contains("JSON object"));
        assert!(err(&format!("{h}.{p}.si+g")).contains("signature"));
        assert!(!is_jwt("not.a.jwt"));
    }

    #[test]
    fn dechunks_standard_bodies() {
        assert_eq!(decode_chunked_body(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap(), b"Wikipedia");
        // upper/lower-case hex, leading zeros, binary data containing CRLF
        assert_eq!(decode_chunked_body(b"0A\r\n0123456789\r\n004\r\na\r\nb\r\n0\r\n\r\n").unwrap(), b"0123456789a\r\nb");
        assert_eq!(decode_chunked_body(b"0\r\n\r\n").unwrap(), b"");
        // anything after the terminating chunk isn't part of the body
        assert_eq!(decode_chunked_body(b"1\r\nx\r\n0\r\n\r\nHTTP/1.1 200 OK").unwrap(), b"x");
    }

    #[test]
    fn chunk_extensions_and_trailers_are_dropped() {
        let body = "abcdefghijklmnopqrstuvwxyz";
        let raw = format!("1a;name=val\r\n{body}\r\n0;last\r\nX-Checksum: 9f\r\nX-Other: 1\r\n\r\n");
        assert_eq!(decode_chunked_body(raw.as_bytes()).unwrap(), body.as_bytes());
    }

    #[test]
    fn bad_chunked_bodies_are_errors() {
        assert!(matches!(decode_chunked_body(b"zz\r\nabc\r\n0\r\n\r\n"), Err(CodecError::BadChunkSize(_))));
        assert!(matches!(decode_chunked_body(b"\r\n"), Err(CodecError::BadChunkSize(_))));
        assert!(matches!(decode_chunked_body(b"-1\r\nx\r\n"), Err(CodecError::BadChunkSize(_))));
        assert!(matches!(decode_chunked_body(b"ffffffffffffffffff\r\n"), Err(CodecError::BadChunkSize(_))));
        // size larger than what's there
        assert_eq!(decode_chunked_body(b"ffffffffffffffff\r\nab"), Err(CodecError::Truncated));
        assert_eq!(decode_chunked_body(b"5\r\nab"), Err(CodecError::Truncated));
        assert_eq!(decode_chunked_body(b"2\r\nab"), Err(CodecError::Truncated));
        assert_eq!(decode_chunked_body(b"4\r\nWiki\r\n"), Err(CodecError::Truncated), "no terminating chunk");
        assert_eq!(decode_chunked_body(b"0\r\n"), Err(CodecError::Truncated), "no final blank line");
        assert_eq!(decode_chunked_body(b""), Err(CodecError::Truncated));
        assert_eq!(decode_chunked_body(b"2\r\nabXY"), Err(CodecError::MissingCrlf));
    }

    #[test]
    fn normalizes_chunked_responses() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: Chunked\r\nContent-Length: 999\r\nX-A: 1\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let res = normalize_response(HttpResponse::parse(raw));
        assert_eq!(res.body, b"Wikipedia");
        assert_eq!(res.header("transfer-encoding"), None);
        assert_eq!(res.header("content-length"), Some("9"));
        assert_eq!(res.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).count(), 1);
        assert_eq!(res.header("x-a"), Some("1"), "other headers kept");
        assert_eq!(res.head_text(), "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-A: 1\r\nContent-Length: 9\r\n\r\n");
        // not chunked, other codings, or a body that doesn't decode: unchanged
        for raw in [&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"[..], b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"] {
            let parsed = HttpResponse::parse(raw);
            assert_eq!(normalize_response(parsed.clone()), parsed);
        }
    }

    #[test]
    fn header_bytes_round_trip() {
        // UTF-8 stays UTF-8
        assert_eq!(decode_header_bytes("X-Name: café".as_bytes()), ("X-Name: café".to_string(), false));
        // anything else: every byte maps to one char and back
        let raw: Vec<u8> = (0u8..=255).collect();
        let (text, latin1) = decode_header_bytes(&raw);
        assert!(latin1);
        assert_eq!(text.chars().count(), 256);
        assert_eq!(encode_header_text(&text, true), raw);
        // a char past U+00FF added to Latin-1 text (an Intercept edit) is written as UTF-8
        assert_eq!(encode_header_text("a\u{e9}\u{263a}", true), [&b"a\xe9"[..], "\u{263a}".as_bytes()].concat());
        // responses keep non-UTF-8 header bytes exactly
        let res = HttpResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=r\xe9sum\xe9.pdf\r\n\r\nbody");
        assert!(res.latin1);
        assert_eq!(res.head_bytes(), b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=r\xe9sum\xe9.pdf\r\n\r\n");
    }
}
