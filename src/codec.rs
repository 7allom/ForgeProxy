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

#[derive(Clone, Copy, Debug, PartialEq)]
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
    use crate::test_utils::assert_table;

    #[derive(Clone, Copy, Debug)]
    enum TestCodec {
        Base64StdPadded,
        Base64StdUnpadded,
        Base64UrlPadded,
        Base64UrlUnpadded,
        Hex,
        AsciiHex,
        UrlStandard,
        UrlFull,
        Html(HtmlMode),
    }

    struct CodecCase<'a> {
        name: &'a str,
        input: &'a [u8],
        codec: TestCodec,
        expected_encoded: &'a str,
        expected_decoded: &'a [u8],
    }

    #[test]
    fn codec_encoding_decoding_matrix() {
        let cases = [
            CodecCase {
                name: "Base64 standard padded ('hello?')",
                input: b"hello?",
                codec: TestCodec::Base64StdPadded,
                expected_encoded: "aGVsbG8/",
                expected_decoded: b"hello?",
            },
            CodecCase {
                name: "Base64 standard padded with '=' ('Hi')",
                input: b"Hi",
                codec: TestCodec::Base64StdPadded,
                expected_encoded: "SGk=",
                expected_decoded: b"Hi",
            },
            CodecCase {
                name: "Base64 standard unpadded ('Hi')",
                input: b"Hi",
                codec: TestCodec::Base64StdUnpadded,
                expected_encoded: "SGk",
                expected_decoded: b"Hi",
            },
            CodecCase {
                name: "Base64 URL-safe unpadded ('hello?')",
                input: b"hello?",
                codec: TestCodec::Base64UrlUnpadded,
                expected_encoded: "aGVsbG8_",
                expected_decoded: b"hello?",
            },
            CodecCase {
                name: "Base64 URL-safe unpadded high bytes ([0xfb, 0xff])",
                input: &[0xfb, 0xff],
                codec: TestCodec::Base64UrlUnpadded,
                expected_encoded: "-_8",
                expected_decoded: &[0xfb, 0xff],
            },
            CodecCase {
                name: "Base64 URL-safe padded ([0xfb, 0xff])",
                input: &[0xfb, 0xff],
                codec: TestCodec::Base64UrlPadded,
                expected_encoded: "-_8=",
                expected_decoded: &[0xfb, 0xff],
            },
            CodecCase {
                name: "Hex lower-case ('Hi')",
                input: b"Hi",
                codec: TestCodec::Hex,
                expected_encoded: "4869",
                expected_decoded: b"Hi",
            },
            CodecCase {
                name: "ASCII hex via decoder_ops ('Hi!')",
                input: b"Hi!",
                codec: TestCodec::AsciiHex,
                expected_encoded: "486921",
                expected_decoded: b"Hi!",
            },
            CodecCase {
                name: "URL standard leaves unreserved chars intact",
                input: b"a-b_c.d~1?x=2&y=3",
                codec: TestCodec::UrlStandard,
                expected_encoded: "a-b_c.d~1%3fx%3d2%26y%3d3",
                expected_decoded: b"a-b_c.d~1?x=2&y=3",
            },
            CodecCase {
                name: "URL full percent-encodes every byte",
                input: b"Hi!",
                codec: TestCodec::UrlFull,
                expected_encoded: "%48%69%21",
                expected_decoded: b"Hi!",
            },
            CodecCase {
                name: "HTML Standard mode encodes only special chars",
                input: b"<a href=\"x\" title='y'>&</a>",
                codec: TestCodec::Html(HtmlMode::Standard),
                expected_encoded: "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;",
                expected_decoded: b"<a href=\"x\" title='y'>&</a>",
            },
            CodecCase {
                name: "HTML AllCharacters mode encodes specials by name and others as decimal",
                input: b"<A>",
                codec: TestCodec::Html(HtmlMode::AllCharacters),
                expected_encoded: "&lt;&#65;&gt;",
                expected_decoded: b"<A>",
            },
            CodecCase {
                name: "HTML AllDecimal mode encodes every character as decimal entity",
                input: b"A&",
                codec: TestCodec::Html(HtmlMode::AllDecimal),
                expected_encoded: "&#65;&#38;",
                expected_decoded: b"A&",
            },
            CodecCase {
                name: "HTML AllHex mode encodes every character as hex entity",
                input: b"A&",
                codec: TestCodec::Html(HtmlMode::AllHex),
                expected_encoded: "&#x41;&#x26;",
                expected_decoded: b"A&",
            },
        ];

        assert_table!(cases, |idx, case| {
            let (encoded, decoded) = match case.codec {
                TestCodec::Base64StdPadded => {
                    let enc = base64_encode(case.input, false, true);
                    let dec = base64_decode(&enc);
                    (enc, dec)
                }
                TestCodec::Base64StdUnpadded => {
                    let enc = base64_encode(case.input, false, false);
                    let dec = base64_decode(&enc);
                    (enc, dec)
                }
                TestCodec::Base64UrlPadded => {
                    let enc = base64_encode(case.input, true, true);
                    let dec = base64url_decode(&enc).expect("valid padded base64url");
                    (enc, dec)
                }
                TestCodec::Base64UrlUnpadded => {
                    let enc = base64url_encode(case.input);
                    let dec = base64url_decode(&enc).expect("valid unpadded base64url");
                    (enc, dec)
                }
                TestCodec::Hex => {
                    let enc = hex_encode(case.input);
                    let dec = hex_decode(&enc);
                    (enc, dec)
                }
                TestCodec::AsciiHex => {
                    let enc_bytes = crate::decoder_ops::encode(crate::decoder_ops::Codec::AsciiHex, case.input);
                    let enc = String::from_utf8(enc_bytes.clone()).unwrap();
                    let dec = crate::decoder_ops::decode(crate::decoder_ops::Codec::AsciiHex, &enc_bytes).unwrap();
                    (enc, dec)
                }
                TestCodec::UrlStandard => {
                    let text = std::str::from_utf8(case.input).unwrap();
                    let enc = url_encode(text, false);
                    let dec = url_decode(&enc).into_bytes();
                    (enc, dec)
                }
                TestCodec::UrlFull => {
                    let text = std::str::from_utf8(case.input).unwrap();
                    let enc = url_encode(text, true);
                    let dec = url_decode(&enc).into_bytes();
                    (enc, dec)
                }
                TestCodec::Html(mode) => {
                    let text = std::str::from_utf8(case.input).unwrap();
                    let enc = html_encode(text, mode);
                    let dec = html_decode(&enc).into_bytes();
                    (enc, dec)
                }
            };
            assert_eq!(encoded, case.expected_encoded, "case #{idx} ({}) encoded mismatch", case.name);
            assert_eq!(decoded, case.expected_decoded, "case #{idx} ({}) decoded mismatch", case.name);
        });

        // Additional decode-only entity variants (&apos;, uppercase &#X41;, plus-to-space in URL)
        assert_eq!(html_decode("&apos;&#X41;&#66;&unknown;"), "'AB&unknown;");
        assert_eq!(url_decode("hello+world%21"), "hello world!");
    }

    #[test]
    fn codec_round_trip_invariant_matrix() {
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let payloads: [(&str, &[u8], bool); 7] = [
            ("empty slice", b"", true),
            ("single ASCII byte", b"a", true),
            ("two ASCII bytes", b"ab", true),
            ("three ASCII bytes", b"abc", true),
            ("ASCII query & special chars", b"hello world?&=/'\"<>\\", true),
            ("multibyte UTF-8 text", "üñí <tag> \"q\" ✓ 🚀".as_bytes(), true),
            ("arbitrary binary 0x00..=0xFF", &all_bytes, false),
        ];

        assert_table!(payloads, |idx, (name, bytes, is_utf8)| {
            // Byte-safe codecs must round-trip all binary and text payloads
            assert_eq!(base64_decode(&base64_encode(bytes, false, true)), bytes, "case #{idx} ({name}) base64 std padded");
            assert_eq!(base64_decode(&base64_encode(bytes, false, false)), bytes, "case #{idx} ({name}) base64 std unpadded");
            assert_eq!(base64_decode(&base64_encode(bytes, true, true)), bytes, "case #{idx} ({name}) base64 url padded");
            assert_eq!(base64url_decode(&base64url_encode(bytes)).unwrap(), bytes, "case #{idx} ({name}) base64url");
            assert_eq!(hex_decode(&hex_encode(bytes)), bytes, "case #{idx} ({name}) hex");

            // Text-based codecs round-trip all valid UTF-8 strings
            if is_utf8 {
                let text = std::str::from_utf8(bytes).unwrap();
                assert_eq!(url_decode(&url_encode(text, false)), text, "case #{idx} ({name}) url standard");
                assert_eq!(url_decode(&url_encode(text, true)), text, "case #{idx} ({name}) url full");
                for mode in [HtmlMode::Standard, HtmlMode::AllCharacters, HtmlMode::AllDecimal, HtmlMode::AllHex] {
                    assert_eq!(html_decode(&html_encode(text, mode)), text, "case #{idx} ({name}) html {mode:?}");
                }
            }
        });

        // Header bytes round-trip matrix (UTF-8 vs Latin-1 and mixed Intercept edits)
        let header_cases: [(&str, &[u8], bool); 3] = [
            ("valid UTF-8 header", "X-Name: café".as_bytes(), false),
            ("full 0..=255 Latin-1 header bytes", &all_bytes, true),
            (
                "non-UTF-8 HTTP response header",
                b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=r\xe9sum\xe9.pdf\r\n\r\n",
                true,
            ),
        ];
        assert_table!(header_cases, |idx, (name, raw, expected_latin1)| {
            let (text, latin1) = decode_header_bytes(raw);
            assert_eq!(latin1, expected_latin1, "case #{idx} ({name}) latin1 flag");
            assert_eq!(encode_header_text(&text, latin1), raw, "case #{idx} ({name}) header round-trip");
        });

        // A char past U+00FF added to Latin-1 text (an Intercept edit) is written as UTF-8
        assert_eq!(
            encode_header_text("a\u{e9}\u{263a}", true),
            [&b"a\xe9"[..], "\u{263a}".as_bytes()].concat()
        );
        let res = HttpResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=r\xe9sum\xe9.pdf\r\n\r\nbody");
        assert!(res.latin1);
        assert_eq!(
            res.head_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=r\xe9sum\xe9.pdf\r\n\r\n"
        );
    }

    #[test]
    fn codec_error_and_malformed_input_matrix() {
        // 1. Strict Base64URL rejection & acceptance matrix
        let b64url_cases: [(&str, &str, Option<&[u8]>); 9] = [
            ("valid unpadded", "SGk", Some(b"Hi")),
            ("valid single '=' pad", "SGk=", Some(b"Hi")),
            ("valid URL-safe chars '-_'", "-_8", Some(&[0xfb, 0xff])),
            ("rejects '+' from standard alphabet", "SGk+", None),
            ("rejects '/' from standard alphabet", "SGk/", None),
            ("rejects impossible mod-4 length 1", "S", None),
            ("rejects internal whitespace", "SG k", None),
            ("rejects excessive padding '==='", "SGk===", None),
            ("rejects non-ASCII characters", "SGk\u{e9}", None),
        ];
        assert_table!(b64url_cases, |idx, (name, input, expected)| {
            assert_eq!(base64url_decode(input).as_deref(), expected, "case #{idx} ({name})");
        });

        // 2. Malformed hex & lenient base64 fallback matrix
        let lenient_cases: [(&str, &str, &[u8], Option<&[u8]>); 5] = [
            ("odd-length hex drops trailing nibble in hex_decode, None in AsciiHex", "4869a", b"Hi", None),
            ("non-hex chars skipped in hex_decode, None in AsciiHex", "48-69-zz", b"Hi", None),
            ("spaced hex decodes in both hex_decode and AsciiHex", "48 69", b"Hi", Some(b"Hi")),
            ("empty hex string", "", b"", Some(b"")),
            ("single nibble hex", "f", b"", None),
        ];
        assert_table!(lenient_cases, |idx, (name, input, expected_lenient, expected_strict)| {
            assert_eq!(hex_decode(input), expected_lenient, "case #{idx} ({name}) hex_decode");
            assert_eq!(
                crate::decoder_ops::decode(crate::decoder_ops::Codec::AsciiHex, input.as_bytes()).as_deref(),
                expected_strict,
                "case #{idx} ({name}) AsciiHex"
            );
        });

        // 3. Malformed JWT token matrix
        let h = base64url_encode(br#"{"alg":"HS256"}"#);
        let p = base64url_encode(br#"{"sub":"x"}"#);
        let bad_jwt_cases: Vec<(&str, String, &str)> = vec![
            ("1 segment", "abc".into(), "this has 1"),
            ("2 segments", format!("{h}.{p}"), "this has 2"),
            ("5 segments (JWE)", format!("{h}.{p}.s.e.t"), "JWE"),
            ("empty header", format!(".{p}.sig"), "header is empty"),
            ("invalid Base64URL payload", format!("{h}.{p}+.sig"), "payload isn't valid Base64URL"),
            ("non-JSON header", format!("{}.{p}.sig", base64url_encode(b"not json")), "header isn't JSON"),
            ("JSON array header", format!("{}.{p}.sig", base64url_encode(b"[1,2]")), "JSON object"),
            ("JSON string payload", format!("{h}.{}.sig", base64url_encode(b"\"just a string\"")), "JSON object"),
            ("invalid Base64URL signature", format!("{h}.{p}.si+g"), "signature"),
        ];
        assert_table!(bad_jwt_cases, |idx, (name, token, expected_substr)| {
            let err = parse_jwt_detailed(&token).expect_err(&format!("case #{idx} ({name}) should fail"));
            assert!(
                err.contains(expected_substr),
                "case #{idx} ({name}): expected {expected_substr:?} in {err:?}"
            );
            assert!(!is_jwt(&token), "case #{idx} ({name}) is_jwt should be false");
        });
        assert!(!is_jwt("not.a.jwt"));

        // 4. Malformed HTTP chunked body matrix
        let bad_chunk_cases: [(&str, &[u8], CodecError); 11] = [
            ("non-hex chunk size", b"zz\r\nabc\r\n0\r\n\r\n", CodecError::BadChunkSize("zz".into())),
            ("empty chunk size line", b"\r\n", CodecError::BadChunkSize("".into())),
            ("negative chunk size", b"-1\r\nx\r\n", CodecError::BadChunkSize("-1".into())),
            (
                "overflow (>16 hex digits) chunk size",
                b"ffffffffffffffffff\r\n",
                CodecError::BadChunkSize("ffffffffffffffffff".into()),
            ),
            ("u64::MAX size with short payload", b"ffffffffffffffff\r\nab", CodecError::Truncated),
            ("declared 5 bytes, only 2 present", b"5\r\nab", CodecError::Truncated),
            ("declared 2 bytes, missing trailing CRLF", b"2\r\nab", CodecError::Truncated),
            ("missing terminating 0 chunk", b"4\r\nWiki\r\n", CodecError::Truncated),
            ("missing final blank line after 0 chunk", b"0\r\n", CodecError::Truncated),
            ("empty input", b"", CodecError::Truncated),
            ("chunk data not followed by CRLF", b"2\r\nabXY", CodecError::MissingCrlf),
        ];
        assert_table!(bad_chunk_cases, |idx, (name, raw, expected_err)| {
            assert_eq!(decode_chunked_body(raw), Err(expected_err), "case #{idx} ({name})");
        });
    }

    // header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234567890","name":"John Doe","iat":1516239022}
    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn jwt_and_timestamp_matrix() {
        let j = parse_jwt(JWT).unwrap();
        assert_eq!(j.alg.as_deref(), Some("HS256"));
        assert_eq!(j.typ.as_deref(), Some("JWT"));
        assert_eq!(j.iat, Some(1_516_239_022));
        assert_eq!(j.exp, None);
        assert_eq!(j.claims, vec![("sub", "1234567890".to_string())]);
        assert_eq!(j.signature_len, 32);
        assert_eq!(j.header_json, "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}");
        assert!(j.payload_json.contains("\n  \"name\": \"John Doe\""));
        let keys: Vec<&str> = j.payload_json.lines().filter_map(|l| l.trim().strip_prefix('"')?.split('"').next()).collect();
        assert_eq!(keys, ["sub", "name", "iat"]);
        assert_eq!(format!("{}.{}.{}", j.header_raw, j.payload_raw, j.signature_raw), JWT);
        assert_eq!(parse_jwt(&format!("  Bearer {JWT}\n")).unwrap(), j);
        assert!(is_jwt(JWT));

        // Unpadded and padded segments of every mod-3 byte length
        let segment_payloads = [r#"{"a":1}"#, r#"{"ab":1}"#, r#"{"abc":1}"#];
        assert_table!(segment_payloads, |idx, payload| {
            let tok = format!("{}.{}.", base64url_encode(br#"{"alg":"none"}"#), base64url_encode(payload.as_bytes()));
            let parsed = parse_jwt(&tok).unwrap_or_else(|| panic!("case #{idx}: {tok}"));
            assert_eq!(parsed.alg.as_deref(), Some("none"));
            assert_eq!(parsed.signature_len, 0, "case #{idx}: unsigned token");
            let padded = format!("{}=.{}.", base64url_encode(br#"{"alg":"none"}"#), base64url_encode(payload.as_bytes()));
            if base64url_encode(br#"{"alg":"none"}"#).len() % 4 != 0 {
                assert!(parse_jwt(&padded).is_some(), "case #{idx}: padded segment accepted");
            }
        });

        // Claims and timestamps
        let payload = r#"{"iss":"https://idp.test","aud":["api","web"],"exp":1700003600,"iat":1700000000,"nbf":1699999990.5,"jti":7}"#;
        let tok = format!("{}.{}.c2ln", base64url_encode(br#"{"alg":"RS256","kid":"k1"}"#), base64url_encode(payload.as_bytes()));
        let j = parse_jwt(&tok).unwrap();
        assert_eq!((j.exp, j.iat, j.nbf), (Some(1_700_003_600), Some(1_700_000_000), Some(1_699_999_990)));
        assert_eq!(j.kid.as_deref(), Some("k1"));
        assert_eq!(
            j.claims,
            vec![("iss", "https://idp.test".to_string()), ("aud", "api, web".to_string()), ("jti", "7".to_string())]
        );

        let utc_cases = [
            (1_700_000_000i64, "2023-11-14 22:13:20 UTC"),
            (0, "1970-01-01 00:00:00 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
        ];
        assert_table!(utc_cases, |idx, (ts, expected)| {
            assert_eq!(format_unix_utc(ts), expected, "utc case #{idx}");
        });

        let duration_cases = [
            (1i64, "1 second"),
            (45, "45 seconds"),
            (120, "2 minutes"),
            (3600, "1 hour"),
            (86_400 * 3, "3 days"),
        ];
        assert_table!(duration_cases, |idx, (secs, expected)| {
            assert_eq!(duration_words(secs), expected, "duration case #{idx}");
        });

        assert_eq!(expiry_status(1_700_003_600, 1_700_004_320), "Expired 12 minutes ago");
        assert_eq!(expiry_status(1_700_003_600, 1_699_996_400), "Valid for 2 hours");
    }

    #[test]
    fn chunked_transfer_encoding_matrix() {
        let valid_chunks: [(&str, &[u8], &[u8]); 5] = [
            ("standard two-chunk body", b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", b"Wikipedia"),
            (
                "upper/lower hex, leading zeros, embedded CRLF",
                b"0A\r\n0123456789\r\n004\r\na\r\nb\r\n0\r\n\r\n",
                b"0123456789a\r\nb",
            ),
            ("empty zero-chunk body", b"0\r\n\r\n", b""),
            ("trailing bytes after terminating chunk are ignored", b"1\r\nx\r\n0\r\n\r\nHTTP/1.1 200 OK", b"x"),
            (
                "chunk extensions and trailers are dropped",
                b"1a;name=val\r\nabcdefghijklmnopqrstuvwxyz\r\n0;last\r\nX-Checksum: 9f\r\nX-Other: 1\r\n\r\n",
                b"abcdefghijklmnopqrstuvwxyz",
            ),
        ];
        assert_table!(valid_chunks, |idx, (name, raw, expected)| {
            assert_eq!(decode_chunked_body(raw).unwrap(), expected, "case #{idx} ({name})");
        });

        // Response normalization matrix
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: Chunked\r\nContent-Length: 999\r\nX-A: 1\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let res = normalize_response(HttpResponse::parse(raw));
        assert_eq!(res.body, b"Wikipedia");
        assert_eq!(res.header("transfer-encoding"), None);
        assert_eq!(res.header("content-length"), Some("9"));
        assert_eq!(res.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).count(), 1);
        assert_eq!(res.header("x-a"), Some("1"));
        assert_eq!(res.head_text(), "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-A: 1\r\nContent-Length: 9\r\n\r\n");

        let unchanged_responses: [(&str, &[u8]); 4] = [
            ("non-chunked Content-Length response", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
            (
                "multiple transfer-encodings (gzip, chunked)",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
            ),
            ("truncated chunked body", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"),
            ("empty chunked body", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ];
        assert_table!(unchanged_responses, |idx, (name, raw_resp)| {
            let parsed = HttpResponse::parse(raw_resp);
            assert_eq!(normalize_response(parsed.clone()), parsed, "case #{idx} ({name})");
        });
    }
}
