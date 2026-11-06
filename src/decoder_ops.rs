//! Decoder functions. The function list is from the original's help page
//! (resources/Documentation/.../tools/decoder.html): URL, HTML, Base64, ASCII hex, Hex,
//! Octal, Binary, GZIP; plus Hash and Smart decode. Exact text formats of Hex, Octal and
//! Binary output are estimated.

use crate::codec;
use std::io::Write;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Codec {
    Url,
    Html,
    Base64,
    Base64Url,
    AsciiHex,
    Hex,
    Octal,
    Binary,
    Gzip,
}

impl Codec {
    pub const ALL: [Codec; 9] =
        [Codec::Url, Codec::Html, Codec::Base64, Codec::Base64Url, Codec::AsciiHex, Codec::Hex, Codec::Octal, Codec::Binary, Codec::Gzip];
    pub fn label(&self) -> &'static str {
        match self {
            Codec::Url => "URL",
            Codec::Html => "HTML",
            Codec::Base64 => "Base64",
            Codec::Base64Url => "Base64URL",
            Codec::AsciiHex => "ASCII hex",
            Codec::Hex => "Hex",
            Codec::Octal => "Octal",
            Codec::Binary => "Binary",
            Codec::Gzip => "GZIP",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Md5,
}

impl Hash {
    pub const ALL: [Hash; 6] = [Hash::Sha1, Hash::Sha224, Hash::Sha256, Hash::Sha384, Hash::Sha512, Hash::Md5];
    pub fn label(&self) -> &'static str {
        match self {
            Hash::Sha1 => "SHA",
            Hash::Sha224 => "SHA-224",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
            Hash::Md5 => "MD5",
        }
    }
}

pub fn encode(c: Codec, data: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(data);
    match c {
        Codec::Url => codec::url_encode(&s, true).into_bytes(),
        Codec::Html => codec::html_encode(&s, codec::HtmlMode::AllHex).into_bytes(),
        Codec::Base64 => codec::base64_encode(data, false, true).into_bytes(),
        Codec::Base64Url => codec::base64url_encode(data).into_bytes(),
        Codec::AsciiHex => codec::hex_encode(data).into_bytes(),
        Codec::Hex => data.iter().map(|b| format!("\\x{b:02x}")).collect::<String>().into_bytes(),
        Codec::Octal => data.iter().map(|b| format!("\\{b:03o}")).collect::<String>().into_bytes(),
        Codec::Binary => data.iter().map(|b| format!("{b:08b}")).collect::<Vec<_>>().join(" ").into_bytes(),
        Codec::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = e.write_all(data);
            e.finish().unwrap_or_default()
        }
    }
}

pub fn decode(c: Codec, data: &[u8]) -> Option<Vec<u8>> {
    let s = String::from_utf8_lossy(data).to_string();
    let t = s.trim();
    match c {
        Codec::Url => Some(codec::url_decode(t).into_bytes()),
        Codec::Html => Some(codec::html_decode(&s).into_bytes()),
        Codec::Base64 => {
            let out = codec::base64_decode(t);
            (!out.is_empty()).then_some(out)
        }
        Codec::Base64Url => codec::base64url_decode(t).filter(|out| !out.is_empty()),
        Codec::AsciiHex => {
            let digits: Vec<u8> = t.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
            if digits.len() % 2 != 0 || !digits.iter().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some(codec::hex_decode(std::str::from_utf8(&digits).ok()?))
        }
        Codec::Hex => {
            let cleaned = t.replace("\\x", "").replace("0x", "");
            let out = codec::hex_decode(&cleaned);
            (!out.is_empty()).then_some(out)
        }
        Codec::Octal => {
            let mut out = Vec::new();
            for part in t.split('\\').filter(|p| !p.is_empty()) {
                out.push(u8::from_str_radix(part.trim(), 8).ok()?);
            }
            Some(out)
        }
        Codec::Binary => {
            let digits: String = t.chars().filter(|c| *c == '0' || *c == '1').collect();
            if digits.is_empty() || digits.len() % 8 != 0 {
                return None;
            }
            digits.as_bytes().chunks(8).map(|ch| u8::from_str_radix(std::str::from_utf8(ch).ok()?, 2).ok()).collect()
        }
        // capped like every decompression in the app (None past 32 MiB of output)
        Codec::Gzip => crate::http::read_capped(flate2::read::GzDecoder::new(data), crate::http::MAX_DECODED),
    }
}

pub fn hash(h: Hash, data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let digest: Vec<u8> = match h {
        Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
        Hash::Sha224 => sha2::Sha224::digest(data).to_vec(),
        Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
        Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
        Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        Hash::Md5 => md5::Md5::digest(data).to_vec(),
    };
    // shown as hex text
    digest.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes()
}

/// Guess the outermost encoding of the data (heuristic, like the original's smart decode).
pub fn detect(data: &[u8]) -> Option<Codec> {
    if data.starts_with(&[0x1f, 0x8b]) {
        return Some(Codec::Gzip);
    }
    let s = std::str::from_utf8(data).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains('%') && s.as_bytes().windows(3).any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit()) {
        return Some(Codec::Url);
    }
    if s.contains("&#") || s.contains("&lt;") || s.contains("&gt;") || s.contains("&amp;") || s.contains("&quot;") {
        return Some(Codec::Html);
    }
    if s.contains("\\x") {
        return Some(Codec::Hex);
    }
    if s.len() >= 8 && s.len() % 8 == 0 && s.chars().all(|c| c == '0' || c == '1' || c == ' ') {
        return Some(Codec::Binary);
    }
    if s.len() >= 4 && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c.is_ascii_digit()) {
        return Some(Codec::AsciiHex);
    }
    let b64 = s.len() >= 4
        && s.len() % 4 == 0
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'));
    if b64 {
        let out = codec::base64_decode(s);
        let printable = !out.is_empty() && out.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace() || *b >= 0x80 || *b == 0x1f || *b == 0x8b);
        if printable || out.starts_with(&[0x1f, 0x8b]) {
            return Some(Codec::Base64);
        }
    }
    None
}

/// Apply layers of decoding until nothing recognisable is left (at most 10 layers).
pub fn smart_decode(data: &[u8]) -> Vec<(Codec, Vec<u8>)> {
    let mut layers = Vec::new();
    let mut cur = data.to_vec();
    for _ in 0..10 {
        let Some(c) = detect(&cur) else { break };
        match decode(c, &cur) {
            Some(next) if next != cur => {
                layers.push((c, next.clone()));
                cur = next;
            }
            _ => break,
        }
    }
    layers
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips() {
        for c in Codec::ALL {
            let e = encode(c, b"Hi there <&>");
            assert_eq!(decode(c, &e).unwrap(), b"Hi there <&>", "{c:?}");
        }
    }
    #[test]
    fn hashes() {
        assert_eq!(String::from_utf8(hash(Hash::Md5, b"abc")).unwrap(), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(String::from_utf8(hash(Hash::Sha1, b"abc")).unwrap(), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
    #[test]
    fn smart_decodes_layers() {
        // base64 of the URL-encoded text "a b"
        let layers = smart_decode(b"YSUyMGI=");
        assert_eq!(layers.last().unwrap().1, b"a b");
        assert_eq!(layers.len(), 2);
    }
}
