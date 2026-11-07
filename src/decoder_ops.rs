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
    use crate::test_utils::assert_table;

    #[test]
    fn hash_algorithms_matrix() {
        let cases: [(&str, &[u8], Hash, &str); 12] = [
            // "abc" standard test vectors
            ("MD5('abc')", b"abc", Hash::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            ("SHA-1('abc')", b"abc", Hash::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                "SHA-224('abc')",
                b"abc",
                Hash::Sha224,
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            ),
            (
                "SHA-256('abc')",
                b"abc",
                Hash::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "SHA-384('abc')",
                b"abc",
                Hash::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                "SHA-512('abc')",
                b"abc",
                Hash::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            // Empty input standard test vectors
            ("MD5('')", b"", Hash::Md5, "d41d8cd98f00b204e9800998ecf8427e"),
            ("SHA-1('')", b"", Hash::Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (
                "SHA-224('')",
                b"",
                Hash::Sha224,
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            ),
            (
                "SHA-256('')",
                b"",
                Hash::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "SHA-384('')",
                b"",
                Hash::Sha384,
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                "SHA-512('')",
                b"",
                Hash::Sha512,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
        ];

        assert_table!(cases, |idx, (name, input, algo, expected_hex_digest)| {
            let got = String::from_utf8(hash(algo, input)).unwrap();
            assert_eq!(got, expected_hex_digest, "case #{idx} ({name})");
            assert!(!algo.label().is_empty(), "case #{idx} ({name}) label");
        });
    }

    #[test]
    fn decoder_ops_round_trips_and_text_byte_operations_matrix() {
        let payloads: [(&str, &[u8]); 3] = [
            ("ASCII with HTML/URL specials", b"Hi there <&>"),
            ("credentials with punctuation", b"admin:p@ssw0rd!#?"),
            ("UTF-8 multibyte text", "üñí ✓".as_bytes()),
        ];

        assert_table!(payloads, |idx, (name, payload)| {
            for c in Codec::ALL {
                let encoded = encode(c, payload);
                let decoded = decode(c, &encoded).unwrap_or_else(|| panic!("case #{idx} ({name}) decode {c:?}"));
                assert_eq!(decoded, payload, "case #{idx} ({name}) round-trip {c:?}");
                assert!(!c.label().is_empty());
            }
        });

        // Text & byte operation matrix: case switching, whitespace manipulation, prefix/offset handling, and malformed rejection
        let op_cases: [(&str, Codec, &[u8], Option<&[u8]>); 15] = [
            ("AsciiHex uppercase hex", Codec::AsciiHex, b"48454C4C4F", Some(b"HELLO")),
            ("AsciiHex mixed-case with spaces and newlines", Codec::AsciiHex, b"  48 65\n6c 6C 6f\t", Some(b"Hello")),
            ("AsciiHex odd nibble count rejected", Codec::AsciiHex, b"486", None),
            ("AsciiHex non-hex character rejected", Codec::AsciiHex, b"48zz", None),
            ("Hex with \\x prefix and mixed case", Codec::Hex, b"\\x48\\x69\\x2A", Some(b"Hi*")),
            ("Hex with 0x prefix and spaces", Codec::Hex, b"0x48 0x69", Some(b"Hi")),
            ("Octal escape sequence with whitespace", Codec::Octal, b" \\110\\151\\041 ", Some(b"Hi!")),
            ("Octal out-of-u8-range rejected", Codec::Octal, b"\\777", None),
            ("Binary space-separated 8-bit groups", Codec::Binary, b"01001000 01101001", Some(b"Hi")),
            ("Binary contiguous bit stream", Codec::Binary, b"0100100001101001", Some(b"Hi")),
            ("Binary non-byte-aligned length rejected", Codec::Binary, b"0100100", None),
            ("Binary empty input rejected", Codec::Binary, b"   ", None),
            ("Base64 with surrounding whitespace", Codec::Base64, b"  SGk= \n", Some(b"Hi")),
            ("Base64Url unpadded", Codec::Base64Url, b"SGk", Some(b"Hi")),
            ("Base64Url rejects standard '+' char", Codec::Base64Url, b"SGk+", None),
        ];

        assert_table!(op_cases, |idx, (name, codec, input, expected)| {
            assert_eq!(decode(codec, input).as_deref(), expected, "case #{idx} ({name})");
        });
    }

    #[test]
    fn smart_decode_multilayer_matrix() {
        // Build nested multi-layer fixtures
        // 1. URL -> AsciiHex -> Base64 ("secret: 1")
        let b64_secret = encode(Codec::Base64, b"secret: 1");
        let hex_b64_secret = encode(Codec::AsciiHex, &b64_secret);
        let url_hex_b64_secret = encode(Codec::Url, &hex_b64_secret);

        // 2. Gzip -> Base64 -> Url ("a b")
        let url_ab = encode(Codec::Url, b"a b");
        let b64_url_ab = encode(Codec::Base64, &url_ab);
        let gzip_b64_url_ab = encode(Codec::Gzip, &b64_url_ab);

        let cases: Vec<(&str, Vec<u8>, Vec<Codec>, &[u8])> = vec![
            (
                "2-layer Base64 -> URL ('a b')",
                b"YSUyMGI=".to_vec(),
                vec![Codec::Base64, Codec::Url],
                b"a b",
            ),
            (
                "3-layer URL -> AsciiHex -> Base64 ('secret: 1')",
                url_hex_b64_secret,
                vec![Codec::Url, Codec::AsciiHex, Codec::Base64],
                b"secret: 1",
            ),
            (
                "3-layer Gzip -> Base64 -> URL ('a b')",
                gzip_b64_url_ab,
                vec![Codec::Gzip, Codec::Base64, Codec::Url],
                b"a b",
            ),
            (
                "single-layer HTML entities",
                b"&lt;script&gt;".to_vec(),
                vec![Codec::Html],
                b"<script>",
            ),
            (
                "single-layer \\x Hex escapes",
                b"\\x6f\\x6b".to_vec(),
                vec![Codec::Hex],
                b"ok",
            ),
            (
                "single-layer Binary bits",
                b"0100111101001011".to_vec(),
                vec![Codec::Binary],
                b"OK",
            ),
            (
                "un-encoded plain text produces 0 layers",
                b"hello plain world".to_vec(),
                vec![],
                b"hello plain world",
            ),
            (
                "empty input produces 0 layers",
                b"".to_vec(),
                vec![],
                b"",
            ),
        ];

        assert_table!(cases, |idx, (name, encoded_input, expected_detected_layers, expected_final_plaintext)| {
            let layers = smart_decode(&encoded_input);
            let detected_codecs: Vec<Codec> = layers.iter().map(|(c, _)| *c).collect();
            let final_bytes = layers.last().map(|(_, b)| b.as_slice()).unwrap_or(encoded_input.as_slice());
            assert_eq!(
                detected_codecs, expected_detected_layers,
                "case #{idx} ({name}) detected layers mismatch"
            );
            assert_eq!(
                final_bytes, expected_final_plaintext,
                "case #{idx} ({name}) final plaintext mismatch"
            );
        });
    }
}
