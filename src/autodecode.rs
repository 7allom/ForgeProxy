//! Auto-Decoder: what a value (an Inspector row, or text selected in a message) might be
//! encoded as, each guess shown as a card. Detection is strict enough that ordinary words
//! and numbers don't produce noise: Base64 has to decode to readable text, a timestamp
//! has to be 10 or 13 digits, a JWT has to parse.

/// One decoded view of the input.
#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    pub title: &'static str,
    pub text: String,
}

/// Longest input decoded (a selection can be a whole message).
pub const MAX_INPUT: usize = 64 * 1024;
/// Bytes shown in the hex card.
const HEX_SHOWN: usize = 256;

/// Every card that applies to `input`, most specific first. Empty for empty input.
pub fn decode_cards(input: &str) -> Vec<Card> {
    let s = crate::editor::capped(input, MAX_INPUT);
    let t = s.trim();
    if t.is_empty() {
        return Vec::new();
    }
    let mut cards = Vec::new();
    if let Some(c) = jwt(t) {
        cards.push(c);
    }
    if let Some(c) = timestamp(t) {
        cards.push(c);
    }
    if let Some(c) = url_decoded(t) {
        cards.push(c);
    }
    if let Some(c) = base64(t) {
        cards.push(c);
    }
    if let Some(c) = hex_decoded(t) {
        cards.push(c);
    }
    cards.push(hex_of(s));
    cards
}

/// A JWT (also "Bearer <jwt>"): header and claims as indented JSON, times in UTC.
pub fn jwt(s: &str) -> Option<Card> {
    let j = crate::codec::parse_jwt(s)?;
    let mut text = format!("Header:\n{}\n\nClaims:\n{}", j.header_json, j.payload_json);
    for (name, ts) in [("exp", j.exp), ("iat", j.iat), ("nbf", j.nbf)] {
        if let Some(ts) = ts {
            text.push_str(&format!("\n{name}: {}", crate::codec::format_unix_utc(ts)));
        }
    }
    Some(Card { title: "JWT", text })
}

/// 10 digits: seconds since 1970; 13 digits: milliseconds. Shown as a UTC date.
pub fn timestamp(s: &str) -> Option<Card> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = s.parse().ok()?;
    let text = match s.len() {
        10 => crate::codec::format_unix_utc(n),
        13 => {
            let date = crate::codec::format_unix_utc(n.div_euclid(1000));
            // "2026-11-03 14:05:09 UTC" -> "2026-11-03 14:05:09.123 UTC"
            format!("{}.{:03} UTC", date.trim_end_matches(" UTC"), n.rem_euclid(1000))
        }
        _ => return None,
    };
    Some(Card { title: if s.len() == 10 { "Unix timestamp (seconds)" } else { "Unix timestamp (milliseconds)" }, text })
}

/// URL-decoded, when there's a %XX escape (a '+' alone isn't enough: it's often literal).
pub fn url_decoded(s: &str) -> Option<Card> {
    let b = s.as_bytes();
    let escaped = b.windows(3).any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit());
    if !escaped {
        return None;
    }
    let d = crate::codec::url_decode(s);
    (d != s).then(|| Card { title: "URL decoded", text: d })
}

/// Base64 or Base64URL that decodes to readable text. Hex strings and short tokens
/// (under 8 characters) are skipped: almost anything that short "decodes".
pub fn base64(s: &str) -> Option<Card> {
    if s.len() < 8 || s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let body = s.trim_end_matches('=');
    let pad = s.len() - body.len();
    let url = body.bytes().any(|b| b == b'-' || b == b'_');
    let std = body.bytes().any(|b| b == b'+' || b == b'/');
    let alphabet_ok = body.bytes().all(|b| b.is_ascii_alphanumeric() || if url { b == b'-' || b == b'_' } else { b == b'+' || b == b'/' });
    // padding only makes sense on a length that's a multiple of 4
    if !alphabet_ok || (url && std) || pad > 2 || body.len() % 4 == 1 || (pad > 0 && s.len() % 4 != 0) {
        return None;
    }
    let bytes = crate::codec::base64_decode(body);
    let text = readable(&bytes)?;
    Some(Card { title: if url { "Base64URL decoded" } else { "Base64 decoded" }, text })
}

/// A hex string (even length, at least 2 bytes) that decodes to readable text.
pub fn hex_decoded(s: &str) -> Option<Card> {
    let h: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let h = h.strip_prefix("0x").unwrap_or(&h);
    if h.len() < 4 || h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let text = readable(&crate::codec::hex_decode(h))?;
    Some(Card { title: "Hex decoded", text })
}

/// The input's bytes as hex (the first 256, with the total when there are more).
pub fn hex_of(s: &str) -> Card {
    let b = s.as_bytes();
    let shown: Vec<String> = b.iter().take(HEX_SHOWN).map(|x| format!("{x:02x}")).collect();
    let mut text = shown.join(" ");
    if b.len() > HEX_SHOWN {
        text.push_str(&format!(" … ({} bytes)", b.len()));
    }
    Card { title: "Hex", text }
}

/// UTF-8 text that is mostly printable (at least 90% of characters, tabs and newlines
/// counting as printable), else None.
fn readable(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let total = s.chars().count();
    if total == 0 {
        return None;
    }
    let printable = s.chars().filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')).count();
    (printable * 10 >= total * 9).then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn titles(s: &str) -> Vec<&'static str> {
        decode_cards(s).into_iter().map(|c| c.title).collect()
    }

    /// Iteratively peel the highest-priority detected card from `decode_cards` until only the
    /// raw `"Hex"` dump card remains (or a terminal card such as JWT / Unix timestamp is reached).
    fn peel_autodecode_layers(input: &str) -> (Vec<&'static str>, String) {
        let mut layers = Vec::new();
        let mut cur = input.to_string();
        for _ in 0..8 {
            let cards = decode_cards(&cur);
            let Some(top) = cards.first() else {
                return (layers, String::new());
            };
            if top.title == "Hex" {
                break;
            }
            layers.push(top.title);
            cur = top.text.clone();
            if top.title == "JWT" || top.title.starts_with("Unix timestamp") {
                break;
            }
        }
        (layers, cur)
    }

    #[test]
    fn autodecode_detection_and_multilayer_matrix() {
        // Multi-layer chain: "hello world" -> Base64 ("aGVsbG8gd29ybGQ=") -> Hex -> URL-encoded
        let b64_hello = "aGVsbG8gd29ybGQ=";
        let hex_of_b64 = crate::codec::hex_encode(b64_hello.as_bytes());
        let url_of_hex_of_b64 = crate::codec::url_encode(&hex_of_b64, true);

        // Multi-layer chain: "a b/c" -> URL ("a%20b%2Fc") -> Base64
        let b64_of_url = crate::codec::base64_encode(b"a%20b%2Fc", false, true);

        let cases: Vec<(&str, String, Vec<&str>, &str)> = vec![
            // Single-layer encodings
            ("URL-escaped spaces and slash", "a%20b%2Fc".into(), vec!["URL decoded"], "a b/c"),
            ("URL-escaped UTF-8 checkmark", "%E2%9C%93".into(), vec!["URL decoded"], "✓"),
            ("URL-escaped key=value", "a%3Db".into(), vec!["URL decoded"], "a=b"),
            ("Base64 padded", "aGVsbG8gd29ybGQ=".into(), vec!["Base64 decoded"], "hello world"),
            ("Base64 unpadded", "aGVsbG8gd29ybGQ".into(), vec!["Base64 decoded"], "hello world"),
            ("Base64URL ('??>??>')", "Pz8-Pz8-".into(), vec!["Base64URL decoded"], "??>??>"),
            ("Hex lower-case", "68656c6c6f".into(), vec!["Hex decoded"], "hello"),
            ("Hex with 0x prefix and space", "0x6869 6869".into(), vec!["Hex decoded"], "hihi"),
            (
                "Unix timestamp (10-digit seconds)",
                "1700000000".into(),
                vec!["Unix timestamp (seconds)"],
                "2023-11-14 22:13:20 UTC",
            ),
            (
                "Unix timestamp (13-digit milliseconds)",
                "1700000000123".into(),
                vec!["Unix timestamp (milliseconds)"],
                "2023-11-14 22:13:20.123 UTC",
            ),
            // Nested multi-layer chains
            (
                "3-layer chain: URL -> Hex -> Base64",
                url_of_hex_of_b64,
                vec!["URL decoded", "Hex decoded", "Base64 decoded"],
                "hello world",
            ),
            (
                "2-layer chain: Base64 -> URL",
                b64_of_url,
                vec!["Base64 decoded", "URL decoded"],
                "a b/c",
            ),
            // Un-encoded plain text & binary fallbacks
            ("plain text word 'admin'", "admin".into(), vec![], "admin"),
            ("plain 5-digit number '12345'", "12345".into(), vec![], "12345"),
            ("plain text with literal plus", "plain+text".into(), vec![], "plain+text"),
            ("empty string", "".into(), vec![], ""),
            ("whitespace-only string", "   ".into(), vec![], ""),
            ("binary control characters", "\u{0}\u{1}\u{fffd}".into(), vec![], "\u{0}\u{1}\u{fffd}"),
        ];

        assert_table!(cases, |idx, (name, encoded_input, expected_detected_layers, expected_final_plaintext)| {
            let (detected_layers, final_plaintext) = peel_autodecode_layers(&encoded_input);
            assert_eq!(
                detected_layers, expected_detected_layers,
                "case #{idx} ({name}) detected layers mismatch"
            );
            assert_eq!(
                final_plaintext, expected_final_plaintext,
                "case #{idx} ({name}) final plaintext mismatch"
            );
        });
    }

    #[test]
    fn autodecode_rejection_and_edge_case_matrix() {
        // Negative / rejection cases across individual detectors so ordinary tokens never produce noise
        let rejection_cases: [(&str, &str, Vec<&str>); 12] = [
            ("plus alone is not a URL escape", "plain+text", vec!["Hex"]),
            ("trailing percent is not a URL escape", "100%", vec!["Hex"]),
            ("8-char word decoding to binary is not Base64", "password", vec!["Hex"]),
            ("pure hex string is not treated as Base64", "deadbeefcafe", vec!["Hex"]),
            ("short (<8 chars) token is not Base64", "abc", vec!["Hex"]),
            ("Base64 with padding in the middle is rejected", "aGVsbG8=d29y", vec!["Hex"]),
            ("Base64 with mixed + and - alphabets is rejected", "a+b-cdefgh", vec!["Hex"]),
            ("9-digit number is not a timestamp", "170000000", vec!["Hex"]),
            ("11-digit number is not a timestamp", "17000000001", vec!["Hex"]),
            ("10-char alphanumeric is not a timestamp", "17000000x0", vec!["Hex"]),
            ("non-JSON 3-part dot string is not a JWT", "a.b.c", vec!["Hex"]),
            ("non-printable hex bytes (00ff00ff) are not Hex decoded", "00ff00ff", vec!["Hex"]),
        ];

        assert_table!(rejection_cases, |idx, (name, input, expected_titles)| {
            assert_eq!(titles(input), expected_titles, "case #{idx} ({name})");
        });

        // JWT card formatting (including Bearer prefix) and Hex dump truncation
        let h = crate::codec::base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let c = crate::codec::base64url_encode(br#"{"sub":"42","exp":1700000000}"#);
        let token = format!("{h}.{c}.c2ln");
        let card = jwt(&format!("Bearer {token}")).unwrap();
        assert!(card.text.contains("\"alg\": \"HS256\""), "{}", card.text);
        assert!(card.text.contains("\"sub\": \"42\""));
        assert!(card.text.contains("exp: 2023-11-14 22:13:20 UTC"));
        assert_eq!(titles(&token)[0], "JWT");

        assert_eq!(hex_of("Hi").text, "48 69");
        assert!(hex_of(&"x".repeat(300)).text.ends_with("… (300 bytes)"));
    }
}
