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

    fn titles(s: &str) -> Vec<&'static str> {
        decode_cards(s).into_iter().map(|c| c.title).collect()
    }

    #[test]
    fn url_escapes() {
        assert_eq!(url_decoded("a%20b%2Fc").unwrap().text, "a b/c");
        assert_eq!(url_decoded("%E2%9C%93").unwrap().text, "✓");
        assert!(url_decoded("plain+text").is_none(), "a plus alone isn't an escape");
        assert!(url_decoded("100%").is_none());
    }

    #[test]
    fn base64_variants() {
        assert_eq!(base64("aGVsbG8gd29ybGQ=").unwrap(), Card { title: "Base64 decoded", text: "hello world".into() });
        assert_eq!(base64("aGVsbG8gd29ybGQ").unwrap().text, "hello world", "unpadded");
        // "??>" encodes to "Pz8-" in Base64URL
        assert_eq!(base64("Pz8-Pz8-").unwrap(), Card { title: "Base64URL decoded", text: "??>??>".into() });
        assert!(base64("password").is_none(), "decodes to binary, not text");
        assert!(base64("deadbeefcafe").is_none(), "hex strings aren't treated as Base64");
        assert!(base64("abc").is_none(), "too short");
        assert!(base64("aGVsbG8=d29y").is_none(), "padding in the middle");
        assert!(base64("a+b-cdefgh").is_none(), "mixed alphabets");
    }

    #[test]
    fn timestamps() {
        assert_eq!(timestamp("1700000000").unwrap().text, "2023-11-14 22:13:20 UTC");
        assert_eq!(timestamp("1700000000123").unwrap().text, "2023-11-14 22:13:20.123 UTC");
        assert!(timestamp("170000000").is_none());
        assert!(timestamp("17000000001").is_none());
        assert!(timestamp("17000000x0").is_none());
    }

    #[test]
    fn jwts() {
        let h = crate::codec::base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let c = crate::codec::base64url_encode(br#"{"sub":"42","exp":1700000000}"#);
        let token = format!("{h}.{c}.c2ln");
        let card = jwt(&format!("Bearer {token}")).unwrap();
        assert!(card.text.contains("\"alg\": \"HS256\""), "{}", card.text);
        assert!(card.text.contains("\"sub\": \"42\""));
        assert!(card.text.contains("exp: 2023-11-14 22:13:20 UTC"));
        assert!(jwt("a.b.c").is_none());
        assert_eq!(titles(&token)[0], "JWT");
    }

    #[test]
    fn hex() {
        assert_eq!(hex_decoded("68656c6c6f").unwrap().text, "hello");
        assert_eq!(hex_decoded("0x6869 6869").unwrap().text, "hihi");
        assert!(hex_decoded("abc").is_none());
        assert!(hex_decoded("00ff00ff").is_none(), "not readable");
        assert_eq!(hex_of("Hi").text, "48 69");
        assert!(hex_of(&"x".repeat(300)).text.ends_with("… (300 bytes)"));
    }

    #[test]
    fn plain_values_only_get_hex() {
        assert_eq!(titles("admin"), ["Hex"]);
        assert_eq!(titles("12345"), ["Hex"]);
        assert!(decode_cards("").is_empty());
        assert!(decode_cards("   ").is_empty());
        // binary-looking text never panics
        assert_eq!(titles("\u{0}\u{1}\u{fffd}"), ["Hex"]);
        assert_eq!(titles("1700000000"), ["Unix timestamp (seconds)", "Hex"]);
        assert_eq!(titles("a%3Db"), ["URL decoded", "Hex"]);
    }
}
