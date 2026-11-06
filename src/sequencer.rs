//! Sequencer: collect tokens and judge how random they are.
//! Defaults from ProjectDefaults.json sequencer.*: 5 capture threads, pad short tokens at the
//! start with "0", ignore tokens whose length deviates by more than 5 characters.
//! Rules from the original's help pages (tools/sequencer/index.html, results/tests.html,
//! sample/live-capture.html):
//! - at least 100 tokens to analyse; at most 20,000 (the FIPS sample size); 5,000 usually enough;
//! - character-level: each position gets bits from the size of its character set (4 chars = 2 bits,
//!   8 = 3 bits) and counts toward effective entropy if it passes at the chosen significance level;
//! - bit-level: tokens become bits (per position, by character-set size) and the FIPS monobit,
//!   poker, runs and long-run tests run at each bit position across the sample, with the pass
//!   criteria adjusted to the sample size; long runs only fail when a run is too long.

use regex::Regex;

pub const MAX_LENGTH_DEVIATION: usize = 5;
pub const MIN_TOKENS: usize = 100;
pub const MAX_TOKENS: usize = 20_000;
pub const RECOMMENDED_TOKENS: usize = 5_000;
/// Default significance level for the summary (scientific experiments use 1%-5%).
pub const SIGNIFICANCE: f64 = 0.01;

/// Pull a token from a response: a cookie value, a form/JSON field value, or a regex capture.
pub fn extract(response: &str, location: u8, name: &str) -> Option<String> {
    let name = name.trim();
    match location {
        0 => response.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if !k.trim().eq_ignore_ascii_case("set-cookie") {
                return None;
            }
            let first = v.trim().split(';').next()?;
            let (n, val) = first.split_once('=')?;
            (name.is_empty() || n.trim() == name).then(|| val.trim().to_string())
        }),
        1 => {
            let pat = format!(r#"(?i)name=["']?{}["']?[^>]*value=["']([^"']+)|"{}"\s*:\s*"([^"]+)""#, regex::escape(name), regex::escape(name));
            let re = Regex::new(&pat).ok()?;
            let c = re.captures(response)?;
            c.get(1).or(c.get(2)).map(|m| m.as_str().to_string())
        }
        _ => {
            let re = Regex::new(name).ok()?;
            let c = re.captures(response)?;
            c.get(1).or(c.get(0)).map(|m| m.as_str().to_string())
        }
    }
}

/// Where a token is taken from each response. The string is the cookie name, the header name,
/// or a regular expression (its first capture group, else the whole match).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenLocation {
    Cookie(String),
    Header(String),
    Regex(String),
}

impl Default for TokenLocation {
    fn default() -> Self {
        TokenLocation::Cookie(String::new())
    }
}

/// Pull a token from a response by the chosen location. Cookie and Regex reuse [`extract`];
/// Header reads a `Name: value` line from the response head.
pub fn extract_token(location: &TokenLocation, response: &str) -> Option<String> {
    match location {
        TokenLocation::Cookie(name) => extract(response, 0, name),
        TokenLocation::Regex(pattern) => extract(response, 2, pattern),
        TokenLocation::Header(name) => {
            let name = name.trim();
            let head = response.split("\n\n").next().unwrap_or(response);
            head.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (!name.is_empty() && k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().to_string())
            })
        }
    }
}

/// Structured randomness statistics over a set of captured tokens: lengths, Shannon entropy
/// (overall and per character position) and the FIPS monobit ratio. The detailed FIPS
/// bit-level report is [`analyse`].
#[derive(Clone, Debug, PartialEq)]
pub struct SequencerAnalysis {
    pub sample_count: usize,
    pub min_len: usize,
    pub max_len: usize,
    /// Shannon entropy of the character distribution, in bits per character.
    pub overall_entropy: f64,
    /// The most entropy the observed alphabet could carry: log2(distinct characters).
    pub max_possible_entropy: f64,
    /// Entropy (bits) of the character distribution at each position, left to right.
    pub per_char_entropy: Vec<f64>,
    pub char_distribution: std::collections::BTreeMap<char, usize>,
    /// Proportion of 1 bits across all tokens' bytes.
    pub monobit_ratio: f64,
    /// The monobit ratio is within the FIPS band (0.485..=0.515).
    pub fips_monobit_passed: bool,
}

/// Shannon entropy (bits) of a set of counts summing to `total`.
fn shannon_entropy(counts: impl Iterator<Item = usize>, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .filter(|&c| c > 0)
        .map(|c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// If every (non-blank) token is hexadecimal, or every one is standard Base64, the raw bytes
/// they decode to; otherwise `None` (tokens are used as their own bytes). Hex is preferred
/// where both could match, since its alphabet is a subset of Base64's.
fn decoded_token_bytes(tokens: &[String]) -> Option<Vec<u8>> {
    let toks: Vec<&str> = tokens.iter().map(|t| t.trim()).filter(|t| !t.is_empty()).collect();
    if toks.is_empty() {
        return None;
    }
    // hex: even length, all hex digits
    if toks.iter().all(|t| t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit())) {
        let mut out = Vec::new();
        for t in &toks {
            let b = t.as_bytes();
            for pair in b.chunks_exact(2) {
                let hi = (pair[0] as char).to_digit(16)?;
                let lo = (pair[1] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
            }
        }
        return Some(out);
    }
    // Base64, standard or URL-safe ('+/' or '-_'), padded or not (e.g. Google's unpadded
    // URL-safe AEC cookies of 98-100 chars). Accept any length a real encoding can have:
    // at most two trailing '=' and a pad-trimmed length that is not %4 == 1 (impossible).
    let is_base64 = toks.iter().all(|t| {
        let body = t.trim_end_matches('=');
        let pad = t.len() - body.len();
        pad <= 2 && body.len() % 4 != 1 && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
    });
    if is_base64 {
        let mut out = Vec::new();
        for t in &toks {
            out.extend(crate::codec::base64_decode(t));
        }
        if !out.is_empty() {
            return Some(out);
        }
    }
    None
}

/// Compute randomness statistics for `tokens`. `None` when there are no tokens.
pub fn analyze_tokens(tokens: &[String]) -> Option<SequencerAnalysis> {
    if tokens.is_empty() {
        return None;
    }
    let chars: Vec<Vec<char>> = tokens.iter().map(|t| t.chars().collect()).collect();
    let lens: Vec<usize> = chars.iter().map(|c| c.len()).collect();
    let min_len = *lens.iter().min().unwrap_or(&0);
    let max_len = *lens.iter().max().unwrap_or(&0);

    let mut char_distribution: std::collections::BTreeMap<char, usize> = Default::default();
    let mut total_chars = 0usize;
    for token in &chars {
        for &c in token {
            *char_distribution.entry(c).or_insert(0) += 1;
            total_chars += 1;
        }
    }
    let overall_entropy = shannon_entropy(char_distribution.values().copied(), total_chars);
    let distinct = char_distribution.len();
    let max_possible_entropy = if distinct > 1 { (distinct as f64).log2() } else { 0.0 };

    let per_char_entropy = (0..max_len)
        .map(|pos| {
            let mut counts: std::collections::BTreeMap<char, usize> = Default::default();
            let mut n = 0usize;
            for token in &chars {
                if let Some(&c) = token.get(pos) {
                    *counts.entry(c).or_insert(0) += 1;
                    n += 1;
                }
            }
            shannon_entropy(counts.values().copied(), n)
        })
        .collect();

    // The monobit test wants the raw entropy bits. When the tokens are hex or base64, the
    // text encoding skews the bit balance (ASCII '0'..'f' are not bit-balanced), so decode them
    // to the bytes they represent first; otherwise a perfectly random hex token would fail.
    let decoded = decoded_token_bytes(tokens);
    let (ones, total_bits): (u64, u64) = match &decoded {
        Some(bytes) => (bytes.iter().map(|b| b.count_ones() as u64).sum(), bytes.len() as u64 * 8),
        None => {
            let mut ones = 0u64;
            let mut bits = 0u64;
            for token in tokens {
                for b in token.as_bytes() {
                    ones += b.count_ones() as u64;
                    bits += 8;
                }
            }
            (ones, bits)
        }
    };
    let monobit_ratio = if total_bits > 0 { ones as f64 / total_bits as f64 } else { 0.0 };
    let fips_monobit_passed = (0.485..=0.515).contains(&monobit_ratio);

    Some(SequencerAnalysis {
        sample_count: tokens.len(),
        min_len,
        max_len,
        overall_entropy,
        max_possible_entropy,
        per_char_entropy,
        char_distribution,
        monobit_ratio,
        fips_monobit_passed,
    })
}

/// A one-word rating of a Shannon entropy value (bits per character) against the most the
/// observed alphabet could carry, for the Analysis scorecard.
pub fn entropy_rating(entropy: f64, max_possible: f64) -> &'static str {
    if max_possible <= 0.0 {
        return "Poor";
    }
    match entropy / max_possible {
        r if r >= 0.95 => "Excellent",
        r if r >= 0.75 => "Moderate",
        _ => "Poor",
    }
}

/// Standard normal upper-tail probability.
fn normal_sf(z: f64) -> f64 {
    // Abramowitz & Stegun 7.1.26 erf approximation
    let x = z / std::f64::consts::SQRT_2;
    let t = 1.0 / (1.0 + 0.3275911 * x.abs());
    let y = 1.0 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * (-x * x).exp();
    let erf = if x >= 0.0 { y } else { -y };
    0.5 * (1.0 - erf)
}

/// Upper-tail probability of a chi-square value (Wilson-Hilferty approximation).
fn chi2_sf(x: f64, df: f64) -> f64 {
    if df <= 0.0 {
        return 1.0;
    }
    let z = ((x / df).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df))) / (2.0 / (9.0 * df)).sqrt();
    normal_sf(z)
}

struct Position {
    charset: Vec<char>,
    bits: u32,
    p_value: f64,
}

fn char_positions(padded: &[Vec<char>], width: usize) -> Vec<Position> {
    (0..width)
        .map(|pos| {
            let mut counts: std::collections::BTreeMap<char, usize> = Default::default();
            for t in padded {
                *counts.entry(t[pos]).or_insert(0) += 1;
            }
            let k = counts.len();
            let bits = if k >= 2 { (k as f64).log2().floor() as u32 } else { 0 };
            let n = padded.len() as f64;
            let exp = n / k.max(1) as f64;
            let x2: f64 = counts.values().map(|&o| (o as f64 - exp).powi(2) / exp).sum();
            let p_value = if k >= 2 { chi2_sf(x2, (k - 1) as f64) } else { 0.0 };
            Position { charset: counts.keys().copied().collect(), bits, p_value }
        })
        .collect()
}

/// Per-token bit strings, built from each character's index in its position's character set.
fn token_bits(padded: &[Vec<char>], positions: &[Position]) -> Vec<Vec<u8>> {
    padded
        .iter()
        .map(|t| {
            let mut out = Vec::new();
            for (pos, info) in positions.iter().enumerate() {
                if info.bits == 0 {
                    continue;
                }
                let idx = info.charset.iter().position(|c| *c == t[pos]).unwrap_or(0) as u32 & ((1 << info.bits) - 1);
                for b in (0..info.bits).rev() {
                    out.push(((idx >> b) & 1) as u8);
                }
            }
            out
        })
        .collect()
}

/// FIPS 140-2 tests on one bit position's sequence (one bit per token), with the 20,000-bit
/// bounds scaled to the sample size. Returns (monobit, poker, runs, long run) pass flags.
fn fips(seq: &[u8]) -> (bool, bool, bool, bool) {
    let n = seq.len() as f64;
    let scale = n / 20_000.0;
    let ones = seq.iter().filter(|&&b| b == 1).count() as f64;
    let monobit = ones > 9_725.0 * scale && ones < 10_275.0 * scale;
    let m = seq.len() / 4;
    let mut f = [0usize; 16];
    for ch in seq.chunks_exact(4) {
        f[(ch[0] * 8 + ch[1] * 4 + ch[2] * 2 + ch[3]) as usize] += 1;
    }
    let x = if m > 0 { 16.0 / m as f64 * f.iter().map(|&v| (v * v) as f64).sum::<f64>() - m as f64 } else { 0.0 };
    let poker = x > 2.16 && x < 46.17;
    let mut runs = [[0usize; 7]; 2];
    let mut longest = 0;
    let mut i = 0;
    while i < seq.len() {
        let mut j = i;
        while j < seq.len() && seq[j] == seq[i] {
            j += 1;
        }
        longest = longest.max(j - i);
        runs[seq[i] as usize][(j - i).min(6)] += 1;
        i = j;
    }
    let bounds = [(2_315.0, 2_685.0), (1_114.0, 1_386.0), (527.0, 723.0), (240.0, 384.0), (103.0, 209.0), (103.0, 209.0)];
    let runs_ok = (0..2).all(|v| (1..=6).all(|l| {
        let (lo, hi) = bounds[l - 1];
        let c = runs[v][l] as f64;
        c >= lo * scale && c <= hi * scale
    }));
    let long_ok = longest < 26;
    (monobit, poker, runs_ok, long_ok)
}

/// Plain-language report.
pub fn analyse(raw: &[String]) -> String {
    let tokens: Vec<String> = raw.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).take(MAX_TOKENS).collect();
    if tokens.len() < MIN_TOKENS {
        return format!("At least {MIN_TOKENS} tokens are needed to analyse ({} so far). {RECOMMENDED_TOKENS} is usually enough; {MAX_TOKENS} gives FIPS-compliant results.", tokens.len());
    }
    let mut lens: Vec<usize> = tokens.iter().map(|t| t.chars().count()).collect();
    lens.sort();
    let median = lens[lens.len() / 2];
    let kept: Vec<String> = tokens.iter().filter(|t| t.chars().count().abs_diff(median) <= MAX_LENGTH_DEVIATION).cloned().collect();
    let width = kept.iter().map(|t| t.chars().count()).max().unwrap_or(0);
    let padded: Vec<Vec<char>> = kept
        .iter()
        .map(|t| {
            let mut c: Vec<char> = std::iter::repeat('0').take(width - t.chars().count()).collect();
            c.extend(t.chars());
            c
        })
        .collect();
    let positions = char_positions(&padded, width);
    let effective: u32 = positions.iter().filter(|p| p.p_value >= SIGNIFICANCE).map(|p| p.bits).sum();
    let possible: u32 = positions.iter().map(|p| p.bits).sum();
    let duplicates = kept.len() - kept.iter().collect::<std::collections::HashSet<_>>().len();

    let bits = token_bits(&padded, &positions);
    let nbits = bits.first().map(|b| b.len()).unwrap_or(0);
    let mut passed = [0usize; 4];
    for b in 0..nbits {
        let seq: Vec<u8> = bits.iter().map(|t| t[b]).collect();
        let r = fips(&seq);
        for (k, ok) in [r.0, r.1, r.2, r.3].into_iter().enumerate() {
            passed[k] += ok as usize;
        }
    }
    let quality = if duplicates > 0 {
        "poor (tokens repeat)"
    } else if effective >= 64 {
        "excellent"
    } else if effective >= 48 {
        "good"
    } else if effective >= 32 {
        "reasonable"
    } else if effective >= 16 {
        "poor"
    } else {
        "extremely poor"
    };
    let note = if kept.len() < MAX_TOKENS { format!("\n(Sample of {}: FIPS pass criteria scaled to this size; {MAX_TOKENS} tokens give formal FIPS results.)", kept.len()) } else { String::new() };
    format!(
        "Tokens analysed: {} ({} ignored for abnormal length)\nToken length: {width} characters (short tokens padded at the start with 0)\nRepeated tokens: {duplicates}\n\n\
         Overall quality of randomness: {quality}\nEffective entropy at a significance level of 1%: {effective} bits (of {possible} possible)\n\n\
         Bit-level FIPS tests, bit positions passing (of {nbits}):\n  monobit {}   poker {}   runs {}   long runs {}{note}",
        kept.len(),
        tokens.len() - kept.len(),
        passed[0], passed[1], passed[2], passed[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_cookie_field_and_regex() {
        let r = "HTTP/1.1 200 OK\nSet-Cookie: sid=abc123; Path=/\n\n<input name=\"csrf\" value=\"tok9\">";
        assert_eq!(extract(r, 0, "sid"), Some("abc123".into()));
        assert_eq!(extract(r, 1, "csrf"), Some("tok9".into()));
        assert_eq!(extract(r, 2, r#"value="(\w+)""#), Some("tok9".into()));
    }
    #[test]
    fn extract_token_from_each_location() {
        let r = "HTTP/1.1 200 OK\nSet-Cookie: sid=abc123; Path=/\nX-Token: hdr-value\n\nbody tok=zzz9";
        assert_eq!(extract_token(&TokenLocation::Cookie("sid".into()), r), Some("abc123".into()));
        assert_eq!(extract_token(&TokenLocation::Header("X-Token".into()), r), Some("hdr-value".into()));
        assert_eq!(extract_token(&TokenLocation::Regex(r"tok=(\w+)".into()), r), Some("zzz9".into()));
        // a header name that isn't there, and the status line isn't treated as a header
        assert_eq!(extract_token(&TokenLocation::Header("Missing".into()), r), None);
        assert_eq!(extract_token(&TokenLocation::Header("HTTP/1.1".into()), r), None);
    }

    #[test]
    fn repeated_tokens_have_no_entropy() {
        let t: Vec<String> = (0..50).map(|_| "AAAA".to_string()).collect();
        let a = analyze_tokens(&t).unwrap();
        assert_eq!(a.sample_count, 50);
        assert_eq!((a.min_len, a.max_len), (4, 4));
        assert!(a.overall_entropy < 1e-9, "entropy {}", a.overall_entropy);
        assert!(a.per_char_entropy.iter().all(|&e| e < 1e-9));
        assert_eq!(a.char_distribution.get(&'A'), Some(&200));
        // "AAAA" is hex, decoding to 0xAA = 10101010 (balanced), so monobit passes even though
        // the tokens are identical — monobit alone cannot detect the absence of entropy
        assert!(a.fips_monobit_passed);
    }

    #[test]
    fn hex_tokens_are_decoded_for_monobit() {
        // raw ASCII hex is bit-biased and would falsely fail monobit; decoding to bytes fixes it.
        // "a5" -> 0xA5 = 10100101 (balanced) -> passes
        let balanced: Vec<String> = (0..20).map(|_| "a5a5".to_string()).collect();
        let a = analyze_tokens(&balanced).unwrap();
        assert!((a.monobit_ratio - 0.5).abs() < 1e-9, "ratio {}", a.monobit_ratio);
        assert!(a.fips_monobit_passed);
        // "ff" -> 0xFF = 11111111 (all ones) -> fails
        let skewed: Vec<String> = (0..20).map(|_| "ffff".to_string()).collect();
        let a = analyze_tokens(&skewed).unwrap();
        assert!((a.monobit_ratio - 1.0).abs() < 1e-9, "ratio {}", a.monobit_ratio);
        assert!(!a.fips_monobit_passed);
    }

    #[test]
    fn base64_tokens_are_decoded_for_monobit() {
        // "qg==" decodes to a single 0xAA byte (balanced); not all hex, so the Base64 path runs
        let t: Vec<String> = (0..40).map(|_| "qg==".to_string()).collect();
        let a = analyze_tokens(&t).unwrap();
        assert!((a.monobit_ratio - 0.5).abs() < 1e-9, "ratio {}", a.monobit_ratio);
        assert!(a.fips_monobit_passed);
    }

    #[test]
    fn urlsafe_unpadded_base64_tokens_are_decoded() {
        // Google AEC-style tokens: ~99 chars, URL-safe alphabet ('-' and '_'), no '=' padding,
        // length not a multiple of 4. These must be decoded, not read as raw ASCII (which is
        // bit-biased and would falsely fail monobit around 0.46).
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let t: Vec<String> = (0..300)
            .map(|_| (0..99).map(|_| {
                x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                ALPHA[(x as usize) % ALPHA.len()] as char
            }).collect())
            .collect();
        assert_eq!(t[0].len(), 99, "unpadded, not a multiple of 4");
        assert!(t.iter().any(|s| s.contains('-') || s.contains('_')), "corpus exercises URL-safe chars");
        let a = analyze_tokens(&t).unwrap();
        assert!(a.fips_monobit_passed, "decoded random bytes should pass monobit: ratio {}", a.monobit_ratio);
    }

    #[test]
    fn random_hex_approaches_full_entropy() {
        let mut x: u64 = 0x2545F4914F6CDD1D;
        let t: Vec<String> = (0..2000)
            .map(|_| (0..16).map(|_| {
                x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                b"0123456789abcdef"[(x % 16) as usize] as char
            }).collect())
            .collect();
        let a = analyze_tokens(&t).unwrap();
        assert!((a.max_possible_entropy - 4.0).abs() < 1e-9, "alphabet {}", a.max_possible_entropy);
        assert!(a.overall_entropy > 3.9, "entropy {}", a.overall_entropy);
        assert_eq!(entropy_rating(a.overall_entropy, a.max_possible_entropy), "Excellent");
        // decoded to random bytes, the bitstream is balanced and passes monobit (raw ASCII hex
        // would have come in around 0.44 and failed)
        assert!(a.fips_monobit_passed, "ratio {}", a.monobit_ratio);
    }

    #[test]
    fn sequential_tokens_have_low_leading_entropy() {
        let t: Vec<String> = (0..1000).map(|i| format!("{i:08}")).collect();
        let a = analyze_tokens(&t).unwrap();
        // the leading digits are almost always '0'; the last digit cycles 0-9
        assert!(a.per_char_entropy[0] < a.per_char_entropy[7], "{:?}", a.per_char_entropy);
        assert_eq!(entropy_rating(a.overall_entropy, a.max_possible_entropy), "Poor");
    }

    #[test]
    fn repeated_tokens_are_poor() {
        let t: Vec<String> = (0..150).map(|_| "aaaa".to_string()).collect();
        assert!(analyse(&t).contains("poor"));
    }
    #[test]
    fn needs_100_tokens() {
        let t: Vec<String> = (0..99).map(|i| format!("{i:04x}")).collect();
        assert!(analyse(&t).starts_with("At least 100 tokens"));
    }
    #[test]
    fn random_tokens_score_well() {
        let mut x: u64 = 0x2545F4914F6CDD1D;
        let t: Vec<String> = (0..5000).map(|_| {
            (0..16).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; b"0123456789abcdef"[(x % 16) as usize] as char }).collect()
        }).collect();
        let r = analyse(&t);
        assert!(r.contains("excellent"), "{r}");
    }
    #[test]
    fn counter_tokens_score_poorly() {
        let t: Vec<String> = (0..2000).map(|i| format!("{i:08}")).collect();
        let r = analyse(&t);
        assert!(!r.contains("excellent") && !r.contains("good"), "{r}");
    }
}
