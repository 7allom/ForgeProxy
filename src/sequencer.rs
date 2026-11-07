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

/// Token encoding format used when pre-processing tokens for randomness analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TokenFormat {
    #[default]
    Auto,
    Ascii,
    Hex,
    Base64,
}

impl TokenFormat {
    pub const ALL: [TokenFormat; 4] = [
        TokenFormat::Auto,
        TokenFormat::Ascii,
        TokenFormat::Hex,
        TokenFormat::Base64,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            TokenFormat::Auto => "Auto",
            TokenFormat::Ascii => "Raw/ASCII",
            TokenFormat::Hex => "Hex",
            TokenFormat::Base64 => "Base64",
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
    /// Proportion of 1 bits across all decoded token bytes (0.0 when format is Ascii).
    pub monobit_ratio: f64,
    /// The monobit ratio is within the FIPS band (0.485..=0.515).
    pub fips_monobit_passed: bool,
    /// True when tokens were decoded to raw binary bytes (Hex or Base64) so FIPS bitstream
    /// tests are meaningful; false for raw/ASCII text where 8-bit ASCII byte representation
    /// is inherently skewed.
    pub fips_applicable: bool,
    /// The resolved token format used during analysis (`Hex`, `Base64`, or `Ascii`).
    pub detected_format: TokenFormat,
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

fn decode_hex_str(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn is_valid_base64_str(t: &str) -> bool {
    if t.is_empty() {
        return false;
    }
    let body = t.trim_end_matches('=');
    let pad = t.len() - body.len();
    pad <= 2
        && !body.is_empty()
        && body.len() % 4 != 1
        && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
}

/// Resolve the effective token format (`Hex`, `Base64`, or `Ascii`) and decode each non-empty
/// token into raw bytes when the resolved format is `Hex` or `Base64`.
///
/// In `Auto` mode:
/// - If all tokens are valid even-length hex strings, treat as `Hex`.
/// - Else if all tokens are valid Base64 and the sample uses Base64-distinguishing characters
///   (`+`, `/`, `-`, `_`, or `=` padding), treat as `Base64`. Pure alphanumeric (`A-Za-z0-9`)
///   tokens without Base64 symbols or padding use a 62-char alphabet (`5.95` bits/char) rather
///   than 64-char Base64, so `Auto` treats them as `Ascii` to avoid a false-negative monobit
///   skew on missing 6-bit values `62` (`111110`) and `63` (`111111`).
pub fn decode_tokens_with_format(tokens: &[String], format: TokenFormat) -> (TokenFormat, Option<Vec<Vec<u8>>>) {
    let toks: Vec<&str> = tokens.iter().map(|t| t.trim()).filter(|t| !t.is_empty()).collect();
    if toks.is_empty() {
        return (TokenFormat::Ascii, None);
    }
    match format {
        TokenFormat::Ascii => (TokenFormat::Ascii, None),
        TokenFormat::Hex => {
            let mut per_tok = Vec::with_capacity(toks.len());
            for t in &toks {
                match decode_hex_str(t) {
                    Some(b) if !b.is_empty() => per_tok.push(b),
                    _ => return (TokenFormat::Ascii, None),
                }
            }
            (TokenFormat::Hex, Some(per_tok))
        }
        TokenFormat::Base64 => {
            if !toks.iter().all(|t| is_valid_base64_str(t)) {
                return (TokenFormat::Ascii, None);
            }
            let mut per_tok = Vec::with_capacity(toks.len());
            for t in &toks {
                let b = crate::codec::base64_decode(t);
                if b.is_empty() {
                    return (TokenFormat::Ascii, None);
                }
                per_tok.push(b);
            }
            (TokenFormat::Base64, Some(per_tok))
        }
        TokenFormat::Auto => {
            if toks.iter().all(|t| t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit())) {
                return decode_tokens_with_format(tokens, TokenFormat::Hex);
            }
            let has_b64_markers = toks.iter().any(|t| {
                t.ends_with('=') || t.bytes().any(|b| matches!(b, b'+' | b'/' | b'-' | b'_'))
            });
            if has_b64_markers && toks.iter().all(|t| is_valid_base64_str(t)) {
                return decode_tokens_with_format(tokens, TokenFormat::Base64);
            }
            (TokenFormat::Ascii, None)
        }
    }
}

/// Compute randomness statistics for `tokens` using `TokenFormat::Auto`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn analyze_tokens(tokens: &[String]) -> Option<SequencerAnalysis> {
    analyze_tokens_with_format(tokens, TokenFormat::Auto)
}

/// Compute randomness statistics for `tokens` using the specified [`TokenFormat`].
/// FIPS 140-2 bitstream checks run ONLY on decoded raw bytes (`Hex` or `Base64`).
/// When the resolved format is `Ascii` (or un-decodable alphanumeric text), flat byte-level
/// FIPS monobit checks are skipped (`fips_applicable = false`).
pub fn analyze_tokens_with_format(tokens: &[String], format: TokenFormat) -> Option<SequencerAnalysis> {
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

    let (detected_format, decoded) = decode_tokens_with_format(tokens, format);
    let (monobit_ratio, fips_monobit_passed, fips_applicable) = match decoded {
        Some(per_tok) => {
            let ones: u64 = per_tok.iter().flatten().map(|b| b.count_ones() as u64).sum();
            let total_bits: u64 = per_tok.iter().map(|v| v.len() as u64 * 8).sum();
            let ratio = if total_bits > 0 { ones as f64 / total_bits as f64 } else { 0.0 };
            let passed = (0.485..=0.515).contains(&ratio);
            (ratio, passed, true)
        }
        None => (0.0, false, false),
    };

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
        fips_applicable,
        detected_format,
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
            Position { bits, p_value }
        })
        .collect()
}

/// Per-token bit strings built strictly from decoded raw bytes (padded with leading 0 bytes to
/// match the longest decoded token in the sample).
fn decoded_byte_bits(decoded: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let max_bytes = decoded.iter().map(|b| b.len()).max().unwrap_or(0);
    decoded
        .iter()
        .map(|bytes| {
            let mut out = Vec::with_capacity(max_bytes * 8);
            for _ in 0..(max_bytes - bytes.len()) {
                out.extend([0u8; 8]);
            }
            for &byte in bytes {
                for shift in (0..8).rev() {
                    out.push((byte >> shift) & 1);
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

/// Plain-language report using `TokenFormat::Auto`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn analyse(raw: &[String]) -> String {
    analyse_with_format(raw, TokenFormat::Auto)
}

/// Plain-language report using the specified [`TokenFormat`].
pub fn analyse_with_format(raw: &[String], format: TokenFormat) -> String {
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

    let (_, decoded) = decode_tokens_with_format(&kept, format);
    let fips_section = match decoded {
        Some(per_tok) => {
            let bits = decoded_byte_bits(&per_tok);
            let nbits = bits.first().map(|b| b.len()).unwrap_or(0);
            let mut passed = [0usize; 4];
            for b in 0..nbits {
                let seq: Vec<u8> = bits.iter().map(|t| t[b]).collect();
                let r = fips(&seq);
                for (k, ok) in [r.0, r.1, r.2, r.3].into_iter().enumerate() {
                    passed[k] += ok as usize;
                }
            }
            let note = if kept.len() < MAX_TOKENS {
                format!("\n(Sample of {}: FIPS pass criteria scaled to this size; {MAX_TOKENS} tokens give formal FIPS results.)", kept.len())
            } else {
                String::new()
            };
            format!(
                "Bit-level FIPS tests, bit positions passing (of {nbits}):\n  monobit {}   poker {}   runs {}   long runs {}{note}",
                passed[0], passed[1], passed[2], passed[3]
            )
        }
        None => "Bit-level FIPS tests: N/A (ASCII text - rely on Shannon entropy)".to_string(),
    };

    format!(
        "Tokens analysed: {} ({} ignored for abnormal length)\nToken length: {width} characters (short tokens padded at the start with 0)\nRepeated tokens: {duplicates}\n\n\
         Overall quality of randomness: {quality}\nEffective entropy at a significance level of 1%: {effective} bits (of {possible} possible)\n\n\
         {fips_section}",
        kept.len(),
        tokens.len() - kept.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn prng_tokens(count: usize, len: usize, alphabet: &[u8], seed: u64) -> Vec<String> {
        let mut x = seed;
        (0..count)
            .map(|_| {
                (0..len)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        alphabet[(x as usize) % alphabet.len()] as char
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn token_format_and_preprocessing_matrix() {
        const ALPHANUM_62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const B64_URL_64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let base62_sample = prng_tokens(300, 24, ALPHANUM_62, 0x517CC1B727220A95);
        let urlsafe_b64_sample = prng_tokens(300, 99, B64_URL_64, 0x9E3779B97F4A7C15);
        let hex_balanced: Vec<String> = (0..120).map(|_| "a5a5".to_string()).collect();
        let std_b64_padded: Vec<String> = (0..120).map(|_| "qg==".to_string()).collect();
        let invalid_hex: Vec<String> = (0..120).map(|_| "a5g".to_string()).collect();
        let invalid_b64: Vec<String> = (0..120).map(|_| "tok!@#".to_string()).collect();

        struct FormatCase<'a> {
            name: &'a str,
            tokens: &'a [String],
            setting: TokenFormat,
            expected_resolved: TokenFormat,
            expected_fips_applicable: bool,
            expected_monobit_pass: bool,
        }

        let cases = [
            FormatCase {
                name: "Auto on 62-char alphanumeric resolves to Ascii and marks FIPS N/A",
                tokens: &base62_sample,
                setting: TokenFormat::Auto,
                expected_resolved: TokenFormat::Ascii,
                expected_fips_applicable: false,
                expected_monobit_pass: false,
            },
            FormatCase {
                name: "Auto on even-length hex resolves to Hex and runs FIPS",
                tokens: &hex_balanced,
                setting: TokenFormat::Auto,
                expected_resolved: TokenFormat::Hex,
                expected_fips_applicable: true,
                expected_monobit_pass: true,
            },
            FormatCase {
                name: "Explicit Ascii on hex tokens overrides to Ascii and skips FIPS",
                tokens: &hex_balanced,
                setting: TokenFormat::Ascii,
                expected_resolved: TokenFormat::Ascii,
                expected_fips_applicable: false,
                expected_monobit_pass: false,
            },
            FormatCase {
                name: "Explicit Hex on hex tokens resolves to Hex and runs FIPS",
                tokens: &hex_balanced,
                setting: TokenFormat::Hex,
                expected_resolved: TokenFormat::Hex,
                expected_fips_applicable: true,
                expected_monobit_pass: true,
            },
            FormatCase {
                name: "Auto on standard padded Base64 ('qg==') resolves to Base64",
                tokens: &std_b64_padded,
                setting: TokenFormat::Auto,
                expected_resolved: TokenFormat::Base64,
                expected_fips_applicable: true,
                expected_monobit_pass: true,
            },
            FormatCase {
                name: "Auto on 99-char unpadded URL-safe Base64 resolves to Base64 and passes monobit",
                tokens: &urlsafe_b64_sample,
                setting: TokenFormat::Auto,
                expected_resolved: TokenFormat::Base64,
                expected_fips_applicable: true,
                expected_monobit_pass: true,
            },
            FormatCase {
                name: "Explicit Hex on odd/non-hex tokens falls back to Ascii",
                tokens: &invalid_hex,
                setting: TokenFormat::Hex,
                expected_resolved: TokenFormat::Ascii,
                expected_fips_applicable: false,
                expected_monobit_pass: false,
            },
            FormatCase {
                name: "Explicit Base64 on punctuation tokens falls back to Ascii",
                tokens: &invalid_b64,
                setting: TokenFormat::Base64,
                expected_resolved: TokenFormat::Ascii,
                expected_fips_applicable: false,
                expected_monobit_pass: false,
            },
        ];

        assert_table!(cases, |idx, case| {
            let a = analyze_tokens_with_format(case.tokens, case.setting).unwrap();
            assert_eq!(a.detected_format, case.expected_resolved, "case #{idx} ({}) format", case.name);
            assert_eq!(a.fips_applicable, case.expected_fips_applicable, "case #{idx} ({}) fips_applicable", case.name);
            assert_eq!(a.fips_monobit_passed, case.expected_monobit_pass, "case #{idx} ({}) monobit pass", case.name);
            let report = analyse_with_format(case.tokens, case.setting);
            if case.expected_fips_applicable {
                assert!(report.contains("Bit-level FIPS tests, bit positions passing"), "case #{idx} ({}) report", case.name);
            } else {
                assert!(
                    report.contains("N/A (ASCII text - rely on Shannon entropy)"),
                    "case #{idx} ({}) N/A report: {report}",
                    case.name
                );
            }
        });

        // Token extraction matrix (Cookie, Header, Form/JSON field, Regex)
        let resp = "HTTP/1.1 200 OK\nSet-Cookie: sid=abc123; Path=/\nX-Token: hdr-value\n\n<input name=\"csrf\" value=\"tok9\"> body tok=zzz9";
        let extract_cases: [(&str, Option<String>, Option<&str>); 7] = [
            ("extract location 0 (Set-Cookie)", extract(resp, 0, "sid"), Some("abc123")),
            ("extract location 1 (HTML input field)", extract(resp, 1, "csrf"), Some("tok9")),
            ("extract location 2 (Regex capture)", extract(resp, 2, r#"value="(\w+)""#), Some("tok9")),
            ("TokenLocation::Cookie", extract_token(&TokenLocation::Cookie("sid".into()), resp), Some("abc123")),
            ("TokenLocation::Header", extract_token(&TokenLocation::Header("X-Token".into()), resp), Some("hdr-value")),
            ("TokenLocation::Regex", extract_token(&TokenLocation::Regex(r"tok=(\w+)".into()), resp), Some("zzz9")),
            ("TokenLocation::Header ignores missing and status line", extract_token(&TokenLocation::Header("HTTP/1.1".into()), resp), None),
        ];
        assert_table!(extract_cases, |idx, (name, got, expected)| {
            assert_eq!(got.as_deref(), expected, "extract case #{idx} ({name})");
        });
    }

    #[test]
    fn entropy_verification_matrix() {
        const HEX_16: &[u8] = b"0123456789abcdef";
        const ALPHANUM_62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        let static_tokens: Vec<String> = (0..150).map(|_| "AAAA".to_string()).collect();
        let binary_alt: Vec<String> = (0..200).map(|i| if i % 2 == 0 { "01010101".into() } else { "10101010".into() }).collect();
        let random_hex = prng_tokens(2000, 16, HEX_16, 0x2545F4914F6CDD1D);
        let random_base62 = prng_tokens(1000, 24, ALPHANUM_62, 0x517CC1B727220A95);
        // 256 distinct Unicode characters appearing uniformly -> 8.0 bits/char
        let uniform_256: Vec<String> = (0..256)
            .map(|b| std::iter::repeat(char::from_u32(0x0100 + b).unwrap()).take(8).collect())
            .collect();

        struct EntropyCase<'a> {
            name: &'a str,
            tokens: &'a [String],
            expected_min_entropy: f64,
            expected_max_entropy: f64,
            expected_theoretical_max: f64,
            expected_rating: &'a str,
        }

        let cases = [
            EntropyCase {
                name: "static repeated tokens have 0.0 bits entropy",
                tokens: &static_tokens,
                expected_min_entropy: 0.0,
                expected_max_entropy: 1e-9,
                expected_theoretical_max: 0.0,
                expected_rating: "Poor",
            },
            EntropyCase {
                name: "binary alternation has 1.0 bit entropy",
                tokens: &binary_alt,
                expected_min_entropy: 0.999,
                expected_max_entropy: 1.001,
                expected_theoretical_max: 1.0,
                expected_rating: "Excellent",
            },
            EntropyCase {
                name: "uniform 16-symbol hex approaches 4.0 bits",
                tokens: &random_hex,
                expected_min_entropy: 3.95,
                expected_max_entropy: 4.001,
                expected_theoretical_max: 4.0,
                expected_rating: "Excellent",
            },
            EntropyCase {
                name: "uniform 62-symbol Base62 approaches ~5.95 bits",
                tokens: &random_base62,
                expected_min_entropy: 5.90,
                expected_max_entropy: 5.96,
                expected_theoretical_max: 62.0_f64.log2(),
                expected_rating: "Excellent",
            },
            EntropyCase {
                name: "uniform 256-symbol distribution has exact 8.0 bits",
                tokens: &uniform_256,
                expected_min_entropy: 7.999,
                expected_max_entropy: 8.001,
                expected_theoretical_max: 8.0,
                expected_rating: "Excellent",
            },
        ];

        assert_table!(cases, |idx, case| {
            let a = analyze_tokens(case.tokens).unwrap();
            assert!(
                a.overall_entropy >= case.expected_min_entropy && a.overall_entropy <= case.expected_max_entropy,
                "case #{idx} ({}) entropy {} not in [{}..={}]",
                case.name,
                a.overall_entropy,
                case.expected_min_entropy,
                case.expected_max_entropy
            );
            assert!(
                (a.max_possible_entropy - case.expected_theoretical_max).abs() < 1e-6,
                "case #{idx} ({}) theoretical max {} != {}",
                case.name,
                a.max_possible_entropy,
                case.expected_theoretical_max
            );
            assert_eq!(
                entropy_rating(a.overall_entropy, a.max_possible_entropy),
                case.expected_rating,
                "case #{idx} ({}) rating",
                case.name
            );
        });

        // Summary report quality checks
        let short_99: Vec<String> = (0..99).map(|i| format!("{i:04x}")).collect();
        assert!(analyse(&short_99).starts_with("At least 100 tokens"));
        assert!(analyse(&static_tokens).contains("poor"));
        let counter_2000: Vec<String> = (0..2000).map(|i| format!("{i:08}")).collect();
        let counter_rep = analyse(&counter_2000);
        assert!(!counter_rep.contains("excellent") && !counter_rep.contains("good"));
        let random_5000 = prng_tokens(5000, 16, HEX_16, 0x2545F4914F6CDD1D);
        assert!(analyse(&random_5000).contains("excellent"));
    }

    #[test]
    fn fips_140_2_statistical_matrix() {
        // Generate deterministic 20,000-bit streams for FIPS 140-2 (monobit, poker, runs, long run)
        let mut x: u64 = 0x2545F4914F6CDD1D;
        let prng_bits: Vec<u8> = (0..20_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x & 1) as u8
            })
            .collect();
        let all_ones = vec![1u8; 20_000];
        let all_zeros = vec![0u8; 20_000];
        let alternating: Vec<u8> = (0..20_000).map(|i| (i % 2) as u8).collect();
        let mut long_run_bits = prng_bits.clone();
        for b in &mut long_run_bits[100..126] {
            *b = 1;
        }

        let bit_cases: [(&str, &[u8], (bool, bool, bool, bool)); 5] = [
            ("PRNG 20,000-bit stream passes all 4 FIPS tests", &prng_bits, (true, true, true, true)),
            ("all-1s stream fails Monobit, Poker, Runs, and Long Run", &all_ones, (false, false, false, false)),
            ("all-0s stream fails Monobit, Poker, Runs, and Long Run", &all_zeros, (false, false, false, false)),
            (
                "alternating 0101... passes Monobit & Long Run, fails Poker & Runs",
                &alternating,
                (true, false, false, true),
            ),
            (
                "PRNG stream with injected 26-bit run fails only Long Run",
                &long_run_bits,
                (true, true, true, false),
            ),
        ];

        assert_table!(bit_cases, |idx, (name, seq, expected)| {
            assert_eq!(fips(seq), expected, "FIPS bit case #{idx} ({name})");
        });

        // Token-level Monobit ratio table on decoded bytes
        let monobit_token_cases: [(&str, &str, f64, bool); 4] = [
            ("hex 'a5a5' (0xA5 = 10100101) has 0.50 monobit ratio and passes", "a5a5", 0.5, true),
            ("hex 'AAAA' (0xAA = 10101010) has 0.50 monobit ratio and passes", "AAAA", 0.5, true),
            ("hex 'ffff' (0xFF = 11111111) has 1.00 monobit ratio and fails", "ffff", 1.0, false),
            ("base64 'qg==' (0xAA = 10101010) has 0.50 monobit ratio and passes", "qg==", 0.5, true),
        ];
        assert_table!(monobit_token_cases, |idx, (name, tok, expected_ratio, expected_pass)| {
            let sample: Vec<String> = (0..40).map(|_| tok.to_string()).collect();
            let a = analyze_tokens(&sample).unwrap();
            assert!((a.monobit_ratio - expected_ratio).abs() < 1e-9, "case #{idx} ({name}) ratio {}", a.monobit_ratio);
            assert_eq!(a.fips_monobit_passed, expected_pass, "case #{idx} ({name}) monobit pass");
        });
    }

    #[test]
    fn per_position_entropy_matrix() {
        const HEX_16: &[u8] = b"0123456789abcdef";

        // 1. Static prefix "TOKEN_" + 8 random hex chars
        let random_suffixes = prng_tokens(1000, 8, HEX_16, 0x9E3779B97F4A7C15);
        let prefixed: Vec<String> = random_suffixes.iter().map(|s| format!("TOKEN_{s}")).collect();

        // 2. Sequential zero-padded 8-digit counters ("00000000".."00000999")
        let sequential: Vec<String> = (0..1000).map(|i| format!("{i:08}")).collect();

        // 3. Variable-length tokens ("TOKEN_" + 4..=8 random hex chars)
        let variable_len: Vec<String> = random_suffixes
            .iter()
            .enumerate()
            .map(|(i, s)| format!("TOKEN_{}", &s[..4 + (i % 5)]))
            .collect();

        struct PosCase<'a> {
            name: &'a str,
            tokens: &'a [String],
            expected_min_len: usize,
            expected_max_len: usize,
            zero_entropy_positions: &'a [usize],
            high_entropy_positions: &'a [usize],
            min_high_entropy: f64,
        }

        let cases = [
            PosCase {
                name: "static 'TOKEN_' prefix has 0 entropy at 0..6 and ~4 bits at 6..14",
                tokens: &prefixed,
                expected_min_len: 14,
                expected_max_len: 14,
                zero_entropy_positions: &[0, 1, 2, 3, 4, 5],
                high_entropy_positions: &[6, 7, 8, 9, 10, 11, 12, 13],
                min_high_entropy: 3.9,
            },
            PosCase {
                name: "sequential 8-digit counter has 0 entropy at 0..5 and ~3.32 bits at 5..8",
                tokens: &sequential,
                expected_min_len: 8,
                expected_max_len: 8,
                zero_entropy_positions: &[0, 1, 2, 3, 4],
                high_entropy_positions: &[5, 6, 7],
                min_high_entropy: 3.3,
            },
            PosCase {
                name: "variable-length tokens (10..=14 chars) track min/max length and per-position entropy",
                tokens: &variable_len,
                expected_min_len: 10,
                expected_max_len: 14,
                zero_entropy_positions: &[0, 1, 2, 3, 4, 5],
                high_entropy_positions: &[6, 7, 8, 9, 10, 11, 12, 13],
                min_high_entropy: 3.8,
            },
        ];

        assert_table!(cases, |idx, case| {
            let a = analyze_tokens(case.tokens).unwrap();
            assert_eq!(
                (a.min_len, a.max_len),
                (case.expected_min_len, case.expected_max_len),
                "case #{idx} ({}) min/max len",
                case.name
            );
            assert_eq!(a.per_char_entropy.len(), case.expected_max_len, "case #{idx} ({}) position count", case.name);
            for &pos in case.zero_entropy_positions {
                assert!(
                    a.per_char_entropy[pos] < 1e-9,
                    "case #{idx} ({}) pos {pos} expected 0 entropy, got {}",
                    case.name,
                    a.per_char_entropy[pos]
                );
            }
            for &pos in case.high_entropy_positions {
                assert!(
                    a.per_char_entropy[pos] >= case.min_high_entropy,
                    "case #{idx} ({}) pos {pos} expected >= {}, got {}",
                    case.name,
                    case.min_high_entropy,
                    a.per_char_entropy[pos]
                );
            }
        });
    }
}
