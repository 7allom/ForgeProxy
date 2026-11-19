//! The scanner's check registry: every weakness check is a small, testable unit kept apart
//! from the engine that drives it (`crate::scan`). Passive checks read one captured
//! request/response pair and make no traffic of their own; active checks (added on top of the
//! insertion-point model) probe a target and are gated by scan [`Intensity`].

pub mod passive;
pub mod active;

use crate::scan::Finding;

/// How hard a scan probes. Passive checks always run; each active check names the lowest
/// intensity at which its extra traffic is worth sending, and the engine skips anything above
/// the level the operator chose. Ordered least to most, so `>=` comparisons gate cleanly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Intensity {
    /// No active request at all beyond the crawl itself.
    PassiveOnly,
    Light,
    Standard,
    Thorough,
}

impl Default for Intensity {
    /// A fresh scan audits at the balanced level: existing parameters are fuzzed, but the
    /// slower timing-based probes are held back for `Thorough`.
    fn default() -> Self {
        Intensity::Standard
    }
}

impl Intensity {
    pub fn label(&self) -> &'static str {
        match self {
            Intensity::PassiveOnly => "Passive only",
            Intensity::Light => "Light",
            Intensity::Standard => "Standard",
            Intensity::Thorough => "Thorough",
        }
    }

    /// An intensity by the word a command line or settings file carries, however it is cased.
    /// Anything unfamiliar settles on the balanced default rather than refusing the scan.
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "passive" | "passiveonly" | "passive only" => Intensity::PassiveOnly,
            "light" => Intensity::Light,
            "thorough" => Intensity::Thorough,
            _ => Intensity::Standard,
        }
    }
}

/// One captured request/response pair, handed to every passive check. The body is lower-cased
/// once here rather than in each check.
pub struct PassiveCtx<'a> {
    pub host: &'a str,
    pub path: &'a str,
    /// The request was made over HTTPS.
    pub secure: bool,
    pub headers: &'a str,
    pub body: &'a str,
    pub lbody: String,
}

impl<'a> PassiveCtx<'a> {
    pub fn new(host: &'a str, path: &'a str, secure: bool, headers: &'a str, body: &'a str) -> Self {
        Self { host, path, secure, headers, body, lbody: body.to_ascii_lowercase() }
    }
}

/// A passive check: a captured exchange in, zero or more findings out, no network traffic.
pub type PassiveCheck = fn(&PassiveCtx) -> Vec<Finding>;

/// Every passive check, in the order the scanner runs them, each paired with a stable id used
/// by tests and logs.
pub fn passive_registry() -> &'static [(&'static str, PassiveCheck)] {
    passive::REGISTRY
}

/// True when a header line whose name is `name` (any case) is present in the block.
pub(crate) fn header_present(headers: &str, name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    headers.lines().any(|l| l.to_ascii_lowercase().trim_start().starts_with(&lname))
}

/// Every header line whose name is `name` (any case), kept in order.
pub(crate) fn header_lines<'a>(headers: &'a str, name: &str) -> Vec<&'a str> {
    let lname = name.to_ascii_lowercase();
    headers
        .lines()
        .filter(|l| l.to_ascii_lowercase().trim_start().starts_with(&lname))
        .collect()
}

/// The value of the first header named `name` (any case), trimmed, or `None` when absent.
pub(crate) fn header_value(headers: &str, name: &str) -> Option<String> {
    let lname = name.to_ascii_lowercase();
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(&lname) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// Whether a string contains a `<digits>.<digits>` version-number run, e.g. in `Server: x/1.4`.
pub(crate) fn has_version_number(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'.' && i > 0 && i + 1 < b.len() && b[i - 1].is_ascii_digit() && b[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}
