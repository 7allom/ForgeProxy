//! Compiled regular expressions, cached by pattern: scope rules and match-and-replace rules
//! are tested on every proxied request and every UI frame, and compiling a pattern each time
//! costs far more than the match. A `Regex` clone is cheap (its program is shared).

use regex::Regex;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Patterns kept before the cache is emptied (rules are edited one keystroke at a time, so
/// every half-typed pattern lands here too).
const MAX_PATTERNS: usize = 512;

/// The compiled `pattern`, matched case sensitively, or None if it isn't a valid regular
/// expression (also cached).
pub fn get(pattern: &str) -> Option<Regex> {
    get_with(pattern, false)
}

/// The compiled `pattern`, ignoring case when asked. The two forms of a pattern are cached
/// apart, so a rule switching between them costs one compile, not one per request.
pub fn get_with(pattern: &str, case_insensitive: bool) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<(String, bool), Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    let key = (pattern.to_string(), case_insensitive);
    if let Some(re) = map.get(&key) {
        return re.clone();
    }
    if map.len() >= MAX_PATTERNS {
        map.clear();
    }
    let re = regex::RegexBuilder::new(pattern).case_insensitive(case_insensitive).build().ok();
    map.insert(key, re.clone());
    re
}

#[cfg(test)]
mod tests {
    #[test]
    fn caches_valid_and_invalid_patterns() {
        let a = super::get(r"^ab+c$").unwrap();
        assert!(a.is_match("abbc"));
        assert!(super::get(r"^ab+c$").unwrap().is_match("abc"));
        assert!(super::get("(unclosed").is_none());
        assert!(super::get("(unclosed").is_none());
        for i in 0..(super::MAX_PATTERNS + 5) {
            assert!(super::get(&format!("x{i}")).is_some(), "stays usable past the cap");
        }
    }
}
