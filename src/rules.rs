//! Rules and numbers taken from the original (see MECHANICS.md for sources).

/// Proxy listener: loopback_only, port 8080.
pub const PROXY_HOST: &str = "127.0.0.1";
pub const PROXY_PORT: u16 = 8080;
/// enable_proxy_interception_at_startup = never.
pub const INTERCEPT_AT_STARTUP: bool = false;
/// Request intercept rule: file extension does not match these.
pub const SKIP_EXTENSIONS: [&str; 11] =
    ["gif", "jpg", "png", "css", "js", "ico", "svg", "eot", "woff", "woff2", "ttf"];

/// Repeater: follow_redirections = never.
pub const REPEATER_FOLLOW_REDIRECTS: bool = false;

/// Default resource pool.
pub const POOL_CONCURRENT_LIMIT: usize = 10;

/// Scanner crawl limits (CrawlDefaults.json crawler.*).
pub const CRAWL_MAX_LINK_DEPTH: usize = 4;
pub const CRAWL_MAX_UNIQUE_LOCATIONS: usize = 1500;
pub const CRAWL_MAX_TIME_MIN: u64 = 150;
/// Audit (AuditDefaults.json scanner.audit_optimization): the scanner follows redirects.
pub const AUDIT_FOLLOW_REDIRECTS: bool = true;



/// Organizer default display filter (ProjectDefaults.json organiser.display_filter.by_file_extension.hide_items).
pub const ORGANIZER_HIDE_EXTENSIONS: [&str; 10] =
    ["js", "gif", "jpg", "png", "ico", "css", "woff", "woff2", "ttf", "svg"];

/// Sequencer live capture.
pub const SEQUENCER_THREADS: usize = 5;

/// How many recorded requests the traffic store keeps. Once it is full the oldest go first,
/// so a capture left running for hours costs a bounded amount of memory instead of growing
/// until there is none left.
pub const MAX_RECORDED_REQUESTS: usize = 50_000;

/// `SKIP_EXTENSIONS` as the editable list a new project starts with.
pub fn default_skip_extensions() -> Vec<String> {
    SKIP_EXTENSIONS.iter().map(|s| s.to_string()).collect()
}

/// Would the request rule intercept this path? Not when its file extension is in `skip`
/// (compared without case; a leading dot in the list is ignored).
pub fn would_intercept(path: &str, skip: &[String]) -> bool {
    let file = path.split(['?', '#']).next().unwrap_or("");
    let last = file.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((_, ext)) => !skip.iter().any(|s| s.trim().trim_start_matches('.').eq_ignore_ascii_case(ext)),
        None => true,
    }
}

/// Composable traffic rule conditions for evaluating HTTP requests and responses.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RuleCondition {
    /// Path passes extension skip list (`would_intercept`).
    ExtensionNotSkipped(Vec<String>),
    /// URL starts with or contains `pattern` (or regex when `is_regex == true`).
    UrlMatches { pattern: String, is_regex: bool },
    /// HTTP method matches `method` (case-insensitive).
    MethodEquals(String),
    /// Response HTTP status code falls in `min..=max` (e.g. `200..=299` for 2xx, `400..=499` for 4xx).
    StatusInRange { min: u16, max: u16 },
    /// Request or response contains header `name` (and optional substring `value`).
    HeaderPresent { name: String, value: Option<String>, in_response: bool },
}

/// Boolean logic combinators for grouping [`RuleCondition`]s (AND, OR, NOT).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RuleExpr {
    Condition(RuleCondition),
    Not(Box<RuleExpr>),
    And(Vec<RuleExpr>),
    Or(Vec<RuleExpr>),
}

#[allow(dead_code)]
impl RuleCondition {
    pub fn matches(&self, entry: &crate::http::HttpEntry) -> bool {
        match self {
            RuleCondition::ExtensionNotSkipped(skip) => would_intercept(&entry.path, skip),
            RuleCondition::UrlMatches { pattern, is_regex } => {
                if *is_regex {
                    crate::regex_cache::get(pattern).is_some_and(|re| re.is_match(&entry.url))
                } else {
                    entry.url.contains(pattern.as_str())
                }
            }
            RuleCondition::MethodEquals(m) => entry.method.eq_ignore_ascii_case(m.trim()),
            RuleCondition::StatusInRange { min, max } => {
                entry.status_code().is_some_and(|code| code >= *min && code <= *max)
            }
            RuleCondition::HeaderPresent { name, value, in_response } => {
                let raw = if *in_response { &entry.response } else { &entry.request };
                let head = raw.split("\r\n\r\n").next().unwrap_or(raw).split("\n\n").next().unwrap_or(raw);
                head.lines().skip(1).any(|line| {
                    let Some((k, v)) = line.split_once(':') else { return false };
                    if !k.trim().eq_ignore_ascii_case(name.trim()) {
                        return false;
                    }
                    match value {
                        Some(expected) => v.trim().to_ascii_lowercase().contains(&expected.to_ascii_lowercase()),
                        None => true,
                    }
                })
            }
        }
    }
}

#[allow(dead_code)]
impl RuleExpr {
    pub fn evaluate(&self, entry: &crate::http::HttpEntry) -> bool {
        match self {
            RuleExpr::Condition(c) => c.matches(entry),
            RuleExpr::Not(inner) => !inner.evaluate(entry),
            RuleExpr::And(list) => list.iter().all(|e| e.evaluate(entry)),
            RuleExpr::Or(list) => list.iter().any(|e| e.evaluate(entry)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_table, HttpFixture};

    #[test]
    fn rule_match_matrix() {
        let default_skip = default_skip_extensions();
        let custom_skip = vec![".json".to_string(), "js".to_string()];

        let api_post = HttpFixture::post("api.example.com", "/v1/users?active=1", "{\"name\":\"alice\"}")
            .with_tls(true)
            .with_header("Authorization", "Bearer secret-jwt")
            .with_response("201 Created", "{\"id\":10}")
            .into_history_entry(1, "Proxy");

        let static_png = HttpFixture::get("cdn.example.com", "/assets/logo.PNG?v=1")
            .with_tls(true)
            .with_response("200 OK", "png-bytes")
            .into_history_entry(2, "Proxy");

        let json_404 = HttpFixture::get("api.example.com", "/a/data.json")
            .with_tls(true)
            .with_response("404 Not Found", "{\"error\":\"missing\"}")
            .into_history_entry(3, "Proxy");

        let cases: Vec<(&str, RuleCondition, &crate::http::HttpEntry, bool)> = vec![
            // Extension skip rules (would_intercept)
            (
                "default skip list ignores uppercase .PNG with query string",
                RuleCondition::ExtensionNotSkipped(default_skip.clone()),
                &static_png,
                false,
            ),
            (
                "default skip list intercepts extensionless /v1/users path",
                RuleCondition::ExtensionNotSkipped(default_skip.clone()),
                &api_post,
                true,
            ),
            (
                "default skip list intercepts .json path",
                RuleCondition::ExtensionNotSkipped(default_skip),
                &json_404,
                true,
            ),
            (
                "custom skip list with leading dot (.json) skips /a/data.json",
                RuleCondition::ExtensionNotSkipped(custom_skip.clone()),
                &json_404,
                false,
            ),
            (
                "custom skip list without .png intercepts /assets/logo.PNG",
                RuleCondition::ExtensionNotSkipped(custom_skip),
                &static_png,
                true,
            ),
            (
                "empty skip list intercepts every file extension",
                RuleCondition::ExtensionNotSkipped(vec![]),
                &static_png,
                true,
            ),
            // URL substring & regex matches
            (
                "URL substring match on /v1/users",
                RuleCondition::UrlMatches { pattern: "api.example.com/v1/users".into(), is_regex: false },
                &api_post,
                true,
            ),
            (
                "URL regex match on ^https://api\\.example\\.com/v\\d+/",
                RuleCondition::UrlMatches { pattern: r"^https://api\.example\.com/v\d+/".into(), is_regex: true },
                &api_post,
                true,
            ),
            (
                "URL regex mismatch on cdn host",
                RuleCondition::UrlMatches { pattern: r"^https://api\.example\.com/".into(), is_regex: true },
                &static_png,
                false,
            ),
            // HTTP method matches
            (
                "MethodEquals POST matches POST request (case-insensitive)",
                RuleCondition::MethodEquals("post".into()),
                &api_post,
                true,
            ),
            (
                "MethodEquals GET does not match POST request",
                RuleCondition::MethodEquals("GET".into()),
                &api_post,
                false,
            ),
            // Status code ranges
            (
                "StatusInRange 2xx (200..=299) matches 201 Created",
                RuleCondition::StatusInRange { min: 200, max: 299 },
                &api_post,
                true,
            ),
            (
                "StatusInRange 4xx (400..=499) matches 404 Not Found",
                RuleCondition::StatusInRange { min: 400, max: 499 },
                &json_404,
                true,
            ),
            (
                "StatusInRange 2xx does not match 404 Not Found",
                RuleCondition::StatusInRange { min: 200, max: 299 },
                &json_404,
                false,
            ),
            // Header presence and value matching
            (
                "HeaderPresent matches Authorization Bearer header in request",
                RuleCondition::HeaderPresent {
                    name: "authorization".into(),
                    value: Some("bearer".into()),
                    in_response: false,
                },
                &api_post,
                true,
            ),
            (
                "HeaderPresent returns false when header is absent",
                RuleCondition::HeaderPresent {
                    name: "X-Missing-Header".into(),
                    value: None,
                    in_response: false,
                },
                &api_post,
                false,
            ),
            (
                "HeaderPresent matches Content-Type in response",
                RuleCondition::HeaderPresent {
                    name: "Content-Type".into(),
                    value: Some("application/json".into()),
                    in_response: true,
                },
                &api_post,
                true,
            ),
        ];

        assert_table!(cases, |idx, (name, cond, entry, expected)| {
            assert_eq!(cond.matches(entry), expected, "case #{idx} ({name})");
        });
    }

    #[test]
    fn logic_operators_matrix() {
        let entry = HttpFixture::post("api.example.com", "/v1/orders", "{\"item\":1}")
            .with_tls(true)
            .with_header("X-Api-Key", "k123")
            .with_response("200 OK", "{\"ok\":true}")
            .into_history_entry(1, "Proxy");

        let is_post = RuleExpr::Condition(RuleCondition::MethodEquals("POST".into()));
        let is_get = RuleExpr::Condition(RuleCondition::MethodEquals("GET".into()));
        let is_2xx = RuleExpr::Condition(RuleCondition::StatusInRange { min: 200, max: 299 });
        let is_5xx = RuleExpr::Condition(RuleCondition::StatusInRange { min: 500, max: 599 });
        let has_api_key = RuleExpr::Condition(RuleCondition::HeaderPresent {
            name: "X-Api-Key".into(),
            value: None,
            in_response: false,
        });

        let cases: Vec<(&str, RuleExpr, bool)> = vec![
            (
                "AND group: all true -> true",
                RuleExpr::And(vec![is_post.clone(), is_2xx.clone(), has_api_key.clone()]),
                true,
            ),
            (
                "AND group: one false -> false",
                RuleExpr::And(vec![is_post.clone(), is_5xx.clone(), has_api_key.clone()]),
                false,
            ),
            (
                "OR group: at least one true -> true",
                RuleExpr::Or(vec![is_get.clone(), is_5xx.clone(), is_2xx.clone()]),
                true,
            ),
            (
                "OR group: all false -> false",
                RuleExpr::Or(vec![is_get.clone(), is_5xx.clone()]),
                false,
            ),
            (
                "NOT inversion: NOT(false) -> true",
                RuleExpr::Not(Box::new(is_get.clone())),
                true,
            ),
            (
                "NOT inversion: NOT(true) -> false",
                RuleExpr::Not(Box::new(is_post.clone())),
                false,
            ),
            (
                "nested (POST AND 2xx) AND NOT(5xx) -> true",
                RuleExpr::And(vec![
                    RuleExpr::Or(vec![is_get, is_post]),
                    is_2xx,
                    RuleExpr::Not(Box::new(is_5xx)),
                ]),
                true,
            ),
        ];

        assert_table!(cases, |idx, (name, expr, expected)| {
            assert_eq!(expr.evaluate(&entry), expected, "case #{idx} ({name})");
        });
    }
}
