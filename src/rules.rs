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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interception_follows_the_skip_list() {
        let skip = default_skip_extensions();
        assert!(!would_intercept("/a/logo.PNG?v=1", &skip));
        assert!(would_intercept("/api/users", &skip));
        assert!(would_intercept("/a/data.json", &skip));
        let custom = vec![".json".to_string(), "js".to_string()];
        assert!(!would_intercept("/a/data.json", &custom));
        assert!(would_intercept("/a/logo.png", &custom), "png no longer skipped");
        assert!(would_intercept("/a/app.js", &[]), "empty list: everything is held");
    }
}
