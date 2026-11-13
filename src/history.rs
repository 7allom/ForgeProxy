//! HTTP history filtering and sorting (Proxy > HTTP history, Logger, the site map table).
//! Both work on the rows about to be drawn; the recorded history itself is never changed
//! or reordered.

use crate::http::HttpEntry;
use std::sync::Arc;

/// Columns the history table can be sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistorySortColumn {
    Id,
    Time,
    Tool,
    Method,
    Host,
    Path,
    Status,
    Length,
    Mime,
}

/// The filter ribbon's settings, and the table's sort order.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryFilter {
    pub search_term: String,
    /// `search_term` is a regular expression (case-insensitive) rather than plain text.
    pub is_regex: bool,
    pub only_in_scope: bool,
    /// Hide requests for files whose extension is in Settings > Proxy > Skipped file
    /// extensions (images, scripts, style sheets, fonts...).
    pub hide_static_assets: bool,
    /// Hide requests that got no HTTP response (connection failed, or still waiting).
    pub hide_no_response: bool,
    pub show_2xx: bool,
    pub show_3xx: bool,
    pub show_4xx: bool,
    pub show_5xx: bool,
    pub sort_column: Option<HistorySortColumn>,
    pub sort_ascending: bool,
}

impl Default for HistoryFilter {
    fn default() -> Self {
        HistoryFilter {
            search_term: String::new(),
            is_regex: false,
            only_in_scope: false,
            hide_static_assets: false,
            hide_no_response: false,
            show_2xx: true,
            show_3xx: true,
            show_4xx: true,
            show_5xx: true,
            sort_column: Some(HistorySortColumn::Id),
            sort_ascending: true,
        }
    }
}

/// The response's status class (2 for "200 OK" and for HTTPS tunnels), or None when no
/// response came back: a connection or transport failure, or still pending.
pub fn status_class(e: &HttpEntry) -> Option<u8> {
    e.status_code().map(|c| (c / 100) as u8)
}

/// A request for a static file: its path's extension is in `skip_extensions`.
pub fn is_static_asset(e: &HttpEntry, skip_extensions: &[String]) -> bool {
    !crate::rules::would_intercept(&e.path, skip_extensions)
}

impl HistoryFilter {
    /// Everything shows (sorting aside).
    pub fn is_default_filter(&self) -> bool {
        let d = HistoryFilter::default();
        HistoryFilter { sort_column: d.sort_column, sort_ascending: d.sort_ascending, ..self.clone() } == d
    }

    /// Back to showing everything (the sort order stays).
    pub fn reset_filter(&mut self) {
        *self = HistoryFilter { sort_column: self.sort_column, sort_ascending: self.sort_ascending, ..HistoryFilter::default() };
    }

    /// The search as a regex, when it is one and it compiles (case-insensitive).
    fn search_regex(&self) -> Option<regex::Regex> {
        crate::regex_cache::get(&format!("(?i){}", self.search_term.trim()))
    }

    /// Search is a regex that doesn't compile: it's ignored until fixed.
    pub fn regex_error(&self) -> bool {
        self.is_regex && !self.search_term.trim().is_empty() && self.search_regex().is_none()
    }

    /// Does the row pass every filter?
    pub fn matches(&self, e: &HttpEntry, scope: &crate::scope::TargetScope, skip_extensions: &[String]) -> bool {
        if self.only_in_scope && !scope.is_in_scope(&crate::actions::entry_url(e)) {
            return false;
        }
        if self.hide_static_assets && is_static_asset(e, skip_extensions) {
            return false;
        }
        match status_class(e) {
            None if self.hide_no_response => return false,
            Some(2) if !self.show_2xx => return false,
            Some(3) if !self.show_3xx => return false,
            Some(4) if !self.show_4xx => return false,
            Some(5) if !self.show_5xx => return false,
            _ => {}
        }
        self.search_matches(e)
    }

    /// The search term against method, host, path, status and MIME type: any field
    /// containing it (ignoring case), or matching it as a regex. An empty term, or a regex
    /// that doesn't compile, matches everything.
    fn search_matches(&self, e: &HttpEntry) -> bool {
        let q = self.search_term.trim();
        if q.is_empty() {
            return true;
        }
        let fields = [e.method.as_str(), e.host.as_str(), e.path.as_str(), e.status.as_str(), e.mime.as_str()];
        if self.is_regex {
            return match self.search_regex() {
                Some(re) => fields.iter().any(|f| re.is_match(f)),
                None => true,
            };
        }
        let q = q.to_lowercase();
        fields.iter().any(|f| f.to_lowercase().contains(&q))
    }

    /// Click on a column header: the same column flips the order, another one sorts by it
    /// ascending.
    pub fn click_column(&mut self, col: HistorySortColumn) {
        if self.sort_column == Some(col) {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = Some(col);
            self.sort_ascending = true;
        }
    }

    /// Sort rows for display (stable; ties keep capture order).
    pub fn sort(&self, rows: &mut [Arc<HttpEntry>]) {
        let Some(col) = self.sort_column else { return };
        sort_rows(rows, col, self.sort_ascending);
    }
}

/// Sort by `col`, then by id (so equal values keep a fixed order). Rows without a status
/// sort after every status code, whichever way the column is sorted.
pub fn sort_rows(rows: &mut [Arc<HttpEntry>], col: HistorySortColumn, ascending: bool) {
    use std::cmp::Ordering;
    let text = |a: &str, b: &str| a.to_lowercase().cmp(&b.to_lowercase());
    rows.sort_by(|a, b| {
        let primary = match col {
            HistorySortColumn::Id => a.id.cmp(&b.id),
            HistorySortColumn::Time => a.time.cmp(&b.time),
            HistorySortColumn::Tool => text(&a.tool, &b.tool),
            HistorySortColumn::Method => text(&a.method, &b.method),
            HistorySortColumn::Host => text(&a.host, &b.host),
            HistorySortColumn::Path => text(&a.path, &b.path),
            HistorySortColumn::Length => a.length.cmp(&b.length),
            HistorySortColumn::Mime => text(&a.mime, &b.mime),
            HistorySortColumn::Status => match (a.status_code(), b.status_code()) {
                (Some(x), Some(y)) => x.cmp(&y),
                // no response: always last
                (Some(_), None) => return Ordering::Less,
                (None, Some(_)) => return Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
        };
        let primary = if ascending { primary } else { primary.reverse() };
        primary.then(a.id.cmp(&b.id))
    });
}

/// "14:05:09" (UTC) for the Time column; empty for entries recorded before times were kept.
pub fn time_of_day(ms: u64) -> String {
    if ms == 0 {
        return String::new();
    }
    let full = crate::codec::format_unix_utc((ms / 1000) as i64);
    full.split(' ').nth(1).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{ScopeRule, TargetScope};
    use crate::test_utils::{assert_table, HttpFixture};

    fn entry(id: usize, url: &str, status: &str) -> HttpEntry {
        let is_tls = url.starts_with("https://");
        let (host, path) = crate::http::split_url(url);
        let mut e = HttpFixture::get(host, path)
            .with_tls(is_tls)
            .with_response(status, "")
            .into_history_entry(id, "Proxy");
        e.url = url.into();
        e.mime = "HTML".into();
        e
    }

    fn skip() -> Vec<String> {
        crate::rules::default_skip_extensions()
    }

    fn rows() -> Vec<Arc<HttpEntry>> {
        // id, status, time, length
        [
            (1, "404 Not Found", 3000, 50),
            (2, "200 OK", 1000, 900),
            (3, crate::http::CONNECTION_FAILED, 2000, 0),
            (4, "302 Found", 1000, 900),
            (5, "500 Error", 4000, 10),
        ]
        .into_iter()
        .map(|(id, status, time, length)| {
            let mut e = entry(id, "http://a.test/", status);
            e.time = time;
            e.length = length;
            Arc::new(e)
        })
        .collect()
    }

    fn ids(rows: &[Arc<HttpEntry>]) -> Vec<usize> {
        rows.iter().map(|e| e.id).collect()
    }

    #[test]
    fn history_log_operations_matrix() {
        // 1. Entry ID sequencing & FIFO / ring buffer trimming invariants, as the store does
        // them: ids count up for the life of the project, whatever has been dropped since
        let store = crate::http::Recorder::new(5);
        let seq_ids: Vec<usize> = (0..5)
            .map(|_| store.record(|id| entry(id, "http://a.test/", "200 OK")).expect("recorded"))
            .collect();
        assert_eq!(seq_ids, vec![1, 2, 3, 4, 5]);

        struct BufferOpCase {
            name: &'static str,
            capacity: usize,
            insert_count: usize,
            clear_after: bool,
            expected_ids: Vec<usize>,
        }

        let buffer_cases = [
            BufferOpCase {
                name: "within capacity retains all entries in order",
                capacity: 5,
                insert_count: 3,
                clear_after: false,
                expected_ids: vec![1, 2, 3],
            },
            BufferOpCase {
                name: "FIFO eviction trims oldest entries when exceeding ring limit",
                capacity: 3,
                insert_count: 5,
                clear_after: false,
                expected_ids: vec![3, 4, 5],
            },
            BufferOpCase {
                name: "clear reset empties history log completely",
                capacity: 5,
                insert_count: 4,
                clear_after: true,
                expected_ids: vec![],
            },
        ];

        assert_table!(buffer_cases, |case| {
            let store = crate::http::Recorder::new(case.capacity);
            for _ in 0..case.insert_count {
                store.record(|id| entry(id, "http://a.test/", "200 OK"));
            }
            let mut log = store.history.lock().unwrap().clone();
            if case.clear_after {
                store.history.lock().unwrap().clear();
                log = store.history.lock().unwrap().clone();
            }
            assert_eq!(ids(&log), case.expected_ids, "case '{}'", case.name);
        });

        // and nothing is recorded at all, nor any id spent, while capture is paused
        let store = crate::http::Recorder::new(5);
        assert_eq!(store.record(|id| entry(id, "http://a.test/", "200 OK")), Some(1));
        store.paused.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(store.record(|id| entry(id, "http://a.test/", "200 OK")), None, "paused: not recorded");
        store.paused.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(store.record(|id| entry(id, "http://a.test/", "200 OK")), Some(2), "and no id was spent while paused");
        assert_eq!(ids(&store.history.lock().unwrap()), vec![1, 2]);

        // 2. Filter reset preserves active sort column and sort direction
        let mut f = HistoryFilter {
            search_term: "x".into(),
            only_in_scope: true,
            show_2xx: false,
            sort_column: Some(HistorySortColumn::Length),
            sort_ascending: false,
            ..Default::default()
        };
        assert!(!f.is_default_filter());
        f.reset_filter();
        assert!(f.is_default_filter());
        assert_eq!((f.sort_column, f.sort_ascending), (Some(HistorySortColumn::Length), false));

        // 3. Column click state machine transitions
        let mut click_filter = HistoryFilter::default();
        assert_eq!((click_filter.sort_column, click_filter.sort_ascending), (Some(HistorySortColumn::Id), true));
        click_filter.click_column(HistorySortColumn::Id);
        assert!(!click_filter.sort_ascending, "same column: reversed");
        click_filter.click_column(HistorySortColumn::Length);
        assert_eq!(
            (click_filter.sort_column, click_filter.sort_ascending),
            (Some(HistorySortColumn::Length), true),
            "a new column starts ascending"
        );

        // 4. Sorting matrix across columns and directions
        struct SortCase {
            name: &'static str,
            column: Option<HistorySortColumn>,
            ascending: bool,
            expected_ids: [usize; 5],
        }

        let sort_cases = [
            SortCase {
                name: "sort by status ascending places CONNECTION_FAILED last",
                column: Some(HistorySortColumn::Status),
                ascending: true,
                expected_ids: [2, 4, 1, 5, 3],
            },
            SortCase {
                name: "sort by status descending still places CONNECTION_FAILED last",
                column: Some(HistorySortColumn::Status),
                ascending: false,
                expected_ids: [5, 1, 4, 2, 3],
            },
            SortCase {
                name: "sort by time ascending preserves id order on ties",
                column: Some(HistorySortColumn::Time),
                ascending: true,
                expected_ids: [2, 4, 3, 1, 5],
            },
            SortCase {
                name: "sort by time descending preserves id order on ties",
                column: Some(HistorySortColumn::Time),
                ascending: false,
                expected_ids: [5, 1, 3, 2, 4],
            },
            SortCase {
                name: "sort by length ascending",
                column: Some(HistorySortColumn::Length),
                ascending: true,
                expected_ids: [3, 5, 1, 2, 4],
            },
            SortCase {
                name: "sort by length descending",
                column: Some(HistorySortColumn::Length),
                ascending: false,
                expected_ids: [2, 4, 1, 5, 3],
            },
            SortCase {
                name: "no sort column leaves order untouched",
                column: None,
                ascending: true,
                expected_ids: [1, 2, 3, 4, 5],
            },
        ];

        assert_table!(sort_cases, |case| {
            let history: Vec<Arc<HttpEntry>> = rows();
            let mut view: Vec<Arc<HttpEntry>> = history.clone();
            HistoryFilter {
                sort_column: case.column,
                sort_ascending: case.ascending,
                ..Default::default()
            }
            .sort(&mut view);
            assert_eq!(ids(&view), case.expected_ids, "case '{}'", case.name);
            assert_eq!(ids(&history), [1, 2, 3, 4, 5], "underlying history slice must stay untouched");
        });

        // 5. Time formatting matrix
        let time_cases = [
            ("zero timestamp renders empty string", 0u64, ""),
            ("epoch ms renders UTC time of day", 1_700_000_000_123u64, "22:13:20"),
        ];
        assert_table!(time_cases, |(name, ms, expected)| {
            assert_eq!(time_of_day(ms), expected, "{name}");
        });
    }

    #[test]
    fn filter_and_search_matrix() {
        let default_scope = TargetScope::default();
        let mut shop_scope = TargetScope::default();
        shop_scope.include.push(ScopeRule::new("https://shop.test/"));

        let default_skip = skip();
        let custom_json_skip = vec!["json".to_string()];

        let mut post_api_entry = HttpFixture::post("API.test", "/v1/users?id=7", "id=7")
            .with_tls(true)
            .with_response("201 Created", "created")
            .into_history_entry(1, "Proxy");
        post_api_entry.mime = "HTML".into();
        post_api_entry.length = 512;

        struct FilterCase {
            name: &'static str,
            filter: HistoryFilter,
            entry: HttpEntry,
            scope: TargetScope,
            skip_ext: Vec<String>,
            expected: bool,
        }

        let cases = [
            // Scope filtering
            FilterCase {
                name: "scope off allows in-scope entry",
                filter: HistoryFilter::default(),
                entry: entry(1, "https://shop.test/cart", "200 OK"),
                scope: shop_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "scope off allows out-of-scope entry",
                filter: HistoryFilter::default(),
                entry: entry(2, "https://ads.test/p", "200 OK"),
                scope: shop_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "only_in_scope allows in-scope entry",
                filter: HistoryFilter { only_in_scope: true, ..Default::default() },
                entry: entry(1, "https://shop.test/cart", "200 OK"),
                scope: shop_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "only_in_scope rejects out-of-scope entry",
                filter: HistoryFilter { only_in_scope: true, ..Default::default() },
                entry: entry(2, "https://ads.test/p", "200 OK"),
                scope: shop_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            // Static asset filtering
            FilterCase {
                name: "hide_static_assets skips uppercase PNG with query string",
                filter: HistoryFilter { hide_static_assets: true, ..Default::default() },
                entry: entry(1, "https://a.test/logo.PNG?v=2", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "hide_static_assets skips .js asset",
                filter: HistoryFilter { hide_static_assets: true, ..Default::default() },
                entry: entry(2, "https://a.test/app.js", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "hide_static_assets keeps extensionless API route",
                filter: HistoryFilter { hide_static_assets: true, ..Default::default() },
                entry: entry(3, "https://a.test/api/users", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "hide_static_assets keeps .json under default skip list",
                filter: HistoryFilter { hide_static_assets: true, ..Default::default() },
                entry: entry(4, "https://a.test/data.json", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "hide_static_assets skips .json when custom skip list includes json",
                filter: HistoryFilter { hide_static_assets: true, ..Default::default() },
                entry: entry(4, "https://a.test/data.json", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: custom_json_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "hide_static_assets keeps .png when custom skip list only has json",
                filter: HistoryFilter { hide_static_assets: true, ..Default::default() },
                entry: entry(1, "https://a.test/logo.png", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: custom_json_skip.clone(),
                expected: true,
            },
            // Status code buckets
            FilterCase {
                name: "status bucket filter allows 200 OK when 2xx enabled",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", "200 OK"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "status bucket filter allows 204 No Content when 2xx enabled",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", "204 No Content"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "status bucket filter hides 302 Found when 3xx disabled",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", "302 Found"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "status bucket filter allows 404 Not Found when 4xx enabled",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", "404 Not Found"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "status bucket filter hides 503 Unavailable when 5xx disabled",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", "503 Unavailable"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "status bucket filter allows 200 (Tunnel) when 2xx enabled",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", "200 (Tunnel)"),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "status bucket filter allows CONNECTION_FAILED when hide_no_response is false",
                filter: HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() },
                entry: entry(1, "http://a.test/", crate::http::CONNECTION_FAILED),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "hide_no_response hides CONNECTION_FAILED",
                filter: HistoryFilter { hide_no_response: true, ..Default::default() },
                entry: entry(1, "http://a.test/", crate::http::CONNECTION_FAILED),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            // Substring & Regex search across host, method, path, status, MIME
            FilterCase {
                name: "substring search matches host case-insensitively",
                filter: HistoryFilter { search_term: "api.test".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "substring search matches method case-insensitively",
                filter: HistoryFilter { search_term: "post".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "substring search matches path case-insensitively",
                filter: HistoryFilter { search_term: "/V1/US".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "substring search matches status code",
                filter: HistoryFilter { search_term: "201".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "substring search matches MIME type case-insensitively",
                filter: HistoryFilter { search_term: "html".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "substring search trims surrounding whitespace",
                filter: HistoryFilter { search_term: "  users  ".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "substring search rejects unmatched method",
                filter: HistoryFilter { search_term: "delete".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "substring search treats regex brackets literally",
                filter: HistoryFilter { search_term: "v[0-9]".into(), is_regex: false, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "regex search matches path digits",
                filter: HistoryFilter { search_term: r"/v\d+/".into(), is_regex: true, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "regex search matches whole method field case-insensitively",
                filter: HistoryFilter { search_term: "^post$".into(), is_regex: true, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "regex search matches 2xx status pattern",
                filter: HistoryFilter { search_term: r"^2\d\d".into(), is_regex: true, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
            FilterCase {
                name: "regex search rejects non-matching 4xx status pattern",
                filter: HistoryFilter { search_term: r"^4\d\d".into(), is_regex: true, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: false,
            },
            FilterCase {
                name: "invalid regex filters nothing and allows entry through",
                filter: HistoryFilter { search_term: "(unclosed".into(), is_regex: true, ..Default::default() },
                entry: post_api_entry.clone(),
                scope: default_scope.clone(),
                skip_ext: default_skip.clone(),
                expected: true,
            },
        ];

        assert_table!(cases, |case| {
            assert_eq!(
                case.filter.matches(&case.entry, &case.scope, &case.skip_ext),
                case.expected,
                "case '{}'",
                case.name
            );
        });

        assert!(HistoryFilter::default().is_default_filter());
        assert!(!HistoryFilter { hide_static_assets: true, ..Default::default() }.is_default_filter());
        assert!(HistoryFilter { search_term: "(unclosed".into(), is_regex: true, ..Default::default() }.regex_error());
        assert!(!HistoryFilter { search_term: "(unclosed".into(), is_regex: false, ..Default::default() }.regex_error());
    }
}
