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

    fn entry(id: usize, url: &str, status: &str) -> HttpEntry {
        let (host, path) = crate::http::split_url(url);
        HttpEntry { id, tool: "Proxy".into(), method: "GET".into(), host, path, status: status.into(), length: 0,
            mime: "HTML".into(), request: String::new(), response: String::new(), url: url.into(), truncated: false, time: 0 }
    }

    fn skip() -> Vec<String> {
        crate::rules::default_skip_extensions()
    }

    #[test]
    fn scope_filtering() {
        let mut scope = TargetScope::default();
        scope.include.push(ScopeRule::new("https://shop.test/"));
        let mut f = HistoryFilter::default();
        let (inside, outside) = (entry(1, "https://shop.test/cart", "200 OK"), entry(2, "https://ads.test/p", "200 OK"));
        assert!(f.matches(&inside, &scope, &skip()) && f.matches(&outside, &scope, &skip()));
        f.only_in_scope = true;
        assert!(f.matches(&inside, &scope, &skip()));
        assert!(!f.matches(&outside, &scope, &skip()));
    }

    #[test]
    fn static_assets_follow_the_skip_list() {
        let scope = TargetScope::default();
        let f = HistoryFilter { hide_static_assets: true, ..Default::default() };
        assert!(!f.matches(&entry(1, "https://a.test/logo.PNG?v=2", "200 OK"), &scope, &skip()));
        assert!(!f.matches(&entry(2, "https://a.test/app.js", "200 OK"), &scope, &skip()));
        assert!(f.matches(&entry(3, "https://a.test/api/users", "200 OK"), &scope, &skip()));
        assert!(f.matches(&entry(4, "https://a.test/data.json", "200 OK"), &scope, &skip()));
        // the user's own list decides
        let custom = vec!["json".to_string()];
        assert!(!f.matches(&entry(4, "https://a.test/data.json", "200 OK"), &scope, &custom));
        assert!(f.matches(&entry(1, "https://a.test/logo.png", "200 OK"), &scope, &custom));
        assert!(HistoryFilter::default().is_default_filter() && !f.is_default_filter());
    }

    #[test]
    fn status_code_buckets() {
        let scope = TargetScope::default();
        let f = HistoryFilter { show_3xx: false, show_5xx: false, ..Default::default() };
        let rows = [("200 OK", true), ("204 No Content", true), ("302 Found", false), ("404 Not Found", true), ("503 Unavailable", false),
                    ("200 (Tunnel)", true), (crate::http::CONNECTION_FAILED, true)];
        for (status, shown) in rows {
            assert_eq!(f.matches(&entry(1, "http://a.test/", status), &scope, &skip()), shown, "{status}");
        }
        let f = HistoryFilter { hide_no_response: true, ..Default::default() };
        assert!(!f.matches(&entry(1, "http://a.test/", crate::http::CONNECTION_FAILED), &scope, &skip()));
    }

    #[test]
    fn substring_and_regex_search() {
        let scope = TargetScope::default();
        let mut e = entry(1, "https://API.test/v1/users?id=7", "201 Created");
        e.method = "POST".into();
        let search = |q: &str, regex: bool| HistoryFilter { search_term: q.into(), is_regex: regex, ..Default::default() }.matches(&e, &scope, &skip());
        for q in ["api.test", "post", "/V1/US", "201", "html", "  users  "] {
            assert!(search(q, false), "{q}");
        }
        assert!(!search("delete", false));
        assert!(!search("v[0-9]", false), "plain text: brackets are literal");
        assert!(search(r"/v\d+/", true));
        assert!(search("^post$", true), "case-insensitive, whole field");
        assert!(search(r"^2\d\d", true));
        assert!(!search(r"^4\d\d", true));
        // a regex that doesn't compile filters nothing (and is reported)
        assert!(search("(unclosed", true));
        let bad = HistoryFilter { search_term: "(unclosed".into(), is_regex: true, ..Default::default() };
        assert!(bad.regex_error());
        assert!(!HistoryFilter { search_term: "(unclosed".into(), ..Default::default() }.regex_error());
    }

    #[test]
    fn reset_keeps_the_sort() {
        let mut f = HistoryFilter { search_term: "x".into(), only_in_scope: true, show_2xx: false, sort_column: Some(HistorySortColumn::Length), sort_ascending: false, ..Default::default() };
        assert!(!f.is_default_filter());
        f.reset_filter();
        assert!(f.is_default_filter());
        assert_eq!((f.sort_column, f.sort_ascending), (Some(HistorySortColumn::Length), false));
    }

    fn rows() -> Vec<Arc<HttpEntry>> {
        // id, status, time, length
        [(1, "404 Not Found", 3000, 50), (2, "200 OK", 1000, 900), (3, crate::http::CONNECTION_FAILED, 2000, 0),
         (4, "302 Found", 1000, 900), (5, "500 Error", 4000, 10)]
            .into_iter().map(|(id, status, time, length)| {
                let mut e = entry(id, "http://a.test/", status);
                e.time = time;
                e.length = length;
                Arc::new(e)
            }).collect()
    }

    fn ids(rows: &[Arc<HttpEntry>]) -> Vec<usize> {
        rows.iter().map(|e| e.id).collect()
    }

    #[test]
    fn sort_by_status() {
        let mut r = rows();
        sort_rows(&mut r, HistorySortColumn::Status, true);
        assert_eq!(ids(&r), [2, 4, 1, 5, 3], "no response last");
        sort_rows(&mut r, HistorySortColumn::Status, false);
        assert_eq!(ids(&r), [5, 1, 4, 2, 3], "no response still last");
    }

    #[test]
    fn sort_by_time_and_length() {
        let mut r = rows();
        sort_rows(&mut r, HistorySortColumn::Time, true);
        assert_eq!(ids(&r), [2, 4, 3, 1, 5], "ties keep id order");
        sort_rows(&mut r, HistorySortColumn::Time, false);
        assert_eq!(ids(&r), [5, 1, 3, 2, 4], "ties keep id order descending too");
        sort_rows(&mut r, HistorySortColumn::Length, true);
        assert_eq!(ids(&r), [3, 5, 1, 2, 4]);
        sort_rows(&mut r, HistorySortColumn::Length, false);
        assert_eq!(ids(&r), [2, 4, 1, 5, 3]);
    }

    #[test]
    fn clicking_columns() {
        let mut f = HistoryFilter::default();
        assert_eq!((f.sort_column, f.sort_ascending), (Some(HistorySortColumn::Id), true));
        f.click_column(HistorySortColumn::Id);
        assert!(!f.sort_ascending, "same column: reversed");
        f.click_column(HistorySortColumn::Length);
        assert_eq!((f.sort_column, f.sort_ascending), (Some(HistorySortColumn::Length), true), "a new column starts ascending");
        let mut r = rows();
        let before = ids(&r);
        HistoryFilter { sort_column: None, ..Default::default() }.sort(&mut r);
        assert_eq!(ids(&r), before, "no sort column: order untouched");
    }

    #[test]
    fn sorting_a_view_leaves_history_alone() {
        let history: Vec<Arc<HttpEntry>> = rows();
        let mut view: Vec<Arc<HttpEntry>> = history.clone();
        HistoryFilter { sort_column: Some(HistorySortColumn::Length), sort_ascending: false, ..Default::default() }.sort(&mut view);
        assert_eq!(ids(&history), [1, 2, 3, 4, 5]);
        assert_ne!(ids(&view), ids(&history));
    }

    #[test]
    fn time_column() {
        assert_eq!(time_of_day(0), "");
        assert_eq!(time_of_day(1_700_000_000_123), "22:13:20");
    }
}
