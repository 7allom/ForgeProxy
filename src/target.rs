//! The target site map: a hierarchical tree of everything seen in HTTP history, grouped by
//! origin (scheme://host:port) and then by path segment. Each recorded request is filed under
//! the node for its endpoint; a branch gathers every request beneath it on demand.
//!
//! Scope (which URLs count as the target) lives in [`crate::scope`]; this module is only the
//! tree. Nodes are built lazily from history on the UI thread, so the map never duplicates the
//! request bodies — it holds only history ids that point back into the shared history.

use std::collections::BTreeMap;

/// One node in the site map: an origin (the root) or a single path segment under it.
/// `history_ids` are the requests whose endpoint is exactly this node; descendants carry the
/// rest. `children` is a `BTreeMap`, so the tree is always in a stable, sorted order.
#[derive(Clone, Debug, Default)]
pub struct SiteMapNode {
    /// The label shown in the tree: the origin for a root, otherwise the path segment.
    pub name: String,
    /// The cumulative URL of this node, used as its stable selection key.
    pub full_url: String,
    /// History ids whose endpoint is exactly this node (not its descendants).
    pub history_ids: Vec<usize>,
    /// The most recent status line filed on this node ("200 OK", "404 Not Found", ...).
    pub latest_status: Option<String>,
    /// The distinct methods seen on this node, in first-seen order.
    pub methods: Vec<String>,
    pub children: BTreeMap<String, SiteMapNode>,
}

impl SiteMapNode {
    fn new(name: impl Into<String>, full_url: impl Into<String>) -> Self {
        SiteMapNode { name: name.into(), full_url: full_url.into(), ..Default::default() }
    }

    /// File a request on this exact node: remember the history id (once), the method (once)
    /// and the latest status.
    fn record(&mut self, history_id: usize, method: &str, status: Option<&str>) {
        if !self.history_ids.contains(&history_id) {
            self.history_ids.push(history_id);
        }
        if !method.is_empty() && !self.methods.iter().any(|m| m == method) {
            self.methods.push(method.to_string());
        }
        if let Some(s) = status.filter(|s| !s.is_empty()) {
            self.latest_status = Some(s.to_string());
        }
    }

    /// All history ids on this node and every descendant, sorted and de-duplicated.
    fn collect(&self, out: &mut Vec<usize>) {
        out.extend_from_slice(&self.history_ids);
        for child in self.children.values() {
            child.collect(out);
        }
    }

    /// The node whose `full_url` equals `target`, searched over this subtree.
    fn find(&self, target: &str) -> Option<&SiteMapNode> {
        if self.full_url == target {
            return Some(self);
        }
        self.children.values().find_map(|c| c.find(target))
    }
}

/// The whole site map: origins at the top, each a tree of path segments.
#[derive(Clone, Debug, Default)]
pub struct SiteMap {
    /// Keyed by origin ("https://example.com:443"); `BTreeMap` keeps hosts sorted.
    pub roots: BTreeMap<String, SiteMapNode>,
}

/// Split a URL into its origin ("scheme://authority") and its path (no query or fragment).
/// A URL with no scheme is treated as `http`.
fn split_origin_path(url: &str) -> (String, String) {
    let s = url.trim();
    let (scheme, rest) = match s.find("://") {
        Some(i) => (&s[..i], &s[i + 3..]),
        None => ("http", s),
    };
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(cut);
    let authority = authority.rsplit('@').next().unwrap_or(authority); // drop user:pass@
    let path = after.split(['?', '#']).next().unwrap_or("");
    (format!("{}://{}", scheme.to_ascii_lowercase(), authority), path.to_string())
}

impl SiteMap {
    /// File a recorded request: build (or walk to) the origin root and then one node per path
    /// segment, and record the request on the deepest node.
    pub fn insert_url(&mut self, url: &str, history_id: usize, method: &str, status: Option<&str>) {
        let (origin, path) = split_origin_path(url);
        let root = self
            .roots
            .entry(origin.clone())
            .or_insert_with(|| SiteMapNode::new(origin.clone(), origin.clone()));
        let mut node = root;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            let full = format!("{}/{}", node.full_url, seg);
            node = node
                .children
                .entry(seg.to_string())
                .or_insert_with(|| SiteMapNode::new(seg, full));
        }
        node.record(history_id, method, status);
    }

    /// Every history id filed under the node whose `full_url` is `path` (the node itself and
    /// all of its descendants), sorted and de-duplicated. Empty if no such node exists.
    pub fn collect_history_ids(&self, path: &str) -> Vec<usize> {
        let mut out = Vec::new();
        if let Some(node) = self.roots.values().find_map(|r| r.find(path)) {
            node.collect(&mut out);
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_table, HttpFixture};

    #[test]
    fn site_map_tree_insertion_matrix() {
        // 1. Hierarchical segmentation, query/fragment stripping, deduplication & status tracking
        let mut map = SiteMap::default();
        let entries = [
            HttpFixture::get("example.com", "/api/v1/users?page=1#top")
                .with_tls(true)
                .with_response("200 OK", "[]")
                .into_history_entry(1, "Proxy"),
            HttpFixture::post("example.com", "/api/v1/orders", "{}")
                .with_tls(true)
                .with_response("201 Created", "{}")
                .into_history_entry(2, "Proxy"),
            HttpFixture::get("example.com", "/api/v1/users?id=3")
                .with_method("DELETE")
                .with_tls(true)
                .with_response("204 No Content", "")
                .into_history_entry(3, "Proxy"),
            // Duplicate insertion of history_id=1 and method="GET" must deduplicate
            HttpFixture::get("example.com", "/api/v1/users")
                .with_tls(true)
                .with_response("200 OK", "[]")
                .into_history_entry(1, "Proxy"),
        ];

        for e in &entries {
            map.insert_url(&e.url, e.id, &e.method, Some(&e.status));
        }

        assert_eq!(map.roots.len(), 1);
        let root = &map.roots["https://example.com"];
        assert_eq!(root.name, "https://example.com");

        let v1 = &root.children["api"].children["v1"];
        assert_eq!(v1.children.keys().collect::<Vec<_>>(), vec!["orders", "users"]);

        let users = &v1.children["users"];
        assert_eq!(users.full_url, "https://example.com/api/v1/users");
        assert_eq!(users.history_ids, vec![1, 3]);
        assert_eq!(users.methods, vec!["GET", "DELETE"]);
        assert_eq!(users.latest_status.as_deref(), Some("200 OK"));
        assert!(root.children["api"].history_ids.is_empty());

        // 2. Branch collection, multi-origin isolation & root-path filing matrix
        let mut multi_map = SiteMap::default();
        let insert_rows = [
            ("https://a.test/api/users", 1, "GET", Some("200 OK")),
            ("https://a.test/api/orders", 2, "GET", Some("200 OK")),
            ("https://a.test/login", 3, "POST", Some("302 Found")),
            ("https://a.test/", 4, "GET", Some("200 OK")),
            ("https://a.test", 5, "HEAD", Some("200 OK")),
            ("http://a.test/x", 6, "GET", None),
            ("https://b.test/x", 7, "GET", None),
        ];
        for (url, id, method, status) in insert_rows {
            multi_map.insert_url(url, id, method, status);
        }

        assert_eq!(multi_map.roots.len(), 3, "separate origins (scheme or host) do not merge");
        assert_eq!(multi_map.roots["https://a.test"].history_ids, vec![4, 5]);
        assert_eq!(multi_map.roots["https://a.test"].methods, vec!["GET", "HEAD"]);

        let collect_cases = [
            ("/api branch gathers both leaves under it", "https://a.test/api", vec![1, 2]),
            ("/login leaf gathers only its own id", "https://a.test/login", vec![3]),
            ("origin root gathers root ids and all descendant leaves", "https://a.test", vec![1, 2, 3, 4, 5]),
            ("plain HTTP origin stays isolated from HTTPS origin", "http://a.test/x", vec![6]),
            ("second host origin stays isolated", "https://b.test/x", vec![7]),
            ("unknown node gathers empty vector", "https://a.test/missing", vec![]),
        ];

        assert_table!(collect_cases, |(name, query_url, expected_ids)| {
            assert_eq!(multi_map.collect_history_ids(query_url), expected_ids, "{name}");
        });
    }

    #[test]
    fn site_map_issue_association_matrix() {
        let mut map = SiteMap::default();
        let e1 = HttpFixture::get("shop.test", "/account/login")
            .with_tls(false)
            .with_response("200 OK", "<input type=\"password\">")
            .into_history_entry(1, "Proxy");
        let e2 = HttpFixture::get("shop.test", "/account/profile")
            .with_tls(true)
            .with_response("200 OK", "Contact admin@shop.test at 10.0.0.42")
            .into_history_entry(2, "Proxy");

        map.insert_url(&e1.url, e1.id, &e1.method, Some(&e1.status));
        map.insert_url(&e2.url, e2.id, &e2.method, Some(&e2.status));

        let mut findings = Vec::new();
        findings.extend(crate::scan::passive_checks(&e1.host, &e1.path, false, "Content-Type: text/html", "<input type=\"password\">"));
        findings.extend(crate::scan::passive_checks(&e2.host, &e2.path, true, "Content-Type: text/html", "Contact admin@shop.test at 10.0.0.42"));
        let findings = crate::scan::consolidate(findings);

        let assoc_cases = [
            ("http://shop.test/account/login", "Cleartext submission of password", true),
            ("http://shop.test/account/login", "Password field with autocomplete enabled", true),
            ("https://shop.test/account/profile", "Email addresses disclosed", true),
            ("https://shop.test/account/profile", "Private IP addresses disclosed", true),
            ("https://shop.test/account/profile", "Cleartext submission of password", false),
        ];

        assert_table!(assoc_cases, |(node_url, expected_issue, should_exist)| {
            let ids = map.collect_history_ids(node_url);
            assert!(!ids.is_empty(), "node {node_url} exists in site map");
            let (_, node_path) = split_origin_path(node_url);
            let matched = findings.iter().any(|f| f.path == node_path && f.name == expected_issue);
            assert_eq!(matched, should_exist, "node '{node_url}' issue '{expected_issue}'");
        });
    }
}
