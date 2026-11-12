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

/// What the site map's filter bar is asking for: the scope toggle and the search text.
/// Borrowed rather than owned, so filtering a frame copies nothing.
#[derive(Clone, Copy, Debug)]
pub struct SiteMapFilter<'a> {
    pub scope: &'a crate::scope::TargetScope,
    /// Show only what the target scope covers.
    pub scope_only: bool,
    /// Plain text, matched against a node's name and its URL, ignoring case.
    pub query: &'a str,
}

impl SiteMapFilter<'_> {
    /// Nothing filtered out: every node is shown.
    pub fn is_open(&self) -> bool {
        !self.scope_only && self.query.trim().is_empty()
    }

    /// The same filter with the search text dropped. Once a node matches the text, everything
    /// under it is shown, so a search for a host does not then hide that host's paths.
    pub fn below_a_match(&self) -> Self {
        SiteMapFilter { query: "", ..*self }
    }

    /// Does the node itself read as a match for the search text? A node with no text to
    /// search for matches everything.
    pub fn hits(&self, node: &SiteMapNode) -> bool {
        let query = self.query.trim().to_lowercase();
        query.is_empty()
            || node.name.to_lowercase().contains(&query)
            || node.full_url.to_lowercase().contains(&query)
    }

    /// Is this node an endpoint of its own (a request was filed on it) that the scope covers?
    /// A branch nobody requested directly is not an endpoint, so it stands or falls by what
    /// is underneath it.
    fn endpoint_in_scope(&self, node: &SiteMapNode) -> bool {
        !node.history_ids.is_empty() && self.scope.is_in_scope(&node.full_url)
    }

    /// Is this node drawn? It is if it stands on its own -- an endpoint the filter admits --
    /// or if anything under it does, which is what keeps the folders above a match on screen.
    /// A host whose every endpoint is out of scope therefore disappears entirely rather than
    /// being dimmed, and so does a subtree the scope excludes.
    pub fn keeps(&self, node: &SiteMapNode) -> bool {
        if self.is_open() {
            return true;
        }
        let stands_alone = (!self.scope_only || self.endpoint_in_scope(node)) && self.hits(node);
        // `any` stops at the first child that stays, so a wide tree is not walked in full
        stands_alone || node.children.values().any(|child| self.keeps(child))
    }

    /// Does a request recorded at `url` survive the filter? This is the same question for the
    /// table beside the tree, which lists requests rather than nodes.
    pub fn keeps_url(&self, url: &str) -> bool {
        if self.scope_only && !self.scope.is_in_scope(url) {
            return false;
        }
        let query = self.query.trim().to_lowercase();
        query.is_empty() || url.to_lowercase().contains(&query)
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

    /// A map of three hosts: one wholly inside the scope, one with an excluded subtree, and
    /// one nobody put in scope at all.
    fn filtered_map() -> SiteMap {
        let mut map = SiteMap::default();
        let mut id = 0;
        let mut put = |map: &mut SiteMap, url: &str| {
            id += 1;
            map.insert_url(url, id, "GET", Some("200 OK"));
        };
        put(&mut map, "https://shop.internal/api/v1/orders");
        put(&mut map, "https://shop.internal/api/v1/accounts");
        put(&mut map, "https://shop.internal/static/app.js");
        put(&mut map, "https://shop.internal/static/logo.png");
        put(&mut map, "https://metrics.external-host.test/collect");
        put(&mut map, "https://metrics.external-host.test/beacon/ping");
        put(&mut map, "https://cdn.internal/assets/style.css");
        map
    }

    /// The hosts and folders drawn under this filter, as "host > folder > ..." lines, in the
    /// order the tree shows them.
    fn drawn(map: &SiteMap, filter: SiteMapFilter<'_>) -> Vec<String> {
        fn walk(node: &SiteMapNode, trail: &str, filter: SiteMapFilter<'_>, out: &mut Vec<String>) {
            if !filter.keeps(node) {
                return;
            }
            let trail = if trail.is_empty() { node.name.clone() } else { format!("{trail} > {}", node.name) };
            out.push(trail.clone());
            // the drawing code reveals everything under a node that matched the search text
            let below = if filter.hits(node) { filter.below_a_match() } else { filter };
            for child in node.children.values() {
                walk(child, &trail, below, out);
            }
        }
        let mut out = Vec::new();
        for root in map.roots.values() {
            walk(root, "", filter, &mut out);
        }
        out
    }

    /// "Scope only" hides a host with nothing in scope under it, and an excluded folder,
    /// outright -- while every folder on the way down to something in scope stays, so the
    /// branch can still be opened. Switching it off brings the whole tree back.
    #[test]
    fn site_map_filtering_matrix() {
        let map = filtered_map();
        let mut scope = crate::scope::TargetScope::default();
        scope.include.push(crate::scope::ScopeRule::new("https://shop.internal"));
        scope.exclude.push(crate::scope::ScopeRule::new("https://shop.internal/static"));
        let scope = &scope;

        let everything = [
            "https://cdn.internal",
            "https://cdn.internal > assets",
            "https://cdn.internal > assets > style.css",
            "https://metrics.external-host.test",
            "https://metrics.external-host.test > beacon",
            "https://metrics.external-host.test > beacon > ping",
            "https://metrics.external-host.test > collect",
            "https://shop.internal",
            "https://shop.internal > api",
            "https://shop.internal > api > v1",
            "https://shop.internal > api > v1 > accounts",
            "https://shop.internal > api > v1 > orders",
            "https://shop.internal > static",
            "https://shop.internal > static > app.js",
            "https://shop.internal > static > logo.png",
        ];
        let in_scope_only = [
            "https://shop.internal",
            "https://shop.internal > api",
            "https://shop.internal > api > v1",
            "https://shop.internal > api > v1 > accounts",
            "https://shop.internal > api > v1 > orders",
        ];

        struct Case<'a> {
            name: &'a str,
            scope_only: bool,
            query: &'a str,
            expected: Vec<&'a str>,
        }
        let cases = [
            Case { name: "no filter shows every host", scope_only: false, query: "", expected: everything.to_vec() },
            Case {
                name: "scope only drops the host with nothing in scope and the excluded folder",
                scope_only: true,
                query: "",
                expected: in_scope_only.to_vec(),
            },
            Case {
                name: "a search keeps the folders above what matched",
                scope_only: false,
                query: "orders",
                expected: vec!["https://shop.internal", "https://shop.internal > api", "https://shop.internal > api > v1", "https://shop.internal > api > v1 > orders"],
            },
            Case {
                name: "matching a host reveals everything under it",
                scope_only: false,
                query: "cdn.internal",
                expected: vec!["https://cdn.internal", "https://cdn.internal > assets", "https://cdn.internal > assets > style.css"],
            },
            Case {
                name: "the search ignores case",
                scope_only: false,
                query: "COLLECT",
                expected: vec!["https://metrics.external-host.test", "https://metrics.external-host.test > collect"],
            },
            Case {
                name: "both at once: the search cannot bring back what the scope hid",
                scope_only: true,
                query: "static",
                expected: vec![],
            },
            Case {
                name: "both at once, on something in scope",
                scope_only: true,
                query: "accounts",
                expected: vec!["https://shop.internal", "https://shop.internal > api", "https://shop.internal > api > v1", "https://shop.internal > api > v1 > accounts"],
            },
            Case { name: "a search nothing matches empties the tree", scope_only: false, query: "nowhere", expected: vec![] },
            // turning the toggle off restores the tree, which is what lets the UI keep the
            // folders open: nothing about the map itself changed
            Case { name: "turning scope only off restores every host", scope_only: false, query: "", expected: everything.to_vec() },
        ];

        assert_table!(cases, |idx, Case { name, scope_only, query, expected }| {
            let filter = SiteMapFilter { scope, scope_only, query };
            assert_eq!(drawn(&map, filter), expected, "case #{idx} ({name})");
        });
    }

    /// The requests listed beside the tree answer the same filter as the tree does.
    #[test]
    fn site_map_filter_on_recorded_requests_matrix() {
        let mut scope = crate::scope::TargetScope::default();
        scope.include.push(crate::scope::ScopeRule::new("https://shop.internal"));
        scope.exclude.push(crate::scope::ScopeRule::new("https://shop.internal/static"));
        let scope = &scope;

        let cases: [(&str, bool, &str, &str, bool); 6] = [
            ("in scope, no search", true, "", "https://shop.internal/api/v1/orders", true),
            ("excluded folder", true, "", "https://shop.internal/static/app.js", false),
            ("another host entirely", true, "", "https://metrics.external-host.test/collect", false),
            ("out of scope, but the filter is off", false, "", "https://metrics.external-host.test/collect", true),
            ("the search reaches the address", false, "orders", "https://shop.internal/api/v1/orders", true),
            ("and turns away what it does not match", false, "orders", "https://shop.internal/api/v1/accounts", false),
        ];
        assert_table!(cases, |idx, (what, scope_only, query, url, expected)| {
            let filter = SiteMapFilter { scope, scope_only, query };
            assert_eq!(filter.keeps_url(url), expected, "case #{idx} ({what})");
        });
    }

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
