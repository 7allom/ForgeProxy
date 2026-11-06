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

    #[test]
    fn urls_under_one_host_build_a_hierarchy() {
        let mut map = SiteMap::default();
        map.insert_url("https://example.com/api/v1/users", 1, "GET", Some("200 OK"));
        map.insert_url("https://example.com/api/v1/orders", 2, "POST", Some("201 Created"));
        map.insert_url("https://example.com/api/v1/users", 3, "DELETE", Some("204 No Content"));

        // one origin root
        assert_eq!(map.roots.len(), 1);
        let root = &map.roots["https://example.com"];
        assert_eq!(root.name, "https://example.com");

        // api -> v1 -> {orders, users}
        let v1 = &root.children["api"].children["v1"];
        assert_eq!(v1.children.keys().collect::<Vec<_>>(), vec!["orders", "users"]);

        // leaf placement: the two /users requests land on the users node, nothing above it
        let users = &v1.children["users"];
        assert_eq!(users.full_url, "https://example.com/api/v1/users");
        assert_eq!(users.history_ids, vec![1, 3]);
        assert_eq!(users.methods, vec!["GET", "DELETE"]);
        assert_eq!(users.latest_status.as_deref(), Some("204 No Content"));
        assert!(root.children["api"].history_ids.is_empty());
    }

    #[test]
    fn collect_gathers_a_whole_branch() {
        let mut map = SiteMap::default();
        map.insert_url("https://a.test/api/users", 1, "GET", None);
        map.insert_url("https://a.test/api/orders", 2, "GET", None);
        map.insert_url("https://a.test/login", 3, "GET", None);

        // the /api branch gathers both of its leaves, not /login
        assert_eq!(map.collect_history_ids("https://a.test/api"), vec![1, 2]);
        // a single leaf
        assert_eq!(map.collect_history_ids("https://a.test/login"), vec![3]);
        // the origin gathers everything
        assert_eq!(map.collect_history_ids("https://a.test"), vec![1, 2, 3]);
        // an unknown node gathers nothing
        assert!(map.collect_history_ids("https://a.test/missing").is_empty());
    }

    #[test]
    fn separate_origins_do_not_merge() {
        let mut map = SiteMap::default();
        map.insert_url("https://a.test/x", 1, "GET", None);
        map.insert_url("http://a.test/x", 2, "GET", None); // different scheme
        map.insert_url("https://b.test/x", 3, "GET", None);
        assert_eq!(map.roots.len(), 3);
        assert_eq!(map.collect_history_ids("https://a.test/x"), vec![1]);
        assert_eq!(map.collect_history_ids("http://a.test/x"), vec![2]);
    }

    #[test]
    fn root_path_files_on_the_origin() {
        let mut map = SiteMap::default();
        map.insert_url("https://a.test/", 1, "GET", Some("200 OK"));
        map.insert_url("https://a.test", 2, "HEAD", Some("200 OK"));
        let root = &map.roots["https://a.test"];
        assert!(root.children.is_empty());
        assert_eq!(root.history_ids, vec![1, 2]);
        assert_eq!(root.methods, vec!["GET", "HEAD"]);
    }
}
