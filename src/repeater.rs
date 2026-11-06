//! Repeater tabs: each holds a request, its address bar and its last response. The tab
//! operations (add, duplicate, close, rename) keep two rules: there is always at least one
//! tab, and `active_repeater_tab` always points at one.

use crate::state::App;
use crate::viewer::MessageViewMode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepeaterTab {
    pub id: usize,
    pub title: String,
    pub method: String,
    pub url: String,
    pub request: String,
    /// The last response as shown ("200 OK\n<headers>\n\n<body>"); None before the first send.
    pub response: Option<String>,
    pub response_status: Option<u16>,
    pub response_time_ms: Option<u128>,
    pub response_bytes: Option<usize>,
    #[serde(default)]
    pub view_mode: MessageViewMode,
    /// Status line text shown above the response ("200 OK", "Sending...", an error).
    #[serde(default)]
    pub status_text: String,
    /// A request is on its way (not saved: a reopened project has nothing in flight).
    #[serde(skip)]
    pub waiting: bool,
}

impl RepeaterTab {
    pub fn new(id: usize, title: String, method: &str, url: &str, request: &str) -> Self {
        RepeaterTab {
            id,
            title,
            method: method.to_string(),
            url: url.to_string(),
            request: request.to_string(),
            response: None,
            response_status: None,
            response_time_ms: None,
            response_bytes: None,
            view_mode: MessageViewMode::Raw,
            status_text: String::new(),
            waiting: false,
        }
    }

    /// The first tab of a new project: the example request.
    pub fn example(id: usize) -> Self {
        Self::new(id, "1".into(), "GET", crate::state::DEFAULT_REP_URL, crate::state::DEFAULT_REP_REQUEST)
    }

    /// Nothing in it yet (the "+" button, or after closing every tab).
    pub fn blank(id: usize, title: String) -> Self {
        Self::new(id, title, "GET", "", "")
    }

    /// Can it be sent? (Not while a request is in flight, and not with an empty request.)
    pub fn can_send(&self) -> bool {
        !self.waiting && !self.request.trim().is_empty()
    }

    /// Something worth saving: a request other than the example, or a response.
    pub fn has_data(&self) -> bool {
        self.response.is_some() || (self.request != crate::state::DEFAULT_REP_REQUEST && !self.request.trim().is_empty())
    }
}

/// The first positive number not already used as a tab title ("1", "2", ...).
pub fn next_title(tabs: &[RepeaterTab]) -> String {
    (1..).map(|n: usize| n.to_string()).find(|t| !tabs.iter().any(|tab| &tab.title == t)).unwrap_or_default()
}

/// The tabs a new project starts with: the example request in tab "1".
pub fn default_tabs() -> Vec<RepeaterTab> {
    vec![RepeaterTab::example(1)]
}

impl App {
    /// The tab being shown.
    pub fn rep(&self) -> &RepeaterTab {
        let i = self.active_repeater_tab.min(self.repeater_tabs.len().saturating_sub(1));
        &self.repeater_tabs[i]
    }

    pub fn rep_mut(&mut self) -> &mut RepeaterTab {
        let i = self.active_repeater_tab.min(self.repeater_tabs.len().saturating_sub(1));
        &mut self.repeater_tabs[i]
    }

    fn take_repeater_id(&mut self) -> usize {
        self.next_repeater_id += 1;
        self.next_repeater_id
    }

    /// Append a tab holding this request and switch to it; returns its index.
    pub fn add_repeater_tab(&mut self, method: &str, url: &str, request: &str) -> usize {
        let id = self.take_repeater_id();
        let title = next_title(&self.repeater_tabs);
        self.repeater_tabs.push(RepeaterTab::new(id, title, method, url, request));
        self.active_repeater_tab = self.repeater_tabs.len() - 1;
        self.active_repeater_tab
    }

    /// "+": append an empty tab and switch to it.
    pub fn add_blank_repeater_tab(&mut self) -> usize {
        let id = self.take_repeater_id();
        let title = next_title(&self.repeater_tabs);
        self.repeater_tabs.push(RepeaterTab::blank(id, title));
        self.active_repeater_tab = self.repeater_tabs.len() - 1;
        self.active_repeater_tab
    }

    /// A copy of tab `i` (request and response) right after it, switched to.
    pub fn duplicate_repeater_tab(&mut self, i: usize) {
        let Some(tab) = self.repeater_tabs.get(i).cloned() else { return };
        let id = self.take_repeater_id();
        let title = next_title(&self.repeater_tabs);
        self.repeater_tabs.insert(i + 1, RepeaterTab { id, title, waiting: false, ..tab });
        self.active_repeater_tab = i + 1;
    }

    /// Close tab `i`. The tab to its left (or the new first tab) is shown if it was the
    /// active one; closing the last tab leaves a single blank tab "1".
    pub fn close_repeater_tab(&mut self, i: usize) {
        if i >= self.repeater_tabs.len() {
            return;
        }
        self.repeater_tabs.remove(i);
        if self.repeater_tabs.is_empty() {
            let id = self.take_repeater_id();
            self.repeater_tabs.push(RepeaterTab::blank(id, "1".into()));
            self.active_repeater_tab = 0;
            return;
        }
        if self.active_repeater_tab > i || self.active_repeater_tab >= self.repeater_tabs.len() {
            self.active_repeater_tab = self.active_repeater_tab.saturating_sub(1);
        }
    }

    /// Close every tab but `i`, which becomes the active one.
    pub fn close_other_repeater_tabs(&mut self, i: usize) {
        if let Some(keep) = self.repeater_tabs.get(i).cloned() {
            self.repeater_tabs = vec![keep];
            self.active_repeater_tab = 0;
        }
    }

    /// Rename tab `i` (an empty name keeps the old one).
    pub fn rename_repeater_tab(&mut self, i: usize, title: &str) {
        let title = title.trim();
        if let Some(tab) = self.repeater_tabs.get_mut(i).filter(|_| !title.is_empty()) {
            tab.title = title.to_string();
        }
    }

    /// Index of the tab with this id (it may have been closed since).
    pub fn repeater_tab_index(&self, id: usize) -> Option<usize> {
        self.repeater_tabs.iter().position(|t| t.id == id)
    }

    /// Send the responses of tabs `a` and `b` to the Comparer and open their word
    /// comparison. False when either has no response.
    pub fn compare_repeater_responses(&mut self, a: usize, b: usize) -> bool {
        let (Some(ta), Some(tb)) = (self.repeater_tabs.get(a), self.repeater_tabs.get(b)) else { return false };
        let (Some(ra), Some(rb)) = (ta.response.clone(), tb.response.clone()) else { return false };
        let (la, lb) = (format!("Repeater tab {} response", ta.title), format!("Repeater tab {} response", tb.title));
        crate::comparer::add_text(self, la, &ra);
        crate::comparer::add_text(self, lb, &rb);
        crate::comparer::compare_selected(self, crate::comparer::DiffMode::Words)
    }

    /// Start over with the project's default tabs.
    pub fn reset_repeater(&mut self) {
        self.repeater_tabs = default_tabs();
        self.active_repeater_tab = 0;
        self.next_repeater_id = 1;
    }

    /// Use tabs loaded from a project (none: the defaults). Ids are made unique and the
    /// counter continues after the largest.
    pub fn load_repeater_tabs(&mut self, mut tabs: Vec<RepeaterTab>, active: usize) {
        if tabs.is_empty() {
            self.reset_repeater();
            return;
        }
        let mut seen = std::collections::HashSet::new();
        let mut next = tabs.iter().map(|t| t.id).max().unwrap_or(0);
        for t in &mut tabs {
            t.waiting = false;
            if !seen.insert(t.id) {
                next += 1;
                t.id = next;
                seen.insert(next);
            }
        }
        self.next_repeater_id = next;
        self.active_repeater_tab = active.min(tabs.len() - 1);
        self.repeater_tabs = tabs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::App;

    fn app() -> App {
        app_ctx().1
    }

    /// An app and the context it was made with (its fonts are installed there).
    fn app_ctx() -> (egui::Context, App) {
        let ctx = egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        // a screenshot path keeps the proxy listener off
        let app = App::new(&cc, Some("/dev/null".into()), None, false);
        (ctx, app)
    }

    fn titles(app: &App) -> Vec<&str> {
        app.repeater_tabs.iter().map(|t| t.title.as_str()).collect()
    }

    #[test]
    fn starts_with_the_example_tab() {
        let app = app();
        assert_eq!(titles(&app), ["1"]);
        assert_eq!(app.rep().url, "https://example.com/");
        assert!(app.rep().request.starts_with("GET / HTTP/1.1"));
        assert!(!app.has_project_data(), "the example tab alone isn't data");
    }

    #[test]
    fn titles_fill_the_first_free_number() {
        let mut tabs = default_tabs();
        assert_eq!(next_title(&tabs), "2");
        tabs.push(RepeaterTab::blank(5, "3".into()));
        assert_eq!(next_title(&tabs), "2");
        tabs[0].title = "login".into();
        assert_eq!(next_title(&tabs), "1");
    }

    #[test]
    fn create_duplicate_and_close() {
        let mut app = app();
        app.add_blank_repeater_tab();
        assert_eq!((titles(&app), app.active_repeater_tab), (vec!["1", "2"], 1));
        assert!(app.rep().request.is_empty() && !app.rep().can_send(), "a blank tab can't be sent");
        app.repeater_tabs[0].response = Some("200 OK\n\nhi".into());
        app.duplicate_repeater_tab(0);
        assert_eq!((titles(&app), app.active_repeater_tab), (vec!["1", "3", "2"], 1));
        assert_eq!(app.rep().response.as_deref(), Some("200 OK\n\nhi"), "the copy has the response too");
        let ids: std::collections::HashSet<usize> = app.repeater_tabs.iter().map(|t| t.id).collect();
        assert_eq!(ids.len(), 3, "ids are unique");
        // closing a tab left of the active one keeps the same tab active
        app.active_repeater_tab = 2;
        app.close_repeater_tab(0);
        assert_eq!((titles(&app), app.rep().title.as_str()), (vec!["3", "2"], "2"));
        // closing the active last tab moves left
        app.close_repeater_tab(1);
        assert_eq!((titles(&app), app.active_repeater_tab), (vec!["3"], 0));
        // closing the final tab leaves a single blank tab 1
        app.close_repeater_tab(0);
        assert_eq!(titles(&app), ["1"]);
        assert!(app.rep().request.is_empty() && app.rep().response.is_none());
        assert_eq!(app.active_repeater_tab, 0);
        // out-of-range requests are ignored
        app.close_repeater_tab(9);
        app.duplicate_repeater_tab(9);
        assert_eq!(titles(&app), ["1"]);
    }

    #[test]
    fn close_others_and_rename() {
        let mut app = app();
        app.add_blank_repeater_tab();
        app.add_blank_repeater_tab();
        app.rename_repeater_tab(1, "  login  ");
        app.rename_repeater_tab(2, "   ");
        assert_eq!(titles(&app), ["1", "login", "3"], "trimmed; blank names are ignored");
        app.close_other_repeater_tabs(1);
        assert_eq!((titles(&app), app.active_repeater_tab), (vec!["login"], 0));
    }

    #[test]
    fn send_to_repeater_appends_and_focuses() {
        let mut app = app();
        app.rep_mut().request = "GET /mine HTTP/1.1\nHost: keep.test\n\n".into();
        app.tab = crate::state::Tab::Proxy;
        crate::actions::send_to_repeater(&mut app, "POST", "https://shop.test/cart", "POST /cart HTTP/1.1\nHost: shop.test\n\nqty=1");
        assert_eq!(titles(&app), ["1", "2"]);
        assert_eq!(app.active_repeater_tab, 1);
        assert!(app.tab == crate::state::Tab::Repeater);
        assert_eq!(app.rep().method, "POST");
        assert_eq!(app.rep().url, "https://shop.test/cart");
        assert!(app.rep().response.is_none());
        assert!(app.repeater_tabs[0].request.contains("/mine"), "the existing tab is untouched");
        // from history: the same path
        let e = crate::http::HttpEntry {
            id: 7, tool: "Proxy".into(), method: "GET".into(), host: "a.test".into(), path: "/x".into(), status: "200 OK".into(),
            length: 0, mime: String::new(), request: "GET /x HTTP/1.1\nHost: a.test\n\n".into(), response: String::new(),
            url: "http://a.test/x".into(), truncated: false, time: 0,
        };
        crate::actions::send_to(&mut app, &e, crate::actions::SendTo::Repeater);
        assert_eq!((titles(&app), app.active_repeater_tab), (vec!["1", "2", "3"], 2));
        assert_eq!(app.rep().url, "http://a.test/x");
    }

    #[test]
    fn responses_land_in_the_tab_that_sent_them() {
        let (ctx, mut app) = app_ctx();
        app.add_blank_repeater_tab();
        let first = app.repeater_tabs[0].id;
        app.active_repeater_tab = 1;
        let r = crate::http::SendResult { status: "404 Not Found".into(), body: "nope".into(), headers: "Server: x".into(), length: 4, mime: String::new(), error: None };
        app.tx.send(crate::state::Job::Repeater { tab: first, result: r, elapsed_ms: 12 }).unwrap();
        let _ = ctx.run(egui::RawInput::default(), |ctx| eframe::App::update(&mut app, ctx, &mut eframe::Frame::_new_kittest()));
        let t = &app.repeater_tabs[0];
        assert_eq!(t.response.as_deref(), Some("404 Not Found\nServer: x\n\nnope"));
        assert_eq!((t.response_status, t.response_time_ms, t.response_bytes), (Some(404), Some(12), Some(4)));
        assert!(app.repeater_tabs[1].response.is_none(), "the shown tab is untouched");
        // a response for a tab closed meanwhile is dropped
        app.tx.send(crate::state::Job::Repeater { tab: 999, result: crate::http::SendResult { status: String::new(), body: String::new(), headers: String::new(), length: 0, mime: String::new(), error: Some("x".into()) }, elapsed_ms: 1 }).unwrap();
        let _ = ctx.run(egui::RawInput::default(), |ctx| eframe::App::update(&mut app, ctx, &mut eframe::Frame::_new_kittest()));
        assert_eq!(app.repeater_tabs.len(), 2);
    }

    #[test]
    fn compare_two_tabs() {
        let mut app = app();
        app.repeater_tabs[0].response = Some("200 OK\n\nalpha beta".into());
        app.add_blank_repeater_tab();
        assert!(!app.compare_repeater_responses(0, 1), "tab 2 has no response");
        app.repeater_tabs[1].response = Some("200 OK\n\nalpha gamma".into());
        assert!(app.compare_repeater_responses(0, 1));
        let view = app.comparer_active_diff.as_ref().expect("the diff window opens");
        assert_eq!((view.a.label.as_str(), view.b.label.as_str()), ("Repeater tab 1 response", "Repeater tab 2 response"));
        assert_eq!(app.comparer_items.len(), 2);
    }

    #[test]
    fn project_round_trip_with_tabs() {
        let mut app = app();
        crate::actions::send_to_repeater(&mut app, "POST", "https://shop.test/a", "POST /a HTTP/1.1\nHost: shop.test\n\nx=1");
        app.rep_mut().response = Some("200 OK\n\n{}".into());
        app.rep_mut().response_status = Some(200);
        app.rep_mut().view_mode = MessageViewMode::Pretty;
        app.rep_mut().waiting = true;
        app.rename_repeater_tab(1, "api");
        let file = crate::project::snapshot(&app);
        let json = serde_json::to_string(&file).unwrap();
        let back: crate::project::ProjectFile = serde_json::from_str(&json).unwrap();
        let mut other = self::app();
        crate::project::apply_all(&mut other, back);
        assert_eq!(titles(&other), ["1", "api"]);
        assert_eq!(other.active_repeater_tab, 1);
        let t = other.rep();
        assert_eq!((t.method.as_str(), t.response_status, t.view_mode), ("POST", Some(200), MessageViewMode::Pretty));
        assert!(!t.waiting, "nothing is in flight in a reopened project");
        // a new tab after loading gets a fresh id
        let ids: Vec<usize> = other.repeater_tabs.iter().map(|t| t.id).collect();
        other.add_blank_repeater_tab();
        assert!(!ids.contains(&other.rep().id));
    }

    #[test]
    fn older_projects_open_their_one_request_as_tab_1() {
        let old: crate::project::ProjectFile = serde_json::from_str(r#"{"version":1,"name":"o","scope_include":[],"scope_exclude":[],"scope_advanced":false,"match_replace":[],"history":[],"tasks":[],"organizer":[],
            "repeater_url":"https://old.test/","repeater_request":"PUT /old HTTP/1.1\nHost: old.test\n\n","intruder_target":"","intruder_template":"","intruder_payloads":"","intruder_payloads_b":"","collab_server":""}"#).unwrap();
        let mut app = app();
        app.add_blank_repeater_tab();
        crate::project::apply_all(&mut app, old);
        assert_eq!(titles(&app), ["1"]);
        assert_eq!((app.rep().method.as_str(), app.rep().url.as_str()), ("PUT", "https://old.test/"));
    }
}
