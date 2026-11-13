//! Shared test harness: fluent `MockAppBuilder`, `HttpFixture` request/response builders,
//! and the `assert_table!` table-driven test runner macro.

use crate::http::HttpEntry;
use crate::state::{App, Tab};
use eframe::egui;
use std::sync::Arc;

/// Table-driven test runner macro that iterates `(description, case)` or arbitrary test cases,
/// reporting the 0-based case index and description if an assertion fails.
#[macro_export]
macro_rules! assert_table {
    ($cases:expr, |$idx:ident, $case:pat_param| $body:block) => {{
        for ($idx, $case) in ($cases).into_iter().enumerate() {
            $body
        }
    }};
    ($cases:expr, |$case:pat_param| $body:block) => {{
        for (_case_idx, $case) in ($cases).into_iter().enumerate() {
            $body
        }
    }};
}
pub use crate::assert_table;

/// Fluent builder for constructing an [`App`] instance in unit tests without boilerplate.
pub struct MockAppBuilder {
    start_tab: Option<Tab>,
    light: bool,
    int_target: Option<String>,
    int_template: Option<String>,
    repeater_tabs: Vec<(String, String, String)>,
    history_entries: Vec<HttpEntry>,
}

impl Default for MockAppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl MockAppBuilder {
    pub fn new() -> Self {
        Self {
            start_tab: None,
            light: false,
            int_target: None,
            int_template: None,
            repeater_tabs: Vec::new(),
            history_entries: Vec::new(),
        }
    }

    pub fn with_tab(mut self, tab: Tab) -> Self {
        self.start_tab = Some(tab);
        self
    }

    pub fn with_light_theme(mut self, light: bool) -> Self {
        self.light = light;
        self
    }

    pub fn with_intruder_target(mut self, target: impl Into<String>) -> Self {
        self.int_target = Some(target.into());
        self
    }

    pub fn with_intruder_template(mut self, template: impl Into<String>) -> Self {
        self.int_template = Some(template.into());
        self
    }

    pub fn with_repeater_tab(
        mut self,
        method: impl Into<String>,
        url: impl Into<String>,
        request: impl Into<String>,
    ) -> Self {
        self.repeater_tabs.push((method.into(), url.into(), request.into()));
        self
    }

    pub fn with_history_entry(mut self, entry: HttpEntry) -> Self {
        self.history_entries.push(entry);
        self
    }

    pub fn build_with_ctx(self) -> (egui::Context, App) {
        let ctx = egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = App::new(&cc, Some("/dev/null".into()), self.start_tab, self.light);
        if let Some(target) = self.int_target {
            app.int_target = target;
        }
        if let Some(template) = self.int_template {
            app.int_template = template;
        }
        for (method, url, req) in self.repeater_tabs {
            app.add_repeater_tab(&method, &url, &req);
        }
        if !self.history_entries.is_empty() {
            let mut hist = app.history.lock().unwrap_or_else(|e| e.into_inner());
            for entry in self.history_entries {
                hist.push(Arc::new(entry));
            }
        }
        (ctx, app)
    }

    pub fn build(self) -> App {
        self.build_with_ctx().1
    }
}

/// Builder for generating realistic raw HTTP requests, responses, and [`HttpEntry`] fixtures.
#[derive(Clone, Debug)]
pub struct HttpFixture {
    pub method: String,
    pub is_tls: bool,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub status: String,
    pub response_headers: Vec<(String, String)>,
    pub response_body: String,
}

#[allow(dead_code)]
impl HttpFixture {
    pub fn get(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: "GET".into(),
            is_tls: false,
            host: host.into(),
            port: None,
            path: path.into(),
            headers: vec![("User-Agent".into(), "ForgeProxy-Test/1.0".into())],
            body: String::new(),
            status: "200 OK".into(),
            response_headers: vec![("Content-Type".into(), "text/plain".into())],
            response_body: "ok".into(),
        }
    }

    pub fn post(host: impl Into<String>, path: impl Into<String>, body: impl Into<String>) -> Self {
        let body = body.into();
        Self {
            method: "POST".into(),
            is_tls: false,
            host: host.into(),
            port: None,
            path: path.into(),
            headers: vec![
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
                ("Content-Length".into(), body.len().to_string()),
            ],
            body,
            status: "200 OK".into(),
            response_headers: vec![("Content-Type".into(), "application/json".into())],
            response_body: "{\"ok\":true}".into(),
        }
    }

    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn with_tls(mut self, is_tls: bool) -> Self {
        self.is_tls = is_tls;
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    pub fn with_response(mut self, status: impl Into<String>, body: impl Into<String>) -> Self {
        self.status = status.into();
        self.response_body = body.into();
        self
    }

    pub fn authority(&self) -> String {
        let bare = self.host.trim_start_matches('[').trim_end_matches(']');
        let host_fmt = if bare.contains(':') {
            format!("[{bare}]")
        } else {
            bare.to_string()
        };
        let default_port = if self.is_tls { 443 } else { 80 };
        match self.port {
            Some(p) if p != default_port => format!("{host_fmt}:{p}"),
            _ => host_fmt,
        }
    }

    pub fn origin(&self) -> String {
        let scheme = if self.is_tls { "https" } else { "http" };
        format!("{scheme}://{}", self.authority())
    }

    pub fn url(&self) -> String {
        let path = if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        };
        format!("{}{path}", self.origin())
    }

    pub fn raw_request(&self) -> String {
        let path = if self.path.starts_with('/') {
            self.path.as_str()
        } else {
            "/"
        };
        let mut s = format!("{} {} HTTP/1.1\nHost: {}\n", self.method, path, self.authority());
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}\n"));
        }
        s.push('\n');
        s.push_str(&self.body);
        s
    }

    pub fn raw_bytes(&self) -> Vec<u8> {
        self.raw_request().into_bytes()
    }

    pub fn raw_response(&self) -> String {
        let mut s = format!("HTTP/1.1 {}\n", self.status);
        for (k, v) in &self.response_headers {
            s.push_str(&format!("{k}: {v}\n"));
        }
        s.push('\n');
        s.push_str(&self.response_body);
        s
    }

    pub fn into_history_entry(self, id: usize, tool: &str) -> HttpEntry {
        let url = self.url();
        let req = self.raw_request();
        let resp = self.raw_response();
        let host = self.authority();
        HttpEntry {
            id,
            tool: tool.into(),
            method: self.method,
            host,
            path: self.path,
            status: self.status,
            length: self.response_body.len(),
            mime: "text/plain".into(),
            request: req,
            response: resp,
            url,
            truncated: false,
            time: 0,
            elapsed_ms: 0,
        }
    }
}
