//! Project files: everything worth keeping between sessions, saved as JSON.
//! "Load from configuration file" reads the same format but only applies the settings
//! (scope and match-and-replace rules).

use crate::http::HttpEntry;
use crate::rewrite::Rule;
use crate::scope::{ScopeRule, TargetScope};
use crate::state::{App, OrgItem, Task};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct ProjectFile {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub target_scope: TargetScope,
    // scope as saved by older versions: read (and migrated), no longer written
    #[serde(default, skip_serializing)]
    pub scope_include: Vec<ScopeRule>,
    #[serde(default, skip_serializing)]
    pub scope_exclude: Vec<ScopeRule>,
    #[serde(default, skip_serializing)]
    pub scope_advanced: bool,
    pub match_replace: Vec<Rule>,
    pub history: Vec<HttpEntry>,
    pub tasks: Vec<Task>,
    pub organizer: Vec<OrgItem>,
    pub repeater_url: String,
    pub repeater_request: String,
    pub intruder_target: String,
    pub intruder_template: String,
    pub intruder_payloads: String,
    pub intruder_payloads_b: String,
    pub collab_server: String,
    /// "Default Proxy interception state": applied when the project is opened.
    #[serde(default)]
    pub intercept_at_startup: bool,
    /// Proxy > Intercept "Only in scope".
    #[serde(default)]
    pub intercept_only_in_scope: bool,
    /// Settings > Proxy > TLS pass-through host patterns.
    #[serde(default)]
    pub tls_passthrough: Vec<String>,
    /// Request interception rule: file extensions that aren't held. Missing in older
    /// project files, which get the default list.
    #[serde(default = "crate::rules::default_skip_extensions")]
    pub skip_extensions: Vec<String>,
    /// Repeater tabs. Missing in older files, which have one request in `repeater_*`.
    #[serde(default)]
    pub repeater_tabs: Vec<crate::repeater::RepeaterTab>,
    #[serde(default)]
    pub repeater_active: usize,
    /// Per-project overrides of user settings (theme, timeouts, upstream proxy, TLS). Absent
    /// in older files, which inherit all global settings.
    #[serde(default)]
    pub overrides: crate::state::Overrides,
}

pub fn snapshot(app: &App) -> ProjectFile {
    ProjectFile {
        version: 1,
        name: app.project_name.clone(),
        target_scope: app.target_scope.clone(),
        scope_include: Vec::new(),
        scope_exclude: Vec::new(),
        scope_advanced: false,
        match_replace: app.mr_rules.clone(),
        history: app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|e| (**e).clone()).collect(),
        tasks: app.tasks.iter().cloned().map(|mut t| { t.running = false; t }).collect(),
        organizer: app.organizer.clone(),
        // the active tab, also in the old fields (older versions read only those)
        repeater_url: app.rep().url.clone(),
        repeater_request: app.rep().request.clone(),
        repeater_tabs: app.repeater_tabs.clone(),
        repeater_active: app.active_repeater_tab,
        intruder_target: app.int_target.clone(),
        intruder_template: app.int_template.clone(),
        intruder_payloads: app.int_payloads.clone(),
        intruder_payloads_b: app.int_payloads_b.clone(),
        collab_server: app.collab_server.clone(),
        intercept_at_startup: app.intercept_default,
        intercept_only_in_scope: app.intercept_only_in_scope,
        tls_passthrough: app.tls_passthrough.clone(),
        skip_extensions: app.skip_extensions.clone(),
        overrides: app.overrides.clone(),
    }
}

pub fn save(app: &App, path: &str) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let json = serde_json::to_string_pretty(&snapshot(app)).map_err(|e| e.to_string())?;
    // projects hold captured traffic (cookies, tokens): owner-only
    crate::paths::write_private(std::path::Path::new(path), json.as_bytes()).map_err(|e| e.to_string())
}

pub fn read(path: &str) -> Result<ProjectFile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("Couldn't read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("Not a project file: {e}"))
}

impl ProjectFile {
    /// The file's scope, from `target_scope` or, in files from older versions, the
    /// separate scope fields.
    pub fn scope(&self) -> TargetScope {
        let old = !self.scope_include.is_empty() || !self.scope_exclude.is_empty() || self.scope_advanced;
        if self.target_scope == TargetScope::default() && old {
            TargetScope { include: self.scope_include.clone(), exclude: self.scope_exclude.clone(), advanced: self.scope_advanced }
        } else {
            self.target_scope.clone()
        }
    }
}

/// Apply only the settings part (scope and rules).
pub fn apply_settings(app: &mut App, f: &ProjectFile) {
    app.target_scope = f.scope();
    app.intercept_only_in_scope = f.intercept_only_in_scope;
    app.tls_passthrough = f.tls_passthrough.clone();
    app.skip_extensions = f.skip_extensions.clone();
    app.overrides = f.overrides.clone();
    if !f.match_replace.is_empty() {
        app.mr_rules = f.match_replace.clone();
    }
}

/// Start over with an empty temporary project: everything a project file holds goes back
/// to how a fresh start has it (app preferences, the proxy listener and the CA stay).
pub fn reset(app: &mut App) {
    use crate::state::*;
    app.history.lock().unwrap_or_else(|e| e.into_inner()).clear();
    *app.next_id.lock().unwrap_or_else(|e| e.into_inner()) = 0;
    app.history_sel = None;
    app.sitemap_path = None;
    app.target_scope = TargetScope::default();
    app.overrides = Overrides::default();
    app.mr_rules = crate::rewrite::defaults();
    app.intercept_only_in_scope = false;
    app.tls_passthrough.clear();
    app.skip_extensions = crate::rules::default_skip_extensions();
    app.skip_extensions_sel = None;
    app.tasks = default_tasks();
    app.task_sel = 0;
    app.show_new_scan = false;
    app.new_scan_urls.clear();
    app.new_scan_crawl = true;
    app.organizer.clear();
    app.org_sel = None;
    app.discover_sel = None;
    app.reset_repeater();
    app.rep_renaming = None;
    app.int_target = DEFAULT_INT_TARGET.into();
    app.int_template = DEFAULT_INT_TEMPLATE.into();
    app.int_payloads.clear();
    app.int_payloads_b.clear();
    app.int_results.clear();
    app.collab_server.clear();
    app.collab_payloads.clear();
    app.collab_interactions.clear();
    app.collab_polling = false;
    app.collab_msg.clear();
    app.decoder_pending_delete = None;
    app.project_name.clear();
    app.project_path = None;
}

/// Apply the whole project (data and settings).
pub fn apply_all(app: &mut App, f: ProjectFile) {
    apply_settings(app, &f);
    app.project_name = f.name;
    *app.history.lock().unwrap_or_else(|e| e.into_inner()) = f.history.into_iter().map(std::sync::Arc::new).collect();
    let max_id = app.history.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|e| e.id).max().unwrap_or(0);
    *app.next_id.lock().unwrap_or_else(|e| e.into_inner()) = max_id;
    if !f.tasks.is_empty() {
        app.tasks = f.tasks;
    }
    app.organizer = f.organizer;
    // the project's Repeater tabs replace the open ones
    app.rep_renaming = None;
    if !f.repeater_tabs.is_empty() {
        app.load_repeater_tabs(f.repeater_tabs, f.repeater_active);
    } else if !f.repeater_request.is_empty() {
        // an older project: its one request becomes tab 1
        let method = crate::actions::request_method(&f.repeater_request).unwrap_or_else(|| "GET".into());
        let tab = crate::repeater::RepeaterTab::new(1, "1".into(), &method, &f.repeater_url, &f.repeater_request);
        app.load_repeater_tabs(vec![tab], 0);
    } else {
        app.reset_repeater();
    }
    if !f.intruder_template.is_empty() {
        app.int_target = f.intruder_target;
        app.int_template = f.intruder_template;
    }
    app.int_payloads = f.intruder_payloads;
    app.int_payloads_b = f.intruder_payloads_b;
    app.collab_server = f.collab_server;
    // the project's default interception state takes effect as it opens
    app.intercept_default = f.intercept_at_startup;
    if app.proxy.intercept.load(std::sync::atomic::Ordering::SeqCst) != app.intercept_default {
        crate::ui_proxy::toggle_intercept(app);
    }
}

/// Extension of project files.
pub const EXTENSION: &str = "forge";

/// File name for a project called `name` ("My shop" -> "My_shop.forge").
pub fn default_file_name(name: &str) -> String {
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let safe = if safe.is_empty() { "project".to_string() } else { safe };
    format!("{safe}.{EXTENSION}")
}

/// Default location for a new project file.
pub fn default_path(name: &str) -> String {
    crate::paths::documents_dir().join(default_file_name(name)).display().to_string()
}

/// `path` with the `.forge` extension added when it has none (save dialogs may return the
/// name exactly as typed).
pub fn with_extension(path: std::path::PathBuf) -> std::path::PathBuf {
    if path.extension().is_some() { path } else { path.with_extension(EXTENSION) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_round_trip() {
        let mut f = ProjectFile { version: 1, name: "t".into(), ..Default::default() };
        f.target_scope.include.push(ScopeRule::new("https://a.test/"));
        f.target_scope.exclude.push(ScopeRule::new("https://a.test/logout"));
        f.match_replace = crate::rewrite::defaults();
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("scope_include"), "old fields aren't written");
        let back: ProjectFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scope(), f.target_scope);
        assert_eq!(back.match_replace.len(), 12);
    }

    #[cfg(unix)]
    #[test]
    fn project_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let ctx = eframe::egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx);
        let app = App::new(&cc, Some("/dev/null".into()), None, false);
        let dir = std::env::temp_dir().join(format!("forgeproxy-project-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("p.forge");
        let path_s = path.display().to_string();
        save(&app, &path_s).unwrap();
        let mode = || std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(), 0o600);
        // an older, world-readable file is tightened when saved over
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save(&app, &path_s).unwrap();
        assert_eq!(mode(), 0o600);
        assert!(read(&path_s).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_in_scope_is_saved() {
        let f = ProjectFile { intercept_only_in_scope: true, tls_passthrough: vec!["*.pinned.test".into()], ..Default::default() };
        let back: ProjectFile = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert!(back.intercept_only_in_scope);
        assert_eq!(back.tls_passthrough, ["*.pinned.test"]);
        // projects saved before the setting existed load with it off
        let old: ProjectFile = serde_json::from_str(r#"{"version":1,"name":"o","scope_include":[],"scope_exclude":[],"scope_advanced":false,"match_replace":[],"history":[],"tasks":[],"organizer":[],
            "repeater_url":"","repeater_request":"","intruder_target":"","intruder_template":"","intruder_payloads":"","intruder_payloads_b":"","collab_server":""}"#).unwrap();
        assert!(!old.intercept_only_in_scope);
        assert!(old.tls_passthrough.is_empty());
        assert_eq!(old.skip_extensions, crate::rules::default_skip_extensions(), "older files get the default list");
    }

    #[test]
    fn old_scope_fields_migrate() {
        let json = r#"{"version":1,"name":"old","scope_include":[{"enabled":true,"prefix":"https://a.test/","subdomains":true}],
            "scope_exclude":[],"scope_advanced":false,"match_replace":[],"history":[],"tasks":[],"organizer":[],
            "repeater_url":"","repeater_request":"","intruder_target":"","intruder_template":"","intruder_payloads":"",
            "intruder_payloads_b":"","collab_server":""}"#;
        let f: ProjectFile = serde_json::from_str(json).unwrap();
        let s = f.scope();
        assert_eq!(s.include.len(), 1);
        assert!(s.include[0].subdomains);
        assert!(s.is_in_scope("https://api.a.test/"));
    }

    #[test]
    fn project_file_names() {
        assert_eq!(default_file_name("My shop"), "My_shop.forge");
        assert_eq!(default_file_name(""), "project.forge");
        assert!(default_path("x").ends_with("x.forge"));
        use std::path::PathBuf;
        assert_eq!(with_extension(PathBuf::from("/a/b")), PathBuf::from("/a/b.forge"));
        assert_eq!(with_extension(PathBuf::from("/a/b.forge")), PathBuf::from("/a/b.forge"));
        assert_eq!(with_extension(PathBuf::from("/a/b.json")), PathBuf::from("/a/b.json"));
    }

    #[test]
    fn reset_starts_an_empty_temporary_project() {
        let ctx = egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx);
        // a screenshot path keeps the proxy listener off
        let mut app = crate::state::App::new(&cc, Some("/dev/null".into()), None, false);
        app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
            id: 1, tool: "Proxy".into(), method: "GET".into(), host: "h".into(), path: "/".into(), status: "200 OK".into(),
            length: 0, mime: String::new(), request: String::new(), response: String::new(), url: String::new(), truncated: false, time: 0,
        }));
        *app.next_id.lock().unwrap() = 1;
        app.target_scope.add("https://shop.test");
        app.add_repeater_tab("GET", "https://x.test/", "GET / HTTP/1.1\n\n");
        app.int_payloads = "a\nb".into();
        app.tls_passthrough.push("pinned.test".into());
        app.project_name = "Old".into();
        app.project_path = Some("/tmp/old.forge".into());
        assert!(app.has_project_data());
        reset(&mut app);
        assert!(!app.has_project_data());
        assert!(!app.has_unsaved_data());
        assert!(app.history.lock().unwrap().is_empty());
        assert_eq!(*app.next_id.lock().unwrap(), 0);
        assert_eq!(app.repeater_tabs, crate::repeater::default_tabs());
        assert_eq!(app.active_repeater_tab, 0);
        assert!(app.tls_passthrough.is_empty());
        assert!(app.project_name.is_empty() && app.project_path.is_none());
    }
}
