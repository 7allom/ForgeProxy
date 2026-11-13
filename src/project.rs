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
    /// The Organizer's collections. Absent from files saved before collections existed,
    /// whose items all read back in the inbox.
    #[serde(default = "crate::organizer::default_collections")]
    pub org_collections: Vec<crate::organizer::OrgCollection>,
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
        org_collections: app.org_collections.clone(),
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
    app.org_collections = crate::organizer::default_collections();
    app.org_collection = crate::organizer::INBOX;
    app.org_view = crate::organizer::OrgView::default();
    app.org_renaming = None;
    app.org_new_collection = None;
    app.org_message.clear();
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
    // the collections first, then the items, then the mending of anything the file was
    // saved too early to hold: ids of their own for the items, and a collection that is
    // really there for each of them
    app.org_collections = f.org_collections;
    app.organizer = f.organizer;
    crate::organizer::renumber(&mut app.organizer);
    crate::organizer::adopt_orphans(&mut app.organizer, &mut app.org_collections);
    app.org_collection = crate::organizer::INBOX;
    app.org_sel = None;
    app.org_renaming = None;
    app.org_new_collection = None;
    app.org_message.clear();
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

    /// Repeater and Intruder start a new project on the same baseline origin, and the Intruder
    /// template's Host header agrees with its target: the default request is sendable as written,
    /// and the Target/Host sync has nothing to correct on the first frame.
    #[test]
    fn a_new_project_starts_both_tools_on_the_same_origin() {
        use crate::actions::{host_header, host_header_value, url_parts};
        use crate::state::{DEFAULT_INT_TARGET, DEFAULT_INT_TEMPLATE, DEFAULT_REP_REQUEST, DEFAULT_REP_URL};
        use crate::test_utils::assert_table;
        let (rep_scheme, rep_authority, _) = url_parts(DEFAULT_REP_URL);
        let (int_scheme, int_authority, _) = url_parts(DEFAULT_INT_TARGET);
        // positions are the user's to move, so the header is read with the markers stripped
        let template = DEFAULT_INT_TEMPLATE.replace('§', "");
        let cases: [(&str, String, String); 4] = [
            ("Intruder and Repeater share the scheme", int_scheme.clone(), rep_scheme),
            ("Intruder and Repeater share the authority", int_authority.clone(), rep_authority),
            ("the template's Host header matches the target", host_header(&template).unwrap_or_default(), host_header_value(&int_scheme, &int_authority)),
            ("Repeater's request still matches its own bar", host_header(DEFAULT_REP_REQUEST).unwrap_or_default(), "example.com".to_string()),
        ];
        assert_table!(cases, |idx, (what, got, want)| {
            assert_eq!(got, want, "case #{idx} ({what})");
        });
    }
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

    /// An app with an Organizer worth saving: two collections, an item in each, with the
    /// statuses, highlights and notes that make a triage worth keeping.
    fn organized_app() -> App {
        let ctx = eframe::egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx);
        let mut app = App::new(&cc, Some("/dev/null".into()), None, false);
        crate::actions::send_to_organizer(
            &mut app,
            "http://shop.test/cart?id=2",
            "GET /cart?id=2 HTTP/1.1\nHost: shop.test\n\n",
            "HTTP/1.1 200 OK\ncontent-length: 2\n\nok",
        );
        crate::actions::send_to_organizer(
            &mut app,
            "http://api.test/v1/login",
            "POST /v1/login HTTP/1.1\nHost: api.test\n\nuser=root",
            "HTTP/1.1 401 Unauthorized\n\ndenied",
        );
        let auth = crate::organizer::add_collection(&mut app.org_collections, "Auth flows");
        app.organizer[1].collection = auth;
        app.organizer[0].status = crate::state::OrgStatus::Postponed;
        app.organizer[0].highlight = Some(3);
        app.organizer[0].note = "comes back twice\nsecond line".into();
        app.organizer[1].status = crate::state::OrgStatus::Done;
        app.organizer[1].note = "401 as it should".into();
        app
    }

    /// A project file carries the whole of the Organizer: its collections, which collection
    /// each item is in, the raw request and response, and the status, highlight and notes the
    /// triage put on them. Work done in the Organizer is the kind nobody wants to do twice.
    #[test]
    fn a_project_keeps_the_organizer_whole() {
        let app = organized_app();
        let saved = serde_json::to_string(&snapshot(&app)).unwrap();
        let back: ProjectFile = serde_json::from_str(&saved).unwrap();

        let mut loaded = {
            let ctx = eframe::egui::Context::default();
            let cc = eframe::CreationContext::_new_kittest(ctx);
            App::new(&cc, Some("/dev/null".into()), None, false)
        };
        apply_all(&mut loaded, back);

        assert_eq!(loaded.org_collections, app.org_collections, "the collections, with their ids and names");
        assert_eq!(loaded.organizer.len(), 2);
        for (got, want) in loaded.organizer.iter().zip(app.organizer.iter()) {
            let what = format!("item #{}", want.id);
            assert_eq!((got.id, got.collection), (want.id, want.collection), "{what}: its id and the collection it is in");
            assert_eq!((&got.method, &got.host, &got.path, &got.url), (&want.method, &want.host, &want.path, &want.url), "{what}: its address");
            assert_eq!(got.request, want.request, "{what}: the raw request");
            assert_eq!(got.response, want.response, "{what}: the raw response");
            assert_eq!(got.status, want.status, "{what}: its status");
            assert_eq!(got.highlight, want.highlight, "{what}: its highlight");
            assert_eq!(got.note, want.note, "{what}: its notes, line breaks and all");
        }
        assert_eq!(loaded.organizer[0].note.lines().count(), 2, "a note of two lines comes back as two");
        // and the table can be drawn from what came back: each collection shows its own item
        let view = crate::organizer::OrgView::default();
        let auth = loaded.org_collections[1].id;
        assert_eq!(crate::organizer::rows(&loaded.organizer, crate::organizer::INBOX, &view).len(), 1);
        assert_eq!(crate::organizer::rows(&loaded.organizer, auth, &view).len(), 1);
    }

    /// A project saved before the Organizer had collections, or ids for its items, has to
    /// open without either -- with everything in the inbox and an id apiece, rather than a
    /// table of items that cannot be told apart.
    #[test]
    fn an_organizer_from_an_older_project_opens_in_the_inbox() {
        let old = r#"{"version":1,"name":"o","match_replace":[],"history":[],"tasks":[],
            "organizer":[
                {"method":"GET","host":"shop.test","path":"/cart","note":"had a look","highlight":2,"status":"Postponed"},
                {"method":"POST","host":"api.test","path":"/login","note":"","highlight":null,"status":"New"}
            ],
            "repeater_url":"","repeater_request":"","intruder_target":"","intruder_template":"","intruder_payloads":"","intruder_payloads_b":"","collab_server":""}"#;
        let f: ProjectFile = serde_json::from_str(old).expect("an older project file still reads");
        assert_eq!(f.org_collections, crate::organizer::default_collections(), "the inbox stands in for the collections it has none of");

        let ctx = eframe::egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx);
        let mut app = App::new(&cc, Some("/dev/null".into()), None, false);
        apply_all(&mut app, f);

        assert_eq!(app.organizer.iter().map(|it| it.id).collect::<Vec<_>>(), [1, 2], "an id apiece");
        assert!(app.organizer.iter().all(|it| it.collection == crate::organizer::INBOX), "everything in the inbox");
        assert_eq!(app.organizer[0].note, "had a look", "and what the file did hold is kept");
        assert_eq!(app.organizer[0].highlight, Some(2));
        assert_eq!(app.organizer[0].status, crate::state::OrgStatus::Postponed);
        // both rows are in the table, and they are two rows and not one
        let rows = crate::organizer::rows(&app.organizer, crate::organizer::INBOX, &crate::organizer::OrgView::default());
        assert_eq!(rows.len(), 2);
        assert_eq!(app.organizer[rows[0]].id, 1);
    }

    /// Saving and reading a real file on disk, rather than the JSON in between.
    #[test]
    fn the_organizer_survives_a_file_on_disk() {
        let app = organized_app();
        let dir = std::env::temp_dir().join(format!("forgeproxy-organizer-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("triage.forge").display().to_string();
        save(&app, &path).unwrap();
        let f = read(&path).expect("the file reads back");
        assert_eq!(f.org_collections, app.org_collections);
        assert_eq!(f.organizer.len(), 2);
        assert_eq!(f.organizer[1].note, "401 as it should");
        assert_eq!(f.organizer[1].collection, app.org_collections[1].id);
        let _ = std::fs::remove_dir_all(&dir);
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
            length: 0, mime: String::new(), request: String::new(), response: String::new(), url: String::new(), truncated: false, time: 0, elapsed_ms: 0,
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
