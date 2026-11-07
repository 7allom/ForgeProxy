//! Application state: the tab set, data types, and the App struct used by every screen.

use crate::http::History;
use crate::intruder::AttackType;
use crate::rewrite;
use crate::rules;
use crate::scan::Finding;
use crate::theme::{self, Look, Palette};
use eframe::egui;
use egui::Color32;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub enum Tab {
    Dashboard, Target, Proxy, Intruder, Repeater, Collaborator, Sequencer,
    Decoder, Comparer, Logger, Organizer, Discover,
}
impl Copy for Tab {}

impl Tab {
    pub const ALL: [Tab; 12] = [
        Tab::Dashboard, Tab::Target, Tab::Proxy, Tab::Intruder, Tab::Repeater, Tab::Collaborator,
        Tab::Sequencer, Tab::Decoder, Tab::Comparer, Tab::Logger, Tab::Organizer, Tab::Discover,
    ];
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard", Tab::Target => "Target", Tab::Proxy => "Proxy",
            Tab::Intruder => "Intruder", Tab::Repeater => "Repeater", Tab::Collaborator => "Collaborator",
            Tab::Sequencer => "Sequencer", Tab::Decoder => "Decoder", Tab::Comparer => "Comparer",
            Tab::Logger => "Logger", Tab::Organizer => "Organizer",
            Tab::Discover => "Discover",
        }
    }
}

#[derive(Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OrgStatus { New, InProgress, Postponed, Done, Ignored }
impl OrgStatus {
    pub const ALL: [OrgStatus; 5] = [OrgStatus::New, OrgStatus::InProgress, OrgStatus::Postponed, OrgStatus::Done, OrgStatus::Ignored];
    pub fn label(&self) -> &'static str {
        match self { OrgStatus::New => "New", OrgStatus::InProgress => "In progress", OrgStatus::Postponed => "Postponed", OrgStatus::Done => "Done", OrgStatus::Ignored => "Ignored" }
    }
    pub fn color(&self, p: &Palette) -> Color32 {
        match self { OrgStatus::New => p.st_new, OrgStatus::InProgress => p.st_progress, OrgStatus::Postponed => p.st_postponed, OrgStatus::Done => p.st_done, OrgStatus::Ignored => p.st_ignored }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OrgItem {
    pub method: String,
    pub host: String,
    pub path: String,
    pub note: String,
    pub highlight: Option<usize>,
    pub status: OrgStatus,
    #[serde(default)]
    pub request: String,
    #[serde(default)]
    pub response: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Clone)]
pub struct DecBlock {
    pub text: String,
    pub hex: bool,
    pub label: Option<String>,
    pub color: Color32,
}

#[derive(Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TaskKind { LiveCrawl, Scan { crawl: bool } }

/// A Dashboard task: the live passive crawl, or a scan started with "New scan".
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Task {
    pub kind: TaskKind,
    pub url: String,
    pub capturing: bool,
    pub running: bool,
    pub requests: usize,
    pub findings: Vec<Finding>,
    pub log: Vec<String>,
}

impl Task {
    pub fn title(&self) -> String {
        match self.kind {
            TaskKind::LiveCrawl => "Live passive crawl from Proxy (all traffic)".into(),
            TaskKind::Scan { crawl: true } => format!("Crawl and audit of {}", crate::http::split_url(&self.url).0),
            TaskKind::Scan { crawl: false } => format!("Audit of {}", crate::http::split_url(&self.url).0),
        }
    }
}

/// One row of the Intruder attack results.
#[derive(Clone)]
pub struct IntResult {
    pub request: usize,
    pub payload: String,
    pub status: String,
    pub length: usize,
    pub error: String,
    /// The request/response as recorded in history.
    pub history_id: usize,
}

/// Messages from background worker threads.
pub enum Job {
    /// A Repeater response, for the tab with this id (which may have been closed since).
    Repeater { tab: usize, result: crate::http::SendResult, elapsed_ms: u128 },
    /// One finished Intruder request; `attack` is the attack it belongs to.
    Intruder { attack: u64, result: IntResult },
    IntruderDone { attack: u64 },
    ScanProgress { task: usize, requests: usize, line: String },
    ScanDone { task: usize, findings: Vec<Finding> },
    SeqToken(String),
    SeqMiss(String),
    SeqDone,
    CollabPoll(Result<Vec<crate::collab::CollabInteraction>, String>),
}

/// Tabs of the bottom drawer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DrawerTab {
    EventLog,
    AllIssues,
}

/// Pages of the Settings window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsPage {
    Proxy,
    Intruder,
    Repeater,
    Sequencer,
    NetworkConnections,
    NetworkTls,
    Display,
    Hotkeys,
}

pub use crate::upstream::{ProtocolSettings, UpstreamProxyConfig, UpstreamProxyType};

/// Dialogs reachable from the Project menu.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProjectDialog {
    New,
    Open,
    SaveAs,
    LoadConfig,
}

/// Default "HTTP client timeout" (Repeater, Intruder, Scanner, Sequencer), in seconds.
pub const DEFAULT_HTTP_TIMEOUT: u64 = 15;
/// Default proxy socket read timeout (browser and target connections), in seconds.
pub const DEFAULT_PROXY_READ_TIMEOUT: u64 = 120;
/// The user settings file, in the config directory next to the CA.
pub const SETTINGS_FILE: &str = "settings.json";

/// Settings kept across restarts in `settings.json` (every project uses them). Missing or
/// unknown fields fall back to the defaults; out-of-range values are clamped on load.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct UserSettings {
    pub theme: Look,
    pub editor_font_size: f32,
    pub http_timeout_secs: u64,
    pub proxy_read_timeout_secs: u64,
    /// Settings > Network > Connections: send outgoing traffic through another proxy.
    pub upstream_proxy: UpstreamProxyConfig,
    /// Settings > Network > TLS / Protocols.
    pub protocol: ProtocolSettings,
    // Former "session" settings: now saved globally so they persist across restarts. These
    // mirror live `App` fields, synced in on startup and out on exit (see `App`).
    pub proxy_host: String,
    pub proxy_port: String,
    pub intercept_rules: bool,
    pub fix_length: bool,
    pub int_concurrency: usize,
    pub int_delay_ms: u64,
    pub int_update_host: bool,
    pub rep_follow: bool,
    pub rep_unpack: bool,
    pub sequencer_threads: usize,
}

impl Default for UserSettings {
    fn default() -> Self {
        UserSettings {
            theme: Look::Dark,
            editor_font_size: crate::editor::DEFAULT_FONT,
            http_timeout_secs: DEFAULT_HTTP_TIMEOUT,
            proxy_read_timeout_secs: DEFAULT_PROXY_READ_TIMEOUT,
            upstream_proxy: UpstreamProxyConfig::default(),
            protocol: ProtocolSettings::default(),
            proxy_host: crate::rules::PROXY_HOST.into(),
            proxy_port: crate::rules::PROXY_PORT.to_string(),
            intercept_rules: true,
            fix_length: true,
            int_concurrency: crate::rules::POOL_CONCURRENT_LIMIT,
            int_delay_ms: 0,
            int_update_host: true,
            rep_follow: crate::rules::REPEATER_FOLLOW_REDIRECTS,
            rep_unpack: true,
            sequencer_threads: crate::rules::SEQUENCER_THREADS,
        }
    }
}

impl UserSettings {
    pub const FONT_RANGE: std::ops::RangeInclusive<f32> = 9.0..=24.0;
    pub const HTTP_TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=120;
    pub const PROXY_TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 5..=3600;

    /// Values brought into their ranges (a hand-edited file can hold anything).
    fn clamped(mut self) -> Self {
        let f = Self::FONT_RANGE;
        self.editor_font_size = if self.editor_font_size.is_finite() { self.editor_font_size.clamp(*f.start(), *f.end()) } else { crate::editor::DEFAULT_FONT };
        let h = Self::HTTP_TIMEOUT_RANGE;
        self.http_timeout_secs = self.http_timeout_secs.clamp(*h.start(), *h.end());
        let p = Self::PROXY_TIMEOUT_RANGE;
        self.proxy_read_timeout_secs = self.proxy_read_timeout_secs.clamp(*p.start(), *p.end());
        self.int_concurrency = self.int_concurrency.clamp(1, 50);
        self.int_delay_ms = self.int_delay_ms.min(60_000);
        self.sequencer_threads = self.sequencer_threads.clamp(1, 20);
        self
    }

    /// Read `dir/settings.json`: the defaults when there's no file yet; Err (with a message
    /// for the Event log) when it can't be read or parsed, and the defaults are used.
    pub fn load(dir: &std::path::Path) -> Result<Self, String> {
        let path = dir.join(SETTINGS_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<Self>(&text).map(Self::clamped)
                .map_err(|e| format!("Couldn't read {}: {e}. Using default settings.", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("Couldn't read {}: {e}. Using default settings.", path.display())),
        }
    }

    /// The settings a run starts with: settings.json from the config directory, unless
    /// `load` is off (screenshot runs) or this is a unit test; plus a load warning, if any.
    fn initial(load: bool) -> (Self, Option<String>) {
        if !load || cfg!(test) {
            return (Self::default(), None);
        }
        match Self::load(&crate::ca::config_dir()) {
            Ok(s) => (s, None),
            Err(e) => (Self::default(), Some(e)),
        }
    }

    /// Write `dir/settings.json` (owner-only, like the CA key).
    pub fn save(&self, dir: &std::path::Path) -> std::io::Result<()> {
        crate::paths::create_private_dir(dir)?;
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        crate::paths::write_private(&dir.join(SETTINGS_FILE), json.as_bytes())
    }
}

/// Per-project overrides of user settings. When a field is `Some`, the project uses that value
/// instead of the global one in [`UserSettings`]; `None` means "inherit the global default".
/// Saved in the project file; only the settings for which a per-project override is meaningful
/// appear here.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Overrides {
    pub theme: Option<Look>,
    pub http_timeout_secs: Option<u64>,
    pub proxy_read_timeout_secs: Option<u64>,
    pub upstream_proxy: Option<UpstreamProxyConfig>,
    pub verify_upstream_tls: Option<bool>,
}

/// What a new project starts with in Repeater and Intruder.
pub const DEFAULT_REP_URL: &str = "https://example.com/";
pub const DEFAULT_REP_REQUEST: &str = concat!("GET / HTTP/1.1\nHost: example.com\nUser-Agent: ForgeProxy/", env!("CARGO_PKG_VERSION"), "\nAccept: */*\nConnection: close\n\n");
pub const DEFAULT_INT_TARGET: &str = "http://localhost:80";
pub const DEFAULT_INT_TEMPLATE: &str = "POST /example?p1=§p1val§&p2=§p2val§ HTTP/1.0\nCookie: c=§cval§\nContent-Length: 17\n\np3=§p3val§&p4=§p4val§";

/// A new project's Dashboard tasks: the live passive crawl.
pub fn default_tasks() -> Vec<Task> {
    vec![Task { kind: TaskKind::LiveCrawl, url: String::new(), capturing: true, running: true, requests: 0, findings: Vec::new(), log: Vec::new() }]
}

pub struct App {
    /// Theme, editor font size and timeouts, kept in settings.json across restarts. These are
    /// the global values; a project may override some of them (see `overrides` and `eff`).
    pub settings: UserSettings,
    /// Per-project overrides of `settings`, saved in the project file.
    pub overrides: Overrides,
    pub tab: Tab,
    pub history: History,
    pub next_id: Arc<Mutex<usize>>,
    pub tx: Sender<Job>,
    pub rx: Receiver<Job>,

    // project: starts as a temporary in-memory project; Project menu dialogs change it
    pub project_dialog: Option<ProjectDialog>,
    pub project_name: String,
    pub project_file: String, // path field of the open dialog
    pub project_path: Option<String>, // None = temporary project
    /// "Save Project Before Exiting?" is showing.
    pub show_exit_save_dialog: bool,
    /// Project > New project...: the "New project" choice (save to a file, or temporary).
    pub show_new_project_dialog: bool,
    /// Close without asking (chosen "Discard & Exit", saved, or screenshot mode).
    pub force_exit: bool,
    /// "Save Project" was chosen in the exit dialog: close once the save has worked.
    pub exit_after_save: bool,
    pub project_msg: String,

    // proxy
    pub proxy: crate::proxy::Shared,
    pub proxy_host: String,
    pub proxy_port: String,
    pub proxy_msg: String,
    pub held_edit: String,
    /// The held request whose text `held_edit` holds (None: nothing loaded).
    pub held_loaded: Option<u64>,
    pub mr_sel: Option<usize>,
    pub proxy_sub: u8,
    pub mr_rules: Vec<rewrite::Rule>,

    // target
    pub target_sub: u8,
    pub target_scope: crate::scope::TargetScope,
    /// The site map tree, rebuilt lazily from history (see [`crate::actions::sync_site_map`]).
    pub site_map: crate::target::SiteMap,
    /// How many history entries have already been filed into `site_map`.
    pub site_map_cursor: usize,
    /// The site map node (its `full_url`) whose requests are shown, if any.
    pub target_selected_node: Option<String>,
    /// The history id open in the site map's request/response viewer, if any.
    pub target_selected_history_id: Option<usize>,
    /// Selected scope rule: (in the exclude list, index).
    pub scope_sel: Option<(bool, usize)>,
    pub issue_sel: usize,

    // repeater: never empty; `active_repeater_tab` always indexes it (see crate::repeater)
    pub repeater_tabs: Vec<crate::repeater::RepeaterTab>,
    pub active_repeater_tab: usize,
    /// The last tab id handed out (ids are never reused, so a late response can't land in
    /// a different tab).
    pub next_repeater_id: usize,
    /// The tab being renamed in the tab strip, and the name typed so far.
    pub rep_renaming: Option<(usize, String)>,

    // intruder
    pub int_target: String,
    pub int_template: String,
    pub int_payloads: String,
    pub int_payloads_b: String,
    pub int_attack: AttackType,
    pub int_results: Vec<IntResult>,
    pub int_running: bool,
    /// Requests the current attack will send (progress bar total).
    pub int_total: usize,
    /// Bumped by every new attack, so late results from an older one are ignored.
    pub int_attack_id: u64,
    pub int_stop: Arc<std::sync::atomic::AtomicBool>,
    pub show_attack: bool,
    /// "Update Host header to match target": send the target's host instead of the template's.
    pub int_update_host: bool,
    pub int_msg: String,
    pub int_sel: Option<(usize, usize)>,
    /// The results-table row open in the detail viewer (its history id), if any.
    pub int_result_sel: Option<usize>,

    // sequencer
    /// Capture / Analysis sub-tab.
    pub seq_sub: u8,
    /// The raw request sent repeatedly to collect tokens, and its origin for sending.
    pub seq_template: String,
    pub seq_origin: String,
    pub seq_location: crate::sequencer::TokenLocation,
    pub seq_target_samples: usize,
    pub seq_samples: Vec<String>,
    pub seq_running: bool,
    pub seq_stop: Arc<std::sync::atomic::AtomicBool>,
    /// Status line under the capture controls (last miss, or an error).
    pub seq_message: String,
    pub seq_analysis: Option<crate::sequencer::SequencerAnalysis>,

    // decoder
    pub dec_blocks: Vec<DecBlock>,
    /// Raw bytes for each Decoder stage (`dec_raw[0]` is Box 1's raw bytes).
    pub dec_raw: Vec<Vec<u8>>,
    /// Editable hex buffer for Box 1 when Hex mode is selected.
    pub dec_hex_input: String,
    /// Validation warning when Box 1's hex buffer contains invalid or odd-length hex.
    pub dec_hex_error: Option<String>,
    /// Decoder view: 0 Transform, 1 JWT Inspector.
    pub dec_view: u8,
    /// Stage index awaiting confirmation in the Decoder delete/reset modal.
    pub decoder_pending_delete: Option<usize>,
    /// Inspector panel (Repeater, Intercept, HTTP history): shown, and how wide.
    pub inspector: crate::ui_inspector::InspectorState,
    /// Root CA (loaded or created at startup); None if that failed (see `ca_error`).
    pub ca: Option<Arc<crate::ca::CertificateAuthority>>,
    pub ca_error: Option<String>,
    /// Per-host TLS server configs signed by `ca` (rebuilt whenever the CA changes).
    pub tls_cache: Option<Arc<crate::ca::TlsConfigCache>>,
    /// Settings > Proxy: folder the CA certificate is exported to, and the last result.
    pub ca_export_dir: String,
    pub ca_msg: String,
    pub ca_confirm_regenerate: bool,
    /// Token shown in the JWT Inspector.
    pub jwt_input: String,

    // comparer
    pub comparer_items: Vec<crate::comparer::ComparerItem>,
    /// Selected item (index) in the Item 1 and Item 2 lists.
    pub comparer_sel_a: Option<usize>,
    pub comparer_sel_b: Option<usize>,
    /// Active Comparer table pane: 0 = Item 1, 1 = Item 2.
    pub comparer_active_pane: u8,
    /// The open comparison window.
    pub comparer_active_diff: Option<crate::comparer::DiffView>,
    pub comparer_next_id: usize,
    /// Text typed or pasted into the Comparer to add as an item.
    pub comparer_paste: String,

    // organizer
    pub organizer: Vec<OrgItem>,
    pub org_sel: Option<usize>,
    pub org_only_highlighted: bool,
    pub org_only_notes: bool,
    pub org_search: String,
    pub discover_sel: Option<usize>,

    // extensions
    pub show_settings: bool,
    pub settings_page: SettingsPage,
    /// Card the Settings window scrolls to once (deep links from the command palette).
    pub settings_focus: Option<&'static str>,
    /// Repeater: decompress gzip/deflate responses.
    pub rep_unpack: bool,
    /// Proxy interception state a project starts with (saved in the project file).
    pub intercept_default: bool,
    /// Proxy > Intercept "Only in scope": hold only requests inside Target > Scope.
    pub intercept_only_in_scope: bool,
    /// Hosts whose HTTPS is never decrypted (certificate pinning etc.): "host" or "*.domain".
    pub tls_passthrough: Vec<String>,
    /// Request interception rule: requests for files with these extensions aren't held.
    pub skip_extensions: Vec<String>,
    /// Settings > Proxy > Skipped file extensions: the new-extension field and selected row.
    pub skip_extensions_new: String,
    pub skip_extensions_sel: Option<usize>,
    /// Settings > Proxy > TLS pass-through: the pattern being typed, and the selected row.
    pub tls_passthrough_new: String,
    pub tls_passthrough_sel: Option<usize>,
    /// Font size of the HTTP message editors.
    pub show_palette: bool,
    pub palette_query: String,
    /// Highlighted row in the command palette.
    pub palette_sel: usize,
    /// Bottom drawer above the status bar: which tab is open, if any.
    pub drawer: Option<DrawerTab>,
    pub rep_follow: bool,
    pub int_concurrency: usize,
    pub int_delay_ms: u64,
    /// Sequencer live capture: requests sent at once.
    pub sequencer_threads: usize,

    // dashboard
    pub tasks: Vec<Task>,
    pub task_sel: usize,
    pub task_sub: u8,
    pub finding_sel: usize,
    pub show_new_scan: bool,
    pub new_scan_urls: String,
    pub new_scan_crawl: bool,
    pub report_msg: String,

    // collaborator
    pub collab_server: String,
    pub collab_payloads: Vec<String>,
    pub collab_interactions: Vec<crate::collab::CollabInteraction>,
    pub collab_polling: bool,
    pub collab_msg: String,
    pub collab_custom: String,
    pub collab_with_server: bool,
    pub collab_counter: u64,
    pub event_log: crate::proxy::Events,

    // site map / logger selection
    pub history_sel: Option<usize>,
    // traffic filter bar (HTTP history, site map, Logger)
    /// HTTP history / Logger / site map filter ribbon and sort order.
    pub history_filter: crate::history::HistoryFilter,
    pub sitemap_path: Option<String>,

    // screenshot driver
    pub shot_path: Option<String>,
    pub frame: u64,
    pub shot_requested: bool,
}

#[allow(dead_code)]
pub type AppState = App;

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, shot_path: Option<String>, start_tab: Option<Tab>, light: bool) -> Self {
        theme::install_fonts(&cc.egui_ctx);
        // settings.json (not for unit tests or screenshot runs: those mustn't depend on, or
        // write to, the real config directory); --light overrides the saved theme
        let (mut settings, settings_warning) = UserSettings::initial(shot_path.is_none());
        if light {
            settings.theme = Look::Light;
        }
        theme::apply(&cc.egui_ctx, settings.theme);
        let (tx, rx) = std::sync::mpsc::channel();
        let history: crate::http::History = Arc::new(Mutex::new(Vec::new()));
        let next_id = Arc::new(Mutex::new(0usize));
        let events: crate::proxy::Events = Arc::new(Mutex::new(Default::default()));
        let start_proxy = shot_path.is_none();
        let mut app = Self {
            settings,
            overrides: Overrides::default(),
            tab: start_tab.unwrap_or(Tab::Dashboard),
            history: history.clone(),
            next_id: next_id.clone(),
            tx, rx,
            project_dialog: None,
            project_name: String::new(),
            project_file: String::new(),
            project_path: None,
            show_exit_save_dialog: false,
            show_new_project_dialog: false,
            // screenshot runs close themselves when done
            force_exit: shot_path.is_some(),
            exit_after_save: false,
            project_msg: String::new(),
            proxy: crate::proxy::Shared {
                history: history.clone(),
                next_id: next_id.clone(),
                intercept: Arc::new(std::sync::atomic::AtomicBool::new(rules::INTERCEPT_AT_STARTUP)),
                held: Arc::new(Mutex::new(Vec::new())),
                rules: Arc::new(Mutex::new(rewrite::defaults())),
                events: events.clone(),
                running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                use_rules: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                fix_length: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                // on out of the box: the launched browser trusts the root CA by its SPKI pin
                decrypt_https: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                intercept_only_in_scope: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                scope: Arc::new(Mutex::new(crate::scope::TargetScope::default())),
                tls_passthrough: Arc::new(Mutex::new(Vec::new())),
                skip_extensions: Arc::new(Mutex::new(rules::default_skip_extensions())),
                read_timeout_secs: Arc::new(std::sync::atomic::AtomicU64::new(DEFAULT_PROXY_READ_TIMEOUT)),
                upstream_proxy: Arc::new(Mutex::new(UpstreamProxyConfig::default())),
                verify_upstream_tls: Arc::new(std::sync::atomic::AtomicBool::new(ProtocolSettings::default().verify_upstream_tls)),
                tls: Arc::new(Mutex::new(None)),
                upstream_tls: crate::proxy::upstream_client_config(),
            },
            proxy_host: rules::PROXY_HOST.into(),
            proxy_port: rules::PROXY_PORT.to_string(),
            proxy_msg: String::new(),
            held_edit: String::new(),
            held_loaded: None,
            mr_sel: None,
            proxy_sub: 0,
            mr_rules: rewrite::defaults(),
            target_sub: 0,
            target_scope: crate::scope::TargetScope::default(),
            site_map: crate::target::SiteMap::default(),
            site_map_cursor: 0,
            target_selected_node: None,
            target_selected_history_id: None,
            scope_sel: None,
            issue_sel: 0,
            repeater_tabs: crate::repeater::default_tabs(),
            active_repeater_tab: 0,
            next_repeater_id: 1,
            rep_renaming: None,
            int_target: DEFAULT_INT_TARGET.into(),
            int_template: DEFAULT_INT_TEMPLATE.into(),
            int_payloads: String::new(),
            int_payloads_b: String::new(),
            int_attack: AttackType::Sniper,
            int_results: Vec::new(),
            int_running: false,
            int_total: 0,
            int_attack_id: 0,
            int_stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            show_attack: false,
            int_update_host: true,
            int_msg: String::new(),
            int_sel: None,
            int_result_sel: None,
            seq_sub: 0,
            seq_template: String::new(),
            seq_origin: String::new(),
            seq_location: crate::sequencer::TokenLocation::default(),
            seq_target_samples: 1000,
            seq_samples: Vec::new(),
            seq_running: false,
            seq_stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            seq_message: String::new(),
            seq_analysis: None,
            dec_blocks: vec![DecBlock { text: String::new(), hex: false, label: None, color: Color32::TRANSPARENT }],
            dec_raw: vec![Vec::new()],
            dec_hex_input: String::new(),
            dec_hex_error: None,
            dec_view: 0,
            decoder_pending_delete: None,
            inspector: crate::ui_inspector::InspectorState::default(),
            ca: None,
            ca_error: None,
            tls_cache: None,
            ca_export_dir: crate::ca::default_export_dir().display().to_string(),
            ca_msg: String::new(),
            ca_confirm_regenerate: false,
            jwt_input: String::new(),
            comparer_items: Vec::new(),
            comparer_sel_a: None,
            comparer_sel_b: None,
            comparer_active_pane: 0,
            comparer_active_diff: None,
            comparer_next_id: 0,
            comparer_paste: String::new(),
            organizer: Vec::new(),
            org_sel: None,
            org_only_highlighted: false,
            org_only_notes: false,
            org_search: String::new(),
            discover_sel: None,
            show_settings: false,
            settings_page: SettingsPage::Proxy,
            settings_focus: None,
            rep_unpack: true,
            intercept_default: rules::INTERCEPT_AT_STARTUP,
            intercept_only_in_scope: false,
            tls_passthrough: Vec::new(),
            skip_extensions: rules::default_skip_extensions(),
            skip_extensions_new: String::new(),
            skip_extensions_sel: None,
            tls_passthrough_new: String::new(),
            tls_passthrough_sel: None,
            show_palette: false,
            palette_query: String::new(),
            palette_sel: 0,
            drawer: None,
            rep_follow: rules::REPEATER_FOLLOW_REDIRECTS,
            int_concurrency: rules::POOL_CONCURRENT_LIMIT,
            int_delay_ms: 0,
            sequencer_threads: rules::SEQUENCER_THREADS,
            tasks: default_tasks(),
            task_sel: 0,
            task_sub: 0,
            finding_sel: 0,
            show_new_scan: false,
            new_scan_urls: String::new(),
            new_scan_crawl: true,
            report_msg: String::new(),
            collab_server: String::new(),
            collab_payloads: Vec::new(),
            collab_interactions: Vec::new(),
            collab_polling: false,
            collab_msg: String::new(),
            collab_custom: String::new(),
            collab_with_server: true,
            collab_counter: 0,
            event_log: events,
            history_sel: None,
            history_filter: crate::history::HistoryFilter::default(),
            sitemap_path: None,
            shot_path,
            frame: 0,
            shot_requested: false,
        };
        if let Some(w) = settings_warning {
            crate::proxy::log_warning(&app.proxy.events, w);
        }
        // unit tests construct App too; they must not touch the real config directory
        #[cfg(not(test))]
        app.load_ca();
        // the persisted former-session settings become the live values before the listener starts
        app.apply_user_settings();
        if start_proxy {
            crate::ui_proxy::start_listener(&mut app);
        }
        app
    }

    /// Resolve the effective user settings for this project: the global `settings`, with any
    /// per-project `overrides` applied on top. Everything that reads a user setting at runtime
    /// (theme, timeouts, upstream proxy, TLS verification) goes through this.
    pub fn eff(&self) -> UserSettings {
        let mut s = self.settings.clone();
        let o = &self.overrides;
        if let Some(v) = o.theme { s.theme = v; }
        if let Some(v) = o.http_timeout_secs { s.http_timeout_secs = v; }
        if let Some(v) = o.proxy_read_timeout_secs { s.proxy_read_timeout_secs = v; }
        if let Some(v) = &o.upstream_proxy { s.upstream_proxy = v.clone(); }
        if let Some(v) = o.verify_upstream_tls { s.protocol.verify_upstream_tls = v; }
        s
    }

    /// Set the effective theme: writes to the project override when one is active, else to the
    /// global setting. Used by the menu-bar quick toggle.
    pub fn set_theme(&mut self, look: Look) {
        match &mut self.overrides.theme {
            Some(t) => *t = look,
            None => self.settings.theme = look,
        }
    }

    /// Copy the persisted former-session settings into the live `App`/proxy fields (on startup).
    fn apply_user_settings(&mut self) {
        let s = &self.settings;
        self.proxy_host = s.proxy_host.clone();
        self.proxy_port = s.proxy_port.clone();
        self.int_concurrency = s.int_concurrency;
        self.int_delay_ms = s.int_delay_ms;
        self.int_update_host = s.int_update_host;
        self.rep_follow = s.rep_follow;
        self.rep_unpack = s.rep_unpack;
        self.sequencer_threads = s.sequencer_threads;
        self.proxy.use_rules.store(s.intercept_rules, std::sync::atomic::Ordering::SeqCst);
        self.proxy.fix_length.store(s.fix_length, std::sync::atomic::Ordering::SeqCst);
    }

    /// Copy the live former-session settings back into `settings` (before saving on exit).
    fn collect_user_settings(&mut self) {
        self.settings.proxy_host = self.proxy_host.clone();
        self.settings.proxy_port = self.proxy_port.clone();
        self.settings.int_concurrency = self.int_concurrency;
        self.settings.int_delay_ms = self.int_delay_ms;
        self.settings.int_update_host = self.int_update_host;
        self.settings.rep_follow = self.rep_follow;
        self.settings.rep_unpack = self.rep_unpack;
        self.settings.sequencer_threads = self.sequencer_threads;
        self.settings.intercept_rules = self.proxy.use_rules.load(std::sync::atomic::Ordering::SeqCst);
        self.settings.fix_length = self.proxy.fix_length.load(std::sync::atomic::Ordering::SeqCst);
    }

    pub fn p(&self) -> Palette { theme::palette(self.eff().theme) }

    /// How the tools send requests now: timeout, upstream proxy, certificate checking.
    pub fn send_options(&self) -> crate::http::SendOptions {
        let s = self.eff();
        crate::http::SendOptions {
            timeout: std::time::Duration::from_secs(s.http_timeout_secs),
            net: crate::upstream::NetConfig {
                upstream: s.upstream_proxy.clone(),
                verify_tls: s.protocol.verify_upstream_tls,
            },
        }
    }

    /// Something a project file would keep is in the app: captured history, a Repeater
    /// request, Organizer items, scope rules or Intruder payloads (saved or not).
    pub fn has_project_data(&self) -> bool {
        !self.history.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
            || self.repeater_tabs.len() > 1
            || self.repeater_tabs.iter().any(|t| t.has_data())
            || !self.organizer.is_empty()
            || self.target_scope != crate::scope::TargetScope::default()
            || !self.int_payloads.trim().is_empty()
    }

    /// A temporary (never saved) project holding something a project file would keep:
    /// captured history, a Repeater request, Organizer items, scope rules or Intruder
    /// payloads. Saved projects are written on exit anyway (`on_exit`).
    pub fn has_unsaved_data(&self) -> bool {
        self.project_path.is_none() && self.has_project_data()
    }

    /// Exit handling for this frame: a close request on a temporary project with data in it
    /// is cancelled and the save prompt shown instead; after "Save Project", close once the
    /// save worked (or drop back to the app if the save dialog was cancelled).
    pub fn handle_close(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) && !self.force_exit && self.has_unsaved_data() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.show_exit_save_dialog = true;
        }
        if self.exit_after_save && self.project_dialog.is_none() {
            self.exit_after_save = false;
            if self.project_path.is_some() {
                self.force_exit = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    /// Load the root CA from the config directory, or create one there, and log the result.
    #[cfg_attr(test, allow(dead_code))] // App::new skips it in unit tests
    pub fn load_ca(&mut self) {
        let dir = crate::ca::config_dir();
        match crate::ca::CertificateAuthority::load_or_generate(&dir) {
            Ok((ca, created)) => {
                let what = if created { "created" } else { "loaded" };
                crate::proxy::log(&self.proxy.events, format!("Root CA certificate {what}: CN={} (SHA-256 {}…) in {}",
                    crate::ca::COMMON_NAME, &ca.fingerprint()[..23], dir.display()));
                if let Some(w) = crate::ca::key_permission_warning(&dir) {
                    crate::proxy::log_warning(&self.proxy.events, w);
                }
                self.set_ca(ca);
            }
            Err(e) => {
                crate::proxy::log_error(&self.proxy.events, format!("Root CA certificate unavailable: {e}"));
                self.ca = None;
                self.tls_cache = None;
                *self.proxy.tls.lock().unwrap_or_else(|e| e.into_inner()) = None;
                self.ca_error = Some(e.to_string());
            }
        }
    }

    /// Use `ca`, with a fresh leaf-certificate cache (certificates from an older CA would no
    /// longer be trusted).
    fn set_ca(&mut self, ca: crate::ca::CertificateAuthority) {
        let ca = Arc::new(ca);
        let cache = Arc::new(crate::ca::TlsConfigCache::new(ca.clone()));
        // the proxy threads see the new CA's certificates from the next CONNECT on
        *self.proxy.tls.lock().unwrap_or_else(|e| e.into_inner()) = Some(cache.clone());
        self.tls_cache = Some(cache);
        self.ca = Some(ca);
        self.ca_error = None;
    }

    /// Replace the root CA with a new one, on disk too.
    pub fn regenerate_ca(&mut self) {
        let dir = crate::ca::config_dir();
        let result = crate::ca::CertificateAuthority::generate().and_then(|ca| { ca.save(&dir)?; Ok(ca) });
        match result {
            Ok(ca) => {
                let msg = format!("Root CA certificate regenerated (SHA-256 {}…). Re-export it and replace the old one wherever it was trusted.", &ca.fingerprint()[..23]);
                crate::proxy::log(&self.proxy.events, msg.clone());
                self.set_ca(ca);
                self.ca_msg = msg;
            }
            Err(e) => {
                let msg = format!("Couldn't regenerate the root CA: {e}");
                crate::proxy::log_error(&self.proxy.events, msg.clone());
                self.ca_msg = msg;
            }
        }
    }

    /// Apply the result of a background Collaborator poll (`Job::CollabPoll`).
    pub fn apply_collab_poll(&mut self, res: Result<Vec<crate::collab::CollabInteraction>, String>) {
        self.collab_polling = false;
        match res {
            Ok(hits) => {
                let mut added = 0usize;
                for hit in hits {
                    if !self.collab_interactions.contains(&hit) {
                        self.collab_interactions.push(hit);
                        added += 1;
                    }
                }
                if self.collab_interactions.is_empty() {
                    self.collab_msg = format!(
                        "No interactions received yet for {} payload(s).",
                        self.collab_payloads.len()
                    );
                } else if added > 0 {
                    self.collab_msg = format!(
                        "Received {added} new interaction(s) ({} total).",
                        self.collab_interactions.len()
                    );
                } else {
                    self.collab_msg = format!(
                        "No new interactions ({} total).",
                        self.collab_interactions.len()
                    );
                }
            }
            Err(err) => {
                crate::proxy::log_error(&self.event_log, format!("Collaborator poll failed: {err}"));
                self.collab_msg = format!("Poll failed: {err}");
            }
        }
    }

    /// Execute a confirmed Decoder stage deletion (cascading to downstream stages, or resetting all when `idx == 0`).
    pub fn confirm_decoder_delete(&mut self, idx: usize) {
        if idx == 0 {
            self.dec_blocks = vec![DecBlock {
                text: String::new(),
                hex: false,
                label: None,
                color: Color32::TRANSPARENT,
            }];
            self.dec_raw = vec![Vec::new()];
            self.dec_hex_input.clear();
            self.dec_hex_error = None;
        } else if idx < self.dec_blocks.len() {
            self.dec_blocks.truncate(idx);
            self.dec_raw.truncate(idx);
        }
        self.decoder_pending_delete = None;
    }
}

impl eframe::App for App {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(path) = self.project_path.clone() {
            let _ = crate::project::save(self, &path);
        }
        // user settings outlive the project (not from unit tests or screenshot runs)
        if self.shot_path.is_none() && !cfg!(test) {
            self.collect_user_settings();
            let _ = self.settings.save(&crate::ca::config_dir());
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_close(ctx);
        while let Ok(job) = self.rx.try_recv() {
            match job {
                Job::Repeater { tab, result: r, elapsed_ms } => {
                    if let Some(i) = self.repeater_tab_index(tab) {
                        let t = &mut self.repeater_tabs[i];
                        t.status_text = r.error.clone().unwrap_or_else(|| r.status.clone());
                        t.response = Some(format!("{}\n{}\n\n{}", r.status, r.headers, r.body));
                        t.response_status = r.status.get(..3).and_then(|c| c.parse().ok()).filter(|_| r.error.is_none());
                        t.response_time_ms = Some(elapsed_ms);
                        t.response_bytes = Some(r.length);
                        t.waiting = false;
                    }
                }
                Job::Intruder { attack, result } => {
                    if attack == self.int_attack_id {
                        self.int_results.push(result);
                        self.int_results.sort_by_key(|r| r.request);
                    }
                }
                Job::IntruderDone { attack } => {
                    if attack == self.int_attack_id {
                        self.int_running = false;
                    }
                }
                Job::ScanProgress { task, requests, line } => {
                    if let Some(t) = self.tasks.get_mut(task) {
                        t.requests = requests;
                        t.log.push(line);
                    }
                }
                Job::SeqToken(t) => self.seq_samples.push(t),
                Job::SeqMiss(status) => self.seq_message = format!("No token found in a response ({status}). Check the token location."),
                Job::SeqDone => {
                    self.seq_running = false;
                    self.seq_analysis = crate::sequencer::analyze_tokens(&self.seq_samples);
                }
                Job::ScanDone { task, findings } => {
                    if let Some(t) = self.tasks.get_mut(task) {
                        t.findings = findings;
                        t.running = false;
                        t.log.push(format!("Finished: {} issues found", t.findings.len()));
                    }
                }
                Job::CollabPoll(res) => {
                    self.apply_collab_poll(res);
                }
            }
        }

        // keep the proxy's copies of the match-and-replace rules, the scope and the
        // "Only in scope" switch current
        *self.proxy.rules.lock().unwrap_or_else(|e| e.into_inner()) = self.mr_rules.clone();
        {
            let mut scope = self.proxy.scope.lock().unwrap_or_else(|e| e.into_inner());
            if *scope != self.target_scope { *scope = self.target_scope.clone(); }
        }
        self.proxy.intercept_only_in_scope.store(self.intercept_only_in_scope, std::sync::atomic::Ordering::SeqCst);
        {
            let mut list = self.proxy.tls_passthrough.lock().unwrap_or_else(|e| e.into_inner());
            if *list != self.tls_passthrough { *list = self.tls_passthrough.clone(); }
        }
        {
            let mut list = self.proxy.skip_extensions.lock().unwrap_or_else(|e| e.into_inner());
            if *list != self.skip_extensions { *list = self.skip_extensions.clone(); }
        }
        let eff = self.eff();
        self.proxy.read_timeout_secs.store(eff.proxy_read_timeout_secs, std::sync::atomic::Ordering::SeqCst);
        self.proxy.verify_upstream_tls.store(eff.protocol.verify_upstream_tls, std::sync::atomic::Ordering::SeqCst);
        {
            let mut up = self.proxy.upstream_proxy.lock().unwrap_or_else(|e| e.into_inner());
            if *up != eff.upstream_proxy { *up = eff.upstream_proxy.clone(); }
        }
        if self.int_running || self.collab_polling {
            // Intruder and Collaborator results arrive from worker threads; keep the UI moving
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        } else if !self.proxy.held.lock().unwrap_or_else(|e| e.into_inner()).is_empty() || self.proxy.running.load(std::sync::atomic::Ordering::SeqCst) {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        crate::actions::sync_site_map(self);
        crate::ui_core::frame(self, ctx);

        if self.shot_path.is_some() {
            self.frame += 1;
            ctx.request_repaint();
            if self.frame == 120 && !self.shot_requested {
                self.shot_requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            }
            if self.shot_requested {
                let img = ctx.input(|i| i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                }));
                if let Some(image) = img {
                    save_png(&image, self.shot_path.as_ref().unwrap());
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }
}

fn save_png(image: &egui::ColorImage, path: &str) {
    let [w, h] = image.size;
    let mut buf = Vec::with_capacity(w * h * 4);
    for px in &image.pixels { buf.extend_from_slice(&[px.r(), px.g(), px.b(), px.a()]); }
    if let Some(rgba) = image::RgbaImage::from_raw(w as u32, h as u32, buf) { let _ = rgba.save(path); }
}

#[cfg(test)]
mod close_tests {
    use super::*;

    fn new_app() -> (egui::Context, App) {
        let ctx = egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        // a screenshot path keeps the proxy listener off; then behave like a normal run
        let mut app = App::new(&cc, Some("/dev/null".into()), None, false);
        app.force_exit = false;
        (ctx, app)
    }

    /// Run one frame (with a close request if `close`), returning the viewport commands sent.
    fn frame(ctx: &egui::Context, app: &mut App, close: bool) -> Vec<egui::ViewportCommand> {
        let mut input = egui::RawInput::default();
        if close {
            input.viewports.entry(egui::ViewportId::ROOT).or_default().events.push(egui::ViewportEvent::Close);
        }
        let out = ctx.run(input, |ctx| app.handle_close(ctx));
        out.viewport_output.get(&egui::ViewportId::ROOT).map(|v| v.commands.clone()).unwrap_or_default()
    }

    fn entry() -> crate::http::HttpEntry {
        crate::http::HttpEntry { id: 1, tool: "Proxy".into(), method: "GET".into(), host: "a.test".into(), path: "/".into(), status: "200 OK".into(),
            length: 0, mime: String::new(), request: String::new(), response: String::new(), url: "http://a.test/".into(), truncated: false, time: 0 }
    }

    #[test]
    fn https_interception_is_on_by_default() {
        let (_, app) = new_app();
        assert!(app.proxy.decrypt_https.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn what_counts_as_unsaved() {
        let (_, mut app) = new_app();
        assert!(!app.has_unsaved_data(), "a fresh temporary project has nothing to lose");
        app.history.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::new(entry()));
        assert!(app.has_unsaved_data());
        app.project_path = Some("/tmp/x.forge".into());
        assert!(!app.has_unsaved_data(), "saved projects are written on exit anyway");
        let (_, mut app) = new_app();
        app.rep_mut().request = "GET /edited HTTP/1.1\n\n".into();
        assert!(app.has_unsaved_data(), "a Repeater request");
        let (_, mut app) = new_app();
        app.target_scope.include.push(crate::scope::ScopeRule::new("a.test"));
        assert!(app.has_unsaved_data(), "scope rules");
    }

    #[test]
    fn closing_asks_only_when_there_is_something_to_lose() {
        let (ctx, mut app) = new_app();
        // nothing to lose: the close goes ahead
        assert!(!frame(&ctx, &mut app, true).contains(&egui::ViewportCommand::CancelClose));
        assert!(!app.show_exit_save_dialog);
        // history in a temporary project: cancelled, and the dialog shows
        app.history.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::new(entry()));
        assert!(frame(&ctx, &mut app, true).contains(&egui::ViewportCommand::CancelClose));
        assert!(app.show_exit_save_dialog);
        // "Discard & Exit" sets force_exit: the next close goes through
        app.show_exit_save_dialog = false;
        app.force_exit = true;
        assert!(!frame(&ctx, &mut app, true).contains(&egui::ViewportCommand::CancelClose));
    }

    #[test]
    fn save_then_exit() {
        let (ctx, mut app) = new_app();
        app.history.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::new(entry()));
        // "Save Project": the Save As dialog is open, nothing happens yet
        app.exit_after_save = true;
        app.project_dialog = Some(ProjectDialog::SaveAs);
        assert!(frame(&ctx, &mut app, false).is_empty());
        // the save worked (dialog closed, project has a path): close
        app.project_dialog = None;
        app.project_path = Some("/tmp/x.forge".into());
        assert!(frame(&ctx, &mut app, false).contains(&egui::ViewportCommand::Close));
        assert!(app.force_exit && !app.exit_after_save);
        // the Save As dialog was cancelled instead: stay in the app
        let (ctx, mut app) = new_app();
        app.history.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::new(entry()));
        app.exit_after_save = true;
        assert!(frame(&ctx, &mut app, false).is_empty());
        assert!(!app.force_exit && !app.exit_after_save);
    }

    #[test]
    fn collab_poll_updates_interactions_and_logs_errors() {
        let (_ctx, mut app) = new_app();
        let hit = crate::collab::CollabInteraction {
            interaction_type: "DNS".into(),
            client_ip: "192.0.2.10".into(),
            timestamp: "18:55:00".into(),
            protocol_details: "A query".into(),
            comment: "Custom data: test1".into(),
            payload: "abc.collab.test".into(),
        };
        app.apply_collab_poll(Ok(vec![hit.clone()]));
        assert_eq!(app.collab_interactions.len(), 1);
        assert!(app.collab_msg.contains("Received 1 new interaction(s)"));

        // Unreachable server logs an error to event_log and sets a failure notice
        app.apply_collab_poll(Err("Collaborator server 127.0.0.1:1 is unreachable: connection refused".into()));
        assert!(app.collab_msg.starts_with("Poll failed:"));
        let log = app.event_log.lock().unwrap();
        assert!(log.iter().any(|e| e.level == crate::proxy::Level::Error && e.message.contains("Collaborator poll failed")));
    }

    #[test]
    fn decoder_cascading_delete_and_modal_messages() {
        let (_ctx, mut app) = new_app();
        app.dec_blocks = vec![
            DecBlock { text: "root".into(), hex: false, label: None, color: Color32::TRANSPARENT },
            DecBlock { text: "stage1".into(), hex: false, label: Some("Encoded as Base64".into()), color: Color32::WHITE },
            DecBlock { text: "stage2".into(), hex: false, label: Some("Encoded as URL".into()), color: Color32::WHITE },
            DecBlock { text: "stage3".into(), hex: false, label: Some("SHA-256 hash".into()), color: Color32::WHITE },
        ];
        assert_eq!(
            crate::ui_tools::decoder_delete_message(0, 4),
            "Reset Decoder? This will clear all input and remove all transformation stages."
        );
        assert_eq!(
            crate::ui_tools::decoder_delete_message(1, 4),
            "Delete this stage? This will also remove the 2 subsequent transformation(s) below it."
        );
        assert_eq!(
            crate::ui_tools::decoder_delete_message(3, 4),
            "Remove this transformation stage?"
        );

        // Delete last stage (count == 1)
        app.decoder_pending_delete = Some(3);
        app.confirm_decoder_delete(3);
        assert_eq!(app.dec_blocks.len(), 3);
        assert!(app.decoder_pending_delete.is_none());

        // Cascade delete stage 1 (removes stage 1 and stage 2)
        app.decoder_pending_delete = Some(1);
        app.confirm_decoder_delete(1);
        assert_eq!(app.dec_blocks.len(), 1);
        assert_eq!(app.dec_blocks[0].text, "root");

        // Reset root stage 0
        app.decoder_pending_delete = Some(0);
        app.confirm_decoder_delete(0);
        assert_eq!(app.dec_blocks.len(), 1);
        assert!(app.dec_blocks[0].text.is_empty());
        assert!(app.decoder_pending_delete.is_none());
    }

    #[test]
    fn decoder_box1_hex_edit_updates_downstream_and_handles_invalid_hex() {
        let (_ctx, mut app) = new_app();
        app.dec_blocks = vec![
            DecBlock { text: String::new(), hex: true, label: None, color: Color32::TRANSPARENT },
            DecBlock { text: String::new(), hex: false, label: Some("Encoded as Base64".into()), color: Color32::WHITE },
        ];
        app.dec_raw = vec![Vec::new(), Vec::new()];

        // Formatted hex "61 64 6d" -> "adm" -> Base64 "YWRt"
        app.dec_hex_input = "61 64 6d".into();
        crate::ui_tools::apply_box1_hex_edit(&mut app);
        assert!(app.dec_hex_error.is_none());
        assert_eq!(app.dec_raw[0], b"adm");
        assert_eq!(app.dec_blocks[0].text, "adm");
        assert_eq!(app.dec_blocks[1].text, "YWRt");

        // Unformatted hex "61646d696e" -> "admin" -> Base64 "YWRtaW4="
        app.dec_hex_input = "61646d696e".into();
        crate::ui_tools::apply_box1_hex_edit(&mut app);
        assert!(app.dec_hex_error.is_none());
        assert_eq!(app.dec_raw[0], b"admin");
        assert_eq!(app.dec_blocks[1].text, "YWRtaW4=");

        // Odd-length or invalid hex while typing sets warning without clearing buffer or panicking
        app.dec_hex_input = "61 64 6".into();
        crate::ui_tools::apply_box1_hex_edit(&mut app);
        assert!(app.dec_hex_error.as_deref().unwrap_or("").contains("Invalid hex sequence"));
        assert_eq!(app.dec_hex_input, "61 64 6");
        assert_eq!(app.dec_raw[0], b"admin");
    }

    #[test]
    fn comparer_remove_selected_respects_active_pane_and_fallback() {
        let (_ctx, mut app) = new_app();
        crate::comparer::add_text(&mut app, "first", "one");
        crate::comparer::add_text(&mut app, "second", "two");
        crate::comparer::add_text(&mut app, "third", "three");
        assert_eq!(app.comparer_items.len(), 3);

        // Select row 0 in Item 1, row 2 in Item 2 with pane 1 active -> removes row 2
        app.comparer_sel_a = Some(0);
        app.comparer_sel_b = Some(2);
        app.comparer_active_pane = 1;
        crate::comparer::remove_selected(&mut app);
        assert_eq!(app.comparer_items.len(), 2);
        assert_eq!(app.comparer_sel_a, Some(0));
        assert_eq!(app.comparer_sel_b, None);

        // Fallback: pane 0 is active, but only Item 2 has a selection -> removes Item 2's selection
        app.comparer_sel_a = None;
        app.comparer_sel_b = Some(1);
        app.comparer_active_pane = 0;
        crate::comparer::remove_selected(&mut app);
        assert_eq!(app.comparer_items.len(), 1);
        assert_eq!(app.comparer_items[0].label, "first");
        assert_eq!(app.comparer_sel_b, None);

        // Out-of-bounds selection is safely clamped without panicking
        app.comparer_sel_a = Some(99);
        crate::comparer::remove_selected(&mut app);
        assert_eq!(app.comparer_sel_a, Some(0));
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("forgeproxy-settings-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn missing_file_gives_defaults() {
        let dir = temp_dir("missing");
        let s = UserSettings::load(&dir).unwrap();
        assert_eq!(s, UserSettings::default());
        assert_eq!((s.http_timeout_secs, s.proxy_read_timeout_secs), (15, 120));
    }

    #[test]
    fn settings_round_trip_owner_only() {
        let dir = temp_dir("round");
        let s = UserSettings {
            theme: Look::Light, editor_font_size: 15.5, http_timeout_secs: 45, proxy_read_timeout_secs: 300,
            upstream_proxy: UpstreamProxyConfig { enabled: true, proxy_type: UpstreamProxyType::Socks5, host: "10.1.2.3".into(), port: 1080 },
            protocol: ProtocolSettings { verify_upstream_tls: true },
            ..Default::default()
        };
        s.save(&dir).unwrap();
        assert_eq!(UserSettings::load(&dir).unwrap(), s);
        let text = std::fs::read_to_string(dir.join(SETTINGS_FILE)).unwrap();
        assert!(text.contains("\"proxy_type\": \"socks5\"") && text.contains("\"verify_upstream_tls\": true"), "{text}");
        assert!(text.contains("\"theme\": \"light\""), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(SETTINGS_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_and_out_of_range_files_are_fixed_up() {
        let dir = temp_dir("partial");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SETTINGS_FILE), r#"{"http_timeout_secs": 9999, "editor_font_size": 2.0, "unknown": 1}"#).unwrap();
        let s = UserSettings::load(&dir).unwrap();
        assert_eq!(s.http_timeout_secs, 120);
        assert_eq!(s.editor_font_size, 9.0);
        assert_eq!(s.theme, Look::Dark, "missing fields take the defaults");
        assert_eq!(s.proxy_read_timeout_secs, DEFAULT_PROXY_READ_TIMEOUT);
        // files from before the network settings: off, and certificates not checked
        assert_eq!(s.upstream_proxy, UpstreamProxyConfig::default());
        assert!(!s.upstream_proxy.enabled && !s.protocol.verify_upstream_tls);
        std::fs::write(dir.join(SETTINGS_FILE), "not json").unwrap();
        assert!(UserSettings::load(&dir).unwrap_err().contains("Using default settings"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
