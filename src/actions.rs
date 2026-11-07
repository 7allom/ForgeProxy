//! Request sending, the Intruder runner, and small parsing/diff helpers.

use crate::http::{self, History, HttpEntry};
use crate::intruder;
use crate::rewrite;
use crate::rules;
use crate::scan;
use crate::state::{App, IntResult, Job, Task, TaskKind};
use std::sync::{Arc, Mutex};

pub fn next_id(nid: &Arc<Mutex<usize>>) -> usize {
    let mut g = nid.lock().unwrap_or_else(|e| e.into_inner());
    *g += 1;
    *g
}

/// Send the active Repeater tab's request; the response comes back to that tab (by id),
/// whichever tab is showing by then.
pub fn send_repeater(app: &mut App) {
    if !app.rep().can_send() {
        return;
    }
    let tab = app.rep_mut();
    tab.waiting = true;
    tab.status_text = "Sending...".into();
    let tab_id = tab.id;
    let (method, _, headers, body) = parse_raw_request(&tab.request);
    // the request itself says where it goes (Host header + request line); the address bar
    // only supplies the scheme, and is updated to show the real destination
    let url = repeater_target(&tab.request, &tab.url);
    tab.url = url.clone();
    let req_sent = tab.request.clone();
    let htext = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n");
    let (htext, body2) = rewrite::apply(&app.mr_rules, true, &htext, &body);
    let hv = parse_headers(&htext);
    let rules_copy = app.mr_rules.clone();
    let follow = app.rep_follow;
    let unpack = app.rep_unpack;
    let opts = app.send_options();
    let tx = app.tx.clone();
    let hist = app.history.clone();
    let nid = app.next_id.clone();
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let mut r = http::send(&method, &url, &hv, &body2, follow, unpack, &opts);
        let elapsed_ms = started.elapsed().as_millis();
        let (rh, rb) = rewrite::apply(&rules_copy, false, &r.headers, &r.body);
        r.headers = rh;
        r.body = rb;
        let _ = record_bg_full(&hist, &nid, "Repeater", &method, &url, req_sent, &r);
        let _ = tx.send(Job::Repeater { tab: tab_id, result: r, elapsed_ms });
    });
}

/// "Send to Repeater": the request goes into a new tab (numbered after the others), which
/// is shown; existing tabs are left as they are.
pub fn send_to_repeater(app: &mut App, method: &str, url: &str, request: &str) {
    let fb = active_fallback_for(app, request);
    let target = HttpTarget::parse_or_infer(url, request.as_bytes(), fb.as_ref());
    let path = resolve_request_path(url, request);
    let full_url = format!("{}{path}", target.to_url());
    let method = request_method(request).unwrap_or_else(|| method.to_string());
    app.add_repeater_tab(&method, &full_url, request);
    app.tab = crate::state::Tab::Repeater;
}

/// Non-empty payload lines.
pub fn payload_lines(s: &str) -> Vec<String> {
    s.lines().filter(|l| !l.trim().is_empty()).map(|l| l.to_string()).collect()
}

/// Why the Intruder attack can't start yet, or None when it can.
pub fn attack_problem(app: &App) -> Option<String> {
    let target = app.int_target.trim();
    if !(target.starts_with("http://") || target.starts_with("https://")) || url_parts(target).1.is_empty() {
        return Some("Enter a target such as http://host:port".into());
    }
    if intruder::count_positions(&app.int_template) == 0 {
        return Some("Mark at least one payload position with § (Add § or Auto §)".into());
    }
    if payload_lines(&app.int_payloads).is_empty() {
        return Some("Enter at least one payload".into());
    }
    let two_sets = matches!(app.int_attack, intruder::AttackType::Pitchfork | intruder::AttackType::ClusterBomb);
    if two_sets && intruder::count_positions(&app.int_template) > 1 && payload_lines(&app.int_payloads_b).is_empty() {
        return Some("Enter at least one payload in payload set 2".into());
    }
    None
}

/// Stop the running attack and forget its results (they belong to the old request).
pub fn reset_attack(app: &mut App) {
    app.int_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    app.int_attack_id += 1;
    app.int_running = false;
    app.int_results.clear();
    app.int_total = 0;
    app.int_result_sel = None;
}

/// Run the Intruder attack with the default resource pool: up to 10 requests at once, no delay.
/// Each worker takes the next filled-in request, sends it to the target and reports the result
/// over the job channel; the attack window shows them as they arrive.
pub fn start_attack(app: &mut App) {
    if let Some(problem) = attack_problem(app) {
        app.int_msg = problem;
        return;
    }
    app.int_msg.clear();
    reset_attack(app);
    // the plan computes each request from its index on demand, so a large Cluster bomb is
    // never materialised in memory
    let plan = intruder::AttackPlan::from_two(app.int_attack, &app.int_template,
        &payload_lines(&app.int_payloads), &payload_lines(&app.int_payloads_b));
    if plan.is_empty() {
        app.int_msg = "These payloads produce no requests for this attack type".into();
        return;
    }
    // a fresh stop flag: the old one stays set for any worker still finishing
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    app.int_stop = stop.clone();
    let attack = app.int_attack_id;
    let total = plan.len();
    app.int_total = total;
    app.int_running = true;
    app.show_attack = true;
    let origin = origin_of(app.int_target.trim());
    let update_host = app.int_update_host;
    let plan = Arc::new(plan);
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let workers = app.int_concurrency.max(1).min(total);
    let delay = app.int_delay_ms;
    let opts = app.send_options();
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..workers {
        let (plan, next, done, origin, stop) = (plan.clone(), next.clone(), done.clone(), origin.clone(), stop.clone());
        let (tx, hist, nid) = (app.tx.clone(), app.history.clone(), app.next_id.clone());
        let opts = opts.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if i >= total {
                    break;
                }
                let (label, raw) = plan.request(i);
                // the target supplies scheme and host to connect to; the filled-in request supplies
                // method, path, headers and body (and the Host header when update_host is off)
                let (method, path, _, body) = parse_raw_request(&raw);
                let headers = intruder::dispatch_headers(&raw, update_host);
                let path = if path.starts_with('/') { path } else { format!("/{path}") };
                let full = format!("{origin}{path}");
                let r = http::send(&method, &full, &headers, &body, false, true, &opts);
                // keep the full substituted request (line, headers, body) so the results
                // inspector and "Copy as cURL" show exactly what was generated for this payload
                let history_id = record_bg_full(&hist, &nid, "Intruder", &method, &full, raw, &r);
                let result = IntResult {
                    request: i + 1,
                    payload: label,
                    status: if r.error.is_some() { String::new() } else { r.status.clone() },
                    length: r.length,
                    error: r.error.clone().unwrap_or_default(),
                    history_id,
                };
                let _ = tx.send(Job::Intruder { attack, result });
                if delay > 0 { std::thread::sleep(std::time::Duration::from_millis(delay)); }
            }
            if done.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == workers {
                let _ = tx.send(Job::IntruderDone { attack });
            }
        });
    }
}

/// Start a scan task: optional crawl of same-site links within the crawl limits,
/// passive checks on every page, then a benign marker check on the start page.
pub fn start_scan(app: &mut App, url: String, crawl: bool) {
    let task = app.tasks.len();
    app.tasks.push(Task {
        kind: TaskKind::Scan { crawl },
        url: url.clone(),
        capturing: false,
        running: true,
        requests: 0,
        findings: Vec::new(),
        log: vec![format!("Started {}", if crawl { "crawl and audit" } else { "audit" })],
    });
    app.task_sel = task;
    app.task_sub = 0;
    let (tx, hist, nid) = (app.tx.clone(), app.history.clone(), app.next_id.clone());
    let opts = app.send_options();
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let limit = std::time::Duration::from_secs(rules::CRAWL_MAX_TIME_MIN * 60);
        let mut findings = Vec::new();
        let mut queue = std::collections::VecDeque::from([(url.clone(), 0usize)]);
        let mut seen = std::collections::HashSet::from([url.clone()]);
        let mut requests = 0usize;
        while let Some((page, depth)) = queue.pop_front() {
            if requests >= rules::CRAWL_MAX_UNIQUE_LOCATIONS || started.elapsed() > limit {
                break;
            }
            requests += 1;
            let r = http::send("GET", &page, &[], "", rules::AUDIT_FOLLOW_REDIRECTS, true, &opts);
            let _ = record_bg(&hist, &nid, "Scanner", "GET", &page, &r);
            let (host, path) = http::split_url(&page);
            findings.extend(scan::passive_checks(&host, &path, page.starts_with("https"), &r.headers, &r.body));
            let _ = tx.send(Job::ScanProgress { task, requests, line: format!("GET {page} — {}", r.status) });
            if crawl && depth < rules::CRAWL_MAX_LINK_DEPTH {
                for link in scan::extract_links(&page, &r.body) {
                    if seen.insert(link.clone()) {
                        queue.push_back((link, depth + 1));
                    }
                }
            }
        }
        let (host, path) = http::split_url(&url);
        let marker = "fpx9q7z";
        let probe = if url.contains('?') { format!("{url}&q={marker}") } else { format!("{url}?q={marker}") };
        let pr = http::send("GET", &probe, &[], "", rules::AUDIT_FOLLOW_REDIRECTS, true, &opts);
        requests += 1;
        let _ = record_bg(&hist, &nid, "Scanner", "GET", &probe, &pr);
        let _ = tx.send(Job::ScanProgress { task, requests, line: format!("GET {probe} — {}", pr.status) });
        if scan::reflects_marker(&pr.body, marker) {
            findings.push(scan::Finding::new(scan::INPUT_REFLECTED, scan::Confidence::Certain, &host, &path,
                "A value sent in the query string came back unchanged in the page. That is the first condition \
                 for reflected cross-site scripting; check how this value is encoded."));
        }
        if let Some(sig) = scan::sql_error_signature(&pr.body) {
            findings.push(scan::Finding::new(scan::SQL_INJECTION, scan::Confidence::Tentative, &host, &path,
                &format!("The page showed a database error message ({sig}). That can point to SQL injection and \
                          also reveals details about the database.")));
        }
        let _ = tx.send(Job::ScanDone { task, findings: scan::consolidate(findings) });
    });
}

pub fn origin_of(url: &str) -> String {
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    match url[scheme_end..].find('/') {
        Some(i) => url[..scheme_end + i].to_string(),
        None => url.trim_end_matches('/').to_string(),
    }
}

/// An absolute URL split into (scheme, authority, path-and-query). The path defaults to "/",
/// a missing scheme comes back empty and any #fragment is dropped.
pub fn url_parts(url: &str) -> (String, String, String) {
    let url = url.trim();
    let url = url.split('#').next().unwrap_or(url);
    let (scheme, rest) = match url.find("://") {
        Some(i) => (url[..i].to_ascii_lowercase(), &url[i + 3..]),
        None => (String::new(), url),
    };
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(cut);
    let path = if path.is_empty() { "/".to_string() } else if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
    (scheme, authority.to_string(), path)
}

/// Index of each header line of a raw request (between the request line and the blank line).
fn header_lines(lines: &[&str]) -> std::ops::Range<usize> {
    let end = lines.iter().skip(1).position(|l| l.trim().is_empty()).map(|i| i + 1).unwrap_or(lines.len());
    1.min(end)..end
}

/// Value of the request's Host header, if it has a non-empty one.
pub fn host_header(raw: &str) -> Option<String> {
    let lines: Vec<&str> = raw.split('\n').collect();
    lines[header_lines(&lines)].iter().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case("host") && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

/// Set the Host header (replacing the first one, or adding it after the request line).
pub fn set_host_header(raw: &str, authority: &str) -> String {
    let mut lines: Vec<String> = raw.split('\n').map(String::from).collect();
    let refs: Vec<&str> = lines.iter().map(|l| l.as_str()).collect();
    let range = header_lines(&refs);
    let found = range.clone().find(|&i| lines[i].split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("host")));
    match found {
        Some(i) => {
            let cr = if lines[i].ends_with('\r') { "\r" } else { "" };
            lines[i] = format!("Host: {authority}{cr}");
        }
        None if !lines.is_empty() => {
            let cr = if lines[0].ends_with('\r') { "\r" } else { "" };
            lines.insert(1, format!("Host: {authority}{cr}"));
        }
        None => {}
    }
    lines.join("\n")
}

/// The request-line target ("/path?query", or an absolute URL), if the line has one.
pub fn request_target(raw: &str) -> Option<String> {
    raw.lines().next()?.split_whitespace().nth(1).map(String::from)
}

/// The request line's method ("GET"), if it has one.
pub fn request_method(raw: &str) -> Option<String> {
    raw.lines().next()?.split_whitespace().next().map(String::from)
}

/// Replace the request-line method, keeping the target, version and everything else.
pub fn set_request_method(raw: &str, method: &str) -> String {
    let (first, rest) = match raw.split_once('\n') { Some((f, r)) => (f, Some(r)), None => (raw, None) };
    let cr = if first.ends_with('\r') { "\r" } else { "" };
    let line = first.trim_end_matches('\r');
    let after = line.trim_start().split_once(char::is_whitespace).map(|(_, a)| a).unwrap_or("");
    let line = if after.is_empty() { method.to_string() } else { format!("{method} {after}") };
    match rest {
        Some(r) => format!("{line}{cr}\n{r}"),
        None => format!("{line}{cr}"),
    }
}

/// Replace the request-line target, keeping the method and HTTP version.
pub fn set_request_target(raw: &str, target: &str) -> String {
    let (first, rest) = match raw.split_once('\n') { Some((f, r)) => (f, Some(r)), None => (raw, None) };
    let cr = if first.ends_with('\r') { "\r" } else { "" };
    let parts: Vec<&str> = first.trim_end_matches('\r').split_whitespace().collect();
    if parts.len() < 2 {
        return raw.to_string();
    }
    let mut line = format!("{} {target}", parts[0]);
    for p in &parts[2..] {
        line.push(' ');
        line.push_str(p);
    }
    match rest {
        Some(r) => format!("{line}{cr}\n{r}"),
        None => format!("{line}{cr}"),
    }
}

/// Where a Repeater request goes: the authority from its Host header and the path from its
/// request line (an absolute-form request line wins outright). The scheme comes from the
/// Host port when it is 80 or 443, otherwise from `url` (the address bar), else http.
/// Without a Host header the address bar's authority is used.
pub fn repeater_target(raw: &str, url: &str) -> String {
    let (bar_scheme, bar_authority, bar_path) = url_parts(url);
    let target = request_target(raw).unwrap_or_default();
    if target.starts_with("http://") || target.starts_with("https://") {
        let (s, a, p) = url_parts(&target);
        return format!("{s}://{a}{p}");
    }
    // origin-form path; authority-form (CONNECT host:port) and "*" fall back to the address bar
    let path = if target.starts_with('/') { target } else { bar_path };
    let authority = host_header(raw).unwrap_or(bar_authority);
    let scheme = match authority.rsplit_once(':').map(|(_, port)| port) {
        Some("443") => "https".to_string(),
        Some("80") => "http".to_string(),
        _ if !bar_scheme.is_empty() => bar_scheme,
        _ => "http".to_string(),
    };
    format!("{scheme}://{authority}{path}")
}

pub fn parse_raw_request(raw: &str) -> (String, String, Vec<(String, String)>, String) {
    let (head, body) = raw.split_once("\n\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("GET / HTTP/1.1");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| !k.trim().eq_ignore_ascii_case("host") && !k.trim().eq_ignore_ascii_case("content-length"))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (method, path, headers, body.to_string())
}

pub fn parse_headers(s: &str) -> Vec<(String, String)> {
    s.lines().filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect()
}

/// Record a request sent by a tool; returns its history id.
pub fn record_bg(hist: &History, nid: &Arc<Mutex<usize>>, tool: &str, method: &str, url: &str, r: &http::SendResult) -> usize {
    record_bg_full(hist, nid, tool, method, url, format!("{method} {url}"), r)
}

/// As [`record_bg`], but stores `request` verbatim: the full raw HTTP request (request line,
/// headers and body) actually sent, so the history viewer shows exactly what went over the
/// wire rather than just "METHOD url".
pub fn record_bg_full(hist: &History, nid: &Arc<Mutex<usize>>, tool: &str, method: &str, url: &str, request: String, r: &http::SendResult) -> usize {
    let (host, path) = http::split_url(url);
    let id = next_id(nid);
    hist.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::new(HttpEntry {
        id,
        tool: tool.into(),
        method: method.into(),
        host,
        path,
        status: r.status.clone(),
        length: r.length,
        mime: r.mime.clone(),
        request,
        response: format!("{}\n{}\n\n{}", r.status, r.headers, r.body),
        url: url.to_string(),
        truncated: false,
        time: http::now_ms(),
    }));
    id
}

/// "Send to Decoder": the text becomes the Decoder's input (a JWT is also loaded into the
/// JWT Inspector, and the Transform view offers to open it).
pub fn send_text_to_decoder(app: &mut App, text: String) {
    use crate::state::{DecBlock, Tab};
    if crate::codec::is_jwt(&text) {
        app.jwt_input = text.trim().to_string();
    }
    app.dec_raw = vec![text.as_bytes().to_vec()];
    app.dec_hex_input = crate::ui_tools::format_hex_bytes(text.as_bytes());
    app.dec_hex_error = None;
    app.dec_blocks = vec![DecBlock { text, hex: false, label: None, color: eframe::egui::Color32::TRANSPARENT }];
    app.dec_view = 0;
    app.tab = Tab::Decoder;
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SendTo { Repeater, Intruder, Sequencer, Comparer, ComparerRequest, Decoder, Organizer, Scope }

/// Split an authority (`host:port`, `[::1]:8888`, or `host`) into `(hostname, Option<port>)`.
pub fn split_host_port(auth: &str) -> (&str, Option<&str>) {
    let auth = auth.trim();
    if let Some(rest) = auth.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let host = &auth[..=idx + 1];
            let port = rest[idx + 1..].strip_prefix(':').filter(|p| !p.is_empty());
            return (host, port);
        }
    }
    match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && !p.is_empty() => (h, Some(p)),
        _ => (auth, None),
    }
}

/// Unified HTTP/HTTPS target endpoint (`scheme://host[:port]`) resolved across all tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTarget {
    pub is_tls: bool,
    pub host: String,
    pub port: u16,
}

impl HttpTarget {
    /// Format this target as an origin URL (`http://host[:port]` or `https://host[:port]`),
    /// omitting the port only when it matches the scheme's default (80 for HTTP, 443 for HTTPS).
    pub fn to_url(&self) -> String {
        let scheme = if self.is_tls { "https" } else { "http" };
        let default_port = if self.is_tls { 443 } else { 80 };
        let bare = self.host.trim_start_matches('[').trim_end_matches(']');
        let host_fmt = if bare.contains(':') {
            format!("[{bare}]")
        } else {
            bare.to_string()
        };
        if self.port == default_port {
            format!("{scheme}://{host_fmt}")
        } else {
            format!("{scheme}://{host_fmt}:{}", self.port)
        }
    }

    /// Resolve an [`HttpTarget`] from a source URL, raw HTTP request bytes, and an optional
    /// fallback target context.
    ///
    /// Resolution precedence:
    /// 1. An absolute-form request line (`GET http://...` or `GET https://...`) in `raw_http`.
    /// 2. Explicit `url` scheme (`http://` vs `https://`) combined with `Host:` header / URL
    ///    authority, ignoring Repeater's untouched `DEFAULT_REP_URL` placeholder when `Host:`
    ///    points to a different host.
    /// 3. Port-inferred scheme (`443` -> `https`, `80`/`8080`/`8888`/etc. -> `http`) or
    ///    inheritance from `fallback` when targeting the same host.
    pub fn parse_or_infer(url: &str, raw_http: &[u8], fallback: Option<&HttpTarget>) -> Self {
        let raw_str = String::from_utf8_lossy(raw_http);
        let clean_req = raw_str.replace('§', "");

        if let Some(req_target) = request_target(&clean_req) {
            if req_target.starts_with("http://") || req_target.starts_with("https://") {
                let (s, a, _) = url_parts(&req_target);
                let (h, p_opt) = split_host_port(&a);
                let bare_h = h.trim_start_matches('[').trim_end_matches(']').to_string();
                if !bare_h.is_empty() {
                    let is_tls = s == "https";
                    let default_port = if is_tls { 443 } else { 80 };
                    let port = p_opt.and_then(|p| p.parse::<u16>().ok()).unwrap_or(default_port);
                    return HttpTarget {
                        is_tls,
                        host: bare_h,
                        port,
                    };
                }
            }
        }

        let req_host_raw = host_header(&clean_req)
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        let req_parsed: Option<(String, Option<u16>)> = req_host_raw.as_deref().and_then(|rh| {
            let (h, p_opt) = split_host_port(rh);
            let bare = h.trim_start_matches('[').trim_end_matches(']').to_string();
            (!bare.is_empty()).then(|| (bare, p_opt.and_then(|p| p.parse::<u16>().ok())))
        });

        let (bar_scheme, bar_authority, _) = url_parts(url);
        let (bar_h_raw, bar_p_str) = split_host_port(&bar_authority);
        let bar_host = bar_h_raw.trim_start_matches('[').trim_end_matches(']').to_string();
        let bar_port: Option<u16> = bar_p_str.and_then(|p| p.parse::<u16>().ok());

        let is_stale_default_rep = url.trim() == crate::state::DEFAULT_REP_URL
            && req_parsed
                .as_ref()
                .is_some_and(|(rh, _)| !rh.eq_ignore_ascii_case("example.com"));

        let bar_matches_req_host = match (&req_parsed, bar_host.is_empty()) {
            (Some((rh, _)), false) => rh.eq_ignore_ascii_case(&bar_host),
            (None, false) => true,
            _ => false,
        };

        let (host, explicit_port) = if let Some((rh, rp)) = req_parsed {
            let port = if rp.is_some() {
                rp
            } else if !is_stale_default_rep && bar_matches_req_host && bar_port.is_some() {
                bar_port
            } else if let Some(fb) = fallback.filter(|fb| fb.host.eq_ignore_ascii_case(&rh)) {
                Some(fb.port)
            } else {
                None
            };
            (rh, port)
        } else if !bar_host.is_empty() && !is_stale_default_rep {
            let port = bar_port.or_else(|| {
                fallback
                    .filter(|fb| fb.host.eq_ignore_ascii_case(&bar_host))
                    .map(|fb| fb.port)
            });
            (bar_host, port)
        } else if let Some(fb) = fallback {
            return fb.clone();
        } else {
            return HttpTarget {
                is_tls: false,
                host: "localhost".to_string(),
                port: 80,
            };
        };

        let has_known_bar_scheme =
            !is_stale_default_rep && (bar_scheme == "http" || bar_scheme == "https");

        if has_known_bar_scheme && (bar_matches_req_host || req_host_raw.is_none()) {
            let is_tls = bar_scheme == "https";
            let default_port = if is_tls { 443 } else { 80 };
            let port = explicit_port.unwrap_or(default_port);
            return HttpTarget { is_tls, host, port };
        }

        let fb_match = fallback.filter(|fb| {
            fb.host.eq_ignore_ascii_case(&host)
                && (explicit_port.is_none() || explicit_port == Some(fb.port))
        });

        let (is_tls, port) = match explicit_port {
            Some(443) => (fb_match.map_or(true, |fb| fb.is_tls), 443),
            Some(80) => (fb_match.map_or(false, |fb| fb.is_tls), 80),
            Some(p) => (fb_match.map_or(false, |fb| fb.is_tls), p),
            None => match fb_match {
                Some(fb) => (fb.is_tls, fb.port),
                None => (false, 80),
            },
        };

        HttpTarget { is_tls, host, port }
    }
}

fn active_fallback_for(app: &App, request: &str) -> Option<HttpTarget> {
    let clean = request.replace('§', "");
    let req_host = host_header(&clean).map(|h| {
        split_host_port(&h)
            .0
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    });
    let mut candidates = Vec::new();
    let int_u = app.int_target.trim();
    if !int_u.is_empty() && int_u != crate::state::DEFAULT_INT_TARGET {
        candidates.push(HttpTarget::parse_or_infer(int_u, b"", None));
    }
    if let Some(tab) = app.repeater_tabs.get(app.active_repeater_tab) {
        let u = tab.url.trim();
        if !u.is_empty() && u != crate::state::DEFAULT_REP_URL {
            candidates.push(HttpTarget::parse_or_infer(u, b"", None));
        }
    }
    if let Some(rh) = &req_host {
        if let Some(matched) = candidates.iter().find(|c| c.host.eq_ignore_ascii_case(rh)) {
            return Some(matched.clone());
        }
    }
    candidates.into_iter().next()
}

fn resolve_request_path(url: &str, request: &str) -> String {
    let clean = request.replace('§', "");
    let (_, _, bar_path) = url_parts(url);
    let target = request_target(&clean).unwrap_or_default();
    if target.starts_with("http://") || target.starts_with("https://") {
        url_parts(&target).2
    } else if target.starts_with('/') {
        target
    } else {
        bar_path
    }
}

/// Resolve the target origin (`scheme://host[:port]`) using [`HttpTarget::parse_or_infer`].
pub fn resolve_target_origin(app: &App, url: &str, request: &str) -> String {
    let fb = active_fallback_for(app, request);
    HttpTarget::parse_or_infer(url, request.as_bytes(), fb.as_ref()).to_url()
}

/// "Send to Intruder": populates the Intruder target and request template from a raw request
/// and switches to the Intruder tab, resolving the target through [`HttpTarget::parse_or_infer`].
pub fn send_to_intruder(app: &mut App, url: &str, request: &str) {
    let fb = active_fallback_for(app, request);
    let target = HttpTarget::parse_or_infer(url, request.as_bytes(), fb.as_ref());
    app.int_target = target.to_url();
    app.int_template = request.to_string();
    // results of the previous attack belong to the previous request
    reset_attack(app);
    app.int_sel = None;
    app.tab = crate::state::Tab::Intruder;
}

/// "Send to Sequencer": populates the Sequencer live-capture request template and target origin,
/// resets any previous token collection, and switches to the Sequencer tab.
pub fn send_to_sequencer(app: &mut App, url: &str, request: &str) {
    let fb = active_fallback_for(app, request);
    let target = HttpTarget::parse_or_infer(url, request.as_bytes(), fb.as_ref());
    app.seq_origin = target.to_url();
    app.seq_template = request.to_string();
    app.seq_samples.clear();
    app.seq_analysis = None;
    app.seq_message.clear();
    app.seq_sub = 0;
    app.tab = crate::state::Tab::Sequencer;
}

/// "Send to Organizer": stores the request/response in the Organizer inbox and switches to Organizer.
pub fn send_to_organizer(app: &mut App, url: &str, request: &str, response: &str) {
    use crate::state::{OrgItem, OrgStatus, Tab};
    let fb = active_fallback_for(app, request);
    let target = HttpTarget::parse_or_infer(url, request.as_bytes(), fb.as_ref());
    let path = resolve_request_path(url, request);
    let full_url = format!("{}{path}", target.to_url());
    let (host, path) = http::split_url(&full_url);
    let method = request_method(request).unwrap_or_else(|| "GET".to_string());
    app.organizer.push(OrgItem {
        method,
        host,
        path,
        note: String::new(),
        highlight: None,
        status: OrgStatus::New,
        request: request.to_string(),
        response: response.to_string(),
        url: full_url,
    });
    app.tab = Tab::Organizer;
}

/// Full raw HTTP request for an Organizer item (synthesizing a minimal HTTP/1.1 request if
/// loaded from an older project file that only stored method/host/path).
pub fn org_item_request(it: &crate::state::OrgItem) -> String {
    if !it.request.trim().is_empty() {
        return it.request.clone();
    }
    let path = if it.path.is_empty() { "/".to_string() } else { it.path.clone() };
    format!("{} {} HTTP/1.1\nHost: {}\nUser-Agent: {}\nAccept: */*\nConnection: close\n\n", it.method, path, it.host, http::USER_AGENT)
}

/// Target URL for an Organizer item.
pub fn org_item_url(it: &crate::state::OrgItem) -> String {
    if !it.url.trim().is_empty() {
        return it.url.clone();
    }
    format!("http://{}{}", it.host, if it.path.is_empty() { "/" } else { &it.path })
}

/// "Proxy history", "Repeater history"... for labels of items taken from history.
pub fn history_name(e: &HttpEntry) -> String {
    format!("{} history", e.tool)
}

/// Turn a recorded entry into a full raw request (Proxy entries already are one).
pub fn raw_request(e: &HttpEntry) -> String {
    let first = e.request.lines().next().unwrap_or("");
    if first.split_whitespace().count() >= 3 {
        return e.request.clone();
    }
    let path = if e.path.is_empty() { "/".to_string() } else { e.path.clone() };
    format!("{} {} HTTP/1.1\nHost: {}\nUser-Agent: {}\nAccept: */*\nConnection: close\n\n", e.method, path, e.host, http::USER_AGENT)
}

/// File any history entries recorded since the last call into `app.site_map`. Runs on the UI
/// thread (background threads record straight into the shared history, which has no `App`), so
/// it works incrementally from a cursor; a shrunken history (a project load or clear) rebuilds
/// the map from scratch.
pub fn sync_site_map(app: &mut App) {
    let (rebuild, snapshot) = {
        let hist = app.history.lock().unwrap_or_else(|e| e.into_inner());
        let len = hist.len();
        let rebuild = app.site_map_cursor > len;
        let start = if rebuild { 0 } else { app.site_map_cursor };
        let snap: Vec<(String, usize, String, String)> = hist[start..]
            .iter()
            .map(|e| (entry_url(e), e.id, e.method.clone(), e.status.clone()))
            .collect();
        app.site_map_cursor = len;
        (rebuild, snap)
    };
    if rebuild {
        app.site_map = crate::target::SiteMap::default();
    }
    for (url, id, method, status) in snapshot {
        app.site_map.insert_url(&url, id, &method, Some(&status));
    }
}

/// A recorded entry as a runnable `curl` command (for "Copy as cURL").
pub fn entry_as_curl(e: &HttpEntry) -> String {
    crate::export::to_curl(&raw_request(e), &origin_of(&entry_url(e)))
}

pub fn entry_url(e: &HttpEntry) -> String {
    if !e.url.is_empty() {
        return e.url.clone();
    }
    format!("http://{}{}", e.host, if e.path.is_empty() { "/" } else { &e.path })
}

pub fn send_to(app: &mut App, e: &HttpEntry, to: SendTo) {
    use crate::state::Tab;
    match to {
        SendTo::Repeater => send_to_repeater(app, &e.method, &entry_url(e), &raw_request(e)),
        SendTo::Intruder => send_to_intruder(app, &entry_url(e), &raw_request(e)),
        SendTo::Sequencer => send_to_sequencer(app, &entry_url(e), &raw_request(e)),
        SendTo::Comparer => {
            crate::comparer::add(app, format!("{} #{} (Response)", history_name(e), e.id), e.response.as_bytes());
            app.tab = Tab::Comparer;
        }
        SendTo::ComparerRequest => {
            crate::comparer::add(app, format!("{} #{} (Request)", history_name(e), e.id), raw_request(e).as_bytes());
            app.tab = Tab::Comparer;
        }
        SendTo::Decoder => {
            let text = if !e.request.trim().is_empty() { raw_request(e) } else { e.response.clone() };
            send_text_to_decoder(app, text);
        }
        SendTo::Organizer => send_to_organizer(app, &entry_url(e), &raw_request(e), &e.response),
        SendTo::Scope => app.target_scope.add(&scope_prefix(e)),
    }
}

/// The scope prefix for an entry: its origin ("https://host:port/").
pub fn scope_prefix(e: &HttpEntry) -> String {
    origin_of(&entry_url(e)) + "/"
}

/// Sequencer live capture: send the chosen request repeatedly with the configured number of
/// threads (ProjectDefaults: 5) and collect a token from each response.
pub fn start_sequencer(app: &mut App) {
    if app.seq_template.trim().is_empty() {
        return;
    }
    app.seq_running = true;
    app.seq_message.clear();
    app.seq_stop.store(false, std::sync::atomic::Ordering::SeqCst);
    let (method, path, headers, body) = parse_raw_request(&app.seq_template);
    let url = format!("{}{}", app.seq_origin, path);
    let location = app.seq_location.clone();
    let target = app.seq_target_samples.max(1).min(crate::sequencer::MAX_TOKENS);
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(app.seq_samples.len()));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let threads = app.sequencer_threads.max(1);
    let opts = app.send_options();
    for _ in 0..threads {
        let (tx, stop, count, done) = (app.tx.clone(), app.seq_stop.clone(), count.clone(), done.clone());
        let (method, url, headers, body, location) = (method.clone(), url.clone(), headers.clone(), body.clone(), location.clone());
        let opts = opts.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) && count.load(std::sync::atomic::Ordering::SeqCst) < target {
                let r = http::send(&method, &url, &headers, &body, false, true, &opts);
                let full = format!("{}\n{}\n\n{}", r.status, r.headers, r.body);
                match crate::sequencer::extract_token(&location, &full) {
                    Some(t) => {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = tx.send(Job::SeqToken(t));
                    }
                    None => {
                        let _ = tx.send(Job::SeqMiss(r.status.clone()));
                        break;
                    }
                }
            }
            if done.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == threads {
                let _ = tx.send(Job::SeqDone);
            }
        });
    }
}

/// Dispatch a background Collaborator poll for all generated payloads via `Job::CollabPoll`.
pub fn poll_collaborator(app: &mut App) {
    let server = app.collab_server.trim().to_string();
    if server.is_empty() {
        app.collab_msg = "No Collaborator server set.".into();
        return;
    }
    if app.collab_polling {
        return;
    }
    app.collab_polling = true;
    app.collab_msg = format!("Polling {server}…");
    let payloads = app.collab_payloads.clone();
    let opts = app.send_options();
    let tx = app.tx.clone();
    std::thread::spawn(move || {
        let res = crate::collab::poll_all(&server, &payloads, &opts);
        let _ = tx.send(Job::CollabPoll(res));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &str = "GET /a?b=1 HTTP/1.1\nHost: shop.test:8080\nAccept: */*\n\nbody: not a header";

    #[test]
    fn url_parts_splits() {
        assert_eq!(url_parts("https://ex.com"), ("https".into(), "ex.com".into(), "/".into()));
        assert_eq!(url_parts("http://h:81/p/q?x=1#f"), ("http".into(), "h:81".into(), "/p/q?x=1".into()));
        assert_eq!(url_parts("h.test?x"), ("".into(), "h.test".into(), "/?x".into()));
    }

    #[test]
    fn host_header_read_and_write() {
        assert_eq!(host_header(REQ).as_deref(), Some("shop.test:8080"));
        let r = set_host_header(REQ, "other.test");
        assert_eq!(host_header(&r).as_deref(), Some("other.test"));
        assert!(r.ends_with("\n\nbody: not a header"));
        // no Host header: added straight after the request line, CRLF kept
        let r = set_host_header("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", "n.test");
        assert_eq!(r, "GET / HTTP/1.1\r\nHost: n.test\r\nAccept: */*\r\n\r\n");
        // a "host:" line in the body is not a header
        assert_eq!(host_header("GET / HTTP/1.1\n\nHost: body.test"), None);
    }

    #[test]
    fn request_target_read_and_write() {
        assert_eq!(request_target(REQ).as_deref(), Some("/a?b=1"));
        let r = set_request_target(REQ, "/z");
        assert!(r.starts_with("GET /z HTTP/1.1\nHost: shop.test:8080\n"));
        assert_eq!(set_request_target("garbage", "/z"), "garbage");
    }

    #[test]
    fn request_method_read_and_write() {
        assert_eq!(request_method(REQ).as_deref(), Some("GET"));
        let r = set_request_method(REQ, "POST");
        assert!(r.starts_with("POST /a?b=1 HTTP/1.1\nHost: shop.test:8080\n"));
        assert!(r.ends_with("\n\nbody: not a header"));
        // CRLF kept, lone method replaced, empty request gets one
        assert_eq!(set_request_method("GET / HTTP/1.1\r\nHost: x\r\n", "PUT"), "PUT / HTTP/1.1\r\nHost: x\r\n");
        assert_eq!(set_request_method("GET", "HEAD"), "HEAD");
        assert_eq!(set_request_method("", "GET"), "GET");
        assert_eq!(request_method(""), None);
    }

    #[test]
    fn repeater_target_follows_the_request() {
        // Host header wins over a stale address bar
        assert_eq!(repeater_target(REQ, "https://example.com/"), "https://shop.test:8080/a?b=1");
        // request line "/" means "/", not the address bar's path
        assert_eq!(repeater_target("GET / HTTP/1.1\nHost: h.test\n\n", "http://h.test/old/path"), "http://h.test/");
        // well-known ports pick the scheme
        assert_eq!(repeater_target("GET /x HTTP/1.1\nHost: h.test:443\n\n", "http://h.test/"), "https://h.test:443/x");
        // no Host header: the address bar's host
        assert_eq!(repeater_target("GET /x HTTP/1.1\n\n", "https://bar.test/"), "https://bar.test/x");
        // absolute-form request line
        assert_eq!(repeater_target("GET http://abs.test/p HTTP/1.1\nHost: x\n\n", "https://bar.test/"), "http://abs.test/p");
        // CONNECT entries from the proxy keep the address bar's path
        assert_eq!(repeater_target("CONNECT t.test:443 HTTP/1.1\nHost: t.test:443", "https://t.test/"), "https://t.test:443/");
    }

    // ---- Intruder runner (thread pool over the lazy plan) ----

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// A minimal HTTP/1.1 server that records each request line and answers "ok". Handles
    /// connections concurrently, so a pooled attack is served in parallel.
    fn test_http_server() -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let log = log.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
                        buf.push(byte[0]);
                    }
                    let first = String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string();
                    log.lock().unwrap().push(first);
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                });
            }
        });
        (port, seen)
    }

    fn test_app() -> (egui::Context, App) {
        crate::test_utils::MockAppBuilder::new().build_with_ctx()
    }

    /// Run update frames until the attack finishes (or a generous timeout).
    fn drain_attack(ctx: &egui::Context, app: &mut App, expected: usize) {
        for _ in 0..600 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| eframe::App::update(app, ctx, &mut eframe::Frame::_new_kittest()));
            if app.int_results.len() >= expected && !app.int_running {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn payloads_hit(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        let mut v: Vec<String> = seen.lock().unwrap().iter()
            .filter_map(|l| l.split("x=").nth(1).and_then(|s| s.split_whitespace().next()).map(str::to_string))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn pool_runs_every_planned_request_once() {
        let (port, seen) = test_http_server();
        let (ctx, mut app) = test_app();
        app.int_target = format!("http://127.0.0.1:{port}");
        app.int_template = "GET /p?x=§v§ HTTP/1.1\nHost: 127.0.0.1\n\n".into();
        app.int_attack = intruder::AttackType::Sniper;
        app.int_payloads = "a\nb\nc\nd\ne".into();
        app.int_concurrency = 3;
        app.int_delay_ms = 0;
        start_attack(&mut app);
        assert_eq!(app.int_total, 5);
        assert!(app.int_running);
        drain_attack(&ctx, &mut app, 5);
        assert_eq!(app.int_results.len(), 5, "every request produced a result");
        assert!(!app.int_running, "the pool finished");
        assert_eq!(payloads_hit(&seen), ["a", "b", "c", "d", "e"], "each payload reached the server once");
    }

    #[test]
    fn result_stores_the_full_substituted_request() {
        let (port, _seen) = test_http_server();
        let (ctx, mut app) = test_app();
        app.int_target = format!("http://127.0.0.1:{port}");
        app.int_template = "POST /p HTTP/1.1\nHost: 127.0.0.1\nX-Marker: keepme\n\nbody=§v§".into();
        app.int_attack = intruder::AttackType::Sniper;
        app.int_payloads = "alpha\nbeta".into();
        app.int_concurrency = 1;
        app.int_delay_ms = 0;
        start_attack(&mut app);
        drain_attack(&ctx, &mut app, 2);
        assert_eq!(app.int_results.len(), 2);

        // the recorded history entry holds the full raw request: request line, the custom
        // header, and the substituted body (not just "METHOD url")
        let hist = app.history.lock().unwrap();
        let mut requests: Vec<String> = app
            .int_results
            .iter()
            .map(|res| hist.iter().find(|e| e.id == res.history_id).unwrap().request.clone())
            .collect();
        requests.sort();
        assert!(requests[0].starts_with("POST /p HTTP/1.1"), "{}", requests[0]);
        assert!(requests.iter().all(|r| r.contains("X-Marker: keepme")), "custom header kept: {requests:?}");
        assert!(requests[0].contains("body=alpha") && requests[1].contains("body=beta"), "bodies substituted: {requests:?}");
    }

    #[test]
    fn throttle_delay_still_sends_all_requests() {
        let (port, seen) = test_http_server();
        let (ctx, mut app) = test_app();
        app.int_target = format!("http://127.0.0.1:{port}");
        app.int_template = "GET /p?x=§v§ HTTP/1.1\nHost: 127.0.0.1\n\n".into();
        app.int_attack = intruder::AttackType::Sniper;
        app.int_payloads = "1\n2\n3".into();
        app.int_concurrency = 1; // single worker so the delay actually paces it
        app.int_delay_ms = 10;
        let start = std::time::Instant::now();
        start_attack(&mut app);
        drain_attack(&ctx, &mut app, 3);
        assert_eq!(app.int_results.len(), 3);
        assert_eq!(payloads_hit(&seen), ["1", "2", "3"]);
        // a per-request delay means the whole run took at least a couple of delays
        assert!(start.elapsed() >= std::time::Duration::from_millis(20), "the delay paced the requests");
    }

    #[test]
    fn stopping_halts_the_pool_early() {
        let (port, _seen) = test_http_server();
        let (ctx, mut app) = test_app();
        app.int_target = format!("http://127.0.0.1:{port}");
        app.int_template = "GET /p?x=§v§ HTTP/1.1\nHost: 127.0.0.1\n\n".into();
        app.int_attack = intruder::AttackType::Sniper;
        app.int_payloads = (0..500).map(|n| n.to_string()).collect::<Vec<_>>().join("\n");
        app.int_concurrency = 2;
        start_attack(&mut app);
        assert_eq!(app.int_total, 500);
        app.int_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        drain_attack(&ctx, &mut app, 500);
        assert!(!app.int_running, "stopped");
        assert!(app.int_results.len() < 500, "not every request ran after Stop");
    }

    #[test]
    fn http_target_parse_or_infer_matrix() {
        use crate::assert_table;

        struct Case<'a> {
            desc: &'a str,
            url: &'a str,
            raw_http: &'a [u8],
            fallback: Option<HttpTarget>,
            expected: HttpTarget,
            expected_url: &'a str,
        }

        let cases = [
            Case {
                desc: "explicit http URL with custom port",
                url: "http://127.0.0.1:8888/login",
                raw_http: b"POST /login HTTP/1.1\nHost: 127.0.0.1:8888\n\nuser=admin",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "127.0.0.1".into(), port: 8888 },
                expected_url: "http://127.0.0.1:8888",
            },
            Case {
                desc: "explicit https URL on custom port",
                url: "https://127.0.0.1:8888/login",
                raw_http: b"POST /login HTTP/1.1\nHost: 127.0.0.1:8888\n\nuser=admin",
                fallback: None,
                expected: HttpTarget { is_tls: true, host: "127.0.0.1".into(), port: 8888 },
                expected_url: "https://127.0.0.1:8888",
            },
            Case {
                desc: "explicit https URL on default port 443 omits port in to_url",
                url: "https://example.com/api",
                raw_http: b"",
                fallback: None,
                expected: HttpTarget { is_tls: true, host: "example.com".into(), port: 443 },
                expected_url: "https://example.com",
            },
            Case {
                desc: "explicit http URL on default port 80 omits port in to_url",
                url: "http://example.com/api",
                raw_http: b"",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "example.com".into(), port: 80 },
                expected_url: "http://example.com",
            },
            Case {
                desc: "explicit http scheme on port 443 is preserved",
                url: "http://target.local:443/",
                raw_http: b"GET / HTTP/1.1\nHost: target.local:443\n\n",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "target.local".into(), port: 443 },
                expected_url: "http://target.local:443",
            },
            Case {
                desc: "port-inferred https from schemeless authority :443",
                url: "api.internal:443/v1",
                raw_http: b"",
                fallback: None,
                expected: HttpTarget { is_tls: true, host: "api.internal".into(), port: 443 },
                expected_url: "https://api.internal",
            },
            Case {
                desc: "port-inferred http from schemeless authority :8080",
                url: "api.internal:8080/v1",
                raw_http: b"",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "api.internal".into(), port: 8080 },
                expected_url: "http://api.internal:8080",
            },
            Case {
                desc: "raw HTTP bytes with Host: 127.0.0.1:8888 and empty URL infers http",
                url: "",
                raw_http: b"POST /login HTTP/1.1\nHost: 127.0.0.1:8888\n\nuser=admin",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "127.0.0.1".into(), port: 8888 },
                expected_url: "http://127.0.0.1:8888",
            },
            Case {
                desc: "raw HTTP bytes with custom port Host: internal.corp:8443 and TLS fallback on same host",
                url: "",
                raw_http: b"GET /admin HTTP/1.1\nHost: internal.corp:8443\n\n",
                fallback: Some(HttpTarget { is_tls: true, host: "internal.corp".into(), port: 8443 }),
                expected: HttpTarget { is_tls: true, host: "internal.corp".into(), port: 8443 },
                expected_url: "https://internal.corp:8443",
            },
            Case {
                desc: "raw HTTP bytes with Host header without port inherits fallback scheme and port on same host",
                url: "",
                raw_http: b"POST /login HTTP/1.1\nHost: 127.0.0.1\n\nuser=admin",
                fallback: Some(HttpTarget { is_tls: true, host: "127.0.0.1".into(), port: 8888 }),
                expected: HttpTarget { is_tls: true, host: "127.0.0.1".into(), port: 8888 },
                expected_url: "https://127.0.0.1:8888",
            },
            Case {
                desc: "untouched DEFAULT_REP_URL does not force https onto pasted local HTTP request",
                url: crate::state::DEFAULT_REP_URL,
                raw_http: b"POST /login HTTP/1.1\nHost: 127.0.0.1:8888\n\nuser=admin",
                fallback: Some(HttpTarget { is_tls: true, host: "example.com".into(), port: 443 }),
                expected: HttpTarget { is_tls: false, host: "127.0.0.1".into(), port: 8888 },
                expected_url: "http://127.0.0.1:8888",
            },
            Case {
                desc: "IPv6 host and port in raw Host header",
                url: "",
                raw_http: b"GET /ipv6 HTTP/1.1\nHost: [::1]:8888\n\n",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "::1".into(), port: 8888 },
                expected_url: "http://[::1]:8888",
            },
            Case {
                desc: "absolute-form request line overrides stale URL bar",
                url: "https://stale.example.com/",
                raw_http: b"GET http://abs.local:9000/p HTTP/1.1\nHost: abs.local:9000\n\n",
                fallback: None,
                expected: HttpTarget { is_tls: false, host: "abs.local".into(), port: 9000 },
                expected_url: "http://abs.local:9000",
            },
        ];

        assert_table!(cases, |idx, case| {
            let got = HttpTarget::parse_or_infer(case.url, case.raw_http, case.fallback.as_ref());
            assert_eq!(got, case.expected, "case #{idx} ({}) target mismatch", case.desc);
            assert_eq!(got.to_url(), case.expected_url, "case #{idx} ({}) to_url mismatch", case.desc);
        });
    }

    #[test]
    fn inter_tool_routing_preserves_target_and_payload_matrix() {
        use crate::assert_table;
        use crate::state::Tab;
        use crate::test_utils::{HttpFixture, MockAppBuilder};

        let fixtures = [
            (
                "plaintext localhost:8888 POST",
                HttpFixture::post("127.0.0.1", "/login", "user=admin&pass=secret").with_port(8888),
            ),
            (
                "TLS default port 443 GET",
                HttpFixture::get("auth.example.com", "/session?id=42").with_tls(true),
            ),
            (
                "plaintext custom port 8080 PUT",
                HttpFixture::post("internal.corp", "/api/v1/items", "{\"k\":\"v\"}")
                    .with_method("PUT")
                    .with_port(8080),
            ),
            (
                "TLS custom port 8443 POST",
                HttpFixture::post("secure.corp", "/token", "grant=client").with_tls(true).with_port(8443),
            ),
        ];

        assert_table!(fixtures, |idx, (desc, fx)| {
            let expected_origin = fx.origin();
            let expected_url = fx.url();
            let raw_req = fx.raw_request();
            let entry = fx.clone().into_history_entry(idx + 1, "Proxy");

            // 1. Send to Intruder (direct & via send_to)
            let mut app = MockAppBuilder::new().build();
            send_to_intruder(&mut app, &expected_url, &raw_req);
            assert_eq!(app.tab, Tab::Intruder, "case #{idx} ({desc}): Intruder tab");
            assert_eq!(app.int_target, expected_origin, "case #{idx} ({desc}): Intruder target");
            assert_eq!(app.int_template, raw_req, "case #{idx} ({desc}): Intruder payload bit-for-bit");

            // 2. Send to Repeater
            let mut app = MockAppBuilder::new().build();
            send_to(&mut app, &entry, SendTo::Repeater);
            assert_eq!(app.tab, Tab::Repeater, "case #{idx} ({desc}): Repeater tab");
            let rep = app.repeater_tabs.last().expect("Repeater tab created");
            assert_eq!(rep.method, fx.method, "case #{idx} ({desc}): Repeater method");
            assert_eq!(rep.url, expected_url, "case #{idx} ({desc}): Repeater url");
            assert_eq!(rep.request, raw_req, "case #{idx} ({desc}): Repeater payload bit-for-bit");

            // 3. Send to Sequencer
            let mut app = MockAppBuilder::new().build();
            app.seq_samples = vec!["stale_tok".into()];
            send_to(&mut app, &entry, SendTo::Sequencer);
            assert_eq!(app.tab, Tab::Sequencer, "case #{idx} ({desc}): Sequencer tab");
            assert_eq!(app.seq_origin, expected_origin, "case #{idx} ({desc}): Sequencer origin");
            assert_eq!(app.seq_template, raw_req, "case #{idx} ({desc}): Sequencer payload bit-for-bit");
            assert!(app.seq_samples.is_empty(), "case #{idx} ({desc}): Sequencer samples cleared");

            // 4. Send to Organizer
            let mut app = MockAppBuilder::new().build();
            send_to(&mut app, &entry, SendTo::Organizer);
            let org = app.organizer.last().expect("Organizer item created");
            assert_eq!(org.method, fx.method, "case #{idx} ({desc}): Organizer method");
            assert_eq!(org.url, expected_url, "case #{idx} ({desc}): Organizer url");
            assert_eq!(org.request, raw_req, "case #{idx} ({desc}): Organizer request bit-for-bit");
            assert_eq!(org.response, entry.response, "case #{idx} ({desc}): Organizer response bit-for-bit");

            // 5. Send to Decoder
            let mut app = MockAppBuilder::new().build();
            send_to(&mut app, &entry, SendTo::Decoder);
            assert_eq!(app.tab, Tab::Decoder, "case #{idx} ({desc}): Decoder tab");
            assert_eq!(app.dec_blocks[0].text, raw_req, "case #{idx} ({desc}): Decoder text bit-for-bit");
            assert_eq!(app.dec_raw[0], raw_req.as_bytes(), "case #{idx} ({desc}): Decoder raw bytes bit-for-bit");

            // 6. Send to Comparer (Request)
            let mut app = MockAppBuilder::new().build();
            send_to(&mut app, &entry, SendTo::ComparerRequest);
            assert_eq!(app.tab, Tab::Comparer, "case #{idx} ({desc}): Comparer tab");
            let comp = app.comparer_items.last().expect("Comparer item created");
            assert_eq!(comp.data, raw_req.as_bytes(), "case #{idx} ({desc}): Comparer bytes bit-for-bit");
        });
    }

    #[test]
    fn context_menu_targets_filter_calling_tool() {
        use crate::assert_table;
        use crate::state::Tab;

        let cases = [
            (Tab::Repeater, 5, Some("Send to Repeater")),
            (Tab::Intruder, 5, Some("Send to Intruder")),
            (Tab::Sequencer, 5, Some("Send to Sequencer")),
            (Tab::Comparer, 5, Some("Send to Comparer")),
            (Tab::Decoder, 5, Some("Send to Decoder")),
            (Tab::Organizer, 5, Some("Send to Organizer")),
            (Tab::Proxy, 6, None),
            (Tab::Target, 6, None),
            (Tab::Logger, 6, None),
        ];

        assert_table!(cases, |idx, (tab, expected_len, hidden_label)| {
            let targets = crate::ui_tools::traffic_context_menu_targets(tab);
            assert_eq!(targets.len(), expected_len, "case #{idx} ({tab:?}): target count");
            if let Some(hidden) = hidden_label {
                assert!(
                    targets.iter().all(|(l, _)| *l != hidden),
                    "case #{idx} ({tab:?}): self-link {hidden:?} must be hidden"
                );
            }
        });
    }
}
