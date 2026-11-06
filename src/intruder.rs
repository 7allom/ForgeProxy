//! Intruder attack types. Names and behaviour per the product's documented set
//! (Sniper, Battering ram, Pitchfork, Cluster bomb). The template marks each payload
//! position with § on both sides, like the original (ProjectDefaults intercept rules use §).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackType {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

impl AttackType {
    pub const ALL: [AttackType; 4] =
        [AttackType::Sniper, AttackType::BatteringRam, AttackType::Pitchfork, AttackType::ClusterBomb];
    pub fn label(&self) -> &'static str {
        match self {
            AttackType::Sniper => "Sniper",
            AttackType::BatteringRam => "Battering ram",
            AttackType::Pitchfork => "Pitchfork",
            AttackType::ClusterBomb => "Cluster bomb",
        }
    }
}

/// "Auto §": clear existing markers, then mark every parameter value in the query string,
/// the Cookie header and a form-style body (name=value pairs).
pub fn auto_positions(template: &str) -> String {
    let clean = template.replace('§', "");
    let mark = |s: &str, sep: char| -> String {
        s.split(sep)
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => format!("{k}=§{v}§"),
                _ => pair.to_string(),
            })
            .collect::<Vec<_>>()
            .join(&sep.to_string())
    };
    let (head, body) = match clean.split_once("\n\n") {
        Some((h, b)) => (h.to_string(), Some(b.to_string())),
        None => (clean.clone(), None),
    };
    let mut out = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            let mut parts: Vec<String> = line.splitn(3, ' ').map(String::from).collect();
            if parts.len() >= 2 {
                if let Some((path, q)) = parts[1].split_once('?') {
                    parts[1] = format!("{path}?{}", mark(q, '&'));
                }
            }
            out.push(parts.join(" "));
        } else if let Some((k, v)) = line.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("cookie")) {
            let cookies: Vec<String> = v.split(';').map(|c| {
                let lead = if c.starts_with(' ') { " " } else { "" };
                match c.trim().split_once('=') { Some((n, val)) => format!("{lead}{n}=§{val}§"), None => c.to_string() }
            }).collect();
            out.push(format!("{k}:{}", cookies.join(";")));
        } else {
            out.push(line.to_string());
        }
    }
    let mut res = out.join("\n");
    if let Some(b) = body {
        res.push_str("\n\n");
        res.push_str(&if b.contains('=') && !b.trim_start().starts_with('{') { mark(&b, '&') } else { b });
    }
    res
}

/// Count the § positions in a template (pairs of markers).
pub fn count_positions(template: &str) -> usize {
    template.matches('§').count() / 2
}

/// Ready-made payload lists for common tests: HTTP verbs, parameter names and API routes.
pub const PRESETS: &[(&str, &[&str])] = &[
    ("HTTP verbs", &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
    ("Parameter names", &["id", "user", "redirect", "url", "file", "token", "debug"]),
    ("API routes", &["/api", "/health", "/status", "/metrics", "/version", "/docs"]),
];

/// A preset's payloads, one per line.
pub fn preset_lines(name: &str) -> Option<String> {
    PRESETS.iter().find(|(n, _)| *n == name).map(|(_, lines)| lines.join("\n"))
}

/// Split a template into the fixed text around its positions and each position's default
/// (the text between a § pair). `parts[k]` precedes position `k`, and the final part comes
/// after the last position, so there is one more part than positions. An unclosed final §
/// is ignored, matching `count_positions` (which counts marker pairs).
fn split_template(template: &str) -> (Vec<String>, Vec<String>) {
    let mut parts = Vec::new();
    let mut defaults = Vec::new();
    let mut cur = String::new();
    let mut base = String::new();
    let mut inside = false;
    for ch in template.chars() {
        if ch == '§' {
            if inside {
                defaults.push(std::mem::take(&mut base));
            } else {
                parts.push(std::mem::take(&mut cur));
            }
            inside = !inside;
        } else if inside {
            base.push(ch);
        } else {
            cur.push(ch);
        }
    }
    parts.push(cur);
    (parts, defaults)
}

/// Build one request from the template pieces and the value chosen for each position
/// (`None` keeps that position's default).
fn fill_values(parts: &[String], defaults: &[String], values: &[Option<String>]) -> String {
    let mut out = String::new();
    for k in 0..defaults.len() {
        out.push_str(parts.get(k).map_or("", |s| s.as_str()));
        match values.get(k).and_then(|v| v.as_ref()) {
            Some(v) => out.push_str(v),
            None => out.push_str(&defaults[k]),
        }
    }
    out.push_str(parts.get(defaults.len()).map_or("", |s| s.as_str()));
    out
}

/// The payloads a request used, in position order, for the results label.
fn label_of(values: &[Option<String>]) -> String {
    values.iter().flatten().cloned().collect::<Vec<_>>().join(", ")
}

/// An attack prepared for execution: it computes request `i` from its index on demand, so
/// even a large Cluster bomb needs no memory beyond the template and the payload lists.
///
/// `sets` holds one payload list per marker. Sniper and Battering ram use only the first
/// list; Pitchfork and Cluster bomb give marker `k` the list `sets[k]` (an empty or missing
/// list leaves that marker at its default). The first list is the primary set: when it is
/// empty the attack produces no requests.
#[derive(Clone, Debug, PartialEq)]
pub struct AttackPlan {
    kind: AttackType,
    parts: Vec<String>,
    defaults: Vec<String>,
    sets: Vec<Vec<String>>,
    len: usize,
}

impl AttackPlan {
    pub fn new(kind: AttackType, template: &str, sets: &[Vec<String>]) -> Self {
        let (parts, defaults) = split_template(template);
        let positions = defaults.len();
        let sets = sets.to_vec();
        let s0 = sets.first().map_or(0, |s| s.len());
        // lists that actually vary a marker (non-empty, within the marker count); empty
        // when the primary set is empty, so the attack then produces nothing
        let driving: Vec<usize> = if s0 == 0 {
            Vec::new()
        } else {
            (0..positions).filter_map(|k| sets.get(k).map(Vec::len).filter(|&n| n > 0)).collect()
        };
        let len = if positions == 0 {
            0
        } else {
            match kind {
                AttackType::Sniper => s0 * positions,
                AttackType::BatteringRam => s0,
                AttackType::Pitchfork => driving.iter().copied().min().unwrap_or(0),
                AttackType::ClusterBomb => driving.iter().try_fold(1usize, |a, &n| a.checked_mul(n)).unwrap_or(usize::MAX),
            }
        };
        let len = if driving.is_empty() && !matches!(kind, AttackType::Sniper | AttackType::BatteringRam) { 0 } else { len };
        AttackPlan { kind, parts, defaults, sets, len }
    }

    /// Two payload lists, the shape the current UI produces: Sniper and Battering ram take
    /// only `set_a`; Pitchfork and Cluster bomb take both.
    pub fn from_two(kind: AttackType, template: &str, set_a: &[String], set_b: &[String]) -> Self {
        let sets = match kind {
            AttackType::Sniper | AttackType::BatteringRam => vec![set_a.to_vec()],
            AttackType::Pitchfork | AttackType::ClusterBomb => vec![set_a.to_vec(), set_b.to_vec()],
        };
        Self::new(kind, template, &sets)
    }

    /// How many requests the attack sends.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Request `i` (for `i < len`): the payloads it uses (for the label) and the filled
    /// request text.
    pub fn request(&self, i: usize) -> (String, String) {
        let positions = self.defaults.len();
        let mut values: Vec<Option<String>> = vec![None; positions];
        match self.kind {
            AttackType::Sniper => {
                if positions > 0 {
                    if let Some(p) = self.sets.first().and_then(|s| s.get(i / positions)) {
                        values[i % positions] = Some(p.clone());
                    }
                }
            }
            AttackType::BatteringRam => {
                if let Some(p) = self.sets.first().and_then(|s| s.get(i)) {
                    for v in values.iter_mut() {
                        *v = Some(p.clone());
                    }
                }
            }
            AttackType::Pitchfork => {
                for k in 0..positions {
                    if let Some(p) = self.sets.get(k).filter(|s| !s.is_empty()).and_then(|s| s.get(i)) {
                        values[k] = Some(p.clone());
                    }
                }
            }
            AttackType::ClusterBomb => {
                // active markers, most-significant first; the last marker varies fastest,
                // so request order matches nested loops over the lists
                let active: Vec<usize> = (0..positions)
                    .filter(|&k| self.sets.get(k).is_some_and(|s| !s.is_empty()))
                    .collect();
                let mut idx = i;
                for &k in active.iter().rev() {
                    let s = &self.sets[k];
                    values[k] = Some(s[idx % s.len()].clone());
                    idx /= s.len();
                }
            }
        }
        (label_of(&values), fill_values(&self.parts, &self.defaults, &values))
    }
}

/// Headers to send for one filled-in request. The connection always goes to the attack
/// target; with `update_host` the HTTP client writes the target's host as the Host header,
/// otherwise the request's own Host header (if it has one) is sent as written.
pub fn dispatch_headers(raw: &str, update_host: bool) -> Vec<(String, String)> {
    let (_, _, mut headers, _) = crate::actions::parse_raw_request(raw);
    if !update_host {
        if let Some(host) = crate::actions::host_header(raw) {
            headers.insert(0, ("Host".to_string(), host));
        }
    }
    headers
}

/// How many requests the attack will produce, without building them. `set_a`/`set_b` are
/// payload-line counts (the two lists the current UI offers).
pub fn request_count(kind: AttackType, positions: usize, set_a: usize, set_b: usize) -> usize {
    // a template with only fixed count data: reconstruct enough § markers and dummy lists
    let template = "§x§".repeat(positions.max(1));
    let a = vec![String::new(); set_a];
    let b = vec![String::new(); set_b];
    AttackPlan::from_two(kind, &template, &a, &b).len()
}

/// Produce all the filled requests for an attack (the runner uses `AttackPlan` lazily
/// instead; this materialises the whole list, for tests and comparison).
#[cfg(test)]
pub fn requests(kind: AttackType, template: &str, set_a: &[String], set_b: &[String]) -> Vec<(String, String)> {
    let plan = AttackPlan::from_two(kind, template, set_a, set_b);
    (0..plan.len()).map(|i| plan.request(i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(xs: &[&str]) -> Vec<String> { xs.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn auto_marks_query_cookie_and_body() {
        let t = "POST /a?x=1&y=2 HTTP/1.1\nCookie: s=abc; t=9\nHost: h\n\nu=me&p=pw";
        let out = auto_positions(t);
        assert_eq!(out, "POST /a?x=§1§&y=§2§ HTTP/1.1\nCookie: s=§abc§; t=§9§\nHost: h\n\nu=§me§&p=§pw§");
        assert_eq!(count_positions(&out), 6);
    }

    #[test]
    fn dispatch_headers_respects_update_host() {
        let raw = "GET /a HTTP/1.1\nHost: §x§.internal\nCookie: c=1\n\n";
        let filled = &requests(AttackType::Sniper, raw, &v(&["evil"]), &[])[0].1;
        let has_host = |h: &[(String, String)]| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone());
        // on: no Host header of ours, so the client uses the target's
        assert_eq!(has_host(&dispatch_headers(filled, true)), None);
        // off: the template's Host, with its payload filled in
        let off = dispatch_headers(filled, false);
        assert_eq!(has_host(&off).as_deref(), Some("evil.internal"));
        assert!(off.iter().any(|(k, v)| k == "Cookie" && v == "c=1"));
        // off, but the template has no Host header: nothing to keep, target host it is
        assert_eq!(has_host(&dispatch_headers("GET / HTTP/1.1\nAccept: */*\n\n", false)), None);
    }

    #[test]
    fn request_count_matches_requests() {
        let t = "a=§x§&b=§y§";
        for kind in AttackType::ALL {
            for (a, b) in [(v(&["1", "2", "3"]), v(&["p", "q"])), (v(&["1"]), vec![]), (vec![], v(&["p"]))] {
                assert_eq!(request_count(kind, count_positions(t), a.len(), b.len()), requests(kind, t, &a, &b).len(), "{}", kind.label());
            }
        }
    }

    #[test]
    fn sniper_keeps_base_value_elsewhere() {
        let r = requests(AttackType::Sniper, "a=§x§&b=§y§", &v(&["P"]), &[]);
        let filled: Vec<_> = r.iter().map(|(_, f)| f.as_str()).collect();
        assert_eq!(filled, ["a=P&b=y", "a=x&b=P"]);
    }
    #[test]
    fn battering_ram_same_everywhere() {
        let r = requests(AttackType::BatteringRam, "a=§x§&b=§y§", &v(&["P", "Q"]), &[]);
        assert_eq!(r[1].1, "a=Q&b=Q");
    }
    #[test]
    fn pitchfork_lockstep() {
        let r = requests(AttackType::Pitchfork, "u=§x§&p=§y§", &v(&["a", "b", "c"]), &v(&["1", "2"]));
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].1, "u=b&p=2");
    }
    #[test]
    fn cluster_bomb_all_combinations() {
        let r = requests(AttackType::ClusterBomb, "u=§x§&p=§y§", &v(&["a", "b"]), &v(&["1", "2", "3"]));
        assert_eq!(r.len(), 6);
        assert_eq!(r[5].0, "b, 3");
    }

    // ---- lazy AttackPlan ----

    /// Every index the plan reports produces the same (label, request) as the eager list.
    fn plan_matches_eager(kind: AttackType, template: &str, a: &[String], b: &[String]) {
        let plan = AttackPlan::from_two(kind, template, a, b);
        let eager = requests(kind, template, a, b);
        assert_eq!(plan.len(), eager.len(), "{} count", kind.label());
        for (i, expected) in eager.iter().enumerate() {
            assert_eq!(&plan.request(i), expected, "{} request {i}", kind.label());
        }
    }

    #[test]
    fn plan_reproduces_each_mode_lazily() {
        let t = "u=§x§&p=§y§&z=§q§";
        for kind in AttackType::ALL {
            for (a, b) in [
                (v(&["1", "2", "3"]), v(&["p", "q"])),
                (v(&["only"]), vec![]),
                (vec![], v(&["p"])),
                (v(&["a", "b", "c", "d"]), v(&["x", "y", "z"])),
            ] {
                plan_matches_eager(kind, t, &a, &b);
            }
        }
    }

    #[test]
    fn template_splits_into_parts_and_defaults() {
        let (parts, defaults) = split_template("a=§x§&b=§y§");
        assert_eq!(parts, ["a=", "&b=", ""]);
        assert_eq!(defaults, ["x", "y"]);
        // no markers: one part, no positions
        assert_eq!(split_template("plain"), (vec!["plain".to_string()], Vec::<String>::new()));
    }

    #[test]
    fn marker_edge_cases_do_not_panic() {
        // unclosed final marker: the dangling text is ignored, like count_positions
        assert_eq!(count_positions("a§b§c§d"), 1);
        let plan = AttackPlan::from_two(AttackType::Sniper, "a§b§c§d", &v(&["P"]), &[]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.request(0).1, "aPc");
        // no markers at all: nothing to attack
        let none = AttackPlan::from_two(AttackType::BatteringRam, "no markers here", &v(&["P"]), &[]);
        assert!(none.is_empty());
        // empty primary set: every mode produces nothing
        for kind in AttackType::ALL {
            assert!(AttackPlan::from_two(kind, "a=§x§", &[], &v(&["p"])).is_empty(), "{}", kind.label());
        }
    }

    #[test]
    fn sniper_index_walks_payload_then_marker() {
        let plan = AttackPlan::from_two(AttackType::Sniper, "a=§x§&b=§y§", &v(&["P", "Q"]), &[]);
        assert_eq!(plan.len(), 4); // 2 payloads × 2 markers
        let filled: Vec<String> = (0..plan.len()).map(|i| plan.request(i).1).collect();
        assert_eq!(filled, ["a=P&b=y", "a=x&b=P", "a=Q&b=y", "a=x&b=Q"]);
    }

    #[test]
    fn battering_ram_broadcasts_one_value() {
        let plan = AttackPlan::from_two(AttackType::BatteringRam, "a=§x§&b=§y§&c=§z§", &v(&["P", "Q"]), &[]);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.request(1), ("Q, Q, Q".to_string(), "a=Q&b=Q&c=Q".to_string()));
    }

    #[test]
    fn pitchfork_zips_up_to_the_shortest_list() {
        let plan = AttackPlan::from_two(AttackType::Pitchfork, "u=§x§&p=§y§", &v(&["a", "b", "c"]), &v(&["1", "2"]));
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.request(0).1, "u=a&p=1");
        assert_eq!(plan.request(1).1, "u=b&p=2");
    }

    #[test]
    fn cluster_bomb_decomposes_the_index_into_strides() {
        let plan = AttackPlan::from_two(AttackType::ClusterBomb, "u=§x§&p=§y§", &v(&["a", "b"]), &v(&["1", "2", "3"]));
        assert_eq!(plan.len(), 6);
        // last marker varies fastest: index 0..6 → (a,1)(a,2)(a,3)(b,1)(b,2)(b,3)
        let filled: Vec<String> = (0..6).map(|i| plan.request(i).1).collect();
        assert_eq!(filled, ["u=a&p=1", "u=a&p=2", "u=a&p=3", "u=b&p=1", "u=b&p=2", "u=b&p=3"]);
    }

    #[test]
    fn presets_are_available_as_lines() {
        assert_eq!(preset_lines("HTTP verbs").unwrap().lines().next(), Some("GET"));
        assert_eq!(preset_lines("Parameter names").unwrap().lines().count(), 7);
        assert!(preset_lines("API routes").unwrap().contains("/metrics"));
        assert_eq!(preset_lines("Nonexistent"), None);
        // every preset is non-empty
        for (name, lines) in PRESETS {
            assert!(!lines.is_empty(), "{name}");
        }
    }

    #[test]
    fn plan_supports_more_than_two_sets() {
        // three markers, three lists in lock-step
        let sets = [v(&["a", "b"]), v(&["1", "2", "3"]), v(&["x", "y"])];
        let plan = AttackPlan::new(AttackType::Pitchfork, "§p§-§q§-§r§", &sets);
        assert_eq!(plan.len(), 2); // shortest list
        assert_eq!(plan.request(1).1, "b-2-y");
        // cluster bomb over three lists: 2 × 3 × 2 = 12
        let plan = AttackPlan::new(AttackType::ClusterBomb, "§p§-§q§-§r§", &sets);
        assert_eq!(plan.len(), 12);
        assert_eq!(plan.request(0).1, "a-1-x");
        assert_eq!(plan.request(11).1, "b-3-y");
    }
}
