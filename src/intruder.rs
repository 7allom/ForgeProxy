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

/// Mark `name=value` pairs in a query string or URL-encoded form body (`&` or `;` delimited),
/// stopping each extracted value strictly at `&`, `;`, `\r`, `\n`, or whitespace so trailing
/// newlines or blank lines are never captured inside `§...§`.
fn mark_urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    let mut start = 0;
    for (idx, ch) in s.char_indices() {
        if matches!(ch, '&' | ';') {
            out.push_str(&mark_one_pair(&s[start..idx]));
            out.push(ch);
            start = idx + ch.len_utf8();
        }
    }
    out.push_str(&mark_one_pair(&s[start..]));
    out
}

fn mark_one_pair(pair: &str) -> String {
    match pair.split_once('=') {
        Some((k, v)) if !k.trim().is_empty() && !k.trim().contains(char::is_whitespace) => {
            let val_end = v
                .find(|c: char| matches!(c, '&' | ';' | '\r' | '\n') || c.is_whitespace())
                .unwrap_or(v.len());
            let (val, suffix) = v.split_at(val_end);
            format!("{k}=§{val}§{suffix}")
        }
        _ => pair.to_string(),
    }
}

/// Mark values in a JSON body (`"key": "§value§"` and `"key": §123§`), ensuring the closing
/// `§` never consumes closing quotes, commas, braces, or trailing whitespace/newlines.
fn mark_json_body(b: &str) -> String {
    let bytes = b.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(b.len() + 16);
    let mut i = 0;

    while i < n {
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            while i < n {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(n);
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            out.push_str(&b[start..i]);

            let ws_start = i;
            while i < n && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < n && bytes[i] == b':' {
                i += 1;
                while i < n && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                out.push_str(&b[ws_start..i]);

                if i < n && bytes[i] == b'"' {
                    out.push('"');
                    i += 1;
                    let val_start = i;
                    while i < n {
                        if bytes[i] == b'\\' {
                            i = (i + 2).min(n);
                        } else if bytes[i] == b'"' {
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    out.push('§');
                    out.push_str(&b[val_start..i]);
                    out.push('§');
                    if i < n && bytes[i] == b'"' {
                        out.push('"');
                        i += 1;
                    }
                } else if i < n && !matches!(bytes[i], b'{' | b'[' | b'}' | b']' | b',') {
                    let val_start = i;
                    while i < n
                        && !matches!(bytes[i], b',' | b'}' | b']' | b'\r' | b'\n')
                        && !bytes[i].is_ascii_whitespace()
                    {
                        i += 1;
                    }
                    if i > val_start {
                        out.push('§');
                        out.push_str(&b[val_start..i]);
                        out.push('§');
                    }
                }
            } else {
                i = ws_start;
            }
        } else {
            let ch = b[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Does the request's Host header carry payload positions? Its value is then the user's to
/// place and the target must leave it alone: rewriting `Host: §sub§.example.test` as a plain
/// host would drop a position and renumber every position after it. The line is matched with
/// its markers stripped, so a position around the field name (`§Host§: x`) counts too.
pub fn host_marked(template: &str) -> bool {
    template
        .split('\n')
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .any(|l| l.contains('§') && l.replace('§', "").split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("host")))
}

/// "Auto §": clear existing markers, then mark every parameter value in the query string,
/// the Cookie header, a form-style body (name=value pairs), or a JSON body.
pub fn auto_positions(template: &str) -> String {
    let clean = template.replace('§', "");
    let (head, sep_str, body) = if let Some((h, b)) = clean.split_once("\r\n\r\n") {
        (h.to_string(), "\r\n\r\n", Some(b.to_string()))
    } else if let Some((h, b)) = clean.split_once("\n\n") {
        (h.to_string(), "\n\n", Some(b.to_string()))
    } else {
        (clean.clone(), "", None)
    };
    let line_sep = if head.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = Vec::new();
    for (i, raw_line) in head.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if i == 0 {
            let mut parts: Vec<String> = line.splitn(3, ' ').map(String::from).collect();
            if parts.len() >= 2 {
                if let Some((path, q)) = parts[1].split_once('?') {
                    parts[1] = format!("{path}?{}", mark_urlencoded(q));
                }
            }
            out.push(parts.join(" "));
        } else if let Some((k, v)) = line.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("cookie")) {
            let cookies: Vec<String> = v
                .split(';')
                .map(|c| {
                    let lead: String = c.chars().take_while(|ch| ch.is_whitespace()).collect();
                    let trimmed = &c[lead.len()..];
                    match trimmed.split_once('=') {
                        Some((n, val_part)) if !n.trim().is_empty() => {
                            let val_end = val_part
                                .find(|ch: char| matches!(ch, '&' | ';' | '\r' | '\n') || ch.is_whitespace())
                                .unwrap_or(val_part.len());
                            let (val, suffix) = val_part.split_at(val_end);
                            format!("{lead}{n}=§{val}§{suffix}")
                        }
                        _ => c.to_string(),
                    }
                })
                .collect();
            out.push(format!("{k}:{}", cookies.join(";")));
        } else {
            out.push(line.to_string());
        }
    }
    let mut res = out.join(line_sep);
    if let Some(b) = body {
        res.push_str(sep_str);
        let trimmed = b.trim_start();
        let marked_body = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            mark_json_body(&b)
        } else if b.contains('=') {
            mark_urlencoded(&b)
        } else {
            b
        };
        res.push_str(&marked_body);
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
/// (`None` keeps that position's default). If the request contains a `Content-Length`
/// header (without `§` markers on that header line itself) and a body separated by a
/// blank line, `Content-Length` is dynamically updated to match the substituted body length.
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
    sync_content_length(out)
}

/// Update `Content-Length` in `raw` to match the byte length of the body after `\r\n\r\n` or `\n\n`.
pub fn sync_content_length(raw: String) -> String {
    let (sep, split_idx) = if let Some(idx) = raw.find("\r\n\r\n") {
        ("\r\n\r\n", idx)
    } else if let Some(idx) = raw.find("\n\n") {
        ("\n\n", idx)
    } else {
        return raw;
    };
    let head = &raw[..split_idx];
    let body = &raw[split_idx + sep.len()..];
    let has_cl = head.lines().skip(1).any(|l| {
        l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
    });
    if !has_cl {
        return raw;
    }
    let line_sep = if sep == "\r\n\r\n" { "\r\n" } else { "\n" };
    let updated_head: Vec<String> = head
        .split('\n')
        .enumerate()
        .map(|(i, raw_line)| {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if i > 0 {
                if let Some((k, _)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        return format!("{}: {}", k.trim(), body.len());
                    }
                }
            }
            line.to_string()
        })
        .collect();
    format!("{}{sep}{body}", updated_head.join(line_sep))
}

/// Configurable payload generators for Intruder payload sets.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PayloadGenerator {
    /// Static list of strings.
    SimpleList(Vec<String>),
    /// Inclusive numeric range `from..=to` with `step`, optional `prefix`, and zero-padding width.
    NumberRange {
        from: i64,
        to: i64,
        step: i64,
        pad_width: usize,
        prefix: String,
    },
    /// Cartesian product of per-slot token lists joined by `separator`.
    CustomIterator {
        slots: Vec<Vec<String>>,
        separator: String,
    },
    /// Exhaustive character-set combinations from `min_len..=max_len` with an optional `prefix`.
    BruteForce {
        charset: String,
        min_len: usize,
        max_len: usize,
        prefix: String,
    },
}

#[allow(dead_code)]
impl PayloadGenerator {
    pub fn generate(&self) -> Vec<String> {
        match self {
            PayloadGenerator::SimpleList(list) => list.clone(),
            PayloadGenerator::NumberRange { from, to, step, pad_width, prefix } => {
                if *step == 0 || (*step > 0 && from > to) || (*step < 0 && from < to) {
                    return Vec::new();
                }
                let mut out = Vec::new();
                let mut cur = *from;
                while (*step > 0 && cur <= *to) || (*step < 0 && cur >= *to) {
                    if *pad_width > 0 && cur >= 0 {
                        out.push(format!("{prefix}{cur:0width$}", width = *pad_width));
                    } else {
                        out.push(format!("{prefix}{cur}"));
                    }
                    match cur.checked_add(*step) {
                        Some(next) => cur = next,
                        None => break,
                    }
                }
                out
            }
            PayloadGenerator::CustomIterator { slots, separator } => {
                if slots.is_empty() || slots.iter().any(Vec::is_empty) {
                    return Vec::new();
                }
                let mut acc = vec![String::new()];
                for (idx, slot) in slots.iter().enumerate() {
                    let mut next = Vec::with_capacity(acc.len() * slot.len());
                    for prefix in &acc {
                        for item in slot {
                            if idx == 0 {
                                next.push(item.clone());
                            } else {
                                next.push(format!("{prefix}{separator}{item}"));
                            }
                        }
                    }
                    acc = next;
                }
                acc
            }
            PayloadGenerator::BruteForce { charset, min_len, max_len, prefix } => {
                let chars: Vec<char> = charset.chars().collect();
                if chars.is_empty() || min_len > max_len || *max_len == 0 {
                    return Vec::new();
                }
                let mut out = Vec::new();
                for len in (*min_len).max(1)..=*max_len {
                    let mut level = vec![prefix.clone()];
                    for _ in 0..len {
                        let mut next = Vec::with_capacity(level.len() * chars.len());
                        for p in &level {
                            for &ch in &chars {
                                let mut s = p.clone();
                                s.push(ch);
                                next.push(s);
                            }
                        }
                        level = next;
                    }
                    out.extend(level);
                }
                out
            }
        }
    }
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
    use crate::test_utils::assert_table;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    struct AttackMatrixCase<'a> {
        name: &'a str,
        attack_type: AttackType,
        template: &'a str,
        payload_sets: Vec<Vec<String>>,
        expected_request_count: usize,
        expected_payload_combinations: Vec<(&'a str, &'a str)>,
    }

    #[test]
    fn attack_type_matrix() {
        let cases = [
            // 1 position
            AttackMatrixCase {
                name: "Sniper with 1 position and 3 payloads",
                attack_type: AttackType::Sniper,
                template: "GET /item?id=§1§ HTTP/1.1",
                payload_sets: vec![v(&["10", "20", "30"])],
                expected_request_count: 3,
                expected_payload_combinations: vec![
                    ("10", "GET /item?id=10 HTTP/1.1"),
                    ("20", "GET /item?id=20 HTTP/1.1"),
                    ("30", "GET /item?id=30 HTTP/1.1"),
                ],
            },
            AttackMatrixCase {
                name: "BatteringRam with 1 position and 2 payloads",
                attack_type: AttackType::BatteringRam,
                template: "GET /item?id=§1§ HTTP/1.1",
                payload_sets: vec![v(&["A", "B"])],
                expected_request_count: 2,
                expected_payload_combinations: vec![
                    ("A", "GET /item?id=A HTTP/1.1"),
                    ("B", "GET /item?id=B HTTP/1.1"),
                ],
            },
            // 2 positions
            AttackMatrixCase {
                name: "Sniper with 2 positions keeps base value in non-targeted position",
                attack_type: AttackType::Sniper,
                template: "a=§x§&b=§y§",
                payload_sets: vec![v(&["P", "Q"])],
                expected_request_count: 4,
                expected_payload_combinations: vec![
                    ("P", "a=P&b=y"),
                    ("P", "a=x&b=P"),
                    ("Q", "a=Q&b=y"),
                    ("Q", "a=x&b=Q"),
                ],
            },
            AttackMatrixCase {
                name: "BatteringRam with 2 positions broadcasts same payload to all positions",
                attack_type: AttackType::BatteringRam,
                template: "a=§x§&b=§y§",
                payload_sets: vec![v(&["P", "Q"])],
                expected_request_count: 2,
                expected_payload_combinations: vec![
                    ("P, P", "a=P&b=P"),
                    ("Q, Q", "a=Q&b=Q"),
                ],
            },
            AttackMatrixCase {
                name: "Pitchfork with 2 positions zips in lockstep up to shortest list",
                attack_type: AttackType::Pitchfork,
                template: "u=§x§&p=§y§",
                payload_sets: vec![v(&["a", "b", "c"]), v(&["1", "2"])],
                expected_request_count: 2,
                expected_payload_combinations: vec![
                    ("a, 1", "u=a&p=1"),
                    ("b, 2", "u=b&p=2"),
                ],
            },
            AttackMatrixCase {
                name: "ClusterBomb with 2 positions produces Cartesian product (last position fastest)",
                attack_type: AttackType::ClusterBomb,
                template: "u=§x§&p=§y§",
                payload_sets: vec![v(&["a", "b"]), v(&["1", "2", "3"])],
                expected_request_count: 6,
                expected_payload_combinations: vec![
                    ("a, 1", "u=a&p=1"),
                    ("a, 2", "u=a&p=2"),
                    ("a, 3", "u=a&p=3"),
                    ("b, 1", "u=b&p=1"),
                    ("b, 2", "u=b&p=2"),
                    ("b, 3", "u=b&p=3"),
                ],
            },
            // 3 positions
            AttackMatrixCase {
                name: "Sniper with 3 positions and 2 payloads",
                attack_type: AttackType::Sniper,
                template: "§a§-§b§-§c§",
                payload_sets: vec![v(&["1", "2"])],
                expected_request_count: 6,
                expected_payload_combinations: vec![
                    ("1", "1-b-c"),
                    ("1", "a-1-c"),
                    ("1", "a-b-1"),
                    ("2", "2-b-c"),
                    ("2", "a-2-c"),
                    ("2", "a-b-2"),
                ],
            },
            AttackMatrixCase {
                name: "BatteringRam with 3 positions broadcasts one value everywhere",
                attack_type: AttackType::BatteringRam,
                template: "a=§x§&b=§y§&c=§z§",
                payload_sets: vec![v(&["P", "Q"])],
                expected_request_count: 2,
                expected_payload_combinations: vec![
                    ("P, P, P", "a=P&b=P&c=P"),
                    ("Q, Q, Q", "a=Q&b=Q&c=Q"),
                ],
            },
            AttackMatrixCase {
                name: "Pitchfork with 3 positions and 3 payload sets",
                attack_type: AttackType::Pitchfork,
                template: "§p§-§q§-§r§",
                payload_sets: vec![v(&["a", "b"]), v(&["1", "2", "3"]), v(&["x", "y"])],
                expected_request_count: 2,
                expected_payload_combinations: vec![
                    ("a, 1, x", "a-1-x"),
                    ("b, 2, y", "b-2-y"),
                ],
            },
            AttackMatrixCase {
                name: "ClusterBomb with 3 positions and 3 payload sets (2x3x2 = 12)",
                attack_type: AttackType::ClusterBomb,
                template: "§p§-§q§-§r§",
                payload_sets: vec![v(&["a", "b"]), v(&["1", "2", "3"]), v(&["x", "y"])],
                expected_request_count: 12,
                expected_payload_combinations: vec![
                    ("a, 1, x", "a-1-x"),
                    ("a, 1, y", "a-1-y"),
                    ("a, 2, x", "a-2-x"),
                    ("a, 2, y", "a-2-y"),
                    ("a, 3, x", "a-3-x"),
                    ("a, 3, y", "a-3-y"),
                    ("b, 1, x", "b-1-x"),
                    ("b, 1, y", "b-1-y"),
                    ("b, 2, x", "b-2-x"),
                    ("b, 2, y", "b-2-y"),
                    ("b, 3, x", "b-3-x"),
                    ("b, 3, y", "b-3-y"),
                ],
            },
            // Edge cases: unclosed final marker, zero markers, empty primary set
            AttackMatrixCase {
                name: "unclosed final marker is ignored without panic",
                attack_type: AttackType::Sniper,
                template: "a§b§c§d",
                payload_sets: vec![v(&["P"])],
                expected_request_count: 1,
                expected_payload_combinations: vec![("P", "aPc")],
            },
            AttackMatrixCase {
                name: "template without markers produces 0 requests",
                attack_type: AttackType::BatteringRam,
                template: "no markers here",
                payload_sets: vec![v(&["P"])],
                expected_request_count: 0,
                expected_payload_combinations: vec![],
            },
            AttackMatrixCase {
                name: "empty primary payload set produces 0 requests",
                attack_type: AttackType::ClusterBomb,
                template: "a=§x§&b=§y§",
                payload_sets: vec![vec![], v(&["p"])],
                expected_request_count: 0,
                expected_payload_combinations: vec![],
            },
        ];

        assert_table!(cases, |idx, case| {
            let plan = AttackPlan::new(case.attack_type, case.template, &case.payload_sets);
            assert_eq!(plan.len(), case.expected_request_count, "case #{idx} ({}) count", case.name);
            assert_eq!(plan.is_empty(), case.expected_request_count == 0, "case #{idx} ({}) is_empty", case.name);
            let generated: Vec<(String, String)> = (0..plan.len()).map(|i| plan.request(i)).collect();
            let expected: Vec<(String, String)> = case
                .expected_payload_combinations
                .iter()
                .map(|(l, r)| (l.to_string(), r.to_string()))
                .collect();
            assert_eq!(generated, expected, "case #{idx} ({}) combinations", case.name);
        });

        // Verify lazy AttackPlan::from_two matches eager requests() and request_count() across all modes
        let t = "u=§x§&p=§y§&z=§q§";
        for kind in AttackType::ALL {
            for (a, b) in [
                (v(&["1", "2", "3"]), v(&["p", "q"])),
                (v(&["only"]), vec![]),
                (vec![], v(&["p"])),
                (v(&["a", "b", "c", "d"]), v(&["x", "y", "z"])),
            ] {
                let plan = AttackPlan::from_two(kind, t, &a, &b);
                let eager = requests(kind, t, &a, &b);
                assert_eq!(plan.len(), eager.len(), "{} count", kind.label());
                assert_eq!(request_count(kind, count_positions(t), a.len(), b.len()), eager.len(), "{} request_count", kind.label());
                for (i, expected) in eager.iter().enumerate() {
                    assert_eq!(&plan.request(i), expected, "{} request {i}", kind.label());
                }
            }
        }
        assert_eq!(split_template("plain"), (vec!["plain".to_string()], Vec::<String>::new()));
    }

    #[test]
    fn auto_positions_delimiter_matrix() {
        let cases: [(&str, &str, &str, usize); 6] = [
            (
                "marks query, Cookie header, and form body simultaneously",
                "POST /a?x=1&y=2 HTTP/1.1\nCookie: s=abc; t=9\nHost: h\n\nu=me&p=pw",
                "POST /a?x=§1§&y=§2§ HTTP/1.1\nCookie: s=§abc§; t=§9§\nHost: h\n\nu=§me§&p=§pw§",
                6,
            ),
            (
                "stops before CRLF, semicolon, ampersand, and trailing blank lines",
                "POST /login?a=1;b=2 HTTP/1.1\r\nHost: example.com\r\nCookie: sid=tok123\r\n\r\nuser=admin&pass=secret\r\n\r\n",
                "POST /login?a=§1§;b=§2§ HTTP/1.1\r\nHost: example.com\r\nCookie: sid=§tok123§\r\n\r\nuser=§admin§&pass=§secret§\r\n\r\n",
                5,
            ),
            (
                "stops before trailing spaces and newlines in form body",
                "POST /api HTTP/1.1\nHost: example.com\n\nq=search_term   \n\n",
                "POST /api HTTP/1.1\nHost: example.com\n\nq=§search_term§   \n\n",
                1,
            ),
            (
                "marks JSON string, number, and boolean values without consuming quotes or commas",
                "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\": \"value\", \"count\": 123, \"active\": true}\r\n",
                "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"key\": \"§value§\", \"count\": §123§, \"active\": §true§}\r\n",
                3,
            ),
            (
                "handles JSON escaped quotes inside string values",
                "POST /api HTTP/1.1\nHost: h\n\n{\"msg\":\"he said \\\"hi\\\"\",\"n\":-42}",
                "POST /api HTTP/1.1\nHost: h\n\n{\"msg\":\"§he said \\\"hi\\\"§\",\"n\":§-42§}",
                2,
            ),
            (
                "clears pre-existing § markers before re-marking",
                "GET /p?x=§old§ HTTP/1.1\nHost: §h§\n\n",
                "GET /p?x=§old§ HTTP/1.1\nHost: h\n\n",
                1,
            ),
        ];

        assert_table!(cases, |idx, (name, input, expected_marked, expected_count)| {
            let marked = auto_positions(input);
            assert_eq!(marked, expected_marked, "case #{idx} ({name}) marked output");
            assert_eq!(count_positions(&marked), expected_count, "case #{idx} ({name}) position count");
        });
    }

    #[test]
    fn content_length_and_header_recalculation_matrix() {
        let cl_cases: [(&str, &str, &[&str], &[&str]); 3] = [
            (
                "LF request updates Content-Length across varying payload sizes",
                "POST /login HTTP/1.1\nHost: example.com\nContent-Length: 9\n\nuser=§root§",
                &["a", "administrator", ""],
                &[
                    "POST /login HTTP/1.1\nHost: example.com\nContent-Length: 6\n\nuser=a",
                    "POST /login HTTP/1.1\nHost: example.com\nContent-Length: 18\n\nuser=administrator",
                    "POST /login HTTP/1.1\nHost: example.com\nContent-Length: 5\n\nuser=",
                ],
            ),
            (
                "CRLF request preserves CRLF and updates case-insensitive content-length",
                "POST /api HTTP/1.1\r\nHost: example.com\r\ncontent-length: 12\r\n\r\n{\"k\":\"§val§\"}",
                &["x", "longer_payload_value"],
                &[
                    "POST /api HTTP/1.1\r\nHost: example.com\r\ncontent-length: 9\r\n\r\n{\"k\":\"x\"}",
                    "POST /api HTTP/1.1\r\nHost: example.com\r\ncontent-length: 28\r\n\r\n{\"k\":\"longer_payload_value\"}",
                ],
            ),
            (
                "request without Content-Length header leaves headers untouched",
                "POST /api HTTP/1.1\nHost: example.com\n\nbody=§x§",
                &["short", "much_longer"],
                &[
                    "POST /api HTTP/1.1\nHost: example.com\n\nbody=short",
                    "POST /api HTTP/1.1\nHost: example.com\n\nbody=much_longer",
                ],
            ),
        ];

        assert_table!(cl_cases, |idx, (name, template, payloads, expected_requests)| {
            let plan = AttackPlan::from_two(AttackType::Sniper, template, &v(payloads), &[]);
            let got: Vec<String> = (0..plan.len()).map(|i| plan.request(i).1).collect();
            let expected: Vec<String> = expected_requests.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, expected, "case #{idx} ({name})");
        });

        // Host header recalculation / preservation in dispatch_headers
        let raw = "GET /a HTTP/1.1\nHost: §x§.internal\nCookie: c=1\n\n";
        let filled = &requests(AttackType::Sniper, raw, &v(&["evil"]), &[])[0].1;
        let has_host = |h: &[(String, String)]| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone());
        assert_eq!(has_host(&dispatch_headers(filled, true)), None);
        let off = dispatch_headers(filled, false);
        assert_eq!(has_host(&off).as_deref(), Some("evil.internal"));
        assert!(off.iter().any(|(k, v)| k == "Cookie" && v == "c=1"));
        assert_eq!(has_host(&dispatch_headers("GET / HTTP/1.1\nAccept: */*\n\n", false)), None);
    }

    #[test]
    fn payload_generators_matrix() {
        let cases: Vec<(&str, PayloadGenerator, Vec<&str>)> = vec![
            (
                "SimpleList preserves exact items",
                PayloadGenerator::SimpleList(v(&["admin", "guest", "root"])),
                vec!["admin", "guest", "root"],
            ),
            (
                "NumberRange ascending with step 5 and prefix",
                PayloadGenerator::NumberRange {
                    from: 10,
                    to: 25,
                    step: 5,
                    pad_width: 0,
                    prefix: "id_".into(),
                },
                vec!["id_10", "id_15", "id_20", "id_25"],
            ),
            (
                "NumberRange with zero-padding width 3",
                PayloadGenerator::NumberRange {
                    from: 1,
                    to: 3,
                    step: 1,
                    pad_width: 3,
                    prefix: "u".into(),
                },
                vec!["u001", "u002", "u003"],
            ),
            (
                "NumberRange descending with negative step",
                PayloadGenerator::NumberRange {
                    from: 3,
                    to: 1,
                    step: -1,
                    pad_width: 0,
                    prefix: String::new(),
                },
                vec!["3", "2", "1"],
            ),
            (
                "NumberRange invalid step 0 returns empty",
                PayloadGenerator::NumberRange {
                    from: 1,
                    to: 5,
                    step: 0,
                    pad_width: 0,
                    prefix: String::new(),
                },
                vec![],
            ),
            (
                "CustomIterator joins 2 slots with separator",
                PayloadGenerator::CustomIterator {
                    slots: vec![v(&["admin", "dev"]), v(&["1", "2"])],
                    separator: ":".into(),
                },
                vec!["admin:1", "admin:2", "dev:1", "dev:2"],
            ),
            (
                "BruteForce charset 'ab' length 1..=2 with prefix 'p_'",
                PayloadGenerator::BruteForce {
                    charset: "ab".into(),
                    min_len: 1,
                    max_len: 2,
                    prefix: "p_".into(),
                },
                vec!["p_a", "p_b", "p_aa", "p_ab", "p_ba", "p_bb"],
            ),
        ];

        assert_table!(cases, |idx, (name, gen, expected)| {
            let expected_owned: Vec<String> = expected.into_iter().map(String::from).collect();
            assert_eq!(gen.generate(), expected_owned, "case #{idx} ({name})");
        });

        // Built-in PRESETS table
        assert_eq!(preset_lines("HTTP verbs").unwrap().lines().next(), Some("GET"));
        assert_eq!(preset_lines("Parameter names").unwrap().lines().count(), 7);
        assert!(preset_lines("API routes").unwrap().contains("/metrics"));
        assert_eq!(preset_lines("Nonexistent"), None);
        for (name, lines) in PRESETS {
            assert!(!lines.is_empty(), "{name}");
        }
    }
}
