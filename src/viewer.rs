//! Read-only message views: Pretty (JSON re-indented, XML/HTML tags indented, each with
//! syntax colours) and Hex (a 16-bytes-per-row dump). They only ever produce new display
//! text; the message itself is never changed.

use crate::theme::Palette;
use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId};

/// How a read-only message is shown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MessageViewMode {
    #[default]
    Raw,
    Pretty,
    Hex,
}

impl MessageViewMode {
    pub const ALL: [MessageViewMode; 3] = [MessageViewMode::Raw, MessageViewMode::Pretty, MessageViewMode::Hex];
    pub fn label(self) -> &'static str {
        match self { MessageViewMode::Raw => "Raw", MessageViewMode::Pretty => "Pretty", MessageViewMode::Hex => "Hex" }
    }
}

/// What a message's body was recognised as by `pretty_message`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyKind {
    Json,
    Markup,
    Other,
}

/// The Pretty view of a message: its head as is (line endings made `\n`) and its body
/// re-indented when it's JSON or XML/HTML. Also says which, for colouring. A message
/// without a head (just a JSON document, say) is treated as all body.
pub fn pretty_message(raw: &str) -> (String, BodyKind) {
    let text = raw.replace("\r\n", "\n");
    let (head, body) = match text.split_once("\n\n") {
        Some((h, b)) if looks_like_head(h) => (Some(h), b),
        _ if looks_like_head(&text) => (Some(text.as_str()), ""),
        _ => (None, text.as_str()),
    };
    let (body, kind) = pretty_body(body);
    let out = match head {
        Some(h) if body.is_empty() => h.to_string(),
        Some(h) => format!("{h}\n\n{body}"),
        None => body,
    };
    (out, kind)
}

/// A request or status line first ("GET / HTTP/1.1", "HTTP/1.1 200 OK", Repeater's "200 OK").
fn looks_like_head(s: &str) -> bool {
    let first = s.lines().next().unwrap_or("");
    let mut t = first.split_whitespace();
    match (t.next(), t.next()) {
        (Some(a), Some(_)) => a.starts_with("HTTP/") || (a.len() == 3 && a.bytes().all(|b| b.is_ascii_digit()))
            || (a.bytes().all(|b| b.is_ascii_uppercase()) && a.len() <= 10),
        _ => false,
    }
}

fn pretty_body(body: &str) -> (String, BodyKind) {
    let t = body.trim();
    if t.starts_with('{') || t.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            // preserve_order is on: keys stay in the order the server sent them
            return (serde_json::to_string_pretty(&v).unwrap_or_else(|_| body.to_string()), BodyKind::Json);
        }
    }
    if t.starts_with('<') && t.ends_with('>') {
        return (indent_markup(t), BodyKind::Markup);
    }
    (body.to_string(), BodyKind::Other)
}

/// Elements that never have a closing tag in HTML.
const VOID: [&str; 14] = ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"];

/// XML or HTML with one tag or text run per line, indented two spaces per level. Text is
/// trimmed; `<script>` and `<style>` contents are kept as they are; comments, `<!DOCTYPE>`,
/// `<?xml?>`, self-closing and void tags don't open a level. Malformed input never fails:
/// a stray closing tag just doesn't go below level 0.
pub fn indent_markup(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    let line = |out: &mut String, depth: usize, text: &str| {
        out.push_str(&"  ".repeat(depth));
        out.push_str(text);
        out.push('\n');
    };
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' {
            // comments end at "-->", anything else at the first '>' outside quotes
            let end = if s[i..].starts_with("<!--") {
                s[i..].find("-->").map(|e| i + e + 3)
            } else {
                let mut q: Option<u8> = None;
                let mut j = i + 1;
                let mut found = None;
                while j < b.len() {
                    match (q, b[j]) {
                        (None, b'"' | b'\'') => q = Some(b[j]),
                        (Some(c), x) if x == c => q = None,
                        (None, b'>') => { found = Some(j + 1); break; }
                        _ => {}
                    }
                    j += 1;
                }
                found
            };
            let end = end.unwrap_or(b.len());
            let tag = &s[i..end];
            let name: String = tag.trim_start_matches(['<', '/']).chars().take_while(|c| c.is_alphanumeric() || matches!(c, '-' | ':' | '_')).collect::<String>().to_ascii_lowercase();
            if tag.starts_with("</") {
                depth = depth.saturating_sub(1);
                line(&mut out, depth, tag);
            } else if tag.starts_with("<!") || tag.starts_with("<?") || tag.ends_with("/>") || VOID.contains(&name.as_str()) {
                line(&mut out, depth, tag);
            } else {
                line(&mut out, depth, tag);
                depth += 1;
                // raw text elements: everything up to the closing tag, untouched
                if name == "script" || name == "style" {
                    let close = format!("</{name}");
                    let rest = &s[end..];
                    let stop = rest.to_ascii_lowercase().find(&close).map_or(s.len(), |k| end + k);
                    let inner = s[end..stop].trim();
                    if !inner.is_empty() {
                        for l in inner.lines() {
                            line(&mut out, depth, l.trim_end());
                        }
                    }
                    i = stop;
                    continue;
                }
            }
            i = end;
        } else {
            let next = s[i..].find('<').map_or(s.len(), |k| i + k);
            let text = s[i..next].trim();
            if !text.is_empty() {
                line(&mut out, depth, text);
            }
            i = next;
        }
    }
    out.truncate(out.trim_end().len());
    out
}

/// Bytes shown by the Hex view before "Show full message" (each row is ~78 characters, so
/// 64 KiB is already 4096 rows).
pub const HEX_LIMIT: usize = 64 * 1024;

/// A classic hex dump: `00000010  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|`
/// (offset, 16 bytes in two groups of 8, then the bytes as ASCII with '.' for anything
/// unprintable). Empty input gives an empty string.
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() / 16 * 79 + 79);
    for (row, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", row * 16));
        for k in 0..16 {
            match chunk.get(k) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
            if k == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        out.extend(chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        out.push_str("|\n");
    }
    out.truncate(out.trim_end_matches('\n').len());
    out
}

fn fmt(color: Color32, size: f32) -> TextFormat {
    TextFormat { font_id: FontId::monospace(size), color, ..Default::default() }
}

/// Colours for the Pretty view: the head as the Raw view colours it, the body by `kind`.
pub fn pretty_job(p: &Palette, text: &str, kind: BodyKind, size: f32) -> LayoutJob {
    let (head, body) = match text.split_once("\n\n") {
        Some((h, b)) if looks_like_head(h) => (Some(h), b),
        _ if looks_like_head(text) => (Some(text), ""),
        _ => (None, text),
    };
    let mut job = match head {
        Some(h) => {
            let mut j = crate::editor::highlight(p, h, false);
            if head.is_some_and(|h| h.len() < text.len()) {
                j.append("\n\n", 0.0, fmt(p.ed_text, size));
            }
            j
        }
        None => LayoutJob::default(),
    };
    match kind {
        BodyKind::Json => json_spans(&mut job, p, body, size),
        BodyKind::Markup => markup_spans(&mut job, p, body, size),
        BodyKind::Other => job.append(body, 0.0, fmt(p.ed_text, size)),
    }
    for s in &mut job.sections {
        s.format.font_id.size = size;
    }
    if job.text.is_empty() {
        job.append("", 0.0, fmt(p.ed_text, size));
    }
    job
}

/// JSON colours: keys, string values, numbers, true/false/null, punctuation in plain text.
fn json_spans(job: &mut LayoutJob, p: &Palette, s: &str, size: f32) {
    let b = s.as_bytes();
    let mut i = 0;
    let mut plain = 0; // start of the uncoloured run
    let flush = |job: &mut LayoutJob, from: usize, to: usize| if to > from { job.append(&s[from..to], 0.0, fmt(p.ed_text, size)); };
    while i < b.len() {
        let c = b[i];
        let (end, col) = if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            // a key is a string followed by ':'
            let key = s[end..].trim_start().starts_with(':');
            (end, if key { p.syn_key } else { p.syn_string })
        } else if c == b'-' || c.is_ascii_digit() {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_digit() || matches!(b[j], b'.' | b'e' | b'E' | b'+' | b'-')) {
                j += 1;
            }
            (j, p.syn_number)
        } else if let Some(w) = ["true", "false", "null"].iter().find(|w| s[i..].starts_with(**w)) {
            (i + w.len(), p.syn_literal)
        } else {
            i += 1;
            continue;
        };
        flush(job, plain, i);
        job.append(&s[i..end], 0.0, fmt(col, size));
        i = end;
        plain = end;
    }
    flush(job, plain, b.len());
}

/// Markup colours: tag names, attribute names and values; text and brackets plain.
fn markup_spans(job: &mut LayoutJob, p: &Palette, s: &str, size: f32) {
    let mut rest = s;
    while !rest.is_empty() {
        let Some(open) = rest.find('<') else {
            job.append(rest, 0.0, fmt(p.ed_text, size));
            break;
        };
        job.append(&rest[..open], 0.0, fmt(p.ed_text, size));
        let close = rest[open..].find('>').map_or(rest.len(), |k| open + k + 1);
        let tag = &rest[open..close];
        if tag.starts_with("<!--") {
            job.append(tag, 0.0, fmt(p.ed_line_numbers, size));
        } else {
            // "<" "/"? name, then attributes name="value", then ">" or "/>"
            let name_start = if tag.starts_with("</") { 2 } else { 1 };
            let name_end = tag[name_start..].find(|c: char| c.is_whitespace() || c == '>' || c == '/').map_or(tag.len(), |k| name_start + k);
            job.append(&tag[..name_start], 0.0, fmt(p.ed_text, size));
            job.append(&tag[name_start..name_end], 0.0, fmt(p.syn_key, size));
            let attrs = &tag[name_end..];
            let mut in_value: Option<char> = None;
            let mut buf = String::new();
            let mut col = p.syn_number;
            for ch in attrs.chars() {
                let next_col = match (in_value, ch) {
                    (None, '"' | '\'') => { in_value = Some(ch); p.syn_string }
                    (Some(q), c) if c == q => { in_value = None; p.syn_string }
                    (Some(_), _) => p.syn_string,
                    (None, '=' | '>' | '/') => p.ed_text,
                    (None, c) if c.is_whitespace() => p.ed_text,
                    (None, _) => p.syn_number,
                };
                if next_col != col && !buf.is_empty() {
                    job.append(&buf, 0.0, fmt(col, size));
                    buf.clear();
                }
                col = next_col;
                buf.push(ch);
            }
            if !buf.is_empty() {
                job.append(&buf, 0.0, fmt(col, size));
            }
        }
        rest = &rest[close..];
    }
}

/// Colours for the Hex view: offsets dim, bytes plain, the ASCII column like values.
pub fn hex_job(p: &Palette, text: &str, size: f32) -> LayoutJob {
    let mut job = LayoutJob::default();
    for line in text.split_inclusive('\n') {
        let (offset, rest) = line.split_at(line.len().min(10));
        job.append(offset, 0.0, fmt(p.ed_line_numbers, size));
        match rest.find(" |") {
            Some(k) => {
                job.append(&rest[..k + 1], 0.0, fmt(p.ed_text, size));
                job.append(&rest[k + 1..], 0.0, fmt(p.ed_param_value, size));
            }
            None => job.append(rest, 0.0, fmt(p.ed_text, size)),
        }
    }
    if job.text.is_empty() {
        job.append("", 0.0, fmt(p.ed_text, size));
    }
    job
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    /// Pretty lays out the body of a whole message, and a blank line is what tells it where
    /// that body starts. A head glued to its body by a single newline is not a message with a
    /// body: it reads as one long head and comes back untouched, which is exactly how a
    /// response recorded without that blank line used to arrive here.
    #[test]
    fn the_blank_line_is_what_separates_a_head_from_its_body() {
        let json = "{\"id\":8821,\"items\":[{\"sku\":\"A-1\"}]}";
        let html = "<html><body><p>Hi</p></body></html>";
        let cases: [(&str, String, BodyKind, &str); 5] = [
            ("a CRLF response with compact JSON",
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{json}"), BodyKind::Json, "\n  \"id\": 8821,"),
            ("an LF response with compact JSON",
                format!("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{json}"), BodyKind::Json, "\n  \"items\": ["),
            ("a request body counts the same",
                format!("POST /v1/orders HTTP/1.1\nHost: api.test\n\n{json}"), BodyKind::Json, "\n  \"id\": 8821,"),
            ("an HTML body is indented tag by tag",
                format!("HTTP/1.1 200 OK\nContent-Type: text/html\n\n{html}"), BodyKind::Markup, "\n  <body>\n"),
            // the shape the proxy used to record: no blank line, so no body to format
            ("a head glued to its body has no body",
                format!("HTTP/1.1 200 OK\nContent-Type: application/json\n{json}"), BodyKind::Other, json),
        ];
        assert_table!(cases, |idx, (what, raw, kind, want)| {
            let (out, got) = pretty_message(&raw);
            assert_eq!(got, kind, "case #{idx} ({what}): {raw:?}");
            assert!(out.contains(want), "case #{idx} ({what}): {want:?} missing from {out:?}");
            if kind == BodyKind::Other {
                assert_eq!(out, raw.replace("\r\n", "\n"), "case #{idx} ({what}): left as it came");
            }
        });
    }

    #[test]
    fn json_bodies_are_reindented_keeping_key_order() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"z\":1,\"a\":{\"b\":[true,null,\"x\"]},\"n\":-2.5e3}";
        let (out, kind) = pretty_message(raw);
        assert_eq!(kind, BodyKind::Json);
        assert_eq!(out, "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"z\": 1,\n  \"a\": {\n    \"b\": [\n      true,\n      null,\n      \"x\"\n    ]\n  },\n  \"n\": -2500.0\n}");
        // a bare JSON document (no head) is all body
        assert_eq!(pretty_message("[1,2]").0, "[\n  1,\n  2\n]");
    }

    #[test]
    fn other_bodies_and_broken_json_are_left_alone() {
        let raw = "POST /a HTTP/1.1\nHost: x\n\n{\"broken\": ";
        assert_eq!(pretty_message(raw), (raw.to_string(), BodyKind::Other));
        assert_eq!(pretty_message("GET / HTTP/1.1\nHost: x\n\n").0, "GET / HTTP/1.1\nHost: x");
        assert_eq!(pretty_message("").0, "");
        assert_eq!(pretty_message("plain text").0, "plain text");
    }

    #[test]
    fn markup_is_indented() {
        let html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Hi</title><script>if (a < b) { go(); }</script></head><body><p class=\"x>y\">Hello <b>you</b></p><br/><!-- note --></body></html>";
        assert_eq!(indent_markup(html), "<!DOCTYPE html>\n<html>\n  <head>\n    <meta charset=\"utf-8\">\n    <title>\n      Hi\n    </title>\n    <script>\n      if (a < b) { go(); }\n    </script>\n  </head>\n  <body>\n    <p class=\"x>y\">\n      Hello\n      <b>\n        you\n      </b>\n    </p>\n    <br/>\n    <!-- note -->\n  </body>\n</html>");
        let xml = "<?xml version=\"1.0\"?><a><b id='1'/><c>t</c></a>";
        assert_eq!(indent_markup(xml), "<?xml version=\"1.0\"?>\n<a>\n  <b id='1'/>\n  <c>\n    t\n  </c>\n</a>");
        // stray closing tags and an unterminated tag don't panic or underflow
        assert_eq!(indent_markup("</x></y><z"), "</x>\n</y>\n<z");
        let (_, kind) = pretty_message("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<p>a</p>");
        assert_eq!(kind, BodyKind::Markup);
    }

    #[test]
    fn hex_dump_rows() {
        assert_eq!(hex_dump(b""), "");
        assert_eq!(hex_dump(b"HTTP/1.1 200 OK\r\n"),
            "00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|\n\
             00000010  0a                                                |.|");
        let all: Vec<u8> = (0..=255).collect();
        let dump = hex_dump(&all);
        assert_eq!(dump.lines().count(), 16);
        assert!(dump.lines().nth(15).unwrap().starts_with("000000f0  f0 f1"));
        assert!(dump.lines().all(|l| l.len() == 78), "every full row is the same width");
    }

    #[test]
    fn colour_jobs_keep_the_text() {
        let p = crate::theme::palette(crate::theme::Look::Dark);
        for raw in ["", "HTTP/1.1 200 OK\n\n{\"a\":\"b\\\"c\",\"n\":1,\"t\":true}", "<a href=\"x\">t</a>", "\u{0}\u{1}binary\u{fffd}", "{\"unterminated"] {
            let (text, kind) = pretty_message(raw);
            let job = pretty_job(&p, &text, kind, 12.0);
            assert_eq!(job.text, text, "{raw:?}");
            let dump = hex_dump(raw.as_bytes());
            assert_eq!(hex_job(&p, &dump, 12.0).text, dump);
        }
        // keys and values get different colours
        let job = pretty_job(&p, "{\n  \"k\": \"v\"\n}", BodyKind::Json, 12.0);
        let colour_of = |needle: &str| {
            let at = job.text.find(needle).unwrap();
            job.sections.iter().find(|s| s.byte_range.contains(&at)).unwrap().format.color
        };
        assert_eq!(colour_of("\"k\""), p.syn_key);
        assert_eq!(colour_of("\"v\""), p.syn_string);
    }
}
