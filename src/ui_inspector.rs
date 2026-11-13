//! Inspector: a right-docked panel that breaks the current request (and response) into
//! request attributes, query parameters, headers, cookies and body parameters. Used by
//! Repeater, Proxy > Intercept and the HTTP history / site map / Logger message viewer.

use crate::theme::{bold, Palette};
use eframe::egui;
use egui::{RichText, Ui};

#[derive(Clone, Debug, PartialEq)]
pub struct InspectorState {
    pub show_inspector: bool,
    /// Width of the panel; dragging its edge changes it within `WIDTH_RANGE`.
    pub panel_width: f32,
}

/// Drag range for the panel. The floor is what a name column plus a readable value column
/// need: below it the values break into fragments a few characters wide. The ceiling lets a
/// long value (a token, a Set-Cookie) be read without leaving the panel.
pub const WIDTH_RANGE: std::ops::RangeInclusive<f32> = 260.0..=560.0;

impl Default for InspectorState {
    fn default() -> Self {
        InspectorState { show_inspector: true, panel_width: 300.0 }
    }
}

pub type Pairs = Vec<(String, String)>;

/// A request or response split into the parts the Inspector shows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Parsed {
    pub is_response: bool,
    /// Request: Method, Path, Protocol. Response: Protocol, Status, Reason.
    pub attributes: Pairs,
    pub query: Pairs,
    pub headers: Pairs,
    /// Request: from Cookie headers. Response: one per Set-Cookie header (attributes in the value).
    pub cookies: Pairs,
    /// Form or JSON body parameters; None when the body is neither.
    pub body: Option<Pairs>,
}

/// URL-decode a query or form component ('+' is a space).
fn decode(s: &str) -> String {
    crate::codec::url_decode(s)
}

/// `a=1&b=two+words&flag` as decoded pairs (a key without '=' has an empty value).
pub fn parse_query(q: &str) -> Pairs {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

/// Header lines up to the blank line; a value may contain colons ("Host: a.test:8080").
/// Lines without a colon are skipped.
pub fn parse_headers(lines: &[&str]) -> Pairs {
    lines.iter().filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).filter(|(k, _)| !k.is_empty()).collect()
}

/// `Cookie: a=1; b=2` → [(a, 1), (b, 2)].
pub fn parse_cookie_header(v: &str) -> Pairs {
    v.split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| match c.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => (c.to_string(), String::new()),
        })
        .collect()
}

/// `Set-Cookie: id=abc; Path=/; HttpOnly` → (id, "abc  (Path=/; HttpOnly)").
pub fn parse_set_cookie(v: &str) -> Option<(String, String)> {
    let mut parts = v.split(';').map(str::trim);
    let (name, value) = parts.next()?.split_once('=')?;
    let attrs: Vec<&str> = parts.filter(|a| !a.is_empty()).collect();
    let value = if attrs.is_empty() { value.trim().to_string() } else { format!("{}  ({})", value.trim(), attrs.join("; ")) };
    Some((name.trim().to_string(), value))
}

/// Top-level keys of a JSON object body (strings unquoted, other values as compact JSON).
fn json_params(body: &str) -> Option<Pairs> {
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let obj = v.as_object()?;
    Some(obj.iter().map(|(k, v)| (k.clone(), v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))).collect())
}

pub fn parse_message(raw: &str) -> Parsed {
    let raw = raw.replace("\r\n", "\n");
    let (head, body) = raw.split_once("\n\n").unwrap_or((raw.as_str(), ""));
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("").trim();
    let rest: Vec<&str> = lines.collect();
    let mut out = Parsed { headers: parse_headers(&rest), ..Default::default() };
    let tokens: Vec<&str> = first.split_whitespace().collect();
    // "HTTP/1.1 200 OK", or "200 OK" as Repeater keeps its response
    let status_first = tokens.first().is_some_and(|t| t.len() == 3 && t.bytes().all(|b| b.is_ascii_digit()));
    if first.starts_with("HTTP/") || status_first {
        out.is_response = true;
        let (proto, status, reason) = if status_first {
            (String::new(), tokens[0].to_string(), tokens[1..].join(" "))
        } else {
            (tokens.first().unwrap_or(&"").to_string(), tokens.get(1).unwrap_or(&"").to_string(), tokens.get(2..).map(|t| t.join(" ")).unwrap_or_default())
        };
        if !proto.is_empty() { out.attributes.push(("Protocol".into(), proto)); }
        out.attributes.push(("Status".into(), status));
        if !reason.is_empty() { out.attributes.push(("Reason".into(), reason)); }
        out.cookies = out.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).filter_map(|(_, v)| parse_set_cookie(v)).collect();
    } else if !tokens.is_empty() {
        let method = tokens[0].to_string();
        let target = tokens.get(1).copied().unwrap_or("");
        // absolute-form ("GET http://host/p?q HTTP/1.1", or history's "GET http://host/p?q")
        let path = match target.find("://") {
            Some(i) => target[i + 3..].find('/').map_or("/", |j| &target[i + 3 + j..]),
            None => target,
        };
        let path = path.split('#').next().unwrap_or(path);
        out.attributes.push(("Method".into(), method));
        out.attributes.push(("Path".into(), path.to_string()));
        if let Some(proto) = tokens.get(2) { out.attributes.push(("Protocol".into(), proto.to_string())); }
        if let Some((_, q)) = path.split_once('?') { out.query = parse_query(q); }
        out.cookies = out.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("cookie")).flat_map(|(_, v)| parse_cookie_header(v)).collect();
    }
    let ctype = out.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.to_ascii_lowercase()).unwrap_or_default();
    if !body.trim().is_empty() {
        out.body = if ctype.starts_with("application/x-www-form-urlencoded") {
            Some(parse_query(body.trim()))
        } else if ctype.contains("json") || (ctype.is_empty() && body.trim_start().starts_with('{')) {
            json_params(body)
        } else {
            None
        };
    }
    out
}

/// "Inspector" toggle for a view's toolbar: highlighted while the panel is shown.
pub fn toggle_button(ui: &mut Ui, state: &mut InspectorState) {
    let b = egui::Button::new("Inspector").selected(state.show_inspector);
    if ui.add(b).on_hover_text(if state.show_inspector { "Hide the Inspector" } else { "Show the Inspector" }).clicked() {
        state.show_inspector = !state.show_inspector;
    }
}

/// A `Set-Cookie` value split up: name, value, and each attribute (`Path=/`, `HttpOnly`...).
#[derive(Clone, Debug, PartialEq)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub attributes: Pairs,
}

pub fn parse_set_cookie_full(v: &str) -> Option<SetCookie> {
    let mut parts = v.split(';').map(str::trim);
    let (name, value) = parts.next()?.split_once('=')?;
    let attributes = parts.filter(|a| !a.is_empty()).map(|a| match a.split_once('=') {
        Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
        None => (a.to_string(), String::new()),
    }).collect();
    Some(SetCookie { name: name.trim().to_string(), value: value.trim().to_string(), attributes })
}

/// The Inspector panel, docked on the right of `ui`'s remaining space. `id` keeps each
/// view's panel apart; `message` identifies the message shown (a history entry, a held
/// request): when it changes, the Auto-Decoder starts empty. `response` is None when there
/// isn't one (yet).
#[allow(clippy::too_many_arguments)]
pub fn inspector_panel(ui: &mut Ui, p: &Palette, state: &mut InspectorState, id: &str, message: &str, request: &str, response: Option<&str>) {
    // tracked even while the panel is hidden, so it never shows a value from another message
    crate::editor::decoder_context(ui.ctx(), "message", format!("{id}/{message}"));
    if !state.show_inspector {
        return;
    }
    let shown = egui::SidePanel::right(egui::Id::new(("inspector", id))).resizable(true)
        .default_width(state.panel_width).width_range(WIDTH_RANGE)
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(8)))
        .show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(bold("Inspector", 13.5).color(p.strong));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(egui::Button::new(RichText::new("×").size(15.0).color(p.text)).frame(false)).on_hover_text("Hide the Inspector").clicked() {
                        state.show_inspector = false;
                    }
                });
            });
            ui.separator();
            egui::ScrollArea::vertical().id_salt(("inspector_scroll", id)).auto_shrink([false, false]).show(ui, |ui| {
                let pick = crate::editor::decoder_pick(ui.ctx());
                let mut rows = Rows { p, id, pick: pick.as_ref() };
                // parsed every frame, so only the start of a huge message is looked at
                let req = parse_message(crate::editor::capped(request, crate::editor::DISPLAY_LIMIT));
                let res = response.filter(|r| !r.trim().is_empty())
                    .map(|r| parse_message(crate::editor::capped(r, crate::editor::DISPLAY_LIMIT)));
                rows.section(ui, "Request attributes", "Attribute", &req.attributes, true);
                rows.section(ui, "Query Parameters", "Query", &req.query, true);
                if let Some(body) = &req.body {
                    rows.section(ui, "Body Parameters", "Body", body, true);
                }
                let set_cookies: Vec<SetCookie> = res.as_ref().map(|r| r.headers.iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                    .filter_map(|(_, v)| parse_set_cookie_full(v)).collect()).unwrap_or_default();
                rows.cookies(ui, &req.cookies, &set_cookies);
                rows.headers(ui, &req.headers, res.as_ref().map(|r| r.headers.as_slice()));
                if let Some(res) = &res {
                    rows.section(ui, "Response attributes", "Response", &res.attributes, false);
                }
                auto_decoder(ui, p, id, pick.as_ref());
            });
        });
    state.panel_width = shown.response.rect.width().clamp(*WIDTH_RANGE.start(), *WIDTH_RANGE.end());
}

/// Would wrapping `v` in a column `value_w` wide break it into fragments?
///
/// A value with somewhere to break (a media-type list, a Set-Cookie, anything with spaces)
/// wraps into two or three readable lines. One long token (a JWT, a base64 cursor, a session
/// id) has no break in it, so the wrapper cuts it wherever the column ends and the value
/// comes apart into slivers a few characters wide. Those are cut with an ellipsis instead:
/// the whole value is still on hover, under the copy button and in the Auto-Decoder.
/// `ch_w` is the width of one monospace character.
fn shreds_when_wrapped(v: &str, value_w: f32, ch_w: f32) -> bool {
    let longest = v.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(|part| part.chars().count())
        .max()
        .unwrap_or(0);
    (longest as f32) * ch_w > value_w
}

/// Draws key/value rows: click one to decode it below, copy it with its button or
/// right-click menu.
struct Rows<'a> {
    p: &'a Palette,
    id: &'a str,
    pick: Option<&'a crate::editor::DecodePick>,
}

impl Rows<'_> {
    /// A collapsible "Title (n)" section; "(Empty)" when there are no rows. `kind` names the
    /// rows for the Auto-Decoder ("Query q").
    fn section(&mut self, ui: &mut Ui, title: &str, kind: &str, rows: &[(String, String)], open: bool) {
        egui::CollapsingHeader::new(bold(format!("{title} ({})", rows.len()), 12.5).color(self.p.strong))
            .id_salt(("inspector_section", self.id, title))
            .default_open(open)
            .show(ui, |ui| {
                if rows.is_empty() {
                    ui.label(RichText::new("(Empty)").size(12.0).color(self.p.disabled));
                }
                for (k, v) in rows {
                    self.row(ui, kind, k, v, &[]);
                }
            });
    }

    /// Request cookies, then the response's Set-Cookie headers with their attributes.
    fn cookies(&mut self, ui: &mut Ui, request: &[(String, String)], set: &[SetCookie]) {
        egui::CollapsingHeader::new(bold(format!("Cookies ({})", request.len() + set.len()), 12.5).color(self.p.strong))
            .id_salt(("inspector_section", self.id, "Cookies"))
            .default_open(true)
            .show(ui, |ui| {
                if request.is_empty() && set.is_empty() {
                    ui.label(RichText::new("(Empty)").size(12.0).color(self.p.disabled));
                }
                if !request.is_empty() {
                    self.group(ui, "Sent (Cookie)");
                    for (k, v) in request {
                        self.row(ui, "Cookie", k, v, &[]);
                    }
                }
                if !set.is_empty() {
                    self.group(ui, "Set by the response (Set-Cookie)");
                    for c in set {
                        self.row(ui, "Set-Cookie", &c.name, &c.value, &c.attributes);
                    }
                }
            });
    }

    fn headers(&mut self, ui: &mut Ui, request: &[(String, String)], response: Option<&[(String, String)]>) {
        let n = request.len() + response.map_or(0, |r| r.len());
        egui::CollapsingHeader::new(bold(format!("Headers ({n})"), 12.5).color(self.p.strong))
            .id_salt(("inspector_section", self.id, "Headers"))
            .default_open(true)
            .show(ui, |ui| {
                self.group(ui, "Request");
                if request.is_empty() {
                    ui.label(RichText::new("(Empty)").size(12.0).color(self.p.disabled));
                }
                for (k, v) in request {
                    self.row(ui, "Header", k, v, &[]);
                }
                if let Some(response) = response {
                    self.group(ui, "Response");
                    for (k, v) in response {
                        self.row(ui, "Response header", k, v, &[]);
                    }
                }
            });
    }

    fn group(&self, ui: &mut Ui, title: &str) {
        ui.add_space(2.0);
        ui.label(RichText::new(title).size(11.5).color(self.p.disabled).italics());
    }

    /// One row: the name, the value (wrapped, monospace), a copy button; `attributes` (a
    /// Set-Cookie's) listed underneath. Clicking the row sends its value to the Auto-Decoder.
    fn row(&mut self, ui: &mut Ui, kind: &str, k: &str, v: &str, attributes: &[(String, String)]) {
        let p = self.p;
        let source = format!("{kind} {k}");
        let picked = self.pick.is_some_and(|d| d.source == source && d.text == v);
        // the highlight goes behind the row, so reserve its place before drawing the row
        let bg = ui.painter().add(egui::Shape::Noop);
        let width = ui.available_width();
        // the name column is kept narrow so the value keeps most of the panel; it never wraps,
        // so a name is one line ("Protocol", "X-Correlation-Id") whatever the panel's width
        let key_w = (width * 0.32).clamp(60.0, 110.0);
        let copy_w = 18.0;
        let value_w = (width - key_w - copy_w - 2.0 * ui.spacing().item_spacing.x).max(40.0);
        let ch_w = ui.fonts(|f| f.glyph_width(&egui::FontId::monospace(12.0), '0')).max(1.0);
        let shreds = shreds_when_wrapped(v, value_w, ch_w);
        let row = ui.horizontal_top(|ui| {
            let key = ui.allocate_ui_with_layout(egui::vec2(key_w, 0.0), egui::Layout::top_down(egui::Align::LEFT), |ui| {
                ui.set_width(key_w);
                ui.add(egui::Label::new(RichText::new(k).size(12.0).color(p.disabled)).truncate().sense(egui::Sense::click()))
            }).inner;
            let value = ui.allocate_ui_with_layout(egui::vec2(value_w, 0.0), egui::Layout::top_down(egui::Align::LEFT), |ui| {
                ui.set_width(value_w);
                let shown = if v.is_empty() { "(empty)" } else { v };
                let col = if v.is_empty() { p.disabled } else { p.text };
                let label = egui::Label::new(RichText::new(shown).size(12.0).monospace().color(col)).sense(egui::Sense::click());
                let r = ui.add(if shreds { label.truncate() } else { label.wrap() });
                for (a, av) in attributes {
                    let text = if av.is_empty() { a.clone() } else { format!("{a}={av}") };
                    ui.label(RichText::new(format!("· {text}")).size(11.0).color(p.disabled));
                }
                r
            }).inner;
            let copy = ui.add(egui::Button::new(RichText::new("📋").size(11.0).color(p.disabled)).frame(false).min_size(egui::vec2(copy_w, 16.0)))
                .on_hover_text("Copy the value");
            (key | value, copy)
        });
        let (hit, copy) = row.inner;
        if copy.clicked() {
            ui.ctx().copy_text(v.to_string());
        }
        if hit.clicked() {
            crate::editor::offer_to_decoder(ui.ctx(), &source, v);
        }
        // a cut name or value is read here in full, whatever the panel's width
        let hit = hit.on_hover_ui(|ui| {
            ui.set_max_width(480.0);
            ui.label(bold(k, 12.0).color(p.strong));
            if !v.is_empty() {
                ui.add(egui::Label::new(RichText::new(crate::editor::capped(v, 2048)).size(12.0).monospace().color(p.text)).wrap());
            }
            ui.add_space(2.0);
            ui.label(RichText::new("Click to decode in the Auto-Decoder below; right-click to copy").size(11.0).color(p.disabled));
        });
        hit.context_menu(|ui| {
            if ui.button("Copy value").clicked() {
                ui.ctx().copy_text(v.to_string());
                ui.close_menu();
            }
            if ui.button("Copy name and value").clicked() {
                let sep = if kind.contains("eader") { ": " } else { "=" };
                ui.ctx().copy_text(format!("{k}{sep}{v}"));
                ui.close_menu();
            }
            if ui.button("Decode").clicked() {
                crate::editor::offer_to_decoder(ui.ctx(), &source, v);
                ui.close_menu();
            }
        });
        let rect = row.response.rect.expand2(egui::vec2(2.0, 1.0));
        let fill = if picked { p.selection } else if hit.hovered() || copy.hovered() { p.header.gamma_multiply(0.5) } else { egui::Color32::TRANSPARENT };
        ui.painter().set(bg, egui::Shape::rect_filled(rect, 2.0, fill));
        ui.add_space(2.0);
    }
}

/// Longest card text drawn (the rest is reachable with the card's copy button).
const CARD_SHOWN: usize = 4096;

/// The Auto-Decoder: what the picked value decodes to, one card per guess.
fn auto_decoder(ui: &mut Ui, p: &Palette, id: &str, pick: Option<&crate::editor::DecodePick>) {
    egui::CollapsingHeader::new(bold("Auto-Decoder", 12.5).color(p.strong))
        .id_salt(("inspector_section", id, "Auto-Decoder"))
        .default_open(true)
        .show(ui, |ui| {
            let Some(pick) = pick else {
                ui.add(egui::Label::new(RichText::new("Click a parameter, cookie or header above, or select text in a message, to decode it here.").size(11.5).color(p.disabled)).wrap());
                return;
            };
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("From: {}", pick.source)).size(11.5).color(p.disabled));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Clear").clicked() {
                        crate::editor::clear_decoder_pick(ui.ctx());
                    }
                });
            });
            let cards = crate::autodecode::decode_cards(&pick.text);
            if cards.is_empty() {
                ui.label(RichText::new("(Empty value)").size(12.0).color(p.disabled));
            }
            for card in cards {
                egui::Frame::new().fill(p.panel).stroke(egui::Stroke::new(1.0_f32, p.header)).corner_radius(4.0)
                    .inner_margin(egui::Margin::same(6)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(bold(card.title, 12.0).color(p.strong));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(egui::Button::new(RichText::new("📋").size(11.0).color(p.disabled)).frame(false)).on_hover_text("Copy").clicked() {
                                    ui.ctx().copy_text(card.text.clone());
                                }
                            });
                        });
                        let shown = crate::editor::capped(&card.text, CARD_SHOWN);
                        let more = if shown.len() < card.text.len() { "\n…" } else { "" };
                        ui.add(egui::Label::new(RichText::new(format!("{shown}{more}")).size(11.5).monospace().color(p.text)).wrap().selectable(true));
                    });
                ui.add_space(4.0);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    fn pairs(v: &[(&str, &str)]) -> Pairs {
        v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// A value is only cut short when wrapping it would shred it: one unbroken token wider
    /// than its column. Anything with a break in it keeps wrapping and stays readable.
    #[test]
    fn values_wrap_unless_wrapping_would_shred_them() {
        // the Inspector's value column at its narrowest (panel at WIDTH_RANGE's floor) and a
        // 12px monospace character
        let (value_w, ch_w) = (150.0, 7.2);
        let fits = (value_w / ch_w) as usize; // 20 characters
        let cases: [(&str, String, bool); 7] = [
            ("short value", "HTTP/1.1".into(), false),
            ("empty value", String::new(), false),
            ("a list breaks at its commas", "application/json, text/plain;q=0.9, */*;q=0.5".into(), false),
            ("a Set-Cookie breaks at its semicolons", "id=xyz; Path=/; HttpOnly; SameSite=Lax".into(), false),
            ("a token just inside the column", "e".repeat(fits - 1), false),
            ("a token past the column", "e".repeat(fits + 8), true),
            ("a JWT in a Bearer header: the word breaks, the token does not", format!("Bearer {}", "e".repeat(300)), true),
        ];
        assert_table!(cases, |i, (what, v, shreds)| {
            assert_eq!(shreds_when_wrapped(&v, value_w, ch_w), shreds, "case {i} ({what})");
        });
        // a wider panel takes a value that a narrow one had to cut
        let token = "e".repeat(40);
        assert!(shreds_when_wrapped(&token, 150.0, 7.2));
        assert!(!shreds_when_wrapped(&token, 400.0, 7.2));
    }

    #[test]
    fn query_parameters_are_decoded() {
        let p = parse_message("GET /search?q=red+shoes&size=10%2F11&flag&empty=&enc%20key=%E2%9C%93#frag HTTP/1.1\nHost: a.test\n\n");
        assert_eq!(p.attributes, pairs(&[("Method", "GET"), ("Path", "/search?q=red+shoes&size=10%2F11&flag&empty=&enc%20key=%E2%9C%93"), ("Protocol", "HTTP/1.1")]));
        assert_eq!(p.query, pairs(&[("q", "red shoes"), ("size", "10/11"), ("flag", ""), ("empty", ""), ("enc key", "✓")]));
        // absolute-form, as history stores requests sent by Repeater and Intruder
        let p = parse_message("GET https://a.test:8443/p?x=1");
        assert_eq!(p.attributes[1], ("Path".to_string(), "/p?x=1".to_string()));
        assert_eq!(p.query, pairs(&[("x", "1")]));
        assert!(parse_message("GET / HTTP/1.1\n\n").query.is_empty());
    }

    #[test]
    fn headers_keep_colons_in_values() {
        let p = parse_message("GET / HTTP/1.1\r\nHost: a.test:8080\r\nReferer: https://b.test/x?y=1\r\nX-Empty:\r\nnot a header\r\nAccept: */*\r\n\r\nbody: not a header");
        assert_eq!(p.headers, pairs(&[("Host", "a.test:8080"), ("Referer", "https://b.test/x?y=1"), ("X-Empty", ""), ("Accept", "*/*")]));
    }

    #[test]
    fn cookies() {
        let p = parse_message("GET / HTTP/1.1\nCookie: session=abc123; theme=dark; flag\nCookie: second=2\n\n");
        assert_eq!(p.cookies, pairs(&[("session", "abc123"), ("theme", "dark"), ("flag", ""), ("second", "2")]));
        let r = parse_message("HTTP/1.1 200 OK\nSet-Cookie: id=xyz; Path=/; HttpOnly\nSet-Cookie: plain=1\nContent-Type: text/html\n\n<p>");
        assert!(r.is_response);
        assert_eq!(r.attributes, pairs(&[("Protocol", "HTTP/1.1"), ("Status", "200"), ("Reason", "OK")]));
        assert_eq!(r.cookies, pairs(&[("id", "xyz  (Path=/; HttpOnly)"), ("plain", "1")]));
        assert_eq!(r.body, None, "HTML bodies have no parameters");
    }

    #[test]
    fn repeater_style_response() {
        // Repeater keeps "200 OK\n<headers>\n\n<body>"
        let r = parse_message("404 Not Found\nContent-Type: application/json\n\n{\"error\":\"missing\",\"code\":44,\"ok\":false}");
        assert!(r.is_response);
        assert_eq!(r.attributes, pairs(&[("Status", "404"), ("Reason", "Not Found")]));
        assert_eq!(r.body.unwrap(), pairs(&[("error", "missing"), ("code", "44"), ("ok", "false")]));
    }

    #[test]
    fn body_parameters() {
        let p = parse_message("POST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\n\nuser=al%40ice&pass=p+w");
        assert_eq!(p.body.unwrap(), pairs(&[("user", "al@ice"), ("pass", "p w")]));
        let p = parse_message("POST /api HTTP/1.1\nContent-Type: application/json\n\n{\"id\": 7, \"tags\": [\"a\",\"b\"], \"name\": \"x\"}");
        assert_eq!(p.body.unwrap(), pairs(&[("id", "7"), ("tags", "[\"a\",\"b\"]"), ("name", "x")]));
        assert_eq!(parse_message("POST / HTTP/1.1\nContent-Type: text/plain\n\nhello").body, None);
        assert_eq!(parse_message("POST / HTTP/1.1\nContent-Type: application/json\n\nnot json").body, None);
    }

    #[test]
    fn set_cookie_attributes() {
        let c = parse_set_cookie_full("id=a=b; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600").unwrap();
        assert_eq!((c.name.as_str(), c.value.as_str()), ("id", "a=b"));
        assert_eq!(c.attributes, pairs(&[("Path", "/"), ("Secure", ""), ("HttpOnly", ""), ("SameSite", "Lax"), ("Max-Age", "3600")]));
        assert!(parse_set_cookie_full("no-equals").is_none());
    }
}

#[cfg(test)]
mod ui_tests {
    use crate::editor::{set_view_mode, MessageViewMode};
    use crate::state::App;
    use eframe::egui;

    fn app_on_history(request: &str, response: &str) -> (egui::Context, App) {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = App::new(&cc, Some("/dev/null".into()), None, false);
        app.tab = crate::state::Tab::Proxy;
        app.proxy_sub = 1;
        app.history.lock().unwrap().push(std::sync::Arc::new(crate::http::HttpEntry {
            id: 1, tool: "Proxy".into(), method: "GET".into(), host: "shop.test".into(), path: "/".into(),
            status: "200 OK".into(), length: response.len(), mime: "application/octet-stream".into(),
            request: request.into(), response: response.into(), url: "http://shop.test/".into(), truncated: false, time: 0, elapsed_ms: 0,
        }));
        app.history_sel = Some(1);
        (ctx, app)
    }

    fn frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> Option<egui::accesskit::TreeUpdate> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 900.0))),
            events,
            ..Default::default()
        };
        ctx.run(input, |ctx| crate::ui_core::frame(app, ctx)).platform_output.accesskit_update
    }

    fn all_modes(ctx: &egui::Context, app: &mut App) {
        for mode in MessageViewMode::ALL {
            for view in ["tv_req", "tv_resp"] {
                set_view_mode(ctx, view, mode);
            }
            frame(ctx, app, vec![]);
            frame(ctx, app, vec![]);
        }
    }

    #[test]
    fn view_modes_and_inspector_toggle_survive_binary_and_empty_messages() {
        let binary: String = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".to_string()
            + "\u{0}\u{1}\u{2}\u{fffd}\u{fffd}PK\u{3}\u{4}{\"not\": json";
        for (request, response) in [("", ""), ("", binary.as_str()), ("GET / HTTP/1.1\n\n", "{\"a\":[1,2"), ("\u{0}", "<<<>>>")] {
            let (ctx, mut app) = app_on_history(request, response);
            all_modes(&ctx, &mut app);
            // Ctrl+Shift+N hides the Inspector, and shows it again
            let shown = app.inspector.show_inspector;
            let ctrl_shift_n = || egui::Event::Key { key: egui::Key::N, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::COMMAND | egui::Modifiers::SHIFT };
            frame(&ctx, &mut app, vec![ctrl_shift_n()]);
            assert_eq!(app.inspector.show_inspector, !shown);
            all_modes(&ctx, &mut app);
            frame(&ctx, &mut app, vec![ctrl_shift_n()]);
            assert_eq!(app.inspector.show_inspector, shown);
            all_modes(&ctx, &mut app);
        }
    }

    #[test]
    fn clicking_an_inspector_row_feeds_the_auto_decoder() {
        let (ctx, mut app) = app_on_history("GET /?token=aGVsbG8gd29ybGQ%3D HTTP/1.1\nHost: shop.test\n\n", "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nok");
        app.inspector.show_inspector = true;
        frame(&ctx, &mut app, vec![]);
        let update = frame(&ctx, &mut app, vec![]);
        let nodes = &update.expect("accesskit").nodes;
        // the query row's value, decoded from the URL: "aGVsbG8gd29ybGQ="
        let r = nodes.iter().find(|(_, n)| n.label() == Some("aGVsbG8gd29ybGQ=") || n.value() == Some("aGVsbG8gd29ybGQ="))
            .and_then(|(_, n)| n.bounds()).expect("the token row");
        let at = egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32);
        let button = |pressed| egui::Event::PointerButton { pos: at, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        frame(&ctx, &mut app, vec![egui::Event::PointerMoved(at), button(true)]);
        frame(&ctx, &mut app, vec![button(false)]);
        let pick = crate::editor::decoder_pick(&ctx).expect("picked");
        assert_eq!((pick.source.as_str(), pick.text.as_str()), ("Query token", "aGVsbG8gd29ybGQ="));
        let cards = crate::autodecode::decode_cards(&pick.text);
        assert!(cards.iter().any(|c| c.title == "Base64 decoded" && c.text == "hello world"));
        frame(&ctx, &mut app, vec![]);
    }

    fn center(r: egui::accesskit::Rect) -> egui::Pos2 {
        egui::pos2(((r.x0 + r.x1) / 2.0) as f32, ((r.y0 + r.y1) / 2.0) as f32)
    }

    /// Bounds of the node whose label or value is `text` in a fresh full frame.
    fn bounds_of(ctx: &egui::Context, app: &mut App, text: &str) -> egui::accesskit::Rect {
        let update = frame(ctx, app, vec![]).expect("accesskit");
        update.nodes.iter().find(|(_, n)| n.label() == Some(text) || n.value() == Some(text))
            .and_then(|(_, n)| n.bounds()).unwrap_or_else(|| panic!("nothing shows {text:?}"))
    }

    fn press_release(ctx: &egui::Context, app: &mut App, from: egui::Pos2, to: egui::Pos2) {
        let button = |pos, pressed| egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        frame(ctx, app, vec![egui::Event::PointerMoved(from), button(from, true)]);
        frame(ctx, app, vec![egui::Event::PointerMoved(to)]);
        frame(ctx, app, vec![button(to, false)]);
        frame(ctx, app, vec![]);
    }

    fn click_text(ctx: &egui::Context, app: &mut App, text: &str) {
        frame(ctx, app, vec![]);
        let at = center(bounds_of(ctx, app, text));
        press_release(ctx, app, at, at);
    }

    fn picked(ctx: &egui::Context) -> Option<(String, String)> {
        crate::editor::decoder_pick(ctx).map(|p| (p.source, p.text))
    }

    /// History with two entries, the first selected, the Inspector shown.
    fn two_entries() -> (egui::Context, App) {
        let (ctx, mut app) = app_on_history("GET /?q=first HTTP/1.1\nHost: a.test\n\n", "HTTP/1.1 200 OK\nX-Token: one\n\nfirst body text");
        let mut second = (*app.history.lock().unwrap()[0]).clone();
        second.id = 2;
        second.request = "GET /?q=second HTTP/1.1\nHost: a.test\n\n".into();
        app.history.lock().unwrap().push(std::sync::Arc::new(second));
        app.inspector.show_inspector = true;
        (ctx, app)
    }

    #[test]
    fn switching_message_or_tab_clears_the_auto_decoder() {
        let (ctx, mut app) = two_entries();
        click_text(&ctx, &mut app, "first");
        assert_eq!(picked(&ctx), Some(("Query q".into(), "first".into())));
        // another history entry
        app.history_sel = Some(2);
        frame(&ctx, &mut app, vec![]);
        assert_eq!(picked(&ctx), None, "a different message starts empty");
        // pick again, then go to another tab and back
        click_text(&ctx, &mut app, "second");
        assert!(picked(&ctx).is_some());
        app.tab = crate::state::Tab::Repeater;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(picked(&ctx), None, "another tab starts empty");
        app.tab = crate::state::Tab::Proxy;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(picked(&ctx), None);
        // a sub-tab change counts too
        click_text(&ctx, &mut app, "second");
        assert!(picked(&ctx).is_some());
        app.proxy_sub = 0;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(picked(&ctx), None);
    }

    #[test]
    fn text_highlighted_in_the_focused_pane_survives() {
        let (ctx, mut app) = two_entries();
        frame(&ctx, &mut app, vec![]);
        // drag across the start of the response text (Raw view): selected, pane focused
        let r = bounds_of(&ctx, &mut app, "HTTP/1.1 200 OK\nX-Token: one\n\nfirst body text");
        let y = r.y0 as f32 + 8.0;
        press_release(&ctx, &mut app, egui::pos2(r.x0 as f32 + 2.0, y), egui::pos2(r.x0 as f32 + 60.0, y));
        let (source, text) = picked(&ctx).expect("the selection is offered");
        assert_eq!(source, "Selection");
        assert!("HTTP/1.1 200 OK".starts_with(&text) && !text.is_empty(), "{text:?}");
        // the message key changes while that pane keeps its highlight: it comes straight back
        crate::editor::decoder_context(&ctx, "message", "something else".into());
        assert_eq!(picked(&ctx), None);
        frame(&ctx, &mut app, vec![]);
        frame(&ctx, &mut app, vec![]);
        assert_eq!(picked(&ctx).map(|p| p.0), Some("Selection".into()));
        // clicking an Inspector row moves focus away: the old highlight no longer overrides it
        click_text(&ctx, &mut app, "first");
        for _ in 0..3 {
            frame(&ctx, &mut app, vec![]);
        }
        assert_eq!(picked(&ctx), Some(("Query q".into(), "first".into())));
    }

    #[test]
    fn switching_repeater_tabs_changes_the_decoder_context() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = App::new(&cc, Some("/dev/null".into()), None, false);
        app.inspector.show_inspector = true;
        app.rep_mut().request = "GET /?q=tabone HTTP/1.1\nHost: a.test\n\n".into();
        crate::actions::send_to_repeater(&mut app, "GET", "http://a.test/", "GET /?q=tabtwo HTTP/1.1\nHost: a.test\n\n");
        app.active_repeater_tab = 0;
        let (one, two) = (app.repeater_tabs[0].id, app.repeater_tabs[1].id);
        frame(&ctx, &mut app, vec![]);
        assert_eq!(crate::editor::decoder_context_key(&ctx, "message"), Some(format!("repeater/{one}")));
        click_text(&ctx, &mut app, "tabone");
        assert_eq!(picked(&ctx), Some(("Query q".into(), "tabone".into())));
        // click tab "2" in the strip
        click_text(&ctx, &mut app, "2");
        assert_eq!(app.active_repeater_tab, 1);
        assert_eq!(crate::editor::decoder_context_key(&ctx, "message"), Some(format!("repeater/{two}")));
        assert_eq!(picked(&ctx), None, "the other tab starts with an empty Auto-Decoder");
        // and back
        click_text(&ctx, &mut app, "tabtwo");
        assert!(picked(&ctx).is_some());
        app.active_repeater_tab = 0;
        frame(&ctx, &mut app, vec![]);
        assert_eq!(picked(&ctx), None);
    }
}
