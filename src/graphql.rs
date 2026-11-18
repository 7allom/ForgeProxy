//! GraphQL requests: recognising them, and saying what operation they carry.
//!
//! Every operation against a GraphQL endpoint is the same method on the same path, so a
//! history row says nothing that tells one apart from another. What tells them apart is the
//! operation: its kind (query, mutation, subscription) and its name. This works that out from
//! the raw request, and formats the document and its variables for reading.
//!
//! There is no GraphQL parser here, and there is deliberately not going to be one. A request
//! is recognised by its envelope, and the document is re-indented by its brackets. Anything
//! this does not understand is passed through as it stands rather than dropped.

/// What an operation is. The shorthand `{ ... }` form, which names no kind, is a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    Query,
    Mutation,
    Subscription,
}

impl OperationKind {
    pub fn label(self) -> &'static str {
        match self {
            OperationKind::Query => "query",
            OperationKind::Mutation => "mutation",
            OperationKind::Subscription => "subscription",
        }
    }
}

/// One operation carried by a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub kind: OperationKind,
    /// The operation's name, when it has one. The shorthand form and `query { ... }` do not.
    pub name: Option<String>,
}

/// The operations a request carries, or none at all when it isn't GraphQL.
///
/// Three shapes are recognised: a body that is the document itself (`application/graphql`), a
/// JSON envelope with a `query` string (one operation, or an array of them for a batch), and a
/// `GET` carrying the same fields in its query string.
pub fn operations(raw_request: &str) -> Vec<Operation> {
    // the cheap way out first: a project may hold tens of thousands of requests, and all but
    // a few of them say nothing that could make them GraphQL
    if !looks_possible(raw_request) {
        return Vec::new();
    }
    // a body sent as the document itself carries no envelope to read
    if header(raw_request, "content-type").is_some_and(|v| v.to_ascii_lowercase().contains("application/graphql")) {
        return first_operation(body_of(raw_request)).into_iter().collect();
    }
    if let Some(ops) = from_query_string(raw_request) {
        return ops;
    }
    let Some(value) = parse_json(body_of(raw_request)) else { return Vec::new() };
    match value {
        serde_json::Value::Array(items) => items.iter().filter_map(envelope).collect(),
        single => envelope(&single).into_iter().collect(),
    }
}

/// A header's value from the request head, by name, case-insensitively.
fn header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.lines()
        .take_while(|l| !l.trim().is_empty())
        .skip(1)
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
}

/// The operation a `GET` carries in its query string, when it carries one. `None` means this
/// is not that shape of request, which is not the same as a request that carries nothing.
fn from_query_string(raw: &str) -> Option<Vec<Operation>> {
    let first = raw.lines().next()?;
    let mut parts = first.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("GET") {
        return None;
    }
    let (_, query) = parts.next()?.split_once('?')?;
    let param = |name: &str| {
        query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| crate::codec::url_decode(v))
        })
    };
    let mut op = first_operation(&param("query")?)?;
    if let Some(name) = param("operationName") {
        let name = name.trim().to_string();
        if !name.is_empty() {
            op.name = Some(name);
        }
    }
    Some(vec![op])
}

/// Could this be GraphQL at all? A substring scan, so running it over a whole project costs
/// about as much as reading the requests does. "graphql" is in here for the shorthand form,
/// which names no kind and would otherwise be missed wherever it is sent.
fn looks_possible(raw: &str) -> bool {
    raw.contains("query") || raw.contains("mutation") || raw.contains("subscription") || raw.contains("graphql")
}

/// Is this text a GraphQL document rather than a word that happens to be one of its keywords?
///
/// A parameter called `query` on a site search is the common way to be wrong about this, and
/// being wrong puts a made-up operation in a column people sort and search by. Every document
/// has a selection set, and prose does not.
fn has_selection_set(document: &str) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for c in document.chars() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string && depth > 0 => return true,
            _ => {}
        }
    }
    false
}

/// Everything after the blank line that ends the head, either line ending. A request with no
/// blank line has no body, and a head on its own is never a GraphQL document.
fn body_of(raw: &str) -> &str {
    let crlf = raw.find("\r\n\r\n").map(|i| i + 4);
    let lf = raw.find("\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => &raw[a.min(b)..],
        (Some(i), None) | (None, Some(i)) => &raw[i..],
        // nothing that reads as a head: the text is the document itself, which is how a
        // message carried over a socket arrives
        (None, None) => raw,
    }
}

/// A JSON document, when the text is one. Anything else (a form post, a query string) is not
/// an envelope this understands.
fn parse_json(body: &str) -> Option<serde_json::Value> {
    let t = body.trim();
    if !t.starts_with('{') && !t.starts_with('[') {
        return None;
    }
    serde_json::from_str(t).ok()
}

/// Carried over a socket, the operation sits one level down, under `payload`, inside a
/// message that says what it is. Anything else is already the envelope.
fn unwrap_envelope(value: &serde_json::Value) -> &serde_json::Value {
    match value.get("payload") {
        Some(inner) if inner.get("query").is_some() => inner,
        _ => value,
    }
}

/// One `{"query": ..., "operationName": ...}` envelope. The name the envelope gives wins over
/// the one in the document: with several operations in one document it is what picks between
/// them, so it is what the server actually ran.
fn envelope(value: &serde_json::Value) -> Option<Operation> {
    let value = unwrap_envelope(value);
    let document = value.get("query")?.as_str()?;
    let mut op = first_operation(document)?;
    if let Some(name) = value.get("operationName").and_then(|n| n.as_str()) {
        let name = name.trim();
        if !name.is_empty() {
            op.name = Some(name.to_string());
        }
    }
    Some(op)
}

/// The first operation a document declares. `{ ... }` on its own is the shorthand for a query.
fn first_operation(document: &str) -> Option<Operation> {
    if !has_selection_set(document) {
        return None;
    }
    let rest = skip_ignored(document);
    if rest.starts_with('{') {
        return Some(Operation { kind: OperationKind::Query, name: None });
    }
    let (keyword, rest) = word(rest);
    let kind = match keyword {
        "query" => OperationKind::Query,
        "mutation" => OperationKind::Mutation,
        "subscription" => OperationKind::Subscription,
        _ => return None,
    };
    let (name, _) = word(skip_ignored(rest));
    Some(Operation { kind, name: (!name.is_empty()).then(|| name.to_string()) })
}

/// Past whitespace, commas (which GraphQL treats as whitespace) and `#` comments.
fn skip_ignored(s: &str) -> &str {
    let mut s = s.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
    while let Some(rest) = s.strip_prefix('#') {
        s = rest.find('\n').map_or("", |i| &rest[i..]);
        s = s.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
    }
    s
}

/// The leading name, and what follows it. A GraphQL name is letters, digits and underscores.
fn word(s: &str) -> (&str, &str) {
    let end = s.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(s.len());
    (&s[..end], &s[end..])
}

/// What the traffic tables show in their Operation column: "mutation SignIn", "query" when the
/// operation is anonymous, "query A +2 more" for a batch, and "" when this isn't GraphQL.
pub fn operation_label(raw_request: &str) -> String {
    let ops = operations(raw_request);
    let Some(first) = ops.first() else { return String::new() };
    let mut out = match &first.name {
        Some(name) => format!("{} {name}", first.kind.label()),
        None => first.kind.label().to_string(),
    };
    if ops.len() > 1 {
        out.push_str(&format!(" +{} more", ops.len() - 1));
    }
    out
}

/// The request's GraphQL as it reads: the document re-indented, and the variables under it as
/// JSON. `None` when the request carries no GraphQL at all.
///
/// Brackets drive the indentation and nothing else is interpreted, so a document using syntax
/// this does not know comes through unharmed rather than mangled.
pub fn formatted(raw_request: &str) -> Option<String> {
    let (document, variables) = document_and_variables(raw_request)?;
    let mut out = indent_document(&document);
    if let Some(vars) = variables {
        out.push_str("\n\nVariables\n");
        out.push_str(&serde_json::to_string_pretty(&vars).unwrap_or_else(|_| vars.to_string()));
    }
    Some(out)
}

/// The document a request carries and the variables beside it. A batch is shown by its first
/// operation, which is the one the row is named after.
fn document_and_variables(raw: &str) -> Option<(String, Option<serde_json::Value>)> {
    if !looks_possible(raw) {
        return None;
    }
    if header(raw, "content-type").is_some_and(|v| v.to_ascii_lowercase().contains("application/graphql")) {
        let body = body_of(raw);
        return first_operation(body).map(|_| (body.to_string(), None));
    }
    if let Some(first) = raw.lines().next() {
        if first.split_whitespace().next().is_some_and(|m| m.eq_ignore_ascii_case("GET")) {
            let ops = from_query_string(raw)?;
            let _ = ops.first()?;
            let (_, query) = first.split_whitespace().nth(1)?.split_once('?')?;
            let param = |name: &str| {
                query.split('&').find_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    (k == name).then(|| crate::codec::url_decode(v))
                })
            };
            let document = param("query")?;
            let variables = param("variables").and_then(|v| serde_json::from_str(&v).ok());
            return Some((document, variables));
        }
    }
    let value = parse_json(body_of(raw))?;
    let envelope_value = match &value {
        serde_json::Value::Array(items) => items.first()?,
        single => single,
    };
    let envelope_value = unwrap_envelope(envelope_value);
    let document = envelope_value.get("query")?.as_str()?;
    first_operation(document)?;
    let variables = envelope_value
        .get("variables")
        .filter(|v| !v.is_null())
        .cloned();
    Some((document.to_string(), variables))
}

/// Re-indent a document by its brackets.
///
/// Three things decide what a gap between two words becomes. Inside a selection set it is a
/// line break, because that is how fields read. Before the first `{`, where the operation
/// names itself, and inside an argument list, it stays a space. And inside a string literal
/// nothing is interpreted at all: the literal is copied across whole, so a brace within one
/// neither opens a line nor shifts the indentation.
fn indent_document(document: &str) -> String {
    let mut out = String::with_capacity(document.len() + document.len() / 4);
    let mut depth = 0usize;
    let mut paren = 0usize;
    let mut at_line_start = true;
    // what the gap seen so far should become once the next real character says what follows it
    let mut pending_space = false;
    let mut pending_break = false;

    fn indent_to(out: &mut String, depth: usize) {
        for _ in 0..depth {
            out.push_str("  ");
        }
    }

    let mut chars = document.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                if at_line_start {
                    indent_to(&mut out, depth);
                } else if !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push('{');
                out.push('\n');
                depth += 1;
                at_line_start = true;
                (pending_space, pending_break) = (false, false);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if !at_line_start {
                    out.push('\n');
                }
                indent_to(&mut out, depth);
                out.push('}');
                out.push('\n');
                at_line_start = true;
                (pending_space, pending_break) = (false, false);
            }
            // a gap: inside a selection set it separates fields, anywhere else it is just a gap
            c if c.is_whitespace() || c == ',' => {
                if c == ',' && paren > 0 {
                    settle(&mut out, &mut at_line_start, &mut pending_space, &mut pending_break, depth);
                    out.push(',');
                }
                if depth > 0 && paren == 0 {
                    pending_break = !at_line_start;
                } else {
                    pending_space = !at_line_start;
                }
            }
            c => {
                settle(&mut out, &mut at_line_start, &mut pending_space, &mut pending_break, depth);
                out.push(c);
                match c {
                    '(' => paren += 1,
                    ')' => paren = paren.saturating_sub(1),
                    '"' => copy_string_literal(&mut out, &mut chars),
                    _ => {}
                }
            }
        }
    }
    out.trim_end().to_string()
}

/// Put down whatever the gap before this character came to, and the indentation if it starts
/// a line.
fn settle(out: &mut String, at_line_start: &mut bool, pending_space: &mut bool, pending_break: &mut bool, depth: usize) {
    if *pending_break && !*at_line_start {
        out.push('\n');
        *at_line_start = true;
    }
    if *at_line_start {
        for _ in 0..depth {
            out.push_str("  ");
        }
        *at_line_start = false;
    } else if *pending_space {
        out.push(' ');
    }
    (*pending_space, *pending_break) = (false, false);
}

/// Copy the rest of a string literal, escapes and all, after its opening quote.
fn copy_string_literal(out: &mut String, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
            continue;
        }
        if c == '"' {
            return;
        }
    }
}

/// What the Inspector lists for a GraphQL request: the operation, then each variable it was
/// given. Empty when the request carries no GraphQL.
pub fn inspector_rows(raw_request: &str) -> Vec<(String, String)> {
    let label = operation_label(raw_request);
    if label.is_empty() {
        return Vec::new();
    }
    let mut rows = vec![("Operation".to_string(), label)];
    if let Some((_, Some(serde_json::Value::Object(vars)))) = document_and_variables(raw_request) {
        for (name, value) in vars {
            // a string variable reads better without its quotes; anything else as it stands
            let shown = match value {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            rows.push((name, shown));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    /// A request as the proxy records it: head, blank line, body.
    fn post(body: &str) -> String {
        format!("POST /graphql HTTP/1.1\nHost: shop.test\nContent-Type: application/json\n\n{body}")
    }

    #[test]
    fn an_operation_is_named_by_its_kind_and_name() {
        let raw = post(r#"{"query":"mutation SignIn($who: String!) { signIn(who: $who) { token } }"}"#);
        assert_eq!(
            operations(&raw),
            vec![Operation { kind: OperationKind::Mutation, name: Some("SignIn".into()) }],
        );
        assert_eq!(operation_label(&raw), "mutation SignIn");
    }

    #[test]
    fn an_anonymous_operation_is_named_by_its_kind_alone() {
        let raw = post(r#"{"query":"{ me { id } }"}"#);
        assert_eq!(operations(&raw), vec![Operation { kind: OperationKind::Query, name: None }]);
        assert_eq!(operation_label(&raw), "query", "the shorthand form is a query");
    }

    #[test]
    fn the_envelopes_operation_name_wins_over_the_documents() {
        // a document may declare several operations; operationName is what picks the one the
        // server runs, so it is what the row should say
        let raw = post(
            r#"{"query":"query First { a } query Second { b }","operationName":"Second"}"#,
        );
        assert_eq!(operation_label(&raw), "query Second");
    }

    #[test]
    fn a_batch_says_how_many_more_it_carries() {
        let raw = post(
            r#"[{"query":"query A { a }"},{"query":"mutation B { b }"},{"query":"{ c }"}]"#,
        );
        assert_eq!(operations(&raw).len(), 3);
        assert_eq!(operation_label(&raw), "query A +2 more");
    }

    #[test]
    fn a_body_that_is_the_document_itself_is_recognised_by_its_content_type() {
        let raw = "POST /graphql HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/graphql\r\n\r\n                   subscription Ticks { ticks { at } }";
        assert_eq!(operation_label(raw), "subscription Ticks");
    }

    #[test]
    fn a_get_carries_its_operation_in_the_query_string() {
        let raw = "GET /graphql?query=mutation%20SignOut%20%7B%20signOut%20%7D&foo=1 HTTP/1.1\nHost: shop.test\n\n";
        assert_eq!(operation_label(raw), "mutation SignOut");
    }

    #[test]
    fn comments_and_leading_commas_before_the_operation_are_passed_over() {
        let raw = post(r##"{"query":"# what this does\n\n  mutation Pay { pay }"}"##);
        assert_eq!(operation_label(&raw), "mutation Pay");
    }

    #[test]
    fn the_document_is_re_indented_by_its_brackets() {
        let raw = post(r#"{"query":"query Me { me { id name friends(first: 3) { id } } }"}"#);
        assert_eq!(
            formatted(&raw).expect("it is GraphQL"),
            "query Me {\n  me {\n    id\n    name\n    friends(first: 3) {\n      id\n    }\n  }\n}",
        );
    }

    #[test]
    fn the_variables_are_shown_under_the_document() {
        let raw = post(r#"{"query":"mutation Pay($amount: Int!) { pay(amount: $amount) }","variables":{"amount":500}}"#);
        let out = formatted(&raw).expect("it is GraphQL");
        assert!(out.starts_with("mutation Pay($amount: Int!) {\n  pay(amount: $amount)\n}"), "{out}");
        assert!(out.contains("Variables\n{\n  \"amount\": 500\n}"), "{out}");
    }

    #[test]
    fn braces_inside_a_string_do_not_indent_anything() {
        let raw = post(r#"{"query":"query { search(term: \"a { b\") { id } }"}"#);
        let out = formatted(&raw).expect("it is GraphQL");
        assert!(out.contains(r#"search(term: "a { b")"#), "the string is left whole: {out}");
        assert_eq!(out.lines().count(), 5, "and only the real braces opened lines: {out}");
    }

    #[test]
    fn the_inspector_lists_the_operation_and_each_variable() {
        let raw = post(
            r#"{"query":"mutation Pay($amount: Int!, $to: String) { pay }","variables":{"amount":500,"to":"a"}}"#,
        );
        assert_eq!(
            inspector_rows(&raw),
            vec![
                ("Operation".to_string(), "mutation Pay".to_string()),
                ("amount".to_string(), "500".to_string()),
                ("to".to_string(), "a".to_string()),
            ],
        );
        assert!(inspector_rows(&post(r#"{"user":"a"}"#)).is_empty(), "and nothing for a request that is not GraphQL");
    }

    #[test]
    fn a_request_that_is_not_graphql_has_nothing_to_format() {
        assert!(formatted(&post(r#"{"user":"a"}"#)).is_none());
    }

    /// Over a WebSocket there is no request around the document: the message is the JSON on
    /// its own, and the envelope the protocol uses carries the operation one level down,
    /// under "payload".
    #[test]
    fn a_message_with_no_request_around_it_is_still_read() {
        let bare = r#"{"query":"query Me { me { id } }"}"#;
        assert_eq!(operation_label(bare), "query Me", "a document with no head above it");

        let over_a_socket = r#"{"id":"1","type":"subscribe","payload":{"query":"subscription Ticks { ticks { at } }"}}"#;
        assert_eq!(operation_label(over_a_socket), "subscription Ticks", "and one inside the socket envelope");
        assert!(
            formatted(over_a_socket).expect("it is GraphQL").starts_with("subscription Ticks {"),
            "{:?}",
            formatted(over_a_socket),
        );
    }

    /// A site search with a parameter called `query` is not a GraphQL request, and labelling
    /// it as one puts a wrong answer in a column people sort and search by. What makes a
    /// document is a selection set.
    #[test]
    fn an_ordinary_query_parameter_is_not_mistaken_for_an_operation() {
        assert_table!(
            [
                ("a site search that reads like a keyword", "GET /search?query=mutation+testing HTTP/1.1\nHost: shop.test\n\n"),
                ("a search for a word", "GET /search?query=subscription HTTP/1.1\nHost: shop.test\n\n"),
                ("a JSON body whose query is prose", "POST /find HTTP/1.1\nHost: shop.test\nContent-Type: application/json\n\n{\"query\":\"mutation of the gene\"}"),
            ],
            |idx, (what, raw)| {
                assert_eq!(operation_label(raw), "", "case #{idx} ({what})");
            }
        );
    }

    /// The shorthand form names no kind at all, so the words that usually give a request away
    /// are absent. What gives it away instead is where it was sent.
    #[test]
    fn a_shorthand_document_is_found_by_its_content_type_or_path() {
        let by_type = "POST /api HTTP/1.1\nHost: shop.test\nContent-Type: application/graphql\n\n{ me { id } }";
        assert_eq!(operation_label(by_type), "query");

        let by_path = "POST /graphql HTTP/1.1\nHost: shop.test\nContent-Type: application/json\n\n{\"query\":\"{ me { id } }\"}";
        assert_eq!(operation_label(by_path), "query");
    }

    #[test]
    fn a_request_that_is_not_graphql_carries_no_operation() {
        assert_table!(
            [
                ("an ordinary JSON body", post(r#"{"user":"a","password":"b"}"#)),
                ("a body whose query is not a string", post(r#"{"query":{"nested":1}}"#)),
                ("no body at all", "GET /index.html HTTP/1.1\nHost: shop.test\n\n".to_string()),
                ("a form post", "POST /login HTTP/1.1\nHost: shop.test\n\nquery=1&operationName=2".to_string()),
            ],
            |idx, (what, raw)| {
                assert!(operations(raw.as_str()).is_empty(), "case #{idx} ({what}): should carry no operation");
                assert_eq!(operation_label(raw.as_str()), "", "case #{idx} ({what}): and no label");
            }
        );
    }
}
