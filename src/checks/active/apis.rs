//! GraphQL endpoint checks: whether the schema can be read by introspection, and whether the
//! endpoint runs a batch of queries in one request (which removes a natural rate limit). Both
//! only run when the target looks like a GraphQL endpoint, so no other endpoint is POSTed to.

use crate::checks::active::Sender;
use crate::insertion::PreparedRequest;
use crate::scan::{Confidence, Finding, GRAPHQL_BATCHING, GRAPHQL_INTROSPECTION};

/// A JSON POST to the endpoint with the given body.
fn post_json(url: &str, body: String, send: &mut Sender) -> crate::http::SendResult {
    send(
        &PreparedRequest {
            method: "POST".into(),
            url: url.to_string(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
        },
        true,
    )
}

/// When `start` looks like a GraphQL endpoint, test introspection and query batching.
pub fn graphql(start: &str, send: &mut Sender) -> Vec<Finding> {
    if !start.to_ascii_lowercase().contains("graphql") {
        return Vec::new();
    }
    let (host, path) = crate::http::split_url(start);
    let mut out = Vec::new();

    // Introspection: the standard schema query. If the schema types come back, it is open.
    let introspection = r#"{"query":"{__schema{types{name}}}"}"#.to_string();
    let r = post_json(start, introspection, send);
    if r.body.contains("__schema") || (r.body.contains("\"types\"") && r.body.contains("\"data\"")) {
        let mut f = Finding::new(
            GRAPHQL_INTROSPECTION,
            Confidence::Firm,
            &host,
            &path,
            "The GraphQL endpoint answered an introspection query with its schema. Introspection hands \
             an attacker the full type system; disable it in production unless it is needed.",
        );
        f.point = "GraphQL introspection".to_string();
        out.push(f);
    }

    // Batching: a JSON array of two queries. If both run, a single request can be amplified.
    let batch = r#"[{"query":"{__typename}"},{"query":"{__typename}"}]"#.to_string();
    let r = post_json(start, batch, send);
    let typename_count = r.body.matches("__typename").count() + r.body.matches("\"data\"").count();
    if r.body.trim_start().starts_with('[') && typename_count >= 2 {
        let mut f = Finding::new(
            GRAPHQL_BATCHING,
            Confidence::Tentative,
            &host,
            &path,
            "The GraphQL endpoint ran a batch of queries sent in one request. Unbounded batching (and \
             query aliasing) lets one request do the work of many, which can be used to brute-force or \
             to exhaust resources. Cap the batch size and query cost.",
        );
        f.point = "GraphQL batching".to_string();
        out.push(f);
    }
    out
}
