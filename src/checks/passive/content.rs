//! Passive checks on the subresources a page pulls in: mixed content on a secure page, external
//! scripts with no integrity guarantee, and active content framed in from another origin.

use crate::checks::PassiveCtx;
use crate::scan::{Confidence, Finding, MISSING_SRI, MIXED_CONTENT, UNTRUSTED_INCLUSION};

/// The host a subresource URL points at when it is on another origin than `page_host`; `None`
/// for a same-host or relative reference.
fn external_host(src: &str, page_host: &str) -> Option<String> {
    let src = src.trim();
    // Absolute or protocol-relative only; a relative reference is same-origin, so `None`.
    let rest = src
        .strip_prefix("https://")
        .or_else(|| src.strip_prefix("http://"))
        .or_else(|| src.strip_prefix("//"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    let page = page_host.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == page {
        None
    } else {
        Some(host)
    }
}

/// The text of each HTML tag of the given name, from `<name` up to the next `>`.
fn tags<'a>(body: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let low = body.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = low[i..].find(&open) {
        let start = i + rel;
        let end = low[start..].find('>').map(|e| start + e + 1).unwrap_or(body.len());
        out.push(&body[start..end]);
        i = end;
    }
    out
}

/// The value of an attribute inside one tag's text, e.g. `src` or `integrity`.
fn attr(tag: &str, name: &str) -> Option<String> {
    let low = tag.to_ascii_lowercase();
    let key = format!("{name}=");
    let at = low.find(&key)? + key.len();
    let rest = &tag[at..];
    let rest = rest.trim_start();
    let (quote, body) = match rest.chars().next() {
        Some(q @ ('"' | '\'')) => (Some(q), &rest[1..]),
        _ => (None, rest),
    };
    let end = match quote {
        Some(q) => body.find(q).unwrap_or(body.len()),
        None => body.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(body.len()),
    };
    Some(body[..end].to_string())
}

/// A secure page that loads an active subresource (script, image, frame) over plain HTTP.
pub fn mixed_content(ctx: &PassiveCtx) -> Vec<Finding> {
    if ctx.secure && (ctx.lbody.contains("src=\"http://") || ctx.lbody.contains("src='http://")) {
        return vec![Finding::new(
            MIXED_CONTENT,
            Confidence::Firm,
            ctx.host,
            ctx.path,
            "A page served over HTTPS loads a subresource over plain HTTP. A network attacker can tamper \
             with the insecure resource, which undermines the security of the whole page.",
        )];
    }
    Vec::new()
}

/// An external script loaded without a Subresource Integrity hash to pin its contents.
pub fn missing_sri(ctx: &PassiveCtx) -> Vec<Finding> {
    for tag in tags(ctx.body, "script") {
        if let Some(src) = attr(tag, "src") {
            if external_host(&src, ctx.host).is_some() && attr(tag, "integrity").is_none() {
                return vec![Finding::new(
                    MISSING_SRI,
                    Confidence::Firm,
                    ctx.host,
                    ctx.path,
                    "A script was loaded from another origin without a Subresource Integrity hash. If that \
                     origin is compromised it can serve altered code; add an integrity attribute to pin it.",
                )];
            }
        }
    }
    Vec::new()
}

/// Active content (a frame or embedded object) pulled in from an external origin.
pub fn untrusted_inclusion(ctx: &PassiveCtx) -> Vec<Finding> {
    for name in ["iframe", "object", "embed"] {
        for tag in tags(ctx.body, name) {
            let src = attr(tag, "src").or_else(|| attr(tag, "data"));
            if let Some(src) = src {
                if external_host(&src, ctx.host).is_some() {
                    return vec![Finding::new(
                        UNTRUSTED_INCLUSION,
                        Confidence::Firm,
                        ctx.host,
                        ctx.path,
                        "The page frames or embeds active content from another origin. Content from a third \
                         party can change under you; include only origins you control or trust.",
                    )];
                }
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_host_tells_third_party_from_same_origin() {
        assert_eq!(external_host("/app.js", "a.test"), None);
        assert_eq!(external_host("https://a.test/x.js", "a.test"), None);
        assert_eq!(external_host("//cdn.other/x.js", "a.test").as_deref(), Some("cdn.other"));
        assert_eq!(external_host("http://other.test/x.js", "a.test").as_deref(), Some("other.test"));
    }

    #[test]
    fn attr_reads_quoted_and_unquoted_values() {
        assert_eq!(attr(r#"<script src="x.js" integrity="sha">"#, "src").as_deref(), Some("x.js"));
        assert_eq!(attr(r#"<script src="x.js" integrity="sha">"#, "integrity").as_deref(), Some("sha"));
        assert_eq!(attr("<script src=x.js >", "src").as_deref(), Some("x.js"));
        assert_eq!(attr("<script defer>", "src"), None);
    }
}
