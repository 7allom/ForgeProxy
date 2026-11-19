//! Client-side signals read from the scripts in a page: input that may flow into a dangerous
//! sink (DOM-based cross-site scripting), and a cross-document message handler that does not
//! check the sender's origin. Both are heuristics on the response text, so they are reported
//! tentatively -- a signpost to review the code, not proof of a flaw.

use crate::checks::PassiveCtx;
use crate::scan::{Confidence, Finding, DOM_XSS_SINK, POSTMESSAGE_NO_ORIGIN};

/// Places attacker-controllable input enters client-side script.
const SOURCES: &[&str] = &[
    "location.hash",
    "location.search",
    "location.href",
    "document.url",
    "document.documenturi",
    "document.referrer",
    "window.name",
];

/// Places that turn a string into markup or code if fed unsanitised input.
const SINKS: &[&str] = &[
    ".innerhtml",
    ".outerhtml",
    "document.write",
    ".insertadjacenthtml",
    "eval(",
];

/// A page whose script reads a controllable source and also writes to a dangerous sink: the two
/// conditions for DOM-based cross-site scripting, worth a manual look at how the value flows.
pub fn dom_xss_sink(ctx: &PassiveCtx) -> Vec<Finding> {
    let has_source = SOURCES.iter().any(|s| ctx.lbody.contains(s));
    let has_sink = SINKS.iter().any(|s| ctx.lbody.contains(s));
    if has_source && has_sink {
        return vec![Finding::new(
            DOM_XSS_SINK,
            Confidence::Tentative,
            ctx.host,
            ctx.path,
            "The page's scripts read input from the URL or document and also write to a sink that can \
             execute markup (such as innerHTML or document.write). Check that the value is encoded or \
             sanitised before it reaches the sink, to rule out DOM-based cross-site scripting.",
        )];
    }
    Vec::new()
}

/// A message-event handler with no visible origin check, so any site that can open the page may
/// post to it and be trusted.
pub fn postmessage_origin(ctx: &PassiveCtx) -> Vec<Finding> {
    let listens = ctx.lbody.contains("addeventlistener(\"message\"")
        || ctx.lbody.contains("addeventlistener('message'")
        || ctx.lbody.contains(".onmessage");
    if listens && !ctx.lbody.contains(".origin") {
        return vec![Finding::new(
            POSTMESSAGE_NO_ORIGIN,
            Confidence::Tentative,
            ctx.host,
            ctx.path,
            "The page handles cross-document messages but does not appear to check the sender's origin. \
             A handler that trusts any sender can be driven by another site; compare event.origin against \
             an allow-list before acting on a message.",
        )];
    }
    Vec::new()
}
