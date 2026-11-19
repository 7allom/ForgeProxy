//! Exposure checks that request well-known paths near the target and confirm the response by a
//! signature, not just a 200, so a soft error page is not mistaken for a real file.

use crate::checks::active::Sender;
use crate::insertion::PreparedRequest;
use crate::scan::{Confidence, Finding, EXPOSED_FILE};

/// The scheme-and-authority of a URL, with no path.
fn origin(url: &str) -> String {
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    match url[scheme_end..].find('/') {
        Some(i) => url[..scheme_end + i].to_string(),
        None => url.trim_end_matches('/').to_string(),
    }
}

/// A path to try and the signature that confirms a real file sits there.
struct Probe {
    path: &'static str,
    /// A plain substring the body must contain, or a regex when it starts with `re:`.
    signature: &'static str,
    note: &'static str,
}

// The paths are the target's own artifacts a misconfigured server leaks; the notes describe them
// without naming any tool.
const PROBES: &[Probe] = &[
    Probe { path: "/.git/HEAD", signature: "ref:", note: "a version-control metadata file is served, so the repository history is reachable" },
    Probe { path: "/.git/config", signature: "[core]", note: "a version-control configuration file is served, so the repository history is reachable" },
    Probe { path: "/.env", signature: "re:(?m)^[A-Z][A-Z0-9_]+=", note: "an environment file is served, which usually holds credentials and keys" },
];

/// Request each well-known path at the target's origin and report the files whose content
/// matches, skipping anything that merely returns a 200 HTML page (a soft error).
pub fn exposed_files(start: &str, send: &mut Sender) -> Vec<Finding> {
    let origin = origin(start);
    let mut out = Vec::new();
    for probe in PROBES {
        let url = format!("{origin}{}", probe.path);
        let r = send(
            &PreparedRequest { method: "GET".into(), url: url.clone(), headers: Vec::new(), body: String::new() },
            false,
        );
        if !r.status.starts_with("200") {
            continue;
        }
        let low = r.body.to_ascii_lowercase();
        // a page that looks like HTML is almost always a soft error, not the raw file
        if low.contains("<html") || low.contains("<!doctype") {
            continue;
        }
        let matched = if let Some(pat) = probe.signature.strip_prefix("re:") {
            crate::regex_cache::get(pat).is_some_and(|re| re.is_match(&r.body))
        } else {
            r.body.contains(probe.signature)
        };
        if matched {
            let (host, path) = crate::http::split_url(&url);
            let mut f = Finding::new(
                EXPOSED_FILE,
                Confidence::Firm,
                &host,
                &path,
                &format!("A sensitive file is exposed at {}: {}. Block access to it or remove it from the web root.", probe.path, probe.note),
            );
            f.point = probe.path.to_string();
            out.push(f);
        }
    }
    out
}
