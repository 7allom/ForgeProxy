//! Passive checks, grouped by the part of the response they read. Each returns findings for
//! one captured exchange and sends no traffic. [`REGISTRY`] lists them in the order the scanner
//! runs them; adding a check means adding its function here.

pub mod headers;
pub mod cookies;
pub mod secrets;
pub mod content;
pub mod dom;

use super::{PassiveCheck, PassiveCtx};

/// Every passive check in run order, each with a stable id for tests and logs. The first group
/// matches the order the engine reported findings in before the checks were split out, so
/// consolidation and reports are unchanged; the rest were added with the wider CWE coverage.
pub const REGISTRY: &[(&str, PassiveCheck)] = &[
    ("hsts", headers::hsts as fn(&PassiveCtx) -> _),
    ("csp", headers::csp),
    ("frameable", headers::frameable),
    ("cookie_flags", cookies::cookie_flags),
    ("cacheable_https", headers::cacheable_https),
    ("directory_listing", secrets::directory_listing),
    ("password_fields", secrets::password_fields),
    ("email_disclosed", secrets::email_disclosed),
    ("private_ip_disclosed", secrets::private_ip_disclosed),
    // Added with the wider CWE coverage.
    ("content_type_options", headers::content_type_options),
    ("cors", headers::cors),
    ("referrer_policy", headers::referrer_policy),
    ("version_banner", headers::version_banner),
    ("cookie_samesite", cookies::cookie_samesite),
    ("token_in_url", secrets::token_in_url),
    ("jwt_weakness", secrets::jwt_weakness),
    ("secret_in_response", secrets::secret_in_response),
    ("source_map", secrets::source_map),
    ("stack_trace", secrets::stack_trace),
    ("mixed_content", content::mixed_content),
    ("missing_sri", content::missing_sri),
    ("untrusted_inclusion", content::untrusted_inclusion),
    ("dom_xss_sink", dom::dom_xss_sink),
    ("postmessage_origin", dom::postmessage_origin),
];
