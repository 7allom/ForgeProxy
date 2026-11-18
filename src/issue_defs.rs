//! Issue definitions: the issues ForgeProxy's scanner can actually report, each classified by
//! its CWE number (https://cwe.mitre.org). The listing is the scanner's own table, so a new
//! check shows up here as soon as it is added to `scan::ALL_CHECKS`.

use crate::scan::{self, IssueDef, Severity};

pub const ISSUE_DEFS: &[IssueDef] = scan::ALL_CHECKS;

/// The severity a finding of this kind is normally reported at, for undoing "false positive".
/// A finding the scanner did not raise (one a program reported, say) has no definition here and
/// goes back to informational.
pub fn typical_severity(cwe: u32, name: &str) -> Severity {
    ISSUE_DEFS
        .iter()
        .find(|d| d.0 == cwe && d.1 == name)
        .map_or(Severity::Info, |d| d.2)
}

/// The public MITRE page for a CWE number.
pub fn cwe_url(cwe: u32) -> Option<String> {
    (cwe != scan::NO_CWE).then(|| format!("https://cwe.mitre.org/data/definitions/{cwe}.html"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    #[test]
    fn issue_catalogue_integrity_matrix() {
        assert!(!ISSUE_DEFS.is_empty());
        assert_table!(ISSUE_DEFS, |(cwe, name, severity)| {
            assert!(*cwe != scan::NO_CWE && *cwe < 0x1_0000, "issue '{name}' must carry a real CWE number, not {cwe}");
            assert!(!name.trim().is_empty(), "CWE-{cwe} issue must have a name");
            assert_ne!(*severity, Severity::FalsePositive, "'{name}' cannot be a false positive by default");
        });
        // a CWE may be shared, but (CWE, name) is how findings are keyed, so it must be unique
        let mut seen = std::collections::HashSet::new();
        for (cwe, name, _) in ISSUE_DEFS {
            assert!(seen.insert((cwe, name)), "CWE-{cwe} '{name}' is listed twice");
        }
    }

    #[test]
    fn every_old_type_index_maps_to_its_cwe() {
        assert_table!(
            [
                (0x0010_0200, scan::SQL_INJECTION),
                (0x0050_0600, scan::COOKIE_NO_HTTPONLY),
                (0x0100_0300, scan::HSTS_NOT_ENFORCED),
                (0x0010_0300, scan::BLIND_SSRF),
                (0x0010_0120, scan::OOB_COMMAND_INJECTION),
            ],
            |(old, def)| {
                assert_eq!(scan::cwe_from_legacy(old), def.0, "{old:#x} should become CWE-{}", def.0);
            }
        );
        assert_eq!(scan::cwe_from_legacy(0x0080_0000), scan::NO_CWE, "the old imported default has no CWE");
        assert_eq!(scan::cwe_from_legacy(79), 79, "a CWE number is kept as it is");
    }

    #[test]
    fn a_finding_saved_with_an_old_type_index_loads_with_its_cwe() {
        let old = r#"{"type_index":5244416,"name":"Cookie without HttpOnly flag set","severity":"Low",
                      "confidence":"Firm","host":"shop.test","path":"/","detail":""}"#;
        let f: scan::Finding = serde_json::from_str(old).expect("an old finding still loads");
        assert_eq!(f.cwe, 1004);
        let saved = serde_json::to_string(&f).expect("it saves");
        assert!(saved.contains("\"cwe\":1004") && !saved.contains("type_index"), "{saved}");
    }

    #[test]
    fn undoing_a_false_positive_restores_the_checks_own_severity() {
        assert_eq!(typical_severity(scan::TLS_COOKIE_NO_SECURE.0, scan::TLS_COOKIE_NO_SECURE.1), Severity::Medium);
        // same CWE, different check
        assert_eq!(typical_severity(319, scan::HSTS_NOT_ENFORCED.1), Severity::Low);
        assert_eq!(typical_severity(319, scan::CLEARTEXT_PASSWORD.1), Severity::High);
        assert_eq!(typical_severity(scan::NO_CWE, "Something a program reported"), Severity::Info);
    }
}
