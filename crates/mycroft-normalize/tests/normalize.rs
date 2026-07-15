//! Golden-corpus tests for the parsers, driven by real-shaped fixtures in `fixtures/`.

use mycroft_core::{Severity, Tool};
use mycroft_normalize::{normalize, NormalizeError};

fn fixture(rel: &str) -> Vec<u8> {
    let path = format!("{}/../../fixtures/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

#[test]
fn nmap_open_ports_become_findings() {
    let raw = fixture("nmap/scanme.xml");
    let findings = normalize(&Tool::Nmap, &raw, None).unwrap();

    // 22, 80, 8080 are open/open|filtered; 443 is closed and must be excluded.
    assert_eq!(findings.len(), 3, "{findings:#?}");
    assert!(findings.iter().all(|f| f.severity == Severity::Info));
    // IPv4 address preferred over the MAC address.
    assert!(findings.iter().all(|f| f.target == "10.0.0.42"));

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert!(titles.contains(&"Open port 22/tcp (ssh)"));
    assert!(titles.contains(&"Open port 80/tcp (http)"));
    assert!(titles.contains(&"Open port 8080/tcp (http-proxy)"));

    let ssh = findings
        .iter()
        .find(|f| f.title.contains("22/tcp"))
        .unwrap();
    assert!(ssh.description.contains("OpenSSH 8.9p1"));
    assert!(ssh.description.contains("hostname: scanme.example.org"));
}

#[test]
fn nuclei_jsonl_skips_bad_lines_and_maps_severity() {
    let raw = fixture("nuclei/findings.jsonl");
    let findings = normalize(&Tool::Nuclei, &raw, None).unwrap();

    // 5 valid records; 1 invalid line and 1 blank line are skipped.
    assert_eq!(findings.len(), 5, "{findings:#?}");

    let crit = findings
        .iter()
        .find(|f| f.title.contains("Log4Shell"))
        .expect("critical finding present");
    assert_eq!(crit.severity, Severity::Critical);
    assert_eq!(crit.target, "https://scanme.example.org/api");
    assert!(crit.description.contains("CVE-2021-44228"));

    // A record without an `info` block falls back to the template id for its title.
    let fallback = findings
        .iter()
        .find(|f| f.title == "no-info-record")
        .unwrap();
    assert_eq!(fallback.severity, Severity::Info);

    // An unrecognized severity string maps to Info rather than being dropped.
    let odd = findings.iter().find(|f| f.title == "Odd Severity").unwrap();
    assert_eq!(odd.severity, Severity::Info);

    // Severity-string mapping sanity.
    let medium = findings
        .iter()
        .find(|f| f.title == "TLS Weak Cipher")
        .unwrap();
    assert_eq!(medium.severity, Severity::Medium);
}

#[test]
fn unsupported_tool_is_rejected() {
    let err = normalize(&Tool::from_name("ffuf"), b"{}", None).unwrap_err();
    assert!(matches!(err, NormalizeError::Unsupported(_)));
}

#[test]
fn malformed_nmap_xml_errors_cleanly() {
    let err = normalize(&Tool::Nmap, b"<nmaprun><host", None).unwrap_err();
    assert!(matches!(err, NormalizeError::Parse { tool: "nmap", .. }));
}

#[test]
fn empty_nuclei_input_is_ok_and_empty() {
    let findings = normalize(&Tool::Nuclei, b"", None).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn nuclei_target_falls_back_to_hint() {
    // A record with neither matched-at nor host uses the caller's hint.
    let line = br#"{"template-id":"t","info":{"name":"n","severity":"low"}}"#;
    let findings = normalize(&Tool::Nuclei, line, Some("10.0.0.9")).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].target, "10.0.0.9");
    assert_eq!(findings[0].severity, Severity::Low);
}
