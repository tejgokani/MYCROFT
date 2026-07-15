//! Report rendering tests over an in-memory engagement.

use mycroft_core::{FindingStatus, ScopeKind, ScopeRuleType, Severity, Tool};
use mycroft_store::{Db, NewFinding};

fn seed() -> (Db, mycroft_core::EngagementId) {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("acme-external", "ACME Corp").unwrap();
    db.add_scope_rule(e.id, "10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr)
        .unwrap();
    db.record_finding(
        e.id,
        &NewFinding {
            title: "Apache Log4j RCE".to_string(),
            severity: Severity::Critical,
            source_tool: Tool::Nuclei,
            target: "https://app.acme.com".to_string(),
            description: "Remote code execution via JNDI.".to_string(),
            status: FindingStatus::New,
            command_id: None,
        },
    )
    .unwrap();
    db.record_finding(
        e.id,
        &NewFinding {
            title: "Open port 22/tcp".to_string(),
            severity: Severity::Info,
            source_tool: Tool::Nmap,
            target: "10.0.0.42".to_string(),
            description: "ssh open".to_string(),
            status: FindingStatus::New,
            command_id: None,
        },
    )
    .unwrap();
    (db, e.id)
}

#[test]
fn markdown_report_has_all_sections_and_content() {
    let (db, id) = seed();
    let bundle = mycroft_report::build(&db, id).unwrap();
    let md = &bundle.markdown;

    for heading in [
        "# Engagement Report — acme-external",
        "## Summary",
        "## Scope",
        "## Findings",
        "## Command Log",
        "## Evidence Appendix",
    ] {
        assert!(md.contains(heading), "missing `{heading}`");
    }
    assert!(md.contains("Apache Log4j RCE"));
    assert!(md.contains("`10.0.0.0/24`"));
    assert!(md.contains("intact (tamper-evident)"));
    // Critical is summarized above Info (severity-first ordering).
    let crit = md.find("[CRITICAL] Apache Log4j RCE").unwrap();
    let info = md.find("[INFO] Open port 22/tcp").unwrap();
    assert!(crit < info, "findings must be severity-ordered");
}

#[test]
fn html_is_self_contained_and_escapes() {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("t", "c").unwrap();
    db.record_finding(
        e.id,
        &NewFinding {
            title: "XSS <script>alert(1)</script>".to_string(),
            severity: Severity::High,
            source_tool: Tool::Other("burp".to_string()),
            target: "app.acme.com".to_string(),
            description: "reflected".to_string(),
            status: FindingStatus::New,
            command_id: None,
        },
    )
    .unwrap();

    let html = mycroft_report::build(&db, e.id).unwrap().html;
    assert!(html.starts_with("<!doctype html>"));
    assert!(
        html.contains("<style>"),
        "CSS must be inlined (self-contained)"
    );
    // The angle brackets in the title must be escaped, not injected as a tag.
    assert!(html.contains("XSS &lt;script&gt;"));
    assert!(!html.contains("<script>alert(1)</script>"));
}

#[test]
fn tampered_audit_is_surfaced_in_report() {
    let (db, id) = seed();
    // Tamper with an audited row directly.
    db.conn()
        .execute(
            "UPDATE findings SET title = 'forged' WHERE severity = 'critical'",
            [],
        )
        .ok();
    // The findings table isn't in the audit chain, so tamper the chain itself:
    db.conn()
        .execute("UPDATE audit_log SET event = 'x' WHERE id = 1", [])
        .unwrap();

    let bundle = mycroft_report::build(&db, id).unwrap();
    assert!(bundle.markdown.contains("VERIFICATION FAILED"));
    assert!(bundle.html.contains("verification FAILED"));
}
