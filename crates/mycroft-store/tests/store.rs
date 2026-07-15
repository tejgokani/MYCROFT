//! Store integration tests: engagement + scope lifecycle and audit-chain tamper detection.

use mycroft_core::{ScopeKind, ScopeRuleType};
use mycroft_store::{Db, StoreError};

#[test]
fn create_engagement_seeds_genesis_audit_entry() {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("acme-external", "ACME Corp").unwrap();
    assert_eq!(e.name, "acme-external");

    // Genesis entry exists and the chain verifies.
    let n: i64 = db
        .conn()
        .query_row(
            "SELECT count(*) FROM audit_log WHERE engagement_id = ?1",
            [e.id.get()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    db.verify_audit(e.id).unwrap();

    let fetched = db.get_engagement(e.id).unwrap();
    assert_eq!(fetched, e);
}

#[test]
fn scope_rules_round_trip_and_extend_chain() {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("test", "client").unwrap();

    db.add_scope_rule(e.id, "10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr)
        .unwrap();
    db.add_scope_rule(e.id, "*.example.com", ScopeKind::In, ScopeRuleType::Domain)
        .unwrap();
    db.add_scope_rule(e.id, "10.0.0.5", ScopeKind::Out, ScopeRuleType::Cidr)
        .unwrap();

    let rules = db.list_scope_rules(e.id).unwrap();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].pattern, "10.0.0.0/24");
    assert_eq!(rules[2].kind, ScopeKind::Out);

    // Chain now has 1 genesis + 3 scope entries and still verifies.
    db.verify_audit(e.id).unwrap();
}

#[test]
fn tampering_breaks_the_audit_chain() {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("test", "client").unwrap();
    db.add_scope_rule(e.id, "10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr)
        .unwrap();
    db.verify_audit(e.id).unwrap();

    // Silently alter an audited event, as a tamperer editing the DB directly would.
    db.conn()
        .execute(
            "UPDATE audit_log SET event = 'scope.forged' WHERE event = 'scope.added'",
            [],
        )
        .unwrap();

    let err = db.verify_audit(e.id).unwrap_err();
    assert!(matches!(err, StoreError::AuditChainBroken { .. }));
}

#[test]
fn deleting_a_middle_entry_breaks_the_chain() {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("test", "client").unwrap();
    db.add_scope_rule(e.id, "a.example.com", ScopeKind::In, ScopeRuleType::Domain)
        .unwrap();
    db.add_scope_rule(e.id, "b.example.com", ScopeKind::In, ScopeRuleType::Domain)
        .unwrap();

    // Remove the genesis entry; the next entry's prev_hash no longer matches.
    db.conn()
        .execute(
            "DELETE FROM audit_log WHERE event = 'engagement.created'",
            [],
        )
        .unwrap();

    let err = db.verify_audit(e.id).unwrap_err();
    assert!(matches!(err, StoreError::AuditChainBroken { .. }));
}
