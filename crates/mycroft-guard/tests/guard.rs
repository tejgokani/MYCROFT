//! Adversarial tests for the scope guard — the highest-risk unit (CLAUDE.md §4).
//! Every out-of-scope path must be blocked; the default posture is deny.

use std::net::IpAddr;

use mycroft_core::{
    now_utc, EngagementId, ScopeKind, ScopeRule, ScopeRuleId, ScopeRuleType, Target,
};
use mycroft_guard::{check, evaluate, Scope, StaticResolver};

fn rule(pattern: &str, kind: ScopeKind, ty: ScopeRuleType) -> ScopeRule {
    ScopeRule {
        id: ScopeRuleId(0),
        engagement_id: EngagementId(1),
        pattern: pattern.to_string(),
        kind,
        rule_type: ty,
        created_at: now_utc(),
    }
}

fn scope(rules: Vec<ScopeRule>) -> Scope {
    Scope::compile(&rules).expect("rules should compile")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ---- CIDR inclusion / exclusion ---------------------------------------------

#[test]
fn ip_in_cidr_is_allowed() {
    let s = scope(vec![rule(
        "10.0.0.0/24",
        ScopeKind::In,
        ScopeRuleType::Cidr,
    )]);
    let d = evaluate(
        &Target::parse("10.0.0.5").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    assert!(d.is_allowed(), "{d:?}");
}

#[test]
fn ip_outside_all_cidrs_is_default_denied() {
    let s = scope(vec![rule(
        "10.0.0.0/24",
        ScopeKind::In,
        ScopeRuleType::Cidr,
    )]);
    let d = evaluate(
        &Target::parse("192.168.1.1").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    assert!(!d.is_allowed(), "target outside scope must be blocked");
}

#[test]
fn empty_scope_denies_everything() {
    let s = scope(vec![]);
    let d = evaluate(
        &Target::parse("10.0.0.5").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    assert!(!d.is_allowed(), "empty scope must default-deny");
}

#[test]
fn exclusion_wins_over_inclusion_regardless_of_order() {
    // Exclusion listed AFTER the broad inclusion.
    let s = scope(vec![
        rule("10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr),
        rule("10.0.0.53", ScopeKind::Out, ScopeRuleType::Cidr),
    ]);
    let allowed = evaluate(
        &Target::parse("10.0.0.10").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    let blocked = evaluate(
        &Target::parse("10.0.0.53").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    assert!(allowed.is_allowed());
    assert!(!blocked.is_allowed(), "excluded host must be blocked");

    // And when the exclusion is listed BEFORE the inclusion.
    let s2 = scope(vec![
        rule("10.0.0.53", ScopeKind::Out, ScopeRuleType::Cidr),
        rule("10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr),
    ]);
    let blocked2 = evaluate(
        &Target::parse("10.0.0.53").unwrap(),
        &s2,
        &StaticResolver::new(),
    );
    assert!(!blocked2.is_allowed());
}

#[test]
fn overlapping_cidrs_still_enforce_exclusion() {
    let s = scope(vec![
        rule("10.0.0.0/8", ScopeKind::In, ScopeRuleType::Cidr),
        rule("10.1.0.0/16", ScopeKind::Out, ScopeRuleType::Cidr),
    ]);
    assert!(evaluate(
        &Target::parse("10.2.3.4").unwrap(),
        &s,
        &StaticResolver::new()
    )
    .is_allowed());
    assert!(!evaluate(
        &Target::parse("10.1.2.3").unwrap(),
        &s,
        &StaticResolver::new()
    )
    .is_allowed());
}

#[test]
fn ipv6_cidr_matching() {
    let s = scope(vec![rule(
        "2001:db8::/32",
        ScopeKind::In,
        ScopeRuleType::Cidr,
    )]);
    assert!(evaluate(
        &Target::parse("2001:db8::1").unwrap(),
        &s,
        &StaticResolver::new()
    )
    .is_allowed());
    assert!(!evaluate(
        &Target::parse("2001:dead::1").unwrap(),
        &s,
        &StaticResolver::new()
    )
    .is_allowed());
}

// ---- Domain rules ------------------------------------------------------------

#[test]
fn wildcard_matches_subdomains_but_not_apex() {
    let s = scope(vec![rule(
        "*.acme.com",
        ScopeKind::In,
        ScopeRuleType::Domain,
    )]);
    let r = StaticResolver::new()
        .with("a.acme.com", &[ip("93.184.216.34")])
        .with("a.b.acme.com", &[ip("93.184.216.34")])
        .with("acme.com", &[ip("93.184.216.34")])
        .with("notacme.com", &[ip("93.184.216.34")]);

    assert!(evaluate(&Target::parse("a.acme.com").unwrap(), &s, &r).is_allowed());
    assert!(evaluate(&Target::parse("a.b.acme.com").unwrap(), &s, &r).is_allowed());
    assert!(
        !evaluate(&Target::parse("acme.com").unwrap(), &s, &r).is_allowed(),
        "apex must not match *.acme.com"
    );
    assert!(
        !evaluate(&Target::parse("notacme.com").unwrap(), &s, &r).is_allowed(),
        "suffix-confusion host must not match"
    );
}

#[test]
fn exact_domain_matches_only_itself() {
    let s = scope(vec![rule("acme.com", ScopeKind::In, ScopeRuleType::Domain)]);
    let r = StaticResolver::new()
        .with("acme.com", &[ip("93.184.216.34")])
        .with("www.acme.com", &[ip("93.184.216.34")]);
    assert!(evaluate(&Target::parse("acme.com").unwrap(), &s, &r).is_allowed());
    assert!(!evaluate(&Target::parse("www.acme.com").unwrap(), &s, &r).is_allowed());
}

#[test]
fn domain_rule_never_authorizes_a_bare_ip_target() {
    let s = scope(vec![rule(
        "*.acme.com",
        ScopeKind::In,
        ScopeRuleType::Domain,
    )]);
    let d = evaluate(
        &Target::parse("93.184.216.34").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    assert!(!d.is_allowed(), "a domain rule must not cover an IP target");
}

// ---- The DNS-rebind seam (the reason resolution is security-critical) --------

#[test]
fn in_scope_name_resolving_into_excluded_cidr_is_blocked() {
    // The name is explicitly in scope, but it currently points at an excluded host.
    let s = scope(vec![
        rule("*.acme.com", ScopeKind::In, ScopeRuleType::Domain),
        rule("169.254.0.0/16", ScopeKind::Out, ScopeRuleType::Cidr), // link-local, e.g. cloud metadata
    ]);
    let r = StaticResolver::new().with("app.acme.com", &[ip("169.254.169.254")]);
    let d = evaluate(&Target::parse("app.acme.com").unwrap(), &s, &r);
    assert!(
        !d.is_allowed(),
        "domain must be blocked when it resolves into an excluded network (rebind defense)"
    );
}

#[test]
fn domain_target_allowed_via_in_scope_cidr_of_its_resolved_addr() {
    // Scope is defined by network; the target is a name that resolves into it.
    let s = scope(vec![rule(
        "10.0.0.0/24",
        ScopeKind::In,
        ScopeRuleType::Cidr,
    )]);
    let r = StaticResolver::new().with("internal.acme.com", &[ip("10.0.0.7")]);
    assert!(evaluate(&Target::parse("internal.acme.com").unwrap(), &s, &r).is_allowed());
}

#[test]
fn unresolvable_host_is_blocked_not_allowed() {
    let s = scope(vec![rule(
        "*.acme.com",
        ScopeKind::In,
        ScopeRuleType::Domain,
    )]);
    // Static resolver has no entry -> resolution fails.
    let d = evaluate(
        &Target::parse("ghost.acme.com").unwrap(),
        &s,
        &StaticResolver::new(),
    );
    assert!(!d.is_allowed(), "unresolvable host must be blocked");
}

#[test]
fn multi_addr_domain_blocked_if_any_addr_excluded() {
    // A name resolving to several IPs is blocked if ANY of them is excluded.
    let s = scope(vec![
        rule("10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr),
        rule("10.0.0.53", ScopeKind::Out, ScopeRuleType::Cidr),
    ]);
    let r = StaticResolver::new().with("ha.acme.com", &[ip("10.0.0.10"), ip("10.0.0.53")]);
    let d = evaluate(&Target::parse("ha.acme.com").unwrap(), &s, &r);
    assert!(
        !d.is_allowed(),
        "any excluded resolved addr must block the target"
    );
}

// ---- URL rules & malformed input --------------------------------------------

#[test]
fn url_rule_matches_on_host() {
    let s = scope(vec![rule(
        "https://api.acme.com/v1/health",
        ScopeKind::In,
        ScopeRuleType::Url,
    )]);
    let r = StaticResolver::new().with("api.acme.com", &[ip("93.184.216.34")]);
    assert!(evaluate(&Target::parse("api.acme.com").unwrap(), &s, &r).is_allowed());
    let r2 = StaticResolver::new().with("other.acme.com", &[ip("93.184.216.34")]);
    assert!(!evaluate(&Target::parse("other.acme.com").unwrap(), &s, &r2).is_allowed());
}

#[test]
fn malformed_rules_are_rejected_at_compile_time() {
    assert!(Scope::compile(&[rule("not-a-cidr", ScopeKind::In, ScopeRuleType::Cidr)]).is_err());
    assert!(Scope::compile(&[rule("10.0.0.0/99", ScopeKind::In, ScopeRuleType::Cidr)]).is_err());
    assert!(Scope::compile(&[rule("*.*.com", ScopeKind::In, ScopeRuleType::Domain)]).is_err());
    assert!(Scope::compile(&[rule("", ScopeKind::In, ScopeRuleType::Domain)]).is_err());
}

// ---- Pure check determinism --------------------------------------------------

#[test]
fn check_is_deterministic() {
    use mycroft_core::ResolvedTarget;
    let s = scope(vec![rule(
        "10.0.0.0/24",
        ScopeKind::In,
        ScopeRuleType::Cidr,
    )]);
    let rt = ResolvedTarget {
        target: Target::parse("10.0.0.9").unwrap(),
        addrs: vec![ip("10.0.0.9")],
    };
    let d1 = check(&rt, &s);
    let d2 = check(&rt, &s);
    assert_eq!(d1, d2);
    assert!(d1.is_allowed());
}
