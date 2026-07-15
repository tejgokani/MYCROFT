//! Runner integration tests against a real child process.
//!
//! Invariant coverage: a blocked target must never spawn a process; an allowed run
//! must persist the command, capture hashed evidence, and leave the audit chain intact.

use std::net::IpAddr;
use std::path::PathBuf;

use mycroft_core::{
    EngagementId, IssuedBy, ScopeKind, ScopeRule, ScopeRuleId, ScopeRuleType, Target,
};
use mycroft_guard::{Scope, StaticResolver};
use mycroft_runner::{CollectingSink, RunOutcome, RunSpec, Runner};
use mycroft_store::Db;

fn rule(pattern: &str, kind: ScopeKind, ty: ScopeRuleType) -> ScopeRule {
    ScopeRule {
        id: ScopeRuleId(0),
        engagement_id: EngagementId(1),
        pattern: pattern.to_string(),
        kind,
        rule_type: ty,
        created_at: mycroft_core::now_utc(),
    }
}

/// A resolver that maps a probe host to a stable in-scope / out-of-scope address.
fn resolver() -> StaticResolver {
    StaticResolver::new()
        .with("in.example.com", &["10.0.0.9".parse::<IpAddr>().unwrap()])
        .with(
            "out.example.com",
            &["203.0.113.9".parse::<IpAddr>().unwrap()],
        )
}

fn spec(program: &str, args: &[&str], target: &str) -> RunSpec {
    RunSpec {
        raw_cmd: format!("{program} {}", args.join(" ")),
        program: program.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        target: Target::parse(target).unwrap(),
        issued_by: IssuedBy::Human,
    }
}

struct Fixture {
    db: Db,
    engagement_id: EngagementId,
    scope: Scope,
    evidence_root: PathBuf,
    _tmp: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let db = Db::open_in_memory().unwrap();
    let e = db.create_engagement("t", "c").unwrap();
    let scope = Scope::compile(&[rule("10.0.0.0/24", ScopeKind::In, ScopeRuleType::Cidr)]).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let evidence_root = tmp.path().to_path_buf();
    Fixture {
        db,
        engagement_id: e.id,
        scope,
        evidence_root,
        _tmp: tmp,
    }
}

#[tokio::test]
async fn allowed_command_executes_captures_and_persists() {
    let f = fixture();
    let r = resolver();
    let runner = Runner::new(
        &f.db,
        f.engagement_id,
        &f.scope,
        &r,
        f.evidence_root.clone(),
    );

    // `printf` writes deterministic bytes; target resolves into 10.0.0.0/24 (in scope).
    let mut sink = CollectingSink::default();
    let outcome = runner
        .run(spec("printf", &["MYCROFT-OK"], "in.example.com"), &mut sink)
        .await
        .unwrap();

    let command = match outcome {
        RunOutcome::Executed {
            command,
            exit_code,
            findings,
        } => {
            assert_eq!(exit_code, Some(0));
            assert_eq!(findings, 0, "echo output normalizes to no findings");
            command
        }
        RunOutcome::Blocked { .. } => panic!("expected execution, got block"),
    };

    // Live output reached the sink.
    assert_eq!(sink.stdout, b"MYCROFT-OK");

    // The command was persisted, not blocked, with a resolved target and end time.
    assert!(!command.blocked);
    assert_eq!(command.resolved_target.as_deref(), Some("10.0.0.9"));
    assert!(command.ended_at.is_some());
    assert_eq!(command.exit_code, Some(0));

    // Evidence: stdout captured with the correct sha256 (sha256 of "MYCROFT-OK").
    let evidence = f.db.list_evidence_for_command(command.id).unwrap();
    assert_eq!(evidence.len(), 2, "stdout + stderr evidence");
    let stdout_ev = evidence
        .iter()
        .find(|e| e.path.ends_with("stdout.log"))
        .unwrap();
    let expected = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(b"MYCROFT-OK"))
    };
    assert_eq!(stdout_ev.sha256, expected);

    // The evidence file exists on disk with the captured bytes.
    let disk = std::fs::read(&stdout_ev.path).unwrap();
    assert_eq!(disk, b"MYCROFT-OK");

    // Audit chain still verifies after the full lifecycle.
    f.db.verify_audit(f.engagement_id).unwrap();
}

#[tokio::test]
async fn blocked_target_never_executes() {
    let f = fixture();
    let r = resolver();
    let runner = Runner::new(
        &f.db,
        f.engagement_id,
        &f.scope,
        &r,
        f.evidence_root.clone(),
    );

    // This target resolves to 203.0.113.9 — outside 10.0.0.0/24 (default deny).
    // If the guard failed, `printf` would create a sentinel file we can detect.
    let sentinel = f.evidence_root.join("SHOULD_NOT_EXIST");
    let mut sink = CollectingSink::default();
    let outcome = runner
        .run(
            spec("touch", &[sentinel.to_str().unwrap()], "out.example.com"),
            &mut sink,
        )
        .await
        .unwrap();

    match outcome {
        RunOutcome::Blocked { command, reason } => {
            assert!(command.blocked);
            assert!(command.exit_code.is_none());
            assert!(reason.contains("default deny"));
        }
        RunOutcome::Executed { .. } => panic!("out-of-scope target must be blocked"),
    }

    // The process must not have run: no sentinel, no evidence, no output.
    assert!(!sentinel.exists(), "blocked command must not have executed");
    assert!(sink.stdout.is_empty() && sink.stderr.is_empty());
    let cmds = f.db.list_commands(f.engagement_id).unwrap();
    assert_eq!(cmds.len(), 1);
    assert!(cmds[0].blocked);
    assert!(f
        .db
        .list_evidence_for_command(cmds[0].id)
        .unwrap()
        .is_empty());

    f.db.verify_audit(f.engagement_id).unwrap();
}

#[tokio::test]
async fn unresolvable_target_is_blocked() {
    let f = fixture();
    let r = resolver();
    let runner = Runner::new(
        &f.db,
        f.engagement_id,
        &f.scope,
        &r,
        f.evidence_root.clone(),
    );
    let mut sink = CollectingSink::default();
    let outcome = runner
        .run(spec("printf", &["x"], "ghost.example.com"), &mut sink)
        .await
        .unwrap();
    assert!(matches!(outcome, RunOutcome::Blocked { .. }));
    f.db.verify_audit(f.engagement_id).unwrap();
}

#[tokio::test]
async fn nonzero_exit_is_recorded() {
    let f = fixture();
    let r = resolver();
    let runner = Runner::new(
        &f.db,
        f.engagement_id,
        &f.scope,
        &r,
        f.evidence_root.clone(),
    );
    let mut sink = CollectingSink::default();
    // `false` exits 1; target is in scope.
    let outcome = runner
        .run(spec("false", &[], "in.example.com"), &mut sink)
        .await
        .unwrap();
    match outcome {
        RunOutcome::Executed { exit_code, .. } => assert_eq!(exit_code, Some(1)),
        RunOutcome::Blocked { .. } => panic!("expected execution"),
    }
    f.db.verify_audit(f.engagement_id).unwrap();
}
