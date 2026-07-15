//! # mycroft-runner — guarded execution and capture.
//!
//! This crate is the single place a command becomes a process. It enforces the two
//! load-bearing invariants directly (CLAUDE.md §2):
//!
//! 1. **Guard before exec.** [`Runner::run`] asks `mycroft-guard` for a verdict first.
//!    A block is recorded as a terminal attempt and the process is **never spawned** —
//!    there is no code path from a `Block` to the network.
//! 2. **Persist everything.** Every attempt (blocked or executed) becomes a `commands`
//!    row; every execution's stdout/stderr is captured to disk, hashed (sha256), and
//!    attached as evidence; every step extends the audit chain.
//!
//! The runner is transport-agnostic about *display*: live output goes to an
//! [`OutputSink`] (terminal, TUI pane, or test buffer), while the parse-and-evidence
//! copy always lands on disk (the dual-capture decision).

#![forbid(unsafe_code)]

mod capture;
mod sink;

use std::path::PathBuf;

use anyhow::{Context, Result};
use mycroft_core::{Command, EngagementId, IssuedBy, Target, Tool};
use mycroft_core::{EvidenceKind, FindingStatus, GuardDecision};
use mycroft_guard::{evaluate, Resolver, Scope};
use mycroft_store::{Db, NewCommand, NewEvidence, NewFinding};

pub use sink::{CollectingSink, ConsoleSink, NullSink, OutputSink};

/// Best-effort inference of the target to scope-check from a command's tokens.
///
/// Only literal IPs and dotted hostnames are treated as candidates, so flags
/// (`-sV`) and bare port numbers (`80`) are never mistaken for a target. Returns an
/// error when zero or multiple distinct candidates are found; callers should let the
/// operator disambiguate with an explicit target.
pub fn infer_target(tokens: &[String]) -> std::result::Result<Target, String> {
    let mut seen: Vec<Target> = Vec::new();
    for tok in tokens {
        if let Ok(t) = Target::parse(tok) {
            let is_candidate = matches!(t, Target::Ip(_)) || tok.contains('.');
            if is_candidate && !seen.contains(&t) {
                seen.push(t);
            }
        }
    }
    match seen.len() {
        1 => Ok(seen.into_iter().next().unwrap()),
        0 => Err("could not infer a target; specify one explicitly".to_string()),
        _ => {
            let hosts: Vec<String> = seen.iter().map(Target::host).collect();
            Err(format!(
                "ambiguous target ({hosts:?}); specify one explicitly"
            ))
        }
    }
}

/// What to run: an already-split program + args, a declared target, and provenance.
#[derive(Debug, Clone)]
pub struct RunSpec {
    /// The full command as the operator wrote it (for the record and the report).
    pub raw_cmd: String,
    /// The executable to launch (e.g. `nmap`). Never passed through a shell.
    pub program: String,
    /// Arguments, as a vector (no shell word-splitting).
    pub args: Vec<String>,
    /// The target the guard must authorize before anything runs.
    pub target: Target,
    /// Who issued this command. AI-issued commands take this identical path (§7).
    pub issued_by: IssuedBy,
}

/// The result of a [`Runner::run`] call.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// The guard blocked the target; nothing was executed.
    Blocked {
        /// The persisted (terminal) command row.
        command: Command,
        /// The actionable reason, suitable for showing the operator.
        reason: String,
    },
    /// The command executed and its output was captured.
    Executed {
        /// The persisted, finalized command row.
        command: Command,
        /// Exit code, or `None` if the process was signalled.
        exit_code: Option<i32>,
        /// Number of findings normalized from the output (0 for tools without a parser
        /// or output that wasn't in the expected machine format).
        findings: usize,
    },
}

/// Executes commands for one engagement under one compiled scope.
pub struct Runner<'a> {
    db: &'a Db,
    engagement_id: EngagementId,
    scope: &'a Scope,
    resolver: &'a dyn Resolver,
    evidence_root: PathBuf,
}

impl<'a> Runner<'a> {
    /// Create a runner. `evidence_root` is where per-command output directories are
    /// written (one `cmd-<id>/` subdir per execution).
    pub fn new(
        db: &'a Db,
        engagement_id: EngagementId,
        scope: &'a Scope,
        resolver: &'a dyn Resolver,
        evidence_root: PathBuf,
    ) -> Self {
        Self {
            db,
            engagement_id,
            scope,
            resolver,
            evidence_root,
        }
    }

    /// Guard, execute (if allowed), capture, and persist a single command.
    pub async fn run(&self, spec: RunSpec, sink: &mut dyn OutputSink) -> Result<RunOutcome> {
        let tool = Tool::from_name(&spec.program);
        let host = spec.target.host();

        // 1. Guard decides first. There is no execution path from a Block.
        match evaluate(&spec.target, self.scope, self.resolver) {
            GuardDecision::Block { reason } => {
                let new = NewCommand {
                    raw_cmd: spec.raw_cmd.clone(),
                    tool,
                    target: host,
                    resolved_target: None,
                    blocked: true,
                    scope_check: reason.clone(),
                    issued_by: spec.issued_by,
                };
                let command = self
                    .db
                    .record_blocked_command(self.engagement_id, &new)
                    .context("recording blocked command")?;
                Ok(RunOutcome::Blocked { command, reason })
            }
            GuardDecision::Allow { resolved } => {
                let resolved_str = resolved
                    .addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let scope_check = if resolved_str.is_empty() {
                    "allowed".to_string()
                } else {
                    format!("allowed; resolved to {resolved_str}")
                };
                let new = NewCommand {
                    raw_cmd: spec.raw_cmd.clone(),
                    tool,
                    target: host,
                    resolved_target: (!resolved_str.is_empty()).then_some(resolved_str),
                    blocked: false,
                    scope_check,
                    issued_by: spec.issued_by,
                };

                // Persist the in-flight row first so a crash still leaves an audited attempt.
                let command = self
                    .db
                    .start_command(self.engagement_id, &new)
                    .context("recording command start")?;

                self.execute(command, &spec, sink).await
            }
        }
    }

    /// Execute an already-authorized, already-recorded command and finalize it.
    async fn execute(
        &self,
        command: Command,
        spec: &RunSpec,
        sink: &mut dyn OutputSink,
    ) -> Result<RunOutcome> {
        let dir = self.evidence_root.join(format!("cmd-{}", command.id.get()));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating evidence directory {}", dir.display()))?;
        let stdout_path = dir.join("stdout.log");
        let stderr_path = dir.join("stderr.log");

        let cap =
            capture::run_and_capture(&spec.program, &spec.args, &stdout_path, &stderr_path, sink)
                .await;

        match cap {
            Ok(cap) => {
                self.db
                    .finish_command(
                        self.engagement_id,
                        command.id,
                        cap.exit_code,
                        Some(&stdout_path.to_string_lossy()),
                        Some(&stderr_path.to_string_lossy()),
                    )
                    .context("finalizing command record")?;

                self.db
                    .add_evidence(
                        self.engagement_id,
                        &NewEvidence {
                            finding_id: None,
                            command_id: Some(command.id),
                            kind: EvidenceKind::Output,
                            path: stdout_path.to_string_lossy().into_owned(),
                            sha256: cap.stdout_sha256,
                        },
                    )
                    .context("attaching stdout evidence")?;
                self.db
                    .add_evidence(
                        self.engagement_id,
                        &NewEvidence {
                            finding_id: None,
                            command_id: Some(command.id),
                            kind: EvidenceKind::Output,
                            path: stderr_path.to_string_lossy().into_owned(),
                            sha256: cap.stderr_sha256,
                        },
                    )
                    .context("attaching stderr evidence")?;

                // Auto-normalize recognized tool output into findings. Best-effort:
                // output that isn't in the expected machine format simply yields none,
                // and a parser error never fails the run (the evidence is already saved).
                let findings = self.normalize_output(&command, spec, &stdout_path);

                let finalized = self
                    .db
                    .get_command(command.id)
                    .context("re-reading finalized command")?;
                Ok(RunOutcome::Executed {
                    command: finalized,
                    exit_code: cap.exit_code,
                    findings,
                })
            }
            Err(e) => {
                // Exec failed (e.g. program not found). Close the record so the audit
                // trail reflects a completed, failed attempt rather than a dangling one.
                self.db
                    .finish_command(self.engagement_id, command.id, None, None, None)
                    .context("finalizing failed command record")?;
                Err(e)
            }
        }
    }

    /// Parse a recognized tool's captured stdout into findings linked to the command.
    /// Returns the number recorded; never errors (findings are a bonus, not the point).
    fn normalize_output(
        &self,
        command: &Command,
        spec: &RunSpec,
        stdout_path: &std::path::Path,
    ) -> usize {
        let tool = Tool::from_name(&spec.program);
        if !tool.is_normalizable() {
            return 0;
        }
        let Ok(bytes) = std::fs::read(stdout_path) else {
            return 0;
        };
        let host = spec.target.host();
        let Ok(normalized) = mycroft_normalize::normalize(&tool, &bytes, Some(&host)) else {
            return 0;
        };

        let mut count = 0;
        for nf in normalized {
            let new = NewFinding {
                title: nf.title,
                severity: nf.severity,
                source_tool: tool.clone(),
                target: nf.target,
                description: nf.description,
                status: FindingStatus::New,
                command_id: Some(command.id),
            };
            if self.db.record_finding(self.engagement_id, &new).is_ok() {
                count += 1;
            }
        }
        count
    }
}
