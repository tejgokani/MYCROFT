//! Gathering the report data model from the store (read-only, ARCHITECTURE.md).

use std::collections::HashMap;

use mycroft_core::{
    now_utc, Command, CommandId, Engagement, Evidence, Finding, ScopeRule, Severity, Timestamp,
};
use mycroft_store::Db;

/// Everything a report needs, read once from the engagement database.
pub struct ReportData {
    pub engagement: Engagement,
    pub generated_at: Timestamp,
    pub scope_rules: Vec<ScopeRule>,
    pub findings: Vec<Finding>,
    pub commands: Vec<Command>,
    /// Evidence keyed by the command it belongs to.
    pub evidence: HashMap<i64, Vec<Evidence>>,
    /// Whether the tamper-evident audit chain verified.
    pub audit_ok: bool,
    /// The audit failure detail, if verification failed.
    pub audit_error: Option<String>,
}

impl ReportData {
    /// Collect the full report data set for one engagement.
    pub fn gather(db: &Db, engagement: Engagement) -> anyhow::Result<Self> {
        let scope_rules = db.list_scope_rules(engagement.id)?;
        let findings = db.list_findings(engagement.id)?;
        let commands = db.list_commands(engagement.id)?;

        let mut evidence = HashMap::new();
        for cmd in &commands {
            let ev = db.list_evidence_for_command(cmd.id)?;
            if !ev.is_empty() {
                evidence.insert(cmd.id.get(), ev);
            }
        }

        let (audit_ok, audit_error) = match db.verify_audit(engagement.id) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        Ok(ReportData {
            engagement,
            generated_at: now_utc(),
            scope_rules,
            findings,
            commands,
            evidence,
            audit_ok,
            audit_error,
        })
    }

    /// Count of findings at each severity, highest first.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        Severity::ALL
            .iter()
            .rev() // ALL is Info..Critical; report Critical..Info
            .map(|sev| {
                let n = self.findings.iter().filter(|f| f.severity == *sev).count();
                (*sev, n)
            })
            .collect()
    }

    /// Look up the command that produced a finding, if any.
    pub fn command_for(&self, id: Option<CommandId>) -> Option<&Command> {
        let id = id?;
        self.commands.iter().find(|c| c.id == id)
    }
}
