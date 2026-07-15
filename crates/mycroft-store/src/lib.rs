//! # mycroft-store
//!
//! The persistence layer and **source of truth** (CLAUDE.md invariant §3). One
//! SQLite file per engagement. Owns the schema, migrations, the tamper-evident
//! audit chain, and typed repositories. Other crates never touch SQL directly.
//!
//! ## Concurrency
//! SQLite runs in WAL mode with a single logical writer serialized by the caller
//! (ARCHITECTURE.md concurrency model). `foreign_keys` is enforced.
//!
//! ## Encryption at rest (CLAUDE.md §6)
//! Off by default. Build with `--features encryption` (SQLCipher) and pass a key to
//! [`Db::open_with_key`]; the same `PRAGMA key` seam is inert on stock SQLite, so the
//! API is stable whether or not encryption is compiled in.

#![forbid(unsafe_code)]

pub mod audit;
mod error;
mod migrations;
mod repo;
mod timefmt;

pub use error::{Result, StoreError};
pub use migrations::CURRENT_VERSION;
pub use repo::{NewCommand, NewEvidence, NewFinding};

use mycroft_core::{
    now_utc, Command, CommandId, Engagement, EngagementId, Evidence, Finding, ScopeKind, ScopeRule,
    ScopeRuleType,
};
use rusqlite::Connection;
use std::path::Path;

/// A handle to one engagement database.
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open (creating if absent) an unencrypted engagement DB and run migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(path, None)
    }

    /// Open an engagement DB encrypted at rest with `key` (effective only when built
    /// with `--features encryption`). See the module docs for the seam's semantics.
    pub fn open_with_key(path: impl AsRef<Path>, key: &str) -> Result<Self> {
        Self::open_inner(path, Some(key))
    }

    /// Open an in-memory DB (tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::bootstrap(conn, None)
    }

    fn open_inner(path: impl AsRef<Path>, key: Option<&str>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::bootstrap(conn, key)
    }

    fn bootstrap(conn: Connection, key: Option<&str>) -> Result<Self> {
        // Key must be set before any other access so the whole file is encrypted.
        if let Some(key) = key {
            conn.pragma_update(None, "key", key)?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrations::migrate(&conn)?;
        Ok(Self { conn })
    }

    /// Borrow the raw connection (for repositories in sibling crates in later phases).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Create a new engagement and record the genesis audit entry, atomically.
    pub fn create_engagement(&self, name: &str, client: &str) -> Result<Engagement> {
        let tx = self.conn.unchecked_transaction()?;
        let engagement = repo::insert_engagement(&tx, name, client)?;
        audit::append(
            &tx,
            engagement.id,
            "engagement.created",
            Some("engagement"),
            Some(engagement.id.get()),
        )?;
        tx.commit()?;
        Ok(engagement)
    }

    /// Fetch an engagement by id.
    pub fn get_engagement(&self, id: EngagementId) -> Result<Engagement> {
        repo::get_engagement(&self.conn, id)
    }

    /// List engagements, newest first.
    pub fn list_engagements(&self) -> Result<Vec<Engagement>> {
        repo::list_engagements(&self.conn)
    }

    /// Add a scope rule and record it in the audit chain, atomically.
    pub fn add_scope_rule(
        &self,
        engagement_id: EngagementId,
        pattern: &str,
        kind: ScopeKind,
        rule_type: ScopeRuleType,
    ) -> Result<ScopeRule> {
        let tx = self.conn.unchecked_transaction()?;
        let rule = repo::insert_scope_rule(&tx, engagement_id, pattern, kind, rule_type)?;
        audit::append(
            &tx,
            engagement_id,
            "scope.added",
            Some("scope_rules"),
            Some(rule.id.get()),
        )?;
        tx.commit()?;
        Ok(rule)
    }

    /// List scope rules for an engagement.
    pub fn list_scope_rules(&self, engagement_id: EngagementId) -> Result<Vec<ScopeRule>> {
        repo::list_scope_rules(&self.conn, engagement_id)
    }

    /// Verify the tamper-evident audit chain for an engagement.
    pub fn verify_audit(&self, engagement_id: EngagementId) -> Result<()> {
        audit::verify(&self.conn, engagement_id)
    }

    /// Record a command the guard **blocked** — a terminal attempt that never ran
    /// (CLAUDE.md invariant §2: attempts are persisted, not just executions).
    pub fn record_blocked_command(
        &self,
        engagement_id: EngagementId,
        new: &NewCommand,
    ) -> Result<Command> {
        let now = now_utc();
        let tx = self.conn.unchecked_transaction()?;
        let cmd = repo::insert_command(&tx, engagement_id, new, now, Some(now), None)?;
        audit::append(
            &tx,
            engagement_id,
            "command.blocked",
            Some("commands"),
            Some(cmd.id.get()),
        )?;
        tx.commit()?;
        Ok(cmd)
    }

    /// Record the start of an **allowed** execution and return the in-flight row.
    /// Close it later with [`Db::finish_command`].
    pub fn start_command(&self, engagement_id: EngagementId, new: &NewCommand) -> Result<Command> {
        let now = now_utc();
        let tx = self.conn.unchecked_transaction()?;
        let cmd = repo::insert_command(&tx, engagement_id, new, now, None, None)?;
        audit::append(
            &tx,
            engagement_id,
            "command.started",
            Some("commands"),
            Some(cmd.id.get()),
        )?;
        tx.commit()?;
        Ok(cmd)
    }

    /// Close an in-flight command with its exit code and output references.
    pub fn finish_command(
        &self,
        engagement_id: EngagementId,
        id: CommandId,
        exit_code: Option<i32>,
        stdout_ref: Option<&str>,
        stderr_ref: Option<&str>,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        repo::finish_command(&tx, id, now_utc(), exit_code, stdout_ref, stderr_ref)?;
        audit::append(
            &tx,
            engagement_id,
            "command.completed",
            Some("commands"),
            Some(id.get()),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Attach an evidence artifact (content-addressed by sha256) and audit it.
    pub fn add_evidence(&self, engagement_id: EngagementId, new: &NewEvidence) -> Result<Evidence> {
        let tx = self.conn.unchecked_transaction()?;
        let ev = repo::insert_evidence(&tx, engagement_id, new)?;
        audit::append(
            &tx,
            engagement_id,
            "evidence.captured",
            Some("evidence"),
            Some(ev.id.get()),
        )?;
        tx.commit()?;
        Ok(ev)
    }

    /// Record a normalized finding and audit it.
    pub fn record_finding(&self, engagement_id: EngagementId, new: &NewFinding) -> Result<Finding> {
        let tx = self.conn.unchecked_transaction()?;
        let finding = repo::insert_finding(&tx, engagement_id, new)?;
        audit::append(
            &tx,
            engagement_id,
            "finding.recorded",
            Some("findings"),
            Some(finding.id.get()),
        )?;
        tx.commit()?;
        Ok(finding)
    }

    /// List findings for an engagement, most severe first.
    pub fn list_findings(&self, engagement_id: EngagementId) -> Result<Vec<Finding>> {
        repo::list_findings(&self.conn, engagement_id)
    }

    /// Fetch a command by id.
    pub fn get_command(&self, id: CommandId) -> Result<Command> {
        repo::get_command(&self.conn, id)
    }

    /// List commands for an engagement, newest first.
    pub fn list_commands(&self, engagement_id: EngagementId) -> Result<Vec<Command>> {
        repo::list_commands(&self.conn, engagement_id)
    }

    /// List evidence attached to a command.
    pub fn list_evidence_for_command(&self, id: CommandId) -> Result<Vec<Evidence>> {
        repo::list_evidence_for_command(&self.conn, id)
    }
}
