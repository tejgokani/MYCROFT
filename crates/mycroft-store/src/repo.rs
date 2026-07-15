//! Typed repositories. Modules never write raw SQL; they call these functions and
//! receive domain types (ARCHITECTURE.md: "no raw SQL leaks into modules").
//!
//! Phase 0 implements engagement + scope repositories; Phase 2 adds command +
//! evidence, all against the same pattern.

use mycroft_core::{
    now_utc, Command, CommandId, Engagement, EngagementId, EngagementStatus, Evidence, EvidenceId,
    EvidenceKind, Finding, FindingId, FindingStatus, IssuedBy, ScopeKind, ScopeRule, ScopeRuleId,
    ScopeRuleType, Severity, Timestamp, Tool,
};
use rusqlite::{Connection, Row};

use crate::error::{Result, StoreError};
use crate::timefmt;

/// Input for inserting a command row. Timestamps/exit are supplied by the caller so
/// the same struct serves both blocked attempts and executions.
#[derive(Debug, Clone)]
pub struct NewCommand {
    pub raw_cmd: String,
    pub tool: Tool,
    pub target: String,
    pub resolved_target: Option<String>,
    pub blocked: bool,
    pub scope_check: String,
    pub issued_by: IssuedBy,
}

/// Input for inserting an evidence row.
#[derive(Debug, Clone)]
pub struct NewEvidence {
    pub finding_id: Option<FindingId>,
    pub command_id: Option<CommandId>,
    pub kind: EvidenceKind,
    pub path: String,
    pub sha256: String,
}

/// Input for inserting a finding row.
#[derive(Debug, Clone)]
pub struct NewFinding {
    pub title: String,
    pub severity: Severity,
    pub source_tool: Tool,
    pub target: String,
    pub description: String,
    pub status: FindingStatus,
    /// The command this finding was normalized from, if any (imports have none).
    pub command_id: Option<CommandId>,
}

fn map_engagement(row: &Row<'_>) -> rusqlite::Result<(i64, String, String, String, String)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn engagement_from_parts(
    id: i64,
    name: String,
    client: String,
    created_at: String,
    status: String,
) -> Result<Engagement> {
    Ok(Engagement {
        id: EngagementId(id),
        name,
        client,
        created_at: timefmt::from_text(&created_at)?,
        status: EngagementStatus::parse(&status).map_err(|e| StoreError::Corrupt {
            table: "engagement",
            detail: e.to_string(),
        })?,
    })
}

/// Insert a new engagement row (does not append audit; the caller composes that in a tx).
pub fn insert_engagement(conn: &Connection, name: &str, client: &str) -> Result<Engagement> {
    let created_at = now_utc();
    let created_text = timefmt::to_text(created_at)?;
    let status = EngagementStatus::Active;
    conn.execute(
        "INSERT INTO engagement (name, client, created_at, status) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, client, created_text, status.as_str()],
    )?;
    Ok(Engagement {
        id: EngagementId(conn.last_insert_rowid()),
        name: name.to_string(),
        client: client.to_string(),
        created_at,
        status,
    })
}

/// Fetch an engagement by id.
pub fn get_engagement(conn: &Connection, id: EngagementId) -> Result<Engagement> {
    let row = conn
        .query_row(
            "SELECT id, name, client, created_at, status FROM engagement WHERE id = ?1",
            [id.get()],
            map_engagement,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound {
                entity: "engagement",
                id: id.get(),
            },
            other => StoreError::Sqlite(other),
        })?;
    engagement_from_parts(row.0, row.1, row.2, row.3, row.4)
}

/// List all engagements, newest first.
pub fn list_engagements(conn: &Connection) -> Result<Vec<Engagement>> {
    let mut stmt = conn
        .prepare("SELECT id, name, client, created_at, status FROM engagement ORDER BY id DESC")?;
    let rows = stmt.query_map([], map_engagement)?;
    let mut out = Vec::new();
    for r in rows {
        let (id, name, client, created_at, status) = r?;
        out.push(engagement_from_parts(id, name, client, created_at, status)?);
    }
    Ok(out)
}

/// Insert a scope rule (does not append audit; caller composes that in a tx).
pub fn insert_scope_rule(
    conn: &Connection,
    engagement_id: EngagementId,
    pattern: &str,
    kind: ScopeKind,
    rule_type: ScopeRuleType,
) -> Result<ScopeRule> {
    let created_at = now_utc();
    let created_text = timefmt::to_text(created_at)?;
    conn.execute(
        "INSERT INTO scope_rules (engagement_id, pattern, kind, \"type\", created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            engagement_id.get(),
            pattern,
            kind.as_str(),
            rule_type.as_str(),
            created_text
        ],
    )?;
    Ok(ScopeRule {
        id: ScopeRuleId(conn.last_insert_rowid()),
        engagement_id,
        pattern: pattern.to_string(),
        kind,
        rule_type,
        created_at,
    })
}

/// List scope rules for an engagement in insertion order.
pub fn list_scope_rules(conn: &Connection, engagement_id: EngagementId) -> Result<Vec<ScopeRule>> {
    let mut stmt = conn.prepare(
        "SELECT id, pattern, kind, \"type\", created_at FROM scope_rules \
         WHERE engagement_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([engagement_id.get()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (id, pattern, kind, rule_type, created_at) = r?;
        out.push(ScopeRule {
            id: ScopeRuleId(id),
            engagement_id,
            pattern,
            kind: ScopeKind::parse(&kind).map_err(|e| StoreError::Corrupt {
                table: "scope_rules",
                detail: e.to_string(),
            })?,
            rule_type: ScopeRuleType::parse(&rule_type).map_err(|e| StoreError::Corrupt {
                table: "scope_rules",
                detail: e.to_string(),
            })?,
            created_at: timefmt::from_text(&created_at)?,
        });
    }
    Ok(out)
}

// ---- commands ----------------------------------------------------------------

/// Insert a command row. `started_at` is always set; `ended_at`/`exit_code` are set
/// for a completed run or a blocked attempt (both terminal), and left `None` for an
/// in-flight execution to be closed later by [`finish_command`].
#[allow(clippy::too_many_arguments)]
pub fn insert_command(
    conn: &Connection,
    engagement_id: EngagementId,
    new: &NewCommand,
    started_at: Timestamp,
    ended_at: Option<Timestamp>,
    exit_code: Option<i32>,
) -> Result<Command> {
    let started_text = timefmt::to_text(started_at)?;
    let ended_text = ended_at.map(timefmt::to_text).transpose()?;
    conn.execute(
        "INSERT INTO commands \
         (engagement_id, raw_cmd, tool, target, resolved_target, blocked, scope_check, \
          started_at, ended_at, exit_code, stdout_ref, stderr_ref, issued_by) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, ?11)",
        rusqlite::params![
            engagement_id.get(),
            new.raw_cmd,
            new.tool.as_str(),
            new.target,
            new.resolved_target,
            new.blocked as i64,
            new.scope_check,
            started_text,
            ended_text,
            exit_code,
            new.issued_by.as_str(),
        ],
    )?;
    Ok(Command {
        id: CommandId(conn.last_insert_rowid()),
        engagement_id,
        raw_cmd: new.raw_cmd.clone(),
        tool: new.tool.clone(),
        target: new.target.clone(),
        resolved_target: new.resolved_target.clone(),
        blocked: new.blocked,
        scope_check: new.scope_check.clone(),
        started_at,
        ended_at,
        exit_code,
        stdout_ref: None,
        stderr_ref: None,
        issued_by: new.issued_by,
    })
}

/// Close an in-flight command: record its end time, exit code, and output refs.
pub fn finish_command(
    conn: &Connection,
    id: CommandId,
    ended_at: Timestamp,
    exit_code: Option<i32>,
    stdout_ref: Option<&str>,
    stderr_ref: Option<&str>,
) -> Result<()> {
    let ended_text = timefmt::to_text(ended_at)?;
    let n = conn.execute(
        "UPDATE commands SET ended_at = ?2, exit_code = ?3, stdout_ref = ?4, stderr_ref = ?5 \
         WHERE id = ?1",
        rusqlite::params![id.get(), ended_text, exit_code, stdout_ref, stderr_ref],
    )?;
    if n == 0 {
        return Err(StoreError::NotFound {
            entity: "command",
            id: id.get(),
        });
    }
    Ok(())
}

fn command_from_row(row: &Row<'_>) -> Result<Command> {
    let tool_text: String = row.get(3)?;
    let issued_text: String = row.get(13)?;
    let started_text: String = row.get(8)?;
    let ended_text: Option<String> = row.get(9)?;
    Ok(Command {
        id: CommandId(row.get(0)?),
        engagement_id: EngagementId(row.get(1)?),
        raw_cmd: row.get(2)?,
        tool: Tool::from_name(&tool_text),
        target: row.get(4)?,
        resolved_target: row.get(5)?,
        blocked: row.get::<_, i64>(6)? != 0,
        scope_check: row.get(7)?,
        started_at: timefmt::from_text(&started_text)?,
        ended_at: ended_text.as_deref().map(timefmt::from_text).transpose()?,
        exit_code: row.get(10)?,
        stdout_ref: row.get(11)?,
        stderr_ref: row.get(12)?,
        issued_by: IssuedBy::parse(&issued_text).map_err(|e| StoreError::Corrupt {
            table: "commands",
            detail: e.to_string(),
        })?,
    })
}

const COMMAND_COLS: &str = "id, engagement_id, raw_cmd, tool, target, resolved_target, blocked, \
     scope_check, started_at, ended_at, exit_code, stdout_ref, stderr_ref, issued_by";

/// Fetch a command by id.
pub fn get_command(conn: &Connection, id: CommandId) -> Result<Command> {
    let sql = format!("SELECT {COMMAND_COLS} FROM commands WHERE id = ?1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([id.get()])?;
    match rows.next()? {
        Some(row) => command_from_row(row),
        None => Err(StoreError::NotFound {
            entity: "command",
            id: id.get(),
        }),
    }
}

/// List commands for an engagement, newest first.
pub fn list_commands(conn: &Connection, engagement_id: EngagementId) -> Result<Vec<Command>> {
    let sql =
        format!("SELECT {COMMAND_COLS} FROM commands WHERE engagement_id = ?1 ORDER BY id DESC");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([engagement_id.get()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(command_from_row(row)?);
    }
    Ok(out)
}

// ---- evidence ----------------------------------------------------------------

/// Insert an evidence row.
pub fn insert_evidence(
    conn: &Connection,
    engagement_id: EngagementId,
    new: &NewEvidence,
) -> Result<Evidence> {
    let created_at = now_utc();
    let created_text = timefmt::to_text(created_at)?;
    conn.execute(
        "INSERT INTO evidence \
         (engagement_id, finding_id, command_id, kind, path, sha256, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            engagement_id.get(),
            new.finding_id.map(|f| f.get()),
            new.command_id.map(|c| c.get()),
            new.kind.as_str(),
            new.path,
            new.sha256,
            created_text,
        ],
    )?;
    Ok(Evidence {
        id: EvidenceId(conn.last_insert_rowid()),
        engagement_id,
        finding_id: new.finding_id,
        command_id: new.command_id,
        kind: new.kind,
        path: new.path.clone(),
        sha256: new.sha256.clone(),
        created_at,
    })
}

// ---- findings ----------------------------------------------------------------

/// Insert a normalized finding.
pub fn insert_finding(
    conn: &Connection,
    engagement_id: EngagementId,
    new: &NewFinding,
) -> Result<Finding> {
    let created_at = now_utc();
    let created_text = timefmt::to_text(created_at)?;
    conn.execute(
        "INSERT INTO findings \
         (engagement_id, title, severity, source_tool, target, description, status, \
          command_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            engagement_id.get(),
            new.title,
            new.severity.as_str(),
            new.source_tool.as_str(),
            new.target,
            new.description,
            new.status.as_str(),
            new.command_id.map(|c| c.get()),
            created_text,
        ],
    )?;
    Ok(Finding {
        id: FindingId(conn.last_insert_rowid()),
        engagement_id,
        title: new.title.clone(),
        severity: new.severity,
        source_tool: new.source_tool.clone(),
        target: new.target.clone(),
        description: new.description.clone(),
        status: new.status,
        command_id: new.command_id,
        created_at,
    })
}

/// List findings for an engagement, most severe first (ties broken by newest).
pub fn list_findings(conn: &Connection, engagement_id: EngagementId) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "SELECT id, title, severity, source_tool, target, description, status, command_id, \
                created_at \
         FROM findings WHERE engagement_id = ?1 ORDER BY id DESC",
    )?;
    let mut rows = stmt.query([engagement_id.get()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let severity_text: String = row.get(2)?;
        let tool_text: String = row.get(3)?;
        let status_text: String = row.get(6)?;
        let created_text: String = row.get(8)?;
        out.push(Finding {
            id: FindingId(row.get(0)?),
            engagement_id,
            title: row.get(1)?,
            severity: Severity::parse(&severity_text).map_err(|e| StoreError::Corrupt {
                table: "findings",
                detail: e.to_string(),
            })?,
            source_tool: Tool::from_name(&tool_text),
            target: row.get(4)?,
            description: row.get(5)?,
            status: FindingStatus::parse(&status_text).map_err(|e| StoreError::Corrupt {
                table: "findings",
                detail: e.to_string(),
            })?,
            command_id: row.get::<_, Option<i64>>(7)?.map(CommandId),
            created_at: timefmt::from_text(&created_text)?,
        });
    }
    // Stable, severity-first ordering for display/report.
    out.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(b.id.get().cmp(&a.id.get()))
    });
    Ok(out)
}

/// List evidence attached to a command.
pub fn list_evidence_for_command(
    conn: &Connection,
    command_id: CommandId,
) -> Result<Vec<Evidence>> {
    let mut stmt = conn.prepare(
        "SELECT id, engagement_id, finding_id, command_id, kind, path, sha256, created_at \
         FROM evidence WHERE command_id = ?1 ORDER BY id ASC",
    )?;
    let mut rows = stmt.query([command_id.get()])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let kind_text: String = row.get(4)?;
        let created_text: String = row.get(7)?;
        out.push(Evidence {
            id: EvidenceId(row.get(0)?),
            engagement_id: EngagementId(row.get(1)?),
            finding_id: row.get::<_, Option<i64>>(2)?.map(FindingId),
            command_id: row.get::<_, Option<i64>>(3)?.map(CommandId),
            kind: EvidenceKind::parse(&kind_text).map_err(|e| StoreError::Corrupt {
                table: "evidence",
                detail: e.to_string(),
            })?,
            path: row.get(5)?,
            sha256: row.get(6)?,
            created_at: timefmt::from_text(&created_text)?,
        });
    }
    Ok(out)
}
