//! The tamper-evident audit chain (CLAUDE.md deviation §5).
//!
//! Every consequential event (engagement created, command executed, command blocked,
//! finding recorded, evidence attached) appends a link whose hash commits to the
//! previous link. Editing or deleting any row breaks every subsequent hash, which
//! `verify` detects. This is the chain-of-custody backbone for defensible reports.

use mycroft_core::{now_utc, AuditEntry, EngagementId, Timestamp};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};
use crate::timefmt;

/// The `prev_hash` of the first (genesis) entry: 64 hex zeros.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Unit-separator-delimited canonical form of an entry's committed fields.
/// Using a control separator (0x1F) that cannot appear in event/table names keeps
/// the encoding unambiguous without length-prefixing.
fn canonical(event: &str, ref_table: Option<&str>, ref_id: Option<i64>, ts_text: &str) -> String {
    format!(
        "{event}\u{1f}{}\u{1f}{}\u{1f}{ts_text}",
        ref_table.unwrap_or(""),
        ref_id.map(|i| i.to_string()).unwrap_or_default(),
    )
}

/// Compute the hex sha256 link hash from the predecessor hash and this entry's fields.
fn link_hash(prev_hash: &str, canonical: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// The most recent link hash for an engagement, or [`GENESIS_PREV`] if none yet.
fn last_hash(conn: &Connection, engagement_id: EngagementId) -> Result<String> {
    let hash: Option<String> = conn
        .query_row(
            "SELECT hash FROM audit_log WHERE engagement_id = ?1 ORDER BY id DESC LIMIT 1",
            [engagement_id.get()],
            |r| r.get(0),
        )
        .ok();
    Ok(hash.unwrap_or_else(|| GENESIS_PREV.to_string()))
}

/// Append a new link to the chain and return the persisted [`AuditEntry`].
///
/// Callers should invoke this in the *same transaction* as the row it describes, so
/// the audit trail and the fact it attests to commit or roll back together.
pub fn append(
    conn: &Connection,
    engagement_id: EngagementId,
    event: &str,
    ref_table: Option<&str>,
    ref_id: Option<i64>,
) -> Result<AuditEntry> {
    append_at(conn, engagement_id, event, ref_table, ref_id, now_utc())
}

/// Like [`append`] but with an explicit timestamp (used in tests for determinism).
pub fn append_at(
    conn: &Connection,
    engagement_id: EngagementId,
    event: &str,
    ref_table: Option<&str>,
    ref_id: Option<i64>,
    ts: Timestamp,
) -> Result<AuditEntry> {
    let ts_text = timefmt::to_text(ts)?;
    let prev_hash = last_hash(conn, engagement_id)?;
    let canon = canonical(event, ref_table, ref_id, &ts_text);
    let hash = link_hash(&prev_hash, &canon);

    conn.execute(
        "INSERT INTO audit_log (engagement_id, event, ref_table, ref_id, ts, prev_hash, hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            engagement_id.get(),
            event,
            ref_table,
            ref_id,
            ts_text,
            prev_hash,
            hash,
        ],
    )?;
    let id = conn.last_insert_rowid();

    Ok(AuditEntry {
        id,
        engagement_id,
        event: event.to_string(),
        ref_table: ref_table.map(str::to_string),
        ref_id,
        ts,
        prev_hash,
        hash,
    })
}

/// Re-walk the entire chain for an engagement and confirm it is intact.
///
/// Fails with [`StoreError::AuditChainBroken`] at the first inconsistency: a broken
/// prev-link, a recomputed hash that doesn't match the stored one, or a genesis
/// entry whose `prev_hash` is not [`GENESIS_PREV`].
pub fn verify(conn: &Connection, engagement_id: EngagementId) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, event, ref_table, ref_id, ts, prev_hash, hash \
         FROM audit_log WHERE engagement_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([engagement_id.get()], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
        ))
    })?;

    let mut expected_prev = GENESIS_PREV.to_string();
    for row in rows {
        let (id, event, ref_table, ref_id, ts_text, prev_hash, stored_hash) = row?;

        if prev_hash != expected_prev {
            return Err(StoreError::AuditChainBroken {
                id,
                detail: format!(
                    "prev_hash does not match predecessor (expected {expected_prev}, found {prev_hash})"
                ),
            });
        }
        let canon = canonical(&event, ref_table.as_deref(), ref_id, &ts_text);
        let recomputed = link_hash(&prev_hash, &canon);
        if recomputed != stored_hash {
            return Err(StoreError::AuditChainBroken {
                id,
                detail: "stored hash does not match recomputed hash (row was altered)".to_string(),
            });
        }
        expected_prev = stored_hash;
    }
    Ok(())
}
