//! Embedded, forward-only migration runner keyed on `PRAGMA user_version`.
//!
//! Deliberately tiny: no external migration framework. Each migration is applied in
//! its own transaction; `user_version` is bumped only if the SQL succeeds, so a
//! partially-applied migration can never leave the DB in an inconsistent state.

use rusqlite::Connection;

use crate::error::Result;

/// (schema_version, sql). Ordered ascending. Append new migrations; never edit shipped ones.
const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../../../migrations/0001_init.sql"))];

/// The schema version this build expects.
pub const CURRENT_VERSION: i32 = 1;

/// Apply any migrations whose version exceeds the DB's current `user_version`.
pub fn migrate(conn: &Connection) -> Result<()> {
    let current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (version, sql) in MIGRATIONS {
        if *version > current {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            // PRAGMA cannot be parameterized; version is a compile-time constant.
            tx.pragma_update(None, "user_version", version)?;
            tx.commit()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        // Second run is a no-op and must not error.
        migrate(&conn).unwrap();
        let v: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, CURRENT_VERSION);
        // All tables exist.
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN \
                 ('engagement','scope_rules','commands','findings','evidence','audit_log')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 6);
    }
}
