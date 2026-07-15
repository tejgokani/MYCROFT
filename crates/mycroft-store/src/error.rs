//! Storage error taxonomy.

use thiserror::Error;

/// Errors from the persistence layer. Actionable and typed so the CLI can surface
/// precise messages (CLAUDE.md §8).
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying SQLite failure.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A row was read but a stored enum/text value did not map to a domain type.
    #[error("corrupt or unexpected data in `{table}`: {detail}")]
    Corrupt { table: &'static str, detail: String },

    /// A requested row did not exist.
    #[error("{entity} with id {id} not found")]
    NotFound { entity: &'static str, id: i64 },

    /// Timestamp could not be formatted or parsed as RFC3339.
    #[error("timestamp error: {0}")]
    TimeFormat(String),

    /// The audit chain failed verification — possible tampering.
    #[error("audit chain broken at entry id {id}: {detail}")]
    AuditChainBroken { id: i64, detail: String },
}

impl From<mycroft_core::CoreError> for StoreError {
    fn from(e: mycroft_core::CoreError) -> Self {
        StoreError::Corrupt {
            table: "<enum decode>",
            detail: e.to_string(),
        }
    }
}

/// Store result alias.
pub type Result<T> = std::result::Result<T, StoreError>;
