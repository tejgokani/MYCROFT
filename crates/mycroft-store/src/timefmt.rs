//! RFC3339 (UTC) text <-> `Timestamp`, the on-disk representation of all times.

use mycroft_core::Timestamp;
use time::format_description::well_known::Rfc3339;

use crate::error::StoreError;

/// Format a timestamp as RFC3339 for storage.
pub fn to_text(ts: Timestamp) -> Result<String, StoreError> {
    ts.format(&Rfc3339)
        .map_err(|e| StoreError::TimeFormat(e.to_string()))
}

/// Parse an RFC3339 timestamp read from storage.
pub fn from_text(s: &str) -> Result<Timestamp, StoreError> {
    Timestamp::parse(s, &Rfc3339).map_err(|e| StoreError::TimeFormat(e.to_string()))
}
