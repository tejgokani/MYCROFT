//! Time handling. Invariant: all timestamps are stored in **UTC** (CLAUDE.md deviation §8).

use time::OffsetDateTime;

/// A UTC timestamp. Wraps [`time::OffsetDateTime`] but is always constructed in UTC.
pub type Timestamp = OffsetDateTime;

/// The current instant in UTC. Use this everywhere a timestamp is recorded so the
/// engagement artifact is timezone-independent and diffable across operators.
pub fn now_utc() -> Timestamp {
    OffsetDateTime::now_utc()
}
