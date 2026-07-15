//! Typed identifiers.
//!
//! SQLite hands out `i64` rowids. Wrapping each in a newtype prevents accidentally
//! passing a `finding_id` where a `command_id` is expected — a cheap, compile-time
//! guard against a whole class of foreign-key mistakes.

use serde::{Deserialize, Serialize};

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub i64);

        impl $name {
            /// The underlying SQLite rowid.
            pub const fn get(self) -> i64 {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<i64> for $name {
            fn from(v: i64) -> Self {
                Self(v)
            }
        }
    };
}

typed_id!(
    /// Identifies an `engagement` row.
    EngagementId
);
typed_id!(
    /// Identifies a `scope_rules` row.
    ScopeRuleId
);
typed_id!(
    /// Identifies a `commands` row.
    CommandId
);
typed_id!(
    /// Identifies a `findings` row.
    FindingId
);
typed_id!(
    /// Identifies an `evidence` row.
    EvidenceId
);
