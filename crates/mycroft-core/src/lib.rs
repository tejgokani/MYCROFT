//! # mycroft-core
//!
//! The shared vocabulary of Mycroft. Every other crate codes against the types
//! defined here — never against another crate's internals (CLAUDE.md §8).
//!
//! This crate is intentionally dependency-light: pure domain types, enums, and a
//! small error taxonomy. It knows nothing about SQLite, processes, or the network.
//! Persistence mapping lives in `mycroft-store`; enforcement lives in `mycroft-guard`.

#![forbid(unsafe_code)]

mod error;
mod ids;
mod model;
mod target;
mod time_util;

pub use error::CoreError;
pub use ids::{CommandId, EngagementId, EvidenceId, FindingId, ScopeRuleId};
pub use model::{
    AuditEntry, Command, Engagement, EngagementStatus, Evidence, EvidenceKind, Finding,
    FindingStatus, IssuedBy, ScopeKind, ScopeRule, ScopeRuleType, Severity, Tool,
};
pub use target::{GuardDecision, ResolvedTarget, Target};
pub use time_util::{now_utc, Timestamp};

/// Result alias for fallible operations that produce a [`CoreError`].
pub type Result<T> = std::result::Result<T, CoreError>;
