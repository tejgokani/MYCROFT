//! The shared error taxonomy for parsing and validating domain values.
//!
//! Persistence and runtime errors live in their own crates (`mycroft-store`,
//! `mycroft-runner`). `CoreError` covers only the pure, input-validation failures
//! that can occur when constructing domain values from untrusted text.

use thiserror::Error;

/// Errors produced while parsing or validating core domain values.
///
/// Every variant is actionable: it names *what* was rejected so the operator (or a
/// calling crate) can surface a precise message (CLAUDE.md §8).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A target string could not be interpreted as an IP, domain, or URL.
    #[error("could not parse target `{input}`: {reason}")]
    InvalidTarget { input: String, reason: String },

    /// A scope rule pattern was malformed for its declared type.
    #[error("invalid scope rule `{pattern}` (type {rule_type}): {reason}")]
    InvalidScopeRule {
        pattern: String,
        rule_type: String,
        reason: String,
    },

    /// An enum-like string (severity, status, tool, ...) was not a known variant.
    #[error("unknown {kind} value `{value}`")]
    UnknownVariant { kind: &'static str, value: String },
}
