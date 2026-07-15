//! Guard error taxonomy.

use thiserror::Error;

/// Errors from scope compilation and resolution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// A scope rule pattern was malformed for its declared type.
    #[error("invalid scope rule `{pattern}` ({rule_type}): {reason}")]
    InvalidRule {
        pattern: String,
        rule_type: String,
        reason: String,
    },

    /// DNS resolution of a target failed; scope cannot be verified, so egress is denied.
    #[error("could not resolve `{host}`: {reason}")]
    ResolutionFailed { host: String, reason: String },
}
