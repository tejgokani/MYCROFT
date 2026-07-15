//! The persistent domain model — the source of truth (CLAUDE.md invariant §3).
//!
//! These structs mirror the SQLite schema owned by `mycroft-store`, but carry no
//! persistence logic. Enum <-> text mapping lives here so the schema stores stable,
//! human-readable strings rather than opaque integers.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::ids::{CommandId, EngagementId, EvidenceId, FindingId, ScopeRuleId};
use crate::time_util::Timestamp;

/// Defines a closed set of string-backed enum variants with `as_str` / `parse`.
macro_rules! str_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident ($kind:literal) { $( $variant:ident => $text:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        $vis enum $name { $( $variant ),+ }

        impl $name {
            /// The stable text form persisted in SQLite.
            pub const fn as_str(&self) -> &'static str {
                match self { $( $name::$variant => $text ),+ }
            }

            /// Every variant, in declaration order (useful for reports and CLI help).
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];

            /// Parse from the persisted text form. Rejects unknown values defensively.
            pub fn parse(s: &str) -> Result<Self, CoreError> {
                match s {
                    $( $text => Ok($name::$variant), )+
                    other => Err(CoreError::UnknownVariant { kind: $kind, value: other.to_string() }),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

str_enum! {
    /// Lifecycle state of an engagement.
    pub enum EngagementStatus ("engagement status") {
        Active => "active",
        Paused => "paused",
        Closed => "closed",
    }
}

str_enum! {
    /// Whether a scope rule includes or excludes its pattern. Exclusions (`Out`) win.
    pub enum ScopeKind ("scope kind") {
        In => "in",
        Out => "out",
    }
}

str_enum! {
    /// How a scope rule's pattern should be interpreted.
    pub enum ScopeRuleType ("scope rule type") {
        Cidr => "cidr",
        Domain => "domain",
        Url => "url",
    }
}

str_enum! {
    /// Who issued a command. AI-issued commands take the identical guarded path (§7).
    pub enum IssuedBy ("issued_by") {
        Human => "human",
        Ai => "ai",
    }
}

str_enum! {
    /// Finding severity, ordered Info..Critical.
    pub enum Severity ("severity") {
        Info => "info",
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

impl Severity {
    /// Numeric rank for sorting (higher = more severe).
    pub const fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

str_enum! {
    /// Triage state of a finding.
    pub enum FindingStatus ("finding status") {
        New => "new",
        Confirmed => "confirmed",
        Dead => "dead",
        Manual => "manual",
    }
}

str_enum! {
    /// The kind of evidence artifact captured.
    pub enum EvidenceKind ("evidence kind") {
        Output => "output",
        Screenshot => "screenshot",
        File => "file",
    }
}

/// The tool that produced a command/finding. Known tools have parsers; unknown
/// tools are still run and logged, just not normalized.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tool {
    Nmap,
    Nuclei,
    /// Any other executed program, preserved by name for the audit trail.
    Other(String),
}

impl Tool {
    /// Canonical text form. `Other` round-trips its stored name.
    pub fn as_str(&self) -> &str {
        match self {
            Tool::Nmap => "nmap",
            Tool::Nuclei => "nuclei",
            Tool::Other(name) => name.as_str(),
        }
    }

    /// Map a program name (possibly a path) to a known tool, falling back to `Other`.
    /// Matching is on the basename so `/usr/bin/nmap` and `nmap` both resolve to `Nmap`.
    pub fn from_name(name: &str) -> Self {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        match base.to_ascii_lowercase().as_str() {
            "nmap" => Tool::Nmap,
            "nuclei" => Tool::Nuclei,
            _ => Tool::Other(name.to_string()),
        }
    }

    /// True if `mycroft-normalize` has a parser for this tool's output.
    pub fn is_normalizable(&self) -> bool {
        matches!(self, Tool::Nmap | Tool::Nuclei)
    }
}

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An engagement — the top-level container. One SQLite file per engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Engagement {
    pub id: EngagementId,
    pub name: String,
    pub client: String,
    pub created_at: Timestamp,
    pub status: EngagementStatus,
}

/// A single scope rule. Precedence and matching semantics are enforced in `mycroft-guard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    pub id: ScopeRuleId,
    pub engagement_id: EngagementId,
    pub pattern: String,
    pub kind: ScopeKind,
    pub rule_type: ScopeRuleType,
    pub created_at: Timestamp,
}

/// A recorded command. Persisted for **both** executions and blocked attempts
/// (CLAUDE.md invariant §2 covers attempts, not just successful runs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub id: CommandId,
    pub engagement_id: EngagementId,
    pub raw_cmd: String,
    pub tool: Tool,
    pub target: String,
    /// The IP the guard actually approved (DNS/redirect evidence). `None` if blocked.
    pub resolved_target: Option<String>,
    /// True if the scope guard blocked this attempt; it never reached the network.
    pub blocked: bool,
    /// Human-readable guard verdict recorded for audit.
    pub scope_check: String,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
    pub exit_code: Option<i32>,
    pub stdout_ref: Option<String>,
    pub stderr_ref: Option<String>,
    pub issued_by: IssuedBy,
}

/// A normalized finding. All tools converge here regardless of source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub engagement_id: EngagementId,
    pub title: String,
    pub severity: Severity,
    pub source_tool: Tool,
    pub target: String,
    pub description: String,
    pub status: FindingStatus,
    pub command_id: Option<CommandId>,
    pub created_at: Timestamp,
}

/// An evidence artifact, content-addressed by sha256 and linked to a finding
/// and/or the command that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub engagement_id: EngagementId,
    pub finding_id: Option<FindingId>,
    pub command_id: Option<CommandId>,
    pub kind: EvidenceKind,
    pub path: String,
    pub sha256: String,
    pub created_at: Timestamp,
}

/// One link in the tamper-evident audit chain (CLAUDE.md deviation §5).
///
/// `hash = sha256(prev_hash || canonical(event, ref_table, ref_id, ts))`. The
/// genesis entry uses an all-zero `prev_hash`. `mycroft verify` re-walks the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub engagement_id: EngagementId,
    /// What happened, e.g. `engagement.created`, `command.executed`, `command.blocked`.
    pub event: String,
    /// The table the event refers to (`commands`, `findings`, ...), if any.
    pub ref_table: Option<String>,
    /// The rowid within `ref_table`, if any.
    pub ref_id: Option<i64>,
    pub ts: Timestamp,
    /// Hex sha256 of the previous entry (64 zeros for genesis).
    pub prev_hash: String,
    /// Hex sha256 of this entry.
    pub hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_round_trips_and_orders() {
        for s in Severity::ALL {
            assert_eq!(Severity::parse(s.as_str()).unwrap(), *s);
        }
        assert!(Severity::Critical.rank() > Severity::Info.rank());
    }

    #[test]
    fn unknown_variant_is_rejected() {
        let err = FindingStatus::parse("bogus").unwrap_err();
        assert!(matches!(err, CoreError::UnknownVariant { .. }));
    }

    #[test]
    fn tool_name_mapping() {
        assert_eq!(Tool::from_name("NMAP"), Tool::Nmap);
        assert_eq!(Tool::from_name("ffuf"), Tool::Other("ffuf".to_string()));
        assert!(Tool::Nuclei.is_normalizable());
        assert!(!Tool::from_name("ffuf").is_normalizable());
    }
}
