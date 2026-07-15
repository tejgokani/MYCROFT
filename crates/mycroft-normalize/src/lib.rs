//! # mycroft-normalize — tool output to findings.
//!
//! Every parser turns a tool's **native machine output** (nmap XML, nuclei JSONL)
//! into a tool-agnostic [`NormalizedFinding`]. The store then stamps engagement,
//! source tool, and command linkage onto each one — so no matter which tool produced
//! it, a finding lands in the single findings model (CLAUDE.md invariant §3).
//!
//! Parsing is **defensive** (CLAUDE.md §8): input is untrusted tool output. A parser
//! never panics on malformed data. Line-oriented formats (nuclei) skip bad records
//! and keep going; document formats (nmap) fail cleanly with an actionable error.

#![forbid(unsafe_code)]

mod nmap;
mod nuclei;

use mycroft_core::{Severity, Tool};
use thiserror::Error;

/// A finding in tool-agnostic form, before the store assigns identity and linkage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFinding {
    pub title: String,
    pub severity: Severity,
    pub target: String,
    pub description: String,
}

/// Errors from normalization.
#[derive(Debug, Error)]
pub enum NormalizeError {
    /// No parser exists for this tool.
    #[error("no parser for tool `{0}`")]
    Unsupported(String),

    /// The input was not valid for the declared tool's format.
    #[error("failed to parse {tool} output: {detail}")]
    Parse { tool: &'static str, detail: String },
}

/// Normalize `raw` output from `tool` into findings.
///
/// `target_hint` is used as a fallback target when a record does not carry its own
/// (e.g. a nuclei line missing both `host` and `matched-at`).
pub fn normalize(
    tool: &Tool,
    raw: &[u8],
    target_hint: Option<&str>,
) -> Result<Vec<NormalizedFinding>, NormalizeError> {
    match tool {
        Tool::Nmap => nmap::parse(raw, target_hint),
        Tool::Nuclei => nuclei::parse(raw, target_hint),
        Tool::Other(name) => Err(NormalizeError::Unsupported(name.clone())),
    }
}

/// Map a tool-reported severity string to the canonical [`Severity`]. Unknown or
/// unrecognized values fall back to `Info` rather than being dropped.
pub(crate) fn severity_from_str(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}
