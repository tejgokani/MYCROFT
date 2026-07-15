//! Targets: the thing the scope guard decides on.
//!
//! Design note (CLAUDE.md deviation §1): the guard is a **pure function over a
//! `ResolvedTarget`**, but resolution (turning a domain into the IPs it currently
//! points at) is a separate, security-critical step performed by `mycroft-guard`.
//! A raw [`Target`] is never sufficient to allow network egress; only a
//! [`ResolvedTarget`] that passed the guard is.

use std::net::IpAddr;

use crate::error::CoreError;

/// A destination an operator or tool wants to reach, parsed from untrusted text.
///
/// URLs are reduced to their host component: the guard only ever reasons about a
/// host or a literal IP. The original input is retained for evidence and logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A literal IPv4 or IPv6 address. No DNS resolution needed.
    Ip(IpAddr),
    /// A DNS hostname (possibly extracted from a URL). Must be resolved before egress.
    Domain(String),
}

impl Target {
    /// Parse a target from a raw string: a literal IP, a bare hostname, or a URL
    /// (from which the host is extracted). Defensive against malformed input.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidTarget {
                input: raw.to_string(),
                reason: "empty".to_string(),
            });
        }

        // Strip a URL scheme and path/query/fragment to isolate the authority.
        let host_port = match trimmed.split_once("://") {
            Some((_scheme, rest)) => rest,
            None => trimmed,
        };
        // authority = everything before the first '/', '?', or '#'
        let authority = host_port.split(['/', '?', '#']).next().unwrap_or(host_port);
        // Drop userinfo (user:pass@host) if present.
        let host_port = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);

        let host = strip_port(host_port);
        if host.is_empty() {
            return Err(CoreError::InvalidTarget {
                input: raw.to_string(),
                reason: "no host component".to_string(),
            });
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Target::Ip(ip));
        }
        validate_hostname(host).map_err(|reason| CoreError::InvalidTarget {
            input: raw.to_string(),
            reason,
        })?;
        // Normalize an FQDN trailing dot away so scope matching is canonical.
        let host = host.strip_suffix('.').unwrap_or(host);
        Ok(Target::Domain(host.to_ascii_lowercase()))
    }

    /// The host string for display/logging (IP text or lowercased hostname).
    pub fn host(&self) -> String {
        match self {
            Target::Ip(ip) => ip.to_string(),
            Target::Domain(d) => d.clone(),
        }
    }
}

/// Separate a host from an optional `:port`, correctly handling bracketed IPv6
/// (`[::1]:8080`) and bare IPv6 (`::1`, which must not be split on its colons).
fn strip_port(host_port: &str) -> &str {
    if let Some(rest) = host_port.strip_prefix('[') {
        // Bracketed IPv6 literal: host is between '[' and ']'.
        return rest.split(']').next().unwrap_or(rest);
    }
    // A bare IPv6 literal contains multiple ':' — never strip a port from it.
    if host_port.matches(':').count() > 1 {
        return host_port;
    }
    host_port.split(':').next().unwrap_or(host_port)
}

/// Minimal, defensive hostname validation (RFC 1123-ish). We are permissive enough
/// for real targets but reject obviously bogus input rather than trusting shape.
fn validate_hostname(host: &str) -> Result<(), String> {
    if host.len() > 253 {
        return Err("hostname exceeds 253 characters".to_string());
    }
    let host = host.strip_suffix('.').unwrap_or(host); // allow FQDN trailing dot
    if host.is_empty() {
        return Err("empty hostname".to_string());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("empty label (consecutive dots)".to_string());
        }
        if label.len() > 63 {
            return Err("label exceeds 63 characters".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("label `{label}` starts or ends with a hyphen"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!("label `{label}` has invalid characters"));
        }
    }
    Ok(())
}

/// A [`Target`] plus the concrete IP addresses it resolves to at exec time.
///
/// For an `Ip` target the set is the singleton IP. For a `Domain` it is whatever
/// DNS returned *now*. The guard must approve **every** address in this set —
/// a domain that resolves partly out-of-scope is blocked (DNS-rebind defense).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The original target as parsed.
    pub target: Target,
    /// All addresses the target currently resolves to (never empty when Allow-able).
    pub addrs: Vec<IpAddr>,
}

/// The guard's verdict on a [`ResolvedTarget`]. There is no third state: a command
/// either passed the guard (and may run) or was blocked (and is logged as an attempt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    /// Allowed. Carries the resolved addresses that were approved (recorded as evidence).
    Allow { resolved: ResolvedTarget },
    /// Blocked. Carries a human-readable, actionable reason for the operator and the log.
    Block { reason: String },
}

impl GuardDecision {
    /// True if the command may proceed to the runner.
    pub fn is_allowed(&self) -> bool {
        matches!(self, GuardDecision::Allow { .. })
    }
}
