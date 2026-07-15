//! # mycroft-guard — the scope enforcement unit (SECURITY-CRITICAL).
//!
//! Invariant §1: **no command reaches the network without passing this guard**,
//! including AI-issued commands. The guard is split into two pieces so the risky
//! decision logic is also the most testable (ARCHITECTURE.md):
//!
//! - [`check`] is a **pure function** over a [`ResolvedTarget`] and a compiled
//!   [`Scope`]. Given the same inputs it always returns the same [`GuardDecision`].
//! - [`evaluate`] performs the impure **resolution** step (via a [`Resolver`]) and
//!   then calls [`check`]. Resolution is where DNS-rebind is defended: a domain that
//!   resolves into an out-of-scope network is blocked even if its name is in scope.
//!
//! Default posture is **deny**: a target matching no in-scope rule is blocked, and an
//! out-of-scope (exclusion) rule always wins over an in-scope match.

#![forbid(unsafe_code)]

mod error;
mod resolver;
mod scope;

use std::net::IpAddr;

use mycroft_core::{GuardDecision, ResolvedTarget, Target};

pub use error::GuardError;
pub use resolver::{Resolver, StaticResolver, SystemResolver};
pub use scope::Scope;

/// Pure scope decision over an already-resolved target. No I/O, fully deterministic.
///
/// Precedence: an exclusion (`out`) match blocks unconditionally; otherwise an
/// inclusion (`in`) match allows; otherwise the default-deny blocks.
pub fn check(resolved: &ResolvedTarget, scope: &Scope) -> GuardDecision {
    let target = &resolved.target;
    let addrs = &resolved.addrs;

    let mut in_match = false;
    let mut out_match: Option<&str> = None;

    for rule in &scope.rules {
        if rule.matches(target, addrs) {
            match rule.kind {
                mycroft_core::ScopeKind::Out => {
                    out_match = Some(rule.pattern.as_str());
                    // Out wins; keep scanning only to prefer a stable first-match reason.
                    break;
                }
                mycroft_core::ScopeKind::In => in_match = true,
            }
        }
    }

    if let Some(pattern) = out_match {
        return GuardDecision::Block {
            reason: format!(
                "target `{}` is excluded by out-of-scope rule `{}`",
                target.host(),
                pattern
            ),
        };
    }
    if in_match {
        return GuardDecision::Allow {
            resolved: resolved.clone(),
        };
    }
    GuardDecision::Block {
        reason: format!(
            "target `{}` matches no in-scope rule (default deny)",
            target.host()
        ),
    }
}

/// Resolve `target` (if it is a hostname) and apply [`check`].
///
/// A hostname that fails to resolve is **blocked**, not allowed: if we cannot
/// determine where a name points, we cannot prove it is in scope.
pub fn evaluate(target: &Target, scope: &Scope, resolver: &dyn Resolver) -> GuardDecision {
    let addrs: Vec<IpAddr> = match target {
        Target::Ip(ip) => vec![*ip],
        Target::Domain(host) => match resolver.resolve(host) {
            Ok(addrs) => addrs,
            Err(e) => {
                return GuardDecision::Block {
                    reason: format!("cannot verify scope: {e}"),
                }
            }
        },
    };
    let resolved = ResolvedTarget {
        target: target.clone(),
        addrs,
    };
    check(&resolved, scope)
}
