//! Compiled scope rules and their matching semantics.
//!
//! ## Semantics (documented contract)
//! - **CIDR** rule matches a target if any of the target's addresses fall in the
//!   network. A bare IP is treated as a host route (`/32` or `/128`).
//! - **Domain** rule `example.com` matches the host `example.com` exactly.
//!   `*.example.com` matches any strict subdomain (`a.example.com`, `a.b.example.com`)
//!   but **not** the apex `example.com`.
//! - **URL** rule matches on its host component, treated as a Domain (or CIDR if the
//!   host is a literal IP). Path/scheme are ignored for scope purposes in v0.
//! - Domain/URL rules never match a bare-IP target, and CIDR rules match a Domain
//!   target only through its resolved addresses (the DNS-rebind seam).

use std::net::IpAddr;

use ipnet::IpNet;
use mycroft_core::{ScopeKind, ScopeRule, ScopeRuleType, Target};

use crate::error::GuardError;

/// A single compiled rule: its matcher plus the original text for audit messages.
#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    pub kind: ScopeKind,
    pub pattern: String,
    matcher: Matcher,
}

#[derive(Debug, Clone)]
enum Matcher {
    Cidr(IpNet),
    Domain(DomainPattern),
}

#[derive(Debug, Clone)]
struct DomainPattern {
    /// Lowercased base domain (for `*.acme.com`, this is `acme.com`).
    base: String,
    /// True for `*.base` (strict-subdomain) patterns.
    wildcard: bool,
}

impl DomainPattern {
    fn parse(pattern: &str) -> Result<Self, String> {
        let (base, wildcard) = match pattern.strip_prefix("*.") {
            Some(rest) => (rest, true),
            None => (pattern, false),
        };
        let base = base.trim().trim_end_matches('.').to_ascii_lowercase();
        if base.is_empty() {
            return Err("empty domain".to_string());
        }
        if base.contains('*') {
            return Err("`*` is only allowed as a leading `*.` label".to_string());
        }
        if !base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err("domain contains invalid characters".to_string());
        }
        Ok(DomainPattern { base, wildcard })
    }

    fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.wildcard {
            // Strict subdomain: host ends with ".base" and is longer than that suffix.
            host.len() > self.base.len() + 1 && host.ends_with(&format!(".{}", self.base))
        } else {
            host == self.base
        }
    }
}

/// Parse a CIDR or bare-IP string into an [`IpNet`] host/network.
fn parse_cidr(pattern: &str) -> Result<IpNet, String> {
    let p = pattern.trim();
    if let Ok(net) = p.parse::<IpNet>() {
        return Ok(net);
    }
    // Bare IP -> host route.
    match p.parse::<IpAddr>() {
        Ok(ip) => {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            IpNet::new(ip, prefix).map_err(|e| e.to_string())
        }
        Err(_) => Err("not a valid CIDR or IP address".to_string()),
    }
}

/// Extract the host from a URL-ish scope pattern and compile it to a matcher.
fn compile_url(pattern: &str) -> Result<Matcher, String> {
    // Reuse Target's URL/host extraction so scope hosts and command targets are
    // normalized identically.
    match Target::parse(pattern) {
        Ok(Target::Ip(ip)) => {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            Ok(Matcher::Cidr(
                IpNet::new(ip, prefix).map_err(|e| e.to_string())?,
            ))
        }
        Ok(Target::Domain(host)) => Ok(Matcher::Domain(DomainPattern {
            base: host,
            wildcard: false,
        })),
        Err(e) => Err(e.to_string()),
    }
}

impl CompiledRule {
    fn compile(rule: &ScopeRule) -> Result<Self, GuardError> {
        let matcher = match rule.rule_type {
            ScopeRuleType::Cidr => Matcher::Cidr(parse_cidr(&rule.pattern).map_err(|reason| {
                GuardError::InvalidRule {
                    pattern: rule.pattern.clone(),
                    rule_type: "cidr".to_string(),
                    reason,
                }
            })?),
            ScopeRuleType::Domain => {
                Matcher::Domain(DomainPattern::parse(&rule.pattern).map_err(|reason| {
                    GuardError::InvalidRule {
                        pattern: rule.pattern.clone(),
                        rule_type: "domain".to_string(),
                        reason,
                    }
                })?)
            }
            ScopeRuleType::Url => {
                compile_url(&rule.pattern).map_err(|reason| GuardError::InvalidRule {
                    pattern: rule.pattern.clone(),
                    rule_type: "url".to_string(),
                    reason,
                })?
            }
        };
        Ok(CompiledRule {
            kind: rule.kind,
            pattern: rule.pattern.clone(),
            matcher,
        })
    }

    /// Does this rule match the target (by name for Domain rules, by address for CIDR)?
    pub(crate) fn matches(&self, target: &Target, addrs: &[IpAddr]) -> bool {
        match &self.matcher {
            Matcher::Cidr(net) => addrs.iter().any(|a| net.contains(a)),
            Matcher::Domain(pat) => match target {
                Target::Domain(host) => pat.matches_host(host),
                Target::Ip(_) => false,
            },
        }
    }
}

/// A compiled scope: the full rule set for an engagement, ready for fast checking.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub(crate) rules: Vec<CompiledRule>,
}

impl Scope {
    /// Compile raw scope rules. Fails fast on any malformed pattern (defensive: a
    /// scope we cannot fully understand must not silently under-enforce).
    pub fn compile(rules: &[ScopeRule]) -> Result<Self, GuardError> {
        let compiled = rules
            .iter()
            .map(CompiledRule::compile)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Scope { rules: compiled })
    }

    /// True if the scope contains no rules (everything is out of scope by default-deny).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
