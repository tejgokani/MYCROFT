//! DNS resolution, abstracted behind a trait.
//!
//! Resolution is the security-critical step in front of the pure `check` (CLAUDE.md
//! deviation §1): a hostname must be turned into the concrete IPs it points at *now*
//! before egress can be authorized. Abstracting it as a trait keeps the guard's
//! decision logic pure and lets tests inject deterministic answers (including
//! rebind-style mismatches) without touching the network.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};

use crate::error::GuardError;

/// Resolves a hostname to the set of IP addresses it currently points at.
pub trait Resolver {
    /// Resolve `host`. An empty result must be returned as `Ok(vec![])`, not an error;
    /// only a genuine lookup failure is an `Err`.
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, GuardError>;
}

/// The default resolver, backed by the OS resolver via `std::net::ToSocketAddrs`.
///
/// v0 deliberately uses the std resolver (zero extra dependencies). A future version
/// can swap in a controlled resolver (timeouts, DoH, custom nameservers) behind this
/// same trait without changing any decision logic.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, GuardError> {
        // Port 0 is irrelevant; we only want address resolution.
        match (host, 0u16).to_socket_addrs() {
            Ok(addrs) => Ok(addrs.map(|sa| sa.ip()).collect()),
            Err(e) => Err(GuardError::ResolutionFailed {
                host: host.to_string(),
                reason: e.to_string(),
            }),
        }
    }
}

/// A fixed, in-memory resolver for tests: maps hostnames to canned addresses.
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    map: HashMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    /// Create an empty static resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a host -> addresses mapping. Host is matched case-insensitively.
    pub fn with(mut self, host: &str, addrs: &[IpAddr]) -> Self {
        self.map.insert(host.to_ascii_lowercase(), addrs.to_vec());
        self
    }
}

impl Resolver for StaticResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, GuardError> {
        match self.map.get(&host.to_ascii_lowercase()) {
            Some(addrs) => Ok(addrs.clone()),
            None => Err(GuardError::ResolutionFailed {
                host: host.to_string(),
                reason: "no such host (static resolver)".to_string(),
            }),
        }
    }
}
