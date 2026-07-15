//! Adversarial-ish parsing tests for `Target::parse` (the untrusted-input boundary).

use std::net::IpAddr;

use mycroft_core::{CoreError, Target};

#[test]
fn parses_ipv4() {
    assert_eq!(
        Target::parse("10.0.0.5").unwrap(),
        Target::Ip("10.0.0.5".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn parses_ipv6_bare_and_bracketed() {
    let expected = Target::Ip("::1".parse::<IpAddr>().unwrap());
    assert_eq!(Target::parse("::1").unwrap(), expected);
    assert_eq!(Target::parse("[::1]:8080").unwrap(), expected);
    assert_eq!(Target::parse("http://[::1]:8080/path").unwrap(), expected);
}

#[test]
fn extracts_host_from_url() {
    assert_eq!(
        Target::parse("https://user:pass@example.com:443/a/b?q=1#frag").unwrap(),
        Target::Domain("example.com".to_string())
    );
}

#[test]
fn lowercases_hostnames() {
    assert_eq!(
        Target::parse("EXAMPLE.COM").unwrap(),
        Target::Domain("example.com".to_string())
    );
}

#[test]
fn strips_port_from_hostname() {
    assert_eq!(
        Target::parse("scanme.example.org:8080").unwrap(),
        Target::Domain("scanme.example.org".to_string())
    );
}

#[test]
fn allows_fqdn_trailing_dot() {
    assert_eq!(
        Target::parse("example.com.").unwrap(),
        Target::Domain("example.com".to_string())
    );
}

#[test]
fn rejects_empty() {
    assert!(matches!(
        Target::parse("   "),
        Err(CoreError::InvalidTarget { .. })
    ));
}

#[test]
fn rejects_consecutive_dots_and_bad_chars() {
    assert!(Target::parse("a..b.com").is_err());
    assert!(Target::parse("bad_host!.com").is_err());
    assert!(Target::parse("-leading.com").is_err());
}

#[test]
fn rejects_overlong_label() {
    let long = "a".repeat(64);
    assert!(Target::parse(&format!("{long}.com")).is_err());
}
