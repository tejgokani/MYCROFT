//! nmap XML (`nmap -oX`) → findings. One finding per open port.
//!
//! Open ports are recorded at `Info` severity: they are attack surface, not
//! vulnerabilities. The report and the operator triage them upward from there.

use mycroft_core::Severity;

use crate::{NormalizeError, NormalizedFinding};

pub(crate) fn parse(
    raw: &[u8],
    target_hint: Option<&str>,
) -> Result<Vec<NormalizedFinding>, NormalizeError> {
    let text = std::str::from_utf8(raw).map_err(|e| NormalizeError::Parse {
        tool: "nmap",
        detail: format!("output is not valid UTF-8: {e}"),
    })?;
    // nmap emits a `<!DOCTYPE nmaprun>`; allow the DTD declaration (we never resolve
    // external entities — roxmltree does not, which also avoids XXE by construction).
    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..roxmltree::ParsingOptions::default()
    };
    let doc =
        roxmltree::Document::parse_with_options(text, opts).map_err(|e| NormalizeError::Parse {
            tool: "nmap",
            detail: format!("invalid nmap XML: {e}"),
        })?;

    let mut findings = Vec::new();
    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let addr = host_address(host).or_else(|| target_hint.map(str::to_string));
        let hostname = host_name(host);
        let target = addr
            .clone()
            .or_else(|| hostname.clone())
            .unwrap_or_else(|| "unknown".to_string());

        for port in host.descendants().filter(|n| n.has_tag_name("port")) {
            // Only report ports nmap saw as open (or open|filtered).
            let state = port
                .children()
                .find(|n| n.has_tag_name("state"))
                .and_then(|n| n.attribute("state"))
                .unwrap_or("");
            if !state.starts_with("open") {
                continue;
            }
            let Some(portid) = port.attribute("portid") else {
                continue;
            };
            let proto = port.attribute("protocol").unwrap_or("tcp");

            let service = port.children().find(|n| n.has_tag_name("service"));
            let svc_name = service.and_then(|s| s.attribute("name")).unwrap_or("");
            let product = service.and_then(|s| s.attribute("product")).unwrap_or("");
            let version = service.and_then(|s| s.attribute("version")).unwrap_or("");

            let title = if svc_name.is_empty() {
                format!("Open port {portid}/{proto}")
            } else {
                format!("Open port {portid}/{proto} ({svc_name})")
            };

            let mut description = format!("nmap observed {portid}/{proto} open on {target}");
            if state != "open" {
                description.push_str(&format!(" (state: {state})"));
            }
            let banner = [product, version]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            if !banner.is_empty() {
                description.push_str(&format!("; service: {banner}"));
            } else if !svc_name.is_empty() {
                description.push_str(&format!("; service: {svc_name}"));
            }
            if let Some(h) = &hostname {
                description.push_str(&format!("; hostname: {h}"));
            }

            findings.push(NormalizedFinding {
                title,
                severity: Severity::Info,
                target: target.clone(),
                description,
            });
        }
    }
    Ok(findings)
}

/// Prefer an IP address; fall back to any address element.
fn host_address(host: roxmltree::Node) -> Option<String> {
    let addrs: Vec<roxmltree::Node> = host
        .children()
        .filter(|n| n.has_tag_name("address"))
        .collect();
    addrs
        .iter()
        .find(|n| {
            n.attribute("addrtype")
                .map(|t| t.starts_with("ipv"))
                .unwrap_or(false)
        })
        .or_else(|| addrs.first())
        .and_then(|n| n.attribute("addr"))
        .map(str::to_string)
}

fn host_name(host: roxmltree::Node) -> Option<String> {
    host.descendants()
        .find(|n| n.has_tag_name("hostname"))
        .and_then(|n| n.attribute("name"))
        .map(str::to_string)
}
