//! Markdown renderer — the primary, always-available report format.

use std::fmt::Write;

use crate::data::ReportData;
use crate::util::fmt_ts;

pub fn render(d: &ReportData) -> String {
    let mut s = String::new();
    let e = &d.engagement;

    let _ = writeln!(s, "# Engagement Report — {}", e.name);
    let _ = writeln!(s);
    let _ = writeln!(s, "**Client:** {}  ", e.client);
    let _ = writeln!(s, "**Engagement:** {} (status: {})  ", e.name, e.status);
    let _ = writeln!(s, "**Generated:** {}  ", fmt_ts(d.generated_at));
    let _ = writeln!(
        s,
        "**Audit chain:** {}",
        if d.audit_ok {
            "✅ intact (tamper-evident)"
        } else {
            "⚠️ VERIFICATION FAILED — see below"
        }
    );
    let _ = writeln!(s);

    // Executive summary
    let _ = writeln!(s, "## Summary");
    let _ = writeln!(s);
    let _ = writeln!(s, "| Severity | Count |");
    let _ = writeln!(s, "|---|---|");
    for (sev, n) in d.severity_counts() {
        let _ = writeln!(s, "| {} | {} |", sev.to_string().to_uppercase(), n);
    }
    let _ = writeln!(s, "| **Total findings** | **{}** |", d.findings.len());
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "{} commands executed or attempted; {} scope rules defined.",
        d.commands.len(),
        d.scope_rules.len()
    );
    let _ = writeln!(s);

    // Scope
    let _ = writeln!(s, "## Scope");
    let _ = writeln!(s);
    if d.scope_rules.is_empty() {
        let _ = writeln!(s, "_No scope rules were defined._");
    } else {
        let _ = writeln!(s, "| Disposition | Type | Pattern |");
        let _ = writeln!(s, "|---|---|---|");
        for r in &d.scope_rules {
            let _ = writeln!(
                s,
                "| {} | {} | `{}` |",
                if r.kind == mycroft_core::ScopeKind::Out {
                    "OUT (excluded)"
                } else {
                    "IN"
                },
                r.rule_type,
                r.pattern
            );
        }
    }
    let _ = writeln!(s);

    // Findings
    let _ = writeln!(s, "## Findings");
    let _ = writeln!(s);
    if d.findings.is_empty() {
        let _ = writeln!(s, "_No findings recorded._");
    } else {
        for f in &d.findings {
            let _ = writeln!(
                s,
                "### [{}] {}",
                f.severity.to_string().to_uppercase(),
                f.title
            );
            let _ = writeln!(s);
            let _ = writeln!(s, "- **Target:** `{}`", f.target);
            let _ = writeln!(s, "- **Source tool:** {}", f.source_tool);
            let _ = writeln!(s, "- **Status:** {}", f.status);
            if let Some(cmd) = d.command_for(f.command_id) {
                let _ = writeln!(
                    s,
                    "- **Produced by:** command #{} — `{}`",
                    cmd.id, cmd.raw_cmd
                );
            }
            let _ = writeln!(s);
            for line in f.description.lines() {
                let _ = writeln!(s, "> {line}");
            }
            let _ = writeln!(s);
        }
    }

    // Command log
    let _ = writeln!(s, "## Command Log");
    let _ = writeln!(s);
    if d.commands.is_empty() {
        let _ = writeln!(s, "_No commands recorded._");
    } else {
        let _ = writeln!(s, "| # | Issued | Status | Target | Command |");
        let _ = writeln!(s, "|---|---|---|---|---|");
        for c in &d.commands {
            let status = if c.blocked {
                "BLOCKED".to_string()
            } else {
                format!(
                    "exit {}",
                    c.exit_code.map(|x| x.to_string()).unwrap_or_default()
                )
            };
            let _ = writeln!(
                s,
                "| {} | {} | {} | `{}` | `{}` |",
                c.id,
                c.issued_by,
                status,
                c.target,
                c.raw_cmd.replace('|', "\\|")
            );
        }
    }
    let _ = writeln!(s);

    // Evidence appendix
    let _ = writeln!(s, "## Evidence Appendix");
    let _ = writeln!(s);
    if d.evidence.is_empty() {
        let _ = writeln!(s, "_No evidence captured._");
    } else {
        let _ = writeln!(
            s,
            "Each artifact is content-addressed by SHA-256 for chain-of-custody."
        );
        let _ = writeln!(s);
        for c in &d.commands {
            if let Some(items) = d.evidence.get(&c.id.get()) {
                let _ = writeln!(s, "**Command #{} — `{}`**", c.id, c.raw_cmd);
                let _ = writeln!(s);
                for ev in items {
                    let _ = writeln!(s, "- `{}` ({})  ", ev.path, ev.kind);
                    let _ = writeln!(s, "  `sha256:{}`", ev.sha256);
                }
                let _ = writeln!(s);
            }
        }
    }

    if !d.audit_ok {
        let _ = writeln!(s, "## ⚠️ Audit Chain Warning");
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "The tamper-evident audit chain did **not** verify: {}",
            d.audit_error.as_deref().unwrap_or("unknown error")
        );
        let _ = writeln!(
            s,
            "\nThis report may not faithfully reflect the recorded engagement."
        );
    }

    s
}
