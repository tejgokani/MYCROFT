//! typst source renderer. Emitting a `.typ` document keeps the typst decision intact
//! (single-binary PDF once the compiler is embedded or `typst` is on PATH) without
//! taking a heavy, version-fragile compiler dependency into v0.

use std::fmt::Write;

use crate::data::ReportData;
use crate::util::{fmt_ts, typst_escape as t};

pub fn render(d: &ReportData) -> String {
    let e = &d.engagement;
    let mut s = String::new();

    let _ = writeln!(
        s,
        "#set document(title: \"Mycroft Report — {}\", author: \"Mycroft\")",
        t(&e.name)
    );
    let _ = writeln!(s, "#set page(paper: \"a4\", margin: 2cm, numbering: \"1\")");
    let _ = writeln!(s, "#set text(size: 10pt)");
    let _ = writeln!(s, "#set heading(numbering: none)");
    let _ = writeln!(s);
    let _ = writeln!(s, "#align(center)[");
    let _ = writeln!(
        s,
        "  #text(size: 20pt, weight: \"bold\")[Engagement Report] \\"
    );
    let _ = writeln!(
        s,
        "  #text(size: 13pt)[{} · {}] \\",
        t(&e.name),
        t(&e.client)
    );
    let _ = writeln!(
        s,
        "  #text(size: 9pt, fill: gray)[Generated {} · Status: {}]",
        t(&fmt_ts(d.generated_at)),
        t(&e.status.to_string())
    );
    let _ = writeln!(s, "]");
    let _ = writeln!(s);
    if d.audit_ok {
        let _ = writeln!(
            s,
            "#align(center)[#text(fill: green)[*Audit chain intact (tamper-evident)*]]"
        );
    } else {
        let _ = writeln!(
            s,
            "#align(center)[#text(fill: red)[*Audit chain verification FAILED: {}*]]",
            t(d.audit_error.as_deref().unwrap_or("unknown"))
        );
    }
    let _ = writeln!(s, "#line(length: 100%, stroke: 0.5pt + gray)");
    let _ = writeln!(s);

    // Summary
    let _ = writeln!(s, "= Summary");
    let _ = writeln!(s, "#table(columns: 2, align: (left, right),");
    let _ = writeln!(s, "  [*Severity*], [*Count*],");
    for (sev, n) in d.severity_counts() {
        let _ = writeln!(s, "  [{}], [{}],", sev.to_string().to_uppercase(), n);
    }
    let _ = writeln!(s, "  [*Total*], [*{}*],", d.findings.len());
    let _ = writeln!(s, ")");
    let _ = writeln!(
        s,
        "{} commands · {} scope rules.",
        d.commands.len(),
        d.scope_rules.len()
    );
    let _ = writeln!(s);

    // Scope
    let _ = writeln!(s, "= Scope");
    if d.scope_rules.is_empty() {
        let _ = writeln!(s, "_No scope rules were defined._");
    } else {
        let _ = writeln!(s, "#table(columns: 3,");
        let _ = writeln!(s, "  [*Disposition*], [*Type*], [*Pattern*],");
        for r in &d.scope_rules {
            let disp = if r.kind == mycroft_core::ScopeKind::Out {
                "OUT (excluded)"
            } else {
                "IN"
            };
            let _ = writeln!(
                s,
                "  [{}], [{}], [`{}`],",
                disp,
                t(&r.rule_type.to_string()),
                t(&r.pattern)
            );
        }
        let _ = writeln!(s, ")");
    }
    let _ = writeln!(s);

    // Findings
    let _ = writeln!(s, "= Findings");
    if d.findings.is_empty() {
        let _ = writeln!(s, "_No findings recorded._");
    } else {
        for f in &d.findings {
            let _ = writeln!(
                s,
                "== [{}] {}",
                f.severity.to_string().to_uppercase(),
                t(&f.title)
            );
            let _ = writeln!(s, "- *Target:* `{}`", t(&f.target));
            let _ = writeln!(s, "- *Source tool:* {}", t(&f.source_tool.to_string()));
            let _ = writeln!(s, "- *Status:* {}", t(&f.status.to_string()));
            if let Some(cmd) = d.command_for(f.command_id) {
                let _ = writeln!(
                    s,
                    "- *Produced by:* command \\#{} — `{}`",
                    cmd.id,
                    t(&cmd.raw_cmd)
                );
            }
            let _ = writeln!(s, "#quote(block: true)[{}]", t(&f.description));
            let _ = writeln!(s);
        }
    }

    // Command log
    let _ = writeln!(s, "= Command Log");
    if d.commands.is_empty() {
        let _ = writeln!(s, "_No commands recorded._");
    } else {
        let _ = writeln!(s, "#table(columns: 5,");
        let _ = writeln!(
            s,
            "  [*\\#*], [*Issued*], [*Status*], [*Target*], [*Command*],"
        );
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
                "  [{}], [{}], [{}], [`{}`], [`{}`],",
                c.id,
                t(&c.issued_by.to_string()),
                status,
                t(&c.target),
                t(&c.raw_cmd)
            );
        }
        let _ = writeln!(s, ")");
    }
    let _ = writeln!(s);

    // Evidence appendix
    let _ = writeln!(s, "= Evidence Appendix");
    if d.evidence.is_empty() {
        let _ = writeln!(s, "_No evidence captured._");
    } else {
        let _ = writeln!(
            s,
            "Each artifact is content-addressed by SHA-256 for chain-of-custody."
        );
        for c in &d.commands {
            if let Some(items) = d.evidence.get(&c.id.get()) {
                let _ = writeln!(s, "*Command \\#{}* — `{}`", c.id, t(&c.raw_cmd));
                for ev in items {
                    let _ = writeln!(
                        s,
                        "- `{}` ({}) \\ #text(size: 8pt, fill: gray)[`sha256:{}`]",
                        t(&ev.path),
                        t(&ev.kind.to_string()),
                        t(&ev.sha256)
                    );
                }
            }
        }
    }

    s
}
