//! Self-contained HTML renderer — styled and printable to PDF from any browser.

use std::fmt::Write;

use mycroft_core::Severity;

use crate::data::ReportData;
use crate::util::{fmt_ts, html_escape as h};

fn severity_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "#b00020",
        Severity::High => "#e65100",
        Severity::Medium => "#f9a825",
        Severity::Low => "#2e7d32",
        Severity::Info => "#546e7a",
    }
}

pub fn render(d: &ReportData) -> String {
    let e = &d.engagement;
    let mut s = String::new();

    let _ = write!(
        s,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Mycroft Report — {name}</title><style>{css}</style></head><body>",
        name = h(&e.name),
        css = CSS
    );

    // Header
    let _ = write!(
        s,
        "<header><h1>Engagement Report</h1>\
<p class=\"sub\">{name} · {client}</p>\
<p class=\"meta\">Generated {gen} · Status: {status}</p>{audit}</header>",
        name = h(&e.name),
        client = h(&e.client),
        gen = h(&fmt_ts(d.generated_at)),
        status = h(&e.status.to_string()),
        audit = if d.audit_ok {
            "<p class=\"audit ok\">Audit chain intact (tamper-evident)</p>".to_string()
        } else {
            format!(
                "<p class=\"audit bad\">Audit chain verification FAILED: {}</p>",
                h(d.audit_error.as_deref().unwrap_or("unknown"))
            )
        }
    );

    // Summary
    let _ = write!(s, "<section><h2>Summary</h2><div class=\"badges\">");
    for (sev, n) in d.severity_counts() {
        let _ = write!(
            s,
            "<span class=\"badge\" style=\"background:{col}\">{label}: {n}</span>",
            col = severity_color(sev),
            label = sev.to_string().to_uppercase(),
        );
    }
    let _ = write!(
        s,
        "</div><p>{total} total findings · {cmds} commands · {rules} scope rules.</p></section>",
        total = d.findings.len(),
        cmds = d.commands.len(),
        rules = d.scope_rules.len()
    );

    // Scope
    let _ = write!(s, "<section><h2>Scope</h2>");
    if d.scope_rules.is_empty() {
        let _ = write!(s, "<p class=\"empty\">No scope rules were defined.</p>");
    } else {
        let _ = write!(
            s,
            "<table><tr><th>Disposition</th><th>Type</th><th>Pattern</th></tr>"
        );
        for r in &d.scope_rules {
            let out = r.kind == mycroft_core::ScopeKind::Out;
            let _ = write!(
                s,
                "<tr><td>{disp}</td><td>{ty}</td><td><code>{pat}</code></td></tr>",
                disp = if out { "OUT (excluded)" } else { "IN" },
                ty = h(&r.rule_type.to_string()),
                pat = h(&r.pattern),
            );
        }
        let _ = write!(s, "</table>");
    }
    let _ = write!(s, "</section>");

    // Findings
    let _ = write!(s, "<section><h2>Findings</h2>");
    if d.findings.is_empty() {
        let _ = write!(s, "<p class=\"empty\">No findings recorded.</p>");
    } else {
        for f in &d.findings {
            let _ = write!(
                s,
                "<div class=\"finding\"><h3><span class=\"chip\" style=\"background:{col}\">{sev}</span> {title}</h3>\
<ul class=\"kv\"><li><b>Target:</b> <code>{target}</code></li>\
<li><b>Source:</b> {tool}</li><li><b>Status:</b> {status}</li>",
                col = severity_color(f.severity),
                sev = f.severity.to_string().to_uppercase(),
                title = h(&f.title),
                target = h(&f.target),
                tool = h(&f.source_tool.to_string()),
                status = h(&f.status.to_string()),
            );
            if let Some(cmd) = d.command_for(f.command_id) {
                let _ = write!(
                    s,
                    "<li><b>Produced by:</b> command #{id} — <code>{raw}</code></li>",
                    id = cmd.id,
                    raw = h(&cmd.raw_cmd)
                );
            }
            let _ = write!(
                s,
                "</ul><pre class=\"desc\">{}</pre></div>",
                h(&f.description)
            );
        }
    }
    let _ = write!(s, "</section>");

    // Command log
    let _ = write!(s, "<section><h2>Command Log</h2>");
    if d.commands.is_empty() {
        let _ = write!(s, "<p class=\"empty\">No commands recorded.</p>");
    } else {
        let _ = write!(
            s,
            "<table><tr><th>#</th><th>Issued</th><th>Status</th><th>Target</th><th>Command</th></tr>"
        );
        for c in &d.commands {
            let (status, cls) = if c.blocked {
                ("BLOCKED".to_string(), "st-block")
            } else {
                (
                    format!(
                        "exit {}",
                        c.exit_code.map(|x| x.to_string()).unwrap_or_default()
                    ),
                    "st-ok",
                )
            };
            let _ = write!(
                s,
                "<tr><td>{id}</td><td>{by}</td><td class=\"{cls}\">{status}</td>\
<td><code>{target}</code></td><td><code>{raw}</code></td></tr>",
                id = c.id,
                by = h(&c.issued_by.to_string()),
                target = h(&c.target),
                raw = h(&c.raw_cmd),
            );
        }
        let _ = write!(s, "</table>");
    }
    let _ = write!(s, "</section>");

    // Evidence appendix
    let _ = write!(s, "<section><h2>Evidence Appendix</h2>");
    if d.evidence.is_empty() {
        let _ = write!(s, "<p class=\"empty\">No evidence captured.</p>");
    } else {
        let _ = write!(
            s,
            "<p>Each artifact is content-addressed by SHA-256 for chain-of-custody.</p>"
        );
        for c in &d.commands {
            if let Some(items) = d.evidence.get(&c.id.get()) {
                let _ = write!(
                    s,
                    "<div class=\"evidence\"><b>Command #{id}</b> — <code>{raw}</code><ul>",
                    id = c.id,
                    raw = h(&c.raw_cmd)
                );
                for ev in items {
                    let _ = write!(
                        s,
                        "<li><code>{path}</code> ({kind})<br><span class=\"hash\">sha256:{hash}</span></li>",
                        path = h(&ev.path),
                        kind = h(&ev.kind.to_string()),
                        hash = h(&ev.sha256),
                    );
                }
                let _ = write!(s, "</ul></div>");
            }
        }
    }
    let _ = write!(s, "</section>");

    let _ = write!(
        s,
        "<footer>Generated by Mycroft · local-first engagement console</footer></body></html>"
    );
    s
}

const CSS: &str = r#"
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0 auto; max-width: 900px; padding: 2rem; line-height: 1.5; color: #1a1a1a; }
header { border-bottom: 3px solid #00838f; padding-bottom: 1rem; margin-bottom: 1.5rem; }
h1 { margin: 0; font-size: 1.9rem; }
h2 { border-bottom: 1px solid #ddd; padding-bottom: .3rem; margin-top: 2rem; }
h3 { margin-bottom: .3rem; }
.sub { font-size: 1.1rem; color: #00838f; font-weight: 600; margin: .2rem 0; }
.meta { color: #666; margin: .2rem 0; }
.audit { font-weight: 600; }
.audit.ok { color: #2e7d32; } .audit.bad { color: #b00020; }
.badges { display: flex; flex-wrap: wrap; gap: .5rem; margin: .5rem 0 1rem; }
.badge { color: #fff; padding: .25rem .6rem; border-radius: 4px; font-size: .85rem; font-weight: 600; }
.chip { color: #fff; padding: .1rem .45rem; border-radius: 4px; font-size: .75rem; vertical-align: middle; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; font-size: .9rem; }
th, td { border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; vertical-align: top; }
th { background: #f5f5f5; }
code { background: #f0f0f0; padding: .1rem .3rem; border-radius: 3px; font-size: .85em; word-break: break-all; }
.finding { border-left: 4px solid #00838f; padding: .3rem 0 .3rem 1rem; margin: 1rem 0; }
.kv { list-style: none; padding: 0; margin: .3rem 0; }
.kv li { margin: .15rem 0; }
.desc { background: #fafafa; border: 1px solid #eee; padding: .6rem; white-space: pre-wrap; border-radius: 4px; }
.st-block { color: #b00020; font-weight: 600; } .st-ok { color: #2e7d32; }
.evidence { margin: .6rem 0; }
.hash { font-family: monospace; font-size: .8rem; color: #555; }
.empty { color: #888; font-style: italic; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd; color: #888; font-size: .85rem; }
@media (prefers-color-scheme: dark) {
  body { background: #1a1a1a; color: #e0e0e0; }
  th { background: #2a2a2a; } th, td { border-color: #444; }
  code, .desc { background: #2a2a2a; } .desc { border-color: #444; }
  .meta, .hash { color: #aaa; }
}
@media print { body { max-width: none; padding: 0; } .finding { break-inside: avoid; } }
"#;
