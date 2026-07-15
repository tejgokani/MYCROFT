# ROADMAP.md — Mycroft

## v0 — MVP (~1 month, ship end-to-end)
| Phase | Deliverable | Sub-agents (parallel) |
|---|---|---|
| 0 | Repo skeleton, CI, schema, migrations, `mycroft init` | schema-agent, tui-agent |
| 1 | Scope manager + Guard (double-reviewed) | guard-agent + review-agent |
| 2 | Command runner + logger (PTY capture, persist) | runner-agent |
| 3 | nuclei + nmap parsers → findings normalization | 2x parser-agent |
| 4 | Report export (MD → PDF) + evidence linking | report-agent |

**v0 gate:** run a real engagement start→report inside Mycroft.

## v1 — Differentiators
- Recon orchestration chain (subs → resolve → ports → http → nuclei).
- Correlation / attack-narrative view (web dashboard over same SQLite; CIPG tie-in).
- AI Mode (see AI_MODE.md).
- Parsers: ffuf, httpx, nessus, burp.

## v2 — Team / scale
- Multi-operator engagements (server-backed).
- Live deconfliction feed for blue team.
- Report templates per client / framework (OWASP, PTES).

## Launch checklist (OSS)
- Killer README + demo GIF (init → run → report).
- One-command install.
- LICENSE, SECURITY.md, CONTRIBUTING.md.
- Sample engagement dataset for reviewers.
