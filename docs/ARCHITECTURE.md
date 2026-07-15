# ARCHITECTURE.md — Mycroft

## System shape

```
┌──────────────────────────── Mycroft (single binary) ────────────────────────────┐
│                                                                                  │
│   TUI (ratatui)                                                                   │
│   ├─ Scope pane      ├─ Runner pane      ├─ Findings pane     ├─ AI pane (v1)     │
│                                                                                  │
│   Core                                                                            │
│   ├─ Scope Guard ──── validates every target before exec (SECURITY-CRITICAL)     │
│   ├─ Command Runner ─ tokio::process + PTY capture                               │
│   ├─ Normalizer ───── tool output → findings model (serde)                       │
│   ├─ Evidence ─────── captures output/screens, sha256, links to finding+command  │
│   ├─ Reporter ─────── SQLite → template → MD → PDF                               │
│   └─ AI Orchestrator (v1) ─ Ollama provision + agent loop (routes via Guard)     │
│                                                                                  │
│   Storage: SQLite (one file per engagement) ── source of truth                   │
└──────────────────────────────────────────────────────────────────────────────────┘
                                     │
                    external tools: nmap / nuclei / ffuf / httpx ...
```

## Critical path of a command
1. Operator (or AI) issues a command targeting `T`.
2. **Scope Guard** resolves `T` against `scope_rules`. Out-of-scope → hard block + logged attempt. In-scope → proceed.
3. **Runner** execs via PTY, streams stdout/stderr live into the Runner pane, buffers to disk.
4. On exit: `commands` row persisted (timings, exit code, output refs). Output stored as evidence (sha256).
5. **Normalizer** parses recognized tool output → `findings` rows, linked to the `command_id`.
6. Findings pane updates live from SQLite.

This path is identical whether the command comes from a human or from AI Mode. No alternate route exists. This is invariant.

## Module boundaries (contracts for sub-agents)
- **guard**: `fn check(target: &Target, rules: &[ScopeRule]) -> GuardDecision`. Pure, deterministic, exhaustively tested.
- **runner**: `async fn run(cmd: Command, sink: OutputSink) -> CommandRecord`. Never calls network directly; only execs after guard approval upstream.
- **normalizer**: `fn normalize(tool: Tool, raw: &[u8]) -> Vec<Finding>`. One impl per tool, defensive parsing.
- **reporter**: `fn render(engagement_id) -> Report`. Read-only over SQLite.
- **storage**: owns schema + migrations; exposes typed repositories, no raw SQL leaks into modules.

## Concurrency model
- TUI event loop on main; runner tasks on tokio; DB writes serialized through a single writer (SQLite WAL).
- Sub-agents build modules independently against the contracts above; integrator (Architect) wires them.

## Why these choices
- **SQLite single file** = portable per-engagement artifact; trivial backup/handoff; queryable for report + correlation.
- **PTY capture** = tools that behave differently on a tty (color, progress) still work; full fidelity evidence.
- **Guard as a pure function** = the security-critical unit is the most testable unit. By design.
- **Rust** = one codebase from console to the CIPG correlation engine in v1; no FFI seam.
