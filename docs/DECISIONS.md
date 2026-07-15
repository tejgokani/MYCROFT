# DECISIONS.md — Architecture Decision Log

Append-only. Every non-trivial choice + reason. Newest at top.

## Format
- **[YYYY-MM-DD] Decision** — context → choice → why → alternatives rejected.

## Phase 4 decisions (2026-07-15)
- **Three text formats + optional PDF, not a bundled compiler** — `report` always emits **Markdown** (primary, diffable), a **self-contained styled HTML** (printable to PDF from any browser, CSS inlined, light/dark aware, XSS-escaped), and a **typst `.typ` source**. A **PDF** is compiled only if a `typst` binary is on PATH. This honors the typst decision (we emit a real typst document) while **deferring** embedding the typst compiler + fonts into the binary — that dependency is heavy and version-fragile, and shelling out / printing HTML already yields a client-ready PDF. Recorded as a conscious v0 scope cut; embedding typst-as-lib is a clean later swap behind `mycroft_report::write`.
- **No `tera` templating in v0** — the report layout is fixed, so renderers build strings directly in Rust. Avoids a dependency and the `{{ }}`/typst-`#` escaping friction; revisit tera if user-customizable templates are added (v2 per-client/framework templates).
- **Report is read-only and self-attesting** — it re-runs the audit-chain verification and prints the result at the top; a failed chain produces a prominent warning in every format so a reader never trusts a tampered engagement. Tested (`tampered_audit_is_surfaced_in_report`).
- **Evidence appendix by command** — each artifact listed under its producing command with its SHA-256, giving chain-of-custody from finding → command → evidence hash in the deliverable itself.

## Phase 3 decisions (2026-07-15)
- **Tool-agnostic `NormalizedFinding` intermediate** — parsers emit `{title, severity, target, description}`; the store stamps engagement, source tool, and command linkage. Keeps every tool converging on the one findings model (invariant §3) and lets the runner and `import` share the identical insert path.
- **`roxmltree` for nmap XML** — a small, read-only, allocation-light DOM. New dependency recorded here. It does **not** resolve external entities, so enabling `allow_dtd` (nmap emits `<!DOCTYPE nmaprun>`) is XXE-safe by construction.
- **Defensive parsing posture** — line-oriented formats (nuclei JSONL) skip malformed records and continue; document formats (nmap XML) fail cleanly with an actionable error. Unrecognized severity strings map to `Info` rather than dropping the finding. Golden corpora in `fixtures/` include a deliberately-bad line and a closed port to lock this behavior.
- **Open ports are `Info` findings** — attack surface, not vulnerabilities; the operator triages upward. One finding per open (or open|filtered) port; closed ports are excluded.
- **Auto-normalize on `run`** — after an execution, recognized tool output (nmap/nuclei) is parsed from the captured stdout and inserted as findings linked to the producing command (`command_id`). Best-effort: non-machine output yields zero findings and a parse error never fails the run (evidence is already saved). This realizes the core promise: run a tool through Mycroft → findings appear.
- **`Tool::from_name` matches on basename** — so `/usr/bin/nmap` and `nmap` both resolve to `Nmap`, making auto-normalize robust to path-qualified invocations.
- **`import` shares the normalizer path** — `mycroft import --tool <t> <file>` inserts findings with no `command_id`; makes the parsers useful on pre-existing scan files and independently testable.

## Phase 2 decisions (2026-07-15)
- **Piped capture in v0, PTY deferred** — the runner captures stdout/stderr via pipes (`tokio::process`), which *is* the correct parse-and-evidence source (machine output, not tty-decorated text). True PTY allocation (`portable-pty`) — needed only for tools that alter behavior on a tty and for pixel-faithful live display — is deferred behind the `OutputSink` seam; adding it later changes no call sites. This honors the dual-capture decision's intent (don't parse PTY-colored text) while shipping Phase 2 sooner.
- **Exec by arg-vector, no shell** — `Command::new(program).args(args)` with `stdin` nulled; untrusted args are never interpolated into `sh -c`. Enforced in `capture::run_and_capture`.
- **Guard-before-exec is structural** — in `Runner::run`, a `GuardDecision::Block` returns before any spawn; there is no code path from a block to a process. Proven by the `blocked_target_never_executes` test (a `touch` sentinel is never created).
- **Concurrent read-to-EOF then wait** — stdout and stderr are drained via `tokio::select!` before awaiting exit, so a chatty child cannot deadlock on a full pipe.
- **Evidence layout** — `<db-stem>.evidence/cmd-<id>/{stdout,stderr}.log`, each content-addressed by sha256 and linked to the command; the `.evidence/` dir is git-ignored (local-first).
- **Command lifecycle audit events** — `command.started` → `command.completed` for executions, `command.blocked` for denials, `evidence.captured` per artifact; every attempt (executed or blocked) is a persisted `commands` row (invariant §2).
- **Both interception modes share one core** — `mycroft run -- <tool>` and the TUI runner pane both call the identical `Runner`; the TUI only swaps a `CollectingSink` for the `ConsoleSink`. TUI command input uses whitespace splitting in v0 (no shell quoting); spaced args go through `mycroft run --`.
- **`infer_target` shared helper** — target auto-detection lives in `mycroft-runner` and is used by both the CLI and TUI so detection can't drift between them.

## Phase 1 decisions (2026-07-15)
- **`ipnet` crate for CIDR math** — correct v4/v6 network containment (incl. bare-IP host routes) rather than hand-rolled bit masking → fewer edge-case bugs in the security-critical unit. New dependency recorded here.
- **std `ToSocketAddrs` resolver for v0, behind a `Resolver` trait** — zero extra deps; the trait lets us swap in a controlled resolver (timeouts, DoH, custom nameservers) later without touching decision logic. Deviation from the planned `hickory-resolver` (deferred to when we need resolver control). Tests inject a `StaticResolver` for determinism.
- **Guard decision semantics (documented contract)** — default-deny; exclusion (`out`) always wins over inclusion (`in`) regardless of rule order; CIDR matches by resolved address, Domain/URL match by name; `*.base` matches strict subdomains only (not the apex); a domain that resolves into an excluded CIDR is blocked (DNS-rebind defense); unresolvable host is blocked, never allowed.
- **`mycroft scope check <target>` is a non-persisting dry-run** — previews the guard verdict without executing anything; the persisting path is the runner (Phase 2), which logs every attempt including blocks.

## Phase 0 decisions (2026-07-15)
- **Guard is not a purely static function** — context: a domain resolves to an IP at exec time and tools follow redirects to other hosts → choice: keep `check(&ResolvedTarget, rules)` pure, but front it with a security-critical `resolve()` step and a redirect re-check hook (both land in Phase 1) → why: a static `check(target, rules)` cannot defend against DNS-rebind or redirect-to-out-of-scope → the core `Target`/`ResolvedTarget` split now encodes this. Rejected: trusting the raw target string.
- **Dual capture in the runner** — parse the tool's native machine format (`nmap -oX`, `nuclei -jsonl`); display/evidence from the PTY stream → why: PTY-colored text is the wrong thing to parse; machine output is stable. (Implemented Phase 2/3.)
- **Add `import`** — `mycroft import --tool <t> <file>` normalizes existing scan output → why: makes the normalizer testable against real corpora and useful before the runner exists. (Phase 3.)
- **typst over pandoc** — single self-contained binary, embeddable as a Rust crate → keeps one-command-install → rejected pandoc (drags in a LaTeX toolchain). (Phase 4.)
- **Hash-chained audit log** — append-only `audit_log` table, `hash = sha256(prev_hash || canonical(row))`, `mycroft verify` re-walks it → tamper-evident chain-of-custody for defensible reports. Implemented + tested in Phase 0 (tampering and deletion both detected).
- **Encryption at rest via SQLCipher** — off by default; `--features encryption` swaps rusqlite to `bundled-sqlcipher`; the `PRAGMA key` seam is inert on stock SQLite so the API (`Db::open_with_key`) is stable either way. (Seam wired Phase 0.)
- **Exec by arg-vector, never `sh -c`** — no shell interpolation of untrusted args. (Enforced Phase 2.)
- **Timestamps stored RFC3339 UTC** — timezone-independent, diffable engagement artifact.
- **Cargo workspace of small crates** — `core / store / guard / runner / normalize / report / tui / cli` — each a reviewable unit coding to `mycroft-core` contracts, matching the sub-agent doctrine.
- **Tiny embedded migration runner** keyed on `PRAGMA user_version` — rejected sqlx/refinery: no async or framework needed for forward-only per-engagement schemas.
- **Typed id newtypes** (`EngagementId`, `CommandId`, …) — compile-time defense against foreign-key mix-ups.

## Seed decisions
- **Rust over Go** — endgame correlation engine is CIPG (Rust); one codebase, no FFI seam. Rejected Go (faster v0) because v1 rewrite cost outweighs ~1wk saved.
- **TUI over GUI/web for v0** — survives SSH/jump boxes, fastest to build, matches operator workflow. Web dashboard deferred to v1 for graph/report views only.
- **Wrap Ollama for AI Mode** — auto-setup promise for days of work vs weeks building model infra; cross-platform. Rejected custom llama.cpp orchestration.
- **SQLite as source of truth** — portable per-engagement file, queryable for report + correlation, zero-config.
