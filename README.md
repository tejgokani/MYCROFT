# Mycroft

> The operating system for a pentest engagement — recon to report, one console.

Mycroft is a terminal-native **engagement console**. Define your scope once and the tool
guards it; run every tool *through* Mycroft and every command is auto-logged, timestamped,
and captured; all output normalizes into one findings database; and one command produces a
client-ready report with an evidence appendix. Local-first: client data never leaves the box.

## Status

**v0 MVP complete** — a real engagement runs end-to-end inside Mycroft, recon to report
(see [docs/ROADMAP.md](docs/ROADMAP.md)). 46 tests; `fmt` + `clippy -D warnings` clean.

| Phase | Unit | State |
|---|---|---|
| 0 | Workspace, schema, migrations, audit chain, `init` | ✅ done, tested |
| 1 | Scope manager + **guard** (parse / resolve / check) | ✅ done, tested |
| 2 | Command runner (guarded exec, capture, persist) + TUI runner pane | ✅ done, tested |
| 3 | Parsers (nmap, nuclei) → findings + `import` + auto-normalize on run | ✅ done, tested |
| 4 | Report (Markdown / HTML / typst → PDF) + evidence appendix | ✅ done, tested |

## Design invariants (non-negotiable)

1. **No command reaches the network without passing the scope guard** — including AI-issued ones.
2. **Every command attempt is persisted** — executions *and* blocks, with full context.
3. **The findings model is the source of truth** — everything normalizes into it.
4. **Local-first** — no telemetry, no phone-home.

The engagement DB additionally carries a **tamper-evident, hash-chained audit log**
(`mycroft verify`) and supports **encryption at rest** (SQLCipher, opt-in).

## Architecture

A Cargo workspace of small, single-purpose crates, each coding to shared contracts in
`mycroft-core`:

```
mycroft-core       shared domain types + errors (the contract surface)
mycroft-store      SQLite: schema, migrations, typed repos, audit chain, encryption seam
mycroft-guard      scope parse + resolve + check   [SECURITY-CRITICAL]
mycroft-runner     guarded exec, dual capture (machine output + PTY), persistence   (Phase 2)
mycroft-normalize  tool output -> findings (nmap, nuclei)                            (Phase 3)
mycroft-report     SQLite -> typst -> PDF + evidence appendix                        (Phase 4)
mycroft-tui        ratatui panes (scope / runner / findings)                         (Phase 2+)
mycroft-cli        the `mycroft` binary
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the decision log in
[docs/DECISIONS.md](docs/DECISIONS.md).

## Try it (what works today)

```sh
cargo build
BIN=target/debug/mycroft

# Start an engagement (creates ./mycroft.db + genesis audit entry)
$BIN init --name acme-external --client "ACME Corp"

# Define scope. Exclusions ("out") always win over inclusions.
$BIN scope add 10.0.0.0/24  --type cidr
$BIN scope add '*.acme.com'  --type domain
$BIN scope add 10.0.0.53      --kind out --type cidr

# Ask the guard for a verdict (dry-run; nothing is executed)
$BIN scope check 10.0.0.10        # ALLOW
$BIN scope check 10.0.0.53        # BLOCK  (excluded)
$BIN scope check 192.168.1.1      # BLOCK  (default deny)

# Run a tool THROUGH Mycroft: guard-checked, logged, output captured as evidence.
# In-scope -> executes and captures; out-of-scope -> hard-blocked, never runs.
$BIN scope add 127.0.0.0/8 --type cidr
$BIN run --target 127.0.0.1 -- nmap -sV 127.0.0.1
$BIN run --target 8.8.8.8   -- curl https://8.8.8.8   # BLOCKED (exit 3), never executes

# Output from a recognized tool (nmap -oX, nuclei -jsonl) auto-normalizes into
# findings, linked to the command that produced them. You can also import files:
$BIN import --tool nmap   scan.xml
$BIN import --tool nuclei findings.jsonl
$BIN findings                      # most severe first, all tools in one view

# See recorded commands (executions + blocked attempts), then the audit trail
$BIN commands
$BIN status
$BIN verify

# One client-ready report: Markdown + self-contained HTML + typst source (+ PDF if
# `typst` is installed), with a severity summary, command log, and evidence appendix.
$BIN report

# Or drive it interactively — the runner pane routes typed commands through the
# identical guarded path, with scope + history live alongside:
$BIN tui
```

The guard defends against DNS-rebind: a host that is in scope by name but currently resolves
into an excluded network is blocked. It fails closed — a name that cannot be resolved is
blocked, never allowed.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Both must be clean before any integration. The guard is the highest-risk unit and carries an
adversarial test suite (DNS-rebind, exclusion precedence, default-deny, IPv6, malformed rules).

## License

Apache-2.0.
