<div align="center">

# Mycroft

**The operating system for a pentest engagement — recon to report, one console.**

[![CI](https://github.com/tejgokani/MYCROFT/actions/workflows/ci.yml/badge.svg)](https://github.com/tejgokani/MYCROFT/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![Local-first](https://img.shields.io/badge/local--first-no%20telemetry-brightgreen.svg)](#design-invariants)

</div>

Mycroft replaces the usual engagement chaos — 12 terminals, a notes file, a screenshots
folder, and a findings spreadsheet — with **one terminal-native console**. Define your
scope once and Mycroft guards it. Run every tool *through* Mycroft and every command is
scope-checked, logged, timestamped, and its output captured as hashed evidence. All of it
normalizes into a single findings database, and one command turns that into a client-ready
report with an evidence appendix.

**Local-first by design:** client data never leaves the box. No telemetry, no phone-home.

---

## Highlights

- 🛡️ **Scope guard you can't accidentally bypass.** Every command — human *or* AI-issued —
  is checked before it touches the network. Default-deny, exclusions win, DNS-rebind aware
  (a host that resolves into an excluded network is blocked), and it fails closed.
- 🧾 **Everything is logged.** Executions *and* blocked attempts are persisted with target,
  args, exit code, timing, and captured stdout/stderr — deconfliction and an audit trail for free.
- 🔗 **Tamper-evident audit chain.** A hash-chained log means editing or deleting any
  recorded action is detectable with `mycroft verify` — defensible chain-of-custody.
- 🧩 **One findings model.** nmap and nuclei output normalize into the same database; run a
  tool through Mycroft and findings appear automatically, linked to the command that produced them.
- 📎 **Evidence that attaches itself.** Output is content-addressed by SHA-256 and linked to
  its finding and command.
- 📄 **One-command reporting.** Markdown + self-contained HTML + typst source (and PDF when
  `typst` is present), with a severity summary, command log, and evidence appendix.
- 🔒 **Encryption at rest** (SQLCipher, opt-in) and a single portable SQLite file per engagement.
- 🖥️ **Two ways to drive it:** a scriptable CLI (`mycroft run -- …`) and an interactive
  ratatui **runner pane** — both on the identical guarded path.

## Demo

![Mycroft demo](docs/demo.gif)

Scripted as a [VHS](https://github.com/charmbracelet/vhs) tape at
[`docs/demo.tape`](docs/demo.tape); regenerate with `vhs docs/demo.tape`.

## Install

Mycroft is a single ~4 MB binary (`mycroft`). It's an **orchestrator** — it runs your
existing tools (`nmap`, `nuclei`, …) *through* its guard and logger, so install those
separately for whatever you scan. `typst` is optional, for PDF reports.

**From source** (needs a recent [Rust](https://rustup.rs) toolchain — works today):

```sh
cargo install --git https://github.com/tejgokani/MYCROFT mycroft
# or clone and build
git clone https://github.com/tejgokani/MYCROFT && cd MYCROFT && cargo build --release
```

**Prebuilt binaries & package managers** (from the first tagged release):

```sh
# One-line installer (macOS / Linux) — downloads + checksum-verifies a prebuilt binary
curl --proto '=https' --tlsv1.2 -LsSf \
  https://raw.githubusercontent.com/tejgokani/MYCROFT/main/install.sh | sh

brew install tejgokani/mycroft/mycroft   # Homebrew
cargo install mycroft                     # crates.io
```

Prebuilt archives for macOS (arm64/x64), Linux (x64/arm64), and Windows are attached to
each [release](https://github.com/tejgokani/MYCROFT/releases). See
[docs/RELEASING.md](docs/RELEASING.md) for how releases are cut.

## Quickstart

```sh
# 1. Start an engagement (creates ./mycroft.db + a genesis audit entry)
mycroft init --name acme-q3 --client "ACME Corp"

# 2. Define scope once. Exclusions ("out") always win over inclusions.
mycroft scope add 10.0.0.0/24 --type cidr
mycroft scope add 10.0.0.53   --kind out --type cidr
mycroft scope check 10.0.0.10          # ALLOW   (dry-run verdict)
mycroft scope check 10.0.0.53          # BLOCK   (excluded)

# 3. Run tools THROUGH Mycroft: guard-checked, logged, output captured & normalized.
mycroft run --target 10.0.0.5 -- nmap -sV -oX - 10.0.0.5
mycroft run --target 8.8.8.8  -- curl https://8.8.8.8    # BLOCKED (exit 3) — never runs

# 4. Or ingest scans you already have.
mycroft import --tool nuclei findings.jsonl

# 5. Review, report, and verify the audit trail.
mycroft findings          # most severe first, every tool in one view
mycroft report            # Markdown + HTML + typst (+ PDF if typst is installed)
mycroft verify            # is the tamper-evident audit chain intact?

# Prefer it interactive?
mycroft tui               # runner pane: scope + history live, same guarded path
```

## How it works

Every command follows exactly one path — there is no alternate route, and AI Mode (v1)
will inherit it unchanged:

```
issue command ─▶ Scope Guard ─▶ (block → logged attempt, no network)
                     │
                     └▶ allow ─▶ Runner (arg-vector exec, no shell)
                                    │  live output ─▶ terminal / TUI pane
                                    └▶ capture ─▶ sha256 evidence ─▶ SQLite
                                                    │
                                                    └▶ Normalizer ─▶ findings
```

The scope guard is a **pure function** over a *resolved* target, kept deliberately small and
exhaustively tested, with resolution (DNS) as a separate security-critical step in front of
it. The findings database is the single source of truth; the reporter is read-only over it
and re-verifies the audit chain so a reader can trust the output.

## Architecture

A Cargo workspace of eight small, single-purpose crates, each coding to shared contracts in
`mycroft-core`:

```
mycroft-core       shared domain types + error taxonomy (the contract surface)
mycroft-store      SQLite: schema, migrations, typed repos, audit chain, encryption seam
mycroft-guard      scope parse + resolve + check          [security-critical]
mycroft-runner     guarded exec, capture, sha256 evidence, persistence
mycroft-normalize  tool output → findings (nmap, nuclei)
mycroft-report     SQLite → Markdown / HTML / typst → PDF + evidence appendix
mycroft-tui        ratatui runner pane (scope · runner · history)
mycroft            the CLI binary
```

More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); every non-trivial decision is
logged in [docs/DECISIONS.md](docs/DECISIONS.md).

## Design invariants

These four properties are non-negotiable; the codebase and its tests are built to enforce them:

1. **No command reaches the network without passing the scope guard** — including AI-issued ones.
2. **Every command attempt is persisted** — executions *and* blocks, with full context.
3. **The findings model is the source of truth** — everything normalizes into it.
4. **Local-first** — no telemetry, no network call that sends engagement data off-box.

## Roadmap

Mycroft's core (define scope → run guarded → normalize → report) is complete and tested
(eight crates, 46 tests, `fmt` + `clippy -D warnings` clean). What's next:

**Shipping v0.1 (operational)**
- [ ] Cut the first tagged release (publishes prebuilt binaries; enables `curl | sh`)
- [ ] Publish to crates.io (`cargo install mycroft`)
- [ ] Create the Homebrew tap and fill in per-release checksums
- [ ] Record and embed the demo GIF

**v1 — differentiators**
- [ ] Recon orchestration chain (subdomains → resolve → ports → http → nuclei)
- [ ] **AI Mode** — a local LLM assistant (Ollama wrapper) that proposes commands through
      the same guard + logger; propose-then-approve by default (see [docs/AI_MODE.md](docs/AI_MODE.md))
- [ ] More parsers: httpx, ffuf, nessus, burp
- [ ] Correlation / attack-narrative view (web dashboard over the same SQLite)
- [ ] True PTY capture for tools that alter behavior on a tty
- [ ] Embedded typst compiler for single-binary PDF (no external `typst` needed)

**v2 — team & scale**
- [ ] Multi-operator engagements (server-backed)
- [ ] Live deconfliction feed for blue teams
- [ ] Report templates per client / framework (OWASP, PTES)

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). In short: `cargo fmt`,
`cargo clippy -- -D warnings`, and `cargo test --workspace` must be clean, changes stay small
and reviewable, and anything touching the guard, runner, or audit log gets extra scrutiny.

## Security

Mycroft is offensive-security tooling for **authorized** engagements only. To report a
vulnerability, see [SECURITY.md](SECURITY.md) — please do not open a public issue.

## License

[Apache-2.0](LICENSE).
