# Contributing to Mycroft

Thanks for your interest in Mycroft — a terminal-native pentest engagement console.
This project favours **small, verifiable, auditable** changes over large clever ones.

## Ground rules (the invariants)

Mycroft has four non-negotiable invariants. A change that weakens any of them will
not be merged:

1. **No command reaches the network without passing the scope guard** — including
   AI-issued commands.
2. **Every executed command is persisted** — with timestamp, target, args, exit code,
   and captured output (blocked attempts are persisted too).
3. **The findings data model is the source of truth** — everything normalizes into it.
4. **Local-first** — no telemetry, no network call that sends engagement data off-box.

See [CLAUDE.md](CLAUDE.md) for the full engineering doctrine and
[docs/DECISIONS.md](docs/DECISIONS.md) for the decision log (append your rationale
there for any non-trivial choice).

## Development setup

```sh
# Requires a recent stable Rust toolchain (rustup)
git clone https://github.com/tejgokani/MYCROFT && cd MYCROFT
cargo build
cargo test --workspace
```

Optional runtime tools for a full experience: `nmap`, `nuclei` (tools you run
through Mycroft), and `typst` (for PDF reports).

## Before you open a PR

All of these must be clean — CI enforces them:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Standards:

- **No `unwrap()` / `expect()`** in non-test code except at proven-safe boundaries
  (comment why).
- **All external input is untrusted** — tool output, scope files, model output — and
  is parsed defensively.
- **Errors are actionable**: say what failed, on what target, and what to do.
- Every module exposes a documented public contract; code to contracts, not internals.
- Tests: unit per module plus, for the guard and parsers, adversarial / malformed-input
  cases. The scope guard is the highest-risk unit — new guard logic needs matching
  adversarial tests.

## Architecture at a glance

A Cargo workspace of small, single-purpose crates coding to shared contracts in
`mycroft-core`:

```
core · store · guard · runner · normalize · report · tui · cli (bin: mycroft)
```

Adding a **parser** for a new tool? Implement it in `mycroft-normalize` behind the
`normalize(tool, raw, hint) -> Vec<NormalizedFinding>` contract, add a golden-corpus
fixture under `fixtures/`, and (optionally) make the tool recognized in
`Tool::from_name` so it auto-normalizes on `run`.

## Commits & PRs

- Keep PRs focused and reviewable (no 800-line changes).
- Reference the phase/area in the subject line.
- Describe what you changed and how you verified it; note any invariant you touched.
- Security-sensitive changes (guard, runner, audit) get extra scrutiny — call them out.

## Reporting security issues

Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
