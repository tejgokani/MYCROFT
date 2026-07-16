# Releasing Mycroft

Three distribution channels, in order of how users get it:

1. **Prebuilt binaries** on GitHub Releases (most users) — automated by CI on tag.
2. **`curl … | sh`** installer — pulls those binaries.
3. **`cargo install mycroft`** (Rust users) — from crates.io.
4. **Homebrew** — from a tap that points at the release binaries.

## 1. Cut a release (prebuilt binaries)

Bump the version in `Cargo.toml` (`[workspace.package] version`), commit, then tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The [`release`](../.github/workflows/release.yml) workflow builds `mycroft` for every
target and attaches `mycroft-<target>.tar.gz` + `.sha256` to a GitHub Release:

| OS | Targets |
|---|---|
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| Linux | `x86_64-unknown-linux-musl` (static), `aarch64-unknown-linux-gnu` |
| Windows | `x86_64-pc-windows-msvc` (`.zip`) |

Asset names are **version-less** so `…/releases/latest/download/mycroft-<target>.tar.gz`
always resolves to the newest release (which the installer relies on).

## 2. The installer

`install.sh` needs no changes per release — it fetches `latest` by default and
verifies the published `.sha256`. Users run:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://raw.githubusercontent.com/tejgokani/MYCROFT/main/install.sh | sh
```

## 3. Publish to crates.io (`cargo install mycroft-cli`)

Publishing is **manual and irreversible** — it requires your crates.io token and is
not done by CI. The workspace is publish-ready (every internal dependency carries a
`version`). Publish **bottom-up** so each crate's dependencies already exist:

```sh
cargo login              # once, with your crates.io token
cargo publish -p mycroft-core
cargo publish -p mycroft-store
cargo publish -p mycroft-guard
cargo publish -p mycroft-normalize
cargo publish -p mycroft-runner
cargo publish -p mycroft-report
cargo publish -p mycroft-tui
cargo publish -p mycroft-cli     # the binary crate -> installs the `mycroft` binary
```

> **Name note:** the crate name `mycroft` is already taken on crates.io (an unrelated
> 2018 project), so the binary crate publishes as **`mycroft-cli`** and users run
> `cargo install mycroft-cli`. The installed executable is still `mycroft`.
>
> **New-crate rate limit:** crates.io throttles publishing *new* crate names (a small
> burst, then a cooldown of several hours). Publishing all eight at once will 429
> partway through with a "try again after <time>" message — just re-run the remaining
> `cargo publish` commands after that time. Already-published crates are skipped.

### Current publish state (v0.1.0)

Published: `mycroft-core`, `mycroft-store`, `mycroft-guard`, `mycroft-normalize`,
`mycroft-runner`. Remaining (blocked by the new-crate rate limit): `mycroft-report`,
`mycroft-tui`, `mycroft-cli` — publish these after the cooldown.

## 4. Homebrew tap

One-time: create a repo named **`homebrew-mycroft`** under your account.

Per release: copy [`packaging/homebrew/mycroft.rb`](../packaging/homebrew/mycroft.rb)
into the tap's `Formula/`, set `version`, and paste each target's SHA-256 (from the
release's `.sha256` assets). Users then:

```sh
brew install tejgokani/mycroft/mycroft
```

## Pre-release checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] version bumped in `Cargo.toml`
- [ ] `CHANGELOG`/release notes drafted (GitHub can auto-generate from commits)
