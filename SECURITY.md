# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
vulnerability.

- Preferred: open a [GitHub private security advisory](https://github.com/tejgokani/MYCROFT/security/advisories/new).
- Or email the maintainer: **tejmgokani@gmail.com** with `SECURITY` in the subject.

Please include:

- affected version / commit,
- a description and impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage. Please give us a reasonable window to fix an issue before
any public disclosure. We are happy to credit reporters in the release notes.

## What we consider highest-severity

Mycroft's value rests on a small set of invariants; a break in any of these is a
**critical** report:

1. **Scope-guard bypass** — any way to make a command (human- or AI-issued) reach
   the network for a target the scope guard would block. This includes DNS-rebind,
   redirect-following, resolution races, and parser tricks.
2. **Audit-log forgery** — altering a recorded command, finding, or piece of
   evidence without `mycroft verify` detecting it (a break in the hash chain's
   tamper-evidence).
3. **Command injection** — reaching a shell or interpolating untrusted arguments so
   that something other than the intended arg-vector executes.
4. **Data exfiltration** — any code path that sends engagement data off the box
   (Mycroft is local-first: no telemetry, no phone-home).

## Supported versions

Mycroft is pre-1.0. Security fixes land on `main` and in the latest release. Older
tagged releases are not maintained.

| Version | Supported |
|---|---|
| `main` / latest release | ✅ |
| older tags | ❌ |

## Responsible use

Mycroft is offensive-security tooling intended for **authorized** penetration
testing and VAPT engagements. Only use it against systems you own or have explicit,
written permission to test. The scope guard is a safety aid, not a legal
authorization — you are responsible for operating within your engagement's scope
and applicable law.
