# Changelog

All notable changes to micro-notify are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Release
tags are `vX.Y.Z` and every release ships a source tarball asset that the Homebrew
tap formula pins by `sha256` (see `packaging/README.md`).

## [Unreleased]

## [0.1.0] - 2026-11-02

First public release.

### Added

- `mnotify mail send` — email from one scoped Microsoft 365 mailbox through
  Microsoft Graph app-only auth (certificate preferred, client secret as
  fallback), with `--dry-run`, `--json`, attachments up to the configured cap.
- `mnotify teams send` — Teams channel posts and 1:1 DMs through Workflows
  webhook targets stored in the macOS keychain.
- Guardrails evaluated before any network call: recipient allowlist, recipient
  count, daily cap, attachment size (design §3.3). A refusal exits 3 and sends
  nothing.
- JSONL audit log with no message bodies and no secrets (`mnotify log`).
- `mnotify setup`, `mnotify doctor`, `mnotify config show` with secret masking
  and locally generated authentication certificates.
- Homebrew tap packaging: `packaging/Formula/micro-notify.rb.tmpl` (a Python
  virtualenv formula with its dependency closure pinned) and
  `scripts/release.py`, which hashes the release tarball, renders the formula
  into a local tap checkout and prints — without running — the tag, release and
  tap-commit commands.
- `docs/ADMIN-SETUP.md`: the one-time tenant steps, including the Exchange
  Online application-RBAC scoping that keeps the app registration able to send
  as exactly one mailbox.

### Known limits in v1

- macOS only for the keychain; no mail reading; no templating engine;
  attachments capped at 3 MB total. See the "What is NOT supported" section of
  the README.
