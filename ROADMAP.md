# micro-notify — roadmap

Build order from `docs/design/2026-10-27-micro-notify-design.md` §8. One module per step, one PR per
step, merged by the orchestrator after review. Design §8 is the contract: steps are not re-litigated.

Every step carries the same three VERIFY gates:

- `pytest -q` green.
- **Socket-blocking harness** (`tests/conftest.py`, step 1) present and passing — the suite FAILS if any
  test opens a real network socket. No test ever sends a real email or Teams message.
- **Leak guard** (`tests/test_leak_guard.py`, design §5) passing — tracked files contain no GUIDs other
  than documented placeholders, no `*.logic.azure.com` / `*.powerplatform.com` webhook URLs, no
  private-key blocks, no email domains other than `example.com` / `contoso.com`.

## Now

1. **Scaffold** — `pyproject.toml`, package `micro_notify`, console scripts `micro-notify` + `mnotify`,
   argparse CLI skeleton, `config.py` (`~/.config/mnotify/config.toml`, 0600, `MICRO_NOTIFY_CONFIG`
   override), `secrets.py` (macOS keychain via `/usr/bin/security`, service `mnotify`), plus the shared
   test harness (socket blocker + leak guard) and every shared schema key the later steps need.

## Next

2. **guard + audit** — `guard.py`: `allow.domains` (default empty = refuse all), `allow.addresses`,
   `limits.max_recipients`, `limits.daily_max` counter, `limits.max_attach_mb`; all enforced before any
   network call. `audit.py`: JSONL to `~/Library/Logs/mnotify/sent.jsonl`, never the body.
3. **mail** — `graph.py`: msal `ConfidentialClientApplication` (certificate preferred, secret fallback),
   `POST /users/{sender}/sendMail`, `saveToSentItems`, to/cc/bcc, `--reply-to`, `fileAttachment` base64
   with total ≤ 3 MB refused above, 429/5xx backoff honouring `Retry-After` (max 3 tries).
4. **teams** — `teams.py`: Workflows webhook targets (`channel` | `dm`), Adaptive Card 1.4 builder
   (title, markdown text, facts, one link button, `--card-file` passthrough), channel post + Flow-bot DM
   post, webhook URLs from the keychain (account `teams:<target>`).
5. **doctor + setup** — `mnotify doctor` (config, keychain presence, token acquire, `Mail.Send` in token
   roles, each Teams target URL present, optional `--send-test`), `mnotify setup` incl. `--gen-cert`,
   `mnotify config show` with secrets masked to presence.
6. **docs** — `docs/ADMIN-SETUP.md` (Entra app reg, Exchange Online RBAC-for-Applications scoping to the
   one mailbox, removal of the tenant-wide consent and why, Teams workflows, `Test-ServicePrincipalAuthorization`
   positive + negative) and `README.md` (install, setup, agent usage incl. Hermes one-liners, exit codes).

## Later

7. **Packaging** — `pom11/homebrew-micro-notify` tap with a Python virtualenv formula (release tarball
   `url` + `sha256`, pinned resources, same pattern as `pom11/homebrew-hscc`), release script that bumps
   the formula, tag `v0.1.0`, real `brew install pom11/micro-notify/micro-notify` on the Mac.

## Operator-gated (outside the build DAG, blocks v0.1.0)

- §6 admin steps in a real tenant (app registration, certificate, admin consent, Exchange scoped role,
  Teams workflow creation + pasting webhook URLs). Orch writes the doc; only the operator runs it.
- First real sends (`mnotify doctor --send-test`, one mail, one channel post, one DM) and the
  scoped-mailbox negative test expecting 403.
- Visibility flip of `pom11/micro-notify` to public at v0.1.0, and the same flip for
  `pom11/homebrew-micro-notify`. The tap repo itself is created **private** up front by the orchestrator
  (operator decision 2026-10-27); only the flip stays with the operator.

## Definition of done for the project

`brew install` works from the tap, `mnotify doctor` is green against a real tenant, a real mail +
channel post + DM land, an external recipient is refused with exit 3, a sender override to a mailbox
outside the scoped role is refused with 403, and the whole test suite passes with sockets blocked.
