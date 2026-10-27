# micro-notify — design (2026-10-27)

Status: APPROVED by operator for build (2026-10-27: "write the design and give it to an orch, also add
Teams messages"; "call it something generic so we can make it public"). Calls marked *(my call)* were
made on the operator's behalf; change them only with a reason.

**PUBLIC-READY REPO.** Generic for any Microsoft 365 tenant. No company names, real domains, tenant/
client IDs, mailbox addresses or webhook URLs in tracked files — examples use `example.com` /
`contoso` placeholders only. Visibility flip to public = operator decision at v0.1.0.

## 1. Why

AI agents and scripts (Hermes orchs/workers, Claude, ERP flows, cron jobs) need to notify people: send
an email from a Microsoft 365 mailbox (typically a `noreply@<domain>`) and post a Teams message, with
one CLI, without each agent handling Microsoft auth or secrets. Install via Homebrew. First user: our
own tenant (configured outside the repo).

## 2. Goals / non-goals / anti-goals

Goals
- `mnotify mail send` — email from `noreply@example.com` through Microsoft Graph (app-only).
- `mnotify teams send` — Teams message to a named **channel** or to a **person (1:1)**.
- Non-interactive, agent-friendly: stdin/file bodies, `--json` output, stable exit codes, `--dry-run`.
- Secrets only in the macOS keychain; config file holds no secrets.
- Guardrails so an agent cannot spam or send outside the company by mistake.
- `brew install pom11/micro-notify/micro-notify` (public tap).

Non-goals (v1): reading/receiving mail, bulk/marketing mail, calendar, templating engine (a file body
is enough), Windows/Linux keychains (macOS only; keep the secret store behind one interface).

Anti-goals (a build that does any of these FAILED even if tests pass)
- The app registration can send as ANY mailbox in the tenant (must be scoped to noreply only).
- A secret, token or webhook URL printed to stdout/stderr/logs, committed, or written to the config.
- A real email/Teams post sent from the test suite.
- Any real tenant ID, domain, mailbox, person or webhook URL in a tracked file (public repo).

## 3. Architecture

Python ≥3.12 package `micro_notify`, console scripts `micro-notify` and short alias `mnotify`. Dependencies: `msal` (token),
`httpx` (HTTP). Nothing else unless justified. *(my call: Python like hscc; msal handles cert auth.)*

```
mnotify CLI (argparse)
 ├─ config.py   ~/.config/mnotify/config.toml (tomllib read, simple writer)
 ├─ secrets.py  macOS keychain via /usr/bin/security (service "mnotify", accounts below)
 ├─ guard.py    allowlist, caps, recipient count, daily counter
 ├─ audit.py    JSONL log ~/Library/Logs/mnotify/sent.jsonl
 ├─ graph.py    msal ConfidentialClientApplication → token → POST /users/{sender}/sendMail
 └─ teams.py    Workflows webhook POST (Adaptive Card payload)
```

### 3.1 Email — Microsoft Graph, app-only
- Entra app registration `micro-notify`, application permission **Mail.Send**, client credentials.
- Auth: **certificate** preferred (private key PEM + thumbprint in keychain); client secret supported
  as fallback. *(my call)*
- Send: `POST https://graph.microsoft.com/v1.0/users/noreply@example.com/sendMail`, `saveToSentItems`
  true. Body text or HTML; to/cc/bcc; `--reply-to` (so replies reach a real person, noreply has no
  reader); attachments as `fileAttachment` base64, **total ≤ 3 MB in v1** (refuse above with a clear
  error; upload sessions = later).
- Tenant-wide risk control (REQUIRED, operator does it, §6): Exchange Online **RBAC for Applications**
  scoping the app to `noreply@example.com` only, and the tenant-wide Entra Mail.Send consent removed
  afterwards, so the only grant left is the scoped one.

### 3.2 Teams — Workflows webhooks *(my call; no bot registration, no extra Graph perms)*
Graph cannot post chat/channel messages app-only (ChatMessage.Send is delegated-only), and the old
Office 365 Connector incoming webhooks are retired. The supported no-code path is **Teams Workflows**
(Power Automate) webhook triggers:
- **Channel target**: workflow template "Post to a channel when a webhook request is received", one per
  channel. CLI posts an Adaptive Card to its URL.
- **Person (1:1) target**: ONE workflow "When a Teams webhook request is received" → "Post card in a chat
  or channel" (Post as: Flow bot, Post in: Chat with Flow bot, Recipient = `triggerBody()?['recipient']`).
  CLI sends `{recipient: "<upn>", attachments:[card]}`. The person gets it from the Workflows bot.
- Webhook URLs contain a signature = **secrets** → keychain (account `teams:<target>`), config holds only
  target names + kind (`channel`|`dm`).
- Message: Adaptive Card 1.4 with optional title, markdown text, optional facts list and one link button.
  `--card-file` accepts a full card JSON for power users.
- Later (not v1): Azure Bot for richer DMs/replies — only if the Workflows bot sender is a problem.

### 3.3 Guardrails (enforced in `guard.py`, all before any network call)
- `allow.domains` (default EMPTY → every send refused until configured) + `allow.addresses` — every to/cc/bcc and Teams DM
  recipient must match; else exit 3, nothing sent. `--allow-external` does NOT exist in v1.
- `limits.max_recipients` per message (default 20), `limits.daily_max` sends per day (default 200,
  counter in `~/Library/Application Support/mnotify/counter.json`).
- `limits.max_attach_mb` 3.
- Audit line per attempt (sent / refused / failed): ts, channel (mail|teams), sender/target, recipients,
  subject/title, body sha256 + size, attachment names+sizes, graph request-id, outcome. Never the body.

### 3.4 Config (`~/.config/mnotify/config.toml`, 0600)
```toml
[mail]
tenant_id = "<guid>"
client_id = "<guid>"
sender = "noreply@example.com"
auth = "certificate"          # or "secret"
default_reply_to = ""         # optional

[allow]
domains = ["example.com"]
addresses = []

[limits]
max_recipients = 20
daily_max = 200
max_attach_mb = 3

[teams.targets.alerts]        # name -> kind; URL lives in the keychain
kind = "channel"
[teams.targets.dm]
kind = "dm"
```
Env overrides for CI/agents: `MICRO_NOTIFY_CONFIG` (path). No secrets via env in v1.

## 4. CLI

```
mnotify setup                          interactive: tenant/client/sender, store cert or secret in keychain
mnotify doctor [--send-test <addr>]    config ok, keychain items present, token acquired, token roles has
                                        Mail.Send, each Teams target URL present; optional real test send
mnotify mail send --to a@example.com [--to ...] [--cc ...] [--bcc ...] --subject S
                   (--body TEXT | --body-file F | stdin) [--html] [--attach F ...] [--reply-to R]
                   [--dry-run] [--json]
mnotify teams targets add <name> --kind channel|dm     (prompts for URL, hidden input, keychain)
mnotify teams targets list | remove <name>
mnotify teams send <target> [--to <upn>]  (required for kind dm)  [--title T]
                   (--text TEXT | --text-file F | stdin) [--fact k=v ...] [--link URL --link-title T]
                   [--card-file F] [--dry-run] [--json]
mnotify log [--tail N] [--json]
mnotify config show                    secrets masked (presence only)
```
Exit codes: 0 sent · 2 usage/config error · 3 refused by guard · 4 auth error · 5 remote error
(Graph/webhook non-2xx, message includes request-id) · 6 daily cap reached.
`--dry-run` prints the exact payload (secrets masked) and audits as `dry_run`; performs NO token call.
`--json` prints `{"ok":…, "outcome":…, "requestId":…, "recipients":[…]}`.

## 5. Packaging
- Repo `pom11/micro-notify` (private until v0.1.0, then public on operator OK). MIT license *(my call)*.
  Releases tagged `vX.Y.Z` with GitHub release tarballs.
- Tap `pom11/homebrew-micro-notify` (public with the repo), formula `micro-notify` = Python virtualenv
  formula, `url` = release tarball + sha256, resources pinned. Same pattern as pom11/homebrew-hscc.
- Release script bumps the formula (run by the orch; no GH Actions secrets needed v1).
- Leak guard: a test scans tracked files and fails on GUIDs that are not the documented placeholders,
  `https://*.logic.azure.com`/`*.powerplatform.com` webhook URLs, private-key blocks, and e-mail
  domains other than example.com/contoso.com.

## 6. Operator one-time admin steps (docs/ADMIN-SETUP.md — orch writes it, operator runs it)
1. Entra → App registrations → New `micro-notify` (single tenant). Upload certificate public key
   (cert generated locally by `mnotify setup --gen-cert`, key goes to keychain). API permissions →
   Microsoft Graph → Application → Mail.Send → Grant admin consent.
2. Exchange Online PowerShell (exact commands in the doc, with placeholders):
   `New-ServicePrincipal -AppId <clientId> -ObjectId <enterpriseAppObjectId> -DisplayName micro-notify`
   `New-ManagementScope -Name mnotify-noreply -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'noreply@example.com'"`
   `New-ManagementRoleAssignment -App <clientId> -Role "Application Mail.Send" -CustomResourceScope mnotify-noreply`
   `Test-ServicePrincipalAuthorization -Identity <clientId> -Resource noreply@example.com` (InScope True)
   and against another mailbox (InScope False).
3. Remove the tenant-wide Entra Mail.Send admin consent (keep only the Exchange scoped role) and re-run
   `mnotify doctor --send-test` + a negative test (sender override to another mailbox must fail 403).
   *(the doc must explain why: Entra consent alone = any mailbox.)*
4. Teams: create the channel workflow(s) + the DM workflow, paste URLs via `mnotify teams targets add`.
5. noreply mailbox: confirm it is a licensed or shared mailbox (shared needs no license) — Graph send works
   for both.

## 7. Testing / acceptance
- Unit tests (pytest, `httpx.MockTransport`/respx, msal mocked): guard (allowlist, caps, counts, attach
  size), payload builders (mail JSON, Adaptive Card, DM payload), keychain wrapper (subprocess mocked),
  exit codes, audit never contains body/secret, `--dry-run` makes zero network calls.
- A test that FAILS if any test performs a real network call (block sockets).
- Manual acceptance (after operator §6): `brew install` from the private tap on the Mac Studio;
  `mnotify doctor` green; one real mail to the operator's address; one channel post; one DM; one
  guard refusal (external address → exit 3); scoped-mailbox negative test → 403.
- README: install, setup, agent usage examples (incl. Hermes one-liners), exit codes.

## 8. Build order (atomic cards)
1. Scaffold: pyproject, package, CLI skeleton, config + keychain wrapper + tests.
2. guard + audit + tests.
3. mail: msal cert/secret token + sendMail payload + attachments + tests.
4. teams: targets, card builder, channel + dm send + tests.
5. doctor + setup (`--gen-cert`) + `config show` masking.
6. docs/ADMIN-SETUP.md + README.
7. Packaging: tap repo + formula + release script → v0.1.0 → real brew install on the Mac.
Each card: one PR, tests green, no real sends. Merge = orch after review.

## 9. Left to the builder
Module internals, card styling, CLI help wording, test layout, retry/backoff on 429/5xx (respect
`Retry-After`, max 3 tries).
