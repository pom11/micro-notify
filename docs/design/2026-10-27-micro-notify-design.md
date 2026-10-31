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

[paths]                       # optional; lets tests point audit + counter at a tmp dir
audit = "~/Library/Logs/mnotify/sent.jsonl"
state_dir = "~/Library/Application Support/mnotify"   # holds counter.json

[teams.targets.alerts]        # name -> kind; URL lives in the keychain
kind = "channel"
[teams.targets.dm]
kind = "dm"
```
Env overrides for CI/agents: `MICRO_NOTIFY_CONFIG` (path). No secrets via env in v1.

Keychain accounts (service `mnotify`, design §3) — operator approved 2026-10-27:

| account | holds |
| --- | --- |
| `graph.certificate_pem` | private key PEM (auth = "certificate") |
| `graph.certificate_thumbprint` | cert thumbprint paired with the PEM |
| `graph.client_secret` | client secret (auth = "secret") |
| `teams:<target>` | Workflows webhook URL for target `<target>` (= a secret) |

The config file above holds **no** secret values; `[paths]` exists so the test suite can redirect the
audit log and `counter.json` into a temp dir instead of the real HOME.

## 4. CLI

```
mnotify setup                          interactive: tenant/client/sender, store cert or secret in keychain
mnotify doctor [--send-test <addr>]    config ok, keychain items present, token acquired; if the token's
                                        roles claim is present it includes Mail.Send — an absent claim
                                        after §6 step 3 is expected (Exchange app-RBAC is invisible to
                                        the Entra claim) and reports `warn`, exit unchanged; an
                                        unreadable claim or a read claim without Mail.Send stays a
                                        fail (exit 4, fail-closed). *(amended 2026-10-29 per t_24a04813)*
                                        Each Teams target URL present; optional real test send
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
- Tap `pom11/homebrew-micro-notify` — created **private** alongside the main repo (operator decision
  2026-10-27); goes public with the repo at v0.1.0, so `brew install` works publicly only after the flip.
  Formula `micro-notify` = Python virtualenv
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

## Amendment 2026-10-30 — delegated (as-a-person) mode

Status: Amendment direction approved by operator 2026-10-30; binding seams decided by orch. **Append-only.** Sections 1–9 above stand exactly as written and
are not rewritten here. Where this text and a section above disagree, this amendment wins **only** for the
delegated mode defined below; app-only behaviour is unchanged. *(amended 2026-10-30 per t_589877bf)*

### A.1 Exception to section 2 — there are now two auth modes, not one

Section 2 sets out one auth stance: app-only, certificate-backed, sending from `noreply@…`. That stays the
**default**. This amendment adds a second, opt-in mode:

```toml
[mail]
mode = "delegated"     # default "app"; "delegated" = send as the signed-in person
```

| | app-only (sections 1–9, unchanged) | delegated (this amendment) |
| --- | --- | --- |
| who signs in | nobody — certificate or secret | a real user, device-code flow |
| mail sender | `sender`, the scoped `noreply@example.com` | the signed-in user's own mailbox |
| Teams person target | the Workflows bot (§3.2) | **the person themselves**, via `ChatMessage.Send` |
| Entra registration | our `micro-notify` app | the same app, with delegated permissions |

Two facts forced this mode, and one of them decides *which* registration it signs in through:

1. **The Azure CLI's first-party app cannot be borrowed.** The obvious shortcut for a delegated login is
   a well-known public client that already exists — the Microsoft Azure CLI's own app. It is closed to us:
   that app carries neither `Mail.Send` nor `ChatMessage.Send` in its permission list, and scopes cannot be
   added to an app you do not own. A token from it can therefore never send mail or post a chat. Delegated
   mode must ride **our** `micro-notify` registration, which we control and can grant delegated scopes to
   (§A.4 adds the admin step).
2. **Graph forbids app-only posting to a personal chat.** §3.2 already states `ChatMessage.Send` is
   delegated-only. The application permission that does exist, `ChatMessage.Send.AsApp`, posts as the
   *app* — never as a person — and the only app-only route into a personal (1:1) chat is the
   migration/import API, which is a history-import path, not a notification path. So for a Teams message
   that arrives as though a person typed it, **delegated is the only person-identity path**. Channel posts
   keep using the Workflows webhook; delegated chat is additive, not a replacement.

Section 2's non-goals and anti-goals stay in force. The anti-goal "a secret, token … printed … or written
to the config" is **strengthened** here: the delegated token cache is a secret (§A.2). The anti-goal "the
app registration can send as ANY mailbox" continues to bind app-only mode; in delegated mode the
equivalent control is different and holds by construction — a delegated token can act only as the one
identity that signed in and consented (§A.3).

### A.2 Threat model for the delegated token

In delegated mode **the cached token is the user's identity** for the scopes it was granted — not a
capability we scoped down ourselves. Whoever holds that cache can, until the refresh token dies, send mail
from a real person's mailbox and post chat messages in their name: their signature on it, their delegates
seeing it, no trace back to this tool. It is handled with the same care as that person's password.

Granted delegated scopes — exactly these five, nothing more:

| scope | why it is needed |
| --- | --- |
| `Mail.Send` | `mnotify mail send` in delegated mode |
| `ChatMessage.Send` | the person-identity Teams post (§A.1 reason 2) |
| `Chat.ReadBasic` | read chat names/memberships so a named person can be matched to a 1:1 chat the user is already in |
| `User.Read` | read the signed-in profile — who am I, and does it match what config claims |
| `offline_access` | silent re-auth, so a cron send does not prompt a human every time |

`offline_access` is what makes the cache dangerous: it holds a **long-lived refresh token**, not merely a
short-lived access token. The §2 / §3.4 rules therefore apply to the cache as they do to a private key:

- the cache lives in the **macOS keychain only** — service `mnotify`, account
  `graph.delegated_token_cache` — through the same wrapper as §3.4 (`secrets.py`: value in argv of one
  exec, never a shell string, errors naming the *account* only);
- it is **never on disk**: not in `~/.config/mnotify`, not in the state dir, not beside `counter.json`,
  and not at msal's own default cache path — the serialised token cache is persisted into that one keychain
  item and nowhere else;
- it is **never printed**: not by `doctor`, not by `config show` (presence only), not in `--json`, not in
  an audit line, never in an exception message;
- the promise stays tested (§7): no test may write a token-cache file, and the §5 leak guard keeps scanning
  tracked files.

**Revocation — two levels, and the docs must not blur them:**

1. `mnotify logout` deletes the keychain item `graph.delegated_token_cache`. Immediate and local; enough
   when the machine itself is trusted. It stops **this Mac** and reaches nothing else.
2. Entra **revoke sessions** on the user (Entra ID → Users → *user* → Revoke sessions) is the **hard**
   revoke: refresh tokens stop being redeemable tenant-wide. Add removal of the delegated consent
   (`DelegatedPermissionGrant`) to end the mode permanently. `mnotify logout` alone is not a hard revoke
   and must never be presented as one.

**Conditional operator setting — `Allow public client flows`.** The delegated sign-in is a device-code
flow, which Entra classes as a *public client* flow, so that switch has to be **Yes** for delegated use.
The switch belongs to the whole registration, and the operator runs both kinds of tenant configuration
(the app-only one from §6 and the delegated one from here), so it is documented as a condition:

**One registration per tenant.** Bootstrap creates or reuses a single `micro-notify` registration in each
tenant; delegated mode does not get its own app. `Allow public client flows` is therefore a **per-tenant
setting**, not a per-registration choice: **Yes** in a tenant that runs delegated mode (required by the
device-code flow), **No** in a tenant that runs app-only mode — and it is never flipped to Yes in an
app-only tenant. Each tenant runs one mode, and the switch matches the mode.

| what the tenant's registration is used for | Allow public client flows |
| --- | --- |
| app-only (§6 as written) | **No** — keep it off; nothing in app-only mode needs it |
| delegated mode (this amendment) | **Yes** — required; device-code sign-in fails closed without it |

ADMIN-SETUP.md must present the switch as a per-tenant setting that follows the tenant's mode, not as a
default to leave on.

### A.3 Constraints carried forward, unchanged

Delegated mode buys identity, not latitude. These rules apply to a delegated send exactly as to an
app-only send, and `guard.py` still runs **before** any token call or network call:

- **The sender is always the signed-in identity.** No send-as-other, ever. In delegated mode the `[mail]
  sender` key is ignored and the send goes to `/users/me/sendMail` (equivalently
  `/users/<upn>/sendMail` where `<upn>` is the identity carried in the token); a request naming any other
  mailbox is a config error (exit 2) raised before the network. The check compares the configured/asked-for
  identity against the signed-in `upn`/`oid` from the token — it does not trust config.
- `allow.domains`, `allow.addresses`, `limits.max_recipients`, `limits.daily_max`,
  `limits.max_attach_mb`: same defaults, same `guard.py`, same exit codes (3 refused, 6 cap reached).
- Audit: same JSONL line and the same **no-body** rule, which matters more here, because that log is the
  only record of what a person's identity did through this tool. The line gains `mode = delegated` and the
  signed-in `upn` next to the existing fields.
- A Teams **channel** post still goes through the Workflows webhook (§3.2). Delegated chat is used only for
  the person-identity case, and the chat it posts to must be a target the guard accepted.
- Exit codes are unchanged (§4); a failed delegated sign-in is exit 4, same as an app-only auth failure.

### A.4 Additive deltas (listed here; the sections above are left intact)

- §3.4 keychain table gains one row: `graph.delegated_token_cache` | msal delegated token cache (access +
  refresh token) — a secret, `config show` prints presence only.
- §3.4 config gains one key: `[mail] mode = "app" | "delegated"`, default `app`, so every
  existing config file keeps working untouched.
- §4 CLI gains two commands. `mnotify login` — device-code sign-in: shows the code and URL once, writes the
  cache to the keychain, then prints the signed-in `upn` (never a token). `mnotify logout` — deletes that
  cache item; §A.2 says what that does and does not revoke.
- §4 `doctor` in delegated mode: a delegated token carries `scp`, not `roles`, so the tri-state check reads
  `scp` and requires `Mail.Send` in it — same pass/warn/fail shape, same exit codes; `roles` stays the
  app-only check.
- §6 gains an optional step 6 for a delegated tenant: grant the five delegated permissions of §A.2 to the
  registration and consent them, set `Allow public client flows = Yes` per the table in §A.2, and record the
  hard-revoke procedure. Nothing in steps 1–5 changes.
- Placeholders for every delegated example in any doc: sender `me@contoso.com`; tenant and client IDs
  `00000000-0000-0000-0000-000000000000`; chat id `19:00000000000000000000000000000000@thread.v2`. No real
  tenant, domain, upn, chat id or token in a tracked file — the §5 leak guard applies unchanged.

### A.5 Open question, recorded rather than guessed

`Chat.ReadBasic` covers reading chats the user is already in. Whether posting a **first** message into a
1:1 that does not yet exist needs a further delegated scope (`Chat.Create` / `Chat.ReadWrite`) is not
settled by this amendment. The list deliberately stays at the five scopes in §A.2; if the first live test
proves a sixth is required, it is added to §A.2 here, with a reason, before it appears in code.
