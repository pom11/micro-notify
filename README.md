# micro-notify

`mnotify` is a command-line notifier for **agents and scripts**: it sends email from
one Microsoft 365 mailbox through Microsoft Graph (app-only), and posts Teams
messages through Workflows webhooks. No interactive sign-in, no per-agent Microsoft
auth, no secrets in config files or environment variables.

Design contract:
[`docs/design/2026-10-27-micro-notify-design.md`](docs/design/2026-10-27-micro-notify-design.md)
— cited below as §n. Admin-side (one-time, per tenant) setup:
[`docs/ADMIN-SETUP.md`](docs/ADMIN-SETUP.md).

Requires macOS (the secret store is the macOS keychain) and Python ≥ 3.12 if
installing from source.

## Install

```sh
brew install pom11/micro-notify/micro-notify
```

Until the v0.1.0 visibility flip both `pom11/micro-notify` and its tap
`pom11/homebrew-micro-notify` are **private**, so that command only works for someone
with access to the tap and with git authenticated to GitHub (`gh auth setup-git`, or
an SSH key registered for the tap). If you cannot authenticate to GitHub, install
from a checkout of this repo instead — that is the unauthenticated path, and it is
how the package is built from source:

```sh
git clone https://github.com/pom11/micro-notify.git
cd micro-notify
pip install .            # or: pipx install .
```

Both names are installed: `mnotify` (the short form used everywhere below) and
`micro-notify`. Confirm with `mnotify --version`.

Dependencies are `msal` and `httpx`, nothing else (§3).

## Set up (one command, after the admin steps)

`mnotify setup` writes `~/.config/mnotify/config.toml` (mode 0600) and puts the
credential in the keychain. Run it at a terminal once per machine:

```sh
mnotify setup
```

It asks for the tenant ID, the app (client) ID, the sender mailbox, the credential
kind and the recipient domains to allow. With `--gen-cert` it also generates a
key pair locally, keeps the **private** half in the keychain, prints the SHA-1
fingerprint and writes the public certificate for you to upload to Entra
(§6 step 1). Every prompt has a flag for non-interactive use
(`--tenant-id`, `--client-id`, `--sender`, `--auth`, `--reply-to`, `--allow-domain`,
`--force`, `--json`), so CI and agents can drive it — but there is deliberately **no
`--client-secret` flag and no secret via environment variable**: a secret on a
command line lands in shell history and in `ps` output, and §3.4 rules env vars out
for v1. `mnotify setup --gen-cert` is the non-interactive path because its
credential is generated, not typed.

Then check the whole chain:

```sh
mnotify doctor                    # config, keychain, Teams targets, token, Mail.Send role
mnotify doctor --send-test you@example.com   # plus one real test send
```

`doctor` runs its checks in the order you will hit them and stops at the first
failure, printing a `fix:` hint that names the command or admin step that resolves
it. It prints presence only — never a secret.

One thing to expect: `doctor` proves the `Mail.Send` grant by reading it out of the
token Entra issued. The tenant hardening in
[`docs/ADMIN-SETUP.md`](docs/ADMIN-SETUP.md) step 3 removes that Entra consent on
purpose, so that the Exchange scoped role is the only thing limiting the app to one
mailbox. After that step `doctor`'s `token` check reports `Mail.Send` missing and
exits 4 — that red line means the hardening worked, not that something broke. Verify
sends with `mnotify mail send` from then on.

## Guardrails: read this before your first send

**An empty allowlist means every send is refused until you configure it.** `[allow]
domains` and `[allow] addresses` start empty (§3.3), and empty means *fail closed*:
`mnotify mail send` exits **3** and nothing is sent, no token is requested, no
socket is opened. That is intentional — an agent must not be able to mail strangers
because nobody configured the tool. Add the domains you actually need:

```sh
mnotify setup --force --allow-domain example.com --allow-domain contoso.com
```

Everything else that is enforced, always before any network call (§3.3):

| Guardrail                      | Default | Behaviour when exceeded                     |
| ------------------------------ | ------- | ------------------------------------------- |
| `allow.domains` / `allow.addresses` | empty   | exit **3**, recipient named in the message |
| `limits.max_recipients`        | 20      | exit **3** (to + cc + bcc + DM recipients)   |
| `limits.max_attach_mb`         | 3       | exit **3** (total across all attachments)    |
| `limits.daily_max`             | 200     | exit **6** (counter keyed by UTC date)       |

Matching is exact and case-insensitive: allowing the domain `example.com` admits
`a@example.com` but not an address sitting at a sub-domain such as
`dept.example.com`. There is **no `--allow-external` flag in v1** — widening the
allowlist is a config edit, not a per-send escape hatch. A failed or refused send
does not spend the daily budget; only a send that actually succeeded does.

Every attempt — `sent`, `refused`, `failed`, `dry_run` — appends one JSONL line to
`~/Library/Logs/mnotify/sent.jsonl` with timestamp, channel, sender/target,
recipients, subject/title, body **sha256 + size** (never the body), attachment
names + sizes, and the Graph request-id when there was one.

## One-liners

The body can come from an argument, a file, or stdin — so anything you can pipe
becomes a notification:

```sh
# text body
mnotify mail send --to ops@example.com --subject "nightly build failed" --body "see CI"

# body from a file, HTML, with a reply-to a human will read
mnotify mail send --to ops@example.com --subject "report" \
  --body-file /tmp/report.html --html --reply-to ops@example.com

# body from stdin (this is the shape an agent wants: no TTY needed)
git log -1 --format='%h %s' | mnotify mail send --to ops@example.com --subject "deployed"

# several recipients and an attachment (total attachments must fit limits.max_attach_mb)
mnotify mail send --to a@example.com --to b@example.com --cc lead@example.com \
  --subject "log bundle" --body "attached" --attach /tmp/app.log

# Teams: a channel post, and a DM to one person
mnotify teams send alerts --title "Build 42" --text "nightly run **finished**"
mnotify teams send dm --to someone@example.com --text "the deploy needs your approval"
```

If you find yourself reaching for `curl` against Graph, stop: that path needs a
bearer token in your command line, which is exactly what `mnotify` exists to avoid.

## Machine mode (`--json`) and exit codes

Every send/doctor/config command takes `--json`. Success prints one JSON document on
stdout with the design §4 shape; errors print
`{"ok": false, "outcome": "error", "exitCode": N, "message": "..."}` on stdout (in
human mode the message goes to stderr instead). Keys are sorted, one line each, so
it is `jq`-safe:

```sh
mnotify mail send --to ops@example.com --subject "hi" --body "x" --json
# {"ok": true, "outcome": "sent", "recipients": ["ops@example.com"], "requestId": "…"}
```

Exit codes are a public contract for agents — they do not change (§4):

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| 0    | sent (or a `--dry-run` payload printed, or a check passed)          |
| 2    | usage or config error (bad flag, missing/invalid config, unknown target) |
| 3    | refused by a guardrail (allowlist, recipient count, attachment size) |
| 4    | auth error (missing keychain item, token acquisition, no `Mail.Send` role) |
| 5    | remote error (Graph or webhook non-2xx; the message carries the request-id) |
| 6    | daily cap reached (`limits.daily_max`)                              |

`1` means an unexpected crash — a bug, never a documented outcome. `130` is the
shell convention for Ctrl-C. A stub of a future command exits 2 and says so loudly;
it never pretends to have sent something.

Handling it in a script — the point is that "not sent" is a *result*, not a crash:

```sh
#!/bin/sh
set -u
mnotify mail send --to ops@example.com --subject "job done" --body "$1" --json > /tmp/out.json
case $? in
  0) echo "sent: $(tr -d '\n' < /tmp/out.json)" ;;
  3) echo "refused by guardrail — check [allow]; nothing was sent" >&2 ;;
  4) echo "credential problem — run mnotify doctor" >&2 ;;
  5) echo "Microsoft refused the request — see the request-id in the message" >&2 ;;
  6) echo "daily cap reached; not retrying today" >&2 ;;
  *) echo "unexpected failure" >&2; exit 1 ;;
esac
```

### Agent usage (Hermes-style one-liners)

Designed for a non-interactive tool call: no TTY, no prompts, no secrets needed at
call time (they are already in the keychain), and the exit code tells the agent what
happened.

```sh
# report a finished run, and let the caller see the guardrail verdict verbatim
mnotify teams send alerts --title "worker finished" \
  --text "380 tests passed" --json || echo "not delivered (exit $?)"

# a cron step that must not spam: dry-run first, then decide
mnotify mail send --to ops@example.com --subject "digest" --body-file /tmp/digest.md --dry-run \
  && mnotify mail send --to ops@example.com --subject "digest" --body-file /tmp/digest.md --json

# what did I already send today?
mnotify log --tail 20 --json | jq -r '.entries[] | "\(.ts) \(.outcome) \(.channel)"'

# before escalating, prove the pipeline is intact
mnotify doctor --json | jq '.checks'
```

## Previewing without sending: `--dry-run`

`mnotify mail send --dry-run` and `mnotify teams send --dry-run` print the **exact
payload** that would go on the wire and audit it as `dry_run`. No token is requested
and no HTTP request is made, and the daily counter is not touched. The teams command
does read the webhook URL out of the keychain, because what it prints is that URL
**masked**; `--json` adds the payload under `payload`.

```sh
mnotify mail send --to ops@example.com --subject "dry" --body "x" --dry-run
mnotify teams send alerts --text "dry" --dry-run
```

Exit 0 means "the payload is valid and the guardrails passed" — it does **not**
prove the credential works or that Microsoft will accept it. For that you have to
send for real: `mnotify mail send` (or `mnotify doctor --send-test <addr>`, whose
token check needs the Entra consent that ADMIN-SETUP step 3 removes).

## Teams targets

A target is a named Workflows webhook, stored as `kind` + name in the config with
the URL in the keychain (§3.2). `channel` posts to one fixed channel; `dm` posts to
one person per call through a single shared DM workflow, so `--to <UPN>` is required
for `dm` and rejected for `channel`.

```sh
mnotify teams targets add alerts --kind channel    # prompts for the URL, hidden input
mnotify teams targets add dm --kind dm
mnotify teams targets list                         # name, kind, presence — never the URL
mnotify teams targets remove alerts                # config entry *and* keychain item
```

The webhook URL contains a signature, so **it is a secret**: paste it only at the
hidden prompt, never into a flag, an env var, a config file or a ticket. If a URL
leaks, `teams targets remove` it, recreate the workflow in Teams, and add the new
URL.

Card building is `--title`, `--text` (markdown), repeatable `--fact k=v`, and one
`--link URL --link-title T` button; `--card-file F` posts your own Adaptive Card JSON
verbatim and cannot be combined with the others.

## Keychain accounts

All secrets live in the macOS keychain under service `mnotify` (§3.4), written only
by `mnotify setup` and `mnotify teams targets add`:

| Keychain account                 | Holds                                              | Written by                           |
| -------------------------------- | -------------------------------------------------- | ------------------------------------ |
| `graph.certificate_pem`          | the private key (auth = `certificate`)              | `mnotify setup --gen-cert`            |
| `graph.certificate_thumbprint`   | the certificate thumbprint paired with that key     | `mnotify setup --gen-cert`            |
| `graph.client_secret`            | the client secret (auth = `secret`)                 | `mnotify setup --auth secret`         |
| `teams:<target>`                 | the Workflows webhook URL for `<target>` (= secret) | `mnotify teams targets add`           |

Ask `mnotify` about them rather than the keychain — `mnotify config show` prints the
effective config with credentials reduced to presence markers, and `mnotify doctor`
checks the accounts the configured auth mode needs. To delete one (a delete prints
nothing secret): `/usr/bin/security delete-generic-password -s mnotify -a
graph.client_secret`. Never read a value into a terminal, a log or a screenshot —
and note that `security find-generic-password … -w` **prints the secret**, which is
why this tool never calls it in a way that echoes the value.

## Configuration file

`~/.config/mnotify/config.toml`, mode 0600, and it **cannot hold a secret** (§3.4).
Point at a different file with `MICRO_NOTIFY_CONFIG=/path/to/config.toml` (that is
how tests and CI get an isolated config).

```toml
[mail]
tenant_id = "00000000-0000-0000-0000-000000000000"   # your tenant GUID
client_id = "00000000-0000-0000-0000-000000000000"   # your app (client) GUID
sender = "noreply@example.com"
auth = "certificate"            # or "secret"
default_reply_to = "ops@example.com"

[allow]
domains = ["example.com"]       # EMPTY = every send refused
addresses = []

[limits]
max_recipients = 20
daily_max = 200
max_attach_mb = 3

[paths]                         # optional; lets tests redirect audit + counter
audit = "~/Library/Logs/mnotify/sent.jsonl"
state_dir = "~/Library/Application Support/mnotify"

[teams.targets.alerts]
kind = "channel"                # the URL lives in the keychain, not here
[teams.targets.dm]
kind = "dm"
```

`mnotify setup` writes this file; `--force` rewrites it and preserves your
`[teams.targets]` entries. Values that look like URLs are refused on the way in, in
every field — a webhook URL in the config file is the leak the schema is designed to
make impossible.

## What is NOT supported (v1)

By design (§2 non-goals), and not an oversight:

- **Reading or receiving anything.** No inbox, no Graph notifications, no reading
  Teams replies. `mnotify` is send-only, and the audit log is the only record it
  keeps.
- **Bulk or marketing mail.** No lists, no template engine, no throttled fan-out. A
  file body is the templating story; use a real sending service for campaigns.
- **Calendar, contacts, OneDrive, Teams chat history** — nothing beyond `Mail.Send`
  on one mailbox and Workflows posts.
- **A sanitising or escaping layer.** The body is what you wrote; `--html` marks it
  as HTML and nothing sanitises it.
- **Windows and Linux.** Secrets go to the macOS keychain via `/usr/bin/security`.
  The secret store sits behind one interface (`micro_notify/secrets.py`) precisely so
  another platform can be added later without touching the senders.
- **A sender other than the configured one.** There is no `--from`/`--sender` flag:
  the tenant-side scoping (ADMIN-SETUP.md steps 2–3) restricts the app to one
  mailbox, and a flag that lets an agent pick the sender would defeat it.
- **Sending to non-allowlisted addresses.** No `--allow-external`, no per-send
  override.
- **Attachment uploads above 3 MB total** — refused with exit 3 rather than
  attempted. Larger files belong in a share link (`--link` on a Teams card), not in
  the message.
- **Reading Teams replies or interactive cards.** `--card-file` gives you a full
  Adaptive Card; buttons other than the single `Action.OpenUri` are your problem.

## Troubleshooting

| Symptom                                     | Do this                                                            |
| ------------------------------------------- | ------------------------------------------------------------------ |
| exit 3 on every send                        | the allowlist is empty or does not cover the recipient — `mnotify config show`, then `mnotify setup --force --allow-domain <domain>` |
| exit 4, message names a keychain account    | re-run `mnotify setup` (or `mnotify teams targets add`) on this Mac |
| exit 4 with an `AADSTS…` detail             | wrong tenant/client ID, certificate not uploaded, or expired — see ADMIN-SETUP.md step 1 |
| exit 5 with `HTTP 403`                      | the mailbox is outside the Exchange scoped role — ADMIN-SETUP.md steps 2–3 |
| exit 6                                      | `limits.daily_max` spent today (UTC); the counter rolls at midnight UTC |
| `no recipient: pass --to ADDRESS`           | exit 2; `--to` is required for mail. `dm` targets need `--to <UPN>` too |
| `unknown teams target '…'`                  | exit 2; `mnotify teams targets list` to see what exists             |
| config already exists, rewrite refused      | expected without `--force`; re-run with it — Teams targets survive  |

`mnotify log --tail 20` shows what the tool already tried, including refusals. The
admin-side failure table is in
[`docs/ADMIN-SETUP.md`](docs/ADMIN-SETUP.md#where-to-look-when-something-fails).

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```

The suite is hermetic by construction: `tests/conftest.py` blocks sockets autouse,
so a test that opens a real connection fails, and `tests/test_leak_guard.py` scans
every tracked file for real tenant identifiers (§5, §7). No test sends an email or a
Teams message.

## License

MIT — see [`LICENSE`](LICENSE).
