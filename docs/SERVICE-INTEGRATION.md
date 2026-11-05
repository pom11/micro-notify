# Service integration: how gateclerk calls mnotify

This is the micro-notify side of the interface between gateclerk and this
repository. It is written for the person wiring gateclerk's production install
plan: the contract is the CLI process boundary, not a Python API. Every claim
here is derived from the code in this repository; the pull request that added
this document lists the file and line behind each claim.

mnotify sends Microsoft 365 mail through Graph and Teams messages through
Workflows webhooks. It is a short-lived process: it reads configuration and
credentials, applies guardrails, makes one logical send, writes one audit line,
and exits. gateclerk should treat it exactly that way.

## 1. The interface: exec, exit code, JSON

Exec `mnotify` synchronously as a child process and wait for it. Do not import
micro-notify's Python modules, call Graph yourself, or scrape human output.

The integration contract has three parts:

1. **Branch on the process exit code.** That is mnotify's result vocabulary.
2. **Pass `--json` and parse one JSON document from stdout.** Success and
   expected failure both produce a document; the exit code says which.
3. **Never interpolate alert text into a shell string.** Build an argv array.
   Put the alert body in a file and pass `--body-file` (mail) or `--text-file`
   (Teams). Alert text is untrusted input; a list argv cannot become shell
   syntax, and a file keeps long or sensitive bodies out of the process list.

Exit 0 means "Microsoft accepted the request", not "the human read it". Mail
means Graph accepted `sendMail`; Teams means the webhook or Graph chat endpoint
returned 2xx.

`--json` writes one sorted JSON document on stdout. Expected errors stay
machine-readable: with `--json`, even an error document is on stdout; in human
mode the error text goes to stderr. Capture both streams anyway, and trust the
exit code over the presence of output.

## 2. Commands and flags

### Mail

```text
mnotify mail send --to ADDR [--to ADDR ...] [--cc ADDR ...] [--bcc ADDR ...]
                  --subject S (--body TEXT | --body-file F)
                  [--html] [--attach F ...] [--reply-to ADDR]
                  [--dry-run] [--json]
```

`--to` is required; an empty recipient list is exit 2. If neither `--body` nor
`--body-file` is given, the body is read from stdin. `--attach` is repeatable
and the total size is capped by `[limits] max_attach_mb`. `--dry-run` prints
the exact payload, performs no token call and no network call, and still writes
an audit line.

A successful `--json` document is:

```json
{"ok": true, "outcome": "sent", "recipients": ["alerts@example.com"], "requestId": "..."}
```

`requestId` is Graph's `request-id` response header and may be `null` when
Graph did not send one. Put it in gateclerk's own log next to the alert id.
On a failed send the error document has no separate request-id field; the
`message` text includes `Graph request-id <id>` when Graph supplied one.

### Teams

```text
mnotify teams send TARGET [--to UPN] [--title T]
                    (--text TEXT | --text-file F)
                    [--fact K=V ...] [--link URL] [--link-title T]
                    [--card-file F] [--dry-run] [--json]
```

`TARGET` is a name from `[teams.targets]` in the config. For a `dm` target,
`--to UPN` is required and must pass the allowlist; for a `channel` target,
`--to` is refused. `--card-file` posts the Adaptive Card JSON verbatim and
cannot be combined with the builder flags (`--title`, `--text`, `--text-file`,
`--fact`, `--link`, `--link-title`). With no text flag, the body is read from
stdin.

A successful channel or DM `--json` document is:

```json
{"ok": true, "outcome": "sent", "target": "alerts", "recipients": [], "status": 202}
```

A `dm` send fills `recipients` with the UPN; a chat target also emits
`"kind": "chat"` and uses the alias as its recipient. The Teams webhook path
does **not** return a request-id: use gateclerk's own alert id (for example in
the subject or title) as the correlation key, and record mnotify's exit code
and `status` alongside it.

`--dry-run --json` uses `"outcome": "dry_run"`, no `requestId`, and includes
the payload it would have posted.

### Errors

With `--json`, every expected failure is one document on stdout:

```json
{"ok": false, "outcome": "error", "exitCode": 3, "message": "recipient not allowed by [allow]: someone@example.net"}
```

Do not treat `{"ok": true}` alone as success: check the exit code first, then
the `ok` field. Conversely, a non-zero exit with a parseable document is a
result, not a crashed process.

## 3. Exit codes and retry policy

These are the public codes. They do not change. There is no separate
"target not found" code: an unknown Teams target is a configuration error,
exit 2.

| Exit | Meaning | What mnotify already did | What gateclerk should do |
| ---- | ------- | ------------------------ | ------------------------ |
| 0 | sent, or a dry-run/check passed | The send was accepted, or nothing was sent in dry-run. A successful send consumed one unit of the daily counter. | Record success. For mail, store `requestId`. |
| 2 | usage or config error (bad flag, unreadable/invalid config, unknown target, missing `--to`) | Nothing was sent; no token call and no socket. | Do not retry. Fix the argv or the config; the same call will fail the same way. |
| 3 | refused by a guardrail (allowlist, recipient count, attachment size) | Nothing was sent; no token call and no socket. | Do not retry. This is policy, not a transient fault. Change the recipient, limits, or allowlist deliberately. |
| 4 | auth error (missing/unreadable secret, msal/AADSTS failure) | Nothing was sent. The message names the account or Entra detail, never the secret. | Do not retry automatically. This is operator action: provision the secret, fix the tenant/client ids, or re-run the admin setup. |
| 5 | remote error (Graph or webhook non-2xx, or the endpoint was unreachable) | mnotify retried 429 and 5xx up to three attempts in total (two retries after the first), honouring `Retry-After`; it did not retry other 4xx or transport-level failures. | Do **not** retry blindly: a 5xx or a lost response can mean the alert was already delivered. Retry at most once, and only for a known-flaky network path, after dedupe review. |
| 6 | daily cap reached (`limits.daily_max`) | Nothing was sent. The counter is keyed by UTC date. | Do not retry today. If the volume is real, raise the limit deliberately; otherwise wait for the UTC rollover. |
| 130 | interrupted (SIGINT) | The send may or may not have completed. | Treat the outcome as unknown. Check the audit line and the request-id before deciding whether to resend. |

Any other exit status is outside this table. Treat it as a crash or
infrastructure failure and do not retry blindly.

Two details behind the retry column matter to gateclerk:

* mnotify's retries are bounded at `MAX_TRIES = 3` in both the Graph mail path
  and the Teams paths. A "transient 5xx" is therefore already retried twice by
  mnotify; a third attempt from gateclerk is a third *logical* send from
  Microsoft's point of view.
* A failed send does not consume the daily counter. Only a success increments
  it, after the send returns 2xx.

## 4. Worked example

The example writes the untrusted alert text to a file, builds an argv list, and
gives the process a timeout larger than mnotify's own network envelope. It
assumes `MICRO_NOTIFY_CONFIG` is already set in the service environment as a
path (see section 7).

```python
import json
import os
import subprocess
import tempfile

alert_text = "deployment blocked: approval required\n"  # untrusted input

with tempfile.NamedTemporaryFile(
    "w", encoding="utf-8", dir="/var/lib/gateclerk/outbox", delete=False
) as handle:
    handle.write(alert_text)
    body_path = handle.name

try:
    argv = [
        "mnotify", "mail", "send",
        "--to", "alerts@example.com",
        "--subject", "gateclerk: deployment blocked",
        "--body-file", body_path,
        "--json",
    ]
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
finally:
    os.unlink(body_path)

document = json.loads(proc.stdout) if proc.stdout.strip() else None

if proc.returncode == 0 and document and document.get("ok"):
    request_id = document.get("requestId")   # may be None
elif proc.returncode == 5:
    # Ambiguous: the alert may already be delivered. Dedupe before any retry.
    pass
elif proc.returncode in (2, 3, 4, 6, 130):
    # Permanent or operator-action outcomes: do not retry the same call.
    pass
else:
    # Unexpected crash or infrastructure failure: do not retry blindly.
    pass
```

The same invocation from a shell, with the body in a file:

```sh
mnotify mail send \
  --to alerts@example.com \
  --subject "gateclerk: deployment blocked" \
  --body-file /var/lib/gateclerk/outbox/alert-123.md \
  --json
```

Use an argv array in the real caller. Never build one shell string from alert
content.

### Timeout guidance

Set gateclerk's exec timeout **larger** than mnotify's own network budget, then
treat a gateclerk timeout as an unknown outcome, not as a clean failure.

* **Mail:** Graph requests use a 30-second httpx timeout. mnotify can make up
  to three attempts, with 1 s and 2 s backoff, or `Retry-After` values capped at
  60 s each. Budget roughly 210 s worst case and use **300 s** for the exec
  timeout. Token acquisition may add its own network time before the POST.
* **Teams webhook:** 15-second timeout per attempt, up to three attempts, with
  linear 1 s/2 s backoff (a 429 `Retry-After` is honoured as sent). A **120 s**
  exec timeout is ample for the normal envelope.
* **Teams chat:** a Graph request with a 30-second timeout and up to three
  attempts; use the same **120 s** budget.

If gateclerk kills mnotify first, gateclerk owns an ambiguous result. That is
strictly worse than letting mnotify finish and report exit 5 or 0.

## 5. Container pattern

Two deployment shapes are legitimate; pontaje's plan should choose one.

**Same image (default).** Install the `mnotify` binary in gateclerk's image and
exec it directly. There is no extra hop, no shared volume negotiation, and one
lifecycle to upgrade. This is the simplest shape when gateclerk's image already
has a Python runtime and mnotify's dependencies.

**Sidecar (only with a stated reason).** Run mnotify in its own container and
have gateclerk `docker exec` into it. This isolates mnotify's Python runtime,
dependencies, and secret mounts from gateclerk's image. The cost is operational:
the body file must be visible inside the sidecar (a shared volume or a mount),
the sidecar must be running before the alert, and upgrades are a separate
lifecycle. Choose it only if the plan needs one of those separations; otherwise
keep the same-image shape.

Either way the call is synchronous. A `docker exec` exit status is mnotify's
exit status when the exec itself succeeded. Docker's own 125/126/127-style
errors mean the container or binary could not be invoked; they are
infrastructure failures outside this contract.

## 6. Concurrency and shared state

`[paths] state_dir` holds `counter.json`, the daily send counter. The check and
the write are separate steps:

1. `check` reads the counter and compares it with `limits.daily_max`;
2. after a successful send, `record_send` reads the counter again, adds one,
   writes a temporary file, fsyncs it, and atomically replaces the counter.

The temporary-file replace prevents a torn file. It does **not** lock the
read-modify-write across processes. Two mnotify processes that share a
`state_dir` can both read the same count, both send, and both write the same
incremented value, so the daily cap can be exceeded and the recorded count can
under-report.

The contract is therefore:

* **mnotify instances sharing a `state_dir` must not send concurrently.**
* Gateclerk must serialise the whole invocation (check, send, record) across
  every worker that shares that `state_dir`, for example with one `flock`
  around the exec. Locking only the counter write is too late.
* Alternatively, give each independent worker its own `state_dir`. That makes
  the cap per worker rather than global; decide that deliberately.

The audit file is appended one line at a time with `O_APPEND` and fsync, and it
contains no message bodies, so concurrent appends do not corrupt it. That does
not make the counter safe.

## 7. Secrets and configuration on Linux

`MICRO_NOTIFY_CONFIG` is the path to the config file. The config is mode 0600,
contains no secret values, and its `[paths]` audit and state dirs are absolute.
This variable is a path, never a value.

On Linux the secret material is supplied through paths as well:

* `MICRO_NOTIFY_SECRETS` — path to a secrets file;
* `MICRO_NOTIFY_SECRETS_DIR` — path to a directory of secrets, as an
  alternative to the single file.

The rule is the spine of this contract: **secrets never travel through argv or
environment values; only paths do.** Do not inline a token, webhook URL, client
secret, private key, or delegated cache into the command line, the config file,
the environment value, a log line, or an exception message. mnotify reads the
path it was given. The same rule holds on macOS, where the values live in the
keychain instead of a file.

A missing or unreadable secret is exit 4. The message names the account or
item, never the secret. The macOS `security(1)` status 44 for "item not found"
is an internal detail: it is mapped to exit 4 and never escapes as 44.

The Linux file/directory layout, permissions, and provisioning are owned by the
L1/L3 lanes and documented there; see section 9. Do not duplicate those paths
in gateclerk's plan without taking them from that document.

## 8. Audit

`[paths] audit` is a JSONL file, append-only, one line per attempt: sent,
refused, failed, and dry-run. It is the compliance story for "what did
gateclerk deliver?".

Each line carries metadata only: timestamp, channel, outcome, recipients,
sender/target, subject or title, attachment names and sizes, the Graph
request-id when one exists, and `body_sha256` plus `body_size` for the message
body. It never contains the message body, a token, a webhook URL, or a private
key. A webhook URL appears only through its masked form
(`https://host/***`).

Two consequences for gateclerk:

* Keep sensitive content in the body, where only its digest is stored. The
  subject and title are recorded verbatim; do not put a secret or personal
  data there.
* Join gateclerk's alert id to mnotify's line using your own log and, for
  mail, the returned `requestId`. mnotify does not know gateclerk's alert id.

## 9. Linux prerequisites

Linux prerequisites are maintained in two places, not here: the Linux section
of `docs/ADMIN-SETUP.md` (owned by the L1 lane) and `packaging/docker/` (owned
by the L3 lane). Follow those for the runtime, package layout, secret file
permissions, and container image. This document only defines how gateclerk
calls the resulting binary.

## 10. Questions for ecofire-pontaje-orch

The gateclerk side must settle these before the production plan is final:

1. **Sender and allowlist.** Which mailbox sends the alerts, and which
   domains/addresses go in `[allow]`? An empty allowlist refuses every
   recipient, so production must name at least the alert recipient domain.
2. **Recipient caps.** What are the per-alert recipient limits (to, cc, bcc,
   Teams DM UPNs), and which of those channels are allowed? These become
   `limits.max_recipients` and the allowlist entries.
3. **Teams or mail-only.** Are Teams channel alerts wanted, and if so which
   target names and kinds (channel webhook or DM)? Who creates and stores the
   workflow URLs as secrets?
4. **Exec timeout.** Does gateclerk accept 300 s for mail and 120 s for Teams,
   and what does its scheduler do on timeout? A kill must be treated as an
   unknown outcome, not a clean failure.
5. **Dedupe on exit 5.** What alert id and dedupe store let gateclerk decide
   whether a remote failure was actually delivered? Will it ever retry, and if
   so, only once after that check?
6. **Image strategy.** Same image or sidecar? If sidecar, where does the body
   file live, how is it mounted, and who starts/updates the container?
7. **Secrets provisioning.** Who creates the secrets file or directory on the
   production host, with which owner and modes, and who rotates it? This
   includes the config path and the `[paths]` state/audit locations.
8. **Concurrency.** Does gateclerk run one sender worker or several? If several
   share a `state_dir`, who owns the lock around the whole invocation, or does
   each worker get its own `state_dir`?
9. **Audit handling.** Where does the audit JSONL live, who ships or rotates it,
   and is subject/title content acceptable under the compliance policy?
10. **Daily cap.** What alert volume is expected, and should
    `limits.daily_max` be raised or lowered from the default before go-live?
