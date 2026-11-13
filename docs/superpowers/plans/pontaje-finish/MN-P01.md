# MN-P01 — container proof: the Alpine image builds and sends one Teams alert in CI

Repo: `/Users/desac/dev/micro-notify` (package `micro_notify`, CLI `mnotify`). One deliverable,
~30 tool calls. Board: `micro-notify`.

## WHY

Operator ruling 2026-11-13: MN-P01 is **only the container proof**. The `env` secret backend is
dropped — secret values never travel through the environment; the container story is the merged
**file** backend plus mounted secret files.

What is already merged and must NOT be redone: `b89f25d` #43 (Linux file backend, fail-closed),
`afeab10` #45 (delegated mode on it), `8e0bd41` #42 (Alpine image, non-root, secrets mounted).

What has never happened: **the image has never been built and mnotify has never run on Linux.**
Every existing test is macOS-only, and `tests/test_docker_packaging.py` asserts only the
*Dockerfile / README text*. `packaging/docker/README.md` says so in its own words: "This worktree
had no reachable Docker daemon, so no build was run here and no versions are asserted."

Downstream waiting on this: gateclerk GC-P16a..c and, through GC-P21, gate G3 (alerts proven on the
demo device). There is no Docker daemon on the orchestrator's Mac and the Sparks are off limits for
raw docker, so the proof runs as a **GitHub Actions job on `ubuntu-latest`** in this repo.

## VERIFY (do this first, before writing anything — R5)

1. `grep -n "no build was run here" packaging/docker/README.md` — present.
2. `ls .github` — no workflows exist yet (orch verified 2026-11-13).
3. `gh api repos/pom11/micro-notify/actions/permissions` — Actions must be enabled. Orch verified
   `{"enabled": true, "allowed": "all"}` on 2026-11-13. If it is disabled, STOP and block
   (needs_input) — do not fake the proof another way.
4. `src/micro_notify/teams.py`, `webhook_url()` (~line 224): it does NOT enforce a URL scheme; the
   `https://` rule is only in `src/micro_notify/commands/teams.py:221` (`targets add`). So a stub URL
   written directly into the secrets dir is read and POSTed.
5. `python -c "from micro_notify import secrets_file; print(secrets_file.account_filename('teams:alerts'))"`
   → `teams__alerts`.
If any of these is false in the tree, stop and close the card with the evidence.

## FILES

May create: `.github/workflows/container-proof.yml`, `packaging/docker/ci/stub_webhook.py`,
`packaging/docker/ci/config.toml`, `packaging/docker/ci/message.md`,
`docs/superpowers/plans/pontaje-finish/MN-P01.md` (this card, verbatim) and `INDEX.md` next to it
(one row, `depends on: -`).
May edit: `packaging/docker/README.md`, `tests/test_docker_packaging.py`.
READ only: `packaging/docker/Dockerfile`, `packaging/docker/config.example.toml`,
`src/micro_notify/**`, `tests/test_leak_guard.py`, `tests/test_hermeticity.py`, `src/micro_notify/commands/doctor.py`.
Must NOT change: `src/micro_notify/**`, `packaging/docker/config.example.toml`,
`packaging/docker/Dockerfile`, the formula, `scripts/release.py`, `pyproject.toml` (no new deps).

## CHANGE

`.github/workflows/container-proof.yml` — `on: pull_request` + `workflow_dispatch`,
`runs-on: ubuntu-latest`, `permissions: contents: read`, one job `container-proof`:

1. **Build.** `docker build -f packaging/docker/Dockerfile -t mnotify:ci .` from the repo root. The
   build prints `python3 --version` and `python3 -m pip --version`; capture both into `$GITHUB_STEP_SUMMARY`.
2. **Fixtures (fake values only).** A temp secrets dir with exactly the three files the file backend
   expects — `graph.certificate_pem`, `graph.certificate_thumbprint`, `teams__alerts` — mode `0444`,
   dir `0755`. Contents: canary strings (`CANARY-NOT-A-KEY`, 40 hex chars, and the stub URL). The
   yaml must contain **no** `-----BEGIN ... PRIVATE KEY-----` header, no GUID other than the
   documented placeholders (`00000000-...`, `ffff...`), and no email domain other than
   `example.com` / `contoso.com` — `tests/test_leak_guard.py` runs over tracked files.
   `packaging/docker/ci/config.toml` (committed, placeholders, copied in shape from
   `config.example.toml`) with `[teams.targets.alerts] kind = "channel"` enabled and `[paths]`
   under `/data`. `packaging/docker/ci/message.md` is the alert body.
3. **Proof A — the permission contract, on real Linux.** `docker run --rm --user 10001:10001
   -v $PWD/packaging/docker/ci/config.toml:/data/config.toml:ro -v $SECRETS:/run/secrets/mnotify:ro
   -w /data mnotify:ci doctor --json`, with the secrets mount `chmod 0666` on one file first:
   assert **exit 4** (unreadable). Restore `0444`, run again: assert **exit 4** — the `token` check
   fails closed with fake credentials — and that the `config`, `keychain` and `teams` rows came back
   ok. Take the row/status field names from `commands/doctor.py` (`record` / `emit`); do not invent
   the JSON shape. Also assert `id -u` prints `10001` from inside the container.
4. **Proof B — one real alert send, no Teams involved.** `packaging/docker/ci/stub_webhook.py`:
   stdlib `http.server` over **TLS** (wrap with `ssl.SSLContext`), `do_POST` writes the raw body +
   content type to a host file and replies `202`. The cert is generated in the job
   (`openssl req -x509 ... -addext "subjectAltName=IP:127.0.0.1"`); the **key stays on the runner**,
   only the certificate is mounted into the container. The stub listens on the runner, the container
   reaches it with `--network=host` (Linux-only, fine on ubuntu-latest), and trusts it via
   `-e SSL_CERT_FILE=/ci/stub-cert.pem`. `teams__alerts` holds `https://127.0.0.1:<port>/hub/x`.
   Then `docker run ... mnotify:ci teams send alerts --text-file /ci/message.md --json` → assert
   **exit 0**, and assert the stub's received file exists on the runner, contains the message text
   and posts `application/json`. Print the received payload in the job log.
   **If httpx will not honour `SSL_CERT_FILE`, do NOT add a TLS bypass, `verify=False`, an http://
   URL or a new flag to the product.** Record it as `LEFT:` and report — that is a finding, not a
   thing to work around.
5. **README.** Replace the "no reachable Docker daemon … no versions are asserted" paragraph with
   what actually ran: image tag, the printed python/pip versions, the Actions run id/URL, the three
   exit codes, the date. Fix the two stale "this branch does not implement the backend / until L1
   merges" sentences (one in the README, one in the Dockerfile comment — the Dockerfile comment is
   the only Dockerfile change allowed). Keep every string `test_readme_documents_build_run_and_permission_smoke` pins.

## TESTS

Extend `tests/test_docker_packaging.py` (static only — the offline suite stays hermetic, no docker,
no network):
- the workflow exists, triggers on `pull_request`, sets `permissions: contents: read`, builds with
  `-f packaging/docker/Dockerfile`, runs the container with `--user 10001:10001`, mounts the config
  and the secrets read-only, and checks the exit codes;
- the workflow yaml has no PEM header, no non-placeholder GUID, no non-placeholder email domain
  (reuse the patterns from `tests/test_leak_guard.py`);
- `packaging/docker/ci/config.toml` loads through the real product loader and keeps `[paths]` under
  `/data`; `ci/stub_webhook.py` compiles and defines `do_POST`; the private key is not mounted.
- the README records a real build (assert the new "actually ran" section) **and** still contains all
  previously pinned strings.

## GATE

From the worktree root:

```
uv run --extra test pytest -q
```

Baseline on `main` @ `afeab10`: **1263 passed** in ~12s (orch, 2026-11-13). Then push, open the PR,
and the `container-proof` Actions job must be **green on the PR head**. Never run the workflow
locally with docker; there is no daemon here.

## ACCEPT

1. `uv run --extra test pytest -q` green (report the count).
2. `container-proof` green on the PR, with the build's python/pip versions and the stub's received
   payload visible in the job log.
3. `packaging/docker/README.md` no longer says "no build was run here" and states what ran.
4. Product code, `config.example.toml` and `pyproject.toml` unchanged (`git diff --stat` proves it);
   no TLS bypass anywhere; no new dependency; no third secret backend.
5. `git status --short` empty after the commit.

## OUT

No `env` backend (operator ruling). No product-code change, no behaviour change, no new CLI flag.
No real Teams webhook, no real mail, no real tenant id, no LIVE (R7). No edits in other repos —
gateclerk's pin bump is theirs.

## HANDOFF

`DONE:` the merge sha · `PR #N` · Actions run id + conclusion · README line replaced · pass count.
`LEFT:` anything undone, as `file:line + next step`. Expected LEFT and explicitly NOT yours: "bump
`ARG MICRO_NOTIFY_SHA` in `~/dev/gateclerk/deploy/Dockerfile` to the merge sha" — name it, do not
do it.

## MERGE

Operator instruction 2026-11-13: **you squash-merge your own PR into `main`** when the offline gate
and the Actions job are both green and the PR is mergeable (this overrides this board's usual
orch-merges rule for this card). Never force-push, never merge with a red or skipped Actions job.
Quote the merge sha from `gh pr view --json state,mergedAt,mergeCommit`; the orch re-runs the gate
on `main` afterwards and reports the image/sha gateclerk must pin.
