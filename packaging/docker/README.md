# Docker image (Linux / Alpine)

First-party container recipe for running `mnotify` on a production Linux box,
including Alpine/musl. It installs the project into `/opt/mnotify-venv`, runs as
an unprivileged numeric UID (`10001:10001`), and bakes **no secrets** — config
and credentials arrive only through mounts at runtime. The macOS/Homebrew
distribution, the release script and `packaging/Formula` are unchanged.

Files:

```
Dockerfile                    pinned Alpine image, non-root runtime
Dockerfile.dockerignore       keeps the repo-root build context to install inputs
config.example.toml           placeholders only; [paths] explicitly under /data
README.md                     this file
```

## Build

Run from the repository root (the Dockerfile needs `pyproject.toml`, `README.md`
and `src/`):

```sh
docker build -f packaging/docker/Dockerfile -t mnotify:local .
```

The base is pinned to `alpine:3.20`; `apk` supplies Python 3.12.x and pip. The
build log prints the exact `python3 --version` and `python3 -m pip --version`
lines — copy those into the release record for the image you ship.

**Version record.** See [Container proof](#container-proof) below: the image is
built on `ubuntu-latest` by `.github/workflows/container-proof.yml`, which prints
the `python3 --version` and `python3 -m pip --version` lines into its job summary.
Copy them into the release record for the image you ship.

### Why single stage, and the fallback

`cryptography` is the only compiled runtime dependency (Rust extension). PyPI
publishes `musllinux_1_2` wheels for `cryptography` and `cffi` on x86_64 and
aarch64, and pip understands those tags, so this image installs wheels and keeps
`rust`, `cargo`, `gcc` and `musl-dev` out of the final layer. If a future release
has no musllinux wheel, switch to a two-stage build: stage 1 on Alpine adds
`rust cargo gcc musl-dev` and builds the wheels, stage 2 copies only
`/opt/mnotify-venv`. Do not add compilers to the shipped image as a shortcut.

## Run

```sh
# Entrypoint sanity; no config or secret is needed.
docker run --rm mnotify:local --version

# App-mode ready signal, with a real config and real file-backend secrets:
# expect exit 0, with doctor's token line reporting `warn` (not verifiable).
docker run --rm -it \
  -v "$PWD/packaging/docker/config.example.toml:/data/config.toml:ro" \
  -v "$PWD/secrets:/run/secrets/mnotify:ro" \
  mnotify:local doctor
```

`/data` is the container's HOME and the only writable directory (uid 10001).
Mount a volume there if audit/state must survive the container:

```sh
-v mnotify-data:/data
```

Audit and state paths come from `config.example.toml` (`/data/audit/sent.jsonl`,
`/data/state`); do not rely on the macOS `~/Library/...` defaults in a container.

## Config and secrets

Config is a bind mount at `/data/config.toml`, read-only:

```sh
MICRO_NOTIFY_CONFIG=/data/config.toml
```

Secrets are **never** in an image layer or in the config file. App mode
mounts them read-only through the file backend (L1, merged in `b89f25d`):

```sh
MICRO_NOTIFY_SECRETS=file
MICRO_NOTIFY_SECRETS_DIR=/run/secrets/mnotify
-v "$PWD/secrets:/run/secrets/mnotify:ro"
```

The file backend's permission contract (L1): root-owned `0444` files on a
read-only mount are accepted; group- or world-writable files are refused as
unreadable with exit 4. The Dockerfile sets both `MICRO_NOTIFY_SECRETS*`
variables and the backend is merged, so the image does read credentials — the
contract is what `.github/workflows/container-proof.yml` proves on real Linux.

The smoke tree below is **fabricated**; never point these commands at a real
keychain or the live `~/.config/mnotify/config.toml`:

```sh
mkdir -p secrets
printf '%s\n' 'CANARY-NOT-A-KEY' > secrets/graph.certificate_pem
printf '%s\n' 'AABBCCDDEEFF00112233445566778899AABBCCDD' \
  > secrets/graph.certificate_thumbprint
chmod 0600 secrets/*

# Permission proof (the same contract the CI job asserts):
chmod 0666 secrets/graph.certificate_pem
docker run --rm -it \
  -v "$PWD/packaging/docker/config.example.toml:/data/config.toml:ro" \
  -v "$PWD/secrets:/run/secrets/mnotify:ro" \
  mnotify:local doctor          # expect: unreadable, exit 4
chmod 0444 secrets/graph.certificate_pem
docker run --rm -it \
  -v "$PWD/packaging/docker/config.example.toml:/data/config.toml:ro" \
  -v "$PWD/secrets:/run/secrets/mnotify:ro" \
  mnotify:local doctor          # accepted; with fake creds, later auth failure
```

With fabricated credentials, a later `token`/`AADSTS...` failure (exit 4) is the
expected fail-closed result. A green `doctor` with `token: warn` needs real
tenant credentials and is the app-mode ready signal.

Delegated mode needs a writable secrets mount; that variant is card L2's docs,
not something this image changes.

## Container proof

The image is built and `mnotify` is exercised on real Linux by
`.github/workflows/container-proof.yml` — `pull_request` + `workflow_dispatch`,
`runs-on: ubuntu-latest`, `permissions: contents: read`. It is the only place the
image is ever built, because the maintainer's machine has no Docker daemon.

The job runs two proofs, both against fabricated credentials only:

1. **The permission contract.** With the secrets mounted `0444` on a read-only
   volume, `doctor --json` as uid `10001` reports `config`, `keychain` and `teams`
   passing and `token` failing closed on the fake credentials — **exit 4**. Flip
   one secret to `0666` and the same command still exits **4**, this time stopping
   at `keychain` because a group-writable secret is unreadable rather than absent.
   The job also asserts `id -u` inside the container prints `10001`.
2. **One real send.** `packaging/docker/ci/stub_webhook.py` serves TLS on the
   runner with a throwaway self-signed certificate for `127.0.0.1`; the container
   reaches it with `--network=host` and trusts it through `SSL_CERT_FILE`, which
   httpx honours — there is no TLS bypass, no `verify=False` and no plain-HTTP URL
   anywhere. `teams send alerts --text-file /ci/message.md --json` exits **0** and
   the stub records an `application/json` Adaptive Card carrying the message text.

The private key stays on the runner: only the certificate is mounted read-only,
and the job's last step proves the key is not reachable from inside the container.
Fixtures live in `packaging/docker/ci/` and contain canary values and placeholder
GUIDs only; `tests/test_leak_guard.py` scans them like any other tracked file.

| Case | Command | Exit |
| --- | --- | --- |
| secret `0666` | `doctor --json` | 4 (unreadable) |
| secret `0444`, fake credentials | `doctor --json` | 4 (token fails closed) |
| stub webhook reachable | `teams send alerts … --json` | 0 (one POST recorded) |

## Updating the image

1. Build and smoke on a host with Docker (the commands above).
2. Record the printed Python/pip versions and the build log tail in the release
   notes.
3. Re-run the permission proof (the CI job does it on every pull request).
4. Keep the Alpine tag pinned and bump it deliberately.
