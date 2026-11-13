# syntax=docker/dockerfile:1
#
# micro-notify on Linux (Alpine/musl).
#
# Build from the repository root, not from this directory:
#   docker build -f packaging/docker/Dockerfile -t mnotify:local .
#
# Path taken: single stage. PyPI publishes musllinux_1_2 wheels for the only
# compiled runtime dependency, cryptography (and for cffi), on x86_64 and
# aarch64, so no Rust/musl-dev/gcc toolchain is needed in the final image.
# If a future dependency release has no musllinux wheel, use the fallback
# documented in packaging/docker/README.md: a first stage that builds wheels
# with rust/cargo/gcc/musl-dev and a second stage that copies only the venv.
#
# The base tag is pinned. The build prints the Python and pip versions that tag
# actually installs; record them in the release notes (see README).
FROM alpine:3.20

# Runtime packages only. py3-pip is needed to install into the venv; Alpine's
# python3 does not ship ensurepip, so the venv is created without pip and uses
# the distro pip through --system-site-packages.
RUN apk add --no-cache python3 py3-pip \
 && python3 --version \
 && python3 -m pip --version

WORKDIR /src
# Only the install inputs enter the image. Secrets and operator config are
# never COPYed/ADDed; they arrive at runtime through mounts (see README).
COPY pyproject.toml README.md ./
COPY src ./src

# Same virtualenv shape as the Homebrew formula: one venv, entrypoints in its
# bin/. `pip install .` is a normal (non-editable) install, so /src can go.
RUN python3 -m venv --without-pip --system-site-packages /opt/mnotify-venv \
 && /opt/mnotify-venv/bin/python -m pip install --no-cache-dir . \
 && rm -rf /src

# The console script is the image entrypoint and must resolve from PATH.
RUN ln -s /opt/mnotify-venv/bin/mnotify /usr/local/bin/mnotify

# Unprivileged, numeric UID, no login shell. /data is the only writable place,
# and it holds config + audit + state; the image layers hold no secrets.
RUN addgroup -g 10001 mnotify \
 && adduser -D -H -u 10001 -G mnotify -s /sbin/nologin -h /data mnotify \
 && mkdir -p /data \
 && chown 10001:10001 /data \
 && chmod 0700 /data

# Runtime contract. MICRO_NOTIFY_SECRETS* select the file backend (L1, merged in
# b89f25d): it reads one file per account from the mounted secrets directory and
# refuses anything a non-owner could have written. See packaging/docker/README.md
# for the contract the CI job proves on real Linux.
ENV HOME=/data \
    MICRO_NOTIFY_CONFIG=/data/config.toml \
    MICRO_NOTIFY_SECRETS=file \
    MICRO_NOTIFY_SECRETS_DIR=/run/secrets/mnotify

WORKDIR /data
USER 10001:10001

ENTRYPOINT ["mnotify"]
CMD ["--help"]
