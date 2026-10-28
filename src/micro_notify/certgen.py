"""Self-signed certificate generation for ``mnotify setup --gen-cert`` (design §6 step 1).

The operator's one-time Entra step is "upload the certificate public key" — so the
tool needs a key pair, and the private half must never leave the machine. This
module generates one locally with the macOS system tool and hands the caller three
pieces:

* ``private_key_pem``   -> keychain account ``graph.certificate_pem`` (design §3.4);
* ``certificate_thumbprint`` -> keychain account ``graph.certificate_thumbprint``,
  the SHA-1 fingerprint msal puts in the client-assertion ``x5t`` header;
* ``public_key_pem``    -> the X.509 certificate PEM the operator uploads to Entra
  (public material only — no private key bytes).

Why shell out to ``/usr/bin/openssl`` rather than the ``cryptography`` dependency:
``cryptography`` is already installed transitively (``msal`` -> ``PyJWT[crypto]`` ->
``cryptography``), but adding it as a *direct* dependency of this package buys
nothing here — a self-signed cert is one ``req -x509`` call, ``/usr/bin/openssl``
ships with macOS (design §3: "macOS only"), and the private key never has to pass
through a second library's key object. Keeping the dependency list at ``msal`` +
``httpx`` (design §3) is worth more than avoiding one subprocess call.

Nothing here touches the network: generating a key is local CPU work. The subprocess
is a single argv exec (never a shell string), the key is written into a 0700
temporary directory that is removed on every exit path, and a failure names the
*step* rather than echoing ``openssl``'s stderr, which can quote the arguments it
was given.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import UsageError

OPENSSL_BINARY = "/usr/bin/openssl"
OPENSSL_TIMEOUT = 60.0

# Design §6: Entra credentials should be rotated; 825 days is the maximum Entra
# accepts for a one-time upload, so the operator is not re-doing §6 every month.
DEFAULT_KEY_SIZE = 2048
DEFAULT_VALIDITY_DAYS = 825
DEFAULT_COMMON_NAME = "micro-notify"

# `openssl x509 -fingerprint -sha1` prints `SHA1 Fingerprint=AA:BB:...` (LibreSSL)
# or `sha1 Fingerprint=AA:BB:...` (OpenSSL 3). Only the hex after `=` is used.
_FINGERPRINT_RE = re.compile(r"Fingerprint=([0-9A-Fa-f:]{2,})\s*$", re.MULTILINE)


@dataclass(frozen=True)
class GeneratedCertificate:
    """The three outputs of one generation run. Only ``public_key_pem`` is written out."""

    private_key_pem: str
    public_key_pem: str
    certificate_thumbprint: str


def parse_fingerprint(stdout: str) -> str:
    """Return the SHA-1 thumbprint as upper-case hex, from ``openssl`` output.

    Raises :class:`UsageError` (exit 2) rather than guessing: a wrong thumbprint
    means every token request is rejected with an unhelpful AADSTS error, so a
    fingerprint we cannot read is a setup failure, not a warning.
    """
    match = _FINGERPRINT_RE.search(stdout or "")
    if not match:
        raise UsageError(
            "could not read the certificate fingerprint from openssl output "
            "(re-run `mnotify setup --gen-cert`)"
        )
    hexified = match.group(1).replace(":", "").upper()
    if len(hexified) != 40:
        raise UsageError(
            "certificate fingerprint is not a SHA-1 thumbprint "
            f"(expected 40 hex characters, got {len(hexified)})"
        )
    return hexified


def _run(
    args: Sequence[str], runner: Callable[..., subprocess.CompletedProcess] | None
) -> str:
    """Run one openssl argv and return stdout; failures become exit-2 messages."""
    argv = [str(a) for a in args]
    try:
        if runner is not None:
            result = runner(argv, capture_output=True, text=True, timeout=OPENSSL_TIMEOUT)
        else:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=OPENSSL_TIMEOUT, check=False
            )
    except FileNotFoundError as exc:
        raise UsageError(
            f"{OPENSSL_BINARY} not found — install the Xcode command line tools "
            "or generate a certificate yourself and store it with `mnotify setup`"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise UsageError("openssl timed out while generating the certificate") from exc
    except OSError as exc:
        raise UsageError(f"could not run {OPENSSL_BINARY} ({type(exc).__name__})") from exc
    if result.returncode != 0:
        # result.stderr deliberately unused: it can quote the argv it was handed.
        step = argv[1] if len(argv) > 1 else "openssl"
        raise UsageError(
            f"openssl {step} failed (exit {result.returncode}) — "
            "see `mnotify setup --help` for the --gen-cert requirements"
        )
    return result.stdout or ""


def generate_certificate(
    *,
    common_name: str = DEFAULT_COMMON_NAME,
    days: int = DEFAULT_VALIDITY_DAYS,
    key_size: int = DEFAULT_KEY_SIZE,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> GeneratedCertificate:
    """Create a self-signed certificate locally and return its three outputs.

    The private key is returned in memory for the caller to hand to the keychain —
    it is never printed, never logged, and the file it is generated into is deleted
    before this returns (including on the failure paths).
    """
    if not common_name or any(c.isspace() for c in common_name):
        raise UsageError("certificate common name must be a non-empty, space-free string")

    workdir = Path(tempfile.mkdtemp(prefix="mnotify-cert-"))
    os.chmod(workdir, 0o700)  # belt and braces: the key lands in here
    key_path = workdir / "key.pem"
    cert_path = workdir / "cert.pem"
    try:
        _run(
            [
                OPENSSL_BINARY,
                "req",
                "-x509",
                "-newkey",
                f"rsa:{key_size}",
                "-sha256",
                "-days",
                str(days),
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-subj",
                f"/CN={common_name}",
            ],
            runner,
        )
        fingerprint_output = _run(
            [OPENSSL_BINARY, "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha1"],
            runner,
        )
        thumbprint = parse_fingerprint(fingerprint_output)
        try:
            private_key_pem = key_path.read_text(encoding="utf-8")
            public_key_pem = cert_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise UsageError(
                f"could not read the generated certificate ({type(exc).__name__})"
            ) from exc
        return GeneratedCertificate(
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
            certificate_thumbprint=thumbprint,
        )
    finally:
        # Every exit path: a private key must not survive in a temp directory.
        shutil.rmtree(workdir, ignore_errors=True)


__all__ = [
    "DEFAULT_COMMON_NAME",
    "DEFAULT_KEY_SIZE",
    "DEFAULT_VALIDITY_DAYS",
    "OPENSSL_BINARY",
    "OPENSSL_TIMEOUT",
    "GeneratedCertificate",
    "generate_certificate",
    "parse_fingerprint",
]
