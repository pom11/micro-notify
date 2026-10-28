"""``mnotify setup`` — write the config, store the credential (design §4, §6 step 1).

Two jobs, one command:

1. write ``~/.config/mnotify/config.toml`` with mode 0600 through
   :func:`micro_notify.config.write_config` — a file whose schema (design §3.4)
   cannot hold a secret, and which this module additionally validates so that no
   URL-shaped value can be written into it at all;
2. put the credential in the keychain (design §3.4): with ``--gen-cert`` a key pair
   is generated locally by :mod:`micro_notify.certgen` and the *public* PEM is
   written next to the config for the operator to upload to Entra (§6 step 1); with
   ``auth = "secret"`` the client secret is read through hidden input.

Non-interactive safety
----------------------
Every prompt has a flag (``--tenant-id`` / ``--client-id`` / ``--sender`` /
``--auth`` / ``--reply-to`` / ``--allow-domain``), so CI can drive the whole command
without a TTY. The credential deliberately has **no flag**: a secret on the command
line lands in shell history and in ``ps`` output. Without a TTY it is read from a
piped stdin line instead, which is how a CI job or an agent hands it over.

A secret, token, private key or webhook URL never reaches stdout, stderr, the config
file or the ``--json`` document. What is printed is account *names*, the values the
operator just supplied, and the certificate fingerprint Entra asks to be verified.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import uuid
from collections.abc import Callable
from pathlib import Path

from .. import EXIT_OK, UsageError
from .. import certgen
from .. import secrets
from ..config import (
    AUTH_CERTIFICATE,
    AUTH_MODES,
    AUTH_SECRET,
    CONFIG_ENV_VAR,
    AllowConfig,
    Config,
    LimitsConfig,
    MailConfig,
    PathsConfig,
    TeamTarget,
    config_path,
    load_config,
    write_config,
)
from . import print_json

NAME = "setup"
BUILD_STEP = "5"

# The public certificate the operator uploads to Entra (§6 step 1). It lives beside
# the config so a listing of the config directory shows what is still pending.
PUBLIC_CERT_FILENAME = "entra-certificate.pem"
PUBLIC_CERT_MODE = 0o600
CONFIG_DIR_MODE = 0o700

URL_SCHEMES = ("http://", "https://", "file://", "smb://", "ftp://")


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    setup = subparsers.add_parser(
        NAME,
        help="create the config file and store credentials in the keychain",
        description=(
            "Write ~/.config/mnotify/config.toml (0600) and store the credential "
            "in the macOS keychain. Prompts use hidden input for secrets."
        ),
    )
    setup.add_argument(
        "--gen-cert",
        action="store_true",
        help="generate a local certificate + private key and store them in the keychain (design §6 step 1)",
    )
    setup.add_argument("--tenant-id", metavar="GUID", default=None, help="Entra tenant ID")
    setup.add_argument("--client-id", metavar="GUID", default=None, help="Entra app (client) ID")
    setup.add_argument("--sender", metavar="ADDR", default=None, help="mailbox to send from")
    setup.add_argument(
        "--auth",
        choices=["certificate", "secret"],
        default=None,
        help="credential kind stored in the keychain",
    )
    setup.add_argument(
        "--reply-to",
        metavar="ADDR",
        default=None,
        help="default_reply_to written into [mail]",
    )
    setup.add_argument(
        "--allow-domain",
        action="append",
        default=None,
        metavar="DOMAIN",
        help="write an allowed recipient domain; repeatable (empty default refuses all)",
    )
    setup.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing config file",
    )
    setup.add_argument("--json", action="store_true", help="machine-readable result on stdout")


# --- Prompt plumbing ---------------------------------------------------------
def _is_tty() -> bool:
    """Whether a human is on the other end of stdin. A seam for the tests."""
    return sys.stdin is not None and sys.stdin.isatty()


def _refuse_url(label: str, value: str) -> None:
    """No URL-shaped string may be written into the config (design §3.2 / §3.4).

    A Workflows webhook URL carries its signature in the path, so it is a secret and
    belongs in the keychain. The message never echoes the value — echoing it would
    print the very secret we are refusing.
    """
    lowered = value.strip().lower()
    if any(lowered.startswith(scheme) for scheme in URL_SCHEMES) or "://" in lowered:
        raise UsageError(
            f"{label} looks like a URL; a webhook URL is a secret and belongs in the "
            "keychain, not in the config file (use `mnotify teams targets add`)"
        )


def _ask(
    flag: str,
    question: str,
    *,
    validate: Callable[[str], str] | None = None,
    default: str | None = None,
) -> str:
    """Prompt for one non-secret value; without a TTY, name the missing flag."""
    if not _is_tty():
        raise UsageError(
            f"missing --{flag} and there is no terminal to ask for it (pass the flag "
            f"to run non-interactively; the config path comes from {CONFIG_ENV_VAR})"
        )
    suffix = f" [{default}]" if default else ""
    while True:
        raw = input(f"{question}{suffix}: ").strip()
        if not raw and default is not None:
            raw = default
        if not raw:
            print("  (an answer is required)", file=sys.stderr)
            continue
        return validate(raw) if validate else raw


def _valid_guid(label: str, raw: str) -> str:
    """A GUID, or an error naming which flag supplied the bad value."""
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError) as exc:
        raise UsageError(f"{label} must be a GUID, e.g. 00000000-0000-0000-0000-000000000000") from exc


def _valid_address(label: str, raw: str) -> str:
    _refuse_url(label, raw)
    if "@" not in raw or raw.count("@") != 1:
        raise UsageError(f"{label} must be a mailbox address, e.g. noreply@example.com")
    return raw


def _valid_domain(raw: str) -> str:
    _refuse_url("--allow-domain", raw)
    if "@" in raw or any(c.isspace() for c in raw):
        raise UsageError(f"--allow-domain must be a bare domain, not an address: {raw!r}")
    return raw.lower()


def _valid_auth(raw: str) -> str:
    value = raw.strip().lower()
    if value not in AUTH_MODES:
        raise UsageError(f"auth must be one of: {', '.join(AUTH_MODES)}")
    return value


# --- Credential handling -----------------------------------------------------
def _read_secret_from_terminal() -> str:
    """Hidden-input intake for the client secret.

    There is deliberately **no** ``--client-secret`` flag and no stdin/env path: a
    secret passed as an argument is visible in shell history and in process listings,
    and design §3.4 rules out secrets via env in v1. So a secret needs a terminal;
    CI and agents use ``--gen-cert``, whose credential is generated locally instead.
    """
    if not _is_tty():
        raise UsageError(
            "--auth secret needs a terminal for hidden input and none is attached. "
            "For a non-interactive setup use `mnotify setup --gen-cert` (the key is "
            "generated locally, never typed); run `mnotify setup --auth secret` once "
            "at a terminal if the tenant must use a client secret"
        )
    secret = getpass.getpass("Client secret (input hidden): ")
    if not secret.strip():
        raise UsageError("client secret was empty")
    return secret.strip()


def _store_certificate(*, generate: bool, machine: bool) -> bool:
    """Store the certificate credential, generating one when asked. Returns generated."""
    if not generate:
        if not machine:
            print(
                "no certificate generated: store your own key and thumbprint under "
                f"'{secrets.ACCOUNT_CERT_PEM}' and '{secrets.ACCOUNT_CERT_THUMBPRINT}' "
                f"(service '{secrets.SERVICE}'), or re-run with --gen-cert"
            )
        return False

    generated = certgen.generate_certificate()
    secrets.set_secret(secrets.ACCOUNT_CERT_PEM, generated.private_key_pem)
    secrets.set_secret(secrets.ACCOUNT_CERT_THUMBPRINT, generated.certificate_thumbprint)
    public_path = _write_public_certificate(generated.public_key_pem)
    if not machine:
        print(
            f"stored '{secrets.ACCOUNT_CERT_PEM}' and "
            f"'{secrets.ACCOUNT_CERT_THUMBPRINT}' in the keychain (service "
            f"'{secrets.SERVICE}')"
        )
        # The fingerprint is what Entra displays, so printing it lets the operator
        # confirm both sides hold the same certificate. It is not a secret.
        print(f"certificate fingerprint (SHA-1): {generated.certificate_thumbprint}")
        print(f"upload this public certificate in Entra (design §6 step 1): {public_path}")
    return True


def _write_public_certificate(public_key_pem: str) -> Path:
    """Write only the public certificate, mode 0600, beside the config.

    The private half never reaches this function: the caller holds it in memory only
    long enough to hand it to :func:`micro_notify.secrets.set_secret`.
    """
    directory = config_path().parent
    directory.mkdir(parents=True, exist_ok=True, mode=CONFIG_DIR_MODE)
    target = directory / PUBLIC_CERT_FILENAME
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PUBLIC_CERT_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(public_key_pem)
    os.chmod(str(target), PUBLIC_CERT_MODE)
    return target


# --- Preserving what setup does not own --------------------------------------
def _previous_config(path: Path) -> Config | None:
    """The earlier config when it parses; None when absent or unusable.

    A config that cannot be parsed has nothing worth preserving, so a ``--force``
    rewrite proceeds from defaults rather than refusing the rewrite the operator
    just asked for.
    """
    if not path.exists():
        return None
    try:
        return load_config(path)
    except UsageError:
        return None


# --- Assembly ----------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    """``mnotify setup`` (design §4, §6 step 1). Nothing is sent and no secret is printed."""
    machine = bool(getattr(args, "json", False))
    path = config_path()

    # Refuse to clobber the operator's file before any side effect at all.
    if path.exists() and not args.force:
        raise UsageError(
            f"config file already exists: {path} (re-run with --force to overwrite; "
            "[paths] and Teams targets are preserved)"
        )
    previous = _previous_config(path)

    # --- [mail] values: flag first, then prompt, then fail naming the flag ----
    tenant_id = (
        _valid_guid("--tenant-id", args.tenant_id)
        if args.tenant_id is not None
        else _ask("tenant-id", "Entra tenant ID",
                  validate=lambda raw: _valid_guid("--tenant-id", raw))
    )
    client_id = (
        _valid_guid("--client-id", args.client_id)
        if args.client_id is not None
        else _ask("client-id", "Entra app (client) ID",
                  validate=lambda raw: _valid_guid("--client-id", raw))
    )
    sender = (
        _valid_address("--sender", args.sender)
        if args.sender is not None
        else _ask(
            "sender",
            "Sender mailbox (e.g. noreply@example.com)",
            validate=lambda raw: _valid_address("--sender", raw),
        )
    )
    auth = (
        _valid_auth(args.auth)
        if args.auth is not None
        else _ask(
            "auth",
            f"Credential kind ({' or '.join(AUTH_MODES)})",
            validate=_valid_auth,
            default=AUTH_CERTIFICATE,
        )
    )
    reply_to = args.reply_to or ""
    if reply_to:
        _valid_address("--reply-to", reply_to)
    domains = tuple(_valid_domain(domain) for domain in (args.allow_domain or ()))

    generate = bool(args.gen_cert)
    if auth == AUTH_CERTIFICATE and not generate and _is_tty() and not machine:
        answer = _ask("gen-cert", "Generate a new self-signed certificate now? [y/N]", default="n")
        generate = answer.strip().lower() in ("y", "yes")

    # The credential is stored before the config exists: a setup that cannot store its
    # credential should not leave behind a config claiming that it did.
    if auth == AUTH_SECRET:
        secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, _read_secret_from_terminal())
        if not machine:
            print(
                f"stored '{secrets.ACCOUNT_CLIENT_SECRET}' in the keychain "
                f"(service '{secrets.SERVICE}')"
            )
    else:
        generate = _store_certificate(generate=generate, machine=machine)

    # --- write the config last: every value in it has been validated ----------
    paths = previous.paths if previous is not None else PathsConfig()
    targets: tuple[TeamTarget, ...] = previous.teams_targets if previous is not None else ()
    config = Config(
        mail=MailConfig(
            tenant_id=tenant_id,
            client_id=client_id,
            sender=sender,
            auth=auth,
            default_reply_to=reply_to,
        ),
        allow=AllowConfig(domains=domains),
        limits=LimitsConfig(),
        paths=paths,
        teams_targets=targets,
        source_path=path,
    )
    written_path = write_config(config, path)

    if machine:
        print_json(
            {
                "ok": True,
                "outcome": "configured",
                "configPath": str(written_path),
                "auth": auth,
                "certificateGenerated": generate,
                "keychain": [
                    {"account": account, "service": secrets.SERVICE, "present": True}
                    for account in config.keychain_accounts()
                    if secrets.has(account)
                ],
            }
        )
    else:
        print(f"wrote {written_path} (mode 0600)")
        print(
            "next: `mnotify doctor` to check it, then the admin steps in "
            "docs/ADMIN-SETUP.md (design §6)"
        )
    return EXIT_OK


__all__ = ["BUILD_STEP", "NAME", "PUBLIC_CERT_FILENAME", "add_parser", "run"]
