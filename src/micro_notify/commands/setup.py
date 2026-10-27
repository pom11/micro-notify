"""``mnotify setup`` — argparse surface (design section 4, §6 step 1).

Build step 5 (P5) owns :func:`run`: interactive tenant/client/sender questions,
optional local certificate generation (``--gen-cert``), and keychain storage of
the PEM/thumbprint or the client secret (design section 3.4 account names).

Attributes P5 gets from these parsers:

    args.setup_command          "run" when `mnotify setup` is used bare
    args.tenant_id / args.client_id / args.sender / args.auth
    args.reply_to               str | None
    args.gen_cert               bool
    args.allow_domain           list[str]
    args.force                  bool
    args.json                   bool

Non-interactive flags exist so an agent can drive setup without a TTY; the
secret itself is still only ever accepted via hidden input (:mod:`getpass`) or
generated locally, never as a flag value (it would land in shell history).
"""

from __future__ import annotations

import argparse
from types import ModuleType

from . import not_implemented  # noqa: F401  (shared seam)

NAME = "setup"
BUILD_STEP = "5"


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


def run(args: argparse.Namespace) -> int:
    """Implemented by build step 5 (doctor + setup + config show masking)."""
    raise not_implemented("mnotify setup", BUILD_STEP)
