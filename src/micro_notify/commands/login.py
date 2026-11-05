"""``mnotify login`` — delegated (as-a-person) sign-in, design amendment A.4.

Device-code sign-in against our own registration (A.1: the Azure CLI's first-party
app cannot be used because it lacks ``Mail.Send`` / ``ChatMessage.Send``), with the
token cache landing in the secret store and nowhere else.

Attributes:

    args.no_prompt   bool   check the existing cache only; never prompt a human
    args.json        bool

The device-code prompt goes to **stderr** and the result line to **stdout**: with
``--json`` stdout must stay a single parseable document, and the code/URL is an
instruction to the person at the keyboard rather than the command's result. No
token value is ever printed, on either stream — :mod:`micro_notify.delegation`
never hands one to this module.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from .. import EXIT_OK
from .. import delegation
from . import print_json

NAME = "login"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    login = subparsers.add_parser(
        NAME,
        help="sign in as a person (delegated mode)",
        description=(
            "Sign in with the device-code flow and cache the delegated token in the "
            f"secret store (account '{delegation.ACCOUNT_DELEGATED_CACHE}'). "
            "No token is ever printed."
        ),
    )
    login.add_argument(
        "--no-prompt",
        action="store_true",
        help="never prompt: only verify that the cached sign-in still works (for scripts)",
    )
    login.add_argument("--json", action="store_true", help="machine-readable result on stdout")


def _expiry_text(epoch: float) -> str:
    """Expiry as local ISO-8601. A timestamp, never a token."""
    return datetime.fromtimestamp(epoch).isoformat(timespec="seconds")


def run(args: argparse.Namespace) -> int:
    result = delegation.login(interactive=not getattr(args, "no_prompt", False))
    if getattr(args, "json", False):
        print_json(
            {
                "ok": True,
                "outcome": "signed_in",
                "upn": result.upn,
                "mode": result.mode,
                "expiresAt": result.expires_at,
            }
        )
        return EXIT_OK
    line = f"signed in as {result.upn} (mode: {result.mode})"
    if result.expires_at is not None:
        line += f"; access token valid until {_expiry_text(result.expires_at)}"
    print(line)
    print(
        f"token cache: secret store account '{delegation.ACCOUNT_DELEGATED_CACHE}'; "
        "`mnotify logout` removes it",
        file=sys.stderr,
    )
    return EXIT_OK


__all__ = ["NAME", "add_parser", "run"]
