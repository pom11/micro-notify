"""``mnotify whoami`` — who is the cached delegated identity, if anyone.

Reads the keychain cache only (amendment A.4: "prints the signed-in upn, never a
token"). It does **not** acquire a token, does not contact Graph, and does not
validate the ID token's signature — it decodes the cached ID token's claims to name
the identity and reports the access token's expiry as a timestamp. The three values
it can print are UPN, mode and expiry; a token value has no path to either stream,
which the tests pin by asserting a canary token never appears in captured output.

Attributes:

    args.json   bool
"""

from __future__ import annotations

import argparse
from datetime import datetime

from .. import EXIT_OK
from .. import delegation
from . import print_json

NAME = "whoami"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    whoami = subparsers.add_parser(
        NAME,
        help="print the signed-in delegated identity (never a token)",
        description=(
            "Print the identity held in the delegated token cache, its mode and the "
            "access-token expiry. A token value is never printed."
        ),
    )
    whoami.add_argument("--json", action="store_true", help="machine-readable result on stdout")


def _expiry_text(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).isoformat(timespec="seconds")


def run(args: argparse.Namespace) -> int:
    result = delegation.whoami()
    if getattr(args, "json", False):
        print_json(
            {
                "ok": True,
                "outcome": "ok",
                "upn": result.upn,
                "mode": result.mode,
                "expiresAt": result.expires_at,
            }
        )
        return EXIT_OK
    line = f"{result.upn}  (mode: {result.mode})"
    if result.expires_at is not None:
        line += f"  access token expires {_expiry_text(result.expires_at)}"
    print(line)
    return EXIT_OK


__all__ = ["NAME", "add_parser", "run"]
