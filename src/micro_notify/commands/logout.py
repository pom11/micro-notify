"""``mnotify logout`` — remove the local delegated token cache (amendment A.2).

One job, stated honestly: delete keychain account ``graph.delegated_token_cache``.
That is **revocation level 1** in the amendment's two-level model — immediate and
local. It stops this Mac and reaches nothing else; the hard revoke is Entra's
"Revoke sessions" (plus removing the delegated consent), and the human output says
so, because presenting `logout` as a full revoke would be a security claim this
command cannot support.

Attributes:

    args.json   bool
"""

from __future__ import annotations

import argparse
import sys

from .. import EXIT_OK
from .. import delegation
from .. import secrets
from . import print_json

NAME = "logout"

# The sentence that keeps A.2's two levels from being blurred. Kept in one place
# so both output modes carry the same claim.
HARD_REVOKE_NOTE = (
    "this removed only the local cache; to revoke the session tenant-wide use "
    "Entra ID -> Users -> <user> -> Revoke sessions (and remove the delegated consent)"
)


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    logout = subparsers.add_parser(
        NAME,
        help="delete the local delegated token cache",
        description=(
            "Delete the delegated token cache from the macOS keychain (account "
            f"'{delegation.ACCOUNT_DELEGATED_CACHE}'). This is a local revoke only — "
            "see the output for the hard revoke."
        ),
    )
    logout.add_argument("--json", action="store_true", help="machine-readable result on stdout")


def run(args: argparse.Namespace) -> int:
    was_present = delegation.logout()
    if getattr(args, "json", False):
        print_json(
            {
                "ok": True,
                "outcome": "logged_out",
                "account": delegation.ACCOUNT_DELEGATED_CACHE,
                "service": secrets.SERVICE,
                "wasPresent": was_present,
                "scope": "local",
                "hardRevoke": "Entra ID Revoke sessions",
            }
        )
        return EXIT_OK
    if was_present:
        print(f"removed keychain account '{delegation.ACCOUNT_DELEGATED_CACHE}'")
    else:
        print(f"nothing to remove: '{delegation.ACCOUNT_DELEGATED_CACHE}' was not present")
    print(HARD_REVOKE_NOTE, file=sys.stderr)
    return EXIT_OK


__all__ = ["HARD_REVOKE_NOTE", "NAME", "add_parser", "run"]
