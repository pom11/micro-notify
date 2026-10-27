"""``mnotify doctor`` — argparse surface (design section 4).

Build step 5 (P5) owns :func:`run`: config readable, keychain items present,
token acquired, ``Mail.Send`` in the token's roles, every Teams target URL
present, and optionally one real test send.

Attributes P5 gets from this parser:

    args.send_test          str | None   (an address; performs a REAL send)
    args.json               bool

A real network call happens only when ``--send-test`` is given, and never in
tests — the shared socket-blocking harness makes that structural. Teams target
checks are presence-only (design section 4); a real Teams post is
``mnotify teams send`` itself.
"""

from __future__ import annotations

import argparse
from types import ModuleType

from . import not_implemented  # noqa: F401  (shared seam)

NAME = "doctor"
BUILD_STEP = "5"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    doctor = subparsers.add_parser(
        NAME,
        help="check config, keychain, token and Teams targets",
        description=(
            "Report config validity, keychain presence, token acquisition, the "
            "Mail.Send role and every Teams target URL. Checks print presence "
            "only — never a secret."
        ),
    )
    doctor.add_argument(
        "--send-test",
        metavar="ADDR",
        default=None,
        help="after the checks, send one real test mail to ADDR (exit 0 on success)",
    )
    doctor.add_argument("--json", action="store_true", help="machine-readable report on stdout")


def run(args: argparse.Namespace) -> int:
    """Implemented by build step 5 (doctor + setup + config show masking)."""
    raise not_implemented("mnotify doctor", BUILD_STEP)
