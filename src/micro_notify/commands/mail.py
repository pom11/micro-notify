"""``mnotify mail send`` — argparse surface (design section 4).

Build step 3 (P3) owns :func:`run`. The parser, and the attribute names it
produces, are the contract P3 codes against — they must not change:

    args.command == "mail"
    args.mail_command == "send"
    args.to / args.cc / args.bcc      list[str] (to may be empty)
    args.subject                      str
    args.body / args.body_file        str | None   (else stdin)
    args.html                         bool
    args.attach                       list[str]
    args.reply_to                     str | None
    args.dry_run / args.json          bool

P3 order of operations is fixed by the card: config -> guard -> (dry-run stop)
-> token -> POST -> audit.
"""

from __future__ import annotations

import argparse
from types import ModuleType

from . import not_implemented, read_text_argument  # noqa: F401  (shared seam)

NAME = "mail"
BUILD_STEP = "3"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    mail = subparsers.add_parser(
        NAME,
        help="send mail through Microsoft Graph",
        description="Send mail through Microsoft Graph (app-only).",
    )
    mail_sub = mail.add_subparsers(dest="mail_command", metavar="<action>")

    send = mail_sub.add_parser("send", help="send one message")
    send.add_argument(
        "--to",
        action="append",
        default=None,
        metavar="ADDR",
        help="recipient; repeatable",
    )
    send.add_argument(
        "--cc",
        action="append",
        default=None,
        metavar="ADDR",
        help="carbon copy; repeatable",
    )
    send.add_argument(
        "--bcc",
        action="append",
        default=None,
        metavar="ADDR",
        help="blind carbon copy; repeatable",
    )
    send.add_argument("--subject", required=True, metavar="S", help="message subject")
    body = send.add_mutually_exclusive_group()
    body.add_argument("--body", metavar="TEXT", help="message body as an argument")
    body.add_argument("--body-file", metavar="F", help="read the message body from file F")
    send.add_argument(
        "--html",
        action="store_true",
        help="body is HTML (default: text/plain)",
    )
    send.add_argument(
        "--attach",
        action="append",
        default=None,
        metavar="F",
        help="attach file F; repeatable (total size capped by limits.max_attach_mb)",
    )
    send.add_argument(
        "--reply-to",
        metavar="R",
        default=None,
        help="Reply-To address (default: mail.default_reply_to)",
    )
    send.add_argument(
        "--dry-run",
        action="store_true",
        help="print the exact payload (secrets masked) and audit it; no token, no network",
    )
    send.add_argument(
        "--json",
        action="store_true",
        help="machine-readable result on stdout",
    )


def run(args: argparse.Namespace) -> int:
    """Implemented by build step 3 (mail: msal token + Graph sendMail)."""
    if getattr(args, "mail_command", None) != "send":
        raise not_implemented("mnotify mail", BUILD_STEP)
    raise not_implemented("mnotify mail send", BUILD_STEP)
