"""``mnotify teams ...`` — argparse surface (design section 4).

Build step 4 (P4) owns :func:`run`. Attribute names produced by these parsers
are the contract P4 codes against — they must not change:

    args.teams_command in {"send", "targets"}

  send:
    args.target                       str (positional)
    args.to                           str | None   (the DM UPN; required when kind dm)
    args.title                        str | None
    args.text / args.text_file        str | None   (else stdin)
    args.fact                         list[str]    each "k=v"
    args.link / args.link_title       str | None
    args.card_file                    str | None   (bypasses the card builder)
    args.dry_run / args.json          bool

  targets add|list|remove:
    args.targets_command in {"add", "list", "remove"}
    args.name / args.kind             str | None
    args.json                         bool

The webhook URL is a secret and therefore is never a flag on ``send``; it comes
from the keychain account ``teams:<target>`` (design section 3.2). ``targets add``
collects it with hidden input (``getpass``) inside P4's implementation.
"""

from __future__ import annotations

import argparse
from types import ModuleType

from . import not_implemented  # noqa: F401  (shared seam)

NAME = "teams"
BUILD_STEP = "4"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    teams = subparsers.add_parser(
        NAME,
        help="post Teams messages through Workflows webhooks",
        description="Post Teams messages through Workflows webhooks (design §3.2).",
    )
    teams_sub = teams.add_subparsers(dest="teams_command", metavar="<action>")

    send = teams_sub.add_parser("send", help="send one Teams message")
    send.add_argument("target", metavar="TARGET", help="configured target name from [teams.targets]")
    send.add_argument(
        "--to",
        metavar="UPN",
        default=None,
        help="recipient UPN; required when the target kind is 'dm'",
    )
    send.add_argument("--title", metavar="T", default=None, help="card title")
    body = send.add_mutually_exclusive_group()
    body.add_argument("--text", metavar="TEXT", help="markdown body as an argument")
    body.add_argument("--text-file", metavar="F", help="read the markdown body from file F")
    send.add_argument(
        "--fact",
        action="append",
        default=None,
        metavar="K=V",
        help="add a fact row; repeatable",
    )
    send.add_argument("--link", metavar="URL", default=None, help="one OpenUri action button URL")
    send.add_argument(
        "--link-title",
        metavar="T",
        default=None,
        help="label for --link (default: 'Open')",
    )
    send.add_argument(
        "--card-file",
        metavar="F",
        default=None,
        help="post the Adaptive Card JSON in file F verbatim (bypasses the builder)",
    )
    send.add_argument(
        "--dry-run",
        action="store_true",
        help="print the exact payload (webhook URL masked) and audit it; no network",
    )
    send.add_argument(
        "--json",
        action="store_true",
        help="machine-readable result on stdout",
    )

    targets = teams_sub.add_parser("targets", help="manage Teams targets")
    targets_sub = targets.add_subparsers(dest="targets_command", metavar="<action>")

    add = targets_sub.add_parser("add", help="create or update a target")
    add.add_argument("name", metavar="NAME", help="target name used by `teams send`")
    add.add_argument(
        "--kind",
        required=True,
        choices=["channel", "dm"],
        help="target kind (webhook URL is collected with hidden input, keychain only)",
    )
    add.add_argument("--json", action="store_true", help="machine-readable result on stdout")

    listp = targets_sub.add_parser("list", help="list targets (never the URL)")
    listp.add_argument("--json", action="store_true", help="machine-readable result on stdout")

    remove = targets_sub.add_parser("remove", help="delete a target and its keychain URL")
    remove.add_argument("name", metavar="NAME", help="target name to remove")
    remove.add_argument("--json", action="store_true", help="machine-readable result on stdout")


def run(args: argparse.Namespace) -> int:
    """Implemented by build step 4 (teams: targets, card builder, sends)."""
    raise not_implemented("mnotify teams", BUILD_STEP)
