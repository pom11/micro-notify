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
import getpass
import re
from types import ModuleType

from .. import EXIT_OK, UsageError
from ..config import KIND_DM, load_config, with_team_target, without_team_target, write_config
from .. import secrets
from ..teams import (
    build_card,
    load_card_file,
    parse_facts,
    resolve_target,
)
from . import not_implemented, print_json, read_text_argument  # shared seam

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
    """Execute ``mnotify teams ...`` (build step 4)."""
    action = getattr(args, "teams_command", None)
    if action == "send":
        return _send(args)
    if action == "targets":
        return _targets(args)
    raise UsageError("a teams action is required: send | targets (see `mnotify teams --help`)")


# --- targets add | list | remove ---------------------------------------------
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def _validate_target_name(name: str) -> None:
    # TOML bare keys only: a dot would silently nest into another table.
    if not _NAME_RE.match(name):
        raise UsageError(
            f"invalid target name '{name}': use letters, digits, '_' or '-', "
            "starting with a letter or digit"
        )


def _targets(args: argparse.Namespace) -> int:
    action = getattr(args, "targets_command", None)
    if action == "add":
        return _targets_add(args)
    if action == "list":
        return _targets_list(args)
    if action == "remove":
        return _targets_remove(args)
    raise UsageError("a targets action is required: add | list | remove")


def _targets_add(args: argparse.Namespace) -> int:
    _validate_target_name(args.name)
    # Validate everything that can fail *before* asking for the secret: a
    # prompt followed by a failure trains operators to paste secrets anyway.
    config = load_config()
    url = getpass.getpass(
        f"Workflows webhook URL for teams target '{args.name}' "
        "(input hidden, stored in the keychain): "
    ).strip()
    if not url.startswith("https://"):
        raise UsageError(
            "webhook URL must be an https:// URL (Workflows webhook URLs are "
            "HTTPS; the value was not stored)"
        )
    secrets.set_secret(secrets.teams_account(args.name), url)
    write_config(with_team_target(config, args.name, args.kind))
    message = (
        f"teams target '{args.name}' ({args.kind}) saved; webhook URL stored in "
        f"keychain account '{secrets.teams_account(args.name)}'"
    )
    if getattr(args, "json", False):
        print_json({"ok": True, "outcome": "ok", "target": args.name, "kind": args.kind})
    else:
        print(message)
    return EXIT_OK


def _targets_list(args: argparse.Namespace) -> int:
    config = load_config()
    targets = [
        {
            "name": target.name,
            "kind": target.kind,
            "url": "present" if secrets.has(secrets.teams_account(target.name)) else "missing",
        }
        for target in config.teams_targets
    ]
    if getattr(args, "json", False):
        print_json({"ok": True, "outcome": "ok", "targets": targets})
    else:
        if not targets:
            print("no teams targets configured (add one with `mnotify teams targets add`)")
        for entry in targets:
            print(f"{entry['name']:<24} {entry['kind']:<8} {entry['url']}")
    return EXIT_OK


def _targets_remove(args: argparse.Namespace) -> int:
    config = load_config()
    if config.target(args.name) is None:
        raise UsageError(f"unknown teams target '{args.name}' (nothing removed)")
    secrets.delete(secrets.teams_account(args.name))
    write_config(without_team_target(config, args.name))
    if getattr(args, "json", False):
        print_json({"ok": True, "outcome": "ok", "removed": args.name})
    else:
        print(f"teams target '{args.name}' removed (config entry + keychain account)")
    return EXIT_OK


# --- send ---------------------------------------------------------------------
def _send(args: argparse.Namespace) -> int:
    # config (design §4 send order: config -> guard -> (dry-run stop) -> POST -> audit)
    config = load_config()
    target = resolve_target(config, args.target)

    # Usage-level checks, all before any guardrail or network work.
    if target.kind == KIND_DM and not args.to:
        raise UsageError(
            f"teams target '{target.name}' is a dm target: --to <upn> is required"
        )
    if target.kind == KIND_CHANNEL and args.to:
        raise UsageError(
            f"--to is only valid for dm targets; '{target.name}' is a channel target"
        )
    if args.card_file:
        if args.title or args.fact or args.link or args.link_title or args.text or args.text_file:
            raise UsageError(
                "--card-file posts the file verbatim and cannot be combined with "
                "--title/--text/--text-file/--fact/--link/--link-title"
            )
        card = load_card_file(args.card_file)
    else:
        text = read_text_argument(
            args.text, args.text_file, flag="--text", file_flag="--text-file"
        )
        if not text.strip():
            raise UsageError("empty message: pass --text / --text-file / stdin")
        card = build_card(
            text=text,
            title=args.title,
            facts=parse_facts(args.fact),
            link=args.link,
            link_title=args.link_title,
        )

    # guard -> (dry-run stop) -> POST -> audit is build step 2 territory:
    # guard.py and audit.py must exist and expose check()/mask_url(). Until
    # then nothing is guessed and nothing is sent.
    raise not_implemented("mnotify teams send (guardrails + audit stages)", "2")
