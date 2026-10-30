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
import json
import re
from types import ModuleType

from .. import (
    EXIT_OK,
    DailyCapReached,
    GuardRefusal,
    RemoteError,
    UsageError,
)
from .. import audit, guard
from ..config import KIND_CHANNEL, KIND_DM, load_config, with_team_target, without_team_target, write_config
from .. import secrets
from ..teams import (
    build_card,
    build_channel_payload,
    build_dm_payload,
    load_card_file,
    parse_facts,
    post_card,
    resolve_target,
    webhook_url,
)
from . import print_json, read_text_argument  # shared seam

# D3 (chat targets) — appended as new lines so every import line above stays
# byte-identical: this file is append-only for the delegated phase.
from ..config import KIND_CHAT, MAIL_MODE_DELEGATED, mask_chat_id  # noqa: E402
from ..teams import (  # noqa: E402
    build_chat_payload,
    get_my_chats,
    new_attachment_id,
    post_chat_message,
    require_delegated_mode,
    validate_chat_id,
)

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

    # --- chats (D3: delegated Graph chat targets; appended, no edits above) ---
    chats = teams_sub.add_parser(
        "chats",
        help="list and register Teams chats for `kind = chat` targets (delegated)",
        description=(
            "Register chat targets from the signed-in person's Teams chats "
            "(Graph /me/chats; requires `mnotify login`)."
        ),
    )
    chats_sub = chats.add_subparsers(dest="chats_command", metavar="<action>")

    chats_list = chats_sub.add_parser("list", help="list chats (id masked in human output)")
    chats_list.add_argument("--json", action="store_true", help="machine-readable result on stdout")

    chats_add = chats_sub.add_parser("add", help="register a chat target by alias")
    chats_add.add_argument("name", metavar="NAME", help="target alias used by `teams send`")
    chats_add.add_argument(
        "chat_id",
        metavar="CHAT_ID",
        nargs="?",
        default=None,
        help="Teams conversation id (19:...@thread.v2); omit with --pick",
    )
    chats_add.add_argument(
        "--pick",
        action="store_true",
        help="list the chats and choose one by number instead of pasting an id",
    )
    chats_add.add_argument("--json", action="store_true", help="machine-readable result on stdout")


def run(args: argparse.Namespace) -> int:
    """Execute ``mnotify teams ...`` (build step 4)."""
    action = getattr(args, "teams_command", None)
    if action == "send":
        return _send(args)
    if action == "targets":
        return _targets(args)
    if action == "chats":
        return _chats(args)
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

    # D3: a chat target is a Graph operation, not a webhook — its whole flow
    # (usage checks, guard, POST, audit) lives in _send_chat. Added as a new
    # branch so the channel/dm path below stays byte-identical.
    if target.kind == KIND_CHAT:
        return _send_chat(args, config, target)

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
        # No builder text exists: the audit digest covers the card JSON we post.
        body_text = json.dumps(card, ensure_ascii=False, sort_keys=True)
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
        body_text = text

    # --- guard (design §3.3: every guardrail before any network call) ---------
    # A channel post has no recipient list, so only the daily cap applies to it;
    # a DM UPN must satisfy [allow] like any other recipient.
    verdict = guard.check(
        config, dm_recipients=[args.to] if target.kind == KIND_DM else ()
    )
    if verdict.status != guard.OK:
        audit.record(
            config,
            channel=audit.CHANNEL_TEAMS,
            outcome=audit.REFUSED,
            recipients=[args.to] if target.kind == KIND_DM else (),
            target=target.name,
            title=args.title,
            **_body_field(body_text),
        )
        refusal = DailyCapReached if verdict.status == guard.CAP_REACHED else GuardRefusal
        raise refusal(verdict.reason)

    # The webhook URL is resolved only once the send is actually allowed.
    url = webhook_url(target.name)
    payload = (
        build_dm_payload(args.to, card)
        if target.kind == KIND_DM
        else build_channel_payload(card)
    )
    url_label = audit.mask_url(url)

    # --- dry-run stop (design §4: prints the payload, secrets masked, no HTTP) -
    if args.dry_run:
        _print_dry_run(target.kind, url_label, payload, args.to, json_mode=args.json)
        audit.record(
            config,
            channel=audit.CHANNEL_TEAMS,
            outcome=audit.DRY_RUN,
            recipients=[args.to] if target.kind == KIND_DM else (),
            target=target.name,
            title=args.title,
            **_body_field(body_text),
        )
        return EXIT_OK

    # --- POST, then audit; a failed send costs no daily budget ----------------
    try:
        result = post_card(url, payload, url_label=url_label)
    except RemoteError:
        audit.record(
            config,
            channel=audit.CHANNEL_TEAMS,
            outcome=audit.FAILED,
            recipients=[args.to] if target.kind == KIND_DM else (),
            target=target.name,
            title=args.title,
            **_body_field(body_text),
        )
        raise
    guard.record_send(config)
    audit.record(
        config,
        channel=audit.CHANNEL_TEAMS,
        outcome=audit.SENT,
        recipients=[args.to] if target.kind == KIND_DM else (),
        target=target.name,
        title=args.title,
        **_body_field(body_text),
    )
    recipients = [args.to] if target.kind == KIND_DM else []
    if args.json:
        print_json(
            {
                "ok": True,
                "outcome": "sent",
                "target": target.name,
                "recipients": recipients,
                "status": result.status,
            }
        )
    else:
        print(f"teams {target.kind} message sent to '{target.name}' (HTTP {result.status})")
    return EXIT_OK


def _body_field(body_text: str) -> dict:
    """Audit carries the body as sha256 + size only (design §3.3, §7).

    The caller hands the text it actually put on the wire — the markdown for a
    built card, the card JSON for ``--card-file`` — so the digest identifies
    what was sent without re-deriving it from the card structure.
    """
    return {"body": body_text}


# --- chats: list | add  (D3; delegated Graph — appended block) ----------------
def _chats(args: argparse.Namespace) -> int:
    action = getattr(args, "chats_command", None)
    if action == "list":
        return _chats_list(args)
    if action == "add":
        return _chats_add(args)
    raise UsageError("a chats action is required: list | add")


def _chats_list(args: argparse.Namespace) -> int:
    """``mnotify teams chats list`` — Graph ``GET /me/chats`` for this identity.

    Human output prints topic + type + a masked id; ``--json`` prints the id in
    full, because a chat id is config data rather than a secret (a Workflows
    webhook URL would be the opposite case and is never printed at all).
    """
    config = load_config()
    chats = get_my_chats(config=config)
    rows = [
        {
            "id": str(chat.get("id", "")),
            "topic": str(chat.get("topic") or ""),
            "type": str(chat.get("chatType") or ""),
            "last_modified": str(chat.get("lastModifiedDateTime") or ""),
        }
        for chat in chats
    ]
    if getattr(args, "json", False):
        print_json({"ok": True, "outcome": "ok", "chats": rows})
        return EXIT_OK
    if not rows:
        print("no chats visible to the signed-in identity")
        return EXIT_OK
    for row in rows:
        topic = row["topic"] or "(no topic)"
        print(f"{topic:<40} {row['type']:<12} {mask_chat_id(row['id'])}")
    return EXIT_OK


def _pick_chat(config) -> str:
    """Interactive ``--pick``: list the chats, read a number, return that chat id.

    The id is printed unmasked here on purpose — the operator is choosing the
    exact conversation to store, and the value is config data, not a secret.
    """
    chats = get_my_chats(config=config)
    if not chats:
        raise UsageError(
            "no chats visible to the signed-in identity (nothing to pick; "
            "sign in with `mnotify login` as a person who is in the chat)"
        )
    print(f"chats visible to the signed-in identity ({len(chats)}):")
    for index, chat in enumerate(chats, start=1):
        topic = str(chat.get("topic") or "(no topic)")
        chat_type = str(chat.get("chatType") or "")
        print(f"{index:>3}  {topic:<40} {chat_type:<12} {chat.get('id', '')}")
    raw = input("chat number to store: ").strip()
    if not raw.isdigit() or not (1 <= int(raw) <= len(chats)):
        raise UsageError(
            f"'{raw}' is not one of 1..{len(chats)} (nothing was stored)"
        )
    return str(chats[int(raw) - 1].get("id", ""))


def _chats_add(args: argparse.Namespace) -> int:
    """``mnotify teams chats add ALIAS <chatId> | --pick``.

    Writes through the config layer only (``with_team_target`` + ``write_config``)
    — no TOML is touched here — and stores no keychain account: a chat target has
    no webhook URL (D1a already keeps ``keychain_accounts()`` from claiming one).
    """
    _validate_target_name(args.name)
    config = load_config()
    # Chat registration is itself a Graph operation when it needs the list, and
    # in every case it creates a target that only delegated mode can send to, so
    # the gate runs before anything is written.
    require_delegated_mode(config, action="chat targets")
    if args.pick and args.chat_id:
        raise UsageError("--pick chooses the chat from the list; pass the id or --pick, not both")
    if args.pick:
        chat_id = _pick_chat(config)
    elif args.chat_id:
        chat_id = args.chat_id
    else:
        raise UsageError("pass a CHAT_ID or --pick (nothing was stored)")
    chat_id = validate_chat_id(chat_id, where=f"chat id for target '{args.name}'")

    write_config(with_team_target(config, args.name, KIND_CHAT, chat_id))
    if getattr(args, "json", False):
        print_json(
            {
                "ok": True,
                "outcome": "ok",
                "target": args.name,
                "kind": KIND_CHAT,
                "chat_id": chat_id,
            }
        )
    else:
        print(
            f"teams target '{args.name}' (chat) saved; chat id "
            f"{mask_chat_id(chat_id)} (config only, no keychain account)"
        )
    return EXIT_OK


# --- send: chat target (delegated Graph; appended block) ----------------------
def _send_chat(args: argparse.Namespace, config, target) -> int:
    """One chat send: card -> Graph chatMessage attachment -> audit.

    Same design §4 order as the webhook path (config -> guard -> dry-run stop ->
    POST -> audit) and the same content-free audit contract: the body travels as
    a digest, the recipient field carries the *alias* rather than a conversation
    id, and no token or chat id appears in any message.
    """
    # First thing: an app-mode config cannot serve this target at all, so even
    # the dry-run preview (which performs no HTTP) must refuse rather than
    # preview a send the credentials could never make.
    require_delegated_mode(config)
    if args.to:
        raise UsageError(
            f"--to is only valid for dm targets; '{target.name}' is a chat target "
            "(the chat id comes from the config)"
        )
    if not target.chat_id:
        # Reachable only for a hand-edited config; load_config validates this too.
        raise UsageError(
            f"teams target '{target.name}' is a chat target with no chat_id "
            "(re-register it with `mnotify teams chats add`)"
        )

    if args.card_file:
        if args.title or args.fact or args.link or args.link_title or args.text or args.text_file:
            raise UsageError(
                "--card-file posts the file verbatim and cannot be combined with "
                "--to/--title/--text/--text-file/--fact/--link/--link-title"
            )
        card = load_card_file(args.card_file)
        body_text = json.dumps(card, ensure_ascii=False, sort_keys=True)
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
        body_text = text

    # Guardrail before any network call (design §3.3). A chat has no addressable
    # recipient list — the alias is a configured target, not a stranger to be
    # allowlisted — so the daily cap and counter are what apply here, exactly as
    # for a channel post.
    verdict = guard.check(config)
    if verdict.status != guard.OK:
        _audit_chat(config, args, target, audit.REFUSED, body_text)
        refusal = DailyCapReached if verdict.status == guard.CAP_REACHED else GuardRefusal
        raise refusal(verdict.reason)

    payload = build_chat_payload(card, attachment_id=new_attachment_id())

    if args.dry_run:
        _print_chat_dry_run(target, payload, json_mode=args.json)
        _audit_chat(config, args, target, audit.DRY_RUN, body_text)
        return EXIT_OK

    try:
        result = post_chat_message(config=config, chat_id=target.chat_id, payload=payload)
    except RemoteError:
        _audit_chat(config, args, target, audit.FAILED, body_text)
        raise
    guard.record_send(config)
    _audit_chat(config, args, target, audit.SENT, body_text)
    if args.json:
        print_json(
            {
                "ok": True,
                "outcome": "sent",
                "target": target.name,
                "kind": KIND_CHAT,
                "recipients": [target.name],
                "status": result.status,
            }
        )
    else:
        print(
            f"teams chat message sent to '{target.name}' "
            f"({mask_chat_id(target.chat_id)}) (HTTP {result.status})"
        )
    return EXIT_OK


def _audit_chat(config, args: argparse.Namespace, target, outcome: str, body_text: str) -> None:
    """One audit line for a chat send: alias as recipient, body as digest only."""
    audit.record(
        config,
        channel=audit.CHANNEL_TEAMS,
        outcome=outcome,
        recipients=[target.name],
        target=target.name,
        title=args.title,
        **_body_field(body_text),
    )


def _print_chat_dry_run(target, payload: dict, *, json_mode: bool) -> None:
    """Print the exact Graph body; the chat id appears only in masked form."""
    label = mask_chat_id(target.chat_id)
    if json_mode:
        print_json(
            {
                "ok": True,
                "outcome": "dry_run",
                "kind": KIND_CHAT,
                "target": target.name,
                "chat_id": label,
                "recipients": [target.name],
                "payload": payload,
            }
        )
        return
    print(f"dry run — would POST a chatMessage attachment to chat {label}")
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _print_dry_run(kind: str, url_label: str, payload: dict, upn: str | None, *, json_mode: bool) -> None:
    """Print the exact payload plus the masked URL; the URL itself never appears."""
    if json_mode:
        print_json(
            {
                "ok": True,
                "outcome": "dry_run",
                "kind": kind,
                "target_url": url_label,
                "recipients": [upn] if upn else [],
                "payload": payload,
            }
        )
        return
    print(f"dry run — would POST to {url_label}")
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
