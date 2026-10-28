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
-> token -> POST -> audit. The sequence in :func:`run` *is* that order, and the
comment markers name each stage so a reviewer can check it against the design
without re-deriving it. A guard refusal returns before the first line that could
read the keychain or open a socket, and ``--dry-run`` stops after printing the
payload it just built (§4: "performs NO token call").
"""

from __future__ import annotations

import argparse
from pathlib import Path
from types import ModuleType

from .. import (
    EXIT_OK,
    DailyCapReached,
    GuardRefusal,
    MicroNotifyError,
    UsageError,
)
from .. import audit as audit_module
from .. import guard as guard_module
from ..config import load_config
from ..graph import Attachment as GraphAttachment
from ..graph import build_send_payload, send_mail
from . import not_implemented, print_json, read_text_argument  # shared seam

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


def _stat_attachments(paths: list[str]) -> list[guard_module.Attachment]:
    """Name + size of each ``--attach`` path, without reading a single byte.

    The guard decides on sizes (§3.3), so a refusal must not cost the disk read of
    a 3 MB file — and a missing file is a usage error (exit 2) rather than a
    guardrail refusal, because it is a bad invocation, not a policy decision.
    """
    sized: list[guard_module.Attachment] = []
    for raw in paths:
        path = Path(raw).expanduser()
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise UsageError(
                f"--attach: cannot read {path} ({type(exc).__name__})"
            ) from exc
        sized.append(guard_module.Attachment(name=path.name, size_bytes=size))
    return sized


def _read_attachments(
    paths: list[str], sized: list[guard_module.Attachment]
) -> list[GraphAttachment]:
    """Read the bytes for attachments the guard has already sized."""
    by_name = {a.name: a for a in sized}
    blobs: list[GraphAttachment] = []
    for raw in paths:
        path = Path(raw).expanduser()
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise UsageError(
                f"--attach: cannot read {path} ({type(exc).__name__})"
            ) from exc
        name = by_name[path.name].name
        blobs.append(GraphAttachment(name=name, bytes=data))
    return blobs


def _audit(config, **kwargs) -> None:
    """One audit line per attempt (§3.3) — content-free by construction.

    Callers hand recipients, subject, the body (which :func:`audit.record`
    digests) and name+size pairs; nothing here can put a secret, token or the
    body text into the line.
    """
    audit_module.record(config, channel=audit_module.CHANNEL_MAIL, **kwargs)


def _result_payload(
    *, outcome: str, request_id: str | None, recipients: list[str], payload: dict | None = None
) -> dict:
    """The design section 4 ``--json`` document for a mail outcome."""
    document = {
        "ok": True,
        "outcome": outcome,
        "requestId": request_id,
        "recipients": recipients,
    }
    if payload is not None:
        document["payload"] = payload
    return document


def run(args: argparse.Namespace) -> int:
    """``mnotify mail send`` (design sections 3.1, 3.3, 4, 9)."""
    if getattr(args, "mail_command", None) != "send":
        raise not_implemented("mnotify mail", BUILD_STEP)

    # --- 1. config ----------------------------------------------------------
    config = load_config()
    to = list(args.to or [])
    cc = list(args.cc or [])
    bcc = list(args.bcc or [])
    if not to:
        # Nothing to address is a bad invocation, and it must be caught before the
        # guard so an empty --to is not reported as an allowlist refusal.
        raise UsageError("no recipient: pass --to ADDRESS (repeatable)")

    body = read_text_argument(
        args.body, args.body_file, flag="--body", file_flag="--body-file"
    )
    sized = _stat_attachments(list(args.attach or []))

    # --- 2. guard (before any token, keychain read or socket) ---------------
    verdict = guard_module.check(
        config, recipients=to, cc=cc, bcc=bcc, attachments=sized
    )
    if verdict.status != guard_module.OK:
        # Exit 3 for a content refusal, 6 for the daily cap (§4). The attempt is
        # audited as refused first, then the typed error carries the reason to
        # stderr/stdout via cli.py — the same shape commands/teams.py uses, so the
        # two channels report a refusal identically.
        _audit(
            config,
            outcome=audit_module.REFUSED,
            recipients=[*to, *cc, *bcc],
            sender=config.mail.sender,
            subject=args.subject,
            body=body,
            attachments=sized,
        )
        refusal = (
            DailyCapReached
            if verdict.status == guard_module.CAP_REACHED
            else GuardRefusal
        )
        raise refusal(verdict.reason)

    try:
        attachments = _read_attachments(list(args.attach or []), sized)
        payload = build_send_payload(
            to=to,
            subject=args.subject,
            body=body,
            html=args.html,
            cc=cc,
            bcc=bcc,
            reply_to=args.reply_to or config.mail.default_reply_to,
            attachments=attachments,
            max_total_attach_bytes=config.limits.max_attach_mb * guard_module.BYTES_PER_MB,
        )
    except GuardRefusal as refusal:
        _audit(
            config,
            outcome=audit_module.REFUSED,
            recipients=[*to, *cc, *bcc],
            sender=config.mail.sender,
            subject=args.subject,
            body=body,
            attachments=sized,
        )
        raise

    recipients = [*to, *cc, *bcc]
    machine = bool(getattr(args, "json", False))

    # --- 3. dry-run stop (zero network calls, zero keychain reads) ----------
    if args.dry_run:
        # The payload carries no secret by construction: credentials are only ever
        # read inside graph.acquire_token, which this branch never reaches. The
        # printed document *is* what would have been sent (§4).
        if machine:
            print_json(
                _result_payload(
                    outcome=audit_module.DRY_RUN,
                    request_id=None,
                    recipients=recipients,
                    payload=payload,
                )
            )
        else:
            print_json(payload)
        _audit(
            config,
            outcome=audit_module.DRY_RUN,
            recipients=recipients,
            sender=config.mail.sender,
            subject=args.subject,
            body=body,
            attachments=sized,
        )
        return EXIT_OK

    # --- 4. token, then 5. POST (graph.send_mail acquires the token itself) --
    try:
        result = send_mail(mail=config.mail, payload=payload)
    except MicroNotifyError as failure:
        # Auth (exit 4) and remote (exit 5) failures both get exactly one audit
        # line; the request-id is recorded when Graph sent one. `failure` is then
        # re-raised so cli.py stays the only place that maps errors to output.
        _audit(
            config,
            outcome=audit_module.FAILED,
            recipients=recipients,
            sender=config.mail.sender,
            subject=args.subject,
            body=body,
            attachments=sized,
            request_id=getattr(failure, "request_id", None),
        )
        raise

    # --- 6. audit the success, then spend the daily budget ------------------
    guard_module.record_send(config)
    _audit(
        config,
        outcome=audit_module.SENT,
        recipients=recipients,
        sender=config.mail.sender,
        subject=args.subject,
        body=body,
        attachments=sized,
        request_id=result.request_id,
    )
    if machine:
        print_json(
            _result_payload(
                outcome=audit_module.SENT,
                request_id=result.request_id,
                recipients=recipients,
            )
        )
    else:
        where = f" (Graph request-id {result.request_id})" if result.request_id else ""
        print(f"sent: {len(recipients)} recipient(s) for {config.mail.sender}{where}")
    return EXIT_OK


__all__ = ["NAME", "BUILD_STEP", "add_parser", "run"]
