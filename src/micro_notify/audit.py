"""JSONL audit log: one line per send attempt (design §3.3, §7).

Appended to ``[paths]audit`` (default ``~/Library/Logs/mnotify/sent.jsonl``).
Every attempt — sent, refused, failed, dry_run — produces exactly one line.

The schema below is the whole contract, and it is deliberately **content-free**:
``body_sha256`` + ``body_size`` describe the body without carrying it, and
webhook URLs appear only through :func:`mask_url`. A secret, token, webhook URL
or message body must never enter a line, so nothing here may be handed raw
payloads: callers pass recipients, subject/title, digests and attachment
name+size pairs only (design §2 anti-goals, §7 "audit never contains body").
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

from .config import Config
from .guard import Attachment

# Channels (design §3.3: mail | teams).
CHANNEL_MAIL = "mail"
CHANNEL_TEAMS = "teams"

# Outcomes (design §3.3 sent/refused/failed + §4 dry_run).
SENT = "sent"
REFUSED = "refused"
FAILED = "failed"
DRY_RUN = "dry_run"

AUDIT_FILE_MODE = 0o600

# The replacement tail mask_url() appends instead of path/query/credentials.
MASKED_URL = "***"


def body_digest(body: str) -> tuple[str, int]:
    """Return ``(sha256 hex, size in bytes)`` for a body — never the body."""
    raw = body.encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _attachment_field(attachments: Sequence[Attachment]) -> list[dict[str, Any]]:
    return [{"name": a.name, "size_bytes": a.size_bytes} for a in attachments]


def record(
    config: Config,
    *,
    channel: str,
    outcome: str,
    recipients: Sequence[str] = (),
    sender: str | None = None,
    target: str | None = None,
    subject: str | None = None,
    title: str | None = None,
    body: str | None = None,
    body_sha256: str | None = None,
    body_size: int | None = None,
    attachments: Sequence[Attachment] = (),
    request_id: str | None = None,
) -> dict[str, Any]:
    """Append one audit line and return the entry that was written.

    Exactly one of ``body`` / (``body_sha256`` + ``body_size``) describes the
    content: passing the body stores only its digest and size.
    """
    if body is not None:
        body_sha256, body_size = body_digest(body)

    entry: dict[str, Any] = {
        "ts": _now_iso(),
        "channel": channel,
        "outcome": outcome,
    }
    if sender is not None:
        entry["sender"] = sender
    if target is not None:
        entry["target"] = target
    entry["recipients"] = list(recipients)
    if subject is not None:
        entry["subject"] = subject
    if title is not None:
        entry["title"] = title
    if body_sha256 is not None:
        entry["body_sha256"] = body_sha256
    if body_size is not None:
        entry["body_size"] = body_size
    if attachments:
        entry["attachments"] = _attachment_field(attachments)
    if request_id:
        entry["request_id"] = request_id

    _append_line(config.paths.audit, json.dumps(entry, ensure_ascii=False, sort_keys=True))
    return entry


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def mask_url(url: str) -> str:
    """Return ``scheme://host/***`` — the only form a URL may appear in output.

    Workflows webhook URLs carry their signature in the path (design §3.2), so
    ``--dry-run`` output and any error path print this instead of the URL. If
    the input is not a parseable absolute http(s) URL, nothing is echoed back:
    an error path may hand us anything, and "***" is the safe answer.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return MASKED_URL
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return MASKED_URL
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}/{MASKED_URL}"


def _append_line(path: Path, line: str) -> None:
    """Append one JSONL line with mode 0600, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, AUDIT_FILE_MODE)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(str(path), AUDIT_FILE_MODE)


__all__ = [
    "AUDIT_FILE_MODE",
    "CHANNEL_MAIL",
    "CHANNEL_TEAMS",
    "DRY_RUN",
    "FAILED",
    "MASKED_URL",
    "REFUSED",
    "SENT",
    "body_digest",
    "mask_url",
    "record",
]
