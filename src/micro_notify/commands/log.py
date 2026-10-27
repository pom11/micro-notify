"""``mnotify log [--tail N] [--json]`` — read the audit log back.

No later build step owns ``log`` (design §8 covers audit *writing* in step 2),
so it is implemented here. It is read-only and never touches the network, and it
deliberately does not import :mod:`micro_notify.audit` (build step 2's file): it
only needs the ``[paths]audit`` location from the config, so it works with
whatever JSONL step 2 writes.

Attributes:

    args.tail      int | None   (last N entries; 0 means everything)
    args.json      bool

Never print a body, a secret or a webhook URL: the audit schema (design §3.3)
has none, and human mode prints selected fields only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .. import EXIT_OK, UsageError
from ..config import load_config
from . import print_json

NAME = "log"
DEFAULT_TAIL = 25
# Human-mode columns, in print order. Chosen so no secret-bearing field can slip in.
HUMAN_FIELDS = ("ts", "outcome", "channel", "sender", "target", "subject", "title", "request_id")


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    log = subparsers.add_parser(
        NAME,
        help="print the audit log",
        description=(
            "Print entries from the JSONL audit log (design §3.3). Bodies, "
            "secrets and webhook URLs are never recorded, so they can never be "
            "printed."
        ),
    )
    log.add_argument(
        "--tail",
        type=int,
        metavar="N",
        default=None,
        help=f"show the last N entries (default: {DEFAULT_TAIL}; 0 shows all)",
    )
    log.add_argument("--json", action="store_true", help="machine-readable entries on stdout")


def read_audit_lines(path: Path) -> list[str]:
    """Return the audit file's non-empty lines (oldest first)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise UsageError(f"audit log unreadable: {path} ({type(exc).__name__})") from exc
    return [line for line in raw.splitlines() if line.strip()]


def parse_entries(lines: list[str], tail: int | None) -> tuple[list[dict[str, Any]], int]:
    """Parse ``lines`` into JSON objects, keeping the last ``tail`` (0 = all).

    Returns ``(entries, malformed_count)``; malformed lines are counted, not
    silently dropped.
    """
    entries: list[dict[str, Any]] = []
    malformed = 0
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(record, dict):
            malformed += 1
            continue
        entries.append(record)
    if tail is None:
        tail = DEFAULT_TAIL
    if tail > 0:
        entries = entries[-tail:]
    return entries, malformed


def _human_line(entry: dict[str, Any]) -> str:
    parts = [str(entry[field]) for field in HUMAN_FIELDS if entry.get(field) not in (None, "", [])]
    recipients = entry.get("recipients")
    if isinstance(recipients, list) and recipients:
        parts.append(", ".join(str(r) for r in recipients))
    return "  ".join(parts) if parts else "(entry without printable fields)"


def run(args: argparse.Namespace) -> int:
    config = load_config()
    entries, malformed = parse_entries(read_audit_lines(config.paths.audit), args.tail)
    if getattr(args, "json", False):
        print_json(
            {
                "ok": True,
                "outcome": "ok",
                "auditPath": str(config.paths.audit),
                "count": len(entries),
                "malformed": malformed,
                "entries": entries,
            }
        )
        return EXIT_OK
    if not entries:
        print(f"no audit entries in {config.paths.audit}")
        return EXIT_OK
    for entry in entries:
        print(_human_line(entry))
    if malformed:
        print(f"({malformed} malformed entr{'y' if malformed == 1 else 'ies'} skipped)")
    return EXIT_OK
