"""Guardrails: allowlist, caps, daily counter (design §3.3).

Single decision entry point :func:`check` returns a typed
:class:`Verdict` (``ok`` / ``refused`` / ``cap_reached``) with a human reason
so a command can map it to the design §4 exit code; this module never calls
``sys.exit`` and never touches the network. All guardrails are evaluated
before any network call — commands must call :func:`check` first (design §3.3).

Allowlist semantics (design §3.3): an *empty* allowlist (no ``[allow]``
section, or both lists empty) refuses **every** recipient. This is the
anti-goal guard of design §2: fail closed until the operator opts in.
Matching is case-insensitive and exact: ``example.com`` admits addresses at
that domain, not at ``dept.example.com``; ``allow.addresses`` admits the one
address listed verbatim.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from . import EXIT_DAILY_CAP, EXIT_GUARD, EXIT_OK
from .config import Config

# Verdict statuses (design §3.3 / §4 outcome vocabulary).
OK = "ok"
REFUSED = "refused"
CAP_REACHED = "cap_reached"

# limits.max_attach_mb is counted in binary megabytes (MiB) — the unit the
# Graph fileAttachment guidance uses for the ~3.75 MB request body ceiling.
BYTES_PER_MB = 1024 * 1024


def utc_today() -> str:
    """Today's UTC date as ``YYYY-MM-DD`` — the daily counter's key.

    A module-level function so tests can freeze the clock; the daily cap is
    defined on UTC dates (design §3.3), so the local timezone must not leak in.
    """
    return datetime.now(timezone.utc).date().isoformat()

_STATUS_EXIT_CODES = {
    OK: EXIT_OK,
    REFUSED: EXIT_GUARD,
    CAP_REACHED: EXIT_DAILY_CAP,
}


@dataclass(frozen=True)
class Attachment:
    """One attachment's name and byte size.

    The caller (``mail send``) stats the file and hands the guard numbers:
    :func:`check` never opens the file, so a refusal happens before any body
    or attachment bytes are read or encoded.
    """

    name: str
    size_bytes: int


@dataclass(frozen=True)
class Verdict:
    """The guard's decision: one of the three statuses plus a human reason.

    ``exit_code`` maps the status onto the design §4 exit codes so commands
    never re-derive it.
    """

    status: str
    reason: str = ""

    @property
    def exit_code(self) -> int:
        return _STATUS_EXIT_CODES[self.status]


def _is_well_formed(address: str) -> bool:
    """Cheap shape check: one ``@``, non-empty sides, no whitespace."""
    if "@" not in address or address.count("@") != 1:
        return False
    local, _, domain = address.partition("@")
    if not local or not domain:
        return False
    return not any(c.isspace() for c in address)


def _allowed(config: Config, address: str) -> bool:
    """True when ``address`` matches allow.addresses verbatim or allow.domains.

    Both sides are lower-cased here rather than trusting config.py's load-time
    normalisation: :class:`Config` can also be built directly (tests, callers),
    and a case slip must never widen or narrow what is admitted.
    """
    if not _is_well_formed(address):
        return False
    lowered = address.lower()
    if lowered in {a.lower() for a in config.allow.addresses}:
        return True
    domain = lowered.partition("@")[2]
    return domain in {d.lower() for d in config.allow.domains}


def _counter_state(config: Config, today: str) -> int:
    """Sends recorded for ``today``; 0 when absent or from a previous UTC day.

    Raises ValueError when the file exists but cannot be understood — the
    caller turns that into a refusal rather than assuming budget.
    """
    path = config.paths.counter_file
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return 0
    except OSError as exc:
        raise ValueError(f"counter file unreadable: {type(exc).__name__}") from exc
    try:
        data = json.loads(raw)
        date = data["date"]
        count = data["count"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"counter file corrupt: {path}") from exc
    if not isinstance(date, str) or not isinstance(count, int) or isinstance(count, bool):
        raise ValueError(f"counter file corrupt: {path}")
    if date != today:
        return 0
    return count


def check(
    config: Config,
    *,
    recipients: Sequence[str] = (),
    cc: Sequence[str] = (),
    bcc: Sequence[str] = (),
    dm_recipients: Sequence[str] = (),
    attachments: Sequence[Attachment] = (),
) -> Verdict:
    """Decide one send attempt against the configured guardrails.

    ``recipients`` are the mail ``to`` addresses, ``cc``/``bcc`` the carbon
    copies, ``dm_recipients`` the Teams DM UPNs. Every one of them must match
    the allowlist, the combined per-message recipient count must fit
    ``limits.max_recipients``, the combined ``attachments`` size must fit
    ``limits.max_attach_mb``, and today's counter must be below
    ``limits.daily_max``.

    Content refusals are evaluated before the daily cap so a message that
    would be refused anyway does not consume the day's budget.
    """
    all_recipients = [*recipients, *cc, *bcc, *dm_recipients]
    for address in all_recipients:
        if not _allowed(config, address):
            return Verdict(REFUSED, f"recipient not allowed by [allow]: {address}")

    limit = config.limits.max_recipients
    if len(all_recipients) > limit:
        return Verdict(
            REFUSED,
            f"{len(all_recipients)} recipients exceeds limits.max_recipients={limit}",
        )

    max_attach_bytes = config.limits.max_attach_mb * BYTES_PER_MB
    total_attach_bytes = sum(a.size_bytes for a in attachments)
    if total_attach_bytes > max_attach_bytes:
        names = ", ".join(a.name for a in attachments) or "(none)"
        return Verdict(
            REFUSED,
            f"attachments total {total_attach_bytes} bytes over {names}; "
            f"limits.max_attach_mb={config.limits.max_attach_mb} "
            f"({max_attach_bytes} bytes)",
        )

    today = utc_today()
    try:
        used = _counter_state(config, today)
    except ValueError as exc:
        # Fail closed: an unparseable counter cannot prove budget remains.
        return Verdict(REFUSED, f"{exc} (refusing rather than assuming budget)")
    if used >= config.limits.daily_max:
        return Verdict(
            CAP_REACHED,
            f"daily cap reached: {used}/{config.limits.daily_max} sends used today "
            f"({today} UTC)",
        )
    return Verdict(OK)


def record_send(config: Config) -> int:
    """Add one successful send to today's counter; return the new count.

    Commands call this only after a send actually succeeded — ``check`` never
    writes, so a refusal or a remote failure does not consume budget. The
    counter is keyed by UTC date, so the first write of a new day restarts at
    1 (design §3.3: rollover at midnight UTC). Written atomically with mode
    0600 so a crash mid-write cannot leave a half-written counter.
    """
    today = utc_today()
    try:
        used = _counter_state(config, today)
    except ValueError:
        used = 0  # a corrupt counter is replaced by a fresh, correct one
    count = used + 1
    path = config.paths.counter_file
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    payload = json.dumps({"date": today, "count": count})
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    return count


__all__ = [
    "BYTES_PER_MB",
    "CAP_REACHED",
    "OK",
    "REFUSED",
    "Attachment",
    "Verdict",
    "check",
    "record_send",
    "utc_today",
]
