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

from dataclasses import dataclass
from typing import Sequence

from . import EXIT_DAILY_CAP, EXIT_GUARD, EXIT_OK
from .config import Config

# Verdict statuses (design §3.3 / §4 outcome vocabulary).
OK = "ok"
REFUSED = "refused"
CAP_REACHED = "cap_reached"

_STATUS_EXIT_CODES = {
    OK: EXIT_OK,
    REFUSED: EXIT_GUARD,
    CAP_REACHED: EXIT_DAILY_CAP,
}


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


def check(
    config: Config,
    *,
    recipients: Sequence[str] = (),
    cc: Sequence[str] = (),
    bcc: Sequence[str] = (),
    dm_recipients: Sequence[str] = (),
) -> Verdict:
    """Decide one send attempt against the configured guardrails.

    ``recipients`` are the mail ``to`` addresses, ``cc``/``bcc`` the carbon
    copies, ``dm_recipients`` the Teams DM UPNs. Every one of them must match
    the allowlist, and the combined per-message recipient count must fit
    ``limits.max_recipients``.
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
    return Verdict(OK)


__all__ = ["CAP_REACHED", "OK", "REFUSED", "Verdict", "check"]
