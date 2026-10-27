"""micro-notify — agent-friendly notifications over Microsoft 365.

Design contract: docs/design/2026-10-27-micro-notify-design.md

This module owns the two cross-module vocabularies every command shares, so that
no later module has to edit another module's file:

* the exit codes of design section 4 (``EXIT_*`` constants below), and
* the typed exceptions commands raise, each carrying the ``exit_code`` the CLI
  must return (``MicroNotifyError`` and subclasses).

Rules for every module (design sections 2, 4, 5):

* a secret, token or webhook URL never reaches stdout/stderr/logs, an exception
  message, or the config file;
* every guardrail is evaluated before any network call;
* nothing is faked: an unimplemented code path raises, it never returns success.
"""

from __future__ import annotations

__version__ = "0.0.1"

# --- Exit codes (design section 4) -----------------------------------------
# These are a public contract for agents driving the CLI; do not renumber.
EXIT_OK = 0             # message sent (or dry-run payload printed)
EXIT_USAGE = 2          # usage or config error (bad flag, unreadable/invalid config)
EXIT_GUARD = 3          # refused by a guardrail (allowlist, recipient count, attach size)
EXIT_AUTH = 4           # auth error (missing keychain item, msal/AADSTS failure)
EXIT_REMOTE = 5         # remote error (Graph/webhook non-2xx; message carries request-id)
EXIT_DAILY_CAP = 6      # daily cap reached (limits.daily_max)

EXIT_CODES = (
    EXIT_OK,
    EXIT_USAGE,
    EXIT_GUARD,
    EXIT_AUTH,
    EXIT_REMOTE,
    EXIT_DAILY_CAP,
)


# --- Typed errors ----------------------------------------------------------
class MicroNotifyError(Exception):
    """Base for every error the CLI turns into an exit code.

    ``message`` is the operator-facing text and must never contain a secret,
    token, webhook URL or private key.
    """

    exit_code = EXIT_USAGE

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class UsageError(MicroNotifyError):
    """Bad invocation or unusable configuration -> exit 2."""

    exit_code = EXIT_USAGE


class GuardRefusal(MicroNotifyError):
    """A guardrail refused the send -> exit 3 (design section 3.3)."""

    exit_code = EXIT_GUARD


class AuthError(MicroNotifyError):
    """Token acquisition / credential problem -> exit 4."""

    exit_code = EXIT_AUTH


class RemoteError(MicroNotifyError):
    """Graph or webhook returned non-2xx (or was unreachable) -> exit 5."""

    exit_code = EXIT_REMOTE


class DailyCapReached(MicroNotifyError):
    """``limits.daily_max`` exhausted for today -> exit 6."""

    exit_code = EXIT_DAILY_CAP


class NotImplementedYet(MicroNotifyError):
    """A command module that a later build step owns was reached.

    It maps to exit 2 and is announced loudly on stderr: a stub must never look
    like a success (design section 2, anti-goals).
    """

    exit_code = EXIT_USAGE


__all__ = [
    "__version__",
    "EXIT_OK",
    "EXIT_USAGE",
    "EXIT_GUARD",
    "EXIT_AUTH",
    "EXIT_REMOTE",
    "EXIT_DAILY_CAP",
    "EXIT_CODES",
    "MicroNotifyError",
    "UsageError",
    "GuardRefusal",
    "AuthError",
    "RemoteError",
    "DailyCapReached",
    "NotImplementedYet",
]
