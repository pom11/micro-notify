"""macOS keychain access via ``/usr/bin/security`` (design section 3 / 3.4).

One service name (``mnotify``) and these accounts, fixed by the orchestrator so
later cards never rename them:

    graph.certificate_pem        private key PEM (auth = "certificate")
    graph.certificate_thumbprint certificate thumbprint paired with the PEM
    graph.client_secret          client secret (auth = "secret")
    teams:<target>               Workflows webhook URL for <target> (a secret)

Contract every caller relies on:

* the value is NEVER echoed, logged, or placed in an exception message; errors
  name the *account* only;
* the subprocess is injectable (``runner`` argument / :func:`set_runner`), so
  tests use the shared ``fake_keychain`` fixture and never invoke
  ``/usr/bin/security``;
* the value is passed to the subprocess in argv of a single exec (not a shell)
  and the subprocess environment inherits nothing secret from us.

Note on ``-w``: ``security`` documents prompting when ``-w`` is last, so the
value is passed as a separate argv element after it — never via a shell string.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from typing import Protocol

from . import EXIT_AUTH, AuthError

SECURITY_BINARY = "/usr/bin/security"
SERVICE = "mnotify"
TEAMS_ACCOUNT_PREFIX = "teams:"

# Canonical account names (design section 3.4 table).
ACCOUNT_CERT_PEM = "graph.certificate_pem"
ACCOUNT_CERT_THUMBPRINT = "graph.certificate_thumbprint"
ACCOUNT_CLIENT_SECRET = "graph.client_secret"

# Timeout for a keychain invocation; a hung security(1) must not hang the CLI.
SUBPROCESS_TIMEOUT = 15.0

Runner = Callable[..., subprocess.CompletedProcess]


class KeychainError(AuthError):
    """The keychain could not be read or written -> exit 4. Message is account-only."""

    exit_code = EXIT_AUTH


def teams_account(target: str) -> str:
    """Keychain account name holding the webhook URL for ``target``."""
    if not target or any(c.isspace() for c in target):
        raise KeychainError("team target name must be a non-empty, space-free string")
    return f"{TEAMS_ACCOUNT_PREFIX}{target}"


def account_name(account: str) -> str:
    """Sanitised account name for messages (accounts never contain secrets)."""
    return account if account else "<empty account>"


# --- Subprocess plumbing ---------------------------------------------------
_default_runner_flags: dict[str, object] = {}


def set_runner(runner: Runner | None = None, **kwargs: object) -> None:
    """Install a process-wide runner (used by the shared ``fake_keychain``).

    ``set_runner()`` restores the real ``subprocess.run``.
    """
    _default_runner_flags.clear()
    if runner is not None:
        _default_runner_flags["runner"] = runner
    _default_runner_flags.update(kwargs)


def _run(args: list[str], timeout: float = SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess:
    runner = _default_runner_flags.get("runner", subprocess.run)
    extra = {k: v for k, v in _default_runner_flags.items() if k != "runner"}
    try:
        return runner(args, capture_output=True, text=True, timeout=timeout, **extra)
    except FileNotFoundError as exc:
        raise KeychainError(f"keychain binary not found: {SECURITY_BINARY}") from exc
    except subprocess.TimeoutExpired as exc:
        raise KeychainError("keychain call timed out") from exc
    except OSError as exc:
        raise KeychainError(f"keychain call failed: {type(exc).__name__}") from exc


def _check(result: subprocess.CompletedProcess, account: str, action: str) -> str:
    """Return stdout on success; raise a value-free KeychainError otherwise.

    stderr from ``security`` is deliberately dropped: it can echo the item's
    attributes and we must not carry it into an exception message.
    """
    if result.returncode != 0:
        raise KeychainError(
            f"keychain {action} failed for account '{account_name(account)}' "
            f"(service '{SERVICE}', exit {result.returncode})"
        )
    return result.stdout or ""


# --- Public API ------------------------------------------------------------
def get(account: str, *, runner: Runner | None = None) -> str:
    """Read the secret stored for ``account``. Raises KeychainError if absent."""
    if not account:
        raise KeychainError("account must be a non-empty string")
    args = [SECURITY_BINARY, "find-generic-password", "-s", SERVICE, "-a", account, "-w"]
    result = _run(args) if runner is None else runner(args, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    return _decode_hex_dump(_check(result, account, "read").rstrip("\n"))


def _decode_hex_dump(raw: str) -> str:
    """Undo security(1)'s hex dump of values with non-printable bytes.

    ``find-generic-password -w`` prints a value containing a newline (a PEM
    private key) as one lowercase hex string instead of the text. Decode only
    when the result is valid UTF-8 that itself contains a newline, which is the
    reason security(1) hex-dumped it; a secret that merely looks like hex (an
    uppercase certificate thumbprint) never decodes to that and is returned
    unchanged.
    """
    if len(raw) % 2 or not raw or any(c not in "0123456789abcdef" for c in raw):
        return raw
    try:
        decoded = bytes.fromhex(raw).decode("utf-8")
    except ValueError:
        return raw
    return decoded if "\n" in decoded else raw


def set_secret(account: str, value: str, *, runner: Runner | None = None) -> None:
    """Store ``value`` for ``account`` (create, or update in place).

    ``-U`` updates an existing item. The value rides in argv of an exec'd
    process; it is never interpolated into a shell command, logged, or returned.
    """
    if not account:
        raise KeychainError("account must be a non-empty string")
    if not isinstance(value, str):
        raise KeychainError(f"secret for account '{account_name(account)}' must be a string")
    args = [SECURITY_BINARY, "add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", value]
    result = _run(args) if runner is None else runner(args, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    _check(result, account, "write")


def delete(account: str, *, runner: Runner | None = None) -> bool:
    """Delete ``account``. Returns False when there was nothing to delete."""
    if not account:
        raise KeychainError("account must be a non-empty string")
    args = [SECURITY_BINARY, "delete-generic-password", "-s", SERVICE, "-a", account]
    result = _run(args) if runner is None else runner(args, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    if result.returncode != 0:
        # security(1) exits 44 ("item not found") — treat as "nothing to delete".
        if result.returncode == 44:
            return False
        raise KeychainError(
            f"keychain delete failed for account '{account_name(account)}' "
            f"(service '{SERVICE}', exit {result.returncode})"
        )
    return True


def has(account: str, *, runner: Runner | None = None) -> bool:
    """True when a non-empty secret exists for ``account``. Never raises for absence."""
    try:
        return bool(get(account, runner=runner))
    except KeychainError:
        return False


class SecretStore(Protocol):
    """Duck-type the fake_keychain fixture can satisfy."""

    def get(self, account: str) -> str: ...
    def set_secret(self, account: str, value: str) -> None: ...
    def delete(self, account: str) -> bool: ...
    def has(self, account: str) -> bool: ...


__all__ = [
    "ACCOUNT_CERT_PEM",
    "ACCOUNT_CERT_THUMBPRINT",
    "ACCOUNT_CLIENT_SECRET",
    "SECURITY_BINARY",
    "SERVICE",
    "SUBPROCESS_TIMEOUT",
    "TEAMS_ACCOUNT_PREFIX",
    "KeychainError",
    "SecretStore",
    "delete",
    "get",
    "has",
    "set_runner",
    "set_secret",
    "teams_account",
]
