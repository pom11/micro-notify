"""Secret storage facade: macOS keychain or Linux/container file backend.

One service name (``mnotify``) and these accounts, fixed by the orchestrator so
later cards never rename them:

    graph.certificate_pem        private key PEM (auth = "certificate")
    graph.certificate_thumbprint certificate thumbprint paired with the PEM
    graph.client_secret          client secret (auth = "secret")
    graph.delegated_token_cache  msal delegated token cache (design amendment A.2)
    teams:<target>               Workflows webhook URL for <target> (a secret)

Backend selection is explicit and fail-closed (``MICRO_NOTIFY_SECRETS``):

* ``keychain`` — the macOS ``/usr/bin/security`` path, byte-identical to the
  pre-L1 behaviour;
* ``file`` — files under ``MICRO_NOTIFY_SECRETS_DIR`` (see
  :mod:`micro_notify.secrets_file`).

With the variable unset the default is ``keychain`` on darwin only; every other
platform refuses with a usage error (exit 2) instead of guessing. There is no
implicit file backend on macOS and no implicit keychain attempt on Linux.

Contract every caller relies on:

* the value is NEVER echoed, logged, or placed in an exception message; errors
  name the *account* (and, for files, the path) only;
* the subprocess is injectable (``runner`` argument / :func:`set_runner`), so
  tests use the shared ``fake_keychain`` fixture and never invoke
  ``/usr/bin/security``;
* the value is passed to the subprocess in argv of a single exec (not a shell)
  and the subprocess environment inherits nothing secret from us;
* absence (missing item / missing file) raises :class:`KeychainItemMissing`
  (exit 44 -> 4); an unreadable item raises :class:`KeychainError` (exit 4).

Note on ``-w``: ``security`` documents prompting when ``-w`` is last, so the
value is passed as a separate argv element after it — never via a shell string.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from . import EXIT_AUTH, AuthError, UsageError

SECURITY_BINARY = "/usr/bin/security"
SERVICE = "mnotify"
TEAMS_ACCOUNT_PREFIX = "teams:"

# Backend selection (binding L1 decisions). Env carries selection and paths
# only; secret values never travel through the environment.
SECRETS_BACKEND_ENV = "MICRO_NOTIFY_SECRETS"
SECRETS_DIR_ENV = "MICRO_NOTIFY_SECRETS_DIR"
BACKEND_KEYCHAIN = "keychain"
BACKEND_FILE = "file"

# ``security`` exits 44 ("item not found") when the item provably does not exist
# (see security(1) / Security.framework's errSecItemNotFound). Every *other*
# non-zero exit — a locked keychain, a denied ACL, a corrupt keychain file —
# means the same question could not be answered. The two must never be
# conflated where a wrong answer costs the operator something: the B6 incident
# (2026-10-31) started exactly there, when a failed read read as "no certificate
# pair" and ``mnotify admin bootstrap`` regenerated the tenant's key pair.
EXIT_ITEM_NOT_FOUND = 44

# The three verdicts :func:`probe` can return. Strings (not enum members) keep
# the dataclass trivially JSON-dumpable for ``--json`` callers later.
PROBE_PRESENT = "present"
PROBE_ABSENT = "absent"
PROBE_UNREADABLE = "unreadable"

# Canonical account names (design section 3.4 table).
ACCOUNT_CERT_PEM = "graph.certificate_pem"
ACCOUNT_CERT_THUMBPRINT = "graph.certificate_thumbprint"
ACCOUNT_CLIENT_SECRET = "graph.client_secret"
# Design amendment 2026-10-30 A.2/A.4: the serialised msal delegated token cache
# (access + refresh token). A secret in the same class as the private key: never on
# disk, never printed. Owned by micro_notify.delegation, which is the only reader.
# Deliberately absent from Config.keychain_accounts(): that list drives the presence
# checks for app-only mode, and a machine that never signs in delegationally has
# nothing missing. The delegated presence check is doctor's, in delegated mode only.
ACCOUNT_DELEGATED_CACHE = "graph.delegated_token_cache"

# Timeout for a keychain invocation; a hung security(1) must not hang the CLI.
SUBPROCESS_TIMEOUT = 15.0

Runner = Callable[..., subprocess.CompletedProcess]


class KeychainError(AuthError):
    """The stored item could not be read or written -> exit 4. Message is account-only."""

    exit_code = EXIT_AUTH


class KeychainItemMissing(KeychainError):
    """The item provably does not exist (keychain exit 44 / missing file) -> exit 4.

    A distinct type so a caller that must tell "absent" from "unreadable" can
    catch absence alone; every existing ``except KeychainError`` keeps catching
    it unchanged, and the operator-facing message is identical.
    """

    exit_code = EXIT_AUTH


class SecretBackendError(UsageError):
    """Backend selection or its directory is unusable -> exit 2."""

    exit_code = 2


def select_backend(
    environ: Mapping[str, str] | None = None, platform: str | None = None
) -> str:
    """Return ``keychain`` or ``file``; refuse instead of guessing off-darwin.

    ``platform`` defaults to :data:`sys.platform`; it is a parameter only so the
    default matrix is testable without pretending to run on another OS.
    An unset (or empty) ``MICRO_NOTIFY_SECRETS`` means keychain on darwin and a
    usage error everywhere else.
    """
    env = os.environ if environ is None else environ
    requested = env.get(SECRETS_BACKEND_ENV, "")
    if requested:
        if requested not in (BACKEND_KEYCHAIN, BACKEND_FILE):
            raise SecretBackendError(
                f"{SECRETS_BACKEND_ENV} must be '{BACKEND_KEYCHAIN}' or "
                f"'{BACKEND_FILE}' (got '{requested}')"
            )
        return requested
    host = sys.platform if platform is None else platform
    if host == "darwin":
        return BACKEND_KEYCHAIN
    raise SecretBackendError(
        f"no secret backend selected: set {SECRETS_BACKEND_ENV} explicitly to "
        f"'{BACKEND_KEYCHAIN}' (macOS) or '{BACKEND_FILE}' (Linux/containers)"
    )


def _file_backend():
    """Import the file backend lazily to keep module import order simple."""
    from . import secrets_file

    return secrets_file


def account_filename(account: str) -> str:
    """Map an account to its file name: literal except ``:`` -> ``__``.

    Documented pure function for the file backend; see
    :func:`micro_notify.secrets_file.account_filename`.
    """
    return _file_backend().account_filename(account)


def teams_account(target: str) -> str:
    """Stored-item account name holding the webhook URL for ``target``."""
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

    ``set_runner()`` restores the real ``subprocess.run``. The file backend has
    no subprocess, so this seam only affects keychain reads and writes.
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
    attributes and we must not carry it into an exception message. Exit 44
    raises the *typed* :class:`KeychainItemMissing` — every existing
    ``except KeychainError`` keeps catching it, and the message is identical.
    """
    if result.returncode != 0:
        error = (
            KeychainItemMissing
            if result.returncode == EXIT_ITEM_NOT_FOUND
            else KeychainError
        )
        raise error(
            f"keychain {action} failed for account '{account_name(account)}' "
            f"(service '{SERVICE}', exit {result.returncode})"
        )
    return result.stdout or ""


def _find_argv(account: str) -> list[str]:
    """The single argv shape both :func:`get` and :func:`probe` read with."""
    return [SECURITY_BINARY, "find-generic-password", "-s", SERVICE, "-a", account, "-w"]


def _read_raw(account: str, runner: Runner | None) -> subprocess.CompletedProcess:
    """Run the find command once, through whichever runner is installed."""
    if not account:
        raise KeychainError("account must be a non-empty string")
    args = _find_argv(account)
    return (
        _run(args)
        if runner is None
        else runner(args, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    )


# --- Keychain backend ------------------------------------------------------
def _keychain_get(account: str, *, runner: Runner | None = None) -> str:
    result = _read_raw(account, runner)
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


def _keychain_set_secret(account: str, value: str, *, runner: Runner | None = None) -> None:
    if not account:
        raise KeychainError("account must be a non-empty string")
    if not isinstance(value, str):
        raise KeychainError(f"secret for account '{account_name(account)}' must be a string")
    args = [SECURITY_BINARY, "add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", value]
    result = _run(args) if runner is None else runner(args, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    _check(result, account, "write")


def _keychain_delete(account: str, *, runner: Runner | None = None) -> bool:
    if not account:
        raise KeychainError("account must be a non-empty string")
    args = [SECURITY_BINARY, "delete-generic-password", "-s", SERVICE, "-a", account]
    result = _run(args) if runner is None else runner(args, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
    if result.returncode != 0:
        # security(1) exits 44 ("item not found") — treat as "nothing to delete".
        if result.returncode == EXIT_ITEM_NOT_FOUND:
            return False
        raise KeychainError(
            f"keychain delete failed for account '{account_name(account)}' "
            f"(service '{SERVICE}', exit {result.returncode})"
        )
    return True


# --- Public API ------------------------------------------------------------
def get(account: str, *, runner: Runner | None = None) -> str:
    """Read the secret stored for ``account``. Raises KeychainError if absent.

    Absence (keychain exit 44 / a missing file) raises
    :class:`KeychainItemMissing`; every other failure raises
    :class:`KeychainError`. Callers that only need to *report* presence keep
    using :func:`has`; callers that would *destroy* something when they read
    "absent" must use :func:`probe` instead.
    """
    if select_backend() == BACKEND_FILE:
        return _file_backend().get(account)
    return _keychain_get(account, runner=runner)


def set_secret(account: str, value: str, *, runner: Runner | None = None) -> None:
    """Store ``value`` for ``account`` (create, or update in place).

    Keychain: ``-U`` updates an existing item and the value rides in argv of an
    exec'd process. File: an atomic 0600 write inside ``MICRO_NOTIFY_SECRETS_DIR``.
    Neither backend logs, returns, or interpolates the value into a shell.
    """
    if select_backend() == BACKEND_FILE:
        _file_backend().set_secret(account, value)
        return
    _keychain_set_secret(account, value, runner=runner)


def delete(account: str, *, runner: Runner | None = None) -> bool:
    """Delete ``account``. Returns False when there was nothing to delete."""
    if select_backend() == BACKEND_FILE:
        return _file_backend().delete(account)
    return _keychain_delete(account, runner=runner)


@dataclass(frozen=True)
class SecretProbe:
    """What one read proved about ``account`` — never the secret itself.

    ``value`` carries the decoded value only for :data:`PROBE_PRESENT`; absent and
    unreadable verdicts carry ``""`` so a caller that forgets to check the verdict
    cannot accidentally pass a blank string where a thumbprint belongs. ``reason``
    is account-and-exit-code only: the backend's stderr is dropped for the same
    reason :func:`_check` drops it.
    """

    account: str
    verdict: str
    value: str = ""
    reason: str = ""

    @property
    def is_present(self) -> bool:
        return self.verdict == PROBE_PRESENT

    @property
    def is_absent(self) -> bool:
        return self.verdict == PROBE_ABSENT

    @property
    def is_unreadable(self) -> bool:
        return self.verdict == PROBE_UNREADABLE


def probe(account: str, *, runner: Runner | None = None, read_value: bool = True) -> SecretProbe:
    """Three-way verdict on ``account``: present, absent, or unreadable.

    The distinction :func:`has` cannot make, and the reason it exists: ``has()``
    answers "is it there?" with a bool, so a locked keychain, a denied ACL, an
    insecure secret file and a genuinely missing item all answer ``False``.
    Where ``False`` only feeds a report line that is harmless; where ``False``
    means "no key pair exists, generate one" it cost the operator their
    certificate on 2026-10-31 (see the B6 forensics in
    :mod:`micro_notify.admin.certupload`). A caller that would destroy something
    on "absent" must use this and treat :data:`PROBE_UNREADABLE` as a hard stop.

    The verdict comes from :func:`get`'s typed exception — the one place the
    absence signal is interpreted — on either backend, so a caller never has to
    read an exit code and a missing item can never be mistaken for a failure.
    Absence is a verdict and a failure is a verdict: this function never raises
    for either (a *bad account argument* is a programming error and still raises).

    ``read_value=False`` is for a caller that must know whether an account holds
    *anything* but has no business seeing what — the private key half of a
    certificate pair. The read still happens (an unreadable item must not read as
    absent, which is the whole point), the value is dropped here rather than
    returned; it reaches no result, message, argv or file. With ``read_value=False``
    any existing item is :data:`PROBE_PRESENT`, even an empty one: an item that
    exists but holds nothing is a corrupt item to be investigated, not a blank
    slate to be overwritten.
    """
    if not account:
        raise KeychainError("account must be a non-empty string")
    try:
        value = get(account, runner=runner)
    except KeychainItemMissing:
        return SecretProbe(account, PROBE_ABSENT)
    except KeychainError as exc:  # locked keychain, denied ACL, insecure file, timeout
        return SecretProbe(account, PROBE_UNREADABLE, reason=exc.message)
    if not read_value:
        return SecretProbe(account, PROBE_PRESENT)
    if not value:
        # An item that exists but holds nothing is, for every value-consuming
        # caller, "no secret" — the same answer has() has always given.
        return SecretProbe(account, PROBE_ABSENT)
    return SecretProbe(account, PROBE_PRESENT, value=value)


def has(account: str, *, runner: Runner | None = None) -> bool:
    """True when a non-empty secret exists for ``account``. Never raises for absence.

    Best-effort by contract, not by accident: an *unreadable* item also answers
    ``False``. That is correct for the status reports that use it (``doctor``,
    ``setup``, ``config show``, ``teams list``), where "missing" and "cannot
    tell" share one report line and no state changes. It is **not** a safe basis
    for a decision that could destroy anything — use :func:`probe` there and
    fail closed on :data:`PROBE_UNREADABLE`.
    """
    verdict = probe(account, runner=runner)
    return verdict.is_present


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
    "ACCOUNT_DELEGATED_CACHE",
    "BACKEND_FILE",
    "BACKEND_KEYCHAIN",
    "EXIT_ITEM_NOT_FOUND",
    "PROBE_ABSENT",
    "PROBE_PRESENT",
    "PROBE_UNREADABLE",
    "SECRETS_BACKEND_ENV",
    "SECRETS_DIR_ENV",
    "SECURITY_BINARY",
    "SERVICE",
    "SUBPROCESS_TIMEOUT",
    "TEAMS_ACCOUNT_PREFIX",
    "KeychainError",
    "KeychainItemMissing",
    "SecretBackendError",
    "SecretProbe",
    "SecretStore",
    "account_filename",
    "delete",
    "get",
    "has",
    "probe",
    "select_backend",
    "set_runner",
    "set_secret",
    "teams_account",
]
