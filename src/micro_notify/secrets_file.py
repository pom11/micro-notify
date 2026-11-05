"""File-backed secret storage for Linux and containers.

This is the Linux/container half of :mod:`micro_notify.secrets`. The facade
selects it explicitly with ``MICRO_NOTIFY_SECRETS=file``; there is no implicit
fallback and macOS keeps using the keychain.

Layout and rules (binding decisions for the L1 card):

* ``MICRO_NOTIFY_SECRETS_DIR`` is a directory path, never a secret value.
* one file per account, named by the literal account string, except that the
  teams separator maps ``:`` -> ``__`` (:func:`account_filename`). The mapping
  is pure and is the only place a caller has to look.
* an item must be a regular file (never a symlink), mode 0400 or 0600 owned by
  the effective uid, or a read-only provisioned file (no owner/group/other
  write bits, world-readable) such as a root:root 0444 Docker secret.
* group- or other-writable files are unreadable, not absent: ``probe()`` says
  ``unreadable`` and ``get()`` raises :class:`~micro_notify.secrets.KeychainError`
  (exit 4). A missing file is absent (exit 44 -> 4), like a missing keychain item.
* writes are atomic (temp file in the same directory + ``os.replace``), mode
  0600, and refuse a directory this uid cannot write to.
* values never enter argv, environment variables or messages; errors name the
  account and path only.
"""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path

from .secrets import (
    EXIT_ITEM_NOT_FOUND,
    SECRETS_BACKEND_ENV,
    SECRETS_DIR_ENV,
    KeychainError,
    KeychainItemMissing,
    SecretBackendError,
    account_name,
)

_TEMP_PREFIX = ".mnotify-secret-"


def _effective_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else -1


def account_filename(account: str) -> str:
    """Return the one file name used for ``account`` (pure, documented mapping).

    The literal account is the file name; only the teams separator changes,
    ``teams:facturare`` -> ``teams__facturare``. Path separators and the two
    dot entries are refused rather than allowed to escape the secrets
    directory; accounts are fixed names or ``teams:<target>`` in normal use.
    """
    if not account:
        raise KeychainError("account must be a non-empty string")
    name = str(account).replace(":", "__")
    if name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise KeychainError(
            f"account '{account_name(account)}' cannot be mapped to a file name"
        )
    return name


def secrets_dir(environ: Mapping[str, str] | None = None) -> Path:
    """The configured secrets directory, or exit 2 when it is not set."""
    env = os.environ if environ is None else environ
    raw = env.get(SECRETS_DIR_ENV, "")
    if not raw:
        raise SecretBackendError(
            f"{SECRETS_DIR_ENV} must be set when {SECRETS_BACKEND_ENV}=file"
        )
    return Path(raw)


def path_for(account: str, environ: Mapping[str, str] | None = None) -> Path:
    """Full path of the file backing ``account`` (inside the configured dir)."""
    return secrets_dir(environ) / account_filename(account)


def _missing(account: str, path: Path) -> KeychainItemMissing:
    return KeychainItemMissing(
        f"file secret read failed for account '{account_name(account)}' "
        f"(path '{path}', exit {EXIT_ITEM_NOT_FOUND})"
    )


def _unreadable(account: str, path: Path, reason: str) -> KeychainError:
    return KeychainError(
        f"file secret read failed for account '{account_name(account)}' "
        f"(path '{path}': {reason})"
    )


def _read_refusal(info: os.stat_result) -> str:
    """Why ``info`` is not an acceptable secret file, or ``""`` when it is."""
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode):
        return "not a regular file"
    if mode & 0o022:
        return f"mode {mode:04o} is writable by group or other"
    if info.st_uid == _effective_uid():
        if mode in (0o400, 0o600):
            return ""
        return f"mode {mode:04o} is not 0400 or 0600 for the owner"
    # Provisioned read-only file (the Docker secrets convention): nobody may
    # write it, and it is world-readable so a non-root container uid can read.
    if (mode & 0o222) == 0 and (mode & 0o004):
        return ""
    return f"mode {mode:04o} is not a readable read-only provisioned file"


def get(account: str, environ: Mapping[str, str] | None = None) -> str:
    """Read ``account`` from the file backend; absent and unreadable stay distinct."""
    path = path_for(account, environ)
    try:
        link_info = os.lstat(path)
    except FileNotFoundError as exc:
        raise _missing(account, path) from exc
    except OSError as exc:
        raise _unreadable(account, path, type(exc).__name__) from exc
    if stat.S_ISLNK(link_info.st_mode):
        raise _unreadable(account, path, "symlink refused")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise _missing(account, path) from exc
    except OSError as exc:
        reason = "symlink refused" if exc.errno == errno.ELOOP else type(exc).__name__
        raise _unreadable(account, path, reason) from exc

    try:
        info = os.fstat(fd)
        reason = _read_refusal(info)
        if reason:
            raise _unreadable(account, path, reason)
        with os.fdopen(fd, "r", encoding="utf-8", newline="") as handle:
            fd = -1
            try:
                return handle.read()
            except UnicodeDecodeError as exc:
                raise _unreadable(account, path, "not valid UTF-8") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _ensure_writable_dir(root: Path) -> None:
    """Refuse to write unless ``root`` is a real directory this uid can write."""
    try:
        info = os.lstat(root)
    except FileNotFoundError as exc:
        raise KeychainError(
            f"file secret write refused: secrets directory '{root}' does not exist"
        ) from exc
    except OSError as exc:
        raise KeychainError(
            f"file secret write refused: secrets directory '{root}' cannot be "
            f"inspected ({type(exc).__name__})"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise KeychainError(
            f"file secret write refused: secrets directory '{root}' is not a directory"
        )
    mode = stat.S_IMODE(info.st_mode)
    if (mode & 0o222) == 0 or not os.access(root, os.W_OK):
        raise KeychainError(
            f"file secret write refused: secrets directory '{root}' is not writable "
            f"by uid {_effective_uid()} (mode {mode:04o})"
        )


def set_secret(
    account: str, value: str, environ: Mapping[str, str] | None = None
) -> None:
    """Atomically write ``value`` for ``account`` as a 0600 file in the root."""
    if not isinstance(value, str):
        raise KeychainError(f"secret for account '{account_name(account)}' must be a string")
    path = path_for(account, environ)
    root = path.parent
    _ensure_writable_dir(root)

    fd = -1
    tmp_name: str | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=_TEMP_PREFIX, dir=str(root))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            fd = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
    except OSError as exc:
        raise KeychainError(
            f"file secret write failed for account '{account_name(account)}' "
            f"(path '{path}': {type(exc).__name__})"
        ) from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def delete(account: str, environ: Mapping[str, str] | None = None) -> bool:
    """Unlink ``account``; ``False`` when there was nothing to delete."""
    path = path_for(account, environ)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise KeychainError(
            f"file secret delete failed for account '{account_name(account)}' "
            f"(path '{path}': {type(exc).__name__})"
        ) from exc
    return True


__all__ = [
    "account_filename",
    "delete",
    "get",
    "path_for",
    "secrets_dir",
    "set_secret",
]
