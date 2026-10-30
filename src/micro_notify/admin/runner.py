"""The one fakeable command runner used by every ``mnotify admin`` probe.

Why this module exists
----------------------

The admin flow shells out to three third-party CLIs — ``az`` (Azure CLI),
``pwsh`` (PowerShell, for Exchange Online) and ``brew`` (installs). Each of them
would be a test that cannot run on CI: ``az`` needs a logged-in tenant, ``pwsh``
needs a module installed, ``brew`` changes the machine. So nothing in
:mod:`micro_notify.admin` calls :func:`subprocess.run` directly. Every exec goes
through the seam below, which tests replace with a fake that answers canned JSON.

Declared seams (later admin cards read them, never edit them)
-------------------------------------------------------------

* :class:`CommandRunner` — the protocol: one ``run(argv, *, stdin=None)`` method.
* :func:`set_runner` / :func:`get_runner` — the process-wide injection seam, the
  same shape :func:`micro_notify.secrets.set_runner` already uses, so a test
  fixture installs a fake once and every admin probe lands on it.
* :class:`DryRunRunner` — records every argv it is handed and executes **nothing**;
  ``mnotify admin bootstrap --dry-run`` is built on this, not on an ``if dry_run``
  branch sprinkled through the command modules.
* :func:`which` and :func:`run_json` — the two helpers every probe needs.

Rules this module keeps
-----------------------

* ``argv`` is always a list and ``shell`` is never used, so no caller can get
  shell injection from a mailbox address or a display name containing quotes;
* a non-zero exit is **returned, not raised** — a check has to be able to read the
  exit code and stderr and turn them into an operator-facing hint;
* a missing binary or a timeout is likewise turned into an ordinary result
  (exit 127 / 124) instead of an exception, so a probe reports "not installed"
  rather than crashing the CLI;
* nothing here prints. Callers own stdout; this module only returns bytes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol, cast

from .. import UsageError

# A pre-flight probe is a short Azure/Graph round trip; long enough for a slow
# tenant, short enough that a hung CLI cannot hang the operator's terminal.
SUBPROCESS_TIMEOUT = 60.0

# Exit codes this module synthesises when the exec itself never happened. 127 and
# 124 are the shell's own conventions for "not found" and "timed out", reused here
# so a fake runner can reproduce them without learning a private vocabulary.
EXIT_NOT_FOUND = 127
EXIT_TIMEOUT = 124

# How much stderr a CommandError quotes. Enough for one az error line, short enough
# that a stack dump or a token blob cannot ride along into the terminal.
STDERR_QUOTE_LIMIT = 200


class CommandError(UsageError):
    """A probe could not be run, or its output was not usable -> exit 2.

    The message names the executable and the exit code. It quotes at most
    :data:`STDERR_QUOTE_LIMIT` characters of stderr, because that is where the
    tool's own diagnosis lives; it never contains a token or a private key, and
    it never contains a value passed on stdin (which is where a secret would be,
    if anything ever had one to pass).
    """


class CommandResult(Protocol):
    """The ``subprocess.CompletedProcess``-like shape a runner must return.

    A fake may return a real ``CompletedProcess`` or a ``SimpleNamespace``; only
    these three attributes are read anywhere in this package.
    """

    @property
    def argv(self) -> Sequence[str]: ...
    @property
    def returncode(self) -> int: ...
    @property
    def stdout(self) -> str | None: ...
    @property
    def stderr(self) -> str | None: ...


class CommandRunner(Protocol):
    """Everything the admin package knows about "run a command".

    ``argv`` is an argument vector, never a shell string. ``stdin`` is text fed to
    the process and closed — it exists so a caller never has to put a secret in
    argv, where it would be visible in ``ps`` and in shell history.
    """

    def run(
        self, argv: Sequence[str], *, stdin: str | None = None
    ) -> Any: ...


class SubprocessRunner:
    """The default :class:`CommandRunner`: a real ``subprocess.run``.

    Executed with no shell, captured as text, bounded by ``timeout``. Failures of
    the exec itself are converted into ordinary results (see the module docstring)
    so that callers have exactly one way to learn what happened — the return code.
    """

    def __init__(self, timeout: float = SUBPROCESS_TIMEOUT) -> None:
        self.timeout = timeout

    def run(
        self, argv: Sequence[str], *, stdin: str | None = None
    ) -> subprocess.CompletedProcess:
        args = [str(a) for a in argv]
        if not args:
            raise CommandError("cannot run an empty command")
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                input=stdin,
                check=False,
            )
        except FileNotFoundError:
            return _synthetic(args, EXIT_NOT_FOUND, f"command not found: {args[0]}")
        except PermissionError:
            return _synthetic(args, EXIT_NOT_FOUND, f"not executable: {args[0]}")
        except subprocess.TimeoutExpired:
            return _synthetic(
                args, EXIT_TIMEOUT, f"timed out after {self.timeout:g}s: {args[0]}"
            )
        except OSError as exc:
            # type + errno only: an OSError str can carry the full command line.
            return _synthetic(args, EXIT_NOT_FOUND, f"{args[0]}: {type(exc).__name__}")


class DryRunRunner:
    """A :class:`CommandRunner` that records and never executes.

    Every argv (and whether it carried stdin) is appended to :attr:`calls`; the
    result is a canned success whose stdout is either the per-call response the
    test or command supplied, or empty. Nothing is imported, spawned or written:
    a dry run of the admin flow must be able to run on a machine with no ``az``
    installed and no network, and must not change a tenant that is already set up.

    ``responses`` maps a command prefix — the argv tuple to match from its start —
    to the stdout a caller needs in order to be believed. B5 uses it to make a
    dry-run report look like the real one without lying about a probe it skipped.
    """

    def __init__(
        self,
        responses: dict[tuple[str, ...], str] | None = None,
        *,
        returncode: int = 0,
    ) -> None:
        self.calls: list[list[str]] = []
        self.stdin_payloads: list[str | None] = []
        self.responses = dict(responses or {})
        self.returncode = returncode

    def run(
        self, argv: Sequence[str], *, stdin: str | None = None
    ) -> subprocess.CompletedProcess:
        args = [str(a) for a in argv]
        self.calls.append(args)
        self.stdin_payloads.append(stdin)
        return _synthetic(args, self.returncode, "", self._stdout_for(args))

    def _stdout_for(self, args: Sequence[str]) -> str:
        """Longest matching prefix response, so ``az account show`` can answer
        more specifically than every ``az`` call."""
        best: tuple[str, ...] | None = None
        for prefix in self.responses:
            if len(prefix) > len(args) or tuple(args[: len(prefix)]) != prefix:
                continue
            if best is None or len(prefix) > len(best):
                best = prefix
        return self.responses[best] if best is not None else ""

    @property
    def executed_anything(self) -> bool:
        """Always False — the point of the class, exposed so a test can assert it."""
        return False


# --- Process-wide seam -----------------------------------------------------
# Same shape as micro_notify/secrets.py: one dict, `set_runner()` clears it.
_runner_flags: dict[str, Any] = {}


def set_runner(runner: CommandRunner | Callable[..., Any] | None = None, **kwargs: Any) -> None:
    """Install the process-wide runner; ``set_runner()`` restores the real one.

    Accepts anything with a ``run`` method, and also a bare callable (adapter
    below) so a test can hand over a lambda or a ``__call__``-style fake in the
    style of the shared ``fake_keychain`` fixture.
    """
    _runner_flags.clear()
    if runner is not None:
        _runner_flags["runner"] = (
            runner if hasattr(runner, "run") else _CallableRunner(cast("Any", runner))
        )
    _runner_flags.update(kwargs)


def get_runner() -> CommandRunner:
    """The runner in effect right now (the real one unless a test replaced it)."""
    runner = _runner_flags.get("runner")
    return runner if runner is not None else SubprocessRunner()


class _CallableRunner:
    """Adapts ``fn(argv, **kwargs) -> result`` to :class:`CommandRunner`."""

    def __init__(self, fn: Callable[..., Any]) -> None:
        self._fn = fn

    def run(
        self, argv: Sequence[str], *, stdin: str | None = None
    ) -> Any:
        return self._fn([str(a) for a in argv], stdin=stdin)


# --- Helpers ---------------------------------------------------------------
def which(name: str) -> Path | None:
    """Absolute :class:`~pathlib.Path` for ``name`` on ``PATH``, else ``None``.

    A pure lookup (``shutil.which``): it never executes the binary, so a
    "is it installed?" check costs nothing and cannot prompt, upgrade or
    register anything.
    """
    if not name:
        return None
    found = shutil.which(name)
    return Path(found) if found else None


def run_json(
    argv: Sequence[str],
    *,
    runner: CommandRunner | None = None,
    stdin: str | None = None,
) -> Any:
    """Run ``argv`` and parse its stdout as JSON (``az`` prints JSON by default).

    Raises :class:`CommandError` — never ``json.JSONDecodeError`` and never a
    bare non-zero exit — because a pre-flight check that cannot read the answer
    has to report that plainly instead of tracebacking.
    """
    args = [str(a) for a in argv]
    result = (runner or get_runner()).run(args, stdin=stdin)
    return parse_json_result(result, args[0] if args else "<empty command>")


def parse_json_result(result: Any, label: str) -> Any:
    """Parse ``result.stdout`` as JSON, turning every failure into CommandError.

    Split out from :func:`run_json` so a check that already holds a result from a
    previous probe (or a fake) can reuse the exact same failure wording.
    """
    returncode = int(getattr(result, "returncode", 1) or 0)
    stdout = getattr(result, "stdout", None) or ""
    stderr = getattr(result, "stderr", None) or ""

    text = stdout.strip()
    if text:
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            pass  # fall through to the shared failure wording below
    if returncode != 0:
        raise CommandError(
            f"'{label}' exited {returncode}{_quote(stderr)}"
        )
    raise CommandError(
        f"'{label}' did not print JSON{_quote(stderr)}"
    )


def _quote(stderr: str) -> str:
    """One collapsed, length-bounded line of the tool's own stderr, or ``''``."""
    line = " ".join((stderr or "").split())
    if not line:
        return ""
    if len(line) > STDERR_QUOTE_LIMIT:
        line = line[:STDERR_QUOTE_LIMIT].rstrip() + "..."
    return f" — {line}"


def _synthetic(
    args: Sequence[str], returncode: int, stderr: str, stdout: str = ""
) -> subprocess.CompletedProcess:
    """A result for an exec that never happened, shaped like one that did."""
    return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)


__all__ = [
    "EXIT_NOT_FOUND",
    "EXIT_TIMEOUT",
    "STDERR_QUOTE_LIMIT",
    "SUBPROCESS_TIMEOUT",
    "CommandError",
    "CommandResult",
    "CommandRunner",
    "DryRunRunner",
    "SubprocessRunner",
    "get_runner",
    "parse_json_result",
    "run_json",
    "set_runner",
    "which",
]
