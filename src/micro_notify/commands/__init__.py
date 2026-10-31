"""Command modules (design section 4) and the helpers they share.

Each module exposes three names and is registered here:

    NAME                  the subcommand string (``mnotify <NAME> ...``)
    add_parser(subparsers)  declares the whole surface for that subcommand
    run(args) -> int        executes it; raises MicroNotifyError on failure

This package is the shared seam for build steps 2-5: the helpers two commands
would otherwise duplicate live here (``read_text_argument``, ``print_json``,
``error_payload``, ``emit_error``, ``not_implemented``) so those steps never edit
``cli.py`` or ``conftest.py``.

The helper definitions deliberately precede the command imports below: the
command modules import these names from this package, so importing them first
would deadlock on a partially initialised module.
"""

from __future__ import annotations

import argparse
import json
import sys
from types import ModuleType
from typing import Any

from .. import EXIT_USAGE, NotImplementedYet, UsageError


def not_implemented(command: str, build_step: str) -> NotImplementedYet:
    """The exception a stubbed command raises — loud, never a fake success."""
    return NotImplementedYet(
        f"`{command}` is not implemented yet (design section 8 build step {build_step}); "
        "nothing was sent."
    )


def error_payload(message: str, exit_code: int) -> dict[str, Any]:
    """Machine-readable error object, shared shape for every command."""
    return {"ok": False, "outcome": "error", "exitCode": exit_code, "message": message}


def print_json(payload: dict[str, Any]) -> None:
    """Emit one JSON document on stdout (design section 4 ``--json``)."""
    json.dump(payload, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()


def emit_error(args: argparse.Namespace, message: str, exit_code: int = EXIT_USAGE) -> int:
    """Report a command-level failure in the mode the caller asked for."""
    if getattr(args, "json", False):
        print_json(error_payload(message, exit_code))
    else:
        print(f"mnotify: {message}", file=sys.stderr)
    return exit_code


def read_text_argument(
    explicit: str | None,
    file_path: str | None,
    *,
    flag: str,
    file_flag: str,
) -> str:
    """Resolve ``--flag TEXT | --file-flag F | stdin`` into text.

    ``--flag`` and ``--file-flag`` are mutually exclusive in the parsers, so a
    conflict is already an argparse exit 2. With neither given, the body comes
    from stdin; an interactive terminal with no body is a usage error rather
    than a hang.
    """
    if file_path:
        from pathlib import Path

        path = Path(file_path).expanduser()
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise UsageError(f"{file_flag}: cannot read {path} ({type(exc).__name__})") from exc
    if explicit is not None:
        return explicit
    if sys.stdin is None or sys.stdin.isatty():
        raise UsageError(f"no body: pass {flag} / {file_flag}, or pipe the text on stdin")
    return sys.stdin.read()


# Imported last, for the reason stated in the module docstring.
from . import config_cmd, doctor, log, mail, setup, teams  # noqa: E402
from . import admin  # noqa: E402  # B5: appended line, so this file stays deletion-free

# Order here is the order in `mnotify --help`.
COMMAND_MODULES: tuple[ModuleType, ...] = (
    mail,
    teams,
    setup,
    doctor,
    log,
    config_cmd,
    admin,
)


__all__ = [
    "COMMAND_MODULES",
    "emit_error",
    "error_payload",
    "not_implemented",
    "print_json",
    "read_text_argument",
]
