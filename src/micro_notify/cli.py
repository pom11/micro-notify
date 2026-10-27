"""Argparse root and the subcommand dispatch table (design section 4).

Every subcommand and flag of design section 4 is declared here or in the command
module that owns it, so build steps 2-5 never edit this file. Command modules
register their own parsers (``add_parser``) and provide ``run(args) -> int``.

Shared contract later modules rely on:

* ``main(argv)`` returns the exit code; the console-script wrapper maps it with
  ``sys.exit``. Unknown subcommands / bad flags exit 2 via argparse itself.
* Handlers raise :class:`micro_notify.MicroNotifyError` subclasses; this module
  is the only place that turns them into exit codes, and it never prints an
  exception traceback for an expected error.
* Error output shape for machine mode (``--json`` on the subcommand)::

      {"ok": false, "outcome": "error", "exitCode": <int>, "message": "<text>"}

  Success output is produced by the command itself with the design section 4
  shape ``{"ok": true, "outcome": ..., "requestId": ..., "recipients": [...]}``.
* Exit 1 means an unexpected crash (a bug), never a documented outcome; 130 is
  the shell convention for Ctrl-C and is not part of the section 4 contract.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any

from . import (
    EXIT_USAGE,
    MicroNotifyError,
    __version__,
)
from .commands import COMMAND_MODULES

# Subcommand name -> handler. Built from the command-module table so adding a
# module (or reading which module owns what) stays a one-line change here.
DISPATCH: dict[str, Callable[[argparse.Namespace], int]] = {
    module.NAME: module.run for module in COMMAND_MODULES
}


def build_parser() -> argparse.ArgumentParser:
    """Build the ``mnotify`` root parser with every design section 4 surface."""
    parser = argparse.ArgumentParser(
        prog="mnotify",
        description=(
            "Send email (Microsoft Graph) and Teams messages (Workflows webhooks) "
            "from agents and scripts."
        ),
        epilog=(
            "exit codes: 0 sent | 2 usage/config | 3 refused by guard | "
            "4 auth | 5 remote | 6 daily cap"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mnotify {__version__}",
        help="print version and exit",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for module in COMMAND_MODULES:
        module.add_parser(subparsers)
    return parser


def error_payload(message: str, exit_code: int) -> dict[str, Any]:
    """Machine-readable error object (shared shape for every command)."""
    return {"ok": False, "outcome": "error", "exitCode": exit_code, "message": message}


def _report(exc: MicroNotifyError, args: argparse.Namespace) -> int:
    """Print an expected error and return the exit code it carries."""
    if getattr(args, "json", False):
        json.dump(error_payload(exc.message, exc.exit_code), sys.stdout)
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        print(f"mnotify: {exc.message}", file=sys.stderr)
    return exc.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Parse ``argv``, dispatch, map typed errors to exit codes."""
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    command = getattr(args, "command", None)
    if not command:
        parser.print_usage(sys.stderr)
        print("mnotify: a subcommand is required (see `mnotify --help`)", file=sys.stderr)
        return EXIT_USAGE

    handler = DISPATCH[command]
    try:
        return handler(args)
    except MicroNotifyError as exc:
        return _report(exc, args)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("mnotify: interrupted", file=sys.stderr)
        return 130


def entrypoint() -> None:  # pragma: no cover - console-script shim
    sys.exit(main())


__all__ = ["DISPATCH", "build_parser", "entrypoint", "error_payload", "main"]
