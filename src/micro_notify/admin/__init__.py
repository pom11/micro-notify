"""Operator-side admin tooling (design §6), starting with the pre-flight layer.

This package holds the code behind ``mnotify admin bootstrap`` — the one-command
version of the tenant steps written by hand in ``docs/ADMIN-SETUP.md``. Build card
B1 owns the two modules below; later cards (B2 the app registration, B3 the
Exchange scoped role, B4 Teams targets, B5 the ``admin bootstrap`` command itself)
**read** these seams and must never edit them:

``admin/runner.py``
    :class:`~micro_notify.admin.runner.CommandRunner` — the one and only way this
    package talks to ``az`` / ``pwsh`` / ``brew``; :func:`~micro_notify.admin.runner.set_runner`
    — the process-wide injection seam (same shape as :mod:`micro_notify.secrets`);
    :class:`~micro_notify.admin.runner.DryRunRunner` — records argv, executes nothing.

``admin/preflight.py``
    :class:`~micro_notify.admin.preflight.CheckResult` (``name``, ``status``
    ``ok|fail|warn``, ``detail``, ``fix_hint``, ``install_hint``),
    :func:`~micro_notify.admin.preflight.run_preflight` and
    :func:`~micro_notify.admin.preflight.plan_installs`.

Two rules every module here inherits from the package root:

* nothing in this package prompts, installs, writes a config entry or logs a
  secret — it probes, it reports, and the command layer (B5) decides what to do;
* ``az login`` / ``Connect-ExchangeOnline`` are never run for the operator. The
  pre-flight tells them to run it; it does not run it.
"""

from __future__ import annotations

from .preflight import (
    CHECK_ORDER,
    FAIL,
    OK,
    WARN,
    CheckResult,
    PreflightReport,
    plan_installs,
    run_preflight,
)
from .runner import (
    CommandError,
    CommandRunner,
    DryRunRunner,
    SubprocessRunner,
    get_runner,
    run_json,
    set_runner,
    which,
)

__all__ = [
    "CHECK_ORDER",
    "CommandError",
    "CommandRunner",
    "DryRunRunner",
    "FAIL",
    "OK",
    "PreflightReport",
    "SubprocessRunner",
    "WARN",
    "CheckResult",
    "get_runner",
    "plan_installs",
    "run_json",
    "run_preflight",
    "set_runner",
    "which",
]
