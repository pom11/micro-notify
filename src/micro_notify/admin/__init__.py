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

``admin/entra.py``
    :func:`~micro_notify.admin.entra.ensure_entra_app` — the idempotent app
    registration + service principal step, returning
    :class:`~micro_notify.admin.entra.EntraProvisioning` (``app_id``,
    ``sp_object_id``, ``created``). Its two ``find_*`` functions are exported so a
    read-only command (``doctor``) can ask "does it exist?" without any chance of
    creating one; ``create_app`` / ``create_service_principal`` are deliberately
    **not** re-exported here, because calling one directly skips the find-first
    rule that keeps a re-run from registering a second application.

``admin/exo.py``
    :func:`~micro_notify.admin.exo.ensure_exchange_scope` — the idempotent
    Exchange Online scoping step: it generates the one PowerShell script that
    grants ``Application Mail.Send`` to the service principal inside a
    sender-only management scope, runs it once through the pwsh seam, and refuses
    to report success unless the scope is *proven* (sender ``InScope True``
    through our scope, signed-in admin ``InScope False``).
    :func:`~micro_notify.admin.exo.plan_commands` is its dry-run surface: the
    planned argv plus the script text, written by nobody. ``build_script`` and the
    file/parse helpers stay module-level rather than being re-exported here, so a
    caller cannot run the script while skipping the verification that
    ``ensure_exchange_scope`` wraps around it.

Two rules every module here inherits from the package root:

* nothing in this package prompts, installs, writes a config entry or logs a
  secret — it probes, it reports, and the command layer (B5) decides what to do;
* ``az login`` / ``Connect-ExchangeOnline`` are never run for the operator. The
  pre-flight tells them to run it; it does not run it.
"""

from __future__ import annotations

from .entra import (
    EntraError,
    EntraProvisioning,
    ensure_entra_app,
    find_app_id,
    find_service_principal_id,
)
from .exo import (
    ExchangeError,
    ExchangeProvisioning,
    ensure_exchange_scope,
)
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
    "EntraError",
    "EntraProvisioning",
    "ExchangeError",
    "ExchangeProvisioning",
    "FAIL",
    "OK",
    "PreflightReport",
    "SubprocessRunner",
    "WARN",
    "CheckResult",
    "ensure_entra_app",
    "ensure_exchange_scope",
    "find_app_id",
    "find_service_principal_id",
    "get_runner",
    "plan_installs",
    "run_json",
    "run_preflight",
    "set_runner",
    "which",
]
