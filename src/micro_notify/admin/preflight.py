"""Ordered, read-only pre-flight checks for ``mnotify admin bootstrap``.

What this module is
-------------------

Six checks an operator's machine and tenant must pass before the bootstrap can
register an app, scope a mailbox and wire Teams (docs/ADMIN-SETUP.md §Before you
start, §step 2, §step 5). Each check runs **read-only probes** through
:mod:`micro_notify.admin.runner` and returns a :class:`CheckResult`. Nothing here
prompts, installs, writes a config file, creates a tenant object, or prints a
secret — the install step (``--install-missing``, the y/N prompt, the ``brew``
call) belongs to B5, and this module keeps its side-effect-free promise so B5 can
call the checks first and dry-run them for real.

The checks, in the order an operator hits them
----------------------------------------------

``az-cli``               is ``az`` on PATH                      -> fail, install azure-cli
``az-login``             is ``az`` signed in                    -> fail, **the operator** runs ``az login``
``admin-roles``          does that account hold the admin roles -> fail, name what is missing
``pwsh``                 is ``pwsh`` on PATH                    -> fail, install powershell
``exchange-module``      is ExchangeOnlineManagement installed   -> fail, ``Install-Module``
``sender-mailbox``       does the sender address resolve         -> fail, fix the mailbox/``--sender``

Why ``az login`` is never run for you
------------------------------------

``az login`` opens a browser and needs a human — possibly an MFA prompt, possibly
a password. A CLI that launches it behind your back can hang a script, silently
switch tenants, or put an interactive prompt inside someone else's automation. So
this check reports what is missing and stops; it does not help. Same reasoning for
``Connect-ExchangeOnline``.

Why the role check reads ``memberOf`` and nothing else
-----------------------------------------------------

Requirement: **Global Administrator**, or **both** Application Administrator and
Exchange Administrator (the pair that can register an app and make the Exchange
delegating assignment). The cheapest authoritative-enough evidence is the group
memberships the signed-in account already carries::

    az rest --method GET --uri https://graph.microsoft.com/v1.0/me/memberOf

Do **not** "improve" this into the ``/roleManagement/directory/`` eligibility or
activations APIs. Those need ``RoleManagement.Read.Directory`` (or similar), which
the token ``az`` hands us does not carry — proven live on 2026-10-30: the call
comes back ``Authorization_RequestDenied`` and the check would report "you do not
have the role" when the truth is "I could not look". ``memberOf`` is reachable
with the token ``az`` already has, and it is the same membership Graph shows the
admin portal.

It is an *advisory* signal in one direction: holding a role group assignment can
also arrive via PIM activation or a directory role that is not in ``memberOf``, so
a fail here says "not visible to this check", and the fix hint says so rather than
claiming the operator is wrong.

Statuses, and what a skipped check looks like
---------------------------------------------

``CheckResult.status`` is exactly ``ok`` | ``fail`` | ``warn`` — that shape is a
declared seam for later cards, so no fourth value is invented here. When a check
cannot run because an earlier one blocked it (no ``az`` -> no signed-in probe), the
dependent is reported as ``warn`` whose detail says **"not evaluated"**, and its
name is also listed in :attr:`PreflightReport.skipped`. ``ok`` stays False either
way, because the blocking check failed. A ``warn`` on its own never makes a report
not-ok: it means "could not verify", not "verified bad".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .runner import CommandError, CommandRunner, get_runner, run_json

# --- Vocabulary -------------------------------------------------------------
OK = "ok"
FAIL = "fail"
WARN = "warn"

# Check names, in run order. A declared seam: B5 prints these and tests pin them.
CHECK_AZ_CLI = "az-cli"
CHECK_AZ_LOGIN = "az-login"
CHECK_ADMIN_ROLES = "admin-roles"
CHECK_PWSH = "pwsh"
CHECK_EXO_MODULE = "exchange-module"
CHECK_SENDER = "sender-mailbox"

CHECK_ORDER: tuple[str, ...] = (
    CHECK_AZ_CLI,
    CHECK_AZ_LOGIN,
    CHECK_ADMIN_ROLES,
    CHECK_PWSH,
    CHECK_EXO_MODULE,
    CHECK_SENDER,
)

# --- Installable fixes ------------------------------------------------------
# The Homebrew formula that provides each binary (design §5 ships via brew).
AZ_FORMULA = "azure-cli"
PWSH_FORMULA = "powershell"

# The PowerShell module the Exchange steps in ADMIN-SETUP §step 2 need. Not a brew
# formula: it comes from the PowerShell Gallery, so it is fixable but not
# `plan_installs`-able.
EXO_MODULE = "ExchangeOnlineManagement"

INSTALL_AZ_HINT = f"brew install {AZ_FORMULA}"
INSTALL_PWSH_HINT = f"brew install {PWSH_FORMULA}"
INSTALL_EXO_HINT = (
    f"Install-Module -Name {EXO_MODULE} -Scope CurrentUser -Force "
    "(from an elevated pwsh; ADMIN-SETUP 'Before you start')"
)
LOGIN_HINT = (
    "run `az login` yourself — mnotify never signs you in; it can need a browser, "
    "MFA or a password, and a CLI that guesses your tenant is worse than one that asks"
)
ROLES_HINT = (
    "ask a Global Administrator to add this account to Global Administrator, or to "
    "both Application Administrator and Exchange Administrator (ADMIN-SETUP 'Before "
    "you start'); or run the bootstrap as someone who already holds them"
)
EXCH_ROLE_GROUP_HINT = (
    "Exchange Online also needs membership of the Organization Management role group "
    "to make the delegating assignment (ADMIN-SETUP §step 2)"
)
SENDER_HINT = (
    "create the mailbox, or pass the address that exists: `mnotify admin bootstrap "
    "--sender noreply@example.com` (a shared mailbox is fine — ADMIN-SETUP §step 5)"
)

# Graph's own collection of "groups this account belongs to". Reachable with the
# token az already holds; see the module docstring before changing it.
GRAPH_MEMBER_OF_URI = "https://graph.microsoft.com/v1.0/me/memberOf"

GLOBAL_ADMIN_ROLE = "Global Administrator"
APP_ADMIN_ROLE = "Application Administrator"
EXCHANGE_ADMIN_ROLE = "Exchange Administrator"

# An account satisfies the requirement with this one role...
REQUIRED_ANY = (GLOBAL_ADMIN_ROLE,)
# ...or with all of these together.
REQUIRED_ALL_ALTERNATIVE = (APP_ADMIN_ROLE, EXCHANGE_ADMIN_ROLE)

# memberOf is paged. Following the next links costs one read-only call per page and
# prevents a false "missing role" for an operator in many groups; the cap keeps a
# pathological tenant from turning a pre-flight into a crawl.
MAX_MEMBER_OF_PAGES = 10

# Cap on how many group names are echoed back, so a 300-group tenant cannot flood
# the terminal with the "found" half of the message.
MAX_LISTED_GROUPS = 12

NOT_EVALUATED = "not evaluated"


class PreflightError(CommandError):
    """The pre-flight could not be run at all -> exit 2.

    Deliberately rare: an individual check that fails is a :class:`CheckResult`,
    not an exception. This is only for "we could not even start asking questions",
    e.g. an empty sender address.
    """


# --- Result shapes (declared seam) ------------------------------------------
@dataclass(frozen=True)
class CheckResult:
    """One check's verdict. Shape is a contract for B2-B5; do not extend casually.

    ``detail`` is operator-facing prose about what was *seen* (a tenant id, a
    version, a missing role) — never a token, and never a value that was passed to
    a probe on stdin.

    ``fix_hint`` is the next action that makes this check pass. ``install_hint`` is
    the narrower thing: the **Homebrew formula name** when a missing package is the
    whole problem, otherwise ``None``. Keeping it a formula name (not a sentence)
    is what lets :func:`plan_installs` answer without parsing prose.

    ``details`` is an additive, machine-readable companion for the facts a check
    extracted (tenant id, tenant name, UPN), so the aggregate report can surface
    them without re-parsing ``detail``. The five documented fields above keep their
    positions and meaning; nothing may rely on ``details`` holding a secret.
    """

    name: str
    status: str
    detail: str = ""
    fix_hint: str = ""
    install_hint: str | None = None
    details: Mapping[str, str] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status == FAIL

    def to_dict(self) -> dict[str, Any]:
        """Machine-readable form (``mnotify admin bootstrap --json``).

        ``installHint`` is omitted when there is nothing installable, so a consumer
        can tell "no fix to install" apart from "fix is install X" without reading
        an empty string.
        """
        payload: dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "fixHint": self.fix_hint,
        }
        if self.install_hint:
            payload["installHint"] = self.install_hint
        if self.details:
            payload["details"] = dict(self.details)
        return payload


@dataclass(frozen=True)
class PreflightReport:
    """Everything the pre-flight learned, in check order.

    ``ok`` is "no check failed". A ``warn`` — including the ``warn``/``skipped``
    pair used for checks a blocker prevented — does not make it False on its own;
    the blocker itself always fails, so a report that skipped something is never
    reported as green.
    """

    sender: str = ""
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    skipped: tuple[str, ...] = field(default_factory=tuple)
    tenant_id: str | None = None
    tenant_name: str | None = None
    signed_in_upn: str | None = None

    @property
    def ok(self) -> bool:
        return not any(check.status == FAIL for check in self.checks)

    @property
    def failing(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if check.status == FAIL)

    def by_name(self, name: str) -> CheckResult | None:
        for check in self.checks:
            if check.name == name:
                return check
        return None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "sender": self.sender,
            "checks": [check.to_dict() for check in self.checks],
        }
        if self.skipped:
            payload["skipped"] = list(self.skipped)
        for key, value in (
            ("tenantId", self.tenant_id),
            ("tenantName", self.tenant_name),
            ("signedInAs", self.signed_in_upn),
        ):
            if value:
                payload[key] = value
        return payload


# --- Check 1: az on PATH ----------------------------------------------------
def check_azure_cli(*, runner: CommandRunner | None = None) -> CheckResult:
    """``az`` is on PATH. A pure lookup — the binary is never executed."""
    from .runner import which

    path = which("az")
    if path is None:
        return CheckResult(
            CHECK_AZ_CLI,
            FAIL,
            detail="`az` (Azure CLI) is not on PATH",
            fix_hint=INSTALL_AZ_HINT,
            install_hint=AZ_FORMULA,
        )
    return CheckResult(CHECK_AZ_CLI, OK, detail=f"found {path}")


# --- Check 2: az is signed in ----------------------------------------------
def check_azure_signed_in(*, runner: CommandRunner | None = None) -> CheckResult:
    """``az account show`` answers, and carries a tenant + a signed-in principal.

    Read-only. On success the tenant id, tenant display name and UPN are also
    surfaced on the :class:`PreflightReport` (this returns them in ``details``), so
    the operator can see *which tenant* is about to be changed before anything is
    created. ``az login`` is never invoked here — see the module docstring.
    """
    active = get_runner() if runner is None else runner
    try:
        account = run_json(["az", "account", "show"], runner=active)
    except CommandError as exc:
        return CheckResult(
            CHECK_AZ_LOGIN,
            FAIL,
            detail=f"no usable Azure session ({exc.message})",
            fix_hint=LOGIN_HINT,
        )
    if not isinstance(account, dict):
        return CheckResult(
            CHECK_AZ_LOGIN,
            FAIL,
            detail="`az account show` did not print an object",
            fix_hint=LOGIN_HINT,
        )

    tenant_id = _text(account.get("tenantId")) or _text(account.get("homeTenantId"))
    upn = _nested_text(account.get("user"), "name")
    if not tenant_id or not upn:
        return CheckResult(
            CHECK_AZ_LOGIN,
            FAIL,
            detail="`az account show` answered without a tenant or a signed-in user",
            fix_hint=LOGIN_HINT,
        )

    # The subscription's `name` is NOT the tenant's name, so ask for the directory
    # explicitly. Read-only, and its absence only costs the prettier wording.
    tenant_name = _tenant_display_name(active, tenant_id)

    parts = [f"tenant {tenant_id}"]
    if tenant_name:
        parts.append(f"name {tenant_name}")
    parts.append(f"signed in as {upn}")
    return CheckResult(
        CHECK_AZ_LOGIN,
        OK,
        detail=", ".join(parts),
        details={"tenantId": tenant_id, "tenantName": tenant_name or "", "upn": upn},
    )


# --- Check 3: admin roles ---------------------------------------------------
def check_admin_roles(*, runner: CommandRunner | None = None) -> CheckResult:
    """The signed-in account holds Global Administrator, or App + Exchange admin.

    Evidence is ``memberOf`` (module docstring explains why, and why the
    eligibility APIs must not be used instead). Paging is followed up to
    :data:`MAX_MEMBER_OF_PAGES` so an operator in many groups is not falsely
    reported as missing a role.
    """
    active = get_runner() if runner is None else runner
    try:
        groups, paged_out = _member_of_display_names(active)
    except CommandError as exc:
        return CheckResult(
            CHECK_ADMIN_ROLES,
            FAIL,
            detail=f"could not read group memberships ({exc.message})",
            fix_hint=(
                "the signed-in session cannot query Graph for memberships; re-run "
                f"`az login` and retry — {ROLES_HINT}"
            ),
        )

    held = {name.casefold() for name in groups}
    missing_any = [role for role in REQUIRED_ANY if role.casefold() not in held]
    missing_all = [role for role in REQUIRED_ALL_ALTERNATIVE if role.casefold() not in held]
    satisfied = not missing_any or not missing_all

    found = _listed(groups)
    if satisfied:
        detail = (
            "holds " + GLOBAL_ADMIN_ROLE
            if not missing_any
            else f"holds {' and '.join(REQUIRED_ALL_ALTERNATIVE)}"
        )
        if paged_out:
            detail += f" (from the first {MAX_MEMBER_OF_PAGES} membership pages)"
        return CheckResult(CHECK_ADMIN_ROLES, OK, detail=detail)

    # A fail here always means both paths fell short (no Global Administrator and
    # an incomplete pair), so the roles worth naming are the ones missing from the
    # pair: naming Global Administrator as "missing" when the operator already
    # holds Application Administrator reads like a bug, not like a diagnosis.
    detail = (
        f"missing {_listed(missing_all) or '(none named)'} — needs "
        f"{GLOBAL_ADMIN_ROLE}, or both {APP_ADMIN_ROLE} and {EXCHANGE_ADMIN_ROLE}"
    )
    if found:
        detail += f"; visible memberships: {found}"
    if paged_out:
        detail += (
            f" (only the first {MAX_MEMBER_OF_PAGES} membership pages were read, so a "
            "role held further down is not visible here)"
        )
    detail += ". This check only sees group memberships; an active PIM assignment may not appear."
    fix_hint = ROLES_HINT
    if missing_all:
        # The Exchange half of the bootstrap needs the role group that holds the
        # delegating assignment, not just the Entra directory role (ADMIN-SETUP §2).
        fix_hint = f"{ROLES_HINT}. {EXCH_ROLE_GROUP_HINT}"
    return CheckResult(CHECK_ADMIN_ROLES, FAIL, detail=detail, fix_hint=fix_hint)


# --- Check 4: pwsh on PATH --------------------------------------------------
def check_powershell(*, runner: CommandRunner | None = None) -> CheckResult:
    """``pwsh`` is on PATH. A pure lookup — the binary is never executed."""
    from .runner import which

    path = which("pwsh")
    if path is None:
        return CheckResult(
            CHECK_PWSH,
            FAIL,
            detail="`pwsh` (PowerShell 7) is not on PATH; the Exchange Online steps need it",
            fix_hint=INSTALL_PWSH_HINT,
            install_hint=PWSH_FORMULA,
        )
    return CheckResult(CHECK_PWSH, OK, detail=f"found {path}")


# --- Check 5: ExchangeOnlineManagement module -------------------------------
def check_exchange_module(*, runner: CommandRunner | None = None) -> CheckResult:
    """The Exchange Online PowerShell module is installed for this user.

    Asks ``pwsh`` for the module's version without importing it: a bare
    ``Get-Module -ListAvailable`` never loads the module, so the probe cannot hang
    on a sign-in prompt. Empty output means "installed: no" (exit 0), which is why
    stdout decides the verdict rather than the exit code.
    """
    active = get_runner() if runner is None else runner
    argv = [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"Get-Module -ListAvailable {EXO_MODULE} | "
        "Select-Object -First 1 -ExpandProperty Version",
    ]
    result = active.run(argv)
    returncode = int(getattr(result, "returncode", 1) or 0)
    stderr = (getattr(result, "stderr", None) or "").strip()
    stdout = " ".join((getattr(result, "stdout", None) or "").split())

    if returncode != 0:
        return CheckResult(
            CHECK_EXO_MODULE,
            FAIL,
            detail=f"pwsh could not list installed modules (exit {returncode})"
            + (f": {stderr}" if stderr else ""),
            fix_hint=INSTALL_EXO_HINT,
        )
    if not stdout:
        return CheckResult(
            CHECK_EXO_MODULE,
            FAIL,
            detail=f"module {EXO_MODULE} is not installed for this user",
            fix_hint=INSTALL_EXO_HINT,
        )
    return CheckResult(CHECK_EXO_MODULE, OK, detail=f"{EXO_MODULE} {stdout}")


# --- Check 6: the sender mailbox exists ------------------------------------
def check_sender_mailbox(sender: str, *, runner: CommandRunner | None = None) -> CheckResult:
    """The sender address resolves to a real directory user.

    ``az ad user show --id`` accepts a UPN, which is what a mailbox address is for
    a licensed user *and* for a shared mailbox (a shared mailbox is still a user
    object, just not a sign-in-able one) — so a hit here is the cheap proof that
    the address in the config is not a typo. Nothing about mail-enabled-ness or
    licensing is inferred from it; that is what the scoped-role test in
    ADMIN-SETUP §step 2/3 is for.
    """
    address = (sender or "").strip()
    if not address:
        raise PreflightError(
            "a sender address is required — pass `--sender noreply@example.com`"
        )
    active = get_runner() if runner is None else runner
    try:
        user = run_json(["az", "ad", "user", "show", "--id", address], runner=active)
    except CommandError as exc:
        return CheckResult(
            CHECK_SENDER,
            FAIL,
            detail=f"no directory user for {address} ({exc.message})",
            fix_hint=SENDER_HINT,
        )
    if not isinstance(user, dict):
        return CheckResult(
            CHECK_SENDER,
            FAIL,
            detail=f"`az ad user show` did not print an object for {address}",
            fix_hint=SENDER_HINT,
        )
    resolved = _text(user.get("userPrincipalName")) or address
    object_id = _text(user.get("id")) or _text(user.get("objectId"))
    display = _text(user.get("displayName"))
    detail = f"found {resolved}"
    if display:
        detail += f" ({display})"
    if object_id:
        detail += f" id {object_id}"
    return CheckResult(CHECK_SENDER, OK, detail=detail + "; a shared mailbox is valid here")


# --- Aggregation -----------------------------------------------------------
def run_preflight(
    sender: str,
    *,
    runner: CommandRunner | None = None,
    include_exchange: bool = True,
) -> PreflightReport:
    """Run every check in :data:`CHECK_ORDER` and collect the verdicts.

    Side effects: read-only probes through the runner, and nothing else — no
    install, no prompt, no tenant write. Checks blocked by an earlier failure are
    reported as ``warn`` with a "not evaluated" detail and listed in
    :attr:`PreflightReport.skipped` (see the module docstring for why that is not a
    fourth status).

    ``include_exchange=False`` drops the two PowerShell checks, for a caller that
    only needs the Entra half; :data:`CHECK_ORDER` is still what a caller prints.
    """
    active = get_runner() if runner is None else runner
    # Fail before the first probe: a bootstrap with no sender is not worth running
    # six read-only calls for, and the answer would be the same every time.
    address = (sender or "").strip()
    if not address:
        raise PreflightError(
            "a sender address is required — pass `--sender noreply@example.com`"
        )
    checks: list[CheckResult] = []
    skipped: list[str] = []
    facts: dict[str, Any] = {}

    def record(result: CheckResult) -> CheckResult:
        checks.append(result)
        return result

    def skip(name: str, blocked_by: str) -> None:
        checks.append(
            CheckResult(
                name,
                WARN,
                detail=f"{NOT_EVALUATED}: {blocked_by} did not pass",
                fix_hint=f"fix `{blocked_by}` first, then re-run the pre-flight",
            )
        )
        skipped.append(name)

    az_cli = record(check_azure_cli(runner=active))
    if az_cli.status == OK:
        login = record(check_azure_signed_in(runner=active))
        facts.update(login.details)
    else:
        login = None
        skip(CHECK_AZ_LOGIN, CHECK_AZ_CLI)

    if login is not None and login.status == OK:
        record(check_admin_roles(runner=active))
    else:
        skip(CHECK_ADMIN_ROLES, CHECK_AZ_LOGIN)

    if include_exchange:
        pwsh = record(check_powershell(runner=active))
        if pwsh.status == OK:
            record(check_exchange_module(runner=active))
        else:
            skip(CHECK_EXO_MODULE, CHECK_PWSH)

    if az_cli.status == OK and login is not None and login.status == OK:
        record(check_sender_mailbox(sender, runner=active))
    else:
        skip(CHECK_SENDER, CHECK_AZ_CLI if az_cli.status != OK else CHECK_AZ_LOGIN)

    return PreflightReport(
        sender=(sender or "").strip(),
        checks=tuple(checks),
        skipped=tuple(skipped),
        tenant_id=facts.get("tenantId") or None,
        tenant_name=facts.get("tenantName") or None,
        signed_in_upn=facts.get("upn") or None,
    )


def plan_installs(report: PreflightReport) -> list[str]:
    """Homebrew formula names that would fix this report, in check order.

    ``--install-missing`` support (B5 calls this, shows the list, prompts y/N, and
    runs brew itself). Only genuinely brew-installable failures appear: the
    Exchange Online **module** comes from the PowerShell Gallery, so it has no brew
    formula and is reported through its ``fix_hint`` instead — listing it here
    would make B5 hand ``brew`` a name brew does not know. Duplicates collapse;
    a report with nothing installable to install returns ``[]`` (B5 then skips the
    prompt entirely instead of asking "install nothing?").

    Assumes brew itself is present; that is B5's precondition to offer the flag.
    """
    formulas: list[str] = []
    for check in report.checks:
        if check.status != FAIL or not check.install_hint:
            continue
        if check.install_hint not in formulas:
            formulas.append(check.install_hint)
    return formulas


# --- Internals -------------------------------------------------------------
def _tenant_display_name(runner: CommandRunner, tenant_id: str) -> str:
    """Directory display name for ``tenant_id``, or ``''`` when unavailable.

    A missing name is cosmetic and must not fail the check, so every failure path
    here degrades to the empty string.
    """
    try:
        tenants = run_json(["az", "account", "tenant", "list"], runner=runner)
    except CommandError:
        return ""
    entries = tenants if isinstance(tenants, list) else [tenants]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if tenant_id and _text(entry.get("tenantId")) != tenant_id:
            continue
        name = _text(entry.get("displayName"))
        if name:
            return name
    return ""


def _member_of_display_names(runner: CommandRunner) -> tuple[list[str], bool]:
    """``(display names, hit the page cap)`` from Graph's memberOf collection.

    Any key that case-insensitively reads ``displayName`` is accepted, because
    ``az rest`` has passed this collection back with both spellings over time; a
    page with neither yields no names and is not treated as an error.
    """
    names: list[str] = []
    uri: str | None = GRAPH_MEMBER_OF_URI
    pages = 0
    while uri and pages < MAX_MEMBER_OF_PAGES:
        payload = run_json(["az", "rest", "--method", "GET", "--uri", uri], runner=runner)
        pages += 1
        if isinstance(payload, list):
            entries: Sequence[Any] = payload
            uri = None
        elif isinstance(payload, dict):
            value = payload.get("value")
            entries = value if isinstance(value, list) else []
            link = payload.get("@odata.nextLink") or payload.get("odata.nextLink")
            uri = link if isinstance(link, str) and link else None
        else:
            raise CommandError("`az rest` for memberOf did not print a collection")
        for entry in entries:
            if isinstance(entry, dict):
                name = _display_name(entry)
                if name:
                    names.append(name)
    return names, bool(uri)


def _display_name(entry: dict[str, Any]) -> str:
    for key, value in entry.items():
        if str(key).casefold() == "displayname" and isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _listed(names: Sequence[str]) -> str:
    """Comma-join, capped, with an explicit marker when something was dropped."""
    items = list(names)
    if not items:
        return ""
    if len(items) <= MAX_LISTED_GROUPS:
        return ", ".join(items)
    return ", ".join(items[:MAX_LISTED_GROUPS]) + f", (+{len(items) - MAX_LISTED_GROUPS} more)"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _nested_text(value: Any, key: str) -> str:
    return _text(value.get(key)) if isinstance(value, dict) else ""


__all__ = [
    "CHECK_ADMIN_ROLES",
    "CHECK_AZ_CLI",
    "CHECK_AZ_LOGIN",
    "CHECK_EXO_MODULE",
    "CHECK_ORDER",
    "CHECK_PWSH",
    "CHECK_SENDER",
    "EXO_MODULE",
    "EXCH_ROLE_GROUP_HINT",
    "FAIL",
    "GLOBAL_ADMIN_ROLE",
    "APP_ADMIN_ROLE",
    "EXCHANGE_ADMIN_ROLE",
    "GRAPH_MEMBER_OF_URI",
    "INSTALL_AZ_HINT",
    "INSTALL_EXO_HINT",
    "INSTALL_PWSH_HINT",
    "LOGIN_HINT",
    "MAX_LISTED_GROUPS",
    "MAX_MEMBER_OF_PAGES",
    "NOT_EVALUATED",
    "OK",
    "PreflightError",
    "PreflightReport",
    "ROLES_HINT",
    "SENDER_HINT",
    "WARN",
    "CheckResult",
    "check_admin_roles",
    "check_azure_cli",
    "check_azure_signed_in",
    "check_exchange_module",
    "check_powershell",
    "check_sender_mailbox",
    "plan_installs",
    "run_preflight",
]
