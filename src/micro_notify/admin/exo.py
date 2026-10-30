"""Idempotent Exchange Online scoping for the sender mailbox (design §6 step 2).

This is the code behind the Exchange half of ``mnotify admin bootstrap``: the
``Connect-ExchangeOnline`` session and the three ``New-*`` cmdlets that
``docs/ADMIN-SETUP.md`` §step 2 currently tells an operator to run by hand. It is
the control that satisfies the design §2 anti-goal "the app registration can send
as ANY mailbox in the tenant" — Entra's ``Mail.Send`` is tenant-wide by
construction, and Exchange Online **RBAC for Applications** is what narrows it to
one address.

One script, one session
----------------------

Rather than shelling out per cmdlet (three sessions, three device-code sign-ins,
and no way to keep a session alive between calls), this module generates **one**
PowerShell script, writes it to a private temp file and runs it once::

    pwsh -NoProfile -NonInteractive -File <temp script>

The script is generated, not templated from disk, so the ids and mailbox handles
it carries are the ones this run resolved — and so the whole thing can be printed
by ``--dry-run`` (:func:`plan_commands`) without a file ever being written.

The generated script contains **identifiers and handles only**: an app id, an
object id, two mailbox addresses and a scope name. No secret, no token, no URL,
no certificate material — a test pins that the string ``http`` never appears in
it. It is written with :func:`os.open` at mode ``0o600`` under ``O_EXCL`` and
removed in a ``finally``, so a crash or a Ctrl-C cannot leave it behind.

Device-code sign-in, surfaced live
----------------------------------

``Connect-ExchangeOnline -Device`` prints a URL plus a one-time code and then
**waits for a human to use a browser**. A runner that captures output until the
process exits would either swallow that line or sit on it for the whole timeout.
So the script merges every PowerShell stream into one flushing writer
(``*>&1`` + ``[Console]::Out.Flush()``) and the Python side hands the runner an
``on_line`` callback that is fed each line as it arrives.

That streaming is a *capability*, not a requirement of
:class:`~micro_notify.admin.runner.CommandRunner`: :func:`run_pwsh` uses
``run_streaming`` when the installed runner has it, and otherwise falls back to
``run()`` and feeds the captured output through the same sink afterwards. Either
way the device-code line reaches the caller's sink — it is never swallowed. The
real streaming runner belongs to :mod:`micro_notify.admin.runner`, not to this
module: this file never imports ``subprocess``.

Get before New, everywhere
--------------------------

Every object is looked up before it is created, and the lookup is an enumeration
with the match re-applied **locally** (same rule as
:mod:`micro_notify.admin.entra`): ``Get-ServicePrincipal``,
``Get-ManagementScope`` and ``Get-ManagementRoleAssignment`` are called without a
server-side filter and the comparison happens in the script. A ``Get`` that
*throws* is a failure, never a "not found" — reading an unreadable answer as
"absent" is exactly how a duplicate scope or a second role assignment gets made.

Two deviations from ``ADMIN-SETUP.md`` §2, both proven live and both recorded
here rather than silently adopted:

* ``New-ManagementRoleAssignment -App`` is given the **enterprise application
  object id**, not the client id. The doc lists the client id first and mentions
  the object id as a retry; the object id is what worked in the live tenant.
* ``Test-ServicePrincipalAuthorization -Identity`` takes the same object id.

Proof, not hope
---------------

The script finishes with two ``Test-ServicePrincipalAuthorization`` calls and the
Python side *parses* them; the bootstrap fails unless both come out as designed::

    -Resource <sender>            -> InScope True   (the grant works)
    -Resource <signed-in admin>   -> InScope False  (and it is really scoped)

The negative control is what makes the positive one mean anything, and it has two
traps the parser closes rather than trusts:

* the control mailbox must **resolve to a real user mailbox**. An address that
  does not exist also answers ``InScope False``, so accepting it would "prove"
  the restriction for a tenant that has none;
* a ``True`` row whose ``AllowedResourceScope`` is not our scope (typically
  ``Organization``) is a **failure**, not a success — that is a tenant-wide grant
  wearing our scope's clothes, the exact state §2.4 warns about.

``Disconnect-ExchangeOnline`` runs in a ``finally`` so a failed run does not leak
an authenticated session.

Nothing here prompts or prints on its own: :func:`ensure_exchange_scope` takes an
``echo`` callable and the command layer (B5) decides what the operator sees.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from .runner import (
    STDERR_QUOTE_LIMIT,
    CommandError,
    CommandRunner,
    get_runner,
)

# --- Vocabulary -------------------------------------------------------------

# The Exchange application role, exactly as ADMIN-SETUP §2.3 names it. A rename
# here would create a role assignment for a role that does not exist.
MANAGEMENT_ROLE = "Application Mail.Send"

# The DisplayName New-ServicePrincipal gives the Exchange-side mirror of the Entra
# app. Deliberately the same string as the Entra app display name so an operator
# reading either portal sees one name for one thing.
SERVICE_PRINCIPAL_DISPLAY_NAME = "micro-notify"

# Prefix of every machine-readable line the script prints. Everything else in the
# stream is for the operator's eyes and is echoed verbatim.
EVENT_PREFIX = "MNOTIFY:"

# How long the whole pwsh run may take. The device-code flow needs a human to
# open a browser and type a code, which the 60 s a pre-flight probe gets does not
# cover. Only a streaming runner is handed this value; the capturing
# SubprocessRunner keeps its own cap and cannot carry a device-code sign-in.
PWSH_TIMEOUT = 600.0

# The sign-in prompt Connect-ExchangeOnline -Device prints. Only its *presence*
# is recorded — the code itself is ephemeral and never stored or re-printed.
DEVICE_CODE_RE = re.compile(
    r"(?:enter the code|device code|to sign in, use a web browser)", re.IGNORECASE
)

# A mailbox address: local part, one @, dotted host with an alphabetic TLD. This
# character set has no quote, no dollar, no backtick, no space, no semicolon and
# no newline, which is what lets the script put the value in a single-quoted
# PowerShell literal without further escaping.
_ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")

# Characters an app id / object id may contain (same rule as admin/entra.py).
_ID_SAFE_CHARS = frozenset("0123456789abcdefABCDEF-")

# Chars a management scope name may contain. Exchange also dislikes a name that
# starts with a reserved word, which is why every name this tool makes starts with
# the tool's own prefix.
_SCOPE_NAME_PREFIX = "mnotify-"
_SCOPE_SAFE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
)
SCOPE_NAME_MAX = 64

OUTCOME_CREATED = "created"
OUTCOME_EXISTS = "exists"

# What the two Test-ServicePrincipalAuthorization calls are for.
CONTROL_SENDER = "sender"
CONTROL_ADMIN = "admin"


class ExchangeError(CommandError):
    """The Exchange scoping cannot be completed or cannot be proven -> exit 2.

    Raised instead of guessing: a value that cannot safely reach PowerShell, a
    pwsh run that did not report, or — the important one — a verification that did
    not come out as designed. ``result`` carries the structured outcome when the
    run produced one, so the command layer can still show which objects it made
    before the proof failed; a bootstrap that cannot prove the scope must not go
    on to write a config file.
    """

    def __init__(self, message: str, result: "ExchangeProvisioning | None" = None) -> None:
        super().__init__(message)
        self.result = result


# --- Seams ------------------------------------------------------------------


class StreamingCommandRunner(CommandRunner, Protocol):
    """A :class:`~micro_notify.admin.runner.CommandRunner` that can also stream.

    Optional: :func:`run_pwsh` calls ``run_streaming`` only when the installed
    runner has it. ``on_line`` receives each stdout/stderr line as it arrives, so
    a device-code prompt can reach the operator while pwsh is still waiting. The
    return value is read the same way as ``run()``'s (``returncode``, ``stdout``,
    ``stderr``).

    Declared here rather than in ``admin/runner.py`` because B4 may not edit that
    file. Adding the same optional method to ``SubprocessRunner`` is the smallest
    upstream change that would make this a plain runner capability.
    """

    def run_streaming(
        self,
        argv: Sequence[str],
        *,
        on_line: Callable[[str], None],
        stdin: str | None = None,
        timeout: float | None = None,
    ) -> Any: ...


# --- Argument guards --------------------------------------------------------


def _check_id(value: str, label: str) -> str:
    """Reject an id that must not reach a PowerShell literal or an OData filter."""
    if not isinstance(value, str) or not value:
        raise ExchangeError(f"the {label} must not be empty")
    if value != value.strip():
        raise ExchangeError(f"the {label} {value!r} has leading or trailing whitespace")
    if any(ch not in _ID_SAFE_CHARS for ch in value):
        raise ExchangeError(
            f"the {label} must be a GUID (hex digits and dashes); got something "
            "else, which is not safe to put in the PowerShell script"
        )
    return value


def _check_address(value: str, label: str) -> str:
    """Reject anything that is not plainly a mailbox address.

    This is the injection boundary: the address is interpolated into a
    ``-RecipientRestrictionFilter`` string inside the generated script, so the
    accepted character set carries no quote, dollar, backtick or newline. A
    display name, a UPN with a space or an address with a directory suffix would
    either break the filter or make it match something other than one mailbox.
    """
    if not isinstance(value, str) or not value:
        raise ExchangeError(f"the {label} must not be empty")
    if value != value.strip():
        raise ExchangeError(f"the {label} {value!r} has leading or trailing whitespace")
    if not _ADDRESS_RE.match(value):
        raise ExchangeError(
            f"the {label} {value!r} is not a plain mailbox address (a local part, "
            "an @, then a dotted host); refusing to put it in the script"
        )
    return value


def scope_name_for(sender: str) -> str:
    """``mnotify-<local part of sender>``, sanitised and length-bounded.

    Deterministic on purpose: the scope name is the idempotency key for the role
    assignment, so ``Noreply@Example.com`` and ``noreply@example.com`` must land
    on one scope and a re-run must find it. Anything the local part carries that
    a scope name may not hold becomes a dash, and the result is capped — an
    over-long name would be rejected by Exchange after the sign-in, which is the
    worst place to discover a naming problem.
    """
    address = _check_address(sender, "sender mailbox address")
    local = address.split("@", 1)[0].lower()
    cleaned = "".join(ch if ch in _SCOPE_SAFE_CHARS else "-" for ch in local)
    cleaned = cleaned.strip("-.")
    if not cleaned:
        raise ExchangeError(
            f"the sender address {sender!r} has no usable local part, so a "
            "management scope name cannot be derived from it"
        )
    budget = max(1, SCOPE_NAME_MAX - len(_SCOPE_NAME_PREFIX))
    return _SCOPE_NAME_PREFIX + cleaned[:budget].strip("-.")


# --- Script generation ------------------------------------------------------


def _ps(value: str) -> str:
    """``value`` as a single-quoted PowerShell literal.

    Single quotes do not interpolate, and doubling an embedded quote closes the
    literal honestly. Together with the guards above this is belt and braces: a
    value that reached here with a quote in it could not have come through
    :func:`_check_address` or :func:`_check_id`, but the escaping is written so it
    does not depend on that.
    """
    if any(ord(ch) < 0x20 for ch in value):
        raise ExchangeError("a value for the script contains a control character")
    return "'" + value.replace("'", "''") + "'"


@dataclass(frozen=True)
class ExchangeScript:
    """The generated script plus everything needed to run or print it.

    ``text`` is what gets written to the temp file and what ``--dry-run`` prints.
    ``argv`` needs the path the caller chose, so it is a method rather than a
    field: a dry run has no path and must not invent one that looks real.
    """

    text: str
    app_id: str
    sp_object_id: str
    sender: str
    admin_mailbox: str
    scope_name: str
    role: str = MANAGEMENT_ROLE

    def argv(self, path: str) -> list[str]:
        """The real argv for one run of this script.

        ``-NonInteractive`` is deliberate and deviates from the bare
        ``pwsh -NoProfile -File`` shape: with it, a cmdlet that decides to prompt
        on stdin fails immediately instead of holding the session open until the
        timeout. The device-code flow is out-of-band (browser + code), so it needs
        no stdin at all — which is also why no secret can be smuggled in that way.
        """
        return ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(path)]

    def argv_plan(self) -> list[str]:
        """The argv with the script path shown as a marker, for ``--dry-run``."""
        return self.argv("<generated-script-path>")

    def argv_line(self) -> str:
        """The planned argv as one printable line (what B5 prints first)."""
        return " ".join(self.argv_plan())

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "sp_object_id": self.sp_object_id,
            "sender": self.sender,
            "admin_mailbox": self.admin_mailbox,
            "scope_name": self.scope_name,
            "role": self.role,
            "argv": self.argv_plan(),
            "script_lines": len(self.text.splitlines()),
        }


def build_script(
    app_id: str,
    sp_object_id: str,
    sender: str,
    *,
    admin_mailbox: str = "",
    scope_name: str | None = None,
) -> ExchangeScript:
    """Generate the whole PowerShell script. Pure: writes nothing, runs nothing.

    ``admin_mailbox`` is the signed-in administrator's own mailbox, used as the
    **negative control** (it must come back ``InScope False``). B5 passes
    ``PreflightReport.signed_in_upn``. An empty value is allowed here so a dry run
    can print a plan before the pre-flight has run, but the script refuses to
    claim the scope is proven without it, and :func:`ensure_exchange_scope` will
    not accept the result.
    """
    checked_app = _check_id(app_id, "application id")
    checked_sp = _check_id(sp_object_id, "enterprise application object id")
    checked_sender = _check_address(sender, "sender mailbox address")
    checked_admin = (
        _check_address(admin_mailbox, "signed-in admin mailbox") if admin_mailbox else ""
    )
    scope = scope_name_for(checked_sender) if scope_name is None else _check_scope_name(scope_name)

    lines: list[str] = [
        "# micro-notify Exchange Online bootstrap (generated by `mnotify admin bootstrap`).",
        "# Identifiers and mailbox handles only: no secret, no token, no URL, no key material.",
        "# Read this before editing the generator: every Get below is an enumeration with the",
        "# match applied locally, and a Get that throws is a failure - never a 'not found'.",
        "$ErrorActionPreference = 'Stop'",
        "$InformationPreference  = 'Continue'",
        "$ProgressPreference     = 'SilentlyContinue'",
        "$ConfirmPreference      = 'None'",
        "",
        f"$MnotifyAppId      = {_ps(checked_app)}",
        f"$MnotifySpObjectId = {_ps(checked_sp)}",
        f"$MnotifySender     = {_ps(checked_sender)}",
        f"$MnotifyAdmin      = {_ps(checked_admin)}",
        f"$MnotifyScope      = {_ps(scope)}",
        f"$MnotifyRole       = {_ps(MANAGEMENT_ROLE)}",
        "",
        "function Write-MnotifyLine {",
        "    param([string]$Text)",
        "    [Console]::Out.WriteLine($Text)",
        "    [Console]::Out.Flush()",
        "}",
        "function Write-MnotifyEvent {",
        "    param([hashtable]$Payload)",
        "    Write-MnotifyLine ($script:MnotifyPrefix + ($Payload | ConvertTo-Json -Compress -Depth 6))",
        "}",
        "function Stop-Mnotify {",
        "    param([string]$Step, [string]$Reason)",
        "    Write-MnotifyEvent @{ event = 'failure'; step = $Step; reason = $Reason }",
        "    throw \"mnotify: $Step\"",
        "}",
        "$script:MnotifyPrefix = 'MNOTIFY:'",
        "$MnotifyConnected = $false",
        "$MnotifyOk = $true",
        "",
        "try {",
        "    # --- 0. connect: the device-code prompt must reach the terminal now, not later.",
        "    Write-MnotifyLine 'mnotify: connecting to Exchange Online (device-code sign-in).'",
        "    Write-MnotifyLine 'mnotify: open the page and enter the code below when prompted.'",
        "    $MnotifyErrBefore = $Error.Count",
        "    Connect-ExchangeOnline -Device -ShowBanner:$false *>&1 | ForEach-Object { Write-MnotifyLine \"$_\" }",
        "    if ($Error.Count -gt $MnotifyErrBefore -or -not (Get-ConnectionInformation)) {",
        "        Write-MnotifyEvent @{ event = 'failure'; step = 'connect'; reason = 'Connect-ExchangeOnline -Device did not establish a session' }",
        "        $MnotifyOk = $false",
        "        throw 'mnotify: connect'",
        "    }",
        "    $MnotifyConnected = $true",
        "    Write-MnotifyEvent @{ event = 'connected' }",
        "",
        "    # --- 1. Get-before-New: the Exchange-side service principal object.",
        "    $MnotifySp = @(Get-ServicePrincipal | Where-Object { \"$($_.AppId)\" -eq $MnotifyAppId })",
        "    if ($MnotifySp.Count -gt 0) {",
        "        Write-MnotifyEvent @{ event = 'service_principal'; outcome = 'exists'; found = $MnotifySp.Count }",
        "    } else {",
        "        $null = New-ServicePrincipal -AppId $MnotifyAppId -ObjectId $MnotifySpObjectId -DisplayName 'micro-notify'",
        "        Write-MnotifyEvent @{ event = 'service_principal'; outcome = 'created' }",
        "    }",
        "",
        "    # --- 2. Get-before-New: a scope that matches exactly the one sender mailbox.",
        "    $MnotifyScopes = @(Get-ManagementScope | Where-Object { \"$($_.Name)\" -eq $MnotifyScope })",
        "    if ($MnotifyScopes.Count -gt 0) {",
        "        Write-MnotifyEvent @{ event = 'management_scope'; outcome = 'exists'; found = $MnotifyScopes.Count }",
        "    } else {",
        "        $MnotifyFilter = \"PrimarySmtpAddress -eq '$MnotifySender'\"",
        "        $null = New-ManagementScope -Name $MnotifyScope -RecipientRestrictionFilter $MnotifyFilter",
        "        Write-MnotifyEvent @{ event = 'management_scope'; outcome = 'created' }",
        "    }",
        "",
        "    # --- 3. Get-before-New: the application role, inside that scope and only that scope.",
        "    # -App takes the ENTERPRISE APPLICATION OBJECT ID: the client id is what the doc",
        "    # lists first, but the object id is what the live tenant accepted.",
        "    $MnotifyAssignments = @(Get-ManagementRoleAssignment -Role $MnotifyRole | Where-Object {",
        "        $($_.RoleAssigneeName) -eq $MnotifySpObjectId -or",
        "        $($_.RoleAssigneeName) -eq $MnotifyAppId -or",
        "        $($_.RoleAssigneeObjectId) -eq $MnotifySpObjectId -or",
        "        \"$($_.CustomResourceScopeName)\" -eq $MnotifyScope -and (",
        "            $($_.RoleAssigneeName) -eq $MnotifySpObjectId -or $($_.RoleAssigneeObjectId) -eq $MnotifySpObjectId)",
        "    })",
        "    if ($MnotifyAssignments.Count -gt 0) {",
        "        Write-MnotifyEvent @{ event = 'role_assignment'; outcome = 'exists'; found = $MnotifyAssignments.Count }",
        "    } else {",
        "        $null = New-ManagementRoleAssignment -App $MnotifySpObjectId -Role $MnotifyRole -CustomResourceScope $MnotifyScope",
        "        Write-MnotifyEvent @{ event = 'role_assignment'; outcome = 'created' }",
        "    }",
        "",
        "    # --- 4. prove it. The positive case alone would also be true of a tenant-wide",
        "    #      grant, so the negative control is what makes the first one mean anything.",
        "    function Get-MnotifyAuthzRows {",
        "        param([string]$Resource)",
        "        @(Test-ServicePrincipalAuthorization -Identity $MnotifySpObjectId -Resource $Resource -ErrorAction Stop |",
        "            ForEach-Object {",
        "                [pscustomobject]@{",
        "                    RoleName = \"$($_.RoleName)\"",
        "                    Scope    = \"$($_.AllowedResourceScope)\"",
        "                    ScopeType = \"$($_.ScopeType)\"",
        "                    InScope  = \"$($_.InScope)\"",
        "                }",
        "            })",
        "    }",
        "    $MnotifySenderRows = Get-MnotifyAuthzRows -Resource $MnotifySender",
        "    Write-MnotifyEvent @{ event = 'authz'; control = 'sender'; resource = $MnotifySender; rows = $MnotifySenderRows }",
        "",
        "    if ([string]::IsNullOrWhiteSpace($MnotifyAdmin)) {",
        "        Stop-Mnotify 'negative_control' 'the signed-in admin mailbox was not supplied, so the scope restriction cannot be proven'",
        "    }",
        "    $MnotifyAdminMb = @(Get-Mailbox -Identity $MnotifyAdmin -RecipientTypeDetails UserMailbox -ErrorAction SilentlyContinue)",
        "    if ($MnotifyAdminMb.Count -eq 0) {",
        "        Stop-Mnotify 'negative_control' \"$MnotifyAdmin is not a user mailbox in this tenant; an address that does not resolve also answers InScope False, which proves nothing\"",
        "    }",
        "    $MnotifyAdminAddress = \"$($MnotifyAdminMb[0].PrimarySmtpAddress)\"",
        "    if ($MnotifyAdminAddress -ieq $MnotifySender) {",
        "        Stop-Mnotify 'negative_control' 'the control mailbox is the sender itself; choose a different mailbox for the negative test'",
        "    }",
        "    $MnotifyAdminRows = Get-MnotifyAuthzRows -Resource $MnotifyAdminAddress",
        "    Write-MnotifyEvent @{ event = 'authz'; control = 'admin'; resource = $MnotifyAdminAddress; rows = $MnotifyAdminRows }",
        "",
        "    Write-MnotifyEvent @{ event = 'summary'; ok = $MnotifyOk }",
        "} catch {",
        "    $MnotifyOk = $false",
        "    Write-MnotifyEvent @{ event = 'error'; reason = \"$($_.Exception.Message)\" }",
        "} finally {",
        "    # Always release the session: a failed run must not leave an authenticated",
        "    # Exchange Online session sitting on the tenant.",
        "    if ($MnotifyConnected) {",
        "        try {",
        "            Disconnect-ExchangeOnline -Confirm:$false | Out-Null",
        "            Write-MnotifyEvent @{ event = 'disconnected' }",
        "        } catch {",
        "            Write-MnotifyLine \"mnotify: Disconnect-ExchangeOnline failed: $($_.Exception.Message)\"",
        "        }",
        "    }",
        "}",
        "if ($MnotifyOk) { exit 0 } else { exit 1 }",
        "",
    ]
    text = "\n".join(lines)
    if "http" in text.lower():
        # Cannot happen with the guards above; kept so a future value that smuggles
        # a URL through a name is refused at generation time, not on the operator's
        # screen. A URL in this file would mean a token-shaped string in the script.
        raise ExchangeError("the generated script must not contain a URL")

    return ExchangeScript(
        text=text,
        app_id=checked_app,
        sp_object_id=checked_sp,
        sender=checked_sender,
        admin_mailbox=checked_admin,
        scope_name=scope,
    )


def plan_commands(
    app_id: str,
    sp_object_id: str,
    sender: str,
    *,
    admin_mailbox: str = "",
    scope_name: str | None = None,
) -> list[str]:
    """The plan ``mnotify admin bootstrap --dry-run`` prints, as text lines.

    Line 0 is the command that would be run, with the script path shown as a
    marker rather than a path that does not exist; the rest is the script that
    would be written. Nothing is written or executed — this is the only dry-run
    surface B4 offers, and it is a pure function of its arguments, so two calls
    print identical plans.

    B5 should import it as ``from micro_notify.admin.exo import plan_commands``
    (module-qualified, like ``preflight.run_preflight``). It is deliberately *not*
    re-exported from the package root: B3's certificate step exposes a plan
    function of the same shape, and two same-named functions re-exported from one
    package would silently shadow each other depending on import order.
    """
    script = build_script(
        app_id, sp_object_id, sender, admin_mailbox=admin_mailbox, scope_name=scope_name
    )
    return [script.argv_line(), *script.text.splitlines()]


def _check_scope_name(name: str) -> str:
    """Validate a caller-supplied scope name instead of deriving one."""
    if not isinstance(name, str) or not name:
        raise ExchangeError("the management scope name must not be empty")
    if name != name.strip():
        raise ExchangeError(f"the management scope name {name!r} has leading or trailing whitespace")
    if len(name) > SCOPE_NAME_MAX:
        raise ExchangeError(
            f"the management scope name {name!r} is longer than {SCOPE_NAME_MAX} characters"
        )
    if any(ch not in _SCOPE_SAFE_CHARS for ch in name):
        raise ExchangeError(
            f"the management scope name {name!r} contains a character Exchange "
            "does not allow in a scope name"
        )
    return name


# --- Running it -------------------------------------------------------------


@dataclass
class _RunCapture:
    """Every line pwsh produced, in arrival order, plus what was echoed where."""

    lines: list[str] = field(default_factory=list)
    echoed: list[str] = field(default_factory=list)
    device_code_seen: bool = False

    def feed(self, line: str, *, echo: Callable[[str], None] | None) -> None:
        text = line.rstrip("\r\n")
        self.lines.append(text)
        if DEVICE_CODE_RE.search(text):
            self.device_code_seen = True
        if EVENT_PREFIX not in text and echo is not None:
            # The device-code prompt and any human-facing output go to the caller's
            # sink as they arrive. Machine lines are parsed, not re-printed.
            echo(text)
            self.echoed.append(text)


def run_pwsh(
    argv: Sequence[str],
    capture: _RunCapture,
    *,
    runner: CommandRunner | None = None,
    echo: Callable[[str], None] | None = None,
    timeout: float = PWSH_TIMEOUT,
) -> Any:
    """Run ``argv`` through the seam, streaming lines into ``capture`` when possible.

    A runner that offers ``run_streaming`` gets the ``on_line`` callback and the
    device-code prompt appears while pwsh waits. Anything else (including B1's
    :class:`~micro_notify.admin.runner.SubprocessRunner`) gets ``run()`` and its
    captured output is fed through the same sink afterwards — later, but never
    dropped.
    """
    active = runner or get_runner()
    streamer = getattr(active, "run_streaming", None)
    if callable(streamer):
        return streamer(
            [str(a) for a in argv],
            on_line=lambda line: capture.feed(line, echo=echo),
            timeout=timeout,
        )

    result = active.run([str(a) for a in argv])
    for line in _split(getattr(result, "stdout", None)):
        capture.feed(line, echo=echo)
    for line in _split(getattr(result, "stderr", None)):
        capture.feed(line, echo=echo)
    return result


def _split(text: str | None) -> list[str]:
    if not text:
        return []
    return text.splitlines()


def write_script_file(script: ExchangeScript) -> str:
    """Write ``script.text`` to a private temp file (mode 0600) and return its path.

    ``O_EXCL`` means a pre-existing name is never overwritten — a collision moves
    to a new name instead of clobbering someone else's file — and the mode is
    fixed at 0600 rather than inherited: the script carries a tenant's object ids
    and mailbox addresses, which is not material for other users on a shared
    machine even briefly. The caller owns removal; :func:`ensure_exchange_scope`
    does it in a ``finally``.
    """
    directory = tempfile.gettempdir()
    last_error: OSError | None = None
    for _ in range(5):
        path = os.path.join(directory, f"mnotify-exo-{uuid.uuid4().hex}.ps1")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:  # collision: try a fresh name
            last_error = exc
            continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(script.text)
            os.chmod(path, 0o600)
        except OSError:
            _remove(path)
            raise
        return path
    raise ExchangeError(
        f"cannot create a private script file in {directory}"
        + (f": {type(last_error).__name__}" if last_error else "")
    )


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        # Nothing to report to the operator: the file is either already gone or
        # not ours to remove, and the run must not fail because of it.
        pass


# --- Reading the script's answer -------------------------------------------


@dataclass(frozen=True)
class StepOutcome:
    """One of the three objects: did we make it, or was it already there?"""

    name: str
    created: bool
    found: int = 0

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "outcome": self.outcome, "found": self.found}


@dataclass(frozen=True)
class AuthzCheck:
    """One ``Test-ServicePrincipalAuthorization`` call, as parsed.

    ``in_scope`` is tri-state on purpose: ``True``/``False`` are answers and
    ``None`` is "the cmdlet said nothing usable" (``Not Run``, an empty row set,
    a row we could not read). Only ``None`` is a shrug, and a shrug is never
    accepted as either verdict — see :meth:`problem`.
    """

    control: str
    resource: str
    in_scope: bool | None
    rows: tuple[dict[str, Any], ...] = ()
    expected_in_scope: bool = True
    expected_scope: str = ""

    @property
    def passed(self) -> bool:
        return self.in_scope is self.expected_in_scope and not self.problem

    @property
    def problem(self) -> str:
        """Why this check does not prove what the bootstrap needs, or ``''``."""
        if self.in_scope is None:
            return (
                f"the authorization test for {self.resource!r} returned no usable "
                f"InScope value (rows: {self._row_summary()}); 'Not Run' or an empty "
                "answer proves nothing"
            )
        if self.in_scope is not self.expected_in_scope:
            want = "True" if self.expected_in_scope else "False"
            got = "True" if self.in_scope else "False"
            if self.control == CONTROL_ADMIN:
                return (
                    f"the app can send as {self.resource!r} (InScope {got}); the "
                    "management scope is not restricting anything and the sender "
                    "mailbox is not the only mailbox this app can use"
                )
            return (
                f"the app cannot send as {self.resource!r} (InScope {got}, expected "
                f"{want}); the role assignment for scope {self.expected_scope!r} "
                "did not take effect"
            )
        if self.expected_in_scope:
            # A True row that is not scoped to *our* scope is the tenant-wide grant
            # ADMIN-SETUP §2.4 warns about: the positive test passes, and the
            # restriction is an illusion.
            off_scope = sorted(
                {
                    str(row.get("Scope") or "").strip()
                    for row in self.rows
                    if _is_true(row.get("InScope"))
                    and str(row.get("Scope") or "").strip().casefold()
                    != self.expected_scope.casefold()
                }
            )
            if off_scope:
                return (
                    f"the app is InScope True for {self.resource!r} through scope(s) "
                    f"{', '.join(off_scope)} rather than {self.expected_scope!r}; a "
                    "grant scoped to Organization is tenant-wide, not scoped"
                )
        return ""

    def _row_summary(self) -> str:
        if not self.rows:
            return "none"
        return ", ".join(
            f"{row.get('RoleName') or '?'}@{row.get('Scope') or '?'}={row.get('InScope') or '?'}"
            for row in self.rows[:5]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "resource": self.resource,
            "expected_in_scope": self.expected_in_scope,
            "in_scope": self.in_scope,
            "passed": self.passed,
            "rows": [dict(row) for row in self.rows],
            "problem": self.problem,
        }


def _is_true(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "true"


def _as_rows(value: Any) -> list[Any]:
    """One authorization event's ``rows`` payload as a list.

    The script always sends a JSON **array** here (verified on pwsh 7.6.7: an
    ``@()`` array nested in a hashtable keeps its shape, so a single row still
    arrives as ``[{...}]``). The bare-object form is accepted too, because
    ``ConvertTo-Json`` *does* unwrap a single object that is piped rather than
    nested — a future edit that changes how the rows are collected would otherwise
    turn a working bootstrap into "no usable InScope value", which is the worst
    possible failure to debug on a live tenant. A scalar/``null`` stays "no rows":
    it is not an answer, and inventing one from a non-answer is what this guards.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return [value]
    return []


def _as_in_scope(value: Any) -> bool | None:
    """``InScope`` as True/False, or ``None`` for anything that is not an answer."""
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().casefold()
    if text == "true":
        return True
    if text == "false":
        return False
    return None  # 'Not Run', '', 'Skipped' — a non-answer, never read as False


def parse_authz_rows(
    rows: Iterable[Any],
    *,
    control: str,
    resource: str,
    expected_in_scope: bool,
    expected_scope: str = "",
) -> AuthzCheck:
    """Turn one authorization test's rows into a verdict.

    Any row with a usable ``InScope`` decides it: one ``True`` anywhere makes the
    check True (the negative control must therefore have *no* True row at all).
    Rows with no readable ``InScope`` are kept for the report but never count as
    ``False`` — that is the difference between "this mailbox is out of scope" and
    "the cmdlet was not asked", and collapsing them would let an unverified grant
    read as a working restriction.
    """
    parsed: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            parsed.append({"InScope": None, "RoleName": "?", "Scope": "?", "raw": str(row)})
            continue
        parsed.append(
            {
                "RoleName": str(row.get("RoleName") or row.get("roleName") or ""),
                "Scope": str(row.get("Scope") or row.get("AllowedResourceScope") or ""),
                "ScopeType": str(row.get("ScopeType") or ""),
                "InScope": row.get("InScope", row.get("inScope")),
            }
        )
    answers = [v for v in (_as_in_scope(r["InScope"]) for r in parsed) if v is not None]
    in_scope: bool | None = True if True in answers else (False if answers else None)
    return AuthzCheck(
        control=control,
        resource=resource,
        in_scope=in_scope,
        rows=tuple(parsed),
        expected_in_scope=expected_in_scope,
        expected_scope=expected_scope,
    )


@dataclass(frozen=True)
class ExchangeProvisioning:
    """What the Exchange step did and whether it proved it — B5's report payload.

    ``ok`` is True only when all three objects exist, the sender test came back
    ``InScope True`` through our scope, and the admin control came back ``InScope
    False``. ``created`` is True when this run made at least one object, so a
    re-run on a configured tenant reports ``exists`` for every step and exits 0.
    """

    sender: str
    scope_name: str
    app_id: str
    sp_object_id: str
    admin_mailbox: str
    service_principal: StepOutcome
    management_scope: StepOutcome
    role_assignment: StepOutcome
    sender_check: AuthzCheck
    admin_check: AuthzCheck
    connected: bool = True
    disconnected: bool = True
    device_code_surfaced: bool = False
    ok: bool = True
    failures: tuple[str, ...] = ()

    @property
    def created(self) -> bool:
        return any(
            step.created
            for step in (self.service_principal, self.management_scope, self.role_assignment)
        )

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    @property
    def steps(self) -> tuple[StepOutcome, ...]:
        return (self.service_principal, self.management_scope, self.role_assignment)

    @property
    def detail(self) -> str:
        """One operator-facing line: what this run made, and that the scope held."""
        made = [
            step.name
            for step in self.steps
            if step.created
        ]
        if made:
            what = ", ".join(made)
            return f"created {what}; scope {self.scope_name} verified for {self.sender}"
        return (
            f"already present: service principal, scope {self.scope_name} and the "
            f"{MANAGEMENT_ROLE} assignment; scope verified for {self.sender}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sender": self.sender,
            "scope_name": self.scope_name,
            "app_id": self.app_id,
            "sp_object_id": self.sp_object_id,
            "admin_mailbox": self.admin_mailbox,
            "created": self.created,
            "outcome": self.outcome,
            "detail": self.detail,
            "ok": self.ok,
            "steps": [step.to_dict() for step in self.steps],
            "checks": [self.sender_check.to_dict(), self.admin_check.to_dict()],
            "connected": self.connected,
            "disconnected": self.disconnected,
            "device_code_surfaced": self.device_code_surfaced,
            "failures": list(self.failures),
        }


def parse_pwsh_output(
    lines: Sequence[str],
    *,
    script: ExchangeScript,
    device_code_seen: bool = False,
) -> ExchangeProvisioning:
    """Build the result from the script's ``MNOTIFY:`` lines.

    Parsing is deliberately not a text search for ``True``: the two authorization
    tests print rows that look alike, so the only safe reading is per-event, keyed
    by which control it belongs to. Missing events are failures too — a script
    that died before printing the role assignment must not be read as "nothing to
    do".
    """
    events: list[dict[str, Any]] = []
    unparsed: list[str] = []
    for line in lines:
        text = line.strip()
        if not text.startswith(EVENT_PREFIX):
            continue
        try:
            payload = json.loads(text[len(EVENT_PREFIX):].strip())
        except (ValueError, TypeError):
            unparsed.append(text)
            continue
        if isinstance(payload, dict):
            events.append(payload)
        else:
            unparsed.append(text)

    by_event: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_event.setdefault(str(event.get("event") or ""), []).append(event)

    failures: list[str] = []
    for failure in by_event.get("failure", []):
        step = str(failure.get("step") or "step")
        reason = str(failure.get("reason") or "reported a failure")
        failures.append(f"{step}: {reason}")
    # The catch block reports whatever terminated the script. It is not enough on its
    # own (a caught exception still has to be confirmed by the checks below), but
    # losing it would throw away the one line that names the cmdlet that failed.
    for error in by_event.get("error", []):
        reason = " ".join(str(error.get("reason") or "the script threw an exception").split())
        if reason and not any(reason in failure for failure in failures):
            failures.append(f"the script threw: {reason}")
    if unparsed:
        failures.append(
            f"{len(unparsed)} machine-readable line(s) could not be parsed, so the "
            "run cannot be trusted"
        )

    connected = bool(by_event.get("connected"))
    disconnected = bool(by_event.get("disconnected")) or not connected
    if not connected and not failures:
        failures.append("the script never reported a connected Exchange Online session")
    if not disconnected:
        failures.append("the script exited without disconnecting Exchange Online")

    def one_step(name: str, event: str) -> StepOutcome:
        found = by_event.get(event, [])
        if not found:
            failures.append(f"no result was reported for the {name}")
            return StepOutcome(name=name, created=False, found=0)
        outcome = str(found[-1].get("outcome") or "").strip().casefold()
        count = found[-1].get("found")
        try:
            count_int = int(count) if count is not None else 0
        except (TypeError, ValueError):
            count_int = 0
        if outcome == OUTCOME_CREATED:
            return StepOutcome(name=name, created=True, found=count_int)
        if outcome == OUTCOME_EXISTS:
            return StepOutcome(name=name, created=False, found=max(count_int, 1))
        failures.append(f"the {name} step reported outcome {outcome!r}, not created or exists")
        return StepOutcome(name=name, created=False, found=0)

    service_principal = one_step("Exchange service principal", "service_principal")
    management_scope = one_step("management scope", "management_scope")
    role_assignment = one_step("role assignment", "role_assignment")

    checks: dict[str, AuthzCheck] = {}
    for event in by_event.get("authz", []):
        control = str(event.get("control") or "")
        resource = str(event.get("resource") or "")
        expected = control != CONTROL_ADMIN
        checks[control] = parse_authz_rows(
            _as_rows(event.get("rows")),
            control=control,
            resource=resource,
            expected_in_scope=expected,
            expected_scope=script.scope_name,
        )
    for control, expected, label in (
        (CONTROL_SENDER, True, "the sender mailbox"),
        (CONTROL_ADMIN, False, "the signed-in admin's own mailbox"),
    ):
        if control not in checks:
            failures.append(f"no authorization test was reported for {label}")
            checks[control] = AuthzCheck(
                control=control,
                resource=script.sender if control == CONTROL_SENDER else script.admin_mailbox,
                in_scope=None,
                expected_in_scope=expected,
                expected_scope=script.scope_name,
            )

    summary = by_event.get("summary", [])
    if not summary:
        failures.append("the script did not report a summary; it may have been interrupted")
    elif summary[-1].get("ok") is False:
        failures.append("the script reported a failed run")

    for check in checks.values():
        if check.problem:
            failures.append(check.problem)

    ok = not failures
    return ExchangeProvisioning(
        sender=script.sender,
        scope_name=script.scope_name,
        app_id=script.app_id,
        sp_object_id=script.sp_object_id,
        admin_mailbox=script.admin_mailbox,
        service_principal=service_principal,
        management_scope=management_scope,
        role_assignment=role_assignment,
        sender_check=checks[CONTROL_SENDER],
        admin_check=checks[CONTROL_ADMIN],
        connected=connected,
        disconnected=disconnected,
        device_code_surfaced=device_code_seen,
        ok=ok,
        failures=tuple(failures),
    )


# --- The step itself --------------------------------------------------------


def ensure_exchange_scope(
    app_id: str,
    sp_object_id: str,
    sender: str,
    admin_mailbox: str,
    *,
    runner: CommandRunner | None = None,
    echo: Callable[[str], None] | None = None,
    scope_name: str | None = None,
) -> ExchangeProvisioning:
    """Generate, run and verify the Exchange script. Idempotent, and fails closed.

    Order: guard the inputs, write the script to a 0600 temp file, run it once,
    parse the answer, delete the file — the deletion is in a ``finally`` so a
    crash or a Ctrl-C cannot leave it on disk.

    Raises :class:`ExchangeError` (exit 2) rather than returning a result that
    looks like success when the scope could not be proven. The exception carries
    the structured result in ``.result`` when the run produced one, so the command
    layer can report which objects it made *before* the proof failed — and must
    not go on to write a config file for an unproven grant.
    """
    checked_app = _check_id(app_id, "application id")
    checked_sp = _check_id(sp_object_id, "enterprise application object id")
    checked_sender = _check_address(sender, "sender mailbox address")
    checked_admin = _check_address(admin_mailbox, "signed-in admin mailbox")
    if checked_admin.casefold() == checked_sender.casefold():
        raise ExchangeError(
            "the sender mailbox and the signed-in admin mailbox are the same "
            f"address ({checked_sender}); the negative control needs a different "
            "mailbox to prove the scope actually restricts something"
        )

    script = build_script(
        checked_app,
        checked_sp,
        checked_sender,
        admin_mailbox=checked_admin,
        scope_name=scope_name,
    )
    path = write_script_file(script)
    capture = _RunCapture()
    try:
        result = run_pwsh(script.argv(path), capture, runner=runner, echo=echo)
    finally:
        _remove(path)

    raw_returncode = getattr(result, "returncode", None)
    # A result with no exit code is not a success: read it as a failed run.
    returncode = 1 if raw_returncode is None else int(raw_returncode)
    provisioning = parse_pwsh_output(
        capture.lines, script=script, device_code_seen=capture.device_code_seen
    )

    if returncode != 0:
        # The exit code is always part of the diagnosis: a transcript full of
        # failures and a non-zero exit say different things (the cmdlets failed,
        # *and* pwsh itself did not finish cleanly), and suppressing one to keep the
        # message short would hide how the run ended. stderr is quoted short and
        # without the command line, matching how admin/runner.py words a failed probe.
        stderr = " ".join(str(getattr(result, "stderr", "") or "").split())
        if len(stderr) > STDERR_QUOTE_LIMIT:
            stderr = stderr[:STDERR_QUOTE_LIMIT].rstrip() + "..."
        diagnosis = f"pwsh exited {returncode}" + (f" — {stderr}" if stderr else "")
        provisioning = replace(
            provisioning,
            ok=False,
            failures=(diagnosis, *provisioning.failures),
        )

    if not provisioning.ok:
        raise ExchangeError(
            "Exchange Online scoping could not be verified: "
            + "; ".join(provisioning.failures),
            result=provisioning,
        )
    return provisioning


__all__ = [
    "DEVICE_CODE_RE",
    "EVENT_PREFIX",
    "ExchangeError",
    "ExchangeProvisioning",
    "ExchangeScript",
    "MANAGEMENT_ROLE",
    "OUTCOME_CREATED",
    "OUTCOME_EXISTS",
    "PWSH_TIMEOUT",
    "SERVICE_PRINCIPAL_DISPLAY_NAME",
    "StreamingCommandRunner",
    "AuthzCheck",
    "StepOutcome",
    "build_script",
    "ensure_exchange_scope",
    "parse_authz_rows",
    "parse_pwsh_output",
    "plan_commands",
    "run_pwsh",
    "scope_name_for",
    "write_script_file",
]
