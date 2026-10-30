"""Idempotent Entra ID app registration + service principal (design §6 step 1).

This is the code behind the first write step of ``mnotify admin bootstrap``: the
app registration that ``docs/ADMIN-SETUP.md`` §step 1 currently tells an operator
to click through in the portal. The whole point of doing it here instead of in the
portal is that a re-run must be a no-op — the bootstrap will be run more than once
(a typo mid-flow, a second Mac, a CI image) and a second app registration named
``micro-notify`` would be a silent, expensive mistake: the certificate (B3) and the
Exchange scoped role (B4) both attach to *one* object id, and attaching them to the
wrong one produces an app that authenticates and then cannot send.

Find-first, never second
------------------------

Every step asks before it creates, and the asking is a read-only ``az`` list:

``az ad app list --display-name micro-notify``
    reused only when an entry's ``displayName`` equals the requested name **exactly**.
    ``az``'s own filter is an OData ``eq``, but the tenant is the operator's and a
    near-miss such as ``micro-notify-staging`` must never be adopted — so the exact
    comparison is repeated here rather than trusted to the server.
``az ad sp list --filter "appId eq '<appId>'"``
    same rule, applied to ``appId``.

Only when nothing matches does anything get created::

    az ad app create --display-name ...  ->  az ad sp create --id <appId>

(The ``sp create`` object id is the *enterprise application* object id that
ADMIN-SETUP §step 2 hands to ``New-ServicePrincipal`` — B4 needs it, so it is
returned as ``sp_object_id`` rather than being re-looked-up later.)

Never any permissions, ever
---------------------------

This module creates two objects and stops. It does not touch API permissions,
``appRoles``, ``--set requiredResourceAccess...``, ``appRoleAssignedTo``,
delegated-permission grants or consent of any kind, and it never creates a password
or a credential. The design settled on the Exchange-only route (ADMIN-SETUP §step 2:
a scoped ``New-ServicePrincipal`` + ``Set-Mailbox -PermissionSendTo``), which was
proven live — the app can send as the sender, and an out-of-scope sender is refused
403. Tenant-wide Graph ``Mail.Send`` consent is deliberately **never** granted by
this package: a consent grant would widen blast radius across the whole tenant to
buy nothing. The no-consent rule is pinned by a test that inspects every argv the
module builds, so a future edit that adds a ``--set`` cannot pass silently.

Every command goes through :mod:`micro_notify.admin.runner` — no ``subprocess`` here
— so a test swaps in a fake that answers canned JSON, and ``--dry-run`` is
:class:`~micro_notify.admin.runner.DryRunRunner` rather than a branch in this file.
A dry run therefore has to supply canned stdout for the calls whose *output* is
read: the two ``list`` calls (``[]`` means "not found", so a dry run of a fresh
tenant also reaches the two ``create`` calls, which need an ``appId``/``id`` in
their canned response). An unreadable response is an error, never a guess.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .runner import CommandError, CommandRunner, run_json

# --- Vocabulary -------------------------------------------------------------
# The display name this tool looks for and creates. B4 and B5 print it; a test
# pins it, because a rename here silently breaks idempotency for existing tenants.
APP_DISPLAY_NAME = "micro-notify"

# Single-tenant, exactly as ADMIN-SETUP §step 1 ("Accounts in this organizational
# directory only"). The other az values (AzureADandPersonalMicrosoftAccount,
# PersonalMicrosoftAccount) would let personal accounts authenticate to an app that
# is supposed to be scoped to one org — never a correct default for a sender app.
SIGN_IN_AUDIENCE = "AzureADMyOrg"

# Characters an app id / object id may contain. An id is interpolated into the OData
# filter string, so a stray quote there would let a value close the literal and
# write its own filter clause. Nothing legitimate needs anything else.
_ID_SAFE_CHARS = frozenset("0123456789abcdefABCDEF-")

# How many object ids are quoted in an ambiguity message, so a tenant with a dozen
# same-named apps does not flood the terminal.
MAX_LISTED_IDS = 5

OUTCOME_CREATED = "created"
OUTCOME_EXISTS = "exists"


class EntraError(CommandError):
    """The app/SP step cannot be completed safely -> exit 2.

    Raised instead of guessing: an unreadable ``az`` answer, an object that came
    back without the field this step needs, or more than one same-named app. Each
    case has a different fix, and all of them are better reported than papered
    over — the cost of guessing wrong is a certificate and a send permission on the
    wrong application object.
    """


# --- Result shapes (declared seam for B5) -----------------------------------
@dataclass(frozen=True)
class AppOutcome:
    """The app registration step: which ``appId`` to use, and whether we made it."""

    app_id: str
    created: bool
    display_name: str = APP_DISPLAY_NAME

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "display_name": self.display_name,
            "created": self.created,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class ServicePrincipalOutcome:
    """The service principal step: the enterprise app object id, and if we made it."""

    sp_object_id: str
    created: bool

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "sp_object_id": self.sp_object_id,
            "created": self.created,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class EntraProvisioning:
    """Both steps together — what ``mnotify admin bootstrap --json`` reports.

    The three fields every admin card agreed on come first: ``app_id`` (the client
    id that goes in ``[mail] client_id``), ``sp_object_id`` (the enterprise app
    object id B4 gives to ``New-ServicePrincipal``) and ``created``. ``created`` is
    True when this run created **at least one** of the two objects, so a re-run on
    an already-configured tenant reports ``exists`` and a first run reports
    ``created``; ``app_created`` / ``sp_created`` carry the per-step truth for the
    case where the app existed and only the service principal was missing.
    """

    app_id: str
    sp_object_id: str
    created: bool
    app_created: bool = False
    sp_created: bool = False
    display_name: str = APP_DISPLAY_NAME

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    @property
    def detail(self) -> str:
        """One operator-facing line saying what this run did."""
        if self.app_created and self.sp_created:
            return f"created app registration and service principal {self.display_name}"
        if self.app_created:
            return f"created app registration {self.display_name} (service principal already existed)"
        if self.sp_created:
            return f"created service principal for the existing app {self.display_name}"
        return f"app registration and service principal for {self.display_name} already exist"

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "sp_object_id": self.sp_object_id,
            "created": self.created,
            "app_created": self.app_created,
            "sp_created": self.sp_created,
            "display_name": self.display_name,
            "outcome": self.outcome,
            "detail": self.detail,
        }


# --- Lookups (read-only) ----------------------------------------------------
def find_app_id(
    display_name: str = APP_DISPLAY_NAME, *, runner: CommandRunner | None = None
) -> str | None:
    """``appId`` of the app registered under ``display_name``, or ``None``.

    ``az ad app list --display-name`` already filters with ``displayName eq``, but
    the match is re-applied here: this decides which application object the rest of
    the bootstrap attaches a certificate and a send permission to, so it must not
    depend on a server-side filter behaving. An entry without an ``appId`` is not a
    finding — it is a response this step cannot use.
    """
    _check_display_name(display_name)
    payload = run_json(
        ["az", "ad", "app", "list", "--display-name", display_name], runner=runner
    )
    matches = [
        entry
        for entry in _as_entries(payload, "az ad app list")
        if _field(entry, "displayName") == display_name
    ]
    if not matches:
        return None
    if len(matches) > 1:
        raise EntraError(
            f"{len(matches)} apps are registered with the exact name "
            f"{display_name!r} ({_preview(_field(e, 'appId') for e in matches)}); "
            "delete or rename the stale ones so the bootstrap knows which one to use"
        )
    app_id = _field(matches[0], "appId")
    if not app_id:
        raise EntraError(
            f"the app named {display_name!r} came back without an appId; "
            "cannot continue without an application id"
        )
    return app_id


def find_service_principal_id(
    app_id: str, *, runner: CommandRunner | None = None
) -> str | None:
    """Enterprise app (service principal) object id for ``app_id``, or ``None``.

    An app registration and its service principal are separate objects, and only
    the second one can be granted an Exchange scoped role — which is why this is a
    lookup of its own and not something the caller infers from the app.
    """
    _check_app_id(app_id)
    payload = run_json(
        ["az", "ad", "sp", "list", "--filter", f"appId eq '{app_id}'"], runner=runner
    )
    matches = [
        entry
        for entry in _as_entries(payload, "az ad sp list")
        if _field(entry, "appId").casefold() == app_id.casefold()
    ]
    if not matches:
        return None
    object_ids = sorted({_field(entry, "id") for entry in matches if _field(entry, "id")})
    if not object_ids:
        raise EntraError(
            f"a service principal for {app_id} came back without an object id; "
            "cannot continue without an enterprise application id"
        )
    if len(object_ids) > 1:
        raise EntraError(
            f"{len(object_ids)} service principals claim appId {app_id} "
            f"({_preview(object_ids)}); one application must have one service principal"
        )
    return object_ids[0]


# --- Creates ----------------------------------------------------------------
def create_app(
    display_name: str = APP_DISPLAY_NAME, *, runner: CommandRunner | None = None
) -> str:
    """``az ad app create`` for ``display_name`` -> its ``appId``.

    Single-tenant on purpose (``SIGN_IN_AUDIENCE``). Nothing else is passed: no
    ``--set``, no requiredResourceAccess, no appRoles, no password — see the module
    docstring for why permissions are out of scope for this package.
    """
    _check_display_name(display_name)
    payload = run_json(
        [
            "az",
            "ad",
            "app",
            "create",
            "--display-name",
            display_name,
            "--sign-in-audience",
            SIGN_IN_AUDIENCE,
        ],
        runner=runner,
    )
    entry = _single(payload, "az ad app create")
    app_id = _field(entry, "appId")
    if not app_id:
        raise EntraError(
            f"`az ad app create` for {display_name!r} did not report an appId"
        )
    return app_id


def create_service_principal(
    app_id: str, *, runner: CommandRunner | None = None
) -> str:
    """``az ad sp create --id <appId>`` -> the enterprise app object id."""
    _check_app_id(app_id)
    payload = run_json(["az", "ad", "sp", "create", "--id", app_id], runner=runner)
    entry = _single(payload, "az ad sp create")
    sp_object_id = _field(entry, "id")
    if not sp_object_id:
        raise EntraError(
            f"`az ad sp create` for {app_id} did not report an object id; "
            "B4 needs the enterprise application id to grant the Exchange role"
        )
    return sp_object_id


# --- The step itself --------------------------------------------------------
def ensure_app_registration(
    display_name: str = APP_DISPLAY_NAME, *, runner: CommandRunner | None = None
) -> AppOutcome:
    """Reuse the app named ``display_name`` if there is one, else create it."""
    existing = find_app_id(display_name, runner=runner)
    if existing is not None:
        return AppOutcome(app_id=existing, created=False, display_name=display_name)
    return AppOutcome(
        app_id=create_app(display_name, runner=runner), created=True, display_name=display_name
    )


def ensure_service_principal(
    app_id: str, *, runner: CommandRunner | None = None
) -> ServicePrincipalOutcome:
    """Reuse the service principal for ``app_id`` if there is one, else create it."""
    existing = find_service_principal_id(app_id, runner=runner)
    if existing is not None:
        return ServicePrincipalOutcome(sp_object_id=existing, created=False)
    return ServicePrincipalOutcome(
        sp_object_id=create_service_principal(app_id, runner=runner), created=True
    )


def ensure_entra_app(
    display_name: str = APP_DISPLAY_NAME, *, runner: CommandRunner | None = None
) -> EntraProvisioning:
    """The whole step, idempotent: app registration + service principal.

    Each step looks up before it creates, so a tenant that is already set up issues
    two reads and no writes at all. And the service principal is looked up by the
    *resolved* ``appId`` — never a name — so the SP of an app that shares a display
    name with a stale registration is still found by the only key that is unique.

    Re-running against a configured tenant returns the same ids with
    ``created=False``, which is what lets B5 print "exists" and exit 0.
    """
    app = ensure_app_registration(display_name, runner=runner)
    sp = ensure_service_principal(app.app_id, runner=runner)
    return EntraProvisioning(
        app_id=app.app_id,
        sp_object_id=sp.sp_object_id,
        created=app.created or sp.created,
        app_created=app.created,
        sp_created=sp.created,
        display_name=app.display_name,
    )


# --- Reading az's answers ---------------------------------------------------
def _as_entries(payload: Any, label: str) -> list[Mapping[str, Any]]:
    """A ``list`` command's payload as a list of objects.

    ``az`` answers a list command with a JSON array, and an empty array is the
    normal "not found" answer. A bare object (older az, or a one-element response)
    is accepted as a one-item list; anything else means the response is not
    something this step can read, and guessing would decide an application id.
    """
    if payload is None:
        return []
    if isinstance(payload, Mapping):
        return [payload]
    if isinstance(payload, list):
        entries: list[Mapping[str, Any]] = []
        for item in payload:
            if isinstance(item, Mapping):
                entries.append(item)
        return entries
    raise EntraError(f"`{label}` did not print a list of objects")


def _single(payload: Any, label: str) -> Mapping[str, Any]:
    """A ``create`` command's payload as one object."""
    if isinstance(payload, Mapping):
        return payload
    entries = _as_entries(payload, label)
    if len(entries) == 1:
        return entries[0]
    raise EntraError(f"`{label}` did not print a single object")


def _field(entry: Mapping[str, Any], key: str) -> str:
    """``entry[key]`` as a stripped string, or ``''`` when absent/not a string."""
    value: Any = entry.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def _preview(values: Iterable[str]) -> str:
    """First few values, comma-joined — enough to point at the problem object."""
    shown = [v or "<missing>" for v in values][:MAX_LISTED_IDS]
    return ", ".join(shown) if shown else "<none>"


# --- Argument guards --------------------------------------------------------
def _check_display_name(display_name: str) -> None:
    """Reject a display name that cannot safely be a name.

    Two real risks, not hygiene: a name starting with ``-`` would be read by ``az``
    as an option instead of a value, and a name padded with whitespace would never
    equal itself in the exact-match comparison above, so the step would create a
    second app on every run.
    """
    if not isinstance(display_name, str) or not display_name:
        raise EntraError("the app display name must not be empty")
    if display_name != display_name.strip():
        raise EntraError(
            f"the app display name {display_name!r} has leading or trailing "
            "whitespace, which would never match the registered name"
        )
    if display_name.startswith("-"):
        raise EntraError(
            f"the app display name {display_name!r} starts with '-', which az "
            "would read as an option"
        )


def _check_app_id(app_id: str) -> None:
    """Reject an app id that must not be interpolated into an OData filter.

    The filter is a quoted literal inside a string argument; a quote or a space in
    the value would close that literal and let the value write its own filter
    clause. A non-GUID-shaped value is also almost certainly a UPN or a name
    passed to the wrong parameter, and `az` would answer an empty list — i.e. "not
    found" — and the step would create a duplicate application.
    """
    if not isinstance(app_id, str) or not app_id:
        raise EntraError("the application id must not be empty")
    if app_id != app_id.strip():
        raise EntraError(f"the application id {app_id!r} has leading or trailing whitespace")
    if any(ch not in _ID_SAFE_CHARS for ch in app_id):
        raise EntraError(
            "the application id must be a GUID (hex digits and dashes); got "
            "something else, which is not safe to put in an az --filter"
        )


__all__ = [
    "APP_DISPLAY_NAME",
    "OUTCOME_CREATED",
    "OUTCOME_EXISTS",
    "SIGN_IN_AUDIENCE",
    "AppOutcome",
    "EntraError",
    "EntraProvisioning",
    "ServicePrincipalOutcome",
    "create_app",
    "create_service_principal",
    "ensure_app_registration",
    "ensure_entra_app",
    "ensure_service_principal",
    "find_app_id",
    "find_service_principal_id",
]
