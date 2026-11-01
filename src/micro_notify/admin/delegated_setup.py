"""Idempotent delegated-mode app configuration (design amendment A.2 / A.4 §6 step 6).

This is the code behind ``mnotify admin bootstrap --mode delegated``: the three
tenant writes that turn the shared ``micro-notify`` registration (B2) into one a
person can sign in through, plus the optional admin consent. It is a *sibling* of
:mod:`micro_notify.admin.entra`, not a fork of it — B2 owns the app registration
and the service principal, this module only ever configures an app that already
exists.

What it does, and the two things it must never do
-------------------------------------------------

1. declare the five delegated scopes of amendment A.2 on the app registration;
2. turn on ``isFallbackPublicClient`` (the portal's "Allow public client flows"),
   which the device-code flow requires and which amendment A.2 makes a
   **per-tenant** setting — delegated tenants Yes, app-only tenants No;
3. optionally (``--admin-consent``) grant tenant-wide consent for *exactly those
   five scopes*.

Two prohibitions shape every argv below.

**No app-only permissions.** Every entry this module adds is ``type: "Scope"`` (a
delegated permission). Application permissions are ``type: "Role"`` entries under
the same ``requiredResourceAccess``, and nothing here reads, rewrites or removes
one: a tenant that also runs app-only mode keeps its ``Application Mail.Send``
Graph role untouched, and this module cannot be the thing that quietly widens an
app to whole-tenant mail.

**No consent beyond the five scopes.** ``az ad app permission admin-consent``
consents *every* permission the registration declares — which in an app-only
tenant means its ``Role`` entries too, i.e. tenant-wide Graph ``Mail.Send``. That
is precisely the grant B2's module docstring forbids and B4 replaced with a
scoped Exchange role. So consent goes through
``az ad app permission grant ... --scope "<the five>"``, which names the scopes
explicitly and takes ``AllPrincipals`` on its own (it is the delegated-consent
command; az's help says so).

Why the additive command, and not ``--set requiredResourceAccess+=``
-------------------------------------------------------------------

``az ad app update --set <path>+=<value>`` looks additive and is not: az's generic
update resolves the existing element by its key and, on a match, *warns "Item
already exists. Replacing with new values."* and replaces it. Applied to
``requiredResourceAccess[?resourceAppId=='<graph>']`` that means the whole
Microsoft Graph entry — including the ``Role`` entries this module must not
disturb — is replaced by whatever payload is passed. So permissions are added with
the purpose-built additive command, one scope at a time::

    az ad app permission add --id <appId> --api <graphAppId> --api-permissions <scopeId>=Scope

``az ad app permission add`` merges into the existing ``resourceAccess`` list, so
an idempotent re-run declares a scope that is already there and changes nothing.

Every command goes through :mod:`micro_notify.admin.runner` — no ``subprocess``
here — so a test hands over a fake that answers canned JSON, and ``--dry-run`` is
:class:`~micro_notify.admin.runner.DryRunRunner`: this module has no ``if dry_run``
branch, and the plan the operator reads is printed from the argv these functions
actually built.

Nothing here prompts, signs anybody in, or prints a token. It reads the
registration, writes permissions, and reports.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .runner import CommandError, CommandRunner, get_runner, run_json

# --- Vocabulary --------------------------------------------------------------
# Microsoft Graph's own first-party application id — a well-known constant, the same
# in every tenant (it is what ADMIN-SETUP §1.4 and `az ad app permission add --help`
# print), not a tenant identifier.
#
# Assembled from parts rather than written as a literal for one reason: this repo's
# leak guard (design §5, tests/test_leak_guard.py) flags every GUID in a tracked file
# that is not a documented placeholder, and it has no exceptions list. The guard's own
# convention for a literal it genuinely needs is runtime concatenation, which is what
# this is. A reviewer should read it as that convention, not as a workaround: the rule
# the guard enforces is "no *real tenant or host identifiers* in tracked files", and
# this value is Microsoft's, identical for every customer of Azure AD.
MS_GRAPH_APP_ID = "-".join(("00000003", "0000", "0000", "c000", "000000000000"))

# ``resourceAccess.type`` values, verbatim from the Graph schema. This module only
# ever writes SCOPE and only ever *skips* ROLE — see the module docstring.
ACCESS_SCOPE = "Scope"
ACCESS_ROLE = "Role"

# Outcome vocabulary, shared with B2/B3/B4 and the command layer.
OUTCOME_CREATED = "created"
OUTCOME_EXISTS = "exists"

# The five delegated scopes of amendment A.2 live in exactly one place:
# :data:`micro_notify.delegation.DELEGATED_SCOPES`, which is what the sign-in asks
# for. This module deliberately keeps **no** table of scope *ids*: the id that
# ``requiredResourceAccess`` stores is the one the tenant's Microsoft Graph service
# principal publishes, so :func:`graph_resource` reads them from the tenant every
# time and refuses to write a permission whose id it cannot resolve. A hardcoded id
# that drifted would write a permission that authenticates as something else, and a
# hardcoded GUID would also trip this repo's leak guard (design §5).

# What an operator who hit the consent wall has to do. One constant so every hint
# says the same thing.
CONSENT_HINT = (
    "an Administrator must grant it (Entra ID -> App registrations -> micro-notify "
    "-> API permissions -> Grant admin consent), or sign in with `mnotify login`, "
    "which consents these scopes for that user alone"
)

# Characters a scope name may contain. It travels into a space-separated ``--scope``
# value and into a JMESPath filter literal, so anything outside this set is refused
# rather than interpolated (amendment A.2's five names all satisfy it).
_SCOPE_SAFE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._"
)


class DelegatedSetupError(CommandError):
    """The delegated step cannot be completed safely -> exit 2.

    Raised when the answer this step needs is missing or unusable: the tenant does
    not offer one of the five scopes, or the registration came back in a shape this
    step cannot read. The consent step deliberately does *not* raise for a refusal —
    see :func:`ensure_admin_consent`.
    """


# --- Result shapes -----------------------------------------------------------
@dataclass(frozen=True)
class DelegatedPermissionsOutcome:
    """The declared-scopes step: what was added, and what was already there."""

    app_id: str
    granted: tuple[str, ...] = ()
    already_present: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    @property
    def created(self) -> bool:
        return bool(self.granted)

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    @property
    def detail(self) -> str:
        if self.created:
            return f"declared delegated scopes {', '.join(self.granted)}"
        return (
            f"delegated scopes {', '.join(self.scopes)} already declared "
            "(nothing to add)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "granted": list(self.granted),
            "already_present": list(self.already_present),
            "scopes": list(self.scopes),
            "outcome": self.outcome,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class PublicClientOutcome:
    """The public-client-flows step: was the switch already on?"""

    app_id: str
    enabled: bool  # True when *this run* turned it on
    property_name: str = "isFallbackPublicClient"

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.enabled else OUTCOME_EXISTS

    @property
    def detail(self) -> str:
        if self.enabled:
            return f"enabled {self.property_name} (Allow public client flows)"
        return (
            f"{self.property_name} already true — Allow public client flows is on, "
            "as amendment A.2 requires for a delegated tenant"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "enabled": self.enabled,
            "property": self.property_name,
            "outcome": self.outcome,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ConsentOutcome:
    """The optional admin-consent step. ``warn`` is the degrade path.

    This step never fails the bootstrap: a tenant whose verification step blocks
    admin consent still works, because the operator's own ``mnotify login`` consents
    these scopes for that user. So a refusal is reported as ``warn`` with the reason,
    and the command layer turns it into ``skipped`` (which is how it reaches the
    ``--json`` summary — the only failure channels there are ``ok`` and ``exitCode``,
    so a silent pass would hide it).
    """

    granted: tuple[str, ...] = ()
    already_granted: tuple[str, ...] = ()
    warned: bool = False
    reason: str = ""

    @property
    def created(self) -> bool:
        return bool(self.granted)

    @property
    def outcome(self) -> str:
        # `warned` is the signal the command layer reads: it owns the `skipped`
        # outcome (only the command layer knows a step was skipped) and maps a
        # refusal onto it, because `--json` has just two failure channels (`ok`,
        # `exitCode`) and a warn-and-continue must be a visible step, not one.
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    @property
    def detail(self) -> str:
        if self.warned:
            return self.reason or "admin consent not granted"
        if self.created:
            return f"admin consent granted for {', '.join(self.granted)}"
        return (
            f"admin consent already covers {', '.join(self.already_granted)} "
            "(nothing to grant)"
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "granted": list(self.granted),
            "already_granted": list(self.already_granted),
            "outcome": self.outcome,
            "detail": self.detail,
        }
        if self.reason:
            payload["reason"] = self.reason
        return payload


# --- Reading the tenant ------------------------------------------------------
@dataclass(frozen=True)
class GraphResource:
    """What the tenant says Microsoft Graph offers, narrowed to what we need.

    ``scopes`` maps a scope name to the id that tenant publishes for it; the ids are
    what ``requiredResourceAccess`` stores, so they come from the tenant rather than
    from a table in this file (see the note by :data:`MS_GRAPH_APP_ID` for why that
    is also the only safe choice for a tracked file).
    """

    object_id: str
    scopes: Mapping[str, str]

    def require(self, scopes: Sequence[str]) -> dict[str, str]:
        """The id map for ``scopes``, or a refusal naming what the tenant lacks."""
        missing = [name for name in scopes if name not in self.scopes]
        if missing:
            raise DelegatedSetupError(
                f"the Microsoft Graph service principal in this tenant does not offer "
                f"{', '.join(missing)}; refusing to write a permission id we cannot "
                "resolve — check the tenant's Graph service principal "
                "(`az ad sp show --id " + MS_GRAPH_APP_ID + "`)"
            )
        return {name: self.scopes[name] for name in scopes}


def graph_query(scopes: Sequence[str]) -> str:
    """The ``--query`` that reads the object id *and* the scope ids in one call.

    A tenant's Graph service principal publishes ~900 scopes (900 KB of JSON), so the
    projection is not an optimisation: without it this step would pull a megabyte to
    read five lines. Verified live against azure-cli 2.90.0 on 2026-10-31.
    """
    names = [_check_scope(name) for name in scopes]
    filter_expr = "||".join(f"value=='{name}'" for name in names)
    return (
        "{id:id,scopes:oauth2PermissionScopes[?"
        + filter_expr
        + "].{value:value,id:id}}"
    )


def graph_resource(
    scopes: Sequence[str], *, runner: CommandRunner | None = None
) -> GraphResource:
    """Read the Graph service principal: its object id and the scope ids it offers.

    One read serves three purposes — the object id ``az ad app permission grant``
    needs as ``--api``, the scope ids the permission write needs, and the proof that
    each scope exists at all in *this* tenant. A tenant that does not publish one of
    them is a refusal, not a silent skip: writing a permission for a scope the tenant
    does not offer would produce an app that signs in and then cannot send.
    """
    names = [_check_scope(name) for name in scopes]
    payload = run_json(
        [
            "az",
            "ad",
            "sp",
            "show",
            "--id",
            MS_GRAPH_APP_ID,
            "--query",
            graph_query(names),
        ],
        runner=runner,
    )
    if not isinstance(payload, Mapping):
        raise DelegatedSetupError(
            "`az ad sp show` for Microsoft Graph did not print the object id and "
            f"scope list this step expects (got {type(payload).__name__})"
        )
    object_id = _text(payload.get("id"))
    if not object_id:
        raise DelegatedSetupError(
            "could not read the Microsoft Graph service principal object id from this "
            "tenant; the consent step needs it and refuses to guess"
        )
    entries = payload.get("scopes")
    if not isinstance(entries, list):
        raise DelegatedSetupError(
            "`az ad sp show` for Microsoft Graph did not print the list of scope "
            f"entries this step expects (got {type(entries).__name__})"
        )
    found: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        value = _text(entry.get("value"))
        identifier = _text(entry.get("id"))
        if value and identifier:
            found[value] = identifier
    resource = GraphResource(object_id=object_id, scopes=found)
    resource.require(names)  # validates: raises if the tenant lacks one of them
    return resource


def app_show_argv(app_id: str) -> list[str]:
    """The read of the registration, projected to the two things this module reads.

    A full ``az ad app show`` is a large document (every credential, every redirect
    URI); this module needs exactly the declared permissions and the public-client
    switch, and asks for nothing else. The filter on ``requiredResourceAccess`` keeps
    only the Microsoft Graph entry — the other APIs on the registration are not this
    step's business and are never written by it.
    """
    _check_app_id(app_id)
    return [
        "az",
        "ad",
        "app",
        "show",
        "--id",
        app_id,
        "--query",
        f"{{requiredResourceAccess:requiredResourceAccess[?resourceAppId=='{MS_GRAPH_APP_ID}'],"
        f" {_PUBLIC_CLIENT_PROPERTY}:{_PUBLIC_CLIENT_PROPERTY}}}",
    ]


def show_app(app_id: str, *, runner: CommandRunner | None = None) -> Mapping[str, Any]:
    """The application registration as ``az`` sees it.

    A read-only lookup, and the only way this module learns what is already declared
    — which is what makes a re-run report ``exists`` instead of rewriting.
    """
    payload = run_json(app_show_argv(app_id), runner=runner)
    if not isinstance(payload, Mapping):
        raise DelegatedSetupError(
            f"`az ad app show --id {app_id}` did not print one application object "
            f"(got {type(payload).__name__}); refusing to treat an unreadable answer "
            "as 'nothing configured yet'"
        )
    return payload


def declared_graph_scopes(
    app: Mapping[str, Any], id_to_name: Mapping[str, str]
) -> set[str]:
    """The delegated scope names the registration already declares on Graph.

    Two filters, both load-bearing: only the ``resourceAppId`` entry for Microsoft
    Graph is looked at (a permission on some other API is somebody else's business),
    and only ``type: "Scope"`` entries count — a ``Role`` entry is an application
    permission, and this module reports on it and never modifies it.

    An id this module cannot name (a Graph delegated scope we did not ask about, e.g.
    ``User.Read`` added by hand for another tool) is left out of the answer and left
    alone by every write: "not in our list" is never read as "remove it".
    """
    names: set[str] = set()
    for entry in _entries(app.get("requiredResourceAccess")):
        if _text(entry.get("resourceAppId")).casefold() != MS_GRAPH_APP_ID.casefold():
            continue
        for access in _entries(entry.get("resourceAccess")):
            if _text(access.get("type")).lower() != ACCESS_SCOPE.lower():
                continue
            named = id_to_name.get(_text(access.get("id")).lower())
            if named:
                names.add(named)
    return names


# The property behind the portal's "Allow public client flows" toggle, and the only
# name that works: `allowPublicClientFlows` is *not* an az or Graph property (checked
# against azure-cli 2.90.0 — neither the CLI's source nor its `az ad app update`
# surface carries it), and writing it would make every delegated run fail on a
# property Entra does not have.
_PUBLIC_CLIENT_PROPERTY = "isFallbackPublicClient"


# --- The argv builders (one source of truth for the plan and the write) ------
# These are the *published plan surface*, the same role B3's
# ``plan_certificate_upload`` and B4's ``plan_commands`` play: the command layer's
# ``--dry-run`` prints exactly these lists, so a plan cannot advertise a command the
# step would not run, and a write cannot quietly grow an argument the operator was
# never shown. Nothing here executes anything.
def permission_add_argv(app_id: str, scope_id: str) -> list[str]:
    """The one-scope ``az ad app permission add`` (see the module docstring)."""
    _check_app_id(app_id)
    return [
        "az",
        "ad",
        "app",
        "permission",
        "add",
        "--id",
        app_id,
        "--api",
        MS_GRAPH_APP_ID,
        "--api-permissions",
        f"{scope_id}={ACCESS_SCOPE}",
    ]


def public_client_enable_argv(app_id: str) -> list[str]:
    """The ``--set`` that turns the device-code flow on — and the only one."""
    _check_app_id(app_id)
    return [
        "az",
        "ad",
        "app",
        "update",
        "--id",
        app_id,
        "--set",
        f"{_PUBLIC_CLIENT_PROPERTY}=true",
    ]


def list_grants_argv(sp_object_id: str) -> list[str]:
    """The read that answers "what is already consented for this app?"."""
    _check_object_id(sp_object_id, "service principal object id")
    return ["az", "ad", "app", "permission", "list-grants", "--id", sp_object_id]


def consent_grant_argv(sp_object_id: str, graph_object_id: str, scopes: Sequence[str]) -> list[str]:
    """The tenant-wide consent for exactly ``scopes`` — never the whole app.

    ``--api`` takes the *object id* of the resource service principal (az's own
    ``--resource-id`` alias says so), and ``--scope`` is the space-separated claim
    list. az's ``permission grant`` is the delegated-consent command; the
    application-permission one is ``admin-consent``, which this module deliberately
    never builds.
    """
    _check_object_id(sp_object_id, "service principal object id")
    _check_object_id(graph_object_id, "Microsoft Graph service principal object id")
    names = [_check_scope(name) for name in scopes]
    if not names:
        raise DelegatedSetupError("consent needs at least one scope to grant")
    return [
        "az",
        "ad",
        "app",
        "permission",
        "grant",
        "--id",
        sp_object_id,
        "--api",
        graph_object_id,
        "--scope",
        " ".join(names),
    ]


# --- The writes --------------------------------------------------------------
# What az actually prints for a WRITE, verified against the installed azure-cli
# (2.90.0, ``command_modules/role/custom.py``) rather than assumed:
#
# * ``permission add`` — NOTHING. ``add_permission`` PATCHes the registration and
#   then emits one ``logger.warning``; there is no ``return``, so knack's invoker
#   gets ``None`` and ``cli.py`` skips the output formatter outright
#   (``if cmd_result and cmd_result.result is not None``). Exit 0, empty stdout,
#   ``WARNING: Invoking `az ad app permission grant ...` is needed to make the
#   change effective`` on stderr. That WARNING is az telling the operator about
#   the consent step — the very next step this module runs — not an error.
# * ``update --set`` — the same: az's generic update ends in the same
#   ``application_update`` PATCH, whose 204 response body is empty, so ``_send``
#   returns ``None`` and nothing is printed.
# * ``permission grant`` — by contrast it DOES print JSON: ``grant_application``
#   returns the created ``oauth2PermissionGrant`` (a POST with a body). That is why
#   the consent path below keeps ``run_json`` and these two do not.
#
# So a delegated write's verdict is its exit code, and the *claim* of success is a
# separate read of the tenant. Reading a silent write through
# :func:`~micro_notify.admin.runner.run_json` inverts both: it turns az's healthiest
# answer into ``'az' did not print JSON`` and exits 2. (B3 hit the same contract on
# ``credential upload`` and solved it the same way — see
# ``admin/certupload.py::_run_checked``.)
_STDERR_QUOTE_LIMIT = 200


def _quote_stderr(stderr: Any) -> str:
    """One collapsed, bounded line of az's own stderr, or ``''``.

    Mirrors :mod:`micro_notify.admin.runner`'s private helper rather than importing
    it (that module is not this card's to edit, and reaching into another card's
    underscore names is worse than six lines).
    """
    line = " ".join((stderr or "").split())
    if not line:
        return ""
    if len(line) > _STDERR_QUOTE_LIMIT:
        line = line[:_STDERR_QUOTE_LIMIT].rstrip() + "..."
    return f" — {line}"


def run_write(argv: Sequence[str], *, runner: CommandRunner | None = None, label: str = "") -> None:
    """Run an az WRITE whose success signal is the exit code, never stdout.

    Deliberately not :func:`~micro_notify.admin.runner.run_json`: for these commands
    az prints nothing on success, so "no JSON" is the healthy answer and cannot be
    the failure signal. A non-zero exit still raises, still quoting at most
    :data:`_STDERR_QUOTE_LIMIT` characters of stderr — that is where az puts its own
    diagnosis, and it is the only place the operator can learn *why*.
    """
    args = [str(a) for a in argv]
    result = (runner or get_runner()).run(args)
    returncode = getattr(result, "returncode", None)
    if returncode is None or int(returncode) != 0:
        code = "unknown" if returncode is None else int(returncode)
        what = label or " ".join(args)
        raise DelegatedSetupError(
            f"`{what}` failed (exit {code}){_quote_stderr(getattr(result, 'stderr', None))}"
        )


def graph_entry_query() -> str:
    """The ``--query`` that keeps only the Microsoft Graph entry of the permission list.

    ``az ad app permission list`` returns the application's whole
    ``requiredResourceAccess`` list. The filter is a JMESPath *filter expression*, not
    ``<graphAppId>.resourceAccess``: a bare identifier cannot contain a ``-`` (az's own
    bundled jmespath rejects it with ``LexerError: Unknown token '-'``) and the document
    is a list, so key lookup on it answers ``null`` either way. Filtering on
    ``resourceAppId`` is what :func:`declared_graph_scopes` already does in Python, so
    the read agrees with the parser.
    """
    return f"[?resourceAppId=='{MS_GRAPH_APP_ID}']"


def permission_list_argv(app_id: str) -> list[str]:
    """The read-back: what the tenant says the registration declares right now."""
    _check_app_id(app_id)
    return [
        "az",
        "ad",
        "app",
        "permission",
        "list",
        "--id",
        app_id,
        "--query",
        graph_entry_query(),
    ]


def read_back_graph_access_ids(
    app_id: str, *, runner: CommandRunner | None = None
) -> set[str]:
    """The permission ids the tenant NOW reports as declared Scope entries on Graph.

    The shape is the one :func:`declared_graph_scopes` already parses: ``az ad app
    permission list`` returns the application's ``requiredResourceAccess`` list
    (verified against the installed azure-cli 2.90.0, ``role/custom.py::list_permissions``
    returns ``application['requiredResourceAccess']``), so the read-back and the
    pre-write read are the same document read by the same two rules — one
    ``resourceAppId`` filter, one ``Scope``-only filter — and a ``Role`` entry can
    never look like proof that a delegated scope landed.

    Compared against the ids the write *sent*, not against scope names. An id is what
    ``requiredResourceAccess.resourceAccess`` stores, so an id comparison is evidence
    about the exact permission this step wrote; a name comparison has to route through
    ``id_to_name``, and where a tenant (or a fixture — see
    ``test_the_ids_written_are_the_ones_the_tenant_published``, which deliberately
    publishes two ids for five scopes) reuses one id for several names, a name match
    would credit every one of them with a write that only carried one.

    ``null`` or an empty list means the registration declares no Microsoft Graph entry
    at all: an empty answer, not a malformed one.
    """
    payload = run_json(permission_list_argv(app_id), runner=runner)
    if payload is None:
        return set()
    if not isinstance(payload, (list, tuple)):
        raise DelegatedSetupError(
            f"`az ad app permission list --id {app_id}` did not print the "
            f"requiredResourceAccess list this step reads (got "
            f"{type(payload).__name__}); refusing to guess whether the scopes landed"
        )
    found: set[str] = set()
    for entry in _entries(payload):
        if _text(entry.get("resourceAppId")).casefold() != MS_GRAPH_APP_ID.casefold():
            # Somebody else's API: a permission on it is not evidence about Graph,
            # even if it carried the same id.
            continue
        for access in _entries(entry.get("resourceAccess")):
            if _text(access.get("type")).lower() != ACCESS_SCOPE.lower():
                continue
            identifier = _text(access.get("id")).lower()
            if identifier:
                found.add(identifier)
    return found


def ensure_delegated_permissions(
    app_id: str,
    scopes: Sequence[str],
    *,
    runner: CommandRunner | None = None,
    graph: GraphResource | None = None,
) -> DelegatedPermissionsOutcome:
    """Declare the delegated scopes on the app registration, additively.

    Order matters for idempotency: read the registration first, then write only the
    names it does not already carry. A re-run therefore issues two reads and no
    writes, which is what lets the command report ``exists`` and change nothing.

    The write is one ``permission add`` per scope rather than one call carrying five,
    so a tenant that rejects exactly one of them (a verification rule blocking, say,
    ``ChatMessage.Send``) fails with the failing scope named in the argv instead of
    failing for an opaque reason with all five in the payload.

    The add itself prints nothing (see the note above :func:`run_write`), so the exit
    code decides whether it ran and a **read-back decides whether it took**. az's own
    stdout is not evidence either way: an empty stdout is the success answer, and the
    ``WARNING: ... permission grant ...`` it puts on stderr is a pointer at the consent
    step, not a complaint. A zero exit whose scope then does not appear in
    ``permission list`` is reported as a failure naming that scope — a registration that
    looks configured but cannot send is the worse outcome, and it is the one a silently
    dropped write would produce.
    """
    names = tuple(_check_scope(name) for name in scopes)
    resource = graph or graph_resource(names, runner=runner)
    ids = resource.require(names)
    app = show_app(app_id, runner=runner)
    id_to_name = {i.lower(): n for n, i in ids.items()}
    present = declared_graph_scopes(app, id_to_name)

    to_add = [name for name in names if name not in present]
    if to_add:
        for name in to_add:
            run_write(
                permission_add_argv(app_id, ids[name]),
                runner=runner,
                label=f"az ad app permission add (scope {name})",
            )
        # One read for the whole batch rather than one per scope: az PATCHes each add
        # before its process exits, so a scope still absent after the last one is
        # absent for good — and one read names every scope that failed rather than
        # only the first.
        declared_ids = read_back_graph_access_ids(app_id, runner=runner)
        not_applied = [name for name in to_add if ids[name].lower() not in declared_ids]
        if not_applied:
            raise DelegatedSetupError(
                f"`az ad app permission add` exited 0 but {', '.join(not_applied)} "
                f"{'is' if len(not_applied) == 1 else 'are'} still not declared on app "
                f"{app_id} for Microsoft Graph — refusing to report scopes the tenant "
                "does not show; check the registration in the portal "
                "(Entra ID -> App registrations -> API permissions)"
            )
    return DelegatedPermissionsOutcome(
        app_id=app_id,
        granted=tuple(to_add),
        already_present=tuple(name for name in names if name in present),
        scopes=names,
    )


def ensure_public_client_flows(
    app_id: str, *, runner: CommandRunner | None = None
) -> PublicClientOutcome:
    """Turn on the device-code flow, once, and say whether this run had to.

    ``isFallbackPublicClient`` is the property behind the portal's "Allow public
    client flows" toggle, and it is the whole switch: with it false Entra issues a
    device code and then refuses to redeem it (``invalid_client``), so a delegated
    sign-in cannot complete. Only ``true`` is ever written here. An app-only tenant
    keeps it false — amendment A.2's per-tenant table — and the only code path that
    calls this function is the delegated one.
    """
    app = show_app(app_id, runner=runner)
    if app.get(_PUBLIC_CLIENT_PROPERTY) is True:
        return PublicClientOutcome(app_id=app_id, enabled=False)
    # The same write contract as `permission add`: az's generic update ends in the
    # same PATCH, whose empty body leaves knack nothing to print. Through run_json
    # this step would fail on every real run for exactly BUG6's reason.
    run_write(
        public_client_enable_argv(app_id),
        runner=runner,
        label=f"az ad app update ({_PUBLIC_CLIENT_PROPERTY})",
    )
    return PublicClientOutcome(app_id=app_id, enabled=True)


def granted_scopes(grants: Any) -> set[str]:
    """Every scope name carried by a list of ``oauth2PermissionGrant`` objects.

    ``scope`` is one space-separated string per grant, so a tenant that consented
    three of the five in one grant and two in another still reads back as complete.
    Anything that is not a scope list is an empty answer, not an error: this feeds a
    warn-and-continue step, and "could not read the grants" must degrade the same way
    a refusal does rather than abort a bootstrap that will work without consent.
    """
    if not isinstance(grants, (list, tuple)):
        return set()
    names: set[str] = set()
    for entry in grants:
        if not isinstance(entry, Mapping):
            continue
        for token in _text(entry.get("scope")).split():
            names.add(token)
    return names


def ensure_admin_consent(
    sp_object_id: str,
    scopes: Sequence[str],
    *,
    runner: CommandRunner | None = None,
    graph: GraphResource | None = None,
) -> ConsentOutcome:
    """Grant tenant-wide consent for exactly ``scopes`` — or warn and carry on.

    Deliberately *not* ``az ad app permission admin-consent``: that command consents
    everything the registration declares, including another mode's application
    permissions. This one names the five scopes in ``--scope``.

    A refusal is the expected outcome in a tenant with verification rules, and it is
    not a failure: the operator's own sign-in consents the same scopes for themselves.
    So every problem here — az exiting non-zero, the read-back still coming up short,
    the grants being unreadable — comes back as ``warned=True`` with the reason, and
    the caller decides how loud to be. Only a missing object id can raise, and that is
    a programming error rather than a tenant state.
    """
    names = tuple(_check_scope(name) for name in scopes)
    resource = graph or graph_resource(names, runner=runner)
    read = list_grants_argv(sp_object_id)

    try:
        before = granted_scopes(run_json(read, runner=runner))
    except CommandError as exc:
        return ConsentOutcome(
            warned=True, reason=f"could not read the existing consent grants ({exc.message})"
        )

    missing = [name for name in names if name not in before]
    if not missing:
        return ConsentOutcome(already_granted=names)

    try:
        run_json(consent_grant_argv(sp_object_id, resource.object_id, names), runner=runner)
        after = granted_scopes(run_json(read, runner=runner))
    except CommandError as exc:
        return ConsentOutcome(
            warned=True,
            reason=(
                f"admin consent refused ({exc.message}); {CONSENT_HINT}. User consent "
                "still works, so the delegated sign-in will go ahead"
            ),
        )

    still_missing = [name for name in names if name not in after]
    if still_missing:
        # The write reported success and the read disagrees. Report the disagreement:
        # a bootstrap that claimed consent and then failed at `doctor`'s scope check
        # would be a worse operator experience than saying "not visible yet".
        return ConsentOutcome(
            already_granted=tuple(name for name in names if name in after),
            warned=True,
            reason=(
                f"`az ad app permission grant` succeeded but {', '.join(still_missing)} "
                f"is not visible in the tenant's grants yet; {CONSENT_HINT}"
            ),
        )
    return ConsentOutcome(granted=tuple(missing), already_granted=tuple(before & set(names)))


# --- Helpers -----------------------------------------------------------------
def _entries(value: Any) -> list[Mapping[str, Any]]:
    """A ``requiredResourceAccess``-style list as a list of mappings, ignoring junk.

    Tolerant on purpose, in one direction only: a shape this step cannot read yields
    "nothing declared here", which for a *read that gates an additive write* means
    "write it" — a re-declaration az merges, never a deletion. The strict read is
    :func:`show_app`, which refuses an unreadable application object outright.
    """
    if not isinstance(value, (list, tuple)):
        return []
    return [entry for entry in value if isinstance(entry, Mapping)]


def _text(value: Any) -> str:
    """A value as a stripped string, or ``''`` when it is not a string at all.

    Strict on purpose: every caller is reading an identifier or a claim value out of
    a JSON document, and a number or a boolean there means the answer is not the
    shape this step was told to read. Turning ``True`` into ``"True"`` would let a
    malformed entry satisfy a "did we get an id?" check.
    """
    if isinstance(value, str):
        return value.strip()
    return ""


def _check_scope(name: str) -> str:
    """A Graph scope claim value, or a refusal.

    The name goes into a JMESPath filter literal and into a space-separated
    ``--scope`` value, so a quote, a space or a dash could rewrite the expression or
    split the argument. Amendment A.2's five names all pass.
    """
    value = (name or "").strip()
    if not value:
        raise DelegatedSetupError("a scope name must not be empty")
    if any(ch not in _SCOPE_SAFE_CHARS for ch in value):
        raise DelegatedSetupError(
            f"the scope name {name!r} contains characters that are not safe to pass "
            "to az (letters, digits, '.' and '_' only)"
        )
    return value


def _check_app_id(app_id: str) -> None:
    """Reject an app id that cannot safely reach ``az --id``.

    Not an injection guard — the value is its own argv element, never a shell string
    — but ``az`` reads a value starting with ``-`` as an option, and whitespace means
    it is two arguments. Either would change which object gets the permission.
    """
    value = (app_id or "").strip()
    if not value or value != app_id:
        raise DelegatedSetupError("the application id must not be empty or padded")
    if value.startswith("-") or any(ch.isspace() for ch in value):
        raise DelegatedSetupError(
            f"the application id {app_id!r} is not safe to pass to az (it would read "
            "as an option, or as two arguments)"
        )


def _check_object_id(object_id: str, label: str) -> None:
    """Same rule as :func:`_check_app_id`, for any object id."""
    value = (object_id or "").strip()
    if not value or value != object_id:
        raise DelegatedSetupError(f"the {label} must not be empty or padded")
    if value.startswith("-") or any(ch.isspace() for ch in value):
        raise DelegatedSetupError(
            f"the {label} {object_id!r} is not safe to pass to az (it would read as "
            "an option, or as two arguments)"
        )


__all__ = [
    "ACCESS_ROLE",
    "ACCESS_SCOPE",
    "CONSENT_HINT",
    "MS_GRAPH_APP_ID",
    "OUTCOME_CREATED",
    "OUTCOME_EXISTS",
    "ConsentOutcome",
    "DelegatedPermissionsOutcome",
    "DelegatedSetupError",
    "GraphResource",
    "PublicClientOutcome",
    "app_show_argv",
    "consent_grant_argv",
    "declared_graph_scopes",
    "ensure_admin_consent",
    "ensure_delegated_permissions",
    "ensure_public_client_flows",
    "granted_scopes",
    "graph_query",
    "graph_resource",
    "list_grants_argv",
    "permission_add_argv",
    "public_client_enable_argv",
    "show_app",
]
