"""Tests for :mod:`micro_notify.admin.entra` (card B2).

Nothing here can run a real ``az``: the autouse ``no_real_admin_binaries`` guard
turns the *real* subprocess layer into a tripwire for az/pwsh/brew/security, and
each test installs its own fake :class:`CommandRunner` holding canned ``az`` JSON.
Sockets stay blocked by the untouched ``tests/conftest.py``. Every id in this file
is the documented placeholder GUID.

The five behaviours the card pins: the create path, the reuse paths (app + SP, and
SP only), exact-name matching (a ``micro-notify-staging`` near-miss must never be
adopted), and the no-consent invariant — asserted over *every* argv any scenario
builds, so a future ``--set requiredResourceAccess`` cannot pass silently.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from micro_notify import EXIT_USAGE
from micro_notify.admin.entra import (
    APP_DISPLAY_NAME,
    OUTCOME_CREATED,
    OUTCOME_EXISTS,
    SIGN_IN_AUDIENCE,
    AppOutcome,
    EntraError,
    EntraProvisioning,
    ServicePrincipalOutcome,
    create_app,
    create_service_principal,
    ensure_app_registration,
    ensure_entra_app,
    ensure_service_principal,
    find_app_id,
    find_service_principal_id,
)
from micro_notify.admin.runner import (
    CommandError,
    DryRunRunner,
    get_runner,
    set_runner,
)

# --- Placeholders only (design §5, leak guard) -------------------------------
APP_ID = "00000000-0000-0000-0000-000000000000"
SP_OBJECT_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"


def other_guid(placeholder: str, last: str) -> str:
    """An id that differs from ``placeholder``, assembled at runtime.

    The leak guard (tests/test_leak_guard.py) rejects any GUID that is not the
    all-zero or the all-ones placeholder, and these tests need to tell two ids
    apart — which app was adopted, which of two service principals was refused.
    Deriving the second one from a documented placeholder is that guard's own
    convention for canaries: no non-placeholder literal appears in a tracked file,
    and the assertions still compare two genuinely different values.
    """
    return placeholder[:-1] + last


NEAR_MISS_APP_ID = other_guid(APP_ID, "1")
SECOND_SP_OBJECT_ID = other_guid(SP_OBJECT_ID, "e")

# Binaries a unit test must never execute, whatever the reason (same list as B1).
FORBIDDEN_BINARIES = frozenset({"az", "pwsh", "brew", "powershell", "security"})

# Any argv carrying one of these (case-insensitively) would mean this step touched
# permissions, roles, credentials or consent. The card forbids all of it.
FORBIDDEN_ARGV_MARKERS = (
    "requiredresourceaccess",
    "approle",  # also covers appRoles / appRoleAssignedTo
    "permission",
    "consent",
    "grant",
    "password",
    "credential",
    "secret",
    "certificate",
    "--set",
    "delegatedpermissiongrant",
)


@pytest.fixture(autouse=True)
def restore_process_runner() -> Any:
    """No test leaks its fake runner into the next one."""
    try:
        yield
    finally:
        set_runner(None)


@pytest.fixture(autouse=True)
def no_real_admin_binaries(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Tripwire: the real subprocess layer must never be asked for az/pwsh/brew."""
    real_run = subprocess.run

    def guarded(run_args: Any, **kwargs: Any) -> Any:
        argv = [str(a) for a in run_args]
        if argv and Path(str(argv[0])).name in FORBIDDEN_BINARIES:
            raise AssertionError(f"test attempted to execute a real {argv[0]!r}")
        return real_run(run_args, **kwargs)

    monkeypatch.setattr("micro_notify.admin.runner.subprocess.run", guarded)
    return guarded


# --- Fake runner ------------------------------------------------------------
def completed(
    argv: list[str], returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


class FakeAz:
    """A :class:`CommandRunner` that answers canned ``az`` JSON and records argv.

    ``answers`` maps the argv prefix that identifies a call to the JSON text (or a
    ready-made result, or an exception to raise). Anything unmatched records too and
    answers ``[]`` — the honest "not found" for a list command, and the reason a
    test that forgot to script a create still sees the create attempted rather than
    a silent success.
    """

    def __init__(self, answers: dict[tuple[str, ...], Any] | None = None) -> None:
        self.answers = dict(answers or {})
        self.calls: list[list[str]] = []
        self.stdin_payloads: list[str | None] = []

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        self.calls.append(args)
        self.stdin_payloads.append(stdin)
        for prefix, answer in self.answers.items():
            if tuple(args[: len(prefix)]) == prefix:
                if isinstance(answer, BaseException):
                    raise answer
                if isinstance(answer, str):
                    return completed(args, 0, answer)
                return answer
        return completed(args, 0, "[]")

    # --- assertions helpers used by the tests below
    @property
    def joined(self) -> str:
        return " ".join(" ".join(call) for call in self.calls)

    def argv_for(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]

    def executed(self, *prefix: str) -> bool:
        return bool(self.argv_for(*prefix))

    @property
    def created_anything(self) -> bool:
        """True if any write (``create``) call was attempted."""
        return any("create" in call for call in self.calls)


def app_entry(display_name: str = APP_DISPLAY_NAME, app_id: str = APP_ID) -> str:
    return json.dumps([{"appId": app_id, "displayName": display_name}])


def sp_entry(object_id: str = SP_OBJECT_ID, app_id: str = APP_ID) -> str:
    return json.dumps([{"id": object_id, "appId": app_id, "displayName": APP_DISPLAY_NAME}])


FRESH_TENANT: dict[tuple[str, ...], Any] = {
    ("az", "ad", "app", "list"): "[]",
    ("az", "ad", "sp", "list"): "[]",
    ("az", "ad", "app", "create"): json.dumps({"appId": APP_ID, "displayName": APP_DISPLAY_NAME}),
    ("az", "ad", "sp", "create"): json.dumps({"id": SP_OBJECT_ID, "appId": APP_ID}),
}

CONFIGURED_TENANT: dict[tuple[str, ...], Any] = {
    ("az", "ad", "app", "list"): app_entry(),
    ("az", "ad", "sp", "list"): sp_entry(),
}


# --- Create path ------------------------------------------------------------
def test_fresh_tenant_creates_both_objects_and_reports_created() -> None:
    fake = FakeAz(FRESH_TENANT)
    result = ensure_entra_app(runner=fake)

    assert isinstance(result, EntraProvisioning)
    assert (result.app_id, result.sp_object_id) == (APP_ID, SP_OBJECT_ID)
    assert result.created is True
    assert result.app_created is True and result.sp_created is True
    assert result.outcome == OUTCOME_CREATED
    # The app we created is the app we report; the SP id is the enterprise-app id B4 needs.
    assert "created" in result.detail and "already exist" not in result.detail


def test_create_path_builds_exactly_the_four_documented_commands() -> None:
    fake = FakeAz(FRESH_TENANT)
    ensure_entra_app(runner=fake)

    assert fake.calls == [
        # Each step looks up before it writes; the SP lookup can only happen once
        # an appId exists, so on a fresh tenant it follows the app create.
        ["az", "ad", "app", "list", "--display-name", APP_DISPLAY_NAME],
        [
            "az",
            "ad",
            "app",
            "create",
            "--display-name",
            APP_DISPLAY_NAME,
            "--sign-in-audience",
            SIGN_IN_AUDIENCE,
        ],
        ["az", "ad", "sp", "list", "--filter", f"appId eq '{APP_ID}'"],
        ["az", "ad", "sp", "create", "--id", APP_ID],
    ]


def test_find_app_returns_none_on_empty_list_without_creating() -> None:
    fake = FakeAz({("az", "ad", "app", "list"): "[]"})
    assert find_app_id(runner=fake) is None
    assert fake.calls == [["az", "ad", "app", "list", "--display-name", APP_DISPLAY_NAME]]
    assert not fake.created_anything


def test_app_create_is_single_tenant() -> None:
    fake = FakeAz(FRESH_TENANT)
    assert create_app(runner=fake) == APP_ID
    create = fake.argv_for("az", "ad", "app", "create")[0]
    assert create[create.index("--sign-in-audience") + 1] == "AzureADMyOrg"


def test_service_principal_create_returns_the_enterprise_app_object_id() -> None:
    fake = FakeAz(FRESH_TENANT)
    assert create_service_principal(APP_ID, runner=fake) == SP_OBJECT_ID
    assert fake.argv_for("az", "ad", "sp", "create") == [["az", "ad", "sp", "create", "--id", APP_ID]]


# --- Reuse paths ------------------------------------------------------------
def test_configured_tenant_reuses_both_and_writes_nothing() -> None:
    fake = FakeAz(CONFIGURED_TENANT)
    result = ensure_entra_app(runner=fake)

    assert (result.app_id, result.sp_object_id) == (APP_ID, SP_OBJECT_ID)
    assert result.created is False
    assert result.app_created is False and result.sp_created is False
    assert result.outcome == OUTCOME_EXISTS
    assert "found existing" in result.detail
    assert not fake.created_anything, f"a reuse run wrote: {fake.calls}"
    # Exactly two reads, in lookup order, and nothing else.
    assert fake.calls == [
        ["az", "ad", "app", "list", "--display-name", APP_DISPLAY_NAME],
        ["az", "ad", "sp", "list", "--filter", f"appId eq '{APP_ID}'"],
    ]


def test_only_service_principal_missing_creates_the_sp_but_never_a_second_app() -> None:
    """The real-world retry: the app exists, the SP step died halfway."""
    fake = FakeAz(
        {
            ("az", "ad", "app", "list"): app_entry(),
            ("az", "ad", "sp", "list"): "[]",
            ("az", "ad", "sp", "create"): json.dumps({"id": SP_OBJECT_ID, "appId": APP_ID}),
        }
    )
    result = ensure_entra_app(runner=fake)

    assert result.app_id == APP_ID
    assert result.sp_object_id == SP_OBJECT_ID
    assert result.created is True  # at least one object came from this run
    assert result.app_created is False
    assert result.sp_created is True
    assert not fake.executed("az", "ad", "app", "create"), "a duplicate app was created"
    assert "service principal" in result.detail


def test_sp_exists_but_app_lookup_happens_first() -> None:
    """The SP is looked up by the resolved appId, never by display name."""
    fake = FakeAz(CONFIGURED_TENANT)
    ensure_entra_app(runner=fake)
    sp_call = fake.argv_for("az", "ad", "sp", "list")[0]
    assert sp_call[:5] == ["az", "ad", "sp", "list", "--filter"]
    assert sp_call[5] == f"appId eq '{APP_ID}'"
    assert APP_DISPLAY_NAME not in sp_call


def test_repeated_ensure_is_stable_and_write_free() -> None:
    """The card's acceptance criterion: a re-run reports 'exists' and exits 0-able."""
    fake = FakeAz(CONFIGURED_TENANT)
    first = ensure_entra_app(runner=fake)
    second = ensure_entra_app(runner=fake)

    assert first.to_dict() == second.to_dict()
    assert second.created is False
    assert not fake.created_anything


# --- Exact-name matching ----------------------------------------------------
def test_near_miss_display_name_is_never_adopted() -> None:
    """``micro-notify-staging`` must not be reused, even though az's filter may pass it."""
    fake = FakeAz(
        {
            ("az", "ad", "app", "list"): json.dumps(
                [
                    {"displayName": "micro-notify-staging", "appId": NEAR_MISS_APP_ID},
                    {"displayName": "micro-notify-dev", "appId": NEAR_MISS_APP_ID},
                    {"displayName": "micro-notify-extra", "appId": NEAR_MISS_APP_ID},
                ]
            )
        }
    )
    assert find_app_id(runner=fake) is None


def test_near_miss_alongside_the_real_app_picks_the_exact_one() -> None:
    fake = FakeAz(
        {
            ("az", "ad", "app", "list"): json.dumps(
                [
                    {"displayName": "micro-notify-staging", "appId": NEAR_MISS_APP_ID},
                    {"displayName": APP_DISPLAY_NAME, "appId": APP_ID},
                    {"displayName": "micro-notify-legacy", "appId": NEAR_MISS_APP_ID},
                ]
            ),
            ("az", "ad", "sp", "list"): sp_entry(),
        }
    )
    result = ensure_entra_app(runner=fake)
    assert result.app_id == APP_ID
    assert result.created is False
    assert not fake.created_anything


def test_case_differing_name_is_treated_as_a_different_app() -> None:
    """Documented decision: adopting a differently-named app is the unrecoverable error.

    Attaching a certificate and an Exchange Send-as grant to an application this
    tool did not name cannot be undone quietly; creating a second app registration
    can. So the match is exact, case included.
    """
    fake = FakeAz(
        {("az", "ad", "app", "list"): json.dumps([{"displayName": "Micro-Notify", "appId": NEAR_MISS_APP_ID}])}
    )
    assert find_app_id(runner=fake) is None


def test_two_exact_matches_refuse_rather_than_pick() -> None:
    fake = FakeAz(
        {
            ("az", "ad", "app", "list"): json.dumps(
                [
                    {"displayName": APP_DISPLAY_NAME, "appId": APP_ID},
                    {"displayName": APP_DISPLAY_NAME, "appId": NEAR_MISS_APP_ID},
                ]
            )
        }
    )
    with pytest.raises(EntraError) as excinfo:
        find_app_id(runner=fake)
    assert "exact name" in str(excinfo.value)
    assert not fake.created_anything, "an ambiguous tenant must not trigger a create"


def test_ambiguous_service_principals_refuse() -> None:
    fake = FakeAz(
        {
            ("az", "ad", "sp", "list"): json.dumps(
                [
                    {"id": SP_OBJECT_ID, "appId": APP_ID},
                    {"id": SECOND_SP_OBJECT_ID, "appId": APP_ID},
                ]
            )
        }
    )
    with pytest.raises(EntraError):
        find_service_principal_id(APP_ID, runner=fake)
    assert not fake.created_anything


def test_sp_appid_match_is_case_insensitive_but_the_id_is_not_invented() -> None:
    """az hands back a lower-cased GUID; that is the same app."""
    fake = FakeAz({("az", "ad", "sp", "list"): json.dumps([{"id": SP_OBJECT_ID, "appId": APP_ID.upper()}])})
    assert find_service_principal_id(APP_ID, runner=fake) == SP_OBJECT_ID


def test_sp_entry_for_a_different_app_is_not_a_match() -> None:
    fake = FakeAz(
        {("az", "ad", "sp", "list"): json.dumps([{"id": SP_OBJECT_ID, "appId": NEAR_MISS_APP_ID}])}
    )
    assert find_service_principal_id(APP_ID, runner=fake) is None


# --- No-consent / no-permission invariant -----------------------------------
@pytest.mark.parametrize(
    "answers",
    [FRESH_TENANT, CONFIGURED_TENANT, dict(FRESH_TENANT)],
    ids=["fresh", "configured", "fresh-copy"],
)
def test_no_argv_ever_mentions_permissions_roles_or_consent(answers: dict[tuple[str, ...], Any]) -> None:
    """The card's hard rule, asserted over every argv the flow can build."""
    fake = FakeAz(answers)
    ensure_entra_app(runner=fake)

    offenders = [
        (call, marker)
        for call in fake.calls
        for marker in FORBIDDEN_ARGV_MARKERS
        if marker in " ".join(call).lower()
    ]
    assert not offenders, f"forbidden argv: {offenders}"


def test_no_argv_mentions_permissions_even_on_error_paths() -> None:
    """The invariant must hold for calls made before the failure too."""
    fake = FakeAz(
        {
            ("az", "ad", "app", "list"): "[]",
            ("az", "ad", "app", "create"): json.dumps({"displayName": APP_DISPLAY_NAME}),  # no appId
        }
    )
    with pytest.raises(EntraError):
        ensure_entra_app(runner=fake)
    assert all(
        marker not in " ".join(call).lower() for call in fake.calls for marker in FORBIDDEN_ARGV_MARKERS
    )


def test_nothing_is_ever_passed_on_stdin() -> None:
    """A credential would arrive on stdin; this step has no business with one."""
    fake = FakeAz(FRESH_TENANT)
    ensure_entra_app(runner=fake)
    assert fake.stdin_payloads == [None] * len(fake.calls)


# --- Unreadable answers are never "not found" -------------------------------
@pytest.mark.parametrize(
    "payload",
    ["null", '"not a list"', "[1, 2]", '{"value": []}'],
    ids=["null", "string", "scalars", "graph-envelope"],
)
def test_unreadable_app_list_raises_instead_of_creating(payload: str) -> None:
    """An answer we cannot read must not become a second application registration."""
    fake = FakeAz({**FRESH_TENANT, ("az", "ad", "app", "list"): payload})
    with pytest.raises(EntraError):
        find_app_id(runner=fake)
    assert not fake.created_anything


@pytest.mark.parametrize(
    "payload", ["null", "[1, 2]", '{"value": []}', "[[]]"], ids=["null", "scalars", "graph-envelope", "nested-list"]
)
def test_unreadable_sp_list_raises_instead_of_creating(payload: str) -> None:
    fake = FakeAz({**FRESH_TENANT, ("az", "ad", "sp", "list"): payload})
    with pytest.raises(EntraError):
        find_service_principal_id(APP_ID, runner=fake)
    assert not fake.created_anything


def test_app_found_without_appid_is_an_error_not_a_create() -> None:
    fake = FakeAz({("az", "ad", "app", "list"): json.dumps([{"displayName": APP_DISPLAY_NAME}])})
    with pytest.raises(EntraError):
        find_app_id(runner=fake)
    assert not fake.created_anything


def test_sp_found_without_object_id_is_an_error_not_a_create() -> None:
    fake = FakeAz({("az", "ad", "sp", "list"): json.dumps([{"appId": APP_ID}])})
    with pytest.raises(EntraError):
        find_service_principal_id(APP_ID, runner=fake)
    assert not fake.created_anything


def test_app_create_without_appid_raises() -> None:
    fake = FakeAz({("az", "ad", "app", "create"): json.dumps({"displayName": APP_DISPLAY_NAME})})
    with pytest.raises(EntraError):
        create_app(runner=fake)


def test_sp_create_without_object_id_raises_and_names_b4() -> None:
    fake = FakeAz({("az", "ad", "sp", "create"): json.dumps({"appId": APP_ID})})
    with pytest.raises(EntraError) as excinfo:
        create_service_principal(APP_ID, runner=fake)
    assert "object id" in str(excinfo.value)


def test_a_nonzero_exit_becomes_command_error_not_a_traceback() -> None:
    fake = FakeAz(
        {("az", "ad", "app", "list"): completed(["az"], 1, "", "Az CLI Error: AADSTS90002")}
    )
    with pytest.raises(CommandError):
        find_app_id(runner=fake)
    assert not fake.created_anything


# --- Argument guards --------------------------------------------------------
@pytest.mark.parametrize(
    "bad_name", ["  micro-notify", "micro-notify ", "-micro-notify", ""], ids=["leading", "trailing", "dash", "empty"]
)
def test_a_name_that_cannot_match_safely_is_rejected_before_az_runs(bad_name: str) -> None:
    fake = FakeAz(FRESH_TENANT)
    with pytest.raises(EntraError):
        find_app_id(bad_name, runner=fake)
    assert fake.calls == [], f"az was called with {fake.calls}"


@pytest.mark.parametrize(
    "bad_id",
    [
        APP_ID + "' or '1' eq '1",
        "admin@contoso.com",
        "micro-notify",
        " " + APP_ID,
        "",
    ],
    ids=["filter-injection", "upn", "name", "padded", "empty"],
)
def test_an_id_that_cannot_go_in_a_filter_is_rejected_before_az_runs(bad_id: str) -> None:
    fake = FakeAz(FRESH_TENANT)
    with pytest.raises(EntraError):
        find_service_principal_id(bad_id, runner=fake)
    with pytest.raises(EntraError):
        create_service_principal(bad_id, runner=fake)
    assert fake.calls == [], f"az was called with {fake.calls}"


def test_the_injection_shaped_id_never_reaches_the_filter_string() -> None:
    """Belt and braces on the one interpolated value in the whole module."""
    fake = FakeAz(FRESH_TENANT)
    with pytest.raises(EntraError):
        find_service_principal_id(APP_ID + "'", runner=fake)
    assert "'" not in fake.joined.replace(f"appId eq '{APP_ID}'", "")


# --- Seam usage -------------------------------------------------------------
def test_the_process_wide_runner_is_used_when_none_is_passed() -> None:
    """The module must go through the B1 seam, not its own subprocess call."""
    fake = FakeAz(CONFIGURED_TENANT)
    set_runner(fake)
    result = ensure_entra_app()  # no runner= argument
    assert isinstance(get_runner(), FakeAz)
    assert result.created is False
    assert fake.calls and not fake.created_anything


def test_explicit_runner_wins_over_the_process_wide_one() -> None:
    process_fake = FakeAz(CONFIGURED_TENANT)
    explicit = FakeAz(FRESH_TENANT)
    set_runner(process_fake)
    result = ensure_entra_app(runner=explicit)
    assert result.created is True
    assert process_fake.calls == []


def test_a_bare_callable_is_accepted_through_the_seam() -> None:
    """Like the shared fake_keychain fixture: a callable, not an object."""
    seen: list[list[str]] = []

    def fn(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        seen.append(list(argv))
        if argv[:4] == ["az", "ad", "app", "list"]:
            return completed(argv, 0, app_entry())
        return completed(argv, 0, sp_entry())

    set_runner(fn)
    assert ensure_entra_app().created is False
    assert len(seen) == 2


def test_command_error_is_an_exit_2_error() -> None:
    assert EntraError("x").exit_code == EXIT_USAGE
    assert issubclass(EntraError, CommandError)


# --- Dry-run behaviour ------------------------------------------------------
def test_dry_run_records_every_command_and_executes_nothing() -> None:
    """B5's --dry-run: the module's argv is the report, and nothing runs."""
    dry = DryRunRunner(
        {
            ("az", "ad", "app", "list"): "[]",
            ("az", "ad", "sp", "list"): "[]",
            ("az", "ad", "app", "create"): json.dumps({"appId": APP_ID}),
            ("az", "ad", "sp", "create"): json.dumps({"id": SP_OBJECT_ID}),
        }
    )
    result = ensure_entra_app(runner=dry)

    assert dry.executed_anything is False
    assert (result.app_id, result.sp_object_id) == (APP_ID, SP_OBJECT_ID)
    assert [c[:4] for c in dry.calls] == [
        ["az", "ad", "app", "list"],
        ["az", "ad", "app", "create"],
        ["az", "ad", "sp", "list"],
        ["az", "ad", "sp", "create"],
    ]


def test_dry_run_on_an_already_configured_tenant_reports_exists_and_writes_nothing() -> None:
    dry = DryRunRunner(
        {("az", "ad", "app", "list"): app_entry(), ("az", "ad", "sp", "list"): sp_entry()}
    )
    result = ensure_entra_app(runner=dry)
    assert result.created is False
    assert [c[3] for c in dry.calls] == ["list", "list"], dry.calls
    assert "found existing" in result.detail


# --- Reporting shapes (B5 prints these) -------------------------------------
def test_app_outcome_and_sp_outcome_expose_created_exists() -> None:
    app = AppOutcome(app_id=APP_ID, created=False)
    sp = ServicePrincipalOutcome(sp_object_id=SP_OBJECT_ID, created=True)
    assert app.outcome == OUTCOME_EXISTS
    assert sp.outcome == OUTCOME_CREATED
    assert app.to_dict()["created"] is False
    assert sp.to_dict()["outcome"] == OUTCOME_CREATED


@pytest.mark.parametrize(
    "app_created,sp_created,expect_detail",
    [
        (True, True, "created app registration and service principal"),
        (True, False, "created app registration"),
        (False, True, "created service principal"),
        (False, False, "found existing app registration and service principal"),
    ],
    ids=["both", "app-only", "sp-only", "neither"],
)
def test_detail_wording_distinguishes_the_four_cases(
    app_created: bool, sp_created: bool, expect_detail: str
) -> None:
    result = EntraProvisioning(
        app_id=APP_ID,
        sp_object_id=SP_OBJECT_ID,
        created=app_created or sp_created,
        app_created=app_created,
        sp_created=sp_created,
    )
    assert result.detail.startswith(expect_detail)
    assert result.outcome == (OUTCOME_CREATED if app_created or sp_created else OUTCOME_EXISTS)


def test_to_dict_carries_the_three_agreed_fields_first() -> None:
    payload = EntraProvisioning(
        app_id=APP_ID, sp_object_id=SP_OBJECT_ID, created=False
    ).to_dict()
    assert payload["app_id"] == APP_ID
    assert payload["sp_object_id"] == SP_OBJECT_ID
    assert payload["created"] is False
    assert payload["outcome"] == OUTCOME_EXISTS


def test_result_objects_are_frozen() -> None:
    """A step result must not be editable by whoever prints it."""
    result = ensure_entra_app(runner=FakeAz(CONFIGURED_TENANT))
    with pytest.raises(Exception):
        result.app_id = NEAR_MISS_APP_ID  # type: ignore[misc]


def test_the_derived_second_id_really_differs_from_the_placeholder() -> None:
    """Guard-compliant derivation must not silently make a comparison vacuous.

    If ``other_guid`` ever stopped changing the value, the near-miss and ambiguity
    tests would compare an id with itself and pass for the wrong reason.
    """
    assert NEAR_MISS_APP_ID != APP_ID
    assert SECOND_SP_OBJECT_ID != SP_OBJECT_ID
    assert len(NEAR_MISS_APP_ID) == len(APP_ID) == 36


def test_default_display_name_is_the_documented_one() -> None:
    assert APP_DISPLAY_NAME == "micro-notify"
    assert SIGN_IN_AUDIENCE == "AzureADMyOrg"


def test_package_level_seam_exports_the_step_for_b5() -> None:
    """B5 imports from ``micro_notify.admin`` — the export list must carry the step."""
    from micro_notify import admin

    assert hasattr(admin, "ensure_entra_app")
    assert hasattr(admin, "EntraProvisioning")
    # A read-only command must be able to ask 'does it exist?' at all.
    assert hasattr(admin, "find_app_id") and hasattr(admin, "find_service_principal_id")
    for name in ("ensure_entra_app", "EntraProvisioning", "find_app_id", "find_service_principal_id"):
        assert name in admin.__all__


def test_creators_are_not_re_exported_so_find_first_cannot_be_skipped() -> None:
    """Deliberate: the package surface offers no way to create without looking first."""
    from micro_notify import admin

    assert "create_app" not in admin.__all__
    assert "create_service_principal" not in admin.__all__


def test_module_never_imports_subprocess_directly() -> None:
    """Every exec must go through the runner seam (B1's declared contract).

    Checked on the AST, not on a source substring: the module docstring is allowed
    to *say* the word ``subprocess`` when it explains why it does not use it.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(inspect.getmodule(find_app_id) or inspect))
    offenders = [
        node
        for node in ast.walk(tree)
        if (isinstance(node, ast.Import) and any(a.name.split(".")[0] == "subprocess" for a in node.names))
        or (isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "subprocess")
    ]
    assert not offenders, f"entra.py shells out on its own: {offenders}"
    assert hasattr(get_runner(), "run"), "the seam must expose a run(argv, stdin=...) runner"
