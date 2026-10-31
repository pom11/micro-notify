"""Tests for :mod:`micro_notify.admin.preflight` (card B1).

Every probe is answered by a fake runner holding canned ``az`` / ``pwsh`` JSON
fixtures — no test here can execute a real ``az``, ``pwsh`` or ``brew``, or reach
the network (``tests/conftest.py`` blocks sockets autouse; the guard below blocks
the binaries). All tenant values are the documented placeholders.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from micro_notify import EXIT_USAGE
from micro_notify.admin import preflight as pf
from micro_notify.admin.preflight import (
    APP_ADMIN_ROLE,
    CHECK_ADMIN_ROLES,
    CHECK_AZ_CLI,
    CHECK_AZ_LOGIN,
    CHECK_EXO_MODULE,
    CHECK_ORDER,
    CHECK_PWSH,
    CHECK_SENDER,
    EXCHANGE_ADMIN_ROLE,
    EXO_MODULE,
    FAIL,
    GLOBAL_ADMIN_ROLE,
    NOT_EVALUATED,
    OK,
    WARN,
    CheckResult,
    PreflightError,
    check_admin_roles,
    check_azure_cli,
    check_azure_signed_in,
    check_exchange_module,
    check_powershell,
    check_sender_mailbox,
    plan_installs,
    run_preflight,
)
from micro_notify.admin.runner import DryRunRunner, set_runner

# --- Placeholders only (design §5, leak guard) -------------------------------
TENANT_ID = "00000000-0000-0000-0000-000000000000"
UPN = "admin@contoso.com"
SENDER = "noreply@example.com"

ACCOUNT_JSON = json.dumps(
    {
        "cloudName": "AzureCloud",
        "homeTenantId": TENANT_ID,
        "id": TENANT_ID,
        "isDefault": True,
        "name": "Contoso (placeholder subscription)",
        "state": "Enabled",
        "tenantId": TENANT_ID,
        "user": {
            "displayName": "Contoso Admin",
            "name": UPN,
            "type": "user",
        },
    }
)
TENANTS_JSON = json.dumps([{"displayName": "contoso.com", "tenantId": TENANT_ID, "countryCode": "US"}])


def member_of(*display_names: str, next_link: str | None = None) -> str:
    payload: dict[str, Any] = {
        "value": [{"odata.type": "#microsoft.graph.group", "displayName": name} for name in display_names]
    }
    if next_link:
        payload["@odata.nextLink"] = next_link
    return json.dumps(payload)


USER_JSON = json.dumps(
    {
        "displayName": "No-Reply Mailbox",
        "id": TENANT_ID,
        "mail": SENDER,
        "userPrincipalName": SENDER,
    }
)


class FakeAdminCli:
    """Answers canned argv prefixes; records every call. Runs nothing.

    Unmatched argv exits 1 with an ``ERROR:`` line, which is what an unexpected
    probe looks like to a real ``az`` — so a check that invents a call fails as a
    missing fixture instead of silently succeeding.
    """

    def __init__(self, responses: dict[tuple[str, ...], str] | None = None) -> None:
        self.responses: dict[tuple[str, ...], str] = dict(responses or {})
        self.returncodes: dict[tuple[str, ...], int] = {}
        self.calls: list[list[str]] = []
        self.stdin_payloads: list[str | None] = []

    # --- configuration ---------------------------------------------------
    def set(self, prefix: tuple[str, ...], stdout: str, returncode: int = 0) -> None:
        self.responses[prefix] = stdout
        self.returncodes[prefix] = returncode

    def remove(self, prefix: tuple[str, ...]) -> None:
        self.responses.pop(prefix, None)
        self.returncodes.pop(prefix, None)

    # --- CommandRunner ---------------------------------------------------
    def run(self, argv: Any, *, stdin: str | None = None) -> subprocess.CompletedProcess:
        args = [str(a) for a in argv]
        self.calls.append(args)
        self.stdin_payloads.append(stdin)
        best: tuple[str, ...] | None = None
        for prefix in self.responses:
            if len(prefix) <= len(args) and tuple(args[: len(prefix)]) == prefix:
                if best is None or len(prefix) > len(best):
                    best = prefix
        if best is None:
            return subprocess.CompletedProcess(args, 1, "", f"ERROR: no fixture for {' '.join(args)}")
        return subprocess.CompletedProcess(
            args,
            self.returncodes.get(best, 0),
            self.responses[best],
            "",
        )

    @property
    def argv_text(self) -> str:
        return "\n".join(" ".join(call) for call in self.calls)


def healthy_cli(*roles: str) -> FakeAdminCli:
    """A machine and tenant that pass every check."""
    cli = FakeAdminCli(
        {
            ("az", "account", "show"): ACCOUNT_JSON,
            ("az", "account", "tenant", "list"): TENANTS_JSON,
            ("az", "rest", "--method", "GET"): member_of(*roles) if roles else member_of(),
            ("az", "ad", "user", "show"): USER_JSON,
            ("pwsh", "-NoProfile"): "3.0.0\n",
        }
    )
    return cli


@pytest.fixture(autouse=True)
def restore_runner() -> Any:
    try:
        yield
    finally:
        set_runner(None)


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Pretend az and pwsh are on PATH, without touching the real PATH lookup.

    Only the lookup is patched — never an execution: a check that decided to
    *run* ``az`` instead of finding it would hit the missing-fixture path below.
    """
    def fake_which(name: str) -> Path | None:
        return Path(f"/opt/homebrew/bin/{name}") if name in {"az", "pwsh"} else None

    monkeypatch.setattr("micro_notify.admin.runner.which", fake_which)
    return fake_which


# The role pairs the requirement accepts, as named in the card.
GLOBAL = (GLOBAL_ADMIN_ROLE,)
APP_PLUS_EXCH = (APP_ADMIN_ROLE, EXCHANGE_ADMIN_ROLE)


# --- The runner seam the whole suite depends on -----------------------------
def test_a_failing_probe_is_returned_as_a_check_not_an_exception(installed: Any) -> None:
    """A tenant that says no is a verdict, not a crash."""
    cli = healthy_cli()
    cli.set(("az", "account", "show"), "", returncode=3)
    result = check_azure_signed_in(runner=cli)
    assert result.status == FAIL
    assert "az login" in result.fix_hint


# --- Check 1: az on PATH ----------------------------------------------------
def test_missing_az_fails_with_the_brew_formula(installed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("micro_notify.admin.runner.which", lambda name: None)
    result = check_azure_cli()
    assert (result.name, result.status) == (CHECK_AZ_CLI, FAIL)
    assert result.fix_hint == "brew install azure-cli"
    assert result.install_hint == "azure-cli"


def test_azure_cli_check_finds_az_on_path(installed: Any) -> None:
    result = check_azure_cli()
    assert result.status == OK
    assert "az" in result.detail
    assert result.install_hint is None


# --- Check 2: signed in, and what gets surfaced -----------------------------
def test_signed_in_surfaces_tenant_id_tenant_name_and_upn(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    result = check_azure_signed_in(runner=cli)
    assert result.status == OK
    assert TENANT_ID in result.detail
    assert "contoso.com" in result.detail  # the directory display name
    assert UPN in result.detail
    assert result.details["tenantId"] == TENANT_ID
    assert result.details["tenantName"] == "contoso.com"
    assert result.details["upn"] == UPN


def test_signed_in_details_drive_the_report_fields(installed: Any) -> None:
    report = run_preflight(SENDER, runner=healthy_cli(*GLOBAL))
    assert report.tenant_id == TENANT_ID
    assert report.tenant_name == "contoso.com"
    assert report.signed_in_upn == UPN


def test_signed_in_probe_asks_az_account_show_only(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    check_azure_signed_in(runner=cli)
    assert ["az", "account", "show"] in cli.calls
    assert "az login" not in cli.argv_text


def test_logged_out_fails_with_the_self_login_hint(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "account", "show"), "", returncode=1)
    result = check_azure_signed_in(runner=cli)
    assert (result.name, result.status) == (CHECK_AZ_LOGIN, FAIL)
    assert "az login" in result.fix_hint
    assert "yourself" in result.fix_hint


def test_a_session_without_a_user_is_not_treated_as_signed_in(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "account", "show"), json.dumps({"tenantId": TENANT_ID}))
    result = check_azure_signed_in(runner=cli)
    assert result.status == FAIL
    assert "az login" in result.fix_hint


def test_tenant_name_lookup_failure_does_not_fail_the_login_check(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "account", "tenant", "list"), "", returncode=1)
    result = check_azure_signed_in(runner=cli)
    assert result.status == OK
    assert result.details["tenantName"] == ""


# --- Check 3: the role matrix ----------------------------------------------
def roles_result(*roles: str) -> CheckResult:
    return check_admin_roles(runner=healthy_cli(*roles))


def test_role_matrix_global_administrator_passes() -> None:
    result = roles_result("Helpdesk Administrator", *GLOBAL)
    assert (result.name, result.status) == (CHECK_ADMIN_ROLES, OK)
    assert GLOBAL_ADMIN_ROLE in result.detail


def test_role_matrix_app_plus_exchange_administrators_pass() -> None:
    result = roles_result("Users", *APP_PLUS_EXCH)
    assert result.status == OK
    assert APP_ADMIN_ROLE in result.detail and EXCHANGE_ADMIN_ROLE in result.detail


def test_role_matrix_app_administrator_only_names_the_missing_exchange_role() -> None:
    result = roles_result("Users", APP_ADMIN_ROLE)
    assert result.status == FAIL
    missing_part = result.detail.split(" — needs ")[0]
    # Only the role it lacks is named as missing; the one it holds is not.
    assert missing_part == f"missing {EXCHANGE_ADMIN_ROLE}"
    assert APP_ADMIN_ROLE not in missing_part


def test_role_matrix_exchange_administrator_only_names_the_missing_app_role() -> None:
    result = roles_result("Users", EXCHANGE_ADMIN_ROLE)
    assert result.status == FAIL
    assert f"missing {APP_ADMIN_ROLE}" in result.detail


def test_role_matrix_neither_role_names_both_missing_roles() -> None:
    result = roles_result("Users", "Search Administrator")
    assert result.status == FAIL
    assert APP_ADMIN_ROLE in result.detail and EXCHANGE_ADMIN_ROLE in result.detail
    assert "missing" in result.detail
    # The operator is told which two shapes of access would satisfy the check.
    assert GLOBAL_ADMIN_ROLE in result.detail
    assert "visible memberships: Users, Search Administrator" in result.detail


def test_role_check_hint_names_the_role_group_the_exchange_step_needs() -> None:
    result = roles_result("Users")
    assert "Organization Management" in result.fix_hint


def test_role_check_reads_member_of_and_never_the_eligibility_apis(installed: Any) -> None:
    """Pin the deliberate probe choice (module docstring, proven live 2026-10-30)."""
    cli = healthy_cli(*GLOBAL)
    check_admin_roles(runner=cli)
    assert ["az", "rest", "--method", "GET", "--uri", pf.GRAPH_MEMBER_OF_URI] in cli.calls
    assert "roleManagement" not in cli.argv_text
    assert "roleEligibility" not in cli.argv_text


def test_role_check_follows_the_membership_next_link(installed: Any) -> None:
    cli = FakeAdminCli(
        {
            ("az", "rest", "--method", "GET"): member_of(
                "Users",
                next_link="https://graph.microsoft.com/v1.0/me/memberOf?$skiptoken=page2",
            )
        }
    )
    # Page 2 is served by the same prefix, so the loop must terminate at the cap
    # rather than fetching forever.
    result = check_admin_roles(runner=cli)
    assert result.status == FAIL
    assert len([c for c in cli.calls if c[:2] == ["az", "rest"]]) == pf.MAX_MEMBER_OF_PAGES
    assert "not visible" in result.detail or "first" in result.detail


def test_role_check_accepts_a_bare_array_response(installed: Any) -> None:
    cli = FakeAdminCli({("az", "rest", "--method", "GET"): json.dumps([{"displayName": GLOBAL_ADMIN_ROLE}])})
    assert check_admin_roles(runner=cli).status == OK


def test_role_check_is_case_insensitive_on_display_names(installed: Any) -> None:
    cli = FakeAdminCli(
        {("az", "rest", "--method", "GET"): member_of("global administrator", "exchange administrator", "application administrator")}
    )
    assert check_admin_roles(runner=cli).status == OK


def test_role_check_fails_when_the_membership_query_is_denied(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "rest", "--method", "GET"), "", returncode=1)
    result = check_admin_roles(runner=cli)
    assert result.status == FAIL
    assert "membership" in result.detail.lower()


# --- Check 4 / 5: PowerShell and the Exchange module ------------------------
def test_missing_pwsh_fails_with_the_brew_formula(installed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("micro_notify.admin.runner.which", lambda name: None if name == "pwsh" else Path("/opt/homebrew/bin/az"))
    result = check_powershell()
    assert (result.name, result.status) == (CHECK_PWSH, FAIL)
    assert result.fix_hint == "brew install powershell"
    assert result.install_hint == "powershell"


def test_exchange_module_probe_asks_pwsh_without_importing(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    check_exchange_module(runner=cli)
    argv = cli.calls[-1]
    assert argv[0] == "pwsh"
    assert "-NoProfile" in argv and "-NonInteractive" in argv
    command = argv[argv.index("-Command") + 1]
    assert f"Get-Module -ListAvailable {EXO_MODULE}" in command
    # Importing the module can prompt for credentials; listing must not import it.
    assert "Import-Module" not in command
    assert "Connect-ExchangeOnline" not in " ".join(argv)


def test_exchange_module_reports_the_installed_version(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("pwsh", "-NoProfile"), "3.0.0\n")
    result = check_exchange_module(runner=cli)
    assert (result.name, result.status) == (CHECK_EXO_MODULE, OK)
    assert "3.0.0" in result.detail


def test_absent_exchange_module_fails_with_the_install_module_hint(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("pwsh", "-NoProfile"), "\n")  # exit 0, no output = not installed
    result = check_exchange_module(runner=cli)
    assert result.status == FAIL
    assert "Install-Module" in result.fix_hint
    assert "-Scope CurrentUser" in result.fix_hint
    assert EXO_MODULE in result.detail


def test_a_pwsh_that_cannot_list_modules_is_reported_not_swallowed(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("pwsh", "-NoProfile"), "", returncode=1)
    result = check_exchange_module(runner=cli)
    assert result.status == FAIL
    assert "exit 1" in result.detail


# --- Check 6: the sender mailbox -------------------------------------------
def test_sender_probe_asks_ad_user_show_for_the_address(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    result = check_sender_mailbox(SENDER, runner=cli)
    assert result.status == OK
    assert ["az", "ad", "user", "show", "--id", SENDER] in cli.calls
    assert SENDER in result.detail
    assert "shared mailbox" in result.detail  # the operator is told that is allowed


def test_sender_that_does_not_resolve_fails_with_the_config_hint(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "ad", "user", "show"), "", returncode=3)
    result = check_sender_mailbox(SENDER, runner=cli)
    assert (result.name, result.status) == (CHECK_SENDER, FAIL)
    assert "--sender" in result.fix_hint
    assert SENDER in result.detail


def test_an_empty_sender_is_a_usage_error_not_a_probe(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    with pytest.raises(PreflightError) as excinfo:
        check_sender_mailbox("   ", runner=cli)
    assert excinfo.value.exit_code == EXIT_USAGE
    assert cli.calls == []


# --- Aggregation ------------------------------------------------------------
def test_healthy_machine_reports_ok_in_check_order(installed: Any) -> None:
    cli = healthy_cli(*APP_PLUS_EXCH)
    report = run_preflight(SENDER, runner=cli)
    assert report.ok is True
    assert tuple(check.name for check in report.checks) == CHECK_ORDER
    assert all(check.status == OK for check in report.checks)
    assert report.failing == ()
    assert report.sender == SENDER


def test_ok_is_false_when_any_single_check_fails(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "ad", "user", "show"), "", returncode=3)
    report = run_preflight(SENDER, runner=cli)
    assert report.ok is False
    assert tuple(check.name for check in report.failing) == (CHECK_SENDER,)


def test_a_warn_alone_does_not_make_the_report_not_ok(installed: Any) -> None:
    """The status vocabulary is exactly ok|fail|warn, and warn is not a failure."""
    report = pf.PreflightReport(
        sender=SENDER,
        checks=(CheckResult("x", WARN, detail="could not verify"),),
    )
    assert report.ok is True
    assert {c.status for c in report.checks} <= {OK, FAIL, WARN}


def test_a_blocked_check_is_warned_and_listed_as_skipped_not_silently_dropped(
    installed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No az -> nothing downstream can be probed, and the report must say so."""
    monkeypatch.setattr("micro_notify.admin.runner.which", lambda name: None)
    cli = healthy_cli(*GLOBAL)
    report = run_preflight(SENDER, runner=cli)
    assert report.ok is False
    names = tuple(check.name for check in report.checks)
    assert names == CHECK_ORDER  # every check is accounted for
    blocked = report.by_name(CHECK_SENDER)
    assert blocked is not None and blocked.status == WARN
    assert NOT_EVALUATED in blocked.detail
    assert CHECK_AZ_CLI in blocked.detail
    # pwsh is a PATH lookup and still gets a real verdict; everything that needed
    # the Azure session is reported as warn + skipped.
    assert report.by_name(CHECK_PWSH).status == FAIL  # type: ignore[union-attr]
    assert set(report.skipped) == {CHECK_AZ_LOGIN, CHECK_ADMIN_ROLES, CHECK_EXO_MODULE, CHECK_SENDER}


def test_a_blocked_login_skips_the_role_and_sender_checks(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "account", "show"), "", returncode=1)
    report = run_preflight(SENDER, runner=cli)
    assert report.ok is False
    assert report.by_name(CHECK_ADMIN_ROLES).status == WARN  # type: ignore[union-attr]
    assert report.by_name(CHECK_SENDER).status == WARN  # type: ignore[union-attr]
    assert CHECK_ADMIN_ROLES in report.skipped and CHECK_SENDER in report.skipped
    # The probes that would have needed the session were never attempted.
    assert "az rest" not in cli.argv_text
    assert "az ad user show" not in cli.argv_text


def test_missing_pwsh_skips_only_the_exchange_module_check(
    installed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "micro_notify.admin.runner.which",
        lambda name: None if name == "pwsh" else Path("/opt/homebrew/bin/az"),
    )
    cli = healthy_cli(*GLOBAL)
    report = run_preflight(SENDER, runner=cli)
    assert report.skipped == (CHECK_EXO_MODULE,)
    assert report.by_name(CHECK_SENDER).status == OK  # type: ignore[union-attr]
    assert "Get-Module" not in cli.argv_text  # the module probe was not attempted


def test_include_exchange_false_stops_at_the_entra_half(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    report = run_preflight(SENDER, runner=cli, include_exchange=False)
    assert tuple(check.name for check in report.checks) == (
        CHECK_AZ_CLI,
        CHECK_AZ_LOGIN,
        CHECK_ADMIN_ROLES,
        CHECK_SENDER,
    )
    assert report.ok is True
    assert "pwsh" not in cli.argv_text


def test_run_preflight_uses_the_process_wide_runner_when_none_passed(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    set_runner(cli)
    report = run_preflight(SENDER)
    assert report.ok is True
    assert cli.calls  # the process-wide fake is what answered


def test_run_preflight_refuses_an_empty_sender_before_any_probe(installed: Any) -> None:
    cli = healthy_cli(*GLOBAL)
    with pytest.raises(PreflightError, match="--sender"):
        run_preflight("", runner=cli)
    assert cli.calls == []


# --- --install-missing plan -------------------------------------------------
def test_plan_installs_names_both_formulas_in_check_order(
    installed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("micro_notify.admin.runner.which", lambda name: None)
    report = run_preflight(SENDER, runner=healthy_cli(*GLOBAL))
    assert plan_installs(report) == ["azure-cli", "powershell"]


def test_plan_installs_is_empty_when_nothing_is_installable(installed: Any) -> None:
    report = run_preflight(SENDER, runner=healthy_cli(*GLOBAL))
    assert plan_installs(report) == []


def test_plan_installs_names_only_the_missing_package(
    installed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("micro_notify.admin.runner.which", lambda name: None if name == "az" else Path("/opt/homebrew/bin/pwsh"))
    report = run_preflight(SENDER, runner=healthy_cli(*GLOBAL))
    assert plan_installs(report) == ["azure-cli"]


def test_plan_installs_never_offers_the_powershell_gallery_module(installed: Any) -> None:
    """brew does not know ExchangeOnlineManagement; B5 must not be handed that name."""
    cli = healthy_cli(*GLOBAL)
    cli.set(("pwsh", "-NoProfile"), "\n")  # module absent
    report = run_preflight(SENDER, runner=cli)
    assert plan_installs(report) == []
    assert report.by_name(CHECK_EXO_MODULE).install_hint is None  # type: ignore[union-attr]
    assert "Install-Module" in report.by_name(CHECK_EXO_MODULE).fix_hint  # type: ignore[union-attr]


def test_plan_installs_deduplicates_repeated_formulae() -> None:
    report = pf.PreflightReport(
        sender=SENDER,
        checks=(
            CheckResult("a", FAIL, install_hint="azure-cli"),
            CheckResult("b", FAIL, install_hint="azure-cli"),
            CheckResult("c", FAIL, install_hint="powershell"),
        ),
    )
    assert plan_installs(report) == ["azure-cli", "powershell"]


def test_plan_installs_ignores_a_warned_check() -> None:
    report = pf.PreflightReport(
        sender=SENDER, checks=(CheckResult("a", WARN, install_hint="azure-cli"),)
    )
    assert plan_installs(report) == []


# --- Dry-run compatibility (B5's --dry-run depends on this here) ------------
def test_run_preflight_against_a_dry_run_runner_spawns_nothing(
    installed: Any,
) -> None:
    """A dry run can drive the whole pre-flight and record instead of execute."""
    dry = DryRunRunner(
        {
            ("az", "account", "show"): ACCOUNT_JSON,
            ("az", "account", "tenant", "list"): TENANTS_JSON,
            ("az", "rest", "--method", "GET"): member_of(*GLOBAL),
            ("az", "ad", "user", "show"): USER_JSON,
            ("pwsh", "-NoProfile"): "3.0.0\n",
        }
    )
    report = run_preflight(SENDER, runner=dry)
    assert dry.calls  # everything was recorded...
    assert dry.executed_anything is False  # ...nothing was executed
    assert tuple(check.name for check in report.checks) == CHECK_ORDER


def test_report_serialisation_carries_the_documented_shape(installed: Any) -> None:
    cli = healthy_cli("Users")
    report = run_preflight(SENDER, runner=cli)
    payload = report.to_dict()
    assert payload["ok"] is False
    assert payload["tenantId"] == TENANT_ID
    assert payload["signedInAs"] == UPN
    assert payload["checks"][0]["name"] == CHECK_AZ_CLI
    role_check = payload["checks"][2]
    assert role_check["status"] == FAIL and role_check["fixHint"]
    assert "installHint" not in role_check
    assert json.dumps(payload)  # the --json surface must be serialisable


def test_check_result_to_dict_includes_install_hint_only_when_present() -> None:
    installable = CheckResult(CHECK_AZ_CLI, FAIL, install_hint="azure-cli").to_dict()
    assert installable["installHint"] == "azure-cli"
    assert "installHint" not in CheckResult(CHECK_PWSH, OK).to_dict()


# --- Safety properties ------------------------------------------------------
def test_no_pre_flight_probe_ever_runs_az_login_or_connects_to_exchange(
    installed: Any,
) -> None:
    """The checks read state; an interactive sign-in is always the operator's job."""
    cli = healthy_cli("Users")
    run_preflight(SENDER, runner=cli)
    text = cli.argv_text
    assert "az login" not in text
    assert "Connect-ExchangeOnline" not in text
    assert "brew install" not in text  # installs are B5's, after a y/N prompt


def test_a_probe_that_would_return_a_token_leaves_it_in_the_fixture(installed: Any) -> None:
    """Nothing here echoes a credential-looking value into a detail line."""
    cli = healthy_cli(*GLOBAL)
    cli.set(("az", "account", "show"), json.dumps({"accessToken": "eyJhbGciOi.s3cr3t"}))
    report = run_preflight(SENDER, runner=cli)
    assert report.by_name(CHECK_AZ_LOGIN).status == FAIL  # type: ignore[union-attr]
    assert "s3cr3t" not in json.dumps(report.to_dict())
