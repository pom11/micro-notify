"""Tests for :mod:`micro_notify.commands.admin` (card B5).

Everything runs through fake runners plus the shared ``fake_keychain``: no test can
execute a real ``az``, ``pwsh``, ``brew`` or ``openssl`` (the autouse tripwire below
turns the real subprocess layer into a failure), and sockets stay blocked by the
untouched ``tests/conftest.py``. All tenant values are the documented placeholders.

What the card pins, and where it is pinned:

* step ORDER — the az/pwsh argv an operator would see, plus the ``steps`` array of
  the ``--json`` summary, both asserted in run order;
* the empty-allowlist refusal — exit 2, before any probe, with a fix hint;
* ``--dry-run`` executes nothing yet prints every command, and exits 0;
* the ``--json`` summary shape (``ok`` + ``steps:[{name, outcome, detail}]``);
* the idempotent re-run — every step ``exists`` and exit 0;
* the ``--install-missing`` y/N gate — auto-refused on ``n``, refused outright with no
  terminal, and ``brew`` never reached in either case.

The certificate step is driven down its *exists* path (keychain pair whose thumbprint
is already uploaded). Its create path spawns ``openssl`` through certgen's own seam,
which this card must not reach: card B3 owns that, and ``FORBIDDEN_BINARIES`` below
makes reaching it a test failure rather than a slow test.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from micro_notify import EXIT_OK, EXIT_USAGE, cli
from micro_notify.admin import exo as exo_module
from micro_notify.admin import runner as admin_runner
from micro_notify.commands import admin as admin_cmd
from micro_notify.config import (
    AUTH_CERTIFICATE,
    AllowConfig,
    Config,
    LimitsConfig,
    MailConfig,
    PathsConfig,
    TeamTarget,
    write_config,
)
from micro_notify.secrets import ACCOUNT_CERT_PEM, ACCOUNT_CERT_THUMBPRINT

# --- Placeholders only (design §5, leak guard) --------------------------------
APP_ID = "00000000-0000-0000-0000-000000000000"
SP_OBJECT_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
SENDER = "noreply@example.com"
ADMIN_UPN = "admin@contoso.com"
DOMAIN = "example.com"
SCOPE = "mnotify-noreply"
THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD"
TENANT_ID = "00000000-0000-0000-0000-000000000000"
DEVICE_CODE_LINE = (
    "To sign in, use a web browser to open the page https://example.com/devicelogin "
    "and enter the code WXYZ123 to authenticate."
)

FORBIDDEN_BINARIES = frozenset({"az", "pwsh", "brew", "powershell", "security", "openssl"})

BOOTSTRAP = ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN]


# --- Guards ------------------------------------------------------------------
@pytest.fixture(autouse=True)
def restore_process_runner() -> Any:
    """No test leaks its fake runner (or a dry run's) into the next one."""
    try:
        yield
    finally:
        admin_cmd.set_runner(None)


@pytest.fixture(autouse=True)
def no_real_admin_binaries(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Tripwire: the real subprocess layer must never be asked for az/pwsh/brew/etc."""
    real_run = subprocess.run

    def guarded(args: Any, **kwargs: Any) -> Any:
        argv = [str(a) for a in (args if isinstance(args, (list, tuple)) else [args])]
        if argv and Path(argv[0]).name in FORBIDDEN_BINARIES:
            raise AssertionError(f"test attempted to execute {argv[0]!r}")
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded)


# The operator's own config file. Referenced only to prove this test module never
# writes it — never read, never printed, never used as a target.
OPERATOR_CONFIG = Path("~/.config/mnotify/config.toml").expanduser()


def _config_stamp() -> tuple[bool, float | None]:
    """(exists, mtime) of the operator's config. A stamp, not a read: the bytes
    contain the operator's real tenant id and sender, which must not enter output."""
    try:
        return True, OPERATOR_CONFIG.stat().st_mtime_ns
    except FileNotFoundError:
        return False, None


@pytest.fixture(autouse=True)
def real_config_is_never_touched(
    isolated_config: Path, tmp_path: Path
) -> Any:
    """Tripwire: no test in this module may write the operator's config file.

    Why this exists rather than merely the fixture above: the bootstrap's config step
    calls the real ``write_config``, and it *preserves* ``[paths]``, the Teams targets
    and ``[limits]`` from whatever file is there. So a run that reaches that step with
    ``MICRO_NOTIFY_CONFIG`` unset produces a file that looks almost right — the
    operator's own paths and targets, with placeholder ``[mail]`` and ``[allow]`` on
    top of them. That is the worst possible shape to notice: the config still parses,
    ``doctor`` still passes ``config``, and the first real send fails with an AADSTS
    error naming a tenant the operator never typed. It has already happened to this
    machine once (see the card comment); an opt-in fixture is not a guard against it.

    Checks both directions at teardown: the env var must point under ``tmp_path``, and
    the operator's file must be exactly as it was (absent, or the same mtime).
    """
    before = _config_stamp()
    yield
    target = os.environ.get("MICRO_NOTIFY_CONFIG")
    assert target, (
        "MICRO_NOTIFY_CONFIG was unset at teardown: a test reached the config step "
        "with the default path in effect, i.e. it could have written the operator's file"
    )
    assert Path(target).resolve().is_relative_to(tmp_path.resolve()), (
        f"MICRO_NOTIFY_CONFIG points outside tmp_path: {target}"
    )
    assert _config_stamp() == before, (
        "this test module modified the operator's real config file — the isolation "
        "fixture did not hold, and the file now holds placeholder [mail] values"
    )


@pytest.fixture(autouse=True)
def tools_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """``az`` and ``pwsh`` are installed, as a lookup (never an execution)."""
    monkeypatch.setattr(
        "micro_notify.admin.runner.which",
        lambda name: Path("/opt/homebrew/bin") / name,
    )


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``MICRO_NOTIFY_CONFIG`` at a path under tmp_path, with no file there yet.

    No test may write the operator's real ``~/.config/mnotify/config.toml``, and no
    test should inherit a config from a previous one. The path exists as a *target*:
    ``write_config`` creates the parent directory (mode 0700) itself. Tests that need an
    existing file write one into ``tmp_path`` and repoint the variable.
    """
    path = tmp_path / "config" / "config.toml"
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(path))
    return path


# --- Canned answers ----------------------------------------------------------
def authz_row(in_scope: str, scope: str = SCOPE) -> dict:
    return {
        "RoleName": "Application Mail.Send",
        "Scope": scope,
        "ScopeType": "CustomRecipientScope",
        "InScope": in_scope,
    }


def pwsh_transcript(created: bool = False) -> str:
    """A full, verifiable ``MNOTIFY:`` transcript for one Exchange run.

    Built the way B4's script emits it: the device-code line, then one machine event
    per step, then the two authorization controls, then the disconnect and summary.
    ``created=False`` makes every step report ``exists`` with a non-zero found count —
    the transcript a configured tenant produces.
    """
    outcome = "created" if created else "exists"
    found = 0 if created else 1

    def event(**payload: Any) -> str:
        return "MNOTIFY:" + json.dumps(payload, separators=(",", ":"))

    lines = [
        "mnotify: connecting to Exchange Online (device-code sign-in).",
        DEVICE_CODE_LINE,
        event(event="connected"),
        event(event="service_principal", outcome=outcome, found=found),
        event(event="management_scope", outcome=outcome, found=found),
        event(event="role_assignment", outcome=outcome, found=found),
        event(
            event="authz",
            control="sender",
            resource=SENDER,
            rows=[authz_row("True")],
        ),
        event(
            event="authz",
            control="admin",
            resource=ADMIN_UPN,
            rows=[authz_row("False")],
        ),
        event(event="disconnected"),
        event(event="summary", ok=True),
    ]
    return "\n".join(lines)


def account_json(upn: str = ADMIN_UPN) -> str:
    return json.dumps(
        {
            "tenantId": TENANT_ID,
            "id": TENANT_ID,
            "name": "Contoso (placeholder subscription)",
            "user": {"name": upn, "displayName": "Contoso Admin", "type": "user"},
        }
    )


def app_list_json(*, present: bool) -> str:
    if not present:
        return "[]"
    return json.dumps([{"displayName": "micro-notify", "appId": APP_ID}])


def sp_list_json(*, present: bool) -> str:
    if not present:
        return "[]"
    return json.dumps([{"appId": APP_ID, "id": SP_OBJECT_ID}])


def credential_list_json(*, present: bool) -> str:
    if not present:
        return "[]"
    return json.dumps([{"customKeyIdentifier": THUMBPRINT, "endDateTime": "2099-01-01T00:00:00Z"}])


class FakeAdminCli:
    """Answers canned argv prefixes; records every call. Executes nothing.

    An unmatched argv exits 1 with an ``ERROR:`` line, which is what an unexpected
    probe looks like to a real ``az`` — so a step that invents a call fails as a
    missing fixture instead of silently passing.
    """

    def __init__(self, responses: dict[tuple[str, ...], str] | None = None) -> None:
        self.responses: dict[tuple[str, ...], str] = dict(responses or {})
        self.returncodes: dict[tuple[str, ...], int] = {}
        self.calls: list[list[str]] = []

    def set(self, prefix: tuple[str, ...], stdout: str, returncode: int = 0) -> None:
        self.responses[prefix] = stdout
        self.returncodes[prefix] = returncode

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        self.calls.append(args)
        best: tuple[str, ...] | None = None
        for prefix in self.responses:
            if len(prefix) > len(args) or tuple(args[: len(prefix)]) != prefix:
                continue
            if best is None or len(prefix) > len(best):
                best = prefix
        if best is None:
            return subprocess.CompletedProcess(
                args, 1, "", f"ERROR: no fixture for {' '.join(args)}"
            )
        return subprocess.CompletedProcess(
            args, self.returncodes.get(best, 0), self.responses[best], ""
        )

    # --- assertions helpers ------------------------------------------------
    @property
    def joined(self) -> list[str]:
        return [" ".join(call) for call in self.calls]

    def prefixes(self) -> list[tuple[str, ...]]:
        """Each call reduced to a recognisable command name (up to 6 tokens)."""
        return [tuple(call[:6]) for call in self.calls]

    def matching(self, needle: str) -> list[str]:
        return [line for line in self.joined if needle in line]

    def executed(self) -> bool:
        return bool(self.calls)


def healthy_responses(*, configured: bool = True) -> dict[tuple[str, ...], str]:
    """Every answer a configured tenant gives, so the flow reaches every step."""
    return {
        ("az", "account", "show"): account_json(),
        ("az", "account", "tenant", "list"): json.dumps(
            [{"tenantId": TENANT_ID, "displayName": "contoso.com"}]
        ),
        ("az", "rest", "--method"): json.dumps(
            {"value": [{"displayName": "Global Administrator"}]}
        ),
        ("az", "ad", "user", "show"): json.dumps(
            {"userPrincipalName": SENDER, "id": TENANT_ID, "displayName": "No-Reply"}
        ),
        ("pwsh", "-NoProfile", "-NonInteractive", "-Command"): "3.11.0\n",
        ("az", "ad", "app", "list"): app_list_json(present=configured),
        ("az", "ad", "sp", "list"): sp_list_json(present=configured),
        ("az", "ad", "app", "create"): json.dumps({"appId": APP_ID}),
        ("az", "ad", "sp", "create"): json.dumps({"id": SP_OBJECT_ID}),
        ("az", "ad", "app", "credential", "list"): credential_list_json(present=configured),
        ("pwsh", "-NoProfile", "-NonInteractive", "-File"): pwsh_transcript(
            created=not configured
        ),
    }


@pytest.fixture
def fake_cli(monkeypatch: pytest.MonkeyPatch) -> FakeAdminCli:
    """A healthy, already-configured tenant behind the runner seam."""
    fake = FakeAdminCli(healthy_responses(configured=True))
    admin_cmd.set_runner(fake)
    return fake


@pytest.fixture
def keychain_with_certificate(fake_keychain: Any) -> Any:
    """The keychain holds the pair whose certificate is already uploaded."""
    fake_keychain.seed(ACCOUNT_CERT_PEM, "placeholder-private-material-not-a-real-key")
    fake_keychain.seed(ACCOUNT_CERT_THUMBPRINT, THUMBPRINT)
    return fake_keychain


@pytest.fixture
def quiet_doctor(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Stub ``doctor.run`` so a step-order test does not need msal; records its call."""
    calls: list[dict] = []

    def fake_run(args: argparse.Namespace) -> int:
        calls.append({"send_test": getattr(args, "send_test", None), "json": args.json})
        return EXIT_OK

    monkeypatch.setattr("micro_notify.commands.doctor.run", fake_run)
    return calls


def run_admin(*argv: str) -> int:
    return cli.main(["admin", *argv])


def parse_summary(capsys: pytest.CaptureFixture[str]) -> dict:
    """The one JSON document stdout must hold under ``--json``."""
    out = capsys.readouterr().out
    return json.loads(out)


# ===========================================================================
# Registration and surface (append-only wiring)
# ===========================================================================
def test_admin_is_a_registered_command_module() -> None:
    from micro_notify.commands import COMMAND_MODULES

    assert admin_cmd.NAME == "admin"
    assert admin_cmd in COMMAND_MODULES
    assert cli.DISPATCH["admin"] is admin_cmd.run


def test_bootstrap_flags_all_parse() -> None:
    args = cli.build_parser().parse_args(
        [
            "admin",
            "bootstrap",
            "--sender",
            SENDER,
            "--allow-domain",
            DOMAIN,
            "--allow-domain",
            "contoso.com",
            "--install-missing",
            "--dry-run",
            "--json",
            "--send-test",
            "person@contoso.com",
            "--control-mailbox",
            ADMIN_UPN,
            "--force-config",
        ]
    )
    assert args.command == "admin" and args.admin_command == "bootstrap"
    assert args.sender == SENDER
    assert args.allow_domain == [DOMAIN, "contoso.com"]
    assert args.install_missing and args.dry_run and args.json
    assert args.send_test == "person@contoso.com"
    assert args.control_mailbox == ADMIN_UPN


def test_sender_is_required() -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args(["admin", "bootstrap"])
    assert excinfo.value.code == EXIT_USAGE


def test_admin_without_an_action_is_a_usage_error(capsys) -> None:
    assert run_admin() == EXIT_USAGE
    assert "admin action is required" in capsys.readouterr().err


def test_an_unknown_admin_action_is_refused_by_the_parser() -> None:
    """argparse owns an unknown subcommand: exit 2, before this module runs."""
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["admin", "teardown"])
    assert excinfo.value.code == EXIT_USAGE


# ===========================================================================
# Step order
# ===========================================================================
def test_the_steps_run_in_the_declared_order(
    fake_cli: FakeAdminCli, keychain_with_certificate: Any, quiet_doctor: list[dict]
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK

    # The pre-flight probes come first, then the Entra reads, then the credential
    # read, then pwsh — i.e. B1 -> B2 -> B3 -> B4 -> config -> doctor.
    order = fake_cli.prefixes()
    first = next(i for i, p in enumerate(order) if p[:2] == ("az", "account"))
    app_list = next(i for i, p in enumerate(order) if p[:4] == ("az", "ad", "app", "list"))
    sp_list = next(i for i, p in enumerate(order) if p[:4] == ("az", "ad", "sp", "list"))
    creds = next(i for i, p in enumerate(order) if p[:5] == ("az", "ad", "app", "credential", "list"))
    script = next(i for i, p in enumerate(order) if p[:4] == ("pwsh", "-NoProfile", "-NonInteractive", "-File"))
    assert first < app_list < sp_list < creds < script
    assert order[0][:1] == ("az",) or order[0][:1] == ("pwsh",)
    assert quiet_doctor, "doctor never ran"


def test_the_json_steps_are_in_run_order(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    summary = parse_summary(capsys)
    assert [step["name"] for step in summary["steps"]] == [
        admin_cmd.STEP_PREFLIGHT,
        admin_cmd.STEP_ENTRA,
        admin_cmd.STEP_CERTIFICATE,
        admin_cmd.STEP_EXCHANGE,
        admin_cmd.STEP_CONFIG,
        admin_cmd.STEP_DOCTOR,
    ]


def test_the_config_is_written_only_after_the_exchange_proof(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
) -> None:
    """A config for an unproven grant would advertise a capability the tenant lacks.

    Runs against the autouse ``isolated_config`` (no file yet) so the config step
    genuinely *writes*: with a config that already matches, the idempotent path
    reports ``exists`` and writes nothing, and this test would be asserting on an
    empty list for the wrong reason.
    """
    written_at: list[int] = []
    real_write = admin_cmd.write_config

    def spy(config: Config, path: Any = None) -> Path:
        written_at.append(len(fake_cli.calls))
        return real_write(config, path)

    admin_cmd.write_config = spy  # type: ignore[assignment]
    try:
        assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK
    finally:
        admin_cmd.write_config = real_write  # type: ignore[assignment]

    script = max(
        i for i, call in enumerate(fake_cli.calls) if call[:4] == ["pwsh", "-NoProfile", "-NonInteractive", "-File"]
    )
    assert written_at and written_at[0] > script


def test_a_failed_exchange_proof_never_writes_the_config(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B4 fails closed; the bootstrap must not advertise a scope it could not prove."""

    def refuse(*_a: Any, **_kw: Any) -> Any:
        from micro_notify.admin.exo import ExchangeError

        raise ExchangeError("the scope could not be proven")

    monkeypatch.setattr("micro_notify.admin.exo.ensure_exchange_scope", refuse)
    written: list[Any] = []
    monkeypatch.setattr(admin_cmd, "write_config", lambda *_a, **_k: written.append(1))

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_USAGE
    assert written == []


def test_a_failing_preflight_provisions_nothing(
    keychain_with_certificate: Any, quiet_doctor: list[dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No `az` session -> exit 2, and not one write command attempted."""
    fake = FakeAdminCli(healthy_responses())
    fake.set(("az", "account", "show"), "", returncode=1)
    admin_cmd.set_runner(fake)

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_USAGE
    assert not fake.matching("app create")
    assert not fake.matching("sp create")
    assert not fake.matching("credential reset")


# ===========================================================================
# The empty-allowlist refusal
# ===========================================================================
def test_an_empty_allowlist_is_refused_before_any_probe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, and refused *first*: the tenant must not be mutated for a config that
    refuses every send."""
    fake = FakeAdminCli(healthy_responses())
    admin_cmd.set_runner(fake)
    monkeypatch.setattr(
        admin_cmd,
        "write_config",
        lambda *_a, **_k: pytest.fail("the config must not be written"),
    )

    assert run_admin("bootstrap", "--sender", SENDER) == EXIT_USAGE

    err = capsys.readouterr().err
    assert "allowlist" in err and "example.com" in err
    assert not fake.executed(), f"a probe ran before the refusal: {fake.joined}"


def test_the_empty_allowlist_refusal_ignores_a_falsy_but_present_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--allow-domain ""`` is still an empty allowlist -> the same exit 2."""
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", "") == EXIT_USAGE
    assert "allow-domain" in capsys.readouterr().err


def test_a_malformed_sender_is_exit_2_without_probing(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_admin("bootstrap", "--sender", "not-an-address", "--allow-domain", DOMAIN) == EXIT_USAGE
    assert "--sender" in capsys.readouterr().err


def test_a_malformed_allow_domain_is_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", "user@example.com") == EXIT_USAGE
    assert "bare domain" in capsys.readouterr().err


def test_the_control_mailbox_must_differ_from_the_sender(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B4's negative control is the whole point of the scope proof."""
    code = run_admin(
        "bootstrap",
        "--sender",
        SENDER,
        "--allow-domain",
        DOMAIN,
        "--control-mailbox",
        SENDER,
    )
    assert code == EXIT_USAGE
    assert "negative control" in capsys.readouterr().err
    assert not fake_cli.matching("-File"), "the Exchange step ran without a usable control"


def test_the_signed_in_upn_is_the_default_control_mailbox(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    summary = parse_summary(capsys)
    assert summary["controlMailbox"] == ADMIN_UPN
    script_line = fake_cli.matching("-File")
    assert script_line, "the Exchange script was never run"


# ===========================================================================
# --dry-run
# ===========================================================================
def test_dry_run_executes_nothing_yet_prints_every_command(
    keychain_with_certificate: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The card's acceptance criterion for the dry run, in both directions."""
    recorder = admin_cmd.DryRunRunner(admin_cmd.DRY_RUN_RESPONSES)
    admin_cmd.set_runner(recorder)
    monkeypatch.setattr(admin_cmd, "set_runner", lambda runner=None: None)  # already installed
    monkeypatch.setattr(admin_cmd, "write_config", lambda *_a, **_k: pytest.fail("dry run wrote a config"))

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run") == EXIT_OK
    out = capsys.readouterr().out

    assert recorder.executed_anything is False
    assert recorder.calls, "the dry run recorded no commands at all"

    lines = out.splitlines()
    # Every recorded argv is printed, one per line.
    for call in recorder.calls:
        assert " ".join(call) in lines, f"not printed: {' '.join(call)}"
    # The command shapes the operator needs to see before approving a real run.
    joined = "\n".join(lines)
    for needle in (
        "az account show",
        "az ad app list --display-name micro-notify",
        "az ad app create",
        "az ad sp create",
        "az ad app credential reset",
        "--end-date",
        "--append",
        "pwsh -NoProfile -NonInteractive -File",
        "New-ManagementRoleAssignment",
        "Test-ServicePrincipalAuthorization",
    ):
        assert needle in joined, f"missing from the plan: {needle}"
    assert "brew install" not in joined, "brew is not part of a plain dry run"


def test_dry_run_executes_nothing_at_the_binary_level(
    keychain_with_certificate: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The tripwire fixture makes this an assertion failure if anything spawns."""
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run") == EXIT_OK
    )
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run", "--json") == EXIT_OK


def test_dry_run_reports_every_step_as_dryrun(
    keychain_with_certificate: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        run_admin(
            "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run", "--json"
        )
        == EXIT_OK
    )
    summary = parse_summary(capsys)
    assert summary["ok"] is True and summary["dryRun"] is True
    outcomes = {step["name"]: step["outcome"] for step in summary["steps"]}
    assert outcomes[admin_cmd.STEP_PREFLIGHT] == admin_cmd.OUTCOME_DRYRUN
    assert outcomes[admin_cmd.STEP_ENTRA] == admin_cmd.OUTCOME_DRYRUN
    assert outcomes[admin_cmd.STEP_CERTIFICATE] == admin_cmd.OUTCOME_DRYRUN
    assert outcomes[admin_cmd.STEP_EXCHANGE] == admin_cmd.OUTCOME_DRYRUN
    assert outcomes[admin_cmd.STEP_CONFIG] == admin_cmd.OUTCOME_DRYRUN
    assert outcomes[admin_cmd.STEP_DOCTOR] == admin_cmd.OUTCOME_SKIPPED


def test_dry_run_never_generates_a_key_or_writes_the_keychain(
    keychain_with_certificate: Any,
    fake_keychain: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B3 refuses a recording runner on its write path; the dry run must respect that."""
    writes: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "micro_notify.admin.certupload.secrets.set_secret",
        lambda account, value, **kw: writes.append((account, value)),
    )
    monkeypatch.setattr(
        "micro_notify.admin.certupload.certgen.generate_certificate",
        lambda **kw: pytest.fail("a dry run must not generate a key pair"),
    )
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run") == EXIT_OK
    )
    assert writes == []
    assert fake_keychain.security_binaries_invoked == []


def test_dry_run_plans_the_install_command_when_offered(
    keychain_with_certificate: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        run_admin(
            "bootstrap",
            "--sender",
            SENDER,
            "--allow-domain",
            DOMAIN,
            "--dry-run",
            "--install-missing",
        )
        == EXIT_OK
    )
    joined = "\n".join(capsys.readouterr().out.splitlines())
    assert "brew install <formula>" in joined


# ===========================================================================
# --json summary shape
# ===========================================================================
def test_the_json_summary_has_the_declared_shape(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    summary = parse_summary(capsys)  # raises if stdout is not exactly one document
    assert isinstance(summary["ok"], bool)
    assert isinstance(summary["steps"], list) and summary["steps"]
    for step in summary["steps"]:
        assert set(step) <= {"name", "outcome", "detail"}
        assert isinstance(step["name"], str) and isinstance(step["outcome"], str)
        allowed = {
            admin_cmd.OUTCOME_CREATED,
            admin_cmd.OUTCOME_EXISTS,
            admin_cmd.OUTCOME_DRYRUN,
            admin_cmd.OUTCOME_SKIPPED,
        }
        assert step["outcome"] in allowed, step
    assert summary["appId"] == APP_ID
    assert summary["spObjectId"] == SP_OBJECT_ID
    assert summary["scopeName"] == SCOPE
    assert summary["tenantId"] == TENANT_ID
    assert summary["allowDomains"] == [DOMAIN]


def test_the_json_summary_says_exists_created_for_the_run_that_made_objects(
    monkeypatch: pytest.MonkeyPatch,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A fresh tenant: the Entra step creates, and says so (B2's own vocabulary)."""
    fake = FakeAdminCli(healthy_responses(configured=False))
    fake.set(
        ("az", "ad", "app", "credential", "list"),
        credential_list_json(present=True),  # the pair is already on the app
    )
    admin_cmd.set_runner(fake)

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    outcomes = {step["name"]: step["outcome"] for step in parse_summary(capsys)["steps"]}
    assert outcomes[admin_cmd.STEP_ENTRA] == admin_cmd.OUTCOME_CREATED


def test_json_mode_keeps_stdout_to_one_document(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The device-code line and doctor's report must not corrupt the document."""
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    captured = capsys.readouterr()
    json.loads(captured.out)  # one parseable document
    assert DEVICE_CODE_LINE.split(" ")[0] in captured.err or "device-code" in captured.err


def test_doctor_output_is_not_printed_on_stdout_in_json_mode(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Doctor owns its own printing; under our --json it lands on stderr."""

    def chatty(_args: argparse.Namespace) -> int:
        print("config: pass — this line must not be in the summary")
        return EXIT_OK

    monkeypatch.setattr("micro_notify.commands.doctor.run", chatty)
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert "this line must not be in the summary" in captured.err
    assert summary["ok"] is True


def test_a_failing_doctor_drives_the_exit_code_and_ok(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from micro_notify import EXIT_GUARD

    monkeypatch.setattr("micro_notify.commands.doctor.run", lambda _a: EXIT_GUARD)
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_GUARD
    summary = parse_summary(capsys)
    assert summary["ok"] is False and summary["exitCode"] == EXIT_GUARD
    doctor = next(s for s in summary["steps"] if s["name"] == admin_cmd.STEP_DOCTOR)
    assert doctor["outcome"] == admin_cmd.OUTCOME_SKIPPED


# ===========================================================================
# Idempotent re-run (the acceptance criterion)
# ===========================================================================
def test_a_re_run_on_a_configured_tenant_reports_exists_everywhere_and_exits_0(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The card's acceptance criterion: run it twice; the second run is a no-op.

    First run writes the config, so the second run sees a tenant *and* a machine that
    already say everything this command would say — every step must answer ``exists``
    and the exit code must be 0.
    """
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    first = parse_summary(capsys)
    assert first["ok"] is True
    assert next(s for s in first["steps"] if s["name"] == admin_cmd.STEP_CONFIG)["outcome"] == (
        admin_cmd.OUTCOME_CREATED
    )

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    second = parse_summary(capsys)
    assert second["ok"] is True
    for step in second["steps"]:
        assert step["outcome"] == admin_cmd.OUTCOME_EXISTS, step
    # The re-run read the tenant but wrote nothing to it.
    assert not fake_cli.matching("app create")
    assert not fake_cli.matching("sp create")
    assert not fake_cli.matching("credential reset")


def test_a_re_run_does_not_rewrite_a_config_that_already_matches(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    isolated_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`exists` for the config step means *no bytes written*, not a rewrite."""
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK
    calls: list[Any] = []
    monkeypatch.setattr(
        admin_cmd, "write_config", lambda *_a, **_k: calls.append(1) or isolated_config
    )
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK
    assert calls == []


def test_a_differing_existing_config_is_refused_without_force(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Someone chose that sender; a re-verify run must not quietly replace it."""
    existing = Config(
        mail=MailConfig(
            tenant_id=TENANT_ID, client_id=APP_ID, sender="ops@example.com",
            auth=AUTH_CERTIFICATE,
        ),
        allow=AllowConfig(domains=(DOMAIN,)),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "audit.jsonl", state_dir=tmp_path / "state"),
    )
    path = tmp_path / "other-config.toml"
    write_config(existing, path)
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(path))

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_USAGE
    assert "--force-config" in capsys.readouterr().err
    assert "ops@example.com" in path.read_text(encoding="utf-8")


def test_force_config_overwrites_a_differing_file(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = Config(
        mail=MailConfig(
            tenant_id=TENANT_ID, client_id=APP_ID, sender="ops@example.com",
            auth=AUTH_CERTIFICATE,
        ),
        allow=AllowConfig(domains=(DOMAIN,)),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "audit.jsonl", state_dir=tmp_path / "state"),
    )
    path = tmp_path / "other-config.toml"
    write_config(existing, path)
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(path))

    assert (
        run_admin(
            "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--force-config"
        )
        == EXIT_OK
    )
    assert f'sender = "{SENDER}"' in path.read_text(encoding="utf-8")


def test_a_re_run_creates_no_objects_and_regenerates_no_key(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    fake_keychain: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "micro_notify.admin.certupload.certgen.generate_certificate",
        lambda **kw: pytest.fail("a re-run must not generate a key pair"),
    )
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK
    assert fake_keychain.security_binaries_invoked == []


def test_a_second_run_reports_the_same_ids_as_the_first(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    first = parse_summary(capsys)
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    second = parse_summary(capsys)
    assert (first["appId"], first["spObjectId"], first["scopeName"]) == (
        second["appId"],
        second["spObjectId"],
        second["scopeName"],
    )


def test_an_existing_secret_auth_config_is_not_read_as_matching(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`auth = "secret"` is not this command's end state, so it is not "unchanged".

    Without the auth term in the match, a config left over from `mnotify setup --auth
    secret` would be reported `exists` and left alone after a run that had just
    uploaded a certificate — the file would keep pointing at a client secret while the
    summary claimed the certificate credential was in place. The mismatch has to
    surface as the same refusal any other differing [mail] gets.
    """
    existing = Config(
        mail=MailConfig(
            tenant_id=TENANT_ID, client_id=APP_ID, sender=SENDER, auth="secret",
        ),
        allow=AllowConfig(domains=(DOMAIN,)),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "audit.jsonl", state_dir=tmp_path / "state"),
    )
    path = tmp_path / "secret-auth-config.toml"
    write_config(existing, path)
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(path))

    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_USAGE
    assert "--force-config" in capsys.readouterr().err
    assert 'auth = "secret"' in path.read_text(encoding="utf-8")


def test_force_config_switches_a_secret_auth_config_to_certificate(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half: with the flag, the file ends up on the certificate path."""
    existing = Config(
        mail=MailConfig(
            tenant_id=TENANT_ID, client_id=APP_ID, sender=SENDER, auth="secret",
        ),
        allow=AllowConfig(domains=(DOMAIN,)),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "audit.jsonl", state_dir=tmp_path / "state"),
    )
    path = tmp_path / "secret-auth-config.toml"
    write_config(existing, path)
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(path))

    assert (
        run_admin(
            "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--force-config"
        )
        == EXIT_OK
    )
    text = path.read_text(encoding="utf-8")
    assert 'auth = "certificate"' in text and 'auth = "secret"' not in text


# ===========================================================================
# --install-missing gate
# ===========================================================================
class Stdin:
    """A stdin stand-in with the two attributes the gate reads."""

    def __init__(self, answer: str | None) -> None:
        self.answer = answer

    def isatty(self) -> bool:
        return self.answer is not None

    def readline(self) -> str:
        return "" if self.answer is None else self.answer + "\n"


@pytest.fixture
def az_missing(monkeypatch: pytest.MonkeyPatch) -> FakeAdminCli:
    """A machine with no ``az`` on PATH: the pre-flight fails with a brew formula."""
    monkeypatch.setattr(
        "micro_notify.admin.runner.which",
        lambda name: None if name == "az" else Path("/opt/homebrew/bin") / name,
    )
    fake = FakeAdminCli(healthy_responses())
    admin_cmd.set_runner(fake)
    return fake


def test_install_missing_without_a_terminal_is_refused(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No prompt possible -> exit 2 naming the flag, and brew never runs."""
    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: False)
    monkeypatch.setattr(sys, "stdin", Stdin(None))

    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    assert "terminal" in capsys.readouterr().err
    assert not az_missing.matching("brew install"), az_missing.joined


def test_answering_no_skips_the_install_and_provisions_nothing(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(sys, "stdin", Stdin("n"))

    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    err = capsys.readouterr().err
    assert "install declined" in err
    assert not az_missing.matching("brew install"), az_missing.joined
    assert not az_missing.matching("app create")


def test_answering_yes_runs_brew_for_the_formula_b1_named(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``y`` installs *azure-cli* (B1's formula name), not a re-invented one."""
    az_missing.set(("brew", "install"), "", returncode=0)
    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(sys, "stdin", Stdin("y"))

    # Still exit 2: `az` is still missing after the install (the lookup is patched),
    # which is exactly what the second pre-flight reports. What matters is that brew ran.
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    assert ["brew", "install", "azure-cli"] in az_missing.calls


def test_an_empty_answer_is_a_no(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(sys, "stdin", Stdin(""))
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    assert not az_missing.matching("brew install")


def test_a_closed_pipe_is_a_no_not_an_install(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Closed:
        def isatty(self) -> bool:
            return True

        def readline(self) -> str:
            raise OSError("closed")

    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(sys, "stdin", Closed())
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    assert not az_missing.matching("brew install")


def test_a_failing_preflight_without_the_flag_names_the_install(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "--install-missing" in err and "azure-cli" in err


def test_install_missing_with_nothing_installable_says_so(
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed sign-in is not a brew formula: the flag must not promise an install."""
    fake = FakeAdminCli(healthy_responses())
    fake.set(("az", "account", "show"), "", returncode=1)
    admin_cmd.set_runner(fake)
    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(sys, "stdin", Stdin("y"))

    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    assert "nothing to install" in capsys.readouterr().err
    assert not fake.matching("brew install")


def test_a_failing_brew_is_reported_not_swallowed(
    az_missing: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    az_missing.set(("brew", "install"), "", returncode=1)
    monkeypatch.setattr(admin_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(sys, "stdin", Stdin("y"))
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--install-missing")
        == EXIT_USAGE
    )
    assert "brew install" in capsys.readouterr().err


# ===========================================================================
# The config write: the same keys `mnotify setup` writes
# ===========================================================================
def test_the_config_is_written_with_the_setup_keys(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[Config] = []

    def spy(config: Config, path: Any = None) -> Path:
        written.append(config)
        return Path("/tmp/placeholder-config.toml")

    monkeypatch.setattr(admin_cmd, "write_config", spy)
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK

    config = written[0]
    assert config.mail.auth == AUTH_CERTIFICATE
    assert config.mail.sender == SENDER
    assert config.mail.client_id == APP_ID
    assert config.mail.tenant_id == TENANT_ID
    assert config.allow.domains == (DOMAIN,)


def test_a_second_allow_domain_flag_lands_in_the_config(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[Config] = []
    monkeypatch.setattr(
        admin_cmd,
        "write_config",
        lambda config, path=None: written.append(config) or Path("/tmp/placeholder.toml"),
    )
    assert (
        run_admin(
            "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--allow-domain", "contoso.com"
        )
        == EXIT_OK
    )
    assert written[0].allow.domains == (DOMAIN, "contoso.com")


def test_paths_and_teams_targets_survive_the_rewrite(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bootstrap owns [mail] and [allow]; [paths] and Teams targets are not its."""
    existing = Config(
        mail=MailConfig(
            tenant_id=TENANT_ID, client_id=SP_OBJECT_ID, sender="other@example.com",
            auth=AUTH_CERTIFICATE,
        ),
        allow=AllowConfig(domains=("contoso.com",)),
        limits=LimitsConfig(daily_max=7),
        paths=PathsConfig(audit=tmp_path / "audit.jsonl", state_dir=tmp_path / "state"),
        teams_targets=(TeamTarget(name="alerts", kind="channel"),),
    )
    path = tmp_path / "config.toml"
    write_config(existing, path)
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(path))

    written: list[Config] = []
    monkeypatch.setattr(
        admin_cmd,
        "write_config",
        lambda config, p=None: written.append(config) or path,
    )
    assert run_admin(
        "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--force-config"
    ) == EXIT_OK

    config = written[0]
    assert config.limits.daily_max == 7
    assert config.paths.audit == tmp_path / "audit.jsonl"
    assert [t.name for t in config.teams_targets] == ["alerts"]


# ===========================================================================
# --send-test
# ===========================================================================
def test_send_test_is_handed_to_doctor_which_owns_the_send(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Doctor delegates to the real mail path; the bootstrap must not send a second time."""
    assert (
        run_admin(
            "bootstrap",
            "--sender",
            SENDER,
            "--allow-domain",
            DOMAIN,
            "--send-test",
            "person@contoso.com",
            "--json",
        )
        == EXIT_OK
    )
    assert quiet_doctor[0]["send_test"] == "person@contoso.com"
    summary = parse_summary(capsys)
    step = next(s for s in summary["steps"] if s["name"] == admin_cmd.STEP_SEND_TEST)
    assert step["outcome"] == admin_cmd.OUTCOME_CREATED
    assert summary["testRecipient"] == "p***@contoso.com"


def test_send_test_is_skipped_when_doctor_fails(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from micro_notify import EXIT_REMOTE

    calls: list[dict] = []

    def failing(args: argparse.Namespace) -> int:
        calls.append({"send_test": args.send_test})
        return EXIT_REMOTE

    monkeypatch.setattr("micro_notify.commands.doctor.run", failing)
    assert (
        run_admin(
            "bootstrap",
            "--sender",
            SENDER,
            "--allow-domain",
            DOMAIN,
            "--send-test",
            "person@contoso.com",
            "--json",
        )
        == EXIT_REMOTE
    )
    summary = parse_summary(capsys)
    step = next(s for s in summary["steps"] if s["name"] == admin_cmd.STEP_SEND_TEST)
    assert step["outcome"] == admin_cmd.OUTCOME_SKIPPED


def test_doctor_is_really_delegated_not_reimplemented(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tripwire for a copy-paste doctor: patch the real module and prove it runs.

    Here the *real* doctor is left in place with a stubbed msal, so a green bootstrap
    means doctor's own checks ran against the config this command just wrote. That is
    why this test runs on the autouse ``isolated_config`` rather than on the shared
    ``mnotify_config``: conftest's placeholder config carries two Teams targets whose
    webhook URLs no keychain holds, so doctor would exit 4 on `teams` before ever
    reaching the checks this test is about. The bootstrap writes its own minimal
    config here — no targets — which is the end state `bootstrap` actually produces.
    """
    import base64

    from micro_notify import graph

    def segment(payload: dict) -> str:
        raw = json.dumps(payload).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    token = f"{segment({'alg': 'RS256'})}.{segment({'aud': 'https://graph.microsoft.com'})}.sig"

    class _App:
        def acquire_token_silent(self, *_a, **_k):
            return None

        def acquire_token_for_client(self, *_a, **_k):
            return {"access_token": token}

    monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", lambda **kw: _App())
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK


# ===========================================================================
# The real-machine runner (streaming + per-kind timeouts)
# ===========================================================================
class SentinelRunner(admin_runner.SubprocessRunner):
    """A SubprocessRunner *subclass*: proves the swap is narrow, not broad."""


def test_the_plain_default_runner_is_replaced_by_the_streaming_one() -> None:
    """The real CLI (nobody installed a runner) must get the streaming runner, or
    the Exchange step's device-code prompt is held until pwsh exits: the operator
    never reads the code, the sign-in never completes, and the step can never
    finish on a real machine."""
    from micro_notify.admin.runner import SubprocessRunner

    admin_cmd.set_runner(None)
    assert isinstance(admin_cmd.admin_runner.get_runner(), SubprocessRunner)

    admin_cmd._use_streaming_runner()
    try:
        runner = admin_cmd.admin_runner.get_runner()
        assert isinstance(runner, admin_cmd.StreamingRunner)
        # The seam B4 declared, and the check B4 publishes: with this runner
        # installed the Exchange step no longer warns about a capturing runner.
        assert callable(getattr(runner, "run_streaming", None))
        assert exo_module.supports_streaming() is True
    finally:
        admin_cmd.set_runner(None)


def test_bootstrap_itself_installs_the_streaming_runner(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins the CALL SITE, not just the function.

    A test that only calls :func:`_use_streaming_runner` stays green when someone
    deletes the line in ``bootstrap()`` that calls it — the defect would then be the
    exact one this runner exists to prevent (the device-code prompt captured until
    pwsh exits), reported by no test at all. So: run the command and require the hook
    to have fired, before any step runs.
    """
    calls: list[int] = []
    real = admin_cmd._use_streaming_runner

    def hook() -> None:
        calls.append(len(fake_cli.calls))
        real()

    monkeypatch.setattr(admin_cmd, "_use_streaming_runner", hook)
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK
    assert calls == [0], f"expected one call before the first command, got {calls}"


def test_dry_run_never_installs_the_streaming_runner(
    keychain_with_certificate: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dry run's whole promise is that the runner stays a recorder; swapping in a
    real streaming runner there would execute the plan it just printed."""
    monkeypatch.setattr(
        admin_cmd,
        "_use_streaming_runner",
        lambda: pytest.fail("a dry run must keep the recording runner"),
    )
    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run")
        == EXIT_OK
    )


def test_an_installed_fake_runner_is_never_replaced(
    fake_cli: FakeAdminCli,
) -> None:
    """The swap must not bypass an installed fake: that would send the flow to a
    real ``az`` in a process that believes it is talking to a placeholder tenant —
    and it would make this command untestable."""
    admin_cmd._use_streaming_runner()
    assert admin_cmd.admin_runner.get_runner() is fake_cli


def test_a_subclass_of_the_default_runner_is_left_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subclass is somebody else's runner (B1 documents subclassing through the
    seam), so the identity check is exact, not `isinstance`."""
    sentinel = SentinelRunner()
    admin_cmd.set_runner(sentinel)
    admin_cmd._use_streaming_runner()
    assert admin_cmd.admin_runner.get_runner() is sentinel


def test_run_streaming_hands_the_prompt_over_before_the_process_ends(
    tmp_path: Path,
) -> None:
    """The behavioural pin for the failure this runner exists to prevent.

    Lives here rather than in ``tests/test_admin_runner.py`` on purpose: the class it
    exercises now lives in :mod:`micro_notify.admin.runner`, but what this test proves
    is a property of the *installed* runner on the real CLI path — the thing the
    Exchange step depends on — so it travels with the call-site pins below. The class's
    own pins (transcript collection, timeout, missing binary, per-binary budget) are in
    ``tests/test_admin_runner.py``, where the class is.

    The child prints a device-code-shaped line and then waits for a file that only
    the sink can create: if the prompt reaches ``on_line`` while pwsh is still
    running, the child exits and the call returns 0. If output is captured until
    exit instead, the child never sees the file and the call can only end in the
    timeout (exit 124). A capturing runner therefore *cannot* pass this test — which
    is exactly what "capturing" costs on a real machine.
    """
    gate = tmp_path / "gate"
    seen: list[str] = []

    def sink(line: str) -> None:
        seen.append(line)
        if "enter the code" in line:
            gate.write_text("the operator saw the code", encoding="utf-8")

    # Written as a file rather than `-c` so the child's argv carries no code literal.
    child = tmp_path / "child.py"
    child.write_text(
        "import pathlib, sys, time\n"
        "gate = pathlib.Path(sys.argv[1])\n"
        "print('To sign in, open the page and enter the code WXYZ123', flush=True)\n"
        "deadline = time.monotonic() + 20\n"
        "while not gate.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.05)\n"
        "sys.exit(0 if gate.exists() else 3)\n",
        encoding="utf-8",
    )

    result = admin_cmd.StreamingRunner().run_streaming(
        [sys.executable, "-u", str(child), str(gate)], on_line=sink, timeout=30.0
    )
    assert seen and "enter the code" in seen[0]
    assert gate.exists(), "the sink never saw the prompt while the child was running"
    assert result.returncode == 0, "streaming fell back to capture: the child timed out"


# ===========================================================================
# Nothing prints a secret
# ===========================================================================
def test_no_keychain_value_reaches_the_output(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN) == EXIT_OK
    captured = capsys.readouterr()
    assert "placeholder-private-material-not-a-real-key" not in captured.out + captured.err


def test_the_thumbprint_is_reported_because_entra_displays_it(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A thumbprint is not a secret — ADMIN-SETUP §1.3 asks the operator to compare it."""
    assert run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--json") == EXIT_OK
    assert parse_summary(capsys)["thumbprint"] == THUMBPRINT


def test_a_dry_run_does_not_leave_its_recording_runner_installed(
    keychain_with_certificate: Any,
) -> None:
    """The leak this restore exists for: a DryRunRunner still installed afterwards
    would make every later command in the same process report success having done
    nothing."""
    from micro_notify.admin.runner import SubprocessRunner

    assert (
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--dry-run")
        == EXIT_OK
    )
    runner = admin_cmd.admin_runner.get_runner()
    assert not isinstance(runner, admin_cmd.DryRunRunner)
    assert isinstance(runner, SubprocessRunner)


def test_the_callers_runner_survives_a_mid_run_failure(
    fake_cli: FakeAdminCli,
    keychain_with_certificate: Any,
    quiet_doctor: list[dict],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A harness that installed its own runner keeps it after a raising bootstrap.

    Resetting to the *default* on failure would hand the next command the real
    :class:`SubprocessRunner` — a real ``az`` in a process that believed it was
    talking to a fake tenant. Restoring the caller's runner is the safe direction,
    and the dry run's runner is still replaced by the same mechanism.
    """
    monkeypatch.setattr(
        "micro_notify.admin.entra.ensure_entra_app",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    with pytest.raises(RuntimeError):
        run_admin("bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN)
    assert admin_cmd.admin_runner.get_runner() is fake_cli


def test_report_renders_one_line_per_step_in_human_mode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = admin_cmd.Report(machine=False)
    report.add("alpha", admin_cmd.OUTCOME_EXISTS, "already there")
    report.add("beta", admin_cmd.OUTCOME_CREATED)
    out = capsys.readouterr().out
    assert "alpha: exists — already there" in out
    assert "beta: created" in out


def test_report_is_silent_in_machine_mode_until_it_emits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = admin_cmd.Report(machine=True)
    report.add("alpha", admin_cmd.OUTCOME_EXISTS, "already there")
    report.line("progress nobody asked for")
    assert capsys.readouterr().out == ""
    report.emit(ok=True)
    assert json.loads(capsys.readouterr().out)["steps"][0]["name"] == "alpha"
