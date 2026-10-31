"""Tests for :mod:`micro_notify.admin.exo` (card B4).

Nothing here can run a real ``pwsh``: the autouse ``no_real_admin_binaries``
tripwire turns the *real* subprocess layer into a failure for az/pwsh/brew/
security, and each test installs its own fake runner holding canned pwsh output.
Sockets stay blocked by the untouched ``tests/conftest.py``. Every id is the
all-zero or all-ones placeholder; every mailbox is example.com / contoso.com.

What the card pins, and where it is pinned:

* device-code line reaches the caller **live** with a streaming runner, and is
  never swallowed by a capturing one — ``run_pwsh`` section;
* get-before-New: the generated script guards every ``New-*`` behind its
  ``Get-*`` enumeration, and a canned "found" answer reports ``exists``;
* the temp ``.ps1`` is mode 0600 and gone after a success, a failure, a crash and
  an interrupt;
* the ``InScope`` parser matrix, including the two answers that must FAIL the
  bootstrap: the negative control coming back ``True`` and a ``True`` row that is
  scoped to ``Organization`` rather than to our scope;
* ``Disconnect-ExchangeOnline`` is emitted from a ``finally`` block, so a failed
  run still releases the session.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from micro_notify.admin import exo
from micro_notify.admin.exo import (
    DEVICE_CODE_RE,
    EVENT_PREFIX,
    MANAGEMENT_ROLE,
    OUTCOME_CREATED,
    OUTCOME_EXISTS,
    PWSH_TIMEOUT,
    AuthzCheck,
    ExchangeError,
    ExchangeProvisioning,
    ExchangeScript,
    build_script,
    ensure_exchange_scope,
    parse_authz_rows,
    parse_pwsh_output,
    plan_commands,
    run_pwsh,
    scope_name_for,
    supports_streaming,
    write_script_file,
)
from micro_notify.admin.runner import STDERR_QUOTE_LIMIT, set_runner

# --- Placeholders only (design §5, leak guard) -------------------------------
APP_ID = "00000000-0000-0000-0000-000000000000"
SP_OBJECT_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
SENDER = "noreply@example.com"
ADMIN_MAILBOX = "admin@contoso.com"
SCOPE = "mnotify-noreply"
DEVICE_CODE_LINE = (
    "To sign in, use a web browser to open the page https://example.com/devicelogin "
    "and enter the code WXYZ123 to authenticate."
)

# Binaries a unit test must never execute, whatever the reason (same list as B1/B2).
FORBIDDEN_BINARIES = frozenset({"az", "pwsh", "brew", "powershell", "security"})


@pytest.fixture(autouse=True)
def restore_process_runner() -> Any:
    """No test leaks its fake runner into the next one."""
    try:
        yield
    finally:
        set_runner(None)


@pytest.fixture(autouse=True)
def no_real_admin_binaries(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Tripwire: the real subprocess layer must never be asked for pwsh (or az)."""
    real_run = subprocess.run

    def guarded(run_args: Any, **kwargs: Any) -> Any:
        argv = [str(a) for a in run_args]
        if argv and Path(str(argv[0])).name in FORBIDDEN_BINARIES:
            raise AssertionError(f"test attempted to execute a real {argv[0]!r}")
        return real_run(run_args, **kwargs)

    monkeypatch.setattr("micro_notify.admin.runner.subprocess.run", guarded)
    return guarded


@pytest.fixture
def temp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the generated script into tmp_path so its mode and life are visible."""
    monkeypatch.setattr(exo.tempfile, "gettempdir", lambda: str(tmp_path))
    return tmp_path


# --- Fake runners -----------------------------------------------------------
def completed(
    argv: list[str], returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


def event(**payload: Any) -> str:
    """One machine-readable line, exactly as the generated script prints it."""
    return EVENT_PREFIX + json.dumps(payload, separators=(",", ":"))


def to_json_rows(rows: list[dict]) -> Any:
    """The shape ``ConvertTo-Json`` produces for the ``rows`` value.

    Verified against pwsh 7.6.7 rather than assumed: an array variable nested in a
    hashtable keeps its array shape (``{"rows":[{...}]}``), so the single-row happy
    path **does** arrive as a one-element list. Only piping a bare object to
    ``ConvertTo-Json`` unwraps it. The parser therefore expects a list and tolerates
    the bare object as well, and both shapes are pinned below.
    """
    return list(rows)


def authz_row(in_scope: str = "True", scope: str = SCOPE, role: str = MANAGEMENT_ROLE) -> dict:
    return {"RoleName": role, "Scope": scope, "ScopeType": "CustomRecipientScope", "InScope": in_scope}


def pwsh_lines(
    *,
    sp: str = OUTCOME_CREATED,
    scope: str = OUTCOME_CREATED,
    role: str = OUTCOME_CREATED,
    sender_in_scope: str = "True",
    admin_in_scope: str = "False",
    admin_scope: str = SCOPE,
    connected: bool = True,
    disconnected: bool = True,
    summary_ok: bool = True,
    device_code: bool = True,
    rows_extra_sender: tuple[dict, ...] = (),
) -> list[str]:
    """A full canned pwsh transcript for one scenario."""
    lines = [
        "mnotify: connecting to Exchange Online (device-code sign-in).",
        "mnotify: open the page and enter the code below when prompted.",
    ]
    if device_code:
        lines.append(DEVICE_CODE_LINE)
    if connected:
        lines.append(event(event="connected"))
    for name, outcome in (
        ("service_principal", sp),
        ("management_scope", scope),
        ("role_assignment", role),
    ):
        # The script reports the enumeration count: 0 when it created the object,
        # at least 1 when it found one. A `found` of 0 alongside `exists` is a
        # transcript the script cannot produce, so the fake never emits one.
        lines.append(event(event=name, outcome=outcome, found=1 if outcome == "exists" else 0))
    lines.append(
        event(
            event="authz",
            control="sender",
            resource=SENDER,
            rows=to_json_rows([authz_row(sender_in_scope)] + list(rows_extra_sender)),
        )
    )
    lines.append(
        event(
            event="authz",
            control="admin",
            resource=ADMIN_MAILBOX,
            rows=to_json_rows([authz_row(admin_in_scope, scope=admin_scope)]),
        )
    )
    if disconnected:
        lines.append(event(event="disconnected"))
    lines.append(event(event="summary", ok=summary_ok))
    return lines


class FakePwsh:
    """A capturing :class:`CommandRunner`: canned stdout, records argv.

    Answers any script path (the real path is only known at run time) and records
    whether the file existed while it ran, which is how the file-lifetime pins
    assert without watching the filesystem from another thread.
    """

    def __init__(
        self,
        lines: list[str] | None = None,
        *,
        returncode: int = 0,
        stderr: str = "",
        raises: BaseException | None = None,
    ) -> None:
        self.lines = list(lines if lines is not None else pwsh_lines())
        self.returncode = returncode
        self.stderr = stderr
        self.raises = raises
        self.calls: list[list[str]] = []
        self.paths_seen_during_run: list[str] = []

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        self.calls.append(args)
        path = args[-1]
        self.paths_seen_during_run.append(path)
        if self.raises is not None:
            raise self.raises
        return completed(
            args, self.returncode, "\n".join(self.lines), self.stderr
        )

    @property
    def joined(self) -> str:
        return "\n".join(" ".join(c) for c in self.calls)


class StreamingFakePwsh(FakePwsh):
    """A runner with ``run_streaming``: it feeds lines as they 'arrive'."""

    def __init__(
        self,
        lines: list[str] | None = None,
        *,
        after_line: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(lines, **kwargs)
        self.after_line = after_line
        self.streaming_used = False
        self.timeouts: list[float | None] = []
        self.emission_order: list[str] = []

    def run_streaming(
        self,
        argv: Any,
        *,
        on_line: Any = None,
        stdin: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        args = [str(a) for a in argv]
        self.calls.append(args)
        self.streaming_used = True
        self.timeouts.append(timeout)
        self.paths_seen_during_run.append(args[-1])
        if self.raises is not None:
            raise self.raises
        for line in self.lines:
            self.emission_order.append(line)
            if on_line is not None:
                on_line(line)
            if self.after_line is not None:
                self.after_line(line)
        return completed(args, self.returncode, "\n".join(self.lines), self.stderr)


class Echo:
    """A sink that records what reached the operator, in order."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)


def script(**overrides: Any) -> ExchangeScript:
    kwargs: dict[str, Any] = {
        "app_id": APP_ID,
        "sp_object_id": SP_OBJECT_ID,
        "sender": SENDER,
        "admin_mailbox": ADMIN_MAILBOX,
    }
    kwargs.update(overrides)
    admin = kwargs.pop("admin_mailbox")
    return build_script(
        kwargs["app_id"], kwargs["sp_object_id"], kwargs["sender"], admin_mailbox=admin
    )


def capture_of(lines: list[str]) -> exo._RunCapture:
    capture = exo._RunCapture()
    for line in lines:
        capture.feed(line, echo=None)
    return capture


# ===========================================================================
# Generated script: get-before-New, no secrets, disconnect in finally
# ===========================================================================
def test_every_new_cmdlet_is_guarded_behind_its_own_get_enumeration() -> None:
    """No ``New-*`` runs unconditionally — each one sits inside the else-branch of
    a ``Get-*`` count test, so a re-run on a configured tenant creates nothing."""
    text = script().text
    pairs = (
        ("Get-ServicePrincipal", "New-ServicePrincipal"),
        ("Get-ManagementScope", "New-ManagementScope"),
        ("Get-ManagementRoleAssignment", "New-ManagementRoleAssignment"),
    )
    for get, new in pairs:
        assert get in text, f"{get} is missing — the step would create unconditionally"
        assert new in text, f"{new} is missing — the step can never create"
        assert text.index(get) < text.index(new), f"{new} appears before its {get}"
        guard = text[text.index(get) : text.index(new)]
        assert "if (" in guard and ".Count -gt 0" in guard, (
            f"{new} is not guarded by a {get} count check"
        )


def test_the_guard_compares_locally_instead_of_trusting_a_server_side_filter() -> None:
    """Same rule as admin/entra.py: the match is re-applied here, on the object's
    own property, so a near-miss scope or assignee is never adopted."""
    text = script().text
    assert '-eq $MnotifyAppId' in text
    assert '-eq $MnotifyScope' in text
    assert "Where-Object" in text


def test_the_script_uses_the_documented_role_scope_shape_and_new_service_principal_args() -> None:
    text = script().text
    assert MANAGEMENT_ROLE in text
    assert "PrimarySmtpAddress -eq '$MnotifySender'" in text
    assert "-RecipientRestrictionFilter" in text
    assert (
        "New-ServicePrincipal -AppId $MnotifyAppId -ObjectId $MnotifySpObjectId "
        "-DisplayName 'micro-notify'" in text
    )


def test_the_role_assignment_is_given_the_enterprise_object_id_not_the_client_id() -> None:
    """Live finding, recorded: ``-App <spObjectId>`` is what the tenant accepted."""
    text = script().text
    assignment = [ln for ln in text.splitlines() if "New-ManagementRoleAssignment" in ln]
    assert assignment and " -App $MnotifySpObjectId " in assignment[0]
    assert "-App $MnotifyAppId" not in text
    assert " -CustomResourceScope $MnotifyScope" in assignment[0]


def test_the_authorization_test_is_identified_by_the_object_id_and_run_twice() -> None:
    """One call for the sender (must be True), one for the admin (must be False)."""
    text = script().text
    assert "Test-ServicePrincipalAuthorization -Identity $MnotifySpObjectId" in text
    assert text.count("Get-MnotifyAuthzRows -Resource") == 2
    assert "control = 'sender'" in text and "control = 'admin'" in text


def test_disconnect_exchange_online_sits_in_a_finally_block() -> None:
    """A failed run must not leave an authenticated session on the tenant."""
    text = script().text
    finally_at = text.index("} finally {")
    disconnect_at = text.index("Disconnect-ExchangeOnline -Confirm:$false")
    assert disconnect_at > finally_at
    assert "try {" in text[finally_at:disconnect_at]


def test_the_device_code_output_is_merged_into_one_flushing_writer() -> None:
    """PowerShell's own stream merge plus an explicit Flush: the prompt cannot be
    buffered behind the cmdlet that then blocks waiting for the browser."""
    text = script().text
    assert "*>&1" in text
    assert "[Console]::Out.Flush()" in text
    connect_at = text.index("Connect-ExchangeOnline -Device")
    first_new_at = min(
        text.index(c) for c in ("New-ServicePrincipal", "New-ManagementScope", "New-ManagementRoleAssignment")
    )
    assert connect_at < first_new_at, "the sign-in must happen before any write step"


def test_the_generated_script_carries_no_url_no_token_and_no_key_material() -> None:
    """The card's rule: ids and handles only. Checked on the text that goes to disk."""
    text = script().text
    assert "http" not in text.lower()
    assert "-----BEGIN" not in text
    assert "Bearer " not in text and "client_secret" not in text
    assert APP_ID in text and SP_OBJECT_ID in text and SENDER in text


def test_the_script_interpolates_values_only_into_quoted_assignments() -> None:
    """Every value lands in a single-quoted PowerShell literal on its own line."""
    text = script().text
    for name, value in (
        ("$MnotifyAppId", APP_ID),
        ("$MnotifySpObjectId", SP_OBJECT_ID),
        ("$MnotifySender", SENDER),
        ("$MnotifyAdmin", ADMIN_MAILBOX),
        ("$MnotifyScope", SCOPE),
    ):
        lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith(name + " ")]
        assert lines, name
        assert all(ln.endswith(f"= '{value}'") for ln in lines), lines


def test_write_script_file_writes_the_script_verbatim_at_mode_0600(temp_dir: Path) -> None:
    generated = script()
    path = write_script_file(generated)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, oct(mode)
        assert Path(path).read_text(encoding="utf-8") == generated.text
        assert Path(path).suffix == ".ps1"
        assert Path(path).name.startswith("mnotify-exo-")
    finally:
        os.unlink(path)


def test_write_script_file_never_clobbers_an_existing_file(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """O_EXCL: a colliding name moves to a fresh one instead of overwriting."""

    class Fixed:
        def __init__(self) -> None:
            self.n = 0

        def uuid4(self) -> Any:
            self.n += 1
            return type("H", (), {"hex": "0" * 31 + str(self.n)})()

    monkeypatch.setattr(exo.uuid, "uuid4", Fixed().uuid4)
    clash = temp_dir / ("mnotify-exo-" + "0" * 31 + "1" + ".ps1")
    clash.write_text("someone else's file", encoding="utf-8")

    path = write_script_file(script())
    try:
        assert Path(path) != clash
        assert clash.read_text(encoding="utf-8") == "someone else's file"
    finally:
        os.unlink(path)


# --- Guards on what may reach the script ------------------------------------
@pytest.mark.parametrize(
    "app_id, sp_object_id",
    [
        ("", SP_OBJECT_ID),
        ("not-a-guid", SP_OBJECT_ID),
        ("00000000-0000-0000-0000-000000000000 ", SP_OBJECT_ID),
        (APP_ID, "'); New-ManagementScope('"),
        (APP_ID, "ff/ff"),
        (APP_ID, ""),
    ],
)
def test_a_malformed_id_is_refused_before_anything_is_generated(
    app_id: str, sp_object_id: str
) -> None:
    with pytest.raises(ExchangeError):
        build_script(app_id, sp_object_id, SENDER, admin_mailbox=ADMIN_MAILBOX)


@pytest.mark.parametrize(
    "address",
    [
        "",
        "  noreply@example.com",
        "noreply@example.com ",
        "noreply example@example.com",
        "noreply@localhost",
        "noreply",
        "norep\nly@example.com",
        "noreply'; Get-Mailbox; '@example.com",
        "noreply$(Get-Mailbox)@example.com",
        "noreply`@example.com",
    ],
)
def test_an_address_that_is_not_plainly_a_mailbox_is_refused(address: str) -> None:
    """The address is interpolated into a restriction filter; anything with a
    quote, dollar, backtick, space or newline is refused at the boundary."""
    with pytest.raises(ExchangeError):
        build_script(APP_ID, SP_OBJECT_ID, address or "noreply", admin_mailbox=ADMIN_MAILBOX)


def test_the_admin_mailbox_is_validated_too() -> None:
    with pytest.raises(ExchangeError):
        build_script(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox="admin@localhost;")


def test_a_supplied_scope_name_is_validated() -> None:
    for bad in ("", " has-space", "a" * 65, "scope;Get-Mailbox", "scope$name"):
        with pytest.raises(ExchangeError):
            build_script(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX, scope_name=bad)
    good = build_script(
        APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX, scope_name="mnotify-custom"
    )
    assert good.scope_name == "mnotify-custom"


@pytest.mark.parametrize(
    "sender, expected",
    [
        ("noreply@example.com", "mnotify-noreply"),
        ("Noreply@Example.com", "mnotify-noreply"),
        ("a.b+c@contoso.com", "mnotify-a.b-c"),
        ("ops_team@contoso.com", "mnotify-ops_team"),
    ],
)
def test_scope_name_is_derived_from_the_local_part_and_is_deterministic(
    sender: str, expected: str
) -> None:
    assert scope_name_for(sender) == expected
    assert build_script(APP_ID, SP_OBJECT_ID, sender, admin_mailbox=ADMIN_MAILBOX).scope_name == expected


def test_a_long_local_part_is_capped_but_stays_deterministic() -> None:
    sender = "z" * 120 + "@example.com"
    name = scope_name_for(sender)
    assert len(name) <= 64
    assert name == scope_name_for(sender)
    assert name.startswith("mnotify-")


def test_an_address_with_no_usable_local_part_has_no_scope_name() -> None:
    with pytest.raises(ExchangeError):
        scope_name_for("...@example.com")


# ===========================================================================
# plan_commands — B5's --dry-run surface
# ===========================================================================
def test_plan_commands_returns_the_argv_line_then_the_script(temp_dir: Path) -> None:
    plan = plan_commands(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX)
    assert plan[0].startswith("pwsh -NoProfile")
    assert "-File" in plan[0]
    assert "".join(plan[1:])  # the script body follows
    generated = script()
    assert plan[1:] == generated.text.splitlines()


def test_plan_commands_writes_no_file_and_runs_nothing(temp_dir: Path) -> None:
    """--dry-run must be safe on a machine that has no pwsh and nothing set up."""
    plan_commands(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX)
    assert list(temp_dir.iterdir()) == []


def test_plan_commands_is_deterministic() -> None:
    first = plan_commands(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX)
    second = plan_commands(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX)
    assert first == second


def test_plan_commands_marks_the_script_path_instead_of_inventing_one() -> None:
    plan = plan_commands(APP_ID, SP_OBJECT_ID, SENDER, admin_mailbox=ADMIN_MAILBOX)
    assert plan[0].endswith("<generated-script-path>")


def test_argv_of_the_generated_script_is_the_documented_shape() -> None:
    argv = script().argv("/tmp/mnotify-exo-test.ps1")
    assert argv == [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        "/tmp/mnotify-exo-test.ps1",
    ]


def test_plan_without_an_admin_mailbox_still_prints_and_says_it_cannot_prove() -> None:
    """A dry run may plan before the pre-flight knows the signed-in UPN; the script
    then refuses to claim the scope is proven."""
    plan = plan_commands(APP_ID, SP_OBJECT_ID, SENDER)
    body = "\n".join(plan)
    assert "negative_control" in body
    assert "not a user mailbox" in body


# ===========================================================================
# run_pwsh — the streaming contract
# ===========================================================================
def test_a_streaming_runner_gets_on_line_and_the_device_code_reaches_the_sink_live() -> None:
    """The card's central streaming pin: at the instant pwsh emitted the device-code
    line, the sink had already received it — not after the process exited."""
    echo = Echo()
    sink_depth_after: list[int] = []
    fake = StreamingFakePwsh(after_line=lambda line: sink_depth_after.append(len(echo.lines)))
    run_pwsh(["pwsh", "-File", "x.ps1"], capture := exo._RunCapture(), runner=fake, echo=echo)

    assert fake.streaming_used is True
    assert DEVICE_CODE_LINE in echo.lines
    # Every human-facing line reached the sink, in order; machine lines did not.
    human = [ln for ln in fake.emission_order if EVENT_PREFIX not in ln]
    assert echo.lines == human
    at = fake.emission_order.index(DEVICE_CODE_LINE)
    already_human = sum(1 for ln in fake.emission_order[: at + 1] if EVENT_PREFIX not in ln)
    assert sink_depth_after[at] == already_human, "the prompt was buffered instead of streamed"
    # and the run was still going when it landed
    assert at < len(fake.emission_order) - 1


def test_the_device_code_line_is_flagged_so_the_cli_can_react_to_it() -> None:
    fake = StreamingFakePwsh()
    capture = exo._RunCapture()
    run_pwsh(["pwsh", "-File", "x.ps1"], capture, runner=fake, echo=Echo())
    assert capture.device_code_seen is True
    assert DEVICE_CODE_RE.search(DEVICE_CODE_LINE)


def test_a_capturing_runner_still_feeds_the_device_code_line_to_the_sink() -> None:
    """Fallback path: a runner without streaming must not swallow the prompt."""
    fake = FakePwsh()
    echo = Echo()
    capture = exo._RunCapture()
    result = run_pwsh(["pwsh", "-File", "x.ps1"], capture, runner=fake, echo=echo)

    assert DEVICE_CODE_LINE in echo.lines
    assert capture.device_code_seen is True
    assert result.returncode == 0


def test_a_capturing_runner_warns_before_the_wait_not_after() -> None:
    """An operator watching a silent terminal during a browser sign-in cannot tell
    a hung process from a slow one. The fallback runner says up front that the
    prompt will arrive late; the line still arrives either way."""
    fake = FakePwsh()
    echo = Echo()
    capture = exo._RunCapture()
    run_pwsh(["pwsh", "-File", "x.ps1"], capture, runner=fake, echo=echo)

    assert echo.lines[0].startswith("mnotify:") and "instead of streaming" in echo.lines[0]
    assert DEVICE_CODE_LINE in echo.lines  # still not swallowed
    assert echo.lines.index(DEVICE_CODE_LINE) > 0


def test_a_streaming_runner_is_never_warned_at() -> None:
    """The warning is about a limitation the streaming path does not have."""
    echo = Echo()
    run_pwsh(["pwsh", "-File", "x.ps1"], exo._RunCapture(), runner=StreamingFakePwsh(), echo=echo)
    assert not [ln for ln in echo.lines if "instead of streaming" in ln]


def test_supports_streaming_reports_the_capability_of_the_installed_runner() -> None:
    assert supports_streaming(FakePwsh()) is False
    assert supports_streaming(StreamingFakePwsh()) is True
    set_runner(StreamingFakePwsh())
    assert supports_streaming() is True
    set_runner(FakePwsh())
    assert supports_streaming() is False


def test_the_warning_goes_to_the_sink_not_into_the_parsed_lines() -> None:
    """The heads-up is ours, not pwsh's: it must not end up in the transcript the
    parser reads."""
    capture = exo._RunCapture()
    echo = Echo()
    run_pwsh(["pwsh", "-File", "x.ps1"], capture, runner=FakePwsh(), echo=echo)
    assert not [ln for ln in capture.lines if "instead of streaming" in ln]
    assert any("instead of streaming" in ln for ln in echo.lines)


def test_machine_readable_lines_are_parsed_not_re_printed() -> None:
    echo = Echo()
    run_pwsh(["pwsh", "-File", "x.ps1"], capture_of([]), runner=FakePwsh(), echo=echo)
    assert not [ln for ln in echo.lines if ln.startswith(EVENT_PREFIX)]
    assert any("connecting to Exchange Online" in ln for ln in echo.lines)


def test_the_device_code_timeout_is_only_offered_to_a_streaming_runner() -> None:
    """A 60 s capture cannot carry a browser sign-in; the long budget goes with the
    capability that can stream it."""
    fake = StreamingFakePwsh()
    run_pwsh(["pwsh", "-File", "x.ps1"], exo._RunCapture(), runner=fake)
    assert fake.timeouts == [PWSH_TIMEOUT]
    assert PWSH_TIMEOUT > 60


def test_a_capturing_runner_is_never_handed_the_device_code_timeout() -> None:
    """A capture that swallows output for 10 minutes would be worse than the 60 s
    default it keeps: pwsh would hang and the operator would see nothing."""
    from micro_notify.admin import runner as runner_module

    class CapturingSubprocessLike(runner_module.SubprocessRunner):
        def __init__(self) -> None:
            super().__init__(timeout=60.0)
            self.timeouts_seen: list[float | None] = []

        def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
            self.timeouts_seen.append(self.timeout)
            self.timeouts_seen.append(kwargs.get("timeout"))
            return completed([str(a) for a in argv], 0, "")

    fake = CapturingSubprocessLike()
    run_pwsh(["pwsh", "-File", "x.ps1"], exo._RunCapture(), runner=fake)
    assert fake.timeouts_seen == [60.0, None]


def test_run_pwsh_uses_the_process_wide_runner_when_none_is_passed() -> None:
    fake = FakePwsh()
    set_runner(fake)
    run_pwsh(["pwsh", "-File", "x.ps1"], exo._RunCapture())
    assert fake.calls == [["pwsh", "-File", "x.ps1"]]


def test_no_runner_at_all_still_does_not_spawn_pwsh(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no runner installed the seam's default is used — and the tripwire bites
    if that default ever reaches a real pwsh."""
    from micro_notify.admin import runner as runner_module

    recorded: list[list[str]] = []

    class Recorder:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def run(self, argv: Any, **kwargs: Any) -> Any:
            args = [str(a) for a in argv]
            recorded.append(args)
            return completed(args, 0, "")

    monkeypatch.setattr(runner_module, "SubprocessRunner", Recorder)
    run_pwsh(["pwsh", "-File", "x.ps1"], exo._RunCapture())
    assert recorded == [["pwsh", "-File", "x.ps1"]]


# ===========================================================================
# Parser: InScope matrix, missing events, fail-closed
# ===========================================================================
def test_the_happy_transcript_proves_the_scope_and_reports_every_step() -> None:
    generated = script()
    result = parse_pwsh_output(
        capture_of(pwsh_lines()).lines, script=generated, device_code_seen=True
    )
    assert isinstance(result, ExchangeProvisioning)
    assert result.ok is True and result.failures == ()
    assert result.created is True and result.outcome == OUTCOME_CREATED
    assert result.device_code_surfaced is True
    assert result.sender_check.in_scope is True and result.sender_check.passed
    assert result.admin_check.in_scope is False and result.admin_check.passed
    assert [s.outcome for s in result.steps] == ["created"] * 3


def test_a_re_run_reports_exists_for_every_object_and_creates_nothing() -> None:
    generated = script()
    result = parse_pwsh_output(
        capture_of(
            pwsh_lines(sp=OUTCOME_EXISTS, scope=OUTCOME_EXISTS, role=OUTCOME_EXISTS)
        ).lines,
        script=generated,
    )
    assert result.ok is True
    assert result.created is False and result.outcome == OUTCOME_EXISTS
    assert [s.outcome for s in result.steps] == ["exists"] * 3
    assert "already present" in result.detail


@pytest.mark.parametrize(
    "sp, scope, role, expected_created",
    [
        ("created", "created", "created", True),
        ("exists", "created", "created", True),
        ("exists", "exists", "created", True),
        ("exists", "exists", "exists", False),
        ("created", "exists", "exists", True),
    ],
)
def test_created_is_true_when_at_least_one_object_was_made(
    sp: str, scope: str, role: str, expected_created: bool
) -> None:
    result = parse_pwsh_output(
        capture_of(pwsh_lines(sp=sp, scope=scope, role=role)).lines, script=script()
    )
    assert result.created is expected_created
    if expected_created:
        assert "created" in result.detail


# --- The InScope matrix the card asks for ----------------------------------
def test_sender_true_and_admin_false_is_the_only_green_combination() -> None:
    result = parse_pwsh_output(
        capture_of(pwsh_lines(sender_in_scope="True", admin_in_scope="False")).lines,
        script=script(),
    )
    assert result.ok is True


def test_the_negative_control_flipping_to_true_fails_the_bootstrap() -> None:
    """The app can send as the admin's own mailbox: the scope restricts nothing."""
    result = parse_pwsh_output(
        capture_of(pwsh_lines(sender_in_scope="True", admin_in_scope="True")).lines,
        script=script(),
    )
    assert result.ok is False
    assert result.admin_check.in_scope is True
    assert result.admin_check.passed is False
    assert "can send as" in result.admin_check.problem
    assert "not restricting" in result.admin_check.problem


def test_sender_false_reports_that_the_assignment_did_not_take() -> None:
    result = parse_pwsh_output(
        capture_of(pwsh_lines(sender_in_scope="False", admin_in_scope="False")).lines,
        script=script(),
    )
    assert result.ok is False
    assert result.sender_check.passed is False
    assert "did not take effect" in result.sender_check.problem
    assert SCOPE in result.sender_check.problem


def test_both_verdicts_wrong_lists_both_problems() -> None:
    result = parse_pwsh_output(
        capture_of(pwsh_lines(sender_in_scope="False", admin_in_scope="True")).lines,
        script=script(),
    )
    assert result.ok is False
    assert len(result.failures) == 2
    joined = " ".join(result.failures)
    assert "did not take effect" in joined and "can send as" in joined


@pytest.mark.parametrize("answer", ["Not Run", "", "Skipped", "Unknown"])
def test_an_unusable_inscope_answer_is_never_read_as_false(answer: str) -> None:
    """'Not Run' means the cmdlet was not asked. Reading it as False would turn an
    unverified grant into a working restriction."""
    check = parse_authz_rows(
        [authz_row(answer)],
        control="sender",
        resource=SENDER,
        expected_in_scope=True,
        expected_scope=SCOPE,
    )
    assert check.in_scope is None
    assert check.passed is False
    assert "no usable InScope value" in check.problem


def test_an_unusable_answer_on_the_negative_control_also_fails() -> None:
    result = parse_pwsh_output(
        capture_of(pwsh_lines(sender_in_scope="True", admin_in_scope="Not Run")).lines,
        script=script(),
    )
    assert result.ok is False
    assert result.admin_check.in_scope is None
    assert result.admin_check.expected_in_scope is False


def test_no_rows_at_all_is_not_an_answer() -> None:
    check = parse_authz_rows(
        [], control="admin", resource=ADMIN_MAILBOX, expected_in_scope=False, expected_scope=SCOPE
    )
    assert check.in_scope is None
    assert check.passed is False


def test_any_true_row_wins_over_a_false_row() -> None:
    """A tenant-wide row and a scoped row can both be returned; the app *can* send,
    which is the answer that matters for a restriction test."""
    check = parse_authz_rows(
        [authz_row("False"), authz_row("True", scope="Organization")],
        control="sender",
        resource=SENDER,
        expected_in_scope=True,
        expected_scope=SCOPE,
    )
    assert check.in_scope is True
    assert "Organization" in check.problem  # and it is the wrong scope


def test_a_true_row_outside_our_scope_is_a_failure_not_a_pass() -> None:
    """ADMIN-SETUP §2.4's warning: a True through scope ``Organization`` is a
    tenant-wide grant wearing our scope's clothes."""
    result = parse_pwsh_output(
        capture_of(
            pwsh_lines(sender_in_scope="True", rows_extra_sender=(authz_row("True", scope="Organization"),))
        ).lines,
        script=script(),
    )
    assert result.ok is False
    assert "tenant-wide" in result.sender_check.problem
    assert "Organization" in result.sender_check.problem


def test_the_scope_comparison_ignores_case_only() -> None:
    check = parse_authz_rows(
        [authz_row("True", scope=SCOPE.upper())],
        control="sender",
        resource=SENDER,
        expected_in_scope=True,
        expected_scope=SCOPE,
    )
    assert check.passed is True and check.problem == ""


def test_a_row_that_is_not_an_object_is_kept_and_never_trusted() -> None:
    check = parse_authz_rows(
        ["InScope : True"], control="sender", resource=SENDER, expected_in_scope=True, expected_scope=SCOPE
    )
    assert check.in_scope is None
    assert check.rows[0]["raw"] == "InScope : True"


# --- Missing / broken reporting is a failure, never a shrug -----------------
def test_a_missing_step_event_fails_rather_than_reading_as_nothing_to_do() -> None:
    lines = [ln for ln in pwsh_lines() if '"event":"management_scope"' not in ln]
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("management scope" in f for f in result.failures)


def test_a_missing_authorization_event_fails_the_run() -> None:
    lines = [ln for ln in pwsh_lines() if '"control":"admin"' not in ln]
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("admin" in f for f in result.failures)


def test_a_missing_summary_is_treated_as_an_interruption() -> None:
    lines = [ln for ln in pwsh_lines() if '"event":"summary"' not in ln]
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("summary" in f for f in result.failures)


def test_a_summary_saying_not_ok_fails_the_run_even_when_both_checks_look_right() -> None:
    result = parse_pwsh_output(
        capture_of(pwsh_lines(summary_ok=False)).lines, script=script()
    )
    assert result.ok is False
    assert any("failed run" in f for f in result.failures)


def test_an_unparsable_machine_line_fails_the_run() -> None:
    lines = pwsh_lines() + [EVENT_PREFIX + "{not json"]
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("could not be parsed" in f for f in result.failures)


def test_a_never_connected_run_fails() -> None:
    result = parse_pwsh_output(capture_of(pwsh_lines(connected=False)).lines, script=script())
    assert result.ok is False
    assert result.connected is False
    assert any("never reported a connected" in f for f in result.failures)


def test_exiting_without_disconnecting_fails() -> None:
    """The finally block is supposed to always run; if it did not, the session is
    still open on the tenant and the operator has to be told."""
    result = parse_pwsh_output(
        capture_of(pwsh_lines(disconnected=False)).lines, script=script()
    )
    assert result.ok is False
    assert result.disconnected is False
    assert any("without disconnecting" in f for f in result.failures)


def test_a_failure_event_from_the_script_is_carried_into_the_report() -> None:
    lines = pwsh_lines()
    lines.insert(
        len(lines) - 1,
        event(event="failure", step="negative_control", reason="not a user mailbox"),
    )
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("negative_control" in f and "not a user mailbox" in f for f in result.failures)


def test_a_non_json_machine_line_is_not_counted_as_an_event() -> None:
    assert parse_pwsh_output([EVENT_PREFIX + "[1,2]"], script=script()).ok is False


# ===========================================================================
# ensure_exchange_scope: end to end, file lifetime, fail-closed
# ===========================================================================
def test_happy_path_streams_the_device_code_and_leaves_no_script_behind(temp_dir: Path) -> None:
    fake = StreamingFakePwsh()
    echo = Echo()
    result = ensure_exchange_scope(
        APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake, echo=echo
    )
    assert result.ok is True
    assert DEVICE_CODE_LINE in echo.lines
    assert list(temp_dir.iterdir()) == [], "the generated script must be deleted"
    assert fake.streaming_used is True


def test_the_runner_is_handed_the_generated_script_path(temp_dir: Path) -> None:
    fake = FakePwsh()
    ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    argv = fake.calls[0]
    assert argv[0] == "pwsh" and "-File" in argv
    path = argv[-1]
    assert path.startswith(str(temp_dir)) and path.endswith(".ps1")
    # It existed while pwsh ran, and it is gone now.
    assert fake.paths_seen_during_run == [path]
    assert not Path(path).exists()


def test_the_file_the_runner_saw_is_mode_0600_and_holds_the_script(temp_dir: Path) -> None:
    seen: dict[str, Any] = {}

    class Peeky(FakePwsh):
        def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
            path = str([str(a) for a in argv][-1])
            seen["mode"] = stat.S_IMODE(os.stat(path).st_mode)
            seen["text"] = Path(path).read_text(encoding="utf-8")
            return super().run(argv, stdin=stdin, **kwargs)

    ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=Peeky())
    assert seen["mode"] == 0o600
    assert seen["text"] == script().text
    assert "http" not in seen["text"].lower()


def test_the_script_is_deleted_after_a_failing_verdict(temp_dir: Path) -> None:
    fake = FakePwsh(pwsh_lines(sender_in_scope="True", admin_in_scope="True"))
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert list(temp_dir.iterdir()) == []
    assert excinfo.value.result is not None
    assert excinfo.value.result.ok is False
    assert "can send as" in " ".join(excinfo.value.result.failures)


def test_the_script_is_deleted_after_a_non_zero_exit(temp_dir: Path) -> None:
    fake = FakePwsh(["mnotify: something went wrong"], returncode=1, stderr="boom")
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert list(temp_dir.iterdir()) == []
    assert "pwsh exited 1" in excinfo.value.message
    assert "boom" in excinfo.value.message


@pytest.mark.parametrize(
    "raises",
    [RuntimeError("pwsh vanished"), KeyboardInterrupt(), OSError("disk gone")],
    ids=["crash", "interrupt", "oserror"],
)
def test_the_script_is_deleted_after_a_crash_or_interrupt(
    temp_dir: Path, raises: BaseException
) -> None:
    """The card's pin: deleted in a finally even on failure — a Ctrl-C during the
    device-code wait must not leave the tenant's ids on disk."""
    fake = FakePwsh(raises=raises)
    with pytest.raises(type(raises)):
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert list(temp_dir.iterdir()) == []


def test_the_parser_accepts_the_bare_object_rows_shape_too() -> None:
    """The script sends a JSON array (verified on pwsh 7.6.7), but ``ConvertTo-Json``
    does unwrap a single object that is *piped* rather than nested. If a future edit
    changed how rows are collected, a parser that only read arrays would turn a
    working bootstrap into "no usable InScope value" — the worst failure to debug on
    a live tenant — so both shapes are accepted and both are pinned."""
    line = event(
        event="authz",
        control="sender",
        resource=SENDER,
        rows=authz_row("True"),  # a dict, the piped-object shape
    )
    lines = [ln for ln in pwsh_lines() if '"control":"sender"' not in ln]
    lines.insert(-1, line)
    assert any('"rows":{"RoleName"' in ln for ln in lines)
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.sender_check.in_scope is True
    assert result.sender_check.rows[0]["Scope"] == SCOPE
    assert result.ok is True


def test_the_happy_path_rows_shape_is_a_one_element_list() -> None:
    """What the generated script really emits for a correct single-row scope:
    a JSON array of one object, verified against pwsh 7.6.7's ConvertTo-Json."""
    sender_lines = [ln for ln in pwsh_lines() if '"control":"sender"' in ln]
    assert len(sender_lines) == 1
    assert '"rows":[{"RoleName"' in sender_lines[0]


def test_several_rows_still_arrive_as_a_list() -> None:
    line = event(
        event="authz",
        control="sender",
        resource=SENDER,
        rows=[authz_row("False"), authz_row("True", scope="Organization")],
    )
    assert '"rows":[{' in line
    lines = [ln for ln in pwsh_lines() if '"control":"sender"' not in ln]
    lines.insert(-1, line)
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.sender_check.in_scope is True
    assert len(result.sender_check.rows) == 2


def test_rows_of_null_is_not_invented_as_an_answer() -> None:
    lines = [ln for ln in pwsh_lines() if '"control":"admin"' not in ln]
    lines.append(event(event="authz", control="admin", resource=ADMIN_MAILBOX, rows=None))
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert result.admin_check.in_scope is None


def test_the_scripts_exception_event_is_carried_into_the_report() -> None:
    """The catch block names the cmdlet that died; losing that line would leave the
    operator with 'no rows' and nothing to act on."""
    lines = [
        ln for ln in pwsh_lines() if '"event":"summary"' not in ln and '"control":"admin"' not in ln
    ]
    lines.insert(
        len(lines) - 1,
        event(event="error", reason="The term 'Get-ServicePrincipal' is not recognized"),
    )
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("Get-ServicePrincipal" in f for f in result.failures)


def test_a_repeated_error_reason_is_reported_once() -> None:
    reason = "scope already exists"
    lines = pwsh_lines()
    lines.insert(len(lines) - 1, event(event="failure", step="management_scope", reason=reason))
    lines.insert(len(lines) - 1, event(event="error", reason=reason))
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert sum(1 for f in result.failures if reason in f) == 1


# --- Structure of the generated PowerShell ---------------------------------
def test_the_disconnect_is_guarded_by_the_connection_flag_and_not_a_constant() -> None:
    """The finally block must actually reach the disconnect when a session exists.

    A guard that is always false would keep the ``finally`` and the
    ``Disconnect-ExchangeOnline`` line — so a parser-level test on a canned
    transcript stays green — while leaving an authenticated Exchange Online session
    on the tenant after every failed run. The flag it checks has to be the one the
    script sets only after the connect check passed.
    """
    text = script().text
    block = text[text.index("} finally {"):]
    assert "if ($MnotifyConnected) {" in block
    assert block.index("if ($MnotifyConnected) {") < block.index("Disconnect-ExchangeOnline")
    flag_set = text.index("$MnotifyConnected = $true")
    assert text.index("Connect-ExchangeOnline -Device") < flag_set < text.index("} finally {")


def test_exists_with_a_zero_count_is_reported_not_repaired() -> None:
    """'Found it already' with a count of nothing is a transcript the script cannot
    produce. Repairing it silently would let a step that actually found nothing
    report exists - and a re-run's whole purpose is to trust that answer."""
    lines = [ln for ln in pwsh_lines() if '"event":"management_scope"' not in ln]
    lines.insert(-1, event(event="management_scope", outcome="exists", found=0))
    result = parse_pwsh_output(capture_of(lines).lines, script=script())
    assert result.ok is False
    assert any("'exists' while finding nothing" in f for f in result.failures)
    assert result.management_scope.found == 0  # reported as it came in


def test_os_open_itself_is_asked_for_0600_not_just_the_final_chmod(
    temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mode that closes the race is the one passed to ``os.open``, not the one
    chmod sets afterwards. Between creation and chmod the file already holds the
    tenant's object ids; ``O_EXCL`` creates it with this mode atomically, so a
    loosened argument leaves a world-readable window that a final-mode assertion
    cannot see — the later chmod makes the end state look correct.
    """
    seen: list[tuple[bool, int]] = []
    real_open = os.open

    def spy(path: Any, flags: int, mode: int = 0o777) -> int:
        seen.append((bool(flags & (os.O_CREAT | os.O_EXCL)), mode))
        return real_open(path, flags, mode)

    monkeypatch.setattr(exo.os, "open", spy)
    path = write_script_file(script())
    try:
        creat_excl_modes = [m for excl, m in seen if excl]
        assert creat_excl_modes == [0o600], [oct(m) for m in creat_excl_modes]
    finally:
        os.unlink(path)


def test_the_generated_script_is_structurally_balanced() -> None:
    """Cheap proxy for 'PowerShell can parse this': every brace, bracket and paren
    the generator emits has to close, and the try/catch/finally must nest."""
    text = script().text
    for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
        assert text.count(opener) == text.count(closer), f"unbalanced {opener}{closer}"
    # three try/catch pairs: the outer run, the per-attempt connect wrap (the retry
    # cannot see a terminating error otherwise), and the disconnect guard - plus
    # exactly one finally, no more, or a block has escaped its guard
    assert text.count("try {") == 3 and text.count("} catch {") == 3 and text.count("} finally {") == 1
    assert text.index("try {") < text.index("} catch {") < text.index("} finally {")
    assert "\nif ($MnotifyOk) { exit 0 } else { exit 1 }" in text


def test_no_write_cmdlet_can_run_outside_the_try_block() -> None:
    """Everything that touches the tenant sits inside the try, so nothing can run
    before the session check and everything is followed by the finally block."""
    text = script().text
    try_at = text.index("try {")
    finally_at = text.index("} finally {")
    for cmdlet in ("New-ServicePrincipal", "New-ManagementScope", "New-ManagementRoleAssignment"):
        at = text.index(cmdlet)
        assert try_at < at < finally_at, cmdlet
    disconnect = text.index("Disconnect-ExchangeOnline")
    assert disconnect > finally_at


def test_the_script_declares_stop_preference_before_any_cmdlet_runs() -> None:
    """Without Stop, a Get that fails would write an error and the script would carry
    on to the New-* call — creating an object that was never proven to be absent."""
    text = script().text
    assert text.index("$ErrorActionPreference = 'Stop'") < text.index("Connect-ExchangeOnline")
    assert "-ErrorAction Stop" in text  # the proof cmdlet, explicitly


def test_the_script_is_deleted_when_parsing_raises(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("parser blew up")

    monkeypatch.setattr(exo, "parse_pwsh_output", explode)
    with pytest.raises(RuntimeError, match="parser blew up"):
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=FakePwsh())
    assert list(temp_dir.iterdir()) == []


def test_a_non_zero_exit_with_a_clean_transcript_still_fails(temp_dir: Path) -> None:
    """pwsh can die after printing (killed, module unloaded); the exit code is the
    last word, not the transcript."""
    fake = FakePwsh(pwsh_lines(), returncode=137)
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert "137" in excinfo.value.message
    assert excinfo.value.result is not None and excinfo.value.result.ok is False


def test_a_result_without_an_exit_code_is_a_failure_not_a_zero(temp_dir: Path) -> None:
    """A runner that answers with no returncode did not run a process. Reading that
    as success would green-light an unproven grant."""
    from types import SimpleNamespace

    class NoReturnCode:
        def run(self, argv: Any, **kwargs: Any) -> Any:
            return SimpleNamespace(stdout="\n".join(pwsh_lines()), stderr=None)

    with pytest.raises(ExchangeError, match="exited 1"):
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=NoReturnCode())


def test_a_zero_exit_with_a_failed_summary_still_fails(temp_dir: Path) -> None:
    """The exit code never gets to overrule a transcript that says the run failed."""
    fake = FakePwsh(pwsh_lines(summary_ok=False), returncode=0)
    with pytest.raises(ExchangeError, match="failed run"):
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)


def test_a_zero_exit_with_a_flipped_negative_control_still_fails(temp_dir: Path) -> None:
    fake = FakePwsh(pwsh_lines(admin_in_scope="True"), returncode=0)
    with pytest.raises(ExchangeError, match="can send as"):
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)


def test_stderr_is_quoted_short_and_never_carries_the_argv() -> None:
    """The stderr quote is bounded on its own, not by luck in the joined message."""
    noise = "~" * (STDERR_QUOTE_LIMIT * 3)
    fake = FakePwsh(["fatal"], returncode=1, stderr=noise + " pwsh -NoProfile -File /tmp/secret.ps1")
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    carried = excinfo.value.result
    assert carried is not None
    message = excinfo.value.message
    diagnosis = carried.failures[0]
    assert diagnosis.startswith("pwsh exited 1")
    assert "~" * STDERR_QUOTE_LIMIT in diagnosis and "..." in diagnosis
    assert "~" * (STDERR_QUOTE_LIMIT + 1) not in diagnosis
    assert "/tmp/secret.ps1" not in message
    assert message.count("~") == STDERR_QUOTE_LIMIT


def test_both_checks_failing_raises_and_still_carries_the_structured_result(temp_dir: Path) -> None:
    fake = FakePwsh(pwsh_lines(sender_in_scope="False", admin_in_scope="True"))
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    carried = excinfo.value.result
    assert isinstance(carried, ExchangeProvisioning)
    assert carried.ok is False and len(carried.failures) == 2
    # What it did before failing is still reportable to the operator.
    assert [s.name for s in carried.steps] == [
        "Exchange service principal",
        "management scope",
        "role assignment",
    ]


def test_sender_and_admin_must_be_different_mailboxes(temp_dir: Path) -> None:
    """Using the sender as the negative control proves nothing: it is InScope True."""
    fake = FakePwsh()
    with pytest.raises(ExchangeError, match="negative control needs a different"):
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, SENDER, runner=fake)
    assert fake.calls == [] and list(temp_dir.iterdir()) == []


@pytest.mark.parametrize("bad", ["", "not-an-id", "noreply@example.com"])
def test_an_id_that_is_not_a_guid_never_reaches_a_file(temp_dir: Path, bad: str) -> None:
    fake = FakePwsh()
    with pytest.raises(ExchangeError):
        ensure_exchange_scope(bad, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert fake.calls == [] and list(temp_dir.iterdir()) == []


def test_a_rejected_address_never_reaches_a_file(temp_dir: Path) -> None:
    fake = FakePwsh()
    with pytest.raises(ExchangeError):
        ensure_exchange_scope(
            APP_ID, SP_OBJECT_ID, "sender'; New-Mailbox; '@example.com", ADMIN_MAILBOX, runner=fake
        )
    assert fake.calls == [] and list(temp_dir.iterdir()) == []


def test_the_result_payload_b5_needs_is_complete_and_secret_free(temp_dir: Path) -> None:
    result = ensure_exchange_scope(
        APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=StreamingFakePwsh()
    )
    payload = result.to_dict()
    assert payload["ok"] is True
    assert payload["outcome"] == OUTCOME_CREATED
    assert [s["outcome"] for s in payload["steps"]] == ["created"] * 3
    assert [c["control"] for c in payload["checks"]] == ["sender", "admin"]
    assert payload["checks"][1]["expected_in_scope"] is False
    assert payload["scope_name"] == SCOPE
    assert json.dumps(payload)  # reportable as --json
    assert "http" not in json.dumps(payload).lower()


def test_an_existing_tenant_re_run_is_all_exists_and_still_green(temp_dir: Path) -> None:
    fake = FakePwsh(pwsh_lines(sp=OUTCOME_EXISTS, scope=OUTCOME_EXISTS, role=OUTCOME_EXISTS))
    result = ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert result.ok is True and result.created is False
    assert result.outcome == OUTCOME_EXISTS


def test_the_authz_check_to_dict_is_self_explanatory() -> None:
    check = parse_authz_rows(
        [authz_row("False")],
        control="admin",
        resource=ADMIN_MAILBOX,
        expected_in_scope=False,
        expected_scope=SCOPE,
    )
    payload = check.to_dict()
    assert payload["passed"] is True and payload["problem"] == ""
    assert payload["expected_in_scope"] is False and payload["in_scope"] is False
    assert isinstance(check, AuthzCheck)


# ===========================================================================
# BUG 4 (live run B6, 2026-10-31): the transient Connect-ExchangeOnline death
#
# The operator's device-code sign-in finished and the Exchange step died with
# ``pwsh exited 1; the script threw: Error while copying content to a stream.``
# and NO rows for the SP / scope / role-assignment / InScope checks. That
# message is a known TRANSIENT Connect-ExchangeOnline network failure - the
# tenant was fine - and two things were wrong with how it was handled: the
# connect was never retried, and "could not verify because the session died" was
# reported exactly like "verification FAILED (scope wrong)", which sends the
# operator hunting a config problem that does not exist.
#
# The vocabulary the fix adds (``verified``, ``reason``, ``connect_attempts``,
# ``connect_failures``, ``REASON_CONNECT_TRANSIENT``, ``REASON_CONNECT_FAILED``,
# ``REASON_SCRIPT_DIED``, ``REASON_CHECK_UNANSWERED``,
# ``TRANSIENT_CONNECT_SIGNATURES``, ``is_transient_connect_error``) is reached
# through ``exo.`` rather than imported, so the red phase fails per-test on the
# missing behaviour instead of once at import time.
# ===========================================================================

DEAD_CONNECT_ERROR = "Error while copying content to a stream"


def legacy_death_lines() -> list[str]:
    """The transcript the live run actually produced, before any retry existed.

    Two machine lines and nothing else: the connect failure event, the exception
    the outer catch printed, no check rows, no summary. Exit code 1.
    """
    return [
        "mnotify: connecting to Exchange Online (device-code sign-in).",
        "mnotify: open the page and enter the code below when prompted.",
        DEVICE_CODE_LINE,
        event(
            event="failure",
            step="connect",
            reason="Connect-ExchangeOnline -Device did not establish a session",
        ),
        event(event="error", reason=DEAD_CONNECT_ERROR),
    ]


def failed_attempt(attempt: int, *, transient: bool, error: str = DEAD_CONNECT_ERROR) -> str:
    """One reported connect attempt that did not establish a session."""
    return event(
        event="connect_attempt",
        attempt=attempt,
        outcome="failed",
        transient=transient,
        error=error,
    )


def ok_attempt(attempt: int) -> str:
    """One reported connect attempt that did."""
    return event(event="connect_attempt", attempt=attempt, outcome="ok")


def retry_death_lines(*, attempts: int = 2, transient: bool = True) -> list[str]:
    """The same death from a script that retries: one ``connect_attempt`` per failed
    attempt, then the giving-up event, still with no check rows."""
    lines = [
        "mnotify: connecting to Exchange Online (device-code sign-in).",
        DEVICE_CODE_LINE,
    ]
    for attempt in range(1, attempts + 1):
        lines.append(failed_attempt(attempt, transient=transient))
    lines.append(
        event(
            event="connect_failed",
            attempts=attempts,
            transient=transient,
            error=DEAD_CONNECT_ERROR,
        )
    )
    lines.append(event(event="error", reason="mnotify: connect"))
    return lines


def retry_recovered_lines() -> list[str]:
    """Attempt 1 transient, attempt 2 succeeds: the checks then run for real."""
    lines = [DEVICE_CODE_LINE, failed_attempt(1, transient=True), ok_attempt(2)]
    lines += [ln for ln in pwsh_lines() if ln.startswith(EVENT_PREFIX)]
    return lines


# --- (a) today's parser cannot tell the two failures apart ------------------
def test_a_session_that_died_is_reported_as_could_not_verify_not_as_a_failed_check() -> None:
    """The live transcript, pinned as the card states it.

    Before the fix this transcript is indistinguishable from a wrong-scope verdict:
    both came back ``ok=False`` with a message beginning "could not be verified". The
    distinguishable state is what the CLI needs.
    """
    result = parse_pwsh_output(legacy_death_lines(), script=script())
    assert result.ok is False, "a session that died is never a pass"
    assert result.verified is False, "the checks never ran, so nothing was verified"
    assert result.reason == exo.REASON_CONNECT_TRANSIENT, (
        "the death message is in the transient list, so the report says re-run"
    )
    # No connect_attempt line exists in this transcript: the script that produced it
    # had no retry to report. The parser reports what it saw, not what it expects.
    assert result.connect_attempts == 0 and result.connect_failures == 0
    assert result.sender_check.in_scope is None and result.admin_check.in_scope is None


def test_a_script_that_died_somewhere_else_reports_script_died_not_a_connect_death() -> None:
    """``could-not-verify`` is one state with several reasons: a connect that never
    established, and a script that threw further along (here the negative-control
    guard) both leave the restriction unproven, but only one of them is "re-run and it
    may work".
    """
    lines = [ln for ln in pwsh_lines() if '"control":"admin"' not in ln]
    lines.insert(
        len(lines) - 1,
        event(event="failure", step="negative_control", reason="not a user mailbox"),
    )
    lines.insert(len(lines) - 1, event(event="error", reason="mnotify: negative_control"))
    result = parse_pwsh_output(lines, script=script())
    assert result.ok is False
    assert result.verified is False
    assert result.reason == exo.REASON_SCRIPT_DIED
    assert any("negative_control" in f for f in result.failures)


def test_a_died_session_and_a_wrong_scope_verdict_are_now_distinguishable() -> None:
    """The misdirection the operator hit: one report for two different facts.

    ``sender_in_scope=True`` through scope ``Organization`` is a verification that RAN
    and FAILED (a tenant-wide grant); the live death is a verification that NEVER RAN.
    Same exit code, different sentence - and only the first one means "fix the scope".
    """
    died = parse_pwsh_output(legacy_death_lines(), script=script())
    wrong_scope = parse_pwsh_output(
        capture_of(
            pwsh_lines(
                sender_in_scope="True",
                rows_extra_sender=(authz_row("True", scope="Organization"),),
            )
        ).lines,
        script=script(),
    )
    assert died.ok is False and wrong_scope.ok is False  # both fail closed
    assert died.verified is False and died.reason != ""
    assert wrong_scope.verified is True and wrong_scope.reason == ""
    assert "tenant-wide" in wrong_scope.sender_check.problem


def test_a_check_that_did_not_run_can_never_read_as_a_pass() -> None:
    """The B4 class of bug, extended: a True row with the wrong scope fails, and so
    does a check whose rows are absent, empty, null or unparseable. A missing answer is
    not a False answer and is never a pass."""
    shapes = {
        "the session died": legacy_death_lines(),
        "no rows at all": [
            ln for ln in pwsh_lines() if '"control":"sender"' not in ln
        ] + [event(event="authz", control="sender", resource=SENDER, rows=[])],
        "rows of null": [
            ln for ln in pwsh_lines() if '"control":"admin"' not in ln
        ] + [event(event="authz", control="admin", resource=ADMIN_MAILBOX, rows=None)],
        "no authz event": [ln for ln in pwsh_lines() if '"control":"admin"' not in ln],
    }
    for label, lines in shapes.items():
        result = parse_pwsh_output(lines, script=script())
        assert result.ok is False, label
        # The anti-pattern is the whole verification reading green. A control that
        # really did answer may still pass on its own - what must never happen is
        # both reading as passed while one of them was never answered.
        assert not (result.sender_check.passed and result.admin_check.passed), label
        unanswered = [
            check for check in (result.sender_check, result.admin_check)
            if check.in_scope is None
        ]
        assert unanswered, label
        assert all(not check.passed for check in unanswered), label
        assert result.verified is False, f"{label}: an absent check must not read as verified"


# --- (1) the retry: one named list, one retry, non-transient gives up at once
def test_the_transient_signature_list_names_the_live_error_verbatim() -> None:
    """The operator's exact message is in the constant, not paraphrased: a rewrite of
    the sentence would stop the retry working on the failure it was written for."""
    assert DEAD_CONNECT_ERROR in " ".join(exo.TRANSIENT_CONNECT_SIGNATURES)
    assert exo.is_transient_connect_error(f"Connect-ExchangeOnline: {DEAD_CONNECT_ERROR}")


@pytest.mark.parametrize(
    "text, transient",
    [
        (f"pwsh exited 1 — {DEAD_CONNECT_ERROR}", True),
        ("The term 'Connect-ExchangeOnline' is not recognized as a name of a cmdlet", False),
        ("AADSTS50126: Error validating credentials due to invalid username or password", False),
        ("Sign-in was canceled by the user", False),
        ("AADSTS700016: Application with identifier was not found in the directory", False),
        ("The operation has timed out", True),
        ("Unable to connect to the remote server", True),
        (
            "The underlying connection was closed: Could not establish trust relationship",
            True,
        ),
        ("An error occurred while sending the request", True),
        ("", False),
    ],
)
def test_the_transient_classifier_retries_network_hiccups_and_only_those(
    text: str, transient: bool
) -> None:
    """A sign-in denial must fail immediately: a second device-code prompt cannot turn
    a denied consent into an accepted one, and it costs the operator another sign-in."""
    assert exo.is_transient_connect_error(text) is transient


def test_the_generated_script_retries_the_connect_once_and_never_more_than_once() -> None:
    """One call site, a loop bounded by an explicit attempt count of two.

    ``Connect-ExchangeOnline -Device`` is a device-code prompt: a loop that could run
    three times would ask a human to sign in three times, so the bound is pinned as the
    literal the loop reads rather than as a comment.
    """
    text = script().text
    call_sites = [
        ln for ln in text.splitlines() if ln.strip().startswith("Connect-ExchangeOnline -Device")
    ]
    assert len(call_sites) == 1, (
        "two call sites would mean two device-code prompts in one run"
    )
    assert "$MnotifyConnectTries = 2" in text
    assert "$MnotifyAttempt -le $MnotifyConnectTries" in text, (
        "the retry loop is not bounded by the attempt count"
    )
    loop_at = text.index("for ($MnotifyAttempt = 1;")
    assert loop_at < text.index("Connect-ExchangeOnline -Device"), (
        "the connect must sit inside the retry loop, not before it"
    )
    assert "Start-Sleep" in text[loop_at:], (
        "an immediate re-attempt hits the same network blip"
    )
    # The retry branch must actually skip the give-up path: without `continue` a
    # first failed attempt would emit the 'both attempts' failure and throw before
    # attempt 2 ever ran - the retry would exist on paper only.
    retry_branch = text[text.index("if ($MnotifyAttempt -lt $MnotifyConnectTries) {") :]
    retry_branch = retry_branch[: retry_branch.index("        }")]
    assert "continue" in retry_branch, "the retry branch must skip the give-up path"


def test_the_powershell_classifier_checks_permanent_markers_before_transient_ones() -> None:
    """AADSTS text carries network-shaped words, so a script that matched the
    transient list first would re-prompt a refused sign-in. The Python classifier is
    pinned by the parametrized matrix; this pins the script's copy of the same rule."""
    text = script().text
    fn = text[text.index("function Test-MnotifyTransient {") :]
    fn = fn[: fn.index("\n}", fn.index("return $false"))]
    permanent = fn.index("foreach ($MnotifyMarker in $MnotifyPermanent)")
    transient = fn.index("foreach ($MnotifySignature in $MnotifyTransient)")
    assert permanent < transient


def test_the_connect_loop_is_followed_by_a_not_connected_belt() -> None:
    """No write cmdlet may run on a session that was never established.

    Every failing path in the loop throws, so the belt is unreachable today - which
    is exactly why a pin is the only thing keeping it there: a future edit that
    softens one throw (or adds a `break`) would otherwise route an unauthenticated
    run straight into New-ServicePrincipal.
    """
    text = script().text
    loop_end = text.index("Connect-ExchangeOnline -Device")
    belt = text.index("if (-not $MnotifyConnected) {", loop_end)
    finally_at = text.index("} finally {")
    assert belt < finally_at, "the belt must sit inside the try, before the writes are reachable"
    assert text.index("New-ServicePrincipal") > belt
    segment = text[belt: belt + 300]
    assert "throw" in segment, "the belt must stop the run, not log and continue"


def test_the_generated_script_gives_up_without_a_second_sign_in_on_a_non_transient_error() -> None:
    """Structural pin for "any NON-transient error fails immediately": the transient
    test and its throw sit inside the loop, before the retry notice is reachable."""
    text = script().text
    loop_body = text[text.index("for ($MnotifyAttempt = 1;") :]
    gate = loop_body.index("if (-not $MnotifyAttemptTransient) {")
    throw = loop_body.index("throw", gate)
    retry_notice = loop_body.index("retrying the connect once", gate)
    assert gate < throw < retry_notice, (
        "the non-transient path must throw before the retry notice is reachable"
    )
    # The reason reaches the parser twice over before the throw: the per-attempt
    # line (emitted before the gate, for every failed attempt) and the giving-up
    # line (emitted inside the gate, before the throw that ends the run).
    assert "connect_attempt" in loop_body[:gate], (
        "the failed attempt must be reported before the give-up gate"
    )
    assert gate < loop_body.index("connect_failed") < throw, (
        "giving up on a non-transient error must still report why to the parser"
    )


def test_the_generated_script_emits_the_transient_list_from_the_one_python_constant() -> None:
    """The list lives in Python once and is written into the script; a script holding
    its own copy would drift from the classifier that labels the report."""
    text = script().text
    assert "$MnotifyTransient = @(" in text
    for signature in exo.TRANSIENT_CONNECT_SIGNATURES:
        assert f"'{signature}'" in text, signature
    assert "Test-MnotifyTransient" in text


# --- (2) could-not-verify: distinct report, same fail-closed -----------------
def test_both_attempts_transient_reports_could_not_verify_and_still_fails_closed(
    temp_dir: Path,
) -> None:
    """The card's case (c): non-zero, config NOT written, and a sentence that names the
    session death rather than a scope problem."""
    fake = FakePwsh(retry_death_lines(attempts=2), returncode=1)
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)

    carried = excinfo.value.result
    assert carried is not None
    assert carried.ok is False, "could-not-verify is STILL a bootstrap failure"
    assert carried.verified is False
    assert carried.reason == exo.REASON_CONNECT_TRANSIENT
    assert carried.connect_attempts == 2 and carried.connect_failures == 2
    assert excinfo.value.exit_code == 2, "still exit 2: distinct reporting, same safety"
    assert list(temp_dir.iterdir()) == [], "the generated script must still be deleted"
    assert DEAD_CONNECT_ERROR in excinfo.value.message, "the pwsh error must be quoted"
    assert "re-run" in excinfo.value.message
    assert "verification failed" not in excinfo.value.message
    assert "NOT a scope" in excinfo.value.message


def test_a_transient_death_json_is_self_reporting_for_the_command_layer() -> None:
    """``--json`` must carry the distinction too: an agent reading the document gets
    the same two facts the terminal shows, and ``ok`` stays false either way."""
    result = parse_pwsh_output(retry_death_lines(attempts=2), script=script())
    payload = result.to_dict()
    assert payload["ok"] is False and payload["verified"] is False
    assert payload["reason"] == exo.REASON_CONNECT_TRANSIENT
    assert payload["could_not_verify"] is True
    assert payload["connect_attempts"] == 2 and payload["connect_failures"] == 2
    assert json.dumps(payload)


def test_a_first_transient_that_recovered_is_a_green_run_with_the_retry_visible(
    temp_dir: Path,
) -> None:
    """The card's case (b): attempt 1 transient, the script retried, attempt 2
    connected, the checks ran. The result is ok, and the retry is visible in it so a
    tenant that keeps being flaky is still diagnosable."""
    fake = StreamingFakePwsh(retry_recovered_lines())
    result = ensure_exchange_scope(
        APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake
    )
    assert result.ok is True and result.verified is True and result.reason == ""
    assert result.connect_attempts == 2 and result.connect_failures == 1
    assert result.sender_check.passed and result.admin_check.passed
    assert list(temp_dir.iterdir()) == []


def test_a_non_transient_connect_death_names_the_reason_and_not_a_retry() -> None:
    """A denied sign-in must not be dressed up as "the network hiccuped, re-run": the
    reason says the connect failed, the attempts stop at one, and the error is quoted."""
    result = parse_pwsh_output(
        retry_death_lines(attempts=1, transient=False), script=script()
    )
    assert result.ok is False and result.verified is False
    assert result.reason == exo.REASON_CONNECT_FAILED
    assert result.connect_attempts == 1 and result.connect_failures == 1
    assert result.connected is False


def test_a_died_session_raises_the_could_not_verify_sentence_not_the_failed_one(
    temp_dir: Path,
) -> None:
    """The other half of the misdirection fix, at the raise: the transcript the operator
    actually got must produce the re-run sentence with the pwsh error quoted, and must
    not read like a scope verdict."""
    fake = FakePwsh(legacy_death_lines(), returncode=1)
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    message = excinfo.value.message
    assert DEAD_CONNECT_ERROR in message
    assert "could not be verified" in message
    assert "re-run" in message
    assert "verification failed" not in message
    assert excinfo.value.result.verified is False


def test_a_reported_connect_death_overrules_a_connected_claim() -> None:
    """The belt on the belt: if the script says the connect gave up, the run is not
    trusted even when the same transcript also claims a session.

    A truthful script cannot emit both lines - `connected` only follows a successful
    attempt - so a transcript carrying both is broken or forged, and either way the
    checks after the death cannot be believed.
    """
    lines = [
        event(event="connect_attempt", attempt=1, outcome="failed", transient=True, error=DEAD_CONNECT_ERROR),
        event(event="connect_failed", attempts=2, transient=True, error=DEAD_CONNECT_ERROR),
        event(event="connected"),  # contradicts the death above
    ] + [ln for ln in pwsh_lines() if ln.startswith(EVENT_PREFIX)]
    result = parse_pwsh_output(lines, script=script())
    assert result.ok is False
    assert result.verified is False, "a death the script itself reported wins"
    assert result.reason == exo.REASON_CONNECT_TRANSIENT
    assert any("connect giving up" in f for f in result.failures)


def test_a_wrong_scope_still_uses_the_failed_verification_sentence(temp_dir: Path) -> None:
    """The distinction cuts both ways: a scope that really is wrong must not be softened
    into "could not verify, just re-run", because re-running cannot fix a tenant-wide
    grant."""
    fake = FakePwsh(
        pwsh_lines(
            sender_in_scope="True", rows_extra_sender=(authz_row("True", scope="Organization"),)
        )
    )
    with pytest.raises(ExchangeError) as excinfo:
        ensure_exchange_scope(APP_ID, SP_OBJECT_ID, SENDER, ADMIN_MAILBOX, runner=fake)
    assert "verification failed" in excinfo.value.message
    assert "could not be verified" not in excinfo.value.message
    assert excinfo.value.result.verified is True
