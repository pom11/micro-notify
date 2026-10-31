"""Tests for :mod:`micro_notify.admin.runner` (card B1).

Nothing here runs ``az``, ``pwsh`` or ``brew``: the autouse ``no_real_admin_binaries``
guard turns the *real* subprocess layer into a tripwire for those three names, and
each test installs its own fake for everything else. A test that accidentally lets a
real ``az`` through therefore fails loudly instead of hitting a live tenant.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from micro_notify import EXIT_USAGE
from micro_notify.admin import exo as exo_module
from micro_notify.admin import runner as runner_module
from micro_notify.admin.runner import (
    BREW_TIMEOUT,
    EXIT_NOT_FOUND,
    EXIT_TIMEOUT,
    STDERR_QUOTE_LIMIT,
    SUBPROCESS_TIMEOUT,
    CommandError,
    DryRunRunner,
    StreamingRunner,
    SubprocessRunner,
    get_runner,
    parse_json_result,
    run_json,
    set_runner,
    which,
)

# Binaries a unit test must never execute, whatever the reason.
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
    """Tripwire: the real subprocess layer must never be asked for az/pwsh/brew.

    Everything else passes through untouched, so this cannot break pytest's own
    use of subprocess — it only bites on the four names the admin package exists
    to run.
    """
    real_run = subprocess.run

    def guarded(run_args: Any, **kwargs: Any) -> Any:
        argv = [str(a) for a in run_args]
        if argv and Path(str(argv[0])).name in FORBIDDEN_BINARIES:
            raise AssertionError(f"test attempted to execute a real {argv[0]!r}")
        return real_run(run_args, **kwargs)

    monkeypatch.setattr(runner_module.subprocess, "run", guarded)
    return guarded


def completed(
    argv: list[str], returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


class RecordingRunner:
    """A :class:`CommandRunner` that answers from a script and records everything."""

    def __init__(self, results: dict[tuple[str, ...], Any] | None = None) -> None:
        self.results = dict(results or {})
        self.calls: list[list[str]] = []
        self.stdin_payloads: list[str | None] = []
        self.kwargs_seen: list[dict[str, Any]] = []

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        self.calls.append(args)
        self.stdin_payloads.append(stdin)
        self.kwargs_seen.append(kwargs)
        for prefix, result in self.results.items():
            if tuple(args[: len(prefix)]) == prefix:
                if isinstance(result, BaseException):
                    raise result
                return result
        return completed(args, 0, "{}")

    @property
    def last(self) -> list[str]:
        return self.calls[-1]


# --- The seam itself --------------------------------------------------------
def test_default_runner_is_the_real_subprocess_runner() -> None:
    assert isinstance(get_runner(), SubprocessRunner)


def test_set_runner_installs_and_clears_the_process_wide_runner() -> None:
    fake = RecordingRunner()
    set_runner(fake)
    try:
        assert get_runner() is fake
    finally:
        set_runner(None)
    assert isinstance(get_runner(), SubprocessRunner)


def test_a_bare_callable_is_accepted_as_a_runner() -> None:
    """A ``fn(argv, **kw)``-style fake works, like the shared fake_keychain fixture."""
    seen: list[list[str]] = []

    def fn(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        seen.append(args)
        return completed(args, 0, '{"ok": true}')

    set_runner(fn)
    assert run_json(["az", "account", "show"]) == {"ok": True}
    assert seen == [["az", "account", "show"]]


def test_run_json_prefers_the_explicit_runner_over_the_process_wide_one() -> None:
    global_fake = RecordingRunner({(): completed(["x"], 0, '{"source": "global"}')})
    set_runner(global_fake)
    explicit = RecordingRunner({(): completed(["x"], 0, '{"source": "explicit"}')})

    assert run_json(["az", "account", "show"], runner=explicit) == {"source": "explicit"}
    assert explicit.calls == [["az", "account", "show"]]
    assert global_fake.calls == []  # the process-wide runner was never consulted


# --- SubprocessRunner: the real implementation, without real binaries -------
def test_subprocess_runner_execs_an_argv_list_with_no_shell(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def fake_run(run_args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        captured["argv"] = run_args
        captured.update(kwargs)
        return completed(list(run_args), 0, "hi", "")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    result = SubprocessRunner().run(["az", "ad", "user", "show", "--id", "a@contoso.com"])

    assert result.stdout == "hi"
    assert isinstance(captured["argv"], list)
    assert captured["argv"] == ["az", "ad", "user", "show", "--id", "a@contoso.com"]
    assert "shell" not in captured or captured["shell"] is False
    assert captured["capture_output"] is True and captured["text"] is True
    assert captured["timeout"] == SUBPROCESS_TIMEOUT
    assert captured["check"] is False


def test_subprocess_runner_feeds_stdin_and_never_puts_it_in_argv(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def fake_run(run_args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        captured["argv"] = list(run_args)
        captured["input"] = kwargs.get("input")
        return completed(list(run_args), 0, "", "")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    SubprocessRunner().run(["pwsh", "-Command", "x"], stdin="a secret on stdin")

    assert captured["input"] == "a secret on stdin"
    assert "a secret on stdin" not in captured["argv"]


def test_subprocess_runner_defaults_stdin_to_none(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def fake_run(run_args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        captured["input"] = kwargs.get("input", "MISSING")
        return completed(list(run_args), 0, "", "")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    SubprocessRunner().run(["true"])
    assert captured["input"] is None


def test_missing_binary_becomes_exit_127_not_a_traceback() -> None:
    """The real exec path, honestly exercised: a binary that does not exist."""
    result = SubprocessRunner().run(["mnotify-no-such-binary-anywhere"])
    assert result.returncode == EXIT_NOT_FOUND
    assert "mnotify-no-such-binary-anywhere" in result.stderr


def test_timeout_becomes_exit_124(monkeypatch: Any) -> None:
    def fake_run(run_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess:
        raise subprocess.TimeoutExpired(list(run_args), 60)

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    result = SubprocessRunner(timeout=0.5).run(["az", "rest"])
    assert result.returncode == EXIT_TIMEOUT
    assert "timed out" in result.stderr


def test_oserror_is_reported_by_type_only(monkeypatch: Any) -> None:
    """An OSError str can carry the whole command line; it must not be echoed."""

    def fake_run(run_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess:
        raise OSError(5, "input/output error on /some/path", "a@contoso.com")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    result = SubprocessRunner().run(["az", "ad", "user", "show", "--id", "a@contoso.com"])
    assert result.returncode == EXIT_NOT_FOUND
    assert result.stderr == "az: OSError"
    assert "a@contoso.com" not in result.stderr
    assert "input/output error" not in result.stderr


def test_a_binary_that_is_not_executable_says_so(monkeypatch: Any) -> None:
    def fake_run(run_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess:
        raise PermissionError(13, "Permission denied: /opt/homebrew/bin/az")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    result = SubprocessRunner().run(["az", "account", "show"])
    assert result.returncode == EXIT_NOT_FOUND
    assert result.stderr == "not executable: az"
    assert "/opt/homebrew" not in result.stderr


def test_empty_argv_is_a_command_error() -> None:
    with pytest.raises(CommandError) as excinfo:
        SubprocessRunner().run([])
    assert excinfo.value.exit_code == EXIT_USAGE


# --- which -----------------------------------------------------------------
def test_which_finds_an_executable_on_path(tmp_path: Path, monkeypatch: Any) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "az"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    found = which("az")
    assert found == fake
    assert isinstance(found, Path)


def test_which_returns_none_when_absent(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert which("az") is None


def test_which_never_executes_the_thing_it_finds(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A lookup is a lookup: the binary is not run, so it cannot prompt or install."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "was-executed"
    fake = bin_dir / "az"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    assert which("az") == fake
    assert not marker.exists()


def test_which_ignores_an_empty_name() -> None:
    assert which("") is None


# --- run_json --------------------------------------------------------------
def test_run_json_parses_az_style_json_stdout() -> None:
    fake = RecordingRunner(
        {("az", "account", "show"): completed(["az"], 0, '{"id": "00000000-0000-0000-0000-000000000000"}\n')}
    )
    assert run_json(["az", "account", "show"], runner=fake) == {
        "id": "00000000-0000-0000-0000-000000000000"
    }


def test_run_json_accepts_a_json_array() -> None:
    fake = RecordingRunner({(): completed(["az"], 0, '[{"displayName": "Operators"}]')})
    assert run_json(["az", "rest"], runner=fake) == [{"displayName": "Operators"}]


def test_run_json_passes_stdin_through_to_the_runner() -> None:
    fake = RecordingRunner({(): completed(["pwsh"], 0, "[]")})
    run_json(["pwsh", "-Command", "x"], runner=fake, stdin="body")
    assert fake.stdin_payloads == ["body"]


def test_run_json_raises_command_error_on_a_nonzero_exit() -> None:
    fake = RecordingRunner(
        {(): completed(["az"], 3, "", "ERROR: az command failed, please run 'az login'")}
    )
    with pytest.raises(CommandError) as excinfo:
        run_json(["az", "account", "show"], runner=fake)
    message = excinfo.value.message
    assert "exited 3" in message
    assert "az login" in message  # the tool's own diagnosis is the useful part
    assert excinfo.value.exit_code == EXIT_USAGE


def test_run_json_raises_command_error_on_unparseable_stdout() -> None:
    fake = RecordingRunner({(): completed(["az"], 0, "Not a JSON document at all")})
    with pytest.raises(CommandError, match="did not print JSON"):
        run_json(["az", "account", "show"], runner=fake)


def test_run_json_raises_command_error_on_empty_stdout() -> None:
    fake = RecordingRunner({(): completed(["az"], 0, "", "")})
    with pytest.raises(CommandError, match="did not print JSON"):
        run_json(["az", "account", "show"], runner=fake)


def test_run_json_quotes_stderr_once_and_bounds_it() -> None:
    noisy = "ERROR: " + ("detail " * 200)
    fake = RecordingRunner({(): completed(["az"], 1, "", noisy)})
    with pytest.raises(CommandError) as excinfo:
        run_json(["az", "account", "show"], runner=fake)
    message = excinfo.value.message
    assert "\n" not in message  # collapsed to one line
    assert message.endswith("...")
    assert STDERR_QUOTE_LIMIT <= len(message) < STDERR_QUOTE_LIMIT + 120


def test_parse_json_result_reuses_one_failure_wording() -> None:
    with pytest.raises(CommandError, match="'pwsh' exited 2"):
        parse_json_result(completed(["pwsh"], 2, "", "boom"), "pwsh")


# --- DryRunRunner ----------------------------------------------------------
def test_dry_run_runner_records_and_executes_nothing(
    no_real_admin_binaries: Any,
) -> None:
    """The declared B5 seam: every argv is recorded, no process is spawned.

    The tripwire fixture is what makes "executes nothing" a fact rather than a
    claim about intent.
    """
    dry = DryRunRunner()
    dry.run(["az", "ad", "app", "create", "--name", "micro-notify"])
    dry.run(["pwsh", "-Command", "New-ManagementScope"])
    dry.run(["brew", "install", "azure-cli"])

    assert dry.calls == [
        ["az", "ad", "app", "create", "--name", "micro-notify"],
        ["pwsh", "-Command", "New-ManagementScope"],
        ["brew", "install", "azure-cli"],
    ]
    assert dry.executed_anything is False


def test_dry_run_runner_answers_successfully_with_empty_stdout() -> None:
    dry = DryRunRunner()
    result = dry.run(["az", "account", "show"])
    assert result.returncode == 0
    assert (result.stdout or "") == ""


def test_dry_run_runner_serves_longest_matching_prefix_response() -> None:
    dry = DryRunRunner(
        {
            ("az",): '{"generic": true}',
            ("az", "account", "show"): '{"tenantId": "00000000-0000-0000-0000-000000000000"}',
        }
    )
    assert json.loads(dry.run(["az", "account", "show"]).stdout)["tenantId"] == (
        "00000000-0000-0000-0000-000000000000"
    )
    assert json.loads(dry.run(["az", "ad", "group", "list"]).stdout) == {"generic": True}


def test_dry_run_runner_records_stdin_without_echoing_it() -> None:
    """A secret belongs on stdin, and a dry run must not launder it into argv.

    The PEM-looking value is assembled at runtime so this tracked file carries no
    private-key header (the leak guard, design §5); the guard's own convention is
    that positive-detection canaries are built by concatenation.
    """
    header = "-----BEGIN " + "PRIVATE KEY" + "-----"
    dry = DryRunRunner()
    dry.run(["pwsh", "-Command", "x"], stdin=header)
    assert dry.stdin_payloads == [header]
    assert "PRIVATE KEY" not in repr(dry.calls)


def test_dry_run_runner_can_script_a_failure() -> None:
    dry = DryRunRunner(returncode=3)
    assert dry.run(["az", "rest"]).returncode == 3


def test_dry_run_runner_is_a_drop_in_for_run_json() -> None:
    """A dry run can drive the same code path a real probe uses."""
    dry = DryRunRunner({("az", "ad", "user", "show"): '{"userPrincipalName": "person@contoso.com"}'})
    assert run_json(["az", "ad", "user", "show", "--id", "person@contoso.com"], runner=dry) == {
        "userPrincipalName": "person@contoso.com"
    }


# --- StreamingRunner (moved in from the command layer, card B7) --------------
# These are the class's own pins and they travel with the class: what is being
# exercised is the mechanism in this module, not a call site. The call-site pins —
# that the real CLI ends up with this runner installed and a dry run never does —
# stay in tests/test_admin_cli.py, where the command is.
#
# The two tests marked (B7) did not exist before the move: mutation probes on the
# relocated class found the property unpinned (a mutant that ignores an explicit
# timeout survived; a mutant that drops the package-root re-export survived), so
# they close a pre-existing gap rather than test new behaviour.
def test_the_timeout_budget_follows_the_command_not_the_caller() -> None:
    """pwsh waits on a human typing a code into a browser and brew installs real
    packages; a 60 s probe budget fits neither. az keeps its 60 s."""
    runner = StreamingRunner()
    assert runner._budget(["pwsh", "-NoProfile", "-File", "x.ps1"]) == exo_module.PWSH_TIMEOUT
    assert runner._budget(["powershell", "-File", "x.ps1"]) == exo_module.PWSH_TIMEOUT
    assert runner._budget(["brew", "install", "azure-cli"]) == BREW_TIMEOUT
    assert runner._budget(["az", "account", "show"]) == SUBPROCESS_TIMEOUT


def test_an_explicit_timeout_beats_the_per_binary_budget(monkeypatch: Any) -> None:
    """(B7) The per-kind budget is the *default*, never an override.

    A caller that passes ``timeout=`` knows something ``argv`` cannot show, and a
    runner that quietly swapped in its own 600 s for pwsh would hang exactly the call
    that was bounded on purpose. Pinned the way this module pins SubprocessRunner's
    own timeout plumbing: the exec is faked and the keyword is read back.
    """
    captured: dict[str, Any] = {}

    def fake_run(run_args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        captured["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(list(run_args), 0, "", "")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    StreamingRunner().run(["pwsh", "-File", "x.ps1"], timeout=1.0)
    assert captured["timeout"] == 1.0  # not exo's PWSH_TIMEOUT
    StreamingRunner().run(["pwsh", "-File", "x.ps1"])
    assert captured["timeout"] == exo_module.PWSH_TIMEOUT  # the default still applies


def test_the_package_root_re_exports_the_streaming_runner() -> None:
    """(B7) ``micro_notify.admin.StreamingRunner`` must exist.

    The move added it to the package's ``__all__`` append-only, and the package root is
    the surface the rest of the codebase reads (same rule as ``ensure_entra_app``). A
    dropped re-export is invisible to every test that imports the module directly, so
    it is pinned at the root instead.
    """
    from micro_notify import admin

    assert admin.StreamingRunner is runner_module.StreamingRunner
    assert "StreamingRunner" in admin.__all__


def test_run_streaming_collects_the_whole_transcript_and_exit_code() -> None:
    """B4 still reads the transcript back to decide whether the scope holds, and
    reads a missing returncode as failure — so both must survive streaming."""
    result = StreamingRunner().run_streaming(
        [sys.executable, "-c", "print('one'); print('two'); raise SystemExit(0)"],
        on_line=None,
        timeout=30.0,
    )
    assert result.returncode == 0
    assert result.stdout.split() == ["one", "two"]


def test_run_streaming_reports_a_timeout_as_124_not_as_success() -> None:
    """A sign-in nobody completed must not read as a green step."""
    result = StreamingRunner().run_streaming(
        [sys.executable, "-c", "import time; print('waiting'); time.sleep(30)"],
        on_line=None,
        timeout=1.0,
    )
    assert result.returncode == EXIT_TIMEOUT
    assert "timed out" in (result.stderr or "")


def test_run_streaming_surfaces_a_missing_binary_as_127() -> None:
    """The pre-flight's 'not installed' wording depends on this, not on a crash."""
    result = StreamingRunner().run_streaming(
        ["definitely-not-a-real-binary-9f3a"], on_line=None, timeout=5.0
    )
    assert result.returncode == EXIT_NOT_FOUND


# --- Contract pins ---------------------------------------------------------
def test_runner_protocol_is_satisfied_by_both_implementations() -> None:
    """Whatever satisfies ``run(argv, *, stdin=...)`` is a runner."""
    for candidate in (SubprocessRunner(), DryRunRunner(), RecordingRunner()):
        assert callable(getattr(candidate, "run"))
        result = candidate.run(["true"], stdin=None) if not isinstance(
            candidate, SubprocessRunner
        ) else None
        if result is not None:
            assert hasattr(result, "returncode")
