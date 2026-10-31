"""Proofs that the P0 hermeticity guard in ``tests/conftest.py`` bites.

A live operator incident: a suite run overwrote the operator's real
``~/.config/mnotify/config.toml`` with placeholder values, and the per-module
tripwire that existed then demonstrably did not cover the module that did it.
The fix is global (``conftest.hermetic_home`` + the session-scoped subprocess
guard); this module is what keeps the fix from rotting silently, in the same
spirit as ``test_socket_block_harness_works`` proving the socket blocker.

Two kinds of proof live here:

* in-process — what the guard does to *this* suite: HOME and the config env var
  are pinned under the test's own tree, a default-path ``write_config`` lands in
  the sandbox and never near the operator's file, and the keychain guard turns a
  ``security`` argv into an immediate failure;
* out-of-process — what the guard does to a *guilty* test: a generated probe
  file is run under pytest twice, once with the conftest guard loaded and once
  with ``--noconftest``. The probe must fail with the guard and pass without
  it, which pins the failure to the guard itself rather than to the probe.

The probe never touches the operator's real directories even when the guard is
broken: it writes into a stand-in directory wired in through the conftest seam
``MICRO_NOTIFY_TEST_WATCH_DIR``, which only ever *adds* a watched root. The real
``~/.config/mnotify`` is the thing the guard protects, not a test fixture.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from micro_notify import secrets
from micro_notify.config import CONFIG_ENV_VAR, config_path, write_config
from micro_notify.secrets import SECURITY_BINARY

import conftest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent

# The exact path shape from the incident: the default config path, unoverridden.
OPERATOR_CONFIG = conftest.REAL_USER_HOME / ".config" / "mnotify" / "config.toml"


# --- The incident's exact shape: default path with the env var unset ---------
def test_the_default_config_path_is_pinned_inside_the_test_sandbox(
    default_config_env: Path, tmp_path: Path
) -> None:
    """``MICRO_NOTIFY_CONFIG`` unset resolves under the *pinned* HOME, not the operator's."""
    assert CONFIG_ENV_VAR not in os.environ, "the opt-in fixture must have deleted it"
    resolved = config_path()
    assert resolved == default_config_env
    assert str(resolved).startswith(str(tmp_path)), (
        f"the default path escaped the test sandbox: {resolved}"
    )
    assert resolved != OPERATOR_CONFIG, (
        "HOME is not pinned: config_path() resolves to the operator's own file, "
        "which is the exact shape of the clobber incident"
    )
    assert conftest.REAL_USER_HOME not in resolved.parents


def test_write_config_with_env_unset_never_touches_the_operators_file(
    default_config_env: Path, tmp_path: Path
) -> None:
    """The incident replayed against the guard: the write lands in the sandbox.

    The autouse watch is part of the assertion here — this test writes a config
    while the default path is in effect, and it only reaches its own green if the
    guard's before/after stamp of the real ``~/.config/mnotify`` came out equal.
    """
    written = write_config(conftest.placeholder_config(tmp_path))
    assert written == default_config_env
    assert written.exists(), "the write must actually have landed in the sandbox"
    assert OPERATOR_CONFIG not in written.parents
    assert conftest.REAL_USER_HOME not in written.parents, (
        "a config written through the default path reached the real HOME — the "
        "guard's structural pin (HOME under tmp_path) did not hold"
    )
    # Reaching this line is the rest of the proof: the autouse watch compared the
    # before/after stamp of the real ~/.config/mnotify and found it identical.


# --- The structural pins are in force for every test ------------------------
def test_home_and_config_env_are_pinned_for_every_test(tmp_path: Path) -> None:
    """Any test that forgets the config fixture still cannot reach the real HOME."""
    home = Path(os.environ["HOME"])
    assert home == conftest._pinned_home(tmp_path)
    assert str(home).startswith(str(tmp_path.parent))
    target = Path(os.environ[CONFIG_ENV_VAR])
    assert str(target).startswith(str(home)), (
        "the config env var must default into the pinned HOME, not leak an ambient value"
    )
    assert not target.exists() or str(target).startswith(str(tmp_path))


def test_the_watch_covers_the_config_and_both_library_state_dirs() -> None:
    """The watched set is exactly the three real state roots under the real HOME."""
    real = conftest.REAL_USER_HOME
    assert conftest.REAL_STATE_DIRS == (
        real / ".config" / "mnotify",
        real / "Library" / "Logs" / "mnotify",
        real / "Library" / "Application Support" / "mnotify",
    )
    assert conftest.REAL_STATE_DIRS[0] == OPERATOR_CONFIG.parent


def test_the_guard_stamps_the_real_file_never_reads_it(tmp_path: Path) -> None:
    """A snapshot carries size/mtime/hash only — no bytes of a real config leak out.

    Proved against a stand-in file holding a canary string: nothing in the
    snapshot may contain it, because the guard must be able to detect a clobber
    without the operator's tenant id or mailbox ever entering test output.
    """
    watched = tmp_path / "stand-in-config"
    watched.mkdir()
    canary = "tenant_id = " + "0" * 36
    (watched / "config.toml").write_text(canary, encoding="utf-8")

    snapshot = conftest._snapshot(watched)
    assert set(snapshot) == {".", "config.toml"}
    for value in snapshot.values():
        assert canary not in repr(value)
        kind, _size, _mtime, digest = value
        assert kind in {"file", "dir"}
        assert digest == "" or len(digest) == 16, "digests are fixed-width hashes, never content"


def test_the_snapshot_detects_created_modified_and_deleted(tmp_path: Path) -> None:
    """All three clobber shapes are findings — a watch that only saw size would miss mtime."""
    root = tmp_path / "watched"
    root.mkdir()
    (root / "stable.toml").write_text("one", encoding="utf-8")
    before = conftest._snapshot(root)

    (root / "stable.toml").write_text("two", encoding="utf-8")  # same name, new bytes
    (root / "newcomer.toml").write_text("three", encoding="utf-8")
    stale = root / "doomed.toml"
    stale.write_text("four", encoding="utf-8")
    between = conftest._snapshot(root)
    stale.unlink()
    after = conftest._snapshot(root)

    created = conftest._diff_snapshot(between, after)
    modified = conftest._diff_snapshot(before, between)
    assert any(f == "deleted: doomed.toml" for f in created), created
    assert any(f == "modified: stable.toml" for f in modified), modified
    assert any(f == "created: newcomer.toml" for f in modified), modified


# --- The keychain guard: security(1) must never be exec'd -------------------
# Every in-process probe below names a *path that cannot exist*
# (``/nonexistent-mnotify-test/security``) or a read-only verb against a canary
# account that cannot exist. Both shapes still exercise the check — it matches the
# executable NAME — while making a broken guard harmless: a removed check then dies
# with ``FileNotFoundError``, or misses an absent keychain item. It must never be
# possible for a regression in the guard to execute the real ``security(1)``
# against a real account, which would echo the operator's secret into the test
# report, or to reach ``add-generic-password``, which would mutate the keychain.
UNEXECUTABLE_SECURITY = "/nonexistent-mnotify-test/security"
CANARY_ACCOUNT = "hermeticity.canary.does-not-exist"


def test_the_session_patch_is_the_one_in_force() -> None:
    """Structural proof: every exec entry point is the guarded object right now.

    Paired with the argv tests below, this pins the chain — the check bites AND
    it sits on the path a test would actually take. Proved structurally rather
    than by calling ``os.execvp`` for real: a broken exec-guard left uncaught
    would replace the pytest process, so the check itself is tested as a pure
    function and the wiring is asserted here.
    """
    assert subprocess.run is conftest._guarded_run
    assert subprocess.call is conftest._guarded_call
    assert subprocess.check_output is conftest._guarded_check_output
    assert subprocess.check_call is conftest._guarded_check_call
    assert subprocess.Popen is conftest._GuardedPopen
    assert os.system is conftest._guarded_system
    assert os.popen is conftest._guarded_os_popen
    assert os.execv is conftest._guarded_execv
    assert os.execvp is conftest._guarded_execvp
    assert os.execve is conftest._guarded_execve


def test_the_forbidden_set_is_the_documented_one() -> None:
    """The keychain binary and the admin binaries, and nothing narrower by accident.

    ``openssl`` is deliberately absent globally — ``tests/test_certgen.py`` proves
    the product's key generation against the real binary. If it ever appears here,
    that proof stops running and nobody notices; this pins the decision.
    """
    assert conftest.FORBIDDEN_BINARIES == frozenset(
        {"az", "pwsh", "brew", "powershell", "security"}
    )
    assert "security" in conftest.FORBIDDEN_BINARIES


@pytest.mark.parametrize(
    "argv",
    [
        [UNEXECUTABLE_SECURITY, "find-generic-password", "-s", secrets.SERVICE, "-a", CANARY_ACCOUNT],
        ["security", "find-generic-password", "-s", secrets.SERVICE, "-a", CANARY_ACCOUNT],
        [UNEXECUTABLE_SECURITY, "delete-generic-password", "-s", secrets.SERVICE, "-a", CANARY_ACCOUNT],
    ],
    ids=["absolute-path", "bare-name", "delete-verb"],
)
def test_the_keychain_guard_refuses_a_security_argv_before_executing_it(argv: list[str]) -> None:
    """``security`` fails the test at the argv, so the binary is never reached."""
    with pytest.raises(AssertionError, match="off-limits in tests"):
        subprocess.run(argv, capture_output=True, text=True, timeout=5)
    with pytest.raises(AssertionError, match="off-limits in tests"):
        subprocess.Popen(argv)


def test_the_keychain_guard_catches_a_path_object_as_argv_zero() -> None:
    """``Path`` argv is as good as a string: the check stringifies before matching."""
    with pytest.raises(AssertionError, match="off-limits in tests"):
        subprocess.run([Path(UNEXECUTABLE_SECURITY), "find-generic-password"])


@pytest.mark.parametrize(
    "command",
    [
        f"{UNEXECUTABLE_SECURITY} find-generic-password -s mnotify -a {CANARY_ACCOUNT}",
        "security find-generic-password -s mnotify -a " + CANARY_ACCOUNT,
    ],
    ids=["absolute-path-shell", "bare-name-shell"],
)
def test_the_shell_guards_refuse_a_security_command(command: str) -> None:
    """``os.system`` / ``os.popen`` are guarded too — a shell string is not a hole."""
    with pytest.raises(AssertionError, match="off-limits in tests"):
        os.system(command)
    with pytest.raises(AssertionError, match="off-limits in tests"):
        os.popen(command)


@pytest.mark.parametrize(
    "argv",
    [
        [UNEXECUTABLE_SECURITY, "find-generic-password", "-a", CANARY_ACCOUNT],
        [UNEXECUTABLE_SECURITY, "-i"],
    ],
    ids=["find-verb", "interactive-flag"],
)
def test_the_exec_guards_refuse_before_the_process_is_replaced(argv: list[str]) -> None:
    """``os.exec*`` runs the argv check; the check is pure, so nothing is exec'd here.

    The unexecutable path is what makes this probe safe to *run*: ``os.execvp``
    resolves its name through PATH, so with the check removed a bare ``security``
    would exec the real binary and replace the pytest process — the one failure
    mode that cannot report itself. A path that cannot exist turns that outcome
    into a plain ``FileNotFoundError``, and the guard still sees the same argv
    shape it guards in production. The wiring of these functions onto ``os`` is
    pinned by :func:`test_the_session_patch_is_the_one_in_force`.
    """
    for guard in (conftest._guarded_execv, conftest._guarded_execvp):
        with pytest.raises(AssertionError, match="off-limits in tests"):
            guard(argv[0], argv)
    with pytest.raises(AssertionError, match="off-limits in tests"):
        conftest._guarded_execve(argv[0], argv, {})


def test_a_permitted_subprocess_still_runs_after_the_guard() -> None:
    """The guard is narrow: refusing the forbidden names must not break real subprocess use.

    ``git`` and ``python`` stay available (the release-script and leak-guard
    modules depend on them), and the refusal happens before any exec.
    """
    result = subprocess.run([sys.executable, "-c", "print('ok')"], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.strip() == "ok"
    assert subprocess.check_output(["git", "--version"], cwd=REPO_ROOT).startswith(b"git version")


def test_a_permitted_command_naming_security_in_an_argument_still_runs() -> None:
    """The boundary, documented: only the leading token is matched.

    ``git log --grep security`` is a legitimate command — matching any token rather
    than the executable would fail it. A test that reached a forbidden binary
    through a wrapper (``sudo security ...``) would slip past this check; no shape
    in this suite does, and the watch on the real state tree is the backstop for
    that class of bypass.
    """
    out = subprocess.run(
        ["git", "log", "--grep", "security", "--max-count=1"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, (out.stdout, out.stderr)  # ran, i.e. was not refused


# --- Out-of-process canaries: the guard fails a guilty test ------------------
def run_probe(pytest_args: list[str], probe: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run a generated probe file under pytest and return what it reported."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *pytest_args, str(probe)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    return result


def write_probe(tmp_path: Path, body: str) -> Path:
    """A throwaway test module outside ``tests/`` — only the guard is under test here."""
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe = probe_dir / "test_probe.py"
    probe.write_text(body, encoding="utf-8")
    return probe


PROBE_BASE = "import os\nimport subprocess\nimport sys\nfrom pathlib import Path\n\n"
GUARD_PLUGIN_ARGS = ["-p", "conftest"]  # loads tests/conftest.py as a plugin, not as a collection root


def _probe_env(tmp_path: Path, watched: Path, with_guard: bool) -> dict[str, str]:
    env = dict(os.environ)
    env["MICRO_NOTIFY_TEST_WATCH_DIR"] = str(watched)
    if with_guard:
        # The conftest lives in tests/ and the probe sits outside it, so make it
        # importable for `-p conftest`. Nothing else about the environment changes.
        env["PYTHONPATH"] = str(TESTS_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    else:
        env.pop("PYTHONPATH", None)
    return env


def _assert_guarded_failure(result: subprocess.CompletedProcess[str], needle: str) -> None:
    output = result.stdout + result.stderr
    assert result.returncode != 0, f"the guard let a violating test pass:\n{output}"
    assert needle in output, f"expected {needle!r} in the failure report:\n{output}"


def test_a_probe_writing_a_watched_real_path_fails_the_suite(tmp_path: Path) -> None:
    """The watch bites: create a file where a real state root is watched.

    The write goes to the conftest seam directory, which stands in for
    ``~/.config/mnotify`` — the operator's real file is never a test fixture.
    """
    watched = tmp_path / "stand-in-real-state"
    watched.mkdir()
    probe = write_probe(
        tmp_path,
        PROBE_BASE
        + "def test_probe_writes_a_watched_file():\n"
        '    target = Path(os.environ["MICRO_NOTIFY_TEST_WATCH_DIR"]) / "config.toml"\n'
        '    target.write_text("placeholder", encoding="utf-8")\n',
    )

    watched_guarded = tmp_path / "stand-in-real-state-guarded"
    watched_guarded.mkdir()
    guarded = run_probe(
        GUARD_PLUGIN_ARGS, probe, _probe_env(tmp_path, watched_guarded, with_guard=True)
    )
    _assert_guarded_failure(guarded, "HERMETICITY VIOLATION")
    assert "created: config.toml" in guarded.stdout, guarded.stdout

    # Control: the same probe with the guard absent must pass on its own clean
    # watch dir, otherwise the guarded failure above proves nothing about the guard.
    watched_control = tmp_path / "stand-in-real-state-control"
    watched_control.mkdir()
    control = run_probe(
        ["--noconftest"], probe, _probe_env(tmp_path, watched_control, with_guard=False)
    )
    assert control.returncode == 0, (
        "the probe must pass with the guard absent, otherwise the guarded run above "
        "proves nothing:\n" + control.stdout + control.stderr
    )
    assert (watched_control / "config.toml").exists(), (
        "the probe itself did not perform the write, so the guarded failure was vacuous"
    )


def test_a_probe_deleting_a_watched_real_file_fails_the_suite(tmp_path: Path) -> None:
    """Deletion is as much a clobber as a write: the guard watches existence too."""
    watched = tmp_path / "stand-in-real-state"
    watched.mkdir()
    (watched / "config.toml").write_text("placeholder", encoding="utf-8")
    probe = write_probe(
        tmp_path,
        PROBE_BASE
        + "def test_probe_deletes_a_watched_file():\n"
        '    (Path(os.environ["MICRO_NOTIFY_TEST_WATCH_DIR"]) / "config.toml").unlink()\n',
    )

    guarded = run_probe(GUARD_PLUGIN_ARGS, probe, _probe_env(tmp_path, watched, with_guard=True))
    _assert_guarded_failure(guarded, "HERMETICITY VIOLATION")
    assert "deleted: config.toml" in guarded.stdout, guarded.stdout


def test_a_probe_invoking_the_security_binary_fails_the_suite(tmp_path: Path) -> None:
    """The keychain half of the guard, proven out-of-process the same way.

    With the guard absent the probe would exec ``security(1)``; the control run
    therefore uses a verb-and-account pair that cannot exist, so a broken guard
    costs a read-only miss rather than a keychain write. The guarded run must
    refuse at the argv instead.
    """
    watched = tmp_path / "stand-in-real-state"
    watched.mkdir()
    probe = write_probe(
        tmp_path,
        PROBE_BASE
        + "def test_probe_runs_security():\n"
        f'    subprocess.run(["{SECURITY_BINARY}", "find-generic-password",\n'
        '        "-s", "mnotify", "-a", "hermeticity.canary.does-not-exist"],\n'
        "        capture_output=True, text=True, timeout=10)\n",
    )

    guarded = run_probe(GUARD_PLUGIN_ARGS, probe, _probe_env(tmp_path, watched, with_guard=True))
    _assert_guarded_failure(guarded, "off-limits in tests")
    assert "attempted to execute 'security'" in guarded.stdout, guarded.stdout


def test_a_probe_pointing_the_config_env_at_a_real_file_fails_the_suite(tmp_path: Path) -> None:
    """The env-var half: a test may point at a *missing* path, never a real one."""
    watched = tmp_path / "stand-in-real-state"
    watched.mkdir()
    outside = tmp_path / "outside-sandbox"
    outside.mkdir()
    victim = outside / "someone-elses-config.toml"
    victim.write_text("placeholder", encoding="utf-8")
    probe = write_probe(
        tmp_path,
        PROBE_BASE
        + "def test_probe_points_env_at_a_real_file(monkeypatch):\n"
        f'    monkeypatch.setenv("{CONFIG_ENV_VAR}", {str(victim)!r})\n',
    )

    control = run_probe(
        ["--noconftest"], probe, _probe_env(tmp_path, watched, with_guard=False)
    )
    assert control.returncode == 0, control.stdout + control.stderr

    guarded = run_probe(GUARD_PLUGIN_ARGS, probe, _probe_env(tmp_path, watched, with_guard=True))
    _assert_guarded_failure(guarded, "HERMETICITY VIOLATION")
    assert "outside this test's sandbox" in guarded.stdout, guarded.stdout
