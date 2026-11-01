"""Tests for micro_notify.secrets (design section 3 / 3.4).

``/usr/bin/security`` is never invoked: every test injects a runner or uses the
shared ``fake_keychain`` fixture.
"""

from __future__ import annotations

import subprocess

import pytest

from micro_notify import EXIT_AUTH
from micro_notify import secrets


class RecordingRunner:
    """Stands in for subprocess.run and records the exact argv."""

    def __init__(self, results=None) -> None:
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []
        self.results = results or []

    def __call__(self, args, **kwargs):
        argv = [str(a) for a in args]
        self.calls.append(argv)
        self.kwargs.append(kwargs)
        if len(self.results) > len(self.calls) - 1:
            result = self.results[len(self.calls) - 1]
        else:
            result = subprocess.CompletedProcess(argv, 0, stdout="s3cr3t-value\n", stderr="")
        if isinstance(result, Exception):
            raise result
        return result

    @property
    def last(self) -> list[str]:
        return self.calls[-1]


def completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["security"], returncode, stdout, stderr)


# --- Read ------------------------------------------------------------------
def test_get_builds_the_documented_argv_and_returns_stdout() -> None:
    runner = RecordingRunner([completed(0, "the-value\n")])
    secrets.set_runner(runner)
    try:
        assert secrets.get("graph.client_secret") == "the-value"
    finally:
        secrets.set_runner(None)

    assert runner.last == [
        secrets.SECURITY_BINARY,
        "find-generic-password",
        "-s",
        secrets.SERVICE,
        "-a",
        "graph.client_secret",
        "-w",
    ]
    assert runner.kwargs[0]["capture_output"] is True
    assert runner.kwargs[0]["text"] is True


def test_get_decodes_the_hex_dump_security_prints_for_multiline_values() -> None:
    """security(1) -w prints a value containing a newline (a PEM key) as hex."""
    # Multi-line canary; deliberately not a PEM header (the leak guard scans tests).
    pem = "CANARY-KEY-LINE-1\nCANARYPRIVATEKEYBODYNOTAREALKEY\nCANARY-KEY-END\n"
    runner = RecordingRunner([completed(0, pem.encode().hex() + "\n")])
    secrets.set_runner(runner)
    try:
        assert secrets.get("graph.certificate_pem") == pem
    finally:
        secrets.set_runner(None)


@pytest.mark.parametrize(
    "value",
    ["0123456789ABCDEF0123456789ABCDEF01234567", "deadbeef", "abc", "c0ffee00"],
)
def test_get_leaves_hex_looking_single_line_secrets_alone(value: str) -> None:
    runner = RecordingRunner([completed(0, value + "\n")])
    secrets.set_runner(runner)
    try:
        assert secrets.get("graph.certificate_thumbprint") == value
    finally:
        secrets.set_runner(None)


def test_get_passes_no_shell_and_no_env_carrying_the_value() -> None:
    runner = RecordingRunner([completed(0, "v\n")])
    secrets.set_runner(runner)
    try:
        secrets.get("graph.client_secret")
    finally:
        secrets.set_runner(None)
    assert "shell" not in runner.kwargs[0] or runner.kwargs[0]["shell"] is False
    assert "env" not in runner.kwargs[0]


def test_missing_item_raises_a_keychain_error_naming_the_account_only() -> None:
    runner = RecordingRunner(
        [completed(44, "", "security: SecKeychainSearchCopyNext: The specified item could not be found.")]
    )
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError) as excinfo:
            secrets.get("graph.client_secret")
    finally:
        secrets.set_runner(None)

    message = str(excinfo.value)
    assert "graph.client_secret" in message
    assert "44" in message
    assert excinfo.value.exit_code == EXIT_AUTH


def test_error_message_never_carries_stderr_or_the_value() -> None:
    # A hostile stderr that repeats the value must not reach the exception text.
    runner = RecordingRunner([completed(1, "", "refused for value s3cr3t-value")])
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError) as excinfo:
            secrets.get("teams:alerts")
    finally:
        secrets.set_runner(None)
    assert "s3cr3t-value" not in str(excinfo.value)


def test_missing_binary_raises_a_keychain_error_without_a_traceback_leak() -> None:
    runner = RecordingRunner([FileNotFoundError("/usr/bin/security")])
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError, match="binary not found"):
            secrets.get("graph.client_secret")
    finally:
        secrets.set_runner(None)


def test_timeout_raises_a_keychain_error_without_leaking_anything() -> None:
    runner = RecordingRunner(
        [subprocess.TimeoutExpired(["security", "find-generic-password"], timeout=15)]
    )
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError, match="timed out") as excinfo:
            secrets.get("graph.certificate_pem")
    finally:
        secrets.set_runner(None)
    assert "SecKeychain" not in str(excinfo.value)


# --- Write -----------------------------------------------------------------
def test_set_secret_uses_update_flag_and_passes_value_as_its_own_argv_item() -> None:
    runner = RecordingRunner([completed(0)])
    secrets.set_runner(runner)
    try:
        secrets.set_secret("graph.client_secret", "abcdef")
    finally:
        secrets.set_runner(None)

    argv = runner.last
    assert argv[:2] == [secrets.SECURITY_BINARY, "add-generic-password"]
    assert "-U" in argv
    assert argv[argv.index("-a") + 1] == "graph.client_secret"
    assert argv[argv.index("-w") + 1] == "abcdef"
    assert argv[argv.index("-s") + 1] == secrets.SERVICE


def test_set_secret_message_never_includes_the_value_on_failure() -> None:
    runner = RecordingRunner([completed(1, "", "denied")])
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError) as excinfo:
            secrets.set_secret("graph.client_secret", "super-secret-value")
    finally:
        secrets.set_runner(None)
    assert "super-secret-value" not in str(excinfo.value)
    assert "graph.client_secret" in str(excinfo.value)


def test_set_secret_rejects_non_string_values() -> None:
    runner = RecordingRunner()
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError, match="must be a string"):
            secrets.set_secret("graph.client_secret", None)  # type: ignore[arg-type]
    finally:
        secrets.set_runner(None)
    assert runner.calls == []


# --- Delete / has ----------------------------------------------------------
def test_delete_returns_true_when_the_item_existed() -> None:
    runner = RecordingRunner([completed(0)])
    secrets.set_runner(runner)
    try:
        assert secrets.delete("teams:alerts") is True
    finally:
        secrets.set_runner(None)
    assert runner.last[:2] == [secrets.SECURITY_BINARY, "delete-generic-password"]
    assert "-w" not in runner.last


def test_delete_reports_false_for_a_missing_item_without_raising() -> None:
    runner = RecordingRunner([completed(44)])
    secrets.set_runner(runner)
    try:
        assert secrets.delete("teams:ghost") is False
    finally:
        secrets.set_runner(None)


def test_delete_surfaces_a_real_failure() -> None:
    runner = RecordingRunner([completed(1)])
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError, match="delete failed"):
            secrets.delete("teams:alerts")
    finally:
        secrets.set_runner(None)


def test_has_is_true_only_for_a_non_empty_value() -> None:
    secrets.set_runner(RecordingRunner([completed(0, "value\n")]))
    try:
        assert secrets.has("graph.client_secret") is True
    finally:
        secrets.set_runner(None)

    secrets.set_runner(RecordingRunner([completed(0, "\n")]))
    try:
        assert secrets.has("graph.client_secret") is False
    finally:
        secrets.set_runner(None)

    secrets.set_runner(RecordingRunner([completed(44)]))
    try:
        assert secrets.has("graph.client_secret") is False
    finally:
        secrets.set_runner(None)


# --- Absent vs unreadable (BUG2 follow-through, t_362c34cc) -----------------
# ``has()`` collapses every failure into False, which is what let a locked
# keychain during ``mnotify admin bootstrap`` read as "no certificate pair" and
# re-key the tenant (B6, 2026-10-31; the keychain key's RSA modulus proved the
# replacement). The three-way verdict lives here so the *read path* can fail
# closed at the seam where a misread costs the operator a key pair; ``has()``
# stays a best-effort status bool for every reporting caller.

def test_probe_reports_present_with_the_value_and_the_documented_argv() -> None:
    runner = RecordingRunner([completed(0, "the-value\n")])
    secrets.set_runner(runner)
    try:
        verdict = secrets.probe("graph.client_secret")
    finally:
        secrets.set_runner(None)

    assert verdict.is_present
    assert not verdict.is_absent and not verdict.is_unreadable
    assert verdict.account == "graph.client_secret"
    assert verdict.value == "the-value"
    assert verdict.reason == ""
    # Same argv get() builds — one read shape, two verdict APIs.
    assert runner.last == [
        secrets.SECURITY_BINARY,
        "find-generic-password",
        "-s",
        secrets.SERVICE,
        "-a",
        "graph.client_secret",
        "-w",
    ]


def test_probe_reports_absent_for_security_s_exit_44() -> None:
    """Exit 44 is security(1)'s documented "item not found" — provably absent."""
    runner = RecordingRunner([completed(44, "", "The specified item could not be found.")])
    secrets.set_runner(runner)
    try:
        verdict = secrets.probe("graph.client_secret")
    finally:
        secrets.set_runner(None)

    assert verdict.is_absent
    assert not verdict.is_present and not verdict.is_unreadable
    assert verdict.value == ""


def test_probe_reports_absent_for_an_empty_stored_value() -> None:
    runner = RecordingRunner([completed(0, "\n")])
    secrets.set_runner(runner)
    try:
        verdict = secrets.probe("graph.client_secret")
    finally:
        secrets.set_runner(None)
    assert verdict.is_absent


def test_probe_reports_unreadable_for_any_other_exit_never_absent() -> None:
    """A locked keychain must not be able to masquerade as "nothing stored"."""
    runner = RecordingRunner([completed(60, "", "keychain access denied")])
    secrets.set_runner(runner)
    try:
        verdict = secrets.probe("graph.client_secret")
    finally:
        secrets.set_runner(None)

    assert verdict.is_unreadable
    assert not verdict.is_absent and not verdict.is_present
    assert verdict.value == ""
    assert "60" in verdict.reason  # the exit code is part of the diagnosis
    assert "graph.client_secret" in verdict.account


def test_probe_unreadable_reason_never_carries_stderr_or_a_value() -> None:
    runner = RecordingRunner([completed(60, "s3cr3t-value", "refused for s3cr3t-value")])
    secrets.set_runner(runner)
    try:
        verdict = secrets.probe("teams:alerts")
    finally:
        secrets.set_runner(None)
    assert "s3cr3t-value" not in verdict.reason
    assert "s3cr3t-value" not in verdict.value


def test_probe_reports_unreadable_when_the_binary_or_the_clock_fails() -> None:
    secrets.set_runner(RecordingRunner([FileNotFoundError("/usr/bin/security")]))
    try:
        verdict = secrets.probe("graph.client_secret")
    finally:
        secrets.set_runner(None)
    assert verdict.is_unreadable
    assert "not found" in verdict.reason

    secrets.set_runner(
        RecordingRunner([subprocess.TimeoutExpired(["security"], timeout=15)])
    )
    try:
        verdict = secrets.probe("graph.client_secret")
    finally:
        secrets.set_runner(None)
    assert verdict.is_unreadable
    assert "timed out" in verdict.reason


def test_probe_rejects_an_empty_account_before_any_subprocess() -> None:
    runner = RecordingRunner()
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError):
            secrets.probe("")  # type: ignore[arg-type]
    finally:
        secrets.set_runner(None)
    assert runner.calls == []


def test_get_raises_a_typed_error_for_a_provably_missing_item() -> None:
    """Absence and failure stay catchable apart: KeychainItemMissing, and the
    existing ``except KeychainError`` catches keep working unchanged."""
    runner = RecordingRunner([completed(44, "", "item not found")])
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainItemMissing) as excinfo:
            secrets.get("graph.client_secret")
    finally:
        secrets.set_runner(None)

    assert isinstance(excinfo.value, secrets.KeychainError)
    message = str(excinfo.value)
    assert "graph.client_secret" in message
    assert "44" in message
    assert excinfo.value.exit_code == EXIT_AUTH


def test_get_raises_plain_keychain_error_for_a_locked_keychain() -> None:
    """Anything but exit 44 is a failure, not a typed absence — a caller that
    catches only KeychainItemMissing must not treat it as "no item"."""
    runner = RecordingRunner([completed(60, "", "keychain access denied")])
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError) as excinfo:
            secrets.get("graph.client_secret")
    finally:
        secrets.set_runner(None)
    assert not isinstance(excinfo.value, secrets.KeychainItemMissing)


def test_has_stays_a_best_effort_bool_even_when_the_keychain_is_unreadable() -> None:
    """Pinned contract, not an accident: ``has()`` answers status questions
    (doctor, setup, config show, teams list) where "missing" and "cannot tell"
    share one report line. It must stay total — never raises — and it must
    never be the basis of a destructive decision; that is what probe() is for.
    """
    runner = RecordingRunner([completed(60, "", "keychain access denied")])
    secrets.set_runner(runner)
    try:
        assert secrets.has("graph.client_secret") is False
    finally:
        secrets.set_runner(None)


# --- Names -----------------------------------------------------------------
def test_teams_account_uses_the_declared_prefix() -> None:
    assert secrets.teams_account("alerts") == "teams:alerts"
    assert secrets.ACCOUNT_CERT_PEM == "graph.certificate_pem"
    assert secrets.ACCOUNT_CERT_THUMBPRINT == "graph.certificate_thumbprint"
    assert secrets.ACCOUNT_CLIENT_SECRET == "graph.client_secret"
    assert secrets.SERVICE == "mnotify"


@pytest.mark.parametrize("target", ["", "two words", " "])
def test_teams_account_rejects_unusable_names(target: str) -> None:
    with pytest.raises(secrets.KeychainError):
        secrets.teams_account(target)


@pytest.mark.parametrize("account", ["", None])
def test_empty_account_is_rejected_before_any_subprocess(account) -> None:
    runner = RecordingRunner()
    secrets.set_runner(runner)
    try:
        with pytest.raises(secrets.KeychainError):
            secrets.get(account)  # type: ignore[arg-type]
    finally:
        secrets.set_runner(None)
    assert runner.calls == []


# --- Integration with the shared fixture ----------------------------------
def test_fake_keychain_round_trips_without_touching_the_binary(fake_keychain) -> None:
    secrets.set_secret("teams:alerts", "https://example.com/hidden-canary-sig")
    assert secrets.get("teams:alerts") == "https://example.com/hidden-canary-sig"
    assert secrets.has("teams:alerts") is True
    assert secrets.delete("teams:alerts") is True
    assert secrets.has("teams:alerts") is False
    assert fake_keychain.security_binaries_invoked == []


def test_fake_keychain_is_visible_to_module_level_callers(fake_keychain) -> None:
    fake_keychain.seed("graph.client_secret", "preset-value")
    assert secrets.get("graph.client_secret") == "preset-value"
    assert fake_keychain.audit == ["graph.client_secret"]
