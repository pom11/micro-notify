"""Linux/container file secret backend and backend-dispatch contract (L1).

All values here are fabricated canaries. Nothing reads the live keychain, the
live config or any real secret; file tests use ``tmp_path`` only.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from micro_notify import EXIT_AUTH, EXIT_USAGE, secrets
from micro_notify import secrets_file

CANARY = "CANARY-FILE-SECRET-7f3a-do-not-log"
CANARY_PEM = "CANARY-KEY-LINE-1\nCANARYPRIVATEKEYBODYNOTAREALKEY\nCANARY-KEY-END\n"


def completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["security"], returncode, stdout, stderr)


# --- Fixtures --------------------------------------------------------------
@pytest.fixture
def file_backend(tmp_path, monkeypatch):
    root = tmp_path / "secrets"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_FILE)
    monkeypatch.setenv(secrets.SECRETS_DIR_ENV, str(root))
    return root


def write_secret(root, account: str, value: str, mode: int = 0o600):
    path = root / secrets.account_filename(account)
    path.write_text(value, encoding="utf-8")
    path.chmod(mode)
    return path


# --- S1: dispatch and the account -> filename function ---------------------
def test_default_backend_is_keychain_on_darwin() -> None:
    assert secrets.select_backend({}, platform="darwin") == secrets.BACKEND_KEYCHAIN


@pytest.mark.parametrize("platform", ["linux", "win32", "freebsd14"])
def test_default_backend_is_an_explicit_usage_error_off_darwin(platform: str) -> None:
    with pytest.raises(secrets.SecretBackendError) as excinfo:
        secrets.select_backend({}, platform=platform)
    assert excinfo.value.exit_code == EXIT_USAGE
    assert secrets.SECRETS_BACKEND_ENV in str(excinfo.value)


@pytest.mark.parametrize(
    "value", [secrets.BACKEND_KEYCHAIN, secrets.BACKEND_FILE]
)
def test_explicit_backend_value_is_honoured_on_any_platform(value: str) -> None:
    assert secrets.select_backend({secrets.SECRETS_BACKEND_ENV: value}, platform="linux") == value
    assert secrets.select_backend({secrets.SECRETS_BACKEND_ENV: value}, platform="darwin") == value


def test_unknown_backend_value_fails_closed() -> None:
    with pytest.raises(secrets.SecretBackendError) as excinfo:
        secrets.select_backend({secrets.SECRETS_BACKEND_ENV: "vault"}, platform="darwin")
    assert excinfo.value.exit_code == EXIT_USAGE
    assert "vault" in str(excinfo.value)


def test_empty_backend_value_counts_as_unset() -> None:
    assert secrets.select_backend({secrets.SECRETS_BACKEND_ENV: ""}, platform="darwin") == "keychain"
    with pytest.raises(secrets.SecretBackendError):
        secrets.select_backend({secrets.SECRETS_BACKEND_ENV: ""}, platform="linux")


def test_select_backend_reads_the_process_environment(monkeypatch) -> None:
    monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_FILE)
    assert secrets.select_backend() == secrets.BACKEND_FILE
    monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_KEYCHAIN)
    assert secrets.select_backend() == secrets.BACKEND_KEYCHAIN


def test_account_filename_is_literal_for_non_teams_accounts() -> None:
    assert secrets.account_filename(secrets.ACCOUNT_CERT_PEM) == "graph.certificate_pem"
    assert secrets.account_filename(secrets.ACCOUNT_CLIENT_SECRET) == "graph.client_secret"
    assert secrets.account_filename("Graph.Case_Sensitive") == "Graph.Case_Sensitive"


def test_account_filename_maps_only_the_teams_separator() -> None:
    assert secrets.account_filename("teams:facturare") == "teams__facturare"
    assert secrets.account_filename(secrets.teams_account("alerts")) == "teams__alerts"


@pytest.mark.parametrize("account", ["", None, ".", "..", "a/b", "a\\b", "a\x00b"])
def test_account_filename_refuses_names_that_could_escape_the_directory(account) -> None:
    with pytest.raises(secrets.KeychainError):
        secrets.account_filename(account)


def test_file_backend_requires_the_directory_env(monkeypatch) -> None:
    monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_FILE)
    monkeypatch.delenv(secrets.SECRETS_DIR_ENV, raising=False)
    with pytest.raises(secrets.SecretBackendError) as excinfo:
        secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    assert excinfo.value.exit_code == EXIT_USAGE
    assert secrets.SECRETS_DIR_ENV in str(excinfo.value)


# --- S2: file backend read permission matrix -------------------------------
def test_get_reads_a_0600_file_exactly(file_backend) -> None:
    write_secret(file_backend, secrets.ACCOUNT_CERT_PEM, CANARY_PEM, 0o600)
    assert secrets.get(secrets.ACCOUNT_CERT_PEM) == CANARY_PEM


def test_get_accepts_0400_owned_by_the_effective_uid(file_backend) -> None:
    write_secret(file_backend, secrets.ACCOUNT_CLIENT_SECRET, CANARY, 0o400)
    assert secrets.get(secrets.ACCOUNT_CLIENT_SECRET) == CANARY


def test_get_accepts_a_provisioned_read_only_file_from_another_owner(
    file_backend, monkeypatch
) -> None:
    path = write_secret(file_backend, secrets.ACCOUNT_CLIENT_SECRET, CANARY, 0o444)
    monkeypatch.setattr(secrets_file.os, "geteuid", lambda: os.getuid() + 12345)
    assert path.stat().st_uid != os.getuid() + 12345
    assert secrets.get(secrets.ACCOUNT_CLIENT_SECRET) == CANARY


def test_world_readable_but_owner_writable_file_is_unreadable(file_backend) -> None:
    write_secret(file_backend, secrets.ACCOUNT_CLIENT_SECRET, CANARY, 0o644)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    assert not isinstance(excinfo.value, secrets.KeychainItemMissing)
    assert excinfo.value.exit_code == EXIT_AUTH
    assert CANARY not in str(excinfo.value)
    assert secrets.probe(secrets.ACCOUNT_CLIENT_SECRET).is_unreadable


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_group_or_other_writable_file_is_unreadable(file_backend, mode: int) -> None:
    write_secret(file_backend, secrets.ACCOUNT_CLIENT_SECRET, CANARY, mode)
    verdict = secrets.probe(secrets.ACCOUNT_CLIENT_SECRET)
    assert verdict.is_unreadable and not verdict.is_absent
    assert CANARY not in verdict.reason


def test_symlink_is_unreadable_not_absent(file_backend, tmp_path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text(CANARY, encoding="utf-8")
    target.chmod(0o600)
    link = file_backend / secrets.account_filename(secrets.ACCOUNT_CLIENT_SECRET)
    link.symlink_to(target)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    assert not isinstance(excinfo.value, secrets.KeychainItemMissing)
    assert "symlink" in str(excinfo.value)
    assert secrets.probe(secrets.ACCOUNT_CLIENT_SECRET).is_unreadable


def test_directory_entry_is_unreadable(file_backend) -> None:
    path = file_backend / secrets.account_filename(secrets.ACCOUNT_CLIENT_SECRET)
    path.mkdir()
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    assert not isinstance(excinfo.value, secrets.KeychainItemMissing)


def test_non_utf8_file_is_unreadable(file_backend) -> None:
    path = file_backend / secrets.account_filename(secrets.ACCOUNT_CLIENT_SECRET)
    path.write_bytes(b"\xff\xfe\x00not-utf8")
    path.chmod(0o600)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    assert "not valid UTF-8" in str(excinfo.value)


def test_missing_file_is_typed_absent(file_backend) -> None:
    with pytest.raises(secrets.KeychainItemMissing) as excinfo:
        secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    assert excinfo.value.exit_code == EXIT_AUTH
    assert "44" in str(excinfo.value)
    assert secrets.probe(secrets.ACCOUNT_CLIENT_SECRET).is_absent
    assert secrets.has(secrets.ACCOUNT_CLIENT_SECRET) is False


def test_empty_file_reads_empty_and_probe_says_absent(file_backend) -> None:
    write_secret(file_backend, secrets.ACCOUNT_CLIENT_SECRET, "", 0o600)
    assert secrets.get(secrets.ACCOUNT_CLIENT_SECRET) == ""
    assert secrets.probe(secrets.ACCOUNT_CLIENT_SECRET).is_absent
    assert secrets.has(secrets.ACCOUNT_CLIENT_SECRET) is False


def test_probe_read_value_false_reports_presence_without_the_value(file_backend) -> None:
    write_secret(file_backend, secrets.ACCOUNT_CERT_PEM, CANARY_PEM, 0o600)
    verdict = secrets.probe(secrets.ACCOUNT_CERT_PEM, read_value=False)
    assert verdict.is_present
    assert verdict.value == ""
    assert CANARY_PEM not in repr(verdict)


# --- S3: file backend write / delete ---------------------------------------
def test_set_secret_writes_exactly_0600_and_leaves_no_temp_file(file_backend) -> None:
    secrets.set_secret(secrets.ACCOUNT_CERT_PEM, CANARY_PEM)
    path = file_backend / "graph.certificate_pem"
    assert path.read_text(encoding="utf-8") == CANARY_PEM
    assert (path.stat().st_mode & 0o777) == 0o600
    assert sorted(p.name for p in file_backend.iterdir()) == ["graph.certificate_pem"]


def test_set_secret_updates_an_existing_file_in_place(file_backend) -> None:
    secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, "first-value")
    secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, "second-value")
    assert secrets.get(secrets.ACCOUNT_CLIENT_SECRET) == "second-value"


def test_set_secret_refuses_a_read_only_directory(file_backend) -> None:
    file_backend.chmod(0o500)
    try:
        with pytest.raises(secrets.KeychainError) as excinfo:
            secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, CANARY)
    finally:
        file_backend.chmod(0o700)
    message = str(excinfo.value)
    assert str(file_backend) in message
    assert "not writable" in message
    assert CANARY not in message
    assert not (file_backend / "graph.client_secret").exists()


def test_set_secret_refuses_a_missing_directory(file_backend) -> None:
    missing = file_backend / "gone"
    missing.mkdir()
    missing.rmdir()
    import micro_notify.secrets as facade
    old = os.environ[secrets.SECRETS_DIR_ENV]
    os.environ[secrets.SECRETS_DIR_ENV] = str(missing)
    try:
        with pytest.raises(secrets.KeychainError, match="does not exist") as excinfo:
            facade.set_secret(secrets.ACCOUNT_CLIENT_SECRET, CANARY)
    finally:
        os.environ[secrets.SECRETS_DIR_ENV] = old
    assert str(missing) in str(excinfo.value)


def test_set_secret_refuses_a_symlinked_directory(tmp_path, monkeypatch) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_FILE)
    monkeypatch.setenv(secrets.SECRETS_DIR_ENV, str(link))
    with pytest.raises(secrets.KeychainError, match="not a directory"):
        secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, CANARY)


def test_set_secret_rejects_non_string_values(file_backend) -> None:
    with pytest.raises(secrets.KeychainError, match="must be a string"):
        secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, None)  # type: ignore[arg-type]
    assert list(file_backend.iterdir()) == []


def test_delete_returns_true_then_false(file_backend) -> None:
    write_secret(file_backend, "teams:alerts", CANARY, 0o600)
    assert secrets.delete("teams:alerts") is True
    assert secrets.delete("teams:alerts") is False
    assert secrets.probe("teams:alerts").is_absent


def test_delete_unlinks_a_symlink_without_touching_its_target(file_backend, tmp_path) -> None:
    target = tmp_path / "target"
    target.write_text(CANARY, encoding="utf-8")
    link = file_backend / "teams__alerts"
    link.symlink_to(target)
    assert secrets.delete("teams:alerts") is True
    assert not link.exists()
    assert target.read_text(encoding="utf-8") == CANARY


def test_write_failure_leaves_no_temp_file_and_no_value_in_the_message(
    file_backend, monkeypatch
) -> None:
    def explode(*_args, **_kwargs):
        raise OSError(f"disk full while writing {CANARY}")

    monkeypatch.setattr(secrets_file.os, "replace", explode)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.set_secret(secrets.ACCOUNT_CLIENT_SECRET, CANARY)
    assert CANARY not in str(excinfo.value)
    assert list(file_backend.iterdir()) == []


def test_delete_failure_is_a_keychain_error_naming_the_path(file_backend, monkeypatch) -> None:
    write_secret(file_backend, "teams:alerts", CANARY, 0o600)

    def refused(*_args, **_kwargs):
        raise PermissionError(CANARY)

    monkeypatch.setattr(secrets_file.os, "unlink", refused)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.delete("teams:alerts")
    assert str(file_backend) in str(excinfo.value)
    assert CANARY not in str(excinfo.value)


# --- S4: the same contract against both backends ---------------------------
class KeychainStore:
    """Minimal fake runner: same argv shapes, in-memory items."""

    def __init__(self) -> None:
        self.items: dict[str, str] = {}
        self.failures: dict[str, int] = {}

    def __call__(self, args, **_kwargs):
        argv = [str(a) for a in args]
        verb = argv[1]
        account = argv[argv.index("-a") + 1]
        if verb == "find-generic-password":
            if account in self.failures:
                return completed(self.failures[account])
            if account not in self.items:
                return completed(44)
            return completed(0, self.items[account])
        if verb == "add-generic-password":
            self.items[account] = argv[argv.index("-w") + 1]
            return completed(0)
        if verb == "delete-generic-password":
            if account not in self.items:
                return completed(44)
            del self.items[account]
            return completed(0)
        return completed(2)

    def seed(self, account: str, value: str) -> None:
        self.items[account] = value

    def unreadable(self, account: str) -> None:
        self.failures[account] = 60

    def path(self, account: str):
        return account


class FileStore:
    def __init__(self, root) -> None:
        self.root = root

    def path(self, account: str):
        return self.root / secrets_file.account_filename(account)

    def seed(self, account: str, value: str) -> None:
        path = self.path(account)
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)

    def unreadable(self, account: str) -> None:
        self.path(account).chmod(0o666)


@pytest.fixture(params=["file", "keychain"])
def backend_store(request, tmp_path, monkeypatch):
    if request.param == "file":
        root = tmp_path / "secrets"
        root.mkdir(mode=0o700)
        monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_FILE)
        monkeypatch.setenv(secrets.SECRETS_DIR_ENV, str(root))
        yield FileStore(root)
    else:
        monkeypatch.setenv(secrets.SECRETS_BACKEND_ENV, secrets.BACKEND_KEYCHAIN)
        store = KeychainStore()
        secrets.set_runner(store)
        try:
            yield store
        finally:
            secrets.set_runner(None)


def test_cross_backend_round_trip(backend_store) -> None:
    account = "teams:alerts"
    assert secrets.set_secret(account, CANARY) is None
    assert secrets.get(account) == CANARY
    assert secrets.has(account) is True
    verdict = secrets.probe(account)
    assert verdict.is_present and verdict.value == CANARY
    assert secrets.delete(account) is True
    assert secrets.has(account) is False


def test_cross_backend_absent_is_typed_and_closes_as_44(backend_store) -> None:
    account = "teams:absent"
    with pytest.raises(secrets.KeychainItemMissing) as excinfo:
        secrets.get(account)
    assert excinfo.value.exit_code == EXIT_AUTH
    assert "44" in str(excinfo.value)
    assert secrets.probe(account).is_absent
    assert secrets.delete(account) is False


def test_cross_backend_unreadable_is_never_absent(backend_store) -> None:
    account = "graph.client_secret"
    backend_store.seed(account, CANARY)
    backend_store.unreadable(account)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.get(account)
    assert not isinstance(excinfo.value, secrets.KeychainItemMissing)
    assert excinfo.value.exit_code == EXIT_AUTH
    verdict = secrets.probe(account)
    assert verdict.is_unreadable and not verdict.is_absent and verdict.value == ""


def test_cross_backend_leak_guard_messages_and_stderr(backend_store, capsys) -> None:
    account = "graph.certificate_pem"
    backend_store.seed(account, CANARY)
    backend_store.unreadable(account)
    with pytest.raises(secrets.KeychainError) as excinfo:
        secrets.get(account)
    verdict = secrets.probe(account)
    captured = capsys.readouterr()
    assert CANARY not in str(excinfo.value)
    assert CANARY not in verdict.reason
    assert CANARY not in captured.out
    assert CANARY not in captured.err
