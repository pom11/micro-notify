"""Tests for :mod:`micro_notify.admin.certupload` (card B3).

Nothing here can touch a real tenant, a real keychain or a real ``openssl``: the
autouse ``no_real_admin_binaries`` guard turns the *real* subprocess layer into a
tripwire for az/pwsh/brew/security/openssl, the shared ``fake_keychain`` answers
every keychain read and write, and each test installs its own fake ``CommandRunner``
holding canned ``az`` JSON. Certificates are throwaway pairs built at runtime by
``cryptography`` — no key material of any kind is stored in this file, and the leak
guard's placeholder rules apply to every id in it.

The five behaviours the card pins:

* ``--end-date`` is present **and equals the certificate's own ``notAfter``** — the
  live 2026-10-30 failure where ``az`` silently capped a 825-day credential at one
  year. Pinned twice: against the exact formatted date, and against the one-year
  horizon it must not have;
* ``--append`` is present (without it az clears every existing credential first);
* only the **public** PEM ever reaches argv — the private key bytes, the keychain
  account names and the keychain values are asserted absent from every call;
* the exists path regenerates nothing at all (no openssl, no keychain write, no
  upload);
* a thumbprint mismatch fails loudly instead of reporting success.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from micro_notify import EXIT_AUTH, EXIT_USAGE, UsageError
from micro_notify.admin import certupload
from micro_notify.admin.certupload import (
    CERT_END_DATE_FORMAT,
    OUTCOME_CREATED,
    OUTCOME_EXISTS,
    CertUploadError,
    CertificateProvisioning,
    StaleKeyPairRefusal,
    UploadedCredential,
    certificate_end_date,
    ensure_certificate_credential,
    keychain_thumbprint,
    list_uploaded_credentials,
    plan_certificate_upload,
    reset_command,
    upload_certificate,
    verify_uploaded,
    write_public_certificate_file,
)
from micro_notify.admin.runner import CommandError, DryRunRunner, set_runner
from micro_notify import secrets

# --- Placeholders only (design §5, leak guard) -------------------------------
APP_ID = "00000000-0000-0000-0000-000000000000"
OTHER_APP_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

# Binaries a unit test must never execute, whatever the reason. ``openssl`` is on
# the list because card B3 must drive cert generation through certgen's injected
# runner, never by spawning the real binary.
FORBIDDEN_BINARIES = frozenset({"az", "pwsh", "brew", "powershell", "security", "openssl"})


# --- Throwaway key material (generated, never stored) ------------------------
def make_pair(days: int = 825, common_name: str = "micro-notify") -> dict[str, str]:
    """A fresh self-signed key pair, built at runtime and kept in memory.

    The card forbids any real key material in the repo, so nothing here is a
    fixture PEM: every test that needs a certificate calls this and gets a key that
    dies with the process. ``days`` is deliberately variable — the end-date pin has
    to prove the value comes from the certificate rather than from a constant.
    """
    not_after = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(days=days)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x5EED)
        .not_valid_before(not_after - datetime.timedelta(days=days))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return {
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
        "thumbprint": certificate.fingerprint(hashes.SHA1()).hex().upper(),
        "not_after": not_after.strftime(CERT_END_DATE_FORMAT),
    }


@pytest.fixture(scope="module")
def pair() -> dict[str, str]:
    """One throwaway pair, reused by the tests that only need *a* certificate."""
    return make_pair()


# --- Guards ------------------------------------------------------------------
@pytest.fixture(autouse=True)
def restore_process_runner() -> Any:
    """No test leaks its fake runner into the next one."""
    try:
        yield
    finally:
        set_runner(None)


@pytest.fixture(autouse=True)
def no_real_admin_binaries(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Tripwire: the real subprocess layer must never be asked for az/openssl/etc."""
    real_run = subprocess.run

    def guarded(run_args: Any, **kwargs: Any) -> Any:
        argv = [str(a) for a in run_args]
        if argv and Path(str(argv[0])).name in FORBIDDEN_BINARIES:
            raise AssertionError(f"test attempted to execute a real {argv[0]!r}")
        return real_run(run_args, **kwargs)

    monkeypatch.setattr("micro_notify.admin.runner.subprocess.run", guarded)
    monkeypatch.setattr("micro_notify.certgen.subprocess.run", guarded)
    return guarded


@pytest.fixture(autouse=True)
def no_stray_temp_files() -> Any:
    """A run must not leave certificate material in the temp directory.

    Asserted after every test rather than per-test, so a path added later cannot
    leak even if its own test forgets to check. Only files with this module's own
    prefix are inspected, so a concurrent test elsewhere in the suite is unaffected.
    """
    before = _public_cert_files()
    try:
        yield
    finally:
        leaked = _public_cert_files() - before
        assert not leaked, f"public certificate temp files left behind: {sorted(leaked)}"


def _public_cert_files() -> set[str]:
    directory = tempfile.gettempdir()
    try:
        return {
            name
            for name in os.listdir(directory)
            if name.startswith(certupload.PUBLIC_CERT_PREFIX)
        }
    except OSError:
        return set()


@pytest.fixture
def cert_temp_baseline() -> set[str]:
    """The public-cert temp files that existed before this test started.

    Tests compare against *this* rather than asserting the directory is empty: an
    unrelated leftover (another test process, another mutant run in the same TMPDIR)
    is not this test's failure, and an assertion that pretends otherwise turns a
    green suite red for the wrong reason.
    """
    return _public_cert_files()


# --- Fake az -----------------------------------------------------------------
def completed(
    argv: list[str], returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


class FakeAz:
    """A :class:`CommandRunner` that answers canned ``az`` JSON and inspects itself.

    On top of B2's shape, this fake *looks at the certificate argument it is handed*
    while the reset call is in flight: it records the path, whether the file existed,
    its mode and its content. That is the only way to pin "a 0600 file holding the
    public PEM" — after the call the file is gone, which is the other half of the
    contract.

    An answer may also be a callable taking the argv: the upload path asks the same
    ``credential list`` command twice and must be told two different things (nothing
    uploaded yet, then the new certificate), which a static answer cannot express.
    """

    def __init__(self, answers: dict[tuple[str, ...], Any] | None = None) -> None:
        self.answers = dict(answers or {})
        self.calls: list[list[str]] = []
        self.stdin_payloads: list[str | None] = []
        # What the reset call saw at the moment az was invoked.
        self.cert_snapshots: list[dict[str, Any]] = []

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        self.calls.append(args)
        self.stdin_payloads.append(stdin)
        if self.argv_for("az", "ad", "app", "credential", "reset"):
            self.cert_snapshots.append(self._snapshot(args))
        for prefix, answer in self.answers.items():
            if tuple(args[: len(prefix)]) == prefix:
                if isinstance(answer, BaseException):
                    raise answer
                if callable(answer):
                    return completed(args, 0, str(answer(args)))
                if isinstance(answer, str):
                    return completed(args, 0, answer)
                return answer
        return completed(args, 0, "[]")

    @staticmethod
    def _snapshot(args: list[str]) -> dict[str, Any]:
        entry: dict[str, Any] = {"argv": list(args)}
        argument = _flag(args, "--cert")
        entry["cert_argument"] = argument
        if argument and argument.startswith("@"):
            path = argument[1:]
            entry["path"] = path
            entry["exists"] = os.path.exists(path)
            try:
                entry["mode"] = os.stat(path).st_mode & 0o777
            except OSError:
                entry["mode"] = None
            try:
                entry["content"] = Path(path).read_text(encoding="utf-8")
            except OSError:
                entry["content"] = None
        return entry

    # --- assertion helpers
    @property
    def joined(self) -> str:
        return " \n".join(" ".join(call) for call in self.calls)

    def argv_for(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]

    def executed(self, *prefix: str) -> bool:
        return bool(self.argv_for(*prefix))

    @property
    def reset_calls(self) -> list[list[str]]:
        return self.argv_for("az", "ad", "app", "credential", "reset")

    @property
    def list_calls(self) -> list[list[str]]:
        return self.argv_for("az", "ad", "app", "credential", "list")


def _flag(argv: list[str], flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None


def cert_entry(thumbprint: str, end_date: str | None = None) -> dict[str, Any]:
    """One credential entry as ``az ad app credential list --cert`` returns it.

    Graph computes ``customKeyIdentifier`` as the certificate's SHA-1 fingerprint and
    az returns it base64-encoded, so that is the spelling used by default.
    """
    import base64

    entry: dict[str, Any] = {
        "customKeyIdentifier": base64.b64encode(
            bytes.fromhex(thumbprint)
        ).decode("ascii"),
        "keyId": OTHER_APP_ID,
        "type": "AsymmetricX509Cert",
        "usage": "Verify",
    }
    if end_date is not None:
        entry["endDateTime"] = end_date
    return entry


def credential_list(*entries: dict[str, Any]) -> str:
    return json.dumps(list(entries))


def appears_after_the_upload(*entries: dict[str, Any]) -> Any:
    """A ``credential list`` answer that changes once the upload has happened.

    The step lists *before* it decides whether to generate and lists again to verify
    the upload, so a static answer cannot exercise the upload path at all: "[]" twice
    means the verification always fails, and the new thumbprint twice means the step
    short-circuits to ``exists`` and never uploads. This hands out "nothing uploaded"
    for the first read and the entries for every read after it.
    """
    seen = {"count": 0}

    def answer(argv: list[str]) -> str:
        seen["count"] += 1
        return "[]" if seen["count"] <= 1 else credential_list(*entries)

    return answer


NO_CREDENTIALS: dict[tuple[str, ...], Any] = {
    ("az", "ad", "app", "credential", "list"): "[]",
}


def upload_succeeds(pair: dict[str, str]) -> dict[tuple[str, ...], Any]:
    """Answer map for a full run on an app with no usable credential yet."""
    return {
        ("az", "ad", "app", "credential", "list"): appears_after_the_upload(
            cert_entry(pair["thumbprint"], pair["not_after"])
        )
    }


# --- Fake openssl (drives certgen's own runner seam) -------------------------
class FakeOpenssl:
    """A certgen ``runner``: writes the throwaway pair where ``openssl`` would.

    :func:`micro_notify.certgen.generate_certificate` is passed a
    ``subprocess.run``-shaped callable, so this fake stands in for the binary
    completely: it honours ``-keyout`` / ``-out`` by writing the PEMs certgen then
    reads back, and answers the ``-fingerprint`` call in the format certgen parses.
    It also records every invocation, so "the exists path generated nothing" is an
    observable fact rather than an assumption.
    """

    def __init__(self, pair: dict[str, str], *, returncode: int = 0) -> None:
        self.pair = pair
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        argv = [str(a) for a in args]
        self.calls.append(argv)
        if self.returncode != 0:
            return completed(argv, self.returncode, "", "generated failure")
        if "req" in argv:
            key_path = _flag(argv, "-keyout")
            cert_path = _flag(argv, "-out")
            if key_path:
                Path(key_path).write_text(self.pair["private_key_pem"], encoding="utf-8")
            if cert_path:
                Path(cert_path).write_text(self.pair["public_key_pem"], encoding="utf-8")
            return completed(argv, 0, "writing new private key")
        if "-fingerprint" in argv:
            hexified = self.pair["thumbprint"]
            pretty = ":".join(hexified[i : i + 2] for i in range(0, len(hexified), 2))
            return completed(argv, 0, f"SHA1 Fingerprint={pretty}\n")
        return completed(argv, 1, "", "unexpected openssl call")

    @property
    def invoked(self) -> bool:
        return bool(self.calls)


# --- Keychain helpers --------------------------------------------------------
def seed_pair(fake_keychain: Any, pair: dict[str, str]) -> None:
    fake_keychain.seed(secrets.ACCOUNT_CERT_PEM, pair["private_key_pem"])
    fake_keychain.seed(secrets.ACCOUNT_CERT_THUMBPRINT, pair["thumbprint"])


@pytest.fixture
def keychain_writes(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Records ``(account, value)`` for every keychain write this module attempts.

    The recorder is deliberately a spy rather than an absence check: a test that
    asserts *which* accounts were written and with *what* needs the values, and the
    refusal tests below assert the same list is empty — one mechanism, two claims.
    """
    recorded: list[tuple[str, str]] = []

    def spy(account: str, value: str, **kwargs: Any) -> None:
        recorded.append((account, value))

    monkeypatch.setattr(certupload.secrets, "set_secret", spy)
    return recorded


@pytest.fixture
def forbid_keychain_writes(keychain_writes: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The same recorder, named for the claim a refusal test makes with it.

    Every refusal test's whole point is that it stopped *before* a write, so its
    assertion is ``== []``; a name that reads as a prohibition says so at the call
    site without a comment. One recorder, two names — the spy lives in
    :func:`keychain_writes` so a fix to it cannot land in only one of them.
    """
    return keychain_writes


# =============================================================================
# The 1-year-cap regression pins (the reason this module exists)
# =============================================================================
def test_end_date_is_passed_and_equals_the_certificates_not_after(
    pair: dict[str, str]
) -> None:
    """``--end-date`` present, and exactly the certificate's ``notAfter``."""
    fake = FakeAz(NO_CREDENTIALS)
    end_date = upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)

    assert len(fake.reset_calls) == 1
    argv = fake.reset_calls[0]
    assert "--end-date" in argv, argv
    sent = _flag(argv, "--end-date")
    assert sent == pair["not_after"] == end_date
    assert sent == certificate_end_date(pair["public_key_pem"])


def test_end_date_is_azs_own_wire_format(pair: dict[str, str]) -> None:
    """The value is ``YYYY-MM-DDTHH:MM:SSZ`` — what az itself sends and echoes."""
    sent = certificate_end_date(pair["public_key_pem"])
    assert sent.endswith("Z")
    parsed = datetime.datetime.strptime(sent, CERT_END_DATE_FORMAT)
    assert parsed.tzinfo is None  # 'Z' means UTC; no offset suffix rides along


@pytest.mark.parametrize("days", [825, 2200], ids=["825-day cert", "6-year cert"])
def test_end_date_never_collapses_to_one_year(days: int) -> None:
    """The regression itself: the credential must live as long as the certificate.

    Without ``--end-date`` az sets the credential's expiry to one year from now
    whatever the certificate says — the live failure of 2026-10-30. Both horizons
    here are far past a year, so a cap anywhere in this module is a visible failure.
    """
    pair = make_pair(days=days)
    fake = FakeAz(NO_CREDENTIALS)
    upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)

    sent = _flag(fake.reset_calls[0], "--end-date")
    expiry = datetime.datetime.strptime(sent, CERT_END_DATE_FORMAT).replace(
        tzinfo=datetime.timezone.utc
    )
    horizon = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
    assert horizon > days - 3, f"credential expires in {horizon} days, cert lives {days}"
    assert horizon > 400, "credential looks capped at ~1 year"


def test_end_date_never_defaults_to_a_constant() -> None:
    """No hard-coded date: two certificates with different validity give two values."""
    short = make_pair(days=100)
    long_ = make_pair(days=900)
    assert certificate_end_date(short["public_key_pem"]) != certificate_end_date(
        long_["public_key_pem"]
    )


def test_append_is_always_present() -> None:
    """Without ``--append`` az clears every existing credential before uploading."""
    argv = reset_command(APP_ID, pem_argument="@/tmp/whatever.pem", end_date="2030-01-01T00:00:00Z")
    assert "--append" in argv
    assert argv.index("--append") < argv.index("--end-date")


def test_reset_uses_the_documented_command_shape() -> None:
    argv = reset_command(APP_ID, pem_argument="@/tmp/x.pem", end_date="2030-01-01T00:00:00Z")
    assert argv[:5] == ["az", "ad", "app", "credential", "reset"]
    assert _flag(argv, "--id") == APP_ID
    assert _flag(argv, "--cert") == "@/tmp/x.pem"


def test_reset_command_refuses_a_missing_end_date() -> None:
    """An empty end date is the bug, not a pass-through: az would cap at 1 year."""
    with pytest.raises(CertUploadError, match="one year"):
        reset_command(APP_ID, pem_argument="@/tmp/x.pem", end_date="")


def test_reset_command_refuses_an_empty_certificate_argument() -> None:
    with pytest.raises(CertUploadError, match="must not be empty"):
        reset_command(APP_ID, pem_argument="", end_date="2030-01-01T00:00:00Z")


# =============================================================================
# Public material only — the private key must never travel
# =============================================================================
def test_only_the_public_pem_reaches_argv(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """Every az argv this step builds carries a temp *path*, never key bytes."""
    fake = FakeAz(upload_succeeds(pair))
    openssl = FakeOpenssl(pair)
    ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert fake.reset_calls, "the upload never happened"
    private_marker = "-----" + "BEGIN " + "PRIVATE KEY"
    for call in fake.calls:
        joined = " ".join(call)
        assert private_marker not in joined
        assert pair["private_key_pem"] not in joined
        # The keychain account names are not az's business either.
        assert secrets.ACCOUNT_CERT_PEM not in joined
        assert secrets.ACCOUNT_CERT_THUMBPRINT not in joined
    # And nothing was smuggled in on stdin.
    assert all(payload is None for payload in fake.stdin_payloads)


def test_cert_argument_is_an_at_path_to_the_public_file(pair: dict[str, str]) -> None:
    fake = FakeAz(NO_CREDENTIALS)
    upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)

    snapshot = fake.cert_snapshots[0]
    assert snapshot["cert_argument"].startswith("@")
    assert snapshot["exists"] is True
    assert snapshot["content"] == pair["public_key_pem"]
    assert Path(snapshot["path"]).name.startswith(certupload.PUBLIC_CERT_PREFIX)


def test_public_file_is_mode_0600_while_az_reads_it(pair: dict[str, str]) -> None:
    fake = FakeAz(NO_CREDENTIALS)
    upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)

    assert fake.cert_snapshots[0]["mode"] == 0o600


def test_create_requests_0600_even_though_a_later_chmod_fixes_it(
    pair: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mode is asked for at *create* time too, not only fixed afterwards.

    Both settings are load-bearing in opposite directions (create protects before
    the chmod runs, chmod protects against a restrictive umask), so each is pinned
    on its own rather than relying on the final mode hiding whichever one broke.
    """
    requested: list[int] = []
    real_open = os.open

    def spy(path: Any, flags: int, mode: int = 0o777) -> int:
        requested.append(mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(certupload.os, "open", spy)
    upload_certificate(APP_ID, pair["public_key_pem"], runner=FakeAz(NO_CREDENTIALS))

    assert requested == [0o600]


def test_mode_0600_survives_a_umask_that_would_strip_it(
    pair: dict[str, str],
) -> None:
    """The follow-up chmod is what makes the guarantee independent of the umask.

    ``O_CREAT``'s mode is masked by the process umask, so on a machine whose umask
    strips owner bits the create mode alone would leave an unreadable-or-wrong file.
    Run under such a umask, the mode az sees must still be exactly 0600.
    """
    recorded = os.umask(0o600)  # would mask a create mode of 0600 down to 0000
    try:
        fake = FakeAz(NO_CREDENTIALS)
        upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)
        assert fake.cert_snapshots[0]["mode"] == 0o600
        assert fake.cert_snapshots[0]["content"] == pair["public_key_pem"]
    finally:
        os.umask(recorded)


def test_public_file_is_removed_after_the_upload(pair: dict[str, str]) -> None:
    fake = FakeAz(NO_CREDENTIALS)
    upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)

    path = fake.cert_snapshots[0]["path"]
    assert fake.cert_snapshots[0]["exists"] is True  # while az ran
    assert not os.path.exists(path)  # and not after


def test_public_file_is_removed_when_the_upload_fails(pair: dict[str, str]) -> None:
    """The ``finally`` has to bite on the failure path too — that is the point."""
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "reset"): completed(
                ["az"], 1, "", "AADSTS50173: credential rejected"
            )
        }
    )
    with pytest.raises(CertUploadError, match="exit 1"):
        upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)

    assert fake.cert_snapshots[0]["exists"] is True  # az was invoked with a real file
    assert not os.path.exists(fake.cert_snapshots[0]["path"])


def test_upload_failure_message_names_the_app_and_exit_code(pair: dict[str, str]) -> None:
    fake = FakeAz(
        {("az", "ad", "app", "credential", "reset"): completed(["az"], 1, "", "boom")}
    )
    with pytest.raises(CertUploadError) as excinfo:
        upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)
    assert APP_ID in str(excinfo.value)
    assert "exit 1" in str(excinfo.value)
    assert excinfo.value.exit_code == EXIT_AUTH


def test_write_public_file_refuses_private_key_material() -> None:
    """A caller that mixed up its halves must be stopped before anything is written."""
    private_marker = "-----" + "BEGIN " + "RSA PRIVATE KEY-----\nQUJD\n"
    with pytest.raises(CertUploadError, match="private key"):
        write_public_certificate_file(private_marker)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("", False),
        ("-----BEGIN CERTIFICATE-----\nQUJD\n", False),
        ("a PEM header lives here", False),
    ],
    ids=["empty", "public certificate", "prose about headers"],
)
def test_private_key_detector_does_not_cry_wolf(text: str, expected: bool) -> None:
    assert certupload._looks_like_private_key(text) is expected


@pytest.mark.parametrize("kind", ["PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PKCS8 PRIVATE KEY"])
def test_private_key_detector_catches_every_spelling(kind: str) -> None:
    text = "-----" + "BEGIN " + kind + "-----\nQUJD\n"
    assert certupload._looks_like_private_key(text) is True


def test_keychain_pair_is_written_to_the_documented_accounts(
    pair: dict[str, str], fake_keychain: Any, keychain_writes: list[tuple[str, str]]
) -> None:
    fake = FakeAz(upload_succeeds(pair))
    ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )

    accounts = [account for account, _ in keychain_writes]
    assert accounts == [secrets.ACCOUNT_CERT_PEM, secrets.ACCOUNT_CERT_THUMBPRINT]
    values = dict(keychain_writes)
    assert values[secrets.ACCOUNT_CERT_PEM] == pair["private_key_pem"]
    assert values[secrets.ACCOUNT_CERT_THUMBPRINT] == pair["thumbprint"]
    # The thumbprint is public (Entra displays it); the key is not printed anywhere.
    assert pair["private_key_pem"] not in fake.joined


# =============================================================================
# The exists path
# =============================================================================
def test_exists_path_regenerates_and_rewrites_nothing(
    pair: dict[str, str], fake_keychain: Any, keychain_writes: list[tuple[str, str]]
) -> None:
    """Card's rule: pair present *and* matching the uploaded credential -> exists."""
    seed_pair(fake_keychain, pair)
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): credential_list(
                cert_entry(pair["thumbprint"], pair["not_after"])
            )
        }
    )
    openssl = FakeOpenssl(pair)

    result = ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert isinstance(result, CertificateProvisioning)
    assert (result.created, result.generated) == (False, False)
    assert result.outcome == OUTCOME_EXISTS
    assert result.thumbprint == pair["thumbprint"]
    assert openssl.invoked is False, "a key was generated on the exists path"
    assert keychain_writes == [], "the keychain was rewritten on the exists path"
    assert fake.reset_calls == [], "an upload was attempted on the exists path"
    assert len(fake.list_calls) == 1


def test_exists_path_reports_the_tenant_end_date(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """Expiry comes from Entra on the reuse path, so a capped credential is visible."""
    seed_pair(fake_keychain, pair)
    capped = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    ).strftime(CERT_END_DATE_FORMAT)
    fake = FakeAz(
        {("az", "ad", "app", "credential", "list"): credential_list(cert_entry(pair["thumbprint"], capped))}
    )
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )
    assert result.expires_at == capped
    assert result.expired is False
    assert capped in result.detail


def test_exists_path_flags_an_expired_credential(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    seed_pair(fake_keychain, pair)
    expired = "2020-01-01T00:00:00Z"
    fake = FakeAz(
        {("az", "ad", "app", "credential", "list"): credential_list(cert_entry(pair["thumbprint"], expired))}
    )
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )
    assert result.outcome == OUTCOME_EXISTS  # it really is uploaded
    assert result.expired is True
    assert "expired" in result.detail


def test_expiry_is_compared_against_the_injected_moment(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """A credential that ends today is expired for tomorrow, live for yesterday."""
    seed_pair(fake_keychain, pair)
    end = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    fake = FakeAz(
        {("az", "ad", "app", "credential", "list"): credential_list(cert_entry(pair["thumbprint"], "2026-01-01T00:00:00Z"))}
    )
    before = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair), now=end - datetime.timedelta(days=1)
    )
    after = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair), now=end + datetime.timedelta(days=1)
    )
    assert (before.expired, after.expired) == (False, True)


def test_unreadable_end_date_is_never_reported_as_expired(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """A date shape this code does not know must not end up in a scary message."""
    seed_pair(fake_keychain, pair)
    fake = FakeAz(
        {("az", "ad", "app", "credential", "list"): credential_list(cert_entry(pair["thumbprint"], "sometime"))}
    )
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )
    assert result.expired is False
    assert result.expires_at == "sometime"


def test_credential_without_an_end_date_is_not_expired(pair: dict[str, str]) -> None:
    credential = UploadedCredential(thumbprint="A" * 40)
    assert credential.end_date_dt() is None
    assert credential.expired(datetime.datetime.now(datetime.timezone.utc)) is False


def test_other_uploaded_credentials_are_counted(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """Two stale certificates on the app must be visible to the operator."""
    seed_pair(fake_keychain, pair)
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): appears_after_the_upload(
                cert_entry(pair["thumbprint"], pair["not_after"]),
                cert_entry("B" * 40, "2027-01-01T00:00:00Z"),
                cert_entry("C" * 40, "2027-01-01T00:00:00Z"),
            )
        }
    )
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair), force=True
    )
    assert (result.created, result.generated) == (True, True)  # the seeded pair was not uploaded
    assert result.other_credentials == 2
    assert "2 other certificate credential" in result.detail


# =============================================================================
# The thumbprint-verify path
# =============================================================================
def test_thumbprint_mismatch_fails(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """``reset`` exits 0 even when the app ends up with a different certificate."""
    fake = FakeAz(
        {("az", "ad", "app", "credential", "list"): credential_list(cert_entry("B" * 40))}
    )
    with pytest.raises(CertUploadError, match="thumbprint") as excinfo:
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=FakeOpenssl(pair))

    assert excinfo.value.exit_code == EXIT_AUTH
    assert pair["thumbprint"] in str(excinfo.value)
    assert "B" * 40 in str(excinfo.value)


def test_verify_uploaded_accepts_only_the_matching_thumbprint(pair: dict[str, str]) -> None:
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): credential_list(
                cert_entry("B" * 40), cert_entry(pair["thumbprint"])
            )
        }
    )
    found = verify_uploaded(APP_ID, pair["thumbprint"], runner=fake)
    assert found.thumbprint == pair["thumbprint"]

    with pytest.raises(CertUploadError):
        verify_uploaded(APP_ID, "C" * 40, runner=fake)


def test_verify_uploaded_refuses_an_empty_thumbprint() -> None:
    with pytest.raises(CertUploadError, match="without a SHA-1 thumbprint"):
        verify_uploaded(APP_ID, "  ", runner=FakeAz())


def test_mismatch_with_the_keychain_pair_refuses_and_names_the_pair(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """A key that does not match this app is useless here — and must be named.

    BEHAVIOUR CHANGE (card t_9bac19ba, ORCH ruling on t_362c34cc comment 102): this
    path used to generate and upload a fresh pair unasked. It now refuses, because a
    pair that matches no credential *here* may be the live credential of a different
    app registration, and B6 (2026-10-31) is the record of what replacing one
    unasked costs. The replace behaviour this test used to pin moved to
    :func:`test_mismatch_with_the_keychain_pair_regenerates_when_forced`, whose
    assertions are the ones PR #27 (merged as 8671d2b) pinned — unchanged.
    """
    stale = make_pair(days=200)
    seed_pair(fake_keychain, stale)
    fake = FakeAz(upload_succeeds(pair))
    openssl = FakeOpenssl(pair)

    with pytest.raises(StaleKeyPairRefusal) as excinfo:
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert stale["thumbprint"] in str(excinfo.value)
    assert openssl.invoked is False
    assert fake.reset_calls == []


def test_mismatch_with_the_keychain_pair_regenerates_when_forced(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """The PR #27 pins, byte-for-byte: forced replacement reports the orphan."""
    stale = make_pair(days=200)
    seed_pair(fake_keychain, stale)
    fake = FakeAz(upload_succeeds(pair))
    openssl = FakeOpenssl(pair)

    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=openssl, force=True
    )

    assert (result.created, result.generated) == (True, True)
    assert result.thumbprint == pair["thumbprint"]
    assert result.replaced_thumbprint == stale["thumbprint"]
    assert stale["thumbprint"] in result.detail
    assert openssl.invoked is True


def test_missing_keychain_pair_generates_and_uploads(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    fake = FakeAz(upload_succeeds(pair))
    openssl = FakeOpenssl(pair)
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=openssl
    )
    assert (result.created, result.generated) == (True, True)
    assert result.replaced_thumbprint == ""
    assert len(fake.list_calls) == 2  # before (nothing to reuse) and after (verify)


def test_generated_upload_reports_the_end_date_sent_when_tenant_sends_none(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): appears_after_the_upload(
                cert_entry(pair["thumbprint"])
            )
        }
    )
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )
    assert result.expires_at == pair["not_after"]


# =============================================================================
# Fail-closed reading of az's answers
# =============================================================================
UNREADABLE = [
    pytest.param("null", id="null"),
    pytest.param('{"value": []}', id="graph envelope"),
    pytest.param('["AAAA"]', id="list of scalars"),
    pytest.param('"[]"', id="json string"),
]


@pytest.mark.parametrize("payload", UNREADABLE)
def test_unreadable_credential_list_never_triggers_a_new_key(
    payload: str, fake_keychain: Any
) -> None:
    """Fail-open here would overwrite the operator's private key. It must not."""
    fake = FakeAz({("az", "ad", "app", "credential", "list"): payload})
    openssl = FakeOpenssl(make_pair())

    with pytest.raises(CertUploadError, match="refusing"):
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert openssl.invoked is False, "a key was generated from an unreadable answer"
    assert fake.reset_calls == []


def test_credential_entry_without_a_thumbprint_refuses(
    fake_keychain: Any,
) -> None:
    """An entry we cannot identify is not "not uploaded"."""
    fake = FakeAz({("az", "ad", "app", "credential", "list"): json.dumps([{"keyId": OTHER_APP_ID}])})
    openssl = FakeOpenssl(make_pair())
    with pytest.raises(CertUploadError, match="without a readable thumbprint"):
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)
    assert openssl.invoked is False


def test_list_reports_its_command_name_on_failure() -> None:
    fake = FakeAz(
        {("az", "ad", "app", "credential", "list"): completed(["az"], 1, "", "insufficient privileges")}
    )
    with pytest.raises(CommandError, match="insufficient privileges"):
        list_uploaded_credentials(APP_ID, runner=fake)


# =============================================================================
# Keychain shape
# =============================================================================
def test_half_stored_pair_refuses(fake_keychain: Any, keychain_writes: list[tuple[str, str]]) -> None:
    """A thumbprint without a key (or the reverse) is never silently repaired."""
    fake_keychain.seed(secrets.ACCOUNT_CERT_PEM, "whatever")
    fake = FakeAz(NO_CREDENTIALS)
    with pytest.raises(CertUploadError, match="half stored") as excinfo:
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=FakeOpenssl(make_pair()))
    assert secrets.ACCOUNT_CERT_THUMBPRINT in str(excinfo.value)
    assert keychain_writes == []
    assert fake.reset_calls == []


def test_half_stored_pair_other_way(fake_keychain: Any) -> None:
    fake_keychain.seed(secrets.ACCOUNT_CERT_THUMBPRINT, "A" * 40)
    with pytest.raises(CertUploadError, match="half stored"):
        keychain_thumbprint()


def test_empty_keychain_reports_no_pair(fake_keychain: Any) -> None:
    assert keychain_thumbprint() is None


def test_garbage_thumbprint_refuses(fake_keychain: Any) -> None:
    fake_keychain.seed(secrets.ACCOUNT_CERT_PEM, "private")
    fake_keychain.seed(secrets.ACCOUNT_CERT_THUMBPRINT, "not-a-thumbprint")
    with pytest.raises(CertUploadError, match="not a SHA-1 thumbprint"):
        keychain_thumbprint()


# =============================================================================
# Thumbprint spellings
# =============================================================================
def test_thumbprint_normalisation_accepts_both_spellings() -> None:
    import base64

    hexified = "0123456789ABCDEF0123456789ABCDEF01234567"
    raw = bytes.fromhex(hexified)
    assert certupload._normalise_thumbprint(hexified) == hexified
    assert certupload._normalise_thumbprint(hexified.lower()) == hexified
    colonned = ":".join(hexified[i : i + 2] for i in range(0, 40, 2))
    assert certupload._normalise_thumbprint(colonned) == hexified
    assert certupload._normalise_thumbprint(base64.b64encode(raw).decode()) == hexified
    assert certupload._normalise_thumbprint("short") == ""
    assert certupload._normalise_thumbprint("") == ""


def test_thumbprint_from_entry_prefers_the_graph_field(pair: dict[str, str]) -> None:
    assert certupload._thumbprint_from_entry(cert_entry(pair["thumbprint"])) == pair["thumbprint"]
    assert (
        certupload._thumbprint_from_entry(
            {"thumbprint": pair["thumbprint"]}
        )
        == pair["thumbprint"]
    )
    assert certupload._thumbprint_from_entry({}) == ""


# =============================================================================
# Argument guards
# =============================================================================
@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "   ",
        " leading",
        "-id",
        "00000000-0000-0000-0000-000000000000'; --append",
        "micro-notify",
        "api://micro-notify",
    ],
    ids=["empty", "blank", "padded", "dash-leading", "injection", "name", "identifier-uri"],
)
def test_app_id_guard_runs_before_any_command(bad_id: str) -> None:
    fake = FakeAz()
    with pytest.raises(CertUploadError):
        ensure_certificate_credential(bad_id, runner=fake, cert_runner=FakeOpenssl(make_pair()))
    assert fake.calls == []


def test_certificate_end_date_rejects_unparsable_pem() -> None:
    with pytest.raises(CertUploadError, match="could not be read"):
        certificate_end_date("not a certificate")


def test_certificate_end_date_rejects_empty_input() -> None:
    with pytest.raises(CertUploadError, match="empty"):
        certificate_end_date("   ")


# =============================================================================
# Generation failures propagate, and cost nothing
# =============================================================================
def test_openssl_failure_propagates_as_a_usage_error(
    fake_keychain: Any, keychain_writes: list[tuple[str, str]]
) -> None:
    """certgen's exit-2 wording is better than anything invented here."""
    fake = FakeAz(NO_CREDENTIALS)
    with pytest.raises(UsageError) as excinfo:
        ensure_certificate_credential(
            APP_ID, runner=fake, cert_runner=FakeOpenssl(make_pair(), returncode=1)
        )
    assert excinfo.value.exit_code == EXIT_USAGE
    assert keychain_writes == []
    assert fake.reset_calls == []


# =============================================================================
# Dry run (B5 interop)
# =============================================================================
def test_plan_is_pure_and_carries_the_contract(cert_temp_baseline: set[str]) -> None:
    """``--dry-run`` must be printable without touching a keychain, a disk or az."""
    argv = plan_certificate_upload(APP_ID, end_date="2030-01-01T00:00:00Z")
    assert argv[:5] == ["az", "ad", "app", "credential", "reset"]
    assert "--append" in argv
    assert _flag(argv, "--end-date") == "2030-01-01T00:00:00Z"
    assert _flag(argv, "--cert").startswith("@<")  # a marker, not a real path
    assert _public_cert_files() == cert_temp_baseline


def test_plan_without_an_end_date_shows_a_marker() -> None:
    argv = plan_certificate_upload(APP_ID)
    assert "<certificate-not-after>" in argv


def test_plan_is_the_real_argv_apart_from_the_path(pair: dict[str, str]) -> None:
    """A dry run that differs from the real command would be a lie, not a preview."""
    planned = plan_certificate_upload(APP_ID, end_date=pair["not_after"])
    fake = FakeAz(NO_CREDENTIALS)
    upload_certificate(APP_ID, pair["public_key_pem"], runner=fake)
    actual = fake.reset_calls[0]

    assert [a for a in planned if not a.startswith("@<")] == [
        a for a in actual if not a.startswith("@/")
    ]


def test_dry_run_runner_reports_exists_without_executing(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """B5 wires ``--dry-run`` to B1's DryRunRunner; this is the read it can serve."""
    dry = DryRunRunner(
        {
            ("az", "ad", "app", "credential", "list"): credential_list(
                cert_entry(pair["thumbprint"], pair["not_after"])
            )
        }
    )
    seed_pair(fake_keychain, pair)
    result = ensure_certificate_credential(APP_ID, runner=dry, cert_runner=FakeOpenssl(pair))

    assert result.outcome == OUTCOME_EXISTS
    assert dry.executed_anything is False
    assert len(dry.calls) == 1  # one read, zero writes
    assert dry.calls[0][:5] == ["az", "ad", "app", "credential", "list"]


def test_dry_run_runner_never_generates_a_key_or_writes_the_keychain(
    pair: dict[str, str],
    fake_keychain: Any,
    keychain_writes: list[tuple[str, str]],
    cert_temp_baseline: set[str],
) -> None:
    """The dangerous combination, refused: a recording runner plus local side effects.

    Under ``--dry-run`` the az half of this step is recorded and skipped, so the
    verification could never pass — but ``openssl`` and the keychain are reached
    through their *own* injection points and would really run. A dry run that
    replaced the operator's private key would be the worst kind of lie, so the write
    path refuses before any of it happens.
    """
    dry = DryRunRunner({("az", "ad", "app", "credential", "list"): "[]"})
    openssl = FakeOpenssl(pair)

    with pytest.raises(CertUploadError, match="records commands instead of executing"):
        ensure_certificate_credential(APP_ID, runner=dry, cert_runner=openssl)

    assert openssl.invoked is False, "a key was generated by a dry run"
    assert keychain_writes == [], "the keychain was written by a dry run"
    assert [c for c in dry.calls if c[:5] == ["az", "ad", "app", "credential", "reset"]] == []
    assert _public_cert_files() == cert_temp_baseline


def test_dry_run_refusal_names_the_plan_function() -> None:
    """B5 needs to be told what to print instead of attempting the step."""
    dry = DryRunRunner({("az", "ad", "app", "credential", "list"): "[]"})
    with pytest.raises(CertUploadError, match="plan_certificate_upload"):
        upload_certificate(APP_ID, make_pair()["public_key_pem"], runner=dry)


def test_process_wide_dry_run_runner_is_refused_too(
    pair: dict[str, str], fake_keychain: Any, keychain_writes: list[tuple[str, str]]
) -> None:
    """B5 installs the dry-run runner process-wide; a missing ``runner=`` is no hole."""
    seed_pair(fake_keychain, make_pair(days=30))  # keychain does not match -> write path
    set_runner(DryRunRunner({("az", "ad", "app", "credential", "list"): "[]"}))
    openssl = FakeOpenssl(pair)

    with pytest.raises(CertUploadError, match="records commands instead of executing"):
        ensure_certificate_credential(APP_ID, cert_runner=openssl)

    assert openssl.invoked is False
    assert keychain_writes == []


def test_process_wide_dry_run_runner_can_still_report_exists(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    seed_pair(fake_keychain, pair)
    set_runner(
        DryRunRunner(
            {
                ("az", "ad", "app", "credential", "list"): credential_list(
                    cert_entry(pair["thumbprint"], pair["not_after"])
                )
            }
        )
    )
    result = ensure_certificate_credential(APP_ID, cert_runner=FakeOpenssl(pair))
    assert result.outcome == OUTCOME_EXISTS


# =============================================================================
# Package surface
# =============================================================================
def test_step_is_exported_from_the_package() -> None:
    from micro_notify import admin

    assert admin.ensure_certificate_credential is ensure_certificate_credential
    assert admin.CertUploadError is CertUploadError


def test_plan_function_is_not_re_exported_to_avoid_shadowing_b4() -> None:
    """B4's exo.py exports a same-named plan; the root must not carry two."""
    from micro_notify import admin

    assert not hasattr(admin, "plan_commands")
    assert not hasattr(admin, "plan_certificate_upload")


def test_error_is_an_auth_error() -> None:
    assert issubclass(CertUploadError, secrets.KeychainError.__bases__[0])
    assert CertUploadError("x").exit_code == EXIT_AUTH


# =============================================================================
# BUG2 live-scenario reducer — the shape ``az`` 2.90.0 ACTUALLY emits
# =============================================================================
# The 2026-10-31 live B6 run reported ``created`` on an already-configured
# tenant, generated a new key pair and replaced the keychain certificate.
# This reducer replays that exact scenario — keychain pair present, and the
# app holding exactly one credential whose thumbprint is the keychain's —
# against the canned answer ``az`` really prints, so idempotency is pinned to
# the CLI's real output rather than to the older spelling in ``cert_entry``
# (which base64-encodes the thumbprint; live az prints 40-char UPPERCASE HEX
# instead). Shape sources, all cited in the PR body:
#
# * azure-cli 2.90.0 source (the operator's own install):
#   ``azure/cli/command_modules/role/custom.py:1148``
#   ``list_application_credentials`` -> ``show_application`` (:1072) ->
#   ``_list_credentials`` (:2117) returns the application object's
#   ``keyCredentials`` verbatim; ``role/_msgrpah/_graph_client.py:99``
#   ``application_get`` is ``GET /applications/{id}`` (Graph v1.0). No
#   transformation is applied between Graph and stdout.
# * Graph ``keyCredential`` resource schema: ``customKeyIdentifier``,
#   ``displayName``, ``endDateTime``, ``key``, ``keyId``, ``startDateTime``,
#   ``type``, ``usage``.
# * Live capture (operator machine, az 2.90.0, 2026-10-31, values redacted):
#   ``customKeyIdentifier`` arrives as 40-character uppercase hex (20-byte
#   SHA-1), ``key`` is ``null``, dates carry az's own
#   ``%Y-%m-%dT%H:%M:%SZ`` wire format (``custom.py:1931 _datetime_to_utc``),
#   and the entry key set is exactly the eight keys above.
#
# The reducer is deliberately written against live state BEFORE any product
# change: on main it passes — the live scenario reports ``exists`` — which is
# the finding of the BUG2 investigation (the parser is not what missed).

# Placeholder key id for canned credentials (metadata only, never a secret).
CREDENTIAL_KEY_ID = "00000000-0000-0000-0000-000000000000"


def live_az_credential_entry(
    thumbprint_hex: str,
    *,
    end_date: str,
    key_id: str = CREDENTIAL_KEY_ID,
    display_name: str = "CN=micro-notify",
    start_date: str = "2026-10-31T13:59:27Z",
) -> dict[str, Any]:
    """One ``keyCredentials`` entry exactly as az 2.90.0 prints it (see above).

    ``thumbprint_hex`` goes into ``customKeyIdentifier`` as the uppercase hex
    az/Graph served — deliberately *not* base64, because that is what the CLI
    was observed to emit on the operator's tenant.
    """
    return {
        "customKeyIdentifier": thumbprint_hex.upper(),
        "displayName": display_name,
        "endDateTime": end_date,
        "key": None,
        "keyId": key_id,
        "startDateTime": start_date,
        "type": "AsymmetricX509Cert",
        "usage": "Verify",
    }


def _forbid_generate(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Make any call to ``certgen.generate_certificate`` an immediate failure."""
    counter = {"calls": 0}

    def spy(*args: Any, **kwargs: Any) -> Any:
        counter["calls"] += 1
        raise AssertionError("generate_certificate was called on the exists path")

    monkeypatch.setattr(certupload.certgen, "generate_certificate", spy)
    return counter


def test_live_az_shape_reports_exists_without_rekeying(
    pair: dict[str, str],
    fake_keychain: Any,
    keychain_writes: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The BUG2 reducer: live az shape + matching keychain pair -> ``exists``.

    Pins the whole card DoD for the exists path: the outcome, no call to
    :func:`micro_notify.certgen.generate_certificate` (spied at the call site,
    not only via the fake openssl), no ``credential reset`` argv, exactly one
    read, and both keychain accounts byte-equal after the run.
    """
    seed_pair(fake_keychain, pair)
    before = dict(fake_keychain.items)
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): json.dumps(
                [live_az_credential_entry(pair["thumbprint"], end_date=pair["not_after"])]
            )
        }
    )
    openssl = FakeOpenssl(pair)
    generated = _forbid_generate(monkeypatch)

    result = ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert result.outcome == OUTCOME_EXISTS
    assert (result.created, result.generated) == (False, False)
    assert result.thumbprint == pair["thumbprint"]
    assert result.expires_at == pair["not_after"]
    assert result.expired is False
    assert result.other_credentials == 0
    assert generated["calls"] == 0
    assert openssl.invoked is False, "openssl ran on the exists path"
    assert fake.reset_calls == [], "an upload was attempted on the exists path"
    assert fake.list_calls == [
        ["az", "ad", "app", "credential", "list", "--id", APP_ID, "--cert"]
    ]
    assert keychain_writes == []
    assert dict(fake_keychain.items) == before, "the keychain pair was rewritten"


def test_live_az_shape_matches_ours_among_foreign_credentials(
    pair: dict[str, str],
    fake_keychain: Any,
    keychain_writes: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression pin: foreign credentials on the app must not mask our match.

    The tenant may carry other certificates (a rotation, a different app's
    orphan); the exists check must still find ours by thumbprint among them,
    report them as ``other_credentials``, and change nothing.
    """
    seed_pair(fake_keychain, pair)
    before = dict(fake_keychain.items)
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): json.dumps(
                [
                    live_az_credential_entry("B" * 40, end_date="2027-01-01T00:00:00Z"),
                    live_az_credential_entry(pair["thumbprint"], end_date=pair["not_after"]),
                    live_az_credential_entry("C" * 40, end_date="2027-01-01T00:00:00Z"),
                ]
            )
        }
    )
    generated = _forbid_generate(monkeypatch)

    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )

    assert result.outcome == OUTCOME_EXISTS
    assert result.thumbprint == pair["thumbprint"]
    assert result.other_credentials == 2
    assert generated["calls"] == 0
    assert fake.reset_calls == []
    assert keychain_writes == []
    assert dict(fake_keychain.items) == before


def test_live_az_shape_matches_ours_alongside_a_base64_spelling(
    pair: dict[str, str],
    fake_keychain: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both thumbprint spellings may sit on one app; ours still matches.

    ``cert_entry`` (base64) models what other tools/tenants have been seen to
    carry; ``live_az_credential_entry`` (hex) is what this tenant serves. The
    normaliser's job is precisely that the two spellings of the same 20 bytes
    compare equal, so the exists check must not depend on which spelling the
    *matching* entry happens to use.
    """
    seed_pair(fake_keychain, pair)
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): json.dumps(
                [
                    cert_entry("D" * 40, "2027-01-01T00:00:00Z"),
                    live_az_credential_entry(pair["thumbprint"], end_date=pair["not_after"]),
                ]
            )
        }
    )
    generated = _forbid_generate(monkeypatch)

    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )

    assert result.outcome == OUTCOME_EXISTS
    assert result.other_credentials == 1
    assert generated["calls"] == 0
    assert fake.reset_calls == []


def test_live_az_shape_expired_still_reports_exists_not_a_rekey(
    pair: dict[str, str],
    fake_keychain: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An expired matching credential is reported, never silently re-keyed.

    Re-keying is ``mnotify setup --gen-cert``'s call to make; the bootstrap
    step only surfaces the expiry. Pinning this here matters because the
    BUG2 live report showed what an unasked-for re-key costs the operator.
    """
    seed_pair(fake_keychain, pair)
    fake = FakeAz(
        {
            ("az", "ad", "app", "credential", "list"): json.dumps(
                [live_az_credential_entry(pair["thumbprint"], end_date="2020-01-01T00:00:00Z")]
            )
        }
    )
    generated = _forbid_generate(monkeypatch)

    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )

    assert result.outcome == OUTCOME_EXISTS
    assert result.expired is True
    assert "expired" in result.detail
    assert generated["calls"] == 0
    assert fake.reset_calls == []


# =============================================================================
# Absent vs unreadable: the B6 fail-open closed (card t_9bac19ba)
# =============================================================================
# On 2026-10-31 a transient keychain failure — locked keychain, denied ACL — read
# as "no certificate pair" through `secrets.has()`, and `mnotify admin bootstrap`
# generated a fresh pair, rewrote both accounts and uploaded it over a tenant that
# was already configured. `secrets.probe()` (PR #31, merged as 4474d74) can tell the
# two apart; these tests pin that the *certificate step* is the caller that stops
# using the difference to decide "generate".
def test_transient_keychain_failure_never_regenerates_the_pair(
    pair: dict[str, str],
    fake_keychain: Any,
    forbid_keychain_writes: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE reducer this card exists for — red-first against the has()-based probe.

    Both certificate accounts answer a non-44 exit (60: the shape a locked keychain
    or a denied ACL produces) while the app answers "no credentials" — the most
    dangerous combination for the fail-open, because "no credentials" is the other
    half of the answer that makes the step generate. The step must refuse outright,
    and none of the four destructive effects may happen.
    """
    seed_pair(fake_keychain, pair)
    fake_keychain.fail_read(secrets.ACCOUNT_CERT_PEM, 60)
    fake_keychain.fail_read(secrets.ACCOUNT_CERT_THUMBPRINT, 60)
    fake = FakeAz(NO_CREDENTIALS)
    openssl = FakeOpenssl(pair)
    generated = _forbid_generate(monkeypatch)

    with pytest.raises(CertUploadError) as excinfo:
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    message = str(excinfo.value)
    assert secrets.SECURITY_BINARY in message or "security" in message
    assert secrets.ACCOUNT_CERT_PEM in message
    assert secrets.ACCOUNT_CERT_THUMBPRINT in message
    assert "unreadable" in message.lower()
    # The destructive quartet, each pinned at its own seam.
    assert fake_keychain.probe_reads, "the probe never attempted the read it was refused for"
    assert generated["calls"] == 0
    assert openssl.invoked is False
    assert forbid_keychain_writes == []
    assert fake.reset_calls == []


def test_unreadable_read_is_never_given_the_items_it_could_not_read(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """The refusal's own leak rule: an unreadable read carries nothing to echo.

    ``security``'s stdout and stderr are dropped inside
    :mod:`micro_notify.secrets` for exactly this reason; a message that quoted them
    would put keychain content into an operator-visible error on the one path where
    the content was never legitimately read.
    """
    fake_keychain.seed(secrets.ACCOUNT_CERT_PEM, pair["private_key_pem"])
    fake_keychain.fail_read(secrets.ACCOUNT_CERT_PEM, 60)

    with pytest.raises(CertUploadError) as excinfo:
        keychain_thumbprint()

    assert pair["private_key_pem"] not in str(excinfo.value)


def test_unreadable_thumbprint_account_alone_is_not_reported_as_half_stored(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """PEM readable + thumbprint exit 60 is *not* "half stored".

    Under the old has()-based probe this shape raised the half-stored message — a
    wrong diagnosis that told the operator to delete a pair whose thumbprint was
    merely unreadable. The failure must be named as an unreadable read.
    """
    fake_keychain.seed(secrets.ACCOUNT_CERT_PEM, pair["private_key_pem"])
    fake_keychain.fail_read(secrets.ACCOUNT_CERT_THUMBPRINT, 60)

    with pytest.raises(CertUploadError) as excinfo:
        keychain_thumbprint()

    message = str(excinfo.value)
    assert secrets.ACCOUNT_CERT_THUMBPRINT in message
    assert "unreadable" in message.lower()
    assert "half stored" not in message


def test_provably_absent_accounts_still_report_no_pair(fake_keychain: Any) -> None:
    """Fail-closed must not become fail-always: exit 44 on both accounts is the
    documented "nothing stored" answer, and the generation path stays allowed."""
    fake_keychain.fail_read(secrets.ACCOUNT_CERT_PEM, secrets.EXIT_ITEM_NOT_FOUND)
    fake_keychain.fail_read(
        secrets.ACCOUNT_CERT_THUMBPRINT, secrets.EXIT_ITEM_NOT_FOUND
    )
    assert keychain_thumbprint() is None


def test_first_run_with_absent_accounts_generates_and_uploads(
    pair: dict[str, str],
    fake_keychain: Any,
    forbid_keychain_writes: list[tuple[str, str]],
) -> None:
    """End-to-end half of the same pin: an honest "absent" still generates — so
    closing the fail-open did not break the documented first-run path."""
    fake_keychain.fail_read(secrets.ACCOUNT_CERT_PEM, secrets.EXIT_ITEM_NOT_FOUND)
    fake_keychain.fail_read(
        secrets.ACCOUNT_CERT_THUMBPRINT, secrets.EXIT_ITEM_NOT_FOUND
    )
    fake = FakeAz(upload_succeeds(pair))
    openssl = FakeOpenssl(pair)

    result = ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert (result.created, result.generated) == (True, True)
    assert [account for account, _ in forbid_keychain_writes] == [
        secrets.ACCOUNT_CERT_PEM,
        secrets.ACCOUNT_CERT_THUMBPRINT,
    ]


def test_pair_probe_verdicts_are_three_way_not_bool(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """keychain_thumbprint() must see PRESENT/ABSENT/UNREADABLE, not bool.

    The unit the e2e reducer runs through: a readable pair yields the normalised
    thumbprint, one unreadable account raises. Written against the verdict constants
    so a probe that collapsed to a bool cannot pass it.
    """
    seed_pair(fake_keychain, pair)
    assert keychain_thumbprint() == pair["thumbprint"]

    fake_keychain.fail_read(secrets.ACCOUNT_CERT_PEM, 1)
    with pytest.raises(CertUploadError, match="unreadable"):
        keychain_thumbprint()


def test_the_pair_probe_reads_value_once_and_from_the_probe(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """One read per account, and the value comes from that read.

    Two reads of the thumbprint account would be a TOCTOU window: the value the
    step compares against Entra would not be the value whose presence was just
    established. Asserting the exact read count is what makes a re-read
    (`secrets.get` after `secrets.has`) a test failure rather than a race.
    """
    seed_pair(fake_keychain, pair)

    assert keychain_thumbprint() == pair["thumbprint"]
    assert fake_keychain.probe_reads.count(secrets.ACCOUNT_CERT_THUMBPRINT) == 1
    assert fake_keychain.probe_reads.count(secrets.ACCOUNT_CERT_PEM) == 1


def test_pair_probe_never_reaches_the_real_subprocess_layer(
    pair: dict[str, str],
    fake_keychain: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pair probe must go through the injectable runner seam, or a test cannot
    hold it still.

    The shared fixture answers keychain reads in memory; a probe that decided
    presence through its own ``subprocess.run`` (or any path that bypasses
    :mod:`micro_notify.secrets`) would read the *operator's* keychain during a test.
    The tripwire below makes that an immediate failure rather than a wrong answer,
    and the assertion afterwards proves the tripwire had something to catch.
    """

    def tripwire(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a keychain pair probe reached the real subprocess layer")

    monkeypatch.setattr("micro_notify.secrets.subprocess.run", tripwire)
    seed_pair(fake_keychain, pair)

    assert keychain_thumbprint() == pair["thumbprint"]
    assert fake_keychain.security_binaries_invoked == []


# =============================================================================
# Stale keychain pair: refuse unless forced (ORCH ruling, t_362c34cc comment 102)
# =============================================================================
def stale_pair() -> dict[str, str]:
    """A second throwaway pair, deliberately different from the ``pair`` fixture."""
    return make_pair(days=200)


def app_holding_only(*pairs: dict[str, str]) -> FakeAz:
    """An ``az`` answer listing exactly these pairs' certificates as uploaded."""
    return FakeAz(
        {
            (
                "az",
                "ad",
                "app",
                "credential",
                "list",
            ): credential_list(
                *[cert_entry(p["thumbprint"], p["not_after"]) for p in pairs]
            )
        }
    )


def test_stale_keychain_pair_refuses_without_force(
    pair: dict[str, str],
    fake_keychain: Any,
    forbid_keychain_writes: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ruling (a): a pair matching nothing is refused, not silently replaced.

    The B6 lesson generalised: a stale pair may be the live credential of a
    *different* app registration, and replacing it destroys a working setup
    elsewhere. Exit 2 — the refusal family, same class as the ``--force-config``
    config and state refusals — naming the keychain thumbprint and the fix.
    """
    stale = stale_pair()
    seed_pair(fake_keychain, stale)
    fake = app_holding_only(pair)  # the app holds a *different* certificate
    openssl = FakeOpenssl(pair)
    generated = _forbid_generate(monkeypatch)

    with pytest.raises(StaleKeyPairRefusal) as excinfo:
        ensure_certificate_credential(APP_ID, runner=fake, cert_runner=openssl)

    assert isinstance(excinfo.value, UsageError)
    assert excinfo.value.exit_code == EXIT_USAGE
    message = str(excinfo.value)
    # This module's leak rule makes a thumbprint public (Entra displays it, and
    # ADMIN-SETUP §1.3 asks the operator to compare it), so it can be named in full.
    assert stale["thumbprint"] in message
    assert "--force" in message
    assert pair["private_key_pem"] not in message
    assert generated["calls"] == 0
    assert openssl.invoked is False
    assert forbid_keychain_writes == []
    assert fake.reset_calls == []


def test_stale_keychain_pair_is_replaced_only_when_forced(
    pair: dict[str, str],
    fake_keychain: Any,
    forbid_keychain_writes: list[tuple[str, str]],
) -> None:
    """Ruling (c): ``force`` restores the pre-ruling replace behaviour verbatim.

    Byte-identical to what PR #27 (merged as 8671d2b) pins for the mismatch path:
    created+generated, the new thumbprint reported, the replaced one reported too.
    """
    stale = stale_pair()
    seed_pair(fake_keychain, stale)
    fake = FakeAz(upload_succeeds(pair))
    openssl = FakeOpenssl(pair)

    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=openssl, force=True
    )

    assert (result.created, result.generated) == (True, True)
    assert result.thumbprint == pair["thumbprint"]
    assert result.replaced_thumbprint == stale["thumbprint"]
    assert stale["thumbprint"] in result.detail
    assert openssl.invoked is True
    assert [account for account, _ in forbid_keychain_writes] == [
        secrets.ACCOUNT_CERT_PEM,
        secrets.ACCOUNT_CERT_THUMBPRINT,
    ]


def test_forced_replacement_reports_the_orphan_in_the_json_payload(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """The operator always sees which certificate just became an orphan."""
    stale = stale_pair()
    seed_pair(fake_keychain, stale)
    result = ensure_certificate_credential(
        APP_ID,
        runner=FakeAz(upload_succeeds(pair)),
        cert_runner=FakeOpenssl(pair),
        force=True,
    )
    assert result.replaced_thumbprint == stale["thumbprint"]
    assert result.to_dict()["replaced_thumbprint"] == stale["thumbprint"]


def test_matching_pair_needs_no_force(
    pair: dict[str, str],
    fake_keychain: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal guards *replacement*, not the step.

    A pair whose thumbprint IS an app credential takes the ``exists`` path whether
    or not ``force`` is set: forcing must not turn an idempotent re-run into a
    re-key, which is the exact failure BUG2 was about.
    """
    seed_pair(fake_keychain, pair)
    fake = app_holding_only(pair)
    generated = _forbid_generate(monkeypatch)

    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair), force=True
    )

    assert result.outcome == OUTCOME_EXISTS
    assert generated["calls"] == 0
    assert fake.reset_calls == []


def test_no_keychain_pair_needs_no_force(
    pair: dict[str, str], fake_keychain: Any
) -> None:
    """The refusal protects *existing* material: with nothing stored there is
    nothing to destroy, so the documented generate+upload path stands."""
    fake = FakeAz(upload_succeeds(pair))
    result = ensure_certificate_credential(
        APP_ID, runner=fake, cert_runner=FakeOpenssl(pair)
    )
    assert (result.created, result.generated) == (True, True)


def test_refusal_order_recording_runner_first_then_force(
    pair: dict[str, str],
    fake_keychain: Any,
    forbid_keychain_writes: list[tuple[str, str]],
) -> None:
    """A dry run must still get the *dry-run* refusal even on the write path.

    Without this order a ``--dry-run`` against a stale pair would raise the
    force-refusal, whose "re-run with --force" advice is exactly the wrong
    suggestion for a run that promised to change nothing.
    """
    stale = stale_pair()
    seed_pair(fake_keychain, stale)
    dry = DryRunRunner({("az", "ad", "app", "credential", "list"): "[]"})

    with pytest.raises(CertUploadError, match="records commands instead of executing"):
        ensure_certificate_credential(APP_ID, runner=dry, cert_runner=FakeOpenssl(pair))

    assert forbid_keychain_writes == []


def test_stale_pair_refusal_is_exported_from_the_admin_package() -> None:
    """B5 prints one column per step; the refusal has to be reachable from there."""
    from micro_notify.admin import certupload as package_certupload

    assert package_certupload.StaleKeyPairRefusal is StaleKeyPairRefusal


def test_refusal_is_not_a_credential_failure() -> None:
    """The pair is fine — the invocation is what changes (ruling: usage family)."""
    assert not issubclass(StaleKeyPairRefusal, CertUploadError)
    assert issubclass(StaleKeyPairRefusal, UsageError)
