"""certgen: local self-signed certificate for `mnotify setup --gen-cert` (design §6 step 1).

Two layers here, and both are exercised:

* the runner seam — argv built for ``/usr/bin/openssl``, error paths typed as
  exit-2 config errors, and no private-key text ever leaving the module except
  as the returned key PEM (which ``setup`` hands straight to the keychain);
* one real end-to-end run against the system ``/usr/bin/openssl``. Generating a
  key is a local CPU operation, not a network operation, so this test is honest
  coverage rather than a mock of ourselves. It is skipped only where the system
  binary genuinely is not there.

Canary PEM markers are assembled at runtime: a literal ``-----BEGIN ...
PRIVATE KEY-----`` in a tracked file is exactly what the leak guard (design §5)
fails on.
"""

from __future__ import annotations

import pytest

from micro_notify import certgen

BEGIN_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
CANARY_KEY_BODY = "CANARYPRIVATEKEYBODYNOTAREALKEY"

# openssl prints SHA-1 as 40 colon-separated hex chars; fakes keep that shape.
FAKE_SHA1 = "00112233445566778899AABBCCDDEEFF00112233"
FAKE_SHA1_COLONS = ":".join(FAKE_SHA1[i : i + 2] for i in range(0, 40, 2))


def fake_pem(kind: str) -> str:
    """A PEM-shaped string that is not a real key (marker assembled at runtime)."""
    marker = BEGIN_KEY if kind == "key" else BEGIN_CERT
    return marker + "\n" + CANARY_KEY_BODY + "\n"


class OpensslStub:
    """Records openssl invocations and answers them from a scripted map."""

    def __init__(self, replies: dict[str, str] | None = None, returncode: int = 0) -> None:
        self.replies = replies or {}
        self.returncode = returncode
        self.calls: list[list[str]] = []
        self.written: dict[str, bytes] = {}

    def __call__(self, args, **_kwargs):
        from types import SimpleNamespace

        argv = [str(a) for a in args]
        self.calls.append(argv)
        verb = argv[1] if len(argv) > 1 else ""
        if self.returncode != 0:
            return SimpleNamespace(returncode=self.returncode, stdout="", stderr="bad")
        # `openssl x509 -fingerprint` answers on stdout; key/cert land in files.
        for flag in ("-out", "-keyout"):
            if flag in argv:
                path = argv[argv.index(flag) + 1]
                kind = "key" if flag == "-keyout" else "cert"
                from pathlib import Path

                Path(path).write_text(self.replies.get(kind, fake_pem(kind)), encoding="utf-8")
                self.written[path] = self.replies.get(kind, fake_pem(kind)).encode()
        return SimpleNamespace(returncode=0, stdout=self.replies.get("stdout", ""), stderr="")

    @property
    def binaries(self) -> list[str]:
        return [call[0] for call in self.calls]


# --- The contract the rest of the package relies on -------------------------
def test_generated_certificate_exposes_key_cert_thumbprint_and_public_key() -> None:
    """--gen-cert needs: key for the keychain, public cert for Entra, thumbprint."""
    result = certgen.generate_certificate(
        common_name="mnotify",
        days=825,
        runner=OpensslStub(
            {
                "key": fake_pem("key"),
                "cert": fake_pem("cert"),
                "stdout": f"SHA1 Fingerprint={FAKE_SHA1_COLONS}\n",
            }
        ),
    )
    assert result.private_key_pem == fake_pem("key")
    assert result.certificate_thumbprint == FAKE_SHA1
    assert result.public_key_pem == fake_pem("cert")


def test_fingerprint_is_reported_in_the_sha1_hex_form_entra_shows() -> None:
    """Entra prints the credential thumbprint as colon-separated SHA-1 hex."""
    result = certgen.generate_certificate(
        common_name="mnotify",
        days=825,
        runner=OpensslStub(
            {
                "key": fake_pem("key"),
                "cert": fake_pem("cert"),
                "stdout": "SHA1 Fingerprint=00:11:22:33:AA:BB:CC:DD:EE:FF:00:11:22:33:AA:BB:CC:DD:EE:FF\n",
            }
        ),
    )
    assert result.certificate_thumbprint == (
        "00112233AABBCCDDEEFF00112233AABBCCDDEEFF"
    )


def test_fingerprint_helper_accepts_both_openssl_wordings() -> None:
    """LibreSSL prints 'SHA1 Fingerprint=', OpenSSL 3 prints 'sha1 Fingerprint='."""
    assert certgen.parse_fingerprint(f"SHA1 Fingerprint={FAKE_SHA1_COLONS}\n") == FAKE_SHA1
    assert certgen.parse_fingerprint(f"sha1 Fingerprint={FAKE_SHA1_COLONS.lower()}\n") == FAKE_SHA1


# --- Runner seam -------------------------------------------------------------
def test_openssl_binary_is_invoked_never_a_shell() -> None:
    """Every argv is an exec'd list whose first element is the openssl path."""
    stub = OpensslStub(
        {"key": fake_pem("key"), "cert": fake_pem("cert"), "stdout": f"SHA1 Fingerprint={FAKE_SHA1_COLONS}\n"}
    )
    certgen.generate_certificate(common_name="mnotify", days=825, runner=stub)
    assert stub.calls, "generate_certificate must invoke openssl"
    assert all(call[0] == certgen.OPENSSL_BINARY for call in stub.calls)
    assert all("-subj" in call for call in stub.calls if call[1] == "req")


def test_subject_carries_the_common_name_and_no_real_domain() -> None:
    stub = OpensslStub(
        {"key": fake_pem("key"), "cert": fake_pem("cert"), "stdout": f"SHA1 Fingerprint={FAKE_SHA1_COLONS}\n"}
    )
    certgen.generate_certificate(common_name="mnotify", days=825, runner=stub)
    req = next(call for call in stub.calls if call[1] == "req")
    assert f"/CN=mnotify" in req


def test_missing_openssl_binary_is_a_config_error_naming_the_tool() -> None:
    """No openssl on PATH must be an operator-readable fix hint, not a traceback."""
    from micro_notify import EXIT_USAGE, UsageError

    def missing(args, **_kwargs):
        raise FileNotFoundError(certgen.OPENSSL_BINARY)

    with pytest.raises(UsageError) as excinfo:
        certgen.generate_certificate(common_name="mnotify", days=825, runner=missing)
    assert excinfo.value.exit_code == EXIT_USAGE
    assert "openssl" in excinfo.value.message


def test_openssl_failure_names_the_step_not_its_output() -> None:
    """stderr from openssl may echo arguments; only the step name may surface."""
    from micro_notify import UsageError

    def failing(args, **_kwargs):
        from types import SimpleNamespace

        return SimpleNamespace(returncode=1, stdout="", stderr="attempted to read /secret/path")

    with pytest.raises(UsageError) as excinfo:
        certgen.generate_certificate(common_name="mnotify", days=825, runner=failing)
    assert "/secret/path" not in excinfo.value.message


def test_unparsable_fingerprint_is_reported_not_guessed() -> None:
    from micro_notify import UsageError

    with pytest.raises(UsageError):
        certgen.parse_fingerprint("no fingerprint here")
    with pytest.raises(UsageError):
        certgen.parse_fingerprint("")


def test_private_key_never_appears_in_the_public_key_field() -> None:
    """The file the operator uploads to Entra is the certificate, not the key."""
    result = certgen.generate_certificate(
        common_name="mnotify",
        days=825,
        runner=OpensslStub(
            {
                "key": fake_pem("key") + "\nSECRETKEYMATERIAL\n",
                "cert": BEGIN_CERT + "\nPUBLICMATERIAL\n",
                "stdout": f"SHA1 Fingerprint={FAKE_SHA1_COLONS}\n",
            }
        ),
    )
    assert "SECRETKEYMATERIAL" not in result.public_key_pem
    assert result.public_key_pem.startswith(BEGIN_CERT)


def test_key_and_certificate_are_read_from_a_private_temporary_directory() -> None:
    """The private key must not sit in a world-readable location."""
    import os
    import stat

    seen: list[tuple[str, int]] = []

    class RecordingStub(OpensslStub):
        def __call__(self, args, **kwargs):
            argv = [str(a) for a in args]
            if "-keyout" in argv:
                key_path = argv[argv.index("-keyout") + 1]
                directory = os.path.dirname(key_path)
                # stat it WHILE the key exists — the module cleans up on exit.
                seen.append((directory, stat.S_IMODE(os.stat(directory).st_mode)))
            return super().__call__(args, **kwargs)

    certgen.generate_certificate(
        common_name="mnotify",
        days=825,
        runner=RecordingStub(
            {"key": fake_pem("key"), "cert": fake_pem("cert"), "stdout": f"SHA1 Fingerprint={FAKE_SHA1_COLONS}\n"}
        ),
    )
    assert seen, "openssl must be given a -keyout path"
    directory, mode = seen[0]
    assert mode & 0o077 == 0, f"temporary key directory is group/other accessible: {oct(mode)} in {directory}"


def test_generated_key_file_is_removed_when_the_run_fails() -> None:
    """A failed run must not leave a private key on disk."""
    import pathlib

    leftover: list[str] = []

    class FailingWriteStub(OpensslStub):
        def __call__(self, args, **kwargs):
            result = super().__call__(args, **kwargs)
            argv = [str(a) for a in args]
            if "-keyout" in argv:
                leftover.append(argv[argv.index("-keyout") + 1])
            return result

    with pytest.raises(Exception):
        certgen.generate_certificate(
            common_name="mnotify",
            days=825,
            runner=FailingWriteStub(
                {"key": fake_pem("key"), "cert": fake_pem("cert"), "stdout": "not a fingerprint"}
            ),
        )
    assert leftover
    assert not pathlib.Path(leftover[0]).exists(), "private key left behind on a failed run"


# --- Real openssl: local key generation, zero network -----------------------
@pytest.mark.skipif(
    not __import__("os").path.exists(certgen.OPENSSL_BINARY),
    reason="system openssl not present",
)
def test_real_openssl_generates_a_usable_key_pair_and_sha1_thumbprint() -> None:
    """End to end with the system tool: real PEMs, real 40-hex SHA-1 thumbprint."""
    result = certgen.generate_certificate(common_name="mnotify", days=825, key_size=2048)
    assert result.private_key_pem.startswith(BEGIN_KEY) or "PRIVATE KEY" in result.private_key_pem
    assert result.public_key_pem.startswith(BEGIN_CERT)
    assert "PRIVATE" not in result.public_key_pem
    thumb = result.certificate_thumbprint
    assert len(thumb) == 40 and all(c in "0123456789ABCDEF" for c in thumb)
