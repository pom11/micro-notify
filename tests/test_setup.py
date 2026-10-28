"""``mnotify setup`` — config writing, keychain storage, --gen-cert (design §4, §6 step 1).

Rules pinned here (card + design §2 anti-goals):
* every prompt is skippable by flag, so CI can drive setup with no TTY;
* the config file lands 0600 and never contains a secret or a webhook URL;
* secrets go to the (fake) keychain only; a canary secret never appears in the
  config file, stdout or stderr;
* --gen-cert stores key + thumbprint, writes the *public* PEM for Entra, and
  prints the fingerprint — never the private key.

The canary webhook URL is assembled at runtime (tests/test_leak_guard.py does the
same): a tracked file carrying one literally must fail the leak guard, and the
guard should.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from micro_notify import EXIT_USAGE, cli
from micro_notify.commands import setup as setup_cmd
from micro_notify.config import (
    CONFIG_ENV_VAR,
    AllowConfig,
    Config,
    LimitsConfig,
    MailConfig,
    PathsConfig,
    TeamTarget,
    write_config,
)
from micro_notify.secrets import (
    ACCOUNT_CERT_PEM,
    ACCOUNT_CERT_THUMBPRINT,
    ACCOUNT_CLIENT_SECRET,
)

EXIT_OK_CODE = 0
GUID = "00000000-0000-0000-0000-000000000000"
CANARY_SECRET = "canary-c1ient-secret-DO-NOT-LEAK"
# Private-key body marker for the --gen-cert canaries. The PEM header itself is
# assembled at runtime so this tracked file carries no private-key block.
CANARY_KEY_BODY = "CANARYPRIVATEKEYBODYNOTAREALKEY"
CANARY_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD"
BEGIN_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
BEGIN_CERT = "-----BEGIN CERTIFICATE-----"

BASE = [
    "--tenant-id", GUID,
    "--client-id", GUID,
    "--sender", "noreply@example.com",
    "--auth", "certificate",
]
SECRET_BASE = BASE[:6] + ["--auth", "secret"]


def canary_webhook_url() -> str:
    host = ".".join(["tenant-abc", "logic", "azure"]) + ".com"
    return "https" + "://" + host + "/triggers/R7x9Qm2/HTTP"


def generated_cert():
    from micro_notify.certgen import GeneratedCertificate

    return GeneratedCertificate(
        private_key_pem=f"{BEGIN_KEY}\n{CANARY_KEY_BODY}\n",
        public_key_pem=f"{BEGIN_CERT}\nPUBLICMATERIAL\n",
        certificate_thumbprint=CANARY_THUMBPRINT,
    )


def non_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the no-TTY path and make any accidental prompt a hard failure."""
    monkeypatch.setattr(setup_cmd, "_is_tty", lambda: False)

    def no_prompt(*_args, **_kwargs):
        raise AssertionError("setup prompted in non-interactive mode")

    monkeypatch.setattr("builtins.input", no_prompt)
    monkeypatch.setattr(setup_cmd.getpass, "getpass", no_prompt)


def stub_certgen(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Replace certgen.generate_certificate; return the list capturing its kwargs."""
    calls: list[dict] = []

    def fake_generate(**kwargs):
        calls.append(kwargs)
        return generated_cert()

    monkeypatch.setattr(setup_cmd.certgen, "generate_certificate", fake_generate)
    return calls


@pytest.fixture
def target_config(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config path that does not exist yet, selected via MICRO_NOTIFY_CONFIG."""
    path = tmp_path / "config" / "config.toml"
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    return path


def run_setup(*argv: str) -> int:
    return cli.main(["setup", *argv])


# --- Non-interactive, certificate mode --------------------------------------
def test_setup_writes_a_readable_config_from_flags_alone(
    target_config, fake_keychain, monkeypatch
) -> None:
    """CI drives the whole command with flags: zero prompts, config on disk."""
    non_interactive(monkeypatch)
    stub_certgen(monkeypatch)
    assert run_setup(*BASE, "--gen-cert", "--allow-domain", "example.com") == EXIT_OK_CODE
    assert target_config.exists()
    text = target_config.read_text(encoding="utf-8")
    assert 'sender = "noreply@example.com"' in text
    assert 'domains = ["example.com"]' in text


def test_setup_config_file_mode_is_0600(target_config, fake_keychain, monkeypatch) -> None:
    non_interactive(monkeypatch)
    stub_certgen(monkeypatch)
    assert run_setup(*BASE, "--gen-cert") == EXIT_OK_CODE
    assert stat.S_IMODE(target_config.stat().st_mode) == 0o600


# --- Secret handling ---------------------------------------------------------
def test_secret_mode_stores_hidden_input_in_keychain_and_never_in_config(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    """The client secret travels getpass -> keychain; config and output stay clean."""
    prompts: list[str] = []

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return CANARY_SECRET

    monkeypatch.setattr(setup_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(setup_cmd.getpass, "getpass", fake_getpass)
    assert run_setup(*SECRET_BASE) == EXIT_OK_CODE
    assert prompts, "secret must be taken through hidden input, not a flag"
    assert fake_keychain.items[ACCOUNT_CLIENT_SECRET] == CANARY_SECRET
    assert CANARY_SECRET not in target_config.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert CANARY_SECRET not in captured.out + captured.err


def test_secret_mode_fails_in_non_interactive_without_leaking_a_hint_of_a_value(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    """No TTY + auth=secret cannot prompt: exit 2 with a fix hint, nothing written."""
    non_interactive(monkeypatch)
    assert run_setup(*SECRET_BASE) == EXIT_USAGE
    assert not target_config.exists()
    assert "secret" in capsys.readouterr().err.lower()


def test_secret_is_never_a_flag(target_config, monkeypatch) -> None:
    """A --client-secret flag value would land in shell history (design §3.2 rule)."""
    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args(SECRET_BASE + ["--client-secret", "oops"])
    assert excinfo.value.code == EXIT_USAGE


def test_secret_mode_does_not_write_keychain_certificate_accounts(
    target_config, fake_keychain, monkeypatch
) -> None:
    """auth=secret must not leave half a certificate credential behind."""
    monkeypatch.setattr(setup_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr(setup_cmd.getpass, "getpass", lambda *_a: CANARY_SECRET)
    assert run_setup(*SECRET_BASE) == EXIT_OK_CODE
    assert ACCOUNT_CERT_PEM not in fake_keychain.items
    assert ACCOUNT_CERT_THUMBPRINT not in fake_keychain.items


# --- --gen-cert --------------------------------------------------------------
def test_gen_cert_stores_key_and_thumbprint_and_writes_the_public_pem(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    """Design §6 step 1: key + thumbprint to the keychain, public PEM for Entra."""
    non_interactive(monkeypatch)
    calls = stub_certgen(monkeypatch)
    assert run_setup(*BASE, "--gen-cert") == EXIT_OK_CODE
    assert calls, "generate_certificate must be called once"
    assert fake_keychain.items[ACCOUNT_CERT_PEM] == generated_cert().private_key_pem
    assert fake_keychain.items[ACCOUNT_CERT_THUMBPRINT] == CANARY_THUMBPRINT

    captured = capsys.readouterr()
    assert CANARY_THUMBPRINT in captured.out, "the fingerprint is printed for Entra"
    assert CANARY_KEY_BODY not in captured.out + captured.err
    assert "PRIVATE KEY" not in captured.out, "the private key must never be printed"

    public_files = [p for p in target_config.parent.glob("*") if p.suffix == ".pem"]
    assert public_files, "the public PEM must be written for the operator to upload"
    public_text = public_files[0].read_text(encoding="utf-8")
    assert "PUBLICMATERIAL" in public_text
    assert CANARY_KEY_BODY not in public_text
    assert stat.S_IMODE(public_files[0].stat().st_mode) & 0o077 == 0, (
        "even the public PEM belongs in a private directory next to the config"
    )


def test_gen_cert_never_puts_a_private_key_into_the_config_or_json_output(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    non_interactive(monkeypatch)
    stub_certgen(monkeypatch)
    assert run_setup(*BASE, "--gen-cert", "--json") == EXIT_OK_CODE
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    blob = json.dumps(payload)
    assert CANARY_KEY_BODY not in blob
    assert "PRIVATE KEY" not in blob
    assert CANARY_KEY_BODY not in target_config.read_text(encoding="utf-8")


def test_gen_cert_failure_is_reported_and_no_config_is_written(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    """A missing openssl is exit 2 with the tool named, and no half-config left."""
    from micro_notify import UsageError

    non_interactive(monkeypatch)

    def boom(**_kwargs):
        raise UsageError("/usr/bin/openssl not found — install the Xcode command line tools")

    monkeypatch.setattr(setup_cmd.certgen, "generate_certificate", boom)
    assert run_setup(*BASE, "--gen-cert") == EXIT_USAGE
    assert not target_config.exists()
    assert "openssl" in capsys.readouterr().err


# --- Webhook URLs are refused ------------------------------------------------
def test_setup_refuses_to_write_a_config_containing_a_webhook_url(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    """A webhook URL is a secret (design §3.2) — it must never reach config.toml."""
    non_interactive(monkeypatch)
    url = canary_webhook_url()
    rc = run_setup("--tenant-id", GUID, "--client-id", GUID, "--sender", url,
                   "--auth", "certificate")
    assert rc == EXIT_USAGE
    assert not target_config.exists()
    assert url not in capsys.readouterr().err, "the refusal must not echo the webhook URL"


def test_setup_refuses_a_url_in_any_written_value(target_config, fake_keychain, monkeypatch) -> None:
    non_interactive(monkeypatch)
    assert run_setup(*BASE, "--reply-to", canary_webhook_url()) == EXIT_USAGE
    assert not target_config.exists()


# --- Interactive prompts -----------------------------------------------------
def test_prompts_fill_what_flags_omitted(target_config, fake_keychain, monkeypatch) -> None:
    """tenant/client/sender/auth are prompted when not given; certgen confirmed."""
    answers = iter([GUID, GUID, "noreply@example.com", "certificate", "y"])
    monkeypatch.setattr(setup_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a: next(answers))
    stub_certgen(monkeypatch)
    assert run_setup() == EXIT_OK_CODE
    assert target_config.exists()
    assert fake_keychain.items[ACCOUNT_CERT_PEM] == generated_cert().private_key_pem


def test_answering_no_to_certificate_generation_prompts_for_existing_material(
    target_config, fake_keychain, monkeypatch
) -> None:
    """An operator who already has a cert must not be forced to generate one."""
    answers = iter([GUID, GUID, "noreply@example.com", "certificate", "n"])
    monkeypatch.setattr(setup_cmd, "_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a: next(answers))
    stub = stub_certgen(monkeypatch)
    assert run_setup() == EXIT_OK_CODE
    assert stub == [], "answering 'n' must not generate a certificate"
    # The operator will store the key themselves; the config still has to land.
    assert target_config.exists()


def test_missing_flag_without_a_tty_names_the_flag(target_config, fake_keychain, monkeypatch, capsys) -> None:
    non_interactive(monkeypatch)
    assert run_setup("--client-id", GUID) == EXIT_USAGE
    assert "tenant-id" in capsys.readouterr().err


# --- Existing config ---------------------------------------------------------
def test_existing_config_is_not_clobbered_without_force(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    non_interactive(monkeypatch)
    stub_certgen(monkeypatch)
    target_config.parent.mkdir(parents=True)
    target_config.write_text("# operator edits\n", encoding="utf-8")
    assert run_setup(*BASE, "--gen-cert") == EXIT_USAGE
    assert target_config.read_text(encoding="utf-8") == "# operator edits\n"
    assert "--force" in capsys.readouterr().err


def test_force_preserves_configured_teams_targets(
    target_config, fake_keychain, monkeypatch
) -> None:
    """Re-running setup must not orphan the keychain teams:<target> entries."""
    non_interactive(monkeypatch)
    stub_certgen(monkeypatch)
    existing = Config(
        mail=MailConfig(tenant_id=GUID, client_id=GUID, sender="noreply@example.com",
                        auth="certificate"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=target_config.parent / "audit.jsonl",
                          state_dir=target_config.parent / "state"),
        teams_targets=(TeamTarget(name="alerts", kind="channel"),),
    )
    write_config(existing, target_config)
    assert run_setup(*BASE, "--gen-cert", "--force") == EXIT_OK_CODE
    assert "[teams.targets.alerts]" in target_config.read_text(encoding="utf-8")


# --- Bad input ---------------------------------------------------------------
def test_bad_guid_is_a_config_error_naming_the_flag(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    non_interactive(monkeypatch)
    assert run_setup("--tenant-id", "not-a-guid", "--client-id", GUID,
                     "--sender", "noreply@example.com", "--auth", "certificate") == EXIT_USAGE
    assert "tenant-id" in capsys.readouterr().err


def test_sender_without_at_sign_is_refused(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    non_interactive(monkeypatch)
    assert run_setup("--tenant-id", GUID, "--client-id", GUID, "--sender", "not-an-address",
                     "--auth", "certificate") == EXIT_USAGE
    assert "sender" in capsys.readouterr().err


def test_setup_announces_what_it_stored_without_naming_values(
    target_config, fake_keychain, monkeypatch, capsys
) -> None:
    non_interactive(monkeypatch)
    stub_certgen(monkeypatch)
    run_setup(*BASE, "--gen-cert")
    out = capsys.readouterr().out
    assert ACCOUNT_CERT_PEM in out  # account names are safe; values are not
    assert CANARY_KEY_BODY not in out
