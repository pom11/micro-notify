"""``mnotify config show`` — resolved config with secrets reduced to presence (design §4).

The card's central guarantee: a canary placed in the fake keychain — as a
certificate PEM, a client secret, or a Teams webhook URL — must not appear in the
output in any form. The config schema (design §3.4) holds no secret values at all,
so the risk is not a config key, it is this command deciding to "helpfully" print
what it found in the keychain.

Note on which of these tests are pins: the scaffold already implemented
``config show`` and ``log`` (design §8 covers neither as a separate step), so a
test that passes on first sight of it is a pin of behaviour the card requires, not
evidence of a bug. Every RED found while writing this file is named in the PR body.
"""

from __future__ import annotations

import json

import pytest

from micro_notify import EXIT_OK, EXIT_USAGE, cli
from micro_notify.commands import config_cmd
from micro_notify.secrets import (
    ACCOUNT_CERT_PEM,
    ACCOUNT_CERT_THUMBPRINT,
    ACCOUNT_CLIENT_SECRET,
)

CANARY_PEM_BODY = "CANARYPRIVATEKEYBODYNOTAREALKEY"
CANARY_SECRET = "canary-c1ient-secret-DO-NOT-LEAK"
CANARY_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD"


def canary_webhook_url() -> str:
    """A Workflows-shaped URL assembled at runtime (see tests/test_leak_guard.py)."""
    host = ".".join(["tenant-abc", "logic", "azure"]) + ".com"
    return "https" + "://" + host + "/triggers/R7x9Qm2/HTTP"


def run_config(*argv: str) -> int:
    return cli.main(["config", *argv])


@pytest.fixture
def loaded_keychain(fake_keychain):
    """Everything a certificate-mode config needs, plus a canary Teams URL."""
    fake_keychain.seed(ACCOUNT_CERT_PEM, "-----BEGIN " + "PRIVATE KEY-----\n" + CANARY_PEM_BODY)
    fake_keychain.seed(ACCOUNT_CERT_THUMBPRINT, CANARY_THUMBPRINT)
    fake_keychain.seed("teams:alerts", canary_webhook_url())
    fake_keychain.seed("teams:dm", canary_webhook_url())
    return fake_keychain


# --- The masking guarantee ---------------------------------------------------
def test_show_prints_no_keychain_value_in_human_mode(
    mnotify_config, loaded_keychain, capsys
) -> None:
    assert run_config("show") == EXIT_OK
    blob = capsys.readouterr().out
    for canary in (CANARY_PEM_BODY, CANARY_SECRET, canary_webhook_url(), CANARY_THUMBPRINT):
        assert canary not in blob, f"{canary[:12]}... leaked into `config show` output"


def test_show_prints_no_keychain_value_in_json_mode(
    mnotify_config, loaded_keychain, capsys
) -> None:
    assert run_config("show", "--json") == EXIT_OK
    blob = json.dumps(json.loads(capsys.readouterr().out))
    for canary in (CANARY_PEM_BODY, CANARY_SECRET, canary_webhook_url(), CANARY_THUMBPRINT):
        assert canary not in blob


def test_a_webhook_url_fragment_never_appears(
    mnotify_config, loaded_keychain, capsys
) -> None:
    """Not even a path fragment: the signature lives in the path (design §3.2)."""
    assert run_config("show") == EXIT_OK
    blob = capsys.readouterr().out
    assert "triggers" not in blob
    assert "R7x9Qm2" not in blob


def test_certificate_pem_is_reported_as_presence_not_value(
    mnotify_config, loaded_keychain, capsys
) -> None:
    """The card's wording: `certificate_pem: present`."""
    assert run_config("show") == EXIT_OK
    out = capsys.readouterr().out
    assert f"{ACCOUNT_CERT_PEM}: present" in out


def test_thumbprint_account_is_reported_by_name_with_presence(
    mnotify_config, loaded_keychain, capsys
) -> None:
    assert run_config("show") == EXIT_OK
    out = capsys.readouterr().out
    assert f"{ACCOUNT_CERT_THUMBPRINT}: present" in out


def test_a_missing_account_is_loudly_missing(
    mnotify_config, fake_keychain, capsys
) -> None:
    """An absent credential is a setup problem; show must not print it as present."""
    assert run_config("show") == EXIT_OK
    out = capsys.readouterr().out
    assert f"{ACCOUNT_CERT_PEM}: MISSING" in out


def test_secret_mode_reports_the_secret_account(config_file, fake_keychain, capsys) -> None:
    from micro_notify.config import AUTH_SECRET, write_config
    from conftest import placeholder_config

    config = placeholder_config(config_file.parent)
    object.__setattr__(config.mail, "auth", AUTH_SECRET)
    write_config(config, config_file)
    fake_keychain.seed(ACCOUNT_CLIENT_SECRET, CANARY_SECRET)

    assert run_config("show") == EXIT_OK
    out = capsys.readouterr().out
    assert f"{ACCOUNT_CLIENT_SECRET}: present" in out
    assert CANARY_SECRET not in out
    # auth=secret must not claim a certificate is missing when none is expected.
    assert ACCOUNT_CERT_PEM not in out


# --- The config body itself --------------------------------------------------
def test_non_secret_values_are_printed_verbatim(mnotify_config, loaded_keychain, capsys) -> None:
    """Tenant/client/sender are identifiers, not secrets — masking them helps nobody."""
    assert run_config("show") == EXIT_OK
    out = capsys.readouterr().out
    assert "noreply@example.com" in out
    assert "certificate" in out


def test_teams_targets_are_listed_by_name_and_kind(
    mnotify_config, loaded_keychain, capsys
) -> None:
    """Names and kinds are config data; only the URL is secret (design §3.4)."""
    assert run_config("show") == EXIT_OK
    out = capsys.readouterr().out
    assert "alerts" in out and "channel" in out
    assert "dm" in out


def test_json_document_shape(mnotify_config, loaded_keychain, capsys) -> None:
    assert run_config("show", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["config"]["mail"]["sender"] == "noreply@example.com"
    accounts = {item["account"]: item["present"] for item in payload["keychain"]}
    assert accounts[ACCOUNT_CERT_PEM] is True
    assert accounts[ACCOUNT_CERT_THUMBPRINT] is True


def test_json_keychain_entries_are_presence_booleans_only(
    mnotify_config, loaded_keychain, capsys
) -> None:
    """A keychain entry carries account/service/present and nothing else."""
    assert run_config("show", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    for entry in payload["keychain"]:
        assert set(entry) == {"account", "service", "present"}


# --- Defensive masking -------------------------------------------------------
def test_a_url_shaped_config_value_is_masked() -> None:
    """No config key holds a URL today; if one appears later it must not print raw."""
    assert config_cmd.mask_value("webhook_url", canary_webhook_url()) == config_cmd.MASK
    assert config_cmd.mask_value("audit_url", canary_webhook_url()) == config_cmd.MASK


def test_a_secret_shaped_key_is_masked_even_without_a_url() -> None:
    assert config_cmd.mask_value("client_secret", "hunter2") == config_cmd.MASK
    assert config_cmd.mask_value("token", "abc") == config_cmd.MASK


def test_ordinary_values_pass_through_unchanged() -> None:
    assert config_cmd.mask_value("sender", "noreply@example.com") == "noreply@example.com"
    assert config_cmd.mask_value("daily_max", 200) == 200
    assert config_cmd.mask_value("domains", ["example.com"]) == ["example.com"]


def test_masking_reaches_nested_dicts_and_lists() -> None:
    masked = config_cmd.mask_value(
        "targets", {"alerts": {"url": canary_webhook_url(), "kind": "channel"}}
    )
    assert masked["alerts"]["kind"] == "channel"
    assert masked["alerts"]["url"] == config_cmd.MASK


def test_presence_report_never_reads_a_value_into_the_report(
    mnotify_config, loaded_keychain
) -> None:
    """presence_report's entries have no field a value could hide in."""
    report = config_cmd.presence_report((ACCOUNT_CERT_PEM, "teams:alerts"))
    assert [entry["present"] for entry in report] == [True, True]
    assert json.dumps(report).count(CANARY_PEM_BODY) == 0


# --- Failure and usage paths -------------------------------------------------
def test_show_on_a_broken_config_exits_2(config_file, capsys) -> None:
    config_file.write_text("[mail]\ntenant_id = \"not-a-guid\"\n", encoding="utf-8")
    assert run_config("show") == EXIT_USAGE


def test_show_without_the_show_action_exits_2(mnotify_config, capsys) -> None:
    assert run_config() == EXIT_USAGE
    assert "config show" in capsys.readouterr().err


def test_show_never_writes_anywhere(mnotify_config, loaded_keychain, tmp_path) -> None:
    """A read-only command must not create the audit log or the counter."""
    assert run_config("show") == EXIT_OK
    from micro_notify.config import load_config

    config = load_config(mnotify_config)
    assert not config.paths.audit.exists()
    assert not config.paths.counter_file.exists()


def test_show_does_not_touch_the_network(mnotify_config, loaded_keychain, monkeypatch) -> None:
    """Presence-only checks: no httpx client, no subprocess."""
    import httpx

    def explode(*_args, **_kwargs):
        raise AssertionError("config show attempted a network call")

    monkeypatch.setattr(httpx, "Client", explode)
    assert run_config("show") == EXIT_OK
