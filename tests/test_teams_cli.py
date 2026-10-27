"""``mnotify teams ...`` command tests (design §4) — build step 4 (P4).

Keychain goes through the shared ``fake_keychain`` fixture; config through
``mnotify_config`` (paths redirected to tmp_path). No sockets, no keychain
binary, no audit assumptions here: these tests cover the target management
surface plus the send-path errors that fire before guard/audit.
"""

from __future__ import annotations

import json

import httpx
import pytest

from micro_notify import cli

CANARY_URL = "https://" + "example.com/hidden-canary-sig"


def run(argv: list[str]) -> int:
    return cli.main(argv)


# --- targets add -------------------------------------------------------------
def test_targets_add_stores_url_in_keychain_under_teams_account(
    mnotify_config, fake_keychain, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda prompt="": CANARY_URL)

    code = run(["teams", "targets", "add", "alerts", "--kind", "channel"])

    assert code == 0
    assert fake_keychain.items["teams:alerts"] == CANARY_URL


def test_targets_add_writes_only_name_and_kind_into_config(
    mnotify_config, fake_keychain, monkeypatch
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda prompt="": CANARY_URL)

    run(["teams", "targets", "add", "newt", "--kind", "dm"])

    text = mnotify_config.read_text(encoding="utf-8")
    assert '[teams.targets.newt]' in text
    assert 'kind = "dm"' in text
    assert CANARY_URL not in text


def test_targets_add_never_prints_the_url(
    mnotify_config, fake_keychain, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda prompt="": CANARY_URL)

    code = run(["teams", "targets", "add", "alerts", "--kind", "channel"])

    assert code == 0  # not vacuous: the command must have actually succeeded
    out = capsys.readouterr()
    assert CANARY_URL not in out.out
    assert CANARY_URL not in out.err


def test_targets_add_rejects_a_url_without_https_scheme(
    mnotify_config, fake_keychain, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "not-a-url")

    code = run(["teams", "targets", "add", "alerts", "--kind", "channel"])

    assert code == 2
    assert "https" in capsys.readouterr().err
    assert fake_keychain.items == {}


def test_targets_add_rejects_a_name_that_is_not_a_toml_key(
    mnotify_config, fake_keychain, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda prompt="": CANARY_URL)

    code = run(["teams", "targets", "add", "bad.name", "--kind", "channel"])

    assert code == 2
    assert "bad.name" in capsys.readouterr().err
    assert fake_keychain.items == {}


def test_targets_add_checks_config_before_prompting_for_the_secret(
    tmp_path, fake_keychain, monkeypatch
) -> None:
    """A broken config must fail before the operator pastes a URL (no wasted secret)."""
    from micro_notify.config import CONFIG_ENV_VAR

    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "missing.toml"))

    def boom(prompt: str = "") -> str:
        raise AssertionError("getpass must not be reached when config is broken")

    monkeypatch.setattr("getpass.getpass", boom)

    assert run(["teams", "targets", "add", "alerts", "--kind", "channel"]) == 2


# --- targets list ------------------------------------------------------------
def test_targets_list_shows_name_kind_and_presence_not_the_url(
    mnotify_config, fake_keychain, capsys
) -> None:
    fake_keychain.seed("teams:alerts", CANARY_URL)

    code = run(["teams", "targets", "list"])

    out = capsys.readouterr().out
    assert code == 0
    assert "alerts" in out and "channel" in out and "present" in out
    assert "dm" in out and "missing" in out
    assert CANARY_URL not in out


def test_targets_list_json_reports_presence(
    mnotify_config, fake_keychain, capsys
) -> None:
    fake_keychain.seed("teams:alerts", CANARY_URL)

    code = run(["teams", "targets", "list", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["targets"] == [
        {"name": "alerts", "kind": "channel", "url": "present"},
        {"name": "dm", "kind": "dm", "url": "missing"},
    ]
    assert CANARY_URL not in capsys.readouterr().out


# --- targets remove ----------------------------------------------------------
def test_targets_remove_drops_config_entry_and_keychain_account(
    mnotify_config, fake_keychain, capsys
) -> None:
    fake_keychain.seed("teams:alerts", CANARY_URL)

    code = run(["teams", "targets", "remove", "alerts"])

    assert code == 0
    text = mnotify_config.read_text(encoding="utf-8")
    assert "[teams.targets.alerts]" not in text
    assert "teams:alerts" not in fake_keychain.items


def test_targets_remove_unknown_name_is_a_usage_error(
    mnotify_config, fake_keychain, capsys
) -> None:
    code = run(["teams", "targets", "remove", "ghost"])

    assert code == 2
    assert "ghost" in capsys.readouterr().err


# --- send: errors that fire before any guard/network (P2-independent) -------
def test_send_unknown_target_is_exit_2_naming_the_target(
    mnotify_config, fake_keychain, capsys
) -> None:
    code = run(["teams", "send", "ghost", "--text", "hi"])

    err = capsys.readouterr().err
    assert code == 2
    assert "ghost" in err


def test_send_dm_without_to_is_exit_2(mnotify_config, fake_keychain, capsys) -> None:
    fake_keychain.seed("teams:dm", CANARY_URL)

    code = run(["teams", "send", "dm", "--text", "hi"])

    assert code == 2
    assert "--to" in capsys.readouterr().err


# --- send: stages that require guard.py + audit.py (build step 2, P2) --------
# xfail(strict): these pin the contract and turn the suite RED the moment the
# implementation exists, forcing the marker to be removed on resume.
P2_PENDING = "blocked on guard/audit (build step 2 / card t_bab5345d); remove marker when merged"


@pytest.mark.xfail(strict=True, reason=P2_PENDING)
def test_send_channel_missing_keychain_url_is_exit_4_naming_the_account(
    mnotify_config, fake_keychain, capsys
) -> None:
    code = run(["teams", "send", "alerts", "--text", "hi"])

    err = capsys.readouterr().err
    assert code == 4
    assert "teams:alerts" in err
    assert CANARY_URL not in err


@pytest.mark.xfail(strict=True, reason=P2_PENDING)
def test_send_dm_recipient_outside_allowlist_is_exit_3_with_zero_http(
    mnotify_config, fake_keychain, capsys
) -> None:
    from micro_notify import teams as teams_module

    fake_keychain.seed("teams:dm", CANARY_URL)
    calls: list[tuple[str, dict]] = []
    real_post = teams_module.post_card

    def spy(url, payload, **kw):
        calls.append((url, payload))
        return real_post(url, payload, **kw)

    teams_module.post_card = spy
    try:
        code = run(["teams", "send", "dm", "--to", "outsider@evil.example", "--text", "hi"])
    finally:
        teams_module.post_card = real_post

    assert code == 3
    assert calls == []


@pytest.mark.xfail(strict=True, reason=P2_PENDING)
def test_send_dry_run_prints_masked_payload_and_zero_network(
    mnotify_config, fake_keychain, capsys, read_json_lines
) -> None:
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)

    code = run(["teams", "send", "alerts", "--text", "hello", "--dry-run"])

    out = capsys.readouterr()
    assert code == 0
    assert CANARY_URL not in out.out and CANARY_URL not in out.err
    assert "https://example.com/***" in out.out  # masked form only
    config = load_config(mnotify_config)
    lines = read_json_lines(config.paths.audit)
    assert lines and lines[-1]["outcome"] == "dry_run"
    assert lines[-1]["channel"] == "teams"


@pytest.mark.xfail(strict=True, reason=P2_PENDING)
def test_send_ok_exits_0_and_audits_sent(mnotify_config, fake_keychain, capsys, read_json_lines, monkeypatch) -> None:
    from micro_notify import teams as teams_module
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)

    def fake_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={})

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(fake_transport), **{k: v for k, v in kw.items() if k != "transport"})
    )

    code = run(["teams", "send", "alerts", "--text", "hello"])

    assert code == 0
    config = load_config(mnotify_config)
    lines = read_json_lines(config.paths.audit)
    assert lines and lines[-1]["outcome"] == "sent"


@pytest.mark.xfail(strict=True, reason=P2_PENDING)
def test_canary_url_absent_from_every_output_surface(
    mnotify_config, fake_keychain, capsys, read_json_lines
) -> None:
    """End-to-end canary: URL must not reach stdout/stderr/config/audit."""
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)

    run(["teams", "send", "alerts", "--text", "hello", "--dry-run"])
    run(["teams", "targets", "list"])

    out = capsys.readouterr()
    config = load_config(mnotify_config)
    audit_text = config.paths.audit.read_text(encoding="utf-8") if config.paths.audit.exists() else ""
    config_text = mnotify_config.read_text(encoding="utf-8")
    assert CANARY_URL not in out.out
    assert CANARY_URL not in out.err
    assert CANARY_URL not in audit_text
    assert CANARY_URL not in config_text
