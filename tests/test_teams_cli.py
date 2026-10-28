"""``mnotify teams ...`` command tests (design §4) — build step 4 (P4).

Keychain goes through the shared ``fake_keychain`` fixture; config through
``mnotify_config`` (paths redirected to tmp_path). Every HTTP call is served by
``httpx.MockTransport`` through the ``mock_http`` fixture below: these tests
exercise the real chain ``cli.main`` -> ``commands.teams`` -> ``teams.post_card``
-> ``httpx.Client`` and replace only the transport, so no socket is opened
(design §7, and the autouse ``no_network`` harness makes it impossible anyway).
"""

from __future__ import annotations

import json

import httpx
import pytest

from micro_notify import cli

CANARY_URL = "https://" + "example.com/hidden-canary-sig"


def run(argv: list[str]) -> int:
    return cli.main(argv)


class Recorded:
    """Requests seen by a MockTransport, answering with canned responses."""

    def __init__(self, responses: list[tuple[int, dict, dict]]) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, headers, body = (
            self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        )
        return httpx.Response(status, headers=headers, json=body)

    @property
    def bodies(self) -> list[dict]:
        return [json.loads(r.content.decode("utf-8")) for r in self.requests]


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch):
    """Install a MockTransport-backed ``httpx.Client``; return a factory."""
    real_client = httpx.Client

    def install(responses: list[tuple[int, dict, dict]]) -> Recorded:
        recorded = Recorded(responses)

        def fake_client(**kwargs):
            kwargs.pop("transport", None)  # the only seam: swap the transport
            return real_client(transport=httpx.MockTransport(recorded.handle), **kwargs)

        monkeypatch.setattr(httpx, "Client", fake_client)
        return recorded

    return install


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


# --- send: the full tail — config -> guard -> (dry-run stop) -> POST -> audit -


def test_send_channel_missing_keychain_url_is_exit_4_naming_the_account(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    recorded = mock_http([(202, {}, {})])

    code = run(["teams", "send", "alerts", "--text", "hi"])

    err = capsys.readouterr().err
    assert code == 4
    assert "teams:alerts" in err
    assert CANARY_URL not in err
    assert recorded.requests == []  # exit 4 before any HTTP


def test_send_dm_recipient_outside_allowlist_is_exit_3_with_zero_http(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    fake_keychain.seed("teams:dm", CANARY_URL)
    recorded = mock_http([(202, {}, {})])

    # contoso.com is a placeholder domain but NOT in this config's allow list
    # (which holds domain example.com + the verbatim person@contoso.com).
    code = run(["teams", "send", "dm", "--to", "outsider@contoso.com", "--text", "hi"])

    assert code == 3
    assert recorded.requests == []
    assert "outsider@contoso.com" in capsys.readouterr().err


def test_send_refusal_is_audited_as_one_refused_line(
    mnotify_config, fake_keychain, mock_http, read_json_lines
) -> None:
    """Design §3.3: every attempt gets a line — refused ones included."""
    from micro_notify.config import load_config

    fake_keychain.seed("teams:dm", CANARY_URL)
    mock_http([(202, {}, {})])

    run(["teams", "send", "dm", "--to", "outsider@contoso.com", "--text", "hi"])

    lines = read_json_lines(load_config(mnotify_config).paths.audit)
    assert [e["outcome"] for e in lines] == ["refused"]
    assert lines[0]["channel"] == "teams"
    assert lines[0]["target"] == "dm"


def test_send_refusal_does_not_consume_the_daily_budget(
    mnotify_config, fake_keychain, mock_http
) -> None:
    from micro_notify.config import load_config

    fake_keychain.seed("teams:dm", CANARY_URL)
    mock_http([(202, {}, {})])

    run(["teams", "send", "dm", "--to", "outsider@contoso.com", "--text", "hi"])

    assert not load_config(mnotify_config).paths.counter_file.exists()


def test_send_dry_run_prints_masked_payload_and_zero_network(
    mnotify_config, fake_keychain, mock_http, capsys, read_json_lines
) -> None:
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)
    recorded = mock_http([(202, {}, {})])

    code = run(["teams", "send", "alerts", "--text", "hello", "--dry-run"])

    out = capsys.readouterr()
    assert code == 0
    # Security property, not a mask format: the signature must be gone, while
    # scheme+host stay visible so the operator can confirm the right target.
    assert CANARY_URL not in out.out and CANARY_URL not in out.err
    assert "example.com" in out.out
    assert "hidden-canary-sig" not in out.out
    assert recorded.requests == []  # dry-run performs no HTTP at all
    lines = read_json_lines(load_config(mnotify_config).paths.audit)
    assert lines and lines[-1]["outcome"] == "dry_run"
    assert lines[-1]["channel"] == "teams"


def test_send_dry_run_does_not_consume_the_daily_budget(
    mnotify_config, fake_keychain, mock_http
) -> None:
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)
    mock_http([(202, {}, {})])

    assert run(["teams", "send", "alerts", "--text", "hi", "--dry-run"]) == 0

    assert not load_config(mnotify_config).paths.counter_file.exists()


def test_send_channel_posts_the_workflow_message_body_verbatim(
    mnotify_config, fake_keychain, mock_http
) -> None:
    """The wire body for a channel target is exactly the design §3.2 template."""
    fake_keychain.seed("teams:alerts", CANARY_URL)
    recorded = mock_http([(202, {}, {})])

    code = run(["teams", "send", "alerts", "--text", "deploy finished"])

    assert code == 0
    assert recorded.requests[0].method == "POST"
    assert recorded.bodies == [
        {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "text": "deploy finished", "wrap": True}
                        ],
                    },
                }
            ],
        }
    ]


def test_send_dm_posts_the_recipient_and_card_body(
    mnotify_config, fake_keychain, mock_http
) -> None:
    fake_keychain.seed("teams:dm", CANARY_URL)
    recorded = mock_http([(202, {}, {})])

    code = run(["teams", "send", "dm", "--to", "person@contoso.com", "--text", "hi"])

    assert code == 0
    body = recorded.bodies[0]
    assert body["recipient"] == "person@contoso.com"
    assert body["attachments"][0]["type"] == "AdaptiveCard"


def test_send_ok_exits_0_audits_sent_and_counts_the_send(
    mnotify_config, fake_keychain, mock_http, read_json_lines
) -> None:
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)
    mock_http([(202, {}, {})])

    code = run(["teams", "send", "alerts", "--text", "hello"])

    assert code == 0
    config = load_config(mnotify_config)
    lines = read_json_lines(config.paths.audit)
    assert lines and lines[-1]["outcome"] == "sent"
    assert lines[-1]["target"] == "alerts"
    counter = json.loads(config.paths.counter_file.read_text(encoding="utf-8"))
    assert counter["count"] == 1


def test_send_json_mode_reports_sent_without_the_url(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    fake_keychain.seed("teams:alerts", CANARY_URL)
    mock_http([(202, {}, {})])

    code = run(["teams", "send", "alerts", "--text", "hello", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["outcome"] == "sent"
    assert payload["target"] == "alerts"
    assert CANARY_URL not in json.dumps(payload)


def test_send_non_2xx_is_exit_5_audits_failed_and_spares_the_budget(
    mnotify_config, fake_keychain, mock_http, capsys, read_json_lines
) -> None:
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)
    mock_http([(400, {}, {"error": "bad card"})])

    code = run(["teams", "send", "alerts", "--text", "hello"])

    err = capsys.readouterr().err
    assert code == 5
    assert "400" in err and "bad card" in err
    assert CANARY_URL not in err
    config = load_config(mnotify_config)
    assert [e["outcome"] for e in read_json_lines(config.paths.audit)] == ["failed"]
    assert not config.paths.counter_file.exists()  # a failed send spends nothing


def test_send_daily_cap_is_exit_6_with_zero_http(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    from micro_notify import guard
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)
    recorded = mock_http([(202, {}, {})])
    config = load_config(mnotify_config)
    config.paths.counter_file.parent.mkdir(parents=True, exist_ok=True)
    config.paths.counter_file.write_text(
        json.dumps({"date": guard.utc_today(), "count": config.limits.daily_max}),
        encoding="utf-8",
    )

    code = run(["teams", "send", "alerts", "--text", "hello"])

    assert code == 6
    assert recorded.requests == []
    assert "daily" in capsys.readouterr().err


def test_send_succeeds_after_a_429_and_honours_retry_after(
    mnotify_config, fake_keychain, mock_http, monkeypatch
) -> None:
    """End-to-end §9 retry through the CLI: the fake clock proves no sleeping."""
    fake_keychain.seed("teams:alerts", CANARY_URL)
    recorded = mock_http([(429, {"Retry-After": "5"}, {"err": "slow"}), (202, {}, {})])
    delays: list[float] = []
    monkeypatch.setattr("micro_notify.teams.time.sleep", delays.append)

    code = run(["teams", "send", "alerts", "--text", "hello"])

    assert code == 0
    assert len(recorded.requests) == 2
    assert delays == [5.0]


def test_card_file_is_posted_verbatim(
    mnotify_config, fake_keychain, mock_http, tmp_path
) -> None:
    card = {"type": "AdaptiveCard", "version": "1.4", "body": [], "custom": {"keep": True}}
    path = tmp_path / "card.json"
    path.write_text(json.dumps(card), encoding="utf-8")
    fake_keychain.seed("teams:alerts", CANARY_URL)
    recorded = mock_http([(202, {}, {})])

    code = run(["teams", "send", "alerts", "--card-file", str(path)])

    assert code == 0
    assert recorded.bodies[0]["attachments"][0]["content"] == card


def test_canary_url_absent_from_every_output_surface(
    mnotify_config, fake_keychain, mock_http, capsys, read_json_lines
) -> None:
    """End-to-end canary: URL must not reach stdout/stderr/config/audit."""
    from micro_notify.config import load_config

    fake_keychain.seed("teams:alerts", CANARY_URL)
    mock_http([(202, {}, {})])

    dry = run(["teams", "send", "alerts", "--text", "hello", "--dry-run"])
    sent = run(["teams", "send", "alerts", "--text", "hello"])
    listed = run(["teams", "targets", "list"])

    # Not vacuous: every command must have actually succeeded.
    assert dry == 0
    assert sent == 0
    assert listed == 0
    out = capsys.readouterr()
    config = load_config(mnotify_config)
    audit_text = config.paths.audit.read_text(encoding="utf-8") if config.paths.audit.exists() else ""
    config_text = mnotify_config.read_text(encoding="utf-8")
    assert CANARY_URL not in out.out
    assert CANARY_URL not in out.err
    assert CANARY_URL not in audit_text
    assert CANARY_URL not in config_text
