"""``mnotify log [--tail N] [--json]`` — read the audit JSONL back (design §3.3, §4).

Requirements pinned here from the card: ``--tail N`` returns the last N entries,
``--json`` parses, and a missing or empty audit file is *not* an error. Plus the
design §7 guarantee that stays true of the reader as well as the writer: a body, a
secret or a webhook URL must not reach the terminal.

These tests are pins, not bug reports: ``log`` was implemented by the scaffold
(design §8 covers audit *writing* in step 2, and no later step owns the reader), so
a test that passes on first sight is proving the card's requirement is met.
"""

from __future__ import annotations

import json

import pytest

from micro_notify import EXIT_OK, cli
from micro_notify.commands import log as log_cmd
from micro_notify.config import load_config

BODY_MARKER = "BODY-TEXT-MUST-NEVER-PRINT"
CANARY_URL_FRAGMENT = "R7x9Qm2"


def canary_webhook_url() -> str:
    host = ".".join(["tenant-abc", "logic", "azure"]) + ".com"
    return "https" + "://" + host + "/triggers/" + CANARY_URL_FRAGMENT + "/HTTP"


def run_log(*argv: str) -> int:
    return cli.main(["log", *argv])


def entry(**overrides) -> dict:
    """One audit line in the shape audit.record writes (design §3.3)."""
    record = {
        "ts": "2026-10-27T12:00:00Z",
        "channel": "mail",
        "outcome": "sent",
        "sender": "noreply@example.com",
        "recipients": ["someone@example.com"],
        "subject": "build report",
        "body_sha256": "a" * 64,
        "body_size": 12,
    }
    record.update(overrides)
    return record


@pytest.fixture
def audit_path(mnotify_config):
    return load_config(mnotify_config).paths.audit


def write_audit(audit_path, records: list[object]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for record in records:
        lines.append(record if isinstance(record, str) else json.dumps(record))
    audit_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# --- tail --------------------------------------------------------------------
def test_tail_returns_the_last_n_entries_in_order(audit_path, capsys) -> None:
    write_audit(audit_path, [entry(subject=f"msg {i}") for i in range(1, 6)])
    assert run_log("--tail", "2", "--json") == EXIT_OK
    subjects = [e["subject"] for e in json.loads(capsys.readouterr().out)["entries"]]
    assert subjects == ["msg 4", "msg 5"]


def test_tail_larger_than_the_file_returns_everything(audit_path, capsys) -> None:
    write_audit(audit_path, [entry(subject="only one")])
    assert run_log("--tail", "50", "--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert [e["subject"] for e in payload["entries"]] == ["only one"]


def test_tail_zero_shows_all_entries(audit_path, capsys) -> None:
    write_audit(audit_path, [entry(subject=f"msg {i}") for i in range(1, 8)])
    assert run_log("--tail", "0", "--json") == EXIT_OK
    assert json.loads(capsys.readouterr().out)["count"] == 7


def test_default_tail_is_bounded(audit_path, capsys) -> None:
    """A 10k-line audit file must not be dumped by `mnotify log` alone."""
    write_audit(audit_path, [entry(subject=f"msg {i}") for i in range(100)])
    assert run_log("--json") == EXIT_OK
    assert json.loads(capsys.readouterr().out)["count"] == log_cmd.DEFAULT_TAIL


def test_human_mode_prints_the_tail_only(audit_path, capsys) -> None:
    write_audit(audit_path, [entry(subject=f"msg {i}") for i in range(1, 6)])
    assert run_log("--tail", "1") == EXIT_OK
    out = capsys.readouterr().out
    assert "msg 5" in out
    assert "msg 1" not in out


# --- empty and missing files are not errors ----------------------------------
def test_missing_audit_file_is_not_an_error(mnotify_config, capsys) -> None:
    assert run_log() == EXIT_OK
    assert "no audit entries" in capsys.readouterr().out


def test_missing_audit_file_in_json_mode_is_a_clean_empty_report(
    mnotify_config, capsys
) -> None:
    assert run_log("--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["count"] == 0
    assert payload["entries"] == []


def test_empty_audit_file_is_not_an_error(audit_path, capsys) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text("", encoding="utf-8")
    assert run_log() == EXIT_OK
    assert "no audit entries" in capsys.readouterr().out


def test_whitespace_only_audit_file_is_not_an_error(audit_path, capsys) -> None:
    write_audit(audit_path, ["", "   ", "\t"])
    assert run_log("--json") == EXIT_OK
    assert json.loads(capsys.readouterr().out)["count"] == 0


# --- malformed lines are counted, not hidden ---------------------------------
def test_malformed_lines_are_counted_and_the_rest_still_prints(audit_path, capsys) -> None:
    write_audit(audit_path, [entry(), "{not json", entry(subject="second")])
    assert run_log("--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert payload["malformed"] == 1


def test_malformed_lines_are_announced_in_human_mode(audit_path, capsys) -> None:
    write_audit(audit_path, ["{not json"])
    assert run_log() == EXIT_OK
    assert "malformed" in capsys.readouterr().out


def test_a_json_array_line_is_malformed_not_a_valid_entry(audit_path, capsys) -> None:
    """Only objects are audit records; a bare list would crash field printing."""
    write_audit(audit_path, ["[1, 2, 3]"])
    assert run_log("--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 0
    assert payload["malformed"] == 1


# --- nothing secret reaches the terminal ------------------------------------
def test_human_mode_never_prints_a_body_field(audit_path, capsys) -> None:
    """The writer must not record bodies; the reader must not print one either."""
    write_audit(audit_path, [entry(body=BODY_MARKER)])
    assert run_log() == EXIT_OK
    assert BODY_MARKER not in capsys.readouterr().out


def test_human_mode_never_prints_a_webhook_url(audit_path, capsys) -> None:
    write_audit(audit_path, [entry(channel="teams", target="alerts", target_url=canary_webhook_url())])
    assert run_log() == EXIT_OK
    blob = capsys.readouterr().out
    assert CANARY_URL_FRAGMENT not in blob
    assert "triggers" not in blob


def test_json_mode_is_the_passthrough_documented_for_agents(audit_path, capsys) -> None:
    """--json gives the entries as recorded, so an agent can read outcomes."""
    write_audit(audit_path, [entry(outcome="refused", subject="nope")])
    assert run_log("--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["entries"][0]["outcome"] == "refused"


def test_human_mode_prints_recipients_for_an_agent_visible_summary(
    audit_path, capsys
) -> None:
    write_audit(audit_path, [entry()])
    assert run_log() == EXIT_OK
    assert "someone@example.com" in capsys.readouterr().out


def test_audit_path_is_reported_so_a_user_can_find_the_file(
    mnotify_config, audit_path, capsys
) -> None:
    write_audit(audit_path, [entry()])
    assert run_log("--json") == EXIT_OK
    assert json.loads(capsys.readouterr().out)["auditPath"] == str(audit_path)


# --- read-only guarantee -----------------------------------------------------
def test_log_never_creates_or_modifies_the_audit_file(mnotify_config, capsys) -> None:
    config = load_config(mnotify_config)
    assert run_log() == EXIT_OK
    assert not config.paths.audit.exists(), "`log` created the audit file"


def test_log_does_not_touch_the_keychain(mnotify_config, fake_keychain) -> None:
    assert run_log() == EXIT_OK
    assert fake_keychain.items == {}
    assert fake_keychain.audit == [], "log read a keychain account"


def test_log_does_not_need_a_keychain_or_a_network(
    mnotify_config, monkeypatch
) -> None:
    import httpx
    from micro_notify import secrets

    def explode(*_args, **_kwargs):
        raise AssertionError("log attempted a network call")

    monkeypatch.setattr(httpx, "Client", explode)
    monkeypatch.setattr(secrets, "get", explode)
    assert run_log() == EXIT_OK


def _stdout(capsys) -> str:
    return capsys.readouterr().out
