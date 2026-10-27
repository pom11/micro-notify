"""Audit log tests (design §3.3: one JSONL line per attempt, never the body).

The leak assertions matter more than the shape assertions: a body carrying a
canary, a fake secret and a fake webhook URL goes through the pipeline, then
the raw file text is checked for every one of them. Fake secret/webhook values
are assembled at runtime so no canary ever appears as a live secret or a
scheme-bearing webhook URL in a tracked file (tests/test_leak_guard.py scope).
"""

from __future__ import annotations

import hashlib
import json

from dataclasses import replace

import pytest

from micro_notify.audit import (
    CHANNEL_MAIL,
    DRY_RUN,
    FAILED,
    REFUSED,
    SENT,
    mask_url,
    record,
)
from micro_notify.config import AllowConfig
from micro_notify.guard import Attachment

from conftest import placeholder_config


def without_allowlist(config):
    """Same config but with the default-empty [allow] (refuse-everything)."""
    return replace(config, allow=AllowConfig())

# Fake values for the leak probe. The webhook host and the "secret" are
# assembled at runtime; nothing here is a real credential.
CANARY_BODY = "SECRET-CANARY-42 the quick brown fox jumps"
FAKE_SECRET = "fake-t0ken-" + "9e1f2a3b4c5d"
FAKE_WEBHOOK = "https" + "://" + "tenant-abc.demo.example" + "/triggers/x7Qm2/HTTP"


@pytest.fixture
def config(tmp_path):
    return placeholder_config(tmp_path)


def lines(config) -> list[dict]:
    text = config.paths.audit.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


# --- One JSONL line per attempt ---------------------------------------------
def test_record_writes_exactly_one_line_per_attempt(config) -> None:
    record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
           recipients=["someone@example.com"], subject="hi", body="first")
    record(config, channel=CHANNEL_MAIL, outcome=REFUSED, sender="noreply@example.com",
           recipients=["stranger@example.com"], subject="no", body="second")

    entries = lines(config)
    assert len(entries) == 2
    assert [e["outcome"] for e in entries] == [SENT, REFUSED]


def test_record_creates_missing_parent_directories(config) -> None:
    assert not config.paths.audit.parent.exists()

    record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
           recipients=["someone@example.com"], subject="hi", body="hello")

    assert config.paths.audit.is_file()


def test_record_appends_rather_than_truncates(config) -> None:
    for i in range(3):
        record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
               recipients=["someone@example.com"], subject=f"n{i}", body="x")

    entries = lines(config)
    assert [e["subject"] for e in entries] == ["n0", "n1", "n2"]


def test_audit_file_is_owner_only(config) -> None:
    """Audit lines carry recipient addresses — mode 0600, like the config."""
    record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
           recipients=["someone@example.com"], subject="hi", body="hello")

    assert config.paths.audit.stat().st_mode & 0o777 == 0o600


# --- Never the body, never a secret, never a webhook URL --------------------
def test_body_content_never_reaches_the_audit_file(config) -> None:
    """Canary + fake secret + fake webhook in the body: only sha256 and size land."""
    body = f"{CANARY_BODY} token={FAKE_SECRET} post to {FAKE_WEBHOOK} now"

    record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
           recipients=["someone@example.com"], subject="standup", body=body)

    raw = config.paths.audit.read_text(encoding="utf-8")
    assert CANARY_BODY not in raw
    assert FAKE_SECRET not in raw
    assert FAKE_WEBHOOK not in raw
    # ...and the two fields that describe the body instead of carrying it:
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in raw
    assert str(len(body.encode("utf-8"))) in raw


def test_subject_is_recorded_verbatim_but_body_still_never_is(config) -> None:
    """Subjects/titles are audit fields by design; bodies are not — keep the line."""
    record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
           recipients=["someone@example.com"],
           subject="deploy done", body=CANARY_BODY)

    entry = lines(config)[0]
    assert entry["subject"] == "deploy done"
    assert CANARY_BODY not in config.paths.audit.read_text(encoding="utf-8")


def test_entry_carries_exactly_the_design_33_fields(config) -> None:
    """A full mail attempt: every design §3.3 field present, nothing extra."""
    record(config, channel=CHANNEL_MAIL, outcome=SENT, sender="noreply@example.com",
           recipients=["someone@example.com", "cc2@example.com"], subject="hi",
           body="hello", attachments=[Attachment("report.pdf", 1234)],
           request_id="graph-req-1")

    entry = lines(config)[0]
    assert set(entry) == {
        "ts", "channel", "outcome", "sender", "recipients", "subject",
        "body_sha256", "body_size", "attachments", "request_id",
    }
    assert entry["channel"] == "mail"
    assert entry["recipients"] == ["someone@example.com", "cc2@example.com"]
    assert entry["attachments"] == [{"name": "report.pdf", "size_bytes": 1234}]
    assert entry["request_id"] == "graph-req-1"


def test_teams_entry_uses_target_and_title(config) -> None:
    """Teams attempts carry the target name and card title (design §3.3)."""
    record(config, channel="teams", outcome=SENT, target="alerts",
           title="build failed", body="job 42 red")

    entry = lines(config)[0]
    assert entry["channel"] == "teams"
    assert entry["target"] == "alerts"
    assert entry["title"] == "build failed"
    assert "sender" not in entry and "subject" not in entry


def test_no_request_id_field_when_absent(config) -> None:
    """Graph request-id appears only when present (design §3.3: 'when present')."""
    record(config, channel=CHANNEL_MAIL, outcome=REFUSED, sender="noreply@example.com",
           recipients=["someone@example.com"], subject="x", body="y")

    assert "request_id" not in lines(config)[0]


# --- Guard refusal -> `refused` audit line (card: "refuses ... and writes a
#     refused audit line"). The command layer maps the verdict to exit 3; the
#     audit writer stamps the same outcome name on the line.
def test_guard_refusal_is_audited_as_refused(config) -> None:
    """A refused attempt still produces exactly one audit line (design §3.3)."""
    from micro_notify.guard import check

    verdict = check(without_allowlist(config), recipients=["someone@example.com"])
    assert verdict.status == REFUSED

    record(config, channel=CHANNEL_MAIL, outcome=verdict.status,
           sender="noreply@example.com", recipients=["someone@example.com"],
           subject="hi", body="never sent")

    entry = lines(config)[0]
    assert entry["outcome"] == "refused"
    assert verdict.exit_code == 3  # the exit code the command must return
    # The body of a refused message is never stored either:
    assert "never sent" not in config.paths.audit.read_text(encoding="utf-8")


def test_dry_run_and_failed_outcomes_are_auditable(config) -> None:
    """dry_run / failed are first-class outcomes, one line each."""
    record(config, channel=CHANNEL_MAIL, outcome=DRY_RUN, sender="noreply@example.com",
           recipients=["someone@example.com"], subject="s", body="b")
    record(config, channel="teams", outcome=FAILED, target="alerts", title="t",
           body="b", request_id="req-9")

    entries = lines(config)
    assert [e["outcome"] for e in entries] == [DRY_RUN, FAILED]
    assert entries[1]["request_id"] == "req-9"


# --- mask_url: safe for --dry-run output and error paths (design §3.3) ------
def test_mask_url_keeps_only_scheme_and_host() -> None:
    """The webhook path carries the signature — everything after the host goes."""
    url = FAKE_WEBHOOK + "?sig=Sup3rSecretSignature"

    masked = mask_url(url)

    assert masked == "https://tenant-abc.demo.example/***"
    assert "x7Qm2" not in masked and "Sup3rSecretSignature" not in masked


def test_mask_url_strips_credentials_and_port() -> None:
    """Netloc userinfo is a secret too; host means hostname only."""
    assert mask_url("https://user:pw@example.com:8443/path") == "https://example.com/***"


def test_mask_url_never_echoes_unparseable_input() -> None:
    """An error path may pass anything in; the fallback must not repeat it."""
    assert mask_url(FAKE_SECRET) == "***"
    assert mask_url("") == "***"
    assert mask_url("no-scheme.example/path") == "***"
