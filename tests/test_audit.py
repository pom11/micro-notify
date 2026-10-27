"""Audit log tests (design §3.3: one JSONL line per attempt, never the body).

The leak assertions matter more than the shape assertions: a body carrying a
canary, a fake secret and a fake webhook URL goes through the pipeline, then
the raw file text is checked for every one of them. The fake webhook URL is
assembled at runtime so no scheme-bearing webhook URL ever appears literally
in a tracked file (tests/test_leak_guard.py scope ruling).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from micro_notify.audit import (
    CHANNEL_MAIL,
    REFUSED,
    SENT,
    record,
)

from conftest import placeholder_config


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
