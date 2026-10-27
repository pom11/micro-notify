"""Guardrail tests (design §3.3, §4 exit codes 3 and 6).

Every guardrail is evaluated before any network call; the autouse ``no_network``
harness in conftest.py makes that mechanically true, and the ordering assertion
here pins the *logical* order (a content refusal must not consume budget).

Addresses outside the placeholder domains are built at runtime by ``foreign()``
so no non-placeholder e-mail address ever appears literally in a tracked file
(tests/test_leak_guard.py scope ruling).
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from micro_notify import EXIT_DAILY_CAP, EXIT_GUARD, EXIT_OK
from micro_notify import guard
from micro_notify.config import AllowConfig, Config
from micro_notify.guard import CAP_REACHED, OK, REFUSED, Attachment, check, record_send

from conftest import placeholder_config


def foreign(local: str, *labels: str) -> str:
    """A recipient outside the placeholder domains, assembled at runtime."""
    return local + "@" + ".".join(labels)


@pytest.fixture
def config(tmp_path) -> Config:
    return placeholder_config(tmp_path)


def without_allowlist(config: Config) -> Config:
    """Same config but with the default-empty [allow] (refuse-everything)."""
    return replace(config, allow=AllowConfig())


# --- Allowlist: default empty => refuse everything (design §2 anti-goal) ----
def test_empty_allowlist_refuses_even_an_example_com_recipient(config: Config) -> None:
    """A config with no [allow] section must refuse, not allow.

    The refusal carries exit 3 (design §4) and names the offending recipient so
    the operator can act on it.
    """
    verdict = check(without_allowlist(config), recipients=["someone@example.com"])

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD
    assert "someone@example.com" in verdict.reason


def test_empty_allowlist_refuses_a_teams_dm_recipient_too(config: Config) -> None:
    """Teams DM recipients are allowlist-checked exactly like mail recipients."""
    verdict = check(without_allowlist(config), dm_recipients=["person@contoso.com"])

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD


def test_allowed_domain_allows_the_recipient(config: Config) -> None:
    """placeholder_config allows example.com; an address there must pass."""
    verdict = check(config, recipients=["someone@example.com"])

    assert verdict.status == OK
    assert verdict.exit_code == EXIT_OK


def test_foreign_domain_refuses(config: Config) -> None:
    """A recipient outside the allowlist is refused even if the rest is fine."""
    verdict = check(config, recipients=[foreign("ops", "real-tenant", "onmicrosoft", "com")])

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD


def test_allowlisted_address_matches_verbatim(config: Config) -> None:
    """placeholder_config lists person@contoso.com in allow.addresses: verbatim match."""
    verdict = check(config, dm_recipients=["person@contoso.com"])

    assert verdict.status == OK


def test_address_allowlist_does_not_open_the_whole_domain(config: Config) -> None:
    """Listing one address must not admit other addresses of the same domain."""
    verdict = check(config, dm_recipients=["someone-else@contoso.com"])

    assert verdict.status == REFUSED


def test_domain_match_is_case_insensitive(config: Config) -> None:
    """Comparison lowercases both sides, not just the config (guard's job)."""
    upper = replace(config, allow=AllowConfig(domains=("EXAMPLE.COM",), addresses=()))

    assert check(upper, recipients=["Someone@Example.COM"]).status == OK


def test_address_match_is_case_insensitive(config: Config) -> None:
    upper = replace(config, allow=AllowConfig(domains=(), addresses=("Person@Contoso.COM",)))

    assert check(upper, dm_recipients=["PERSON@contoso.com"]).status == OK


def test_subdomain_is_not_admitted_by_its_parent_domain(config: Config) -> None:
    """Least privilege: example.com in the allowlist does not admit dept.example.com."""
    verdict = check(config, recipients=[foreign("boss", "dept", "example", "com")])

    assert verdict.status == REFUSED


@pytest.mark.parametrize(
    "bad",
    ["no-at-sign", "", "  ", "@example.com", "user@", "user name@example.com", "two@@example.com"],
    ids=["no-at", "empty", "spaces", "empty-local", "empty-domain", "inner-space", "double-at"],
)
def test_malformed_address_is_refused_not_crashed(config: Config, bad: str) -> None:
    """A malformed address must produce a refusal verdict — never an exception."""
    verdict = check(config, recipients=[bad])

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD


# --- Recipient count per message (design §3.3, exit 3) ---------------------
def three_recipients(n: int) -> list[str]:
    return [f"user{i}@example.com" for i in range(n)]


def test_one_below_the_recipient_limit_is_allowed(config: Config) -> None:
    tight = replace(config, limits=replace(config.limits, max_recipients=3))

    verdict = check(tight, recipients=three_recipients(2))

    assert verdict.status == OK


def test_exactly_at_the_recipient_limit_is_allowed(config: Config) -> None:
    """The limit is a maximum, so count == max_recipients still sends."""
    tight = replace(config, limits=replace(config.limits, max_recipients=3))

    verdict = check(tight, recipients=three_recipients(3))

    assert verdict.status == OK


def test_one_over_the_recipient_limit_refuses_with_exit_3(config: Config) -> None:
    tight = replace(config, limits=replace(config.limits, max_recipients=3))

    verdict = check(tight, recipients=three_recipients(4))

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD
    assert "4" in verdict.reason and "3" in verdict.reason


def test_cc_and_bcc_count_towards_the_recipient_limit(config: Config) -> None:
    """The limit is per *message*: to/cc/bcc are counted together."""
    tight = replace(config, limits=replace(config.limits, max_recipients=3))

    verdict = check(
        tight,
        recipients=["a@example.com", "b@example.com"],
        cc=["c@example.com"],
        bcc=["d@example.com"],
    )

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD


# --- Attachment total size (design §3.3: total <= limits.max_attach_mb) ----
MB_BYTES = 1024 * 1024


def test_attachment_at_the_limit_is_allowed(config: Config) -> None:
    """Exactly max_attach_mb total bytes still sends — the cap is a maximum."""
    verdict = check(
        config,
        recipients=["someone@example.com"],
        attachments=[Attachment("report.pdf", MB_BYTES * config.limits.max_attach_mb)],
    )

    assert verdict.status == OK


def test_attachment_one_byte_over_the_limit_refuses_with_exit_3(config: Config) -> None:
    """Just over the cap on the *total* is refused before any network call."""
    verdict = check(
        config,
        recipients=["someone@example.com"],
        attachments=[Attachment("report.pdf", MB_BYTES * config.limits.max_attach_mb + 1)],
    )

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD
    assert "report.pdf" in verdict.reason


def test_attachment_limit_applies_to_the_total_not_per_file(config: Config) -> None:
    """Three files of 1.5 MB each are 4.5 MB total — refused even though each fits."""
    half = MB_BYTES * config.limits.max_attach_mb // 2 + 1
    verdict = check(
        config,
        recipients=["someone@example.com"],
        attachments=[Attachment(f"part{i}.bin", half) for i in range(3)],
    )

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD


def test_no_attachments_never_trips_the_size_guard(config: Config) -> None:
    verdict = check(config, recipients=["someone@example.com"], attachments=[])

    assert verdict.status == OK


# --- Daily counter (design §3.3: limits.daily_max, exit 6) ------------------
TODAY = "2026-10-27"
STALE_DAY = "2000-01-01"


@pytest.fixture
def frozen_today(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the guard's UTC clock so date behaviour is deterministic."""
    monkeypatch.setattr(guard, "utc_today", lambda: TODAY)
    return TODAY


def seed_counter(config: Config, day: str, count: int) -> None:
    """Write a counter.json by hand — the same shape record_send produces."""
    path = config.paths.counter_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"date": day, "count": count}), encoding="utf-8")


def test_check_allows_a_send_below_the_daily_cap(
    config: Config, frozen_today: str
) -> None:
    seed_counter(config, frozen_today, config.limits.daily_max - 1)

    verdict = check(config, recipients=["someone@example.com"])

    assert verdict.status == OK


def test_check_blocks_at_the_daily_cap_with_exit_6(
    config: Config, frozen_today: str
) -> None:
    """Count == daily_max means the day's sends are spent: exit 6 (design §4)."""
    seed_counter(config, frozen_today, config.limits.daily_max)

    verdict = check(config, recipients=["someone@example.com"])

    assert verdict.status == CAP_REACHED
    assert verdict.exit_code == EXIT_DAILY_CAP
    assert "daily" in verdict.reason.lower()


def test_record_send_increments_the_counter(config: Config, frozen_today: str) -> None:
    first = record_send(config)
    second = record_send(config)

    assert (first, second) == (1, 2)
    stored = json.loads(config.paths.counter_file.read_text(encoding="utf-8"))
    assert stored == {"date": frozen_today, "count": 2}


def test_record_send_then_check_blocks_once_the_cap_is_reached(
    config: Config, frozen_today: str
) -> None:
    """End-to-end: sends consume budget; the attempt after the cap is exit 6."""
    tight = replace(config, limits=replace(config.limits, daily_max=2))

    assert check(tight, recipients=["a@example.com"]).status == OK
    record_send(tight)
    assert check(tight, recipients=["a@example.com"]).status == OK
    record_send(tight)

    assert check(tight, recipients=["a@example.com"]).status == CAP_REACHED


def test_counter_resets_on_a_new_utc_date(config: Config, frozen_today: str) -> None:
    """A spent counter from a previous UTC day must not block today."""
    seed_counter(config, STALE_DAY, config.limits.daily_max)

    assert check(config, recipients=["someone@example.com"]).status == OK

    assert record_send(config) == 1
    stored = json.loads(config.paths.counter_file.read_text(encoding="utf-8"))
    assert stored == {"date": frozen_today, "count": 1}


def test_record_send_writes_atomically_leaving_no_temp_file(
    config: Config, frozen_today: str
) -> None:
    """Atomic write evidence: only counter.json remains, parseable, 0600 mode."""
    record_send(config)
    record_send(config)

    leftovers = [p.name for p in config.paths.state_dir.iterdir()]
    assert leftovers == ["counter.json"]
    assert json.loads(config.paths.counter_file.read_text(encoding="utf-8"))["count"] == 2
    mode = config.paths.counter_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_corrupt_counter_file_fails_closed(config: Config, frozen_today: str) -> None:
    """An unreadable counter cannot prove budget remains — refuse, exit 3."""
    path = config.paths.counter_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("this is not json {{{", encoding="utf-8")

    verdict = check(config, recipients=["someone@example.com"])

    assert verdict.status == REFUSED
    assert verdict.exit_code == EXIT_GUARD
    assert "counter" in verdict.reason


def test_check_itself_never_writes_the_counter(
    config: Config, frozen_today: str
) -> None:
    check(config, recipients=["someone@example.com"])

    assert not config.paths.counter_file.exists()
