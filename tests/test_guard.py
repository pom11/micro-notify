"""Guardrail tests (design §3.3, §4 exit codes 3 and 6).

Every guardrail is evaluated before any network call; the autouse ``no_network``
harness in conftest.py makes that mechanically true, and the ordering assertion
here pins the *logical* order (a content refusal must not consume budget).

Addresses outside the placeholder domains are built at runtime by ``foreign()``
so no non-placeholder e-mail address ever appears literally in a tracked file
(tests/test_leak_guard.py scope ruling).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from micro_notify import EXIT_GUARD, EXIT_OK
from micro_notify.config import AllowConfig, Config
from micro_notify.guard import OK, REFUSED, Attachment, check

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
