"""Tests for micro_notify.config (design section 3.4)."""

from __future__ import annotations

import os
import stat

import pytest

from micro_notify import EXIT_USAGE
from micro_notify.config import (
    CONFIG_ENV_VAR,
    DEFAULT_AUDIT_PATH,
    DEFAULT_STATE_DIR,
    KIND_CHAT,
    MAIL_MODES,
    MAIL_MODE_APP,
    MAIL_MODE_DELEGATED,
    AllowConfig,
    Config,
    ConfigError,
    LimitsConfig,
    MailConfig,
    PathsConfig,
    TeamTarget,
    config_path,
    load_config,
    mask_chat_id,
    parse_config,
    render_toml,
    with_team_target,
    without_team_target,
    write_config,
)
from micro_notify.secrets import (
    ACCOUNT_CERT_PEM,
    ACCOUNT_CERT_THUMBPRINT,
    ACCOUNT_CLIENT_SECRET,
)

from conftest import PLACEHOLDER_DOMAIN, PLACEHOLDER_GUID, PLACEHOLDER_SENDER

# A fake Teams chat id (design amendment 2026-10-30): chat ids are config data,
# not keychain secrets, and this one carries no real conversation address. The
# `.v2` suffix is not an alphabetic TLD, so the leak guard's e-mail pattern does
# not read it as a mailbox.
FAKE_CHAT_ID = "19:fake@thread.v2"
FAKE_CHAT_ID_LONG = "19:fake-conversation-4c9e@thread.v2"

VALID_TOML = """
[mail]
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
sender = "noreply@example.com"
auth = "certificate"
default_reply_to = ""

[allow]
domains = ["example.com"]
addresses = []

[limits]
max_recipients = 20
daily_max = 200
max_attach_mb = 3

[paths]
audit = "{audit}"
state_dir = "{state}"

[teams.targets.alerts]
kind = "channel"
[teams.targets.dm]
kind = "dm"
"""


def write_raw(tmp_path, text: str) -> str:
    path = tmp_path / "cfg.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- Loading ---------------------------------------------------------------
def test_loads_every_declared_key(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        VALID_TOML.format(audit=tmp_path / "sent.jsonl", state=tmp_path / "state"),
    )
    config = load_config(path)

    assert config.mail.tenant_id == PLACEHOLDER_GUID
    assert config.mail.sender == PLACEHOLDER_SENDER
    assert config.mail.auth == "certificate"
    assert config.allow.domains == (PLACEHOLDER_DOMAIN,)
    assert config.allow.addresses == ()
    assert config.limits == LimitsConfig(max_recipients=20, daily_max=200, max_attach_mb=3)
    assert config.paths.audit == tmp_path / "sent.jsonl"
    assert config.paths.state_dir == tmp_path / "state"
    assert [t.name for t in config.teams_targets] == ["alerts", "dm"]
    assert config.target("dm").kind == "dm"
    assert config.target("nope") is None


def test_defaults_apply_when_optional_sections_are_absent(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        """
[mail]
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
sender = "noreply@example.com"
auth = "secret"
default_reply_to = ""
""",
    )
    config = load_config(path)

    assert config.allow.domains == ()
    assert config.limits == LimitsConfig()
    assert str(config.paths.audit) == os.path.expanduser(DEFAULT_AUDIT_PATH)
    assert str(config.paths.state_dir) == os.path.expanduser(DEFAULT_STATE_DIR)
    assert config.paths.counter_file == config.paths.state_dir / "counter.json"
    assert config.teams_targets == ()


def test_env_var_overrides_the_default_path(tmp_path, monkeypatch) -> None:
    target = tmp_path / "elsewhere.toml"
    target.write_text(
        VALID_TOML.format(audit=tmp_path / "a.jsonl", state=tmp_path / "s"), encoding="utf-8"
    )
    monkeypatch.setenv(CONFIG_ENV_VAR, str(target))
    assert config_path() == target
    assert load_config().source_path == target


def test_explicit_argument_beats_env_var(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(CONFIG_ENV_VAR, str(tmp_path / "env.toml"))
    explicit = tmp_path / "explicit.toml"
    explicit.write_text(
        VALID_TOML.format(audit=tmp_path / "a.jsonl", state=tmp_path / "s"), encoding="utf-8"
    )
    assert load_config(explicit).source_path == explicit


def test_missing_file_is_a_config_error_that_maps_to_exit_2(tmp_path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "absent.toml")
    assert excinfo.value.exit_code == EXIT_USAGE
    assert "not found" in excinfo.value.message


def test_malformed_toml_is_a_config_error(tmp_path) -> None:
    path = write_raw(tmp_path, "[mail\nsender = ")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_config_file_mode_is_reported_but_not_rewritten_on_read(tmp_path) -> None:
    path = tmp_path / "cfg.toml"
    path.write_text(
        VALID_TOML.format(audit=tmp_path / "a.jsonl", state=tmp_path / "s"), encoding="utf-8"
    )
    os.chmod(path, 0o644)
    load_config(str(path))  # must not raise: loading is read-only
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


# --- Validation ------------------------------------------------------------
def toml_with(**overrides: str) -> str:
    """VALID_TOML with whole-line replacements applied (key -> new line)."""
    text = VALID_TOML
    for key, replacement in overrides.items():
        needle = next(line for line in text.splitlines() if line.strip().startswith(key + " ="))
        text = text.replace(needle, replacement)
    return text


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"tenant_id": 'tenant_id = "not-a-guid"'}, "GUID"),
        ({"client_id": 'client_id = "00000000-0000-0000-0000"'}, "GUID"),
        ({"auth": 'auth = "bearer"'}, "auth must be one of"),
        ({"sender": 'sender = "nope"'}, "mailbox address"),
        ({"max_recipients": "max_recipients = 0"}, "must be >= 1"),
        ({"daily_max": 'daily_max = "lots"'}, "must be an integer"),
        ({"domains": 'domains = "example.com"'}, "must be a list of strings"),
        ({"domains": 'domains = ["noreply@example.com"]'}, "bare domains"),
    ],
)
def test_bad_values_raise_typed_config_error(tmp_path, overrides, match) -> None:
    text = toml_with(**overrides).format(audit=tmp_path / "a.jsonl", state=tmp_path / "s")
    path = write_raw(tmp_path, text)
    with pytest.raises(ConfigError, match=match) as excinfo:
        load_config(path)
    assert excinfo.value.exit_code == EXIT_USAGE


def test_missing_required_mail_key_names_the_key(tmp_path) -> None:
    path = write_raw(tmp_path, '[mail]\nclient_id = "00000000-0000-0000-0000-000000000000"\n')
    with pytest.raises(ConfigError, match="missing required key 'tenant_id'"):
        load_config(path)


def test_unknown_team_kind_is_rejected(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        VALID_TOML.format(audit=tmp_path / "a.jsonl", state=tmp_path / "s").replace(
            'kind = "channel"', 'kind = "carrier-pigeon"'
        ),
    )
    with pytest.raises(ConfigError, match="kind must be one of"):
        load_config(path)


def test_relative_paths_are_rejected(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        VALID_TOML.format(audit="relative/sent.jsonl", state=tmp_path / "s"),
    )
    with pytest.raises(ConfigError, match="audit must be an absolute path"):
        load_config(path)


def test_tilde_paths_are_expanded(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        VALID_TOML.format(audit="~/mnotify-audit.jsonl", state="~/mnotify-state"),
    )
    config = load_config(path)
    assert config.paths.audit.is_absolute()
    assert str(config.paths.audit).endswith("mnotify-audit.jsonl")


def test_allow_entries_are_lowercased(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        VALID_TOML.format(audit=tmp_path / "a.jsonl", state=tmp_path / "s").replace(
            'domains = ["example.com"]', 'domains = ["EXAMPLE.COM"]'
        ).replace("addresses = []", 'addresses = ["Person@Contoso.COM"]'),
    )
    config = load_config(path)
    assert config.allow.domains == ("example.com",)
    assert config.allow.addresses == ("person@contoso.com",)


def test_empty_allowlist_is_represented_as_empty(tmp_path) -> None:
    path = write_raw(
        tmp_path,
        VALID_TOML.format(audit=tmp_path / "a.jsonl", state=tmp_path / "s").replace(
            'domains = ["example.com"]', "domains = []"
        ),
    )
    config = load_config(path)
    assert config.allow == AllowConfig()
    assert config.allow.domains == ()


# --- Keychain account expectation -----------------------------------------
def test_certificate_auth_requires_pem_and_thumbprint_accounts() -> None:
    config = parse_config(
        {
            "mail": {
                "tenant_id": PLACEHOLDER_GUID,
                "client_id": PLACEHOLDER_GUID,
                "sender": PLACEHOLDER_SENDER,
                "auth": "certificate",
                "default_reply_to": "",
            }
        }
    )
    assert config.mail.keychain_accounts() == (ACCOUNT_CERT_PEM, ACCOUNT_CERT_THUMBPRINT)


def test_secret_auth_requires_the_client_secret_account() -> None:
    config = parse_config(
        {
            "mail": {
                "tenant_id": PLACEHOLDER_GUID,
                "client_id": PLACEHOLDER_GUID,
                "sender": PLACEHOLDER_SENDER,
                "auth": "secret",
                "default_reply_to": "",
            }
        }
    )
    assert config.mail.keychain_accounts() == (ACCOUNT_CLIENT_SECRET,)


def test_config_keychain_accounts_include_teams_targets() -> None:
    config = parse_config(
        {
            "mail": {
                "tenant_id": PLACEHOLDER_GUID,
                "client_id": PLACEHOLDER_GUID,
                "sender": PLACEHOLDER_SENDER,
                "auth": "secret",
                "default_reply_to": "",
            },
            "teams": {"targets": {"alerts": {"kind": "channel"}}},
        }
    )
    assert config.keychain_accounts() == (ACCOUNT_CLIENT_SECRET, "teams:alerts")


def test_a_chat_target_needs_no_keychain_account() -> None:
    """A chat target sends through the delegated token and its address is in the
    config file, so it has no secret to look up (design amendment 2026-10-30)."""
    config = parse_config(
        {
            "mail": {
                "tenant_id": PLACEHOLDER_GUID,
                "client_id": PLACEHOLDER_GUID,
                "sender": PLACEHOLDER_SENDER,
                "auth": "certificate",
                "default_reply_to": "",
            },
            "teams": {
                "targets": {
                    "ops": {"kind": "chat", "chat_id": FAKE_CHAT_ID},
                    "alerts": {"kind": "channel"},
                }
            },
        }
    )
    accounts = config.keychain_accounts()
    assert "teams:ops" not in accounts
    assert accounts == (ACCOUNT_CERT_PEM, ACCOUNT_CERT_THUMBPRINT, "teams:alerts")


# --- Writing ---------------------------------------------------------------
def test_write_config_produces_mode_0600_and_round_trips(tmp_path) -> None:
    target = tmp_path / "nested" / "deeper" / "config.toml"
    written = write_config(
        Config(
            mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate"),
            allow=AllowConfig(domains=("example.com",)),
            limits=LimitsConfig(),
            paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
            teams_targets=(TeamTarget("alerts", "channel"),),
        ),
        target,
    )
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    reloaded = load_config(written)
    assert reloaded.allow.domains == ("example.com",)
    assert reloaded.teams_targets == (TeamTarget("alerts", "channel"),)
    assert not list(tmp_path.glob("*.tmp"))


def test_written_file_names_no_secret_values(tmp_path) -> None:
    written = write_config(
        Config(
            mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate"),
            allow=AllowConfig(),
            limits=LimitsConfig(),
            paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
        ),
        tmp_path / "config.toml",
    )
    text = written.read_text(encoding="utf-8")
    for forbidden in (ACCOUNT_CERT_PEM, ACCOUNT_CLIENT_SECRET, "teams:"):
        assert forbidden not in text


def test_writer_uses_a_temp_file_then_rename(tmp_path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    original_replace = os.replace
    seen: list[str] = []

    def spy(src, dst, *args, **kwargs):
        seen.append(str(src))
        return original_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", spy)
    write_config(
        Config(
            mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "secret"),
            allow=AllowConfig(),
            limits=LimitsConfig(),
            paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
        ),
        target,
    )
    assert seen and seen[0].endswith("config.toml.tmp")
    assert not target.with_name("config.toml.tmp").exists()


def test_render_then_parse_is_stable(tmp_path) -> None:
    original = Config(
        mail=MailConfig(
            PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate", "me@contoso.com"
        ),
        allow=AllowConfig(domains=("example.com", "contoso.com"), addresses=("a@contoso.com",)),
        limits=LimitsConfig(max_recipients=5, daily_max=7, max_attach_mb=1),
        paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
        teams_targets=(TeamTarget("alerts", "channel"), TeamTarget("dm", "dm")),
    )
    parsed = parse_config(__import__("tomllib").loads(render_toml(original)))
    assert parsed.mail == original.mail
    assert parsed.allow == original.allow
    assert parsed.limits == original.limits
    assert parsed.teams_targets == original.teams_targets


# --- Team-target helpers (used by P4) --------------------------------------
def test_with_team_target_adds_then_replaces_without_touching_the_original(tmp_path) -> None:
    base = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "secret"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
    )
    added = with_team_target(base, "alerts", "channel")
    assert base.teams_targets == ()  # frozen input untouched
    assert added.teams_targets == (TeamTarget("alerts", "channel"),)

    replaced = with_team_target(added, "alerts", "dm")
    assert replaced.teams_targets == (TeamTarget("alerts", "dm"),)
    assert added.teams_targets == (TeamTarget("alerts", "channel"),)


def test_without_team_target_drops_only_the_named_target() -> None:
    base = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "secret"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit="/tmp/a.jsonl", state_dir="/tmp/s"),
        teams_targets=(TeamTarget("alerts", "channel"), TeamTarget("dm", "dm")),
    )
    assert without_team_target(base, "alerts").teams_targets == (TeamTarget("dm", "dm"),)
    assert without_team_target(base, "ghost").teams_targets == base.teams_targets


def test_with_team_target_rejects_an_unknown_kind() -> None:
    base = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "secret"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit="/tmp/a.jsonl", state_dir="/tmp/s"),
    )
    with pytest.raises(ConfigError, match="kind must be one of"):
        with_team_target(base, "alerts", "carrier-pigeon")


def test_as_dict_has_no_secret_valued_key() -> None:
    config = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "secret"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit="/tmp/a.jsonl", state_dir="/tmp/s"),
    )
    flat = config.as_dict()
    assert set(flat) == {"mail", "allow", "limits", "paths", "teams"}
    assert "client_secret" not in str(flat)


# --- Delegated-phase schema: [mail] mode (design amendment 2026-10-30) -------
def mail_toml(extra: str = "") -> str:
    """A minimal valid [mail] table, with optional extra lines appended."""
    return (
        "[mail]\n"
        f'tenant_id = "{PLACEHOLDER_GUID}"\n'
        f'client_id = "{PLACEHOLDER_GUID}"\n'
        f'sender = "{PLACEHOLDER_SENDER}"\n'
        'auth = "certificate"\n' + extra
    )


def test_mail_mode_defaults_to_app_for_pre_amendment_configs(tmp_path) -> None:
    """A config written before the amendment carries no `mode` and must parse
    unchanged, as today's app-only behaviour."""
    path = write_raw(tmp_path, mail_toml())
    config = load_config(path)
    assert config.mail.mode == MAIL_MODE_APP
    assert MAIL_MODE_APP == "app" and MAIL_MODE_DELEGATED == "delegated"
    assert MAIL_MODES == (MAIL_MODE_APP, MAIL_MODE_DELEGATED)


def test_mail_mode_delegated_is_parsed_and_round_trips(tmp_path) -> None:
    path = write_raw(tmp_path, mail_toml('mode = "delegated"\n'))
    config = load_config(path)
    assert config.mail.mode == MAIL_MODE_DELEGATED
    written = write_config(config, tmp_path / "out.toml")
    assert 'mode = "delegated"' in written.read_text(encoding="utf-8")
    assert load_config(written).mail.mode == MAIL_MODE_DELEGATED


def test_mail_mode_is_rendered_by_render_toml(tmp_path) -> None:
    config = parse_config(__import__("tomllib").loads(mail_toml()))
    text = render_toml(config)
    assert 'mode = "app"' in text  # the default is written explicitly, not omitted
    delegated = Config(
        mail=MailConfig(
            PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate",
            mode=MAIL_MODE_DELEGATED,
        ),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
    )
    assert 'mode = "delegated"' in render_toml(delegated)


def test_mail_mode_is_shown_by_as_dict() -> None:
    config = parse_config(__import__("tomllib").loads(mail_toml('mode = "delegated"\n')))
    assert config.as_dict()["mail"]["mode"] == MAIL_MODE_DELEGATED


@pytest.mark.parametrize(
    "line,match",
    [
        ('mode = "delegation"', "mode must be one of"),
        ('mode = "app-only"', "mode must be one of"),
        ("mode = 1", "must be a string"),
    ],
)
def test_bad_mail_mode_is_a_config_error(tmp_path, line, match) -> None:
    path = write_raw(tmp_path, mail_toml(line + "\n"))
    with pytest.raises(ConfigError, match=match) as excinfo:
        load_config(path)
    assert excinfo.value.exit_code == EXIT_USAGE


def test_mail_mode_is_case_and_space_insensitive(tmp_path) -> None:
    path = write_raw(tmp_path, mail_toml('mode = "  Delegated  "\n'))
    assert load_config(path).mail.mode == MAIL_MODE_DELEGATED


# --- Delegated-phase schema: Teams chat target kind --------------------------
def teams_toml(target_body: str) -> str:
    """VALID_TOML-shaped config with one teams target carrying ``target_body``."""
    return (
        mail_toml()
        + "\n[teams.targets.ops]\n"
        + target_body
    )


def test_chat_target_is_parsed_with_its_chat_id(tmp_path) -> None:
    path = write_raw(tmp_path, teams_toml(f'kind = "chat"\nchat_id = "{FAKE_CHAT_ID}"\n'))
    target = load_config(path).target("ops")
    assert target.kind == KIND_CHAT
    assert target.chat_id == FAKE_CHAT_ID  # stored verbatim — not a secret


def test_channel_and_dm_targets_have_an_empty_chat_id(tmp_path) -> None:
    path = write_raw(tmp_path, teams_toml('kind = "channel"\n'))
    assert load_config(path).target("ops").chat_id == ""


@pytest.mark.parametrize(
    "body,match",
    [
        # chat needs an address; both "absent" and "present but blank" are refusals.
        ('kind = "chat"\n', "requires a non-empty chat_id"),
        (f'kind = "chat"\nchat_id = ""\n', "requires a non-empty chat_id"),
        (f'kind = "chat"\nchat_id = "   "\n', "requires a non-empty chat_id"),
        # the other kinds address a webhook target, not a chat.
        (f'kind = "channel"\nchat_id = "{FAKE_CHAT_ID}"\n', "chat_id is only valid"),
        (f'kind = "dm"\nchat_id = "{FAKE_CHAT_ID}"\n', "chat_id is only valid"),
        (f'kind = "chat"\nchat_id = 42\n', "must be a string"),
    ],
)
def test_chat_id_validation_matrix(tmp_path, body, match) -> None:
    path = write_raw(tmp_path, teams_toml(body))
    with pytest.raises(ConfigError, match=match) as excinfo:
        load_config(path)
    assert excinfo.value.exit_code == EXIT_USAGE


def test_chat_target_round_trips_through_write_and_read(tmp_path) -> None:
    """The card's round-trip requirement, via with_team_target like P4 does."""
    base = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
    )
    updated = with_team_target(base, "ops", KIND_CHAT, FAKE_CHAT_ID)
    written = write_config(updated, tmp_path / "config.toml")
    reloaded = load_config(written)
    assert reloaded.target("ops") == TeamTarget("ops", KIND_CHAT, FAKE_CHAT_ID)
    assert f'chat_id = "{FAKE_CHAT_ID}"' in written.read_text(encoding="utf-8")


def test_with_team_target_chat_requires_a_chat_id_and_others_reject_one() -> None:
    base = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit="/tmp/a.jsonl", state_dir="/tmp/s"),
    )
    with pytest.raises(ConfigError, match="requires a non-empty chat_id"):
        with_team_target(base, "ops", KIND_CHAT)
    with pytest.raises(ConfigError, match="chat_id is only valid"):
        with_team_target(base, "alerts", "channel", FAKE_CHAT_ID)


def test_replacing_a_target_clears_a_stale_chat_id(tmp_path) -> None:
    """chat -> channel on the same name must not leave the old address behind."""
    base = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit=tmp_path / "a.jsonl", state_dir=tmp_path / "s"),
        teams_targets=(TeamTarget("ops", KIND_CHAT, FAKE_CHAT_ID),),
    )
    replaced = with_team_target(base, "ops", "channel")
    assert replaced.target("ops") == TeamTarget("ops", "channel", "")
    assert "chat_id" not in render_toml(replaced)


# --- Masking of the chat id in display views ---------------------------------
def test_mask_chat_id_shows_last_four_only() -> None:
    assert mask_chat_id(FAKE_CHAT_ID_LONG) == "***" + FAKE_CHAT_ID_LONG[-4:]
    assert FAKE_CHAT_ID_LONG[:-4] not in mask_chat_id(FAKE_CHAT_ID_LONG)
    assert mask_chat_id("abcd") == "***"      # nothing safe left to show
    assert mask_chat_id("") == ""             # absent value renders as absent
    assert mask_chat_id("  ") == ""


def test_as_dict_masks_chat_id_last_four_only() -> None:
    """``config show`` prints as_dict(); the masking lives with the schema so the
    display command cannot print a full chat address by forgetting a step."""
    config = Config(
        mail=MailConfig(PLACEHOLDER_GUID, PLACEHOLDER_GUID, PLACEHOLDER_SENDER, "certificate"),
        allow=AllowConfig(),
        limits=LimitsConfig(),
        paths=PathsConfig(audit="/tmp/a.jsonl", state_dir="/tmp/s"),
        teams_targets=(
            TeamTarget("ops", KIND_CHAT, FAKE_CHAT_ID_LONG),
            TeamTarget("alerts", "channel"),
        ),
    )
    targets = config.as_dict()["teams"]["targets"]
    assert targets["ops"] == {"kind": "chat", "chat_id": "***" + FAKE_CHAT_ID_LONG[-4:]}
    assert FAKE_CHAT_ID_LONG not in str(targets)
    assert targets["alerts"] == {"kind": "channel"}  # no chat_id key when there is none
