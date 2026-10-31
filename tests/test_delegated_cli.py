"""``mnotify login`` / ``logout`` / ``whoami`` (design amendment A.4).

These go through :func:`micro_notify.cli.main` — the wiring an agent's ``mnotify``
invocation actually hits — with msal stubbed (``tests/test_delegation.py``'s fake) and
the keychain stubbed (the shared ``fake_keychain`` fixture). The pins that matter here
are about *output*: a token value must have no path to stdout or stderr in any mode,
``--json`` stdout must stay one parseable document, and the exit code must be the
documented 4 when a send cannot be authorised.
"""

from __future__ import annotations

import argparse
import json

import pytest

from micro_notify import EXIT_AUTH, EXIT_OK, cli, delegation
from micro_notify.commands import login as login_cmd
from micro_notify.commands import logout as logout_cmd
from micro_notify.commands import whoami as whoami_cmd
from micro_notify.delegation import ACCOUNT_DELEGATED_CACHE

from test_delegation import (  # noqa: E402  (pytest puts tests/ on sys.path)
    CANARY_ACCESS,
    CANARY_ID,
    CANARY_REFRESH,
    DEVICE_FLOW_MESSAGE,
    PERSON,
    FakeMsal,
    cache_state,
)

ALL_CANARIES = (CANARY_ACCESS, CANARY_REFRESH, CANARY_ID)


def run(argv: list[str]) -> int:
    return cli.main(argv)


def json_blob(capsys) -> dict:
    """Parse stdout as the single JSON document ``--json`` promises."""
    out = capsys.readouterr().out
    return json.loads(out)


@pytest.fixture(autouse=True)
def fake_msal(monkeypatch: pytest.MonkeyPatch) -> FakeMsal:
    """The same msal stub as tests/test_delegation.py, installed for this module too.

    A real ``PublicClientApplication`` does tenant discovery when built, so without
    this every login/whoami CLI test would depend on the socket harness to fail
    rather than on the code under test. The stub class is imported, not duplicated.
    """
    stub = FakeMsal()
    monkeypatch.setattr(delegation.msal, "PublicClientApplication", stub.make_app)
    return stub


@pytest.fixture(autouse=True)
def _sandboxed_config(mnotify_config):
    """Point MICRO_NOTIFY_CONFIG at tmp_path for the whole module.

    ``mnotify login`` reads [mail] for the client id and tenant, so without this a
    test here would read — and a future one could write — the operator's real
    config file under ~/.config/mnotify.
    """
    return mnotify_config


@pytest.fixture
def signed_in(fake_keychain):
    """Keychain pre-loaded with one delegated sign-in whose values are canaries."""
    fake_keychain.seed(ACCOUNT_DELEGATED_CACHE, cache_state())
    return fake_keychain


# --- surface: the three commands exist and parse ----------------------------
def test_the_three_delegated_commands_are_registered() -> None:
    parser = cli.build_parser()
    names: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            names.update(action.choices or ())
    assert {"login", "logout", "whoami"} <= names


def test_command_modules_keep_the_shared_contract() -> None:
    """Each module exposes NAME / add_parser / run exactly like the others."""
    for module, name in ((login_cmd, "login"), (logout_cmd, "logout"), (whoami_cmd, "whoami")):
        assert module.NAME == name
        assert cli.DISPATCH[name] is module.run


def test_login_accepts_no_prompt_and_json() -> None:
    args = cli.build_parser().parse_args(["login", "--no-prompt", "--json"])
    assert args.command == "login" and args.no_prompt is True and args.json is True


# --- login -------------------------------------------------------------------
def test_login_human_mode_prints_upn_never_a_token(fake_keychain, capsys) -> None:
    assert run(["login"]) == EXIT_OK
    captured = capsys.readouterr()
    assert PERSON in captured.out
    for canary in ALL_CANARIES:
        assert canary not in captured.out
        assert canary not in captured.err


def test_login_prints_the_device_prompt_once_on_stderr(fake_keychain, capsys) -> None:
    assert run(["login"]) == EXIT_OK
    captured = capsys.readouterr()
    # stdout stays clean so `mnotify login --json` output is machine-readable.
    assert DEVICE_FLOW_MESSAGE in captured.err
    assert DEVICE_FLOW_MESSAGE not in captured.out


def test_login_json_mode_is_one_parseable_document(fake_keychain, capsys) -> None:
    assert run(["login", "--json"]) == EXIT_OK
    payload = json_blob(capsys)
    assert payload["ok"] is True
    assert payload["outcome"] == "signed_in"
    assert payload["upn"] == PERSON
    assert payload["mode"] == "delegated"
    assert payload["expiresAt"] > 0
    # Token values are absent by construction: the whole document is printed here.
    text = json.dumps(payload)
    for canary in ALL_CANARIES:
        assert canary not in text


def test_login_writes_only_the_keychain_account(fake_keychain) -> None:
    assert run(["login"]) == EXIT_OK
    assert list(fake_keychain.items) == [ACCOUNT_DELEGATED_CACHE]


def test_login_failure_exits_auth_and_names_the_remedy(fake_keychain, fake_msal, capsys) -> None:
    fake_msal.device_result = {"error": "authorization_declined"}
    assert run(["login"]) == EXIT_AUTH
    err = capsys.readouterr().err
    assert "run mnotify login" in err
    assert all(canary not in err for canary in ALL_CANARIES)


def test_login_failure_in_json_mode_reports_json_on_stdout(fake_keychain, fake_msal, capsys) -> None:
    fake_msal.device_result = {"error": "authorization_declined"}
    assert run(["login", "--json"]) == EXIT_AUTH
    payload = json_blob(capsys)
    assert payload["ok"] is False
    assert payload["exitCode"] == EXIT_AUTH
    assert "run mnotify login" in payload["message"]


def test_login_no_prompt_never_starts_a_device_flow(signed_in, fake_msal) -> None:
    """The scripted cached answer comes from the real cache; no human is involved."""
    assert run(["login", "--no-prompt"]) == EXIT_OK
    assert fake_msal.device_flow_calls == 0


def test_login_no_prompt_without_a_cache_is_an_auth_error(fake_keychain, capsys) -> None:
    assert run(["login", "--no-prompt"]) == EXIT_AUTH
    assert "run mnotify login" in capsys.readouterr().err


# --- logout ------------------------------------------------------------------
def test_logout_deletes_the_account_and_says_so(signed_in, capsys) -> None:
    assert run(["logout"]) == EXIT_OK
    assert ACCOUNT_DELEGATED_CACHE not in signed_in.items
    assert ACCOUNT_DELEGATED_CACHE in capsys.readouterr().out


def test_logout_does_not_claim_a_full_revoke(signed_in, capsys) -> None:
    """A.2: level 1 is a local delete; the hard revoke is Entra's. The output must not blur them."""
    assert run(["logout"]) == EXIT_OK
    captured = capsys.readouterr()
    note = captured.err
    assert "Revoke sessions" in note
    assert "local" in note.lower()


def test_logout_is_honest_when_there_was_nothing_to_remove(fake_keychain, capsys) -> None:
    assert run(["logout"]) == EXIT_OK
    assert "not present" in capsys.readouterr().out


def test_logout_json_mode_reports_scope_and_account(signed_in, capsys) -> None:
    assert run(["logout", "--json"]) == EXIT_OK
    payload = json_blob(capsys)
    assert payload["ok"] is True and payload["outcome"] == "logged_out"
    assert payload["account"] == ACCOUNT_DELEGATED_CACHE
    assert payload["wasPresent"] is True
    assert payload["scope"] == "local"
    assert "Entra" in payload["hardRevoke"]


def test_logout_then_whoami_asks_for_a_login(signed_in, capsys) -> None:
    assert run(["logout"]) == EXIT_OK
    assert run(["whoami"]) == EXIT_AUTH
    assert "run mnotify login" in capsys.readouterr().err


# --- whoami ------------------------------------------------------------------
def test_whoami_prints_the_identity_and_no_token(signed_in, capsys) -> None:
    assert run(["whoami"]) == EXIT_OK
    captured = capsys.readouterr()
    assert PERSON in captured.out
    assert "delegated" in captured.out
    for canary in ALL_CANARIES:
        assert canary not in captured.out
        assert canary not in captured.err


def test_whoami_json_mode_carries_upn_mode_and_expiry(signed_in, capsys) -> None:
    assert run(["whoami", "--json"]) == EXIT_OK
    payload = json_blob(capsys)
    assert payload["upn"] == PERSON
    assert payload["mode"] == "delegated"
    assert payload["expiresAt"] > 0
    assert all(canary not in json.dumps(payload) for canary in ALL_CANARIES)


def test_whoami_needs_no_config_file(signed_in, tmp_path, monkeypatch, capsys) -> None:
    """A diagnostic must work with a broken config: point the env var at nothing."""
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "absent" / "config.toml"))
    assert run(["whoami"]) == EXIT_OK
    assert PERSON in capsys.readouterr().out


def test_whoami_without_a_cache_exits_auth(fake_keychain, capsys) -> None:
    assert run(["whoami"]) == EXIT_AUTH
    captured = capsys.readouterr()
    assert "run mnotify login" in captured.err
    assert captured.out == ""  # a refusal must not look like a partial success


def test_whoami_never_writes_to_the_keychain(signed_in) -> None:
    before = dict(signed_in.items)
    assert run(["whoami"]) == EXIT_OK
    assert signed_in.items == before


# --- cross-command leak pin ---------------------------------------------------
@pytest.mark.parametrize(
    "argv",
    [
        ["logout", "--json"],
        ["whoami"],
        ["whoami", "--json"],
    ],
)
def test_no_read_path_can_print_a_token(signed_in, capsys, argv) -> None:
    """Every path that reads the seeded cache, swept: no canary token on either stream.

    The seeded cache is the one holding the canary values, so logout/whoami are the
    paths where a leak would be possible; login's own sweep is pinned above with the
    tokens its fake flow produced.
    """
    assert run(argv) == EXIT_OK
    captured = capsys.readouterr()
    both = captured.out + captured.err
    for canary in ALL_CANARIES:
        assert canary not in both, f"{argv} printed a cached token"
