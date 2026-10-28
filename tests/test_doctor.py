"""``mnotify doctor`` — the ordered pre-flight check (design §4, §6, §7).

Two properties matter more than the check list itself, and both are pinned hard:

* **without ``--send-test`` the command makes no network call at all.** Asserted on
  the recorded request list of a counting ``httpx.MockTransport`` installed at the
  client seam — not only via the autouse socket blocker, because a blocked socket
  proves a call *failed*, not that one was never *attempted*;
* **no secret is ever printed.** Keychain checks report account name + presence, and
  canary values planted in the fake keychain must not appear anywhere in the output.

msal is stubbed at the attribute ``graph.py`` reaches for, exactly as
tests/test_graph.py does, so the roles check is exercised with no token endpoint.
"""

from __future__ import annotations

import argparse
import base64
import json

import httpx
import pytest

from micro_notify import (
    EXIT_AUTH,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
    cli,
    graph,
)
from micro_notify.config import AUTH_SECRET, load_config, render_toml, write_config
from micro_notify.secrets import (
    ACCOUNT_CERT_PEM,
    ACCOUNT_CERT_THUMBPRINT,
    ACCOUNT_CLIENT_SECRET,
)
from conftest import placeholder_config

CANARY_PEM_BODY = "CANARYPRIVATEKEYBODYNOTAREALKEY"
CANARY_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD"
SEND_TARGET = "someone@example.com"


def canary_webhook_url() -> str:
    """A Workflows-shaped URL, assembled at runtime (see tests/test_leak_guard.py)."""
    host = ".".join(["tenant-abc", "logic", "azure"]) + ".com"
    return "https" + "://" + host + "/triggers/R7x9Qm2/HTTP"


def jwt_with_roles(*roles: str) -> str:
    """An unsigned JWT-shaped bearer token carrying ``roles`` in its payload."""

    def segment(value: dict) -> str:
        raw = json.dumps(value).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment({'roles': list(roles)})}.sig"


class MsalStub:
    """Script + record for msal.ConfidentialClientApplication (mirrors test_graph)."""

    def __init__(self, token: str | None = None, fail: bool = False) -> None:
        self.token = token
        self.fail = fail
        self.token_calls = 0
        self.apps: list[dict] = []

    def make_app(self, **kwargs):
        self.apps.append(kwargs)
        stub = self

        class _App:
            def acquire_token_silent(self, *_a, **_kw):
                return None

            def acquire_token_for_client(self, *_a, **_kw):
                # Counted: this is the one msal call that would hit the network.
                stub.token_calls += 1
                if stub.fail:
                    return {"error": "invalid_client", "error_description": "AADSTS7000215"}
                return {"access_token": stub.token} if stub.token else None

        return _App()


@pytest.fixture
def msal_stub(monkeypatch: pytest.MonkeyPatch):
    """Install a scripted msal; returns the installer so tests can assert on call counts."""
    def install(token: str | None = None, *, fail: bool = False) -> MsalStub:
        stub = MsalStub(token=token, fail=fail)
        monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", stub.make_app)
        return stub

    return install


@pytest.fixture
def http_counter(monkeypatch: pytest.MonkeyPatch):
    """A counting mock transport installed at the httpx client seam.

    Production code passes no transport, so every client it builds lands here: the
    real ``graph.send_mail`` URL building and retry loop run unchanged, and
    ``requests`` / ``clients`` record what actually happened. An empty ``requests``
    is the proof that no HTTP was attempted.
    """
    requests: list[httpx.Request] = []
    clients: list[str] = []
    responses: list[httpx.Response] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return responses.pop(0) if responses else httpx.Response(202)

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    class CountingClient(real_client):
        def __init__(self, *args, **kwargs):
            clients.append("explicit" if kwargs.get("transport") else "default")
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(graph.httpx, "Client", CountingClient)
    return argparse.Namespace(requests=requests, clients=clients, responses=responses)


@pytest.fixture
def seeded_keychain(fake_keychain):
    """Keychain holds everything a certificate-mode config needs, plus canary URLs."""
    fake_keychain.seed(ACCOUNT_CERT_PEM, "-----BEGIN " + "PRIVATE KEY-----\n" + CANARY_PEM_BODY)
    fake_keychain.seed(ACCOUNT_CERT_THUMBPRINT, CANARY_THUMBPRINT)
    fake_keychain.seed("teams:alerts", canary_webhook_url())
    fake_keychain.seed("teams:dm", canary_webhook_url())
    return fake_keychain


def run_doctor(*argv: str) -> int:
    return cli.main(["doctor", *argv])


# --- Exit code 2: config -----------------------------------------------------
def test_missing_config_is_exit_2_naming_the_fix_command(monkeypatch, capsys) -> None:
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", "/nonexistent/mnotify-config.toml")
    assert run_doctor() == EXIT_USAGE
    err = capsys.readouterr().err
    assert "config" in err.lower()
    assert "mnotify setup" in err, "the fix hint must name the command that fixes it"


def test_unparsable_config_is_exit_2_and_names_the_file(config_file, capsys) -> None:
    config_file.write_text("this is [ not toml", encoding="utf-8")
    assert run_doctor() == EXIT_USAGE
    assert str(config_file) in capsys.readouterr().err


def test_config_missing_a_mail_key_is_exit_2_and_names_the_key(config_file, capsys) -> None:
    text = render_toml(placeholder_config(config_file.parent))
    config_file.write_text(
        "\n".join(line for line in text.splitlines() if not line.startswith("sender")),
        encoding="utf-8",
    )
    assert run_doctor() == EXIT_USAGE
    assert "sender" in capsys.readouterr().err


# --- Exit code 4: keychain ---------------------------------------------------
def test_missing_certificate_key_is_exit_4_naming_the_account(
    mnotify_config, fake_keychain, capsys
) -> None:
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert ACCOUNT_CERT_PEM in err
    assert "--gen-cert" in err, "the fix hint must name the flag that creates it"


def test_missing_thumbprint_alone_is_exit_4(mnotify_config, fake_keychain, capsys) -> None:
    fake_keychain.seed(ACCOUNT_CERT_PEM, "-----BEGIN " + "PRIVATE KEY-----\nX")
    assert run_doctor() == EXIT_AUTH
    assert ACCOUNT_CERT_THUMBPRINT in capsys.readouterr().err


def test_secret_mode_checks_the_secret_account_not_the_certificate(
    config_file, fake_keychain, capsys
) -> None:
    """auth=secret must look for graph.client_secret, not a certificate (design §3.4)."""
    config = placeholder_config(config_file.parent)
    object.__setattr__(config.mail, "auth", AUTH_SECRET)
    write_config(config, config_file)
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert ACCOUNT_CLIENT_SECRET in err
    assert ACCOUNT_CERT_PEM not in err, "secret mode must not demand a certificate"


def test_teams_target_without_a_keychain_url_is_exit_4(
    mnotify_config, seeded_keychain, capsys
) -> None:
    """Design §4: 'each Teams target URL present'."""
    del seeded_keychain.items["teams:dm"]
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert "teams:dm" in err
    assert "teams targets add" in err, "the fix hint must name the command that fixes it"


# --- Check 4: token + roles --------------------------------------------------
def test_token_without_mail_send_role_fails_with_the_design_wording(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """Design §4: the check is literally 'token roles has Mail.Send'."""
    msal_stub(jwt_with_roles("User.Read"))
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert "Mail.Send" in err
    assert "roles" in err.lower()
    assert "admin consent" in err.lower(), "the fix hint must name the §6 step that grants it"


def test_token_with_mail_send_role_passes_the_roles_check(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    assert "Mail.Send" in capsys.readouterr().out


def test_token_acquisition_failure_is_exit_4(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(fail=True)
    assert run_doctor() == EXIT_AUTH
    assert "token" in capsys.readouterr().err.lower()


def test_a_token_we_cannot_read_fails_closed(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """A bearer token that is not a readable JWT cannot prove the role: refuse."""
    msal_stub("not-a-jwt-at-all")
    assert run_doctor() == EXIT_AUTH
    assert "roles" in capsys.readouterr().err.lower()


def test_roles_come_from_the_token_payload_with_zero_http(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """The roles check decodes the token msal already handed us: no extra call."""
    stub = msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    assert stub.token_calls == 1, "roles must not cost a second token acquisition"
    assert http_counter.requests == [], f"doctor made HTTP requests: {http_counter.requests}"


# --- Check 5: empty allowlist ------------------------------------------------
def test_empty_allowlist_warns_loudly_and_exits_3(
    config_file, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """Empty allowlist = every send refused (design §3.3); doctor must say so in words."""
    from micro_notify.config import AllowConfig

    msal_stub(jwt_with_roles("Mail.Send"))
    config = placeholder_config(config_file.parent)
    object.__setattr__(config, "allow", AllowConfig())
    write_config(config, config_file)

    assert run_doctor() == EXIT_GUARD
    err = capsys.readouterr().err
    assert "allow" in err.lower()
    assert "refus" in err.lower(), "the warning must say sends will be refused"


def test_populated_allowlist_is_not_reported_as_a_failure(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK


# --- Zero network without --send-test ---------------------------------------
def test_doctor_without_send_test_makes_zero_network_calls(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """The card's central guarantee, asserted on the transport's call count."""
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    assert http_counter.requests == []
    assert http_counter.clients == [], "doctor opened an HTTP client without --send-test"


def test_doctor_without_send_test_never_calls_the_mail_send_path(
    mnotify_config, seeded_keychain, msal_stub, http_counter, monkeypatch
) -> None:
    from micro_notify.commands import mail as mail_cmd

    msal_stub(jwt_with_roles("Mail.Send"))

    def never(*_args, **_kwargs):
        raise AssertionError("doctor ran the mail send path without --send-test")

    monkeypatch.setattr(mail_cmd, "run", never)
    assert run_doctor() == EXIT_OK


def test_doctor_without_send_test_never_acquires_a_second_token_than_the_roles_check(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    stub = msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    assert stub.token_calls == 1


def test_doctor_does_not_spend_the_daily_budget_itself(
    mnotify_config, seeded_keychain, msal_stub, http_counter, monkeypatch
) -> None:
    """record_send belongs to the send path, not the checker (orch directive)."""
    from micro_notify import guard

    msal_stub(jwt_with_roles("Mail.Send"))

    def never(*_args, **_kwargs):
        raise AssertionError("doctor wrote the daily counter")

    monkeypatch.setattr(guard, "record_send", never)
    assert run_doctor() == EXIT_OK


def test_doctor_without_send_test_leaves_no_counter_file(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """The state-level half of the budget guarantee: nothing on disk after a check run.

    A monkeypatch tripwire only bites when the patched function is reachable; the
    counter file simply not existing proves no budget was spent on any path.
    """
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    counter = load_config(mnotify_config).paths.counter_file
    assert not counter.exists(), f"doctor spent daily budget without sending: {counter}"


# --- Secrets never printed ---------------------------------------------------
def test_report_contains_no_canary_secret_or_webhook_url(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    for canary in (CANARY_PEM_BODY, canary_webhook_url(), "R7x9Qm2"):
        assert canary not in blob
    assert "triggers" not in blob, "a webhook path fragment leaked into the report"


def test_json_report_carries_no_secret_either(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor("--json") == EXIT_OK
    blob = json.dumps(json.loads(capsys.readouterr().out))
    assert CANARY_PEM_BODY not in blob
    assert canary_webhook_url() not in blob


# --- --send-test -------------------------------------------------------------
def test_send_test_routes_through_the_guard_and_the_mail_send_path(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """One real send end to end: guard -> token -> POST, through the real graph code."""
    msal_stub(jwt_with_roles("Mail.Send"))
    http_counter.responses.append(httpx.Response(202))

    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    # httpx normalises %40 back to '@' in the path; what matters is that the POST went
    # to the configured sender's sendMail endpoint and nowhere else.
    assert [r.url.path for r in http_counter.requests] == [
        "/v1.0/users/noreply@example.com/sendMail"
    ]
    assert [r.url.host for r in http_counter.requests] == ["graph.microsoft.com"]
    assert len(http_counter.requests) == 1, "--send-test must send exactly ONE message"


def test_send_test_spends_exactly_one_unit_of_daily_budget(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """The counter belongs to the send path: one confirmed 202 = counter 1, no more.

    If doctor ever calls record_send itself (on top of the mail command's own
    bookkeeping) a diagnostic run quietly burns two units of the operator's budget.
    """
    msal_stub(jwt_with_roles("Mail.Send"))
    http_counter.responses.append(httpx.Response(202))

    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    counter = load_config(mnotify_config).paths.counter_file
    assert json.loads(counter.read_text(encoding="utf-8"))["count"] == 1


def test_send_test_payload_addresses_only_the_flag_recipient(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    body = json.loads(http_counter.requests[0].content.decode("utf-8"))
    assert body["message"]["toRecipients"] == [
        {"recipient": {"emailAddress": {"address": SEND_TARGET}}}
    ]


def test_send_test_recipient_still_goes_through_the_guard(
    config_file, seeded_keychain, msal_stub, http_counter
) -> None:
    """An address outside [allow] is refused (exit 3) before any POST, even with the flag."""
    from micro_notify.config import AllowConfig

    msal_stub(jwt_with_roles("Mail.Send"))
    config = placeholder_config(config_file.parent)
    object.__setattr__(config, "allow", AllowConfig(domains=("contoso.com",)))
    write_config(config, config_file)

    assert run_doctor("--send-test", SEND_TARGET) == EXIT_GUARD
    assert http_counter.requests == [], "a guard refusal must not reach the POST"


def test_send_test_echoes_the_recipient_masked(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET, "--json") == EXIT_OK
    blob = json.dumps(json.loads(capsys.readouterr().out))
    assert SEND_TARGET not in blob, "the flag value must be echoed masked"
    assert "s***@example.com" in blob


def test_send_test_audits_one_sent_line(
    mnotify_config, seeded_keychain, msal_stub, http_counter, read_json_lines
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    entries = read_json_lines(load_config(mnotify_config).paths.audit)
    assert [e["outcome"] for e in entries] == ["sent"]
    assert entries[0]["recipients"] == [SEND_TARGET]


def test_send_test_failure_keeps_the_remote_exit_code(
    mnotify_config, seeded_keychain, msal_stub, http_counter, monkeypatch
) -> None:
    """A non-2xx from Graph stays a remote error (exit 5), not a swallowed warning."""
    monkeypatch.setattr(graph.time, "sleep", lambda _seconds: None)
    msal_stub(jwt_with_roles("Mail.Send"))
    http_counter.responses.extend([httpx.Response(503)] * 3)
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_REMOTE


# --- Report shape ------------------------------------------------------------
def test_human_report_prints_one_line_per_check(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor() == EXIT_OK
    out = capsys.readouterr().out
    for name in ("config", "keychain", "teams", "token", "allow"):
        assert name in out, f"missing check line for {name!r}: {out}"


def test_json_report_lists_checks_in_the_documented_order(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor("--json") == EXIT_OK
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert [c["name"] for c in checks] == [
        "config", "keychain", "teams", "token", "allow", "send-test",
    ]
    assert all(c["status"] == "pass" for c in checks[:-1])


def test_send_test_not_requested_is_reported_as_skipped_not_passed(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """'not asked for' must not be dressed up as a green check."""
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor("--json") == EXIT_OK
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["send-test"]["status"] == "skipped"


def test_checks_after_the_first_failure_are_skipped_not_run(
    mnotify_config, fake_keychain, msal_stub, http_counter, capsys
) -> None:
    """An empty keychain must not be followed by a token attempt: the checks are ordered."""
    fake_keychain.items.clear()
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor("--json") == EXIT_AUTH
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert [c["name"] for c in checks if c["status"] == "fail"] == ["keychain"]
    # Everything after the failure is skipped: teams, token, allow, send-test.
    assert [c["status"] for c in checks[2:]] == ["skipped"] * 4
    assert checks[2]["name"] == "teams"
