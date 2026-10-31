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
from datetime import datetime

import httpx
import msal
import pytest

from micro_notify import (
    EXIT_AUTH,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
    cli,
    delegation,
    graph,
)
from micro_notify.config import (
    AUTH_SECRET,
    MAIL_MODE_APP,
    MAIL_MODE_DELEGATED,
    TeamTarget,
    load_config,
    render_toml,
    write_config,
)
from micro_notify.secrets import (
    ACCOUNT_CERT_PEM,
    ACCOUNT_CERT_THUMBPRINT,
    ACCOUNT_CLIENT_SECRET,
    ACCOUNT_DELEGATED_CACHE,
)
from conftest import PLACEHOLDER_GUID, placeholder_config
from test_delegation import fake_id_token

CANARY_PEM_BODY = "CANARYPRIVATEKEYBODYNOTAREALKEY"
CANARY_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD"
SEND_TARGET = "someone@example.com"


def canary_webhook_url() -> str:
    """A Workflows-shaped URL, assembled at runtime (see tests/test_leak_guard.py)."""
    host = ".".join(["tenant-abc", "logic", "azure"]) + ".com"
    return "https" + "://" + host + "/triggers/R7x9Qm2/HTTP"


def jwt_payload(payload: dict) -> str:
    """An unsigned JWT-shaped bearer token carrying ``payload`` as its claims."""

    def segment(value: dict) -> str:
        raw = json.dumps(value).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment(payload)}.sig"


def jwt_with_roles(*roles: str) -> str:
    """An unsigned JWT-shaped bearer token carrying ``roles`` in its payload."""
    return jwt_payload({"roles": list(roles)})


def jwt_without_roles() -> str:
    """A token as Entra issues it once the tenant-wide Mail.Send consent is gone
    (design §6 step 3): a readable payload with **no** ``roles`` claim at all.

    The Exchange Online ``Application Mail.Send`` scoped role that authorises the
    send after step 3 is not, and cannot be, a claim in this token.
    """
    return jwt_payload({"aud": "https://graph.microsoft.com", "tid": "00000000-0000-0000-0000-000000000000"})


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


# --- Check 4, post-§6-step-3: an absent roles claim is NOT a failure --------
# Design §6 step 3 tells the operator to REMOVE the tenant-wide Entra Mail.Send
# consent and keep only the Exchange Online ``Application Mail.Send`` scoped role.
# That grant is deliberately invisible to the Entra token's ``roles`` claim, so on a
# correctly hardened tenant the claim is absent *by construction*. Treating it as a
# failure made `mnotify doctor` unsatisfiable (exit 4 forever), skipped `allow`, and
# made `--send-test` — §6 step 3's own verification command — unreachable. See card
# t_24a04813. An ABSENT claim is therefore "not verifiable", not "not authorised";
# a PRESENT claim that lacks the role stays a hard failure, because there Entra is
# speaking authoritatively.
def test_absent_roles_claim_warns_and_does_not_fail_the_run(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """§6 step 3 end state: token acquired, no roles claim -> warn, exit 0."""
    msal_stub(jwt_without_roles())
    assert run_doctor() == EXIT_OK
    out = capsys.readouterr().out
    assert "token: warn" in out, f"an absent roles claim must be a warn line, got: {out}"
    assert "Mail.Send" in out
    assert "step 3" in out, "the note must name the §6 step that removes the claim"


def test_absent_roles_claim_still_runs_the_later_checks(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """The old bug in its sharpest form: a warn used to skip `allow` and `--send-test`."""
    msal_stub(jwt_without_roles())
    assert run_doctor("--json") == EXIT_OK
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["token"]["status"] == "warn"
    assert checks["allow"]["status"] == "pass", "`allow` must still run after a warn"
    assert checks["send-test"]["status"] == "skipped", "not requested, so skipped — not run"


def test_absent_roles_claim_reaches_send_test_and_sends_exactly_one(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """§6 step 3 says to re-run `mnotify doctor --send-test`; it must be reachable."""
    msal_stub(jwt_without_roles())
    http_counter.responses.append(httpx.Response(202))

    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    assert [r.url.path for r in http_counter.requests] == [
        "/v1.0/users/noreply@example.com/sendMail"
    ]
    assert len(http_counter.requests) == 1, "--send-test must send exactly ONE message"


def test_absent_roles_claim_send_test_still_pays_the_guard_first(
    config_file, seeded_keychain, msal_stub, http_counter
) -> None:
    """The warn must not smuggle a send past the guardrail: outside [allow] -> exit 3, zero POSTs."""
    from micro_notify.config import AllowConfig

    msal_stub(jwt_without_roles())
    config = placeholder_config(config_file.parent)
    object.__setattr__(config, "allow", AllowConfig(domains=("contoso.com",)))
    write_config(config, config_file)

    assert run_doctor("--send-test", SEND_TARGET) == EXIT_GUARD
    assert http_counter.requests == [], "a guard refusal must not reach the POST"


def test_empty_roles_list_behaves_like_an_absent_claim(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """`roles: []` and no `roles` key are the same tenant state — both are 'unknown'."""
    msal_stub(jwt_payload({"roles": []}))
    assert run_doctor() == EXIT_OK
    assert "token: warn" in capsys.readouterr().out


def test_empty_roles_list_still_reaches_send_test(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    msal_stub(jwt_payload({"roles": []}))
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    assert len(http_counter.requests) == 1


def test_absent_roles_claim_costs_no_extra_token_and_no_http_without_send_test(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """The warn path must not buy its certainty with a second token or a request."""
    stub = msal_stub(jwt_without_roles())
    assert run_doctor() == EXIT_OK
    assert stub.token_calls == 1
    assert http_counter.requests == []
    assert http_counter.clients == [], "doctor opened an HTTP client without --send-test"


def test_warn_line_prints_on_stdout_not_stderr(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """A warn is not a failure: it must not go to stderr like a fail does."""
    msal_stub(jwt_without_roles())
    assert run_doctor() == EXIT_OK
    captured = capsys.readouterr()
    assert "token: warn" in captured.out
    assert "token: warn" not in captured.err


def test_json_report_warn_does_not_claim_the_role_was_proven(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """`ok: true` means nothing failed; the warn detail must say the role is unverified."""
    msal_stub(jwt_without_roles())
    assert run_doctor("--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["exitCode"] == EXIT_OK
    token = next(c for c in payload["checks"] if c["name"] == "token")
    assert token["status"] == "warn"
    detail = token["detail"].lower()
    assert "not verifiable" in detail or "cannot verify" in detail
    assert "scoped" in detail, "the note must point at the Exchange scoped role"


def test_warn_reports_no_secret(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """The new detail text names claims and roles — never a token value."""
    msal_stub(jwt_without_roles())
    assert run_doctor() == EXIT_OK
    blob = capsys.readouterr().out + capsys.readouterr().err
    for canary in (CANARY_PEM_BODY, canary_webhook_url(), "R7x9Qm2"):
        assert canary not in blob
    assert "triggers" not in blob
    assert "eyJ" not in blob, "a JWT segment leaked into the report"


def test_a_read_roles_claim_still_fails_closed_without_mail_send(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """The hardening must not become a blanket pass: Entra listing other roles and no
    Mail.Send is an authoritative 'not granted' -> exit 4."""
    msal_stub(jwt_with_roles("User.Read", "Calendars.Read"))
    assert run_doctor() == EXIT_AUTH
    assert "Mail.Send" in capsys.readouterr().err


def test_a_read_roles_claim_without_mail_send_still_skips_the_later_checks(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """Ordering is unchanged for real failures: only the warn keeps the run going."""
    msal_stub(jwt_with_roles("User.Read"))
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["token"]["status"] == "fail"
    assert checks["allow"]["status"] == "skipped"
    assert checks["send-test"]["status"] == "skipped"


def test_unreadable_token_still_fails_closed_after_the_change(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    """Not-a-JWT is NOT 'absent claim': we cannot read the assertion, so we refuse."""
    msal_stub("not-a-jwt-at-all")
    assert run_doctor("--json") == EXIT_AUTH
    # (asserted again by the pre-existing test_a_token_we_cannot_read_fails_closed;
    # pinned here so a future 'treat anything unreadable as warn' fix trips on it.)


def test_unreadable_token_with_send_test_sends_nothing(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """Fail-closed means the run STOPS, not 'print red and carry on to a real send'.

    An unreadable assertion is the one token state where we know nothing at all, so
    reaching the POST would be a send with no verification behind it. The exit code
    alone cannot prove this (the FAIL already set it), which is why the POST count and
    the skipped lines are asserted here.
    """
    msal_stub("not-a-jwt-at-all")
    http_counter.responses.append(httpx.Response(202))

    assert run_doctor("--send-test", SEND_TARGET, "--json") == EXIT_AUTH
    assert http_counter.requests == [], "an unreadable token must not reach the POST"
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["token"]["status"] == "fail"
    assert checks["allow"]["status"] == "skipped"
    assert checks["send-test"]["status"] == "skipped"
    counter = load_config(mnotify_config).paths.counter_file
    assert not counter.exists(), "a refused pre-flight must not spend daily budget"


# --- The claim reader itself ------------------------------------------------
# The tri-state lives here, so it is pinned at unit level too: an e2e test cannot
# tell "the reader said absent" from "the reader said unreadable and the caller
# happened to map it to the same line".
def test_read_roles_claim_distinguishes_the_three_states() -> None:
    from micro_notify.commands.doctor import (
        CLAIM_ABSENT,
        CLAIM_READ,
        CLAIM_UNREADABLE,
        read_roles_claim,
    )

    assert read_roles_claim(jwt_with_roles("Mail.Send", "User.Read")) == (
        CLAIM_READ, ["Mail.Send", "User.Read"])
    assert read_roles_claim(jwt_with_roles("User.Read")) == (CLAIM_READ, ["User.Read"])
    assert read_roles_claim(jwt_without_roles()) == (CLAIM_ABSENT, [])
    assert read_roles_claim(jwt_payload({"roles": []})) == (CLAIM_ABSENT, [])
    for unreadable in ("not-a-jwt-at-all", "a.b", "a.b.c.d", ""):
        assert read_roles_claim(unreadable) == (CLAIM_UNREADABLE, []), unreadable


def test_read_roles_claim_rejects_a_shape_entra_cannot_produce() -> None:
    """A `roles` claim that is not a list of strings is not evidence of anything."""
    from micro_notify.commands.doctor import (
        CLAIM_ABSENT,
        CLAIM_UNREADABLE,
        read_roles_claim,
    )

    assert read_roles_claim(jwt_payload({"roles": "Mail.Send"})) == (CLAIM_UNREADABLE, [])
    assert read_roles_claim(jwt_payload({"roles": {"a": 1}})) == (CLAIM_UNREADABLE, [])
    assert read_roles_claim(jwt_payload({"roles": [1, 2]})) == (CLAIM_UNREADABLE, [])
    # A half-string claim is not a shape Entra produces either, and the code must not
    # quietly drop the entry it could not read: that would turn a bogus token into a
    # "no roles" answer, which is the one state allowed to reach --send-test.
    assert read_roles_claim(jwt_payload({"roles": ["Mail.Send", 7]})) == (CLAIM_UNREADABLE, [])
    # A payload that is valid JSON but not an object cannot carry claims at all.
    not_a_dict = ".".join(["e30", "WyJhIiwgImIiXQ", "c2ln"])
    assert read_roles_claim(not_a_dict) == (CLAIM_UNREADABLE, [])
    # (and the trivially readable empty object is an absent claim, not garbage)
    assert read_roles_claim(jwt_payload({})) == (CLAIM_ABSENT, [])


def test_send_test_after_step_three_audits_one_sent_line(
    mnotify_config, seeded_keychain, msal_stub, http_counter, read_json_lines
) -> None:
    msal_stub(jwt_without_roles())
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    entries = read_json_lines(load_config(mnotify_config).paths.audit)
    assert [e["outcome"] for e in entries] == ["sent"]


def test_doctor_does_not_spend_the_daily_budget_itself_after_step_three(
    mnotify_config, seeded_keychain, msal_stub, http_counter, monkeypatch
) -> None:
    """The warn path must not re-introduce doctor's own record_send call."""
    from micro_notify import guard

    msal_stub(jwt_without_roles())

    def never(*_args, **_kwargs):
        raise AssertionError("doctor wrote the daily counter")

    monkeypatch.setattr(guard, "record_send", never)
    assert run_doctor() == EXIT_OK


def test_send_test_after_step_three_spends_exactly_one_unit(
    mnotify_config, seeded_keychain, msal_stub, http_counter
) -> None:
    msal_stub(jwt_without_roles())
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    counter = load_config(mnotify_config).paths.counter_file
    assert json.loads(counter.read_text(encoding="utf-8"))["count"] == 1


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
        {"emailAddress": {"address": SEND_TARGET}}
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


# =========================================================================
# Delegated mode (design amendment 2026-10-30, D4)
# =========================================================================
# When ``[mail] mode = delegated`` the operator signed in as a person with
# ``mnotify login``, so the app-only questions ("is the certificate in the
# keychain", "does the client-credentials token carry the Mail.Send *role*") are the
# wrong questions — a delegated install has neither, and asking would report a
# missing credential the design deliberately does not use. These tests pin the
# adapted check list, the four new delegated facts (presence, expiry, scopes,
# identity) and the fact that ``--send-test`` routes through the D2 path.
#
# The msal token cache is REAL here (as in tests/test_delegation.py): a serialised
# msal cache is seeded into the shared fake keychain, so what is being exercised is
# the actual stored shape the doctor has to read, not a fixture-shaped approximation.
# The two identity/token seams are patched where a real call would need the network:
# ``delegation.get_delegated_token`` builds a ``PublicClientApplication`` (tenant
# discovery), so the send-test tests stub exactly that one attribute and let the
# keychain-only ``whoami`` run for real.

PERSON = "person@contoso.com"
OTHER_PERSON = "someoneelse@contoso.com"
CANARY_DELEGATED = "DELEGATED-AT-CANARY-DO-NOT-PRINT"
# A Teams chat id is config data, not a secret (amendment 2026-10-30); this one is
# the documented fake shape.
CHAT_ID = "19:" + "fakechat01" + "@thread.v2"


def _b64url(value: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(value).encode("utf-8"))
    return raw.decode("ascii").rstrip("=")


def delegated_state(
    *,
    scopes: tuple[str, ...] = None,
    expires_in: int = 3599,
    refresh_token: bool = True,
    upn: str = PERSON,
) -> str:
    """A serialised msal cache holding one delegated sign-in, with scripted contents.

    Populated through msal's own ``cache.add()`` — the entry point the library uses
    internally — so the serialised shape (``target`` scope list, ``expires_on``, the
    separate ``RefreshToken`` entry) is msal's and not our guess. The credential
    values are canaries: every test that prints a report asserts they stay hidden.
    """
    cache = msal.SerializableTokenCache()
    response = {
        "token_type": "Bearer",
        "scope": " ".join(delegation.DELEGATED_SCOPES if scopes is None else scopes),
        "expires_in": str(expires_in),
        "access_token": CANARY_DELEGATED,
        "id_token": fake_id_token(upn),
        "client_info": _b64url({"uid": "uid-1", "utid": PLACEHOLDER_GUID}),
    }
    if refresh_token:
        response["refresh_token"] = "RT-CANARY-DO-NOT-PRINT"
    cache.add(event={
        "client_id": PLACEHOLDER_GUID,
        "scope": list(delegation.DELEGATED_SCOPES if scopes is None else scopes),
        "token_endpoint": "https://login.microsoftonline.com/x/oauth2/v2.0/token",
        "response": {**response, "client_info": _b64url({"uid": "uid-1", "utid": PLACEHOLDER_GUID})},
        "username": upn,
        "actor": None,
        "analyzer": None,
        "resp_from_wsd": False,
    })
    return cache.serialize()


def delegated_expiry_text(state: str) -> str:
    """The same rendering ``doctor`` prints, derived from the seeded cache itself.

    Read out of the serialised ``expires_on`` rather than recomputed from a test-side
    clock, so the assertion cannot drift from the value under test.
    """
    for entry in json.loads(state).get("AccessToken", {}).values():
        return datetime.fromtimestamp(float(entry["expires_on"])).isoformat(timespec="seconds")
    raise AssertionError("seeded cache has no access token")


def delegated_config_file(
    config_file,
    *,
    mode: str = MAIL_MODE_DELEGATED,
    sender: str = PERSON,
    teams_targets=None,
    allow=None,
):
    """Write a delegated-mode config (or override any of the three interesting parts)."""
    from dataclasses import replace

    config = placeholder_config(config_file.parent)
    config = replace(config, mail=replace(config.mail, mode=mode, sender=sender))
    if teams_targets is not None:
        config = replace(config, teams_targets=teams_targets)
    if allow is not None:
        config = replace(config, allow=allow)
    write_config(config, config_file)
    return config_file


def seed_delegated_sign_in(fake_keychain, **state_kwargs):
    """Seed a delegated sign-in plus the webhook URLs the placeholder targets need.

    The two Teams accounts are here because ``placeholder_config`` declares a channel
    and a dm target and check 3 is mode-independent for those kinds; a test that is
    about checks 4/5/6 must not trip on check 3 first. Tests that ARE about check 3
    rewrite the targets and seed what they need themselves.
    """
    fake_keychain.seed(ACCOUNT_DELEGATED_CACHE, delegated_state(**state_kwargs))
    fake_keychain.seed("teams:alerts", canary_webhook_url())
    fake_keychain.seed("teams:dm", canary_webhook_url())
    return fake_keychain


@pytest.fixture
def signed_in(fake_keychain):
    """A live delegated sign-in: right scopes, unexpired, refreshable."""
    return seed_delegated_sign_in(fake_keychain)


@pytest.fixture
def delegated_env(config_file, signed_in, monkeypatch):
    """Delegated config + live sign-in + a stubbed delegated token, no app-mode stubs.

    Returns the pieces a test needs: the fake keychain (for cache surgery) and the
    recording stub for the one seam that would otherwise hit the network.
    """
    delegated_config_file(config_file)

    class TokenStub:
        def __init__(self) -> None:
            self.calls: list[bool] = []

        def get_delegated_token(self) -> str:
            self.calls.append(True)
            return CANARY_DELEGATED

    stub = TokenStub()
    # Only this one seam: `whoami` is keychain-only and runs for real, so the sender
    # check is exercised against the same cached identity the send path uses (D2).
    monkeypatch.setattr(delegation, "get_delegated_token", stub.get_delegated_token)
    # And the app-only client must never be built in delegated mode.
    monkeypatch.setattr(
        graph.msal, "ConfidentialClientApplication",
        lambda **_kw: (_ for _ in ()).throw(AssertionError("delegated mode built a cert client")),
    )
    return argparse.Namespace(keychain=signed_in, tokens=stub)


def delegated_checks(capsys) -> list[dict]:
    return json.loads(capsys.readouterr().out)["checks"]


# --- The check list itself --------------------------------------------------
def test_delegated_mode_reports_the_delegated_check_list_in_order(
    delegated_env, capsys
) -> None:
    """The card's ordering: config -> keychain -> teams -> token -> scopes -> sender -> allow."""
    assert run_doctor("--json") == EXIT_OK
    checks = delegated_checks(capsys)
    assert [c["name"] for c in checks] == [
        "config", "keychain", "teams", "token", "scopes", "sender", "allow", "send-test",
    ]
    assert all(c["status"] == "pass" for c in checks[:-1]), checks


def test_delegated_mode_replaces_the_roles_check_rather_than_adding_to_it(
    delegated_env, capsys
) -> None:
    """A delegated install has no app-only roles claim to read: no phantom, no duplicate."""
    assert run_doctor("--json") == EXIT_OK
    names = [c["name"] for c in delegated_checks(capsys)]
    assert names.count("token") == 1, "one token check, whichever mode this is"
    assert len(names) == len(set(names)), f"duplicate check names: {names}"


def test_app_mode_check_list_is_unchanged_even_with_a_cached_sign_in(
    mnotify_config, seeded_keychain, msal_stub, http_counter, fake_keychain, capsys
) -> None:
    """App mode must not grow `scopes`/`sender` because a token cache happens to exist.

    The branch keys on ``[mail] mode`` alone — an operator who signed in but left the
    config at ``app`` gets exactly the report they got before the amendment.
    """
    seed_delegated_sign_in(fake_keychain)
    msal_stub(jwt_with_roles("Mail.Send"))
    assert run_doctor("--json") == EXIT_OK
    assert [c["name"] for c in delegated_checks(capsys)] == [
        "config", "keychain", "teams", "token", "allow", "send-test",
    ]


def test_check_names_is_the_report_shape_for_each_mode() -> None:
    """Unit-level pin of the two lists, so an e2e rename cannot pass both ways."""
    from micro_notify.commands.doctor import CHECK_ORDER, DELEGATED_CHECK_ORDER, check_names

    assert check_names(False) == CHECK_ORDER
    assert check_names(True) == DELEGATED_CHECK_ORDER
    # Every shared name keeps its relative position; only the two new ones are added.
    shared = [name for name in DELEGATED_CHECK_ORDER if name in CHECK_ORDER]
    assert shared == list(CHECK_ORDER)
    assert set(DELEGATED_CHECK_ORDER) - set(CHECK_ORDER) == {"scopes", "sender"}


def test_json_document_shape_is_unchanged_in_delegated_mode(
    delegated_env, capsys
) -> None:
    """The card's contract: the machine shape is the same checks list, mode or not."""
    assert run_doctor("--json") == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"ok", "outcome", "exitCode", "checks"}
    assert payload["ok"] is True and payload["exitCode"] == EXIT_OK
    for entry in payload["checks"]:
        assert entry["status"] in {"pass", "warn", "fail", "skipped"}
        assert set(entry) <= {"name", "status", "detail"}


# --- Check 2 (delegated): the token cache account ---------------------------
def test_delegated_mode_without_a_sign_in_is_exit_4_naming_the_account(
    config_file, fake_keychain, capsys
) -> None:
    delegated_config_file(config_file)
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert ACCOUNT_DELEGATED_CACHE in err
    assert "mnotify login" in err, "the fix hint must name the command that creates it"


def test_delegated_mode_does_not_demand_the_certificate_or_the_webhook_secrets(
    config_file, fake_keychain, capsys
) -> None:
    """No phantom secrets: a delegated send reads neither the cert nor a client secret.

    D1b declined to add the cache account to ``Config.keychain_accounts()`` for this
    exact reason and left the presence check to this card; D2 proved the delegated
    path never reads the certificate accounts. An empty keychain must therefore fail
    on the *token cache* and name nothing else.
    """
    delegated_config_file(config_file)
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert ACCOUNT_DELEGATED_CACHE in err
    assert ACCOUNT_CERT_PEM not in err, "delegated mode must not demand a certificate"
    assert ACCOUNT_CLIENT_SECRET not in err


def test_delegated_keychain_check_reports_presence_never_the_value(
    config_file, fake_keychain, capsys
) -> None:
    """Presence, not contents: the canaries in the cache must not reach stdout."""
    delegated_config_file(config_file)
    seed_delegated_sign_in(fake_keychain)
    assert run_doctor() == EXIT_OK
    captured = capsys.readouterr()
    blob = captured.out + captured.err
    assert ACCOUNT_DELEGATED_CACHE in captured.out
    for canary in (CANARY_DELEGATED, "RT-CANARY-DO-NOT-PRINT", "IDT-CANARY-DO-NOT-PRINT"):
        assert canary not in blob
    assert "eyJ" not in blob, "a JWT segment leaked into the report"


# --- Check 4 (delegated): expiry -------------------------------------------
def test_delegated_live_token_reports_the_expiry_time(
    delegated_env, capsys
) -> None:
    state = delegated_state()
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = state
    assert run_doctor() == EXIT_OK
    out = capsys.readouterr().out
    assert delegated_expiry_text(state) in out, "the expiry time is the point of the check"


def test_expired_token_without_a_refresh_token_fails_and_names_the_hint(
    delegated_env, capsys
) -> None:
    """Dead sign-in: no access token, nothing to refresh -> exit 4 with the fix."""
    state = delegated_state(expires_in=-100, refresh_token=False)
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = state
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["token"]["status"] == "fail"
    assert delegated_expiry_text(state) in checks["token"]["detail"], "report WHEN it expired"
    assert checks["scopes"]["status"] == "skipped"
    assert checks["sender"]["status"] == "skipped"
    assert checks["allow"]["status"] == "skipped"


def test_expired_token_without_a_refresh_token_says_what_to_do(
    delegated_env, capsys
) -> None:
    state = delegated_state(expires_in=-100, refresh_token=False)
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = state
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert "expired" in err.lower()
    assert "mnotify login" in err, "the hint must name the command that fixes it"


def test_expired_token_with_a_refresh_token_warns_and_the_run_continues(
    delegated_env, capsys
) -> None:
    """The one warn state, and why: `mail send` refreshes this silently.

    A ``fail`` here would skip ``allow`` and put ``--send-test`` out of reach, making
    doctor unsatisfiable an hour after every login — the t_24a04813 lesson applied to
    the new mode instead of re-litigated.
    """
    state = delegated_state(expires_in=-100)
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = state
    assert run_doctor("--json") == EXIT_OK
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["token"]["status"] == "warn"
    assert checks["allow"]["status"] == "pass", "a warn must not stop the run"
    assert checks["send-test"]["status"] == "skipped", "not requested, so skipped — not run"


def test_expired_but_refreshable_token_is_a_warn_on_stdout_not_a_fail(
    delegated_env, capsys
) -> None:
    state = delegated_state(expires_in=-100)
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = state
    assert run_doctor() == EXIT_OK
    captured = capsys.readouterr()
    assert "token: warn" in captured.out
    assert "token: warn" not in captured.err


def test_unreadable_token_cache_fails_closed_with_the_sign_in_hint(
    delegated_env, capsys
) -> None:
    """A corrupt keychain item tells the operator nothing unless it is reported."""
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = "this-is-not-a-cache"
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["token"]["status"] == "fail"
    assert "unreadable" in checks["token"]["detail"]


def test_account_present_but_holding_no_sign_in_is_exit_4(
    config_file, fake_keychain, capsys
) -> None:
    """An item that exists but holds no access token is a fail, not a pass.

    The presence check asks only whether the account is there, so this is the state
    where it says ``present`` and the token check is the one that must refuse: a
    half-written sign-in (or one msal has emptied) has nothing to send with and
    nothing to refresh.
    """
    delegated_config_file(config_file)
    seed_delegated_sign_in(fake_keychain)
    fake_keychain.items[ACCOUNT_DELEGATED_CACHE] = "{}"
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["keychain"]["status"] == "pass", "the account IS there"
    assert checks["token"]["status"] == "fail"
    assert checks["scopes"]["status"] == "skipped"
    assert checks["sender"]["status"] == "skipped"


def test_account_present_but_holding_no_sign_in_names_the_fix(
    config_file, fake_keychain, capsys
) -> None:
    delegated_config_file(config_file)
    seed_delegated_sign_in(fake_keychain)
    fake_keychain.items[ACCOUNT_DELEGATED_CACHE] = "{}"
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert "nobody is signed in" in err
    assert "mnotify login" in err


def test_cache_access_token_pruned_but_refresh_token_held_warns_and_continues(
    config_file, fake_keychain, capsys
) -> None:
    """The msal-pruned shape: no access token, refresh token held -> warn, not fail.

    msal prunes expired access tokens during ``search()`` and the silent-refresh path
    persists that pruning, so a cache that has been through one expired-AT lookup
    holds ONLY a refresh token — and ``get_delegated_token`` still authenticates from
    it. Failing this shape would make doctor unsatisfiable for a working sign-in
    (the t_24a04813 class, in the new mode).
    """
    delegated_config_file(config_file)
    seed_delegated_sign_in(fake_keychain)
    state = json.loads(delegated_state())
    state["AccessToken"] = {}  # exactly what msal's prune leaves behind
    fake_keychain.items[ACCOUNT_DELEGATED_CACHE] = json.dumps(state)
    assert run_doctor("--json") == EXIT_OK
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["token"]["status"] == "warn"
    assert checks["scopes"]["status"] == "pass", "the refresh token's target list names the grant"
    assert checks["sender"]["status"] == "pass"
    assert checks["allow"]["status"] == "pass"


def test_cache_entry_without_a_readable_expiry_and_nothing_to_refresh_fails(
    config_file, fake_keychain, capsys
) -> None:
    """A malformed ``expires_on`` is not 'never expires'; with no RT it is a dead sign-in."""
    delegated_config_file(config_file)
    seed_delegated_sign_in(fake_keychain)
    state = json.loads(delegated_state(expires_in=-100, refresh_token=False))
    for entry in state["AccessToken"].values():
        entry["expires_on"] = "not-a-number"
    fake_keychain.items[ACCOUNT_DELEGATED_CACHE] = json.dumps(state)
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["token"]["status"] == "fail"


# --- Check 5 (delegated): scopes -------------------------------------------
def test_missing_chat_message_send_scope_fails_and_names_the_scope(
    delegated_env, capsys
) -> None:
    """The cached ``target`` list is what the token was issued for: authoritative."""
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = delegated_state(
        scopes=("Mail.Send", "Chat.ReadBasic", "User.Read", "offline_access")
    )
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["scopes"]["status"] == "fail"
    assert "ChatMessage.Send" in checks["scopes"]["detail"]
    assert checks["sender"]["status"] == "skipped", "the failure stops the run"


def test_missing_mail_send_scope_fails_and_names_only_that_scope(
    delegated_env, capsys
) -> None:
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = delegated_state(
        scopes=("ChatMessage.Send", "User.Read", "offline_access")
    )
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["scopes"]["status"] == "fail"
    # "missing" and "cached" must not blur: ChatMessage.Send IS granted here, it
    # appears only inside the cached-grant list, never in the "do not include" part.
    missing_part, cached_part = checks["scopes"]["detail"].split("(cached grant:")
    assert missing_part == "granted scopes do not include Mail.Send "
    assert "ChatMessage.Send" in cached_part


def test_scope_failure_hint_names_both_the_login_command_and_the_app_registration(
    delegated_env, capsys
) -> None:
    """Two causes, one hint: the operator can re-login, or an admin must grant the permission."""
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = delegated_state(
        scopes=("User.Read",)
    )
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert "mnotify login" in err
    assert "ADMIN-SETUP" in err, "a trimmed tenant consent is an admin-side fix"


def test_a_full_grant_passes_the_scope_check_without_printing_anything_sensitive(
    delegated_env, capsys
) -> None:
    assert run_doctor() == EXIT_OK
    captured = capsys.readouterr()
    assert "Mail.Send" in captured.out and "ChatMessage.Send" in captured.out
    assert CANARY_DELEGATED not in captured.out + captured.err


def test_scope_check_reads_the_grant_of_an_expired_but_refreshable_token(
    delegated_env, capsys
) -> None:
    """The warn must not smuggle a bad grant through: a refresh renews the SAME grant."""
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = delegated_state(
        expires_in=-100, scopes=("Mail.Send", "User.Read", "offline_access")
    )
    assert run_doctor("--json") == EXIT_AUTH
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["token"]["status"] == "warn", "expiry is still only a warn"
    assert checks["scopes"]["status"] == "fail", "the grant is a fact, warn or not"


def test_scope_grant_is_read_without_touching_the_credential_fields(
    delegated_env, monkeypatch
) -> None:
    """The reader must not be ``cache.search()``: that prunes expired tokens as a side effect."""
    import micro_notify.commands.doctor as doctor

    calls: list[bool] = []
    real_search = msal.TokenCache.search

    def spy(self, *args, **kwargs):
        calls.append(True)
        return real_search(self, *args, **kwargs)

    monkeypatch.setattr(msal.TokenCache, "search", spy)
    delegated_env.keychain.items[ACCOUNT_DELEGATED_CACHE] = delegated_state(expires_in=-100)
    # `whoami` legitimately uses search for the identity; zero it out by patching the
    # sender check's identity source so this test measures ONLY the cache reader.
    monkeypatch.setattr(
        delegation, "whoami",
        lambda: delegation.WhoamiResult(upn=PERSON, mode=MAIL_MODE_DELEGATED, expires_at=None),
    )
    assert doctor.run(argparse.Namespace(json=True, send_test=None)) == EXIT_OK
    assert calls == [], "doctor must parse the serialised cache, not query a live msal cache"


def test_read_delegated_cache_reports_names_numbers_and_readability() -> None:
    """Unit-level pin of the four facts, including the ones the e2e run cannot separate."""
    from micro_notify.commands.doctor import read_delegated_cache

    live = read_delegated_cache(delegated_state())
    assert live.readable is True and live.has_refresh_token is True
    assert set(live.scopes) == set(delegation.DELEGATED_SCOPES)
    assert live.expires_at is not None

    dead = read_delegated_cache(delegated_state(refresh_token=False))
    assert dead.has_refresh_token is False

    narrow = read_delegated_cache(delegated_state(scopes=("User.Read",)))
    assert narrow.scopes == ("User.Read",)

    assert read_delegated_cache("").readable is True, "absent is not corrupt"
    assert read_delegated_cache("").expires_at is None
    for garbage in ("not-json", "[1,2,3]", '{"AccessToken": 7}', '{"AccessToken": {"k": 7}}'):
        assert read_delegated_cache(garbage).readable is False, garbage


# --- Check 6 (delegated): identity == effective sender ----------------------
def test_signed_in_upn_matching_the_sender_passes(
    delegated_env, capsys
) -> None:
    assert run_doctor() == EXIT_OK
    assert f"signed in as {PERSON}" in capsys.readouterr().out


def test_upn_mismatch_fails_with_the_logout_and_login_hint(
    config_file, fake_keychain, capsys
) -> None:
    """The D2 rule, checked before a send is spent: /me/sendMail has no send-as-other."""
    delegated_config_file(config_file, sender=OTHER_PERSON)
    seed_delegated_sign_in(fake_keychain)
    assert run_doctor("--json") == EXIT_USAGE
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["sender"]["status"] == "fail"
    assert checks["allow"]["status"] == "skipped"
    assert PERSON in checks["sender"]["detail"] and OTHER_PERSON in checks["sender"]["detail"]


def test_upn_mismatch_hint_tells_the_operator_to_logout_and_login_as_the_sender(
    config_file, fake_keychain, capsys
) -> None:
    delegated_config_file(config_file, sender=OTHER_PERSON)
    seed_delegated_sign_in(fake_keychain)
    assert run_doctor() == EXIT_USAGE
    err = capsys.readouterr().err
    assert "logout" in err and "login" in err
    assert OTHER_PERSON in err, "the hint must name the account to sign in as"


def test_upn_comparison_ignores_case(
    config_file, fake_keychain, capsys
) -> None:
    """Entra treats UPN case as not meaningful, so this is not a different mailbox."""
    delegated_config_file(config_file, sender=PERSON.upper())
    seed_delegated_sign_in(fake_keychain)
    assert run_doctor() == EXIT_OK
    assert "sender: pass" in capsys.readouterr().out


def test_sender_check_never_prints_a_token(
    config_file, fake_keychain, capsys
) -> None:
    delegated_config_file(config_file, sender=OTHER_PERSON)
    seed_delegated_sign_in(fake_keychain)
    assert run_doctor() == EXIT_USAGE
    blob = capsys.readouterr().out + capsys.readouterr().err
    for canary in (CANARY_DELEGATED, "RT-CANARY-DO-NOT-PRINT", "IDT-CANARY-DO-NOT-PRINT"):
        assert canary not in blob
    assert "eyJ" not in blob


def test_sender_check_refuses_without_printing_a_token_in_json_too(
    config_file, fake_keychain, capsys
) -> None:
    delegated_config_file(config_file, sender=OTHER_PERSON)
    seed_delegated_sign_in(fake_keychain)
    assert run_doctor("--json") == EXIT_USAGE
    blob = json.dumps(json.loads(capsys.readouterr().out))
    assert CANARY_DELEGATED not in blob and "eyJ" not in blob


def test_sender_check_reports_a_refusal_as_a_sign_in_failure(
    config_file, fake_keychain, monkeypatch
) -> None:
    """Unit-level pin of the defensive branch the check ORDER normally hides.

    An e2e run can never reach it — check 4 fails first — so it is called directly:
    a cache that holds a usable access token but names nobody must produce exit 4 and
    the sign-in hint, not a crash and not a ``sender: pass`` for an unknown identity.
    """
    from micro_notify import AuthError
    from micro_notify.commands.doctor import FAIL, Report, check_delegated_sender

    def refusing() -> delegation.WhoamiResult:
        raise AuthError("nobody is signed in; run mnotify login")

    monkeypatch.setattr(delegation, "whoami", refusing)
    delegated_config_file(config_file)
    report = Report(True)
    config = load_config(config_file)
    assert check_delegated_sender(report, config) is False
    entry = report.checks[-1]
    assert entry == {"name": "sender", "status": FAIL, "detail": "nobody is signed in; run mnotify login"}
    assert report.exit_code == EXIT_AUTH


def test_delegated_human_report_prints_scopes_and_sender_on_stdout(
    delegated_env, capsys
) -> None:
    """The two new checks are lines like every other check: name, status, detail, stdout."""
    assert run_doctor() == EXIT_OK
    captured = capsys.readouterr()
    assert "scopes: pass" in captured.out
    assert "sender: pass" in captured.out
    assert not captured.err, "a passing delegated run writes nothing to stderr"


# --- Check 3 (delegated): chat targets are valid ---------------------------
def test_delegated_mode_accepts_a_chat_target_with_no_webhook_url(
    config_file, fake_keychain, capsys
) -> None:
    """D3: a chat is addressed by the config's chat_id over Graph — no webhook to find."""
    seed_delegated_sign_in(fake_keychain)
    delegated_config_file(
        config_file, teams_targets=(TeamTarget(name="standup", kind="chat", chat_id=CHAT_ID),)
    )
    assert run_doctor("--json") == EXIT_OK
    checks = {c["name"]: c for c in delegated_checks(capsys)}
    assert checks["teams"]["status"] == "pass"
    assert "teams:standup" not in json.dumps(checks), "no phantom webhook account demanded"


def test_delegated_mode_still_requires_webhook_urls_for_channel_and_dm(
    config_file, fake_keychain, capsys
) -> None:
    """The relaxation is per-kind, not a blanket skip."""
    seed_delegated_sign_in(fake_keychain)
    del fake_keychain.items["teams:alerts"]  # the channel target's URL is missing
    delegated_config_file(
        config_file,
        teams_targets=(
            TeamTarget(name="standup", kind="chat", chat_id=CHAT_ID),
            TeamTarget(name="alerts", kind="channel"),
        ),
    )
    assert run_doctor() == EXIT_AUTH
    err = capsys.readouterr().err
    assert "teams:alerts" in err
    assert "teams:standup" not in err


def test_delegated_mode_prints_which_targets_needed_no_url(
    config_file, fake_keychain, capsys
) -> None:
    seed_delegated_sign_in(fake_keychain)
    fake_keychain.seed("teams:alerts", canary_webhook_url())
    delegated_config_file(
        config_file,
        teams_targets=(
            TeamTarget(name="standup", kind="chat", chat_id=CHAT_ID),
            TeamTarget(name="alerts", kind="channel"),
        ),
    )
    assert run_doctor() == EXIT_OK
    out = capsys.readouterr().out
    assert "chat target" in out, "the report must explain why no URL was looked for"
    assert canary_webhook_url() not in out


def test_app_mode_still_demands_a_url_for_every_target_including_a_chat(
    mnotify_config, seeded_keychain, msal_stub, http_counter, capsys
) -> None:
    """App mode's check 3 is byte-identical: the flag defaults to False, behaviour unchanged."""
    from dataclasses import replace

    msal_stub(jwt_with_roles("Mail.Send"))
    config = placeholder_config(mnotify_config.parent)
    write_config(
        replace(config, teams_targets=config.teams_targets
                + (TeamTarget(name="standup", kind="chat", chat_id=CHAT_ID),)),
        mnotify_config,
    )
    assert run_doctor() == EXIT_AUTH
    assert "teams:standup" in capsys.readouterr().err, "app mode cannot post to a chat"


# --- --send-test branches per mode -----------------------------------------
def test_delegated_send_test_posts_to_me_sendmail(
    delegated_env, http_counter, capsys
) -> None:
    """D2's URL: no sender in the path — the mailbox is the signed-in person's."""
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    assert [r.url.path for r in http_counter.requests] == ["/v1.0/me/sendMail"]
    assert [r.url.host for r in http_counter.requests] == ["graph.microsoft.com"]


def test_delegated_send_test_carries_the_delegated_token_not_a_cert_token(
    delegated_env, http_counter
) -> None:
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    assert [r.headers["authorization"] for r in http_counter.requests] == [
        f"Bearer {CANARY_DELEGATED}"
    ]
    assert delegated_env.tokens.calls, "the send must go through the D2 token path"


def test_delegated_send_test_never_prints_the_token(
    delegated_env, http_counter, capsys
) -> None:
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET, "--json") == EXIT_OK
    blob = json.dumps(json.loads(capsys.readouterr().out))
    assert CANARY_DELEGATED not in blob and "eyJ" not in blob
    assert "s***@example.com" in blob, "the recipient echo is still masked"


def test_delegated_send_test_spends_exactly_one_unit_of_budget(
    delegated_env, http_counter, mnotify_config
) -> None:
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    counter = load_config(mnotify_config).paths.counter_file
    assert json.loads(counter.read_text(encoding="utf-8"))["count"] == 1


def test_delegated_send_test_audits_one_sent_line(
    delegated_env, http_counter, mnotify_config, read_json_lines
) -> None:
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_OK
    entries = read_json_lines(load_config(mnotify_config).paths.audit)
    assert [e["outcome"] for e in entries] == ["sent"]


def test_delegated_guard_refusal_costs_no_token_and_no_http(
    config_file, fake_keychain, http_counter, monkeypatch
) -> None:
    """Order preserved in the new mode: guard first, token only for a send that may happen."""
    from micro_notify.config import AllowConfig

    def never(*_args, **_kwargs):
        raise AssertionError("delegated mode spent a token on a refused send")

    delegated_config_file(config_file, allow=AllowConfig(domains=("contoso.com",)))
    seed_delegated_sign_in(fake_keychain)
    monkeypatch.setattr(delegation, "get_delegated_token", never)
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_GUARD
    assert http_counter.requests == []


def test_delegated_mode_without_a_sign_in_never_reaches_the_send(
    config_file, fake_keychain, http_counter, monkeypatch
) -> None:
    """Fail-closed ordering: a missing sign-in stops the run before any send attempt."""
    def never(*_args, **_kwargs):
        raise AssertionError("delegated mode tried to send without a sign-in")

    delegated_config_file(config_file)
    monkeypatch.setattr(delegation, "get_delegated_token", never)
    monkeypatch.setattr(delegation, "whoami", never)
    http_counter.responses.append(httpx.Response(202))
    assert run_doctor("--send-test", SEND_TARGET) == EXIT_AUTH
    assert http_counter.requests == []
    counter = load_config(config_file).paths.counter_file
    assert not counter.exists(), "a refused pre-flight must not spend daily budget"


# --- Zero network without --send-test, delegated mode ----------------------
def test_delegated_mode_without_send_test_makes_zero_network_calls(
    delegated_env, http_counter
) -> None:
    assert run_doctor() == EXIT_OK
    assert http_counter.requests == []
    assert http_counter.clients == [], "doctor opened an HTTP client without --send-test"


def test_delegated_mode_without_send_test_never_builds_a_public_client(
    delegated_env, http_counter, monkeypatch
) -> None:
    """A real PublicClientApplication does tenant discovery: that is a network call."""
    def never(**_kwargs):
        raise AssertionError("doctor built a PublicClientApplication without --send-test")

    monkeypatch.setattr(delegation.msal, "PublicClientApplication", never)
    assert run_doctor() == EXIT_OK
    assert http_counter.requests == []


def test_delegated_mode_reads_and_parses_the_token_cache_once_per_run(
    delegated_env, monkeypatch, capsys
) -> None:
    """One parsed read shared by the token, scopes and sender checks.

    Counted at ``read_delegated_state`` rather than in the keychain audit, because the
    audit also carries the presence probe and ``whoami``'s own keychain-only identity
    read — both of which are supposed to happen. What must NOT happen is three parses
    of the same blob, or a diagnostic writing the operator's credential back.
    """
    import micro_notify.commands.doctor as doctor

    calls: list[bool] = []
    real = doctor.read_delegated_state

    def spy():
        calls.append(True)
        return real()

    monkeypatch.setattr(doctor, "read_delegated_state", spy)
    before = dict(delegated_env.keychain.items)
    assert run_doctor("--json") == EXIT_OK
    delegated_checks(capsys)
    assert len(calls) == 1, f"expected one parse of the cache, got {len(calls)}"
    assert delegated_env.keychain.items == before, "a diagnostic must not rewrite the cache"


def test_delegated_mode_does_not_spend_the_daily_budget_itself(
    delegated_env, monkeypatch
) -> None:
    from micro_notify import guard

    def never(*_args, **_kwargs):
        raise AssertionError("doctor wrote the daily counter")

    monkeypatch.setattr(guard, "record_send", never)
    assert run_doctor() == EXIT_OK
