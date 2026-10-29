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
