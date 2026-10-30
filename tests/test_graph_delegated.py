"""Delegated mail send (design amendment 2026-10-30): /me/sendMail + token UPN sender.

The card's four pins, each asserted from both sides so a regression on either mode
is caught here rather than in a live run:

* the URL — ``POST /me/sendMail`` in delegated mode, ``POST /users/<sender>/sendMail``
  in app mode;
* the payload — the JSON bytes handed to httpx are **identical** between the two
  modes, because both go through :func:`graph.build_send_payload`. The recipient
  shape (``{"emailAddress": {"address": ...}}``, no ``{"recipient": ...}`` wrapper)
  is asserted against the example in the Graph sendMail doc, not against our own
  fixtures: the doc's request is

      POST https://graph.microsoft.com/v1.0/me/sendMail
      Content-type: application/json

      {
        "message": {
          "subject": "Meet for lunch?",
          "body": {"contentType": "Text", "content": "The new cafeteria is open."},
          "toRecipients": [{"emailAddress": {"address": "frannis@contoso.com"}}],
          "ccRecipients": [{"emailAddress": {"address": "danas@contoso.com"}}]
        },
        "saveToSentItems": "false"
      }

* the sender rule — a configured ``[mail] sender`` that differs from the token's
  UPN is refused as a config error (exit 2) *before* any token call or socket;
* the pipeline — guard, daily cap and audit run identically in delegated mode,
  so a refusal or a cap in that mode still costs zero HTTP calls and zero
  keychain reads.

Nothing opens a socket: HTTP goes through ``httpx.MockTransport`` and
``delegation.whoami`` / ``delegation.get_delegated_token`` are patched at the
module attribute ``graph._delegated_send`` reaches for (it imports the module, not
the names, precisely so this seam works). The autouse ``no_network`` harness in
tests/conftest.py is the backstop (design §7). Placeholder identities only:
zero-GUIDs, example.com / contoso.com (design §5).
"""

from __future__ import annotations

import json

import httpx
import pytest

from micro_notify import (
    EXIT_AUTH,
    EXIT_DAILY_CAP,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
    AuthError,
    cli,
    config as config_module,
    delegation,
    graph,
    guard,
)
from micro_notify.config import (
    MAIL_MODE_APP,
    MAIL_MODE_DELEGATED,
    AllowConfig,
    Config,
    LimitsConfig,
    MailConfig,
    PathsConfig,
    write_config,
)

from conftest import PLACEHOLDER_DOMAIN, PLACEHOLDER_GUID, PLACEHOLDER_REPLY_TO
from test_graph import (  # noqa: E402  (pytest puts tests/ on sys.path)
    CANARY_PEM_BODY,
    CANARY_THUMBPRINT,
    MsalStub,
    REQUEST_ID,
    TransportHarness,
    mail_config,
    ok202,
    send_payload,
)

# The signed-in person (a placeholder UPN, design §5) and the delegated token
# canary: the token value must never reach an audit line, stdout or stderr.
PERSON = "person@contoso.com"
OTHER_PERSON = "someoneelse@contoso.com"
CANARY_DELEGATED = "DELEGATED-AT-CANARY-DO-NOT-PRINT"
# The scripted app-only token, named so the stub and the header assertion below
# quote one value rather than two that can drift apart.
APP_TOKEN = "app-token-value"
BODY_CANARY = "BODY-CANARY-77 the pipeline is red"

SEND = [
    "mail",
    "send",
    "--to",
    "someone@example.com",
    "--subject",
    "hi",
    "--body",
    BODY_CANARY,
]


def delegated_mail(**overrides) -> MailConfig:
    """A [mail] block in delegated mode, sender = the signed-in UPN."""
    values = dict(
        tenant_id=PLACEHOLDER_GUID,
        client_id=PLACEHOLDER_GUID,
        sender=PERSON,
        auth="certificate",
        default_reply_to="",
        mode=MAIL_MODE_DELEGATED,
    )
    values.update(overrides)
    return MailConfig(**values)


class DelegationStub:
    """Script + record for the two delegation entry points graph.py calls.

    ``whoami`` is what names the sender and ``get_delegated_token`` what authorises
    the call, so the stub records both and can be asked "was a token even
    attempted" — the pin for the sender-mismatch refusal, which must happen first.
    """

    def __init__(self) -> None:
        self.upn: str = PERSON
        self.token: str = CANARY_DELEGATED
        self.token_error: Exception | None = None
        self.whoami_calls: list[bool] = []
        self.token_calls: list[bool] = []

    def whoami(self):
        self.whoami_calls.append(True)
        return delegation.WhoamiResult(
            upn=self.upn, mode=MAIL_MODE_DELEGATED, expires_at=1_800_000_000.0
        )

    def get_delegated_token(self) -> str:
        self.token_calls.append(True)
        if self.token_error is not None:
            raise self.token_error
        return self.token

    @property
    def calls(self) -> int:
        return len(self.token_calls)


@pytest.fixture
def delegated(monkeypatch: pytest.MonkeyPatch) -> DelegationStub:
    """Patch the delegated auth seam graph.py uses (module attributes)."""
    stub = DelegationStub()
    monkeypatch.setattr(delegation, "whoami", stub.whoami)
    monkeypatch.setattr(delegation, "get_delegated_token", stub.get_delegated_token)
    return stub


@pytest.fixture
def msal_stub(monkeypatch: pytest.MonkeyPatch) -> MsalStub:
    """App-only msal, so app-mode tests can send and delegated tests can tripwire."""
    stub = MsalStub()
    monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", stub.make_app)
    return stub


@pytest.fixture
def app_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to build the *app-only* client fails the test."""

    def boom(**_kwargs):
        raise AssertionError("delegated mode must not use the cert/secret token")

    monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", boom)


@pytest.fixture
def cert_keychain(fake_keychain):
    """A populated cert-mode keychain: a delegated send must never read it."""
    fake_keychain.seed(graph.secrets.ACCOUNT_CERT_PEM, CANARY_PEM_BODY)
    fake_keychain.seed(graph.secrets.ACCOUNT_CERT_THUMBPRINT, CANARY_THUMBPRINT)
    return fake_keychain


@pytest.fixture
def sleeper(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(graph.time, "sleep", lambda seconds: slept.append(seconds))
    return slept


def transport(*responses: httpx.Response) -> TransportHarness:
    harness = TransportHarness(list(responses) or [ok202()])
    return harness


def mock(harness: TransportHarness) -> httpx.MockTransport:
    return httpx.MockTransport(harness.handler)


# --- The URL + token source --------------------------------------------------
class TestUrlAndTokenSource:
    def test_delegated_mode_posts_to_me_sendmail(self, delegated, app_tripwire) -> None:
        """``/me/sendMail``, bearer = the delegated token, no sender in the path."""
        sent = transport(ok202())

        result = graph.send_mail(
            mail=delegated_mail(), payload=send_payload(), transport=mock(sent)
        )

        assert str(sent.requested[0].url) == graph.GRAPH_BASE + "/me/sendMail"
        assert sent.requested[0].method == "POST"
        assert sent.requested[0].headers["authorization"] == f"Bearer {CANARY_DELEGATED}"
        assert sent.requested[0].headers["content-type"].startswith("application/json")
        assert result.status_code == 202
        assert result.request_id == REQUEST_ID

    def test_delegated_url_never_carries_the_sender(self, delegated, app_tripwire) -> None:
        """The path segment is the literal ``me``: a sender can only be the token's."""
        sent = transport(ok202())

        graph.send_mail(
            mail=delegated_mail(sender=PERSON),
            payload=send_payload(),
            transport=mock(sent),
        )

        path = sent.requested[0].url.path
        assert path.endswith("/me/sendMail")
        assert "contoso" not in path and "%40" not in path

    def test_delegated_mode_never_touches_the_app_only_token_path(
        self, delegated, app_tripwire, cert_keychain
    ) -> None:
        """msal.ConfidentialClientApplication is a tripwire here: if the delegated
        branch fell through to ``acquire_token`` the test fails, and the keychain
        accounts of the certificate must stay untouched."""
        sent = transport(ok202())

        graph.send_mail(
            mail=delegated_mail(), payload=send_payload(), transport=mock(sent)
        )

        assert sent.calls == 1
        assert cert_keychain.audit == []

    def test_app_mode_still_posts_to_the_sender_url(
        self, msal_stub, cert_keychain
    ) -> None:
        """The app-only URL is byte-identical to what it was before the amendment:
        the same quoted sender under ``/users/`` (design §3.1)."""
        msal_stub.silent_result = {"access_token": APP_TOKEN}
        sent = transport(ok202())

        result = graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(sent)
        )

        assert str(sent.requested[0].url) == (
            graph.GRAPH_BASE + "/users/" + "noreply%40example.com" + "/sendMail"
        )
        assert sent.requested[0].headers["authorization"] == f"Bearer {APP_TOKEN}"
        # App mode has no token-derived sender to report: the caller keeps using
        # [mail] sender, so SendResult.sender stays None.
        assert result.sender is None

    def test_app_mode_is_unaffected_by_a_delegated_sign_in(
        self, msal_stub, cert_keychain, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """mode="app" ignores the delegated cache entirely — whoami/token are never
        consulted, so an app-only install with a stale sign-in behaves as before."""
        msal_stub.silent_result = {"access_token": APP_TOKEN}
        spy = DelegationStub()
        monkeypatch.setattr(delegation, "whoami", spy.whoami)
        monkeypatch.setattr(delegation, "get_delegated_token", spy.get_delegated_token)
        sent = transport(ok202())

        graph.send_mail(
            mail=mail_config(mode=MAIL_MODE_APP),
            payload=send_payload(),
            transport=mock(sent),
        )

        assert spy.calls == 0
        assert spy.whoami_calls == []


# --- Payload identity between the two modes ----------------------------------
class TestPayloadIsIdenticalBetweenModes:
    def _rich_payload(self) -> dict:
        return graph.build_send_payload(
            to=["alice@example.com", "second@example.com"],
            subject="Build failed",
            body=BODY_CANARY,
            html=True,
            cc=["carbon@example.com"],
            bcc=["blind@contoso.com"],
            reply_to="human@contoso.com",
            attachments=[graph.Attachment(name="report.txt", bytes=b"report data")],
        )

    def test_request_bytes_are_identical_in_both_modes(
        self, delegated, msal_stub, cert_keychain
    ) -> None:
        """Same builder, same bytes: the only per-mode decisions are the URL and the
        bearer token. A divergence here would mean a second payload path crept in."""
        msal_stub.silent_result = {"access_token": APP_TOKEN}
        app_sent, delegated_sent = transport(ok202()), transport(ok202())

        graph.send_mail(
            mail=mail_config(), payload=self._rich_payload(), transport=mock(app_sent)
        )
        graph.send_mail(
            mail=delegated_mail(),
            payload=self._rich_payload(),
            transport=mock(delegated_sent),
        )

        assert delegated_sent.requested[0].content == app_sent.requested[0].content
        assert json.loads(delegated_sent.requested[0].content) == json.loads(
            app_sent.requested[0].content
        )
        assert str(app_sent.requested[0].url) != str(delegated_sent.requested[0].url)

    def test_recipient_shape_matches_the_graph_doc_example(self) -> None:
        """Regression for the 2026-10-30 live run (PR #12): a recipient is an
        ``emailAddress`` resource, never wrapped in ``{"recipient": ...}``."""
        payload = graph.build_send_payload(
            to=["frannis@contoso.com"],
            subject="Meet for lunch?",
            body="The new cafeteria is open.",
            cc=["danas@contoso.com"],
        )

        assert payload == {
            "message": {
                "subject": "Meet for lunch?",
                "body": {
                    "contentType": "text",
                    "content": "The new cafeteria is open.",
                },
                "toRecipients": [
                    {"emailAddress": {"address": "frannis@contoso.com"}}
                ],
                "ccRecipients": [
                    {"emailAddress": {"address": "danas@contoso.com"}}
                ],
            },
            "saveToSentItems": True,
        }
        for key in ("toRecipients", "ccRecipients"):
            for entry in payload["message"][key]:
                assert set(entry) == {"emailAddress"}


# --- The sender rule ---------------------------------------------------------
class TestSenderComesFromTheToken:
    def test_matching_sender_is_accepted_and_reported(self, delegated, app_tripwire) -> None:
        """The sender the caller reports is the identity in the token (amendment A.3)."""
        sent = transport(ok202())

        result = graph.send_mail(
            mail=delegated_mail(sender=PERSON),
            payload=send_payload(),
            transport=mock(sent),
        )

        assert result.sender == PERSON

    def test_unset_sender_is_taken_from_the_token(self, delegated, app_tripwire) -> None:
        """An empty [mail] sender is not an error in delegated mode: the token names
        the mailbox (config.py cannot express "absent", so this is the empty form)."""
        sent = transport(ok202())

        result = graph.send_mail(
            mail=delegated_mail(sender=""), payload=send_payload(), transport=mock(sent)
        )

        assert result.sender == PERSON
        assert sent.calls == 1

    def test_sender_mismatch_is_refused_as_exit_2_before_any_call(
        self, delegated, app_tripwire, cert_keychain
    ) -> None:
        """No send-as-other: a configured sender that is not the signed-in identity
        stops the send as a config error (exit 2) naming the UPN to log in as."""
        delegated.upn = OTHER_PERSON
        sent = transport(ok202())

        with pytest.raises(config_module.ConfigError) as excinfo:
            graph.send_mail(
                mail=delegated_mail(sender=PERSON),
                payload=send_payload(),
                transport=mock(sent),
            )

        assert excinfo.value.exit_code == EXIT_USAGE
        assert "no send-as-other" in excinfo.value.message
        assert OTHER_PERSON in excinfo.value.message
        # Refused before the token was even fetched, and before the socket.
        assert delegated.calls == 0
        assert sent.calls == 0
        assert cert_keychain.audit == []

    def test_mismatch_message_carries_no_token_value(
        self, delegated, app_tripwire
    ) -> None:
        delegated.upn = OTHER_PERSON

        with pytest.raises(config_module.ConfigError) as excinfo:
            graph.send_mail(
                mail=delegated_mail(sender=PERSON),
                payload=send_payload(),
                transport=mock(transport(ok202())),
            )

        assert CANARY_DELEGATED not in excinfo.value.message

    def test_sender_comparison_ignores_case(self, delegated, app_tripwire) -> None:
        """A UPN's case is not a different mailbox (Entra treats it as case-insensitive),
        so an operator who typed it differently has not asked to send-as-other."""
        sent = transport(ok202())

        result = graph.send_mail(
            mail=delegated_mail(sender="Person@Contoso.COM"),
            payload=send_payload(),
            transport=mock(sent),
        )

        assert result.sender == PERSON

    def test_mismatch_is_reported_as_the_upn_in_the_token(self, delegated, app_tripwire) -> None:
        """The remedy names the identity to log in as, so the operator can act."""
        delegated.upn = OTHER_PERSON

        with pytest.raises(config_module.ConfigError) as excinfo:
            graph.send_mail(
                mail=delegated_mail(sender=PERSON),
                payload=send_payload(),
                transport=mock(transport(ok202())),
            )

        assert OTHER_PERSON in excinfo.value.message
        assert "remove sender or login as" in excinfo.value.message


# --- Retry / error policy is the shared one ----------------------------------
class TestRetryPolicyIsShared:
    def test_delegated_token_is_acquired_once_across_retries(
        self, delegated, app_tripwire, sleeper
    ) -> None:
        sent = transport(httpx.Response(500, headers={"request-id": REQUEST_ID}), ok202())

        graph.send_mail(
            mail=delegated_mail(), payload=send_payload(), transport=mock(sent)
        )

        assert delegated.calls == 1
        assert sent.calls == 2

    def test_429_retry_after_is_honoured_in_delegated_mode(
        self, delegated, app_tripwire, sleeper
    ) -> None:
        sent = transport(
            httpx.Response(429, headers={"Retry-After": "1", "request-id": REQUEST_ID}),
            ok202(),
        )

        result = graph.send_mail(
            mail=delegated_mail(), payload=send_payload(), transport=mock(sent)
        )

        assert (sent.calls, sleeper) == (2, [1.0])
        assert result.request_id == REQUEST_ID

    def test_400_is_exit_5_after_one_try_with_the_request_id(
        self, delegated, app_tripwire, sleeper
    ) -> None:
        sent = transport(
            httpx.Response(
                400,
                headers={"request-id": REQUEST_ID},
                json={"error": {"code": "BadRequest", "message": "bad address"}},
            )
        )

        with pytest.raises(graph.GraphRemoteError) as excinfo:
            graph.send_mail(
                mail=delegated_mail(), payload=send_payload(), transport=mock(sent)
            )

        assert excinfo.value.exit_code == EXIT_REMOTE
        assert sent.calls == 1 and sleeper == []
        assert REQUEST_ID in excinfo.value.message

    def test_a_401_body_that_echoes_the_message_never_reaches_the_error(
        self, delegated, app_tripwire
    ) -> None:
        sent = transport(
            httpx.Response(
                401,
                headers={"request-id": REQUEST_ID},
                json={"error": {"message": f"echo: {BODY_CANARY}"}},
            )
        )

        with pytest.raises(graph.GraphRemoteError) as excinfo:
            graph.send_mail(
                mail=delegated_mail(),
                payload=graph.build_send_payload(
                    to=["alice@example.com"], subject="hi", body=BODY_CANARY
                ),
                transport=mock(sent),
            )

        assert BODY_CANARY not in excinfo.value.message
        assert REQUEST_ID in excinfo.value.message

    def test_missing_delegated_sign_in_is_exit_4_with_the_hint(
        self, delegated, app_tripwire
    ) -> None:
        """delegation.get_delegated_token's own refusal (exit 4, "run mnotify login")
        travels through unchanged — no new error class for the delegated path."""
        delegated.token_error = AuthError(
            f"no delegated sign-in cached; {delegation.LOGIN_HINT}"
        )
        sent = transport(ok202())

        with pytest.raises(AuthError) as excinfo:
            graph.send_mail(
                mail=delegated_mail(), payload=send_payload(), transport=mock(sent)
            )

        assert excinfo.value.exit_code == EXIT_AUTH
        assert delegation.LOGIN_HINT in excinfo.value.message
        assert sent.calls == 0


# --- The command pipeline is unchanged in delegated mode ----------------------
def delegated_config(tmp_path, **mail_overrides) -> Config:
    """The placeholder config conftest writes, with [mail] mode = delegated.

    ``[mail] sender`` defaults to the signed-in UPN so the mismatch rule passes;
    the allow list is the same example.com/contoso.com set.
    """
    values = dict(
        tenant_id=PLACEHOLDER_GUID,
        client_id=PLACEHOLDER_GUID,
        sender=PERSON,
        auth="certificate",
        default_reply_to=PLACEHOLDER_REPLY_TO,
        mode=MAIL_MODE_DELEGATED,
    )
    values.update(mail_overrides)
    return Config(
        mail=MailConfig(**values),
        allow=AllowConfig(domains=(PLACEHOLDER_DOMAIN,), addresses=(PERSON,)),
        limits=LimitsConfig(),
        paths=PathsConfig(
            audit=tmp_path / "logs" / "sent.jsonl", state_dir=tmp_path / "state"
        ),
    )


@pytest.fixture
def delegated_cli_config(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Point MICRO_NOTIFY_CONFIG at a delegated-mode config under tmp_path."""
    made: list[Config] = []

    def install(**mail_overrides) -> Config:
        cfg = delegated_config(tmp_path, **mail_overrides)
        path = tmp_path / "config" / "delegated.toml"
        write_config(cfg, path)
        monkeypatch.setenv(config_module.CONFIG_ENV_VAR, str(path))
        made.append(cfg)
        return cfg

    install()
    return install


@pytest.fixture
def mail_transport(monkeypatch: pytest.MonkeyPatch):
    """Put a MockTransport where ``graph.send_mail`` opens its httpx client."""

    def install(*responses: httpx.Response) -> TransportHarness:
        sent = transport(*responses)
        real_client = httpx.Client

        def fake_client(**kwargs):
            kwargs["transport"] = httpx.MockTransport(sent.handler)
            return real_client(**kwargs)

        monkeypatch.setattr(graph.httpx, "Client", fake_client)
        return sent

    return install


def audit_lines(cfg: Config) -> list[dict]:
    path = cfg.paths.audit
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestMailCommandInDelegatedMode:
    def test_success_is_audited_under_the_token_upn_and_spends_one_budget(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        fake_keychain, capsys,
    ) -> None:
        cfg = delegated_cli_config()
        sent = mail_transport(ok202())

        assert cli.main(SEND) == EXIT_OK

        assert str(sent.requested[0].url).endswith("/me/sendMail")
        lines = audit_lines(cfg)
        assert len(lines) == 1
        assert lines[0]["outcome"] == "sent"
        assert lines[0]["channel"] == "mail"
        assert lines[0]["sender"] == PERSON
        assert lines[0]["request_id"] == REQUEST_ID
        assert lines[0]["recipients"] == ["someone@example.com"]
        assert lines[0]["body_size"] == len(BODY_CANARY.encode("utf-8"))
        # No bodies, no token value, anywhere in the line or the output.
        raw = cfg.paths.audit.read_text(encoding="utf-8")
        assert BODY_CANARY not in raw and CANARY_DELEGATED not in raw
        captured = capsys.readouterr()
        assert PERSON in captured.out
        assert CANARY_DELEGATED not in captured.out + captured.err
        assert json.loads(cfg.paths.counter_file.read_text(encoding="utf-8"))["count"] == 1

    def test_allowlist_refusal_exits_3_before_any_token_or_http_call(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        fake_keychain, capsys,
    ) -> None:
        cfg = delegated_cli_config()
        sent = mail_transport()

        exit_code = cli.main(
            ["mail", "send", "--to", "bob@notallowed.example", "--subject", "hi",
             "--body", BODY_CANARY]
        )

        assert exit_code == EXIT_GUARD
        assert sent.calls == 0 and delegated.calls == 0
        assert fake_keychain.audit == []
        assert "not allowed" in capsys.readouterr().err.lower()
        assert audit_lines(cfg)[-1]["outcome"] == "refused"

    def test_daily_cap_exits_6_before_any_token_or_http_call(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        fake_keychain, capsys,
    ) -> None:
        cfg = delegated_cli_config()
        cfg.paths.counter_file.parent.mkdir(parents=True, exist_ok=True)
        cfg.paths.counter_file.write_text(
            json.dumps({"date": guard.utc_today(), "count": cfg.limits.daily_max}),
            encoding="utf-8",
        )
        sent = mail_transport()

        assert cli.main(SEND) == EXIT_DAILY_CAP

        assert sent.calls == 0 and delegated.calls == 0
        assert fake_keychain.audit == []
        assert "daily cap" in capsys.readouterr().err
        assert audit_lines(cfg)[-1]["outcome"] == "refused"

    def test_attachment_over_the_cap_is_refused_before_any_token_or_http_call(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        tmp_path, fake_keychain, capsys,
    ) -> None:
        cfg = delegated_cli_config()
        big = tmp_path / "big.bin"
        with big.open("ab") as handle:
            handle.truncate(cfg.limits.max_attach_mb * guard.BYTES_PER_MB + 1)
        sent = mail_transport()

        exit_code = cli.main(SEND + ["--attach", str(big)])

        assert exit_code == EXIT_GUARD
        assert sent.calls == 0 and delegated.calls == 0
        assert "max_attach_mb" in capsys.readouterr().err
        assert audit_lines(cfg)[-1]["outcome"] == "refused"

    def test_sender_mismatch_exits_2_with_one_body_free_audit_line(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        fake_keychain, capsys,
    ) -> None:
        cfg = delegated_cli_config(sender="noreply@example.com")
        delegated.upn = OTHER_PERSON
        sent = mail_transport()

        assert cli.main(SEND) == EXIT_USAGE

        assert sent.calls == 0 and delegated.calls == 0
        captured = capsys.readouterr()
        assert "no send-as-other" in captured.err
        assert OTHER_PERSON in captured.err
        assert BODY_CANARY not in captured.err + captured.out
        lines = audit_lines(cfg)
        assert len(lines) == 1 and lines[0]["outcome"] == "failed"
        assert BODY_CANARY not in json.dumps(lines[0])

    def test_missing_sign_in_exits_4_and_is_audited_as_failed(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        fake_keychain, capsys,
    ) -> None:
        cfg = delegated_cli_config()
        delegated.token_error = AuthError(
            f"no delegated sign-in cached; {delegation.LOGIN_HINT}"
        )
        sent = mail_transport()

        assert cli.main(SEND) == EXIT_AUTH

        assert sent.calls == 0
        captured = capsys.readouterr()
        assert delegation.LOGIN_HINT in captured.err
        assert CANARY_DELEGATED not in captured.err + captured.out
        assert audit_lines(cfg)[-1]["outcome"] == "failed"

    def test_dry_run_in_delegated_mode_needs_no_sign_in_and_reads_nothing(
        self, delegated_cli_config, app_tripwire, mail_transport, fake_keychain,
        capsys,
    ) -> None:
        """--dry-run stops before the mode branch: no token, no whoami, no keychain
        (design §4), and the printed document is the exact payload (§3.1 shape)."""
        cfg = delegated_cli_config()
        spy = DelegationStub()
        sent = mail_transport()

        assert cli.main(SEND + ["--dry-run"]) == EXIT_OK

        assert spy.calls == 0 and spy.whoami_calls == []
        assert sent.calls == 0
        assert fake_keychain.audit == []
        printed = json.loads(capsys.readouterr().out)
        assert printed["message"]["toRecipients"] == [
            {"emailAddress": {"address": "someone@example.com"}}
        ]
        assert printed["saveToSentItems"] is True
        assert audit_lines(cfg)[-1]["outcome"] == "dry_run"

    def test_json_mode_reports_a_sent_delegated_message(
        self, delegated_cli_config, delegated, app_tripwire, mail_transport,
        fake_keychain, capsys,
    ) -> None:
        delegated_cli_config()
        mail_transport(ok202())

        assert cli.main(SEND + ["--json"]) == EXIT_OK

        document = json.loads(capsys.readouterr().out)
        assert document["ok"] is True
        assert document["outcome"] == "sent"
        assert document["requestId"] == REQUEST_ID
        assert document["recipients"] == ["someone@example.com"]

    def test_app_mode_cli_behaviour_is_unchanged(
        self, delegated_cli_config, msal_stub, cert_keychain, mail_transport,
        capsys,
    ) -> None:
        """Same command, mode="app": the sender printed and audited is still
        [mail] sender, via the cert token — the pre-amendment path."""
        cfg = delegated_cli_config(sender="noreply@example.com", mode=MAIL_MODE_APP)
        msal_stub.silent_result = {"access_token": APP_TOKEN}
        sent = mail_transport(ok202())

        assert cli.main(SEND) == EXIT_OK

        assert str(sent.requested[0].url).endswith(
            "/users/noreply%40example.com/sendMail"
        )
        assert audit_lines(cfg)[-1]["sender"] == "noreply@example.com"
        assert "noreply@example.com" in capsys.readouterr().out
