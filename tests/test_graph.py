"""Microsoft Graph mail layer (design sections 3.1, 9) — payload, token, transport.

Nothing here opens a socket: HTTP goes through ``httpx.MockTransport`` and msal is
patched at the attribute the production code calls. The autouse ``no_network``
fixture from tests/conftest.py is the backstop (design section 7).
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from micro_notify import (
    EXIT_AUTH,
    EXIT_GUARD,
    EXIT_REMOTE,
    AuthError,
    GuardRefusal,
    RemoteError,
    config,
    graph,
)
from micro_notify.config import AUTH_SECRET, MailConfig
from micro_notify.secrets import (
    ACCOUNT_CERT_PEM,
    ACCOUNT_CERT_THUMBPRINT,
    ACCOUNT_CLIENT_SECRET,
)

PLACEHOLDER_TENANT = "00000000-0000-0000-0000-000000000000"
SENDER = "noreply@example.com"
CANARY_SECRET = "super-secret-client-value-DO-NOT-LEAK"
CANARY_PEM_BODY = "FAKEPEMBODYSUPERSECRETNOTAREALKEY"
CANARY_THUMBPRINT = "AABBCCDDEEFF00112233445566778899AABBCCDD"


def mail_config(**overrides) -> MailConfig:
    """A [mail] block using only documented placeholders."""
    values = dict(
        tenant_id=PLACEHOLDER_TENANT,
        client_id=PLACEHOLDER_TENANT,
        sender=SENDER,
        auth="certificate",
        default_reply_to="",
    )
    values.update(overrides)
    return MailConfig(**values)


class MsalStub:
    """Script + record for msal.ConfidentialClientApplication.

    One instance per test, handed out by the ``msal_stub`` fixture: set
    ``silent_result`` / ``client_result`` to script what msal returns, then assert
    on ``apps`` (the construction kwargs) and the recorded token calls.
    """

    def __init__(self) -> None:
        self.silent_result: dict | None = None
        self.client_result: dict | None = None
        self.apps: list[dict] = []
        self.silent_calls: list[tuple] = []
        self.client_calls: list[tuple] = []

    @property
    def token_calls(self) -> int:
        return len(self.silent_calls) + len(self.client_calls)

    def make_app(self, **kwargs):
        self.apps.append(kwargs)
        stub = self

        class _App:
            def acquire_token_silent(self, *args, **call_kwargs):
                stub.silent_calls.append((args, call_kwargs))
                return stub.silent_result

            def acquire_token_for_client(self, *args, **call_kwargs):
                stub.client_calls.append((args, call_kwargs))
                return stub.client_result

        return _App()


@pytest.fixture
def msal_stub(monkeypatch: pytest.MonkeyPatch) -> MsalStub:
    """Patch msal at the attribute graph.py reaches for."""
    stub = MsalStub()
    monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", stub.make_app)
    return stub


@pytest.fixture
def seeded_keychain(fake_keychain):
    """Keychain holding a cert-mode pair, using placeholder-shaped values."""
    fake_keychain.seed(ACCOUNT_CERT_PEM, CANARY_PEM_BODY)
    fake_keychain.seed(ACCOUNT_CERT_THUMBPRINT, CANARY_THUMBPRINT)
    return fake_keychain


# --- Payload builder -------------------------------------------------------
class TestBuildSendPayloadText:
    def test_minimal_text_message_shape(self) -> None:
        """One to-recipient, a subject and a plain-text body produce the exact
        Graph sendMail document (design section 3.1)."""
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            subject="Build failed",
            body="the pipeline is red",
        )

        assert payload["message"]["subject"] == "Build failed"
        assert payload["message"]["body"] == {
            "contentType": "text",
            "content": "the pipeline is red",
        }
        assert payload["message"]["toRecipients"] == [
            {"recipient": {"emailAddress": {"address": "alice@example.com"}}}
        ]
        assert payload["saveToSentItems"] is True


class TestHtmlContentType:
    def test_html_flag_switches_content_type(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            subject="hi",
            body="<p>red</p>",
            html=True,
        )

        assert payload["message"]["body"] == {
            "contentType": "html",
            "content": "<p>red</p>",
        }

    def test_default_content_type_is_text_not_html(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"], subject="hi", body="plain"
        )

        assert payload["message"]["body"]["contentType"] == "text"


class TestCcBccArrays:
    def test_cc_and_bcc_become_their_own_recipient_arrays(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            cc=["carbon@example.com"],
            bcc=["blind@contoso.com"],
            subject="hi",
            body="body",
        )

        message = payload["message"]
        assert message["toRecipients"] == [
            {"recipient": {"emailAddress": {"address": "alice@example.com"}}}
        ]
        assert message["ccRecipients"] == [
            {"recipient": {"emailAddress": {"address": "carbon@example.com"}}}
        ]
        assert message["bccRecipients"] == [
            {"recipient": {"emailAddress": {"address": "blind@contoso.com"}}}
        ]

    def test_multiple_recipients_keep_their_order(self) -> None:
        payload = graph.build_send_payload(
            to=["one@example.com", "two@example.com"], subject="hi", body="body"
        )

        addresses = [
            r["recipient"]["emailAddress"]["address"]
            for r in payload["message"]["toRecipients"]
        ]
        assert addresses == ["one@example.com", "two@example.com"]

    def test_empty_cc_and_bcc_are_omitted_not_sent_empty(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"], subject="hi", body="body"
        )

        assert "ccRecipients" not in payload["message"]
        assert "bccRecipients" not in payload["message"]


class TestReplyTo:
    def test_reply_to_is_a_recipient_array(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            subject="hi",
            body="body",
            reply_to="human@contoso.com",
        )

        assert payload["message"]["replyTo"] == [
            {"recipient": {"emailAddress": {"address": "human@contoso.com"}}}
        ]

    def test_no_reply_to_means_the_key_is_absent(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"], subject="hi", body="body"
        )

        assert "replyTo" not in payload["message"]

    def test_blank_reply_to_is_treated_as_absent(self) -> None:
        """``mail.default_reply_to`` defaults to "" — an empty Reply-To would be a
        Graph 400, so it must not reach the payload."""
        payload = graph.build_send_payload(
            to=["alice@example.com"], subject="hi", body="body", reply_to="   "
        )

        assert "replyTo" not in payload["message"]


class TestAttachments:
    def test_attachment_is_a_base64_file_attachment_with_name_and_size(self) -> None:
        raw = b"report data"
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            subject="hi",
            body="body",
            attachments=[graph.Attachment(name="report.txt", bytes=raw)],
        )

        attachment = payload["message"]["attachments"][0]
        assert attachment["@odata.type"] == "#microsoft.graph.fileAttachment"
        assert attachment["name"] == "report.txt"
        assert base64.b64decode(attachment["contentBytes"]) == raw
        assert attachment["size"] == len(raw)

    def test_multiple_attachments_keep_order_and_each_is_decoded_back(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            subject="hi",
            body="body",
            attachments=[
                graph.Attachment(name="a.txt", bytes=b"AAA"),
                graph.Attachment(name="b.bin", bytes=b"\x00\x01\x02"),
            ],
        )

        names = [a["name"] for a in payload["message"]["attachments"]]
        blobs = [
            base64.b64decode(a["contentBytes"])
            for a in payload["message"]["attachments"]
        ]
        assert names == ["a.txt", "b.bin"]
        assert blobs == [b"AAA", b"\x00\x01\x02"]

    def test_no_attachments_key_when_there_are_no_attachments(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"], subject="hi", body="body"
        )

        assert "attachments" not in payload["message"]


class TestAttachmentTotalCap:
    """Design section 3.3: total attachment bytes are capped and refusal is exit 3,
    before any network call."""

    def test_total_exactly_at_the_cap_is_allowed(self) -> None:
        payload = graph.build_send_payload(
            to=["alice@example.com"],
            subject="hi",
            body="body",
            attachments=[graph.Attachment(name="a.bin", bytes=b"x" * 100)],
            max_total_attach_bytes=100,
        )

        assert payload["message"]["attachments"][0]["size"] == 100

    def test_total_one_byte_over_the_cap_is_refused_as_exit_3(self) -> None:
        attachments = [
            graph.Attachment(name="a.bin", bytes=b"x" * 60),
            graph.Attachment(name="b.bin", bytes=b"y" * 41),
        ]

        with pytest.raises(GuardRefusal) as excinfo:
            graph.build_send_payload(
                to=["alice@example.com"],
                subject="hi",
                body="body",
                attachments=attachments,
                max_total_attach_bytes=100,
            )

        assert excinfo.value.exit_code == EXIT_GUARD
        # The message names the sizes so the operator can act, without content.
        assert "101" in excinfo.value.message
        assert "100" in excinfo.value.message


# --- Token acquisition (design section 3.1) --------------------------------
class TestCertificateToken:
    def test_client_app_is_built_from_the_keychain_pair(
        self, seeded_keychain, msal_stub
    ) -> None:
        """Certificate mode passes msal a credential dict of the private key PEM
        plus the thumbprint, both read from the keychain accounts of design §3.4."""
        msal_stub.silent_result = {"access_token": "a-token"}

        token = graph.acquire_token(mail_config())

        assert token == "a-token"
        assert msal_stub.apps[0]["client_id"] == PLACEHOLDER_TENANT
        assert msal_stub.apps[0]["client_credential"] == {
            "private_key": CANARY_PEM_BODY,
            "thumbprint": CANARY_THUMBPRINT,
        }
        assert msal_stub.apps[0]["authority"] == (
            "https://login.microsoftonline.com/" + PLACEHOLDER_TENANT + "/v2.0"
        )
        # Read through the secrets module attributes so fake_keychain intercepts.
        assert seeded_keychain.audit == [
            ACCOUNT_CERT_PEM,
            ACCOUNT_CERT_THUMBPRINT,
        ]

    def test_silent_token_is_used_and_scope_is_the_graph_default(
        self, seeded_keychain, msal_stub
    ) -> None:
        """``acquire_token_silent`` is tried first with the Graph .default scope
        (design section 3.1), so a cached token costs no round trip."""
        msal_stub.silent_result = {"access_token": "cached-token"}

        token = graph.acquire_token(mail_config())

        assert token == "cached-token"
        assert msal_stub.silent_calls[0][0] == ([graph.GRAPH_SCOPE],)
        assert msal_stub.client_calls == []

    def test_falls_back_to_client_credentials_when_cache_is_cold(
        self, seeded_keychain, msal_stub
    ) -> None:
        msal_stub.silent_result = None
        msal_stub.client_result = {"access_token": "fresh-token"}

        token = graph.acquire_token(mail_config())

        assert token == "fresh-token"
        assert len(msal_stub.silent_calls) == 1
        assert msal_stub.client_calls[0][0] == ([graph.GRAPH_SCOPE],)


class TestSecretToken:
    def test_secret_mode_passes_the_secret_as_client_credential(
        self, fake_keychain, msal_stub
    ) -> None:
        fake_keychain.seed(ACCOUNT_CLIENT_SECRET, CANARY_SECRET)
        msal_stub.silent_result = {"access_token": "a-token"}

        token = graph.acquire_token(mail_config(auth=AUTH_SECRET))

        assert token == "a-token"
        assert msal_stub.apps[0]["client_credential"] == CANARY_SECRET
        assert fake_keychain.audit == [ACCOUNT_CLIENT_SECRET]


class TestTokenFailurePaths:
    def test_missing_certificate_pem_is_exit_4_naming_the_account_only(
        self, fake_keychain, msal_stub
    ) -> None:
        """Design section 3: a missing keychain item is an auth error whose message
        names the *account*, never a value."""
        fake_keychain.seed(ACCOUNT_CERT_THUMBPRINT, CANARY_THUMBPRINT)

        with pytest.raises(AuthError) as excinfo:
            graph.acquire_token(mail_config())

        assert excinfo.value.exit_code == EXIT_AUTH
        assert ACCOUNT_CERT_PEM in excinfo.value.message
        assert CANARY_PEM_BODY not in excinfo.value.message
        assert CANARY_THUMBPRINT not in excinfo.value.message

    def test_missing_thumbprint_is_exit_4_naming_the_account_only(
        self, fake_keychain, msal_stub
    ) -> None:
        fake_keychain.seed(ACCOUNT_CERT_PEM, CANARY_PEM_BODY)

        with pytest.raises(AuthError) as excinfo:
            graph.acquire_token(mail_config())

        assert excinfo.value.exit_code == EXIT_AUTH
        assert ACCOUNT_CERT_THUMBPRINT in excinfo.value.message
        assert CANARY_PEM_BODY not in excinfo.value.message

    def test_missing_client_secret_is_exit_4_naming_the_account_only(
        self, fake_keychain, msal_stub
    ) -> None:
        with pytest.raises(AuthError) as excinfo:
            graph.acquire_token(mail_config(auth=AUTH_SECRET))

        assert excinfo.value.exit_code == EXIT_AUTH
        assert ACCOUNT_CLIENT_SECRET in excinfo.value.message
        assert CANARY_SECRET not in excinfo.value.message

    def test_no_msal_client_is_constructed_when_a_key_is_missing(
        self, fake_keychain, msal_stub
    ) -> None:
        """A keychain read failure must short-circuit before msal is touched."""
        with pytest.raises(AuthError):
            graph.acquire_token(mail_config())

        assert msal_stub.apps == []

    def test_msal_error_response_is_exit_4_without_leaking_the_token(
        self, seeded_keychain, msal_stub
    ) -> None:
        """An msal error body (invalid_client / AADSTS...) maps to exit 4."""
        msal_stub.silent_result = None
        msal_stub.client_result = {
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid provided secret value",
        }

        with pytest.raises(AuthError) as excinfo:
            graph.acquire_token(mail_config())

        assert excinfo.value.exit_code == EXIT_AUTH
        assert "invalid_client" in excinfo.value.message
        assert "AADSTS7000215" in excinfo.value.message

    def test_msal_error_without_description_still_names_the_error_code(
        self, seeded_keychain, msal_stub
    ) -> None:
        msal_stub.silent_result = None
        msal_stub.client_result = {"error": "invalid_scope"}

        with pytest.raises(AuthError) as excinfo:
            graph.acquire_token(mail_config())

        assert excinfo.value.exit_code == EXIT_AUTH
        assert "invalid_scope" in excinfo.value.message

    def test_token_without_access_token_is_exit_4(
        self, seeded_keychain, msal_stub
    ) -> None:
        msal_stub.silent_result = None
        msal_stub.client_result = {"token_type": "Bearer"}

        with pytest.raises(AuthError) as excinfo:
            graph.acquire_token(mail_config())

        assert excinfo.value.exit_code == EXIT_AUTH


# --- Transport + retry (design sections 3.1, 9) -----------------------------
REQUEST_ID = "req-00000000-0000-0000-0000-000000000000"


def send_payload() -> dict:
    return graph.build_send_payload(
        to=["alice@example.com"], subject="hi", body="body"
    )


class RecordingSleeper:
    """A fake clock for the backoff: records the sleep durations, sleeps never."""

    def __init__(self) -> None:
        self.slept: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.slept.append(seconds)


class TransportHarness:
    """httpx.MockTransport scripted with canned responses + a full request log."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self.remaining = list(responses)
        self.requested: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requested.append(request)
        if len(self.remaining) > 1:
            return self.remaining.pop(0)
        return self.remaining[0]

    @property
    def calls(self) -> int:
        return len(self.requested)


def harness(*responses: httpx.Response) -> TransportHarness:
    return TransportHarness(list(responses))


def ok202(request_id: str = REQUEST_ID) -> httpx.Response:
    return httpx.Response(202, headers={"request-id": request_id})


def mock(transport: TransportHarness) -> httpx.MockTransport:
    """Wrap the scripted harness in the real MockTransport machinery."""
    return httpx.MockTransport(transport.handler)


@pytest.fixture
def sleeper(monkeypatch: pytest.MonkeyPatch) -> RecordingSleeper:
    """No test sleeps for real; every backoff duration is recorded instead."""
    fake = RecordingSleeper()
    monkeypatch.setattr(graph.time, "sleep", fake)
    return fake


class TestSendMailSuccess:
    def test_202_returns_the_graph_request_id_and_posts_to_sendmail(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(ok202())

        result = graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(transport)
        )

        assert result.request_id == REQUEST_ID
        assert transport.calls == 1
        request = transport.requested[0]
        assert request.method == "POST"
        assert str(request.url) == (
            graph.GRAPH_BASE + "/users/" + "noreply%40example.com" + "/sendMail"
        )
        assert request.headers["authorization"] == "Bearer a-token"
        assert request.headers["content-type"].startswith("application/json")
        body = json.loads(request.content)
        assert body["message"]["subject"] == "hi"
        assert body["saveToSentItems"] is True
        assert sleeper.slept == []

    def test_sender_is_url_encoded_in_the_path(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """An SMTP address is not a URL path segment; Graph wants it encoded."""
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(ok202())

        graph.send_mail(
            mail=mail_config(sender="first.last+alerts@example.com"),
            payload=send_payload(),
            transport=mock(transport),
        )

        assert "first.last%2Balerts%40example.com" in str(
            transport.requested[0].url
        )


class TestNonRetryableErrors:
    def test_400_is_exit_5_after_exactly_one_call_with_the_request_id(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """Design section 9: no retry on 4xx (other than 429). The Graph
        request-id rides in the message so the operator can correlate (§4)."""
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(
                400,
                headers={"request-id": REQUEST_ID},
                json={"error": {"code": "BadRequest", "message": "bad address"}},
            )
        )

        with pytest.raises(RemoteError) as excinfo:
            graph.send_mail(
                mail=mail_config(),
                payload=send_payload(),
                transport=mock(transport),
            )

        assert excinfo.value.exit_code == EXIT_REMOTE
        assert transport.calls == 1
        assert REQUEST_ID in excinfo.value.message
        assert "400" in excinfo.value.message
        assert sleeper.slept == []

    def test_401_is_exit_5_with_no_retry_and_no_body_leak(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """A 401 body from Graph can echo message content; only status +
        request-id may reach the message (design section 2 anti-goals)."""
        msal_stub.silent_result = {"access_token": "a-token"}
        secret_word = "pipeline-is-red-body-content"
        transport = harness(
            httpx.Response(
                401,
                headers={"request-id": REQUEST_ID},
                json={"error": {"message": f"echo: {secret_word}"}},
            )
        )

        with pytest.raises(RemoteError) as excinfo:
            graph.send_mail(
                mail=mail_config(),
                payload=graph.build_send_payload(
                    to=["alice@example.com"], subject="hi", body=secret_word
                ),
                transport=mock(transport),
            )

        assert excinfo.value.exit_code == EXIT_REMOTE
        assert transport.calls == 1
        assert secret_word not in excinfo.value.message
        assert REQUEST_ID in excinfo.value.message


class TestRetryPolicy:
    """Design section 9: retry on 429 and 5xx only, honour Retry-After capped at
    60 s, max 3 tries total."""

    def test_429_with_retry_after_is_retried_then_succeeds(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(429, headers={"Retry-After": "1", "request-id": REQUEST_ID}),
            ok202(),
        )

        result = graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(transport)
        )

        assert result.request_id == REQUEST_ID
        assert transport.calls == 2
        assert sleeper.slept == [1.0]

    def test_retry_after_is_capped_at_60_seconds(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(429, headers={"Retry-After": "3600", "request-id": REQUEST_ID}),
            ok202(),
        )

        graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(transport)
        )

        assert sleeper.slept == [60.0]

    def test_500_three_times_is_exit_5_after_exactly_three_tries(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(500, headers={"request-id": REQUEST_ID})
        )

        with pytest.raises(RemoteError) as excinfo:
            graph.send_mail(
                mail=mail_config(),
                payload=send_payload(),
                transport=mock(transport),
            )

        assert excinfo.value.exit_code == EXIT_REMOTE
        assert transport.calls == 3
        # Two waits between the three tries, and no real sleeping.
        assert len(sleeper.slept) == 2
        assert REQUEST_ID in excinfo.value.message

    def test_503_is_retried(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(503, headers={"request-id": REQUEST_ID}),
            ok202(),
        )

        result = graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(transport)
        )

        assert transport.calls == 2
        assert result.request_id == REQUEST_ID

    def test_429_without_retry_after_falls_back_to_exponential_backoff(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """Without a server hint the waits still grow and still stay capped."""
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(429, headers={"request-id": REQUEST_ID}),
            ok202(),
        )

        graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(transport)
        )

        assert len(sleeper.slept) == 1
        assert 0 < sleeper.slept[0] <= 60.0

    def test_token_is_acquired_once_across_retries(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """Retries reuse the token; they do not re-auth on every try."""
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(
            httpx.Response(500, headers={"request-id": REQUEST_ID}), ok202()
        )

        graph.send_mail(
            mail=mail_config(), payload=send_payload(), transport=mock(transport)
        )

        assert msal_stub.token_calls == 1

    def test_failure_exception_carries_the_request_id_for_the_audit_line(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """The caller audits the Graph request-id on the failed line, so the
        exception must expose it as data, not only inside the message."""
        msal_stub.silent_result = {"access_token": "a-token"}
        transport = harness(httpx.Response(502, headers={"request-id": REQUEST_ID}))

        with pytest.raises(RemoteError) as excinfo:
            graph.send_mail(
                mail=mail_config(), payload=send_payload(), transport=mock(transport)
            )

        assert excinfo.value.request_id == REQUEST_ID

    def test_unreachable_graph_is_exit_5_not_a_crash(
        self, seeded_keychain, msal_stub, sleeper
    ) -> None:
        """Design §4 exit 5 covers an unreachable Graph: a transport error becomes
        RemoteError, so cli.main never prints a traceback (exit 1) for it."""
        msal_stub.silent_result = {"access_token": "a-token"}
        calls: list[httpx.Request] = []

        def refusing(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            raise httpx.ConnectError("connection refused")

        with pytest.raises(RemoteError) as excinfo:
            graph.send_mail(
                mail=mail_config(),
                payload=send_payload(),
                transport=httpx.MockTransport(refusing),
            )

        assert excinfo.value.exit_code == EXIT_REMOTE
        assert len(calls) == 1
