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
