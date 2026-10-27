"""Microsoft Graph mail layer (design sections 3.1, 9) — payload, token, transport.

Nothing here opens a socket: HTTP goes through ``httpx.MockTransport`` and msal is
patched at the attribute the production code calls. The autouse ``no_network``
fixture from tests/conftest.py is the backstop (design section 7).
"""

from __future__ import annotations

import base64

import pytest

from micro_notify import graph


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
        """Graph accepts empty arrays but a payload without the key is the exact
        payload we want to show in --dry-run and to audit."""
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
        blobs = [base64.b64decode(a["contentBytes"]) for a in payload["message"]["attachments"]]
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
        from micro_notify import EXIT_GUARD, GuardRefusal

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
        # The message must name the sizes so the operator can act, without
        # printing content.
        assert "101" in excinfo.value.message
        assert "100" in excinfo.value.message
