"""Minimal Graph mail layer: the pure payload builder (design section 3.1)."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from . import GuardRefusal

ATTACH_CAP_EXCEEDS = "total attachment size"


@dataclass(frozen=True)
class Attachment:
    name: str
    bytes: bytes


def _recipient(address: str) -> dict:
    return {"recipient": {"emailAddress": {"address": address}}}


def build_send_payload(
    *,
    to: list[str],
    subject: str,
    body: str,
    html: bool = False,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to: str | None = None,
    attachments: list[Attachment] | None = None,
    max_total_attach_bytes: int | None = None,
) -> dict:
    attachments = attachments or []
    total = sum(len(a.bytes) for a in attachments)
    if max_total_attach_bytes is not None and total > max_total_attach_bytes:
        raise GuardRefusal(
            f"{ATTACH_CAP_EXCEEDS}: {total} bytes exceeds the limit of "
            f"{max_total_attach_bytes} bytes"
        )

    message: dict = {
        "subject": subject,
        "body": {"contentType": "html" if html else "text", "content": body},
        "toRecipients": [_recipient(a) for a in to],
    }
    if cc:
        message["ccRecipients"] = [_recipient(a) for a in cc]
    if bcc:
        message["bccRecipients"] = [_recipient(a) for a in bcc]
    if reply_to and reply_to.strip():
        message["replyTo"] = [_recipient(reply_to.strip())]
    if attachments:
        message["attachments"] = [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": a.name,
                "contentBytes": base64.b64encode(a.bytes).decode("ascii"),
                "size": len(a.bytes),
            }
            for a in attachments
        ]
    return {"message": message, "saveToSentItems": True}
