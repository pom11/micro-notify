"""Graph mail layer (design sections 3.1, 9): payload builder, token, transport.

Three separable pieces, so the pieces a test can exercise without the others:

* :func:`build_send_payload` — pure; no msal, no httpx, no keychain.
* :func:`acquire_token` — msal ``ConfidentialClientApplication`` for the client
  credentials flow. The keychain is read through :mod:`micro_notify.secrets`
  module attributes (never ``from ... import``) so the shared ``fake_keychain``
  fixture intercepts, and a failure names the *account*, never a value (§3).
* :func:`send_mail` — one POST to ``/users/{sender}/sendMail`` with the retry
  policy of design section 9.

The msal and httpx imports are module-level attributes (``graph.msal``,
``graph.httpx``) precisely so tests can patch them at the call site.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import msal

from . import AuthError, GuardRefusal
from . import secrets
from .config import AUTH_SECRET, MailConfig

ATTACH_CAP_EXCEEDS = "total attachment size"

# Design section 3.1: one scope for app-only Graph access.
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/v2.0"


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


# --- Token acquisition (design section 3.1) ---------------------------------
def _client_credential(mail: MailConfig):
    """Build the msal ``client_credential`` from keychain-held secrets.

    Reads go through ``secrets.<attr>`` (module attribute lookup, not a
    ``from``-import) so the shared fake_keychain fixture intercepts them. A
    missing item raises ``KeychainError`` (exit 4) naming the *account*; no
    value ever enters an exception message here.
    """
    if mail.auth == AUTH_SECRET:
        return secrets.get(secrets.ACCOUNT_CLIENT_SECRET)
    private_key = secrets.get(secrets.ACCOUNT_CERT_PEM)
    thumbprint = secrets.get(secrets.ACCOUNT_CERT_THUMBPRINT)
    return {"private_key": private_key, "thumbprint": thumbprint}


def acquire_token(mail: MailConfig) -> str:
    """Return an app-only Graph bearer token, from cache when possible.

    ``acquire_token_silent`` runs first so a cached token costs no round trip;
    the client-credentials flow only runs on a cold cache. Any msal error
    (``invalid_client``, ``AADSTS...``) becomes :class:`AuthError` -> exit 4.
    """
    app = msal.ConfidentialClientApplication(
        client_id=mail.client_id,
        # Evaluated before the constructor runs: a missing keychain item raises
        # here, so msal is never constructed with half a credential.
        client_credential=_client_credential(mail),
        authority=AUTHORITY_TEMPLATE.format(tenant_id=mail.tenant_id),
    )
    result = app.acquire_token_silent([GRAPH_SCOPE], account=None)
    if not result:
        result = app.acquire_token_for_client([GRAPH_SCOPE])
    if not isinstance(result, dict) or not result.get("access_token"):
        error = (result or {}).get("error", "unknown_error")
        description = (result or {}).get("error_description", "")
        detail = f"{error}: {description}" if description else str(error)
        raise AuthError(f"Graph token acquisition failed ({detail})")
    return result["access_token"]
