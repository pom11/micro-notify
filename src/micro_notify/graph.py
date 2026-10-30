"""Graph mail layer (design sections 3.1, 9): payload builder, token, transport.

Three separable pieces, so the pieces a test can exercise without the others:

* :func:`build_send_payload` — pure; no msal, no httpx, no keychain.
* :func:`acquire_token` — msal ``ConfidentialClientApplication`` for the client
  credentials flow. The keychain is read through :mod:`micro_notify.secrets`
  module attributes (never ``from ... import``) so the shared ``fake_keychain``
  fixture intercepts, and a failure names the *account*, never a value (§3).
* :func:`send_mail` — one POST to ``/users/{sender}/sendMail`` with the retry
  policy of design section 9. In mail mode ``delegated`` (amendment 2026-10-30)
  the same payload instead goes to ``/me/sendMail`` with the signed-in person's
  token — see :func:`_delegated_send`; the app-only path below is unchanged.

The msal and httpx imports are module-level attributes (``graph.msal``,
``graph.httpx``) precisely so tests can patch them at the call site.
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import quote

import httpx
import msal

from . import AuthError, GuardRefusal, RemoteError
from . import secrets
from .config import AUTH_SECRET, MAIL_MODE_DELEGATED, ConfigError, MailConfig

ATTACH_CAP_EXCEEDS = "total attachment size"

# Design section 3.1: one scope for app-only Graph access.
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# Design amendment 2026-10-30 (delegated mode): the signed-in person's own mailbox,
# addressed as ``/me``. The Graph sendMail doc lists ``POST /me/sendMail`` and
# ``POST /users/{id | userPrincipalName}/sendMail`` as the two forms of the same
# action, and the ``/me`` form has no sender in it at all — Graph resolves the sender
# from the token. A delegated send therefore *cannot* be a send-as-other, whichever
# way the config file is written.
DELEGATED_SENDMAIL_URL = f"{GRAPH_BASE}/me/sendMail"
# msal appends /v2.0/.well-known/openid-configuration itself; a /v2.0 suffix
# here doubles it and tenant discovery 404s.
AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"


@dataclass(frozen=True)
class Attachment:
    name: str
    bytes: bytes


def _recipient(address: str) -> dict:
    # Graph recipient resource: {"emailAddress": {"address": ...}} with no wrapper.
    return {"emailAddress": {"address": address}}


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
    # Evaluated before the constructor runs: a missing keychain item raises
    # here, so msal is never constructed with half a credential.
    credential = _client_credential(mail)
    try:
        app = msal.ConfidentialClientApplication(
            client_id=mail.client_id,
            client_credential=credential,
            authority=AUTHORITY_TEMPLATE.format(tenant_id=mail.tenant_id),
        )
    except ValueError as exc:
        # msal raises ValueError when tenant discovery fails (bad tenant id,
        # bad authority, no network) — an auth failure, not a crash.
        raise AuthError(f"Graph authority discovery failed ({exc})") from exc
    result = app.acquire_token_silent([GRAPH_SCOPE], account=None)
    if not result:
        result = app.acquire_token_for_client([GRAPH_SCOPE])
    if not isinstance(result, dict) or not result.get("access_token"):
        error = (result or {}).get("error", "unknown_error")
        description = (result or {}).get("error_description", "")
        detail = f"{error}: {description}" if description else str(error)
        raise AuthError(f"Graph token acquisition failed ({detail})")
    return result["access_token"]


# --- Transport + retry (design sections 3.1, 9) ------------------------------
MAX_TRIES = 3
RETRY_AFTER_CAP_SECONDS = 60.0
BASE_BACKOFF_SECONDS = 1.0
SUCCESS_STATUSES = frozenset({200, 201, 202, 204})

# Graph error codes are machine tokens; only that shape may join a message, so a
# response body echoing message content can never reach stderr or the audit log.
_GRAPH_CODE_CHARS = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,63}$")


@dataclass(frozen=True)
class SendResult:
    """What the caller needs for the design section 4 JSON and the audit line.

    ``sender`` is ``None`` on the app-only path — there the sender is always
    ``[mail] sender`` and the caller already has it. A delegated send fills it with
    the identity the token names (amendment 2026-10-30), which is the only value
    that may be reported as the sender of that message.
    """

    status_code: int
    request_id: str | None
    sender: str | None = None


class GraphRemoteError(RemoteError):
    """:class:`RemoteError` plus the Graph request-id as *data*.

    ``cli.py`` (P1) maps ``MicroNotifyError.exit_code`` to the exit code and prints
    ``message``; it knows nothing of Graph. The audit line, though, must carry the
    request-id (§3.3), so the caller needs it as an attribute rather than having
    to re-parse it out of the message. Subclassing keeps ``cli.py`` untouched.
    """

    def __init__(self, message: str, request_id: str | None = None) -> None:
        super().__init__(message)
        self.request_id = request_id


def _retryable(status_code: int) -> bool:
    """Design section 9: retry on 429 and 5xx only — never another 4xx."""
    return status_code == 429 or 500 <= status_code <= 599


def _wait_seconds(response: httpx.Response, attempt: int) -> float:
    """Honour ``Retry-After`` when Graph sends one, else back off exponentially.

    Either way the wait is capped, so a hostile or misconfigured ``Retry-After``
    cannot stall the CLI.
    """
    raw = response.headers.get("retry-after")
    if raw is not None:
        try:
            requested = float(raw.strip())
        except ValueError:
            requested = BASE_BACKOFF_SECONDS
        return min(max(requested, 0.0), RETRY_AFTER_CAP_SECONDS)
    return min(BASE_BACKOFF_SECONDS * (2**attempt), RETRY_AFTER_CAP_SECONDS)


def _failure_detail(response: httpx.Response, request_id: str | None) -> str:
    """Status + Graph request-id (+ a machine-only error code). Never the body."""
    parts = [f"HTTP {response.status_code}"]
    code = ""
    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError):
        body = None
    if isinstance(body, dict):
        candidate = (body.get("error") or {}).get("code") if isinstance(
            body.get("error"), dict
        ) else None
        if isinstance(candidate, str) and _GRAPH_CODE_CHARS.match(candidate):
            code = candidate
    if code:
        parts.append(f"code {code}")
    if request_id:
        parts.append(f"Graph request-id {request_id}")
    return ", ".join(parts)


def _delegated_send(mail: MailConfig) -> tuple[str, str]:
    """The delegated mode's (token, sender) pair — amendment 2026-10-30.

    Two rules, both resolved here rather than in the command so the send path is
    the only place that knows them:

    * the sender is **always** the identity the token names. ``delegation.whoami``
      reads the keychain cache only, so this costs no round trip; if ``[mail]
      sender`` is set and is not that identity, the request is refused as a
      config error (exit 2) — a delegated ``/me/sendMail`` has no sender to put in
      the URL, so Graph would silently send as the signed-in person and the
      operator's config would be a lie. When ``sender`` is unset the token's UPN
      simply is the sender.
    * the token is the delegated one, from :func:`delegation.get_delegated_token`
      (silent refresh, exit 4 plus ``run mnotify login`` when it cannot produce
      one). Never the cert/secret client-credentials token.

    Compared case-insensitively: a UPN's case is not meaningful to Entra, and an
    operator who typed the address in another case has not asked for a different
    mailbox.
    """
    # Function-local import: delegation.py imports this module for the authority
    # template, so a module-level import here would be a cycle. Same shape as
    # doctor's late import of the mail command, and it keeps both seams patchable.
    from . import delegation

    identity = delegation.whoami()
    configured = (mail.sender or "").strip()
    if configured and configured.lower() != identity.upn.lower():
        raise ConfigError(
            f"no send-as-other; remove sender or login as {identity.upn}"
        )
    return delegation.get_delegated_token(), identity.upn


def send_mail(
    *,
    mail: MailConfig,
    payload: dict,
    transport: httpx.BaseTransport | None = None,
) -> SendResult:
    """POST one sendMail request (design section 3.1) with the retry policy of §9.

    ``transport`` is the seam tests use (``httpx.MockTransport``); production
    leaves it None. The token is acquired once — retries reuse it.

    Two modes, one payload builder and one retry policy (amendment 2026-10-30):

    * ``mode = "app"`` (the default): ``POST /users/{sender}/sendMail`` with the
      client-credentials token. Unchanged.
    * ``mode = "delegated"``: ``POST /me/sendMail`` with the signed-in person's
      token. Nothing but the URL, the token source and where the sender comes from
      differs — see :func:`_delegated_send`.
    """
    sender: str | None = None
    if mail.mode == MAIL_MODE_DELEGATED:
        token, sender = _delegated_send(mail)
        url = DELEGATED_SENDMAIL_URL
    else:
        token = acquire_token(mail)
        url = f"{GRAPH_BASE}/users/{quote(mail.sender, safe='')}/sendMail"
    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json; charset=utf-8",
    }
    with httpx.Client(transport=transport, timeout=30.0) as client:
        for attempt in range(MAX_TRIES):
            try:
                response = client.post(url, json=payload, headers=headers)
            except httpx.TransportError as exc:
                # Design §4: an unreachable Graph is a remote error (exit 5), not a
                # crash (exit 1). §9 scopes retries to HTTP statuses, so a
                # transport-level failure fails fast — no request-id exists.
                raise GraphRemoteError(
                    f"Graph sendMail failed (transport error {type(exc).__name__})"
                ) from exc
            request_id = response.headers.get("request-id")
            if response.status_code in SUCCESS_STATUSES:
                return SendResult(
                    status_code=response.status_code,
                    request_id=request_id,
                    sender=sender,
                )
            if not _retryable(response.status_code) or attempt == MAX_TRIES - 1:
                raise GraphRemoteError(
                    f"Graph sendMail failed ({_failure_detail(response, request_id)})",
                    request_id=request_id,
                )
            time.sleep(_wait_seconds(response, attempt))
    raise AssertionError("unreachable: the retry loop always returns or raises")
