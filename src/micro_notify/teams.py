"""Teams Workflows webhook delivery (design §3.2, §3.4, §4, §9).

Pure builders first, then the target/keychain lookup, then the POST with the
design §9 retry policy. A webhook URL is a secret: it lives only in the keychain
account ``teams:<target>``, never in the config, and any message that must refer
to it goes through the audit module's ``mask_url``.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import quote

import httpx

from . import AuthError, RemoteError, UsageError
from .config import Config, TeamTarget
from . import secrets
from . import delegation
from .graph import GRAPH_BASE, GraphRemoteError

ADAPTIVE_CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"
ADAPTIVE_CARD_SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"


def build_card(
    *,
    text: str,
    title: str | None = None,
    facts: list[tuple[str, str]] | None = None,
    link: str | None = None,
    link_title: str | None = None,
) -> dict:
    """Adaptive Card 1.4 with the markdown body (design §3.2).

    At most one action button: an ``Action.OpenUri`` when ``link`` is given.
    """
    body: list[dict] = []
    if title:
        body.append(
            {
                "type": "TextBlock",
                "text": title,
                "wrap": True,
                "size": "Medium",
                "weight": "Bolder",
            }
        )
    body.append({"type": "TextBlock", "text": text, "wrap": True})
    if facts:
        body.append(
            {
                "type": "FactSet",
                "facts": [{"title": k, "value": v} for k, v in facts],
            }
        )
    card: dict = {
        "type": "AdaptiveCard",
        "$schema": ADAPTIVE_CARD_SCHEMA,
        "version": "1.4",
        "body": body,
    }
    if link:
        card["actions"] = [
            {"type": "Action.OpenUri", "title": link_title or "Open", "url": link}
        ]
    return card


def parse_facts(raw: list[str] | None) -> list[tuple[str, str]]:
    """Parse repeatable ``--fact k=v`` values; first ``=`` splits key and value."""
    if not raw:
        return []
    facts: list[tuple[str, str]] = []
    for item in raw:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise UsageError(f"--fact must be key=value, got '{item}'")
        facts.append((key.strip(), value))
    return facts


def load_card_file(path: str) -> dict:
    """Read a full Adaptive Card JSON file verbatim (``--card-file``, design §3.2)."""
    from pathlib import Path

    file = Path(path).expanduser()
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise UsageError(f"--card-file: cannot read {file} (FileNotFoundError)") from exc
    except OSError as exc:
        raise UsageError(f"--card-file: cannot read {file} ({type(exc).__name__})") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"--card-file: {file} is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("type") != "AdaptiveCard" or "version" not in data:
        raise UsageError(f"--card-file: {file} is not an Adaptive Card (needs type + version)")
    return data


def build_channel_payload(card: dict) -> dict:
    """Workflow "post to a channel" template body (design §3.2)."""
    return {
        "type": "message",
        "attachments": [
            {"contentType": ADAPTIVE_CARD_CONTENT_TYPE, "content": card}
        ],
    }


def build_dm_payload(upn: str, card: dict) -> dict:
    """Single DM workflow body: Flow bot posts to ``triggerBody()?['recipient']``."""
    return {"recipient": upn, "attachments": [card]}


# --- chat targets (delegated Graph; design amendment 2026-10-30) --------------
# A chat target has no webhook URL: the conversation address (``19:...@thread.v2``)
# is config data and the credential is the delegated token, so app-only credentials
# must never reach a chat send. Graph answers ``POST /chats/{id}/messages`` with
# 201 Created (not 200/202 like a Workflows webhook).

# Teams conversation ids: ``19:<id>@thread.v2`` for chats, ``...@thread.tacv2``
# for channel ids (the documented samples use both). ``chats add`` rejects
# anything else — an operator pasting a URL or a card id fails at add time
# rather than at send time, which is the same reasoning behind the ``https://``
# check on webhook URLs in ``teams targets add``.
CHAT_ID_RE = re.compile(r"^19:[^\s@]+@thread\.(?:v2|tacv2)$")


def validate_chat_id(chat_id: str, *, where: str = "chat id") -> str:
    """Strip and shape-check a Teams conversation id; ``UsageError`` (exit 2) otherwise."""
    value = (chat_id or "").strip()
    if not CHAT_ID_RE.match(value):
        raise UsageError(
            f"{where} '{value}' does not look like a Teams conversation id "
            "(expected 19:<id>@thread.v2 — find it with `mnotify teams chats list`)"
        )
    return value


def require_delegated_mode(config: Config, *, action: str = "chat targets") -> None:
    """Refuse a Graph chat operation while ``[mail] mode`` is app (exit 2).

    Graph forbids app-only posting into a personal chat, so an app-mode config
    cannot serve this operation at all; naming the remedy (``mnotify login``)
    beats letting msal fail with an opaque AADSTS error later.
    """
    from .config import MAIL_MODE_DELEGATED

    if config.mail.mode != MAIL_MODE_DELEGATED:
        raise UsageError(
            f"{action} need [mail] mode = delegated; run mnotify login"
        )


def build_chat_payload(card: dict, *, attachment_id: str) -> dict:
    """Graph ``chatMessage`` body carrying the adaptive card as an ATTACHMENT.

    Shape is the Microsoft Graph documented example for
    ``POST /chats/{chat-id}/messages`` (chatmessage-post, "Send a message
    containing cards"), reproduced by ``DOC_CHAT_MESSAGE_EXAMPLE`` in
    tests/test_teams_chat.py and pinned byte-for-byte there. Three details are
    load-bearing and each is exactly what a re-typed fixture gets wrong:

    * ``content`` is a **JSON string**, not a nested object — Graph's
      ``chatMessageAttachment.content`` is a string field;
    * ``body.content`` is an ``<attachment id="..."></attachment>`` reference
      whose id **equals** ``attachments[0].id`` (the docs call this out);
    * ``body.contentType`` is ``html``, and the optional attachment fields
      (``contentUrl``/``name``/``thumbnailUrl``) are present and ``null``.
    """
    return {
        "subject": None,
        "body": {
            "contentType": "html",
            "content": f'<attachment id="{attachment_id}"></attachment>',
        },
        "attachments": [
            {
                "id": attachment_id,
                "contentType": ADAPTIVE_CARD_CONTENT_TYPE,
                "contentUrl": None,
                "content": json.dumps(card),
                "name": None,
                "thumbnailUrl": None,
            }
        ],
    }


def new_attachment_id() -> str:
    """A fresh attachment id (32 hex chars, as in the documented example)."""
    return uuid.uuid4().hex


def chat_messages_url(chat_id: str) -> str:
    """``POST /chats/{chat-id}/messages`` for the v1.0 base.

    The chat id is percent-encoded (``:`` -> ``%3A``, ``@`` -> ``%40``) exactly
    as Graph's own samples show it in ``@odata.context``; ``quote`` leaves the
    rest of the id alone.
    """
    return f"{GRAPH_BASE}/chats/{quote(chat_id, safe='')}/messages"


# --- Target resolution + webhook URL lookup ----------------------------------
def resolve_target(config: Config, name: str) -> TeamTarget:
    """The ``[teams.targets.<name>]`` entry, or a usage error naming it (exit 2)."""
    target = config.target(name)
    if target is None:
        raise UsageError(
            f"unknown teams target '{name}' (configured: "
            f"{', '.join(t.name for t in config.teams_targets) or 'none'}; "
            "add one with `mnotify teams targets add`)"
        )
    return target


def webhook_url(target_name: str) -> str:
    """The Workflows webhook URL for ``target_name`` from the keychain.

    Exit 4 when the account is absent; the message names the account, never a
    URL (design §3.2 — the URL is a secret).
    """
    account = secrets.teams_account(target_name)
    try:
        return secrets.get(account)
    except secrets.KeychainError as exc:
        raise AuthError(
            f"no webhook URL stored for teams target '{target_name}': keychain "
            f"account '{account}' is missing (set it with "
            f"`mnotify teams targets add {target_name} --kind <kind>`)"
        ) from exc


# --- POST with design §9 retry ------------------------------------------------
WEBHOOK_TIMEOUT = 15.0
MAX_TRIES = 3
_ERROR_BODY_LIMIT = 500


@dataclass(frozen=True)
class PostResult:
    status: int
    text: str


def _retry_delay(response: httpx.Response, tries: int) -> float:
    """Seconds to wait: honour Retry-After on 429, else linear backoff."""
    if response.status_code == 429:
        header = response.headers.get("Retry-After", "")
        try:
            return max(0.0, float(header))
        except ValueError:
            return float(tries)
    return float(tries)


def _truncate(text: str) -> str:
    if len(text) <= _ERROR_BODY_LIMIT:
        return text
    return text[:_ERROR_BODY_LIMIT] + "..."


def post_card(
    url: str,
    payload: dict,
    *,
    url_label: str,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] | None = None,
    timeout: float = WEBHOOK_TIMEOUT,
) -> PostResult:
    """POST the Workflows payload; retry 429/5xx per design §9 (max 3 tries).

    ``url_label`` is the masked form (``audit.mask_url(url)``) used in every
    message; the raw URL never appears in an error or log line. Non-2xx raises
    :class:`RemoteError` (exit 5) with status + truncated response text.

    ``sleep`` is the backoff clock, resolved when the call runs rather than
    bound as a default argument: a default of ``time.sleep`` would capture the
    function at import time and keep the real one even after a test patches
    ``time.sleep``, i.e. a suite that silently sleeps for real.
    """
    wait = sleep if sleep is not None else time.sleep
    tries = 0
    last: httpx.Response | None = None
    with httpx.Client(transport=transport, timeout=timeout) as client:
        while True:
            tries += 1
            try:
                response = client.post(url, json=payload)
            except httpx.HTTPError as exc:
                raise RemoteError(
                    f"teams webhook {url_label} unreachable: {type(exc).__name__}"
                ) from exc
            if 200 <= response.status_code < 300:
                return PostResult(response.status_code, response.text)
            last = response
            if not (response.status_code == 429 or response.status_code >= 500):
                break
            if tries >= MAX_TRIES:
                break
            wait(_retry_delay(response, tries))
    assert last is not None
    raise RemoteError(
        f"teams webhook {url_label} returned HTTP {last.status_code}: "
        f"{_truncate(last.text)}"
    )


# --- chat POST + chat list over Graph (delegated; amendment 2026-10-30) ------
# Graph's error policy differs from the webhook policy above: a Graph error body
# can echo message content, so only the status, the machine error code and the
# request-id travel (same stance as graph._failure_detail — re-implemented here
# rather than importing a private helper across modules).
_GRAPH_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,63}$")
_CHAT_SEND_TIMEOUT = 30.0


def _graph_failure_detail(response: httpx.Response) -> str:
    parts = [f"HTTP {response.status_code}"]
    code = ""
    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError):
        body = None
    if isinstance(body, dict):
        error = body.get("error")
        candidate = error.get("code") if isinstance(error, dict) else None
        if isinstance(candidate, str) and _GRAPH_CODE_RE.match(candidate):
            code = candidate
    if code:
        parts.append(f"code {code}")
    request_id = response.headers.get("request-id")
    if request_id:
        parts.append(f"Graph request-id {request_id}")
    return ", ".join(parts)


def _delegated_headers() -> dict:
    """Bearer headers for the delegated identity (never prints the token)."""
    token = delegation.get_delegated_token()
    return {
        "authorization": f"Bearer {token}",
        "content-type": "application/json; charset=utf-8",
    }


def post_chat_message(
    *,
    config: Config,
    chat_id: str,
    payload: dict,
    transport: httpx.BaseTransport | None = None,
    timeout: float = _CHAT_SEND_TIMEOUT,
    sleep: Callable[[float], None] | None = None,
) -> PostResult:
    """POST one chatMessage to ``/chats/{chat-id}/messages`` (amendment A.5).

    Enforces the delegated-mode gate again here — the command checks it too, but
    a caller that skips the CLI must not be able to talk to a personal chat with
    app-only credentials. The token is acquired only after the gate, so an
    app-mode config never even reads the keychain. 201 is success; 429/5xx
    retry per design §9 like every other send; other 4xx fail fast. Error text
    carries the masked chat id, never the response body.
    """
    from .config import mask_chat_id

    require_delegated_mode(config)
    headers = _delegated_headers()
    url = chat_messages_url(chat_id)
    label = mask_chat_id(chat_id)
    wait = sleep if sleep is not None else time.sleep
    tries = 0
    last: httpx.Response | None = None
    with httpx.Client(transport=transport, timeout=timeout) as client:
        while True:
            tries += 1
            try:
                response = client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                raise GraphRemoteError(
                    f"Graph chat message for {label} unreachable: "
                    f"{type(exc).__name__}"
                ) from exc
            if response.status_code == 201:
                return PostResult(response.status_code, response.text)
            last = response
            if not (response.status_code == 429 or response.status_code >= 500):
                break
            if tries >= MAX_TRIES:
                break
            wait(_retry_delay(response, tries))
    assert last is not None
    raise GraphRemoteError(
        f"Graph chat message for {label} failed ({_graph_failure_detail(last)})",
        request_id=last.headers.get("request-id"),
    )


# GET /me/chats selects exactly the fields `teams chats list` prints.
CHAT_LIST_SELECT = "topic,lastModifiedDateTime,chatType"


def get_my_chats(
    *,
    config: Config,
    transport: httpx.BaseTransport | None = None,
    timeout: float = _CHAT_SEND_TIMEOUT,
) -> list[dict]:
    """The signed-in person's chats via ``GET /me/chats`` (Chat.ReadBasic).

    Same delegated gate as the send: listing chats with app-only credentials is
    not a thing Graph offers, so the answer is the login hint, not an empty list.
    Returns the ``value`` entries (id/topic/chatType/lastModifiedDateTime); a
    missing or non-list ``value`` is treated as an empty collection, never a
    crash.
    """
    require_delegated_mode(config)
    headers = _delegated_headers()
    url = f"{GRAPH_BASE}/me/chats"
    with httpx.Client(transport=transport, timeout=timeout) as client:
        try:
            response = client.get(url, params={"$select": CHAT_LIST_SELECT}, headers=headers)
        except httpx.HTTPError as exc:
            raise GraphRemoteError(
                f"Graph chat list unreachable: {type(exc).__name__}"
            ) from exc
    if not 200 <= response.status_code < 300:
        raise GraphRemoteError(
            f"Graph chat list failed ({_graph_failure_detail(response)})",
            request_id=response.headers.get("request-id"),
        )
    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError) as exc:
        raise RemoteError("Graph chat list returned an unreadable body") from exc
    value = body.get("value") if isinstance(body, dict) else None
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
