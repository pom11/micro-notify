"""Teams Workflows webhook delivery (design §3.2, §3.4, §4, §9).

Pure builders first, then the target/keychain lookup, then the POST with the
design §9 retry policy. A webhook URL is a secret: it lives only in the keychain
account ``teams:<target>``, never in the config, and any message that must refer
to it goes through the audit module's ``mask_url``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from collections.abc import Callable

import httpx

from . import AuthError, RemoteError, UsageError
from .config import Config, TeamTarget
from . import secrets

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
