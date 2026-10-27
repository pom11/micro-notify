"""Teams Workflows webhook delivery (design §3.2, §3.4, §4, §9).

Pure builders first, then the target/keychain lookup, then the POST with the
design §9 retry policy. A webhook URL is a secret: it lives only in the keychain
account ``teams:<target>``, never in the config, and any message that must refer
to it goes through the audit module's ``mask_url``.
"""

from __future__ import annotations

from . import AuthError, UsageError
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
