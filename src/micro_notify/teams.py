"""Teams Workflows webhook delivery (design §3.2, §3.4, §4, §9).

Pure builders first, then the target/keychain lookup, then the POST with the
design §9 retry policy. A webhook URL is a secret: it lives only in the keychain
account ``teams:<target>``, never in the config, and any message that must refer
to it goes through the audit module's ``mask_url``.
"""

from __future__ import annotations

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
