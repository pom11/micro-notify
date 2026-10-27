"""Teams module tests (design §3.2, §4, §9) — build step 4 (P4).

Pure-function tests for the Adaptive Card builder, the two Workflows payload
shapes, target resolution, and the webhook POST with retry. All HTTP goes
through ``httpx.MockTransport`` (design §7): no test here opens a socket, and
the autouse ``no_network`` harness makes that impossible anyway.
"""

from __future__ import annotations

import pytest

from micro_notify import teams

# A webhook-URL-shaped secret for leak assertions. example.com keeps the leak
# guard (design §5) happy while still being a URL-shaped canary.
CANARY_URL = "https://" + "example.com/hidden-canary-sig"


def test_build_card_text_only_is_adaptive_card_14() -> None:
    card = teams.build_card(text="deploy finished")

    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.4"
    assert card["body"] == [
        {"type": "TextBlock", "text": "deploy finished", "wrap": True}
    ]
    assert "actions" not in card


def test_build_card_title_renders_as_heading_before_text() -> None:
    card = teams.build_card(text="body text", title="Build failed")

    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["body"][0] == {
        "type": "TextBlock",
        "text": "Build failed",
        "wrap": True,
        "size": "Medium",
        "weight": "Bolder",
    }
    assert card["body"][1] == {"type": "TextBlock", "text": "body text", "wrap": True}


def test_build_card_facts_render_as_a_factset_of_key_value_pairs() -> None:
    card = teams.build_card(
        text="deploy finished",
        facts=[("service", "api"), ("duration", "42s")],
    )

    assert card["body"][1] == {
        "type": "FactSet",
        "facts": [
            {"title": "service", "value": "api"},
            {"title": "duration", "value": "42s"},
        ],
    }


def test_build_card_without_facts_has_no_factset() -> None:
    card = teams.build_card(text="plain")

    assert [el["type"] for el in card["body"]] == ["TextBlock"]


def test_build_card_link_adds_exactly_one_openuri_action() -> None:
    card = teams.build_card(text="see run", link="https://example.com/run/9", link_title="Open run")

    assert card["actions"] == [
        {
            "type": "Action.OpenUri",
            "title": "Open run",
            "url": "https://example.com/run/9",
        }
    ]


def test_build_card_link_without_title_defaults_label_to_open() -> None:
    card = teams.build_card(text="see run", link="https://example.com/run/9")

    assert card["actions"] == [
        {"type": "Action.OpenUri", "title": "Open", "url": "https://example.com/run/9"}
    ]


def test_build_card_without_link_has_no_actions() -> None:
    card = teams.build_card(text="no link")

    assert "actions" not in card


# --- Payload shapes: design §3.2 verbatim ------------------------------------
def _tiny_card() -> dict:
    return {"type": "AdaptiveCard", "version": "1.4", "body": []}


def test_build_channel_payload_matches_design_section_3_2() -> None:
    card = _tiny_card()

    assert teams.build_channel_payload(card) == {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }
        ],
    }


def test_build_dm_payload_matches_design_section_3_2() -> None:
    card = _tiny_card()

    assert teams.build_dm_payload("person@contoso.com", card) == {
        "recipient": "person@contoso.com",
        "attachments": [card],
    }


# --- Target resolution + keychain lookup (config + secrets seams only) ------
def test_resolve_target_returns_configured_target(mnotify_config) -> None:
    from micro_notify.config import load_config

    config = load_config(mnotify_config)

    target = teams.resolve_target(config, "alerts")

    assert target.kind == "channel"


def test_resolve_target_unknown_raises_usage_error_naming_the_target(mnotify_config) -> None:
    from micro_notify import UsageError
    from micro_notify.config import load_config

    config = load_config(mnotify_config)

    with pytest.raises(UsageError) as excinfo:
        teams.resolve_target(config, "nope")

    assert "nope" in excinfo.value.message


def test_webhook_url_reads_keychain_account_teams_target(fake_keychain) -> None:
    fake_keychain.seed("teams:alerts", CANARY_URL)

    assert teams.webhook_url("alerts") == CANARY_URL


def test_webhook_url_missing_raises_auth_error_naming_the_account(fake_keychain) -> None:
    from micro_notify import AuthError

    with pytest.raises(AuthError) as excinfo:
        teams.webhook_url("alerts")

    assert "teams:alerts" in excinfo.value.message


def test_webhook_url_message_never_contains_the_url(fake_keychain) -> None:
    """The whole point of the keychain: an absence message must not leak a URL."""
    from micro_notify import AuthError

    fake_keychain.seed("teams:other", CANARY_URL)

    with pytest.raises(AuthError) as excinfo:
        teams.webhook_url("alerts")

    assert CANARY_URL not in excinfo.value.message
