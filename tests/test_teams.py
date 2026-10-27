"""Teams module tests (design §3.2, §4, §9) — build step 4 (P4).

Pure-function tests for the Adaptive Card builder, the two Workflows payload
shapes, target resolution, and the webhook POST with retry. All HTTP goes
through ``httpx.MockTransport`` (design §7): no test here opens a socket, and
the autouse ``no_network`` harness makes that impossible anyway.
"""

from __future__ import annotations

from micro_notify import teams


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
