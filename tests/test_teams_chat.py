"""Teams ``chat`` target kind: delegated-only Graph posting (D3).

Design contract: ``docs/design/2026-10-27-micro-notify-design.md`` sections 3.2/4
plus **Amendment 2026-10-30** (delegated mode). A chat target addresses a
personal 1:1/group conversation by its Teams chat id (``19:...@thread.v2``).
Graph forbids app-only posting into a personal chat, so every chat send must run
on the delegated token (``delegation.get_delegated_token``) and go to
``POST /chats/{chat-id}/messages`` with the adaptive card as a chatMessage
**attachment**.

Why the doc example below is stored as a *string* and parsed, not re-typed as a
Python dict: PR #12's 400 came from a fixture that encoded the same wrong shape
as the code, so a fixture that re-interprets the doc proves nothing. This file
keeps the documented request body byte-for-byte and compares the builder's
structure against the parsed doc object (see test_chat_payload_shape_matches_doc).

Placeholders only. Real Teams chat ids contain ``@`` in an e-mail shape that the
leak guard (tests/test_leak_guard.py EMAIL_RE) would flag as a foreign mailbox,
so the test chat id is assembled at runtime — the same trick the leak guard's
own canaries use — and never appears literally in this tracked file.

HTTP goes through the same ``httpx.MockTransport`` seam as tests/test_teams_cli.py;
the delegated token is replaced at the ``micro_notify.delegation`` attribute the
transport actually calls. No sockets (autouse ``no_network`` harness).
"""

from __future__ import annotations

import json

import httpx
import pytest

from micro_notify import cli
from micro_notify import delegation
from micro_notify.config import (
    KIND_CHAT,
    MAIL_MODE_DELEGATED,
    load_config,
    with_team_target,
    write_config,
)
from micro_notify.graph import GRAPH_BASE
from micro_notify.teams import (
    CHAT_LIST_SELECT,
    build_chat_payload,
    chat_messages_url,
    new_attachment_id,
)

# --- placeholder chat id, assembled so the leak guard's e-mail rule stays clean
CHAT_ID = "19:" + "0" * 16 + "@thread.v2"
CHAT_ID_TAIL = CHAT_ID[-4:]
DOC_CHAT_ID = "19:" + "0" * 32 + "@thread.tacv2"  # the docs' own id shape

FAKE_TOKEN = "fake-" + "token-value"  # inert, and never printed


def chat_id_with(middle: str) -> str:
    return "19:" + middle + "@thread.v2"


# --- the Microsoft Graph documented request body, transcribed verbatim --------
# Source: "Send chatMessage in a channel or a chat" (api-reference/v1.0/api/
# chatmessage-post.md), Example 3 "Send a message containing cards" — the HTTP
# tab's request body. Raw string: backslashes stay exactly as the doc prints
# them; nothing here was re-escaped by hand.
DOC_CHAT_MESSAGE_EXAMPLE = r"""
{
    "subject": null,
    "body": {
        "contentType": "html",
        "content": "<attachment id=\"74d20c7f34aa4a7fb74e2b30004247c5\"></attachment>"
    },
    "attachments": [
        {
            "id": "74d20c7f34aa4a7fb74e2b30004247c5",
            "contentType": "application/vnd.microsoft.card.thumbnail",
            "contentUrl": null,
            "content": "{\r\n  \"title\": \"This is an example of posting a card\",\r\n  \"subtitle\": \"<h3>This is the subtitle</h3>\",\r\n  \"text\": \"Here is some body text. <br>\\r\\nAnd a <a href=\\\"http://microsoft.com/\\\">hyperlink</a>. <br>\\r\\nAnd below that is some buttons:\",\r\n  \"buttons\": [\r\n    {\r\n      \"type\": \"messageBack\",\r\n      \"title\": \"Login to FakeBot\",\r\n      \"text\": \"login\",\r\n      \"displayText\": \"login\",\r\n      \"value\": \"login\"\r\n    }\r\n  ]\r\n}",
            "name": null,
            "thumbnailUrl": null
        }
    ]
}
"""
DOC_ATTACHMENT_ID = "74d20c7f34aa4a7fb74e2b30004247c5"

# The card our builder produces for `--text "deploy finished"` (same card the
# channel-payload pin in tests/test_teams_cli.py uses), so the byte pin below is
# about the *attachment wrapper*, not about card contents.
FIXED_CARD = {
    "type": "AdaptiveCard",
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.4",
    "body": [{"type": "TextBlock", "text": "deploy finished", "wrap": True}],
}


def run(argv: list[str]) -> int:
    return cli.main(argv)


# --- fixtures (same seams as tests/test_teams_cli.py) -------------------------
class Recorded:
    """Requests seen by a MockTransport, answering with canned responses."""

    def __init__(self, responses: list[tuple[int, dict, dict]]) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, headers, body = (
            self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        )
        return httpx.Response(status, headers=headers, json=body)

    @property
    def bodies(self) -> list[dict]:
        return [json.loads(r.content.decode("utf-8")) for r in self.requests]


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch):
    """Install a MockTransport-backed ``httpx.Client``; return a factory."""
    real_client = httpx.Client

    def install(responses: list[tuple[int, dict, dict]]) -> Recorded:
        recorded = Recorded(responses)

        def fake_client(**kwargs):
            kwargs.pop("transport", None)  # the only seam: swap the transport
            return real_client(transport=httpx.MockTransport(recorded.handle), **kwargs)

        monkeypatch.setattr(httpx, "Client", fake_client)
        return recorded

    return install


@pytest.fixture
def delegated(mnotify_config, monkeypatch: pytest.MonkeyPatch):
    """Config switched to ``mode = delegated`` + an inert delegated token.

    The mode goes through the config layer (``load_config`` + ``write_config``),
    never by editing TOML text; the token replaces the function the transport
    actually calls, so no msal and no keychain cache is involved.
    """
    config = load_config(mnotify_config)
    write_config(
        config.__class__(
            mail=config.mail.__class__(
                tenant_id=config.mail.tenant_id,
                client_id=config.mail.client_id,
                sender=config.mail.sender,
                auth=config.mail.auth,
                default_reply_to=config.mail.default_reply_to,
                mode=MAIL_MODE_DELEGATED,
            ),
            allow=config.allow,
            limits=config.limits,
            paths=config.paths,
            teams_targets=config.teams_targets,
            source_path=config.source_path,
        ),
        mnotify_config,
    )
    monkeypatch.setattr(delegation, "get_delegated_token", lambda: FAKE_TOKEN)
    return mnotify_config


def add_chat_target(config_path, alias: str, chat_id: str):
    """Register a chat target through the config layer and return the Config."""
    config = load_config(config_path)
    config = with_team_target(config, alias, KIND_CHAT, chat_id)
    write_config(config, config_path)
    return load_config(config_path)


def chats_payload(count: int = 2) -> dict:
    return {
        "value": [
            {
                "id": chat_id_with(f"chat{index}"),
                "topic": f"Ops thread {index}",
                "chatType": "group" if index % 2 else "person",
                "lastUpdatedDateTime": "2026-10-30T09:00:0" + str(index) + "Z",
            }
            for index in range(1, count + 1)
        ]
    }


# --- mode gating ---------------------------------------------------------------
def test_chat_send_in_app_mode_is_refused_with_login_hint(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    """Default mode is app (D1a); a chat target must never ride app-only creds."""
    add_chat_target(mnotify_config, "oncall", CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1"})])

    code = run(["teams", "send", "oncall", "--text", "hi"])

    err = capsys.readouterr().err
    assert code == 2
    assert "[mail] mode = delegated" in err
    assert "run mnotify login" in err
    assert CHAT_ID not in err  # refusal does not echo the conversation address
    assert recorded.requests == []


def test_chat_dry_run_in_app_mode_is_also_refused(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    """A preview the credentials could never perform is still a refusal."""
    add_chat_target(mnotify_config, "oncall", CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1"})])

    code = run(["teams", "send", "oncall", "--text", "hi", "--dry-run"])

    assert code == 2
    assert "run mnotify login" in capsys.readouterr().err
    assert recorded.requests == []


def test_chats_commands_in_app_mode_are_refused(
    mnotify_config, fake_keychain, mock_http, capsys
) -> None:
    recorded = mock_http([(200, {}, chats_payload())])

    assert run(["teams", "chats", "list"]) == 2
    assert run(["teams", "chats", "add", "oncall", CHAT_ID]) == 2

    err = capsys.readouterr().err
    assert err.count("run mnotify login") == 2
    assert recorded.requests == []
    # Nothing half-registered behind the refusal.
    assert "oncall" not in [t.name for t in load_config(mnotify_config).teams_targets]


# --- only registered aliases are targetable ------------------------------------
def test_chat_send_unknown_alias_is_exit_2_naming_it(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    recorded = mock_http([(201, {}, {"id": "1"})])

    code = run(["teams", "send", "ghost", "--text", "hi"])

    assert code == 2
    assert "ghost" in capsys.readouterr().err
    assert recorded.requests == []


def test_chat_send_needs_no_keychain_account(
    delegated, fake_keychain, mock_http
) -> None:
    """A chat target has no webhook URL: unlike channel/dm it sends with no teams: account."""
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http([(201, {}, {"id": "1"})])

    code = run(["teams", "send", "oncall", "--text", "hi"])

    assert code == 0
    assert "teams:oncall" not in fake_keychain.items


# --- chats list -----------------------------------------------------------------
def test_chats_list_selects_the_documented_fields(delegated, fake_keychain, mock_http) -> None:
    recorded = mock_http([(200, {}, chats_payload())])

    assert run(["teams", "chats", "list"]) == 0

    (request,) = recorded.requests
    assert request.method == "GET"
    assert request.url.path == "/v1.0/me/chats"
    assert request.url.params["$select"] == CHAT_LIST_SELECT
    assert CHAT_LIST_SELECT == "topic,lastUpdatedDateTime,chatType"
    assert request.headers["authorization"] == "Bearer " + FAKE_TOKEN


def test_chats_list_human_output_masks_the_id(delegated, fake_keychain, mock_http, capsys) -> None:
    mock_http([(200, {}, chats_payload(count=1))])

    assert run(["teams", "chats", "list"]) == 0

    out = capsys.readouterr().out
    first_id = chat_id_with("chat1")
    assert "Ops thread 1" in out
    assert "group" in out
    assert first_id not in out  # human output shows the reduced form only
    assert "***" + first_id[-4:] in out


def test_chats_list_json_mode_prints_full_ids(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    """Chat ids are config data, not secrets: --json is the copy-paste surface."""
    mock_http([(200, {}, chats_payload(count=2))])

    assert run(["teams", "chats", "list", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    ids = [entry["id"] for entry in payload["chats"]]
    assert ids == [chat_id_with("chat1"), chat_id_with("chat2")]
    assert payload["chats"][0]["topic"] == "Ops thread 1"
    assert payload["chats"][0]["type"] == "group"


def test_chats_list_empty_is_not_an_error(delegated, fake_keychain, mock_http, capsys) -> None:
    mock_http([(200, {}, {"value": []})])

    assert run(["teams", "chats", "list"]) == 0

    assert "no chats" in capsys.readouterr().out


# --- chats add ------------------------------------------------------------------
def test_chats_add_writes_chat_id_through_the_config_layer(
    delegated, fake_keychain
) -> None:
    assert run(["teams", "chats", "add", "oncall", CHAT_ID]) == 0

    config = load_config(delegated)
    target = config.target("oncall")
    assert target is not None and target.kind == KIND_CHAT
    assert target.chat_id == CHAT_ID  # round-trips verbatim through write+load
    assert 'chat_id = "' + CHAT_ID + '"' in delegated.read_text(encoding="utf-8")
    # No keychain involvement: a chat target has no webhook URL.
    assert fake_keychain.items == {}
    # The display view still masks it (D1a).
    assert config.as_dict()["teams"]["targets"]["oncall"]["chat_id"] == "***" + CHAT_ID_TAIL


def test_chats_add_json_mode_reports_the_alias(delegated, fake_keychain, capsys) -> None:
    assert run(["teams", "chats", "add", "oncall", CHAT_ID, "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "ok"
    assert payload["target"] == "oncall"
    assert payload["kind"] == KIND_CHAT
    assert payload["chat_id"] == CHAT_ID


def test_chats_add_rejects_an_id_that_is_not_a_conversation_id(
    delegated, fake_keychain, capsys
) -> None:
    for bad in ("https://teams.example.com/l/chat", "19:abc@thread", "not-a-chat"):
        code = run(["teams", "chats", "add", "oncall", bad])
        assert code == 2, bad

    assert "conversation id" in capsys.readouterr().err
    assert load_config(delegated).target("oncall") is None  # nothing stored


def test_chats_add_rejects_a_name_that_is_not_a_toml_key(delegated, fake_keychain, capsys) -> None:
    assert run(["teams", "chats", "add", "bad.name", CHAT_ID]) == 2

    assert "bad.name" in capsys.readouterr().err
    assert load_config(delegated).target("bad.name") is None


def test_chats_add_without_id_or_pick_is_a_usage_error(delegated, fake_keychain, capsys) -> None:
    assert run(["teams", "chats", "add", "oncall"]) == 2

    assert "--pick" in capsys.readouterr().err
    assert load_config(delegated).target("oncall") is None


def test_chats_add_pick_stores_the_chosen_chat(
    delegated, fake_keychain, mock_http, monkeypatch, capsys
) -> None:
    mock_http([(200, {}, chats_payload(count=2))])
    monkeypatch.setattr("builtins.input", lambda prompt="": "2")

    assert run(["teams", "chats", "add", "oncall", "--pick"]) == 0

    target = load_config(delegated).target("oncall")
    assert target is not None and target.chat_id == chat_id_with("chat2")
    # The picker listed the choices so the operator could see what they chose.
    out = capsys.readouterr().out
    assert "Ops thread 2" in out
    assert chat_id_with("chat2") in out  # the picker prints the full id for selection


def test_chats_add_pick_rejects_an_out_of_range_number(
    delegated, fake_keychain, mock_http, monkeypatch, capsys
) -> None:
    mock_http([(200, {}, chats_payload(count=2))])
    monkeypatch.setattr("builtins.input", lambda prompt="": "7")

    assert run(["teams", "chats", "add", "oncall", "--pick"]) == 2

    err = capsys.readouterr().err  # read once: capsys drains on read
    assert "1..2" in err
    assert "nothing was stored" in err
    assert load_config(delegated).target("oncall") is None


def test_chats_add_pick_with_no_chats_stores_nothing(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    mock_http([(200, {}, {"value": []})])

    assert run(["teams", "chats", "add", "oncall", "--pick"]) == 2

    assert "no chats" in capsys.readouterr().err
    assert load_config(delegated).target("oncall") is None


# --- the payload, pinned against the Microsoft Graph doc example ----------------
def test_chat_payload_shape_matches_the_doc_example() -> None:
    """Structural identity with the documented chatMessage body (card attachment).

    The doc's own example carries a *thumbnail* card; ours carries the adaptive
    card. Same container, different payload — so the comparison is over the
    skeleton: keys at every level, the value *types*, the attachment content
    type, and the body<->attachment id linkage. If this drifts, Graph 400s —
    which is exactly what PR #12's fixture failed to catch.
    """
    doc = json.loads(DOC_CHAT_MESSAGE_EXAMPLE)
    ours = build_chat_payload(FIXED_CARD, attachment_id=DOC_ATTACHMENT_ID)

    assert sorted(ours) == sorted(doc)  # top-level keys
    assert sorted(ours["body"]) == sorted(doc["body"])
    assert sorted(ours["attachments"][0]) == sorted(doc["attachments"][0])
    assert len(ours["attachments"]) == 1

    # Types: content is a JSON *string* in both; never a nested object.
    assert isinstance(ours["body"]["content"], str)
    assert isinstance(ours["attachments"][0]["content"], str)
    assert ours["attachments"][0]["contentUrl"] is None
    assert ours["attachments"][0]["name"] is None
    assert ours["attachments"][0]["thumbnailUrl"] is None

    # Values the doc fixes: contentType html; the id is referenced by the body.
    assert ours["body"]["contentType"] == doc["body"]["contentType"] == "html"
    assert (
        ours["body"]["content"]
        == '<attachment id="' + DOC_ATTACHMENT_ID + '"></attachment>'
    )
    assert ours["attachments"][0]["id"] == doc["attachments"][0]["id"]

    # The doc's content string really is JSON of a card-shaped object — proof
    # the stringified-content rule is about real nesting, not escaping trivia.
    assert json.loads(ours["attachments"][0]["content"]) == FIXED_CARD
    assert json.loads(doc["attachments"][0]["content"])["title"] == (
        "This is an example of posting a card"
    )


def test_chat_payload_is_byte_pinned_against_the_doc_shape() -> None:
    """Every key in the exact documented order, and content == json.dumps(card)."""
    ours = build_chat_payload(FIXED_CARD, attachment_id=DOC_ATTACHMENT_ID)

    assert list(ours) == ["subject", "body", "attachments"]
    assert ours["subject"] is None
    assert list(ours["body"]) == ["contentType", "content"]
    assert list(ours["attachments"][0]) == [
        "id",
        "contentType",
        "contentUrl",
        "content",
        "name",
        "thumbnailUrl",
    ]
    assert ours["attachments"][0]["contentType"] == (
        "application/vnd.microsoft.card.adaptive"
    )
    assert ours["attachments"][0]["content"] == json.dumps(FIXED_CARD)


def test_attachment_ids_are_unique_and_always_match_the_body_reference() -> None:
    """The docs require one id used identically in body and attachments; two
    sends must not collide, so the id is generated per payload, never hardcoded."""
    first = build_chat_payload(FIXED_CARD, attachment_id=new_attachment_id())
    second = build_chat_payload(FIXED_CARD, attachment_id=new_attachment_id())

    id_a = first["attachments"][0]["id"]
    id_b = second["attachments"][0]["id"]
    assert id_a != id_b
    assert len(id_a) == 32 and all(c in "0123456789abcdef" for c in id_a)
    for payload in (first, second):
        used = payload["attachments"][0]["id"]
        assert payload["body"]["content"] == '<attachment id="' + used + '"></attachment>'


def test_chat_messages_url_encodes_the_id_as_graph_shows() -> None:
    """Graph samples show %3A/%40 in conversation ids inside @odata.context."""
    assert chat_messages_url(DOC_CHAT_ID) == (
        GRAPH_BASE
        + "/chats/19%3A"
        + "0" * 32
        + "%40thread.tacv2/messages"
    )


def test_send_posts_the_pinned_payload_to_the_encoded_chat_url(
    delegated, fake_keychain, mock_http
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1", "messageType": "message"})])

    code = run(["teams", "send", "oncall", "--text", "deploy finished"])

    assert code == 0
    (request,) = recorded.requests
    assert request.method == "POST"
    # .path is percent-*decoded* by httpx; the encoded wire form is on the URL
    # itself — assert the thing Graph actually receives.
    assert str(request.url).endswith(
        "/v1.0/chats/19%3A" + "0" * 16 + "%40thread.v2/messages"
    )
    assert request.headers["content-type"].startswith("application/json")
    body = recorded.bodies[0]
    assert list(body) == ["subject", "body", "attachments"]
    assert body["body"]["contentType"] == "html"
    assert (
        body["body"]["content"]
        == '<attachment id="' + body["attachments"][0]["id"] + '"></attachment>'
    )
    attachment = body["attachments"][0]
    assert sorted(attachment) == sorted(
        json.loads(DOC_CHAT_MESSAGE_EXAMPLE)["attachments"][0]
    )
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert json.loads(attachment["content"]) == FIXED_CARD


def test_chat_send_accepts_the_thread_tacv2_id_shape(delegated, fake_keychain, mock_http) -> None:
    """The docs' samples use @thread.tacv2 ids; validate_chat_id must accept both."""
    add_chat_target(delegated, "chan", DOC_CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "chan", "--text", "hi"]) == 0

    assert len(recorded.requests) == 1


# --- guard / audit / outcomes ----------------------------------------------------
def test_chat_send_audits_alias_as_recipient_and_no_bodies(
    delegated, fake_keychain, mock_http, read_json_lines
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "oncall", "--text", "deploy finished"]) == 0

    config = load_config(delegated)
    (entry,) = read_json_lines(config.paths.audit)
    assert entry["channel"] == "teams"
    assert entry["outcome"] == "sent"
    assert entry["target"] == "oncall"
    assert entry["recipients"] == ["oncall"]  # the alias — not a conversation address
    assert CHAT_ID not in json.dumps(entry)
    assert FAKE_TOKEN not in json.dumps(entry)
    assert "deploy finished" not in json.dumps(entry)  # body is digest-only
    from micro_notify.audit import body_digest

    sha, size = body_digest("deploy finished")
    assert entry["body_sha256"] == sha and entry["body_size"] == size
    counter = json.loads(config.paths.counter_file.read_text(encoding="utf-8"))
    assert counter["count"] == 1


def test_chat_send_counts_once_and_reuses_the_counter(
    delegated, fake_keychain, mock_http
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http([(201, {}, {"id": "1"})])

    run(["teams", "send", "oncall", "--text", "one"])
    run(["teams", "send", "oncall", "--text", "two"])

    config = load_config(delegated)
    counter = json.loads(config.paths.counter_file.read_text(encoding="utf-8"))
    assert counter["count"] == 2


def test_chat_send_daily_cap_is_exit_6_with_zero_http(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    from micro_notify import guard

    add_chat_target(delegated, "oncall", CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1"})])
    config = load_config(delegated)
    config.paths.counter_file.parent.mkdir(parents=True, exist_ok=True)
    config.paths.counter_file.write_text(
        json.dumps({"date": guard.utc_today(), "count": config.limits.daily_max}),
        encoding="utf-8",
    )

    code = run(["teams", "send", "oncall", "--text", "hi"])

    assert code == 6
    assert recorded.requests == []
    assert "daily" in capsys.readouterr().err
    (entry,) = read_audit(load_config(delegated))
    assert entry["outcome"] == "refused"


def read_audit(config):
    path = config.paths.audit
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_chat_send_non_2xx_is_exit_5_audited_failed_and_spares_the_budget(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http(
        [
            (
                400,
                {"request-id": "req-1"},
                {"error": {"code": "invalidRequest", "message": "card body echo " + "deploy finished"}},
            )
        ]
    )

    code = run(["teams", "send", "oncall", "--text", "deploy finished"])

    err = capsys.readouterr().err
    assert code == 5
    assert "invalidRequest" in err  # machine code is safe to surface
    assert "card body echo" not in err  # the body echo is NOT
    assert "req-1" in err
    assert not load_config(delegated).paths.counter_file.exists()
    (entry,) = read_audit(load_config(delegated))
    assert entry["outcome"] == "failed"


def test_chat_send_retries_429_and_honours_retry_after(
    delegated, fake_keychain, mock_http, monkeypatch
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    recorded = mock_http([(429, {"Retry-After": "5"}, {"error": {}}), (201, {}, {"id": "1"})])
    delays: list[float] = []
    monkeypatch.setattr("micro_notify.teams.time.sleep", delays.append)

    assert run(["teams", "send", "oncall", "--text", "hi"]) == 0

    assert len(recorded.requests) == 2
    assert delays == [5.0]


def test_chat_dry_run_masks_id_and_audits_dry_run(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "oncall", "--text", "hi", "--dry-run"]) == 0

    out = capsys.readouterr().out
    assert recorded.requests == []
    assert CHAT_ID not in out
    assert "***" + CHAT_ID_TAIL in out
    assert "attachment id" in out  # the exact payload is still previewed
    (entry,) = read_audit(load_config(delegated))
    assert entry["outcome"] == "dry_run"
    assert not load_config(delegated).paths.counter_file.exists()


def test_chat_send_human_output_never_prints_token_or_full_id(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "oncall", "--text", "hi"]) == 0

    surfaces = capsys.readouterr()
    assert FAKE_TOKEN not in surfaces.out + surfaces.err
    assert FAKE_TOKEN not in str(fake_keychain.items)
    assert CHAT_ID not in surfaces.out + surfaces.err
    assert "***" + CHAT_ID_TAIL in surfaces.out


def test_chat_send_rejects_to_flag(delegated, fake_keychain, mock_http, capsys) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "oncall", "--to", "person@contoso.com", "--text", "hi"]) == 2

    assert "--to" in capsys.readouterr().err


def test_chat_send_json_mode_reports_sent_with_alias_recipient(
    delegated, fake_keychain, mock_http, capsys
) -> None:
    add_chat_target(delegated, "oncall", CHAT_ID)
    mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "oncall", "--text", "hi", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["outcome"] == "sent"
    assert payload["target"] == "oncall"
    assert payload["recipients"] == ["oncall"]
    assert payload["status"] == 201
    assert CHAT_ID not in json.dumps(payload)


def test_chat_card_file_is_posted_verbatim_as_attachment(
    delegated, fake_keychain, mock_http, tmp_path
) -> None:
    card = {"type": "AdaptiveCard", "version": "1.4", "body": [], "custom": {"keep": True}}
    path = tmp_path / "card.json"
    path.write_text(json.dumps(card), encoding="utf-8")
    add_chat_target(delegated, "oncall", CHAT_ID)
    recorded = mock_http([(201, {}, {"id": "1"})])

    assert run(["teams", "send", "oncall", "--card-file", str(path)]) == 0

    body = recorded.bodies[0]
    assert json.loads(body["attachments"][0]["content"]) == card


def test_channel_and_dm_targets_stay_on_the_webhook_path(
    mnotify_config, fake_keychain, mock_http
) -> None:
    """Regression: adding chat must not reroute the Workflows kinds (design §3.2)."""
    url = "https://" + "example.com/hidden-canary-sig"
    fake_keychain.seed("teams:alerts", url)
    recorded = mock_http([(202, {}, {})])

    assert run(["teams", "send", "alerts", "--text", "hi"]) == 0

    (request,) = recorded.requests
    assert request.url.host == "example.com"  # the webhook host, not graph
    assert recorded.bodies[0]["type"] == "message"  # workflow template, not chatMessage
    assert "authorization" not in request.headers  # webhook path sends no bearer
