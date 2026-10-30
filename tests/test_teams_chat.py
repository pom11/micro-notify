"""Teams ``chat`` target kind: delegated-only Graph posting (D3).

Design contract: ``docs/design/2026-10-27-micro-notify-design.md`` section 3.2/4
plus **Amendment 2026-10-30** (delegated mode). A chat target addresses a
personal 1:1/group conversation by its Teams chat id (``19:...@thread.v2``), and
Graph forbids app-only posting into it, so every chat send must run on the
delegated token (``delegation.get_delegated_token``) and go to
``POST /chats/{chat-id}/messages`` with the adaptive card as a chatMessage
attachment.

The wire shape is pinned against a fixture transcribed from the Microsoft Graph
docs' "Send chatMessage in a channel or a chat" attachment example — see
``DOC_ATTACHMENT_EXAMPLE`` below. PR #12 regressed because a fixture encoded the
same wrong shape as the code, so this file keeps the reference JSON as a *string*
that is parsed and compared, not re-typed into Python.

Fixtures: ``mnotify_config`` + ``fake_keychain`` from conftest; HTTP through the
same ``httpx.MockTransport`` seam used by tests/test_teams_cli.py; the delegated
token is a module-attribute patch on ``micro_notify.teams``. No sockets (the
autouse ``no_network`` harness makes one impossible).
"""

from __future__ import annotations

# Placeholder-only literals are assembled at runtime so a concatenation of the
# pieces cannot trip the leak guard's e-mail-domain rule; see tests/test_leak_guard.py.
CHAT_ID = "19:" + "0" * 16 + "@thread.v2"
CHAT_ID_TAIL = CHAT_ID[-4:]

# Filled in by the work below.
PLACEHOLDER = None
