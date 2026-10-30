"""``mnotify mail send`` (design sections 3.1, 3.3, 4, 9) — end-to-end CLI.

The assertions here are about the *order of operations* the card fixes —
config -> guard -> (dry-run stop) -> token -> POST -> audit — and about what
lands on stdout/stderr and in the audit line. Nothing opens a socket:

* HTTP: ``mail_transport`` swaps an ``httpx.MockTransport`` in where
  ``graph.send_mail`` builds its httpx client, so every request is recorded and
  every response scripted.
* msal: ``ConfidentialClientApplication`` is patched at the attribute graph.py
  reaches for; ordering tests replace it with a tripwire that fails if a token
  is even attempted.
* keychain: the shared ``fake_keychain`` fixture — no /usr/bin/security run.
* clock: ``graph.time.sleep`` is recorded, never slept.

Foreign (non-placeholder) addresses are assembled at runtime, as in
tests/test_guard.py, so this tracked file carries no non-placeholder address.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest

from micro_notify import (
    EXIT_AUTH,
    EXIT_DAILY_CAP,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
    cli,
    guard,
    graph,
)
from micro_notify import secrets as secrets_module

from conftest import PLACEHOLDER_REPLY_TO, placeholder_config

REQUEST_ID = "req-00000000-0000-0000-0000-000000000000"
BODY_CANARY = "BODY-CANARY-42 the pipeline is red"
CANARY_PEM_BODY = "FAKEPEMBODYSUPERSECRETNOTAREALKEY"

SEND = ["mail", "send", "--to", "someone@example.com", "--subject", "hi", "--body"]


def foreign(local: str, *labels: str) -> str:
    """A recipient outside the placeholder domains, assembled at runtime."""
    return local + "@" + ".".join(labels) + "." + "net"


def argv(*extra: str) -> list[str]:
    """``mnotify mail send`` with a body carrying the canary, plus extra flags."""
    return SEND + [BODY_CANARY] + list(extra)


def seed_cert(keychain) -> None:
    """Cert-mode credentials in the fake keychain (placeholder-shaped values)."""
    keychain.seed(secrets_module.ACCOUNT_CERT_PEM, CANARY_PEM_BODY)
    keychain.seed(secrets_module.ACCOUNT_CERT_THUMBPRINT, "AABBCC")


def addresses(recipients: list[dict]) -> list[str]:
    return [r["emailAddress"]["address"] for r in recipients]


# --- Scriptable transport ---------------------------------------------------
class TransportHarness:
    """httpx.MockTransport scripted with canned responses + a full request log."""

    def __init__(self, *responses: httpx.Response | Exception) -> None:
        self.remaining = list(responses) or [
            httpx.Response(202, headers={"request-id": REQUEST_ID})
        ]
        self.requested: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requested.append(request)
        item = self.remaining.pop(0) if len(self.remaining) > 1 else self.remaining[0]
        if isinstance(item, Exception):
            raise item
        return item

    @property
    def calls(self) -> int:
        return len(self.requested)

    @property
    def payload(self) -> dict:
        """The JSON body of the last POST — exactly what Graph was sent."""
        return json.loads(self.requested[-1].content)


@pytest.fixture
def mail_transport(monkeypatch: pytest.MonkeyPatch):
    """Put a MockTransport where ``graph.send_mail`` opens its httpx client.

    Production never passes a transport, so this is the seam: patch the client
    factory, never the caller.
    """

    def install(*responses: httpx.Response | Exception) -> TransportHarness:
        harness = TransportHarness(*responses)
        real_client = httpx.Client

        def fake_client(**kwargs):
            kwargs["transport"] = httpx.MockTransport(harness.handler)
            return real_client(**kwargs)

        monkeypatch.setattr(graph.httpx, "Client", fake_client)
        return harness

    return install


# --- msal -------------------------------------------------------------------
class MsalStub:
    """Script + record for msal.ConfidentialClientApplication (same shape as
    tests/test_graph.py's stub, so both files read alike)."""

    def __init__(self) -> None:
        self.silent_result: dict | None = {"access_token": "***"}
        self.client_result: dict | None = None
        self.apps: list[dict] = []
        self.token_calls: list[str] = []

    def make_app(self, **kwargs):
        self.apps.append(kwargs)
        outer = self

        class _App:
            def acquire_token_silent(self, *_args, **_kwargs):
                outer.token_calls.append("silent")
                return outer.silent_result

            def acquire_token_for_client(self, *_args, **_kwargs):
                outer.token_calls.append("client")
                return outer.client_result

        return _App()


@pytest.fixture
def msal_stub(monkeypatch: pytest.MonkeyPatch) -> MsalStub:
    stub = MsalStub()
    monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", stub.make_app)
    return stub


@pytest.fixture
def msal_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to build an msal client fails the test (design §4 --dry-run)."""

    def boom(**_kwargs):
        raise AssertionError("msal must not be touched on this path")

    monkeypatch.setattr(graph.msal, "ConfidentialClientApplication", boom)


@pytest.fixture
def sleeper(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record backoff waits instead of sleeping (card: mock clock, no real sleep)."""
    slept: list[float] = []
    monkeypatch.setattr(graph.time, "sleep", lambda seconds: slept.append(seconds))
    return slept


@pytest.fixture
def config(tmp_path):
    """In-memory view of the config ``mnotify_config`` wrote, for path asserts."""
    return placeholder_config(tmp_path)


def audit_lines(config) -> list[dict]:
    path = config.paths.audit
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --- Order of operations ----------------------------------------------------
def test_send_happy_path_exits_zero_after_one_post_with_a_token(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, capsys
) -> None:
    """202 from Graph -> exit 0, exactly one POST carrying the bearer token (§3.1)."""
    seed_cert(fake_keychain)
    transport = mail_transport()

    assert cli.main(argv()) == EXIT_OK

    assert transport.calls == 1
    assert transport.requested[0].headers["authorization"] == "Bearer ***"
    assert transport.payload["message"]["subject"] == "hi"
    assert transport.payload["saveToSentItems"] is True
    assert msal_stub.apps, "a token should have been acquired"
    captured = capsys.readouterr()
    assert "sent" in captured.out.lower()
    assert CANARY_PEM_BODY not in captured.out + captured.err


def test_guard_refusal_exits_3_before_any_token_or_network_call(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    """The card's hard rule: a guard refusal must not reach msal or HTTP (§3.3)."""
    transport = mail_transport()

    exit_code = cli.main(
        ["mail", "send", "--to", foreign("bob", "external"), "--subject", "hi", "--body", "x"]
    )

    assert exit_code == EXIT_GUARD
    assert transport.calls == 0
    assert "not allowed" in capsys.readouterr().err.lower()


def test_refused_attempt_is_audited_as_refused_without_a_body(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain
) -> None:
    mail_transport()

    cli.main(
        [
            "mail",
            "send",
            "--to",
            foreign("bob", "external"),
            "--subject",
            "hi",
            "--body",
            BODY_CANARY,
        ]
    )

    lines = audit_lines(config)
    assert len(lines) == 1
    assert lines[0]["outcome"] == "refused"
    assert lines[0]["channel"] == "mail"
    assert lines[0]["subject"] == "hi"
    assert BODY_CANARY not in json.dumps(lines[0])


def test_dry_run_exits_zero_prints_the_payload_and_touches_nothing(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    """--dry-run prints the exact payload with zero network calls (§4)."""
    transport = mail_transport()

    assert cli.main(argv("--dry-run")) == EXIT_OK

    assert transport.calls == 0
    assert fake_keychain.audit == [], "dry-run must not read the keychain"
    printed = json.loads(capsys.readouterr().out)
    assert printed == graph.build_send_payload(
        to=["someone@example.com"],
        subject="hi",
        body=BODY_CANARY,
        reply_to=PLACEHOLDER_REPLY_TO,
    )


def test_dry_run_is_audited_as_dry_run_and_spends_no_budget(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain
) -> None:
    mail_transport()

    assert cli.main(argv("--dry-run")) == EXIT_OK

    assert [entry["outcome"] for entry in audit_lines(config)] == ["dry_run"]
    assert not config.paths.counter_file.exists()


def test_dry_run_never_leaks_a_keychain_value_that_is_present(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    seed_cert(fake_keychain)
    mail_transport()

    assert cli.main(argv("--dry-run")) == EXIT_OK

    captured = capsys.readouterr()
    assert CANARY_PEM_BODY not in captured.out
    assert CANARY_PEM_BODY not in captured.err


def test_dry_run_with_an_attachment_carries_it_and_never_reads_the_keychain(
    mnotify_config, config, tmp_path, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    """The dry-run payload is the *exact* document that would be sent, so an
    attachment appears in it with its base64 bytes — while still performing zero
    keychain reads and zero network calls (§4)."""
    report = tmp_path / "note.txt"
    report.write_bytes(b"hello attach")
    transport = mail_transport()

    assert cli.main(argv("--dry-run", "--attach", str(report))) == EXIT_OK

    assert transport.calls == 0
    assert fake_keychain.audit == []
    printed = json.loads(capsys.readouterr().out)
    attachment = printed["message"]["attachments"][0]
    assert attachment["name"] == "note.txt"
    assert base64.b64decode(attachment["contentBytes"]) == b"hello attach"
    assert audit_lines(config)[-1]["outcome"] == "dry_run"


def test_missing_config_is_exit_2_and_is_not_audited(
    tmp_path, monkeypatch, mail_transport, msal_tripwire, capsys
) -> None:
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "absent.toml"))
    transport = mail_transport()

    assert cli.main(argv()) == EXIT_USAGE
    assert transport.calls == 0
    assert "config file not found" in capsys.readouterr().err
    assert audit_lines(placeholder_config(tmp_path)) == []


def test_send_without_any_recipient_is_a_usage_error(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    transport = mail_transport()

    assert cli.main(["mail", "send", "--subject", "hi", "--body", "x"]) == EXIT_USAGE
    assert transport.calls == 0
    assert "--to" in capsys.readouterr().err


def test_successful_send_is_audited_with_the_request_id_and_never_the_body(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain
) -> None:
    seed_cert(fake_keychain)
    mail_transport()

    assert cli.main(argv()) == EXIT_OK

    lines = audit_lines(config)
    assert len(lines) == 1
    entry = lines[0]
    assert entry["outcome"] == "sent"
    assert entry["request_id"] == REQUEST_ID
    assert entry["recipients"] == ["someone@example.com"]
    assert entry["sender"] == "noreply@example.com"
    assert entry["body_size"] == len(BODY_CANARY.encode("utf-8"))
    assert BODY_CANARY not in config.paths.audit.read_text(encoding="utf-8")


def test_a_successful_send_consumes_one_unit_of_daily_budget(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain
) -> None:
    """guard.record_send runs only after a send actually succeeded (§3.3)."""
    seed_cert(fake_keychain)
    mail_transport()

    assert cli.main(argv()) == EXIT_OK

    counter = json.loads(config.paths.counter_file.read_text(encoding="utf-8"))
    assert counter["count"] == 1
    assert counter["date"] == guard.utc_today()


# --- Payload composition from the flags -------------------------------------
def test_cc_bcc_and_html_reach_the_payload(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain
) -> None:
    seed_cert(fake_keychain)
    transport = mail_transport()

    assert (
        cli.main(
            [
                "mail",
                "send",
                "--to",
                "someone@example.com",
                "--to",
                "second@example.com",
                "--cc",
                "carbon@example.com",
                "--bcc",
                "blind@example.com",
                "--subject",
                "hi",
                "--body",
                "<p>red</p>",
                "--html",
            ]
        )
        == EXIT_OK
    )

    message = transport.payload["message"]
    assert message["body"] == {"contentType": "html", "content": "<p>red</p>"}
    assert addresses(message["toRecipients"]) == [
        "someone@example.com",
        "second@example.com",
    ]
    assert addresses(message["ccRecipients"]) == ["carbon@example.com"]
    assert addresses(message["bccRecipients"]) == ["blind@example.com"]


def test_reply_to_flag_beats_the_config_default(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain
) -> None:
    """§3.1: ``--reply-to`` overrides ``mail.default_reply_to`` (the fixture sets
    someone@contoso.com)."""
    seed_cert(fake_keychain)
    transport = mail_transport()

    assert cli.main(argv("--reply-to", "human@contoso.com")) == EXIT_OK

    assert addresses(transport.payload["message"]["replyTo"]) == ["human@contoso.com"]


def test_config_default_reply_to_is_used_when_the_flag_is_absent(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain
) -> None:
    seed_cert(fake_keychain)
    transport = mail_transport()

    assert cli.main(argv()) == EXIT_OK

    assert addresses(transport.payload["message"]["replyTo"]) == [PLACEHOLDER_REPLY_TO]


def test_html_flag_selects_the_html_content_type_in_a_dry_run(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    mail_transport()

    assert (
        cli.main(
            [
                "mail",
                "send",
                "--to",
                "someone@example.com",
                "--subject",
                "hi",
                "--body",
                "<b>x</b>",
                "--html",
                "--dry-run",
            ]
        )
        == EXIT_OK
    )

    printed = json.loads(capsys.readouterr().out)
    assert printed["message"]["body"] == {"contentType": "html", "content": "<b>x</b>"}


# --- Attachments -------------------------------------------------------------
def test_attachment_is_read_encoded_and_audited_by_name_and_size(
    mnotify_config, config, tmp_path, mail_transport, msal_stub, fake_keychain
) -> None:
    seed_cert(fake_keychain)
    report = tmp_path / "report.txt"
    report.write_bytes(b"report data")
    transport = mail_transport()

    assert cli.main(argv("--attach", str(report))) == EXIT_OK

    attachment = transport.payload["message"]["attachments"][0]
    assert attachment["@odata.type"] == "#microsoft.graph.fileAttachment"
    assert attachment["name"] == "report.txt"
    assert base64.b64decode(attachment["contentBytes"]) == b"report data"
    assert attachment["size"] == len(b"report data")

    assert audit_lines(config)[-1]["attachments"] == [
        {"name": "report.txt", "size_bytes": len(b"report data")}
    ]


def test_attachment_over_the_cap_is_refused_before_any_http_call(
    mnotify_config, config, tmp_path, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    """§3.3 total <= 3 MB: the refusal comes from the *stat* size, before a token
    is attempted and before the transport is touched."""
    big = tmp_path / "big.bin"
    with big.open("ab") as handle:
        handle.truncate(3 * 1024 * 1024 + 1)  # limits.max_attach_mb default = 3
    transport = mail_transport()

    exit_code = cli.main(argv("--attach", str(big)))

    assert exit_code == EXIT_GUARD
    assert transport.calls == 0
    assert "max_attach_mb" in capsys.readouterr().err


def test_attachment_that_does_not_exist_is_a_usage_error_before_any_http_call(
    mnotify_config, config, tmp_path, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    transport = mail_transport()

    exit_code = cli.main(argv("--attach", str(tmp_path / "absent.bin")))

    assert exit_code == EXIT_USAGE
    assert transport.calls == 0
    assert "absent.bin" in capsys.readouterr().err


def test_builder_cap_refusal_is_audited_even_when_the_stat_size_passed_guard(
    mnotify_config, config, tmp_path, monkeypatch, mail_transport, msal_tripwire,
    fake_keychain,
) -> None:
    """A file that grows between the guard's stat and the read must still exit 3
    with a refusal line — the payload builder's own cap is the backstop, and the
    audit must not silently miss that attempt (§3.3: one line per attempt)."""
    from micro_notify.commands import mail as mail_command

    big = tmp_path / "grew.bin"
    big.write_bytes(b"y" * (3 * 1024 * 1024 + 1))
    # The guard sees the pre-growth size; the bytes read are over the cap.
    monkeypatch.setattr(
        mail_command,
        "_stat_attachments",
        lambda paths: [guard.Attachment(name=Path(paths[0]).name, size_bytes=1)],
    )
    transport = mail_transport()

    assert cli.main(argv("--attach", str(big))) == EXIT_GUARD

    assert transport.calls == 0
    assert audit_lines(config)[-1]["outcome"] == "refused"


# --- Remote failures (design sections 4, 9) ---------------------------------
def test_429_then_202_exits_zero_after_one_capped_retry(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, sleeper
) -> None:
    seed_cert(fake_keychain)
    transport = mail_transport(
        httpx.Response(429, headers={"Retry-After": "1", "request-id": REQUEST_ID}),
        httpx.Response(202, headers={"request-id": REQUEST_ID}),
    )

    assert cli.main(argv()) == EXIT_OK

    assert transport.calls == 2
    assert sleeper == [1.0]
    assert audit_lines(config)[-1]["outcome"] == "sent"


def test_retries_do_not_re_acquire_the_token(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, sleeper
) -> None:
    """§9: the retry loop reuses the bearer token it already paid for."""
    seed_cert(fake_keychain)
    mail_transport(httpx.Response(500, headers={"request-id": REQUEST_ID}))

    cli.main(argv())

    assert msal_stub.token_calls == ["silent"]


def test_500_three_times_exits_5_with_the_request_id_and_one_failed_audit_line(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, sleeper, capsys
) -> None:
    seed_cert(fake_keychain)
    transport = mail_transport(httpx.Response(500, headers={"request-id": REQUEST_ID}))

    assert cli.main(argv()) == EXIT_REMOTE

    assert transport.calls == 3
    assert len(sleeper) == 2
    captured = capsys.readouterr()
    assert REQUEST_ID in captured.err
    assert BODY_CANARY not in captured.err

    lines = audit_lines(config)
    assert len(lines) == 1
    assert lines[0]["outcome"] == "failed"
    assert lines[0]["request_id"] == REQUEST_ID
    assert BODY_CANARY not in config.paths.audit.read_text(encoding="utf-8")


def test_400_exits_5_without_retrying(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, sleeper, capsys
) -> None:
    seed_cert(fake_keychain)
    transport = mail_transport(
        httpx.Response(
            400,
            headers={"request-id": REQUEST_ID},
            json={"error": {"code": "ErrorMissingMessage", "message": "no"}},
        )
    )

    assert cli.main(argv()) == EXIT_REMOTE

    assert transport.calls == 1
    assert sleeper == []
    assert "400" in capsys.readouterr().err


def test_a_failed_send_spends_no_daily_budget(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, sleeper
) -> None:
    """§3.3: only a confirmed send consumes budget — a Graph 5xx must not tick the
    counter, or three failures could starve the day."""
    seed_cert(fake_keychain)
    mail_transport(httpx.Response(500, headers={"request-id": REQUEST_ID}))

    assert cli.main(argv()) == EXIT_REMOTE

    assert not config.paths.counter_file.exists()


def test_daily_cap_exits_6_and_refuses_before_any_network_call(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    config.paths.counter_file.parent.mkdir(parents=True, exist_ok=True)
    config.paths.counter_file.write_text(
        json.dumps({"date": guard.utc_today(), "count": config.limits.daily_max}),
        encoding="utf-8",
    )
    transport = mail_transport()

    assert cli.main(argv()) == EXIT_DAILY_CAP

    assert transport.calls == 0
    assert "daily cap" in capsys.readouterr().err
    assert audit_lines(config)[-1]["outcome"] == "refused"


# --- Auth failures (design section 4 exit 4) ---------------------------------
def test_missing_certificate_is_exit_4_and_is_audited_as_failed(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, capsys
) -> None:
    """No cert in the keychain -> exit 4 naming the account, never a value (§3)."""
    transport = mail_transport()

    assert cli.main(argv()) == EXIT_AUTH

    assert transport.calls == 0
    captured = capsys.readouterr()
    assert secrets_module.ACCOUNT_CERT_PEM in captured.err
    assert audit_lines(config)[-1]["outcome"] == "failed"


def test_msal_failure_is_exit_4_without_leaking_the_key_or_body(
    mnotify_config,
    config,
    mail_transport,
    msal_stub,
    fake_keychain,
    capsys,
) -> None:
    """A *present* cert whose acquisition fails: exit 4, and stdout/stderr stay
    clean of both the key material and the message body."""
    seed_cert(fake_keychain)
    msal_stub.silent_result = None
    msal_stub.client_result = {
        "error": "invalid_client",
        "error_description": "AADSTS7000215: Invalid provided secret value",
    }
    mail_transport()

    assert cli.main(argv()) == EXIT_AUTH

    captured = capsys.readouterr()
    assert "invalid_client" in captured.err
    assert CANARY_PEM_BODY not in captured.err + captured.out
    assert BODY_CANARY not in captured.err + captured.out
    assert audit_lines(config)[-1]["outcome"] == "failed"


# --- Machine-readable output (design section 4) ------------------------------
def test_json_mode_emits_the_documented_success_shape(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, capsys
) -> None:
    seed_cert(fake_keychain)
    mail_transport()

    assert cli.main(argv("--json")) == EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["outcome"] == "sent"
    assert payload["requestId"] == REQUEST_ID
    assert payload["recipients"] == ["someone@example.com"]


def test_json_mode_reports_a_guard_refusal_as_the_shared_error_shape(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    mail_transport()
    stranger = foreign("bob", "external")

    exit_code = cli.main(
        ["mail", "send", "--to", stranger, "--subject", "hi", "--body", "x", "--json"]
    )

    assert exit_code == EXIT_GUARD
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["outcome"] == "error"
    assert payload["exitCode"] == EXIT_GUARD
    assert stranger in payload["message"]


def test_json_mode_reports_a_remote_failure_as_the_shared_error_shape(
    mnotify_config, config, mail_transport, msal_stub, fake_keychain, sleeper, capsys
) -> None:
    seed_cert(fake_keychain)
    mail_transport(httpx.Response(403, headers={"request-id": REQUEST_ID}))

    assert cli.main(argv("--json")) == EXIT_REMOTE

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["exitCode"] == EXIT_REMOTE
    assert REQUEST_ID in payload["message"]
    assert BODY_CANARY not in payload["message"]


def test_json_dry_run_reports_dry_run_and_carries_the_payload(
    mnotify_config, config, mail_transport, msal_tripwire, fake_keychain, capsys
) -> None:
    mail_transport()

    assert cli.main(argv("--dry-run", "--json")) == EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["outcome"] == "dry_run"
    assert payload["requestId"] is None
    assert payload["recipients"] == ["someone@example.com"]
    assert payload["payload"]["message"]["subject"] == "hi"
