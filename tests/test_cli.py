"""CLI surface tests (design section 4).

Asserts every subcommand and flag the design declares parses, that the exit-code
mapping is exactly the documented one, and that a stubbed command fails loudly
instead of faking success.
"""

from __future__ import annotations

import argparse
import json

import pytest

from micro_notify import (
    DailyCapReached,
    AuthError,
    EXIT_AUTH,
    EXIT_DAILY_CAP,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
    GuardRefusal,
    MicroNotifyError,
    NotImplementedYet,
    RemoteError,
    UsageError,
    __version__,
)
from micro_notify import cli
from micro_notify.commands import COMMAND_MODULES

BODY = ["--body", "hello"]
MAIL_SEND = ["mail", "send", "--to", "someone@example.com", "--subject", "hi"]


def parse(argv: list[str]) -> argparse.Namespace:
    return cli.build_parser().parse_args(argv)


# --- Surface: every design section 4 command exists ------------------------
def test_every_command_module_is_dispatchable() -> None:
    parser = cli.build_parser()
    names: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            names.update(action.choices)
    assert {"mail", "teams", "setup", "doctor", "log", "config"} <= names
    assert set(cli.DISPATCH) == {module.NAME for module in COMMAND_MODULES}


def test_module_names_match_the_dispatch_keys() -> None:
    for module in COMMAND_MODULES:
        assert cli.DISPATCH[module.NAME] is module.run


def test_mail_send_flags_all_parse() -> None:
    args = parse(
        MAIL_SEND
        + BODY
        + [
            "--to",
            "second@example.com",
            "--cc",
            "cc@example.com",
            "--bcc",
            "bcc@example.com",
            "--html",
            "--attach",
            "a.txt",
            "--attach",
            "b.txt",
            "--reply-to",
            "person@contoso.com",
            "--dry-run",
            "--json",
        ]
    )
    assert args.command == "mail" and args.mail_command == "send"
    assert args.to == ["someone@example.com", "second@example.com"]
    assert args.cc == ["cc@example.com"]
    assert args.bcc == ["bcc@example.com"]
    assert args.subject == "hi"
    assert args.body == "hello"
    assert args.body_file is None
    assert args.html is True
    assert args.attach == ["a.txt", "b.txt"]
    assert args.reply_to == "person@contoso.com"
    assert args.dry_run is True
    assert args.json is True


def test_mail_send_body_file_and_stdin_paths_parse() -> None:
    from_file = parse(MAIL_SEND + ["--body-file", "body.md"])
    assert from_file.body_file == "body.md" and from_file.body is None

    bare = parse(MAIL_SEND)
    assert bare.body is None and bare.body_file is None
    assert bare.html is False and bare.dry_run is False and bare.json is False


def test_mail_send_rejects_both_body_flags_at_once() -> None:
    with pytest.raises(SystemExit) as excinfo:
        parse(MAIL_SEND + ["--body", "x", "--body-file", "f"])
    assert excinfo.value.code == EXIT_USAGE


def test_mail_send_requires_a_subject() -> None:
    with pytest.raises(SystemExit) as excinfo:
        parse(["mail", "send", "--to", "someone@example.com"])
    assert excinfo.value.code == EXIT_USAGE


def test_teams_send_flags_all_parse() -> None:
    args = parse(
        [
            "teams",
            "send",
            "alerts",
            "--to",
            "person@contoso.com",
            "--title",
            "Build",
            "--text",
            "green",
            "--fact",
            "branch=main",
            "--fact",
            "stage=prod",
            "--link",
            "https://example.com/job/1",
            "--link-title",
            "Job",
            "--dry-run",
            "--json",
        ]
    )
    assert args.command == "teams" and args.teams_command == "send"
    assert args.target == "alerts"
    assert args.to == "person@contoso.com"
    assert args.title == "Build"
    assert args.text == "green" and args.text_file is None
    assert args.fact == ["branch=main", "stage=prod"]
    assert args.link == "https://example.com/job/1"
    assert args.link_title == "Job"
    assert args.card_file is None
    assert args.dry_run is True and args.json is True


def test_teams_send_accepts_a_card_file() -> None:
    args = parse(["teams", "send", "alerts", "--card-file", "card.json"])
    assert args.card_file == "card.json"


def test_teams_send_rejects_both_text_flags() -> None:
    with pytest.raises(SystemExit) as excinfo:
        parse(["teams", "send", "alerts", "--text", "a", "--text-file", "f"])
    assert excinfo.value.code == EXIT_USAGE


def test_teams_targets_surface_parses() -> None:
    added = parse(["teams", "targets", "add", "alerts", "--kind", "channel"])
    assert added.targets_command == "add" and added.name == "alerts" and added.kind == "channel"

    listed = parse(["teams", "targets", "list", "--json"])
    assert listed.targets_command == "list" and listed.json is True

    removed = parse(["teams", "targets", "remove", "alerts"])
    assert removed.targets_command == "remove" and removed.name == "alerts"


@pytest.mark.parametrize("kind", ["channel", "dm"])
def test_teams_targets_add_accepts_only_the_two_kinds(kind: str) -> None:
    assert parse(["teams", "targets", "add", "t", "--kind", kind]).kind == kind


def test_teams_targets_add_rejects_an_unknown_kind() -> None:
    with pytest.raises(SystemExit) as excinfo:
        parse(["teams", "targets", "add", "t", "--kind", "pigeon"])
    assert excinfo.value.code == EXIT_USAGE


def test_teams_targets_add_requires_a_kind() -> None:
    with pytest.raises(SystemExit) as excinfo:
        parse(["teams", "targets", "add", "t"])
    assert excinfo.value.code == EXIT_USAGE


def test_teams_targets_add_has_no_url_flag() -> None:
    """A webhook URL as a flag value would land in shell history — design §3.2."""
    with pytest.raises(SystemExit):
        parse(["teams", "targets", "add", "t", "--kind", "channel", "--url", "https://example.com"])


def test_doctor_surface_parses() -> None:
    args = parse(["doctor", "--send-test", "someone@example.com"])
    assert args.command == "doctor"
    assert args.send_test == "someone@example.com"
    assert parse(["doctor"]).send_test is None
    assert parse(["doctor", "--json"]).json is True


def test_log_surface_parses() -> None:
    assert parse(["log"]).tail is None
    assert parse(["log", "--tail", "5"]).tail == 5
    assert parse(["log", "--json"]).json is True


def test_config_show_surface_parses() -> None:
    args = parse(["config", "show"])
    assert args.command == "config" and args.config_command == "show"


def test_setup_surface_parses() -> None:
    args = parse(
        [
            "setup",
            "--gen-cert",
            "--tenant-id",
            "00000000-0000-0000-0000-000000000000",
            "--client-id",
            "00000000-0000-0000-0000-000000000000",
            "--sender",
            "noreply@example.com",
            "--auth",
            "certificate",
            "--reply-to",
            "person@contoso.com",
            "--allow-domain",
            "example.com",
            "--force",
            "--json",
        ]
    )
    assert args.command == "setup"
    assert args.gen_cert is True
    assert args.sender == "noreply@example.com"
    assert args.auth == "certificate"
    assert args.allow_domain == ["example.com"]
    assert args.force is True


# --- Exit-code mapping -----------------------------------------------------
@pytest.mark.parametrize(
    "exception,expected",
    [
        (UsageError("bad"), EXIT_USAGE),
        (GuardRefusal("nope"), EXIT_GUARD),
        (AuthError("no token"), EXIT_AUTH),
        (RemoteError("500"), EXIT_REMOTE),
        (DailyCapReached("full"), EXIT_DAILY_CAP),
    ],
)
def test_typed_errors_map_to_the_documented_exit_codes(
    tmp_path, monkeypatch, capsys, exception, expected
) -> None:
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "unused.toml"))

    def handler(_args: argparse.Namespace) -> int:
        raise exception

    monkeypatch.setitem(cli.DISPATCH, "log", handler)
    assert cli.main(["log"]) == expected
    assert expected == exception.exit_code
    captured = capsys.readouterr()
    assert exception.message in captured.err
    assert captured.out == ""


def test_success_return_value_is_passed_through(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "unused.toml"))
    monkeypatch.setitem(cli.DISPATCH, "log", lambda _args: EXIT_OK)
    assert cli.main(["log"]) == EXIT_OK


def test_json_mode_reports_errors_as_json_on_stdout(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "unused.toml"))
    monkeypatch.setitem(cli.DISPATCH, "log", lambda _args: (_ for _ in ()).throw(GuardRefusal("refused")))
    assert cli.main(["log", "--json"]) == EXIT_GUARD
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == {"ok": False, "outcome": "error", "exitCode": 3, "message": "refused"}
    assert captured.err == ""


def test_error_message_never_suggests_a_send_happened(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "unused.toml"))
    monkeypatch.setitem(cli.DISPATCH, "log", lambda _args: (_ for _ in ()).throw(RemoteError("graph 500")))
    assert cli.main(["log"]) == EXIT_REMOTE
    assert "mnotify: graph 500" in capsys.readouterr().err


# --- Stubs fail loudly -----------------------------------------------------
@pytest.mark.parametrize(
    "argv,owner",
    [
        # mail argv dropped: commands/mail.py is implemented on wt/p3 (t_349ecae3) and its
        # behaviour is pinned by tests/test_mail_cli.py; these pins only exist for stubs.
        # teams argvs dropped: commands/teams.py is implemented on wt/p4 (t_ba58663d) and its
        # behaviour is pinned by tests/test_teams_cli.py; these pins only exist for stubs.
        # setup argv dropped: commands/setup.py is implemented on wt/p5 (t_5f4a5de4) and its
        # behaviour is pinned by tests/test_setup.py; this pin only exists for stubs.
        # doctor argv dropped: commands/doctor.py is implemented on wt/p5 (t_5f4a5de4) and its
        # behaviour is pinned by tests/test_doctor.py; this pin only exists for stubs.
        # Kept: bare `mnotify mail` with no action is the one remaining stub in build steps 1-5
        # (mail.py's run() still raises not_implemented when args.mail_command is not "send").
        # This list must not be empty: with no parameters pytest collects the test as a single
        # skip, so the "stubs fail loudly" invariant would stop being exercised and still look green.
        (["mail"], "mail"),
    ],
)
def test_stubbed_commands_exit_2_and_say_so(argv, owner, capsys) -> None:
    module = next(m for m in COMMAND_MODULES if m.NAME == owner)
    with pytest.raises(NotImplementedYet) as excinfo:
        module.run(parse(argv))
    message = excinfo.value.message
    assert "not implemented" in message
    assert "nothing was sent" in message
    assert excinfo.value.exit_code == EXIT_USAGE
    assert capsys.readouterr().out == ""


def test_stub_never_reports_success(capsys) -> None:
    with pytest.raises(MicroNotifyError) as excinfo:
        cli.DISPATCH["mail"](parse(MAIL_SEND))
    assert excinfo.value.exit_code != EXIT_OK


# --- Root behaviour --------------------------------------------------------
def test_no_subcommand_is_a_usage_error(capsys) -> None:
    assert cli.main([]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "subcommand is required" in captured.err
    assert "usage:" in captured.err


def test_unknown_subcommand_exits_2() -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["frobnicate"])
    assert excinfo.value.code == EXIT_USAGE


def test_version_flag_prints_the_package_version(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == EXIT_OK
    assert __version__ in capsys.readouterr().out


def test_keyboard_interrupt_does_not_look_like_a_send(capsys, monkeypatch) -> None:
    monkeypatch.setitem(cli.DISPATCH, "log", lambda _args: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["log"]) == 130
    assert "interrupted" in capsys.readouterr().err


def test_unexpected_exception_is_not_swallowed(monkeypatch) -> None:
    def boom(_args: argparse.Namespace) -> int:
        raise ValueError("bug")

    monkeypatch.setitem(cli.DISPATCH, "log", boom)
    with pytest.raises(ValueError, match="bug"):
        cli.main(["log"])


def test_log_reads_a_jsonl_file_it_did_not_write(tmp_path, monkeypatch, capsys) -> None:
    """P1's `log` must render whatever P2's audit writer produces."""
    audit = tmp_path / "logs" / "sent.jsonl"
    audit.parent.mkdir(parents=True)
    audit.write_text(
        json.dumps(
            {
                "ts": "2026-10-27T12:00:00Z",
                "channel": "mail",
                "sender": "noreply@example.com",
                "recipients": ["someone@example.com"],
                "subject": "hi",
                "body_sha256": "a" * 64,
                "body_size": 5,
                "outcome": "sent",
                "request_id": "graph-req-1",
            }
        )
        + "\n"
        + "{not json}\n",
        encoding="utf-8",
    )
    from micro_notify.config import write_config
    from conftest import placeholder_config

    # placeholder_config already points [paths]audit at tmp_path/logs/sent.jsonl.
    config_path = tmp_path / "config.toml"
    write_config(placeholder_config(tmp_path), config_path)
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(config_path))

    assert cli.main(["log", "--tail", "1", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["malformed"] == 1
    assert payload["entries"][0]["outcome"] == "sent"


def test_log_human_output_has_no_body_field(tmp_path, monkeypatch, capsys) -> None:
    from micro_notify.config import write_config
    from conftest import placeholder_config

    audit = tmp_path / "logs" / "sent.jsonl"
    audit.parent.mkdir(parents=True)
    body_marker = "CANARY-body-must-not-print"
    audit.write_text(
        json.dumps(
            {
                "ts": "2026-10-27T12:00:00Z",
                "channel": "mail",
                "target": "alerts",
                "outcome": "sent",
                "body": body_marker,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    write_config(placeholder_config(tmp_path), tmp_path / "config.toml")
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "config.toml"))

    assert cli.main(["log"]) == EXIT_OK
    assert body_marker not in capsys.readouterr().out


def test_log_on_a_missing_audit_file_is_not_an_error(tmp_path, monkeypatch, capsys) -> None:
    from micro_notify.config import write_config
    from conftest import placeholder_config

    write_config(placeholder_config(tmp_path), tmp_path / "config.toml")
    monkeypatch.setenv("MICRO_NOTIFY_CONFIG", str(tmp_path / "config.toml"))
    assert cli.main(["log"]) == EXIT_OK
    assert "no audit entries" in capsys.readouterr().out


# --- Packaging surface -----------------------------------------------------
def test_both_console_scripts_are_declared() -> None:
    import tomllib
    from pathlib import Path

    pyproject = Path(cli.__file__).resolve().parents[2] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    assert scripts["micro-notify"] == "micro_notify.cli:main"
    assert scripts["mnotify"] == "micro_notify.cli:main"


def test_entrypoint_wraps_main_with_sys_exit(monkeypatch) -> None:
    seen: list[int] = []
    monkeypatch.setattr(cli, "main", lambda argv=None: EXIT_GUARD)
    monkeypatch.setattr("sys.exit", lambda code: seen.append(code))
    cli.entrypoint()
    assert seen == [EXIT_GUARD]


def test_base_error_defaults_to_exit_2() -> None:
    assert MicroNotifyError("x").exit_code == EXIT_USAGE
