"""``mnotify doctor`` — ordered pre-flight checks (design §4, §6, §7).

The checks run in the order an operator hits them, and the first failure stops the
run — a broken config must not be followed by a token attempt, and a missing
keychain item must not be followed by a Teams lookup. Each check prints one line and,
when it fails, a fix hint that names the command or admin step that resolves it
(design §6: the doctor mirrors the admin steps the operator is about to perform).

Exits: 0 everything green · 2 config · 3 the guard would refuse every send (empty
allowlist) · 4 auth (keychain item, token, or a token without ``Mail.Send``) ·
5 remote (only via ``--send-test``).

What "no network without ``--send-test``" means here, precisely: doctor performs no
data-plane request of its own. Check 4 *does* acquire a token — design §4 lists
"token acquired" as a check — and that goes through msal, the same call
``mnotify mail send`` makes. What never happens without the flag is a sendMail POST
or a webhook POST: the send path is entered only when the operator asks for it.

The optional test send is **delegated** to :func:`micro_notify.commands.mail.run`
rather than re-implemented, so the guard, the daily-counter write and the audit line
all come from the real send path (design §3.3). Doctor itself never calls
:func:`micro_notify.guard.record_send` — it did not send anything.

Nothing printed here carries a secret: keychain checks report *account name +
presence*, and ``--send-test`` echoes the recipient masked.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import sys
from typing import Any

from .. import (
    EXIT_AUTH,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
    AuthError,
    MicroNotifyError,
    UsageError,
)
from .. import secrets
from ..config import Config, load_config
from ..graph import acquire_token
from . import print_json

NAME = "doctor"
BUILD_STEP = "5"

# Design §3.1 / §4: the app must hold Mail.Send, and it is the token's own claim
# about itself, so it is read from the assertion msal just handed us.
REQUIRED_ROLE = "Mail.Send"
ROLE_HINT = (
    "grant Microsoft Graph application permission Mail.Send, then grant admin consent "
    "in Entra (docs/ADMIN-SETUP.md, design §6 step 1)"
)

PASS = "pass"
FAIL = "fail"
SKIPPED = "skipped"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    doctor = subparsers.add_parser(
        NAME,
        help="check config, keychain, token and Teams targets",
        description=(
            "Report config validity, keychain presence, token acquisition, the "
            "Mail.Send role and every Teams target URL. Checks print presence "
            "only — never a secret."
        ),
    )
    doctor.add_argument(
        "--send-test",
        metavar="ADDR",
        default=None,
        help="after the checks, send one real test mail to ADDR (exit 0 on success)",
    )
    doctor.add_argument("--json", action="store_true", help="machine-readable report on stdout")


# --- Report ------------------------------------------------------------------
class Report:
    """Collects check outcomes and prints them in the mode the caller asked for.

    Passing lines go to stdout; a failure line and its fix hint go to stderr, so an
    operator scanning a terminal sees red where red belongs, and ``--json`` stdout
    stays a single parseable document.
    """

    def __init__(self, machine: bool) -> None:
        self.machine = machine
        self.checks: list[dict[str, Any]] = []
        self.exit_code = EXIT_OK

    def record(self, name: str, status: str, detail: str = "", hint: str = "", exit_code: int = EXIT_OK) -> None:
        self.checks.append({"name": name, "status": status, **({"detail": detail} if detail else {})})
        if status == FAIL:
            self.exit_code = exit_code or EXIT_USAGE
        if self.machine:
            return
        line = f"{name}: {status}" + (f" — {detail}" if detail else "")
        if status == FAIL:
            print(line, file=sys.stderr)
            if hint:
                print(f"  fix: {hint}", file=sys.stderr)
        else:
            print(line)

    def skip_remaining(self, names: list[str]) -> None:
        for name in names:
            self.checks.append({"name": name, "status": SKIPPED})
            if not self.machine:
                print(f"{name}: {SKIPPED}")

    def emit(self, *, extra: dict[str, Any] | None = None) -> int:
        if self.machine:
            payload: dict[str, Any] = {
                "ok": self.exit_code == EXIT_OK,
                "outcome": "ok" if self.exit_code == EXIT_OK else "failing",
                "exitCode": self.exit_code,
                "checks": self.checks,
            }
            if extra:
                payload.update(extra)
            print_json(payload)
        return self.exit_code


# --- Helpers -----------------------------------------------------------------
def token_roles(token: str) -> list[str]:
    """The ``roles`` claim inside a bearer token's payload.

    The token is a JWT msal just issued for exactly the scopes we asked for, so its
    own payload is the cheapest authoritative answer and it costs no extra request.
    A token we cannot decode yields an empty list, which makes the check fail closed
    rather than assume the permission is there.
    """
    try:
        _, payload, _ = token.split(".", 2)
    except ValueError:
        return []
    try:
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeDecodeError, TypeError):
        return []
    if not isinstance(claims, dict):
        return []
    roles = claims.get("roles")
    return [role for role in roles if isinstance(role, str)] if isinstance(roles, list) else []


def mask_address(address: str) -> str:
    """``someone@example.com`` -> ``s***@example.com``.

    The operator needs to see which address the flag carried; the full address in a
    terminal transcript or a CI log is not worth that, and the card requires the
    echo to be masked.
    """
    local, at, domain = address.partition("@")
    if not at or not local:
        return "***"
    return f"{local[0]}***{at}{domain}"


def _mail_send_args(address: str) -> argparse.Namespace:
    """The namespace ``commands/mail.py`` expects for one plain-text test message."""
    return argparse.Namespace(
        mail_command="send",
        to=[address],
        cc=None,
        bcc=None,
        subject="mnotify doctor test",
        body="This is a one-off test send from `mnotify doctor --send-test`.",
        body_file=None,
        html=False,
        attach=None,
        reply_to=None,
        dry_run=False,
        json=False,
    )


# --- Checks ------------------------------------------------------------------
def check_config(report: Report) -> Config | None:
    """1. config file exists, parses, [mail] keys present (design §3.4) -> exit 2."""
    try:
        config = load_config()
    except UsageError as exc:
        report.record("config", FAIL, exc.message, hint=f"run `mnotify setup` ({NAME} cannot fix this)",
                      exit_code=EXIT_USAGE)
        return None
    report.record("config", PASS, str(config.source_path))
    return config


def check_keychain(report: Report, config: Config) -> bool:
    """2. keychain items present for the configured auth mode -> exit 4.

    Presence only, via :func:`micro_notify.secrets.has`: the value is never read into
    this process, so it cannot be printed.
    """
    missing = [account for account in config.mail.keychain_accounts() if not secrets.has(account)]
    if missing:
        report.record(
            "keychain",
            FAIL,
            f"missing: {', '.join(missing)}",
            hint=(
                f"store them with `mnotify setup --gen-cert` (or `mnotify setup --auth secret`) "
                f"— service '{secrets.SERVICE}'"
            ),
            exit_code=EXIT_AUTH,
        )
        return False
    report.record(
        "keychain", PASS, f"present: {', '.join(config.mail.keychain_accounts())}"
    )
    return True


def check_teams(report: Report, config: Config) -> bool:
    """3. every configured Teams target has its webhook URL in the keychain -> exit 4."""
    if not config.teams_targets:
        report.record("teams", PASS, "no targets configured")
        return True
    missing = [
        secrets.teams_account(target.name)
        for target in config.teams_targets
        if not secrets.has(secrets.teams_account(target.name))
    ]
    if missing:
        report.record(
            "teams",
            FAIL,
            f"missing webhook URL in keychain accounts: {', '.join(missing)}",
            hint=f"paste each URL with `mnotify teams targets add <name> --kind channel|dm` "
                 f"(the URL is a secret; it goes to the keychain, never the config)",
            exit_code=EXIT_AUTH,
        )
        return False
    report.record("teams", PASS, f"{len(config.teams_targets)} target(s) have a URL")
    return True


def check_token(report: Report, config: Config) -> bool:
    """4. token acquisition works and the token's roles include Mail.Send -> exit 4."""
    try:
        token = acquire_token(config.mail)
    except AuthError as exc:
        report.record("token", FAIL, exc.message,
                      hint="check the app registration and the stored credential (design §6 step 1)",
                      exit_code=EXIT_AUTH)
        return False
    roles = token_roles(token)
    if REQUIRED_ROLE not in roles:
        report.record(
            "token",
            FAIL,
            f"token acquired but its roles do not include {REQUIRED_ROLE}",
            hint=ROLE_HINT,
            exit_code=EXIT_AUTH,
        )
        return False
    report.record("token", PASS, f"acquired; roles include {REQUIRED_ROLE}")
    return True


def check_allow(report: Report, config: Config) -> bool:
    """5. [allow] is non-empty (design §3.3) -> exit 3 with a loud warning.

    An empty allowlist is a valid configuration — it is the fail-closed default — but
    it means *every* send will be refused, which looks like a broken install to
    whoever is reading the doctor output. So it is reported as a failure of the
    operator's intent, in words.
    """
    if not config.allow.domains and not config.allow.addresses:
        report.record(
            "allow",
            FAIL,
            "[allow] is empty — every send will be refused (exit 3) until you configure it",
            hint="add `domains = [\"example.com\"]` under [allow] in the config file, "
                 "or re-run `mnotify setup --allow-domain example.com`",
            exit_code=EXIT_GUARD,
        )
        return False
    report.record(
        "allow",
        PASS,
        f"{len(config.allow.domains)} domain(s), {len(config.allow.addresses)} address(es)",
    )
    return True


def check_send_test(report: Report, address: str) -> int:
    """6. one real send, only because the operator asked for it (design §4).

    Delegated to the mail command so the guard runs on this recipient, the daily
    counter is spent by the code that actually sent, and the audit line is the same
    shape every other mail send writes.
    """
    from . import mail as mail_module  # here, not at import time: keeps the seam patchable

    masked = mask_address(address)
    try:
        # The mail command prints for a human; doctor owns this command's stdout (and
        # its --json document), so that output is routed to stderr instead.
        with contextlib.redirect_stdout(sys.stderr):
            code = mail_module.run(_mail_send_args(address))
    except MicroNotifyError as exc:
        code = exc.exit_code
        detail = f"test send to {masked} failed"
        if code == EXIT_REMOTE:
            report.record("send-test", FAIL, detail, hint="Graph returned an error (design §4 exit 5)",
                          exit_code=EXIT_REMOTE)
        elif code == EXIT_GUARD:
            report.record("send-test", FAIL, detail,
                          hint="the recipient is not covered by [allow] (design §3.3)",
                          exit_code=EXIT_GUARD)
        else:
            report.record("send-test", FAIL, detail, hint=str(exc.message), exit_code=code)
        return code
    if code == EXIT_OK:
        report.record("send-test", PASS, f"one test message sent to {masked}")
    else:
        report.record("send-test", FAIL, f"test send to {masked} failed (exit {code})",
                      exit_code=code)
    return code


# --- Entry point -------------------------------------------------------------
CHECK_ORDER = ("config", "keychain", "teams", "token", "allow", "send-test")


def run(args: argparse.Namespace) -> int:
    """``mnotify doctor`` — ordered checks, first failure wins, no secret printed."""
    machine = bool(getattr(args, "json", False))
    report = Report(machine)
    address = getattr(args, "send_test", None)
    remaining: list[str] = list(CHECK_ORDER)

    config = check_config(report)
    remaining.remove("config")
    if config is None:
        report.skip_remaining(remaining)
        return report.emit()

    for name, check in (
        ("keychain", lambda: check_keychain(report, config)),
        ("teams", lambda: check_teams(report, config)),
        ("token", lambda: check_token(report, config)),
        ("allow", lambda: check_allow(report, config)),
    ):
        remaining.remove(name)
        if not check():
            # Nothing downstream runs: remaining holds `allow` and `send-test`, and both
            # are reported as skipped rather than silently dropped.
            report.skip_remaining(remaining)
            return report.emit()

    if address:
        code = check_send_test(report, address)
        if code != EXIT_OK:
            report.exit_code = code
        return report.emit(extra={"recipient": mask_address(address)})

    # Not requested: report it as skipped, which is what it is — a green check for a
    # send nobody asked for would overstate what doctor has proven.
    report.skip_remaining(remaining)
    return report.emit()


__all__ = [
    "BUILD_STEP",
    "CHECK_ORDER",
    "NAME",
    "REQUIRED_ROLE",
    "ROLE_HINT",
    "add_parser",
    "mask_address",
    "run",
    "token_roles",
]
