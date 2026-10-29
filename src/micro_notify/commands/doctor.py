"""``mnotify doctor`` — ordered pre-flight checks (design §4, §6, §7).

The checks run in the order an operator hits them, and the first failure stops the
run — a broken config must not be followed by a token attempt, and a missing
keychain item must not be followed by a Teams lookup. Each check prints one line and,
when it fails, a fix hint that names the command or admin step that resolves it
(design §6: the doctor mirrors the admin steps the operator is about to perform).

Exits: 0 everything green (or only warnings) · 2 config · 3 the guard would refuse
every send (empty allowlist) · 4 auth (keychain item, token, or a token whose roles
claim names other roles but not ``Mail.Send``) · 5 remote (only via ``--send-test``).

``Mail.Send`` is checked against the ``roles`` claim of the token msal handed us, and
that claim is what makes this check tri-state rather than pass/fail. Entra fills it
from the app's **consented Entra app roles**; design §6 step 3 tells the operator to
remove the tenant-wide ``Mail.Send`` consent and keep only the Exchange Online
``Application Mail.Send`` **scoped** role, and a scoped role is not, and cannot be, a
claim in this token. So on the hardened tenant the design mandates, an absent ``roles``
claim is the *expected* state — treating it as a failure made ``mnotify doctor``
unsatisfiable (exit 4 forever), skipped ``allow``, and put ``--send-test`` — §6 step 3's
own verification command — out of reach (card t_24a04813). Hence:

* claim present and listing ``Mail.Send``            -> ``pass``
* claim present, readable, without ``Mail.Send``     -> ``fail`` exit 4 (authoritative:
  the tenant-wide grant is there and the app does not hold it)
* claim absent or empty, token readable              -> ``warn``, run continues; the
  grant lives in Exchange app-RBAC, which this claim cannot see. The only proof that
  the scoped role works is a real send, so ``--send-test`` must be reachable.
* token not a readable JWT                           -> ``fail`` exit 4 (we cannot read
  the assertion, so we refuse rather than assume)

A ``warn`` never changes the exit code and never stops the run: it reports honestly that
this one thing could not be verified, and lets the checks that *can* prove something run.

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
# about itself, so it is read from the assertion msal just handed us. The claim is
# authoritative only when Entra put it there: after design §6 step 3 removes the
# tenant-wide consent, the remaining grant is the Exchange Online *scoped* role,
# which never appears in this claim — an absent claim is therefore "not verifiable",
# not "not authorised" (see this module's docstring and card t_24a04813).
REQUIRED_ROLE = "Mail.Send"
ROLE_HINT = (
    "grant Microsoft Graph application permission Mail.Send, then grant admin consent "
    "in Entra (docs/ADMIN-SETUP.md, design §6 step 1)"
)
ROLE_UNVERIFIABLE = (
    f"token acquired; {REQUIRED_ROLE} not verifiable from the token — its roles claim "
    "is absent or empty. Expected after design §6 step 3: the Exchange Online scoped "
    "Application Mail.Send role is invisible to the Entra roles claim. Prove the grant "
    "with `mnotify doctor --send-test <addr>`; do not re-grant the tenant-wide consent "
    "to silence this line"
)

PASS = "pass"
WARN = "warn"
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

    Passing and warning lines go to stdout; a failure line and its fix hint go to
    stderr, so an operator scanning a terminal sees red where red belongs, and
    ``--json`` stdout stays a single parseable document. A ``warn`` records a thing
    that could not be verified: unlike ``fail`` it never sets the exit code and never
    stops the run (see :func:`check_token` for the one check that can produce one).
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
# The three states of the ``roles`` claim, named rather than encoded as None/[]
# tricks: the difference between "the claim is empty" and "the claim could not be
# read at all" is the entire behaviour of check 4.
CLAIM_READ = "read"
CLAIM_ABSENT = "absent"
CLAIM_UNREADABLE = "unreadable"


def read_roles_claim(token: str) -> tuple[str, list[str]]:
    """``(state, roles)`` for the ``roles`` claim inside a bearer token's payload.

    The token is a JWT msal just issued for exactly the scopes we asked for, so its
    own payload is the cheapest answer available and it costs no extra request.

    Three states, because they mean three different things to the operator:

    * ``CLAIM_READ`` — the payload decoded and the claim carries entries. Entra
      wrote them from the app's consented app roles: authoritative.
    * ``CLAIM_ABSENT`` — the payload decoded and the claim is missing or empty.
      This is exactly what a token looks like once design §6 step 3 removed the
      tenant-wide consent; it says nothing either way about the Exchange Online
      scoped role, so the caller reports it as not verifiable.
    * ``CLAIM_UNREADABLE`` — not a decodable JWT (or a claim shape Entra does not
      produce). The assertion cannot be read, so the caller must fail closed
      rather than assume the permission is there.
    """
    try:
        _, payload, _ = token.split(".", 2)
    except ValueError:
        return CLAIM_UNREADABLE, []
    try:
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeDecodeError, TypeError):
        return CLAIM_UNREADABLE, []
    if not isinstance(claims, dict):
        return CLAIM_UNREADABLE, []
    raw = claims.get("roles")
    if raw is None or raw == []:
        return CLAIM_ABSENT, []
    if not isinstance(raw, list):
        return CLAIM_UNREADABLE, []
    roles = [role for role in raw if isinstance(role, str)]
    return (CLAIM_READ if roles else CLAIM_ABSENT), roles


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
    """4. token acquisition works, and the roles claim is read -> exit 4 on real faults.

    Tri-state on purpose (module docstring): an unreadable assertion or a claim that
    names other roles without ``Mail.Send`` is a failure the operator must fix; an
    absent claim is only *not verifiable*, because after design §6 step 3 that is what
    a correctly hardened tenant's token looks like. A warn keeps the run going — the
    grant that matters then lives in Exchange app-RBAC, and the only evidence that it
    works is the ``--send-test`` this check must therefore not block.
    """
    try:
        token = acquire_token(config.mail)
    except AuthError as exc:
        report.record("token", FAIL, exc.message,
                      hint="check the app registration and the stored credential (design §6 step 1)",
                      exit_code=EXIT_AUTH)
        return False
    state, roles = read_roles_claim(token)
    if state == CLAIM_UNREADABLE:
        report.record(
            "token",
            FAIL,
            f"token acquired but its roles claim could not be read, so {REQUIRED_ROLE} "
            "cannot be verified",
            hint=ROLE_HINT,
            exit_code=EXIT_AUTH,
        )
        return False
    if state == CLAIM_ABSENT:
        report.record("token", WARN, ROLE_UNVERIFIABLE)
        return True
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
    "CLAIM_ABSENT",
    "CLAIM_READ",
    "CLAIM_UNREADABLE",
    "FAIL",
    "NAME",
    "PASS",
    "REQUIRED_ROLE",
    "ROLE_HINT",
    "ROLE_UNVERIFIABLE",
    "SKIPPED",
    "WARN",
    "add_parser",
    "mask_address",
    "read_roles_claim",
    "run",
]
