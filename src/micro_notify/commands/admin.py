"""``mnotify admin bootstrap`` — the tenant steps of ADMIN-SETUP in one command.

Design §6 / docs/ADMIN-SETUP.md, automated. The manual path stays the reference and
stays untouched; this command is the same procedure in the order the parent cards
built it, so the operator runs one command instead of clicking through the portal and
pasting PowerShell:

    preflight (B1) -> Entra app + service principal (B2) -> certificate upload (B3)
    -> Exchange Online scoping (B4) -> write the config -> doctor

Order is the contract. Each step is the previous step's precondition: the certificate
attaches to the app B2 resolved, the Exchange scope is granted to the service principal
B2 created, and the config is written only once the scope has been *proven* — B4 fails
closed, and a config for an unproven grant would advertise a capability the tenant does
not have.

Step outcomes: one column, two sources
---------------------------------------

``created`` this run made an object; ``exists`` it was already there and this run
changed nothing (the idempotent re-run — a configured tenant reports ``exists`` for
every step and exits 0); ``dryrun`` the step was planned and printed instead of
performed; ``skipped`` the step did not confirm anything. The first two values come
straight from the parent modules (``admin/entra.py``, ``admin/certupload.py``,
``admin/exo.py`` own that vocabulary) and are never inferred here; ``dryrun`` and
``skipped`` are this layer's, because only the command layer knows a step was skipped.
``doctor`` reports ``exists`` when it is green (the end state is verified to exist) and
``skipped`` when it is not — its own report, printed above, names the failing check, and
the summary carries ``ok: false`` so nothing downstream can read it as success.

Dry-run has no branch inside a step
-----------------------------------

``--dry-run`` installs B1's :class:`~micro_notify.admin.runner.DryRunRunner` as the
process-wide runner — that is the only dry-run mechanism, and it is why a dry run needs
no ``if dry_run`` guard inside a step. The steps that go through the seam then record
instead of executing, and their argv is printed as it is recorded. Two steps have a
local half that does *not* go through the seam (B3's ``openssl`` + keychain write, B4's
temp ``.ps1`` file), and both refuse a recording runner by design — replacing an
operator's private key during a run that promised to change nothing is the failure this
avoids — so for those two the command prints the plan functions B3 and B4 publish
(``plan_certificate_upload``, ``plan_commands``), which is exactly what those cards
declare as their dry-run surface.

Nothing here prompts for a secret, and nothing installs silently
----------------------------------------------------------------

``az login`` is never run for the operator (B1's rule) and neither is
``Connect-ExchangeOnline``. ``--install-missing`` is the only path that can run
``brew``, and it needs a ``y`` at a prompt first; without a terminal the flag is refused
rather than assumed, because "install two packages on this machine" is not a decision a
script should make on an operator's behalf.

A secret — a private key, a token, a webhook URL — never reaches stdout, stderr, the
config file or the ``--json`` document. What is printed is account names, tenant ids,
thumbprints and mailbox addresses: the values ADMIN-SETUP asks an operator to verify.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from .. import EXIT_OK, AuthError, UsageError
from .. import delegation
from ..admin import exo
from ..admin import preflight
from ..admin import runner as admin_runner
from ..admin import set_runner
from ..admin.certupload import plan_certificate_upload
from ..admin.exo import plan_commands, supports_streaming
from ..admin.runner import DryRunRunner, StreamingRunner
from ..config import (
    AUTH_CERTIFICATE,
    AllowConfig,
    Config,
    LimitsConfig,
    MailConfig,
    PathsConfig,
    config_path,
    load_config,
    write_config,
)
from ..delegation import DELEGATED_SCOPES
from . import doctor as doctor_module
from . import print_json

NAME = "admin"
BUILD_STEP = "6"

# The step-outcome vocabulary. The first two are the parents' own strings (imported so
# a rename upstream cannot silently desynchronise this module); the last two belong here.
OUTCOME_CREATED = "created"
OUTCOME_EXISTS = "exists"
OUTCOME_DRYRUN = "dryrun"
OUTCOME_SKIPPED = "skipped"

# Step names, in run order. A declared surface: the ``--json`` document, the human
# report and the tests all key off these, so changing one is a deliberate act.
STEP_PREFLIGHT = "preflight"
STEP_ENTRA = "entra-app"
STEP_CERTIFICATE = "certificate"
STEP_EXCHANGE = "exchange-scope"
STEP_CONFIG = "config"
STEP_DOCTOR = "doctor"
STEP_SEND_TEST = "send-test"

# The delegated-mode steps (D5). Names, not redefinitions: everything the two modes
# share keeps its name, so a reader comparing the two lists sees exactly which steps
# differ and which are the same step run for a different credential.
STEP_PERMISSIONS = "delegated-permissions"
STEP_PUBLIC_CLIENT = "public-client-flows"
STEP_CONSENT = "admin-consent"
STEP_SIGNIN = "signin"

BOOTSTRAP_STEPS: tuple[str, ...] = (
    STEP_PREFLIGHT,
    STEP_ENTRA,
    STEP_CERTIFICATE,
    STEP_EXCHANGE,
    STEP_CONFIG,
    STEP_DOCTOR,
)

# The delegated run order, and why it differs from the app-only list in two places:
#
# * permissions and the public-client switch come **before** anything that signs a
#   person in, because the device-code flow needs both — an app that has not declared
#   the scopes cannot be consented, and `isFallbackPublicClient` false makes Entra
#   refuse to redeem the code (`invalid_client`). Signing in first would fail on a
#   fresh tenant;
# * `config` comes **before** the sign-in, which is the reverse of the app-only list.
#   That is not an ordering preference: amendment A.1 says the delegated sign-in rides
#   *this* registration, so `mnotify login` reads its client id and tenant from the
#   config file that does not exist yet on a fresh tenant. The config is login's
#   precondition here, not its reward — and the sender it writes is the operator's
#   declared `--sender`, which the sign-in then has to *prove* (see
#   :func:`_require_signed_in_as`);
# * `doctor` stays last, and `admin-consent` is the only step that may be *absent*
#   (it runs only when `--admin-consent` is passed).
DELEGATED_BOOTSTRAP_STEPS: tuple[str, ...] = (
    STEP_PREFLIGHT,
    STEP_ENTRA,
    STEP_PERMISSIONS,
    STEP_PUBLIC_CLIENT,
    STEP_CONSENT,
    STEP_CONFIG,
    STEP_SIGNIN,
    STEP_DOCTOR,
)

# The two credentials one registration can be used with (design amendment A.1).
# `app` is the default and keeps every app-only behaviour byte-identical.
MODE_APP = "app"
MODE_DELEGATED = "delegated"
BOOTSTRAP_MODES: tuple[str, ...] = (MODE_APP, MODE_DELEGATED)

INSTALL_PROMPT = "Install {formulas} with brew? This changes the machine. [y/N]: "

# The one outcome the bootstrap must never leave behind: a config whose [allow] refuses
# every recipient. Surfaced as a hint here rather than discovered by `doctor` after the
# tenant has already been mutated.
EMPTY_ALLOWLIST_HINT = (
    "pass at least one allowed recipient domain, e.g. `--allow-domain example.com` "
    "— with an empty [allow] every send is refused (exit 3), so nothing you send will "
    "arrive (design §3.3)"
)

DEVICE_CODE_HINT = (
    "Exchange Online sign-in: open the page pwsh prints and enter the code. This is "
    "the one step that needs you — mnotify never signs you in."
)

CONTROL_MAILBOX_HINT = (
    "the Exchange proof needs a second mailbox as the negative control (ADMIN-SETUP "
    "§2.4): pass --control-mailbox <another mailbox>, or sign `az` in as someone who is "
    "not the sender"
)

# Markers a dry run prints in place of values it has not earned. Same convention B3/B4
# use (`<public-certificate-path>`, `<generated-script-path>`): a placeholder that looks
# like a real value is worse than one that admits the step has not happened.
DRY_APP_ID = "<appId>"
DRY_SP_OBJECT_ID = "<spObjectId>"
DRY_CONTROL_MAILBOX = "<signed-in-admin-mailbox>"
DRY_TENANT_ID = "<tenantId>"
# The delegated-mode markers (D5). A scope id is not earned until the tenant's Graph
# service principal has been read, and the signed-in UPN does not exist until a human
# has finished a browser — printing an all-zero GUID for either would look like a real
# value the plan had resolved.
DRY_SCOPE_ID = "<scopeId>"
DRY_GRAPH_SP_OBJECT_ID = "<graphServicePrincipalObjectId>"
DRY_SIGNIN_UPN = "<signed-in-upn>"
DRY_PUBLIC_CLIENT_FLAG = "isFallbackPublicClient=true"


def _mode_of(args: argparse.Namespace) -> str:
    """Which credential this run configures — the one branch point of the bootstrap.

    ``getattr`` with the app-only default rather than a direct attribute read, for the
    same reason B5 reads every other flag defensively: a caller that builds a Namespace
    by hand (a test, an embedding caller) that pre-dates ``--mode`` must keep getting
    exactly the behaviour it always got. A missing attribute here means app-only, which
    is the conservative answer — the delegated steps are the ones that mutate a
    registration's permissions, so no run may reach them by accident.
    """
    return (getattr(args, "mode", None) or MODE_APP).strip().lower()


class BootstrapError(UsageError):
    """The bootstrap cannot proceed safely -> exit 2, naming the fix.

    A :class:`~micro_notify.UsageError` rather than a new exit code: every case here is
    something the operator fixes in the flags they passed or in the tenant, which is
    what design §4 exit 2 means. The parents' own errors (``EntraError``,
    ``ExchangeError``, ``CertUploadError``) propagate untouched so their exit codes —
    including exit 4 for a credential problem — stay theirs.
    """


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    admin = subparsers.add_parser(
        NAME,
        help="tenant-side provisioning (docs/ADMIN-SETUP.md) in one command",
        description=(
            "Run the ADMIN-SETUP tenant steps in order: pre-flight, Entra app "
            "registration + service principal, certificate credential, Exchange "
            "Online scoped role, then the config file and `mnotify doctor`. "
            "Idempotent — a re-run on a configured tenant reports `exists` "
            "everywhere and changes nothing."
        ),
    )
    steps = admin.add_subparsers(dest="admin_command", metavar="<action>")

    bootstrap = steps.add_parser(
        "bootstrap",
        help="create or verify the tenant objects and write the config",
        description=(
            "Preflight, Entra app + service principal, certificate upload, Exchange "
            "Online scoped role, config write, doctor. Every step looks before it "
            "creates, so re-running is safe. Nothing is installed and nobody is signed "
            "in without being asked."
        ),
    )
    bootstrap.add_argument(
        "--sender",
        metavar="ADDR",
        required=True,
        help="the one mailbox the app may send from (e.g. noreply@example.com)",
    )
    bootstrap.add_argument(
        "--allow-domain",
        action="append",
        default=None,
        metavar="DOMAIN",
        help="write an allowed recipient domain; repeatable. The bootstrap refuses to "
        "finish with an empty allowlist (every send would be refused, exit 3)",
    )
    bootstrap.add_argument(
        "--control-mailbox",
        metavar="ADDR",
        default=None,
        help="mailbox used as the Exchange negative control; must not be the sender. "
        "Default: the address `az` is signed in as",
    )
    bootstrap.add_argument(
        "--install-missing",
        action="store_true",
        help="offer to `brew install` what the pre-flight found missing (azure-cli, "
        "powershell). Needs a `y` at a prompt; refused without a terminal",
    )
    bootstrap.add_argument(
        "--force-config",
        action="store_true",
        help="overwrite an existing config file ([paths] and Teams targets are "
        "preserved, as with `mnotify setup --force`)",
    )
    bootstrap.add_argument(
        "--dry-run",
        action="store_true",
        help="print every az/pwsh command that would run, execute nothing, exit 0",
    )
    bootstrap.add_argument(
        "--json", action="store_true", help="machine-readable summary on stdout"
    )
    bootstrap.add_argument(
        "--send-test",
        metavar="ADDR",
        default=None,
        help="after everything, send one real test mail to ADDR through the normal "
        "mail path (spends one unit of the daily cap)",
    )
    # --- delegated mode (design amendment A.1-A.4, card D5) -------------------
    # Appended rather than folded into the flags above: `--mode` defaults to `app`,
    # so every app-only invocation parses and behaves exactly as it did before this
    # flag existed.
    bootstrap.add_argument(
        "--mode",
        choices=BOOTSTRAP_MODES,
        default=MODE_APP,
        help="which credential this tenant is configured for. `app` (the default) is "
        "the certificate + Exchange Online scoped-role route above. `delegated` "
        "configures the SAME registration for a person to sign in through: it declares "
        "the five delegated scopes of amendment A.2, turns on the public-client flows "
        "the device-code sign-in needs, and skips the certificate and the Exchange "
        "scoped role — neither is read by a delegated send. It does NOT grant any "
        "application permission.",
    )
    bootstrap.add_argument(
        "--admin-consent",
        action="store_true",
        help="delegated mode only: also ask Entra for tenant-wide admin consent for "
        "exactly those five delegated scopes. Needs the privilege; if it is refused "
        "the bootstrap WARNS and continues, because `mnotify login` consents the same "
        "scopes for the signed-in user alone. Refused in app mode: app-only tenants "
        "send through the Exchange scoped role and must not gain a consented Graph "
        "permission (docs/ADMIN-SETUP.md §3.1)",
    )


# --- Reporting ---------------------------------------------------------------
class Step:
    """One line of the report: which step, and what it made of it.

    ``outcome`` stays an opaque string rather than an enum: the parents own
    ``created``/``exists`` and this layer adds ``dryrun``/``skipped``.
    """

    def __init__(self, name: str, outcome: str, detail: str = "") -> None:
        self.name = name
        self.outcome = outcome
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "outcome": self.outcome}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class Report:
    """Accumulates the steps and owns how they are printed.

    Human mode prints one line per step as it happens — a bootstrap can wait on a
    browser sign-in, so a wall of output at the end is useless. ``--json`` mode prints
    exactly one document at the end, on stdout; progress lines are dropped and child
    output (the device-code prompt, doctor's own report) is routed to stderr, so an
    operator who asked for JSON gets a parseable stdout.
    """

    def __init__(self, machine: bool) -> None:
        self.machine = machine
        self.steps: list[Step] = []
        self.details: dict[str, Any] = {}
        self.exit_code = EXIT_OK

    # --- recording ---------------------------------------------------------
    def add(self, name: str, outcome: str, detail: str = "") -> Step:
        step = Step(name, outcome, detail)
        self.steps.append(step)
        if not self.machine:
            print(f"{name}: {outcome}" + (f" — {detail}" if detail else ""))
            sys.stdout.flush()
        return step

    def note(self, key: str, value: Any) -> None:
        """Attach a machine-readable fact to the summary (tenant id, config path)."""
        self.details[key] = value

    def line(self, text: str) -> None:
        """Progress for a human. Dropped in machine mode so stdout stays one document."""
        if not self.machine:
            print(text)

    def echo(self, text: str) -> None:
        """A line that must reach the operator even under ``--json`` (device-code prompt)."""
        stream = sys.stderr if self.machine else sys.stdout
        print(text, file=stream)
        stream.flush()

    # --- emitting ----------------------------------------------------------
    def summary(self, *, ok: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": ok,
            "exitCode": self.exit_code,
            "steps": [step.to_dict() for step in self.steps],
        }
        payload.update(self.details)
        return payload

    def emit(self, *, ok: bool) -> int:
        if self.machine:
            print_json(self.summary(ok=ok))
        return self.exit_code


# --- Argument validation -----------------------------------------------------
def _valid_sender(address: str, flag: str = "--sender") -> str:
    """A plain mailbox address, or an error naming the flag.

    Stricter than the config loader on purpose: this value is interpolated into a
    PowerShell variable and into an ``az`` ``--id`` argument, and B4 applies the same
    rule before it builds anything. Catching it here names the flag instead of
    surfacing three steps later as an ``ExchangeError``.
    """
    value = (address or "").strip()
    if (
        "@" not in value
        or value.count("@") != 1
        or value.startswith("@")
        or value.endswith("@")
        or any(ch.isspace() for ch in value)
        or "://" in value
    ):
        raise BootstrapError(
            f"{flag} must be one mailbox address, e.g. noreply@example.com (got "
            f"{address!r})"
        )
    return value


def _valid_domains(values: Sequence[str] | None) -> tuple[str, ...]:
    domains: list[str] = []
    for raw in values or ():
        value = (raw or "").strip().lower()
        if not value:
            raise BootstrapError("--allow-domain must not be empty")
        if "@" in value or any(ch.isspace() for ch in value) or "://" in value:
            raise BootstrapError(
                f"--allow-domain must be a bare domain (example.com), not an address "
                f"or a URL: {raw!r}"
            )
        if value not in domains:
            domains.append(value)
    return tuple(domains)


# --- The install gate --------------------------------------------------------
def _is_tty() -> bool:
    """Whether a human is on the other end of stdin. A seam for the tests."""
    return sys.stdin is not None and sys.stdin.isatty()


def _confirm_installs(formulas: Sequence[str]) -> bool:
    """Ask about exactly the formulas B1 said are brew-installable.

    The prompt names what will be installed: a bare "install missing? [y/N]" invites a
    yes that means two packages' worth of software. EOF or a read error counts as "no" —
    a closed pipe must not install anything.
    """
    names = " ".join(formulas)
    if not _is_tty():
        raise BootstrapError(
            f"--install-missing needs a terminal to ask before installing {names}, and "
            f"none is attached. Install them yourself (`brew install {names}`) and "
            "re-run, or drop the flag"
        )
    print(INSTALL_PROMPT.format(formulas=names), end="", file=sys.stderr)
    sys.stderr.flush()
    try:
        answer = (sys.stdin.readline() if sys.stdin is not None else "").strip().lower()
    except OSError:
        answer = ""
    return answer in ("y", "yes")


@contextlib.contextmanager
def _restored_runner() -> Iterator[None]:
    """Put the runner back exactly as this command found it, whatever happens.

    ``--dry-run`` installs a recording runner process-wide, so leaving it behind
    would make every later command in the same process silently stop executing —
    in production that means a subsequent ``mnotify`` invocation inside the same
    Python process would report success having done nothing. That is why this is a
    ``finally`` and not a happy-path reset.

    The restore is a *restore*, not a hard reset to the default: a harness that
    installed its own runner before calling ``run()`` (a test, or an embedding
    caller) keeps it. Resetting to ``None`` here would hand the second half of such
    a run the real :class:`SubprocessRunner`, i.e. a real ``az`` — the difference
    between a fake tenant and mutating a live one. When nothing was installed
    beforehand, ``get_runner()`` hands back a fresh default runner, so restoring it
    is the same behaviour as the default.
    """
    previous = admin_runner.get_runner()
    try:
        yield
    finally:
        set_runner(previous)


def _install_via_brew(formulas: Sequence[str], report: Report) -> None:
    """Run ``brew install`` for the names B1 approved, through the runner seam.

    Only ever called after an explicit ``y``. B1's contract is *formula names only*
    (deliberately excluding the Exchange PowerShell module, which comes from the
    Gallery and is not a brew formula), so the argv is assembled here and the names are
    passed through unchanged.
    """
    argv = ["brew", "install", *formulas]
    report.line(f"running: {' '.join(argv)}")
    result = admin_runner.get_runner().run([str(a) for a in argv])
    returncode = int(getattr(result, "returncode", 1) or 0)
    if returncode != 0:
        raise BootstrapError(
            f"`brew install {' '.join(formulas)}` exited {returncode}; nothing was "
            "provisioned. Install the missing tools and re-run the bootstrap"
        )


# --- The real-machine runner -------------------------------------------------
# The runner the real CLI installs lives in B1's module, where the other runners
# live: :class:`micro_notify.admin.runner.StreamingRunner` (streaming + per-binary
# timeouts, including ``PWSH_TIMEOUT`` for pwsh and ``BREW_TIMEOUT`` for brew). What
# stays here is the *policy* of when it applies — see :func:`_use_streaming_runner`.


def _use_streaming_runner() -> None:
    """Replace the *plain default* runner with :class:`StreamingRunner`.

    Deliberately narrow: the swap happens only when the active runner is exactly
    B1's :class:`~micro_notify.admin.runner.SubprocessRunner`, i.e. the real CLI.
    Anything else — a test's fake, a dry run's recorder, a runner an embedding
    caller installed — is left in place. Bypassing an installed fake would send the
    flow to a real ``az`` in a process that believes it is talking to a placeholder
    tenant, and it would make this command untestable.
    """
    active = admin_runner.get_runner()
    if type(active) is admin_runner.SubprocessRunner:
        set_runner(StreamingRunner())


# --- Preflight ---------------------------------------------------------------
def _failing_line(report: preflight.PreflightReport) -> str:
    parts = [f"{check.name}: {check.detail}" for check in report.failing]
    return "; ".join(parts) if parts else "the pre-flight did not pass"


def _print_checks(report: preflight.PreflightReport, out: Report) -> None:
    """The per-check verdicts, with the fix hint on the line below a failure."""
    for check in report.checks:
        out.line(f"  {check.name}: {check.status} — {check.detail}")
        if check.status == preflight.FAIL and check.fix_hint:
            out.line(f"    fix: {check.fix_hint}")


def _refuse_failing_preflight(
    report: preflight.PreflightReport, formulas: Sequence[str]
) -> None:
    """Stop before the first write, naming the failing checks and the way out."""
    fix = ""
    if formulas:
        fix = f" (or re-run with `--install-missing` to install {', '.join(formulas)})"
    raise BootstrapError(
        f"pre-flight failed: {_failing_line(report)}. Nothing was provisioned{fix}"
    )


def _preflight_step(
    sender: str, install_missing: bool, out: Report, *, include_exchange: bool = True
) -> preflight.PreflightReport:
    """1. B1's six read-only checks, plus the opt-in install round.

    The install round is a *second* pre-flight, not a patched first one: B1's report is
    the answer to "what is wrong with this machine right now", and editing it afterwards
    would make it describe a state no check ever observed. So: probe -> ask -> install ->
    probe again, and the second report is what everything downstream reads.

    ``include_exchange=False`` (delegated mode) hands B1's own flag straight through:
    the delegated route never calls `pwsh`, so failing two PowerShell checks it cannot
    use would refuse a machine that is perfectly ready (see B1's
    :func:`~micro_notify.admin.preflight.run_preflight`).
    """
    first = preflight.run_preflight(sender, include_exchange=include_exchange)
    _print_checks(first, out)
    if first.ok:
        out.add(STEP_PREFLIGHT, OUTCOME_EXISTS, "all checks already pass")
        return first

    formulas = preflight.plan_installs(first)
    if not install_missing:
        _refuse_failing_preflight(first, formulas)
    if not formulas:
        # `--install-missing` was offered nothing brew can install (an un-logged-in az,
        # a missing role, the Exchange module from the Gallery). Saying so and stopping is
        # honest; installing nothing and carrying on would be a lie of omission.
        raise BootstrapError(
            "`--install-missing` has nothing to install for these failures — "
            f"{_failing_line(first)}. Fix them as the hints above say, then re-run"
        )
    if not _confirm_installs(formulas):
        raise BootstrapError(
            f"install declined, so {', '.join(formulas)} is still missing and nothing "
            "was provisioned. Re-run and answer y, or install them yourself"
        )

    _install_via_brew(formulas, out)
    second = preflight.run_preflight(sender, include_exchange=include_exchange)
    _print_checks(second, out)
    if not second.ok:
        _refuse_failing_preflight(second, preflight.plan_installs(second))
    out.add(STEP_PREFLIGHT, OUTCOME_CREATED, f"installed {', '.join(formulas)}")
    return second


# --- Dry-run -----------------------------------------------------------------
# Canned answers that describe a FRESH tenant: every lookup answers "not found", so the
# plan reaches the creates a first run needs rather than showing a no-op. A dry run must
# work on a machine with no `az` and no network (B1's rule), which is why these are
# canned rather than probed. Keys are argv prefixes, longest-match wins (DryRunRunner).
DRY_RUN_RESPONSES: dict[tuple[str, ...], str] = {
    ("az", "account", "show"): (
        '{"tenantId": "00000000-0000-0000-0000-000000000000", '
        '"user": {"name": "admin@contoso.com"}}'
    ),
    ("az", "account", "tenant", "list"): (
        '[{"tenantId": "00000000-0000-0000-0000-000000000000", '
        '"displayName": "contoso.com"}]'
    ),
    ("az", "rest",): '{"value": [{"displayName": "Global Administrator"}]}',
    ("az", "ad", "user", "show"): '{"userPrincipalName": "noreply@example.com"}',
    ("az", "ad", "app", "list"): "[]",
    ("az", "ad", "sp", "list"): "[]",
    ("az", "ad", "app", "create"): '{"appId": "00000000-0000-0000-0000-000000000000"}',
    ("az", "ad", "sp", "create"): '{"id": "ffffffff-ffff-ffff-ffff-ffffffffffff"}',
    ("pwsh",): "3.11.0",
}


def _command_line(argv: Sequence[str]) -> str:
    """One recorded argv as a printable line."""
    return " ".join(str(a) for a in argv)


class _PlanPrinter:
    """Prints each command the moment the runner records it.

    Printing as they are recorded (rather than in a list at the end) is what makes a
    dry run read like the real thing, and it means the printed commands *are* the ones
    the code built — the dry run cannot advertise a command the step would not run.
    """

    def __init__(self, runner: DryRunRunner, out: Report) -> None:
        self._runner = runner
        self._out = out
        self._seen = 0

    def flush(self) -> None:
        for argv in self._runner.calls[self._seen :]:
            self._out.echo(_command_line(argv))
        self._seen = len(self._runner.calls)

    def planned(self, lines: Sequence[str]) -> None:
        """Print a step's own plan surface (B3/B4 publish these; nothing is executed)."""
        for line in lines:
            self._out.echo(line)


def _dry_run(sender: str, args: argparse.Namespace, out: Report) -> int:
    """Print every command the bootstrap would run, and run none of them.

    B1's :class:`~micro_notify.admin.runner.DryRunRunner` is installed as the
    process-wide runner first, so nothing anywhere in the flow can execute — the
    probes, the ``az`` writes, a ``brew`` call and the ``pwsh`` script all land in
    ``runner.calls`` instead. The steps that are pure ``az`` (the pre-flight probes and
    B2's find-then-create) are actually *run* under it, so the printed commands come
    from the real code paths; the two steps with a local half that bypasses the seam
    (B3's key generation, B4's temp script) print their published plans instead, which
    is what those cards declare as their dry-run surface and why both refuse a
    recording runner on their write path.

    The mode branch is a step-list branch, not a second dry run: the pre-flight and the
    Entra step are the same calls with the same printer in both modes, and only the
    middle of the flow differs. Delegated steps are pure ``az``, so they are *run*
    under the recorder rather than printed from a parallel plan — the same rule B5 set,
    and why the plan cannot advertise a command the step would not run.

    Exits 0 whatever the canned answers say: a dry run reports a plan, it does not
    grade the tenant.
    """
    # Reuse a recording runner the caller already installed (a harness, or an
    # embedding caller); otherwise install this command's own. Reusing matters: a
    # runner someone else installed is the one the steps will actually talk to, so
    # printing from a *different* DryRunRunner would print nothing — the dry run
    # would report an empty plan and still exit 0, which is the worst possible
    # failure for a flag whose whole job is to show the plan.
    active = admin_runner.get_runner()
    runner = active if isinstance(active, DryRunRunner) else DryRunRunner(DRY_RUN_RESPONSES)
    if runner is not active:
        set_runner(runner)
    printer = _PlanPrinter(runner, out)
    # No try/finally here: the runner belongs to the caller's `_restored_runner`,
    # which puts it back whatever happens (see there). A dry run reports a plan, it
    # does not grade the tenant, so it never raises on purpose.
    out.line("# dry run: every line below is a command that WOULD run; nothing is executed")

    report = preflight.run_preflight(sender)
    printer.flush()
    out.add(STEP_PREFLIGHT, OUTCOME_DRYRUN, "read-only probes recorded, none executed")
    _print_checks(report, out)
    if args.install_missing:
        # The install command is only ever run behind a y/N answer, and a dry run
        # asks nothing — so the line is planned, with the formula name shown as a
        # marker because which formulas are needed depends on a probe not run.
        printer.planned(["brew install <formula>"])

    from ..admin import entra

    provisioning = entra.ensure_entra_app()
    printer.flush()
    out.add(STEP_ENTRA, OUTCOME_DRYRUN, f"would report: {provisioning.detail}")
    app_id = provisioning.app_id or DRY_APP_ID
    sp_object_id = provisioning.sp_object_id or DRY_SP_OBJECT_ID

    if _mode_of(args) == MODE_DELEGATED:
        return _dry_run_delegated(app_id, sp_object_id, args, out, printer)
    return _dry_run_app_only(
        sender, app_id, sp_object_id, args, report, out, printer
    )


def _dry_run_app_only(
    sender: str,
    app_id: str,
    sp_object_id: str,
    args: argparse.Namespace,
    report: Any,
    out: Report,
    printer: _PlanPrinter,
) -> int:
    """The certificate + Exchange-scoped-role half of the plan (B5's original)."""
    # B3's write path refuses a recording runner (it would generate a real key and
    # rewrite the keychain while the tenant stayed unchanged) — so print its plan.
    # `plan_certificate_upload` returns ONE argv as a token list (B3's shape, unlike
    # B4's plan_commands which already returns lines), so it joins to a single line:
    # printing tokens one per line would scatter the command across the plan.
    printer.planned([" ".join(plan_certificate_upload(app_id))])
    out.add(
        STEP_CERTIFICATE,
        OUTCOME_DRYRUN,
        "planned the upload; no key generated and nothing written to the keychain",
    )

    control = _dry_control_mailbox(args, report)
    printer.planned(plan_commands(app_id, sp_object_id, sender, admin_mailbox=control))
    out.add(STEP_EXCHANGE, OUTCOME_DRYRUN, "planned the script; no file written or run")

    out.add(STEP_CONFIG, OUTCOME_DRYRUN, "no config file written")
    out.add(STEP_DOCTOR, OUTCOME_SKIPPED, "nothing was changed, so nothing to verify")
    if getattr(args, "send_test", None):
        out.add(STEP_SEND_TEST, OUTCOME_SKIPPED, "a dry run sends nothing")

    out.note("dryRun", True)
    out.note("sender", sender)
    out.note("allowDomains", list(_valid_domains(args.allow_domain)))
    out.note("controlMailbox", _dry_control_mailbox(args, report))
    out.note("appId", app_id)
    out.exit_code = EXIT_OK
    return out.emit(ok=True)


def _dry_run_delegated(
    app_id: str,
    sp_object_id: str,
    args: argparse.Namespace,
    out: Report,
    printer: _PlanPrinter,
) -> int:
    """The delegated half of the plan: permissions, the switch, consent, nothing else.

    Two things this deliberately does *not* print, both of them the point:

    * no certificate upload and no Exchange script — a delegated send reads neither,
      and a plan that showed them would advertise credential work the mode does not do
      (the card's regression guard, pinned from the other side too);
    * no ``admin-consent`` line unless ``--admin-consent`` was passed. A dry run that
      showed a tenant-wide consent nobody asked for would be the worst kind of surprise.

    The device-code prompt is reported rather than printed: a dry run must not look
    like it is asking the operator to sign in.
    """
    from ..admin import delegated_setup

    scopes = list(delegation.DELEGATED_SCOPES)

    # The reads the real step makes, through the seam, then the writes it would make.
    delegated_setup.show_app(app_id)
    delegated_setup.graph_resource(scopes)
    printer.flush()
    for name in scopes:
        printer.planned([_command_line(delegated_setup.permission_add_argv(app_id, DRY_SCOPE_ID))])
    out.add(
        STEP_PERMISSIONS,
        OUTCOME_DRYRUN,
        f"would declare {len(scopes)} delegated scopes ({', '.join(scopes)}); "
        f"no application permission is touched",
    )

    delegated_setup.show_app(app_id)
    printer.flush()
    printer.planned(
        [_command_line(delegated_setup.public_client_enable_argv(app_id))]
    )
    out.add(
        STEP_PUBLIC_CLIENT,
        OUTCOME_DRYRUN,
        f"would set {DRY_PUBLIC_CLIENT_FLAG}; delegated mode only — an app-only tenant "
        "keeps it false",
    )

    if getattr(args, "admin_consent", False):
        delegated_setup.list_grants_argv(sp_object_id)
        delegated_setup.graph_resource(scopes)
        printer.flush()
        printer.planned(
            [
                _command_line(
                    delegated_setup.consent_grant_argv(
                        sp_object_id, DRY_GRAPH_SP_OBJECT_ID, scopes
                    )
                )
            ]
        )
        out.add(
            STEP_CONSENT,
            OUTCOME_DRYRUN,
            "would request admin consent for the delegated scopes only; a refusal "
            "warns and continues (user consent via `mnotify login` still works)",
        )
    else:
        out.add(
            STEP_CONSENT,
            OUTCOME_SKIPPED,
            "not requested: pass --admin-consent, or consent per user with `mnotify login`",
        )

    out.add(
        STEP_SIGNIN,
        OUTCOME_SKIPPED,
        f"a dry run does not sign anyone in — the real run ends with the device-code "
        f"flow of `mnotify login` and {DRY_SIGNIN_UPN} becomes the config sender",
    )
    out.add(STEP_CONFIG, OUTCOME_DRYRUN, "no config file written")
    out.add(STEP_DOCTOR, OUTCOME_SKIPPED, "nothing was changed, so nothing to verify")
    if getattr(args, "send_test", None):
        out.add(STEP_SEND_TEST, OUTCOME_SKIPPED, "a dry run sends nothing")

    out.note("dryRun", True)
    out.note("mode", MODE_DELEGATED)
    out.note("sender", _valid_sender(args.sender))
    out.note("allowDomains", list(_valid_domains(args.allow_domain)))
    out.note("appId", app_id)
    out.note("delegatedScopes", scopes)
    out.exit_code = EXIT_OK
    return out.emit(ok=True)


def _dry_control_mailbox(args: argparse.Namespace, report: Any) -> str:
    """The control mailbox for the printed plan: the flag, else the dry-run UPN.

    The canned ``az account show`` answer above carries the UPN, so the printed script
    and the summary agree on one value. It is a placeholder address like every other
    value a dry run prints.
    """
    explicit = (getattr(args, "control_mailbox", None) or "").strip()
    if explicit:
        return _valid_sender(explicit, "--control-mailbox")
    upn = getattr(report, "signed_in_upn", None) if report is not None else None
    return upn or DRY_CONTROL_MAILBOX


# --- The write steps ---------------------------------------------------------
def _entra_step(out: Report) -> Any:
    """2. The app registration and its service principal (B2, find-first)."""
    from ..admin import entra

    result = entra.ensure_entra_app()
    out.add(STEP_ENTRA, result.outcome, result.detail)
    out.note("appId", result.app_id)
    out.note("spObjectId", result.sp_object_id)
    return result


def _certificate_step(app_id: str, out: Report) -> Any:
    """3. The certificate credential on the app registration (B3)."""
    from ..admin import certupload

    result = certupload.ensure_certificate_credential(app_id)
    out.add(STEP_CERTIFICATE, result.outcome, result.detail)
    out.note("thumbprint", result.thumbprint)
    if result.expires_at:
        out.note("certificateExpiresAt", result.expires_at)
    return result


def _exchange_step(
    app_id: str, sp_object_id: str, sender: str, control: str, out: Report
) -> Any:
    """4. The Exchange Online scoped role, and the proof that it holds (B4)."""
    from ..admin import exo

    if not supports_streaming():
        # Said up front: with a capturing runner the device-code line reaches the
        # terminal only after the sign-in finishes, and an operator watching a silent
        # screen cannot tell a slow browser from a dead process.
        out.echo(
            "mnotify: the pwsh runner in use captures output, so the device-code line "
            "appears only after the sign-in completes. " + DEVICE_CODE_HINT
        )
    result = exo.ensure_exchange_scope(
        app_id, sp_object_id, sender, control, echo=out.echo
    )
    out.add(STEP_EXCHANGE, result.outcome, result.detail)
    out.note("scopeName", result.scope_name)
    out.note("controlMailbox", result.admin_mailbox)
    return result


# --- The delegated-mode steps (D5, design amendment A.2 / A.4 §6 step 6) ------
def _permissions_step(app_id: str, out: Report) -> Any:
    """D.1 Declare the five delegated scopes on the shared registration.

    The scope list is :data:`micro_notify.delegation.DELEGATED_SCOPES` — the same
    tuple the sign-in requests — so the app can never be configured for fewer scopes
    than a login asks for (which would fail at the consent screen, after the tenant
    was already mutated). The declaration is additive and touches no ``Role`` entry;
    see ``admin/delegated_setup.py`` for why that rules out az's ``--set +=``.
    """
    from ..admin import delegated_setup

    result = delegated_setup.ensure_delegated_permissions(
        app_id, delegation.DELEGATED_SCOPES
    )
    out.add(STEP_PERMISSIONS, result.outcome, result.detail)
    out.note("delegatedScopes", list(delegation.DELEGATED_SCOPES))
    return result


def _public_client_step(app_id: str, out: Report) -> Any:
    """D.2 ``isFallbackPublicClient`` = true: the device-code flow's only switch.

    Loudly conditional (the card's word, and amendment A.2's table): this flag belongs
    to the *whole registration*, and this is the only line of code in the project that
    turns it on. It runs only under ``--mode delegated``; an app-only tenant keeps it
    false, and flipping it there would open a registration that holds a certificate
    credential to public-client flows for no reason.
    """
    from ..admin import delegated_setup

    result = delegated_setup.ensure_public_client_flows(app_id)
    out.add(STEP_PUBLIC_CLIENT, result.outcome, result.detail)
    out.note("publicClientFlows", True)
    return result


def _consent_step(sp_object_id: str, out: Report) -> Any:
    """D.3 Optional tenant-wide consent for exactly the five scopes.

    The whole point of ``--admin-consent`` being opt-in and warn-and-continue: the
    privilege often is not there (verification-blocked tenants), and the delegated
    flow works without tenant-wide consent — the operator's own sign-in consents the
    same scopes for themselves. A refusal is therefore ``skipped`` carrying the reason
    as its detail, never a failed run; under ``--json`` that step entry is the only
    place the reason can appear, because ``ok``/``exitCode`` are the only failure
    channels and neither may open for a warn.
    """
    from ..admin import delegated_setup

    result = delegated_setup.ensure_admin_consent(
        sp_object_id, delegation.DELEGATED_SCOPES
    )
    if result.warned:
        out.add(STEP_CONSENT, OUTCOME_SKIPPED, result.detail)
        out.note("consentHint", delegated_setup.CONSENT_HINT)
    else:
        out.add(STEP_CONSENT, result.outcome, result.detail)
    out.note("adminConsent", result.to_dict())
    return result


def _signin_args(*, machine: bool, no_prompt: bool) -> argparse.Namespace:
    """The namespace ``commands/login.py`` expects for one sign-in."""
    return argparse.Namespace(no_prompt=no_prompt, json=machine)


def _signin_step(out: Report) -> str:
    """D.4 ``mnotify login``, delegated rather than re-implemented — and last.

    Same contract B5 set for doctor: login owns its own printing (the device-code
    prompt goes to its stderr, the result line to its stdout), so under our ``--json``
    its stdout is routed to stderr and the bootstrap's summary stays the single
    document on stdout.

    The order is the interesting part. The *verify* comes first
    (``login --no-prompt`` — the cache-only check, which never prompts): on a re-run
    of an already-configured tenant the sign-in reports ``exists`` and no operator is
    ever asked to open a browser twice. Only when the cache cannot produce a token
    does the interactive device-code flow start — after every tenant write, so the
    operator is asked exactly once, at the point where the tenant is ready for them.

    Returns the signed-in UPN, which becomes the config's sender: amendment A.3 makes
    the sender the identity in the token, so this value is the only honest one to
    write, and the caller refuses to write a config whose sender is some other address.
    """
    from . import login as login_module

    def _run(*, no_prompt: bool) -> int:
        if out.machine:
            with contextlib.redirect_stdout(sys.stderr):
                return login_module.run(_signin_args(machine=True, no_prompt=no_prompt))
        return login_module.run(_signin_args(machine=False, no_prompt=no_prompt))

    try:
        _run(no_prompt=True)
        out.add(STEP_SIGNIN, OUTCOME_EXISTS, "cached delegated sign-in still works")
    except AuthError:
        # Not a failure — the fresh-tenant state. The interactive flow is the fix,
        # and this is the same AuthError that would exit 4 if it were raised by the
        # interactive call below, where it genuinely is a failure.
        _run(no_prompt=False)
        out.add(STEP_SIGNIN, OUTCOME_CREATED, "signed in via the device-code flow")

    identity = delegation.whoami()  # reads the keychain only; never returns a token
    if not identity.upn:
        raise AuthError(
            f"signed in but the cached identity names no user; {delegation.LOGIN_HINT}"
        )
    out.note("signedInAs", identity.upn)
    return identity.upn


# --- The config write --------------------------------------------------------
def _previous_config(path: Path) -> Config | None:
    """The earlier config when it parses; ``None`` when absent or unusable.

    Same rule as ``mnotify setup``: a file that cannot be parsed has nothing worth
    preserving, so a rewrite the operator just confirmed proceeds from defaults rather
    than refusing the rewrite.
    """
    if not path.exists():
        return None
    try:
        return load_config(path)
    except UsageError:
        return None


def _config_step(
    tenant_id: str,
    app_id: str,
    sender: str,
    domains: Sequence[str],
    force: bool,
    out: Report,
    *,
    mode: str = MODE_APP,
    auth: str | None = None,
) -> Path:
    """5. Write the config with the same keys ``mnotify setup`` writes.

    ``auth`` is ``certificate`` in the default app-only mode because that is the only
    credential that command establishes (B3 uploaded the public half); ``tenant_id``
    comes from the signed-in directory and ``client_id`` from the app B2 resolved,
    which is the whole advantage over the manual path — nothing is typed.

    In delegated mode (``mode=`` :data:`MODE_DELEGATED`, D5) two values change and
    nothing else does: ``mode`` becomes ``delegated`` and ``sender`` is the UPN the
    sign-in produced, because amendment A.3 makes the sender the identity in the token
    rather than a mailbox the app impersonates. ``auth`` stays ``certificate`` — see
    :func:`_bootstrap_delegated` for why a delegated run writes no new credential.

    A file that already says exactly what this run would say is *not* rewritten: the
    re-run reports ``exists`` and leaves the bytes (and the mtime) alone, which is what
    makes the idempotent re-run a genuine no-op. A file that says something *different*
    is refused unless ``--force-config`` was passed — someone edited it, and silently
    overwriting their choice of sender during a run that only meant to re-verify the
    tenant is the failure mode a flag is for.

    ``mode`` is part of the "says exactly the same thing" test, on purpose: a config
    that matches on tenant, client, sender and auth but declares the other mode is not
    a match, and writing over it without ``--force-config`` would flip which credential
    every later send uses.

    This command owns ``[mail]`` and ``[allow]`` and nobody else's: ``[paths]``, the
    Teams targets **and** ``[limits]`` carry over from whatever is already there. The
    ``[limits]`` part is one step beyond ``setup --force``, which resets them to the
    defaults, and the difference is deliberate — a bootstrap re-run is a routine,
    expected operation, and quietly reverting an operator's raised ``daily_max`` to 200
    during a run that only meant to re-check the tenant would be an unannounced
    downgrade.
    """
    path = config_path()
    previous = _previous_config(path)
    wanted_auth = auth if auth is not None else AUTH_CERTIFICATE

    mail_matches = previous is not None and (
        previous.mail.tenant_id == tenant_id
        and previous.mail.client_id == app_id
        and previous.mail.sender == sender
        and previous.mail.auth == wanted_auth
        and previous.mail.mode == mode
    )
    allow_matches = previous is not None and tuple(previous.allow.domains) == tuple(domains)
    if previous is not None and not (mail_matches and allow_matches):
        if not force:
            raise BootstrapError(
                f"{path} already holds different [mail]/[allow] values than this run "
                f"would write (sender {previous.mail.sender!r} -> {sender!r}; mode "
                f"{previous.mail.mode!r} -> {mode!r}). Re-run with `--force-config` to "
                "overwrite it, or edit the file yourself (`mnotify config show` prints "
                "it with secrets masked)"
            )
        out.line(f"overwriting {path} (--force-config)")

    if previous is not None and mail_matches and allow_matches:
        # Nothing to write: the file already describes this tenant and this sender.
        out.note("configPath", str(path))
        out.add(STEP_CONFIG, OUTCOME_EXISTS, f"{path} (unchanged)")
        return path

    config = Config(
        mail=MailConfig(
            tenant_id=tenant_id,
            client_id=app_id,
            sender=sender,
            auth=wanted_auth,
            mode=mode,
        ),
        allow=AllowConfig(domains=tuple(domains)),
        limits=previous.limits if previous is not None else LimitsConfig(),
        paths=previous.paths if previous is not None else PathsConfig(),
        teams_targets=previous.teams_targets if previous is not None else (),
        source_path=path,
    )
    written = write_config(config, path)
    out.add(
        STEP_CONFIG,
        OUTCOME_EXISTS if previous is not None else OUTCOME_CREATED,
        str(written),
    )
    out.note("configPath", str(written))
    return written


# --- Doctor and the optional test send ---------------------------------------
def _doctor_args(*, send_test: str | None, machine: bool) -> argparse.Namespace:
    """The namespace ``commands/doctor.py`` expects for one doctor run."""
    return argparse.Namespace(send_test=send_test, json=machine)


def _doctor_step(send_test: str | None, out: Report) -> int:
    """6. ``mnotify doctor``, delegated rather than re-implemented.

    Doctor owns its own printing — including its own ``--json`` document — so under our
    ``--json`` its stdout is routed to stderr: the bootstrap's summary stays the single
    JSON document on stdout. In human mode it prints straight through to the terminal
    (its own stdout, its own fix hints), which is why the one-line verdict here never
    repeats what doctor just said.
    """
    if out.machine:
        with contextlib.redirect_stdout(sys.stderr):
            code = doctor_module.run(
                _doctor_args(send_test=send_test, machine=True)
            )
    else:
        code = doctor_module.run(_doctor_args(send_test=send_test, machine=False))
    out.add(
        STEP_DOCTOR,
        OUTCOME_EXISTS if code == EXIT_OK else OUTCOME_SKIPPED,
        "checks green" if code == EXIT_OK else f"doctor exited {code} (see its report)",
    )
    out.note("doctorExit", code)
    if code != EXIT_OK:
        out.exit_code = code
    return code


def _send_test_step(address: str, out: Report, doctor_exit: int) -> None:
    """Report the test send the doctor check performed.

    Doctor already does the send when it is given ``--send-test`` — through
    :func:`micro_notify.commands.mail.run`, so the guard, the daily counter and the
    audit line all come from the real send path. Sending again here would spend the
    daily cap twice to prove the same thing, so this step records what doctor proved and
    names the recipient masked, the way doctor does.
    """
    masked = doctor_module.mask_address(address)
    out.note("testRecipient", masked)
    out.add(
        STEP_SEND_TEST,
        OUTCOME_CREATED if doctor_exit == EXIT_OK else OUTCOME_SKIPPED,
        f"one message sent to {masked}" if doctor_exit == EXIT_OK else "not sent",
    )


# --- Entry point -------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    """``mnotify admin ...`` — dispatch to the subcommand."""
    action = getattr(args, "admin_command", None)
    if action == "bootstrap":
        return bootstrap(args)
    raise UsageError("an admin action is required: bootstrap (see `mnotify admin --help`)")


def bootstrap(args: argparse.Namespace) -> int:
    """``mnotify admin bootstrap`` — the ADMIN-SETUP procedure, in order, idempotent."""
    sender = _valid_sender(args.sender)
    domains = _valid_domains(args.allow_domain)
    mode = _mode_of(args)

    # `--admin-consent` in app mode is refused rather than ignored. The flag can only
    # do one of two things there: grant a Graph delegated consent the app-only route
    # never uses, or — worse, if it were widened to the app's `Role` entries — hand the
    # tenant the whole-directory Mail.Send consent ADMIN-SETUP §3.1 tells the operator
    # to *remove*. Ignoring it silently would leave the operator believing they had
    # consented something.
    if getattr(args, "admin_consent", False) and mode == MODE_APP:
        raise BootstrapError(
            "`--admin-consent` needs `--mode delegated`: an app-only tenant sends "
            "through the Exchange Online scoped role (ADMIN-SETUP §2) and must not "
            "gain a consented Graph permission — §3.1 removes the tenant-wide consent "
            "on purpose. Drop the flag, or run the delegated bootstrap"
        )

    # The empty-allowlist refusal comes first, before the first probe. Not tidiness:
    # otherwise the bootstrap mutates the tenant and then hands over a config where every
    # send exits 3, with `doctor`'s own allow check as the only clue. The fix is one flag
    # on the command the operator is already typing.
    if not domains:
        raise BootstrapError(f"an empty allowlist refuses every send. {EMPTY_ALLOWLIST_HINT}")

    out = Report(bool(getattr(args, "json", False)))
    out.note("sender", sender)
    out.note("allowDomains", list(domains))
    out.note("mode", mode)

    # The runner is a process-wide global. A dry run installs a recording runner, and
    # nothing may be left behind if the run raises partway through — a recording
    # runner still installed would make a later command in the same process report
    # success having done nothing. The context manager puts it back whatever happens.
    with _restored_runner():
        if args.dry_run:
            return _dry_run(sender, args, out)

        # Only the real CLI gets the streaming runner (see there): the Exchange step's
        # device-code prompt has to reach the terminal while pwsh is still waiting.
        _use_streaming_runner()

        report = _preflight_step(
            sender, args.install_missing, out, include_exchange=mode == MODE_APP
        )
        out.note("preflight", report.to_dict())
        if report.tenant_id:
            out.note("tenantId", report.tenant_id)
        if report.tenant_name:
            out.note("tenantName", report.tenant_name)

        if mode == MODE_DELEGATED:
            return _bootstrap_delegated(sender, domains, args, report, out)

        control = _control_mailbox(args, report, sender)
        out.note("controlMailbox", control)

        entra = _entra_step(out)
        _certificate_step(entra.app_id, out)
        _exchange_step(entra.app_id, entra.sp_object_id, sender, control, out)
        # Only now: every value the config advertises has been proven to exist.
        _config_step(
            report.tenant_id or "",
            entra.app_id,
            sender,
            domains,
            bool(getattr(args, "force_config", False)),
            out,
        )
        code = _doctor_step(getattr(args, "send_test", None), out)
        if getattr(args, "send_test", None):
            _send_test_step(args.send_test, out, code)

    return out.emit(ok=code == EXIT_OK)


def _bootstrap_delegated(
    sender: str,
    domains: Sequence[str],
    args: argparse.Namespace,
    report: preflight.PreflightReport,
    out: Report,
) -> int:
    """``mnotify admin bootstrap --mode delegated`` — the delegated route, in order.

    The shared frame is untouched: the same pre-flight (minus the two PowerShell
    checks, which this route never needs — see :func:`_preflight_step`), the same B2
    find-first app registration, the same config writer, the same doctor. What differs
    is the middle: instead of a certificate and an Exchange scoped role, this run
    declares the five delegated scopes, turns on the public-client flow, optionally
    consents them, and finishes by signing the operator in.

    Two steps the app-only route has and this one does not, and neither is an omission:
    no certificate (a delegated send builds no confidential client, so a key here would
    be a credential the tool never reads) and no Exchange scoped role (the sender is the
    signed-in person, not a mailbox the app impersonates — amendment A.3).
    """
    entra = _entra_step(out)
    _permissions_step(entra.app_id, out)
    _public_client_step(entra.app_id, out)
    if getattr(args, "admin_consent", False):
        _consent_step(entra.sp_object_id, out)

    # The config before the sign-in, because the sign-in needs it: amendment A.1 puts
    # the delegated login on *this* registration, and `mnotify login` reads its client
    # id and tenant from `[mail]`. On a fresh tenant that file does not exist yet, so
    # login would fail on its own missing config before a human ever saw a code.
    #
    # The sender written here is the operator's declared `--sender`; the sign-in below
    # is what proves that address is a person who can actually sign in, and
    # :func:`_require_signed_in_as` refuses to let the run call itself successful when
    # the identity in the token is somebody else.
    _config_step(
        report.tenant_id or "",
        entra.app_id,
        sender,
        domains,
        bool(getattr(args, "force_config", False)),
        out,
        mode=MODE_DELEGATED,
    )
    signed_in = _signin_step(out)
    _require_signed_in_as(signed_in, sender)

    code = _doctor_step(getattr(args, "send_test", None), out)
    if getattr(args, "send_test", None):
        _send_test_step(args.send_test, out, code)

    return out.emit(ok=code == EXIT_OK)


def _require_signed_in_as(upn: str, sender: str) -> None:
    """The delegated mode's one hard identity rule, checked before ``doctor``.

    Amendment A.3: in delegated mode the sender *is* the identity in the token, so a
    config whose sender is an address nobody is signed in as cannot be honoured at all
    — every send would fail with the sender-mismatch refusal (exit 2) D2 built into the
    send path. Saying so here, right after the sign-in, is the difference between an
    operator who fixes it in one command and one who discovers it at the first send.

    The config is deliberately *not* rewritten to match the token. The operator passed
    ``--sender`` on purpose, and quietly changing the mailbox a tool sends from is the
    kind of surprise a bootstrap must not commit; the hint names both ways out.
    """
    if upn.casefold() == sender.casefold():
        return
    raise BootstrapError(
        f"signed in as {upn} but this run was asked to configure sender {sender!r}. "
        "In delegated mode the sender must be the signed-in person (design amendment "
        "A.3), so either `mnotify logout` and sign in again as "
        f"{sender!r}, or re-run with `--sender {upn}`"
    )


def _control_mailbox(
    args: argparse.Namespace, report: preflight.PreflightReport, sender: str
) -> str:
    """The mailbox B4 uses as its negative control, or the refusal to pick one.

    B4 requires a second, *different* mailbox whose ``InScope`` must come back False: a
    scope that also covers the signed-in admin is a scope that was never restricted, and
    a sender-equals-admin pair raises before anything is written. B1's
    :attr:`~micro_notify.admin.preflight.PreflightReport.signed_in_upn` is the default
    because it is the only address proven to exist and to sit outside a sender-scoped
    role; ``--control-mailbox`` overrides it for the case where the operator is signed in
    as the sender itself.
    """
    explicit = (getattr(args, "control_mailbox", None) or "").strip()
    control = _valid_sender(explicit, "--control-mailbox") if explicit else ""
    if not control:
        control = (report.signed_in_upn or "").strip()
    if not control:
        raise BootstrapError(
            f"no mailbox to use as the Exchange negative control. {CONTROL_MAILBOX_HINT}"
        )
    if control.casefold() == sender.casefold():
        raise BootstrapError(
            f"the Exchange negative control must be a different mailbox from --sender "
            f"({sender}). {CONTROL_MAILBOX_HINT}"
        )
    return control


__all__ = [
    "BOOTSTRAP_STEPS",
    "BUILD_STEP",
    "CONTROL_MAILBOX_HINT",
    "EMPTY_ALLOWLIST_HINT",
    "INSTALL_PROMPT",
    "NAME",
    "OUTCOME_CREATED",
    "OUTCOME_DRYRUN",
    "OUTCOME_EXISTS",
    "OUTCOME_SKIPPED",
    "Report",
    "STEP_CERTIFICATE",
    "STEP_CONFIG",
    "STEP_DOCTOR",
    "STEP_ENTRA",
    "STEP_EXCHANGE",
    "STEP_PREFLIGHT",
    "STEP_SEND_TEST",
    "Step",
    "add_parser",
    "bootstrap",
    "run",
]
