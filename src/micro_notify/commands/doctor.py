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

Two modes, one report shape (design amendment 2026-10-30, D4). When ``[mail] mode``
is ``delegated`` the operator signed in as a person with ``mnotify login``, so the
app-only questions ("is the certificate in the keychain", "does the app-only token
carry Mail.Send") are the wrong questions — a delegated install has neither, and
asking for them would make ``doctor`` report a missing credential that the design
deliberately does not use. The check *order* therefore adapts:

    app:        config -> keychain -> teams -> token -> allow -> send-test
    delegated:  config -> keychain -> teams -> token -> scopes -> sender -> allow -> send-test

The names ``config``, ``keychain``, ``teams``, ``token``, ``allow`` and
``send-test`` keep their meaning in both modes (in delegated mode ``token`` is the
cached delegated token's expiry rather than an app-only acquisition), and the two
delegated-only checks are ``scopes`` and ``sender``. App mode's checks, including the
tri-state ``token: warn`` behaviour above, are untouched and byte-identical.

Delegated mode reads the token cache the way ``mnotify whoami`` does — one keychain
item, decoded in memory, never printed. What it reports is *presence*, *expiry time*,
*the scope names granted* and *the UPN*, which are exactly the four things amendment
A.4 allows a diagnostic to say. The ``scp``/``target`` grant is authoritative here in
a way the app-mode ``roles`` claim is not: it is the scope list the token itself was
issued for, so a missing ``ChatMessage.Send`` is a real failure rather than a
not-verifiable warning. The states that are only a warning are the ones a refresh
token can still answer for — an access token past its expiry, or none cached at all
because msal pruned it — since ``mnotify mail send`` refreshes either silently, and
declaring them broken would make doctor unsatisfiable an hour after every login (the
t_24a04813 lesson, applied to the new mode instead of re-litigated).

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
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import msal

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
from .. import delegation
from .. import secrets
from ..config import KINDS_WITH_CHAT_ID, MAIL_MODE_DELEGATED, Config, load_config
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

# --- Delegated mode (design amendment 2026-10-30, D4) ------------------------
# The two scopes a delegated install needs to do what this tool does: send mail as
# the signed-in person (A.2, and the D2 send path) and post to a Teams chat (A.2 plus
# the D3 chat target). The other three granted scopes (Chat.ReadBasic, User.Read,
# offline_access) are supporting scopes and are not asserted here — a diagnostic that
# demanded them all would fail on a tenant where an admin trimmed the consent.
REQUIRED_DELEGATED_SCOPES: tuple[str, ...] = ("Mail.Send", "ChatMessage.Send")

SCOPE_HINT = (
    "re-run `mnotify login` to grant the scopes of design amendment A.2 (Mail.Send, "
    "ChatMessage.Send, Chat.ReadBasic, User.Read, offline_access); if the consent "
    "prompt does not list them, the app registration in Entra is missing the "
    "delegated permission — grant it there first (docs/ADMIN-SETUP.md)"
)

# The remedy for the one state no flag can fix: the token names a different person
# than the config's sender, and a delegated /me/sendMail has no other mailbox to send
# from (D2 refuses it the same way, before spending a token).
SENDER_HINT_TEMPLATE = "run `mnotify logout` then `mnotify login` as {upn}"


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    doctor = subparsers.add_parser(
        NAME,
        help="check config, keychain, token and Teams targets",
        description=(
            "Report config validity, keychain presence, token acquisition, the "
            "Mail.Send role and every Teams target URL. In [mail] mode = delegated "
            "the token checks are the cached sign-in's instead: expiry, the granted "
            "scopes, and that the signed-in UPN is the sender. Checks print presence "
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
    # A claim must be a list of strings. Anything else is a shape Entra does not
    # produce, so it is not evidence of anything and must not be read as "no roles".
    if not isinstance(raw, list) or not all(isinstance(role, str) for role in raw):
        return CLAIM_UNREADABLE, []
    return CLAIM_READ, list(raw)


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


def _expiry_text(epoch: float) -> str:
    """Human-readable expiry, same rendering ``mnotify whoami`` prints."""
    return datetime.fromtimestamp(epoch).isoformat(timespec="seconds")


# --- The delegated cache read (amendment A.4: presence, expiry, scopes, UPN) --
@dataclass(frozen=True)
class DelegatedCache:
    """What the cached delegated sign-in says about itself. Carries no token.

    Four facts, and they are the four amendment A.4 allows a diagnostic to print:
    whether anything is cached, what scopes the cache grants, when the access token
    expires, and whether a refresh token exists. The stored values themselves are
    never read into this object — see :func:`read_delegated_cache` for why that is
    structural and not just a convention.
    """

    readable: bool
    scopes: tuple[str, ...]
    expires_at: float | None
    has_refresh_token: bool


def read_delegated_cache(state: str) -> DelegatedCache:
    """Read presence / scopes / expiry out of the serialised msal cache, read-only.

    Deliberately *not* ``cache.search()``:

    * ``search()`` deletes expired access tokens as a side effect (msal prunes them
      from the cache it was handed). A diagnostic must not rewrite the operator's
      credential blob — and pruning would hide exactly the expired entry this check
      exists to report. The cache is never persisted from here, so even an in-memory
      mutation would be a surprise; reading the serialised dict cannot mutate at all.
    * every value taken out of here is a *name* or a *number*: the ``target`` scope
      list and ``expires_on``. The entry key that holds a credential — ``secret`` —
      is never read, so no code path from this function to a printed line can carry a
      token. The identity comparison is separate and goes through
      :func:`micro_notify.delegation.whoami`, which has its own no-token pin.

    An unparseable value is reported as ``readable=False`` rather than raising: the
    caller's answer to that is the same as for any other broken sign-in (sign in
    again), and a diagnostic that crashes on a corrupt keychain item tells the
    operator nothing.
    """
    if not state:
        return DelegatedCache(readable=True, scopes=(), expires_at=None, has_refresh_token=False)
    try:
        sections = json.loads(state)
    except (ValueError, TypeError):
        return DelegatedCache(readable=False, scopes=(), expires_at=None, has_refresh_token=False)
    if not isinstance(sections, dict):
        return DelegatedCache(readable=False, scopes=(), expires_at=None, has_refresh_token=False)

    types = msal.TokenCache.CredentialType
    scopes: set[str] = set()
    expires_at: float | None = None
    has_refresh = False
    for section, credential_type in (
        ("AccessToken", types.ACCESS_TOKEN),
        ("RefreshToken", types.REFRESH_TOKEN),
    ):
        entries = sections.get(credential_type) or sections.get(section) or {}
        if not isinstance(entries, dict):
            # A section that exists but is not a table of entries is not "no tokens"
            # — it is a corrupt item, and the honest word for that is `readable=False`.
            # Reporting "nobody is signed in" instead would send the operator to look
            # for a sign-in window they already used.
            return DelegatedCache(readable=False, scopes=(), expires_at=None, has_refresh_token=False)
        for entry in entries.values():
            if not isinstance(entry, dict):
                # Same reasoning: a cache whose entry is not an object is broken, not
                # empty. msal's own shape is a table of objects.
                return DelegatedCache(readable=False, scopes=(), expires_at=None, has_refresh_token=False)
            target = entry.get("target")
            if isinstance(target, str):
                scopes.update(token for token in target.split() if token)
            if credential_type == types.REFRESH_TOKEN:
                # Presence of the entry is the fact; the value it holds is a
                # credential and is not read.
                has_refresh = True
                continue
            try:
                value = float(entry.get("expires_on", ""))
            except (TypeError, ValueError):
                continue
            if expires_at is None or value > expires_at:
                expires_at = value
    return DelegatedCache(
        readable=True,
        scopes=tuple(sorted(scopes)),
        expires_at=expires_at,
        has_refresh_token=has_refresh,
    )


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


def check_delegated_keychain(report: Report) -> bool:
    """2 (delegated mode). The token-cache account is present -> exit 4.

    The certificate/secret accounts are deliberately **not** required here: a
    delegated send never builds the confidential client and never reads them (D2), so
    demanding them would report a missing credential the design does not use — the
    same phantom-secret trap D1b documented for ``Config.keychain_accounts()``, which
    is why ``graph.delegated_token_cache`` lives outside that list and this check
    exists. Presence only, via :func:`micro_notify.secrets.has`: the value is a
    credential blob and is not read by this check.
    """
    if secrets.has(delegation.ACCOUNT_DELEGATED_CACHE):
        report.record("keychain", PASS, f"present: {delegation.ACCOUNT_DELEGATED_CACHE}")
        return True
    report.record(
        "keychain",
        FAIL,
        f"missing: {delegation.ACCOUNT_DELEGATED_CACHE}",
        hint=f"sign in with `mnotify login` (design amendment A.2) — service '{secrets.SERVICE}'",
        exit_code=EXIT_AUTH,
    )
    return False


def check_teams(report: Report, config: Config, *, delegated: bool = False) -> bool:
    """3. every configured Teams target has its webhook URL in the keychain -> exit 4.

    ``delegated=True`` makes a ``chat`` target *valid* rather than a phantom
    credential (amendment 2026-10-30, D3): a chat is addressed by the ``chat_id`` in
    the config file and posted to over Graph with the delegated token, so there is no
    webhook URL to look for. App mode passes no flag and behaves exactly as before,
    byte for byte — including a chat target, which app mode refuses to use at send
    time anyway.
    """
    needed = [
        target for target in config.teams_targets
        if not (delegated and target.kind in KINDS_WITH_CHAT_ID)
    ]
    if not config.teams_targets:
        report.record("teams", PASS, "no targets configured")
        return True
    missing = [
        secrets.teams_account(target.name)
        for target in needed
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
    detail = f"{len(needed)} target(s) have a URL"
    skipped = len(config.teams_targets) - len(needed)
    if skipped:
        detail += f"; {skipped} chat target(s) address Graph, so no webhook URL is expected"
    report.record("teams", PASS, detail)
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


def read_delegated_state() -> DelegatedCache:
    """The delegated cache facts, read from the keychain — read-only, no token out.

    One keychain read, one parse, no msal client: building a ``PublicClientApplication``
    performs tenant discovery over the network, which is the thing this command must not
    do without ``--send-test``. The value is read with :func:`micro_notify.secrets.get`
    and consumed inside :func:`read_delegated_cache`, which returns names and numbers
    only; a read failure is reported as unreadable rather than raised, so the caller
    answers with the same sign-in hint every other delegated refusal carries.
    """
    try:
        state = secrets.get(delegation.ACCOUNT_DELEGATED_CACHE)
    except secrets.KeychainError:
        return DelegatedCache(readable=False, scopes=(), expires_at=None, has_refresh_token=False)
    return read_delegated_cache(state)


def check_delegated_token(report: Report, cache: DelegatedCache) -> bool:
    """4 (delegated mode). Can this sign-in still produce a token? Report the expiry.

    One question decides whether the run may continue: *can this sign-in still
    authenticate?* The refresh token is the answer to it, which is why every branch
    below reads ``has_refresh_token`` rather than trusting the access token alone.

    * cache cannot be parsed -> ``fail`` exit 4. Nothing can be asserted about it,
      and the remedy is the same as for any broken sign-in.
    * no access token **and** no refresh token -> ``fail`` exit 4. There is nothing to
      send with and nothing to refresh; every delegated send would exit 4 anyway, so
      stopping here costs the operator nothing.
    * the access token is expired, or absent, **while a refresh token is cached** ->
      ``warn``, run continues. :func:`micro_notify.delegation.get_delegated_token`
      refreshes both of these silently — and the absent-access-token shape is
      reachable rather than theoretical: msal prunes expired access tokens during
      ``search()`` and the refresh path persists that pruning, so a cache that has
      been through one failed silent refresh holds only a refresh token. Failing it
      would be the t_24a04813 bug re-imported into the new mode: doctor unsatisfiable
      an hour after every login, ``allow`` skipped, and ``--send-test`` — the only
      proof that a delegated install works — made unreachable.

    The expiry time is printed whenever it is known, so an operator can see how long
    they have; a token value never is (amendment A.4).
    """
    if not cache.readable:
        report.record(
            "token",
            FAIL,
            f"delegated token cache in '{delegation.ACCOUNT_DELEGATED_CACHE}' is unreadable",
            hint=f"run `mnotify logout` then {delegation.LOGIN_HINT}",
            exit_code=EXIT_AUTH,
        )
        return False
    expires_at = cache.expires_at
    if expires_at is None and not cache.has_refresh_token:
        report.record(
            "token",
            FAIL,
            f"nobody is signed in — '{delegation.ACCOUNT_DELEGATED_CACHE}' holds neither an "
            "access token nor a refresh token, so no delegated send can authenticate",
            hint=delegation.LOGIN_HINT,
            exit_code=EXIT_AUTH,
        )
        return False
    if expires_at is None:
        # No access token, but the refresh token says the sign-in is alive.
        report.record(
            "token",
            WARN,
            f"no unexpired access token is cached in '{delegation.ACCOUNT_DELEGATED_CACHE}'; "
            f"a refresh token is cached so a send refreshes it silently — run "
            f"{delegation.LOGIN_HINT} to refresh it now",
        )
        return True
    expiry = _expiry_text(expires_at)
    if expires_at <= time.time():
        if not cache.has_refresh_token:
            report.record(
                "token",
                FAIL,
                f"delegated access token expired at {expiry} and no refresh token is cached, "
                "so no delegated send can authenticate",
                hint=delegation.LOGIN_HINT,
                exit_code=EXIT_AUTH,
            )
            return False
        report.record(
            "token",
            WARN,
            f"delegated access token expired at {expiry}; a refresh token is cached so a send "
            f"refreshes it silently — run {delegation.LOGIN_HINT} to refresh it now",
        )
        return True
    report.record("token", PASS, f"access token cached, expires at {expiry}")
    return True


def check_delegated_scopes(report: Report, cache: DelegatedCache) -> bool:
    """5 (delegated mode). The cached grant covers Mail.Send and ChatMessage.Send -> exit 4.

    Authoritative in a way the app-mode ``roles`` claim is not: the ``target`` list on a
    cached access token is the scope set the token was actually issued for, so a missing
    entry means Graph will refuse the send — there is no "invisible scoped role" state
    here to warn about. An expired-but-refreshable token is still read: its ``target``
    list is what the operator consented to, and a refresh is issued for that same grant,
    so a scope missing now will be missing after the refresh too.
    """
    missing = [scope for scope in REQUIRED_DELEGATED_SCOPES if scope not in cache.scopes]
    if missing:
        report.record(
            "scopes",
            FAIL,
            f"granted scopes do not include {', '.join(missing)} "
            f"(cached grant: {', '.join(cache.scopes) or 'empty'})",
            hint=SCOPE_HINT,
            exit_code=EXIT_AUTH,
        )
        return False
    report.record(
        "scopes", PASS, f"granted scopes include {', '.join(REQUIRED_DELEGATED_SCOPES)}"
    )
    return True


def check_delegated_sender(report: Report, config: Config) -> bool:
    """6 (delegated mode). The signed-in UPN is the effective sender -> exit 2.

    The D2 rule, checked before the operator spends a send finding out: a delegated
    ``/me/sendMail`` carries no sender in the path, so the mailbox is always the
    signed-in person's, and a ``[mail] sender`` naming somebody else is a config that
    cannot be honoured (``micro_notify.graph._delegated_send`` refuses it as a
    :class:`~micro_notify.config.ConfigError`, exit 2, before it acquires a token).
    Compared case-insensitively, exactly as that check does — a UPN's case is not
    meaningful to Entra, so an operator who typed the address in another case has not
    asked for a different mailbox.

    The identity comes from :func:`micro_notify.delegation.whoami` — the keychain-only
    read, not a fresh token — because D2 decided the *cached* identity is the effective
    sender, and doctor must compare against the same value the send path uses or the two
    would disagree. ``[mail] sender`` is always present here: config validation rejects a
    sender without an ``@``, so "sender unset, the UPN is the sender" is a state this
    command can never be handed.
    """
    try:
        identity = delegation.whoami()
    except AuthError as exc:
        report.record("sender", FAIL, exc.message, hint=delegation.LOGIN_HINT, exit_code=EXIT_AUTH)
        return False
    configured = config.mail.sender.strip()
    if configured.lower() == identity.upn.lower():
        report.record("sender", PASS, f"signed in as {identity.upn}, the effective sender")
        return True
    report.record(
        "sender",
        FAIL,
        f"signed in as {identity.upn} but [mail] sender is {configured} — a delegated "
        "send has no send-as-other, so the sender is always the signed-in person",
        hint=SENDER_HINT_TEMPLATE.format(upn=configured),
        exit_code=EXIT_USAGE,
    )
    return False


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
# The app-mode list is the design §4 order and is unchanged by the amendment; the
# delegated list keeps every shared name in the same relative order and inserts the two
# delegated-only checks where the card puts them — after the token check (a grant and an
# identity are only meaningful once something is cached) and before `allow`.
CHECK_ORDER = ("config", "keychain", "teams", "token", "allow", "send-test")
DELEGATED_CHECK_ORDER = (
    "config", "keychain", "teams", "token", "scopes", "sender", "allow", "send-test",
)


def check_names(delegated: bool) -> tuple[str, ...]:
    """The check names this mode reports, in order — the report's shape, per mode."""
    return DELEGATED_CHECK_ORDER if delegated else CHECK_ORDER


def run(args: argparse.Namespace) -> int:
    """``mnotify doctor`` — ordered checks, first failure wins, no secret printed."""
    machine = bool(getattr(args, "json", False))
    report = Report(machine)
    address = getattr(args, "send_test", None)

    config = check_config(report)
    if config is None:
        # The config is what names the mode, so with no config there is nothing to
        # branch on: report the app-mode remainder, as this command always has.
        report.skip_remaining([name for name in CHECK_ORDER if name != "config"])
        return report.emit()

    delegated = config.mail.mode == MAIL_MODE_DELEGATED
    remaining: list[str] = [name for name in check_names(delegated) if name != "config"]

    # The delegated cache is read once, and only by the checks that need it — after the
    # keychain presence check has said the account exists. Reading the value before the
    # presence check would invert exactly the ordering this module's docstring forbids.
    read: list[DelegatedCache] = []

    def delegated_cache() -> DelegatedCache:
        if not read:
            read.append(read_delegated_state())
        return read[0]

    steps = [
        ("keychain", lambda: check_delegated_keychain(report) if delegated else check_keychain(report, config)),
        ("teams", lambda: check_teams(report, config, delegated=delegated)),
        ("token", lambda: check_delegated_token(report, delegated_cache())
                       if delegated else check_token(report, config)),
    ]
    if delegated:
        steps += [
            ("scopes", lambda: check_delegated_scopes(report, delegated_cache())),
            ("sender", lambda: check_delegated_sender(report, config)),
        ]
    steps.append(("allow", lambda: check_allow(report, config)))

    for name, check in steps:
        remaining.remove(name)
        if not check():
            # Nothing downstream runs: whatever is left — `allow`, `send-test`, and in
            # delegated mode the checks the failure invalidates — is reported as skipped
            # rather than silently dropped.
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
    "DELEGATED_CHECK_ORDER",
    "FAIL",
    "NAME",
    "PASS",
    "REQUIRED_DELEGATED_SCOPES",
    "REQUIRED_ROLE",
    "ROLE_HINT",
    "ROLE_UNVERIFIABLE",
    "SCOPE_HINT",
    "SENDER_HINT_TEMPLATE",
    "SKIPPED",
    "WARN",
    "add_parser",
    "check_names",
    "mask_address",
    "read_delegated_cache",
    "read_roles_claim",
    "run",
]
