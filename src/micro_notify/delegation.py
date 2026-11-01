"""Delegated (as-a-person) auth: device-code sign-in and the keychain token cache.

Design contract: ``docs/design/2026-10-27-micro-notify-design.md`` section 2 plus
**Amendment 2026-10-30, sections A.1–A.3** (delegated mode). This module owns the
auth half of that amendment; the send paths that consume :func:`get_delegated_token`
belong to the mail/Teams cards, and the ``[mail] mode`` schema belongs to
:mod:`micro_notify.config` (never edit that file from here — the seams
``MAIL_MODE_APP`` / ``MAIL_MODE_DELEGATED`` are already declared).

Why our own app registration (A.1): the Azure CLI's first-party app carries neither
``Mail.Send`` nor ``ChatMessage.Send`` and scopes cannot be added to an app you do
not own, so a delegated sign-in must ride the ``micro-notify`` registration. The
client id and tenant therefore come from ``[mail]``, exactly as in app-only mode.

The cache is the user's identity (A.2), so three rules are structural here rather
than advisory:

* the serialised msal cache lives in **one keychain item** — service ``mnotify``,
  account :data:`ACCOUNT_DELEGATED_CACHE` — read and written only through
  :mod:`micro_notify.secrets`, which takes the value in argv of a single exec and
  names the *account* (never a value) in its errors;
* it is **never on disk**: the cache is an in-memory ``msal.SerializableTokenCache``
  handed to msal via ``token_cache=``, so msal's own file persistence is never
  engaged and this module opens no files at all;
* it is **never printed**: the only values this module emits are the device-code
  prompt (which is public by design — it is shown to the person typing it), the
  signed-in UPN, and an expiry timestamp. No function returns, logs or formats a
  token, and error messages carry msal's ``error`` code only.

Every msal call site is a module attribute (``delegation.msal``) so tests patch it,
following the same seam :mod:`micro_notify.graph` uses.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import msal

from . import AuthError
from . import secrets
from .config import MAIL_MODE_DELEGATED, MailConfig, load_config
from .graph import AUTHORITY_TEMPLATE

# Design amendment A.2: exactly these five delegated scopes, nothing more.
# Order is part of the contract — it is what Entra lists in the consent prompt,
# and the tests pin it verbatim. Adding a sixth scope requires amending A.2 first.
DELEGATED_SCOPES: tuple[str, ...] = (
    "Mail.Send",
    "ChatMessage.Send",
    "Chat.ReadBasic",
    "User.Read",
    "offline_access",
)

# msal reserves these and adds them to every request itself; passing one to
# initiate_device_flow or acquire_token_silent raises ValueError ("You cannot use
# any scope value that is reserved"). offline_access stays in DELEGATED_SCOPES
# because that tuple is also what the app registration declares, but every msal
# call gets REQUEST_SCOPES: the same scopes, same order, minus the reserved ones.
MSAL_RESERVED_SCOPES: frozenset[str] = frozenset({"openid", "profile", "offline_access"})
REQUEST_SCOPES: tuple[str, ...] = tuple(
    scope for scope in DELEGATED_SCOPES if scope not in MSAL_RESERVED_SCOPES
)

# The single keychain account holding the serialised cache (A.2 / A.4). The value
# lives in secrets.py — the file that names every keychain account — and is re-exported
# here because delegation.py is its only reader and `from micro_notify.delegation
# import ACCOUNT_DELEGATED_CACHE` is what the commands and the docs quote. One literal,
# two names; renaming it means amending A.4 first.
ACCOUNT_DELEGATED_CACHE = secrets.ACCOUNT_DELEGATED_CACHE

# What an operator who is stuck has to do. Kept as one constant so every refusal
# names the same remedy.
LOGIN_HINT = "run mnotify login"

# msal's device-code poll can outlive the operator's patience; this is the wall
# clock we are willing to wait for a human to finish the browser step.
DEVICE_FLOW_TIMEOUT_SECONDS = 900.0

# Claims that can name the signed-in person, in preference order (A.3: the sender
# is always the signed-in identity, so this value is load-bearing).
_UPN_CLAIMS = ("preferred_username", "upn", "email")


@dataclass(frozen=True)
class LoginResult:
    """What a successful sign-in tells the caller. Deliberately token-free."""

    upn: str
    expires_at: float | None
    mode: str = MAIL_MODE_DELEGATED


@dataclass(frozen=True)
class WhoamiResult:
    """The cached identity (design A.4: ``whoami`` prints the UPN, never a token).

    ``mode`` is always :data:`~micro_notify.config.MAIL_MODE_DELEGATED` — this
    cache can only ever describe a delegated identity. ``expires_at`` is the
    access token's expiry, or ``None`` when the cache holds no live access token.
    """

    upn: str
    mode: str
    expires_at: float | None


# --- Keychain-backed cache --------------------------------------------------
def _read_cache_state() -> str:
    """The serialised cache from the keychain, or ``""`` when there is none.

    A read failure is folded into "no cache" on purpose: :func:`secrets.get`
    cannot tell "item absent" from "keychain unusable" (its error is account-only
    by design), and both answers lead to the same safe action — sign in again. The
    fold only ever *denies* a send, so it is fail-closed: an unreadable cache can
    produce a login prompt, never a leaked or half-valid token. ``logout`` reads the
    keychain too and lets a real failure surface as exit 4.
    """
    try:
        return secrets.get(ACCOUNT_DELEGATED_CACHE)
    except secrets.KeychainError:
        return ""


def _new_cache(state: str) -> msal.SerializableTokenCache:
    """An msal cache loaded from a keychain state string — in memory only, never a file."""
    cache = msal.SerializableTokenCache()
    if state:
        try:
            cache.deserialize(state)
        except ValueError as exc:
            # Corrupt item: refuse rather than send half a credential set. The
            # remedy is a fresh sign-in, which overwrites the item.
            raise AuthError(
                f"delegated token cache in '{ACCOUNT_DELEGATED_CACHE}' is unreadable "
                f"({type(exc).__name__}); {LOGIN_HINT}"
            ) from exc
    return cache


def _persist(cache: msal.SerializableTokenCache) -> None:
    """Write the cache back to the keychain, but only when it actually changed.

    ``has_state_changed`` is msal's own dirty flag. Skipping an unchanged write
    keeps `mnotify whoami` from touching the keychain at all.
    """
    if not cache.has_state_changed:
        return
    secrets.set_secret(ACCOUNT_DELEGATED_CACHE, cache.serialize())


def _build_app(cache: msal.SerializableTokenCache, mail: MailConfig):
    """The msal public client for our registration, with the keychain cache wired in.

    ``token_cache=`` is the whole persistence story: msal writes tokens into this
    in-memory object and nowhere else. ``client_credential`` stays unset — a public
    client has none, and passing one would turn this into a confidential client.
    """
    try:
        return msal.PublicClientApplication(
            client_id=mail.client_id,
            authority=AUTHORITY_TEMPLATE.format(tenant_id=mail.tenant_id),
            token_cache=cache,
        )
    except ValueError as exc:
        # msal raises ValueError when authority discovery fails (bad tenant id,
        # unreachable endpoint) — an auth failure, not a crash. Same treatment as
        # graph.acquire_token, and the message carries msal's text only.
        raise AuthError(f"Graph authority discovery failed ({exc})") from exc


def _mail_config(mail: MailConfig | None) -> MailConfig:
    return mail if mail is not None else load_config().mail


# --- Identity extraction ----------------------------------------------------
def _decode_claims(id_token: str) -> dict[str, Any]:
    """Decode an ID token's payload **without validating it**.

    Same stance msal itself takes (its tokens arrive over a TLS channel straight
    from the token endpoint, and it does not verify the signature either): this is
    a display and self-check aid, not an authorisation decision. Never raises —
    an undecodable token simply yields no claims and the caller falls back.
    """
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (IndexError, ValueError, TypeError, UnicodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _identity(cache: msal.SerializableTokenCache) -> str:
    """The signed-in UPN held by the cache, or ``""`` when the cache names nobody.

    msal stores the ID token as a **raw JWT string** in the entry's ``secret`` —
    it does not keep a parsed ``id_token_claims`` key (verified against msal
    1.39). The token is decoded here and then dropped on the floor: the value that
    leaves this function is the UPN claim only, never the token itself.
    """
    for entry in cache.search(msal.TokenCache.CredentialType.ID_TOKEN):
        claims = entry.get("id_token_claims")
        if not isinstance(claims, dict):
            claims = _decode_claims(str(entry.get("secret", "")))
        for claim in _UPN_CLAIMS:
            value = claims.get(claim)
            if isinstance(value, str) and value.strip():
                return value.strip()
    # An account entry can carry the username even when no id token was cached.
    for entry in cache.search(msal.TokenCache.CredentialType.ACCOUNT):
        value = entry.get("username")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _access_expiry(cache: msal.SerializableTokenCache) -> float | None:
    """Latest unexpired access-token expiry in the cache, or ``None``.

    msal prunes expired access tokens on search, so an entry here is one it still
    considers usable. The expiry is read defensively: a malformed entry is treated
    as "no known expiry" rather than crashing a diagnostic command.
    """
    latest: float | None = None
    for entry in cache.search(msal.TokenCache.CredentialType.ACCESS_TOKEN):
        try:
            value = float(entry.get("expires_on", ""))
        except (TypeError, ValueError):
            continue
        if latest is None or value > latest:
            latest = value
    return latest


# --- Public API -------------------------------------------------------------
def login(
    interactive: bool = True,
    *,
    mail: MailConfig | None = None,
    printer: Callable[[str], None] | None = None,
    timeout: float = DEVICE_FLOW_TIMEOUT_SECONDS,
) -> LoginResult:
    """Sign a person in and cache the tokens in the keychain.

    ``interactive=True`` runs the device-code flow: msal's own prompt (code and
    verification URL) is printed verbatim — it is public information meant for the
    person at the keyboard — and the call then blocks while msal polls, up to
    ``timeout`` seconds.

    ``interactive=False`` never starts a flow and never blocks on a human: it only
    checks that the existing cache can still produce a token (silent refresh), and
    raises :class:`~micro_notify.AuthError` naming :data:`LOGIN_HINT` otherwise.
    That is what ``mnotify login --no-prompt`` uses from a script.

    Never returns or prints a token. Raises :class:`~micro_notify.AuthError`
    (exit 4) for a refused, expired, interrupted or otherwise failed sign-in.
    """
    resolved = _mail_config(mail)
    emit = printer if printer is not None else (lambda text: print(text, file=sys.stderr))
    cache = _new_cache(_read_cache_state())
    app = _build_app(cache, resolved)

    if not interactive:
        # Same accept/reject rule as get_delegated_token: only a result carrying a
        # fresh access_token counts, so a server-side "invalid_grant" on the
        # refresh token cannot masquerade as a working sign-in.
        account = _only_account(app)
        if account is None:
            raise AuthError(f"no delegated sign-in cached; {LOGIN_HINT}")
        result = app.acquire_token_silent(list(REQUEST_SCOPES), account)
        _persist(cache)
        if not isinstance(result, dict) or not result.get("access_token"):
            code = (result or {}).get("error", "not_refreshable")
            raise AuthError(f"cached delegated sign-in cannot produce a token ({code}); {LOGIN_HINT}")
        return LoginResult(
            upn=_identity(cache) or str(account.get("username", "")),
            expires_at=_access_expiry(cache),
        )

    flow = app.initiate_device_flow(scopes=list(REQUEST_SCOPES))
    if not isinstance(flow, dict) or flow.get("error") or "device_code" not in flow:
        code = (flow or {}).get("error", "flow_not_started")
        raise AuthError(f"device-code sign-in could not start ({code}); {LOGIN_HINT}")

    # msal composes the operator-facing prompt itself; print it verbatim so the
    # wording matches what Microsoft documents. Fall back to the raw fields when
    # a (fake or future) flow dict carries no message.
    prompt = flow.get("message")
    if not isinstance(prompt, str) or not prompt.strip():
        url = flow.get("verification_uri") or flow.get("verification_uri_complete", "")
        prompt = f"To sign in, open {url} and enter the code {flow.get('user_code', '')}".strip()
    emit(prompt.rstrip())

    # Bound the wait by shortening the flow's own expiry: msal's poll loop ends when
    # ``expires_at`` passes (its documented abort switch), which is the only way to
    # stop while a human is still deciding. A clock check *after* the call would be
    # unreachable. Ctrl-C is deliberately not caught here — cli.py maps
    # KeyboardInterrupt to 130, the shell convention, and this call is the only
    # blocking one in the command.
    if isinstance(flow.get("expires_at"), (int, float)):
        flow["expires_at"] = min(float(flow["expires_at"]), time.time() + max(float(timeout), 0.0))

    result = app.acquire_token_by_device_flow(flow)

    _persist(cache)  # even a failed flow may have pruned a dead refresh token
    if not isinstance(result, dict) or not result.get("access_token"):
        code = (result or {}).get("error", "no_token")
        raise AuthError(f"delegated sign-in did not produce a token ({code}); {LOGIN_HINT}")

    upn = _identity(cache) or str((result.get("id_token_claims") or {}).get("preferred_username", ""))
    if not upn:
        raise AuthError(f"signed in but the token names no user; {LOGIN_HINT}")
    return LoginResult(upn=upn, expires_at=_access_expiry(cache))


def _only_account(app: Any) -> dict[str, Any] | None:
    """The single account in the cache, or ``None``.

    This tool caches exactly one delegated identity (one keychain account, one
    registration), so a multi-account cache is unexpected: use the first and let
    :func:`whoami` show who it is.
    """
    accounts = app.get_accounts() or []
    return accounts[0] if accounts else None


def logout() -> bool:
    """Delete the local delegated token cache (:meth:`A.2` revocation level 1).

    Idempotent: an absent item is success, not an error. The return value is
    additive to the card's ``-> None`` contract (a caller that ignores it behaves
    identically) and exists so `mnotify logout` can say whether anything was
    removed. What this does **not** do is revoke anything server-side — the hard
    revoke is Entra's "Revoke sessions" (and removing the delegated consent), and
    the CLI says so.
    """
    return secrets.delete(ACCOUNT_DELEGATED_CACHE)


def whoami() -> WhoamiResult:
    """Report the cached identity: UPN, mode and access-token expiry. No token value.

    Reads the keychain only — no config file, no network, no msal client — so it
    answers "am I signed in, and as whom" even when the config is broken. Raises
    :class:`~micro_notify.AuthError` (exit 4) when nothing is cached.
    """
    cache = _new_cache(_read_cache_state())
    upn = _identity(cache)
    if not upn:
        raise AuthError(f"nobody is signed in; {LOGIN_HINT}")
    return WhoamiResult(upn=upn, mode=MAIL_MODE_DELEGATED, expires_at=_access_expiry(cache))


def get_delegated_token() -> str:
    """A usable delegated access token, refreshed silently where possible.

    The caller's contract: either a token comes back, or
    :class:`~micro_notify.AuthError` (exit 4) says what to do about it, always
    naming :data:`LOGIN_HINT`. Absent cache, dead refresh token and a refused
    silent call all take that one path, because from the caller's side they want
    the same answer.

    A refreshed or pruned cache is written back to the keychain before returning;
    an unchanged cache is not rewritten at all.
    """
    state = _read_cache_state()
    if not state:
        raise AuthError(f"no delegated sign-in cached; {LOGIN_HINT}")
    cache = _new_cache(state)
    app = _build_app(cache, _mail_config(None))
    account = _only_account(app)
    if account is None:
        raise AuthError(f"no delegated sign-in cached; {LOGIN_HINT}")

    result = app.acquire_token_silent(list(REQUEST_SCOPES), account)
    _persist(cache)
    if not isinstance(result, dict) or not result.get("access_token"):
        code = (result or {}).get("error", "no_token")
        raise AuthError(f"delegated token is absent or expired ({code}); {LOGIN_HINT}")
    return str(result["access_token"])


__all__ = [
    "ACCOUNT_DELEGATED_CACHE",
    "DELEGATED_SCOPES",
    "DEVICE_FLOW_TIMEOUT_SECONDS",
    "LOGIN_HINT",
    "LoginResult",
    "MSAL_RESERVED_SCOPES",
    "REQUEST_SCOPES",
    "WhoamiResult",
    "get_delegated_token",
    "login",
    "logout",
    "whoami",
]
