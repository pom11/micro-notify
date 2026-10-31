"""Delegated auth core (design amendment 2026-10-30, A.1–A.3).

The fake msal here is deliberately shallow but honest: ``PublicClientApplication``
is replaced (the seam ``tests/test_graph.py`` also uses), while
``msal.SerializableTokenCache`` and its credential schema stay **real** — that is
what makes the important pin mean something: the token cache really is serialised,
really is written through ``micro_notify.secrets`` (the shared ``fake_keychain``
fixture), and really is read back on the next call. msal's cache population is
simulated through its own public ``cache.add(event=...)`` entry point, the same one
the library uses internally, so the serialised shape is msal's, not ours.

No socket can open: the autouse ``no_network`` harness makes it impossible, and the
stub msal would not try anyway.
"""

from __future__ import annotations

import base64
import json
import time

import msal
import pytest

from micro_notify import EXIT_AUTH, AuthError, delegation, secrets
from micro_notify.config import MAIL_MODE_DELEGATED, MailConfig, load_config
from micro_notify.delegation import ACCOUNT_DELEGATED_CACHE
from micro_notify.secrets import SERVICE

# Placeholders only (design section 5): zero-GUIDs, contoso.com/example.com.
TENANT = "00000000-0000-0000-0000-000000000000"
CLIENT = "00000000-0000-0000-0000-000000000000"
PERSON = "person@contoso.com"

# Canary values: anything with these strings in it must never reach an exception
# message, stdout or stderr. They are the only values msal would cache as secrets.
CANARY_ACCESS = "AT-CANARY-DO-NOT-PRINT"
CANARY_REFRESH = "RT-CANARY-DO-NOT-PRINT"
CANARY_ID = "IDT-CANARY-DO-NOT-PRINT"

DEVICE_FLOW_MESSAGE = (
    "To sign in, use a web browser to open the page https://microsoft.com/devicelogin "
    "and enter the code ABCDEF123 to authenticate."
)
DEVICE_FLOW = {
    "device_code": "FAKE-DEVICE-CODE-VALUE",
    "user_code": "ABCDEF123",
    "verification_uri": "https://microsoft.com/devicelogin",
    "expires_in": 900,
    "interval": 5,
    "message": DEVICE_FLOW_MESSAGE,
}


def mail_config(**overrides) -> MailConfig:
    values = dict(
        tenant_id=TENANT,
        client_id=CLIENT,
        sender="noreply@example.com",
        auth="certificate",
        default_reply_to="",
    )
    values.update(overrides)
    return MailConfig(**values)


def _b64url(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
    return raw.decode("ascii").rstrip("=")


def fake_id_token(upn: str = PERSON) -> str:
    """An unvalidated, unsigned JWT-shaped string — shaped like a real ID token.

    msal stores the ID token in the cache as exactly this raw string (verified
    against msal 1.39), and delegation decodes it without checking the signature,
    so only the payload part matters here.
    """
    claims = {"sub": "local-sub-1", "tid": TENANT, "preferred_username": upn, "upn": upn}
    return ".".join([_b64url({"alg": "RS256", "typ": "JWT"}), _b64url(claims), CANARY_ID])


def token_response(
    *,
    expires_in: int | str = 3599,
    access_token: str = CANARY_ACCESS,
    refresh_token: str | None = CANARY_REFRESH,
    id_token: str | None = None,
) -> dict:
    response = {
        "token_type": "Bearer",
        "scope": " ".join(delegation.DELEGATED_SCOPES),
        "expires_in": str(expires_in),
        "access_token": access_token,
        "id_token": id_token if id_token is not None else fake_id_token(),
    }
    if refresh_token is not None:
        response["refresh_token"] = refresh_token
    return response


def ingest(cache: msal.SerializableTokenCache, response: dict, *, upn: str = PERSON) -> None:
    """Put a token response into a real msal cache the way msal itself does."""
    cache.add(
        event={
            "client_id": CLIENT,
            "scope": list(delegation.DELEGATED_SCOPES),
            "token_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
            "response": {**response, "client_info": _b64url({"uid": "uid-1", "utid": TENANT})},
            "username": upn,
            "actor": None,
            "analyzer": None,
            "resp_from_wsd": False,
        }
    )


def cache_state(**response_kwargs) -> str:
    """A serialised msal cache holding one sign-in — the keychain's stored value."""
    cache = msal.SerializableTokenCache()
    ingest(cache, token_response(**response_kwargs))
    return cache.serialize()


def state_without_a_readable_id_token() -> str:
    """A valid cache whose cached ID token cannot be decoded.

    Built by editing msal's own serialised shape rather than by feeding ``add()`` a
    bad token — msal's own cache entry point rejects one, which is exactly why the
    fallback in :func:`delegation._identity` matters: a half-written or tampered item
    must still name the person instead of crashing.
    """
    state = json.loads(cache_state())
    for entry in state.get("IdToken", {}).values():
        entry["secret"] = "not-a-json-jwt"
    return json.dumps(state)


class FakeApp:
    """Stand-in for ``msal.PublicClientApplication``; records, scripts, ingests."""

    def __init__(self, stub: FakeMsal, kwargs: dict) -> None:
        self.stub = stub
        self.kwargs = kwargs
        self.cache = kwargs["token_cache"]

    def initiate_device_flow(self, scopes=None, **_kwargs):
        self.stub.flows.append(list(scopes or []))
        return dict(self.stub.flow)

    def acquire_token_by_device_flow(self, flow, **_kwargs):
        self.stub.device_flows.append(dict(flow))
        result = self.stub.device_result
        if result is None:
            return {"error": "authorization_declined", "error_description": "user said no"}
        if result.get("access_token"):
            ingest(self.cache, result, upn=self.stub.upn)
        return dict(result)

    def acquire_token_silent(self, scopes, account=None, **_kwargs):
        self.stub.silent_calls.append((list(scopes), account))
        # Real msal answers from the cache first, and the cache here is real, so a
        # live access token is served from it rather than from a script. Only a
        # cache miss (absent or expired token) consults ``silent_result`` — which is
        # how a refresh, or a refusal, gets scripted.
        cached = list(
            self.cache.search(msal.TokenCache.CredentialType.ACCESS_TOKEN, target=list(scopes or []))
        )
        if cached:
            return {
                "access_token": cached[0]["secret"],
                "token_type": cached[0].get("token_type", "Bearer"),
            }
        result = self.stub.silent_result
        if result is None:
            return None
        if result.get("access_token") and self.stub.silent_changes_cache:
            ingest(self.cache, result, upn=self.stub.upn)
        return dict(result)

    def get_accounts(self, username=None):
        # Mirrors what real msal derives from the cache's account entries.
        accounts = [
            {"username": entry.get("username")}
            for entry in self.cache.search(msal.TokenCache.CredentialType.ACCOUNT)
        ]
        if username:
            accounts = [a for a in accounts if str(a["username"]).lower() == username.lower()]
        return accounts


class FakeMsal:
    """Script + record for the msal public client, handed out by ``fake_msal``."""

    def __init__(self) -> None:
        self.flow: dict = dict(DEVICE_FLOW, expires_at=time.time() + 900)
        self.device_result: dict | None = token_response()
        self.silent_result: dict | None = None
        self.silent_changes_cache = False
        self.upn = PERSON
        self.apps: list[dict] = []  # construction kwargs per app
        self.flows: list[list[str]] = []  # scopes per initiate_device_flow
        self.device_flows: list[dict] = []  # flow dicts passed to the poll
        self.silent_calls: list[tuple] = []

    @property
    def device_flow_calls(self) -> int:
        return len(self.device_flows)

    def make_app(self, **kwargs):
        self.apps.append(kwargs)
        return FakeApp(self, kwargs)


@pytest.fixture(autouse=True)
def _sandboxed_config(mnotify_config):
    """Point MICRO_NOTIFY_CONFIG at tmp_path for the whole module.

    :func:`delegation.get_delegated_token` reads [mail] for the client id and tenant,
    so without this a test would read the operator's real config file under
    ~/.config/mnotify — and pass or fail depending on what that machine happens to
    have, which is exactly the kind of environment-coupled green this suite forbids.
    """
    return mnotify_config


@pytest.fixture(autouse=True)
def fake_msal(monkeypatch: pytest.MonkeyPatch) -> FakeMsal:
    """Replace msal's public client with the stub; the token cache stays real.

    Autouse on purpose: a real ``PublicClientApplication`` performs tenant discovery
    over the network when built, so leaving it installed would make every test here
    depend on the socket harness to stay green (and would fail on a machine where the
    harness is not in force). The stub is also what scripts a silent refresh.
    """
    stub = FakeMsal()
    monkeypatch.setattr(delegation.msal, "PublicClientApplication", stub.make_app)
    return stub


@pytest.fixture
def signed_in(fake_keychain):
    """Keychain pre-loaded with one delegated sign-in (canary tokens inside)."""
    fake_keychain.seed(delegation.ACCOUNT_DELEGATED_CACHE, cache_state())
    return fake_keychain


def state_in(keychain) -> str:
    """The exact bytes the fake keychain holds for the delegated account."""
    return keychain.items.get(delegation.ACCOUNT_DELEGATED_CACHE, "")


# --- The contract constants (amendment A.2 / A.4) ----------------------------
def test_scopes_are_exactly_the_five_granted_by_the_amendment() -> None:
    """A.2 lists five scopes; the tuple, including its order, is the contract."""
    assert delegation.DELEGATED_SCOPES == (
        "Mail.Send",
        "ChatMessage.Send",
        "Chat.ReadBasic",
        "User.Read",
        "offline_access",
    )


def test_scopes_are_requested_verbatim_by_the_device_flow(fake_msal, fake_keychain) -> None:
    """The device flow must ask for exactly the amendment's five, in order."""
    delegation.login(mail=mail_config(), printer=lambda _text: None)
    assert fake_msal.flows == [list(delegation.DELEGATED_SCOPES)]


def test_scopes_are_requested_verbatim_by_the_silent_path(signed_in, fake_msal) -> None:
    """A silent refresh may not widen or reorder the scopes either."""
    fake_msal.silent_result = token_response()
    delegation.get_delegated_token()
    assert [call[0] for call in fake_msal.silent_calls] == [list(delegation.DELEGATED_SCOPES)]


def test_cache_account_is_the_one_the_amendment_named() -> None:
    """A.4 fixes the keychain account name; doctor and docs cite it verbatim."""
    assert delegation.ACCOUNT_DELEGATED_CACHE == "graph.delegated_token_cache"
    assert SERVICE == "mnotify"


def test_the_account_literal_lives_in_secrets_and_is_re_exported() -> None:
    """One literal for the account name: secrets.py owns it, delegation re-exports it.

    secrets.py is the file that names every keychain account (its docstring table is
    the design section 3.4 list), so a second copy of the string here would be a
    rename hazard — two places to change, one of which doctor could drift from.
    """
    assert secrets.ACCOUNT_DELEGATED_CACHE == "graph.delegated_token_cache"
    assert delegation.ACCOUNT_DELEGATED_CACHE is secrets.ACCOUNT_DELEGATED_CACHE


def test_app_only_configs_do_not_report_the_delegated_cache_as_missing() -> None:
    """A machine that never signs in delegationally has nothing missing.

    So the delegated account is deliberately *not* part of Config.keychain_accounts():
    adding it would make `config show` and app-only `doctor` shout MISSING at every
    existing install. The delegated presence check belongs to doctor's delegated-mode
    checks (D4), reached only when [mail] mode says so.
    """
    config = load_config()
    assert ACCOUNT_DELEGATED_CACHE not in config.keychain_accounts()
    assert ACCOUNT_DELEGATED_CACHE not in config.mail.keychain_accounts()


# --- login -------------------------------------------------------------------
def test_login_prints_the_device_flow_prompt_verbatim(fake_msal, fake_keychain) -> None:
    printed: list[str] = []
    delegation.login(mail=mail_config(), printer=printed.append)
    assert printed == [DEVICE_FLOW_MESSAGE]


def test_login_never_prints_the_device_code_value(fake_msal, fake_keychain) -> None:
    """The redeemable device_code stays internal; only the public code is shown."""
    printed: list[str] = []
    delegation.login(mail=mail_config(), printer=printed.append)
    assert all("FAKE-DEVICE-CODE-VALUE" not in line for line in printed)


def test_login_without_a_message_falls_back_to_url_and_code(fake_msal, fake_keychain) -> None:
    fake_msal.flow = {
        "device_code": "FAKE-DEVICE-CODE-VALUE",
        "user_code": "ABCDEF123",
        "verification_uri": "https://microsoft.com/devicelogin",
    }
    printed: list[str] = []
    delegation.login(mail=mail_config(), printer=printed.append)
    assert "https://microsoft.com/devicelogin" in printed[0]
    assert "ABCDEF123" in printed[0]


def test_login_builds_a_public_client_for_our_registration(fake_msal, fake_keychain) -> None:
    """A.1: our own registration, and a *public* client — no secret is shipped."""
    delegation.login(mail=mail_config(), printer=lambda _text: None)
    kwargs = fake_msal.apps[0]
    assert kwargs["client_id"] == CLIENT
    assert TENANT in kwargs["authority"]
    assert "client_credential" not in kwargs
    assert isinstance(kwargs["token_cache"], msal.SerializableTokenCache)


def test_login_reports_the_identity_and_an_expiry_not_a_token(fake_msal, fake_keychain) -> None:
    result = delegation.login(mail=mail_config(), printer=lambda _text: None)
    assert result.upn == PERSON
    assert result.mode == MAIL_MODE_DELEGATED
    assert result.expires_at is not None and result.expires_at > time.time()
    assert CANARY_ACCESS not in repr(result)
    assert CANARY_REFRESH not in repr(result)


def test_login_failure_is_an_auth_error_with_the_hint(fake_msal, fake_keychain) -> None:
    fake_msal.device_result = {"error": "authorization_declined"}
    with pytest.raises(AuthError) as excinfo:
        delegation.login(mail=mail_config(), printer=lambda _text: None)
    assert "authorization_declined" in excinfo.value.message
    assert "run mnotify login" in excinfo.value.message
    assert excinfo.value.exit_code == EXIT_AUTH


def test_login_flow_that_cannot_start_names_the_hint(fake_msal, fake_keychain) -> None:
    fake_msal.flow = {"error": "invalid_client"}
    with pytest.raises(AuthError, match="run mnotify login"):
        delegation.login(mail=mail_config(), printer=lambda _text: None)
    assert fake_msal.device_flow_calls == 0  # refused before any polling


def test_login_caps_the_wait_by_shortening_the_flow_expiry(fake_msal, fake_keychain) -> None:
    """msal's poll ends when expires_at passes, so the cap must live in the dict."""
    fake_msal.flow["expires_at"] = time.time() + 86400
    delegation.login(mail=mail_config(), printer=lambda _text: None, timeout=30)
    assert fake_msal.device_flows[0]["expires_at"] <= time.time() + 30


def test_login_survives_a_flow_dict_without_an_expiry_key(fake_msal, fake_keychain) -> None:
    fake_msal.flow.pop("expires_at", None)
    result = delegation.login(mail=mail_config(), printer=lambda _text: None)
    assert result.upn == PERSON


# --- the keychain is the only store -----------------------------------------
def test_cache_round_trips_through_the_keychain_only(fake_msal, fake_keychain) -> None:
    """The stored keychain value is a real msal cache: reload it and the token is there."""
    delegation.login(mail=mail_config(), printer=lambda _text: None)
    stored = state_in(fake_keychain)
    assert stored, "the cache never reached the keychain"
    assert CANARY_ACCESS in stored  # msal stores the AT under "secret"

    reloaded = msal.SerializableTokenCache()
    reloaded.deserialize(stored)
    entries = list(reloaded.search(msal.TokenCache.CredentialType.ACCESS_TOKEN))
    assert [e["secret"] for e in entries] == [CANARY_ACCESS]
    # Nothing bypassed the secrets wrapper to reach the security(1) argv path.
    assert fake_keychain.calls == []


def test_a_second_call_reads_the_keychain_it_wrote(signed_in) -> None:
    """whoami has no msal client and no disk: it can only have read the keychain."""
    assert delegation.whoami().upn == PERSON


def test_no_token_cache_file_lands_anywhere(fake_keychain, tmp_path, monkeypatch) -> None:
    """A.2: never on disk. HOME and CWD are moved into a watched dir; it stays empty.

    Those are the two places a cache file could plausibly appear (a `~/.config` path
    via ``Path.home()``, or msal's own default-cache recipe relative to the working
    directory), so both are redirected into the tree we then assert is untouched.
    """
    watched = tmp_path / "watched"
    watched.mkdir()
    monkeypatch.setenv("HOME", str(watched))
    monkeypatch.chdir(watched)
    delegation.login(mail=mail_config(), printer=lambda _text: None)
    delegation.whoami()
    delegation.get_delegated_token()
    delegation.logout()
    assert list(watched.rglob("*")) == []


# --- get_delegated_token ------------------------------------------------------
def test_get_delegated_token_returns_the_cached_token(signed_in) -> None:
    assert delegation.get_delegated_token() == CANARY_ACCESS


def test_get_delegated_token_refuses_without_a_cache_and_says_what_to_do(fake_keychain) -> None:
    with pytest.raises(AuthError) as excinfo:
        delegation.get_delegated_token()
    assert "run mnotify login" in excinfo.value.message
    assert excinfo.value.exit_code == EXIT_AUTH


def test_get_delegated_token_expired_cache_refuses_with_the_hint(fake_keychain) -> None:
    """Access token past expiry and the refresh is dead: AuthError + login hint."""
    fake_keychain.seed(
        delegation.ACCOUNT_DELEGATED_CACHE,
        cache_state(expires_in=-100),  # msal prunes the AT on search
    )
    with pytest.raises(AuthError) as excinfo:
        delegation.get_delegated_token()
    assert "run mnotify login" in excinfo.value.message
    assert excinfo.value.exit_code == EXIT_AUTH
    assert CANARY_ACCESS not in excinfo.value.message
    assert CANARY_REFRESH not in excinfo.value.message


def test_get_delegated_token_reports_msals_error_code_only(fake_keychain, fake_msal) -> None:
    """A refused refresh names msal's code, never its (possibly echoing) description."""
    # An expired access token forces the silent path to be consulted at all: with a
    # live token in the cache msal answers from it and never reaches the error.
    fake_keychain.seed(
        delegation.ACCOUNT_DELEGATED_CACHE,
        cache_state(expires_in=-100, access_token="AT-EXPIRED-OLD"),
    )
    fake_msal.silent_result = {"error": "invalid_grant", "error_description": CANARY_REFRESH}
    with pytest.raises(AuthError) as excinfo:
        delegation.get_delegated_token()
    assert "invalid_grant" in excinfo.value.message
    assert CANARY_REFRESH not in excinfo.value.message  # description never travels


def test_get_delegated_token_persists_a_silent_refresh(fake_keychain, fake_msal) -> None:
    fake_keychain.seed(
        delegation.ACCOUNT_DELEGATED_CACHE,
        cache_state(expires_in=-100, access_token="AT-EXPIRED-OLD"),
    )
    fake_msal.silent_result = token_response(access_token="AT-FRESH-AFTER-REFRESH")
    fake_msal.silent_changes_cache = True
    assert delegation.get_delegated_token() == "AT-FRESH-AFTER-REFRESH"
    assert "AT-FRESH-AFTER-REFRESH" in state_in(fake_keychain)


def test_get_delegated_token_leaves_an_unchanged_cache_unwritten(signed_in, fake_msal) -> None:
    before = state_in(signed_in)
    fake_msal.silent_result = token_response()  # cached hit; the fake does not mutate
    assert delegation.get_delegated_token() == CANARY_ACCESS
    assert state_in(signed_in) == before
    assert signed_in.audit == [delegation.ACCOUNT_DELEGATED_CACHE]  # read only


# --- whoami -------------------------------------------------------------------
def test_whoami_reports_upn_mode_and_expiry(signed_in) -> None:
    result = delegation.whoami()
    assert (result.upn, result.mode) == (PERSON, MAIL_MODE_DELEGATED)
    assert result.expires_at is not None and result.expires_at > time.time()


def test_whoami_carries_no_token_value(signed_in) -> None:
    """The dataclass itself must be safe to print: no token in any field or repr."""
    result = delegation.whoami()
    text = repr(result) + str(result) + "".join(str(v) for v in result.__dict__.values())
    for canary in (CANARY_ACCESS, CANARY_REFRESH, CANARY_ID):
        assert canary not in text


def test_whoami_falls_back_to_the_account_username(fake_keychain) -> None:
    """A cache whose id token is unparseable still names the person."""
    fake_keychain.seed(delegation.ACCOUNT_DELEGATED_CACHE, state_without_a_readable_id_token())
    assert delegation.whoami().upn == PERSON


def test_whoami_without_a_cache_is_an_auth_error(fake_keychain) -> None:
    with pytest.raises(AuthError, match="run mnotify login"):
        delegation.whoami()


def test_whoami_on_a_corrupt_cache_is_an_auth_error(fake_keychain) -> None:
    fake_keychain.seed(delegation.ACCOUNT_DELEGATED_CACHE, "{not json")
    with pytest.raises(AuthError) as excinfo:
        delegation.whoami()
    assert "unreadable" in excinfo.value.message
    assert "run mnotify login" in excinfo.value.message
    assert excinfo.value.exit_code == EXIT_AUTH


def test_whoami_does_not_rewrite_the_keychain(signed_in) -> None:
    before = state_in(signed_in)
    delegation.whoami()
    assert state_in(signed_in) == before
    assert signed_in.audit == [delegation.ACCOUNT_DELEGATED_CACHE]


# --- logout --------------------------------------------------------------------
def test_logout_deletes_the_keychain_account(signed_in) -> None:
    assert delegation.logout() is True
    assert delegation.ACCOUNT_DELEGATED_CACHE not in signed_in.items


def test_logout_is_idempotent_and_honest_about_it(signed_in) -> None:
    assert delegation.logout() is True
    assert delegation.logout() is False  # nothing left, and still not an error


def test_logout_of_an_empty_keychain_is_not_an_error(fake_keychain) -> None:
    assert delegation.logout() is False


def test_logout_then_whoami_asks_for_a_login(signed_in) -> None:
    delegation.logout()
    with pytest.raises(AuthError, match="run mnotify login"):
        delegation.whoami()
