"""``mnotify admin bootstrap --mode delegated`` (card D5, design amendment A.1-A.4).

Same fake-runner discipline as ``tests/test_admin_cli.py``, whose fixtures and canned
answers are **imported** rather than duplicated — including its autouse tripwires, which
re-register here because pytest treats a fixture found in a module's namespace as one of
that module's fixtures, autouse flag and all:

* a real ``az``/``pwsh``/``brew``/``security``/``openssl`` is an assertion failure;
* this module may never write the operator's real ``~/.config/mnotify/config.toml`` — the
  guard B5 added after that actually happened to this machine, which has to be re-declared
  here because autouse fixtures do not cross module boundaries;
* sockets stay blocked by the untouched ``tests/conftest.py``.

Every tenant value is a documented placeholder (design §5).

The card's pins, and where each lives:

* delegated mode never emits the certificate or Exchange steps — and never builds their
  argv either (step names are what the summary claims; the argv log is what the code
  attempted);
* app mode never emits the permission / public-client / consent / signin steps, which is
  the direction that would actually hurt an existing tenant;
* ``--admin-consent`` failing degrades to a visible warning and the run still exits 0;
* the sign-in is the last step before doctor;
* a re-run reports ``exists`` for the permissions and the public-client switch;
* ``--dry-run`` executes nothing.

Plus the two things this card decided rather than inherited, pinned so they cannot be
"fixed" back:

* the config is written *before* the sign-in (amendment A.1 puts the delegated login on
  our own registration, so ``mnotify login`` needs the file to exist at all);
* a sign-in whose UPN is not the configured sender refuses the run rather than quietly
  rewriting the sender (amendment A.3).

The sign-in and doctor are stubbed at their module boundaries: card D1b owns msal's
behaviour and D4 owns doctor's. That is not a weakened pin — these tests are about which
steps this command runs, in what order, with what argv, and a stub that let a step be
*skipped* would fail the order and mismatch assertions below.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from micro_notify import EXIT_OK, AuthError, cli
from micro_notify import delegation
from micro_notify.admin import delegated_setup
from micro_notify.admin import runner as admin_runner
from micro_notify.commands import admin as admin_cmd
from micro_notify.config import load_config

# Imported for their side effects as well as their behaviour: `isolated_config`,
# `tools_on_path`, `no_real_admin_binaries`, `restore_process_runner` and
# `real_config_is_never_touched` are autouse fixtures in their own module, and importing
# them into this namespace makes them autouse here too. That is the only reason this
# module is as safe as the one it borrows from — drop one of these imports and the
# tripwire behind it silently stops applying.
from test_admin_cli import (  # noqa: E402  (pytest puts tests/ on sys.path)
    ADMIN_UPN,
    APP_ID,
    DOMAIN,
    SENDER,
    SP_OBJECT_ID,
    TENANT_ID,
    FakeAdminCli,
    account_json,
    app_list_json,
    healthy_responses,
    isolated_config,  # noqa: F401  (autouse: MICRO_NOTIFY_CONFIG under tmp_path)
    keychain_with_certificate,  # noqa: F401  (fixture the app-mode cert step needs)
    no_real_admin_binaries,  # noqa: F401  (autouse subprocess tripwire)
    real_config_is_never_touched,  # noqa: F401  (autouse operator-config tripwire)
    restore_process_runner,  # noqa: F401  (autouse runner reset)
    sp_list_json,
    tools_on_path,  # noqa: F401  (autouse `which` stub)
)

# Microsoft Graph's first-party application id — a well-known constant, taken from the
# module under test rather than written out here, so this file carries no GUID literal the
# leak guard (design §5) would have to except.
GRAPH_APP_ID = delegated_setup.MS_GRAPH_APP_ID
# The tenant's Graph *service principal* object id (what `permission grant --api` takes).
# An all-ones placeholder, so it reads as a placeholder at a glance.
GRAPH_SP_OBJECT_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

SCOPES = list(delegation.DELEGATED_SCOPES)


def scope_id(index: int) -> str:
    """A distinct scope id for the canned tenant, derived from the placeholder GUID.

    Distinct on purpose, and this is the reason the first draft of these tests failed:
    ``requiredResourceAccess`` stores *ids*, and the idempotency read maps id -> name, so
    two scopes sharing an id are indistinguishable and only one is ever recognised — a
    tenant whose ids collide is not a tenant that reports ``exists``. Every real Graph
    scope has its own id, so the fixture must too.

    Derived from the documented all-zero placeholder rather than written out, so no new
    GUID literal enters a tracked file (design §5 leak guard).
    """
    return f"{TENANT_ID[:24]}{index:012d}"


SCOPE_IDS: dict[str, str] = {name: scope_id(i) for i, name in enumerate(SCOPES)}

# A write whose answer nobody reads still has to answer with something `run_json` can
# parse: an empty stdout is not JSON, and a fake that returns "" would look to the code
# under test exactly like an az that printed garbage. These are JSON documents carrying no
# information, which is what `az` really prints for a successful write with no projection.
NO_CONTENT = "{}"


# --- Canned answers ----------------------------------------------------------
def graph_sp_json(missing: str | None = None) -> str:
    """The projected Graph service principal: its object id plus the scope ids.

    Exactly the shape ``delegated_setup.graph_query`` asks az for, so the read path is
    exercised rather than bypassed. ``missing`` drops one scope to simulate a tenant that
    does not publish it.
    """
    entries = [
        {"value": name, "id": identifier}
        for name, identifier in SCOPE_IDS.items()
        if name != missing
    ]
    return json.dumps({"id": GRAPH_SP_OBJECT_ID, "scopes": entries})


def app_json(*, declared: bool, public_client: bool, resource_app_id: str = GRAPH_APP_ID) -> str:
    """The projected application object: declared Graph scopes + the public-client flag.

    A ``Role`` entry is present on both shapes on purpose: this step must report on
    another mode's application permission and never modify or remove it, and
    :func:`test_role_entries_are_never_written_or_removed` is what proves it.
    """
    access: list[dict[str, str]] = [{"id": SCOPE_IDS[SCOPES[0]], "type": "Role"}]
    if declared:
        access += [
            {"id": SCOPE_IDS[name], "type": "Scope"} for name in SCOPES if name in SCOPE_IDS
        ]
    return json.dumps(
        {
            "requiredResourceAccess": [
                {"resourceAppId": resource_app_id, "resourceAccess": access}
            ],
            delegated_setup._PUBLIC_CLIENT_PROPERTY: public_client,
        }
    )


def grants_json(complete: bool) -> str:
    """``oauth2PermissionGrant`` rows, as ``permission list-grants`` prints them.

    Split across two grants because the read-back must still see all five when a tenant
    consented three in one grant and two in another.
    """
    if not complete:
        return "[]"
    return json.dumps([{"scope": " ".join(SCOPES[:3])}, {"scope": " ".join(SCOPES[3:])}])


def tenant_answers(
    *,
    declared: bool = False,
    public_client: bool = False,
    consented: bool = True,
    graph_missing: str | None = None,
    app_resource_id: str = GRAPH_APP_ID,
) -> dict[tuple[str, ...], str]:
    """A healthy, registration-already-exists tenant plus the delegated-mode answers."""
    answers = healthy_responses(configured=True)
    answers[("az", "ad", "sp", "show")] = graph_sp_json(missing=graph_missing)
    answers[("az", "ad", "app", "show")] = app_json(
        declared=declared, public_client=public_client, resource_app_id=app_resource_id
    )
    answers[("az", "ad", "app", "permission", "add")] = NO_CONTENT
    answers[("az", "ad", "app", "update")] = NO_CONTENT
    answers[("az", "ad", "app", "permission", "list-grants")] = grants_json(consented)
    # What the grant command itself prints (az echoes the created grant). The *read-back*
    # is separate: TenantCli answers it from `grants_after` once a grant has succeeded.
    answers[("az", "ad", "app", "permission", "grant")] = grants_json(consented)
    return answers


# --- The stubbed neighbours --------------------------------------------------
class SigninStub:
    """``login.run`` and ``delegation.whoami``, replaced with a recorded UPN.

    D1b owns msal's behaviour (stubbed in ``tests/test_delegation.py``) and no test may
    start a real device-code flow. This answers *both* calls the step makes — the
    cache-only check and the identity read — so the bootstrap cannot skip past the
    sign-in step without failing the order and mismatch assertions below.
    """

    def __init__(self, upn: str = SENDER, *, cached: bool = True) -> None:
        self.upn = upn
        self.calls: list[bool] = []  # one entry per login.run; True = --no-prompt
        self._cached = cached

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from micro_notify.commands import login as login_module

        def fake_run(args: Any) -> int:
            no_prompt = bool(getattr(args, "no_prompt", False))
            self.calls.append(no_prompt)
            if no_prompt and not self._cached:
                # What a fresh tenant looks like: the cache cannot produce a token.
                raise AuthError("no cached delegated sign-in")
            return EXIT_OK

        monkeypatch.setattr(login_module, "run", fake_run)
        monkeypatch.setattr(
            delegation,
            "whoami",
            lambda: delegation.WhoamiResult(
                upn=self.upn, mode=delegation.MAIL_MODE_DELEGATED, expires_at=None
            ),
        )


class TenantCli(FakeAdminCli):
    """B5's fake plus the things a flat answer table cannot express.

    **A command that fails the way ``az`` really fails** (:meth:`fail`):

    * :meth:`fail` drops longer-prefix answers first, because the inherited fake answers
      with the *longest* matching prefix — leaving ``az ad app permission grant``
      registered would let a shorter ``("pwsh",)`` failure silently never apply;
    * the diagnosis goes on **stderr**. :func:`~micro_notify.admin.runner.parse_json_result`
      quotes stderr and only stderr, because that is where the tool writes its own
      explanation; a fake that put it on stdout would produce a step detail no real ``az``
      could ever produce, and the test would pin something untrue.

    **A tenant whose consent read-back reflects the consent it was given**
    (``grants_track_grants``). This is the one piece of state a flat table cannot model,
    and the reason the first draft of the consent test failed: ``ensure_admin_consent``
    writes, then re-reads ``list-grants`` and reports what it now sees. A fake that answers
    the read-back with the pre-write answer would make a *successful* consent look like a
    refused one — pinning the warning path as the normal path. With the flag off the answers
    stay flat, which is exactly what
    :func:`test_a_consent_that_is_not_visible_after_the_write_warns_too` wants: a write that
    reported success and a tenant that still says nothing is consented.

    **A tenant whose permission read-back reflects the writes it was given**
    (``tracks_writes``, BUG6). The same statefulness for the permission half: az's
    ``permission add`` PATCHes the same ``requiredResourceAccess`` property that
    ``permission list`` and ``app show`` read, answers with **nothing on stdout** (and
    its "run permission grant" WARNING on stderr), and ``update --set
    isFallbackPublicClient=true`` writes the same property ``app show`` projects. So the
    fake derives the ``permission list`` answer from the tenant's own stored state plus
    the adds it actually accepted, and flips the public-client flag on a successful
    update. A flat table could not model either, and a read-back frozen at the pre-write
    answer would make BUG6's fix untestable.
    """

    GRANT_PREFIX = ("az", "ad", "app", "permission", "grant")
    READ_PREFIX = ("az", "ad", "app", "permission", "list-grants")
    ADD_PREFIX = ("az", "ad", "app", "permission", "add")
    # NOT ``list-grants``: ``list`` is a distinct 5th token, so the two commands
    # never match each other's prefix.
    LIST_PREFIX = ("az", "ad", "app", "permission", "list")
    UPDATE_PREFIX = ("az", "ad", "app", "update")
    APP_SHOW_PREFIX = ("az", "ad", "app", "show")
    PUBLIC_CLIENT_SET = "isFallbackPublicClient=true"

    def __init__(
        self,
        responses: dict[tuple[str, ...], str] | None = None,
        *,
        grants_track_grants: bool = False,
        grants_after: str | None = None,
        tracks_writes: bool = True,
    ) -> None:
        super().__init__(responses)
        self._failures: dict[tuple[str, ...], str] = {}
        self.grants_track_grants = grants_track_grants
        # What the tenant reports once a grant has succeeded. Defaults to "everything".
        self.grants_after = grants_after if grants_after is not None else grants_json(True)
        self._granted = False
        self.tracks_writes = tracks_writes
        # Scope ids the tenant actually accepted via `permission add`.
        self._added_ids: list[str] = []

    def fail(self, prefix: tuple[str, ...], message: str = "ERROR: refused") -> None:
        for key in [k for k in self.responses if tuple(k[: len(prefix)]) == prefix]:
            del self.responses[key]
            self.returncodes.pop(key, None)
        self._failures[prefix] = message

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        for prefix, message in self._failures.items():
            if len(prefix) <= len(args) and tuple(args[: len(prefix)]) == prefix:
                self.calls.append(args)
                return subprocess.CompletedProcess(args, 1, "", message)
        if self._matches(args, self.ADD_PREFIX):
            result = super().run(args, stdin=stdin, **kwargs)
            if result.returncode == 0 and self.tracks_writes:
                identifier = _api_permission_id(args)
                if identifier:
                    self._added_ids.append(identifier)
            # az prints NOTHING on stdout for a successful add (see
            # test_a_permission_add_that_prints_nothing_is_not_a_failure), and its
            # stderr note is informational. The table may still force a non-zero rc.
            return subprocess.CompletedProcess(
                args,
                result.returncode,
                "",
                result.stderr if result.returncode else PERMISSION_ADD_WARNING,
            )
        if self._matches(args, self.LIST_PREFIX):
            answer = self._permission_list_answer()
            if answer is not None:
                self.calls.append(args)
                return subprocess.CompletedProcess(args, 0, answer, "")

        if self.grants_track_grants and self._matches(args, self.READ_PREFIX) and self._granted:
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 0, self.grants_after, "")
        result = super().run(args, stdin=stdin, **kwargs)
        if (
            self.tracks_writes
            and result.returncode == 0
            and self._matches(args, self.UPDATE_PREFIX)
            and self.PUBLIC_CLIENT_SET in args
        ):
            self._mark_public_client_on()
        if (
            self.grants_track_grants
            and self._matches(args, self.GRANT_PREFIX)
            and result.returncode == 0
        ):
            self._granted = True
        return result

    def _permission_list_answer(self) -> str | None:
        """The Graph entry of ``requiredResourceAccess``, as az would print it now.

        Same stored state the ``app show`` answer is built from, plus every add the
        tenant accepted — one source of truth for both reads, so the fake cannot say
        "declared" to one command and "not declared" to another unless it means it.
        """
        raw = self.responses.get(self.APP_SHOW_PREFIX)
        if raw is None:
            return None
        try:
            document = json.loads(raw)
        except ValueError:
            return None
        access: list[dict[str, str]] = []
        for entry in document.get("requiredResourceAccess", []):
            if entry.get("resourceAppId", "").casefold() != GRAPH_APP_ID.casefold():
                continue
            access = [dict(a) for a in entry.get("resourceAccess", [])]
        # Appended unconditionally, exactly as az does (`resourceAccess += [...]`): no
        # de-duplication here. The canned tenant carries a Graph `Role` entry whose id
        # is shared with one of the delegated scopes — the same id can appear with both
        # types, and it is `declared_graph_scopes` that decides a `Scope` entry counts
        # and a `Role` one does not.
        for identifier in self._added_ids:
            access.append({"id": identifier, "type": "Scope"})
        graph_entry = {"resourceAppId": GRAPH_APP_ID, "resourceAccess": access}
        # A second API's entry rides along because az's `permission list` does not
        # project: the reader's resourceAppId filter has to earn its keep.
        decoy = {
            "resourceAppId": "some-other-api",
            "resourceAccess": [{"id": "some-other-permission", "type": "Scope"}],
        }
        return json.dumps([graph_entry, decoy])

    def _mark_public_client_on(self) -> None:
        """Apply a successful ``--set isFallbackPublicClient=true`` to the stored app."""
        raw = self.responses.get(self.APP_SHOW_PREFIX)
        if raw is None:
            return
        try:
            document = json.loads(raw)
        except ValueError:
            return
        if not isinstance(document, dict):
            return
        document[delegated_setup._PUBLIC_CLIENT_PROPERTY] = True
        self.responses[self.APP_SHOW_PREFIX] = json.dumps(document)

    @staticmethod
    def _matches(args: list[str], prefix: tuple[str, ...]) -> bool:
        return len(prefix) <= len(args) and tuple(args[: len(prefix)]) == prefix


class Stub:
    """One fake tenant, the stubbed sign-in and doctor, and everything they reported."""

    def __init__(
        self,
        tenant: dict[tuple[str, ...], str],
        signin: SigninStub,
        *,
        grants_track_grants: bool = True,
        grants_after: str | None = None,
        tracks_writes: bool = True,
    ) -> None:
        self.cli = TenantCli(
            tenant,
            grants_track_grants=grants_track_grants,
            grants_after=grants_after,
            tracks_writes=tracks_writes,
        )
        self.signin = signin
        self._raw: str | None = None

    # --- driving -----------------------------------------------------------
    def run(self, *argv: str) -> int:
        """``mnotify admin bootstrap`` in the default (app-only) mode."""
        return cli.main(
            ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, *argv]
        )

    def delegated(self, *argv: str) -> int:
        return self.run("--mode", "delegated", *argv)

    def summary(self, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
        """The one JSON document ``--json`` stdout must hold (raises on prose).

        Read once and cached: ``capsys.readouterr()`` *consumes* the capture, so a second
        read would return an empty string and every helper below would fail on
        "Expecting value: line 1 column 1" instead of telling you what the summary said.
        """
        if self._raw is None:
            self._raw = capsys.readouterr().out
        return json.loads(self._raw)

    # --- inspection --------------------------------------------------------
    @property
    def argv(self) -> list[str]:
        return self.cli.joined

    def lines(self, needle: str) -> list[str]:
        return self.cli.matching(needle)

    def steps(self, capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
        return list(self.summary(capsys)["steps"])

    def names(self, capsys: pytest.CaptureFixture[str]) -> list[str]:
        return [entry["name"] for entry in self.steps(capsys)]

    def outcome(self, capsys: pytest.CaptureFixture[str], name: str) -> str:
        for entry in self.steps(capsys):
            if entry["name"] == name:
                return entry["outcome"]
        raise AssertionError(f"no step named {name!r} in {self.names(capsys)}")

    def detail(self, capsys: pytest.CaptureFixture[str], name: str) -> str:
        for entry in self.steps(capsys):
            if entry["name"] == name:
                return entry.get("detail", "")
        raise AssertionError(f"no step named {name!r} in {self.names(capsys)}")

    def fail_command(self, prefix: tuple[str, ...], message: str = "ERROR: refused") -> None:
        """Convenience for :meth:`TenantCli.fail` — make one command fail like az."""
        self.cli.fail(prefix, message)


@pytest.fixture(autouse=True)
def doctor_stub(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """``doctor.run`` records that it ran and returns green.

    B5 and D4 pin doctor's own behaviour in their own modules; this one needs to know that
    the bootstrap reached it, and that it reached it last.
    """
    calls: list[dict] = []

    def fake_run(args: argparse.Namespace) -> int:
        calls.append({"send_test": getattr(args, "send_test", None), "json": args.json})
        return EXIT_OK

    monkeypatch.setattr("micro_notify.commands.doctor.run", fake_run)
    return calls


@pytest.fixture
def make_stub(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Build a stub over an arbitrary canned tenant; each variation names itself."""

    def build(
        tenant: dict[tuple[str, ...], str],
        *,
        upn: str = SENDER,
        cached: bool = True,
        grants_track_grants: bool = True,
        grants_after: str | None = None,
    ) -> Stub:
        signin = SigninStub(upn=upn, cached=cached)
        signin.install(monkeypatch)
        stub = Stub(
            tenant,
            signin,
            grants_track_grants=grants_track_grants,
            grants_after=grants_after,
        )
        admin_cmd.set_runner(stub.cli)
        return stub

    return build


@pytest.fixture
def stub(make_stub: Any) -> Stub:
    """A healthy tenant with nothing delegated configured yet, and a working sign-in."""
    return make_stub(tenant_answers())


# ===========================================================================
# The parser surface
# ===========================================================================
def test_mode_defaults_to_app_so_existing_invocations_are_unchanged() -> None:
    args = cli.build_parser().parse_args(
        ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN]
    )
    assert args.mode == admin_cmd.MODE_APP


def test_both_modes_are_valid_choices() -> None:
    parser = cli.build_parser()
    for mode in admin_cmd.BOOTSTRAP_MODES:
        args = parser.parse_args(
            ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, "--mode", mode]
        )
        assert admin_cmd._mode_of(args) == mode


def test_an_unknown_mode_is_refused_by_the_parser() -> None:
    """argparse owns an unknown choice: exit 2 before this module can reach a step."""
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN,
             "--mode", "on-behalf-of"]
        )
    assert excinfo.value.code == 2


def test_a_namespace_without_mode_keeps_the_app_only_behaviour() -> None:
    """B5's defensive ``getattr`` rule: an older caller must not drift into the writes.

    The delegated steps mutate a registration's permissions, so no run may reach them by
    accident — a missing attribute has to mean app-only, not "try the new thing".
    """
    assert admin_cmd._mode_of(argparse.Namespace()) == admin_cmd.MODE_APP
    assert admin_cmd._mode_of(argparse.Namespace(mode=None)) == admin_cmd.MODE_APP


def test_mode_is_normalised_for_callers_that_build_a_namespace() -> None:
    assert admin_cmd._mode_of(argparse.Namespace(mode=" Delegated ")) == admin_cmd.MODE_DELEGATED
    assert admin_cmd._mode_of(argparse.Namespace(mode="APP")) == admin_cmd.MODE_APP


def test_admin_consent_flag_parses() -> None:
    args = cli.build_parser().parse_args(
        ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN,
         "--mode", "delegated", "--admin-consent"]
    )
    assert args.admin_consent is True
    assert args.send_test is None


# ===========================================================================
# The step sequence, both directions
# ===========================================================================
def test_delegated_mode_runs_the_delegated_steps_in_order(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    assert stub.delegated("--json") == EXIT_OK
    assert stub.names(capsys) == [
        admin_cmd.STEP_PREFLIGHT,
        admin_cmd.STEP_ENTRA,
        admin_cmd.STEP_PERMISSIONS,
        admin_cmd.STEP_PUBLIC_CLIENT,
        admin_cmd.STEP_CONSENT,
        admin_cmd.STEP_CONFIG,
        admin_cmd.STEP_SIGNIN,
        admin_cmd.STEP_DOCTOR,
    ]
    assert stub.summary(capsys)["mode"] == admin_cmd.MODE_DELEGATED


def test_delegated_mode_never_emits_the_certificate_or_exchange_steps(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    """The card's first regression guard, on the step names.

    A delegated send reads no certificate and no Exchange recipient scope, so a run that
    still did them would upload a public key nobody uses and grant a mailbox scope for a
    sender that is not a mailbox the app impersonates (amendment A.3).
    """
    assert stub.delegated("--json") == EXIT_OK
    names = stub.names(capsys)
    assert admin_cmd.STEP_CERTIFICATE not in names
    assert admin_cmd.STEP_EXCHANGE not in names


def test_delegated_mode_never_builds_a_certificate_or_exchange_command(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same guard over the argv, which is the stronger of the two.

    A step that reported itself skipped while still running the Exchange script would
    satisfy the assertion above and fail this one.
    """
    assert stub.delegated("--json") == EXIT_OK
    joined = "\n".join(stub.argv).lower()
    assert "managementscope" not in joined
    assert "managementroleassignment" not in joined
    assert "credential" not in joined, "a credential command was built"
    assert "openssl" not in joined
    assert not [
        call for call in stub.cli.calls if call[:1] == ["pwsh"] and "-File" in call
    ], "the Exchange script was invoked"


def test_app_mode_never_emits_the_delegated_steps(
    stub: Stub,
    keychain_with_certificate: Any,  # noqa: F811  (the cert step needs an uploaded pair)
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The card's second regression guard — and the one that protects existing tenants.

    An app-only bootstrap that began declaring delegated scopes and enabling
    public-client flows would open a registration holding a certificate credential to
    device-code flows, silently, for every operator who re-ran the documented command.
    """
    assert stub.run("--json") == EXIT_OK
    names = stub.names(capsys)
    for forbidden in (
        admin_cmd.STEP_PERMISSIONS,
        admin_cmd.STEP_PUBLIC_CLIENT,
        admin_cmd.STEP_CONSENT,
        admin_cmd.STEP_SIGNIN,
    ):
        assert forbidden not in names, f"app mode emitted {forbidden}"
    assert admin_cmd.STEP_CERTIFICATE in names
    assert admin_cmd.STEP_EXCHANGE in names


def test_app_mode_never_builds_a_permission_public_client_or_consent_command(
    stub: Stub, keychain_with_certificate: Any, capsys: pytest.CaptureFixture[str]  # noqa: F811
) -> None:
    assert stub.run("--json") == EXIT_OK
    offenders = [
        line
        for line in stub.argv
        if any(
            marker in line.lower()
            for marker in (
                "permission add",
                "permission grant",
                "list-grants",
                "isfallbackpublicclient",
                "requiredresourceaccess",
            )
        )
    ]
    assert not offenders, f"app mode built a delegated command: {offenders}"


def test_app_mode_config_is_byte_identical_with_and_without_the_new_flag(
    stub: Stub,
    keychain_with_certificate: Any,  # noqa: F811
    isolated_config: Path,
) -> None:
    """``--mode`` must be inert for app-only tenants, not merely similar."""
    assert stub.run() == EXIT_OK
    first = isolated_config.read_bytes()
    isolated_config.unlink()
    assert stub.run("--mode", "app") == EXIT_OK
    assert isolated_config.read_bytes() == first


# ===========================================================================
# The permission declaration
# ===========================================================================
def test_delegated_mode_declares_exactly_the_five_scopes_one_command_each(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    """One ``permission add`` per scope: a tenant that rejects one fails naming it."""
    assert stub.delegated("--json") == EXIT_OK
    adds = stub.lines("permission add")
    assert len(adds) == len(SCOPES), adds
    for line in adds:
        assert f"--api {GRAPH_APP_ID}" in line
        assert "=Scope" in line, "only delegated Scope entries may be written"
        assert "=Role" not in line
        assert any(identifier in line for identifier in SCOPE_IDS.values()), line
    assert stub.outcome(capsys, admin_cmd.STEP_PERMISSIONS) == "created"


def test_the_ids_written_are_the_ones_the_tenant_published(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The tenant's Graph service principal is the only source of a scope id.

    A local table would survive this mutation — and would write a permission that
    authenticates as something else.
    """
    other = {
        name: (SP_OBJECT_ID if i % 2 == 0 else TENANT_ID) for i, name in enumerate(SCOPES)
    }
    assert other != SCOPE_IDS, "the rewritten ids must differ from the default fixture"
    tenant = tenant_answers()
    tenant[("az", "ad", "sp", "show")] = json.dumps(
        {"id": GRAPH_SP_OBJECT_ID, "scopes": [{"value": n, "id": i} for n, i in other.items()]}
    )
    stub = make_stub(tenant)
    assert stub.delegated("--json") == EXIT_OK
    adds = stub.lines("permission add")
    assert len(adds) == len(SCOPES)
    for line in adds:
        assert any(identifier in line for identifier in other.values()), line


def test_a_scope_the_tenant_does_not_publish_refuses_before_any_write(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Skipping an unavailable scope silently would yield an app that signs in and then
    cannot send, so the run stops and names the scope."""
    stub = make_stub(tenant_answers(graph_missing="Mail.Send"))
    assert stub.delegated("--json") == 2
    payload = stub.summary(capsys)
    assert payload["ok"] is False and payload["exitCode"] == 2
    assert "Mail.Send" in json.dumps(payload)
    assert not stub.lines("permission add"), "a write happened despite the refusal"


def test_a_graph_entry_for_another_resource_is_not_read_as_declared(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Otherwise the step reports ``exists``, writes nothing, and the tenant looks
    configured while being unable to send."""
    stub = make_stub(
        tenant_answers(declared=True, public_client=True, app_resource_id=GRAPH_SP_OBJECT_ID)
    )
    assert stub.delegated("--json") == EXIT_OK
    assert len(stub.lines("permission add")) == len(SCOPES)


def test_role_entries_are_never_written_or_removed(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    """B2's no-consent invariant, extended to the delegated writes *deliberately* — card
    B5's handoff asked for the exemption to be named rather than the pin widened silently.

    The canned registration carries a Graph ``Role`` entry, the shape an app-only tenant
    has. A delegated run must leave it alone: no removal, no ``--set`` replacing the whole
    list, no consent of it.
    """
    assert stub.delegated("--json") == EXIT_OK
    for line in stub.lines("permission add"):
        assert "Role" not in line
    assert not stub.lines("admin-consent"), "the whole-app consent command was built"
    assert not [
        call
        for call in stub.cli.calls
        if "--set" in call and "requiredresourceaccess" in " ".join(call).lower()
    ], "a generic --set would replace the whole requiredResourceAccess list"


def test_a_re_run_reports_exists_and_writes_nothing(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The card's idempotency pin: the second run reads, changes nothing, says ``exists``."""
    stub = make_stub(tenant_answers(declared=True, public_client=True))
    assert stub.delegated("--json") == EXIT_OK
    assert stub.outcome(capsys, admin_cmd.STEP_PERMISSIONS) == "exists"
    assert stub.outcome(capsys, admin_cmd.STEP_PUBLIC_CLIENT) == "exists"
    assert not stub.lines("permission add")
    assert not stub.lines("isFallbackPublicClient=true")


# ===========================================================================
# The public-client switch
# ===========================================================================
def test_the_public_client_switch_is_set_once_by_the_only_real_property(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    assert stub.delegated("--json") == EXIT_OK
    sets = stub.lines("isFallbackPublicClient=true")
    assert len(sets) == 1
    assert sets[0].startswith(f"az ad app update --id {APP_ID} --set ")
    assert stub.outcome(capsys, admin_cmd.STEP_PUBLIC_CLIENT) == "created"


def test_the_card_body_property_name_is_never_used(stub: Stub) -> None:
    """``allowPublicClientFlows`` is not an az or Graph property.

    Checked against the installed azure-cli 2.90.0: ``az ad app update`` has no such flag
    and the name appears nowhere in the CLI's source tree. Writing it would fail every
    delegated run, so it is pinned here rather than left to a comment in the module.
    """
    assert stub.delegated("--json") == EXIT_OK
    assert "allowPublicClientFlows" not in " ".join(stub.argv)


# ===========================================================================
# --admin-consent
# ===========================================================================
def test_consent_grants_exactly_the_five_scopes_and_nothing_else(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = make_stub(tenant_answers(consented=False))
    assert stub.delegated("--admin-consent", "--json") == EXIT_OK
    grants = stub.lines("permission grant")
    assert len(grants) == 1, grants
    line = grants[0]
    assert f"--id {SP_OBJECT_ID}" in line
    assert f"--api {GRAPH_SP_OBJECT_ID}" in line
    for name in SCOPES:
        assert name in line
    assert stub.outcome(capsys, admin_cmd.STEP_CONSENT) == "created"


def test_consent_uses_permission_grant_never_admin_consent(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """``az ad app permission admin-consent`` consents *every* declared permission — the
    whole-directory grant ADMIN-SETUP §3.1 tells the operator to remove."""
    stub = make_stub(tenant_answers(consented=False))
    assert stub.delegated("--admin-consent", "--json") == EXIT_OK
    assert not [call for call in stub.cli.calls if "admin-consent" in call]


def test_a_refused_consent_warns_visibly_and_the_run_still_succeeds(
    make_stub: Any, capsys: pytest.CaptureFixture[str], doctor_stub: list[dict]
) -> None:
    """The card's degrade pin: a verification-blocked tenant still ends configured.

    The reason must be *visible*. Under ``--json`` the only failure channels are ``ok``
    and ``exitCode`` and neither may open for a warn, so the step is ``skipped`` carrying
    the az reason as its detail — the one place it can reach an operator.
    """
    stub = make_stub(tenant_answers(consented=False))
    stub.fail_command(("az", "ad", "app", "permission", "grant"), "ERROR: privilege required")
    assert stub.delegated("--admin-consent", "--json") == EXIT_OK
    payload = stub.summary(capsys)
    assert payload["ok"] is True and payload["exitCode"] == EXIT_OK
    entry = next(s for s in payload["steps"] if s["name"] == admin_cmd.STEP_CONSENT)
    assert entry["outcome"] == "skipped"
    assert "privilege required" in entry["detail"]
    assert delegated_setup.CONSENT_HINT.split(";")[0] in json.dumps(payload)
    names = [s["name"] for s in payload["steps"]]
    assert names.index(admin_cmd.STEP_SIGNIN) > names.index(admin_cmd.STEP_CONSENT)
    assert doctor_stub, "the run stopped at the refused consent"


def test_a_consent_that_is_not_visible_after_the_write_warns_too(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The write reported success and the read-back disagrees: report the disagreement
    rather than claiming a consent the tenant has not applied.

    ``grants_track_grants=False`` is the point here — it freezes the read-back at "nothing
    consented", which is exactly the tenant that grants and then does not show it.
    """
    tenant = tenant_answers(consented=False)
    tenant[("az", "ad", "app", "permission", "grant")] = grants_json(False)
    stub = make_stub(tenant, grants_track_grants=False)
    assert stub.delegated("--admin-consent", "--json") == EXIT_OK
    assert stub.outcome(capsys, admin_cmd.STEP_CONSENT) == "skipped"
    assert "not visible" in stub.detail(capsys, admin_cmd.STEP_CONSENT)


def test_consent_already_covering_the_scopes_reports_exists_without_a_write(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = make_stub(tenant_answers(consented=True))
    assert stub.delegated("--admin-consent", "--json") == EXIT_OK
    assert stub.outcome(capsys, admin_cmd.STEP_CONSENT) == "exists"
    assert not stub.lines("permission grant")


def test_no_tenant_wide_consent_is_attempted_without_the_flag(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    assert stub.delegated("--json") == EXIT_OK
    assert not stub.lines("permission grant")
    assert not stub.lines("list-grants")
    assert stub.outcome(capsys, admin_cmd.STEP_CONSENT) == "skipped"
    assert "admin-consent" in stub.detail(capsys, admin_cmd.STEP_CONSENT)


def test_admin_consent_in_app_mode_is_refused_not_ignored(
    stub: Stub, capsys: pytest.CaptureFixture[str], doctor_stub: list[dict]
) -> None:
    """An app-only tenant must not gain a consented Graph permission — §3.1 removes the
    tenant-wide consent on purpose. Ignoring the flag would leave the operator believing
    they had consented something, so: exit 2, both ways out named, nothing mutated."""
    assert stub.run("--admin-consent", "--json") == 2
    payload = stub.summary(capsys)
    assert payload["ok"] is False and payload["exitCode"] == 2
    assert "delegated" in json.dumps(payload)
    assert not doctor_stub
    assert not stub.argv, "a probe ran before the refusal"


# ===========================================================================
# The sign-in
# ===========================================================================
def test_the_sign_in_is_the_last_step_before_doctor(
    stub: Stub, capsys: pytest.CaptureFixture[str], doctor_stub: list[dict]
) -> None:
    """The card asks for login "at the end". Precisely: the last step needing a human,
    with doctor after it so a fresh tenant's delegated checks (D4) can be green."""
    assert stub.delegated("--json") == EXIT_OK
    names = stub.names(capsys)
    assert names.index(admin_cmd.STEP_SIGNIN) == names.index(admin_cmd.STEP_DOCTOR) - 1
    assert names.index(admin_cmd.STEP_SIGNIN) > names.index(admin_cmd.STEP_PUBLIC_CLIENT)
    assert doctor_stub == [{"send_test": None, "json": True}]


def test_the_config_is_written_before_the_sign_in(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    """A deliberate deviation from the card body, pinned so it cannot drift back.

    Amendment A.1 puts the delegated login on *this* registration and ``mnotify login``
    reads its client id and tenant from ``[mail]``. On a fresh tenant that file does not
    exist yet, so signing in first would fail on login's own missing-config error before
    a human ever saw a device code.
    """
    assert stub.delegated("--json") == EXIT_OK
    names = stub.names(capsys)
    assert names.index(admin_cmd.STEP_CONFIG) < names.index(admin_cmd.STEP_SIGNIN)


def test_a_configured_tenant_is_not_asked_to_sign_in_again(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """The cache-only check runs first, so a routine re-run never opens a browser."""
    stub = make_stub(tenant_answers(declared=True, public_client=True), cached=True)
    assert stub.delegated("--json") == EXIT_OK
    assert stub.signin.calls == [True], "the interactive flow was started over a usable cache"
    assert stub.outcome(capsys, admin_cmd.STEP_SIGNIN) == "exists"


def test_a_fresh_tenant_falls_back_to_the_device_code_flow(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    stub = make_stub(tenant_answers(), cached=False)
    assert stub.delegated("--json") == EXIT_OK
    assert stub.signin.calls == [True, False]
    assert stub.outcome(capsys, admin_cmd.STEP_SIGNIN) == "created"


def test_a_sign_in_as_somebody_else_refuses_the_run(
    make_stub: Any,
    capsys: pytest.CaptureFixture[str],
    doctor_stub: list[dict],
) -> None:
    """Amendment A.3: the sender IS the identity in the token.

    The config is *not* quietly rewritten to match the token — the operator passed
    ``--sender`` on purpose, and a bootstrap silently changing which mailbox a tool sends
    from is the surprise this refuses. Exit 2, both fixes named, doctor not reached.
    """
    stub = make_stub(tenant_answers(), upn="somebody.else@contoso.com")
    assert stub.delegated("--json") == 2
    payload = stub.summary(capsys)
    assert payload["ok"] is False and payload["exitCode"] == 2
    assert "somebody.else@contoso.com" in json.dumps(payload)
    assert "--sender" in json.dumps(payload)
    assert not doctor_stub, "doctor ran after a run that must not claim success"


def test_the_upn_comparison_ignores_case(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Directory UPNs are case-insensitive; refusing here would block a real tenant."""
    stub = make_stub(tenant_answers(declared=True, public_client=True), upn=SENDER.upper())
    assert stub.delegated("--json") == EXIT_OK


def test_the_send_test_flag_reaches_doctor(
    stub: Stub, doctor_stub: list[dict], capsys: pytest.CaptureFixture[str]
) -> None:
    """B5's rule: the test send goes through the normal mail path, so doctor owns it."""
    assert stub.delegated("--send-test", "person@contoso.com", "--json") == EXIT_OK
    assert doctor_stub == [{"send_test": "person@contoso.com", "json": True}]
    assert admin_cmd.STEP_SEND_TEST in stub.names(capsys)


# ===========================================================================
# The config it writes, and the checks it skips
# ===========================================================================
def test_delegated_mode_writes_a_delegated_config(stub: Stub, isolated_config: Path) -> None:
    assert stub.delegated() == EXIT_OK
    config = load_config(isolated_config)
    assert config.mail.mode == "delegated"
    assert config.mail.auth == "certificate", "a delegated run writes no new credential"
    assert config.mail.sender == SENDER
    assert config.mail.client_id == APP_ID
    assert config.mail.tenant_id == TENANT_ID
    assert tuple(config.allow.domains) == (DOMAIN,)


def test_delegated_mode_never_asks_for_a_control_mailbox(
    stub: Stub, capsys: pytest.CaptureFixture[str]
) -> None:
    """The negative control is the Exchange proof's requirement, which is app mode's.

    B1 raises when sender == control, so leaving that in delegated mode would refuse
    every delegated bootstrap on its most natural invocation.
    """
    assert stub.delegated("--json") == EXIT_OK
    assert "controlMailbox" not in stub.summary(capsys)


def test_delegated_mode_does_not_require_powershell(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """A machine with no pwsh is perfectly ready for a delegated tenant.

    Drop the ``include_exchange`` threading and B1's two PowerShell checks fail the
    pre-flight and this run exits 2 — exactly the failure this card must not ship.
    """
    stub = make_stub(tenant_answers())
    stub.fail_command(("pwsh",), "ERROR: pwsh is not installed")
    assert stub.delegated("--json") == EXIT_OK
    assert not [call for call in stub.cli.calls if call[:1] == ["pwsh"]]


def test_app_mode_still_requires_powershell(make_stub: Any) -> None:
    """The other half of the pin: the exemption is delegated-only, not a weakened check."""
    stub = make_stub(tenant_answers())
    stub.fail_command(("pwsh", "-NoProfile", "-NonInteractive", "-Command"), "ERROR: no pwsh")
    assert stub.run("--json") == 2


def test_delegated_mode_still_refuses_an_empty_allowlist(
    make_stub: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    """Mode-independent: B5's guard is about the config, not the credential."""
    stub = make_stub(tenant_answers())
    code = cli.main(["admin", "bootstrap", "--sender", SENDER, "--mode", "delegated", "--json"])
    assert code == 2
    assert "allow-domain" in json.dumps(stub.summary(capsys))
    assert not stub.argv, "a probe ran before the refusal"


# ===========================================================================
# --dry-run
# ===========================================================================
def _dry() -> admin_runner.DryRunRunner:
    """A recorder with the answers a fresh tenant would give, canned rather than probed.

    A dry run must work on a machine with no ``az`` and no network (B1's rule), which is
    why every value below is canned rather than observed.
    """
    return admin_runner.DryRunRunner(
        {
            ("az", "account", "show"): account_json(),
            ("az", "account", "tenant", "list"): json.dumps(
                [{"tenantId": TENANT_ID, "displayName": "contoso.com"}]
            ),
            ("az", "rest"): json.dumps({"value": [{"displayName": "Global Administrator"}]}),
            ("az", "ad", "user", "show"): json.dumps({"userPrincipalName": SENDER}),
            ("az", "ad", "app", "list"): app_list_json(present=True),
            ("az", "ad", "sp", "list"): sp_list_json(present=True),
            ("az", "ad", "sp", "show"): graph_sp_json(),
            ("az", "ad", "app", "show"): app_json(declared=False, public_client=False),
        }
    )


def _dry_argv(*extra: str) -> list[str]:
    return ["admin", "bootstrap", "--sender", SENDER, "--allow-domain", DOMAIN, *extra]


def test_dry_run_executes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    recorder = _dry()
    admin_cmd.set_runner(recorder)
    assert cli.main(_dry_argv("--mode", "delegated", "--dry-run", "--json")) == EXIT_OK
    assert recorder.executed_anything is False
    assert recorder.stdin_payloads == [] or all(p is None for p in recorder.stdin_payloads)
    payload = json.loads(capsys.readouterr().out)
    assert payload["dryRun"] is True
    assert payload["mode"] == admin_cmd.MODE_DELEGATED
    assert payload["delegatedScopes"] == SCOPES


def test_dry_run_plans_the_permission_and_switch_commands(capsys: pytest.CaptureFixture[str]) -> None:
    """The plan prints from the real code path, so it cannot advertise a command the step
    would not run — and the delegated plan must not contain app mode's work."""
    admin_cmd.set_runner(_dry())
    assert cli.main(_dry_argv("--mode", "delegated", "--dry-run")) == EXIT_OK
    printed = capsys.readouterr().out
    assert "permission add" in printed
    assert "isFallbackPublicClient=true" in printed
    assert "permission grant" not in printed, "planned a consent nobody asked for"
    assert "ManagementScope" not in printed, "planned the Exchange scoped role"


def test_app_mode_dry_run_never_plans_a_delegated_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    admin_cmd.set_runner(_dry())
    assert cli.main(_dry_argv("--dry-run")) == EXIT_OK
    printed = capsys.readouterr().out.lower()
    assert "permission add" not in printed
    assert "isfallbackpublicclient" not in printed


def test_dry_run_plans_consent_only_when_it_was_requested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    admin_cmd.set_runner(_dry())
    assert cli.main(_dry_argv("--mode", "delegated", "--dry-run", "--admin-consent")) == EXIT_OK
    assert "permission grant" in capsys.readouterr().out


def test_dry_run_reports_the_sign_in_instead_of_starting_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A dry run that looked like it was asking the operator to sign in would be a lie
    about a step that has not happened."""
    admin_cmd.set_runner(_dry())
    assert cli.main(_dry_argv("--mode", "delegated", "--dry-run", "--json")) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    entry = next(s for s in payload["steps"] if s["name"] == admin_cmd.STEP_SIGNIN)
    assert entry["outcome"] == "skipped"
    assert admin_cmd.DRY_SIGNIN_UPN in entry["detail"]


def test_dry_run_installs_no_streaming_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """B5's pin, extended to the delegated path: printing a plan must spawn nothing."""
    installed: list[Any] = []
    real = admin_cmd.set_runner

    def spy(runner: Any) -> None:
        installed.append(runner)
        real(runner)

    monkeypatch.setattr(admin_cmd, "set_runner", spy)
    admin_cmd.set_runner(_dry())
    assert cli.main(_dry_argv("--mode", "delegated", "--dry-run")) == EXIT_OK
    assert not any(isinstance(runner, admin_runner.StreamingRunner) for runner in installed)


# ===========================================================================
# BUG6 — `az ad app permission add` prints NOTHING on stdout
# ===========================================================================
# Verified against azure-cli 2.90.0's own source
# (``command_modules/role/custom.py``::``add_permission``): it PATCHes the
# registration and then emits ONE ``logger.warning`` — there is no ``return``
# statement, so knack's invoker gets ``None`` and ``cli.py`` skips the formatter
# entirely (``if cmd_result and cmd_result.result is not None``). Exit 0, empty
# stdout, the "run permission grant" note on stderr.
#
# The old code read that through ``run_json``, whose whole contract is "stdout is a
# JSON document", so it refused with ``'az' did not print JSON — WARNING: Invoking
# `az ad app permission grant ...``` on EVERY real delegated run. Same class as the
# ``az ad app update`` write below, and the reason the success claim must come from
# the tenant's own list rather than from az's stdout.

PERMISSION_ADD_PREFIX = ("az", "ad", "app", "permission", "add")
# NOT ``list-grants``: the fifth element distinguishes the two commands.
PERMISSION_LIST_PREFIX = ("az", "ad", "app", "permission", "list")
PUBLIC_CLIENT_UPDATE_PREFIX = ("az", "ad", "app", "update")

# az's own words on a SUCCESSFUL add (assembled from the module under test so this
# file keeps no extra GUID literal — design §5).
PERMISSION_ADD_WARNING = (
    "WARNING: Invoking `az ad app permission grant --id <appId> --api "
    + GRAPH_APP_ID
    + "` is needed to make the change effective"
)

SCOPE_ID_TO_NAME = {identifier.lower(): name for name, identifier in SCOPE_IDS.items()}


def permission_list_json(declared: Sequence[str]) -> str:
    """What ``az ad app permission list --id <app>`` prints.

    az does **not** project this one: it returns the application's whole
    ``requiredResourceAccess`` list, so a decoy entry for another API is part of the
    shape and proves the Microsoft Graph filter is doing its job.
    """
    graph_entry = {
        "resourceAppId": GRAPH_APP_ID,
        "resourceAccess": [
            {"id": SCOPE_IDS[name], "type": "Scope"} for name in declared if name in SCOPE_IDS
        ],
    }
    other_api = {
        # Somebody else's API: this step must neither read it as declared nor write it.
        "resourceAppId": GRAPH_SP_OBJECT_ID,
        "resourceAccess": [{"id": SP_OBJECT_ID, "type": "Scope"}],
    }
    return json.dumps([graph_entry, other_api])


def app_json_partial(declared: Sequence[str], *, public_client: bool = False) -> str:
    """The projected registration with EXACTLY ``declared`` delegated Graph scopes.

    This is the operator's live tenant after the first run died halfway: one of the
    five (``Mail.Send``) declared, the other four not.
    """
    access: list[dict[str, str]] = [{"id": SCOPE_IDS[SCOPES[0]], "type": "Role"}]
    access += [{"id": SCOPE_IDS[name], "type": "Scope"} for name in declared if name in SCOPE_IDS]
    return json.dumps(
        {
            "requiredResourceAccess": [
                {"resourceAppId": GRAPH_APP_ID, "resourceAccess": access}
            ],
            delegated_setup._PUBLIC_CLIENT_PROPERTY: public_client,
        }
    )


def _api_permission_id(argv: Sequence[str]) -> str:
    """The scope id out of ``--api-permissions <id>=Scope``."""
    if "--api-permissions" not in argv:
        return ""
    value = argv[argv.index("--api-permissions") + 1]
    return value.split("=", 1)[0].strip().lower()


class PermissionCli(TenantCli):
    """``TenantCli`` plus the two things a flat answer table cannot say about the write.

    * ``permission add`` answers the way az really does — exit 0, **nothing** on stdout,
      az's own WARNING on stderr. Every previous fixture answered it with ``"{}"``
      (:data:`NO_CONTENT`), which is a document az never prints, and that is exactly why
      the bug was invisible to the suite: the fake was more generous than the tool.
    * ``permission list`` (the read-back) reflects the adds the tenant was handed.
      ``adopt=False`` is the tenant that accepted the write and then did not show it —
      the state the success claim must catch.
    """

    def __init__(
        self,
        responses: dict[tuple[str, ...], str] | None = None,
        *,
        add_stdout: str = "",
        add_stderr: str = PERMISSION_ADD_WARNING,
        add_returncode: int = 0,
        declared: Sequence[str] = (),
        adopt: bool = True,
    ) -> None:
        super().__init__(responses)
        self.add_stdout = add_stdout
        self.add_stderr = add_stderr
        self.add_returncode = add_returncode
        self.declared = {name for name in declared if name in SCOPE_IDS}
        self.adopt = adopt
        self.added: list[str] = []

    def run(self, argv: Any, *, stdin: str | None = None, **kwargs: Any) -> Any:
        args = [str(a) for a in argv]
        if tuple(args[: len(PERMISSION_ADD_PREFIX)]) == PERMISSION_ADD_PREFIX:
            self.calls.append(args)
            if self.add_returncode == 0 and self.adopt:
                name = SCOPE_ID_TO_NAME.get(_api_permission_id(args), "")
                if name:
                    self.added.append(name)
            return subprocess.CompletedProcess(
                args, self.add_returncode, self.add_stdout, self.add_stderr
            )
        if tuple(args[: len(PERMISSION_LIST_PREFIX)]) == PERMISSION_LIST_PREFIX:
            self.calls.append(args)
            return subprocess.CompletedProcess(
                args, 0, permission_list_json(sorted(self.declared | set(self.added))), ""
            )
        return super().run(args, stdin=stdin, **kwargs)


def permission_stub(
    monkeypatch: pytest.MonkeyPatch,
    tenant: dict[tuple[str, ...], str],
    **cli_kwargs: Any,
) -> Stub:
    """A :class:`Stub` whose fake tenant is a :class:`PermissionCli`."""
    signin = SigninStub()
    signin.install(monkeypatch)
    stub = Stub(tenant, signin)
    stub.cli = PermissionCli(tenant, **cli_kwargs)
    admin_cmd.set_runner(stub.cli)
    return stub


def _adds(fake: PermissionCli) -> list[list[str]]:
    return [
        call
        for call in fake.calls
        if tuple(call[: len(PERMISSION_ADD_PREFIX)]) == PERMISSION_ADD_PREFIX
    ]


def test_a_permission_add_that_prints_nothing_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The bug, end to end: exit 0 + empty stdout + a WARNING on stderr means SUCCESS.

    On the pre-fix code this run dies at the first scope with
    ``'az' did not print JSON — WARNING: Invoking `az ad app permission grant ...```
    and exits 2, which is what the operator hit twice on a real tenant.
    """
    stub = permission_stub(monkeypatch, tenant_answers(), declared=())
    assert stub.delegated("--json") == EXIT_OK
    payload = stub.summary(capsys)
    assert payload["ok"] is True and payload["exitCode"] == EXIT_OK
    assert len(_adds(stub.cli)) == len(SCOPES)
    assert stub.outcome(capsys, admin_cmd.STEP_PERMISSIONS) == "created"
    text = json.dumps(payload)
    assert "did not print JSON" not in text, "az's healthy write was read as a failure"
    assert "needed to make the change effective" not in text, (
        "az's informational WARNING was surfaced as this step's failure"
    )


def test_a_partial_declaration_adds_only_the_missing_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator's live tenant: one of five declared, four not.

    The read-back has to be idempotent against a PARTIAL declaration, which is a
    different case from "nothing declared" (the first run) and "all declared" (a
    re-run): exactly the four missing scopes are written, and the one that was already
    there is reported as ``already_present`` rather than rewritten or ignored.
    """
    tenant = tenant_answers(public_client=True)
    tenant[("az", "ad", "app", "show")] = app_json_partial(["Mail.Send"], public_client=True)
    fake = PermissionCli(tenant, declared=["Mail.Send"])

    outcome = delegated_setup.ensure_delegated_permissions(APP_ID, SCOPES, runner=fake)

    assert outcome.already_present == ("Mail.Send",)
    assert outcome.granted == tuple(name for name in SCOPES if name != "Mail.Send")
    assert outcome.outcome == "created"
    adds = _adds(fake)
    assert len(adds) == 4, adds
    # Compared against the `--api-permissions <id>=Scope` value, not against the whole
    # argv: scope id 0 is derived from the all-zero placeholder and so is byte-identical
    # to APP_ID, which every add carries as `--id`. A substring check over the joined
    # argv would therefore fail on all four adds whatever this step wrote.
    written = {_api_permission_id(c) for c in adds}
    assert SCOPE_IDS["Mail.Send"].lower() not in written, (
        "a scope the registration already declared was written again"
    )


def test_an_add_the_tenant_did_not_apply_names_the_scope(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 is not the verdict — the tenant's own list is.

    A write that reported success and a read-back that still lacks the scope is the
    disagreement this step must refuse rather than report ``created``: the bootstrap
    would otherwise hand ``doctor`` and the sign-in a registration that cannot send.
    """
    stub = permission_stub(monkeypatch, tenant_answers(), declared=(), adopt=False)
    assert stub.delegated("--json") == 2
    text = json.dumps(stub.summary(capsys))
    assert SCOPES[0] in text, f"the scope that failed to appear was not named: {text}"
    assert "did not print JSON" not in text


def test_a_refused_permission_add_quotes_what_az_said(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A non-zero add still fails — and the operator gets az's own explanation.

    The empty stdout must not turn a genuine refusal into "did not print JSON": the
    exit code is the signal, stderr is the diagnosis, and the scope is the thing to
    name (one add per scope is what makes that possible).

    The tenant declares ``Mail.Send`` on BOTH sides — in the registration the step
    reads first and in the read-back — so the first add it attempts really is
    ``ChatMessage.Send``. Setting only the read-back side would leave the pre-write
    read empty, make the first add ``Mail.Send``, and name the wrong scope.
    """
    tenant = tenant_answers(public_client=True)
    tenant[("az", "ad", "app", "show")] = app_json_partial(
        ["Mail.Send"], public_client=True
    )
    stub = permission_stub(
        monkeypatch,
        tenant,
        declared=["Mail.Send"],
        adopt=False,
        add_returncode=1,
        add_stderr="ERROR: At least one permission assigned to your app is invalid.",
    )
    assert stub.delegated("--json") == 2
    text = json.dumps(stub.summary(capsys))
    assert "permission assigned to your app is invalid" in text, text
    assert "ChatMessage.Send" in text, "the failing scope was not named"


def test_a_public_client_update_that_prints_nothing_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same az contract one step later: ``az ad app update`` prints nothing either.

    ``--set`` goes through az's generic update, whose setter is the same PATCH call, so
    knack again has nothing to print. Proven by the same reading of the installed
    azure-cli: the update is a PATCH whose 204 body is empty, ``_send`` returns
    ``None``, and the formatter is skipped.
    """
    tenant = tenant_answers(public_client=False)
    fake = PermissionCli(tenant)
    fake.set(PUBLIC_CLIENT_UPDATE_PREFIX, "", 0)

    outcome = delegated_setup.ensure_public_client_flows(APP_ID, runner=fake)

    assert outcome.enabled is True and outcome.outcome == "created"
    sets = [
        call
        for call in fake.calls
        if tuple(call[: len(PUBLIC_CLIENT_UPDATE_PREFIX)]) == PUBLIC_CLIENT_UPDATE_PREFIX
    ]
    assert len(sets) == 1, sets


def test_the_shipped_dry_run_answers_plan_a_whole_delegated_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--dry-run`` on a machine with no ``az``: the shipped table alone must suffice.

    Deliberately built from :data:`admin_cmd.DRY_RUN_RESPONSES` rather than this
    module's ``_dry()`` — that dict is what a real ``--dry-run`` installs, and it was
    missing the two answers the delegated reads need (``az ad app show`` and
    ``az ad sp show``), which is why the operator's own dry run died at the same step
    as the real one.
    """
    recorder = admin_runner.DryRunRunner(admin_cmd.DRY_RUN_RESPONSES)
    admin_cmd.set_runner(recorder)
    assert cli.main(_dry_argv("--mode", "delegated", "--dry-run")) == EXIT_OK
    assert recorder.executed_anything is False
    printed = capsys.readouterr().out
    assert "permission add" in printed
    assert "isFallbackPublicClient=true" in printed
    assert "permission grant" not in printed, "planned a consent nobody asked for"
    assert "ManagementScope" not in printed, "planned app mode's Exchange work"


def test_the_shipped_dry_run_plans_the_consent_it_was_asked_for(
    capsys: pytest.CaptureFixture[str],
) -> None:
    recorder = admin_runner.DryRunRunner(admin_cmd.DRY_RUN_RESPONSES)
    admin_cmd.set_runner(recorder)
    assert (
        cli.main(_dry_argv("--mode", "delegated", "--dry-run", "--admin-consent")) == EXIT_OK
    )
    assert recorder.executed_anything is False
    assert "permission grant" in capsys.readouterr().out
