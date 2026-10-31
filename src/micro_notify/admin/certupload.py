"""Certificate credential upload for ``mnotify admin bootstrap`` (design §6 step 1).

This is the code behind the second write step of the bootstrap: turning the local
key pair into an Entra *certificate credential* on the app registration B2
resolved, and proving the upload landed. The portal route in
``docs/ADMIN-SETUP.md`` §1.2–1.3 does the same thing by hand; doing it here exists
because the hand route has two failure modes an operator cannot see:

* the credential silently expires early. ``az ad app credential reset`` defaults
  ``--end-date`` to **one year from now**, whatever the certificate's real validity
  is (the generated certificate lives 825 days). The credential then dies while the
  key is still fine, and the only symptom is a ``401`` from Graph weeks later. This
  was hit live on 2026-10-30. So ``--end-date`` is always passed, always taken from
  the certificate's own ``notAfter`` — never a constant, never a guess.
* the upload "succeeds" and the thumbprints do not match. Then every token request
  fails with an AADSTS error that points at the wrong component. So after the upload
  the step re-reads the app's credentials and refuses unless the keychain thumbprint
  is actually there.

What is a secret here
---------------------

The **private key never leaves the keychain**. It lives in account
``graph.certificate_pem`` (design §3.4) and this module only ever asks whether that
account exists — it never reads its value into a result, an argv, a message or a
file. The only thing written to disk is the **public** certificate, into a 0600
temporary file that is removed in a ``finally`` (the same hygiene as
``mnotify setup``'s public PEM). The thumbprint is not a secret: it is what Entra
displays and what §1.3 asks the operator to compare, so it is reported.

Reuse, never a second key pair
------------------------------

The generation path is :func:`micro_notify.certgen.generate_certificate` — the same
one ``mnotify setup --gen-cert`` uses, so both routes store the same pair of
accounts and ``doctor`` can check either. When the keychain already holds a complete
pair *and* its thumbprint is already uploaded, this step reports ``exists`` and does
nothing else: no new key, no keychain write, no upload. A keychain pair that is only
half there (PEM without thumbprint, or the reverse) refuses rather than silently
overwriting a key the operator may still be using elsewhere.

Every ``az`` call goes through :mod:`micro_notify.admin.runner` — no ``subprocess``
here — so a test swaps in a fake that answers canned JSON, and an ``az`` answer this
step cannot read is an error rather than a "not uploaded" that triggers a new key.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import os
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from .. import AuthError, certgen, secrets
from .runner import STDERR_QUOTE_LIMIT, CommandRunner, get_runner, run_json

# --- Vocabulary --------------------------------------------------------------
# Same two outcomes as admin/entra.py and admin/exo.py, so B5 can print one column.
OUTCOME_CREATED = "created"
OUTCOME_EXISTS = "exists"

# The wire format az itself uses for credential dates
# (``azure.cli.command_modules.role.custom._datetime_to_utc``). dateutil also
# accepts "+00:00", but matching az's own format keeps the value az echoes back
# byte-identical to what we sent, which is what makes the verification readable.
CERT_END_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Prefix of the 0600 temp file holding the public certificate. Deliberately not
# certgen's "mnotify-cert-" (which names its private-key *directory*) so a stray
# file from either path is recognisable at a glance.
PUBLIC_CERT_PREFIX = "mnotify-public-cert-"

# A SHA-1 thumbprint is 20 bytes: 40 hex characters, or 27 base64 characters
# ("=" padded). Both spellings appear in the wild — Graph returns base64 in
# ``customKeyIdentifier``, the keychain holds the upper-case hex msal wants.
SHA1_HEX_LENGTH = 40
SHA1_RAW_LENGTH = 20

# How many other credentials are named in a rotation hint.
MAX_LISTED_IDS = 5


class CertUploadError(AuthError):
    """The certificate credential cannot be established -> exit 4.

    An :class:`~micro_notify.AuthError` rather than a usage error: every case here
    is a credential problem the operator fixes in the keychain or in Entra, not a
    bad flag. The message names accounts, app ids and thumbprints — never a key.
    """


# --- Result shapes (declared seam for B5) ------------------------------------
@dataclass(frozen=True)
class UploadedCredential:
    """One certificate credential as Entra reports it (metadata only, no key)."""

    thumbprint: str
    end_date: str = ""
    key_id: str = ""

    def end_date_dt(self) -> datetime.datetime | None:
        """``end_date`` parsed as UTC, or ``None`` when Entra did not send a date."""
        if not self.end_date:
            return None
        text = self.end_date.strip()
        # ``fromisoformat`` accepts the trailing Z only on 3.11+; this package
        # requires 3.12, and a value az produced always parses.
        try:
            parsed = datetime.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed

    def expired(self, now: datetime.datetime) -> bool:
        """True only when a readable end date is in the past.

        An unreadable or missing date is **not** treated as expired: this feeds a
        report line, and claiming an operator's credential is dead because a date
        field moved would be a worse lie than staying quiet about it.
        """
        parsed = self.end_date_dt()
        return parsed is not None and parsed <= now

    def to_dict(self) -> dict[str, Any]:
        return {
            "thumbprint": self.thumbprint,
            "end_date": self.end_date,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class CertificateProvisioning:
    """What the certificate step did — what ``--json`` reports for it.

    ``created`` is True when this run uploaded a credential, and ``generated`` is
    True when it also made the key pair (so an operator who had a key and merely
    had not uploaded it sees ``created`` without ``generated``). ``expires_at`` is
    the date the credential actually stops working: the certificate's ``notAfter``
    on the upload path, Entra's ``endDateTime`` on the reuse path — which is how a
    credential capped at one year by an older version of this tool becomes visible.
    ``replaced_thumbprint`` carries the keychain thumbprint this run overwrote, so
    an operator who had a key for a *different* app registration can see that the
    old certificate is now orphaned on this machine.
    """

    app_id: str
    thumbprint: str
    created: bool
    generated: bool = False
    expires_at: str = ""
    other_credentials: int = 0
    expired: bool = False
    replaced_thumbprint: str = ""

    @property
    def outcome(self) -> str:
        return OUTCOME_CREATED if self.created else OUTCOME_EXISTS

    @property
    def detail(self) -> str:
        """One operator-facing line saying what this run did."""
        if self.created and self.generated:
            base = (
                f"generated a key pair and uploaded its public certificate "
                f"(thumbprint {self.thumbprint})"
            )
        elif self.created:
            base = f"uploaded the keychain certificate (thumbprint {self.thumbprint})"
        elif self.expired:
            base = (
                f"certificate {self.thumbprint} is already uploaded but expired"
                + (f" on {self.expires_at}" if self.expires_at else "")
                + " — re-run `mnotify setup --gen-cert` and this step to rotate it"
            )
        else:
            base = f"certificate {self.thumbprint} is already uploaded"
        if self.expires_at and not self.expired:
            base += f"; valid until {self.expires_at}"
        if self.replaced_thumbprint:
            base += (
                f"; replaced keychain certificate {self.replaced_thumbprint} "
                "(still valid in the tenant it was uploaded to)"
            )
        if self.other_credentials > 0:
            base += (
                f"; {self.other_credentials} other certificate credential(s) are "
                "uploaded on this app — remove the old ones once this one sends"
            )
        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "thumbprint": self.thumbprint,
            "created": self.created,
            "generated": self.generated,
            "expires_at": self.expires_at,
            "other_credentials": self.other_credentials,
            "expired": self.expired,
            "replaced_thumbprint": self.replaced_thumbprint,
            "outcome": self.outcome,
            "detail": self.detail,
        }


# --- Reading what the machine and the tenant already hold --------------------
def keychain_thumbprint() -> str | None:
    """The thumbprint of the keychain certificate pair, or ``None`` if there is none.

    Presence is checked with :func:`micro_notify.secrets.has`, so the private key's
    *value* is never returned from this function — it is not needed to decide
    anything here, and keeping it out of the return type is what lets a test assert
    the key never reaches ``az``.

    A half-stored pair is refused rather than repaired: overwriting
    ``graph.certificate_pem`` because its thumbprint account went missing would
    destroy the private half of a certificate some other machine may still be
    presenting to Entra.
    """
    pem_present = secrets.has(secrets.ACCOUNT_CERT_PEM)
    thumbprint_present = secrets.has(secrets.ACCOUNT_CERT_THUMBPRINT)
    if pem_present != thumbprint_present:
        missing = (
            secrets.ACCOUNT_CERT_THUMBPRINT
            if pem_present
            else secrets.ACCOUNT_CERT_PEM
        )
        present = (
            secrets.ACCOUNT_CERT_PEM if pem_present else secrets.ACCOUNT_CERT_THUMBPRINT
        )
        raise CertUploadError(
            f"the keychain holds '{present}' but not '{missing}' (service "
            f"'{secrets.SERVICE}'): refusing to overwrite a certificate pair that "
            "is only half stored. Delete both accounts, or re-run "
            "`mnotify setup --gen-cert` on the machine that owns the key"
        )
    if not pem_present:
        return None
    value = (secrets.get(secrets.ACCOUNT_CERT_THUMBPRINT) or "").strip()
    thumbprint = _normalise_thumbprint(value)
    if not thumbprint:
        raise CertUploadError(
            f"'{secrets.ACCOUNT_CERT_THUMBPRINT}' (service '{secrets.SERVICE}') is "
            "not a SHA-1 thumbprint; re-run `mnotify setup --gen-cert`"
        )
    return thumbprint


def list_uploaded_credentials(
    app_id: str, *, runner: CommandRunner | None = None
) -> list[UploadedCredential]:
    """``az ad app credential list --id <appId> --cert`` parsed into credentials.

    An empty list is the honest "nothing uploaded" answer. Anything this call cannot
    read raises instead: a response that parses as *no credentials* is the one answer
    that makes this module generate a new key pair and write the keychain, so
    guessing wrong there costs the operator their existing certificate.
    """
    checked = _check_app_id(app_id)
    payload = run_json(
        ["az", "ad", "app", "credential", "list", "--id", checked, "--cert"],
        runner=runner,
    )
    entries = _as_entries(payload)
    credentials: list[UploadedCredential] = []
    for entry in entries:
        thumbprint = _thumbprint_from_entry(entry)
        if not thumbprint:
            raise CertUploadError(
                "the app's certificate credentials came back without a readable "
                "thumbprint; refusing to treat a credential it cannot identify as "
                f"'not uploaded' (check with `az ad app credential list --id "
                f"{checked} --cert`)"
            )
        credentials.append(
            UploadedCredential(
                thumbprint=thumbprint,
                end_date=_text(entry, "endDateTime"),
                key_id=_text(entry, "keyId"),
            )
        )
    return credentials


# --- The certificate itself --------------------------------------------------
def certificate_end_date(public_key_pem: str) -> str:
    """The ``--end-date`` value for one public certificate, from its own ``notAfter``.

    This is the 1-year-cap fix: the credential must die when the certificate does,
    not one year after the day the operator happened to run the command. Parsing the
    certificate rather than computing ``now + 825 days`` also keeps the value correct
    for a certificate the operator generated themselves with a different validity.
    """
    return _format_utc(_certificate_not_after(public_key_pem))


def write_public_certificate_file(public_key_pem: str) -> str:
    """Write ``public_key_pem`` to a private 0600 temp file and return its path.

    Public material only — the caller must not pass anything containing a private
    key, and :func:`upload_certificate` refuses if it does (see there). ``O_EXCL``
    means an existing name is never clobbered: a collision moves to a fresh name
    instead of overwriting someone else's file with our bytes.
    """
    if _looks_like_private_key(public_key_pem):
        # Belt and braces: this function's name promises public material.
        raise CertUploadError("refusing to write a private key to a temporary file")
    directory = tempfile.gettempdir()
    last_error: OSError | None = None
    for _ in range(5):
        path = os.path.join(directory, f"{PUBLIC_CERT_PREFIX}{uuid.uuid4().hex}.pem")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:  # collision: try a fresh name
            last_error = exc
            continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(public_key_pem)
            # The mode is fixed after the write too: umask can lower the create mode
            # but never raise it, and the value handed to O_CREAT is masked.
            os.chmod(path, 0o600)
        except OSError:
            _remove(path)
            raise
        return path
    raise CertUploadError(
        f"cannot create a private temporary file in {directory}"
        + (f": {type(last_error).__name__}" if last_error else "")
    )


def upload_certificate(
    app_id: str,
    public_key_pem: str,
    *,
    runner: CommandRunner | None = None,
) -> str:
    """Upload the public certificate and return the ``--end-date`` that was sent.

    The PEM goes to a 0600 temp file because ``az`` takes the certificate as
    ``--cert @path``; the file is deleted in a ``finally`` so no exit path —
    including a failed upload — leaves certificate material behind. The private key
    is never passed to this function and never appears in argv.
    """
    checked = _check_app_id(app_id)
    _refuse_recording_runner(runner)
    end_date = certificate_end_date(public_key_pem)
    path = write_public_certificate_file(public_key_pem)
    try:
        _run_checked(
            reset_command(checked, pem_argument="@" + path, end_date=end_date),
            app_id=checked,
            runner=runner,
            label="az ad app credential reset",
        )
    finally:
        _remove(path)
    return end_date


def reset_command(
    app_id: str, *, pem_argument: str, end_date: str
) -> list[str]:
    """The exact argv that uploads one certificate.

    Three flags carry the whole contract, and each is pinned by a test because each
    has caused a live failure:

    ``--cert @<path>``
        the public PEM, via a file so the bytes never ride in argv (``ps`` and shell
        history are readable by other users on a shared machine);
    ``--append``
        without it az *clears every existing credential first* — on a tenant that
        already has a working certificate that means an instant outage;
    ``--end-date``
        without it az caps the credential at one year regardless of the certificate's
        validity, which is the bug this module exists to fix.
    """
    checked = _check_app_id(app_id)
    if not pem_argument:
        raise CertUploadError("the certificate argument must not be empty")
    if not end_date:
        raise CertUploadError(
            "the credential end date must not be empty — az would silently cap the "
            "credential at one year"
        )
    return [
        "az",
        "ad",
        "app",
        "credential",
        "reset",
        "--id",
        checked,
        "--cert",
        pem_argument,
        "--append",
        "--end-date",
        end_date,
    ]


def plan_certificate_upload(
    app_id: str, *, end_date: str | None = None
) -> list[str]:
    """The argv ``mnotify admin bootstrap --dry-run`` prints, with no real paths.

    The same shape as ``admin.exo.plan_commands``: a pure function of its arguments
    that touches no keychain, no temp directory and no network, so B5 can print the
    plan without the ``if dry_run`` branches B1's docstring forbids. The PEM path is
    a marker because a dry run writes no file, and inventing one that looks real
    would be worse than admitting the step has not happened.

    Import it module-qualified (``from micro_notify.admin import certupload``, like
    ``preflight.run_preflight``): B4 exports a same-named plan from ``exo`` and two
    same-named re-exports from the package root would shadow each other by import
    order.
    """
    return reset_command(
        app_id,
        pem_argument="@<public-certificate-path>",
        end_date=end_date or "<certificate-not-after>",
    )


# --- Verification ------------------------------------------------------------
def verify_uploaded(
    app_id: str, thumbprint: str, *, runner: CommandRunner | None = None
) -> UploadedCredential:
    """Assert the thumbprint is present among the app's credentials; return it.

    The read-back is not ceremony. ``az ad app credential reset`` exits 0 when Graph
    accepted the patch, and a credential can still be useless — the classic case
    being the keychain and the app holding *different* certificates, which produces
    an AADSTS error at send time that looks like a permissions problem.
    """
    checked = _check_app_id(app_id)
    wanted = _normalise_thumbprint(thumbprint)
    if not wanted:
        raise CertUploadError("cannot verify an upload without a SHA-1 thumbprint")
    return _match_or_raise(checked, wanted, list_uploaded_credentials(checked, runner=runner))


def _match_or_raise(
    app_id: str, wanted: str, credentials: list[UploadedCredential]
) -> UploadedCredential:
    """The one wording used when a thumbprint is not among the credentials."""
    for credential in credentials:
        if credential.thumbprint == wanted:
            return credential
    raise CertUploadError(
        f"the certificate was not accepted for app {app_id}: no uploaded "
        f"credential has thumbprint {wanted} "
        f"(found {len(credentials)} certificate credential(s): "
        f"{_preview(c.thumbprint for c in credentials)}). The keychain pair and the "
        "app registration are out of sync — re-run this step, or re-upload the "
        "public certificate manually (docs/ADMIN-SETUP.md §1.3)"
    )


# --- The step itself --------------------------------------------------------
def ensure_certificate_credential(
    app_id: str,
    *,
    runner: CommandRunner | None = None,
    cert_runner: Callable[..., Any] | None = None,
    common_name: str = certgen.DEFAULT_COMMON_NAME,
    now: datetime.datetime | None = None,
) -> CertificateProvisioning:
    """Make the app hold the public half of the keychain certificate. Idempotent.

    Order: read the keychain, read the tenant, and only then write anything. The two
    reads come first because they are the only thing that can *avoid* a side effect —
    a re-run on a configured tenant issues two reads and no writes, generates no key,
    touches no keychain account and creates no temp file.

    Three states, in the order the reads can distinguish them:

    * keychain pair whose thumbprint is among the app's credentials -> ``exists``,
      nothing generated, nothing written (the card's "do not regenerate" rule);
    * keychain pair that does **not** match -> the pair is useless for this app (the
      public certificate cannot be rebuilt from the keychain, which holds only the
      private half), so a fresh pair is generated and uploaded, and the thumbprint
      that got replaced is reported so the orphan is visible;
    * no keychain pair at all -> generate and upload, the same path
      ``mnotify setup --gen-cert`` + §1.3 take by hand.

    ``cert_runner`` is passed straight to
    :func:`micro_notify.certgen.generate_certificate` (which drives ``openssl`` with
    its own ``subprocess.run``-shaped callable, not this package's
    :class:`CommandRunner`); it exists so a test can supply a throwaway certificate
    without ever running ``openssl``. ``now`` only affects the *reporting* of
    expiry, never a decision.

    Raises :class:`CertUploadError` (exit 4) when the credential cannot be proven to
    exist afterwards. ``micro_notify.UsageError`` from :mod:`micro_notify.certgen`
    (exit 2) propagates unchanged on an ``openssl`` failure, because that module's
    wording already names the fix.

    A runner that records without executing — ``--dry-run``'s
    :class:`~micro_notify.admin.runner.DryRunRunner`, recognised by its declared
    ``executed_anything`` property — never reaches the write path. The reason is not
    tidiness: the az half of this step would record and do nothing, so the
    verification could not pass, while the *local* halves (``openssl``, the keychain)
    do not go through that seam and would really run — replacing the operator's
    private key on a run that promised to change nothing. The read-only answer
    (``exists``, or the refusal to write) is all such a runner gets;
    :func:`plan_certificate_upload` is what ``--dry-run`` prints instead, the same
    arrangement B4 settled on for the Exchange script.
    """
    checked = _check_app_id(app_id)
    moment = now or datetime.datetime.now(datetime.timezone.utc)

    # --- reads ---------------------------------------------------------------
    existing = keychain_thumbprint()
    uploaded = list_uploaded_credentials(checked, runner=runner)
    if existing is not None:
        match = next((c for c in uploaded if c.thumbprint == existing), None)
        if match is not None:
            # Nothing to do and nothing to regenerate: this is the re-run path.
            return CertificateProvisioning(
                app_id=checked,
                thumbprint=existing,
                created=False,
                generated=False,
                expires_at=match.end_date,
                other_credentials=max(len(uploaded) - 1, 0),
                expired=match.expired(moment),
            )

    # --- writes --------------------------------------------------------------
    # Nothing above this line touched the machine. Everything below it does, so a
    # runner that only records has to stop here — the local half of this step
    # (openssl, the keychain) does not go through the runner seam and would really
    # run, replacing the operator's private key during a `--dry-run`.
    _refuse_recording_runner(runner)
    generated = certgen.generate_certificate(common_name=common_name, runner=cert_runner)
    secrets.set_secret(secrets.ACCOUNT_CERT_PEM, generated.private_key_pem)
    secrets.set_secret(secrets.ACCOUNT_CERT_THUMBPRINT, generated.certificate_thumbprint)

    end_date = upload_certificate(checked, generated.public_key_pem, runner=runner)
    after_upload = list_uploaded_credentials(checked, runner=runner)
    credential = _match_or_raise(
        checked,
        _normalise_thumbprint(generated.certificate_thumbprint),
        # One read does both jobs: it proves the upload landed (the card's
        # thumbprint-verify requirement) and it counts the credentials left behind,
        # which is what makes a stale certificate visible to the operator.
        after_upload,
    )
    return CertificateProvisioning(
        app_id=checked,
        thumbprint=generated.certificate_thumbprint,
        created=True,
        generated=True,
        expires_at=credential.end_date or end_date,
        other_credentials=max(len(after_upload) - 1, 0),
        expired=False,
        replaced_thumbprint=existing or "",
    )


# --- az plumbing -------------------------------------------------------------
def _refuse_recording_runner(runner: CommandRunner | None) -> None:
    """Stop a runner that records without executing from doing local damage.

    Detection is by the capability the runner declares — B1's
    :class:`~micro_notify.admin.runner.DryRunRunner` advertises
    ``executed_anything`` precisely so a module can ask "will you really run
    this?" — the same way B4 asks for ``run_streaming``. It is not a
    ``if dry_run`` branch in the command layer, which B1's seam forbids.

    The refusal matters because only *part* of this step goes through the seam.
    Under a recording runner the ``az`` calls would be recorded and skipped, so the
    post-upload verification could never pass; meanwhile ``openssl`` and the keychain
    — reached through their own injection points — would really execute, so a
    ``--dry-run`` would replace the operator's private key and report a failure.
    """
    active = runner or get_runner()
    if not hasattr(active, "executed_anything"):
        return
    if not getattr(active, "executed_anything"):
        raise CertUploadError(
            "this runner records commands instead of executing them, and the "
            "certificate step's local half (key generation, keychain) does not go "
            "through it: a dry run would replace your private key while changing "
            "nothing in the tenant. Print the plan instead with "
            "`mnotify admin bootstrap --dry-run` (see "
            "micro_notify.admin.certupload.plan_certificate_upload)"
        )


def _run_checked(
    argv: Sequence[str],
    *,
    app_id: str,
    runner: CommandRunner | None,
    label: str,
) -> Any:
    """Run a write command and require a zero exit — without parsing its stdout.

    Deliberately not :func:`~micro_notify.admin.runner.run_json`: the value of a
    credential upload is not in what az prints (a bare ``{"appId": ..., "password":
    null}``, plus a warning the operator must not act on) but in the credential list
    the caller re-reads afterwards. Requiring JSON here would turn a successful
    upload on an az version that prints nothing into a failure.
    """
    args = [str(a) for a in argv]
    result = (runner or get_runner()).run(args)
    returncode = getattr(result, "returncode", None)
    if returncode is None or int(returncode) != 0:
        code = "unknown" if returncode is None else int(returncode)
        raise CertUploadError(
            f"`{label}` failed (exit {code})"
            f"{_quote_stderr(getattr(result, 'stderr', None))}"
            f" — the certificate was not uploaded for app {app_id}"
        )
    return result


def _quote_stderr(stderr: Any) -> str:
    """One collapsed, bounded line of az's own stderr, or ``''``.

    Same wording budget as :mod:`micro_notify.admin.runner` (whose private helper
    this mirrors rather than imports: reaching into another card's underscore names
    makes a rename in B1 a silent break here).
    """
    line = " ".join(str(stderr or "").split())
    if not line:
        return ""
    if len(line) > STDERR_QUOTE_LIMIT:
        line = line[:STDERR_QUOTE_LIMIT].rstrip() + "..."
    return f" — {line}"


def _as_entries(payload: Any) -> list[Mapping[str, Any]]:
    """A credential list payload as objects; anything else raises.

    ``az`` answers this command with a JSON array (it returns the application's
    ``keyCredentials`` property directly). An envelope, a ``null`` or a list of
    scalars would read as "zero credentials" — and "zero credentials" is the answer
    this module reacts to by generating a new key pair and rewriting the keychain.
    """
    if isinstance(payload, list):
        entries: list[Mapping[str, Any]] = []
        for item in payload:
            if not isinstance(item, Mapping):
                raise CertUploadError(
                    "`az ad app credential list` printed a list containing "
                    f"{type(item).__name__}, not credential objects; refusing to "
                    "treat a credential list it cannot read as 'not uploaded'"
                )
            entries.append(item)
        return entries
    raise CertUploadError(
        "`az ad app credential list` did not print a list of credentials "
        f"(got {type(payload).__name__}); refusing to read an unreadable answer "
        "as 'no certificate uploaded'"
    )


# --- Thumbprints -------------------------------------------------------------
def _thumbprint_from_entry(entry: Mapping[str, Any]) -> str:
    """The thumbprint of one credential entry, however az spelled it.

    Graph computes ``customKeyIdentifier`` as the certificate's SHA-1 fingerprint and
    az returns it base64-encoded; some callers and older tools carry the same 20 bytes
    as hex (with or without colons). Both are normalised to upper-case hex, which is
    also the spelling the keychain and msal use.
    """
    for key in ("customKeyIdentifier", "thumbprint"):
        value = _text(entry, key)
        if value:
            normalised = _normalise_thumbprint(value)
            if normalised:
                return normalised
    return ""


def _normalise_thumbprint(value: str) -> str:
    """Upper-case hex for a SHA-1 thumbprint, or ``''`` when it is not one.

    Hex is tried first on purpose: a 40-character hex string is also a syntactically
    valid base64 string (it decodes to 30 bytes), so ordering the other way would
    reject the common spelling.
    """
    if not isinstance(value, str):
        return ""
    text = value.strip().replace(":", "").replace(" ", "")
    if not text:
        return ""
    if len(text) == SHA1_HEX_LENGTH and _is_hex(text):
        return text.upper()
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return ""
    if len(raw) != SHA1_RAW_LENGTH:
        return ""
    return raw.hex().upper()


def _is_hex(text: str) -> bool:
    return all(ch in "0123456789abcdefABCDEF" for ch in text)


def _looks_like_private_key(text: str) -> bool:
    """Whether ``text`` carries a PEM private-key header.

    The header is assembled at runtime rather than written as a literal: this repo's
    leak guard (tests/test_leak_guard.py) treats a private-key PEM header in any
    tracked file as a finding, and the same convention its own canary tests use
    applies here. The pattern covers every spelling the guard covers — bare
    ``PRIVATE KEY``, ``RSA PRIVATE KEY``, ``ENCRYPTED PKCS8 PRIVATE KEY`` — because
    the thing being refused here is any of them, not one of them.
    """
    if not isinstance(text, str):
        return False
    marker = "PRIVATE KEY"
    head = "-----" + "BEGIN "
    tail = "-----"
    start = text.find(head)
    while start != -1:
        line_end = text.find("\n", start)
        line = text[start : line_end if line_end != -1 else len(text)]
        if line.endswith(tail) and marker in line:
            return True
        start = text.find(head, start + len(head))
    return False


# --- Date handling -----------------------------------------------------------
def _certificate_not_after(public_key_pem: str) -> datetime.datetime:
    """The certificate's ``notAfter`` as an aware UTC datetime."""
    if not isinstance(public_key_pem, str) or not public_key_pem.strip():
        raise CertUploadError("the public certificate is empty")
    try:
        certificate = x509.load_pem_x509_certificate(public_key_pem.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any parse failure is one message
        # Type only: cryptography's parse errors can quote the input it rejected,
        # and an operator pasting a whole PEM should not see it echoed back.
        raise CertUploadError(
            f"the public certificate could not be read ({type(exc).__name__}); "
            "re-run `mnotify setup --gen-cert`"
        ) from exc
    # ``not_valid_after`` (naive) is deprecated and being removed; ``not_valid_after_utc``
    # is the 42+ spelling. The fallback keeps an older installed cryptography working,
    # and treats the naive value as UTC, which is what X.509 means.
    aware = getattr(certificate, "not_valid_after_utc", None)
    if aware is not None:
        return _as_utc(aware)
    naive = getattr(certificate, "not_valid_after", None)
    if naive is None:
        raise CertUploadError("the public certificate has no expiry date")
    return _as_utc(naive)


def _as_utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _format_utc(value: datetime.datetime) -> str:
    return _as_utc(value).strftime(CERT_END_DATE_FORMAT)


# --- Small guards ------------------------------------------------------------
# Characters an app id may contain. The id is a path-ish value in every az command
# this module builds, and a value that starts with '-' would be read as an option.
_ID_SAFE_CHARS = frozenset("0123456789abcdefABCDEF-")


def _check_app_id(app_id: str) -> str:
    """Validate the app id before it reaches ``az`` (same rule as admin/entra.py)."""
    if not isinstance(app_id, str) or not app_id:
        raise CertUploadError("the application id must not be empty")
    if app_id != app_id.strip():
        raise CertUploadError(
            f"the application id {app_id!r} has leading or trailing whitespace"
        )
    if app_id.startswith("-"):
        raise CertUploadError(
            f"the application id {app_id!r} starts with '-', which az would read "
            "as an option"
        )
    if any(ch not in _ID_SAFE_CHARS for ch in app_id):
        raise CertUploadError(
            "the application id must be a GUID (hex digits and dashes); got "
            "something else, which is not safe to pass to az"
        )
    return app_id


def _text(entry: Mapping[str, Any], key: str) -> str:
    """``entry[key]`` as a stripped string, or ``''`` when absent/not a string."""
    value: Any = entry.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def _preview(values: Sequence[str] | Any) -> str:
    """First few values, comma-joined — enough to point at the wrong credential."""
    shown = [v or "<missing>" for v in list(values)[:MAX_LISTED_IDS]]
    return ", ".join(shown) if shown else "<none>"


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        # Already gone, or not ours to remove. The run must not fail over a file
        # that is not there — but the caller's `finally` is what guarantees we get
        # here at all.
        pass


__all__ = [
    "CERT_END_DATE_FORMAT",
    "OUTCOME_CREATED",
    "OUTCOME_EXISTS",
    "PUBLIC_CERT_PREFIX",
    "CertUploadError",
    "CertificateProvisioning",
    "UploadedCredential",
    "certificate_end_date",
    "ensure_certificate_credential",
    "keychain_thumbprint",
    "list_uploaded_credentials",
    "plan_certificate_upload",
    "reset_command",
    "upload_certificate",
    "verify_uploaded",
    "write_public_certificate_file",
]
