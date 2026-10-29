"""Leak guard for a repo that goes public at v0.1.0 (design section 5).

Scans every tracked file (``git ls-files``) and fails on:

* a GUID that is not the documented placeholder (all-zero) or all-ones;
* a **scheme-bearing** webhook URL for the Workflows / connector hosts;
* a private-key PEM header;
* an e-mail address whose domain is not example.com / contoso.com;
* the literal word for the vendor in a tracked file or path.

Scope ruling from the orchestrator (2026-10-27), implemented here: design §5
targets webhook **URLs**, not the words. Every webhook pattern therefore requires
``http(s)://`` followed by a real host label, and the host position excludes ``*``
— so docs that name the hosts descriptively (``*.logic.azure.com`` and
``https://*.logic.azure.com``, exactly how ROADMAP.md and design §5 phrase the
rule) are not findings. Same for private keys: the PEM header is the finding, the
phrase "private key" is not. Do not work around this guard by rewording a doc.

The positive-detection tests build their canaries **at runtime by
concatenation**, so no canary ever appears literally in a tracked file while the
guard is still proven to bite.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# --- Documented placeholders -------------------------------------------------
NULL_GUID = "00000000-0000-0000-0000-000000000000"
ONES_GUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
ALLOWED_GUIDS = frozenset({NULL_GUID.lower(), ONES_GUID.lower()})

ALLOWED_EMAIL_DOMAINS = frozenset({"example.com", "contoso.com"})

# --- Patterns ----------------------------------------------------------------
GUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
PEM_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
# The TLD must be alphabetic: ``python@3.12`` is a Homebrew formula name that has
# to appear in the tap formula (design §5), and a numeric TLD is not a real mailbox.
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
# The vendor's name in its own script (U+5FAE U+8F6F U+4FE1 U+606F). Written as code
# points so this guard file stays free of it.
VENDOR_WORD = re.compile("".join(chr(c) for c in (0x5FAE, 0x8F6F, 0x4FE1, 0x606F)))

# Characters allowed between the scheme and the target host. `*` is excluded on
# purpose: `https://*.logic.azure.com` in the design doc is prose, not a URL.
HOST_CHARS = r"[^\s\"'<>*]"


def webhook_url_pattern(host: str) -> re.Pattern[str]:
    """Scheme-bearing webhook URL pattern for one host."""
    return re.compile(r"https?://" + HOST_CHARS + "*" + re.escape(host), re.IGNORECASE)


def _host(*labels: str) -> str:
    """Assemble a host from labels so this file carries no complete host literal."""
    return ".".join(labels) + ".com"


# Hosts a real Workflows (or retired connector) webhook URL can carry.
AZURE_LOGIC_HOST = _host("logic", "azure")
POWERPLATFORM_HOST = _host("powerplatform")
OUTLOOK_WEBHOOK_HOST = _host("outlook", "office")

WEBHOOK_PATTERNS = (
    webhook_url_pattern(AZURE_LOGIC_HOST),
    webhook_url_pattern(POWERPLATFORM_HOST),
    # The retired Office 365 connector path (design §3.2) carries a signature too.
    re.compile(
        r"https?://" + HOST_CHARS + "*" + re.escape(OUTLOOK_WEBHOOK_HOST) + r"/webhook/",
        re.IGNORECASE,
    ),
)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    names = [n for n in result.stdout.split("\0") if n]
    return [REPO_ROOT / name for name in names]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def scan_text(text: str) -> list[str]:
    """Return every finding in ``text``. An empty list means clean."""
    findings: list[str] = []
    for guid in sorted(set(GUID_RE.findall(text))):
        if guid.lower() not in ALLOWED_GUIDS:
            findings.append(f"non-placeholder GUID {guid}")
    for pattern in WEBHOOK_PATTERNS:
        if pattern.search(text):
            findings.append("webhook URL in a tracked file")
            break
    if PEM_KEY_RE.search(text):
        findings.append("private-key block in a tracked file")
    for domain in sorted(set(EMAIL_RE.findall(text))):
        if domain.lower() not in ALLOWED_EMAIL_DOMAINS:
            findings.append(f"e-mail domain not in the placeholder set: {domain}")
    if VENDOR_WORD.search(text):
        findings.append("literal vendor name in a tracked file")
    return findings


# --- The guard itself --------------------------------------------------------
def test_tracked_files_are_clean() -> None:
    files = tracked_files()
    assert files, "git ls-files returned nothing — the guard would be vacuous"
    offenders: list[str] = []
    for path in files:
        for finding in scan_text(read_text(path)):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {finding}")
    assert not offenders, "leak guard findings:\n" + "\n".join(sorted(offenders))


def test_tracked_paths_do_not_name_the_vendor() -> None:
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in tracked_files()
        if VENDOR_WORD.search(str(path.relative_to(REPO_ROOT)))
    ]
    assert not offenders, f"vendor name in tracked path: {offenders}"


# --- Positive detection: canaries built at runtime ---------------------------
def webhook_url(host: str, trigger: str = "R7x9Qm2") -> str:
    """A webhook-shaped URL, assembled so it never appears literally in a file."""
    return "https" + "://" + "tenant-abc." + host + "/triggers/" + trigger + "/HTTP"


def pem_header(kind: str = "RSA") -> str:
    return "-----" + "BEGIN " + kind + " PRIVATE KEY-----"


def foreign_address(local: str, *domain_labels: str) -> str:
    """A non-placeholder mailbox, assembled at runtime."""
    return local + "@" + ".".join(domain_labels)


@pytest.mark.parametrize(
    "host",
    [AZURE_LOGIC_HOST, POWERPLATFORM_HOST],
    ids=["logic-azure", "powerplatform"],
)
def test_guard_detects_a_webhook_url(host: str) -> None:
    findings = scan_text("post it to " + webhook_url(host) + " please")
    assert any("webhook URL" in f for f in findings), findings


def test_guard_detects_the_retired_connector_webhook_path() -> None:
    url = (
        "https" + "://" + OUTLOOK_WEBHOOK_HOST + "/webhook/"
        + "11111111" + "-2222-3333-4444-555566667777"
    )
    findings = scan_text(f"target url = {url}")
    assert any("webhook URL" in f for f in findings), findings


def test_guard_detects_a_non_placeholder_guid() -> None:
    leaked = "1a2b3c4d" + "-5e6f-7a8b-9c0d-" + "1e2f3a4b5c6d"
    findings = scan_text(f'tenant_id = "{leaked}"')
    assert any("GUID" in f for f in findings), findings


def test_guard_allows_the_documented_placeholder_guids() -> None:
    assert scan_text(f'tenant_id = "{NULL_GUID}"\nclient_id = "{ONES_GUID}"') == []


def test_guard_detects_a_private_key_block() -> None:
    body = pem_header() + "\nTUlJRVpBQ0NnRGdCQVFC\n" + "-----END RSA PRIVATE KEY-----"
    findings = scan_text(body)
    assert any("private-key" in f for f in findings), findings


def test_guard_detects_a_wrapped_pkcs8_private_key_block() -> None:
    findings = scan_text(pem_header("ENCRYPTED PKCS8") + "\nTUlJRVpBQ0Nn\n")
    assert any("private-key" in f for f in findings), findings


def test_guard_ignores_the_phrase_private_key() -> None:
    # The design and roadmap both say "private key"; only the PEM header bites.
    assert scan_text("the private key lives in the keychain, never in config") == []


@pytest.mark.parametrize(
    "address",
    [
        foreign_address("someone", "internal-corp", "example"),
        foreign_address("ops", "real-tenant", "onmicrosoft", "com"),
    ],
    ids=["bare-corp-domain", "onmicrosoft-tenant"],
)
def test_guard_detects_a_foreign_email_domain(address: str) -> None:
    findings = scan_text(f"--to {address}")
    assert any("e-mail domain" in f for f in findings), findings


def test_guard_allows_placeholder_email_domains() -> None:
    assert scan_text("--to noreply@example.com --cc ops@contoso.com") == []


def test_guard_ignores_a_versioned_tool_reference() -> None:
    """``python@3.12`` is a Homebrew formula name (tap formula, design §5), not a mailbox."""
    assert scan_text('depends_on "python@3.12"') == []


def test_guard_catches_a_mailbox_alongside_a_versioned_reference() -> None:
    """The alpha-TLD rule must not cost detection: the mailbox still bites."""
    address = foreign_address("ops", "real-tenant", "onmicrosoft", "com")
    text = 'depends_on "python@3.12"\n' + f"--to {address}"
    findings = [f for f in scan_text(text) if "e-mail" in f]
    assert findings == [
        "e-mail domain not in the placeholder set: real-tenant" + ".onmicrosoft.com"
    ], findings


def test_descriptive_host_mentions_are_not_findings() -> None:
    """The exact phrasing used in ROADMAP.md and design §5 must pass the guard."""
    descriptive = (
        "no `*." + AZURE_LOGIC_HOST + "` / `*." + POWERPLATFORM_HOST + "` webhook URLs, "
        "and no https://*." + AZURE_LOGIC_HOST + " URLs either"
    )
    assert scan_text(descriptive) == []


def test_scan_reports_every_category_at_once() -> None:
    """One text carrying four problems produces four distinct findings."""
    text = "\n".join(
        [
            'tenant_id = "' + "1a2b3c4d" + "-5e6f-7a8b-9c0d-" + "1e2f3a4b5c6d" + '"',
            webhook_url(AZURE_LOGIC_HOST),
            pem_header(),
            "--to ops@" + "real-tenant" + ".onmicrosoft.com",
        ]
    )
    findings = scan_text(text)
    kinds = {f.split()[0] for f in findings}
    assert {"non-placeholder", "webhook", "private-key", "e-mail"} == kinds, findings
