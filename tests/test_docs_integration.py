"""Anti-drift pins for docs/SERVICE-INTEGRATION.md (card t_32e224f7).

The integration document is the authority gateclerk's production plan cites.
These tests keep the two parts that would silently rot executable:

* every ``bash``/``sh`` example must parse with :mod:`shlex`, and it must not
  reference a secret through the environment (path variables are allowed);
* every exit code the document cites must be one of the public codes.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from micro_notify import (
    EXIT_AUTH,
    EXIT_DAILY_CAP,
    EXIT_GUARD,
    EXIT_OK,
    EXIT_REMOTE,
    EXIT_USAGE,
)

DOC = Path(__file__).resolve().parents[1] / "docs" / "SERVICE-INTEGRATION.md"

# 130 is the shell convention for Ctrl-C (cli.py); it is not one of the
# design-section-4 constants but it is part of the process contract.
PUBLIC_EXIT_CODES = {
    EXIT_OK,
    EXIT_USAGE,
    EXIT_GUARD,
    EXIT_AUTH,
    EXIT_REMOTE,
    EXIT_DAILY_CAP,
    130,
}

# The Linux lanes make these environment variables paths, never values.
PATH_ONLY_ENV = {
    "MICRO_NOTIFY_CONFIG",
    "MICRO_NOTIFY_SECRETS",
    "MICRO_NOTIFY_SECRETS_DIR",
}

SECRET_NAME = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|WEBHOOK|CERT|KEY)",
    re.IGNORECASE,
)
ENV_REF = re.compile(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)(?:\})?")
FENCE = re.compile(
    r"^```(?P<lang>[A-Za-z0-9_-]+)\s*\n(?P<body>.*?)^```\s*$",
    re.MULTILINE | re.DOTALL,
)
EXIT_PROSE = re.compile(
    r"\bexit(?:s|ed)?\s+(?:with\s+)?(?:code\s+)?\*{0,2}(\d+)\b",
    re.IGNORECASE,
)
EXIT_TABLE_ROW = re.compile(r"^\|\s*`?(\d+)`?\s*\|", re.MULTILINE)


def _shell_blocks(text: str) -> list[str]:
    return [
        match.group("body")
        for match in FENCE.finditer(text)
        if match.group("lang").lower() in {"bash", "sh"}
    ]


def _shell_tokens(block: str) -> list[str]:
    """Tokenise a shell block line by line, joining backslash continuations."""
    block = re.sub(r"\\\n", " ", block)
    tokens: list[str] = []
    for line in block.splitlines():
        try:
            tokens.extend(shlex.split(line, comments=True, posix=True))
        except ValueError as exc:  # unbalanced quote in the document
            pytest.fail(f"shell example does not parse with shlex: {exc}")
    return tokens


def _secret_env_refs(tokens: list[str]) -> list[str]:
    bad: list[str] = []
    for token in tokens:
        for name in ENV_REF.findall(token):
            if name in PATH_ONLY_ENV:
                continue
            if SECRET_NAME.search(name):
                bad.append(f"${name}")
    return bad


def test_document_exists_and_keeps_its_binding_sections() -> None:
    text = DOC.read_text(encoding="utf-8")
    for heading in (
        "## 1. The interface: exec, exit code, JSON",
        "## 2. Commands and flags",
        "## 3. Exit codes and retry policy",
        "## 4. Worked example",
        "## 5. Container pattern",
        "## 6. Concurrency and shared state",
        "## 7. Secrets and configuration on Linux",
        "## 8. Audit",
        "## 9. Linux prerequisites",
        "## 10. Questions for ecofire-pontaje-orch",
    ):
        assert heading in text, f"missing binding section: {heading}"


def test_shell_examples_never_carry_a_secret_value_through_the_environment() -> None:
    text = DOC.read_text(encoding="utf-8")
    blocks = _shell_blocks(text)
    assert blocks, "the document no longer has a bash/sh example to pin"

    offenders: list[str] = []
    for block in blocks:
        offenders.extend(_secret_env_refs(_shell_tokens(block)))
    assert not offenders, (
        "shell example references a secret through the environment; pass a "
        f"path variable instead: {', '.join(sorted(set(offenders)))}"
    )


def test_secret_env_detector_flags_a_fabricated_canary() -> None:
    """The check above must not be vacuous: a secret env name is rejected."""
    canary = ["mnotify", "mail", "send", "--body", "$MICRO_NOTIFY_WEBHOOK_URL"]

    assert _secret_env_refs(canary) == ["$MICRO_NOTIFY_WEBHOOK_URL"]


def _cited_exit_codes(text: str) -> set[int]:
    codes = {int(match) for match in EXIT_PROSE.findall(text)}

    # The policy table is the authoritative list; read its first column too.
    section = re.search(
        r"^## 3\. Exit codes and retry policy\s*$(.*?)(?=^## )",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert section is not None, "the exit-code policy section disappeared"
    codes.update(int(match) for match in EXIT_TABLE_ROW.findall(section.group(1)))
    return codes


def test_every_cited_exit_code_is_public() -> None:
    text = DOC.read_text(encoding="utf-8")
    cited = _cited_exit_codes(text)

    assert cited, "the document no longer cites any exit code"
    assert cited <= PUBLIC_EXIT_CODES, (
        "the document cites an exit code that is not part of the public "
        f"contract: {sorted(cited - PUBLIC_EXIT_CODES)}"
    )


def test_the_retry_table_covers_every_public_exit_code() -> None:
    text = DOC.read_text(encoding="utf-8")

    assert PUBLIC_EXIT_CODES <= _cited_exit_codes(text)
