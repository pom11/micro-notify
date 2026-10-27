"""``mnotify config show`` — print the effective config with secrets masked.

Design section 4: "config show — secrets masked (presence only)".

The config schema (design §3.4) contains no secret values at all, so masking has
two jobs here and both are enforced in this module rather than trusted to the
caller:

1. keychain-backed credentials are reported by **account name + presence**, never
   by value;
2. a value canary assertion: any string that looks like a credential or a webhook
   URL is replaced by ``"<set>"`` before anything is printed, so a future config
   key cannot accidentally leak.

Attributes:

    args.show_secrets   never exists in v1 (no such flag on purpose)
    args.json           bool

Implemented by the scaffold; build step 5 may reuse :func:`presence_report`
for ``doctor`` rather than re-deriving it.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

from .. import EXIT_OK
from .. import secrets
from ..config import config_path, load_config
from . import print_json

NAME = "config"
MASK = "<set>"
# Anything that must never be printed verbatim, even if it ends up in config.
_SECRETISH_KEYS = frozenset(
    {"secret", "client_secret", "token", "password", "webhook", "webhook_url", "url", "key", "pem"}
)
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def add_parser(subparsers: "argparse._SubParsersAction") -> None:
    config = subparsers.add_parser(
        NAME,
        help="show the effective configuration (secrets masked)",
        description=(
            "Print the effective configuration. Credential values are never "
            "printed; keychain items are shown as account names with presence."
        ),
    )
    config_sub = config.add_subparsers(dest="config_command", metavar="<action>")
    show = config_sub.add_parser("show", help="print the config with secrets masked")
    show.add_argument("--json", action="store_true", help="machine-readable output on stdout")


def mask_value(key: str, value: Any) -> Any:
    """Replace anything credential-shaped with the presence marker."""
    if isinstance(value, str):
        if _SECRETISH_KEYS.intersection(key.lower().split("_")) or _URL_RE.match(value):
            return MASK
        return value
    if isinstance(value, dict):
        return {k: mask_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_value(key, item) for item in value]
    return value


def presence_report(accounts: tuple[str, ...]) -> list[dict[str, Any]]:
    """Keychain accounts this config needs, each with presence only."""
    return [
        {"account": account, "service": secrets.SERVICE, "present": secrets.has(account)}
        for account in accounts
    ]


def _print_human(config, presence: list[dict[str, Any]]) -> None:
    shown = mask_value("", config.as_dict())
    print(f"config file: {config.source_path or config_path()}")
    for section in ("mail", "allow", "limits", "paths", "teams"):
        table = shown.get(section, {})
        if section == "teams":
            targets = table.get("targets", {})
            print("teams targets: " + (", ".join(f"{n} ({t['kind']})" for n, t in targets.items()) or "none"))
            continue
        print(f"{section}: " + ", ".join(f"{k}={v}" for k, v in table.items()))
    print("keychain:")
    for item in presence:
        print(f"  {item['account']}: {'present' if item['present'] else 'MISSING'}")


def run(args: argparse.Namespace) -> int:
    if getattr(args, "config_command", None) != "show":
        print("mnotify: `config show` is the only config action in v1", file=sys.stderr)
        return 2
    config = load_config()
    presence = presence_report(config.keychain_accounts())
    if getattr(args, "json", False):
        print_json(
            {
                "ok": True,
                "outcome": "ok",
                "configPath": str(config.source_path or config_path()),
                "config": mask_value("", config.as_dict()),
                "keychain": presence,
            }
        )
        return EXIT_OK
    _print_human(config, presence)
    return EXIT_OK
