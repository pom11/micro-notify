"""Configuration loading and writing (design section 3.4).

Location: ``~/.config/mnotify/config.toml``, overridable for this v1 only by the
``MICRO_NOTIFY_CONFIG`` environment variable (path only — no secrets via env).
The file must be 0600 and must never contain a secret: credentials live in the
macOS keychain (see :mod:`micro_notify.secrets`).

The key set below is the whole cross-module contract. Later modules read these
attributes and must not need a new key; if one is missing that is a blocker on
the scaffold card, not an edit to this file.

    [mail]    tenant_id, client_id, sender, auth, default_reply_to
    [allow]   domains = [], addresses = []      (empty => refuse everything)
    [limits]  max_recipients, daily_max, max_attach_mb
    [paths]   audit, state_dir                  (defaults under ~/Library)
    [teams.targets.<name>]  kind = "channel" | "dm"

:func:`load_config` raises :class:`ConfigError` (exit 2) on anything unusable.
:func:`write_config` is the writer used by ``mnotify setup`` /
``mnotify teams targets add``; it creates parents, writes atomically and ends
with the file mode at 0600.
"""

from __future__ import annotations

import os
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import EXIT_USAGE, UsageError

CONFIG_ENV_VAR = "MICRO_NOTIFY_CONFIG"
DEFAULT_CONFIG_PATH = "~/.config/mnotify/config.toml"

AUTH_CERTIFICATE = "certificate"
AUTH_SECRET = "secret"
AUTH_MODES = (AUTH_CERTIFICATE, AUTH_SECRET)

KIND_CHANNEL = "channel"
KIND_DM = "dm"
TARGET_KINDS = (KIND_CHANNEL, KIND_DM)

# Design section 3.3 / 3.4 defaults.
DEFAULT_MAX_RECIPIENTS = 20
DEFAULT_DAILY_MAX = 200
DEFAULT_MAX_ATTACH_MB = 3

DEFAULT_AUDIT_PATH = "~/Library/Logs/mnotify/sent.jsonl"
DEFAULT_STATE_DIR = "~/Library/Application Support/mnotify"

# Config files are secrets-adjacent (tenant id, client id, mailbox). Keep the
# mode tight even when the caller does not ask for it.
CONFIG_FILE_MODE = 0o600
CONFIG_DIR_MODE = 0o700


class ConfigError(UsageError):
    """The config file is missing, unreadable, or fails validation -> exit 2."""

    exit_code = EXIT_USAGE


def config_path(env: Mapping[str, str] | None = None) -> Path:
    """Return the config file path honouring ``MICRO_NOTIFY_CONFIG``."""
    environ = os.environ if env is None else env
    override = environ.get(CONFIG_ENV_VAR)
    if override:
        return Path(override).expanduser()
    return Path(DEFAULT_CONFIG_PATH).expanduser()


@dataclass(frozen=True)
class MailConfig:
    tenant_id: str
    client_id: str
    sender: str
    auth: str = AUTH_CERTIFICATE
    default_reply_to: str = ""

    def keychain_accounts(self) -> tuple[str, ...]:
        """Keychain accounts this mail config requires (design section 3.4).

        Names only — never values.
        """
        from .secrets import ACCOUNT_CERT_PEM, ACCOUNT_CERT_THUMBPRINT, ACCOUNT_CLIENT_SECRET

        if self.auth == AUTH_CERTIFICATE:
            return (ACCOUNT_CERT_PEM, ACCOUNT_CERT_THUMBPRINT)
        return (ACCOUNT_CLIENT_SECRET,)


@dataclass(frozen=True)
class AllowConfig:
    """Empty by design: an unconfigured allowlist refuses every recipient."""

    domains: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class LimitsConfig:
    max_recipients: int = DEFAULT_MAX_RECIPIENTS
    daily_max: int = DEFAULT_DAILY_MAX
    max_attach_mb: int = DEFAULT_MAX_ATTACH_MB


@dataclass(frozen=True)
class PathsConfig:
    audit: Path = field(default_factory=lambda: Path(DEFAULT_AUDIT_PATH).expanduser())
    state_dir: Path = field(default_factory=lambda: Path(DEFAULT_STATE_DIR).expanduser())

    @property
    def counter_file(self) -> Path:
        """Daily counter location: ``[paths]state_dir/counter.json``."""
        return self.state_dir / "counter.json"


@dataclass(frozen=True)
class TeamTarget:
    name: str
    kind: str


@dataclass(frozen=True)
class Config:
    mail: MailConfig
    allow: AllowConfig
    limits: LimitsConfig
    paths: PathsConfig
    teams_targets: tuple[TeamTarget, ...] = ()
    source_path: Path | None = None

    def target(self, name: str) -> TeamTarget | None:
        for target in self.teams_targets:
            if target.name == name:
                return target
        return None

    def keychain_accounts(self) -> tuple[str, ...]:
        """Every keychain account this config expects, mail first, then teams."""
        names = list(self.mail.keychain_accounts())
        names.extend(f"teams:{target.name}" for target in self.teams_targets)
        return tuple(names)

    def as_dict(self) -> dict[str, Any]:
        """Plain-data view for ``mnotify config show``.

        There are no secret fields in the config schema (design section 3.4), so
        this is safe to print verbatim.
        """
        return {
            "mail": {
                "tenant_id": self.mail.tenant_id,
                "client_id": self.mail.client_id,
                "sender": self.mail.sender,
                "auth": self.mail.auth,
                "default_reply_to": self.mail.default_reply_to,
            },
            "allow": {
                "domains": list(self.allow.domains),
                "addresses": list(self.allow.addresses),
            },
            "limits": {
                "max_recipients": self.limits.max_recipients,
                "daily_max": self.limits.daily_max,
                "max_attach_mb": self.limits.max_attach_mb,
            },
            "paths": {
                "audit": str(self.paths.audit),
                "state_dir": str(self.paths.state_dir),
            },
            "teams": {
                "targets": {t.name: {"kind": t.kind} for t in self.teams_targets},
            },
        }


# --- Loading ---------------------------------------------------------------
def _require_str(table: Mapping[str, Any], key: str, where: str) -> str:
    if key not in table:
        raise ConfigError(f"{where}: missing required key '{key}'")
    value = table[key]
    if not isinstance(value, str):
        raise ConfigError(f"{where}: key '{key}' must be a string")
    return value


def _require_guid(value: str, label: str) -> str:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ConfigError(f"{label} is not a valid GUID: {type(exc).__name__}") from exc
    return value


def _require_int(table: Mapping[str, Any], key: str, where: str, default: int) -> int:
    if key not in table:
        return default
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: key '{key}' must be an integer")
    if value < 1:
        raise ConfigError(f"{where}: key '{key}' must be >= 1")
    return value


def _require_str_list(table: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    if key not in table:
        return ()
    value = table[key]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{where}: key '{key}' must be a list of strings")
    return tuple(item.strip() for item in value if item.strip())


def _section(data: Mapping[str, Any], name: str) -> dict[str, Any]:
    table = data.get(name, {})
    if not isinstance(table, dict):
        raise ConfigError(f"[{name}] must be a table")
    return table


def _load_mail(data: Mapping[str, Any]) -> MailConfig:
    table = _section(data, "mail")
    where = "[mail]"
    tenant_id = _require_guid(_require_str(table, "tenant_id", where), f"{where} tenant_id")
    client_id = _require_guid(_require_str(table, "client_id", where), f"{where} client_id")
    sender = _require_str(table, "sender", where).strip()
    if "@" not in sender:
        raise ConfigError(f"{where} sender must be a mailbox address")
    auth = _require_str(table, "auth", where).strip().lower()
    if auth not in AUTH_MODES:
        raise ConfigError(f"{where} auth must be one of: {', '.join(AUTH_MODES)}")
    reply_to = _require_str(table, "default_reply_to", where).strip() if "default_reply_to" in table else ""
    return MailConfig(
        tenant_id=tenant_id,
        client_id=client_id,
        sender=sender,
        auth=auth,
        default_reply_to=reply_to,
    )


def _load_allow(data: Mapping[str, Any]) -> AllowConfig:
    table = _section(data, "allow")
    where = "[allow]"
    domains = tuple(d.lower() for d in _require_str_list(table, "domains", where))
    addresses = tuple(a.lower() for a in _require_str_list(table, "addresses", where))
    for domain in domains:
        if "@" in domain or any(c.isspace() for c in domain):
            raise ConfigError(f"{where} domains must be bare domains, not addresses: {domain!r}")
    return AllowConfig(domains=domains, addresses=addresses)


def _load_limits(data: Mapping[str, Any]) -> LimitsConfig:
    table = _section(data, "limits")
    where = "[limits]"
    return LimitsConfig(
        max_recipients=_require_int(table, "max_recipients", where, DEFAULT_MAX_RECIPIENTS),
        daily_max=_require_int(table, "daily_max", where, DEFAULT_DAILY_MAX),
        max_attach_mb=_require_int(table, "max_attach_mb", where, DEFAULT_MAX_ATTACH_MB),
    )


def _load_paths(data: Mapping[str, Any]) -> PathsConfig:
    table = _section(data, "paths")
    where = "[paths]"
    audit_raw = table.get("audit", DEFAULT_AUDIT_PATH)
    state_raw = table.get("state_dir", DEFAULT_STATE_DIR)
    if not isinstance(audit_raw, str) or not isinstance(state_raw, str):
        raise ConfigError(f"{where} audit and state_dir must be strings")
    audit = Path(audit_raw).expanduser()
    state_dir = Path(state_raw).expanduser()
    if not audit.is_absolute():
        raise ConfigError(f"{where} audit must be an absolute path (after ~ expansion)")
    if not state_dir.is_absolute():
        raise ConfigError(f"{where} state_dir must be an absolute path (after ~ expansion)")
    return PathsConfig(audit=audit, state_dir=state_dir)


def _load_teams(data: Mapping[str, Any]) -> tuple[TeamTarget, ...]:
    teams = _section(data, "teams")
    targets = teams.get("targets", {})
    if not isinstance(targets, dict):
        raise ConfigError("[teams] targets must be a table")
    loaded: list[TeamTarget] = []
    for name, table in targets.items():
        if not isinstance(table, dict):
            raise ConfigError(f"[teams.targets.{name}] must be a table")
        kind = _require_str(table, "kind", f"[teams.targets.{name}]").strip().lower()
        if kind not in TARGET_KINDS:
            raise ConfigError(
                f"[teams.targets.{name}] kind must be one of: {', '.join(TARGET_KINDS)}"
            )
        loaded.append(TeamTarget(name=name, kind=kind))
    return tuple(sorted(loaded, key=lambda t: t.name))


def parse_config(data: Mapping[str, Any], source_path: Path | None = None) -> Config:
    """Validate a decoded TOML mapping into a :class:`Config`.

    Raises :class:`ConfigError` (exit 2) on any structural or value problem.
    """
    if not isinstance(data, Mapping):
        raise ConfigError("config root must be a TOML table")
    return Config(
        mail=_load_mail(data),
        allow=_load_allow(data),
        limits=_load_limits(data),
        paths=_load_paths(data),
        teams_targets=_load_teams(data),
        source_path=source_path,
    )


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load and validate the config file.

    Precedence: explicit ``path`` argument > ``MICRO_NOTIFY_CONFIG`` >
    ``~/.config/mnotify/config.toml``. Missing file, TOML syntax error and
    validation failure all raise :class:`ConfigError` (exit 2).
    """
    resolved = Path(path).expanduser() if path is not None else config_path()
    try:
        raw = resolved.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigError(
            f"config file not found: {resolved} (run `mnotify setup`, or set "
            f"{CONFIG_ENV_VAR})"
        ) from exc
    except OSError as exc:
        raise ConfigError(f"config file unreadable: {resolved} ({type(exc).__name__})") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"config file is not valid TOML: {resolved}") from exc
    return parse_config(data, source_path=resolved)


# --- Writing ---------------------------------------------------------------
def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_toml(config: Config) -> str:
    """Render a :class:`Config` as TOML text in a stable key order.

    Only non-secret keys are part of the schema, so nothing here can emit a
    credential (design section 3.4).
    """
    lines: list[str] = [
        "# micro-notify configuration (design section 3.4). No secrets here.",
        "",
        "[mail]",
        f"tenant_id = {_quote(config.mail.tenant_id)}",
        f"client_id = {_quote(config.mail.client_id)}",
        f"sender = {_quote(config.mail.sender)}",
        f"auth = {_quote(config.mail.auth)}",
        f"default_reply_to = {_quote(config.mail.default_reply_to)}",
        "",
        "[allow]",
        "domains = [" + ", ".join(_quote(d) for d in config.allow.domains) + "]",
        "addresses = [" + ", ".join(_quote(a) for a in config.allow.addresses) + "]",
        "",
        "[limits]",
        f"max_recipients = {config.limits.max_recipients}",
        f"daily_max = {config.limits.daily_max}",
        f"max_attach_mb = {config.limits.max_attach_mb}",
        "",
        "[paths]",
        f"audit = {_quote(str(config.paths.audit))}",
        f"state_dir = {_quote(str(config.paths.state_dir))}",
    ]
    for target in config.teams_targets:
        lines += ["", f"[teams.targets.{target.name}]", f"kind = {_quote(target.kind)}"]
    return "\n".join(lines) + "\n"


def write_config(config: Config, path: str | os.PathLike[str] | None = None) -> Path:
    """Write ``config`` atomically with mode 0600 (design section 3.4).

    Used by ``mnotify setup`` and ``mnotify teams targets add|remove`` (P5, P4)
    so neither has to hand-roll file handling.
    """
    resolved = Path(path).expanduser() if path is not None else config_path()
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=CONFIG_DIR_MODE)
    text = render_toml(config)
    tmp = resolved.with_name(resolved.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, CONFIG_FILE_MODE)
        os.replace(tmp, resolved)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise ConfigError(f"could not write config file: {resolved}") from exc
    os.chmod(resolved, CONFIG_FILE_MODE)
    return resolved


# --- Team-target mutation helpers (used by P4 `teams targets ...`) ---------
def with_team_target(config: Config, name: str, kind: str) -> Config:
    """Return a copy of ``config`` with target ``name`` set to ``kind``."""
    if kind not in TARGET_KINDS:
        raise ConfigError(f"team target kind must be one of: {', '.join(TARGET_KINDS)}")
    targets = [t for t in config.teams_targets if t.name != name]
    targets.append(TeamTarget(name=name, kind=kind))
    return _replace_targets(config, sorted(targets, key=lambda t: t.name))


def without_team_target(config: Config, name: str) -> Config:
    """Return a copy of ``config`` with target ``name`` dropped."""
    return _replace_targets(config, [t for t in config.teams_targets if t.name != name])


def _replace_targets(config: Config, targets: list[TeamTarget]) -> Config:
    return Config(
        mail=config.mail,
        allow=config.allow,
        limits=config.limits,
        paths=config.paths,
        teams_targets=tuple(targets),
        source_path=config.source_path,
    )


__all__ = [
    "AUTH_CERTIFICATE",
    "AUTH_MODES",
    "AUTH_SECRET",
    "CONFIG_DIR_MODE",
    "CONFIG_ENV_VAR",
    "CONFIG_FILE_MODE",
    "DEFAULT_AUDIT_PATH",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_DAILY_MAX",
    "DEFAULT_MAX_ATTACH_MB",
    "DEFAULT_MAX_RECIPIENTS",
    "DEFAULT_STATE_DIR",
    "KIND_CHANNEL",
    "KIND_DM",
    "TARGET_KINDS",
    "AllowConfig",
    "Config",
    "ConfigError",
    "LimitsConfig",
    "MailConfig",
    "PathsConfig",
    "TeamTarget",
    "config_path",
    "load_config",
    "parse_config",
    "render_toml",
    "with_team_target",
    "without_team_target",
    "write_config",
]
