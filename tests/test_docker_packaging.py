"""Static guard for the Alpine Docker packaging (card t_e180aec2).

The Docker build itself is proven by the S3 smoke on a host with a daemon; this
module pins the parts that must never drift silently: a pinned base, a numeric
non-root user, a venv install, no secret/config COPY, the exec-form entrypoint,
and the shipped example config loading through the real product loader.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from micro_notify.config import (
    CONFIG_ENV_VAR,
    MAIL_MODE_APP,
    load_config,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = REPO_ROOT / "packaging" / "docker"
DOCKERFILE = DOCKER_DIR / "Dockerfile"
DOCKERIGNORE = DOCKER_DIR / "Dockerfile.dockerignore"
EXAMPLE_CONFIG = DOCKER_DIR / "config.example.toml"
README = DOCKER_DIR / "README.md"


def dockerfile_lines() -> list[str]:
    return [line.strip() for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()]


def active_instructions() -> list[str]:
    """Non-comment, non-blank Dockerfile lines (comments may name the fallback)."""
    return [line for line in dockerfile_lines() if line and not line.startswith("#")]


def active_text() -> str:
    return "\n".join(active_instructions())


def test_base_image_is_pinned_alpine() -> None:
    from_lines = [line for line in active_instructions() if line.upper().startswith("FROM ")]
    assert from_lines == ["FROM alpine:3.20"]


def test_python_and_pip_come_from_apk_without_a_toolchain() -> None:
    text = active_text()
    assert "apk add --no-cache python3 py3-pip" in text
    # Single-stage path: musllinux wheels mean no compiler in the shipped image.
    for compiler in ("rust", "cargo", "gcc", "musl-dev"):
        assert compiler not in text, f"{compiler} must stay out of the final image"


def test_project_is_installed_into_the_venv() -> None:
    text = active_text()
    assert "venv --without-pip --system-site-packages /opt/mnotify-venv" in text
    assert "/opt/mnotify-venv/bin/python -m pip install --no-cache-dir ." in text
    assert "ln -s /opt/mnotify-venv/bin/mnotify /usr/local/bin/mnotify" in text


def test_no_secrets_or_operator_config_are_copied_in() -> None:
    copy_lines = [
        line for line in active_instructions() if line.upper().startswith(("COPY ", "ADD "))
    ]
    assert copy_lines, "expected the source tree to be copied in for the install"
    allowed_sources = {"pyproject.toml", "README.md", "src"}
    for line in copy_lines:
        tokens = line.split()
        sources = tokens[1:-1]
        assert sources, f"COPY/ADD without a source: {line}"
        assert set(sources) <= allowed_sources, f"unexpected COPY/ADD source: {line}"
        lowered = line.lower()
        assert "secret" not in lowered
        assert "config" not in lowered
    assert not any(line.upper().startswith("ADD ") for line in active_instructions())


def test_runs_as_a_numeric_unprivileged_user() -> None:
    text = active_text()
    assert "USER 10001:10001" in text
    assert "addgroup -g 10001 mnotify" in text
    assert "adduser -D -H -u 10001 -G mnotify -s /sbin/nologin" in text
    assert "chown 10001:10001 /data" in text
    assert "HOME=/data" in text
    assert "USER root" not in text
    assert "USER 0" not in text


def test_entrypoint_is_the_console_script_with_help_default() -> None:
    text = active_text()
    assert 'ENTRYPOINT ["mnotify"]' in text
    assert 'CMD ["--help"]' in text


def test_runtime_contract_uses_mounted_config_and_file_secrets() -> None:
    text = active_text()
    assert "MICRO_NOTIFY_CONFIG=/data/config.toml" in text
    assert "MICRO_NOTIFY_SECRETS=file" in text
    assert "MICRO_NOTIFY_SECRETS_DIR=/run/secrets/mnotify" in text


def test_dockerignore_keeps_only_install_inputs_in_context() -> None:
    lines = [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert lines[0] == "*"
    for keep in ("!pyproject.toml", "!README.md", "!src", "!src/**"):
        assert keep in lines
    assert not any("secret" in line.lower() for line in lines)
    assert not any("config" in line.lower() for line in lines)


def test_example_config_loads_through_the_product_loader(tmp_path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    shutil.copyfile(EXAMPLE_CONFIG, target)
    monkeypatch.setenv(CONFIG_ENV_VAR, str(target))

    config = load_config()

    assert config.mail.mode == MAIL_MODE_APP
    assert config.mail.sender == "noreply@example.com"
    assert config.teams_targets == ()
    assert config.source_path == target


def test_example_config_keeps_runtime_paths_under_data(tmp_path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    shutil.copyfile(EXAMPLE_CONFIG, target)
    monkeypatch.setenv(CONFIG_ENV_VAR, str(target))

    config = load_config()

    assert config.paths.audit.is_absolute()
    assert config.paths.state_dir.is_absolute()
    assert str(config.paths.audit).startswith("/data/")
    assert str(config.paths.state_dir).startswith("/data/")


def test_readme_documents_build_run_and_permission_smoke() -> None:
    text = README.read_text(encoding="utf-8")
    assert "docker build -f packaging/docker/Dockerfile -t mnotify:local ." in text
    assert "packaging/docker/config.example.toml:/data/config.toml:ro" in text
    assert "secrets:/run/secrets/mnotify:ro" in text
    assert "mnotify:local doctor" in text
    assert "chmod 0666" in text
    assert "chmod 0444" in text
    assert "MICRO_NOTIFY_SECRETS=file" in text
    assert "MICRO_NOTIFY_SECRETS_DIR=/run/secrets/mnotify" in text
