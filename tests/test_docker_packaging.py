"""Static guard for the Alpine Docker packaging (card t_e180aec2) and for the
container-proof CI job that finally builds and runs it (card MN-P01).

The Docker build itself is proven by `.github/workflows/container-proof.yml` on
`ubuntu-latest` — never here, where there is no daemon. This module pins the parts
that must never drift silently: a pinned base, a numeric non-root user, a venv
install, no secret/config COPY, the exec-form entrypoint, the shipped example config
loading through the real product loader, and the shape of that workflow — its
triggers, its permissions, its mount list, the exit codes it asserts, and the leak
guard's own patterns applied to the yaml and the CI fixtures it fabricates.
"""

from __future__ import annotations

import py_compile
import shutil
from pathlib import Path

from micro_notify.config import (
    CONFIG_ENV_VAR,
    MAIL_MODE_APP,
    load_config,
)

import test_leak_guard

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = REPO_ROOT / "packaging" / "docker"
DOCKERFILE = DOCKER_DIR / "Dockerfile"
DOCKERIGNORE = DOCKER_DIR / "Dockerfile.dockerignore"
EXAMPLE_CONFIG = DOCKER_DIR / "config.example.toml"
README = DOCKER_DIR / "README.md"
CI_DIR = DOCKER_DIR / "ci"
CI_CONFIG = CI_DIR / "config.toml"
CI_MESSAGE = CI_DIR / "message.md"
CI_STUB = CI_DIR / "stub_webhook.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "container-proof.yml"


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


# --- The container-proof CI job (card MN-P01) --------------------------------
# Static only, on purpose: the offline suite has no daemon and no network, so what
# it can pin is the *shape* of the job that runs the real build. A workflow that
# silently stopped asserting an exit code, or started mounting the private key,
# would keep passing on the runner and quietly stop proving anything.

def workflow_text() -> str:
    assert WORKFLOW.is_file(), f"{WORKFLOW} must exist — the image is only ever built there"
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_triggers_on_pull_request_with_read_only_permissions() -> None:
    lines = [line.strip() for line in workflow_text().splitlines()]
    assert "on:" in lines
    # `pull_request` (not just workflow_dispatch): the proof must run unattended.
    assert "pull_request:" in lines
    assert "workflow_dispatch:" in lines
    assert "permissions:" in lines
    assert "contents: read" in lines
    assert "runs-on: ubuntu-latest" in lines


def test_workflow_builds_the_pinned_dockerfile_and_checks_exit_codes() -> None:
    text = workflow_text()
    assert "docker build -f packaging/docker/Dockerfile" in text
    assert "mnotify:ci" in text
    # The whole point of the job: three specific exit codes, asserted not observed.
    assert text.count("-eq 4") == 2, "both permission-contract cases must assert exit 4"
    assert "-eq 0" in text, "the send case must assert exit 0"
    assert "$GITHUB_STEP_SUMMARY" in text, "the python/pip versions must be recorded"


def test_workflow_runs_as_the_documented_uid_with_read_only_mounts() -> None:
    text = workflow_text()
    assert "--user 10001:10001" in text
    assert ":/data/config.toml:ro" in text
    assert ":/run/secrets/mnotify:ro" in text
    assert ":/ci/stub-cert.pem:ro" in text
    # The container reaches the stub on the runner's loopback and trusts exactly
    # the one certificate the job generated.
    assert "--network=host" in text
    assert "SSL_CERT_FILE=/ci/stub-cert.pem" in text
    # The certificate must be readable by uid 10001 (it is public); at umask 077
    # openssl writes it 0600 and the container cannot open it.
    assert 'chmod 0444 "$CERT"' in text
    assert 'chmod 0600 "$KEY"' in text


def test_workflow_never_mounts_the_private_key() -> None:
    """Only the certificate crosses into the container; the key stays on the runner."""
    mount_lines = [
        line.strip()
        for line in workflow_text().splitlines()
        if line.strip().startswith("-v ") or line.strip().startswith("-v\"")
    ]
    assert mount_lines, "expected explicit bind mounts"
    for line in mount_lines:
        assert "key" not in line.lower(), f"a private key must never be mounted: {line}"
        assert ".pem" not in line or "stub-cert.pem" in line, line
    assert "verify=False" not in workflow_text()
    assert "SSL_CERT_FILE" in workflow_text()


def test_workflow_carries_no_context_expressions() -> None:
    """`${{ runner.temp }}` in a job-level `env:` made GitHub refuse the whole file.

    Pinned because nothing local catches it: pyyaml and ruamel both parse the file
    happily, and the failed run has no job, no log and the file path as its name —
    the only message is an "Invalid workflow file … Unrecognized named-value:
    'runner'" annotation. The `runner` context is not available in a job-level
    `env:` block, so the job derives its temp paths from `$RUNNER_TEMP` per step.
    """
    assert "${{" not in workflow_text()


def test_ci_config_loads_through_the_product_loader(tmp_path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    shutil.copyfile(CI_CONFIG, target)
    monkeypatch.setenv(CONFIG_ENV_VAR, str(target))

    config = load_config()

    assert config.mail.mode == MAIL_MODE_APP
    assert config.mail.sender == "noreply@example.com"
    target_names = [t.name for t in config.teams_targets]
    assert target_names == ["alerts"], target_names
    alerts = config.target("alerts")
    assert alerts is not None and alerts.kind == "channel"


def test_ci_config_keeps_runtime_paths_under_data(tmp_path, monkeypatch) -> None:
    target = tmp_path / "config.toml"
    shutil.copyfile(CI_CONFIG, target)
    monkeypatch.setenv(CONFIG_ENV_VAR, str(target))

    config = load_config()

    assert str(config.paths.audit).startswith("/data/")
    assert str(config.paths.state_dir).startswith("/data/")


def test_ci_stub_compiles_and_serves_one_post_over_tls() -> None:
    py_compile.compile(str(CI_STUB), doraise=True)
    text = CI_STUB.read_text(encoding="utf-8")
    assert "def do_POST" in text
    # TLS, not plain HTTP: the product posts to an https:// webhook URL.
    assert "ssl.SSLContext" in text
    assert "PROTOCOL_TLS_SERVER" in text
    assert "202" in text
    assert "http://" not in text, "the stub must not offer a plain-HTTP path"


def test_ci_message_fixture_carries_the_proved_text() -> None:
    assert "Container proof alert" in CI_MESSAGE.read_text(encoding="utf-8")


def test_leak_guard_patterns_pass_over_the_workflow_and_ci_fixtures() -> None:
    """The guard's own patterns, applied to the files that fabricate credentials."""
    for path in (WORKFLOW, CI_CONFIG, CI_MESSAGE, CI_STUB):
        findings = test_leak_guard.scan_text(test_leak_guard.read_text(path))
        assert not findings, f"{path.relative_to(REPO_ROOT)}: {findings}"


def test_readme_records_the_build_that_actually_ran() -> None:
    text = README.read_text(encoding="utf-8")
    # The sentence that made this card exist must be gone, not merely softened.
    assert "no build was run here" not in text
    assert "no reachable Docker daemon" not in text
    # ...and what replaced it must say what the job proves, in exit codes.
    assert "## Container proof" in text
    assert "container-proof.yml" in text
    assert "ubuntu-latest" in text
    assert "SSL_CERT_FILE" in text
    assert "exit 4" in text
    assert "exits **0**" in text
    assert "id -u" in text
