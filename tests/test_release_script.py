"""Release script + tap formula template (design section 5): render, never publish.

``scripts/release.py`` is the only publishing-adjacent tool in the repo and it is
deliberately a *printer*: it hashes the release tarball, renders the formula into
a local tap checkout, and prints the ``git tag`` / ``gh release create`` / tap
commit commands for the operator to run. These tests drive it as a real
subprocess against a throwaway git repo, a fake dist dir in ``tmp_path`` and a
fake tap directory, then assert what it wrote, what it printed, and — just as
importantly — what it refused to do.

Two tests run a real Ruby parser (``ruby -c``) over the rendered formula: the
syntax proof design section 5 asks for. They skip (never silently pass) if no
Ruby interpreter exists on the host, so the proof is never faked.

No test reaches the network, the real tap, or the real keychain. Publishing is
proven against *behaviour*, not source text: the fake repo has no remote at all
(so a ``git push`` would fail loudly), a PATH shim records any ``gh`` or
``security`` invocation, and the assertions check those logs stayed empty.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_SCRIPT = REPO_ROOT / "scripts" / "release.py"
FORMULA_TEMPLATE = REPO_ROOT / "packaging" / "Formula" / "micro-notify.rb.tmpl"

RELEASE_VERSION = "0.1.0"
TARBALL_NAME = f"micro_notify-{RELEASE_VERSION}.tar.gz"
FORMULA_URL = (
    "https://github.com/pom11/micro-notify/releases/download/"
    f"v{RELEASE_VERSION}/{TARBALL_NAME}"
)


# --- Runner / fixture helpers ----------------------------------------------
def run_release(
    *args: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the release script the way the orchestrator would."""
    return subprocess.run(
        [sys.executable, str(RELEASE_SCRIPT), *args],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def git(repo: Path, *args: str) -> str:
    """Run git in ``repo`` with a throwaway identity (never the operator's)."""
    result = subprocess.run(
        ["git", "-c", "user.name=release-test", "-c", "user.email=release@example.com", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def make_fake_repo(tmp_path: Path, version: str = RELEASE_VERSION) -> Path:
    """A committed, clean git repo shaped like the project (pyproject + src + template).

    Deliberately has **no remote**: if the script ever ran ``git push``, git would
    fail instead of silently publishing, and the test's exit-code assertion
    catches it.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        'name = "micro-notify"\n'
        f'version = "{version}"\n'
        'requires-python = ">=3.12"\n'
        "\n[project.scripts]\n"
        'micro-notify = "micro_notify.cli:main"\n'
        'mnotify = "micro_notify.cli:main"\n',
        encoding="utf-8",
    )
    pkg = repo / "src" / "micro_notify"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (repo / "packaging" / "Formula").mkdir(parents=True)
    shutil.copy(FORMULA_TEMPLATE, repo / "packaging" / "Formula" / "micro-notify.rb.tmpl")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "scaffold")
    return repo


def make_fake_dist(
    dist: Path,
    tarball_name: str = TARBALL_NAME,
    payload: bytes = b"[project]\n",
    root_dir: str = f"micro_notify-{RELEASE_VERSION}",
) -> Path:
    """A real (tiny) tarball standing in for the release asset.

    Sits outside the fake repo on purpose: an untracked ``dist/`` inside the repo
    would itself be the dirty tree the script is meant to refuse.
    """
    dist.mkdir(parents=True, exist_ok=True)
    tarball = dist / tarball_name
    with tarfile.open(tarball, "w:gz") as tar:
        info = tarfile.TarInfo(f"{root_dir}/pyproject.toml")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return tarball


def make_fake_tap(tmp_path: Path) -> Path:
    tap = tmp_path / "homebrew-micro-notify"
    (tap / "Formula").mkdir(parents=True)
    return tap


def make_shim_dir(tmp_path: Path, log: Path, *names: str) -> Path:
    """PATH prefix dir with logging stand-ins for the publishing binaries.

    Each shim records its argv and fails, so a script that actually tried to
    publish would surface as a log entry plus a non-zero plan.
    """
    shim = tmp_path / "shim-bin"
    shim.mkdir(exist_ok=True)
    for name in names:
        script = shim / name
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name} $*" >> "{log}"\n'
            "exit 99\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
    return shim


def shim_env(tmp_path: Path, log: Path, *names: str) -> dict[str, str]:
    shim = make_shim_dir(tmp_path, log, *names)
    env = dict(os.environ)
    env["PATH"] = f"{shim}{os.pathsep}{env.get('PATH', '')}"
    # No credentials in the environment at all: the script must not need any.
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        env.pop(key, None)
    return env


def happy_render(tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Render with a pre-built fake asset; returns (result, repo, tap)."""
    repo = make_fake_repo(tmp_path)
    tarball = make_fake_dist(tmp_path / "dist")
    tap = make_fake_tap(tmp_path)
    result = run_release(
        RELEASE_VERSION,
        "--repo-dir", str(repo),
        "--asset", str(tarball),
        "--tap-dir", str(tap),
        *extra,
    )
    return result, repo, tap


def formula_text(tap: Path) -> str:
    path = tap / "Formula" / "micro-notify.rb"
    assert path.exists(), f"release script did not write {path}"
    return path.read_text(encoding="utf-8")


# --- The render ------------------------------------------------------------
def test_render_writes_formula_with_release_url_and_tarball_sha256(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path)
    tarball = make_fake_dist(tmp_path / "dist", payload=b"the exact bytes the operator uploads\n")
    tap = make_fake_tap(tmp_path)
    expected_sha = hashlib.sha256(tarball.read_bytes()).hexdigest()

    result = run_release(
        RELEASE_VERSION, "--repo-dir", str(repo), "--asset", str(tarball), "--tap-dir", str(tap)
    )

    assert result.returncode == 0, result.stderr
    formula = formula_text(tap)
    # The url must name the asset whose bytes were hashed and the sha256 must be
    # the hash of those bytes, so `brew install` cannot fetch something the
    # digest does not describe.
    assert f'url "{FORMULA_URL}"' in formula, formula
    assert f'sha256 "{expected_sha}"' in formula, formula
    assert "{{" not in formula and "}}" not in formula, "unsubstituted placeholder in formula"


def test_rendered_formula_provides_both_console_scripts(tmp_path: Path) -> None:
    result, _repo, tap = happy_render(tmp_path)

    assert result.returncode == 0, result.stderr
    formula = formula_text(tap)
    # The formula installs the project from the tarball (whose [project.scripts]
    # own both console scripts) and its `test do` runs each name through the
    # linked bin, so a build that links only one of them fails `brew test`.
    assert re.search(r"pip_install_and_link\s+buildpath", formula), formula
    for script in ("micro-notify", "mnotify"):
        assert re.search(rf"\{{bin\}}/{re.escape(script)}\b", formula), (
            f"{script} is not exercised from bin in the formula's test block: {formula}"
        )


def test_formula_declares_python_and_pinned_dependency_closure(tmp_path: Path) -> None:
    result, _repo, tap = happy_render(tmp_path)

    assert result.returncode == 0, result.stderr
    formula = formula_text(tap)
    assert 'depends_on "python@3.12"' in formula, formula
    # Homebrew's pip runs with --no-deps, so every transitive distribution has
    # to be a sha256-pinned resource block or the build resolves a version off
    # the network that nobody chose.
    pinned = {
        name
        for name, _url, _sha in re.findall(
            r'resource "([^"]+)" do\n\s*url "([^"]+)"\n\s*sha256 "([0-9a-f]{64})"', formula
        )
    }
    for required in (
        "msal", "httpx", "httpcore", "h11", "anyio", "certifi", "idna",
        "requests", "urllib3", "charset-normalizer", "PyJWT", "cryptography",
        "cffi", "pycparser", "typing-extensions",
    ):
        assert required in pinned, f"{required} not pinned: {sorted(pinned)}"


def test_pinned_resource_filenames_match_their_distribution_names() -> None:
    """Catches a copy-paste that pairs one package's name with another's url."""
    template = FORMULA_TEMPLATE.read_text(encoding="utf-8")
    blocks = re.findall(
        r'resource "([^"]+)" do\n\s*url "https://files\.pythonhosted\.org/[^"]+/([^"]+\.tar\.gz)"\n'
        r'\s*sha256 "([0-9a-f]{64})"',
        template,
    )
    assert len(blocks) >= 15, f"expected the full closure pinned, got {len(blocks)}"
    for name, filename, digest in blocks:
        normalised = re.sub(r"[-_.]+", "_", name).lower()
        assert filename.lower().startswith(f"{normalised}-"), f"{name} pinned to {filename}"
        assert len(digest) == 64, name


# --- The printed publish plan ---------------------------------------------
def test_prints_publish_commands_without_running_them(tmp_path: Path) -> None:
    log = tmp_path / "publish.log"
    repo = make_fake_repo(tmp_path)
    tarball = make_fake_dist(tmp_path / "dist")
    tap = make_fake_tap(tmp_path)

    result = run_release(
        RELEASE_VERSION,
        "--repo-dir", str(repo),
        "--asset", str(tarball),
        "--tap-dir", str(tap),
        env=shim_env(tmp_path, log, "gh", "security"),
    )

    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert f"git tag -a v{RELEASE_VERSION}" in out, out
    assert "git push origin" in out, out
    assert f"gh release create v{RELEASE_VERSION} {tmp_path / 'dist' / TARBALL_NAME}" in out, out
    assert str(tap / "Formula" / "micro-notify.rb") in out, out
    # Behaviour, not prose: gh and security(1) were never invoked, and no tag
    # was created in the repo (the repo has no remote, so a push could not have
    # succeeded unnoticed either).
    assert not log.exists(), f"script invoked a publishing binary: {log.read_text()}"
    assert git(repo, "tag", "--list") == "", "script created the tag itself"


def test_dry_run_without_tap_dir_writes_no_formula(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path)
    tarball = make_fake_dist(tmp_path / "dist")
    tap = make_fake_tap(tmp_path)

    result = run_release(RELEASE_VERSION, "--repo-dir", str(repo), "--asset", str(tarball))

    assert result.returncode == 0, result.stderr
    assert not (tap / "Formula" / "micro-notify.rb").exists(), "dry run wrote the formula"
    assert "dry run" in result.stdout.lower(), result.stdout
    # A dry run still shows the real numbers, or the operator validates nothing.
    assert f"sha256   {hashlib.sha256(tarball.read_bytes()).hexdigest()}" in result.stdout, result.stdout


def test_builds_the_tarball_from_head_when_no_asset_is_given(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path)
    tap = make_fake_tap(tmp_path)
    dist = tmp_path / "built"

    result = run_release(
        RELEASE_VERSION, "--repo-dir", str(repo), "--dist-dir", str(dist), "--tap-dir", str(tap)
    )

    assert result.returncode == 0, result.stderr
    tarball = dist / TARBALL_NAME
    assert tarball.is_file() and tarball.stat().st_size > 0, f"script did not build {tarball}"
    with tarfile.open(tarball, "r:gz") as tar:
        names = tar.getnames()
    assert any(n.endswith("/pyproject.toml") for n in names), names
    formula = formula_text(tap)
    assert f'sha256 "{hashlib.sha256(tarball.read_bytes()).hexdigest()}"' in formula, formula


def test_built_tarball_is_reproducible(tmp_path: Path) -> None:
    """Same HEAD -> same bytes, so a re-run cannot hand the operator two hashes."""
    repo = make_fake_repo(tmp_path)
    hashes = set()
    for attempt in (1, 2):
        dist = tmp_path / f"built{attempt}"
        tap = tmp_path / f"tap{attempt}"
        (tap / "Formula").mkdir(parents=True)
        result = run_release(
            RELEASE_VERSION, "--repo-dir", str(repo), "--dist-dir", str(dist), "--tap-dir", str(tap)
        )
        assert result.returncode == 0, result.stderr
        hashes.add(hashlib.sha256((dist / TARBALL_NAME).read_bytes()).hexdigest())
    assert len(hashes) == 1, hashes


# --- Refusals --------------------------------------------------------------
def test_version_that_does_not_match_pyproject_refuses(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path, version="0.1.0")
    tarball = make_fake_dist(tmp_path / "dist", tarball_name="micro_notify-9.9.9.tar.gz")
    tap = make_fake_tap(tmp_path)

    result = run_release("9.9.9", "--repo-dir", str(repo), "--asset", str(tarball), "--tap-dir", str(tap))

    assert result.returncode == 2, result.stdout
    assert "0.1.0" in result.stderr and "9.9.9" in result.stderr, result.stderr
    assert not (tap / "Formula" / "micro-notify.rb").exists(), "refused, yet wrote the formula"


def test_existing_tag_refuses(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path)
    git(repo, "tag", f"v{RELEASE_VERSION}")
    tarball = make_fake_dist(tmp_path / "dist")
    tap = make_fake_tap(tmp_path)

    result = run_release(RELEASE_VERSION, "--repo-dir", str(repo), "--asset", str(tarball), "--tap-dir", str(tap))

    assert result.returncode == 2, result.stdout
    assert f"v{RELEASE_VERSION}" in result.stderr, result.stderr
    assert not (tap / "Formula" / "micro-notify.rb").exists(), "refused, yet wrote the formula"


def test_dirty_tree_refuses(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path)
    (repo / "src" / "micro_notify" / "oops.py").write_text("VALUE = 1\n", encoding="utf-8")
    tarball = make_fake_dist(tmp_path / "dist")
    tap = make_fake_tap(tmp_path)

    result = run_release(RELEASE_VERSION, "--repo-dir", str(repo), "--asset", str(tarball), "--tap-dir", str(tap))

    assert result.returncode == 2, result.stdout
    assert "clean" in result.stderr.lower(), result.stderr
    assert not (tap / "Formula" / "micro-notify.rb").exists(), "refused, yet wrote the formula"


def test_unnormalised_version_form_refuses(tmp_path: Path) -> None:
    repo = make_fake_repo(tmp_path)

    result = run_release("0.1.0rc1", "--repo-dir", str(repo), "--asset", str(tmp_path / "nope.tar.gz"))

    assert result.returncode == 2, result.stdout
    assert "X.Y.Z" in result.stderr, result.stderr


def test_tarball_without_project_root_refuses(tmp_path: Path) -> None:
    """The formula installs from the extracted tree, so a bare tarball is fatal."""
    repo = make_fake_repo(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    tarball = dist / TARBALL_NAME
    payload = b"nothing installable\n"
    with tarfile.open(tarball, "w:gz") as tar:
        info = tarfile.TarInfo(f"micro_notify-{RELEASE_VERSION}/README.md")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    tap = make_fake_tap(tmp_path)

    result = run_release(RELEASE_VERSION, "--repo-dir", str(repo), "--asset", str(tarball), "--tap-dir", str(tap))

    assert result.returncode == 2, result.stdout
    assert "pyproject.toml" in result.stderr, result.stderr


def test_missing_template_refuses(tmp_path: Path) -> None:
    """Template absent at the path the script reads -> exit 2, nothing written.

    The template is committed, so deleting it from the work tree is itself a
    dirty-tree refusal; commit the removal first to reach the template check.
    """
    repo = make_fake_repo(tmp_path)
    template = repo / "packaging" / "Formula" / "micro-notify.rb.tmpl"
    template.unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "drop the formula template")
    tarball = make_fake_dist(tmp_path / "dist")

    result = run_release(
        RELEASE_VERSION, "--repo-dir", str(repo), "--asset", str(tarball),
        "--tap-dir", str(make_fake_tap(tmp_path)),
    )

    assert result.returncode == 2, result.stdout
    assert "template" in result.stderr.lower(), result.stderr


# --- Syntax proof ----------------------------------------------------------
@pytest.mark.skipif(shutil.which("ruby") is None, reason="no Ruby interpreter on this host")
def test_rendered_formula_is_valid_ruby(tmp_path: Path) -> None:
    """`ruby -c` on the rendered formula — the syntax proof, or an honest skip."""
    result, _repo, tap = happy_render(tmp_path)
    assert result.returncode == 0, result.stderr

    check = subprocess.run(
        ["ruby", "-c", str(tap / "Formula" / "micro-notify.rb")],
        capture_output=True,
        text=True,
    )

    assert check.returncode == 0, f"ruby -c failed:\n{check.stdout}{check.stderr}"
    assert "Syntax OK" in check.stdout, check.stdout


@pytest.mark.skipif(shutil.which("ruby") is None, reason="no Ruby interpreter on this host")
def test_tracked_template_is_valid_ruby_once_placeholders_are_filled(tmp_path: Path) -> None:
    """The template in git must parse too, not only a render someone ran."""
    template = FORMULA_TEMPLATE.read_text(encoding="utf-8")
    # Fill every placeholder with a plausible value so the parse proves the
    # structure and not just the literal text around the holes.
    filled = re.sub(r"\{\{([A-Z_]+)\}\}", lambda m: f"{RELEASE_VERSION}-x", template)
    probe = tmp_path / "template-probe.rb"
    probe.write_text(filled, encoding="utf-8")

    check = subprocess.run(["ruby", "-c", str(probe)], capture_output=True, text=True)

    assert check.returncode == 0, f"ruby -c failed:\n{check.stdout}{check.stderr}"
    assert "Syntax OK" in check.stdout, check.stdout
