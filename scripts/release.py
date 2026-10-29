"""Prepare a micro-notify release: hash the tarball, render the tap formula.

Run by the orchestrator (design section 5 — v1 has no GH Actions secrets, so
publishing is a human step). This script *prepares and prints*; it never
publishes. It does not run ``git tag``, ``git push``, ``gh release create`` or
any tap commit — those lines are printed for the operator to copy. It reads no
secrets, no tokens, no keychain, and needs no environment variables.

Usage::

    python scripts/release.py 0.1.0 --tap-dir ~/dev/homebrew-micro-notify
    python scripts/release.py 0.1.0                 # dry run, no tap written

Exit codes: 0 prepared, 2 refused (bad version, dirty tree, existing tag,
version mismatch, missing template).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT_DEFAULT = Path(__file__).resolve().parents[1]
FORMULA_TEMPLATE = Path("packaging/Formula/micro-notify.rb.tmpl")
FORMULA_NAME = "micro-notify.rb"
GITHUB_ORG = "pom11"
GITHUB_REPO = "micro-notify"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
# Dist-info names are normalised (PEP 503): micro-notify -> micro_notify.
ASSET_NAME = "micro_notify-{version}.tar.gz"

REFUSED = 2


def fail(message: str) -> int:
    """Print a refusal on stderr and report the exit code. Never raises."""
    print(f"refusing: {message}", file=sys.stderr)
    return REFUSED


def git(repo_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )


def check_version(version: str) -> str | None:
    if not VERSION_RE.match(version):
        return f"version {version!r} is not X.Y.Z (tags are vX.Y.Z per design section 5)"
    return None


def declared_pyproject_version(repo_dir: Path) -> str | None:
    """The [project] version from pyproject.toml, read without tomllib guesswork."""
    pyproject = repo_dir / "pyproject.toml"
    if not pyproject.exists():
        return None
    in_project = False
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
            continue
        if in_project and stripped.startswith("version"):
            match = re.match(r'version\s*=\s*["\']([^"\']+)["\']', stripped)
            if match:
                return match.group(1)
    return None


def declared_package_version(repo_dir: Path) -> str | None:
    """``__version__`` from src/micro_notify/__init__.py — must agree with pyproject."""
    init = repo_dir / "src" / "micro_notify" / "__init__.py"
    if not init.exists():
        return None
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match else None


def check_tree_is_clean(repo_dir: Path) -> str | None:
    result = git(repo_dir, "status", "--porcelain")
    if result.returncode != 0:
        return f"`git status --porcelain` failed: {result.stderr.strip()}"
    if result.stdout.strip():
        changed = ", ".join(line.strip() for line in result.stdout.splitlines()[:10])
        return f"the working tree is not clean ({changed})"
    return None


def check_tag_is_free(repo_dir: Path, version: str) -> str | None:
    tag = f"v{version}"
    local = git(repo_dir, "show-ref", "--tags", "--verify", f"refs/tags/{tag}")
    if local.returncode == 0:
        return f"tag {tag} already exists locally"
    # Tags fetched from the remote land under refs/remotes too; catch those
    # without touching the network (this script never talks to a remote).
    listed = git(repo_dir, "tag", "--list", tag)
    if listed.returncode == 0 and listed.stdout.strip():
        return f"tag {tag} already exists locally"
    return None


def build_source_tarball(repo_dir: Path, version: str, asset: Path) -> str | None:
    """Deterministic source tarball of HEAD via ``git archive``. Returns an error.

    ``git archive`` is used rather than a PEP 517 build so the artifact is the
    committed tree exactly — no build backend, no network, and the bytes we
    hash are the bytes the operator uploads.
    """
    asset.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"micro_notify-{version}/"
    result = git(
        repo_dir,
        "archive",
        f"--format=tar.gz",
        f"--prefix={prefix}",
        f"--output={asset}",
        "HEAD",
    )
    if result.returncode != 0:
        return f"`git archive` failed: {result.stderr.strip()}"
    if not asset.exists() or asset.stat().st_size == 0:
        return f"`git archive` produced no artifact at {asset}"
    return None


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tarball_has_project_root(path: Path) -> bool:
    """The formula installs from the extracted tree, so it needs pyproject.toml."""
    with tarfile.open(path, "r:gz") as tar:
        names = tar.getnames()
    return any(re.fullmatch(r"[^/]+/pyproject\.toml", name) or name == "pyproject.toml" for name in names)


def render_formula(template_text: str, version: str, url: str, sha256: str) -> str:
    """Substitute the three placeholders; refuse loudly if any other remains."""
    rendered = (
        template_text.replace("{{VERSION}}", version)
        .replace("{{URL}}", url)
        .replace("{{SHA256}}", sha256)
    )
    leftovers = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", rendered)))
    if leftovers:
        raise ValueError(f"template placeholders left unsubstituted: {leftovers}")
    return rendered


def asset_url(version: str, asset_name: str) -> str:
    return (
        f"https://github.com/{GITHUB_ORG}/{GITHUB_REPO}/releases/download/"
        f"v{version}/{asset_name}"
    )


def publish_commands(version: str, asset: Path, tap_dir: Path | None, sha256: str) -> list[str]:
    """The exact commands the operator runs. This script prints them, never runs them."""
    tag = f"v{version}"
    lines = [
        f"cd {REPO_ROOT_DEFAULT}",
        f"git tag -a {tag} -m \"micro-notify {tag}\"",
        f"git push origin {tag}",
        f"gh release create {tag} {asset} "
        f"--title \"micro-notify {tag}\" --generate-notes",
    ]
    if tap_dir is not None:
        lines += [
            f"cd {tap_dir}",
            "git add Formula/" + FORMULA_NAME,
            f'git commit -m "micro-notify {tag} (sha256 {sha256[:12]}...)"',
            "git push origin main",
        ]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="release.py",
        description="Prepare a micro-notify release: hash the tarball, render the tap formula, "
        "print the publish commands. Publishes nothing.",
    )
    parser.add_argument("version", help="release version as X.Y.Z (tag will be vX.Y.Z)")
    parser.add_argument("--repo-dir", type=Path, default=REPO_ROOT_DEFAULT, help="project checkout (default: this repo)")
    parser.add_argument(
        "--tap-dir",
        type=Path,
        default=None,
        help="local clone of the tap; omit for a dry run that writes nothing",
    )
    parser.add_argument("--dist-dir", type=Path, default=None, help="where the tarball is written (default: <repo>/dist)")
    parser.add_argument(
        "--asset",
        type=Path,
        default=None,
        help="use this already-built tarball instead of building one (hashing is unchanged)",
    )
    parser.add_argument("--dry-run", action="store_true", help="render nothing to disk, print only (implied without --tap-dir)")
    args = parser.parse_args(argv)

    version = args.version.lstrip("v")
    problems: list[str] = []
    for check in (
        check_version(version),
        check_tree_is_clean(args.repo_dir) if args.repo_dir.is_dir() else f"no such repo dir: {args.repo_dir}",
    ):
        if check:
            problems.append(check)
    if problems:
        return fail("; ".join(problems))

    pyproject_version = declared_pyproject_version(args.repo_dir)
    package_version = declared_package_version(args.repo_dir)
    if pyproject_version is None:
        return fail("cannot read [project] version from pyproject.toml")
    if pyproject_version != version:
        return fail(f"pyproject.toml says {pyproject_version!r} but {version!r} was requested — bump it first")
    if package_version is not None and package_version != version:
        return fail(f"src/micro_notify/__init__.py says {package_version!r} but {version!r} was requested")

    tag_check = check_tag_is_free(args.repo_dir, version)
    if tag_check:
        return fail(tag_check)

    template_path = args.repo_dir / FORMULA_TEMPLATE
    if not template_path.exists():
        return fail(f"missing formula template {FORMULA_TEMPLATE}")

    dry_run = args.dry_run or args.tap_dir is None
    dist_dir = args.dist_dir or (args.repo_dir / "dist")
    asset = args.asset or dist_dir / ASSET_NAME.format(version=version)
    if args.asset is None:
        build_error = build_source_tarball(args.repo_dir, version, asset)
        if build_error:
            return fail(build_error)
    elif not asset.exists():
        return fail(f"--asset {asset} does not exist")

    if not tarball_has_project_root(asset):
        return fail(f"{asset} does not carry pyproject.toml at its root — the formula installs from that tree")

    sha256 = sha256_of(asset)
    url = asset_url(version, asset.name)
    rendered = render_formula(template_path.read_text(encoding="utf-8"), version, url, sha256)

    tap_target = args.tap_dir / "Formula" / FORMULA_NAME if args.tap_dir is not None else None
    if dry_run:
        target = tap_target if tap_target is not None else Path("<tap>") / "Formula" / FORMULA_NAME
        print("dry run: nothing written to disk")
        print(f"would write {target}")
    else:
        assert tap_target is not None
        tap_target.parent.mkdir(parents=True, exist_ok=True)
        tap_target.write_text(rendered, encoding="utf-8")
        print(f"wrote {tap_target}")

    print(f"version  {version}")
    print(f"tarball  {asset}")
    print(f"sha256   {sha256}")
    print(f"url      {url}")
    print()
    print("Publish commands (the operator runs these — this script does not):")
    for line in publish_commands(version, asset, args.tap_dir, sha256):
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
