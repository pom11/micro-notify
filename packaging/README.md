# Packaging: the Homebrew tap and the release script

This directory holds the packaging side of micro-notify: the tap formula
template. Design contract: `docs/design/2026-10-27-micro-notify-design.md`
section 5 (packaging) and section 8 step 7.

Everything about *using* the CLI lives elsewhere — install and usage in
[`README.md`](../README.md), the one-time tenant work in
[`docs/ADMIN-SETUP.md`](../docs/ADMIN-SETUP.md). This file is only about how a
release gets from a commit to `brew install`.

## What is here

```
packaging/Formula/micro-notify.rb.tmpl   Homebrew formula template (the tap's only file)
scripts/release.py                       prepares a release; publishes nothing
```

The tap itself is a separate repository, `pom11/homebrew-micro-notify`, laid
out the way Homebrew expects for a third-party tap:

```
homebrew-micro-notify/
└── Formula/
    └── micro-notify.rb      <- written by scripts/release.py from the .tmpl here
```

## How `brew install pom11/micro-notify/micro-notify` resolves

1. `brew tap pom11/micro-notify` clones `github.com/pom11/homebrew-micro-notify`
   into Homebrew's tap directory. The tap repo name must start with `homebrew-`
   — that is why the tap is `homebrew-micro-notify` and not `micro-notify`.
2. `brew install pom11/micro-notify/micro-notify` (or the shorter
   `brew install pom11/micro-notify/micro-notify` form once the tap is tapped)
   reads `Formula/micro-notify.rb`.
3. The formula is a **Python virtualenv** formula
   (`include Language::Python::Virtualenv`). Homebrew downloads the `url` — the
   GitHub release tarball for the tagged version — verifies it against the
   `sha256` in the formula, and extracts it.
4. `install` creates a private venv under the keg (`libexec/venv`), installs
   every pinned `resource` from its staged sdist, then installs the project
   itself with `pip_install_and_link buildpath`. That last call is what puts
   `micro-notify` and `mnotify` in `bin`, because both are `[project.scripts]`
   entries in `pyproject.toml`.
5. `brew test micro-notify` runs the formula's `test do` block: both console
   scripts with `--version` (argparse's eager version action, which exits
   before any config, keychain or network access) plus a check that the guard
   flags appear in `mail send --help`.

### Why the dependency closure is pinned by hand

Homebrew passes `--no-deps` to pip, so a formula that only pinned `msal` and
`httpx` would install a package that cannot import its own dependencies. Every
distribution in the runtime closure is therefore a `resource` block with a
`url` and `sha256` — including the transitive ones msal brings
(`requests`, `PyJWT`, `cryptography`, `cffi`, `pycparser`, `typing_extensions`)
and the ones httpx brings (`httpcore`, `h11`, `anyio`, `certifi`, `idna`, plus
requests' `urllib3` and `charset-normalizer`). `tests/test_release_script.py`
asserts the list, so a dependency added to `pyproject.toml` without a matching
resource block fails the suite instead of failing someone's `brew install`.

`cryptography` builds a Rust extension, so the formula also declares build
dependencies for a Rust toolchain, `pkgconf` and OpenSSL. The PEP 517 build
backends the sdists need are resolved by pip in a build-isolated environment,
which is why the formula carries `allow_network_access! :build` — the same
trade-off homebrew-core makes for `awscli`.

Keeping the pins current is a manual step: when a `pyproject.toml` dependency
changes, refresh the resource blocks and run the suite. The pinned versions in
this repo were taken from PyPI's own sdists and digests.

## Preparing a release

Run from a clean checkout of the repo you intend to release:

```bash
python scripts/release.py 0.1.0                      # dry run: prints, writes nothing
python scripts/release.py 0.1.0 --tap-dir ~/dev/homebrew-micro-notify
```

The script:

1. refuses unless the tree is clean, the requested `X.Y.Z` matches both
   `pyproject.toml` and `src/micro_notify/__init__.py`, and the tag `vX.Y.Z`
   does not already exist locally;
2. builds a deterministic source tarball from `HEAD` (`git archive`) into
   `dist/`, and refuses if that tarball has no `pyproject.toml` at its root —
   the formula installs from the extracted tree, so a bare tarball is fatal;
3. computes the tarball's `sha256` and renders the formula template to
   `<tap>/Formula/micro-notify.rb`, substituting `{{VERSION}}`, `{{URL}}` and
   `{{SHA256}}`;
4. prints the exact `git tag`, `git push`, `gh release create` and tap
   commit/push commands.

**It prints those commands; it never runs them.** Publishing is the operator's
step, so the script needs no token, no secret, no keychain access and no
credentials in the environment. `tests/test_release_script.py` proves this
behaviourally: the fixture repo has no remote at all, `gh` and `security` are
replaced by logging PATH shims, and the test asserts those shims were never
invoked and no tag was created.

Order matters for a real release: tag and `gh release create` first (the
formula `url` points at the release asset, so it must exist), then push the tap
commit. The printed plan follows that order.

## Checking the formula without a release

`ruby -c` parses the rendered formula (and the template with its placeholders
substituted) — both are covered by real `ruby -c` invocations in
`tests/test_release_script.py`, which skip rather than pass on a host with no
Ruby. `brew style Formula/micro-notify.rb` in a tap checkout is the stricter
lint and is worth running before the tap commit; it is not part of this repo's
test suite because it needs a Homebrew installation.
