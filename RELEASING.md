# Releasing Pynzor

This guide is for maintainers cutting a new Pynzor release. Following it from top
to bottom produces a tagged GitHub release with per-platform binaries and a PyPI
publish, all driven by
[`.github/workflows/release.yml`](.github/workflows/release.yml).

Releases are triggered by pushing a `v*` tag. The workflow runs the test suite,
builds standalone binaries for Windows, macOS, and Linux, attaches them to the
GitHub release, and publishes the package to PyPI via trusted publishing.

Pynzor follows [Semantic Versioning](https://semver.org/): bump the **major** for
breaking changes, **minor** for backwards-compatible features, and **patch** for
fixes.

## 1. Pre-release checks

Run from a clean checkout of `main`:

```bash
uv sync
uv run pytest   # full suite must pass — this is the gate CI enforces
```

Optionally lint if you have `ruff` available (`uv run ruff check .`).

Also confirm:

- `CHANGELOG.md` has an accurate `Unreleased` section describing what ships.
- `README.md` reflects any new commands, flags, or install notes.
- You are on `main` with no uncommitted changes and the working tree matches the
  remote.

## 2. Bump the version

The version is single-sourced from `pyproject.toml`:

```toml
[project]
version = "1.1.0"
```

The CLI reads it at runtime via `importlib.metadata`
(`src/pynzor/cli/commands.py::get_version`), so `Pynzor --version` and the demo
output update automatically — no other file needs editing.

Bump `version` to the release you are cutting, then update `CHANGELOG.md`:

- Rename the `## [Unreleased]` heading to `## [X.Y.Z] - YYYY-MM-DD`.
- Add a fresh, empty `## [Unreleased]` section above it.
- Add the matching link references at the bottom of the file
  (`[X.Y.Z]: .../releases/tag/vX.Y.Z` and update the `[Unreleased]` compare
  range).

Commit these together:

```bash
git commit -am "Release vX.Y.Z"
git push origin main
```

## 3. Tag and push

The workflow fires on any tag matching `v*`:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Pushing the tag starts `release.yml`. The Windows build job creates the GitHub
release with `generate_release_notes: true`, so the release notes are
auto-populated from merged PRs since the previous tag. Review and edit them on
the GitHub Releases page if needed after the run completes.

## 4. PyPI trusted publishing

The `publish-pypi` job runs after all three binary builds succeed. It uses
**PyPI trusted publishing** (OpenID Connect) — there is no stored API token:

- The job runs in the GitHub `pypi` environment with `id-token: write`
  permission.
- PyPI is configured with a trusted publisher for this repository, workflow
  (`release.yml`), and environment (`pypi`). If publishing fails with an
  identity error, verify that trusted-publisher config on
  <https://pypi.org/manage/project/Pynzor/settings/publishing/>.
- The job builds the sdist + wheel (`python -m build`), validates them
  (`twine check`), and uploads with `pypa/gh-action-pypi-publish`.

## 5. Binary artifacts

Each platform job builds a standalone PyInstaller binary from `Pynzor.spec`,
smoke-tests it on its native runner (`--version`, `--help`, `headers --help`),
and attaches it to the release:

| Platform | Runner          | Artifact        |
|----------|-----------------|-----------------|
| Windows  | `windows-latest`| `Pynzor.exe`    |
| macOS    | `macos-latest`  | `Pynzor-macos`  |
| Linux    | `ubuntu-latest` | `Pynzor-linux`  |

The bundled config, wordlists, and HTML report template are embedded in each
binary and resolved at runtime.

## 6. Post-release verification

- Confirm all jobs in the workflow run are green.
- Confirm the three binaries are attached to the GitHub release.
- Confirm the new version is live: `pipx install Pynzor==X.Y.Z && Pynzor --version`.

## 7. Rollback

PyPI releases are **immutable** — a version number can never be reused. To back
out a bad release:

1. **Yank the PyPI release** (hides it from new installs without deleting it):
   PyPI project page → *Manage* → *Releases* → *Options* → *Yank*.
2. **Delete or mark the GitHub release** as a draft so its binaries are no longer
   advertised.
3. **Delete the bad tag** so it can't be confused for a good release:
   ```bash
   git push --delete origin vX.Y.Z
   git tag -d vX.Y.Z
   ```
4. **Ship a fixed patch release** (e.g. `X.Y.Z+1`) following this guide again.
   Never attempt to re-publish the same version number.
