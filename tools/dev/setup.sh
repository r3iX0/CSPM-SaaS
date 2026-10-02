#!/usr/bin/env bash
# One command from a fresh clone to a working checkout: the API's dev tools,
# the web app's locked dependencies, and the git hooks.
#
# Git never installs hooks from a clone on its own -- a repository that could
# run code on `git clone` would be a remote-execution bug -- so every clone runs
# this once. CI runs the same hooks on every pull request, so a checkout that
# skipped it still cannot merge what they refuse.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is required ($2)." >&2; exit 1; }
}
need node "22 or later"
need npm "ships with node"

echo "==> apps/api: virtualenv and dev dependencies"
if command -v uv >/dev/null 2>&1; then
  (cd apps/api && uv venv --python 3.12 --allow-existing .venv && uv pip install --python .venv/bin/python -e ".[dev]")
else
  need python3.12 "the API targets 3.12; or install uv, which fetches it"
  (cd apps/api && python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]")
fi

echo "==> apps/web: locked dependencies"
(cd apps/web && npm ci)

echo "==> git hooks"
# The pinned pre-commit from the API's dev dependencies, so every clone runs
# the same version CI does. default_install_hook_types in the config installs
# both the commit and the push stage.
apps/api/.venv/bin/pre-commit install --install-hooks

# The repository-wide formatting commits are noise in `git blame`; this file
# lists them so blame looks past them (GitHub reads it on its own).
git config blame.ignoreRevsFile .git-blame-ignore-revs

echo "Done. Hooks run on commit and push; 'pre-commit run --all-files' runs them by hand."
