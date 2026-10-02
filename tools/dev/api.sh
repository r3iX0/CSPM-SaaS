#!/usr/bin/env bash
# Runs one of the API's dev tools (mypy, pytest...) from apps/api, the version
# pinned in pyproject.toml rather than whatever is first on PATH. Used by the
# local hooks in .pre-commit-config.yaml.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root/apps/api"

tool="$1"
shift
if [[ -x ".venv/bin/$tool" ]]; then
  exec ".venv/bin/$tool" "$@"
elif command -v "$tool" >/dev/null 2>&1; then
  # CI installs into the runner's Python rather than a venv.
  exec "$tool" "$@"
fi
echo "error: '$tool' is not installed for apps/api. Run tools/dev/setup.sh first." >&2
exit 1
