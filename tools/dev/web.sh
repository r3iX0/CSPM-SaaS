#!/usr/bin/env bash
# Runs one of the web app's dev tools (eslint, prettier, tsc) at the version
# locked in apps/web/package-lock.json. Used by the local hooks in
# .pre-commit-config.yaml.
#
# Prettier runs from the repository root, so the root .prettierrc.json and
# .prettierignore apply to the paths pre-commit passes. ESLint runs from
# apps/web, beside its config, with the paths rewritten to match.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
tool="$1"
shift
bin="$root/apps/web/node_modules/.bin/$tool"
if [[ ! -x "$bin" ]]; then
  echo "error: '$tool' is not installed for apps/web. Run tools/dev/setup.sh first." >&2
  exit 1
fi

if [[ "$tool" == "prettier" ]]; then
  cd "$root"
  exec "$bin" "$@"
fi

cd "$root/apps/web"
args=()
for arg in "$@"; do
  args+=("${arg#apps/web/}")
done
exec "$bin" "${args[@]+"${args[@]}"}"
