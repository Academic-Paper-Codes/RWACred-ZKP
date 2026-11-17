#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cli="$root/node_modules/snarkjs/build/cli.cjs"
if [[ ! -f "$cli" ]]; then
  echo "Missing snarkjs. Run npm ci in $root." >&2
  exit 1
fi

exec node "$cli" "$@"
