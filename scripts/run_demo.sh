#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f packages/orbit-control-plane-console/dist/index.html ]]; then
  echo "Build the retained console first: npm ci --prefix packages/orbit-control-plane-console --ignore-scripts && npm run build --prefix packages/orbit-control-plane-console" >&2
  exit 1
fi
export PYTHONPATH=src:.
exec uv run --locked --offline python -m showcase.server
