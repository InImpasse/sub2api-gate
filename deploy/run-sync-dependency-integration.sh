#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  echo "sync dependency integration requires an available Docker daemon" >&2
  exit 1
fi

cd "$repo_dir"
SUB2API_RUN_DEPENDENCY_INTEGRATION=1 \
  python3 -m unittest discover \
    -s sub2api-sync/tests \
    -p 'test_sync_dependency_integration.py' \
    -v
