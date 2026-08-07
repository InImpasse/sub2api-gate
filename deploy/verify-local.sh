#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

python3 -I deploy/verify-release-policy.py
bash deploy/check-core-coverage.sh
bash deploy/check-release-tool-coverage.sh
bash deploy/run-sync-dependency-integration.sh
npm --prefix worker-allow-ip run test:browser-ui
git diff --check
