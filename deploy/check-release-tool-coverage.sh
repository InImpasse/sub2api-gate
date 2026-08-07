#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "$temporary_dir"' EXIT

cd "$repo_dir"
uvx --python "$(command -v python3)" --from coverage==7.15.3 coverage run \
  --branch \
  --data-file "$temporary_dir/coverage.data" \
  --include 'deploy/local-worker-publish.py,deploy/recover-worker-admin.py' \
  -m unittest \
  sub2api-sync/tests/test_local_worker_publish.py \
  sub2api-sync/tests/test_worker_admin_recovery.py \
  sub2api-sync/tests/test_worker_admin_recovery_subprocess.py
uvx --python "$(command -v python3)" --from coverage==7.15.3 coverage json \
  --data-file "$temporary_dir/coverage.data" \
  -o "$temporary_dir/coverage.json"

python3 - "$temporary_dir/coverage.json" <<'PY'
import json
import pathlib
import sys


report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
thresholds = {
    "deploy/local-worker-publish.py": (90.0, 85.0),
    "deploy/recover-worker-admin.py": (90.0, 85.0),
}
failures = []
for path, (statement_minimum, branch_minimum) in thresholds.items():
    summary = report.get("files", {}).get(path, {}).get("summary", {})
    statements = float(summary.get("percent_statements_covered", 0.0))
    branches = float(summary.get("percent_branches_covered", 0.0))
    print(f"{path}: statements={statements:.2f}% branches={branches:.2f}%")
    if statements < statement_minimum or branches < branch_minimum:
        failures.append(path)
if failures:
    raise SystemExit("release-tool coverage gate failed")
PY
