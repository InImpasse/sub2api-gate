#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
baseline_path="$repo_dir/deploy/core-coverage-baseline.json"
temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "$temporary_dir"' EXIT

if [[ ! -f "$baseline_path" ]]; then
  echo "core coverage baseline is unavailable" >&2
  exit 1
fi

worker_report="$temporary_dir/worker-coverage.txt"
if ! (
  cd "$repo_dir/worker-allow-ip"
  node --test --experimental-test-coverage \
    --experimental-test-isolation=none >"$worker_report" 2>&1
); then
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    worker_summary="$({
      awk '
        $2 ~ /^(tests|pass|fail|cancelled|skipped|todo)$/ && $3 ~ /^[0-9]+$/ {
          printf "%s%s=%s", separator, $2, $3
          separator=","
        }
      ' "$worker_report"
    } || true)"
    if [[ -z "$worker_summary" ]]; then
      worker_summary="bounded test summary unavailable"
    fi
    printf '::error title=Worker test gate failed::%s\n' "$worker_summary" >&2
  fi
  tail -n 80 "$worker_report" >&2 || true
  exit 1
fi

python3 - "$worker_report" "$baseline_path" <<'PY'
import json
import os
import pathlib
import re
import sys

report_path = pathlib.Path(sys.argv[1])
baseline = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="ascii"))
worker = baseline.get("worker")
if not isinstance(worker, dict) or not worker:
    raise SystemExit("core coverage baseline has no Worker thresholds")

# Node 22 prefixes its native coverage table with `#`; Node 24 uses the
# information symbol. Both reports carry the same bounded numeric columns.
row = re.compile(r"^\s*(?:\N{INFORMATION SOURCE}|#)\s+(.+?)\s+\|\s+([0-9.]+)\s+\|\s+([0-9.]+)\s+\|")
observed = {}
for line in report_path.read_text(encoding="utf-8", errors="replace").splitlines():
    match = row.match(line)
    if not match:
        continue
    path = match.group(1).strip().replace("\\", "/")
    observed[path] = (float(match.group(2)), float(match.group(3)))

failures = []
for suffix, threshold in worker.items():
    if not isinstance(threshold, dict):
        failures.append(f"{suffix}: invalid threshold")
        continue
    basename = suffix.rsplit("/", 1)[-1]
    match = next(
        (value for path, value in observed.items() if path.endswith(suffix) or path == basename),
        None,
    )
    if match is None:
        failures.append(f"{suffix}: coverage row missing")
        continue
    line, branch = match
    line_minimum = float(threshold["line"])
    branch_minimum = float(threshold["branch"])
    print(f"worker {suffix}: line={line:.2f}% branch={branch:.2f}%")
    if line < line_minimum or branch < branch_minimum:
        failures.append(
            f"{suffix}: line={line:.2f}%/{line_minimum:.2f}% "
            f"branch={branch:.2f}%/{branch_minimum:.2f}%"
        )
if failures:
    message = "Worker coverage regression: " + "; ".join(failures)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        annotation = (
            message.replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )
        print(f"::error title=Worker coverage gate failed::{annotation}")
    raise SystemExit(message)
PY

cd "$repo_dir"
uvx --python "$(command -v python3)" --from coverage==7.15.3 coverage run \
  --branch \
  --data-file "$temporary_dir/sync-coverage.data" \
  --include 'sub2api-sync/sub2api_sync.py' \
  -m unittest discover -s sub2api-sync/tests -q
uvx --python "$(command -v python3)" --from coverage==7.15.3 coverage json \
  --data-file "$temporary_dir/sync-coverage.data" \
  -o "$temporary_dir/sync-coverage.json"

python3 - "$temporary_dir/sync-coverage.json" "$baseline_path" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
baseline = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="ascii"))
threshold = baseline.get("sync")
summary = report.get("files", {}).get("sub2api-sync/sub2api_sync.py", {}).get("summary", {})
if not isinstance(threshold, dict) or not summary:
    raise SystemExit("sync coverage baseline or report is unavailable")
line = float(summary.get("percent_covered", 0.0))
branch = float(summary.get("percent_branches_covered", 0.0))
line_minimum = float(threshold["line"])
branch_minimum = float(threshold["branch"])
print(f"sync sub2api_sync.py: line={line:.2f}% branch={branch:.2f}%")
if line < line_minimum or branch < branch_minimum:
    raise SystemExit(
        "sync coverage regression: "
        f"line={line:.2f}%/{line_minimum:.2f}% "
        f"branch={branch:.2f}%/{branch_minimum:.2f}%"
    )
PY
