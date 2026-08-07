#!/usr/bin/env bash
set -euo pipefail

readonly git_binary="/usr/bin/git"
readonly env_binary="/usr/bin/env"
readonly safe_command_path="/usr/sbin:/usr/bin:/sbin:/bin"
PATH="$safe_command_path"
export PATH

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_dir"

safe_git() {
  "$env_binary" -i \
    PATH="$safe_command_path" \
    HOME=/nonexistent \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    "$git_binary" \
      -c core.fsmonitor=false \
      -c core.hooksPath=/dev/null \
      "$@"
}

# This gate is intentionally stricter than verify-local.sh: a release source
# must be a clean Git tree before it can enter a trusted production tree.
"/usr/bin/python3" -I deploy/verify-release-policy.py
/usr/bin/bash deploy/require-clean-worktree.sh check
safe_git diff --check

for forbidden in \
  .env \
  worker-allow-ip/wrangler.private.jsonc \
  worker-allow-ip/.dev.vars
do
  if safe_git ls-files --error-unmatch -- "$forbidden" >/dev/null 2>&1; then
    echo "release candidate contains a private file: $forbidden" >&2
    exit 1
  fi
done

head="$(safe_git rev-parse --verify HEAD^{commit})"
case "$head" in
  ''|*[!0-9a-f]*)
    echo "release candidate Git HEAD is not a canonical commit" >&2
    exit 1
    ;;
esac

echo "clean release candidate verified at Git ${head:0:12}"
