#!/usr/bin/env bash
set -eu

mode="${1:-check}"
case "$mode" in
  check) ;;
  *) echo "usage: $0 [check]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if ! git -C "$repo_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release actions require a Git worktree" >&2
  exit 1
fi
if [ -n "$(git -C "$repo_dir" status --porcelain=v1 --untracked-files=all)" ]; then
  echo "release action refused because the Git worktree is dirty" >&2
  exit 1
fi

echo "clean Git worktree verified"
