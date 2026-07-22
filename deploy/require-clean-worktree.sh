#!/bin/bash
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

trusted_production_root="/opt/sub2api-gate-release"

mode="${1:-check}"
case "$mode" in
  check) ;;
  *) echo "usage: $0 [check]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ "$(id -u)" -eq 0 ]; then
  if [ "$repo_dir" != "$trusted_production_root" ]; then
    echo "root release actions require the fixed trusted production tree" >&2
    exit 1
  fi

  for trusted_directory in / /opt "$trusted_production_root"; do
    if [ -L "$trusted_directory" ] || [ ! -d "$trusted_directory" ]; then
      echo "trusted production release directory boundary is unsafe" >&2
      exit 1
    fi
    owner="$(stat -c '%u' -- "$trusted_directory")" || {
      echo "trusted production release directory boundary is unavailable" >&2
      exit 1
    }
    mode_bits="$(stat -c '%a' -- "$trusted_directory")" || {
      echo "trusted production release directory boundary is unavailable" >&2
      exit 1
    }
    case "$mode_bits" in
      ''|*[!0-7]*)
        echo "trusted production release directory mode is invalid" >&2
        exit 1
        ;;
    esac
    if [ "$owner" != "0" ] || [ $((8#$mode_bits & 8#022)) -ne 0 ]; then
      echo "trusted production release directory must be root-owned and immutable to other users" >&2
      exit 1
    fi
  done

  unsafe_entry="$(
    find "$trusted_production_root" -xdev \
      \( -type l -o ! -user root -o -perm /022 \
         -o \( ! -type f ! -type d \) \) \
      -print -quit
  )" || {
    echo "trusted production release tree could not be inspected" >&2
    exit 1
  }
  if [ -n "$unsafe_entry" ]; then
    echo "trusted production release tree contains an unsafe entry" >&2
    exit 1
  fi

  if awk -v root="$trusted_production_root" '
    $5 == root || index($5, root "/") == 1 { found = 1 }
    END { exit(found ? 0 : 1) }
  ' /proc/self/mountinfo; then
    echo "trusted production release tree must not contain a mount boundary" >&2
    exit 1
  fi
fi

if ! git -C "$repo_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release actions require a Git worktree" >&2
  exit 1
fi
if [ -n "$(git -C "$repo_dir" status --porcelain=v1 --untracked-files=all)" ]; then
  echo "release action refused because the Git worktree is dirty" >&2
  exit 1
fi

echo "clean Git worktree verified"
