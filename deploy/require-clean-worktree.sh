#!/bin/bash
set -eu

readonly safe_command_path="/usr/sbin:/usr/bin:/sbin:/bin"
readonly env_binary="/usr/bin/env"
readonly git_binary="/usr/bin/git"
readonly id_binary="/usr/bin/id"
readonly stat_binary="/usr/bin/stat"
readonly find_binary="/usr/bin/find"
readonly awk_binary="/usr/bin/awk"
readonly grep_binary="/usr/bin/grep"
PATH="$safe_command_path"
export PATH

trusted_production_root="/opt/sub2api-gate-release"

trusted_git() {
  "$env_binary" -i \
    PATH="$safe_command_path" \
    HOME=/nonexistent \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    "$git_binary" \
      -c core.fsmonitor=false \
      -c core.hooksPath=/dev/null \
      -c core.sparseCheckout=false \
      "$@"
}

mode="${1:-check}"
case "$mode" in
  check) ;;
  *) echo "usage: $0 [check]" >&2; exit 2 ;;
esac

script_reference="$0"
script_directory="${script_reference%/*}"
if [ "$script_directory" = "$script_reference" ]; then
  script_directory='.'
fi
repo_dir="$(CDPATH= builtin cd -P -- "$script_directory/.." && builtin pwd -P)"
git_metadata_dir="$repo_dir/.git"

if [ -L "$git_metadata_dir" ] || [ ! -d "$git_metadata_dir" ]; then
  echo "release actions require an in-tree Git metadata directory" >&2
  exit 1
fi

if [ "$("$id_binary" -u)" -eq 0 ]; then
  if [ "$repo_dir" != "$trusted_production_root" ]; then
    echo "root release actions require the fixed trusted production tree" >&2
    exit 1
  fi

  for trusted_directory in / /opt "$trusted_production_root"; do
    if [ -L "$trusted_directory" ] || [ ! -d "$trusted_directory" ]; then
      echo "trusted production release directory boundary is unsafe" >&2
      exit 1
    fi
    owner="$("$stat_binary" -c '%u' -- "$trusted_directory")" || {
      echo "trusted production release directory boundary is unavailable" >&2
      exit 1
    }
    mode_bits="$("$stat_binary" -c '%a' -- "$trusted_directory")" || {
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
    "$find_binary" "$trusted_production_root" -xdev \
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

  if "$awk_binary" -v root="$trusted_production_root" '
    $5 == root || index($5, root "/") == 1 { found = 1 }
    END { exit(found ? 0 : 1) }
  ' /proc/self/mountinfo; then
    echo "trusted production release tree must not contain a mount boundary" >&2
    exit 1
  fi
fi

if ! trusted_git -C "$repo_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release actions require a Git worktree" >&2
  exit 1
fi
git_top_level="$(trusted_git -C "$repo_dir" rev-parse --show-toplevel)" || {
  echo "release actions require a Git worktree" >&2
  exit 1
}
git_directory="$(trusted_git -C "$repo_dir" rev-parse --absolute-git-dir)" || {
  echo "release actions require a Git worktree" >&2
  exit 1
}
if [ "$git_top_level" != "$repo_dir" ] || [ "$git_directory" != "$git_metadata_dir" ]; then
  echo "release actions require an in-tree Git metadata directory" >&2
  exit 1
fi

set +e
trusted_git -C "$repo_dir" ls-files -v -z | "$grep_binary" -z -qv '^H '
index_flag_status=("${PIPESTATUS[@]}")
set -e
if [ "${index_flag_status[1]}" -eq 0 ]; then
  echo "release action refused because the Git index has nonstandard trust flags" >&2
  exit 1
fi
if [ "${index_flag_status[0]}" -ne 0 ] || [ "${index_flag_status[1]}" -ne 1 ]; then
  echo "release action could not verify Git index trust flags" >&2
  exit 1
fi
if [ -n "$(trusted_git -C "$repo_dir" status --porcelain=v1 --untracked-files=all)" ]; then
  echo "release action refused because the Git worktree is dirty" >&2
  exit 1
fi

echo "clean Git worktree verified"
