#!/usr/bin/env bash
set -eu

mode="${1:-check}"
if [ "$#" -gt 0 ]; then
  shift
fi

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
default_deploy_root="/home/ubuntu/sub2api-deploy"
deploy_root="${SUB2API_DEPLOY_ROOT:-$default_deploy_root}"
allowed_deploy_roots="${SUB2API_CLEANUP_ALLOWED_DEPLOY_ROOTS:-$default_deploy_root}"
data_dir="${SUB2API_DEPLOY_DATA_DIR:-$deploy_root/data}"
nginx_log_dir="${SUB2API_NGINX_LOG_DIR:-/var/log/nginx}"
test_root="${SUB2API_CLEANUP_TEST_ROOT:-}"
legacy_container=""
stage="cleanup"
docker_bin="${SUB2API_CLEANUP_DOCKER_BIN:-/usr/bin/docker}"
docker_socket="${SUB2API_CLEANUP_DOCKER_SOCKET:-/var/run/docker.sock}"

if [ -n "$test_root" ]; then
  default_legacy_record="$test_root/legacy-container-log.record"
else
  default_legacy_record="/run/sub2api-gate/legacy-container-log.record"
fi
legacy_record="${SUB2API_LEGACY_LOG_RECORD:-$default_legacy_record}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --legacy-container)
      shift
      [ "$#" -gt 0 ] || {
        echo "--legacy-container requires a name" >&2
        exit 2
      }
      legacy_container="$1"
      ;;
    --stage)
      shift
      [ "$#" -gt 0 ] || {
        echo "--stage requires record or cleanup" >&2
        exit 2
      }
      stage="$1"
      ;;
    *)
      echo "usage: $0 [check|--apply|verify] [--stage record|cleanup] [--legacy-container NAME]" >&2
      exit 2
      ;;
  esac
  shift
done

case "$mode" in
  check|--apply|verify) ;;
  *)
    echo "usage: $0 [check|--apply|verify] [--stage record|cleanup] [--legacy-container NAME]" >&2
    exit 2
    ;;
esac
case "$stage" in
  record|cleanup) ;;
  *)
    echo "--stage must be record or cleanup" >&2
    exit 2
    ;;
esac
if [ "$mode" != "--apply" ] && [ "$stage" != "cleanup" ]; then
  echo "record stage requires explicit --apply" >&2
  exit 2
fi

if [ ! -d "$data_dir" ]; then
  echo "deployment data directory is unavailable" >&2
  exit 1
fi

validate_container_name() {
  [ "${#1}" -le 128 ] \
    && [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
}

if [ "$mode" != "check" ] && ! validate_container_name "$legacy_container"; then
  echo "an explicit valid legacy container name is required" >&2
  exit 2
fi

reject_broad_root() {
  label="$1"
  path="$2"
  resolved="$(realpath -e -- "$path")"
  case "$resolved" in
    /|/home|/home/ubuntu|/var|/var/log)
      echo "$label is too broad for log cleanup" >&2
      exit 1
      ;;
  esac
}

require_exact_target() {
  label="$1"
  path="$2"
  expected="$3"
  resolved="$(realpath -e -- "$path")"
  reject_broad_root "$label" "$resolved"
  if [ "$resolved" != "$expected" ]; then
    echo "$label does not resolve to its approved location" >&2
    exit 1
  fi
}

require_allowed_deploy_root() {
  selected_root="$1"
  matched=0
  old_ifs="$IFS"
  IFS=':'
  for allowed_root in $allowed_deploy_roots; do
    [ -n "$allowed_root" ] || continue
    if [ ! -d "$allowed_root" ]; then
      echo "an allowed deployment root does not exist" >&2
      exit 1
    fi
    allowed_resolved="$(realpath -e -- "$allowed_root")"
    case "$allowed_resolved" in
      /etc|/etc/*|/usr|/usr/*|/tmp|/tmp/*|/var/log|/var/log/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*)
        echo "an allowed deployment root is a protected system path" >&2
        exit 1
        ;;
    esac
    if [ "$selected_root" = "$allowed_resolved" ]; then
      matched=1
    fi
  done
  IFS="$old_ifs"
  if [ "$matched" -ne 1 ]; then
    echo "deployment root is not approved for log cleanup" >&2
    exit 1
  fi
}

validate_cleanup_targets() {
  if [ -n "$test_root" ]; then
    test_resolved="$(realpath -e -- "$test_root")"
    case "$test_resolved" in
      /tmp/*) ;;
      *)
        echo "SUB2API_CLEANUP_TEST_ROOT must resolve below /tmp" >&2
        exit 1
        ;;
    esac
    require_exact_target "data directory" "$data_dir" "$test_resolved/data"
    if [ -d "$nginx_log_dir" ]; then
      require_exact_target "Nginx log directory" "$nginx_log_dir" "$test_resolved/nginx"
    fi
    return
  fi

  deploy_resolved="$(realpath -e -- "$deploy_root")"
  reject_broad_root "deployment root" "$deploy_resolved"
  require_allowed_deploy_root "$deploy_resolved"
  require_exact_target "data directory" "$data_dir" "$deploy_resolved/data"
  if [ -d "$nginx_log_dir" ]; then
    require_exact_target "Nginx log directory" "$nginx_log_dir" "/var/log/nginx"
  fi
}

expected_record_owner() {
  if [ -n "$test_root" ]; then
    printf '%s:%s\n' "$(id -u)" "$(id -g)"
  else
    printf '%s\n' '0:0'
  fi
}

expected_log_owner() {
  if [ -n "$test_root" ]; then
    id -u
  else
    printf '%s\n' '0'
  fi
}

validate_record_location() {
  record_parent="$(dirname -- "$legacy_record")"
  if [ ! -d "$record_parent" ] || [ -L "$record_parent" ]; then
    echo "legacy Docker log record directory is unavailable" >&2
    exit 1
  fi
  record_parent_resolved="$(realpath -e -- "$record_parent")"
  if [ -n "$test_root" ]; then
    expected_record="$test_resolved/legacy-container-log.record"
  else
    expected_record="/run/sub2api-gate/legacy-container-log.record"
    if [ "$record_parent_resolved" != "/run/sub2api-gate" ]; then
      echo "legacy Docker log record must remain below the approved runtime directory" >&2
      exit 1
    fi
  fi
  if [ "$record_parent_resolved/$(basename -- "$legacy_record")" != "$expected_record" ]; then
    echo "legacy Docker log record location is not approved" >&2
    exit 1
  fi
  parent_metadata="$(stat -c '%u:%g:%a' -- "$record_parent_resolved")"
  if [ "$parent_metadata" != "$(expected_record_owner):700" ]; then
    echo "legacy Docker log record directory permissions are unsafe" >&2
    exit 1
  fi
}

validate_docker_boundary() {
  if [ -n "$test_root" ]; then
    case "$docker_bin" in
      "$test_resolved"/*) ;;
      *)
        echo "test Docker client must remain below SUB2API_CLEANUP_TEST_ROOT" >&2
        exit 1
        ;;
    esac
    case "$docker_socket" in
      "$test_resolved"/*) ;;
      *)
        echo "test Docker socket must remain below SUB2API_CLEANUP_TEST_ROOT" >&2
        exit 1
        ;;
    esac
  else
    if [ "$docker_bin" != "/usr/bin/docker" ] \
      || [ "$docker_socket" != "/var/run/docker.sock" ]; then
      echo "cleanup must use the trusted local Docker client and socket" >&2
      exit 1
    fi
  fi
  if [ ! -x "$docker_bin" ] \
    || { [ -z "$test_root" ] && { [ ! -S "$docker_socket" ] || [ -L "$docker_socket" ]; }; }; then
    echo "trusted local Docker access is unavailable" >&2
    exit 1
  fi
}

run_docker() {
  env \
    -u DOCKER_HOST \
    -u DOCKER_CONTEXT \
    -u DOCKER_CONFIG \
    -u DOCKER_CERT_PATH \
    -u DOCKER_TLS_VERIFY \
    "$docker_bin" --host "unix://$docker_socket" "$@"
}

validate_record_value() {
  [ -n "$1" ] && [[ "$1" =~ ^[A-Za-z0-9_./:-]+$ ]]
}

validate_log_path_shape() {
  record_docker_root="$1"
  record_container_id="$2"
  record_log_driver="$3"
  record_log_path="$4"
  [[ "$record_container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  case "$record_log_driver" in
    json-file)
      expected_log_path="$record_docker_root/containers/$record_container_id/$record_container_id-json.log"
      ;;
    local)
      expected_log_path="$record_docker_root/containers/$record_container_id/local-logs/container.log"
      ;;
    *) return 1 ;;
  esac
  [ "$record_log_path" = "$expected_log_path" ]
}

record_legacy_log_path() {
  if [ -e "$legacy_record" ] || [ -L "$legacy_record" ]; then
    echo "legacy Docker log record already exists" >&2
    exit 1
  fi
  if ! inspected_name="$(run_docker container inspect --format '{{.Name}}' "$legacy_container" 2>/dev/null)" \
    || [ "$inspected_name" != "/$legacy_container" ]; then
    echo "legacy container could not be identified exactly" >&2
    exit 1
  fi
  if ! container_id="$(run_docker container inspect --format '{{.Id}}' "$legacy_container" 2>/dev/null)" \
    || ! container_running="$(run_docker container inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null)" \
    || ! log_driver="$(run_docker container inspect --format '{{.HostConfig.LogConfig.Type}}' "$container_id" 2>/dev/null)" \
    || ! log_path="$(run_docker container inspect --format '{{.LogPath}}' "$container_id" 2>/dev/null)" \
    || ! docker_root="$(run_docker info --format '{{.DockerRootDir}}' 2>/dev/null)" \
    || ! daemon_id="$(run_docker info --format '{{.ID}}' 2>/dev/null)"; then
    echo "legacy Docker log metadata could not be inspected" >&2
    exit 1
  fi
  if [ "$container_running" != "false" ]; then
    echo "legacy container must be stopped before recording Docker LogPath evidence" >&2
    exit 1
  fi
  for record_value in "$container_id" "$log_driver" "$log_path" "$docker_root" "$daemon_id"; do
    if ! validate_record_value "$record_value"; then
      echo "legacy Docker log metadata is invalid" >&2
      exit 1
    fi
  done
  docker_root="$(realpath -e -- "$docker_root")"
  if ! validate_log_path_shape "$docker_root" "$container_id" "$log_driver" "$log_path" \
    || [ ! -f "$log_path" ] \
    || [ -L "$log_path" ] \
    || [ "$(realpath -e -- "$log_path")" != "$log_path" ] \
    || [ "$(stat -c '%u' -- "$log_path")" != "$(expected_log_owner)" ]; then
    echo "legacy Docker LogPath failed validation" >&2
    exit 1
  fi

  umask 077
  temporary_record="$record_parent_resolved/.legacy-container-log.$$"
  (set -C; : > "$temporary_record") 2>/dev/null || {
    echo "legacy Docker log record could not be created" >&2
    exit 1
  }
  cleanup_record_temp() {
    find "$record_parent_resolved" -maxdepth 1 -type f \
      -name ".legacy-container-log.$$" -delete 2>/dev/null || true
  }
  trap cleanup_record_temp EXIT
  trap 'cleanup_record_temp; exit 130' HUP INT TERM
  {
    printf 'version=1\n'
    printf 'container_name=%s\n' "$legacy_container"
    printf 'container_id=%s\n' "$container_id"
    printf 'log_driver=%s\n' "$log_driver"
    printf 'log_path=%s\n' "$log_path"
    printf 'docker_root=%s\n' "$docker_root"
    printf 'daemon_id=%s\n' "$daemon_id"
  } > "$temporary_record"
  chmod 0600 "$temporary_record"
  mv -T -- "$temporary_record" "$legacy_record"
  sync -f "$record_parent_resolved"
  trap - EXIT HUP INT TERM
  echo "legacy Docker LogPath evidence recorded; remove the container before cleanup"
}

read_legacy_record() {
  if [ ! -f "$legacy_record" ] || [ -L "$legacy_record" ]; then
    echo "legacy Docker log record is missing or unsafe" >&2
    exit 1
  fi
  record_metadata="$(stat -c '%u:%g:%a' -- "$legacy_record")"
  if [ "$record_metadata" != "$(expected_record_owner):600" ]; then
    echo "legacy Docker log record permissions are unsafe" >&2
    exit 1
  fi
  exec 9< "$legacy_record"
  IFS= read -r record_version <&9 || true
  IFS= read -r record_name <&9 || true
  IFS= read -r record_id <&9 || true
  IFS= read -r record_driver <&9 || true
  IFS= read -r record_path <&9 || true
  IFS= read -r record_root <&9 || true
  IFS= read -r record_daemon <&9 || true
  IFS= read -r unexpected_record_data <&9 || true
  exec 9<&-
  [ "$record_version" = "version=1" ] \
    && [ "$record_name" = "container_name=$legacy_container" ] \
    && [ -z "$unexpected_record_data" ] || {
      echo "legacy Docker log record does not match the requested container" >&2
      exit 1
    }
  case "$record_id|$record_driver|$record_path|$record_root|$record_daemon" in
    container_id=*\|log_driver=*\|log_path=*\|docker_root=*\|daemon_id=*) ;;
    *)
      echo "legacy Docker log record is invalid" >&2
      exit 1
      ;;
  esac
  record_id="${record_id#container_id=}"
  record_driver="${record_driver#log_driver=}"
  record_path="${record_path#log_path=}"
  record_root="${record_root#docker_root=}"
  record_daemon="${record_daemon#daemon_id=}"
  for record_value in "$record_id" "$record_driver" "$record_path" "$record_root" "$record_daemon"; do
    if ! validate_record_value "$record_value"; then
      echo "legacy Docker log record is invalid" >&2
      exit 1
    fi
  done
  if ! validate_log_path_shape "$record_root" "$record_id" "$record_driver" "$record_path"; then
    echo "legacy Docker log record is invalid" >&2
    exit 1
  fi
}

verify_legacy_container_removed() {
  read_legacy_record
  if ! current_daemon="$(run_docker info --format '{{.ID}}' 2>/dev/null)" \
    || ! current_root="$(run_docker info --format '{{.DockerRootDir}}' 2>/dev/null)"; then
    echo "local Docker daemon could not be verified" >&2
    exit 1
  fi
  current_root="$(realpath -e -- "$current_root")"
  if [ "$current_daemon" != "$record_daemon" ] || [ "$current_root" != "$record_root" ]; then
    echo "local Docker daemon does not match the recorded evidence" >&2
    exit 1
  fi
  if run_docker container inspect "$legacy_container" >/dev/null 2>&1 \
    || run_docker container inspect "$record_id" >/dev/null 2>&1; then
    echo "legacy container still exists" >&2
    exit 1
  fi
  if [ -e "$record_path" ] || [ -L "$record_path" ]; then
    echo "recorded legacy Docker LogPath still exists" >&2
    exit 1
  fi
  record_container_directory="$record_root/containers/$record_id"
  if [ -e "$record_container_directory" ] || [ -L "$record_container_directory" ]; then
    echo "recorded legacy Docker container log directory still exists" >&2
    exit 1
  fi
}

conversation_logs_exist() {
  if [ -n "$(find "$data_dir" -type f \
    \( -name 'sub2api-response-preview.log*' \
    -o -name 'sub2api-response-debug.log*' \
    -o -path '*/logs/sub2api*.log*' \) \
    -print -quit)" ]; then
    return 0
  fi
  if [ -d "$nginx_log_dir" ] && [ -n "$(find "$nginx_log_dir" -type f \
    \( -name 'sub2api-response.log*' \
    -o -name 'sub2api-capture.log*' \
    -o -name '*response-preview*' \) \
    -print -quit)" ]; then
    return 0
  fi
  return 1
}

if [ "$mode" = "check" ]; then
  if conversation_logs_exist; then
    echo "conversation-capable log files were found"
  else
    echo "no conversation-capable log files found"
  fi
  echo "check only; no file was deleted and Docker was not accessed"
  exit 0
fi

validate_cleanup_targets
validate_record_location
validate_docker_boundary

if [ "$mode" = "--apply" ] && [ "$stage" = "record" ]; then
  if [ -z "$test_root" ]; then
    "$repo_dir/deploy/require-clean-worktree.sh" check
  fi
  record_legacy_log_path
  exit 0
fi

verify_legacy_container_removed

if [ "$mode" = "verify" ]; then
  if conversation_logs_exist; then
    echo "conversation-capable log files still exist" >&2
    exit 1
  fi
  echo "legacy container, Docker LogPath, and conversation-capable logs are absent"
  exit 0
fi

if [ -z "$test_root" ]; then
  "$repo_dir/deploy/require-clean-worktree.sh" check
fi

recheck_seconds="${SUB2API_LOG_RECHECK_SECONDS:-2}"
case "$recheck_seconds" in
  *[!0-9]*|"")
    echo "SUB2API_LOG_RECHECK_SECONDS must be an integer" >&2
    exit 1
    ;;
esac
if [ "$recheck_seconds" -gt 60 ]; then
  echo "SUB2API_LOG_RECHECK_SECONDS must not exceed 60" >&2
  exit 1
fi

find "$data_dir" -type f \
  \( -name 'sub2api-response-preview.log*' \
  -o -name 'sub2api-response-debug.log*' \
  -o -path '*/logs/sub2api*.log*' \) \
  -delete

if [ -d "$nginx_log_dir" ]; then
  find "$nginx_log_dir" -type f \
    \( -name 'sub2api-response.log*' \
    -o -name 'sub2api-capture.log*' \
    -o -name '*response-preview*' \) \
    -delete
fi

sleep "$recheck_seconds"
verify_legacy_container_removed
if conversation_logs_exist; then
  echo "conversation-capable log files were recreated after cleanup" >&2
  exit 1
fi

echo "legacy Docker log removal and conversation-capable log cleanup passed"
