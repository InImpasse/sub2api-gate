#!/bin/bash
set -euo pipefail

test_mode="${SUB2API_AOP_TEST_MODE:-0}"
case "$test_mode" in
  0|1) ;;
  *) echo "SUB2API_AOP_TEST_MODE must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$test_mode" = "1" ] && [ "$EUID" -eq 0 ]; then
  echo "test mode may not run as root" >&2
  exit 1
fi

if [ "$test_mode" = "0" ]; then
  PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  export PATH
fi

if [ "$test_mode" = "1" ]; then
  env_bin="$(command -v env)"
  openssl_bin="$(command -v openssl)"
else
  env_bin="/usr/bin/env"
  openssl_bin="/usr/bin/openssl"
fi
if [ ! -x "$env_bin" ] || [ ! -x "$openssl_bin" ]; then
  echo "env or openssl executable is unavailable" >&2
  exit 1
fi

mode="${1:-check}"
if [ "$mode" = "check" ] || [ "$mode" = "--apply" ]; then
  shift || true
else
  echo "usage: $0 [check|--apply] [--stage optional|probe|required] [--hostname HOST] [--ca-file PATH]" >&2
  exit 2
fi

stage="optional"
ca_file=""
hostname=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stage)
      [ "$#" -ge 2 ] || { echo "--stage requires a value" >&2; exit 2; }
      stage="$2"
      shift 2
      ;;
    --ca-file)
      [ "$#" -ge 2 ] || { echo "--ca-file requires a value" >&2; exit 2; }
      ca_file="$2"
      shift 2
      ;;
    --hostname)
      [ "$#" -ge 2 ] || { echo "--hostname requires a value" >&2; exit 2; }
      hostname="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$stage" in
  optional|probe|required) ;;
  *) echo "stage must be optional, probe, or required" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
source_optional="$repo_dir/nginx/snippets/sub2api-aop-optional.conf"
source_required="$repo_dir/nginx/snippets/sub2api-aop-required.conf"
source_active=""
if [ "$stage" != "probe" ]; then
  source_active="$repo_dir/nginx/snippets/sub2api-aop-$stage.conf"
fi

nginx_root="${SUB2API_NGINX_ROOT:-/etc/nginx}"
if [ "$test_mode" = "1" ]; then
  canonical_nginx_root="$(/usr/bin/realpath -m -- "$nginx_root")" || {
    echo "could not resolve the Nginx root" >&2
    exit 1
  }
  production_nginx_root="$(/usr/bin/realpath -m -- /etc/nginx)" || {
    echo "could not resolve the production Nginx root" >&2
    exit 1
  }
  if [ "$canonical_nginx_root" = "$production_nginx_root" ]; then
    echo "test mode may not target the production Nginx root" >&2
    exit 1
  fi
fi
if [ "$nginx_root" != "/etc/nginx" ] && [ "$test_mode" != "1" ]; then
  echo "SUB2API_NGINX_ROOT override is allowed only in explicit test mode" >&2
  exit 1
fi
case "$nginx_root" in
  /*) ;;
  *) echo "Nginx root must be an absolute path" >&2; exit 1 ;;
esac
if [ "$nginx_root" = "/" ]; then
  echo "refusing to use the filesystem root as the Nginx root" >&2
  exit 1
fi

snippets_dir="$nginx_root/snippets"
state_root="$nginx_root/sub2api-gate"
aop_dir="$nginx_root/sub2api-gate/aop"
backup_root="$nginx_root/sub2api-gate/backups"
operation_lock="$state_root/nginx-operation.lock"
dest_optional="$snippets_dir/sub2api-aop-optional.conf"
dest_required="$snippets_dir/sub2api-aop-required.conf"
dest_active="$snippets_dir/sub2api-aop-active.conf"
dest_ca="$aop_dir/client-ca.pem"
install_state="$aop_dir/install-state"

runtime_root="${SUB2API_AOP_RUNTIME_ROOT:-/run/sub2api-gate}"
if [ "$test_mode" = "1" ] && [ "$runtime_root" = "/run/sub2api-gate" ]; then
  echo "test mode must use an isolated AOP runtime root" >&2
  exit 1
fi
if [ "$test_mode" != "1" ] && [ "$runtime_root" != "/run/sub2api-gate" ]; then
  echo "SUB2API_AOP_RUNTIME_ROOT override is allowed only in explicit test mode" >&2
  exit 1
fi
case "$runtime_root" in
  /*) ;;
  *) echo "AOP runtime root must be an absolute path" >&2; exit 1 ;;
esac
if [ "$runtime_root" = "/" ]; then
  echo "refusing to use the filesystem root as the AOP runtime root" >&2
  exit 1
fi
proof_file="$runtime_root/aop-proof"
proof_ttl_seconds=300
probe_path="/.well-known/sub2api-aop-probe"

expected_uid="$(id -u)"
if [ "$test_mode" != "1" ]; then
  expected_uid=0
fi

require_trusted_directory() {
  local path="$1"
  local label="$2"
  local resolved_path path_uid path_mode_text path_mode
  if [ ! -d "$path" ] || [ -L "$path" ]; then
    echo "$label is missing or unsafe" >&2
    return 1
  fi
  resolved_path="$(realpath -e -- "$path")" || {
    echo "$label could not be resolved" >&2
    return 1
  }
  if [ "$resolved_path" != "$path" ]; then
    echo "$label must not traverse symlinks" >&2
    return 1
  fi
  path_uid="$(stat -c '%u' -- "$path")" || return 1
  path_mode_text="$(stat -c '%a' -- "$path")" || return 1
  path_mode=$((8#$path_mode_text))
  if [ "$path_uid" -ne "$expected_uid" ] || ((path_mode & 0022)); then
    echo "$label has unsafe ownership or permissions" >&2
    return 1
  fi
}

require_trusted_directory_if_present() {
  local path="$1"
  local label="$2"
  if [ -e "$path" ] || [ -L "$path" ]; then
    require_trusted_directory "$path" "$label"
  fi
}

require_private_directory() {
  local path="$1" label="$2" path_mode_text path_mode
  require_trusted_directory "$path" "$label" || return 1
  path_mode_text="$(stat -c '%a' -- "$path")" || return 1
  path_mode=$((8#$path_mode_text))
  if ((path_mode & 0077)); then
    echo "$label must be owner-only" >&2
    return 1
  fi
}

ensure_trusted_directory() {
  local path="$1"
  local label="$2"
  local create_mode="$3"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    if ! mkdir -m "$create_mode" -- "$path"; then
      [ -e "$path" ] || [ -L "$path" ] || {
        echo "$label could not be created" >&2
        return 1
      }
    fi
  fi
  require_trusted_directory "$path" "$label"
}

require_trusted_file_if_present() {
  local path="$1"
  local label="$2"
  local path_uid path_mode_text path_mode
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    return 0
  fi
  if [ -L "$path" ] || [ ! -f "$path" ]; then
    echo "$label must be a regular non-symlink file" >&2
    return 1
  fi
  path_uid="$(stat -c '%u' -- "$path")" || return 1
  path_mode_text="$(stat -c '%a' -- "$path")" || return 1
  path_mode=$((8#$path_mode_text))
  if [ "$path_uid" -ne "$expected_uid" ] || ((path_mode & 0022)); then
    echo "$label has unsafe ownership or permissions" >&2
    return 1
  fi
}

require_private_file_if_present() {
  local path="$1"
  local label="$2"
  local path_mode_text path_mode path_links
  require_trusted_file_if_present "$path" "$label"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    return 0
  fi
  path_mode_text="$(stat -c '%a' -- "$path")" || return 1
  path_mode=$((8#$path_mode_text))
  path_links="$(stat -c '%h' -- "$path")" || return 1
  if ((path_mode & 0077)) || [ "$path_links" -ne 1 ]; then
    echo "$label must be owner-only and have exactly one link" >&2
    return 1
  fi
}

validate_apply_paths() {
  require_trusted_directory "$nginx_parent" "Nginx root parent"
  require_trusted_directory "$nginx_root" "Nginx root"
  require_trusted_directory_if_present "$snippets_dir" "Nginx snippets directory"
  require_trusted_directory_if_present "$state_root" "Nginx state directory"
  require_trusted_directory_if_present "$aop_dir" "Nginx AOP directory"
  require_trusted_directory_if_present "$backup_root" "Nginx backup directory"
  require_trusted_file_if_present "$operation_lock" "Nginx operation lock"
  require_trusted_file_if_present "$dest_optional" "managed optional AOP snippet"
  require_trusted_file_if_present "$dest_required" "managed required AOP snippet"
  require_trusted_file_if_present "$dest_active" "managed active AOP snippet"
  require_trusted_file_if_present "$dest_ca" "managed AOP CA"
  require_private_file_if_present "$install_state" "managed AOP install state"
}

acquire_operation_lock() {
  local lock_path_identity lock_fd_identity
  require_trusted_file_if_present "$operation_lock" "Nginx operation lock"
  exec {nginx_lock_fd}>>"$operation_lock" || {
    echo "could not open the shared Nginx operation lock" >&2
    return 1
  }
  require_trusted_file_if_present "$operation_lock" "Nginx operation lock"
  lock_path_identity="$(stat -Lc '%d:%i' -- "$operation_lock")" || return 1
  lock_fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$nginx_lock_fd")" || return 1
  if [ "$lock_path_identity" != "$lock_fd_identity" ]; then
    echo "Nginx operation lock changed while it was opened" >&2
    return 1
  fi
  if ! "$flock_bin" -n "$nginx_lock_fd"; then
    echo "another Nginx apply operation is already in progress" >&2
    return 1
  fi
}

validate_hostname() {
  local candidate="$1"
  local label
  local -a labels
  if [ -z "$candidate" ] || [ "${#candidate}" -gt 253 ] \
      || [ "$candidate" != "${candidate,,}" ] || [[ "$candidate" != *.* ]] \
      || [[ "$candidate" == .* ]] || [[ "$candidate" == *. ]] \
      || [[ "$candidate" == *..* ]]; then
    echo "AOP hostname must be a canonical lowercase DNS hostname" >&2
    return 1
  fi
  IFS='.' read -r -a labels <<< "$candidate"
  for label in "${labels[@]}"; do
    if [ "${#label}" -gt 63 ] \
        || [[ ! "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
      echo "AOP hostname must be a canonical lowercase DNS hostname" >&2
      return 1
    fi
  done
  label="${labels[${#labels[@]} - 1]}"
  if [[ ! "$label" =~ [a-z] ]]; then
    echo "AOP hostname must not be an IP address or use a numeric-only TLD" >&2
    return 1
  fi
}

current_epoch() {
  local value
  if [ "$test_mode" = "1" ] && [ -n "${SUB2API_AOP_TEST_NOW:-}" ]; then
    value="$SUB2API_AOP_TEST_NOW"
  else
    value="$(date -u +%s)"
  fi
  [[ "$value" =~ ^[0-9]+$ ]] || {
    echo "could not determine a valid AOP proof timestamp" >&2
    return 1
  }
  printf '%s\n' "$value"
}

current_uptime() {
  local value remainder
  if [ "$test_mode" = "1" ] && [ -n "${SUB2API_AOP_TEST_UPTIME:-}" ]; then
    value="$SUB2API_AOP_TEST_UPTIME"
  else
    read -r value remainder < /proc/uptime || {
      echo "could not read host uptime for AOP proof" >&2
      return 1
    }
    value="${value%%.*}"
  fi
  [[ "$value" =~ ^[0-9]+$ ]] || {
    echo "could not determine a valid host uptime for AOP proof" >&2
    return 1
  }
  printf '%s\n' "$value"
}

current_boot_id() {
  local value
  if [ "$test_mode" = "1" ] && [ -n "${SUB2API_AOP_TEST_BOOT_ID:-}" ]; then
    value="$SUB2API_AOP_TEST_BOOT_ID"
  else
    IFS= read -r value < /proc/sys/kernel/random/boot_id || {
      echo "could not read host boot identity for AOP proof" >&2
      return 1
    }
  fi
  [[ "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
    echo "could not determine a valid host boot identity for AOP proof" >&2
    return 1
  }
  printf '%s\n' "$value"
}

certificate_sha256() {
  local certificate="$1"
  local fingerprint
  fingerprint="$("$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C \
    "$openssl_bin" x509 -in "$certificate" -noout -fingerprint -sha256 2>/dev/null \
    | sed -E 's/^[^=]+=//; s/://g' | tr 'A-F' 'a-f')" || return 1
  [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || {
    echo "could not calculate the AOP CA fingerprint" >&2
    return 1
  }
  printf '%s\n' "$fingerprint"
}

file_sha256() {
  local path="$1"
  local digest
  digest="$(sha256sum -- "$path" | awk '{print $1}')" || return 1
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "could not calculate an AOP configuration fingerprint" >&2
    return 1
  }
  printf '%s\n' "$digest"
}

load_install_state() {
  local line key value seen="," state_size
  state_version=""
  state_stage=""
  state_hostname=""
  state_ca_sha256=""
  state_active_sha256=""
  state_generation=""
  state_installed_at_epoch=""
  if [ ! -f "$install_state" ] || [ -L "$install_state" ]; then
    echo "AOP optional install state is missing or unsafe" >&2
    return 1
  fi
  require_private_file_if_present "$install_state" "managed AOP install state" || return 1
  state_size="$(stat -c '%s' -- "$install_state")" || return 1
  if [ "$state_size" -gt 4096 ]; then
    echo "AOP install state exceeds the 4 KiB limit" >&2
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *=*) key="${line%%=*}"; value="${line#*=}" ;;
      *) echo "AOP install state has an invalid schema" >&2; return 1 ;;
    esac
    case "$seen" in
      *",$key,"*) echo "AOP install state has duplicate fields" >&2; return 1 ;;
    esac
    seen="$seen$key,"
    case "$key" in
      version) state_version="$value" ;;
      stage) state_stage="$value" ;;
      hostname) state_hostname="$value" ;;
      ca_sha256) state_ca_sha256="$value" ;;
      active_sha256) state_active_sha256="$value" ;;
      generation) state_generation="$value" ;;
      installed_at_epoch) state_installed_at_epoch="$value" ;;
      *) echo "AOP install state has unknown fields" >&2; return 1 ;;
    esac
  done < "$install_state"
  if [ "$state_version" != "1" ] \
      || { [ "$state_stage" != "optional" ] && [ "$state_stage" != "required" ]; } \
      || ! validate_hostname "$state_hostname" \
      || [[ ! "$state_ca_sha256" =~ ^[0-9a-f]{64}$ ]] \
      || [[ ! "$state_active_sha256" =~ ^[0-9a-f]{64}$ ]] \
      || [[ ! "$state_generation" =~ ^[0-9a-f]{64}$ ]] \
      || [[ ! "$state_installed_at_epoch" =~ ^[0-9]+$ ]] \
      || [ "${#state_installed_at_epoch}" -gt 12 ]; then
    echo "AOP install state has invalid values" >&2
    return 1
  fi
}

load_probe_proof() {
  local line key value seen="," proof_size
  proof_version=""
  proof_hostname=""
  proof_ca_sha256=""
  proof_optional_sha256=""
  proof_generation=""
  proof_boot_id=""
  proof_epoch=""
  proof_uptime=""
  if [ ! -f "$proof_file" ] || [ -L "$proof_file" ]; then
    echo "fresh AOP public probe proof is missing" >&2
    return 1
  fi
  require_private_file_if_present "$proof_file" "AOP public probe proof" || return 1
  proof_size="$(stat -c '%s' -- "$proof_file")" || return 1
  if [ "$proof_size" -gt 4096 ]; then
    echo "AOP public probe proof exceeds the 4 KiB limit" >&2
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      *=*) key="${line%%=*}"; value="${line#*=}" ;;
      *) echo "AOP public probe proof has an invalid schema" >&2; return 1 ;;
    esac
    case "$seen" in
      *",$key,"*) echo "AOP public probe proof has duplicate fields" >&2; return 1 ;;
    esac
    seen="$seen$key,"
    case "$key" in
      version) proof_version="$value" ;;
      hostname) proof_hostname="$value" ;;
      ca_sha256) proof_ca_sha256="$value" ;;
      optional_sha256) proof_optional_sha256="$value" ;;
      generation) proof_generation="$value" ;;
      boot_id) proof_boot_id="$value" ;;
      probed_at_epoch) proof_epoch="$value" ;;
      probed_at_uptime) proof_uptime="$value" ;;
      *) echo "AOP public probe proof has unknown fields" >&2; return 1 ;;
    esac
  done < "$proof_file"
  if [ "$proof_version" != "1" ] \
      || ! validate_hostname "$proof_hostname" \
      || [[ ! "$proof_ca_sha256" =~ ^[0-9a-f]{64}$ ]] \
      || [[ ! "$proof_optional_sha256" =~ ^[0-9a-f]{64}$ ]] \
      || [[ ! "$proof_generation" =~ ^[0-9a-f]{64}$ ]] \
      || [[ ! "$proof_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
      || [[ ! "$proof_epoch" =~ ^[0-9]+$ ]] \
      || [[ ! "$proof_uptime" =~ ^[0-9]+$ ]] \
      || [ "${#proof_epoch}" -gt 12 ] || [ "${#proof_uptime}" -gt 12 ]; then
    echo "AOP public probe proof has invalid values" >&2
    return 1
  fi
}

write_install_state() {
  local target_stage="$1" target_hostname="$2" ca_hash="$3" active_hash="$4"
  local generation="$5" installed_epoch="$6" temp_file
  temp_file="$(mktemp "$aop_dir/.install-state.tmp.XXXXXX")"
  if ! chmod 0600 "$temp_file" \
      || ! printf '%s\n' \
        "version=1" \
        "stage=$target_stage" \
        "hostname=$target_hostname" \
        "ca_sha256=$ca_hash" \
        "active_sha256=$active_hash" \
        "generation=$generation" \
        "installed_at_epoch=$installed_epoch" > "$temp_file" \
      || ! mv -f -- "$temp_file" "$install_state"; then
    rm -f -- "$temp_file"
    return 1
  fi
}

write_probe_proof() {
  local proof_hostname_value="$1" ca_hash="$2" optional_hash="$3"
  local generation="$4" boot_id="$5" epoch="$6" uptime="$7" temp_file
  temp_file="$(mktemp "$runtime_root/.aop-proof.tmp.XXXXXX")"
  if ! chmod 0600 "$temp_file" \
      || ! printf '%s\n' \
        "version=1" \
        "hostname=$proof_hostname_value" \
        "ca_sha256=$ca_hash" \
        "optional_sha256=$optional_hash" \
        "generation=$generation" \
        "boot_id=$boot_id" \
        "probed_at_epoch=$epoch" \
        "probed_at_uptime=$uptime" > "$temp_file" \
      || ! mv -f -- "$temp_file" "$proof_file"; then
    rm -f -- "$temp_file"
    return 1
  fi
}

validate_optional_readiness() {
  local requested_hostname="$1" requested_ca_hash="${2:-}"
  local current_ca_hash optional_hash
  load_install_state || return 1
  if [ "$state_stage" != "optional" ] || [ "$state_hostname" != "$requested_hostname" ]; then
    echo "AOP required transition must start from optional on the same hostname" >&2
    return 1
  fi
  if [ ! -f "$dest_active" ] || [ -L "$dest_active" ] \
      || ! cmp -s -- "$source_optional" "$dest_active" \
      || ! cmp -s -- "$source_optional" "$dest_optional"; then
    echo "active AOP configuration is not the reviewed optional stage" >&2
    return 1
  fi
  validate_ca "$dest_ca" || return 1
  current_ca_hash="$(certificate_sha256 "$dest_ca")" || return 1
  optional_hash="$(file_sha256 "$source_optional")" || return 1
  if [ "$state_ca_sha256" != "$current_ca_hash" ] \
      || [ "$state_active_sha256" != "$optional_hash" ]; then
    echo "AOP optional install state no longer matches the active files" >&2
    return 1
  fi
  if [ -n "$requested_ca_hash" ] && [ "$requested_ca_hash" != "$current_ca_hash" ]; then
    echo "required AOP transition must reuse the installed CA" >&2
    return 1
  fi
  validated_ca_hash="$current_ca_hash"
  validated_optional_hash="$optional_hash"
  validated_generation="$state_generation"
}

validate_fresh_probe_proof() {
  local requested_hostname="$1" ca_hash="$2" optional_hash="$3" generation="$4"
  local boot_id now uptime
  load_probe_proof || return 1
  boot_id="$(current_boot_id)" || return 1
  now="$(current_epoch)" || return 1
  uptime="$(current_uptime)" || return 1
  if [ "$proof_hostname" != "$requested_hostname" ] \
      || [ "$proof_ca_sha256" != "$ca_hash" ] \
      || [ "$proof_optional_sha256" != "$optional_hash" ] \
      || [ "$proof_generation" != "$generation" ] \
      || [ "$proof_boot_id" != "$boot_id" ]; then
    echo "AOP public probe proof does not match the current optional stage" >&2
    return 1
  fi
  if ((proof_epoch > now || proof_uptime > uptime \
      || now - proof_epoch > proof_ttl_seconds \
      || uptime - proof_uptime > proof_ttl_seconds)); then
    echo "AOP public probe proof is expired or from an invalid clock state" >&2
    return 1
  fi
}

run_public_probe() (
  local probe_hostname="$1" nonce headers_file http_status probe_url
  if ! ulimit -f 64 2>/dev/null; then
    echo "could not bound the AOP probe response-header file" >&2
    exit 1
  fi
  nonce="$("$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C \
    "$openssl_bin" rand -hex 16 2>/dev/null)" || exit 1
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || exit 1
  headers_file="$(mktemp "$runtime_root/.probe-headers.tmp.XXXXXX")" || exit 1
  chmod 0600 "$headers_file"
  trap 'rm -f -- "$headers_file"' EXIT INT TERM HUP
  probe_url="https://${probe_hostname}${probe_path}?nonce=${nonce}"
  if ! http_status="$("$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C \
      "$curl_bin" --disable \
      --silent --show-error \
      --noproxy '*' \
      --proto '=https' \
      --proto-redir '=https' \
      --connect-timeout 5 \
      --max-time 10 \
      --max-redirs 0 \
      --request GET \
      --header 'Cache-Control: no-cache, no-store' \
      --header 'Pragma: no-cache' \
      --dump-header "$headers_file" \
      --output /dev/null \
      --write-out '%{http_code}' \
      "$probe_url" 2>/dev/null)"; then
    echo "public Cloudflare AOP HTTPS probe failed" >&2
    exit 1
  fi
  if [ "$http_status" != "204" ] \
      || ! LC_ALL=C grep -Eiq '^X-Sub2API-AOP-Verify:[[:space:]]*SUCCESS[[:space:]]*$' "$headers_file"; then
    echo "public Cloudflare AOP HTTPS probe did not confirm a verified client certificate" >&2
    exit 1
  fi
)

for source_file in "$source_optional" "$source_required"; do
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    echo "missing or unsafe tracked AOP snippet: $source_file" >&2
    exit 1
  fi
done

validate_ca() {
  local candidate="$1"
  if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then
    echo "AOP CA must be a regular, non-symlink file" >&2
    return 1
  fi
  if grep -Eq -- '-----BEGIN ([A-Z0-9 ]* )?PRIVATE KEY-----' "$candidate"; then
    echo "refusing AOP CA input that contains a private key" >&2
    return 1
  fi
  if ! LC_ALL=C awk '
      BEGIN { blocks = 0; inside = 0; bad = 0 }
      /^[[:space:]]*$/ { next }
      /^-----BEGIN CERTIFICATE-----$/ {
        if (inside || blocks != 0) bad = 1
        inside = 1
        blocks++
        next
      }
      /^-----END CERTIFICATE-----$/ {
        if (!inside) bad = 1
        inside = 0
        next
      }
      {
        if (!inside || $0 !~ /^[A-Za-z0-9+\/=]+$/) bad = 1
      }
      END { exit !(blocks == 1 && inside == 0 && bad == 0) }
    ' "$candidate"; then
    echo "AOP CA input must contain exactly one PEM certificate and no other data" >&2
    return 1
  fi
  if ! "$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C \
      "$openssl_bin" x509 -in "$candidate" -noout -checkend 2592000 \
      >/dev/null 2>&1; then
    echo "AOP CA must remain valid for at least 30 days" >&2
    return 1
  fi
  if ! "$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C \
      "$openssl_bin" x509 -in "$candidate" -noout -purpose 2>/dev/null \
      | grep -Fq 'SSL client CA : Yes'; then
    echo "AOP CA certificate is not permitted to issue TLS client certificates" >&2
    return 1
  fi
}

if [ -n "$ca_file" ]; then
  validate_ca "$ca_file"
  if [ "$test_mode" != "1" ]; then
    ca_resolved="$(realpath -e -- "$ca_file")" || {
      echo "could not resolve AOP CA input" >&2
      exit 1
    }
    if [ "$ca_resolved" != "$dest_ca" ]; then
      echo "production AOP CA must already reside at $dest_ca" >&2
      exit 1
    fi
  fi
fi

if [ -n "$hostname" ]; then
  validate_hostname "$hostname"
fi

if [ "$mode" != "--apply" ]; then
  echo "AOP check only: stage=$stage"
  echo "active snippet: $dest_active"
  echo "custom client CA: $dest_ca"
  if [ -z "$ca_file" ]; then
    echo "CA input was not supplied; production certificate readiness remains unverified."
  else
    echo "CA input is a valid public certificate."
  fi
  case "$stage" in
    optional)
      echo "optional-stage inputs were checked; installed readiness was not modified"
      ;;
    probe)
      [ -n "$hostname" ] || {
        echo "probe readiness check requires --hostname" >&2
        exit 2
      }
      if [ -n "$ca_file" ]; then
        requested_ca_hash="$(certificate_sha256 "$ca_file")"
        validate_optional_readiness "$hostname" "$requested_ca_hash"
      else
        validate_optional_readiness "$hostname"
      fi
      echo "optional-stage state is ready for a public probe"
      ;;
    required)
      [ -n "$hostname" ] && [ -n "$ca_file" ] || {
        echo "required readiness check requires --hostname and --ca-file" >&2
        exit 2
      }
      requested_ca_hash="$(certificate_sha256 "$ca_file")"
      validate_optional_readiness "$hostname" "$requested_ca_hash"
      validate_fresh_probe_proof \
        "$hostname" "$validated_ca_hash" "$validated_optional_hash" "$validated_generation"
      echo "fresh public probe proof is ready for the required transition"
      ;;
  esac
  echo "no file was changed and nginx was not reloaded"
  exit 0
fi

if [ "$test_mode" != "1" ] && [ "$(id -u)" -ne 0 ]; then
  echo "--apply must run as root" >&2
  exit 1
fi
if [ -z "$hostname" ]; then
  echo "--apply requires --hostname with the exact public Cloudflare hostname" >&2
  exit 2
fi
if [ "$stage" != "probe" ] && [ -z "$ca_file" ]; then
  echo "optional and required apply require --ca-file with the custom per-hostname CA certificate" >&2
  exit 2
fi
if [ "$test_mode" != "1" ] \
    && { [ -n "${SUB2API_AOP_TEST_NOW:-}" ] \
      || [ -n "${SUB2API_AOP_TEST_UPTIME:-}" ] \
      || [ -n "${SUB2API_AOP_TEST_BOOT_ID:-}" ]; }; then
  echo "AOP test clock overrides are forbidden outside explicit test mode" >&2
  exit 1
fi

if [ "$test_mode" = "1" ] && [ -n "${SUB2API_RELEASE_GUARD:-}" ]; then
  "$SUB2API_RELEASE_GUARD" check
else
  "$repo_dir/deploy/require-clean-worktree.sh" check
fi

if [ "$test_mode" = "1" ]; then
  nginx_bin="$(command -v nginx)"
  systemctl_bin="$(command -v systemctl)"
  flock_bin="$(command -v flock)"
  curl_bin="$(command -v curl)"
else
  nginx_bin="/usr/sbin/nginx"
  if [ -x /usr/bin/systemctl ]; then
    systemctl_bin="/usr/bin/systemctl"
  else
    systemctl_bin="/bin/systemctl"
  fi
  flock_bin="/usr/bin/flock"
  curl_bin="/usr/bin/curl"
fi
if [ ! -x "$nginx_bin" ] || [ ! -x "$systemctl_bin" ] \
    || [ ! -x "$flock_bin" ] || [ ! -x "$curl_bin" ] || [ ! -x "$env_bin" ]; then
  echo "nginx, systemctl, flock, curl, or env executable is unavailable" >&2
  exit 1
fi

umask 077
if [ "$test_mode" = "1" ]; then
  nginx_parent="$(dirname -- "$nginx_root")"
else
  nginx_parent="/etc"
fi

if [ "$stage" = "probe" ]; then
  runtime_parent="$(dirname -- "$runtime_root")"
  require_trusted_directory "$nginx_parent" "Nginx root parent"
  require_trusted_directory "$nginx_root" "Nginx root"
  require_trusted_directory "$snippets_dir" "Nginx snippets directory"
  require_trusted_directory "$state_root" "Nginx state directory"
  require_trusted_directory "$aop_dir" "Nginx AOP directory"
  validate_apply_paths
  acquire_operation_lock
  require_trusted_directory "$runtime_parent" "AOP runtime parent"
  ensure_trusted_directory "$runtime_root" "AOP runtime directory" 0700
  require_private_directory "$runtime_root" "AOP runtime directory"
  require_private_file_if_present "$proof_file" "AOP public probe proof"
  validate_optional_readiness "$hostname"
  run_public_probe "$hostname"
  proof_boot_id_value="$(current_boot_id)"
  proof_epoch_value="$(current_epoch)"
  proof_uptime_value="$(current_uptime)"
  write_probe_proof \
    "$hostname" "$validated_ca_hash" "$validated_optional_hash" \
    "$validated_generation" "$proof_boot_id_value" "$proof_epoch_value" \
    "$proof_uptime_value"
  require_private_file_if_present "$proof_file" "AOP public probe proof"
  echo "recorded a short-lived public Cloudflare AOP proof for '$hostname'"
  exit 0
fi

validate_apply_paths
ensure_trusted_directory "$state_root" "Nginx state directory" 0700
acquire_operation_lock
ensure_trusted_directory "$snippets_dir" "Nginx snippets directory" 0755
ensure_trusted_directory "$aop_dir" "Nginx AOP directory" 0700
ensure_trusted_directory "$backup_root" "Nginx backup directory" 0700
validate_apply_paths

requested_ca_hash="$(certificate_sha256 "$ca_file")"
if [ "$stage" = "required" ]; then
  require_private_directory "$runtime_root" "AOP runtime directory"
  validate_optional_readiness "$hostname" "$requested_ca_hash"
  validate_fresh_probe_proof \
    "$hostname" "$validated_ca_hash" "$validated_optional_hash" "$validated_generation"
  generation="$validated_generation"
  rm -f -- "$proof_file"
else
  generation="$("$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C \
    "$openssl_bin" rand -hex 32 2>/dev/null)"
  [[ "$generation" =~ ^[0-9a-f]{64}$ ]] || {
    echo "could not generate AOP install state identity" >&2
    exit 1
  }
  if [ -e "$runtime_root" ] || [ -L "$runtime_root" ]; then
    require_private_directory "$runtime_root" "AOP runtime directory"
    require_private_file_if_present "$proof_file" "AOP public probe proof"
  fi
fi

backup_dir="$(mktemp -d "$backup_root/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
chmod 0700 "$backup_dir"
require_trusted_directory "$backup_dir" "Nginx AOP backup"

managed_paths=("$dest_optional" "$dest_required" "$dest_active" "$install_state")
managed_names=(optional required active install-state)
if [ "$stage" = "optional" ]; then
  managed_paths+=("$dest_ca")
  managed_names+=(client-ca)
fi
for index in "${!managed_paths[@]}"; do
  path="${managed_paths[$index]}"
  name="${managed_names[$index]}"
  require_trusted_file_if_present "$path" "managed AOP path"
  if [ -e "$path" ] || [ -L "$path" ]; then
    cp -a -- "$path" "$backup_dir/$name"
    : > "$backup_dir/$name.present"
  else
    : > "$backup_dir/$name.absent"
  fi
done

restore_needed=0
restore() {
  restore_failed=0
  # Remove only the exact staging files managed by this invocation.
  rm -f -- \
    "$dest_optional.tmp.$$" \
    "$dest_required.tmp.$$" \
    "$dest_active.tmp.$$" \
    "$dest_ca.tmp.$$" || restore_failed=1
  for index in "${!managed_paths[@]}"; do
    path="${managed_paths[$index]}"
    name="${managed_names[$index]}"
    rm -f -- "$path" || restore_failed=1
    if [ -f "$backup_dir/$name.present" ]; then
      cp -a -- "$backup_dir/$name" "$path" || restore_failed=1
    fi
  done
  if "$nginx_bin" -t >/dev/null 2>&1; then
    "$systemctl_bin" reload nginx >/dev/null 2>&1 || restore_failed=1
  else
    restore_failed=1
  fi
  if [ "$restore_failed" -eq 0 ]; then
    echo "AOP change failed; previous files were restored and reloaded" >&2
  else
    echo "AOP change failed; previous files were restored but old-config validation or reload also failed" >&2
  fi
}

on_exit() {
  status=$?
  trap - EXIT INT TERM
  if [ "$restore_needed" -eq 1 ]; then
    set +e
    restore
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

restore_needed=1
install -m 0644 "$source_optional" "$dest_optional.tmp.$$"
mv -f -- "$dest_optional.tmp.$$" "$dest_optional"
install -m 0644 "$source_required" "$dest_required.tmp.$$"
mv -f -- "$dest_required.tmp.$$" "$dest_required"
install -m 0644 "$source_active" "$dest_active.tmp.$$"
mv -f -- "$dest_active.tmp.$$" "$dest_active"
if [ "$stage" = "optional" ]; then
  install -m 0644 "$ca_file" "$dest_ca.tmp.$$"
  mv -f -- "$dest_ca.tmp.$$" "$dest_ca"
fi

# Every live change is checked with the equivalent of `nginx -t` before reload.
if ! "$nginx_bin" -t; then
  echo "new Nginx configuration failed validation" >&2
  exit 1
fi
if ! "$systemctl_bin" reload nginx; then
  echo "Nginx reload failed" >&2
  exit 1
fi

if [ "$stage" = "required" ]; then
  if ! run_public_probe "$hostname"; then
    echo "required AOP stage failed its post-reload public probe" >&2
    exit 1
  fi
else
  if [ -e "$runtime_root" ] || [ -L "$runtime_root" ]; then
    rm -f -- "$proof_file"
  fi
fi

active_hash="$(file_sha256 "$source_active")"
installed_epoch="$(current_epoch)"
write_install_state \
  "$stage" "$hostname" "$requested_ca_hash" "$active_hash" "$generation" "$installed_epoch"
require_private_file_if_present "$install_state" "managed AOP install state"

restore_needed=0
trap - EXIT INT TERM
echo "installed custom AOP stage '$stage'; backup retained at $backup_dir"
