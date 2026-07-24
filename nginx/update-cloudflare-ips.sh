#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV CDPATH GLOBIGNORE SHELLOPTS BASHOPTS \
  LD_PRELOAD LD_LIBRARY_PATH PYTHONHOME PYTHONPATH \
  TMPDIR TMP TEMP CURL_HOME CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR \
  http_proxy https_proxy all_proxy no_proxy \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY 2>/dev/null || true

mode="${1:-check}"
script_dir="$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)"
repo_dir="$(CDPATH= cd -- "$script_dir/.." && pwd)"
default_out_dir="$script_dir/snippets"
default_geo_file="$script_dir/cloudflare-source-geo.conf"
trusted_release_root="/opt/sub2api-gate-release"
production_out_dir="/etc/nginx/snippets"
production_geo_file="/etc/nginx/conf.d/00-cloudflare-source-geo.conf"
production_tmp_root="/run/sub2api-gate"
out_dir="${2:-$default_out_dir}"
geo_file="${3:-$default_geo_file}"
validator="$script_dir/validate_cloudflare_cidrs.py"
[ "$#" -le 3 ] || {
  echo "usage: $0 [check|--apply] [SNIPPET_DIR] [GEO_FILE]" >&2
  exit 2
}
case "$mode" in
  check|--apply) ;;
  *) echo "usage: $0 [check|--apply] [SNIPPET_DIR] [GEO_FILE]" >&2; exit 2 ;;
esac
root_apply=0
if [ "$mode" = "--apply" ] && [ "$(/usr/bin/id -u)" -eq 0 ]; then
  root_apply=1
fi

only_file="$out_dir/cloudflare-only.conf"
real_ip_file="$out_dir/cloudflare-real-ip.conf"

require_root_safe_metadata() {
  path="$1"
  expected_type="$2"
  label="$3"
  if [ -L "$path" ]; then
    echo "$label must not be a symlink" >&2
    exit 1
  fi
  case "$expected_type" in
    directory) [ -d "$path" ] ;;
    file) [ -f "$path" ] ;;
    *) echo "internal Cloudflare updater path validation error" >&2; exit 1 ;;
  esac || {
    echo "$label is unavailable or has the wrong type" >&2
    exit 1
  }
  metadata="$(/usr/bin/stat -c '%u:%a' -- "$path")" || {
    echo "$label metadata is unavailable" >&2
    exit 1
  }
  owner="${metadata%%:*}"
  permissions="${metadata#*:}"
  case "$permissions" in
    ''|*[!0-7]*)
      echo "$label permissions are invalid" >&2
      exit 1
      ;;
  esac
  if [ "$owner" != "0" ] || [ $((0$permissions & 022)) -ne 0 ]; then
    echo "$label must be root-owned and not group/world writable" >&2
    exit 1
  fi
}

require_root_safe_directory_chain() {
  directory="$1"
  case "$directory" in
    /*) ;;
    *) echo "production Cloudflare updater path must be absolute" >&2; exit 1 ;;
  esac
  require_root_safe_metadata / directory "production path root"
  remainder="${directory#/}"
  current=""
  while [ -n "$remainder" ]; do
    component="${remainder%%/*}"
    case "$component" in
      ''|.|..)
        echo "production Cloudflare updater path is not canonical" >&2
        exit 1
        ;;
    esac
    current="$current/$component"
    require_root_safe_metadata "$current" directory "production path directory"
    if [ "$remainder" = "$component" ]; then
      remainder=""
    else
      remainder="${remainder#*/}"
    fi
  done
}

run_validator() {
  if [ "$root_apply" -eq 1 ]; then
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
      /usr/bin/python3 -I "$validator" "$@"
  else
    /usr/bin/python3 "$validator" "$@"
  fi
}

run_release_guard() {
  if [ "$root_apply" -eq 1 ]; then
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
      "$repo_dir/deploy/require-clean-worktree.sh" check
  else
    "$repo_dir/deploy/require-clean-worktree.sh" check
  fi
}

run_curl() {
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/bin/curl --disable "$@"
}

if [ "$mode" != "--apply" ]; then
  missing=0
  for path in "$only_file" "$real_ip_file" "$geo_file"; do
    if [ -f "$path" ]; then
      /usr/bin/cksum "$path"
    else
      echo "missing Cloudflare IP snippet: $path" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
  run_validator --installed "$real_ip_file" "$geo_file" "$only_file"
  echo "check only; no network request was made and no file was changed"
  exit 0
fi

if [ "$root_apply" -eq 1 ]; then
  if [ "$#" -ne 1 ]; then
    echo "root --apply does not accept Cloudflare updater output overrides" >&2
    exit 1
  fi
  if [ "$repo_dir" != "$trusted_release_root" ] || [ "$script_dir" != "$trusted_release_root/nginx" ]; then
    echo "root --apply must run from the trusted production release tree" >&2
    exit 1
  fi
  out_dir="$production_out_dir"
  geo_file="$production_geo_file"
  only_file="$out_dir/cloudflare-only.conf"
  real_ip_file="$out_dir/cloudflare-real-ip.conf"
  geo_dir="$(/usr/bin/dirname -- "$geo_file")"
  require_root_safe_directory_chain "$trusted_release_root"
  require_root_safe_directory_chain "$script_dir"
  require_root_safe_metadata "$script_dir/update-cloudflare-ips.sh" file "Cloudflare updater source"
  require_root_safe_metadata "$validator" file "Cloudflare CIDR validator source"
  require_root_safe_metadata "$repo_dir/deploy/require-clean-worktree.sh" file "release guard source"
  require_root_safe_directory_chain "$out_dir"
  require_root_safe_directory_chain "$geo_dir"
  require_root_safe_directory_chain "$production_tmp_root"
  require_root_safe_metadata "$only_file" file "cloudflare-only target"
  require_root_safe_metadata "$real_ip_file" file "cloudflare-real-ip target"
  require_root_safe_metadata "$geo_file" file "cloudflare-source-geo target"
fi

run_release_guard

if [ "$root_apply" -eq 1 ]; then
  tmp_dir="$(/usr/bin/mktemp -d "$production_tmp_root/cloudflare-ips.XXXXXXXXXX")"
else
  tmp_dir="$(/usr/bin/mktemp -d)"
fi
tmp_v4="$tmp_dir/ips-v4"
tmp_v6="$tmp_dir/ips-v6"
stage_only="$out_dir/.cloudflare-only.conf.$$"
stage_real_ip="$out_dir/.cloudflare-real-ip.conf.$$"
geo_dir="$(/usr/bin/dirname -- "$geo_file")"
stage_geo="$geo_dir/.cloudflare-source-geo.conf.$$"
cleanup() {
  /usr/bin/rm -rf "$tmp_dir"
  /usr/bin/rm -f "$stage_only" "$stage_real_ip" "$stage_geo"
}
trap cleanup EXIT INT TERM

run_curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 20 \
  --max-filesize 65536 https://www.cloudflare.com/ips-v4 -o "$tmp_v4"
run_curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 20 \
  --max-filesize 65536 https://www.cloudflare.com/ips-v6 -o "$tmp_v6"

run_validator "$tmp_v4" "$tmp_v6"

{
  printf '%s\n' '# cloudflare-source-geo.conf evaluates the original TCP peer retained in'
  printf '%s\n' '# $realip_remote_addr after real-IP restoration.'
  printf '%s\n' 'if ($cloudflare_source_allowed = 0) {'
  printf '%s\n' '    return 444;'
  printf '%s\n' '}'
} > "$tmp_dir/cloudflare-only.conf"

{
  printf '%s\n' '# Trust only Cloudflare proxies, then restore the real visitor IP from CF-Connecting-IP.'
  printf '%s\n' '# Source: https://www.cloudflare.com/ips/'
  printf '# Generated: '
  /usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf '\n'
  while IFS= read -r cidr; do
    [ -n "$cidr" ] && printf 'set_real_ip_from %s;\n' "$cidr"
  done < "$tmp_v4"
  printf '\n'
  while IFS= read -r cidr; do
    [ -n "$cidr" ] && printf 'set_real_ip_from %s;\n' "$cidr"
  done < "$tmp_v6"
  printf '\nreal_ip_header CF-Connecting-IP;\n'
  printf 'real_ip_recursive on;\n'
} > "$tmp_dir/cloudflare-real-ip.conf"

{
  printf '%s\n' '# Preserve the original peer check after ngx_http_realip_module replaces'
  printf '%s\n' '# $remote_addr with the visitor address. This file belongs in the http context.'
  printf '%s\n' '# Source: https://www.cloudflare.com/ips/'
  printf '# Generated: '
  /usr/bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf '\n\n'
  printf '%s\n' 'geo $realip_remote_addr $cloudflare_source_allowed {'
  printf '%s\n' '    default 0;'
  printf '\n'
  printf '%s\n' '    # Local health checks cannot forge these source addresses remotely.'
  printf '%s\n' '    127.0.0.1/32 1;'
  printf '%s\n' '    ::1/128 1;'
  printf '\n'
  while IFS= read -r cidr; do
    [ -n "$cidr" ] && printf '    %s 1;\n' "$cidr"
  done < "$tmp_v4"
  printf '\n'
  while IFS= read -r cidr; do
    [ -n "$cidr" ] && printf '    %s 1;\n' "$cidr"
  done < "$tmp_v6"
  printf '%s\n' '}'
} > "$tmp_dir/cloudflare-source-geo.conf"

/usr/bin/mkdir -p "$out_dir" "$geo_dir"
/usr/bin/install -m 0644 "$tmp_dir/cloudflare-only.conf" "$stage_only"
/usr/bin/install -m 0644 "$tmp_dir/cloudflare-real-ip.conf" "$stage_real_ip"
/usr/bin/install -m 0644 "$tmp_dir/cloudflare-source-geo.conf" "$stage_geo"
/usr/bin/mv -f "$stage_only" "$only_file"
/usr/bin/mv -f "$stage_real_ip" "$real_ip_file"
/usr/bin/mv -f "$stage_geo" "$geo_file"
echo "Cloudflare IP snippets updated after explicit --apply"
