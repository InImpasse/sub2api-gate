#!/usr/bin/env sh
set -eu

mode="${1:-check}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(CDPATH= cd -- "$script_dir/.." && pwd)"
out_dir="${2:-$script_dir/snippets}"
geo_file="${3:-$script_dir/cloudflare-source-geo.conf}"
validator="$script_dir/validate_cloudflare_cidrs.py"
[ "$#" -le 3 ] || {
  echo "usage: $0 [check|--apply] [SNIPPET_DIR] [GEO_FILE]" >&2
  exit 2
}
case "$mode" in
  check|--apply) ;;
  *) echo "usage: $0 [check|--apply] [SNIPPET_DIR] [GEO_FILE]" >&2; exit 2 ;;
esac

only_file="$out_dir/cloudflare-only.conf"
real_ip_file="$out_dir/cloudflare-real-ip.conf"
if [ "$mode" != "--apply" ]; then
  missing=0
  for path in "$only_file" "$real_ip_file" "$geo_file"; do
    if [ -f "$path" ]; then
      cksum "$path"
    else
      echo "missing Cloudflare IP snippet: $path" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
  python3 "$validator" --installed "$real_ip_file" "$geo_file" "$only_file"
  echo "check only; no network request was made and no file was changed"
  exit 0
fi

"$repo_dir/deploy/require-clean-worktree.sh" check

tmp_dir="$(mktemp -d)"
tmp_v4="$tmp_dir/ips-v4"
tmp_v6="$tmp_dir/ips-v6"
stage_only="$out_dir/.cloudflare-only.conf.$$"
stage_real_ip="$out_dir/.cloudflare-real-ip.conf.$$"
geo_dir="$(dirname -- "$geo_file")"
stage_geo="$geo_dir/.cloudflare-source-geo.conf.$$"
cleanup() {
  rm -rf "$tmp_dir"
  rm -f "$stage_only" "$stage_real_ip" "$stage_geo"
}
trap cleanup EXIT INT TERM

curl -fsSL --proto '=https' --connect-timeout 5 --max-time 20 \
  --max-filesize 65536 https://www.cloudflare.com/ips-v4 -o "$tmp_v4"
curl -fsSL --proto '=https' --connect-timeout 5 --max-time 20 \
  --max-filesize 65536 https://www.cloudflare.com/ips-v6 -o "$tmp_v6"

python3 "$validator" "$tmp_v4" "$tmp_v6"

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
  date -u '+%Y-%m-%dT%H:%M:%SZ'
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
  date -u '+%Y-%m-%dT%H:%M:%SZ'
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

mkdir -p "$out_dir" "$geo_dir"
install -m 0644 "$tmp_dir/cloudflare-only.conf" "$stage_only"
install -m 0644 "$tmp_dir/cloudflare-real-ip.conf" "$stage_real_ip"
install -m 0644 "$tmp_dir/cloudflare-source-geo.conf" "$stage_geo"
mv -f "$stage_only" "$only_file"
mv -f "$stage_real_ip" "$real_ip_file"
mv -f "$stage_geo" "$geo_file"
echo "Cloudflare IP snippets updated after explicit --apply"
