#!/usr/bin/env sh
set -eu

OUT_DIR="${1:-./snippets}"
mkdir -p "$OUT_DIR"

tmp_v4="$(mktemp)"
tmp_v6="$(mktemp)"
trap 'rm -f "$tmp_v4" "$tmp_v6"' EXIT

curl -fsSL https://www.cloudflare.com/ips-v4 -o "$tmp_v4"
curl -fsSL https://www.cloudflare.com/ips-v6 -o "$tmp_v6"

{
  printf '%s\n' '# Source: https://www.cloudflare.com/ips/'
  printf '# Generated: '
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf '\n'
  while IFS= read -r cidr; do
    [ -n "$cidr" ] && printf 'allow %s;\n' "$cidr"
  done < "$tmp_v4"
  printf '\n'
  while IFS= read -r cidr; do
    [ -n "$cidr" ] && printf 'allow %s;\n' "$cidr"
  done < "$tmp_v6"
  printf '\ndeny all;\n'
} > "$OUT_DIR/cloudflare-only.conf"

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
} > "$OUT_DIR/cloudflare-real-ip.conf"
