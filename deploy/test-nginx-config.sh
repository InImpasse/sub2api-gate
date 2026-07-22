#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
temp_dir="$(mktemp -d /tmp/sub2api-gate-nginx.XXXXXX)"
legacy_image="${NGINX_118_TEST_IMAGE:-nginx@sha256:93baf2ec1bfefd04d29eb070900dd5d79b0f79863653453397e55a5b663a6cb1}"
current_image="${NGINX_TEST_IMAGE:-nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10}"
runtime_image="${NGINX_RUNTIME_TEST_IMAGE:-$legacy_image}"
container_prefix="sub2api-gate-nginx-test-$$"
running_containers=()

cleanup() {
  for container in "${running_containers[@]}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  case "$temp_dir" in
    /tmp/sub2api-gate-nginx.*) rm -rf "$temp_dir" ;;
    *) echo "refusing to remove unexpected temp path" >&2; exit 1 ;;
  esac
}
trap cleanup EXIT INT TERM

fail() {
  echo "Nginx AOP test failed: $*" >&2
  exit 1
}

require_digest_image() {
  image="$1"
  digest="${image#nginx@sha256:}"
  if [ "$digest" = "$image" ] || [ "${#digest}" -ne 64 ]; then
    fail "Nginx test images must use an exact sha256 digest"
  fi
  case "$digest" in
    *[!0-9a-f]*) fail "Nginx test image digest is invalid" ;;
  esac
}

require_digest_image "$legacy_image"
require_digest_image "$current_image"
require_digest_image "$runtime_image"

mkdir -p \
  "$temp_dir/ssl" \
  "$temp_dir/aop" \
  "$temp_dir/certs" \
  "$temp_dir/ca-db/newcerts" \
  "$temp_dir/snippets"
cp "$repo_dir/nginx/snippets/cloudflare-only.conf" "$temp_dir/snippets/"
cp "$repo_dir/nginx/snippets/cloudflare-real-ip.conf" "$temp_dir/snippets/"
cp "$repo_dir/nginx/snippets/cloudflare-authenticated-origin-pull.conf" "$temp_dir/snippets/"
cp "$repo_dir/nginx/snippets/sub2api-aop-optional.conf" "$temp_dir/snippets/"
cp "$repo_dir/nginx/snippets/sub2api-aop-required.conf" "$temp_dir/snippets/"
cp "$repo_dir/nginx/snippets/sub2api-aop-optional.conf" "$temp_dir/snippets/sub2api-aop-active.conf"
cp "$repo_dir/nginx/snippets/sub2api-upstream-stable.conf" "$temp_dir/snippets/sub2api-upstream-active.conf"
cp "$repo_dir/nginx/sub2api-sync-location.conf" "$temp_dir/snippets/"

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$temp_dir/ssl/privkey.pem" \
  -out "$temp_dir/ssl/fullchain.pem" \
  -subj "/CN=api.example.com" \
  -addext "subjectAltName=DNS:api.example.com" \
  -days 2 >/dev/null 2>&1

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$temp_dir/certs/client-ca.key" \
  -out "$temp_dir/aop/client-ca.pem" \
  -subj "/CN=Sub2API Gate test AOP CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -days 2 >/dev/null 2>&1

openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$temp_dir/certs/correct-client.key" \
  -out "$temp_dir/certs/correct-client.csr" \
  -subj "/CN=correct-aop-client" >/dev/null 2>&1
openssl x509 -req \
  -in "$temp_dir/certs/correct-client.csr" \
  -CA "$temp_dir/aop/client-ca.pem" \
  -CAkey "$temp_dir/certs/client-ca.key" \
  -set_serial 1001 \
  -out "$temp_dir/certs/correct-client.pem" \
  -days 1 -sha256 >/dev/null 2>&1

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$temp_dir/certs/wrong-ca.key" \
  -out "$temp_dir/certs/wrong-ca.pem" \
  -subj "/CN=Wrong test AOP CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -days 2 >/dev/null 2>&1
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$temp_dir/certs/wrong-client.key" \
  -out "$temp_dir/certs/wrong-client.csr" \
  -subj "/CN=wrong-aop-client" >/dev/null 2>&1
openssl x509 -req \
  -in "$temp_dir/certs/wrong-client.csr" \
  -CA "$temp_dir/certs/wrong-ca.pem" \
  -CAkey "$temp_dir/certs/wrong-ca.key" \
  -set_serial 2001 \
  -out "$temp_dir/certs/wrong-client.pem" \
  -days 1 -sha256 >/dev/null 2>&1

openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$temp_dir/certs/expired-client.key" \
  -out "$temp_dir/certs/expired-client.csr" \
  -subj "/CN=expired-aop-client" >/dev/null 2>&1
: > "$temp_dir/ca-db/index.txt"
printf '%s\n' 3001 > "$temp_dir/ca-db/serial"
{
  printf '%s\n' '[ca]' 'default_ca = test_ca' '[test_ca]'
  printf 'database = %s\n' "$temp_dir/ca-db/index.txt"
  printf 'new_certs_dir = %s\n' "$temp_dir/ca-db/newcerts"
  printf 'certificate = %s\n' "$temp_dir/aop/client-ca.pem"
  printf 'private_key = %s\n' "$temp_dir/certs/client-ca.key"
  printf 'serial = %s\n' "$temp_dir/ca-db/serial"
  printf '%s\n' 'default_md = sha256' 'policy = test_policy' 'unique_subject = no'
  printf '%s\n' '[test_policy]' 'commonName = supplied'
} > "$temp_dir/ca-db/openssl.cnf"
openssl ca -batch \
  -config "$temp_dir/ca-db/openssl.cnf" \
  -in "$temp_dir/certs/expired-client.csr" \
  -out "$temp_dir/certs/expired-client.pem" \
  -startdate 20200101000000Z \
  -enddate 20200102000000Z >/dev/null 2>&1
if openssl x509 -in "$temp_dir/certs/expired-client.pem" -checkend 0 -noout >/dev/null 2>&1; then
  fail "expired client fixture is unexpectedly valid"
fi

syntax_images=("$legacy_image")
if [ "$current_image" != "$legacy_image" ]; then
  syntax_images+=("$current_image")
fi
for image in "${syntax_images[@]}"; do
  docker run --rm \
    --volume "$repo_dir:/workspace:ro" \
    --volume "$temp_dir/snippets:/etc/nginx/snippets:ro" \
    --volume "$temp_dir/ssl:/etc/nginx/ssl:ro" \
    --volume "$temp_dir/aop:/etc/nginx/sub2api-gate/aop:ro" \
    "$image" \
    nginx -t -c /workspace/nginx/test-nginx.conf
done

# Runtime requests originate outside Cloudflare, so only the source-IP test
# snippet is relaxed. The production snippet above was used for both syntax gates.
printf '%s\n' 'allow all;' > "$temp_dir/snippets/cloudflare-only.conf"
printf '%s\n' \
  'set_real_ip_from 0.0.0.0/0;' \
  'set_real_ip_from ::/0;' \
  'real_ip_header CF-Connecting-IP;' \
  'real_ip_recursive on;' > "$temp_dir/snippets/cloudflare-real-ip.conf"

start_stage() {
  stage="$1"
  cp "$repo_dir/nginx/snippets/sub2api-aop-$stage.conf" \
    "$temp_dir/snippets/sub2api-aop-active.conf"
  container="$container_prefix-$stage"
  docker run --detach --rm \
    --name "$container" \
    --publish 127.0.0.1::80 \
    --publish 127.0.0.1::443 \
    --volume "$repo_dir:/workspace:ro" \
    --volume "$temp_dir/snippets:/etc/nginx/snippets:ro" \
    --volume "$temp_dir/ssl:/etc/nginx/ssl:ro" \
    --volume "$temp_dir/aop:/etc/nginx/sub2api-gate/aop:ro" \
    "$runtime_image" \
    nginx -c /workspace/nginx/test-nginx.conf -g 'daemon off;' >/dev/null
  running_containers+=("$container")
  https_port="$(docker port "$container" 443/tcp | sed -n '1s/.*://p')"
  http_port="$(docker port "$container" 80/tcp | sed -n '1s/.*://p')"
  [ -n "$https_port" ] && [ -n "$http_port" ] || fail "could not resolve test ports"
}

stop_stage() {
  container="$1"
  docker rm -f "$container" >/dev/null
  remaining=()
  for running in "${running_containers[@]}"; do
    [ "$running" = "$container" ] || remaining+=("$running")
  done
  running_containers=("${remaining[@]}")
}

curl_common=(--silent --show-error --insecure --http1.1 --noproxy '*' --connect-timeout 3 --max-time 8)
correct_client=(--cert "$temp_dir/certs/correct-client.pem" --key "$temp_dir/certs/correct-client.key")
wrong_client=(--cert "$temp_dir/certs/wrong-client.pem" --key "$temp_dir/certs/wrong-client.key")
expired_client=(--cert "$temp_dir/certs/expired-client.pem" --key "$temp_dir/certs/expired-client.key")

request_body() {
  host="$1"
  port="$2"
  shift 2
  curl "${curl_common[@]}" \
    --resolve "$host:$port:127.0.0.1" \
    -H 'CF-Connecting-IP: 198.51.100.42' \
    "$@" \
    "https://$host:$port/v1/responses"
}

expect_rejected() {
  label="$1"
  host="$2"
  port="$3"
  shift 3
  output="$temp_dir/rejected-response"
  set +e
  status="$(curl "${curl_common[@]}" \
    --output "$output" \
    --write-out '%{http_code}' \
    --resolve "$host:$port:127.0.0.1" \
    -H 'CF-Connecting-IP: 198.51.100.42' \
    "$@" \
    "https://$host:$port/v1/responses" 2>/dev/null)"
  curl_status=$?
  set -e
  if [ "$curl_status" -eq 0 ] && [ "$status" = "200" ]; then
    fail "$label was accepted"
  fi
}

start_stage optional
optional_container="$container_prefix-optional"
for attempt in 1 2 3 4 5; do
  if optional_body="$(request_body api.example.com "$https_port" 2>/dev/null)"; then
    break
  fi
  optional_body=""
done
case "$optional_body" in
  *sub2api-direct*) ;;
  *) fail "optional stage did not allow a missing client certificate" ;;
esac
correct_body="$(request_body api.example.com "$https_port" "${correct_client[@]}")"
case "$correct_body" in
  *'sub2api-direct|'*'xreal=198.51.100.42|'*'xff=198.51.100.42|'*) ;;
  *) fail "optional stage did not accept the correct client certificate" ;;
esac

sync_status() {
  visitor_ip="$1"
  curl "${curl_common[@]}" \
    --output /dev/null \
    --write-out '%{http_code}' \
    --resolve "api.example.com:$https_port:127.0.0.1" \
    -H "CF-Connecting-IP: $visitor_ip" \
    -H 'Content-Type: application/json' \
    -X POST --data '{}' \
    "${correct_client[@]}" \
    "https://api.example.com:$https_port/_sub2api-sync/provision" 2>/dev/null
}
same_ip_limited=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if [ "$(sync_status 198.51.100.42)" = "429" ]; then
    same_ip_limited=1
    break
  fi
done
[ "$same_ip_limited" -eq 1 ] || fail "sync endpoint did not rate-limit the restored visitor IP"
if [ "$(sync_status 198.51.100.43)" = "429" ]; then
  fail "sync endpoint incorrectly shared a Cloudflare-edge rate-limit bucket"
fi
expect_rejected "wrong optional-stage client certificate" api.example.com "$https_port" "${wrong_client[@]}"
expect_rejected "expired optional-stage client certificate" api.example.com "$https_port" "${expired_client[@]}"
expect_rejected "unknown TLS SNI/Host" unknown.example.com "$https_port" "${correct_client[@]}"

sse_body="$(request_body api.example.com "$https_port" \
  "${correct_client[@]}" -H 'Accept: text/event-stream')"
case "$sse_body" in
  *'sub2api-direct|'*'connection=|'*'upgrade=|'*'accept=text/event-stream|'*) ;;
  *) fail "ordinary SSE request received an Upgrade/Connection header or missed the direct backend" ;;
esac
upgrade_body="$(request_body api.example.com "$https_port" \
  "${correct_client[@]}" -H 'Connection: upgrade' -H 'Upgrade: websocket')"
case "$upgrade_body" in
  *'sub2api-direct|'*'connection=upgrade|'*'upgrade=websocket|'*) ;;
  *) fail "Upgrade request did not preserve the expected headers" ;;
esac

set +e
unknown_http_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --noproxy '*' --connect-timeout 3 --max-time 8 \
  -H 'Host: unknown.example.com' "http://127.0.0.1:$http_port/" 2>/dev/null)"
unknown_http_rc=$?
set -e
if [ "$unknown_http_rc" -eq 0 ] && [ "$unknown_http_status" != "000" ]; then
  fail "unknown HTTP Host was not rejected by the default sink"
fi
stop_stage "$optional_container"

start_stage required
required_container="$container_prefix-required"
expect_rejected "missing required-stage client certificate" api.example.com "$https_port"
required_body="$(request_body api.example.com "$https_port" "${correct_client[@]}")"
case "$required_body" in
  *sub2api-direct*) ;;
  *) fail "required stage did not accept the correct client certificate" ;;
esac
expect_rejected "wrong required-stage client certificate" api.example.com "$https_port" "${wrong_client[@]}"
expect_rejected "expired required-stage client certificate" api.example.com "$https_port" "${expired_client[@]}"
stop_stage "$required_container"

echo "Nginx 1.18/current syntax, per-client sync rate limiting, custom AOP stages, default sinks, direct /v1, SSE, and Upgrade checks passed."
