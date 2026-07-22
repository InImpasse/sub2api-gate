#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container_name="sub2api-gate-redis-$$"
image="${REDIS_TEST_IMAGE:-redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005}"
test_root="$(mktemp -d /tmp/sub2api-gate-sync-redis.XXXXXX)"
acl_file="$test_root/nonce-users.acl"
data_dir="$test_root/data"
sync_password="sync-nonce-test-password-000000001"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  if [ -n "$test_root" ] && [ -d "$test_root" ]; then
    docker run --rm --log-driver none \
      --mount "type=bind,src=$test_root,dst=/cleanup" \
      --entrypoint sh "$image" -c 'find /cleanup -mindepth 1 -depth -delete' \
      >/dev/null 2>&1 || true
    rmdir "$test_root" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

ACL_TOOL="$repo_dir/deploy/configure-redis-acl.py" \
ACL_OUTPUT="$acl_file" \
ACL_SYNC_PASSWORD="$sync_password" \
python3 - <<'PY'
import importlib.util
import os
import pathlib

tool = pathlib.Path(os.environ["ACL_TOOL"])
spec = importlib.util.spec_from_file_location("sync_redis_acl", tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pathlib.Path(os.environ["ACL_OUTPUT"]).write_text(
    module.render_nonce_acl(os.environ["ACL_SYNC_PASSWORD"]),
    encoding="ascii",
)
PY
chmod 0444 "$acl_file"
mkdir -m 0777 "$data_dir"

docker run --detach \
  --name "$container_name" \
  --log-driver none \
  --memory 128m \
  --user 999:1000 \
  --publish 127.0.0.1::6379 \
  --mount "type=bind,src=$acl_file,dst=/etc/redis/users.acl,readonly" \
  --mount "type=bind,src=$data_dir,dst=/data" \
  "$image" \
  redis-server --aclfile /etc/redis/users.acl \
    --appendonly yes --appendfsync always --save "" \
    --maxmemory 32mb --maxmemory-policy noeviction \
    --aof-use-rdb-preamble yes >/dev/null

attempt=0
until docker exec \
  -e REDISCLI_AUTH="$sync_password" \
  "$container_name" \
  redis-cli --user sub2api_sync ping 2>/dev/null | grep -q '^PONG$'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "Redis did not become ready" >&2
    exit 1
  fi
  sleep 1
done

if ! docker exec "$container_name" redis-server --version 2>&1 | grep -Fq 'v=8.8.0'; then
  echo "Redis nonce test requires the reviewed Redis 8.8.0 binary" >&2
  exit 1
fi
nonce_runtime="$(docker inspect --format '{{.HostConfig.Memory}}|{{range .Config.Cmd}}{{printf "<%s>" .}}{{end}}' "$container_name")"
case "$nonce_runtime" in
  134217728\|*"<--maxmemory><32mb><--maxmemory-policy><noeviction>"*) ;;
  *)
    echo "Redis nonce test did not use the reviewed memory boundary" >&2
    exit 1
    ;;
esac

port_output="$(docker port "$container_name" 6379/tcp)"
redis_port="${port_output##*:}"

wait_for_published_redis() {
  published_attempt=0
  until SUB2API_SYNC_REDIS_HOST=127.0.0.1 \
    SUB2API_SYNC_REDIS_PORT="$redis_port" \
    SUB2API_SYNC_REDIS_USERNAME=sub2api_sync \
    SUB2API_SYNC_REDIS_PASSWORD="$sync_password" \
    SUB2API_SYNC_REDIS_DB=15 \
    PYTHONPATH="$repo_dir/sub2api-sync" \
    python3 -c 'import sub2api_sync as sync; raise SystemExit(0 if sync.redis_command("PING") == "PONG" else 1)' \
      >/dev/null 2>&1; do
    published_attempt=$((published_attempt + 1))
    if [ "$published_attempt" -ge 30 ]; then
      echo "Redis published port did not become ready" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_published_redis

SUB2API_SYNC_REDIS_HOST=127.0.0.1 \
SUB2API_SYNC_REDIS_PORT="$redis_port" \
SUB2API_SYNC_REDIS_USERNAME=sub2api_sync \
SUB2API_SYNC_REDIS_PASSWORD="$sync_password" \
SUB2API_SYNC_REDIS_DB=15 \
PYTHONPATH="$repo_dir/sub2api-sync" \
python3 - <<'PY'
import hashlib
from concurrent.futures import ThreadPoolExecutor

import sub2api_sync as sync

nonce = "concurrent-replay-test-nonce-0001"
with ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(lambda _: sync.claim_nonce(nonce), range(20)))
if results.count(True) != 1 or results.count(False) != 19:
    raise SystemExit(f"atomic nonce claim failed: {results}")

nonce_key = "sub2api-sync:nonce:" + hashlib.sha256(nonce.encode()).hexdigest()
ttl = sync.redis_command("TTL", nonce_key)
minimum_ttl = sync.SIGNATURE_MAX_SKEW_SECONDS * 2 - 1
if not minimum_ttl <= ttl <= sync.NONCE_TTL_SECONDS:
    raise SystemExit(
        f"nonce TTL does not cover the complete signed timestamp window: {ttl}"
    )

PY

docker kill "$container_name" >/dev/null
docker start "$container_name" >/dev/null

attempt=0
until docker exec \
  -e REDISCLI_AUTH="$sync_password" \
  "$container_name" \
  redis-cli --user sub2api_sync ping 2>/dev/null | grep -q '^PONG$'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "Redis did not recover after SIGKILL" >&2
    exit 1
  fi
  sleep 1
done

port_output="$(docker port "$container_name" 6379/tcp)"
redis_port="${port_output##*:}"
wait_for_published_redis

SUB2API_SYNC_REDIS_HOST=127.0.0.1 \
SUB2API_SYNC_REDIS_PORT="$redis_port" \
SUB2API_SYNC_REDIS_USERNAME=sub2api_sync \
SUB2API_SYNC_REDIS_PASSWORD="$sync_password" \
SUB2API_SYNC_REDIS_DB=15 \
PYTHONPATH="$repo_dir/sub2api-sync" \
python3 - <<'PY'
import sub2api_sync as sync

nonce = "concurrent-replay-test-nonce-0001"
if sync.claim_nonce(nonce):
    raise SystemExit("nonce replay succeeded after Redis SIGKILL")
PY

echo "Redis nonce concurrency and abnormal-restart integration test passed"
