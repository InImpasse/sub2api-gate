#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
suffix="$$"
app_name="sub2api-gate-app-redis-test-$suffix"
nonce_name="sub2api-gate-nonce-redis-test-$suffix"
image="${REDIS_TEST_IMAGE:-redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005}"
test_root="$(mktemp -d /tmp/sub2api-gate-redis-acl.XXXXXX)"
app_acl="$test_root/app-users.acl"
nonce_acl="$test_root/nonce-users.acl"
nonce_data="$test_root/nonce-data"
app_password="default-test-password-000000000001"
sync_password="sync-test-password-00000000000002"

cleanup() {
  docker rm -f "$app_name" "$nonce_name" >/dev/null 2>&1 || true
  if [ -n "$test_root" ] && [ -d "$test_root" ]; then
    # Redis creates the appendonly directory as UID 999 with mode 0700. Use a
    # one-shot root container to remove only this mktemp-owned test directory.
    docker run --rm --log-driver none \
      --mount "type=bind,src=$test_root,dst=/cleanup" \
      --entrypoint sh "$image" -c 'find /cleanup -mindepth 1 -depth -delete' \
      >/dev/null 2>&1 || true
    rmdir "$test_root" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

mkdir -m 0777 "$nonce_data"
ACL_TOOL="$repo_dir/deploy/configure-redis-acl.py" \
APP_ACL="$app_acl" NONCE_ACL="$nonce_acl" \
APP_PASSWORD="$app_password" SYNC_PASSWORD="$sync_password" \
python3 - <<'PY'
import importlib.util
import os
import pathlib

tool = pathlib.Path(os.environ["ACL_TOOL"])
spec = importlib.util.spec_from_file_location("redis_acl_integration", tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pathlib.Path(os.environ["APP_ACL"]).write_text(
    module.render_application_acl(os.environ["APP_PASSWORD"]), encoding="ascii"
)
pathlib.Path(os.environ["NONCE_ACL"]).write_text(
    module.render_nonce_acl(os.environ["SYNC_PASSWORD"]), encoding="ascii"
)
PY
chmod 0444 "$app_acl" "$nonce_acl"

docker run --detach \
  --name "$app_name" \
  --log-driver none \
  --memory 256m \
  --user 999:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount "type=bind,src=$app_acl,dst=/etc/redis/users.acl,readonly" \
  --tmpfs /data:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=999,gid=1000 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=999,gid=1000 \
  "$image" \
  redis-server --aclfile /etc/redis/users.acl --appendonly no --save "" \
    --maxmemory 128mb --maxmemory-policy noeviction >/dev/null

docker run --detach \
  --name "$nonce_name" \
  --log-driver none \
  --memory 128m \
  --user 999:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount "type=bind,src=$nonce_acl,dst=/etc/redis/users.acl,readonly" \
  --mount "type=bind,src=$nonce_data,dst=/data" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=999,gid=1000 \
  "$image" \
  redis-server --aclfile /etc/redis/users.acl \
    --appendonly yes --appendfsync always --save "" \
    --maxmemory 32mb --maxmemory-policy noeviction \
    --aof-use-rdb-preamble yes >/dev/null

app_redis() {
  docker exec -e REDISCLI_AUTH="$app_password" "$app_name" redis-cli --user default "$@"
}

nonce_redis() {
  docker exec -e REDISCLI_AUTH="$sync_password" "$nonce_name" redis-cli --user sub2api_sync "$@"
}

assert_app_has_no_persistence_files() {
  if docker exec "$app_name" sh -c \
    "find /data -type f \( -name '*.rdb' -o -name '*.aof' -o -name 'appendonly.aof.*' \) -print -quit" \
    2>/dev/null | grep -q .; then
    echo "application Redis created an RDB or AOF file" >&2
    exit 1
  fi
}

wait_for_redis() {
  target="$1"
  attempt=0
  while ! "$target" ping 2>/dev/null | grep -qx PONG; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
      echo "Redis ACL test server did not become ready" >&2
      exit 1
    fi
    sleep 1
  done
}

wait_for_redis app_redis
wait_for_redis nonce_redis
for container in "$app_name" "$nonce_name"; do
  if ! docker exec "$container" redis-server --version 2>&1 | grep -Fq 'v=8.8.0'; then
    echo "Redis ACL test requires the reviewed Redis 8.8.0 binary" >&2
    exit 1
  fi
done

app_data_mount="$(docker inspect --format '{{if index .HostConfig.Tmpfs "/data"}}tmpfs true{{end}}' "$app_name")"
if [ "$app_data_mount" != "tmpfs true" ]; then
  echo "application Redis /data is not a writable tmpfs" >&2
  exit 1
fi
app_memory="$(docker inspect --format '{{.HostConfig.Memory}}' "$app_name")"
app_cmdline="$(docker inspect --format '{{range .Config.Cmd}}{{printf "<%s>" .}}{{end}}' "$app_name")"
case "$app_memory|$app_cmdline" in
  268435456\|*"<--maxmemory><128mb><--maxmemory-policy><noeviction>"*) ;;
  *)
    echo "application Redis did not start with the reviewed memory boundary" >&2
    exit 1
    ;;
esac

for key_value in \
  'billing:balance:1=12.5' \
  'oauth:token:account-1=raw-access-token' \
  'sched:account:1={"credential":"temporary"}' \
  'totp:setup:user-1=temporary-secret' \
  'masked_session:1=temporary-session' \
  'concurrency:account:1=request-identifier' \
  'umq:{1}:lock=request-identifier'; do
  key="${key_value%%=*}"
  value="${key_value#*=}"
  if [ "$(app_redis set "$key" "$value")" != "OK" ]; then
    echo "application Redis rejected a source-audited runtime key" >&2
    exit 1
  fi
done

# Reproduce the exact runtime operation shapes used by Sub2API 0.1.176. The
# wait counter uses Lua GET/INCR/EXPIRE; sticky routing uses numeric account IDs;
# and the cyber block table stores only a one-marker behind a SHA-256 key.
wait_result="$(app_redis eval \
  "local current=redis.call('GET', KEYS[1]); redis.call('INCR', KEYS[1]); redis.call('EXPIRE', KEYS[1], ARGV[1]); return current" \
  1 wait:account:42 900)"
if [ -n "$wait_result" ] || [ "$(app_redis get wait:account:42)" != "1" ]; then
  echo "application Redis rejected the account wait counter operation" >&2
  exit 1
fi
if [ "$(app_redis set sticky_session:7:0123456789abcdef 123 ex 3600)" != "OK" ] \
  || [ "$(app_redis get sticky_session:7:0123456789abcdef)" != "123" ] \
  || [ "$(app_redis expire sticky_session:7:0123456789abcdef 3600)" != "1" ]; then
  echo "application Redis rejected the sticky-session operation" >&2
  exit 1
fi
if [ "$(app_redis set cyber_session_block:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 ex 3600)" != "OK" ] \
  || [ "$(app_redis exists cyber_session_block:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)" != "1" ]; then
  echo "application Redis rejected the cyber-session-block operation" >&2
  exit 1
fi

for forbidden_key in \
  sub2api:prompt_audit:payload:1 \
  image_task:1 \
  content_moderation:flagged_hashes \
  batch_image:queue:ready \
  openai:response:request-id \
  unknown:key; do
  if [ "$(app_redis set "$forbidden_key" private-content 2>/dev/null || true)" = "OK" ]; then
    echo "forbidden content key was writable" >&2
    exit 1
  fi
done
if [ "$(app_redis eval "return redis.call('SET', KEYS[1], ARGV[1])" \
  1 prompt:lua-attempt private-content 2>/dev/null || true)" = "OK" ]; then
  echo "forbidden content key was writable through Lua" >&2
  exit 1
fi
if [ "$(app_redis eval "return redis.call('SET', ARGV[1], ARGV[2])" \
  0 response:dynamic-lua-attempt private-content 2>/dev/null || true)" = "OK" ]; then
  echo "forbidden dynamically addressed content key was writable through Lua" >&2
  exit 1
fi

case "$(app_redis config get save 2>/dev/null || true)" in
  NOPERM*) ;;
  *)
    echo "application Redis user retained an administrative command" >&2
    exit 1
    ;;
esac
if docker exec -e REDISCLI_AUTH="$sync_password" "$app_name" \
  redis-cli --user sub2api_sync ping 2>/dev/null | grep -qx PONG; then
  echo "sync user was enabled on the application Redis" >&2
  exit 1
fi
assert_app_has_no_persistence_files

docker kill "$app_name" >/dev/null
docker start "$app_name" >/dev/null
wait_for_redis app_redis
for key in billing:balance:1 oauth:token:account-1 sched:account:1 \
  totp:setup:user-1 masked_session:1 concurrency:account:1 'umq:{1}:lock' \
  wait:account:42 sticky_session:7:0123456789abcdef \
  cyber_session_block:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; do
  if [ "$(app_redis exists "$key")" != "0" ]; then
    echo "volatile application Redis retained data after SIGKILL" >&2
    exit 1
  fi
done
assert_app_has_no_persistence_files

for key_value in \
  'wait:account:42=1' \
  'sticky_session:7:0123456789abcdef=123' \
  'cyber_session_block:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=1'; do
  key="${key_value%%=*}"
  value="${key_value#*=}"
  if [ "$(app_redis set "$key" "$value" ex 3600)" != "OK" ]; then
    echo "application Redis rejected a volatile restart fixture" >&2
    exit 1
  fi
done
assert_app_has_no_persistence_files
docker stop --time 5 "$app_name" >/dev/null
docker start "$app_name" >/dev/null
wait_for_redis app_redis
for key in wait:account:42 sticky_session:7:0123456789abcdef \
  cyber_session_block:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; do
  if [ "$(app_redis exists "$key")" != "0" ]; then
    echo "volatile application Redis retained data after graceful restart" >&2
    exit 1
  fi
done
assert_app_has_no_persistence_files

nonce="sub2api-sync:nonce:$(printf 'a%.0s' {1..64})"
if [ "$(nonce_redis set "$nonce" 1 nx ex 601)" != "OK" ]; then
  echo "nonce Redis could not claim a replay marker" >&2
  exit 1
fi
if [ "$(nonce_redis set billing:balance:1 12.5 2>/dev/null || true)" = "OK" ]; then
  echo "nonce Redis accepted an application key" >&2
  exit 1
fi
case "$(nonce_redis config get appendonly 2>/dev/null || true)" in
  NOPERM*) ;;
  *)
    echo "runtime nonce user retained CONFIG access" >&2
    exit 1
    ;;
esac
if docker exec -e REDISCLI_AUTH="migration-test-password-0000000001" "$nonce_name" \
  redis-cli --user sub2api_migration ping 2>/dev/null | grep -qx PONG; then
  echo "one-time migration user was enabled at runtime" >&2
  exit 1
fi
nonce_cmdline="$(docker inspect --format '{{range .Config.Cmd}}{{printf "<%s>" .}}{{end}}' "$nonce_name")"
case "$nonce_cmdline" in
  *"<--appendonly><yes>"*"<--appendfsync><always>"*"<--save><>"*"<--maxmemory><32mb><--maxmemory-policy><noeviction>"*"<--aof-use-rdb-preamble><yes>"*) ;;
  *)
    echo "nonce Redis did not start with appendfsync-always AOF and disabled periodic snapshots" >&2
    exit 1
    ;;
esac
if [ "$(docker inspect --format '{{.HostConfig.Memory}}' "$nonce_name")" != "134217728" ]; then
  echo "nonce Redis container memory limit is not the reviewed 128 MiB" >&2
  exit 1
fi

attempt=0
until docker exec "$nonce_name" \
  find /data -type f -name 'appendonly.aof.*' -print -quit 2>/dev/null | grep -q .; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "nonce Redis did not create its AOF" >&2
    exit 1
  fi
  sleep 1
done
docker kill "$nonce_name" >/dev/null
docker start "$nonce_name" >/dev/null
wait_for_redis nonce_redis
if [ -n "$(nonce_redis set "$nonce" 1 nx ex 601)" ]; then
  echo "nonce replay succeeded after Redis SIGKILL" >&2
  exit 1
fi
ttl="$(nonce_redis ttl "$nonce")"
if [ "$ttl" -le 0 ] || [ "$ttl" -gt 601 ]; then
  echo "crash-restored nonce TTL is invalid" >&2
  exit 1
fi
if docker exec "$nonce_name" \
  find /data -maxdepth 1 -type f -name '*.rdb' -print -quit 2>/dev/null | grep -q .; then
  echo "nonce Redis unexpectedly created a periodic RDB snapshot" >&2
  exit 1
fi

echo "volatile application Redis and crash-durable nonce-only Redis gates passed"
