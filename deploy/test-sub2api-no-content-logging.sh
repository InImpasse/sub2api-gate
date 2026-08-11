#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
suffix="$$"
network_name="sub2api-gate-test-$suffix"
postgres_name="sub2api-gate-pg-$suffix"
redis_name="sub2api-gate-redis-$suffix"
nonce_redis_name="sub2api-gate-redis-nonce-$suffix"
sub2api_name="sub2api-gate-app-$suffix"
bootstrap_name="sub2api-gate-bootstrap-$suffix"
sync_name="sub2api-gate-sync-$suffix"
test_root="$(mktemp -d /tmp/sub2api-gate-runtime.XXXXXX)"
app_data="$test_root/app"
bootstrap_data="$test_root/bootstrap"
nonce_redis_data="$test_root/redis-nonce"
redis_acl="$test_root/users.acl"
nonce_redis_acl="$test_root/nonce-users.acl"
postgres_image="postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
redis_image="redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
sub2api_image="${SUB2API_TEST_IMAGE:-weishaw/sub2api@sha256:0ffc0202507c3510a696feab92e99faac28e72624ece8f40484b157ba68547b0}"
sub2api_expected_version="${SUB2API_TEST_EXPECTED_VERSION:-0.1.171}"
sync_image="sub2api-gate-sub2api-sync-test:$suffix"
test_password="local-integration-only"
app_database_password="local-app-database-password-only"
redis_password="local-integration-redis-password-00001"
sync_redis_password="local-integration-sync-redis-password-02"
app_log_driver="${SUB2API_TEST_LOG_DRIVER:-none}"

cleanup() {
  docker rm -f "$sync_name" "$sub2api_name" "$bootstrap_name" "$redis_name" "$nonce_redis_name" "$postgres_name" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
  docker image rm "$sync_image" >/dev/null 2>&1 || true
  if [ -n "$test_root" ] && [ -d "$test_root" ]; then
    docker run --rm --log-driver none \
      --mount "type=bind,src=$test_root,dst=/cleanup" \
      --entrypoint sh "$redis_image" -c 'find /cleanup -mindepth 1 -depth -delete' \
      >/dev/null 2>&1 || true
    rmdir "$test_root" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

mkdir -m 0700 "$app_data"
mkdir -m 0777 "$bootstrap_data"
mkdir -m 0777 "$nonce_redis_data"
ACL_TOOL="$repo_dir/deploy/configure-redis-acl.py" \
ACL_OUTPUT="$redis_acl" \
NONCE_ACL_OUTPUT="$nonce_redis_acl" \
ACL_DEFAULT_PASSWORD="$redis_password" \
ACL_SYNC_PASSWORD="$sync_redis_password" \
python3 - <<'PY'
import importlib.util
import os
import pathlib

tool = pathlib.Path(os.environ["ACL_TOOL"])
spec = importlib.util.spec_from_file_location("sub2api_integration_redis_acl", tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
pathlib.Path(os.environ["ACL_OUTPUT"]).write_text(
    module.render_application_acl(os.environ["ACL_DEFAULT_PASSWORD"]),
    encoding="ascii",
)
pathlib.Path(os.environ["NONCE_ACL_OUTPUT"]).write_text(
    module.render_nonce_acl(os.environ["ACL_SYNC_PASSWORD"]),
    encoding="ascii",
)
PY
chmod 0444 "$redis_acl" "$nonce_redis_acl"

docker build --quiet --tag "$sync_image" "$repo_dir/sub2api-sync" >/dev/null

docker network create "$network_name" >/dev/null
docker run --rm --detach --log-driver none \
  --name "$postgres_name" --network "$network_name" \
  --env "POSTGRES_PASSWORD=$test_password" \
  --env POSTGRES_USER=sub2api --env POSTGRES_DB=sub2api \
  "$postgres_image" \
  postgres \
  -c logging_collector=off \
  -c log_destination=stderr \
  -c log_directory=log \
  -c log_statement=none \
  -c log_min_error_statement=panic \
  -c log_min_messages=panic \
  -c log_error_verbosity=terse \
  -c log_parameter_max_length=0 \
  -c log_parameter_max_length_on_error=0 \
  -c log_duration=off \
  -c log_min_duration_statement=-1 \
  -c log_min_duration_sample=-1 \
  -c log_statement_sample_rate=0 \
  -c log_transaction_sample_rate=0 \
  -c log_connections=off \
  -c log_disconnections=off \
  -c log_replication_commands=off \
  -c log_checkpoints=off \
  -c log_lock_waits=off \
  -c log_temp_files=-1 \
  -c log_autovacuum_min_duration=-1 \
  -c debug_print_parse=off \
  -c debug_print_rewritten=off \
  -c debug_print_plan=off \
  -c log_parser_stats=off \
  -c log_planner_stats=off \
  -c log_executor_stats=off \
  -c log_statement_stats=off >/dev/null
docker run --rm --detach --log-driver none \
  --name "$redis_name" --network "$network_name" \
  --user 999:1000 --read-only \
  --mount "type=bind,src=$redis_acl,dst=/etc/redis/users.acl,readonly" \
  --tmpfs /data:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=999,gid=1000 \
  "$redis_image" \
  redis-server --aclfile /etc/redis/users.acl --appendonly no --save "" >/dev/null
docker run --rm --detach --log-driver none \
  --name "$nonce_redis_name" --network "$network_name" \
  --user 999:1000 --read-only \
  --mount "type=bind,src=$nonce_redis_acl,dst=/etc/redis/users.acl,readonly" \
  --mount "type=bind,src=$nonce_redis_data,dst=/data" \
  "$redis_image" \
  redis-server --aclfile /etc/redis/users.acl \
    --appendonly yes --appendfsync always --save "" --aof-use-rdb-preamble yes >/dev/null

attempt=0
until docker exec "$postgres_name" psql -U sub2api -d sub2api -c 'SELECT 1' >/dev/null 2>&1 \
  && docker exec -e REDISCLI_AUTH="$redis_password" "$redis_name" \
    redis-cli --user default ping 2>/dev/null | grep -q '^PONG$' \
  && docker exec -e REDISCLI_AUTH="$sync_redis_password" "$nonce_redis_name" \
    redis-cli --user sub2api_sync ping 2>/dev/null | grep -q '^PONG$'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "Sub2API dependencies did not become ready" >&2
    exit 1
  fi
  sleep 1
done
docker exec -i "$postgres_name" \
  psql --no-psqlrc --quiet -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/deploy/verify-postgres-runtime-logging.sql" >/dev/null 2>&1
for redis_container in "$redis_name" "$nonce_redis_name"; do
  if ! docker exec "$redis_container" redis-server --version 2>&1 | grep -Fq 'v=8.8.0'; then
    echo "Sub2API integration requires the reviewed Redis 8.8.0 binary" >&2
    exit 1
  fi
done

docker run --detach --log-driver "$app_log_driver" \
  --name "$bootstrap_name" --network "$network_name" \
  --user 1000:1000 --read-only --init \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000 \
  --mount "type=bind,src=$bootstrap_data,dst=/app/data" \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env AUTO_SETUP=true \
  --env DATA_DIR=/app/data --env PRICING_DATA_DIR=/app/data \
  --env ADMIN_EMAIL=admin@sub2api.local --env ADMIN_PASSWORD=local-admin-password-only \
  --env SERVER_HOST=0.0.0.0 --env SERVER_PORT=8080 --env SERVER_MODE=release \
  --env "DATABASE_HOST=$postgres_name" --env DATABASE_PORT=5432 \
  --env DATABASE_USER=sub2api --env "DATABASE_PASSWORD=$test_password" --env DATABASE_DBNAME=sub2api \
  --env DATABASE_SSLMODE=disable \
  --env "REDIS_HOST=$redis_name" --env REDIS_PORT=6379 --env "REDIS_PASSWORD=$redis_password" \
  --env JWT_SECRET=local-jwt-secret-with-at-least-32-characters \
  --env TOTP_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --env SECURITY_URL_ALLOWLIST_ENABLED=true \
  --env SECURITY_URL_ALLOWLIST_ALLOW_INSECURE_HTTP=false \
  --env SECURITY_URL_ALLOWLIST_ALLOW_PRIVATE_HOSTS=false \
  --env SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS=api.openai.com \
  --env LOG_OUTPUT_TO_FILE=false --env LOG_OUTPUT_TO_STDOUT=true \
  --env GATEWAY_LOG_UPSTREAM_ERROR_BODY=false --env RISK_CONTROL_ENABLED=false \
  --env IMAGE_STORAGE_ENABLED=false \
  "$sub2api_image" >/dev/null

attempt=0
until docker exec "$bootstrap_name" wget -q -T 3 -O /dev/null http://127.0.0.1:8080/health; do
  if [ "$(docker inspect --format '{{.State.Running}}' "$bootstrap_name" 2>/dev/null || true)" != "true" ]; then
    if [ "$app_log_driver" != "none" ]; then
      docker logs "$bootstrap_name" >&2 || true
    fi
    echo "Sub2API exited before becoming healthy" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "Sub2API did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

if ! docker exec "$bootstrap_name" /app/sub2api --version 2>&1 \
  | grep -Fq "Sub2API $sub2api_expected_version"; then
  echo "Sub2API integration requires the reviewed $sub2api_expected_version binary" >&2
  exit 1
fi

if [ "$(docker exec "$bootstrap_name" id -u)" != "1000" ]; then
  echo "Sub2API container is not running as UID 1000" >&2
  exit 1
fi
if docker exec "$bootstrap_name" sh -c 'touch /rootfs-must-remain-read-only' >/dev/null 2>&1; then
  echo "Sub2API container root filesystem is writable" >&2
  exit 1
fi
if [ "$(docker exec "$bootstrap_name" sh -c "awk '/^CapEff:/ { print \$2 }' /proc/1/status")" != "0000000000000000" ]; then
  echo "Sub2API container retained Linux capabilities" >&2
  exit 1
fi
if [ "$(docker exec "$bootstrap_name" sh -c "awk '/^NoNewPrivs:/ { print \$2 }' /proc/1/status")" != "1" ]; then
  echo "Sub2API container does not enforce no-new-privileges" >&2
  exit 1
fi

sleep 2
if docker exec "$bootstrap_name" sh -c 'test -e /app/data/logs/sub2api.log'; then
  echo "Sub2API recreated a file log despite LOG_OUTPUT_TO_FILE=false" >&2
  exit 1
fi

docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE
  required RECORD;
BEGIN
  FOR required IN
    SELECT *
    FROM (VALUES
      ('groups', 'id'), ('groups', 'name'), ('groups', 'platform'),
      ('groups', 'subscription_type'), ('groups', 'status'),
      ('groups', 'created_at'), ('groups', 'updated_at'),
      ('user_allowed_groups', 'user_id'), ('user_allowed_groups', 'group_id'),
      ('user_allowed_groups', 'created_at'),
      ('user_subscriptions', 'id'), ('user_subscriptions', 'user_id'),
      ('user_subscriptions', 'group_id'), ('user_subscriptions', 'status'),
      ('user_subscriptions', 'starts_at'), ('user_subscriptions', 'expires_at'),
      ('user_subscriptions', 'created_at'), ('user_subscriptions', 'updated_at'),
      ('api_keys', 'id'), ('api_keys', 'user_id'), ('api_keys', 'group_id'),
      ('api_keys', 'status'), ('api_keys', 'quota'), ('api_keys', 'quota_used'),
      ('api_keys', 'expires_at'), ('api_keys', 'created_at'), ('api_keys', 'updated_at'),
      ('usage_logs', 'id'), ('usage_logs', 'request_id'), ('usage_logs', 'model'),
      ('usage_logs', 'requested_model'),
      ('usage_logs', 'input_tokens'), ('usage_logs', 'output_tokens'),
      ('usage_logs', 'cache_creation_tokens'), ('usage_logs', 'cache_read_tokens'),
      ('usage_logs', 'total_cost'), ('usage_logs', 'actual_cost'),
      ('usage_logs', 'duration_ms'), ('usage_logs', 'stream'),
      ('usage_logs', 'request_type'), ('usage_logs', 'inbound_endpoint'),
      ('usage_logs', 'created_at')
    ) AS expected(table_name, column_name)
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = required.table_name
        AND column_name = required.column_name
    ) THEN
      RAISE EXCEPTION 'safe metadata export column missing: %.%',
        required.table_name, required.column_name;
    END IF;
  END LOOP;
END
$$;
SQL

docker rm -f "$bootstrap_name" >/dev/null

docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/002_remove_conversation_capture.sql"
docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/verify_conversation_guards.sql"
docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/002_scrub_conversation_history.sql"
docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/verify_no_conversation_content.sql"
docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/deploy/verify-postgres-portability.sql"

docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE sub2api_sync LOGIN PASSWORD 'local-sync-database-only';
SQL
docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/003_sync_least_privilege.sql"

{
  printf "\\set app_password_b64 '%s'\n" \
    "bG9jYWwtYXBwLWRhdGFiYXNlLXBhc3N3b3JkLW9ubHk="
  sed -n '1,$p' "$repo_dir/migrations/000_prepare_app_role.sql"
} | docker exec -i "$postgres_name" \
  psql -U sub2api -d sub2api -v ON_ERROR_STOP=1
docker exec -i "$postgres_name" psql -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/005_app_least_privilege.sql"

printf '%s\n' 'installed_by=sub2api-gate-integration' > "$app_data/.installed"
chmod 0444 "$app_data/.installed"

docker run --detach --log-driver "$app_log_driver" \
  --name "$sub2api_name" --network "$network_name" \
  --user 1000:1000 --read-only --init \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000 \
  --mount "type=bind,src=$app_data,dst=/app/data" \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env AUTO_SETUP=false \
  --env DATA_DIR=/app/data --env PRICING_DATA_DIR=/app/data \
  --env SERVER_HOST=0.0.0.0 --env SERVER_PORT=8080 --env SERVER_MODE=release \
  --env "DATABASE_HOST=$postgres_name" --env DATABASE_PORT=5432 \
  --env DATABASE_USER=sub2api_app --env "DATABASE_PASSWORD=$app_database_password" --env DATABASE_DBNAME=sub2api \
  --env DATABASE_SSLMODE=disable \
  --env "REDIS_HOST=$redis_name" --env REDIS_PORT=6379 --env "REDIS_PASSWORD=$redis_password" \
  --env JWT_SECRET=local-jwt-secret-with-at-least-32-characters \
  --env TOTP_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --env SECURITY_URL_ALLOWLIST_ENABLED=true \
  --env SECURITY_URL_ALLOWLIST_ALLOW_INSECURE_HTTP=false \
  --env SECURITY_URL_ALLOWLIST_ALLOW_PRIVATE_HOSTS=false \
  --env SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS=api.openai.com \
  --env LOG_OUTPUT_TO_FILE=false --env LOG_OUTPUT_TO_STDOUT=true \
  --env GATEWAY_LOG_UPSTREAM_ERROR_BODY=false --env RISK_CONTROL_ENABLED=false \
  --env IMAGE_STORAGE_ENABLED=false \
  "$sub2api_image" >/dev/null

attempt=0
until docker exec "$sub2api_name" wget -q -T 3 -O /dev/null http://127.0.0.1:8080/health; do
  if [ "$(docker inspect --format '{{.State.Running}}' "$sub2api_name" 2>/dev/null || true)" != "true" ]; then
    if [ "$app_log_driver" != "none" ]; then
      docker logs "$sub2api_name" >&2 || true
    fi
    echo "runtime Sub2API exited before becoming healthy" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "runtime Sub2API did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

if ! docker exec "$sub2api_name" wget -q -T 3 -O /dev/null http://127.0.0.1:8080/health; then
  echo "Sub2API became unhealthy after the privacy migration" >&2
  exit 1
fi
if docker exec "$sub2api_name" sh -c 'test -e /app/data/config.yaml'; then
  echo "runtime Sub2API persisted config.yaml credentials" >&2
  exit 1
fi
if ! docker exec "$sub2api_name" sh -c 'test -r /app/data/.installed'; then
  echo "runtime Sub2API could not read the credential-free install marker" >&2
  exit 1
fi
if ! docker exec "$sub2api_name" sh -c 'test -w /app/data'; then
  echo "runtime Sub2API app-data bind is not writable by UID 1000" >&2
  exit 1
fi
if ! docker exec "$sub2api_name" sh -c \
  'test "$(stat -c "%u:%g:%a" /tmp)" = "1000:1000:700"'; then
  echo "runtime Sub2API tmpfs is not owned by 1000:1000 with mode 0700" >&2
  exit 1
fi
unexpected_app_entries="$(docker exec "$sub2api_name" sh -c \
  'find /app/data -mindepth 1 -maxdepth 1 ! -name .installed ! -name model_pricing.json ! -name model_pricing.sha256 ! -name pages -print' \
  2>/dev/null || true)"
if [ -n "$unexpected_app_entries" ]; then
  echo "runtime Sub2API app-data contains an unreviewed file or directory" >&2
  printf '%s\n' "$unexpected_app_entries" >&2
  exit 1
fi
if ! docker exec "$sub2api_name" sh -c \
  'test -d /app/data/pages && test ! -L /app/data/pages && test "$(stat -c "%u:%g:%a" /app/data/pages)" = "1000:1000:755" && ! find /app/data/pages -mindepth 1 -print -quit | grep -q .'; then
  echo "runtime Sub2API pages directory is not an empty owner-controlled directory" >&2
  exit 1
fi
if docker exec "$sub2api_name" sh -c \
  'find /app/data -type f \( -name "*.log" -o -iname "*preview*" -o -iname "*capture*" -o -name config.yaml \) -print -quit' \
  | grep -q .; then
  echo "Sub2API recreated a forbidden log, preview, capture, or config file" >&2
  exit 1
fi
docker exec -i "$postgres_name" \
  psql --no-psqlrc --quiet -U sub2api -d sub2api -v ON_ERROR_STOP=1 \
  < "$repo_dir/deploy/verify-postgres-runtime-logging.sql" >/dev/null 2>&1

docker run --detach --log-driver none \
  --name "$sync_name" --network "$network_name" \
  --user 65532:65532 --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env SUB2API_SYNC_HOST=0.0.0.0 --env SUB2API_SYNC_PORT=3021 \
  --env SUB2API_SYNC_SECRET=local-sync-hmac-secret-with-at-least-32-characters \
  --env "SUB2API_SYNC_DATABASE_HOST=$postgres_name" --env SUB2API_SYNC_DATABASE_PORT=5432 \
  --env SUB2API_SYNC_DATABASE_NAME=sub2api --env SUB2API_SYNC_DATABASE_USER=sub2api_sync \
  --env SUB2API_SYNC_DATABASE_PASSWORD=local-sync-database-only \
  --env "SUB2API_SYNC_REDIS_HOST=$nonce_redis_name" --env SUB2API_SYNC_REDIS_PORT=6379 \
  --env SUB2API_SYNC_REDIS_USERNAME=sub2api_sync \
  --env "SUB2API_SYNC_REDIS_PASSWORD=$sync_redis_password" \
  --env SUB2API_SYNC_REDIS_DB=0 --env SUB2API_SYNC_DEFAULT_GROUP=openai-default \
  --env SUB2API_LOGIN_URL=https://api.example.com \
  --env SUB2API_PUBLIC_BASE_URL=https://api.example.com/v1 \
  "$sync_image" >/dev/null

attempt=0
until docker exec "$sync_name" python3 -c \
  "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3021/healthz', timeout=3)" \
  >/dev/null 2>&1; do
  if [ "$(docker inspect --format '{{.State.Running}}' "$sync_name" 2>/dev/null || true)" != "true" ]; then
    echo "sync container exited before becoming healthy" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "sync container did not become healthy" >&2
    exit 1
  fi
  sleep 1
done

if [ "$(docker exec "$sync_name" id -u)" != "65532" ]; then
  echo "sync container is not running as UID 65532" >&2
  exit 1
fi
if docker exec "$sync_name" sh -c 'touch /rootfs-must-remain-read-only' >/dev/null 2>&1; then
  echo "sync container root filesystem is writable" >&2
  exit 1
fi

echo "Sub2API privacy migration, no-file-log, safe metadata schema, and sync health integration test passed"
