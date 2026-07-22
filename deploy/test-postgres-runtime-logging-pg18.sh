#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
suffix="$$-$(date +%s)"
container_name="sub2api-gate-runtime-logging-pg-$suffix"
volume_name="sub2api-gate-runtime-logging-pg-$suffix"
gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  docker volume rm "$volume_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker volume create "$volume_name" >/dev/null

# Match the production bind-directory ownership before starting PostgreSQL as
# its non-root runtime identity. This helper exits before the tested container
# starts and never receives database contents.
docker run --rm --log-driver none \
  --user 0:0 \
  --mount "type=volume,src=$volume_name,dst=/var/lib/postgresql" \
  --entrypoint sh \
  "$image" \
  -ec 'chown 70:70 /var/lib/postgresql && chmod 0700 /var/lib/postgresql' \
  >/dev/null 2>&1

docker run --detach --log-driver none \
  --name "$container_name" \
  --user 70:70 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount "type=volume,src=$volume_name,dst=/var/lib/postgresql" \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,nodev,size=8m,mode=0770,uid=70,gid=70 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=70,gid=70 \
  --env POSTGRES_PASSWORD=local-runtime-logging-test-only \
  --env PGDATA=/var/lib/postgresql/18/docker \
  "$image" \
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
  -c log_statement_stats=off >/dev/null 2>&1

attempt=0
until docker exec "$container_name" \
  psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "PostgreSQL runtime logging test did not become ready" >&2
    exit 1
  fi
  sleep 1
done

if ! docker exec "$container_name" postgres --version 2>/dev/null \
  | grep -Eq 'PostgreSQL\) 18\.'; then
  echo "PostgreSQL runtime logging test requires PostgreSQL 18" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container_name")" != "none" ]; then
  echo "PostgreSQL runtime logging test Docker logs are enabled" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.Config.User}}' "$container_name")" != "70:70" ] \
  || [ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_name")" != "true" ] \
  || [ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container_name")" != '["ALL"]' ]; then
  echo "PostgreSQL runtime hardening controls are incomplete" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Destination}}{{end}}{{end}}' "$container_name")" != "/var/lib/postgresql" ]; then
  echo "PostgreSQL runtime uses an incompatible data mount" >&2
  exit 1
fi
docker exec "$container_name" sh -ec \
  'test "$(id -u):$(id -g)" = 70:70 && test "$PGDATA" = /var/lib/postgresql/18/docker && test "$(stat -c "%u:%g" /var/lib/postgresql)" = 70:70 && test "$(stat -c "%u:%g:%a" /var/lib/postgresql/18)" = 70:70:755 && test "$(stat -c "%u:%g:%a" "$PGDATA")" = 70:70:700'

docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  >/dev/null 2>&1 <<'SQL'
CREATE TABLE runtime_layout_probe (value text PRIMARY KEY);
INSERT INTO runtime_layout_probe (value) VALUES ('persisted-across-restart');
SQL

docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1

docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  >/dev/null 2>&1 <<'SQL'
ALTER SYSTEM SET logging_collector = 'on';
ALTER SYSTEM SET log_destination = 'csvlog';
ALTER SYSTEM SET log_directory = 'legacy-log';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_messages = 'info';
ALTER SYSTEM SET log_parameter_max_length_on_error = '-1';
ALTER SYSTEM SET log_min_duration_sample = '0';
SELECT pg_reload_conf();
SQL

# A pending postmaster-level file setting is unsafe even though the current
# command line wins. It must be cleared before the remaining stale reloadable
# values can be accepted as safely overridden.
if docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1; then
  echo "PostgreSQL runtime logging gate accepted a pending unsafe restart" >&2
  exit 1
fi
docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  >/dev/null 2>&1 <<'SQL'
ALTER SYSTEM RESET logging_collector;
SELECT pg_reload_conf();
SQL
docker restart "$container_name" >/dev/null 2>&1
attempt=0
until docker exec "$container_name" \
  psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "PostgreSQL runtime logging test did not recover after clearing pending settings" >&2
    exit 1
  fi
  sleep 1
done

# Command-line settings continue to outrank stale reloadable file settings.
docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1

docker exec "$container_name" sh -ec \
  ': > "$PGDATA/current_logfiles"'
if docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1; then
  echo "PostgreSQL runtime logging gate accepted current_logfiles residue" >&2
  exit 1
fi
docker exec "$container_name" sh -ec 'unlink "$PGDATA/current_logfiles"'

docker exec "$container_name" sh -ec \
  'install -d -m 0700 "$PGDATA/log" && : > "$PGDATA/log/postgresql-stale.csv"'
if docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1; then
  echo "PostgreSQL runtime logging gate accepted stale log directory contents" >&2
  exit 1
fi

docker exec "$container_name" sh -ec \
  'unlink "$PGDATA/log/postgresql-stale.csv" && rmdir "$PGDATA/log"'
docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1

docker restart "$container_name" >/dev/null 2>&1
attempt=0
until docker exec "$container_name" \
  psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "PostgreSQL runtime logging test did not recover after restart" >&2
    exit 1
  fi
  sleep 1
done
docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$gate" >/dev/null 2>&1
docker exec "$container_name" sh -ec 'test ! -e "$PGDATA/legacy-log"'
if [ "$(docker exec "$container_name" psql --no-psqlrc --tuples-only --no-align -U postgres -d postgres -c 'SELECT value FROM runtime_layout_probe')" != "persisted-across-restart" ]; then
  echo "PostgreSQL runtime data did not survive restart" >&2
  exit 1
fi

echo "PostgreSQL 18 runtime logging privacy integration test passed"
