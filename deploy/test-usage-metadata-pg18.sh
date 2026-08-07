#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
suffix="$$"
network_name="sub2api-gate-usage-$suffix"
postgres_name="sub2api-gate-usage-pg-$suffix"
sync_image="sub2api-gate-sync-usage-test:$suffix"
postgres_image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
test_password="local-usage-integration-only"

cleanup() {
  docker rm -f "$postgres_name" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
  docker image rm "$sync_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create "$network_name" >/dev/null
docker run --rm --detach --log-driver none \
  --name "$postgres_name" --network "$network_name" \
  --env "POSTGRES_PASSWORD=$test_password" \
  "$postgres_image" >/dev/null

attempt=0
consecutive_ready=0
until [ "$consecutive_ready" -ge 2 ]; do
  attempt=$((attempt + 1))
  if docker exec "$postgres_name" psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    consecutive_ready=$((consecutive_ready + 1))
  else
    consecutive_ready=0
  fi
  if [ "$attempt" -ge 30 ]; then
    echo "PostgreSQL 18 did not become ready for usage integration" >&2
    exit 1
  fi
  sleep 1
done
if ! docker exec "$postgres_name" postgres --version | grep -Eq ' 18\.'; then
  echo "usage integration requires PostgreSQL 18" >&2
  exit 1
fi

docker exec -i "$postgres_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE sub2api_sync LOGIN PASSWORD 'local-usage-sync-only';
CREATE TABLE usage_logs (
  id bigint PRIMARY KEY,
  request_id text,
  model text NOT NULL,
  requested_model text,
  input_tokens bigint NOT NULL DEFAULT 0,
  output_tokens bigint NOT NULL DEFAULT 0,
  cache_creation_tokens bigint NOT NULL DEFAULT 0,
  cache_read_tokens bigint NOT NULL DEFAULT 0,
  total_cost numeric NOT NULL DEFAULT 0,
  actual_cost numeric NOT NULL DEFAULT 0,
  duration_ms bigint,
  stream boolean NOT NULL DEFAULT false,
  request_type smallint,
  inbound_endpoint text,
  created_at timestamptz NOT NULL,
  prompt text
);
GRANT USAGE ON SCHEMA public TO sub2api_sync;
GRANT SELECT ON usage_logs TO sub2api_sync;

INSERT INTO usage_logs (
  id,request_id,model,requested_model,input_tokens,output_tokens,
  total_cost,actual_cost,duration_ms,stream,request_type,inbound_endpoint,created_at,prompt
) VALUES
  (1,'req-new','model-new','requested-new',11,5,0.11,0.09,90,true,2,'/v1/responses',now()-interval '1 minute','PRIVATE_SENTINEL'),
  (50,'req-middle','model-middle',NULL,7,3,0.07,0.06,120,false,1,'/v1/chat/completions',now()-interval '30 minutes','PRIVATE_SENTINEL'),
  (2,repeat('r',1000),repeat('m',1000),repeat('q',1000),6,2,0.05,0.04,130,false,1,repeat('e',1000),now()-interval '90 minutes','PRIVATE_SENTINEL'),
  (100,'req-older','model-older',NULL,4,2,0.04,0.03,150,false,0,'/v1/chat/completions',now()-interval '2 hours','PRIVATE_SENTINEL'),
  (999,'req-expired','model-expired',NULL,1,1,0.01,0.01,10,false,0,'/v1/chat/completions',now()-interval '40 days','PRIVATE_SENTINEL');
SQL

set +e
docker exec "$postgres_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE UNIQUE INDEX CONCURRENTLY idx_usage_logs_metadata_search_trgm ON usage_logs ((1));' \
  >/dev/null 2>&1
invalid_index_status=$?
set -e
if [ "$invalid_index_status" -eq 0 ]; then
  echo "usage invalid-index fixture unexpectedly succeeded" >&2
  exit 1
fi
if [ "$(docker exec "$postgres_name" psql -U postgres -d postgres -Atc \
  "SELECT count(*) FROM pg_index WHERE indexrelid='idx_usage_logs_metadata_search_trgm'::regclass AND NOT indisvalid")" != "1" ]; then
  echo "usage invalid-index fixture was not retained" >&2
  exit 1
fi

docker exec -i "$postgres_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/004_usage_cursor_indexes.sql" >/dev/null
if [ "$(docker exec "$postgres_name" psql -U postgres -d postgres -Atc \
  "SELECT count(*) FROM pg_index WHERE indexrelid IN ('idx_usage_logs_created_id_desc'::regclass,'idx_usage_logs_model_created_desc'::regclass,'idx_usage_logs_metadata_search_trgm'::regclass) AND indisvalid AND indisready")" != "3" ]; then
  echo "usage migration left a missing or invalid index" >&2
  exit 1
fi

docker build --quiet --tag "$sync_image" "$repo_dir/sub2api-sync" >/dev/null

docker run --rm --interactive --log-driver none \
  --network "$network_name" --entrypoint python3 \
  --env "SUB2API_SYNC_DATABASE_HOST=$postgres_name" \
  --env SUB2API_SYNC_DATABASE_PORT=5432 \
  --env SUB2API_SYNC_DATABASE_NAME=postgres \
  --env SUB2API_SYNC_DATABASE_USER=sub2api_sync \
  --env SUB2API_SYNC_DATABASE_PASSWORD=local-usage-sync-only \
  "$sync_image" - <<'PY'
import json

import sub2api_sync as sync

first = sync.list_usage_logs({"timePreset": "30d", "pageSize": 2})
if [item["id"] for item in first["items"]] != [1, 50]:
    raise SystemExit(f"usage ordering is not time/id based: {first['items']}")
if not first["page"]["hasMore"] or first["page"]["nextCursor"] != 50:
    raise SystemExit(f"usage first-page cursor is invalid: {first['page']}")
if first["items"][0]["requestType"] != "2":
    raise SystemExit("smallint request_type was not converted to text")
if "PRIVATE_SENTINEL" in json.dumps(first):
    raise SystemExit("usage response exposed a content-bearing column")
if "model-expired" in first["modelOptions"]:
    raise SystemExit("model cache query exceeded the 30-day boundary")

second = sync.list_usage_logs({
    "timePreset": "30d",
    "pageSize": 2,
    "cursorId": first["page"]["nextCursor"],
    "cursorCreatedAt": first["page"]["nextCursorCreatedAt"],
})
if [item["id"] for item in second["items"]] != [2, 100]:
    raise SystemExit(f"usage cursor produced a gap or duplicate: {second['items']}")

detail = sync.get_usage_log_detail({"id": 1})
if detail["item"] != detail["items"][0] or detail["item"]["requestType"] != "2":
    raise SystemExit("usage rolling-upgrade detail shapes are incompatible")

bounded = sync.get_usage_log_detail({"id": 2})["item"]
for field, maximum in {
    "requestId": 128,
    "model": 128,
    "requestedModel": 128,
    "inboundEndpoint": 256,
}.items():
    if len(bounded[field]) > maximum:
        raise SystemExit(f"usage metadata field was not bounded: {field}")

try:
    sync.get_usage_log_detail({"id": 999})
except ValueError:
    pass
else:
    raise SystemExit("usage detail exceeded the 30-day boundary")

if sync.psql("SHOW statement_timeout;") != "3s":
    raise SystemExit("sync PostgreSQL statement_timeout is not 3 seconds")
if sync.psql("SHOW lock_timeout;") != "2s":
    raise SystemExit("sync PostgreSQL lock_timeout is not 2 seconds")
PY

docker exec "$postgres_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c "
INSERT INTO usage_logs (
  id,request_id,model,requested_model,input_tokens,output_tokens,
  total_cost,actual_cost,duration_ms,stream,request_type,inbound_endpoint,created_at,prompt
)
SELECT 1000+item,'perf-request-'||item,'perf-model-'||(item%20),
  'requested-'||(item%10),1,1,0.01,0.01,10,false,1,
  '/v1/responses',now()-interval '2 days','PRIVATE_SENTINEL'
FROM generate_series(1,200000) AS item;
ANALYZE usage_logs;
" >/dev/null

performance_plan="$(docker exec "$postgres_name" psql -U postgres -d postgres -Atc "
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT id FROM usage_logs
WHERE (
  COALESCE(request_id, '') || ' ' || COALESCE(model, '') || ' ' ||
  COALESCE(requested_model, '') || ' ' || COALESCE(inbound_endpoint, '')
) ILIKE '%definitely-no-such-usage-record%'
  AND created_at >= now() - interval '30 days'
ORDER BY created_at DESC,id DESC LIMIT 26;
")"
PERFORMANCE_PLAN="$performance_plan" python3 - <<'PY'
import json
import os

plan = json.loads(os.environ["PERFORMANCE_PLAN"])[0]
encoded = json.dumps(plan)
if "idx_usage_logs_metadata_search_trgm" not in encoded:
    raise SystemExit("usage no-match query did not use the trigram index")
execution_ms = float(plan["Execution Time"])
if execution_ms > 25:
    raise SystemExit(f"usage no-match query exceeded 25ms: {execution_ms:.3f}ms")
PY

echo "PostgreSQL 18 usage metadata integration test passed"
