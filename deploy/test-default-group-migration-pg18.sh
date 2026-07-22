#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container_name="sub2api-gate-group-pg-$$"
image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
test_password="local-group-integration-only"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --rm --detach --log-driver none \
  --name "$container_name" \
  --env "POSTGRES_PASSWORD=$test_password" \
  "$image" >/dev/null

attempt=0
consecutive_ready=0
until [ "$consecutive_ready" -ge 2 ]; do
  attempt=$((attempt + 1))
  if docker exec "$container_name" psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    consecutive_ready=$((consecutive_ready + 1))
  else
    consecutive_ready=0
  fi
  if [ "$attempt" -ge 30 ]; then
    echo "PostgreSQL 18 did not become ready for group migration integration" >&2
    exit 1
  fi
  sleep 1
done
if ! docker exec "$container_name" postgres --version | grep -Eq ' 18\.'; then
  echo "group migration integration requires PostgreSQL 18" >&2
  exit 1
fi

setup_scenario() {
  database="$1"
  docker exec "$container_name" createdb -U postgres "$database"
  docker exec -i "$container_name" psql -U postgres -d "$database" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE groups (
  id bigint PRIMARY KEY,
  name text NOT NULL,
  status text NOT NULL,
  deleted_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  fallback_group_id bigint REFERENCES groups(id),
  fallback_group_id_on_invalid_request bigint REFERENCES groups(id)
);
CREATE TABLE api_keys (
  id bigint PRIMARY KEY,
  group_id bigint NOT NULL REFERENCES groups(id),
  status text NOT NULL,
  deleted_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE account_groups (
  account_id bigint NOT NULL,
  group_id bigint NOT NULL REFERENCES groups(id),
  priority integer NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE(account_id,group_id)
);
CREATE TABLE user_allowed_groups (
  user_id bigint NOT NULL,
  group_id bigint NOT NULL REFERENCES groups(id),
  created_at timestamptz NOT NULL,
  UNIQUE(user_id,group_id)
);
CREATE TABLE user_group_rate_multipliers (
  user_id bigint NOT NULL,
  group_id bigint NOT NULL REFERENCES groups(id),
  rate_multiplier numeric NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE(user_id,group_id)
);
CREATE TABLE user_subscriptions (
  id bigint PRIMARY KEY,
  user_id bigint NOT NULL,
  group_id bigint NOT NULL REFERENCES groups(id),
  status text NOT NULL,
  deleted_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE usage_logs (id bigint PRIMARY KEY, group_id bigint REFERENCES groups(id));
CREATE TABLE redeem_codes (id bigint PRIMARY KEY, group_id bigint REFERENCES groups(id));
CREATE TABLE content_moderation_logs (id bigint PRIMARY KEY, group_id bigint REFERENCES groups(id));
CREATE TABLE channel_groups (id bigint PRIMARY KEY, group_id bigint NOT NULL REFERENCES groups(id));
CREATE TABLE subscription_plans (id bigint PRIMARY KEY, group_id bigint NOT NULL REFERENCES groups(id));

INSERT INTO groups (id,name,status) VALUES
  (1,'default','active'),
  (2,'openai-default','active'),
  (3,'consumer','active');
UPDATE groups SET fallback_group_id=1,fallback_group_id_on_invalid_request=1 WHERE id=3;
INSERT INTO api_keys VALUES (10,1,'active',NULL,now());
INSERT INTO account_groups VALUES (7,1,5,now()),(7,2,10,now());
INSERT INTO user_allowed_groups VALUES (7,1,now()),(7,2,now());
INSERT INTO user_group_rate_multipliers VALUES (7,1,1.25,now(),now()),(7,2,1.0,now(),now());
INSERT INTO user_subscriptions VALUES (10,7,1,'active',NULL,now());
INSERT INTO usage_logs VALUES (10,1);
INSERT INTO redeem_codes VALUES (10,1);
INSERT INTO content_moderation_logs VALUES (10,1);
INSERT INTO channel_groups VALUES (10,1),(11,2);
INSERT INTO subscription_plans VALUES (10,1);
SQL
}

setup_scenario group_success
docker exec -i "$container_name" psql -U postgres -d group_success -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/001_default_to_openai_default.sql"
docker exec -i "$container_name" psql -U postgres -d group_success -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/001_default_to_openai_default.sql"
docker exec -i "$container_name" psql -U postgres -d group_success -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF (SELECT group_id FROM api_keys WHERE id=10) <> 2
     OR (SELECT group_id FROM user_subscriptions WHERE id=10) <> 2
     OR (SELECT group_id FROM usage_logs WHERE id=10) <> 2
     OR (SELECT group_id FROM redeem_codes WHERE id=10) <> 2
     OR (SELECT group_id FROM content_moderation_logs WHERE id=10) <> 2
     OR (SELECT group_id FROM channel_groups WHERE id=10) <> 2
     OR (SELECT group_id FROM subscription_plans WHERE id=10) <> 2
     OR (SELECT fallback_group_id FROM groups WHERE id=3) <> 2
     OR (SELECT fallback_group_id_on_invalid_request FROM groups WHERE id=3) <> 2 THEN
    RAISE EXCEPTION 'known default-group references were not migrated';
  END IF;
  IF EXISTS (SELECT 1 FROM account_groups WHERE group_id=1)
     OR EXISTS (SELECT 1 FROM user_allowed_groups WHERE group_id=1)
     OR EXISTS (SELECT 1 FROM user_group_rate_multipliers WHERE group_id=1)
     OR EXISTS (SELECT 1 FROM channel_groups WHERE group_id=1)
     OR EXISTS (SELECT 1 FROM subscription_plans WHERE group_id=1) THEN
    RAISE EXCEPTION 'source group relationships remain after migration';
  END IF;
  IF (SELECT priority FROM account_groups WHERE account_id=7 AND group_id=2) <> 5
     OR (SELECT count(*) FROM channel_groups) <> 2
     OR (SELECT count(*) FROM subscription_plans) <> 1
     OR (SELECT deleted_at IS NULL FROM groups WHERE id=1) THEN
    RAISE EXCEPTION 'source group relationships were lost or not deactivated correctly';
  END IF;
END
$$;
SQL

setup_scenario group_dual
docker exec "$container_name" psql -U postgres -d group_dual -v ON_ERROR_STOP=1 \
  -c "INSERT INTO user_subscriptions VALUES (11,7,2,'active',NULL,now())" >/dev/null
if docker exec -i "$container_name" psql -U postgres -d group_dual -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/001_default_to_openai_default.sql" >/dev/null 2>&1; then
  echo "dual active subscriptions did not abort group migration" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d group_dual -v ON_ERROR_STOP=1 \
  -c "DO \$\$ BEGIN IF (SELECT group_id FROM api_keys WHERE id=10) <> 1 OR (SELECT deleted_at IS NOT NULL FROM groups WHERE id=1) THEN RAISE EXCEPTION 'dual-subscription rollback failed'; END IF; END \$\$;" >/dev/null

setup_scenario group_relationship_conflict
docker exec "$container_name" psql -U postgres -d group_relationship_conflict -v ON_ERROR_STOP=1 \
  -c "ALTER TABLE channel_groups ADD CONSTRAINT channel_groups_one_per_group UNIQUE(group_id)" >/dev/null
if docker exec -i "$container_name" psql -U postgres -d group_relationship_conflict -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/001_default_to_openai_default.sql" >/dev/null 2>&1; then
  echo "relationship conflict did not abort group migration" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d group_relationship_conflict -v ON_ERROR_STOP=1 \
  -c "DO \$\$ BEGIN IF (SELECT group_id FROM api_keys WHERE id=10) <> 1 OR (SELECT count(*) FROM channel_groups) <> 2 OR (SELECT deleted_at IS NOT NULL FROM groups WHERE id=1) THEN RAISE EXCEPTION 'relationship-conflict rollback failed'; END IF; END \$\$;" >/dev/null

setup_scenario group_unknown
docker exec "$container_name" psql -U postgres -d group_unknown -v ON_ERROR_STOP=1 \
  -c "CREATE TABLE unknown_group_refs (id bigint PRIMARY KEY, group_id bigint REFERENCES groups(id)); INSERT INTO unknown_group_refs VALUES (1,1);" >/dev/null
if docker exec -i "$container_name" psql -U postgres -d group_unknown -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/001_default_to_openai_default.sql" >/dev/null 2>&1; then
  echo "unknown group reference did not abort group migration" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d group_unknown -v ON_ERROR_STOP=1 \
  -c "DO \$\$ BEGIN IF (SELECT group_id FROM api_keys WHERE id=10) <> 1 OR (SELECT deleted_at IS NOT NULL FROM groups WHERE id=1) OR (SELECT group_id FROM unknown_group_refs WHERE id=1) <> 1 THEN RAISE EXCEPTION 'unknown-reference rollback failed'; END IF; END \$\$;" >/dev/null

setup_scenario group_duplicate_source_unknown
docker exec "$container_name" psql -U postgres -d group_duplicate_source_unknown -v ON_ERROR_STOP=1 \
  -c "INSERT INTO groups (id,name,status) VALUES (4,'default','active'); CREATE TABLE duplicate_source_refs (id bigint PRIMARY KEY, group_id bigint REFERENCES groups(id)); INSERT INTO duplicate_source_refs VALUES (1,4);" >/dev/null
if docker exec -i "$container_name" psql -U postgres -d group_duplicate_source_unknown -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/001_default_to_openai_default.sql" >/dev/null 2>&1; then
  echo "duplicate default source unknown reference did not abort group migration" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d group_duplicate_source_unknown -v ON_ERROR_STOP=1 \
  -c "DO \$\$ BEGIN IF (SELECT group_id FROM api_keys WHERE id=10) <> 1 OR EXISTS (SELECT 1 FROM groups WHERE id IN (1,4) AND deleted_at IS NOT NULL) OR (SELECT group_id FROM duplicate_source_refs WHERE id=1) <> 4 THEN RAISE EXCEPTION 'duplicate-source unknown-reference rollback failed'; END IF; END \$\$;" >/dev/null

echo "PostgreSQL 18 default-group migration integration test passed"
