#!/usr/bin/env bash
set -eu

mode="${1:-check}"
repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
compose_file="$repo_dir/docker-compose.yml"

case "$mode" in
  check|running) ;;
  *) echo "usage: $0 [check|running]" >&2; exit 2 ;;
esac

require_compose_text() {
  expected="$1"
  if ! grep -Fq -- "$expected" "$compose_file"; then
    echo "runtime version gate is missing expected Compose text" >&2
    exit 1
  fi
}

require_compose_text "weishaw/sub2api@sha256:0ffc0202507c3510a696feab92e99faac28e72624ece8f40484b157ba68547b0"
require_compose_text "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
require_compose_text "Sub2API 0.1.171"
require_compose_text "v=8.8.0"
require_compose_text "postgres --version"

if [ "$mode" = "check" ]; then
  echo "runtime version configuration check passed; no container was contacted"
  exit 0
fi

command -v docker >/dev/null 2>&1 || {
  echo "docker is required for running version verification" >&2
  exit 1
}

sub2api_container="${SUB2API_CONTAINER_NAME:-sub2api}"
postgres_container="${SUB2API_POSTGRES_CONTAINER_NAME:-sub2api-postgres}"
redis_container="${SUB2API_REDIS_CONTAINER_NAME:-sub2api-redis}"
for name in "$sub2api_container" "$postgres_container" "$redis_container"; do
  if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]; then
    echo "container name is invalid" >&2
    exit 1
  fi
done

sub2api_version="$(docker exec "$sub2api_container" /app/sub2api --version 2>&1)" || {
  echo "could not read the running Sub2API binary version" >&2
  exit 1
}
case "$sub2api_version" in
  "Sub2API 0.1.171"|"Sub2API 0.1.171 "*) ;;
  *) echo "running Sub2API binary is not 0.1.171" >&2; exit 1 ;;
esac

redis_version="$(docker exec "$redis_container" redis-server --version 2>&1)" || {
  echo "could not read the running Redis binary version" >&2
  exit 1
}
case "$redis_version" in
  *"v=8.8.0"*) ;;
  *) echo "running Redis binary is not 8.8.0" >&2; exit 1 ;;
esac

postgres_version="$(docker exec "$postgres_container" postgres --version 2>&1)" || {
  echo "could not read the running PostgreSQL binary version" >&2
  exit 1
}
case "$postgres_version" in
  *"PostgreSQL) 18."*) ;;
  *) echo "running PostgreSQL binary is not major version 18" >&2; exit 1 ;;
esac

echo "running Sub2API 0.1.171, Redis 8.8.0, and PostgreSQL 18 binaries verified"
