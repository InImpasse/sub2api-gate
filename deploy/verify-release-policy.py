#!/usr/bin/env python3
"""Verify that the reviewed runtime release is represented consistently."""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "deploy" / "release-policy.json"
COMPOSE_FILES = (
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.canary.yml",
    ROOT / "docker-compose.traffic-canary.yml",
)
SYNC_COMPOSE_FILES = (
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.sync-canary.yml",
)
SUB2API_IMAGE_RE = re.compile(r"weishaw/sub2api@sha256:[0-9a-f]{64}")
POSTGRES_IMAGE_RE = re.compile(r"postgres@sha256:[0-9a-f]{64}")
REDIS_IMAGE_RE = re.compile(r"redis@sha256:[0-9a-f]{64}")
SOURCE_REVISION_RE = re.compile(r"[0-9a-f]{40}")


class ReleasePolicyError(ValueError):
    """Raised when a release policy or its consumers are inconsistent."""


def read_policy(path=POLICY_PATH):
    try:
        policy = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleasePolicyError("release policy is unavailable or invalid") from error
    validate_policy_shape(policy)
    return policy


def validate_policy_shape(policy):
    if not isinstance(policy, dict) or policy.get("schema") != 1:
        raise ReleasePolicyError("release policy schema is unsupported")
    expected_sections = {"sub2api", "postgres", "redis", "sync"}
    if set(policy) != {"schema", *expected_sections}:
        raise ReleasePolicyError("release policy sections are invalid")
    for section in expected_sections:
        if not isinstance(policy.get(section), dict):
            raise ReleasePolicyError(f"release policy section is invalid: {section}")

    sub2api = policy["sub2api"]
    if not re.fullmatch(r"0\.[0-9]+\.[0-9]+", str(sub2api.get("version", ""))):
        raise ReleasePolicyError("Sub2API version is invalid")
    if not _valid_digest(sub2api.get("image"), "weishaw/sub2api"):
        raise ReleasePolicyError("Sub2API image digest is invalid")
    if not SOURCE_REVISION_RE.fullmatch(str(sub2api.get("source_revision", ""))):
        raise ReleasePolicyError("Sub2API source revision is invalid")

    postgres = policy["postgres"]
    if postgres.get("major") != "18" or postgres.get("client_version") != "18.4":
        raise ReleasePolicyError("PostgreSQL release policy is invalid")
    if not _valid_digest(postgres.get("image"), "postgres"):
        raise ReleasePolicyError("PostgreSQL image digest is invalid")

    redis = policy["redis"]
    if redis.get("version") != "8.8.0":
        raise ReleasePolicyError("Redis release policy is invalid")
    if not _valid_digest(redis.get("image"), "redis"):
        raise ReleasePolicyError("Redis image digest is invalid")

    sync = policy["sync"]
    if sync.get("image") != "sub2api-gate/sub2api-sync:pg18.4-r1":
        raise ReleasePolicyError("sync image policy is invalid")
    if not _valid_digest(sync.get("postgres_client_image"), "postgres"):
        raise ReleasePolicyError("sync PostgreSQL client image digest is invalid")
    if not _valid_digest(sync.get("python_image"), "python"):
        raise ReleasePolicyError("sync Python image digest is invalid")


def _valid_digest(value, prefix):
    return isinstance(value, str) and bool(
        re.fullmatch(re.escape(prefix) + r"@sha256:[0-9a-f]{64}", value)
    )


def _read(path):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReleasePolicyError(f"release consumer is unavailable: {path}") from error


def _require(text, marker, path):
    if marker not in text:
        raise ReleasePolicyError(f"{path.relative_to(ROOT)} is missing reviewed marker")


def _require_no(text, marker, path):
    if marker in text:
        raise ReleasePolicyError(f"{path.relative_to(ROOT)} contains stale release marker")


def _check_runtime_compose(path, policy, *, require_runtime_images=None):
    text = _read(path)
    sub2api_images = sorted(set(SUB2API_IMAGE_RE.findall(text)))
    postgres_images = sorted(set(POSTGRES_IMAGE_RE.findall(text)))
    redis_images = sorted(set(REDIS_IMAGE_RE.findall(text)))
    expected_sub2api = policy["sub2api"]["image"]
    expected_postgres = policy["postgres"]["image"]
    expected_redis = policy["redis"]["image"]
    required = path in COMPOSE_FILES if require_runtime_images is None else require_runtime_images
    if required and sub2api_images != [expected_sub2api]:
        raise ReleasePolicyError(f"{path.name} has an unreviewed Sub2API image")
    if required and postgres_images != [expected_postgres]:
        raise ReleasePolicyError(f"{path.name} has an unreviewed PostgreSQL image")
    if required and redis_images != [expected_redis]:
        raise ReleasePolicyError(f"{path.name} has an unreviewed Redis image")
    if path in COMPOSE_FILES:
        _require(text, f"Sub2API {policy['sub2api']['version']}", path)
    if path == ROOT / "docker-compose.yml":
        _require(text, f"image: {policy['sync']['image']}", path)


def _check_sync_consumer(path, policy):
    text = _read(path)
    if path.name == "Dockerfile":
        _require(text, policy["sync"]["postgres_client_image"], path)
        _require(text, policy["sync"]["python_image"], path)
        release_tag = policy["sync"]["image"].rsplit(":", 1)[1]
        _require(text, f'io.sub2api-gate.sync-release="{release_tag}"', path)
    else:
        _require(text, policy["sync"]["image"], path)


def verify(policy=None, *, root=ROOT):
    policy = read_policy() if policy is None else policy
    validate_policy_shape(policy)
    sub2api = policy["sub2api"]
    redis = policy["redis"]
    sync = policy["sync"]

    for path in COMPOSE_FILES:
        _check_runtime_compose(path, policy)
    for path in SYNC_COMPOSE_FILES:
        text = _read(path)
        _require(text, sync["image"], path)
    _check_sync_consumer(root / "sub2api-sync" / "Dockerfile", policy)

    runtime_gate = root / "deploy" / "verify-runtime-versions.sh"
    runtime_text = _read(runtime_gate)
    _require(runtime_text, sub2api["image"], runtime_gate)
    _require(runtime_text, f"Sub2API {sub2api['version']}", runtime_gate)
    _require(runtime_text, redis["version"], runtime_gate)

    for relative in (
        "deploy/security-preflight.sh",
        "deploy/traffic-canary.py",
        "deploy/test-sub2api-no-content-logging.sh",
        "deploy/migrate-app-metadata.py",
        "deploy/configure-redis-acl.py",
        "deploy/migrate-redis-allowlist.py",
        "deploy/test-redis-runtime-acl.sh",
        "deploy/test-app-role-least-privilege-pg18.sh",
        "migrations/002_remove_conversation_capture.sql",
        "migrations/005_app_least_privilege.sql",
    ):
        path = root / relative
        text = _read(path)
        _require(text, sub2api["version"], path)
    for relative in ("deploy/configure-redis-acl.py", "deploy/migrate-redis-allowlist.py"):
        path = root / relative
        _require(_read(path), sub2api["source_revision"], path)

    policy_json = _read(root / "deploy" / "redis-key-prefixes.json")
    try:
        redis_policy = json.loads(policy_json)
    except json.JSONDecodeError as error:
        raise ReleasePolicyError("Redis key policy is invalid JSON") from error
    if (
        redis_policy.get("reviewed_sub2api_version") != sub2api["version"]
        or redis_policy.get("reviewed_source_revision") != sub2api["source_revision"]
    ):
        raise ReleasePolicyError("Redis key policy does not match the reviewed release")

    deploy_readme = root / "deploy" / "README.md"
    deploy_text = _read(deploy_readme)
    _require(deploy_text, f"Sub2API {sub2api['version']}", deploy_readme)
    _require_no(deploy_text, "0.1.162", deploy_readme)
    return True


def main(argv=None):
    del argv
    try:
        verify()
    except ReleasePolicyError as error:
        print(f"release policy check failed: {error}", file=sys.stderr)
        return 1
    print(
        "release policy verified: "
        f"Sub2API {read_policy()['sub2api']['version']}, "
        "PostgreSQL 18, Redis 8.8.0, and sync image pg18.4-r1"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
