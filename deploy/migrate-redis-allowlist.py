#!/usr/bin/env python3
import datetime
import decimal
import hashlib
import json
import os
import pathlib
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass


EXPECTED_CATEGORIES = {
    "session",
    "oauth",
    "scheduler",
    "billing",
    "concurrency",
    "sync_nonce",
}
EXPECTED_DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
DATA_ROOT_UID = 0
DATA_ROOT_GID = 0
REDIS_UID = 999
REDIS_GID = 1000
PRIVATE_DIRECTORY_MODE = 0o700
ALLOWED_KEY_PREFIXES = "deploy/redis-key-prefixes.json"
MAX_SCAN_PAGES = 100_000
MAX_KEYS = 500_000
SCAN_COUNT = 500
MAX_KEY_BYTES = 1_024
MAX_DUMP_BYTES = 16 * 1024 * 1024
MAX_COLLECTION_ITEMS = 10_000
MAX_VALIDATED_STRING_BYTES = 8 * 1024
DEADLINE_SECONDS = 180
MAX_NONCE_TTL_MS = 601_000
MIGRATION_USERNAME = "sub2api_migration"
VALID_REDIS_TYPES = {"string", "hash", "set"}
VALID_VALUE_FORMATS = {
    "api_key_rate_hash",
    "finite_number",
    "nonnegative_integer",
    "one_marker",
    "platform_quota_dirty_set",
    "platform_quota_hash",
    "refresh_token_metadata",
    "sha256_set",
    "subscription_hash",
}


class MigrationError(RuntimeError):
    pass


class RedisReplyError(MigrationError):
    pass


def _require_private_directory(path, owner, label):
    try:
        path_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError(f"{label} must already exist") from exc
    if path.is_symlink() or not stat.S_ISDIR(path_stat.st_mode) or resolved != path:
        raise MigrationError(f"{label} must be a real directory")
    if (
        (path_stat.st_uid, path_stat.st_gid) != owner
        or stat.S_IMODE(path_stat.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        if label == "SUB2API_DATA_ROOT":
            raise MigrationError(
                "SUB2API_DATA_ROOT must be owned by root:root with mode 0700"
            )
        raise MigrationError(
            f"{label} must be owned by 999:1000 with mode 0700"
        )
    return resolved


def require_private_migration_storage():
    configured = os.environ.get("SUB2API_DATA_ROOT")
    if not configured:
        raise MigrationError("SUB2API_DATA_ROOT is required with --apply")
    data_root = pathlib.Path(configured)
    if data_root != EXPECTED_DATA_ROOT:
        raise MigrationError("SUB2API_DATA_ROOT must be /mnt/data/sub2api-gate")
    _require_private_directory(
        data_root, (DATA_ROOT_UID, DATA_ROOT_GID), "SUB2API_DATA_ROOT"
    )
    redis_root = data_root / "redis"
    _require_private_directory(
        redis_root, (REDIS_UID, REDIS_GID), "Redis data directory"
    )
    return _require_private_directory(
        redis_root / "nonce", (REDIS_UID, REDIS_GID), "Redis nonce directory"
    )


@dataclass(frozen=True)
class RedisCopyRule:
    category: str
    prefix: bytes
    key_pattern: re.Pattern
    redis_type: bytes
    value_format: str
    source: str


class RedisEndpoint:
    def __init__(self, scheme, host, port, database):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.database = database

    def identity(self):
        return self.scheme, self.host.lower(), self.port, self.database


def encode_command(*parts):
    encoded_parts = []
    for part in parts:
        if isinstance(part, bytes):
            encoded = part
        elif isinstance(part, str):
            encoded = part.encode("utf-8")
        elif isinstance(part, int):
            encoded = str(part).encode("ascii")
        else:
            raise TypeError("unsupported Redis command argument")
        encoded_parts.append(encoded)
    chunks = [b"*" + str(len(encoded_parts)).encode("ascii") + b"\r\n"]
    for encoded in encoded_parts:
        chunks.extend(
            (
                b"$" + str(len(encoded)).encode("ascii") + b"\r\n",
                encoded,
                b"\r\n",
            )
        )
    return b"".join(chunks)


def parse_redis_url(value, label):
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise MigrationError(f"{label} Redis URL is invalid") from exc
    if parsed.scheme not in {"redis", "rediss"}:
        raise MigrationError(f"{label} Redis URL must use redis or rediss")
    if parsed.username is not None or parsed.password is not None:
        raise MigrationError(f"{label} Redis URL must not contain credentials")
    if parsed.query or parsed.fragment or not parsed.hostname:
        raise MigrationError(f"{label} Redis URL is invalid")
    path = parsed.path or "/0"
    if not path.startswith("/") or not path[1:].isdigit():
        raise MigrationError(f"{label} Redis URL must contain a numeric database")
    database = int(path[1:])
    if database < 0 or database > 15:
        raise MigrationError(f"{label} Redis database is outside the reviewed range")
    try:
        port = parsed.port or (6380 if parsed.scheme == "rediss" else 6379)
    except ValueError as exc:
        raise MigrationError(f"{label} Redis URL port is invalid") from exc
    return RedisEndpoint(parsed.scheme, parsed.hostname, port, database)


def _validate_prefix(value, label):
    if not isinstance(value, str) or not value or len(value) > 128:
        raise MigrationError(f"invalid Redis prefix in {label}")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise MigrationError(f"invalid Redis prefix in {label}") from exc
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise MigrationError(f"invalid Redis prefix in {label}")
    return encoded


def _validate_source_reference(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or value.startswith("/")
        or ".." in pathlib.PurePosixPath(value).parts
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
    ):
        raise MigrationError("Redis policy source reference is invalid")
    return value


def _load_copy_rule(category, entry):
    expected_fields = {
        "prefix",
        "key_pattern",
        "redis_type",
        "value_format",
        "source",
    }
    if not isinstance(entry, dict) or set(entry) != expected_fields:
        raise MigrationError("Redis copy rule schema is invalid")
    prefix = _validate_prefix(entry["prefix"], category)
    pattern_text = entry["key_pattern"]
    if not isinstance(pattern_text, str) or len(pattern_text) > 512:
        raise MigrationError("Redis key pattern is invalid")
    try:
        pattern_bytes = pattern_text.encode("ascii")
        pattern = re.compile(pattern_bytes)
    except (UnicodeEncodeError, re.error) as exc:
        raise MigrationError("Redis key pattern is invalid") from exc
    if not pattern_text.startswith("^") or not pattern_text.endswith("$"):
        raise MigrationError("Redis key pattern must be fully anchored")
    redis_type = entry["redis_type"]
    if redis_type not in VALID_REDIS_TYPES:
        raise MigrationError("Redis copy rule type is invalid")
    value_format = entry["value_format"]
    if value_format not in VALID_VALUE_FORMATS:
        raise MigrationError("Redis copy rule value format is invalid")
    source = _validate_source_reference(entry["source"])
    return RedisCopyRule(
        category=category,
        prefix=prefix,
        key_pattern=pattern,
        redis_type=redis_type.encode("ascii"),
        value_format=value_format,
        source=source,
    )


def load_prefix_policy(path):
    policy_path = pathlib.Path(path)
    try:
        file_stat = policy_path.stat(follow_symlinks=False)
    except OSError as exc:
        raise MigrationError("Redis prefix policy is unavailable") from exc
    if not stat.S_ISREG(file_stat.st_mode) or policy_path.is_symlink():
        raise MigrationError("Redis prefix policy must be a regular file")
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationError("Redis prefix policy is invalid") from exc
    if set(policy) != {
        "version",
        "reviewed_sub2api_version",
        "reviewed_source_revision",
        "categories",
        "discard_prefixes",
        "forbidden_prefixes",
    }:
        raise MigrationError("Redis prefix policy schema is invalid")
    if (
        policy.get("version") != 2
        or policy.get("reviewed_sub2api_version") != "0.1.162"
        or policy.get("reviewed_source_revision")
        != "27f094e0960ebd8e52de7ff7e763c6fec2ff4057"
        or set(policy.get("categories", {})) != EXPECTED_CATEGORIES
    ):
        raise MigrationError("Redis prefix policy categories are invalid")
    allowed = []
    for category in sorted(EXPECTED_CATEGORIES):
        entries = policy["categories"].get(category)
        if not isinstance(entries, list):
            raise MigrationError("Redis prefix policy category is invalid")
        allowed.extend(_load_copy_rule(category, entry) for entry in entries)
    if not allowed:
        raise MigrationError("Redis copy policy is empty")

    discarded_entries = policy.get("discard_prefixes")
    if not isinstance(discarded_entries, list) or not discarded_entries:
        raise MigrationError("Redis discard policy is empty")
    discarded = []
    for entry in discarded_entries:
        if not isinstance(entry, dict) or set(entry) != {"prefix", "reason", "source"}:
            raise MigrationError("Redis discard rule schema is invalid")
        reason = entry["reason"]
        if not isinstance(reason, str) or not 8 <= len(reason) <= 256:
            raise MigrationError("Redis discard rule reason is invalid")
        _validate_source_reference(entry["source"])
        discarded.append(_validate_prefix(entry["prefix"], "discard"))

    forbidden_values = policy.get("forbidden_prefixes")
    if not isinstance(forbidden_values, list) or not forbidden_values:
        raise MigrationError("Redis forbidden prefix policy is empty")
    forbidden = [_validate_prefix(value, "forbidden") for value in forbidden_values]
    allowed_prefixes = [rule.prefix for rule in allowed]
    all_prefixes = allowed_prefixes + discarded + forbidden
    if len(set(all_prefixes)) != len(all_prefixes):
        raise MigrationError("Redis prefix policy contains duplicates")
    if any(
        left.startswith(right) or right.startswith(left)
        for index, left in enumerate(all_prefixes)
        for right in all_prefixes[index + 1 :]
    ):
        raise MigrationError("Redis prefix policy contains overlapping rules")
    return tuple(allowed), tuple(discarded), tuple(forbidden)


def is_allowed_key(key, allowed, forbidden):
    if not isinstance(key, bytes) or not key or len(key) > MAX_KEY_BYTES:
        return False
    if any(key.startswith(prefix) for prefix in forbidden):
        return False
    return any(
        key.startswith(rule.prefix) and rule.key_pattern.fullmatch(key)
        for rule in allowed
    )


def is_discarded_key(key, discarded):
    return (
        isinstance(key, bytes)
        and bool(key)
        and len(key) <= MAX_KEY_BYTES
        and any(key.startswith(prefix) for prefix in discarded)
    )


class RedisConnection:
    def __init__(self, endpoint, password, deadline, username=None):
        self.endpoint = endpoint
        self.password = password
        self.deadline = deadline
        self.username = username
        self.sock = None
        self.reader = None

    def __enter__(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise MigrationError("Redis migration deadline exceeded")
        timeout = min(10.0, remaining)
        sock = socket.create_connection(
            (self.endpoint.host, self.endpoint.port), timeout=timeout
        )
        if self.endpoint.scheme == "rediss":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self.endpoint.host)
        sock.settimeout(timeout)
        self.sock = sock
        self.reader = sock.makefile("rb", buffering=0)
        try:
            if self.password:
                auth = (
                    ("AUTH", self.username, self.password)
                    if self.username
                    else ("AUTH", self.password)
                )
                _expect_ok(self.execute(*auth), "Redis authentication")
            if self.endpoint.database:
                _expect_ok(self.execute("SELECT", self.endpoint.database), "Redis database selection")
        except Exception:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        if self.reader is not None:
            self.reader.close()
        if self.sock is not None:
            self.sock.close()
        self.reader = None
        self.sock = None

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise MigrationError("Redis migration deadline exceeded")
        self.sock.settimeout(min(10.0, remaining))

    def _readline(self):
        line = self.reader.readline(1024 * 1024 + 1)
        if not line or len(line) > 1024 * 1024 or not line.endswith(b"\r\n"):
            raise MigrationError("invalid Redis response")
        return line[:-2]

    def _read_reply(self):
        self._remaining()
        marker = self.reader.read(1)
        if marker == b"+":
            return self._readline()
        if marker == b"-":
            self._readline()
            raise RedisReplyError("Redis command was rejected")
        if marker == b":":
            try:
                return int(self._readline())
            except ValueError as exc:
                raise MigrationError("invalid Redis integer response") from exc
        if marker == b"$":
            try:
                length = int(self._readline())
            except ValueError as exc:
                raise MigrationError("invalid Redis bulk response") from exc
            if length == -1:
                return None
            if length < 0 or length > MAX_DUMP_BYTES:
                raise MigrationError("Redis value exceeds the migration limit")
            value = self.reader.read(length)
            trailer = self.reader.read(2)
            if len(value) != length or trailer != b"\r\n":
                raise MigrationError("truncated Redis bulk response")
            return value
        if marker == b"*":
            try:
                length = int(self._readline())
            except ValueError as exc:
                raise MigrationError("invalid Redis array response") from exc
            if length == -1:
                return None
            if length < 0 or length > MAX_KEYS + 16:
                raise MigrationError("Redis array response exceeds the migration limit")
            return [self._read_reply() for _ in range(length)]
        raise MigrationError("unsupported Redis response")

    def execute(self, *parts):
        self._remaining()
        self.sock.sendall(encode_command(*parts))
        return self._read_reply()


def parse_info(raw):
    if not isinstance(raw, bytes):
        raise MigrationError("Redis INFO response is invalid")
    result = {}
    for line in raw.splitlines():
        if not line or line.startswith(b"#") or b":" not in line:
            continue
        key, value = line.split(b":", 1)
        try:
            result[key.decode("ascii")] = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise MigrationError("Redis INFO response is invalid") from exc
    return result


def scan_source_keys(source, allowed, discarded, forbidden):
    cursor = 0
    pages = 0
    keys = set()
    discarded_count = 0
    unknown_count = 0
    while True:
        pages += 1
        if pages > MAX_SCAN_PAGES:
            raise MigrationError("Redis SCAN page limit exceeded")
        reply = source.execute("SCAN", cursor, "COUNT", SCAN_COUNT)
        if not isinstance(reply, list) or len(reply) != 2 or not isinstance(reply[1], list):
            raise MigrationError("Redis SCAN response is invalid")
        try:
            cursor = int(reply[0])
        except (TypeError, ValueError) as exc:
            raise MigrationError("Redis SCAN cursor is invalid") from exc
        for key in reply[1]:
            if is_allowed_key(key, allowed, forbidden):
                keys.add(key)
                if len(keys) > MAX_KEYS:
                    raise MigrationError("Redis key count exceeds the migration limit")
                continue
            if is_discarded_key(key, discarded):
                discarded_count += 1
                if discarded_count > MAX_KEYS:
                    raise MigrationError("Redis discarded key count exceeds the migration limit")
                continue
            unknown_count += 1
        if cursor == 0:
            break
    if unknown_count:
        raise MigrationError(
            "unknown Redis key prefix or forbidden content cache; migration refused"
        )
    return sorted(keys), discarded_count


def _rule_for_key(key, allowed):
    matches = [
        rule
        for rule in allowed
        if key.startswith(rule.prefix) and rule.key_pattern.fullmatch(key)
    ]
    if len(matches) != 1:
        raise MigrationError("Redis key did not resolve to exactly one copy rule")
    return matches[0]


def _ascii_value(value, label, allow_empty=False):
    if not isinstance(value, bytes) or len(value) > MAX_VALIDATED_STRING_BYTES:
        raise MigrationError(f"Redis {label} value is invalid")
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MigrationError(f"Redis {label} value is invalid") from exc
    if (not allow_empty and not decoded) or any(ord(char) < 0x20 for char in decoded):
        raise MigrationError(f"Redis {label} value is invalid")
    return decoded


def _validate_decimal_text(value, label, nonnegative=False, allow_empty=False):
    text = _ascii_value(value, label, allow_empty=allow_empty)
    if allow_empty and not text:
        return
    if len(text) > 64:
        raise MigrationError(f"Redis {label} number is invalid")
    try:
        parsed = decimal.Decimal(text)
    except decimal.InvalidOperation as exc:
        raise MigrationError(f"Redis {label} number is invalid") from exc
    if not parsed.is_finite() or abs(parsed) > decimal.Decimal("1e18"):
        raise MigrationError(f"Redis {label} number is invalid")
    if nonnegative and parsed < 0:
        raise MigrationError(f"Redis {label} number is invalid")


def _validate_integer_text(value, label, nonnegative=True, allow_empty=False):
    text = _ascii_value(value, label, allow_empty=allow_empty)
    if allow_empty and not text:
        return
    pattern = r"[0-9]{1,20}" if nonnegative else r"-?[0-9]{1,20}"
    if not re.fullmatch(pattern, text):
        raise MigrationError(f"Redis {label} integer is invalid")
    parsed = int(text)
    if parsed > 2**63 - 1 or (not nonnegative and parsed < -(2**63)):
        raise MigrationError(f"Redis {label} integer is invalid")


def _pairs_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _validate_refresh_token_metadata(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > 2048:
        raise MigrationError("Redis refresh token metadata is invalid")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise MigrationError("Redis refresh token metadata is invalid") from exc
    required = {"user_id", "token_version", "family_id", "created_at", "expires_at"}
    if not isinstance(document, dict) or not required <= set(document) <= required | {"binding_hash"}:
        raise MigrationError("Redis refresh token metadata fields are invalid")
    if (
        isinstance(document["user_id"], bool)
        or not isinstance(document["user_id"], int)
        or document["user_id"] <= 0
        or isinstance(document["token_version"], bool)
        or not isinstance(document["token_version"], int)
        or document["token_version"] < 0
        or not isinstance(document["family_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", document["family_id"])
    ):
        raise MigrationError("Redis refresh token metadata identifiers are invalid")
    binding_hash = document.get("binding_hash", "")
    if not isinstance(binding_hash, str) or (
        binding_hash and not re.fullmatch(r"[0-9a-f]{32}", binding_hash)
    ):
        raise MigrationError("Redis refresh token binding hash is invalid")
    parsed_times = []
    for field in ("created_at", "expires_at"):
        value = document[field]
        if not isinstance(value, str) or not 10 <= len(value) <= 64:
            raise MigrationError("Redis refresh token timestamp is invalid")
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MigrationError("Redis refresh token timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise MigrationError("Redis refresh token timestamp is invalid")
        parsed_times.append(parsed)
    if parsed_times[1] <= parsed_times[0]:
        raise MigrationError("Redis refresh token timestamp order is invalid")


def _hash_from_reply(reply):
    if (
        not isinstance(reply, list)
        or len(reply) % 2
        or len(reply) > MAX_COLLECTION_ITEMS * 2
    ):
        raise MigrationError("Redis hash response is invalid")
    result = {}
    for index in range(0, len(reply), 2):
        field, value = reply[index], reply[index + 1]
        if not isinstance(field, bytes) or not isinstance(value, bytes) or field in result:
            raise MigrationError("Redis hash response is invalid")
        result[field] = value
    return result


def _require_hash_fields(fields, expected):
    encoded_expected = {name.encode("ascii") for name in expected}
    if set(fields) != encoded_expected:
        raise MigrationError("Redis hash contains unreviewed fields")


def _validate_subscription_hash(fields):
    expected = {
        "status",
        "expires_at",
        "daily_usage",
        "weekly_usage",
        "monthly_usage",
        "version",
    }
    _require_hash_fields(fields, expected)
    status = _ascii_value(fields[b"status"], "subscription status")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", status):
        raise MigrationError("Redis subscription status is invalid")
    _validate_integer_text(fields[b"expires_at"], "subscription expiry")
    _validate_integer_text(fields[b"version"], "subscription version")
    for name in (b"daily_usage", b"weekly_usage", b"monthly_usage"):
        _validate_decimal_text(fields[name], "subscription usage", nonnegative=True)


def _validate_api_key_rate_hash(fields):
    expected = {
        "usage_5h",
        "usage_1d",
        "usage_7d",
        "window_5h",
        "window_1d",
        "window_7d",
    }
    _require_hash_fields(fields, expected)
    for name in (b"usage_5h", b"usage_1d", b"usage_7d"):
        _validate_decimal_text(fields[name], "API key rate usage", nonnegative=True)
    for name in (b"window_5h", b"window_1d", b"window_7d"):
        _validate_integer_text(fields[name], "API key rate window")


def _validate_platform_quota_hash(fields):
    expected = {
        "daily_usage",
        "weekly_usage",
        "monthly_usage",
        "version",
        "schema_version",
        "daily_limit",
        "weekly_limit",
        "monthly_limit",
        "daily_window_start",
        "weekly_window_start",
        "monthly_window_start",
    }
    _require_hash_fields(fields, expected)
    for name in (b"daily_usage", b"weekly_usage", b"monthly_usage"):
        _validate_decimal_text(fields[name], "platform quota usage", nonnegative=True)
    for name in (b"version", b"schema_version"):
        _validate_integer_text(fields[name], "platform quota version")
    for name in (b"daily_limit", b"weekly_limit", b"monthly_limit"):
        _validate_decimal_text(
            fields[name], "platform quota limit", nonnegative=True, allow_empty=True
        )
    for name in (
        b"daily_window_start",
        b"weekly_window_start",
        b"monthly_window_start",
    ):
        _validate_integer_text(
            fields[name], "platform quota window", allow_empty=True
        )


def _validate_set_members(reply, value_format):
    if not isinstance(reply, list) or len(reply) > MAX_COLLECTION_ITEMS:
        raise MigrationError("Redis set response is invalid")
    if value_format == "sha256_set":
        if not all(
            isinstance(member, bytes) and re.fullmatch(rb"[0-9a-f]{64}", member)
            for member in reply
        ):
            raise MigrationError("Redis token hash set is invalid")
        return
    if value_format == "platform_quota_dirty_set":
        if not all(
            isinstance(member, bytes)
            and re.fullmatch(rb"[1-9][0-9]*:[a-z][a-z0-9_-]{0,31}", member)
            for member in reply
        ):
            raise MigrationError("Redis platform quota dirty set is invalid")
        return
    raise MigrationError("Redis set validator is unavailable")


def validate_source_key_value(source, key, rule):
    actual_type = source.execute("TYPE", key)
    if actual_type != rule.redis_type:
        raise MigrationError("Redis key type does not match the reviewed policy")
    if rule.redis_type == b"string":
        value = source.execute("GET", key)
        if rule.value_format == "refresh_token_metadata":
            _validate_refresh_token_metadata(value)
        elif rule.value_format == "finite_number":
            _validate_decimal_text(value, "numeric cache")
        elif rule.value_format == "nonnegative_integer":
            _validate_integer_text(value, "counter cache")
        elif rule.value_format == "one_marker":
            if value != b"1":
                raise MigrationError("Redis marker value is invalid")
        else:
            raise MigrationError("Redis string validator is unavailable")
        return
    if rule.redis_type == b"set":
        _validate_set_members(source.execute("SMEMBERS", key), rule.value_format)
        return
    fields = _hash_from_reply(source.execute("HGETALL", key))
    if rule.value_format == "subscription_hash":
        _validate_subscription_hash(fields)
    elif rule.value_format == "api_key_rate_hash":
        _validate_api_key_rate_hash(fields)
    elif rule.value_format == "platform_quota_hash":
        _validate_platform_quota_hash(fields)
    else:
        raise MigrationError("Redis hash validator is unavailable")


def validate_source_values(source, keys, allowed):
    for key in keys:
        validate_source_key_value(source, key, _rule_for_key(key, allowed))


def _config_value(reply, expected_name):
    if not isinstance(reply, list) or len(reply) != 2:
        raise MigrationError("Redis CONFIG response is invalid")
    if reply[0] != expected_name.encode("ascii") or not isinstance(reply[1], bytes):
        raise MigrationError("Redis CONFIG response is invalid")
    return reply[1].decode("ascii", errors="strict").lower()


def _expect_ok(reply, operation):
    if reply != b"OK":
        raise MigrationError(f"{operation} did not return OK")


def rollback_target_keys(target, copied_keys):
    for offset in range(0, len(copied_keys), 100):
        target.execute("UNLINK", *copied_keys[offset : offset + 100])


def migrate_redis(source, target, allowed, discarded, forbidden):
    source_info = parse_info(source.execute("INFO", "server"))
    keys, discarded_count = scan_source_keys(
        source, allowed, discarded, forbidden
    )
    validate_source_values(source, keys, allowed)
    print(
        "checkpoint: source Redis key and value allowlist passed "
        f"({len(keys)} copy, {discarded_count} discard)"
    )

    target_info = parse_info(target.execute("INFO", "server"))
    expected_version = "8.8.0"
    if target_info.get("redis_version") != expected_version:
        raise MigrationError("target Redis server must be exactly version 8.8.0")
    if (
        source_info.get("run_id")
        and source_info.get("run_id") == target_info.get("run_id")
        and source.endpoint.database == target.endpoint.database
    ):
        raise MigrationError("source and target Redis databases must be distinct")
    if target.execute("DBSIZE") != 0:
        raise MigrationError("target Redis database is not fresh and empty")
    target_keyspace = parse_info(target.execute("INFO", "keyspace"))
    if any(name.startswith("db") for name in target_keyspace):
        raise MigrationError("target Redis server has keys outside the selected database")
    appendonly = _config_value(target.execute("CONFIG", "GET", "appendonly"), "appendonly")
    appendfsync = _config_value(target.execute("CONFIG", "GET", "appendfsync"), "appendfsync")
    save_policy = _config_value(target.execute("CONFIG", "GET", "save"), "save")
    maxmemory = _config_value(target.execute("CONFIG", "GET", "maxmemory"), "maxmemory")
    maxmemory_policy = _config_value(
        target.execute("CONFIG", "GET", "maxmemory-policy"), "maxmemory-policy"
    )
    if (
        appendonly != "yes"
        or appendfsync != "always"
        or save_policy
        or maxmemory != "33554432"
        or maxmemory_policy != "noeviction"
    ):
        raise MigrationError(
            "target nonce Redis must use durable AOF, disabled RDB, and the reviewed memory limit"
        )
    print("checkpoint: empty Redis 8.8.0 nonce target with crash-durable AOF verified")

    attempted_keys = []
    try:
        for key in keys:
            payload = source.execute("DUMP", key)
            if payload is None:
                continue
            ttl = source.execute("PTTL", key)
            if ttl == -2:
                continue
            if not isinstance(ttl, int) or not 1 <= ttl <= MAX_NONCE_TTL_MS:
                raise MigrationError("source Redis nonce TTL is invalid")
            # RESTORE may commit before a socket timeout. Record the key first so
            # rollback unlinks it even when no response reaches this process.
            attempted_keys.append(key)
            _expect_ok(
                target.execute("RESTORE", key, ttl, payload),
                "Redis RESTORE",
            )
    except Exception:
        try:
            rollback_target_keys(target, attempted_keys)
        except Exception:
            pass
        raise
    print(
        f"checkpoint: {len(attempted_keys)} nonce markers restored into "
        "appendfsync-always AOF"
    )


def require_environment(name, allow_empty=False):
    if name not in os.environ or (not allow_empty and not os.environ[name]):
        raise MigrationError(f"{name} is required with --apply")
    return os.environ[name]


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    mode = args[0] if args else "check"
    if len(args) > 1 or mode not in {"check", "--apply"}:
        print(f"usage: {pathlib.Path(sys.argv[0]).name} [check|--apply]", file=sys.stderr)
        return 2

    repo_dir = pathlib.Path(__file__).resolve().parents[1]
    policy_path = repo_dir / ALLOWED_KEY_PREFIXES
    allowed, discarded, forbidden = load_prefix_policy(policy_path)
    policy_digest = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    print(f"Redis migration prefix policy sha256: {policy_digest}")
    print("only unexpired HMAC sync nonce markers are copied")
    print("Sub2API cache, raw OAuth tokens, credentials, content-derived identifiers, and old AOF history are never copied")
    if mode != "--apply":
        print("check only; no connection was opened")
        return 0

    subprocess.run([repo_dir / "deploy" / "require-clean-worktree.sh", "check"], check=True)
    if os.environ.get("SUB2API_MIGRATION_WRITES_STOPPED") != "YES":
        raise MigrationError(
            "set SUB2API_MIGRATION_WRITES_STOPPED=YES only after all source writers are stopped"
        )
    require_private_migration_storage()
    source_url = require_environment("SUB2API_SOURCE_REDIS_URL")
    target_url = require_environment("SUB2API_TARGET_REDIS_URL")
    source_password = require_environment(
        "SUB2API_SOURCE_REDIS_PASSWORD", allow_empty=True
    )
    source_username = os.environ.get("SUB2API_SOURCE_REDIS_USERNAME") or None
    target_password = require_environment("SUB2API_TARGET_REDIS_PASSWORD")
    target_username = require_environment("SUB2API_TARGET_REDIS_USERNAME")
    if len(target_password) < 24:
        raise MigrationError("target Redis password must contain at least 24 characters")
    if target_username != MIGRATION_USERNAME:
        raise MigrationError(
            "target Redis must use the one-time sub2api_migration principal"
        )
    if source_username is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", source_username):
        raise MigrationError("source Redis username is invalid")
    source_endpoint = parse_redis_url(source_url, "source")
    target_endpoint = parse_redis_url(target_url, "target")
    if source_endpoint.identity() == target_endpoint.identity():
        raise MigrationError("source and target Redis endpoints must differ")

    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        with RedisConnection(
            source_endpoint, source_password, deadline, source_username
        ) as source:
            with RedisConnection(
                target_endpoint, target_password, deadline, target_username
            ) as target:
                migrate_redis(source, target, allowed, discarded, forbidden)
    except MigrationError:
        raise
    except (OSError, ssl.SSLError) as exc:
        raise MigrationError("Redis connection failed") from exc
    print("Redis allowlist migration completed within the 180 second deadline")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MigrationError, subprocess.CalledProcessError) as error:
        if isinstance(error, MigrationError):
            print(str(error), file=sys.stderr)
        else:
            print("release worktree gate failed", file=sys.stderr)
        raise SystemExit(1)
