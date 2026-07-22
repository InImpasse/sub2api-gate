#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import select
import socket
import string
import subprocess
import threading
import time
import urllib.error
import urllib.request
from usage_metadata import (
    get_usage_log_detail as metadata_usage_log_detail,
    list_usage_logs as metadata_usage_logs,
    usage_log_filters,
)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY_BYTES = 16 * 1024
MAX_LOGIN_RESPONSE_BYTES = 64 * 1024
MAX_LOGIN_AUTH_TOKEN_BYTES = 4 * 1024
MAX_LOGIN_AUTH_RESPONSE_BYTES = 14 * 1024
MAX_LOGIN_USER_FIELD_BYTES = 512
MAX_SAFE_IDENTIFIER = 9_007_199_254_740_991
MAX_USER_API_KEYS = 100
HTTP_CONNECTION_TIMEOUT_SECONDS = 5
MAX_REQUEST_THREADS = 16
DEFAULT_KEY_NAME = "Sub2API"
DEFAULT_BASE_URL = "https://api.example.com/v1"
DEFAULT_USER_BALANCE = "100"
DEFAULT_SUBSCRIPTION_DAYS = 36500
SIGNATURE_MAX_SKEW_SECONDS = 300
NONCE_TTL_SECONDS = SIGNATURE_MAX_SKEW_SECONDS * 2 + 1
DEFAULT_DB_STATEMENT_TIMEOUT_MS = 10_000
USAGE_DB_STATEMENT_TIMEOUT_MS = 2_000
USAGE_DB_CLIENT_TIMEOUT_SECONDS = 3
TOKEN_ID_FIELDS = (
    "sub2apiTokenId",
    "sub2apiApiKeyId",
    "tokenId",
    "apiKeyId",
)
USER_ID_FIELDS = (
    "sub2apiUserId",
    "userId",
)
SYNC_ACTIONS = frozenset({
    "provision",
    "status",
    "login",
    "deprovision",
    "purge",
    "usage_logs_list",
    "usage_log_detail",
})
LOGIN_USER_FIELDS = (
    "id",
    "username",
    "name",
    "email",
    "role",
    "status",
    "balance",
    "avatar",
    "created_at",
    "updated_at",
)
_DATABASE_TRANSACTION = threading.local()


def env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def get_secret():
    secret = os.environ.get("SUB2API_SYNC_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("SUB2API_SYNC_SECRET must be at least 32 characters")
    return secret


def sql_quote(value, max_length=None):
    text = "" if value is None else str(value)
    if max_length is not None:
        text = text[:max_length]
    return "'" + text.replace("\\", "\\\\").replace("'", "''").replace("\0", "") + "'"


def jsonb(value):
    text = json.dumps(value, separators=(",", ":"))
    return "'" + text.replace("'", "''").replace("\0", "") + "'::jsonb"



def query_json_value(sql):
    output = psql(
        sql,
        timeout=USAGE_DB_CLIENT_TIMEOUT_SECONDS,
        statement_timeout_ms=USAGE_DB_STATEMENT_TIMEOUT_MS,
    )
    return json.loads(output) if output else None


def _database_connection(statement_timeout_ms):
    database_host = os.environ.get("SUB2API_SYNC_DATABASE_HOST", "postgres")
    database_port = str(env_int("SUB2API_SYNC_DATABASE_PORT", 5432))
    database_user = os.environ.get("SUB2API_SYNC_DATABASE_USER", "sub2api_sync")
    database_name = os.environ.get("SUB2API_SYNC_DATABASE_NAME", "sub2api")
    database_password = os.environ.get("SUB2API_SYNC_DATABASE_PASSWORD", "")
    if not database_password:
        raise RuntimeError("database_configuration_invalid")
    command = [
        "psql",
        "--host", database_host,
        "--port", database_port,
        "--username", database_user,
        "--dbname", database_name,
        "--no-psqlrc",
        "--quiet",
        "--tuples-only",
        "--no-align",
        "--field-separator", "\t",
        "--set", "ON_ERROR_STOP=1",
    ]
    process_env = os.environ.copy()
    process_env["PGPASSWORD"] = database_password
    process_env["PGOPTIONS"] = (
        f"-c statement_timeout={statement_timeout_ms} -c lock_timeout=2000"
    )
    return command, process_env


def _validated_statement_timeout(statement_timeout_ms):
    if isinstance(statement_timeout_ms, bool):
        raise ValueError("database_statement_timeout_invalid")
    try:
        statement_timeout_ms = int(statement_timeout_ms)
    except (TypeError, ValueError) as error:
        raise ValueError("database_statement_timeout_invalid") from error
    if not 1 <= statement_timeout_ms <= 60_000:
        raise ValueError("database_statement_timeout_invalid")
    return statement_timeout_ms


class DatabaseTransaction:
    def __init__(self, timeout=12, statement_timeout_ms=DEFAULT_DB_STATEMENT_TIMEOUT_MS):
        self.timeout = timeout
        self.statement_timeout_ms = _validated_statement_timeout(statement_timeout_ms)
        self.process = None

    def __enter__(self):
        if getattr(_DATABASE_TRANSACTION, "session", None) is not None:
            raise RuntimeError("database_transaction_nested")
        command, process_env = _database_connection(self.statement_timeout_ms)
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            env=process_env,
        )
        self.output_buffer = b""
        _DATABASE_TRANSACTION.session = self
        try:
            self.execute("BEGIN;")
        except Exception:
            _DATABASE_TRANSACTION.session = None
            self._close()
            raise
        return self

    def __exit__(self, error_type, _error, _traceback):
        try:
            if error_type is None:
                self.execute("COMMIT;")
            elif self.process is not None and self.process.poll() is None:
                try:
                    self.execute("ROLLBACK;", timeout=min(self.timeout, 3))
                except Exception:
                    pass
        finally:
            _DATABASE_TRANSACTION.session = None
            self._close()
        return False

    def execute(self, sql, timeout=None):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError("database_command_failed")
        marker = "__sub2api_sync_" + secrets.token_hex(16) + "__"
        try:
            self.process.stdin.write((str(sql).rstrip() + "\n").encode())
            self.process.stdin.write(f"\\echo {marker}\n".encode())
            self.process.stdin.flush()
            lines = []
            deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
            while True:
                line = self._readline(deadline, timeout or self.timeout)
                if line == marker:
                    return "\n".join(lines).strip()
                lines.append(line)
        except (BrokenPipeError, OSError):
            raise RuntimeError("database_command_failed") from None

    def _readline(self, deadline, timeout):
        try:
            descriptor = self.process.stdout.fileno()
        except (AttributeError, OSError):
            line = self.process.stdout.readline()
            if line in (b"", ""):
                raise RuntimeError("database_command_failed")
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            return line.rstrip("\r\n")

        while b"\n" not in self.output_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("psql", timeout)
            ready, _writeable, _exceptional = select.select(
                [descriptor], [], [], remaining
            )
            if not ready:
                raise subprocess.TimeoutExpired("psql", timeout)
            chunk = os.read(descriptor, 4096)
            if not chunk:
                raise RuntimeError("database_command_failed")
            self.output_buffer += chunk
        line, self.output_buffer = self.output_buffer.split(b"\n", 1)
        return line.rstrip(b"\r").decode("utf-8", errors="replace")

    def _close(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b"\\q\n")
                self.process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
        try:
            self.process.stdin.close()
        except (AttributeError, OSError):
            pass
        try:
            self.process.stdout.close()
        except (AttributeError, OSError):
            pass
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def database_transaction(timeout=12, statement_timeout_ms=DEFAULT_DB_STATEMENT_TIMEOUT_MS):
    return DatabaseTransaction(timeout, statement_timeout_ms)


def psql(sql, timeout=12, statement_timeout_ms=DEFAULT_DB_STATEMENT_TIMEOUT_MS):
    statement_timeout_ms = _validated_statement_timeout(statement_timeout_ms)
    transaction = getattr(_DATABASE_TRANSACTION, "session", None)
    if transaction is not None:
        if statement_timeout_ms != transaction.statement_timeout_ms:
            raise ValueError("database_statement_timeout_mismatch")
        return transaction.execute(sql, timeout=timeout)
    command, process_env = _database_connection(statement_timeout_ms)
    result = subprocess.run(
        command,
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=process_env,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("database_command_failed")
    return result.stdout.strip()


def first_row(sql):
    output = psql(sql)
    if not output:
        return []
    return output.splitlines()[0].split("\t")


def rows(sql):
    output = psql(sql)
    if not output:
        return []
    return [line.split("\t") for line in output.splitlines()]


def sub2api_username(uuid):
    normalized = str(uuid or "").strip().lower()
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        normalized,
    ):
        raise ValueError("invalid uuid")
    compact = normalized.replace("-", "")
    return "u" + compact[:11]


def normalize_username(value):
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = re.sub(r"^[._-]+|[._-]+$", "", text)
    return text[:100]


def payload_identity(payload):
    uuid = str(payload.get("uuid", "")).strip().lower()
    legacy_username = sub2api_username(uuid)
    requested_username = normalize_username(payload.get("username"))
    name_username = normalize_username(payload.get("name"))
    if name_username and (not requested_username or requested_username == legacy_username):
        username = name_username
    else:
        username = requested_username or name_username or legacy_username
    return uuid, legacy_username, username


def default_email(username, email):
    text = str(email or "").strip().lower()
    if "@" in text and len(text) <= 255:
        return text
    return f"{username}@sub2api.local"


def api_key():
    return "sk-" + secrets.token_hex(32)


def is_api_key(value):
    text = str(value or "")
    allowed = set(string.ascii_letters + string.digits)
    if len(text) == 48 and all(ch in allowed for ch in text):
        return True
    return (
        text.startswith("sk-")
        and 1 <= len(text[3:]) <= 125
        and all(ch in allowed for ch in text[3:])
    )


def normalize_api_key(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if not is_api_key(text):
        raise ValueError("invalid api key")
    if text.startswith("sk-"):
        return text
    return "sk-" + text


def payload_identifier(payload, field_names):
    identifiers = set()
    for field_name in field_names:
        value = payload.get(field_name)
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            raise ValueError("invalid identifier")
        if isinstance(value, int):
            if value == 0:
                continue
            identifier = value
        elif isinstance(value, str):
            if value == "0":
                continue
            if not re.fullmatch(r"[1-9][0-9]{0,15}", value):
                raise ValueError("invalid identifier")
            identifier = int(value)
        else:
            raise ValueError("invalid identifier")
        if not 1 <= identifier <= MAX_SAFE_IDENTIFIER:
            raise ValueError("invalid identifier")
        identifiers.add(identifier)
    if len(identifiers) > 1:
        raise ValueError("conflicting identifiers")
    return next(iter(identifiers), 0)


def payload_token_id(payload):
    return payload_identifier(payload, TOKEN_ID_FIELDS)


def payload_user_id(payload):
    return payload_identifier(payload, USER_ID_FIELDS)


def invite_owner_fingerprint(uuid):
    return hmac.new(
        get_secret().encode(),
        b"sub2api-invite-owner:v1:" + str(uuid).encode(),
        hashlib.sha256,
    ).hexdigest()


def _invite_user_row(where, include_deleted):
    deleted_filter = "" if include_deleted else " AND u.deleted_at IS NULL"
    return first_row(
        "SELECT u.id,LEFT(COALESCE(u.username,''),100),"
        "LEFT(COALESCE(u.role,''),32),"
        "COALESCE(o.invite_fingerprint,''),"
        "LEFT(COALESCE(u.email,''),255),COALESCE(u.password_hash,''),"
        "LEFT(COALESCE(u.status,''),16) "
        "FROM users u LEFT JOIN sub2api_sync_invite_owners o ON o.user_id=u.id "
        f"WHERE {where}{deleted_filter} LIMIT 1 FOR UPDATE OF u;"
    )


def _owned_invite_user_row(invite_fingerprint, include_deleted):
    deleted_filter = "" if include_deleted else " AND u.deleted_at IS NULL"
    return first_row(
        "SELECT u.id,LEFT(COALESCE(u.username,''),100),"
        "LEFT(COALESCE(u.role,''),32),o.invite_fingerprint,"
        "LEFT(COALESCE(u.email,''),255),COALESCE(u.password_hash,''),"
        "LEFT(COALESCE(u.status,''),16) "
        "FROM sub2api_sync_invite_owners o JOIN users u ON u.id=o.user_id "
        f"WHERE o.invite_fingerprint={sql_quote(invite_fingerprint, 64)}"
        f"{deleted_filter} LIMIT 1 FOR UPDATE OF u;"
    )


def _bind_or_validate_invite_user(row, uuid, expected_usernames, allow_bind=True):
    if not row or len(row) < 4:
        return []
    if row[2] != "user":
        raise RuntimeError("invite_identity_mismatch")
    expected_fingerprint = invite_owner_fingerprint(uuid)
    stored_fingerprint = str(row[3] or "")
    if stored_fingerprint:
        if not hmac.compare_digest(stored_fingerprint, expected_fingerprint):
            raise RuntimeError("invite_identity_mismatch")
        return row
    if not allow_bind:
        raise RuntimeError("invite_identity_mismatch")
    if str(row[1] or "") not in expected_usernames:
        raise RuntimeError("invite_identity_mismatch")
    psql(
        "INSERT INTO sub2api_sync_invite_owners "
        "(user_id,invite_fingerprint,created_at,updated_at) VALUES "
        f"({int(row[0])},{sql_quote(expected_fingerprint, 64)},now(),now()) "
        "ON CONFLICT (user_id) DO NOTHING;"
    )
    owner = first_row(
        "SELECT invite_fingerprint FROM sub2api_sync_invite_owners "
        f"WHERE user_id={int(row[0])} LIMIT 1;"
    )
    if not owner or not hmac.compare_digest(str(owner[0]), expected_fingerprint):
        raise RuntimeError("invite_identity_mismatch")
    row[3] = expected_fingerprint
    return row


def resolve_invite_user(
    uuid,
    legacy_username,
    username,
    user_id=0,
    api_key_id=0,
    include_deleted=False,
    allow_bind=True,
):
    expected_usernames = {legacy_username, username}
    if user_id > 0:
        row = _invite_user_row(f"u.id={int(user_id)}", include_deleted)
        if not row:
            raise RuntimeError("invite_identity_mismatch")
        row = _bind_or_validate_invite_user(
            row, uuid, expected_usernames, allow_bind=allow_bind
        )
    elif not allow_bind:
        expected_fingerprint = invite_owner_fingerprint(uuid)
        row = _owned_invite_user_row(expected_fingerprint, include_deleted)
        if not row and api_key_id > 0:
            raise RuntimeError("invite_identity_mismatch")
        row = _bind_or_validate_invite_user(
            row, uuid, expected_usernames, allow_bind=False
        )
    else:
        row = []
        for candidate in (username, legacy_username):
            if row or not candidate:
                continue
            row = _invite_user_row(
                f"u.username={sql_quote(candidate, 100)}", include_deleted
            )
        if not row and api_key_id > 0:
            row = _invite_user_row(
                "u.id=(SELECT key_owner.user_id FROM api_keys key_owner "
                f"WHERE key_owner.id={int(api_key_id)} LIMIT 1)",
                include_deleted,
            )
        row = _bind_or_validate_invite_user(
            row, uuid, expected_usernames, allow_bind=allow_bind
        )

    if row and api_key_id > 0:
        key_owner = first_row(
            f"SELECT user_id FROM api_keys WHERE id={int(api_key_id)} LIMIT 1;"
        )
        if key_owner and int(key_owner[0]) != int(row[0]):
            raise RuntimeError("invite_identity_mismatch")
    return row


def clean_key_name(value):
    text = str(value or "").strip()[:100]
    return text or DEFAULT_KEY_NAME


def requested_tokens(payload):
    if isinstance(payload.get("tokens"), list):
        items = payload.get("tokens") or []
    else:
        items = [{
            "tokenKey": payload.get("tokenKey") or payload.get("apiKey") or "",
            "tokenName": payload.get("tokenName") or payload.get("apiKeyName") or DEFAULT_KEY_NAME,
        }]

    result = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = normalize_api_key(item.get("tokenKey") or item.get("apiKey") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        result.append({
            "key": key,
            "name": clean_key_name(item.get("tokenName") or item.get("apiKeyName") or DEFAULT_KEY_NAME),
        })
        if len(result) > MAX_USER_API_KEYS:
            raise RuntimeError("api_key_limit_exceeded")
    return result


def login_password():
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(20))


def list_usage_logs(payload):
    return metadata_usage_logs(query_json_value, payload)


def get_usage_log_detail(payload):
    return metadata_usage_log_detail(query_json_value, payload)


def configured_groups():
    raw = os.environ.get("SUB2API_SYNC_DEFAULT_GROUP", "openai-default")
    groups = []
    seen = set()
    for part in str(raw).split(","):
        group = part.strip()[:100]
        if not group or group in seen:
            continue
        seen.add(group)
        groups.append(group)
    return groups or ["openai-default"]


def group_profile(group):
    name = str(group or "").strip().lower()
    if name == "default" or name.startswith("openai"):
        return "openai", "OpenAI-compatible gateway"
    if name.startswith("anthropic"):
        return "anthropic", "Anthropic gateway"
    if name.startswith("gemini"):
        return "gemini", "Gemini gateway"
    if name.startswith("antigravity"):
        return "antigravity", "Antigravity gateway"
    return "openai", "OpenAI-compatible gateway"


def ensure_group(group):
    platform, description = group_profile(group)
    psql(
        "INSERT INTO groups "
        "(name,description,platform,subscription_type,rate_multiplier,status,allow_messages_dispatch,created_at,updated_at) "
        "SELECT "
        f"{sql_quote(group)},{sql_quote(description)},"
        f"{sql_quote(platform)},'standard',0,'active',true,now(),now() "
        f"WHERE NOT EXISTS (SELECT 1 FROM groups WHERE name={sql_quote(group)} AND deleted_at IS NULL);"
        "UPDATE groups SET subscription_type='standard', rate_multiplier=0, "
        f"description=CASE WHEN COALESCE(description,'')='' THEN {sql_quote(description)} ELSE description END, "
        "status='active', allow_messages_dispatch=true, updated_at=now() "
        f"WHERE name={sql_quote(group)} AND deleted_at IS NULL;"
    )
    row = first_row(f"SELECT id FROM groups WHERE name={sql_quote(group)} AND deleted_at IS NULL LIMIT 1;")
    if not row:
        raise RuntimeError("sub2api group not found")
    return int(row[0])


def ensure_groups():
    return [(group, ensure_group(group)) for group in configured_groups()]


def subscription_days():
    days = env_int("SUB2API_SYNC_DEFAULT_SUBSCRIPTION_DAYS", DEFAULT_SUBSCRIPTION_DAYS)
    return max(1, min(days, DEFAULT_SUBSCRIPTION_DAYS))


def ensure_subscription_plan(group_id):
    plan_name = os.environ.get("SUB2API_SYNC_DEFAULT_PLAN_NAME", "Default")[:100] or "Default"
    days = subscription_days()
    psql(
        "INSERT INTO subscription_plans "
        "(group_id,name,description,price,original_price,validity_days,validity_unit,features,product_name,for_sale,sort_order,created_at,updated_at) "
        "SELECT "
        f"{int(group_id)},{sql_quote(plan_name, 100)},'Default subscription assigned by sub2api sync',0,0,{days},'day',"
        "'OpenAI-compatible access','Sub2API',false,0,now(),now() "
        "WHERE NOT EXISTS ("
        "SELECT 1 FROM subscription_plans "
        f"WHERE group_id={int(group_id)} AND name={sql_quote(plan_name, 100)}"
        ");"
        "UPDATE subscription_plans SET "
        f"description='Default subscription assigned by sub2api sync', price=0, original_price=0, validity_days={days}, "
        "validity_unit='day', features='OpenAI-compatible access', product_name='Sub2API', for_sale=false, updated_at=now() "
        f"WHERE group_id={int(group_id)} AND name={sql_quote(plan_name, 100)};"
    )


def ensure_default_subscription(user_id, group_id):
    days = subscription_days()
    psql(
        "INSERT INTO user_subscriptions "
        "(user_id,group_id,starts_at,expires_at,status,assigned_at,notes,created_at,updated_at) "
        "VALUES "
        f"({int(user_id)},{int(group_id)},now(),now()+({days} || ' days')::interval,'active',now(),"
        "'Default subscription assigned by sub2api sync',now(),now()) "
        "ON CONFLICT (user_id,group_id) WHERE deleted_at IS NULL DO UPDATE SET "
        "status='active', "
        f"expires_at=GREATEST(user_subscriptions.expires_at, now()+({days} || ' days')::interval), "
        "updated_at=now();"
    )


def get_user_keys(user_id):
    key_rows = rows(
        "SELECT id,LEFT(COALESCE(name,''),100),LEFT(COALESCE(key,''),128),"
        "LEFT(COALESCE(status,''),16),LEFT(COALESCE(quota::text,'0'),64),"
        "LEFT(COALESCE(quota_used::text,'0'),64) "
        f"FROM api_keys WHERE user_id={int(user_id)} AND deleted_at IS NULL "
        f"ORDER BY id LIMIT {MAX_USER_API_KEYS + 1};"
    )
    if len(key_rows) > MAX_USER_API_KEYS:
        raise RuntimeError("api_key_limit_exceeded")
    return [
        {
            "apiKeyId": int(row[0]),
            "tokenId": int(row[0]),
            "name": row[1],
            "apiKey": row[2],
            "tokenKey": row[2],
            "status": 1 if row[3] == "active" else 0,
            "quota": float(row[4] or 0),
            "quotaUsed": float(row[5] or 0),
        }
        for row in key_rows
        if len(row) >= 6
    ]


def sync_user_keys(user_id, group_id, tokens):
    active_ids = []
    primary_id = 0
    primary_key = ""

    for token in tokens:
        key = token["key"]
        name = token["name"]
        existing_key = first_row(
            "SELECT id,user_id,COALESCE(deleted_at::text,'') FROM api_keys "
            f"WHERE key={sql_quote(key, 128)} LIMIT 1;"
        )
        if existing_key:
            api_key_id = int(existing_key[0])
            key_user_id = int(existing_key[1])
            key_deleted_at = existing_key[2] if len(existing_key) >= 3 else ""
            if key_user_id != user_id and not key_deleted_at:
                raise RuntimeError("requested api key is already assigned to another active user")
            psql(
                "UPDATE api_keys SET "
                f"user_id={int(user_id)}, key={sql_quote(key, 128)}, name={sql_quote(name, 100)}, group_id={int(group_id)}, "
                "status='active', quota=0, expires_at=NULL, deleted_at=NULL, updated_at=now() "
                f"WHERE id={api_key_id};"
            )
        else:
            psql(
                "INSERT INTO api_keys "
                "(user_id,key,name,group_id,status,quota,quota_used,created_at,updated_at) "
                "VALUES "
                f"({int(user_id)},{sql_quote(key, 128)},{sql_quote(name, 100)},{int(group_id)},'active',0,0,now(),now());"
            )
            api_key_id = int(first_row(f"SELECT id FROM api_keys WHERE key={sql_quote(key, 128)} LIMIT 1;")[0])

        active_ids.append(api_key_id)
        if primary_id <= 0:
            primary_id = api_key_id
            primary_key = key

    if active_ids:
        keep = ",".join(str(item) for item in active_ids)
        psql(
            "UPDATE api_keys SET status='disabled', deleted_at=now(), updated_at=now() "
            f"WHERE user_id={int(user_id)} AND id NOT IN ({keep}) AND deleted_at IS NULL;"
        )
    else:
        psql(
            "UPDATE api_keys SET status='disabled', deleted_at=now(), updated_at=now() "
            f"WHERE user_id={int(user_id)} AND deleted_at IS NULL;"
        )

    return primary_id, primary_key


def provision(payload):
    with database_transaction():
        return _provision(payload)


def _provision(payload):
    uuid, legacy_username, username = payload_identity(payload)
    display_name = str(payload.get("name") or username).strip()[:80]
    email = default_email(username, payload.get("email"))

    password = str(payload.get("loginPassword") or "").strip()
    reset_password = bool(payload.get("resetLoginPassword"))
    user_id = payload_user_id(payload)

    if user_id > 0:
        user = resolve_invite_user(
            uuid,
            legacy_username,
            username,
            user_id=user_id,
            include_deleted=True,
        )
    else:
        user = resolve_invite_user(
            uuid,
            legacy_username,
            username,
            include_deleted=True,
        )

    groups = ensure_groups()
    primary_group_id = groups[0][1]
    for _group_name, group_id in groups:
        ensure_subscription_plan(group_id)

    if user:
        user_id = int(user[0])
        if reset_password or not (8 <= len(password) <= 64):
            if not (8 <= len(password) <= 64):
                password = login_password()
            psql(
                "UPDATE users SET "
                f"email={sql_quote(email, 255)}, "
                f"password_hash=crypt({sql_quote(password)}, gen_salt('bf')), "
                f"username={sql_quote(username, 100)}, "
                f"notes={sql_quote(display_name, 240)}, "
                f"status='active', balance={DEFAULT_USER_BALANCE}, deleted_at=NULL, updated_at=now() "
                f"WHERE id={user_id};"
            )
        else:
            psql(
                "UPDATE users SET "
                f"email={sql_quote(email, 255)}, "
                f"username={sql_quote(username, 100)}, "
                f"notes={sql_quote(display_name, 240)}, "
                f"status='active', balance={DEFAULT_USER_BALANCE}, deleted_at=NULL, updated_at=now() "
                f"WHERE id={user_id};"
            )
    else:
        if not (8 <= len(password) <= 64):
            password = login_password()
        psql(
            "INSERT INTO users "
            "(email,password_hash,role,balance,concurrency,status,username,notes,created_at,updated_at) "
            "VALUES "
            f"({sql_quote(email, 255)},crypt({sql_quote(password)}, gen_salt('bf')),'user',{DEFAULT_USER_BALANCE},5,'active',"
            f"{sql_quote(username, 100)},{sql_quote(display_name, 240)},now(),now());"
        )
        user_id = int(first_row(f"SELECT id FROM users WHERE username={sql_quote(username)} AND deleted_at IS NULL LIMIT 1;")[0])
        _bind_or_validate_invite_user(
            [user_id, username, "user", ""],
            uuid,
            {legacy_username, username},
        )

    for _group_name, group_id in groups:
        psql(
            "INSERT INTO user_allowed_groups (user_id,group_id,created_at) "
            f"VALUES ({user_id},{group_id},now()) ON CONFLICT (user_id,group_id) DO NOTHING;"
        )
        ensure_default_subscription(user_id, group_id)

    tokens = requested_tokens(payload)
    if "tokens" not in payload and not tokens:
        tokens = [{"key": api_key(), "name": DEFAULT_KEY_NAME}]
    api_key_id, key = sync_user_keys(user_id, primary_group_id, tokens)

    password_hash_row = first_row(f"SELECT password_hash FROM users WHERE id={user_id};")
    password_fingerprint = password_hash_fingerprint(password_hash_row[0] if password_hash_row else "")
    return {
        "ok": True,
        "action": "provision",
        "uuid": uuid,
        "username": username,
        "email": email,
        "userId": user_id,
        "apiKeyId": api_key_id,
        "tokenId": api_key_id,
        "apiKey": key,
        "tokenKey": key,
        "loginUrl": os.environ.get("SUB2API_LOGIN_URL", "https://api.example.com"),
        "loginPassword": password,
        "passwordHashFingerprint": password_fingerprint,
        "tokens": get_user_keys(user_id),
        "allowedGroups": [group_name for group_name, _group_id in groups],
        "baseUrl": os.environ.get("SUB2API_PUBLIC_BASE_URL", DEFAULT_BASE_URL),
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def status(payload):
    with database_transaction():
        return _status(payload)


def _status(payload):
    uuid, legacy_username, username = payload_identity(payload)
    user_id = payload_user_id(payload)
    if user_id > 0:
        user = resolve_invite_user(
            uuid,
            legacy_username,
            username,
            user_id=user_id,
        )
    else:
        user = resolve_invite_user(
            uuid,
            legacy_username,
            username,
        )
    if not user:
        return {
            "ok": True,
            "action": "status",
            "uuid": uuid,
            "exists": False,
            "tokens": [],
            "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    user_id = int(user[0])
    return {
        "ok": True,
        "action": "status",
        "uuid": uuid,
        "exists": True,
        "username": user[1],
        "email": user[4],
        "userId": user_id,
        "passwordHashFingerprint": password_hash_fingerprint(user[5]),
        "status": 1 if user[6] == "active" else 0,
        "tokens": get_user_keys(user_id),
        "loginUrl": os.environ.get("SUB2API_LOGIN_URL", "https://api.example.com"),
        "baseUrl": os.environ.get("SUB2API_PUBLIC_BASE_URL", DEFAULT_BASE_URL),
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def login(payload):
    uuid, legacy_username, username = payload_identity(payload)
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("loginPassword") or "").strip()
    if not email or not password:
        raise ValueError("missing login credentials")
    user_id = payload_user_id(payload)
    with database_transaction():
        user = resolve_invite_user(
            uuid,
            legacy_username,
            username,
            user_id=user_id,
            allow_bind=False,
        )
        if not user or str(user[4]).strip().lower() != email.lower():
            raise RuntimeError("invite_identity_mismatch")
    body = json.dumps({"email": email, "password": password}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        os.environ.get("SUB2API_INTERNAL_LOGIN_URL", "http://127.0.0.1:8080/api/v1/auth/login"),
        data=body,
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            declared_length = response.headers.get("content-length", "")
            if declared_length:
                try:
                    if int(declared_length) > MAX_LOGIN_RESPONSE_BYTES:
                        raise RuntimeError("sub2api_login_response_too_large")
                except ValueError as error:
                    raise RuntimeError("sub2api_login_response_invalid_length") from error
            response_body = response.read(MAX_LOGIN_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_LOGIN_RESPONSE_BYTES:
                raise RuntimeError("sub2api_login_response_too_large")
            payload = json.loads(response_body.decode())
    except urllib.error.HTTPError as error:
        raise RuntimeError("sub2api_login_rejected") from error
    if not isinstance(payload, dict) or payload.get("code") != 0:
        raise RuntimeError("sub2api login failed")
    return {
        "ok": True,
        "action": "login",
        "uuid": uuid,
        "auth": sanitize_login_auth(payload.get("data")),
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def sanitize_login_auth(value):
    if not isinstance(value, dict):
        raise RuntimeError("sub2api_login_response_invalid")
    access_token = value.get("access_token")
    if (
        not isinstance(access_token, str)
        or not access_token
        or len(access_token.encode()) > MAX_LOGIN_AUTH_TOKEN_BYTES
    ):
        raise RuntimeError("sub2api_login_response_invalid")

    auth = {"access_token": access_token}
    if "refresh_token" in value:
        refresh_token = value["refresh_token"]
        if (
            not isinstance(refresh_token, str)
            or len(refresh_token.encode()) > MAX_LOGIN_AUTH_TOKEN_BYTES
        ):
            raise RuntimeError("sub2api_login_response_invalid")
        auth["refresh_token"] = refresh_token
    if "expires_in" in value:
        expires_in = value["expires_in"]
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, int)
            or not 0 <= expires_in <= 31_536_000
        ):
            raise RuntimeError("sub2api_login_response_invalid")
        auth["expires_in"] = expires_in
    if "user" in value:
        user = value["user"]
        if not isinstance(user, dict):
            raise RuntimeError("sub2api_login_response_invalid")
        summary = {}
        for field in LOGIN_USER_FIELDS:
            if field not in user:
                continue
            field_value = user[field]
            if isinstance(field_value, bool):
                summary[field] = field_value
            elif isinstance(field_value, int) and abs(field_value) <= MAX_SAFE_IDENTIFIER:
                summary[field] = field_value
            elif (
                isinstance(field_value, str)
                and len(field_value.encode()) <= MAX_LOGIN_USER_FIELD_BYTES
            ):
                summary[field] = field_value
        auth["user"] = summary
    if len(json.dumps(auth, separators=(",", ":")).encode()) > MAX_LOGIN_AUTH_RESPONSE_BYTES:
        raise RuntimeError("sub2api_login_response_invalid")
    return auth


def deprovision(payload):
    with database_transaction():
        return _deprovision(payload)


def _deprovision(payload):
    uuid, legacy_username, username = payload_identity(payload)
    requested_user_id = payload_user_id(payload)
    api_key_id = payload_token_id(payload)
    user = resolve_invite_user(
        uuid,
        legacy_username,
        username,
        user_id=requested_user_id,
        api_key_id=api_key_id,
        allow_bind=False,
    )
    user_id = int(user[0]) if user else 0
    token_only = bool(
        user
        and requested_user_id <= 0
        and api_key_id > 0
        and not normalize_username(payload.get("username"))
        and not normalize_username(payload.get("name"))
        and user[1] != legacy_username
    )
    if token_only:
        psql(
            "UPDATE api_keys SET status='disabled', deleted_at=now(), updated_at=now() "
            f"WHERE id={api_key_id} AND user_id={user_id} AND deleted_at IS NULL;"
        )
    elif user_id > 0:
        psql(f"UPDATE api_keys SET status='disabled', deleted_at=now(), updated_at=now() WHERE user_id={user_id} AND deleted_at IS NULL;")
        psql(f"UPDATE user_subscriptions SET status='cancelled', deleted_at=now(), updated_at=now() WHERE user_id={user_id} AND deleted_at IS NULL;")
        psql(f"DELETE FROM user_allowed_groups WHERE user_id={user_id};")
        psql(f"UPDATE users SET status='disabled', deleted_at=now(), updated_at=now() WHERE id={user_id};")
    return {
        "ok": True,
        "action": "deprovision",
        "uuid": uuid,
        "username": username,
        "userId": user_id,
        "apiKeyId": api_key_id,
        "tokenId": api_key_id,
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def purge(payload):
    with database_transaction():
        return _purge(payload)


def _purge(payload):
    uuid, legacy_username, username = payload_identity(payload)
    requested_user_id = payload_user_id(payload)
    api_key_id = payload_token_id(payload)
    user = resolve_invite_user(
        uuid,
        legacy_username,
        username,
        user_id=requested_user_id,
        api_key_id=api_key_id,
        include_deleted=True,
        allow_bind=False,
    )
    user_id = int(user[0]) if user else 0
    token_only = bool(
        user
        and requested_user_id <= 0
        and api_key_id > 0
        and not normalize_username(payload.get("username"))
        and not normalize_username(payload.get("name"))
        and user[1] != legacy_username
    )
    if token_only:
        psql(f"DELETE FROM api_keys WHERE id={api_key_id} AND user_id={user_id};")
    elif user_id > 0:
        psql(
            f"DELETE FROM api_keys WHERE user_id={user_id};"
            f"DELETE FROM user_subscriptions WHERE user_id={user_id};"
            f"DELETE FROM user_allowed_groups WHERE user_id={user_id};"
            "DELETE FROM sub2api_sync_invite_owners "
            f"WHERE user_id={user_id};"
            f"DELETE FROM users WHERE id={user_id};"
        )
    return {
        "ok": True,
        "action": "purge",
        "uuid": uuid,
        "username": username,
        "userId": user_id,
        "apiKeyId": api_key_id,
        "tokenId": api_key_id,
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def password_hash_fingerprint(value):
    return hmac.new(
        get_secret().encode(),
        b"sub2api-password-hash:" + str(value or "").encode(),
        hashlib.sha256,
    ).hexdigest()


def redis_command(*parts, timeout=2):
    host = os.environ.get("SUB2API_SYNC_REDIS_HOST", "redis")
    port = env_int("SUB2API_SYNC_REDIS_PORT", 6379)
    username = os.environ.get("SUB2API_SYNC_REDIS_USERNAME", "")
    password = os.environ.get("SUB2API_SYNC_REDIS_PASSWORD", "")
    database = env_int("SUB2API_SYNC_REDIS_DB", 0)
    if username and not password:
        raise RuntimeError("redis_configuration_invalid")
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        stream = connection.makefile("rwb", buffering=0)
        if password:
            if username:
                _redis_write(stream, "AUTH", username, password)
            else:
                _redis_write(stream, "AUTH", password)
            _redis_read(stream)
        if database:
            _redis_write(stream, "SELECT", str(database))
            _redis_read(stream)
        _redis_write(stream, *parts)
        return _redis_read(stream)


def _redis_write(stream, *parts):
    encoded = [str(part).encode() for part in parts]
    stream.write(f"*{len(encoded)}\r\n".encode())
    for part in encoded:
        stream.write(f"${len(part)}\r\n".encode() + part + b"\r\n")


def _redis_read(stream):
    prefix = stream.read(1)
    line = stream.readline().rstrip(b"\r\n")
    if prefix == b"+":
        return line.decode()
    if prefix == b"$":
        length = int(line)
        if length < 0:
            return None
        value = stream.read(length)
        stream.read(2)
        return value.decode()
    if prefix == b":":
        return int(line)
    if prefix == b"-":
        raise RuntimeError("redis_command_failed")
    raise RuntimeError("redis_protocol_error")


def claim_nonce(nonce):
    nonce_key = "sub2api-sync:nonce:" + hashlib.sha256(nonce.encode()).hexdigest()
    return redis_command("SET", nonce_key, "1", "NX", "EX", NONCE_TTL_SECONDS) == "OK"


def verify_request(headers, body):
    secret = get_secret()
    timestamp = headers.get("x-sub2api-sync-timestamp", "")
    nonce = headers.get("x-sub2api-sync-nonce", "")
    signature = headers.get("x-sub2api-sync-signature", "")
    if (
        not isinstance(timestamp, str)
        or not isinstance(nonce, str)
        or not isinstance(signature, str)
        or not isinstance(body, (bytes, bytearray))
        or not re.fullmatch(r"[1-9][0-9]{9,12}", timestamp)
        or not re.fullmatch(r"[0-9a-f]{32}", nonce)
        or not re.fullmatch(r"[0-9a-f]{64}", signature)
    ):
        return False
    now = int(time.time())
    request_time = int(timestamp)
    if abs(now - request_time) > SIGNATURE_MAX_SKEW_SECONDS:
        return False
    expected = hmac.new(
        secret.encode(),
        timestamp.encode() + b"." + nonce.encode() + b"." + bytes(body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False
    try:
        return claim_nonce(nonce)
    except (OSError, RuntimeError):
        return False


class SafeThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_REQUEST_THREADS

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_REQUEST_THREADS)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(HTTP_CONNECTION_TIMEOUT_SECONDS)
        return request, client_address

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            print(json.dumps({
                "level": "warning",
                "error_code": "sync_request_capacity_rejected",
            }), flush=True)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def handle_error(self, _request, _client_address):
        print(json.dumps({
            "level": "error",
            "error_code": "sync_request_failed",
        }), flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "sub2api-sync/1.0"

    def do_GET(self):
        self.request_id = request_id(self.headers)
        if self.path in ("/health", "/healthz"):
            try:
                psql(
                    "SELECT user_id,invite_fingerprint,created_at,updated_at "
                    "FROM sub2api_sync_invite_owners LIMIT 0;",
                    timeout=3,
                )
                redis_command("PING", timeout=2)
                self.respond(200, {"ok": True})
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                self.respond(503, {"ok": False, "error": "dependency_unavailable"})
            return
        self.respond(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        self.request_id = request_id(self.headers)
        if self.path != "/provision":
            self.respond(404, {"ok": False, "error": "not found"})
            return
        content_type = self.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.respond(415, {"ok": False, "error": "unsupported media type"})
            return
        try:
            length = int(self.headers.get("content-length", "0") or "0")
        except (TypeError, ValueError):
            self.respond(400, {"ok": False, "error": "invalid content length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self.respond(413, {"ok": False, "error": "invalid body size"})
            return
        try:
            body = self.rfile.read(length)
        except TimeoutError:
            self.close_connection = True
            print(json.dumps({
                "level": "warning",
                "error_code": "sync_request_read_timeout",
                "request_id": self.request_id,
            }), flush=True)
            self.respond(408, {"ok": False, "error": "request timeout"})
            return
        if len(body) != length:
            self.close_connection = True
            print(json.dumps({
                "level": "warning",
                "error_code": "sync_request_body_incomplete",
                "request_id": self.request_id,
            }), flush=True)
            self.respond(400, {"ok": False, "error": "incomplete request body"})
            return
        if not verify_request(self.headers, body):
            self.respond(401, {"ok": False, "error": "unauthorized"})
            return
        action = "unknown"
        try:
            payload = json.loads(body.decode())
            requested_action = str(payload.get("action") or "")
            action = requested_action if requested_action in SYNC_ACTIONS else "invalid"
            if action == "provision":
                result = provision(payload)
            elif action == "status":
                result = status(payload)
            elif action == "login":
                result = login(payload)
            elif action == "deprovision":
                result = deprovision(payload)
            elif action == "purge":
                result = purge(payload)
            elif action == "usage_logs_list":
                result = list_usage_logs(payload)
            elif action == "usage_log_detail":
                result = get_usage_log_detail(payload)
            else:
                raise ValueError("invalid action")
            self.respond(200, result)
        except Exception:
            print(json.dumps({
                "level": "error",
                "error_code": "sync_action_failed",
                "action": str(action)[:40],
                "request_id": self.request_id,
            }), flush=True)
            self.respond(500, {"ok": False, "error": "sync_action_failed"})

    def log_message(self, fmt, *args):
        return

    def respond(self, status, payload):
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("x-request-id", getattr(self, "request_id", ""))
        self.send_header("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def request_id(headers):
    value = str(headers.get("x-request-id", ""))
    if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        return value
    return secrets.token_hex(8)


def main():
    host = os.environ.get("SUB2API_SYNC_HOST", "127.0.0.1")
    port = env_int("SUB2API_SYNC_PORT", 3021)
    get_secret()
    server = SafeThreadingHTTPServer((host, port), Handler)
    print(json.dumps({"level": "info", "message": "sub2api_sync_started", "host": host, "port": port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
