#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import subprocess
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY_BYTES = 16 * 1024
DEFAULT_KEY_NAME = "Sub2API"
DEFAULT_BASE_URL = "https://api.example.com/v1"
DEFAULT_USER_BALANCE = "100"
DEFAULT_SUBSCRIPTION_DAYS = 36500
NONCE_TTL_SECONDS = 300
MAX_NONCES = 4096

NONCES = {}


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
    return sql_quote(json.dumps(value, separators=(",", ":"))) + "::jsonb"


def psql(sql, timeout=12):
    command = [
        "docker",
        "exec",
        "-i",
        "sub2api-postgres",
        "sh",
        "-lc",
        "psql -U \"${POSTGRES_USER:-sub2api}\" -d \"${POSTGRES_DB:-sub2api}\" --tuples-only --no-align --field-separator $'\\t' -v ON_ERROR_STOP=1",
    ]
    result = subprocess.run(
        command,
        input=sql,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "psql command failed")
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
    compact = "".join(ch for ch in str(uuid).lower() if ch in string.hexdigits.lower())
    if len(compact) != 32:
        raise ValueError("invalid uuid")
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
    return text.startswith("sk-") and len(text) <= 128 and all(ch in allowed for ch in text[3:])


def normalize_api_key(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if not is_api_key(text):
        raise ValueError("invalid api key")
    if text.startswith("sk-"):
        return text
    return "sk-" + text


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
    return result


def login_password():
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(20))


def ensure_pgcrypto():
    psql("CREATE EXTENSION IF NOT EXISTS pgcrypto;")


def configured_groups():
    raw = os.environ.get("SUB2API_SYNC_DEFAULT_GROUP", "default")
    groups = []
    seen = set()
    for part in str(raw).split(","):
        group = part.strip()[:100]
        if not group or group in seen:
            continue
        seen.add(group)
        groups.append(group)
    return groups or ["default"]


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
        "SELECT id,name,key,status,quota,quota_used "
        f"FROM api_keys WHERE user_id={int(user_id)} AND deleted_at IS NULL ORDER BY id;"
    )
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
    ensure_pgcrypto()
    groups = ensure_groups()
    primary_group_id = groups[0][1]
    for _group_name, group_id in groups:
        ensure_subscription_plan(group_id)
    uuid, legacy_username, username = payload_identity(payload)
    display_name = str(payload.get("name") or username).strip()[:80]
    email = default_email(username, payload.get("email"))

    password = str(payload.get("loginPassword") or "").strip()
    reset_password = bool(payload.get("resetLoginPassword"))
    user_id = int(payload.get("sub2apiUserId") or payload.get("userId") or 0)

    user = []
    if user_id > 0:
        user = first_row(f"SELECT id FROM users WHERE id={user_id} ORDER BY deleted_at IS NULL DESC, id LIMIT 1;")
    if not user:
        user = first_row(
            "SELECT id FROM users "
            f"WHERE username={sql_quote(legacy_username)} ORDER BY deleted_at IS NULL DESC, id LIMIT 1;"
        )
    if not user and username != legacy_username:
        user = first_row(
            "SELECT id FROM users "
            f"WHERE username={sql_quote(username)} ORDER BY deleted_at IS NULL DESC, id LIMIT 1;"
        )
    if user:
        user_id = int(user[0])
        if reset_password:
            if not (8 <= len(password) <= 64):
                password = login_password()
            psql(
                "UPDATE users SET "
                f"email={sql_quote(email, 255)}, "
                f"password_hash=crypt({sql_quote(password)}, gen_salt('bf')), "
                f"username={sql_quote(username, 100)}, "
                f"notes={sql_quote(display_name, 240)}, "
                f"role='user', status='active', balance={DEFAULT_USER_BALANCE}, deleted_at=NULL, updated_at=now() "
                f"WHERE id={user_id};"
            )
        else:
            psql(
                "UPDATE users SET "
                f"email={sql_quote(email, 255)}, "
                f"username={sql_quote(username, 100)}, "
                f"notes={sql_quote(display_name, 240)}, "
                f"role='user', status='active', balance={DEFAULT_USER_BALANCE}, deleted_at=NULL, updated_at=now() "
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
    password_hash = password_hash_row[0] if password_hash_row else ""
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
        "passwordHash": password_hash,
        "tokens": get_user_keys(user_id),
        "allowedGroups": [group_name for group_name, _group_id in groups],
        "baseUrl": os.environ.get("SUB2API_PUBLIC_BASE_URL", DEFAULT_BASE_URL),
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def status(payload):
    uuid, legacy_username, username = payload_identity(payload)
    user_id = int(payload.get("sub2apiUserId") or payload.get("userId") or 0)
    user = []
    if user_id > 0:
        user = first_row(
            "SELECT id,username,email,password_hash,status "
            f"FROM users WHERE id={user_id} AND deleted_at IS NULL LIMIT 1;"
        )
    if not user:
        user = first_row(
            "SELECT id,username,email,password_hash,status "
            f"FROM users WHERE username={sql_quote(username)} AND deleted_at IS NULL LIMIT 1;"
        )
    if not user and username != legacy_username:
        user = first_row(
            "SELECT id,username,email,password_hash,status "
            f"FROM users WHERE username={sql_quote(legacy_username)} AND deleted_at IS NULL LIMIT 1;"
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
        "email": user[2],
        "userId": user_id,
        "passwordHash": user[3],
        "status": 1 if user[4] == "active" else 0,
        "tokens": get_user_keys(user_id),
        "loginUrl": os.environ.get("SUB2API_LOGIN_URL", "https://api.example.com"),
        "baseUrl": os.environ.get("SUB2API_PUBLIC_BASE_URL", DEFAULT_BASE_URL),
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def login(payload):
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("loginPassword") or "").strip()
    if not email or not password:
        raise ValueError("missing login credentials")
    body = json.dumps({"email": email, "password": password}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        os.environ.get("SUB2API_INTERNAL_LOGIN_URL", "http://127.0.0.1:8080/api/v1/auth/login"),
        data=body,
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        details = error.read().decode(errors="replace")[:200]
        raise RuntimeError(f"sub2api login failed: HTTP {error.code} {details}") from error
    if payload.get("code") != 0 or not payload.get("data", {}).get("access_token"):
        raise RuntimeError("sub2api login failed")
    return {
        "ok": True,
        "action": "login",
        "auth": payload["data"],
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def deprovision(payload):
    uuid, legacy_username, username = payload_identity(payload)
    user_id = int(payload.get("sub2apiUserId") or 0)
    api_key_id = int(payload.get("sub2apiApiKeyId") or payload.get("tokenId") or 0)
    if user_id <= 0:
        row = first_row(f"SELECT id FROM users WHERE username={sql_quote(username)} AND deleted_at IS NULL LIMIT 1;")
        if not row and username != legacy_username:
            row = first_row(f"SELECT id FROM users WHERE username={sql_quote(legacy_username)} AND deleted_at IS NULL LIMIT 1;")
        user_id = int(row[0]) if row else 0
    if user_id > 0:
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
    uuid, legacy_username, username = payload_identity(payload)
    user_id = int(payload.get("sub2apiUserId") or 0)
    api_key_id = int(payload.get("sub2apiApiKeyId") or payload.get("tokenId") or 0)
    if user_id <= 0:
        row = first_row(f"SELECT id FROM users WHERE username={sql_quote(username)} LIMIT 1;")
        if not row and username != legacy_username:
            row = first_row(f"SELECT id FROM users WHERE username={sql_quote(legacy_username)} LIMIT 1;")
        user_id = int(row[0]) if row else 0
    if user_id > 0:
        psql(f"DELETE FROM api_keys WHERE user_id={user_id}; DELETE FROM user_subscriptions WHERE user_id={user_id}; DELETE FROM user_allowed_groups WHERE user_id={user_id}; DELETE FROM users WHERE id={user_id};")
    elif api_key_id > 0:
        psql(f"DELETE FROM api_keys WHERE id={api_key_id};")
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


def cleanup_nonces(now):
    expired = [nonce for nonce, seen_at in NONCES.items() if now - seen_at > NONCE_TTL_SECONDS]
    for nonce in expired:
        NONCES.pop(nonce, None)
    if len(NONCES) > MAX_NONCES:
        for nonce, _seen_at in sorted(NONCES.items(), key=lambda item: item[1])[: len(NONCES) - MAX_NONCES]:
            NONCES.pop(nonce, None)


def verify_request(headers, body):
    secret = get_secret()
    timestamp = headers.get("x-sub2api-sync-timestamp", "")
    nonce = headers.get("x-sub2api-sync-nonce", "")
    signature = headers.get("x-sub2api-sync-signature", "")
    if not timestamp.isdigit() or len(nonce) < 24 or len(signature) != 64:
        return False
    now = int(time.time())
    request_time = int(timestamp)
    if abs(now - request_time) > NONCE_TTL_SECONDS:
        return False
    cleanup_nonces(now)
    if nonce in NONCES:
        return False
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + nonce.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False
    NONCES[nonce] = now
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "sub2api-sync/1.0"

    def do_GET(self):
        if self.path == "/health":
            self.respond(200, {"ok": True})
            return
        self.respond(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/provision":
            self.respond(404, {"ok": False, "error": "not found"})
            return
        content_type = self.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.respond(415, {"ok": False, "error": "unsupported media type"})
            return
        length = int(self.headers.get("content-length", "0") or "0")
        if length <= 0 or length > MAX_BODY_BYTES:
            self.respond(413, {"ok": False, "error": "invalid body size"})
            return
        body = self.rfile.read(length)
        if not verify_request(self.headers, body):
            self.respond(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            payload = json.loads(body.decode())
            action = payload.get("action")
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
            else:
                raise ValueError("invalid action")
            self.respond(200, result)
        except Exception as error:
            print(json.dumps({"level": "error", "message": str(error)}), flush=True)
            self.respond(500, {"ok": False, "error": "sync failed"})

    def log_message(self, fmt, *args):
        print(json.dumps({"level": "info", "client": self.client_address[0], "message": fmt % args}), flush=True)

    def respond(self, status, payload):
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("content-security-policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    host = os.environ.get("SUB2API_SYNC_HOST", "127.0.0.1")
    port = env_int("SUB2API_SYNC_PORT", 3021)
    get_secret()
    server = ThreadingHTTPServer((host, port), Handler)
    print(json.dumps({"level": "info", "message": "sub2api_sync_started", "host": host, "port": port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
