import datetime
import threading
import time


PAGE_DEFAULT = 25
PAGE_MAX = 100
MAX_RANGE_SECONDS = 30 * 24 * 60 * 60
MODEL_CACHE_SECONDS = 5 * 60
MAX_SAFE_ID = 9_007_199_254_740_991
TEXT_FIELD_LIMITS = {
    "requestId": 128,
    "model": 128,
    "requestedModel": 128,
    "totalCost": 64,
    "actualCost": 64,
    "requestType": 32,
    "inboundEndpoint": 256,
    "createdAt": 64,
}
_MODEL_CACHE = {"expires_at": 0.0, "items": []}
_MODEL_CACHE_LOCK = threading.Lock()
FIELDS = (
    "id",
    "requestId",
    "model",
    "requestedModel",
    "inputTokens",
    "outputTokens",
    "cacheCreationTokens",
    "cacheReadTokens",
    "totalCost",
    "actualCost",
    "durationMs",
    "stream",
    "requestType",
    "inboundEndpoint",
    "createdAt",
)
DEFAULTS = {
    "id": 0,
    "requestId": "",
    "model": "",
    "requestedModel": "",
    "inputTokens": 0,
    "outputTokens": 0,
    "cacheCreationTokens": 0,
    "cacheReadTokens": 0,
    "totalCost": "0",
    "actualCost": "0",
    "durationMs": 0,
    "stream": False,
    "requestType": "",
    "inboundEndpoint": "",
    "createdAt": "",
}


def clamp_int(value, default, minimum, maximum):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def clamp_identifier(value, default=0, minimum=0):
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isdigit():
        number = int(value)
    else:
        return default
    return number if minimum <= number <= MAX_SAFE_ID else default


def sql_quote(value, max_length=None):
    text = "" if value is None else str(value)
    if max_length is not None:
        text = text[:max_length]
    return "'" + text.replace("\\", "\\\\").replace("'", "''").replace("\0", "") + "'"


def sql_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S+00")


def ilike_contains(value, max_length):
    text = str(value or "")[:max_length]
    escaped = text.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return sql_quote(f"%{escaped}%") + " ESCAPE '!'"


def usage_log_filters(payload):
    clauses = []
    query = str(payload.get("query") or "").strip()[:120]
    if query:
        escaped = ilike_contains(query, 120)
        clauses.append(
            "(COALESCE(request_id, '') ILIKE " + escaped
            + " OR model ILIKE " + escaped
            + " OR COALESCE(requested_model, '') ILIKE " + escaped
            + " OR COALESCE(inbound_endpoint, '') ILIKE " + escaped + ")"
        )

    request_id = str(payload.get("requestId") or "").strip()[:64]
    if request_id:
        clauses.append(f"COALESCE(request_id, '') ILIKE {ilike_contains(request_id, 64)}")

    model = str(payload.get("model") or "").strip()[:100]
    if model:
        model_pattern = ilike_contains(model, 100)
        clauses.append(
            f"(model ILIKE {model_pattern} OR COALESCE(requested_model, '') ILIKE {model_pattern})"
        )

    presets = {"1h": 3600, "1d": 86400, "7d": 604800, "30d": 2592000}
    preset = str(payload.get("timePreset") or "1h").strip().lower()
    range_seconds = presets.get(preset, MAX_RANGE_SECONDS)
    clauses.append(f"created_at >= now() - interval '{range_seconds} seconds'")

    date_from = sql_timestamp(payload.get("dateFrom"))
    date_to = sql_timestamp(payload.get("dateTo"))
    if date_from:
        clauses.append(f"created_at >= {sql_quote(date_from)}::timestamptz")
    if date_to:
        clauses.append(f"created_at <= {sql_quote(date_to)}::timestamptz")

    cursor_id = clamp_identifier(payload.get("cursorId"))
    cursor_created_at = sql_timestamp(payload.get("cursorCreatedAt"))
    if cursor_id and cursor_created_at:
        clauses.append(
            f"(created_at,id) < ({sql_quote(cursor_created_at)}::timestamptz,{cursor_id})"
        )
    elif cursor_id:
        clauses.append(f"id < {cursor_id}")

    return query, False, ("WHERE " + " AND ".join(clauses) if clauses else "")


def sanitize_usage_item(item):
    if not isinstance(item, dict):
        return None
    sanitized = {field: item.get(field, DEFAULTS[field]) for field in FIELDS}
    for field, limit in TEXT_FIELD_LIMITS.items():
        sanitized[field] = str(sanitized[field] or "")[:limit]
    return sanitized


def usage_log_select(where_clause, limit):
    return (
        "SELECT COALESCE(json_agg(item ORDER BY created_at DESC,id DESC), '[]'::json)::text FROM ("
        "SELECT id,created_at,json_build_object("
        f"'id',id,'requestId',LEFT(COALESCE(request_id,''),{TEXT_FIELD_LIMITS['requestId']}),"
        f"'model',LEFT(COALESCE(model,''),{TEXT_FIELD_LIMITS['model']}),"
        f"'requestedModel',LEFT(COALESCE(requested_model,''),{TEXT_FIELD_LIMITS['requestedModel']}),"
        "'inputTokens',input_tokens,'outputTokens',output_tokens,"
        "'cacheCreationTokens',cache_creation_tokens,'cacheReadTokens',cache_read_tokens,"
        f"'totalCost',LEFT(total_cost::text,{TEXT_FIELD_LIMITS['totalCost']}),"
        f"'actualCost',LEFT(actual_cost::text,{TEXT_FIELD_LIMITS['actualCost']}),"
        "'durationMs',COALESCE(duration_ms,0),'stream',stream,"
        f"'requestType',LEFT(COALESCE(request_type::text,''),{TEXT_FIELD_LIMITS['requestType']}),"
        f"'inboundEndpoint',LEFT(COALESCE(inbound_endpoint,''),{TEXT_FIELD_LIMITS['inboundEndpoint']}),"
        f"'createdAt',LEFT(created_at::text,{TEXT_FIELD_LIMITS['createdAt']})) AS item FROM usage_logs "
        f"{where_clause} ORDER BY created_at DESC,id DESC LIMIT {int(limit)}"
        ") rows;"
    )


def list_usage_models(query_json_value, limit=24):
    with _MODEL_CACHE_LOCK:
        now = time.monotonic()
        if _MODEL_CACHE["expires_at"] > now:
            return list(_MODEL_CACHE["items"])
        sql = (
            "SELECT COALESCE(json_agg(model ORDER BY latest DESC), '[]'::json)::text FROM ("
            f"SELECT LEFT(COALESCE(model,''),{TEXT_FIELD_LIMITS['model']}) AS model, "
            "MAX(created_at) latest FROM usage_logs "
            f"WHERE created_at >= now() - interval '{MAX_RANGE_SECONDS} seconds' "
            f"GROUP BY LEFT(COALESCE(model,''),{TEXT_FIELD_LIMITS['model']}) "
            f"ORDER BY latest DESC LIMIT {clamp_int(limit, 24, 1, 100)}) models;"
        )
        result = query_json_value(sql) or []
        items = [
            str(value)[:TEXT_FIELD_LIMITS["model"]]
            for value in result
            if str(value or "").strip()
        ]
        _MODEL_CACHE["items"] = items
        _MODEL_CACHE["expires_at"] = time.monotonic() + MODEL_CACHE_SECONDS
        return list(items)


def list_usage_logs(query_json_value, payload):
    page_size = clamp_int(payload.get("pageSize"), PAGE_DEFAULT, 1, PAGE_MAX)
    query, _only_failed, where_clause = usage_log_filters(payload)
    rows = query_json_value(usage_log_select(where_clause, page_size + 1)) or []
    items = [sanitize_usage_item(item) for item in rows]
    items = [item for item in items if item is not None]
    has_more = len(items) > page_size
    visible = items[:page_size]
    return {
        "ok": True,
        "action": "usage_logs_list",
        "items": visible,
        "query": query,
        "filters": {
            "requestId": str(payload.get("requestId") or "")[:64],
            "model": str(payload.get("model") or "")[:100],
            "timePreset": str(payload.get("timePreset") or "1h")[:8],
            "dateFrom": str(payload.get("dateFrom") or "")[:40],
            "dateTo": str(payload.get("dateTo") or "")[:40],
        },
        "page": {
            "pageSize": page_size,
            "hasMore": has_more,
            "nextCursor": visible[-1]["id"] if has_more and visible else 0,
            "nextCursorCreatedAt": visible[-1]["createdAt"] if has_more and visible else "",
        },
        "modelOptions": list_usage_models(query_json_value),
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def get_usage_log_detail(query_json_value, payload):
    usage_id = clamp_identifier(payload.get("id"), 0, 1)
    rows = query_json_value(usage_log_select(
        f"WHERE id={usage_id} AND created_at >= now() - interval '{MAX_RANGE_SECONDS} seconds'",
        1,
    )) or []
    item = sanitize_usage_item(rows[0]) if rows else None
    if item is None:
        raise ValueError("usage log not found")
    return {
        "ok": True,
        "action": "usage_log_detail",
        "item": item,
        "items": [item],
        "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
