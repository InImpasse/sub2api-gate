import { fetchWithTimeout, readJsonWithLimit } from "./request-security.js";

export const CLOUDFLARE_TIMEOUT_MS = 10_000;
export const CLOUDFLARE_RESPONSE_LIMIT_BYTES = 256 * 1024;
export const MAX_LIST_PAGES = 50;
const RETRY_DELAYS_MS = [100, 250];

export async function cloudflareApiFetch(env, path, init = {}) {
  if (!isCloudflareIdentifier(env.ACCOUNT_ID) || !isCloudflareIdentifier(env.IP_LIST_ID)) {
    throw new Error("cloudflare_api_identifier_invalid");
  }
  if (!isAllowedCloudflarePath(env, path)) {
    throw new Error("cloudflare_api_path_invalid");
  }
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}${path}`;
  const headers = new Headers(init.headers || {});
  headers.set("authorization", `Bearer ${env.CLOUDFLARE_API_TOKEN}`);
  headers.set("content-type", "application/json");
  const method = String(init.method || "GET").toUpperCase();
  const retryDelays = method === "GET" || method === "HEAD" ? RETRY_DELAYS_MS : [];
  let response;
  for (let attempt = 0; attempt <= retryDelays.length; attempt += 1) {
    response = await fetchWithTimeout(url, {
      ...init,
      method,
      headers,
      redirect: "manual",
    }, CLOUDFLARE_TIMEOUT_MS);
    if (response.status !== 429 && response.status < 500) return response;
    if (attempt < retryDelays.length) await delay(retryDelays[attempt]);
  }
  return response;
}

export function isCloudflareIdentifier(value) {
  return /^[A-Za-z0-9_-]{1,64}$/.test(String(value || ""));
}

export async function readCloudflareJson(response) {
  const payload = await readJsonWithLimit(response, CLOUDFLARE_RESPONSE_LIMIT_BYTES);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("cloudflare_response_invalid");
  }
  return payload;
}

function isAllowedCloudflarePath(env, path) {
  if (typeof path !== "string" || path.includes("#")) return false;
  const listItemsPath = `/rules/lists/${env.IP_LIST_ID}/items`;
  if (path === listItemsPath || path.startsWith(`${listItemsPath}?`)) return true;
  const operationPrefix = "/rules/lists/bulk_operations/";
  return path.startsWith(operationPrefix)
    && /^[A-Za-z0-9_-]{1,128}$/.test(path.slice(operationPrefix.length));
}

export async function listCloudflareItems(env) {
  const items = [];
  const seenCursors = new Set();
  let cursor = "";
  let lastPayload = {};
  let lastStatus = 200;

  for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
    const query = new URLSearchParams({ per_page: "100" });
    if (cursor) query.set("cursor", cursor);
    const response = await cloudflareApiFetch(
      env,
      `/rules/lists/${env.IP_LIST_ID}/items?${query}`,
    );
    lastStatus = response.status;
    try {
      lastPayload = await readCloudflareJson(response);
    } catch {
      return {
        ok: false,
        status: 502,
        errors: [{ code: "cloudflare_response_invalid" }],
        messages: [],
        payload: {},
        items: [],
      };
    }
    if (!response.ok || lastPayload.success !== true || !Array.isArray(lastPayload.result)) {
      return {
        ok: false,
        status: response.ok ? 502 : response.status,
        errors: Array.isArray(lastPayload.errors)
          ? lastPayload.errors
          : [{ code: "cloudflare_response_invalid" }],
        messages: Array.isArray(lastPayload.messages) ? lastPayload.messages : [],
        payload: lastPayload,
        items: [],
      };
    }
    items.push(...lastPayload.result);
    const nextCursor = String(lastPayload.result_info?.cursors?.after || "");
    if (!nextCursor) {
      return { ok: true, status: lastStatus, errors: [], messages: [], payload: lastPayload, items };
    }
    if (seenCursors.has(nextCursor)) throw new Error("cloudflare_list_cursor_repeated");
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  }
  throw new Error("cloudflare_list_page_limit_exceeded");
}

export async function waitForCloudflareOperation(env, payload, maxPolls = 20) {
  const operationId = String(payload?.result?.operation_id || payload?.operation_id || "");
  if (!operationId) return payload;
  for (let poll = 0; poll < maxPolls; poll += 1) {
    const response = await cloudflareApiFetch(
      env,
      `/rules/lists/bulk_operations/${encodeURIComponent(operationId)}`,
    );
    let statusPayload;
    try {
      statusPayload = await readCloudflareJson(response);
    } catch {
      throw new Error("cloudflare_operation_lookup_failed");
    }
    if (!response.ok || statusPayload.success !== true) {
      throw new Error("cloudflare_operation_lookup_failed");
    }
    const status = String(statusPayload.result?.status || "").toLowerCase();
    if (["completed", "success"].includes(status)) return statusPayload;
    if (["failed", "error"].includes(status)) throw new Error("cloudflare_operation_failed");
    if (poll + 1 < maxPolls) await delay(Math.min(1000, 100 + poll * 50));
  }
  throw new Error("cloudflare_operation_timeout");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
