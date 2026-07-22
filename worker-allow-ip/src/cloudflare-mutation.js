import { createAuthStateStore, isAuthStateBindingConfigured } from "./auth-state.js";
import {
  cloudflareListValueHmac,
  cloudflareMutationComment,
} from "./credential-security.js";
import {
  cloudflareApiFetch,
  listCloudflareItems,
  readCloudflareJson,
  waitForCloudflareOperation,
} from "./cloudflare-client.js";

export const CLOUDFLARE_MUTATION_GRACE_MS = 2 * 60 * 1000;
export const CLOUDFLARE_MUTATION_RETRY_MS = 60 * 1000;
const MAX_MUTATION_VALUES = 100;

export async function createManagedCloudflareListItems(env, values, now = Date.now()) {
  const normalizedValues = normalizeListValues(values);
  if (!isAuthStateBindingConfigured(env)) {
    throw new Error("auth_state_unavailable");
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error("cloudflare_mutation_clock_invalid");
  }

  const mutationId = randomHex(32);
  const comment = await cloudflareMutationComment(env.INVITE_ACCESS_HMAC_KEY, mutationId);
  const expectedValueHashes = await Promise.all(
    normalizedValues.map((value) => cloudflareListValueHmac(env.INVITE_ACCESS_HMAC_KEY, value)),
  );
  const store = createAuthStateStore(env);
  await store.registerCloudflareMutation({
    mutationId,
    comment,
    expectedValueHashes,
    itemIds: [],
    createdAt: now,
    notBefore: now + CLOUDFLARE_MUTATION_GRACE_MS,
    leaseUntil: 0,
  });

  try {
    const response = await cloudflareApiFetch(
      env,
      `/rules/lists/${env.IP_LIST_ID}/items?per_page=100`,
      {
        method: "POST",
        body: JSON.stringify(normalizedValues.map((ip) => ({ ip, comment }))),
      },
    );
    const payload = await readCloudflareJson(response);
    if (response.ok && payload.success === true) {
      await waitForCloudflareOperation(env, payload);
    }
  } catch {
    // The request may have committed remotely. The authoritative re-list below decides.
  }

  let listed;
  try {
    listed = await listCloudflareItems(env);
  } catch {
    throw mutationFailure(mutationId);
  }
  if (!listed.ok) throw mutationFailure(mutationId);

  const matches = resolveMutationItems(listed.items, comment, normalizedValues);
  const itemIds = matches.map((item) => item.id);
  try {
    await store.updateCloudflareMutationItems(mutationId, itemIds);
  } catch {
    throw mutationFailure(mutationId);
  }
  if (matches.length !== normalizedValues.length) throw mutationFailure(mutationId);

  return {
    mutationId,
    comment,
    items: matches,
  };
}

export async function findCloudflareMutationCandidates(env, marker, listItems) {
  const itemIds = new Set(Array.isArray(marker?.itemIds) ? marker.itemIds.map(String) : []);
  const expectedHashes = new Set(
    Array.isArray(marker?.expectedValueHashes) ? marker.expectedValueHashes.map(String) : [],
  );
  const comment = String(marker?.comment || "");
  const candidates = [];

  for (const item of listItems || []) {
    const id = String(item?.id || "");
    const exactId = id && itemIds.has(id);
    if (!exactId && String(item?.comment || "") !== comment) continue;
    const valueHash = await cloudflareListValueHmac(
      env.INVITE_ACCESS_HMAC_KEY,
      String(item?.ip || ""),
    );
    if (
      expectedHashes.has(valueHash)
      && (exactId || String(item?.comment || "") === comment)
    ) {
      candidates.push(item);
    }
  }
  return deduplicateItemsById(candidates);
}

export async function resolveCloudflareMutation(env, mutationId) {
  if (!mutationId) return;
  await createAuthStateStore(env).resolveCloudflareMutation(mutationId);
}

export function cloudflareMutationIdFromError(error) {
  const mutationId = String(error?.mutationId || "");
  return /^[a-f0-9]{64}$/.test(mutationId) ? mutationId : "";
}

function resolveMutationItems(items, comment, values) {
  const expected = new Set(values);
  const byValue = new Map();
  for (const item of items || []) {
    const value = String(item?.ip || "");
    const id = String(item?.id || "");
    if (
      expected.has(value)
      && String(item?.comment || "") === comment
      && /^[A-Za-z0-9_-]{1,128}$/.test(id)
      && !byValue.has(value)
    ) {
      byValue.set(value, { id, ip: value, comment });
    }
  }
  return values.flatMap((value) => byValue.has(value) ? [byValue.get(value)] : []);
}

function normalizeListValues(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > MAX_MUTATION_VALUES) {
    throw new Error("cloudflare_mutation_values_invalid");
  }
  const normalized = values.map((value) => String(value || "").trim());
  if (normalized.some((value) => !value || value.length > 180)) {
    throw new Error("cloudflare_mutation_values_invalid");
  }
  return [...new Set(normalized)];
}

function deduplicateItemsById(items) {
  const seen = new Set();
  return items.filter((item) => {
    const id = String(item?.id || "");
    if (!id || seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

function mutationFailure(mutationId) {
  const error = new Error("cloudflare_list_mutation_failed");
  Object.defineProperty(error, "mutationId", { value: mutationId });
  return error;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const __test = Object.freeze({
  normalizeListValues,
  resolveMutationItems,
});
