import { cloudflareListComment } from "./credential-security.js";

export const MAX_COMMENT_REPLACEMENT_ITEMS = 5_000;
const LEGACY_COMMENT = /^sub2api\s+uuid\s+([0-9a-f-]{36})\s+raw\s+/i;

export function countLegacyCloudflareComments(items) {
  if (!Array.isArray(items) || items.length > MAX_COMMENT_REPLACEMENT_ITEMS) {
    throw new Error("cloudflare_comment_replacement_limit_exceeded");
  }
  let count = 0;
  for (const item of items) {
    if (!String(item?.ip || "")) {
      throw new Error("cloudflare_comment_replacement_non_ip_item");
    }
    if (LEGACY_COMMENT.test(String(item?.comment || ""))) count += 1;
  }
  return count;
}

export async function buildCloudflareCommentReplacement(items, hmacKey) {
  if (!Array.isArray(items) || items.length > MAX_COMMENT_REPLACEMENT_ITEMS) {
    throw new Error("cloudflare_comment_replacement_limit_exceeded");
  }

  let legacyCount = 0;
  const replacement = [];
  for (const item of items) {
    const ip = String(item?.ip || "");
    if (!ip) throw new Error("cloudflare_comment_replacement_non_ip_item");
    const match = String(item.comment || "").match(LEGACY_COMMENT);
    let comment = String(item.comment || "");
    if (match) {
      comment = await cloudflareListComment(hmacKey, match[1].toLowerCase());
      legacyCount += 1;
    }
    replacement.push({ ip, comment });
  }
  return { items: replacement, legacyCount };
}

export function assertCloudflareListSnapshot(expected, current) {
  if (snapshot(expected, true) !== snapshot(current, true)) {
    throw new Error("cloudflare_list_changed_before_replacement");
  }
}

export function assertCloudflareReplacement(expected, current) {
  if (snapshot(expected, false) !== snapshot(current, false)) {
    throw new Error("cloudflare_comment_replacement_verification_failed");
  }
}

function snapshot(items, includeId) {
  return JSON.stringify(
    (items || [])
      .map((item) => ({
        ...(includeId ? { id: String(item?.id || "") } : {}),
        ip: String(item?.ip || ""),
        comment: String(item?.comment || ""),
      }))
      .sort((left, right) => {
        const leftKey = `${left.ip}\u0000${left.comment}\u0000${left.id || ""}`;
        const rightKey = `${right.ip}\u0000${right.comment}\u0000${right.id || ""}`;
        return leftKey.localeCompare(rightKey);
      }),
  );
}
