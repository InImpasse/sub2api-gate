import assert from "node:assert/strict";
import test from "node:test";

import {
  __test as adminTest,
  authorizeVisitorIps,
} from "../src/admin.js";
import { cloudflareListValueHmac } from "../src/credential-security.js";

const UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
const HMAC_KEY = "test-only-hmac-key-with-at-least-32-bytes";
const ENCRYPTION_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const VALUE = "198.51.100.0/24";

test("a concurrent public mutation for one invite stops before a Cloudflare side effect", async () => {
  const fixture = fixtureEnv({ invites: [invite()] });
  let unblockFirstRead;
  let firstReadStarted;
  const firstReadGate = new Promise((resolve) => { firstReadStarted = resolve; });
  fixture.beforeCloudflareFetch = async (count) => {
    if (count !== 1) return;
    firstReadStarted();
    await new Promise((resolve) => { unblockFirstRead = resolve; });
  };

  await withExternalMocks(fixture, async () => {
    const first = authorizeVisitorIps(fixture.env, request(), invite(), visitorIps());
    await firstReadGate;
    const second = await authorizeVisitorIps(fixture.env, request(), invite(), visitorIps());
    assert.equal(second.ok, false);
    assert.equal(second.status, 409);
    assert.equal(second.errors[0].code, "ip_records_busy");
    assert.equal(fixture.cloudflareFetchCount, 1);

    unblockFirstRead();
    const completed = await first;
    assert.equal(completed.ok, true);
  });
  assert.equal(fixture.activeRecordLeaseCount, 0);
});

test("public records failure deletes only the exact newly-created List item", async () => {
  const fixture = fixtureEnv({ invites: [invite()], failRecordPuts: 1 });
  await withExternalMocks(fixture, async () => {
    await assert.rejects(
      authorizeVisitorIps(fixture.env, request(), invite(), visitorIps()),
      /records write failed/,
    );
  });
  assert.deepEqual(fixture.listItems, []);
  assert.equal(fixture.markers.size, 0);
  assert.deepEqual(fixture.deletedIds, ["created-1"]);
  assert.equal(fixture.activeRecordLeaseCount, 0);
});

test("manual and IP-group restore records failures compensate their exact mutations", async () => {
  for (const action of ["manual", "restore-group"]) {
    const trash = action === "restore-group" ? [{
      id: "trash-group",
      type: "ip_group",
      deletedAt: "2026-07-21T00:00:00.000Z",
      uuid: UUID,
      group: { id: "group-restore", ips: visitorIps() },
    }] : [];
    const fixture = fixtureEnv({ invites: [invite()], trash, failRecordPuts: 1 });
    await withExternalMocks(fixture, async () => {
      if (action === "manual") {
        await assert.rejects(
          adminTest.addManualIpGroup(
            fixture.env,
            UUID,
            "198.51.100.44",
            "2027-07-21T00:00:00.000Z",
          ),
          /records write failed/,
        );
      } else {
        await assert.rejects(
          adminTest.restoreIpGroupFromTrash(fixture.env, "trash-group"),
          /records write failed/,
        );
      }
    });
    assert.deepEqual(fixture.listItems, [], action);
    assert.equal(fixture.markers.size, 0, action);
    assert.deepEqual(fixture.deletedIds, ["created-1"], action);
  }
});

test("invite restore writes records before AuthState and rolls back when that write fails", async () => {
  const fixture = fixtureEnv({
    invites: [],
    trash: [{
      id: "trash-invite",
      type: "uuid",
      deletedAt: "2026-07-21T00:00:00.000Z",
      invite: { ...invite(), apiConfigs: [], sub2apiSync: { userId: 9, tokenId: 17 } },
      records: [{ id: "group-restore", ips: visitorIps() }],
    }],
    failRecordPuts: 1,
  });
  await withExternalMocks(fixture, async () => {
    await assert.rejects(
      adminTest.restoreInviteFromTrash(fixture.env, "trash-invite"),
      /records write failed/,
    );
  });
  assert.equal(fixture.restoreInviteCalls, 0);
  assert.deepEqual(fixture.syncActions, ["provision", "deprovision"]);
  assert.deepEqual(fixture.listItems, []);
  assert.equal(fixture.markers.size, 0);
});

test("an ambiguous KV write keeps a now-referenced item and resolves its marker", async () => {
  const fixture = fixtureEnv({
    invites: [invite()],
    failRecordPuts: 1,
    commitRecordBeforeThrow: true,
  });
  await withExternalMocks(fixture, async () => {
    await assert.rejects(
      authorizeVisitorIps(fixture.env, request(), invite(), visitorIps()),
      /records write failed/,
    );
  });
  assert.equal(fixture.listItems[0].id, "created-1");
  assert.deepEqual(fixture.deletedIds, []);
  assert.equal(fixture.markers.size, 0);
  assert.match(fixture.values.get(`records:${UUID}`), /created-1/);
  assert.equal(fixture.activeRecordLeaseCount, 0);
});

test("a pre-existing List item is never deleted when the local records write fails", async () => {
  const fixture = fixtureEnv({ invites: [invite()], failRecordPuts: 1 });
  fixture.listItems.push({ id: "pre-existing", ip: VALUE, comment: "managed elsewhere" });
  await withExternalMocks(fixture, async () => {
    await assert.rejects(
      authorizeVisitorIps(fixture.env, request(), invite(), visitorIps()),
      /records write failed/,
    );
  });
  assert.deepEqual(fixture.listItems.map((item) => item.id), ["pre-existing"]);
  assert.deepEqual(fixture.deletedIds, []);
  assert.equal(fixture.markers.size, 0);
  assert.equal(fixture.activeRecordLeaseCount, 0);
});

test("a pre-existing List item is linked to another invite without being duplicated", async () => {
  const fixture = fixtureEnv({ invites: [invite()] });
  fixture.listItems.push({ id: "pre-existing", ip: VALUE, comment: "managed elsewhere" });

  await withExternalMocks(fixture, async () => {
    const result = await authorizeVisitorIps(fixture.env, request(), invite(), visitorIps());
    assert.equal(result.ok, true);
    assert.equal(result.items[0].listItemId, "pre-existing");
    assert.equal(result.items[0].alreadyListed, true);
  });

  assert.deepEqual(fixture.listItems.map((item) => item.id), ["pre-existing"]);
  assert.deepEqual(fixture.deletedIds, []);
  assert.match(fixture.values.get(`records:${UUID}`), /pre-existing/);
  assert.equal(fixture.activeRecordLeaseCount, 0);
});

test("delete failure leaves a leased marker and the scheduler later reconciles it", async () => {
  const fixture = fixtureEnv({ invites: [invite()], failRecordPuts: 1 });
  fixture.failDeletes = true;
  await withExternalMocks(fixture, async () => {
    await assert.rejects(
      authorizeVisitorIps(fixture.env, request(), invite(), visitorIps()),
      /cloudflare_mutation_compensation_failed/,
    );
    assert.equal(fixture.activeRecordLeaseCount, 0);
    assert.equal(fixture.markers.size, 1);
    fixture.failDeletes = false;
    const retryAt = Math.max(...[...fixture.markers.values()].map((marker) => marker.notBefore));
    const reconciled = await adminTest.reconcilePendingCloudflareMutations(fixture.env, retryAt);
    assert.deepEqual(reconciled, { checked: 1, deleted: 1, retained: 0 });
  });
  assert.deepEqual(fixture.listItems, []);
  assert.equal(fixture.markers.size, 0);
});

test("reconciliation preserves a cross-invite reference after the managed comment changes", async () => {
  const otherUuid = "8d595f85-7e04-44e2-a552-11d8e9c5bc22";
  const fixture = fixtureEnv({ invites: [invite(), { ...invite(), uuid: otherUuid }] });
  const mutationId = "f".repeat(64);
  const itemId = "created-cross-invite";
  fixture.markers.set(mutationId, {
    mutationId,
    comment: `sub2api ref ${"d".repeat(32)}`,
    expectedValueHashes: [await cloudflareListValueHmac(HMAC_KEY, VALUE)],
    itemIds: [itemId],
    createdAt: 1,
    notBefore: 1,
    leaseUntil: 0,
  });
  fixture.listItems.push({ id: itemId, ip: VALUE, comment: "comment edited after creation" });
  fixture.values.set(`records:${otherUuid}`, JSON.stringify([{
    id: "other-invite-network",
    ips: [{ listItemId: itemId, listValue: VALUE }],
  }]));

  await withExternalMocks(fixture, async () => {
    const result = await adminTest.compensateCloudflareMutation(fixture.env, mutationId);
    assert.deepEqual(result, { deleted: 0, retained: 1, pending: false });
  });

  assert.deepEqual(fixture.deletedIds, []);
  assert.equal(fixture.listItems.length, 1);
  assert.equal(fixture.markers.size, 0);
});

test("ambiguous create never accepts a stale item after compensation deletes it", async () => {
  const markers = new Map();
  let listRead = 0;
  let deleted = false;
  const staleItem = { id: "stale-created-item", ip: VALUE, comment: "" };
  const stub = {
    async status() { return { migrated: true }; },
    async getInvites() { return { revision: 0, items: [] }; },
    async registerCloudflareMutation(marker) {
      staleItem.comment = marker.comment;
      markers.set(marker.mutationId, structuredClone(marker));
      return { ok: true, created: true };
    },
    async updateCloudflareMutationItems(mutationId, itemIds) {
      const marker = markers.get(mutationId);
      markers.set(mutationId, { ...marker, itemIds: structuredClone(itemIds) });
      return { ok: true, updated: true };
    },
    async getCloudflareMutation(mutationId) {
      return structuredClone(markers.get(mutationId) || null);
    },
    async resolveCloudflareMutation(mutationId) {
      markers.delete(mutationId);
      return { ok: true, resolved: true };
    },
    async releaseCloudflareMutation() { return { ok: true, released: true }; },
    async claimRecordMaintenanceLease(_ownerToken, now, leaseMs) {
      return { claimed: true, leaseUntil: now + leaseMs };
    },
    async releaseRecordMaintenanceLease() { return { released: true }; },
  };
  const env = {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_STORE: { async get() { return null; } },
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    CLOUDFLARE_API_TOKEN: "token",
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    if (url.pathname.includes("/bulk_operations/")) {
      return Response.json({ success: true, result: { status: "completed" } });
    }
    if (method === "POST") {
      return Response.json({ success: false, errors: [{ code: "ambiguous" }] }, { status: 503 });
    }
    if (method === "DELETE") {
      deleted = true;
      return Response.json({ success: true, result: { operation_id: "delete-operation" } });
    }
    listRead += 1;
    const items = listRead === 1 || listRead === 2
      ? []
      : [structuredClone(staleItem)];
    return Response.json({
      success: true,
      result: items,
      result_info: { cursors: { after: "" } },
    });
  };

  try {
    await assert.rejects(
      adminTest.ensureManagedCloudflareEntries(env, [{ ip: "198.51.100.44", listValue: VALUE }]),
      /Cloudflare allowlist update failed/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(deleted, true);
  assert.equal(markers.size, 0);
  assert.equal(listRead, 3, "no post-compensation stale re-list may be trusted");
});

function fixtureEnv({
  invites,
  trash = [],
  failRecordPuts = 0,
  commitRecordBeforeThrow = false,
}) {
  const values = new Map();
  const markers = new Map();
  const listItems = [];
  const deletedIds = [];
  const syncActions = [];
  let remainingFailedPuts = failRecordPuts;
  let restoreInviteCalls = 0;
  let cloudflareFetchCount = 0;
  const recordLeases = new Map();
  const stub = {
    async status() { return { migrated: true }; },
    async getInvites() { return { revision: 1, items: structuredClone(invites) }; },
    async getTrash() { return { revision: 1, items: structuredClone(trash) }; },
    async restoreInvite() {
      restoreInviteCalls += 1;
      return { ok: true, restored: true, inviteRevision: 2, trashRevision: 2 };
    },
    async purgeTrash() { return { ok: true, purged: true, revision: 2 }; },
    async registerCloudflareMutation(marker) {
      markers.set(marker.mutationId, structuredClone(marker));
      return { ok: true, created: true };
    },
    async updateCloudflareMutationItems(mutationId, itemIds) {
      const marker = markers.get(mutationId);
      if (marker) markers.set(mutationId, { ...marker, itemIds: structuredClone(itemIds) });
      return { ok: true, updated: Boolean(marker) };
    },
    async getCloudflareMutation(mutationId) {
      return structuredClone(markers.get(mutationId) || null);
    },
    async resolveCloudflareMutation(mutationId) {
      return { ok: true, resolved: markers.delete(mutationId) };
    },
    async releaseCloudflareMutation(mutationId, retryAt) {
      const marker = markers.get(mutationId);
      if (marker) markers.set(mutationId, { ...marker, notBefore: retryAt, leaseUntil: 0 });
      return { ok: true, released: Boolean(marker) };
    },
    async claimCloudflareMutations(now, limit, leaseMs) {
      const claimed = [...markers.values()]
        .filter((marker) => marker.notBefore <= now && marker.leaseUntil <= now)
        .sort((left, right) => left.createdAt - right.createdAt)
        .slice(0, limit)
        .map((marker) => ({ ...marker, leaseUntil: now + leaseMs }));
      for (const marker of claimed) markers.set(marker.mutationId, structuredClone(marker));
      return structuredClone(claimed);
    },
    async listCloudflareMutationComments() {
      return [...markers.values()].map((marker) => marker.comment);
    },
    async claimRecordLease(uuid, ownerToken, now, leaseMs) {
      const current = recordLeases.get(uuid);
      if (current && current.leaseUntil > now && current.ownerToken !== ownerToken) {
        return { claimed: false, leaseUntil: current.leaseUntil };
      }
      const leaseUntil = now + leaseMs;
      recordLeases.set(uuid, { ownerToken, leaseUntil });
      return { claimed: true, leaseUntil };
    },
    async releaseRecordLease(uuid, ownerToken) {
      const current = recordLeases.get(uuid);
      if (!current || current.ownerToken !== ownerToken) return { released: false };
      recordLeases.delete(uuid);
      return { released: true };
    },
    async claimRecordMaintenanceLease(ownerToken, now, leaseMs) {
      const blocking = [...recordLeases.values()]
        .filter((entry) => entry.ownerToken !== ownerToken && entry.leaseUntil > now)
        .reduce((latest, entry) => Math.max(latest, entry.leaseUntil), 0);
      if (blocking) return { claimed: false, leaseUntil: blocking };
      const leaseUntil = now + leaseMs;
      recordLeases.set("*", { ownerToken, leaseUntil });
      return { claimed: true, leaseUntil };
    },
    async releaseRecordMaintenanceLease(ownerToken) {
      const current = recordLeases.get("*");
      if (!current || current.ownerToken !== ownerToken) return { released: false };
      recordLeases.delete("*");
      return { released: true };
    },
  };
  const fixture = {
    values,
    markers,
    listItems,
    deletedIds,
    syncActions,
    failDeletes: false,
    beforeCloudflareFetch: null,
    async noteCloudflareFetch() {
      cloudflareFetchCount += 1;
      await this.beforeCloudflareFetch?.(cloudflareFetchCount);
    },
    get restoreInviteCalls() { return restoreInviteCalls; },
    get cloudflareFetchCount() { return cloudflareFetchCount; },
    get activeRecordLeaseCount() { return recordLeases.size; },
  };
  fixture.env = {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_STORE: {
      async get(key) { return values.get(key) ?? null; },
      async put(key, value) {
        if (key.startsWith("records:") && remainingFailedPuts > 0) {
          remainingFailedPuts -= 1;
          if (commitRecordBeforeThrow) values.set(key, value);
          throw new Error("records write failed");
        }
        values.set(key, value);
      },
      async delete(key) { values.delete(key); },
    },
    CREDENTIAL_ENCRYPTION_KEY: ENCRYPTION_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    CLOUDFLARE_API_TOKEN: "token",
    ALLOWED_HOSTNAMES: "api.example.test",
    SUB2API_SYNC_SECRET: "test-only-sync-secret-with-at-least-32-bytes",
    SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
    SUB2API_DEFAULT_BASE_URL: "https://api.example.test/v1",
    SUB2API_LOGIN_URL: "https://api.example.test/login",
  };
  return fixture;
}

async function withExternalMocks(fixture, callback) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    if (url.hostname === "api.cloudflare.com") {
      await fixture.noteCloudflareFetch();
      if (url.pathname.includes("/bulk_operations/")) {
        return Response.json({ success: true, result: { status: "completed" } });
      }
      if (method === "GET") {
        return Response.json({
          success: true,
          result: structuredClone(fixture.listItems),
          result_info: { cursors: { after: "" } },
        });
      }
      if (method === "POST") {
        for (const item of JSON.parse(init.body)) {
          fixture.listItems.push({
            id: `created-${fixture.listItems.length + 1}`,
            ip: item.ip,
            comment: item.comment,
          });
        }
        return Response.json({ success: true, result: [] });
      }
      if (fixture.failDeletes) {
        return Response.json({ success: false, errors: [{ code: "delete_failed" }] }, { status: 400 });
      }
      const ids = JSON.parse(init.body).items.map((item) => item.id);
      fixture.deletedIds.push(...ids);
      for (let index = fixture.listItems.length - 1; index >= 0; index -= 1) {
        if (ids.includes(fixture.listItems[index].id)) fixture.listItems.splice(index, 1);
      }
      return Response.json({ success: true, result: { operation_id: "delete-operation" } });
    }

    const body = JSON.parse(init.body);
    fixture.syncActions.push(body.action);
    return Response.json({
      ok: true,
      action: body.action,
      uuid: body.uuid,
      username: body.username || "restored",
      email: body.email || "restored@example.test",
      userId: body.sub2apiUserId || 9,
      tokenId: 17,
      apiKeyId: 17,
      loginPassword: body.loginPassword || "generated-password",
      passwordHashFingerprint: "f".repeat(64),
      tokens: [],
    });
  };
  try {
    return await callback();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function invite() {
  return {
    uuid: UUID,
    username: "alice",
    name: "alice",
    email: "alice@example.test",
    apiConfigs: [],
    sub2apiSync: {},
    createdAt: "2026-07-21T00:00:00.000Z",
  };
}

function visitorIps() {
  return [{
    ip: "198.51.100.44",
    version: "IPv4",
    cidr: VALUE,
    listValue: VALUE,
  }];
}

function request() {
  return new Request("https://api.example.test/allow-ip", {
    headers: { "CF-Connecting-IP": "198.51.100.44" },
  });
}
