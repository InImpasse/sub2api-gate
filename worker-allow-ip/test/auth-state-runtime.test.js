import assert from "node:assert/strict";
import test from "node:test";

import { Miniflare } from "miniflare";

const UUID = "123e4567-e89b-42d3-a456-426614174000";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const SESSION_HASH = "c".repeat(64);
const ENCRYPTION_KEY = "A".repeat(43);
const HMAC_KEY = "h".repeat(32);
const VALID_ENVELOPE_V2 = {
  v: 2,
  alg: "A256GCM",
  iv: "AAAAAAAAAAAAAAAA",
  data: "AAAAAAAAAAAAAAAAAAAAAA",
};

function invite(accessCredentialVersion = 1, accessKeyHmac = HASH_A) {
  return {
    uuid: UUID,
    username: "alice",
    credentialVersion: 2,
    accessCredentialVersion,
    accessKeyHmac,
    apiConfigs: [],
    sub2apiSync: { username: "alice", syncedAt: "2026-07-21T00:00:00.000Z" },
  };
}

function pageInvite(index, migrated = true) {
  return {
    ...invite(migrated ? 1 : 0, migrated ? (index + 1).toString(16).padStart(64, "0") : ""),
    uuid: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
    username: `user-${index}`,
    credentialVersion: migrated ? 2 : 1,
    createdAt: new Date(Date.UTC(2026, 0, 1, 0, index)).toISOString(),
  };
}

function pageTrash(index) {
  return {
    id: `trash-${index}`,
    type: "ip_group",
    uuid: pageInvite(index).uuid,
    deletedAt: new Date(Date.UTC(2026, 0, 2, 0, index)).toISOString(),
    group: { id: `group-${index}`, ips: [{ ip: `198.51.100.${index}` }] },
  };
}

function makeMiniflare() {
  return new Miniflare({
    modules: true,
    scriptPath: new URL("../test-support/auth-state-harness.js", import.meta.url).pathname,
    modulesRoot: new URL("..", import.meta.url).pathname,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    compatibilityDate: "2026-05-03",
    compatibilityFlags: ["nodejs_compat"],
    bindings: {
      CREDENTIAL_ENCRYPTION_KEY: ENCRYPTION_KEY,
      INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
    },
    kvNamespaces: ["INVITE_STORE"],
    durableObjects: {
      AUTH_STATE: {
        className: "AuthState",
        useSQLite: true,
      },
    },
  });
}

async function post(miniflare, path, body) {
  const response = await miniflare.dispatchFetch(`http://worker.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const value = await response.json();
  assert.equal(response.status, 200, `${path}: ${JSON.stringify(value)}`);
  return value;
}

async function postRaw(miniflare, path, body) {
  const response = await miniflare.dispatchFetch(`http://worker.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, value: await response.json() };
}

test("AuthState serializes concurrent invite writes with a revision CAS", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());

  const imported = await post(miniflare, "/import", {
    snapshot: { invites: [invite()], trash: [], adminSessions: [], publicSessions: [] },
    importedAt: "2026-07-21T00:00:00.000Z",
  });
  assert.equal(imported.imported, true);
  const snapshot = await (await miniflare.dispatchFetch("http://worker.test/invites")).json();
  assert.equal(snapshot.revision, 1);

  const [first, second] = await Promise.all([
    post(miniflare, "/replace-invites", {
      revision: snapshot.revision,
      items: [{ ...invite(), username: "first" }],
    }),
    post(miniflare, "/replace-invites", {
      revision: snapshot.revision,
      items: [{ ...invite(), username: "second" }],
    }),
  ]);
  assert.equal([first, second].filter((result) => result.ok).length, 1);
  assert.equal([first, second].filter((result) => result.conflict).length, 1);
  const final = await (await miniflare.dispatchFetch("http://worker.test/invites")).json();
  assert.equal(final.revision, 2);
  assert.match(final.items[0].username, /^first|second$/);
});

test("credential migration commits at most 25 invites atomically and keeps the legacy deadline", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const invites = Array.from({ length: 30 }, (_, index) => pageInvite(index, false));
  await post(miniflare, "/import", {
    snapshot: { invites, trash: [], adminSessions: [], publicSessions: [] },
  });

  const first = await post(miniflare, "/credential-migration-batch", { limit: 25 });
  assert.equal(first.items.length, 25);
  assert.equal(first.remainingCount, 30);
  const migratedAt = Date.now();
  const firstUpdates = first.items.map((item, index) => ({
    uuid: item.uuid,
    accessKeyHmac: (index + 100).toString(16).padStart(64, "0"),
    expectedAccessCredentialVersion: item.accessCredentialVersion,
  }));

  const stale = await post(miniflare, "/credential-migration-commit", {
    revision: first.revision + 1,
    updates: firstUpdates,
    migratedAt,
  });
  assert.equal(stale.conflict, true);
  assert.equal((await post(miniflare, "/credential-migration-batch", { limit: 25 })).remainingCount, 30);

  const beforeCommit = Date.now();
  const committed = await post(miniflare, "/credential-migration-commit", {
    revision: first.revision,
    updates: firstUpdates,
    migratedAt,
  });
  const afterCommit = Date.now();
  assert.equal(committed.ok, true);
  assert.equal(committed.migratedCount, 25);
  assert.equal(committed.remainingCount, 5);

  const second = await post(miniflare, "/credential-migration-batch", { limit: 25 });
  assert.equal(second.items.length, 5);
  assert.equal(second.remainingCount, 5);
  const migrated = await (await miniflare.dispatchFetch("http://worker.test/invites")).json();
  assert.equal(migrated.items.filter((item) => item.accessKeyHmac).length, 25);
  const deadline = Date.parse(
    migrated.items.find((item) => item.uuid === first.items[0].uuid).legacyUuidLoginUntil,
  );
  assert.ok(deadline >= beforeCommit + 7 * 24 * 60 * 60 * 1000);
  assert.ok(deadline <= afterCommit + 7 * 24 * 60 * 60 * 1000);

  const readiness = await post(miniflare, "/legacy-cleanup-readiness", { now: migratedAt });
  assert.equal(readiness.eligible, false);
  assert.equal(readiness.blockerCount, 5);
  assert.equal(readiness.activeDeadlineCount, 25);

  const oversized = await postRaw(miniflare, "/credential-migration-batch", { limit: 26 });
  assert.equal(oversized.response.status, 500);
  assert.equal(oversized.value.error, "auth_state_credential_migration_batch_invalid");
});

test("record leases serialize one invite without blocking other invite UUIDs", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const otherUuid = "8d595f85-7e04-44e2-a552-11d8e9c5bc22";
  const ownerA = "a".repeat(64);
  const ownerB = "b".repeat(64);
  const now = 1_000_000;
  const leaseMs = 60_000;

  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: UUID, ownerToken: ownerA, now, leaseMs,
  }), { claimed: true, leaseUntil: now + leaseMs });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: UUID, ownerToken: ownerB, now: now + 1, leaseMs,
  }), { claimed: false, leaseUntil: now + leaseMs });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: otherUuid, ownerToken: ownerB, now: now + 1, leaseMs,
  }), { claimed: true, leaseUntil: now + leaseMs + 1 });

  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "release", uuid: UUID, ownerToken: ownerB,
  }), { released: false });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: UUID, ownerToken: ownerB, now: now + 2, leaseMs,
  }), { claimed: false, leaseUntil: now + leaseMs });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "release", uuid: UUID, ownerToken: ownerA,
  }), { released: true });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: UUID, ownerToken: ownerB, now: now + 3, leaseMs,
  }), { claimed: true, leaseUntil: now + leaseMs + 3 });

  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: UUID, ownerToken: ownerA, now: now + leaseMs + 3, leaseMs,
  }), { claimed: true, leaseUntil: now + (2 * leaseMs) + 3 });
});

test("record maintenance lease excludes active and future per-invite mutations", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const otherUuid = "8d595f85-7e04-44e2-a552-11d8e9c5bc22";
  const ownerA = "a".repeat(64);
  const ownerB = "b".repeat(64);
  const now = 2_000_000;
  const leaseMs = 60_000;

  await post(miniflare, "/record-lease", {
    action: "claim", uuid: UUID, ownerToken: ownerA, now, leaseMs,
  });
  assert.deepEqual(await post(miniflare, "/record-maintenance-lease", {
    action: "claim", ownerToken: ownerB, now: now + 1, leaseMs,
  }), { claimed: false, leaseUntil: now + leaseMs });
  await post(miniflare, "/record-lease", {
    action: "release", uuid: UUID, ownerToken: ownerA,
  });

  assert.deepEqual(await post(miniflare, "/record-maintenance-lease", {
    action: "claim", ownerToken: ownerB, now: now + 2, leaseMs,
  }), { claimed: true, leaseUntil: now + leaseMs + 2 });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: otherUuid, ownerToken: ownerA, now: now + 3, leaseMs,
  }), { claimed: false, leaseUntil: now + leaseMs + 2 });
  assert.deepEqual(await post(miniflare, "/record-maintenance-lease", {
    action: "release", ownerToken: ownerB,
  }), { released: true });
  assert.deepEqual(await post(miniflare, "/record-lease", {
    action: "claim", uuid: otherUuid, ownerToken: ownerA, now: now + 4, leaseMs,
  }), { claimed: true, leaseUntil: now + leaseMs + 4 });
});

test("Cloudflare reconciliation ledger is bounded, leased, private and idempotent", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  await post(miniflare, "/import", {
    snapshot: { invites: [], trash: [], adminSessions: [], publicSessions: [] },
  });
  const marker = {
    mutationId: "a".repeat(64),
    comment: `sub2api ref ${"b".repeat(32)}`,
    expectedValueHashes: ["c".repeat(64), "d".repeat(64)],
    itemIds: [],
    createdAt: 1_000_000,
    notBefore: 1_120_000,
    leaseUntil: 0,
  };
  assert.deepEqual(
    await post(miniflare, "/cloudflare-mutation", { action: "register", marker }),
    { ok: true, created: true },
  );
  const stored = await post(miniflare, "/cloudflare-mutation", {
    action: "get",
    mutationId: marker.mutationId,
  });
  assert.deepEqual(stored, marker);
  assert.doesNotMatch(JSON.stringify(stored), /7c484f74|198\.51\.100|203\.0\.113/);
  assert.deepEqual(
    await post(miniflare, "/cloudflare-mutation", { action: "comments" }),
    [marker.comment],
  );

  assert.deepEqual(await post(miniflare, "/cloudflare-mutation", {
    action: "claim", now: marker.notBefore - 1, limit: 25, leaseMs: 60_000,
  }), []);
  const claimed = await post(miniflare, "/cloudflare-mutation", {
    action: "claim", now: marker.notBefore, limit: 25, leaseMs: 60_000,
  });
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].leaseUntil, marker.notBefore + 60_000);
  assert.deepEqual(await post(miniflare, "/cloudflare-mutation", {
    action: "claim", now: marker.notBefore + 1, limit: 25, leaseMs: 60_000,
  }), []);

  assert.deepEqual(await post(miniflare, "/cloudflare-mutation", {
    action: "update", mutationId: marker.mutationId, itemIds: ["item-one"],
  }), { ok: true, updated: true });
  assert.deepEqual(await post(miniflare, "/cloudflare-mutation", {
    action: "release", mutationId: marker.mutationId, retryAt: marker.notBefore + 2,
  }), { ok: true, released: true });
  assert.equal((await post(miniflare, "/cloudflare-mutation", {
    action: "claim", now: marker.notBefore + 2, limit: 25, leaseMs: 60_000,
  }))[0].itemIds[0], "item-one");
  assert.deepEqual(await post(miniflare, "/cloudflare-mutation", {
    action: "resolve", mutationId: marker.mutationId,
  }), { ok: true, resolved: true });
  assert.deepEqual(await post(miniflare, "/cloudflare-mutation", {
    action: "resolve", mutationId: marker.mutationId,
  }), { ok: true, resolved: false });

  const unsafe = await postRaw(miniflare, "/cloudflare-mutation", {
    action: "register",
    marker: { ...marker, mutationId: "e".repeat(64), ip: "198.51.100.44" },
  });
  assert.equal(unsafe.response.status, 500);
  assert.equal(unsafe.value.error, "auth_state_cloudflare_mutation_invalid");
});

test("admin pages are independently bounded, globally counted, and deterministically ordered", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const invites = Array.from({ length: 60 }, (_, index) => pageInvite(index, index >= 7));
  const trash = Array.from({ length: 53 }, (_, index) => pageTrash(index));
  invites[34].apiConfigs = [{
    id: "credential-34",
    name: "OpenAI",
    baseUrl: "https://provider.example.test/v1",
    apiKeyEncrypted: VALID_ENVELOPE_V2,
  }];
  invites[34].sub2apiSync.loginPasswordEncrypted = VALID_ENVELOPE_V2;
  await post(miniflare, "/import", {
    snapshot: { invites, trash, adminSessions: [], publicSessions: [] },
  });

  const page = await post(miniflare, "/admin-page", {
    inviteOffset: 25,
    inviteLimit: 25,
    trashOffset: 25,
    trashLimit: 25,
  });
  assert.equal(page.inviteRevision, 1);
  assert.equal(page.trashRevision, 1);
  assert.equal(page.inviteCount, 60);
  assert.equal(page.trashCount, 53);
  assert.equal(page.unmigratedInviteCount, 7);
  assert.equal(page.invites.length, 25);
  assert.equal(page.invites[0].username, "user-34");
  assert.equal(page.invites.at(-1).username, "user-10");
  assert.equal(page.invites[0].apiConfigCount, 1);
  assert.equal(page.invites[0].accessKeyHmac, "configured");
  assert.equal(Object.hasOwn(page.invites[0], "apiConfigs"), false);
  assert.equal(page.trash.length, 25);
  assert.equal(page.trash[0].id, "trash-27");
  assert.equal(page.trash.at(-1).id, "trash-3");
  assert.equal(page.trash[0].group.ipCount, 1);
  assert.equal(Object.hasOwn(page.trash[0].group, "ips"), false);
  assert.doesNotMatch(
    JSON.stringify(page),
    /PRIVATE_IV|PRIVATE_DATA|PRIVATE_LOGIN_IV|PRIVATE_LOGIN_DATA|198\.51\.100\./,
  );

  const maximum = await post(miniflare, "/admin-page", {
    inviteOffset: 0,
    inviteLimit: 50,
    trashOffset: 0,
    trashLimit: 50,
  });
  assert.equal(maximum.invites.length, 50);
  assert.equal(maximum.trash.length, 50);
});

test("admin page RPC rejects invalid offsets, limits, and non-number coercions", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  await post(miniflare, "/import", {
    snapshot: { invites: [], trash: [], adminSessions: [], publicSessions: [] },
  });
  const cases = [
    [{ inviteOffset: -1 }, "auth_state_invite_page_invalid"],
    [{ inviteOffset: 10_001 }, "auth_state_invite_page_invalid"],
    [{ inviteOffset: 1.5 }, "auth_state_invite_page_invalid"],
    [{ inviteOffset: "1" }, "auth_state_invite_page_invalid"],
    [{ inviteOffset: null }, "auth_state_invite_page_invalid"],
    [{ inviteLimit: 0 }, "auth_state_invite_page_invalid"],
    [{ inviteLimit: 51 }, "auth_state_invite_page_invalid"],
    [{ inviteLimit: true }, "auth_state_invite_page_invalid"],
    [{ trashOffset: -1 }, "auth_state_trash_page_invalid"],
    [{ trashOffset: 20_001 }, "auth_state_trash_page_invalid"],
    [{ trashLimit: 0 }, "auth_state_trash_page_invalid"],
    [{ trashLimit: 50.5 }, "auth_state_trash_page_invalid"],
  ];
  for (const [body, expected] of cases) {
    const result = await postRaw(miniflare, "/admin-page", body);
    assert.equal(result.response.status, 500);
    assert.equal(result.value.error, expected);
  }
});

test("credential rotation and explicit logout revoke sessions immediately", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  await post(miniflare, "/import", {
    snapshot: { invites: [invite()], trash: [], adminSessions: [], publicSessions: [] },
  });
  const publicExpiry = Date.now() + 60 * 60 * 1000;
  await post(miniflare, "/public-session", {
    action: "put",
    hash: SESSION_HASH,
    payload: {
      uuid: UUID,
      csrf: "csrf-public",
      expiresAt: publicExpiry,
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
    },
  });
  const valid = await post(miniflare, "/public-session", { action: "get", hash: SESSION_HASH });
  assert.equal(valid.session.uuid, UUID);

  const snapshot = await (await miniflare.dispatchFetch("http://worker.test/invites")).json();
  const rotated = await post(miniflare, "/replace-invites", {
    revision: snapshot.revision,
    items: [invite(2, HASH_B)],
  });
  assert.equal(rotated.ok, true);
  const revoked = await post(miniflare, "/public-session", { action: "get", hash: SESSION_HASH });
  assert.equal(revoked, null);

  const adminHash = "d".repeat(64);
  await post(miniflare, "/admin-session", {
    action: "put",
    hash: adminHash,
    payload: { csrf: "csrf-admin", expiresAt: Date.now() + 60 * 60 * 1000 },
  });
  assert.equal((await post(miniflare, "/admin-session", { action: "get", hash: adminHash })).csrf, "csrf-admin");
  await post(miniflare, "/admin-session", { action: "delete", hash: adminHash });
  assert.equal(await post(miniflare, "/admin-session", { action: "get", hash: adminHash }), null);
});

test("invite removal uses both revisions and commits trash plus revocation atomically", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  await post(miniflare, "/import", {
    snapshot: { invites: [invite()], trash: [], adminSessions: [], publicSessions: [] },
  });
  await post(miniflare, "/public-session", {
    action: "put",
    hash: SESSION_HASH,
    payload: {
      uuid: UUID,
      csrf: "csrf-public",
      expiresAt: Date.now() + 60 * 60 * 1000,
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
    },
  });
  const trashItem = {
    id: "trash-atomic",
    type: "uuid",
    deletedAt: "2026-07-21T00:00:00.000Z",
    invite: { uuid: UUID, username: "alice", apiConfigs: [], sub2apiSync: {} },
    records: [],
  };
  const conflict = await post(miniflare, "/remove-invite", {
    inviteRevision: 1,
    trashRevision: 9,
    uuid: UUID,
    trashItem,
  });
  assert.equal(conflict.conflict, true);
  assert.equal((await post(miniflare, "/get-invite", { uuid: UUID })).uuid, UUID);
  assert.equal((await post(miniflare, "/public-session", { action: "get", hash: SESSION_HASH })).session.uuid, UUID);

  const removed = await post(miniflare, "/remove-invite", {
    inviteRevision: 1,
    trashRevision: 0,
    uuid: UUID,
    trashItem,
  });
  assert.deepEqual(
    { removed: removed.removed, inviteRevision: removed.inviteRevision, trashRevision: removed.trashRevision },
    { removed: true, inviteRevision: 2, trashRevision: 1 },
  );
  assert.equal(await post(miniflare, "/get-invite", { uuid: UUID }), null);
  assert.equal(await post(miniflare, "/public-session", { action: "get", hash: SESSION_HASH }), null);
  assert.equal((await miniflare.dispatchFetch("http://worker.test/trash").then((response) => response.json())).items[0].id, "trash-atomic");
});

test("AuthState rejects plaintext invite credentials and credential-bearing trash", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const plaintext = await postRaw(miniflare, "/import", {
    snapshot: {
      invites: [{ ...invite(), apiConfigs: [{ id: "openai", apiKey: "must-not-store" }] }],
      trash: [],
      adminSessions: [],
      publicSessions: [],
    },
  });
  assert.equal(plaintext.response.status, 500);
  assert.equal(plaintext.value.error, "auth_state_plaintext_credential");

  await post(miniflare, "/import", {
    snapshot: { invites: [invite()], trash: [], adminSessions: [], publicSessions: [] },
  });
  const trashCredential = await postRaw(miniflare, "/replace-trash", {
    revision: 0,
    items: [{
      id: "unsafe-trash",
      type: "uuid",
      invite: {
        uuid: UUID,
        apiKeyEncrypted: { v: 2, alg: "A256GCM", iv: "x", data: "y" },
      },
      records: [],
    }],
  });
  assert.equal(trashCredential.response.status, 500);
  assert.equal(trashCredential.value.error, "auth_state_trash_credential");
});

test("AuthState trash storage drops unknown content fields at every nesting level", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  await post(miniflare, "/import", {
    snapshot: { invites: [], trash: [], adminSessions: [], publicSessions: [] },
  });
  const result = await post(miniflare, "/replace-trash", {
    revision: 0,
    items: [{
      id: "strict-trash",
      type: "ip_group",
      uuid: UUID,
      deletedAt: "2026-07-21T00:00:00.000Z",
      prompt: "top-level-content-sentinel",
      group: {
        id: "group-1",
        country: "US",
        response_body: "group-content-sentinel",
        ips: [{
          ip: "203.0.113.7",
          cidr: "203.0.113.0/24",
          listValue: "203.0.113.0/24",
          content: "ip-content-sentinel",
        }],
      },
    }],
  });
  assert.equal(result.ok, true);

  const stored = await miniflare.dispatchFetch("http://worker.test/trash").then((response) => response.json());
  assert.equal(stored.items[0].group.country, "US");
  assert.equal(stored.items[0].group.ips[0].listValue, "203.0.113.0/24");
  assert.doesNotMatch(JSON.stringify(stored), /content-sentinel|prompt|response_body|content/);
});

test("AuthState rejects invite fields outside the v2 storage schema", { timeout: 30_000 }, async (t) => {
  for (const unsafeInvite of [
    { ...invite(), refresh_token: "unknown-top-level-credential" },
    {
      ...invite(),
      apiConfigs: [{ id: "openai", futureCredential: "unknown-api-credential" }],
    },
    {
      ...invite(),
      sub2apiSync: { ...invite().sub2apiSync, response_body: "unknown-sync-content" },
    },
  ]) {
    const miniflare = makeMiniflare();
    t.after(async () => await miniflare.dispose());
    const result = await postRaw(miniflare, "/import", {
      snapshot: {
        invites: [unsafeInvite],
        trash: [],
        adminSessions: [],
        publicSessions: [],
      },
    });
    assert.equal(result.response.status, 500);
    assert.equal(result.value.error, "auth_state_invite_schema_invalid");
  }
});

test("AuthState rejects malformed credential envelopes and raw fingerprints", { timeout: 30_000 }, async (t) => {
  const unsafeInvites = [
    {
      ...invite(),
      apiConfigs: [{
        id: "openai",
        apiKeyEncrypted: { ...VALID_ENVELOPE_V2, futureCredential: "nested-credential" },
      }],
    },
    {
      ...invite(),
      sub2apiSync: {
        ...invite().sub2apiSync,
        loginPasswordEncrypted: { ...VALID_ENVELOPE_V2, content: "nested-content" },
      },
    },
    {
      ...invite(),
      sub2apiSync: {
        ...invite().sub2apiSync,
        passwordHashFingerprint: "raw-password-hash",
      },
    },
    { ...invite(), accessKeyHmac: "raw-access-key" },
  ];

  for (const unsafeInvite of unsafeInvites) {
    const miniflare = makeMiniflare();
    t.after(async () => await miniflare.dispose());
    const result = await postRaw(miniflare, "/import", {
      snapshot: {
        invites: [unsafeInvite],
        trash: [],
        adminSessions: [],
        publicSessions: [],
      },
    });
    assert.equal(result.response.status, 500);
    assert.match(
      result.value.error,
      /^auth_state_(?:invite_schema|access_key_hmac)_invalid$/,
    );
  }
});

test("lazy migration protects credentials without deleting rollback state or scanning sessions", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const kv = await miniflare.getKVNamespace("INVITE_STORE");
  await kv.put("invites", JSON.stringify([{
    ...invite(),
    refresh_token: "legacy-top-level-refresh",
    prompt: "legacy-top-level-prompt",
    apiConfigs: [{
      id: "openai",
      name: "OpenAI",
      baseUrl: "https://api.example.test/v1",
      apiKey: "sk-legacy",
      futureCredential: "legacy-api-future",
      content: "legacy-api-content",
    }],
    sub2apiSync: {
      username: "alice",
      loginPassword: "legacy-password",
      passwordHash: "legacy-hash",
      access_token: "legacy-sync-access",
      response_body: "legacy-sync-response",
      futureCredential: "legacy-sync-future",
    },
  }]));
  await kv.put("trash", JSON.stringify([{
    id: "trash-1",
    type: "uuid",
    deletedAt: "2026-07-20T00:00:00.000Z",
    invite: {
      ...invite(),
      prompt: "trash-prompt-must-not-survive",
      request_body: "trash-request-must-not-survive",
      response_body: "trash-response-must-not-survive",
      apiConfigs: [{ id: "x", apiKey: "must-not-survive", content: "trash-content-must-not-survive" }],
    },
    records: [{
      id: "legacy-group",
      country: "US",
      prompt: "trash-record-prompt-must-not-survive",
      ips: [{
        ip: "203.0.113.7",
        cidr: "203.0.113.0/24",
        listValue: "203.0.113.0/24",
        response_body: "trash-ip-response-must-not-survive",
      }],
    }],
  }]));
  await kv.put(`session:${SESSION_HASH}`, JSON.stringify({ csrf: "csrf-admin", expiresAt: Date.now() + 60 * 60 * 1000 }));
  await kv.put(`session:${"f".repeat(64)}`, JSON.stringify({ csrf: "expired", expiresAt: Date.now() - 1000 }));
  await kv.put(`uuid-session:${"e".repeat(64)}`, JSON.stringify({
    uuid: UUID,
    csrf: "csrf-public",
    expiresAt: Date.now() + 60 * 60 * 1000,
    authenticationMethod: "access_key",
    accessCredentialVersion: 1,
  }));
  await kv.put(`uuid-session:${"9".repeat(64)}`, JSON.stringify({
    uuid: "223e4567-e89b-42d3-a456-426614174000",
    csrf: "orphan",
    expiresAt: Date.now() + 60 * 60 * 1000,
    authenticationMethod: "access_key",
    accessCredentialVersion: 1,
  }));
  await kv.put(`records:${UUID}`, JSON.stringify([{ id: "group-1", ips: ["203.0.113.9"] }]));

  const status = await (await miniflare.dispatchFetch("http://worker.test/lazy-status")).json();
  assert.equal(status.migrated, true);
  assert.equal(status.legacyCleanupComplete, false);
  assert.notEqual(await kv.get("invites"), null);
  assert.notEqual(await kv.get("trash"), null);
  assert.equal((await kv.list({ prefix: "session:" })).keys.length, 2);
  assert.equal((await kv.list({ prefix: "uuid-session:" })).keys.length, 2);
  assert.equal(status.activeSessionCount, 0);
  assert.notEqual(await kv.get(`records:${UUID}`), null);
  const stored = await (await miniflare.dispatchFetch("http://worker.test/lazy-invites")).json();
  const serialized = JSON.stringify(stored);
  assert.doesNotMatch(serialized, /sk-legacy|legacy-password|legacy-hash/);
  assert.doesNotMatch(serialized, /legacy-(?:top-level|api|sync)/);
  assert.match(serialized, /apiKeyEncrypted/);
  assert.match(serialized, /loginPasswordEncrypted/);
  assert.match(serialized, /passwordHashFingerprint/);
  assert.equal((await post(miniflare, "/lazy-admin-session", { hash: SESSION_HASH })).csrf, "csrf-admin");
  assert.equal(await post(miniflare, "/lazy-admin-session", { hash: "f".repeat(64) }), null);
  assert.equal((await post(miniflare, "/lazy-public-session", { hash: "e".repeat(64) })).session.uuid, UUID);
  assert.equal(await post(miniflare, "/lazy-public-session", { hash: "9".repeat(64) }), null);
  const afterLazySessionReads = await (await miniflare.dispatchFetch("http://worker.test/lazy-status")).json();
  assert.equal(afterLazySessionReads.activeSessionCount, 2);
  assert.equal((await kv.list({ prefix: "session:" })).keys.length, 2);
  assert.equal((await kv.list({ prefix: "uuid-session:" })).keys.length, 2);
  const migratedTrash = await (await miniflare.dispatchFetch("http://worker.test/trash")).json();
  assert.doesNotMatch(
    JSON.stringify(migratedTrash),
    /must-not-survive|apiKeyEncrypted|accessKeyHmac|prompt|request_body|response_body|content/,
  );
  assert.equal(migratedTrash.items[0].records[0].ips[0].listValue, "203.0.113.0/24");
  const records = await post(miniflare, "/lazy-records", { uuid: UUID });
  assert.match(records.value, /203\.0\.113\.9/);

  await kv.put("invites", JSON.stringify([{ ...invite(), username: "changed-in-kv" }]));
  const unchanged = await (await miniflare.dispatchFetch("http://worker.test/lazy-invites")).json();
  assert.equal(unchanged.items[0].username, "alice");
});

test("legacy rollback state is deleted only by an explicit cleanup operation", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const kv = await miniflare.getKVNamespace("INVITE_STORE");
  await kv.put("invites", JSON.stringify([{
    ...invite(),
    legacyUuidLoginUntil: new Date(Date.now() + 60_000).toISOString(),
  }]));

  const initial = await (await miniflare.dispatchFetch("http://worker.test/lazy-status")).json();
  assert.equal(initial.migrated, true);
  assert.equal(initial.legacyCleanupComplete, false);

  await kv.put("trash", "late-private-trash");
  await kv.put(`session:${"1".repeat(64)}`, "late-private-admin-session");
  await kv.put(`uuid-session:${"2".repeat(64)}`, "late-private-public-session");
  for (const reason of ["migration", "alarm", "periodic"]) {
    const rejected = await postRaw(miniflare, "/legacy-cleanup-run", { reason });
    assert.equal(rejected.response.status, 500);
    assert.equal(rejected.value.error, "auth_state_legacy_cleanup_reason_invalid");
  }
  assert.notEqual(await kv.get("invites"), null);
  assert.notEqual(await kv.get("trash"), null);
  assert.equal((await kv.list({ prefix: "session:" })).keys.length, 1);
  assert.equal((await kv.list({ prefix: "uuid-session:" })).keys.length, 1);

  const early = await postRaw(miniflare, "/legacy-cleanup-run", { reason: "explicit" });
  assert.equal(early.response.status, 500);
  assert.equal(early.value.error, "auth_state_legacy_cleanup_deadline_active");
  assert.notEqual(await kv.get("invites"), null);
  assert.notEqual(await kv.get("trash"), null);

  const migrated = await (await miniflare.dispatchFetch("http://worker.test/invites")).json();
  const expired = await post(miniflare, "/replace-invites", {
    revision: migrated.revision,
    items: [{ ...migrated.items[0], legacyUuidLoginUntil: new Date(Date.now() - 1_000).toISOString() }],
  });
  assert.equal(expired.ok, true);

  const explicit = await post(miniflare, "/legacy-cleanup-run", { reason: "explicit" });
  assert.equal(explicit.cleaned, true);
  assert.equal(await kv.get("invites"), null);
  assert.equal(await kv.get("trash"), null);
  assert.equal((await kv.list({ prefix: "session:" })).keys.length, 0);
  assert.equal((await kv.list({ prefix: "uuid-session:" })).keys.length, 0);
});

test("legacy invite migration rejects a UTF-8 collection above the byte limit", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const kv = await miniflare.getKVNamespace("INVITE_STORE");
  const raw = JSON.stringify(["界".repeat(Math.floor((4 * 1024 * 1024) / 3) + 1)]);
  assert.ok(raw.length < 4 * 1024 * 1024);
  assert.ok(new TextEncoder().encode(raw).byteLength > 4 * 1024 * 1024);
  await kv.put("invites", raw);

  const response = await miniflare.dispatchFetch("http://worker.test/lazy-status");
  const result = await response.json();
  assert.equal(response.status, 500);
  assert.equal(result.error, "auth_state_legacy_collection_too_large");
});

test("legacy migration skips a session above the UTF-8 byte limit", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const kv = await miniflare.getKVNamespace("INVITE_STORE");
  await kv.put("invites", JSON.stringify([invite()]));
  const oversizedSessionHash = "8".repeat(64);
  const raw = JSON.stringify({
    csrf: "界".repeat(Math.floor((64 * 1024) / 3) + 1),
    expiresAt: Date.now() + 60 * 60 * 1000,
  });
  assert.ok(raw.length < 64 * 1024);
  assert.ok(new TextEncoder().encode(raw).byteLength > 64 * 1024);
  await kv.put(`session:${oversizedSessionHash}`, raw);

  const status = await miniflare.dispatchFetch("http://worker.test/lazy-status");
  assert.equal(status.status, 200);
  assert.equal(
    await post(miniflare, "/admin-session", { action: "get", hash: oversizedSessionHash }),
    null,
  );
});

test("application logout deletes both AuthState and the matching legacy KV session", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const kv = await miniflare.getKVNamespace("INVITE_STORE");
  const adminHash = "5".repeat(64);
  const publicHash = "6".repeat(64);
  await kv.put("invites", JSON.stringify([invite()]));
  await kv.put(`session:${adminHash}`, JSON.stringify({
    csrf: "legacy-admin-csrf",
    expiresAt: Date.now() + 60_000,
  }));
  await kv.put(`uuid-session:${publicHash}`, JSON.stringify({
    uuid: UUID,
    csrf: "legacy-public-csrf",
    expiresAt: Date.now() + 60_000,
    authenticationMethod: "access_key",
    accessCredentialVersion: 1,
  }));

  assert.equal((await post(miniflare, "/lazy-admin-session", { hash: adminHash })).csrf, "legacy-admin-csrf");
  assert.equal((await post(miniflare, "/lazy-public-session", { hash: publicHash })).session.uuid, UUID);
  await post(miniflare, "/lazy-delete-session", { kind: "admin", hash: adminHash });
  await post(miniflare, "/lazy-delete-session", { kind: "public", hash: publicHash });

  assert.equal(await kv.get(`session:${adminHash}`), null);
  assert.equal(await kv.get(`uuid-session:${publicHash}`), null);
  assert.equal(await post(miniflare, "/lazy-admin-session", { hash: adminHash }), null);
  assert.equal(await post(miniflare, "/lazy-public-session", { hash: publicHash }), null);
});

test("legacy KV sessions survive credential migration only through the seven-day deadline", { timeout: 30_000 }, async (t) => {
  const miniflare = makeMiniflare();
  t.after(async () => await miniflare.dispose());
  const kv = await miniflare.getKVNamespace("INVITE_STORE");
  await kv.put("invites", JSON.stringify([{
    uuid: UUID,
    username: "legacy",
    credentialVersion: 1,
    accessCredentialVersion: 0,
    apiConfigs: [],
    sub2apiSync: {},
  }]));
  const legacyHash = "7".repeat(64);
  const originalExpiry = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await kv.put(`uuid-session:${legacyHash}`, JSON.stringify({
    uuid: UUID,
    csrf: "legacy-csrf",
    expiresAt: originalExpiry,
  }));

  await miniflare.dispatchFetch("http://worker.test/lazy-status");
  const imported = await post(miniflare, "/lazy-public-session", { hash: legacyHash });
  assert.equal(imported.session.authenticationMethod, "legacy_uuid");
  assert.equal(imported.session.expiresAt, originalExpiry);

  const deadline = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const migratedInvite = {
    ...invite(1, HASH_A),
    legacyUuidLoginUntil: new Date(deadline).toISOString(),
  };
  const migrated = await post(miniflare, "/replace-invites", {
    revision: 1,
    items: [migratedInvite],
  });
  assert.equal(migrated.ok, true);
  const retained = await post(miniflare, "/lazy-public-session", { hash: legacyHash });
  assert.equal(retained.session.authenticationMethod, "legacy_uuid");
  assert.ok(retained.session.expiresAt <= deadline);

  const rotated = await post(miniflare, "/replace-invites", {
    revision: 2,
    items: [invite(2, HASH_B)],
  });
  assert.equal(rotated.ok, true);
  assert.equal(await post(miniflare, "/lazy-public-session", { hash: legacyHash }), null);
});

test("worker entrypoint fails closed when AUTH_STATE is missing", { timeout: 30_000 }, async (t) => {
  const miniflare = new Miniflare({
    modules: true,
    scriptPath: new URL("../src/worker-entry.js", import.meta.url).pathname,
    modulesRoot: new URL("..", import.meta.url).pathname,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    compatibilityDate: "2026-05-03",
    compatibilityFlags: ["nodejs_compat"],
    bindings: { ALLOWED_HOSTNAMES: "api.example.test" },
  });
  t.after(async () => await miniflare.dispose());
  const response = await miniflare.dispatchFetch("https://api.example.test/allow-ip");
  assert.equal(response.status, 503);
  assert.equal(await response.text(), "Service unavailable");
});

test("worker entrypoint fails closed for missing, empty, invalid, or overlapping provider hostnames", { timeout: 30_000 }, async (t) => {
  const cases = [
    {},
    { PROVIDER_ALLOWED_HOSTNAMES: "" },
    { PROVIDER_ALLOWED_HOSTNAMES: "127.0.0.1" },
    { PROVIDER_ALLOWED_HOSTNAMES: "api.example.test" },
  ];

  for (const overrides of cases) {
    const miniflare = new Miniflare({
      modules: true,
      scriptPath: new URL("../src/worker-entry.js", import.meta.url).pathname,
      modulesRoot: new URL("..", import.meta.url).pathname,
      modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
      compatibilityDate: "2026-07-21",
      compatibilityFlags: ["nodejs_compat"],
      bindings: {
        ALLOWED_HOSTNAMES: "api.example.test",
        ...overrides,
      },
      durableObjects: {
        AUTH_STATE: { className: "AuthState", useSQLite: true },
      },
    });
    t.after(async () => await miniflare.dispose());
    const response = await miniflare.dispatchFetch("https://api.example.test/allow-ip");
    assert.equal(response.status, 503, JSON.stringify(overrides));
    assert.equal(await response.text(), "Service unavailable");
  }
});

test("worker entrypoint accepts disjoint public and provider hostname allowlists", { timeout: 30_000 }, async (t) => {
  const miniflare = new Miniflare({
    modules: true,
    scriptPath: new URL("../src/worker-entry.js", import.meta.url).pathname,
    modulesRoot: new URL("..", import.meta.url).pathname,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    compatibilityDate: "2026-07-21",
    compatibilityFlags: ["nodejs_compat"],
    bindings: {
      ALLOWED_HOSTNAMES: "api.example.test",
      PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test",
    },
    durableObjects: {
      AUTH_STATE: { className: "AuthState", useSQLite: true },
    },
  });
  t.after(async () => await miniflare.dispose());
  const response = await miniflare.dispatchFetch("https://api.example.test/allow-ip");
  assert.equal(response.status, 200);
});
