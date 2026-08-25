import {
  hasInviteStorageSchema,
  protectInviteCredentials,
  revealInviteCredentials,
  sanitizeInviteForTrash,
} from "./credential-security.js";

export const AUTH_STATE_DO_NAME = "sub2api-gate-auth-state-v1";
export const AUTH_STATE_SCHEMA_VERSION = 4;

const MAX_INVITES = 10_000;
const MAX_TRASH_ITEMS = 20_000;
const MAX_SESSION_IMPORTS = 20_000;
const MAX_LEGACY_LIST_PAGES = 64;
const LEGACY_DELETE_CONCURRENCY = 16;
const MAX_ADMIN_PAGE_SIZE = 50;
const MAX_COLLECTION_BYTES = 4 * 1024 * 1024;
const MAX_ITEM_BYTES = 512 * 1024;
const MAX_SESSION_BYTES = 64 * 1024;
const MAX_CLOUDFLARE_MUTATIONS = 1_000;
const MAX_CLOUDFLARE_MUTATION_ITEMS = 100;
const MAX_CLOUDFLARE_MUTATION_CLAIM = 25;
export const MAX_INVITE_CREDENTIAL_MIGRATION_BATCH = 25;
const MAX_CLOUDFLARE_MUTATION_LEASE_MS = 5 * 60 * 1000;
export const MAX_RECORD_LEASE_MS = 5 * 60 * 1000;
const RECORD_MAINTENANCE_SCOPE = "*";
export const LEGACY_CLEANUP_LEASE_MS = 60 * 1000;
export const LEGACY_CLEANUP_RECHECK_DELAY_MS = 5 * 60 * 1000;
export const LEGACY_CLEANUP_RETRY_DELAY_MS = 60 * 1000;
export const LEGACY_CLEANUP_RECHECKS = 2;
const LEGACY_CLEANUP_SCHEDULER_VERSION = 2;
const UTF8_ENCODER = new TextEncoder();
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const TRASH_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const CLOUDFLARE_COMMENT_PATTERN = /^sub2api ref [a-f0-9]{32}$/;
const CLOUDFLARE_ITEM_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const FORBIDDEN_CREDENTIAL_FIELDS = new Set([
  "accessKey",
  "apiKey",
  "loginPassword",
  "password",
  "passwordHash",
  "secret",
]);
const FORBIDDEN_TRASH_FIELDS = new Set([
  ...FORBIDDEN_CREDENTIAL_FIELDS,
  "accessKeyHmac",
  "apiKeyEncrypted",
  "loginPasswordEncrypted",
  "passwordHashFingerprint",
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class AuthStateUnavailableError extends Error {
  constructor(code = "auth_state_unavailable") {
    super(code);
    this.name = "AuthStateUnavailableError";
    this.code = code;
  }
}

export function isAuthStateBindingConfigured(env) {
  return Boolean(env?.AUTH_STATE && typeof env.AUTH_STATE.getByName === "function");
}

export function requireAuthStateBinding(env) {
  if (!isAuthStateBindingConfigured(env)) {
    throw new AuthStateUnavailableError();
  }
  try {
    const stub = env.AUTH_STATE.getByName(AUTH_STATE_DO_NAME);
    if (!stub || typeof stub.status !== "function") {
      throw new AuthStateUnavailableError();
    }
    return stub;
  } catch (error) {
    if (error instanceof AuthStateUnavailableError) throw error;
    throw new AuthStateUnavailableError();
  }
}

/**
 * Initialize the SQLite-backed object. This function is called only from the
 * Durable Object constructor, before any request is admitted.
 */
export function initializeAuthStateStorage(storage) {
  const sql = requireSql(storage);
  storage.transactionSync(() => {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS auth_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS invites (
        uuid TEXT PRIMARY KEY,
        payload TEXT NOT NULL CHECK (length(CAST(payload AS BLOB)) <= ${MAX_ITEM_BYTES}),
        access_key_hmac TEXT NOT NULL DEFAULT '',
        credential_version INTEGER NOT NULL DEFAULT 0,
        access_credential_version INTEGER NOT NULL DEFAULT 0,
        legacy_uuid_login_until INTEGER
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS trash (
        id TEXT PRIMARY KEY,
        item_type TEXT NOT NULL CHECK (item_type IN ('uuid', 'ip_group')),
        payload TEXT NOT NULL CHECK (length(CAST(payload AS BLOB)) <= ${MAX_ITEM_BYTES})
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        kind TEXT NOT NULL CHECK (kind IN ('admin', 'public')),
        token_hash TEXT NOT NULL,
        uuid TEXT,
        payload TEXT NOT NULL CHECK (length(CAST(payload AS BLOB)) <= ${MAX_SESSION_BYTES}),
        expires_at INTEGER NOT NULL,
        access_credential_version INTEGER NOT NULL DEFAULT 0,
        authentication_method TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (kind, token_hash)
      )
    `);
    sql.exec("CREATE INDEX IF NOT EXISTS idx_auth_sessions_uuid ON sessions(kind, uuid)");
    sql.exec("CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON sessions(expires_at)");
    sql.exec(`
      CREATE TABLE IF NOT EXISTS cloudflare_mutations (
        mutation_id TEXT PRIMARY KEY,
        comment TEXT NOT NULL,
        expected_value_hashes TEXT NOT NULL CHECK (length(CAST(expected_value_hashes AS BLOB)) <= 8192),
        item_ids TEXT NOT NULL CHECK (length(CAST(item_ids AS BLOB)) <= 16384),
        created_at INTEGER NOT NULL,
        not_before INTEGER NOT NULL,
        lease_until INTEGER NOT NULL DEFAULT 0
      )
    `);
    sql.exec("CREATE INDEX IF NOT EXISTS idx_cloudflare_mutations_claim ON cloudflare_mutations(not_before, lease_until, created_at)");
    sql.exec(`
      CREATE TABLE IF NOT EXISTS record_leases (
        uuid TEXT PRIMARY KEY,
        owner_token TEXT NOT NULL,
        lease_until INTEGER NOT NULL
      )
    `);
    sql.exec("CREATE INDEX IF NOT EXISTS idx_record_leases_expiry ON record_leases(lease_until)");
    sql.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_access_key_hmac ON invites(access_key_hmac) WHERE access_key_hmac <> ''");
    sql.exec("CREATE INDEX IF NOT EXISTS idx_invites_admin_order ON invites(COALESCE(json_extract(payload, '$.createdAt'), '') DESC, uuid ASC)");
    sql.exec("CREATE INDEX IF NOT EXISTS idx_trash_admin_order ON trash(COALESCE(json_extract(payload, '$.deletedAt'), '') DESC, id ASC)");
    sql.exec("INSERT INTO auth_meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", String(AUTH_STATE_SCHEMA_VERSION));
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('invites_revision', '0')");
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('trash_revision', '0')");
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('migration_state', 'pending')");
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('legacy_cleanup_state', 'pending')");
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('legacy_cleanup_lease_until', '0')");
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('legacy_cleanup_scheduler_version', '0')");
    sql.exec("INSERT OR IGNORE INTO auth_meta (key, value) VALUES ('legacy_cleanup_rechecks_remaining', '0')");
  });
}

export function authStateStatus(storage, now = Date.now()) {
  requireNow(now);
  const sql = requireSql(storage);
  const migrationState = readMeta(sql, "migration_state");
  const legacyCleanupState = readMeta(sql, "legacy_cleanup_state");
  const legacyCleanupSchedulerVersion = readLegacyCleanupSchedulerVersion(sql);
  const legacyCleanupRechecksRemaining = readLegacyCleanupRechecks(sql);
  const invitesRevision = readRevision(sql, "invites_revision");
  const trashRevision = readRevision(sql, "trash_revision");
  const inviteCount = sql.exec("SELECT COUNT(*) AS count FROM invites").one().count;
  const trashCount = sql.exec("SELECT COUNT(*) AS count FROM trash").one().count;
  const sessionCount = sql.exec("SELECT COUNT(*) AS count FROM sessions WHERE expires_at > ?", now).one().count;
  return {
    schemaVersion: AUTH_STATE_SCHEMA_VERSION,
    migrated: migrationState === "complete",
    legacyCleanupComplete: legacyCleanupState === "complete",
    legacyCleanupVerificationPending: legacyCleanupState === "verifying",
    legacyCleanupSchedulerReady:
      legacyCleanupSchedulerVersion === LEGACY_CLEANUP_SCHEDULER_VERSION,
    legacyCleanupRechecksRemaining,
    invitesRevision,
    trashRevision,
    inviteCount: Number(inviteCount),
    trashCount: Number(trashCount),
    activeSessionCount: Number(sessionCount),
  };
}

export function authStateImportLegacy(storage, snapshot, importedAt = new Date().toISOString(), now = Date.now()) {
  const sql = requireSql(storage);
  const normalized = normalizeLegacySnapshot(snapshot, now);
  return storage.transactionSync(() => {
    if (readMeta(sql, "migration_state") === "complete") {
      return {
        imported: false,
        alreadyComplete: true,
        ...authStateStatus(storage, now),
      };
    }

    sql.exec("DELETE FROM sessions");
    sql.exec("DELETE FROM trash");
    sql.exec("DELETE FROM invites");
    for (const invite of normalized.invites) insertInvite(sql, invite);
    for (const item of normalized.trash) insertTrash(sql, item);
    for (const session of normalized.adminSessions) insertSession(sql, "admin", session);
    for (const session of normalized.publicSessions) {
      const invite = normalized.invites.find((item) => item.uuid === session.payload.uuid);
      if (!invite) continue;
      const payload = reconcileImportedPublicSession(session.payload, invite, now);
      if (payload) insertSession(sql, "public", { ...session, payload });
    }
    setMeta(sql, "invites_revision", normalized.invites.length ? "1" : "0");
    setMeta(sql, "trash_revision", normalized.trash.length ? "1" : "0");
    setMeta(sql, "migration_state", "complete");
    setMeta(sql, "legacy_cleanup_state", "pending");
    setMeta(sql, "legacy_cleanup_scheduler_version", "0");
    setMeta(sql, "legacy_cleanup_rechecks_remaining", "0");
    setMeta(sql, "migrated_at", String(importedAt));
    return {
      imported: true,
      alreadyComplete: false,
      ...authStateStatus(storage, now),
    };
  });
}

export function authStateGetInvites(storage) {
  const sql = requireSql(storage);
  const rows = sql.exec("SELECT payload FROM invites ORDER BY rowid ASC").toArray();
  return {
    revision: readRevision(sql, "invites_revision"),
    items: rows.map((row) => parseStoredInvite(row.payload)),
  };
}

export function authStateGetCredentialMigrationBatch(
  storage,
  limit = MAX_INVITE_CREDENTIAL_MIGRATION_BATCH,
) {
  const normalizedLimit = normalizeCredentialMigrationBatchLimit(limit);
  const sql = requireSql(storage);
  const rows = sql.exec(
    `SELECT uuid, credential_version, access_credential_version,
            substr(COALESCE(json_extract(payload, '$.username'), ''), 1, 100) AS username,
            substr(COALESCE(json_extract(payload, '$.name'), ''), 1, 100) AS name
       FROM invites
      WHERE access_key_hmac = ''
      ORDER BY rowid ASC
      LIMIT ?`,
    normalizedLimit,
  ).toArray();
  return {
    revision: readRevision(sql, "invites_revision"),
    remainingCount: Number(
      sql.exec("SELECT COUNT(*) AS count FROM invites WHERE access_key_hmac = ''").one().count,
    ),
    items: rows.map((row) => ({
      uuid: normalizeUuid(row.uuid),
      username: adminSummaryText(row.username, 100),
      name: adminSummaryText(row.name, 100),
      credentialVersion: normalizeNonNegativeInteger(
        row.credential_version,
        "auth_state_credential_version_invalid",
      ),
      accessCredentialVersion: normalizeNonNegativeInteger(
        row.access_credential_version,
        "auth_state_access_credential_version_invalid",
      ),
    })),
  };
}

export function authStateCommitCredentialMigrationBatch(
  storage,
  expectedRevision,
  updates,
  migratedAt = Date.now(),
) {
  const revision = requireRevision(expectedRevision);
  const normalizedMigratedAt = requireNow(migratedAt);
  const normalizedUpdates = normalizeCredentialMigrationUpdates(updates);
  const sql = requireSql(storage);

  return storage.transactionSync(() => {
    const currentRevision = readRevision(sql, "invites_revision");
    if (currentRevision !== revision) {
      return { ok: false, conflict: true, revision: currentRevision };
    }

    for (const update of normalizedUpdates) {
      const row = sql.exec(
        `SELECT payload, access_key_hmac, access_credential_version
           FROM invites
          WHERE uuid = ?`,
        update.uuid,
      ).toArray()[0];
      if (!row || row.access_key_hmac !== "") {
        fail("auth_state_credential_migration_target_invalid");
      }
      const currentVersion = normalizeNonNegativeInteger(
        row.access_credential_version,
        "auth_state_access_credential_version_invalid",
      );
      if (currentVersion !== update.expectedAccessCredentialVersion) {
        fail("auth_state_credential_migration_target_invalid");
      }
      const invite = parseStoredInvite(row.payload);
      insertInvite(sql, normalizeInvite({
        ...invite,
        credentialVersion: 2,
        accessCredentialVersion: currentVersion + 1,
        accessKeyHmac: update.accessKeyHmac,
        legacyUuidLoginUntil: new Date(
          normalizedMigratedAt + 7 * 24 * 60 * 60 * 1000,
        ).toISOString(),
      }));
    }

    const nextRevision = currentRevision + 1;
    setMeta(sql, "invites_revision", nextRevision);
    return {
      ok: true,
      conflict: false,
      revision: nextRevision,
      migratedCount: normalizedUpdates.length,
      remainingCount: Number(
        sql.exec("SELECT COUNT(*) AS count FROM invites WHERE access_key_hmac = ''").one().count,
      ),
    };
  });
}

export function authStateLegacyCleanupReadiness(storage, now = Date.now()) {
  const normalizedNow = requireNow(now);
  const sql = requireSql(storage);
  if (readMeta(sql, "migration_state") !== "complete") {
    return {
      eligible: false,
      reason: "auth_state_migration_incomplete",
      blockerCount: 0,
      activeDeadlineCount: 0,
      latestDeadline: "",
    };
  }

  const row = sql.exec(
    `SELECT
       SUM(CASE
         WHEN credential_version < 2
           OR access_credential_version < 1
           OR length(access_key_hmac) <> 64
           OR access_key_hmac GLOB '*[^0-9a-f]*'
         THEN 1 ELSE 0 END) AS blocker_count,
       SUM(CASE
         WHEN legacy_uuid_login_until IS NOT NULL
          AND legacy_uuid_login_until > ?
         THEN 1 ELSE 0 END) AS active_deadline_count,
       MAX(legacy_uuid_login_until) AS latest_deadline
     FROM invites`,
    normalizedNow,
  ).one();
  const blockerCount = Number(row.blocker_count || 0);
  const activeDeadlineCount = Number(row.active_deadline_count || 0);
  const latestDeadlineMs = Number(row.latest_deadline);
  const latestDeadline = Number.isFinite(latestDeadlineMs) && latestDeadlineMs > 0
    ? new Date(latestDeadlineMs).toISOString()
    : "";
  const eligible = blockerCount === 0 && activeDeadlineCount === 0;
  return {
    eligible,
    reason: blockerCount > 0
      ? "auth_state_legacy_cleanup_credentials_incomplete"
      : activeDeadlineCount > 0
        ? "auth_state_legacy_cleanup_deadline_active"
        : "",
    blockerCount,
    activeDeadlineCount,
    latestDeadline,
  };
}

export function authStateGetAdminPage(
  storage,
  inviteOffset = 0,
  inviteLimit = 25,
  trashOffset = 0,
  trashLimit = 25,
) {
  const normalizedInviteOffset = normalizePageOffset(
    inviteOffset,
    MAX_INVITES,
    "auth_state_invite_page_invalid",
  );
  const normalizedInviteLimit = normalizePageLimit(
    inviteLimit,
    "auth_state_invite_page_invalid",
  );
  const normalizedTrashOffset = normalizePageOffset(
    trashOffset,
    MAX_TRASH_ITEMS,
    "auth_state_trash_page_invalid",
  );
  const normalizedTrashLimit = normalizePageLimit(
    trashLimit,
    "auth_state_trash_page_invalid",
  );
  const sql = requireSql(storage);
  const inviteRows = sql.exec(
    "SELECT uuid, "
      + "substr(COALESCE(json_extract(payload, '$.username'), ''), 1, 100) AS username, "
      + "substr(COALESCE(json_extract(payload, '$.name'), ''), 1, 100) AS name, "
      + "substr(COALESCE(json_extract(payload, '$.email'), ''), 1, 160) AS email, "
      + "substr(COALESCE(json_extract(payload, '$.remark'), ''), 1, 240) AS remark, "
      + "substr(COALESCE(json_extract(payload, '$.createdAt'), ''), 1, 64) AS created_at, "
      + "CASE WHEN access_key_hmac <> '' THEN 1 ELSE 0 END AS has_access_key, "
      + "credential_version, access_credential_version, legacy_uuid_login_until, "
      + "CASE WHEN json_type(payload, '$.apiConfigs') = 'array' "
      + "THEN min(json_array_length(payload, '$.apiConfigs'), 10000) ELSE 0 END AS api_config_count "
      + "FROM invites "
      + "ORDER BY COALESCE(json_extract(payload, '$.createdAt'), '') DESC, uuid ASC "
      + "LIMIT ? OFFSET ?",
    normalizedInviteLimit,
    normalizedInviteOffset,
  ).toArray();
  const trashRows = sql.exec(
    "SELECT id, item_type, "
      + "substr(COALESCE(json_extract(payload, '$.deletedAt'), ''), 1, 64) AS deleted_at, "
      + "substr(COALESCE(json_extract(payload, '$.invite.uuid'), ''), 1, 36) AS invite_uuid, "
      + "substr(COALESCE(json_extract(payload, '$.invite.username'), ''), 1, 100) AS invite_username, "
      + "substr(COALESCE(json_extract(payload, '$.invite.name'), ''), 1, 100) AS invite_name, "
      + "substr(COALESCE(json_extract(payload, '$.invite.email'), ''), 1, 160) AS invite_email, "
      + "CASE WHEN json_type(payload, '$.records') = 'array' "
      + "THEN min(json_array_length(payload, '$.records'), 20000) ELSE 0 END AS record_count, "
      + "substr(COALESCE(json_extract(payload, '$.uuid'), ''), 1, 36) AS group_uuid, "
      + "substr(COALESCE(json_extract(payload, '$.group.country'), ''), 1, 80) AS country, "
      + "substr(COALESCE(json_extract(payload, '$.group.region'), ''), 1, 120) AS region, "
      + "substr(COALESCE(json_extract(payload, '$.group.city'), ''), 1, 120) AS city, "
      + "CASE WHEN json_type(payload, '$.group.ips') = 'array' "
      + "THEN min(json_array_length(payload, '$.group.ips'), 20000) ELSE 0 END AS ip_count "
      + "FROM trash "
      + "ORDER BY COALESCE(json_extract(payload, '$.deletedAt'), '') DESC, id ASC "
      + "LIMIT ? OFFSET ?",
    normalizedTrashLimit,
    normalizedTrashOffset,
  ).toArray();
  return {
    inviteRevision: readRevision(sql, "invites_revision"),
    trashRevision: readRevision(sql, "trash_revision"),
    inviteCount: Number(sql.exec("SELECT COUNT(*) AS count FROM invites").one().count),
    trashCount: Number(sql.exec("SELECT COUNT(*) AS count FROM trash").one().count),
    unmigratedInviteCount: Number(
      sql.exec("SELECT COUNT(*) AS count FROM invites WHERE access_key_hmac = ''").one().count,
    ),
    invites: inviteRows.map(adminInviteSummaryFromRow),
    trash: trashRows.map(adminTrashSummaryFromRow),
  };
}

export function authStateGetInvite(storage, uuid) {
  const normalizedUuid = normalizeUuid(uuid);
  const row = requireSql(storage)
    .exec("SELECT payload FROM invites WHERE uuid = ?", normalizedUuid)
    .toArray()[0];
  return row ? parseStoredInvite(row.payload) : null;
}

export function authStateFindInviteByAccessKeyHmac(storage, hmac) {
  const normalizedHmac = normalizeHash(hmac, "auth_state_access_key_hmac_invalid");
  const row = requireSql(storage)
    .exec("SELECT payload FROM invites WHERE access_key_hmac = ?", normalizedHmac)
    .toArray()[0];
  return row ? parseStoredInvite(row.payload) : null;
}

export function authStateReplaceInvites(storage, expectedRevision, items) {
  const normalizedRevision = requireRevision(expectedRevision);
  const normalizedItems = normalizeInviteCollection(items);
  assertUniqueInviteFields(normalizedItems);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const currentRevision = readRevision(sql, "invites_revision");
    if (currentRevision !== normalizedRevision) {
      return { ok: false, conflict: true, revision: currentRevision };
    }
    const previous = sql.exec("SELECT uuid, access_key_hmac, credential_version, access_credential_version, legacy_uuid_login_until FROM invites").toArray();
    const nextByUuid = new Map(normalizedItems.map((item) => [item.uuid, item]));
    for (const row of previous) {
      const next = nextByUuid.get(row.uuid);
      if (!next) {
        sql.exec("DELETE FROM sessions WHERE kind = 'public' AND uuid = ?", row.uuid);
      } else {
        reconcilePublicSessionsForInvite(sql, row, next);
      }
    }
    sql.exec("DELETE FROM invites");
    for (const invite of normalizedItems) insertInvite(sql, invite);
    const revision = normalizedRevision + 1;
    setMeta(sql, "invites_revision", String(revision));
    return { ok: true, conflict: false, revision };
  });
}

export function authStateUpsertInvite(storage, expectedRevision, invite) {
  const normalizedRevision = requireRevision(expectedRevision);
  const normalizedInvite = normalizeInvite(invite);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const currentRevision = readRevision(sql, "invites_revision");
    if (currentRevision !== normalizedRevision) {
      return { ok: false, conflict: true, revision: currentRevision };
    }
    const previous = sql.exec("SELECT uuid, access_key_hmac, credential_version, access_credential_version, legacy_uuid_login_until FROM invites WHERE uuid = ?", normalizedInvite.uuid).toArray()[0];
    const duplicate = normalizedInvite.accessKeyHmac
      ? sql.exec("SELECT uuid FROM invites WHERE access_key_hmac = ? AND uuid <> ?", normalizedInvite.accessKeyHmac, normalizedInvite.uuid).toArray()[0]
      : null;
    if (duplicate) fail("auth_state_access_key_hmac_duplicate");
    if (previous) reconcilePublicSessionsForInvite(sql, previous, normalizedInvite);
    insertInvite(sql, normalizedInvite);
    const revision = normalizedRevision + 1;
    setMeta(sql, "invites_revision", String(revision));
    return { ok: true, conflict: false, revision };
  });
}

export function authStateRemoveInvite(storage, expectedInviteRevision, expectedTrashRevision, uuid, trashItem) {
  const inviteRevision = requireRevision(expectedInviteRevision);
  const trashRevision = requireRevision(expectedTrashRevision);
  const normalizedUuid = normalizeUuid(uuid);
  const normalizedTrash = normalizeTrashItem(trashItem);
  if (normalizedTrash.type !== "uuid" || normalizedTrash.invite?.uuid !== normalizedUuid) {
    fail("auth_state_trash_invite_mismatch");
  }
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const currentInviteRevision = readRevision(sql, "invites_revision");
    const currentTrashRevision = readRevision(sql, "trash_revision");
    if (currentInviteRevision !== inviteRevision || currentTrashRevision !== trashRevision) {
      return {
        ok: false,
        conflict: true,
        inviteRevision: currentInviteRevision,
        trashRevision: currentTrashRevision,
      };
    }
    const existing = sql.exec("SELECT uuid FROM invites WHERE uuid = ?", normalizedUuid).toArray()[0];
    if (!existing) return { ok: true, removed: false, inviteRevision, trashRevision };
    if (sql.exec("SELECT id FROM trash WHERE id = ?", normalizedTrash.id).toArray()[0]) {
      fail("auth_state_trash_id_duplicate");
    }
    insertTrash(sql, normalizedTrash);
    sql.exec("DELETE FROM invites WHERE uuid = ?", normalizedUuid);
    sql.exec("DELETE FROM sessions WHERE kind = 'public' AND uuid = ?", normalizedUuid);
    const nextInviteRevision = inviteRevision + 1;
    const nextTrashRevision = trashRevision + 1;
    setMeta(sql, "invites_revision", String(nextInviteRevision));
    setMeta(sql, "trash_revision", String(nextTrashRevision));
    return {
      ok: true,
      removed: true,
      inviteRevision: nextInviteRevision,
      trashRevision: nextTrashRevision,
    };
  });
}

export function authStateGetTrash(storage) {
  const rows = requireSql(storage).exec("SELECT payload FROM trash ORDER BY rowid DESC").toArray();
  return {
    revision: readRevision(requireSql(storage), "trash_revision"),
    items: rows.map((row) => parseStoredTrash(row.payload)),
  };
}

export function authStateReplaceTrash(storage, expectedRevision, items) {
  const normalizedRevision = requireRevision(expectedRevision);
  const normalizedItems = normalizeTrashCollection(items);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const currentRevision = readRevision(sql, "trash_revision");
    if (currentRevision !== normalizedRevision) {
      return { ok: false, conflict: true, revision: currentRevision };
    }
    sql.exec("DELETE FROM trash");
    for (const item of normalizedItems) insertTrash(sql, item);
    const revision = normalizedRevision + 1;
    setMeta(sql, "trash_revision", String(revision));
    return { ok: true, conflict: false, revision };
  });
}

export function authStateRestoreInvite(storage, expectedInviteRevision, expectedTrashRevision, trashId, invite) {
  const inviteRevision = requireRevision(expectedInviteRevision);
  const trashRevision = requireRevision(expectedTrashRevision);
  const normalizedInvite = normalizeInvite(invite);
  const normalizedTrashId = normalizeTrashId(trashId);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const currentInviteRevision = readRevision(sql, "invites_revision");
    const currentTrashRevision = readRevision(sql, "trash_revision");
    if (currentInviteRevision !== inviteRevision || currentTrashRevision !== trashRevision) {
      return {
        ok: false,
        conflict: true,
        inviteRevision: currentInviteRevision,
        trashRevision: currentTrashRevision,
      };
    }
    const trash = sql.exec("SELECT item_type, payload FROM trash WHERE id = ?", normalizedTrashId).toArray()[0];
    if (!trash || trash.item_type !== "uuid") return { ok: true, restored: false, inviteRevision, trashRevision };
    const storedTrash = parseStoredTrash(trash.payload);
    if (storedTrash.invite?.uuid !== normalizedInvite.uuid) fail("auth_state_trash_invite_mismatch");
    if (sql.exec("SELECT uuid FROM invites WHERE uuid = ?", normalizedInvite.uuid).toArray()[0]) {
      fail("auth_state_invite_exists");
    }
    insertInvite(sql, normalizedInvite);
    sql.exec("DELETE FROM trash WHERE id = ?", normalizedTrashId);
    const nextInviteRevision = inviteRevision + 1;
    const nextTrashRevision = trashRevision + 1;
    setMeta(sql, "invites_revision", String(nextInviteRevision));
    setMeta(sql, "trash_revision", String(nextTrashRevision));
    return {
      ok: true,
      restored: true,
      inviteRevision: nextInviteRevision,
      trashRevision: nextTrashRevision,
    };
  });
}

export function authStatePurgeTrash(storage, expectedRevision, trashId) {
  const revision = requireRevision(expectedRevision);
  const normalizedId = normalizeTrashId(trashId);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const currentRevision = readRevision(sql, "trash_revision");
    if (currentRevision !== revision) return { ok: false, conflict: true, revision: currentRevision };
    const existing = sql.exec("SELECT id FROM trash WHERE id = ?", normalizedId).toArray()[0];
    if (!existing) return { ok: true, purged: false, revision };
    sql.exec("DELETE FROM trash WHERE id = ?", normalizedId);
    const nextRevision = revision + 1;
    setMeta(sql, "trash_revision", String(nextRevision));
    return { ok: true, purged: true, revision: nextRevision };
  });
}

export function authStatePutAdminSession(storage, tokenHash, payload, now = Date.now()) {
  const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
  const normalizedPayload = normalizeAdminSession(payload, now);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    insertSession(sql, "admin", { hash: normalizedHash, payload: normalizedPayload });
    return { ok: true, expiresAt: normalizedPayload.expiresAt };
  });
}

export function authStateGetAdminSession(storage, tokenHash, now = Date.now()) {
  const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
  return getSession(storage, "admin", normalizedHash, now);
}

export function authStatePutPublicSession(storage, tokenHash, payload, now = Date.now()) {
  const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
  const sql = requireSql(storage);
  const normalizedPayload = normalizePublicSession(payload, now);
  const invite = authStateGetInvite(storage, normalizedPayload.uuid);
  if (!invite) fail("auth_state_invite_not_found");
  assertPublicSessionAgainstInvite(normalizedPayload, invite, now);
  return storage.transactionSync(() => {
    insertSession(sql, "public", {
      hash: normalizedHash,
      payload: normalizedPayload,
    });
    return { ok: true, expiresAt: normalizedPayload.expiresAt };
  });
}

export function authStateGetPublicSession(storage, tokenHash, now = Date.now()) {
  const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
  const sql = requireSql(storage);
  const row = sql.exec("SELECT payload FROM sessions WHERE kind = 'public' AND token_hash = ?", normalizedHash).toArray()[0];
  if (!row) return null;
  const payload = parseStoredPublicSession(row.payload);
  const invite = authStateGetInvite(storage, payload.uuid);
  if (!invite || payload.expiresAt <= now) {
    sql.exec("DELETE FROM sessions WHERE kind = 'public' AND token_hash = ?", normalizedHash);
    return null;
  }
  try {
    assertPublicSessionAgainstInvite(payload, invite, now);
  } catch {
    sql.exec("DELETE FROM sessions WHERE kind = 'public' AND token_hash = ?", normalizedHash);
    return null;
  }
  return { session: payload, invite };
}

export function authStateDeleteSession(storage, kind, tokenHash) {
  const normalizedKind = normalizeSessionKind(kind);
  const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
  const sql = requireSql(storage);
  const before = sql.exec("SELECT token_hash FROM sessions WHERE kind = ? AND token_hash = ?", normalizedKind, normalizedHash).toArray()[0];
  sql.exec("DELETE FROM sessions WHERE kind = ? AND token_hash = ?", normalizedKind, normalizedHash);
  return { ok: true, deleted: Boolean(before) };
}

export function authStatePurgeExpiredSessions(storage, now = Date.now()) {
  requireNow(now);
  const sql = requireSql(storage);
  const rows = sql.exec("SELECT token_hash FROM sessions WHERE expires_at <= ?", now).toArray();
  sql.exec("DELETE FROM sessions WHERE expires_at <= ?", now);
  return { ok: true, deleted: rows.length };
}

export function authStateMarkLegacyCleanupComplete(
  _storage,
  _completedAt = new Date().toISOString(),
) {
  fail("auth_state_legacy_cleanup_verification_required");
}

export function authStateClaimLegacyCleanup(
  storage,
  now = Date.now(),
  leaseMs = LEGACY_CLEANUP_LEASE_MS,
) {
  const normalizedNow = requireNow(now);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 5 * 60 * 1000) {
    fail("auth_state_legacy_cleanup_lease_invalid");
  }
  const sql = requireSql(storage);
  if (readMeta(sql, "migration_state") !== "complete") {
    fail("auth_state_migration_incomplete");
  }
  return storage.transactionSync(() => {
    const currentLease = requireNow(readMeta(sql, "legacy_cleanup_lease_until"));
    if (currentLease > normalizedNow) {
      return { claimed: false, leaseUntil: currentLease };
    }
    const leaseUntil = normalizedNow + leaseMs;
    setMeta(sql, "legacy_cleanup_lease_until", leaseUntil);
    return { claimed: true, leaseUntil };
  });
}

export function authStateReleaseLegacyCleanup(storage) {
  const sql = requireSql(storage);
  setMeta(sql, "legacy_cleanup_lease_until", "0");
  return { ok: true };
}

export function authStateArmLegacyCleanupRechecks(storage) {
  const sql = requireSql(storage);
  if (readMeta(sql, "legacy_cleanup_state") !== "complete") {
    fail("auth_state_legacy_cleanup_incomplete");
  }
  return storage.transactionSync(() => {
    const currentVersion = readLegacyCleanupSchedulerVersion(sql);
    const currentRemaining = readLegacyCleanupRechecks(sql);
    if (currentVersion === LEGACY_CLEANUP_SCHEDULER_VERSION) {
      return { armed: false, remaining: currentRemaining };
    }
    setMeta(sql, "legacy_cleanup_state", "verifying");
    setMeta(sql, "legacy_cleanup_completed_at", "");
    setMeta(sql, "legacy_cleanup_scheduler_version", LEGACY_CLEANUP_SCHEDULER_VERSION);
    setMeta(sql, "legacy_cleanup_rechecks_remaining", LEGACY_CLEANUP_RECHECKS);
    return { armed: true, remaining: LEGACY_CLEANUP_RECHECKS };
  });
}

export function authStateBeginLegacyCleanupVerification(storage) {
  const sql = requireSql(storage);
  if (readMeta(sql, "migration_state") !== "complete") {
    fail("auth_state_migration_incomplete");
  }
  return storage.transactionSync(() => {
    setMeta(sql, "legacy_cleanup_state", "verifying");
    setMeta(sql, "legacy_cleanup_completed_at", "");
    setMeta(sql, "legacy_cleanup_lease_until", "0");
    setMeta(sql, "legacy_cleanup_scheduler_version", LEGACY_CLEANUP_SCHEDULER_VERSION);
    setMeta(sql, "legacy_cleanup_rechecks_remaining", LEGACY_CLEANUP_RECHECKS);
    return { armed: true, remaining: LEGACY_CLEANUP_RECHECKS };
  });
}

export function authStateConsumeLegacyCleanupRecheck(
  storage,
  completedAt = new Date().toISOString(),
) {
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    if (
      readMeta(sql, "legacy_cleanup_state") !== "verifying"
      || readLegacyCleanupSchedulerVersion(sql) !== LEGACY_CLEANUP_SCHEDULER_VERSION
    ) {
      fail("auth_state_legacy_cleanup_verification_inactive");
    }
    const current = readLegacyCleanupRechecks(sql);
    if (current < 1) fail("auth_state_legacy_cleanup_verification_inactive");
    const remaining = Math.max(0, current - 1);
    setMeta(sql, "legacy_cleanup_rechecks_remaining", remaining);
    if (remaining === 0) {
      setMeta(sql, "legacy_cleanup_state", "complete");
      setMeta(sql, "legacy_cleanup_completed_at", String(completedAt));
    }
    return { consumed: true, remaining, complete: remaining === 0 };
  });
}

export function authStateRegisterCloudflareMutation(storage, marker) {
  const normalized = normalizeCloudflareMutation(marker);
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const existing = sql.exec(
      "SELECT mutation_id, comment, expected_value_hashes, item_ids, created_at, not_before, lease_until FROM cloudflare_mutations WHERE mutation_id = ?",
      normalized.mutationId,
    ).toArray()[0];
    if (existing) {
      const parsed = cloudflareMutationFromRow(existing);
      if (JSON.stringify(parsed) !== JSON.stringify(normalized)) {
        fail("auth_state_cloudflare_mutation_conflict");
      }
      return { ok: true, created: false };
    }
    const count = Number(sql.exec("SELECT COUNT(*) AS count FROM cloudflare_mutations").one().count);
    if (count >= MAX_CLOUDFLARE_MUTATIONS) fail("auth_state_cloudflare_mutation_limit");
    sql.exec(
      `INSERT INTO cloudflare_mutations
       (mutation_id, comment, expected_value_hashes, item_ids, created_at, not_before, lease_until)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      normalized.mutationId,
      normalized.comment,
      JSON.stringify(normalized.expectedValueHashes),
      JSON.stringify(normalized.itemIds),
      normalized.createdAt,
      normalized.notBefore,
      normalized.leaseUntil,
    );
    return { ok: true, created: true };
  });
}

export function authStateUpdateCloudflareMutationItems(storage, mutationId, itemIds) {
  const normalizedId = normalizeHash(mutationId, "auth_state_cloudflare_mutation_id_invalid");
  const normalizedItemIds = normalizeCloudflareItemIds(itemIds);
  const sql = requireSql(storage);
  const existing = sql.exec(
    "SELECT mutation_id FROM cloudflare_mutations WHERE mutation_id = ?",
    normalizedId,
  ).toArray()[0];
  if (!existing) return { ok: true, updated: false };
  sql.exec(
    "UPDATE cloudflare_mutations SET item_ids = ? WHERE mutation_id = ?",
    JSON.stringify(normalizedItemIds),
    normalizedId,
  );
  return { ok: true, updated: true };
}

export function authStateGetCloudflareMutation(storage, mutationId) {
  const normalizedId = normalizeHash(mutationId, "auth_state_cloudflare_mutation_id_invalid");
  const row = requireSql(storage).exec(
    "SELECT mutation_id, comment, expected_value_hashes, item_ids, created_at, not_before, lease_until FROM cloudflare_mutations WHERE mutation_id = ?",
    normalizedId,
  ).toArray()[0];
  return row ? cloudflareMutationFromRow(row) : null;
}

export function authStateClaimCloudflareMutations(
  storage,
  now = Date.now(),
  limit = MAX_CLOUDFLARE_MUTATION_CLAIM,
  leaseMs = 60_000,
) {
  const normalizedNow = requireNow(now);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_CLOUDFLARE_MUTATION_CLAIM) {
    fail("auth_state_cloudflare_mutation_claim_invalid");
  }
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > MAX_CLOUDFLARE_MUTATION_LEASE_MS) {
    fail("auth_state_cloudflare_mutation_lease_invalid");
  }
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    const rows = sql.exec(
      `SELECT mutation_id, comment, expected_value_hashes, item_ids, created_at, not_before, lease_until
       FROM cloudflare_mutations
       WHERE not_before <= ? AND lease_until <= ?
       ORDER BY created_at ASC, mutation_id ASC
       LIMIT ?`,
      normalizedNow,
      normalizedNow,
      limit,
    ).toArray();
    const leaseUntil = normalizedNow + leaseMs;
    for (const row of rows) {
      sql.exec(
        "UPDATE cloudflare_mutations SET lease_until = ? WHERE mutation_id = ? AND lease_until <= ?",
        leaseUntil,
        row.mutation_id,
        normalizedNow,
      );
      row.lease_until = leaseUntil;
    }
    return rows.map(cloudflareMutationFromRow);
  });
}

export function authStateReleaseCloudflareMutation(storage, mutationId, retryAt) {
  const normalizedId = normalizeHash(mutationId, "auth_state_cloudflare_mutation_id_invalid");
  const normalizedRetryAt = requireNow(retryAt);
  const sql = requireSql(storage);
  const existing = sql.exec("SELECT mutation_id FROM cloudflare_mutations WHERE mutation_id = ?", normalizedId).toArray()[0];
  if (!existing) return { ok: true, released: false };
  sql.exec(
    "UPDATE cloudflare_mutations SET not_before = ?, lease_until = 0 WHERE mutation_id = ?",
    normalizedRetryAt,
    normalizedId,
  );
  return { ok: true, released: true };
}

export function authStateResolveCloudflareMutation(storage, mutationId) {
  const normalizedId = normalizeHash(mutationId, "auth_state_cloudflare_mutation_id_invalid");
  const sql = requireSql(storage);
  const existing = sql.exec("SELECT mutation_id FROM cloudflare_mutations WHERE mutation_id = ?", normalizedId).toArray()[0];
  sql.exec("DELETE FROM cloudflare_mutations WHERE mutation_id = ?", normalizedId);
  return { ok: true, resolved: Boolean(existing) };
}

export function authStateListCloudflareMutationComments(storage) {
  const rows = requireSql(storage).exec(
    "SELECT comment FROM cloudflare_mutations ORDER BY created_at ASC, mutation_id ASC LIMIT ?",
    MAX_CLOUDFLARE_MUTATIONS + 1,
  ).toArray();
  if (rows.length > MAX_CLOUDFLARE_MUTATIONS) fail("auth_state_cloudflare_mutation_limit");
  return rows.map((row) => String(row.comment));
}

export function authStateClaimRecordLease(
  storage,
  uuid,
  ownerToken,
  now = Date.now(),
  leaseMs = 60_000,
) {
  const normalizedUuid = normalizeUuid(uuid);
  const normalizedOwner = normalizeHash(ownerToken, "auth_state_record_lease_owner_invalid");
  const normalizedNow = requireNow(now);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > MAX_RECORD_LEASE_MS) {
    fail("auth_state_record_lease_duration_invalid");
  }
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    sql.exec("DELETE FROM record_leases WHERE lease_until <= ?", normalizedNow);
    const maintenance = sql.exec(
      "SELECT owner_token, lease_until FROM record_leases WHERE uuid = ?",
      RECORD_MAINTENANCE_SCOPE,
    ).toArray()[0];
    if (maintenance && maintenance.owner_token !== normalizedOwner) {
      return { claimed: false, leaseUntil: Number(maintenance.lease_until) };
    }
    const existing = sql.exec(
      "SELECT owner_token, lease_until FROM record_leases WHERE uuid = ?",
      normalizedUuid,
    ).toArray()[0];
    const existingLeaseUntil = Number(existing?.lease_until || 0);
    if (existing && existingLeaseUntil > normalizedNow && existing.owner_token !== normalizedOwner) {
      return { claimed: false, leaseUntil: existingLeaseUntil };
    }

    const leaseUntil = normalizedNow + leaseMs;
    if (!Number.isSafeInteger(leaseUntil)) fail("auth_state_record_lease_duration_invalid");
    sql.exec(
      `INSERT INTO record_leases (uuid, owner_token, lease_until)
       VALUES (?, ?, ?)
       ON CONFLICT(uuid) DO UPDATE SET
         owner_token = excluded.owner_token,
         lease_until = excluded.lease_until`,
      normalizedUuid,
      normalizedOwner,
      leaseUntil,
    );
    return { claimed: true, leaseUntil };
  });
}

export function authStateReleaseRecordLease(storage, uuid, ownerToken) {
  const normalizedUuid = normalizeUuid(uuid);
  const normalizedOwner = normalizeHash(ownerToken, "auth_state_record_lease_owner_invalid");
  const sql = requireSql(storage);
  const existing = sql.exec(
    "SELECT uuid FROM record_leases WHERE uuid = ? AND owner_token = ?",
    normalizedUuid,
    normalizedOwner,
  ).toArray()[0];
  if (existing) {
    sql.exec(
      "DELETE FROM record_leases WHERE uuid = ? AND owner_token = ?",
      normalizedUuid,
      normalizedOwner,
    );
  }
  return { released: Boolean(existing) };
}

export function authStateClaimRecordMaintenanceLease(
  storage,
  ownerToken,
  now = Date.now(),
  leaseMs = 60_000,
) {
  const normalizedOwner = normalizeHash(ownerToken, "auth_state_record_lease_owner_invalid");
  const normalizedNow = requireNow(now);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > MAX_RECORD_LEASE_MS) {
    fail("auth_state_record_lease_duration_invalid");
  }
  const sql = requireSql(storage);
  return storage.transactionSync(() => {
    sql.exec("DELETE FROM record_leases WHERE lease_until <= ?", normalizedNow);
    const blocking = sql.exec(
      `SELECT MAX(lease_until) AS lease_until
       FROM record_leases
       WHERE owner_token <> ?`,
      normalizedOwner,
    ).one();
    const blockingLeaseUntil = Number(blocking?.lease_until || 0);
    if (blockingLeaseUntil > normalizedNow) {
      return { claimed: false, leaseUntil: blockingLeaseUntil };
    }

    const leaseUntil = normalizedNow + leaseMs;
    if (!Number.isSafeInteger(leaseUntil)) fail("auth_state_record_lease_duration_invalid");
    sql.exec(
      `INSERT INTO record_leases (uuid, owner_token, lease_until)
       VALUES (?, ?, ?)
       ON CONFLICT(uuid) DO UPDATE SET
         owner_token = excluded.owner_token,
         lease_until = excluded.lease_until`,
      RECORD_MAINTENANCE_SCOPE,
      normalizedOwner,
      leaseUntil,
    );
    return { claimed: true, leaseUntil };
  });
}

export function authStateReleaseRecordMaintenanceLease(storage, ownerToken) {
  const normalizedOwner = normalizeHash(ownerToken, "auth_state_record_lease_owner_invalid");
  const sql = requireSql(storage);
  const existing = sql.exec(
    "SELECT uuid FROM record_leases WHERE uuid = ? AND owner_token = ?",
    RECORD_MAINTENANCE_SCOPE,
    normalizedOwner,
  ).toArray()[0];
  if (existing) {
    sql.exec(
      "DELETE FROM record_leases WHERE uuid = ? AND owner_token = ?",
      RECORD_MAINTENANCE_SCOPE,
      normalizedOwner,
    );
  }
  return { released: Boolean(existing) };
}

function getSession(storage, kind, hash, now) {
  requireNow(now);
  const sql = requireSql(storage);
  const row = sql.exec("SELECT payload, expires_at FROM sessions WHERE kind = ? AND token_hash = ?", kind, hash).toArray()[0];
  if (!row) return null;
  if (Number(row.expires_at) <= now) {
    sql.exec("DELETE FROM sessions WHERE kind = ? AND token_hash = ?", kind, hash);
    return null;
  }
  return kind === "admin" ? parseStoredAdminSession(row.payload, now) : parseStoredPublicSession(row.payload);
}

function insertInvite(sql, invite) {
  sql.exec(
    `INSERT INTO invites (uuid, payload, access_key_hmac, credential_version, access_credential_version, legacy_uuid_login_until)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(uuid) DO UPDATE SET
       payload = excluded.payload,
       access_key_hmac = excluded.access_key_hmac,
       credential_version = excluded.credential_version,
       access_credential_version = excluded.access_credential_version,
       legacy_uuid_login_until = excluded.legacy_uuid_login_until`,
    invite.uuid,
    stringifyBounded(invite, MAX_ITEM_BYTES),
    invite.accessKeyHmac,
    invite.credentialVersion,
    invite.accessCredentialVersion,
    invite.legacyUuidLoginUntil ? Date.parse(invite.legacyUuidLoginUntil) : null,
  );
}

function insertTrash(sql, item) {
  sql.exec(
    "INSERT INTO trash (id, item_type, payload) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET item_type = excluded.item_type, payload = excluded.payload",
    item.id,
    item.type,
    stringifyBounded(item, MAX_ITEM_BYTES),
  );
}

function insertSession(sql, kind, session) {
  const payload = kind === "admin"
    ? normalizeAdminSession(session.payload, session.payload.expiresAt - 1)
    : normalizePublicSession(session.payload, session.payload.expiresAt - 1);
  const uuid = kind === "public" ? payload.uuid : null;
  const accessVersion = kind === "public" ? payload.accessCredentialVersion : 0;
  const method = kind === "public" ? payload.authenticationMethod : "";
  sql.exec(
    `INSERT INTO sessions (kind, token_hash, uuid, payload, expires_at, access_credential_version, authentication_method)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(kind, token_hash) DO UPDATE SET
       uuid = excluded.uuid,
       payload = excluded.payload,
       expires_at = excluded.expires_at,
       access_credential_version = excluded.access_credential_version,
       authentication_method = excluded.authentication_method`,
    kind,
    session.hash,
    uuid,
    stringifyBounded(payload, MAX_SESSION_BYTES),
    payload.expiresAt,
    accessVersion,
    method,
  );
}

function normalizeLegacySnapshot(snapshot, now) {
  if (!isPlainObject(snapshot)) fail("auth_state_legacy_snapshot_invalid");
  const invites = normalizeInviteCollection(snapshot.invites || []);
  assertUniqueInviteFields(invites);
  const trash = normalizeTrashCollection(snapshot.trash || []);
  const adminSessions = normalizeSessionCollection(snapshot.adminSessions || [], "admin", now);
  const publicSessions = normalizeSessionCollection(snapshot.publicSessions || [], "public", now);
  if (adminSessions.length + publicSessions.length > MAX_SESSION_IMPORTS) {
    fail("auth_state_legacy_session_limit");
  }
  return { invites, trash, adminSessions, publicSessions };
}

function normalizeInviteCollection(items) {
  if (!Array.isArray(items) || items.length > MAX_INVITES) fail("auth_state_invites_invalid");
  return items.map(normalizeInvite);
}

function normalizeInvite(value) {
  const invite = cloneBounded(value, MAX_ITEM_BYTES, "auth_state_invite_invalid");
  if (!isPlainObject(invite)) fail("auth_state_invite_invalid");
  rejectCredentialFields(invite);
  if (!hasInviteStorageSchema(invite)) fail("auth_state_invite_schema_invalid");
  invite.uuid = normalizeUuid(invite.uuid);
  invite.accessKeyHmac = invite.accessKeyHmac
    ? normalizeHash(invite.accessKeyHmac, "auth_state_access_key_hmac_invalid")
    : "";
  invite.credentialVersion = normalizeNonNegativeInteger(invite.credentialVersion, "auth_state_credential_version_invalid");
  invite.accessCredentialVersion = normalizeNonNegativeInteger(invite.accessCredentialVersion, "auth_state_access_credential_version_invalid");
  if (invite.legacyUuidLoginUntil) {
    const deadline = Date.parse(String(invite.legacyUuidLoginUntil));
    if (!Number.isFinite(deadline)) fail("auth_state_legacy_deadline_invalid");
    invite.legacyUuidLoginUntil = new Date(deadline).toISOString();
  } else {
    invite.legacyUuidLoginUntil = "";
  }
  return invite;
}

function normalizeTrashCollection(items) {
  if (!Array.isArray(items) || items.length > MAX_TRASH_ITEMS) fail("auth_state_trash_invalid");
  return items.map(normalizeTrashItem);
}

function normalizeTrashItem(value) {
  const source = cloneBounded(value, MAX_ITEM_BYTES, "auth_state_trash_item_invalid");
  if (!isPlainObject(source)) fail("auth_state_trash_item_invalid");
  rejectTrashCredentialFields(source);
  const item = sanitizeTrashForAuthState(source);
  item.id = normalizeTrashId(item.id);
  if (item.type !== "uuid" && item.type !== "ip_group") fail("auth_state_trash_type_invalid");
  if (item.type === "uuid") {
    if (!isPlainObject(item.invite)) fail("auth_state_trash_invite_invalid");
    item.invite.uuid = normalizeUuid(item.invite.uuid);
    if (Array.isArray(item.records) && item.records.length > MAX_TRASH_ITEMS) fail("auth_state_trash_records_invalid");
  } else {
    item.uuid = normalizeUuid(item.uuid);
    if (!isPlainObject(item.group)) fail("auth_state_trash_group_invalid");
  }
  return item;
}

function normalizeSessionCollection(items, kind, now) {
  if (!Array.isArray(items)) fail("auth_state_sessions_invalid");
  const normalized = [];
  const hashes = new Set();
  for (const entry of items) {
    try {
      if (!isPlainObject(entry)) continue;
      const hash = normalizeHash(entry.hash, "auth_state_session_hash_invalid");
      if (hashes.has(hash)) continue;
      const payload = kind === "admin"
        ? normalizeAdminSession(entry.payload, now)
        : normalizeImportedPublicSession(entry.payload, now);
      hashes.add(hash);
      normalized.push({ hash, payload });
    } catch {
      // Invalid legacy sessions are forced out instead of blocking migration.
    }
  }
  return normalized;
}

function normalizeAdminSession(value, now) {
  const payload = cloneBounded(value, MAX_SESSION_BYTES, "auth_state_admin_session_invalid");
  if (!isPlainObject(payload) || typeof payload.csrf !== "string" || !payload.csrf || !Number.isSafeInteger(Number(payload.expiresAt))) {
    fail("auth_state_admin_session_invalid");
  }
  payload.expiresAt = Number(payload.expiresAt);
  requireFutureExpiry(payload.expiresAt, now);
  const normalized = { csrf: payload.csrf, expiresAt: payload.expiresAt };
  if (Object.hasOwn(payload, "totpBinding")) {
    if (typeof payload.totpBinding !== "string" || !/^[a-f0-9]{64}$/.test(payload.totpBinding)) {
      fail("auth_state_admin_session_invalid");
    }
    normalized.totpBinding = payload.totpBinding;
  }
  if (Object.hasOwn(payload, "loginPhase")) {
    if (payload.loginPhase !== "totp" || !normalized.totpBinding) {
      fail("auth_state_admin_session_invalid");
    }
    normalized.loginPhase = "totp";
  }
  return normalized;
}

function normalizePublicSession(value, now) {
  const payload = cloneBounded(value, MAX_SESSION_BYTES, "auth_state_public_session_invalid");
  if (!isPlainObject(payload)
      || typeof payload.csrf !== "string"
      || !payload.csrf
      || !Number.isSafeInteger(Number(payload.expiresAt))) {
    fail("auth_state_public_session_invalid");
  }
  payload.uuid = normalizeUuid(payload.uuid);
  payload.expiresAt = Number(payload.expiresAt);
  payload.authenticationMethod = String(payload.authenticationMethod || "");
  if (payload.authenticationMethod !== "access_key" && payload.authenticationMethod !== "legacy_uuid") {
    fail("auth_state_authentication_method_invalid");
  }
  payload.accessCredentialVersion = normalizeNonNegativeInteger(payload.accessCredentialVersion, "auth_state_access_credential_version_invalid");
  requireFutureExpiry(payload.expiresAt, now);
  return {
    uuid: payload.uuid,
    csrf: payload.csrf,
    expiresAt: payload.expiresAt,
    authenticationMethod: payload.authenticationMethod,
    accessCredentialVersion: payload.accessCredentialVersion,
  };
}

function assertPublicSessionAgainstInvite(session, invite, now) {
  if (session.authenticationMethod === "access_key") {
    if (!invite.accessKeyHmac || session.accessCredentialVersion !== invite.accessCredentialVersion) {
      fail("auth_state_public_session_revoked");
    }
  } else {
    const deadline = Date.parse(String(invite.legacyUuidLoginUntil || ""));
    if (invite.credentialVersion >= 2 && (!Number.isFinite(deadline) || now > deadline)) {
      fail("auth_state_legacy_session_expired");
    }
    if (Number.isFinite(deadline) && session.expiresAt > deadline) {
      fail("auth_state_legacy_session_expiry_invalid");
    }
  }
}

function normalizeImportedPublicSession(value, now) {
  const payload = cloneBounded(value, MAX_SESSION_BYTES, "auth_state_public_session_invalid");
  if (isPlainObject(payload)
      && (!Object.hasOwn(payload, "authenticationMethod") || payload.authenticationMethod === "")) {
    payload.authenticationMethod = "legacy_uuid";
    payload.accessCredentialVersion = 0;
  }
  return normalizePublicSession(payload, now);
}

function reconcileImportedPublicSession(session, invite, now) {
  try {
    const payload = { ...session };
    if (payload.authenticationMethod === "legacy_uuid") {
      const deadline = Date.parse(String(invite.legacyUuidLoginUntil || ""));
      if (Number(invite.credentialVersion || 0) >= 2 && !Number.isFinite(deadline)) return null;
      if (Number.isFinite(deadline)) payload.expiresAt = Math.min(payload.expiresAt, deadline);
      if (payload.expiresAt <= now) return null;
    }
    assertPublicSessionAgainstInvite(payload, invite, now);
    return payload;
  } catch {
    return null;
  }
}

function reconcilePublicSessionsForInvite(sql, previous, next, now = Date.now()) {
  const accessCredentialChanged = String(previous.access_key_hmac || "") !== String(next.accessKeyHmac || "")
    || Number(previous.credential_version || 0) !== Number(next.credentialVersion || 0)
    || Number(previous.access_credential_version || 0) !== Number(next.accessCredentialVersion || 0);
  if (accessCredentialChanged) {
    sql.exec(
      "DELETE FROM sessions WHERE kind = 'public' AND uuid = ? AND authentication_method = 'access_key'",
      next.uuid,
    );
  }

  const deadline = Date.parse(String(next.legacyUuidLoginUntil || ""));
  if (!Number.isFinite(deadline)) {
    if (Number(next.credentialVersion || 0) >= 2) {
      sql.exec(
        "DELETE FROM sessions WHERE kind = 'public' AND uuid = ? AND authentication_method = 'legacy_uuid'",
        next.uuid,
      );
    }
    return;
  }
  if (deadline <= now) {
    sql.exec(
      "DELETE FROM sessions WHERE kind = 'public' AND uuid = ? AND authentication_method = 'legacy_uuid'",
      next.uuid,
    );
    return;
  }

  const sessions = sql.exec(
    "SELECT token_hash, payload, expires_at FROM sessions WHERE kind = 'public' AND uuid = ? AND authentication_method = 'legacy_uuid'",
    next.uuid,
  ).toArray();
  for (const row of sessions) {
    const expiresAt = Math.min(Number(row.expires_at), deadline);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) {
      sql.exec("DELETE FROM sessions WHERE kind = 'public' AND token_hash = ?", row.token_hash);
      continue;
    }
    if (expiresAt === Number(row.expires_at)) continue;
    try {
      const payload = parseStoredPublicSession(row.payload);
      payload.expiresAt = expiresAt;
      sql.exec(
        "UPDATE sessions SET payload = ?, expires_at = ? WHERE kind = 'public' AND token_hash = ?",
        stringifyBounded(payload, MAX_SESSION_BYTES),
        expiresAt,
        row.token_hash,
      );
    } catch {
      sql.exec("DELETE FROM sessions WHERE kind = 'public' AND token_hash = ?", row.token_hash);
    }
  }
}

function assertUniqueInviteFields(items) {
  const uuids = new Set();
  const hmacs = new Set();
  for (const invite of items) {
    if (uuids.has(invite.uuid)) fail("auth_state_duplicate_uuid");
    uuids.add(invite.uuid);
    if (invite.accessKeyHmac) {
      if (hmacs.has(invite.accessKeyHmac)) fail("auth_state_access_key_hmac_duplicate");
      hmacs.add(invite.accessKeyHmac);
    }
  }
}

function adminInviteSummaryFromRow(row) {
  if (!isPlainObject(row)) fail("auth_state_invite_summary_corrupt");
  return {
    uuid: normalizeUuid(row.uuid),
    username: adminSummaryText(row.username, 100),
    name: adminSummaryText(row.name, 100),
    email: adminSummaryText(row.email, 160),
    remark: adminSummaryText(row.remark, 240),
    createdAt: adminSummaryText(row.created_at, 64),
    accessKeyHmac: Number(row.has_access_key) === 1 ? "configured" : "",
    credentialVersion: normalizeNonNegativeInteger(
      row.credential_version,
      "auth_state_invite_summary_corrupt",
    ),
    accessCredentialVersion: normalizeNonNegativeInteger(
      row.access_credential_version,
      "auth_state_invite_summary_corrupt",
    ),
    legacyUuidLoginUntil: adminSummaryText(row.legacy_uuid_login_until, 64),
    apiConfigCount: adminSummaryCount(row.api_config_count, 10_000),
  };
}

function adminTrashSummaryFromRow(row) {
  if (!isPlainObject(row)) fail("auth_state_trash_summary_corrupt");
  const base = {
    id: normalizeTrashId(row.id),
    type: String(row.item_type || ""),
    deletedAt: adminSummaryText(row.deleted_at, 64),
  };
  if (base.type === "uuid") {
    return {
      ...base,
      invite: {
        uuid: normalizeUuid(row.invite_uuid),
        username: adminSummaryText(row.invite_username, 100),
        name: adminSummaryText(row.invite_name, 100),
        email: adminSummaryText(row.invite_email, 160),
      },
      recordCount: adminSummaryCount(row.record_count, MAX_TRASH_ITEMS),
    };
  }
  if (base.type === "ip_group") {
    return {
      ...base,
      uuid: normalizeUuid(row.group_uuid),
      group: {
        country: adminSummaryText(row.country, 80),
        region: adminSummaryText(row.region, 120),
        city: adminSummaryText(row.city, 120),
        ipCount: adminSummaryCount(row.ip_count, MAX_TRASH_ITEMS),
      },
    };
  }
  fail("auth_state_trash_summary_corrupt");
}

function adminSummaryText(value, maximum) {
  return String(value ?? "").slice(0, maximum);
}

function adminSummaryCount(value, maximum) {
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0 || count > maximum) {
    fail("auth_state_admin_summary_count_invalid");
  }
  return count;
}

function parseStoredInvite(payload) {
  return normalizeInvite(parseStoredJson(payload, "auth_state_invite_corrupt"));
}

function parseStoredTrash(payload) {
  return normalizeTrashItem(parseStoredJson(payload, "auth_state_trash_corrupt"));
}

function parseStoredAdminSession(payload, now) {
  return normalizeAdminSession(parseStoredJson(payload, "auth_state_session_corrupt"), now);
}

function parseStoredPublicSession(payload) {
  return normalizePublicSession(parseStoredJson(payload, "auth_state_session_corrupt"), 0);
}

function readMeta(sql, key) {
  const row = sql.exec("SELECT value FROM auth_meta WHERE key = ?", key).toArray()[0];
  if (!row || typeof row.value !== "string") fail("auth_state_meta_corrupt");
  return row.value;
}

function setMeta(sql, key, value) {
  sql.exec("INSERT INTO auth_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, String(value));
}

function readRevision(sql, key) {
  const value = Number(readMeta(sql, key));
  return requireRevision(value);
}

function readLegacyCleanupSchedulerVersion(sql) {
  const value = Number(readMeta(sql, "legacy_cleanup_scheduler_version"));
  if (!Number.isSafeInteger(value) || value < 0 || value > LEGACY_CLEANUP_SCHEDULER_VERSION) {
    fail("auth_state_legacy_cleanup_scheduler_corrupt");
  }
  return value;
}

function readLegacyCleanupRechecks(sql) {
  const value = Number(readMeta(sql, "legacy_cleanup_rechecks_remaining"));
  if (!Number.isSafeInteger(value) || value < 0 || value > LEGACY_CLEANUP_RECHECKS) {
    fail("auth_state_legacy_cleanup_scheduler_corrupt");
  }
  return value;
}

function requireSql(storage) {
  if (!storage || !storage.sql || typeof storage.sql.exec !== "function" || typeof storage.transactionSync !== "function") {
    fail("auth_state_storage_invalid");
  }
  return storage.sql;
}

function normalizePageOffset(value, maximum, code) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    fail(code);
  }
  return value;
}

function normalizePageLimit(value, code) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > MAX_ADMIN_PAGE_SIZE) {
    fail(code);
  }
  return value;
}

function normalizeCredentialMigrationBatchLimit(value) {
  const limit = Number(value);
  if (
    !Number.isInteger(limit)
    || limit < 1
    || limit > MAX_INVITE_CREDENTIAL_MIGRATION_BATCH
  ) {
    fail("auth_state_credential_migration_batch_invalid");
  }
  return limit;
}

function normalizeCredentialMigrationUpdates(value) {
  if (
    !Array.isArray(value)
    || value.length < 1
    || value.length > MAX_INVITE_CREDENTIAL_MIGRATION_BATCH
  ) {
    fail("auth_state_credential_migration_batch_invalid");
  }
  const seen = new Set();
  return value.map((entry) => {
    if (!isPlainObject(entry)) {
      fail("auth_state_credential_migration_batch_invalid");
    }
    const uuid = normalizeUuid(entry.uuid);
    if (seen.has(uuid)) {
      fail("auth_state_credential_migration_batch_invalid");
    }
    seen.add(uuid);
    return {
      uuid,
      accessKeyHmac: normalizeHash(
        entry.accessKeyHmac,
        "auth_state_access_key_hmac_invalid",
      ),
      expectedAccessCredentialVersion: normalizeNonNegativeInteger(
        entry.expectedAccessCredentialVersion,
        "auth_state_access_credential_version_invalid",
      ),
    };
  });
}

function requireRevision(value) {
  if (!Number.isSafeInteger(Number(value)) || Number(value) < 0) fail("auth_state_revision_invalid");
  return Number(value);
}

function requireNow(value) {
  if (!Number.isSafeInteger(Number(value)) || Number(value) < 0) fail("auth_state_clock_invalid");
  return Number(value);
}

function requireFutureExpiry(value, now) {
  requireNow(now);
  if (!Number.isSafeInteger(value) || value <= now) fail("auth_state_session_expired");
}

function normalizeNonNegativeInteger(value, code) {
  const number = value === undefined || value === null || value === "" ? 0 : Number(value);
  if (!Number.isSafeInteger(number) || number < 0) fail(code);
  return number;
}

function normalizeUuid(value) {
  const uuid = String(value || "").toLowerCase();
  if (!UUID_PATTERN.test(uuid)) fail("auth_state_uuid_invalid");
  return uuid;
}

function normalizeHash(value, code) {
  const hash = String(value || "").toLowerCase();
  if (!HASH_PATTERN.test(hash)) fail(code);
  return hash;
}

function normalizeTrashId(value) {
  const id = String(value || "");
  if (!TRASH_ID_PATTERN.test(id)) fail("auth_state_trash_id_invalid");
  return id;
}

function normalizeSessionKind(value) {
  if (value !== "admin" && value !== "public") fail("auth_state_session_kind_invalid");
  return value;
}

function normalizeCloudflareMutation(value) {
  if (!isPlainObject(value)) fail("auth_state_cloudflare_mutation_invalid");
  const allowedFields = new Set([
    "mutationId",
    "comment",
    "expectedValueHashes",
    "itemIds",
    "createdAt",
    "notBefore",
    "leaseUntil",
  ]);
  if (Object.keys(value).some((key) => !allowedFields.has(key))) {
    fail("auth_state_cloudflare_mutation_invalid");
  }
  const mutationId = normalizeHash(value.mutationId, "auth_state_cloudflare_mutation_id_invalid");
  const comment = String(value.comment || "");
  if (!CLOUDFLARE_COMMENT_PATTERN.test(comment)) fail("auth_state_cloudflare_mutation_comment_invalid");
  const expectedValueHashes = normalizeCloudflareValueHashes(value.expectedValueHashes);
  const itemIds = normalizeCloudflareItemIds(value.itemIds || []);
  const createdAt = requireNow(value.createdAt);
  const notBefore = requireNow(value.notBefore);
  const leaseUntil = requireNow(value.leaseUntil || 0);
  if (notBefore < createdAt) fail("auth_state_cloudflare_mutation_time_invalid");
  return { mutationId, comment, expectedValueHashes, itemIds, createdAt, notBefore, leaseUntil };
}

function normalizeCloudflareValueHashes(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_CLOUDFLARE_MUTATION_ITEMS) {
    fail("auth_state_cloudflare_mutation_values_invalid");
  }
  const hashes = value.map((item) => normalizeHash(item, "auth_state_cloudflare_mutation_values_invalid"));
  if (new Set(hashes).size !== hashes.length) fail("auth_state_cloudflare_mutation_values_invalid");
  return hashes;
}

function normalizeCloudflareItemIds(value) {
  if (!Array.isArray(value) || value.length > MAX_CLOUDFLARE_MUTATION_ITEMS) {
    fail("auth_state_cloudflare_mutation_items_invalid");
  }
  const ids = value.map((item) => String(item || ""));
  if (ids.some((item) => !CLOUDFLARE_ITEM_ID_PATTERN.test(item)) || new Set(ids).size !== ids.length) {
    fail("auth_state_cloudflare_mutation_items_invalid");
  }
  return ids;
}

function cloudflareMutationFromRow(row) {
  const marker = {
    mutationId: String(row.mutation_id || ""),
    comment: String(row.comment || ""),
    expectedValueHashes: parseCloudflareMutationArray(row.expected_value_hashes),
    itemIds: parseCloudflareMutationArray(row.item_ids),
    createdAt: Number(row.created_at),
    notBefore: Number(row.not_before),
    leaseUntil: Number(row.lease_until),
  };
  return normalizeCloudflareMutation(marker);
}

function parseCloudflareMutationArray(value) {
  try {
    return JSON.parse(String(value || ""));
  } catch {
    fail("auth_state_cloudflare_mutation_invalid");
  }
}

function rejectCredentialFields(value, seen = new Set()) {
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) fail("auth_state_circular_payload");
  seen.add(value);
  if (Array.isArray(value)) {
    for (const child of value) rejectCredentialFields(child, seen);
  } else {
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_CREDENTIAL_FIELDS.has(key)) fail("auth_state_plaintext_credential");
      rejectCredentialFields(child, seen);
    }
  }
  seen.delete(value);
}

function rejectTrashCredentialFields(value, seen = new Set()) {
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) fail("auth_state_circular_payload");
  seen.add(value);
  if (Array.isArray(value)) {
    for (const child of value) rejectTrashCredentialFields(child, seen);
  } else {
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_TRASH_FIELDS.has(key)) fail("auth_state_trash_credential");
      rejectTrashCredentialFields(child, seen);
    }
  }
  seen.delete(value);
}

function cloneBounded(value, maxBytes, code) {
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch {
    fail(code);
  }
  if (typeof encoded !== "string" || utf8ByteLength(encoded) > maxBytes) fail(code);
  try {
    return JSON.parse(encoded);
  } catch {
    fail(code);
  }
}

function stringifyBounded(value, maxBytes) {
  const encoded = JSON.stringify(value);
  if (typeof encoded !== "string" || utf8ByteLength(encoded) > maxBytes) fail("auth_state_payload_too_large");
  return encoded;
}

function parseStoredJson(value, code) {
  if (typeof value !== "string" || utf8ByteLength(value) > MAX_ITEM_BYTES) fail(code);
  try {
    return JSON.parse(value);
  } catch {
    fail(code);
  }
}

function utf8ByteLength(value) {
  return UTF8_ENCODER.encode(value).byteLength;
}

function fail(code) {
  throw new Error(code);
}

export class AuthStateStore {
  constructor(env) {
    this.env = env;
    this.stub = requireAuthStateBinding(env);
    this.readyPromise = null;
  }

  async status() {
    return await this.call("status");
  }

  async ready() {
    if (!this.readyPromise) {
      this.readyPromise = this.ensureReady().catch((error) => {
        this.readyPromise = null;
        throw error;
      });
    }
    return await this.readyPromise;
  }

  async ensureReady() {
    let status = await this.status();
    if (!status.migrated) {
      const snapshot = await loadLegacySnapshot(this.env);
      await this.call("importLegacy", snapshot, new Date().toISOString());
      status = await this.status();
    }
    if (!status.migrated) throw new AuthStateUnavailableError("auth_state_migration_incomplete");
    return status;
  }

  async readInvites({ reveal = false } = {}) {
    await this.ready();
    const result = await this.call("getInvites");
    if (!reveal) return result;
    const items = await Promise.all(result.items.map((item) => revealInviteCredentials(item, this.env.CREDENTIAL_ENCRYPTION_KEY)));
    return { ...result, items };
  }

  async readCredentialMigrationBatch(limit = MAX_INVITE_CREDENTIAL_MIGRATION_BATCH) {
    await this.ready();
    return await this.call("getCredentialMigrationBatch", limit);
  }

  async commitCredentialMigrationBatch(expectedRevision, updates) {
    await this.ready();
    return await this.call(
      "commitCredentialMigrationBatch",
      expectedRevision,
      updates,
    );
  }

  async getLegacyCleanupReadiness(now = Date.now()) {
    await this.ready();
    return await this.call("legacyCleanupReadiness", now);
  }

  async readAdminPage({
    inviteOffset = 0,
    inviteLimit = 25,
    trashOffset = 0,
    trashLimit = 25,
  } = {}) {
    await this.ready();
    return await this.call(
      "getAdminPage",
      inviteOffset,
      inviteLimit,
      trashOffset,
      trashLimit,
    );
  }

  async getInvite(uuid, { reveal = false } = {}) {
    await this.ready();
    const item = await this.call("getInvite", normalizeUuid(uuid));
    if (!item || !reveal) return item;
    return await revealInviteCredentials(item, this.env.CREDENTIAL_ENCRYPTION_KEY);
  }

  async findInviteByAccessKeyHmac(hmac, { reveal = false } = {}) {
    await this.ready();
    const item = await this.call("findInviteByAccessKeyHmac", normalizeHash(hmac, "auth_state_access_key_hmac_invalid"));
    if (!item || !reveal) return item;
    return await revealInviteCredentials(item, this.env.CREDENTIAL_ENCRYPTION_KEY);
  }

  async compareAndSwapInvites(expectedRevision, items) {
    await this.ready();
    const protectedItems = await protectInviteCollection(this.env, items);
    return await this.call("replaceInvites", expectedRevision, protectedItems);
  }

  async upsertInvite(expectedRevision, invite) {
    await this.ready();
    const protectedInvite = await protectInviteCredentials(invite, this.env.CREDENTIAL_ENCRYPTION_KEY, this.env.INVITE_ACCESS_HMAC_KEY);
    return await this.call("upsertInvite", expectedRevision, protectedInvite);
  }

  async readTrash() {
    await this.ready();
    return await this.call("getTrash");
  }

  async compareAndSwapTrash(expectedRevision, items) {
    await this.ready();
    return await this.call("replaceTrash", expectedRevision, items.map(sanitizeTrashForAuthState));
  }

  async removeInvite(expectedInviteRevision, expectedTrashRevision, uuid, trashItem) {
    await this.ready();
    return await this.call("removeInvite", expectedInviteRevision, expectedTrashRevision, uuid, sanitizeTrashForAuthState(trashItem));
  }

  async restoreInvite(expectedInviteRevision, expectedTrashRevision, trashId, invite) {
    await this.ready();
    const protectedInvite = await protectInviteCredentials(invite, this.env.CREDENTIAL_ENCRYPTION_KEY, this.env.INVITE_ACCESS_HMAC_KEY);
    return await this.call("restoreInvite", expectedInviteRevision, expectedTrashRevision, trashId, protectedInvite);
  }

  async purgeTrash(expectedRevision, trashId) {
    await this.ready();
    return await this.call("purgeTrash", expectedRevision, trashId);
  }

  async createAdminSession(tokenHash, payload) {
    await this.ready();
    return await this.call("putAdminSession", tokenHash, payload);
  }

  async getAdminSession(tokenHash) {
    const status = await this.ready();
    let result = await this.call("getAdminSession", tokenHash);
    if (!result && status.legacyCleanupComplete === false) {
      const payload = await readLegacySession(
        this.env?.INVITE_STORE,
        "session:",
        tokenHash,
        "admin",
      );
      if (payload) {
        await this.call("putAdminSession", tokenHash, payload);
        result = await this.call("getAdminSession", tokenHash);
      }
    }
    return result;
  }

  async createPublicSession(tokenHash, payload) {
    await this.ready();
    return await this.call("putPublicSession", tokenHash, payload);
  }

  async getPublicSession(tokenHash, { reveal = false } = {}) {
    const status = await this.ready();
    let result = await this.call("getPublicSession", tokenHash);
    if (!result && status.legacyCleanupComplete === false) {
      const legacy = await readLegacySession(
        this.env?.INVITE_STORE,
        "uuid-session:",
        tokenHash,
        "public",
      );
      if (legacy) {
        const invite = await this.call("getInvite", legacy.uuid);
        const payload = invite
          ? reconcileImportedPublicSession(legacy, invite, Date.now())
          : null;
        if (payload) {
          await this.call("putPublicSession", tokenHash, payload);
          result = await this.call("getPublicSession", tokenHash);
        }
      }
    }
    if (!result || !reveal) return result;
    return {
      ...result,
      invite: await revealInviteCredentials(
        result.invite,
        this.env.CREDENTIAL_ENCRYPTION_KEY,
      ),
    };
  }

  async deleteAdminSession(tokenHash) {
    await this.ready();
    const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
    if (this.env?.INVITE_STORE && typeof this.env.INVITE_STORE.delete === "function") {
      await this.env.INVITE_STORE.delete(`session:${normalizedHash}`);
    }
    return await this.call("deleteSession", "admin", normalizedHash);
  }

  async deletePublicSession(tokenHash) {
    await this.ready();
    const normalizedHash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
    if (this.env?.INVITE_STORE && typeof this.env.INVITE_STORE.delete === "function") {
      await this.env.INVITE_STORE.delete(`uuid-session:${normalizedHash}`);
    }
    return await this.call("deleteSession", "public", normalizedHash);
  }

  async purgeExpiredSessions() {
    await this.ready();
    return await this.call("purgeExpiredSessions");
  }

  async purgeLegacySourceKeys() {
    await this.ready();
    return await this.call("runLegacyCleanup", "explicit");
  }

  async registerCloudflareMutation(marker) {
    await this.ready();
    return await this.call("registerCloudflareMutation", marker);
  }

  async updateCloudflareMutationItems(mutationId, itemIds) {
    await this.ready();
    return await this.call("updateCloudflareMutationItems", mutationId, itemIds);
  }

  async getCloudflareMutation(mutationId) {
    await this.ready();
    return await this.call("getCloudflareMutation", mutationId);
  }

  async claimCloudflareMutations(now, limit = MAX_CLOUDFLARE_MUTATION_CLAIM, leaseMs = 60_000) {
    await this.ready();
    return await this.call("claimCloudflareMutations", now, limit, leaseMs);
  }

  async releaseCloudflareMutation(mutationId, retryAt) {
    await this.ready();
    return await this.call("releaseCloudflareMutation", mutationId, retryAt);
  }

  async resolveCloudflareMutation(mutationId) {
    await this.ready();
    return await this.call("resolveCloudflareMutation", mutationId);
  }

  async listCloudflareMutationComments() {
    await this.ready();
    return await this.call("listCloudflareMutationComments");
  }

  async claimRecordLease(uuid, ownerToken, now = Date.now(), leaseMs = 60_000) {
    return await this.call("claimRecordLease", uuid, ownerToken, now, leaseMs);
  }

  async releaseRecordLease(uuid, ownerToken) {
    return await this.call("releaseRecordLease", uuid, ownerToken);
  }

  async claimRecordMaintenanceLease(ownerToken, now = Date.now(), leaseMs = 60_000) {
    return await this.call("claimRecordMaintenanceLease", ownerToken, now, leaseMs);
  }

  async releaseRecordMaintenanceLease(ownerToken) {
    return await this.call("releaseRecordMaintenanceLease", ownerToken);
  }

  async getRecords(uuid) {
    return await this.env.INVITE_STORE.get(recordsKey(uuid));
  }

  async putRecords(uuid, value) {
    const encoded = stringifyBounded(value, MAX_COLLECTION_BYTES);
    await this.env.INVITE_STORE.put(recordsKey(uuid), encoded);
  }

  async deleteRecords(uuid) {
    await this.env.INVITE_STORE.delete(recordsKey(uuid));
  }

  async call(method, ...args) {
    if (!this.stub || typeof this.stub[method] !== "function") {
      throw new AuthStateUnavailableError("auth_state_method_unavailable");
    }
    try {
      return await this.stub[method](...args);
    } catch (error) {
      const message = String(error?.message || "");
      if (/^auth_state_[a-z0-9_]+$/.test(message)) throw new Error(message);
      throw new Error("auth_state_request_failed");
    }
  }
}

export function createAuthStateStore(env) {
  return new AuthStateStore(env);
}

async function protectInviteCollection(env, items) {
  if (!Array.isArray(items) || items.length > MAX_INVITES) fail("auth_state_invites_invalid");
  return await Promise.all(items.map((item) => protectInviteCredentials(
    item,
    env.CREDENTIAL_ENCRYPTION_KEY,
    env.INVITE_ACCESS_HMAC_KEY,
  )));
}

function sanitizeTrashForAuthState(item) {
  if (!item || typeof item !== "object") fail("auth_state_trash_item_invalid");
  if (item.type === "uuid") {
    const records = Array.isArray(item.records) ? item.records : [];
    if (records.length > MAX_TRASH_ITEMS) fail("auth_state_trash_records_invalid");
    return {
      id: String(item.id || ""),
      type: "uuid",
      deletedAt: String(item.deletedAt || ""),
      invite: sanitizeInviteForTrash(item.invite || {}),
      records: records.map(sanitizeTrashIpGroup),
    };
  }
  if (item.type === "ip_group") {
    return {
      id: String(item.id || ""),
      type: "ip_group",
      uuid: String(item.uuid || ""),
      group: item.group && typeof item.group === "object"
        ? sanitizeTrashIpGroup(item.group)
        : null,
      deletedAt: String(item.deletedAt || ""),
    };
  }
  fail("auth_state_trash_type_invalid");
}

function sanitizeTrashIpGroup(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const ips = Array.isArray(source.ips) ? source.ips : [];
  if (ips.length > MAX_TRASH_ITEMS) fail("auth_state_trash_ips_invalid");
  return {
    id: boundedTrashText(source.id, 64),
    addedAt: boundedTrashText(source.addedAt, 64),
    updatedAt: boundedTrashText(source.updatedAt, 64),
    expiresAt: boundedTrashText(source.expiresAt, 64),
    country: boundedTrashText(source.country, 80),
    region: boundedTrashText(source.region, 120),
    city: boundedTrashText(source.city, 120),
    timezone: boundedTrashText(source.timezone, 80),
    colo: boundedTrashText(source.colo, 32),
    asn: boundedTrashText(source.asn, 32),
    asOrganization: boundedTrashText(source.asOrganization, 200),
    geoSource: boundedTrashText(source.geoSource, 32),
    ips: ips.map(sanitizeTrashIpItem),
  };
}

function sanitizeTrashIpItem(value) {
  const source = typeof value === "string"
    ? { ip: value, cidr: value, listValue: value }
    : value && typeof value === "object" && !Array.isArray(value)
      ? value
      : {};
  return {
    ip: boundedTrashText(source.ip, 160),
    version: boundedTrashText(source.version, 8),
    cidr: boundedTrashText(source.cidr, 180),
    listValue: boundedTrashText(source.listValue, 180),
    listItemId: boundedTrashText(source.listItemId, 128),
    alreadyListed: Boolean(source.alreadyListed),
  };
}

function boundedTrashText(value, maximum) {
  return typeof value === "string" ? value.slice(0, maximum) : "";
}

export { sanitizeTrashForAuthState };

async function loadLegacySnapshot(env) {
  const kv = env?.INVITE_STORE;
  if (!kv || typeof kv.get !== "function" || typeof kv.list !== "function") {
    throw new AuthStateUnavailableError("auth_state_migration_source_unavailable");
  }
  const invites = await readLegacyArray(kv, "invites");
  const trash = await readLegacyArray(kv, "trash");
  return {
    invites: await protectInviteCollection(env, invites),
    trash: trash.filter(Boolean).map(sanitizeTrashForAuthState),
    adminSessions: [],
    publicSessions: [],
  };
}

export async function cleanupLegacySourceKeys(kv) {
  if (!kv || typeof kv.get !== "function" || typeof kv.list !== "function" || typeof kv.delete !== "function") {
    throw new AuthStateUnavailableError("auth_state_migration_source_unavailable");
  }
  for (const key of ["invites", "trash"]) {
    await kv.delete(key);
    if (await kv.get(key) !== null) {
      throw new AuthStateUnavailableError("auth_state_legacy_cleanup_incomplete");
    }
  }
  for (const prefix of ["session:", "uuid-session:"]) {
    let complete = false;
    for (let pass = 0; pass < MAX_LEGACY_LIST_PAGES; pass += 1) {
      const result = await kv.list({ prefix, limit: 1000 });
      if (!result || !Array.isArray(result.keys)) {
        throw new AuthStateUnavailableError("auth_state_legacy_cleanup_list_invalid");
      }
      const names = result.keys
        .map((entry) => String(entry?.name || ""))
        .filter((name) => name.startsWith(prefix));
      if (names.length === 0) {
        complete = true;
        break;
      }
      for (let offset = 0; offset < names.length; offset += LEGACY_DELETE_CONCURRENCY) {
        await Promise.all(
          names.slice(offset, offset + LEGACY_DELETE_CONCURRENCY).map((name) => kv.delete(name)),
        );
      }
    }
    if (!complete) {
      throw new AuthStateUnavailableError("auth_state_legacy_cleanup_page_limit");
    }
  }
}

export async function inspectLegacySourceKeys(kv) {
  if (!kv || typeof kv.get !== "function" || typeof kv.list !== "function") {
    throw new AuthStateUnavailableError("auth_state_migration_source_unavailable");
  }
  let residualScopes = 0;
  for (const key of ["invites", "trash"]) {
    if (await kv.get(key) !== null) residualScopes += 1;
  }
  for (const prefix of ["session:", "uuid-session:"]) {
    const result = await kv.list({ prefix, limit: 1 });
    if (!result || !Array.isArray(result.keys)) {
      throw new AuthStateUnavailableError("auth_state_legacy_cleanup_list_invalid");
    }
    if (result.keys.length > 0) residualScopes += 1;
  }
  return { empty: residualScopes === 0, residualScopes };
}

async function readLegacyArray(kv, key) {
  const raw = await kv.get(key);
  if (raw === null || raw === undefined || raw === "") return [];
  if (typeof raw !== "string" || utf8ByteLength(raw) > MAX_COLLECTION_BYTES) {
    throw new Error("auth_state_legacy_collection_too_large");
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("auth_state_legacy_collection_invalid");
  }
  if (!Array.isArray(parsed)) throw new Error("auth_state_legacy_collection_invalid");
  return parsed;
}

async function readLegacySession(kv, prefix, tokenHash, kind, now = Date.now()) {
  if (!kv || typeof kv.get !== "function") return null;
  let hash;
  try {
    hash = normalizeHash(tokenHash, "auth_state_session_hash_invalid");
  } catch {
    return null;
  }
  const raw = await kv.get(`${prefix}${hash}`);
  if (typeof raw !== "string" || utf8ByteLength(raw) > MAX_SESSION_BYTES) return null;
  try {
    const payload = JSON.parse(raw);
    return kind === "admin"
      ? normalizeAdminSession(payload, now)
      : normalizeImportedPublicSession(payload, now);
  } catch {
    return null;
  }
}

function recordsKey(uuid) {
  return `records:${normalizeUuid(uuid)}`;
}

export const __test = Object.freeze({
  MAX_INVITES,
  MAX_TRASH_ITEMS,
  MAX_ADMIN_PAGE_SIZE,
  MAX_SESSION_IMPORTS,
  MAX_CLOUDFLARE_MUTATIONS,
  MAX_CLOUDFLARE_MUTATION_ITEMS,
  MAX_CLOUDFLARE_MUTATION_CLAIM,
  normalizeInvite,
  normalizeTrashItem,
  normalizeAdminSession,
  normalizePublicSession,
  parseStoredJson,
  sanitizeTrashForAuthState,
  utf8ByteLength,
  recordsKey,
  normalizeCloudflareMutation,
  cleanupLegacySourceKeys,
  inspectLegacySourceKeys,
});
