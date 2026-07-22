import { DurableObject } from "cloudflare:workers";

import worker from "./index.js";
import {
  authStateArmLegacyCleanupRechecks,
  authStateClaimLegacyCleanup,
  authStateDeleteSession,
  authStateFindInviteByAccessKeyHmac,
  authStateGetCredentialMigrationBatch,
  authStateClaimCloudflareMutations,
  authStateGetCloudflareMutation,
  authStateGetAdminPage,
  authStateGetAdminSession,
  authStateGetInvite,
  authStateGetInvites,
  authStateGetPublicSession,
  authStateGetTrash,
  authStateImportLegacy,
  authStateCommitCredentialMigrationBatch,
  authStateLegacyCleanupReadiness,
  authStatePurgeExpiredSessions,
  authStatePurgeTrash,
  authStateRegisterCloudflareMutation,
  authStateReleaseCloudflareMutation,
  authStateReleaseLegacyCleanup,
  authStateResolveCloudflareMutation,
  authStateListCloudflareMutationComments,
  authStateClaimRecordLease,
  authStateClaimRecordMaintenanceLease,
  authStateReleaseRecordLease,
  authStateReleaseRecordMaintenanceLease,
  authStateMarkLegacyCleanupComplete,
  authStatePutAdminSession,
  authStatePutPublicSession,
  authStateRemoveInvite,
  authStateReplaceInvites,
  authStateReplaceTrash,
  authStateRestoreInvite,
  authStateStatus,
  authStateUpsertInvite,
  authStateUpdateCloudflareMutationItems,
  cleanupLegacySourceKeys,
  initializeAuthStateStorage,
  isAuthStateBindingConfigured,
  LEGACY_CLEANUP_LEASE_MS,
  LEGACY_CLEANUP_RECHECK_DELAY_MS,
} from "./auth-state.js";
import {
  consumeRateLimitAttempt,
  handleRateLimitAlarm,
  resetRateLimitBucket,
} from "./auth-rate-limiter.js";
import { hasSeparatedHostnameAllowlists } from "./url-security.js";

export class AuthRateLimiter extends DurableObject {
  async consume(scope) {
    return await consumeRateLimitAttempt(this.ctx.storage, scope);
  }

  async reset(scope) {
    return await resetRateLimitBucket(this.ctx.storage, scope);
  }

  async alarm() {
    await handleRateLimitAlarm(this.ctx.storage);
  }
}

export class AuthState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      initializeAuthStateStorage(ctx.storage);
    });
  }

  async status() {
    return authStateStatus(this.ctx.storage);
  }

  async importLegacy(snapshot, importedAt) {
    return authStateImportLegacy(this.ctx.storage, snapshot, importedAt);
  }

  async markLegacyCleanupComplete(completedAt) {
    const result = authStateMarkLegacyCleanupComplete(this.ctx.storage, completedAt);
    await this.armLegacyCleanupRechecks();
    return result;
  }

  async armLegacyCleanupRechecks() {
    const status = authStateStatus(this.ctx.storage);
    if (status.legacyCleanupSchedulerReady) {
      return {
        armed: false,
        remaining: status.legacyCleanupRechecksRemaining,
      };
    }
    await this.#scheduleLegacyCleanupAt(Date.now() + LEGACY_CLEANUP_RECHECK_DELAY_MS);
    return authStateArmLegacyCleanupRechecks(this.ctx.storage);
  }

  async runLegacyCleanup(reason) {
    if (reason !== "explicit") {
      throw new Error("auth_state_legacy_cleanup_reason_invalid");
    }
    const readiness = authStateLegacyCleanupReadiness(this.ctx.storage, Date.now());
    if (!readiness.eligible) {
      throw new Error(readiness.reason || "auth_state_legacy_cleanup_ineligible");
    }
    const claim = authStateClaimLegacyCleanup(
      this.ctx.storage,
      Date.now(),
      LEGACY_CLEANUP_LEASE_MS,
    );
    if (!claim.claimed) {
      return { ok: true, cleaned: false, busy: true };
    }

    try {
      await cleanupLegacySourceKeys(this.env?.INVITE_STORE);
    } catch {
      authStateReleaseLegacyCleanup(this.ctx.storage);
      throw new Error("auth_state_legacy_cleanup_failed");
    }

    authStateMarkLegacyCleanupComplete(this.ctx.storage, new Date().toISOString());
    return { ok: true, cleaned: true, busy: false, remaining: 0 };
  }

  async alarm() {
    return { ok: true, cleaned: false };
  }

  async #scheduleLegacyCleanupAt(scheduledAt) {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || scheduledAt < current) {
      await this.ctx.storage.setAlarm(scheduledAt);
      return { scheduledAt };
    }
    return { scheduledAt: current };
  }

  async getInvites() {
    return authStateGetInvites(this.ctx.storage);
  }

  async getCredentialMigrationBatch(limit) {
    return authStateGetCredentialMigrationBatch(this.ctx.storage, limit);
  }

  async commitCredentialMigrationBatch(expectedRevision, updates) {
    return authStateCommitCredentialMigrationBatch(
      this.ctx.storage,
      expectedRevision,
      updates,
      Date.now(),
    );
  }

  async legacyCleanupReadiness(now) {
    return authStateLegacyCleanupReadiness(this.ctx.storage, now);
  }

  async getAdminPage(inviteOffset, inviteLimit, trashOffset, trashLimit) {
    return authStateGetAdminPage(
      this.ctx.storage,
      inviteOffset,
      inviteLimit,
      trashOffset,
      trashLimit,
    );
  }

  async getInvite(uuid) {
    return authStateGetInvite(this.ctx.storage, uuid);
  }

  async findInviteByAccessKeyHmac(hmac) {
    return authStateFindInviteByAccessKeyHmac(this.ctx.storage, hmac);
  }

  async replaceInvites(expectedRevision, items) {
    return authStateReplaceInvites(this.ctx.storage, expectedRevision, items);
  }

  async upsertInvite(expectedRevision, invite) {
    return authStateUpsertInvite(this.ctx.storage, expectedRevision, invite);
  }

  async removeInvite(expectedInviteRevision, expectedTrashRevision, uuid, trashItem) {
    return authStateRemoveInvite(
      this.ctx.storage,
      expectedInviteRevision,
      expectedTrashRevision,
      uuid,
      trashItem,
    );
  }

  async getTrash() {
    return authStateGetTrash(this.ctx.storage);
  }

  async replaceTrash(expectedRevision, items) {
    return authStateReplaceTrash(this.ctx.storage, expectedRevision, items);
  }

  async restoreInvite(expectedInviteRevision, expectedTrashRevision, trashId, invite) {
    return authStateRestoreInvite(
      this.ctx.storage,
      expectedInviteRevision,
      expectedTrashRevision,
      trashId,
      invite,
    );
  }

  async purgeTrash(expectedRevision, trashId) {
    return authStatePurgeTrash(this.ctx.storage, expectedRevision, trashId);
  }

  async putAdminSession(tokenHash, payload) {
    return authStatePutAdminSession(this.ctx.storage, tokenHash, payload);
  }

  async getAdminSession(tokenHash) {
    return authStateGetAdminSession(this.ctx.storage, tokenHash);
  }

  async putPublicSession(tokenHash, payload) {
    return authStatePutPublicSession(this.ctx.storage, tokenHash, payload);
  }

  async getPublicSession(tokenHash) {
    return authStateGetPublicSession(this.ctx.storage, tokenHash);
  }

  async deleteSession(kind, tokenHash) {
    return authStateDeleteSession(this.ctx.storage, kind, tokenHash);
  }

  async purgeExpiredSessions() {
    return authStatePurgeExpiredSessions(this.ctx.storage);
  }

  async registerCloudflareMutation(marker) {
    return authStateRegisterCloudflareMutation(this.ctx.storage, marker);
  }

  async updateCloudflareMutationItems(mutationId, itemIds) {
    return authStateUpdateCloudflareMutationItems(this.ctx.storage, mutationId, itemIds);
  }

  async getCloudflareMutation(mutationId) {
    return authStateGetCloudflareMutation(this.ctx.storage, mutationId);
  }

  async claimCloudflareMutations(now, limit, leaseMs) {
    return authStateClaimCloudflareMutations(this.ctx.storage, now, limit, leaseMs);
  }

  async releaseCloudflareMutation(mutationId, retryAt) {
    return authStateReleaseCloudflareMutation(this.ctx.storage, mutationId, retryAt);
  }

  async resolveCloudflareMutation(mutationId) {
    return authStateResolveCloudflareMutation(this.ctx.storage, mutationId);
  }

  async listCloudflareMutationComments() {
    return authStateListCloudflareMutationComments(this.ctx.storage);
  }

  async claimRecordLease(uuid, ownerToken, now, leaseMs) {
    return authStateClaimRecordLease(this.ctx.storage, uuid, ownerToken, now, leaseMs);
  }

  async releaseRecordLease(uuid, ownerToken) {
    return authStateReleaseRecordLease(this.ctx.storage, uuid, ownerToken);
  }

  async claimRecordMaintenanceLease(ownerToken, now, leaseMs) {
    return authStateClaimRecordMaintenanceLease(this.ctx.storage, ownerToken, now, leaseMs);
  }

  async releaseRecordMaintenanceLease(ownerToken) {
    return authStateReleaseRecordMaintenanceLease(this.ctx.storage, ownerToken);
  }
}

function failClosedIfAuthStateMissing(env) {
  return isAuthStateBindingConfigured(env)
    ? null
    : new Response("Service unavailable", {
      status: 503,
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain; charset=utf-8",
      },
    });
}

function failClosedIfHostnameAllowlistsInvalid(env) {
  return hasSeparatedHostnameAllowlists(
    env?.ALLOWED_HOSTNAMES,
    env?.PROVIDER_ALLOWED_HOSTNAMES,
  )
    ? null
    : new Response("Service unavailable", {
      status: 503,
      headers: {
        "cache-control": "no-store",
        "content-type": "text/plain; charset=utf-8",
      },
    });
}

export default {
  async fetch(request, env, ctx) {
    const unavailable = failClosedIfAuthStateMissing(env)
      || failClosedIfHostnameAllowlistsInvalid(env);
    if (unavailable) return unavailable;
    return await worker.fetch(request, env, ctx);
  },

  async scheduled(event, env, ctx) {
    const unavailable = failClosedIfAuthStateMissing(env);
    if (unavailable) {
      console.error(JSON.stringify({ level: "error", message: "auth_state_binding_missing" }));
      return;
    }
    const invalidHostnames = failClosedIfHostnameAllowlistsInvalid(env);
    if (invalidHostnames) {
      console.error(JSON.stringify({ level: "error", message: "hostname_allowlist_invalid" }));
      return;
    }
    if (typeof worker.scheduled === "function") {
      return await worker.scheduled(event, env, ctx);
    }
  },
};
