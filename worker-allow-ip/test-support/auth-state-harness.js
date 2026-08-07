import { AuthState as ProductionAuthState } from "../src/worker-entry.js";
import { AUTH_STATE_DO_NAME, createAuthStateStore } from "../src/auth-state.js";

export class AuthState extends ProductionAuthState {
  async runTestAlarm() {
    return await this.alarm();
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const body = request.method === "POST" ? await request.json() : {};
    const stub = env.AUTH_STATE.getByName(AUTH_STATE_DO_NAME);

    try {
      if (url.pathname === "/status") return Response.json(await stub.status());
      if (url.pathname === "/import") return Response.json(await stub.importLegacy(body.snapshot, body.importedAt));
      if (url.pathname === "/legacy-cleanup-complete") return Response.json(await stub.markLegacyCleanupComplete(body.completedAt));
      if (url.pathname === "/legacy-cleanup-run") {
        return Response.json(await stub.runLegacyCleanup(body.reason));
      }
      if (url.pathname === "/legacy-cleanup-alarm") {
        return Response.json(await stub.runTestAlarm());
      }
      if (url.pathname === "/invites") return Response.json(await stub.getInvites());
      if (url.pathname === "/credential-migration-batch") {
        return Response.json(await stub.getCredentialMigrationBatch(body.limit));
      }
      if (url.pathname === "/credential-migration-commit") {
        return Response.json(await stub.commitCredentialMigrationBatch(
          body.revision,
          body.updates,
        ));
      }
      if (url.pathname === "/legacy-cleanup-readiness") {
        return Response.json(await stub.legacyCleanupReadiness(body.now));
      }
      if (url.pathname === "/admin-page") {
        return Response.json(await stub.getAdminPage(
          body.inviteOffset,
          body.inviteLimit,
          body.trashOffset,
          body.trashLimit,
        ));
      }
      if (url.pathname === "/replace-invites") return Response.json(await stub.replaceInvites(body.revision, body.items));
      if (url.pathname === "/upsert-invite") return Response.json(await stub.upsertInvite(body.revision, body.invite));
      if (url.pathname === "/find-invite") return Response.json(await stub.findInviteByAccessKeyHmac(body.hmac));
      if (url.pathname === "/get-invite") return Response.json(await stub.getInvite(body.uuid));
      if (url.pathname === "/trash") return Response.json(await stub.getTrash());
      if (url.pathname === "/replace-trash") return Response.json(await stub.replaceTrash(body.revision, body.items));
      if (url.pathname === "/remove-invite") {
        return Response.json(await stub.removeInvite(body.inviteRevision, body.trashRevision, body.uuid, body.trashItem));
      }
      if (url.pathname === "/restore-invite") {
        return Response.json(await stub.restoreInvite(body.inviteRevision, body.trashRevision, body.trashId, body.invite));
      }
      if (url.pathname === "/purge-trash") return Response.json(await stub.purgeTrash(body.revision, body.trashId));
      if (url.pathname === "/admin-session") {
        if (body.action === "put") return Response.json(await stub.putAdminSession(body.hash, body.payload));
        if (body.action === "get") return Response.json(await stub.getAdminSession(body.hash));
        if (body.action === "delete") return Response.json(await stub.deleteSession("admin", body.hash));
      }
      if (url.pathname === "/public-session") {
        if (body.action === "put") return Response.json(await stub.putPublicSession(body.hash, body.payload));
        if (body.action === "get") return Response.json(await stub.getPublicSession(body.hash));
        if (body.action === "delete") return Response.json(await stub.deleteSession("public", body.hash));
      }
      if (url.pathname === "/cloudflare-mutation") {
        if (body.action === "register") return Response.json(await stub.registerCloudflareMutation(body.marker));
        if (body.action === "update") return Response.json(await stub.updateCloudflareMutationItems(body.mutationId, body.itemIds));
        if (body.action === "get") return Response.json(await stub.getCloudflareMutation(body.mutationId));
        if (body.action === "claim") return Response.json(await stub.claimCloudflareMutations(body.now, body.limit, body.leaseMs));
        if (body.action === "release") return Response.json(await stub.releaseCloudflareMutation(body.mutationId, body.retryAt));
        if (body.action === "resolve") return Response.json(await stub.resolveCloudflareMutation(body.mutationId));
        if (body.action === "comments") return Response.json(await stub.listCloudflareMutationComments());
      }
      if (url.pathname === "/record-lease") {
        if (body.action === "claim") {
          return Response.json(await stub.claimRecordLease(
            body.uuid,
            body.ownerToken,
            body.now,
            body.leaseMs,
          ));
        }
        if (body.action === "release") {
          return Response.json(await stub.releaseRecordLease(body.uuid, body.ownerToken));
        }
      }
      if (url.pathname === "/record-maintenance-lease") {
        if (body.action === "claim") {
          return Response.json(await stub.claimRecordMaintenanceLease(
            body.ownerToken,
            body.now,
            body.leaseMs,
          ));
        }
        if (body.action === "release") {
          return Response.json(await stub.releaseRecordMaintenanceLease(body.ownerToken));
        }
      }
      if (url.pathname === "/lazy-status") {
        return Response.json(await createAuthStateStore(env).ready());
      }
      if (url.pathname === "/lazy-admin-session") {
        return Response.json(await createAuthStateStore(env).getAdminSession(body.hash));
      }
      if (url.pathname === "/lazy-public-session") {
        return Response.json(await createAuthStateStore(env).getPublicSession(body.hash));
      }
      if (url.pathname === "/lazy-delete-session") {
        const store = createAuthStateStore(env);
        return Response.json(body.kind === "admin"
          ? await store.deleteAdminSession(body.hash)
          : await store.deletePublicSession(body.hash));
      }
      if (url.pathname === "/lazy-invites") {
        return Response.json(await createAuthStateStore(env).readInvites());
      }
      if (url.pathname === "/lazy-records") {
        return Response.json({ value: await createAuthStateStore(env).getRecords(body.uuid) });
      }
      return new Response("Not found", { status: 404 });
    } catch (error) {
      return Response.json({ error: String(error?.message || "request_failed") }, { status: 500 });
    }
  },
};
