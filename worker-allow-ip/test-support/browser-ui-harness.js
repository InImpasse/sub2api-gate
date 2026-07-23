import productionWorker, { AuthRateLimiter, AuthState } from "../src/worker-entry.js";
import { __test as adminTest } from "../src/admin.js";
import { createAuthStateStore } from "../src/auth-state.js";

export { AuthRateLimiter, AuthState };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/__test__/health") {
      return Response.json({ ok: true });
    }

    if (url.pathname === "/__test__/seed" && request.method === "POST") {
      const body = await request.json();
      const store = createAuthStateStore(env);
      const current = await store.readInvites();
      const replaced = await store.compareAndSwapInvites(current.revision, body.invites || []);
      if (!replaced?.ok) return Response.json(replaced, { status: 409 });

      await store.createAdminSession(body.adminSessionHash, {
        csrf: body.csrf,
        expiresAt: Date.now() + 60 * 60 * 1000,
        totpBinding: await adminTest.adminSessionTotpBinding(
          env.ADMIN_TOTP_SECRET,
          String(env.ADMIN_TOTP_SECRET_NEXT || ""),
          String(env.ADMIN_TOTP_ROTATION_PHASE || ""),
          env.INVITE_ACCESS_HMAC_KEY,
        ),
      });
      await store.createPublicSession(body.publicSessionHash, {
        uuid: body.publicUuid,
        csrf: body.csrf,
        expiresAt: Date.now() + 60 * 60 * 1000,
        authenticationMethod: "access_key",
        accessCredentialVersion: 1,
      });
      await store.putRecords(body.publicUuid, body.records || []);
      return Response.json({ ok: true, inviteCount: body.invites?.length || 0 });
    }

    return await productionWorker.fetch(request, env, ctx);
  },
};
