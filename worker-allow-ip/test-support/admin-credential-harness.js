import productionWorker, { AuthRateLimiter, AuthState } from "../src/worker-entry.js";
import { __test as adminTest } from "../src/admin.js";
import { createAuthStateStore } from "../src/auth-state.js";

export { AuthRateLimiter, AuthState };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/__test__/seed" && request.method === "POST") {
      const body = await request.json();
      const store = createAuthStateStore(env);
      const current = await store.readInvites();
      const result = await store.compareAndSwapInvites(current.revision, body.invites || []);
      if (!result?.ok) return Response.json(result, { status: 409 });
      await store.createAdminSession(body.sessionHash, {
        csrf: body.csrf,
        expiresAt: Date.now() + 60 * 60 * 1000,
        totpBinding: await adminTest.adminSessionTotpBinding(
          env.ADMIN_TOTP_SECRET,
          String(env.ADMIN_TOTP_SECRET_NEXT || ""),
          String(env.ADMIN_TOTP_ROTATION_PHASE || ""),
          env.INVITE_ACCESS_HMAC_KEY,
        ),
      });
      return Response.json(await store.readInvites());
    }

    if (url.pathname === "/__test__/stored") {
      return Response.json(await createAuthStateStore(env).readInvites());
    }

    if (url.pathname === "/__test__/revealed") {
      return Response.json(await createAuthStateStore(env).readInvites({ reveal: true }));
    }

    return await productionWorker.fetch(request, env, ctx);
  },
};
