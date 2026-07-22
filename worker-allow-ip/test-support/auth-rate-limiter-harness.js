import { AuthRateLimiter } from "../src/worker-entry.js";

export { AuthRateLimiter };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const key = url.searchParams.get("key") || "default";
    const scope = url.searchParams.get("scope") || "admin";
    const stub = env.AUTH_RATE_LIMITER.getByName(key);

    if (url.pathname === "/consume") {
      return Response.json(await stub.consume(scope));
    }
    if (url.pathname === "/reset") {
      return Response.json(await stub.reset(scope));
    }
    return new Response("Not found", { status: 404 });
  },
};
