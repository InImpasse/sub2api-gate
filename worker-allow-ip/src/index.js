import { cleanupExpiredIpGroups, findInvite, getInviteApiConfigs, handleAdmin, loginInviteToSub2Api, recordVisitorIp, refreshInviteFromSub2Api } from "./admin.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};
const UUID_COOKIE_NAME = "sub2api_allow_uuid";
const UUID_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const INVITE_ATTEMPT_LIMIT = 10;
const INVITE_ATTEMPT_TTL_SECONDS = 15 * 60;
const SUB2API_FAVICON = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MSA0MSI+PHBhdGggZD0iTTM3LjUzMjQgMTYuODcwN0MzNy45ODA4IDE1LjUyNDEgMzguMTM2MyAxNC4wOTc0IDM3Ljk4ODYgMTIuNjg1OUMzNy44NDA5IDExLjI3NDQgMzcuMzkzNCA5LjkxMDc2IDM2LjY3NiA4LjY4NjIyQzM1LjYxMjYgNi44MzQwNCAzMy45ODgyIDUuMzY3NiAzMi4wMzczIDQuNDk4NUMzMC4wODY0IDMuNjI5NDEgMjcuOTA5OCAzLjQwMjU5IDI1LjgyMTUgMy44NTA3OEMyNC44Nzk2IDIuNzg5MyAyMy43MjE5IDEuOTQxMjUgMjIuNDI1NyAxLjM2MzQxQzIxLjEyOTUgMC43ODU1NzUgMTkuNzI0OSAwLjQ5MTI2OSAxOC4zMDU4IDAuNTAwMTk3QzE2LjE3MDggMC40OTUwNDQgMTQuMDg5MyAxLjE2ODAzIDEyLjM2MTQgMi40MjIxNEMxMC42MzM1IDMuNjc2MjQgOS4zNDg1MyA1LjQ0NjY2IDguNjkxNyA3LjQ3ODE1QzcuMzAwODUgNy43NjI4NiA1Ljk4Njg2IDguMzQxNCA0LjgzNzcgOS4xNzUwNUMzLjY4ODU0IDEwLjAwODcgMi43MzA3MyAxMS4wNzgyIDIuMDI4MzkgMTIuMzEyQzAuOTU2NDY0IDE0LjE1OTEgMC40OTg5MDUgMTYuMjk4OCAwLjcyMTY5OCAxOC40MjI4QzAuOTQ0NDkyIDIwLjU0NjcgMS44MzYxMiAyMi41NDQ5IDMuMjY4IDI0LjEyOTNDMi44MTk2NiAyNS40NzU5IDIuNjY0MTMgMjYuOTAyNiAyLjgxMTgyIDI4LjMxNDFDMi45NTk1MSAyOS43MjU2IDMuNDA3MDEgMzEuMDg5MiA0LjEyNDM3IDMyLjMxMzhDNS4xODc5MSAzNC4xNjU5IDYuODEyMyAzNS42MzIyIDguNzYzMjEgMzYuNTAxM0MxMC43MTQxIDM3LjM3MDQgMTIuODkwNyAzNy41OTczIDE0Ljk3ODkgMzcuMTQ5MkMxNS45MjA4IDM4LjIxMDcgMTcuMDc4NiAzOS4wNTg3IDE4LjM3NDcgMzkuNjM2NkMxOS42NzA5IDQwLjIxNDQgMjEuMDc1NSA0MC41MDg3IDIyLjQ5NDYgNDAuNDk5OEMyNC42MzA3IDQwLjUwNTQgMjYuNzEzMyAzOS44MzIxIDI4LjQ0MTggMzguNTc3MkMzMC4xNzA0IDM3LjMyMjMgMzEuNDU1NiAzNS41NTA2IDMyLjExMTkgMzMuNTE3OUMzMy41MDI3IDMzLjIzMzIgMzQuODE2NyAzMi42NTQ3IDM1Ljk2NTkgMzEuODIxQzM3LjExNSAzMC45ODc0IDM4LjA3MjggMjkuOTE3OCAzOC43NzUyIDI4LjY4NEMzOS44NDU4IDI2LjgzNzEgNDAuMzAyMyAyNC42OTc5IDQwLjA3ODkgMjIuNTc0OEMzOS44NTU2IDIwLjQ1MTcgMzguOTYzOSAxOC40NTQ0IDM3LjUzMjQgMTYuODcwN1pNMjIuNDk3OCAzNy44ODQ5QzIwLjc0NDMgMzcuODg3NCAxOS4wNDU5IDM3LjI3MzMgMTcuNjk5NCAzNi4xNTAxQzE3Ljc2MDEgMzYuMTE3IDE3Ljg2NjYgMzYuMDU4NiAxNy45MzYgMzYuMDE2MUwyNS45MDA0IDMxLjQxNTZDMjYuMTAwMyAzMS4zMDE5IDI2LjI2NjMgMzEuMTM3IDI2LjM4MTMgMzAuOTM3OEMyNi40OTY0IDMwLjczODYgMjYuNTU2MyAzMC41MTI0IDI2LjU1NDkgMzAuMjgyNVYxOS4wNTQyTDI5LjkyMTMgMjAuOTk4QzI5LjkzODkgMjEuMDA2OCAyOS45NTQxIDIxLjAxOTggMjkuOTY1NiAyMS4wMzU5QzI5Ljk3NyAyMS4wNTIgMjkuOTg0MiAyMS4wNzA3IDI5Ljk4NjcgMjEuMDkwMlYzMC4zODg5QzI5Ljk4NDIgMzIuMzc1IDI5LjE5NDYgMzQuMjc5MSAyNy43OTA5IDM1LjY4NDFDMjYuMzg3MiAzNy4wODkyIDI0LjQ4MzggMzcuODgwNiAyMi40OTc4IDM3Ljg4NDlaTTYuMzkyMjcgMzEuMDA2NEM1LjUxMzk3IDI5LjQ4ODggNS4xOTc0MiAyNy43MTA3IDUuNDk4MDQgMjUuOTgzMkM1LjU1NzE4IDI2LjAxODcgNS42NjA0OCAyNi4wODE4IDUuNzM0NjEgMjYuMTI0NEwxMy42OTkgMzAuNzI0OEMxMy44OTc1IDMwLjg0MDggMTQuMTIzMyAzMC45MDIgMTQuMzUzMiAzMC45MDJDMTQuNTgzIDMwLjkwMiAxNC44MDg4IDMwLjg0MDggMTUuMDA3MyAzMC43MjQ4TDI0LjczMSAyNS4xMTAzVjI4Ljk5NzlDMjQuNzMyMSAyOS4wMTc3IDI0LjcyODMgMjkuMDM3NiAyNC43MTk5IDI5LjA1NTZDMjQuNzExNSAyOS4wNzM2IDI0LjY5ODggMjkuMDg5MyAyNC42ODI5IDI5LjEwMTJMMTYuNjMxNyAzMy43NDk3QzE0LjkwOTYgMzQuNzQxNiAxMi44NjQzIDM1LjAwOTcgMTAuOTQ0NyAzNC40OTU0QzkuMDI1MDYgMzMuOTgxMSA3LjM4Nzg1IDMyLjcyNjMgNi4zOTIyNyAzMS4wMDY0Wk00LjI5NzA3IDEzLjYxOTRDNS4xNzE1NiAxMi4wOTk4IDYuNTUyNzkgMTAuOTM2NCA4LjE5ODg1IDEwLjMzMjdDOC4xOTg4NSAxMC40MDEzIDguMTk0OTEgMTAuNTIyOCA4LjE5NDkxIDEwLjYwNzFWMTkuODA4QzguMTkzNTEgMjAuMDM3OCA4LjI1MzM0IDIwLjI2MzggOC4zNjgyMyAyMC40NjI5QzguNDgzMTIgMjAuNjYxOSA4LjY0ODkzIDIwLjgyNjcgOC44NDg2MyAyMC45NDA0TDE4LjU3MjMgMjYuNTU0MkwxNS4yMDYgMjguNDk3OUMxNS4xODk0IDI4LjUwODkgMTUuMTcwMyAyOC41MTU1IDE1LjE1MDUgMjguNTE3M0MxNS4xMzA3IDI4LjUxOTEgMTUuMTEwNyAyOC41MTYgMTUuMDkyNCAyOC41MDgyTDcuMDQwNDYgMjMuODU1N0M1LjMyMTM1IDIyLjg2MDEgNC4wNjcxNiAyMS4yMjM1IDMuNTUyODkgMTkuMzA0NkMzLjAzODYyIDE3LjM4NTggMy4zMDYyNCAxNS4zNDEzIDQuMjk3MDcgMTMuNjE5NFpNMzEuOTU1IDIwLjA1NTZMMjIuMjMxMiAxNC40NDExTDI1LjU5NzYgMTIuNDk4MUMyNS42MTQyIDEyLjQ4NzIgMjUuNjMzMyAxMi40ODA1IDI1LjY1MzEgMTIuNDc4N0MyNS42NzI5IDEyLjQ3NjkgMjUuNjkyOCAxMi40ODAxIDI1LjcxMTEgMTIuNDg3OUwzMy43NjMxIDE3LjEzNjRDMzQuOTk2NyAxNy44NDkgMzYuMDAxNyAxOC44OTgyIDM2LjY2MDYgMjAuMTYxM0MzNy4zMTk0IDIxLjQyNDQgMzcuNjA0NyAyMi44NDkgMzcuNDgzMiAyNC4yNjg0QzM3LjM2MTcgMjUuNjg3OCAzNi44MzgyIDI3LjA0MzIgMzUuOTc0MyAyOC4xNzU5QzM1LjExMDMgMjkuMzA4NiAzMy45NDE1IDMwLjE3MTcgMzIuNjA0NyAzMC42NjQxQzMyLjYwNDcgMzAuNTk0NyAzMi42MDQ3IDMwLjQ3MzMgMzIuNjA0NyAzMC4zODg5VjIxLjE4OEMzMi42MDY2IDIwLjk1ODYgMzIuNTQ3NCAyMC43MzI4IDMyLjQzMzIgMjAuNTMzOEMzMi4zMTkgMjAuMzM0OCAzMi4xNTQgMjAuMTY5OCAzMS45NTUgMjAuMDU1NlpNMzUuMzA1NSAxNS4wMTI4QzM1LjI0NjQgMTQuOTc2NSAzNS4xNDMxIDE0LjkxNDIgMzUuMDY5IDE0Ljg3MTdMMjcuMTA0NSAxMC4yNzEyQzI2LjkwNiAxMC4xNTU0IDI2LjY4MDMgMTAuMDk0MyAyNi40NTA0IDEwLjA5NDNDMjYuMjIwNiAxMC4wOTQzIDI1Ljk5NDggMTAuMTU1NCAyNS43OTYzIDEwLjI3MTJMMTYuMDcyNiAxNS44ODU4VjExLjk5ODJDMTYuMDcxNSAxMS45NzgzIDE2LjA3NTMgMTEuOTU4NSAxNi4wODM3IDExLjk0MDVDMTYuMDkyMSAxMS45MjI1IDE2LjEwNDggMTEuOTA2OCAxNi4xMjA3IDExLjg5NDlMMjQuMTcxOSA3LjI1MDI1QzI1LjQwNTMgNi41MzkwMyAyNi44MTU4IDYuMTkzNzYgMjguMjM4MyA2LjI1NDgyQzI5LjY2MDggNi4zMTU4OSAzMS4wMzY0IDYuNzgwNzcgMzIuMjA0NCA3LjU5NTA4QzMzLjM3MjMgOC40MDkzOSAzNC4yODQyIDkuNTM5NDUgMzQuODMzNCAxMC44NTMxQzM1LjM4MjYgMTIuMTY2NyAzNS41NDY0IDEzLjYwOTUgMzUuMzA1NSAxNS4wMTI4Wk0xNC4yNDI0IDIxLjk0MTlMMTAuODc1MiAxOS45OTgxQzEwLjg1NzYgMTkuOTg5MyAxMC44NDIzIDE5Ljk3NjMgMTAuODMwOSAxOS45NjAyQzEwLjgxOTUgMTkuOTQ0MSAxMC44MTIyIDE5LjkyNTQgMTAuODA5OCAxOS45MDU4VjEwLjYwNzFDMTAuODEwNyA5LjE4Mjk1IDExLjIxNzMgNy43ODg0OCAxMS45ODE5IDYuNTg2OTZDMTIuNzQ2NiA1LjM4NTQ0IDEzLjgzNzcgNC40MjY1OSAxNS4xMjc1IDMuODIyNjRDMTYuNDE3MyAzLjIxODY5IDE3Ljg1MjQgMi45OTQ2NCAxOS4yNjQ5IDMuMTc2N0MyMC42Nzc1IDMuMzU4NzYgMjIuMDA4OSAzLjkzOTQxIDIzLjEwMzQgNC44NTA2N0MyMy4wNDI3IDQuODgzNzkgMjIuOTM3IDQuOTQyMTUgMjIuODY2OCA0Ljk4NDczTDE0LjkwMjQgOS41ODUxN0MxNC43MDI1IDkuNjk4NzggMTQuNTM2NiA5Ljg2MzU2IDE0LjQyMTUgMTAuMDYyNkMxNC4zMDY1IDEwLjI2MTYgMTQuMjQ2NiAxMC40ODc3IDE0LjI0NzkgMTAuNzE3NUwxNC4yNDI0IDIxLjk0MTlaTTE2LjA3MSAxNy45OTkxTDIwLjQwMTggMTUuNDk3OEwyNC43MzI1IDE3Ljk5NzVWMjIuOTk4NUwyMC40MDE4IDI1LjQ5ODNMMTYuMDcxIDIyLjk5ODVWMTcuOTk5MVoiIGZpbGw9IiMxMTEiLz48L3N2Zz4=";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (!isAllowedHostname(env, url.hostname)) {
        return text("Not found", 404);
      }

      if (url.pathname === "/allow-ip/admin" || url.pathname.startsWith("/allow-ip/admin/")) {
        return await handleAdmin(request, env);
      }

      const uuidSession = await getUuidSession(request, env);

      if (request.method === "GET") {
        if (url.pathname === "/allow-ip/sub2api-login") {
          if (!uuidSession) {
            return redirect("/allow-ip");
          }
          const refreshedInvite = await refreshInviteForDisplay(env, uuidSession.invite);
          return html(await renderSub2ApiAutoLogin(env, refreshedInvite || uuidSession.invite));
        }

        const refreshedInvite = uuidSession ? await refreshInviteForDisplay(env, uuidSession.invite) : null;
        const refreshedSession = uuidSession ? { ...uuidSession, invite: refreshedInvite || uuidSession.invite } : null;
        const currentStatus = refreshedSession ? await getCurrentAllowStatus(env, request) : null;
        return html(renderForm(env, url, refreshedSession, request, "", currentStatus));
      }

      if (request.method === "POST") {
        return await handleSubmit(request, env, uuidSession);
      }

      return text("Method not allowed", 405, { allow: "GET, POST" });
    } catch (error) {
      console.error(JSON.stringify({ level: "error", message: error.message }));
      return html(renderMessage("Request failed", "The server could not process this request. Please try again later."), 500);
    }
  },

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(cleanupExpiredIpGroups(env).catch((error) => {
      console.error(JSON.stringify({ level: "error", message: "ip_cleanup_failed", error: error.message }));
    }));
  },
};

async function handleSubmit(request, env, uuidSession) {
  requireEnv(env, [
    "ACCOUNT_ID",
    "IP_LIST_ID",
    "TURNSTILE_SITE_KEY",
    "TURNSTILE_SECRET_KEY",
    "CLOUDFLARE_API_TOKEN",
  ]);

  const form = await request.formData();
  const action = String(form.get("action") || "");
  if (action === "logout_uuid") {
    if (uuidSession && !(await timingSafeEqual(String(form.get("csrf") || ""), uuidSession.csrf))) {
      return html(renderMessage("Invalid request", "Refresh the page and try again."), 403);
    }
    await deleteUuidSession(env, request);
    return redirect("/allow-ip", clearUuidCookie());
  }

  const inviteKey = String(form.get("invite_key") || "").trim() || uuidSession?.invite?.uuid || "";
  if (uuidSession && !(await timingSafeEqual(String(form.get("csrf") || ""), uuidSession.csrf))) {
    return html(renderMessage("Invalid request", "Refresh the page and try again."), 403);
  }
  const turnstileToken = String(form.get("cf-turnstile-response") || "");
  const visitorIps = getVisitorIps(request);
  const attemptKey = inviteAttemptKey(request);

  if (visitorIps.length === 0) {
    return html(renderMessage("No client IP found", "Cloudflare did not provide a valid IPv4 or IPv6 address."), 400);
  }

  if (!uuidSession && env.INVITE_STORE) {
    const attempts = Number(await env.INVITE_STORE.get(attemptKey) || "0");
    if (attempts >= INVITE_ATTEMPT_LIMIT) {
      return html(renderMessage("Too many attempts", "Try again later."), 429);
    }
  }

  const turnstile = await verifyTurnstile(env.TURNSTILE_SECRET_KEY, turnstileToken, visitorIps[0].ip);
  if (!turnstile.success) {
    return html(renderMessage("Verification failed", "Refresh the page and complete the challenge again."), 403);
  }

  const invite = await findInvite(env, inviteKey);
  if (!invite) {
    if (!uuidSession && env.INVITE_STORE) {
      const attempts = Number(await env.INVITE_STORE.get(attemptKey) || "0");
      await env.INVITE_STORE.put(attemptKey, String(attempts + 1), { expirationTtl: INVITE_ATTEMPT_TTL_SECONDS });
    }
    return html(renderMessage("Invalid key", "Check that you entered an assigned UUID or access key."), 403);
  }
  if (!uuidSession && env.INVITE_STORE) {
    await env.INVITE_STORE.delete(attemptKey);
  }

  const result = await addIpsToCloudflareList(env, visitorIps, invite);
  if (!result.ok) {
    console.error(JSON.stringify({
      level: "error",
      message: "list_update_failed",
      ips: visitorIps.map((item) => item.ip),
      status: result.status,
      errors: result.errors,
      messages: result.messages,
    }));
    return html(renderMessage("Allowlist update failed", "Cloudflare could not update the allowlist. Contact the administrator."), 502);
  }

  await recordVisitorIp(env, request, invite, result);

  const createdSession = env.INVITE_STORE ? await createUuidSession(env, invite) : null;
  const addedIps = result.items.map((item) => escapeHtml(item.cidr || item.ip)).join(", ");
  return html(
    renderForm(
      env,
      new URL(request.url),
      { invite, csrf: uuidSession?.csrf || createdSession?.csrf || "" },
      request,
      `${addedIps} has been added or refreshed in the access allowlist.`,
      { ok: true, ips: result.items, error: "" },
    ),
    200,
    createdSession ? { "set-cookie": createdSession.cookie } : {},
  );
}

async function refreshInviteForDisplay(env, invite) {
  try {
    return await refreshInviteFromSub2Api(env, invite.uuid);
  } catch (error) {
    console.error(JSON.stringify({ level: "warn", message: "sub2api_refresh_failed", error: error.message }));
    return invite;
  }
}

async function verifyTurnstile(secret, token, remoteIp) {
  const body = new FormData();
  body.set("secret", secret);
  body.set("response", token);
  body.set("remoteip", remoteIp);

  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
  });

  return await response.json();
}

async function addIpsToCloudflareList(env, ips, invite) {
  const existingItems = await findCloudflareListItems(env);
  if (!existingItems.ok) {
    return {
      ok: false,
      status: existingItems.status,
      errors: existingItems.errors,
      messages: existingItems.messages,
      payload: existingItems.payload,
      items: [],
    };
  }
  const existingByIp = new Map(existingItems.items.map((item) => [item.ip, item]));
  const items = ips.map((item) => {
    const listValue = item.cidr || item.ip;
    const existing = existingByIp.get(listValue) || existingByIp.get(item.ip);
    return {
      ...item,
      listValue,
      listItemId: existing ? existing.id || "" : "",
      alreadyListed: Boolean(existing),
    };
  });
  const itemsToAdd = items.filter((item) => !item.alreadyListed);

  if (itemsToAdd.length === 0) {
    return { ok: true, status: 200, errors: [], messages: [], items };
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/rules/lists/${env.IP_LIST_ID}/items?per_page=100`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(
        itemsToAdd.map((item) => ({
          ip: item.listValue,
          comment: `sub2api uuid ${invite.uuid} raw ${item.ip} ${new Date().toISOString()}`,
        })),
      ),
    },
  );

  const payload = await response.json();
  if (!response.ok || payload.success === false) {
    const itemsAfterFailure = await findCloudflareListItems(env);
    if (!itemsAfterFailure.ok) {
      return {
        ok: false,
        status: response.status,
        errors: payload.errors || [],
        messages: payload.messages || [],
        payload,
        items,
      };
    }
    const afterByIp = new Map(itemsAfterFailure.items.map((item) => [item.ip, item]));
    const allPresent = itemsToAdd.every((item) => afterByIp.has(item.listValue));
    if (allPresent) {
      return { ok: true, status: response.status, errors: [], messages: [], items: items.map((item) => {
        const current = afterByIp.get(item.listValue) || existingByIp.get(item.listValue) || existingByIp.get(item.ip);
        return { ...item, listItemId: current ? current.id || "" : item.listItemId, alreadyListed: Boolean(existingByIp.get(item.listValue) || existingByIp.get(item.ip)) };
      }) };
    }
  }

  const resultItems = Array.isArray(payload.result) ? payload.result : [];
  const resultByIp = new Map(resultItems.map((item) => [item.ip, item]));

  return {
    ok: response.ok && payload.success !== false,
    status: response.status,
    errors: payload.errors || [],
    messages: payload.messages || [],
    payload,
    items: items.map((item) => {
      const created = resultByIp.get(item.listValue);
      return {
        ...item,
        listItemId: created ? created.id || "" : item.listItemId,
      };
    }),
  };
}

async function findCloudflareListItems(env) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/rules/lists/${env.IP_LIST_ID}/items`,
    {
      headers: {
        authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        "content-type": "application/json",
      },
    },
  );

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    return {
      ok: false,
      status: response.status,
      errors: payload.errors || [],
      messages: payload.messages || [],
      payload,
      items: [],
    };
  }

  const payload = await response.json();
  if (!Array.isArray(payload.result)) {
    return { ok: true, status: response.status, errors: [], messages: [], payload, items: [] };
  }

  return { ok: true, status: response.status, errors: [], messages: [], payload, items: payload.result };
}

async function getCurrentAllowStatus(env, request) {
  const visitorIps = getVisitorIps(request);
  if (visitorIps.length === 0) {
    return { ok: false, ips: [], error: "Cloudflare did not provide a valid client IP." };
  }

  const existingItems = await findCloudflareListItems(env);
  if (!existingItems.ok) {
    return { ok: false, ips: visitorIps, error: "Could not check the Cloudflare allowlist." };
  }

  const listed = new Set(existingItems.items.map((item) => item.ip));
  const ips = visitorIps.map((item) => ({
    ...item,
    listValue: item.cidr || item.ip,
    alreadyListed: listed.has(item.cidr || item.ip) || listed.has(item.ip),
  }));

  return {
    ok: ips.length > 0 && ips.every((item) => item.alreadyListed),
    ips,
    error: "",
  };
}

async function isValidInviteKey(input, configuredKeys) {
  if (!input || !configuredKeys) {
    return false;
  }

  const keys = configuredKeys
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean);

  for (const key of keys) {
    if (await timingSafeEqual(input, key)) {
      return true;
    }
  }

  return false;
}

async function timingSafeEqual(left, right) {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const maxLength = Math.max(leftBytes.length, rightBytes.length);
  let diff = leftBytes.length ^ rightBytes.length;

  for (let index = 0; index < maxLength; index += 1) {
    diff |= (leftBytes[index] || 0) ^ (rightBytes[index] || 0);
  }

  return diff === 0;
}

function renderForm(env, url, uuidSession, request, notice = "", currentStatus = null) {
  const invite = uuidSession?.invite || null;
  if (invite) {
    return renderDashboard(env, url, invite, request, notice, currentStatus, uuidSession.csrf || "");
  }

  return page("Join the Allowlist", `
    <section class="hero">
      ${sub2apiIcon()}
      <p class="eyebrow">Sub2API Access</p>
      <h1>Join the allowlist</h1>
      <p class="lede">Verify your key, then add the current client IP address to the Cloudflare allowlist.</p>
    </section>
    <form class="panel" method="post" action="${escapeHtml(url.pathname)}">
      <label for="invite_key">Access key or UUID</label>
      <div class="secret-field">
        <input id="invite_key" name="invite_key" type="password" autocomplete="one-time-code" required autofocus />
        <button class="ghost toggle-secret" type="button" aria-controls="invite_key" aria-pressed="false">Show</button>
      </div>
      <div
        class="cf-turnstile"
        data-sitekey="${escapeHtml(env.TURNSTILE_SITE_KEY || "")}"
        data-callback="onTurnstileSuccess"
        data-expired-callback="onTurnstileReset"
        data-error-callback="onTurnstileReset"
      ></div>
      <button id="submit-button" type="submit" disabled>Add current IP</button>
    </form>
    <script>
      const toggle = document.querySelector(".toggle-secret");
      const input = document.getElementById("invite_key");
      const submitButton = document.getElementById("submit-button");
      window.onTurnstileSuccess = () => {
        submitButton.disabled = false;
      };
      window.onTurnstileReset = () => {
        submitButton.disabled = true;
      };
      toggle.addEventListener("click", () => {
        const shouldShow = input.type === "password";
        input.type = shouldShow ? "text" : "password";
        toggle.textContent = shouldShow ? "Hide" : "Show";
        toggle.setAttribute("aria-pressed", String(shouldShow));
      });
    </script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  `);
}

function renderDashboard(env, url, invite, request, notice = "", currentStatus = null, csrf = "") {
  const configs = getInviteApiConfigs(invite, env, request);
  const statusText = renderCurrentIpStatus(currentStatus);
  const shouldShowAddIp = !currentStatus || (!currentStatus.ok && !currentStatus.error);
  return page("Sub2API Access", `
    <section class="hero">
      ${sub2apiIcon()}
      <p class="eyebrow">Sub2API Access</p>
      <h1>${escapeHtml(invite.name || "Signed in")}</h1>
      <p class="lede">UUID ${escapeHtml(invite.uuid)} is signed in on this browser.</p>
    </section>
    <section class="panel dashboard">
      ${notice ? `<p class="success">${notice}</p>` : ""}
      ${statusText}
      ${shouldShowAddIp ? `<form method="post" action="${escapeHtml(url.pathname)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
        <div
          class="cf-turnstile"
          data-sitekey="${escapeHtml(env.TURNSTILE_SITE_KEY || "")}"
          data-callback="onTurnstileSuccess"
          data-expired-callback="onTurnstileReset"
          data-error-callback="onTurnstileReset"
        ></div>
        <button id="submit-button" type="submit" disabled>Add current IP</button>
      </form>` : ""}
      <div class="api-list">
        ${renderSub2ApiLogin(invite)}
        ${configs.length ? configs.map(renderApiConfig).join("") : `<p class="lede">No OpenAI API link has been configured for this UUID.</p>`}
      </div>
      <form method="post" action="${escapeHtml(url.pathname)}">
        <input type="hidden" name="action" value="logout_uuid" />
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
        <button class="ghost-wide" type="submit">Log out</button>
      </form>
    </section>
    <script>
      const submitButton = document.getElementById("submit-button");
      window.onTurnstileSuccess = () => {
        if (submitButton) submitButton.disabled = false;
      };
      window.onTurnstileReset = () => {
        if (submitButton) submitButton.disabled = true;
      };
      document.querySelectorAll(".copy-value").forEach((button) => {
        button.addEventListener("click", async () => {
          await navigator.clipboard.writeText(button.dataset.copy);
          button.textContent = "Copied";
          window.setTimeout(() => {
            button.textContent = "Copy";
          }, 1400);
        });
      });
      document.querySelectorAll(".toggle-dashboard-secret").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest(".api-card");
          const input = button.closest(".secret-copy-line")?.querySelector(".copy-secret");
          if (!input) return;
          const shouldShow = input.type === "password";
          input.type = shouldShow ? "text" : "password";
          button.textContent = shouldShow ? "Hide" : "Show";
          button.setAttribute("aria-pressed", String(shouldShow));
          card?.querySelectorAll(".secret-format").forEach((code) => {
            code.textContent = shouldShow ? code.dataset.fullValue : code.dataset.maskedValue;
          });
        });
      });
    </script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  `);
}

function renderCurrentIpStatus(status) {
  if (!status) {
    return "";
  }
  if (status.error) {
    return `<p class="warning">${escapeHtml(status.error)}</p>`;
  }

  const values = status.ips.map((item) => `${item.ip} (${item.cidr || item.ip})`).join(", ");
  if (status.ok) {
    return `<p class="success">Current IP already added: ${escapeHtml(values)}</p>`;
  }

  return `<p class="warning">Current IP not added yet: ${escapeHtml(values)}</p>`;
}

function renderApiConfig(config) {
  const key = config.apiKey || "";
  const curl = `curl ${config.baseUrl}/chat/completions -H "Authorization: Bearer ${key}"`;
  const maskedCurl = `curl ${config.baseUrl}/chat/completions -H "Authorization: Bearer ${maskSecret(key)}"`;
  return `
    <div class="api-card">
      <strong>${escapeHtml(displayApiName(config.name))}</strong>
      <label>Base URL</label>
      <div class="copy-line"><code>${escapeHtml(config.baseUrl)}</code><button class="ghost compact copy-value" type="button" data-copy="${escapeHtml(config.baseUrl)}">Copy</button></div>
      <label>API key</label>
      <div class="secret-copy-line">
        <input class="copy-secret" type="password" value="${escapeHtml(key || "Not configured")}" readonly autocomplete="off" spellcheck="false" aria-label="API key" />
        <button class="ghost compact toggle-dashboard-secret" type="button" aria-pressed="false">Show</button>
        <button class="ghost compact copy-value" type="button" data-copy="${escapeHtml(key)}"${key ? "" : " disabled"}>Copy</button>
      </div>
      <label>OpenAI format</label>
      <div class="copy-line"><code class="secret-format" data-masked-value="${escapeHtml(maskedCurl)}" data-full-value="${escapeHtml(curl)}">${escapeHtml(maskedCurl)}</code><button class="ghost compact copy-value" type="button" data-copy="${escapeHtml(curl)}">Copy</button></div>
    </div>
  `;
}

function displayApiName(name) {
  const value = String(name || "").trim();
  return normalizeApiName(value) === "sub2api" ? "Sub2API" : value || "Sub2API";
}

function normalizeApiName(name) {
  return String(name || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function renderSub2ApiLogin(invite) {
  const sync = invite.sub2apiSync || {};
  const loginUrl = sync.loginUrl || "https://api.example.com";
  const hasLogin = Boolean(sync.username && sync.loginPassword);
  if (!sync.username) {
    return "";
  }

  return `
    <div class="api-card">
      <strong>Sub2API account</strong>
      <p class="lede">Use the button below to open Sub2API. Manual username and password sign-in is not available from this page.</p>
      ${hasLogin
        ? `<a class="ghost-wide" href="/allow-ip/sub2api-login">Open Sub2API</a>`
        : `<p class="warning">Sub2API login is not ready for this UUID. Contact the administrator to refresh this account.</p>`}
      <div class="copy-line"><code>${escapeHtml(loginUrl)}</code><button class="ghost compact copy-value" type="button" data-copy="${escapeHtml(loginUrl)}">Copy URL</button></div>
    </div>
  `;
}

async function renderSub2ApiAutoLogin(env, invite) {
  const sync = invite.sub2apiSync || {};
  const username = sync.username || "";
  const email = sync.email || (username ? `${username}@sub2api.local` : "");
  const password = sync.loginPassword || "";
  const loginUrl = sync.loginUrl || "https://api.example.com";
  if (!email || !password) {
    return renderMessage("Sub2API login unavailable", "This UUID is not ready for direct Sub2API login. Contact the administrator to refresh this account.");
  }
  let auth;
  try {
    const result = await loginInviteToSub2Api(env, invite);
    auth = result.auth || {};
  } catch (error) {
    return renderMessage("Sub2API login unavailable", "Automatic login failed. Contact the administrator to refresh this account.");
  }
  if (!auth.access_token) {
    return renderMessage("Sub2API login unavailable", "Automatic login failed. Contact the administrator to refresh this account.");
  }

  return page("Signing in", `
    <section class="message">
      <h1>Signing in</h1>
      <p id="login-status">Opening Sub2API...</p>
      <a id="manual-login" href="${escapeHtml(loginUrl)}">Open Sub2API</a>
    </section>
    <script>
      (async () => {
        const status = document.getElementById("login-status");
        const fallback = document.getElementById("manual-login");
        try {
          localStorage.setItem("auth_token", ${jsString(auth.access_token)});
          ${auth.refresh_token ? `localStorage.setItem("refresh_token", ${jsString(auth.refresh_token)});` : `localStorage.removeItem("refresh_token");`}
          ${auth.expires_in ? `localStorage.setItem("token_expires_at", String(Date.now() + ${Number(auth.expires_in)} * 1000));` : `localStorage.removeItem("token_expires_at");`}
          ${auth.user ? `localStorage.setItem("auth_user", ${jsString(JSON.stringify(auth.user))});` : `localStorage.removeItem("auth_user");`}
          window.location.replace(${jsString(loginUrl)});
        } catch (error) {
          status.textContent = "Automatic login failed. Contact the administrator to refresh this account.";
          fallback.textContent = "Open Sub2API";
        }
      })();
    </script>
  `);
}

function renderMessage(title, message) {
  return page(title, `
    <section class="message">
      <h1>${escapeHtml(title)}</h1>
      <p>${message}</p>
      <a href="/allow-ip">Back</a>
    </section>
  `);
}

function sub2apiIcon() {
  return `
    <span class="sub2api-icon" aria-hidden="true">
      <img src="${SUB2API_FAVICON}" alt="" />
    </span>
  `;
}

async function getUuidSession(request, env) {
  if (!env.INVITE_STORE) {
    return null;
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[UUID_COOKIE_NAME];
  if (!token) {
    return null;
  }

  const raw = await env.INVITE_STORE.get(uuidSessionKey(await sha256Hex(token)));
  const session = parseJson(raw, null);
  if (!session || !session.uuid || !session.csrf || session.expiresAt < Date.now()) {
    return null;
  }

  const invite = await findInvite(env, session.uuid);
  if (!invite) {
    return null;
  }

  return { invite, csrf: session.csrf, expiresAt: session.expiresAt };
}

async function createUuidSession(env, invite) {
  const token = randomHex(32);
  const csrf = randomHex(24);
  const expiresAt = Date.now() + UUID_SESSION_TTL_SECONDS * 1000;
  await env.INVITE_STORE.put(
    uuidSessionKey(await sha256Hex(token)),
    JSON.stringify({ uuid: invite.uuid, csrf, expiresAt }),
    { expirationTtl: UUID_SESSION_TTL_SECONDS },
  );

  const cookie = [
    `${UUID_COOKIE_NAME}=${token}`,
    "Path=/allow-ip",
    `Max-Age=${UUID_SESSION_TTL_SECONDS}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ].join("; ");
  return { cookie, csrf };
}

async function deleteUuidSession(env, request) {
  if (!env.INVITE_STORE) {
    return;
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[UUID_COOKIE_NAME];
  if (token) {
    await env.INVITE_STORE.delete(uuidSessionKey(await sha256Hex(token)));
  }
}

function clearUuidCookie() {
  return `${UUID_COOKIE_NAME}=; Path=/allow-ip; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

function uuidSessionKey(hash) {
  return `uuid-session:${hash}`;
}

function inviteAttemptKey(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return `invite-attempt:${ip}`;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseCookies(header) {
  const cookies = {};
  for (const part of header.split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name) {
      cookies[name] = value.join("=");
    }
  }
  return cookies;
}

function parseJson(value, fallback) {
  if (!value) {
    return fallback;
  }

  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <link rel="icon" href="${SUB2API_FAVICON}" />
  <style>
    :root {
      color-scheme: light dark;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f5f7;
      color: #1d1d1f;
    }
    * {
      box-sizing: border-box;
    }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px 16px;
      background:
        radial-gradient(circle at 50% -20%, rgba(255, 255, 255, 0.95), transparent 42%),
        linear-gradient(180deg, #fbfbfd 0%, #f5f5f7 100%);
    }
    main {
      width: min(100%, 520px);
    }
    .hero, form, .message {
      display: grid;
      gap: 18px;
    }
    .dashboard {
      display: grid;
      gap: 18px;
    }
    .hero {
      margin-bottom: 28px;
      text-align: center;
    }
    .sub2api-icon {
      width: 64px;
      height: 64px;
      margin: 0 auto 2px;
      border-radius: 18px;
      display: inline-grid;
      place-items: center;
      overflow: hidden;
      background: transparent;
      box-shadow: 0 18px 42px rgba(0, 0, 0, 0.16);
    }
    .sub2api-icon img {
      width: 100%;
      height: 100%;
      display: block;
    }
    .eyebrow {
      color: #6e6e73;
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0;
    }
    .lede {
      color: #6e6e73;
      font-size: 17px;
    }
    .panel, .message {
      padding: 18px;
      border: 1px solid rgba(0, 0, 0, 0.08);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.76);
      box-shadow: 0 22px 70px rgba(0, 0, 0, 0.08);
      backdrop-filter: saturate(180%) blur(18px);
    }
    label {
      color: #1d1d1f;
      font-size: 13px;
      font-weight: 700;
    }
    .secret-field {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      height: 42px;
      border: 1px solid #d2d2d7;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.92);
      transition: border-color 160ms ease, box-shadow 160ms ease;
    }
    .secret-field:focus-within {
      border-color: #0071e3;
      box-shadow: 0 0 0 4px rgba(0, 113, 227, 0.18);
    }
    input {
      width: 100%;
      height: 40px;
      border: 0;
      border-radius: 8px;
      padding: 0 10px;
      font-size: 13px;
      font: inherit;
      background: transparent;
      color: #1d1d1f;
      outline: 0;
    }
    button, a {
      min-height: 40px;
      border: 0;
      border-radius: 8px;
      display: inline-grid;
      place-items: center;
      padding: 0 16px;
      background: #0071e3;
      color: #fff;
      font: inherit;
      font-weight: 750;
      text-decoration: none;
      cursor: pointer;
      transition: transform 160ms ease, background 160ms ease, box-shadow 160ms ease;
    }
    button:hover, a:hover {
      background: #0077ed;
      box-shadow: 0 12px 30px rgba(0, 113, 227, 0.22);
      transform: translateY(-1px);
    }
    button:active, a:active {
      transform: translateY(0);
    }
    button.ghost {
      min-height: 30px;
      margin-right: 8px;
      padding: 0 12px;
      border-radius: 8px;
      background: transparent;
      color: #0071e3;
      box-shadow: none;
      font-size: 14px;
    }
    button.ghost:hover {
      background: rgba(0, 113, 227, 0.09);
      box-shadow: none;
    }
    button.ghost-wide {
      width: 100%;
      background: rgba(29, 29, 31, 0.08);
      color: #1d1d1f;
      box-shadow: none;
    }
    button.ghost-wide:hover {
      background: rgba(29, 29, 31, 0.13);
      box-shadow: none;
    }
    .copy-line a {
      min-height: 0;
      padding: 0;
      background: transparent;
      color: #0071e3;
      box-shadow: none;
      display: inline;
      justify-self: start;
    }
    .copy-line a:hover {
      background: transparent;
      box-shadow: none;
      transform: none;
      text-decoration: underline;
    }
    .inline-form {
      display: block;
      margin-top: 4px;
    }
    button.compact {
      min-height: 30px;
      border-radius: 8px;
      padding: 0 12px;
      font-size: 13px;
    }
    button:disabled {
      background: #d2d2d7;
      color: #86868b;
      box-shadow: none;
      cursor: not-allowed;
      transform: none;
    }
    button:disabled:hover {
      background: #d2d2d7;
      box-shadow: none;
      transform: none;
    }
    h1 {
      margin: 0;
      font-size: 44px;
      font-weight: 800;
      line-height: 1.08;
    }
    p {
      margin: 0;
      line-height: 1.6;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .success {
      color: #087443;
      font-weight: 750;
    }
    .warning {
      color: #a15c00;
      font-weight: 750;
    }
    .api-list, .api-card {
      display: grid;
      gap: 12px;
    }
    .api-card {
      padding: 14px;
      border: 1px solid rgba(110, 110, 115, 0.18);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.54);
    }
    .api-card label {
      color: #6e6e73;
      font-size: 12px;
    }
    .copy-line {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .secret-copy-line {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .copy-secret {
      height: 32px;
      border: 1px solid #d2d2d7;
      background: rgba(255, 255, 255, 0.76);
    }
    .cf-turnstile {
      min-height: 65px;
    }
    @media (max-width: 560px) {
      h1 {
        font-size: 34px;
      }
      .panel, .message {
        padding: 22px;
        border-radius: 8px;
      }
      .copy-line, .secret-copy-line {
        grid-template-columns: minmax(0, 1fr);
      }
    }
    @media (prefers-color-scheme: dark) {
      :root {
        background: #000;
        color: #f5f5f7;
      }
      body {
        background:
          radial-gradient(circle at 50% -20%, rgba(70, 70, 74, 0.55), transparent 45%),
          linear-gradient(180deg, #161617 0%, #000 100%);
      }
      .panel, .message {
        border-color: rgba(255, 255, 255, 0.14);
        background: rgba(29, 29, 31, 0.74);
      }
      label, input {
        color: #f5f5f7;
      }
      .secret-field {
        border-color: rgba(255, 255, 255, 0.22);
        background: rgba(255, 255, 255, 0.08);
      }
      .copy-secret {
        border-color: rgba(255, 255, 255, 0.22);
        background: rgba(255, 255, 255, 0.08);
      }
      button.ghost-wide {
        background: rgba(255, 255, 255, 0.12);
        color: #f5f5f7;
      }
      button.ghost-wide:hover {
        background: rgba(255, 255, 255, 0.18);
      }
      .success { color: #7ee2a8; }
      .warning { color: #ffd28a; }
      .api-card {
        border-color: rgba(255, 255, 255, 0.14);
        background: rgba(255, 255, 255, 0.06);
      }
    }
  </style>
</head>
<body>
  <main>${body}</main>
</body>
</html>`;
}

function html(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "content-security-policy": "default-src 'none'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'unsafe-inline'; img-src 'self' data:; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
      ...extraHeaders,
    },
  });
}

function redirect(location, cookie = "") {
  const headers = new Headers({
    location,
    "cache-control": "no-store",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  if (cookie) {
    headers.set("set-cookie", cookie);
  }
  return new Response(null, { status: 303, headers });
}

function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      ...headers,
    },
  });
}

function requireEnv(env, names) {
  const missing = names.filter((name) => !env[name] || String(env[name]).startsWith("replace-with-"));
  if (missing.length > 0) {
    throw new Error(`Missing environment variables: ${missing.join(", ")}`);
  }
}

function getVisitorIps(request) {
  const pseudoIpv4 = request.headers.get("CF-Pseudo-IPv4") || "";
  const candidates = [
    request.headers.get("CF-Connecting-IP") || "",
    request.headers.get("CF-Connecting-IPv6") || "",
  ];
  const seen = new Set();
  const ips = [];

  for (const value of candidates) {
    const ip = value.trim();
    if (!ip || seen.has(ip) || ip === pseudoIpv4 || isPseudoIPv4(ip)) {
      continue;
    }

    const version = getIpVersion(ip);
    if (!version) {
      continue;
    }

    seen.add(ip);
    ips.push({
      ip,
      version,
      cidr: version === "IPv4" ? ipv4Cidr24(ip) : `${ip}/128`,
    });
  }

  return ips;
}

function ipv4Cidr24(ip) {
  const parts = ip.split(".");
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function getIpVersion(value) {
  if (isIPv4(value)) {
    return "IPv4";
  }
  if (isIPv6(value)) {
    return "IPv6";
  }
  return "";
}

function isAllowedHostname(env, hostname) {
  const allowed = String(env.ALLOWED_HOSTNAMES || env.ALLOWED_HOSTNAME || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  return allowed.length === 0 || allowed.includes(hostname);
}

function isIPv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === part.replace(/^0+(?=\d)/, "");
  });
}

function isPseudoIPv4(value) {
  const firstOctet = Number(value.split(".")[0]);
  return Number.isInteger(firstOctet) && firstOctet >= 240 && firstOctet <= 255;
}

function isIPv6(value) {
  return value.includes(":") && /^[0-9a-f:.]+$/i.test(value);
}

function maskSecret(value) {
  if (!value) {
    return "Not configured";
  }

  const text = String(value);
  if (text.startsWith("sk-")) {
    return "sk-********";
  }

  return "********";
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function jsString(value) {
  return JSON.stringify(String(value || ""));
}
