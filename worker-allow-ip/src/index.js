import { authorizeVisitorIps, cleanupExpiredIpGroups, findInvite, getInviteApiConfigs, getInviteByUuid, getInviteIpRecords, handleAdmin, loginInviteToSub2Api, sanitizeInviteForPublic } from "./admin.js";
import { createAuthStateStore, isAuthStateBindingConfigured } from "./auth-state.js";
import {
  rateLimitFingerprint,
  timingSafeTextEqual as timingSafeEqual,
} from "./credential-security.js";
import { fetchWithTimeout, isRequestBodyTooLarge, parseBoundedFormData, readJsonWithLimit } from "./request-security.js";
import { consumeAuthAttempt, resetAuthAttempts } from "./auth-rate-limiter.js";
import { parseApprovedHostnames } from "./url-security.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};
const UUID_COOKIE_NAME = "sub2api_allow_uuid";
const UUID_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
export const TURNSTILE_TIMEOUT_MS = 5000;
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
          return html(await renderSub2ApiAutoLogin(env, uuidSession.invite, url));
        }

        const refreshedSession = uuidSession;
        const currentStatus = refreshedSession ? await getCurrentAllowStatus(env, request, refreshedSession.invite) : null;
        return html(renderForm(env, url, refreshedSession, request, "", currentStatus));
      }

      if (request.method === "POST") {
        return await handleSubmit(request, env, uuidSession);
      }

      return text("Method not allowed", 405, { allow: "GET, POST" });
    } catch (error) {
      if (isRequestBodyTooLarge(error)) {
        return html(renderMessage("Request too large", "Form submissions are limited to 32 KiB."), 413);
      }
      console.error(JSON.stringify({ level: "error", message: "public_request_failed" }));
      return html(renderMessage("Request failed", "The server could not process this request. Please try again later."), 500);
    }
  },

  async scheduled(_event, env, ctx) {
    const authState = createAuthStateStore(env);
    ctx.waitUntil(Promise.all([
      cleanupExpiredIpGroups(env).catch(() => {
        console.error(JSON.stringify({ level: "error", message: "ip_cleanup_failed" }));
      }),
      authState.purgeExpiredSessions().catch(() => {
        console.error(JSON.stringify({ level: "error", message: "auth_session_cleanup_failed" }));
      }),
    ]));
  },
};

async function handleSubmit(request, env, uuidSession) {
  const form = await parseBoundedFormData(request);
  requireEnv({
    ACCOUNT_ID: env.ACCOUNT_ID,
    IP_LIST_ID: env.IP_LIST_ID,
    TURNSTILE_SITE_KEY: env.TURNSTILE_SITE_KEY,
    TURNSTILE_SECRET_KEY: env.TURNSTILE_SECRET_KEY,
    CLOUDFLARE_API_TOKEN: env.CLOUDFLARE_API_TOKEN,
    INVITE_ACCESS_HMAC_KEY: env.INVITE_ACCESS_HMAC_KEY,
  });

  const action = String(form.get("action") || "");
  if (action === "logout_uuid") {
    if (uuidSession && !(await timingSafeEqual(String(form.get("csrf") || ""), uuidSession.csrf))) {
      return html(renderMessage("Invalid request", "Refresh the page and try again."), 403);
    }
    await deleteUuidSession(env, request);
    return redirect("/allow-ip", clearUuidCookie());
  }

  const inviteKey = String(form.get("invite_key") || "").trim();
  if (uuidSession && !(await timingSafeEqual(String(form.get("csrf") || ""), uuidSession.csrf))) {
    return html(renderMessage("Invalid request", "Refresh the page and try again."), 403);
  }
  const turnstileToken = String(form.get("cf-turnstile-response") || "");
  const visitorIps = getVisitorIps(request);
  const attemptKey = await inviteAttemptKey(request, env);

  if (visitorIps.length === 0) {
    return html(renderMessage("No client IP found", "Cloudflare did not provide a valid IPv4 or IPv6 address."), 400);
  }

  const turnstile = await verifyTurnstile(
    env.TURNSTILE_SECRET_KEY,
    turnstileToken,
    visitorIps[0].ip,
    new URL(request.url).hostname,
  );
  if (!turnstile.success) {
    return html(renderMessage("Verification failed", "Refresh the page and complete the challenge again."), 403);
  }

  if (!uuidSession) {
    if (!(await consumeAuthAttempt(env, "invite", attemptKey))) {
      return html(renderMessage("Too many attempts", "Try again later."), 429);
    }
  }

  const invite = uuidSession?.invite || await findInvite(env, inviteKey);
  if (!invite) {
    return html(renderMessage("Invalid key", "Check that you entered an active access key or an eligible legacy UUID."), 403);
  }
  if (!uuidSession) {
    await resetAuthAttempts(env, "invite", attemptKey);
  }

  const result = await authorizeVisitorIps(env, request, invite, visitorIps);
  if (!result.ok) {
    console.error(JSON.stringify({ level: "error", message: "list_update_failed", status: result.status }));
    if (result.errors?.some((error) => error?.code === "ip_records_busy")) {
      return html(renderMessage("Update already in progress", "Another allowlist update is in progress. Try again shortly."), 409);
    }
    return html(renderMessage("Allowlist update failed", "Cloudflare could not update the allowlist. Contact the administrator."), 502);
  }

  const authenticationMethod = await timingSafeEqual(inviteKey, invite.uuid) ? "legacy_uuid" : "access_key";
  const createdSession = (isAuthStateBindingConfigured(env) || env.INVITE_STORE) && !uuidSession
    ? await createUuidSession(env, invite, authenticationMethod)
    : null;
  const addedIps = result.items.map((item) => escapeHtml(item.cidr || item.ip)).join(", ");
  return html(
    renderForm(
      env,
      new URL(request.url),
      { invite, csrf: uuidSession?.csrf || createdSession?.csrf || "" },
      request,
      `${addedIps} has been added or refreshed. IPv4 access authorizes the entire /24 network.`,
      { ok: true, ips: result.items, error: "" },
    ),
    200,
    createdSession ? { "set-cookie": createdSession.cookie } : {},
  );
}


export async function verifyTurnstile(secret, token, remoteIp, expectedHostname) {
  const body = new FormData();
  body.set("secret", secret);
  body.set("response", token);
  body.set("remoteip", remoteIp);

  const response = await fetchWithTimeout("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
    redirect: "manual",
  }, TURNSTILE_TIMEOUT_MS);

  if (!response.ok) return { success: false };
  const result = await readJsonWithLimit(response, 8 * 1024);
  const hostname = String(result?.hostname || "").toLowerCase();
  return {
    ...result,
    success: result?.success === true
      && hostname === String(expectedHostname || "").toLowerCase(),
  };
}

export async function getCurrentAllowStatus(env, request, invite) {
  const visitorIps = getVisitorIps(request);
  if (visitorIps.length === 0) {
    return { ok: false, ips: [], error: "Cloudflare did not provide a valid client IP." };
  }

  const groups = await getInviteIpRecords(env, invite.uuid);
  const listed = new Set(groups.flatMap((group) =>
    (group.ips || []).flatMap((item) =>
      [item.listValue, item.cidr, item.ip].filter(Boolean)
    )
  ));
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

function renderForm(env, url, uuidSession, request, notice = "", currentStatus = null) {
  const invite = uuidSession?.invite || null;
  if (invite) {
    return renderDashboard(env, url, invite, request, notice, currentStatus, uuidSession.csrf || "");
  }

  return page("Join the Allowlist", (nonce) => `
    <section class="hero">
      ${sub2apiIcon()}
      <p class="eyebrow">Sub2API Access</p>
      <h1>Join the allowlist</h1>
      <p class="lede">Verify your key, then authorize the current network. IPv4 authorizes the entire /24 network; IPv6 authorizes one /128 address.</p>
    </section>
    <form class="panel" method="post" action="${escapeHtml(url.pathname)}">
      <label for="invite_key">Access key or legacy UUID</label>
      <div class="secret-field">
        <input id="invite_key" name="invite_key" type="password" autocomplete="one-time-code" required autofocus />
        <button class="ghost toggle-secret" type="button" aria-controls="invite_key" aria-pressed="false">Show</button>
      </div>
      <div id="turnstile-widget" class="turnstile-widget"></div>
      <button id="submit-button" type="submit" disabled>Authorize current network</button>
      <p class="hint">UUID sign-in is temporary migration compatibility; use the one-time access key for ongoing access.</p>
    </form>
    <script nonce="${nonce}">
      const toggle = document.querySelector(".toggle-secret");
      const input = document.getElementById("invite_key");
      const submitButton = document.getElementById("submit-button");
      ${turnstileInitializer(env.TURNSTILE_SITE_KEY)}
      toggle.addEventListener("click", () => {
        const shouldShow = input.type === "password";
        input.type = shouldShow ? "text" : "password";
        toggle.textContent = shouldShow ? "Hide" : "Show";
        toggle.setAttribute("aria-pressed", String(shouldShow));
      });
    </script>
    ${turnstileClientScript(nonce)}
  `);
}

function renderDashboard(env, url, invite, request, notice = "", currentStatus = null, csrf = "") {
  const configs = getInviteApiConfigs(invite, env, request);
  const statusText = renderCurrentIpStatus(currentStatus);
  const shouldShowAddIp = !currentStatus || (!currentStatus.ok && !currentStatus.error);
  return page("Sub2API Access", (nonce) => `
    <section class="hero">
      ${sub2apiIcon()}
      <p class="eyebrow">Sub2API Access</p>
      <h1 class="identity-title">${escapeHtml(invite.name || "Signed in")}</h1>
      <p class="lede">UUID ${escapeHtml(invite.uuid)} is signed in on this browser.</p>
    </section>
    <section class="panel dashboard">
      ${notice ? `<p class="success">${notice}</p>` : ""}
      ${statusText}
      ${shouldShowAddIp ? `<form method="post" action="${escapeHtml(url.pathname)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
        <div id="turnstile-widget" class="turnstile-widget"></div>
        <button id="submit-button" type="submit" disabled>Authorize current network</button>
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
    <script nonce="${nonce}">
      const submitButton = document.getElementById("submit-button");
      ${shouldShowAddIp ? turnstileInitializer(env.TURNSTILE_SITE_KEY) : ""}
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
    ${shouldShowAddIp ? turnstileClientScript(nonce) : ""}
  `);
}

function turnstileInitializer(siteKey) {
  return `window.onTurnstileLoad = () => {
    if (!submitButton || !window.turnstile) return;
    window.turnstile.render("#turnstile-widget", {
      sitekey: ${jsString(siteKey || "")},
      size: window.innerWidth < 372 ? "compact" : "flexible",
      callback: () => {
        submitButton.disabled = false;
      },
      "expired-callback": () => {
        submitButton.disabled = true;
      },
      "error-callback": () => {
        submitButton.disabled = true;
      },
    });
  };`;
}

function turnstileClientScript(nonce) {
  return `<script nonce="${nonce}" src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&amp;onload=onTurnstileLoad" defer></script>`;
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
    return `<p class="success">Current network authorization is active: ${escapeHtml(values)}</p>`;
  }

  return `<p class="warning">Current network is not authorized yet: ${escapeHtml(values)}. IPv4 uses the full /24 network.</p>`;
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
  const loginUrl = sync.loginUrl || "";
  const hasLogin = Boolean(sync.username && sync.loginPassword && loginUrl);
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
      ${loginUrl ? `<div class="copy-line"><code>${escapeHtml(loginUrl)}</code><button class="ghost compact copy-value" type="button" data-copy="${escapeHtml(loginUrl)}">Copy URL</button></div>` : ""}
    </div>
  `;
}

async function renderSub2ApiAutoLogin(env, invite, requestUrl) {
  const sync = invite.sub2apiSync || {};
  const username = sync.username || "";
  const email = sync.email || (username ? `${username}@sub2api.local` : "");
  const password = sync.loginPassword || "";
  const loginUrl = sync.loginUrl || "";
  if (!email || !password || !loginUrl || !hasSameOrigin(loginUrl, requestUrl)) {
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

  return page("Signing in", (nonce) => `
    <section class="message">
      <h1>Signing in</h1>
      <p id="login-status">Opening Sub2API...</p>
      <a id="manual-login" href="${escapeHtml(loginUrl)}">Open Sub2API</a>
    </section>
    <script nonce="${nonce}">
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

function hasSameOrigin(candidate, expected) {
  try {
    return new URL(candidate).origin === new URL(expected).origin;
  } catch {
    return false;
  }
}

function renderMessage(title, message) {
  return page(title, `
    <section class="message">
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
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
  if (!isAuthStateBindingConfigured(env) && !env.INVITE_STORE) {
    return null;
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[UUID_COOKIE_NAME];
  if (!token) {
    return null;
  }

  const sessionHash = await sha256Hex(token);
  if (isAuthStateBindingConfigured(env)) {
    const result = await createAuthStateStore(env).getPublicSession(
      sessionHash,
      { reveal: true },
    );
    if (!result) return null;
    return {
      invite: sanitizeInviteForPublic(env, result.invite),
      csrf: result.session.csrf,
      expiresAt: result.session.expiresAt,
    };
  }

  const raw = await env.INVITE_STORE.get(uuidSessionKey(sessionHash));
  const session = parseJson(raw, null);
  const expiresAt = Number(session?.expiresAt);
  if (!session || !session.uuid || !session.csrf || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    return null;
  }

  const invite = await getInviteByUuid(env, session.uuid);
  if (!invite) {
    return null;
  }

  const sessionVersion = Number(session.accessCredentialVersion || 0);
  const inviteVersion = Number(invite.accessCredentialVersion || 0);
  if (session.authenticationMethod === "access_key" && sessionVersion !== inviteVersion) {
    return null;
  }
  if (session.authenticationMethod !== "access_key" && Number(invite.credentialVersion || 0) >= 2) {
    const legacyDeadline = Date.parse(String(invite.legacyUuidLoginUntil || ""));
    if (!Number.isFinite(legacyDeadline) || Date.now() > legacyDeadline) {
      return null;
    }
  }

  return { invite, csrf: session.csrf, expiresAt };
}

async function createUuidSession(env, invite, authenticationMethod) {
  const token = randomHex(32);
  const csrf = randomHex(24);
  const maximumExpiresAt = Date.now() + UUID_SESSION_TTL_SECONDS * 1000;
  const legacyDeadline = Date.parse(String(invite.legacyUuidLoginUntil || ""));
  const expiresAt = authenticationMethod === "legacy_uuid" && Number.isFinite(legacyDeadline)
    ? Math.min(maximumExpiresAt, legacyDeadline)
    : maximumExpiresAt;
  const expirationTtl = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
  const sessionHash = await sha256Hex(token);
  const payload = {
    uuid: invite.uuid,
    csrf,
    expiresAt,
    authenticationMethod,
    accessCredentialVersion: Number(invite.accessCredentialVersion || 0),
  };
  if (isAuthStateBindingConfigured(env)) {
    await createAuthStateStore(env).createPublicSession(sessionHash, payload);
  } else {
    await env.INVITE_STORE.put(
      uuidSessionKey(sessionHash),
      JSON.stringify(payload),
      { expirationTtl },
    );
  }

  const cookie = [
    `${UUID_COOKIE_NAME}=${token}`,
    "Path=/allow-ip",
    `Max-Age=${expirationTtl}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ].join("; ");
  return { cookie, csrf };
}

async function deleteUuidSession(env, request) {
  if (!isAuthStateBindingConfigured(env) && !env.INVITE_STORE) {
    return;
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[UUID_COOKIE_NAME];
  if (token) {
    const sessionHash = await sha256Hex(token);
    if (isAuthStateBindingConfigured(env)) {
      await createAuthStateStore(env).deletePublicSession(sessionHash);
    } else {
      await env.INVITE_STORE.delete(uuidSessionKey(sessionHash));
    }
  }
}

function clearUuidCookie() {
  return `${UUID_COOKIE_NAME}=; Path=/allow-ip; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

function uuidSessionKey(hash) {
  return `uuid-session:${hash}`;
}

async function inviteAttemptKey(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const fingerprint = await rateLimitFingerprint(
    env.INVITE_ACCESS_HMAC_KEY,
    "public-invite-ip",
    ip,
  );
  return `invite-attempt:${fingerprint}`;
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
  return (nonce) => {
    const renderedBody = typeof body === "function" ? body(nonce) : String(body);
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
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", system-ui, sans-serif;
      background: #f5f5f7;
      color: #1d1d1f;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 40px 20px;
      background: #f5f5f7;
    }
    main { width: min(100%, 480px); }
    .hero, form, .message { display: grid; gap: 20px; }
    .dashboard { display: grid; gap: 16px; }
    .hero {
      margin-bottom: 32px;
      text-align: center;
    }
    .identity-title { overflow-wrap: anywhere; }
    .sub2api-icon {
      width: 72px;
      height: 72px;
      margin: 0 auto 6px;
      border-radius: 20px;
      display: inline-grid;
      place-items: center;
      overflow: hidden;
      background: transparent;
      box-shadow:
        0 4px 12px rgba(0, 0, 0, 0.08),
        0 20px 48px rgba(0, 0, 0, 0.12);
    }
    .sub2api-icon img { width: 100%; height: 100%; display: block; }
    .eyebrow {
      color: #6e6e73;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0;
      text-transform: uppercase;
    }
    .lede {
      color: #6e6e73;
      font-size: 17px;
      font-weight: 400;
      line-height: 1.47;
    }
    .hint {
      color: #6e6e73;
      font-size: 13px;
      line-height: 1.45;
    }
    .panel, .message {
      padding: 24px;
      border: 0.5px solid rgba(0, 0, 0, 0.06);
      border-radius: 8px;
      background: #fff;
      box-shadow:
        0 1px 3px rgba(0, 0, 0, 0.04),
        0 8px 24px rgba(0, 0, 0, 0.06);
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
    }
    label {
      color: #1d1d1f;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0;
    }
    .secret-field {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      height: 44px;
      border: 1px solid rgba(0, 0, 0, 0.1);
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.9);
      transition: border-color 200ms ease, box-shadow 200ms ease;
    }
    .secret-field:focus-within {
      border-color: #0071e3;
      box-shadow: 0 0 0 3.5px rgba(0, 113, 227, 0.16);
    }
    input {
      width: 100%;
      height: 44px;
      border: 0;
      border-radius: 10px;
      padding: 0 14px;
      font: inherit;
      font-size: 15px;
      background: transparent;
      color: #1d1d1f;
      outline: 0;
    }
    button, a {
      min-height: 44px;
      border: 0;
      border-radius: 10px;
      display: inline-grid;
      place-items: center;
      padding: 0 20px;
      background: #0071e3;
      color: #fff;
      font: inherit;
      font-weight: 600;
      font-size: 15px;
      text-decoration: none;
      cursor: pointer;
      transition: transform 120ms ease, background 120ms ease, box-shadow 120ms ease, opacity 120ms ease;
      -webkit-tap-highlight-color: transparent;
    }
    button:hover, a:hover {
      background: #0077ed;
      box-shadow: 0 4px 16px rgba(0, 113, 227, 0.24);
    }
    button:active, a:active {
      transform: scale(0.98);
      opacity: 0.9;
    }
    button.ghost {
      min-height: 32px;
      margin-right: 6px;
      padding: 0 12px;
      border-radius: 8px;
      background: transparent;
      color: #0071e3;
      box-shadow: none;
      font-size: 14px;
      font-weight: 500;
    }
    button.ghost:hover {
      background: rgba(0, 113, 227, 0.08);
      box-shadow: none;
    }
    button.ghost:active {
      background: rgba(0, 113, 227, 0.12);
      transform: none;
    }
    button.ghost-wide {
      width: 100%;
      background: rgba(0, 0, 0, 0.05);
      color: #1d1d1f;
      box-shadow: none;
      font-weight: 500;
    }
    button.ghost-wide:hover {
      background: rgba(0, 0, 0, 0.08);
      box-shadow: none;
    }
    button.ghost-wide:active {
      background: rgba(0, 0, 0, 0.1);
      transform: none;
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
    .inline-form { display: block; margin-top: 4px; }
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
      opacity: 1;
    }
    button:disabled:hover {
      background: #d2d2d7;
      box-shadow: none;
      transform: none;
    }
    h1 {
      margin: 0;
      max-width: 100%;
      font-size: 40px;
      font-weight: 700;
      line-height: 1.1;
      letter-spacing: 0;
      overflow-wrap: anywhere;
    }
    p { margin: 0; line-height: 1.53; }
    code {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .success { color: #248a3d; font-weight: 600; }
    .warning { color: #c77c11; font-weight: 600; }
    .api-list, .api-card { display: grid; gap: 12px; }
    .api-card {
      padding: 16px;
      border: 0.5px solid rgba(0, 0, 0, 0.06);
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.02);
    }
    .api-card strong {
      overflow-wrap: anywhere;
    }
    .api-card label { color: #6e6e73; font-size: 12px; font-weight: 500; }
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
    .copy-line code,
    .secret-format {
      display: block;
      min-width: 0;
      padding: 10px 12px;
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.04);
    }
    .copy-secret {
      height: 36px;
      border: 1px solid rgba(0, 0, 0, 0.1);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.8);
    }
    .turnstile-widget { width: 100%; min-height: 65px; }
    button:focus-visible, a:focus-visible, input:focus-visible {
      outline: 3px solid rgba(0, 113, 227, 0.32);
      outline-offset: 2px;
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        scroll-behavior: auto !important;
        transition: none !important;
      }
    }
    @media (max-width: 560px) {
      body { padding: 24px 16px; }
      h1 { font-size: 32px; }
      .identity-title { font-size: 24px; line-height: 1.15; }
      .panel, .message { padding: 20px; border-radius: 8px; }
      .copy-line, .secret-copy-line { grid-template-columns: minmax(0, 1fr); }
      button, a { width: 100%; }
      button.ghost, button.compact { width: auto; }
      .secret-copy-line button,
      .copy-line button { width: 100%; }
      .copy-secret { height: 40px; }
    }
    @media (max-width: 371px) {
      .turnstile-widget { min-height: 120px; }
    }
    @media (max-width: 240px) {
      body { padding: 16px 6px; }
      h1 { font-size: 28px; }
      .panel, .message { padding: 12px 6px; }
      .turnstile-widget {
        width: 130px;
        max-width: 100%;
        margin-inline: auto;
      }
      button, a {
        min-width: 0;
        padding-inline: 8px;
        overflow-wrap: anywhere;
      }
    }
    @media (prefers-color-scheme: dark) {
      :root { background: #000; color: #f5f5f7; }
      body { background: #000; }
      .sub2api-icon {
        background: #f5f5f7;
        box-shadow:
          0 4px 12px rgba(0, 0, 0, 0.28),
          0 0 0 1px rgba(255, 255, 255, 0.12);
      }
      .eyebrow, .lede, .hint, .api-card label { color: #a1a1a6; }
      .panel, .message {
        border-color: rgba(255, 255, 255, 0.08);
        background: #1c1c1e;
        box-shadow:
          0 1px 3px rgba(0, 0, 0, 0.2),
          0 8px 24px rgba(0, 0, 0, 0.3);
      }
      label, input { color: #f5f5f7; }
      .secret-field {
        border-color: rgba(255, 255, 255, 0.15);
        background: rgba(255, 255, 255, 0.06);
      }
      .secret-field:focus-within {
        border-color: #0a84ff;
        box-shadow: 0 0 0 3.5px rgba(10, 132, 255, 0.2);
      }
      .copy-secret {
        border-color: rgba(255, 255, 255, 0.15);
        background: rgba(255, 255, 255, 0.06);
      }
      .copy-line code,
      .secret-format {
        background: rgba(255, 255, 255, 0.06);
      }
      button, a { background: #0a84ff; }
      button:hover, a:hover { background: #409cff; }
      button.ghost-wide {
        background: rgba(255, 255, 255, 0.1);
        color: #f5f5f7;
      }
      button.ghost-wide:hover { background: rgba(255, 255, 255, 0.16); }
      .success { color: #32d74b; }
      .warning { color: #ffd60a; }
      .api-card {
        border-color: rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.04);
      }
    }
  </style>
</head>
<body>
  <main>${renderedBody}</main>
</body>
</html>`;
  };
}

function html(body, status = 200, extraHeaders = {}) {
  const nonce = randomHex(16);
  const securedBody = renderTrustedHtml(body, nonce);
  return new Response(securedBody, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-resource-policy": "same-origin",
      "x-permitted-cross-domain-policies": "none",
      "content-security-policy": `default-src 'none'; object-src 'none'; script-src 'nonce-${nonce}' https://challenges.cloudflare.com; style-src 'unsafe-inline'; img-src 'self' data:; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
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
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "x-permitted-cross-domain-policies": "none",
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

function requireEnv(values) {
  const missing = Object.entries(values)
    .filter(([, value]) => !value || String(value).startsWith("replace-with-"))
    .map(([name]) => name);
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
  const allowed = parseApprovedHostnames(env.ALLOWED_HOSTNAMES);
  return allowed.length > 0 && allowed.includes(String(hostname).toLowerCase());
}

export function isIPv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === part;
  });
}

function isPseudoIPv4(value) {
  const firstOctet = Number(value.split(".")[0]);
  return Number.isInteger(firstOctet) && firstOctet >= 240 && firstOctet <= 255;
}

export function isIPv6(value) {
  if (!value.includes(":") || !/^[0-9a-f:.]+$/i.test(value)) {
    return false;
  }
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
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

function renderTrustedHtml(document, nonce) {
  return typeof document === "function"
    ? String(document(nonce))
    : String(document);
}

export function jsString(value) {
  return JSON.stringify(String(value || ""))
    .replace(/&/g, "\\u0026")
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export const __test = Object.freeze({
  html,
  renderTrustedHtml,
});
