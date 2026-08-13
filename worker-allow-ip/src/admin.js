import { renderInviteSummary } from "./invite-summary.js";
import { cloudflareApiFetch, isCloudflareIdentifier, listCloudflareItems, readCloudflareJson, waitForCloudflareOperation } from "./cloudflare-client.js";
import { renderUsageInspectorBody, sanitizeUsageInspectorData } from "./usage-inspector.js";
import { fetchWithTimeout, isRequestBodyTooLarge, parseBoundedFormData, readJsonWithLimit } from "./request-security.js";
import { consumeAuthAttempt, resetAuthAttempts } from "./auth-rate-limiter.js";
import {
  createAuthStateStore,
  isAuthStateBindingConfigured,
  MAX_INVITE_CREDENTIAL_MIGRATION_BATCH,
  MAX_RECORD_LEASE_MS,
} from "./auth-state.js";
import {
  CLOUDFLARE_MUTATION_RETRY_MS,
  cloudflareMutationIdFromError,
  createManagedCloudflareListItems,
  findCloudflareMutationCandidates,
  resolveCloudflareMutation,
} from "./cloudflare-mutation.js";
import { parseApprovedHostnames, parseApprovedHttpsUrl } from "./url-security.js";
import {
  accessKeyHmac,
  base64UrlDecode,
  DEFAULT_KEY_GROUP_NAME,
  issueInviteAccessCredential,
  matchesInviteAccess,
  parseKeyGroupName,
  passwordHashFingerprint,
  protectInviteCredentials,
  rateLimitFingerprint,
  revealInviteCredentials,
  sanitizeInviteForTrash,
  timingSafeTextEqual as timingSafeEqual,
  verifyPbkdf2Password,
} from "./credential-security.js";

const ADMIN_PATH = "/allow-ip/admin";
const COOKIE_NAME = "sub2api_allow_admin";
const DELETE_ADMIN_COOKIE = `${COOKIE_NAME}=; Path=${ADMIN_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
const REQUEST_AUTH_STATE_STORE = Symbol("requestAuthStateStore");
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const ADMIN_SESSION_TOTP_BINDING_DOMAIN =
  "sub2api-gate/admin-session-totp-binding/v4\0";
const ADMIN_SESSION_TOTP_BINDING = /^[a-f0-9]{64}$/;
const INVITES_KEY = "invites";
const TRASH_KEY = "trash";
const INVITES_REVISION = Symbol("invitesRevision");
const TRASH_REVISION = Symbol("trashRevision");
const CLOUDFLARE_MUTATION_IDS = Symbol("cloudflareMutationIds");
const DEFAULT_IP_TTL_DAYS = 365;
const SUB2API_SYNC_TIMEOUT_MS = 5000;
const SUB2API_SYNC_LOGIN_TIMEOUT_MS = 10_000;
const SUB2API_SYNC_ERROR_STATUSES = new Set([
  400, 401, 404, 408, 409, 411, 413, 415, 429, 500, 502, 503, 504,
]);
const SUB2API_SYNC_DEFAULT_RESPONSE_MAX_BYTES = 16 * 1024;
const SUB2API_SYNC_ACCOUNT_RESPONSE_MAX_BYTES = 128 * 1024;
const SUB2API_SYNC_MAX_TOKENS = 100;
const SUB2API_SYNC_MAX_AUTH_TOKEN_BYTES = 4 * 1024;
const SUB2API_SYNC_MAX_AUTH_USER_FIELD_BYTES = 512;
const SUB2API_SYNC_MAX_AUTH_USER_BYTES = 8 * 1024;
const SYNC_AUTH_KEYS = new Set(["access_token", "refresh_token", "expires_in", "user"]);
const SYNC_AUTH_USER_KEYS = new Set([
  "id",
  "username",
  "name",
  "email",
  "role",
  "status",
  "balance",
  "avatar",
  "created_at",
  "updated_at",
]);
const GEOIP_TIMEOUT_MS = 5000;
const AUTH_STATE_RECONCILE_ATTEMPTS = 3;
const ADMIN_PAGE_SIZE = 25;
const ADMIN_IP_GROUP_PAGE_SIZE = 20;
const MAX_ADMIN_INVITE_PAGE = 400;
const MAX_ADMIN_TRASH_PAGE = 800;
const MAX_ADMIN_IP_GROUP_PAGE = 400;
const ADMIN_RECORD_PAYLOAD_MAX_BYTES = 256 * 1024;
const ADMIN_LIST_HTML_MAX_BYTES = 96 * 1024;
const ADMIN_DETAIL_HTML_MAX_BYTES = 128 * 1024;
const ADMIN_EDIT_HTML_MAX_BYTES = 160 * 1024;
const ISSUED_ACCESS_KEYS_HTML_MAX_BYTES = 256 * 1024;
const MANAGED_CLOUDFLARE_COMMENT = /^sub2api ref [a-f0-9]{32}$/;
const CLOUDFLARE_LIST_ITEM_ID = /^[A-Za-z0-9_-]{1,128}$/;
export const CLOUDFLARE_DELETE_BATCH_SIZE = 1000;
export const IP_RECORDS_BUSY_CODE = "ip_records_busy";
const EXISTING_CREDENTIAL_MARKER_PREFIX = "@existing-credential:v1:";
const STEP_UP_ACTIONS = new Set([
  "create",
  "migrate_invite_credentials",
  "finalize_legacy_auth_state_cleanup",
  "rotate_access_key",
  "restore_uuid",
  "reset_sub2api_password",
  "update_invite",
  "delete",
  "purge_uuid",
  "delete_ip_group",
  "restore_ip_group",
  "purge_ip_group",
  "update_ip_group_expiration",
  "add_ip_group",
]);
const SUB2API_FAVICON = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MSA0MSI+PHBhdGggZD0iTTM3LjUzMjQgMTYuODcwN0MzNy45ODA4IDE1LjUyNDEgMzguMTM2MyAxNC4wOTc0IDM3Ljk4ODYgMTIuNjg1OUMzNy44NDA5IDExLjI3NDQgMzcuMzkzNCA5LjkxMDc2IDM2LjY3NiA4LjY4NjIyQzM1LjYxMjYgNi44MzQwNCAzMy45ODgyIDUuMzY3NiAzMi4wMzczIDQuNDk4NUMzMC4wODY0IDMuNjI5NDEgMjcuOTA5OCAzLjQwMjU5IDI1LjgyMTUgMy44NTA3OEMyNC44Nzk2IDIuNzg5MyAyMy43MjE5IDEuOTQxMjUgMjIuNDI1NyAxLjM2MzQxQzIxLjEyOTUgMC43ODU1NzUgMTkuNzI0OSAwLjQ5MTI2OSAxOC4zMDU4IDAuNTAwMTk3QzE2LjE3MDggMC40OTUwNDQgMTQuMDg5MyAxLjE2ODAzIDEyLjM2MTQgMi40MjIxNEMxMC42MzM1IDMuNjc2MjQgOS4zNDg1MyA1LjQ0NjY2IDguNjkxNyA3LjQ3ODE1QzcuMzAwODUgNy43NjI4NiA1Ljk4Njg2IDguMzQxNCA0LjgzNzcgOS4xNzUwNUMzLjY4ODU0IDEwLjAwODcgMi43MzA3MyAxMS4wNzgyIDIuMDI4MzkgMTIuMzEyQzAuOTU2NDY0IDE0LjE1OTEgMC40OTg5MDUgMTYuMjk4OCAwLjcyMTY5OCAxOC40MjI4QzAuOTQ0NDkyIDIwLjU0NjcgMS44MzYxMiAyMi41NDQ5IDMuMjY4IDI0LjEyOTNDMi44MTk2NiAyNS40NzU5IDIuNjY0MTMgMjYuOTAyNiAyLjgxMTgyIDI4LjMxNDFDMi45NTk1MSAyOS43MjU2IDMuNDA3MDEgMzEuMDg5MiA0LjEyNDM3IDMyLjMxMzhDNS4xODc5MSAzNC4xNjU5IDYuODEyMyAzNS42MzIyIDguNzYzMjEgMzYuNTAxM0MxMC43MTQxIDM3LjM3MDQgMTIuODkwNyAzNy41OTczIDE0Ljk3ODkgMzcuMTQ5MkMxNS45MjA4IDM4LjIxMDcgMTcuMDc4NiAzOS4wNTg3IDE4LjM3NDcgMzkuNjM2NkMxOS42NzA5IDQwLjIxNDQgMjEuMDc1NSA0MC41MDg3IDIyLjQ5NDYgNDAuNDk5OEMyNC42MzA3IDQwLjUwNTQgMjYuNzEzMyAzOS44MzIxIDI4LjQ0MTggMzguNTc3MkMzMC4xNzA0IDM3LjMyMjMgMzEuNDU1NiAzNS41NTA2IDMyLjExMTkgMzMuNTE3OUMzMy41MDI3IDMzLjIzMzIgMzQuODE2NyAzMi42NTQ3IDM1Ljk2NTkgMzEuODIxQzM3LjExNSAzMC45ODc0IDM4LjA3MjggMjkuOTE3OCAzOC43NzUyIDI4LjY4NEMzOS44NDU4IDI2LjgzNzEgNDAuMzAyMyAyNC42OTc5IDQwLjA3ODkgMjIuNTc0OEMzOS44NTU2IDIwLjQ1MTcgMzguOTYzOSAxOC40NTQ0IDM3LjUzMjQgMTYuODcwN1pNMjIuNDk3OCAzNy44ODQ5QzIwLjc0NDMgMzcuODg3NCAxOS4wNDU5IDM3LjI3MzMgMTcuNjk5NCAzNi4xNTAxQzE3Ljc2MDEgMzYuMTE3IDE3Ljg2NjYgMzYuMDU4NiAxNy45MzYgMzYuMDE2MUwyNS45MDA0IDMxLjQxNTZDMjYuMTAwMyAzMS4zMDE5IDI2LjI2NjMgMzEuMTM3IDI2LjM4MTMgMzAuOTM3OEMyNi40OTY0IDMwLjczODYgMjYuNTU2MyAzMC41MTI0IDI2LjU1NDkgMzAuMjgyNVYxOS4wNTQyTDI5LjkyMTMgMjAuOTk4QzI5LjkzODkgMjEuMDA2OCAyOS45NTQxIDIxLjAxOTggMjkuOTY1NiAyMS4wMzU5QzI5Ljk3NyAyMS4wNTIgMjkuOTg0MiAyMS4wNzA3IDI5Ljk4NjcgMjEuMDkwMlYzMC4zODg5QzI5Ljk4NDIgMzIuMzc1IDI5LjE5NDYgMzQuMjc5MSAyNy43OTA5IDM1LjY4NDFDMjYuMzg3MiAzNy4wODkyIDI0LjQ4MzggMzcuODgwNiAyMi40OTc4IDM3Ljg4NDlaTTYuMzkyMjcgMzEuMDA2NEM1LjUxMzk3IDI5LjQ4ODggNS4xOTc0MiAyNy43MTA3IDUuNDk4MDQgMjUuOTgzMkM1LjU1NzE4IDI2LjAxODcgNS42NjA0OCAyNi4wODE4IDUuNzM0NjEgMjYuMTI0NEwxMy42OTkgMzAuNzI0OEMxMy44OTc1IDMwLjg0MDggMTQuMTIzMyAzMC45MDIgMTQuMzUzMiAzMC45MDJDMTQuNTgzIDMwLjkwMiAxNC44MDg4IDMwLjg0MDggMTUuMDA3MyAzMC43MjQ4TDI0LjczMSAyNS4xMTAzVjI4Ljk5NzlDMjQuNzMyMSAyOS4wMTc3IDI0LjcyODMgMjkuMDM3NiAyNC43MTk5IDI5LjA1NTZDMjQuNzExNSAyOS4wNzM2IDI0LjY5ODggMjkuMDg5MyAyNC42ODI5IDI5LjEwMTJMMTYuNjMxNyAzMy43NDk3QzE0LjkwOTYgMzQuNzQxNiAxMi44NjQzIDM1LjAwOTcgMTAuOTQ0NyAzNC40OTU0QzkuMDI1MDYgMzMuOTgxMSA3LjM4Nzg1IDMyLjcyNjMgNi4zOTIyNyAzMS4wMDY0Wk00LjI5NzA3IDEzLjYxOTRDNS4xNzE1NiAxMi4wOTk4IDYuNTUyNzkgMTAuOTM2NCA4LjE5ODg1IDEwLjMzMjdDOC4xOTg4NSAxMC40MDEzIDguMTk0OTEgMTAuNTIyOCA4LjE5NDkxIDEwLjYwNzFWMTkuODA4QzguMTkzNTEgMjAuMDM3OCA4LjI1MzM0IDIwLjI2MzggOC4zNjgyMyAyMC40NjI5QzguNDgzMTIgMjAuNjYxOSA4LjY0ODkzIDIwLjgyNjcgOC44NDg2MyAyMC45NDA0TDE4LjU3MjMgMjYuNTU0MkwxNS4yMDYgMjguNDk3OUMxNS4xODk0IDI4LjUwODkgMTUuMTcwMyAyOC41MTU1IDE1LjE1MDUgMjguNTE3M0MxNS4xMzA3IDI4LjUxOTEgMTUuMTEwNyAyOC41MTYgMTUuMDkyNCAyOC41MDgyTDcuMDQwNDYgMjMuODU1N0M1LjMyMTM1IDIyLjg2MDEgNC4wNjcxNiAyMS4yMjM1IDMuNTUyODkgMTkuMzA0NkMzLjAzODYyIDE3LjM4NTggMy4zMDYyNCAxNS4zNDEzIDQuMjk3MDcgMTMuNjE5NFpNMzEuOTU1IDIwLjA1NTZMMjIuMjMxMiAxNC40NDExTDI1LjU5NzYgMTIuNDk4MUMyNS42MTQyIDEyLjQ4NzIgMjUuNjMzMyAxMi40ODA1IDI1LjY1MzEgMTIuNDc4N0MyNS42NzI5IDEyLjQ3NjkgMjUuNjkyOCAxMi40ODAxIDI1LjcxMTEgMTIuNDg3OUwzMy43NjMxIDE3LjEzNjRDMzQuOTk2NyAxNy44NDkgMzYuMDAxNyAxOC44OTgyIDM2LjY2MDYgMjAuMTYxM0MzNy4zMTk0IDIxLjQyNDQgMzcuNjA0NyAyMi44NDkgMzcuNDgzMiAyNC4yNjg0QzM3LjM2MTcgMjUuNjg3OCAzNi44MzgyIDI3LjA0MzIgMzUuOTc0MyAyOC4xNzU5QzM1LjExMDMgMjkuMzA4NiAzMy45NDE1IDMwLjE3MTcgMzIuNjA0NyAzMC42NjQxQzMyLjYwNDcgMzAuNTk0NyAzMi42MDQ3IDMwLjQ3MzMgMzIuNjA0NyAzMC4zODg5VjIxLjE4OEMzMi42MDY2IDIwLjk1ODYgMzIuNTQ3NCAyMC43MzI4IDMyLjQzMzIgMjAuNTMzOEMzMi4zMTkgMjAuMzM0OCAzMi4xNTQgMjAuMTY5OCAzMS45NTUgMjAuMDU1NlpNMzUuMzA1NSAxNS4wMTI4QzM1LjI0NjQgMTQuOTc2NSAzNS4xNDMxIDE0LjkxNDIgMzUuMDY5IDE0Ljg3MTdMMjcuMTA0NSAxMC4yNzEyQzI2LjkwNiAxMC4xNTU0IDI2LjY4MDMgMTAuMDk0MyAyNi40NTA0IDEwLjA5NDNDMjYuMjIwNiAxMC4wOTQzIDI1Ljk5NDggMTAuMTU1NCAyNS43OTYzIDEwLjI3MTJMMTYuMDcyNiAxNS44ODU4VjExLjk5ODJDMTYuMDcxNSAxMS45NzgzIDE2LjA3NTMgMTEuOTU4NSAxNi4wODM3IDExLjk0MDVDMTYuMDkyMSAxMS45MjI1IDE2LjEwNDggMTEuOTA2OCAxNi4xMjA3IDExLjg5NDlMMjQuMTcxOSA3LjI1MDI1QzI1LjQwNTMgNi41MzkwMyAyNi44MTU4IDYuMTkzNzYgMjguMjM4MyA2LjI1NDgyQzI5LjY2MDggNi4zMTU4OSAzMS4wMzY0IDYuNzgwNzcgMzIuMjA0NCA3LjU5NTA4QzMzLjM3MjMgOC40MDkzOSAzNC4yODQyIDkuNTM5NDUgMzQuODMzNCAxMC44NTMxQzM1LjM4MjYgMTIuMTY2NyAzNS41NDY0IDEzLjYwOTUgMzUuMzA1NSAxNS4wMTI4Wk0xNC4yNDI0IDIxLjk0MTlMMTAuODc1MiAxOS45OTgxQzEwLjg1NzYgMTkuOTg5MyAxMC44NDIzIDE5Ljk3NjMgMTAuODMwOSAxOS45NjAyQzEwLjgxOTUgMTkuOTQ0MSAxMC44MTIyIDE5LjkyNTQgMTAuODA5OCAxOS45MDU4VjEwLjYwNzFDMTAuODEwNyA5LjE4Mjk1IDExLjIxNzMgNy43ODg0OCAxMS45ODE5IDYuNTg2OTZDMTIuNzQ2NiA1LjM4NTQ0IDEzLjgzNzcgNC40MjY1OSAxNS4xMjc1IDMuODIyNjRDMTYuNDE3MyAzLjIxODY5IDE3Ljg1MjQgMi45OTQ2NCAxOS4yNjQ5IDMuMTc2N0MyMC42Nzc1IDMuMzU4NzYgMjIuMDA4OSAzLjkzOTQxIDIzLjEwMzQgNC44NTA2N0MyMy4wNDI3IDQuODgzNzkgMjIuOTM3IDQuOTQyMTUgMjIuODY2OCA0Ljk4NDczTDE0LjkwMjQgOS41ODUxN0MxNC43MDI1IDkuNjk4NzggMTQuNTM2NiA5Ljg2MzU2IDE0LjQyMTUgMTAuMDYyNkMxNC4zMDY1IDEwLjI2MTYgMTQuMjQ2NiAxMC40ODc3IDE0LjI0NzkgMTAuNzE3NUwxNC4yNDI0IDIxLjk0MTlaTTE2LjA3MSAxNy45OTkxTDIwLjQwMTggMTUuNDk3OEwyNC43MzI1IDE3Ljk5NzVWMjIuOTk4NUwyMC40MDE4IDI1LjQ5ODNMMTYuMDcxIDIyLjk5ODVWMTcuOTk5MVoiIGZpbGw9IiMxMTEiLz48L3N2Zz4=";

export async function handleAdmin(request, env) {
  try {
    return await handleAdminRequest(request, createAdminRequestEnvironment(env));
  } catch (error) {
    if (isRequestBodyTooLarge(error)) {
      return html(renderMessage("Request too large", "Form submissions are limited to 32 KiB."), 413);
    }
    if (isAuthStateConflict(error)) {
      return html(
        renderMessage(
          "Update conflict",
          "The admin state changed while this request was being processed. Refresh the page and try again.",
        ),
        409,
      );
    }
    if (error instanceof Sub2ApiSyncError) {
      const retry = error.retryable ? " Try again after the dependency recovers." : "";
      const response = html(renderMessage(
        "Sub2API request failed",
        `The sync service returned ${error.code}. Request ID: ${error.requestId}.${retry}`,
      ), error.status);
      response.headers.set("x-request-id", error.requestId);
      if (error.retryable && [429, 503, 504].includes(error.status)) {
        response.headers.set("retry-after", "1");
      }
      return response;
    }
    console.error(JSON.stringify({ level: "error", message: "admin_action_failed" }));
    const message = isUserFacingAdminError(error)
      ? error.message
      : "The requested admin action could not be completed. Refresh the admin page and try again.";
    return html(renderMessage("Admin action failed", message), isUserFacingAdminError(error) ? 400 : 500);
  }
}

async function handleAdminRequest(request, env) {
  const adminUrl = new URL(request.url);
  const isDashboardPath = adminUrl.pathname === ADMIN_PATH;
  const isUsagePath = adminUrl.pathname === `${ADMIN_PATH}/requests`
    || adminUrl.pathname === `${ADMIN_PATH}/requests/detail`;
  if (!isDashboardPath && !isUsagePath) {
    return text("Not found", 404);
  }
  const allowedMethods = isDashboardPath ? ["GET", "POST"] : ["GET"];
  if (!allowedMethods.includes(request.method)) {
    return text("Method not allowed", 405, { allow: allowedMethods.join(", ") });
  }
  if (request.method === "POST" && !isSupportedAdminFormRequest(request)) {
    return text("Unsupported media type", 415);
  }

  const setupError = getAdminSetupError(env);
  if (setupError) {
    return html(renderAdminSetupError(setupError), 500);
  }

  const hadSessionCookie = hasAdminSessionCookie(request);
  const session = await getAdminSession(request, env);

  if (request.method === "GET") {
    if (!session) {
      return setResponseCookie(html(renderLogin()), hadSessionCookie ? DELETE_ADMIN_COOKIE : "");
    }

    if (adminUrl.pathname === `${ADMIN_PATH}/requests`) {
      const usage = await listUsageMetadata(env, request);
      return html(renderUsageInspector(usage, session.csrf, request), 200);
    }

    if (adminUrl.pathname === `${ADMIN_PATH}/requests/detail`) {
      const usage = await getUsageMetadataDetail(env, request);
      return html(renderUsageInspector(usage, session.csrf, request), 200);
    }

    const canonicalLocation = legacyAdminCanonicalLocation(adminUrl);
    if (canonicalLocation) return redirect(canonicalLocation);
    const dashboard = await getAdminDashboard(env, adminUrl);
    if (dashboard.selectedUuidRequested && !dashboard.selectedInvite) {
      return html(renderMessage("UUID not found", "Return to the UUID list and select an active UUID."), 404);
    }
    return html(renderAdmin(
      dashboard.invites,
      dashboard.trash,
      session.csrf,
      request,
      env,
      dashboard,
    ), 200, dashboard.view === "list"
      ? ADMIN_LIST_HTML_MAX_BYTES
      : dashboard.view === "edit"
        ? ADMIN_EDIT_HTML_MAX_BYTES
        : ADMIN_DETAIL_HTML_MAX_BYTES);
  }

  let form;
  try {
    form = await parseBoundedFormData(request);
  } catch (error) {
    if (isRequestBodyTooLarge(error)) throw error;
    return html(renderMessage(
      "Invalid form submission",
      "Refresh the admin page and submit the form again.",
    ), 400);
  }
  const action = String(form.get("action") || "");

  if (action === "login") {
    const response = await handleAdminLogin(form, env, request);
    return response.headers.has("set-cookie")
      ? response
      : setResponseCookie(response, hadSessionCookie ? DELETE_ADMIN_COOKIE : "");
  }

  if (!session) {
    return redirect(ADMIN_PATH, hadSessionCookie ? DELETE_ADMIN_COOKIE : "");
  }

  if (!(await timingSafeEqual(String(form.get("csrf") || ""), session.csrf))) {
    return html(renderMessage("Invalid request", "Refresh the admin page and try again."), 403);
  }

  if (action === "logout") {
    await deleteSession(env, request);
    return redirect(ADMIN_PATH, DELETE_ADMIN_COOKIE);
  }

  if (requiresStepUpAction(action)) {
    const attemptKey = await stepUpAttemptKey(env, session.sessionHash);
    if (!(await consumeAuthAttempt(env, "totp", attemptKey))) {
      return html(renderMessage("Too many 2FA attempts", "Try again later."), 429);
    }
    await requireStepUpTotp(form, env);
    await resetAuthAttempts(env, "totp", attemptKey);
  }

  if (action === "create") {
    const uuid = String(form.get("uuid") || "").trim();
    const username = cleanText(form.get("username"), 100);
    const email = cleanText(form.get("email"), 160);
    const remark = cleanText(form.get("remark"), 240);
    const apiConfigs = parseApiConfigs(String(form.get("api_configs") || ""), env);
    const keyGroup = parseKeyGroupName(form.get("key_group"));
    const created = await createInvite(env, uuid, { username, email, remark, apiConfigs, keyGroup });
    if (created.accessKey) {
      return html(renderIssuedAccessKeys([{
        uuid,
        username,
        accessKey: created.accessKey,
      }]), 201);
    }
    return redirect(ADMIN_PATH);
  }

  if (action === "migrate_invite_credentials") {
    return await migrateInviteCredentials(env, new Date(), adminMaintenancePostHref(form));
  }

  if (action === "finalize_legacy_auth_state_cleanup") {
    await finalizeLegacyAuthStateCleanup(env);
    return redirect(adminMaintenancePostHref(form));
  }

  if (action === "rotate_access_key") {
    const uuid = String(form.get("uuid") || "").trim();
    const issued = await rotateInviteAccessKey(env, uuid);
    return html(renderIssuedAccessKeys([issued], 0, adminInvitePostHref(form, uuid)), 200);
  }

  if (action === "refresh_sub2api_status") {
    const uuid = String(form.get("uuid") || "").trim();
    await refreshInviteFromSub2Api(env, uuid);
    return redirect(adminInvitePostHref(form, uuid));
  }

  if (action === "test_api_key") {
    const uuid = String(form.get("uuid") || "").trim();
    const configId = String(form.get("config_id") || "").trim();
    const attemptKey = await keyTestAttemptKey(env, session.sessionHash);
    if (!(await consumeAuthAttempt(env, "keytest", attemptKey))) {
      return html(renderMessage("Too many API key tests", "Try again later."), 429);
    }
    const result = await testInviteApiKey(env, uuid, configId);
    return html(renderKeyTestResult(result, adminInvitePostHref(form, uuid)), result.tested ? 200 : 502);
  }

  if (action === "reset_sub2api_password") {
    const uuid = String(form.get("uuid") || "").trim();
    await resetInviteSub2ApiPassword(env, uuid);
    return redirect(adminInvitePostHref(form, uuid));
  }

  if (action === "update_invite") {
    const originalUuid = String(form.get("original_uuid") || "").trim();
    const uuid = String(form.get("uuid") || "").trim();
    const username = cleanText(form.get("username"), 100);
    const email = cleanText(form.get("email"), 160);
    const remark = cleanText(form.get("remark"), 240);
    const apiConfigs = parseApiConfigs(
      String(form.get("api_configs") || ""),
      env,
      { allowExistingCredentialReferences: true },
    );
    const keyGroup = parseKeyGroupName(form.get("key_group"));
    await updateInvite(env, originalUuid, { uuid, username, email, remark, apiConfigs, keyGroup });
    return redirect(adminInvitePostHref(form, uuid));
  }

  if (action === "delete") {
    const uuid = String(form.get("uuid") || "").trim();
    await deleteInvite(env, uuid);
    return redirect(adminPageHref(parseAdminInvitePostContext(form).page));
  }

  if (action === "restore_uuid") {
    const trashId = String(form.get("trash_id") || "").trim();
    const maintenanceHref = adminMaintenancePostHref(form);
    const restored = await restoreInviteFromTrash(env, trashId);
    return restored
      ? html(renderIssuedAccessKeys([restored], 0, maintenanceHref), 200)
      : redirect(maintenanceHref);
  }

  if (action === "purge_uuid") {
    const trashId = String(form.get("trash_id") || "").trim();
    await purgeInviteTrash(env, trashId);
    return redirect(adminMaintenancePostHref(form));
  }

  if (action === "delete_ip_group") {
    const uuid = String(form.get("uuid") || "").trim();
    const groupId = String(form.get("group_id") || "").trim();
    await deleteIpGroup(env, uuid, groupId);
    return redirect(adminInvitePostHref(form, uuid));
  }

  if (action === "restore_ip_group") {
    const trashId = String(form.get("trash_id") || "").trim();
    await restoreIpGroupFromTrash(env, trashId);
    return redirect(adminMaintenancePostHref(form));
  }

  if (action === "purge_ip_group") {
    const trashId = String(form.get("trash_id") || "").trim();
    await purgeIpGroupTrash(env, trashId);
    return redirect(adminMaintenancePostHref(form));
  }

  if (action === "update_ip_group_expiration") {
    const uuid = String(form.get("uuid") || "").trim();
    const groupId = String(form.get("group_id") || "").trim();
    const expiresAt = parseExpirationInput(
      String(form.get("expires_at") || ""),
      String(form.get("expires_in_days") || ""),
      String(form.get("expiration_mode") || ""),
    );
    await updateIpGroupExpiration(env, uuid, groupId, expiresAt);
    return redirect(adminInvitePostHref(form, uuid));
  }

  if (action === "add_ip_group") {
    const uuid = String(form.get("uuid") || "").trim();
    const ipValue = cleanText(form.get("ip_value"), 160);
    const expiresAt = parseExpirationInput(
      String(form.get("expires_at") || ""),
      String(form.get("expires_in_days") || ""),
      String(form.get("expiration_mode") || ""),
    ) || addDaysIso(new Date().toISOString(), DEFAULT_IP_TTL_DAYS);
    await addManualIpGroup(env, uuid, ipValue, expiresAt);
    return redirect(adminInvitePostHref(form, uuid));
  }

  return html(renderMessage("Unknown admin action", "Refresh the admin page and try again."), 400);
}

function createAdminRequestEnvironment(env) {
  if (!isAuthStateBindingConfigured(env)) return env;
  const requestEnvironment = Object.create(env);
  Object.defineProperty(requestEnvironment, REQUEST_AUTH_STATE_STORE, {
    value: createAuthStateStore(env),
  });
  return requestEnvironment;
}

function authStateStore(env) {
  return env?.[REQUEST_AUTH_STATE_STORE] || createAuthStateStore(env);
}

function isSupportedAdminFormRequest(request) {
  const contentType = String(request.headers.get("content-type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  return contentType === "application/x-www-form-urlencoded"
    || contentType === "multipart/form-data";
}

function hasAdminSessionCookie(request) {
  return Boolean(parseCookies(request.headers.get("Cookie") || "")[COOKIE_NAME]);
}

function setResponseCookie(response, cookie) {
  if (cookie) response.headers.set("set-cookie", cookie);
  return response;
}

class Sub2ApiSyncError extends Error {
  constructor({ status, code, retryable, requestId, action }) {
    super("Sub2API sync request failed");
    this.name = "Sub2ApiSyncError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.requestId = requestId;
    this.action = action;
  }
}

export async function findInvite(env, input) {
  if (!input) {
    return null;
  }

  if (isAuthStateBindingConfigured(env)) {
    const store = authStateStore(env);
    const candidateHmac = await accessKeyHmac(env.INVITE_ACCESS_HMAC_KEY, input);
    let invite = await store.findInviteByAccessKeyHmac(candidateHmac);
    if (!invite && isUuid(input)) {
      invite = await store.getInvite(input);
    }
    if (invite && await matchesInviteAccess(
      invite,
      input,
      env.INVITE_ACCESS_HMAC_KEY,
      new Date(),
      candidateHmac,
    )) {
      return await revealStoredInvite(env, invite);
    }
    return null;
  }

  if (env.INVITE_STORE) {
    const invites = await getStoredInvites(env);
    const candidateHmac = invites.some((invite) => invite.accessKeyHmac)
      ? await accessKeyHmac(env.INVITE_ACCESS_HMAC_KEY, input)
      : "";
    for (const invite of invites) {
      if (await matchesInviteAccess(
        invite,
        input,
        env.INVITE_ACCESS_HMAC_KEY,
        new Date(),
        candidateHmac,
      )) {
        return await revealStoredInvite(env, invite);
      }
    }
  }

  return null;
}

export async function getInviteByUuid(env, uuid) {
  if (!env.INVITE_STORE || !isUuid(uuid)) {
    return null;
  }
  if (isAuthStateBindingConfigured(env)) {
    const invite = await authStateStore(env).getInvite(uuid, { reveal: true });
    return invite ? sanitizeInviteUrls(env, invite) : null;
  }
  const invites = await getStoredInvites(env);
  const invite = invites.find((item) => item.uuid === uuid);
  return invite ? await revealStoredInvite(env, invite) : null;
}

export function sanitizeInviteForPublic(env, invite) {
  return sanitizeInviteUrls(env, invite);
}

export async function authorizeVisitorIps(env, request, invite, ips) {
  try {
    return await withIpRecordsLease(env, invite?.uuid, async (lease) => {
      const result = await addVisitorIpsToCloudflareList(env, ips, lease);
      if (!result.ok) return result;
      await recordVisitorIp(env, request, invite, result, lease);
      return result;
    });
  } catch (error) {
    if (String(error?.message || "") !== IP_RECORDS_BUSY_CODE) throw error;
    return {
      ok: false,
      status: 409,
      errors: [{ code: IP_RECORDS_BUSY_CODE }],
      messages: [],
      items: [],
      mutationIds: [],
    };
  }
}

async function recordVisitorIp(env, request, invite, result, lease) {
  if (!env.INVITE_STORE) {
    return;
  }

  const groups = await getIpRecords(env, invite.uuid);
  const cf = request.cf || {};
  const now = new Date().toISOString();
  const location = await lookupIpLocation(env, result.items?.[0]?.ip || "", cf);
  const group = {
    id: randomHex(12),
    addedAt: now,
    updatedAt: now,
    expiresAt: addDaysIso(now, DEFAULT_IP_TTL_DAYS),
    country: location.country,
    region: location.region,
    city: location.city,
    timezone: location.timezone,
    colo: stringOrEmpty(location.colo || cf.colo),
    asn: location.asn || (cf.asn ? String(cf.asn) : ""),
    asOrganization: location.asOrganization || stringOrEmpty(cf.asOrganization),
    geoSource: location.source,
    ips: (result.items || []).map((item) => ({
      ip: item.ip,
      version: item.version || "",
      cidr: item.cidr || "",
      listValue: item.listValue || item.cidr || item.ip,
      listItemId: item.listItemId || "",
      alreadyListed: Boolean(item.alreadyListed),
    })),
  };

  const nextGroups = upsertIpGroup(groups, group).slice(0, 50);

  try {
    await putIpRecords(env, invite.uuid, nextGroups, lease);
  } catch (error) {
    await compensateCloudflareMutationIds(env, result.mutationIds || [], lease);
    throw error;
  }
  await finalizeCloudflareMutationIds(env, result.mutationIds || []);
}

async function withIpRecordsLease(env, uuid, callback, existingLease = null) {
  if (!isUuid(uuid)) throw new Error("Invalid UUID");
  if (!isAuthStateBindingConfigured(env)) return await callback(null);
  if (existingLease) {
    if (existingLease.scope === "all" || (existingLease.scope === "invite" && existingLease.uuid === uuid)) {
      return await callback(existingLease);
    }
    throw new Error("ip_records_lease_scope_invalid");
  }

  const ownerToken = randomHex(32);
  const store = authStateStore(env);
  const claim = await store.claimRecordLease(
    uuid,
    ownerToken,
    Date.now(),
    MAX_RECORD_LEASE_MS,
  );
  if (!claim?.claimed) throw new Error(IP_RECORDS_BUSY_CODE);

  const lease = Object.freeze({ scope: "invite", uuid, ownerToken });
  try {
    return await callback(lease);
  } finally {
    try {
      await store.releaseRecordLease(uuid, ownerToken);
    } catch {
      console.error(JSON.stringify({ level: "error", message: "ip_records_lease_release_deferred" }));
    }
  }
}

async function withAllIpRecordsLease(env, callback, existingLease = null) {
  if (!isAuthStateBindingConfigured(env)) return await callback(null);
  if (existingLease?.scope === "all") return await callback(existingLease);

  const ownerToken = existingLease?.ownerToken || randomHex(32);
  const store = authStateStore(env);
  const claim = await store.claimRecordMaintenanceLease(
    ownerToken,
    Date.now(),
    MAX_RECORD_LEASE_MS,
  );
  if (!claim?.claimed) throw new Error(IP_RECORDS_BUSY_CODE);

  const lease = Object.freeze({ scope: "all", ownerToken });
  try {
    return await callback(lease);
  } finally {
    try {
      await store.releaseRecordMaintenanceLease(ownerToken);
    } catch {
      console.error(JSON.stringify({ level: "error", message: "ip_records_maintenance_lease_release_deferred" }));
    }
  }
}

function requireIpRecordsLease(env, uuid, lease) {
  if (!isAuthStateBindingConfigured(env)) return;
  if (lease?.scope === "all" || (lease?.scope === "invite" && lease.uuid === uuid)) return;
  throw new Error("ip_records_lease_required");
}

export function getInviteApiConfigs(invite, env, request) {
  const configs = Array.isArray(invite.apiConfigs)
    ? normalizeApiConfigs(invite.apiConfigs)
      .map((config) => ({ ...config, baseUrl: approvedApiConfigUrl(env, config) }))
      .filter((config) => config.baseUrl)
    : [];
  if (configs.length > 0) {
    return configs;
  }

  return [];
}

export async function refreshInviteFromSub2Api(env, uuid) {
  if (!isUuid(uuid)) {
    throw new Error("Invalid UUID");
  }

  const invites = await getInvites(env);
  const invite = invites.find((item) => item.uuid === uuid);
  if (!invite) {
    return null;
  }

  const previousSync = invite.sub2apiSync || {};
  const syncResult = await callSub2ApiSync(env, "status", {
    uuid,
    username: desiredSub2ApiUsername(inviteUsername(invite), uuid),
    name: inviteUsername(invite) || uuid,
    sub2apiUserId: previousSync.userId || 0,
  });
  if (!syncResult.exists) {
    return invite;
  }

  const nextPasswordFingerprint = String(syncResult.passwordHashFingerprint || "") || (
    syncResult.passwordHash
      ? await passwordHashFingerprint(env.INVITE_ACCESS_HMAC_KEY, syncResult.passwordHash)
      : ""
  );
  const previousPasswordFingerprint = previousSync.passwordHashFingerprint || (
    previousSync.passwordHash
      ? await passwordHashFingerprint(env.INVITE_ACCESS_HMAC_KEY, previousSync.passwordHash)
      : ""
  );
  const passwordChangedExternally = Boolean(
    nextPasswordFingerprint
    && previousPasswordFingerprint
    && nextPasswordFingerprint !== previousPasswordFingerprint
  );
  invite.sub2apiSync = {
    ...previousSync,
    ...await sub2apiSyncMetadata(env, {
      ...syncResult,
      loginPassword: passwordChangedExternally ? "" : previousSync.loginPassword,
    }),
    passwordHashFingerprint: nextPasswordFingerprint || previousPasswordFingerprint,
    passwordChangedExternally,
  };
  delete invite.sub2apiSync.passwordHash;
  invite.apiConfigs = mergeSub2ApiConfig(env, invite.apiConfigs, syncResult);
  invite.updatedAt = new Date().toISOString();
  await saveInvites(env, invites);
  return invite;
}

export async function resetInviteSub2ApiPassword(env, uuid) {
  if (!isUuid(uuid)) {
    throw new Error("Invalid UUID");
  }

  const invites = await getInvites(env);
  const invite = invites.find((item) => item.uuid === uuid);
  if (!invite) {
    throw new Error("Invite not found");
  }

  const sync = invite.sub2apiSync || {};
  const syncResult = await provisionSub2ApiUser(env, {
    uuid: invite.uuid,
    username: desiredSub2ApiUsername(inviteUsername(invite), invite.uuid),
    name: inviteUsername(invite) || invite.uuid,
    email: invite.email || "",
    remark: invite.remark || "",
    sub2apiUserId: sync.userId || 0,
    loginPassword: "",
    resetLoginPassword: true,
    tokens: desiredSub2ApiTokens(env, invite.apiConfigs),
  });
  invite.apiConfigs = mergeSub2ApiConfig(env, invite.apiConfigs, syncResult);
  invite.sub2apiSync = await sub2apiSyncMetadata(env, syncResult);
  invite.updatedAt = new Date().toISOString();
  try {
    await saveInvites(env, invites);
  } catch (error) {
    await compensateProvisionConflict(env, invite.uuid, invite);
    throw error;
  }
  return invite;
}

export async function loginInviteToSub2Api(env, invite) {
  const sync = invite.sub2apiSync || {};
  const username = String(sync.username || "");
  const canonicalUsername = desiredSub2ApiUsername(
    inviteUsername(invite) || username,
    invite.uuid,
  );
  const email = String(sync.email || (username ? `${username}@sub2api.local` : ""));
  const password = String(sync.loginPassword || "");
  if (!email || !password) {
    throw new Error("Sub2API login is not ready for this UUID");
  }
  return await callSub2ApiSync(env, "login", {
    uuid: invite.uuid,
    username: canonicalUsername,
    sub2apiUserId: safePositiveIdentifier(sync.userId),
    email,
    loginPassword: password,
  });
}

async function handleAdminLogin(form, env, request) {
  const username = String(form.get("username") || "").trim();
  const password = String(form.get("password") || "");
  const token = String(form.get("token") || "").replace(/\s+/g, "");
  const attemptKey = await loginAttemptKey(env, request);
  if (!(await consumeAuthAttempt(env, "admin", attemptKey))) {
    return html(renderLogin("Too many failed sign-in attempts. Try again later."), 429);
  }

  const usernameOk = await timingSafeEqual(username, env.ADMIN_USERNAME);
  const passwordOk = await verifyPbkdf2Password(password, env.ADMIN_PASSWORD_PBKDF2);
  const tokenOk = await verifyAdminTotp(env, token);

  if (!usernameOk || !passwordOk || !tokenOk) {
    return html(renderLogin("The username, password, or 2FA code is incorrect."), 403);
  }
  await resetAuthAttempts(env, "admin", attemptKey);

  const sessionToken = randomHex(32);
  const sessionHash = await sha256Hex(sessionToken);
  const csrf = randomHex(24);
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  const totpBinding = await adminSessionTotpBindingForEnvironment(env);

  if (isAuthStateBindingConfigured(env)) {
    await authStateStore(env).createAdminSession(sessionHash, {
      csrf,
      expiresAt,
      totpBinding,
    });
  } else {
    await env.INVITE_STORE.put(
      sessionKey(sessionHash),
      JSON.stringify({ csrf, expiresAt, totpBinding }),
      { expirationTtl: SESSION_TTL_SECONDS },
    );
  }

  const cookie = [
    `${COOKIE_NAME}=${sessionToken}`,
    `Path=${ADMIN_PATH}`,
    `Max-Age=${SESSION_TTL_SECONDS}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ].join("; ");

  return redirect(ADMIN_PATH, cookie);
}

async function getAdminSession(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[COOKIE_NAME];
  if (!token) {
    return null;
  }

  const sessionHash = await sha256Hex(token);
  let session;
  if (isAuthStateBindingConfigured(env)) {
    session = await authStateStore(env).getAdminSession(sessionHash);
  } else {
    const raw = await env.INVITE_STORE.get(sessionKey(sessionHash));
    if (!raw) return null;
    const parsed = parseJson(raw, null);
    const expiresAt = Number(parsed?.expiresAt);
    if (parsed && parsed.csrf && Number.isFinite(expiresAt) && expiresAt > Date.now()) {
      session = { ...parsed, expiresAt };
    }
  }

  if (!session || !(await sessionMatchesAdminTotpBinding(session, env))) {
    await deleteAdminSession(env, sessionHash);
    return null;
  }
  return { ...session, sessionHash };
}

async function deleteSession(env, request) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[COOKIE_NAME];
  if (token) {
    const sessionHash = await sha256Hex(token);
    await deleteAdminSession(env, sessionHash);
  }
}

async function deleteAdminSession(env, sessionHash) {
  if (isAuthStateBindingConfigured(env)) {
    // AuthState removes the legacy KV fallback before its durable session.
    await authStateStore(env).deleteAdminSession(sessionHash);
  } else {
    await env.INVITE_STORE.delete(sessionKey(sessionHash));
  }
}

async function getAdminDashboard(env, adminUrl) {
  const requestedPage = parseAdminPageNumber(adminUrl.searchParams.get("page"), MAX_ADMIN_INVITE_PAGE);
  const requestedTrashPage = parseAdminPageNumber(adminUrl.searchParams.get("trashPage"), MAX_ADMIN_TRASH_PAGE);
  const candidateEditUuid = String(adminUrl.searchParams.get("edit") || "");
  const editUuid = isUuid(candidateEditUuid) ? candidateEditUuid : "";
  const candidateDetailUuid = String(adminUrl.searchParams.get("detail") || "");
  const detailUuid = isUuid(candidateDetailUuid) ? candidateDetailUuid : "";
  const selectedUuid = editUuid || detailUuid;
  const requestedView = String(adminUrl.searchParams.get("view") || "").trim().toLowerCase();
  const view = selectedUuid
    ? (editUuid ? "edit" : "detail")
    : requestedView === "create" || requestedView === "maintenance"
      ? requestedView
      : "list";
  const requestedIpPage = parseAdminPageNumber(
    adminUrl.searchParams.get("ipPage"),
    MAX_ADMIN_IP_GROUP_PAGE,
  );

  if (isAuthStateBindingConfigured(env)) {
    const store = authStateStore(env);
    const authStateStatus = await store.ready();
    let page = requestedPage;
    let trashPage = requestedTrashPage;
    const inviteLimit = view === "list" ? ADMIN_PAGE_SIZE : 1;
    const trashLimit = view === "maintenance" ? ADMIN_PAGE_SIZE : 1;
    let result = await store.readAdminPage({
      inviteOffset: view === "list" ? (page - 1) * ADMIN_PAGE_SIZE : 0,
      inviteLimit,
      trashOffset: view === "maintenance" ? (trashPage - 1) * ADMIN_PAGE_SIZE : 0,
      trashLimit,
    });
    const inviteCount = normalizeAdminTotal(result.inviteCount);
    const trashCount = normalizeAdminTotal(result.trashCount);
    page = Math.min(page, adminPageCount(inviteCount));
    trashPage = Math.min(trashPage, adminPageCount(trashCount));
    if (page !== requestedPage || trashPage !== requestedTrashPage) {
      result = await store.readAdminPage({
        inviteOffset: view === "list" ? (page - 1) * ADMIN_PAGE_SIZE : 0,
        inviteLimit,
        trashOffset: view === "maintenance" ? (trashPage - 1) * ADMIN_PAGE_SIZE : 0,
        trashLimit,
      });
    }

    const pageInvites = normalizeStoredInvites(Array.isArray(result.invites) ? result.invites : [])
      .slice(0, ADMIN_PAGE_SIZE);
    const invites = pageInvites.map((invite) => summarizeStoredInvite(env, invite));
    const catalogPromise = (view === "create" || view === "edit")
      ? loadKeyGroupCatalog(env)
      : Promise.resolve([]);
    const selectedStoredInvite = selectedUuid
      ? await store.getInvite(selectedUuid)
      : null;
    const [selectedInvite, keyGroups] = await Promise.all([
      selectedStoredInvite
        ? hydrateAdminInvite(env, selectedStoredInvite, editUuid, requestedIpPage)
        : null,
      catalogPromise,
    ]);
    return {
      invites,
      trash: (Array.isArray(result.trash) ? result.trash : [])
        .slice(0, ADMIN_PAGE_SIZE)
        .map(summarizeAdminTrashItem)
        .filter(Boolean),
      inviteCount,
      trashCount,
      unmigratedInviteCount: normalizeAdminTotal(result.unmigratedInviteCount),
      authStateStatus,
      selectedInvite,
      selectedUuidRequested: candidateEditUuid || candidateDetailUuid,
      view,
      page,
      trashPage,
      keyGroups,
    };
  }

  const [storedInvites, storedTrash] = await Promise.all([getStoredInvites(env), getTrash(env)]);
  const inviteCount = storedInvites.length;
  const trashCount = storedTrash.length;
  const page = Math.min(requestedPage, adminPageCount(inviteCount));
  const trashPage = Math.min(requestedTrashPage, adminPageCount(trashCount));
  const pageInvites = view === "list"
    ? storedInvites.slice((page - 1) * ADMIN_PAGE_SIZE, page * ADMIN_PAGE_SIZE)
    : storedInvites.slice(0, 1);
  const invites = pageInvites.map((invite) => summarizeStoredInvite(env, invite));
  const catalogPromise = (view === "create" || view === "edit")
    ? loadKeyGroupCatalog(env)
    : Promise.resolve([]);
  const selectedStoredInvite = selectedUuid
    ? storedInvites.find((invite) => invite.uuid === selectedUuid)
    : null;
  const [selectedInvite, keyGroups] = await Promise.all([
    selectedStoredInvite
      ? hydrateAdminInvite(env, selectedStoredInvite, editUuid, requestedIpPage)
      : null,
    catalogPromise,
  ]);
  return {
    invites,
    trash: storedTrash
      .slice(
        view === "maintenance" ? (trashPage - 1) * ADMIN_PAGE_SIZE : 0,
        view === "maintenance" ? trashPage * ADMIN_PAGE_SIZE : 1,
      )
      .map(summarizeAdminTrashItem)
      .filter(Boolean),
    inviteCount,
    trashCount,
    unmigratedInviteCount: storedInvites.filter((invite) => !invite.accessKeyHmac).length,
    selectedInvite,
    selectedUuidRequested: candidateEditUuid || candidateDetailUuid,
    view,
    page,
    trashPage,
    keyGroups,
  };
}

async function hydrateAdminInvite(env, storedInvite, _editUuid = "", requestedIpPage = 1) {
  const invite = summarizeStoredInvite(env, storedInvite);
  const { records, recordsOversized } = await getAdminIpRecords(env, invite.uuid);
  const recordCount = records.length;
  const ipPageCount = Math.max(1, Math.ceil(recordCount / ADMIN_IP_GROUP_PAGE_SIZE));
  const ipPage = Math.min(requestedIpPage, ipPageCount);
  const offset = (ipPage - 1) * ADMIN_IP_GROUP_PAGE_SIZE;
  return {
    ...invite,
    records: records.slice(offset, offset + ADMIN_IP_GROUP_PAGE_SIZE),
    recordsOversized,
    recordCount,
    ipPage,
  };
}

function parseAdminPageNumber(value, maximum) {
  const input = String(value || "");
  if (!/^[1-9][0-9]*$/.test(input)) return 1;
  const page = Number(input);
  return Number.isSafeInteger(page) && page <= maximum ? page : 1;
}

function normalizeAdminTotal(value) {
  const total = Number(value);
  return Number.isSafeInteger(total) && total >= 0 ? total : 0;
}

function adminPageCount(total) {
  return Math.max(1, Math.ceil(normalizeAdminTotal(total) / ADMIN_PAGE_SIZE));
}

async function getInvites(env) {
  const invites = await getStoredInvites(env);
  const revealed = await Promise.all(invites.map((invite) => revealStoredInvite(env, invite)));
  return copyCollectionRevision(invites, revealed, INVITES_REVISION);
}

async function getStoredInvites(env) {
  if (isAuthStateBindingConfigured(env)) {
    const result = await authStateStore(env).readInvites();
    const invites = normalizeStoredInvites(result.items);
    return attachCollectionRevision(invites, INVITES_REVISION, result.revision);
  }

  const raw = await env.INVITE_STORE.get(INVITES_KEY);
  const invites = parseJson(raw, []);
  if (!Array.isArray(invites)) {
    return [];
  }

  return normalizeStoredInvites(invites);
}

function normalizeStoredInvites(invites) {
  return invites
    .filter((invite) => invite && invite.uuid)
    .sort((left, right) => String(right.createdAt || "").localeCompare(String(left.createdAt || "")));
}

async function revealStoredInvite(env, invite) {
  return sanitizeInviteUrls(
    env,
    await revealInviteCredentials(invite, env.CREDENTIAL_ENCRYPTION_KEY),
  );
}

function summarizeStoredInvite(env, invite) {
  const sync = invite?.sub2apiSync || {};
  const apiConfigs = (Array.isArray(invite?.apiConfigs) ? invite.apiConfigs : [])
    .map((config) => {
      let groupName = "";
      try {
        groupName = parseKeyGroupName(config?.groupName, { required: false });
      } catch {
        groupName = "";
      }
      return {
        id: boundedRecordText(config?.id, 128),
        name: boundedRecordText(config?.name, 80),
        baseUrl: boundedRecordText(approvedApiConfigUrl(env, config), 2048),
        credentialConfigured: Boolean(config?.apiKeyEncrypted || config?.apiKey),
        ...(groupName ? { groupName } : {}),
      };
    })
    .filter((config) => config.baseUrl)
    .slice(0, 8);
  const storedApiConfigCount = Number(invite?.apiConfigCount);
  return {
    uuid: boundedRecordText(invite?.uuid, 36),
    username: boundedRecordText(invite?.username, 100),
    name: boundedRecordText(invite?.name, 100),
    email: boundedRecordText(invite?.email, 160),
    remark: boundedRecordText(invite?.remark, 240),
    createdAt: boundedRecordText(invite?.createdAt, 64),
    updatedAt: boundedRecordText(invite?.updatedAt, 64),
    legacyUuidLoginUntil: boundedRecordText(invite?.legacyUuidLoginUntil, 64),
    accessKeyHmac: invite?.accessKeyHmac ? "configured" : "",
    credentialVersion: Number(invite?.credentialVersion || 0),
    accessCredentialVersion: Number(invite?.accessCredentialVersion || 0),
    apiConfigs,
    apiConfigCount: Number.isSafeInteger(storedApiConfigCount) && storedApiConfigCount >= 0
      ? Math.min(storedApiConfigCount, 10_000)
      : apiConfigs.length,
    sub2apiSync: {
      userId: Number(sync.userId || 0),
      tokenId: Number(sync.tokenId || 0),
      username: boundedRecordText(sync.username, 100),
      email: boundedRecordText(sync.email, 160),
      loginUrl: boundedRecordText(approvedPublicHttpsUrl(env, sync.loginUrl || ""), 2048),
      syncedAt: boundedRecordText(sync.syncedAt, 64),
      passwordChangedExternally: Boolean(sync.passwordChangedExternally),
    },
  };
}

function summarizeAdminTrashItem(item) {
  if (item?.type === "uuid") {
    const invite = item.invite || {};
    const storedRecordCount = Number(item.recordCount);
    return {
      id: boundedRecordText(item.id, 128),
      type: "uuid",
      deletedAt: boundedRecordText(item.deletedAt, 64),
      invite: {
        uuid: boundedRecordText(invite.uuid, 36),
        username: boundedRecordText(invite.username, 100),
        name: boundedRecordText(invite.name, 100),
        email: boundedRecordText(invite.email, 160),
      },
      recordCount: Number.isSafeInteger(storedRecordCount) && storedRecordCount >= 0
        ? Math.min(storedRecordCount, 20_000)
        : Math.min(Array.isArray(item.records) ? item.records.length : 0, 20_000),
    };
  }
  if (item?.type === "ip_group") {
    const group = item.group || {};
    const storedIpCount = Number(group.ipCount);
    return {
      id: boundedRecordText(item.id, 128),
      type: "ip_group",
      uuid: boundedRecordText(item.uuid, 36),
      deletedAt: boundedRecordText(item.deletedAt, 64),
      group: {
        country: boundedRecordText(group.country, 80),
        region: boundedRecordText(group.region, 120),
        city: boundedRecordText(group.city, 120),
        ipCount: Number.isSafeInteger(storedIpCount) && storedIpCount >= 0
          ? Math.min(storedIpCount, 20_000)
          : Math.min(Array.isArray(group.ips) ? group.ips.length : 0, 20_000),
      },
    };
  }
  return null;
}

async function saveInvites(env, invites) {
  if (isAuthStateBindingConfigured(env)) {
    const revision = requireCollectionRevision(invites, INVITES_REVISION);
    const result = await authStateStore(env).compareAndSwapInvites(revision, invites);
    requireAuthStateWrite(result);
    return result;
  }

  const protectedInvites = await Promise.all(
    invites.map((invite) => protectInviteCredentials(
      invite,
      env.CREDENTIAL_ENCRYPTION_KEY,
      env.INVITE_ACCESS_HMAC_KEY,
    )),
  );
  await env.INVITE_STORE.put(INVITES_KEY, JSON.stringify(protectedInvites));
}

async function getTrash(env) {
  if (isAuthStateBindingConfigured(env)) {
    const result = await authStateStore(env).readTrash();
    const trash = normalizeTrashCollection(result.items);
    return attachCollectionRevision(trash, TRASH_REVISION, result.revision);
  }

  const raw = await env.INVITE_STORE.get(TRASH_KEY);
  const trash = parseJson(raw, []);
  if (!Array.isArray(trash)) {
    return [];
  }

  return normalizeTrashCollection(trash);
}

function normalizeTrashCollection(trash) {
  return trash
    .filter((item) => item && item.id && item.type)
    .map(normalizeTrashItem)
    .filter(Boolean)
    .sort((left, right) => String(right.deletedAt || "").localeCompare(String(left.deletedAt || "")));
}

async function saveTrash(env, trash) {
  if (isAuthStateBindingConfigured(env)) {
    const revision = requireCollectionRevision(trash, TRASH_REVISION);
    const result = await authStateStore(env).compareAndSwapTrash(revision, trash);
    requireAuthStateWrite(result);
    return result;
  }
  await env.INVITE_STORE.put(TRASH_KEY, JSON.stringify(trash));
}

function attachCollectionRevision(items, symbol, revision) {
  if (!Array.isArray(items)) {
    throw new Error("auth_state_collection_invalid");
  }
  const normalizedRevision = Number(revision);
  if (!Number.isSafeInteger(normalizedRevision) || normalizedRevision < 0) {
    throw new Error("auth_state_revision_invalid");
  }
  Object.defineProperty(items, symbol, {
    value: normalizedRevision,
    enumerable: false,
  });
  return items;
}

function copyCollectionRevision(source, target, symbol) {
  if (!Object.hasOwn(source, symbol)) return target;
  return attachCollectionRevision(target, symbol, source[symbol]);
}

function requireCollectionRevision(items, symbol) {
  const revision = items?.[symbol];
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("auth_state_revision_required");
  }
  return revision;
}

function requireAuthStateWrite(result) {
  if (result?.ok === true) return result;
  throw new Error(result?.conflict ? "auth_state_conflict" : "auth_state_write_failed");
}

function normalizeTrashItem(item) {
  if (item.type === "uuid") {
    return {
      id: String(item.id || ""),
      type: "uuid",
      deletedAt: String(item.deletedAt || ""),
      invite: {
        ...sanitizeInviteForTrash(item.invite || {}),
        deletedAt: String(item.invite?.deletedAt || item.deletedAt || ""),
      },
      records: Array.isArray(item.records) ? item.records.map(normalizeIpGroup) : [],
    };
  }

  if (item.type === "ip_group") {
    return {
      id: String(item.id || ""),
      type: "ip_group",
      uuid: String(item.uuid || ""),
      group: item.group ? normalizeIpGroup(item.group) : null,
      deletedAt: String(item.deletedAt || ""),
    };
  }

  return null;
}

async function createInvite(env, uuid, data) {
  if (!isUuid(uuid)) {
    throw new Error("Invalid UUID");
  }

  const invites = await getStoredInvites(env);
  const existing = invites.find((invite) => invite.uuid === uuid);
  if (existing) {
    throw new Error("UUID already exists");
  }
  const username = validateInviteUsername(data.username, uuid);
  assertUniqueInviteUsername(invites, username, null);
  const now = new Date().toISOString();
  const keyGroup = parseKeyGroupName(data.keyGroup || DEFAULT_KEY_GROUP_NAME, { required: false }) || DEFAULT_KEY_GROUP_NAME;
  const syncResult = await provisionSub2ApiUser(env, {
    uuid,
    username: desiredSub2ApiUsername(username, uuid),
    name: username,
    email: data.email || "",
    remark: data.remark || "",
    sub2apiUserId: 0,
    loginPassword: "",
    keyGroup,
    tokens: desiredSub2ApiTokens(env, data.apiConfigs),
  });
  const apiConfigs = mergeSub2ApiConfig(env, data.apiConfigs, syncResult).map((config) => ({
    ...config,
    groupName: config.groupName || keyGroup,
  }));
  const sub2apiSync = await sub2apiSyncMetadata(env, syncResult);

  const issued = await issueInviteAccessCredential({
    uuid,
    username,
    name: username,
    email: data.email || "",
    remark: data.remark || "",
    apiConfigs,
    sub2apiSync,
    createdAt: now,
    updatedAt: now,
  }, env.INVITE_ACCESS_HMAC_KEY, new Date(now), false);
  invites.push(issued.invite);
  try {
    await saveInvites(env, invites);
  } catch (error) {
    await compensateProvisionConflict(env, uuid, issued.invite);
    throw error;
  }
  return issued;
}

async function migrateInviteCredentials(env, now = new Date(), returnHref = ADMIN_PATH) {
  const migratedAt = now.getTime();
  if (!Number.isFinite(migratedAt)) {
    throw new Error("Invalid credential migration timestamp");
  }

  if (isAuthStateBindingConfigured(env)) {
    const store = authStateStore(env);
    const batch = await store.readCredentialMigrationBatch(
      MAX_INVITE_CREDENTIAL_MIGRATION_BATCH,
    );
    const issued = [];
    const updates = [];
    for (const invite of batch.items) {
      const result = await issueInviteAccessCredential(
        invite,
        env.INVITE_ACCESS_HMAC_KEY,
        now,
        true,
      );
      issued.push({
        uuid: result.invite.uuid,
        username: inviteUsername(result.invite),
        accessKey: result.accessKey,
      });
      updates.push({
        uuid: result.invite.uuid,
        accessKeyHmac: result.invite.accessKeyHmac,
        expectedAccessCredentialVersion: Number(invite.accessCredentialVersion || 0),
      });
    }
    const response = prepareIssuedAccessKeysResponse(
      issued,
      Math.max(0, Number(batch.remainingCount || 0) - issued.length),
      returnHref,
    );
    if (updates.length > 0) {
      requireAuthStateWrite(await store.commitCredentialMigrationBatch(
        batch.revision,
        updates,
      ));
    }
    return response;
  }

  const invites = await getStoredInvites(env);
  const trash = await getTrash(env);
  const targets = invites
    .map((invite, index) => ({ invite, index }))
    .filter(({ invite }) => !invite.accessKeyHmac)
    .slice(0, MAX_INVITE_CREDENTIAL_MIGRATION_BATCH);
  const issued = [];
  for (const { invite, index } of targets) {
    const result = await issueInviteAccessCredential(
      invite,
      env.INVITE_ACCESS_HMAC_KEY,
      now,
      true,
    );
    invites[index] = result.invite;
    issued.push({
      uuid: result.invite.uuid,
      username: inviteUsername(result.invite),
      accessKey: result.accessKey,
    });
  }
  const remainingCount = invites.filter((invite) => !invite.accessKeyHmac).length;
  const response = prepareIssuedAccessKeysResponse(issued, remainingCount, returnHref);

  // Sanitize legacy trash before persisting any one-time access keys. If the
  // invite write fails, no generated key has been committed.
  await saveTrash(env, trash);
  if (issued.length > 0) {
    await saveInvites(env, invites);
  }
  return response;
}

async function finalizeLegacyAuthStateCleanup(env, now = Date.now()) {
  if (!isAuthStateBindingConfigured(env)) {
    throw new Error("auth_state_binding_required_for_legacy_cleanup");
  }
  const store = authStateStore(env);
  const status = await store.ready();
  if (status.legacyCleanupComplete === true) return status;

  const collection = await store.readInvites();
  assertLegacyAuthStateCleanupEligible(collection.items, now);
  const result = await store.purgeLegacySourceKeys();
  if (result?.cleaned !== true) {
    throw new Error(result?.busy ? "auth_state_legacy_cleanup_busy" : "auth_state_legacy_cleanup_failed");
  }
  return result;
}

function assertLegacyAuthStateCleanupEligible(invites, now = Date.now()) {
  if (!Array.isArray(invites) || !Number.isSafeInteger(Number(now)) || Number(now) < 0) {
    throw new Error("auth_state_legacy_cleanup_state_invalid");
  }
  for (const invite of invites) {
    if (
      Number(invite?.credentialVersion || 0) < 2
      || Number(invite?.accessCredentialVersion || 0) < 1
      || !/^[a-f0-9]{64}$/.test(String(invite?.accessKeyHmac || ""))
    ) {
      throw new Error("auth_state_legacy_cleanup_credentials_incomplete");
    }
    const deadlineText = String(invite?.legacyUuidLoginUntil || "");
    if (!deadlineText) continue;
    const deadline = Date.parse(deadlineText);
    if (!Number.isFinite(deadline) || deadline > Number(now)) {
      throw new Error("auth_state_legacy_cleanup_deadline_active");
    }
  }
}

async function rotateInviteAccessKey(env, uuid) {
  const invites = await getStoredInvites(env);
  const index = invites.findIndex((invite) => invite.uuid === uuid);
  if (index < 0) throw new Error("UUID not found");
  const result = await issueInviteAccessCredential(
    invites[index],
    env.INVITE_ACCESS_HMAC_KEY,
    new Date(),
    false,
  );
  invites[index] = result.invite;
  await saveInvites(env, invites);
  return {
    uuid,
    username: inviteUsername(result.invite),
    accessKey: result.accessKey,
  };
}

async function requireStepUpTotp(form, env) {
  const token = String(form.get("step_up_token") || "").replace(/\s+/g, "");
  if (!(await verifyAdminTotp(env, token))) {
    throw new Error("A valid 2FA code is required");
  }
}

async function updateInvite(env, originalUuid, data) {
  if (!isUuid(originalUuid) || !isUuid(data.uuid)) {
    throw new Error("Invalid UUID");
  }
  if (originalUuid !== data.uuid) {
    throw new Error("UUID is immutable");
  }

  const invites = await getStoredInvites(env);
  const inviteIndex = invites.findIndex((item) => item.uuid === originalUuid);
  if (inviteIndex < 0) {
    return;
  }

  const username = validateInviteUsername(data.username, data.uuid);
  assertUniqueInviteUsername(invites, username, originalUuid);
  const storedInvite = invites[inviteIndex];
  const invite = await revealStoredInvite(env, storedInvite);
  const apiConfigs = resolveExistingCredentialReferences(
    env,
    data.apiConfigs,
    storedInvite,
    invite,
  );
  const keyGroup = parseKeyGroupName(data.keyGroup || DEFAULT_KEY_GROUP_NAME, { required: false }) || DEFAULT_KEY_GROUP_NAME;

  const syncResult = await provisionSub2ApiUser(env, {
    uuid: data.uuid,
    username: desiredSub2ApiUsername(username, data.uuid),
    name: username,
    email: data.email || "",
    remark: data.remark || "",
    sub2apiUserId: invite.sub2apiSync?.userId || 0,
    loginPassword: invite.sub2apiSync?.loginPassword || "",
    keyGroup,
    tokens: desiredSub2ApiTokens(env, apiConfigs),
  });

  const now = new Date().toISOString();
  invite.uuid = data.uuid;
  invite.username = username;
  invite.name = username;
  invite.email = data.email || "";
  invite.remark = data.remark || "";
  invite.apiConfigs = mergeSub2ApiConfig(env, apiConfigs, syncResult).map((config) => ({
    ...config,
    groupName: config.groupName || keyGroup,
  }));
  invite.sub2apiSync = await sub2apiSyncMetadata(env, syncResult);
  invite.updatedAt = now;
  invites[inviteIndex] = invite;

  try {
    await saveInvites(env, invites);
  } catch (error) {
    await compensateProvisionConflict(env, invite.uuid, invite);
    throw error;
  }
}

async function deleteInvite(env, uuid) {
  return await withAllIpRecordsLease(env, async (lease) => {
    return await deleteInviteWithLease(env, uuid, lease);
  });
}

async function deleteInviteWithLease(env, uuid, lease) {
  const invites = await getStoredInvites(env);
  const invite = invites.find((item) => item.uuid === uuid);
  if (!invite) {
    return;
  }

  const groups = await getIpRecords(env, uuid);
  const protectedKeys = await getReferencedIpKeys(env, { excludeUuid: uuid }, lease);
  const now = new Date().toISOString();

  for (const group of groups) {
    await deleteCloudflareListItems(env, group.ips || [], protectedKeys);
  }

  await deprovisionSub2ApiUser(env, invite);

  const trash = await getTrash(env);
  const trashItem = {
    id: randomHex(12),
    type: "uuid",
    deletedAt: now,
    invite: {
      ...sanitizeInviteForTrash(invite),
      deletedAt: now,
    },
    records: groups,
  };

  if (isAuthStateBindingConfigured(env)) {
    const result = await authStateStore(env).removeInvite(
      requireCollectionRevision(invites, INVITES_REVISION),
      requireCollectionRevision(trash, TRASH_REVISION),
      uuid,
      trashItem,
    );
    if (result?.conflict) {
      const authoritative = await reconcileAuthoritativeInviteAfterConflict(env, uuid);
      if (authoritative) {
        await restoreAuthoritativeIpAccess(env, uuid, lease);
        throw new Error("auth_state_conflict");
      }
    } else {
      requireAuthStateWrite(result);
    }
  } else {
    trash.unshift(trashItem);
    await saveTrash(env, trash);
    await saveInvites(env, invites.filter((candidate) => candidate.uuid !== uuid));
  }
  await deleteIpRecords(env, uuid, lease);
}

async function restoreInviteFromTrash(env, trashId, lease = null) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "uuid");
  if (!item || !item.invite || !isUuid(item.invite.uuid)) {
    return;
  }
  if (!lease) {
    return await withIpRecordsLease(
      env,
      item.invite.uuid,
      async (claimedLease) => await restoreInviteFromTrash(env, trashId, claimedLease),
    );
  }

  const invites = await getStoredInvites(env);
  if (invites.some((invite) => invite.uuid === item.invite.uuid)) {
    throw new Error("UUID already exists");
  }

  const invite = { ...item.invite };
  const username = validateInviteUsername(inviteUsername(invite), invite.uuid);
  assertUniqueInviteUsername(invites, username, null);
  const syncResult = await provisionSub2ApiUser(env, {
    uuid: invite.uuid,
    username: desiredSub2ApiUsername(username, invite.uuid),
    name: username,
    email: invite.email || "",
    remark: invite.remark || "",
    sub2apiUserId: invite.sub2apiSync?.userId || 0,
    loginPassword: invite.sub2apiSync?.loginPassword || "",
    keyGroup: provisionKeyGroup(invite),
    tokens: desiredSub2ApiTokens(env, invite.apiConfigs),
  });

  invite.username = username;
  invite.name = username;
  invite.apiConfigs = mergeSub2ApiConfig(env, invite.apiConfigs, syncResult);
  invite.sub2apiSync = await sub2apiSyncMetadata(env, syncResult);
  invite.updatedAt = new Date().toISOString();
  delete invite.deletedAt;

  let previousRecordsRaw = null;
  let previousRecordsLoaded = false;
  const restoredGroups = [];
  let issued;
  try {
    previousRecordsRaw = await getRawIpRecords(env, invite.uuid);
    previousRecordsLoaded = true;
    for (const group of item.records || []) {
      restoredGroups.push(await restoreCloudflareListItems(env, group, invite.uuid, lease));
    }

    issued = await issueInviteAccessCredential(
      invite,
      env.INVITE_ACCESS_HMAC_KEY,
      new Date(),
      false,
    );
    await putIpRecords(env, invite.uuid, restoredGroups, lease);

    if (isAuthStateBindingConfigured(env)) {
      const result = await authStateStore(env).restoreInvite(
        requireCollectionRevision(invites, INVITES_REVISION),
        requireCollectionRevision(trash, TRASH_REVISION),
        trashId,
        issued.invite,
      );
      requireAuthStateWrite(result);
    } else {
      invites.push(issued.invite);
      await saveInvites(env, invites);
      await saveTrash(env, trash.filter((entry) => entry.id !== trashId));
    }
  } catch (error) {
    if (issued && !isAuthStateConflict(error) && isAuthStateBindingConfigured(env)) {
      try {
        const authoritative = await getInviteByUuid(env, invite.uuid);
        if (authoritative?.accessKeyHmac === issued.invite.accessKeyHmac) {
          await putIpRecords(env, invite.uuid, restoredGroups, lease);
          await finalizeCloudflareMutationIds(
            env,
            cloudflareMutationIdsFromGroups(restoredGroups),
          );
          return {
            uuid: issued.invite.uuid,
            username: inviteUsername(issued.invite),
            accessKey: issued.accessKey,
          };
        }
      } catch {
        // Continue into the fail-closed compensation path below.
      }
    }

    let compensationFailed = false;
    if (previousRecordsLoaded) {
      try {
        await restoreRawIpRecords(env, invite.uuid, previousRecordsRaw, lease);
      } catch {
        compensationFailed = true;
      }
    }

    let authoritative = null;
    if (isAuthStateBindingConfigured(env)) {
      try {
        authoritative = await reconcileAuthoritativeInviteAfterConflict(env, invite.uuid);
      } catch {
        compensationFailed = true;
      }
    }
    try {
      if (authoritative) {
        await rollbackRestoredIpAccess(env, restoredGroups, lease);
        await restoreAuthoritativeIpAccess(env, invite.uuid, lease);
      } else {
        await rollbackRestoredExternalState(env, issued?.invite || invite, restoredGroups, lease);
      }
    } catch {
      compensationFailed = true;
    }
    if (compensationFailed) {
      console.error(JSON.stringify({ level: "error", message: "auth_state_compensation_failed" }));
      throw new Error("auth_state_compensation_failed");
    }
    throw error;
  }

  await finalizeCloudflareMutationIds(env, cloudflareMutationIdsFromGroups(restoredGroups));
  return {
    uuid: issued.invite.uuid,
    username: inviteUsername(issued.invite),
    accessKey: issued.accessKey,
  };
}

async function compensateProvisionConflict(env, uuid, provisionalInvite) {
  try {
    const authoritative = await reconcileAuthoritativeInviteAfterConflict(env, uuid);
    if (!authoritative) {
      await deprovisionSub2ApiUser(env, provisionalInvite);
    }
    return authoritative;
  } catch {
    console.error(JSON.stringify({ level: "error", message: "auth_state_compensation_failed" }));
    throw new Error("auth_state_compensation_failed");
  }
}

async function reconcileAuthoritativeInviteAfterConflict(env, uuid) {
  for (let attempt = 0; attempt < AUTH_STATE_RECONCILE_ATTEMPTS; attempt += 1) {
    const invites = await getInvites(env);
    const invite = invites.find((item) => item.uuid === uuid);
    if (!invite) return null;

    const sync = invite.sub2apiSync || {};
    const loginPassword = String(sync.loginPassword || "");
    const syncResult = await provisionSub2ApiUser(env, {
      uuid: invite.uuid,
      username: desiredSub2ApiUsername(inviteUsername(invite), invite.uuid),
      name: inviteUsername(invite) || invite.uuid,
      email: invite.email || "",
      remark: invite.remark || "",
      sub2apiUserId: sync.userId || 0,
      loginPassword,
      resetLoginPassword: loginPassword.length >= 8 && loginPassword.length <= 64,
      tokens: desiredSub2ApiTokens(env, invite.apiConfigs),
    });

    invite.apiConfigs = mergeSub2ApiConfig(env, invite.apiConfigs, syncResult);
    invite.sub2apiSync = await sub2apiSyncMetadata(env, syncResult);
    invite.updatedAt = new Date().toISOString();
    try {
      await saveInvites(env, invites);
      return invite;
    } catch (error) {
      if (!isAuthStateConflict(error)) throw error;
    }
  }
  throw new Error("auth_state_compensation_failed");
}

async function restoreAuthoritativeIpAccess(env, uuid, lease = null) {
  if (!lease) {
    return await withIpRecordsLease(
      env,
      uuid,
      async (claimedLease) => await restoreAuthoritativeIpAccess(env, uuid, claimedLease),
    );
  }
  const groups = await getIpRecords(env, uuid);
  const restoredGroups = [];
  for (const group of groups) {
    restoredGroups.push(await restoreCloudflareListItems(env, group, uuid, lease));
  }
  const mutationIds = cloudflareMutationIdsFromGroups(restoredGroups);
  try {
    await putIpRecords(env, uuid, restoredGroups, lease);
  } catch (error) {
    await compensateCloudflareMutationIds(env, mutationIds, lease);
    throw error;
  }
  await finalizeCloudflareMutationIds(env, mutationIds);
}

async function rollbackRestoredExternalState(env, provisionalInvite, restoredGroups, lease = null) {
  let failed = false;
  try {
    await rollbackRestoredIpAccess(env, restoredGroups, lease);
  } catch {
    failed = true;
  }

  try {
    await deprovisionSub2ApiUser(env, provisionalInvite);
  } catch {
    failed = true;
  }

  if (failed) throw new Error("auth_state_compensation_failed");
}

async function rollbackRestoredIpAccess(env, restoredGroups, lease = null) {
  await compensateCloudflareMutationIds(env, cloudflareMutationIdsFromGroups(restoredGroups), lease);
}

async function purgeInviteTrash(env, trashId) {
  return await withAllIpRecordsLease(env, async (lease) => {
    return await purgeInviteTrashWithLease(env, trashId, lease);
  });
}

async function purgeInviteTrashWithLease(env, trashId, lease) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "uuid");
  if (!item) {
    return;
  }

  const protectedKeys = await getReferencedIpKeys(env, {}, lease);
  for (const group of item.records || []) {
    await deleteCloudflareListItems(env, group.ips || [], protectedKeys);
  }
  await purgeSub2ApiUser(env, item.invite || {});
  await purgeTrashItem(env, trash, trashId);
}

export async function cleanupExpiredIpGroups(env, now = new Date(), lease = null) {
  if (!hasCloudflareListConfig(env) || !env.INVITE_STORE) {
    console.error(JSON.stringify({ level: "error", message: "ip_cleanup_missing_configuration" }));
    return { checked: 0, deleted: 0 };
  }
  if (!lease) {
    return await withAllIpRecordsLease(
      env,
      async (claimedLease) => await cleanupExpiredIpGroups(env, now, claimedLease),
    );
  }

  const reconciliation = await reconcilePendingCloudflareMutations(env, now.getTime(), lease);
  const invites = await getStoredInvites(env);
  const protectedKeys = new Set();
  const expiredIps = [];
  const updates = [];
  let checked = 0;
  let deleted = 0;
  let orphaned = 0;

  for (const invite of invites) {
    const groups = await getIpRecords(env, invite.uuid);
    checked += groups.length;
    for (const group of groups) {
      if (!isExpired(group.expiresAt, now)) {
        addIpReferences(protectedKeys, group.ips || []);
      }
    }
  }

  for (const invite of invites) {
    const groups = await getIpRecords(env, invite.uuid);
    const expiredGroups = groups.filter((group) => isExpired(group.expiresAt, now));
    if (expiredGroups.length === 0) {
      continue;
    }

    for (const group of expiredGroups) {
      expiredIps.push(...(group.ips || []));
    }

    const nextGroups = groups.filter((group) => !isExpired(group.expiresAt, now));
    updates.push({ uuid: invite.uuid, groups: nextGroups });
    deleted += expiredGroups.length;
  }

  await deleteCloudflareListItems(env, expiredIps, protectedKeys);
  for (const update of updates) {
    if (update.groups.length === 0) {
      await deleteIpRecords(env, update.uuid, lease);
    } else {
      await putIpRecords(env, update.uuid, update.groups, lease);
    }
  }

  const pendingMutationComments = isAuthStateBindingConfigured(env)
    ? new Set(await authStateStore(env).listCloudflareMutationComments())
    : new Set();
  const currentProtectedKeys = await getReferencedIpKeys(env, {}, lease);
  orphaned = await deleteOrphanedCloudflareListItems(
    env,
    currentProtectedKeys,
    pendingMutationComments,
  );

  console.log(JSON.stringify({
    level: "info",
    message: "ip_cleanup_complete",
    checked,
    deleted,
    orphaned,
    reconciled: reconciliation.checked,
  }));
  return { checked, deleted, orphaned, reconciled: reconciliation.checked };
}

async function deleteIpGroup(env, uuid, groupId) {
  return await withAllIpRecordsLease(env, async (lease) => {
    return await deleteIpGroupWithLease(env, uuid, groupId, lease);
  });
}

async function deleteIpGroupWithLease(env, uuid, groupId, lease) {
  const groups = await getIpRecords(env, uuid);
  const group = groups.find((item) => item.id === groupId);
  if (!group) {
    return;
  }

  const protectedKeys = await getReferencedIpKeys(
    env,
    { excludedGroups: new Map([[uuid, new Set([groupId])]]) },
    lease,
  );
  await deleteCloudflareListItems(env, group.ips || [], protectedKeys);
  const trash = await getTrash(env);
  trash.unshift({
    id: randomHex(12),
    type: "ip_group",
    deletedAt: new Date().toISOString(),
    uuid,
    group,
  });
  await saveTrash(env, trash);
  await putIpRecords(env, uuid, groups.filter((item) => item.id !== groupId), lease);
}

async function restoreIpGroupFromTrash(env, trashId, lease = null) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "ip_group");
  if (!item || !isUuid(item.uuid) || !item.group) {
    return;
  }
  if (!lease) {
    return await withIpRecordsLease(
      env,
      item.uuid,
      async (claimedLease) => await restoreIpGroupFromTrash(env, trashId, claimedLease),
    );
  }

  const invites = await getStoredInvites(env);
  if (!invites.some((invite) => invite.uuid === item.uuid)) {
    throw new Error("UUID must be restored before this IP group");
  }

  const groups = await getIpRecords(env, item.uuid);
  const restoredGroup = await restoreCloudflareListItems(env, item.group, item.uuid, lease);
  const nextGroups = upsertIpGroup(groups, restoredGroup).slice(0, 50);
  const mutationIds = cloudflareMutationIdsFromGroups([restoredGroup]);

  try {
    await putIpRecords(env, item.uuid, nextGroups, lease);
  } catch (error) {
    await compensateCloudflareMutationIds(env, mutationIds, lease);
    throw error;
  }
  await finalizeCloudflareMutationIds(env, mutationIds);
  await purgeTrashItem(env, trash, trashId);
}

async function purgeIpGroupTrash(env, trashId) {
  return await withAllIpRecordsLease(env, async (lease) => {
    return await purgeIpGroupTrashWithLease(env, trashId, lease);
  });
}

async function purgeIpGroupTrashWithLease(env, trashId, lease) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "ip_group");
  if (!item) {
    return;
  }

  const protectedKeys = await getReferencedIpKeys(env, {}, lease);
  await deleteCloudflareListItems(env, item.group?.ips || [], protectedKeys);
  await purgeTrashItem(env, trash, trashId);
}

async function purgeTrashItem(env, trash, trashId) {
  if (isAuthStateBindingConfigured(env)) {
    const result = await authStateStore(env).purgeTrash(
      requireCollectionRevision(trash, TRASH_REVISION),
      trashId,
    );
    requireAuthStateWrite(result);
    return;
  }
  await saveTrash(env, trash.filter((entry) => entry.id !== trashId));
}

async function updateIpGroupExpiration(env, uuid, groupId, expiresAt, lease = null) {
  if (!expiresAt) {
    throw new Error("Invalid expiration timestamp");
  }
  if (!lease) {
    return await withIpRecordsLease(
      env,
      uuid,
      async (claimedLease) => await updateIpGroupExpiration(env, uuid, groupId, expiresAt, claimedLease),
    );
  }

  const groups = await getIpRecords(env, uuid);
  const nextGroups = groups.map((group) => group.id === groupId ? { ...group, expiresAt } : group);
  await putIpRecords(env, uuid, nextGroups, lease);
}

async function addVisitorIpsToCloudflareList(env, ips, lease = null) {
  try {
    const result = await ensureManagedCloudflareEntries(env, (ips || []).map((item) => ({
      ...item,
      listValue: item.cidr || item.ip,
    })), lease);
    return {
      ok: true,
      status: 200,
      errors: [],
      messages: [],
      items: result.items,
      mutationIds: result.mutationIds,
    };
  } catch {
    return {
      ok: false,
      status: 502,
      errors: [{ code: "cloudflare_list_mutation_failed" }],
      messages: [],
      items: [],
      mutationIds: [],
    };
  }
}

async function ensureManagedCloudflareEntries(env, entries, lease = null) {
  const existingItems = await findCloudflareListItems(env);
  const existingByIp = new Map(existingItems.map((item) => [String(item.ip || ""), item]));
  const normalized = (entries || []).map((entry) => {
    const listValue = String(entry.listValue || entry.cidr || entry.ip || "");
    const existing = existingByIp.get(listValue) || existingByIp.get(String(entry.ip || ""));
    return {
      ...entry,
      listValue,
      listItemId: existing ? String(existing.id || "") : "",
      alreadyListed: Boolean(existing),
    };
  });
  const valuesToCreate = [...new Set(
    normalized.filter((item) => item.listValue && !item.listItemId).map((item) => item.listValue),
  )];
  if (valuesToCreate.length === 0) return { items: normalized, mutationIds: [] };

  let mutation;
  try {
    mutation = await createManagedCloudflareListItems(
      env,
      valuesToCreate,
      Date.now(),
      authStateStore(env),
    );
  } catch (error) {
    const mutationId = cloudflareMutationIdFromError(error);
    if (mutationId) {
      try {
        await compensateCloudflareMutation(env, mutationId, null, Date.now(), lease);
      } catch {
        // The bounded ledger retains the marker for scheduled reconciliation.
      }
    }
    // A post-compensation re-list can briefly return a deleted item because
    // the Rules Lists API is eventually consistent. Never convert an
    // ambiguous mutation into an unowned "already listed" success.
    throw new Error("Cloudflare allowlist update failed");
  }

  const createdByIp = new Map(mutation.items.map((item) => [String(item.ip || ""), item]));
  return {
    mutationIds: [mutation.mutationId],
    items: normalized.map((item) => {
      const created = createdByIp.get(item.listValue);
      return created ? { ...item, listItemId: created.id, alreadyListed: false } : item;
    }),
  };
}

async function addManualIpGroup(env, uuid, ipValue, expiresAt, lease = null) {
  if (!isUuid(uuid)) {
    throw new Error("Invalid UUID");
  }
  if (!expiresAt) {
    throw new Error("Invalid expiration timestamp");
  }
  if (!lease) {
    return await withIpRecordsLease(
      env,
      uuid,
      async (claimedLease) => await addManualIpGroup(env, uuid, ipValue, expiresAt, claimedLease),
    );
  }

  const invites = await getStoredInvites(env);
  if (!invites.some((invite) => invite.uuid === uuid)) {
    throw new Error("UUID not found");
  }

  const entries = expandManualIpEntries(ipValue);

  const managed = await ensureManagedCloudflareEntries(env, entries, lease);

  const now = new Date().toISOString();
  const location = await lookupIpLocation(env, entries[0]?.ip || "", {});
  const groups = await getIpRecords(env, uuid);
  const group = {
    id: randomHex(12),
    addedAt: now,
    updatedAt: now,
    expiresAt,
    country: location.country,
    region: location.region,
    city: location.city,
    timezone: location.timezone,
    colo: stringOrEmpty(location.colo),
    asn: location.asn || "",
    asOrganization: stringOrEmpty(location.asOrganization),
    geoSource: location.source,
    ips: managed.items,
  };

  const nextGroups = upsertIpGroup(groups, group).slice(0, 50);
  try {
    await putIpRecords(env, uuid, nextGroups, lease);
  } catch (error) {
    await compensateCloudflareMutationIds(env, managed.mutationIds, lease);
    throw error;
  }
  await finalizeCloudflareMutationIds(env, managed.mutationIds);
}

export async function getInviteIpRecords(env, uuid) {
  return await getIpRecords(env, uuid);
}

async function getIpRecords(env, uuid) {
  const raw = await getRawIpRecords(env, uuid);
  const records = parseJson(raw, []);
  return Array.isArray(records) ? records.map(normalizeIpGroup) : [];
}

async function getAdminIpRecords(env, uuid) {
  const raw = await getRawIpRecords(env, uuid);
  if (typeof raw !== "string" || !raw) return { records: [], recordsOversized: false };
  if (exceedsUtf8ByteLimit(raw, ADMIN_RECORD_PAYLOAD_MAX_BYTES)) {
    console.error(JSON.stringify({ level: "error", message: "admin_ip_records_payload_too_large" }));
    return { records: [], recordsOversized: true };
  }
  const records = parseJson(raw, []);
  return {
    records: Array.isArray(records) ? records.slice(0, 50).map(normalizeIpGroup) : [],
    recordsOversized: false,
  };
}

async function getRawIpRecords(env, uuid) {
  return isAuthStateBindingConfigured(env)
    ? await authStateStore(env).getRecords(uuid)
    : await env.INVITE_STORE.get(recordsKey(uuid));
}

async function restoreRawIpRecords(env, uuid, raw, lease) {
  if (raw === null || raw === undefined || raw === "") {
    await deleteIpRecords(env, uuid, lease);
    return;
  }
  const records = parseJson(raw, null);
  if (!Array.isArray(records)) throw new Error("ip_records_restore_invalid");
  await putIpRecords(env, uuid, records, lease);
}

function exceedsUtf8ByteLimit(value, limit) {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff
      && index + 1 < value.length
      && value.charCodeAt(index + 1) >= 0xdc00
      && value.charCodeAt(index + 1) <= 0xdfff) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
    if (bytes > limit) return true;
  }
  return false;
}

async function putIpRecords(env, uuid, records, lease) {
  requireIpRecordsLease(env, uuid, lease);
  if (isAuthStateBindingConfigured(env)) {
    await authStateStore(env).putRecords(uuid, records);
    return;
  }
  await env.INVITE_STORE.put(recordsKey(uuid), JSON.stringify(records));
}

async function deleteIpRecords(env, uuid, lease) {
  requireIpRecordsLease(env, uuid, lease);
  if (isAuthStateBindingConfigured(env)) {
    await authStateStore(env).deleteRecords(uuid);
    return;
  }
  await env.INVITE_STORE.delete(recordsKey(uuid));
}

function normalizeIpGroup(record) {
  const source = record && typeof record === "object" ? record : {};
  if (Array.isArray(source.ips)) {
    return {
      id: boundedRecordText(source.id, 64) || randomHex(12),
      addedAt: boundedRecordText(source.addedAt, 64),
      updatedAt: boundedRecordText(source.updatedAt || source.addedAt, 64),
      expiresAt: boundedRecordText(source.expiresAt, 64)
        || addDaysIso(source.addedAt || new Date().toISOString(), DEFAULT_IP_TTL_DAYS),
      country: boundedRecordText(source.country, 80),
      region: boundedRecordText(source.region, 120),
      city: boundedRecordText(source.city, 120),
      timezone: boundedRecordText(source.timezone, 80),
      colo: boundedRecordText(source.colo, 32),
      asn: boundedRecordText(source.asn, 32),
      asOrganization: boundedRecordText(source.asOrganization, 200),
      geoSource: boundedRecordText(source.geoSource, 32),
      ips: source.ips.map(normalizeIpItem).filter((item) => item.ip || item.listValue),
    };
  }

  const ip = boundedRecordText(source.ip, 160);
  const cidr = boundedRecordText(source.cidr, 180)
    || (ip ? (ip.includes(":") ? `${ip}/128` : ipv4Cidr24(ip)) : "");
  return {
    id: boundedRecordText(source.id, 64) || randomHex(12),
    addedAt: boundedRecordText(source.addedAt, 64),
    updatedAt: boundedRecordText(source.updatedAt || source.addedAt, 64),
    expiresAt: boundedRecordText(source.expiresAt, 64)
      || addDaysIso(source.addedAt || new Date().toISOString(), DEFAULT_IP_TTL_DAYS),
    country: boundedRecordText(source.country, 80),
    region: boundedRecordText(source.region, 120),
    city: boundedRecordText(source.city, 120),
    timezone: boundedRecordText(source.timezone, 80),
    colo: boundedRecordText(source.colo, 32),
    asn: boundedRecordText(source.asn, 32),
    asOrganization: boundedRecordText(source.asOrganization, 200),
    geoSource: boundedRecordText(source.geoSource, 32),
    ips: ip ? [{
      ip,
      version: ip.includes(":") ? "IPv6" : "IPv4",
      cidr,
      listValue: cidr,
      listItemId: boundedRecordText(source.listItemId, 128),
      alreadyListed: Boolean(source.alreadyListed),
    }] : [],
  };
}

function normalizeIpItem(item) {
  const source = item && typeof item === "object" ? item : {};
  const ip = boundedRecordText(source.ip, 160);
  const cidr = boundedRecordText(source.cidr, 180);
  return {
    ip,
    version: boundedRecordText(source.version, 8),
    cidr,
    listValue: boundedRecordText(source.listValue || cidr || ip, 180),
    listItemId: boundedRecordText(source.listItemId, 128),
    alreadyListed: Boolean(source.alreadyListed),
  };
}

function boundedRecordText(value, maximum) {
  return typeof value === "string" ? value.slice(0, maximum) : "";
}

async function deleteCloudflareListItems(env, ips, protectedKeys = new Set()) {
  const currentItems = await findCloudflareListItems(env);
  const ids = resolveCurrentCloudflareDeleteIds(ips, currentItems, protectedKeys);
  if (ids.length === 0) {
    return;
  }
  await deleteCloudflareListItemIds(env, ids);
}

function resolveCurrentCloudflareDeleteIds(ips, currentItems, protectedKeys = new Set()) {
  const currentByValue = new Map(
    (currentItems || []).map((item) => [String(item.ip || ""), String(item.id || "")]),
  );
  const ids = new Set();
  for (const item of ips || []) {
    if (isIpReferenced(protectedKeys, item)) continue;
    const value = String(item.listValue || item.cidr || item.ip || "");
    const currentId = currentByValue.get(value);
    if (currentId) ids.add(currentId);
  }
  return [...ids];
}

async function restoreCloudflareListItems(env, group, uuid, lease = null) {
  void uuid;
  const managed = await ensureManagedCloudflareEntries(env, (group.ips || []).map((item) => ({
    ...item,
    listValue: item.listValue || item.cidr || item.ip,
  })), lease);
  const restored = {
    ...group,
    updatedAt: new Date().toISOString(),
    ips: managed.items,
  };
  Object.defineProperty(restored, CLOUDFLARE_MUTATION_IDS, {
    value: managed.mutationIds,
    enumerable: false,
  });
  return restored;
}

async function finalizeCloudflareMutationIds(env, mutationIds) {
  const store = isAuthStateBindingConfigured(env) ? authStateStore(env) : null;
  for (const mutationId of new Set(mutationIds || [])) {
    try {
      await resolveCloudflareMutation(env, mutationId, store);
    } catch {
      console.error(JSON.stringify({ level: "error", message: "cloudflare_mutation_finalize_deferred" }));
    }
  }
}

async function compensateCloudflareMutationIds(env, mutationIds, lease = null) {
  let failed = false;
  for (const mutationId of new Set(mutationIds || [])) {
    try {
      await compensateCloudflareMutation(env, mutationId, null, Date.now(), lease);
    } catch {
      failed = true;
    }
  }
  if (failed) {
    console.error(JSON.stringify({ level: "error", message: "cloudflare_mutation_compensation_failed" }));
    throw new Error("cloudflare_mutation_compensation_failed");
  }
}

async function compensateCloudflareMutation(
  env,
  mutationId,
  marker = null,
  now = Date.now(),
  lease = null,
) {
  if (lease?.scope !== "all") {
    return await withAllIpRecordsLease(
      env,
      async (maintenanceLease) => await compensateCloudflareMutation(
        env,
        mutationId,
        marker,
        now,
        maintenanceLease,
      ),
      lease,
    );
  }
  const store = authStateStore(env);
  const currentMarker = marker || await store.getCloudflareMutation(mutationId);
  if (!currentMarker) return { deleted: 0, retained: 0, pending: false };

  try {
    const listItems = await findCloudflareListItems(env);
    const candidates = await findCloudflareMutationCandidates(env, currentMarker, listItems);
    if (candidates.length === 0 && now < currentMarker.notBefore) {
      await store.releaseCloudflareMutation(mutationId, currentMarker.notBefore);
      return { deleted: 0, retained: 0, pending: true };
    }

    const protectedKeys = await getReferencedIpKeys(env, {}, lease);
    const deletable = candidates.filter((item) => !isIpReferenced(protectedKeys, {
      listItemId: String(item.id || ""),
      listValue: String(item.ip || ""),
      ip: String(item.ip || ""),
    }));
    await deleteCloudflareListItemIds(
      env,
      deletable.map((item) => String(item.id || "")),
    );
    await store.resolveCloudflareMutation(mutationId);
    return {
      deleted: deletable.length,
      retained: candidates.length - deletable.length,
      pending: false,
    };
  } catch {
    try {
      await store.releaseCloudflareMutation(
        mutationId,
        Math.max(Number(currentMarker.notBefore || 0), now + CLOUDFLARE_MUTATION_RETRY_MS),
      );
    } catch {
      // The lease expires automatically, so a later scheduler run can reclaim it.
    }
    throw new Error("cloudflare_mutation_compensation_failed");
  }
}

async function reconcilePendingCloudflareMutations(env, now = Date.now(), lease = null) {
  if (!isAuthStateBindingConfigured(env)) return { checked: 0, deleted: 0, retained: 0 };
  const store = authStateStore(env);
  const markers = await store.claimCloudflareMutations(now, 25, 60_000);
  let deleted = 0;
  let retained = 0;
  for (const marker of markers) {
    try {
      const result = await compensateCloudflareMutation(
        env,
        marker.mutationId,
        marker,
        now,
        lease,
      );
      deleted += result.deleted;
      retained += result.retained;
    } catch {
      console.error(JSON.stringify({ level: "error", message: "cloudflare_mutation_reconcile_deferred" }));
    }
  }
  return { checked: markers.length, deleted, retained };
}

function cloudflareMutationIdsFromGroups(groups) {
  return (groups || []).flatMap((group) => group?.[CLOUDFLARE_MUTATION_IDS] || []);
}

async function deleteCloudflareListItemIds(env, ids) {
  if (!Array.isArray(ids)) throw new Error("Cloudflare list item delete failed");
  const requestedIds = ids.map((id) => String(id || ""));
  if (requestedIds.some((id) => !CLOUDFLARE_LIST_ITEM_ID.test(id))) {
    throw new Error("Cloudflare list item delete failed");
  }
  const normalizedIds = [...new Set(requestedIds)].sort();
  for (let offset = 0; offset < normalizedIds.length; offset += CLOUDFLARE_DELETE_BATCH_SIZE) {
    const batch = normalizedIds.slice(offset, offset + CLOUDFLARE_DELETE_BATCH_SIZE);
    const response = await cloudflareApiFetch(
      env,
      `/rules/lists/${env.IP_LIST_ID}/items?per_page=100`,
      {
        method: "DELETE",
        body: JSON.stringify({ items: batch.map((id) => ({ id })) }),
      },
    );
    const payload = await readCloudflareJson(response);
    if (!response.ok || payload.success !== true) {
      console.error(JSON.stringify({ level: "error", message: "list_delete_failed", status: response.status }));
      throw new Error("Cloudflare list item delete failed");
    }
    if (!isCloudflareIdentifier(payload?.result?.operation_id)) {
      console.error(JSON.stringify({ level: "error", message: "list_delete_operation_invalid" }));
      throw new Error("Cloudflare list item delete failed");
    }
    await waitForCloudflareOperation(env, payload);
  }
}

async function deleteOrphanedCloudflareListItems(env, protectedKeys, pendingMutationComments = new Set()) {
  const listItems = await findCloudflareListItems(env);
  const ids = [];

  for (const listItem of listItems) {
    const comment = String(listItem.comment || "");
    if (!MANAGED_CLOUDFLARE_COMMENT.test(comment) || pendingMutationComments.has(comment)) {
      continue;
    }

    if (isIpReferenced(protectedKeys, { listItemId: listItem.id, listValue: listItem.ip, ip: listItem.ip })) {
      continue;
    }

    if (isCloudflareIdentifier(listItem.id)) ids.push(String(listItem.id));
  }

  await deleteCloudflareListItemIds(env, ids);
  return ids.length;
}

async function findCloudflareListItems(env) {
  const result = await listCloudflareItems(env);
  if (!result.ok) {
    throw new Error("Cloudflare list lookup failed");
  }
  return result.items;
}

async function getReferencedIpKeys(env, options = {}, lease = null) {
  if (isAuthStateBindingConfigured(env) && lease?.scope !== "all") {
    throw new Error("ip_records_maintenance_lease_required");
  }
  const keys = new Set();
  const invites = await getStoredInvites(env);
  const excludedGroups = options.excludedGroups || new Map();

  for (const invite of invites) {
    if (invite.uuid === options.excludeUuid) {
      continue;
    }

    const groups = await getIpRecords(env, invite.uuid);
    const excludedGroupIds = excludedGroups.get(invite.uuid) || new Set();
    for (const group of groups) {
      if (excludedGroupIds.has(group.id)) {
        continue;
      }
      addIpReferences(keys, group.ips || []);
    }
  }

  return keys;
}

function addIpReferences(keys, ips) {
  for (const item of ips) {
    if (item.listItemId) {
      keys.add(`id:${item.listItemId}`);
    }

    const value = item.listValue || item.cidr || item.ip;
    if (value) {
      keys.add(`value:${value}`);
    }
  }
}

function isIpReferenced(keys, item) {
  const value = item.listValue || item.cidr || item.ip;
  return Boolean(
    (item.listItemId && keys.has(`id:${item.listItemId}`)) ||
    (value && keys.has(`value:${value}`)),
  );
}

function hasCloudflareListConfig(env) {
  return Boolean(env.ACCOUNT_ID && env.IP_LIST_ID && env.CLOUDFLARE_API_TOKEN);
}

function isExpired(expiresAt, now) {
  if (!expiresAt) {
    return false;
  }

  const expiresTime = Date.parse(expiresAt);
  return Number.isFinite(expiresTime) && expiresTime <= now.getTime();
}

async function findCloudflareListItem(env, ip) {
  const items = await findCloudflareListItems(env);
  return items.find((item) => item.ip === ip) || null;
}

function configuredAdminTotpSecrets(env) {
  return [String(env?.ADMIN_TOTP_SECRET || "")];
}

function decodeConfiguredAdminTotpSecret(secret, name) {
  try {
    return base32Decode(secret);
  } catch {
    throw new Error(`${name} must be 16-128 Base32 characters.`);
  }
}

async function verifyAdminTotp(env, token) {
  try {
    return await verifyTotp(configuredAdminTotpSecrets(env)[0], token);
  } catch {
    return false;
  }
}

async function adminSessionTotpBinding(canonicalSecret, bindingSecret = "") {
  const bindingKey = String(bindingSecret || "");
  if (bindingKey.length < 32) {
    throw new Error("INVITE_ACCESS_HMAC_KEY must be at least 32 characters");
  }
  const secret = decodeConfiguredAdminTotpSecret(
    canonicalSecret,
    "ADMIN_TOTP_SECRET",
  );
  const domain = new TextEncoder().encode(ADMIN_SESSION_TOTP_BINDING_DOMAIN);
  const size = domain.byteLength + 1 + secret.byteLength;
  const material = new Uint8Array(size);
  let offset = 0;
  material.set(domain, offset);
  offset += domain.byteLength;
  material[offset] = secret.byteLength;
  offset += 1;
  material.set(secret, offset);
  return await hmacSha256HexBytes(bindingKey, material);
}

async function adminSessionTotpBindingForEnvironment(env) {
  return await adminSessionTotpBinding(
    env.ADMIN_TOTP_SECRET,
    env.INVITE_ACCESS_HMAC_KEY,
  );
}

async function sessionMatchesAdminTotpBinding(session, env) {
  if (!ADMIN_SESSION_TOTP_BINDING.test(String(session?.totpBinding || ""))) return false;
  try {
    return await timingSafeEqual(
      session.totpBinding,
      await adminSessionTotpBindingForEnvironment(env),
    );
  } catch {
    return false;
  }
}

async function verifyTotp(secret, token) {
  if (!/^\d{6}$/.test(token)) {
    return false;
  }

  try {
    const now = Math.floor(Date.now() / 1000 / 30);
    for (const offset of [-1, 0, 1]) {
      const expected = await totp(secret, now + offset);
      if (await timingSafeEqual(token, expected)) {
        return true;
      }
    }
  } catch {
    return false;
  }

  return false;
}

async function totp(secret, counter) {
  const keyBytes = base32Decode(secret);
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(4, counter);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 0xf;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  return String(binary % 1_000_000).padStart(6, "0");
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(value || "").trim().toUpperCase();
  if (!/^[A-Z2-7]{16,128}$/.test(clean)) {
    throw new Error("ADMIN_TOTP_SECRET must be 16-128 Base32 characters");
  }
  let bits = "";

  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      continue;
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(parseInt(bits.slice(offset, offset + 8), 2));
  }

  return new Uint8Array(bytes);
}

function renderLogin(error = "") {
  return page("Admin Sign In", `
    <section class="hero">
      ${sub2apiIcon()}
      <p class="eyebrow">Sub2API Admin</p>
      <h1>Admin sign in</h1>
      <p class="lede">Use your password and 2FA code to manage UUID access.</p>
    </section>
    <form class="panel" method="post" action="${ADMIN_PATH}">
      <input type="hidden" name="action" value="login" />
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
      <label for="username">Admin username</label>
      <input id="username" name="username" type="text" autocomplete="username" required autofocus />
      <label for="password">Admin password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <label for="token">2FA code</label>
      <input id="token" name="token" type="text" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
      <button type="submit">Sign in</button>
    </form>
  `);
}

function renderAdmin(invites, trash, csrf, request, env, dashboard = {}) {
  const defaultBaseUrl = defaultSub2ApiBaseUrl(env, request);
  const inviteCount = Number.isSafeInteger(dashboard.inviteCount) ? dashboard.inviteCount : invites.length;
  const trashCount = Number.isSafeInteger(dashboard.trashCount) ? dashboard.trashCount : trash.length;
  const unmigratedInviteCount = Number.isSafeInteger(dashboard.unmigratedInviteCount)
    ? dashboard.unmigratedInviteCount
    : invites.filter((invite) => !invite.accessKeyHmac).length;
  const currentPage = Number.isSafeInteger(dashboard.page) ? dashboard.page : 1;
  const currentTrashPage = Number.isSafeInteger(dashboard.trashPage) ? dashboard.trashPage : 1;
  const selectedInvite = dashboard.selectedInvite || null;
  const view = String(dashboard.view || (selectedInvite ? "detail" : "list"));
  const keyGroups = Array.isArray(dashboard.keyGroups) ? dashboard.keyGroups : [];
  const authStateStatus = dashboard.authStateStatus || null;
  const legacyCleanupComplete = authStateStatus?.legacyCleanupComplete === true;
  const legacyCleanupVerificationPending =
    authStateStatus?.legacyCleanupVerificationPending === true;
  return page("UUID Admin", (nonce) => `
    <section class="admin">
      <header class="topbar">
        <div class="topbar-title">
          ${sub2apiIcon("compact")}
          <div>
            <p class="eyebrow">Sub2API Admin</p>
            <h1>UUID Admin</h1>
            <p>${inviteCount} active UUID${inviteCount === 1 ? "" : "s"} · ${trashCount} trashed item${trashCount === 1 ? "" : "s"}</p>
          </div>
        </div>
        <div class="inline-actions">
          <a class="secondary compact nav-link" href="${ADMIN_PATH}/requests">Usage Inspector</a>
          <form method="post" action="${ADMIN_PATH}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="action" value="logout" />
            <button class="secondary" type="submit">Sign out</button>
          </form>
        </div>
      </header>

      <nav class="admin-tabs" aria-label="Admin views">
        <a class="nav-link${view === "list" ? " active" : ""}" href="${ADMIN_PATH}"${view === "list" ? ' aria-current="page"' : ""}>UUIDs</a>
        <a class="nav-link${view === "create" ? " active" : ""}" href="${ADMIN_PATH}?view=create"${view === "create" ? ' aria-current="page"' : ""}>Create</a>
        <a class="nav-link${view === "maintenance" ? " active" : ""}" href="${ADMIN_PATH}?view=maintenance"${view === "maintenance" ? ' aria-current="page"' : ""}>Maintenance</a>
      </nav>

      ${view === "maintenance" ? `
      <section class="panel create-panel">
        <div class="section-head">
          <div>
            <h2>Access key migration</h2>
            <p class="muted">${unmigratedInviteCount
              ? `${unmigratedInviteCount} UUID account${unmigratedInviteCount === 1 ? "" : "s"} still require v2 access keys. Each run issues at most ${MAX_INVITE_CREDENTIAL_MIGRATION_BATCH}.`
              : "All active UUID accounts use v2 access keys."}</p>
          </div>
          <span class="stat-pill ${unmigratedInviteCount ? "status-warn" : "status-ok"}">${unmigratedInviteCount ? "Migration required" : "Migration complete"}</span>
        </div>
        ${unmigratedInviteCount ? `
          <form class="inline" method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="migrate_invite_credentials" />
            <input type="hidden" name="trashPage" value="${currentTrashPage}" />
            <label class="field"><span>2FA code</span><input name="step_up_token" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required /></label>
            <button type="submit">Generate next ${Math.min(unmigratedInviteCount, MAX_INVITE_CREDENTIAL_MIGRATION_BATCH)} keys</button>
          </form>
        ` : ""}
      </section>

      ${authStateStatus ? `<section class="panel create-panel">
        <div class="section-head">
          <div>
            <h2>Legacy rollback state</h2>
            <p class="muted">${legacyCleanupComplete
              ? "Legacy invite and session KV has been explicitly removed."
              : legacyCleanupVerificationPending
                ? "Legacy keys were removed and await two consecutive read-only empty checks. Any residual keeps cleanup incomplete."
                : "Legacy KV remains available for rollback. Finalization is allowed only after every account has a v2 access key and every seven-day UUID transition has expired."}</p>
          </div>
          <span class="stat-pill ${legacyCleanupComplete ? "status-ok" : "status-warn"}">${legacyCleanupComplete ? "Cleanup complete" : legacyCleanupVerificationPending ? "Verification pending" : "Cleanup pending"}</span>
        </div>
        ${!legacyCleanupComplete && unmigratedInviteCount === 0 ? `
          <form class="inline" method="post" action="${ADMIN_PATH}" data-confirm="Permanently remove legacy invite and session rollback data? This cannot be undone.">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="finalize_legacy_auth_state_cleanup" />
            <input type="hidden" name="trashPage" value="${currentTrashPage}" />
            <label class="field"><span>2FA code</span><input name="step_up_token" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required /></label>
            <button class="danger" type="submit">Finalize legacy cleanup</button>
          </form>
          <p class="hint">The server checks all transition deadlines again before deleting anything. An early request fails without deleting legacy state.</p>
        ` : ""}
      </section>` : ""}
      ` : ""}

      ${view === "create" ? `
      <section class="panel create-panel">
        <div class="section-head">
          <div>
            <h2>Create UUID</h2>
            <p class="muted">Add a user and attach one or more OpenAI-compatible endpoints.</p>
          </div>
        </div>
        <form class="create" method="post" action="${ADMIN_PATH}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="action" value="create" />
          <div class="form-grid">
            <div class="field span-2">
              <label for="uuid">UUID</label>
              <div class="inline">
                <input id="uuid" name="uuid" type="text" pattern="[0-9a-fA-F-]{36}" required />
                <button class="secondary" id="generate-user" type="button">Generate</button>
                <button class="secondary" id="copy-uuid" type="button">Copy</button>
              </div>
            </div>
            <div class="field">
              <label for="username">Username</label>
              <input id="username" name="username" type="text" maxlength="100" autocapitalize="off" autocomplete="off" spellcheck="false" data-username-input required />
            </div>
            <div class="field">
              <label for="email">Email</label>
              <input id="email" name="email" type="email" maxlength="160" />
            </div>
            <div class="field span-2">
              <label for="remark">Remark</label>
              <input id="remark" name="remark" type="text" maxlength="240" />
            </div>
            ${renderKeyGroupPicker(keyGroups, DEFAULT_KEY_GROUP_NAME)}
          </div>
          ${renderApiConfigEditor("api-configs", [], defaultBaseUrl)}
          <div class="form-footer">
            <span class="hint">Each link is stored separately, then saved in the existing format.</span>
            <label class="field">
              <span>2FA code</span>
              <input name="step_up_token" aria-label="2FA code to create UUID" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
            </label>
            <button type="submit">Save UUID</button>
          </div>
        </form>
      </section>
      ` : ""}

      ${selectedInvite ? `
        <section class="selected-invite-detail">
          <div class="section-head">
            <div>
              <h2>Selected UUID</h2>
              <p class="muted">IP groups and administrative actions load only for this UUID.</p>
            </div>
            <a class="secondary compact nav-link" href="${escapeHtml(adminPageHref(currentPage, currentTrashPage))}">Close details</a>
          </div>
          ${renderInviteRow(
            selectedInvite,
            csrf,
            request,
            env,
            { page: currentPage, trashPage: currentTrashPage },
            keyGroups,
          )}
        </section>
      ` : ""}

      ${view === "list" ? `<section class="invite-list">
        <div class="section-head">
          <div>
            <h2>UUIDs</h2>
            <p class="muted">Edit users, rotate API keys, and manage IP groups.</p>
          </div>
        </div>
        ${invites.length ? invites.map((invite) => renderInviteListRow(
          invite,
          { page: currentPage, trashPage: currentTrashPage },
        )).join("") : `
          <div class="panel empty">No UUIDs yet</div>
        `}
        ${renderAdminPagination("invites", currentPage, inviteCount, currentPage, currentTrashPage)}
      </section>` : ""}

      ${view === "maintenance" ? `<section class="trash-list">
        <div class="section-head">
          <div>
            <h2>Recycle Bin</h2>
            <p class="muted">Restore deleted UUIDs or IP groups, or permanently remove their backend records.</p>
          </div>
        </div>
        ${trash.length ? trash.map((item) => renderTrashRow(item, csrf, currentTrashPage)).join("") : `
          <div class="panel empty">Recycle bin is empty</div>
        `}
        ${renderAdminPagination("trash", currentTrashPage, trashCount, currentPage, currentTrashPage)}
      </section>` : ""}
    </section>
    <script nonce="${nonce}">
      const uuidInput = document.getElementById("uuid");
      const copyButton = document.getElementById("copy-uuid");
      const createEditor = document.getElementById("api-configs");
      const normalizeInviteUsername = (value) =>
        String(value || "")
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9._-]+/g, "-")
          .replace(/^[._-]+|[._-]+$/g, "")
          .slice(0, 100);
      const generateValue = (type) => {
        if (type === "uuid") {
          return crypto.randomUUID();
        }
        const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const bytes = new Uint8Array(45);
        crypto.getRandomValues(bytes);
        return "sk-" + Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
      };
      document.getElementById("generate-user")?.addEventListener("click", () => {
        uuidInput.value = generateValue("uuid");
        ensureGeneratedSub2ApiKey(createEditor);
        copyButton.textContent = "Copy";
      });
      document.querySelectorAll("[data-username-input]").forEach((input) => {
        const applyNormalizedUsername = () => {
          input.value = normalizeInviteUsername(input.value);
          input.setCustomValidity("");
        };
        input.addEventListener("input", applyNormalizedUsername);
        input.addEventListener("blur", applyNormalizedUsername);
      });
      copyButton?.addEventListener("click", async () => {
        if (!uuidInput.value) {
          uuidInput.value = generateValue("uuid");
        }
        await window.copyAdminValue(copyButton, uuidInput.value);
      });
      document.querySelectorAll(".copy-row").forEach((button) => {
        button.addEventListener("click", async () => {
          await window.copyAdminValue(button, button.dataset.copy || "");
        });
      });
      document.querySelectorAll("[data-manual-ip-input]").forEach((input) => {
        const form = input.closest(".manual-ip-form");
        const ipTarget = form?.querySelector("[data-preview-ip]");
        const cidrTarget = form?.querySelector("[data-preview-cidr]");
        const updatePreview = () => {
          const value = String(input.value || "").trim();
          const ipv4 = value.split(".");
          const isIpv4 = ipv4.length === 4 && ipv4.every((part) => {
            if (!part || part.trim() !== part || !Array.from(part).every((char) => char >= "0" && char <= "9")) return false;
            const number = Number(part);
            return Number.isInteger(number) && number >= 0 && number <= 255;
          });
          const isIpv6 = value.includes(":") && /^[0-9a-fA-F:]+$/.test(value);
          if (ipTarget) ipTarget.textContent = value || "Awaiting input";
          if (!value) {
            if (cidrTarget) cidrTarget.textContent = "Auto /24 or /128";
            input.setCustomValidity("");
            return;
          }
          if (isIpv4) {
            if (cidrTarget) cidrTarget.textContent = ipv4[0] + "." + ipv4[1] + "." + ipv4[2] + ".0/24";
            input.setCustomValidity("");
            return;
          }
          if (isIpv6) {
            if (cidrTarget) cidrTarget.textContent = value + "/128";
            input.setCustomValidity("");
            return;
          }
          if (cidrTarget) cidrTarget.textContent = "Invalid IP";
          input.setCustomValidity("Enter a valid IPv4 or IPv6 address.");
        };
        input.addEventListener("input", updatePreview);
        input.addEventListener("blur", updatePreview);
        updatePreview();
      });
      document.querySelectorAll(".generate-key").forEach((button) => {
        button.addEventListener("click", () => {
          const editor = document.getElementById(button.dataset.editor);
          const baseUrl = button.dataset.baseUrl || "";
          const row = addApiRow(editor, "Sub2API", baseUrl, generateValue("api-key"));
          row.querySelector('[data-field="api-key"]').focus();
        });
      });
      document.querySelectorAll(".add-api-link").forEach((button) => {
        button.addEventListener("click", () => {
          const editor = document.getElementById(button.dataset.editor);
          addApiRow(editor, "Sub2API", button.dataset.baseUrl || "", "");
        });
      });
      document.addEventListener("input", (event) => {
        const input = event.target.closest('[data-field="api-key"]');
        if (!input) return;
        const field = input.closest(".api-key-field");
        const hasValue = Boolean(input.value);
        const revealButton = field?.querySelector(".toggle-api-key");
        const copyButton = field?.querySelector(".copy-api-key");
        if (revealButton) revealButton.disabled = !hasValue;
        if (copyButton) copyButton.disabled = !hasValue;
        if (!hasValue) {
          input.type = "password";
          if (revealButton) {
            revealButton.textContent = "Show";
            revealButton.setAttribute("aria-label", "Show API key");
          }
        }
      });
      document.addEventListener("click", async (event) => {
        const copyKeyButton = event.target.closest(".copy-api-key");
        if (copyKeyButton) {
          const input = copyKeyButton.closest(".api-key-field")?.querySelector('[data-field="api-key"]');
          if (!input?.value) return;
          await window.copyAdminValue(copyKeyButton, input.value);
          return;
        }

        const revealButton = event.target.closest(".toggle-api-key");
        if (revealButton) {
          const input = revealButton.closest(".api-key-field")?.querySelector('[data-field="api-key"]');
          if (!input) return;
          const shouldShow = input.type === "password";
          input.type = shouldShow ? "text" : "password";
          revealButton.textContent = shouldShow ? "Hide" : "Show";
          revealButton.setAttribute("aria-label", shouldShow ? "Hide API key" : "Show API key");
          return;
        }

        const button = event.target.closest(".remove-api-link");
        if (!button) return;
        const editor = button.closest(".api-config-editor");
        const rows = editor.querySelectorAll(".api-config-row");
        if (rows.length === 1) {
          const row = rows[0];
          row.querySelectorAll("input").forEach((input) => {
            input.value = "";
          });
          delete row.dataset.existingCredentialId;
          row.querySelector(".credential-meta")?.remove();
          const keyInput = row.querySelector('[data-field="api-key"]');
          if (keyInput) {
            keyInput.placeholder = "sk-...";
            keyInput.dispatchEvent(new Event("input", { bubbles: true }));
          }
          return;
        }
        button.closest(".api-config-row").remove();
      });
      document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", (event) => {
          form.querySelectorAll("[data-manual-ip-input]").forEach((input) => {
            input.dispatchEvent(new Event("input", { bubbles: true }));
          });
          form.querySelectorAll(".api-config-editor").forEach(serializeApiEditor);
          const usernameInput = form.querySelector("[data-username-input]");
          if (!usernameInput) {
            return;
          }
          usernameInput.value = normalizeInviteUsername(usernameInput.value);
          usernameInput.setCustomValidity("");
          if (!usernameInput.value) {
            usernameInput.setCustomValidity("Username is required.");
            usernameInput.reportValidity();
            event.preventDefault();
            return;
          }
          const duplicate = Array.from(document.querySelectorAll("[data-username-input]"))
            .filter((input) => input !== usernameInput)
            .some((input) => normalizeInviteUsername(input.value) === usernameInput.value);
          if (duplicate) {
            usernameInput.setCustomValidity("Username already exists.");
            usernameInput.reportValidity();
            event.preventDefault();
          }
        });
      });
      function addApiRow(editor, name, baseUrl, apiKey) {
        const list = editor.querySelector(".api-config-rows");
        const row = document.createElement("div");
        row.className = "api-config-row";
        row.innerHTML =
          '<input type="text" data-field="name" aria-label="API link name" maxlength="80" placeholder="Name" />' +
          '<input type="url" data-field="base-url" aria-label="API base URL" placeholder="https://example.com/v1" />' +
          '<div class="api-key-field">' +
            '<input type="password" data-field="api-key" aria-label="API key" placeholder="sk-..." autocomplete="off" spellcheck="false" />' +
            '<button class="secondary compact toggle-api-key" type="button" aria-label="Show API key">Show</button>' +
            '<button class="secondary compact copy-api-key" type="button">Copy</button>' +
          '</div>' +
          '<button class="secondary compact remove-api-link" type="button">Remove</button>';
        row.querySelector('[data-field="name"]').value = name || "";
        row.querySelector('[data-field="base-url"]').value = baseUrl || "";
        row.querySelector('[data-field="api-key"]').value = apiKey || "";
        list.appendChild(row);
        return row;
      }
      function normalizeApiName(value) {
        return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      }
      function ensureGeneratedSub2ApiKey(editor) {
        if (!editor) return;
        const defaultBaseUrl = editor.querySelector(".generate-key")?.dataset.baseUrl || "";
        let row = Array.from(editor.querySelectorAll(".api-config-row")).find((item) => {
          const name = normalizeApiName(item.querySelector('[data-field="name"]')?.value.trim());
          const baseUrl = item.querySelector('[data-field="base-url"]')?.value.trim();
          return name === "sub2api" || baseUrl === defaultBaseUrl;
        });
        if (!row) {
          row = addApiRow(editor, "Sub2API", defaultBaseUrl, "");
        }
        const nameInput = row.querySelector('[data-field="name"]');
        const baseUrlInput = row.querySelector('[data-field="base-url"]');
        const keyInput = row.querySelector('[data-field="api-key"]');
        if (nameInput && !nameInput.value.trim()) nameInput.value = "Sub2API";
        if (baseUrlInput && !baseUrlInput.value.trim()) baseUrlInput.value = defaultBaseUrl;
        if (keyInput) keyInput.value = generateValue("api-key");
      }
      function serializeApiEditor(editor) {
        const lines = Array.from(editor.querySelectorAll(".api-config-row"))
          .map((row) => {
            const name = row.querySelector('[data-field="name"]').value.trim();
            const baseUrl = row.querySelector('[data-field="base-url"]').value.trim();
            const apiKey = row.querySelector('[data-field="api-key"]').value.trim();
            const existingMarker = row.dataset.existingCredentialId
              ? "${EXISTING_CREDENTIAL_MARKER_PREFIX}" + encodeURIComponent(row.dataset.existingCredentialId)
              : "";
            const credential = apiKey || existingMarker;
            if (!baseUrl && !credential) return "";
            return [name || "Sub2API", baseUrl, credential].join(" | ");
          })
          .filter(Boolean);
        editor.querySelector('[name="api_configs"]').value = lines.join("\\n");
      }
      document.querySelectorAll(".expiry-form").forEach((form) => {
        const mode = form.querySelector(".expiration-mode");
        form.querySelector(".expires-at")?.addEventListener("input", () => {
          mode.value = "date";
        });
        form.querySelector(".expires-days")?.addEventListener("input", () => {
          mode.value = "days";
        });
      });
    </script>
  `, "wide");
}

function renderAdminPagination(kind, currentPage, totalCount, invitePage, trashPage) {
  const totalPages = adminPageCount(totalCount);
  if (totalPages <= 1) return "";
  const label = kind === "invites" ? "UUID" : "Recycle bin";
  const href = (targetPage) => kind === "invites"
    ? adminPageHref(targetPage)
    : adminMaintenanceHref(targetPage);
  return `
    <nav class="pagination" aria-label="${label} pagination">
      <span class="muted">Page ${currentPage} of ${totalPages} · ${totalCount} total</span>
      <div class="inline-actions">
        ${currentPage > 1 ? `<a class="compact nav-link" href="${escapeHtml(href(currentPage - 1))}">Previous</a>` : ""}
        ${currentPage < totalPages ? `<a class="compact nav-link" href="${escapeHtml(href(currentPage + 1))}">Next</a>` : ""}
      </div>
    </nav>
  `;
}

function adminPageHref(page) {
  const params = new URLSearchParams();
  if (page > 1) params.set("page", String(page));
  const query = params.toString();
  return query ? `${ADMIN_PATH}?${query}` : ADMIN_PATH;
}

function adminMaintenanceHref(trashPage = 1) {
  const params = new URLSearchParams({ view: "maintenance" });
  if (trashPage > 1) params.set("trashPage", String(trashPage));
  return `${ADMIN_PATH}?${params.toString()}`;
}

function adminMaintenancePostHref(form) {
  return adminMaintenanceHref(parseAdminPageNumber(
    form.get("trashPage"),
    MAX_ADMIN_TRASH_PAGE,
  ));
}

function legacyAdminCanonicalLocation(adminUrl) {
  const requestedView = String(adminUrl.searchParams.get("view") || "").trim().toLowerCase();
  if (
    adminUrl.pathname === ADMIN_PATH
    && adminUrl.searchParams.has("view")
    && !adminUrl.searchParams.has("detail")
    && !adminUrl.searchParams.has("edit")
    && requestedView !== "create"
    && requestedView !== "maintenance"
  ) {
    return ADMIN_PATH;
  }
  if (
    adminUrl.pathname !== ADMIN_PATH
    || adminUrl.searchParams.has("view")
    || adminUrl.searchParams.has("detail")
    || adminUrl.searchParams.has("edit")
    || !adminUrl.searchParams.has("trashPage")
  ) {
    return "";
  }
  return adminMaintenanceHref(parseAdminPageNumber(
    adminUrl.searchParams.get("trashPage"),
    MAX_ADMIN_TRASH_PAGE,
  ));
}

function adminInviteHref(uuid, pagination = {}, edit = false, ipPage = 1) {
  const params = new URLSearchParams();
  if (Number.isSafeInteger(pagination.page) && pagination.page > 1) {
    params.set("page", String(pagination.page));
  }
  if (Number.isSafeInteger(pagination.trashPage) && pagination.trashPage > 1) {
    params.set("trashPage", String(pagination.trashPage));
  }
  params.set(edit ? "edit" : "detail", String(uuid || ""));
  if (Number.isSafeInteger(ipPage) && ipPage > 1) {
    params.set("ipPage", String(ipPage));
  }
  return `${ADMIN_PATH}?${params.toString()}`;
}

function adminInvitePostHref(form, uuid) {
  const context = parseAdminInvitePostContext(form);
  return adminInviteHref(
    uuid,
    { page: context.page, trashPage: context.trashPage },
    context.edit,
    context.ipPage,
  );
}

function parseAdminInvitePostContext(form) {
  const fallback = { page: 1, trashPage: 1, ipPage: 1, edit: false };
  const raw = String(form.get("admin_context") || "");
  try {
    decodeURIComponent(raw.replace(/\+/g, " "));
  } catch {
    return fallback;
  }
  const params = new URLSearchParams(raw);
  const allowedKeys = new Set(["p", "t", "i", "v"]);
  const keys = [...params.keys()];
  if (
    keys.length !== allowedKeys.size
    || keys.some((key) => !allowedKeys.has(key))
    || [...allowedKeys].some((key) => params.getAll(key).length !== 1)
  ) {
    return fallback;
  }
  const view = params.get("v");
  if (view !== "d" && view !== "e") return fallback;
  return {
    page: parseAdminPageNumber(params.get("p"), MAX_ADMIN_INVITE_PAGE),
    trashPage: parseAdminPageNumber(params.get("t"), MAX_ADMIN_TRASH_PAGE),
    ipPage: parseAdminPageNumber(params.get("i"), MAX_ADMIN_IP_GROUP_PAGE),
    edit: view === "e",
  };
}

function renderInviteListRow(invite, pagination = {}) {
  const credentialStatus = inviteCredentialStatus(invite);
  const storedApiConfigCount = Number(invite.apiConfigCount);
  const apiConfigCount = Number.isSafeInteger(storedApiConfigCount) && storedApiConfigCount >= 0
    ? storedApiConfigCount
    : (Array.isArray(invite.apiConfigs) ? invite.apiConfigs.length : 0);
  return `
    <article class="panel invite-card invite-summary-card">
      <div class="invite-meta">
        <div class="invite-heading">
          <strong>${escapeHtml(inviteUsername(invite) || invite.uuid)}</strong>
          <div class="stat-row">
            <span class="stat-pill ${credentialStatus.className}">${escapeHtml(credentialStatus.label)}</span>
            <span class="stat-pill">${apiConfigCount} endpoint${apiConfigCount === 1 ? "" : "s"}</span>
          </div>
          ${invite.email ? `<small>${escapeHtml(invite.email)}</small>` : ""}
          ${invite.remark ? `<small>${escapeHtml(invite.remark)}</small>` : ""}
        </div>
        <div class="inline-actions">
          <a class="secondary compact nav-link" href="${escapeHtml(adminInviteHref(invite.uuid, pagination))}">View details</a>
          <a class="secondary compact nav-link" href="${escapeHtml(adminInviteHref(invite.uuid, pagination, true))}">Edit</a>
        </div>
      </div>
    </article>
  `;
}

function renderTrashRow(item, csrf, trashPage = 1) {
  if (item.type === "uuid") {
    return renderUuidTrashRow(item, csrf, trashPage);
  }
  if (item.type === "ip_group") {
    return renderIpGroupTrashRow(item, csrf, trashPage);
  }
  return "";
}

function renderUuidTrashRow(item, csrf, trashPage) {
  const invite = item.invite || {};
  const recordCount = Number.isSafeInteger(Number(item.recordCount))
    ? Math.max(0, Number(item.recordCount))
    : 0;
  return `
    <article class="panel trash-card">
      <div class="trash-meta">
        <div>
          <strong>UUID ${escapeHtml(invite.uuid || "")}</strong>
          ${inviteUsername(invite) ? `<small>${escapeHtml(inviteUsername(invite))}</small>` : ""}
          ${invite.email ? `<small>${escapeHtml(invite.email)}</small>` : ""}
          <small>Deleted ${escapeHtml(formatDate(item.deletedAt) || "Unknown")} · ${recordCount} IP group${recordCount === 1 ? "" : "s"}</small>
        </div>
        <div class="inline-actions">
          <form method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="restore_uuid" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <input type="hidden" name="trashPage" value="${parseAdminPageNumber(trashPage, MAX_ADMIN_TRASH_PAGE)}" />
            <input name="step_up_token" aria-label="2FA code for UUID restore" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="secondary compact" type="submit">Restore</button>
          </form>
          <form method="post" action="${ADMIN_PATH}" data-confirm="Permanently delete this UUID and its Sub2API records?">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="purge_uuid" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <input type="hidden" name="trashPage" value="${parseAdminPageNumber(trashPage, MAX_ADMIN_TRASH_PAGE)}" />
            <input name="step_up_token" aria-label="2FA code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="danger compact" type="submit">Delete forever</button>
          </form>
        </div>
      </div>
    </article>
  `;
}

function renderIpGroupTrashRow(item, csrf, trashPage) {
  const group = item.group || {};
  const place = [group.country, group.region, group.city].filter(Boolean).join(" / ") || "Unknown location";
  const ipCount = Number.isSafeInteger(Number(group.ipCount))
    ? Math.max(0, Number(group.ipCount))
    : 0;
  return `
    <article class="panel trash-card">
      <div class="trash-meta">
        <div>
          <strong>IP group for ${escapeHtml(item.uuid || "")}</strong>
          <small>${escapeHtml(place)}</small>
          <small>Deleted ${escapeHtml(formatDate(item.deletedAt) || "Unknown")} · ${ipCount} IP${ipCount === 1 ? "" : "s"}</small>
        </div>
        <div class="inline-actions">
          <form method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="restore_ip_group" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <input type="hidden" name="trashPage" value="${parseAdminPageNumber(trashPage, MAX_ADMIN_TRASH_PAGE)}" />
            <input name="step_up_token" aria-label="2FA code to restore IP group" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="secondary compact" type="submit">Restore</button>
          </form>
          <form method="post" action="${ADMIN_PATH}" data-confirm="Permanently delete this IP group?">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="purge_ip_group" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <input type="hidden" name="trashPage" value="${parseAdminPageNumber(trashPage, MAX_ADMIN_TRASH_PAGE)}" />
            <input name="step_up_token" aria-label="2FA code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="danger compact" type="submit">Delete forever</button>
          </form>
        </div>
      </div>
    </article>
  `;
}

function renderInviteRow(invite, csrf, request, env, pagination = {}, keyGroups = []) {
  const groups = invite.records || [];
  const recordCount = Number.isSafeInteger(invite.recordCount) ? invite.recordCount : groups.length;
  const ipPage = Number.isSafeInteger(invite.ipPage) ? invite.ipPage : 1;
  const recordsOversized = Boolean(invite.recordsOversized);
  const editorId = `api-${invite.uuid}`;
  const isEditing = new URL(request.url).searchParams.get("edit") === invite.uuid;
  const apiConfigs = isEditing
    ? normalizeApiConfigEditorRows(invite.apiConfigs || [])
    : (Array.isArray(invite.apiConfigs) ? invite.apiConfigs : []);
  const totalIps = groups.reduce((count, group) => count + (group.ips || []).length, 0);
  const latestGroup = groups[0] || null;
  const latestPlace = latestGroup ? formatGroupPlace(latestGroup) : "";
  const credentialStatus = inviteCredentialStatus(invite);
  return `
    <article class="panel invite-card">
      <div class="invite-meta">
        <div class="invite-heading">
          <strong>${escapeHtml(inviteUsername(invite) || invite.uuid)}</strong>
          <div class="stat-row">
            ${recordsOversized
              ? `<span class="stat-pill status-error">IP data unavailable</span>`
              : `<span class="stat-pill">${recordCount} group${recordCount === 1 ? "" : "s"}</span><span class="stat-pill">${totalIps} IP${totalIps === 1 ? "" : "s"} on this page</span>`}
            <span class="stat-pill ${credentialStatus.className}">${escapeHtml(credentialStatus.label)}</span>
            ${latestPlace ? `<span class="stat-pill">${escapeHtml(latestPlace)}</span>` : ""}
          </div>
          ${invite.email ? `<small>${escapeHtml(invite.email)}</small>` : ""}
          ${invite.remark ? `<small>${escapeHtml(invite.remark)}</small>` : ""}
        </div>
        <div class="inline-actions">
          <form method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="rotate_access_key" />
            <input type="hidden" name="uuid" value="${escapeHtml(invite.uuid)}" />
            ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
            <input name="step_up_token" aria-label="2FA code for key rotation" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="secondary compact" type="submit">${invite.accessKeyHmac ? "Rotate key" : "Create access key"}</button>
          </form>
          <form method="post" action="${ADMIN_PATH}" data-confirm="Reset this user's Sub2API login password?">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="reset_sub2api_password" />
            <input type="hidden" name="uuid" value="${escapeHtml(invite.uuid)}" />
            ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
            <input name="step_up_token" aria-label="2FA code for login reset" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="secondary compact" type="submit">Reset login</button>
          </form>
          <form method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="refresh_sub2api_status" />
            <input type="hidden" name="uuid" value="${escapeHtml(invite.uuid)}" />
            ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
            <button class="secondary compact" type="submit">Refresh Sub2API</button>
          </form>
          <form method="post" action="${ADMIN_PATH}" data-confirm="Delete this UUID and all of its IP groups?">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="delete" />
            <input type="hidden" name="uuid" value="${escapeHtml(invite.uuid)}" />
            ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
            <input name="step_up_token" aria-label="2FA code to delete UUID" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="danger compact" type="submit">Delete UUID</button>
          </form>
        </div>
      </div>
      <div class="invite-main">
        ${isEditing ? renderInviteEditForm(invite, apiConfigs, editorId, csrf, request, env, pagination, ipPage, keyGroups) : renderInviteSummary(invite, apiConfigs, ADMIN_PATH, pagination, csrf)}
        <section class="ip-panel">
          <div class="subhead">
            <h3>IP groups</h3>
            <span class="muted">${recordCount} active group${recordCount === 1 ? "" : "s"}</span>
          </div>
          ${recordsOversized
            ? `<span class="error">IP group data is too large to display safely.</span>`
            : `${renderManualIpGroupForm(invite.uuid, csrf, pagination, ipPage, isEditing)}${groups.length ? groups.map((group, index) => renderIpGroup(group, invite.uuid, csrf, index === 0, pagination, ipPage, isEditing)).join("") : `<span class="muted">No IP groups yet</span>`}${renderIpGroupPagination(invite.uuid, ipPage, recordCount, pagination, isEditing)}`}
        </section>
      </div>
    </article>
  `;
}

function renderIpGroupPagination(uuid, currentPage, totalCount, pagination, isEditing) {
  const totalPages = Math.max(1, Math.ceil(totalCount / ADMIN_IP_GROUP_PAGE_SIZE));
  if (totalPages <= 1) return "";
  const href = (targetPage) => adminInviteHref(
    uuid,
    pagination,
    isEditing,
    targetPage,
  );
  return `
    <nav class="pagination" aria-label="IP group pagination">
      <span class="muted">Page ${currentPage} of ${totalPages} · ${totalCount} groups</span>
      <div class="inline-actions">
        ${currentPage > 1 ? `<a class="secondary compact nav-link" href="${escapeHtml(href(currentPage - 1))}">Previous</a>` : ""}
        ${currentPage < totalPages ? `<a class="secondary compact nav-link" href="${escapeHtml(href(currentPage + 1))}">Next</a>` : ""}
      </div>
    </nav>
  `;
}

function renderInvitePostContextFields(pagination, ipPage, isEditing) {
  const page = parseAdminPageNumber(pagination?.page, MAX_ADMIN_INVITE_PAGE);
  const trashPage = parseAdminPageNumber(pagination?.trashPage, MAX_ADMIN_TRASH_PAGE);
  const currentIpPage = parseAdminPageNumber(ipPage, MAX_ADMIN_IP_GROUP_PAGE);
  const context = new URLSearchParams({
    p: String(page),
    t: String(trashPage),
    i: String(currentIpPage),
    v: isEditing ? "e" : "d",
  });
  return `<input type="hidden" name="admin_context" value="${escapeHtml(context.toString())}" />`;
}

function renderManualIpGroupForm(uuid, csrf, pagination, ipPage, isEditing) {
  return `
    <form class="manual-ip-form" method="post" action="${ADMIN_PATH}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
      <input type="hidden" name="action" value="add_ip_group" />
      <input type="hidden" name="uuid" value="${escapeHtml(uuid)}" />
      ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
      <input class="expiration-mode" type="hidden" name="expiration_mode" value="days" />
      <div class="subhead compact-subhead">
        <h3>Add IP</h3>
        <span class="hint">Enter one IP. Only the matching network is added to the allowlist.</span>
      </div>
      <div class="manual-ip-layout">
        <label class="field manual-ip-input" for="manual-ip-value-${escapeHtml(uuid)}">
          <span>IP address (IPv4 authorizes its /24 network)</span>
          <input id="manual-ip-value-${escapeHtml(uuid)}" name="ip_value" type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="192.168.1.1" data-manual-ip-input required />
        </label>
        <div class="manual-ip-preview" data-manual-ip-preview>
          <span class="preview-label">Allowlist entry</span>
          <div class="ip-list preview-pills">
            <span class="ip-pill muted-pill"><b>IP</b><code data-preview-ip>Awaiting input</code></span>
            <span class="ip-pill muted-pill"><b>Net</b><code data-preview-cidr>Auto /24 or /128</code></span>
          </div>
        </div>
      </div>
      <div class="manual-ip-grid">
        <label class="expiry-field" for="manual-expires-days-${escapeHtml(uuid)}">
          <span>Days left</span>
          <input id="manual-expires-days-${escapeHtml(uuid)}" name="expires_in_days" type="number" min="0" step="1" value="${DEFAULT_IP_TTL_DAYS}" required />
        </label>
        <label class="expiry-field" for="manual-expires-at-${escapeHtml(uuid)}">
          <span>Custom expires</span>
          <input id="manual-expires-at-${escapeHtml(uuid)}" class="expires-at" name="expires_at" type="datetime-local" value="" />
        </label>
        <label class="expiry-field">
          <span>2FA code</span>
          <input name="step_up_token" aria-label="2FA code to add IP group" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
        </label>
        <div class="manual-ip-action">
          <button class="secondary compact" type="submit">Add IP group</button>
        </div>
      </div>
    </form>
  `;
}

function renderInviteEditForm(invite, apiConfigs, editorId, csrf, request, env, pagination, ipPage, keyGroups = []) {
  const selectedGroup = selectedKeyGroupName(invite, keyGroups);
  const fieldId = `key_group-${invite.uuid}`;
  return `
    <form class="invite-edit" method="post" action="${ADMIN_PATH}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
      <input type="hidden" name="action" value="update_invite" />
      <input type="hidden" name="original_uuid" value="${escapeHtml(invite.uuid)}" />
      ${renderInvitePostContextFields(pagination, ipPage, true)}
      <div class="form-grid">
        <div class="field span-2">
          <label for="uuid-${escapeHtml(invite.uuid)}">UUID</label>
          <div class="uuid-cell">
            <input id="uuid-${escapeHtml(invite.uuid)}" name="uuid" type="text" value="${escapeHtml(invite.uuid)}" readonly />
            <button class="secondary compact copy-row" type="button" data-copy="${escapeHtml(invite.uuid)}">Copy</button>
          </div>
        </div>
        <div class="field">
          <label for="username-${escapeHtml(invite.uuid)}">Username</label>
          <input id="username-${escapeHtml(invite.uuid)}" name="username" type="text" maxlength="100" autocapitalize="off" autocomplete="off" spellcheck="false" value="${escapeHtml(inviteUsername(invite))}" data-username-input required />
        </div>
        <div class="field">
          <label for="email-${escapeHtml(invite.uuid)}">Email</label>
          <input id="email-${escapeHtml(invite.uuid)}" name="email" type="email" maxlength="160" value="${escapeHtml(invite.email || "")}" />
        </div>
        <div class="field span-2">
          <label for="remark-${escapeHtml(invite.uuid)}">Remark</label>
          <input id="remark-${escapeHtml(invite.uuid)}" name="remark" type="text" maxlength="240" value="${escapeHtml(invite.remark || "")}" />
        </div>
        ${renderKeyGroupPicker(keyGroups, selectedGroup, fieldId)}
      </div>
      ${renderApiConfigEditor(editorId, apiConfigs, defaultSub2ApiBaseUrl(env, request))}
      <div class="form-footer">
        <label class="field">
          <span>2FA code</span>
          <input name="step_up_token" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
        </label>
        <button class="secondary compact" type="submit">Save user</button>
      </div>
    </form>
  `;
}

function renderApiConfigEditor(editorId, apiConfigs, defaultBaseUrl) {
  const rows = normalizeApiConfigEditorRows(apiConfigs);
  const visibleRows = rows.length ? rows : [{ name: "Sub2API", baseUrl: defaultBaseUrl, apiKey: "" }];
  return `
    <section class="api-config-editor" id="${escapeHtml(editorId)}">
      <input type="hidden" name="api_configs" value="${escapeHtml(formatApiConfigEditorRows(rows))}" />
      <div class="subhead">
        <h3>OpenAI API links</h3>
        <div class="inline-actions">
          <button class="secondary compact generate-key" type="button" data-editor="${escapeHtml(editorId)}" data-base-url="${escapeHtml(defaultBaseUrl)}">Generate key</button>
          <button class="secondary compact add-api-link" type="button" data-editor="${escapeHtml(editorId)}" data-base-url="${escapeHtml(defaultBaseUrl)}">Add link</button>
        </div>
      </div>
      <div class="api-config-labels">
        <span>Name</span>
        <span>Base URL</span>
        <span>API key</span>
        <span></span>
      </div>
      <div class="api-config-rows">
        ${visibleRows.map(renderApiConfigInputRow).join("")}
      </div>
    </section>
  `;
}

function renderApiConfigInputRow(config) {
  const credentialId = config.credentialConfigured ? String(config.id || "") : "";
  const apiKey = credentialId ? "" : String(config.apiKey || "");
  const credentialAttributes = credentialId
    ? ` data-existing-credential-id="${escapeHtml(credentialId)}"`
    : "";
  return `
    <div class="api-config-row"${credentialAttributes}>
      <input type="text" data-field="name" aria-label="API link name" maxlength="80" placeholder="Name" value="${escapeHtml(config.name || "")}" />
      <input type="url" data-field="base-url" aria-label="API base URL" placeholder="https://example.com/v1" value="${escapeHtml(config.baseUrl || "")}" />
      <div class="api-key-field">
        <input type="password" data-field="api-key" aria-label="API key" placeholder="${credentialId ? "Saved - leave blank to keep" : "sk-..."}" value="${escapeHtml(apiKey)}" autocomplete="new-password" spellcheck="false" />
        <button class="secondary compact toggle-api-key" type="button" aria-label="Show API key"${apiKey ? "" : " disabled"}>Show</button>
        <button class="secondary compact copy-api-key" type="button"${apiKey ? "" : " disabled"}>Copy</button>
        ${credentialId ? `<small class="credential-meta">Credential ID: ${escapeHtml(credentialId)}. Saved; leave blank to keep this credential. Enter a new key to replace it.</small>` : ""}
      </div>
      <button class="secondary compact remove-api-link" type="button">Remove</button>
    </div>
  `;
}

function renderIpGroup(
  group,
  uuid,
  csrf,
  isInitiallyOpen = false,
  pagination = {},
  ipPage = 1,
  isEditing = false,
) {
  const place = formatGroupPlace(group) || "Unknown location";
  const meta = [group.asOrganization, group.colo, group.geoSource ? `geo: ${group.geoSource}` : ""].filter(Boolean).join(" · ");
  const expiresInDays = daysUntil(group.expiresAt);
  const ipCount = (group.ips || []).length;
  const previewItems = (group.ips || []).slice(0, 3);
  return `
    <details class="ip-group"${isInitiallyOpen ? " open" : ""}>
      <summary class="ip-group-summary">
        <div class="ip-group-summary-main">
          <strong>${escapeHtml(place)}</strong>
          <div class="stat-row">
            <span class="stat-pill">${ipCount} IP${ipCount === 1 ? "" : "s"}</span>
            <span class="stat-pill">${escapeHtml(expiresInDays)} day${Number(expiresInDays) === 1 ? "" : "s"} left</span>
            ${group.colo ? `<span class="stat-pill">${escapeHtml(group.colo)}</span>` : ""}
          </div>
          <small>${escapeHtml(formatDate(group.addedAt) || "Unknown")}${group.updatedAt ? ` · Updated ${escapeHtml(formatDate(group.updatedAt))}` : ""}</small>
        </div>
        <div class="ip-preview-list">
          ${previewItems.map(renderIpPreviewItem).join("")}
          ${ipCount > previewItems.length ? `<span class="ip-preview-more">+${ipCount - previewItems.length}</span>` : ""}
        </div>
      </summary>
      <div class="ip-group-body">
        <div class="ip-group-toolbar">
          <form method="post" action="${ADMIN_PATH}" data-confirm="Delete this IP group from the Cloudflare list?">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="delete_ip_group" />
            <input type="hidden" name="uuid" value="${escapeHtml(uuid)}" />
            <input type="hidden" name="group_id" value="${escapeHtml(group.id)}" />
            ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
            <input name="step_up_token" aria-label="2FA code to delete IP group" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="2FA code" required />
            <button class="danger compact" type="submit">Delete group</button>
          </form>
        </div>
        <div class="time-grid">
          <span><b>Added</b>${escapeHtml(formatDate(group.addedAt) || "Unknown")}</span>
          ${group.updatedAt ? `<span><b>Updated</b>${escapeHtml(formatDate(group.updatedAt))}</span>` : ""}
          <span><b>Location</b>${escapeHtml(place)}</span>
          ${meta ? `<span><b>Network</b>${escapeHtml(meta)}</span>` : ""}
        </div>
        <form class="expiry-form" method="post" action="${ADMIN_PATH}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="action" value="update_ip_group_expiration" />
          <input type="hidden" name="uuid" value="${escapeHtml(uuid)}" />
          <input type="hidden" name="group_id" value="${escapeHtml(group.id)}" />
          ${renderInvitePostContextFields(pagination, ipPage, isEditing)}
          <input class="expiration-mode" type="hidden" name="expiration_mode" value="date" />
          <label class="expiry-field" for="expires-${escapeHtml(group.id)}">
            <span>Expires</span>
            <input class="expires-at" id="expires-${escapeHtml(group.id)}" name="expires_at" type="datetime-local" value="${escapeHtml(toDateTimeLocalValue(group.expiresAt))}" required />
          </label>
          <label class="expiry-field" for="expires-days-${escapeHtml(group.id)}">
            <span>Days left</span>
            <input class="expires-days" id="expires-days-${escapeHtml(group.id)}" name="expires_in_days" type="number" min="0" step="1" value="${escapeHtml(expiresInDays)}" />
          </label>
          <label class="expiry-field">
            <span>2FA code</span>
            <input name="step_up_token" aria-label="2FA code to update IP expiration" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required />
          </label>
          <button class="secondary compact" type="submit">Update</button>
        </form>
        <div class="ip-list">
          ${(group.ips || []).map(renderIpItem).join("")}
        </div>
      </div>
    </details>
  `;
}

function renderIpItem(item) {
  return `
    <span class="ip-pill">
      <b>${escapeHtml(item.version || (item.ip.includes(":") ? "IPv6" : "IPv4"))}</b>
      <code>IP ${escapeHtml(item.ip)}</code>
      <code>Net ${escapeHtml(item.cidr || item.listValue || item.ip)}</code>
    </span>
  `;
}

function renderIpPreviewItem(item) {
  return `<code class="ip-preview">${escapeHtml(item.cidr || item.ip)}</code>`;
}

function formatGroupPlace(group) {
  return [group.country, group.region, group.city].filter(Boolean).join(" / ");
}

function formatDate(value) {
  if (!value) {
    return "";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const parts = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(date).reduce((acc, part) => {
    acc[part.type] = part.value;
    return acc;
  }, {});

  return `${parts.year}年${parts.month}月${parts.day}日 ${parts.hour}:${parts.minute}:${parts.second}`;
}

function renderResponsePills(item) {
  const pills = [];
  const status = Number(item?.responseStatus || 0);
  if (status > 0) {
    pills.push(`<span class="stat-pill ${escapeHtml(responseStatusClass(status))}">HTTP ${escapeHtml(String(status))}</span>`);
  } else {
    pills.push('<span class="stat-pill pending">Response pending</span>');
  }
  if (item?.upstreamStatus) {
    pills.push(`<span class="stat-pill">Upstream ${escapeHtml(String(item.upstreamStatus))}</span>`);
  }
  if (Number(item?.requestTimeMs || 0) > 0) {
    pills.push(`<span class="stat-pill">${escapeHtml(formatMilliseconds(item.requestTimeMs))}</span>`);
  }
  if (item?.responseContentType) {
    pills.push(`<span class="stat-pill">${escapeHtml(String(item.responseContentType))}</span>`);
  }
  return pills.join("");
}

function responseStatusClass(status) {
  const code = Number(status || 0);
  if (code >= 500) return "status-error";
  if (code >= 400) return "status-warn";
  if (code >= 200) return "status-ok";
  return "pending";
}

function formatMilliseconds(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount) || amount <= 0) {
    return "";
  }
  if (amount < 1000) {
    return `${Math.round(amount)} ms`;
  }
  return `${(amount / 1000).toFixed(amount >= 10000 ? 0 : 2)} s`;
}

function toDateTimeLocalValue(value) {
  if (!value) {
    return "";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return date.toISOString().slice(0, 16);
}

function parseDateTimeLocal(value) {
  if (!value) {
    return "";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function parseExpirationInput(dateTimeLocal, daysValue, mode) {
  if (String(dateTimeLocal || "").trim()) {
    const parsed = parseDateTimeLocal(dateTimeLocal);
    if (parsed) {
      return parsed;
    }
  }

  const days = Number(daysValue);
  if (mode === "days" && Number.isFinite(days) && days >= 0 && String(daysValue).trim() !== "") {
    return addDaysIso(new Date().toISOString(), Math.floor(days));
  }

  return parseDateTimeLocal(dateTimeLocal);
}

function daysUntil(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return Math.max(0, Math.ceil((date.getTime() - Date.now()) / 86_400_000));
}

function addDaysIso(value, days) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString();
}

function upsertIpGroup(groups, incoming) {
  const incomingKeys = new Set((incoming.ips || []).map((item) => item.listValue || item.cidr || item.ip).filter(Boolean));
  const existingIndex = groups.findIndex((group) => (group.ips || []).some((item) => {
    const key = item.listValue || item.cidr || item.ip;
    return key && incomingKeys.has(key);
  }));

  if (existingIndex === -1) {
    return [incoming, ...groups];
  }

  return groups.map((group, index) => {
    if (index !== existingIndex) {
      return group;
    }

    const existingByKey = new Map((group.ips || []).map((item) => [item.listValue || item.cidr || item.ip, item]));
    const mergedIps = (incoming.ips || []).map((item) => ({
      ...(existingByKey.get(item.listValue || item.cidr || item.ip) || {}),
      ...item,
    }));

    return {
      ...group,
      ...incoming,
      id: group.id,
      addedAt: group.addedAt || incoming.addedAt,
      ips: mergedIps,
    };
  });
}

async function lookupIpLocation(env, ip, cf) {
  const fallback = {
    country: stringOrEmpty(cf.country),
    region: stringOrEmpty(cf.region),
    city: stringOrEmpty(cf.city),
    timezone: stringOrEmpty(cf.timezone),
    colo: stringOrEmpty(cf.colo),
    asn: cf.asn ? String(cf.asn) : "",
    asOrganization: stringOrEmpty(cf.asOrganization),
    source: "cloudflare",
  };

  if (!ip) {
    return fallback;
  }

  const lookupUrl = resolveGeoIpLookupUrl(env, ip);
  if (!lookupUrl) {
    return fallback;
  }

  try {
    const response = await fetchWithTimeout(lookupUrl, {
      headers: { accept: "application/json" },
      // Workers supports follow/manual only. Manual prevents an unapproved
      // redirect from becoming a second outbound request.
      redirect: "manual",
    }, GEOIP_TIMEOUT_MS);
    if (!response.ok) {
      return fallback;
    }
    const payload = await readJsonWithLimit(response, 16_384);
    const region = stringOrEmpty(payload.region || payload.region_name || payload.province);
    const city = stringOrEmpty(payload.city);
    const country = stringOrEmpty(payload.country_code || payload.countryCode || payload.country);
    if (!country && !region && !city) {
      return fallback;
    }

    return {
      country: country || fallback.country,
      region: region || fallback.region,
      city: city || fallback.city,
      timezone: stringOrEmpty(payload.timezone) || fallback.timezone,
      colo: fallback.colo,
      asn: payload.asn ? String(payload.asn).replace(/^AS/i, "") : fallback.asn,
      asOrganization: stringOrEmpty(payload.organization || payload.org || payload.isp) || fallback.asOrganization,
      source: "geoip",
    };
  } catch (error) {
    console.error(JSON.stringify({ level: "warn", message: "geoip_lookup_failed" }));
    return fallback;
  }
}

function parseGeoIpAllowedHostnames(value) {
  return parseApprovedHostnames(value);
}

function resolveGeoIpLookupUrl(env, ip) {
  const template = String(env.GEOIP_LOOKUP_URL || "").trim();
  const allowedHosts = parseGeoIpAllowedHostnames(env.GEOIP_ALLOWED_HOSTNAMES);
  if (
    !template
    || !ip
    || allowedHosts.length === 0
    || (template.match(/\{ip\}/g) || []).length !== 1
  ) {
    return "";
  }
  const url = parseApprovedHttpsUrl(
    template.replace("{ip}", encodeURIComponent(ip)),
    allowedHosts,
    { allowSearch: true },
  );
  if (!url) {
    return "";
  }
  return url.href;
}

function validateGeoIpConfig(env) {
  const template = String(env.GEOIP_LOOKUP_URL || "").trim();
  const allowedHosts = String(env.GEOIP_ALLOWED_HOSTNAMES || "").trim();
  if (!template && !allowedHosts) return;
  if (!template || !allowedHosts) {
    throw new Error("GEOIP_LOOKUP_URL and GEOIP_ALLOWED_HOSTNAMES must be configured together");
  }
  if (!resolveGeoIpLookupUrl(env, "192.0.2.1")) {
    throw new Error("GEOIP_LOOKUP_URL must contain one {ip} placeholder and use an approved HTTPS hostname");
  }
}

async function provisionSub2ApiUser(env, invite) {
  const keyGroup = provisionKeyGroup(invite);
  const tokens = Array.isArray(invite.tokens)
    ? invite.tokens.map((token) => ({
      ...token,
      groupName: token.groupName || keyGroup,
    }))
    : invite.tokens;
  return await callSub2ApiSync(env, "provision", {
    ...invite,
    allowedGroups: [keyGroup],
    tokens,
  });
}

function provisionKeyGroup(invite) {
  if (invite?.keyGroup) return parseKeyGroupName(invite.keyGroup);
  const fromTokens = (Array.isArray(invite?.tokens) ? invite.tokens : [])
    .map((token) => String(token?.groupName || "").trim())
    .find(Boolean);
  if (fromTokens) return parseKeyGroupName(fromTokens);
  const fromConfigs = (Array.isArray(invite?.apiConfigs) ? invite.apiConfigs : [])
    .map((config) => String(config?.groupName || "").trim())
    .find(Boolean);
  if (fromConfigs) return parseKeyGroupName(fromConfigs);
  return DEFAULT_KEY_GROUP_NAME;
}

function sanitizeKeyGroupCatalog(groups) {
  if (!Array.isArray(groups)) return [];
  const seen = new Set();
  const catalog = [];
  for (const group of groups.slice(0, 32)) {
    if (!isPlainJsonObject(group)) continue;
    let name;
    try {
      name = parseKeyGroupName(group.name);
    } catch {
      continue;
    }
    if (seen.has(name)) continue;
    seen.add(name);
    const id = Number(group.id);
    catalog.push({
      id: Number.isSafeInteger(id) && id > 0 ? id : 0,
      name,
      platform: String(group.platform || "").slice(0, 32),
    });
  }
  return catalog;
}

async function loadKeyGroupCatalog(env) {
  try {
    const result = await callSub2ApiSync(env, "list_groups", {});
    return sanitizeKeyGroupCatalog(result.groups);
  } catch {
    return [];
  }
}

function selectedKeyGroupName(invite, catalog) {
  const names = new Set((Array.isArray(catalog) ? catalog : []).map((group) => group.name));
  try {
    const current = provisionKeyGroup(invite);
    if (!names.size || names.has(current)) return current;
  } catch {
    // Fall through to a catalog default.
  }
  if (names.has(DEFAULT_KEY_GROUP_NAME)) return DEFAULT_KEY_GROUP_NAME;
  return catalog[0]?.name || DEFAULT_KEY_GROUP_NAME;
}

function renderKeyGroupPicker(catalog, selected, fieldId = "key_group") {
  const options = Array.isArray(catalog) && catalog.length
    ? catalog
    : [{ name: DEFAULT_KEY_GROUP_NAME, platform: "openai" }];
  const current = options.some((group) => group.name === selected)
    ? selected
    : options[0].name;
  const id = String(fieldId || "key_group");
  return `
    <div class="field span-2">
      <label for="${escapeHtml(id)}">Key group</label>
      <select id="${escapeHtml(id)}" name="key_group" required>
        ${options.map((group) => `
          <option value="${escapeHtml(group.name)}"${group.name === current ? " selected" : ""}>${escapeHtml(group.name)}${group.platform ? ` (${escapeHtml(group.platform)})` : ""}</option>
        `).join("")}
      </select>
      <p class="hint">New keys are created in this model group. The legacy default group is not available.</p>
    </div>
  `;
}

function apiKeyIdFromConfig(invite, configId) {
  const tokenMatch = /^sub2api-token-(\d+)$/.exec(String(configId || "").trim());
  if (tokenMatch) return safePositiveIdentifier(tokenMatch[1]);
  return safePositiveIdentifier(invite?.sub2apiSync?.apiKeyId)
    || safePositiveIdentifier(invite?.sub2apiSync?.tokenId);
}

export async function testInviteApiKey(env, uuid, configId) {
  if (!isUuid(uuid)) throw new Error("Invalid UUID");
  const invite = await getInviteByUuid(env, uuid);
  if (!invite) throw new Error("UUID not found");
  const apiKeyId = apiKeyIdFromConfig(invite, configId);
  if (apiKeyId <= 0) throw new Error("API key is not ready to test");
  const sync = invite.sub2apiSync || {};
  const result = await callSub2ApiSync(env, "test_api_key", {
    uuid: invite.uuid,
    username: desiredSub2ApiUsername(inviteUsername(invite), invite.uuid),
    sub2apiUserId: safePositiveIdentifier(sync.userId),
    apiKeyId,
    tokenId: apiKeyId,
  });
  return {
    uuid: result.uuid,
    tested: result.tested === true,
    httpStatus: Number.isSafeInteger(result.httpStatus) ? result.httpStatus : 0,
    modelCount: Number.isSafeInteger(result.modelCount) ? result.modelCount : 0,
    modelId: String(result.modelId || ""),
    errorCode: String(result.errorCode || ""),
    latencyMs: Number.isSafeInteger(result.latencyMs) ? result.latencyMs : 0,
  };
}

function renderKeyTestResult(result, returnHref) {
  const tested = result?.tested === true;
  const details = [
    result?.httpStatus ? `HTTP ${result.httpStatus}` : "",
    Number.isSafeInteger(result?.modelCount) ? `${result.modelCount} model${result.modelCount === 1 ? "" : "s"}` : "",
    result?.modelId ? `first model ${result.modelId}` : "",
    result?.errorCode ? result.errorCode.replace(/_/g, " ") : "",
  ].filter(Boolean).join(" · ");
  return page(tested ? "API key works" : "API key test failed", `
    <section class="message" role="${tested ? "status" : "alert"}">
      <p class="eyebrow">Key test</p>
      <h1>${tested ? "API key works" : "API key test failed"}</h1>
      <p>${escapeHtml(details || (tested ? "The current key authenticated successfully." : "The current key did not authenticate."))}</p>
      <a href="${escapeHtml(returnHref)}">Return</a>
    </section>
  `);
}

export function keyTestNotice(result) {
  if (result?.tested) {
    const model = result.modelId ? `; first model ${result.modelId}` : "";
    return `API key works. HTTP ${result.httpStatus || 200}. ${result.modelCount || 0} model${result.modelCount === 1 ? "" : "s"}${model}.`;
  }
  const status = result?.httpStatus ? `; HTTP ${result.httpStatus}` : "";
  const code = result?.errorCode ? ` (${result.errorCode.replace(/_/g, " ")})` : "";
  return `API key test failed${code}${status}.`;
}

export async function keyTestAttemptKey(env, identity) {
  const fingerprint = await rateLimitFingerprint(
    env.INVITE_ACCESS_HMAC_KEY,
    "keytest",
    String(identity || ""),
  );
  return `keytest-attempt:${fingerprint}`;
}

async function deprovisionSub2ApiUser(env, invite) {
  const sync = invite.sub2apiSync || {};
  const apiKeyId = safePositiveIdentifier(sync.apiKeyId)
    || safePositiveIdentifier(sync.tokenId);
  return await callSub2ApiSync(env, "deprovision", {
    uuid: invite.uuid,
    username: desiredSub2ApiUsername(inviteUsername(invite), invite.uuid),
    sub2apiUserId: sync.userId || 0,
    sub2apiApiKeyId: apiKeyId,
    tokenId: apiKeyId,
  });
}

async function purgeSub2ApiUser(env, invite) {
  if (!invite.uuid || !sub2apiSyncUrl(env) || !sub2apiSyncSecret(env)) {
    return null;
  }

  const sync = invite.sub2apiSync || {};
  const apiKeyId = safePositiveIdentifier(sync.apiKeyId)
    || safePositiveIdentifier(sync.tokenId);
  return await callSub2ApiSync(env, "purge", {
    uuid: invite.uuid,
    username: desiredSub2ApiUsername(inviteUsername(invite), invite.uuid),
    sub2apiUserId: sync.userId || 0,
    sub2apiApiKeyId: apiKeyId,
    tokenId: apiKeyId,
  });
}

function safePositiveIdentifier(value) {
  const identifier = Number(value || 0);
  return Number.isSafeInteger(identifier) && identifier > 0 ? identifier : 0;
}

function renderUsageInspector(data, _csrf, request) {
  const safeData = sanitizeUsageInspectorData(data);
  return page("Usage Inspector", renderUsageInspectorBody(safeData, request, ADMIN_PATH), "wide");
}


async function listUsageMetadata(env, request) {
  const url = new URL(request.url);
  return await callSub2ApiSync(env, "usage_logs_list", {
    query: String(url.searchParams.get("q") || "").trim(),
    requestId: String(url.searchParams.get("requestId") || "").trim(),
    model: String(url.searchParams.get("model") || "").trim(),
    timePreset: String(url.searchParams.get("timePreset") || "1h").trim().toLowerCase(),
    dateFrom: parseDateTimeLocal(String(url.searchParams.get("dateFrom") || "")),
    dateTo: parseDateTimeLocal(String(url.searchParams.get("dateTo") || "")),
    cursorId: parseUsageIdentifier(url.searchParams.get("cursorId")),
    cursorCreatedAt: String(url.searchParams.get("cursorCreatedAt") || ""),
    pageSize: 25,
  }, 262_144);
}

async function getUsageMetadataDetail(env, request) {
  const url = new URL(request.url);
  const id = parseUsageIdentifier(url.searchParams.get("id"));
  if (id <= 0) {
    throw new Error("Invalid request log id");
  }
  return await callSub2ApiSync(env, "usage_log_detail", { id }, 262_144);
}

function parseUsageIdentifier(value) {
  const text = String(value ?? "");
  if (!/^\d+$/.test(text)) return 0;
  const number = Number(text);
  return Number.isSafeInteger(number) && number >= 0 ? number : 0;
}

async function callSub2ApiSync(env, action, payload, maxBytes = 0) {
  const syncUrl = sub2apiSyncUrl(env);
  const syncSecret = sub2apiSyncSecret(env);
  if (!syncUrl || !syncSecret) {
    throw new Error("Missing Sub2API sync configuration");
  }
  const validatedSyncUrl = validateSub2ApiSyncConfig(env, syncUrl, syncSecret);

  const body = JSON.stringify({
    ...payload,
    action,
  });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomHex(16);
  const requestId = `worker-${randomHex(16)}`;
  const signature = await hmacSha256Hex(syncSecret, `${timestamp}.${nonce}.${body}`);
  let response;
  try {
    response = await fetch(validatedSyncUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sub2api-sync-timestamp": timestamp,
        "x-sub2api-sync-nonce": nonce,
        "x-sub2api-sync-signature": signature,
        "x-request-id": requestId,
      },
      // Workers supports follow/manual only. Manual prevents an unapproved
      // redirect from becoming a second outbound request.
      redirect: "manual",
      signal: AbortSignal.timeout(sub2apiSyncTimeoutForAction(action)),
      body,
    });
  } catch (error) {
    throw new Sub2ApiSyncError({
      status: error?.name === "TimeoutError" ? 504 : 502,
      code: error?.name === "TimeoutError" ? "worker_timeout" : "transport_unavailable",
      retryable: true,
      requestId,
      action,
    });
  }

  let result;
  try {
    result = await readJsonWithLimit(
      response,
      resolveSub2ApiSyncResponseLimit(action, maxBytes),
    );
  } catch {
    throw new Sub2ApiSyncError({
      status: 502,
      code: "invalid_response",
      retryable: true,
      requestId,
      action,
    });
  }
  if (!response.ok) {
    const failure = parseSub2ApiSyncFailure(response, result, action);
    if (failure) throw failure;
    throw new Sub2ApiSyncError({
      status: 502,
      code: "invalid_response",
      retryable: true,
      requestId,
      action,
    });
  }
  if (
    !result
    || typeof result !== "object"
    || Array.isArray(result)
    || result.ok !== true
    || result.action !== action
  ) {
    throw new Error("Sub2API sync request failed");
  }
  validateSub2ApiSyncResult(result, action, payload);
  return result;
}

function sub2apiSyncTimeoutForAction(action) {
  return action === "login" ? SUB2API_SYNC_LOGIN_TIMEOUT_MS : SUB2API_SYNC_TIMEOUT_MS;
}

function parseSub2ApiSyncFailure(response, result, action) {
  if (
    !SUB2API_SYNC_ERROR_STATUSES.has(response.status)
    || !result
    || typeof result !== "object"
    || Array.isArray(result)
    || result.ok !== false
    || typeof result.retryable !== "boolean"
    || !/^[a-z][a-z0-9_]{0,63}$/.test(String(result.error || ""))
    || !/^[A-Za-z0-9._-]{1,64}$/.test(String(result.requestId || ""))
    || (Object.hasOwn(result, "action") && result.action !== action)
  ) {
    return null;
  }
  const responseRequestId = String(response.headers.get("x-request-id") || "");
  if (responseRequestId && responseRequestId !== result.requestId) return null;
  return new Sub2ApiSyncError({
    status: response.status,
    code: result.error,
    retryable: result.retryable,
    requestId: result.requestId,
    action,
  });
}

function resolveSub2ApiSyncResponseLimit(action, requestedMaxBytes) {
  if (Number.isSafeInteger(requestedMaxBytes) && requestedMaxBytes > 0) {
    return requestedMaxBytes;
  }
  return action === "provision" || action === "status"
    ? SUB2API_SYNC_ACCOUNT_RESPONSE_MAX_BYTES
    : SUB2API_SYNC_DEFAULT_RESPONSE_MAX_BYTES;
}

function validateSub2ApiSyncResult(result, action, requestPayload) {
  const requestedUuid = Object.hasOwn(requestPayload || {}, "uuid")
    ? String(requestPayload.uuid || "").toLowerCase()
    : "";
  if (requestedUuid) {
    if (!isUuid(requestedUuid) || result.uuid !== requestedUuid) {
      throw new Error("Sub2API sync request failed");
    }
  }

  if (action === "list_groups" || action === "test_api_key") {
    rejectSyncContentLeak(result);
    if (action === "list_groups") {
      validateListGroupsResult(result);
    } else {
      validateKeyTestResult(result);
    }
    return;
  }

  validateSyncApiKey(result, "apiKey");
  validateSyncApiKey(result, "tokenKey");
  validateOptionalSyncString(result, "loginPassword", 512);
  if (Object.hasOwn(result, "passwordHash")) {
    throw new Error("Sub2API sync request failed");
  }
  if (Object.hasOwn(result, "passwordHashFingerprint")) {
    const fingerprint = result.passwordHashFingerprint;
    if (typeof fingerprint !== "string" || !/^[a-f0-9]{64}$/i.test(fingerprint)) {
      throw new Error("Sub2API sync request failed");
    }
  }

  if (Object.hasOwn(result, "tokens")) {
    if (!Array.isArray(result.tokens) || result.tokens.length > SUB2API_SYNC_MAX_TOKENS) {
      throw new Error("Sub2API sync request failed");
    }
    for (const token of result.tokens) validateSyncToken(token);
  }

  if (action === "login") {
    validateSyncAuth(result.auth);
  } else if (Object.hasOwn(result, "auth")) {
    throw new Error("Sub2API sync request failed");
  }
}

const SYNC_CONTENT_LEAK_FIELDS = Object.freeze([
  "body",
  "content",
  "choices",
  "data",
  "message",
  "prompt",
  "completion",
  "text",
  "authorization",
]);
const SYNC_CREDENTIAL_LEAK_FIELDS = Object.freeze([
  "apiKey",
  "tokenKey",
  "loginPassword",
  "auth",
  "tokens",
]);

function rejectSyncContentLeak(result) {
  for (const field of SYNC_CONTENT_LEAK_FIELDS) {
    if (Object.hasOwn(result, field)) {
      throw new Error("Sub2API sync request failed");
    }
  }
}

function validateListGroupsResult(result) {
  for (const field of SYNC_CREDENTIAL_LEAK_FIELDS) {
    if (Object.hasOwn(result, field)) {
      throw new Error("Sub2API sync request failed");
    }
  }
  if (!Array.isArray(result.groups) || result.groups.length > 32) {
    throw new Error("Sub2API sync request failed");
  }
  for (const group of result.groups) {
    if (!isPlainJsonObject(group)) throw new Error("Sub2API sync request failed");
    try {
      parseKeyGroupName(group.name);
    } catch {
      throw new Error("Sub2API sync request failed");
    }
  }
}

function validateKeyTestResult(result) {
  for (const field of SYNC_CREDENTIAL_LEAK_FIELDS) {
    if (Object.hasOwn(result, field)) {
      throw new Error("Sub2API sync request failed");
    }
  }
  if (typeof result.tested !== "boolean") {
    throw new Error("Sub2API sync request failed");
  }
  for (const field of ["httpStatus", "modelCount", "latencyMs"]) {
    if (Object.hasOwn(result, field)
        && (!Number.isSafeInteger(result[field]) || result[field] < 0)) {
      throw new Error("Sub2API sync request failed");
    }
  }
  validateOptionalSyncString(result, "modelId", 128);
  validateOptionalSyncString(result, "errorCode", 64);
}

function validateSyncToken(token) {
  if (!isPlainJsonObject(token)) throw new Error("Sub2API sync request failed");
  validateSyncApiKey(token, "apiKey");
  validateSyncApiKey(token, "tokenKey");
  validateOptionalSyncString(token, "name", 100);
  if (Object.hasOwn(token, "groupName") && token.groupName) {
    try {
      parseKeyGroupName(token.groupName);
    } catch {
      throw new Error("Sub2API sync request failed");
    }
  }
  for (const field of ["apiKeyId", "tokenId"]) {
    if (Object.hasOwn(token, field)
        && (!Number.isSafeInteger(token[field]) || token[field] <= 0)) {
      throw new Error("Sub2API sync request failed");
    }
  }
  if (Object.hasOwn(token, "status")
      && ![0, 1, true, false, "active", "disabled"].includes(token.status)) {
    throw new Error("Sub2API sync request failed");
  }
}

function validateSyncApiKey(value, field) {
  if (!Object.hasOwn(value, field)) return;
  const credential = value[field];
  if (typeof credential !== "string"
      || (credential !== "" && !isSub2ApiTokenKey(credential))) {
    throw new Error("Sub2API sync request failed");
  }
}

function validateOptionalSyncString(value, field, maximumLength) {
  if (!Object.hasOwn(value, field)) return;
  if (typeof value[field] !== "string" || value[field].length > maximumLength) {
    throw new Error("Sub2API sync request failed");
  }
}

function validateSyncAuth(auth) {
  if (!isPlainJsonObject(auth)) throw new Error("Sub2API sync request failed");
  if (Object.keys(auth).some((field) => !SYNC_AUTH_KEYS.has(field))) {
    throw new Error("Sub2API sync request failed");
  }
  if (typeof auth.access_token !== "string"
      || !auth.access_token
      || exceedsUtf8ByteLimit(auth.access_token, SUB2API_SYNC_MAX_AUTH_TOKEN_BYTES)) {
    throw new Error("Sub2API sync request failed");
  }
  if (Object.hasOwn(auth, "refresh_token")
      && (typeof auth.refresh_token !== "string"
        || exceedsUtf8ByteLimit(auth.refresh_token, SUB2API_SYNC_MAX_AUTH_TOKEN_BYTES))) {
    throw new Error("Sub2API sync request failed");
  }
  if (Object.hasOwn(auth, "expires_in")
      && (!Number.isSafeInteger(auth.expires_in)
        || auth.expires_in < 0
        || auth.expires_in > 31_536_000)) {
    throw new Error("Sub2API sync request failed");
  }
  if (Object.hasOwn(auth, "user")) {
    if (!isPlainJsonObject(auth.user)) throw new Error("Sub2API sync request failed");
    for (const [field, value] of Object.entries(auth.user)) {
      if (!SYNC_AUTH_USER_KEYS.has(field)) {
        throw new Error("Sub2API sync request failed");
      }
      if (typeof value === "boolean" || Number.isSafeInteger(value)) continue;
      if (typeof value === "string"
          && !exceedsUtf8ByteLimit(value, SUB2API_SYNC_MAX_AUTH_USER_FIELD_BYTES)) {
        continue;
      }
      throw new Error("Sub2API sync request failed");
    }
    let encoded;
    try {
      encoded = JSON.stringify(auth.user);
    } catch {
      throw new Error("Sub2API sync request failed");
    }
    if (exceedsUtf8ByteLimit(encoded, SUB2API_SYNC_MAX_AUTH_USER_BYTES)) {
      throw new Error("Sub2API sync request failed");
    }
  }
}

function isPlainJsonObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function desiredSub2ApiUsername(name, uuid) {
  const normalized = normalizeInviteUsername(name);
  if (normalized) {
    return normalized;
  }
  const compact = String(uuid || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  if (compact.length !== 32) {
    throw new Error("Invalid UUID");
  }
  return `u${compact.slice(0, 11)}`;
}

function inviteUsername(invite) {
  return String(invite?.username || invite?.name || invite?.sub2apiSync?.username || "").trim();
}

function normalizeInviteUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[._-]+|[._-]+$/g, "")
    .slice(0, 100);
}

function validateInviteUsername(value, uuid) {
  const normalized = normalizeInviteUsername(value);
  if (normalized) {
    return normalized;
  }
  if (!isUuid(uuid)) {
    throw new Error("Invalid UUID");
  }
  throw new Error("Username is required");
}

function assertUniqueInviteUsername(invites, username, excludeUuid = null) {
  const normalized = normalizeInviteUsername(username);
  if (!normalized) {
    throw new Error("Username is required");
  }
  const duplicate = invites.find((invite) => invite.uuid !== excludeUuid && normalizeInviteUsername(inviteUsername(invite)) === normalized);
  if (duplicate) {
    throw new Error("Username already exists");
  }
}

function mergeSub2ApiConfig(env, configs, syncResult) {
  const normalized = normalizeApiConfigs(configs).filter((config) => config.id !== "sub2api-sync" && !String(config.id || "").startsWith("sub2api-token-"));
  const tokenConfigs = sub2apiTokenConfigs(env, syncResult);
  if (tokenConfigs.length === 0) {
    return dedupeApiConfigs(normalized);
  }

  const tokenKeys = new Set(tokenConfigs.map(apiConfigDedupeKey));
  const tokenApiKeys = new Set(tokenConfigs.map((config) => String(config.apiKey || "").trim()).filter(Boolean));
  const tokenBaseUrls = new Set(tokenConfigs.map((config) => normalizeBaseUrl(config.baseUrl)).filter(Boolean));
  const remaining = normalized.filter((config) => {
    const name = normalizeApiName(config.name);
    const apiKey = String(config.apiKey || "").trim();
    const baseUrl = normalizeBaseUrl(config.baseUrl);

    if (tokenKeys.has(apiConfigDedupeKey(config))) {
      return false;
    }
    if (apiKey && tokenApiKeys.has(apiKey) && baseUrl && tokenBaseUrls.has(baseUrl)) {
      return false;
    }
    if ((name === "sub2api" || tokenBaseUrls.has(baseUrl)) && apiKey && tokenApiKeys.has(apiKey)) {
      return false;
    }
    return true;
  });

  return dedupeApiConfigs([...tokenConfigs, ...remaining]);
}

function dedupeApiConfigs(configs) {
  const seen = new Set();
  return normalizeApiConfigs(configs).filter((config) => {
    const key = apiConfigDedupeKey(config);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function apiConfigDedupeKey(config) {
  return [
    normalizeApiName(config.name),
    normalizeBaseUrl(config.baseUrl),
    String(config.apiKey || "").trim(),
  ].join("|");
}

function isSub2ApiTokenKey(value) {
  return /^[A-Za-z0-9]{48}$/.test(value) || /^sk-[A-Za-z0-9]{1,125}$/.test(value);
}

function desiredSub2ApiTokens(env, configs) {
  const defaultBaseUrl = configuredSub2ApiBaseUrl(env);
  const seen = new Set();
  return normalizeApiConfigs(configs)
    .filter((item) => {
      const name = normalizeApiName(item.name);
      return name === "sub2api" || normalizeBaseUrl(item.baseUrl) === defaultBaseUrl;
    })
    .map((item) => {
      const key = String(item.apiKey || "").trim();
      const name = String(item.name || "Sub2API").trim().slice(0, 30) || "Sub2API";
      return {
        tokenKey: isSub2ApiTokenKey(key) ? key : "",
        tokenName: normalizeApiName(name) === "sub2api" ? "Sub2API" : name,
        ...(item.groupName ? { groupName: item.groupName } : {}),
      };
    })
    .filter((item) => {
      if (!item.tokenKey || seen.has(item.tokenKey)) {
        return false;
      }
      seen.add(item.tokenKey);
      return true;
    });
}

function sub2apiTokenConfigs(env, syncResult) {
  const baseUrl = approvedPublicHttpsUrl(env, syncResult?.baseUrl || configuredSub2ApiBaseUrl(env));
  if (!baseUrl) {
    return [];
  }

  const tokens = Array.isArray(syncResult?.tokens) && syncResult.tokens.length
    ? syncResult.tokens
    : syncResult?.tokenKey
      ? [{ tokenId: syncResult.tokenId, name: "Sub2API", tokenKey: syncResult.tokenKey, status: 1 }]
      : [];
  const activeTokens = tokens.filter((token) => Number(token.status || 0) === 1 && String(token.tokenKey || "").trim());
  const hasCanonicalSub2Api = activeTokens.some((token) => normalizeApiName(token.name) === "sub2api");

  return activeTokens
    .filter((token) => !(hasCanonicalSub2Api && normalizeApiName(token.name) === "workerallowip"))
    .map((token) => ({
      id: Number(token.tokenId || 0) === Number(syncResult?.tokenId || 0) ? "sub2api-sync" : `sub2api-token-${token.tokenId || randomHex(4)}`,
      name: displayApiName(token.name),
      baseUrl,
      apiKey: String(token.tokenKey || "").trim(),
      ...(token.groupName ? { groupName: String(token.groupName) } : {}),
    }));
}

function displayApiName(name) {
  const value = String(name || "").trim();
  return normalizeApiName(value) === "sub2api" ? "Sub2API" : value || "Sub2API";
}

function normalizeApiName(name) {
  return String(name || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

async function sub2apiSyncMetadata(env, syncResult) {
  return {
    userId: Number(syncResult?.userId || 0),
    tokenId: Number(syncResult?.tokenId || 0),
    username: String(syncResult?.username || ""),
    email: String(syncResult?.email || ""),
    loginPassword: String(syncResult?.loginPassword || ""),
    loginUrl: approvedPublicHttpsUrl(env, syncResult?.loginUrl || ""),
    passwordHashFingerprint: syncResult?.passwordHash
      ? await passwordHashFingerprint(env.INVITE_ACCESS_HMAC_KEY, syncResult.passwordHash)
      : String(syncResult?.passwordHashFingerprint || ""),
    syncedAt: String(syncResult?.syncedAt || new Date().toISOString()),
  };
}

function configuredSub2ApiBaseUrl(env) {
  return approvedPublicHttpsUrl(env, env.SUB2API_DEFAULT_BASE_URL || env.SUB2API_BASE_URL || "");
}

function sub2apiSyncUrl(env) {
  return env.SUB2API_SYNC_URL || "";
}

function sub2apiSyncSecret(env) {
  return env.SUB2API_SYNC_SECRET || "";
}

function validateSub2ApiSyncConfig(env, syncUrl, syncSecret) {
  if (String(syncSecret).length < 32) {
    throw new Error("SUB2API_SYNC_SECRET must be at least 32 characters");
  }

  let url;
  try {
    url = new URL(syncUrl);
  } catch {
    throw new Error("SUB2API_SYNC_URL must be a valid URL");
  }

  if (url.protocol !== "https:") {
    throw new Error("SUB2API_SYNC_URL must use https");
  }
  if (url.username || url.password) {
    throw new Error("SUB2API_SYNC_URL must not include URL credentials");
  }
  if (url.pathname !== "/_sub2api-sync/provision" || url.search || url.hash) {
    throw new Error("SUB2API_SYNC_URL must use the dedicated /_sub2api-sync/provision endpoint");
  }

  const approved = parseApprovedHttpsUrl(syncUrl, env.ALLOWED_HOSTNAMES);
  if (!approved) {
    throw new Error("SUB2API_SYNC_URL hostname must be in ALLOWED_HOSTNAMES");
  }
  return approved.href;
}

function parseApiConfigs(value, env, { allowExistingCredentialReferences = false } = {}) {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split("|").map((part) => part.trim());
      if (parts.length >= 3) {
        const credential = parts.slice(2).join("|").trim();
        const existingCredentialId = parseExistingCredentialMarker(credential);
        if (existingCredentialId !== null) {
          if (!allowExistingCredentialReferences) {
            throw new Error("Stored API credential references are only valid for invite updates");
          }
          return {
            name: parts[0],
            baseUrl: requireApprovedApiConfigUrl(env, parts[0], parts[1]),
            apiKey: "",
            existingCredentialId,
          };
        }
        return { name: parts[0], baseUrl: requireApprovedApiConfigUrl(env, parts[0], parts[1]), apiKey: credential };
      }
      if (parts.length === 2) {
        return { name: parts[0], baseUrl: requireApprovedApiConfigUrl(env, parts[0], parts[1]), apiKey: "" };
      }
      return { name: "Sub2API", baseUrl: requireApprovedApiConfigUrl(env, "Sub2API", parts[0]), apiKey: "" };
    });
}

function existingCredentialMarker(credentialId) {
  const id = String(credentialId || "");
  if (!id || id.length > 128) {
    throw new Error("Stored API credential reference is invalid");
  }
  return `${EXISTING_CREDENTIAL_MARKER_PREFIX}${encodeURIComponent(id)}`;
}

function parseExistingCredentialMarker(value) {
  const marker = String(value || "");
  if (!marker.startsWith(EXISTING_CREDENTIAL_MARKER_PREFIX)) return null;
  const encodedId = marker.slice(EXISTING_CREDENTIAL_MARKER_PREFIX.length);
  let id;
  try {
    id = decodeURIComponent(encodedId);
  } catch {
    throw new Error("Stored API credential reference is invalid");
  }
  if (!id || id.length > 128 || encodeURIComponent(id) !== encodedId) {
    throw new Error("Stored API credential reference is invalid");
  }
  return id;
}

function resolveExistingCredentialReferences(env, configs, storedInvite, revealedInvite) {
  const storedConfigs = Array.isArray(storedInvite?.apiConfigs) ? storedInvite.apiConfigs : [];
  const revealedConfigs = Array.isArray(revealedInvite?.apiConfigs) ? revealedInvite.apiConfigs : [];
  const storedById = uniqueCredentialConfigMap(storedConfigs);
  const revealedById = uniqueCredentialConfigMap(revealedConfigs);
  const referencedIds = new Set();

  return (Array.isArray(configs) ? configs : []).map((config) => {
    const credentialId = String(config?.existingCredentialId || "");
    if (!credentialId) return config;
    if (referencedIds.has(credentialId)) {
      throw new Error("Stored API credential reference is invalid");
    }
    referencedIds.add(credentialId);

    const storedConfig = storedById.get(credentialId);
    const revealedConfig = revealedById.get(credentialId);
    if (
      !storedConfig
      || !revealedConfig
      || !(storedConfig.apiKeyEncrypted || storedConfig.apiKey)
      || !String(revealedConfig.apiKey || "").trim()
    ) {
      throw new Error("Stored API credential reference is invalid");
    }

    const storedBaseUrl = approvedApiConfigUrl(env, storedConfig);
    const submittedBaseUrl = approvedApiConfigUrl(env, config);
    if (!storedBaseUrl || submittedBaseUrl !== storedBaseUrl) {
      throw new Error("Stored API credential endpoint cannot be changed without a new API key");
    }

    return {
      id: credentialId,
      name: config.name,
      baseUrl: storedBaseUrl,
      apiKey: String(revealedConfig.apiKey),
    };
  });
}

function uniqueCredentialConfigMap(configs) {
  const result = new Map();
  const duplicates = new Set();
  for (const config of configs) {
    const id = String(config?.id || "");
    if (!id) continue;
    if (result.has(id)) duplicates.add(id);
    result.set(id, config);
  }
  for (const id of duplicates) result.delete(id);
  return result;
}

function normalizeApiConfigs(configs) {
  if (!Array.isArray(configs)) {
    return [];
  }

  return configs
    .map((config) => {
      let groupName = "";
      try {
        groupName = parseKeyGroupName(config.groupName, { required: false });
      } catch {
        groupName = "";
      }
      return {
        id: config.id || randomHex(8),
        name: displayApiName(config.name).slice(0, 80),
        baseUrl: normalizeBaseUrl(config.baseUrl),
        apiKey: String(config.apiKey || "").trim(),
        ...(groupName ? { groupName } : {}),
      };
    })
    .filter(isUsableApiConfig)
    .slice(0, 8);
}

function normalizeApiConfigEditorRows(configs) {
  if (!Array.isArray(configs)) return [];
  return configs
    .map((config) => ({
      id: String(config?.id || "").slice(0, 128),
      name: displayApiName(config?.name).slice(0, 80),
      baseUrl: normalizeBaseUrl(config?.baseUrl),
      apiKey: String(config?.apiKey || "").trim(),
      credentialConfigured: Boolean(config?.credentialConfigured || config?.apiKeyEncrypted),
    }))
    .filter((config) => (
      config.baseUrl
      && (config.apiKey || (config.credentialConfigured && config.id))
    ))
    .slice(0, 8);
}

function isUsableApiConfig(config) {
  return config && normalizeBaseUrl(config.baseUrl) && String(config.apiKey || "").trim();
}

function normalizeBaseUrl(value) {
  const input = String(value || "").trim();
  if (!input) {
    return "";
  }

  try {
    const url = new URL(input);
    if (url.protocol !== "https:" || url.username || url.password) return "";
    return url.href.replace(/\/$/, "");
  } catch {
    return "";
  }
}

function approvedPublicHttpsUrl(env, value) {
  const approved = parseApprovedHttpsUrl(value, env.ALLOWED_HOSTNAMES);
  return approved ? approved.href.replace(/\/$/, "") : "";
}

function approvedProviderHttpsUrl(env, value) {
  const publicHostnames = new Set(parseApprovedHostnames(env.ALLOWED_HOSTNAMES));
  const providerHostnames = parseApprovedHostnames(env.PROVIDER_ALLOWED_HOSTNAMES);
  if (providerHostnames.some((hostname) => publicHostnames.has(hostname))) {
    return "";
  }
  const approved = parseApprovedHttpsUrl(value, providerHostnames);
  return approved ? approved.href.replace(/\/$/, "") : "";
}

function validateHostnameAllowlistSeparation(env) {
  const publicHostnames = parseApprovedHostnames(env.ALLOWED_HOSTNAMES);
  if (publicHostnames.length === 0) {
    throw new Error("ALLOWED_HOSTNAMES must contain valid public hostnames");
  }

  const providerRaw = String(env.PROVIDER_ALLOWED_HOSTNAMES || "").trim();
  const providerHostnames = parseApprovedHostnames(providerRaw);
  if (providerRaw && providerHostnames.length === 0) {
    throw new Error("PROVIDER_ALLOWED_HOSTNAMES must contain valid provider hostnames");
  }
  const publicSet = new Set(publicHostnames);
  if (providerHostnames.some((hostname) => publicSet.has(hostname))) {
    throw new Error("PROVIDER_ALLOWED_HOSTNAMES must not contain a public ALLOWED_HOSTNAMES hostname");
  }
  return { publicHostnames, providerHostnames };
}

function isManagedSub2ApiConfig(env, config) {
  const id = String(config?.id || "");
  const name = normalizeApiName(config?.name);
  const baseUrl = normalizeBaseUrl(config?.baseUrl);
  const configuredBaseUrl = configuredSub2ApiBaseUrl(env);
  return name === "sub2api"
    || id === "sub2api-sync"
    || id.startsWith("sub2api-token-")
    || Boolean(baseUrl && configuredBaseUrl && baseUrl === configuredBaseUrl);
}

function approvedApiConfigUrl(env, config) {
  const value = config?.baseUrl || "";
  return isManagedSub2ApiConfig(env, config)
    ? approvedPublicHttpsUrl(env, value)
    : approvedProviderHttpsUrl(env, value);
}

function requireApprovedApiConfigUrl(env, name, value) {
  const normalized = approvedApiConfigUrl(env, { name, baseUrl: value });
  if (!normalized) {
    throw new Error("API Base URL must use HTTPS and an approved hostname for its endpoint type");
  }
  return normalized;
}

function sanitizeInviteUrls(env, invite) {
  const sync = invite.sub2apiSync || {};
  return {
    ...invite,
    apiConfigs: (invite.apiConfigs || [])
      .map((config) => ({ ...config, baseUrl: approvedApiConfigUrl(env, config) }))
      .filter((config) => config.baseUrl),
    sub2apiSync: { ...sync, loginUrl: approvedPublicHttpsUrl(env, sync.loginUrl) },
  };
}

function formatApiConfigEditorRows(configs) {
  return normalizeApiConfigEditorRows(configs)
    .map((config) => {
      const credential = config.credentialConfigured
        ? existingCredentialMarker(config.id)
        : config.apiKey;
      return `${config.name} | ${config.baseUrl} | ${credential}`;
    })
    .join("\n");
}

function defaultSub2ApiBaseUrl(env, request) {
  const configured = approvedPublicHttpsUrl(env, env.SUB2API_DEFAULT_BASE_URL || env.SUB2API_BASE_URL || "");
  if (configured) {
    return configured;
  }

  try {
    return approvedPublicHttpsUrl(env, `${new URL(request.url).origin}/v1`);
  } catch {
    return "";
  }
}

function renderAdminSetupError(message) {
  return page("Admin Not Configured", `
    <section class="message">
      <h1>Admin not configured</h1>
      <p>${escapeHtml(message)}</p>
      <a href="${ADMIN_PATH}">Back</a>
    </section>
  `);
}

function renderMessage(title, message) {
  return page(title, `
    <section class="message">
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
      <a href="${ADMIN_PATH}">Back</a>
    </section>
  `);
}

function prepareIssuedAccessKeysResponse(items, remainingCount = 0, returnHref = ADMIN_PATH) {
  const response = html(
    renderIssuedAccessKeys(items, remainingCount, returnHref),
    200,
    ISSUED_ACCESS_KEYS_HTML_MAX_BYTES,
  );
  if (response.status !== 200) {
    throw new Error("issued_access_key_response_too_large");
  }
  return response;
}

function renderIssuedAccessKeys(items, remainingCount = 0, returnHref = ADMIN_PATH) {
  const rows = items.length
    ? items.map((item) => `
      <div class="endpoint-summary">
        <strong>${escapeHtml(item.username || item.uuid)}</strong>
        <code>${escapeHtml(item.accessKey)}</code>
        <button class="secondary compact copy-value" type="button" data-copy="${escapeHtml(item.accessKey)}">Copy</button>
      </div>
    `).join("")
    : `<p>No unmigrated UUID accounts were found.</p>`;
  return page("Access keys issued", `
    <section class="message wide">
      <p class="eyebrow">One-time credentials</p>
      <h1>Access keys issued</h1>
      <p>These keys are shown once. Distribute them securely before leaving this page.</p>
      <div class="endpoint-summary-list">${rows}</div>
      ${remainingCount > 0 ? `<p class="muted">${escapeHtml(String(remainingCount))} account${remainingCount === 1 ? "" : "s"} remain. Return to admin and run the next batch after saving these keys.</p>` : ""}
      <a href="${escapeHtml(returnHref)}">Return to admin</a>
    </section>
  `, "wide");
}

function sub2apiIcon(size = "") {
  return `
    <span class="sub2api-icon ${escapeHtml(size)}" aria-hidden="true">
      <img src="${SUB2API_FAVICON}" alt="" />
    </span>
  `;
}

function page(title, body, layout = "narrow") {
  return (nonce) => {
    const mainClass = layout === "wide" ? "wide" : "";
    const bodyClass = layout === "wide" ? "wide-layout" : "";
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
      grid-template-columns: minmax(0, 1fr);
      place-items: center;
      padding: 40px 20px;
      background: #f5f5f7;
    }
    .wide-layout { align-items: start; }
    main { width: 100%; max-width: 420px; min-width: 0; justify-self: center; }
    main.wide { max-width: 1320px; }
    form, .message, .admin, .create, .hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      min-width: 0;
      gap: 16px;
    }
    .hero { margin-bottom: 32px; text-align: center; }
    .sub2api-icon {
      width: 72px;
      height: 72px;
      margin: 0 auto 6px;
      border-radius: 20px;
      display: inline-grid;
      flex: 0 0 auto;
      place-items: center;
      overflow: hidden;
      background: transparent;
      box-shadow: 0 4px 12px rgba(0,0,0,0.08), 0 20px 48px rgba(0,0,0,0.12);
    }
    .sub2api-icon.compact {
      width: 48px;
      height: 48px;
      margin: 0;
      border-radius: 14px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08), 0 12px 32px rgba(0,0,0,0.1);
    }
    .sub2api-icon img { width: 100%; height: 100%; display: block; }
    .admin { gap: 28px; }
    .create-panel, .invite-list, .trash-list, .invite-card, .api-config-editor, .api-config-rows {
      grid-template-columns: minmax(0, 1fr);
      min-width: 0;
    }
    .create-panel { display: grid; gap: 20px; }
    .section-head, .subhead, .invite-meta, .form-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
    }
    .pagination {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-height: 36px;
    }
    .section-head h2, .subhead h3 { margin: 0; color: #1d1d1f; line-height: 1.2; }
    .section-head h2 { font-size: 20px; font-weight: 700; letter-spacing: 0; }
    .subhead h3 { font-size: 14px; font-weight: 600; }
    .invite-list, .trash-list { display: grid; gap: 16px; }
    .invite-card { display: grid; gap: 20px; }
    .invite-main {
      display: grid;
      grid-template-columns: minmax(420px, 1.05fr) minmax(380px, 0.95fr);
      gap: 20px;
      align-items: start;
    }
    .invite-meta {
      padding-bottom: 16px;
      border-bottom: 0.5px solid rgba(0, 0, 0, 0.08);
    }
    .invite-meta > div { min-width: 0; }
    .invite-heading { display: grid; grid-template-columns: minmax(0, 1fr); min-width: 0; gap: 8px; }
    .invite-heading small { min-width: 0; overflow-wrap: anywhere; }
    .trash-card { display: grid; gap: 12px; }
    .inspector-panel, .inspector-filters, .detail-card { display: grid; gap: 16px; }
    .inspector-filter-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .nav-link { text-decoration: none; }
    .admin-tabs {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    }
    .admin-tabs .nav-link {
      min-width: 0;
      padding: 10px 12px;
      border-radius: 0;
      background: transparent;
      color: #5f6065;
      text-align: center;
      border-bottom: 2px solid transparent;
      box-shadow: none;
    }
    .admin-tabs .nav-link.active {
      color: #1d1d1f;
      border-bottom-color: #0071e3;
      font-weight: 600;
    }
    .admin-tabs .nav-link:hover { background: rgba(0, 0, 0, 0.035); box-shadow: none; }
    .usage-list { display: grid; gap: 10px; }
    .usage-row { display: grid; grid-template-columns: minmax(220px, 1fr) auto auto; align-items: center; gap: 14px; padding: 14px 0; border-bottom: 1px solid rgba(0, 0, 0, 0.08); }
    .usage-row:last-child { border-bottom: 0; }
    .usage-row-main { display: grid; grid-template-columns: minmax(0, 1fr); gap: 4px; min-width: 0; }
    .usage-row-main strong, .usage-row-main span { min-width: 0; overflow-wrap: anywhere; }
    .usage-row-main code { min-width: 0; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .usage-detail { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; margin: 0; background: rgba(0, 0, 0, 0.08); }
    .usage-detail div { min-width: 0; padding: 14px; background: #fff; }
    .usage-detail dt { color: #5f6065; font-size: 13px; }
    .usage-detail dd { margin: 5px 0 0; font-size: 14px; overflow-wrap: anywhere; }
    .clipboard-status {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
    .invite-summary, .endpoint-summary-list { display: grid; gap: 12px; min-width: 0; }
    .key-test-form { margin: 0; }
    .endpoint-summary { display: grid; gap: 5px; padding: 12px; border: 0.5px solid rgba(255, 255, 255, 0.55); border-radius: 16px; background: rgba(255, 255, 255, 0.4); }
    .invite-card { content-visibility: auto; contain-intrinsic-size: auto 520px; }
    .trash-meta {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
    }
    .trash-meta > div:first-child { min-width: 0; }
    .trash-meta strong, .trash-meta small { display: block; overflow-wrap: anywhere; }
    .ip-panel { display: grid; gap: 16px; min-width: 0; }
    .form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .field { display: grid; gap: 6px; min-width: 0; }
    .span-2 { grid-column: 1 / -1; }
    .panel, .message {
      padding: 20px;
      border: 0.5px solid rgba(255, 255, 255, 0.62);
      border-radius: 20px;
      background: rgba(255, 255, 255, 0.64);
      box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 8px 24px rgba(0,0,0,0.06);
      backdrop-filter: blur(20px) saturate(180%);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 8px 0;
    }
    .topbar-title {
      display: flex;
      align-items: center;
      gap: 14px;
      min-width: 0;
    }
    .topbar form { display: block; }
    .topbar p, .muted, small, .lede, .eyebrow { color: #5f6065; }
    .eyebrow {
      margin: 0;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0;
      text-transform: uppercase;
    }
    .lede { font-size: 17px; font-weight: 400; line-height: 1.47; }
    .inline {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      gap: 10px;
    }
    label {
      color: #1d1d1f;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0;
    }
    input, textarea, select {
      width: 100%;
      border: 1px solid rgba(0, 0, 0, 0.1);
      border-radius: 10px;
      padding: 0 14px;
      font-size: 15px;
      font: inherit;
      background: rgba(255, 255, 255, 0.9);
      color: #1d1d1f;
      outline: 0;
      transition: border-color 200ms ease, box-shadow 200ms ease;
    }
    input { height: 40px; }
    textarea {
      min-height: 76px;
      padding-top: 10px;
      resize: vertical;
      line-height: 1.47;
    }
    .api-config-editor {
      display: grid;
      gap: 12px;
      min-width: 0;
      padding: 16px;
      border: 0.5px solid rgba(0, 0, 0, 0.06);
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.02);
    }
    .api-config-labels, .api-config-row {
      display: grid;
      grid-template-columns: minmax(110px, 0.7fr) minmax(210px, 1.35fr) minmax(180px, 1.15fr) auto;
      gap: 8px;
      align-items: center;
    }
    .api-config-labels { color: #5f6065; font-size: 13px; font-weight: 600; }
    .api-config-rows { display: grid; gap: 8px; }
    .api-config-row input { min-width: 0; }
    .api-key-field {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      gap: 8px;
      min-width: 0;
    }
    .api-key-field input { min-width: 0; }
    .credential-meta {
      grid-column: 1 / -1;
      color: #5f6065;
      overflow-wrap: anywhere;
    }
    input:focus, textarea:focus, select:focus {
      border-color: #0071e3;
      box-shadow: 0 0 0 3.5px rgba(0, 113, 227, 0.16);
    }
    button, a {
      min-height: 36px;
      border: 0;
      border-radius: 10px;
      display: inline-grid;
      place-items: center;
      padding: 0 14px;
      background: #0071e3;
      color: #fff;
      font: inherit;
      font-weight: 600;
      font-size: 14px;
      text-decoration: none;
      cursor: pointer;
      transition: transform 120ms ease, background 120ms ease, box-shadow 120ms ease, opacity 120ms ease;
      -webkit-tap-highlight-color: transparent;
    }
    button:hover, a:hover {
      background: #0077ed;
      box-shadow: 0 4px 16px rgba(0, 113, 227, 0.24);
    }
    button:active, a:active { transform: scale(0.98); opacity: 0.9; }
    button.secondary {
      background: rgba(0, 0, 0, 0.05);
      color: #1d1d1f;
      font-weight: 500;
    }
    button.secondary:hover {
      background: rgba(0, 0, 0, 0.08);
      box-shadow: none;
    }
    button.secondary:active { background: rgba(0, 0, 0, 0.1); transform: none; }
    button.danger { background: #ff3b30; }
    button.danger:hover { background: #ff453a; }
    button:disabled {
      background: #d2d2d7;
      color: #5f6065;
      box-shadow: none;
      cursor: not-allowed;
      transform: none;
      opacity: 1;
    }
    button.compact {
      min-height: 30px;
      border-radius: 8px;
      padding: 0 12px;
      font-size: 13px;
    }
    h1 {
      margin: 0;
      font-size: 32px;
      font-weight: 700;
      line-height: 1.1;
      letter-spacing: 0;
    }
    p { margin: 0; line-height: 1.53; }
    .error { color: #d70015; font-weight: 600; }
    .table-wrap { overflow-x: auto; padding: 0; }
    table { width: 100%; border-collapse: collapse; background: transparent; }
    th, td {
      border-bottom: 0.5px solid rgba(0, 0, 0, 0.08);
      padding: 12px;
      text-align: left;
      vertical-align: top;
    }
    tbody tr:last-child td { border-bottom: 0; }
    th { font-size: 13px; color: #5f6065; text-transform: uppercase; font-weight: 600; letter-spacing: 0; }
    code {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .uuid-cell {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }
    .invite-edit { display: grid; gap: 14px; min-width: 0; }
    .inline-actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .hint { color: #5f6065; font-size: 13px; line-height: 1.4; }
    .invite-meta strong { display: block; overflow-wrap: anywhere; }
    td > strong, td > small { display: block; overflow-wrap: anywhere; }
    .stat-row {
      display: flex;
      flex-wrap: wrap;
      min-width: 0;
      max-width: 100%;
      gap: 8px;
    }
    .stat-pill {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border-radius: 999px;
      background: rgba(0, 0, 0, 0.045);
      color: #4f4f53;
      font-size: 13px;
      font-weight: 600;
      line-height: 1;
    }
    .stat-pill.status-ok { background: rgba(46, 125, 50, 0.14); color: #1b5e20; }
    .stat-pill.status-warn { background: rgba(245, 124, 0, 0.14); color: #b45309; }
    .stat-pill.status-error { background: rgba(198, 40, 40, 0.14); color: #b3261e; }
    .stat-pill.pending { background: rgba(0, 113, 227, 0.12); color: #0054b8; }
    .ip-group {
      min-width: 220px;
      border: 0.5px solid rgba(0, 0, 0, 0.08);
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.02);
      overflow: hidden;
    }
    .ip-group + .ip-group { margin-top: 12px; }
    .ip-group-summary {
      list-style: none;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: start;
      padding: 14px 16px;
      cursor: pointer;
    }
    .ip-group-summary::-webkit-details-marker { display: none; }
    .ip-group-summary-main {
      display: grid;
      gap: 8px;
      min-width: 0;
    }
    .ip-group-summary-main strong,
    .ip-group-summary-main small { overflow-wrap: anywhere; }
    .ip-group-body {
      display: grid;
      gap: 14px;
      padding: 0 16px 16px;
      border-top: 0.5px solid rgba(0, 0, 0, 0.06);
    }
    .ip-group-toolbar {
      display: flex;
      justify-content: flex-end;
      padding-top: 14px;
    }
    .ip-preview-list {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 6px;
      max-width: 100%;
    }
    .ip-preview,
    .ip-preview-more {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 9px;
      border-radius: 999px;
      background: rgba(0, 0, 0, 0.045);
      color: #4f4f53;
      font-size: 13px;
    }
    .ip-preview {
      max-width: min(100%, 280px);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .ip-list { display: flex; flex-wrap: wrap; gap: 8px; }
    .time-grid {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      align-items: end;
    }
    .time-grid span { display: grid; gap: 4px; color: #5f6065; font-size: 13px; }
    .expiry-form {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) minmax(88px, 0.35fr);
      align-items: end;
      gap: 8px;
      min-width: 0;
    }
    .expiry-field { display: grid; gap: 4px; min-width: 0; }
    .expiry-field span { color: #5f6065; font-size: 13px; }
    .manual-ip-form {
      display: grid;
      gap: 14px;
      padding: 14px;
      border-radius: 8px;
      border: 0.5px solid rgba(0, 0, 0, 0.08);
      background: rgba(0, 0, 0, 0.02);
    }
    .compact-subhead { align-items: start; }
    .manual-ip-layout {
      display: grid;
      grid-template-columns: minmax(220px, 0.9fr) minmax(260px, 1.1fr);
      gap: 12px;
      align-items: end;
    }
    .manual-ip-input input { height: 36px; }
    .manual-ip-preview {
      display: grid;
      gap: 8px;
      min-width: 0;
      padding: 10px 12px;
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.035);
      border: 0.5px solid rgba(0, 0, 0, 0.05);
    }
    .preview-label { color: #5f6065; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0; }
    .preview-pills { gap: 8px; }
    .muted-pill { opacity: 0.78; }
    .manual-ip-grid {
      display: grid;
      grid-template-columns: minmax(120px, 0.35fr) minmax(220px, 0.75fr);
      gap: 8px;
      align-items: end;
    }
    .manual-ip-grid input[type="datetime-local"] { min-width: 0; }
    .manual-ip-action { display: flex; justify-content: flex-end; }
    .manual-ip-action button { height: 32px; }
    .expiry-form input { height: 32px; border-radius: 8px; font-size: 13px; }
    .expiry-form input[type="datetime-local"] { min-width: 0; }
    .ip-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      max-width: 100%;
      padding: 6px 10px;
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.04);
    }
    .ip-pill code { font-size: 13px; }
    .row-actions { min-width: 128px; }
    .empty { color: #5f6065; text-align: center; padding: 24px 0; }
    button:focus-visible, a:focus-visible, input:focus-visible,
    textarea:focus-visible, select:focus-visible, summary:focus-visible {
      outline: 3px solid rgba(0, 113, 227, 0.32);
      outline-offset: 2px;
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        scroll-behavior: auto !important;
        transition: none !important;
      }
    }
    @media (max-width: 1100px) {
      .invite-main { grid-template-columns: minmax(0, 1fr); }
    }
    @media (max-width: 920px) {
      .inspector-filter-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 680px) {
      body { place-items: start; padding: 20px 16px; }
      .topbar, .section-head, .subhead, .invite-meta, .trash-meta, .form-footer, .ip-group-summary, .pagination {
        display: grid;
        grid-template-columns: minmax(0, 1fr);
        min-width: 0;
      }
      .inline, .form-grid, .invite-main, .api-config-labels, .api-config-row, .inspector-filter-grid {
        grid-template-columns: minmax(0, 1fr);
      }
      .usage-row, .usage-detail {
        grid-template-columns: minmax(0, 1fr);
      }
      .usage-row { align-items: stretch; }
      .usage-row .nav-link { width: 100%; }
      .api-config-labels { display: none; }
      .api-key-field { grid-template-columns: minmax(0, 1fr); }
      .uuid-cell { grid-template-columns: minmax(0, 1fr); }
      .time-grid, .expiry-form, .manual-ip-layout, .manual-ip-grid { grid-template-columns: minmax(0, 1fr); }
      .ip-group-summary { padding: 14px; }
      .ip-group-body { padding: 0 14px 14px; }
      .ip-group-toolbar { justify-content: stretch; }
      .ip-group-toolbar form, .ip-group-toolbar button { width: 100%; }
      .ip-preview-list { justify-content: flex-start; }
      .ip-preview { max-width: 100%; }
      th, td { padding: 10px 8px; }
      h1 { font-size: 28px; }
      .panel, .message { padding: 16px; border-radius: 16px; }
      .admin-tabs { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .admin-tabs .nav-link:last-child { grid-column: 1 / -1; }
    }
    @media (max-width: 240px) {
      body { padding: 16px 6px; }
      .panel, .message { padding: 12px 6px; }
      .topbar-title {
        display: grid;
        grid-template-columns: minmax(0, 1fr);
      }
      .sub2api-icon.compact { width: 40px; height: 40px; }
      .ip-group,
      .expiry-form input[type="datetime-local"],
      .manual-ip-grid input[type="datetime-local"] { min-width: 0; max-width: 100%; }
      .ip-group-summary { padding: 12px 6px; }
      .ip-group-body { padding: 0 6px 12px; }
      button, a {
        min-width: 0;
        padding-inline: 8px;
        white-space: normal;
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
      .panel, .message {
        border-color: rgba(255, 255, 255, 0.14);
        background: rgba(28, 28, 30, 0.62);
        box-shadow: 0 1px 3px rgba(0,0,0,0.2), 0 8px 24px rgba(0,0,0,0.3);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
      }
      label, input, textarea, select { color: #f5f5f7; }
      input, textarea, select {
        background: rgba(255, 255, 255, 0.06);
        border-color: rgba(255, 255, 255, 0.15);
      }
      input:focus, textarea:focus {
        border-color: #0a84ff;
        box-shadow: 0 0 0 3.5px rgba(10, 132, 255, 0.2);
      }
      button, a { background: #0a84ff; }
      button:hover, a:hover { background: #409cff; }
      button.secondary {
        background: rgba(255, 255, 255, 0.1);
        color: #f5f5f7;
      }
      button.secondary:hover { background: rgba(255, 255, 255, 0.16); }
      .admin-tabs { border-bottom-color: rgba(255, 255, 255, 0.12); }
      .admin-tabs .nav-link { background: transparent; color: #aeaeb2; }
      .admin-tabs .nav-link.active { color: #f5f5f7; border-bottom-color: #0a84ff; }
      .admin-tabs .nav-link:hover { background: rgba(255, 255, 255, 0.06); }
      button.secondary:active { background: rgba(255, 255, 255, 0.2); }
      button.danger { background: #ff453a; }
      button.danger:hover { background: #ff6961; }
      .section-head h2, .subhead h3 { color: #f5f5f7; }
      .invite-meta { border-color: rgba(255, 255, 255, 0.08); }
      .api-config-editor {
        border-color: rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.04);
      }
      .manual-ip-form, .manual-ip-preview { background: rgba(255, 255, 255, 0.04); border-color: rgba(255, 255, 255, 0.08); }
      .endpoint-badge { background: rgba(10, 132, 255, 0.22); color: #b4d8ff; }
      .preset-chip.active { background: #f5f5f7; color: #1d1d1f; box-shadow: none; }
      .api-config-labels { color: #98989d; }
      .credential-meta { color: #aeaeb2; }
      .ip-pill, .stat-pill, .ip-preview, .ip-preview-more { background: rgba(255, 255, 255, 0.08); color: #d2d2d7; }
      .stat-pill.status-ok { background: rgba(48, 209, 88, 0.18); color: #b8f5c6; }
      .stat-pill.status-warn { background: rgba(255, 159, 10, 0.18); color: #ffd39a; }
      .stat-pill.status-error { background: rgba(255, 69, 58, 0.2); color: #ffb4ae; }
      .stat-pill.pending { background: rgba(10, 132, 255, 0.18); color: #b4d8ff; }
      .usage-row { border-color: rgba(255, 255, 255, 0.08); }
      .usage-detail { background: rgba(255, 255, 255, 0.08); }
      .usage-detail div { background: #1c1c1e; color: #f5f5f7; }
      .usage-detail dt { color: #aeaeb2; }
      th, td { border-color: rgba(255, 255, 255, 0.08); }
      th, .topbar p, .muted, small { color: #98989d; }
      .hint, .lede, .eyebrow, .preview-label, .expiry-field span, .time-grid span { color: #aeaeb2; }
      .endpoint-summary {
        border-color: rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.04);
      }
      .ip-group { border-color: rgba(255, 255, 255, 0.08); background: rgba(255, 255, 255, 0.04); }
      .ip-group-body { border-color: rgba(255, 255, 255, 0.08); }
      .empty { color: #98989d; }
    }
  </style>
</head>
<body class="${bodyClass}">
  <main class="${mainClass}">${renderedBody}</main>
  <p id="clipboard-status" class="clipboard-status" role="status" aria-live="polite"></p>
  <script nonce="${nonce}">
    const clipboardStatus = document.getElementById("clipboard-status");
    window.copyAdminValue = async (button, value) => {
      const previous = button.textContent;
      try {
        await navigator.clipboard.writeText(value);
        button.textContent = "Copied";
        clipboardStatus?.setAttribute("role", "status");
        if (clipboardStatus) clipboardStatus.textContent = "Copied to clipboard.";
      } catch {
        button.textContent = "Copy failed";
        clipboardStatus?.setAttribute("role", "alert");
        if (clipboardStatus) {
          clipboardStatus.textContent = "Copy failed. Select the value and copy it manually.";
        }
      }
      window.setTimeout(() => { button.textContent = previous; }, 1400);
    };
    document.querySelectorAll("form[data-confirm]").forEach((form) => {
      form.addEventListener("submit", (event) => {
        if (!window.confirm(form.dataset.confirm || "Confirm this action?")) event.preventDefault();
      });
    });
    document.querySelectorAll(".copy-value").forEach((button) => {
      button.addEventListener("click", async () => {
        await window.copyAdminValue(button, button.dataset.copy || "");
      });
    });
    document.querySelectorAll(".key-test-form").forEach((form) => {
      form.addEventListener("submit", () => {
        const button = form.querySelector('button[type="submit"]');
        if (!button || button.disabled) return;
        button.disabled = true;
        button.textContent = "Testing...";
      });
    });
  </script>
</body>
</html>`;
  };
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

function html(body, status = 200, maximumBytes = 0) {
  const nonce = randomHex(16);
  let securedBody = renderTrustedHtml(body, nonce);
  if (maximumBytes > 0 && exceedsUtf8ByteLimit(securedBody, maximumBytes)) {
    securedBody = renderTrustedHtml(renderMessage(
      "Admin page unavailable",
      "Admin page is too large to display safely. Narrow the selected view and try again.",
    ), nonce);
    status = 500;
  }
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
      "content-security-policy": `default-src 'none'; object-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    },
  });
}

function renderTrustedHtml(document, nonce) {
  return typeof document === "function"
    ? String(document(nonce))
    : String(document);
}

function text(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      ...extraHeaders,
    },
  });
}

function isUserFacingAdminError(error) {
  const message = String(error?.message || "");
  return Boolean(
    message === "Invalid UUID" ||
    message === "UUID already exists" ||
    message === "UUID is immutable" ||
    message === "Username is required" ||
    message === "Username already exists" ||
    message === "UUID not found" ||
    message === "A valid 2FA code is required" ||
    message === "Stored API credential reference is invalid" ||
    message === "Stored API credential references are only valid for invite updates" ||
    message === "Stored API credential endpoint cannot be changed without a new API key" ||
    message === "Invalid expiration timestamp" ||
    message === "Invalid key group" ||
    message === "Key group is required" ||
    message === "API key is not ready to test" ||
    message.startsWith("Invalid IP address:") ||
    message === "Cloudflare allowlist update failed"
  );
}

function isAuthStateConflict(error) {
  return String(error?.message || "") === "auth_state_conflict";
}

function getAdminSetupError(env) {
  const missing = [];
  if (!env.INVITE_STORE) missing.push("INVITE_STORE");
  if (!env.AUTH_RATE_LIMITER) missing.push("AUTH_RATE_LIMITER");
  if (!env.ADMIN_USERNAME) missing.push("ADMIN_USERNAME");
  if (!env.ADMIN_PASSWORD_PBKDF2) missing.push("ADMIN_PASSWORD_PBKDF2");
  if (!env.ADMIN_TOTP_SECRET) missing.push("ADMIN_TOTP_SECRET");
  if (!env.CREDENTIAL_ENCRYPTION_KEY) missing.push("CREDENTIAL_ENCRYPTION_KEY");
  if (!env.INVITE_ACCESS_HMAC_KEY) missing.push("INVITE_ACCESS_HMAC_KEY");
  if (!env.ALLOWED_HOSTNAMES) missing.push("ALLOWED_HOSTNAMES");
  if (!env.ACCOUNT_ID) missing.push("ACCOUNT_ID");
  if (!env.IP_LIST_ID) missing.push("IP_LIST_ID");
  if (!env.CLOUDFLARE_API_TOKEN) missing.push("CLOUDFLARE_API_TOKEN");
  if (!sub2apiSyncUrl(env)) {
    missing.push("SUB2API_SYNC_URL");
  }
  if (!sub2apiSyncSecret(env)) {
    missing.push("SUB2API_SYNC_SECRET");
  }
  if (missing.length) {
    return `Missing admin configuration: ${missing.join(", ")}`;
  }
  if (!isCloudflareIdentifier(env.ACCOUNT_ID) || !isCloudflareIdentifier(env.IP_LIST_ID)) {
    return "ACCOUNT_ID and IP_LIST_ID must use valid Cloudflare identifier formats.";
  }
  if (!isValidAdminPasswordRecord(env.ADMIN_PASSWORD_PBKDF2)) {
    return "ADMIN_PASSWORD_PBKDF2 must be a valid PBKDF2-HMAC-SHA256 record.";
  }
  try {
    decodeConfiguredAdminTotpSecret(env.ADMIN_TOTP_SECRET, "ADMIN_TOTP_SECRET");
  } catch (error) {
    return String(error?.message || "Administrator TOTP configuration is invalid.");
  }
  try {
    if (base64UrlByteLength(env.CREDENTIAL_ENCRYPTION_KEY) !== 32) {
      return "CREDENTIAL_ENCRYPTION_KEY must decode to 32 bytes.";
    }
  } catch {
    return "CREDENTIAL_ENCRYPTION_KEY must be valid base64url.";
  }
  if (String(env.INVITE_ACCESS_HMAC_KEY || "").length < 32) {
    return "INVITE_ACCESS_HMAC_KEY must be at least 32 characters.";
  }
  if (String(env.SUB2API_SYNC_SECRET || "").length < 32) {
    return "SUB2API_SYNC_SECRET must be at least 32 characters.";
  }
  try {
    validateHostnameAllowlistSeparation(env);
    validateSub2ApiSyncConfig(env, sub2apiSyncUrl(env), sub2apiSyncSecret(env));
    if (env.SUB2API_DEFAULT_BASE_URL
        && !approvedPublicHttpsUrl(env, env.SUB2API_DEFAULT_BASE_URL)) {
      throw new Error("SUB2API_DEFAULT_BASE_URL must use HTTPS and an approved hostname in the public allowlist");
    }
    if (env.SUB2API_LOGIN_URL
        && !approvedPublicHttpsUrl(env, env.SUB2API_LOGIN_URL)) {
      throw new Error("SUB2API_LOGIN_URL must use HTTPS and an approved hostname in the public allowlist");
    }
    validateGeoIpConfig(env);
  } catch (error) {
    return error.message;
  }
  return "";
}

function recordsKey(uuid) {
  return `records:${uuid}`;
}

async function loginAttemptKey(env, request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const fingerprint = await hmacSha256Hex(
    env.INVITE_ACCESS_HMAC_KEY,
    `admin-login-attempt:${ip}`,
  );
  return `login-attempt:${fingerprint}`;
}

async function stepUpAttemptKey(env, sessionHash) {
  if (!/^[a-f0-9]{64}$/.test(String(sessionHash || ""))) {
    throw new Error("Invalid admin session");
  }
  const fingerprint = await hmacSha256Hex(
    env.INVITE_ACCESS_HMAC_KEY,
    `admin-totp-step-up:${sessionHash}`,
  );
  return `totp-attempt:${fingerprint}`;
}

function requiresStepUpAction(action) {
  return STEP_UP_ACTIONS.has(String(action || ""));
}

function sessionKey(hash) {
  return `session:${hash}`;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64UrlByteLength(value) {
  return base64UrlDecode(value).byteLength;
}

function isValidAdminPasswordRecord(record) {
  const parts = String(record || "").split("$");
  if (
    parts.length !== 4
    || parts[0] !== "pbkdf2_sha256"
    || !/^\d+$/.test(parts[1])
    || !/^[A-Za-z0-9_-]+$/.test(parts[2])
    || !/^[A-Za-z0-9_-]+$/.test(parts[3])
  ) {
    return false;
  }
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) {
    return false;
  }
  try {
    return base64UrlByteLength(parts[2]) >= 16
      && base64UrlByteLength(parts[3]) === 32;
  } catch {
    return false;
  }
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
  return await sha256HexBytes(new TextEncoder().encode(value));
}

async function sha256HexBytes(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret, value) {
  return await hmacSha256HexBytes(secret, new TextEncoder().encode(value));
}

async function hmacSha256HexBytes(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, value);
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function stringOrEmpty(value) {
  return typeof value === "string" ? value : "";
}

function cleanText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}


function expandManualIpEntries(value) {
  const ip = String(value || "").trim();
  const version = detectIpVersion(ip);
  if (!version) {
    throw new Error(`Invalid IP address: ${ip}`);
  }

  const cidr = version === "IPv4" ? ipv4Cidr24(ip) : `${ip}/128`;
  return [{
    ip,
    version,
    cidr,
    listValue: cidr,
  }];
}

function detectIpVersion(value) {
  if (isIPv4(value)) {
    return "IPv4";
  }
  if (isIPv6(value)) {
    return "IPv6";
  }
  return "";
}

function isIPv4(value) {
  const parts = String(value || "").split(".");
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === part;
  });
}

function isIPv6(value) {
  const input = String(value || "").trim();
  if (!input.includes(":") || !/^[0-9a-f:.]+$/i.test(input)) {
    return false;
  }
  try {
    return new URL(`http://[${input}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}


function ipv4Cidr24(ip) {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4) {
    return ip;
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function inviteCredentialStatus(invite, now = Date.now()) {
  if (!invite?.accessKeyHmac) {
    return { state: "migration_required", className: "status-warn", label: "Access key required" };
  }
  const legacyDeadline = Date.parse(String(invite.legacyUuidLoginUntil || ""));
  if (!Number.isFinite(legacyDeadline)) {
    return { state: "access_key_only", className: "status-ok", label: "Access key only" };
  }
  const remainingSeconds = Math.ceil((legacyDeadline - Number(now)) / 1000);
  if (remainingSeconds <= 0) {
    return { state: "legacy_expired", className: "status-ok", label: "Legacy UUID expired" };
  }
  const remainingHours = Math.ceil(remainingSeconds / 3600);
  if (remainingHours <= 48) {
    return {
      state: "legacy_window",
      className: "status-warn",
      label: `Legacy UUID: ${remainingHours} hour${remainingHours === 1 ? "" : "s"} remaining`,
    };
  }
  const remainingDays = Math.ceil(remainingSeconds / 86400);
  return {
    state: "legacy_window",
    className: "status-warn",
    label: `Legacy UUID: ${remainingDays} day${remainingDays === 1 ? "" : "s"} remaining`,
  };
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function shouldRefreshInvitesOnAdminGet() {
  return false;
}

export const __test = Object.freeze({
  sanitizeUsageInspectorData,
  renderUsageInspector,
  shouldRefreshInvitesOnAdminGet,
  getAdminSetupError,
  handleAdminLogin,
  configuredAdminTotpSecrets,
  verifyAdminTotp,
  requireStepUpTotp,
  adminSessionTotpBinding,
  stepUpAttemptKey,
  requiresStepUpAction,
  inviteCredentialStatus,
  detectIpVersion,
  resolveCurrentCloudflareDeleteIds,
  deleteCloudflareListItemIds,
  deleteOrphanedCloudflareListItems,
  ensureManagedCloudflareEntries,
  addManualIpGroup,
  restoreIpGroupFromTrash,
  compensateCloudflareMutation,
  compensateCloudflareMutationIds,
  reconcilePendingCloudflareMutations,
  parseUsageIdentifier,
  getAdminDashboard,
  parseAdminPageNumber,
  parseAdminInvitePostContext,
  renderAdminPagination,
  ADMIN_PAGE_SIZE,
  ADMIN_RECORD_PAYLOAD_MAX_BYTES,
  exceedsUtf8ByteLimit,
  SUB2API_SYNC_TIMEOUT_MS,
  sub2apiSyncTimeoutForAction,
  totp,
  verifyTotp,
  createInvite,
  updateInvite,
  deleteInvite,
  restoreInviteFromTrash,
  compensateProvisionConflict,
  reconcileAuthoritativeInviteAfterConflict,
  restoreAuthoritativeIpAccess,
  rollbackRestoredExternalState,
  rollbackRestoredIpAccess,
  callSub2ApiSync,
  deprovisionSub2ApiUser,
  provisionKeyGroup,
  sanitizeKeyGroupCatalog,
  loadKeyGroupCatalog,
  renderKeyGroupPicker,
  testInviteApiKey,
  keyTestNotice,
  keyTestAttemptKey,
  purgeSub2ApiUser,
  lookupIpLocation,
  resolveGeoIpLookupUrl,
  validateGeoIpConfig,
  approvedApiConfigUrl,
  validateHostnameAllowlistSeparation,
  html,
  renderTrustedHtml,
});
