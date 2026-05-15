const ADMIN_PATH = "/allow-ip/admin";
const COOKIE_NAME = "sub2api_allow_admin";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const INVITES_KEY = "invites";
const TRASH_KEY = "trash";
const DEFAULT_IP_TTL_DAYS = 365;
const LOGIN_ATTEMPT_LIMIT = 5;
const LOGIN_ATTEMPT_TTL_SECONDS = 15 * 60;
const SUB2API_FAVICON = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MSA0MSI+PHBhdGggZD0iTTM3LjUzMjQgMTYuODcwN0MzNy45ODA4IDE1LjUyNDEgMzguMTM2MyAxNC4wOTc0IDM3Ljk4ODYgMTIuNjg1OUMzNy44NDA5IDExLjI3NDQgMzcuMzkzNCA5LjkxMDc2IDM2LjY3NiA4LjY4NjIyQzM1LjYxMjYgNi44MzQwNCAzMy45ODgyIDUuMzY3NiAzMi4wMzczIDQuNDk4NUMzMC4wODY0IDMuNjI5NDEgMjcuOTA5OCAzLjQwMjU5IDI1LjgyMTUgMy44NTA3OEMyNC44Nzk2IDIuNzg5MyAyMy43MjE5IDEuOTQxMjUgMjIuNDI1NyAxLjM2MzQxQzIxLjEyOTUgMC43ODU1NzUgMTkuNzI0OSAwLjQ5MTI2OSAxOC4zMDU4IDAuNTAwMTk3QzE2LjE3MDggMC40OTUwNDQgMTQuMDg5MyAxLjE2ODAzIDEyLjM2MTQgMi40MjIxNEMxMC42MzM1IDMuNjc2MjQgOS4zNDg1MyA1LjQ0NjY2IDguNjkxNyA3LjQ3ODE1QzcuMzAwODUgNy43NjI4NiA1Ljk4Njg2IDguMzQxNCA0LjgzNzcgOS4xNzUwNUMzLjY4ODU0IDEwLjAwODcgMi43MzA3MyAxMS4wNzgyIDIuMDI4MzkgMTIuMzEyQzAuOTU2NDY0IDE0LjE1OTEgMC40OTg5MDUgMTYuMjk4OCAwLjcyMTY5OCAxOC40MjI4QzAuOTQ0NDkyIDIwLjU0NjcgMS44MzYxMiAyMi41NDQ5IDMuMjY4IDI0LjEyOTNDMi44MTk2NiAyNS40NzU5IDIuNjY0MTMgMjYuOTAyNiAyLjgxMTgyIDI4LjMxNDFDMi45NTk1MSAyOS43MjU2IDMuNDA3MDEgMzEuMDg5MiA0LjEyNDM3IDMyLjMxMzhDNS4xODc5MSAzNC4xNjU5IDYuODEyMyAzNS42MzIyIDguNzYzMjEgMzYuNTAxM0MxMC43MTQxIDM3LjM3MDQgMTIuODkwNyAzNy41OTczIDE0Ljk3ODkgMzcuMTQ5MkMxNS45MjA4IDM4LjIxMDcgMTcuMDc4NiAzOS4wNTg3IDE4LjM3NDcgMzkuNjM2NkMxOS42NzA5IDQwLjIxNDQgMjEuMDc1NSA0MC41MDg3IDIyLjQ5NDYgNDAuNDk5OEMyNC42MzA3IDQwLjUwNTQgMjYuNzEzMyAzOS44MzIxIDI4LjQ0MTggMzguNTc3MkMzMC4xNzA0IDM3LjMyMjMgMzEuNDU1NiAzNS41NTA2IDMyLjExMTkgMzMuNTE3OUMzMy41MDI3IDMzLjIzMzIgMzQuODE2NyAzMi42NTQ3IDM1Ljk2NTkgMzEuODIxQzM3LjExNSAzMC45ODc0IDM4LjA3MjggMjkuOTE3OCAzOC43NzUyIDI4LjY4NEMzOS44NDU4IDI2LjgzNzEgNDAuMzAyMyAyNC42OTc5IDQwLjA3ODkgMjIuNTc0OEMzOS44NTU2IDIwLjQ1MTcgMzguOTYzOSAxOC40NTQ0IDM3LjUzMjQgMTYuODcwN1pNMjIuNDk3OCAzNy44ODQ5QzIwLjc0NDMgMzcuODg3NCAxOS4wNDU5IDM3LjI3MzMgMTcuNjk5NCAzNi4xNTAxQzE3Ljc2MDEgMzYuMTE3IDE3Ljg2NjYgMzYuMDU4NiAxNy45MzYgMzYuMDE2MUwyNS45MDA0IDMxLjQxNTZDMjYuMTAwMyAzMS4zMDE5IDI2LjI2NjMgMzEuMTM3IDI2LjM4MTMgMzAuOTM3OEMyNi40OTY0IDMwLjczODYgMjYuNTU2MyAzMC41MTI0IDI2LjU1NDkgMzAuMjgyNVYxOS4wNTQyTDI5LjkyMTMgMjAuOTk4QzI5LjkzODkgMjEuMDA2OCAyOS45NTQxIDIxLjAxOTggMjkuOTY1NiAyMS4wMzU5QzI5Ljk3NyAyMS4wNTIgMjkuOTg0MiAyMS4wNzA3IDI5Ljk4NjcgMjEuMDkwMlYzMC4zODg5QzI5Ljk4NDIgMzIuMzc1IDI5LjE5NDYgMzQuMjc5MSAyNy43OTA5IDM1LjY4NDFDMjYuMzg3MiAzNy4wODkyIDI0LjQ4MzggMzcuODgwNiAyMi40OTc4IDM3Ljg4NDlaTTYuMzkyMjcgMzEuMDA2NEM1LjUxMzk3IDI5LjQ4ODggNS4xOTc0MiAyNy43MTA3IDUuNDk4MDQgMjUuOTgzMkM1LjU1NzE4IDI2LjAxODcgNS42NjA0OCAyNi4wODE4IDUuNzM0NjEgMjYuMTI0NEwxMy42OTkgMzAuNzI0OEMxMy44OTc1IDMwLjg0MDggMTQuMTIzMyAzMC45MDIgMTQuMzUzMiAzMC45MDJDMTQuNTgzIDMwLjkwMiAxNC44MDg4IDMwLjg0MDggMTUuMDA3MyAzMC43MjQ4TDI0LjczMSAyNS4xMTAzVjI4Ljk5NzlDMjQuNzMyMSAyOS4wMTc3IDI0LjcyODMgMjkuMDM3NiAyNC43MTk5IDI5LjA1NTZDMjQuNzExNSAyOS4wNzM2IDI0LjY5ODggMjkuMDg5MyAyNC42ODI5IDI5LjEwMTJMMTYuNjMxNyAzMy43NDk3QzE0LjkwOTYgMzQuNzQxNiAxMi44NjQzIDM1LjAwOTcgMTAuOTQ0NyAzNC40OTU0QzkuMDI1MDYgMzMuOTgxMSA3LjM4Nzg1IDMyLjcyNjMgNi4zOTIyNyAzMS4wMDY0Wk00LjI5NzA3IDEzLjYxOTRDNS4xNzE1NiAxMi4wOTk4IDYuNTUyNzkgMTAuOTM2NCA4LjE5ODg1IDEwLjMzMjdDOC4xOTg4NSAxMC40MDEzIDguMTk0OTEgMTAuNTIyOCA4LjE5NDkxIDEwLjYwNzFWMTkuODA4QzguMTkzNTEgMjAuMDM3OCA4LjI1MzM0IDIwLjI2MzggOC4zNjgyMyAyMC40NjI5QzguNDgzMTIgMjAuNjYxOSA4LjY0ODkzIDIwLjgyNjcgOC44NDg2MyAyMC45NDA0TDE4LjU3MjMgMjYuNTU0MkwxNS4yMDYgMjguNDk3OUMxNS4xODk0IDI4LjUwODkgMTUuMTcwMyAyOC41MTU1IDE1LjE1MDUgMjguNTE3M0MxNS4xMzA3IDI4LjUxOTEgMTUuMTEwNyAyOC41MTYgMTUuMDkyNCAyOC41MDgyTDcuMDQwNDYgMjMuODU1N0M1LjMyMTM1IDIyLjg2MDEgNC4wNjcxNiAyMS4yMjM1IDMuNTUyODkgMTkuMzA0NkMzLjAzODYyIDE3LjM4NTggMy4zMDYyNCAxNS4zNDEzIDQuMjk3MDcgMTMuNjE5NFpNMzEuOTU1IDIwLjA1NTZMMjIuMjMxMiAxNC40NDExTDI1LjU5NzYgMTIuNDk4MUMyNS42MTQyIDEyLjQ4NzIgMjUuNjMzMyAxMi40ODA1IDI1LjY1MzEgMTIuNDc4N0MyNS42NzI5IDEyLjQ3NjkgMjUuNjkyOCAxMi40ODAxIDI1LjcxMTEgMTIuNDg3OUwzMy43NjMxIDE3LjEzNjRDMzQuOTk2NyAxNy44NDkgMzYuMDAxNyAxOC44OTgyIDM2LjY2MDYgMjAuMTYxM0MzNy4zMTk0IDIxLjQyNDQgMzcuNjA0NyAyMi44NDkgMzcuNDgzMiAyNC4yNjg0QzM3LjM2MTcgMjUuNjg3OCAzNi44MzgyIDI3LjA0MzIgMzUuOTc0MyAyOC4xNzU5QzM1LjExMDMgMjkuMzA4NiAzMy45NDE1IDMwLjE3MTcgMzIuNjA0NyAzMC42NjQxQzMyLjYwNDcgMzAuNTk0NyAzMi42MDQ3IDMwLjQ3MzMgMzIuNjA0NyAzMC4zODg5VjIxLjE4OEMzMi42MDY2IDIwLjk1ODYgMzIuNTQ3NCAyMC43MzI4IDMyLjQzMzIgMjAuNTMzOEMzMi4zMTkgMjAuMzM0OCAzMi4xNTQgMjAuMTY5OCAzMS45NTUgMjAuMDU1NlpNMzUuMzA1NSAxNS4wMTI4QzM1LjI0NjQgMTQuOTc2NSAzNS4xNDMxIDE0LjkxNDIgMzUuMDY5IDE0Ljg3MTdMMjcuMTA0NSAxMC4yNzEyQzI2LjkwNiAxMC4xNTU0IDI2LjY4MDMgMTAuMDk0MyAyNi40NTA0IDEwLjA5NDNDMjYuMjIwNiAxMC4wOTQzIDI1Ljk5NDggMTAuMTU1NCAyNS43OTYzIDEwLjI3MTJMMTYuMDcyNiAxNS44ODU4VjExLjk5ODJDMTYuMDcxNSAxMS45NzgzIDE2LjA3NTMgMTEuOTU4NSAxNi4wODM3IDExLjk0MDVDMTYuMDkyMSAxMS45MjI1IDE2LjEwNDggMTEuOTA2OCAxNi4xMjA3IDExLjg5NDlMMjQuMTcxOSA3LjI1MDI1QzI1LjQwNTMgNi41MzkwMyAyNi44MTU4IDYuMTkzNzYgMjguMjM4MyA2LjI1NDgyQzI5LjY2MDggNi4zMTU4OSAzMS4wMzY0IDYuNzgwNzcgMzIuMjA0NCA3LjU5NTA4QzMzLjM3MjMgOC40MDkzOSAzNC4yODQyIDkuNTM5NDUgMzQuODMzNCAxMC44NTMxQzM1LjM4MjYgMTIuMTY2NyAzNS41NDY0IDEzLjYwOTUgMzUuMzA1NSAxNS4wMTI4Wk0xNC4yNDI0IDIxLjk0MTlMMTAuODc1MiAxOS45OTgxQzEwLjg1NzYgMTkuOTg5MyAxMC44NDIzIDE5Ljk3NjMgMTAuODMwOSAxOS45NjAyQzEwLjgxOTUgMTkuOTQ0MSAxMC44MTIyIDE5LjkyNTQgMTAuODA5OCAxOS45MDU4VjEwLjYwNzFDMTAuODEwNyA5LjE4Mjk1IDExLjIxNzMgNy43ODg0OCAxMS45ODE5IDYuNTg2OTZDMTIuNzQ2NiA1LjM4NTQ0IDEzLjgzNzcgNC40MjY1OSAxNS4xMjc1IDMuODIyNjRDMTYuNDE3MyAzLjIxODY5IDE3Ljg1MjQgMi45OTQ2NCAxOS4yNjQ5IDMuMTc2N0MyMC42Nzc1IDMuMzU4NzYgMjIuMDA4OSAzLjkzOTQxIDIzLjEwMzQgNC44NTA2N0MyMy4wNDI3IDQuODgzNzkgMjIuOTM3IDQuOTQyMTUgMjIuODY2OCA0Ljk4NDczTDE0LjkwMjQgOS41ODUxN0MxNC43MDI1IDkuNjk4NzggMTQuNTM2NiA5Ljg2MzU2IDE0LjQyMTUgMTAuMDYyNkMxNC4zMDY1IDEwLjI2MTYgMTQuMjQ2NiAxMC40ODc3IDE0LjI0NzkgMTAuNzE3NUwxNC4yNDI0IDIxLjk0MTlaTTE2LjA3MSAxNy45OTkxTDIwLjQwMTggMTUuNDk3OEwyNC43MzI1IDE3Ljk5NzVWMjIuOTk4NUwyMC40MDE4IDI1LjQ5ODNMMTYuMDcxIDIyLjk5ODVWMTcuOTk5MVoiIGZpbGw9IiMxMTEiLz48L3N2Zz4=";

export async function handleAdmin(request, env) {
  try {
    return await handleAdminRequest(request, env);
  } catch (error) {
    console.error(JSON.stringify({ level: "error", message: "admin_action_failed", error: error.message }));
    const message = isUserFacingAdminError(error)
      ? error.message
      : "The requested admin action could not be completed. Refresh the admin page and try again.";
    return html(renderMessage("Admin action failed", message), isUserFacingAdminError(error) ? 400 : 500);
  }
}

async function handleAdminRequest(request, env) {
  const setupError = getAdminSetupError(env);
  if (setupError) {
    return html(renderAdminSetupError(setupError), 500);
  }

  const session = await getAdminSession(request, env);

  if (request.method === "GET") {
    if (!session) {
      return html(renderLogin());
    }

    await refreshInvitesFromSub2Api(env);
    const invites = await getInvitesWithRecords(env);
    const trash = await getTrash(env);
    return html(renderAdmin(invites, trash, session.csrf, request, env));
  }

  if (request.method !== "POST") {
    return text("Method not allowed", 405, { allow: "GET, POST" });
  }

  const form = await request.formData();
  const action = String(form.get("action") || "");

  if (action === "login") {
    return await handleAdminLogin(form, env, request);
  }

  if (!session) {
    return redirect(ADMIN_PATH);
  }

  if (!(await timingSafeEqual(String(form.get("csrf") || ""), session.csrf))) {
    return html(renderMessage("Invalid request", "Refresh the admin page and try again."), 403);
  }

  if (action === "logout") {
    await deleteSession(env, request);
    return redirect(ADMIN_PATH, `${COOKIE_NAME}=; Path=${ADMIN_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
  }

  if (action === "create") {
    const uuid = String(form.get("uuid") || "").trim();
    const username = cleanText(form.get("username"), 100);
    const email = cleanText(form.get("email"), 160);
    const remark = cleanText(form.get("remark"), 240);
    const apiConfigs = parseApiConfigs(String(form.get("api_configs") || ""));
    await createInvite(env, uuid, { username, email, remark, apiConfigs });
    return redirect(ADMIN_PATH);
  }

  if (action === "update_invite") {
    const originalUuid = String(form.get("original_uuid") || "").trim();
    const uuid = String(form.get("uuid") || "").trim();
    const username = cleanText(form.get("username"), 100);
    const email = cleanText(form.get("email"), 160);
    const remark = cleanText(form.get("remark"), 240);
    const apiConfigs = parseApiConfigs(String(form.get("api_configs") || ""));
    await updateInvite(env, originalUuid, { uuid, username, email, remark, apiConfigs });
    return redirect(ADMIN_PATH);
  }

  if (action === "delete") {
    const uuid = String(form.get("uuid") || "").trim();
    await deleteInvite(env, uuid);
    return redirect(ADMIN_PATH);
  }

  if (action === "restore_uuid") {
    const trashId = String(form.get("trash_id") || "").trim();
    await restoreInviteFromTrash(env, trashId);
    return redirect(ADMIN_PATH);
  }

  if (action === "purge_uuid") {
    const trashId = String(form.get("trash_id") || "").trim();
    await purgeInviteTrash(env, trashId);
    return redirect(ADMIN_PATH);
  }

  if (action === "delete_ip_group") {
    const uuid = String(form.get("uuid") || "").trim();
    const groupId = String(form.get("group_id") || "").trim();
    await deleteIpGroup(env, uuid, groupId);
    return redirect(ADMIN_PATH);
  }

  if (action === "restore_ip_group") {
    const trashId = String(form.get("trash_id") || "").trim();
    await restoreIpGroupFromTrash(env, trashId);
    return redirect(ADMIN_PATH);
  }

  if (action === "purge_ip_group") {
    const trashId = String(form.get("trash_id") || "").trim();
    await purgeIpGroupTrash(env, trashId);
    return redirect(ADMIN_PATH);
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
    return redirect(ADMIN_PATH);
  }

  return redirect(ADMIN_PATH);
}

export async function findInvite(env, input) {
  if (!input) {
    return null;
  }

  if (env.INVITE_STORE) {
    const invites = await getInvites(env);
    const match = invites.find((invite) => invite.uuid === input);
    if (match) {
      return match;
    }
  }

  if (env.INVITE_KEYS && (await isValidConfiguredKey(input, env.INVITE_KEYS))) {
    return { uuid: input, username: "legacy" };
  }

  return null;
}

export async function recordVisitorIp(env, request, invite, result) {
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

  await env.INVITE_STORE.put(recordsKey(invite.uuid), JSON.stringify(nextGroups));
}

export function getInviteApiConfigs(invite, env, request) {
  const configs = Array.isArray(invite.apiConfigs) ? normalizeApiConfigs(invite.apiConfigs) : [];
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

  invite.sub2apiSync = {
    ...previousSync,
    ...sub2apiSyncMetadata({
      ...syncResult,
      loginPassword: syncResult.passwordHash && previousSync.passwordHash && syncResult.passwordHash !== previousSync.passwordHash
        ? ""
        : previousSync.loginPassword,
    }),
    passwordHash: String(syncResult.passwordHash || ""),
    passwordChangedExternally: Boolean(syncResult.passwordHash && previousSync.passwordHash && syncResult.passwordHash !== previousSync.passwordHash),
  };
  invite.apiConfigs = mergeSub2ApiConfig(env, invite.apiConfigs, syncResult);
  invite.updatedAt = new Date().toISOString();
  await saveInvites(env, invites);
  return invite;
}

async function refreshInvitesFromSub2Api(env) {
  const invites = await getInvites(env);
  for (const invite of invites) {
    try {
      await refreshInviteFromSub2Api(env, invite.uuid);
    } catch (error) {
      console.error(JSON.stringify({ level: "warn", message: "sub2api_admin_refresh_failed", uuid: invite.uuid, error: error.message }));
    }
  }
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
  invite.sub2apiSync = sub2apiSyncMetadata(syncResult);
  invite.updatedAt = new Date().toISOString();
  await saveInvites(env, invites);
  return invite;
}

export async function loginInviteToSub2Api(env, invite) {
  const sync = invite.sub2apiSync || {};
  const username = String(sync.username || "");
  const email = String(sync.email || (username ? `${username}@sub2api.local` : ""));
  const password = String(sync.loginPassword || "");
  if (!email || !password) {
    throw new Error("Sub2API login is not ready for this UUID");
  }
  return await callSub2ApiSync(env, "login", {
    uuid: invite.uuid,
    email,
    loginPassword: password,
  });
}

async function handleAdminLogin(form, env, request) {
  const username = String(form.get("username") || "").trim();
  const password = String(form.get("password") || "");
  const token = String(form.get("token") || "").replace(/\s+/g, "");
  const attemptKey = loginAttemptKey(request, username);
  const attempts = Number(await env.INVITE_STORE.get(attemptKey) || "0");
  if (attempts >= LOGIN_ATTEMPT_LIMIT) {
    return html(renderLogin("Too many failed sign-in attempts. Try again later."), 429);
  }

  const usernameOk = await timingSafeEqual(username, env.ADMIN_USERNAME);
  const passwordOk = await verifyPassword(password, env.ADMIN_PASSWORD_HASH);
  const tokenOk = await verifyTotp(env.ADMIN_TOTP_SECRET, token);

  if (!usernameOk || !passwordOk || !tokenOk) {
    await env.INVITE_STORE.put(attemptKey, String(attempts + 1), { expirationTtl: LOGIN_ATTEMPT_TTL_SECONDS });
    return html(renderLogin("The username, password, or 2FA code is incorrect."), 403);
  }
  await env.INVITE_STORE.delete(attemptKey);

  const sessionToken = randomHex(32);
  const sessionHash = await sha256Hex(sessionToken);
  const csrf = randomHex(24);
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;

  await env.INVITE_STORE.put(
    sessionKey(sessionHash),
    JSON.stringify({ csrf, expiresAt }),
    { expirationTtl: SESSION_TTL_SECONDS },
  );

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
  const raw = await env.INVITE_STORE.get(sessionKey(sessionHash));
  if (!raw) {
    return null;
  }

  const session = parseJson(raw, null);
  if (!session || !session.csrf || session.expiresAt < Date.now()) {
    await env.INVITE_STORE.delete(sessionKey(sessionHash));
    return null;
  }

  return session;
}

async function deleteSession(env, request) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const token = cookies[COOKIE_NAME];
  if (token) {
    await env.INVITE_STORE.delete(sessionKey(await sha256Hex(token)));
  }
}

async function getInvitesWithRecords(env) {
  const invites = await getInvites(env);
  const rows = [];

  for (const invite of invites) {
    rows.push({
      ...invite,
      records: await getIpRecords(env, invite.uuid),
    });
  }

  return rows;
}

async function getInvites(env) {
  const raw = await env.INVITE_STORE.get(INVITES_KEY);
  const invites = parseJson(raw, []);
  if (!Array.isArray(invites)) {
    return [];
  }

  return invites
    .filter((invite) => invite && invite.uuid)
    .sort((left, right) => String(right.createdAt || "").localeCompare(String(left.createdAt || "")));
}

async function saveInvites(env, invites) {
  await env.INVITE_STORE.put(INVITES_KEY, JSON.stringify(invites));
}

async function getTrash(env) {
  const raw = await env.INVITE_STORE.get(TRASH_KEY);
  const trash = parseJson(raw, []);
  if (!Array.isArray(trash)) {
    return [];
  }

  return trash
    .filter((item) => item && item.id && item.type)
    .map(normalizeTrashItem)
    .sort((left, right) => String(right.deletedAt || "").localeCompare(String(left.deletedAt || "")));
}

async function saveTrash(env, trash) {
  await env.INVITE_STORE.put(TRASH_KEY, JSON.stringify(trash));
}

function normalizeTrashItem(item) {
  if (item.type === "uuid") {
    return {
      ...item,
      invite: item.invite || {},
      records: Array.isArray(item.records) ? item.records.map(normalizeIpGroup) : [],
      deletedAt: item.deletedAt || "",
    };
  }

  if (item.type === "ip_group") {
    return {
      ...item,
      uuid: String(item.uuid || ""),
      group: item.group ? normalizeIpGroup(item.group) : null,
      deletedAt: item.deletedAt || "",
    };
  }

  return item;
}

async function createInvite(env, uuid, data) {
  if (!isUuid(uuid)) {
    throw new Error("Invalid UUID");
  }

  const invites = await getInvites(env);
  const existing = invites.find((invite) => invite.uuid === uuid);
  const username = validateInviteUsername(data.username, uuid);
  assertUniqueInviteUsername(invites, username, existing?.uuid || null);
  const now = new Date().toISOString();
  const syncResult = await provisionSub2ApiUser(env, {
    uuid,
    username: desiredSub2ApiUsername(username, uuid),
    name: username,
    email: data.email || "",
    remark: data.remark || "",
    sub2apiUserId: existing?.sub2apiSync?.userId || 0,
    loginPassword: existing?.sub2apiSync?.loginPassword || "",
    tokens: desiredSub2ApiTokens(env, data.apiConfigs),
  });
  const apiConfigs = mergeSub2ApiConfig(env, data.apiConfigs, syncResult);
  const sub2apiSync = sub2apiSyncMetadata(syncResult);

  if (existing) {
    existing.username = username;
    existing.name = username;
    existing.email = data.email || "";
    existing.remark = data.remark || "";
    existing.apiConfigs = apiConfigs;
    existing.sub2apiSync = sub2apiSync;
    existing.updatedAt = now;
  } else {
    invites.push({
      uuid,
      username,
      name: username,
      email: data.email || "",
      remark: data.remark || "",
      apiConfigs,
      sub2apiSync,
      createdAt: now,
      updatedAt: now,
    });
  }

  await saveInvites(env, invites);
}

async function updateInvite(env, originalUuid, data) {
  if (!isUuid(originalUuid) || !isUuid(data.uuid)) {
    throw new Error("Invalid UUID");
  }

  const invites = await getInvites(env);
  const invite = invites.find((item) => item.uuid === originalUuid);
  if (!invite) {
    return;
  }

  const username = validateInviteUsername(data.username, data.uuid);
  const uuidChanged = originalUuid !== data.uuid;
  if (uuidChanged && invites.some((item) => item.uuid === data.uuid)) {
    throw new Error("UUID already exists");
  }
  assertUniqueInviteUsername(invites, username, originalUuid);

  let syncResult = null;
  if (uuidChanged) {
    await deprovisionSub2ApiUser(env, invite);
  }
  syncResult = await provisionSub2ApiUser(env, {
    uuid: data.uuid,
    username: desiredSub2ApiUsername(username, data.uuid),
    name: username,
    email: data.email || "",
    remark: data.remark || "",
    sub2apiUserId: uuidChanged ? 0 : invite.sub2apiSync?.userId || 0,
    loginPassword: uuidChanged ? "" : invite.sub2apiSync?.loginPassword || "",
    tokens: desiredSub2ApiTokens(env, data.apiConfigs),
  });

  const now = new Date().toISOString();
  invite.uuid = data.uuid;
  invite.username = username;
  invite.name = username;
  invite.email = data.email || "";
  invite.remark = data.remark || "";
  invite.apiConfigs = mergeSub2ApiConfig(env, data.apiConfigs, syncResult);
  invite.sub2apiSync = sub2apiSyncMetadata(syncResult);
  invite.updatedAt = now;

  await saveInvites(env, invites);

  if (uuidChanged) {
    const records = await env.INVITE_STORE.get(recordsKey(originalUuid));
    if (records) {
      await env.INVITE_STORE.put(recordsKey(data.uuid), records);
    }
    await env.INVITE_STORE.delete(recordsKey(originalUuid));
  }
}

async function deleteInvite(env, uuid) {
  const invites = await getInvites(env);
  const invite = invites.find((item) => item.uuid === uuid);
  if (!invite) {
    return;
  }

  const groups = await getIpRecords(env, uuid);
  const protectedKeys = await getReferencedIpKeys(env, { excludeUuid: uuid });
  const now = new Date().toISOString();

  for (const group of groups) {
    await deleteCloudflareListItems(env, group.ips || [], protectedKeys);
  }

  await deprovisionSub2ApiUser(env, invite);

  const trash = await getTrash(env);
  trash.unshift({
    id: randomHex(12),
    type: "uuid",
    deletedAt: now,
    invite: {
      ...invite,
      deletedAt: now,
    },
    records: groups,
  });

  await saveTrash(env, trash);
  await saveInvites(env, invites.filter((invite) => invite.uuid !== uuid));
  await env.INVITE_STORE.delete(recordsKey(uuid));
}

async function restoreInviteFromTrash(env, trashId) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "uuid");
  if (!item || !item.invite || !isUuid(item.invite.uuid)) {
    return;
  }

  const invites = await getInvites(env);
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
    tokens: desiredSub2ApiTokens(env, invite.apiConfigs),
  });

  invite.username = username;
  invite.name = username;
  invite.apiConfigs = mergeSub2ApiConfig(env, invite.apiConfigs, syncResult);
  invite.sub2apiSync = sub2apiSyncMetadata(syncResult);
  invite.updatedAt = new Date().toISOString();
  delete invite.deletedAt;

  const restoredGroups = [];
  for (const group of item.records || []) {
    restoredGroups.push(await restoreCloudflareListItems(env, group, invite.uuid));
  }

  invites.push(invite);
  await saveInvites(env, invites);
  if (restoredGroups.length) {
    await env.INVITE_STORE.put(recordsKey(invite.uuid), JSON.stringify(restoredGroups));
  }
  await saveTrash(env, trash.filter((entry) => entry.id !== trashId));
}

async function purgeInviteTrash(env, trashId) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "uuid");
  if (!item) {
    return;
  }

  const protectedKeys = await getReferencedIpKeys(env);
  for (const group of item.records || []) {
    await deleteCloudflareListItems(env, group.ips || [], protectedKeys);
  }
  await purgeSub2ApiUser(env, item.invite || {});
  await saveTrash(env, trash.filter((entry) => entry.id !== trashId));
}

export async function cleanupExpiredIpGroups(env, now = new Date()) {
  if (!hasCloudflareListConfig(env) || !env.INVITE_STORE) {
    console.error(JSON.stringify({ level: "error", message: "ip_cleanup_missing_configuration" }));
    return { checked: 0, deleted: 0 };
  }

  const invites = await getInvites(env);
  const activeUuids = new Set(invites.map((invite) => invite.uuid));
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
  orphaned = await deleteOrphanedCloudflareListItems(env, protectedKeys, activeUuids);

  for (const update of updates) {
    if (update.groups.length === 0) {
      await env.INVITE_STORE.delete(recordsKey(update.uuid));
    } else {
      await env.INVITE_STORE.put(recordsKey(update.uuid), JSON.stringify(update.groups));
    }
  }

  console.log(JSON.stringify({ level: "info", message: "ip_cleanup_complete", checked, deleted, orphaned }));
  return { checked, deleted, orphaned };
}

async function deleteIpGroup(env, uuid, groupId) {
  const groups = await getIpRecords(env, uuid);
  const group = groups.find((item) => item.id === groupId);
  if (!group) {
    return;
  }

  const protectedKeys = await getReferencedIpKeys(env, { excludedGroups: new Map([[uuid, new Set([groupId])]]) });
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
  await env.INVITE_STORE.put(recordsKey(uuid), JSON.stringify(groups.filter((item) => item.id !== groupId)));
}

async function restoreIpGroupFromTrash(env, trashId) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "ip_group");
  if (!item || !isUuid(item.uuid) || !item.group) {
    return;
  }

  const invites = await getInvites(env);
  if (!invites.some((invite) => invite.uuid === item.uuid)) {
    throw new Error("UUID must be restored before this IP group");
  }

  const groups = await getIpRecords(env, item.uuid);
  const restoredGroup = await restoreCloudflareListItems(env, item.group, item.uuid);
  const nextGroups = upsertIpGroup(groups, restoredGroup).slice(0, 50);

  await env.INVITE_STORE.put(recordsKey(item.uuid), JSON.stringify(nextGroups));
  await saveTrash(env, trash.filter((entry) => entry.id !== trashId));
}

async function purgeIpGroupTrash(env, trashId) {
  const trash = await getTrash(env);
  const item = trash.find((entry) => entry.id === trashId && entry.type === "ip_group");
  if (!item) {
    return;
  }

  const protectedKeys = await getReferencedIpKeys(env);
  await deleteCloudflareListItems(env, item.group?.ips || [], protectedKeys);
  await saveTrash(env, trash.filter((entry) => entry.id !== trashId));
}

async function updateIpGroupExpiration(env, uuid, groupId, expiresAt) {
  if (!expiresAt) {
    throw new Error("Invalid expiration timestamp");
  }

  const groups = await getIpRecords(env, uuid);
  const nextGroups = groups.map((group) => group.id === groupId ? { ...group, expiresAt } : group);
  await env.INVITE_STORE.put(recordsKey(uuid), JSON.stringify(nextGroups));
}

async function getIpRecords(env, uuid) {
  const records = parseJson(await env.INVITE_STORE.get(recordsKey(uuid)), []);
  return Array.isArray(records) ? records.map(normalizeIpGroup) : [];
}

function normalizeIpGroup(record) {
  if (Array.isArray(record.ips)) {
    return {
      ...record,
      id: record.id || randomHex(12),
      addedAt: record.addedAt || "",
      updatedAt: record.updatedAt || record.addedAt || "",
      expiresAt: record.expiresAt || addDaysIso(record.addedAt || new Date().toISOString(), DEFAULT_IP_TTL_DAYS),
      ips: record.ips.map((item) => ({
        ...item,
        listValue: item.listValue || item.cidr || item.ip || "",
      })),
    };
  }

  const cidr = record.cidr || (record.ip && record.ip.includes(":") ? `${record.ip}/128` : ipv4Cidr24(record.ip || ""));
  return {
    id: record.id || randomHex(12),
    addedAt: record.addedAt || "",
    updatedAt: record.updatedAt || record.addedAt || "",
    expiresAt: record.expiresAt || addDaysIso(record.addedAt || new Date().toISOString(), DEFAULT_IP_TTL_DAYS),
    country: stringOrEmpty(record.country),
    region: stringOrEmpty(record.region),
    city: stringOrEmpty(record.city),
    timezone: stringOrEmpty(record.timezone),
    colo: stringOrEmpty(record.colo),
    asn: record.asn || "",
    asOrganization: stringOrEmpty(record.asOrganization),
    ips: record.ip ? [{
      ip: record.ip,
      version: record.ip.includes(":") ? "IPv6" : "IPv4",
      cidr,
      listValue: cidr,
      listItemId: record.listItemId || "",
    }] : [],
  };
}

async function deleteCloudflareListItems(env, ips, protectedKeys = new Set()) {
  const ids = new Set();

  for (const item of ips) {
    if (isIpReferenced(protectedKeys, item)) {
      continue;
    }

    if (item.listItemId) {
      ids.add(item.listItemId);
      continue;
    }

    const listItem = await findCloudflareListItem(env, item.listValue || item.cidr || item.ip);
    if (listItem && listItem.id) {
      ids.add(listItem.id);
    }
  }

  if (ids.size === 0) {
    return;
  }

  const idList = [...ids];
  await deleteCloudflareListItemIds(env, idList);
}

async function restoreCloudflareListItems(env, group, uuid) {
  const existingItems = await findCloudflareListItems(env);
  const existingByIp = new Map(existingItems.map((item) => [item.ip, item]));
  const ips = (group.ips || []).map((item) => {
    const listValue = item.listValue || item.cidr || item.ip;
    const existing = existingByIp.get(listValue) || existingByIp.get(item.ip);
    return {
      ...item,
      listValue,
      listItemId: existing ? existing.id || "" : "",
    };
  });
  const itemsToAdd = ips.filter((item) => item.listValue && !item.listItemId);

  if (itemsToAdd.length === 0) {
    return { ...group, ips, updatedAt: new Date().toISOString() };
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
          comment: `sub2api uuid ${uuid} raw ${item.ip} ${new Date().toISOString()}`,
        })),
      ),
    },
  );
  const payload = await response.json();

  if (!response.ok || payload.success === false) {
    console.error(JSON.stringify({ level: "error", message: "list_restore_failed", uuid, groupId: group.id, status: response.status, errors: payload.errors || [] }));
    throw new Error("Cloudflare list item restore failed");
  }

  const createdByIp = new Map((Array.isArray(payload.result) ? payload.result : []).map((item) => [item.ip, item]));
  return {
    ...group,
    updatedAt: new Date().toISOString(),
    ips: ips.map((item) => {
      const created = createdByIp.get(item.listValue);
      return {
        ...item,
        listItemId: created ? created.id || "" : item.listItemId,
      };
    }),
  };
}

async function deleteCloudflareListItemIds(env, ids) {
  if (ids.length === 0) {
    return;
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/rules/lists/${env.IP_LIST_ID}/items?per_page=100`,
    {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ items: ids.map((id) => ({ id })) }),
    },
  );
  const payload = await response.json();

  if (!response.ok || payload.success === false) {
    console.error(JSON.stringify({ level: "error", message: "list_delete_failed", ids, status: response.status, errors: payload.errors || [] }));
    throw new Error("Cloudflare list item delete failed");
  }
}

async function deleteOrphanedCloudflareListItems(env, protectedKeys, activeUuids) {
  const listItems = await findCloudflareListItems(env);
  const ids = [];

  for (const listItem of listItems) {
    const uuid = managedListItemUuid(listItem.comment || "");
    if (!uuid || activeUuids.has(uuid)) {
      continue;
    }

    if (isIpReferenced(protectedKeys, { listItemId: listItem.id, listValue: listItem.ip, ip: listItem.ip })) {
      continue;
    }

    ids.push(listItem.id);
  }

  await deleteCloudflareListItemIds(env, ids);
  return ids.length;
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
    throw new Error("Cloudflare list lookup failed");
  }

  const payload = await response.json();
  return Array.isArray(payload.result) ? payload.result : [];
}

async function getReferencedIpKeys(env, options = {}) {
  const keys = new Set();
  const invites = await getInvites(env);
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

function managedListItemUuid(comment) {
  const match = String(comment).match(/^sub2api uuid ([0-9a-fA-F-]{36}) raw /);
  return match && isUuid(match[1]) ? match[1] : "";
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

async function isValidConfiguredKey(input, configuredKeys) {
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

async function verifyPassword(password, expectedHash) {
  return await timingSafeEqual(await sha256Hex(password), expectedHash.toLowerCase());
}

async function verifyTotp(secret, token) {
  if (!/^\d{6}$/.test(token)) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000 / 30);
  for (const offset of [-1, 0, 1]) {
    const expected = await totp(secret, now + offset);
    if (await timingSafeEqual(token, expected)) {
      return true;
    }
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
  const clean = value.toUpperCase().replace(/[^A-Z2-7]/g, "");
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

function renderAdmin(invites, trash, csrf, request, env) {
  const defaultBaseUrl = defaultSub2ApiBaseUrl(env, request);
  return page("UUID Admin", `
    <section class="admin">
      <header class="topbar">
        <div class="topbar-title">
          ${sub2apiIcon("compact")}
          <div>
            <p class="eyebrow">Sub2API Admin</p>
            <h1>UUID Admin</h1>
            <p>${invites.length} active UUID${invites.length === 1 ? "" : "s"} · ${trash.length} trashed item${trash.length === 1 ? "" : "s"}</p>
          </div>
        </div>
        <form method="post" action="${ADMIN_PATH}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="action" value="logout" />
          <button class="secondary" type="submit">Sign out</button>
        </form>
      </header>

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
          </div>
          ${renderApiConfigEditor("api-configs", [], defaultBaseUrl)}
          <div class="form-footer">
            <span class="hint">Each link is stored separately, then saved in the existing format.</span>
            <button type="submit">Save UUID</button>
          </div>
        </form>
      </section>

      <section class="invite-list">
        <div class="section-head">
          <div>
            <h2>UUIDs</h2>
            <p class="muted">Edit users, rotate API keys, and manage IP groups.</p>
          </div>
        </div>
        ${invites.length ? invites.map((invite) => renderInviteRow(invite, csrf, request, env)).join("") : `
          <div class="panel empty">No UUIDs yet</div>
        `}
      </section>

      <section class="trash-list">
        <div class="section-head">
          <div>
            <h2>Recycle Bin</h2>
            <p class="muted">Restore deleted UUIDs or IP groups, or permanently remove their backend records.</p>
          </div>
        </div>
        ${trash.length ? trash.map((item) => renderTrashRow(item, csrf)).join("") : `
          <div class="panel empty">Recycle bin is empty</div>
        `}
      </section>
    </section>
    <script>
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
      document.getElementById("generate-user").addEventListener("click", () => {
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
      copyButton.addEventListener("click", async () => {
        if (!uuidInput.value) {
          uuidInput.value = generateValue("uuid");
        }
        await navigator.clipboard.writeText(uuidInput.value);
        copyButton.textContent = "Copied";
        window.setTimeout(() => {
          copyButton.textContent = "Copy";
        }, 1400);
      });
      document.querySelectorAll(".copy-row").forEach((button) => {
        button.addEventListener("click", async () => {
          await navigator.clipboard.writeText(button.dataset.copy);
          button.textContent = "Copied";
          window.setTimeout(() => {
            button.textContent = "Copy";
          }, 1400);
        });
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
      document.addEventListener("click", async (event) => {
        const copyKeyButton = event.target.closest(".copy-api-key");
        if (copyKeyButton) {
          const input = copyKeyButton.closest(".api-key-field")?.querySelector('[data-field="api-key"]');
          if (!input?.value) return;
          await navigator.clipboard.writeText(input.value);
          copyKeyButton.textContent = "Copied";
          window.setTimeout(() => {
            copyKeyButton.textContent = "Copy";
          }, 1400);
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
          rows[0].querySelectorAll("input").forEach((input) => {
            input.value = "";
          });
          return;
        }
        button.closest(".api-config-row").remove();
      });
      document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", (event) => {
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
          '<input type="text" data-field="name" maxlength="80" placeholder="Name" />' +
          '<input type="url" data-field="base-url" placeholder="https://example.com/v1" />' +
          '<div class="api-key-field">' +
            '<input type="password" data-field="api-key" placeholder="sk-..." autocomplete="off" spellcheck="false" />' +
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
            if (!baseUrl && !apiKey) return "";
            return [name || "Sub2API", baseUrl, apiKey].join(" | ");
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

function renderTrashRow(item, csrf) {
  if (item.type === "uuid") {
    return renderUuidTrashRow(item, csrf);
  }
  if (item.type === "ip_group") {
    return renderIpGroupTrashRow(item, csrf);
  }
  return "";
}

function renderUuidTrashRow(item, csrf) {
  const invite = item.invite || {};
  return `
    <article class="panel trash-card">
      <div class="trash-meta">
        <div>
          <strong>UUID ${escapeHtml(invite.uuid || "")}</strong>
          ${inviteUsername(invite) ? `<small>${escapeHtml(inviteUsername(invite))}</small>` : ""}
          ${invite.email ? `<small>${escapeHtml(invite.email)}</small>` : ""}
          <small>Deleted ${escapeHtml(formatDate(item.deletedAt) || "Unknown")} · ${(item.records || []).length} IP group${(item.records || []).length === 1 ? "" : "s"}</small>
        </div>
        <div class="inline-actions">
          <form method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="restore_uuid" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <button class="secondary compact" type="submit">Restore</button>
          </form>
          <form method="post" action="${ADMIN_PATH}" onsubmit="return confirm('Permanently delete this UUID and its Sub2API records?')">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="purge_uuid" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <button class="danger compact" type="submit">Delete forever</button>
          </form>
        </div>
      </div>
    </article>
  `;
}

function renderIpGroupTrashRow(item, csrf) {
  const group = item.group || {};
  const place = [group.country, group.region, group.city].filter(Boolean).join(" / ") || "Unknown location";
  return `
    <article class="panel trash-card">
      <div class="trash-meta">
        <div>
          <strong>IP group for ${escapeHtml(item.uuid || "")}</strong>
          <small>${escapeHtml(place)}</small>
          <small>Deleted ${escapeHtml(formatDate(item.deletedAt) || "Unknown")} · ${(group.ips || []).length} IP${(group.ips || []).length === 1 ? "" : "s"}</small>
        </div>
        <div class="inline-actions">
          <form method="post" action="${ADMIN_PATH}">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="restore_ip_group" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <button class="secondary compact" type="submit">Restore</button>
          </form>
          <form method="post" action="${ADMIN_PATH}" onsubmit="return confirm('Permanently delete this IP group?')">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="purge_ip_group" />
            <input type="hidden" name="trash_id" value="${escapeHtml(item.id)}" />
            <button class="danger compact" type="submit">Delete forever</button>
          </form>
        </div>
      </div>
      <div class="ip-list">
        ${(group.ips || []).map(renderIpItem).join("")}
      </div>
    </article>
  `;
}

function renderInviteRow(invite, csrf, request, env) {
  const groups = invite.records || [];
  const apiConfigs = normalizeApiConfigs(invite.apiConfigs || []);
  const editorId = `api-${invite.uuid}`;
  const totalIps = groups.reduce((count, group) => count + (group.ips || []).length, 0);
  const latestGroup = groups[0] || null;
  const latestPlace = latestGroup ? formatGroupPlace(latestGroup) : "";
  return `
    <article class="panel invite-card">
      <div class="invite-meta">
        <div class="invite-heading">
          <strong>${escapeHtml(inviteUsername(invite) || invite.uuid)}</strong>
          <div class="stat-row">
            <span class="stat-pill">${groups.length} group${groups.length === 1 ? "" : "s"}</span>
            <span class="stat-pill">${totalIps} IP${totalIps === 1 ? "" : "s"}</span>
            ${latestPlace ? `<span class="stat-pill">${escapeHtml(latestPlace)}</span>` : ""}
          </div>
          ${invite.email ? `<small>${escapeHtml(invite.email)}</small>` : ""}
          ${invite.remark ? `<small>${escapeHtml(invite.remark)}</small>` : ""}
        </div>
        <form method="post" action="${ADMIN_PATH}" onsubmit="return confirm('Delete this UUID and all of its IP groups?')">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="action" value="delete" />
          <input type="hidden" name="uuid" value="${escapeHtml(invite.uuid)}" />
          <button class="danger compact" type="submit">Delete UUID</button>
        </form>
      </div>
      <div class="invite-main">
        ${renderInviteEditForm(invite, apiConfigs, editorId, csrf, request, env)}
        <section class="ip-panel">
          <div class="subhead">
            <h3>IP groups</h3>
            <span class="muted">${groups.length} active group${groups.length === 1 ? "" : "s"}</span>
          </div>
          ${groups.length ? groups.map((group, index) => renderIpGroup(group, invite.uuid, csrf, index === 0)).join("") : `<span class="muted">No IP groups yet</span>`}
        </section>
      </div>
    </article>
  `;
}

function renderInviteEditForm(invite, apiConfigs, editorId, csrf, request, env) {
  return `
    <form class="invite-edit" method="post" action="${ADMIN_PATH}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
      <input type="hidden" name="action" value="update_invite" />
      <input type="hidden" name="original_uuid" value="${escapeHtml(invite.uuid)}" />
      <div class="form-grid">
        <div class="field span-2">
          <label for="uuid-${escapeHtml(invite.uuid)}">UUID</label>
          <div class="uuid-cell">
            <input id="uuid-${escapeHtml(invite.uuid)}" name="uuid" type="text" pattern="[0-9a-fA-F-]{36}" value="${escapeHtml(invite.uuid)}" required />
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
      </div>
      ${renderApiConfigEditor(editorId, apiConfigs, defaultSub2ApiBaseUrl(env, request))}
      <div class="form-footer">
        <span class="hint">Existing links are split into fields for easier editing.</span>
        <button class="secondary compact" type="submit">Save user</button>
      </div>
    </form>
  `;
}

function renderApiConfigEditor(editorId, apiConfigs, defaultBaseUrl) {
  const rows = normalizeApiConfigs(apiConfigs);
  const visibleRows = rows.length ? rows : [{ name: "Sub2API", baseUrl: defaultBaseUrl, apiKey: "" }];
  return `
    <section class="api-config-editor" id="${escapeHtml(editorId)}">
      <input type="hidden" name="api_configs" value="${escapeHtml(formatApiConfigs(rows))}" />
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
  return `
    <div class="api-config-row">
      <input type="text" data-field="name" maxlength="80" placeholder="Name" value="${escapeHtml(config.name || "")}" />
      <input type="url" data-field="base-url" placeholder="https://example.com/v1" value="${escapeHtml(config.baseUrl || "")}" />
      <div class="api-key-field">
        <input type="password" data-field="api-key" placeholder="sk-..." value="${escapeHtml(config.apiKey || "")}" autocomplete="off" spellcheck="false" />
        <button class="secondary compact toggle-api-key" type="button" aria-label="Show API key">Show</button>
        <button class="secondary compact copy-api-key" type="button"${config.apiKey ? "" : " disabled"}>Copy</button>
      </div>
      <button class="secondary compact remove-api-link" type="button">Remove</button>
    </div>
  `;
}

function renderIpGroup(group, uuid, csrf, isInitiallyOpen = false) {
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
          <form method="post" action="${ADMIN_PATH}" onsubmit="return confirm('Delete this IP group from the Cloudflare list?')">
            <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
            <input type="hidden" name="action" value="delete_ip_group" />
            <input type="hidden" name="uuid" value="${escapeHtml(uuid)}" />
            <input type="hidden" name="group_id" value="${escapeHtml(group.id)}" />
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
          <input class="expiration-mode" type="hidden" name="expiration_mode" value="date" />
          <label class="expiry-field" for="expires-${escapeHtml(group.id)}">
            <span>Expires</span>
            <input class="expires-at" id="expires-${escapeHtml(group.id)}" name="expires_at" type="datetime-local" value="${escapeHtml(toDateTimeLocalValue(group.expiresAt))}" required />
          </label>
          <label class="expiry-field" for="expires-days-${escapeHtml(group.id)}">
            <span>Days left</span>
            <input class="expires-days" id="expires-days-${escapeHtml(group.id)}" name="expires_in_days" type="number" min="0" step="1" value="${escapeHtml(expiresInDays)}" />
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

  const endpoint = String(env.GEOIP_LOOKUP_URL || `https://api.ip.sb/geoip/${encodeURIComponent(ip)}`);
  if (!endpoint) {
    return fallback;
  }
  const lookupUrl = endpoint.replace("{ip}", encodeURIComponent(ip));
  if (!lookupUrl.startsWith("https://")) {
    return fallback;
  }

  try {
    const response = await fetch(lookupUrl, {
      headers: { accept: "application/json" },
    });
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
    console.error(JSON.stringify({ level: "warn", message: "geoip_lookup_failed", error: error.message }));
    return fallback;
  }
}

async function readJsonWithLimit(response, maxBytes) {
  const contentLength = Number(response.headers.get("content-length") || "0");
  if (contentLength > maxBytes) {
    throw new Error("response_too_large");
  }

  if (!response.body) {
    return await response.json();
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("response_too_large");
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return JSON.parse(new TextDecoder().decode(bytes));
}

async function provisionSub2ApiUser(env, invite) {
  return await callSub2ApiSync(env, "provision", invite);
}

async function deprovisionSub2ApiUser(env, invite) {
  const sync = invite.sub2apiSync || {};
  return await callSub2ApiSync(env, "deprovision", {
    uuid: invite.uuid,
    sub2apiUserId: sync.userId || 0,
    sub2apiTokenId: sync.tokenId || 0,
  });
}

async function purgeSub2ApiUser(env, invite) {
  if (!invite.uuid || !sub2apiSyncUrl(env) || !sub2apiSyncSecret(env)) {
    return null;
  }

  const sync = invite.sub2apiSync || {};
  return await callSub2ApiSync(env, "purge", {
    uuid: invite.uuid,
    sub2apiUserId: sync.userId || 0,
    sub2apiTokenId: sync.tokenId || 0,
  });
}

async function callSub2ApiSync(env, action, payload) {
  const syncUrl = sub2apiSyncUrl(env);
  const syncSecret = sub2apiSyncSecret(env);
  if (!syncUrl || !syncSecret) {
    throw new Error("Missing Sub2API sync configuration");
  }
  validateSub2ApiSyncConfig(env, syncUrl, syncSecret);

  const body = JSON.stringify({
    action,
    ...payload,
  });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomHex(16);
  const signature = await hmacSha256Hex(syncSecret, `${timestamp}.${nonce}.${body}`);
  const response = await fetch(syncUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-sub2api-sync-timestamp": timestamp,
      "x-sub2api-sync-nonce": nonce,
      "x-sub2api-sync-signature": signature,
    },
    body,
  });

  const result = await readJsonWithLimit(response, 16_384).catch(() => ({}));
  if (!response.ok || result.ok === false) {
    throw new Error(result.error || `Sub2API sync failed with HTTP ${response.status}`);
  }
  return result;
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
  const baseUrl = normalizeBaseUrl(syncResult?.baseUrl || configuredSub2ApiBaseUrl(env));
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
    }));
}

function displayApiName(name) {
  const value = String(name || "").trim();
  return normalizeApiName(value) === "sub2api" ? "Sub2API" : value || "Sub2API";
}

function normalizeApiName(name) {
  return String(name || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function sub2apiSyncMetadata(syncResult) {
  return {
    userId: Number(syncResult?.userId || 0),
    tokenId: Number(syncResult?.tokenId || 0),
    username: String(syncResult?.username || ""),
    email: String(syncResult?.email || ""),
    loginPassword: String(syncResult?.loginPassword || ""),
    loginUrl: normalizeBaseUrl(syncResult?.loginUrl || "https://api.example.com"),
    passwordHash: String(syncResult?.passwordHash || ""),
    syncedAt: String(syncResult?.syncedAt || new Date().toISOString()),
  };
}

function configuredSub2ApiBaseUrl(env) {
  return normalizeBaseUrl(env.SUB2API_DEFAULT_BASE_URL || env.SUB2API_BASE_URL || "https://api.example.com/v1");
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

  const allowedHosts = String(env.ALLOWED_HOSTNAMES || "")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  if (allowedHosts.length > 0 && !allowedHosts.includes(url.hostname.toLowerCase())) {
    throw new Error("SUB2API_SYNC_URL hostname must be in ALLOWED_HOSTNAMES");
  }
}

function parseApiConfigs(value) {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split("|").map((part) => part.trim());
      if (parts.length >= 3) {
        return { name: parts[0], baseUrl: parts[1], apiKey: parts.slice(2).join("|").trim() };
      }
      if (parts.length === 2) {
        return { name: parts[0], baseUrl: parts[1], apiKey: "" };
      }
      return { name: "Sub2API", baseUrl: parts[0], apiKey: "" };
    });
}

function normalizeApiConfigs(configs) {
  if (!Array.isArray(configs)) {
    return [];
  }

  return configs
    .map((config) => ({
      id: config.id || randomHex(8),
      name: displayApiName(config.name).slice(0, 80),
      baseUrl: normalizeBaseUrl(config.baseUrl),
      apiKey: String(config.apiKey || "").trim(),
    }))
    .filter(isUsableApiConfig)
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
    return url.href.replace(/\/$/, "");
  } catch {
    return "";
  }
}

function formatApiConfigs(configs) {
  return normalizeApiConfigs(configs)
    .map((config) => `${config.name} | ${config.baseUrl} | ${config.apiKey}`)
    .join("\n");
}

function defaultSub2ApiBaseUrl(env, request) {
  const configured = normalizeBaseUrl(env.SUB2API_DEFAULT_BASE_URL || env.SUB2API_BASE_URL || "");
  if (configured) {
    return configured;
  }

  try {
    return `${new URL(request.url).origin}/v1`;
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

function sub2apiIcon(size = "") {
  return `
    <span class="sub2api-icon ${escapeHtml(size)}" aria-hidden="true">
      <img src="${SUB2API_FAVICON}" alt="" />
    </span>
  `;
}

function page(title, body, layout = "narrow") {
  const mainClass = layout === "wide" ? "wide" : "";
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
      background:
        radial-gradient(ellipse at 50% 0%, rgba(255, 255, 255, 0.9), transparent 50%),
        linear-gradient(180deg, #fbfbfd 0%, #f5f5f7 100%);
    }
    main { width: min(100%, 420px); }
    main.wide { width: min(100%, 1320px); }
    form, .message, .admin, .create, .hero { display: grid; gap: 16px; }
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
    .create-panel { display: grid; gap: 20px; }
    .section-head, .subhead, .invite-meta, .form-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
    }
    .section-head h2, .subhead h3 { margin: 0; color: #1d1d1f; line-height: 1.2; }
    .section-head h2 { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; }
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
    .invite-heading { display: grid; gap: 8px; }
    .trash-card { display: grid; gap: 12px; }
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
      border: 0.5px solid rgba(0, 0, 0, 0.06);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.72);
      box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 8px 24px rgba(0,0,0,0.06);
      backdrop-filter: saturate(180%) blur(20px);
      -webkit-backdrop-filter: saturate(180%) blur(20px);
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
    .topbar p, .muted, small, .lede, .eyebrow { color: #86868b; }
    .eyebrow {
      margin: 0;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.02em;
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
      letter-spacing: -0.01em;
    }
    input, textarea {
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
      border-radius: 12px;
      background: rgba(0, 0, 0, 0.02);
    }
    .api-config-labels, .api-config-row {
      display: grid;
      grid-template-columns: minmax(110px, 0.7fr) minmax(210px, 1.35fr) minmax(180px, 1.15fr) auto;
      gap: 8px;
      align-items: center;
    }
    .api-config-labels { color: #86868b; font-size: 12px; font-weight: 600; }
    .api-config-rows { display: grid; gap: 8px; }
    .api-config-row input { min-width: 0; }
    .api-key-field {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto auto;
      gap: 8px;
      min-width: 0;
    }
    .api-key-field input { min-width: 0; }
    input:focus, textarea:focus {
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
      color: #86868b;
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
      font-size: 36px;
      font-weight: 700;
      line-height: 1.1;
      letter-spacing: -0.025em;
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
    th { font-size: 12px; color: #86868b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.02em; }
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
    .hint { color: #86868b; font-size: 12px; line-height: 1.4; }
    .invite-meta strong { display: block; overflow-wrap: anywhere; }
    td > strong, td > small { display: block; overflow-wrap: anywhere; }
    .stat-row {
      display: flex;
      flex-wrap: wrap;
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
      font-size: 12px;
      font-weight: 600;
      line-height: 1;
    }
    .ip-group {
      min-width: 220px;
      border: 0.5px solid rgba(0, 0, 0, 0.08);
      border-radius: 14px;
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
      font-size: 12px;
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
    .time-grid span { display: grid; gap: 4px; color: #86868b; font-size: 13px; }
    .expiry-form {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) minmax(88px, 0.35fr) auto;
      align-items: end;
      gap: 8px;
      min-width: 0;
    }
    .expiry-field { display: grid; gap: 4px; min-width: 0; }
    .expiry-field span { color: #86868b; font-size: 13px; }
    .expiry-form input { height: 32px; border-radius: 8px; font-size: 13px; }
    .expiry-form input[type="datetime-local"] { min-width: 220px; }
    .ip-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      max-width: 100%;
      padding: 6px 10px;
      border-radius: 8px;
      background: rgba(0, 0, 0, 0.04);
    }
    .ip-pill code { font-size: 12px; }
    .row-actions { min-width: 128px; }
    .empty { color: #86868b; text-align: center; padding: 24px 0; }
    @media (max-width: 680px) {
      body { place-items: start; padding: 20px 16px; }
      .topbar, .section-head, .subhead, .invite-meta, .trash-meta, .form-footer, .ip-group-summary { display: grid; }
      .inline, .form-grid, .invite-main, .api-config-labels, .api-config-row {
        grid-template-columns: minmax(0, 1fr);
      }
      .api-config-labels { display: none; }
      .api-key-field { grid-template-columns: minmax(0, 1fr); }
      .uuid-cell { grid-template-columns: minmax(0, 1fr); }
      .time-grid, .expiry-form { grid-template-columns: minmax(0, 1fr); }
      .ip-group-summary { padding: 14px; }
      .ip-group-body { padding: 0 14px 14px; }
      .ip-group-toolbar { justify-content: stretch; }
      .ip-group-toolbar form, .ip-group-toolbar button { width: 100%; }
      .ip-preview-list { justify-content: flex-start; }
      .ip-preview { max-width: 100%; }
      th, td { padding: 10px 8px; }
      h1 { font-size: 28px; }
      .panel, .message { padding: 16px; border-radius: 14px; }
    }
    @media (prefers-color-scheme: dark) {
      :root { background: #000; color: #f5f5f7; }
      body {
        background:
          radial-gradient(ellipse at 50% 0%, rgba(44, 44, 46, 0.6), transparent 50%),
          linear-gradient(180deg, #1c1c1e 0%, #000 100%);
      }
      .panel, .message {
        border-color: rgba(255, 255, 255, 0.08);
        background: rgba(28, 28, 30, 0.72);
        box-shadow: 0 1px 3px rgba(0,0,0,0.2), 0 8px 24px rgba(0,0,0,0.3);
      }
      label, input, textarea { color: #f5f5f7; }
      input, textarea {
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
      button.secondary:active { background: rgba(255, 255, 255, 0.2); }
      button.danger { background: #ff453a; }
      button.danger:hover { background: #ff6961; }
      .section-head h2, .subhead h3 { color: #f5f5f7; }
      .invite-meta { border-color: rgba(255, 255, 255, 0.08); }
      .api-config-editor {
        border-color: rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.04);
      }
      .api-config-labels { color: #98989d; }
      .ip-pill, .stat-pill, .ip-preview, .ip-preview-more { background: rgba(255, 255, 255, 0.08); color: #d2d2d7; }
      th, td { border-color: rgba(255, 255, 255, 0.08); }
      th, .topbar p, .muted, small { color: #98989d; }
      .ip-group { border-color: rgba(255, 255, 255, 0.08); background: rgba(255, 255, 255, 0.04); }
      .ip-group-body { border-color: rgba(255, 255, 255, 0.08); }
      .empty { color: #636366; }
    }
  </style>
</head>
<body>
  <main class="${mainClass}">${body}</main>
</body>
</html>`;
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

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "content-security-policy": "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    },
  });
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
    message === "Username is required" ||
    message === "Username already exists"
  );
}

function getAdminSetupError(env) {
  const missing = [
    "INVITE_STORE",
    "ADMIN_USERNAME",
    "ADMIN_PASSWORD_HASH",
    "ADMIN_TOTP_SECRET",
    "ACCOUNT_ID",
    "IP_LIST_ID",
    "CLOUDFLARE_API_TOKEN",
  ].filter(
    (name) => !env[name],
  );
  if (!sub2apiSyncUrl(env)) {
    missing.push("SUB2API_SYNC_URL");
  }
  if (!sub2apiSyncSecret(env)) {
    missing.push("SUB2API_SYNC_SECRET");
  }
  if (missing.length) {
    return `Missing admin configuration: ${missing.join(", ")}`;
  }
  if (!/^[a-f0-9]{64}$/i.test(env.ADMIN_PASSWORD_HASH)) {
    return "ADMIN_PASSWORD_HASH must be the SHA-256 hex digest of the admin password.";
  }
  if (String(env.SUB2API_SYNC_SECRET || "").length < 32) {
    return "SUB2API_SYNC_SECRET must be at least 32 characters.";
  }
  try {
    validateSub2ApiSyncConfig(env, sub2apiSyncUrl(env), sub2apiSyncSecret(env));
  } catch (error) {
    return error.message;
  }
  return "";
}

function recordsKey(uuid) {
  return `records:${uuid}`;
}

function loginAttemptKey(request, username) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return `login-attempt:${ip}:${username || "blank"}`;
}

function sessionKey(hash) {
  return `session:${hash}`;
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

async function hmacSha256Hex(secret, value) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function stringOrEmpty(value) {
  return typeof value === "string" ? value : "";
}

function cleanText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

function ipv4Cidr24(ip) {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4) {
    return ip;
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
