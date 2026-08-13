export function renderInviteSummary(invite, apiConfigs, adminPath, pagination = {}, csrf = "") {
  const editParams = new URLSearchParams();
  if (Number.isSafeInteger(pagination.page) && pagination.page > 1) {
    editParams.set("page", String(pagination.page));
  }
  if (Number.isSafeInteger(pagination.trashPage) && pagination.trashPage > 1) {
    editParams.set("trashPage", String(pagination.trashPage));
  }
  editParams.set("edit", String(invite.uuid || ""));
  const editHref = `${adminPath}?${editParams.toString()}`;
  const context = adminContextValue(pagination, invite.ipPage, false);
  const endpoints = (Array.isArray(apiConfigs) ? apiConfigs : []).map((config) => {
    const configId = String(config.id || "sub2api-sync");
    const groupLabel = String(config.groupName || "").trim();
    return `
    <div class="endpoint-summary">
      <strong>${escapeHtml(config.name || "Sub2API")}</strong>
      <code>${escapeHtml(config.baseUrl || "Not configured")}</code>
      ${groupLabel ? `<span class="muted">Key group: ${escapeHtml(groupLabel)}</span>` : ""}
      ${csrf ? `
        <form class="key-test-form" method="post" action="${escapeHtml(adminPath)}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="action" value="test_api_key" />
          <input type="hidden" name="uuid" value="${escapeHtml(invite.uuid || "")}" />
          <input type="hidden" name="config_id" value="${escapeHtml(configId)}" />
          <input type="hidden" name="admin_context" value="${escapeHtml(context)}" />
          <button class="secondary compact" type="submit">Test API key</button>
        </form>
      ` : ""}
    </div>
  `;
  }).join("");
  return `<section class="invite-summary">
    <div class="subhead">
      <h3>User settings</h3>
      <a class="secondary compact nav-link" href="${escapeHtml(editHref)}">Edit</a>
    </div>
    <div class="endpoint-summary-list">${endpoints || `<span class="muted">No API endpoints configured</span>`}</div>
    <span class="hint">API keys load only on the authenticated edit view.</span>
  </section>`;
}

function adminContextValue(pagination, ipPage, isEditing) {
  const page = Number.isSafeInteger(pagination?.page) && pagination.page > 0 ? pagination.page : 1;
  const trashPage = Number.isSafeInteger(pagination?.trashPage) && pagination.trashPage > 0
    ? pagination.trashPage
    : 1;
  const currentIpPage = Number.isSafeInteger(ipPage) && ipPage > 0 ? ipPage : 1;
  return new URLSearchParams({
    p: String(page),
    t: String(trashPage),
    i: String(currentIpPage),
    v: isEditing ? "e" : "d",
  }).toString();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[character]);
}
