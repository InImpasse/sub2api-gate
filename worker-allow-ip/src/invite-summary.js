export function renderInviteSummary(invite, apiConfigs, adminPath, pagination = {}) {
  const editParams = new URLSearchParams();
  if (Number.isSafeInteger(pagination.page) && pagination.page > 1) {
    editParams.set("page", String(pagination.page));
  }
  if (Number.isSafeInteger(pagination.trashPage) && pagination.trashPage > 1) {
    editParams.set("trashPage", String(pagination.trashPage));
  }
  editParams.set("edit", String(invite.uuid || ""));
  const editHref = `${adminPath}?${editParams.toString()}`;
  const endpoints = (Array.isArray(apiConfigs) ? apiConfigs : []).map((config) => `
    <div class="endpoint-summary">
      <strong>${escapeHtml(config.name || "Sub2API")}</strong>
      <code>${escapeHtml(config.baseUrl || "Not configured")}</code>
    </div>
  `).join("");
  return `<section class="invite-summary">
    <div class="subhead">
      <h3>User settings</h3>
      <a class="secondary compact nav-link" href="${escapeHtml(editHref)}">Edit</a>
    </div>
    <div class="endpoint-summary-list">${endpoints || `<span class="muted">No API endpoints configured</span>`}</div>
    <span class="hint">API keys load only on the authenticated edit view.</span>
  </section>`;
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
