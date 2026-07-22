const METADATA_FIELDS = [
  "id",
  "requestId",
  "model",
  "requestedModel",
  "inputTokens",
  "outputTokens",
  "cacheCreationTokens",
  "cacheReadTokens",
  "totalCost",
  "actualCost",
  "durationMs",
  "stream",
  "requestType",
  "inboundEndpoint",
  "createdAt",
];
const MAX_SAFE_ID = Number.MAX_SAFE_INTEGER;

const DEFAULTS = {
  id: 0,
  requestId: "",
  model: "",
  requestedModel: "",
  inputTokens: 0,
  outputTokens: 0,
  cacheCreationTokens: 0,
  cacheReadTokens: 0,
  totalCost: "0",
  actualCost: "0",
  durationMs: 0,
  stream: false,
  requestType: "",
  inboundEndpoint: "",
  createdAt: "",
};

export function sanitizeUsageInspectorData(value) {
  const source = value && typeof value === "object" ? value : {};
  const itemSource = Array.isArray(source.items)
    ? source.items
    : source.item && typeof source.item === "object"
      ? [source.item]
      : [];
  const items = itemSource.map(sanitizeUsageItem).filter(Boolean);
  return {
    ok: source.ok !== false,
    action: String(source.action || "usage_logs_list"),
    items,
    query: String(source.query || "").slice(0, 120),
    filters: sanitizeFilters(source.filters),
    page: {
      pageSize: boundedNumber(source.page?.pageSize, 25, 1, 100),
      hasMore: Boolean(source.page?.hasMore),
      nextCursor: boundedNumber(source.page?.nextCursor, 0, 0, MAX_SAFE_ID),
      nextCursorCreatedAt: String(source.page?.nextCursorCreatedAt || "").slice(0, 40),
    },
    modelOptions: Array.isArray(source.modelOptions)
      ? source.modelOptions.map((item) => String(item).slice(0, 100)).filter(Boolean).slice(0, 100)
      : [],
    syncedAt: String(source.syncedAt || "").slice(0, 64),
  };
}

function sanitizeUsageItem(value) {
  if (!value || typeof value !== "object") return null;
  const item = {};
  for (const field of METADATA_FIELDS) {
    item[field] = Object.hasOwn(value, field) ? value[field] : DEFAULTS[field];
  }
  item.id = boundedNumber(item.id, 0, 0, MAX_SAFE_ID);
  item.requestId = String(item.requestId || "").slice(0, 64);
  item.model = String(item.model || "").slice(0, 100);
  item.requestedModel = String(item.requestedModel || "").slice(0, 100);
  item.inputTokens = boundedNumber(item.inputTokens, 0, 0, 2_147_483_647);
  item.outputTokens = boundedNumber(item.outputTokens, 0, 0, 2_147_483_647);
  item.cacheCreationTokens = boundedNumber(item.cacheCreationTokens, 0, 0, 2_147_483_647);
  item.cacheReadTokens = boundedNumber(item.cacheReadTokens, 0, 0, 2_147_483_647);
  item.totalCost = String(item.totalCost || "0").slice(0, 40);
  item.actualCost = String(item.actualCost || "0").slice(0, 40);
  item.durationMs = boundedNumber(item.durationMs, 0, 0, 86_400_000);
  item.stream = Boolean(item.stream);
  item.requestType = String(item.requestType || "").slice(0, 40);
  item.inboundEndpoint = String(item.inboundEndpoint || "").slice(0, 128);
  item.createdAt = String(item.createdAt || "").slice(0, 64);
  return item;
}

function sanitizeFilters(value) {
  const filters = value && typeof value === "object" ? value : {};
  return {
    requestId: String(filters.requestId || "").slice(0, 64),
    model: String(filters.model || "").slice(0, 100),
    timePreset: String(filters.timePreset || "1h").slice(0, 8),
    dateFrom: String(filters.dateFrom || "").slice(0, 40),
    dateTo: String(filters.dateTo || "").slice(0, 40),
  };
}

function boundedNumber(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(minimum, Math.min(maximum, Math.trunc(number))) : fallback;
}

export function renderUsageInspectorBody(rawData, request, adminPath) {
  const data = sanitizeUsageInspectorData(rawData);
  const url = new URL(request.url);
  const detail = url.pathname.endsWith("/detail");
  const query = String(url.searchParams.get("q") || data.query || "").slice(0, 120);
  return `
    <section class="admin inspector-admin">
      <header class="topbar">
        <div class="topbar-title">
          <div>
            <p class="eyebrow">Sub2API Admin</p>
            <h1>Usage Inspector</h1>
            <p>Token, cost and timing metadata only</p>
          </div>
        </div>
        <a class="secondary compact nav-link" href="${escapeHtml(detail ? `${adminPath}/requests` : adminPath)}">Back</a>
      </header>
      ${detail ? renderDetail(data.items[0]) : renderList(data, query, request, adminPath)}
    </section>
  `;
}

function renderList(data, query, request, adminPath) {
  return `
    <section class="panel inspector-panel">
      <form class="inspector-filters" method="get" action="${adminPath}/requests">
        <div class="inspector-filter-grid usage-filter-grid">
          <label class="field"><span>Search metadata</span><input name="q" type="search" value="${escapeHtml(query)}" placeholder="request ID, model or endpoint" /></label>
          <label class="field"><span>Model</span><input name="model" value="${escapeHtml(data.filters.model)}" list="usage-models" /></label>
          <label class="field"><span>Request ID</span><input name="requestId" value="${escapeHtml(data.filters.requestId)}" /></label>
          <label class="field"><span>Range</span><select name="timePreset">${timeOptions(data.filters.timePreset)}</select></label>
        </div>
        <datalist id="usage-models">${data.modelOptions.map((model) => `<option value="${escapeHtml(model)}"></option>`).join("")}</datalist>
        <div class="form-footer"><span class="hint">Reads Sub2API usage metadata; no API request is made to the gateway.</span><button type="submit">Apply filters</button></div>
      </form>
    </section>
    <section class="panel inspector-panel">
      <div class="section-head"><div><h2>Recent usage</h2><p class="muted">${data.items.length} record${data.items.length === 1 ? "" : "s"}</p></div></div>
      <div class="usage-list">${data.items.length ? data.items.map((item) => renderUsageRow(item, adminPath)).join("") : `<div class="empty">No matching usage metadata.</div>`}</div>
      <div class="form-footer"><span class="hint">Updated ${escapeHtml(formatTimestamp(data.syncedAt))}</span>${data.page.hasMore ? `<a href="${escapeHtml(loadMoreHref(request, data.page.nextCursor, data.page.nextCursorCreatedAt))}">Load more</a>` : ""}</div>
    </section>
  `;
}

function renderUsageRow(item, adminPath) {
  const totalTokens = item.inputTokens + item.outputTokens;
  return `
    <article class="usage-row">
      <div class="usage-row-main"><strong>${escapeHtml(item.requestedModel || item.model || "Unknown model")}</strong><code>${escapeHtml(item.requestId || `usage-${item.id}`)}</code><span class="muted">${escapeHtml(item.inboundEndpoint || item.requestType || "API usage")} · ${escapeHtml(formatTimestamp(item.createdAt))}</span></div>
      <div class="stat-row"><span class="stat-pill">${formatInteger(totalTokens)} tokens</span><span class="stat-pill">${formatDuration(item.durationMs)}</span><span class="stat-pill">$${escapeHtml(item.actualCost)}</span>${item.stream ? `<span class="stat-pill status-ok">Stream</span>` : ""}</div>
      <a class="secondary compact nav-link" href="${adminPath}/requests/detail?id=${item.id}">Details</a>
    </article>
  `;
}

function renderDetail(item) {
  if (!item) return `<section class="panel"><div class="empty">Usage metadata not found.</div></section>`;
  const entries = [
    ["Request ID", item.requestId || "-"], ["Requested model", item.requestedModel || "-"],
    ["Billed model", item.model || "-"], ["Endpoint", item.inboundEndpoint || "-"],
    ["Request type", item.requestType || (item.stream ? "stream" : "standard")],
    ["Input tokens", formatInteger(item.inputTokens)], ["Output tokens", formatInteger(item.outputTokens)],
    ["Cache creation", formatInteger(item.cacheCreationTokens)], ["Cache read", formatInteger(item.cacheReadTokens)],
    ["Duration", formatDuration(item.durationMs)], ["Total cost", `$${item.totalCost}`],
    ["Actual cost", `$${item.actualCost}`], ["Created", formatTimestamp(item.createdAt)],
  ];
  return `<section class="panel detail-card"><div class="section-head"><div><h2>Usage metadata</h2><p class="muted">Record ${item.id}</p></div></div><dl class="usage-detail">${entries.map(([name, value]) => `<div><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl></section>`;
}

function timeOptions(selected) {
  return [["1h", "Last hour"], ["1d", "Last day"], ["7d", "Last 7 days"], ["30d", "Last 30 days"]]
    .map(([value, label]) => `<option value="${value}"${selected === value ? " selected" : ""}>${label}</option>`).join("");
}

function loadMoreHref(request, cursor, createdAt) {
  const url = new URL(request.url);
  url.searchParams.set("cursorId", String(cursor || 0));
  if (createdAt) url.searchParams.set("cursorCreatedAt", String(createdAt));
  return url.pathname + url.search;
}

function formatInteger(value) {
  return new Intl.NumberFormat("en-US").format(Number(value || 0));
}

function formatDuration(value) {
  const milliseconds = Number(value || 0);
  if (milliseconds < 1000) return `${Math.max(0, Math.round(milliseconds))} ms`;
  return `${(milliseconds / 1000).toFixed(milliseconds >= 10_000 ? 0 : 2)} s`;
}

function formatTimestamp(value) {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString("zh-CN", { hour12: false }) : "-";
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
