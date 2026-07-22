export function parseApprovedHostnames(value) {
  const entries = String(value || "")
    .split(",")
    .map((hostname) => hostname.trim().toLowerCase());
  if (entries.length === 0 || entries.some((hostname) => !isApprovedHostname(hostname))) {
    return [];
  }
  return [...new Set(entries)];
}

export function hasSeparatedHostnameAllowlists(publicValue, providerValue) {
  const publicHostnames = parseApprovedHostnames(publicValue);
  const providerHostnames = parseApprovedHostnames(providerValue);
  if (publicHostnames.length === 0 || providerHostnames.length === 0) return false;
  const publicSet = new Set(publicHostnames);
  return providerHostnames.every((hostname) => !publicSet.has(hostname));
}

export function isApprovedHostname(value) {
  const hostname = String(value || "").trim().toLowerCase();
  if (
    !hostname
    || hostname.length > 253
    || hostname.endsWith(".")
    || hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname.includes("..")
    || hostname.includes(":")
    || hostname.startsWith("[")
    || hostname.endsWith("]")
  ) {
    return false;
  }

  let parsed;
  try {
    parsed = new URL(`https://${hostname}/`);
  } catch {
    return false;
  }
  if (parsed.hostname.toLowerCase() !== hostname || parsed.port) {
    return false;
  }

  const labels = hostname.split(".");
  return labels.length >= 2
    && !/^\d+$/.test(labels.at(-1))
    && labels.every((label) => (
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    ));
}

export function parseApprovedHttpsUrl(value, allowedHostnameValue, options = {}) {
  let url;
  try {
    url = new URL(String(value || "").trim());
  } catch {
    return null;
  }

  const allowedHostnames = Array.isArray(allowedHostnameValue)
    ? allowedHostnameValue
    : parseApprovedHostnames(allowedHostnameValue);
  if (
    allowedHostnames.length === 0
    || url.protocol !== "https:"
    || url.username
    || url.password
    || url.port
    || !isApprovedHostname(url.hostname)
    || !allowedHostnames.includes(url.hostname.toLowerCase())
    || (!options.allowSearch && url.search)
    || (!options.allowHash && url.hash)
  ) {
    return null;
  }
  return url;
}
