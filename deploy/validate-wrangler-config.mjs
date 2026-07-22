#!/usr/bin/env node
import fs from "node:fs";


const EXPECTED_WORKER_NAME = "sub2api-allow-ip";
const EXPECTED_COMPATIBILITY_DATE = "2026-07-19";
const EXPECTED_CRONS = Object.freeze(["17 3 * * *"]);

const configPath = process.argv[2];
if (!configPath) {
  fail("private Wrangler config path is required");
}
const secretManifestPath = process.argv[3]
  || new URL("../worker-allow-ip/required-secrets.json", import.meta.url);
const expectedPublicHostname = String(process.argv[4] || "").trim().toLowerCase();

let config;
try {
  config = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch {
  fail("private Wrangler config must be strict JSON with no comments or trailing commas");
}

if (!isObject(config)) {
  fail("private Wrangler config root must be an object");
}
if (Object.hasOwn(config, "secrets")) {
  fail("Wrangler config must not use the unsupported secrets.required field");
}
if (config.name !== EXPECTED_WORKER_NAME) {
  fail(`Worker name must remain ${EXPECTED_WORKER_NAME}`);
}
if (config.compatibility_date !== EXPECTED_COMPATIBILITY_DATE) {
  fail(`Worker compatibility_date must remain fixed at ${EXPECTED_COMPATIBILITY_DATE}`);
}
if (config.main !== "src/worker-entry.js") {
  fail("Worker main must export AuthRateLimiter and AuthState through src/worker-entry.js");
}
if (config.workers_dev !== false) {
  fail("private Wrangler config must disable workers_dev");
}
if (!Array.isArray(config.compatibility_flags)
    || !config.compatibility_flags.includes("nodejs_compat")) {
  fail("private Wrangler config must enable nodejs_compat");
}
if (JSON.stringify(config.triggers?.crons) !== JSON.stringify(EXPECTED_CRONS)) {
  fail(`Worker cron schedule must be exactly ${EXPECTED_CRONS[0]}`);
}

const observability = config.observability;
if (!isObject(observability) || observability.enabled !== true) {
  fail("Worker observability must remain enabled for bounded metadata logs");
}
if (typeof observability.head_sampling_rate !== "number"
    || observability.head_sampling_rate <= 0
    || observability.head_sampling_rate > 0.1) {
  fail("Worker observability sampling must be greater than 0 and at most 0.1");
}
if (!isObject(observability.logs)
    || observability.logs.invocation_logs !== false) {
  fail("Worker invocation logs must be disabled");
}

const rateLimitBindings = Array.isArray(config.durable_objects?.bindings)
  ? config.durable_objects.bindings.filter((binding) => binding?.name === "AUTH_RATE_LIMITER")
  : [];
if (rateLimitBindings.length !== 1
    || rateLimitBindings[0].class_name !== "AuthRateLimiter"
    || Object.hasOwn(rateLimitBindings[0], "script_name")) {
  fail("Wrangler AUTH_RATE_LIMITER must bind to the local AuthRateLimiter class");
}
const hasRateLimitMigration = Array.isArray(config.migrations)
  && config.migrations.some((migration) => (
    migration?.tag === "v1"
    && Array.isArray(migration.new_sqlite_classes)
    && migration.new_sqlite_classes.includes("AuthRateLimiter")
  ));
if (!hasRateLimitMigration) {
  fail("Wrangler AuthRateLimiter SQLite migration v1 is missing");
}

const authStateBindings = Array.isArray(config.durable_objects?.bindings)
  ? config.durable_objects.bindings.filter((binding) => binding?.name === "AUTH_STATE")
  : [];
if (authStateBindings.length !== 1
    || authStateBindings[0].class_name !== "AuthState"
    || Object.hasOwn(authStateBindings[0], "script_name")) {
  fail("Wrangler AUTH_STATE must bind to the local AuthState class");
}
const hasAuthStateMigration = Array.isArray(config.migrations)
  && config.migrations.some((migration) => (
    migration?.tag === "v2"
    && Array.isArray(migration.new_sqlite_classes)
    && migration.new_sqlite_classes.includes("AuthState")
  ));
if (!hasAuthStateMigration) {
  fail("Wrangler AuthState SQLite migration v2 is missing");
}

const inviteBindings = Array.isArray(config.kv_namespaces)
  ? config.kv_namespaces.filter((binding) => binding?.binding === "INVITE_STORE")
  : [];
if (inviteBindings.length !== 1 || !isCloudflareIdentifier(inviteBindings[0].id)) {
  fail("Wrangler INVITE_STORE must have one 32-character lowercase hexadecimal namespace ID");
}

const requiredVars = [
  "ALLOWED_HOSTNAMES",
  "ACCOUNT_ID",
  "IP_LIST_ID",
  "TURNSTILE_SITE_KEY",
  "SUB2API_DEFAULT_BASE_URL",
  "SUB2API_SYNC_URL",
];
for (const name of requiredVars) {
  if (!isDeploymentValue(config.vars?.[name])) {
    fail(`Wrangler required setting is missing or still a placeholder: ${name}`);
  }
}
if (!isCloudflareIdentifier(config.vars.ACCOUNT_ID)) {
  fail("Wrangler ACCOUNT_ID must be a 32-character lowercase hexadecimal Cloudflare ID");
}
if (!isCloudflareIdentifier(config.vars.IP_LIST_ID)) {
  fail("Wrangler IP_LIST_ID must be a 32-character lowercase hexadecimal Cloudflare ID");
}
if (!Object.hasOwn(config.vars || {}, "PROVIDER_ALLOWED_HOSTNAMES")
    || typeof config.vars.PROVIDER_ALLOWED_HOSTNAMES !== "string"
    || !config.vars.PROVIDER_ALLOWED_HOSTNAMES.trim()) {
  fail("Wrangler PROVIDER_ALLOWED_HOSTNAMES must contain at least one explicit fully qualified hostname");
}

const allowedHostnames = String(config.vars.ALLOWED_HOSTNAMES)
  .split(",")
  .map((hostname) => hostname.trim().toLowerCase())
  .filter(Boolean);
if (allowedHostnames.length === 0
    || allowedHostnames.some((hostname) => !isHostname(hostname))) {
  fail("Wrangler ALLOWED_HOSTNAMES must contain explicit fully qualified hostnames");
}
const providerRaw = config.vars.PROVIDER_ALLOWED_HOSTNAMES.trim();
const providerHostnames = providerRaw
  .split(",")
  .map((hostname) => hostname.trim().toLowerCase());
if (providerHostnames.length === 0
    || providerHostnames.some((hostname) => !isHostname(hostname))) {
  fail("Wrangler PROVIDER_ALLOWED_HOSTNAMES must contain explicit fully qualified hostnames");
}
const publicHostnameSet = new Set(allowedHostnames);
if (providerHostnames.some((hostname) => publicHostnameSet.has(hostname))) {
  fail("Wrangler provider hostnames must not overlap ALLOWED_HOSTNAMES");
}
if (expectedPublicHostname
    && (!isHostname(expectedPublicHostname)
      || !allowedHostnames.includes(expectedPublicHostname))) {
  fail("Wrangler ALLOWED_HOSTNAMES must include the configured public Sub2API hostname");
}
const defaultBaseUrl = approvedHttpsUrl(
  config.vars.SUB2API_DEFAULT_BASE_URL,
  allowedHostnames,
);
if (!defaultBaseUrl) {
  fail("Wrangler SUB2API_DEFAULT_BASE_URL hostname must be in ALLOWED_HOSTNAMES");
}
if (expectedPublicHostname && defaultBaseUrl.hostname.toLowerCase() !== expectedPublicHostname) {
  fail("Wrangler SUB2API_DEFAULT_BASE_URL must use the configured public Sub2API hostname");
}
const syncUrl = approvedHttpsUrl(config.vars.SUB2API_SYNC_URL, allowedHostnames);
if (!syncUrl || syncUrl.pathname !== "/_sub2api-sync/provision") {
  fail("Wrangler SUB2API_SYNC_URL must use an approved hostname and exact /_sub2api-sync/provision path");
}
if (expectedPublicHostname && syncUrl.hostname.toLowerCase() !== expectedPublicHostname) {
  fail("Wrangler SUB2API_SYNC_URL must use the configured public Sub2API hostname");
}
if (!Array.isArray(config.routes) || config.routes.length === 0) {
  fail("Worker routes must be limited to approved /allow-ip* hostnames");
}
const routeHostnames = [];
for (const route of config.routes) {
  const match = isObject(route)
    ? String(route.pattern || "").match(/^([A-Za-z0-9.-]+)\/allow-ip\*$/)
    : null;
  const hostname = match?.[1]?.toLowerCase() || "";
  const zoneName = isObject(route) ? String(route.zone_name || "").toLowerCase() : "";
  if (!match
      || Object.hasOwn(route, "custom_domain")
      || !isHostname(hostname)
      || !allowedHostnames.includes(hostname)
      || !isHostname(zoneName)
      || (hostname !== zoneName && !hostname.endsWith(`.${zoneName}`))) {
    fail("Worker routes must be limited to approved /allow-ip* hostnames");
  }
  routeHostnames.push(hostname);
}
const requiredRouteHostname = expectedPublicHostname || defaultBaseUrl.hostname.toLowerCase();
if (!routeHostnames.includes(requiredRouteHostname)) {
  fail("Worker routes must include the configured public Sub2API hostname on /allow-ip*");
}

const requiredSecrets = readRequiredSecrets(secretManifestPath);
for (const name of requiredSecrets) {
  if (Object.hasOwn(config.vars || {}, name)) {
    fail(`Wrangler secret must not be stored in vars: ${name}`);
  }
}

function readRequiredSecrets(path) {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    fail("required Worker Secret manifest must be valid JSON");
  }
  if (!isObject(manifest)
      || manifest.version !== 1
      || !Array.isArray(manifest.required)
      || manifest.required.length === 0
      || new Set(manifest.required).size !== manifest.required.length
      || manifest.required.some((name) => (
        typeof name !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(name)
      ))) {
    fail("required Worker Secret manifest has an invalid shape");
  }
  return manifest.required;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isDeploymentValue(value) {
  if (typeof value !== "string" || !value.trim()) return false;
  return !value.includes("YOUR_")
    && !value.includes("replace-with-")
    && !value.includes("example.com");
}

function isCloudflareIdentifier(value) {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

function isHostname(hostname) {
  if (hostname.length > 253
      || hostname === "localhost"
      || hostname.endsWith(".localhost")
      || hostname.endsWith(".local")
      || hostname.endsWith(".")
      || hostname.includes("..")
      || hostname.includes(":")
      || hostname.startsWith("[")
      || hostname.endsWith("]")) {
    return false;
  }
  const labels = hostname.split(".");
  return labels.length >= 2
    && !/^\d+$/.test(labels.at(-1))
    && labels.every((label) => (
      /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)
    ));
}

function approvedHttpsUrl(value, allowedHostnames) {
  let url;
  try {
    url = new URL(String(value || ""));
  } catch {
    return null;
  }
  if (url.protocol !== "https:"
      || url.username
      || url.password
      || url.port
      || url.search
      || url.hash
      || !isHostname(url.hostname)
      || !allowedHostnames.includes(url.hostname.toLowerCase())) {
    return null;
  }
  return url;
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
