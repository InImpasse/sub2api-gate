#!/usr/bin/env node

const MAX_LIST_BYTES = 64 * 1024;
import fs from "node:fs";


const manifestPath = process.argv[2]
  || new URL("../worker-allow-ip/required-secrets.json", import.meta.url);
const REQUIRED_WORKER_SECRETS = readRequiredSecrets(manifestPath);

let raw = "";
try {
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, "utf8") > MAX_LIST_BYTES) {
      fail("Cloudflare Worker secret list response is too large");
    }
  }
} catch {
  fail("Cloudflare Worker secret list could not be read");
}

let entries;
try {
  entries = JSON.parse(raw);
} catch {
  fail("Cloudflare Worker secret list is not valid JSON");
}
if (!Array.isArray(entries)) {
  fail("Cloudflare Worker secret list has an invalid shape");
}

const names = new Set();
for (const entry of entries) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)
      || typeof entry.name !== "string"
      || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(entry.name)) {
    fail("Cloudflare Worker secret list contains an invalid entry");
  }
  names.add(entry.name);
}

if (REQUIRED_WORKER_SECRETS.some((name) => !names.has(name))) {
  fail("One or more required Cloudflare Worker Secrets are missing");
}

console.log("Required Cloudflare Worker secret names verified");

function fail(message) {
  console.error(message);
  process.exit(1);
}

function readRequiredSecrets(path) {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    fail("required Worker Secret manifest must be valid JSON");
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
      || manifest.version !== 1
      || !Array.isArray(manifest.required)
      || manifest.required.length === 0
      || new Set(manifest.required).size !== manifest.required.length
      || manifest.required.some((name) => (
        typeof name !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(name)
      ))) {
    fail("required Worker Secret manifest has an invalid shape");
  }
  return Object.freeze([...manifest.required]);
}
