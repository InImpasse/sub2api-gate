#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { WORKER_TOTP_ROTATION_STAGING_SECRETS } from "./worker-totp-rotation-secrets.mjs";
const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
const FORBIDDEN_ROTATION_SECRET_READ = new RegExp(
  `\\b(?:${WORKER_TOTP_ROTATION_STAGING_SECRETS.join("|")})\\b`,
);
const FORBIDDEN_DYNAMIC_ENV_READ = /\benv\s*\[/;
const BUNDLE_SOURCE_FILE = /\.(?:[cm]?[jt]sx?)$/;
const FORBIDDEN_MODULE_IMPORT = /(?:\b(?:import|export)\b[\s\S]*?\bfrom\s*|\bimport\s*)["'](?:\.\.\/|\/)|\b(?:import|require)\s*\(/;

if (process.argv.length > 3) {
  fail("usage: verify-final-worker-totp-source.mjs [worker-source-directory]");
}

const sourceRoot = path.resolve(
  process.argv[2]
    || fileURLToPath(new URL("../worker-allow-ip/src/", import.meta.url)),
);
const sourceFiles = [];
try {
  collectSourceFiles(sourceRoot, sourceFiles);
  if (sourceFiles.length === 0) {
    throw new Error("no Worker source files found");
  }
} catch {
  fail("final Worker source could not be inspected");
}

for (const sourceFile of sourceFiles) {
  let source;
  try {
    source = fs.readFileSync(sourceFile, "utf8");
  } catch {
    fail("final Worker source could not be inspected");
  }
  if (FORBIDDEN_ROTATION_SECRET_READ.test(source)) {
    fail("final Worker source still reads TOTP rotation Secrets");
  }
  if (FORBIDDEN_DYNAMIC_ENV_READ.test(source)) {
    fail("final Worker source contains a dynamic environment access");
  }
  if (FORBIDDEN_MODULE_IMPORT.test(source)) {
    fail("final Worker source contains an unsupported module import");
  }

}
console.log("Final Worker source no longer reads TOTP rotation Secrets");

function collectSourceFiles(directory, sourceFiles) {
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("invalid Worker source directory");
  }
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const child = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      collectSourceFiles(child, sourceFiles);
      continue;
    }
    if (entry.isSymbolicLink()) {
      throw new Error("Worker source symlink is not allowed");
    }
    if (!entry.isFile() || !BUNDLE_SOURCE_FILE.test(entry.name)) {
      continue;
    }
    const fileMetadata = fs.statSync(child);
    if (fileMetadata.size > MAX_SOURCE_FILE_BYTES) {
      throw new Error("Worker source file is too large");
    }
    sourceFiles.push(child);
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
