import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import { resolve } from "node:path";

const HMAC_KEY_PATTERN = /^[A-Za-z0-9_-]{64}$/;

function validateParent(path, expectedUid) {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw new Error("private_hmac_state_directory_unavailable");
  }
  if (
    !metadata.isDirectory()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o777) !== 0o700
    || realpathSync(path) !== resolve(path)
  ) {
    throw new Error("private_hmac_state_directory_unsafe");
  }
  return true;
}

export function readPrivateHmacState(path, { expectedUid = 0, missingOk = false } = {}) {
  if (!validateParent(dirname(path), expectedUid)) {
    if (missingOk) return null;
    throw new Error("private_hmac_migration_state_missing_rotation_required");
  }
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (missingOk && error?.code === "ENOENT") return null;
    throw new Error(error?.code === "ENOENT"
      ? "private_hmac_migration_state_missing_rotation_required"
      : "private_hmac_migration_state_unsafe");
  }

  try {
    const metadata = fstatSync(descriptor);
    if (
      !metadata.isFile()
      || metadata.uid !== expectedUid
      || (metadata.mode & 0o777) !== 0o600
      || metadata.nlink !== 1
      || metadata.size !== 65
    ) {
      throw new Error("private_hmac_migration_state_unsafe");
    }
    const raw = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      raw.length !== 65
      || raw[64] !== 0x0a
      || metadata.dev !== after.dev
      || metadata.ino !== after.ino
      || metadata.size !== after.size
    ) {
      throw new Error("private_hmac_migration_state_invalid");
    }
    const hmacKey = raw.subarray(0, 64).toString("ascii");
    if (!HMAC_KEY_PATTERN.test(hmacKey)) {
      throw new Error("private_hmac_migration_state_invalid");
    }
    return {
      hmacKey,
      identity: { dev: metadata.dev, ino: metadata.ino, size: metadata.size },
    };
  } finally {
    closeSync(descriptor);
  }
}

export function destroyPrivateHmacState(path, state, { expectedUid = 0 } = {}) {
  const current = readPrivateHmacState(path, { expectedUid });
  if (
    current.identity.dev !== state.identity.dev
    || current.identity.ino !== state.identity.ino
    || current.hmacKey !== state.hmacKey
  ) {
    throw new Error("private_hmac_migration_state_changed");
  }

  const descriptor = openSync(path, constants.O_RDWR | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(descriptor);
    if (metadata.dev !== state.identity.dev || metadata.ino !== state.identity.ino) {
      throw new Error("private_hmac_migration_state_changed");
    }
    const zeros = Buffer.alloc(state.identity.size);
    let cleared = 0;
    while (cleared < zeros.length) {
      cleared += writeSync(
        descriptor,
        zeros,
        cleared,
        zeros.length - cleared,
        cleared,
      );
    }
    fsyncSync(descriptor);
    ftruncateSync(descriptor, 0);
    fsyncSync(descriptor);
    const linked = lstatSync(path);
    if (linked.dev !== metadata.dev || linked.ino !== metadata.ino) {
      throw new Error("private_hmac_migration_state_changed");
    }
    unlinkSync(path);
    const parent = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
  } finally {
    closeSync(descriptor);
  }
}
