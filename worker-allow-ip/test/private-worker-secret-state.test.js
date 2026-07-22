import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  destroyPrivateHmacState,
  readPrivateHmacState,
} from "../../deploy/private-worker-secret-state.mjs";

const KEY = "k".repeat(64);

function fixture() {
  const parent = mkdtempSync(join(tmpdir(), "sub2api-hmac-state-"));
  chmodSync(parent, 0o700);
  const path = join(parent, "invite-access-hmac-migration.key");
  writeFileSync(path, `${KEY}\n`, { mode: 0o600 });
  return { parent, path, expectedUid: process.getuid() };
}

test("private HMAC state is read and logically destroyed without printing its value", () => {
  const state = fixture();
  const loaded = readPrivateHmacState(state.path, state);
  assert.equal(loaded.hmacKey, KEY);
  destroyPrivateHmacState(state.path, loaded, state);
  assert.throws(
    () => readPrivateHmacState(state.path, state),
    /private_hmac_migration_state_missing_rotation_required/,
  );
});

test("private HMAC state rejects group-readable files", () => {
  const state = fixture();
  chmodSync(state.path, 0o640);
  assert.throws(() => readPrivateHmacState(state.path, state), /state_unsafe/);
});

test("private HMAC state rejects a writable parent directory", () => {
  const state = fixture();
  chmodSync(state.parent, 0o770);
  assert.throws(() => readPrivateHmacState(state.path, state), /directory_unsafe/);
});

test("private HMAC state does not follow a symlink", () => {
  const state = fixture();
  const link = join(state.parent, "linked.key");
  symlinkSync(state.path, link);
  assert.throws(() => readPrivateHmacState(link, state), /state_unsafe/);
  assert.equal(readFileSync(state.path, "utf8"), `${KEY}\n`);
});

test("missing private HMAC state requires controlled rotation when legacy data remains", () => {
  const state = fixture();
  destroyPrivateHmacState(
    state.path,
    readPrivateHmacState(state.path, state),
    state,
  );
  assert.throws(
    () => readPrivateHmacState(state.path, state),
    /missing_rotation_required/,
  );
});
