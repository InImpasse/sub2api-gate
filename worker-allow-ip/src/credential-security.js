const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const LEGACY_CREDENTIAL_AAD = encoder.encode("sub2api-gate:credential:v1");
const CREDENTIAL_ENVELOPE_VERSION = 2;
const INVITE_STORAGE_FIELDS = new Set([
  "uuid",
  "username",
  "name",
  "email",
  "remark",
  "createdAt",
  "updatedAt",
  "credentialVersion",
  "accessCredentialVersion",
  "accessKeyHmac",
  "legacyUuidLoginUntil",
  "storageVersion",
  "apiConfigs",
  "sub2apiSync",
]);
const API_CONFIG_STORAGE_FIELDS = new Set(["id", "name", "baseUrl", "apiKeyEncrypted", "groupName"]);
const SYNC_STORAGE_FIELDS = new Set([
  "userId",
  "apiKeyId",
  "tokenId",
  "username",
  "email",
  "loginUrl",
  "syncedAt",
  "passwordChangedExternally",
  "loginPasswordEncrypted",
  "passwordHashFingerprint",
]);
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const KEY_GROUP_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FORBIDDEN_KEY_GROUP_NAMES = new Set(["default"]);
export const DEFAULT_KEY_GROUP_NAME = "openai-default";
const MAX_CREDENTIAL_PLAINTEXT_BYTES = 2048;
const MAX_CREDENTIAL_CIPHERTEXT_BYTES = MAX_CREDENTIAL_PLAINTEXT_BYTES + 16;
const MAX_CREDENTIAL_ENVELOPE_DATA_CHARS = Math.ceil(
  MAX_CREDENTIAL_CIPHERTEXT_BYTES * 4 / 3,
);
const MAX_CREDENTIAL_ENVELOPE_IV_CHARS = 64;

export function parseKeyGroupName(value, { required = true } = {}) {
  const name = String(value || "").trim();
  if (!name) {
    if (required) throw new Error("Key group is required");
    return "";
  }
  if (!KEY_GROUP_NAME_PATTERN.test(name) || FORBIDDEN_KEY_GROUP_NAMES.has(name.toLowerCase())) {
    throw new Error("Invalid key group");
  }
  return name;
}

export function generateAccessKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `s2a_${base64UrlEncode(bytes)}`;
}

export async function accessKeyHmac(secret, accessKey) {
  return hmacHex(secret, `invite-access:${String(accessKey || "")}`);
}

export async function rateLimitFingerprint(secret, scope, value) {
  const normalizedScope = String(scope || "").trim();
  if (!normalizedScope || !/^[a-z0-9_-]{1,64}$/i.test(normalizedScope)) {
    throw new Error("Rate-limit scope is invalid");
  }
  return hmacHex(secret, `rate-limit:${normalizedScope}:${String(value || "")}`);
}

export async function inviteReference(secret, uuid) {
  return (await hmacHex(secret, `cloudflare-list:${String(uuid || "")}`)).slice(0, 32);
}

export async function cloudflareListComment(secret, uuid) {
  return `sub2api ref ${await inviteReference(secret, uuid)}`;
}

export async function cloudflareMutationComment(secret, mutationId) {
  const reference = await hmacHex(secret, `cloudflare-mutation:${String(mutationId || "")}`);
  return `sub2api ref ${reference.slice(0, 32)}`;
}

export async function cloudflareListValueHmac(secret, value) {
  return hmacHex(secret, `cloudflare-list-value:${String(value || "")}`);
}

export async function issueInviteAccessCredential(
  invite,
  hmacKey,
  now = new Date(),
  allowLegacyUuid = false,
) {
  const accessKey = generateAccessKey();
  const legacyUuidLoginUntil = allowLegacyUuid
    ? new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString()
    : "";
  return {
    accessKey,
    invite: {
      ...invite,
      credentialVersion: 2,
      accessCredentialVersion: Number(invite?.accessCredentialVersion || 0) + 1,
      accessKeyHmac: await accessKeyHmac(hmacKey, accessKey),
      legacyUuidLoginUntil,
    },
  };
}

export async function matchesInviteAccess(
  invite,
  input,
  hmacKey,
  now = new Date(),
  precomputedCandidateHmac = "",
) {
  const candidate = String(input || "");
  if (!candidate || !invite) return false;
  if (Number(invite.credentialVersion || 0) < 2 && !invite.accessKeyHmac) {
    return await timingSafeTextEqual(candidate, String(invite.uuid || ""));
  }
  if (invite.accessKeyHmac) {
    const candidateHmac = precomputedCandidateHmac || await accessKeyHmac(hmacKey, candidate);
    if (await timingSafeTextEqual(candidateHmac, String(invite.accessKeyHmac))) return true;
  }
  const legacyDeadline = Date.parse(String(invite.legacyUuidLoginUntil || ""));
  return Number.isFinite(legacyDeadline)
    && now.getTime() <= legacyDeadline
    && await timingSafeTextEqual(candidate, String(invite.uuid || ""));
}

export async function passwordHashFingerprint(secret, passwordHash) {
  return hmacHex(secret, `sub2api-password-hash:${String(passwordHash || "")}`);
}

export async function pbkdf2PasswordRecord(password, iterations = 310_000, salt = null) {
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) {
    throw new Error("PBKDF2 iterations are outside the supported range");
  }
  const saltBytes = salt || crypto.getRandomValues(new Uint8Array(16));
  if (!(saltBytes instanceof Uint8Array) || saltBytes.byteLength < 16) {
    throw new Error("PBKDF2 salt must contain at least 16 bytes");
  }
  const derived = await derivePbkdf2(password, saltBytes, iterations);
  return `pbkdf2_sha256$${iterations}$${base64UrlEncode(saltBytes)}$${base64UrlEncode(derived)}`;
}

export async function verifyPbkdf2Password(password, record) {
  const parts = String(record || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256" || !/^\d+$/.test(parts[1])) {
    return false;
  }
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 2_000_000) {
    return false;
  }
  try {
    const salt = base64UrlDecode(parts[2]);
    const expected = base64UrlDecode(parts[3]);
    if (salt.byteLength < 16 || expected.byteLength !== 32) return false;
    const actual = await derivePbkdf2(password, salt, iterations);
    return timingSafeBytesEqual(actual, expected);
  } catch {
    return false;
  }
}

export async function encryptCredential(secret, plaintext, context) {
  if (!plaintext) return null;
  const plaintextBytes = encoder.encode(String(plaintext));
  if (plaintextBytes.byteLength > MAX_CREDENTIAL_PLAINTEXT_BYTES) {
    throw new Error("Credential plaintext is too large");
  }
  const key = await importAesKey(secret, ["encrypt"]);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: credentialAdditionalData(CREDENTIAL_ENVELOPE_VERSION, context),
      tagLength: 128,
    },
    key,
    plaintextBytes,
  );
  return {
    v: CREDENTIAL_ENVELOPE_VERSION,
    alg: "A256GCM",
    iv: base64UrlEncode(iv),
    data: base64UrlEncode(new Uint8Array(ciphertext)),
  };
}

export async function decryptCredential(secret, envelope, context = "") {
  if (!envelope) return "";
  const { iv, ciphertext } = parseCredentialEnvelope(envelope);
  const key = await importAesKey(secret, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: credentialAdditionalData(envelope.v, context),
      tagLength: 128,
    },
    key,
    ciphertext,
  );
  return decoder.decode(plaintext);
}

export async function protectInviteCredentials(invite, encryptionKey, hmacKey) {
  const source = invite && typeof invite === "object" && !Array.isArray(invite) ? invite : {};
  const protectedConfigs = await Promise.all(
    (Array.isArray(source.apiConfigs) ? source.apiConfigs : []).map(async (config) => {
      const configSource = config && typeof config === "object" && !Array.isArray(config)
        ? config
        : {};
      const credentialId = String(configSource.id || "").trim() || randomCredentialId();
      return {
        ...definedFields(configSource, ["name", "baseUrl", "groupName"]),
        id: credentialId,
        apiKeyEncrypted: configSource.apiKey
          ? await encryptCredential(
            encryptionKey,
            configSource.apiKey,
            inviteCredentialContext(source, "api-key", credentialId),
          )
          : configSource.apiKeyEncrypted || null,
      };
    }),
  );
  const sync = source.sub2apiSync && typeof source.sub2apiSync === "object"
    && !Array.isArray(source.sub2apiSync)
    ? source.sub2apiSync
    : {};
  return {
    ...definedFields(source, [
      "uuid",
      "username",
      "name",
      "email",
      "remark",
      "createdAt",
      "updatedAt",
      "credentialVersion",
      "accessCredentialVersion",
      "accessKeyHmac",
      "legacyUuidLoginUntil",
    ]),
    storageVersion: 2,
    apiConfigs: protectedConfigs,
    sub2apiSync: {
      ...definedFields(sync, [
        "userId",
        "apiKeyId",
        "tokenId",
        "username",
        "email",
        "loginUrl",
        "syncedAt",
        "passwordChangedExternally",
      ]),
      loginPasswordEncrypted: sync.loginPassword
        ? await encryptCredential(
          encryptionKey,
          sync.loginPassword,
          inviteCredentialContext(source, "login-password", "sub2api-sync"),
        )
        : sync.loginPasswordEncrypted || null,
      passwordHashFingerprint: sync.passwordHash
        ? await passwordHashFingerprint(hmacKey, sync.passwordHash)
        : sync.passwordHashFingerprint || "",
    },
  };
}

export function hasInviteStorageSchema(value) {
  if (!isPlainObject(value) || !hasOnlyFields(value, INVITE_STORAGE_FIELDS)) return false;
  if (!isOptionalSha256Hex(value.accessKeyHmac)) return false;
  if (value.apiConfigs !== undefined) {
    if (!Array.isArray(value.apiConfigs)) return false;
    if (value.apiConfigs.some((config) => (
      !isPlainObject(config)
      || !hasOnlyFields(config, API_CONFIG_STORAGE_FIELDS)
      || !isOptionalCredentialEnvelope(config.apiKeyEncrypted)
      || !isOptionalKeyGroupName(config.groupName)
    ))) return false;
  }
  if (value.sub2apiSync === undefined) return true;
  return isPlainObject(value.sub2apiSync)
    && hasOnlyFields(value.sub2apiSync, SYNC_STORAGE_FIELDS)
    && isOptionalCredentialEnvelope(value.sub2apiSync.loginPasswordEncrypted)
    && isOptionalSha256Hex(value.sub2apiSync.passwordHashFingerprint);
}

function isOptionalKeyGroupName(value) {
  if (value === undefined || value === "") return true;
  try {
    parseKeyGroupName(value);
    return true;
  } catch {
    return false;
  }
}

function isOptionalSha256Hex(value) {
  return value === undefined || value === "" || (
    typeof value === "string" && SHA256_HEX_PATTERN.test(value)
  );
}

function isOptionalCredentialEnvelope(value) {
  if (value === undefined || value === null) return true;
  try {
    parseCredentialEnvelope(value);
    return true;
  } catch {
    return false;
  }
}

function parseCredentialEnvelope(value) {
  if (
    !isPlainObject(value)
    || !hasOnlyFields(value, new Set(["v", "alg", "iv", "data"]))
    || Object.keys(value).length !== 4
    || ![1, CREDENTIAL_ENVELOPE_VERSION].includes(value.v)
    || value.alg !== "A256GCM"
    || typeof value.iv !== "string"
    || typeof value.data !== "string"
    || value.iv.length > MAX_CREDENTIAL_ENVELOPE_IV_CHARS
    || value.data.length > MAX_CREDENTIAL_ENVELOPE_DATA_CHARS
  ) {
    throw new Error("Unsupported credential envelope");
  }
  const iv = base64UrlDecode(value.iv);
  const ciphertext = base64UrlDecode(value.data);
  if (iv.byteLength !== 12) {
    throw new Error("Credential envelope IV must contain 12 bytes");
  }
  if (ciphertext.byteLength < 16) {
    throw new Error("Credential envelope must contain a 128-bit authentication tag");
  }
  if (ciphertext.byteLength > MAX_CREDENTIAL_CIPHERTEXT_BYTES) {
    throw new Error("Credential envelope is too large");
  }
  return { iv, ciphertext };
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOnlyFields(value, allowedFields) {
  return Object.keys(value).every((field) => allowedFields.has(field));
}

function definedFields(source, allowedFields) {
  const result = {};
  for (const field of allowedFields) {
    if (Object.hasOwn(source, field) && source[field] !== undefined) {
      result[field] = source[field];
    }
  }
  return result;
}

export async function revealInviteCredentials(invite, encryptionKey) {
  const configs = await Promise.all(
    (Array.isArray(invite?.apiConfigs) ? invite.apiConfigs : []).map(async (config) => ({
      ...config,
      apiKey: config.apiKey || await decryptCredential(
        encryptionKey,
        config.apiKeyEncrypted,
        inviteCredentialContext(invite, "api-key", config.id),
      ),
    })),
  );
  const sync = invite?.sub2apiSync || {};
  return {
    ...invite,
    apiConfigs: configs,
    sub2apiSync: {
      ...sync,
      loginPassword: sync.loginPassword
        || await decryptCredential(
          encryptionKey,
          sync.loginPasswordEncrypted,
          inviteCredentialContext(invite, "login-password", "sub2api-sync"),
        ),
    },
  };
}

function credentialAdditionalData(version, context) {
  if (version === 1) {
    return LEGACY_CREDENTIAL_AAD;
  }
  const normalized = String(context || "");
  if (!normalized || normalized.length > 1024) {
    throw new Error("Credential encryption context is required");
  }
  return encoder.encode(`sub2api-gate:credential:v2:${normalized}`);
}

function inviteCredentialContext(invite, field, credentialId) {
  const uuid = String(invite?.uuid || "").trim().toLowerCase();
  const id = String(credentialId || "").trim();
  if (!uuid || !id) {
    throw new Error("Credential invite and field identity are required");
  }
  return JSON.stringify(["invite", uuid, String(field), id]);
}

function randomCredentialId() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `credential-${base64UrlEncode(bytes)}`;
}

export function sanitizeInviteForTrash(invite) {
  const source = invite || {};
  const sync = source.sub2apiSync || {};
  return {
    uuid: String(source.uuid || ""),
    username: String(source.username || ""),
    name: String(source.name || ""),
    email: String(source.email || ""),
    remark: String(source.remark || ""),
    createdAt: String(source.createdAt || ""),
    updatedAt: String(source.updatedAt || ""),
    apiConfigs: (Array.isArray(source.apiConfigs) ? source.apiConfigs : []).map((config) => ({
      id: config.id || "",
      name: config.name || "",
      baseUrl: config.baseUrl || "",
      groupName: String(config.groupName || ""),
    })),
    sub2apiSync: {
      userId: Number(sync.userId || 0),
      tokenId: Number(sync.tokenId || 0),
      username: String(sync.username || ""),
      email: String(sync.email || ""),
      loginUrl: String(sync.loginUrl || ""),
      syncedAt: String(sync.syncedAt || ""),
    },
  };
}

async function hmacHex(secret, value) {
  if (String(secret || "").length < 32) {
    throw new Error("INVITE_ACCESS_HMAC_KEY must be at least 32 characters");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, encoder.encode(value)),
  );
  return [...signature].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function importAesKey(secret, usages) {
  const raw = base64UrlDecode(secret);
  if (raw.byteLength !== 32) {
    throw new Error("CREDENTIAL_ENCRYPTION_KEY must decode to 32 bytes");
  }
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

async function derivePbkdf2(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(String(password || "")),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    256,
  ));
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(value) {
  if (
    typeof value !== "string"
    || !value
    || !/^[A-Za-z0-9_-]+$/.test(value)
    || value.length % 4 === 1
  ) {
    throw new Error("Value must use canonical unpadded base64url");
  }
  const input = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = input + "=".repeat((4 - (input.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("Value must use canonical unpadded base64url");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64UrlEncode(bytes) !== value) {
    throw new Error("Value must use canonical unpadded base64url");
  }
  return bytes;
}

export async function timingSafeTextEqual(left, right) {
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(left))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(right))),
  ]);
  return timingSafeBytesEqual(new Uint8Array(leftHash), new Uint8Array(rightHash));
}

function timingSafeBytesEqual(left, right) {
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(left, right);
  }

  // Node's Web Crypto does not yet expose the Workers-only primitive used in production.
  const maxLength = Math.max(left.byteLength, right.byteLength);
  let difference = left.byteLength ^ right.byteLength;
  for (let index = 0; index < maxLength; index += 1) {
    difference |= (left[index] || 0) ^ (right[index] || 0);
  }
  return difference === 0;
}
