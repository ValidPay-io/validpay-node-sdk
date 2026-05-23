import { randomBytes, createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { ValidPayError } from "./types.js";

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Wire format (matches the Python SDK so blobs are interoperable):
 *   base64(iv[12] || authTag[16] || ciphertext)
 */

export function generateKey(): string {
  return randomBytes(KEY_BYTES).toString("base64");
}

function decodeKey(key: string): Buffer {
  let buf: Buffer;
  try {
    buf = Buffer.from(key, "base64");
  } catch (cause) {
    throw new ValidPayError("invalid_key", "Key is not valid base64", { cause });
  }
  if (buf.length !== KEY_BYTES) {
    throw new ValidPayError(
      "invalid_key",
      `Key must decode to ${KEY_BYTES} bytes (got ${buf.length})`,
    );
  }
  return buf;
}

export function encrypt(plaintext: string, key: string): string {
  const keyBuf = decodeKey(key);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, keyBuf, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

export function decrypt(blob: string, key: string): string {
  const keyBuf = decodeKey(key);

  let buf: Buffer;
  try {
    buf = Buffer.from(blob, "base64");
  } catch (cause) {
    throw new ValidPayError("invalid_blob", "Blob is not valid base64", { cause });
  }

  if (buf.length < IV_BYTES + TAG_BYTES + 1) {
    throw new ValidPayError(
      "invalid_blob",
      `Blob too short: expected at least ${IV_BYTES + TAG_BYTES + 1} bytes`,
    );
  }

  const iv = buf.subarray(0, IV_BYTES);
  const authTag = buf.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const ciphertext = buf.subarray(IV_BYTES + TAG_BYTES);

  const decipher = createDecipheriv(ALGORITHM, keyBuf, iv);
  decipher.setAuthTag(authTag);

  try {
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch (cause) {
    throw new ValidPayError(
      "decryption_failed",
      "Decryption failed — wrong key or tampered blob",
      { cause },
    );
  }
}

export function commitmentHash(plaintext: string): string {
  return createHash("sha256").update(plaintext, "utf8").digest("hex");
}

export function splitKey(key: string): [string, string] {
  const keyBuf = decodeKey(key);
  const shareA = randomBytes(KEY_BYTES);
  const shareB = Buffer.alloc(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) {
    shareB[i] = keyBuf[i]! ^ shareA[i]!;
  }
  return [shareA.toString("base64"), shareB.toString("base64")];
}

export function combineKeyShares(shareA: string, shareB: string): string {
  const a = decodeKey(shareA);
  const b = decodeKey(shareB);
  const combined = Buffer.alloc(KEY_BYTES);
  for (let i = 0; i < KEY_BYTES; i++) {
    combined[i] = a[i]! ^ b[i]!;
  }
  return combined.toString("base64");
}

/** Encrypt each field of payload with its own AES key (Selective Disclosure). */
export function encryptFields(
  payload: Record<string, unknown>,
): { encryptedFields: Record<string, string>; fieldKeys: Record<string, string> } {
  const encryptedFields: Record<string, string> = {};
  const fieldKeys: Record<string, string> = {};
  for (const [name, value] of Object.entries(payload)) {
    const k = generateKey();
    const plaintext = typeof value === "string" ? value : JSON.stringify(value);
    encryptedFields[name] = encrypt(plaintext, k);
    fieldKeys[name] = k;
  }
  return { encryptedFields, fieldKeys };
}

/** Build per-role key map; "full" role always added with all keys. */
export function buildKeyMap(
  fieldKeys: Record<string, string>,
  disclosurePolicy: Record<string, string[]>,
): Record<string, Record<string, string>> {
  const map: Record<string, Record<string, string>> = {};
  for (const [role, fields] of Object.entries(disclosurePolicy)) {
    const roleKeys: Record<string, string> = {};
    for (const f of fields) {
      if (fieldKeys[f] !== undefined) roleKeys[f] = fieldKeys[f];
    }
    map[role] = roleKeys;
  }
  map["full"] = { ...fieldKeys };
  return map;
}

/** Decrypt only fields with keys; others become "[REDACTED]". */
export function decryptFields(
  encryptedFields: Record<string, string>,
  fieldKeys: Record<string, string>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, blob] of Object.entries(encryptedFields)) {
    if (fieldKeys[name] !== undefined) {
      const plaintext = decrypt(blob, fieldKeys[name]);
      try {
        out[name] = JSON.parse(plaintext);
      } catch {
        out[name] = plaintext;
      }
    } else {
      out[name] = "[REDACTED]";
    }
  }
  return out;
}
