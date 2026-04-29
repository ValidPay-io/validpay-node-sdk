import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { ValidPayError } from "./types.js";

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

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
