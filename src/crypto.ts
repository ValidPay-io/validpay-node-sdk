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

/**
 * Encrypt raw bytes (file mode — PDF/image/DOCX). {@link encrypt} is the UTF-8
 * string convenience wrapper. Returns the base64 wire blob.
 */
export function encryptBytes(plaintext: Uint8Array, key: string, aad?: string): string {
  const keyBuf = decodeKey(key);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, keyBuf, iv);
  // M-5: bind metadata as Associated Authenticated Data. Must precede update().
  if (aad) cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

export function encrypt(plaintext: string, key: string, aad?: string): string {
  return encryptBytes(Buffer.from(plaintext, "utf8"), key, aad);
}

/**
 * Decrypt a ValidPay-format base64 blob to raw bytes (file mode).
 * {@link decrypt} is the UTF-8 string wrapper.
 */
export function decryptBytes(blob: string, key: string, aad?: string): Buffer {
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
  if (aad) decipher.setAAD(Buffer.from(aad, "utf8"));

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (cause) {
    throw new ValidPayError(
      "decryption_failed",
      "Decryption failed — wrong key, tampered blob, or altered bound metadata",
      { cause },
    );
  }
}

export function decrypt(blob: string, key: string, aad?: string): string {
  return decryptBytes(blob, key, aad).toString("utf8");
}

/**
 * Canonical AAD for AES-GCM metadata binding (Prompt 097 M-5). MUST be
 * byte-identical across every SDK and the website verifier:
 *   - fixed key order (document_type, valid_from, valid_until);
 *   - compact JSON (JSON.stringify default — no spaces);
 *   - timestamps normalized to epoch milliseconds, NOT raw ISO strings (the
 *     server reformats ISO timestamps, which would break verification of
 *     legitimate time-locked documents).
 */
export function buildAad(
  documentType: string,
  validFrom?: string | null,
  validUntil?: string | null,
): string {
  return JSON.stringify({
    document_type: documentType,
    valid_from: epochMs(validFrom),
    valid_until: epochMs(validUntil),
  });
}

function epochMs(iso?: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/**
 * SHA-256 commitment over the *ciphertext* blob (commitment v2).
 *
 * Pass the base64 wire blob from {@link encrypt} — NOT the plaintext.
 * Hashing the ciphertext lets the commitment be published on the public
 * verify endpoint without becoming a confirmation oracle: SHA-256(plaintext)
 * over a low-entropy structured document can be brute-forced offline to
 * recover contents without the key (Prompt 097 C-1). It still proves the
 * server hasn't swapped the blob — the verifier recomputes and compares.
 */
export function commitmentHash(ciphertextB64: string): string {
  return createHash("sha256").update(ciphertextB64, "utf8").digest("hex");
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

/**
 * End-Cell (CVCP Layer 6B): split a key into ShareA (the QR) plus `pieceCount`
 * mandatory server-side XOR pieces. `K = ShareA ⊕ piece_1 ⊕ … ⊕ piece_m`, n-of-n —
 * every piece is required and each alone reveals nothing. Returns
 * `[shareA, ...pieces]`. With pieceCount=2 this is the default rail + platform split.
 */
export function splitKeyPieces(key: string, pieceCount: number): string[] {
  if (!Number.isInteger(pieceCount) || pieceCount < 1) {
    throw new Error("splitKeyPieces: pieceCount must be >= 1");
  }
  const keyBuf = decodeKey(key);
  const shareA = randomBytes(KEY_BYTES);
  const remainder = Buffer.from(keyBuf);
  for (let i = 0; i < KEY_BYTES; i++) remainder[i]! ^= shareA[i]!; // ShareB = K ⊕ ShareA
  const pieces: Buffer[] = [];
  for (let p = 0; p < pieceCount - 1; p++) {
    const piece = randomBytes(KEY_BYTES);
    for (let i = 0; i < KEY_BYTES; i++) remainder[i]! ^= piece[i]!;
    pieces.push(piece);
  }
  pieces.push(remainder); // last piece absorbs the remainder so XOR(all) == ShareB
  return [shareA.toString("base64"), ...pieces.map((b) => b.toString("base64"))];
}

/** End-Cell: reconstruct the key from ShareA XOR every server-side piece. */
export function combineKeyPieces(shareA: string, pieces: string[]): string {
  if (pieces.length < 1) throw new Error("combineKeyPieces: need at least one piece");
  const combined = Buffer.from(decodeKey(shareA));
  for (const pieceB64 of pieces) {
    const piece = decodeKey(pieceB64);
    for (let i = 0; i < KEY_BYTES; i++) combined[i]! ^= piece[i]!;
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
