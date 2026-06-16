import { describe, it, expect } from "vitest";
import {
  generateKey,
  encrypt,
  encryptBytes,
  decrypt,
  decryptBytes,
  commitmentHash,
  buildAad,
  splitKey,
  combineKeyShares,
  encryptFields,
  buildKeyMap,
  decryptFields,
} from "../src/crypto.js";
import { ValidPayError } from "../src/types.js";

describe("file mode (encryptBytes/decryptBytes)", () => {
  it("round-trips arbitrary binary bytes exactly", () => {
    const key = generateKey();
    const original = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00, 0x01, 0xff, 0xfe, 0x80, 0x90]);
    const out = decryptBytes(encryptBytes(original, key), key);
    expect(Buffer.from(out).equals(Buffer.from(original))).toBe(true);
  });

  it("fails decryptBytes on AAD mismatch", () => {
    const key = generateKey();
    const blob = encryptBytes(new Uint8Array([1, 2, 3]), key, "a");
    expect(() => decryptBytes(blob, key, "b")).toThrow(ValidPayError);
  });

  it("encrypt() delegates to encryptBytes() (UTF-8 round-trip)", () => {
    const key = generateKey();
    expect(decryptBytes(encrypt("héllo ✓", key), key).toString("utf8")).toBe("héllo ✓");
  });
});

describe("AAD binding (M-5)", () => {
  it("round-trips with matching AAD", () => {
    const key = generateKey();
    const aad = buildAad("check", null, "2026-08-01T00:00:00Z");
    expect(decrypt(encrypt('{"amount":100}', key, aad), key, aad)).toBe('{"amount":100}');
  });

  it("fails when the AAD is altered", () => {
    const key = generateKey();
    const blob = encrypt('{"amount":100}', key, buildAad("check"));
    expect(() => decrypt(blob, key, buildAad("other"))).toThrow(ValidPayError);
  });

  it("produces the canonical compact, epoch-ms form (cross-SDK interop)", () => {
    expect(buildAad("check", null, "2026-08-01T00:00:00Z")).toBe(
      '{"document_type":"check","valid_from":null,"valid_until":1785542400000}',
    );
  });
});

describe("crypto", () => {
  it("generateKey returns a 32-byte base64 key", () => {
    const key = generateKey();
    expect(typeof key).toBe("string");
    const buf = Buffer.from(key, "base64");
    expect(buf.length).toBe(32);
  });

  it("generateKey returns unique keys", () => {
    const a = generateKey();
    const b = generateKey();
    expect(a).not.toBe(b);
  });

  it("encrypts and decrypts a round-trip", () => {
    const key = generateKey();
    const plaintext = JSON.stringify({ ssn: "123-45-6789", name: "Jane Doe" });
    const blob = encrypt(plaintext, key);
    expect(typeof blob).toBe("string");
    expect(blob).not.toContain(plaintext);
    expect(decrypt(blob, key)).toBe(plaintext);
  });

  it("encrypts unicode and large payloads", () => {
    const key = generateKey();
    const plaintext = "héllo 🔐 " + "x".repeat(10_000);
    const blob = encrypt(plaintext, key);
    expect(decrypt(blob, key)).toBe(plaintext);
  });

  it("produces different ciphertext for the same plaintext (random IV)", () => {
    const key = generateKey();
    const a = encrypt("hello", key);
    const b = encrypt("hello", key);
    expect(a).not.toBe(b);
  });

  it("blob format is base64(iv[12] + authTag[16] + ciphertext)", () => {
    const key = generateKey();
    const plaintext = "hi";
    const blob = encrypt(plaintext, key);
    const buf = Buffer.from(blob, "base64");
    expect(buf.length).toBe(12 + 16 + Buffer.byteLength(plaintext, "utf8"));
  });

  it("throws when decrypting with the wrong key", () => {
    const k1 = generateKey();
    const k2 = generateKey();
    const blob = encrypt("secret", k1);
    expect(() => decrypt(blob, k2)).toThrow(ValidPayError);
    try {
      decrypt(blob, k2);
    } catch (err) {
      expect(err).toBeInstanceOf(ValidPayError);
      expect((err as ValidPayError).code).toBe("decryption_failed");
    }
  });

  it("throws when the blob has been tampered with (auth tag check)", () => {
    const key = generateKey();
    const blob = encrypt("secret", key);
    const buf = Buffer.from(blob, "base64");
    const last = buf[buf.length - 1] ?? 0;
    buf[buf.length - 1] = last ^ 0x01;
    const tampered = buf.toString("base64");
    expect(() => decrypt(tampered, key)).toThrow(ValidPayError);
    try {
      decrypt(tampered, key);
    } catch (err) {
      expect((err as ValidPayError).code).toBe("decryption_failed");
    }
  });

  it("throws when the auth tag has been tampered with", () => {
    const key = generateKey();
    const blob = encrypt("secret", key);
    const buf = Buffer.from(blob, "base64");
    const tagByte = buf[12] ?? 0;
    buf[12] = tagByte ^ 0xff;
    const tampered = buf.toString("base64");
    expect(() => decrypt(tampered, key)).toThrow(ValidPayError);
  });

  it("throws on a malformed (too-short) blob", () => {
    const key = generateKey();
    expect(() => decrypt("aGk=", key)).toThrow(ValidPayError);
  });

  it("throws on an invalid key length", () => {
    const shortKey = Buffer.from("short").toString("base64");
    expect(() => encrypt("hello", shortKey)).toThrow(ValidPayError);
  });
});

describe("commitmentHash", () => {
  it("returns SHA-256 hex of plaintext (64 chars)", () => {
    const h = commitmentHash("hello");
    expect(h).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    expect(h).toHaveLength(64);
  });

  it("is deterministic", () => {
    expect(commitmentHash("abc")).toBe(commitmentHash("abc"));
  });

  it("differs for different inputs", () => {
    expect(commitmentHash("a")).not.toBe(commitmentHash("b"));
  });
});

describe("splitKey / combineKeyShares", () => {
  it("round-trips a key through XOR shares", () => {
    const key = generateKey();
    const [a, b] = splitKey(key);
    expect(Buffer.from(a, "base64").length).toBe(32);
    expect(Buffer.from(b, "base64").length).toBe(32);
    expect(a).not.toBe(key);
    expect(b).not.toBe(key);
    expect(combineKeyShares(a, b)).toBe(key);
  });

  it("each share alone reveals no key bits (different from original)", () => {
    const key = generateKey();
    const [a, b] = splitKey(key);
    expect(a).not.toBe(b);
    expect(a).not.toBe(key);
  });

  it("shares decrypt only when combined", () => {
    const key = generateKey();
    const blob = encrypt("secret payload", key);
    const [a, b] = splitKey(key);
    expect(() => decrypt(blob, a)).toThrow(ValidPayError);
    expect(() => decrypt(blob, b)).toThrow(ValidPayError);
    const reconstructed = combineKeyShares(a, b);
    expect(decrypt(blob, reconstructed)).toBe("secret payload");
  });
});

describe("selective disclosure helpers", () => {
  it("encryptFields produces per-field independent ciphertexts", () => {
    const payload = { amount: 1500, payee: "Alice", memo: "rent" };
    const { encryptedFields, fieldKeys } = encryptFields(payload);
    expect(Object.keys(encryptedFields).sort()).toEqual(["amount", "memo", "payee"]);
    expect(Object.keys(fieldKeys).sort()).toEqual(["amount", "memo", "payee"]);
    expect(fieldKeys.amount).not.toBe(fieldKeys.payee);
  });

  it("buildKeyMap adds a 'full' role with all keys", () => {
    const fieldKeys = { a: generateKey(), b: generateKey(), c: generateKey() };
    const map = buildKeyMap(fieldKeys, { bank: ["a"], auditor: ["a", "b"] });
    expect(Object.keys(map.bank!).sort()).toEqual(["a"]);
    expect(Object.keys(map.auditor!).sort()).toEqual(["a", "b"]);
    expect(Object.keys(map.full!).sort()).toEqual(["a", "b", "c"]);
  });

  it("decryptFields redacts fields without keys", () => {
    const payload = { amount: 1500, payee: "Alice", memo: "rent" };
    const { encryptedFields, fieldKeys } = encryptFields(payload);
    const partial = { amount: fieldKeys.amount! };
    const result = decryptFields(encryptedFields, partial);
    expect(result).toEqual({
      amount: 1500,
      payee: "[REDACTED]",
      memo: "[REDACTED]",
    });
  });

  it("decryptFields fully decrypts with all keys", () => {
    const payload = { amount: 1500, payee: "Alice" };
    const { encryptedFields, fieldKeys } = encryptFields(payload);
    expect(decryptFields(encryptedFields, fieldKeys)).toEqual(payload);
  });
});
