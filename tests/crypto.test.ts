import { describe, it, expect } from "vitest";
import { generateKey, encrypt, decrypt } from "../src/crypto.js";
import { ValidPayError } from "../src/types.js";

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
