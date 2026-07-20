/**
 * verifyIntent on seal-at-source v0.2 DOCUMENT seals: the decrypted payload
 * is the raw stamped file (a PDF), not JSON. The intent response advertises
 * file metadata (file_content_type / file_size_bytes) — verify must return a
 * document-shaped result instead of failing with invalid_payload. Field-
 * payload (JSON) verifies are regression-locked, and a genuinely broken
 * payload (non-JSON, NO file metadata) still fails invalid_payload.
 */
import { describe, it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import { ValidPayClient } from "../src/client.js";
import {
  commitmentHash,
  encrypt,
  encryptBytes,
  generateKey,
} from "../src/crypto.js";

const INTENT_ID = "vp_docverify123";

/** PDF-ish binary bytes: a %PDF header + bytes that are NOT valid UTF-8 JSON. */
function fakePdfBytes(): Buffer {
  return Buffer.concat([
    Buffer.from("%PDF-1.7\n", "utf8"),
    Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x81, 0x99, 0xc3, 0x28, 0x01, 0x02]),
    Buffer.from("\n%%EOF", "utf8"),
  ]);
}

function intentResponse(overrides: Record<string, unknown>): unknown {
  return {
    intent_id: INTENT_ID,
    issuer: "MD Motors",
    issuer_verified: false,
    registered_at: "2026-07-19T15:25:53.905Z",
    status: "active",
    document_type: "other",
    commitment_version: 2,
    encryption_version: 1,
    split_key: false,
    end_cell: false,
    selective_disclosure: false,
    valid_from: null,
    valid_until: null,
    ...overrides,
  };
}

function clientFor(body: unknown): ValidPayClient {
  const fetchMock = vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
  );
  return new ValidPayClient({
    apiKey: "test_key",
    baseUrl: "https://api.example.test",
    fetch: fetchMock as unknown as typeof fetch,
  });
}

describe("verifyIntent — document payloads (seal-at-source v0.2)", () => {
  it("returns a document-shaped result for a real seal_document-shaped intent", async () => {
    const key = generateKey();
    const pdf = fakePdfBytes();
    const ciphertext = encryptBytes(pdf, key);
    const client = clientFor(
      intentResponse({
        encrypted_payload: ciphertext,
        commitment_hash: commitmentHash(ciphertext),
        // The live document-seal shape (vp_lm0fqvitp3zt / vp_8vw5lin43xu0):
        file_content_type: "application/pdf",
        file_size_bytes: pdf.length,
      }),
    );

    const result = await client.verifyIntent(INTENT_ID, key);

    expect(result.payloadKind).toBe("document");
    expect(result.integrityVerified).toBe(true);
    expect(result.document).toEqual({
      contentType: "application/pdf",
      byteSize: pdf.length,
      declaredByteSize: pdf.length,
      sha256: createHash("sha256").update(pdf).digest("hex"),
    });
    // Untyped callers get the same facts through payload (snake_case).
    expect(result.payload).toEqual({
      payload_kind: "document",
      content_type: "application/pdf",
      byte_size: pdf.length,
      sha256: createHash("sha256").update(pdf).digest("hex"),
    });
  });

  it("detects via metadata even when file_size_bytes is the only file field", async () => {
    const key = generateKey();
    const pdf = fakePdfBytes();
    const ciphertext = encryptBytes(pdf, key);
    const client = clientFor(
      intentResponse({
        encrypted_payload: ciphertext,
        commitment_hash: commitmentHash(ciphertext),
        file_size_bytes: pdf.length,
      }),
    );
    const result = await client.verifyIntent(INTENT_ID, key);
    expect(result.payloadKind).toBe("document");
    expect(result.document!.contentType).toBeNull();
    expect(result.document!.byteSize).toBe(pdf.length);
  });

  it("REGRESSION: JSON field payloads still parse exactly as before", async () => {
    const key = generateKey();
    const payload = { amount: "1500.00", payee: "Jane Doe" };
    const ciphertext = encrypt(JSON.stringify(payload), key);
    const client = clientFor(
      intentResponse({
        encrypted_payload: ciphertext,
        commitment_hash: commitmentHash(ciphertext),
      }),
    );
    const result = await client.verifyIntent<typeof payload>(INTENT_ID, key);
    expect(result.payloadKind).toBe("json");
    expect(result.payload).toEqual(payload);
    expect(result.document).toBeUndefined();
    expect(result.integrityVerified).toBe(true);
  });

  it("JSON payloads WITH file metadata still parse as JSON (file envelope shape)", async () => {
    const key = generateKey();
    const payload = { file_name: "a.pdf", sha256: "ab" };
    const ciphertext = encrypt(JSON.stringify(payload), key);
    const client = clientFor(
      intentResponse({
        encrypted_payload: ciphertext,
        commitment_hash: commitmentHash(ciphertext),
        file_content_type: "application/pdf",
        file_size_bytes: 123,
      }),
    );
    const result = await client.verifyIntent(INTENT_ID, key);
    expect(result.payloadKind).toBe("json");
    expect(result.payload).toEqual(payload);
  });

  it("a genuinely non-JSON, non-document payload still fails invalid_payload", async () => {
    const key = generateKey();
    const ciphertext = encryptBytes(Buffer.from([0x00, 0xff, 0x80, 0x81]), key);
    const client = clientFor(
      intentResponse({
        encrypted_payload: ciphertext,
        commitment_hash: commitmentHash(ciphertext),
        // NO file metadata.
      }),
    );
    await expect(client.verifyIntent(INTENT_ID, key)).rejects.toMatchObject({
      code: "invalid_payload",
    });
  });
});
