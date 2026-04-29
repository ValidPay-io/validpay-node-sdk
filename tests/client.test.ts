import { describe, it, expect, vi } from "vitest";
import { ValidPayClient } from "../src/client.js";
import { decrypt } from "../src/crypto.js";
import { ValidPayError } from "../src/types.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("ValidPayClient", () => {
  it("requires an apiKey", () => {
    expect(() => new ValidPayClient({ apiKey: "" })).toThrow(ValidPayError);
  });

  it("createIntent encrypts client-side, posts to /v1/intent, and never sends the key", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_abc123def456", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "test_key",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const payload = { ssn: "123-45-6789", name: "Jane Doe" };
    const result = await client.createIntent({ documentType: "ssn_card", payload });

    expect(result.retrievalId).toBe("vp_abc123def456");
    expect(typeof result.key).toBe("string");
    expect(Buffer.from(result.key, "base64").length).toBe(32);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0]!;
    expect(calledUrl).toBe("https://api.example.test/v1/intent");
    const init = calledInit as RequestInit;
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer test_key");
    expect(headers["Content-Type"]).toBe("application/json");

    const sentBody = JSON.parse(init.body as string);
    expect(sentBody.document_type).toBe("ssn_card");
    expect(typeof sentBody.encrypted_payload).toBe("string");

    // CRITICAL: key must never appear in the request body, URL, or headers
    const fullCall = JSON.stringify({ url: calledUrl, init });
    expect(fullCall).not.toContain(result.key);
    expect(fullCall).not.toContain("123-45-6789");
    expect(fullCall).not.toContain("Jane Doe");

    // And the encrypted_payload should actually decrypt back to the original
    const decrypted = JSON.parse(decrypt(sentBody.encrypted_payload, result.key));
    expect(decrypted).toEqual(payload);
  });

  it("createIntent strips a trailing slash from baseUrl", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_x", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test/",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await client.createIntent({ documentType: "t", payload: {} });
    expect(fetchMock.mock.calls[0]![0]).toBe("https://api.example.test/v1/intent");
  });

  it("createIntent throws ValidPayError on non-2xx", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(401, { error: "unauthorized" }),
    );
    const client = new ValidPayClient({
      apiKey: "bad",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(
      client.createIntent({ documentType: "t", payload: {} }),
    ).rejects.toMatchObject({ name: "ValidPayError", code: "unauthorized", status: 401 });
  });

  it("verifyIntent fetches /v1/intent/:id without auth, decrypts, and returns shape", async () => {
    // First, encrypt a payload as the API would have stored it.
    const { ValidPayClient: C } = await import("../src/client.js");
    const sender = new C({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: (async () =>
        jsonResponse(201, { retrieval_id: "vp_id_1", status: "active" })) as unknown as typeof fetch,
    });
    const created = await sender.createIntent({
      documentType: "ssn_card",
      payload: { ssn: "111-22-3333" },
    });

    // Re-encrypt deterministically by intercepting the actual blob from the create call body.
    // Simpler: just use the SDK's encrypt directly.
    const { encrypt } = await import("../src/crypto.js");
    const blob = encrypt(JSON.stringify({ ssn: "111-22-3333" }), created.key);

    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_id_1",
        encrypted_payload: blob,
        issuer: "Acme Bank",
        issuer_verified: true,
        registered_at: "2026-04-29T12:00:00.000Z",
        status: "active",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "unused",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const result = await client.verifyIntent<{ ssn: string }>("vp_id_1", created.key);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [verifyUrl, verifyInit] = fetchMock.mock.calls[0]!;
    expect(verifyUrl).toBe("https://api.example.test/v1/intent/vp_id_1");
    const init = verifyInit as RequestInit;
    expect(init.method).toBe("GET");
    const headers = (init.headers ?? {}) as Record<string, string>;
    // verifyIntent does NOT need authentication and the key must not be transmitted
    expect(headers["Authorization"]).toBeUndefined();
    expect(JSON.stringify({ verifyUrl, init })).not.toContain(created.key);

    expect(result).toEqual({
      intentId: "vp_id_1",
      payload: { ssn: "111-22-3333" },
      issuer: "Acme Bank",
      issuerVerified: true,
      registeredAt: "2026-04-29T12:00:00.000Z",
      status: "active",
    });
  });

  it("verifyIntent throws when given the wrong key", async () => {
    const { encrypt, generateKey } = await import("../src/crypto.js");
    const realKey = generateKey();
    const wrongKey = generateKey();
    const blob = encrypt(JSON.stringify({ a: 1 }), realKey);

    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_x",
        encrypted_payload: blob,
        issuer: "X",
        issuer_verified: true,
        registered_at: "2026-04-29T12:00:00.000Z",
        status: "active",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(client.verifyIntent("vp_x", wrongKey)).rejects.toMatchObject({
      name: "ValidPayError",
      code: "decryption_failed",
    });
  });

  it("verifyIntent surfaces 404 as ValidPayError", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(404, { error: "not_found" }));
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(client.verifyIntent("vp_missing", "a".repeat(44))).rejects.toMatchObject({
      name: "ValidPayError",
      code: "not_found",
      status: 404,
    });
  });

  it("verifyIntent and createIntent require their arguments", async () => {
    const client = new ValidPayClient({ apiKey: "k" });
    await expect(client.verifyIntent("", "k")).rejects.toThrow(ValidPayError);
    await expect(client.verifyIntent("id", "")).rejects.toThrow(ValidPayError);
    await expect(client.createIntent({ documentType: "", payload: {} })).rejects.toThrow(
      ValidPayError,
    );
  });
});
