import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { ValidPayClient } from "../src/client.js";
import {
  decrypt,
  encrypt,
  generateKey,
  commitmentHash,
  buildAad,
  splitKey,
  combineKeyShares,
  splitKeyPieces,
  encryptFields,
  buildKeyMap,
} from "../src/crypto.js";
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

  it("createIntent encrypts client-side, posts to /v1/intent, sends commitment hash, never sends key", async () => {
    // Since 0.4.0 createIntent defaults to split-key: result.key is Share A,
    // Share B travels to the server, and neither the full key nor the
    // plaintext ever appears on the wire.
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
    expect(typeof sentBody.commitment_hash).toBe("string");
    // C-1: commitment is over the ciphertext, not the plaintext.
    expect(sentBody.commitment_hash).toBe(commitmentHash(sentBody.encrypted_payload));
    expect(sentBody.commitment_hash).not.toBe(commitmentHash(JSON.stringify(payload)));
    expect(sentBody.split_key).toBe(true);
    expect(typeof sentBody.key_fragment_b).toBe("string");
    // M-5: AAD-bound, declared as encryption_version 2.
    expect(sentBody.encryption_version).toBe(2);

    // CRITICAL: Share A (the returned key) must never appear in the
    // request body, URL, or headers
    const fullCall = JSON.stringify({ url: calledUrl, init });
    expect(fullCall).not.toContain(result.key);
    expect(fullCall).not.toContain("123-45-6789");
    expect(fullCall).not.toContain("Jane Doe");

    // Share A (returned) XOR Share B (sent) reconstructs the full key —
    // which itself never appears on the wire — and decrypts the payload.
    const fullKey = combineKeyShares(result.key, sentBody.key_fragment_b);
    expect(fullCall).not.toContain(fullKey);
    // M-5: the blob is AAD-bound, so pass the same AAD the create call used.
    const decrypted = JSON.parse(
      decrypt(sentBody.encrypted_payload, fullKey, buildAad("ssn_card")),
    );
    expect(decrypted).toEqual(payload);
  });

  it("createIntent with splitKey:false is the legacy single-key flow", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_legacy1", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "test_key",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const payload = { amount: "100.00" };
    const result = await client.createIntent({
      documentType: "check",
      payload,
      splitKey: false,
    });

    const sentBody = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
    expect(sentBody.split_key).toBeUndefined();
    expect(sentBody.key_fragment_b).toBeUndefined();
    // M-5: createIntent binds AAD even for the legacy single-key flow.
    const decrypted = JSON.parse(
      decrypt(sentBody.encrypted_payload, result.key, buildAad("check")),
    );
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
    const fetchMock = vi.fn(async () => jsonResponse(401, { error: "unauthorized" }));
    const client = new ValidPayClient({
      apiKey: "bad",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(
      client.createIntent({ documentType: "t", payload: {} }),
    ).rejects.toMatchObject({ name: "ValidPayError", code: "unauthorized", status: 401 });
  });

  it("createIntent sends valid_from / valid_until when provided", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_t", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await client.createIntent({
      documentType: "check",
      payload: { a: 1 },
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-12-31T23:59:59Z",
    });
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.valid_from).toBe("2026-01-01T00:00:00Z");
    expect(body.valid_until).toBe("2026-12-31T23:59:59Z");
  });

  it("createIntent sends on_behalf_of for platform delegation", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_d", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await client.createIntent({
      documentType: "lease",
      payload: { a: 1 },
      onBehalfOf: { ref: "cust_42", name: "Smith Properties" },
    });
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.on_behalf_of).toEqual({ ref: "cust_42", name: "Smith Properties" });
  });

  it("verifyIntent surfaces verificationLevel + delegatedBy for a delegated issuer", async () => {
    const key = generateKey();
    const blob = encrypt(JSON.stringify({ a: 1 }), key);
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_d",
        encrypted_payload: blob,
        issuer: "Smith Properties",
        issuer_verified: false,
        registered_at: "2026-04-29T12:00:00.000Z",
        status: "active",
        verification_level: "delegated",
        delegated_by: { platform: "Acme Platform", platform_level: "domain" },
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await client.verifyIntent("vp_d", key);
    expect(result.verificationLevel).toBe("delegated");
    expect(result.delegatedBy).toEqual({
      platform: "Acme Platform",
      platformLevel: "domain",
    });
  });

  it("createIntent rejects when validFrom >= validUntil", async () => {
    const client = new ValidPayClient({ apiKey: "k" });
    await expect(
      client.createIntent({
        documentType: "x",
        payload: {},
        validFrom: "2026-12-01T00:00:00Z",
        validUntil: "2026-01-01T00:00:00Z",
      }),
    ).rejects.toThrow(ValidPayError);
  });

  it("verifyIntent fetches /v1/intent/:id without auth, decrypts, returns shape with integrityVerified", async () => {
    const key = generateKey();
    const plaintext = JSON.stringify({ ssn: "111-22-3333" });
    const blob = encrypt(plaintext, key);
    // C-1: commitment v2 over the ciphertext, response carries the version.
    const commitment = commitmentHash(blob);

    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_id_1",
        encrypted_payload: blob,
        commitment_hash: commitment,
        commitment_version: 2,
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

    const result = await client.verifyIntent<{ ssn: string }>("vp_id_1", key);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [verifyUrl, verifyInit] = fetchMock.mock.calls[0]!;
    expect(verifyUrl).toBe("https://api.example.test/v1/intent/vp_id_1");
    const init = verifyInit as RequestInit;
    expect(init.method).toBe("GET");
    const headers = (init.headers ?? {}) as Record<string, string>;
    expect(headers["Authorization"]).toBeUndefined();
    expect(JSON.stringify({ verifyUrl, init })).not.toContain(key);

    expect(result).toEqual({
      intentId: "vp_id_1",
      payload: { ssn: "111-22-3333" },
      issuer: "Acme Bank",
      issuerVerified: true,
      registeredAt: "2026-04-29T12:00:00.000Z",
      status: "active",
      integrityVerified: true,
      validFrom: null,
      validUntil: null,
      timeLockStatus: null,
      delegatedBy: null,
    });
  });

  it("verifyIntent returns integrityVerified=false when server omits commitment_hash (legacy)", async () => {
    const key = generateKey();
    const blob = encrypt(JSON.stringify({ a: 1 }), key);

    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_legacy",
        encrypted_payload: blob,
        issuer: "Legacy",
        issuer_verified: false,
        registered_at: "2026-01-01T00:00:00Z",
        status: "active",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const result = await client.verifyIntent("vp_legacy", key);
    expect(result.integrityVerified).toBe(false);
    expect(result.payload).toEqual({ a: 1 });
  });

  it("verifyIntent raises integrity_failure when commitment hash mismatches", async () => {
    const key = generateKey();
    const blob = encrypt(JSON.stringify({ real: "value" }), key);

    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_x",
        encrypted_payload: blob,
        commitment_hash: "deadbeef".repeat(8),
        commitment_version: 2,
        issuer: "X",
        issuer_verified: true,
        registered_at: "2026-01-01T00:00:00Z",
        status: "active",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(client.verifyIntent("vp_x", key)).rejects.toMatchObject({
      name: "ValidPayError",
      code: "integrity_failure",
    });
  });

  it("verifyIntent throws when given the wrong key", async () => {
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

  it("verifyIntent rejects revoked intents", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_r",
        encrypted_payload: null,
        issuer: "x",
        issuer_verified: true,
        registered_at: "2026-01-01T00:00:00Z",
        status: "revoked",
        revocation_reason: "stop payment",
        revoked_at: "2026-02-02T00:00:00Z",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(client.verifyIntent("vp_r", "a".repeat(44))).rejects.toMatchObject({
      name: "ValidPayError",
      code: "intent_revoked",
    });
  });

  it("verifyIntent transparently verifies a split-key intent (key = Share A)", async () => {
    // Since 0.4.0 the natural createIntent -> verifyIntent round trip
    // works on split-key intents: verifyIntent fetches Share B from the
    // fragment endpoint and XOR-combines it with the Share A it was given.
    const fullKey = generateKey();
    const [shareA, shareB] = splitKey(fullKey);
    const payload = { a: 1 };
    const blob = encrypt(JSON.stringify(payload), fullKey);
    const fetchMock = vi.fn(async (url: string) => {
      if (String(url).endsWith("/fragment")) {
        return jsonResponse(200, { intent_id: "vp_sk", fragment_b: shareB });
      }
      return jsonResponse(200, {
        intent_id: "vp_sk",
        encrypted_payload: blob,
        issuer: "x",
        issuer_verified: true,
        registered_at: "2026-01-01T00:00:00Z",
        status: "active",
        split_key: true,
        // C-1: commitment v2 over the ciphertext.
        commitment_hash: commitmentHash(blob),
        commitment_version: 2,
      });
    });
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await client.verifyIntent("vp_sk", shareA);
    expect(result.payload).toEqual(payload);
    expect(result.integrityVerified).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1]![0])).toBe(
      "https://api.example.test/v1/intent/vp_sk/fragment",
    );
  });

  it("verifyIntent and createIntent require their arguments", async () => {
    const client = new ValidPayClient({ apiKey: "k" });
    await expect(client.verifyIntent("", "k")).rejects.toThrow(ValidPayError);
    await expect(client.verifyIntent("id", "")).rejects.toThrow(ValidPayError);
    await expect(client.createIntent({ documentType: "", payload: {} })).rejects.toThrow(
      ValidPayError,
    );
  });

  it("createIntentBatch encrypts each item with its own key", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, {
        results: [
          { retrieval_id: "vp_a", status: "active" },
          { retrieval_id: "vp_b", status: "active" },
        ],
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const results = await client.createIntentBatch([
      { documentType: "check", payload: { x: 1 } },
      { documentType: "check", payload: { x: 2 } },
    ]);
    expect(results).toHaveLength(2);
    expect(results[0]!.retrievalId).toBe("vp_a");
    expect(results[1]!.retrievalId).toBe("vp_b");
    expect(results[0]!.key).not.toBe(results[1]!.key);

    const sent = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
    expect(sent.intents).toHaveLength(2);
    expect(typeof sent.intents[0].commitment_hash).toBe("string");
  });

  it("createIntentBatch rejects 0 or >100 items", async () => {
    const client = new ValidPayClient({ apiKey: "k" });
    await expect(client.createIntentBatch([])).rejects.toThrow(ValidPayError);
    const tooMany = Array.from({ length: 101 }, () => ({
      documentType: "x",
      payload: {},
    }));
    await expect(client.createIntentBatch(tooMany)).rejects.toThrow(ValidPayError);
  });

  it("createSplitKeyIntent sends share B to API, returns share A as key", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_split", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const r = await client.createSplitKeyIntent({
      documentType: "ssn_card",
      payload: { ssn: "111-22-3333" },
    });
    expect(r.retrievalId).toBe("vp_split");
    expect(Buffer.from(r.key, "base64").length).toBe(32);

    const sent = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
    expect(sent.split_key).toBe(true);
    expect(typeof sent.key_fragment_b).toBe("string");
    expect(Buffer.from(sent.key_fragment_b, "base64").length).toBe(32);
    expect(sent.key_fragment_b).not.toBe(r.key);
  });

  it("verifySplitKeyIntent fetches fragment, combines shares, decrypts", async () => {
    // Set up: encrypt a payload with a full key, split it.
    const fullKey = generateKey();
    const plaintext = JSON.stringify({ ssn: "555-44-3322" });
    const blob = encrypt(plaintext, fullKey);
    const commitment = commitmentHash(blob); // C-1: over ciphertext
    const [shareA, shareB] = splitKey(fullKey);

    let callCount = 0;
    const fetchMock = vi.fn(async (url: string) => {
      callCount++;
      if (callCount === 1) {
        // First call: GET /v1/intent/:id
        expect(url).toContain("/v1/intent/vp_sk1");
        expect(url).not.toContain("/fragment");
        return jsonResponse(200, {
          intent_id: "vp_sk1",
          encrypted_payload: blob,
          commitment_hash: commitment,
          commitment_version: 2,
          issuer: "Bank",
          issuer_verified: true,
          registered_at: "2026-01-01T00:00:00Z",
          status: "active",
        });
      }
      // Second call: /fragment
      expect(url).toContain("/v1/intent/vp_sk1/fragment");
      return jsonResponse(200, { fragment_b: shareB });
    });

    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await client.verifySplitKeyIntent("vp_sk1", shareA);
    expect(result.payload).toEqual({ ssn: "555-44-3322" });
    expect(result.integrityVerified).toBe(true);
  });

  it("createSelectiveIntent encrypts each field with its own key", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { retrieval_id: "vp_sel", status: "active" }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const r = await client.createSelectiveIntent({
      documentType: "check",
      payload: { amount: 1500, payee: "Alice", memo: "rent" },
      disclosurePolicy: {
        bank: ["amount"],
        auditor: ["amount", "payee"],
      },
    });
    expect(r.retrievalId).toBe("vp_sel");
    const sent = JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
    expect(sent.selective_disclosure).toBe(true);
    expect(typeof sent.encrypted_key_map).toBe("string");
    const envelope = JSON.parse(sent.encrypted_payload);
    expect(Object.keys(envelope).sort()).toEqual(["amount", "memo", "payee"]);
    // each field independently encrypted (different IVs → different ciphertexts even for same value)
    expect(envelope.amount).not.toBe(envelope.payee);
  });

  it("verifySelectiveIntent returns only authorized fields, REDACTED for others", async () => {
    const masterKey = generateKey();
    const payload = { amount: 1500, payee: "Alice", memo: "rent" };
    const { encryptedFields, fieldKeys } = encryptFields(payload);
    const keyMap = buildKeyMap(fieldKeys, { bank: ["amount"] });
    const encryptedKeyMap = encrypt(JSON.stringify(keyMap), masterKey);
    const envelope = JSON.stringify(encryptedFields);
    // C-1: commitment v2 over the ciphertext envelope.
    const envelopeCommitment = commitmentHash(envelope);

    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_sel",
        encrypted_payload: envelope,
        commitment_hash: envelopeCommitment,
        commitment_version: 2,
        issuer: "Issuer",
        issuer_verified: true,
        registered_at: "2026-01-01T00:00:00Z",
        status: "active",
        selective_disclosure: true,
        encrypted_key_map: encryptedKeyMap,
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const bankResult = await client.verifySelectiveIntent("vp_sel", masterKey, "bank");
    expect(bankResult.payload).toEqual({
      amount: 1500,
      payee: "[REDACTED]",
      memo: "[REDACTED]",
    });

    // Reset call count for second verify
    fetchMock.mockClear();
    fetchMock.mockImplementation(async () =>
      jsonResponse(200, {
        intent_id: "vp_sel",
        encrypted_payload: envelope,
        commitment_hash: envelopeCommitment,
        commitment_version: 2,
        issuer: "Issuer",
        issuer_verified: true,
        registered_at: "2026-01-01T00:00:00Z",
        status: "active",
        selective_disclosure: true,
        encrypted_key_map: encryptedKeyMap,
      }),
    );
    const fullResult = await client.verifySelectiveIntent("vp_sel", masterKey, "full");
    expect(fullResult.payload).toEqual(payload);
    expect(fullResult.integrityVerified).toBe(true);
  });

  it("revokeIntent PATCHes the revoke endpoint with reason", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_r",
        status: "revoked",
        revoked_at: "2026-05-01T00:00:00Z",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const r = await client.revokeIntent("vp_r", "stop payment");
    expect(r).toEqual({
      intentId: "vp_r",
      status: "revoked",
      revokedAt: "2026-05-01T00:00:00Z",
    });
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({ reason: "stop payment" });
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer k");
  });

  it("reinstateIntent PATCHes the reinstate endpoint", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        intent_id: "vp_r",
        status: "active",
        reinstated_at: "2026-05-02T00:00:00Z",
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const r = await client.reinstateIntent("vp_r");
    expect(r.status).toBe("active");
    expect(r.reinstatedAt).toBe("2026-05-02T00:00:00Z");
  });

  it("getRevocationHistory returns mapped event list", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        events: [
          {
            id: "rev_1",
            action: "revoked",
            reason: "stop payment",
            performed_at: "2026-05-01T00:00:00Z",
          },
          {
            id: "rev_2",
            action: "reinstated",
            performed_at: "2026-05-02T00:00:00Z",
          },
        ],
      }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const history = await client.getRevocationHistory("vp_r");
    expect(history).toHaveLength(2);
    expect(history[0]).toEqual({
      id: "rev_1",
      action: "revoked",
      reason: "stop payment",
      performedAt: "2026-05-01T00:00:00Z",
    });
    expect(history[1]!.action).toBe("reinstated");
  });

  it("health hits /health without auth", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, { status: "ok", version: "1.2.3" }),
    );
    const client = new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const h = await client.health();
    expect(h).toEqual({ status: "ok", version: "1.2.3" });
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>)["Authorization"]).toBeUndefined();
  });
});

// ── Anti-fake QR MAC (?m=) forwarding through verifyIntent (End-Cell).
//    The verify URL's `m` must reach the rail piece request; MAC verdicts must
//    surface as their own fail-closed codes, never as network/rail errors. ──
describe("ValidPayClient — verifyIntent anti-fake QR MAC (qrMac)", () => {
  function endCellWorld() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const spkiB64 = (publicKey.export({ format: "der", type: "spki" }) as Buffer).toString(
      "base64",
    );
    const fullKey = generateKey();
    // holders: ["keyhalve", "platform"] → [ShareA, railPiece, platformPiece]
    const [shareA, railPiece, platformPiece] = splitKeyPieces(fullKey, 2) as [
      string,
      string,
      string,
    ];
    const payload = { invoice: 42 };
    const blob = encrypt(JSON.stringify(payload), fullKey);
    const railSig = nodeSign(
      null,
      Buffer.from(`keyhalve-rail.v1\nvp_mac\nkeyhalve\n${railPiece}`, "utf8"),
      privateKey,
    ).toString("base64");
    return { spkiB64, shareA, railPiece, platformPiece, payload, blob, railSig };
  }

  function makeFetch(w: ReturnType<typeof endCellWorld>, railHandler?: (url: string) => Response) {
    return vi.fn(async (url: string) => {
      const u = String(url);
      if (u.includes("rail.example.test")) {
        if (railHandler) return railHandler(u);
        return jsonResponse(200, {
          intent_id: "vp_mac",
          holder: "keyhalve",
          piece: w.railPiece,
          sig: w.railSig,
          alg: "ed25519",
        });
      }
      if (u.endsWith("/fragment")) {
        return jsonResponse(200, {
          intent_id: "vp_mac",
          end_cell: true,
          holders: ["platform"],
          pieces: { platform: w.platformPiece },
        });
      }
      return jsonResponse(200, {
        intent_id: "vp_mac",
        encrypted_payload: w.blob,
        issuer: "Acme",
        issuer_verified: true,
        registered_at: "2026-07-01T00:00:00Z",
        status: "active",
        end_cell: true,
        commitment_hash: commitmentHash(w.blob),
        commitment_version: 2,
      });
    });
  }

  function makeClient(w: ReturnType<typeof endCellWorld>, fetchMock: ReturnType<typeof makeFetch>) {
    return new ValidPayClient({
      apiKey: "k",
      baseUrl: "https://api.example.test",
      railBaseUrl: "https://rail.example.test",
      railPublicKeySpki: w.spkiB64,
      fetch: fetchMock as unknown as typeof fetch,
    });
  }

  it("forwards options.qrMac as ?m= on the rail piece request and verifies", async () => {
    const w = endCellWorld();
    const fetchMock = makeFetch(w);
    const client = makeClient(w, fetchMock);
    const result = await client.verifyIntent("vp_mac", w.shareA, { qrMac: "X6n5UyGi" });
    expect(result.payload).toEqual(w.payload);
    const railCall = fetchMock.mock.calls
      .map((c) => String(c[0]))
      .find((u) => u.includes("rail.example.test"));
    expect(railCall).toBe("https://rail.example.test/v1/piece/vp_mac?m=X6n5UyGi");
  });

  it("keeps the bare rail request (no ?m=) when no qrMac is given — legacy path unchanged", async () => {
    const w = endCellWorld();
    const fetchMock = makeFetch(w);
    const client = makeClient(w, fetchMock);
    const result = await client.verifyIntent("vp_mac", w.shareA);
    expect(result.payload).toEqual(w.payload);
    const railCall = fetchMock.mock.calls
      .map((c) => String(c[0]))
      .find((u) => u.includes("rail.example.test"));
    expect(railCall).toBe("https://rail.example.test/v1/piece/vp_mac");
  });

  it("surfaces rail 403 mac_invalid as qr_mac_invalid — a fraud verdict, not rail_error", async () => {
    const w = endCellWorld();
    const fetchMock = makeFetch(w, () => jsonResponse(403, { error: "mac_invalid" }));
    const client = makeClient(w, fetchMock);
    await expect(
      client.verifyIntent("vp_mac", w.shareA, { qrMac: "WrongMac1" }),
    ).rejects.toMatchObject({
      name: "ValidPayError",
      code: "qr_mac_invalid",
      message: expect.stringMatching(/fraudulent/i),
    });
  });

  it("surfaces rail 403 mac_required as qr_mac_required — actionable, not rail_error", async () => {
    const w = endCellWorld();
    const fetchMock = makeFetch(w, () => jsonResponse(403, { error: "mac_required" }));
    const client = makeClient(w, fetchMock);
    await expect(client.verifyIntent("vp_mac", w.shareA)).rejects.toMatchObject({
      name: "ValidPayError",
      code: "qr_mac_required",
      message: expect.stringMatching(/anti-fake code/i),
    });
  });

  it("rejects a malformed qrMac up front (invalid_argument) without any network call", async () => {
    const w = endCellWorld();
    const fetchMock = makeFetch(w);
    const client = makeClient(w, fetchMock);
    for (const qrMac of ["", "short", "has spaces!", "way-too-long-for-a-mac-value", "bad$chars"]) {
      await expect(client.verifyIntent("vp_mac", w.shareA, { qrMac })).rejects.toMatchObject({
        code: "invalid_argument",
      });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
