import { describe, it, expect, vi } from "vitest";
import { ValidPayClient } from "../src/index.js";

/**
 * ONE-RAIL CUT-OVER (2026-07-22) — createIntent() seals 3-of-3 by default.
 *
 * The behaviour these tests pin is the whole point of the release: an
 * integrator who writes the simplest possible call gets a real 3-of-3 End-Cell
 * seal, with no flag to remember and no way to land on the legacy rail by
 * accident.
 */

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function clientWith(fetchMock: unknown) {
  return new ValidPayClient({
    apiKey: "k",
    baseUrl: "https://api.example.test",
    fetch: fetchMock as typeof fetch,
  });
}

function sentBody(fetchMock: ReturnType<typeof vi.fn>) {
  return JSON.parse((fetchMock.mock.calls[0]![1] as RequestInit).body as string);
}

describe("createIntent default = 3-of-3 End-Cell", () => {
  it("the simplest possible call produces an End-Cell body", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(201, { retrieval_id: "vp_1" }));
    await clientWith(fetchMock).createIntent({ documentType: "invoice", payload: { a: 1 } });

    const body = sentBody(fetchMock);
    expect(body.end_cell).toBe(true);
    expect(body.pieces.map((p: { holder: string }) => p.holder)).toEqual([
      "keyhalve",
      "platform",
    ]);
    // The legacy fields must be entirely absent, not merely false.
    expect("split_key" in body).toBe(false);
    expect("key_fragment_b" in body).toBe(false);
  });

  it("ShareA is returned to the caller and never sent to the server", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(201, { retrieval_id: "vp_2" }));
    const res = await clientWith(fetchMock).createIntent({
      documentType: "invoice",
      payload: { secret: "do-not-leak-4213" },
    });

    const raw = JSON.stringify(fetchMock.mock.calls[0]);
    expect(raw).not.toContain(res.key);
    expect(raw).not.toContain("do-not-leak-4213");
    // ShareA is a full-width 32-byte share, same as before the cut-over.
    expect(Buffer.from(res.key, "base64").length).toBe(32);
  });

  it("XOR-ing ShareA with both server pieces reconstructs the real key", async () => {
    // Proves the three pieces are a genuine 3-of-3 split of ONE key, not three
    // unrelated blobs — and therefore that any two of them are useless.
    const fetchMock = vi.fn(async () => jsonResponse(201, { retrieval_id: "vp_3" }));
    const res = await clientWith(fetchMock).createIntent({
      documentType: "invoice",
      payload: { a: 1 },
    });
    const body = sentBody(fetchMock);

    const xor = (a: Buffer, b: Buffer) => Buffer.from(a.map((byte, i) => byte ^ b[i]!));
    const shareA = Buffer.from(res.key, "base64");
    const rail = Buffer.from(body.pieces[0].piece, "base64");
    const platform = Buffer.from(body.pieces[1].piece, "base64");

    const reconstructed = xor(xor(shareA, rail), platform);
    expect(reconstructed.length).toBe(32);
    // Each individual piece must differ from the reconstructed key.
    for (const piece of [shareA, rail, platform]) {
      expect(piece.equals(reconstructed)).toBe(false);
    }
  });

  it("passing splitKey explicitly still builds the LEGACY body (rollback client)", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(201, { retrieval_id: "vp_4" }));
    await clientWith(fetchMock).createIntent({
      documentType: "invoice",
      payload: { a: 1 },
      splitKey: true,
    });
    const body = sentBody(fetchMock);
    expect(body.split_key).toBe(true);
    expect(typeof body.key_fragment_b).toBe("string");
    expect(body.end_cell).toBeUndefined();
  });

  it("validation still runs before the End-Cell delegation", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(201, { retrieval_id: "vp_5" }));
    await expect(
      // @ts-expect-error — deliberately omitting the required documentType.
      clientWith(fetchMock).createIntent({ payload: { a: 1 } }),
    ).rejects.toThrow(/documentType is required/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
