import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PDFDocument } from "pdf-lib";
import { ValidPayClient } from "../src/client.js";
import { commitmentHash, combineKeyPieces, decryptBytes } from "../src/crypto.js";
import { ValidPayError } from "../src/types.js";

// US Letter, points.
const W = 612;
const H = 792;

const INTENT_ID = "vp_sealabc12345";
const QR_MAC = "X6n5UyGi";
const RESERVE_VERIFICATION_URL = `https://verify.keyhalve.com/verify/${INTENT_ID}?t=validpay&m=${QR_MAC}`;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function reserveResponse(): Response {
  return jsonResponse(201, {
    intent_id: INTENT_ID,
    qr_mac: QR_MAC,
    verification_url: RESERVE_VERIFICATION_URL,
    expires_at: "2026-07-20T18:00:00.000Z",
  });
}

function commitResponse(): Response {
  return jsonResponse(201, {
    retrieval_id: INTENT_ID,
    status: "active",
    qr_mac: QR_MAC,
    end_cell: true,
    verification_url: RESERVE_VERIFICATION_URL,
  });
}

/** Standard mock: reserve then commit, recording calls. */
function mockApi(overrides?: {
  onCommit?: (call: number) => Response | Promise<Response>;
}) {
  let commitCount = 0;
  const fetchMock = vi.fn(async (url: unknown, init?: unknown) => {
    const u = String(url);
    if (u.endsWith("/v1/intent/reserve")) return reserveResponse();
    if (u.endsWith("/v1/intent/commit")) {
      commitCount += 1;
      if (overrides?.onCommit) return overrides.onCommit(commitCount);
      return commitResponse();
    }
    throw new Error(`unexpected fetch: ${u}`);
  });
  const client = new ValidPayClient({
    apiKey: "test_key",
    baseUrl: "https://api.example.test",
    fetch: fetchMock as unknown as typeof fetch,
  });
  const bodiesFor = (suffix: string) =>
    fetchMock.mock.calls
      .filter(([u]) => String(u).endsWith(suffix))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string));
  return {
    fetchMock,
    client,
    commitBodies: () => bodiesFor("/v1/intent/commit"),
    reserveCalls: () =>
      fetchMock.mock.calls.filter(([u]) => String(u).endsWith("/v1/intent/reserve")).length,
    commitCalls: () => commitCount,
  };
}

async function blankPdf(pages = 1): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  for (let i = 0; i < pages; i++) doc.addPage([W, H]);
  return doc.save();
}

/** Extract ShareA from the verify URL's #key= fragment (base64url → base64). */
function shareAFromVerifyUrl(verifyUrl: string): string {
  const frag = verifyUrl.split("#key=")[1]!;
  const b64 = frag.replace(/-/g, "+").replace(/_/g, "/");
  return b64 + "===".slice((b64.length + 3) % 4);
}

describe("sealDocument — one-call reserve→stamp→encrypt→commit", () => {
  it("orchestrates the full flow: reserve auth'd, QR stamped, STAMPED bytes encrypted, commitment v2, End-Cell pieces, qr_placement recorded", async () => {
    const { client, fetchMock, commitBodies } = mockApi();
    const original = await blankPdf(1);

    const result = await client.sealDocument({
      file: original,
      documentType: "invoice",
      fields: {
        reference: "INV-1001",
        dateIssued: "2026-07-19",
        expirationDate: "2027-01-01",
        notes: "net 30",
        po_number: "PO-9",
      },
      validUntil: "2027-01-01T00:00:00Z",
    });

    // Reserve was called with the API key.
    const [reserveUrl, reserveInit] = fetchMock.mock.calls[0]!;
    expect(String(reserveUrl)).toBe("https://api.example.test/v1/intent/reserve");
    expect((reserveInit as RequestInit).method).toBe("POST");
    expect(
      ((reserveInit as RequestInit).headers as Record<string, string>)["Authorization"],
    ).toBe("Bearer test_key");

    // Result shape.
    expect(result.intentId).toBe(INTENT_ID);
    expect(result.qrMac).toBe(QR_MAC);
    expect(result.sealedPdf).toBeInstanceOf(Buffer);
    expect(result.verifyUrl).toBe(
      `https://verify.keyhalve.com/verify/${INTENT_ID}?t=validpay&m=${QR_MAC}#key=` +
        result.verifyUrl.split("#key=")[1],
    );
    expect(result.certificateUrl).toBe(
      `https://verify.keyhalve.com/certificate/${INTENT_ID}`,
    );
    expect(result.verificationUrl).toBe(RESERVE_VERIFICATION_URL);

    // The stamped artifact is a valid PDF, same page count, bigger (QR added),
    // and NOT the original bytes.
    const sealedDoc = await PDFDocument.load(new Uint8Array(result.sealedPdf));
    expect(sealedDoc.getPageCount()).toBe(1);
    expect(result.sealedPdf.length).toBeGreaterThan(original.length);

    // Commit body — the dashboard commitSchema shape.
    const [body] = commitBodies();
    expect(body!["intent_id"]).toBe(INTENT_ID);
    expect(body!["document_type"]).toBe("invoice");
    expect(body!["end_cell"]).toBe(true);
    expect(body!["split_key"]).toBeUndefined();
    expect(body!["issuer_certified"]).toBe(true);
    expect(body!["file_content_type"]).toBe("application/pdf");
    expect(body!["file_original_name"]).toBe("document-sealed.pdf");
    expect(body!["file_size_bytes"]).toBe(result.sealedPdf.length);
    expect(body!["valid_until"]).toBe("2027-01-01T00:00:00.000Z");

    // Field mapping: well-known keys top-level, the rest in metadata.
    expect(body!["reference"]).toBe("INV-1001");
    expect(body!["date_issued"]).toBe("2026-07-19");
    expect(body!["expiration_date"]).toBe("2027-01-01");
    expect(body!["notes"]).toBe("net 30");
    // page_count is always disclosed since smart-place/page-tags (P-loop):
    // verifiers pair it with the QR's &p= orientation tag.
    expect(body!["metadata"]).toEqual({ po_number: "PO-9", page_count: 1 });

    // End-Cell pieces: exactly one rail share + one platform share.
    const pieces = body!["pieces"] as Array<{ holder: string; piece: string }>;
    expect(pieces.map((p) => p.holder)).toEqual(["keyhalve", "platform"]);

    // qr_placement — default bottom-right 1.0in QR, 0.5in inset, wizard
    // center-percent convention on Letter: center = (540, 720 from top).
    const qp = body!["qr_placement"] as Record<string, number>;
    expect(qp["page"]).toBe(1);
    expect(qp["x"]).toBeCloseTo((540 / W) * 100, 6);
    expect(qp["y"]).toBeCloseTo((720 / H) * 100, 6);
    expect(qp["width"]).toBe(72);

    // Commitment v2 binds the STAMPED ciphertext.
    const ciphertext = body!["encrypted_file_b64"] as string;
    expect(body!["commitment_hash"]).toBe(commitmentHash(ciphertext));

    // ShareA (from the verify URL) + the two committed pieces reconstruct the
    // key; the decrypted ciphertext is EXACTLY the returned stamped artifact.
    const shareA = shareAFromVerifyUrl(result.verifyUrl);
    const fullKey = combineKeyPieces(
      shareA,
      pieces.map((p) => p.piece),
    );
    const decrypted = decryptBytes(ciphertext, fullKey);
    expect(Buffer.compare(decrypted, result.sealedPdf)).toBe(0);
    expect(Buffer.compare(decrypted, Buffer.from(original))).not.toBe(0);

    // Blindness: neither the full key nor ShareA ever hit the wire.
    const everything = JSON.stringify(fetchMock.mock.calls);
    expect(everything).not.toContain(fullKey);
    expect(everything).not.toContain(shareA);
  });

  it("placement variant: explicit top-left placement on page 2 is stamped and recorded on page 2", async () => {
    const { client, commitBodies } = mockApi();
    const original = await blankPdf(2);

    await client.sealDocument({
      file: original,
      documentType: "lease",
      placement: { anchor: "top-left", x: 10, y: 20, width: 100, page: 2 },
    });

    const [body] = commitBodies();
    const qp = body!["qr_placement"] as Record<string, number>;
    // rect: x=10, y(bottom)=792-20-100=672 → center (60, 70 from top).
    expect(qp["page"]).toBe(2);
    expect(qp["x"]).toBeCloseTo((60 / W) * 100, 6);
    expect(qp["y"]).toBeCloseTo((70 / H) * 100, 6);
    expect(qp["width"]).toBe(100);
  });

  it("placement variant: mm units convert through the shared contract", async () => {
    const { client, commitBodies } = mockApi();
    await client.sealDocument({
      file: await blankPdf(1),
      documentType: "invoice",
      placement: { anchor: "bottom-left", x: 25.4, y: 25.4, width: 25.4, units: "mm" },
    });
    const [body] = commitBodies();
    const qp = body!["qr_placement"] as Record<string, number>;
    // 25.4mm = 72pt: rect (72, 72, 72) → center (108, 792-108=684 from top).
    expect(qp["x"]).toBeCloseTo((108 / W) * 100, 4);
    expect(qp["y"]).toBeCloseTo((684 / H) * 100, 4);
    expect(qp["width"]).toBe(72);
  });

  it("allPages stamps every page and records page 1 as the canonical placement (wizard rule)", async () => {
    const { client: allClient, commitBodies: allBodies } = mockApi();
    const original = await blankPdf(3);

    const all = await allClient.sealDocument({
      file: original,
      documentType: "contract",
      allPages: true,
    });

    const [allBody] = allBodies();
    expect((allBody!["qr_placement"] as Record<string, number>)["page"]).toBe(1);
    const allDoc = await PDFDocument.load(new Uint8Array(all.sealedPdf));
    expect(allDoc.getPageCount()).toBe(3);

    // A single-page seal of the same document embeds ONE QR image; the
    // all-pages artifact embeds three, so it must be strictly larger.
    const { client: oneClient } = mockApi();
    const one = await oneClient.sealDocument({
      file: original,
      documentType: "contract",
    });
    expect(all.sealedPdf.length).toBeGreaterThan(one.sealedPdf.length);
  });

  it("reads the file from a path and derives <base>-sealed.pdf as the recorded name", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vp-sdk-seal-"));
    const path = join(dir, "rent-invoice.pdf");
    writeFileSync(path, await blankPdf(1));

    const { client, commitBodies } = mockApi();
    const result = await client.sealDocument({ file: path, documentType: "invoice" });

    expect(result.intentId).toBe(INTENT_ID);
    const [body] = commitBodies();
    expect(body!["file_original_name"]).toBe("rent-invoice-sealed.pdf");
  });

  it("rejects UNSUPPORTED types (Office docs, unknown bytes) with a clear convert-to-PDF error BEFORE any network call", async () => {
    const { client, fetchMock } = mockApi();
    // An Office/ZIP document (docx) → convert-to-PDF hint (images ARE now
    // accepted; see tests/imageSeal.test.ts — this guards the still-rejected
    // types).
    await expect(
      client.sealDocument({
        file: Buffer.from("PK\x03\x04 definitely a docx"),
        documentType: "invoice",
      }),
    ).rejects.toMatchObject({ code: "unsupported_file_type" });
    await expect(
      client.sealDocument({ file: Buffer.from("hello"), documentType: "invoice" }),
    ).rejects.toThrow(/PDF/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects validFrom (unsupported by the v0.2 commit contract) before any network call", async () => {
    const { client, fetchMock } = mockApi();
    await expect(
      client.sealDocument({
        file: await blankPdf(1),
        documentType: "invoice",
        validFrom: "2026-08-01T00:00:00Z",
      }),
    ).rejects.toMatchObject({ code: "invalid_argument" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an out-of-range placement.page before reserving", async () => {
    const { client, fetchMock } = mockApi();
    await expect(
      client.sealDocument({
        file: await blankPdf(1),
        documentType: "invoice",
        placement: { anchor: "top-left", x: 10, y: 10, width: 90, page: 5 },
      }),
    ).rejects.toMatchObject({ code: "invalid_argument" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("retries the commit ONCE on a network-shaped failure, then succeeds", async () => {
    let commitAttempts = 0;
    const { client, commitCalls } = mockApi({
      onCommit: (call) => {
        commitAttempts = call;
        if (call === 1) throw new TypeError("fetch failed: socket hang up");
        return commitResponse();
      },
    });

    const result = await client.sealDocument({
      file: await blankPdf(1),
      documentType: "invoice",
    });
    expect(result.intentId).toBe(INTENT_ID);
    expect(commitAttempts).toBe(2);
    expect(commitCalls()).toBe(2);
  });

  it("after the single retry also fails, surfaces the held reservation (id + qr_mac) in the error", async () => {
    const { client, commitCalls } = mockApi({
      onCommit: () => {
        throw new TypeError("fetch failed");
      },
    });

    let caught: unknown;
    try {
      await client.sealDocument({ file: await blankPdf(1), documentType: "invoice" });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ValidPayError);
    const err = caught as ValidPayError;
    expect(err.code).toBe("network_error");
    expect(err.message).toMatch(/reservation is still held/i);
    expect(err.details).toMatchObject({
      reservation_id: INTENT_ID,
      qr_mac: QR_MAC,
      reservation_still_held: true,
    });
    expect(commitCalls()).toBe(2); // exactly one automatic retry
  });

  it("does NOT retry non-network commit failures (e.g. reservation_expired) and marks the draft not held", async () => {
    const { client, commitCalls } = mockApi({
      onCommit: () =>
        jsonResponse(409, {
          error: "reservation_expired",
          message: "This reservation expired. Reserve again and re-stamp.",
        }),
    });

    let caught: unknown;
    try {
      await client.sealDocument({ file: await blankPdf(1), documentType: "invoice" });
    } catch (e) {
      caught = e;
    }
    const err = caught as ValidPayError;
    expect(err.code).toBe("reservation_expired");
    expect(err.message).not.toMatch(/still held/i);
    expect(err.details).toMatchObject({
      reservation_id: INTENT_ID,
      qr_mac: QR_MAC,
      reservation_still_held: false,
    });
    expect(commitCalls()).toBe(1); // no retry on contract errors
  });

  it("recovers a lost-response commit: network failure then already_committed on the retry = success", async () => {
    const { client, commitCalls } = mockApi({
      onCommit: (call) => {
        if (call === 1) throw new TypeError("fetch failed: response lost");
        return jsonResponse(409, {
          error: "already_committed",
          message: "This reservation was already committed.",
        });
      },
    });

    const result = await client.sealDocument({
      file: await blankPdf(1),
      documentType: "invoice",
    });
    expect(result.intentId).toBe(INTENT_ID);
    expect(result.verificationUrl).toBe(RESERVE_VERIFICATION_URL);
    expect(commitCalls()).toBe(2);
  });

  it("surfaces a rail_unavailable commit refusal with the reservation details (server keeps the draft held)", async () => {
    const { client } = mockApi({
      onCommit: () =>
        jsonResponse(502, {
          error: "rail_unavailable",
          message: "Could not store the rail share; the reservation is still held.",
        }),
    });

    let caught: unknown;
    try {
      await client.sealDocument({ file: await blankPdf(1), documentType: "invoice" });
    } catch (e) {
      caught = e;
    }
    const err = caught as ValidPayError;
    expect(err.code).toBe("rail_unavailable");
    expect(err.details).toMatchObject({
      reservation_id: INTENT_ID,
      qr_mac: QR_MAC,
      reservation_still_held: true,
    });
  });
});
