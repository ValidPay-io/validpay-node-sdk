/**
 * Sidecar-certificate seal for NON-stampable files (Office docs, arbitrary
 * binaries). The ORIGINAL bytes are encrypted + committed as-is; a SEPARATE
 * certificate PDF carries the branded verify QR. Proves:
 *
 *   - routing: a .docx/.xlsx/unknown binary → sealMode "sidecar" (a PDF stays
 *     "stamped");
 *   - the stored ciphertext decrypts (ShareA from the certificate QR + the two
 *     committed pieces) back to the EXACT original bytes, and its sha256
 *     fingerprint matches the original the receiver holds;
 *   - the certificate QR scans (jsQR) to the exact verify URL;
 *   - the certificate renders issuer / date / file / disclosed-field text;
 *   - the original bytes are provably unchanged; quota consumed once; NO fs
 *     writes (transit-only).
 */
import { createHash } from "node:crypto";
import { describe, it, expect, vi } from "vitest";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import { PDFDocument } from "pdf-lib";
import { ValidPayClient } from "../src/client.js";
import { combineKeyPieces, decryptBytes } from "../src/crypto.js";

const INTENT_ID = "vp_sidecar00001";
const QR_MAC = "SideCarMac123";
const RESERVE_VERIFICATION_URL = `https://verify.keyhalve.com/verify/${INTENT_ID}?t=validpay&m=${QR_MAC}`;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function mockApi() {
  let reserveCount = 0;
  let commitCount = 0;
  const fetchMock = vi.fn(async (url: unknown, _init?: unknown) => {
    const u = String(url);
    if (u.endsWith("/v1/intent/reserve")) {
      reserveCount += 1;
      return jsonResponse(201, {
        intent_id: INTENT_ID,
        qr_mac: QR_MAC,
        verification_url: RESERVE_VERIFICATION_URL,
        expires_at: "2026-07-21T00:00:00.000Z",
      });
    }
    if (u.endsWith("/v1/intent/commit")) {
      commitCount += 1;
      return jsonResponse(201, { retrieval_id: INTENT_ID, status: "active", verification_url: RESERVE_VERIFICATION_URL });
    }
    throw new Error(`unexpected fetch: ${u}`);
  });
  const client = new ValidPayClient({
    apiKey: "test_key",
    baseUrl: "https://api.example.test",
    fetch: fetchMock as unknown as typeof fetch,
  });
  const commitBody = () => {
    const call = fetchMock.mock.calls.find(([u]) => String(u).endsWith("/v1/intent/commit"));
    return JSON.parse((call![1] as RequestInit).body as string);
  };
  return { client, fetchMock, commitBody, reserves: () => reserveCount, commits: () => commitCount };
}

/** A byte blob that detects as an Office/ZIP (docx/xlsx) — PK\x03\x04 header +
 *  arbitrary trailing bytes. */
function fakeOffice(seed: number, len = 4096): Uint8Array {
  const b = new Uint8Array(len);
  b.set([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]); // PK.. local file header
  for (let i = 8; i < len; i++) b[i] = (i * 31 + seed) & 0xff;
  return b;
}

function shareAFromVerifyUrl(verifyUrl: string): string {
  const frag = verifyUrl.split("#key=")[1]!;
  const b64 = frag.replace(/-/g, "+").replace(/_/g, "/");
  return b64 + "===".slice((b64.length + 3) % 4);
}

async function decodeCertQr(pdf: Uint8Array): Promise<string | null> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const { createCanvas } = await import("@napi-rs/canvas");
  const { default: jsQR } = await import("jsqr");
  const doc = await pdfjs.getDocument({ data: new Uint8Array(pdf) }).promise;
  const page = await doc.getPage(1);
  const viewport = page.getViewport({ scale: 4 });
  const canvas = createCanvas(Math.ceil(viewport.width), Math.ceil(viewport.height));
  const ctx = canvas.getContext("2d");
  await page.render({ canvasContext: ctx as unknown as CanvasRenderingContext2D, viewport }).promise;
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  await doc.destroy();
  const decoded = jsQR(img.data as unknown as Uint8ClampedArray, img.width, img.height);
  return decoded ? decoded.data : null;
}

async function certText(pdf: Uint8Array): Promise<string> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const doc = await pdfjs.getDocument({ data: new Uint8Array(pdf) }).promise;
  const page = await doc.getPage(1);
  const content = await page.getTextContent();
  const text = content.items.map((i) => ("str" in i ? i.str : "")).join(" ");
  await doc.destroy();
  return text;
}

describe("sidecar-certificate seal (non-stampable originals)", () => {
  it.each([
    ["report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ["books.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  ])(
    "seals %s: original encrypted as-is, certificate QR decrypts back to the exact original",
    async (fileName, expectedType) => {
      const { client, commitBody, reserves, commits } = mockApi();
      const original = fakeOffice(fileName.length);

      const result = await client.sealDocument({
        file: original,
        documentType: "contract",
        fileName,
        issuerName: "MD Motors",
        fields: { reference: "DOC-77", notes: "quarterly filing" },
      });

      // Routing + two-artifact output.
      expect(result.sealMode).toBe("sidecar");
      expect(result.originalFile).toBeInstanceOf(Buffer);
      expect(Buffer.compare(result.originalFile!, Buffer.from(original))).toBe(0); // UNCHANGED
      expect(result.originalContentType).toBe(expectedType);

      // The certificate is a real single-page PDF (the QR carrier).
      const certDoc = await PDFDocument.load(new Uint8Array(result.sealedPdf));
      expect(certDoc.getPageCount()).toBe(1);

      // Quota consumed ONCE (one reserve + one commit) — not per artifact.
      expect(reserves()).toBe(1);
      expect(commits()).toBe(1);

      // Commit records the ORIGINAL, not the certificate.
      const body = commitBody();
      expect(body["file_content_type"]).toBe(expectedType);
      expect(body["file_original_name"]).toBe(fileName);
      expect(body["file_size_bytes"]).toBe(original.length);
      expect(body["end_cell"]).toBe(true);
      expect((body["metadata"] as Record<string, unknown>)["sealed_as"]).toBe("certificate");

      // Verify flow (UNCHANGED core): ShareA from the QR + the two committed
      // pieces reconstruct the key; decrypting the stored ciphertext yields the
      // EXACT original bytes, and the fingerprint matches the original.
      const shareA = shareAFromVerifyUrl(result.verifyUrl);
      const pieces = body["pieces"] as Array<{ holder: string; piece: string }>;
      const fullKey = combineKeyPieces(shareA, pieces.map((p) => p.piece));
      const decrypted = decryptBytes(body["encrypted_file_b64"] as string, fullKey);
      expect(Buffer.compare(decrypted, Buffer.from(original))).toBe(0);
      expect(createHash("sha256").update(decrypted).digest("hex")).toBe(
        createHash("sha256").update(original).digest("hex"),
      );

      // The certificate's QR scans back to the exact verify URL.
      expect(await decodeCertQr(result.sealedPdf)).toBe(result.verifyUrl);

      // The certificate shows the human-readable summary.
      const text = await certText(result.sealedPdf);
      expect(text).toContain("SEALED CERTIFICATE");
      expect(text).toContain(fileName);
      expect(text).toContain("MD Motors");
      expect(text).toContain("DOC-77");
      expect(text).toMatch(/SCAN TO VERIFY/i);
    },
  );

  it("an unknown binary is sealed via sidecar as application/octet-stream", async () => {
    const { client, commitBody } = mockApi();
    const bin = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x42, 0x99, 0x10]);
    const result = await client.sealDocument({ file: bin, documentType: "record", fileName: "blob.bin" });
    expect(result.sealMode).toBe("sidecar");
    expect(commitBody()["file_content_type"]).toBe("application/octet-stream");
  });

  it("a PDF still seals in STAMPED mode (regression: sidecar is additive)", async () => {
    const { client, commitBody } = mockApi();
    const doc = await PDFDocument.create();
    doc.addPage([612, 792]);
    const pdf = await doc.save();
    const result = await client.sealDocument({ file: pdf, documentType: "invoice" });
    expect(result.sealMode).toBe("stamped");
    expect(result.originalFile).toBeUndefined();
    expect(commitBody()["file_content_type"]).toBe("application/pdf");
  });

  it("seals a .docx via sidecar with ZERO filesystem writes (transit-only)", async () => {
    const { client } = mockApi();
    const targets: Array<[object, string]> = [
      [fs, "writeFile"],
      [fs, "writeFileSync"],
      [fs, "appendFileSync"],
      [fs, "createWriteStream"],
      [fs, "mkdtemp"],
      [fs, "mkdtempSync"],
      [fs, "mkdir"],
      [fs, "mkdirSync"],
      [fsPromises, "writeFile"],
      [fsPromises, "mkdtemp"],
    ];
    const spies = targets.map(([o, n]) => ({ n, spy: vi.spyOn(o as never, n as never) }));
    try {
      await client.sealDocument({ file: fakeOffice(7), documentType: "contract", fileName: "x.docx" });
      for (const { n, spy } of spies) {
        expect(spy, `fs.${n} was called during a sidecar seal`).not.toHaveBeenCalled();
      }
    } finally {
      for (const { spy } of spies) spy.mockRestore();
    }
  });
});
