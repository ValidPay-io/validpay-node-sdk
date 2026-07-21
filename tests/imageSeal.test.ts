/**
 * End-to-end: sealing an IMAGE runs the SAME reserve→stamp→encrypt→commit
 * pipeline as a PDF and yields a normal sealed PDF whose stamped QR SCANS.
 *
 *   - PNG → sealed PDF, JPEG → sealed PDF: the sealed page is rasterized with
 *     pdf.js and decoded with jsQR back to the exact verify URL (the same proof
 *     the branded-QR tests use).
 *   - The commit records file_content_type application/pdf and a single page —
 *     verify / KeyHalve see a normal sealed PDF, no changes needed.
 *   - Transit-only: no filesystem writes during an image seal.
 *   - Quota is consumed once (exactly one reserve + one commit).
 */
import { describe, it, expect, vi } from "vitest";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import sharp from "sharp";
import { PDFDocument } from "pdf-lib";
import { ValidPayClient } from "../src/client.js";

const INTENT_ID = "vp_imgseal0001";
const QR_MAC = "Img9SealMac12";
const RESERVE_VERIFICATION_URL = `https://verify.keyhalve.com/verify/${INTENT_ID}?t=validpay&m=${QR_MAC}`;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockApi() {
  let reserveCount = 0;
  let commitCount = 0;
  const fetchMock = vi.fn(async (url: unknown) => {
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
      return jsonResponse(201, {
        retrieval_id: INTENT_ID,
        status: "active",
        verification_url: RESERVE_VERIFICATION_URL,
      });
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

async function makeImage(fmt: "png" | "jpeg", width: number, height: number): Promise<Uint8Array> {
  const base = sharp({
    create: { width, height, channels: 3, background: { r: 210, g: 214, b: 220 } },
  });
  const buf = fmt === "png" ? await base.png().toBuffer() : await base.jpeg().toBuffer();
  return new Uint8Array(buf);
}

/** Rasterize the whole sealed page and let jsQR find the stamped QR anywhere. */
async function decodeSealedQr(pdf: Uint8Array, scale = 4): Promise<string | null> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const { createCanvas } = await import("@napi-rs/canvas");
  const { default: jsQR } = await import("jsqr");
  const doc = await pdfjs.getDocument({ data: new Uint8Array(pdf) }).promise;
  const page = await doc.getPage(1);
  const viewport = page.getViewport({ scale });
  const canvas = createCanvas(Math.ceil(viewport.width), Math.ceil(viewport.height));
  const ctx = canvas.getContext("2d");
  await page.render({
    canvasContext: ctx as unknown as CanvasRenderingContext2D,
    viewport,
  }).promise;
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  await doc.destroy();
  const decoded = jsQR(img.data as unknown as Uint8ClampedArray, img.width, img.height);
  return decoded ? decoded.data : null;
}

describe("sealDocument accepts an image → sealed PDF that scans", () => {
  it.each(["png", "jpeg"] as const)(
    "%s in → the sealed artifact is a 1-page PDF whose stamped QR decodes to the verify URL",
    async (fmt) => {
      const { client, commitBody, reserves, commits } = mockApi();
      const image = await makeImage(fmt, 1000, 1300);

      const result = await client.sealDocument({
        file: image,
        documentType: "invoice",
        // A comfortably scannable placement so the raster round-trip is robust.
        placement: { anchor: "bottom-right", x: 0.5, y: 0.5, width: 1.5, units: "in" },
      });

      // A normal sealed PDF: single page, recorded as application/pdf.
      const sealedDoc = await PDFDocument.load(new Uint8Array(result.sealedPdf));
      expect(sealedDoc.getPageCount()).toBe(1);
      const body = commitBody();
      expect(body["file_content_type"]).toBe("application/pdf");
      expect((body["metadata"] as Record<string, unknown>)["page_count"]).toBe(1);

      // Exactly one reserve + one commit — quota consumed ONCE.
      expect(reserves()).toBe(1);
      expect(commits()).toBe(1);

      // THE property: the stamped QR scans back to the exact verify URL.
      const decoded = await decodeSealedQr(result.sealedPdf);
      expect(decoded).toBe(result.verifyUrl);
    },
  );

  it("preserves aspect ratio on a wide (landscape) image and still seals to one page", async () => {
    const { client } = mockApi();
    const image = await makeImage("png", 1600, 600);
    const result = await client.sealDocument({ file: image, documentType: "receipt" });
    const doc = await PDFDocument.load(new Uint8Array(result.sealedPdf));
    expect(doc.getPageCount()).toBe(1);
    const { width, height } = doc.getPage(0).getSize();
    expect(width / height).toBeCloseTo(1600 / 600, 2);
  });

  it("seals an image with ZERO filesystem writes (transit-only / blindness)", async () => {
    const { client } = mockApi();
    const image = await makeImage("png", 900, 900);
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
      await client.sealDocument({
        file: image,
        documentType: "invoice",
        placement: { anchor: "bottom-right", x: 0.5, y: 0.5, width: 1.2, units: "in" },
      });
      for (const { n, spy } of spies) {
        expect(spy, `fs.${n} was called during an image seal`).not.toHaveBeenCalled();
      }
    } finally {
      for (const { spy } of spies) spy.mockRestore();
    }
  });

  it("rejects an unsupported type (HEIC) BEFORE reserving anything", async () => {
    const { client, fetchMock } = mockApi();
    const heic = Buffer.from([
      0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63,
    ]);
    await expect(
      client.sealDocument({ file: heic, documentType: "invoice" }),
    ).rejects.toMatchObject({ code: "unsupported_file_type" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
