/**
 * Logo-aware grow-to-fit through the REAL seal + embed path (Prompt 159).
 *
 * qrcode is NOT mocked here: sealDocument stamps a real branded/plain QR as PDF
 * vector art, and each case rasterizes the sealed page with pdf.js and decodes
 * it with jsQR back to the EXACT verify URL — the decode-proof Mike asked for:
 *
 *   • roomy page  → grows to a branded QR (KeyHalve mark) that STILL scans;
 *   • cramped page → shrinks to the largest PLAIN QR that fits, still scans;
 *   • a 2-page doc with different room per page → per-page divergence;
 *   • a caller-explicit size overrides auto sizing.
 *
 * The API is mocked (reserve/commit); all crypto + stamping is real.
 */
import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib";
import { ValidPayClient } from "../src/client.js";

const INTENT_ID = "vp_growseal01234567";
const QR_MAC = "Ab3dEf5h9kLm";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockClient() {
  const fetchMock = async (url: unknown) => {
    const u = String(url);
    if (u.endsWith("/v1/intent/reserve")) {
      return jsonResponse(201, { intent_id: INTENT_ID, qr_mac: QR_MAC });
    }
    if (u.endsWith("/v1/intent/commit")) {
      return jsonResponse(201, { retrieval_id: INTENT_ID, status: "active" });
    }
    throw new Error(`unexpected fetch: ${u}`);
  };
  return new ValidPayClient({
    apiKey: "test_key",
    baseUrl: "https://api.example.test",
    fetch: fetchMock as unknown as typeof fetch,
  });
}

async function blankPdf(sizes: Array<[number, number]>): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  for (const [w, h] of sizes) doc.addPage([w, h]);
  return doc.save();
}

/** Rasterize a page region (top-left-origin pt) and decode any QR in it. */
async function decodeRegion(
  pdf: Uint8Array,
  pageNum: number,
  xPt: number,
  yTopPt: number,
  sizePt: number,
  scale: number,
): Promise<string | null> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const { createCanvas } = await import("@napi-rs/canvas");
  const doc = await pdfjs.getDocument({ data: new Uint8Array(pdf) }).promise;
  const page = await doc.getPage(pageNum);
  const viewport = page.getViewport({ scale });
  const cw = Math.ceil(viewport.width);
  const ch = Math.ceil(viewport.height);
  const canvas = createCanvas(cw, ch);
  const ctx = canvas.getContext("2d");
  await page.render({
    canvasContext: ctx as unknown as CanvasRenderingContext2D,
    viewport,
  }).promise;
  const jsQRmod = (await import("jsqr")) as unknown as {
    default: (d: Uint8ClampedArray, w: number, h: number) => { data: string } | null;
  };
  const jsQR = jsQRmod.default;
  const read = (im: { data: Uint8ClampedArray; width: number; height: number }) =>
    jsQR(im.data as unknown as Uint8ClampedArray, im.width, im.height);

  // Crop the QR (plus a quiet margin), clamped to the rendered page bounds.
  const pad = Math.round(10 * scale);
  const sx = Math.max(0, Math.round(xPt * scale) - pad);
  const sy = Math.max(0, Math.round(yTopPt * scale) - pad);
  const sw = Math.min(cw - sx, Math.round(sizePt * scale) + 2 * pad);
  const sh = Math.min(ch - sy, Math.round(sizePt * scale) + 2 * pad);
  let decoded = read(ctx.getImageData(sx, sy, sw, sh));
  // Fallback for small QRs that hug the page edge (little quiet zone left in
  // the clamped crop): decode the full rendered page, whose margins give the
  // decoder ample surrounding light. Robust across renderers/runners.
  if (!decoded) decoded = read(ctx.getImageData(0, 0, cw, ch));
  await doc.destroy();
  return decoded ? decoded.data : null;
}

describe("sealDocument auto grow-to-fit (real embed + decode)", () => {
  it("ROOMY page → branded QR (grew to 1.5in) that decodes to the exact verify URL", async () => {
    const client = mockClient();
    const result = await client.sealDocument({
      file: await blankPdf([[612, 792]]),
      documentType: "invoice",
      placement: "auto",
    });

    const d = result.autoPlacement![0]!;
    expect(d.widthPt).toBe(108); // grew to the ceiling on the clear page
    expect(d.branded).toBe(true);
    expect(d.logoFit).toBe(true);
    expect(result.brandedQr.branded).toBe(true);

    // The branded, grown QR STILL scans back to the exact URL.
    const decoded = await decodeRegion(result.sealedPdf, 1, d.x, d.y, d.widthPt, 4);
    expect(decoded).toBe(result.verifyUrl);
  });

  it("CRAMPED page → largest PLAIN QR that fits, and it still decodes", async () => {
    const client = mockClient();
    // A 90x90pt page can't host a >=74pt branded QR (margins leave 72pt),
    // so grow-to-fit falls to the biggest plain QR that fits.
    const result = await client.sealDocument({
      file: await blankPdf([[90, 90]]),
      documentType: "receipt",
      placement: "auto",
    });

    const d = result.autoPlacement![0]!;
    expect(d.branded).toBe(false);
    expect(d.shrunk).toBe(true);
    expect(d.fallback).toBe(false);
    expect(d.widthPt).toBeGreaterThanOrEqual(54);
    expect(d.widthPt).toBeLessThan(74);
    expect(result.brandedQr.branded).toBe(false);

    const decoded = await decodeRegion(result.sealedPdf, 1, d.x, d.y, d.widthPt, 10);
    expect(decoded).toBe(result.verifyUrl);
  });

  it("PER-PAGE DIVERGENCE: a roomy page and a cramped page in one doc get different sizes/branding", async () => {
    const client = mockClient();
    const result = await client.sealDocument({
      file: await blankPdf([[612, 792], [90, 90]]),
      documentType: "contract",
      placement: "auto",
      allPages: true,
    });

    expect(result.autoPlacement).toHaveLength(2);
    const [p1, p2] = result.autoPlacement!;
    // Page 1 (roomy) → branded & big; page 2 (cramped) → plain & small.
    expect(p1!.branded).toBe(true);
    expect(p1!.widthPt).toBe(108);
    expect(p2!.branded).toBe(false);
    expect(p2!.widthPt).toBeLessThan(74);

    // Each page's branded verdict agrees with its printed pitch.
    expect(p1!.modulePitchMm! >= 0.4).toBe(true);
    expect(p2!.modulePitchMm! < 0.4).toBe(true);

    // Both pages' QRs decode to their own page-tagged URLs.
    const url1 = result.pageVerifyUrls!.find((e) => e.page === 1)!.url;
    const url2 = result.pageVerifyUrls!.find((e) => e.page === 2)!.url;
    expect(await decodeRegion(result.sealedPdf, 1, p1!.x, p1!.y, p1!.widthPt, 4)).toBe(url1);
    expect(await decodeRegion(result.sealedPdf, 2, p2!.x, p2!.y, p2!.widthPt, 10)).toBe(url2);
  });

  it("caller-explicit auto size (qrWidthPt) OVERRIDES grow-to-fit", async () => {
    const client = mockClient();
    const result = await client.sealDocument({
      file: await blankPdf([[612, 792]]),
      documentType: "invoice",
      placement: { mode: "auto", qrWidthPt: 60 }, // pinned small → legacy path
    });
    const d = result.autoPlacement![0]!;
    expect(d.widthPt).toBe(60); // honored, not grown to 108
    expect(d.branded).toBeUndefined(); // legacy fixed-size path
    expect(result.brandedQr.branded).toBe(false); // 60pt < logo target → plain
  });

  it("caller-explicit MANUAL placement wins entirely (no auto decision)", async () => {
    const client = mockClient();
    const result = await client.sealDocument({
      file: await blankPdf([[612, 792]]),
      documentType: "invoice",
      placement: { anchor: "top-left", x: 20, y: 20, width: 120 },
    });
    expect(result.autoPlacement).toBeUndefined();
    expect(result.brandedQr.branded).toBe(true); // 120pt is comfortably branded
    const decoded = await decodeRegion(result.sealedPdf, 1, 20, 20, 120, 4);
    expect(decoded).toBe(result.verifyUrl);
  });
});
