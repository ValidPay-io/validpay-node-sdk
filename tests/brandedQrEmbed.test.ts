/**
 * Branded QR through the REAL embed path: embedQr draws the verify QR as PDF
 * vector art (modules + KeyHalve mark per the Prompt 158 contract), so these
 * tests prove the two things that matter:
 *
 *   1. the mark actually appears (SVG contract path + rendered-pixel checks),
 *   2. the branded QR still SCANS — the sealed PDF's page is rasterized with
 *      pdf.js and decoded with jsQR back to the exact verify URL. The mark
 *      must never cost scannability.
 */
import { PDFDocument } from "pdf-lib";
import { describe, expect, it } from "vitest";
import { buildVerifyUrl, embedQr, renderBrandedQrSvg } from "../src/pdf.js";

const W = 612;
const H = 792;

const URL_TYPICAL = buildVerifyUrl(
  "vp_0123456789abcdefghij",
  Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
  { tenant: "validpay", qrMac: "AbCdEfGh1234" },
);

async function blankPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.addPage([W, H]);
  return doc.save();
}

/** Rasterize page 1 of a PDF with pdf.js (via @napi-rs/canvas) and return
 *  RGBA pixels of the given page-point rectangle (plus padding). */
async function renderRegion(
  pdf: Uint8Array,
  x0Pt: number,
  y0TopPt: number,
  sizePt: number,
  scale: number,
): Promise<{ data: Uint8ClampedArray; width: number; height: number; pad: number }> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const { createCanvas } = await import("@napi-rs/canvas");
  const doc = await pdfjs.getDocument({ data: pdf.slice() }).promise;
  const page = await doc.getPage(1);
  const viewport = page.getViewport({ scale });
  const canvas = createCanvas(Math.ceil(viewport.width), Math.ceil(viewport.height));
  const ctx = canvas.getContext("2d");
  await page.render({
    canvasContext: ctx as unknown as CanvasRenderingContext2D,
    viewport,
  }).promise;
  const pad = Math.round(8 * scale); // quiet space around the crop for the decoder
  const img = ctx.getImageData(
    Math.round(x0Pt * scale) - pad,
    Math.round(y0TopPt * scale) - pad,
    Math.round(sizePt * scale) + 2 * pad,
    Math.round(sizePt * scale) + 2 * pad,
  );
  await doc.destroy();
  return {
    data: img.data as unknown as Uint8ClampedArray,
    width: img.width,
    height: img.height,
    pad,
  };
}

function pixelAt(
  img: { data: Uint8ClampedArray; width: number },
  x: number,
  y: number,
): [number, number, number] {
  const i = (Math.round(y) * img.width + Math.round(x)) * 4;
  return [img.data[i]!, img.data[i + 1]!, img.data[i + 2]!];
}

const isLight = (p: [number, number, number]) => p[0] > 200 && p[1] > 200 && p[2] > 200;
const isDark = (p: [number, number, number]) => p[0] < 80 && p[1] < 80 && p[2] < 80;

describe("renderBrandedQrSvg (contract SVG path)", () => {
  it("large placement → EC-H with the KeyHalve mark group", async () => {
    const { svg, branding } = await renderBrandedQrSvg(URL_TYPICAL, 144);
    expect(branding.branded).toBe(true);
    expect(branding.errorCorrectionLevel).toBe("H");
    expect(svg).toContain("<circle");
    expect(svg).toContain("<rect");
  });

  it("small placement → plain EC-M, no mark", async () => {
    const { svg, branding } = await renderBrandedQrSvg(URL_TYPICAL, 40);
    expect(branding.branded).toBe(false);
    expect(branding.errorCorrectionLevel).toBe("M");
    expect(svg).not.toContain("<circle");
  });

  it("an explicit non-H EC override opts out of the mark", async () => {
    const { svg, branding } = await renderBrandedQrSvg(URL_TYPICAL, 144, {
      errorCorrectionLevel: "Q",
    });
    expect(branding.branded).toBe(false);
    expect(branding.errorCorrectionLevel).toBe("Q");
    expect(svg).not.toContain("<circle");
  });

  it("a custom quiet zone opts out of the mark (contract margin only)", async () => {
    const { branding } = await renderBrandedQrSvg(URL_TYPICAL, 144, { margin: 4 });
    expect(branding.branded).toBe(false);
  });
});

describe("embedQr → rasterize → decode round-trip", () => {
  it("BRANDED: a 2in stamp carries the visible mark AND still decodes to the exact URL", async () => {
    const size = 144; // 2in — comfortably above the mark threshold
    const x = 36;
    const yTop = 36;
    const out = await embedQr(await blankPdf(), {
      retrievalId: "vp_0123456789abcdefghij",
      key: Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
      placement: { anchor: "top-left", x, y: yTop, width: size },
      tenant: "validpay",
      qrMac: "AbCdEfGh1234",
    });

    const scale = 4;
    const img = await renderRegion(out, x, yTop, size, scale);

    // Scannability — THE critical property: jsQR must read the branded QR
    // back to the exact verify URL.
    const { default: jsQR } = await import("jsqr");
    const decoded = jsQR(img.data, img.width, img.height);
    expect(decoded).not.toBeNull();
    expect(decoded!.data).toBe(URL_TYPICAL);

    // Mark visibility in the RENDERED pixels: the paper disc flanks the
    // center left/right; the ink split line runs vertically through it.
    const c = img.pad + (size / 2) * scale;
    const discOffset = size * 0.125 * 0.5 * scale; // half the disc radius
    expect(isLight(pixelAt(img, c - discOffset, c))).toBe(true);
    expect(isLight(pixelAt(img, c + discOffset, c))).toBe(true);
    expect(isDark(pixelAt(img, c, c - discOffset))).toBe(true);
    expect(isDark(pixelAt(img, c, c + discOffset))).toBe(true);
  });

  it("PLAIN: a small stamp stays mark-free and decodes to the exact URL", async () => {
    const size = 40; // ~0.56in — below the mark threshold
    const x = 200;
    const yTop = 300;
    const out = await embedQr(await blankPdf(), {
      retrievalId: "vp_0123456789abcdefghij",
      key: Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
      placement: { anchor: "top-left", x, y: yTop, width: size },
      tenant: "validpay",
      qrMac: "AbCdEfGh1234",
    });

    const img = await renderRegion(out, x, yTop, size, 8);
    const { default: jsQR } = await import("jsqr");
    const decoded = jsQR(img.data, img.width, img.height);
    expect(decoded).not.toBeNull();
    expect(decoded!.data).toBe(URL_TYPICAL);
  });
});
