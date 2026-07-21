/**
 * Image → single-page PDF normalization (imageInput.ts).
 *
 * Proves: magic-byte detection ignores the extension; PNG/JPEG embed with ZERO
 * extra deps; WebP/TIFF/GIF go through the sharp peer; HEIC/Office/unknown
 * reject with a clear (non-crashing) error; a PDF passes through byte-identical;
 * and page geometry preserves aspect ratio inside a sane envelope.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import sharp from "sharp";
import { PDFDocument } from "pdf-lib";
import {
  detectInputType,
  describeInputType,
  normalizeToPdf,
  pageSizeForImage,
} from "../src/imageInput.js";
import { ValidPayError } from "../src/types.js";

/** A solid-color test image in the requested format, with known px dims. */
async function makeImage(
  fmt: "png" | "jpeg" | "webp" | "tiff" | "gif",
  width = 800,
  height = 1000,
): Promise<Uint8Array> {
  const base = sharp({
    create: { width, height, channels: 3, background: { r: 180, g: 190, b: 200 } },
  });
  const buf =
    fmt === "png"
      ? await base.png().toBuffer()
      : fmt === "jpeg"
        ? await base.jpeg().toBuffer()
        : fmt === "webp"
          ? await base.webp().toBuffer()
          : fmt === "tiff"
            ? await base.tiff().toBuffer()
            : await base.gif().toBuffer();
  return new Uint8Array(buf);
}

async function blankPdf(w = 612, h = 792): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.addPage([w, h]);
  return doc.save();
}

describe("detectInputType (magic bytes, never the extension)", () => {
  it("recognizes each supported container by its leading bytes", async () => {
    expect(detectInputType(await blankPdf())).toBe("pdf");
    expect(detectInputType(await makeImage("png"))).toBe("png");
    expect(detectInputType(await makeImage("jpeg"))).toBe("jpeg");
    expect(detectInputType(await makeImage("webp"))).toBe("webp");
    expect(detectInputType(await makeImage("tiff"))).toBe("tiff");
    expect(detectInputType(await makeImage("gif"))).toBe("gif");
  });

  it("classifies a PDF with a leading preamble as pdf (spec tolerance)", () => {
    const pdf = new Uint8Array([0x0a, 0x20, 0x25, 0x50, 0x44, 0x46, 0x2d, 0x31]); // \n %PDF-1
    expect(detectInputType(pdf)).toBe("pdf");
  });

  it("flags HEIC (ftyp box) and Office/ZIP and unknown separately", () => {
    const heic = new Uint8Array([
      0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63,
    ]); // ....ftypheic
    expect(detectInputType(heic)).toBe("heic");
    const docx = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]); // PK..
    expect(detectInputType(docx)).toBe("office-zip");
    expect(detectInputType(new Uint8Array([1, 2, 3, 4, 5]))).toBe("unknown");
  });

  it("goes by CONTENT: PNG bytes labeled .pdf are still png; PDF bytes labeled .jpg are still pdf", async () => {
    // The detector only sees bytes — there is no filename to mislead it.
    const png = await makeImage("png");
    expect(detectInputType(png)).toBe("png");
    const pdf = await blankPdf();
    expect(detectInputType(pdf)).toBe("pdf");
  });
});

describe("pageSizeForImage (aspect ratio inside a sane envelope)", () => {
  it("preserves aspect ratio", () => {
    const s = pageSizeForImage(1000, 500);
    expect(s.width / s.height).toBeCloseTo(2, 5);
  });

  it("scales a huge photo DOWN so the long side stays bounded (≤ 14in)", () => {
    const s = pageSizeForImage(6000, 4000);
    expect(Math.max(s.width, s.height)).toBeLessThanOrEqual(1008 + 0.01);
    expect(s.width / s.height).toBeCloseTo(1.5, 5);
  });

  it("scales a tiny icon UP so a 1in QR still fits", () => {
    const s = pageSizeForImage(120, 120);
    expect(Math.min(s.width, s.height)).toBeGreaterThanOrEqual(288 - 0.01);
  });

  it("an extreme banner keeps its short side ≥ 4in (aspect preserved, long side grows)", () => {
    const s = pageSizeForImage(6000, 300);
    expect(Math.min(s.width, s.height)).toBeGreaterThanOrEqual(288 - 0.01);
    expect(s.width / s.height).toBeCloseTo(20, 4);
  });
});

describe("normalizeToPdf", () => {
  it("returns PDF bytes UNCHANGED (byte-identical passthrough)", async () => {
    const pdf = await blankPdf();
    const out = await normalizeToPdf(pdf);
    expect(out).toBe(pdf); // same reference — untouched path
  });

  it.each(["png", "jpeg"] as const)(
    "embeds a %s as a valid single-page PDF with ZERO extra deps",
    async (fmt) => {
      const img = await makeImage(fmt, 800, 1000);
      const out = await normalizeToPdf(img);
      const doc = await PDFDocument.load(out);
      expect(doc.getPageCount()).toBe(1);
      const { width, height } = doc.getPage(0).getSize();
      expect(width / height).toBeCloseTo(0.8, 3); // 800/1000
    },
  );

  it.each(["webp", "tiff", "gif"] as const)(
    "transcodes a %s through sharp into a valid single-page PDF",
    async (fmt) => {
      const img = await makeImage(fmt, 900, 600);
      const out = await normalizeToPdf(img);
      const doc = await PDFDocument.load(out);
      expect(doc.getPageCount()).toBe(1);
      expect(doc.getPage(0).getSize().width / doc.getPage(0).getSize().height).toBeCloseTo(1.5, 2);
    },
  );

  it("rejects HEIC with a clear, non-crashing error naming the supported types", async () => {
    const heic = new Uint8Array([
      0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63,
    ]);
    await expect(normalizeToPdf(heic)).rejects.toMatchObject({ code: "unsupported_file_type" });
    await expect(normalizeToPdf(heic)).rejects.toThrow(/HEIC/i);
  });

  it("rejects an Office/ZIP document with a convert-to-PDF hint", async () => {
    const docx = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]);
    const err = await normalizeToPdf(docx).catch((e) => e);
    expect(err).toBeInstanceOf(ValidPayError);
    expect((err as ValidPayError).code).toBe("unsupported_file_type");
    expect((err as ValidPayError).message).toMatch(/convert it to PDF/i);
  });

  it("rejects unrecognized bytes with the supported-types list (mentions PDF)", async () => {
    await expect(normalizeToPdf(new Uint8Array([1, 2, 3, 4, 5, 6]))).rejects.toThrow(/PDF/);
  });

  it("rejects empty input", async () => {
    await expect(normalizeToPdf(new Uint8Array(0))).rejects.toMatchObject({
      code: "invalid_argument",
    });
  });

  it("writes NO temp files while normalizing an image (transit-only)", async () => {
    const targets: Array<[object, string]> = [
      [fs, "writeFile"],
      [fs, "writeFileSync"],
      [fs, "createWriteStream"],
      [fs, "mkdtemp"],
      [fs, "mkdtempSync"],
      [fsPromises, "writeFile"],
      [fsPromises, "mkdtemp"],
    ];
    const spies = targets.map(([o, n]) => vi.spyOn(o as never, n as never));
    try {
      await normalizeToPdf(await makeImage("png"));
      await normalizeToPdf(await makeImage("webp")); // sharp path too
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});

describe("describeInputType", () => {
  it("gives human labels", () => {
    expect(describeInputType("png")).toBe("PNG image");
    expect(describeInputType("pdf")).toBe("PDF");
    expect(describeInputType("webp")).toBe("WebP image");
  });
});
