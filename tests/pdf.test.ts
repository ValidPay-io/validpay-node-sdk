import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib";
import { buildVerifyUrl, resolveQrRect, embedQr } from "../src/pdf.js";
import { ValidPayError } from "../src/types.js";

// US Letter, points.
const W = 612;
const H = 792;

describe("buildVerifyUrl", () => {
  it("builds the canonical /verify URL with the key in the fragment", () => {
    expect(buildVerifyUrl("abc123", "deadbeef")).toBe(
      "https://verify.keyhalve.com/verify/abc123#key=deadbeef",
    );
  });

  it("honors a custom base and strips trailing slashes", () => {
    expect(buildVerifyUrl("id", "k", { baseUrl: "https://staging.validpay.com/" })).toBe(
      "https://staging.validpay.com/verify/id#key=k",
    );
  });

  it("url-encodes the retrieval id and base64url-encodes the fragment key", () => {
    // key "K+K/m==" → base64url "K-K_m"; retrieval id is percent-encoded.
    expect(buildVerifyUrl("a/b c", "K+K/m==")).toBe(
      "https://verify.keyhalve.com/verify/a%2Fb%20c#key=K-K_m",
    );
  });

  it("rejects missing args", () => {
    expect(() => buildVerifyUrl("", "k")).toThrow(ValidPayError);
    expect(() => buildVerifyUrl("id", "")).toThrow(ValidPayError);
  });
});

describe("resolveQrRect", () => {
  it("top-left anchor maps inset-from-top into pdf bottom-left y", () => {
    // 90pt QR, 400 from left, 50 from top → bottom = 792 - 50 - 90 = 652.
    expect(resolveQrRect({ anchor: "top-left", x: 400, y: 50, width: 90 }, W, H)).toEqual({
      x: 400,
      y: 652,
      size: 90,
    });
  });

  it("defaults to the top-left anchor and pt units", () => {
    expect(resolveQrRect({ x: 10, y: 20, width: 100 }, W, H)).toEqual({
      x: 10,
      y: H - 20 - 100,
      size: 100,
    });
  });

  it("bottom-right anchor insets from the bottom and right edges", () => {
    // 36 from right → x = 612 - 36 - 90 = 486; 36 from bottom → y = 36.
    expect(resolveQrRect({ anchor: "bottom-right", x: 36, y: 36, width: 90 }, W, H)).toEqual({
      x: 486,
      y: 36,
      size: 90,
    });
  });

  it("top-right and bottom-left anchors", () => {
    expect(resolveQrRect({ anchor: "top-right", x: 40, y: 40, width: 80 }, W, H)).toEqual({
      x: 612 - 40 - 80,
      y: 792 - 40 - 80,
      size: 80,
    });
    expect(resolveQrRect({ anchor: "bottom-left", x: 40, y: 40, width: 80 }, W, H)).toEqual({
      x: 40,
      y: 40,
      size: 80,
    });
  });

  it("converts mm and in to points", () => {
    const mm = resolveQrRect({ anchor: "top-left", x: 25.4, y: 0, width: 25.4, units: "mm" }, W, H);
    expect(mm.size).toBeCloseTo(72, 5);
    expect(mm.x).toBeCloseTo(72, 5);

    const inch = resolveQrRect({ anchor: "bottom-left", x: 1, y: 1, width: 1, units: "in" }, W, H);
    expect(inch).toEqual({ x: 72, y: 72, size: 72 });
  });
});

describe("embedQr", () => {
  async function blankPdf(pages = 1): Promise<Uint8Array> {
    const doc = await PDFDocument.create();
    for (let i = 0; i < pages; i++) doc.addPage([W, H]);
    return doc.save();
  }

  it("stamps a QR and returns a larger, still-valid PDF with the same page count", async () => {
    const original = await blankPdf(1);
    const out = await embedQr(original, {
      retrievalId: "abc123",
      key: "deadbeef",
      placement: { anchor: "bottom-right", x: 36, y: 36, width: 90 },
    });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBeGreaterThan(original.length);
    const reloaded = await PDFDocument.load(out);
    expect(reloaded.getPageCount()).toBe(1);
  });

  it("can target a specific page", async () => {
    const out = await embedQr(await blankPdf(3), {
      retrievalId: "id",
      key: "k",
      placement: { page: 2, anchor: "top-left", x: 50, y: 50, width: 100 },
    });
    expect((await PDFDocument.load(out)).getPageCount()).toBe(3);
  });

  it("rejects an out-of-range page", async () => {
    await expect(
      embedQr(await blankPdf(1), {
        retrievalId: "id",
        key: "k",
        placement: { page: 5, x: 10, y: 10, width: 50 },
      }),
    ).rejects.toThrow(/out of range/);
  });

  it("rejects placement that runs off the page", async () => {
    await expect(
      embedQr(await blankPdf(1), {
        retrievalId: "id",
        key: "k",
        placement: { anchor: "top-left", x: 600, y: 10, width: 100 }, // 600+100 > 612
      }),
    ).rejects.toThrow(/off the page/);
  });

  it("rejects empty input bytes", async () => {
    await expect(
      embedQr(new Uint8Array(), { retrievalId: "id", key: "k", placement: { x: 1, y: 1, width: 50 } }),
    ).rejects.toThrow(ValidPayError);
  });
});
