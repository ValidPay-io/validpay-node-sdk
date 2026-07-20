/**
 * sealDocument smart-place ("auto" placement) + page-tag (&p=) tests.
 *
 * qrcode is mocked so every stamped QR's URL is CAPTURED — that lets the
 * tests assert the exact URL each page's QR encodes (page tags included)
 * without decoding rasterized QR images.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { ValidPayClient } from "../src/client.js";
import { buildVerifyUrl } from "../src/pdf.js";
import { ValidPayError } from "../src/types.js";

// US Letter, points.
const W = 612;
const H = 792;

const INTENT_ID = "vp_autoseal1234";
const QR_MAC = "Ab3dEf5h";

/** 1x1 transparent PNG — a real decodable image for pdf-lib's embedPng. */
const TINY_PNG_DATA_URL =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";

const capturedQrUrls: string[] = [];
vi.mock("qrcode", () => ({
  default: {
    toDataURL: async (text: string) => {
      capturedQrUrls.push(text);
      return TINY_PNG_DATA_URL;
    },
  },
}));

beforeEach(() => {
  capturedQrUrls.length = 0;
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockApi() {
  const fetchMock = vi.fn(async (url: unknown) => {
    const u = String(url);
    if (u.endsWith("/v1/intent/reserve")) {
      return jsonResponse(201, { intent_id: INTENT_ID, qr_mac: QR_MAC });
    }
    if (u.endsWith("/v1/intent/commit")) {
      return jsonResponse(201, { retrieval_id: INTENT_ID, status: "active" });
    }
    throw new Error(`unexpected fetch: ${u}`);
  });
  const client = new ValidPayClient({
    apiKey: "test_key",
    baseUrl: "https://api.example.test",
    fetch: fetchMock as unknown as typeof fetch,
  });
  const commitBodies = () =>
    fetchMock.mock.calls
      .filter(([u]) => String(u).endsWith("/v1/intent/commit"))
      .map(([, init]) => JSON.parse((init as RequestInit).body as string));
  const reserveCalls = () =>
    fetchMock.mock.calls.filter(([u]) => String(u).endsWith("/v1/intent/reserve")).length;
  return { fetchMock, client, commitBodies, reserveCalls };
}

async function blankPdf(pages = 1): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  for (let i = 0; i < pages; i++) doc.addPage([W, H]);
  return doc.save();
}

/** One-page PDF whose BOTTOM-RIGHT corner is blocked by a drawn rect (and
 *  some body text top-left) — smart-place must dodge to bottom-left. */
async function crowdedCornerPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const page = doc.addPage([W, H]);
  page.drawText("Synthetic invoice — smart-place fixture", {
    x: 40,
    y: 740,
    size: 14,
    font,
  });
  // pdf-lib bottom-left origin: occupies x 480..594, y 18..130 — squarely on
  // the default bottom-right candidate (incl. its 8pt clearance).
  page.drawRectangle({ x: 480, y: 18, width: 114, height: 112, color: rgb(0.8, 0.2, 0.2) });
  return doc.save();
}

describe("buildVerifyUrl — display-only page tag (&p=)", () => {
  it("emits p AFTER t and m (canonical order)", () => {
    expect(buildVerifyUrl("id", "k", { tenant: "validpay", qrMac: QR_MAC, page: 3 })).toBe(
      `https://verify.keyhalve.com/verify/id?t=validpay&m=${QR_MAC}&p=3#key=k`,
    );
  });

  it("emits p alone when neither t nor m is given", () => {
    expect(buildVerifyUrl("id", "k", { page: 12 })).toBe(
      "https://verify.keyhalve.com/verify/id?p=12#key=k",
    );
  });

  it("keeps the untagged shape byte-identical when page is omitted", () => {
    expect(buildVerifyUrl("id", "k", { tenant: "t1" })).toBe(
      "https://verify.keyhalve.com/verify/id?t=t1#key=k",
    );
  });

  it("rejects non-positive / non-integer pages", () => {
    expect(() => buildVerifyUrl("id", "k", { page: 0 })).toThrow(ValidPayError);
    expect(() => buildVerifyUrl("id", "k", { page: -1 })).toThrow(ValidPayError);
    expect(() => buildVerifyUrl("id", "k", { page: 1.5 })).toThrow(ValidPayError);
  });
});

describe("sealDocument placement: \"auto\" (smart-place)", () => {
  it("dodges page content: blocked bottom-right corner lands the QR bottom-left, decision reported and recorded", async () => {
    const { client, commitBodies } = mockApi();

    const result = await client.sealDocument({
      file: await crowdedCornerPdf(),
      documentType: "invoice",
      placement: "auto",
    });

    // The reported decision: bottom-left, full size, honest flags.
    expect(result.autoPlacement).toHaveLength(1);
    const d = result.autoPlacement![0]!;
    expect(d.page).toBe(1);
    expect(d.anchorTried).toBe("bottom-left");
    expect(d.widthPt).toBe(72);
    expect(d.shrunk).toBe(false);
    expect(d.fallback).toBe(false);
    expect(d.obstacleCount).toBeGreaterThan(0);

    // The recorded qr_placement matches the decision (center-percent shape).
    const [body] = commitBodies();
    const qp = body!["qr_placement"] as Record<string, number>;
    expect(qp["page"]).toBe(1);
    expect(qp["x"]).toBeCloseTo(((d.x + d.widthPt / 2) / W) * 100, 4);
    expect(qp["y"]).toBeCloseTo(((d.y + d.widthPt / 2) / H) * 100, 4);
    expect(qp["width"]).toBe(72);

    // Single-page seal: the stamped URL carries NO page tag.
    expect(capturedQrUrls).toHaveLength(1);
    expect(capturedQrUrls[0]).not.toContain("&p=");
    expect(result.pageVerifyUrls).toBeUndefined();
  });

  it("auto composes with a page choice ({ mode: 'auto', page: 2 })", async () => {
    const { client, commitBodies } = mockApi();
    await client.sealDocument({
      file: await blankPdf(2),
      documentType: "lease",
      placement: { mode: "auto", page: 2 },
    });
    const [body] = commitBodies();
    const qp = body!["qr_placement"] as Record<string, number>;
    expect(qp["page"]).toBe(2);
    // Blank page → preferred corner at full size, margin 18: QR rect
    // (522, 702)..(594, 774) → center (558, 738) from the top-left.
    expect(qp["x"]).toBeCloseTo((558 / W) * 100, 4);
    expect(qp["y"]).toBeCloseTo((738 / H) * 100, 4);
  });

  it("auto placement options pass through (preferredAnchor)", async () => {
    const { client } = mockApi();
    const result = await client.sealDocument({
      file: await blankPdf(1),
      documentType: "invoice",
      placement: { mode: "auto", preferredAnchor: "top-left" },
    });
    expect(result.autoPlacement![0]!.anchorTried).toBe("top-left");
  });

  it("rejects an out-of-range auto page BEFORE reserving", async () => {
    const { client, reserveCalls } = mockApi();
    await expect(
      client.sealDocument({
        file: await blankPdf(2),
        documentType: "invoice",
        placement: { mode: "auto", page: 5 },
      }),
    ).rejects.toMatchObject({ code: "invalid_argument" });
    expect(reserveCalls()).toBe(0);
  });
});

describe("sealDocument all-pages: per-page auto decisions + &p= page tags", () => {
  it("multi-page all-pages seal: every page's QR URL carries its own &p= tag (and the result lists them)", async () => {
    const { client, commitBodies } = mockApi();

    const result = await client.sealDocument({
      file: await blankPdf(3),
      documentType: "contract",
      placement: "auto",
      allPages: true,
    });

    // Three stamped URLs, tagged p=1..3, otherwise identical.
    expect(capturedQrUrls).toHaveLength(3);
    capturedQrUrls.forEach((url, i) => {
      expect(url).toContain(`?t=validpay&m=${QR_MAC}&p=${i + 1}#key=`);
    });

    // The result reports the same page-tagged URLs.
    expect(result.pageVerifyUrls).toHaveLength(3);
    expect(result.pageVerifyUrls!.map((e) => e.page)).toEqual([1, 2, 3]);
    result.pageVerifyUrls!.forEach((e, i) => {
      expect(e.url).toBe(capturedQrUrls[i]);
    });
    // The canonical verifyUrl stays UNtagged (it is not scanned from a page).
    expect(result.verifyUrl).not.toContain("&p=");

    // Per-page decisions came back, page 1 is the canonical recorded one.
    expect(result.autoPlacement).toHaveLength(3);
    const [body] = commitBodies();
    expect((body!["qr_placement"] as Record<string, number>)["page"]).toBe(1);
    // Sealed page count disclosed.
    expect((body!["metadata"] as Record<string, unknown>)["page_count"]).toBe(3);
  });

  it("single-page all-pages seal stays UNtagged (no &p=, no pageVerifyUrls)", async () => {
    const { client } = mockApi();
    const result = await client.sealDocument({
      file: await blankPdf(1),
      documentType: "invoice",
      allPages: true,
    });
    expect(capturedQrUrls).toHaveLength(1);
    expect(capturedQrUrls[0]).not.toContain("&p=");
    expect(result.pageVerifyUrls).toBeUndefined();
  });

  it("manual multi-page all-pages seals get page tags too (tags are placement-independent)", async () => {
    const { client } = mockApi();
    const result = await client.sealDocument({
      file: await blankPdf(2),
      documentType: "invoice",
      placement: { anchor: "bottom-right", x: 36, y: 36, width: 90 },
      allPages: true,
    });
    expect(capturedQrUrls).toHaveLength(2);
    expect(capturedQrUrls[0]).toContain("&p=1#key=");
    expect(capturedQrUrls[1]).toContain("&p=2#key=");
    expect(result.autoPlacement).toBeUndefined();
  });
});

describe("sealDocument sealed page count (metadata.page_count)", () => {
  it("always discloses the document's total page count", async () => {
    const { client, commitBodies } = mockApi();
    await client.sealDocument({ file: await blankPdf(4), documentType: "report" });
    const [body] = commitBodies();
    expect((body!["metadata"] as Record<string, unknown>)["page_count"]).toBe(4);
  });

  it("a caller-supplied page_count field wins (never clobbered)", async () => {
    const { client, commitBodies } = mockApi();
    await client.sealDocument({
      file: await blankPdf(2),
      documentType: "report",
      fields: { page_count: "2 (double-sided)" },
    });
    const [body] = commitBodies();
    expect((body!["metadata"] as Record<string, unknown>)["page_count"]).toBe(
      "2 (double-sided)",
    );
  });
});
