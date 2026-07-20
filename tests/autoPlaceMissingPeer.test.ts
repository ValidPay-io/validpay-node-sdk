/**
 * pdfjs-dist is an OPTIONAL peer: requesting placement "auto" without it
 * must fail with a clear missing_dependency error NAMING the peer — and
 * before any reservation is spent. Isolated in its own file because the
 * vi.mock factories poison both pdfjs-dist entrypoints for the whole file.
 */
import { describe, it, expect, vi } from "vitest";
import { PDFDocument } from "pdf-lib";
import { ValidPayClient } from "../src/client.js";
import { computeAutoPlacements } from "../src/autoPlace.js";

vi.mock("pdfjs-dist/legacy/build/pdf.mjs", () => {
  throw new Error("Cannot find module 'pdfjs-dist/legacy/build/pdf.mjs'");
});
vi.mock("pdfjs-dist", () => {
  throw new Error("Cannot find module 'pdfjs-dist'");
});

async function blankPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.addPage([612, 792]);
  return doc.save();
}

describe("auto placement without the pdfjs-dist peer", () => {
  it("computeAutoPlacements throws missing_dependency naming pdfjs-dist", async () => {
    await expect(computeAutoPlacements(await blankPdf(), [1])).rejects.toMatchObject({
      code: "missing_dependency",
      message: expect.stringContaining("pdfjs-dist"),
    });
  });

  it("sealDocument with placement 'auto' fails the same way BEFORE reserving", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("network must not be touched");
    });
    const client = new ValidPayClient({
      apiKey: "test_key",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(
      client.sealDocument({
        file: await blankPdf(),
        documentType: "invoice",
        placement: "auto",
      }),
    ).rejects.toMatchObject({
      code: "missing_dependency",
      message: expect.stringContaining("pdfjs-dist"),
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("manual placement is unaffected by the missing peer", async () => {
    const fetchMock = vi.fn(async (url: unknown) => {
      const u = String(url);
      if (u.endsWith("/v1/intent/reserve")) {
        return new Response(
          JSON.stringify({ intent_id: "vp_peerless0001", qr_mac: "Ab3dEf5h" }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        );
      }
      if (u.endsWith("/v1/intent/commit")) {
        return new Response(JSON.stringify({ retrieval_id: "vp_peerless0001" }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${u}`);
    });
    const client = new ValidPayClient({
      apiKey: "test_key",
      baseUrl: "https://api.example.test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await client.sealDocument({
      file: await blankPdf(),
      documentType: "invoice",
    });
    expect(result.intentId).toBe("vp_peerless0001");
  });
});
