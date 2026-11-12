/**
 * Auto placement must tear pdf.js down through the LOADING TASK.
 *
 * pdf.js 6 removed `PDFDocumentProxy.destroy()`; `destroy()` stayed on the
 * loading task returned by `getDocument()` (it exists there on 4, 5 and 6).
 * The previous `finally { await doc.destroy() }` was wrapped in try/catch, so
 * on pdf.js 6 it became a silent no-op and the worker outlived every auto
 * placement. Isolated in its own file because the vi.mock factory poisons the
 * pdfjs-dist entrypoints for the whole file.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { PDFDocument } from "pdf-lib";

const fake = vi.hoisted(() => {
  const state = {
    taskDestroy: vi.fn(async () => undefined),
    docDestroy: vi.fn(async () => undefined),
    /** true = pdf.js ≤5 shape (document proxy has destroy); false = pdf.js 6 */
    docHasDestroy: false,
    getDocumentCalls: 0,
  };
  return state;
});

vi.mock("pdfjs-dist/legacy/build/pdf.mjs", () => ({
  getDocument: (_params: unknown) => {
    fake.getDocumentCalls++;
    const page = {
      getViewport: ({ scale }: { scale: number }) => ({ width: 612 * scale, height: 792 * scale }),
      // Anything obstacle extraction asks for throws → best-effort empty list.
      getTextContent: async () => {
        throw new Error("not in this fake");
      },
      getOperatorList: async () => {
        throw new Error("not in this fake");
      },
    };
    const doc: Record<string, unknown> = {
      numPages: 1,
      getPage: async () => page,
    };
    if (fake.docHasDestroy) doc.destroy = fake.docDestroy;
    return { promise: Promise.resolve(doc), destroy: fake.taskDestroy };
  },
}));

import { extractAutoObstacles } from "../src/autoPlace.js";

async function blankPdf(): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.addPage([612, 792]);
  return doc.save();
}

beforeEach(() => {
  fake.taskDestroy.mockClear();
  fake.docDestroy.mockClear();
  fake.getDocumentCalls = 0;
});

describe("extractAutoObstacles teardown", () => {
  it("pdf.js 6 shape (no destroy on the document proxy): the loading task is destroyed exactly once", async () => {
    fake.docHasDestroy = false;
    const out = await extractAutoObstacles(await blankPdf(), [1]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ page: 1, pageWidthPt: 612, pageHeightPt: 792, obstacles: [] });
    expect(fake.getDocumentCalls).toBe(1);
    expect(fake.taskDestroy).toHaveBeenCalledTimes(1);
  });

  it("pdf.js ≤5 shape (document proxy still has destroy): teardown still goes through the task", async () => {
    fake.docHasDestroy = true;
    await extractAutoObstacles(await blankPdf(), [1]);
    expect(fake.taskDestroy).toHaveBeenCalledTimes(1);
    expect(fake.docDestroy).not.toHaveBeenCalled();
  });

  it("the task is destroyed even when a page is out of range (the error path)", async () => {
    fake.docHasDestroy = false;
    await expect(extractAutoObstacles(await blankPdf(), [7])).rejects.toMatchObject({
      code: "invalid_argument",
    });
    expect(fake.taskDestroy).toHaveBeenCalledTimes(1);
  });
});
