import { describe, it, expect } from "vitest";
import {
  extractPageObstacles,
  type PdfJsModuleLike,
  type PdfJsPageLike,
} from "../src/pdfObstacles.js";

// US Letter, points.
const W = 612;
const H = 792;

/** Real pdf.js matrix semantics: transform(m1, m2) = m1 ∘ m2 (m2 first). */
const Util = {
  transform(m1: ArrayLike<number>, m2: ArrayLike<number>): number[] {
    return [
      m1[0]! * m2[0]! + m1[2]! * m2[1]!,
      m1[1]! * m2[0]! + m1[3]! * m2[1]!,
      m1[0]! * m2[2]! + m1[2]! * m2[3]!,
      m1[1]! * m2[2]! + m1[3]! * m2[3]!,
      m1[0]! * m2[4]! + m1[2]! * m2[5]! + m1[4]!,
      m1[1]! * m2[4]! + m1[3]! * m2[5]! + m1[5]!,
    ];
  },
};

const OPS = {
  save: 10,
  restore: 11,
  transform: 12,
  paintImageXObject: 85,
  paintInlineImageXObject: 86,
  paintJpegXObject: 82,
  paintImageMaskXObject: 83,
  paintSolidColorImageMask: 84,
  constructPath: 91,
};

const pdfjs: PdfJsModuleLike = { Util, OPS };

interface FakePageContent {
  textItems?: unknown[];
  fnArray?: number[];
  argsArray?: unknown[];
}

function fakePage(content: FakePageContent): PdfJsPageLike {
  return {
    getViewport: () => ({
      width: W,
      height: H,
      // Standard scale-1 viewport: flip y so 1 unit == 1pt, top-left origin.
      transform: [1, 0, 0, -1, 0, H],
    }),
    getTextContent: async () => ({ items: content.textItems ?? [] }),
    getOperatorList: async () => ({
      fnArray: content.fnArray ?? [],
      argsArray: content.argsArray ?? [],
    }),
  };
}

describe("extractPageObstacles — text runs", () => {
  it("maps a text run to a top-left-origin box (baseline minus one font-height)", async () => {
    const page = fakePage({
      textItems: [
        // 12pt glyphs at user-space (100, 700), advance width 50.
        { str: "Hello", transform: [12, 0, 0, 12, 100, 700], width: 50 },
      ],
    });
    const boxes = await extractPageObstacles(pdfjs, page);
    expect(boxes).toHaveLength(1);
    expect(boxes[0]!.x).toBeCloseTo(100, 6);
    // Baseline in top-left space: 792 - 700 = 92; top edge = 92 - 12 = 80.
    expect(boxes[0]!.y).toBeCloseTo(80, 6);
    expect(boxes[0]!.width).toBeCloseTo(50, 6);
    expect(boxes[0]!.height).toBeCloseTo(12, 6);
  });

  it("skips whitespace-only and malformed runs", async () => {
    const page = fakePage({
      textItems: [
        { str: "   ", transform: [12, 0, 0, 12, 0, 0], width: 10 },
        { str: "", transform: [12, 0, 0, 12, 0, 0], width: 10 },
        { str: "x" }, // no transform/width
        { notText: true },
      ],
    });
    expect(await extractPageObstacles(pdfjs, page)).toHaveLength(0);
  });
});

describe("extractPageObstacles — images via the operator list", () => {
  it("boxes a painted image from its CTM (unit square transform)", async () => {
    const page = fakePage({
      fnArray: [OPS.save, OPS.transform, OPS.paintImageXObject, OPS.restore],
      argsArray: [null, [200, 0, 0, 100, 50, 600], ["img1"], null],
    });
    const boxes = await extractPageObstacles(pdfjs, page);
    expect(boxes).toHaveLength(1);
    // User rect 50..250 x 600..700 → top-left box y = 792 - 700 = 92.
    expect(boxes[0]).toMatchObject({ x: 50, y: 92, width: 200, height: 100 });
  });

  it("tracks save/restore: a transform inside the pair does not leak out", async () => {
    const page = fakePage({
      fnArray: [
        OPS.save,
        OPS.transform, // [100,0,0,100,10,10] — only inside the save
        OPS.restore,
        OPS.transform, // [50,0,0,50,300,300]
        OPS.paintJpegXObject,
      ],
      argsArray: [null, [100, 0, 0, 100, 10, 10], null, [50, 0, 0, 50, 300, 300], ["img"]],
    });
    const boxes = await extractPageObstacles(pdfjs, page);
    expect(boxes).toHaveLength(1);
    // Only the post-restore CTM applies: 300..350 x 300..350.
    expect(boxes[0]).toMatchObject({ x: 300, y: H - 350, width: 50, height: 50 });
  });

  it("composes nested transforms multiplicatively", async () => {
    const page = fakePage({
      fnArray: [OPS.transform, OPS.transform, OPS.paintImageXObject],
      argsArray: [
        [1, 0, 0, 1, 100, 100], // translate
        [50, 0, 0, 20, 0, 0], // then scale
        ["img"],
      ],
    });
    const boxes = await extractPageObstacles(pdfjs, page);
    // Unit square → 100..150 x 100..120.
    expect(boxes[0]).toMatchObject({ x: 100, y: H - 120, width: 50, height: 20 });
  });

  it("drops full-bleed rasters (>= 90% page coverage) as background", async () => {
    const page = fakePage({
      fnArray: [OPS.transform, OPS.paintImageXObject],
      argsArray: [[W, 0, 0, H, 0, 0], ["scan"]],
    });
    expect(await extractPageObstacles(pdfjs, page)).toHaveLength(0);
  });
});

describe("extractPageObstacles — vector paths (constructPath minMax)", () => {
  it("boxes a path from its exposed [minX, minY, maxX, maxY] bounds", async () => {
    const page = fakePage({
      fnArray: [OPS.constructPath],
      argsArray: [[[13], [100, 100, 300, 200], [100, 100, 300, 200]]],
    });
    const boxes = await extractPageObstacles(pdfjs, page);
    expect(boxes).toHaveLength(1);
    // User rect 100..300 x 100..200 → top-left y = 792 - 200 = 592.
    expect(boxes[0]).toMatchObject({ x: 100, y: 592, width: 200, height: 100 });
  });

  it("transforms path bounds through the current CTM", async () => {
    const page = fakePage({
      fnArray: [OPS.transform, OPS.constructPath],
      argsArray: [
        [2, 0, 0, 2, 0, 0],
        [[13], [], [10, 10, 20, 30]],
      ],
    });
    const boxes = await extractPageObstacles(pdfjs, page);
    expect(boxes[0]).toMatchObject({ x: 20, y: H - 60, width: 20, height: 40 });
  });

  it("skips paths without recognizable bounds (best-effort contract)", async () => {
    const page = fakePage({
      fnArray: [OPS.constructPath],
      argsArray: [[[13], [1, 2, 3]]], // no 4-length minMax array
    });
    expect(await extractPageObstacles(pdfjs, page)).toHaveLength(0);
  });

  it("drops full-bleed background rects (page-covering wash)", async () => {
    const page = fakePage({
      fnArray: [OPS.constructPath],
      argsArray: [[[13], [], [0, 0, W, H]]],
    });
    expect(await extractPageObstacles(pdfjs, page)).toHaveLength(0);
  });
});
