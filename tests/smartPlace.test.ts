import { describe, it, expect } from "vitest";
import {
  chooseClearRect,
  SMART_PLACE_DEFAULTS,
  type Box,
} from "../src/smartPlace.js";

// US Letter, points.
const W = 612;
const H = 792;

// Default-geometry helpers (margin 18, qr 72, clearance 8, min 54).
const FULL = 72;
const MIN = 54;

/** A box covering a whole corner candidate region generously. */
function cornerBlock(anchor: "br" | "bl" | "tr" | "tl"): Box {
  const size = 120;
  const x = anchor === "br" || anchor === "tr" ? W - size : 0;
  const y = anchor === "br" || anchor === "bl" ? H - size : 0;
  return { x, y, width: size, height: size };
}

describe("chooseClearRect — contract behavior", () => {
  it("empty page: preferred corner (bottom-right) at full size", () => {
    const r = chooseClearRect([], W, H);
    expect(r).toEqual({
      x: W - 18 - FULL,
      y: H - 18 - FULL,
      widthPt: FULL,
      anchorTried: "bottom-right",
      shrunk: false,
      fallback: false,
    });
  });

  it("is deterministic — identical inputs give identical output", () => {
    const obstacles: Box[] = [cornerBlock("br"), { x: 10, y: 10, width: 30, height: 12 }];
    const a = chooseClearRect(obstacles, W, H);
    const b = chooseClearRect(obstacles, W, H);
    expect(a).toEqual(b);
  });

  it("preferred corner blocked: walks the fixed corner order (bottom-left next)", () => {
    const r = chooseClearRect([cornerBlock("br")], W, H);
    expect(r.anchorTried).toBe("bottom-left");
    expect(r).toMatchObject({ x: 18, y: H - 18 - FULL, widthPt: FULL, shrunk: false, fallback: false });
  });

  it("bottom corners blocked: top-right is next in the canonical order", () => {
    const r = chooseClearRect([cornerBlock("br"), cornerBlock("bl")], W, H);
    expect(r.anchorTried).toBe("top-right");
    expect(r).toMatchObject({ x: W - 18 - FULL, y: 18, widthPt: FULL });
  });

  it("respects preferredAnchor (tried first, and skipped in the remainder walk)", () => {
    const r = chooseClearRect([], W, H, { preferredAnchor: "top-left" });
    expect(r.anchorTried).toBe("top-left");
    expect(r).toMatchObject({ x: 18, y: 18, widthPt: FULL });

    const r2 = chooseClearRect([cornerBlock("tl")], W, H, { preferredAnchor: "top-left" });
    // After a blocked preferred corner the walk restarts at the canonical
    // order: bottom-right first.
    expect(r2.anchorTried).toBe("bottom-right");
  });

  it("all four corners blocked: falls through to bottom-center then top-center", () => {
    const corners = [cornerBlock("br"), cornerBlock("bl"), cornerBlock("tr"), cornerBlock("tl")];
    const r = chooseClearRect(corners, W, H);
    expect(r.anchorTried).toBe("bottom-center");
    expect(r).toMatchObject({
      x: (W - FULL) / 2,
      y: H - 18 - FULL,
      widthPt: FULL,
      shrunk: false,
      fallback: false,
    });

    const bottomCenterBlock: Box = { x: W / 2 - 60, y: H - 130, width: 120, height: 120 };
    const r2 = chooseClearRect([...corners, bottomCenterBlock], W, H);
    expect(r2.anchorTried).toBe("top-center");
    expect(r2).toMatchObject({ x: (W - FULL) / 2, y: 18, widthPt: FULL });
  });

  it("shrinks in the contractual ladder (72 → 66 → 60 → 54) when only smaller sizes fit", () => {
    // Six 2x2 pin obstacles, each sitting at the far corner of one FULL-width
    // expanded candidate rect — they block every candidate at 72pt but none
    // at 66pt.
    const pins: Box[] = [
      { x: 514, y: 694, width: 2, height: 2 }, // bottom-right far corner
      { x: 96, y: 694, width: 2, height: 2 }, // bottom-left
      { x: 514, y: 96, width: 2, height: 2 }, // top-right
      { x: 96, y: 96, width: 2, height: 2 }, // top-left
      { x: 262, y: 694, width: 2, height: 2 }, // bottom-center
      { x: 262, y: 96, width: 2, height: 2 }, // top-center
    ];
    const r = chooseClearRect(pins, W, H);
    expect(r.anchorTried).toBe("bottom-right");
    expect(r.widthPt).toBeCloseTo(66, 10);
    expect(r.shrunk).toBe(true);
    expect(r.fallback).toBe(false);
    expect(r.x).toBeCloseTo(W - 18 - 66, 10);
    expect(r.y).toBeCloseTo(H - 18 - 66, 10);
  });

  it("everything blocked: fallback = preferred corner at minWidthPt with fallback:true", () => {
    const everything: Box = { x: 0, y: 0, width: W, height: H };
    const r = chooseClearRect([everything], W, H);
    expect(r).toEqual({
      x: W - 18 - MIN,
      y: H - 18 - MIN,
      widthPt: MIN,
      anchorTried: "bottom-right",
      shrunk: true,
      fallback: true,
    });
  });

  it("fallback honors preferredAnchor", () => {
    const everything: Box = { x: 0, y: 0, width: W, height: H };
    const r = chooseClearRect([everything], W, H, { preferredAnchor: "top-left" });
    expect(r).toMatchObject({ x: 18, y: 18, widthPt: MIN, anchorTried: "top-left", fallback: true });
  });

  it("clearance is strict overlap: an obstacle TOUCHING the expanded rect is still free", () => {
    // Full-width bottom-right expanded rect spans x 514..602, y 694..782.
    const touching: Box = { x: 500, y: 600, width: 14, height: 300 }; // right edge == 514
    expect(chooseClearRect([touching], W, H).anchorTried).toBe("bottom-right");

    const crossing: Box = { x: 500, y: 600, width: 14.5, height: 300 }; // right edge 514.5
    expect(chooseClearRect([crossing], W, H).anchorTried).toBe("bottom-left");
  });

  it("zero-area obstacles are LINES and still block when strictly crossed", () => {
    // Vertical line at x=550 crossing the bottom-right candidate.
    const line: Box = { x: 550, y: 0, width: 0, height: H };
    const r = chooseClearRect([line], W, H);
    expect(r.anchorTried).not.toBe("bottom-right");
    expect(r.anchorTried).not.toBe("top-right");

    // The same line exactly ON the expanded boundary (x=602) does not block.
    const boundary: Box = { x: 602, y: 0, width: 0, height: H };
    expect(chooseClearRect([boundary], W, H).anchorTried).toBe("bottom-right");
  });

  it("obstacle-touching-page-edge: content in the margin under the candidate blocks it", () => {
    // Strip along the bottom edge, y 781..792 — the expanded rect reaches 782.
    const strip: Box = { x: 0, y: 781, width: W, height: 11 };
    const r = chooseClearRect([strip], W, H);
    expect(r.anchorTried).toBe("top-right");

    // Moved fully to y >= 782 it only touches → bottom-right is free again.
    const stripTouching: Box = { x: 0, y: 782, width: W, height: 10 };
    expect(chooseClearRect([stripTouching], W, H).anchorTried).toBe("bottom-right");
  });

  it("non-finite / negative-size obstacles are ignored", () => {
    const junk: Box[] = [
      { x: Number.NaN, y: 0, width: 10, height: 10 },
      { x: 0, y: Number.POSITIVE_INFINITY, width: 10, height: 10 },
      { x: 500, y: 700, width: -5, height: 10 },
    ];
    expect(chooseClearRect(junk, W, H).anchorTried).toBe("bottom-right");
  });

  it("small pages skip off-page candidates and land at the largest width that fits", () => {
    // 80x80: the anchor inset is 18, so a width fits while 18 + w <= 80.
    // Ladder 72 (off-page) → 66 (off-page? 18+66=84 no) → 60 (18+60=78 fits).
    const r = chooseClearRect([], 80, 80);
    expect(r.widthPt).toBe(60);
    expect(r.anchorTried).toBe("bottom-right");
    expect(r.shrunk).toBe(true);
    expect(r.fallback).toBe(false);
  });

  it("degenerate page smaller than the minimum QR: clamped fallback", () => {
    const r = chooseClearRect([], 40, 40);
    expect(r.fallback).toBe(true);
    expect(r.x).toBe(0);
    expect(r.y).toBe(0);
    expect(r.widthPt).toBe(MIN);
  });

  it("qrWidthPt == minWidthPt: single-width ladder, shrunk stays false, fallback keeps that width", () => {
    const r = chooseClearRect([], W, H, { qrWidthPt: 90, minWidthPt: 90 });
    expect(r.widthPt).toBe(90);
    expect(r.shrunk).toBe(false);

    const blocked = chooseClearRect([{ x: 0, y: 0, width: W, height: H }], W, H, {
      qrWidthPt: 90,
      minWidthPt: 90,
    });
    expect(blocked).toMatchObject({ widthPt: 90, shrunk: false, fallback: true });
  });

  it("custom margins/clearance are honored", () => {
    const r = chooseClearRect([], W, H, { marginPt: 36, qrWidthPt: 100, minWidthPt: 60 });
    expect(r).toMatchObject({ x: W - 36 - 100, y: H - 36 - 100, widthPt: 100 });
  });

  it("throws on invalid page sizes and options", () => {
    expect(() => chooseClearRect([], 0, H)).toThrow(/positive finite/);
    expect(() => chooseClearRect([], W, Number.NaN)).toThrow(/positive finite/);
    expect(() => chooseClearRect([], W, H, { qrWidthPt: 0 })).toThrow();
    expect(() => chooseClearRect([], W, H, { minWidthPt: -1 })).toThrow();
    expect(() => chooseClearRect([], W, H, { marginPt: -1 })).toThrow();
    expect(() => chooseClearRect([], W, H, { clearancePt: Number.NaN })).toThrow();
  });

  it("exports the contract defaults", () => {
    expect(SMART_PLACE_DEFAULTS).toEqual({
      preferredAnchor: "bottom-right",
      qrWidthPt: 72,
      marginPt: 18,
      clearancePt: 8,
      minWidthPt: 54,
    });
  });
});
