/**
 * smart-place — automatic clear-space QR placement (SHARED CONTRACT).
 *
 * BYTE-IDENTICAL COPIES of this file live in:
 *   - validpay-node-sdk  src/smartPlace.ts
 *   - validpay-mcp       src/smartPlace.ts
 *   - validpay-website   src/lib/smartPlace.ts
 *
 * Like the brandedQr contract, every copy must stay byte-for-byte identical
 * (each PR records the file's sha256) so the SAME page yields the SAME
 * placement on every surface. Pure math, zero dependencies, zero imports —
 * everything is computed LOCALLY by the consumer; no page content is ever
 * sent to a server.
 *
 * Coordinate system: TOP-LEFT-ORIGIN points (1 pt = 1/72 in), matching the
 * canonical QR placement contract (`QrPlacement` with `anchor: "top-left"`)
 * and screen coordinates. Callers that extract obstacles from PDF user
 * space (bottom-left origin) must flip the y axis first — see
 * pdfObstacles.ts, this contract's companion extraction helper.
 *
 * Algorithm (deterministic — the candidate order IS the contract):
 *
 *   1. Candidate anchors, in order: the preferred corner, then the
 *      remaining corners in the fixed order bottom-right, bottom-left,
 *      top-right, top-left (preferred removed), then bottom-center, then
 *      top-center.
 *   2. Candidate widths, in order: the requested `qrWidthPt`, then three
 *      equal shrink steps ending exactly at `minWidthPt` (quarters of the
 *      range). If `minWidthPt >= qrWidthPt` only the requested width is
 *      tried.
 *   3. For each width (outer) and each anchor (inner), build the candidate
 *      rect at `marginPt` inset from the page edges (centers are centered
 *      horizontally). A candidate off the page is skipped. A candidate is
 *      FREE iff its rect expanded by `clearancePt` on every side STRICTLY
 *      overlaps no obstacle — rects that merely touch an obstacle's edge
 *      are still free. The first free candidate wins.
 *   4. If nothing is free, the fallback is the preferred corner at
 *      `minWidthPt`, clamped onto the page, with `fallback: true`.
 *
 * Degenerate obstacles are meaningful: a zero-width/zero-height box is a
 * LINE (rule lines are real obstacles) and still blocks candidates whose
 * expanded rect strictly crosses it. Boxes with non-finite fields are
 * ignored.
 */

/** An axis-aligned obstacle, top-left-origin points. */
export interface Box {
  /** Left edge, pt from the page's left edge. */
  x: number;
  /** Top edge, pt from the page's top edge. */
  y: number;
  /** Width, pt (>= 0; 0 = vertical line). */
  width: number;
  /** Height, pt (>= 0; 0 = horizontal line). */
  height: number;
}

/** The four page corners a placement can prefer. */
export type SmartPlaceAnchor =
  | "top-left"
  | "top-right"
  | "bottom-left"
  | "bottom-right";

/** Every position the candidate ladder can try (corners + edge centers). */
export type SmartPlaceCandidate =
  | SmartPlaceAnchor
  | "bottom-center"
  | "top-center";

export interface SmartPlaceOptions {
  /** Corner tried first (and used for the fallback). Default "bottom-right". */
  preferredAnchor?: SmartPlaceAnchor;
  /** Requested QR side length, pt. Default 72 (1 in — the print-scannable
   *  recommended minimum of the placement contract). */
  qrWidthPt?: number;
  /** Inset from the page edges for every candidate, pt. Default 18. */
  marginPt?: number;
  /** Clear space required around the QR (quiet zone beyond the page
   *  margin), pt. Default 8. */
  clearancePt?: number;
  /** Smallest width the shrink ladder may reach, pt. Default 54 (0.75 in). */
  minWidthPt?: number;
}

export interface SmartPlaceResult {
  /** QR left edge, pt from the page's left edge (top-left origin). */
  x: number;
  /** QR top edge, pt from the page's top edge (top-left origin). */
  y: number;
  /** Chosen QR side length, pt. */
  widthPt: number;
  /** The candidate position the result sits at. */
  anchorTried: SmartPlaceCandidate;
  /** True when the result is smaller than the requested qrWidthPt. */
  shrunk: boolean;
  /** True when NO candidate was free and the preferred corner at
   *  minWidthPt was forced — the page is crowded; a human should review. */
  fallback: boolean;
}

/** The contract's default options — exported so consumers can display them. */
export const SMART_PLACE_DEFAULTS: Required<SmartPlaceOptions> = {
  preferredAnchor: "bottom-right",
  qrWidthPt: 72,
  marginPt: 18,
  clearancePt: 8,
  minWidthPt: 54,
};

/** Fixed canonical corner order the candidate ladder walks (after the
 *  preferred corner). */
const CORNER_ORDER: readonly SmartPlaceAnchor[] = [
  "bottom-right",
  "bottom-left",
  "top-right",
  "top-left",
];

function isFiniteBox(b: Box): boolean {
  return (
    Number.isFinite(b.x) &&
    Number.isFinite(b.y) &&
    Number.isFinite(b.width) &&
    Number.isFinite(b.height) &&
    b.width >= 0 &&
    b.height >= 0
  );
}

/** Strict overlap: touching edges do NOT intersect. Zero-area boxes still
 *  block when strictly crossed (they are lines). */
function strictlyOverlaps(
  ax: number,
  ay: number,
  aw: number,
  ah: number,
  b: Box,
): boolean {
  return (
    ax < b.x + b.width &&
    ax + aw > b.x &&
    ay < b.y + b.height &&
    ay + ah > b.y
  );
}

/** Top-left corner of the candidate rect for a position at a given width. */
function candidateRect(
  at: SmartPlaceCandidate,
  w: number,
  pageWidthPt: number,
  pageHeightPt: number,
  marginPt: number,
): { x: number; y: number } {
  const right = pageWidthPt - marginPt - w;
  const bottom = pageHeightPt - marginPt - w;
  const centerX = (pageWidthPt - w) / 2;
  switch (at) {
    case "top-left":
      return { x: marginPt, y: marginPt };
    case "top-right":
      return { x: right, y: marginPt };
    case "bottom-left":
      return { x: marginPt, y: bottom };
    case "bottom-right":
      return { x: right, y: bottom };
    case "top-center":
      return { x: centerX, y: marginPt };
    case "bottom-center":
      return { x: centerX, y: bottom };
  }
}

/**
 * Choose a clear rectangle for the QR on a page, avoiding the given
 * obstacles. See the module doc for the exact (contractual) candidate
 * order. Pure and deterministic: identical inputs yield identical output
 * on every surface.
 */
export function chooseClearRect(
  obstacles: Box[],
  pageWidthPt: number,
  pageHeightPt: number,
  opts?: SmartPlaceOptions,
): SmartPlaceResult {
  if (
    !Number.isFinite(pageWidthPt) ||
    !Number.isFinite(pageHeightPt) ||
    pageWidthPt <= 0 ||
    pageHeightPt <= 0
  ) {
    throw new Error(
      "smart-place: pageWidthPt and pageHeightPt must be positive finite points",
    );
  }
  const preferredAnchor =
    opts?.preferredAnchor ?? SMART_PLACE_DEFAULTS.preferredAnchor;
  const qrWidthPt = opts?.qrWidthPt ?? SMART_PLACE_DEFAULTS.qrWidthPt;
  const marginPt = opts?.marginPt ?? SMART_PLACE_DEFAULTS.marginPt;
  const clearancePt = opts?.clearancePt ?? SMART_PLACE_DEFAULTS.clearancePt;
  const minWidthPt = opts?.minWidthPt ?? SMART_PLACE_DEFAULTS.minWidthPt;
  if (
    !Number.isFinite(qrWidthPt) ||
    qrWidthPt <= 0 ||
    !Number.isFinite(minWidthPt) ||
    minWidthPt <= 0 ||
    !Number.isFinite(marginPt) ||
    marginPt < 0 ||
    !Number.isFinite(clearancePt) ||
    clearancePt < 0
  ) {
    throw new Error(
      "smart-place: qrWidthPt/minWidthPt must be > 0 and marginPt/clearancePt >= 0",
    );
  }

  const solid = obstacles.filter(isFiniteBox);

  // Contractual width ladder: requested width, then three equal steps down
  // to minWidthPt (skipped when the minimum isn't below the request).
  const effMin = Math.min(minWidthPt, qrWidthPt);
  const widths: number[] = [qrWidthPt];
  if (effMin < qrWidthPt) {
    const range = qrWidthPt - effMin;
    widths.push(qrWidthPt - range / 3, qrWidthPt - (2 * range) / 3, effMin);
  }

  // Contractual anchor ladder: preferred corner, remaining corners in the
  // fixed canonical order, then the two edge centers.
  const anchors: SmartPlaceCandidate[] = [
    preferredAnchor,
    ...CORNER_ORDER.filter((c) => c !== preferredAnchor),
    "bottom-center",
    "top-center",
  ];

  for (const w of widths) {
    for (const at of anchors) {
      const { x, y } = candidateRect(at, w, pageWidthPt, pageHeightPt, marginPt);
      // Off-page candidates (page smaller than margin + QR) are skipped.
      if (x < 0 || y < 0 || x + w > pageWidthPt || y + w > pageHeightPt) {
        continue;
      }
      const ex = x - clearancePt;
      const ey = y - clearancePt;
      const ew = w + 2 * clearancePt;
      let free = true;
      for (const b of solid) {
        if (strictlyOverlaps(ex, ey, ew, ew, b)) {
          free = false;
          break;
        }
      }
      if (free) {
        return {
          x,
          y,
          widthPt: w,
          anchorTried: at,
          shrunk: w < qrWidthPt,
          fallback: false,
        };
      }
    }
  }

  // Everything blocked: force the preferred corner at the minimum width,
  // clamped onto the page.
  const forced = candidateRect(
    preferredAnchor,
    effMin,
    pageWidthPt,
    pageHeightPt,
    marginPt,
  );
  return {
    x: Math.min(Math.max(0, forced.x), Math.max(0, pageWidthPt - effMin)),
    y: Math.min(Math.max(0, forced.y), Math.max(0, pageHeightPt - effMin)),
    widthPt: effMin,
    anchorTried: preferredAnchor,
    shrunk: effMin < qrWidthPt,
    fallback: true,
  };
}
