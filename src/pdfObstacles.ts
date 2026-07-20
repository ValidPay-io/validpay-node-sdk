/**
 * smart-place obstacle extraction (SHARED CONTRACT COMPANION).
 *
 * BYTE-IDENTICAL COPIES of this file live in:
 *   - validpay-node-sdk  src/pdfObstacles.ts
 *   - validpay-mcp       src/pdfObstacles.ts
 *   - validpay-website   src/lib/pdfObstacles.ts
 *
 * Turns one pdf.js page into the obstacle boxes smartPlace.ts consumes —
 * top-left-origin points, matching the page's scale-1 viewport. The file
 * has ZERO imports: the caller passes its own pdf.js module (whichever
 * import style its surface uses — the browser build, the legacy Node
 * build, …) so every copy stays identical. Everything runs LOCALLY; the
 * page content never leaves the process.
 *
 * What is covered (best-effort by design):
 *   - TEXT: every non-whitespace run from getTextContent, one box per run
 *     (baseline + one font-height of ascent — the same approximation the
 *     wizard's click-to-fill layer uses).
 *   - IMAGES: paintImageXObject / paintInlineImageXObject /
 *     paintJpegXObject / paintImageMaskXObject / paintSolidColorImageMask
 *     from getOperatorList — the CTM-transformed unit square's bounding
 *     box, with save/restore/transform tracked.
 *   - VECTOR PATHS: constructPath operations WHEN pdf.js exposes the
 *     path's [minX, minY, maxX, maxY] bounds in the operator arguments
 *     (it does in the builds we ship against); the bounds are
 *     CTM-transformed. Paths without exposed bounds are skipped.
 *
 * NOT covered: annotations (links, form fields), shading patterns, and
 * clipped-away content (a painted-then-clipped image still counts as an
 * obstacle — conservative). Boxes covering >= 90% of the page are treated
 * as BACKGROUND (full-bleed washes, scanned-page rasters, letterheads'
 * base rect) and dropped — otherwise every candidate would collide and
 * auto placement could never do better than the fallback.
 */

/** An axis-aligned obstacle, top-left-origin points (smartPlace's Box). */
export interface ObstacleBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Structural slice of a pdf.js module (browser or legacy Node build). */
export interface PdfJsModuleLike {
  Util: {
    transform(m1: ArrayLike<number>, m2: ArrayLike<number>): ArrayLike<number>;
  };
  OPS: { [op: string]: number | undefined };
}

/** Structural slice of a pdf.js PageProxy. */
export interface PdfJsPageLike {
  getViewport(params: { scale: number }): {
    width: number;
    height: number;
    transform: ArrayLike<number>;
  };
  getTextContent(): Promise<{ items: unknown[] }>;
  getOperatorList(): Promise<{ fnArray: number[]; argsArray: unknown[] }>;
}

/** Fraction of the page area at/above which a box is background, not an
 *  obstacle (full-page washes, scanned rasters). */
const BACKGROUND_COVERAGE = 0.9;

const IDENTITY: readonly number[] = [1, 0, 0, 1, 0, 0];

/** Apply a PDF matrix [a,b,c,d,e,f] to a point. */
function applyM(m: ArrayLike<number>, x: number, y: number): [number, number] {
  const a = m[0] ?? 1;
  const b = m[1] ?? 0;
  const c = m[2] ?? 0;
  const d = m[3] ?? 1;
  const e = m[4] ?? 0;
  const f = m[5] ?? 0;
  return [a * x + c * y + e, b * x + d * y + f];
}

/** Bounding box (in the TARGET space of `m`) of a source-space rect. */
function transformedBounds(
  m: ArrayLike<number>,
  x0: number,
  y0: number,
  x1: number,
  y1: number,
): { minX: number; minY: number; maxX: number; maxY: number } {
  const corners: Array<[number, number]> = [
    applyM(m, x0, y0),
    applyM(m, x1, y0),
    applyM(m, x0, y1),
    applyM(m, x1, y1),
  ];
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const [px, py] of corners) {
    if (px < minX) minX = px;
    if (py < minY) minY = py;
    if (px > maxX) maxX = px;
    if (py > maxY) maxY = py;
  }
  return { minX, minY, maxX, maxY };
}

/** True when every field is finite (drops degenerate pdf.js output). */
function finiteBox(b: ObstacleBox): boolean {
  return (
    Number.isFinite(b.x) &&
    Number.isFinite(b.y) &&
    Number.isFinite(b.width) &&
    Number.isFinite(b.height) &&
    b.width >= 0 &&
    b.height >= 0
  );
}

/** Page-coverage fraction of a box (clipped to the page). */
function pageCoverage(b: ObstacleBox, pageW: number, pageH: number): number {
  const w = Math.min(b.x + b.width, pageW) - Math.max(b.x, 0);
  const h = Math.min(b.y + b.height, pageH) - Math.max(b.y, 0);
  if (w <= 0 || h <= 0) return 0;
  return (w * h) / (pageW * pageH);
}

/** Best-effort: find a [minX, minY, maxX, maxY] bounds array among a
 *  constructPath op's arguments (pdf.js exposes one; its exact slot has
 *  moved between majors, so scan rather than index). */
function findMinMax(args: unknown): ArrayLike<number> | null {
  if (!Array.isArray(args)) return null;
  for (let i = args.length - 1; i >= 0; i--) {
    const cand = args[i] as ArrayLike<number> | null;
    if (
      cand !== null &&
      typeof cand === "object" &&
      typeof (cand as { length?: unknown }).length === "number" &&
      cand.length === 4 &&
      Number.isFinite(cand[0]) &&
      Number.isFinite(cand[1]) &&
      Number.isFinite(cand[2]) &&
      Number.isFinite(cand[3])
    ) {
      return cand;
    }
  }
  return null;
}

/**
 * Extract the obstacle boxes of ONE pdf.js page, in top-left-origin points
 * of the scale-1 viewport — ready for smartPlace's chooseClearRect.
 *
 * Never throws for content it cannot interpret (that content is simply not
 * an obstacle); rejects only if pdf.js itself fails to read the page.
 */
export async function extractPageObstacles(
  pdfjs: PdfJsModuleLike,
  page: PdfJsPageLike,
): Promise<ObstacleBox[]> {
  const viewport = page.getViewport({ scale: 1 });
  const pageW = viewport.width;
  const pageH = viewport.height;
  const out: ObstacleBox[] = [];

  const push = (b: ObstacleBox): void => {
    if (!finiteBox(b)) return;
    if (pageCoverage(b, pageW, pageH) >= BACKGROUND_COVERAGE) return;
    out.push(b);
  };

  // ── Text runs (viewport transform → top-left-origin pt directly) ────────
  const textContent = await page.getTextContent();
  for (const item of textContent.items) {
    const run = item as {
      str?: unknown;
      transform?: ArrayLike<number>;
      width?: unknown;
    };
    if (typeof run.str !== "string" || run.str.trim().length === 0) continue;
    if (!run.transform || typeof run.width !== "number") continue;
    const tx = pdfjs.Util.transform(viewport.transform, run.transform);
    const a2 = tx[2] ?? 0;
    const a3 = tx[3] ?? 0;
    const fontHeight = Math.sqrt(a2 * a2 + a3 * a3);
    if (!Number.isFinite(fontHeight) || fontHeight <= 0) continue;
    push({
      x: tx[4] ?? 0,
      // tx[5] is the BASELINE y in viewport space; approximate the top
      // edge with one font-height of ascent (same as the wizard overlay).
      y: (tx[5] ?? 0) - fontHeight,
      width: run.width,
      height: fontHeight,
    });
  }

  // ── Images + vector paths (operator list, CTM tracked in user space) ────
  const ops = pdfjs.OPS;
  const imageOps = new Set<number>(
    [
      ops["paintImageXObject"],
      ops["paintInlineImageXObject"],
      ops["paintJpegXObject"],
      ops["paintImageXObjectRepeat"],
      ops["paintImageMaskXObject"],
      ops["paintSolidColorImageMask"],
    ].filter((n): n is number => typeof n === "number"),
  );
  const opSave = ops["save"];
  const opRestore = ops["restore"];
  const opTransform = ops["transform"];
  const opConstructPath = ops["constructPath"];

  // User-space rect → top-left-origin viewport pt box.
  const pushUserRect = (
    minX: number,
    minY: number,
    maxX: number,
    maxY: number,
  ): void => {
    push({
      x: minX,
      y: pageH - maxY,
      width: maxX - minX,
      height: maxY - minY,
    });
  };

  const opList = await page.getOperatorList();
  let ctm: ArrayLike<number> = IDENTITY;
  const stack: Array<ArrayLike<number>> = [];
  for (let i = 0; i < opList.fnArray.length; i++) {
    const fn = opList.fnArray[i];
    const args = opList.argsArray[i];
    if (fn === undefined) continue;
    if (fn === opSave) {
      stack.push(ctm);
    } else if (fn === opRestore) {
      const prev = stack.pop();
      if (prev !== undefined) ctm = prev;
    } else if (fn === opTransform) {
      const m = args as ArrayLike<number> | null;
      if (m && typeof m === "object" && typeof m.length === "number") {
        ctm = pdfjs.Util.transform(ctm, m);
      }
    } else if (imageOps.has(fn)) {
      // Images paint the unit square [0,1]x[0,1] under the current CTM.
      const b = transformedBounds(ctm, 0, 0, 1, 1);
      pushUserRect(b.minX, b.minY, b.maxX, b.maxY);
    } else if (fn === opConstructPath) {
      const mm = findMinMax(args);
      if (mm) {
        const m0 = mm[0] ?? 0;
        const m1 = mm[1] ?? 0;
        const m2 = mm[2] ?? 0;
        const m3 = mm[3] ?? 0;
        const b = transformedBounds(
          ctm,
          Math.min(m0, m2),
          Math.min(m1, m3),
          Math.max(m0, m2),
          Math.max(m1, m3),
        );
        pushUserRect(b.minX, b.minY, b.maxX, b.maxY);
      }
    }
  }

  return out;
}
