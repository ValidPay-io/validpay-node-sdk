/**
 * smart-place driver (SDK half): turn a PDF's pages into obstacle boxes and
 * run the shared chooseClearRect contract over them — ALL LOCALLY. The
 * document bytes never leave this process; the server never sees the page.
 *
 * `pdfjs-dist` is an OPTIONAL peer dependency (same pattern as `pdf-lib` /
 * `qrcode`): it is loaded lazily and only needed when a caller asks for
 * `placement: "auto"`. The legacy build is tried first (plain-Node
 * compatible), then the standard build (bundlers/browsers).
 */

import {
  chooseClearRect,
  type Box,
  type SmartPlaceAnchor,
  type SmartPlaceResult,
} from "./smartPlace.js";
import {
  extractPageObstacles,
  type ObstacleBox,
  type PdfJsModuleLike,
  type PdfJsPageLike,
} from "./pdfObstacles.js";
import {
  LOGO_MIN_MODULE_MM,
  modulesForPayload,
  PT_PER_MM,
  QR_MARGIN_MODULES,
} from "./brandedQr.js";
import { ValidPayError } from "./types.js";

/** Tuning knobs for auto placement — the shared contract's options. */
export interface AutoPlacementOptions {
  /** Corner tried first (and used for the fallback). Default "bottom-right". */
  preferredAnchor?: SmartPlaceAnchor;
  /** Requested QR side length, pt. Default 72 (1 in). Supplying this OPTS OUT
   *  of logo-aware grow-to-fit auto sizing (see {@link chooseGrowToFit}) and
   *  restores the legacy fixed-start-then-shrink `chooseClearRect` ladder at
   *  exactly this width. */
  qrWidthPt?: number;
  /** Largest width logo-aware grow-to-fit auto sizing may reach, pt. Default
   *  108 (1.5 in). Ignored when `qrWidthPt` is set (legacy fixed sizing). */
  maxWidthPt?: number;
  /** Inset from the page edges, pt. Default 18. */
  marginPt?: number;
  /** Clear space required around the QR, pt. Default 8. */
  clearancePt?: number;
  /** Smallest width the shrink ladder may reach, pt. Default 54 (0.75 in). */
  minWidthPt?: number;
}

/** Default ceiling for logo-aware grow-to-fit (1.5 in) — large enough that a
 *  branded QR is very scannable, small enough to sit in a document corner. */
export const GROW_MAX_WIDTH_PT = 108;
/** Default floor shared with the smart-place contract (0.75 in). */
export const GROW_MIN_WIDTH_PT = 54;

/** One page's smart-place decision (top-left-origin points). */
export interface AutoPlacementDecision extends SmartPlaceResult {
  /** 1-based page the decision applies to. */
  page: number;
  /** Obstacle boxes considered (top-left-origin pt). Empty when the page's
   *  content could not be read (the decision then saw a blank page). */
  obstacleCount: number;
  /** LOGO-AWARE grow-to-fit only: the chosen width reached the branded-logo
   *  target for THIS page's payload (the KeyHalve mark can print). Undefined
   *  on the legacy fixed-size auto path. */
  logoFit?: boolean;
  /** LOGO-AWARE grow-to-fit only: the branded-logo target width (pt) computed
   *  for this page's exact verify URL — the smallest width at which the mark
   *  stays reliably scannable. Undefined on the legacy path. */
  logoTargetPt?: number;
  /** Whether the stamped QR actually carries the KeyHalve mark, decided by the
   *  shared branded-QR contract from this page's URL + chosen size (the
   *  authoritative verdict `sealDocument` also reports). Undefined until the
   *  seal flow knows the real verify URL. */
  branded?: boolean;
  /** Printed module pitch (mm) the branded verdict was made on. Undefined
   *  until the seal flow knows the real verify URL. */
  modulePitchMm?: number;
}

/** One page's obstacle geometry, extracted LOCALLY from the PDF (top-left
 *  origin pt). The size decision ({@link chooseClearRect} /
 *  {@link chooseGrowToFit}) runs over this without re-parsing the PDF — which
 *  lets the seal flow extract BEFORE reserving an identity (cheap failure) and
 *  size the QR AFTER, once the real verify-URL length is known. */
export interface PageObstacles {
  /** 1-based page the obstacles belong to. */
  page: number;
  /** Page width, pt (scale-1 viewport). */
  pageWidthPt: number;
  /** Page height, pt (scale-1 viewport). */
  pageHeightPt: number;
  /** Obstacle boxes (top-left-origin pt). */
  obstacles: ObstacleBox[];
}

interface PdfJsDocumentLike {
  numPages: number;
  getPage(pageNumber: number): Promise<PdfJsPageLike>;
  destroy(): Promise<unknown>;
}

interface PdfJsEntryLike extends PdfJsModuleLike {
  getDocument(params: {
    data: Uint8Array;
    useSystemFonts?: boolean;
    isEvalSupported?: boolean;
    disableFontFace?: boolean;
  }): { promise: Promise<PdfJsDocumentLike> };
}

async function loadPdfjs(): Promise<PdfJsEntryLike> {
  // Legacy build first: it is the plain-Node-compatible entry. The standard
  // build is the fallback for bundled/browser environments.
  try {
    const mod = (await import(
      "pdfjs-dist/legacy/build/pdf.mjs"
    )) as unknown as PdfJsEntryLike;
    if (typeof mod.getDocument === "function") return mod;
  } catch {
    // fall through to the standard entry
  }
  try {
    const mod = (await import("pdfjs-dist")) as unknown as PdfJsEntryLike;
    if (typeof mod.getDocument === "function") return mod;
  } catch {
    // fall through to the missing_dependency error
  }
  throw new ValidPayError(
    "missing_dependency",
    "placement: \"auto\" requires the optional peer dependency 'pdfjs-dist' " +
      "(obstacle extraction runs locally — the document never leaves this " +
      "process). Install it: npm i pdfjs-dist",
  );
}

/**
 * Extract the obstacle geometry for the given 1-based pages of a PDF, LOCALLY
 * — the pdf.js parse + obstacle extraction that {@link chooseClearRect} /
 * {@link chooseGrowToFit} then run over WITHOUT re-parsing. Splitting this out
 * lets the seal flow do the failure-prone work (missing pdfjs-dist peer,
 * unparseable PDF) BEFORE it reserves an intent identity, and size the QR
 * AFTER, once the real verify-URL length is known (grow-to-fit needs it).
 *
 * Obstacles come from the shared pdfObstacles contract (text runs, images,
 * vector paths where pdf.js exposes bounds); a page whose content cannot be
 * read yields an empty obstacle set (the sizing then sees a blank page).
 * Throws `missing_dependency` when pdfjs-dist is not installed,
 * `unsupported_file_type` when the bytes do not parse as a PDF, and
 * `invalid_argument` on a bad/out-of-range page.
 */
export async function extractAutoObstacles(
  pdf: Uint8Array,
  pages: number[],
): Promise<PageObstacles[]> {
  if (!(pdf instanceof Uint8Array) || pdf.length === 0) {
    throw new ValidPayError(
      "invalid_argument",
      "pdf must be non-empty Uint8Array/Buffer bytes",
    );
  }
  const pdfjs = await loadPdfjs();
  let doc: PdfJsDocumentLike;
  try {
    // pdf.js may transfer the buffer to its worker — hand it a copy.
    doc = await pdfjs.getDocument({
      data: new Uint8Array(pdf),
      useSystemFonts: true,
      isEvalSupported: false,
      disableFontFace: true,
    }).promise;
  } catch (cause) {
    throw new ValidPayError(
      "unsupported_file_type",
      "The file could not be parsed as a PDF for auto placement.",
      { cause },
    );
  }
  try {
    const out: PageObstacles[] = [];
    for (const page of pages) {
      if (!Number.isInteger(page) || page < 1 || page > doc.numPages) {
        throw new ValidPayError(
          "invalid_argument",
          `auto placement page ${page} is out of range (document has ${doc.numPages} page(s))`,
        );
      }
      const pdfPage = await doc.getPage(page);
      const viewport = pdfPage.getViewport({ scale: 1 });
      let obstacles: ObstacleBox[] = [];
      try {
        obstacles = await extractPageObstacles(pdfjs, pdfPage);
      } catch {
        // Unreadable content is BEST-EFFORT territory: place as if blank
        // rather than failing the whole seal.
        obstacles = [];
      }
      out.push({
        page,
        pageWidthPt: viewport.width,
        pageHeightPt: viewport.height,
        obstacles,
      });
    }
    return out;
  } finally {
    try {
      await doc.destroy();
    } catch {
      // best-effort cleanup
    }
  }
}

/**
 * Compute smart-place decisions for the given 1-based pages of a PDF — the
 * LEGACY fixed-size auto path (`chooseClearRect`: start at `qrWidthPt`, shrink
 * toward `minWidthPt`). Logo-aware grow-to-fit sizing lives in the seal flow
 * (which knows the verify URL); this stays for direct callers that pin a size.
 *
 * Obstacles are extracted with {@link extractAutoObstacles}; the same
 * `missing_dependency` / `unsupported_file_type` / `invalid_argument` errors
 * apply.
 */
export async function computeAutoPlacements(
  pdf: Uint8Array,
  pages: number[],
  opts?: AutoPlacementOptions,
): Promise<AutoPlacementDecision[]> {
  const geoms = await extractAutoObstacles(pdf, pages);
  return geoms.map((g) => ({
    ...chooseClearRect(g.obstacles, g.pageWidthPt, g.pageHeightPt, opts),
    page: g.page,
    obstacleCount: g.obstacles.length,
  }));
}

/**
 * The LOGO-AWARE branded-minimum width, pt, for a QR encoding `payload`: the
 * smallest printed side length at which every module still prints at the
 * branded-QR contract's `LOGO_MIN_MODULE_MM` pitch, so the centered KeyHalve
 * mark stays reliably scannable (Prompt 158). Derived — never hardcoded — from
 * the payload's module count and the shared contract constants, then rounded
 * UP to the next 0.5 pt so the chosen width lands strictly on the branded side
 * of the threshold (no floating-point ties with `decideBrandedQr`).
 *
 * For a typical ValidPay verify URL (~120–137 chars → 65 cells) this is
 * ~73.7 pt raw → 74.0 pt — which is why a fixed 72 pt (1 in) start printed
 * PLAIN by a hair, and why grow-to-fit targets this instead.
 */
export function logoTargetWidthPt(payload: string): number {
  const cells = modulesForPayload(payload.length) + 2 * QR_MARGIN_MODULES;
  const raw = LOGO_MIN_MODULE_MM * cells * PT_PER_MM;
  return Math.ceil(raw * 2) / 2;
}

/** Tuning knobs for {@link chooseGrowToFit} (logo-aware grow-to-fit). */
export interface GrowToFitOptions {
  /** Corner tried first (kept if it can host a branded QR) and used for the
   *  crowded-page fallback. Default "bottom-right". */
  preferredAnchor?: SmartPlaceAnchor;
  /** Branded-logo target width (pt) for this page's payload — from
   *  {@link logoTargetWidthPt}. The QR is sized to reach AT LEAST this when
   *  clear space allows, so the KeyHalve mark shows. Required. */
  logoTargetPt: number;
  /** Largest width to grow to, pt. Default {@link GROW_MAX_WIDTH_PT} (108). */
  maxWidthPt?: number;
  /** Smallest width to shrink to, pt. Default {@link GROW_MIN_WIDTH_PT} (54). */
  minWidthPt?: number;
  /** Inset from the page edges, pt. Default 18. */
  marginPt?: number;
  /** Clear space required around the QR, pt. Default 8. */
  clearancePt?: number;
}

/** A grow-to-fit decision — a {@link SmartPlaceResult} plus whether the
 *  branded-logo target was reached. */
export interface GrowToFitResult extends SmartPlaceResult {
  /** The chosen width reached `logoTargetPt` — the KeyHalve mark can print. */
  logoFit: boolean;
}

/** Probe resolution of the grow-to-fit width ladder, pt. The candidate order
 *  IS deterministic: coarser than a continuous fit, fine enough that the
 *  chosen size is within this of the largest that clears. */
const GROW_STEP_PT = 2;

/** Round to 2 dp so ladder widths are clean, reproducible points. */
function round2(v: number): number {
  return Math.round(v * 100) / 100;
}

/** Descending width ladder from `hi` down to `lo` inclusive, step GROW_STEP_PT
 *  (always ending exactly on `lo`). Empty when `hi < lo`. */
function widthLadder(hi: number, lo: number): number[] {
  const out: number[] = [];
  if (hi < lo) return out;
  for (let w = hi; w > lo + 1e-9; w -= GROW_STEP_PT) out.push(round2(w));
  out.push(round2(lo));
  return out;
}

/**
 * LOGO-AWARE, SIZE-ADAPTIVE placement (Mike, Prompt 159): "each document is
 * different — size it properly and place it properly; go as large as the clear
 * space allows so the logo shows when there's room, shrink only when cramped."
 *
 * Deterministic, obstacle-aware, per-page. Reuses the shared, byte-identical
 * {@link chooseClearRect} contract as its free-space primitive (probed at a
 * single width — `qrWidthPt === minWidthPt`), so the placement math stays in
 * one place and this only adds the grow ladder on top:
 *
 *   A. BRANDED at the preferred corner — largest width first, from
 *      `maxWidthPt` down to `logoTargetPt`, at the preferred corner only. The
 *      first that clears wins (roomy corner → big branded QR that stays put).
 *   B. BRANDED at any corner — same width ladder, any candidate position.
 *      Only reached when the preferred corner can't host a branded QR at any
 *      size; the QR moves to keep the mark.
 *   C. PLAIN, largest that fits — widths strictly below the branded threshold,
 *      `maxWidthPt`-or-just-below down to `minWidthPt`, any position. A cramped
 *      page gets the biggest plain QR it can (`shrunk: true`).
 *   D. CROWDED fallback — nothing clears even at `minWidthPt`: the preferred
 *      corner at `minWidthPt`, clamped on-page, `fallback: true`.
 *
 * So: roomy page → branded QR (logo shows); cramped page → largest plain QR
 * that fits; tiny gap → minimum plain + the fallback flag for a human.
 */
export function chooseGrowToFit(
  obstacles: Box[],
  pageWidthPt: number,
  pageHeightPt: number,
  opts: GrowToFitOptions,
): GrowToFitResult {
  const preferredAnchor = opts.preferredAnchor ?? "bottom-right";
  const maxWidthPt = opts.maxWidthPt ?? GROW_MAX_WIDTH_PT;
  const minWidthPt = opts.minWidthPt ?? GROW_MIN_WIDTH_PT;
  const marginPt = opts.marginPt ?? 18;
  const clearancePt = opts.clearancePt ?? 8;
  if (
    !Number.isFinite(opts.logoTargetPt) ||
    opts.logoTargetPt <= 0 ||
    !Number.isFinite(maxWidthPt) ||
    !Number.isFinite(minWidthPt) ||
    maxWidthPt < minWidthPt ||
    minWidthPt <= 0
  ) {
    throw new Error(
      "chooseGrowToFit: logoTargetPt/minWidthPt must be > 0 and maxWidthPt >= minWidthPt",
    );
  }

  // Probe one exact width via the shared contract (single-width ladder). A
  // free candidate comes back with fallback:false; nothing free → null.
  const probe = (
    w: number,
    preferredOnly: boolean,
  ): SmartPlaceResult | null => {
    const r = chooseClearRect(obstacles, pageWidthPt, pageHeightPt, {
      preferredAnchor,
      qrWidthPt: w,
      minWidthPt: w,
      marginPt,
      clearancePt,
    });
    if (r.fallback) return null;
    if (preferredOnly && r.anchorTried !== preferredAnchor) return null;
    return r;
  };

  // The branded target can't exceed the growth ceiling; when the payload needs
  // more than `maxWidthPt` for the mark, no achievable size is branded.
  const brandedFloor = Math.min(opts.logoTargetPt, maxWidthPt);
  const brandedReachable = opts.logoTargetPt <= maxWidthPt;

  if (brandedReachable) {
    // Phase A: branded, preferred corner, largest that fits.
    for (const w of widthLadder(maxWidthPt, brandedFloor)) {
      const r = probe(w, true);
      if (r) return { ...r, shrunk: false, logoFit: true };
    }
    // Phase B: branded, any corner.
    for (const w of widthLadder(maxWidthPt, brandedFloor)) {
      const r = probe(w, false);
      if (r) return { ...r, shrunk: false, logoFit: true };
    }
  }

  // Phase C: plain, largest that fits — strictly below the branded threshold
  // (so decideBrandedQr agrees the mark is off), any corner.
  const plainHi = Math.min(maxWidthPt, round2(opts.logoTargetPt - 0.5));
  for (const w of widthLadder(plainHi, minWidthPt)) {
    const r = probe(w, false);
    if (r) return { ...r, shrunk: true, logoFit: false };
  }

  // Phase D: crowded — force the preferred corner at minWidthPt (fallback).
  const forced = chooseClearRect(obstacles, pageWidthPt, pageHeightPt, {
    preferredAnchor,
    qrWidthPt: minWidthPt,
    minWidthPt,
    marginPt,
    clearancePt,
  });
  return { ...forced, shrunk: forced.widthPt < opts.logoTargetPt, logoFit: false };
}
