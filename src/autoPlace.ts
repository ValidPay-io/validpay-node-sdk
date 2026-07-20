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
  type SmartPlaceAnchor,
  type SmartPlaceResult,
} from "./smartPlace.js";
import {
  extractPageObstacles,
  type ObstacleBox,
  type PdfJsModuleLike,
  type PdfJsPageLike,
} from "./pdfObstacles.js";
import { ValidPayError } from "./types.js";

/** Tuning knobs for auto placement — the shared contract's options. */
export interface AutoPlacementOptions {
  /** Corner tried first (and used for the fallback). Default "bottom-right". */
  preferredAnchor?: SmartPlaceAnchor;
  /** Requested QR side length, pt. Default 72 (1 in). */
  qrWidthPt?: number;
  /** Inset from the page edges, pt. Default 18. */
  marginPt?: number;
  /** Clear space required around the QR, pt. Default 8. */
  clearancePt?: number;
  /** Smallest width the shrink ladder may reach, pt. Default 54 (0.75 in). */
  minWidthPt?: number;
}

/** One page's smart-place decision (top-left-origin points). */
export interface AutoPlacementDecision extends SmartPlaceResult {
  /** 1-based page the decision applies to. */
  page: number;
  /** Obstacle boxes considered (top-left-origin pt). Empty when the page's
   *  content could not be read (the decision then saw a blank page). */
  obstacleCount: number;
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
 * Compute smart-place decisions for the given 1-based pages of a PDF.
 *
 * Obstacles are extracted with the shared pdfObstacles contract (text runs,
 * images, vector paths where pdf.js exposes bounds); a page whose content
 * cannot be read yields an empty obstacle set (the decision then lands on
 * the preferred corner at full size). Throws `missing_dependency` when
 * pdfjs-dist is not installed and `unsupported_file_type` when the bytes do
 * not parse as a PDF.
 */
export async function computeAutoPlacements(
  pdf: Uint8Array,
  pages: number[],
  opts?: AutoPlacementOptions,
): Promise<AutoPlacementDecision[]> {
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
    const decisions: AutoPlacementDecision[] = [];
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
      const decision = chooseClearRect(
        obstacles,
        viewport.width,
        viewport.height,
        opts,
      );
      decisions.push({ ...decision, page, obstacleCount: obstacles.length });
    }
    return decisions;
  } finally {
    try {
      await doc.destroy();
    } catch {
      // best-effort cleanup
    }
  }
}
