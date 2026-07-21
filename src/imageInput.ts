/**
 * Image → single-page PDF normalization for the seal pipeline.
 *
 * The seal pipeline (reserve → smart-place/branded-QR stamp → encrypt → commit)
 * runs on a PDF. To lift the "PDF-only" limit WITHOUT touching verify /
 * KeyHalve / the ceremony, an IMAGE input is first normalized IN MEMORY into a
 * single-page PDF whose one page IS the image; the existing pipeline then runs
 * unchanged, so the sealed artifact is a normal sealed PDF.
 *
 * Detection is by MAGIC BYTES, never the filename — a `.pdf` that is really a
 * PNG, or a `.jpg` that is really a PDF, is handled by its true bytes.
 *
 * First-class, ZERO extra dependencies (pdf-lib, an existing optional peer,
 * embeds them natively): PDF (passthrough), PNG, JPEG.
 *
 * Needs the OPTIONAL `sharp` peer (lazy, Node-only), which transcodes to PNG in
 * memory first: WebP, TIFF, GIF (first frame). When `sharp` is unavailable
 * (e.g. a browser bundle) these degrade with a clear, actionable error rather
 * than a crash.
 *
 * NOT supported (clear error, never a crash): HEIC/HEIF (a heavy decoder we
 * deliberately do not bundle — convert to JPEG/PNG first) and Office documents
 * (Word/Excel — convert to PDF first). Everything happens in memory: no temp
 * files, no filesystem writes — the transit-only / blindness guarantee holds.
 */

import { ValidPayError } from "./types.js";

/** What the magic bytes say the input actually is. */
export type DetectedInputType =
  | "pdf"
  | "png"
  | "jpeg"
  | "webp"
  | "gif"
  | "tiff"
  | "heic"
  | "office-zip"
  | "unknown";

/** Image types normalized to a single-page PDF before sealing. */
export const SUPPORTED_IMAGE_TYPES = ["png", "jpeg", "webp", "tiff", "gif"] as const;

/** Types the seal STAMPS a QR into directly (PDF, or an image via a one-page
 *  PDF). Anything else is sealed via the sidecar certificate. */
export const STAMPABLE_TYPES: ReadonlySet<DetectedInputType> = new Set<DetectedInputType>([
  "pdf",
  ...SUPPORTED_IMAGE_TYPES,
]);

/** True when the input can carry the QR on the document itself. */
export function isStampable(bytes: Uint8Array): boolean {
  return STAMPABLE_TYPES.has(detectInputType(bytes));
}

/** Recorded `file_content_type` for a NON-stampable (sidecar) original. Known
 *  Office types keep their real MIME (nicer verify UX); everything else is the
 *  universal `application/octet-stream` (the original name carries the
 *  extension for download). */
export function sidecarContentType(fileName: string | undefined): string {
  const ext = (fileName ?? "").toLowerCase().match(/\.([a-z0-9]+)$/)?.[1];
  const OFFICE: Record<string, string> = {
    doc: "application/msword",
    docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint",
    pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  };
  return (ext && OFFICE[ext]) || "application/octet-stream";
}

/** Human list used verbatim in error text and tool descriptions. */
export const SUPPORTED_TYPES_LABEL = "PDF, PNG, JPEG, WebP, TIFF, GIF";

/** Types pdf-lib embeds natively — no extra dependency. */
const NATIVE_IMAGE_TYPES = new Set<DetectedInputType>(["png", "jpeg"]);
/** Types that need `sharp` to transcode to PNG first. */
const SHARP_IMAGE_TYPES = new Set<DetectedInputType>(["webp", "tiff", "gif"]);

// ── Page-geometry policy (points; 1pt = 1/72 in) ─────────────────────────────
// The one page is sized to the image AT 96 DPI, aspect ratio preserved, then
// clamped into a sane document envelope so the default 1in branded QR stays a
// meaningful, scannable fraction of the page (and always fits with its inset).
const ASSUMED_DPI = 96;
/** Below this longest side, scale the page UP (tiny inputs → usable page). */
const MIN_LONG_SIDE_PT = 504; // 7 in
/** Above this longest side, scale the page DOWN (huge photos → bounded page). */
const MAX_LONG_SIDE_PT = 1008; // 14 in
/** The short side never falls below this — guarantees a 1in QR at a 0.5in inset
 *  fits with clear room for the branded mark. Wins over the long-side cap on
 *  extreme aspect ratios (aspect is still preserved; the long side just grows). */
const MIN_SHORT_SIDE_PT = 288; // 4 in

/** Does a magic-byte marker sit at `offset`? */
function matchAt(bytes: Uint8Array, offset: number, marker: number[]): boolean {
  if (offset + marker.length > bytes.length) return false;
  for (let i = 0; i < marker.length; i++) {
    if (bytes[offset + i] !== marker[i]) return false;
  }
  return true;
}

/** `%PDF-` within the first 1 KB (the spec tolerates a small preamble, and so
 *  does pdf-lib). */
function looksLikePdf(bytes: Uint8Array): boolean {
  const marker = [0x25, 0x50, 0x44, 0x46, 0x2d]; // %PDF-
  const limit = Math.min(bytes.length, 1024);
  for (let i = 0; i + marker.length <= limit; i++) {
    if (matchAt(bytes, i, marker)) return true;
  }
  return false;
}

/**
 * Detect the input's true type from its leading bytes. Never reads the file
 * name. Returns `"unknown"` for anything unrecognized.
 */
export function detectInputType(bytes: Uint8Array): DetectedInputType {
  if (bytes.length < 4) return "unknown";
  if (looksLikePdf(bytes)) return "pdf";
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (matchAt(bytes, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  // JPEG: FF D8 FF
  if (matchAt(bytes, 0, [0xff, 0xd8, 0xff])) return "jpeg";
  // GIF: "GIF87a" / "GIF89a"
  if (matchAt(bytes, 0, [0x47, 0x49, 0x46, 0x38])) return "gif";
  // WebP: "RIFF" .... "WEBP"
  if (matchAt(bytes, 0, [0x52, 0x49, 0x46, 0x46]) && matchAt(bytes, 8, [0x57, 0x45, 0x42, 0x50])) {
    return "webp";
  }
  // TIFF: "II*\0" (little-endian) or "MM\0*" (big-endian)
  if (matchAt(bytes, 0, [0x49, 0x49, 0x2a, 0x00]) || matchAt(bytes, 0, [0x4d, 0x4d, 0x00, 0x2a])) {
    return "tiff";
  }
  // ISO-BMFF "ftyp" box at offset 4 → HEIC/HEIF/AVIF family (rejected).
  if (matchAt(bytes, 4, [0x66, 0x74, 0x79, 0x70])) return "heic";
  // ZIP local header "PK\x03\x04" → Office Open XML (docx/xlsx/pptx) & friends.
  if (matchAt(bytes, 0, [0x50, 0x4b, 0x03, 0x04])) return "office-zip";
  return "unknown";
}

/** A short, human label for a detected type (for tool reports). */
export function describeInputType(type: DetectedInputType): string {
  switch (type) {
    case "pdf":
      return "PDF";
    case "png":
      return "PNG image";
    case "jpeg":
      return "JPEG image";
    case "webp":
      return "WebP image";
    case "gif":
      return "GIF image";
    case "tiff":
      return "TIFF image";
    default:
      return "file";
  }
}

/** The clear, actionable rejection for a type we cannot seal. */
function unsupported(type: DetectedInputType): ValidPayError {
  if (type === "heic") {
    return new ValidPayError(
      "unsupported_file_type",
      `HEIC/HEIF images are not supported — convert the photo to JPEG or PNG first ` +
        `(supported: ${SUPPORTED_TYPES_LABEL}).`,
    );
  }
  if (type === "office-zip") {
    return new ValidPayError(
      "unsupported_file_type",
      `This looks like an Office document (Word/Excel/PowerPoint). Convert it to PDF first, ` +
        `then seal the PDF (supported: ${SUPPORTED_TYPES_LABEL}).`,
    );
  }
  return new ValidPayError(
    "unsupported_file_type",
    `Unsupported file type — supported: ${SUPPORTED_TYPES_LABEL}. ` +
      `For Word/Excel, convert to PDF first.`,
  );
}

interface SharpLike {
  (input: Uint8Array, opts?: { animated?: boolean }): {
    png(): { toBuffer(): Promise<Buffer> };
  };
}

/** Lazily load the OPTIONAL `sharp` peer. Absent (or a browser bundle) → a
 *  clear degrade error for the caller, never a crash. */
async function loadSharp(type: DetectedInputType): Promise<SharpLike> {
  try {
    const mod = (await import("sharp")) as unknown as { default?: SharpLike } & SharpLike;
    return (mod.default ?? mod) as SharpLike;
  } catch (cause) {
    throw new ValidPayError(
      "missing_dependency",
      `Sealing ${describeInputType(type)}s needs the optional 'sharp' dependency, which is not ` +
        `available in this environment. Install it (npm i sharp), convert the image to PNG or JPEG ` +
        `first, or seal it through the dashboard wizard.`,
      { cause },
    );
  }
}

interface PdfLibLike {
  PDFDocument: {
    create(): Promise<PdfDocLike>;
  };
}
interface PdfDocLike {
  addPage(size: [number, number]): PdfPageLike;
  embedPng(bytes: Uint8Array): Promise<PdfImageLike>;
  embedJpg(bytes: Uint8Array): Promise<PdfImageLike>;
  save(): Promise<Uint8Array>;
}
interface PdfPageLike {
  drawImage(img: PdfImageLike, o: { x: number; y: number; width: number; height: number }): void;
}
interface PdfImageLike {
  width: number;
  height: number;
}

/** Lazily load pdf-lib (an existing optional peer of this SDK). */
async function loadPdfLib(): Promise<PdfLibLike> {
  try {
    return (await import("pdf-lib")) as unknown as PdfLibLike;
  } catch (cause) {
    throw new ValidPayError(
      "missing_dependency",
      "Sealing an image requires the optional peer dependency 'pdf-lib'. Install it: npm i pdf-lib",
      { cause },
    );
  }
}

/** Clamp the natural (96-DPI) page size into the document envelope, preserving
 *  aspect ratio. Exposed for tests. */
export function pageSizeForImage(pxWidth: number, pxHeight: number): { width: number; height: number } {
  if (!(pxWidth > 0) || !(pxHeight > 0)) {
    throw new ValidPayError("unsupported_file_type", "The image has no readable dimensions.");
  }
  let w = (pxWidth * 72) / ASSUMED_DPI;
  let h = (pxHeight * 72) / ASSUMED_DPI;
  const longest = Math.max(w, h);
  let scale = 1;
  if (longest > MAX_LONG_SIDE_PT) scale = MAX_LONG_SIDE_PT / longest;
  else if (longest < MIN_LONG_SIDE_PT) scale = MIN_LONG_SIDE_PT / longest;
  // The short-side floor wins on extreme aspect ratios (never distort).
  const shortest = Math.min(w, h);
  if (shortest * scale < MIN_SHORT_SIDE_PT) scale = MIN_SHORT_SIDE_PT / shortest;
  return { width: w * scale, height: h * scale };
}

/** Embed a PNG/JPEG buffer as a single full-bleed page and return PDF bytes. */
async function embedImageAsPdf(
  bytes: Uint8Array,
  format: "png" | "jpeg",
): Promise<Uint8Array> {
  const { PDFDocument } = await loadPdfLib();
  const doc = await PDFDocument.create();
  let img: PdfImageLike;
  try {
    img = format === "png" ? await doc.embedPng(bytes) : await doc.embedJpg(bytes);
  } catch (cause) {
    // A malformed (or exotic, e.g. CMYK/progressive JPEG) image pdf-lib can't
    // embed — try to rescue it through sharp if that peer happens to be here,
    // otherwise a clear error.
    try {
      const sharp = await loadSharp(format === "png" ? "png" : "jpeg");
      const png = new Uint8Array(await sharp(bytes).png().toBuffer());
      const doc2 = await PDFDocument.create();
      const rescued = await doc2.embedPng(png);
      const size2 = pageSizeForImage(rescued.width, rescued.height);
      const page2 = doc2.addPage([size2.width, size2.height]);
      page2.drawImage(rescued, { x: 0, y: 0, width: size2.width, height: size2.height });
      return doc2.save();
    } catch {
      throw new ValidPayError(
        "unsupported_file_type",
        `The ${format.toUpperCase()} image could not be decoded — it may be corrupt or use an ` +
          `unsupported variant. Re-export it as a standard PNG or JPEG.`,
        { cause },
      );
    }
  }
  const size = pageSizeForImage(img.width, img.height);
  const page = doc.addPage([size.width, size.height]);
  page.drawImage(img, { x: 0, y: 0, width: size.width, height: size.height });
  return doc.save();
}

/**
 * Normalize any supported seal input to PDF bytes, IN MEMORY.
 *
 *   - PDF → returned unchanged (byte-identical) so the existing path is untouched.
 *   - PNG / JPEG → embedded as a single full-bleed page via pdf-lib (no extra dep).
 *   - WebP / TIFF / GIF(first frame) → transcoded to PNG via the optional `sharp`
 *     peer, then embedded.
 *   - HEIC/HEIF, Office documents, anything unrecognized → a clear
 *     `unsupported_file_type` (or `missing_dependency`) ValidPayError.
 *
 * No temporary files are written; everything lives in this process's memory.
 */
export async function normalizeToPdf(bytes: Uint8Array): Promise<Uint8Array> {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new ValidPayError("invalid_argument", "input bytes must be a non-empty Uint8Array/Buffer");
  }
  const type = detectInputType(bytes);
  if (type === "pdf") return bytes;
  if (NATIVE_IMAGE_TYPES.has(type)) {
    return embedImageAsPdf(bytes, type === "png" ? "png" : "jpeg");
  }
  if (SHARP_IMAGE_TYPES.has(type)) {
    const sharp = await loadSharp(type);
    // `animated: false` keeps only the first frame of a GIF; TIFF reads its
    // first page. All in memory — Buffer in, Buffer out.
    const png = new Uint8Array(await sharp(bytes, { animated: false }).png().toBuffer());
    return embedImageAsPdf(png, "png");
  }
  throw unsupported(type);
}
