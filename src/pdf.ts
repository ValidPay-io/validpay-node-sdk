/**
 * QR placement helpers (file mode add-on).
 *
 * `createFileIntent` / `createIntent` seal a document and return
 * `{ retrievalId, key }`. To actually verify it, a scannable QR encoding the
 * verify URL must appear ON the document. WHERE that QR goes is the
 * integrator's call — but historically they were on their own to render it
 * and to guess coordinates, which is fiddly and error-prone (PDFs use a
 * bottom-left origin; every screen uses top-left).
 *
 * This module fixes that with one canonical placement contract used by the
 * SDK, the website "Try it" tool, and the docs, so a position you pick once
 * (e.g. in the tool) maps to the exact same spot here.
 *
 * `pdf-lib` and `qrcode` are OPTIONAL peer dependencies — the core
 * `ValidPayClient` stays zero-dependency. They're loaded lazily, so you only
 * need them installed if you call {@link embedQr}:
 *
 *     npm i pdf-lib qrcode
 *
 * The coordinate math ({@link resolveQrRect}) and {@link buildVerifyUrl} are
 * pure and dependency-free — use them directly if you render PDFs with a
 * different library.
 */
import { ValidPayError } from "./types.js";
import { QR_MAC_RE } from "./rail.js";
import {
  decideBrandedQr,
  injectKeyhalveMark,
  PT_PER_MM,
  QR_MARGIN_MODULES,
} from "./brandedQr.js";

// ── Canonical placement contract ───────────────────────────────────────────

/** Which page corner the (x, y) inset is measured from. */
export type QrAnchor = "top-left" | "top-right" | "bottom-left" | "bottom-right";

/** Units for placement values. 1pt = 1/72 inch (PDF's native unit). */
export type QrUnit = "pt" | "mm" | "in";

/**
 * Where to place the QR on a page, in a coordinate system that matches how
 * people actually think about documents:
 *
 *   - `anchor` names a page CORNER.
 *   - `x` is the horizontal inset from that corner's vertical edge.
 *   - `y` is the vertical inset from that corner's horizontal edge.
 *   - The QR's matching corner is pinned at that inset.
 *
 * So `{ anchor: "bottom-right", x: 36, y: 36, width: 90 }` is a 90pt QR sitting
 * 36pt in from the bottom and right edges — and it stays bottom-right on any
 * page size. The default `top-left` anchor reads like screen coordinates.
 */
export interface QrPlacement {
  /** 1-based page number. Default `1`. */
  page?: number;
  /** Page corner the insets are measured from. Default `"top-left"`. */
  anchor?: QrAnchor;
  /** Horizontal inset from the anchor's vertical edge, in `units`. */
  x: number;
  /** Vertical inset from the anchor's horizontal edge, in `units`. */
  y: number;
  /** QR side length (it is square), in `units`. */
  width: number;
  /** Units for `x` / `y` / `width`. Default `"pt"`. */
  units?: QrUnit;
}

const UNIT_TO_PT: Record<QrUnit, number> = { pt: 1, mm: 72 / 25.4, in: 72 };

/**
 * Smallest QR side we consider reliably scannable from a printed page at
 * arm's length (~72pt ≈ 1in ≈ 2.54cm). Below this, {@link embedQr} emits a
 * one-time console warning. Advisory only — not enforced.
 */
export const MIN_RECOMMENDED_QR_PT = 72;

// ── Verify URL ──────────────────────────────────────────────────────────────

export interface VerifyUrlOptions {
  /** Web origin that serves `/verify`. Default `"https://verify.keyhalve.com"`. */
  baseUrl?: string;
  /** Tenant slug for the branded verify page — emitted as `?t=` (e.g. `"validpay"`). */
  tenant?: string;
  /**
   * Anti-fake QR MAC from the CREATION response (`CreateIntentResult.qrMac`) —
   * emitted as `?m=`, before the `#key=` fragment. MANDATORY for End-Cell seals
   * minted under QR-MAC enforcement: the rail gates the document's share behind
   * it, so a QR built without it scans RED. Shape `/^[A-Za-z0-9_-]{8,16}$/`.
   */
  qrMac?: string;
  /**
   * 1-based page number the QR is stamped on — emitted as `p=`, after `t`
   * and `m`. A DISPLAY-ONLY orientation tag for multi-page all-pages seals
   * ("scanned from page N"); it carries NO security meaning and the verify
   * engine ignores it entirely. Omit for single-page documents and
   * single-page placements.
   */
  page?: number;
}

/** base64 → base64url. Phone QR scanners and share-sheets mangle `+`, `/`,
 *  and `=` inside URL fragments, so keys must be base64url in a QR. Idempotent
 *  on already-base64url input; the `/verify` page accepts both. */
function toBase64Url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Build the canonical verify URL the QR encodes (converged shape):
 *
 *     <baseUrl>/verify/<retrievalId>[?t=<tenant>][&m=<qrMac>][&p=<page>]#key=<base64url(key)>
 *
 * Query params come in the order `t`, `m`, `p` and are omitted when absent —
 * with none given the legacy bare shape is emitted byte-identically.
 * `m` is the rail-minted anti-fake QR MAC from the creation response
 * (`CreateIntentResult.qrMac`); MAC-gated documents scan RED without it.
 * `p` is the display-only page tag of all-pages seals (never a security
 * claim; the attested verify engine ignores it).
 *
 * The key is placed in the URL FRAGMENT (`#key=`), which browsers never send
 * to any server — so the decryption share rides along with the scan without
 * ever touching ValidPay's logs. The key is converted to base64url so phone
 * scanners don't mangle it.
 */
export function buildVerifyUrl(
  retrievalId: string,
  key: string,
  opts: VerifyUrlOptions = {},
): string {
  if (!retrievalId) {
    throw new ValidPayError("invalid_argument", "retrievalId is required");
  }
  if (!key) {
    throw new ValidPayError("invalid_argument", "key is required");
  }
  if (opts.qrMac !== undefined && !QR_MAC_RE.test(opts.qrMac)) {
    throw new ValidPayError(
      "invalid_argument",
      "qrMac must be the creation response's qr_mac (8–16 chars of [A-Za-z0-9_-])",
    );
  }
  if (opts.tenant !== undefined && opts.tenant === "") {
    throw new ValidPayError("invalid_argument", "tenant must be non-empty when given");
  }
  if (
    opts.page !== undefined &&
    (!Number.isInteger(opts.page) || opts.page < 1)
  ) {
    throw new ValidPayError(
      "invalid_argument",
      "page must be a positive integer (1-based page number) when given",
    );
  }
  const base = (opts.baseUrl ?? "https://verify.keyhalve.com").replace(/\/+$/, "");
  const params: string[] = [];
  if (opts.tenant !== undefined) params.push(`t=${encodeURIComponent(opts.tenant)}`);
  if (opts.qrMac !== undefined) params.push(`m=${encodeURIComponent(opts.qrMac)}`);
  if (opts.page !== undefined) params.push(`p=${opts.page}`);
  const query = params.length > 0 ? `?${params.join("&")}` : "";
  return `${base}/verify/${encodeURIComponent(retrievalId)}${query}#key=${toBase64Url(key)}`;
}

// ── Coordinate math (the single source of truth) ────────────────────────────

/** A QR rectangle in pdf-lib's bottom-left-origin point space. */
export interface ResolvedQrRect {
  /** Distance from the page's LEFT edge to the QR's left edge, in points. */
  x: number;
  /** Distance from the page's BOTTOM edge to the QR's bottom edge, in points. */
  y: number;
  /** QR side length, in points. */
  size: number;
}

/**
 * Convert a canonical {@link QrPlacement} (top-left-friendly, anchor-relative
 * insets, arbitrary units) into pdf-lib's bottom-left-origin point rectangle
 * for a page of the given size.
 *
 * This is the EXACT conversion the website "Try it" tool uses, so coordinates
 * you copy from the tool land in the same place here. Pure and
 * dependency-free.
 */
export function resolveQrRect(
  placement: QrPlacement,
  pageWidthPt: number,
  pageHeightPt: number,
): ResolvedQrRect {
  const unit = UNIT_TO_PT[placement.units ?? "pt"];
  const size = placement.width * unit;
  const insetX = placement.x * unit;
  const insetY = placement.y * unit;
  const anchor = placement.anchor ?? "top-left";

  const leftAnchored = anchor === "top-left" || anchor === "bottom-left";
  const topAnchored = anchor === "top-left" || anchor === "top-right";

  // Horizontal: inset measured from the left or right edge to the QR's left.
  const x = leftAnchored ? insetX : pageWidthPt - insetX - size;
  // Vertical: pdf-lib y is the QR's BOTTOM edge from the page bottom. A top
  // inset measures from the page top down to the QR's top edge.
  const y = topAnchored ? pageHeightPt - insetY - size : insetY;

  return { x, y, size };
}

// ── embedQr (optional pdf-lib + qrcode) ─────────────────────────────────────

export interface QrRenderOptions {
  /**
   * Error-correction level OVERRIDE. When omitted (the default), the shared
   * branded-QR contract ({@link decideBrandedQr}, Prompt 158) picks the level
   * from the payload and printed size: `"H"` with the centered KeyHalve mark
   * when every module still prints ≥ 0.4 mm, `"M"` plain below that.
   * Setting this explicitly opts OUT of the contract: the QR renders plain at
   * exactly this level (legacy behavior) — except `"H"`, which keeps the mark
   * when the size allows it.
   */
  errorCorrectionLevel?: "L" | "M" | "Q" | "H";
  /** Quiet-zone width in modules. Default `2` (the branded contract's
   *  `QR_MARGIN_MODULES`). Any other value renders a plain QR (the contract's
   *  size math assumes its own margin). Don't go below 1 or scanners struggle. */
  margin?: number;
  /** Foreground (module + mark ink) color. Default `"#0A0F1E"`. */
  darkColor?: string;
  /** Background (and mark paper) color. Default `"#FFFFFF"` — keep it opaque
   *  for contrast. */
  lightColor?: string;
  /**
   * LEGACY — ignored. The QR (and the KeyHalve mark) are drawn as native PDF
   * vector art now, which is resolution-independent; nothing is rasterized.
   * Kept so existing call sites keep compiling.
   */
  renderPx?: number;
}

/** How {@link embedQr} / {@link renderBrandedQrSvg} actually rendered a QR. */
export interface QrBrandingInfo {
  /** `true` when the centered KeyHalve mark was drawn into the QR. */
  branded: boolean;
  /** Error-correction level actually used. */
  errorCorrectionLevel: "L" | "M" | "Q" | "H";
  /** Printed module pitch (mm) at EC-H the contract decision was made on. */
  modulePitchMm: number;
}

export interface EmbedQrOptions {
  /** From `createIntent` / `createFileIntent`. */
  retrievalId: string;
  /** Share A from `createIntent` / `createFileIntent`. */
  key: string;
  /** Where to stamp the QR. */
  placement: QrPlacement;
  /** Verify URL base. Default `"https://verify.keyhalve.com"`. */
  baseUrl?: string;
  /** Tenant slug for the branded verify page (`?t=`). */
  tenant?: string;
  /** Anti-fake QR MAC from `createEndCellIntent` (`CreateIntentResult.qrMac`) —
   *  REQUIRED for MAC-gated seals or the stamped QR scans RED. */
  qrMac?: string;
  /** Display-only page tag (`&p=`) for all-pages seals — the 1-based page
   *  THIS QR is stamped on. See {@link VerifyUrlOptions.page}. */
  pageTag?: number;
  /** QR rendering tweaks. */
  qr?: QrRenderOptions;
}

let smallQrWarned = false;

/**
 * Stamp a scannable verify QR onto an existing PDF and return the new PDF
 * bytes. The input is not mutated.
 *
 * The QR is drawn as native PDF VECTOR art (background, modules, and — when
 * the shared branded-QR contract allows it — the centered KeyHalve
 * split-circle mark), so it stays crisp at any zoom/print resolution. Whether
 * the mark appears is decided by {@link decideBrandedQr} (Prompt 158) from
 * the payload and the printed size alone: large enough placements get EC-H +
 * mark, small ones stay plain EC-M exactly like before. No flags.
 *
 * Requires the optional peer deps `pdf-lib` and `qrcode` (`npm i pdf-lib
 * qrcode`); it throws a `missing_dependency` ValidPayError if either is
 * absent. Works in Node and the browser (both libs are isomorphic).
 *
 * @example
 * const { retrievalId, key } = await client.createFileIntent({ documentType: "invoice", file });
 * const sealed = await embedQr(originalPdfBytes, {
 *   retrievalId, key,
 *   placement: { anchor: "bottom-right", x: 36, y: 36, width: 90 },
 * });
 */
export async function embedQr(
  pdf: Uint8Array,
  opts: EmbedQrOptions,
): Promise<Uint8Array> {
  if (!(pdf instanceof Uint8Array) || pdf.length === 0) {
    throw new ValidPayError("invalid_argument", "pdf must be non-empty Uint8Array/Buffer bytes");
  }
  if (!opts?.placement) {
    throw new ValidPayError("invalid_argument", "placement is required");
  }
  if (!(opts.placement.width > 0)) {
    throw new ValidPayError("invalid_argument", "placement.width must be > 0");
  }

  const pdfLib = await loadPdfLib();
  const qrcode = await loadQrcode();

  const url = buildVerifyUrl(opts.retrievalId, opts.key, {
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
    ...(opts.tenant !== undefined ? { tenant: opts.tenant } : {}),
    ...(opts.qrMac !== undefined ? { qrMac: opts.qrMac } : {}),
    ...(opts.pageTag !== undefined ? { page: opts.pageTag } : {}),
  });
  const q = opts.qr ?? {};

  const doc = await pdfLib.PDFDocument.load(pdf);
  const pages = doc.getPages();
  const pageIndex = (opts.placement.page ?? 1) - 1;
  if (pageIndex < 0 || pageIndex >= pages.length) {
    throw new ValidPayError(
      "invalid_argument",
      `placement.page ${opts.placement.page ?? 1} is out of range (document has ${pages.length} page(s))`,
    );
  }
  const page = pages[pageIndex]!;
  const { width, height } = page.getSize();
  const rect = resolveQrRect(opts.placement, width, height);

  if (rect.size < MIN_RECOMMENDED_QR_PT && !smallQrWarned) {
    smallQrWarned = true;
    // eslint-disable-next-line no-console
    console.warn(
      `[validpay] QR is ${rect.size.toFixed(0)}pt wide — below the ~${MIN_RECOMMENDED_QR_PT}pt ` +
        "(1in) recommended minimum; it may be hard to scan once printed.",
    );
  }
  if (rect.x < 0 || rect.y < 0 || rect.x + rect.size > width || rect.y + rect.size > height) {
    throw new ValidPayError(
      "invalid_argument",
      "placement puts the QR (partly) off the page — check x/y/width against the page size",
    );
  }

  // The branded contract decides EC level + mark from payload and printed
  // size; the mark's geometry is parsed back out of the contract's own SVG so
  // this stays pixel-consistent with the console/website/checkbooks renderers.
  const built = await buildBrandedQr(qrcode, url, rect.size, q);
  drawQrVector(page, pdfLib.rgb, rect, built, q);
  return doc.save();
}

/**
 * Render the verify QR exactly as {@link embedQr} decides it, but as the
 * branded-contract SVG string (the `qrcode` SVG with the KeyHalve mark
 * injected when the contract says so). `sizePt` is the printed edge length in
 * points the decision is made for. Useful for previews and tests; requires
 * the optional peer dep `qrcode`.
 */
export async function renderBrandedQrSvg(
  url: string,
  sizePt: number,
  qr: QrRenderOptions = {},
): Promise<{ svg: string; branding: QrBrandingInfo }> {
  if (!url) throw new ValidPayError("invalid_argument", "url is required");
  if (!(sizePt > 0)) {
    throw new ValidPayError("invalid_argument", "sizePt must be > 0");
  }
  const qrcode = await loadQrcode();
  const { svg, branding } = await buildBrandedQr(qrcode, url, sizePt, qr);
  return { svg, branding };
}

/** One page's media-box size, in points. */
export interface PdfPageSize {
  width: number;
  height: number;
}

/**
 * Read the page sizes (points) of a PDF — the geometry `sealDocument` needs
 * to convert a canonical {@link QrPlacement} into the commit contract's
 * center-percent `qr_placement` record. Requires the optional peer dep
 * `pdf-lib` (same lazy load as {@link embedQr}); the input is not mutated.
 */
export async function readPdfPageSizes(pdf: Uint8Array): Promise<PdfPageSize[]> {
  if (!(pdf instanceof Uint8Array) || pdf.length === 0) {
    throw new ValidPayError("invalid_argument", "pdf must be non-empty Uint8Array/Buffer bytes");
  }
  const { PDFDocument } = await loadPdfLib();
  const doc = await PDFDocument.load(pdf);
  return doc.getPages().map((p) => p.getSize());
}

// ── internals ───────────────────────────────────────────────────────────────

const DEFAULT_DARK = "#0A0F1E";
const DEFAULT_LIGHT = "#FFFFFF";

interface BuiltQr {
  /** The contract-path SVG: `qrcode` toString(type:'svg') output, with the
   *  KeyHalve mark injected when branded. Source of truth for the mark's
   *  geometry (parsed back out by {@link drawQrVector}). */
  svg: string;
  branding: QrBrandingInfo;
  /** The QR module bitmap (`qrcode.create().modules`) — same library, same
   *  payload, same EC level as the SVG, so the exact same matrix. */
  matrix: { size: number; data: ArrayLike<number> };
  /** Quiet-zone modules per side actually rendered. */
  margin: number;
}

/**
 * Build the QR for a printed edge of `sizePt` points: apply the shared
 * branded-QR contract (Prompt 158) unless the caller explicitly overrode the
 * EC level or quiet zone, produce the contract SVG, and grab the module
 * matrix for vector drawing.
 */
async function buildBrandedQr(
  qrcode: QrcodeModule,
  url: string,
  sizePt: number,
  q: QrRenderOptions,
): Promise<BuiltQr> {
  const margin = q.margin ?? QR_MARGIN_MODULES;
  const dark = q.darkColor ?? DEFAULT_DARK;
  const light = q.lightColor ?? DEFAULT_LIGHT;

  const contract = decideBrandedQr(url, sizePt / PT_PER_MM);
  // The contract owns the decision unless the caller explicitly opted out:
  // a custom quiet zone breaks its size math, and a non-H EC override cannot
  // carry a center mark (the mark occludes ~EC-H-level modules).
  let branded =
    contract.showLogo &&
    margin === QR_MARGIN_MODULES &&
    (q.errorCorrectionLevel === undefined || q.errorCorrectionLevel === "H");
  const errorCorrectionLevel = q.errorCorrectionLevel ?? contract.errorCorrectionLevel;

  let svg: string = await qrcode.toString(url, {
    type: "svg",
    errorCorrectionLevel,
    margin,
    color: { dark, light },
  });
  if (branded) {
    svg = injectKeyhalveMark(svg, url, dark, light);
    // injectKeyhalveMark fails open (returns the SVG unchanged) on an
    // unexpected SVG shape — keep `branded` honest in that case.
    branded = svg.includes("<circle");
  }
  const matrix = qrcode.create(url, { errorCorrectionLevel }).modules;
  return {
    svg,
    branding: { branded, errorCorrectionLevel, modulePitchMm: contract.modulePitchMm },
    matrix,
    margin,
  };
}

/**
 * Draw a built QR as native PDF vector art inside `rect`: opaque background,
 * dark modules as merged horizontal-run rectangles, and — when branded — the
 * KeyHalve mark, whose disc/split geometry is parsed from the contract's own
 * injected SVG (so the mark placed here is BY CONSTRUCTION the one the other
 * renderers show).
 */
function drawQrVector(
  page: PdfLibPage,
  rgb: PdfLibRgb,
  rect: ResolvedQrRect,
  built: BuiltQr,
  q: QrRenderOptions,
): void {
  const darkColor = rgb(...hexToRgb01(q.darkColor ?? DEFAULT_DARK));
  const lightColor = rgb(...hexToRgb01(q.lightColor ?? DEFAULT_LIGHT));
  const n = built.matrix.size;
  const cells = n + 2 * built.margin;
  const pitch = rect.size / cells;

  // Background (quiet zone included) — opaque for scanner contrast.
  page.drawRectangle({
    x: rect.x,
    y: rect.y,
    width: rect.size,
    height: rect.size,
    color: lightColor,
  });

  // Dark modules, horizontal runs merged into single rectangles.
  const data = built.matrix.data;
  for (let row = 0; row < n; row++) {
    let col = 0;
    while (col < n) {
      if (!data[row * n + col]) {
        col++;
        continue;
      }
      let end = col;
      while (end < n && data[row * n + end]) end++;
      page.drawRectangle({
        x: rect.x + (built.margin + col) * pitch,
        y: rect.y + rect.size - (built.margin + row + 1) * pitch,
        width: (end - col) * pitch,
        height: pitch,
        color: darkColor,
      });
      col = end;
    }
  }

  if (!built.branding.branded) return;

  // The KeyHalve mark: paper disc + ink split line, geometry parsed from the
  // injected contract SVG (viewBox units = cells). SVG y grows down; PDF y
  // grows up.
  const circle = built.svg.match(
    /<circle cx="([\d.]+)" cy="([\d.]+)" r="([\d.]+)"/,
  );
  const split = built.svg.match(
    /<rect x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"/,
  );
  if (!circle || !split) return; // mark shape unexpectedly absent — QR stays scannable
  page.drawCircle({
    x: rect.x + parseFloat(circle[1]!) * pitch,
    y: rect.y + rect.size - parseFloat(circle[2]!) * pitch,
    size: parseFloat(circle[3]!) * pitch,
    color: lightColor,
  });
  page.drawRectangle({
    x: rect.x + parseFloat(split[1]!) * pitch,
    y: rect.y + rect.size - (parseFloat(split[2]!) + parseFloat(split[4]!)) * pitch,
    width: parseFloat(split[3]!) * pitch,
    height: parseFloat(split[4]!) * pitch,
    color: darkColor,
  });
}

/** `#RGB` / `#RRGGBB` / `#RRGGBBAA` → [r, g, b] in 0..1 (alpha ignored —
 *  QR surfaces must stay opaque). */
function hexToRgb01(hex: string): [number, number, number] {
  const h = hex.trim().replace(/^#/, "");
  const six =
    h.length === 3
      ? h.split("").map((c) => c + c).join("")
      : h.length === 8
        ? h.slice(0, 6)
        : h;
  if (!/^[0-9a-fA-F]{6}$/.test(six)) {
    throw new ValidPayError(
      "invalid_argument",
      `QR colors must be hex (#RGB or #RRGGBB) — got "${hex}"`,
    );
  }
  return [
    parseInt(six.slice(0, 2), 16) / 255,
    parseInt(six.slice(2, 4), 16) / 255,
    parseInt(six.slice(4, 6), 16) / 255,
  ];
}

interface PdfLibPage {
  getSize: () => { width: number; height: number };
  drawRectangle: (o: {
    x: number;
    y: number;
    width: number;
    height: number;
    color: unknown;
  }) => void;
  drawCircle: (o: { x: number; y: number; size: number; color: unknown }) => void;
}

type PdfLibRgb = (r: number, g: number, b: number) => unknown;

interface PdfLibModule {
  PDFDocument: {
    load: (bytes: Uint8Array) => Promise<{
      getPages: () => PdfLibPage[];
      save: () => Promise<Uint8Array>;
    }>;
  };
  rgb: PdfLibRgb;
}

interface QrcodeModule {
  toString: (text: string, opts?: unknown) => Promise<string>;
  create: (text: string, opts?: unknown) => {
    modules: { size: number; data: ArrayLike<number> };
  };
}

async function loadPdfLib(): Promise<PdfLibModule> {
  try {
    return (await import("pdf-lib")) as unknown as PdfLibModule;
  } catch {
    throw new ValidPayError(
      "missing_dependency",
      "embedQr requires the optional peer dependency 'pdf-lib'. Install it: npm i pdf-lib",
    );
  }
}

async function loadQrcode(): Promise<QrcodeModule> {
  try {
    const mod = (await import("qrcode")) as unknown as { default?: QrcodeModule } & QrcodeModule;
    return (mod.default ?? mod) as QrcodeModule;
  } catch {
    throw new ValidPayError(
      "missing_dependency",
      "embedQr requires the optional peer dependency 'qrcode'. Install it: npm i qrcode",
    );
  }
}
