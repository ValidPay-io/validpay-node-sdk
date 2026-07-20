/**
 * KeyHalve branded QR contract (Prompt 158).
 *
 * ONE rule, byte-identical in every repo that renders a verify QR
 * (console, validpay-website, checkbooks, SDKs) — like the placement
 * contract: change it anywhere, change it everywhere.
 *
 * The rule: the QR itself decides whether the center logo appears.
 * Given the payload length and the printed size, if each module still
 * prints large enough for a phone camera WITH the center occluded by
 * the logo (which forces error-correction H), the logo shows. Below
 * that, the QR stays plain (error-correction M, current behavior) —
 * scan reliability always wins over branding.
 *
 * Consequence worth knowing: shortening a payload (e.g. dropping
 * `?t=` once the engine derives brand from the id prefix) can move a
 * small surface across the threshold and the logo appears on it
 * automatically. No per-surface flags anywhere.
 */

/** Byte-mode capacity (chars) per QR version at error-correction H. */
const BYTE_CAP_H = [
  7, 14, 24, 34, 44, 58, 64, 84, 98, 119, 137, 155, 177, 194, 220, 250, 280,
  310, 338, 382, 403, 439, 461, 511, 535, 593, 625, 658, 698, 742, 790, 842,
  898, 958, 983, 1051, 1093, 1139, 1219, 1273,
];

/** Quiet-zone modules per side the renderer draws (qrcode `margin`). */
export const QR_MARGIN_MODULES = 2;

/**
 * Minimum printed module pitch (mm) for logo-on-EC-H to stay reliably
 * phone-scannable. Provisional 0.40mm — calibrate with the physical
 * phone-camera test at 18mm per Prompt 158 before widening rollout.
 */
export const LOGO_MIN_MODULE_MM = 0.4;

/** Logo geometry as fractions of the rendered code edge. */
export const LOGO_DISC_RADIUS_FRAC = 0.125;
export const LOGO_SPLIT_WIDTH_FRAC = 0.014;

export const PT_PER_MM = 72 / 25.4;

/** Modules per side for the smallest EC-H version that fits `chars`. */
export function modulesForPayload(chars: number): number {
  for (let v = 1; v <= BYTE_CAP_H.length; v++) {
    if (chars <= BYTE_CAP_H[v - 1]) return 17 + 4 * v;
  }
  return 17 + 4 * BYTE_CAP_H.length;
}

export interface BrandedQrDecision {
  showLogo: boolean;
  /** 'H' when the logo shows, 'M' otherwise (plain = current behavior). */
  errorCorrectionLevel: 'H' | 'M';
  /** Printed module pitch (mm) at EC-H — what the decision was made on. */
  modulePitchMm: number;
}

/**
 * THE rule. `sizeMm` = printed edge length of the whole QR image
 * (quiet zone included, as the renderers below draw it).
 */
export function decideBrandedQr(
  payload: string,
  sizeMm: number,
): BrandedQrDecision {
  const cells = modulesForPayload(payload.length) + 2 * QR_MARGIN_MODULES;
  const modulePitchMm = sizeMm / cells;
  const showLogo = modulePitchMm >= LOGO_MIN_MODULE_MM;
  return {
    showLogo,
    errorCorrectionLevel: showLogo ? 'H' : 'M',
    modulePitchMm,
  };
}

/**
 * The KeyHalve mark as native SVG shapes: paper disc + ink split line.
 * `viewSize` = the SVG viewBox edge (for the `qrcode` package that is
 * modules + 2×margin, NOT pixels). No <image>, no external refs — safe
 * for jsdom, HTML→PDF, and CSP alike.
 */
export function keyhalveMarkSvg(
  viewSize: number,
  ink = '#000000',
  paper = '#ffffff',
): string {
  const c = viewSize / 2;
  const r = viewSize * LOGO_DISC_RADIUS_FRAC;
  const clr = viewSize * 0.008; // cleared ring so modules never touch the disc
  const gap = Math.max(viewSize * LOGO_SPLIT_WIDTH_FRAC, 0.5);
  return (
    `<g>` +
    `<circle cx="${c}" cy="${c}" r="${(r + clr).toFixed(2)}" fill="${paper}"/>` +
    `<rect x="${(c - gap / 2).toFixed(2)}" y="${(c - r).toFixed(2)}" width="${gap.toFixed(2)}" height="${(2 * r).toFixed(2)}" fill="${ink}"/>` +
    `</g>`
  );
}

/**
 * Inject the mark into an SVG produced by `qrcode`'s toString(type:'svg').
 * That SVG's viewBox is in module units; pass the same payload/margin so
 * the injected mark lands on the exact module grid.
 */
export function injectKeyhalveMark(
  qrSvg: string,
  payload: string,
  ink = '#000000',
  paper = '#ffffff',
): string {
  const m = qrSvg.match(/viewBox="0 0 (\d+(?:\.\d+)?) \d+(?:\.\d+)?"/);
  if (!m) return qrSvg; // unexpected shape — fail open to the plain QR
  return qrSvg.replace(
    /<\/svg>\s*$/,
    keyhalveMarkSvg(parseFloat(m[1]), ink, paper) + '</svg>',
  );
}
