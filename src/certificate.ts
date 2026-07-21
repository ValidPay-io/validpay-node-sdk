/**
 * Sidecar seal certificate — the QR carrier for NON-STAMPABLE files.
 *
 * A PDF or an image can carry the verify QR ON the document itself. A Word/
 * Excel/PowerPoint file (or any other binary) cannot be stamped — and we will
 * NOT convert it (that would ship the customer's plaintext through a converter
 * and break the transit-only / blindness guarantee). Instead, the ORIGINAL
 * bytes are sealed as-is (encrypted + committed) and a SEPARATE, generated
 * certificate PDF carries the branded verify QR plus a human-readable summary.
 *
 * The certificate is NOT the stored artifact: scanning its QR reconstructs the
 * key and decrypts the stored ciphertext, which is the UNTOUCHED original —
 * the exact same scan → decrypt → view flow as a stamped PDF. The receiver
 * gets both the original file and this certificate.
 *
 * Everything is built in memory with pdf-lib (an optional peer). The QR is
 * drawn by the shared {@link embedQr} path, so it is byte-for-byte the branded/
 * adaptive QR every other surface produces.
 */

import { ValidPayError } from "./types.js";
import { embedQr, resolveQrRect, type QrPlacement } from "./pdf.js";
import { decideBrandedQr, PT_PER_MM } from "./brandedQr.js";

/** A disclosed key/value the issuer chose to show verifiers, for the summary. */
export interface CertificateField {
  label: string;
  value: string;
}

export interface CertificateInfo {
  /** Reserved intent id (`vp_…`). */
  intentId: string;
  /** ShareA — encoded into the QR's `#key=` fragment (never printed as text). */
  key: string;
  /** Full verify URL (contains the key) the QR encodes. */
  verifyUrl: string;
  /** Key-FREE verification URL, printed on the certificate for humans. */
  verificationUrl: string;
  /** The original file's name, e.g. `"Q3-report.xlsx"`. */
  fileName: string;
  /** Document type, e.g. `"invoice"`, `"contract"`. */
  documentType: string;
  /** When the seal was made. Default: now. */
  sealedAt?: Date;
  /** Issuing organization display name, when the caller knows it. */
  issuerName?: string;
  /** Disclosed plaintext fields to summarize (reference, notes, …). */
  disclosedFields?: CertificateField[];
  /** Tenant slug for the QR's `?t=`. */
  tenant?: string;
  /** Anti-fake QR MAC for the QR's `?m=`. */
  qrMac?: string;
  /** Verify-page origin the QR is built against. */
  baseUrl?: string;
}

export interface CertificateResult {
  /** The certificate PDF bytes (single page). */
  pdf: Uint8Array;
  /** How the certificate's QR was rendered (branded contract decision). */
  brandedQr: { branded: boolean; errorCorrectionLevel: "H" | "M"; modulePitchMm: number };
  /** Where the authentic QR sits on the certificate, in the commit contract's
   *  center-percent + width-pt convention (recorded as qr_placement). */
  qrPlacement: { page: number; x: number; y: number; width: number };
}

const PAGE_W = 612; // US Letter, points
const PAGE_H = 792;
const MARGIN = 54; // 0.75in
const INK = [0.039, 0.059, 0.118] as const; // #0A0F1E
const MUTED = [0.42, 0.45, 0.5] as const;
const RULE = [0.85, 0.87, 0.9] as const;

/** Certificate QR: 1.6in — comfortably above the branded-mark threshold. */
const QR_WIDTH_PT = 1.6 * 72;

interface PdfFont {
  widthOfTextAtSize(text: string, size: number): number;
}

async function loadPdfLib() {
  try {
    return await import("pdf-lib");
  } catch (cause) {
    throw new ValidPayError(
      "missing_dependency",
      "Building a seal certificate requires the optional peer dependency 'pdf-lib'. Install it: npm i pdf-lib",
      { cause },
    );
  }
}

/** Break `text` into lines no wider than `maxWidth` at `size` (word wrap; a
 *  single over-long token is hard-split so it can never overflow). */
function wrapText(text: string, font: PdfFont, size: number, maxWidth: number): string[] {
  const out: string[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const words = rawLine.split(/\s+/).filter(Boolean);
    if (words.length === 0) {
      out.push("");
      continue;
    }
    let line = "";
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) <= maxWidth || line === "") {
        // Hard-split a single word that alone exceeds the width.
        if (line === "" && font.widthOfTextAtSize(word, size) > maxWidth) {
          let chunk = "";
          for (const ch of word) {
            if (font.widthOfTextAtSize(chunk + ch, size) > maxWidth && chunk) {
              out.push(chunk);
              chunk = ch;
            } else {
              chunk += ch;
            }
          }
          line = chunk;
        } else {
          line = candidate;
        }
      } else {
        out.push(line);
        line = word;
      }
    }
    if (line) out.push(line);
  }
  return out;
}

/** Truncate a value for a single summary line so the certificate stays tidy. */
function clip(value: string, max = 240): string {
  const v = value.replace(/\s+/g, " ").trim();
  return v.length > max ? `${v.slice(0, max - 1)}…` : v;
}

/**
 * Build the sidecar seal certificate PDF for a non-stampable file.
 */
export async function buildCertificatePdf(info: CertificateInfo): Promise<CertificateResult> {
  if (!info.intentId || !info.key || !info.verifyUrl) {
    throw new ValidPayError("invalid_argument", "certificate needs intentId, key and verifyUrl");
  }
  const { PDFDocument, StandardFonts, rgb } = await loadPdfLib();
  const doc = await PDFDocument.create();
  const page = doc.addPage([PAGE_W, PAGE_H]);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);

  const ink = rgb(...INK);
  const muted = rgb(...MUTED);
  const rule = rgb(...RULE);

  const draw = (text: string, x: number, y: number, size: number, f = font, color = ink) =>
    page.drawText(text, { x, y, size, font: f, color });

  let y = PAGE_H - MARGIN;

  // ── Header ─────────────────────────────────────────────────────────────
  draw("SEALED CERTIFICATE", MARGIN, y - 20, 22, bold);
  y -= 30;
  draw("Cryptographically sealed with ValidPay · KeyHalve", MARGIN, y - 12, 10.5, font, muted);
  y -= 24;
  page.drawLine({
    start: { x: MARGIN, y },
    end: { x: PAGE_W - MARGIN, y },
    thickness: 1,
    color: rule,
  });

  // ── QR (top-right, under the header rule) via the shared branded path ───
  const qrInsetRight = MARGIN;
  const qrInsetTop = PAGE_H - y + 14; // just below the rule
  const placement: QrPlacement = {
    anchor: "top-right",
    x: qrInsetRight,
    y: qrInsetTop,
    width: QR_WIDTH_PT,
    units: "pt",
  };
  // Reserve the QR block on the left-column layout (text wraps before it).
  const qrLeftEdge = PAGE_W - MARGIN - QR_WIDTH_PT;
  const textRight = qrLeftEdge - 18;
  const textWidth = textRight - MARGIN;

  // ── Body: labeled summary rows (left column, clear of the QR) ──────────
  y -= 26;
  const sealedAt = info.sealedAt ?? new Date();
  const rows: CertificateField[] = [
    { label: "File", value: clip(info.fileName, 90) },
    { label: "Document type", value: clip(info.documentType, 90) },
    ...(info.issuerName ? [{ label: "Issued by", value: clip(info.issuerName, 90) }] : []),
    { label: "Sealed", value: sealedAt.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") },
    { label: "Verification ID", value: info.intentId },
  ];
  for (const f of info.disclosedFields ?? []) {
    if (f.value !== undefined && f.value !== null && String(f.value).trim() !== "") {
      rows.push({ label: clip(f.label, 40), value: clip(String(f.value)) });
    }
  }

  const LABEL_SIZE = 8.5;
  const VALUE_SIZE = 11;
  for (const row of rows) {
    if (y < MARGIN + 120) break; // never collide with the footer
    draw(row.label.toUpperCase(), MARGIN, y, LABEL_SIZE, bold, muted);
    y -= 13;
    const lines = wrapText(row.value, font, VALUE_SIZE, Math.max(120, textWidth));
    for (const line of lines) {
      if (y < MARGIN + 110) break;
      draw(line, MARGIN, y, VALUE_SIZE, font, ink);
      y -= 15;
    }
    y -= 8;
  }

  // ── Footer: how to verify (key-free URL; the KEY rides only in the QR) ──
  const footY = MARGIN + 46;
  page.drawLine({
    start: { x: MARGIN, y: footY + 20 },
    end: { x: PAGE_W - MARGIN, y: footY + 20 },
    thickness: 1,
    color: rule,
  });
  draw("Scan the QR to verify this document and download the authentic original.", MARGIN, footY + 4, 9.5, font, ink);
  const urlLines = wrapText(`Verify: ${info.verificationUrl}`, font, 8.5, PAGE_W - 2 * MARGIN);
  let fy = footY - 10;
  for (const line of urlLines.slice(0, 2)) {
    draw(line, MARGIN, fy, 8.5, font, muted);
    fy -= 11;
  }

  const base = await doc.save();

  // ── Stamp the branded QR onto the certificate (shared contract path) ───
  const stamped = await embedQr(base, {
    retrievalId: info.intentId,
    key: info.key,
    placement,
    ...(info.baseUrl !== undefined ? { baseUrl: info.baseUrl } : {}),
    ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
    ...(info.qrMac !== undefined ? { qrMac: info.qrMac } : {}),
  });

  // "Scan to verify" caption centered under the QR.
  const doc2 = await PDFDocument.load(stamped);
  const page2 = doc2.getPage(0);
  const capFont = await doc2.embedFont(StandardFonts.HelveticaBold);
  const rect = resolveQrRect(placement, PAGE_W, PAGE_H);
  const caption = "SCAN TO VERIFY";
  const capSize = 9;
  const capWidth = capFont.widthOfTextAtSize(caption, capSize);
  page2.drawText(caption, {
    x: rect.x + rect.size / 2 - capWidth / 2,
    y: rect.y - 14,
    size: capSize,
    font: capFont,
    color: rgb(...INK),
  });
  const finalPdf = await doc2.save();

  const brand = decideBrandedQr(info.verifyUrl, rect.size / PT_PER_MM);
  return {
    pdf: finalPdf,
    brandedQr: {
      branded: brand.showLogo,
      errorCorrectionLevel: brand.errorCorrectionLevel,
      modulePitchMm: brand.modulePitchMm,
    },
    qrPlacement: {
      page: 1,
      x: Math.min(100, Math.max(0, ((rect.x + rect.size / 2) / PAGE_W) * 100)),
      y: Math.min(100, Math.max(0, ((PAGE_H - rect.y - rect.size / 2) / PAGE_H) * 100)),
      width: Math.round(rect.size),
    },
  };
}
