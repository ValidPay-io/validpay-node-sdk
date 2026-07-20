/**
 * Branded-QR contract (Prompt 158) — the shared rule that decides, from
 * payload length and printed size alone, whether a verify QR carries the
 * centered KeyHalve mark (EC-H) or stays plain (EC-M).
 *
 * The FIRST test is the drift guard: src/brandedQr.ts must remain
 * byte-identical to the copies in keyhalve-console, validpay-website, and
 * checkbooks. Change it anywhere, change it everywhere — then update the
 * pinned hash in every repo's guard.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  decideBrandedQr,
  LOGO_MIN_MODULE_MM,
  modulesForPayload,
  QR_MARGIN_MODULES,
  injectKeyhalveMark,
  keyhalveMarkSvg,
} from "../src/brandedQr.js";
import { buildVerifyUrl } from "../src/pdf.js";

/** sha256 of the cross-repo contract file. */
const CONTRACT_SHA256 =
  "ea5d054af32bc4eb6c7014a510adc0fd5cb277052435d1fa6acbf339a9df392d";

// A realistic ValidPay verify URL: vp_ intent id, tenant, anti-fake MAC, and
// a 32-byte key's base64url share in the fragment.
const TYPICAL_URL = buildVerifyUrl(
  "vp_0123456789abcdefghij",
  Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
  { tenant: "validpay", qrMac: "AbCdEfGh1234" },
);

describe("contract file integrity", () => {
  it("src/brandedQr.ts is byte-identical to the cross-repo contract", () => {
    // .gitattributes pins the file to LF so the raw bytes hash identically on
    // every platform (autocrlf would otherwise corrupt the hash on Windows).
    const bytes = readFileSync(new URL("../src/brandedQr.ts", import.meta.url));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(CONTRACT_SHA256);
  });
});

describe("decideBrandedQr", () => {
  const cells = modulesForPayload(TYPICAL_URL.length) + 2 * QR_MARGIN_MODULES;
  const thresholdMm = LOGO_MIN_MODULE_MM * cells;

  it("turns the mark ON at the exact module-pitch threshold", () => {
    const on = decideBrandedQr(TYPICAL_URL, thresholdMm + 0.01);
    expect(on.showLogo).toBe(true);
    expect(on.errorCorrectionLevel).toBe("H");
    expect(on.modulePitchMm).toBeGreaterThanOrEqual(LOGO_MIN_MODULE_MM);
  });

  it("stays plain (EC-M) just below the threshold", () => {
    const off = decideBrandedQr(TYPICAL_URL, thresholdMm - 0.01);
    expect(off.showLogo).toBe(false);
    expect(off.errorCorrectionLevel).toBe("M");
    expect(off.modulePitchMm).toBeLessThan(LOGO_MIN_MODULE_MM);
  });

  it("a 2in placement of a typical verify URL is branded; a 0.5in one is not", () => {
    expect(decideBrandedQr(TYPICAL_URL, 50.8).showLogo).toBe(true);
    expect(decideBrandedQr(TYPICAL_URL, 12.7).showLogo).toBe(false);
  });
});

describe("injectKeyhalveMark", () => {
  it("injects the split-circle mark into a qrcode-shaped SVG", () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 65 65" shape-rendering="crispEdges"><path fill="#ffffff" d="M0 0h65v65H0z"/></svg>`;
    const out = injectKeyhalveMark(svg, TYPICAL_URL);
    expect(out).toContain("<circle");
    expect(out).toContain("<rect");
    expect(out.endsWith("</svg>")).toBe(true);
    expect(out).toContain(keyhalveMarkSvg(65));
  });

  it("fails open (returns the SVG unchanged) on an unexpected shape", () => {
    const weird = `<svg><path d="M0 0"/></svg>`;
    expect(injectKeyhalveMark(weird, TYPICAL_URL)).toBe(weird);
  });
});
