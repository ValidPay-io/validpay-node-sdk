/**
 * Logo-aware grow-to-fit sizing (Prompt 159) — the PURE, deterministic core.
 *
 * chooseGrowToFit reuses the byte-identical chooseClearRect contract as its
 * free-space primitive and adds the grow ladder: roomy page → branded size
 * (logo shows); cramped page → largest plain QR that fits; tiny gap → minimum
 * plain + fallback flag. logoTargetWidthPt derives the branded threshold from
 * the shared branded-QR contract (never hardcoded), and MUST agree with
 * decideBrandedQr at the chosen size.
 */
import { describe, it, expect } from "vitest";
import {
  chooseGrowToFit,
  logoTargetWidthPt,
  GROW_MAX_WIDTH_PT,
  GROW_MIN_WIDTH_PT,
  type Box,
} from "../src/autoPlace.js";
import { buildVerifyUrl } from "../src/pdf.js";
import { decideBrandedQr, PT_PER_MM } from "../src/brandedQr.js";

const W = 612;
const H = 792;

// A representative ValidPay verify URL (~132 chars → 65 cells).
const TYPICAL_URL = buildVerifyUrl(
  "vp_0123456789abcdefghij",
  Buffer.from(new Uint8Array(32).fill(7)).toString("base64"),
  { tenant: "validpay", qrMac: "AbCdEfGh1234" },
);
const TARGET = logoTargetWidthPt(TYPICAL_URL);

describe("logoTargetWidthPt — derived branded threshold (not hardcoded)", () => {
  it("a typical ValidPay URL lands at ~74pt (raw ~73.7pt rounded up to the next 0.5pt)", () => {
    expect(TARGET).toBe(74);
  });

  it("agrees with decideBrandedQr: the mark shows AT the target, not just below it", () => {
    expect(decideBrandedQr(TYPICAL_URL, TARGET / PT_PER_MM).showLogo).toBe(true);
    expect(decideBrandedQr(TYPICAL_URL, (TARGET - 1) / PT_PER_MM).showLogo).toBe(false);
  });

  it("a longer payload needs a larger target (more modules, same pitch)", () => {
    const longer = TYPICAL_URL + "x".repeat(60);
    expect(logoTargetWidthPt(longer)).toBeGreaterThan(TARGET);
  });
});

describe("chooseGrowToFit — grow, dodge, shrink, fall back", () => {
  it("roomy page: grows to the 1.5in ceiling at the preferred corner, logo fits", () => {
    const r = chooseGrowToFit([], W, H, { logoTargetPt: TARGET });
    expect(r.anchorTried).toBe("bottom-right");
    expect(r.widthPt).toBe(GROW_MAX_WIDTH_PT);
    expect(r.logoFit).toBe(true);
    expect(r.shrunk).toBe(false);
    expect(r.fallback).toBe(false);
    // Authoritative contract agrees the mark prints at this size.
    expect(decideBrandedQr(TYPICAL_URL, r.widthPt / PT_PER_MM).showLogo).toBe(true);
  });

  it("keeps the caller's preferred corner when it is clear", () => {
    const r = chooseGrowToFit([], W, H, { logoTargetPt: TARGET, preferredAnchor: "top-left" });
    expect(r.anchorTried).toBe("top-left");
    expect(r.widthPt).toBe(GROW_MAX_WIDTH_PT);
    expect(r.logoFit).toBe(true);
  });

  it("blocked preferred corner: dodges to another corner but STAYS branded (moves to keep the logo)", () => {
    // Bottom-right blocked to every branded size; bottom-left clear.
    const blockBr: Box = { x: 430, y: 630, width: 182, height: 162 };
    const r = chooseGrowToFit([blockBr], W, H, { logoTargetPt: TARGET });
    expect(r.anchorTried).toBe("bottom-left");
    expect(r.logoFit).toBe(true);
    expect(r.widthPt).toBeGreaterThanOrEqual(TARGET);
    expect(r.fallback).toBe(false);
  });

  it("cramped corner (obstacles bracketing every branded spot): shrinks to the largest PLAIN QR that still fits with clearance", () => {
    // Cover the whole page except the bottom ~90pt band → no >=74pt QR clears
    // (its 8pt quiet zone would cross the block), but a ~64pt plain one fits.
    const bracket: Box = { x: 0, y: 0, width: W, height: H - 90 };
    const r = chooseGrowToFit([bracket], W, H, { logoTargetPt: TARGET });
    expect(r.fallback).toBe(false);
    expect(r.shrunk).toBe(true);
    expect(r.logoFit).toBe(false);
    expect(r.widthPt).toBeLessThan(TARGET);
    expect(r.widthPt).toBeGreaterThanOrEqual(GROW_MIN_WIDTH_PT);
    // Plain per the authoritative contract too.
    expect(decideBrandedQr(TYPICAL_URL, r.widthPt / PT_PER_MM).showLogo).toBe(false);
    // Clearance is actually respected: the QR + 8pt quiet zone clears the block.
    expect(r.y - 8).toBeGreaterThanOrEqual(H - 90);
  });

  it("everything blocked: forced fallback = preferred corner at minWidth, flagged", () => {
    const everything: Box = { x: 0, y: 0, width: W, height: H };
    const r = chooseGrowToFit([everything], W, H, { logoTargetPt: TARGET });
    expect(r.fallback).toBe(true);
    expect(r.widthPt).toBe(GROW_MIN_WIDTH_PT);
    expect(r.logoFit).toBe(false);
    expect(r.anchorTried).toBe("bottom-right");
  });

  it("is deterministic: identical inputs → identical output", () => {
    const obstacles: Box[] = [{ x: 100, y: 100, width: 200, height: 150 }];
    const a = chooseGrowToFit(obstacles, W, H, { logoTargetPt: TARGET });
    const b = chooseGrowToFit(obstacles, W, H, { logoTargetPt: TARGET });
    expect(a).toEqual(b);
  });

  it("respects an explicit maxWidthPt ceiling", () => {
    const r = chooseGrowToFit([], W, H, { logoTargetPt: TARGET, maxWidthPt: 90 });
    expect(r.widthPt).toBe(90);
    expect(r.logoFit).toBe(true);
  });

  it("validates its bounds", () => {
    expect(() => chooseGrowToFit([], W, H, { logoTargetPt: 0 })).toThrow();
    expect(() =>
      chooseGrowToFit([], W, H, { logoTargetPt: TARGET, maxWidthPt: 40, minWidthPt: 54 }),
    ).toThrow();
  });
});
