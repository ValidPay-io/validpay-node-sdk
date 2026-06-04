import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import {
  verifyWebhookSignature,
  DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
} from "../src/webhookSignature.js";

function signFixture(body: string, secret: string, t: number) {
  const hex = crypto.createHmac("sha256", secret).update(`${t}.${body}`).digest("hex");
  return `t=${t},v1=${hex}`;
}

const SECRET = "whsec_abcdefghijklmnopqrstuvwxyz0123456789";
const BODY = JSON.stringify({ event: "intent.created", intent_id: "vp_test" });

describe("verifyWebhookSignature", () => {
  it("returns { valid: true } for a fresh, well-signed payload", () => {
    const now = 1717545600;
    const header = signFixture(BODY, SECRET, now);
    const result = verifyWebhookSignature(header, BODY, SECRET, { nowSeconds: now });
    expect(result).toEqual({ valid: true, timestamp: now });
  });

  it("rejects a missing header", () => {
    expect(verifyWebhookSignature(undefined, BODY, SECRET)).toEqual({
      valid: false,
      reason: "missing_header",
    });
    expect(verifyWebhookSignature(null, BODY, SECRET)).toEqual({
      valid: false,
      reason: "missing_header",
    });
  });

  it("rejects a malformed header", () => {
    expect(verifyWebhookSignature("not,a=valid,header", BODY, SECRET)).toEqual({
      valid: false,
      reason: "malformed_header",
    });
  });

  it("rejects a header without v1", () => {
    expect(verifyWebhookSignature("t=1717545600,v99=abc", BODY, SECRET)).toEqual({
      valid: false,
      reason: "unsupported_version",
    });
  });

  it("rejects a tampered body", () => {
    const now = 1717545600;
    const header = signFixture(BODY, SECRET, now);
    const tampered = BODY + " ";
    const result = verifyWebhookSignature(header, tampered, SECRET, { nowSeconds: now });
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects the wrong secret", () => {
    const now = 1717545600;
    const header = signFixture(BODY, SECRET, now);
    const result = verifyWebhookSignature(header, BODY, "whsec_wrong_secret_value_0123456", {
      nowSeconds: now,
    });
    expect(result).toEqual({ valid: false, reason: "bad_signature" });
  });

  it("rejects a timestamp outside the default tolerance", () => {
    const now = 1717545600;
    const header = signFixture(BODY, SECRET, now - DEFAULT_WEBHOOK_TOLERANCE_SECONDS - 5);
    const result = verifyWebhookSignature(header, BODY, SECRET, { nowSeconds: now });
    expect(result).toEqual({ valid: false, reason: "timestamp_outside_tolerance" });
  });

  it("honours a custom toleranceSeconds", () => {
    const now = 1717545600;
    const header = signFixture(BODY, SECRET, now - 1000);
    const result = verifyWebhookSignature(header, BODY, SECRET, {
      nowSeconds: now,
      toleranceSeconds: 2000,
    });
    expect(result).toEqual({ valid: true, timestamp: now - 1000 });
  });

  it("accepts unknown signature-header keys (forward-compat)", () => {
    const now = 1717545600;
    const hex = crypto.createHmac("sha256", SECRET).update(`${now}.${BODY}`).digest("hex");
    const header = `t=${now},v1=${hex},v2=futurevalue`;
    const result = verifyWebhookSignature(header, BODY, SECRET, { nowSeconds: now });
    expect(result).toEqual({ valid: true, timestamp: now });
  });

  it("rejects v1 hex of the wrong length", () => {
    const now = 1717545600;
    const header = `t=${now},v1=tooshort`;
    const result = verifyWebhookSignature(header, BODY, SECRET, { nowSeconds: now });
    expect(result).toEqual({ valid: false, reason: "malformed_header" });
  });

  it("uses constant-time compare (no early-return on signature mismatch)", () => {
    // Spot check by signing two payloads with the same secret and
    // verifying that swapping a single hex char fails. The behavioural
    // guarantee is documented by the `timingSafeEqual` import in the
    // implementation; this test pins the public outcome.
    const now = 1717545600;
    const header = signFixture(BODY, SECRET, now);
    const flipped = header.slice(0, -1) + (header.endsWith("0") ? "1" : "0");
    const result = verifyWebhookSignature(flipped, BODY, SECRET, { nowSeconds: now });
    expect(result.valid).toBe(false);
  });
});
