/**
 * Webhook signature verification (Prompt 079).
 *
 * Mirrors `ValidPay-API/src/services/webhookSignature.ts` so SDK
 * customers can verify inbound webhooks with one import instead of
 * rolling their own constant-time compare.
 *
 * Wire format
 * -----------
 *   X-ValidPay-Signature: t=<unix-seconds>,v1=<hex-hmac>
 *
 * The HMAC is computed over the EXACT bytes of `${t}.${rawBody}` using
 * the per-webhook secret. The timestamp inside the signed payload
 * bounds the replay window — even if an attacker captures a delivered
 * request, they can't replay it more than `toleranceSeconds` later.
 *
 * IMPORTANT
 * ---------
 *   `rawBody` MUST be the unparsed body string the framework gave you.
 *   `JSON.parse(body).toString()` is NOT equivalent — it loses key order
 *   and whitespace and the HMAC won't match.
 *
 * Express example
 * ---------------
 *   app.post(
 *     "/webhooks/validpay",
 *     express.raw({ type: "application/json" }),  // <- RAW, not json()
 *     (req, res) => {
 *       const result = verifyWebhookSignature(
 *         req.headers["x-validpay-signature"],
 *         req.body.toString("utf8"),
 *         process.env.VALIDPAY_WEBHOOK_SECRET!,
 *       );
 *       if (!result.valid) return res.status(401).send(result.reason);
 *       const event = JSON.parse(req.body.toString("utf8"));
 *       // ... handle event ...
 *       res.status(200).send("OK");
 *     },
 *   );
 */

import crypto from "node:crypto";

/** Default replay-protection window. 5 minutes matches the API side. */
export const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;

export interface VerifyWebhookOptions {
  /**
   * Reject signatures older than this many seconds. Default 300.
   * Pass `Infinity` to disable — only safe for tests.
   */
  toleranceSeconds?: number;
  /** Inject a clock for tests. */
  nowSeconds?: number;
}

export type WebhookVerifyFailureReason =
  | "missing_header"
  | "malformed_header"
  | "unsupported_version"
  | "bad_signature"
  | "timestamp_outside_tolerance";

export type WebhookVerifyResult =
  | { valid: true; timestamp: number }
  | { valid: false; reason: WebhookVerifyFailureReason };

/**
 * Verify a received webhook payload against an X-ValidPay-Signature
 * header. Constant-time signature compare to prevent timing oracles.
 *
 * @param headerValue The X-ValidPay-Signature header value (or null/undefined
 *                    if absent — returns `missing_header`).
 * @param rawBody     The exact unparsed request body string.
 * @param secret      The per-webhook secret returned by POST /v1/webhooks.
 */
export function verifyWebhookSignature(
  headerValue: string | null | undefined,
  rawBody: string,
  secret: string,
  opts: VerifyWebhookOptions = {},
): WebhookVerifyResult {
  if (!headerValue) return { valid: false, reason: "missing_header" };

  const parsed = parseSignatureHeader(headerValue);
  if (!parsed) return { valid: false, reason: "malformed_header" };
  if (!parsed.v1) return { valid: false, reason: "unsupported_version" };

  const tolerance = opts.toleranceSeconds ?? DEFAULT_WEBHOOK_TOLERANCE_SECONDS;
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - parsed.t) > tolerance) {
    return { valid: false, reason: "timestamp_outside_tolerance" };
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${parsed.t}.${rawBody}`, "utf8")
    .digest("hex");

  const expectedBuf = Buffer.from(expected, "hex");
  const actualBuf = Buffer.from(parsed.v1, "hex");
  if (expectedBuf.length !== actualBuf.length) {
    return { valid: false, reason: "bad_signature" };
  }
  if (!crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    return { valid: false, reason: "bad_signature" };
  }

  return { valid: true, timestamp: parsed.t };
}

interface ParsedHeader {
  t: number;
  v1: string | null;
}

function parseSignatureHeader(header: string): ParsedHeader | null {
  const parts = header.split(",").map((p) => p.trim());
  let t: number | null = null;
  let v1: string | null = null;
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq <= 0) return null;
    const key = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (key === "t") {
      const parsed = Number.parseInt(value, 10);
      if (!Number.isFinite(parsed) || parsed <= 0) return null;
      t = parsed;
    } else if (key === "v1") {
      if (!/^[0-9a-fA-F]+$/.test(value) || value.length !== 64) return null;
      v1 = value.toLowerCase();
    }
    // Unknown keys skipped — forward-compat with future versions.
  }
  if (t === null) return null;
  return { t, v1 };
}
