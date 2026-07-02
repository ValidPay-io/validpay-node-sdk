/**
 * KeyHalve rail client (verify side). Fetches the blind rail share `B_keyhalve` from
 * the independent rail and verifies the rail's Ed25519 signature against a PINNED
 * public key. Fails closed on any doubt. The caller XOR-combines the verified rail
 * share with the platform share(s) (from the ValidPay API) and ShareA (the QR key).
 *
 * The pinned key is shipped with the SDK, not fetched at runtime — a hijacked rail or
 * DNS path then produces a signature that fails the pinned check.
 */

import { createPublicKey, verify } from "node:crypto";
import { ValidPayError } from "./types.js";

/** Default rail base + pinned KMS Ed25519 public key (SPKI DER, base64). */
export const KEYHALVE_RAIL_BASE_URL = "https://rail.keyhalve.com";
export const KEYHALVE_RAIL_PUBLIC_KEY_SPKI_B64 =
  "MCowBQYDK2VwAyEAngOcqC4hL467C9RyWUh4bAQD3Fohi9zqhY+l65bul6w=";

const HOLDER = "keyhalve";

/** sig_v 1 canonical payload — custody only. Unchanged forever (back-compat). */
function canonicalMessage(intentId: string, piece: string): string {
  return `keyhalve-rail.v1\n${intentId}\n${HOLDER}\n${piece}`;
}

/** sig_v 2 canonical payload — M2 content binding. The rail additionally signs the
 *  document's ciphertext commitment (sha256 hex of the base64 ciphertext, the same
 *  value as the intent's commitment hash), binding "Authentic" to the content rather
 *  than key custody alone. Byte-exact construction (UTF-8, "\n" separators):
 *  `keyhalve-rail.v2\n<intentId>\nkeyhalve\n<piece>\n<commitment>` */
function canonicalMessageV2(intentId: string, piece: string, commitment: string): string {
  return `keyhalve-rail.v2\n${intentId}\n${HOLDER}\n${piece}\n${commitment}`;
}

const COMMITMENT_HEX_RE = /^[0-9a-f]{64}$/;

interface RailPieceResponse {
  holder?: string;
  piece?: string;
  sig?: string;
  alg?: string;
  error?: string;
  /** M2: present on sig_v 2 responses — the ciphertext commitment the signature covers. */
  commitment?: string;
  /** Signature payload version: 1 (custody-only, default for old pieces) or 2 (content-bound). */
  sig_v?: number;
}

/**
 * Fetch and verify `B_keyhalve` for an intent. Throws (fails closed) on unreachable,
 * missing, revoked, malformed, or bad-signature.
 *
 * M2 content binding: sig_v 2 responses are verified over the v2 payload (which covers
 * the rail-sealed ciphertext commitment). When `expectedCommitmentHex` is supplied
 * (the sha256 the caller computed over the ciphertext it actually received), a sig_v 2
 * commitment that does not match it fails closed — the rail share is never released
 * for content other than what was sealed. sig_v 1 responses keep verifying exactly as
 * before; existing pieces are unaffected.
 */
export async function fetchRailPiece(
  fetchImpl: typeof fetch,
  railBaseUrl: string,
  pinnedSpkiB64: string,
  intentId: string,
  expectedCommitmentHex?: string,
): Promise<string> {
  const base = railBaseUrl.replace(/\/+$/, "");
  let res: Response;
  try {
    res = await fetchImpl(`${base}/v1/piece/${encodeURIComponent(intentId)}`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch (cause) {
    throw new ValidPayError("rail_unreachable", "Could not reach the KeyHalve rail", { cause });
  }

  if (res.status === 404) throw new ValidPayError("rail_not_found", "Rail share not found");
  if (res.status === 409) throw new ValidPayError("rail_revoked", "Rail share revoked");
  if (!res.ok) throw new ValidPayError("rail_error", `Rail returned ${res.status}`);

  const json = (await res.json()) as RailPieceResponse;
  if (json.error) throw new ValidPayError("rail_error", `Rail error: ${json.error}`);
  if (!json.piece || !json.sig || json.holder !== HOLDER) {
    throw new ValidPayError("rail_malformed", "Malformed rail response");
  }

  // Absent sig_v = a pre-M2 (v1) piece. Anything other than 1 or 2 fails closed.
  const sigV = json.sig_v ?? 1;
  let message: string;
  if (sigV === 2) {
    if (typeof json.commitment !== "string" || !COMMITMENT_HEX_RE.test(json.commitment)) {
      throw new ValidPayError("rail_malformed", "Malformed rail response: sig_v 2 without a valid commitment");
    }
    message = canonicalMessageV2(intentId, json.piece, json.commitment);
  } else if (sigV === 1) {
    message = canonicalMessage(intentId, json.piece);
  } else {
    throw new ValidPayError("rail_malformed", `Unsupported rail signature version: ${String(json.sig_v)}`);
  }

  const pub = createPublicKey({
    key: Buffer.from(pinnedSpkiB64, "base64"),
    format: "der",
    type: "spki",
  });
  const ok = verify(null, Buffer.from(message, "utf8"), pub, Buffer.from(json.sig, "base64"));
  if (!ok) {
    throw new ValidPayError("rail_bad_signature", "Rail response failed signature verification");
  }

  // M2 binding check: the (signature-covered) rail commitment must equal the
  // commitment the caller computed locally over the ciphertext it received.
  if (sigV === 2 && expectedCommitmentHex !== undefined && json.commitment !== expectedCommitmentHex) {
    throw new ValidPayError(
      "rail_commitment_mismatch",
      "Rail commitment does not match the ciphertext — the rail attestation is bound to different content",
      { details: { rail_commitment: json.commitment, computed_commitment: expectedCommitmentHex } },
    );
  }

  return json.piece;
}
