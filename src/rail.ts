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

/** v1 canonical payload — custody only. The rail's `sig` field is ALWAYS over this,
 *  for every piece (dual signing) — unchanged forever (back-compat). */
function canonicalMessage(intentId: string, piece: string): string {
  return `keyhalve-rail.v1\n${intentId}\n${HOLDER}\n${piece}`;
}

/** v2 canonical payload — M2 content binding, carried by the ADDITIONAL
 *  `commitment_sig` field (never by `sig`). The rail additionally signs the
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
  /** ALWAYS the Ed25519 signature over the v1 (custody) payload — dual signing. */
  sig?: string;
  alg?: string;
  error?: string;
  /** M2: the ciphertext commitment sealed in at deposit (sig_v 2 responses). */
  commitment?: string;
  /** M2: SECOND Ed25519 signature, over the v2 (content-bound) payload. */
  commitment_sig?: string;
  /** 1 = custody-only (default for old pieces); 2 advertises the ADDITIONAL
   *  commitment binding (`commitment` + `commitment_sig`) — it never changes
   *  what `sig` covers. */
  sig_v?: number;
}

/**
 * Fetch and verify `B_keyhalve` for an intent. Throws (fails closed) on unreachable,
 * missing, revoked, malformed, or bad-signature.
 *
 * `sig` is verified over the v1 payload for EVERY response, exactly as always —
 * existing pieces and old rails are unaffected.
 *
 * M2 content binding (dual signing): when the response advertises a binding
 * (`sig_v: 2` / `commitment` / `commitment_sig` present), the SDK additionally
 * requires a well-formed commitment + `commitment_sig`, verifies `commitment_sig`
 * over the v2 payload against the same pinned key, and — when
 * `expectedCommitmentHex` is supplied (the sha256 the caller computed over the
 * ciphertext it actually received) — fails closed on any mismatch. The rail share
 * is never released for content other than what was sealed.
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

  // Absent sig_v = a pre-M2 (v1-only) piece. Anything other than 1 or 2 fails closed.
  const sigV = json.sig_v ?? 1;
  if (sigV !== 1 && sigV !== 2) {
    throw new ValidPayError("rail_malformed", `Unsupported rail signature version: ${String(json.sig_v)}`);
  }

  const pub = createPublicKey({
    key: Buffer.from(pinnedSpkiB64, "base64"),
    format: "der",
    type: "spki",
  });

  // ── `sig` is ALWAYS over the v1 (custody) payload — for every piece, committed
  //    or not. This check is byte-identical to pre-M2 SDKs. ──
  const ok = verify(
    null,
    Buffer.from(canonicalMessage(intentId, json.piece), "utf8"),
    pub,
    Buffer.from(json.sig, "base64"),
  );
  if (!ok) {
    throw new ValidPayError("rail_bad_signature", "Rail response failed signature verification");
  }

  // ── M2 content binding (additive). If the response advertises a binding in ANY
  //    way, enforce ALL of it — a partially-present binding is malformed, so a
  //    stripped/garbled binding can never quietly degrade to custody-only. ──
  const claimsBinding =
    sigV === 2 || json.commitment !== undefined || json.commitment_sig !== undefined;
  if (claimsBinding) {
    if (typeof json.commitment !== "string" || !COMMITMENT_HEX_RE.test(json.commitment)) {
      throw new ValidPayError("rail_malformed", "Malformed rail response: commitment binding without a valid commitment");
    }
    if (typeof json.commitment_sig !== "string" || json.commitment_sig.length === 0) {
      throw new ValidPayError("rail_malformed", "Malformed rail response: commitment binding without a commitment_sig");
    }
    // The SECOND signature covers the v2 (content-bound) payload — same pinned key.
    const boundOk = verify(
      null,
      Buffer.from(canonicalMessageV2(intentId, json.piece, json.commitment), "utf8"),
      pub,
      Buffer.from(json.commitment_sig, "base64"),
    );
    if (!boundOk) {
      throw new ValidPayError(
        "rail_commitment_mismatch",
        "Rail commitment signature failed verification — the content binding cannot be trusted",
      );
    }
    // The (now signature-verified) rail commitment must equal the commitment the
    // caller computed locally over the ciphertext it received.
    if (expectedCommitmentHex !== undefined && json.commitment !== expectedCommitmentHex) {
      throw new ValidPayError(
        "rail_commitment_mismatch",
        "Rail commitment does not match the ciphertext — the rail attestation is bound to different content",
        { details: { rail_commitment: json.commitment, computed_commitment: expectedCommitmentHex } },
      );
    }
  }

  return json.piece;
}
