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

function canonicalMessage(intentId: string, piece: string): string {
  return `keyhalve-rail.v1\n${intentId}\n${HOLDER}\n${piece}`;
}

interface RailPieceResponse {
  holder?: string;
  piece?: string;
  sig?: string;
  alg?: string;
  error?: string;
}

/**
 * Fetch and verify `B_keyhalve` for an intent. Throws (fails closed) on unreachable,
 * missing, revoked, malformed, or bad-signature.
 */
export async function fetchRailPiece(
  fetchImpl: typeof fetch,
  railBaseUrl: string,
  pinnedSpkiB64: string,
  intentId: string,
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

  const pub = createPublicKey({
    key: Buffer.from(pinnedSpkiB64, "base64"),
    format: "der",
    type: "spki",
  });
  const ok = verify(
    null,
    Buffer.from(canonicalMessage(intentId, json.piece), "utf8"),
    pub,
    Buffer.from(json.sig, "base64"),
  );
  if (!ok) {
    throw new ValidPayError("rail_bad_signature", "Rail response failed signature verification");
  }
  return json.piece;
}
