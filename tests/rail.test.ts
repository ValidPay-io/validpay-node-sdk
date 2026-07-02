import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { fetchRailPiece } from "../src/rail.js";

const INTENT = "vp_railtest";
const PIECE = Buffer.alloc(32, 7).toString("base64");
// M2 fixed vector: a ciphertext commitment (sha256 hex) the rail sealed in.
const COMMITMENT = "0123456789abcdef".repeat(4);

function makeKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privateKey,
    spkiB64: (publicKey.export({ format: "der", type: "spki" }) as Buffer).toString("base64"),
  };
}
function sig(privateKey: KeyObject, intentId: string, piece: string): string {
  const msg = Buffer.from(`keyhalve-rail.v1\n${intentId}\nkeyhalve\n${piece}`, "utf8");
  return nodeSign(null, msg, privateKey).toString("base64");
}
// sig_v 2 payload (M2 content binding) — byte-exact fixed construction.
function sigV2(privateKey: KeyObject, intentId: string, piece: string, commitment: string): string {
  const msg = Buffer.from(`keyhalve-rail.v2\n${intentId}\nkeyhalve\n${piece}\n${commitment}`, "utf8");
  return nodeSign(null, msg, privateKey).toString("base64");
}
function resp(body: unknown, status = 200): Response {
  return { status, ok: status >= 200 && status < 300, json: async () => body } as unknown as Response;
}

describe("fetchRailPiece", () => {
  it("returns the share when the signature verifies against the pinned key", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sig(privateKey, INTENT, PIECE), alg: "ed25519" }),
    );
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).resolves.toBe(PIECE);
  });

  it("fails closed on a tampered signature", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const bad = Buffer.from(sig(privateKey, INTENT, PIECE), "base64");
    bad[0] ^= 0xff;
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: bad.toString("base64"), alg: "ed25519" }),
    );
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/signature/i);
  });

  it("fails closed when signed by a non-pinned key", async () => {
    const attacker = makeKey();
    const pinned = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sig(attacker.privateKey, INTENT, PIECE) }),
    );
    await expect(fetchRailPiece(f, "https://rail.test", pinned.spkiB64, INTENT)).rejects.toThrow(/signature/i);
  });

  it("rejects a wrong holder", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "platform", piece: PIECE, sig: sig(privateKey, INTENT, PIECE) }),
    );
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/malformed/i);
  });

  it("fails closed on 404 / 409 / unreachable", async () => {
    const { spkiB64 } = makeKey();
    await expect(fetchRailPiece(vi.fn().mockResolvedValue(resp({}, 404)), "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/not found/i);
    await expect(fetchRailPiece(vi.fn().mockResolvedValue(resp({}, 409)), "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/revoked/i);
    await expect(fetchRailPiece(vi.fn().mockRejectedValue(new Error("net")), "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/reach/i);
  });
});

// ── M2 content binding (sig_v 2): the rail signature also covers the ciphertext
//    commitment; the SDK verifies the v2 payload and enforces commitment equality. ──
describe("fetchRailPiece — sig_v 2 (M2 content binding)", () => {
  const v2body = (privateKey: KeyObject, over: Record<string, unknown> = {}) => ({
    holder: "keyhalve",
    piece: PIECE,
    commitment: COMMITMENT,
    sig_v: 2,
    sig: sigV2(privateKey, INTENT, PIECE, COMMITMENT),
    alg: "ed25519",
    canonical: "keyhalve-rail.v2",
    ...over,
  });

  it("verifies a sig_v 2 response and enforces the expected commitment", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).resolves.toBe(PIECE);
  });

  it("verifies a sig_v 2 response when the caller passes no expected commitment", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).resolves.toBe(PIECE);
  });

  it("fails closed when the rail commitment does not match the locally computed one", async () => {
    const { privateKey, spkiB64 } = makeKey();
    // Correctly signed by the rail — but bound to DIFFERENT content than we hold.
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    const other = "f".repeat(64);
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, other)).rejects.toThrow(/commitment/i);
  });

  it("fails closed on sig_v 2 with a missing or malformed commitment", async () => {
    const { privateKey, spkiB64 } = makeKey();
    for (const commitment of [undefined, "", COMMITMENT.toUpperCase(), COMMITMENT.slice(0, 63), 42]) {
      const f = vi.fn().mockResolvedValue(resp(v2body(privateKey, { commitment })));
      await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/malformed/i);
    }
  });

  it("fails closed when sig_v 2 is claimed over a v1-signed payload (version binding)", async () => {
    const { privateKey, spkiB64 } = makeKey();
    // Signature is over the v1 payload; claiming sig_v 2 must not verify.
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey, { sig: sig(privateKey, INTENT, PIECE) })));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/signature/i);
  });

  it("fails closed when a v2 signature is presented as sig_v 1 (downgrade)", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sigV2(privateKey, INTENT, PIECE, COMMITMENT), sig_v: 1 }),
    );
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/signature/i);
  });

  it("rejects an unsupported signature version", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey, { sig_v: 3 })));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/version/i);
  });

  it("sig_v 1 (and absent sig_v) keeps verifying exactly as before — existing pieces unaffected", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const absent = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sig(privateKey, INTENT, PIECE) }),
    );
    await expect(fetchRailPiece(absent, "https://rail.test", spkiB64, INTENT, COMMITMENT)).resolves.toBe(PIECE);
    const explicit = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sig(privateKey, INTENT, PIECE), sig_v: 1 }),
    );
    await expect(fetchRailPiece(explicit, "https://rail.test", spkiB64, INTENT, COMMITMENT)).resolves.toBe(PIECE);
  });
});
