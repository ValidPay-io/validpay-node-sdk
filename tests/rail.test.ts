import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { fetchRailPiece } from "../src/rail.js";

const INTENT = "vp_railtest";
const PIECE = Buffer.alloc(32, 7).toString("base64");

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
