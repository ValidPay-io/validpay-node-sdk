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
describe("fetchRailPiece — M2 content binding (dual signing, sig_v 2)", () => {
  // A faithful dual-signed rail response: `sig` is the v1 (custody) signature —
  // exactly as for uncommitted pieces — and `commitment_sig` is the SECOND
  // signature over the v2 (content-bound) payload.
  const v2body = (privateKey: KeyObject, over: Record<string, unknown> = {}) => ({
    holder: "keyhalve",
    piece: PIECE,
    sig: sig(privateKey, INTENT, PIECE),
    alg: "ed25519",
    canonical: "keyhalve-rail.v1",
    commitment: COMMITMENT,
    commitment_sig: sigV2(privateKey, INTENT, PIECE, COMMITMENT),
    sig_v: 2,
    ...over,
  });

  it("verifies a dual-signed response and enforces the expected commitment", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).resolves.toBe(PIECE);
  });

  it("verifies a dual-signed response when the caller passes no expected commitment", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).resolves.toBe(PIECE);
  });

  // ── THE critical compat vector: on a committed piece, `sig` MUST still be the v1
  //    signature. A rail that switched `sig` to the v2 payload (the rejected design)
  //    would break this SDK and every already-published verifier. ──
  it("fails closed if `sig` is the v2-payload signature instead of v1 (sig must never switch)", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp(v2body(privateKey, { sig: sigV2(privateKey, INTENT, PIECE, COMMITMENT) })),
    );
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/signature/i);
  });

  it("fails closed when the rail commitment does not match the locally computed one", async () => {
    const { privateKey, spkiB64 } = makeKey();
    // Correctly dual-signed by the rail — but bound to DIFFERENT content than we hold.
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    const other = "f".repeat(64);
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, other)).rejects.toThrow(/commitment/i);
  });

  it("fails closed on a tampered or wrong-payload commitment_sig", async () => {
    const { privateKey, spkiB64 } = makeKey();
    // Bit-flipped commitment_sig.
    const flipped = Buffer.from(sigV2(privateKey, INTENT, PIECE, COMMITMENT), "base64");
    flipped[0] ^= 0xff;
    const tampered = vi.fn().mockResolvedValue(
      resp(v2body(privateKey, { commitment_sig: flipped.toString("base64") })),
    );
    await expect(fetchRailPiece(tampered, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/commitment/i);
    // commitment_sig that is (only) the v1 signature — wrong payload.
    const wrongPayload = vi.fn().mockResolvedValue(
      resp(v2body(privateKey, { commitment_sig: sig(privateKey, INTENT, PIECE) })),
    );
    await expect(fetchRailPiece(wrongPayload, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/commitment/i);
    // commitment_sig signed by a non-pinned key.
    const attacker = makeKey();
    const wrongKey = vi.fn().mockResolvedValue(
      resp(v2body(privateKey, { commitment_sig: sigV2(attacker.privateKey, INTENT, PIECE, COMMITMENT) })),
    );
    await expect(fetchRailPiece(wrongKey, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/commitment/i);
  });

  it("fails closed on an advertised binding with a missing or malformed commitment", async () => {
    const { privateKey, spkiB64 } = makeKey();
    for (const commitment of [undefined, "", COMMITMENT.toUpperCase(), COMMITMENT.slice(0, 63), 42]) {
      const f = vi.fn().mockResolvedValue(resp(v2body(privateKey, { commitment })));
      await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/malformed/i);
    }
  });

  it("fails closed on an advertised binding with a missing commitment_sig (stripping)", async () => {
    const { privateKey, spkiB64 } = makeKey();
    for (const commitment_sig of [undefined, ""]) {
      const f = vi.fn().mockResolvedValue(resp(v2body(privateKey, { commitment_sig })));
      await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT)).rejects.toThrow(/malformed/i);
    }
  });

  it("enforces the binding even when sig_v is absent but commitment fields are present", async () => {
    const { privateKey, spkiB64 } = makeKey();
    // A well-formed binding without sig_v still verifies…
    const good = vi.fn().mockResolvedValue(resp(v2body(privateKey, { sig_v: undefined })));
    await expect(fetchRailPiece(good, "https://rail.test", spkiB64, INTENT, COMMITMENT)).resolves.toBe(PIECE);
    // …and a mismatching one still fails closed (presence of the fields claims it).
    const bad = vi.fn().mockResolvedValue(resp(v2body(privateKey, { sig_v: undefined })));
    await expect(fetchRailPiece(bad, "https://rail.test", spkiB64, INTENT, "f".repeat(64))).rejects.toThrow(/commitment/i);
  });

  it("rejects an unsupported signature version", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey, { sig_v: 3 })));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).rejects.toThrow(/version/i);
  });

  it("forwards qrMac alongside an expected commitment (both features compose)", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp(v2body(privateKey)));
    await expect(
      fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, COMMITMENT, "X6n5UyGi"),
    ).resolves.toBe(PIECE);
    expect(String(f.mock.calls[0]![0])).toBe(`https://rail.test/v1/piece/${INTENT}?m=X6n5UyGi`);
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

// ── Anti-fake QR MAC (?m=) forwarding + distinct fail-closed error mapping.
//    MAC-gated documents (sealed since QR_MAC_ENFORCE) 403 on a bare piece GET;
//    the rail's MAC verdicts must NEVER surface as network/"rail down" errors. ──
describe("fetchRailPiece — anti-fake QR MAC (?m=)", () => {
  it("forwards qrMac as ?m= on the piece request", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sig(privateKey, INTENT, PIECE), alg: "ed25519" }),
    );
    await expect(
      fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, undefined, "X6n5UyGi"),
    ).resolves.toBe(PIECE);
    expect(String(f.mock.calls[0]![0])).toBe(`https://rail.test/v1/piece/${INTENT}?m=X6n5UyGi`);
  });

  it("sends no ?m= when qrMac is not given (legacy documents unchanged)", async () => {
    const { privateKey, spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(
      resp({ holder: "keyhalve", piece: PIECE, sig: sig(privateKey, INTENT, PIECE) }),
    );
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).resolves.toBe(PIECE);
    expect(String(f.mock.calls[0]![0])).toBe(`https://rail.test/v1/piece/${INTENT}`);
  });

  it("maps 403 mac_invalid to qr_mac_invalid — a FRAUD verdict, never a rail/network error", async () => {
    const { spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp({ error: "mac_invalid" }, 403));
    await expect(
      fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, undefined, "WrongMac1"),
    ).rejects.toMatchObject({
      name: "ValidPayError",
      code: "qr_mac_invalid",
      message: expect.stringMatching(/fraudulent/i),
    });
  });

  it("maps 403 mac_required to qr_mac_required — actionable, never a rail/network error", async () => {
    const { spkiB64 } = makeKey();
    const f = vi.fn().mockResolvedValue(resp({ error: "mac_required" }, 403));
    await expect(fetchRailPiece(f, "https://rail.test", spkiB64, INTENT)).rejects.toMatchObject({
      name: "ValidPayError",
      code: "qr_mac_required",
      message: expect.stringMatching(/anti-fake code/i),
    });
  });

  it("keeps other 403s (and unparseable 403 bodies) as rail_error", async () => {
    const { spkiB64 } = makeKey();
    const other = vi.fn().mockResolvedValue(resp({ error: "forbidden" }, 403));
    await expect(fetchRailPiece(other, "https://rail.test", spkiB64, INTENT)).rejects.toMatchObject({
      code: "rail_error",
    });
    const unparseable = vi.fn().mockResolvedValue({
      status: 403,
      ok: false,
      json: async () => {
        throw new Error("not json");
      },
    } as unknown as Response);
    await expect(
      fetchRailPiece(unparseable, "https://rail.test", spkiB64, INTENT),
    ).rejects.toMatchObject({ code: "rail_error" });
  });

  it("a real network failure still maps to rail_unreachable (unchanged)", async () => {
    const { spkiB64 } = makeKey();
    const f = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    await expect(
      fetchRailPiece(f, "https://rail.test", spkiB64, INTENT, undefined, "X6n5UyGi"),
    ).rejects.toMatchObject({ code: "rail_unreachable" });
  });
});
