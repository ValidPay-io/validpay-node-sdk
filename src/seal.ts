/**
 * ONE-CALL document seal — seal-at-source v0.2, phase 2 (SDK half).
 *
 * `client.sealDocument({ file, documentType, fields })`: a PDF goes in, the
 * sealed+stamped PDF comes out. One artifact — the file you distribute IS the
 * file that verifies. Orchestrates the API's reserve→commit pair
 * (ValidPay-API #145, `POST /v1/intent/reserve` + `POST /v1/intent/commit`)
 * with ALL cryptography local:
 *
 *   1. reserve — pre-issue the intent identity (`vp_…` id + anti-fake QR MAC)
 *   2. generate the AES-256 key locally and End-Cell-split it (ShareA for the
 *      QR + one XOR piece each for the KeyHalve rail and the platform — the
 *      same 3-of-3 custody as `createEndCellIntent` and the dashboard wizard)
 *   3. build the converged verify URL (`?t=<tenant>&m=<qrMac>#key=<ShareA>`)
 *      and stamp its QR INTO the PDF at the chosen placement
 *   4. AES-256-GCM-encrypt the STAMPED bytes (the ciphertext IS the artifact),
 *      commit v2 (SHA-256 over the transported ciphertext string)
 *   5. commit against the held reservation
 *
 * The full key, ShareA, and the plaintext document never leave this process;
 * the server receives only the ciphertext, the two server-side pieces, and
 * the disclosed plaintext fields.
 *
 * Encryption note: this path deliberately binds NO AAD — the reserve→commit
 * surface stores `encryption_version: 1`, byte-compatible with the dashboard
 * wizard's `encryptBlobWithKey`, so the web verifier and `decryptBytes`
 * decrypt the artifact without metadata reconstruction.
 *
 * Failure contract: the reservation is created first, so any later failure
 * (stamping, encryption, commit) leaves a draft held server-side (24 h TTL,
 * fail-closed: it verifies as not_found everywhere until committed). Errors
 * thrown after the reserve carry `details.reservation_id` and
 * `details.qr_mac` so a caller can correlate/retry. Network-shaped commit
 * failures are retried ONCE automatically; a retry answered with
 * `already_committed` means our first commit actually landed and is recovered
 * as success.
 */

import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import {
  chooseGrowToFit,
  computeAutoPlacements,
  extractAutoObstacles,
  GROW_MAX_WIDTH_PT,
  GROW_MIN_WIDTH_PT,
  logoTargetWidthPt,
  type AutoPlacementDecision,
  type AutoPlacementOptions,
  type PageObstacles,
} from "./autoPlace.js";
import {
  commitmentHash,
  encryptBytes,
  generateKey,
  splitKeyPieces,
} from "./crypto.js";
import {
  buildVerifyUrl,
  embedQr,
  readPdfPageSizes,
  resolveQrRect,
  type QrAnchor,
  type QrPlacement,
} from "./pdf.js";
import { decideBrandedQr, PT_PER_MM } from "./brandedQr.js";
import { ValidPayError } from "./types.js";

/** Verify-page origin the QR URL is built against when none is given —
 *  KeyHalve's neutral converged verify surface (same default as
 *  `buildVerifyUrl`). */
const DEFAULT_VERIFY_BASE_URL = "https://verify.keyhalve.com";

/** Tenant slug emitted as `?t=` when none is given — the branded ValidPay
 *  verify page (matches the server's own `verifyUrlFor` builder). */
const DEFAULT_TENANT = "validpay";

/**
 * Default QR placement: a 1.0 in QR whose bottom-right corner sits 0.5 in in
 * from the page's bottom and right edges — on-page on every sane page size,
 * and exactly the `MIN_RECOMMENDED_QR_PT` (72 pt) print-scannable minimum.
 */
export const DEFAULT_SEAL_PLACEMENT: QrPlacement = {
  anchor: "bottom-right",
  x: 0.5,
  y: 0.5,
  width: 1.0,
  units: "in",
};

/**
 * Plaintext metadata the issuer chooses to DISCLOSE to verifiers (it is not
 * encrypted). The four well-known keys map to the commit contract's top-level
 * columns; every other key travels in the free-form `metadata` map — the same
 * split the dashboard wizard performs.
 */
export interface SealDocumentFields {
  /** Reference / check number / policy number etc. → `reference`. */
  reference?: string;
  /** Issue date (free-form, ≤40 chars) → `date_issued`. */
  dateIssued?: string;
  /** Expiration date (free-form, ≤40 chars) → `expiration_date`. */
  expirationDate?: string;
  /** Free-text notes (≤2000 chars) → `notes`. */
  notes?: string;
  /** Anything else is disclosed via the free-form `metadata` map. */
  [field: string]: unknown;
}

/**
 * Smart placement request: the QR spot AND SIZE are CHOSEN AUTOMATICALLY, per
 * page, from the page's own content — text, images, and vector graphics become
 * obstacles (shared smart-place contract, smartPlace.ts) and the QR is sized
 * LOGO-FIRST (Prompt 159): it grows to at least the branded-logo target for
 * this document's verify URL (so the KeyHalve mark shows) when the clear space
 * near the preferred corner allows, up to `maxWidthPt` (default 1.5 in) for
 * scannability, and only shrinks toward `minWidthPt` — going plain — when the
 * corner is cramped. Setting `qrWidthPt` OPTS OUT of grow-to-fit and pins that
 * fixed size (legacy shrink-only ladder). Everything is computed LOCALLY
 * (requires the optional peer dependency `pdfjs-dist`); the page content never
 * leaves the process. The bare string `"auto"` is shorthand for
 * `{ mode: "auto" }`.
 */
export interface AutoQrPlacement extends AutoPlacementOptions {
  mode: "auto";
  /** 1-based page the QR goes on (ignored with `allPages`). Default `1`. */
  page?: number;
  /** Corner tried first — inherited from the smart-place contract. */
  preferredAnchor?: QrAnchor;
}

export interface SealDocumentParams {
  /** The PDF to seal: raw bytes, or a filesystem path to read. PDF only in
   *  v0.2 (`embedQr` stamps via pdf-lib) — anything else throws
   *  `unsupported_file_type`. */
  file: Uint8Array | string;
  /** Document type, e.g. `"invoice"`, `"check"`, `"lease"`. Some sensitive
   *  types (M-1) require a verified issuer account. */
  documentType: string;
  /** Plaintext fields disclosed to verifiers (see {@link SealDocumentFields}). */
  fields?: SealDocumentFields;
  /**
   * Where the QR is stamped — either the canonical {@link QrPlacement}
   * contract (page / anchor / x / y / width / units) shared with `embedQr`
   * and the website tool, or `"auto"` / {@link AutoQrPlacement} to let the
   * shared smart-place contract choose clear space on the page itself
   * (locally, via the optional peer `pdfjs-dist`). Default:
   * {@link DEFAULT_SEAL_PLACEMENT} (1.0 in QR, bottom-right, 0.5 in inset).
   */
  placement?: QrPlacement | "auto" | AutoQrPlacement;
  /** Stamp the QR on EVERY page (like the wizard's "all pages" toggle); page
   *  1 is recorded as the canonical placement. With a manual placement its
   *  `page` is ignored and every page uses the same insets; with auto
   *  placement each page gets its own smart-place decision. On multi-page
   *  documents each page's QR URL additionally carries the display-only
   *  `&p=<page>` orientation tag. Default `false`. */
  allPages?: boolean;
  /**
   * NOT SUPPORTED in v0.2: the reserve→commit contract records `valid_until`
   * only. Passing a value throws `invalid_argument` — this parameter exists
   * so the limitation is explicit rather than silently dropped.
   */
  validFrom?: string;
  /** Optional ISO-8601 expiry (Time-Locked Verification) → `valid_until`. */
  validUntil?: string;
  /** Tenant slug for the branded verify page (`?t=`). Default `"validpay"`. */
  tenant?: string;
  /** Verify-page origin for the stamped URL. Default
   *  `"https://verify.keyhalve.com"`. */
  verifyBaseUrl?: string;
  /** Original filename recorded with the intent (issuer records only; not on
   *  public verify). Default: derived from the path (`<name>-sealed.pdf`), or
   *  `"document-sealed.pdf"` for raw bytes. */
  fileName?: string;
  /** Issuer certification (organization-issued, authentic, issuer accepts
   *  responsibility per Terms §6). Default `true` — calling this method IS
   *  the issuing act; pass `false` only if your integration certifies later. */
  issuerCertified?: boolean;
}

export interface SealDocumentResult {
  /** THE artifact: the stamped PDF whose encrypted bytes were committed.
   *  Distribute exactly this file — its QR verifies it. */
  sealedPdf: Buffer;
  /** The intent id (`vp_…`). */
  intentId: string;
  /** The pre-issued anti-fake QR MAC riding the verify URL as `?m=`. */
  qrMac: string;
  /** The full verify URL the stamped QR encodes — CONTAINS THE DECRYPTION
   *  KEY (ShareA) in its `#key=` fragment. Treat like the document itself. */
  verifyUrl: string;
  /** Neutral KeyHalve certificate page for the intent (two-page trust model).
   *  Key-free — safe to share. */
  certificateUrl: string;
  /** The key-free verification URL from the API response (`verifyUrlFor`
   *  shape, no `#key=` fragment). */
  verificationUrl: string;
  /** Present when placement was auto: the per-page decision for every stamped
   *  page (top-left-origin pt). Default (grow-to-fit) mode also reports, per
   *  page, `branded` (the KeyHalve mark prints), `logoFit` (the branded target
   *  was reached), `logoTargetPt` (that target for this page's URL), and
   *  `modulePitchMm`. `shrunk` pages went plain to fit a cramped corner;
   *  `fallback` pages were crowded — the QR was forced onto the preferred
   *  corner at minimum size and a human should eyeball it. */
  autoPlacement?: AutoPlacementDecision[];
  /** Present for multi-page all-pages seals: the page-tagged verify URL each
   *  page's QR encodes (`&p=<page>` — a display-only orientation tag, never
   *  a security claim). Every entry CONTAINS THE DECRYPTION KEY in its
   *  `#key=` fragment — treat like {@link verifyUrl}. */
  pageVerifyUrls?: Array<{ page: number; url: string }>;
  /** How the canonical page's QR was rendered under the shared branded-QR
   *  contract (Prompt 158): `branded: true` means the stamped QR carries the
   *  centered KeyHalve mark at EC-H; `false` means the placement was too
   *  small for a reliable mark and the QR is plain EC-M (scan reliability
   *  always wins over branding). `modulePitchMm` is the printed module pitch
   *  the decision was made on (the mark turns on at ≥ 0.4 mm). */
  brandedQr: {
    branded: boolean;
    errorCorrectionLevel: "H" | "M";
    modulePitchMm: number;
  };
}

/** The narrow HTTP seam `ValidPayClient` provides — its authenticated
 *  `request` method, so this module stays free of fetch/auth plumbing. */
export interface SealHttp {
  request<T>(
    method: "GET" | "POST" | "PATCH",
    path: string,
    opts: { body?: unknown; auth: boolean },
  ): Promise<T>;
}

interface RawReserveResponse {
  intent_id?: string;
  qr_mac?: string;
  verification_url?: string;
  expires_at?: string;
}

interface RawCommitResponse {
  retrieval_id?: string;
  status?: string;
  qr_mac?: string;
  verification_url?: string;
}

/** Commit-contract statuses after which the reservation is NOT retriable —
 *  the error message must not promise a held draft. */
const NON_RETRIABLE_COMMIT_ERRORS = new Set([
  "reservation_not_found",
  "reservation_conflict",
  "already_committed",
  "reservation_expired",
]);

const clampPct = (v: number): number => Math.min(100, Math.max(0, v));

/** PDF magic sniff: `%PDF-` within the first 1 KB (the spec tolerates a
 *  small preamble before the header, and pdf-lib does too). */
function looksLikePdf(bytes: Uint8Array): boolean {
  const head = bytes.subarray(0, 1024);
  const marker = [0x25, 0x50, 0x44, 0x46, 0x2d]; // %PDF-
  outer: for (let i = 0; i + marker.length <= head.length; i++) {
    for (let j = 0; j < marker.length; j++) {
      if (head[i + j] !== marker[j]) continue outer;
    }
    return true;
  }
  return false;
}

async function loadFileBytes(file: Uint8Array | string): Promise<Uint8Array> {
  if (file instanceof Uint8Array) {
    if (file.length === 0) {
      throw new ValidPayError("invalid_argument", "file is empty");
    }
    return file;
  }
  if (typeof file === "string" && file.length > 0) {
    try {
      return new Uint8Array(await readFile(file));
    } catch (cause) {
      throw new ValidPayError(
        "invalid_argument",
        `Cannot read file at "${file}" — it must exist and be readable on this machine`,
        { cause },
      );
    }
  }
  throw new ValidPayError(
    "invalid_argument",
    "file must be a non-empty Uint8Array/Buffer or a filesystem path",
  );
}

function defaultSealedName(file: Uint8Array | string): string {
  if (typeof file === "string") {
    const base = basename(file).replace(/\.[^.]+$/, "");
    if (base.length > 0) return `${base}-sealed.pdf`;
  }
  return "document-sealed.pdf";
}

/**
 * Wrap a post-reserve failure so the caller always learns WHICH reservation
 * is involved (`details.reservation_id` / `details.qr_mac`) and whether the
 * draft is still held server-side (retriable).
 */
function sealError(
  err: unknown,
  intentId: string,
  qrMac: string,
  expiresAt: string | undefined,
): ValidPayError {
  const base =
    err instanceof ValidPayError
      ? err
      : new ValidPayError(
          "seal_failed",
          err instanceof Error ? err.message : String(err),
          { cause: err },
        );
  const stillHeld = !NON_RETRIABLE_COMMIT_ERRORS.has(base.code);
  const suffix = stillHeld
    ? " The reservation is still held server-side (24h TTL) — the id verifies as not_found until committed; retry the seal."
    : "";
  return new ValidPayError(base.code, `${base.message}${suffix}`, {
    ...(base.status !== undefined ? { status: base.status } : {}),
    details: {
      reservation_id: intentId,
      qr_mac: qrMac,
      ...(expiresAt !== undefined ? { reservation_expires_at: expiresAt } : {}),
      reservation_still_held: stillHeld,
      ...(base.details !== undefined ? { cause_details: base.details } : {}),
    },
    cause: err,
  });
}

/**
 * The one-call seal orchestration. Exposed as `ValidPayClient.sealDocument`;
 * this free function takes the client's request seam so the whole flow is
 * unit-testable against a mocked API.
 */
export async function sealDocumentWithHttp(
  http: SealHttp,
  params: SealDocumentParams,
): Promise<SealDocumentResult> {
  // ── Local validation (nothing reserved yet — plain errors) ──────────────
  if (!params.documentType) {
    throw new ValidPayError("invalid_argument", "documentType is required");
  }
  if (params.validFrom !== undefined) {
    throw new ValidPayError(
      "invalid_argument",
      "validFrom is not supported by the reserve→commit seal contract in v0.2 " +
        "(the commit records valid_until only). Omit validFrom, or use " +
        "createFileIntent + embedQr for a time-locked start.",
    );
  }
  let validUntilIso: string | undefined;
  if (params.validUntil !== undefined) {
    const t = Date.parse(params.validUntil);
    if (Number.isNaN(t)) {
      throw new ValidPayError(
        "invalid_argument",
        `validUntil is not a valid ISO-8601: ${params.validUntil}`,
      );
    }
    // The commit schema wants a strict ISO datetime — normalize.
    validUntilIso = new Date(t).toISOString();
  }

  const bytes = await loadFileBytes(params.file);
  if (!looksLikePdf(bytes)) {
    throw new ValidPayError(
      "unsupported_file_type",
      "sealDocument seals PDFs only in v0.2 (the QR is stamped via pdf-lib). " +
        "The input does not look like a PDF — convert it, or seal images/DOCX " +
        "through the dashboard wizard / createFileIntent.",
    );
  }

  const rawPlacement = params.placement ?? DEFAULT_SEAL_PLACEMENT;
  const autoPlacement: AutoQrPlacement | null =
    rawPlacement === "auto"
      ? { mode: "auto" }
      : typeof rawPlacement === "object" &&
          "mode" in rawPlacement &&
          rawPlacement.mode === "auto"
        ? rawPlacement
        : null;
  const manualPlacement =
    autoPlacement === null ? (rawPlacement as QrPlacement) : null;
  if (manualPlacement !== null && !(manualPlacement.width > 0)) {
    throw new ValidPayError("invalid_argument", "placement.width must be > 0");
  }
  const allPages = params.allPages ?? false;
  const tenant = params.tenant ?? DEFAULT_TENANT;
  const verifyBase = (params.verifyBaseUrl ?? DEFAULT_VERIFY_BASE_URL).replace(/\/+$/, "");

  // Page geometry up-front — also proves the PDF parses and the target page
  // exists BEFORE a reservation is spent.
  let pageSizes: Array<{ width: number; height: number }>;
  try {
    pageSizes = await readPdfPageSizes(bytes);
  } catch (cause) {
    if (cause instanceof ValidPayError && cause.code === "missing_dependency") throw cause;
    throw new ValidPayError(
      "unsupported_file_type",
      "The file could not be parsed as a PDF (sealDocument is PDF-only in v0.2).",
      { cause },
    );
  }
  // Canonical placement page: 1 when stamping every page (the wizard's rule),
  // else the requested page.
  const canonicalPage = allPages
    ? 1
    : ((autoPlacement !== null ? autoPlacement.page : manualPlacement?.page) ?? 1);
  if (canonicalPage < 1 || canonicalPage > pageSizes.length) {
    throw new ValidPayError(
      "invalid_argument",
      `placement.page ${canonicalPage} is out of range (document has ${pageSizes.length} page(s))`,
    );
  }

  const targetPages = allPages
    ? Array.from({ length: pageSizes.length }, (_, i) => i + 1)
    : [canonicalPage];
  // Multi-page all-pages seals tag each page's QR URL with the display-only
  // `&p=<page>` orientation marker (single-page docs stay untagged).
  const pageTagged = allPages && pageSizes.length > 1;

  // ── Smart placement (LOCAL; the failure-prone extraction runs BEFORE the
  // reserve so a missing pdfjs-dist peer or unparseable page costs neither a
  // reservation nor quota). Two auto modes:
  //   • DEFAULT (grow-to-fit): the QR is sized LOGO-FIRST from THIS document's
  //     verify URL — but that URL isn't known until after the reserve, so the
  //     grow decision is DEFERRED to inside the try below; here we only extract
  //     obstacles (the part that can fail early).
  //   • LEGACY (caller pinned `qrWidthPt`): fixed-size shrink ladder — no URL
  //     needed, so it is decided up-front here, exactly as before. ──────────
  let autoDecisions: AutoPlacementDecision[] | undefined;
  const placementFor = new Map<number, QrPlacement>();
  // Grow-to-fit knobs hoisted so the deferred (post-reserve) sizing can see them.
  const growMode = autoPlacement !== null && autoPlacement.qrWidthPt === undefined;
  const preferredAnchor = autoPlacement?.preferredAnchor;
  const growMarginPt = autoPlacement?.marginPt;
  const growClearancePt = autoPlacement?.clearancePt;
  const growMaxWidthPt = autoPlacement?.maxWidthPt ?? GROW_MAX_WIDTH_PT;
  const growMinWidthPt = autoPlacement?.minWidthPt ?? GROW_MIN_WIDTH_PT;
  let pageGeoms: PageObstacles[] | undefined;
  if (autoPlacement !== null) {
    if (growMode) {
      // Extract now (fail-fast, pre-reserve); size after the URL is known.
      pageGeoms = await extractAutoObstacles(bytes, targetPages);
    } else {
      // Legacy fixed size: decide up-front (independent of the verify URL).
      const autoOpts: AutoPlacementOptions = {};
      if (autoPlacement.preferredAnchor !== undefined) {
        autoOpts.preferredAnchor = autoPlacement.preferredAnchor;
      }
      if (autoPlacement.qrWidthPt !== undefined) autoOpts.qrWidthPt = autoPlacement.qrWidthPt;
      if (autoPlacement.marginPt !== undefined) autoOpts.marginPt = autoPlacement.marginPt;
      if (autoPlacement.clearancePt !== undefined) autoOpts.clearancePt = autoPlacement.clearancePt;
      if (autoPlacement.minWidthPt !== undefined) autoOpts.minWidthPt = autoPlacement.minWidthPt;
      autoDecisions = await computeAutoPlacements(bytes, targetPages, autoOpts);
      for (const d of autoDecisions) {
        placementFor.set(d.page, {
          page: d.page,
          anchor: "top-left",
          x: d.x,
          y: d.y,
          width: d.widthPt,
          units: "pt",
        });
      }
    }
  } else {
    for (const page of targetPages) {
      placementFor.set(page, { ...(manualPlacement as QrPlacement), page });
    }
  }

  // ── 1. Reserve the identity ─────────────────────────────────────────────
  const reserve = await http.request<RawReserveResponse>("POST", "/v1/intent/reserve", {
    body: {},
    auth: true,
  });
  if (!reserve?.intent_id || !reserve.qr_mac) {
    throw new ValidPayError(
      "invalid_response",
      "Reserve response missing intent_id/qr_mac",
      { details: reserve },
    );
  }
  const intentId = reserve.intent_id;
  const qrMac = reserve.qr_mac;

  // From here on, a draft is held server-side: annotate every failure with
  // the reservation identity (see sealError).
  try {
    // ── 2. Key + End-Cell split (identical custody to createEndCellIntent /
    // the wizard: ShareA rides the QR; rail + platform each hold one piece) ─
    const fullKey = generateKey();
    const parts = splitKeyPieces(fullKey, 2);
    const shareA = parts[0]!;
    const pieces = [
      { holder: "keyhalve", piece: parts[1]! },
      { holder: "platform", piece: parts[2]! },
    ];

    // ── 3. The converged verify URL the QR encodes ────────────────────────
    const verifyUrl = buildVerifyUrl(intentId, shareA, {
      baseUrl: verifyBase,
      tenant,
      qrMac,
    });

    // ── 3a. Deferred LOGO-AWARE grow-to-fit sizing (default auto mode) ─────
    // Now that the real verify URL is known, size each page LOGO-FIRST from
    // its EXACT payload length: grow to the branded target (mark shows) when
    // clear space allows, up to maxWidthPt; shrink to plain only when cramped.
    // Deterministic per page (each page's &p= tag can change the payload
    // length, hence its own logo target).
    if (growMode && pageGeoms !== undefined) {
      autoDecisions = [];
      for (const g of pageGeoms) {
        const pageUrl = pageTagged
          ? buildVerifyUrl(intentId, shareA, {
              baseUrl: verifyBase,
              tenant,
              qrMac,
              page: g.page,
            })
          : verifyUrl;
        const logoTargetPt = logoTargetWidthPt(pageUrl);
        const grown = chooseGrowToFit(g.obstacles, g.pageWidthPt, g.pageHeightPt, {
          logoTargetPt,
          maxWidthPt: growMaxWidthPt,
          minWidthPt: growMinWidthPt,
          ...(preferredAnchor !== undefined ? { preferredAnchor } : {}),
          ...(growMarginPt !== undefined ? { marginPt: growMarginPt } : {}),
          ...(growClearancePt !== undefined ? { clearancePt: growClearancePt } : {}),
        });
        // Authoritative branded verdict: the shared contract on this page's
        // exact URL + chosen size (byte-for-byte what embedQr will draw).
        const brand = decideBrandedQr(pageUrl, grown.widthPt / PT_PER_MM);
        autoDecisions.push({
          ...grown,
          page: g.page,
          obstacleCount: g.obstacles.length,
          logoFit: grown.logoFit,
          logoTargetPt,
          branded: brand.showLogo,
          modulePitchMm: brand.modulePitchMm,
        });
        placementFor.set(g.page, {
          page: g.page,
          anchor: "top-left",
          x: grown.x,
          y: grown.y,
          width: grown.widthPt,
          units: "pt",
        });
      }
    }

    // ── 4. Stamp the QR into the PDF (each page's own placement; multi-page
    // all-pages seals carry the display-only `&p=` page tag per page) ─────
    let stamped: Uint8Array = bytes;
    for (const page of targetPages) {
      stamped = await embedQr(stamped, {
        retrievalId: intentId,
        key: shareA,
        placement: placementFor.get(page)!,
        baseUrl: verifyBase,
        tenant,
        qrMac,
        ...(pageTagged ? { pageTag: page } : {}),
      });
    }

    // ── 5. Record WHERE the authentic QR lives, in the commit contract's
    // shape: center-of-QR percentages from the page's top-left + width in
    // points — the wizard's exact convention. With auto placement this is
    // the QR-bearing (canonical) page's own smart-place decision. ─────────
    const { width: pw, height: ph } = pageSizes[canonicalPage - 1]!;
    const rect = resolveQrRect(placementFor.get(canonicalPage)!, pw, ph);
    const qrPlacement = {
      page: canonicalPage,
      x: clampPct(((rect.x + rect.size / 2) / pw) * 100),
      y: clampPct(((ph - rect.y - rect.size / 2) / ph) * 100),
      width: Math.round(rect.size),
    };

    // ── 6. Encrypt the STAMPED bytes; commitment v2 over the ciphertext ──
    // (no AAD — encryption_version 1 on this surface, wizard-compatible).
    const ciphertext = encryptBytes(stamped, fullKey);
    const commitment = commitmentHash(ciphertext);

    // ── 7. The commit body — the dashboard commitSchema, byte-identical ──
    const fields = params.fields ?? {};
    const { reference, dateIssued, expirationDate, notes, ...extraFields } = fields;
    const metadata: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(extraFields)) {
      if (v !== undefined) metadata[k] = v;
    }
    // Sealed page count: disclosed so verifiers can see how many pages the
    // sealed artifact has (the verify page pairs it with the QR's `&p=`
    // orientation tag). A caller-supplied page_count field wins.
    if (metadata["page_count"] === undefined) {
      metadata["page_count"] = pageSizes.length;
    }
    const body: Record<string, unknown> = {
      intent_id: intentId,
      qr_placement: qrPlacement,
      document_type: params.documentType,
      encrypted_file_b64: ciphertext,
      commitment_hash: commitment,
      file_size_bytes: stamped.length,
      file_content_type: "application/pdf",
      file_original_name: params.fileName ?? defaultSealedName(params.file),
      end_cell: true,
      pieces,
      issuer_certified: params.issuerCertified ?? true,
    };
    if (reference !== undefined) body["reference"] = reference;
    if (dateIssued !== undefined) body["date_issued"] = dateIssued;
    if (expirationDate !== undefined) body["expiration_date"] = expirationDate;
    if (notes !== undefined) body["notes"] = notes;
    if (Object.keys(metadata).length > 0) body["metadata"] = metadata;
    if (validUntilIso !== undefined) body["valid_until"] = validUntilIso;

    // ── 8. Commit — one automatic retry on network-shaped failures only ──
    let data: RawCommitResponse;
    try {
      data = await http.request<RawCommitResponse>("POST", "/v1/intent/commit", {
        body,
        auth: true,
      });
    } catch (err) {
      if (!(err instanceof ValidPayError) || err.code !== "network_error") throw err;
      try {
        data = await http.request<RawCommitResponse>("POST", "/v1/intent/commit", {
          body,
          auth: true,
        });
      } catch (retryErr) {
        // The lost-response case: our FIRST commit landed but its response
        // never arrived, so the retry sees already_committed. Only this
        // process holds the reservation's account key material mid-flight —
        // recover as success with the reserve's verification_url (the same
        // single builder the commit response uses).
        if (
          retryErr instanceof ValidPayError &&
          retryErr.code === "already_committed"
        ) {
          data = {
            retrieval_id: intentId,
            ...(reserve.verification_url !== undefined
              ? { verification_url: reserve.verification_url }
              : {}),
          };
        } else {
          throw retryErr;
        }
      }
    }

    // Branded-QR (Prompt 158) decision for the canonical page's stamp —
    // recomputed with the exact URL that page's QR encodes (page-tagged on
    // multi-page all-pages seals) and its exact printed size, so this always
    // matches what embedQr drew.
    const canonicalUrl = pageTagged
      ? buildVerifyUrl(intentId, shareA, {
          baseUrl: verifyBase,
          tenant,
          qrMac,
          page: canonicalPage,
        })
      : verifyUrl;
    const brandedDecision = decideBrandedQr(canonicalUrl, rect.size / PT_PER_MM);

    return {
      sealedPdf: Buffer.from(stamped),
      intentId,
      qrMac,
      verifyUrl,
      brandedQr: {
        branded: brandedDecision.showLogo,
        errorCorrectionLevel: brandedDecision.errorCorrectionLevel,
        modulePitchMm: brandedDecision.modulePitchMm,
      },
      certificateUrl: `${verifyBase}/certificate/${encodeURIComponent(intentId)}`,
      verificationUrl:
        data.verification_url ??
        reserve.verification_url ??
        `${verifyBase}/verify/${encodeURIComponent(intentId)}?t=${encodeURIComponent(tenant)}&m=${encodeURIComponent(qrMac)}`,
      ...(autoDecisions !== undefined ? { autoPlacement: autoDecisions } : {}),
      ...(pageTagged
        ? {
            pageVerifyUrls: targetPages.map((page) => ({
              page,
              url: buildVerifyUrl(intentId, shareA, {
                baseUrl: verifyBase,
                tenant,
                qrMac,
                page,
              }),
            })),
          }
        : {}),
    };
  } catch (err) {
    throw sealError(err, intentId, qrMac, reserve.expires_at);
  }
}
