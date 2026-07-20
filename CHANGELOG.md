# Changelog

All notable changes to `@validpay/node-sdk` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Size-adaptive branded QR (Prompt 158) — every stamped verify QR now
  carries the centered KeyHalve split-circle mark when the printed size
  allows it.** The shared contract file `src/brandedQr.ts` (BYTE-IDENTICAL to
  the copies in keyhalve-console, validpay-website, and checkbooks; sha256
  `ea5d054af32bc4eb6c7014a510adc0fd5cb277052435d1fa6acbf339a9df392d`, guarded
  by a test) decides from payload length + printed size alone: module pitch
  ≥ 0.4 mm → EC-H with the mark, below → plain EC-M (current behavior —
  scan reliability always wins). `embedQr` now draws the QR as native **PDF
  vector art** (background, modules, mark — no raster, no new dependencies;
  `qr.renderPx` is accepted but ignored), and an explicit non-H
  `qr.errorCorrectionLevel` or custom `qr.margin` opts out of the contract.
  `sealDocument` results gain `brandedQr` (`branded`, `errorCorrectionLevel`,
  `modulePitchMm`). New exports: `renderBrandedQrSvg`, `decideBrandedQr`,
  `modulesForPayload`, `keyhalveMarkSvg`, `injectKeyhalveMark`,
  `QR_MARGIN_MODULES`, `LOGO_MIN_MODULE_MM`, `LOGO_DISC_RADIUS_FRAC`,
  `LOGO_SPLIT_WIDTH_FRAC`, `PT_PER_MM`, plus `QrBrandingInfo` /
  `BrandedQrDecision` types. Build note: the contract file compiles in its own
  referenced sub-project (`tsconfig.contract.json`) because it cannot satisfy
  `noUncheckedIndexedAccess`; `build`/`typecheck` now go through `tsc -b`.

- **Smart-place: `placement: "auto"` for `sealDocument` — automatic
  clear-space QR placement, computed locally.** The shared contract file
  `src/smartPlace.ts` (`chooseClearRect`) picks the QR spot from the page's
  own content: deterministic candidate ladder (preferred corner → remaining
  corners → bottom/top center → progressively smaller widths down to
  `minWidthPt` → fail-open fallback at the preferred corner, flagged
  `fallback: true`). Obstacles come from `src/pdfObstacles.ts`
  (`extractPageObstacles`): text runs (getTextContent), images
  (getOperatorList paint ops under the tracked CTM), and vector paths where
  pdf.js exposes bounds; full-bleed boxes (≥ 90% page coverage) are treated
  as background. Both files are BYTE-IDENTICAL contract copies shared with
  validpay-mcp and validpay-website. Requires the new OPTIONAL peer
  `pdfjs-dist` (auto only — everything else works without it; a clear
  `missing_dependency` error names the peer). `placement` accepts
  `"auto"` or `{ mode: "auto", page?, preferredAnchor?, qrWidthPt?,
  marginPt?, clearancePt?, minWidthPt? }`; the result gains
  `autoPlacement` (per-page decisions incl. `shrunk` / `fallback`). New
  exports: `chooseClearRect`, `SMART_PLACE_DEFAULTS`, `extractPageObstacles`,
  `computeAutoPlacements`, plus their types.
- **Display-only page tags (`&p=`) on all-pages seals.** Multi-page
  `allPages: true` seals stamp each page's QR with `&p=<page>` (after `?t`
  and `&m`, before `#key=`) so a verifier can say "scanned from page N" —
  an orientation tag only, NEVER a security claim; the attested verify
  engine ignores it (tolerance verified against the live engine).
  `buildVerifyUrl` gains `page`, `embedQr` gains `pageTag`, and the seal
  result gains `pageVerifyUrls` (page → tagged URL). Single-page documents
  and single-page placements stay untagged, byte-identical to before.
- **Sealed page count disclosed.** `sealDocument` now records the document's
  total page count as disclosed metadata (`metadata.page_count`; a
  caller-supplied `page_count` field wins) so verify surfaces can pair it
  with the `&p=` tag ("this document has N pages").
- **Document-payload verification.** `verifyIntent` (and
  `verifySplitKeyIntent`) now verify seal-at-source v0.2 DOCUMENT seals:
  when the decrypted payload is not JSON and the intent carries file
  metadata (`file_content_type` / `file_size_bytes`), the result is
  document-shaped — `payloadKind: "document"` plus `document:
  { contentType, byteSize, declaredByteSize, sha256 }` (sha256 of the
  decrypted bytes, i.e. the distributable artifact's own fingerprint) —
  instead of failing `invalid_payload`. JSON payloads are unchanged
  (`payloadKind: "json"`); only a genuine non-JSON, non-document payload
  still throws `invalid_payload`.

- **`client.sealDocument(params)` — the ONE-CALL document seal (seal-at-source
  v0.2).** A PDF goes in (bytes or path), the sealed+stamped PDF comes out:
  the file you distribute IS the file that verifies. Orchestrates the API's
  reserve→commit pair (`POST /v1/intent/reserve` + `POST /v1/intent/commit`,
  ValidPay-API #145) with ALL crypto local — reserve the identity, End-Cell
  split a fresh AES-256 key (rail + platform custody, same as
  `createEndCellIntent`), stamp the converged verify QR (`?t=&m=#key=`) into
  the PDF via `embedQr` (every page with `allPages: true`; page 1 recorded as
  the canonical `qr_placement`, matching the dashboard wizard), encrypt the
  STAMPED bytes, commitment v2 over the ciphertext, commit against the held
  draft. Returns `{ sealedPdf, intentId, qrMac, verifyUrl, certificateUrl,
  verificationUrl }`. Requires an account-linked API key with `intent:create`
  and the optional peer deps `pdf-lib` + `qrcode`. PDF input only in v0.2
  (non-PDF throws `unsupported_file_type`); `validFrom` is not part of the
  commit contract and throws `invalid_argument` (use `valid_until` only).
  Commit failures carry `details.reservation_id` / `details.qr_mac` (the
  draft stays held server-side, 24 h TTL, fail-closed); network-shaped commit
  failures are retried once automatically, and a retry answered
  `already_committed` (lost response) is recovered as success.
- `readPdfPageSizes(pdf)` — page geometry helper (points) on the same lazy
  `pdf-lib` loader as `embedQr`; used to convert the canonical placement to
  the commit contract's center-percent `qr_placement` record.
- New exports: `DEFAULT_SEAL_PLACEMENT` (1.0 in QR, bottom-right, 0.5 in
  inset), `SealDocumentParams`, `SealDocumentFields`, `SealDocumentResult`,
  `PdfPageSize`.

### Fixed

- **Anti-fake QR MAC (`?m=`) forwarding to the KeyHalve rail.** Documents sealed
  since QR-MAC enforcement carry `&m=` in their verify URL, and the rail gates
  `GET /v1/piece/{id}` behind it. `verifyIntent` now accepts the value as an
  explicit option — `verifyIntent(id, key, { qrMac })` — and forwards it as
  `?m=` on the rail piece request. Previously the MAC was never forwarded, so
  MAC-gated documents 403'd and surfaced as a generic `rail_error` ("rail
  unreachable") even though the rail was healthy.
- **Distinct fail-closed MAC errors (never network errors).** Rail 403
  `mac_invalid` → `ValidPayError("qr_mac_invalid")` — the presented QR/URL is
  not the one issued for this document; treat it as fraudulent. Rail 403
  `mac_required` → `ValidPayError("qr_mac_required")` — the caller must supply
  the document's anti-fake code (`m`) from its QR/URL. Real transport failures
  remain `rail_unreachable` / `rail_error`. The pinned-key Ed25519 signature
  verification of the rail response is unchanged.

- **Seal side: the rail-minted `qr_mac` is no longer dropped.** POST
  `/v1/intent` returns a one-time `qr_mac` for End-Cell seals minted under
  QR-MAC enforcement; the SDK silently discarded it, so freshly sealed
  documents got QRs without `?m=` — which scan RED. Every creation path
  (`createIntent`, `createEndCellIntent`, `createFileIntent`,
  `createSelectiveIntent`, and per-item in `createIntentBatch`) now surfaces
  it as `CreateIntentResult.qrMac`.

### Added

- `buildVerifyUrl` / `embedQr` emit the converged verify-URL shape:
  `<base>/verify/<id>[?t=<tenant>][&m=<qrMac>]#key=…` via new
  `VerifyUrlOptions.tenant` and `VerifyUrlOptions.qrMac` (`t` before `m`,
  params omitted when absent; the bare legacy shape is byte-identical when
  neither is given).
- `VerifyIntentOptions` (with `qrMac`) and the `QR_MAC_RE` shape
  (`/^[A-Za-z0-9_-]{8,16}$/`) are exported for callers that parse verify URLs.

## [0.9.0] — 2026-07-02

### Added

- **End-Cell issuance — `createEndCellIntent()`** (recommended). KeyHalve's
  blind-rail flow: encrypts the payload locally and XOR-splits the AES key into
  **ShareA** (returned as `key`, rides the QR) plus one share per holder
  (`holders` defaults to `["keyhalve", "platform"]` → a 3-of-3 split). No
  single party — not the platform, not KeyHalve — can read or reassemble the
  key. Requires the API deployment to have End-Cell issuance enabled.
- **Rail verify.** `verifyIntent` now detects End-Cell intents and fetches the
  independent KeyHalve rail share alongside the platform share, verifying the
  rail's Ed25519 signature against a **pinned** key (fail-closed) before
  recombining in memory and decrypting. One `verifyIntent` call handles all
  share models.

### Changed

- **Canonical verify origin is now `https://verify.keyhalve.com`.**
  `buildVerifyUrl` (and `embedQr`) emit verify links on the canonical
  KeyHalve verifier origin by default.
- README leads with End-Cell (recommended) — quick start, feature list, and
  "How it works" document the 3-share blind-rail flow first; split-key stays
  the `createIntent` default (2-share).

## [0.8.0] — 2026-06-18

### Added

- **Platform delegation — `onBehalfOf`** (Fork B). Platforms that seal on behalf
  of the businesses they serve can now declare which business each seal is for:
  pass `onBehalfOf: { ref, name }` to `createIntent` / `createFileIntent` /
  `createSelectiveIntent` / `createIntentBatch`. `ref` is your own id for the
  business (the dedupe key — same `ref` rolls up); `name` is who the verifier
  sees. The verifier sees that business as the issuer, attributed *through* your
  platform, at the `delegated` trust rung. ValidPay stays blind to the document
  contents — this is identity only.
- `verifyIntent` now surfaces `verificationLevel` (`none` < `delegated` <
  `domain` < `business`) and `delegatedBy` (`{ platform, platformLevel }`, or
  `null`) so verifiers can render the graded badge.

> Requires the ValidPay API with platform-delegation support deployed.

## [0.6.0] — 2026-06-16

### Added

- **File mode — `createFileIntent()`** (Prompt 099). Seal a full document file
  (PDF, image, DOCX, …) end-to-end: pass the raw bytes (`Uint8Array`/`Buffer`),
  an optional `fileName` and `fileContentType`, and the SDK AES-256-GCM-encrypts
  the bytes locally (split-key by default) and registers them with file
  metadata. A verifier decrypts back the exact original bytes for a
  byte-for-byte match and the correct download type.
- Low-level `encryptBytes()` / `decryptBytes()` helpers for raw-bytes payloads
  (the existing `encrypt()` / `decrypt()` now delegate to them).

## [0.4.0] — 2026-06-12

### Changed

- **Split-key protection (Patent C) is now the default** (Prompt 094).
  `createIntent()` splits the AES key into two XOR shares: Share A is
  returned as `key`, Share B is stored on the ValidPay server. The full
  decryption key never exists on any single system after the call
  returns. Pass `splitKey: false` for the legacy single-key flow.
- `verifyIntent()` now verifies split-key intents transparently: when
  the API marks an intent `split_key`, it fetches Share B from the
  fragment endpoint and XOR-combines it with the key you pass (Share A),
  instead of throwing `split_key_required`. Legacy intents verify
  exactly as before.

### Deprecated

- `createSplitKeyIntent()` — now an alias for `createIntent()` (which
  does split-key by default). Emits a `DeprecationWarning` once per
  process; will be removed in 1.0.

## [0.3.1] — 2026-06-08

### Changed
- `DEFAULT_BASE_URL` is now `https://api.validpay.com` (Prompt 086B —
  primary domain migrated from validpay.io to validpay.com). The old
  `api.validpay.io` continues to work via Cloudflare 301 redirects, so
  existing installations on 0.3.0 are unaffected; new installs default
  to the .com origin. `baseUrl` override still wins when set.
- README links + sample verify URL updated to `validpay.com`.

## [0.3.0] — 2026-06-04

### Added
- `client.listIntents(params?)` — paginated audit/reconciliation list with
  filters: `since`, `until`, `status`, `documentType`, `limit` (≤ 200),
  `offset`, `order`. Returns metadata only — never the AES key or
  ciphertext. (Prompt 080)
- `client.getIntent(retrievalId)` — single-intent metadata fetch.
  Distinct from `verifyIntent`: no decryption, no key required, intended
  for "is this intent still active and how often was it verified?"
  reconciliation checks. (Prompt 080)
- `verifyWebhookSignature(headerValue, rawBody, secret, opts?)` —
  port of the API's HMAC-SHA256 verification with constant-time
  compare. 5-minute default replay window via `toleranceSeconds`.
  Discriminated-union return type with enumerable failure reasons
  (`missing_header`, `malformed_header`, `unsupported_version`,
  `bad_signature`, `timestamp_outside_tolerance`). (Prompt 079)
- README sections: "Building a verification URL" (with the
  `toBase64Url` helper inline), "API error codes (wire format)",
  "Rate limits" (X-RateLimit-Limit / Remaining / Reset), and a full
  "Webhook verification" integration recipe with the express.raw
  ingestion pattern. (Prompt 077)
- New types: `ListIntentsParams`, `ListIntentsResult`, `IntentMetadata`,
  `VerifyWebhookOptions`, `WebhookVerifyResult`, `WebhookVerifyFailureReason`.
- 11 unit tests covering every public outcome of
  `verifyWebhookSignature`. (Prompt 084)
- First GitHub Actions CI workflow (build + test on push/PR).

### Changed
- README polished for first-time integrators. Quick-start example,
  full API reference, and error-code table all live above the fold.

### Compatibility
- Fully backward-compatible. Existing `createIntent`, `verifyIntent`,
  `createIntentBatch`, `revokeIntent`, and `reinstateIntent` callers
  see no behavioural change.

## [0.2.0]

- Webhook routes + signing infrastructure on the server side; SDK
  helper not yet exposed. (Predates the 0.3.0 work above.)

## [0.1.0]

- Initial public release.
