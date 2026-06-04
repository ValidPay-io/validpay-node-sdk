# Changelog

All notable changes to `@validpay/node-sdk` are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

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
