# @validpay/node-sdk

Official Node.js SDK for [ValidPay](https://validpay.com) — document verification API with **client-side AES-256-GCM encryption**. Sensitive payloads are encrypted on your server before they ever leave the box; ValidPay stores the ciphertext, and only your verifier (with the key you hand them) can read the contents.

- **End-Cell issuance (blind rail)** — 3-of-3 XOR key split across the QR, the platform, and the independent KeyHalve rail; no single party can read or reassemble the key
- **Zero production dependencies** — Node.js built-in `crypto` + native `fetch` only
- **AES-256-GCM** authenticated encryption (tampering is detected on decrypt)
- **Hybrid commitment scheme** — SHA-256 commitment hash detects server-side tampering
- **Split-key verification** (Patent C) — XOR-share the key so neither party alone can decrypt
- **Selective field disclosure** (Patent E) — encrypt fields independently, gate per role
- **Blind revocation** (Patent H) — revoke / reinstate / inspect audit history
- **Time-locked verification** (Patent D) — validFrom / validUntil windows
- **TypeScript-first**, ESM-only, requires Node `>= 20`
- The encryption key is **never** sent to the ValidPay API

## Install

```bash
npm install @validpay/node-sdk
```

## Quick start

```ts
import { ValidPayClient } from "@validpay/node-sdk";

const client = new ValidPayClient({ apiKey: process.env.VALIDPAY_API_KEY! });

// 1. Issuer side — seal with End-Cell (recommended). The AES key is split
//    THREE ways: `key` is ShareA (rides the QR); one share goes to the
//    platform; one goes to the independent KeyHalve rail. No single party —
//    not the platform, not KeyHalve — can read or reassemble the key.
const { retrievalId, key } = await client.createEndCellIntent({
  documentType: "ssn_card",
  payload: { ssn: "123-45-6789", name: "Jane Doe" },
  // holders defaults to ["keyhalve", "platform"] → a 3-of-3 split with ShareA
});

// retrievalId is public (e.g. "vp_abc123def456") — embed in a QR code.
// key (ShareA) is secret — deliver it ONLY to the intended verifier, out-of-band.

// 2. Verifier side — fetch and decrypt (no API key needed). verifyIntent
//    fetches the platform share + the rail share (the rail's Ed25519 signature
//    is verified against a PINNED key, fail-closed), recombines in memory,
//    decrypts locally, and re-checks the commitment hash.
const result = await client.verifyIntent<{ ssn: string; name: string }>(retrievalId, key);

console.log(result.payload);             // { ssn: "123-45-6789", name: "Jane Doe" }
console.log(result.integrityVerified);   // true — commitment hash matched
console.log(result.issuer);              // "Acme Bank"
console.log(result.issuerVerified);      // true
```

> **Simpler 2-share option:** `createIntent()` defaults to split-key — the key is
> split between the document and the platform only, with no independent rail
> share, so the platform alone could reconstruct. Prefer **End-Cell** above when
> independence from the platform matters.

### Building a verification URL

The `retrievalId` is public; the `key` is secret. Stamp them into a URL fragment (the `#` part — fragments are never sent to the server, even by curl) so a single link both identifies the intent and decrypts it:

```ts
function toBase64Url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const verifyUrl = `https://verify.keyhalve.com/verify/${retrievalId}#key=${toBase64Url(key)}`;
// → encode in a QR, paste in an email, scan with a phone camera.
// The /verify page reads the fragment client-side and decrypts locally.
```

`toBase64Url` matters because phone QR scanners + browser share-sheets mangle `+`, `/`, and `=` in URL fragments. The `/verify` page accepts both standard base64 and base64url for backward compatibility, but new links should always emit base64url.

### Placing the QR on a document (`embedQr`)

For a PDF, `embedQr` builds the verify QR and stamps it onto the page for you — so you don't have to wire up a QR library, base64url the key, or wrestle with PDF coordinates (PDFs use a bottom-left origin; everything else uses top-left).

`embedQr` needs two **optional** peer dependencies — the core client stays dependency-free, so install them only if you use it:

```bash
npm i pdf-lib qrcode
```

```ts
import { ValidPayClient, embedQr } from "@validpay/node-sdk";
import { readFile, writeFile } from "node:fs/promises";

const client = new ValidPayClient({ apiKey: process.env.VALIDPAY_API_KEY! });

const original = await readFile("invoice.pdf");
const { retrievalId, key } = await client.createFileIntent({
  documentType: "invoice",
  file: original,
  fileContentType: "application/pdf",
});

const sealed = await embedQr(original, {
  retrievalId,
  key,
  // 90pt (1.25in) QR, 36pt in from the bottom-right corner.
  placement: { anchor: "bottom-right", x: 36, y: 36, width: 90 },
});
await writeFile("invoice-sealed.pdf", sealed);
```

#### The placement contract

Coordinates read the way you think about a page, and are identical to what the **"Try it" placement tool** in the developer console emits — so position once in the UI, copy the call, and it lands in the same spot.

| field    | meaning | default |
| -------- | ------- | ------- |
| `anchor` | which page **corner** the insets are measured from (`top-left` \| `top-right` \| `bottom-left` \| `bottom-right`) | `top-left` |
| `x`      | horizontal inset from that corner's vertical edge | — |
| `y`      | vertical inset from that corner's horizontal edge | — |
| `width`  | QR side length (it's square) | — |
| `units`  | `pt` (1/72in) \| `mm` \| `in` | `pt` |
| `page`   | 1-based page number | `1` |

`{ anchor: "bottom-right", x: 36, y: 36, width: 90 }` sits 36pt in from the bottom and right edges — and stays bottom-right on any page size. Keep the QR **≥ ~72pt (1in)** so it scans reliably once printed; `embedQr` warns below that and throws if the placement runs off the page.

If you render PDFs with a different library, the two pure helpers are exported too:

```ts
import { buildVerifyUrl, resolveQrRect } from "@validpay/node-sdk";

const url  = buildVerifyUrl(retrievalId, key);               // base64url key in the fragment
const rect = resolveQrRect(placement, pageWidthPt, pageHeightPt); // → { x, y, size } in pdf bottom-left points
```

## How it works

**End-Cell (recommended, 3-share):**

1. `createEndCellIntent` generates a fresh 256-bit key, encrypts your payload locally with AES-256-GCM, computes a SHA-256 commitment hash of the plaintext, and XOR-splits the key three ways: **ShareA** (returned to you, rides the QR), one share held by the platform, and one share held by the independent **KeyHalve rail**. Only ciphertext + commitment hash + the two escrowed shares leave your box — never the full key.
2. The verifier calls `verifyIntent`, which fetches the platform share and the rail share (the rail's Ed25519 signature is verified against a pinned key, fail-closed), recombines all three shares in memory, decrypts locally, and re-checks the commitment hash. **The full key never exists on any single system.**

**Split-key (2-share, the `createIntent` default):**

1. `createIntent` generates a fresh 256-bit key, encrypts your payload locally with AES-256-GCM, computes a SHA-256 commitment hash of the plaintext, and POSTs only the ciphertext + hash to `POST /v1/intent`.
2. The API returns a public `retrieval_id` and stores the ciphertext + commitment hash.
3. You hand the verifier the `retrievalId` and the `key` through your own secure channel.
4. The verifier calls `verifyIntent`, which fetches `GET /v1/intent/:id`, decrypts the ciphertext locally, then recomputes the commitment hash and compares — any server-side tampering would change the hash.

The key is generated client-side, used client-side, and transmitted client-side. ValidPay can never read the payload.

## API reference

### `new ValidPayClient(options)`

| Option    | Type                | Default                     | Notes                                       |
| --------- | ------------------- | --------------------------- | ------------------------------------------- |
| `apiKey`  | `string` (required) | —                           | Your ValidPay issuer API key.               |
| `baseUrl` | `string`            | `"https://api.validpay.com"` | Override for staging or self-hosted setups. |
| `timeout` | `number`            | `30000`                     | Request timeout (ms).                       |
| `fetch`   | `typeof fetch`      | global `fetch`              | Inject a custom fetch (useful for testing). |

### End-Cell (recommended)

#### `client.createEndCellIntent({ documentType, payload, holders?, validFrom?, validUntil?, onBehalfOf? }) → { retrievalId, key }`

KeyHalve's blind-rail flow. Generates a key, encrypts `JSON.stringify(payload)`, and XOR-splits the key into **ShareA** (returned as `key`, for the QR) plus one share per holder. `holders` defaults to `["keyhalve", "platform"]` → a **3-of-3** split: the independent KeyHalve rail share + the platform share + ShareA. No single party can read or reassemble the key. Verify with `verifyIntent` (below), which fetches the platform + rail shares, verifies the rail's Ed25519 signature against a **pinned** key (fail-closed), recombines in memory, and decrypts. **The full key never exists on any single system.** Requires the API deployment to have End-Cell issuance enabled.

```ts
const { retrievalId, key } = await client.createEndCellIntent({
  documentType: "ssn_card",
  payload: { ssn: "123-45-6789" },
});
const result = await client.verifyIntent(retrievalId, key); // one call handles all share models
```

### Core

#### `client.createIntent({ documentType, payload, validFrom?, validUntil?, splitKey?, onBehalfOf? }) → { retrievalId, key }`

Generates a key, encrypts `JSON.stringify(payload)`, posts ciphertext + commitment hash to `/v1/intent`. Defaults to **split-key** (2-share): the returned `key` is Share A and Share B goes to the platform — neither alone decrypts, but there is **no independent rail share** (the platform alone could reconstruct). For independence from the platform, prefer **`createEndCellIntent`** above. Pass `splitKey: false` for the legacy single-key flow. **The full key is never sent to the API.**

#### `client.createIntentBatch(items[]) → { retrievalId, key }[]`

Same as `createIntent` for up to 100 intents in a single request. Each item gets a unique AES key; results match the input order.

#### `client.verifyIntent<T>(retrievalId, key) → VerifyIntentResult<T>`

Fetches the intent and decrypts the payload locally. Verifies the commitment hash. Throws `ValidPayError`:

- `decryption_failed` — wrong key or tampered ciphertext (GCM auth-tag failure)
- `integrity_failure` — commitment hash mismatch (server-side tampering detected)
- `intent_revoked` — the intent has been revoked
- `split_key_required` / `selective_disclosure_required` — use the specialised verify method

```ts
interface VerifyIntentResult<T> {
  intentId: string;
  payload: T;
  issuer: string;
  issuerVerified: boolean;
  registeredAt: string; // ISO 8601
  status: string;
  integrityVerified: boolean;
  validFrom?: string | null;
  validUntil?: string | null;
  timeLockStatus?: "valid" | "not_yet_valid" | "expired" | null;
}
```

### Split-key (Patent C) — the `createIntent` default (2-share)

All documents created with SDK v0.4+ use split-key by default — `createIntent`
returns Share A and stores Share B at the API; `verifyIntent` detects a
split-key intent, fetches Share B from `/v1/intent/:id/fragment`,
XOR-combines, and decrypts:

```ts
const { retrievalId, key: shareA } = await client.createIntent({
  documentType: "ssn_card",
  payload: { ssn: "123-45-6789" },
});
// shareA goes in the QR; shareB stays at the API.

const result = await client.verifyIntent(retrievalId, shareA);
```

Backward compatibility: `createIntent({ ..., splitKey: false })` gives the
legacy single-key flow; `createSplitKeyIntent()` is a deprecated alias of
`createIntent()` (emits a `DeprecationWarning`); `verifySplitKeyIntent()`
still works.

### Platform delegation — `onBehalfOf`

If you integrate as a **platform** and seal on behalf of the businesses you
serve, name the business on each seal. The verifier sees that business as the
issuer ("who"), attributed *through* your platform ("through whom"), at the
`delegated` trust rung. The businesses never touch ValidPay — no account, no
login — and ValidPay stays blind to the document contents.

```ts
const { retrievalId, key } = await client.createIntent({
  documentType: "lease",
  payload: { unit: "4B", term: "12mo" },
  onBehalfOf: {
    ref: "landlord_8675309",        // YOUR id for this business (the dedupe key)
    name: "Smith Properties LLC",   // who the verifier sees
  },
});

const result = await client.verifyIntent(retrievalId, key);
result.issuer;            // "Smith Properties LLC"
result.verificationLevel; // "delegated"
result.delegatedBy;       // { platform: "Your Platform", platformLevel: "domain" }
```

Same `ref` ⇒ same tracked business (its documents and verification counts roll
up). A sub-issuer surfaces as `delegated` only once **your** platform account is
domain-verified; until then its documents show as unverified.

### Selective disclosure (Patent E)

```ts
const { retrievalId, key } = await client.createSelectiveIntent({
  documentType: "check",
  payload: { amount: 1500, payee: "Alice", memo: "rent" },
  disclosurePolicy: {
    bank: ["amount"],
    auditor: ["amount", "payee"],
  },
});

const bankView = await client.verifySelectiveIntent(retrievalId, key, "bank");
// { amount: 1500, payee: "[REDACTED]", memo: "[REDACTED]" }

const fullView = await client.verifySelectiveIntent(retrievalId, key, "full");
// { amount: 1500, payee: "Alice", memo: "rent" }
```

### Audit + list (Prompt 080)

When you need to reconcile your own records against ValidPay — "how many intents did I create this month, and which got scanned?" — use the audit endpoints. **Metadata only; no ciphertext, no key material.**

```ts
const { intents, total } = await client.listIntents({
  since: "2026-06-01T00:00:00Z",
  status: "active",
  limit: 100,
});
//   total: 142
//   intents[0]: {
//     retrievalId: "vp_abc123def456",
//     documentType: "check",
//     status: "active",
//     createdAt: "2026-06-04T15:52:25Z",
//     verificationCount: 3,
//     lastVerifiedAt: "2026-06-04T16:01:00Z",
//     ...
//   }

const meta = await client.getIntent("vp_abc123def456");
//   status, verificationCount, revokedAt, etc.
//   Use verifyIntent(retrievalId, key) if you want to decrypt.
```

Filters: `since` / `until` (ISO datetime), `status` (`active` | `revoked`), `documentType`, `limit` (≤200), `offset`, `order` (`asc` | `desc`).

### Revocation (Patent H)

```ts
await client.revokeIntent(retrievalId, "stop payment requested");
await client.reinstateIntent(retrievalId, "false alarm");
const history = await client.getRevocationHistory(retrievalId);
```

### Health

```ts
const { status, version } = await client.health();
```

### Low-level crypto helpers

```ts
import {
  generateKey,
  encrypt,
  decrypt,
  commitmentHash,
  splitKey,
  combineKeyShares,
  encryptFields,
  buildKeyMap,
  decryptFields,
} from "@validpay/node-sdk";

const key = generateKey();                       // base64 32-byte key
const blob = encrypt("hello world", key);        // base64(iv[12] || authTag[16] || ciphertext)
const plain = decrypt(blob, key);                // "hello world"
const hash = commitmentHash(plain);              // SHA-256 hex

const [a, b] = splitKey(key);
const reconstructed = combineKeyShares(a, b);    // === key
```

### `ValidPayError`

All SDK errors throw `ValidPayError` with a stable `code`:

| Code                            | Meaning                                                       |
| ------------------------------- | ------------------------------------------------------------- |
| `invalid_config`                | Missing `apiKey` (or other constructor options).              |
| `invalid_argument`              | Required method argument is missing or invalid.               |
| `invalid_key`                   | Key is not valid base64 or not 32 bytes.                      |
| `invalid_blob`                  | Blob is not valid base64 or too short.                        |
| `decryption_failed`             | Wrong key, or ciphertext tampered (GCM auth-tag failure).     |
| `integrity_failure`             | Commitment hash didn't match — server tampering detected.     |
| `intent_revoked`                | The intent has been revoked.                                  |
| `split_key_required`            | Intent uses split-key; use `verifySplitKeyIntent` instead.    |
| `selective_disclosure_required` | Intent uses per-field encryption; use `verifySelectiveIntent`. |
| `invalid_role`                  | Role not present in the disclosure policy.                    |
| `missing_fragment`              | API did not return a key fragment for a split-key intent.     |
| `network_error`                 | `fetch` itself rejected (DNS, TCP, abort, etc.).              |
| `http_error`                    | API returned non-2xx with no machine-readable error.          |
| `not_found`                     | API returned 404 (e.g. unknown retrieval ID).                 |
| `unauthorized`                  | API returned 401 (invalid or missing API key).                |
| `invalid_response`              | API returned 2xx but response shape was unexpected.           |
| `invalid_payload`               | Decrypted bytes were not valid JSON.                          |

### API error codes (wire format)

When the API itself rejects a request, the response body carries a canonical `code` field alongside the legacy `error` string. SDKs (this one included) surface both — use `code` for exhaustive `switch` checks because the values are stable across versions.

| `code`                   | HTTP | Meaning                                                                   |
| ------------------------ | ---- | ------------------------------------------------------------------------- |
| `INVALID_BODY`           | 400  | Request body failed schema validation. `details` carries the field-level errors. |
| `INVALID_CREDENTIALS`    | 401  | Wrong email or password on /v1/auth/login.                                |
| `INVALID_API_KEY`        | 401  | API key is missing, malformed, or revoked.                                |
| `MISSING_TOKEN`          | 401  | Endpoint requires a bearer token and didn't get one.                       |
| `INVALID_TOKEN`          | 401  | Bearer token is expired or doesn't decode.                                |
| `ACCOUNT_LOCKED`         | 423  | Too many failed sign-ins. `message` carries the retry window.             |
| `INSUFFICIENT_SCOPE`     | 403  | API key doesn't have the scope this endpoint requires.                    |
| `INTENT_NOT_FOUND`       | 404  | No intent matches this retrieval ID.                                      |
| `INTENT_REVOKED`         | 200  | Body is intentionally empty — issuer revoked the intent.                  |
| `DOCUMENT_LIMIT_REACHED` | 402  | Free or sandbox quota exhausted. `message` describes the upgrade path.    |
| `PAYLOAD_TOO_LARGE`      | 413  | Encrypted payload exceeds the per-route limit (25 MB for uploads).        |
| `RATE_LIMIT_EXCEEDED`    | 429  | Per-API-key bucket exhausted. Honour the `Retry-After` header.            |
| `VALIDATION_ERROR`       | 422  | Domain-level rule rejected the request (e.g. `valid_from > valid_until`). |
| `NOT_FOUND`              | 404  | Generic — the route exists but the resource doesn't.                      |
| `INTERNAL_ERROR`         | 500  | Unhandled server error. Retry with backoff; report if it persists.        |

The full list lives in [`ValidPay-API/src/errorCodes.ts`](https://github.com/ValidPay-io/ValidPay-API/blob/main/src/errorCodes.ts).

### Webhook verification (Prompt 079)

ValidPay POSTs intent events (`intent.created`, `intent.verified`, `intent.revoked`, `intent.reinstated`) to URLs you register via `POST /v1/webhooks`. Every delivery carries an HMAC signature in the `X-ValidPay-Signature` header — verify it before trusting the body:

```ts
import express from "express";
import { verifyWebhookSignature } from "@validpay/node-sdk";

const app = express();

app.post(
  "/webhooks/validpay",
  // CRITICAL: read the body as raw bytes, not parsed JSON. The HMAC is
  // computed over the EXACT bytes ValidPay sent; JSON.parse loses the
  // key order and whitespace and the signature won't match.
  express.raw({ type: "application/json" }),
  (req, res) => {
    const rawBody = (req.body as Buffer).toString("utf8");
    const result = verifyWebhookSignature(
      req.headers["x-validpay-signature"] as string | undefined,
      rawBody,
      process.env.VALIDPAY_WEBHOOK_SECRET!,
    );
    if (!result.valid) return res.status(401).send(result.reason);

    const event = JSON.parse(rawBody);
    switch (event.event) {
      case "intent.revoked":
        // update your local record, remove "Verified" badge, etc.
        break;
      case "intent.verified":
        // someone scanned the QR
        break;
    }
    res.status(200).send("OK");
  },
);
```

`verifyWebhookSignature` enforces a 5-minute replay window by default. Configure via the `toleranceSeconds` option if you need more.

Also worth knowing:
- `X-ValidPay-Delivery-Id` carries a per-delivery UUID — deduplicate on this to handle at-least-once retries.
- Failed deliveries retry on exponential backoff (5s → 30s → 5min). Non-retryable 4xx responses are not re-attempted.
- The dashboard endpoint `GET /v1/webhooks/:id/deliveries` returns the last 50 attempts so you can see what landed and what didn't.

### Rate limits

All authenticated responses carry three standard headers — read them to pace yourself before you hit a 429:

| Header                  | Meaning                                                                |
| ----------------------- | ---------------------------------------------------------------------- |
| `X-RateLimit-Limit`     | Cap per API key per minute. Currently 600.                             |
| `X-RateLimit-Remaining` | Requests left in the current window.                                   |
| `X-RateLimit-Reset`     | UNIX timestamp (seconds) when the window resets.                       |

On 429 you'll also see `Retry-After` (seconds) — the SDK doesn't auto-retry; honour it from your caller.

## Blob format

`encrypt()` returns a base64 string whose decoded bytes are:

```
[ iv (12 bytes) | authTag (16 bytes) | ciphertext (variable) ]
```

This matches the Python SDK exactly, so blobs are interoperable in both directions.

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT — see [LICENSE](./LICENSE).
