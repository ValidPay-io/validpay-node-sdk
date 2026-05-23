# @validpay/node-sdk

Official Node.js SDK for [ValidPay](https://validpay.io) — document verification API with **client-side AES-256-GCM encryption**. Sensitive payloads are encrypted on your server before they ever leave the box; ValidPay stores the ciphertext, and only your verifier (with the key you hand them) can read the contents.

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

// 1. Issuer side — register an intent with sensitive payload
const { retrievalId, key } = await client.createIntent({
  documentType: "ssn_card",
  payload: { ssn: "123-45-6789", name: "Jane Doe" },
});

// retrievalId is public (e.g. "vp_abc123def456") — embed in a QR code.
// key is secret — deliver it ONLY to the intended verifier, out-of-band.

// 2. Verifier side — fetch and decrypt (no API key needed)
const result = await client.verifyIntent<{ ssn: string; name: string }>(retrievalId, key);

console.log(result.payload);             // { ssn: "123-45-6789", name: "Jane Doe" }
console.log(result.integrityVerified);   // true — commitment hash matched
console.log(result.issuer);              // "Acme Bank"
console.log(result.issuerVerified);      // true
```

## How it works

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
| `baseUrl` | `string`            | `"https://api.validpay.io"` | Override for staging or self-hosted setups. |
| `timeout` | `number`            | `30000`                     | Request timeout (ms).                       |
| `fetch`   | `typeof fetch`      | global `fetch`              | Inject a custom fetch (useful for testing). |

### Core

#### `client.createIntent({ documentType, payload, validFrom?, validUntil? }) → { retrievalId, key }`

Generates a key, encrypts `JSON.stringify(payload)`, posts ciphertext + commitment hash to `/v1/intent`. **The key is never sent to the API.**

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

### Split-key (Patent C)

```ts
const { retrievalId, key: shareA } = await client.createSplitKeyIntent({
  documentType: "ssn_card",
  payload: { ssn: "123-45-6789" },
});
// shareA goes in the QR; shareB stays at the API.

const result = await client.verifySplitKeyIntent(retrievalId, shareA);
// SDK fetches shareB from /v1/intent/:id/fragment, XOR-combines, decrypts.
```

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
