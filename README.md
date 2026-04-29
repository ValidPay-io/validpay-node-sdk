# @validpay/node-sdk

Official Node.js SDK for [ValidPay](https://validpay.io) — document verification API with **client-side AES-256-GCM encryption**. Sensitive payloads are encrypted on your server before they ever leave the box; ValidPay stores the ciphertext, and only your verifier (with the key you hand them) can read the contents.

- **Zero production dependencies** — Node.js built-in `crypto` + native `fetch` only
- **AES-256-GCM** authenticated encryption (tampering is detected on decrypt)
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

// retrievalId is public (e.g. "vp_abc123def456") — share it with the verifier.
// key is secret (44-char base64) — share it ONLY with the intended verifier,
//     out-of-band (encrypted email, secure message, etc.). Never put it in a URL.

// 2. Verifier side — fetch and decrypt
const result = await client.verifyIntent<{ ssn: string; name: string }>(retrievalId, key);

console.log(result.payload);          // { ssn: "123-45-6789", name: "Jane Doe" }
console.log(result.issuer);           // "Acme Bank"
console.log(result.issuerVerified);   // true
console.log(result.registeredAt);     // "2026-04-29T12:00:00.000Z"
```

## How it works

1. `createIntent` generates a fresh 256-bit key, encrypts your payload locally with AES-256-GCM, and POSTs only the ciphertext to `POST /v1/intent`.
2. The API returns a public `retrieval_id` and stores the ciphertext.
3. You hand the verifier the `retrievalId` and the `key` through your own secure channel.
4. The verifier calls `verifyIntent`, which fetches `GET /v1/intent/:id` and decrypts the ciphertext locally.

The key is generated client-side, used client-side, and transmitted client-side. ValidPay can never read the payload.

## API reference

### `new ValidPayClient(options)`

| Option    | Type                | Default                        | Notes                                           |
| --------- | ------------------- | ------------------------------ | ----------------------------------------------- |
| `apiKey`  | `string` (required) | —                              | Your ValidPay issuer API key.                   |
| `baseUrl` | `string`            | `"https://api.validpay.io"`    | Override for staging or self-hosted setups.     |
| `fetch`   | `typeof fetch`      | global `fetch`                 | Inject a custom fetch (useful for testing).     |

### `client.createIntent({ documentType, payload }) → { retrievalId, key }`

Generates a new key, encrypts `JSON.stringify(payload)`, and POSTs to `/v1/intent`. Returns the public retrieval ID and the secret base64 key. **The key is never sent to the API.**

### `client.verifyIntent<T>(retrievalId, key) → VerifyIntentResult<T>`

Fetches the intent and decrypts the payload locally. Throws `ValidPayError` with code `decryption_failed` if the key is wrong or the blob has been tampered with (GCM auth-tag check).

```ts
interface VerifyIntentResult<T> {
  intentId: string;
  payload: T;
  issuer: string;
  issuerVerified: boolean;
  registeredAt: string;  // ISO 8601
  status: string;
}
```

### Low-level crypto helpers

For when you want to encrypt/decrypt outside of the API flow (e.g. caching, proxies):

```ts
import { generateKey, encrypt, decrypt } from "@validpay/node-sdk";

const key = generateKey();                       // base64 32-byte key
const blob = encrypt("hello world", key);        // base64(iv[12] || authTag[16] || ciphertext)
const plaintext = decrypt(blob, key);            // "hello world"
```

### `ValidPayError`

All SDK errors throw `ValidPayError` with a stable `code`:

| Code                | Meaning                                                  |
| ------------------- | -------------------------------------------------------- |
| `invalid_config`    | Missing `apiKey` (or other constructor options).         |
| `invalid_argument`  | Required method argument is missing or empty.            |
| `invalid_key`       | Key is not valid base64 or not 32 bytes after decoding.  |
| `invalid_blob`      | Blob is not valid base64 or is too short.                |
| `decryption_failed` | Wrong key, or blob tampered with (GCM auth-tag failure). |
| `network_error`     | `fetch` itself rejected (DNS, TCP, abort, etc.).         |
| `http_error`        | API returned non-2xx with no machine-readable error.     |
| `not_found`         | API returned 404 (e.g. unknown retrieval ID).            |
| `unauthorized`      | API returned 401 (invalid or missing API key).           |
| `invalid_response`  | API returned 2xx but response shape was unexpected.      |
| `invalid_payload`   | Decrypted bytes were not valid JSON.                     |

```ts
import { ValidPayError } from "@validpay/node-sdk";

try {
  await client.verifyIntent(id, key);
} catch (err) {
  if (err instanceof ValidPayError && err.code === "decryption_failed") {
    // handle tampered or wrong-key case
  }
  throw err;
}
```

## Blob format

`encrypt()` returns a base64 string whose decoded bytes are:

```
[ iv (12 bytes) | authTag (16 bytes) | ciphertext (variable) ]
```

This format is portable — any AES-256-GCM library can verify and decrypt it given the key.

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT — see [LICENSE](./LICENSE).
