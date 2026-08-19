# @validpay/node-sdk — agent context

Node/TypeScript SDK for the ValidPay document-sealing API (`api.validpay.com`). MIT licensed. Public repository.

## Commands
```
npm run build
npm test          # vitest (test:watch for TDD)
npm run typecheck
```

## API shape — the one thing to know
`createIntent()` delegates to **End-Cell** (3-of-3 key split) by default. Batch creation is retired: `createIntentBatch()` throws `legacy_batch_retired` without a network call. The return shape of `createIntent()` is unchanged from earlier versions, so callers that embed the QR need no edit.

## Versions
`main` is **0.10.0**; the latest version published to npm is **0.9.0** — `main` is ahead of the registry. Check both before writing anything version-specific into docs or examples.

## Notes for agents working in this repo

- Keep this file to **build, test and API facts**. This repository is public: no roadmaps, no pricing, no unreleased plans, no internal strategy.
- Wording in the README and docs must stay accurate: the seal is **tamper-evident** (any alteration is detectable), protected by a **3-of-3 key split** — never "tamper-proof", "split key", or "zero-knowledge".
- Releases are cut by the maintainer. Do not publish a package version as part of an ordinary change.
