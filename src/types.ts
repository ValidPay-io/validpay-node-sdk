export interface ValidPayClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  fetch?: typeof fetch;
  /** KeyHalve rail base URL (End-Cell verify). Defaults to https://rail.keyhalve.com. */
  railBaseUrl?: string;
  /** Pinned rail Ed25519 public key (SPKI DER, base64). Defaults to the live rail key. */
  railPublicKeySpki?: string;
}

/**
 * Platform delegation (Fork B). When you integrate as a platform and seal on
 * behalf of the businesses you serve, declare which business each seal is for.
 * The verifier sees that business as the issuer ("who"), attributed through your
 * platform ("through whom"), at the `delegated` trust rung.
 *
 * ValidPay stays blind to the document contents — this is identity only.
 */
export interface OnBehalfOf {
  /** Your OWN id for this business. The dedupe key: same `ref` ⇒ same tracked
   *  sub-issuer (its documents and verification counts roll up). */
  ref: string;
  /** The business name shown to verifiers on a scan. */
  name: string;
}

export interface CreateIntentParams {
  documentType: string;
  payload: unknown;
  validFrom?: string;
  validUntil?: string;
  /**
   * Split-key protection (Patent C). Default `true` since 0.4.0: the
   * returned `key` is Share A of the AES key and Share B is stored on
   * the ValidPay server — neither alone decrypts. Set `false` for the
   * legacy single-key flow where `key` is the full AES key.
   */
  splitKey?: boolean;
  /** Seal on behalf of one of your businesses (platform delegation). */
  onBehalfOf?: OnBehalfOf;
}

/**
 * Params for {@link ValidPayClient.createEndCellIntent} (End-Cell, CVCP Layer 6B).
 * Generalises split-key to an n-of-n XOR across ShareA (returned as `key`, embed in
 * the QR) + one mandatory piece per server-side holder. The full key never exists on
 * any single party.
 */
export interface EndCellIntentParams {
  documentType: string;
  payload: unknown;
  validFrom?: string;
  validUntil?: string;
  /**
   * Server-side holders, one mandatory XOR piece each. Defaults to
   * `["keyhalve", "platform"]` (the blind rail + the platform) → a 3-of-3 split with
   * the receiver's ShareA. Provide more to elect additional independent holders.
   */
  holders?: string[];
  /** Seal on behalf of one of your businesses (platform delegation). */
  onBehalfOf?: OnBehalfOf;
}

/** Params for {@link ValidPayClient.createFileIntent} (file mode, Prompt 099). */
export interface CreateFileIntentParams {
  documentType: string;
  /** Raw file bytes to seal (PDF/image/DOCX/…). Encrypted locally. */
  file: Uint8Array;
  /** Original filename, stored for issuer records. NOT echoed on public verify. */
  fileName?: string;
  /** MIME type, e.g. "application/pdf". Returned on verify for correct download. */
  fileContentType?: string;
  validFrom?: string;
  validUntil?: string;
  /** Split-key protection (Patent C). Default `true`. */
  splitKey?: boolean;
  /** Seal on behalf of one of your businesses (platform delegation). */
  onBehalfOf?: OnBehalfOf;
}

export interface BatchIntentItem {
  documentType: string;
  payload: unknown;
  validFrom?: string;
  validUntil?: string;
  /** Seal on behalf of one of your businesses (platform delegation). */
  onBehalfOf?: OnBehalfOf;
}

export interface SelectiveIntentParams {
  documentType: string;
  payload: Record<string, unknown>;
  disclosurePolicy: Record<string, string[]>;
  splitKey?: boolean;
  validFrom?: string;
  validUntil?: string;
  /** Seal on behalf of one of your businesses (platform delegation). */
  onBehalfOf?: OnBehalfOf;
}

export interface CreateIntentResult {
  retrievalId: string;
  key: string;
  /**
   * Anti-fake QR MAC minted by the rail at seal time (End-Cell seals under
   * QR-MAC enforcement). ONE-TIME: it is returned only on this creation
   * response — it is never served by any public endpoint afterwards. It MUST
   * ride the verify URL as `?m=` (pass it to `buildVerifyUrl`'s `qrMac`
   * option): the rail gates the document's share behind it, so a QR built
   * without it scans RED. Absent for legacy / non-End-Cell seals.
   */
  qrMac?: string;
}

/** Options for {@link ValidPayClient.verifyIntent}. */
export interface VerifyIntentOptions {
  /**
   * Anti-fake QR MAC — the `?m=` query value from the document's verify URL
   * (shape `/^[A-Za-z0-9_-]{8,16}$/`). Documents sealed since QR-MAC
   * enforcement REQUIRE it: the KeyHalve rail releases their End-Cell share
   * only for the exact QR/URL that was issued. Callers that parse a verify
   * URL must extract `m` alongside the id and `#key=` fragment and pass it
   * here. Rejection is surfaced as `qr_mac_invalid` (treat as fraudulent);
   * omission on a MAC-gated document as `qr_mac_required`.
   */
  qrMac?: string;
}

export type TimeLockStatus = "valid" | "not_yet_valid" | "expired";

/** What a DOCUMENT-payload verify decrypted (seal-at-source v0.2 seals carry
 *  the raw stamped file bytes, not JSON fields). */
export interface DocumentPayloadInfo {
  /** The sealed file's content type as recorded at commit (e.g.
   *  `"application/pdf"`), or null when the server didn't say. */
  contentType: string | null;
  /** Actual byte length of the DECRYPTED artifact. */
  byteSize: number;
  /** Byte length the server recorded at commit (`file_size_bytes`), or null. */
  declaredByteSize: number | null;
  /** SHA-256 (hex) of the decrypted bytes — the distributable artifact's own
   *  fingerprint; compare it against a local file to confirm identity. */
  sha256: string;
}

export interface VerifyIntentResult<T = unknown> {
  intentId: string;
  payload: T;
  /** `"json"` for field payloads (payload = the parsed object, as always);
   *  `"document"` for document seals — the decrypted bytes ARE the sealed
   *  artifact, and `document` describes them (payload mirrors it in
   *  snake_case for untyped callers). */
  payloadKind: "json" | "document";
  /** Present when payloadKind is `"document"`. */
  document?: DocumentPayloadInfo;
  issuer: string;
  issuerVerified: boolean;
  registeredAt: string;
  status: string;
  integrityVerified: boolean;
  validFrom?: string | null;
  validUntil?: string | null;
  timeLockStatus?: TimeLockStatus | null;
  /** Graded trust rung of the issuer: none < delegated < domain < business. */
  verificationLevel?: "none" | "delegated" | "domain" | "business";
  /** Set when `issuer` was sealed on behalf of, via a platform (delegation).
   *  Names the vouching platform and its own proven level. */
  delegatedBy?: { platform: string; platformLevel: "domain" | "business" } | null;
}

export interface RevocationResult {
  intentId: string;
  status: string;
  revokedAt?: string;
  reinstatedAt?: string;
}

export interface RevocationEvent {
  id: string;
  action: "revoked" | "reinstated";
  reason?: string;
  performedAt: string;
}

export interface RawIntentResponse {
  intent_id: string;
  encrypted_payload: string | null;
  issuer: string;
  issuer_verified: boolean;
  registered_at: string;
  status: string;
  document_type?: string;
  commitment_hash?: string;
  /** 1 = legacy SHA-256(plaintext), skipped on verify; 2 = SHA-256(ciphertext),
   *  enforced. Absent is treated as 1 (Prompt 097 C-1). */
  commitment_version?: number;
  /** 1 = no AAD (legacy); 2 = {document_type, valid_from, valid_until} bound
   *  as AES-GCM AAD. Absent is treated as 1 (Prompt 097 M-5). */
  encryption_version?: number;
  valid_from?: string | null;
  valid_until?: string | null;
  selective_disclosure?: boolean;
  encrypted_key_map?: string;
  split_key?: boolean;
  /** End-Cell (CVCP Layer 6B): key split n-of-n XOR across ShareA + server pieces. */
  end_cell?: boolean;
  revocation_reason?: string;
  revoked_at?: string;
  verification_level?: "none" | "delegated" | "domain" | "business";
  delegated_by?: { platform: string; platform_level: "domain" | "business" } | null;
  /** Present for document seals (sealDocument / dashboard wizard): content
   *  type of the sealed file. Their decrypted payload is the raw file, not
   *  JSON — see {@link VerifyIntentResult.payloadKind}. */
  file_content_type?: string | null;
  /** Present for document seals: byte length recorded at commit. */
  file_size_bytes?: number | null;
}

export interface RawCreateIntentResponse {
  retrieval_id: string;
  status: string;
  /** Anti-fake QR MAC — present only when the rail minted one at deposit
   *  (End-Cell seals under QR-MAC enforcement). One-time: seal moment only. */
  qr_mac?: string;
}

export interface RawBatchCreateResponse {
  results: Array<{ retrieval_id: string; status?: string; qr_mac?: string }>;
}

export interface ListIntentsParams {
  /** Max results, default 50, max 200. */
  limit?: number;
  offset?: number;
  /** ISO datetime — only intents created at or after this time. */
  since?: string;
  /** ISO datetime — only intents created at or before this time. */
  until?: string;
  status?: "active" | "revoked";
  documentType?: string;
  /** Ordering by createdAt. Default "desc". */
  order?: "asc" | "desc";
}

export interface IntentMetadata {
  retrievalId: string;
  documentType: string;
  status: string;
  createdAt: string;
  revokedAt: string | null;
  revocationReason: string | null;
  validFrom: string | null;
  validUntil: string | null;
  commitmentHash: string | null;
  splitKey: boolean;
  selectiveDisclosure: boolean;
  verificationCount: number;
  lastVerifiedAt: string | null;
}

export interface ListIntentsResult {
  intents: IntentMetadata[];
  total: number;
  limit: number;
  offset: number;
}

export interface RawIntentMetadata {
  retrieval_id: string;
  document_type: string;
  status: string;
  created_at: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  valid_from: string | null;
  valid_until: string | null;
  commitment_hash: string | null;
  split_key: boolean;
  selective_disclosure: boolean;
  verification_count: number;
  last_verified_at: string | null;
}

export interface RawListIntentsResponse {
  intents: RawIntentMetadata[];
  total: number;
  limit: number;
  offset: number;
}

export interface RawFragmentResponse {
  fragment_b?: string;
  /** End-Cell (CVCP Layer 6B): the per-holder server pieces. */
  end_cell?: boolean;
  holders?: string[];
  pieces?: Record<string, string>;
  error?: string;
}

export interface RawRevocationHistoryResponse {
  events?: Array<{
    id: string;
    action: "revoked" | "reinstated";
    reason?: string;
    performed_at: string;
  }>;
}

export class ValidPayError extends Error {
  readonly code: string;
  readonly status?: number;
  readonly details?: unknown;

  constructor(
    code: string,
    message: string,
    options: { status?: number; details?: unknown; cause?: unknown } = {},
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "ValidPayError";
    this.code = code;
    this.status = options.status;
    this.details = options.details;
  }
}
