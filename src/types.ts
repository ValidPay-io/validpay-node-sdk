export interface ValidPayClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  fetch?: typeof fetch;
}

export interface CreateIntentParams {
  documentType: string;
  payload: unknown;
  validFrom?: string;
  validUntil?: string;
}

export interface BatchIntentItem {
  documentType: string;
  payload: unknown;
  validFrom?: string;
  validUntil?: string;
}

export interface SelectiveIntentParams {
  documentType: string;
  payload: Record<string, unknown>;
  disclosurePolicy: Record<string, string[]>;
  splitKey?: boolean;
  validFrom?: string;
  validUntil?: string;
}

export interface CreateIntentResult {
  retrievalId: string;
  key: string;
}

export type TimeLockStatus = "valid" | "not_yet_valid" | "expired";

export interface VerifyIntentResult<T = unknown> {
  intentId: string;
  payload: T;
  issuer: string;
  issuerVerified: boolean;
  registeredAt: string;
  status: string;
  integrityVerified: boolean;
  validFrom?: string | null;
  validUntil?: string | null;
  timeLockStatus?: TimeLockStatus | null;
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
  commitment_hash?: string;
  valid_from?: string | null;
  valid_until?: string | null;
  selective_disclosure?: boolean;
  encrypted_key_map?: string;
  split_key?: boolean;
  revocation_reason?: string;
  revoked_at?: string;
}

export interface RawCreateIntentResponse {
  retrieval_id: string;
  status: string;
}

export interface RawBatchCreateResponse {
  results: Array<{ retrieval_id: string; status?: string }>;
}

export interface RawFragmentResponse {
  fragment_b?: string;
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
