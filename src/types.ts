export interface ValidPayClientOptions {
  apiKey: string;
  baseUrl?: string;
  fetch?: typeof fetch;
}

export interface CreateIntentParams {
  documentType: string;
  payload: unknown;
}

export interface CreateIntentResult {
  retrievalId: string;
  key: string;
}

export interface VerifyIntentResult<T = unknown> {
  intentId: string;
  payload: T;
  issuer: string;
  issuerVerified: boolean;
  registeredAt: string;
  status: string;
}

export interface RawIntentResponse {
  intent_id: string;
  encrypted_payload: string;
  issuer: string;
  issuer_verified: boolean;
  registered_at: string;
  status: string;
}

export interface RawCreateIntentResponse {
  retrieval_id: string;
  status: string;
}

export class ValidPayError extends Error {
  readonly code: string;
  readonly status?: number;
  readonly details?: unknown;

  constructor(code: string, message: string, options: { status?: number; details?: unknown; cause?: unknown } = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "ValidPayError";
    this.code = code;
    this.status = options.status;
    this.details = options.details;
  }
}
