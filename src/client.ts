import { generateKey, encrypt, decrypt } from "./crypto.js";
import {
  ValidPayError,
  type ValidPayClientOptions,
  type CreateIntentParams,
  type CreateIntentResult,
  type VerifyIntentResult,
  type RawIntentResponse,
  type RawCreateIntentResponse,
} from "./types.js";

const DEFAULT_BASE_URL = "https://api.validpay.io";

export class ValidPayClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ValidPayClientOptions) {
    if (!options.apiKey) {
      throw new ValidPayError("invalid_config", "apiKey is required");
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? fetch;
  }

  async createIntent(params: CreateIntentParams): Promise<CreateIntentResult> {
    if (!params.documentType) {
      throw new ValidPayError("invalid_argument", "documentType is required");
    }

    const key = generateKey();
    const encrypted_payload = encrypt(JSON.stringify(params.payload), key);

    const body = {
      document_type: params.documentType,
      encrypted_payload,
    };

    const data = await this.request<RawCreateIntentResponse>("POST", "/v1/intent", {
      body,
      auth: true,
    });

    if (!data.retrieval_id) {
      throw new ValidPayError("invalid_response", "API response missing retrieval_id", {
        details: data,
      });
    }

    return { retrievalId: data.retrieval_id, key };
  }

  async verifyIntent<T = unknown>(retrievalId: string, key: string): Promise<VerifyIntentResult<T>> {
    if (!retrievalId) {
      throw new ValidPayError("invalid_argument", "retrievalId is required");
    }
    if (!key) {
      throw new ValidPayError("invalid_argument", "key is required");
    }

    const data = await this.request<RawIntentResponse>(
      "GET",
      `/v1/intent/${encodeURIComponent(retrievalId)}`,
      { auth: false },
    );

    const decrypted = decrypt(data.encrypted_payload, key);

    let payload: T;
    try {
      payload = JSON.parse(decrypted) as T;
    } catch (cause) {
      throw new ValidPayError("invalid_payload", "Decrypted payload is not valid JSON", { cause });
    }

    return {
      intentId: data.intent_id,
      payload,
      issuer: data.issuer,
      issuerVerified: data.issuer_verified,
      registeredAt: data.registered_at,
      status: data.status,
    };
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    opts: { body?: unknown; auth: boolean },
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (opts.auth) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    } catch (cause) {
      throw new ValidPayError("network_error", `Request to ${url} failed`, { cause });
    }

    const text = await response.text();
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        // leave json undefined; surface as details below if !ok
      }
    }

    if (!response.ok) {
      const errBody = (json ?? text) as { error?: string } | string | undefined;
      const code =
        typeof errBody === "object" && errBody && typeof errBody.error === "string"
          ? errBody.error
          : "http_error";
      throw new ValidPayError(code, `ValidPay API ${method} ${path} failed: ${response.status}`, {
        status: response.status,
        details: errBody,
      });
    }

    return json as T;
  }
}
