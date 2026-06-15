import {
  generateKey,
  encrypt,
  decrypt,
  commitmentHash,
  buildAad,
  splitKey as splitKeyFn,
  combineKeyShares,
  encryptFields,
  buildKeyMap,
  decryptFields,
} from "./crypto.js";
import {
  ValidPayError,
  type ValidPayClientOptions,
  type CreateIntentParams,
  type BatchIntentItem,
  type SelectiveIntentParams,
  type CreateIntentResult,
  type VerifyIntentResult,
  type TimeLockStatus,
  type RevocationResult,
  type RevocationEvent,
  type RawIntentResponse,
  type RawCreateIntentResponse,
  type RawBatchCreateResponse,
  type RawFragmentResponse,
  type RawRevocationHistoryResponse,
  type ListIntentsParams,
  type ListIntentsResult,
  type IntentMetadata,
  type RawIntentMetadata,
  type RawListIntentsResponse,
} from "./types.js";

const DEFAULT_BASE_URL = "https://api.validpay.com";
const DEFAULT_TIMEOUT_MS = 30_000;

type Method = "GET" | "POST" | "PATCH";

interface RequestOpts {
  body?: unknown;
  auth: boolean;
}

let splitKeyDeprecationEmitted = false;
function emitSplitKeyDeprecation(): void {
  if (splitKeyDeprecationEmitted) return;
  splitKeyDeprecationEmitted = true;
  const message =
    "createSplitKeyIntent() is deprecated since @validpay/node-sdk 0.4.0: " +
    "createIntent() uses split-key protection by default. Call createIntent() instead.";
  if (typeof process !== "undefined" && typeof process.emitWarning === "function") {
    process.emitWarning(message, "DeprecationWarning");
  } else {
    console.warn(message);
  }
}

export class ValidPayClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ValidPayClientOptions) {
    if (!options.apiKey) {
      throw new ValidPayError("invalid_config", "apiKey is required");
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetch ?? fetch;
  }

  // === Core ===

  /**
   * Encrypt `payload` locally and register it with the ValidPay API.
   *
   * Since 0.4.0 this uses **split-key protection (Patent C) by default**:
   * the AES-256 key is split into two XOR shares — Share A is returned as
   * `key` (embed it in the QR code exactly as before), Share B is stored
   * on the ValidPay server. The full decryption key never exists on any
   * single system after this call returns. Pass `splitKey: false` for the
   * legacy single-key flow.
   */
  async createIntent(params: CreateIntentParams): Promise<CreateIntentResult> {
    if (!params.documentType) {
      throw new ValidPayError("invalid_argument", "documentType is required");
    }
    validateTimeLock(params.validFrom, params.validUntil);

    const splitKey = params.splitKey !== false;
    const fullKey = generateKey();
    let resultKey = fullKey;
    let shareB: string | undefined;
    if (splitKey) {
      [resultKey, shareB] = splitKeyFn(fullKey);
    }

    const plaintext = JSON.stringify(params.payload);
    // M-5: bind document_type + validity window as AAD.
    const aad = buildAad(params.documentType, params.validFrom, params.validUntil);
    const encrypted_payload = encrypt(plaintext, fullKey, aad);
    // Commitment v2: hash the ciphertext, not the plaintext (C-1).
    const commitment_hash = commitmentHash(encrypted_payload);

    const body: Record<string, unknown> = {
      document_type: params.documentType,
      encrypted_payload,
      commitment_hash,
      encryption_version: 2,
    };
    if (splitKey) {
      body["split_key"] = true;
      body["key_fragment_b"] = shareB;
    }
    if (params.validFrom !== undefined) body["valid_from"] = params.validFrom;
    if (params.validUntil !== undefined) body["valid_until"] = params.validUntil;

    const data = await this.request<RawCreateIntentResponse>("POST", "/v1/intent", {
      body,
      auth: true,
    });

    if (!data?.retrieval_id) {
      throw new ValidPayError("invalid_response", "API response missing retrieval_id", {
        details: data,
      });
    }
    return { retrievalId: data.retrieval_id, key: resultKey };
  }

  async createIntentBatch(items: BatchIntentItem[]): Promise<CreateIntentResult[]> {
    if (!Array.isArray(items) || items.length === 0) {
      throw new ValidPayError("invalid_argument", "items must contain at least 1 item");
    }
    if (items.length > 100) {
      throw new ValidPayError(
        "invalid_argument",
        `items must contain at most 100 items (got ${items.length})`,
      );
    }

    const keys: string[] = [];
    const requestItems: Array<Record<string, unknown>> = [];
    items.forEach((item, idx) => {
      if (!item.documentType) {
        throw new ValidPayError(
          "invalid_argument",
          `items[${idx}].documentType is required`,
        );
      }
      if (!("payload" in item)) {
        throw new ValidPayError("invalid_argument", `items[${idx}].payload is required`);
      }
      try {
        validateTimeLock(item.validFrom, item.validUntil);
      } catch (e) {
        if (e instanceof ValidPayError) {
          throw new ValidPayError("invalid_argument", `items[${idx}]: ${e.message}`);
        }
        throw e;
      }

      const k = generateKey();
      keys.push(k);
      const plaintext = JSON.stringify(item.payload);
      // M-5: bind document_type + validity window as AAD per item.
      const itemAad = buildAad(item.documentType, item.validFrom, item.validUntil);
      const item_encrypted_payload = encrypt(plaintext, k, itemAad);
      const req: Record<string, unknown> = {
        document_type: item.documentType,
        encrypted_payload: item_encrypted_payload,
        // Commitment v2: hash the ciphertext, not the plaintext (C-1).
        commitment_hash: commitmentHash(item_encrypted_payload),
        encryption_version: 2,
      };
      if (item.validFrom !== undefined) req["valid_from"] = item.validFrom;
      if (item.validUntil !== undefined) req["valid_until"] = item.validUntil;
      requestItems.push(req);
    });

    const data = await this.request<RawBatchCreateResponse>("POST", "/v1/intent/batch", {
      body: { intents: requestItems },
      auth: true,
    });

    if (!Array.isArray(data?.results) || data.results.length !== keys.length) {
      throw new ValidPayError(
        "invalid_response",
        "API response missing results array of expected length",
        { details: data },
      );
    }

    return data.results.map((row, i) => {
      if (!row?.retrieval_id) {
        throw new ValidPayError("invalid_response", `results[${i}] missing retrieval_id`, {
          details: data,
        });
      }
      return { retrievalId: row.retrieval_id, key: keys[i]! };
    });
  }

  async verifyIntent<T = unknown>(
    retrievalId: string,
    key: string,
  ): Promise<VerifyIntentResult<T>> {
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

    if (!data || typeof data !== "object") {
      throw new ValidPayError("invalid_response", "API response missing intent body", {
        details: data,
      });
    }

    if (data.status === "revoked" || !data.encrypted_payload) {
      const reasonSuffix = data.revocation_reason ? `: ${data.revocation_reason}` : "";
      throw new ValidPayError(
        "intent_revoked",
        `Intent ${retrievalId} has been revoked${reasonSuffix}`,
        {
          details: {
            intent_id: data.intent_id,
            status: data.status,
            revoked_at: data.revoked_at,
            revocation_reason: data.revocation_reason,
          },
        },
      );
    }

    if (data.selective_disclosure) {
      throw new ValidPayError(
        "selective_disclosure_required",
        "This intent uses selective field disclosure. Use verifySelectiveIntent(retrievalId, key, role) instead.",
      );
    }
    // Split-Key Verification (Patent C). Since 0.4.0 split-key is the
    // default issue path, so the key the caller holds is Share A — fetch
    // Share B from the fragment endpoint and XOR-combine, so the natural
    // createIntent -> verifyIntent round trip keeps working.
    let decryptionKey = key;
    if (data.split_key) {
      decryptionKey = combineKeyShares(key, await this.fetchFragmentB(retrievalId));
    }

    // M-5: reconstruct the AAD for v2 intents.
    const decrypted = decrypt(data.encrypted_payload, decryptionKey, aadFor(data));

    const integrityVerified = checkCommitment(data);

    let payload: T;
    try {
      payload = JSON.parse(decrypted) as T;
    } catch (cause) {
      throw new ValidPayError("invalid_payload", "Decrypted payload is not valid JSON", {
        cause,
      });
    }

    return buildVerifyResult<T>(data, payload, integrityVerified);
  }

  // === Split-key (Patent C) ===

  /**
   * @deprecated Since 0.4.0 `createIntent()` uses split-key protection by
   * default, so this alias adds nothing. Call `createIntent()` instead.
   * Kept so 0.3.x code keeps working; will be removed in 1.0.
   */
  async createSplitKeyIntent(params: CreateIntentParams): Promise<CreateIntentResult> {
    emitSplitKeyDeprecation();
    return this.createIntent({ ...params, splitKey: true });
  }

  /** Fetch Share B from the public fragment endpoint (Patent C). */
  private async fetchFragmentB(retrievalId: string): Promise<string> {
    const frag = await this.request<RawFragmentResponse>(
      "GET",
      `/v1/intent/${encodeURIComponent(retrievalId)}/fragment`,
      { auth: false },
    );
    if (frag?.error) {
      throw new ValidPayError(frag.error, `Fragment retrieval failed: ${frag.error}`, {
        details: frag,
      });
    }
    if (!frag?.fragment_b) {
      throw new ValidPayError("missing_fragment", "Server did not return key fragment", {
        details: frag,
      });
    }
    return frag.fragment_b;
  }

  async verifySplitKeyIntent<T = unknown>(
    retrievalId: string,
    shareA: string,
  ): Promise<VerifyIntentResult<T>> {
    if (!retrievalId) {
      throw new ValidPayError("invalid_argument", "retrievalId is required");
    }
    if (!shareA) {
      throw new ValidPayError("invalid_argument", "shareA is required");
    }

    const data = await this.request<RawIntentResponse>(
      "GET",
      `/v1/intent/${encodeURIComponent(retrievalId)}`,
      { auth: false },
    );

    if (data.status === "revoked" || !data.encrypted_payload) {
      const reasonSuffix = data.revocation_reason ? `: ${data.revocation_reason}` : "";
      throw new ValidPayError(
        "intent_revoked",
        `Intent ${retrievalId} has been revoked${reasonSuffix}`,
        {
          details: {
            intent_id: data.intent_id,
            status: data.status,
            revoked_at: data.revoked_at,
            revocation_reason: data.revocation_reason,
          },
        },
      );
    }

    const fullKey = combineKeyShares(shareA, await this.fetchFragmentB(retrievalId));
    // M-5: reconstruct the AAD for v2 intents.
    const decrypted = decrypt(data.encrypted_payload, fullKey, aadFor(data));

    const integrityVerified = checkCommitment(data);

    let payload: T;
    try {
      payload = JSON.parse(decrypted) as T;
    } catch (cause) {
      throw new ValidPayError("invalid_payload", "Decrypted payload is not valid JSON", {
        cause,
      });
    }

    return buildVerifyResult<T>(data, payload, integrityVerified);
  }

  // === Selective disclosure (Patent E) ===

  async createSelectiveIntent(params: SelectiveIntentParams): Promise<CreateIntentResult> {
    if (!params.documentType) {
      throw new ValidPayError("invalid_argument", "documentType is required");
    }
    if (!params.payload || Object.keys(params.payload).length === 0) {
      throw new ValidPayError("invalid_argument", "payload must be a non-empty object");
    }
    if (!params.disclosurePolicy || Object.keys(params.disclosurePolicy).length === 0) {
      throw new ValidPayError(
        "invalid_argument",
        "disclosurePolicy must be a non-empty object",
      );
    }
    validateTimeLock(params.validFrom, params.validUntil);

    for (const [role, fields] of Object.entries(params.disclosurePolicy)) {
      if (!Array.isArray(fields)) {
        throw new ValidPayError(
          "invalid_argument",
          `disclosurePolicy['${role}'] must be an array`,
        );
      }
      for (const f of fields) {
        if (!(f in params.payload)) {
          throw new ValidPayError(
            "invalid_argument",
            `Field '${f}' in role '${role}' not found in payload`,
          );
        }
      }
    }

    const masterKey = generateKey();
    const { encryptedFields, fieldKeys } = encryptFields(params.payload);
    const keyMap = buildKeyMap(fieldKeys, params.disclosurePolicy);
    const encrypted_key_map = encrypt(JSON.stringify(keyMap), masterKey);

    const envelope = JSON.stringify(encryptedFields);
    // Commitment v2: hash the transported ciphertext envelope, not the
    // plaintext (C-1). Role-independent at verify time.
    const commitment_hash = commitmentHash(envelope);

    let qrKey = masterKey;
    let key_fragment_b: string | undefined;
    if (params.splitKey) {
      const [shareA, shareB] = splitKeyFn(masterKey);
      qrKey = shareA;
      key_fragment_b = shareB;
    }

    const body: Record<string, unknown> = {
      document_type: params.documentType,
      encrypted_payload: envelope,
      commitment_hash,
      selective_disclosure: true,
      disclosure_policy: JSON.stringify(params.disclosurePolicy),
      encrypted_key_map,
      split_key: !!params.splitKey,
    };
    if (key_fragment_b !== undefined) body["key_fragment_b"] = key_fragment_b;
    if (params.validFrom !== undefined) body["valid_from"] = params.validFrom;
    if (params.validUntil !== undefined) body["valid_until"] = params.validUntil;

    const data = await this.request<RawCreateIntentResponse>("POST", "/v1/intent", {
      body,
      auth: true,
    });
    if (!data?.retrieval_id) {
      throw new ValidPayError("invalid_response", "API response missing retrieval_id", {
        details: data,
      });
    }
    return { retrievalId: data.retrieval_id, key: qrKey };
  }

  async verifySelectiveIntent(
    retrievalId: string,
    key: string,
    role = "full",
  ): Promise<VerifyIntentResult<Record<string, unknown>>> {
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

    if (data.status === "revoked" || !data.encrypted_payload) {
      const reasonSuffix = data.revocation_reason ? `: ${data.revocation_reason}` : "";
      throw new ValidPayError(
        "intent_revoked",
        `Intent ${retrievalId} has been revoked${reasonSuffix}`,
        {
          details: {
            intent_id: data.intent_id,
            status: data.status,
            revoked_at: data.revoked_at,
            revocation_reason: data.revocation_reason,
          },
        },
      );
    }

    let masterKey = key;
    if (data.split_key) {
      const frag = await this.request<RawFragmentResponse>(
        "GET",
        `/v1/intent/${encodeURIComponent(retrievalId)}/fragment`,
        { auth: false },
      );
      if (frag?.error) {
        throw new ValidPayError(frag.error, `Fragment retrieval failed: ${frag.error}`, {
          details: frag,
        });
      }
      if (!frag?.fragment_b) {
        throw new ValidPayError("missing_fragment", "Server did not return key fragment", {
          details: frag,
        });
      }
      masterKey = combineKeyShares(key, frag.fragment_b);
    }

    if (!data.encrypted_key_map) {
      throw new ValidPayError(
        "invalid_response",
        "Selective disclosure intent missing encrypted_key_map",
      );
    }

    const keyMapJson = decrypt(data.encrypted_key_map, masterKey);
    let keyMap: Record<string, Record<string, string>>;
    try {
      keyMap = JSON.parse(keyMapJson);
    } catch (cause) {
      throw new ValidPayError("invalid_payload", "Decrypted key map is not valid JSON", {
        cause,
      });
    }

    if (!(role in keyMap)) {
      const available = Object.keys(keyMap).sort().join(", ");
      throw new ValidPayError(
        "invalid_role",
        `Role '${role}' is not defined in this document's disclosure policy. Available roles: ${available}`,
      );
    }
    const fieldKeys = keyMap[role]!;

    let encryptedFields: Record<string, string>;
    try {
      encryptedFields = JSON.parse(data.encrypted_payload);
    } catch (cause) {
      throw new ValidPayError(
        "invalid_payload",
        "Encrypted payload is not a valid JSON envelope",
        { cause },
      );
    }

    const payload = decryptFields(encryptedFields, fieldKeys);

    // Commitment over the ciphertext envelope (C-1) — role-independent now,
    // so any role gets integrity verification. Legacy v1 intents skip it.
    const integrityVerified = checkCommitment(data);

    return buildVerifyResult(data, payload, integrityVerified);
  }

  // === Revocation (Patent H) ===

  async revokeIntent(retrievalId: string, reason?: string): Promise<RevocationResult> {
    if (!retrievalId) {
      throw new ValidPayError("invalid_argument", "retrievalId is required");
    }
    const data = await this.request<{
      intent_id: string;
      status: string;
      revoked_at?: string;
    }>(
      "PATCH",
      `/v1/intent/${encodeURIComponent(retrievalId)}/revoke`,
      { body: reason ? { reason } : {}, auth: true },
    );
    return {
      intentId: data?.intent_id ?? retrievalId,
      status: data?.status ?? "revoked",
      revokedAt: data?.revoked_at,
    };
  }

  async reinstateIntent(retrievalId: string, reason?: string): Promise<RevocationResult> {
    if (!retrievalId) {
      throw new ValidPayError("invalid_argument", "retrievalId is required");
    }
    const data = await this.request<{
      intent_id: string;
      status: string;
      reinstated_at?: string;
    }>(
      "PATCH",
      `/v1/intent/${encodeURIComponent(retrievalId)}/reinstate`,
      { body: reason ? { reason } : {}, auth: true },
    );
    return {
      intentId: data?.intent_id ?? retrievalId,
      status: data?.status ?? "active",
      reinstatedAt: data?.reinstated_at,
    };
  }

  async getRevocationHistory(retrievalId: string): Promise<RevocationEvent[]> {
    if (!retrievalId) {
      throw new ValidPayError("invalid_argument", "retrievalId is required");
    }
    const data = await this.request<RawRevocationHistoryResponse>(
      "GET",
      `/v1/intent/${encodeURIComponent(retrievalId)}/revocations`,
      { auth: true },
    );
    if (!Array.isArray(data?.events)) return [];
    return data.events.map((e) => ({
      id: e.id,
      action: e.action,
      reason: e.reason,
      performedAt: e.performed_at,
    }));
  }

  // === Audit / list (Prompt 080) ===

  /**
   * List the intents this API key has created. Returns metadata only —
   * the AES payload + key are NEVER part of the response, by design.
   * Use this for audit, reconciliation, and "did this intent get
   * scanned?" dashboards.
   */
  async listIntents(params: ListIntentsParams = {}): Promise<ListIntentsResult> {
    const qs = new URLSearchParams();
    if (params.limit !== undefined) qs.set("limit", String(params.limit));
    if (params.offset !== undefined) qs.set("offset", String(params.offset));
    if (params.since !== undefined) qs.set("since", params.since);
    if (params.until !== undefined) qs.set("until", params.until);
    if (params.status !== undefined) qs.set("status", params.status);
    if (params.documentType !== undefined) qs.set("document_type", params.documentType);
    if (params.order !== undefined) qs.set("order", params.order);

    const path = qs.size > 0 ? `/v1/intents?${qs.toString()}` : "/v1/intents";
    const data = await this.request<RawListIntentsResponse>("GET", path, { auth: true });

    return {
      intents: (data?.intents ?? []).map(mapMetadata),
      total: data?.total ?? 0,
      limit: data?.limit ?? params.limit ?? 50,
      offset: data?.offset ?? params.offset ?? 0,
    };
  }

  /**
   * Fetch metadata for a single intent. Distinct from `verifyIntent` —
   * this endpoint never returns ciphertext or key material, so it's
   * safe to call from any service that just needs status / verification
   * counts / revocation state.
   */
  async getIntent(retrievalId: string): Promise<IntentMetadata> {
    if (!retrievalId) {
      throw new ValidPayError("invalid_argument", "retrievalId is required");
    }
    const data = await this.request<RawIntentMetadata>(
      "GET",
      `/v1/intents/${encodeURIComponent(retrievalId)}`,
      { auth: true },
    );
    return mapMetadata(data);
  }

  // === Health ===

  async health(): Promise<{ status: string; version?: string }> {
    return this.request<{ status: string; version?: string }>("GET", "/health", {
      auth: false,
    });
  }

  // === HTTP ===

  private async request<T>(method: Method, path: string, opts: RequestOpts): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (opts.auth) headers["Authorization"] = `Bearer ${this.apiKey}`;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } catch (cause) {
      throw new ValidPayError("network_error", `Request to ${url} failed`, { cause });
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        // leave undefined
      }
    }

    if (!response.ok) {
      const errBody = (json ?? text) as { error?: string } | string | undefined;
      const code =
        typeof errBody === "object" && errBody && typeof errBody.error === "string"
          ? errBody.error
          : "http_error";
      throw new ValidPayError(
        code,
        `ValidPay API ${method} ${path} failed: ${response.status}`,
        { status: response.status, details: errBody },
      );
    }

    return json as T;
  }
}

// === Helpers ===

/**
 * Version-aware commitment check (Prompt 097 C-1). v2 commitments are
 * SHA-256(ciphertext): recompute over the received blob and compare. v1
 * (legacy SHA-256(plaintext)) is a confirmation-oracle risk and is skipped —
 * those documents expire naturally. Throws on a v2 mismatch.
 */
function checkCommitment(data: {
  commitment_hash?: string;
  commitment_version?: number;
  encrypted_payload: string | null;
}): boolean {
  if (!data.commitment_hash || !data.encrypted_payload) return false;
  if ((data.commitment_version ?? 1) < 2) return false;
  const actual = commitmentHash(data.encrypted_payload);
  if (actual !== data.commitment_hash) {
    throw new ValidPayError(
      "integrity_failure",
      "INTEGRITY VERIFICATION FAILED — the ciphertext does not match the commitment hash recorded at issuance. This document may have been tampered with.",
    );
  }
  return true;
}

/**
 * AAD to pass to decrypt for a verify response (Prompt 097 M-5). v2 intents
 * reconstruct it from the server-returned metadata so altered document_type
 * or validity window fails the GCM tag check. undefined for legacy v1.
 */
function aadFor(data: RawIntentResponse): string | undefined {
  if ((data.encryption_version ?? 1) < 2) return undefined;
  return buildAad(data.document_type ?? "", data.valid_from, data.valid_until);
}

function computeTimeLockStatus(
  validFrom: string | null | undefined,
  validUntil: string | null | undefined,
): TimeLockStatus | null {
  if (!validFrom && !validUntil) return null;
  const now = Date.now();
  if (validFrom) {
    const t = Date.parse(validFrom);
    if (!Number.isNaN(t) && now < t) return "not_yet_valid";
  }
  if (validUntil) {
    const t = Date.parse(validUntil);
    if (!Number.isNaN(t) && now > t) return "expired";
  }
  return "valid";
}

function validateTimeLock(validFrom: string | undefined, validUntil: string | undefined): void {
  if (validFrom !== undefined && Number.isNaN(Date.parse(validFrom))) {
    throw new ValidPayError("invalid_argument", `validFrom is not a valid ISO-8601: ${validFrom}`);
  }
  if (validUntil !== undefined && Number.isNaN(Date.parse(validUntil))) {
    throw new ValidPayError(
      "invalid_argument",
      `validUntil is not a valid ISO-8601: ${validUntil}`,
    );
  }
  if (validFrom !== undefined && validUntil !== undefined) {
    if (Date.parse(validFrom) >= Date.parse(validUntil)) {
      throw new ValidPayError("invalid_argument", "validFrom must be before validUntil");
    }
  }
}

function buildVerifyResult<T>(
  data: RawIntentResponse,
  payload: T,
  integrityVerified: boolean,
): VerifyIntentResult<T> {
  return {
    intentId: data.intent_id,
    payload,
    issuer: data.issuer,
    issuerVerified: data.issuer_verified,
    registeredAt: data.registered_at,
    status: data.status,
    integrityVerified,
    validFrom: data.valid_from ?? null,
    validUntil: data.valid_until ?? null,
    timeLockStatus: computeTimeLockStatus(data.valid_from, data.valid_until),
  };
}

function mapMetadata(raw: RawIntentMetadata): IntentMetadata {
  return {
    retrievalId: raw.retrieval_id,
    documentType: raw.document_type,
    status: raw.status,
    createdAt: raw.created_at,
    revokedAt: raw.revoked_at,
    revocationReason: raw.revocation_reason,
    validFrom: raw.valid_from,
    validUntil: raw.valid_until,
    commitmentHash: raw.commitment_hash,
    splitKey: raw.split_key,
    selectiveDisclosure: raw.selective_disclosure,
    verificationCount: raw.verification_count,
    lastVerifiedAt: raw.last_verified_at,
  };
}
