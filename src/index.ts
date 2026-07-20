export { ValidPayClient } from "./client.js";
export {
  generateKey,
  encrypt,
  encryptBytes,
  decrypt,
  decryptBytes,
  commitmentHash,
  splitKey,
  combineKeyShares,
  splitKeyPieces,
  combineKeyPieces,
  encryptFields,
  buildKeyMap,
  decryptFields,
} from "./crypto.js";
export {
  ValidPayError,
  type ValidPayClientOptions,
  type CreateIntentParams,
  type EndCellIntentParams,
  type CreateFileIntentParams,
  type BatchIntentItem,
  type SelectiveIntentParams,
  type CreateIntentResult,
  type VerifyIntentOptions,
  type VerifyIntentResult,
  type DocumentPayloadInfo,
  type TimeLockStatus,
  type RevocationResult,
  type RevocationEvent,
  type RawIntentResponse,
  type RawCreateIntentResponse,
} from "./types.js";
export { QR_MAC_RE } from "./rail.js";
export {
  verifyWebhookSignature,
  DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
  type VerifyWebhookOptions,
  type WebhookVerifyResult,
  type WebhookVerifyFailureReason,
} from "./webhookSignature.js";
export {
  buildVerifyUrl,
  resolveQrRect,
  embedQr,
  renderBrandedQrSvg,
  readPdfPageSizes,
  MIN_RECOMMENDED_QR_PT,
  type QrAnchor,
  type QrUnit,
  type QrPlacement,
  type VerifyUrlOptions,
  type ResolvedQrRect,
  type QrRenderOptions,
  type QrBrandingInfo,
  type EmbedQrOptions,
  type PdfPageSize,
} from "./pdf.js";
export {
  decideBrandedQr,
  modulesForPayload,
  keyhalveMarkSvg,
  injectKeyhalveMark,
  QR_MARGIN_MODULES,
  LOGO_MIN_MODULE_MM,
  LOGO_DISC_RADIUS_FRAC,
  LOGO_SPLIT_WIDTH_FRAC,
  PT_PER_MM,
  type BrandedQrDecision,
} from "./brandedQr.js";
export {
  DEFAULT_SEAL_PLACEMENT,
  type SealDocumentParams,
  type SealDocumentFields,
  type SealDocumentResult,
  type AutoQrPlacement,
} from "./seal.js";
export {
  chooseClearRect,
  SMART_PLACE_DEFAULTS,
  type Box,
  type SmartPlaceAnchor,
  type SmartPlaceCandidate,
  type SmartPlaceOptions,
  type SmartPlaceResult,
} from "./smartPlace.js";
export {
  extractPageObstacles,
  type ObstacleBox,
  type PdfJsModuleLike,
  type PdfJsPageLike,
} from "./pdfObstacles.js";
export {
  computeAutoPlacements,
  type AutoPlacementOptions,
  type AutoPlacementDecision,
} from "./autoPlace.js";
