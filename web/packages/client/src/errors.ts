import {
  knownErrorCodes,
  type ErrorCode,
  type KnownErrorCode,
} from "./types.js";

export class SlateFsError extends Error {
  constructor(
    message: string,
    public readonly requestId: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "SlateFsError";
  }
}
export class SlateFsApiError extends SlateFsError {
  readonly knownCode?: KnownErrorCode;
  constructor(
    message: string,
    requestId: string,
    public readonly status: number,
    public readonly code: ErrorCode,
    public readonly details: Record<string, unknown> = {},
    public readonly retryAfterMs?: number,
  ) {
    super(message, requestId);
    this.name = "SlateFsApiError";
    if ((knownErrorCodes as readonly string[]).includes(code))
      this.knownCode = code as KnownErrorCode;
  }
  get rawCode(): string {
    return this.code;
  }
}
export class SlateFsNetworkError extends SlateFsError {
  constructor(message: string, requestId: string, cause: unknown) {
    super(message, requestId, { cause });
    this.name = "SlateFsNetworkError";
  }
}
export class SlateFsAbortError extends SlateFsError {
  constructor(requestId: string, cause?: unknown) {
    super("The SlateFS request was aborted", requestId, { cause });
    this.name = "SlateFsAbortError";
  }
}
export const isSlateFsError = (value: unknown): value is SlateFsError =>
  value instanceof SlateFsError;
export const isRetryableSlateFsError = (value: unknown): boolean =>
  (value instanceof SlateFsApiError &&
    [408, 429, 502, 503, 504].includes(value.status)) ||
  value instanceof SlateFsNetworkError;
