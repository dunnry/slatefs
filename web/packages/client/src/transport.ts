import {
  SlateFsAbortError,
  SlateFsApiError,
  SlateFsNetworkError,
} from "./errors.js";
import type { UploadProgress } from "./types.js";

export interface RequestContext {
  method: string;
  url: string;
  requestId: string;
}
export interface ResponseMetadata {
  method: string;
  url: string;
  requestId: string;
  status: number;
  resolvedCommit?: string;
}
export interface RetryPolicy {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
}
export interface SlateFsClientOptions {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  credentials?: RequestCredentials;
  getAuthorization?: (
    context: RequestContext,
  ) => string | undefined | Promise<string | undefined>;
  getCsrfToken?: (
    context: RequestContext,
  ) => string | undefined | Promise<string | undefined>;
  retry?: RetryPolicy;
  onResponse?: (metadata: ResponseMetadata) => void;
  onAuthRequired?: (error: SlateFsApiError) => void;
}
export interface TransportRequest {
  method?: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  headers?: HeadersInit;
  body?: BodyInit | null;
  signal?: AbortSignal;
  requestId?: string;
  idempotencyKey?: string;
  ifMatch?: string;
  response?: "json" | "empty" | "stream";
  onUploadProgress?: (progress: UploadProgress) => void;
  onDownloadProgress?: (progress: UploadProgress) => void;
  /** Internal safety override for upstream operations without replay semantics. */
  replaySafe?: boolean;
}
export interface StreamResponse {
  body: ReadableStream<Uint8Array>;
  headers: Headers;
  status: number;
  requestId: string;
}

const unsafe = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const retryStatuses = new Set([408, 429, 502, 503, 504]);
const delay = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const id = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(id);
        reject(signal.reason);
      },
      { once: true },
    );
  });
const requestId = () =>
  globalThis.crypto?.randomUUID?.() ??
  `req-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
function retryAfter(headers: Headers): number | undefined {
  const value = headers.get("retry-after");
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - Date.now());
}
function contentLength(headers: Headers): number | undefined {
  const value = headers.get("content-length");
  if (value === null || !/^(0|[1-9][0-9]*)$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}
function replayable(body: BodyInit | null | undefined): boolean {
  return (
    body == null ||
    typeof body === "string" ||
    body instanceof Blob ||
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body) ||
    body instanceof URLSearchParams
  );
}
function progressStream(
  stream: ReadableStream<Uint8Array>,
  total: number | undefined,
  callback?: (progress: UploadProgress) => void,
): ReadableStream<Uint8Array> {
  if (!callback) return stream;
  let transferred = 0;
  return stream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        transferred += chunk.byteLength;
        callback({
          transferredBytes: transferred,
          ...(total === undefined ? {} : { totalBytes: total }),
        });
        controller.enqueue(chunk);
      },
    }),
  );
}

export class FetchTransport {
  readonly #baseUrl: URL;
  readonly #fetch: typeof globalThis.fetch;
  readonly #options: SlateFsClientOptions;
  constructor(options: SlateFsClientOptions) {
    this.#baseUrl = new URL(
      options.baseUrl,
      globalThis.location?.href ?? "http://localhost/",
    );
    // Chromium's native fetch rejects calls whose receiver is an arbitrary
    // object. A private function field is otherwise invoked with this
    // transport as its receiver (`this.#fetch(...)`). Bind the ambient fetch
    // to its owning global while leaving caller-supplied fetch functions alone.
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#options = options;
  }
  async request<T>(
    spec: TransportRequest & { response?: "json" | "empty" },
  ): Promise<T>;
  async request(
    spec: TransportRequest & { response: "stream" },
  ): Promise<StreamResponse>;
  async request<T>(spec: TransportRequest): Promise<T | StreamResponse> {
    const method = (spec.method ?? "GET").toUpperCase();
    const id = spec.requestId ?? requestId();
    const url = new URL(
      spec.path.replace(/^\//, ""),
      this.#baseUrl.href.endsWith("/")
        ? this.#baseUrl
        : new URL(`${this.#baseUrl.href}/`),
    );
    for (const [key, value] of Object.entries(spec.query ?? {}))
      if (value !== undefined) url.searchParams.set(key, String(value));
    const context = { method, url: url.toString(), requestId: id };
    const headers = new Headers(spec.headers);
    headers.set("X-Request-Id", id);
    headers.set(
      "Accept",
      spec.response === "stream" ? "*/*" : "application/json",
    );
    const auth = await this.#options.getAuthorization?.(context);
    if (auth) headers.set("Authorization", auth);
    if (unsafe.has(method)) {
      const csrf = await this.#options.getCsrfToken?.(context);
      if (csrf) headers.set("X-CSRF-Token", csrf);
    }
    if (spec.idempotencyKey)
      headers.set("Idempotency-Key", spec.idempotencyKey);
    if (spec.ifMatch) headers.set("If-Match", spec.ifMatch);
    const canReplay = replayable(spec.body);
    const idempotent =
      spec.replaySafe !== false &&
      (method === "GET" ||
        method === "HEAD" ||
        Boolean(spec.idempotencyKey && canReplay));
    const max = idempotent ? (this.#options.retry?.maxAttempts ?? 3) : 1;
    const blobBody = spec.body instanceof Blob ? spec.body : undefined;
    const blobUpload = blobBody ? spec.onUploadProgress : undefined;
    if (blobBody && blobUpload)
      blobUpload({ transferredBytes: 0, totalBytes: blobBody.size });
    for (let attempt = 1; ; attempt++) {
      let response: Response;
      try {
        let body = spec.body;
        if (spec.onUploadProgress && body instanceof ReadableStream)
          body = progressStream(body, undefined, spec.onUploadProgress);
        const init: RequestInit & { duplex?: "half" } = {
          method,
          headers,
          body,
          credentials: this.#options.credentials ?? "same-origin",
          signal: spec.signal,
        };
        if (body instanceof ReadableStream) init.duplex = "half";
        response = await this.#fetch(url, init);
      } catch (cause) {
        if (
          spec.signal?.aborted ||
          (cause instanceof DOMException && cause.name === "AbortError")
        )
          throw new SlateFsAbortError(id, cause);
        if (attempt < max) {
          try {
            await delay(this.#backoff(attempt), spec.signal);
          } catch (abortCause) {
            throw new SlateFsAbortError(id, abortCause);
          }
          continue;
        }
        throw new SlateFsNetworkError(
          "SlateFS network request failed",
          id,
          cause,
        );
      }
      const returnedId = response.headers.get("x-request-id") ?? id;
      const retryMs = retryAfter(response.headers);
      if (!response.ok && attempt < max && retryStatuses.has(response.status)) {
        await response.body?.cancel();
        try {
          await delay(retryMs ?? this.#backoff(attempt), spec.signal);
        } catch (cause) {
          throw new SlateFsAbortError(id, cause);
        }
        continue;
      }
      if (blobBody && blobUpload)
        blobUpload({
          transferredBytes: blobBody.size,
          totalBytes: blobBody.size,
        });
      if (!response.ok) {
        let envelope: {
          error?: {
            code?: string;
            message?: string;
            request_id?: string;
            details?: Record<string, unknown>;
          };
        } = {};
        try {
          envelope = (await response.json()) as typeof envelope;
        } catch {
          /* sanitized fallback */
        }
        const error = new SlateFsApiError(
          envelope.error?.message ??
            `SlateFS request failed with status ${response.status}`,
          envelope.error?.request_id ?? returnedId,
          response.status,
          envelope.error?.code ?? `http_${response.status}`,
          envelope.error?.details ?? {},
          retryMs,
        );
        if (response.status === 401) this.#options.onAuthRequired?.(error);
        throw error;
      }
      const metadata = {
        method,
        url: url.toString(),
        requestId: returnedId,
        status: response.status,
        resolvedCommit:
          response.headers.get("x-slatefs-resolved-commit") ?? undefined,
      };
      this.#options.onResponse?.(metadata);
      if (spec.response === "stream") {
        if (!response.body)
          throw new SlateFsNetworkError(
            "SlateFS stream response had no body",
            returnedId,
            new Error("missing body"),
          );
        const length = contentLength(response.headers);
        return {
          body: progressStream(response.body, length, spec.onDownloadProgress),
          headers: response.headers,
          status: response.status,
          requestId: returnedId,
        };
      }
      if (
        spec.response === "empty" ||
        response.status === 204 ||
        response.headers.get("content-length") === "0"
      )
        return undefined as T;
      try {
        return (await response.json()) as T;
      } catch (cause) {
        throw new SlateFsNetworkError(
          "SlateFS returned an invalid JSON response",
          returnedId,
          cause,
        );
      }
    }
  }
  #backoff(attempt: number): number {
    const policy = this.#options.retry ?? {};
    const raw = Math.min(
      policy.maxDelayMs ?? 2_000,
      (policy.baseDelayMs ?? 100) * 2 ** (attempt - 1),
    );
    return policy.jitter === false
      ? raw
      : Math.floor(raw * (0.5 + Math.random() * 0.5));
  }
}
