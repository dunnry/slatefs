import { Readable } from "node:stream";
import type { FastifyReply, FastifyRequest } from "fastify";

export interface BufferedUpstreamResponse {
  body: Uint8Array;
  headers: Headers;
  status: number;
}

export class UpstreamResponseTooLarge extends Error {
  constructor() {
    super("upstream response exceeded the configured limit");
    this.name = "UpstreamResponseTooLarge";
  }
}

const requestHeaders = [
  "accept",
  "content-type",
  "content-length",
  "range",
  "if-match",
  "if-none-match",
  "idempotency-key",
  "x-request-id",
];
const responseHeaders = [
  "content-type",
  "content-length",
  "content-range",
  "content-disposition",
  "etag",
  "last-modified",
  "accept-ranges",
  "retry-after",
  "x-request-id",
  "x-slatefs-resolved-commit",
];
export function upstreamHeaders(
  request: FastifyRequest,
  token: string,
): Headers {
  const headers = new Headers({
    Authorization: `Bearer ${token}`,
    "X-Request-Id": String(request.headers["x-request-id"] ?? request.id),
  });
  for (const name of requestHeaders) {
    const value = request.headers[name];
    if (typeof value === "string" && name !== "x-request-id")
      headers.set(name, value);
  }
  return headers;
}
export function applyResponseHeaders(
  reply: FastifyReply,
  headers: Headers,
): void {
  for (const name of responseHeaders) {
    const value = headers.get(name);
    if (value !== null)
      reply.header(
        name,
        name === "content-disposition" ? sanitizeDisposition(value) : value,
      );
  }
}

export async function bufferUpstreamResponse(
  response: Response,
  limit: number,
): Promise<BufferedUpstreamResponse> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    /^(0|[1-9][0-9]*)$/.test(declaredLength) &&
    Number(declaredLength) > limit
  ) {
    await response.body?.cancel();
    throw new UpstreamResponseTooLarge();
  }
  const reader = response.body?.getReader();
  if (!reader)
    return {
      body: new Uint8Array(),
      headers: new Headers(response.headers),
      status: response.status,
    };
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new UpstreamResponseTooLarge();
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return {
    body,
    headers: new Headers(response.headers),
    status: response.status,
  };
}

export function replayBufferedResponse(
  response: BufferedUpstreamResponse,
): Response {
  return new Response(response.body.slice(), {
    headers: response.headers,
    status: response.status,
  });
}
function sanitizeDisposition(value: string): string {
  return /^(attachment|inline)(?:;[\t\x20-\x7e]*)?$/i.test(value) &&
    !/[\r\n\\/]/.test(value)
    ? value
    : "attachment";
}
function sanitizeDetails(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[truncated]";
  if (typeof value === "string") return sanitizeText(value);
  if (Array.isArray(value))
    return value.slice(0, 100).map((item) => sanitizeDetails(item, depth + 1));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => !/(authorization|token|tenant|cookie)/i.test(key))
        .map(([key, item]) => [key, sanitizeDetails(item, depth + 1)]),
    );
  return value;
}
function sanitizeText(value: string): string {
  return value
    .slice(0, 4_096)
    .replace(/\/admin\/v1\/tenants\/[^/\s]+/g, "/admin/v1/tenants/[redacted]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [redacted]");
}
export async function sendUpstream(
  reply: FastifyReply,
  response: Response,
  requestId: string,
): Promise<void> {
  reply.code(response.status);
  if (!response.ok) {
    for (const name of ["retry-after", "x-request-id"]) {
      const value = response.headers.get(name);
      if (value !== null) reply.header(name, value);
    }
    let body: unknown;
    try {
      const text = await response.text();
      body = text.length <= 65_536 ? JSON.parse(text) : undefined;
    } catch {
      body = undefined;
    }
    const source = body as
      | {
          error?: {
            code?: unknown;
            message?: unknown;
            request_id?: unknown;
            details?: unknown;
          };
        }
      | undefined;
    await reply.header("cache-control", "no-store").send({
      error: {
        code:
          typeof source?.error?.code === "string"
            ? source.error.code
            : `upstream_${response.status}`,
        message:
          typeof source?.error?.message === "string"
            ? sanitizeText(source.error.message)
            : "SlateFS upstream request failed",
        request_id:
          typeof source?.error?.request_id === "string"
            ? source.error.request_id
            : requestId,
        details:
          typeof source?.error?.details === "object" && source.error.details
            ? sanitizeDetails(source.error.details)
            : {},
      },
    });
    return;
  }
  applyResponseHeaders(reply, response.headers);
  if (!response.body) {
    await reply.send();
    return;
  }
  await reply.send(
    Readable.fromWeb(response.body as import("node:stream/web").ReadableStream),
  );
}
