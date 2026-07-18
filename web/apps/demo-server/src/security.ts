import { timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { Account, Session } from "./session-store.js";

const accounts: readonly Account[] = [
  { username: "alice", displayName: "Alice", tenant: "acme" },
  { username: "bob", displayName: "Bob", tenant: "globex" },
];
export function authenticate(
  username: unknown,
  password: unknown,
): Account | undefined {
  const supplied = Buffer.from(typeof password === "string" ? password : "");
  const expected = Buffer.from("slatefs");
  const padded = Buffer.alloc(Math.max(supplied.length, expected.length));
  const expectedPadded = Buffer.alloc(padded.length);
  supplied.copy(padded);
  expected.copy(expectedPadded);
  const valid =
    timingSafeEqual(padded, expectedPadded) &&
    supplied.length === expected.length;
  const account = accounts.find((candidate) => candidate.username === username);
  return valid ? account : undefined;
}
export function sameOrigin(
  request: FastifyRequest,
  allowedOrigins?: readonly string[],
  configuredHost = "127.0.0.1",
): boolean {
  if (request.headers["sec-fetch-site"] === "cross-site") return false;
  const host = request.headers.host;
  if (
    !host ||
    /[\r\n\s]/.test(host) ||
    !/^(?:\[[0-9a-f:]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?$/.test(host)
  )
    return false;
  const hostname = host.startsWith("[")
    ? host.slice(1, host.indexOf("]"))
    : host.split(":", 1)[0]!;
  const configuredLoopback =
    configuredHost === "localhost" ||
    configuredHost === "::1" ||
    configuredHost.startsWith("127.");
  const hostAllowed = configuredLoopback
    ? hostname === "localhost" ||
      hostname === "::1" ||
      hostname.startsWith("127.")
    : hostname === configuredHost ||
      allowedOrigins?.some((value) => new URL(value).hostname === hostname);
  if (!hostAllowed) return false;
  const origin = request.headers.origin;
  if (!origin) return false;
  if (allowedOrigins?.includes(origin)) return true;
  try {
    const parsed = new URL(origin);
    return (
      parsed.host === host &&
      (parsed.protocol === "http:" || parsed.protocol === "https:")
    );
  } catch {
    return false;
  }
}
export function requireCsrf(
  request: FastifyRequest,
  reply: FastifyReply,
  session: Session,
): boolean {
  if (request.headers["x-csrf-token"] !== session.csrfToken) {
    void reply.code(403).send({
      error: {
        code: "csrf_failed",
        message: "CSRF validation failed",
        request_id: request.id,
        details: {},
      },
    });
    return false;
  }
  return true;
}
export function securityHeaders(reply: FastifyReply): void {
  reply.header(
    "Content-Security-Policy",
    "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
  reply.header("X-Content-Type-Options", "nosniff");
  reply.header("Referrer-Policy", "no-referrer");
  reply.header("X-Frame-Options", "DENY");
}
export class Throttle {
  readonly #buckets = new Map<string, { count: number; reset: number }>();
  allow(key: string, limit: number, windowMs = 60_000): boolean {
    const now = Date.now();
    if (this.#buckets.size >= 10_000)
      for (const [bucketKey, bucket] of this.#buckets)
        if (bucket.reset <= now) this.#buckets.delete(bucketKey);
    if (this.#buckets.size >= 10_000) {
      const oldest = this.#buckets.keys().next().value;
      if (oldest !== undefined) this.#buckets.delete(oldest);
    }
    const current = this.#buckets.get(key);
    if (!current || current.reset <= now) {
      this.#buckets.set(key, { count: 1, reset: now + windowMs });
      return true;
    }
    current.count++;
    return current.count <= limit;
  }
}
