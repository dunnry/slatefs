import cookie from "@fastify/cookie";
import staticFiles from "@fastify/static";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { existsSync } from "node:fs";
import { Readable } from "node:stream";
import type { DemoServerConfig } from "./config.js";
import { SessionStore, type Session } from "./session-store.js";
import {
  authenticate,
  requireCsrf,
  sameOrigin,
  securityHeaders,
  Throttle,
} from "./security.js";
import {
  bufferUpstreamResponse,
  replayBufferedResponse,
  sendUpstream,
  UpstreamResponseTooLarge,
  upstreamHeaders,
  type BufferedUpstreamResponse,
} from "./upstream.js";

const cookieName = "slatefs_demo_session";
const safeSegment = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const sessionDto = (session: Session) => ({
  authenticated: Boolean(session.account),
  ...(session.account
    ? {
        user: {
          username: session.account.username,
          displayName: session.account.displayName,
        },
        expiresAt: new Date(session.expiresAt).toISOString(),
      }
    : {}),
  csrfToken: session.csrfToken,
  capabilities: {
    snapshots: true,
    versions: true,
    collaboration: true,
    repository: true,
  },
});
function cookieOptions(config: DemoServerConfig) {
  return {
    path: "/",
    httpOnly: true,
    sameSite: "strict" as const,
    secure: config.secureCookie,
    maxAge: Math.floor(config.sessionTtlMs / 1000),
  };
}
function bodyFor(request: FastifyRequest): BodyInit | undefined {
  if (request.body === undefined || request.body === null) return undefined;
  if (request.body instanceof Readable)
    return Readable.toWeb(request.body) as unknown as BodyInit;
  if (typeof request.body === "string" || request.body instanceof Uint8Array)
    return request.body as BodyInit;
  return JSON.stringify(request.body);
}
function limitedStream(
  body: ReadableStream<Uint8Array>,
  limit: number,
  exceeded: () => void,
): ReadableStream<Uint8Array> {
  let bytes = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        bytes += chunk.byteLength;
        if (bytes > limit) {
          exceeded();
          controller.error(new Error("request body limit exceeded"));
          return;
        }
        controller.enqueue(chunk);
      },
    }),
  );
}
function authSession(
  request: FastifyRequest,
  store: SessionStore,
): Session | undefined {
  return store.get(request.cookies[cookieName]);
}
function fail(
  reply: import("fastify").FastifyReply,
  request: FastifyRequest,
  status: number,
  code: string,
  message: string,
) {
  return reply
    .code(status)
    .header("cache-control", "no-store")
    .send({ error: { code, message, request_id: request.id, details: {} } });
}
function validConsumerPath(url: string): boolean {
  try {
    const pathname = new URL(url, "http://local").pathname;
    const rawSegments = pathname.split("/");
    if (
      !rawSegments.every((raw) => {
        const value = decodeURIComponent(raw);
        return (
          value !== "." &&
          value !== ".." &&
          !value.includes("/") &&
          !value.includes("\\") &&
          !value.includes("\0")
        );
      })
    )
      return false;
    const segments = rawSegments.map((raw) => decodeURIComponent(raw));
    if (segments.slice(0, 4).join("/") !== "/api/consumer/v1") return false;
    const tail = segments.slice(4);
    if (tail.length === 1)
      return tail[0] === "capabilities" || tail[0] === "volumes";
    if (tail.length === 2)
      return tail[0] === "volumes" && safeSegment.test(tail[1]!);
    return (
      tail.length === 3 &&
      tail[0] === "volumes" &&
      safeSegment.test(tail[1]!) &&
      ["entries", "content", "operations", "xattrs"].includes(tail[2]!)
    );
  } catch {
    return false;
  }
}
function validConsumerMethod(url: string, method: string): boolean {
  const pathname = new URL(url, "http://local").pathname;
  if (pathname.endsWith("/capabilities") || pathname.endsWith("/volumes"))
    return method === "GET";
  if (/\/volumes\/[^/]+$/.test(pathname)) return method === "GET";
  if (pathname.endsWith("/entries"))
    return ["GET", "POST", "PATCH", "DELETE"].includes(method);
  if (pathname.endsWith("/content"))
    return method === "GET" || method === "PUT";
  if (pathname.endsWith("/operations")) return method === "POST";
  if (pathname.endsWith("/xattrs"))
    return method === "GET" || method === "PATCH";
  return false;
}

export async function buildServer(
  config: DemoServerConfig,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger:
      config.logger === false
        ? false
        : {
            redact: [
              "req.headers.authorization",
              "req.headers.cookie",
              "req.headers.x-csrf-token",
              "body.password",
            ],
          },
    bodyLimit: config.bodyLimit,
    requestIdHeader: "x-request-id",
  });
  const sessions = new SessionStore(config.sessionTtlMs);
  const throttle = new Throttle();
  const panelReads = new Map<string, Promise<BufferedUpstreamResponse>>();
  await app.register(cookie);
  app.addHook("onSend", async (request, reply) => {
    securityHeaders(reply);
    if (request.url.startsWith("/api/"))
      reply.header("cache-control", "no-store");
    const pathname = request.url.split("?", 1)[0];
    if (pathname === "/" || pathname === "/index.html")
      reply.header("cache-control", "no-store");
  });
  app.addContentTypeParser(
    [
      "application/octet-stream",
      "application/zip",
      "application/vnd.slatefs.version-repository",
    ],
    (_request, payload, done) => done(null, payload),
  );
  app.get("/healthz", async () => ({ ok: true }));
  app.get("/api/v1/session", async (request, reply) => {
    let session = authSession(request, sessions);
    if (!session) {
      session = sessions.create();
      reply.setCookie(cookieName, session.id, cookieOptions(config));
    }
    reply.header("cache-control", "no-store");
    return sessionDto(session);
  });
  app.post<{ Body: { username?: unknown; password?: unknown } }>(
    "/api/v1/login",
    async (request, reply) => {
      const existing = authSession(request, sessions);
      if (!existing)
        return fail(
          reply,
          request,
          401,
          "session_required",
          "Create a session before login",
        );
      if (!sameOrigin(request, config.allowedOrigins, config.host))
        return fail(
          reply,
          request,
          403,
          "origin_rejected",
          "Unsafe cross-origin request rejected",
        );
      if (!requireCsrf(request, reply, existing)) return;
      if (!throttle.allow(`login:${request.ip}`, 5))
        return fail(
          reply,
          request,
          429,
          "rate_limited",
          "Too many login attempts",
        );
      const account = authenticate(
        request.body?.username,
        request.body?.password,
      );
      if (!account)
        return fail(
          reply,
          request,
          401,
          "invalid_credentials",
          "Invalid username or password",
        );
      const session = sessions.rotate(existing.id, account);
      reply
        .setCookie(cookieName, session.id, cookieOptions(config))
        .header("cache-control", "no-store");
      return sessionDto(session);
    },
  );
  app.post("/api/v1/logout", async (request, reply) => {
    const session = authSession(request, sessions);
    if (!session)
      return fail(
        reply,
        request,
        401,
        "authentication_required",
        "Authentication required",
      );
    if (!sameOrigin(request, config.allowedOrigins, config.host))
      return fail(
        reply,
        request,
        403,
        "origin_rejected",
        "Unsafe cross-origin request rejected",
      );
    if (!requireCsrf(request, reply, session)) return;
    sessions.delete(session.id);
    reply
      .clearCookie(cookieName, cookieOptions(config))
      .header("cache-control", "no-store");
    return reply.code(204).send();
  });

  const authorize = (
    request: FastifyRequest,
    reply: import("fastify").FastifyReply,
  ): Session | undefined => {
    const session = authSession(request, sessions);
    if (!session?.account) {
      void fail(
        reply,
        request,
        401,
        "authentication_required",
        "Authentication required",
      );
      return;
    }
    if (!throttle.allow(`session:${session.id}`, 240)) {
      void fail(reply, request, 429, "rate_limited", "Too many requests");
      return;
    }
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
      if (!sameOrigin(request, config.allowedOrigins, config.host)) {
        void fail(
          reply,
          request,
          403,
          "origin_rejected",
          "Unsafe cross-origin request rejected",
        );
        return;
      }
      if (!requireCsrf(request, reply, session)) return;
    }
    return session;
  };
  app.all("/api/consumer/v1/*", async (request, reply) => {
    const session = authorize(request, reply);
    if (!session?.account) return;
    const suffix = request.url.slice("/api".length);
    if (
      !validConsumerPath(request.url) ||
      !validConsumerMethod(request.url, request.method)
    )
      return fail(reply, request, 400, "invalid_path", "Invalid proxy path");
    const target = new URL(suffix, config.consumerBaseUrl);
    const declaredLength = request.headers["content-length"];
    if (
      typeof declaredLength === "string" &&
      Number(declaredLength) > config.bodyLimit
    )
      return fail(
        reply,
        request,
        413,
        "payload_too_large",
        "Request body exceeds the configured limit",
      );
    const controller = new AbortController();
    reply.raw.once("close", () => {
      if (!reply.raw.writableEnded) controller.abort();
    });
    let body =
      request.method === "GET" || request.method === "HEAD"
        ? undefined
        : bodyFor(request);
    let bodyLimitExceeded = false;
    if (body instanceof ReadableStream)
      body = limitedStream(body, config.bodyLimit, () => {
        bodyLimitExceeded = true;
      });
    const headers = upstreamHeaders(
      request,
      config.tenantTokens[session.account.tenant],
    );
    if (
      body === undefined ||
      (!(request.body instanceof Readable) &&
        typeof request.body !== "string" &&
        !(request.body instanceof Uint8Array))
    )
      headers.delete("content-length");
    const init: RequestInit & { duplex?: "half" } = {
      method: request.method,
      headers,
      body,
      signal: controller.signal,
    };
    if (init.body instanceof ReadableStream) init.duplex = "half";
    try {
      const response = await fetch(target, init);
      return sendUpstream(reply, response, request.id);
    } catch {
      if (controller.signal.aborted) return;
      if (bodyLimitExceeded)
        return fail(
          reply,
          request,
          413,
          "payload_too_large",
          "Request body exceeds the configured limit",
        );
      request.log.warn("SlateFS consumer upstream request failed");
      return fail(
        reply,
        request,
        502,
        "upstream_unavailable",
        "SlateFS upstream unavailable",
      );
    }
  });

  app.all<{ Params: { volume: string; "*": string } }>(
    "/api/v1/volumes/:volume/*",
    async (request, reply) => {
      const session = authorize(request, reply);
      if (!session?.account) return;
      const { volume } = request.params;
      const tail = request.params["*"];
      if (
        !safeSegment.test(volume) ||
        tail.split("/").some((value) => !safeSegment.test(value))
      )
        return fail(
          reply,
          request,
          400,
          "invalid_path",
          "Invalid route identifier",
        );
      const mapped = mapAdminRoute(
        request.method,
        tail,
        request.query as Record<string, string>,
        request.body,
      );
      if (!mapped)
        return fail(reply, request, 404, "not_found", "Route not found");
      const base = `/admin/v1/tenants/${encodeURIComponent(session.account.tenant)}/volumes/${encodeURIComponent(volume)}`;
      const headers = upstreamHeaders(
        request,
        config.tenantTokens[session.account.tenant],
      );
      const sharedPanelRead =
        request.method === "GET" &&
        /^(?:snapshots|versioning\/(?:overview|branch-overview|stats))$/.test(
          tail,
        );
      const controller = sharedPanelRead ? undefined : new AbortController();
      if (controller)
        reply.raw.once("close", () => {
          if (!reply.raw.writableEnded) controller.abort();
        });
      if (mapped.expectedHeads) {
        const checkHeaders = new Headers(headers);
        checkHeaders.set("accept", "application/json");
        for (const name of ["content-type", "content-length", "if-match"])
          checkHeaders.delete(name);
        try {
          const response = await fetch(
            new URL(`${base}/versioning/branches`, config.adminBaseUrl),
            { headers: checkHeaders, signal: controller?.signal },
          );
          if (!response.ok) return sendUpstream(reply, response, request.id);
          const declaredLength = Number(
            response.headers.get("content-length") ?? "0",
          );
          if (declaredLength > config.bodyLimit)
            return fail(
              reply,
              request,
              502,
              "invalid_upstream_response",
              "SlateFS branch response exceeded the configured limit",
            );
          const text = await response.text();
          if (Buffer.byteLength(text) > config.bodyLimit)
            return fail(
              reply,
              request,
              502,
              "invalid_upstream_response",
              "SlateFS branch response exceeded the configured limit",
            );
          const payload = JSON.parse(text) as {
            branches?: Array<{ name?: unknown; commit?: unknown }>;
          };
          if (!Array.isArray(payload.branches)) throw new Error("branches");
          const head = (name: string) =>
            payload.branches!.find((branch) => branch.name === name)?.commit;
          const expected = mapped.expectedHeads;
          if (
            (expected.targetCommit !== undefined &&
              head(expected.target) !== expected.targetCommit) ||
            (expected.sourceCommit !== undefined &&
              head(expected.source) !== expected.sourceCommit)
          )
            return fail(
              reply,
              request,
              409,
              "stale_preview",
              "Branch heads changed after preview; preview again before applying",
            );
        } catch {
          if (controller?.signal.aborted) return;
          return fail(
            reply,
            request,
            502,
            "invalid_upstream_response",
            "SlateFS returned an invalid branch response",
          );
        }
      }
      const target = new URL(`${base}/${mapped.path}`, config.adminBaseUrl);
      for (const [key, value] of Object.entries(
        mapped.query ?? (request.query as Record<string, string>),
      ))
        if (typeof value === "string") target.searchParams.set(key, value);
      const method = mapped.method ?? request.method;
      const body =
        method === "GET" || method === "HEAD" || mapped.dropBody
          ? undefined
          : mapped.body === undefined
            ? bodyFor(request)
            : JSON.stringify(mapped.body);
      headers.delete("content-length");
      if (body && !headers.has("content-type"))
        headers.set("content-type", "application/json");
      try {
        let response: Response;
        if (sharedPanelRead) {
          const key = `${session.account.tenant}\n${target.href}`;
          let pending = panelReads.get(key);
          if (!pending) {
            pending = fetch(target, { method, headers, body }).then(
              (upstream) => bufferUpstreamResponse(upstream, config.bodyLimit),
            );
            panelReads.set(key, pending);
            const remove = () => {
              if (panelReads.get(key) === pending) panelReads.delete(key);
            };
            void pending.then(remove, remove);
          }
          const buffered = await pending;
          if (reply.raw.destroyed) return;
          response = replayBufferedResponse(buffered);
        } else {
          response = await fetch(target, {
            method,
            headers,
            body,
            signal: controller?.signal,
          });
        }
        return sendUpstream(reply, response, request.id);
      } catch (error) {
        if (controller?.signal.aborted) return;
        if (error instanceof UpstreamResponseTooLarge)
          return fail(
            reply,
            request,
            502,
            "invalid_upstream_response",
            "SlateFS response exceeded the configured limit",
          );
        request.log.warn("SlateFS admin upstream request failed");
        return fail(
          reply,
          request,
          502,
          "upstream_unavailable",
          "SlateFS upstream unavailable",
        );
      }
    },
  );
  if (config.staticDir && existsSync(config.staticDir)) {
    await app.register(staticFiles, {
      root: config.staticDir,
      prefix: "/",
      cacheControl: true,
      maxAge: "1h",
    });
  }
  app.addHook("onClose", async () => sessions.sweep());
  return app;
}

interface Mapping {
  path: string;
  method?: string;
  query?: Record<string, string>;
  body?: unknown;
  dropBody?: boolean;
  expectedHeads?: {
    target: string;
    source: string;
    targetCommit?: string;
    sourceCommit?: string;
  };
}
function mapAdminRoute(
  method: string,
  tail: string,
  query: Record<string, string>,
  body: unknown,
): Mapping | undefined {
  if (tail === "snapshots" && method === "GET") return { path: "snapshots" };
  if (tail === "snapshots" && method === "POST") {
    const name = (body as { name?: unknown } | undefined)?.name;
    return {
      path: "snapshot",
      query: typeof name === "string" ? { name } : {},
      dropBody: true,
    };
  }
  const clone = /^snapshots\/([^/]+)\/clones$/.exec(tail);
  if (clone && method === "POST") {
    const newVolume = (body as { new_volume?: unknown })?.new_volume;
    if (typeof newVolume !== "string" || !safeSegment.test(newVolume))
      return undefined;
    return {
      path: "clones",
      body: { clone_volume: newVolume, snapshot_id: clone[1] },
    };
  }
  if (tail === "versioning" && (method === "GET" || method === "PATCH"))
    return { path: tail };
  if (tail === "versioning/overview" && method === "GET") return { path: tail };
  if (tail === "versioning/branch-overview" && method === "GET")
    return { path: tail };
  if (tail === "versioning/status" && method === "GET") return { path: tail };
  if (tail === "versioning/commits" && (method === "GET" || method === "POST"))
    return { path: tail };
  if (tail === "versioning/diff" && method === "GET") return { path: tail };
  if (tail === "versioning/tags" && (method === "GET" || method === "POST"))
    return { path: tail };
  if (tail === "versioning/branches" && (method === "GET" || method === "POST"))
    return { path: tail };
  if (/^versioning\/(stats|verify)$/.test(tail) && method === "GET")
    return { path: tail };
  if (
    /^versioning\/commits\/[^/]+(?:\/attestations)?$/.test(tail) &&
    method === "GET"
  )
    return { path: tail };
  if (
    /^versioning\/branches\/[^/]+\/(reflog|attestation-quorum)$/.test(tail) &&
    method === "GET"
  )
    return { path: tail };
  const protection = /^versioning\/branches\/([^/]+)\/protection$/.exec(tail);
  if (protection && method === "GET") return { path: "versioning/branches" };
  if (protection && method === "PUT")
    return {
      path: tail,
      method:
        (body as { protected?: unknown })?.protected === false
          ? "DELETE"
          : "PUT",
      dropBody: (body as { protected?: unknown })?.protected === false,
      body:
        (body as { protected?: unknown })?.protected === false
          ? undefined
          : Object.fromEntries(
              Object.entries((body as Record<string, unknown>) ?? {}).filter(
                ([key]) => key !== "protected",
              ),
            ),
    };
  const preview =
    /^(versioning\/branches\/[^/]+\/(?:merge|cherry-pick))\/preview$/.exec(
      tail,
    );
  if (preview && method === "POST") {
    const values = (body as Record<string, unknown> | undefined) ?? {};
    return {
      path: preview[1]!,
      method: "GET",
      dropBody: true,
      query: Object.fromEntries(
        Object.entries(values)
          .filter(([, v]) => typeof v === "string" || typeof v === "number")
          .map(([k, v]) => [k, String(v)]),
      ),
    };
  }
  if (
    /^versioning\/branches\/[^/]+\/(merge|cherry-pick)$/.test(tail) &&
    method === "POST"
  ) {
    const values = (body as Record<string, unknown> | undefined) ?? {};
    const target = tail.split("/")[2]!;
    const source = values.source;
    if (typeof source !== "string" || !source) return undefined;
    return {
      path: tail,
      body: Object.fromEntries(
        Object.entries(values).filter(([key]) => key !== "target"),
      ),
      ...(typeof values.expected_target === "string" ||
      typeof values.expected_source === "string"
        ? {
            expectedHeads: {
              target,
              source,
              ...(typeof values.expected_target === "string"
                ? { targetCommit: values.expected_target }
                : {}),
              ...(typeof values.expected_source === "string"
                ? { sourceCommit: values.expected_source }
                : {}),
            },
          }
        : {}),
    };
  }
  if (tail === "versioning/restore-preview" && method === "POST") {
    const values = (body as Record<string, unknown> | undefined) ?? {};
    return {
      path: tail,
      method: "GET",
      dropBody: true,
      query: Object.fromEntries(
        Object.entries(values)
          .filter(([, v]) => typeof v === "string")
          .map(([k, v]) => [k, String(v)]),
      ),
    };
  }
  if (tail === "versioning/restore" && method === "POST") return { path: tail };
  return undefined;
}
