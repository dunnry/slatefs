import { once } from "node:events";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildServer } from "../src/server.js";
import type { DemoServerConfig } from "../src/config.js";

const servers: Array<{ close(): Promise<void> }> = [];
const config = (base = "http://127.0.0.1:1"): DemoServerConfig => ({
  host: "127.0.0.1",
  port: 0,
  secureCookie: false,
  allowUnsafeDemoBind: false,
  consumerBaseUrl: base,
  adminBaseUrl: base,
  tenantTokens: { acme: "acme-secret-token", globex: "globex-secret-token" },
  sessionTtlMs: 60_000,
  bodyLimit: 1024 * 1024,
  logger: false,
});
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  vi.restoreAllMocks();
});
function sessionCookie(
  headers: Record<string, string | string[] | number | undefined>,
): string {
  const raw = headers["set-cookie"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string") throw new Error("missing session cookie");
  return value.split(";", 1)[0]!;
}
async function login(
  app: Awaited<ReturnType<typeof buildServer>>,
  username = "alice",
) {
  const initial = await app.inject({ method: "GET", url: "/api/v1/session" });
  const state = initial.json();
  const cookie = sessionCookie(initial.headers);
  const response = await app.inject({
    method: "POST",
    url: "/api/v1/login",
    headers: {
      cookie,
      origin: "http://localhost",
      host: "localhost",
      "x-csrf-token": state.csrfToken,
    },
    payload: { username, password: "slatefs" },
  });
  return {
    response,
    state: response.json(),
    cookie: sessionCookie(response.headers),
  };
}

describe("demo static assets", () => {
  it("does not cache the entry point that selects hashed browser assets", async () => {
    const directory = mkdtempSync(join(tmpdir(), "slatefs-demo-static-"));
    mkdirSync(join(directory, "assets"));
    writeFileSync(join(directory, "index.html"), "<h1>demo</h1>");
    writeFileSync(join(directory, "assets", "index-hash.js"), "export {};");
    try {
      const app = await buildServer({ ...config(), staticDir: directory });
      servers.push(app);
      const index = await app.inject({ method: "GET", url: "/" });
      const asset = await app.inject({
        method: "GET",
        url: "/assets/index-hash.js",
      });
      expect(index.headers["cache-control"]).toBe("no-store");
      expect(asset.headers["cache-control"]).toContain("max-age=3600");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe("demo session boundary", () => {
  it("issues strict HttpOnly cookies and rotates on login", async () => {
    const app = await buildServer(config());
    servers.push(app);
    const initial = await app.inject({ method: "GET", url: "/api/v1/session" });
    expect(initial.headers["set-cookie"]).toContain("HttpOnly");
    expect(initial.headers["set-cookie"]).toContain("SameSite=Strict");
    expect(initial.headers["content-security-policy"]).toContain(
      "default-src 'self'",
    );
    expect(initial.headers["x-content-type-options"]).toBe("nosniff");
    expect(initial.headers["cache-control"]).toBe("no-store");
    const old = sessionCookie(initial.headers);
    const state = initial.json();
    const loginResponse = await app.inject({
      method: "POST",
      url: "/api/v1/login",
      headers: {
        cookie: old,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": state.csrfToken,
      },
      payload: { username: "alice", password: "slatefs" },
    });
    expect(loginResponse.statusCode).toBe(200);
    expect(sessionCookie(loginResponse.headers)).not.toBe(old);
    expect(loginResponse.json().csrfToken).not.toBe(state.csrfToken);
    expect(loginResponse.json().capabilities).toEqual({
      snapshots: true,
      versions: true,
      collaboration: true,
      repository: true,
    });
    expect(loginResponse.body).not.toContain("acme-secret-token");
    expect(loginResponse.body).not.toContain("globex-secret-token");
  });
  it("enforces CSRF and origin and invalidates logout", async () => {
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const bad = await app.inject({
      method: "POST",
      url: "/api/v1/logout",
      headers: {
        cookie: logged.cookie,
        origin: "https://evil.test",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
      },
    });
    expect(bad.statusCode).toBe(403);
    const good = await app.inject({
      method: "POST",
      url: "/api/v1/logout",
      headers: {
        cookie: logged.cookie,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
      },
    });
    expect(good.statusCode).toBe(204);
    const proxy = await app.inject({
      method: "GET",
      url: "/api/consumer/v1/capabilities",
      headers: { cookie: logged.cookie },
    });
    expect(proxy.statusCode).toBe(401);
  });
  it("rejects bad credentials without leaking tenant data", async () => {
    const app = await buildServer(config());
    servers.push(app);
    const initial = await app.inject({ method: "GET", url: "/api/v1/session" });
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/login",
      headers: {
        cookie: sessionCookie(initial.headers),
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": initial.json().csrfToken,
      },
      payload: { username: "alice", password: "wrong" },
    });
    expect(response.statusCode).toBe(401);
    expect(response.body).not.toMatch(/acme|token/);
  });
  it("rejects missing Origin and DNS-rebinding Host values", async () => {
    const app = await buildServer(config());
    servers.push(app);
    const initial = await app.inject({ method: "GET", url: "/api/v1/session" });
    const cookie = sessionCookie(initial.headers);
    const csrf = initial.json().csrfToken;
    for (const headers of [
      { cookie, host: "localhost", "x-csrf-token": csrf },
      {
        cookie,
        host: "evil.example",
        origin: "http://evil.example",
        "x-csrf-token": csrf,
      },
    ]) {
      const response = await app.inject({
        method: "POST",
        url: "/api/v1/login",
        headers,
        payload: { username: "alice", password: "slatefs" },
      });
      expect(response.statusCode).toBe(403);
    }
  });
});

describe("tenant-safe proxy and facade", () => {
  it("single-flights identical bounded panel reads without caching results", async () => {
    let calls = 0;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      calls++;
      await blocked;
      return new Response(JSON.stringify({ commits: [] }), {
        headers: { "content-type": "application/json" },
      });
    });
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const request = () =>
      app.inject({
        method: "GET",
        url: "/api/v1/volumes/docs/versioning/overview?reference=main&limit=50",
        headers: { cookie: logged.cookie },
      });
    const first = request();
    const second = request();
    await vi.waitFor(() => expect(calls).toBe(1));
    release();
    expect((await first).statusCode).toBe(200);
    expect((await second).statusCode).toBe(200);
    expect(calls).toBe(1);
    expect((await request()).statusCode).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("rejects oversized shared panel responses instead of caching or streaming them", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("x".repeat(129), {
        headers: { "content-type": "application/json" },
      }),
    );
    const app = await buildServer({ ...config(), bodyLimit: 128 });
    servers.push(app);
    const logged = await login(app);
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/volumes/docs/versioning/stats",
      headers: { cookie: logged.cookie },
    });
    expect(response.statusCode).toBe(502);
    expect(response.json().error.code).toBe("invalid_upstream_response");
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("keeps shared panel reads isolated by authenticated tenant", async () => {
    const authorizations: string[] = [];
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetch = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (_input, init) => {
        authorizations.push(
          String(new Headers(init?.headers).get("authorization")),
        );
        await blocked;
        return new Response(JSON.stringify({ stats: {} }), {
          headers: { "content-type": "application/json" },
        });
      });
    const app = await buildServer(config());
    servers.push(app);
    const alice = await login(app, "alice");
    const bob = await login(app, "bob");
    const request = (cookie: string) =>
      app.inject({
        method: "GET",
        url: "/api/v1/volumes/docs/versioning/stats",
        headers: { cookie },
      });
    const aliceResponse = request(alice.cookie);
    const bobResponse = request(bob.cookie);
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    release();
    expect((await aliceResponse).statusCode).toBe(200);
    expect((await bobResponse).statusCode).toBe(200);
    expect(authorizations).toEqual([
      "Bearer acme-secret-token",
      "Bearer globex-secret-token",
    ]);
  });

  it("forwards the browser root-list query without changing selector semantics", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ entries: [] }), {
        headers: { "content-type": "application/json" },
      }),
    );
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const response = await app.inject({
      method: "GET",
      url: "/api/consumer/v1/volumes/docs/entries?path=&view=live&limit=200",
      headers: { cookie: logged.cookie },
    });
    expect(response.statusCode).toBe(200);
    const target = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(target.pathname).toBe("/consumer/v1/volumes/docs/entries");
    expect(target.search).toBe("?path=&view=live&limit=200");
  });

  it("derives Alice/Bob tokens server-side and never forwards browser authorization", async () => {
    const seen: string[] = [];
    const upstream = createServer((request, response) => {
      seen.push(String(request.headers.authorization));
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ ok: true }));
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    const base = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
    servers.push({
      close: () => new Promise((resolve) => upstream.close(() => resolve())),
    });
    const app = await buildServer(config(base));
    servers.push(app);
    for (const username of ["alice", "bob"] as const) {
      const logged = await login(app, username);
      const response = await app.inject({
        method: "GET",
        url: "/api/consumer/v1/capabilities",
        headers: {
          cookie: logged.cookie,
          authorization: "Bearer browser-attack",
        },
      });
      expect(response.statusCode).toBe(200);
    }
    expect(seen).toEqual([
      "Bearer acme-secret-token",
      "Bearer globex-secret-token",
    ]);
  });
  it("constructs only the authenticated tenant admin path", async () => {
    let path = "";
    const upstream = createServer((request, response) => {
      path = request.url ?? "";
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ snapshots: [] }));
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    const base = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
    servers.push({
      close: () => new Promise((resolve) => upstream.close(() => resolve())),
    });
    const app = await buildServer(config(base));
    servers.push(app);
    const logged = await login(app);
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/volumes/documents/snapshots",
      headers: { cookie: logged.cookie },
    });
    expect(response.statusCode).toBe(200);
    expect(path).toBe("/admin/v1/tenants/acme/volumes/documents/snapshots");
    const forbidden = await app.inject({
      method: "GET",
      url: "/api/v1/volumes/../globex/versioning/stats",
      headers: { cookie: logged.cookie },
    });
    expect(forbidden.statusCode).toBe(404);
  });
  it("translates typed restore preview and refuses raw admin/bundle routes", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ preview: {} }), {
        headers: {
          "content-type": "application/json",
          "x-slatefs-resolved-commit": "abc",
        },
      }),
    );
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const preview = await app.inject({
      method: "POST",
      url: "/api/v1/volumes/docs/versioning/restore-preview",
      headers: {
        cookie: logged.cookie,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
      },
      payload: { commit: "main", path: "/", mode: "overlay" },
    });
    expect(preview.statusCode).toBe(200);
    const called = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(called.pathname).toContain(
      "/admin/v1/tenants/acme/volumes/docs/versioning/restore-preview",
    );
    expect(called.searchParams.get("commit")).toBe("main");
    const init = fetch.mock.calls[0]?.[1];
    expect(init?.method).toBe("GET");
    expect(init?.body).toBeUndefined();
    expect(new Headers(init?.headers).has("content-length")).toBe(false);
    const bundle = await app.inject({
      method: "GET",
      url: "/api/v1/volumes/docs/versioning/bundle",
      headers: { cookie: logged.cookie },
    });
    expect(bundle.statusCode).toBe(404);
  });
  it("strips facade-only fields and blocks cross-namespace clone targets", async () => {
    const fetch = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const url = new URL(String(input));
        const body = url.pathname.endsWith("/versioning/branches")
          ? {
              branches: [
                { name: "main", commit: "old" },
                { name: "feature", commit: "source" },
              ],
            }
          : { ok: true };
        return new Response(JSON.stringify(body), {
          headers: { "content-type": "application/json" },
        });
      });
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const headers = {
      cookie: logged.cookie,
      origin: "http://localhost",
      host: "localhost",
      "x-csrf-token": logged.state.csrfToken,
    };
    expect(
      (
        await app.inject({
          method: "POST",
          url: "/api/v1/volumes/docs/versioning/branches/main/merge",
          headers,
          payload: {
            target: "main",
            source: "feature",
            expected_target: "old",
          },
        })
      ).statusCode,
    ).toBe(200);
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
      source: "feature",
      expected_target: "old",
    });
    expect(
      (
        await app.inject({
          method: "PUT",
          url: "/api/v1/volumes/docs/versioning/branches/main/protection",
          headers,
          payload: { protected: true, required_attestations: 2 },
        })
      ).statusCode,
    ).toBe(200);
    expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toEqual({
      required_attestations: 2,
    });
    const clone = await app.inject({
      method: "POST",
      url: "/api/v1/volumes/docs/snapshots/s1/clones",
      headers,
      payload: { new_volume: "../globex" },
    });
    expect(clone.statusCode).toBe(404);
    expect(fetch).toHaveBeenCalledTimes(3);
  });
  it("rejects stale merge plans before calling the apply route", async () => {
    const fetch = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(
          JSON.stringify({ branches: [{ name: "main", commit: "new-head" }] }),
          { headers: { "content-type": "application/json" } },
        ),
      );
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/volumes/docs/versioning/branches/main/merge",
      headers: {
        cookie: logged.cookie,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
      },
      payload: {
        source: "feature",
        expected_target: "reviewed-head",
      },
    });
    expect(response.statusCode).toBe(409);
    expect(response.json().error.code).toBe("stale_preview");
    expect(fetch).toHaveBeenCalledOnce();
  });
  it("rejects arbitrary consumer paths and removes transformed body lengths", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      }),
    );
    const app = await buildServer(config());
    servers.push(app);
    const logged = await login(app);
    const rejected = await app.inject({
      method: "POST",
      url: "/api/consumer/v1/volumes/docs/future-admin",
      headers: {
        cookie: logged.cookie,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
      },
      payload: {},
    });
    expect(rejected.statusCode).toBe(400);
    const accepted = await app.inject({
      method: "POST",
      url: "/api/consumer/v1/volumes/docs/entries",
      headers: {
        cookie: logged.cookie,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
        "content-type": "application/json",
      },
      payload: '{ "kind": "file", "name":"x"}',
    });
    expect(accepted.statusCode).toBe(200);
    expect(
      new Headers(fetch.mock.calls[0]?.[1]?.headers).has("content-length"),
    ).toBe(false);
  });
  it("enforces the configured body limit before proxying", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const limited = { ...config(), bodyLimit: 128 };
    const app = await buildServer(limited);
    servers.push(app);
    const logged = await login(app);
    const response = await app.inject({
      method: "PUT",
      url: "/api/consumer/v1/volumes/docs/content?entry_id=e",
      headers: {
        cookie: logged.cookie,
        origin: "http://localhost",
        host: "localhost",
        "x-csrf-token": logged.state.csrfToken,
        "content-type": "application/octet-stream",
      },
      payload: Buffer.alloc(129),
    });
    expect(response.statusCode).toBe(413);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("live streaming proxy", () => {
  it("forwards response chunks incrementally", async () => {
    let upstreamEnded = false;
    const upstream = createServer((_request, response) => {
      response.write("first");
      setTimeout(() => {
        upstreamEnded = true;
        response.end("second");
      }, 120);
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    const base = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
    servers.push({
      close: () => new Promise((resolve) => upstream.close(() => resolve())),
    });
    const app = await buildServer(config(base));
    await app.listen({ host: "127.0.0.1", port: 0 });
    servers.push(app);
    const origin = app.listeningOrigin;
    const initial = await fetch(`${origin}/api/v1/session`);
    const state = (await initial.json()) as { csrfToken: string };
    const cookie = initial.headers.getSetCookie()[0]!.split(";", 1)[0]!;
    const authenticated = await fetch(`${origin}/api/v1/login`, {
      method: "POST",
      headers: {
        cookie,
        origin,
        "x-csrf-token": state.csrfToken,
        "content-type": "application/json",
      },
      body: JSON.stringify({ username: "alice", password: "slatefs" }),
    });
    const authCookie = authenticated.headers
      .getSetCookie()[0]!
      .split(";", 1)[0]!;
    const response = await fetch(
      `${origin}/api/consumer/v1/volumes/docs/content?path=/x`,
      { headers: { cookie: authCookie } },
    );
    const reader = response.body!.getReader();
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toBe("first");
    expect(upstreamEnded).toBe(false);
    const rest = await new Response(
      new ReadableStream({
        async start(controller) {
          for (;;) {
            const item = await reader.read();
            if (item.done) break;
            controller.enqueue(item.value);
          }
          controller.close();
        },
      }),
    ).text();
    expect(rest).toBe("second");
  });
  it("forwards upload chunks incrementally and propagates downstream abort", async () => {
    let firstUpload = false;
    let uploadEnded = false;
    let upstreamClosed = false;
    const upstream = createServer((request, response) => {
      request.once("data", () => {
        firstUpload = true;
      });
      request.once("end", () => {
        uploadEnded = true;
        if (request.method === "PUT") {
          response.setHeader("content-type", "application/json");
          response.end("{}");
        }
      });
      response.once("close", () => {
        upstreamClosed = true;
      });
      if (request.method === "GET") {
        response.write("chunk");
        const interval = setInterval(() => response.write("more"), 20);
        response.once("close", () => clearInterval(interval));
      }
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    const base = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
    servers.push({
      close: () =>
        new Promise((resolve) => {
          upstream.closeAllConnections();
          upstream.close(() => resolve());
        }),
    });
    const app = await buildServer(config(base));
    await app.listen({ host: "127.0.0.1", port: 0 });
    servers.push({
      close: async () => {
        app.server.closeAllConnections();
        await app.close();
      },
    });
    const origin = app.listeningOrigin;
    const initial = await fetch(`${origin}/api/v1/session`);
    const initialState = (await initial.json()) as { csrfToken: string };
    const preauthCookie = initial.headers.getSetCookie()[0]!.split(";", 1)[0]!;
    const authenticated = await fetch(`${origin}/api/v1/login`, {
      method: "POST",
      headers: {
        cookie: preauthCookie,
        origin,
        "x-csrf-token": initialState.csrfToken,
        "content-type": "application/json",
      },
      body: JSON.stringify({ username: "alice", password: "slatefs" }),
    });
    const authState = (await authenticated.json()) as { csrfToken: string };
    const cookie = authenticated.headers.getSetCookie()[0]!.split(";", 1)[0]!;
    let releaseSecond!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseSecond = resolve;
    });
    const uploadBody = new ReadableStream<Uint8Array>({
      async start(controller) {
        controller.enqueue(new TextEncoder().encode("first"));
        await gate;
        controller.enqueue(new TextEncoder().encode("second"));
        controller.close();
      },
    });
    const upload = fetch(
      `${origin}/api/consumer/v1/volumes/docs/content?entry_id=e`,
      {
        method: "PUT",
        headers: {
          cookie,
          origin,
          "x-csrf-token": authState.csrfToken,
          "content-type": "application/octet-stream",
        },
        body: uploadBody,
        duplex: "half",
      } as RequestInit & { duplex: "half" },
    );
    for (let index = 0; index < 50 && !firstUpload; index++)
      await new Promise((resolve) => setTimeout(resolve, 2));
    expect(firstUpload).toBe(true);
    expect(uploadEnded).toBe(false);
    releaseSecond();
    expect((await upload).status).toBe(200);
    upstreamClosed = false;
    const controller = new AbortController();
    const download = await fetch(
      `${origin}/api/consumer/v1/volumes/docs/content?entry_id=e`,
      { headers: { cookie }, signal: controller.signal },
    );
    const reader = download.body!.getReader();
    await reader.read();
    controller.abort();
    await reader.cancel().catch(() => undefined);
    for (let index = 0; index < 50 && !upstreamClosed; index++)
      await new Promise((resolve) => setTimeout(resolve, 2));
    expect(upstreamClosed).toBe(true);
  });
});
