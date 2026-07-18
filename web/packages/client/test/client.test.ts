import { describe, expect, it, vi } from "vitest";
import {
  createSlateFsClient,
  decodeU64,
  encodeU64,
  FetchTransport,
  SlateFsAbortError,
  SlateFsApiError,
  SlateFsNetworkError,
} from "../src/index.js";

const json = (value: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json", ...init.headers },
    ...init,
  });
const entry = {
  entry_id: "e",
  parent_entry_id: null,
  path: "/x",
  name: "x",
  name_bytes_base64: "eA==",
  kind: "file",
  inode: 1,
  generation: 1,
  size: 1,
  allocated_bytes: 1,
  mode: 420,
  uid: 1,
  gid: 1,
  link_count: 1,
  created_at: "",
  modified_at: "",
  changed_at: "",
  accessed_at: "",
  readonly: false,
  can_read: true,
  can_write: true,
  can_delete: true,
  can_rename: true,
  etag: "e",
  symlink_target: null,
} as const;

describe("FetchTransport", () => {
  it("calls the ambient browser fetch with its required global receiver", async () => {
    const browserFetch = vi.fn(function (this: unknown) {
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      return Promise.resolve(json({ ok: true }));
    });
    vi.stubGlobal("fetch", browserFetch);
    try {
      const transport = new FetchTransport({ baseUrl: "http://test/api/" });
      await expect(
        transport.request({ path: "consumer/v1/volumes" }),
      ).resolves.toEqual({ ok: true });
      expect(browserFetch).toHaveBeenCalledOnce();
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("generates and propagates request IDs, credentials, auth, and CSRF", async () => {
    const fetch = vi.fn(async (_url: URL, init: RequestInit) => {
      const headers = new Headers(init.headers);
      expect(init.credentials).toBe("same-origin");
      expect(headers.get("authorization")).toBe("Custom secret");
      expect(headers.get("x-csrf-token")).toBe("csrf");
      expect(headers.get("x-request-id")).toMatch(/.+/);
      return json({ ok: true }, { headers: { "x-request-id": "upstream-id" } });
    });
    const metadata = vi.fn();
    const transport = new FetchTransport({
      baseUrl: "http://test/api/",
      fetch: fetch as unknown as typeof globalThis.fetch,
      getAuthorization: () => "Custom secret",
      getCsrfToken: () => "csrf",
      onResponse: metadata,
    });
    await transport.request({ method: "POST", path: "x", body: "{}" });
    expect(metadata).toHaveBeenCalledWith(
      expect.objectContaining({ requestId: "upstream-id" }),
    );
  });
  it("honors explicit request, idempotency, and If-Match headers", async () => {
    const fetch = vi.fn(async (_url: URL, init: RequestInit) => {
      const headers = new Headers(init.headers);
      expect(headers.get("x-request-id")).toBe("req-1");
      expect(headers.get("idempotency-key")).toBe("idem-1");
      expect(headers.get("if-match")).toBe('"etag"');
      return json({});
    });
    const transport = new FetchTransport({
      baseUrl: "http://test/",
      fetch: fetch as unknown as typeof globalThis.fetch,
    });
    await transport.request({
      method: "PATCH",
      path: "x",
      body: "{}",
      requestId: "req-1",
      idempotencyKey: "idem-1",
      ifMatch: '"etag"',
    });
  });
  it("retries replayable GET failures and honors Retry-After", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        json(
          { error: { code: "busy" } },
          { status: 503, headers: { "retry-after": "0" } },
        ),
      )
      .mockResolvedValueOnce(json({ ok: true }));
    const transport = new FetchTransport({
      baseUrl: "http://test/",
      fetch,
      retry: { baseDelayMs: 0, jitter: false },
    });
    await expect(transport.request({ path: "x" })).resolves.toEqual({
      ok: true,
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("does not retry a mutation without a replay-safe idempotency key", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(json({ error: { code: "busy" } }, { status: 503 }));
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await expect(
      transport.request({ method: "POST", path: "x", body: "{}" }),
    ).rejects.toBeInstanceOf(SlateFsApiError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("honors the replay safety override for non-idempotent upstream operations", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(json({ error: { code: "busy" } }, { status: 503 }));
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await expect(
      transport.request({
        method: "POST",
        path: "snapshot",
        body: "{}",
        idempotencyKey: "caller-key",
        replaySafe: false,
      }),
    ).rejects.toBeInstanceOf(SlateFsApiError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("handles 204 responses", async () => {
    const transport = new FetchTransport({
      baseUrl: "http://test/",
      fetch: vi.fn(async () => new Response(null, { status: 204 })),
    });
    await expect(
      transport.request({ method: "DELETE", path: "x", response: "empty" }),
    ).resolves.toBeUndefined();
  });
  it("classifies malformed success JSON as a transport error", async () => {
    const transport = new FetchTransport({
      baseUrl: "http://test/",
      fetch: vi.fn(async () => new Response("not-json", { status: 200 })),
    });
    await expect(transport.request({ path: "x" })).rejects.toBeInstanceOf(
      SlateFsNetworkError,
    );
  });
  it("preserves unknown structured error codes", async () => {
    const transport = new FetchTransport({
      baseUrl: "http://test/",
      fetch: vi.fn(async () =>
        json(
          {
            error: {
              code: "future_error",
              message: "future",
              request_id: "r",
              details: { n: 1 },
            },
          },
          { status: 418 },
        ),
      ),
    });
    const error = (await transport
      .request({ path: "x" })
      .catch((value: unknown) => value)) as SlateFsApiError;
    expect(error).toBeInstanceOf(SlateFsApiError);
    expect(error).toMatchObject({
      code: "future_error",
      requestId: "r",
      details: { n: 1 },
    });
    expect(error.rawCode).toBe("future_error");
    expect(error.knownCode).toBeUndefined();
  });
  it("classifies aborts", async () => {
    const controller = new AbortController();
    const fetch = vi.fn(async () => {
      controller.abort();
      throw new DOMException("aborted", "AbortError");
    });
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await expect(
      transport.request({ path: "x", signal: controller.signal }),
    ).rejects.toBeInstanceOf(SlateFsAbortError);
  });
  it("streams binary responses and reports progress", async () => {
    const progress = vi.fn();
    const fetch = vi.fn(
      async () =>
        new Response(new Uint8Array([1, 2, 3]), {
          headers: {
            "content-length": "3",
            "content-type": "application/octet-stream",
          },
        }),
    );
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    const response = await transport.request({
      path: "x",
      response: "stream",
      onDownloadProgress: progress,
    });
    expect(
      Array.from(
        new Uint8Array(await new Response(response.body).arrayBuffer()),
      ),
    ).toEqual([1, 2, 3]);
    expect(progress).toHaveBeenLastCalledWith({
      transferredBytes: 3,
      totalBytes: 3,
    });
  });
  it("keeps Blob uploads native and reports deterministic progress", async () => {
    const progress = vi.fn();
    const body = new Blob(["hello"]);
    const fetch = vi.fn(async (_url: URL, init: RequestInit) => {
      expect(init.body).toBe(body);
      expect("duplex" in init).toBe(false);
      return json({ ok: true });
    });
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await transport.request({
      method: "PUT",
      path: "x",
      body,
      onUploadProgress: progress,
    });
    expect(progress.mock.calls).toEqual([
      [{ transferredBytes: 0, totalBytes: 5 }],
      [{ transferredBytes: 5, totalBytes: 5 }],
    ]);
  });
  it("does not report Blob completion when fetch fails", async () => {
    const progress = vi.fn();
    const fetch = vi.fn(async () => {
      throw new TypeError("network failure");
    });
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await expect(
      transport.request({
        method: "PUT",
        path: "x",
        body: new Blob(["hello"]),
        onUploadProgress: progress,
      }),
    ).rejects.toBeInstanceOf(SlateFsNetworkError);
    expect(progress).toHaveBeenCalledOnce();
    expect(progress).toHaveBeenCalledWith({
      transferredBytes: 0,
      totalBytes: 5,
    });
  });
  it("does not report Blob completion when fetch is aborted", async () => {
    const progress = vi.fn();
    const controller = new AbortController();
    const fetch = vi.fn(async () => {
      controller.abort();
      throw new DOMException("aborted", "AbortError");
    });
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await expect(
      transport.request({
        method: "PUT",
        path: "x",
        body: new Blob(["hello"]),
        signal: controller.signal,
        onUploadProgress: progress,
      }),
    ).rejects.toBeInstanceOf(SlateFsAbortError);
    expect(progress).toHaveBeenCalledOnce();
    expect(progress).toHaveBeenCalledWith({
      transferredBytes: 0,
      totalBytes: 5,
    });
  });
  it("retains progress streaming for explicit ReadableStream bodies", async () => {
    const progress = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.enqueue(new Uint8Array([3]));
        controller.close();
      },
    });
    const fetch = vi.fn(async (_url: URL, init: RequestInit) => {
      expect(init.body).toBeInstanceOf(ReadableStream);
      expect(init.body).not.toBe(body);
      expect((init as RequestInit & { duplex?: string }).duplex).toBe("half");
      expect(
        Array.from(new Uint8Array(await new Response(init.body).arrayBuffer())),
      ).toEqual([1, 2, 3]);
      return json({ ok: true });
    });
    const transport = new FetchTransport({ baseUrl: "http://test/", fetch });
    await transport.request({
      method: "PUT",
      path: "x",
      body,
      onUploadProgress: progress,
    });
    expect(progress.mock.calls).toEqual([
      [{ transferredBytes: 2 }],
      [{ transferredBytes: 3 }],
    ]);
  });
});

describe("SlateFs client routing and codecs", () => {
  it("maps absolute component paths to root-relative consumer selectors", async () => {
    const requests: URL[] = [];
    const fetch = vi.fn(async (url: URL) => {
      requests.push(new URL(url));
      return json({
        ...entry,
        entries: [],
        next_page_token: null,
        view: { kind: "live" },
      });
    });
    const client = createSlateFsClient({ baseUrl: "http://test/api/", fetch });

    await client.listEntries(
      "docs",
      { path: "/" },
      { kind: "live" },
      { limit: 200 },
    );
    await client.listEntries(
      "docs",
      { path: "/folder" },
      { kind: "snapshot", ref: "snap-1" },
      { limit: 25, pageToken: "page+/=" },
    );
    await client.readContent(
      "docs",
      { path: "/folder/file.txt" },
      { kind: "version", ref: "main" },
    );

    expect(requests.map((url) => url.search)).toEqual([
      "?path=&view=live&limit=200",
      "?path=folder&view=snapshot&ref=snap-1&limit=25&page_token=page%2B%2F%3D",
      "?path=folder%2Ffile.txt&view=version&ref=main",
    ]);
  });
  it("constructs selectors, views, ranges, and encoded volume URLs", async () => {
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      expect(url.pathname).toBe("/api/consumer/v1/volumes/my.volume/content");
      expect(url.searchParams.get("entry_id")).toBe("opaque");
      expect(url.searchParams.get("view")).toBe("version");
      expect(url.searchParams.get("ref")).toBe("abc");
      expect(new Headers(init.headers).get("range")).toBe("bytes=5-9");
      return new Response("bytes", {
        headers: { etag: "tag", "x-slatefs-resolved-commit": "abc" },
      });
    });
    const client = createSlateFsClient({
      baseUrl: "http://test/api/",
      fetch: fetch as unknown as typeof globalThis.fetch,
    });
    const result = await client.readContent(
      "my.volume",
      { entryId: "opaque" },
      { kind: "version", ref: "main", resolved_commit: "abc" },
      { range: { start: 5, end: 9 } },
    );
    expect(result.resolvedCommit).toBe("abc");
  });
  it("rejects ambiguous selectors and unsafe identifiers before fetch", () => {
    const fetch = vi.fn();
    const client = createSlateFsClient({ baseUrl: "http://test/api/", fetch });
    expect(() =>
      client.listEntries("../other", { path: "/" }, { kind: "live" }),
    ).toThrow("Invalid volume");
    expect(() =>
      client.listEntries("docs", { path: "/", entryId: "x" }, { kind: "live" }),
    ).toThrow("Exactly one");
    expect(fetch).not.toHaveBeenCalled();
  });
  it("injects idempotency and CSRF into filesystem mutations", async () => {
    const fetch = vi.fn(async (_url: URL, init: RequestInit) => {
      const headers = new Headers(init.headers);
      expect(headers.get("idempotency-key")).toBe("op-1");
      expect(headers.get("x-csrf-token")).toBe("csrf");
      return json({ ...entry });
    });
    const client = createSlateFsClient({
      baseUrl: "http://test/api/",
      fetch: fetch as unknown as typeof globalThis.fetch,
      getCsrfToken: () => "csrf",
    });
    await client.createEntry(
      "docs",
      { parent_entry_id: "p", name: "x", kind: "file" },
      { idempotencyKey: "op-1" },
    );
  });
  it("forwards the selected entry ETag when deleting", async () => {
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      expect(url.searchParams.get("entry_id")).toBe("opaque-entry");
      expect(url.searchParams.get("recursive")).toBe("false");
      expect(new Headers(init.headers).get("if-match")).toBe('"fresh"');
      return new Response(null, { status: 204 });
    });
    const client = createSlateFsClient({ baseUrl: "http://test/api/", fetch });
    await client.deleteEntry("docs", "opaque-entry", false, {
      ifMatch: '"fresh"',
    });
  });
  it("retries only daemon-backed idempotent mutations", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ error: { code: "busy" } }, { status: 503 }))
      .mockResolvedValueOnce(json({ commit: { id: "c" } }));
    const client = createSlateFsClient({
      baseUrl: "http://test/api/",
      fetch,
      retry: { baseDelayMs: 0, jitter: false },
    });
    await expect(
      client.commit(
        "docs",
        { branch: "main", paths: ["/x"], message: "m" },
        { idempotencyKey: "commit-1" },
      ),
    ).resolves.toMatchObject({ commit: { id: "c" } });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({
      idempotency_key: "commit-1",
    });

    fetch.mockClear();
    fetch.mockResolvedValue(json({ error: { code: "busy" } }, { status: 503 }));
    await expect(
      client.createEntry(
        "docs",
        { parent_entry_id: "p", name: "x", kind: "file" },
        { idempotencyKey: "unsupported" },
      ),
    ).rejects.toBeInstanceOf(SlateFsApiError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("never retries merge apply because the daemon has no replay contract", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(json({ error: { code: "busy" } }, { status: 503 }));
    const client = createSlateFsClient({
      baseUrl: "http://test/api/",
      fetch,
      retry: { baseDelayMs: 0, jitter: false },
    });
    await expect(
      client.applyMerge(
        "docs",
        { target: "main", source: "feature" },
        { idempotencyKey: "must-not-enable-retry" },
      ),
    ).rejects.toBeInstanceOf(SlateFsApiError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("maps the compatibility branch source to the daemon commit field", async () => {
    const fetch = vi.fn(async (_url: URL, init: RequestInit) => {
      expect(JSON.parse(String(init.body))).toEqual({
        name: "release",
        commit: "abc",
      });
      return json({ branch: { name: "release", commit: "abc" } });
    });
    const client = createSlateFsClient({ baseUrl: "http://test/api/", fetch });
    await client.createBranch("docs", { name: "release", from: "abc" });
  });
  it("preserves the top-level version diff page contract", async () => {
    const fetch = vi.fn(async (url: URL) => {
      expect(url.pathname).toBe("/api/v1/volumes/docs/versioning/diff");
      expect(url.searchParams.get("from")).toBe("commit-1");
      expect(url.searchParams.get("to")).toBe("commit-2");
      expect(url.searchParams.get("limit")).toBe("250");
      expect(url.searchParams.get("page_token")).toBe("/previous.txt");
      return json({
        changes: [{ path: "/changed.txt", change: "modified" }],
        next_page_token: "/changed.txt",
        resolved_from: "commit-1",
        resolved_to: "commit-2",
      });
    });
    const client = createSlateFsClient({ baseUrl: "http://test/api/", fetch });

    await expect(
      client.getDiff("docs", "commit-1", "commit-2", {
        limit: 250,
        pageToken: "/previous.txt",
      }),
    ).resolves.toEqual({
      changes: [{ path: "/changed.txt", change: "modified" }],
      next_page_token: "/changed.txt",
      resolved_from: "commit-1",
      resolved_to: "commit-2",
    });
  });
  it("adapts branch wrappers to the advertised protection shape", async () => {
    const policy = {
      protected: true,
      allowed_committers: ["Alice"],
      allowed_managers: ["Alice"],
      trusted_attestation_keys: [],
      required_attestations: 0,
    };
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        json({ branches: [{ name: "main", commit: "abc", ...policy }] }),
      )
      .mockResolvedValueOnce(
        json({ branch: { name: "main", commit: "abc", ...policy } }),
      );
    const client = createSlateFsClient({ baseUrl: "http://test/api/", fetch });

    await expect(client.getProtection("docs", "main")).resolves.toEqual({
      protection: policy,
    });
    await expect(
      client.setProtection("docs", "main", { protected: true }),
    ).resolves.toEqual({ protection: policy });
  });
  it("round-trips the largest u64 losslessly", () => {
    const value = 18_446_744_073_709_551_615n;
    expect(decodeU64(encodeU64(value))).toBe(value);
    expect(() => decodeU64(Number.MAX_SAFE_INTEGER + 1)).toThrow("lossless");
  });
});
