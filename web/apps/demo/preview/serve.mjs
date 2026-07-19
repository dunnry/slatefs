// Mock API + static server for screenshotting the REAL built demo app.
// Serves apps/demo/dist and answers the demo-server's API surface with
// canned data. Usage: node preview/serve.mjs
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath, URL } from "node:url";

const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const PORT = 4199;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

const session = {
  authenticated: true,
  user: { username: "alice", displayName: "Alice" },
  expiresAt: new Date(Date.now() + 1_800_000).toISOString(),
  csrfToken: "mock-csrf",
  capabilities: {
    snapshots: true,
    versions: true,
    collaboration: true,
    repository: true,
  },
};

const entries = (dir) => ({
  entry: {
    entry_id: "dir_root",
    name: dir === "/" ? "" : dir.split("/").pop(),
    path: dir,
    kind: "directory",
    size: 0,
    link_count: 1,
    modified_at: "2026-07-15T16:00:00Z",
  },
  entries: [
    {
      entry_id: "d_contracts",
      name: "Contracts",
      kind: "directory",
      size: 0,
      link_count: 1,
      modified_at: "2026-07-14T14:41:00Z",
    },
    {
      entry_id: "d_design",
      name: "Design",
      kind: "directory",
      size: 0,
      link_count: 1,
      modified_at: "2026-07-12T09:15:00Z",
    },
    {
      entry_id: "f_roadmap",
      name: "Q3 roadmap.md",
      kind: "file",
      size: 24576,
      link_count: 1,
      modified_at: "2026-07-15T16:03:00Z",
      content_type: "text/markdown",
    },
    {
      entry_id: "f_brand",
      name: "brand-guidelines.pdf",
      kind: "file",
      size: 2516582,
      link_count: 1,
      modified_at: "2026-07-11T11:20:00Z",
      content_type: "application/pdf",
    },
    {
      entry_id: "f_launch",
      name: "launch-plan.docx",
      kind: "file",
      size: 184320,
      link_count: 1,
      modified_at: "2026-07-10T17:47:00Z",
      content_type: "application/octet-stream",
    },
    {
      entry_id: "f_hero",
      name: "hero-render.png",
      kind: "file",
      size: 4300800,
      link_count: 1,
      modified_at: "2026-07-08T15:30:00Z",
      content_type: "image/png",
    },
  ],
  next_page_token: null,
  view: { kind: "live" },
});

const volumes = {
  volumes: [
    {
      name: "acme-demo-documents",
      kind: "local",
      browsable: true,
      readonly: false,
      quota: { used_bytes: 1288490189, limit_bytes: 5368709120 },
    },
    {
      name: "acme-archive",
      kind: "s3",
      browsable: true,
      readonly: true,
      quota: { used_bytes: 42949672960, limit_bytes: null },
    },
  ],
  next_page_token: null,
};

const json = (res, value, status = 200) => {
  const body = JSON.stringify(value);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");

  // --- API surface -----------------------------------------------------
  if (url.pathname === "/api/v1/session") return json(res, session);
  if (url.pathname === "/api/v1/login" && req.method === "POST")
    return json(res, session);
  if (url.pathname === "/api/v1/logout" && req.method === "POST")
    return json(res, { authenticated: false, csrfToken: "mock" });
  if (url.pathname === "/api/consumer/v1/capabilities")
    return json(res, {
      features: {
        historical_snapshots: true,
        historical_versions: true,
        xattrs: true,
        symlinks: true,
      },
    });
  if (url.pathname === "/api/consumer/v1/volumes") return json(res, volumes);

  const entriesMatch = url.pathname.match(
    /^\/api\/consumer\/v1\/volumes\/[^/]+\/entries$/,
  );
  if (entriesMatch)
    return json(res, entries(url.searchParams.get("path") ?? "/"));

  const overviewMatch = url.pathname.match(
    /^\/api\/v1\/volumes\/[^/]+\/versioning\/overview$/,
  );
  if (overviewMatch)
    return json(res, {
      status: {
        reference: "main",
        commit: "a1b2c3",
        root: "/",
        changes: [
          { path: "Contracts/acme-msa-2026.pdf", change: "added" },
          { path: "Q3 roadmap.md", change: "modified" },
          { path: "Design/old-logo.sketch", change: "deleted" },
        ],
      },
      commits: [
        {
          commit: "a1b2c3d4e5f6",
          message: "Snapshot before launch",
          author: "Alice",
          committed_at: "2026-07-15T16:02:00Z",
          parents: [],
        },
        {
          commit: "d4e5f6a1b2c3",
          message: "Rename contracts folder",
          author: "Alice",
          committed_at: "2026-07-14T14:40:00Z",
          parents: [],
        },
      ],
      branches: [
        {
          name: "main",
          commit: "a1b2c3d4e5f6",
          protected: true,
          allowed_committers: [],
          allowed_managers: [],
          trusted_attestation_keys: [],
          required_attestations: 0,
        },
        {
          name: "feature/launch-copy",
          commit: "789abcdef0",
          protected: false,
          allowed_committers: [],
          allowed_managers: [],
          trusted_attestation_keys: [],
          required_attestations: 0,
        },
      ],
      entries: [],
      next_page_token: null,
    });

  const policyMatch = url.pathname.match(
    /^\/api\/v1\/volumes\/[^/]+\/versioning\/policy$/,
  );
  if (policyMatch) return json(res, { versioning: { enabled: true } });

  const snapsMatch = url.pathname.match(
    /^\/api\/v1\/volumes\/[^/]+\/snapshots$/,
  );
  if (snapsMatch)
    return json(res, {
      snapshots: [
        {
          id: "snap_prelaunch",
          name: "pre-launch-2026-07-15",
          created_at: "2026-07-15T16:00:00Z",
        },
        {
          id: "snap_daily",
          name: "daily-2026-07-14",
          created_at: "2026-07-14T00:00:00Z",
        },
      ],
      next_page_token: null,
    });

  const statsMatch = url.pathname.match(
    /^\/api\/v1\/volumes\/[^/]+\/versioning\/repository\/stats$/,
  );
  if (statsMatch)
    return json(res, {
      stats: {
        objects: 1284,
        commits: 42,
        storage_bytes: 1288490189,
        last_verified: "2026-07-15T16:05:00Z",
      },
    });

  if (url.pathname.startsWith("/api/"))
    return json(
      res,
      { error: { message: "not mocked: " + url.pathname } },
      404,
    );

  // --- static files ----------------------------------------------------
  const rel = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const file = normalize(join(DIST, rel));
  if (!file.startsWith(DIST)) {
    res.writeHead(403);
    return res.end();
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, {
      "content-type": MIME[extname(file)] ?? "application/octet-stream",
    });
    res.end(body);
  } catch {
    const body = await readFile(join(DIST, "index.html"));
    res.writeHead(200, { "content-type": MIME[".html"] });
    res.end(body);
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mock slatefs demo on http://127.0.0.1:${PORT}`);
});
