# SlateFS demo server

Loopback-only same-origin BFF for the consumer demo. It owns tenant credentials and the browser receives only an opaque `HttpOnly`, `SameSite=Strict` session cookie plus an in-memory CSRF token.

```sh
cp .env.example .env # export values with your preferred environment loader
pnpm --dir web --filter @slatefs/demo-server dev
```

For the production entrypoint, build the demo and server, then run `pnpm --dir web --filter @slatefs/demo-server start`. The server serves `../demo/dist` by default; override `SLATEFS_DEMO_STATIC_DIR` when starting elsewhere. Both tenant token sources are required at startup.

The browser uses `GET /api/v1/session`, `POST /api/v1/login`, and `POST /api/v1/logout`. Consumer traffic is under `/api/consumer/v1`; typed snapshot/version routes are under `/api/v1/volumes/:volume`. Unsafe requests require `X-CSRF-Token`, an explicit matching Origin, and an allowed Host. The facade never accepts a tenant identifier.

Snapshot create/clone and merge are not automatically retried because their upstream operations are not replay-safe. Bundle import/export, native sync, retention mutation, GC, purge, leases, exports, fleet, nodes, and arbitrary admin paths are deliberately absent.

Upload/download success bodies are piped as streams with backpressure; file bodies are never collected. Fetch streaming progress is available in modern browsers. Environments without streaming request bodies still support `Blob` upload through native fetch, but precise upload progress is platform-dependent; hosts needing legacy progress may provide an XHR-backed transport.

Seed/reset remains an integration-phase gap: this server does not safely own a filesystem store and therefore does not attempt to seed through a second writer. Use the existing daemon/CLI to provision `acme/documents`, `acme/documents-mirror`, and `globex/media`, then verify isolation through the BFF.
