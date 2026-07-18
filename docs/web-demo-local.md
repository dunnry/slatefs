# Local consumer demo seed and reset

The local harness runs exactly one `slatefsd` process. That daemon is the only
writable `Volume` opener for the two demo volumes. The seed script performs all
served-volume file mutations, snapshots, and version operations through the
daemon's loopback consumer/admin HTTP APIs; it never opens the object store.

Prerequisites: Rust/Cargo, Node.js 22 or newer, curl, jq, OpenSSL, and `timeout`
(GNU coreutils on macOS). The launcher uses a global `pnpm` when available. If
there is no global `pnpm`, it calls `corepack pnpm` directly from the web
workspace, which activates the exact version in `web/package.json` without
enabling global Corepack shims. If neither provider works, the launcher prints
the exact `npm` or Corepack commands needed to install/activate that checked-in
version. Ports 9400,
9410, and 4174 must be free. Override them with
`SLATEFS_DEMO_ADMIN_PORT`, `SLATEFS_DEMO_CONSUMER_PORT`, and
`SLATEFS_DEMO_PORT`. `SLATEFS_DEMO_WORKDIR` defaults to
`/tmp/slatefs-web-demo` and must be a demo-only directory.

```sh
scripts/web-demo.sh up
scripts/web-demo.sh dry-run
scripts/web-demo.sh seed
scripts/web-demo.sh smoke
scripts/web-demo.sh status
scripts/web-demo.sh down
```

`up` creates only tenants `acme` and `globex` and volumes
`acme-demo-documents` and `globex-demo-documents` in the demo work directory,
then starts `slatefsd` and the compiled BFF. It generates tenant bearer tokens
in mode-0600 local files. Tokens are supplied to the BFF and seed process by
file path and are never put in browser assets.

`seed` first performs the explicit safe reset, confined by prefix checks to the
two volume names above. It deletes root children through `/consumer/v1`, deletes
their snapshots through the tenant admin API, and purges only their version
repositories. It then writes tenant-distinct files, creates a snapshot, enables
versioning, creates two commits, creates `demo-baseline` and `demo-review` tag
and branch refs, and leaves a recognizable uncommitted restore candidate.
`reset` performs only the scoped deletion. Re-running `seed` is deterministic.

`smoke` is a bounded socket-level acceptance run against the started, seeded
demo. It logs in independently as Alice and Bob and checks tenant isolation,
live upload/delete/range I/O, snapshot creation and browsing, version history,
diff and exact/symbolic historical reads, cross-view token rejection, restore
preview, branch/tag inventory, fast-forward merge, and stale merge/cherry-pick
heads. The smoke mutates demo-only state; run `seed` again afterward when a
pristine story is required.

Alice logs in as `alice` and Bob as `bob`; the local demo password is
`slatefs`. These are intentionally fixed demo identities, not bearer tokens.

For teardown, run `down`, verify `status`, and remove only the configured demo
work directory. Never point `SLATEFS_DEMO_WORKDIR` at a production or shared
SlateFS store.
