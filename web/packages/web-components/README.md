# `@slatefs/web-components`

Framework-independent Lit custom elements for consumer SlateFS file, snapshot, and version workflows. The package registers exactly eleven public tags when imported.

## Install and register

```sh
pnpm add @slatefs/client @slatefs/web-components
```

```ts
import { createSlateFsClient } from "@slatefs/client";
import "@slatefs/web-components";

const client = createSlateFsClient({ baseUrl: "/api" });
const explorer = document.querySelector("slatefs-file-explorer");
Object.assign(explorer, {
  client, // property, never an attribute
  volume: "documents",
  path: "/",
  view: { kind: "live" },
});
```

Components accept narrow structural clients. A host can inject the relevant subset of `FileSystemClient`, `SnapshotClient`, `VersionClient`, `CollaborationClient`, or `RepositoryClient`; no component reads credentials, a tenant identifier, a router, or a global store. To share progress, construct `OperationController` and assign it to an explorer's `operationController`.

## Elements

| Tag                        | Responsibility                                                            |
| -------------------------- | ------------------------------------------------------------------------- |
| `slatefs-volume-picker`    | Inventory, browsability, read-only and quota                              |
| `slatefs-file-explorer`    | Paginated browse, selection, keyboard, clipboard, drag/drop and mutations |
| `slatefs-file-preview`     | Bounded safe preview and ETag-aware text edit                             |
| `slatefs-file-properties`  | POSIX metadata, links and byte-safe xattrs                                |
| `slatefs-snapshot-manager` | List/create/browse/clone snapshots                                        |
| `slatefs-version-status`   | Enable policy, status and explicit commits                                |
| `slatefs-version-history`  | Paginated history, exact commit browsing and comparison requests          |
| `slatefs-diff-viewer`      | Bounded structured change summary                                         |
| `slatefs-branch-manager`   | Publish targets, preview-first merge/cherry-pick and reflog               |
| `slatefs-restore-dialog`   | Preview-token restore review and apply                                    |
| `slatefs-repository-tools` | Consumer-safe stats and verification                                      |

All elements share property-only `client`, `view`, and `selection`, plus `volume`, `path`, `readonly`, and `density`. Historical `{kind: "snapshot"|"version", ref}` views are always read-only in the UI. A resolved version commit should be pinned with `resolvedCommit`; components also accept the wire-compatible `resolved_commit` shape.

## Events

Events bubble through shadow DOM and are composed. Request hooks that allow host interception are cancelable.

| Event                                                                              | Typical detail                                                                                                    |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `slatefs-volume-change`                                                            | `{ volume }`                                                                                                      |
| `slatefs-path-change`                                                              | `{ volume, path, entryId? }`                                                                                      |
| `slatefs-selection-change`                                                         | `{ selection: Entry[] }`                                                                                          |
| `slatefs-view-change`                                                              | `{ view }`                                                                                                        |
| `slatefs-entry-open`, `slatefs-preview-request`                                    | Selected entry and view                                                                                           |
| `slatefs-download-request`                                                         | Cancelable `{ version, entry, view }`; host starts a streamed save                                                |
| `slatefs-recursive-delete-request`                                                 | Cancelable `{ version, volume, entries, reason }`; host supplies a bounded preview until the server contracts one |
| `slatefs-before-operation`                                                         | Cancelable versioned operation request                                                                            |
| `slatefs-operation-start`, `slatefs-operation-complete`, `slatefs-operation-error` | Operation, entry IDs and request/error metadata                                                                   |
| `slatefs-conflict`                                                                 | Stale ETag, merge, or collision context                                                                           |
| `slatefs-auth-required`                                                            | Request ID when available                                                                                         |
| `slatefs-version-commit`, `slatefs-commit-select`, `slatefs-compare-request`       | Version orchestration details                                                                                     |

## Styling and slots

Theme tokens include `--slatefs-color-text`, `--slatefs-color-surface`, `--slatefs-color-border`, `--slatefs-color-muted`, `--slatefs-color-accent`, `--slatefs-color-readonly`, `--slatefs-font-family`, `--slatefs-font-size`, `--slatefs-radius`, and `--slatefs-focus-ring`. Useful parts include `inspector`, `toolbar`, `breadcrumb`, `row`, `loading`, `empty`, `error`, `readonly-banner`, `preview`, `editor`, `metadata`, `xattrs`, `snapshot-row`, `commit-row`, `diff`, `branch-row`, `reflog`, `stats`, and `verify`. Explorer exposes an `actions` slot; preview exposes `fallback`; loading/empty surfaces use the `empty` slot.

```css
slatefs-file-explorer::part(toolbar) {
  background: #f3f8f6;
}
slatefs-file-explorer::part(row) {
  min-height: 44px;
}
```

## Framework hosts

Set object values as DOM properties after mount in React, Vue, Svelte, Angular, or plain HTML. Listen with `addEventListener` when a framework does not map custom event names. Avoid serializing `client`, `view`, `selection`, `entry`, or controllers into attributes. See `web/examples/vanilla` for a complete host-owned mock client and event bridge.

## Capability behavior

Missing methods render an unsupported explanation rather than assuming a demo BFF. Mutations are disabled in historical views and for entry permissions. Reads are aborted on navigation/disconnect, late responses are ignored, preview bodies are bounded, and object URLs are revoked. Current historical file browsing, durable operation polling/server-side cancellation, recursive-delete preview, and full patch content remain gated until those server contracts are exposed. In-flight uploads and client requests are locally abortable.
