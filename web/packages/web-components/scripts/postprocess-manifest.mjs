import { readFile, writeFile } from "node:fs/promises";
import { URL } from "node:url";

const path = new URL("../custom-elements.json", import.meta.url);
const manifest = JSON.parse(await readFile(path, "utf8"));
const tags = [
  "slatefs-volume-picker",
  "slatefs-file-explorer",
  "slatefs-file-preview",
  "slatefs-file-properties",
  "slatefs-snapshot-manager",
  "slatefs-version-status",
  "slatefs-version-history",
  "slatefs-diff-viewer",
  "slatefs-branch-manager",
  "slatefs-restore-dialog",
  "slatefs-repository-tools",
];
const commonParts = [
  "inspector",
  "toolbar",
  "loading",
  "empty",
  "error",
  "unsupported",
];
const cssProperties = [
  "--slatefs-color-text",
  "--slatefs-color-surface",
  "--slatefs-color-border",
  "--slatefs-color-muted",
  "--slatefs-color-accent",
  "--slatefs-color-readonly",
  "--slatefs-font-family",
  "--slatefs-font-size",
  "--slatefs-radius",
  "--slatefs-focus-ring",
].map((name) => ({ name }));
const eventTypes = {
  "slatefs-auth-required": "{ version: 1; requestId?: string }",
  "slatefs-volume-change": "{ version: 1; volume: string }",
  "slatefs-path-change":
    "{ version: 1; volume: string; path: string; entryId?: string }",
  "slatefs-selection-change": "{ version: 1; selection: Entry[] }",
  "slatefs-view-change": "{ version: 1; view: ViewSelection }",
  "slatefs-entry-open": "{ version: 1; entry: Entry; view: ViewSelection }",
  "slatefs-preview-request":
    "{ version: 1; entry: Entry; view: ViewSelection }",
  "slatefs-before-operation":
    "{ version: 1; operation: string; entryIds: string[] }",
  "slatefs-operation-start":
    "{ version: 1; operation: string; entryIds: string[] }",
  "slatefs-operation-complete":
    "{ version: 1; operation: string; entryIds: string[] }",
  "slatefs-operation-error":
    "{ version: 1; operation: string; entryIds: string[]; code: string; message: string; requestId?: string }",
  "slatefs-conflict":
    "{ version: 1; operation?: string; entry?: Entry; message: string }",
  "slatefs-upload-progress":
    "{ version: 1; file: string; transferredBytes: number; totalBytes?: number }",
  "slatefs-recursive-delete-request":
    "{ version: 1; volume: string; entries: Entry[]; reason: string }",
  "slatefs-save-complete": "{ version: 1; entry: Entry }",
  "slatefs-download-request":
    "{ version: 1; entry: Entry; view: ViewSelection }",
  "slatefs-edit-dirty": "{ version: 1; entry?: Entry; dirty: boolean }",
  "slatefs-properties-change": "{ version: 1; entry: Entry }",
  "slatefs-version-commit": "{ version: 1; commit: VersionCommit }",
  "slatefs-commit-select": "{ version: 1; commit: string }",
  "slatefs-reflog-request": "{ version: 1; reference: string }",
  "slatefs-compare-request": "{ version: 1; from: string; to: string }",
  "slatefs-publish-target-change": "{ version: 1; branch: string }",
  "slatefs-restore-preview":
    "{ version: 1; preview: RestorePreviewResponse['preview'] }",
  "slatefs-restore-complete": "{ version: 1; restored: unknown }",
};
const metadata = {
  SlateFsVolumePicker: {
    events: ["slatefs-volume-change"],
    parts: ["select", "option", "quota", "kind-badge"],
  },
  SlateFsFileExplorer: {
    events: [
      "slatefs-path-change",
      "slatefs-selection-change",
      "slatefs-entry-open",
      "slatefs-preview-request",
      "slatefs-before-operation",
      "slatefs-operation-start",
      "slatefs-operation-complete",
      "slatefs-operation-error",
      "slatefs-conflict",
      "slatefs-upload-progress",
      "slatefs-recursive-delete-request",
    ],
    slots: ["actions", "empty"],
    parts: [
      "readonly-banner",
      "breadcrumb",
      "details-grid",
      "row",
      "pagination",
    ],
  },
  SlateFsFilePreview: {
    events: [
      "slatefs-save-complete",
      "slatefs-conflict",
      "slatefs-operation-error",
      "slatefs-download-request",
      "slatefs-edit-dirty",
    ],
    slots: ["fallback", "empty"],
    parts: ["readonly-banner", "preview", "editor", "text", "image", "media"],
  },
  SlateFsMetadataPanel: {
    events: [
      "slatefs-before-operation",
      "slatefs-properties-change",
      "slatefs-conflict",
      "slatefs-operation-error",
    ],
    slots: ["empty"],
    parts: ["metadata", "symlink", "xattrs", "xattr-row"],
  },
  SlateFsSnapshotBrowser: {
    events: [
      "slatefs-operation-complete",
      "slatefs-view-change",
      "slatefs-volume-change",
    ],
    slots: ["empty"],
    parts: ["snapshot-list", "snapshot-row"],
  },
  SlateFsVersionStatus: {
    events: ["slatefs-version-commit", "slatefs-operation-error"],
    slots: ["empty"],
    parts: ["change-row"],
  },
  SlateFsVersionHistory: {
    events: [
      "slatefs-commit-select",
      "slatefs-view-change",
      "slatefs-reflog-request",
      "slatefs-compare-request",
    ],
    slots: ["empty"],
    parts: ["history", "commit-row", "parents", "commit-detail"],
  },
  SlateFsVersionDiff: {
    events: ["slatefs-path-change", "slatefs-operation-error"],
    slots: ["empty"],
    parts: ["truncation", "diff", "addition", "deletion", "line"],
  },
  SlateFsBranchManager: {
    events: [
      "slatefs-before-operation",
      "slatefs-publish-target-change",
      "slatefs-view-change",
      "slatefs-conflict",
      "slatefs-operation-error",
    ],
    slots: ["empty"],
    parts: ["branch-list", "branch-row", "preview", "reflog", "protection"],
  },
  SlateFsRestoreDialog: {
    events: [
      "slatefs-before-operation",
      "slatefs-restore-preview",
      "slatefs-restore-complete",
      "slatefs-operation-error",
    ],
    slots: ["empty"],
    parts: ["dialog", "warning", "summary", "action-list"],
  },
  SlateFsRepositoryTools: {
    events: ["slatefs-operation-error"],
    slots: ["empty"],
    parts: ["stats", "verify", "trust"],
  },
};
for (const module of manifest.modules) {
  module.declarations = (module.declarations ?? []).filter(
    (declaration) => declaration.name !== "SlateFsElement",
  );
  module.exports = (module.exports ?? []).filter(
    (entry) => entry.name !== "SlateFsElement" && entry.name !== "tag",
  );
  for (const declaration of module.declarations ?? []) {
    const value = metadata[declaration.name];
    if (!value) continue;
    declaration.events = [
      ...new Set([
        "slatefs-auth-required",
        "slatefs-operation-error",
        ...value.events,
      ]),
    ].map((name) => ({
      name,
      type: { text: `CustomEvent<${eventTypes[name] ?? "{ version: 1 }"}>` },
      ...(name === "slatefs-before-operation" ||
      name === "slatefs-recursive-delete-request" ||
      name === "slatefs-download-request"
        ? { description: "Bubbles, is composed, and is cancelable." }
        : { description: "Bubbles and is composed." }),
    }));
    declaration.slots = (value.slots ?? []).map((name) => ({ name }));
    declaration.cssParts = [...commonParts, ...(value.parts ?? [])].map(
      (name) => ({ name }),
    );
    declaration.cssProperties = cssProperties;
    declaration.members = (declaration.members ?? []).filter(
      (member) =>
        member.privacy !== "private" &&
        member.privacy !== "protected" &&
        member.name !== "componentLabel",
    );
  }
}
for (const module of manifest.modules) {
  module.declarations = (module.declarations ?? []).filter(
    (declaration) => metadata[declaration.name],
  );
  module.exports = (module.exports ?? []).filter(
    (entry) => entry.kind === "custom-element-definition",
  );
}
manifest.modules = manifest.modules.filter(
  (module) =>
    (module.declarations?.length ?? 0) > 0 || (module.exports?.length ?? 0) > 0,
);
const definitions = manifest.modules
  .flatMap((module) => module.exports ?? [])
  .filter((entry) => entry.kind === "custom-element-definition")
  .map((entry) => entry.name);
if (JSON.stringify(definitions) !== JSON.stringify(tags))
  throw new Error(`Unexpected public tag set: ${definitions.join(", ")}`);
await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
