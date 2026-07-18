import type {
  Entry,
  FileSystemClient,
  SnapshotClient,
  ViewSelection,
} from "@slatefs/client";
import "@slatefs/web-components";
import type {
  SlateFsFileExplorer,
  SlateFsSnapshotManager,
} from "@slatefs/web-components";

const now = new Date().toISOString();
const directory: Entry = {
  entry_id: "root",
  parent_entry_id: null,
  path: "/",
  name: null,
  name_bytes_base64: "",
  kind: "directory",
  inode: 1,
  generation: 1,
  size: 0,
  allocated_bytes: 0,
  mode: 493,
  uid: 1000,
  gid: 1000,
  link_count: 2,
  created_at: now,
  modified_at: now,
  changed_at: now,
  accessed_at: now,
  readonly: false,
  can_read: true,
  can_write: true,
  can_delete: false,
  can_rename: false,
  etag: '"root"',
  symlink_target: null,
};
const entry = (
  id: string,
  name: string,
  kind: Entry["kind"],
  size: number,
): Entry => ({
  ...directory,
  entry_id: id,
  parent_entry_id: "root",
  path: `/${name}`,
  name,
  name_bytes_base64: btoa(name),
  kind,
  size,
  allocated_bytes: size,
  link_count: 1,
  can_delete: true,
  can_rename: true,
  etag: `"${id}"`,
});
let entries = [
  entry("docs", "Projects", "directory", 0),
  entry("readme", "Welcome.txt", "file", 384),
  entry("link", "Latest report", "symlink", 0),
];
const mock: Pick<
  FileSystemClient,
  | "listEntries"
  | "createEntry"
  | "updateEntry"
  | "deleteEntry"
  | "startOperation"
  | "uploadContent"
  | "getCapabilities"
> &
  SnapshotClient = {
  async getCapabilities() {
    return {
      api_version: "consumer/v1",
      limits: {
        max_page_size: 200,
        max_range_bytes: 1048576,
        max_recursive_entries: 1000,
        max_recursive_bytes: 10485760,
        max_text_edit_bytes: 1048576,
        max_diff_bytes: 1048576,
        max_diff_lines: 5000,
      },
      features: {
        historical_snapshots: false,
        historical_versions: false,
        hardlinks: true,
        symlinks: true,
        xattrs: true,
      },
    };
  },
  async listEntries(_volume, _selector, view: ViewSelection) {
    return { view, entry: directory, entries, next_page_token: null };
  },
  async createEntry(_volume, r) {
    const e = entry(crypto.randomUUID(), r.name, r.kind, 0);
    entries = [...entries, e];
    return e;
  },
  async updateEntry(_volume, r) {
    const old = entries.find((e) => e.entry_id === r.entry_id)!;
    const e = { ...old, name: r.name ?? old.name, mode: r.mode ?? old.mode };
    entries = entries.map((x) => (x.entry_id === e.entry_id ? e : x));
    return e;
  },
  async deleteEntry(_volume, id) {
    entries = entries.filter((e) => e.entry_id !== id);
  },
  async startOperation() {
    return {
      operation_id: crypto.randomUUID(),
      preview: false,
      total_entries: 1,
      total_bytes: 0,
      completed_entries: 1,
      failed_entries: 0,
    };
  },
  async uploadContent(_v, target, body) {
    const name = "parentEntryId" in target ? target.name : "Upload.bin";
    return entry(
      crypto.randomUUID(),
      name,
      "file",
      body instanceof Blob ? body.size : 0,
    );
  },
  async listSnapshots() {
    return {
      snapshots: [
        { id: "snap-2026-07-15", name: "Before launch", created_at: now },
      ],
      next_page_token: null,
    };
  },
  async createSnapshot(_v, name) {
    return { snapshot: { id: crypto.randomUUID(), name } };
  },
  async cloneSnapshot(v, id, newVolume) {
    return {
      clone: {
        tenant: "host-owned",
        volume: newVolume,
        source_volume: v,
        snapshot_id: id,
      },
    };
  },
};
const explorer = document.querySelector<SlateFsFileExplorer>("#explorer")!;
const snapshots = document.querySelector<SlateFsSnapshotManager>("#snapshots")!;
Object.assign(explorer, {
  client: mock,
  view: { kind: "live" },
  volume: "documents",
});
Object.assign(snapshots, {
  client: mock,
  view: { kind: "live" },
  volume: "documents",
});
document.addEventListener("slatefs-selection-change", (e) => {
  document.querySelector("#events")!.textContent =
    `Selected ${(e as CustomEvent<{ selection: Entry[] }>).detail.selection.map((x) => x.name).join(", ") || "nothing"}`;
});
document.addEventListener("slatefs-view-change", (e) => {
  document.querySelector("#events")!.textContent =
    `Host received view request: ${(e as CustomEvent<{ view: ViewSelection }>).detail.view.kind}. Historical reads are disabled by this mock capability.`;
});
