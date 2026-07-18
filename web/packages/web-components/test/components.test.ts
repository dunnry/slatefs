// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createSlateFsClient,
  type Entry,
  type ViewSelection,
} from "@slatefs/client";
import {
  OperationController,
  SlateFsFileExplorer,
  SlateFsFilePreview,
  SlateFsFileProperties,
  SlateFsSnapshotBrowser,
  SlateFsVersionStatus,
  SlateFsVersionHistory,
  SlateFsVersionDiff,
  SlateFsBranchManager,
  SlateFsRepositoryTools,
  SlateFsRestoreDialog,
  SlateFsVolumePicker,
} from "../src/index.js";
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
const now = new Date().toISOString();
const entry = (
  id: string,
  name: string,
  kind: Entry["kind"] = "file",
): Entry => ({
  entry_id: id,
  parent_entry_id: "root",
  path: `/${name}`,
  name,
  name_bytes_base64: btoa(name),
  kind,
  inode: 1,
  generation: 1,
  size: 5,
  allocated_bytes: 5,
  mode: 420,
  uid: 1,
  gid: 1,
  link_count: 1,
  created_at: now,
  modified_at: now,
  changed_at: now,
  accessed_at: now,
  readonly: false,
  can_read: true,
  can_write: true,
  can_delete: true,
  can_rename: true,
  etag: '"1"',
  symlink_target: null,
});
const root = entry("root", "", "directory");
const listing = (entries: Entry[], view: ViewSelection = { kind: "live" }) => ({
  view,
  entry: root,
  entries,
  next_page_token: null,
});
const textStream = (value: string) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(value));
      controller.close();
    },
  });
const blobText = (blob: Blob) =>
  new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(String(reader.result)));
    reader.addEventListener("error", () => reject(reader.error));
    reader.readAsText(blob);
  });
const settle = () => new Promise((resolve) => setTimeout(resolve));
const submitActionDialog = async (
  element: HTMLElement & { updateComplete: Promise<boolean> },
  values: Record<string, string> = {},
) => {
  await element.updateComplete;
  const dialog =
    element.shadowRoot!.querySelector<HTMLFormElement>("form.action-dialog")!;
  expect(dialog).toBeTruthy();
  for (const [name, value] of Object.entries(values)) {
    const input = dialog.elements.namedItem(name) as HTMLInputElement;
    input.value = value;
  }
  dialog.requestSubmit();
  await settle();
};
const cancelActionDialog = async (
  element: HTMLElement & { updateComplete: Promise<boolean> },
) => {
  await element.updateComplete;
  const dialog =
    element.shadowRoot!.querySelector<HTMLFormElement>("form.action-dialog")!;
  expect(dialog).toBeTruthy();
  [...dialog.querySelectorAll("button")]
    .find((button) => button.textContent?.trim() === "Cancel")!
    .click();
  await settle();
};
afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});
describe("public contract", () => {
  it("registers exactly the eleven planned tags", () => {
    expect(tags.every((t) => customElements.get(t))).toBe(true);
    expect(customElements.get("slatefs-metadata-panel")).toBeUndefined();
    expect(customElements.get("slatefs-operation-center")).toBeUndefined();
    expect(customElements.get("slatefs-snapshot-browser")).toBeUndefined();
    expect(customElements.get("slatefs-version-diff")).toBeUndefined();
  });
  it.each(tags)("renders an accessible %s region", async (tag) => {
    const el = document.createElement(tag) as HTMLElement & {
      updateComplete: Promise<boolean>;
    };
    document.body.append(el);
    await el.updateComplete;
    expect(el.shadowRoot?.querySelector("[aria-label]")).toBeTruthy();
  });
});
describe("loading lifecycle", () => {
  it("renders SlateFS wire timestamps and tolerates absent or invalid values", async () => {
    const entries = [
      {
        ...entry("wire", "wire.txt"),
        modified_at: "1784178488.393467000Z",
      },
      { ...entry("missing", "missing.txt"), modified_at: undefined },
      { ...entry("empty", "empty.txt"), modified_at: "" },
      { ...entry("invalid", "invalid.txt"), modified_at: "not-a-date" },
    ] as unknown as Entry[];
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: { listEntries: vi.fn().mockResolvedValue(listing(entries)) },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    await explorer.updateComplete;
    expect(
      explorer.shadowRoot?.textContent?.match(/Date unavailable/g),
    ).toHaveLength(6);
    expect(explorer.shadowRoot?.textContent).toContain("2026");
    expect(explorer.shadowRoot?.querySelector('time[datetime=""]')).toBeNull();
    const modified = [...explorer.shadowRoot!.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Modified",
    );
    expect(() => modified?.click()).not.toThrow();
    await explorer.updateComplete;
  });

  it("renders success, empty, and errors with retry", async () => {
    const picker = new SlateFsVolumePicker();
    picker.client = {
      listVolumes: vi
        .fn()
        .mockResolvedValue({ volumes: [], next_page_token: null }),
    };
    document.body.append(picker);
    await new Promise((r) => setTimeout(r));
    await picker.updateComplete;
    expect(picker.shadowRoot?.textContent).toContain("Nothing here");
    picker.client = {
      listVolumes: vi.fn().mockRejectedValue(new Error("offline")),
    };
    await picker.updateComplete;
    await new Promise((resolve) => setTimeout(resolve));
    await picker.updateComplete;
    expect(picker.shadowRoot?.textContent).toContain("offline");
  });
  it("auto-selects and preserves the only browsable volume when enabled", async () => {
    const picker = new SlateFsVolumePicker();
    picker.autoSelectSingle = true;
    const changed = vi.fn();
    picker.addEventListener("slatefs-volume-change", changed);
    picker.client = {
      listVolumes: vi.fn().mockResolvedValue({
        volumes: [
          {
            name: "docs",
            kind: "filesystem",
            browsable: true,
            readonly: false,
            quota: { used_bytes: 0, limit_bytes: null },
          },
        ],
        next_page_token: null,
      }),
    };
    document.body.append(picker);
    await settle();
    await picker.updateComplete;
    expect(picker.volume).toBe("docs");
    expect(changed).toHaveBeenCalledOnce();
    await picker.refresh();
    expect(picker.volume).toBe("docs");
    expect(changed).toHaveBeenCalledOnce();
  });
  it("aborts stale explorer loads and ignores late responses", async () => {
    const resolvers: Array<(v: ReturnType<typeof listing>) => void> = [];
    let firstSignal: AbortSignal | undefined;
    const explorer = new SlateFsFileExplorer();
    explorer.volume = "docs";
    explorer.client = {
      listEntries: vi.fn((_v, _s, _w, o) => {
        firstSignal ??= o?.signal;
        return new Promise((r) => {
          resolvers.push(r);
        });
      }),
    } as never;
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    explorer.path = "/new";
    await explorer.updateComplete;
    expect(firstSignal?.aborted).toBe(true);
    resolvers[0]!(listing([entry("late", "Late.txt")]));
    await new Promise((r) => setTimeout(r));
    expect(explorer.shadowRoot?.textContent).not.toContain("Late.txt");
  });
});
describe("explorer behavior", () => {
  it("creates, renames, and cancels forms without issuing canceled requests", async () => {
    const createEntry = vi.fn().mockResolvedValue(entry("new", "draft.txt"));
    const updateEntry = vi.fn().mockResolvedValue(entry("a", "renamed.txt"));
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      selection: ["a"],
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(listing([entry("a", "Alpha.txt")])),
        createEntry,
        updateEntry,
      },
    });
    document.body.append(explorer);
    await settle();
    const button = (label: string) =>
      [...explorer.shadowRoot!.querySelectorAll("button")].find(
        (candidate) => candidate.textContent?.trim() === label,
      )!;

    button("New file").click();
    await cancelActionDialog(explorer);
    expect(createEntry).not.toHaveBeenCalled();

    button("New folder").click();
    await submitActionDialog(explorer, { name: "Projects" });
    expect(createEntry).toHaveBeenCalledWith(
      "docs",
      { parent_entry_id: "root", name: "Projects", kind: "directory" },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );

    button("Rename").click();
    await submitActionDialog(explorer, { name: "renamed.txt" });
    expect(updateEntry).toHaveBeenCalledWith(
      "docs",
      { entry_id: "a", name: "renamed.txt" },
      expect.objectContaining({ ifMatch: '"1"' }),
    );
  });
  it("builds breadcrumbs for opaque-ID folder listings and drops IDs across views", async () => {
    const folder = { ...entry("folder", "Folder", "directory"), path: null };
    const listEntries = vi
      .fn()
      .mockResolvedValueOnce(listing([folder]))
      .mockResolvedValue(listing([], { kind: "snapshot", ref: "snap-1" }));
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      path: "/parent",
      client: {
        listEntries,
        getCapabilities: vi.fn().mockResolvedValue({
          features: { historical_snapshots: true },
        }),
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    const changed = vi.fn();
    explorer.addEventListener("slatefs-path-change", changed);

    explorer
      .shadowRoot!.querySelector<HTMLElement>("[data-index='0']")!
      .dispatchEvent(new MouseEvent("dblclick", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve));
    expect(changed).toHaveBeenCalledWith(
      expect.objectContaining({
        detail: expect.objectContaining({
          path: "/parent/Folder",
          entryId: "folder",
        }),
      }),
    );
    expect(listEntries).toHaveBeenLastCalledWith(
      "docs",
      { entryId: "folder" },
      { kind: "live" },
      expect.objectContaining({ limit: 200 }),
    );

    explorer.path = "/";
    explorer.view = { kind: "snapshot", ref: "snap-1" };
    await new Promise((resolve) => setTimeout(resolve));
    expect(listEntries).toHaveBeenLastCalledWith(
      "docs",
      { path: "/" },
      { kind: "snapshot", ref: "snap-1" },
      expect.objectContaining({ limit: 200 }),
    );
  });
  it("emits composed selection and open events from keyboard", async () => {
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(listing([entry("a", "Alpha.txt")])),
      },
    });
    document.body.append(explorer);
    await new Promise((r) => setTimeout(r));
    await explorer.updateComplete;
    const selected = vi.fn(),
      opened = vi.fn();
    document.addEventListener("slatefs-selection-change", selected);
    document.addEventListener("slatefs-entry-open", opened);
    const row =
      explorer.shadowRoot!.querySelector<HTMLElement>("[data-index='0']")!;
    row.dispatchEvent(
      new KeyboardEvent("keydown", { key: " ", bubbles: true }),
    );
    row.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
    );
    expect(selected).toHaveBeenCalledOnce();
    expect(opened).toHaveBeenCalledOnce();
  });
  it("gates mutations in historical views", async () => {
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      view: { kind: "snapshot", ref: "s1" },
      client: {
        getCapabilities: vi.fn().mockResolvedValue({
          features: { historical_snapshots: true },
        }),
        listEntries: vi
          .fn()
          .mockResolvedValue(
            listing([entry("a", "Alpha.txt")], { kind: "snapshot", ref: "s1" }),
          ),
      },
    });
    document.body.append(explorer);
    await new Promise((r) => setTimeout(r));
    await explorer.updateComplete;
    expect(explorer.shadowRoot?.textContent).toContain(
      "Historical views are read-only",
    );
    expect(
      explorer.shadowRoot?.querySelector<HTMLButtonElement>("button")?.disabled,
    ).toBe(true);
  });
  it("does not issue unsupported historical reads", async () => {
    const listEntries = vi.fn();
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      view: { kind: "version", ref: "abc" },
      client: {
        getCapabilities: vi.fn().mockResolvedValue({
          features: { historical_versions: false },
        }),
        listEntries,
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    await explorer.updateComplete;
    expect(listEntries).not.toHaveBeenCalled();
    expect(explorer.shadowRoot?.textContent).toContain(
      "This capability is not available",
    );
  });
  it("keeps a bounded DOM while allowing every loaded row to be reached", async () => {
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(
            listing(
              Array.from({ length: 900 }, (_, i) =>
                entry(String(i), `File ${i}`),
              ),
            ),
          ),
      },
    });
    document.body.append(explorer);
    await new Promise((r) => setTimeout(r));
    await explorer.updateComplete;
    expect(explorer.shadowRoot?.querySelectorAll(".entry")).toHaveLength(200);
    const next = [...explorer.shadowRoot!.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Next rows",
    )!;
    next.click();
    next.click();
    next.click();
    next.click();
    await explorer.updateComplete;
    expect(explorer.shadowRoot?.textContent).toContain("File 899");
    expect(
      explorer.shadowRoot?.querySelectorAll(".entry").length,
    ).toBeLessThanOrEqual(200);
  });
  it("translates file deletion exactly and host-mediates recursive deletion", async () => {
    const deleteEntry = vi.fn().mockResolvedValue(undefined);
    const operationController = new OperationController();
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      selection: ["a"],
      operationController,
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(listing([entry("a", "Alpha.txt")])),
        deleteEntry,
      },
    });
    document.body.append(explorer);
    await new Promise((r) => setTimeout(r));
    await explorer.updateComplete;
    const deleteButton = [
      ...explorer.shadowRoot!.querySelectorAll("button"),
    ].find((button) => button.textContent?.trim() === "Delete")!;
    deleteButton.click();
    await submitActionDialog(explorer);
    expect(deleteEntry).toHaveBeenCalledWith(
      "docs",
      "a",
      false,
      expect.objectContaining({
        ifMatch: '"1"',
        signal: expect.any(AbortSignal),
      }),
    );

    const folder = entry("d", "Folder", "directory");
    Object.assign(explorer, { selection: ["d"] });
    (
      explorer.client!.listEntries as ReturnType<typeof vi.fn>
    ).mockResolvedValue(listing([folder]));
    await explorer.refresh();
    deleteEntry.mockRejectedValueOnce(new Error("directory not empty"));
    const mediated = vi.fn((event: Event) => event.preventDefault());
    explorer.addEventListener("slatefs-recursive-delete-request", mediated);
    [...explorer.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Delete")!
      .click();
    await submitActionDialog(explorer);
    expect(mediated).toHaveBeenCalledOnce();
    expect(deleteEntry).toHaveBeenCalledTimes(2);
    expect(deleteEntry.mock.calls[1]).toEqual([
      "docs",
      "d",
      false,
      expect.objectContaining({
        ifMatch: '"1"',
        signal: expect.any(AbortSignal),
      }),
    ]);
    expect(
      operationController.operations.find(
        (operation) => operation.status === "error",
      )?.detail,
    ).toContain("Folder: directory not empty");
  });
  it("loads subsequent server pages with the exact page token", async () => {
    const listEntries = vi
      .fn()
      .mockResolvedValueOnce({
        ...listing([entry("a", "Alpha.txt")]),
        next_page_token: "page-2",
      })
      .mockResolvedValueOnce(listing([entry("b", "Beta.txt")]));
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, { volume: "docs", client: { listEntries } });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    [...explorer.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Load more")!
      .click();
    await new Promise((resolve) => setTimeout(resolve));
    expect(listEntries.mock.calls[1]![3]).toMatchObject({
      limit: 200,
      pageToken: "page-2",
      signal: expect.any(AbortSignal),
    });
    expect(explorer.shadowRoot?.textContent).toContain("Beta.txt");
  });
  it("restores filtered rows and drops stale controlled selections", async () => {
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      selection: ["a", "untrusted-url-id"],
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(
            listing([entry("a", "Alpha.txt"), entry("b", "Beta.txt")]),
          ),
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    expect(explorer.selection).toEqual(["a"]);
    const filter =
      explorer.shadowRoot!.querySelector<HTMLInputElement>(
        "input[type=search]",
      )!;
    filter.value = "Alpha";
    filter.dispatchEvent(new Event("input", { bubbles: true }));
    await explorer.updateComplete;
    expect(explorer.shadowRoot?.textContent).not.toContain("Beta.txt");
    filter.value = "";
    filter.dispatchEvent(new Event("input", { bubbles: true }));
    await explorer.updateComplete;
    expect(explorer.shadowRoot?.textContent).toContain("Beta.txt");
  });
  it("uses the reviewed operation signature for clipboard paste", async () => {
    const startOperation = vi.fn().mockResolvedValue({
      operation_id: "op-1",
      preview: false,
      total_entries: 1,
      total_bytes: 5,
      completed_entries: 1,
      failed_entries: 0,
    });
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      conflictPolicy: "fail",
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(listing([entry("a", "Alpha.txt")])),
        startOperation,
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    const row =
      explorer.shadowRoot!.querySelector<HTMLElement>("[data-index='0']")!;
    row.click();
    row.dispatchEvent(
      new KeyboardEvent("keydown", { key: "c", ctrlKey: true, bubbles: true }),
    );
    await explorer.updateComplete;
    [...explorer.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Paste")!
      .click();
    await new Promise((resolve) => setTimeout(resolve));
    expect(startOperation).toHaveBeenCalledWith(
      "docs",
      {
        operation: "copy",
        source_entry_ids: ["a"],
        destination_parent_entry_id: "root",
        conflict_policy: "fail",
        preview: false,
      },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });
  it("duplicates into the current directory with a useful default collision policy", async () => {
    const startOperation = vi.fn().mockResolvedValue({
      operation_id: "copy-1",
      preview: false,
      total_entries: 1,
      total_bytes: 5,
      completed_entries: 1,
      failed_entries: 0,
    });
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(listing([entry("a", "Alpha.txt")])),
        startOperation,
      },
    });
    document.body.append(explorer);
    await settle();
    explorer
      .shadowRoot!.querySelector<HTMLElement>("[data-index='0']")!
      .click();
    await explorer.updateComplete;
    [...explorer.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Duplicate")!
      .click();
    await vi.waitFor(() => expect(startOperation).toHaveBeenCalledOnce());
    expect(startOperation.mock.calls[0]![1]).toMatchObject({
      operation: "copy",
      source_entry_ids: ["a"],
      destination_parent_entry_id: "root",
      conflict_policy: "keep_both",
    });
  });
  it("uploads external files with progress and cancellation options", async () => {
    const uploadContent = vi.fn().mockResolvedValue(entry("u", "unsafe.html"));
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: {
        listEntries: vi.fn().mockResolvedValue(listing([])),
        uploadContent,
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    const input =
      explorer.shadowRoot!.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File(["<script>"], "unsafe.html", { type: "text/html" })],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve));
    expect(uploadContent.mock.calls[0]![1]).toEqual({
      parentEntryId: "root",
      name: "unsafe.html",
    });
    expect(uploadContent.mock.calls[0]![3]).toMatchObject({
      signal: expect.any(AbortSignal),
      onProgress: expect.any(Function),
    });
  });
  it("moves an internally dragged entry into the dropped-on directory", async () => {
    const startOperation = vi.fn().mockResolvedValue({
      operation_id: "move-1",
      preview: false,
      total_entries: 1,
      total_bytes: 5,
      completed_entries: 1,
      failed_entries: 0,
    });
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(
            listing([
              entry("a", "Alpha.txt"),
              entry("folder", "Folder", "directory"),
            ]),
          ),
        startOperation,
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    const folder = explorer.shadowRoot!.querySelector<HTMLElement>(
      "[data-entry-id='folder']",
    )!;
    const drop = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(drop, "dataTransfer", {
      value: {
        files: [],
        getData: (type: string) =>
          type === "application/x-slatefs-entry" ? "a" : "",
      },
    });
    folder.dispatchEvent(drop);
    await new Promise((resolve) => setTimeout(resolve));
    expect(startOperation.mock.calls[0]![1]).toMatchObject({
      operation: "move",
      source_entry_ids: ["a"],
      destination_parent_entry_id: "folder",
    });
  });
  it("accepts external file drops as bounded upload requests", async () => {
    const uploadContent = vi.fn().mockResolvedValue(entry("u", "drop.txt"));
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      client: {
        listEntries: vi.fn().mockResolvedValue(listing([])),
        uploadContent,
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    const drop = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(drop, "dataTransfer", {
      value: { files: [new File(["drop"], "drop.txt")] },
    });
    explorer.shadowRoot!.querySelector("section")!.dispatchEvent(drop);
    await new Promise((resolve) => setTimeout(resolve));
    expect(uploadContent).toHaveBeenCalledWith(
      "docs",
      { parentEntryId: "root", name: "drop.txt" },
      expect.any(File),
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
  });
  it("sends picker and drop uploads through the real client path with progress", async () => {
    const requests: Array<{ url: URL; init: RequestInit }> = [];
    const fetch = vi.fn(async (input: URL | RequestInfo, init: RequestInit) => {
      const url = new URL(String(input));
      requests.push({ url, init });
      if (init.method === "PUT")
        return new Response(
          JSON.stringify(
            entry(`uploaded-${requests.length}`, url.searchParams.get("name")!),
          ),
          { headers: { "content-type": "application/json" } },
        );
      return new Response(JSON.stringify(listing([])), {
        headers: { "content-type": "application/json" },
      });
    });
    const explorer = new SlateFsFileExplorer();
    const progress = vi.fn();
    explorer.addEventListener("slatefs-upload-progress", progress);
    Object.assign(explorer, {
      volume: "docs",
      client: createSlateFsClient({
        baseUrl: "http://slatefs.test/api/",
        fetch,
      }),
    });
    document.body.append(explorer);
    await settle();

    const input =
      explorer.shadowRoot!.querySelector<HTMLInputElement>("input[type=file]")!;
    const picked = new File(["picked"], "picked.txt");
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [picked],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await vi.waitFor(() =>
      expect(
        requests.filter((request) => request.init.method === "PUT"),
      ).toHaveLength(1),
    );

    const dropped = new File(["dropped"], "dropped.txt");
    const drop = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(drop, "dataTransfer", {
      value: { files: [dropped] },
    });
    explorer.shadowRoot!.querySelector("section")!.dispatchEvent(drop);
    await vi.waitFor(() =>
      expect(
        requests.filter((request) => request.init.method === "PUT"),
      ).toHaveLength(2),
    );

    const uploads = requests.filter((request) => request.init.method === "PUT");
    expect(
      uploads.map((request) => [
        request.url.pathname,
        request.url.searchParams.get("name"),
      ]),
    ).toEqual([
      ["/api/consumer/v1/volumes/docs/content", "picked.txt"],
      ["/api/consumer/v1/volumes/docs/content", "dropped.txt"],
    ]);
    expect(uploads[0]!.init.body).toBe(picked);
    expect(uploads[1]!.init.body).toBe(dropped);
    expect(
      progress.mock.calls.map(([event]) => event.detail.transferredBytes),
    ).toEqual([0, picked.size, 0, dropped.size]);
  });
  it("applies collisions and surfaces BFF client errors for uploads", async () => {
    const uploadedNames: string[] = [];
    const fetch = vi.fn(async (input: URL | RequestInfo, init: RequestInit) => {
      const url = new URL(String(input));
      if (init.method !== "PUT")
        return new Response(
          JSON.stringify(listing([entry("same", "same.txt")])),
          { headers: { "content-type": "application/json" } },
        );
      const name = url.searchParams.get("name")!;
      uploadedNames.push(name);
      if (name === "broken.txt")
        return new Response(
          JSON.stringify({
            error: { code: "conflict", message: "upstream rejected upload" },
          }),
          {
            status: 409,
            headers: { "content-type": "application/json" },
          },
        );
      return new Response(JSON.stringify(entry("copy", name)), {
        headers: { "content-type": "application/json" },
      });
    });
    const explorer = new SlateFsFileExplorer();
    const failed = vi.fn();
    explorer.addEventListener("slatefs-operation-error", failed);
    Object.assign(explorer, {
      volume: "docs",
      client: createSlateFsClient({
        baseUrl: "http://slatefs.test/api/",
        fetch,
      }),
    });
    document.body.append(explorer);
    await settle();
    const input =
      explorer.shadowRoot!.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File(["copy"], "same.txt"), new File(["bad"], "broken.txt")],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await vi.waitFor(() => expect(failed).toHaveBeenCalledOnce());
    expect(uploadedNames).toEqual(["same (2).txt", "broken.txt"]);
    expect(failed.mock.calls[0]![0].detail).toMatchObject({
      operation: "upload",
      code: "conflict",
      message: "upstream rejected upload",
    });
  });
  it("requires confirmation and If-Match for upload overwrite", async () => {
    const uploadContent = vi.fn().mockResolvedValue(entry("a", "same.txt"));
    const explorer = new SlateFsFileExplorer();
    Object.assign(explorer, {
      volume: "docs",
      conflictPolicy: "overwrite",
      client: {
        listEntries: vi
          .fn()
          .mockResolvedValue(listing([entry("a", "same.txt")])),
        uploadContent,
      },
    });
    document.body.append(explorer);
    await new Promise((resolve) => setTimeout(resolve));
    const input =
      explorer.shadowRoot!.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File(["replacement"], "same.txt")],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await submitActionDialog(explorer);
    expect(uploadContent).toHaveBeenCalledWith(
      "docs",
      { entryId: "a" },
      expect.any(File),
      expect.objectContaining({ ifMatch: '"1"' }),
    );
  });
});
describe("preview and operations", () => {
  it("previews generic .txt content as text without widening binary inference", async () => {
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      entry: entry("a", "seeded.txt"),
      client: {
        readContent: vi.fn().mockResolvedValue({
          body: textStream("seeded content"),
          contentType: "application/octet-stream",
          etag: '"1"',
        }),
      },
    });
    document.body.append(preview);
    await settle();
    await preview.updateComplete;
    expect(preview.shadowRoot?.querySelector("pre")?.textContent).toBe(
      "seeded content",
    );
    expect(preview.shadowRoot?.textContent).toContain("text/plain");
  });
  it("loads bounded text and preserves ETag when saving", async () => {
    const upload = vi
      .fn()
      .mockResolvedValue({ ...entry("a", "a.txt"), etag: '"2"' });
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      editable: true,
      entry: entry("a", "a.txt"),
      client: {
        readContent: vi.fn().mockResolvedValue({
          body: textStream("hello"),
          contentType: "text/plain",
          etag: '"1"',
          requestId: "r",
        }),
        uploadContent: upload,
      },
    });
    document.body.append(preview);
    await new Promise((r) => setTimeout(r));
    await preview.updateComplete;
    const area =
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!;
    const save = [...preview.shadowRoot!.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Save",
    )!;
    expect(save.disabled).toBe(true);
    area.value = "changed";
    area.dispatchEvent(new Event("input", { bubbles: true }));
    await preview.updateComplete;
    expect(save.disabled).toBe(false);
    await preview.save();
    expect(upload.mock.calls[0]![3]).toMatchObject({ ifMatch: '"1"' });
    expect(await blobText(upload.mock.calls[0]![2] as Blob)).toBe("changed");
  });
  it("opens a known empty text file without an unsatisfiable range", async () => {
    const readContent = vi.fn();
    const saved = {
      ...entry("empty", "empty.txt"),
      size: 0,
      size_decimal: "0",
      etag: '"2"',
    };
    const uploadContent = vi.fn().mockResolvedValue(saved);
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      editable: true,
      entry: { ...saved, etag: '"1"' },
      client: { readContent, uploadContent },
    });
    document.body.append(preview);
    await settle();
    await preview.updateComplete;
    const area =
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!;
    expect(area.value).toBe("");
    expect(readContent).not.toHaveBeenCalled();
    area.value = "first contents";
    area.dispatchEvent(new InputEvent("input", { bubbles: true }));
    await preview.updateComplete;
    const save = [...preview.shadowRoot!.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Save",
    )!;
    expect(save.disabled).toBe(false);
    save.click();
    await vi.waitFor(() => expect(uploadContent).toHaveBeenCalledOnce());
    await vi.waitFor(() => expect(save.disabled).toBe(true));
    expect(await blobText(uploadContent.mock.calls[0]![2] as Blob)).toBe(
      "first contents",
    );
    expect(readContent).not.toHaveBeenCalled();
  });
  it("resets an unsaved draft when the selected entry changes", async () => {
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      editable: true,
      entry: entry("a", "a.txt"),
      client: {
        readContent: vi.fn((_volume, selected) =>
          Promise.resolve({
            body: textStream(
              (selected as { entryId: string }).entryId === "a"
                ? "alpha"
                : "bravo",
            ),
            contentType: "text/plain",
            etag: '"1"',
          }),
        ),
        uploadContent: vi.fn(),
      },
    });
    document.body.append(preview);
    await settle();
    const first =
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!;
    first.value = "unsaved";
    first.dispatchEvent(new InputEvent("input", { bubbles: true }));
    await preview.updateComplete;
    preview.entry = entry("b", "b.txt");
    await settle();
    await preview.updateComplete;
    expect(
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!.value,
    ).toBe("bravo");
    expect(
      [...preview.shadowRoot!.querySelectorAll("button")].find(
        (button) => button.textContent?.trim() === "Save",
      )!.disabled,
    ).toBe(true);
  });
  it("refuses a save when the rendered draft no longer matches the selected entry", async () => {
    const uploadContent = vi.fn();
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      editable: true,
      entry: entry("alice", "alice-only.txt"),
      client: {
        readContent: vi.fn().mockResolvedValue({
          body: textStream("alice"),
          contentType: "text/plain",
          etag: '"alice-1"',
        }),
        uploadContent,
      },
    });
    document.body.append(preview);
    await settle();
    const area =
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!;
    area.value = "edited alice";
    area.dispatchEvent(new InputEvent("input", { bubbles: true }));
    await preview.updateComplete;

    // A host selection can change before Lit replaces the still-visible Save
    // button. Saving that stale rendered draft must never target the new entry.
    preview.entry = entry("versioned", "versioned.txt");
    await preview.save();
    expect(uploadContent).not.toHaveBeenCalled();
  });
  it("ignores a late preview response after selection clears", async () => {
    let resolveRead!: (value: {
      body: ReadableStream<Uint8Array>;
      contentType: string;
      etag: string;
    }) => void;
    const readContent = vi.fn(
      () =>
        new Promise((resolve) => {
          resolveRead = resolve;
        }),
    );
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      entry: entry("a", "a.txt"),
      client: { readContent, uploadContent: vi.fn() },
    });
    document.body.append(preview);
    await settle();
    preview.entry = undefined;
    await preview.updateComplete;
    await settle();
    resolveRead({
      body: textStream("obsolete"),
      contentType: "text/plain",
      etag: '"1"',
    });
    await settle();
    expect(readContent).toHaveBeenCalledWith(
      "docs",
      { entryId: "a" },
      { kind: "live" },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(preview.shadowRoot?.textContent).toContain("Nothing here yet");
    expect(preview.shadowRoot?.textContent).toContain("No selection");
    expect(preview.shadowRoot?.textContent).not.toContain("text/plain");
    expect(preview.shadowRoot?.textContent).not.toContain("obsolete");
    expect(preview.shadowRoot?.querySelector('[part="error"]')).toBeNull();
  });
  it("keeps an editable draft available when save fails", async () => {
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      editable: true,
      entry: entry("a", "a.txt"),
      client: {
        readContent: vi.fn().mockResolvedValue({
          body: textStream("hello"),
          contentType: "text/plain",
          etag: '"1"',
        }),
        uploadContent: vi.fn().mockRejectedValue(new Error("disk full")),
      },
    });
    document.body.append(preview);
    await settle();
    const area =
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!;
    area.value = "keep this draft";
    area.dispatchEvent(new InputEvent("input", { bubbles: true }));
    await preview.updateComplete;
    await preview.save();
    await preview.updateComplete;
    expect(
      preview.shadowRoot?.querySelector('[part="save-error"]')?.textContent,
    ).toContain("disk full");
    expect(
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!.value,
    ).toBe("keep this draft");
    expect(
      [...preview.shadowRoot!.querySelectorAll("button")].find(
        (button) => button.textContent?.trim() === "Save",
      )!.disabled,
    ).toBe(false);
  });
  it("emits a conflict on stale save", async () => {
    const preview = new SlateFsFilePreview();
    Object.assign(preview, {
      volume: "docs",
      editable: true,
      entry: entry("a", "a.txt"),
      client: {
        readContent: vi.fn().mockResolvedValue({
          body: textStream("hello"),
          contentType: "text/plain",
          etag: '"1"',
          requestId: "r",
        }),
        uploadContent: vi
          .fn()
          .mockRejectedValue({ status: 412, message: "stale" }),
      },
    });
    document.body.append(preview);
    await new Promise((r) => setTimeout(r));
    const conflict = vi.fn();
    preview.addEventListener("slatefs-conflict", conflict);
    const area =
      preview.shadowRoot!.querySelector<HTMLTextAreaElement>("textarea")!;
    area.dispatchEvent(new Event("input"));
    await preview.save();
    expect(conflict).toHaveBeenCalledOnce();
  });
  it("emits a versioned, cancelable download request with copied detail", () => {
    const preview = new SlateFsFilePreview();
    preview.entry = entry("a", "safe.txt");
    let captured: CustomEvent | undefined;
    preview.addEventListener("slatefs-download-request", (event) => {
      captured = event as CustomEvent;
      event.preventDefault();
    });
    preview.download();
    expect(captured?.bubbles).toBe(true);
    expect(captured?.composed).toBe(true);
    expect(captured?.cancelable).toBe(true);
    expect(captured?.detail.version).toBe(1);
    captured!.detail.entry.name = "changed-by-host";
    expect(preview.entry.name).toBe("safe.txt");
  });
  it("supports progress, cancel, retry, dismiss, and clear", async () => {
    const controller = new OperationController();
    const cancel = vi.fn(),
      retry = vi.fn();
    const id = controller.add({
      label: "Upload",
      status: "running",
      progress: 0.5,
      cancel,
      retry,
    });
    expect(controller.operations[0]?.label).toBe("Upload");
    controller.cancel(id);
    expect(cancel).toHaveBeenCalled();
    controller.update(id, { status: "error" });
    await controller.retry(id);
    expect(retry).toHaveBeenCalled();
    controller.clearCompleted();
    expect(controller.operations).toHaveLength(0);
  });
});
describe("snapshots", () => {
  it("creates named snapshots, clones reviewed names, and cancels cleanly", async () => {
    const createSnapshot = vi
      .fn()
      .mockResolvedValue({ snapshot: { id: "s2" } });
    const cloneSnapshot = vi
      .fn()
      .mockResolvedValue({ clone: { volume: "writable-copy" } });
    const browser = new SlateFsSnapshotBrowser();
    Object.assign(browser, {
      volume: "docs",
      client: {
        listSnapshots: vi.fn().mockResolvedValue({
          snapshots: [{ id: "s1", name: "Before" }],
        }),
        createSnapshot,
        cloneSnapshot,
      },
    });
    document.body.append(browser);
    await settle();
    const before = vi.fn();
    const started = vi.fn();
    const completed = vi.fn();
    const changed = vi.fn();
    browser.addEventListener("slatefs-before-operation", before);
    browser.addEventListener("slatefs-operation-start", started);
    browser.addEventListener("slatefs-operation-complete", completed);
    browser.addEventListener("slatefs-volume-change", changed);
    const create = [...browser.shadowRoot!.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Create snapshot",
    )!;
    create.click();
    await cancelActionDialog(browser);
    expect(createSnapshot).not.toHaveBeenCalled();
    create.click();
    await submitActionDialog(browser, { name: "Release" });
    expect(createSnapshot).toHaveBeenCalledWith("docs", "Release");
    completed.mockClear();

    const clone = [...browser.shadowRoot!.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Create writable copy",
    )!;
    clone.click();
    await submitActionDialog(browser, { name: "writable-copy" });
    expect(cloneSnapshot).toHaveBeenCalledWith("docs", "s1", "writable-copy");
    const operation = {
      version: 1,
      operation: "clone-snapshot",
      entryIds: [],
    };
    expect(before).toHaveBeenCalledOnce();
    expect(before.mock.calls[0]![0].detail).toEqual(operation);
    expect(started.mock.calls[0]![0].detail).toEqual(operation);
    expect(completed.mock.calls[0]![0].detail).toEqual(operation);
    expect(changed.mock.calls[0]![0].detail).toEqual({
      version: 1,
      volume: "writable-copy",
    });
  });
  it("emits a read-only view request", async () => {
    const browser = new SlateFsSnapshotBrowser();
    Object.assign(browser, {
      volume: "docs",
      client: {
        listSnapshots: vi
          .fn()
          .mockResolvedValue({ snapshots: [{ id: "s1", name: "Before" }] }),
        createSnapshot: vi.fn(),
        cloneSnapshot: vi.fn(),
      },
    });
    document.body.append(browser);
    await new Promise((r) => setTimeout(r));
    const event = vi.fn();
    browser.addEventListener("slatefs-view-change", event);
    browser
      .shadowRoot!.querySelector<HTMLButtonElement>(
        "[part=snapshot-row] button",
      )!
      .click();
    expect(event.mock.calls[0]![0].detail.view).toEqual({
      kind: "snapshot",
      ref: "s1",
    });
  });
  it("pages snapshot results instead of rendering a placeholder", async () => {
    const listSnapshots = vi
      .fn()
      .mockResolvedValueOnce({
        snapshots: [{ id: "s1" }],
        next_page_token: "next",
      })
      .mockResolvedValueOnce({
        snapshots: [{ id: "s2" }],
        next_page_token: null,
      });
    const browser = new SlateFsSnapshotBrowser();
    Object.assign(browser, { volume: "docs", client: { listSnapshots } });
    document.body.append(browser);
    await new Promise((resolve) => setTimeout(resolve));
    [...browser.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Load more")!
      .click();
    await new Promise((resolve) => setTimeout(resolve));
    expect(listSnapshots.mock.calls[1]![1]).toMatchObject({
      pageToken: "next",
    });
    expect(browser.shadowRoot?.textContent).toContain("s2");
  });
});

describe("properties", () => {
  it("submits mode and xattr forms with exact payloads", async () => {
    const updateEntry = vi
      .fn()
      .mockResolvedValue({ ...entry("a", "a.txt"), mode: 0o640 });
    const updateXattrs = vi.fn().mockResolvedValue({
      xattrs: [{ name: "user.note", value_base64: "aGVsbG8=" }],
    });
    const panel = new SlateFsFileProperties();
    Object.assign(panel, {
      volume: "docs",
      entry: entry("a", "a.txt"),
      client: {
        getXattrs: vi.fn().mockResolvedValue({ xattrs: [] }),
        updateEntry,
        updateXattrs,
      },
    });
    document.body.append(panel);
    await settle();
    const button = (label: string) =>
      [...panel.shadowRoot!.querySelectorAll("button")].find(
        (candidate) => candidate.textContent?.trim() === label,
      )!;
    button("Edit mode").click();
    await submitActionDialog(panel, { mode: "640" });
    expect(updateEntry).toHaveBeenCalledWith(
      "docs",
      { entry_id: "a", mode: 0o640 },
      { ifMatch: '"1"' },
    );
    button("Add or replace attribute").click();
    await submitActionDialog(panel, { name: "user.note", value: "hello" });
    expect(updateXattrs).toHaveBeenCalledWith(
      "docs",
      "a",
      { set: { "user.note": "aGVsbG8=" } },
      { ifMatch: '"1"' },
    );
  });
  it("aborts an obsolete xattr read when selection changes", async () => {
    const calls: Array<{
      signal?: AbortSignal;
      resolve(value: unknown): void;
    }> = [];
    const panel = new SlateFsFileProperties();
    panel.volume = "docs";
    panel.entry = entry("a", "a.txt");
    panel.client = {
      getXattrs: vi.fn(
        (_volume, _entry, _view, options) =>
          new Promise((resolve) =>
            calls.push({ signal: options?.signal, resolve }),
          ),
      ),
    } as never;
    document.body.append(panel);
    await new Promise((resolve) => setTimeout(resolve));
    panel.entry = entry("b", "b.txt");
    await panel.updateComplete;
    await new Promise((resolve) => setTimeout(resolve));
    expect(calls[0]!.signal?.aborted).toBe(true);
    calls[0]!.resolve({
      entry_id: "a",
      xattrs: [
        { name: "hostile<img>", name_bytes_base64: "", value_base64: "QQ==" },
      ],
    });
    await new Promise((resolve) => setTimeout(resolve));
    expect(panel.shadowRoot?.querySelector("img")).toBeNull();
    expect(panel.shadowRoot?.textContent).not.toContain("hostile<img>");
  });
  it("does not request xattrs after selection clears during capabilities", async () => {
    let resolveCapabilities!: (value: {
      features: { xattrs: boolean };
    }) => void;
    const getXattrs = vi.fn();
    const panel = new SlateFsFileProperties();
    Object.assign(panel, {
      volume: "docs",
      entry: entry("a", "a.txt"),
      client: {
        getCapabilities: vi.fn(
          () =>
            new Promise((resolve) => {
              resolveCapabilities = resolve;
            }),
        ),
        getXattrs,
      },
    });
    document.body.append(panel);
    await settle();
    panel.entry = undefined;
    await panel.updateComplete;
    await settle();
    resolveCapabilities({ features: { xattrs: true } });
    await settle();
    expect(getXattrs).not.toHaveBeenCalled();
    expect(panel.shadowRoot?.textContent).toContain("Nothing here yet");
    expect(panel.shadowRoot?.querySelector('[part="error"]')).toBeNull();
  });
});

describe("restore", () => {
  it("passes the reviewed request and preview token to apply", async () => {
    const previewRestore = vi.fn().mockResolvedValue({
      preview: { token: "plan-1", actions: [{ action: "replace" }] },
    });
    const applyRestore = vi.fn().mockResolvedValue({ restored: { count: 1 } });
    const restore = new SlateFsRestoreDialog();
    Object.assign(restore, {
      client: { previewRestore, applyRestore },
      volume: "docs",
      commit: "abc123",
      paths: ["/a.txt"],
      mode: "exact",
      open: true,
    });
    document.body.append(restore);
    await restore.previewRestore();
    const applying = restore.apply();
    await submitActionDialog(restore);
    await applying;
    expect(previewRestore).toHaveBeenCalledWith(
      "docs",
      { commit: "abc123", path: "/a.txt", mode: "exact" },
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(applyRestore).toHaveBeenCalledWith("docs", {
      commit: "abc123",
      path: "/a.txt",
      mode: "exact",
      token: "plan-1",
    });
  });

  it("honors the cancelable destructive hook", async () => {
    const applyRestore = vi.fn();
    const restore = new SlateFsRestoreDialog();
    Object.assign(restore, {
      client: {
        previewRestore: vi.fn().mockResolvedValue({
          preview: { token: "plan-1", actions: [] },
        }),
        applyRestore,
      },
      volume: "docs",
      commit: "abc123",
      paths: ["/a.txt"],
      open: true,
    });
    restore.addEventListener("slatefs-before-operation", (event) =>
      event.preventDefault(),
    );
    document.body.append(restore);
    await restore.previewRestore();
    const applying = restore.apply();
    await submitActionDialog(restore);
    await applying;
    expect(applyRestore).not.toHaveBeenCalled();
  });
  it("invalidates a stale plan and requires a fresh preview", async () => {
    const restore = new SlateFsRestoreDialog();
    Object.assign(restore, {
      client: {
        previewRestore: vi
          .fn()
          .mockResolvedValue({ preview: { token: "old", actions: [] } }),
        applyRestore: vi.fn().mockRejectedValue({ status: 409 }),
      },
      volume: "docs",
      commit: "abc",
      paths: ["/a.txt"],
      open: true,
    });
    document.body.append(restore);
    await restore.previewRestore();
    const applying = restore.apply();
    await submitActionDialog(restore);
    await applying;
    await restore.updateComplete;
    expect(restore.shadowRoot?.textContent).toContain("plan is stale");
    expect(restore.shadowRoot?.textContent).toContain("Preview restore");
  });
  it("moves focus into the dialog and restores it on close", async () => {
    const trigger = document.createElement("button");
    document.body.append(trigger);
    trigger.focus();
    const restore = new SlateFsRestoreDialog();
    document.body.append(restore);
    restore.show();
    await restore.updateComplete;
    expect(restore.shadowRoot?.activeElement?.textContent).toContain("Close");
    restore
      .shadowRoot!.querySelector("section")!
      .dispatchEvent(
        new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
      );
    expect(document.activeElement).toBe(trigger);
    expect(restore.open).toBe(false);
  });
});

describe("version and repository capability surfaces", () => {
  it("commits, tags, and creates branches through reviewed forms", async () => {
    const commit = vi.fn().mockResolvedValue({ commit: { id: "c2" } });
    const getVersionPolicy = vi
      .fn()
      .mockResolvedValue({ versioning: { enabled: true } });
    const status = new SlateFsVersionStatus();
    Object.assign(status, {
      volume: "docs",
      author: "Alice",
      versioningEnabled: true,
      client: {
        getVersionPolicy,
        getStatus: vi.fn().mockResolvedValue({
          status: { changes: [{ path: "/a.txt", change: "modify" }] },
        }),
        commit,
      },
    });
    document.body.append(status);
    await settle();
    expect(getVersionPolicy).not.toHaveBeenCalled();
    [...status.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Save new version")!
      .click();
    await submitActionDialog(status, { message: "Publish change" });
    expect(commit.mock.calls[0]![1]).toEqual({
      branch: "main",
      paths: ["/a.txt"],
      message: "Publish change",
      author: "Alice",
    });

    const createTag = vi.fn().mockResolvedValue({});
    const history = new SlateFsVersionHistory();
    Object.assign(history, {
      volume: "docs",
      client: {
        getLog: vi.fn().mockResolvedValue({ commits: [{ id: "c1" }] }),
        createTag,
        showCommit: vi.fn().mockResolvedValue({ commit: { id: "c1" } }),
      },
    });
    document.body.append(history);
    await settle();
    [...history.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Tag")!
      .click();
    await submitActionDialog(history, { name: "v1" });
    expect(createTag).toHaveBeenCalledWith("docs", {
      name: "v1",
      commit: "c1",
    });

    const createBranch = vi.fn().mockResolvedValue({
      branch: { name: "feature", commit: "c1" },
    });
    const branches = new SlateFsBranchManager();
    Object.assign(branches, {
      volume: "docs",
      client: {
        getBranches: vi
          .fn()
          .mockResolvedValueOnce({
            branches: [{ name: "main", commit: "c1" }],
          })
          .mockResolvedValue({
            branches: [
              { name: "main", commit: "c1" },
              { name: "feature", commit: "c1" },
            ],
          }),
        getReflog: vi.fn().mockResolvedValue({ entries: [] }),
        getProtection: vi
          .fn()
          .mockResolvedValue({ protection: { protected: false } }),
        createBranch,
      },
    });
    document.body.append(branches);
    await settle();
    [...branches.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "New branch")!
      .click();
    await submitActionDialog(branches, { name: "feature" });
    expect(createBranch).toHaveBeenCalledWith("docs", {
      name: "feature",
      commit: "c1",
    });
    expect(branches.shadowRoot?.textContent).toContain("feature");
  });

  it("refreshes a diff from edited endpoints using the visible Compare action", async () => {
    const getDiff = vi.fn().mockResolvedValue({
      changes: [{ path: "/a.txt", change: "modify" }],
      next_page_token: null,
    });
    const diff = new SlateFsVersionDiff();
    Object.assign(diff, { volume: "docs", client: { getDiff } });
    document.body.append(diff);
    await settle();
    expect(getDiff).not.toHaveBeenCalled();
    expect(diff.shadowRoot?.textContent).toContain(
      "Choose two versions and click Compare.",
    );
    const inputs = diff.shadowRoot!.querySelectorAll<HTMLInputElement>("input");
    inputs[0]!.value = "c1";
    inputs[0]!.dispatchEvent(new Event("input", { bubbles: true }));
    inputs[1]!.value = "c2";
    inputs[1]!.dispatchEvent(new Event("input", { bubbles: true }));
    expect(diff.from).toBe("c1");
    expect(diff.to).toBe("c2");
    await diff.updateComplete;
    expect(getDiff).not.toHaveBeenCalled();
    [...diff.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Compare")!
      .click();
    await settle();
    expect(getDiff).toHaveBeenLastCalledWith(
      "docs",
      "c1",
      "c2",
      expect.objectContaining({ limit: 250 }),
    );
    expect(diff.shadowRoot?.textContent).toContain("1 changed paths");
  });
  it("renders a missing diff reference as an operation error, not an unsupported capability", async () => {
    const diff = new SlateFsVersionDiff();
    Object.assign(diff, {
      volume: "docs",
      client: {
        getDiff: vi.fn().mockRejectedValue(
          Object.assign(new Error("version reference live was not found"), {
            status: 404,
            code: "not_found",
          }),
        ),
      },
    });
    document.body.append(diff);
    await settle();
    await diff.refresh();
    await diff.updateComplete;
    expect(diff.shadowRoot?.textContent).toContain(
      "version reference live was not found",
    );
    expect(diff.shadowRoot?.textContent).not.toContain(
      "This capability is not available",
    );
  });
  it("compares a history commit to the selected version reference", async () => {
    const history = new SlateFsVersionHistory();
    Object.assign(history, {
      volume: "docs",
      reference: "release",
      client: {
        getLog: vi.fn().mockResolvedValue({
          commits: [{ id: "c1", message: "First" }],
          next_page_token: null,
        }),
      },
    });
    const compared = vi.fn();
    history.addEventListener("slatefs-compare-request", compared);
    document.body.append(history);
    await settle();
    [...history.shadowRoot!.querySelectorAll("button")]
      .find((button) => button.textContent?.trim() === "Compare")!
      .click();
    expect(compared.mock.calls[0]![0].detail).toEqual({
      version: 1,
      from: "c1",
      to: "release",
    });
  });
  it("browses the resolved branch commit and contains long branch names", async () => {
    const longName = "feature-" + "x".repeat(120);
    const branches = new SlateFsBranchManager();
    Object.assign(branches, {
      volume: "docs",
      client: {
        getBranches: vi.fn().mockResolvedValue({
          branches: [{ name: longName, commit: "commit-123" }],
        }),
        getReflog: vi.fn().mockResolvedValue({ entries: [] }),
        getProtection: vi
          .fn()
          .mockResolvedValue({ protection: { protected: false } }),
      },
    });
    const changed = vi.fn();
    branches.addEventListener("slatefs-view-change", changed);
    document.body.append(branches);
    await settle();

    const row = branches.shadowRoot!.querySelector<HTMLElement>(
      ".branch-row[part='branch-row']",
    )!;
    const summary = row.querySelector<HTMLElement>(
      ".branch-summary[part='branch-summary']",
    )!;
    const name = summary.querySelector<HTMLElement>(
      ".branch-name[part='branch-name']",
    )!;
    const actions = row.querySelector<HTMLElement>(
      ".branch-actions[part='branch-actions']",
    )!;
    const browse = [...actions.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === "Browse",
    )!;

    expect(name.textContent).toBe(longName);
    expect(summary.parentElement).toBe(row);
    expect(actions.parentElement).toBe(row);
    expect(browse).toBeTruthy();

    browse.click();
    expect(changed.mock.calls[0]![0].detail).toEqual({
      version: 1,
      view: {
        kind: "version",
        ref: "commit-123",
        resolvedCommit: "commit-123",
      },
    });
  });
  it("visualizes source-to-target history flow and defaults main into a selected branch", async () => {
    const branches = new SlateFsBranchManager();
    Object.assign(branches, {
      volume: "docs",
      client: {
        getBranches: vi.fn().mockResolvedValue({
          branches: [
            { name: "main", commit: "m1" },
            { name: "feature", commit: "f1" },
          ],
        }),
        getReflog: vi.fn().mockResolvedValue({ entries: [] }),
        getProtection: vi
          .fn()
          .mockResolvedValue({ protection: { protected: false } }),
      },
    });
    const publishTarget = vi.fn();
    branches.addEventListener("slatefs-publish-target-change", publishTarget);
    document.body.append(branches);
    await settle();

    branches
      .shadowRoot!.querySelector<HTMLButtonElement>(
        'button[aria-label="Use feature as target branch"]',
      )!
      .click();
    await branches.updateComplete;

    const source = branches.shadowRoot!.querySelector<HTMLSelectElement>(
      'select[aria-label="Source branch"]',
    )!;
    const target = branches.shadowRoot!.querySelector<HTMLSelectElement>(
      'select[aria-label="Target branch"]',
    )!;
    const preview = [...branches.shadowRoot!.querySelectorAll("button")].find(
      (button) =>
        button.textContent?.trim() === "Preview merge main into feature",
    )!;
    expect(source.value).toBe("main");
    expect(target.value).toBe("feature");
    expect(preview.disabled).toBe(false);
    expect(branches.shadowRoot!.textContent).toContain(
      "They do not overwrite the live workspace.",
    );
    expect(publishTarget.mock.calls[0]![0].detail).toEqual({
      version: 1,
      branch: "feature",
    });
  });
  it("applies the exact merge inputs that were previewed", async () => {
    const client = {
      getBranches: vi.fn().mockResolvedValue({
        branches: [
          { name: "main", commit: "m1" },
          { name: "feature", commit: "f1" },
        ],
      }),
      getReflog: vi.fn().mockResolvedValue({ entries: [] }),
      getProtection: vi
        .fn()
        .mockResolvedValue({ protection: { protected: false } }),
      previewMerge: vi.fn().mockResolvedValue({ preview: { base: "b1" } }),
      applyMerge: vi.fn().mockResolvedValue({ merge: { commit: "m2" } }),
    };
    const branches = new SlateFsBranchManager();
    Object.assign(branches, { client, volume: "docs", source: "feature" });
    document.body.append(branches);
    await new Promise((resolve) => setTimeout(resolve));
    await branches.previewMerge();
    await branches.updateComplete;
    const applying = branches.applyMerge();
    await submitActionDialog(branches);
    await applying;
    expect(client.applyMerge).toHaveBeenCalledWith(
      "docs",
      {
        target: "main",
        source: "feature",
        expected_target: "m1",
        expected_source: "f1",
        conflict_strategy: "fail",
      },
      expect.objectContaining({ idempotencyKey: expect.any(String) }),
    );
  });
  it.each([
    ["merge", "previewMerge", "applyMerge"],
    ["cherry-pick", "previewCherryPick", "applyCherryPick"],
  ] as const)(
    "reports a failed %s as both a conflict and a completed operation error",
    async (operation, previewMethod, applyMethod) => {
      const failure = Object.assign(new Error(`${operation} rejected`), {
        code: "conflict",
      });
      const client = {
        getBranches: vi.fn().mockResolvedValue({
          branches: [
            { name: "main", commit: "m1" },
            { name: "feature", commit: "f1" },
          ],
        }),
        getReflog: vi.fn().mockResolvedValue({ entries: [] }),
        getProtection: vi
          .fn()
          .mockResolvedValue({ protection: { protected: false } }),
        [previewMethod]: vi
          .fn()
          .mockResolvedValue({ preview: { paths: ["/a.txt"] } }),
        [applyMethod]: vi.fn().mockRejectedValue(failure),
      };
      const branches = new SlateFsBranchManager();
      Object.assign(branches, { client, volume: "docs", source: "feature" });
      const conflict = vi.fn();
      const operationError = vi.fn();
      branches.addEventListener("slatefs-conflict", conflict);
      branches.addEventListener("slatefs-operation-error", operationError);
      document.body.append(branches);
      await new Promise((resolve) => setTimeout(resolve));

      await branches[previewMethod]();
      const applying = branches[applyMethod]();
      await submitActionDialog(branches);
      await applying;

      expect(conflict).toHaveBeenCalledOnce();
      expect(operationError.mock.calls[0]![0].detail).toEqual({
        version: 1,
        operation,
        entryIds: [],
        code: "conflict",
        message: `${operation} rejected`,
      });
    },
  );
  it("invalidates merge and cherry-pick previews when reviewed inputs change", async () => {
    const client = {
      getBranches: vi.fn().mockResolvedValue({
        branches: [
          { name: "main", commit: "m1" },
          { name: "feature", commit: "f1" },
        ],
      }),
      getReflog: vi.fn().mockResolvedValue({ entries: [] }),
      getProtection: vi
        .fn()
        .mockResolvedValue({ protection: { protected: false } }),
      previewMerge: vi.fn().mockResolvedValue({ preview: { base: "b1" } }),
      applyMerge: vi.fn(),
      previewCherryPick: vi
        .fn()
        .mockResolvedValue({ preview: { paths: ["/a"] } }),
      applyCherryPick: vi.fn(),
    };
    const branches = new SlateFsBranchManager();
    Object.assign(branches, { client, volume: "docs", source: "feature" });
    document.body.append(branches);
    await new Promise((resolve) => setTimeout(resolve));
    await branches.previewMerge();
    branches.source = "changed-after-preview";
    await branches.updateComplete;
    await branches.applyMerge();
    expect(client.applyMerge).not.toHaveBeenCalled();

    branches.source = "feature";
    await branches.updateComplete;
    await branches.previewCherryPick();
    branches.mainline = 2;
    await branches.updateComplete;
    await branches.applyCherryPick();
    await branches.updateComplete;
    expect(client.applyCherryPick).not.toHaveBeenCalled();
  });
  it("loads status, history, diff, branches, recovery, and safe repository stats", async () => {
    const client = {
      getVersionPolicy: vi
        .fn()
        .mockResolvedValue({ versioning: { enabled: true } }),
      getStatus: vi.fn().mockResolvedValue({
        status: {
          changes: [{ path: "/a.txt", change: "modify" }],
          commit: "abc123",
          reference: "main",
          root: "/",
        },
      }),
      getLog: vi.fn().mockResolvedValue({
        commits: [{ id: "abc123", message: "First", author: "Alice" }],
        next_page_token: null,
      }),
      getDiff: vi.fn().mockResolvedValue({
        changes: [{ path: "/a.txt", change: "modify" }],
        next_page_token: null,
      }),
      getBranches: vi
        .fn()
        .mockResolvedValue({ branches: [{ name: "main", commit: "abc123" }] }),
      getReflog: vi.fn().mockResolvedValue({ entries: [{ commit: "abc123" }] }),
      getProtection: vi.fn().mockResolvedValue({
        protection: { protected: false },
      }),
      getRepositoryStats: vi.fn().mockResolvedValue({ stats: { commits: 1 } }),
    };
    const elements = [
      new SlateFsVersionStatus(),
      new SlateFsVersionHistory(),
      new SlateFsVersionDiff(),
      new SlateFsBranchManager(),
      new SlateFsRepositoryTools(),
    ];
    for (const element of elements) {
      Object.assign(element, { client, volume: "docs" });
      document.body.append(element);
    }
    await new Promise((resolve) => setTimeout(resolve));
    await Promise.all(elements.map((element) => element.updateComplete));
    await (elements[2] as SlateFsVersionDiff).refresh();
    await elements[2]!.updateComplete;
    expect(elements[0]!.shadowRoot?.textContent).toContain("a.txt");
    expect(elements[1]!.shadowRoot?.textContent).toContain("First");
    expect(elements[2]!.shadowRoot?.textContent).toContain("1 changed paths");
    expect(elements[3]!.shadowRoot?.textContent).toContain("main");
    expect(elements[4]!.shadowRoot?.textContent).toContain('"commits": 1');
  });

  it("keeps the hidden diff change list array-shaped before and after loading", async () => {
    const diff = new SlateFsVersionDiff();
    diff.hidden = true;
    document.body.append(diff);
    await diff.updateComplete;
    expect(diff.shadowRoot?.textContent).toContain("0 changed paths");

    diff.volume = "docs";
    diff.client = {
      getDiff: vi.fn().mockResolvedValue({
        changes: [{ path: "/a.txt", change: "modified" }],
        next_page_token: null,
      }),
    };
    await diff.updateComplete;
    await diff.refresh();
    await diff.updateComplete;
    expect(diff.shadowRoot?.textContent).toContain("1 changed paths");
    expect(diff.shadowRoot?.textContent).toContain("a.txt");
  });
});
