import type {
  CollaborationClient,
  Entry,
  FileSystemClient,
  FileSystemReadClient,
  RepositoryClient,
  SnapshotClient,
  VersionClient,
  ViewSelection,
  VolumeSummary,
  XattrValue,
} from "@slatefs/client";
import { displayEntryName } from "@slatefs/client";
import {
  css,
  html,
  nothing,
  type PropertyValues,
  type TemplateResult,
} from "lit";
import { SlateFsElement } from "./base.js";
import { OperationController } from "./operations.js";

const fmtBytes = (n: number | string | undefined) => {
  const value = Number(n ?? 0);
  if (!Number.isFinite(value)) return String(n ?? "—");
  if (value < 1024) return `${value} B`;
  const u = ["KiB", "MiB", "GiB", "TiB"];
  let v = value,
    i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < u.length - 1);
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
};
const fmtLosslessBytes = (decimal: string | undefined, fallback: number) =>
  decimal ? `${fmtBytes(decimal)} (${decimal} bytes)` : fmtBytes(fallback);
const exceedsBytes = (
  decimal: string | undefined,
  fallback: number,
  limit: number,
) => {
  try {
    return BigInt(decimal ?? fallback) > BigInt(limit);
  } catch {
    return fallback > limit;
  }
};
const isZeroBytes = (decimal: string | undefined, fallback: number) => {
  try {
    return BigInt(decimal ?? fallback) === 0n;
  } catch {
    return fallback === 0;
  }
};
const parsedDate = (value: unknown): Date | undefined => {
  if (value === undefined || value === null || value === "") return undefined;
  const slateTimestamp =
    typeof value === "string"
      ? /^(-?\d+)(?:\.(\d{1,9}))?Z$/.exec(value.trim())
      : null;
  const numeric =
    typeof value === "number"
      ? value
      : slateTimestamp
        ? Number(slateTimestamp[1]) +
          Number(`0.${(slateTimestamp[2] ?? "0").padEnd(9, "0")}`)
        : typeof value === "string" && /^-?\d+(?:\.\d+)?$/.test(value.trim())
          ? Number(value)
          : undefined;
  const candidate =
    numeric === undefined
      ? new Date(String(value))
      : new Date(
          Math.abs(numeric) < 1_000_000_000_000 ? numeric * 1000 : numeric,
        );
  return Number.isFinite(candidate.getTime()) ? candidate : undefined;
};
const date = (value: unknown) => {
  const candidate = parsedDate(value);
  if (!candidate) return "Date unavailable";
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(candidate);
  } catch {
    return "Date unavailable";
  }
};
const dateTimeAttribute = (value: unknown) =>
  parsedDate(value)?.toISOString() ?? nothing;
const selector = (entry: Entry) => ({ entryId: entry.entry_id });
const copyEntry = (entry: Entry): Entry => ({ ...entry });
const copyView = (view: ViewSelection): ViewSelection => ({ ...view });
const isText = (type: string) =>
  type.startsWith("text/") || /json|javascript|xml|yaml/.test(type);
const previewMime = (type: string, name: string | null | undefined) => {
  const normalized =
    type.split(";")[0]?.trim().toLowerCase() || "application/octet-stream";
  if (normalized === "application/octet-stream" && /\.txt$/i.test(name ?? ""))
    return "text/plain";
  return normalized;
};
const isRasterImage = (type: string) =>
  ["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"].includes(
    type,
  );
const readStream = async (body: ReadableStream<Uint8Array>, limit: number) => {
  const reader = body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error(`Preview exceeds ${fmtBytes(limit)}`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
};
const defer = (work: () => Promise<unknown>) =>
  queueMicrotask(() => void work());

/** Volume inventory and quota selector. @fires slatefs-volume-change */
export class SlateFsVolumePicker extends SlateFsElement<
  Pick<FileSystemReadClient, "listVolumes">
> {
  static override properties = {
    ...SlateFsElement.properties,
    includeUnbrowsable: { type: Boolean, attribute: "include-unbrowsable" },
    autoSelectSingle: { type: Boolean, attribute: "auto-select-single" },
    disabled: { type: Boolean, reflect: true },
  };
  readonly componentLabel = "SlateFS volume picker";
  includeUnbrowsable = false;
  autoSelectSingle = false;
  disabled = false;
  private volumes: VolumeSummary[] = [];
  protected override updated(changes: PropertyValues) {
    if (changes.has("client") || changes.has("includeUnbrowsable"))
      defer(() => this.refresh());
  }
  async refresh() {
    if (!this.client) {
      this.loadState = "unsupported";
      this.requestUpdate();
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      const result = await this.client.listVolumes({ signal });
      if (!this.loadCurrent(serial)) return;
      this.volumes = result.volumes.filter(
        (v) => this.includeUnbrowsable || v.browsable,
      );
      const selectedStillExists = this.volumes.some(
        (candidate) => candidate.name === this.volume,
      );
      const nextVolume = selectedStillExists
        ? this.volume
        : this.autoSelectSingle && this.volumes.length === 1
          ? this.volumes[0]!.name
          : "";
      if (nextVolume !== this.volume) {
        this.volume = nextVolume;
        this.emit("slatefs-volume-change", {
          version: 1,
          volume: nextVolume,
        });
      }
      this.finishLoad(serial, this.volumes.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  override focus(options?: FocusOptions) {
    this.renderRoot.querySelector("select")?.focus(options);
  }
  protected override render() {
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <label class="grow"
          ><span class="sr-only">Volume</span
          ><select
            part="select"
            ?disabled=${this.disabled || this.loadState === "loading"}
            .value=${this.volume}
            @change=${(e: Event) => {
              const v = (e.target as HTMLSelectElement).value;
              this.volume = v;
              this.emit("slatefs-volume-change", { version: 1, volume: v });
            }}
          >
            <option value="" ?selected=${!this.volume}>Choose a volume</option>
            ${this.volumes.map(
              (v) =>
                html`<option
                  part="option"
                  value=${v.name}
                  ?selected=${v.name === this.volume}
                  ?disabled=${!v.browsable}
                >
                  ${v.name} · ${v.kind}${v.readonly ? " · read-only" : ""}
                </option>`,
            )}
          </select></label
        ><button aria-label="Refresh volumes" @click=${this.refresh}>↻</button>
      </header>
      ${this.stateTemplate(this.refresh)}${this.volume
        ? html`<div class="body split" part="quota">
            ${(() => {
              const v = this.volumes.find((x) => x.name === this.volume);
              if (!v) return nothing;
              const used = Number(v.quota.used_bytes ?? 0);
              const limit =
                v.quota.limit_bytes === null
                  ? null
                  : Number(v.quota.limit_bytes);
              const ratio =
                limit && Number.isFinite(used) && limit > 0
                  ? Math.min(1, used / limit)
                  : null;
              return html`<span class="badge" part="kind-badge">${v.kind}</span
                ><span class="muted grow"
                  >${fmtBytes(v.quota.used_bytes)}
                  used${v.quota.limit_bytes === null
                    ? ""
                    : ` of ${fmtBytes(v.quota.limit_bytes)}`}</span
                >${ratio === null
                  ? nothing
                  : html`<span
                      class="quota-meter"
                      part="quota-meter"
                      role="meter"
                      aria-valuemin="0"
                      aria-valuemax="100"
                      aria-valuenow=${Math.round(ratio * 100)}
                      aria-label="Quota used"
                      ><i style="inline-size: ${(ratio * 100).toFixed(1)}%"></i
                    ></span>`}`;
            })()}
          </div>`
        : nothing}
      <div class="sr-only" aria-live="polite">
        ${this.loadState === "ready"
          ? `${this.volumes.length} volumes available`
          : ""}
      </div>
    </section>`;
  }
}

type ExplorerClient = Pick<
  FileSystemClient,
  | "listEntries"
  | "createEntry"
  | "updateEntry"
  | "deleteEntry"
  | "startOperation"
  | "uploadContent"
  | "getCapabilities"
>;
/** Paginated, keyboard-operable and bounded-DOM file explorer. */
export class SlateFsFileExplorer extends SlateFsElement<ExplorerClient> {
  static override properties = {
    ...SlateFsElement.properties,
    directoryEntryId: { type: String, attribute: "directory-entry-id" },
    displayMode: { type: String, attribute: "display-mode", reflect: true },
    sort: { type: String },
    filter: { type: String },
    operationController: { attribute: false },
    conflictPolicy: { type: String, attribute: "conflict-policy" },
  };
  static override styles = [
    SlateFsElement.styles,
    css`
      .crumbs {
        padding: 0.55rem 0.75rem;
        border-bottom: 1px solid var(--_border);
        display: flex;
        gap: 0.25rem;
        overflow: auto;
        align-items: center;
        color: var(--_muted);
        font-size: 0.85rem;
      }
      .crumbs button {
        border: 0;
        padding: 0.2rem 0.35rem;
        background: transparent;
        color: var(--_accent);
        border-radius: 6px;
        min-height: 0;
      }
      .crumbs button:hover {
        background: color-mix(in srgb, var(--_accent) 12%, transparent);
      }
      .table {
        display: grid;
        grid-template-columns: minmax(13rem, 3fr) minmax(7rem, 1fr) 7rem minmax(
            9rem,
            1.3fr
          );
        max-height: 32rem;
        overflow: auto;
      }
      .head,
      .entry {
        display: contents;
      }
      .cell {
        padding: 0.55rem 0.7rem;
        border-bottom: 1px solid var(--_border);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        transition: background 0.14s ease;
      }
      .head .cell {
        position: sticky;
        top: 0;
        background: var(--_subtle-bg);
        z-index: 1;
        font-size: 0.72rem;
        font-weight: 750;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--_muted);
      }
      .entry:hover .cell {
        background: color-mix(in srgb, var(--_selected-bg) 45%, transparent);
      }
      .entry[aria-selected="true"] .cell {
        background: var(--_selected-bg);
      }
      .entry[aria-selected="true"] .cell:first-child {
        box-shadow: inset 3px 0
          color-mix(in srgb, var(--_accent) 75%, transparent);
      }
      .entry[aria-selected="true"]:hover .cell {
        background: color-mix(
          in srgb,
          var(--_selected-bg) 82%,
          var(--_accent) 18%
        );
      }
      .entry.focused .cell {
        box-shadow: inset 3px 0 var(--_accent);
      }
      .name {
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.55rem;
      }
      .entry-icon {
        flex: 0 0 auto;
        width: 1rem;
        height: 1rem;
        color: var(--_muted);
      }
      .entry[aria-selected="true"] .entry-icon,
      .entry:hover .entry-icon {
        color: var(--_accent);
      }
      .drop {
        outline: 3px dashed var(--_accent);
        outline-offset: -5px;
      }
      .quota {
        margin-left: auto;
      }
      .menu {
        display: flex;
        gap: 0.25rem;
      }
      .mobile {
        display: none;
      }
      @media (max-width: 620px) {
        .table {
          grid-template-columns: 1fr;
        }
        .head,
        .meta {
          display: none;
        }
        .cell {
          white-space: normal;
          min-height: 3rem;
        }
        .mobile {
          display: block;
          font-size: 0.8rem;
          color: var(--_muted);
        }
      }
    `,
  ];
  readonly componentLabel = "SlateFS file explorer";
  directoryEntryId = "";
  displayMode: "details" | "grid" = "details";
  sort = "name";
  filter = "";
  operationController?: OperationController;
  conflictPolicy: "fail" | "overwrite" | "keep_both" | "skip" = "keep_both";
  private loadedEntries: Entry[] = [];
  private entries: Entry[] = [];
  private directory?: Entry;
  private next: string | null = null;
  private focused = 0;
  private anchor = 0;
  private clipboard: { mode: "copy" | "move"; ids: string[] } | null = null;
  private dragging = false;
  private renderStart = 0;
  private readonly renderLimit = 200;
  private resolvedView: ViewSelection = { kind: "live" };
  protected override willUpdate(changes: PropertyValues) {
    // Entry IDs are bound to both the volume and resolved view. Never reuse a
    // directory token after either boundary changes.
    if (changes.has("volume") || changes.has("view"))
      this.directoryEntryId = "";
  }
  protected override updated(changes: PropertyValues) {
    if (
      changes.has("volume") ||
      changes.has("client") ||
      changes.has("path") ||
      changes.has("view") ||
      changes.has("directoryEntryId")
    )
      defer(() => this.refresh());
  }
  async refresh() {
    this.loadedEntries = [];
    this.entries = [];
    this.next = null;
    this.renderStart = 0;
    if (!this.client || !this.volume) {
      this.loadState = this.client ? "empty" : "unsupported";
      this.requestUpdate();
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      if (this.view.kind !== "live") {
        const capabilities = await this.client.getCapabilities({ signal });
        const supported =
          this.view.kind === "snapshot"
            ? capabilities.features.historical_snapshots
            : capabilities.features.historical_versions;
        if (!supported) {
          this.finishLoad(serial, "unsupported");
          return;
        }
      }
      const result = await this.client.listEntries(
        this.volume,
        this.directoryEntryId
          ? { entryId: this.directoryEntryId }
          : { path: this.path },
        this.view,
        { limit: 200, signal },
      );
      if (!this.loadCurrent(serial)) return;
      this.directory = result.entry;
      this.loadedEntries = result.entries;
      this.entries = this.arrange(this.loadedEntries);
      this.reconcileSelection();
      this.next = result.next_page_token;
      this.resolvedView = copyView(result.view);
      this.finishLoad(serial, this.entries.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async loadMore() {
    if (!this.next || !this.client) return;
    const token = this.next,
      { signal, serial } = this.beginLoad();
    try {
      const result = await this.client.listEntries(
        this.volume,
        this.directoryEntryId
          ? { entryId: this.directoryEntryId }
          : { path: this.path },
        this.view,
        { limit: 200, pageToken: token, signal },
      );
      if (!this.loadCurrent(serial)) return;
      this.loadedEntries = [...this.loadedEntries, ...result.entries];
      this.entries = this.arrange(this.loadedEntries);
      this.reconcileSelection();
      this.next = result.next_page_token;
      this.finishLoad(serial);
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  private arrange(entries: Entry[]) {
    const f = this.filter.toLocaleLowerCase();
    return entries
      .filter((e) => !f || displayEntryName(e).toLocaleLowerCase().includes(f))
      .sort((a, b) => {
        if (this.sort === "size") return a.size - b.size;
        if (this.sort === "modified")
          return String(a.modified_at ?? "").localeCompare(
            String(b.modified_at ?? ""),
          );
        if (this.sort === "type") return a.kind.localeCompare(b.kind);
        return displayEntryName(a).localeCompare(
          displayEntryName(b),
          undefined,
          { numeric: true },
        );
      });
  }
  private reconcileSelection() {
    const available = new Set(
      this.loadedEntries.map((entry) => entry.entry_id),
    );
    const selection = this.selection.filter((id) => available.has(id));
    if (
      selection.length !== this.selection.length ||
      selection.some((id, index) => id !== this.selection[index])
    ) {
      this.selection = selection;
      this.emit("slatefs-selection-change", {
        version: 1,
        selection: this.loadedEntries
          .filter((entry) => selection.includes(entry.entry_id))
          .map(copyEntry),
      });
    }
  }
  private select(index: number, extend = false, toggle = false) {
    const entry = this.entries[index];
    if (!entry) return;
    let ids = [...this.selection];
    if (extend) {
      const bounds = [this.anchor, index].sort((x, y) => x - y);
      ids = this.entries
        .slice(bounds[0]!, bounds[1]! + 1)
        .map((e) => e.entry_id);
    } else if (toggle) {
      ids = ids.includes(entry.entry_id)
        ? ids.filter((id) => id !== entry.entry_id)
        : [...ids, entry.entry_id];
      this.anchor = index;
    } else {
      ids = [entry.entry_id];
      this.anchor = index;
    }
    this.selection = ids;
    this.focused = index;
    this.emit("slatefs-selection-change", {
      version: 1,
      selection: this.entries
        .filter((e) => ids.includes(e.entry_id))
        .map(copyEntry),
    });
    this.requestUpdate();
  }
  private open(entry: Entry) {
    if (entry.kind === "directory") {
      if (entry.path) this.path = `/${entry.path.replace(/^\/+/, "")}`;
      else if (entry.name)
        this.path = `${this.path.replace(/\/$/, "")}/${entry.name}`;
      this.directoryEntryId = entry.entry_id;
      this.emit("slatefs-path-change", {
        version: 1,
        volume: this.volume,
        path: this.path,
        entryId: entry.entry_id,
      });
    } else {
      this.emit("slatefs-entry-open", {
        version: 1,
        entry: copyEntry(entry),
        view: copyView(this.resolvedView),
      });
      this.emit("slatefs-preview-request", {
        version: 1,
        entry: copyEntry(entry),
        view: copyView(this.resolvedView),
      });
    }
  }
  private key(e: KeyboardEvent, index: number) {
    const meta = e.metaKey || e.ctrlKey;
    if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
      e.preventDefault();
      const n =
        e.key === "Home"
          ? 0
          : e.key === "End"
            ? this.entries.length - 1
            : Math.max(
                0,
                Math.min(
                  this.entries.length - 1,
                  index + (e.key === "ArrowDown" ? 1 : -1),
                ),
              );
      if (n < this.renderStart || n >= this.renderStart + this.renderLimit)
        this.renderStart = Math.floor(n / this.renderLimit) * this.renderLimit;
      this.select(n, e.shiftKey, meta);
      void this.updateComplete.then(() =>
        this.renderRoot
          .querySelector<HTMLElement>(`[data-index='${n}']`)
          ?.focus(),
      );
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      this.open(this.entries[index]!);
    } else if (e.key === " ") {
      e.preventDefault();
      this.select(index, e.shiftKey, meta);
    } else if (e.key === "F2") {
      e.preventDefault();
      void this.rename(this.entries[index]!);
    } else if (e.key === "Delete") {
      e.preventDefault();
      void this.deleteSelected();
    } else if (meta && ["c", "x"].includes(e.key.toLowerCase())) {
      e.preventDefault();
      this.clipboard = {
        mode: e.key.toLowerCase() === "c" ? "copy" : "move",
        ids: [...this.selection],
      };
      this.requestUpdate();
    } else if (meta && e.key.toLowerCase() === "v") {
      e.preventDefault();
      void this.paste();
    } else if (meta && e.key.toLowerCase() === "a") {
      e.preventDefault();
      this.selection = this.entries.map((entry) => entry.entry_id);
      this.emit("slatefs-selection-change", {
        version: 1,
        selection: this.entries.map(copyEntry),
      });
      this.requestUpdate();
    } else if (meta && e.key.toLowerCase() === "d") {
      e.preventDefault();
      void this.duplicateSelected();
    } else if (e.key === "Escape") {
      this.clearTransientState();
    }
  }
  private async mutate(
    label: string,
    run: (
      signal: AbortSignal,
      progress: (value: number, detail?: string) => void,
    ) => Promise<unknown>,
    entryIds: readonly string[] = this.selection,
  ): Promise<boolean> {
    if (this.readOnlyView) return false;
    const detail = {
      version: 1,
      operation: label,
      entryIds: [...entryIds],
    };
    if (!this.emit("slatefs-before-operation", detail, true)) return false;
    const controller = new AbortController();
    const id = this.operationController?.add({
      label,
      status: "running",
      progress: 0,
      cancel: () => controller.abort(),
    });
    const progress = (value: number, text?: string) => {
      if (id)
        this.operationController?.update(id, {
          progress: Math.max(0, Math.min(1, value)),
          ...(text ? { detail: text } : {}),
        });
    };
    this.emit("slatefs-operation-start", detail);
    try {
      await run(controller.signal, progress);
      if (id)
        this.operationController?.update(id, {
          status: "success",
          progress: 1,
        });
      this.emit("slatefs-operation-complete", detail);
      await this.refresh();
      return true;
    } catch (e) {
      if (id)
        this.operationController?.update(id, {
          status: "error",
          detail: e instanceof Error ? e.message : "Failed",
          retry: async () => {
            await this.mutate(label, run, entryIds);
          },
        });
      this.emit("slatefs-operation-error", {
        ...detail,
        code: (e as { code?: string }).code ?? "error",
        message: e instanceof Error ? e.message : "Failed",
      });
      if (
        (e as { status?: number }).status === 409 ||
        (e as { status?: number }).status === 412
      )
        this.emit("slatefs-conflict", {
          version: 1,
          operation: label,
          message: e instanceof Error ? e.message : "Conflict",
        });
      return false;
    }
  }
  private async create(kind: "file" | "directory") {
    if (!this.client || !this.directory) return;
    const values = await this.ask({
      title: `New ${kind}`,
      description: `Enter a name for the new ${kind}.`,
      submitLabel: `Create ${kind}`,
      fields: [{ name: "name", label: "Name", required: true }],
    });
    const name = values?.name?.trim();
    if (!name) return;
    await this.mutate(
      `create-${kind}`,
      (signal) =>
        this.client!.createEntry(
          this.volume,
          {
            parent_entry_id: this.directory!.entry_id,
            name,
            kind,
          },
          { signal },
        ),
      [],
    );
  }
  private async rename(entry: Entry) {
    if (!this.client || !entry.can_rename) return;
    const values = await this.ask({
      title: "Rename item",
      description: `Choose a new name for ${displayEntryName(entry)}.`,
      submitLabel: "Rename",
      fields: [
        {
          name: "name",
          label: "Name",
          value: entry.name ?? "",
          required: true,
        },
      ],
    });
    const name = values?.name?.trim();
    if (!name || name === entry.name) return;
    await this.mutate(
      "rename",
      (signal) =>
        this.client!.updateEntry(
          this.volume,
          { entry_id: entry.entry_id, name },
          { ifMatch: entry.etag, signal },
        ),
      [entry.entry_id],
    );
  }
  private async deleteSelected() {
    if (!this.client) return;
    const selected = this.entries.filter((e) =>
      this.selection.includes(e.entry_id),
    );
    if (!selected.length) return;
    if (
      !(await this.confirmAction(
        "Delete selected items",
        `Permanently delete ${selected.length} item(s)? Folders are attempted non-recursively. Recovery requires a prior snapshot or version.`,
        "Delete permanently",
        true,
      ))
    )
      return;
    await this.mutate(
      "delete",
      async (signal) => {
        const outcomes = await Promise.allSettled(
          selected.map((e) =>
            this.client!.deleteEntry(this.volume, e.entry_id, false, {
              ifMatch: e.etag,
              signal,
            }),
          ),
        );
        const failed = outcomes.filter((x) => x.status === "rejected");
        if (failed.length) {
          const failedDirectories = selected.filter(
            (entry, index) =>
              entry.kind === "directory" &&
              outcomes[index]?.status === "rejected",
          );
          if (failedDirectories.length)
            this.emit(
              "slatefs-recursive-delete-request",
              {
                version: 1,
                volume: this.volume,
                entries: failedDirectories.map(copyEntry),
                reason:
                  "Non-recursive deletion failed. Recursive delete requires a server-provided bounded preview and a separate confirmation.",
              },
              true,
            );
          const details = outcomes.flatMap((outcome, index) =>
            outcome.status === "rejected"
              ? [
                  `${displayEntryName(selected[index]!)}: ${
                    outcome.reason instanceof Error
                      ? outcome.reason.message
                      : String(outcome.reason ?? "Delete failed")
                  }`,
                ]
              : [],
          );
          throw new Error(
            `${failed.length} of ${outcomes.length} deletes failed: ${details.join("; ")}`,
          );
        }
      },
      selected.map((entry) => entry.entry_id),
    );
  }
  private async paste(destination = this.directory) {
    if (!this.client || !destination || !this.clipboard) return;
    const clip = this.clipboard;
    if (
      this.conflictPolicy === "overwrite" &&
      !(await this.confirmAction(
        "Overwrite destination entries",
        "Existing destination files with matching names may be replaced.",
        "Overwrite and continue",
        true,
      ))
    )
      return;
    const completed = await this.mutate(
      clip.mode,
      async (signal, progress) => {
        const operation = await this.client!.startOperation(
          this.volume,
          {
            operation: clip.mode,
            source_entry_ids: clip.ids,
            destination_parent_entry_id: destination.entry_id,
            conflict_policy: this.conflictPolicy,
            preview: false,
          },
          { signal },
        );
        progress(
          operation.total_entries
            ? operation.completed_entries / operation.total_entries
            : 1,
          operation.failed_entries
            ? `${operation.failed_entries} entries failed`
            : undefined,
        );
        if (operation.failed_entries)
          throw new Error(
            `${operation.failed_entries} of ${operation.total_entries} entries failed`,
          );
        return operation;
      },
      clip.ids,
    );
    if (completed && clip.mode === "move") this.clipboard = null;
  }
  private async duplicateSelected() {
    if (!this.directory || !this.selection.length) return;
    this.clipboard = { mode: "copy", ids: [...this.selection] };
    await this.paste();
  }
  private async upload(files: FileList | File[]) {
    if (!this.client || !this.directory) return;
    for (const file of [...files]) {
      const existing = this.loadedEntries.find(
        (entry) => entry.name === file.name,
      );
      if (existing && this.conflictPolicy === "skip") continue;
      if (existing && this.conflictPolicy === "overwrite") {
        if (existing.kind !== "file" || !existing.can_write) {
          this.reportActionError(
            "upload",
            new Error(`Cannot overwrite ${file.name}`),
            [existing.entry_id],
          );
          continue;
        }
        if (
          !(await this.confirmAction(
            `Overwrite ${file.name}`,
            "The existing file will be replaced.",
            "Overwrite file",
            true,
          ))
        )
          continue;
      }
      let name = file.name;
      if (existing && this.conflictPolicy === "keep_both") {
        const dot = file.name.lastIndexOf(".");
        const stem = dot > 0 ? file.name.slice(0, dot) : file.name;
        const extension = dot > 0 ? file.name.slice(dot) : "";
        for (let copy = 2; ; copy++) {
          const candidate = `${stem} (${copy})${extension}`;
          if (!this.loadedEntries.some((entry) => entry.name === candidate)) {
            name = candidate;
            break;
          }
        }
      }
      await this.mutate(
        "upload",
        (signal, progress) =>
          this.client!.uploadContent(
            this.volume,
            existing && this.conflictPolicy === "overwrite"
              ? { entryId: existing.entry_id }
              : { parentEntryId: this.directory!.entry_id, name },
            file,
            {
              signal,
              ...(existing && this.conflictPolicy === "overwrite"
                ? { ifMatch: existing.etag }
                : {}),
              onProgress: (p) => {
                progress(
                  p.totalBytes ? p.transferredBytes / p.totalBytes : 0,
                  `${fmtBytes(p.transferredBytes)} transferred`,
                );
                this.emit("slatefs-upload-progress", {
                  version: 1,
                  file: file.name,
                  ...p,
                });
              },
            },
          ),
        existing ? [existing.entry_id] : [],
      );
    }
  }
  private drop(e: DragEvent) {
    e.preventDefault();
    this.dragging = false;
    if (e.dataTransfer?.files.length) void this.upload(e.dataTransfer.files);
    else {
      const id =
        e.dataTransfer?.getData("application/x-slatefs-entry") ||
        e.dataTransfer?.getData("text/plain");
      if (id) {
        this.clipboard = { mode: "move", ids: [id] };
        const target = e
          .composedPath()
          .find(
            (candidate): candidate is HTMLElement =>
              candidate instanceof HTMLElement &&
              Boolean(candidate.dataset.entryId),
          );
        const destination = this.entries.find(
          (entry) =>
            entry.entry_id === target?.dataset.entryId &&
            entry.kind === "directory",
        );
        void this.paste(destination ?? this.directory);
      }
    }
    this.requestUpdate();
  }
  clearSelection() {
    this.selection = [];
    this.emit("slatefs-selection-change", { version: 1, selection: [] });
    this.requestUpdate();
  }
  clearTransientState() {
    this.clipboard = null;
    this.dragging = false;
    this.requestUpdate();
  }
  cancelOperation(id: string) {
    this.operationController?.cancel(id);
  }
  focusEntry(id: string) {
    const i = this.entries.findIndex((e) => e.entry_id === id);
    if (i >= 0)
      this.renderRoot
        .querySelector<HTMLElement>(`[data-index='${i}']`)
        ?.focus();
  }
  openEntry(id: string) {
    const e = this.entries.find((x) => x.entry_id === id);
    if (e) this.open(e);
  }
  protected override render() {
    const crumbs = this.path.split("/").filter(Boolean);
    const visible: Entry[] = this.entries.slice(
      this.renderStart,
      this.renderStart + this.renderLimit,
    );
    const canWriteDirectory =
      !this.readOnlyView && (this.directory?.can_write ?? false);
    const selectedEntries: Entry[] = this.entries.filter((entry) =>
      this.selection.includes(entry.entry_id),
    );
    return html`<section
      part="inspector"
      aria-label=${this.componentLabel}
      class=${this.dragging ? "drop" : ""}
      @dragover=${(e: DragEvent) => {
        e.preventDefault();
        if (e.dataTransfer)
          e.dataTransfer.dropEffect = e.dataTransfer.files.length
            ? "copy"
            : "move";
        this.dragging = true;
        this.requestUpdate();
      }}
      @dragleave=${() => {
        this.dragging = false;
        this.requestUpdate();
      }}
      @drop=${this.drop}
    >
      <header class="toolbar" part="toolbar">
        <button
          @click=${() => this.create("directory")}
          ?disabled=${!canWriteDirectory}
        >
          New folder</button
        ><button
          @click=${() => this.create("file")}
          ?disabled=${!canWriteDirectory}
        >
          New file</button
        ><label class="button" aria-label="Upload files"
          >Upload<input
            class="sr-only"
            type="file"
            multiple
            @change=${(e: Event) =>
              this.upload((e.target as HTMLInputElement).files!)}
            ?disabled=${!canWriteDirectory} /></label
        ><button
          @click=${() => {
            this.clipboard = { mode: "copy", ids: [...this.selection] };
            this.requestUpdate();
          }}
          ?disabled=${!this.selection.length}
        >
          Copy</button
        ><button
          @click=${() => {
            this.clipboard = { mode: "move", ids: [...this.selection] };
            this.requestUpdate();
          }}
          ?disabled=${!this.selection.length ||
          selectedEntries.some((entry) => !entry.can_rename) ||
          this.readOnlyView}
        >
          Cut</button
        ><button
          @click=${() => this.paste()}
          ?disabled=${!this.clipboard || !canWriteDirectory}
        >
          Paste</button
        ><button
          @click=${this.duplicateSelected}
          ?disabled=${!this.selection.length || !canWriteDirectory}
        >
          Duplicate</button
        ><button
          @click=${() => {
            const entry = selectedEntries[0];
            if (entry) void this.rename(entry);
          }}
          ?disabled=${selectedEntries.length !== 1 ||
          !selectedEntries[0]?.can_rename ||
          this.readOnlyView}
        >
          Rename</button
        ><button
          @click=${this.deleteSelected}
          ?disabled=${!this.selection.length ||
          this.readOnlyView ||
          selectedEntries.some((entry) => !entry.can_delete)}
        >
          Delete</button
        ><label
          >On collision
          <select
            .value=${this.conflictPolicy}
            @change=${(event: Event) => {
              this.conflictPolicy = (event.target as HTMLSelectElement)
                .value as typeof this.conflictPolicy;
            }}
            ?disabled=${this.readOnlyView}
          >
            <option value="fail">Stop and report</option>
            <option value="keep_both">Keep both</option>
            <option value="skip">Skip existing</option>
            <option value="overwrite">Overwrite</option>
          </select> </label
        ><input
          class="grow"
          type="search"
          placeholder="Filter this folder"
          .value=${this.filter}
          @input=${(e: Event) => {
            this.filter = (e.target as HTMLInputElement).value;
            this.entries = this.arrange(this.loadedEntries);
            this.reconcileSelection();
            this.requestUpdate();
          }}
        /><span class="badge">${this.selection.length} selected</span>
      </header>
      ${this.readOnlyView
        ? html`<p class="banner" part="readonly-banner">
            Historical views are read-only. Return to Live files to make
            changes.
          </p>`
        : nothing}
      <p class="sr-only" id="recursive-delete-help">
        Folder deletion requires a host handling the
        slatefs-recursive-delete-request event until bounded delete previews are
        supported by the server.
      </p>
      <nav class="crumbs" part="breadcrumb" aria-label="Breadcrumb">
        <button
          @click=${() => {
            this.path = "/";
            this.directoryEntryId = "";
            this.emit("slatefs-path-change", {
              version: 1,
              volume: this.volume,
              path: "/",
            });
          }}
        >
          Files</button
        >${crumbs.map(
          (c, i) =>
            html`<span aria-hidden="true">/</span
              ><button
                @click=${() => {
                  this.path = "/" + crumbs.slice(0, i + 1).join("/");
                  this.directoryEntryId = "";
                  this.emit("slatefs-path-change", {
                    version: 1,
                    volume: this.volume,
                    path: this.path,
                  });
                }}
              >
                ${c}
              </button>`,
        )}
      </nav>
      ${this.stateTemplate(this.refresh)}${this.entries.length
        ? html`<div
              class="table"
              part="details-grid"
              role="grid"
              aria-label="Directory entries"
            >
              <div class="head" role="row">
                <button
                  class="cell"
                  role="columnheader"
                  @click=${() => {
                    this.sort = "name";
                    this.entries = this.arrange(this.entries);
                    this.requestUpdate();
                  }}
                >
                  Name</button
                ><button
                  class="cell meta"
                  role="columnheader"
                  @click=${() => {
                    this.sort = "type";
                    this.entries = this.arrange(this.entries);
                    this.requestUpdate();
                  }}
                >
                  Type</button
                ><button
                  class="cell meta"
                  role="columnheader"
                  @click=${() => {
                    this.sort = "size";
                    this.entries = this.arrange(this.entries);
                    this.requestUpdate();
                  }}
                >
                  Size</button
                ><button
                  class="cell meta"
                  role="columnheader"
                  @click=${() => {
                    this.sort = "modified";
                    this.entries = this.arrange(this.entries);
                    this.requestUpdate();
                  }}
                >
                  Modified
                </button>
              </div>
              ${visible.map((entry, visibleIndex) => {
                const i = this.renderStart + visibleIndex;
                return html`<div
                  class="entry ${i === this.focused ? "focused" : ""}"
                  part="row"
                  role="row"
                  aria-selected=${this.selection.includes(entry.entry_id)}
                  tabindex=${i === this.focused ? 0 : -1}
                  data-index=${i}
                  data-entry-id=${entry.entry_id}
                  draggable=${!this.readOnlyView}
                  @dragstart=${(e: DragEvent) => {
                    if (!e.dataTransfer) return;
                    e.dataTransfer.effectAllowed = "move";
                    e.dataTransfer.setData(
                      "application/x-slatefs-entry",
                      entry.entry_id,
                    );
                    e.dataTransfer.setData("text/plain", entry.entry_id);
                  }}
                  @dragend=${() => {
                    this.dragging = false;
                    this.requestUpdate();
                  }}
                  @click=${(e: MouseEvent) =>
                    this.select(i, e.shiftKey, e.metaKey || e.ctrlKey)}
                  @dblclick=${() => this.open(entry)}
                  @keydown=${(e: KeyboardEvent) => this.key(e, i)}
                >
                  <div class="cell name" role="gridcell">
                    <svg
                      class="entry-icon"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      stroke-width="1.7"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      aria-hidden="true"
                    >
                      ${entry.kind === "directory"
                        ? html`<path
                            d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"
                          />`
                        : entry.kind === "symlink"
                          ? html`<path d="M7 17 17 7" /><path d="M9 7h8v8" />`
                          : html`<path
                                d="M6 3h8l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"
                              /><path d="M14 3v4h4" />`}
                    </svg>
                    ${displayEntryName(entry)}<span class="mobile"
                      >${entry.kind} · ${fmtBytes(entry.size)} ·
                      ${date(entry.modified_at)}</span
                    >
                  </div>
                  <div class="cell meta" role="gridcell">
                    ${entry.kind}${entry.link_count > 1
                      ? ` · ${entry.link_count} links`
                      : ""}
                  </div>
                  <div class="cell meta" role="gridcell">
                    ${entry.kind === "directory"
                      ? "—"
                      : fmtBytes(entry.size_decimal ?? entry.size)}
                  </div>
                  <div class="cell meta" role="gridcell">
                    <time datetime=${dateTimeAttribute(entry.modified_at)}
                      >${date(entry.modified_at)}</time
                    >
                  </div>
                </div>`;
              })}
            </div>
            <div class="body split" part="pagination">
              <button
                @click=${() => {
                  this.renderStart = Math.max(
                    0,
                    this.renderStart - this.renderLimit,
                  );
                  this.requestUpdate();
                }}
                ?disabled=${this.renderStart === 0}
              >
                Previous rows
              </button>
              <span class="muted"
                >${this.renderStart + 1}–${Math.min(
                  this.entries.length,
                  this.renderStart + this.renderLimit,
                )}
                of ${this.entries.length} loaded</span
              >
              <button
                @click=${() => {
                  this.renderStart += this.renderLimit;
                  this.requestUpdate();
                }}
                ?disabled=${this.renderStart + this.renderLimit >=
                this.entries.length}
              >
                Next rows
              </button>
            </div>
            ${this.next
              ? html`<div class="body">
                  <button @click=${this.loadMore}>Load more</button>
                </div>`
              : nothing}`
        : nothing}<slot name="actions"></slot>
      <div class="sr-only" aria-live="polite">
        ${this.loadState === "ready"
          ? `${this.entries.length} entries loaded`
          : ""}
      </div>
      ${this.actionDialogTemplate()}
    </section>`;
  }
}

type PreviewClient = Pick<FileSystemClient, "readContent" | "uploadContent">;
/** Safe bounded preview and ETag-aware small text editor. */
export class SlateFsFilePreview extends SlateFsElement<PreviewClient> {
  static override properties = {
    ...SlateFsElement.properties,
    entry: { attribute: false },
    editable: { type: Boolean, reflect: true },
    maxPreviewBytes: { type: Number, attribute: "max-preview-bytes" },
  };
  readonly componentLabel = "SlateFS file preview";
  entry?: Entry;
  editable = false;
  maxPreviewBytes = 1024 * 1024;
  private content = "";
  private bytes?: Uint8Array;
  private mime = "";
  private etag = "";
  private dirty = false;
  private saveError = "";
  private objectUrl = "";
  private loadedEntryId = "";
  private loadedVolume = "";
  protected override updated(changes: PropertyValues) {
    if (
      changes.has("client") ||
      changes.has("entry") ||
      changes.has("view") ||
      changes.has("volume") ||
      changes.has("maxPreviewBytes")
    )
      defer(() => this.load());
  }
  async load() {
    this.cleanup();
    this.content = "";
    this.bytes = undefined;
    this.mime = "";
    this.etag = "";
    this.loadedEntryId = "";
    this.loadedVolume = "";
    this.saveError = "";
    this.setDirty(false);
    if (!this.client || !this.entry || this.entry.kind !== "file") {
      this.resetLoad(this.entry ? "unsupported" : "empty");
      return;
    }
    const entry = this.entry;
    if (exceedsBytes(entry.size_decimal, entry.size, this.maxPreviewBytes)) {
      this.resetLoad("unsupported");
      this.errorMessage = `File is larger than the ${fmtBytes(this.maxPreviewBytes)} preview limit.`;
      this.requestUpdate();
      return;
    }
    const { signal, serial } = this.beginLoad();
    if (isZeroBytes(entry.size_decimal, entry.size)) {
      this.bytes = new Uint8Array();
      this.mime = previewMime("application/octet-stream", entry.name);
      this.etag = entry.etag;
      this.loadedEntryId = entry.entry_id;
      this.loadedVolume = this.volume;
      this.finishLoad(serial, "ready");
      return;
    }
    try {
      const result = await this.client.readContent(
        this.volume,
        selector(entry),
        this.view,
        {
          signal,
          range: { start: 0, end: Math.max(0, this.maxPreviewBytes - 1) },
        },
      );
      if (!this.loadCurrent(serial)) return;
      const bytes = await readStream(result.body, this.maxPreviewBytes);
      if (!this.loadCurrent(serial)) return;
      this.bytes = bytes;
      this.mime = previewMime(result.contentType, entry.name);
      this.etag = result.etag || entry.etag;
      if (isText(this.mime)) {
        this.content = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      } else if (
        isRasterImage(this.mime) ||
        this.mime.startsWith("audio/") ||
        this.mime.startsWith("video/") ||
        this.mime === "application/pdf"
      ) {
        this.objectUrl = URL.createObjectURL(
          new Blob([bytes], { type: this.mime }),
        );
      }
      this.loadedEntryId = entry.entry_id;
      this.loadedVolume = this.volume;
      this.finishLoad(serial, "ready");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async save() {
    if (!this.client || !this.entry || !this.canEdit) return;
    const entry = this.entry;
    const content = this.content;
    const etag = this.etag;
    const operation = {
      version: 1 as const,
      operation: "save",
      entryIds: [entry.entry_id],
    };
    if (!this.emit("slatefs-before-operation", operation, true)) return;
    this.emit("slatefs-operation-start", operation);
    this.saveError = "";
    try {
      const saved = await this.client.uploadContent(
        this.volume,
        selector(entry),
        new Blob([content], { type: this.mime }),
        { ifMatch: etag },
      );
      if (this.entry?.entry_id === entry.entry_id) {
        this.entry = saved;
        this.etag = saved.etag;
        this.setDirty(false);
      }
      this.emit("slatefs-save-complete", {
        version: 1,
        entry: copyEntry(saved),
      });
      this.emit("slatefs-operation-complete", operation);
      this.requestUpdate();
    } catch (e) {
      if ((e as { status?: number }).status === 412) {
        this.emit("slatefs-conflict", {
          version: 1,
          entry: copyEntry(entry),
          message: "The file changed on the server.",
        });
        this.saveError =
          "This file changed elsewhere. Reload before saving again.";
        this.requestUpdate();
      } else {
        this.saveError = e instanceof Error ? e.message : "Save failed";
        this.emit("slatefs-operation-error", {
          version: 1,
          operation: "save",
          entryIds: [entry.entry_id],
          code: (e as { code?: string }).code ?? "error",
          message: this.saveError,
        });
        this.requestUpdate();
      }
    }
  }
  get canEdit() {
    return (
      this.editable &&
      !this.readOnlyView &&
      !!this.entry?.can_write &&
      this.entry.entry_id === this.loadedEntryId &&
      this.volume === this.loadedVolume &&
      isText(this.mime) &&
      !exceedsBytes(
        this.entry.size_decimal,
        this.entry.size,
        this.maxPreviewBytes,
      )
    );
  }
  download() {
    if (this.entry)
      this.emit(
        "slatefs-download-request",
        {
          version: 1,
          entry: copyEntry(this.entry),
          view: copyView(this.view),
        },
        true,
      );
  }
  discard() {
    this.setDirty(false);
    void this.load();
  }
  private setDirty(dirty: boolean) {
    if (this.dirty === dirty) return;
    this.dirty = dirty;
    this.emit("slatefs-edit-dirty", {
      version: 1,
      entry: this.entry ? copyEntry(this.entry) : undefined,
      dirty,
    });
    this.requestUpdate();
  }
  private cleanup() {
    if (this.objectUrl) URL.revokeObjectURL(this.objectUrl);
    this.objectUrl = "";
  }
  override disconnectedCallback() {
    this.cleanup();
    super.disconnectedCallback();
  }
  protected override render() {
    let preview: TemplateResult | typeof nothing = nothing;
    if (this.loadState === "ready") {
      if (isText(this.mime))
        preview = this.canEdit
          ? html`<textarea
              part="editor"
              aria-label="File contents"
              .value=${this.content}
              @input=${(e: Event) => {
                this.content = (e.target as HTMLTextAreaElement).value;
                this.saveError = "";
                this.setDirty(true);
              }}
            ></textarea>`
          : html`<pre part="text">${this.content}</pre>`;
      else if (isRasterImage(this.mime))
        preview = html`<img
          part="image"
          src=${this.objectUrl}
          alt=${this.entry?.name ?? "File preview"}
        />`;
      else if (this.mime.startsWith("audio/"))
        preview = html`<audio
          part="media"
          controls
          src=${this.objectUrl}
        ></audio>`;
      else if (this.mime.startsWith("video/"))
        preview = html`<video
          part="media"
          controls
          src=${this.objectUrl}
        ></video>`;
      else if (this.mime === "application/pdf")
        preview = html`<iframe
          part="preview"
          sandbox
          title="PDF preview"
          src=${this.objectUrl}
        ></iframe>`;
      else
        preview = html`<div class="state">
          Binary preview unavailable. Download to open this file safely.
        </div>`;
    }
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>${this.entry ? displayEntryName(this.entry) : "Preview"}</h2>
        <span class="badge"
          >${this.mime || this.entry?.kind || "No selection"}</span
        ><button @click=${this.download} ?disabled=${!this.entry}>
          Download</button
        >${this.canEdit
          ? html`<button
              class="primary"
              @click=${this.save}
              ?disabled=${!this.dirty}
            >
              Save
            </button>`
          : nothing}
      </header>
      ${this.readOnlyView
        ? html`<p class="banner" part="readonly-banner">
            Previewing a read-only historical view.
          </p>`
        : nothing}${this.saveError
        ? html`<p class="banner error" part="save-error" role="alert">
            ${this.saveError}
          </p>`
        : nothing}${this.stateTemplate(this.load)}
      <div class="body" part="preview">
        ${preview}<slot name="fallback"></slot>
      </div>
    </section>`;
  }
}

type MetadataClient = Pick<
  FileSystemClient,
  "getXattrs" | "updateEntry" | "updateXattrs"
> &
  Partial<Pick<FileSystemClient, "getCapabilities">>;
/** Identity, POSIX metadata, links, and byte-safe xattrs. */
export class SlateFsMetadataPanel extends SlateFsElement<MetadataClient> {
  static override properties = {
    ...SlateFsElement.properties,
    entry: { attribute: false },
    showAdvanced: { type: Boolean, attribute: "show-advanced" },
  };
  readonly componentLabel = "SlateFS metadata panel";
  entry?: Entry;
  showAdvanced = false;
  private xattrs: XattrValue[] = [];
  protected override updated(changes: PropertyValues) {
    if (
      changes.has("client") ||
      changes.has("entry") ||
      changes.has("view") ||
      changes.has("volume")
    )
      defer(() => this.refresh());
  }
  async refresh() {
    if (!this.client || !this.entry) {
      this.xattrs = [];
      this.resetLoad(this.entry ? "unsupported" : "empty");
      return;
    }
    const entry = this.entry;
    const { signal, serial } = this.beginLoad();
    try {
      if (this.client.getCapabilities) {
        const capabilities = await this.client.getCapabilities({ signal });
        if (!this.loadCurrent(serial)) return;
        if (!capabilities.features.xattrs) {
          this.xattrs = [];
          this.finishLoad(serial, "unsupported");
          return;
        }
      }
      const result = await this.client.getXattrs(
        this.volume,
        entry.entry_id,
        this.view,
        { signal },
      );
      if (!this.loadCurrent(serial)) return;
      this.xattrs = result.xattrs;
      this.finishLoad(serial);
    } catch (e) {
      if ((e as { status?: number }).status === 404) {
        this.xattrs = [];
        this.finishLoad(serial);
      } else this.failLoad(serial, e);
    }
  }
  async beginEdit() {
    const values = await this.ask({
      title: "Edit POSIX mode",
      description: "Enter a three- or four-digit octal mode.",
      submitLabel: "Apply mode",
      fields: [
        {
          name: "mode",
          label: "POSIX mode (octal)",
          value: this.entry?.mode.toString(8),
          required: true,
          pattern: "[0-7]{3,4}",
        },
      ],
    });
    const value = values?.mode;
    if (!value || !this.entry || !this.client) return;
    const mode = Number.parseInt(value, 8);
    if (!/^[0-7]{3,4}$/.test(value) || !Number.isInteger(mode) || mode > 0o7777)
      return;
    if (
      !this.emit(
        "slatefs-before-operation",
        {
          version: 1,
          operation: "change-mode",
          entryIds: [this.entry.entry_id],
        },
        true,
      )
    )
      return;
    try {
      this.entry = await this.client.updateEntry(
        this.volume,
        { entry_id: this.entry.entry_id, mode },
        { ifMatch: this.entry.etag },
      );
      this.emit("slatefs-properties-change", {
        version: 1,
        entry: copyEntry(this.entry),
      });
    } catch (e) {
      this.emit("slatefs-conflict", {
        version: 1,
        entry: copyEntry(this.entry),
        message: e instanceof Error ? e.message : "Metadata conflict",
      });
    }
    this.requestUpdate();
  }
  async save() {
    await this.refresh();
  }
  async setXattr() {
    if (
      !this.client ||
      !this.entry ||
      this.readOnlyView ||
      !this.entry.can_write
    )
      return;
    const values = await this.ask({
      title: "Add or replace attribute",
      description: "Set a UTF-8 extended attribute on this item.",
      submitLabel: "Save attribute",
      fields: [
        { name: "name", label: "Extended attribute name", required: true },
        { name: "value", label: "UTF-8 value" },
      ],
    });
    const name = values?.name?.trim();
    if (!name || /[\0]/.test(name)) return;
    const value = values?.value;
    if (value === undefined) return;
    if (
      !this.emit(
        "slatefs-before-operation",
        {
          version: 1,
          operation: "set-xattr",
          entryIds: [this.entry.entry_id],
        },
        true,
      )
    )
      return;
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    try {
      const result = await this.client.updateXattrs(
        this.volume,
        this.entry.entry_id,
        { set: { [name]: btoa(binary) } },
        { ifMatch: this.entry.etag },
      );
      this.xattrs = result.xattrs;
      this.requestUpdate();
    } catch (error) {
      this.emit("slatefs-conflict", {
        version: 1,
        operation: "set-xattr",
        message: error instanceof Error ? error.message : "Update failed",
      });
    }
  }
  async setByteXattr() {
    if (
      !this.client ||
      !this.entry ||
      this.readOnlyView ||
      !this.entry.can_write
    )
      return;
    const values = await this.ask({
      title: "Add byte-named attribute",
      description: "Names and values must be valid base64.",
      submitLabel: "Save attribute",
      fields: [
        {
          name: "name",
          label: "Attribute name bytes (base64)",
          required: true,
        },
        {
          name: "value",
          label: "Attribute value bytes (base64)",
          required: true,
        },
      ],
    });
    const name = values?.name?.trim();
    const value = values?.value?.trim();
    if (!name || value === undefined || value === null) return;
    try {
      atob(name);
      atob(value);
    } catch {
      this.reportActionError(
        "set-byte-xattr",
        new Error("Names and values must be valid base64"),
        [this.entry.entry_id],
      );
      return;
    }
    if (
      !this.emit(
        "slatefs-before-operation",
        {
          version: 1,
          operation: "set-byte-xattr",
          entryIds: [this.entry.entry_id],
        },
        true,
      )
    )
      return;
    try {
      const result = await this.client.updateXattrs(
        this.volume,
        this.entry.entry_id,
        {
          set_bytes: [{ name_bytes_base64: name, value_base64: value }],
        },
        { ifMatch: this.entry.etag },
      );
      this.xattrs = result.xattrs;
      this.requestUpdate();
    } catch (error) {
      this.reportActionError("set-byte-xattr", error, [this.entry.entry_id]);
    }
  }
  async removeXattr(value: XattrValue) {
    if (
      !this.client ||
      !this.entry ||
      this.readOnlyView ||
      !this.entry.can_write
    )
      return;
    if (
      !(await this.confirmAction(
        "Remove extended attribute",
        `Remove ${value.name ?? "this byte-named attribute"}?`,
        "Remove attribute",
        true,
      ))
    )
      return;
    const request = value.name
      ? { remove: [value.name] }
      : { remove_bytes_base64: [value.name_bytes_base64] };
    if (
      !this.emit(
        "slatefs-before-operation",
        {
          version: 1,
          operation: "remove-xattr",
          entryIds: [this.entry.entry_id],
        },
        true,
      )
    )
      return;
    try {
      const result = await this.client.updateXattrs(
        this.volume,
        this.entry.entry_id,
        request,
        { ifMatch: this.entry.etag },
      );
      this.xattrs = result.xattrs;
      this.requestUpdate();
    } catch (error) {
      this.reportActionError("remove-xattr", error, [this.entry.entry_id]);
    }
  }
  protected override render() {
    const e = this.entry;
    if (!e)
      return html`<section part="inspector" aria-label=${this.componentLabel}>
        ${this.stateTemplate(this.refresh)}
      </section>`;
    const rows: [[string, unknown], ...[string, unknown][]] = [
      ["Type", e.kind],
      ["Size", fmtLosslessBytes(e.size_decimal, e.size)],
      [
        "Allocated",
        fmtLosslessBytes(e.allocated_bytes_decimal, e.allocated_bytes),
      ],
      ["Name bytes (base64)", e.name_bytes_base64],
      ["Modified", date(e.modified_at)],
      ["Created", date(e.created_at)],
      ["Mode", e.mode.toString(8).padStart(4, "0")],
      ["Owner", `${e.uid}:${e.gid}`],
      ["Links", e.link_count_decimal ?? e.link_count],
      ["Inode", e.inode_decimal ?? e.inode],
      ["Generation", e.generation_decimal ?? e.generation],
    ];
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Details</h2>
        <button
          @click=${this.beginEdit}
          ?disabled=${this.readOnlyView || !e.can_write}
        >
          Edit mode
        </button>
      </header>
      ${this.readOnlyView
        ? html`<p class="banner">Metadata is read-only in this view.</p>`
        : nothing}
      <div class="body" part="metadata">
        <dl>
          ${rows.map(
            ([k, v]) =>
              html`<dt class="muted">${k}</dt>
                <dd>${String(v)}</dd>`,
          )}
        </dl>
        ${e.symlink_target
          ? html`<div part="symlink">
              <strong>Symlink target</strong>
              <p>${e.symlink_target}</p>
            </div>`
          : nothing}
        <div part="xattrs">
          <h3>Extended attributes</h3>
          <button
            @click=${this.setXattr}
            ?disabled=${this.readOnlyView || !e.can_write}
          >
            Add or replace attribute
          </button>
          <button
            @click=${this.setByteXattr}
            ?disabled=${this.readOnlyView || !e.can_write}
          >
            Add byte-named attribute
          </button>
          ${this.xattrs.length
            ? html`<ul class="list">
                ${this.xattrs.map(
                  (x) =>
                    html`<li class="row" part="xattr-row">
                      <code>${x.name ?? `bytes:${x.name_bytes_base64}`}</code>
                      <span class="muted">${x.value_base64}</span>
                      <button
                        aria-label=${`Remove ${x.name ?? "byte-named attribute"}`}
                        @click=${() => this.removeXattr(x)}
                        ?disabled=${this.readOnlyView || !e.can_write}
                      >
                        Remove
                      </button>
                    </li>`,
                )}
              </ul>`
            : html`<p class="muted">No extended attributes.</p>`}
        </div>
      </div>
      ${this.actionDialogTemplate()}
    </section>`;
  }
}

/** Snapshot list/create/read-only browse/clone. */
export class SlateFsSnapshotBrowser extends SlateFsElement<SnapshotClient> {
  readonly componentLabel = "SlateFS snapshot browser";
  private snapshots: Array<Record<string, unknown>> = [];
  private next: string | null = null;
  protected override updated(c: PropertyValues) {
    if (c.has("client") || c.has("volume")) defer(() => this.refresh());
  }
  async refresh() {
    this.snapshots = [];
    this.next = null;
    await this.page();
  }
  async loadMore() {
    if (this.next) await this.page(this.next);
  }
  private async page(pageToken?: string) {
    if (!this.client || !this.volume) {
      this.loadState = this.client ? "empty" : "unsupported";
      this.requestUpdate();
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      const r = await this.client.listSnapshots(this.volume, {
        limit: 50,
        pageToken,
        signal,
      });
      if (!this.loadCurrent(serial)) return;
      this.snapshots = pageToken
        ? [...this.snapshots, ...r.snapshots]
        : r.snapshots;
      this.next = r.next_page_token ?? null;
      this.finishLoad(serial, this.snapshots.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async createSnapshot() {
    if (!this.client || this.readOnlyView) return;
    const values = await this.ask({
      title: "Create snapshot",
      description:
        "Create an immutable point-in-time view. The name is optional.",
      submitLabel: "Create snapshot",
      fields: [{ name: "name", label: "Snapshot name (optional)" }],
    });
    if (!values) return;
    const name = values.name?.trim() || undefined;
    try {
      await this.client.createSnapshot(this.volume, name);
      this.emit("slatefs-operation-complete", {
        version: 1,
        operation: "create-snapshot",
        entryIds: [],
      });
      await this.refresh();
    } catch (error) {
      this.reportActionError("create-snapshot", error);
    }
  }
  openSnapshot(ref: string) {
    this.emit("slatefs-view-change", {
      version: 1,
      view: { kind: "snapshot", ref } satisfies ViewSelection,
    });
  }
  returnLive() {
    this.emit("slatefs-view-change", {
      version: 1,
      view: { kind: "live" } satisfies ViewSelection,
    });
  }
  async cloneSnapshot(ref: string) {
    if (!this.client) return;
    const values = await this.ask({
      title: "Create writable copy",
      description: "Choose a volume name for the writable snapshot copy.",
      submitLabel: "Create writable copy",
      fields: [
        {
          name: "name",
          label: "Volume name",
          required: true,
          pattern: "[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
        },
      ],
    });
    const name = values?.name?.trim();
    if (!name || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) return;
    const operation = {
      version: 1 as const,
      operation: "clone-snapshot",
      entryIds: [] as string[],
    };
    if (!this.emit("slatefs-before-operation", operation, true)) return;
    this.emit("slatefs-operation-start", operation);
    try {
      const r = await this.client.cloneSnapshot(this.volume, ref, name);
      this.emit("slatefs-volume-change", {
        version: 1,
        volume: r.clone.volume,
      });
      this.emit("slatefs-operation-complete", operation);
    } catch (error) {
      this.reportActionError("clone-snapshot", error);
    }
  }
  protected override render() {
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Snapshots</h2>
        <button @click=${this.createSnapshot} ?disabled=${this.readOnlyView}>
          Create snapshot</button
        >${this.view.kind === "snapshot"
          ? html`<button class="primary" @click=${this.returnLive}>
              Return to live files
            </button>`
          : nothing}
      </header>
      ${this.view.kind === "snapshot"
        ? html`<p class="banner">
            Browsing snapshot ${this.view.ref}. It cannot be modified.
          </p>`
        : nothing}${this.stateTemplate(this.refresh)}
      <ul class="list" part="snapshot-list">
        ${this.snapshots.map((s) => {
          const ref = String(s.id ?? s.checkpoint ?? "");
          return html`<li class="row split" part="snapshot-row">
            <div class="grow">
              <strong>${String(s.name ?? ref)}</strong>
              <div class="muted">
                ${s.created_at !== undefined &&
                s.created_at !== null &&
                s.created_at !== ""
                  ? date(s.created_at)
                  : s.time !== undefined && s.time !== null && s.time !== ""
                    ? date(s.time)
                    : "Immutable point in time"}
              </div>
            </div>
            <button @click=${() => this.openSnapshot(ref)}>Browse</button
            ><button @click=${() => this.cloneSnapshot(ref)}>
              Create writable copy
            </button>
          </li>`;
        })}
      </ul>
      ${this.next
        ? html`<div class="body">
            <button @click=${this.loadMore}>Load more</button>
          </div>`
        : nothing}
      ${this.actionDialogTemplate()}
    </section>`;
  }
}

type StatusClient = Pick<
  VersionClient,
  "getVersionPolicy" | "enableVersioning" | "getStatus" | "commit"
>;
export class SlateFsVersionStatus extends SlateFsElement<StatusClient> {
  static override properties = {
    ...SlateFsElement.properties,
    reference: { type: String },
    paths: { attribute: false },
    targetBranch: { type: String, attribute: "target-branch" },
    author: { type: String },
    versioningEnabled: { attribute: false },
  };
  readonly componentLabel = "SlateFS version status";
  reference = "main";
  paths: readonly string[] = ["/"];
  targetBranch = "main";
  author = "";
  /** Known host state. Leave undefined to discover the volume policy. */
  versioningEnabled?: boolean;
  private enabled = false;
  private changes: Array<Record<string, unknown>> = [];
  private selectedPaths = new Set<string>();
  protected override updated(c: PropertyValues) {
    if (
      c.has("client") ||
      c.has("volume") ||
      c.has("reference") ||
      c.has("path") ||
      c.has("paths") ||
      c.has("versioningEnabled")
    )
      defer(() => this.refresh());
  }
  async refresh() {
    if (!this.client || !this.volume) {
      this.loadState = "unsupported";
      this.requestUpdate();
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      this.enabled =
        this.versioningEnabled ??
        (await this.client.getVersionPolicy(this.volume, { signal })).versioning
          .enabled;
      if (!this.enabled) {
        this.finishLoad(serial, "empty");
        return;
      }
      const r = await this.client.getStatus(
        this.volume,
        { reference: this.reference, path: this.path },
        { signal },
      );
      if (!this.loadCurrent(serial)) return;
      this.changes = r.status.changes;
      this.selectedPaths = new Set(
        this.changes.map((change) => String(change.path)),
      );
      this.finishLoad(serial, this.changes.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async enable() {
    if (!this.client) return;
    const operation = {
      version: 1 as const,
      operation: "enable-versioning",
      entryIds: [] as string[],
    };
    if (!this.emit("slatefs-before-operation", operation, true)) return;
    this.emit("slatefs-operation-start", operation);
    try {
      await this.client.enableVersioning(this.volume);
      this.versioningEnabled = true;
      this.emit("slatefs-operation-complete", operation);
      await this.refresh();
    } catch (error) {
      this.reportActionError("enable-versioning", error);
    }
  }
  async commitSelected() {
    if (!this.client || !this.selectedPaths.size) return;
    const values = await this.ask({
      title: "Save a new version",
      description: `${this.selectedPaths.size} selected path(s) will be saved as a new version on ${this.targetBranch}.`,
      submitLabel: "Save new version",
      fields: [{ name: "message", label: "Commit message", required: true }],
    });
    const message = values?.message?.trim();
    if (!message) return;
    const operation = {
      version: 1 as const,
      operation: "save-new-version",
      entryIds: [] as string[],
    };
    if (!this.emit("slatefs-before-operation", operation, true)) return;
    this.emit("slatefs-operation-start", operation);
    try {
      const r = await this.client.commit(
        this.volume,
        {
          branch: this.targetBranch,
          paths: [...this.selectedPaths],
          message,
          ...(this.author ? { author: this.author } : {}),
        },
        {
          idempotencyKey: globalThis.crypto?.randomUUID?.(),
        },
      );
      this.emit("slatefs-version-commit", {
        version: 1,
        commit: { ...r.commit },
      });
      this.emit("slatefs-operation-complete", operation);
      await this.refresh();
    } catch (error) {
      this.reportActionError("save-new-version", error);
    }
  }
  protected override render() {
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Version status</h2>
        <span class="badge"
          >${this.enabled ? this.targetBranch : "Not enabled"}</span
        >${!this.enabled
          ? html`<button @click=${this.enable} ?disabled=${this.readOnlyView}>
              Enable versioning
            </button>`
          : html`<button
              class="primary"
              @click=${this.commitSelected}
              ?disabled=${this.readOnlyView || !this.selectedPaths.size}
            >
              Save new version
            </button>`}
      </header>
      ${this.stateTemplate(this.refresh)}${this.enabled &&
      !this.changes.length &&
      this.loadState === "empty"
        ? html`<div class="state">
            Live files match the latest published version.
          </div>`
        : nothing}
      <ul class="list">
        ${this.changes.map(
          (c) =>
            html`<li class="row" part="change-row">
              <label
                ><input
                  type="checkbox"
                  .checked=${this.selectedPaths.has(String(c.path))}
                  @change=${(event: Event) => {
                    const path = String(c.path);
                    if ((event.target as HTMLInputElement).checked)
                      this.selectedPaths.add(path);
                    else this.selectedPaths.delete(path);
                    this.requestUpdate();
                  }}
                /><span class="badge">${String(c.change)}</span> ${String(
                  c.path,
                )}</label
              >
            </li>`,
        )}
      </ul>
      ${this.actionDialogTemplate()}
    </section>`;
  }
}

type HistoryClient = Pick<
  VersionClient,
  "getLog" | "showCommit" | "getTags" | "createTag"
>;
export class SlateFsVersionHistory extends SlateFsElement<HistoryClient> {
  static override properties = {
    ...SlateFsElement.properties,
    reference: { type: String },
    pathFilter: { type: String, attribute: "path-filter" },
    selectedCommit: { type: String, attribute: "selected-commit" },
  };
  readonly componentLabel = "SlateFS version history";
  reference = "main";
  pathFilter = "";
  selectedCommit = "";
  private commits: Array<Record<string, unknown>> = [];
  private next: string | null = null;
  private detail?: Record<string, unknown>;
  protected override updated(c: PropertyValues) {
    if (c.has("client") || c.has("volume") || c.has("reference"))
      defer(() => this.refresh());
  }
  async refresh() {
    this.commits = [];
    await this.page();
  }
  async loadMore() {
    await this.page(this.next ?? undefined);
  }
  private async page(token?: string) {
    if (!this.client || !this.volume) {
      this.loadState = "unsupported";
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      const r = await this.client.getLog(this.volume, this.reference, {
        limit: 50,
        pageToken: token,
        signal,
      });
      if (!this.loadCurrent(serial)) return;
      this.commits = token ? [...this.commits, ...r.commits] : r.commits;
      this.next = r.next_page_token ?? null;
      this.finishLoad(serial, this.commits.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async openCommit(id: string) {
    this.selectedCommit = id;
    this.emit("slatefs-commit-select", { version: 1, commit: id });
    if (!this.client) return;
    try {
      const result = await this.client.showCommit(this.volume, id);
      this.detail = { ...result.commit };
      this.requestUpdate();
    } catch (error) {
      this.errorMessage =
        error instanceof Error ? error.message : "Unable to load commit";
      this.loadState = "error";
      this.requestUpdate();
    }
  }
  async createTag(id: string) {
    if (!this.client) return;
    const values = await this.ask({
      title: "Create tag",
      description: `Create a tag for commit ${id.slice(0, 12)}.`,
      submitLabel: "Create tag",
      fields: [{ name: "name", label: "Tag name", required: true }],
    });
    const name = values?.name?.trim();
    if (!name) return;
    try {
      await this.client.createTag(this.volume, { name, commit: id });
      await this.openCommit(id);
    } catch (error) {
      this.reportActionError("create-tag", error);
    }
  }
  browse(id: string) {
    this.emit("slatefs-view-change", {
      version: 1,
      view: {
        kind: "version",
        ref: id,
        resolvedCommit: id,
      } satisfies ViewSelection,
    });
  }
  protected override render() {
    const list = this.commits.filter(
      (c) => !this.pathFilter || JSON.stringify(c).includes(this.pathFilter),
    );
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Version history</h2>
        <input
          type="search"
          placeholder="Filter path"
          .value=${this.pathFilter}
          @input=${(e: Event) => {
            this.pathFilter = (e.target as HTMLInputElement).value;
            this.requestUpdate();
          }}
        /><button
          @click=${() =>
            this.emit("slatefs-reflog-request", {
              version: 1,
              reference: this.reference,
            })}
        >
          Recovery log
        </button>
      </header>
      ${this.stateTemplate(this.refresh)}
      <ol class="list" part="history">
        ${list.map((c) => {
          const id = String(c.id);
          return html`<li class="row split" part="commit-row">
            <span aria-hidden="true">●</span
            ><button class="grow" @click=${() => void this.openCommit(id)}>
              <strong>${String(c.message ?? "Untitled version")}</strong>
              <div class="muted">
                ${String(c.author ?? "Unknown author")} · ${date(c.created_at)}
                · ${id.slice(0, 10)}
              </div>
              <div part="parents" class="muted">
                Parents:
                ${Array.isArray(c.parents) ? c.parents.join(", ") : "none"}
              </div></button
            ><button @click=${() => this.browse(id)}>Browse</button
            ><button @click=${() => void this.createTag(id)}>Tag</button
            ><button
              @click=${() =>
                this.emit("slatefs-compare-request", {
                  version: 1,
                  from: id,
                  to: this.reference,
                })}
            >
              Compare
            </button>
          </li>`;
        })}
      </ol>
      ${this.detail
        ? html`<details open part="commit-detail">
            <summary>Commit details</summary>
            <pre>${JSON.stringify(this.detail, null, 2)}</pre>
          </details>`
        : nothing}
      ${this.next
        ? html`<div class="body">
            <button @click=${this.loadMore}>Load more</button>
          </div>`
        : nothing}${this.actionDialogTemplate()}
    </section>`;
  }
}

export class SlateFsVersionDiff extends SlateFsElement<
  Pick<VersionClient, "getDiff">
> {
  static override properties = {
    ...SlateFsElement.properties,
    from: { type: String },
    to: { type: String },
    selectedPath: { type: String, attribute: "selected-path" },
    mode: { type: String },
    ignoreWhitespace: { type: Boolean, attribute: "ignore-whitespace" },
    wrap: { type: Boolean, reflect: true },
  };
  readonly componentLabel = "SlateFS version diff";
  from = "main";
  to = "main";
  selectedPath = "";
  mode: "unified" | "structured" = "structured";
  ignoreWhitespace = false;
  wrap = true;
  private changes: Array<Record<string, unknown>> = [];
  private truncated = false;
  private next: string | null = null;
  protected override willUpdate(c: PropertyValues) {
    if (c.has("client") || c.has("volume")) {
      this.changes = [];
      this.next = null;
      this.truncated = false;
      this.resetLoad(
        this.client && this.volume ? "empty" : "unsupported",
        false,
      );
    }
  }
  async refresh() {
    if (!this.client || !this.volume) {
      this.loadState = "unsupported";
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      const r = await this.client.getDiff(this.volume, this.from, this.to, {
        limit: 250,
        signal,
      });
      if (!this.loadCurrent(serial)) return;
      this.changes = r.changes;
      this.next = r.next_page_token ?? null;
      this.truncated = !!this.next;
      this.finishLoad(serial, this.changes.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async loadMore() {
    if (!this.client || !this.next) return;
    const token = this.next;
    const { signal, serial } = this.beginLoad();
    try {
      const result = await this.client.getDiff(
        this.volume,
        this.from,
        this.to,
        {
          limit: 250,
          pageToken: token,
          signal,
        },
      );
      if (!this.loadCurrent(serial)) return;
      this.changes = [...this.changes, ...result.changes];
      this.next = result.next_page_token ?? null;
      this.truncated = !!this.next;
      this.finishLoad(serial, this.changes.length ? "ready" : "empty");
    } catch (error) {
      this.failLoad(serial, error);
    }
  }
  copyPatch() {
    const result = navigator.clipboard?.writeText(
      this.changes.map((c) => `${c.change}\t${c.path}`).join("\n"),
    );
    void result?.catch((error) => this.reportActionError("copy-diff", error));
  }
  protected override render() {
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Compare versions</h2>
        <label
          >From
          <input
            .value=${this.from}
            @input=${(e: Event) => {
              this.from = (e.target as HTMLInputElement).value;
            }} /></label
        ><label
          >To
          <input
            .value=${this.to}
            @input=${(e: Event) => {
              this.to = (e.target as HTMLInputElement).value;
            }} /></label
        ><button @click=${this.copyPatch} ?disabled=${!this.changes.length}>
          Copy summary</button
        ><button
          class="primary"
          @click=${this.refresh}
          ?disabled=${!this.client || !this.volume || !this.from || !this.to}
        >
          Compare
        </button>
      </header>
      ${this.loadState === "empty"
        ? html`<div class="state">Choose two versions and click Compare.</div>`
        : this.stateTemplate(this.refresh)}${this.truncated
        ? html`<p class="banner" part="truncation">
            Diff is truncated at 250 paths. Narrow the comparison to inspect
            safely.
          </p>`
        : nothing}
      ${this.next
        ? html`<div class="body">
            <button @click=${this.loadMore}>Load more changed paths</button>
          </div>`
        : nothing}
      <div part="diff" class="body">
        <p class="muted">
          ${this.changes.length} changed paths. Binary and content patch
          rendering appears only when the server supplies bounded patch data.
        </p>
        <ul class="list">
          ${this.changes.map(
            (c) =>
              html`<li
                class="row"
                part=${String(c.change) === "add"
                  ? "addition"
                  : String(c.change) === "delete"
                    ? "deletion"
                    : "line"}
              >
                <button
                  @click=${() =>
                    this.emit("slatefs-path-change", {
                      version: 1,
                      volume: this.volume,
                      path: String(c.path),
                    })}
                >
                  <span class="badge">${String(c.change)}</span> ${String(
                    c.path,
                  )}
                </button>
              </li>`,
          )}
        </ul>
      </div>
    </section>`;
  }
}

type BranchClient = Pick<VersionClient, "getBranches" | "createBranch"> &
  Pick<
    CollaborationClient,
    | "previewMerge"
    | "applyMerge"
    | "previewCherryPick"
    | "applyCherryPick"
    | "getReflog"
    | "getProtection"
    | "setProtection"
  >;
export class SlateFsBranchManager extends SlateFsElement<BranchClient> {
  static override properties = {
    ...SlateFsElement.properties,
    branch: { type: String },
    source: { type: String },
    conflictStrategy: { type: String, attribute: "conflict-strategy" },
    mainline: { type: Number },
    advanced: { type: Boolean, reflect: true },
  };
  static override styles = [
    SlateFsElement.styles,
    css`
      .branch-list {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(min(18rem, 100%), 1fr));
        gap: 0.75rem;
        min-width: 0;
        max-width: 100%;
        padding: 0.75rem;
      }
      .branch-row {
        display: flex;
        flex-wrap: wrap;
        align-items: start;
        gap: 0.5rem;
        max-width: 100%;
        border: 1px solid var(--_border);
        border-radius: 12px;
        background: var(--slatefs-color-control, #fff);
        transition:
          border-color 0.18s ease,
          box-shadow 0.18s ease,
          transform 0.18s ease;
      }
      .branch-row:hover {
        border-color: color-mix(
          in srgb,
          var(--_border) 50%,
          var(--_accent) 50%
        );
        transform: translateY(-1px);
      }
      .branch-row.target {
        border-color: var(--_accent);
        box-shadow:
          inset 0 0 0 1px var(--_accent),
          0 6px 18px -10px var(--_accent);
      }
      .branch-row.source {
        background: var(--slatefs-color-source, #f4f8ff);
        border-color: var(--slatefs-color-source-border, #91aee5);
      }
      .branch-summary {
        flex: 1 1 16rem;
        min-width: 0;
        max-width: 100%;
        overflow: hidden;
        text-align: start;
        white-space: normal;
      }
      .branch-name {
        overflow-wrap: anywhere;
        word-break: break-word;
      }
      .branch-actions {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        gap: 0.5rem;
      }
      .branch-map {
        display: grid;
        gap: 1rem;
        padding: 0.75rem;
        border-top: 1px solid var(--_border);
        background: var(--slatefs-color-map, #f8fbfa);
      }
      .branch-map h3,
      .branch-map p {
        margin: 0;
      }
      .flow {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
        align-items: stretch;
        gap: 0.75rem;
      }
      .flow-card {
        display: grid;
        align-content: center;
        gap: 0.25rem;
        min-width: 0;
        min-height: 5.5rem;
        padding: 0.75rem;
        border: 1px solid var(--_border);
        border-radius: 10px;
        background: var(--slatefs-color-control, #fff);
      }
      .flow-card.live {
        border-style: dashed;
      }
      .flow-card.target {
        border-color: var(--_accent);
        box-shadow: inset 0 0 0 1px var(--_accent);
      }
      .flow-card strong,
      .flow-card select {
        min-width: 0;
        max-width: 100%;
        overflow-wrap: anywhere;
      }
      .commit-ref {
        display: block;
        min-width: 0;
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .flow-arrow {
        display: grid;
        place-items: center;
        min-width: 5rem;
        color: var(--_accent);
        font-weight: 800;
        text-align: center;
      }
      .flow-arrow span {
        display: block;
        font-size: 1.6rem;
        line-height: 1;
      }
      .flow-actions,
      .advanced-controls {
        display: flex;
        flex-wrap: wrap;
        align-items: end;
        gap: 0.75rem;
      }
      .advanced-controls label {
        display: grid;
        flex: 1 1 15rem;
        gap: 0.25rem;
      }
      .preview-card {
        display: grid;
        gap: 0.75rem;
        padding: 0.85rem;
        border: 1px solid var(--slatefs-color-source-border, #91aee5);
        border-radius: 10px;
        background: var(--slatefs-color-source, #f4f8ff);
      }
      .preview-card header {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 0.5rem;
      }
      .preview-facts {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
      }
      .history-only {
        padding: 0.55rem 0.75rem;
        border-left: 3px solid var(--slatefs-color-warn, #d5a72e);
        background: var(--slatefs-color-warn-bg, #fff8e5);
      }
      @media (max-width: 42rem) {
        .flow {
          grid-template-columns: 1fr;
        }
        .flow-arrow {
          min-width: 0;
          min-height: 3rem;
        }
        .flow-arrow span {
          transform: rotate(90deg);
        }
      }
    `,
  ];
  readonly componentLabel = "SlateFS branch manager";
  branch = "main";
  source = "";
  conflictStrategy: "fail" | "ours" | "theirs" = "fail";
  mainline = 0;
  advanced = false;
  private branches: Array<Record<string, unknown>> = [];
  private reflog: unknown[] = [];
  private preview?: Record<string, unknown>;
  private previewKind?: "merge" | "cherry-pick";
  private reviewed?: {
    kind: "merge" | "cherry-pick";
    target: string;
    source: string;
    expectedTarget?: string;
    expectedSource?: string;
    conflictStrategy?: "fail" | "ours" | "theirs";
    mainline?: number;
  };
  private protection?: Record<string, unknown>;
  protected override updated(changes: PropertyValues) {
    if (
      this.reviewed &&
      (changes.has("branch") ||
        changes.has("source") ||
        changes.has("conflictStrategy") ||
        changes.has("mainline"))
    ) {
      this.preview = undefined;
      this.previewKind = undefined;
      this.reviewed = undefined;
    }
    if (changes.has("client") || changes.has("volume") || changes.has("branch"))
      defer(() => this.refresh());
  }
  async refresh() {
    if (!this.client || !this.volume) {
      this.loadState = "unsupported";
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      const [b, r, p] = await Promise.all([
        this.client.getBranches(this.volume, { signal }),
        this.client.getReflog(this.volume, this.branch, { signal }),
        this.client.getProtection(this.volume, this.branch, { signal }),
      ]);
      if (!this.loadCurrent(serial)) return;
      this.branches = b.branches;
      if (!this.branches.some((candidate) => candidate.name === this.branch))
        this.branch = String(
          this.branches.find((candidate) => candidate.name === "main")?.name ??
            this.branches[0]?.name ??
            "main",
        );
      if (!this.branches.some((candidate) => candidate.name === this.source))
        this.source = "";
      this.reflog = r.entries;
      this.protection = { ...p.protection };
      this.finishLoad(serial, this.branches.length ? "ready" : "empty");
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async create() {
    if (!this.client) return;
    const values = await this.ask({
      title: "New branch",
      description: `Create a branch from ${this.branch}.`,
      submitLabel: "Create branch",
      fields: [{ name: "name", label: "Branch name", required: true }],
    });
    const name = values?.name?.trim();
    if (!name) return;
    try {
      const sourceBranch = this.branch;
      const result = await this.client.createBranch(this.volume, {
        name,
        commit: this.branches.find((b) => b.name === this.branch)?.commit as
          | string
          | undefined,
      });
      this.branches = [
        ...this.branches.filter((branch) => branch.name !== result.branch.name),
        { ...result.branch },
      ];
      this.source = sourceBranch;
      this.selectTarget(String(result.branch.name));
      this.requestUpdate();
      this.emit("slatefs-operation-complete", {
        version: 1,
        operation: "create-branch",
        entryIds: [],
      });
      await this.refresh();
    } catch (error) {
      this.failAction("create-branch", error);
    }
  }
  private selectTarget(name: string) {
    this.branch = name;
    if (this.source === name) this.source = "";
    if (
      !this.source &&
      name !== "main" &&
      this.branches.some((candidate) => candidate.name === "main")
    )
      this.source = "main";
    this.emit("slatefs-publish-target-change", {
      version: 1,
      branch: this.branch,
    });
  }
  private selectSource(name: string) {
    this.source = name === this.branch ? "" : name;
  }
  async previewMerge() {
    if (!this.client || !this.source) return;
    try {
      const r = await this.client.previewMerge(this.volume, {
        target: this.branch,
        source: this.source,
        expected_target: this.head(this.branch),
        expected_source: this.head(this.source),
        conflict_strategy: this.conflictStrategy,
      });
      this.preview = { ...r.preview };
      this.previewKind = "merge";
      this.reviewed = {
        kind: "merge",
        target: this.branch,
        source: this.source,
        expectedTarget: this.head(this.branch),
        expectedSource: this.head(this.source),
        conflictStrategy: this.conflictStrategy,
      };
      this.requestUpdate();
    } catch (error) {
      this.failAction("merge-preview", error);
    }
  }
  async applyMerge() {
    if (
      this.preview &&
      (this.reviewed?.kind !== "merge" ||
        this.reviewed.target !== this.branch ||
        this.reviewed.source !== this.source ||
        this.reviewed.conflictStrategy !== this.conflictStrategy)
    ) {
      this.preview = undefined;
      this.previewKind = undefined;
      this.reviewed = undefined;
      this.requestUpdate();
      return;
    }
    if (
      !this.client ||
      !this.source ||
      !this.preview ||
      this.reviewed?.kind !== "merge"
    )
      return;
    if (
      !(await this.confirmAction(
        "Apply reviewed merge",
        `Publish merge from ${this.source} to ${this.branch}? This changes version history, not live files.`,
        "Apply merge",
      ))
    )
      return;
    if (
      !this.emit(
        "slatefs-before-operation",
        { version: 1, operation: "merge", entryIds: [] },
        true,
      )
    )
      return;
    try {
      const reviewed = this.reviewed;
      await this.client.applyMerge(
        this.volume,
        {
          target: reviewed.target,
          source: reviewed.source,
          expected_target: reviewed.expectedTarget,
          expected_source: reviewed.expectedSource,
          conflict_strategy: reviewed.conflictStrategy,
        },
        {
          idempotencyKey: globalThis.crypto?.randomUUID?.(),
        },
      );
      this.preview = undefined;
      this.previewKind = undefined;
      this.reviewed = undefined;
      this.emit("slatefs-operation-complete", {
        version: 1,
        operation: "merge",
        entryIds: [],
      });
      await this.refresh();
    } catch (e) {
      this.emit("slatefs-conflict", {
        version: 1,
        operation: "merge",
        message: e instanceof Error ? e.message : "Merge conflict",
      });
      this.failAction("merge", e);
    }
  }
  async previewCherryPick() {
    if (!this.client || !this.source) return;
    try {
      const r = await this.client.previewCherryPick(this.volume, {
        target: this.branch,
        source: this.source,
        expected_target: this.head(this.branch),
        ...(this.mainline > 0 ? { mainline: this.mainline } : {}),
      });
      this.preview = { ...r.preview };
      this.previewKind = "cherry-pick";
      this.reviewed = {
        kind: "cherry-pick",
        target: this.branch,
        source: this.source,
        expectedTarget: this.head(this.branch),
        ...(this.mainline > 0 ? { mainline: this.mainline } : {}),
      };
      this.requestUpdate();
    } catch (error) {
      this.failAction("cherry-pick-preview", error);
    }
  }
  async applyCherryPick() {
    if (
      this.preview &&
      (this.reviewed?.kind !== "cherry-pick" ||
        this.reviewed.target !== this.branch ||
        this.reviewed.source !== this.source ||
        this.reviewed.mainline !==
          (this.mainline > 0 ? this.mainline : undefined))
    ) {
      this.preview = undefined;
      this.previewKind = undefined;
      this.reviewed = undefined;
      this.requestUpdate();
      return;
    }
    if (
      !this.client ||
      !this.source ||
      !this.preview ||
      this.reviewed?.kind !== "cherry-pick"
    )
      return;
    if (
      !(await this.confirmAction(
        "Apply reviewed cherry-pick",
        `Publish ${this.source} onto ${this.branch}? This changes version history, not live files.`,
        "Apply cherry-pick",
      ))
    )
      return;
    if (
      !this.emit(
        "slatefs-before-operation",
        { version: 1, operation: "cherry-pick", entryIds: [] },
        true,
      )
    )
      return;
    try {
      const reviewed = this.reviewed;
      await this.client.applyCherryPick(
        this.volume,
        {
          target: reviewed.target,
          source: reviewed.source,
          expected_target: reviewed.expectedTarget,
          ...(reviewed.mainline === undefined
            ? {}
            : { mainline: reviewed.mainline }),
        },
        {
          idempotencyKey: globalThis.crypto?.randomUUID?.(),
        },
      );
      this.preview = undefined;
      this.previewKind = undefined;
      this.reviewed = undefined;
      this.emit("slatefs-operation-complete", {
        version: 1,
        operation: "cherry-pick",
        entryIds: [],
      });
      await this.refresh();
    } catch (error) {
      this.emit("slatefs-conflict", {
        version: 1,
        operation: "cherry-pick",
        message:
          error instanceof Error ? error.message : "Cherry-pick conflict",
      });
      this.failAction("cherry-pick", error);
    }
  }
  private head(name: string) {
    const value = this.branches.find((branch) => branch.name === name)?.commit;
    return typeof value === "string" ? value : undefined;
  }
  private failAction(operation: string, error: unknown) {
    this.emit("slatefs-operation-error", {
      version: 1,
      operation,
      entryIds: [],
      code: (error as { code?: string }).code ?? "error",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
  async toggleProtection() {
    if (!this.client) return;
    const currently = Boolean(this.protection?.protected);
    if (
      !(await this.confirmAction(
        `${currently ? "Remove" : "Enable"} branch protection`,
        `${currently ? "Remove" : "Enable"} protection for ${this.branch}?`,
        currently ? "Remove protection" : "Enable protection",
        currently,
      ))
    )
      return;
    if (
      !this.emit(
        "slatefs-before-operation",
        { version: 1, operation: "branch-protection", entryIds: [] },
        true,
      )
    )
      return;
    try {
      const result = await this.client.setProtection(this.volume, this.branch, {
        protected: !currently,
      });
      this.protection = { ...result.protection };
      this.requestUpdate();
    } catch (error) {
      this.failAction("branch-protection", error);
    }
  }
  protected override render() {
    const canTransfer =
      Boolean(this.source) &&
      this.source !== this.branch &&
      this.branches.some((candidate) => candidate.name === this.source) &&
      this.branches.some((candidate) => candidate.name === this.branch);
    const previewPaths = Array.isArray(this.preview?.paths)
      ? this.preview.paths.length
      : undefined;
    const previewConflicts = Array.isArray(this.preview?.conflicts)
      ? this.preview.conflicts.length
      : undefined;
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Branches</h2>
        <button @click=${this.create} ?disabled=${this.readOnlyView}>
          New branch
        </button>
      </header>
      <p class="banner">
        Branches are publish targets for history. They are not checked-out
        working trees.
      </p>
      ${this.stateTemplate(this.refresh)}
      <ul class="list branch-list" part="branch-list">
        ${this.branches.map((b) => {
          const name = String(b.name);
          const isTarget = name === this.branch;
          const isSource = name === this.source;
          return html`<li
            class="row branch-row ${isTarget ? "target" : ""} ${isSource
              ? "source"
              : ""}"
            part="branch-row"
          >
            <button
              class="branch-summary"
              part="branch-summary"
              aria-label=${`Use ${name} as target branch`}
              @click=${() => this.selectTarget(name)}
            >
              <strong class="branch-name" part="branch-name">${name}</strong>
              ${isTarget ? html`<span class="badge">Target</span>` : nothing}
              ${isSource ? html`<span class="badge">Source</span>` : nothing}
              <div class="muted">${String(b.commit).slice(0, 12)}</div>
            </button>
            <div class="branch-actions" part="branch-actions">
              <button
                @click=${() => this.selectSource(name)}
                ?disabled=${isTarget}
              >
                ${isSource ? "Source selected" : "Use as source"}
              </button>
              <button
                @click=${() => {
                  const commit = String(b.commit);
                  this.emit("slatefs-view-change", {
                    version: 1,
                    view: {
                      kind: "version",
                      ref: commit,
                      resolvedCommit: commit,
                    } satisfies ViewSelection,
                  });
                }}
              >
                Browse
              </button>
            </div>
          </li>`;
        })}
      </ul>
      <div class="branch-map" part="branch-map">
        <div>
          <h3>How branch work moves</h3>
          <p class="muted">
            Edit the live workspace, publish a version to a target branch, then
            move history between branches without changing live files.
          </p>
        </div>
        <div class="flow" aria-label="Live files publish flow">
          <div class="flow-card live">
            <small>Editable workspace</small>
            <strong>Live files</strong>
            <span class="muted">The only writable file tree</span>
          </div>
          <div class="flow-arrow" aria-hidden="true">
            <small>Save new version</small><span>→</span>
          </div>
          <div class="flow-card target">
            <small>Publish target</small>
            <strong>${this.branch}</strong>
            <span class="muted">Branch head moves to the new commit</span>
          </div>
        </div>
        <div>
          <h3>Move history between branches</h3>
          <p class="muted">
            Choose a source and target. The arrow always shows the direction
            before you preview anything.
          </p>
        </div>
        <div class="flow" aria-label="Branch history transfer">
          <label class="flow-card">
            <small>Source history</small>
            <select
              aria-label="Source branch"
              .value=${this.source}
              @change=${(event: Event) =>
                this.selectSource((event.target as HTMLSelectElement).value)}
            >
              <option value="" ?selected=${!this.source}>
                Choose a source
              </option>
              ${this.branches.map((candidate) => {
                const name = String(candidate.name);
                return html`<option
                  value=${name}
                  ?selected=${name === this.source}
                  ?disabled=${name === this.branch}
                >
                  ${name}
                </option>`;
              })}
            </select>
            <span
              class="muted commit-ref"
              title=${this.source
                ? (this.head(this.source) ?? "No head")
                : "No source selected"}
              >${this.source
                ? this.head(this.source)
                : "No source selected"}</span
            >
          </label>
          <div class="flow-arrow" aria-hidden="true">
            <small>Merge or cherry-pick</small><span>→</span>
          </div>
          <label class="flow-card target">
            <small>Target history</small>
            <select
              aria-label="Target branch"
              .value=${this.branch}
              @change=${(event: Event) =>
                this.selectTarget((event.target as HTMLSelectElement).value)}
            >
              ${this.branches.map((candidate) => {
                const name = String(candidate.name);
                return html`<option
                  value=${name}
                  ?selected=${name === this.branch}
                >
                  ${name}
                </option>`;
              })}
            </select>
            <span
              class="muted commit-ref"
              title=${this.head(this.branch) ?? "No head"}
              >${this.head(this.branch) ?? "No head"}</span
            >
          </label>
        </div>
        <p class="history-only">
          Merge and cherry-pick update <strong>${this.branch}</strong> history.
          They do not overwrite the live workspace.
        </p>
        <div class="flow-actions">
          <button @click=${this.previewMerge} ?disabled=${!canTransfer}>
            Preview merge ${this.source || "source"} into ${this.branch}
          </button>
          <button @click=${this.previewCherryPick} ?disabled=${!canTransfer}>
            Preview cherry-pick ${this.source || "source"} onto ${this.branch}
          </button>
        </div>
        <details>
          <summary>Advanced conflict options</summary>
          <div class="advanced-controls body">
            <label
              >Merge conflict strategy
              <select
                .value=${this.conflictStrategy}
                @change=${(event: Event) =>
                  (this.conflictStrategy = (event.target as HTMLSelectElement)
                    .value as typeof this.conflictStrategy)}
              >
                <option value="fail">Fail and show conflicts</option>
                <option value="ours">Resolve whole paths with target</option>
                <option value="theirs">Resolve whole paths with source</option>
              </select>
            </label>
            <label
              >Cherry-pick mainline (merge commits only)
              <input
                type="number"
                min="0"
                .value=${String(this.mainline)}
                @input=${(event: Event) =>
                  (this.mainline = Number(
                    (event.target as HTMLInputElement).value,
                  ))}
              />
            </label>
          </div>
        </details>
        ${this.preview
          ? html`<div class="preview-card" part="preview">
              <header>
                <span class="badge">Reviewed preview</span>
                <strong>${this.source} → ${this.branch}</strong>
              </header>
              <div class="preview-facts">
                ${this.preview.ahead !== undefined
                  ? html`<span class="badge"
                      >${String(this.preview.ahead)} ahead</span
                    >`
                  : nothing}
                ${this.preview.behind !== undefined
                  ? html`<span class="badge"
                      >${String(this.preview.behind)} behind</span
                    >`
                  : nothing}
                ${previewPaths !== undefined
                  ? html`<span class="badge">${previewPaths} paths</span>`
                  : nothing}
                ${previewConflicts !== undefined
                  ? html`<span class="badge"
                      >${previewConflicts} conflicts</span
                    >`
                  : nothing}
              </div>
              <p>
                ${this.previewKind === "merge"
                  ? `Merge all source history into ${this.branch}.`
                  : `Apply the source head commit onto ${this.branch}.`}
              </p>
              <details>
                <summary>Technical preview details</summary>
                <pre>${JSON.stringify(this.preview, null, 2)}</pre>
              </details>
              ${this.previewKind === "merge"
                ? html`<button class="primary" @click=${this.applyMerge}>
                    Merge ${this.source} into ${this.branch}
                  </button>`
                : html`<button class="primary" @click=${this.applyCherryPick}>
                    Cherry-pick ${this.source} onto ${this.branch}
                  </button>`}
            </div>`
          : nothing}
        <details part="reflog">
          <summary>Recovery log (${this.reflog.length})</summary>
          <pre>${JSON.stringify(this.reflog, null, 2)}</pre>
        </details>
        <details part="protection">
          <summary>Branch protection</summary>
          <pre>${JSON.stringify(this.protection ?? {}, null, 2)}</pre>
          <button @click=${this.toggleProtection}>
            ${this.protection?.protected
              ? "Remove protection"
              : "Enable protection"}
          </button>
        </details>
      </div>
      ${this.actionDialogTemplate()}
    </section>`;
  }
}

type RestoreClient = Pick<VersionClient, "previewRestore" | "applyRestore">;
/** Preview-first restore UI. Multi-path restore remains unavailable until the facade contracts it. */
export class SlateFsRestoreDialog extends SlateFsElement<RestoreClient> {
  static override properties = {
    ...SlateFsElement.properties,
    open: { type: Boolean, reflect: true },
    commit: { type: String },
    paths: { attribute: false },
    mode: { type: String },
  };
  readonly componentLabel = "SlateFS restore dialog";
  open = false;
  commit = "";
  paths: readonly string[] = [];
  mode: "overlay" | "exact" = "overlay";
  private preview?: { token: string; actions?: unknown[] };
  private stale = false;
  private returnFocus?: HTMLElement;

  protected override updated(changes: PropertyValues) {
    if (
      this.preview &&
      (changes.has("commit") || changes.has("paths") || changes.has("mode"))
    ) {
      this.preview = undefined;
      this.stale = true;
    }
  }

  show() {
    const active =
      this.getRootNode() instanceof Document
        ? document.activeElement
        : (this.getRootNode() as ShadowRoot).activeElement;
    this.returnFocus = active instanceof HTMLElement ? active : undefined;
    this.open = true;
    this.requestUpdate();
    void this.updateComplete.then(() =>
      this.renderRoot
        .querySelector<HTMLElement>("[data-initial-focus]")
        ?.focus(),
    );
  }
  close() {
    this.open = false;
    this.preview = undefined;
    this.stale = false;
    this.requestUpdate();
    this.returnFocus?.focus();
    this.returnFocus = undefined;
  }
  async previewRestore() {
    const path = this.paths[0];
    if (!this.client || !this.volume || !this.commit || !path) return;
    const { signal, serial } = this.beginLoad();
    try {
      const result = await this.client.previewRestore(
        this.volume,
        { commit: this.commit, path, mode: this.mode },
        { signal },
      );
      if (!this.loadCurrent(serial)) return;
      this.preview = result.preview;
      this.stale = false;
      this.finishLoad(serial, "ready");
      this.emit("slatefs-restore-preview", {
        version: 1,
        preview: {
          ...result.preview,
          actions: Array.isArray(result.preview.actions)
            ? [...result.preview.actions]
            : undefined,
        },
      });
    } catch (error) {
      this.failLoad(serial, error);
    }
  }
  async apply() {
    const path = this.paths[0];
    if (!this.client || !this.preview || !path) return;
    if (
      !(await this.confirmAction(
        "Apply reviewed restore",
        "This reviewed restore changes live paths and may replace or delete content.",
        "Apply restore",
        true,
      ))
    )
      return;
    const detail = {
      version: 1 as const,
      operation: "restore",
      entryIds: [],
    };
    if (!this.emit("slatefs-before-operation", detail, true)) return;
    try {
      const result = await this.client.applyRestore(this.volume, {
        commit: this.commit,
        path,
        mode: this.mode,
        token: this.preview.token,
      });
      this.emit("slatefs-restore-complete", {
        version: 1,
        restored: result.restored,
      });
      this.close();
    } catch (error) {
      if ((error as { status?: number }).status === 409) {
        this.preview = undefined;
        this.stale = true;
        this.requestUpdate();
      } else {
        this.errorMessage =
          (error as { message?: string }).message ?? "Restore failed";
        this.loadState = "error";
        this.requestUpdate();
        this.emit("slatefs-operation-error", {
          ...detail,
          code: (error as { code?: string }).code ?? "error",
          message: (error as { message?: string }).message ?? "Restore failed",
        });
      }
    }
  }
  private dialogKey(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      this.close();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = [
      ...this.renderRoot.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ];
    if (!controls.length) return;
    const current = controls.indexOf(
      (this.renderRoot as ShadowRoot).activeElement as HTMLElement,
    );
    const next = event.shiftKey
      ? current <= 0
        ? controls.length - 1
        : current - 1
      : current < 0 || current === controls.length - 1
        ? 0
        : current + 1;
    event.preventDefault();
    controls[next]?.focus();
  }
  protected override render() {
    const actions = this.preview?.actions ?? [];
    return html`<section
      part="dialog"
      aria-label=${this.componentLabel}
      role="dialog"
      aria-modal="true"
      ?hidden=${!this.open}
      @keydown=${this.dialogKey}
    >
      <header class="toolbar" part="toolbar">
        <h2>Restore to live files</h2>
        <button data-initial-focus @click=${this.close}>Close</button>
      </header>
      <p class="banner" part="warning">
        Restore changes live files. It does not check out a branch.
      </p>
      ${this.paths.length > 1
        ? html`<p class="state" part="unsupported">
            Multi-path restore is not supported by the current facade. Select
            one path.
          </p>`
        : nothing}
      ${this.stale
        ? html`<p class="state error" role="alert">
            The restore plan is stale. Preview again and reconfirm.
          </p>`
        : nothing}
      ${this.stateTemplate(this.previewRestore)}
      <div class="body" part="summary">
        <p><strong>${this.commit || "No commit selected"}</strong></p>
        <p>${this.paths[0] ?? "No path selected"} · ${this.mode}</p>
        ${this.preview
          ? html`<ol part="action-list">
                ${actions.map(
                  (action) => html`<li>${JSON.stringify(action)}</li>`,
                )}
              </ol>
              <button class="primary" @click=${this.apply}>
                Apply reviewed restore
              </button>`
          : html`<button
              @click=${this.previewRestore}
              ?disabled=${!this.client ||
              !this.commit ||
              this.paths.length !== 1 ||
              this.readOnlyView}
            >
              Preview restore
            </button>`}
      </div>
      ${this.actionDialogTemplate()}
    </section>`;
  }
}

type RepoClient = Pick<
  RepositoryClient,
  "getRepositoryStats" | "verifyRepository"
> &
  Partial<Pick<CollaborationClient, "getAttestations" | "getQuorum">>;
export class SlateFsRepositoryTools extends SlateFsElement<RepoClient> {
  static override properties = {
    ...SlateFsElement.properties,
    commit: { type: String },
    branch: { type: String },
    section: { type: String },
  };
  readonly componentLabel = "SlateFS repository tools";
  commit = "";
  branch = "main";
  section = "stats";
  private stats?: Record<string, unknown>;
  private verifyResult?: Record<string, unknown>;
  private attestations?: unknown[];
  private quorum?: Record<string, unknown>;
  protected override updated(changes: PropertyValues) {
    if (changes.has("client") || changes.has("volume"))
      defer(() => this.refresh());
  }
  async refresh() {
    if (!this.client || !this.volume) {
      this.loadState = "unsupported";
      return;
    }
    const { signal, serial } = this.beginLoad();
    try {
      const r = await this.client.getRepositoryStats(this.volume, { signal });
      if (!this.loadCurrent(serial)) return;
      this.stats = r.stats;
      this.finishLoad(serial);
    } catch (e) {
      this.failLoad(serial, e);
    }
  }
  async verify() {
    if (!this.client || !this.volume) return;
    const operation = {
      version: 1 as const,
      operation: "verify-health",
      entryIds: [] as string[],
    };
    if (!this.emit("slatefs-before-operation", operation, true)) return;
    this.emit("slatefs-operation-start", operation);
    try {
      const r = await this.client.verifyRepository(this.volume, {});
      this.verifyResult = { ...r.verify };
      this.requestUpdate();
      this.emit("slatefs-operation-complete", operation);
    } catch (error) {
      this.failAction("verify", error);
    }
  }
  async inspectTrust() {
    if (!this.client || !this.commit) return;
    try {
      const [attestations, quorum] = await Promise.all([
        this.client.getAttestations
          ? this.client.getAttestations(this.volume, this.commit)
          : Promise.resolve(undefined),
        this.client.getQuorum
          ? this.client.getQuorum(this.volume, this.branch, this.commit)
          : Promise.resolve(undefined),
      ]);
      this.attestations = attestations
        ? [...attestations.attestations]
        : undefined;
      this.quorum = quorum ? { ...quorum.quorum } : undefined;
      this.requestUpdate();
    } catch (error) {
      this.failAction("trust-inspection", error);
    }
  }
  private failAction(operation: string, error: unknown) {
    this.emit("slatefs-operation-error", {
      version: 1,
      operation,
      entryIds: [],
      code: (error as { code?: string }).code ?? "error",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
  protected override render() {
    return html`<section part="inspector" aria-label=${this.componentLabel}>
      <header class="toolbar" part="toolbar">
        <h2>Repository health</h2>
        <button @click=${this.verify}>Verify</button>
      </header>
      ${this.stateTemplate(this.refresh)}
      <div class="body">
        <div part="stats">
          <h3>Statistics</h3>
          <pre>
${this.stats ? JSON.stringify(this.stats, null, 2) : "Unavailable"}</pre
          >
        </div>
        ${this.verifyResult
          ? html`<div part="verify">
              <h3>Verification result</h3>
              <pre>${JSON.stringify(this.verifyResult, null, 2)}</pre>
            </div>`
          : nothing}
        ${this.client?.getAttestations || this.client?.getQuorum
          ? html`<div part="trust">
              <h3>Attestations and quorum</h3>
              <button @click=${this.inspectTrust} ?disabled=${!this.commit}>
                Inspect selected commit
              </button>
              ${this.attestations
                ? html`<pre>${JSON.stringify(this.attestations, null, 2)}</pre>`
                : nothing}
              ${this.quorum
                ? html`<pre>${JSON.stringify(this.quorum, null, 2)}</pre>`
                : nothing}
            </div>`
          : html`<p class="muted">
              Attestation and quorum inspection are not exposed by this host.
            </p>`}
        <p class="muted">
          Safe consumer tools only. Bundle transfer, native sync, retention
          changes, garbage collection, purge, leases, and fleet controls are
          intentionally unavailable.
        </p>
      </div>
    </section>`;
  }
}

// Source-compatible class aliases from the Phase 0 scaffold; only the requested tags are registered.
export {
  SlateFsMetadataPanel as SlateFsFileProperties,
  SlateFsSnapshotBrowser as SlateFsSnapshotManager,
  SlateFsVersionDiff as SlateFsDiffViewer,
};
if (!customElements.get("slatefs-volume-picker"))
  customElements.define("slatefs-volume-picker", SlateFsVolumePicker);
if (!customElements.get("slatefs-file-explorer"))
  customElements.define("slatefs-file-explorer", SlateFsFileExplorer);
if (!customElements.get("slatefs-file-preview"))
  customElements.define("slatefs-file-preview", SlateFsFilePreview);
if (!customElements.get("slatefs-file-properties"))
  customElements.define("slatefs-file-properties", SlateFsMetadataPanel);
if (!customElements.get("slatefs-snapshot-manager"))
  customElements.define("slatefs-snapshot-manager", SlateFsSnapshotBrowser);
if (!customElements.get("slatefs-version-status"))
  customElements.define("slatefs-version-status", SlateFsVersionStatus);
if (!customElements.get("slatefs-version-history"))
  customElements.define("slatefs-version-history", SlateFsVersionHistory);
if (!customElements.get("slatefs-diff-viewer"))
  customElements.define("slatefs-diff-viewer", SlateFsVersionDiff);
if (!customElements.get("slatefs-branch-manager"))
  customElements.define("slatefs-branch-manager", SlateFsBranchManager);
if (!customElements.get("slatefs-restore-dialog"))
  customElements.define("slatefs-restore-dialog", SlateFsRestoreDialog);
if (!customElements.get("slatefs-repository-tools"))
  customElements.define("slatefs-repository-tools", SlateFsRepositoryTools);
declare global {
  interface HTMLElementTagNameMap {
    "slatefs-volume-picker": SlateFsVolumePicker;
    "slatefs-file-explorer": SlateFsFileExplorer;
    "slatefs-file-preview": SlateFsFilePreview;
    "slatefs-file-properties": SlateFsMetadataPanel;
    "slatefs-snapshot-manager": SlateFsSnapshotBrowser;
    "slatefs-version-status": SlateFsVersionStatus;
    "slatefs-version-history": SlateFsVersionHistory;
    "slatefs-diff-viewer": SlateFsVersionDiff;
    "slatefs-branch-manager": SlateFsBranchManager;
    "slatefs-restore-dialog": SlateFsRestoreDialog;
    "slatefs-repository-tools": SlateFsRepositoryTools;
  }
}
