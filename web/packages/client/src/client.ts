import type { SlateFsClient } from "./capabilities.js";
import {
  FetchTransport,
  type SlateFsClientOptions,
  type TransportRequest,
} from "./transport.js";
import type * as T from "./types.js";

const segmentPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
function segment(value: string, label: string): string {
  if (!segmentPattern.test(value) || value === "." || value === "..")
    throw new TypeError(`Invalid ${label}`);
  return encodeURIComponent(value);
}
function selector(value: T.EntrySelector): Record<string, string> {
  const present =
    Number(value.entryId !== undefined) + Number(value.path !== undefined);
  if (present !== 1)
    throw new TypeError("Exactly one of entryId or path is required");
  return value.entryId === undefined
    ? { path: wirePath(value.path!) }
    : { entry_id: value.entryId };
}
function wirePath(value: string): string {
  // Entry paths exposed by the consumer API and accepted by the web
  // components are absolute. The wire selector is volume-root-relative.
  return value.startsWith("/") ? value.slice(1) : value;
}
function uploadSelector(
  value: T.EntrySelector | T.UploadTarget,
): Record<string, string> {
  if ("parentEntryId" in value) {
    if (
      !value.parentEntryId ||
      !value.name ||
      value.name === "." ||
      value.name === ".." ||
      /[/\\\0]/.test(value.name)
    )
      throw new TypeError("Invalid upload target");
    return { parent_entry_id: value.parentEntryId, name: value.name };
  }
  return selector(value);
}
function view(value: T.ViewSelection): Record<string, string> {
  const reference = value.resolvedCommit ?? value.resolved_commit ?? value.ref;
  if (value.kind === "live" && reference !== undefined)
    throw new TypeError("A live view cannot have a ref");
  if (value.kind !== "live" && reference === undefined)
    throw new TypeError("Historical views require a ref");
  return {
    view: value.kind,
    ...(reference === undefined ? {} : { ref: reference }),
  };
}
function json(body: unknown): { body: string; headers: HeadersInit } {
  return {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
  };
}
const newIdempotencyKey = () =>
  globalThis.crypto?.randomUUID?.() ??
  `idem-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
function opts(
  options?: T.RequestOptions,
): Pick<TransportRequest, "signal" | "requestId" | "idempotencyKey"> {
  return {
    signal: options?.signal,
    requestId: options?.requestId,
    idempotencyKey: options?.idempotencyKey,
  };
}

function protectionFromBranch(
  branch: Record<string, unknown> | undefined,
): T.ProtectionResponse["protection"] {
  const embedded = branch?.protection;
  if (embedded && typeof embedded === "object")
    return { ...(embedded as Record<string, unknown>) };
  const policyFields = [
    "protected",
    "allowed_committers",
    "allowed_managers",
    "trusted_attestation_keys",
    "required_attestations",
  ];
  return Object.fromEntries(
    policyFields.flatMap((field) =>
      branch && field in branch ? [[field, branch[field]]] : [],
    ),
  );
}

export function createSlateFsClient(
  options: SlateFsClientOptions,
): SlateFsClient {
  const transport = new FetchTransport(options);
  const consumer = "consumer/v1";
  const facade = "v1";
  const vp = (volume: string) =>
    `${facade}/volumes/${segment(volume, "volume")}/versioning`;
  const cp = (volume: string) =>
    `${consumer}/volumes/${segment(volume, "volume")}`;
  return {
    getCapabilities: (o) =>
      transport.request({ path: `${consumer}/capabilities`, ...opts(o) }),
    listVolumes: (o) =>
      transport.request({
        path: `${consumer}/volumes`,
        query: { limit: o?.limit, page_token: o?.pageToken },
        ...opts(o),
      }),
    getVolume: (v, o) => transport.request({ path: cp(v), ...opts(o) }),
    listEntries: (v, s, w, o) =>
      transport.request({
        path: `${cp(v)}/entries`,
        query: {
          ...selector(s),
          ...view(w),
          limit: o?.limit,
          page_token: o?.pageToken,
        },
        ...opts(o),
      }),
    async readContent(v, s, w, o) {
      if (
        o?.range &&
        (!Number.isSafeInteger(o.range.start) ||
          o.range.start < 0 ||
          (o.range.end !== undefined &&
            (!Number.isSafeInteger(o.range.end) ||
              o.range.end < o.range.start)))
      )
        throw new TypeError("Invalid byte range");
      const result = await transport.request({
        path: `${cp(v)}/content`,
        query: { ...selector(s), ...view(w) },
        headers: o?.range
          ? { Range: `bytes=${o.range.start}-${o.range.end ?? ""}` }
          : undefined,
        response: "stream",
        onDownloadProgress: o?.onProgress,
        ...opts(o),
      });
      const lengthHeader = result.headers.get("content-length");
      const length =
        lengthHeader !== null && /^(0|[1-9][0-9]*)$/.test(lengthHeader)
          ? Number(lengthHeader)
          : undefined;
      return {
        body: result.body,
        ...(length !== undefined && Number.isSafeInteger(length)
          ? { contentLength: length }
          : {}),
        contentType:
          result.headers.get("content-type") ?? "application/octet-stream",
        contentDisposition:
          result.headers.get("content-disposition") ?? undefined,
        etag: result.headers.get("etag") ?? "",
        requestId: result.requestId,
        resolvedCommit:
          result.headers.get("x-slatefs-resolved-commit") ?? undefined,
      };
    },
    uploadContent: (v, s, content, o) =>
      transport.request({
        method: "PUT",
        path: `${cp(v)}/content`,
        query: uploadSelector(s),
        headers: { "content-type": "application/octet-stream" },
        body: content,
        response: "json",
        ifMatch: o?.ifMatch,
        onUploadProgress: o?.onProgress,
        replaySafe: false,
        ...opts(o),
      }),
    createEntry: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${cp(v)}/entries`,
        ...json(request),
        replaySafe: false,
        ...opts(o),
      }),
    updateEntry: (v, request, o) =>
      transport.request({
        method: "PATCH",
        path: `${cp(v)}/entries`,
        ...json(request),
        ifMatch: o?.ifMatch,
        replaySafe: false,
        ...opts(o),
      }),
    deleteEntry: (v, entryId, recursive, o) =>
      transport.request({
        method: "DELETE",
        path: `${cp(v)}/entries`,
        query: { entry_id: entryId, recursive },
        response: "empty",
        ifMatch: o?.ifMatch,
        replaySafe: false,
        ...opts(o),
      }),
    startOperation: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${cp(v)}/operations`,
        ...json(request),
        ...opts(o),
        idempotencyKey: o?.idempotencyKey ?? newIdempotencyKey(),
      }),
    getXattrs: (v, entryId, w, o) =>
      transport.request({
        path: `${cp(v)}/xattrs`,
        query: { entry_id: entryId, ...view(w) },
        ...opts(o),
      }),
    updateXattrs: (v, entryId, request, o) =>
      transport.request({
        method: "PATCH",
        path: `${cp(v)}/xattrs`,
        query: { entry_id: entryId },
        ...json(request),
        ifMatch: o?.ifMatch,
        replaySafe: false,
        ...opts(o),
      }),
    listSnapshots: (v, o) =>
      transport.request({
        path: `${facade}/volumes/${segment(v, "volume")}/snapshots`,
        query: { limit: o?.limit, page_token: o?.pageToken },
        ...opts(o),
      }),
    createSnapshot: (v, name, o) =>
      transport.request({
        method: "POST",
        path: `${facade}/volumes/${segment(v, "volume")}/snapshots`,
        ...json({ ...(name === undefined ? {} : { name }) }),
        ...opts(o),
        replaySafe: false,
      }),
    cloneSnapshot: (v, ref, newVolume, o) =>
      transport.request({
        method: "POST",
        path: `${facade}/volumes/${segment(v, "volume")}/snapshots/${segment(ref, "snapshot")}/clones`,
        ...json({ new_volume: newVolume }),
        ...opts(o),
        replaySafe: false,
      }),
    getVersionPolicy: (v, o) => transport.request({ path: vp(v), ...opts(o) }),
    enableVersioning: (v, o) =>
      transport.request({
        method: "PATCH",
        path: vp(v),
        ...json({ enabled: true }),
        replaySafe: false,
        ...opts(o),
      }),
    getStatus(
      v: string,
      requestOrReference: string | T.VersionStatusRequest,
      pathsOrOptions?: string[] | T.RequestOptions,
      maybeOptions?: T.RequestOptions,
    ) {
      const legacy = typeof requestOrReference === "string";
      const request: T.VersionStatusRequest = legacy
        ? {
            reference: requestOrReference,
            path: (pathsOrOptions as string[] | undefined)?.[0] ?? "/",
          }
        : requestOrReference;
      const o = (legacy ? maybeOptions : pathsOrOptions) as
        | T.RequestOptions
        | undefined;
      return transport.request<T.VersionStatusResponse>({
        path: `${vp(v)}/status`,
        query: { reference: request.reference, path: request.path },
        ...opts(o),
      });
    },
    commit: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/commits`,
        ...json({
          ...request,
          ...(o?.idempotencyKey === undefined
            ? {}
            : { idempotency_key: o.idempotencyKey }),
        }),
        ...opts(o),
      }),
    getLog: (v, branch, o) =>
      transport.request({
        path: `${vp(v)}/commits`,
        query: { branch, limit: o?.limit, page_token: o?.pageToken },
        ...opts(o),
      }),
    showCommit: (v, commit, o) =>
      transport.request({
        path: `${vp(v)}/commits/${segment(commit, "commit")}`,
        ...opts(o),
      }),
    async getRefs(v, o) {
      const [branches, tags] = await Promise.all([
        transport.request<T.BranchListResponse>({
          path: `${vp(v)}/branches`,
          ...opts(o),
        }),
        transport.request<T.TagListResponse>({
          path: `${vp(v)}/tags`,
          ...opts(o),
        }),
      ]);
      return { branches: branches.branches, tags: tags.tags };
    },
    getBranches: (v, o) =>
      transport.request({ path: `${vp(v)}/branches`, ...opts(o) }),
    createBranch: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/branches`,
        ...json({ name: request.name, commit: request.commit ?? request.from }),
        replaySafe: false,
        ...opts(o),
      }),
    getTags: (v, o) => transport.request({ path: `${vp(v)}/tags`, ...opts(o) }),
    createTag: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/tags`,
        ...json(request),
        replaySafe: false,
        ...opts(o),
      }),
    getDiff: (v, from, to, o) =>
      transport.request({
        path: `${vp(v)}/diff`,
        query: { from, to, limit: o?.limit, page_token: o?.pageToken },
        ...opts(o),
      }),
    previewRestore: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/restore-preview`,
        ...json(request),
        replaySafe: false,
        ...opts(o),
      }),
    applyRestore(v, requestOrToken, options_) {
      if (typeof requestOrToken === "string")
        throw new TypeError(
          "Restore apply requires the original commit, path, mode, and preview token",
        );
      const request = requestOrToken;
      return transport.request({
        method: "POST",
        path: `${vp(v)}/restore`,
        ...json(request),
        replaySafe: false,
        ...opts(options_),
      });
    },
    previewMerge: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/branches/${segment(request.target, "branch")}/merge/preview`,
        ...json(request),
        ...opts(o),
      }),
    applyMerge: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/branches/${segment(request.target, "branch")}/merge`,
        ...json(request),
        ...opts(o),
        // The current admin merge route has no idempotency/replay contract.
        // A transport retry after an ambiguous response could publish twice.
        replaySafe: false,
      }),
    previewCherryPick: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/branches/${segment(request.target, "branch")}/cherry-pick/preview`,
        ...json(request),
        ...opts(o),
      }),
    applyCherryPick: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/branches/${segment(request.target, "branch")}/cherry-pick`,
        ...json({
          ...request,
          ...(o?.idempotencyKey === undefined
            ? {}
            : { idempotency_key: o.idempotencyKey }),
        }),
        ...opts(o),
      }),
    getReflog(
      v: string,
      branchOrOptions?: string | T.PageOptions,
      maybeOptions?: T.PageOptions,
    ) {
      const branch =
        typeof branchOrOptions === "string" ? branchOrOptions : "main";
      const o =
        typeof branchOrOptions === "string" ? maybeOptions : branchOrOptions;
      return transport.request<T.ReflogResponse>({
        path: `${vp(v)}/branches/${segment(branch, "branch")}/reflog`,
        query: { limit: o?.limit, page_token: o?.pageToken },
        ...opts(o),
      });
    },
    async getProtection(
      v: string,
      branchOrOptions?: string | T.RequestOptions,
      maybeOptions?: T.RequestOptions,
    ) {
      const branch =
        typeof branchOrOptions === "string" ? branchOrOptions : "main";
      const o =
        typeof branchOrOptions === "string" ? maybeOptions : branchOrOptions;
      const response = await transport.request<T.BranchListResponse>({
        path: `${vp(v)}/branches/${segment(branch, "branch")}/protection`,
        ...opts(o),
      });
      const selected = response.branches.find((item) => item.name === branch);
      return { protection: protectionFromBranch(selected) };
    },
    async setProtection(v, branch, request, o) {
      const response = await transport.request<T.BranchCreateResponse>({
        method: "PUT",
        path: `${vp(v)}/branches/${segment(branch, "branch")}/protection`,
        ...json(request),
        replaySafe: false,
        ...opts(o),
      });
      return { protection: protectionFromBranch(response.branch) };
    },
    getAttestations: (v, commit, o) =>
      transport.request({
        path: `${vp(v)}/commits/${segment(commit, "commit")}/attestations`,
        ...opts(o),
      }),
    getQuorum: (v, branch, commit, o) =>
      transport.request({
        path: `${vp(v)}/branches/${segment(branch, "branch")}/attestation-quorum`,
        query: { commit },
        ...opts(o),
      }),
    getRepositoryStats: (v, o) =>
      transport.request({ path: `${vp(v)}/stats`, ...opts(o) }),
    verifyRepository: (v, o) =>
      transport.request({ path: `${vp(v)}/verify`, ...opts(o) }),
    async exportBundle(v, _request, o) {
      const result = await transport.request({
        path: `${vp(v)}/bundle`,
        response: "stream",
        ...opts(o),
      });
      return {
        body: result.body,
        contentType:
          result.headers.get("content-type") ?? "application/octet-stream",
        etag: result.headers.get("etag") ?? "",
        requestId: result.requestId,
      };
    },
    importBundle: (v, body, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/bundle`,
        body,
        ...opts(o),
      }),
    syncBranch: (v, request, o) =>
      transport.request({
        method: "POST",
        path: `${vp(v)}/sync`,
        ...json(request),
        ...opts(o),
      }),
  };
}
