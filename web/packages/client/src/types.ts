export type ViewKind = "live" | "snapshot" | "version";

export interface ViewSelection {
  kind: ViewKind;
  ref?: string;
  resolved_commit?: string;
  /** Camel-case compatibility accessor accepted by client helpers. Not sent on the wire. */
  resolvedCommit?: string;
}

export interface CapabilityLimits {
  max_page_size: number;
  max_range_bytes: number;
  max_recursive_entries: number;
  max_recursive_bytes: number;
  max_text_edit_bytes: number;
  max_diff_bytes: number;
  max_diff_lines: number;
}

export interface CapabilitiesResponse {
  api_version: "consumer/v1";
  limits: CapabilityLimits;
  features: {
    historical_snapshots: boolean;
    historical_versions: boolean;
    hardlinks: boolean;
    symlinks: boolean;
    xattrs: boolean;
    [feature: string]: boolean;
  };
}

export interface QuotaUsage {
  used_bytes: number;
  limit_bytes: number | null;
  used_inodes: number;
  limit_inodes: number | null;
}

export interface VolumeSummary {
  name: string;
  kind: "filesystem" | "block";
  browsable: boolean;
  readonly: boolean;
  quota: QuotaUsage;
}

export interface VolumeListResponse {
  volumes: VolumeSummary[];
  next_page_token?: string | null;
}
export interface VolumeDetail extends VolumeSummary {
  allocated_bytes: number;
  available_bytes: number;
  total_bytes: number;
}

export interface Entry {
  entry_id: string;
  parent_entry_id: string | null;
  path: string | null;
  name: string | null;
  name_bytes_base64: string;
  kind: "file" | "directory" | "symlink" | "special";
  inode: number;
  generation: number;
  size: number;
  allocated_bytes: number;
  mode: number;
  uid: number;
  gid: number;
  link_count: number;
  created_at: string;
  modified_at: string;
  changed_at: string;
  accessed_at: string;
  readonly: boolean;
  can_read: boolean;
  can_write: boolean;
  can_delete: boolean;
  can_rename: boolean;
  etag: string;
  symlink_target: string | null;
  inode_decimal?: string;
  generation_decimal?: string;
  size_decimal?: string;
  allocated_bytes_decimal?: string;
  link_count_decimal?: string;
}

export interface EntryListResponse {
  view: ViewSelection;
  entry: Entry;
  entries: Entry[];
  next_page_token: string | null;
}
export interface CreateEntryRequest {
  parent_entry_id: string;
  name: string;
  kind: "file" | "directory" | "symlink";
  mode?: number;
  symlink_target?: string;
}
export interface UpdateEntryRequest {
  entry_id: string;
  destination_parent_entry_id?: string;
  name?: string;
  mode?: number;
}
export interface OperationRequest {
  operation: "copy" | "move" | "hardlink";
  source_entry_ids: string[];
  destination_parent_entry_id: string;
  conflict_policy: "fail" | "overwrite" | "keep_both" | "skip";
  preview: boolean;
}
export interface OperationResult {
  operation_id: string;
  preview: boolean;
  total_entries: number;
  total_bytes: number;
  completed_entries: number;
  failed_entries: number;
}
export interface XattrValue {
  name: string | null;
  name_bytes_base64: string;
  value_base64: string;
}
export interface XattrListResponse {
  entry_id: string;
  xattrs: XattrValue[];
  view?: ViewSelection;
}
export interface UpdateXattrsRequest {
  set?: Record<string, string>;
  remove?: string[];
  set_bytes?: Array<{ name_bytes_base64: string; value_base64: string }>;
  remove_bytes_base64?: string[];
}

export const knownErrorCodes = [
  "authentication_required",
  "permission_denied",
  "not_found",
  "conflict",
  "invalid_path",
  "invalid_request",
  "malformed_range",
  "range_not_satisfiable",
  "read_only_view",
  "precondition_failed",
  "quota_exceeded",
  "rate_limited",
  "primary_unavailable",
  "internal",
] as const;
export type KnownErrorCode = (typeof knownErrorCodes)[number];
/** Open string union: future server error codes remain usable at runtime. */
export type ErrorCode = KnownErrorCode | (string & {});
export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    request_id: string;
    details: Record<string, unknown>;
  };
}

export interface PageOptions {
  limit?: number;
  pageToken?: string;
  signal?: AbortSignal;
  requestId?: string;
}
export interface EntrySelector {
  entryId?: string;
  path?: string;
}
export type UploadTarget =
  | { entryId: string }
  | { parentEntryId: string; name: string };
export interface ContentReadResult {
  body: ReadableStream<Uint8Array>;
  contentLength?: number;
  contentType: string;
  contentDisposition?: string;
  etag: string;
  requestId: string;
  resolvedCommit?: string;
}
export interface UploadProgress {
  transferredBytes: number;
  totalBytes?: number;
}
export interface RequestOptions {
  signal?: AbortSignal;
  requestId?: string;
  idempotencyKey?: string;
}

export interface Snapshot {
  id: string;
  name?: string | null;
  checkpoint?: string;
  time?: number | string;
  expire_time?: number | string | null;
  manifest_id?: string;
  /** Compatibility alias accepted from older facade implementations. */
  created_at?: string | number;
  [field: string]: unknown;
}
export interface SnapshotListResponse {
  snapshots: Snapshot[];
  next_page_token?: string | null;
}
export interface SnapshotCreateResponse {
  snapshot: Snapshot;
}
export interface SnapshotCloneRequest {
  new_volume: string;
}
export interface SnapshotCloneResponse {
  clone: {
    tenant: string;
    volume: string;
    source_volume: string;
    snapshot_id: string;
    [field: string]: unknown;
  };
}

export interface VersionPolicy {
  enabled: boolean;
  [field: string]: unknown;
}
export interface VersionPolicyResponse {
  versioning: VersionPolicy;
}
export interface VersionStatusRequest {
  reference: string;
  path: string;
}
export interface VersionChange {
  path: string;
  change: string;
  [field: string]: unknown;
}
export interface VersionStatusResponse {
  status: {
    changes: VersionChange[];
    commit?: string;
    reference?: string;
    root?: string;
    [field: string]: unknown;
  };
  resolved_commit?: string;
  [field: string]: unknown;
}
export interface VersionCommitRequest {
  branch: string;
  paths: string[];
  message: string;
  author?: string;
  idempotency_key?: string;
}
export interface VersionCommit {
  id: string;
  message?: string;
  author?: string;
  parents?: string[];
  created_at?: string | number;
  [field: string]: unknown;
}
export interface VersionCommitResponse {
  commit: VersionCommit;
}
export interface VersionLogResponse {
  commits: VersionCommit[];
  next_page_token?: string | null;
}
export interface VersionDiffResponse {
  changes: VersionChange[];
  next_page_token?: string | null;
  resolved_from?: string;
  resolved_to?: string;
}
export interface NamedRef {
  name: string;
  commit: string;
  [field: string]: unknown;
}
export interface BranchListResponse {
  branches: NamedRef[];
}
export interface TagListResponse {
  tags: NamedRef[];
}
export interface TagCreateResponse {
  tag: NamedRef;
}
export interface BranchCreateResponse {
  branch: NamedRef;
}
export interface TagRequest {
  name: string;
  commit: string;
}
export interface BranchRequest {
  name: string;
  commit?: string;
  /** @deprecated Use commit. Retained only for source compatibility. */
  from?: string;
}
export interface RestoreRequest {
  commit: string;
  path: string;
  mode: "exact" | "overlay";
  token?: string;
}
export interface RestorePreviewResponse {
  preview: { token: string; actions?: unknown[]; [field: string]: unknown };
  resolved_commit?: string;
}
export interface RestoreApplyResponse {
  restored: unknown;
}
export interface MergeRequest {
  source: string;
  conflict_strategy?: "fail" | "ours" | "theirs";
  expected_source?: string;
  expected_target?: string;
}
export interface MergePreviewResponse {
  preview: { [field: string]: unknown };
}
export interface MergeApplyResponse {
  merge: { [field: string]: unknown };
}
export interface CherryPickRequest {
  source: string;
  mainline?: number;
  expected_target?: string;
  idempotency_key?: string;
}
export interface CherryPickPreviewResponse {
  preview: { [field: string]: unknown };
}
export interface CherryPickApplyResponse {
  cherry_pick: { [field: string]: unknown };
}
export interface ReflogResponse {
  entries: unknown[];
}
export interface ProtectionRequest {
  protected: boolean;
  allowed_committers?: string[];
  allowed_managers?: string[];
  trusted_attestation_keys?: unknown[];
  required_attestations?: number;
}
export interface ProtectionResponse {
  protection: { [field: string]: unknown };
}
export interface QuorumResponse {
  quorum: { [field: string]: unknown };
}
export interface RepositoryStatsResponse {
  stats: {
    bytes: number;
    max_bytes?: number | null;
    available_bytes?: number | null;
    over_limit?: boolean;
    nodes?: number;
    blobs?: number;
    commits?: number;
    attestations?: number;
    [field: string]: unknown;
  };
}
export interface RepositoryVerifyResponse {
  verify: { valid?: boolean; [field: string]: unknown };
}
export interface SessionCapabilities {
  snapshots: boolean;
  versions: boolean;
  collaboration: boolean;
  repository: boolean;
}
export interface SessionResponse {
  authenticated: boolean;
  user?: { username: string; displayName: string };
  csrfToken: string;
  expiresAt?: string;
  capabilities: SessionCapabilities;
}
