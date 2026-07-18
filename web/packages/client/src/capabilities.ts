import type {
  BranchListResponse,
  BranchCreateResponse,
  BranchRequest,
  CapabilitiesResponse,
  CherryPickApplyResponse,
  CherryPickPreviewResponse,
  CherryPickRequest,
  ContentReadResult,
  CreateEntryRequest,
  Entry,
  EntryListResponse,
  EntrySelector,
  MergeApplyResponse,
  MergePreviewResponse,
  MergeRequest,
  OperationRequest,
  OperationResult,
  PageOptions,
  ProtectionRequest,
  ProtectionResponse,
  QuorumResponse,
  ReflogResponse,
  RepositoryStatsResponse,
  RepositoryVerifyResponse,
  RequestOptions,
  RestoreApplyResponse,
  RestorePreviewResponse,
  RestoreRequest,
  SnapshotCloneResponse,
  SnapshotCreateResponse,
  SnapshotListResponse,
  TagListResponse,
  TagCreateResponse,
  TagRequest,
  UpdateEntryRequest,
  UpdateXattrsRequest,
  UploadProgress,
  UploadTarget,
  VersionCommitRequest,
  VersionCommitResponse,
  VersionDiffResponse,
  VersionLogResponse,
  VersionPolicyResponse,
  VersionStatusRequest,
  VersionStatusResponse,
  ViewSelection,
  VolumeDetail,
  VolumeListResponse,
  XattrListResponse,
} from "./types.js";

export interface CapabilityClient {
  getCapabilities(options?: RequestOptions): Promise<CapabilitiesResponse>;
}
export interface VolumeClient {
  listVolumes(options?: PageOptions): Promise<VolumeListResponse>;
  getVolume(volume: string, options?: RequestOptions): Promise<VolumeDetail>;
}
export interface FileSystemReadClient extends CapabilityClient, VolumeClient {
  listEntries(
    volume: string,
    selector: EntrySelector,
    view: ViewSelection,
    options?: PageOptions,
  ): Promise<EntryListResponse>;
  readContent(
    volume: string,
    selector: EntrySelector,
    view: ViewSelection,
    options?: RequestOptions & {
      range?: { start: number; end?: number };
      onProgress?: (progress: UploadProgress) => void;
    },
  ): Promise<ContentReadResult>;
}
export interface FileSystemMutationClient {
  uploadContent(
    volume: string,
    selector: EntrySelector | UploadTarget,
    content: ReadableStream<Uint8Array> | Blob,
    options?: RequestOptions & {
      ifMatch?: string;
      onProgress?: (progress: UploadProgress) => void;
    },
  ): Promise<Entry>;
  createEntry(
    volume: string,
    request: CreateEntryRequest,
    options?: RequestOptions,
  ): Promise<Entry>;
  updateEntry(
    volume: string,
    request: UpdateEntryRequest,
    options?: RequestOptions & { ifMatch?: string },
  ): Promise<Entry>;
  deleteEntry(
    volume: string,
    entryId: string,
    recursive: boolean,
    options?: RequestOptions & { ifMatch?: string },
  ): Promise<void>;
  startOperation(
    volume: string,
    request: OperationRequest,
    options?: RequestOptions,
  ): Promise<OperationResult>;
}
export interface FileSystemMetadataClient {
  getXattrs(
    volume: string,
    entryId: string,
    view: ViewSelection,
    options?: RequestOptions,
  ): Promise<XattrListResponse>;
  updateXattrs(
    volume: string,
    entryId: string,
    request: UpdateXattrsRequest,
    options?: RequestOptions & { ifMatch?: string },
  ): Promise<XattrListResponse>;
}
export interface FileSystemClient
  extends FileSystemReadClient,
    FileSystemMutationClient,
    FileSystemMetadataClient {}

export interface SnapshotClient {
  listSnapshots(
    volume: string,
    options?: PageOptions,
  ): Promise<SnapshotListResponse>;
  createSnapshot(
    volume: string,
    name: string | undefined,
    options?: RequestOptions,
  ): Promise<SnapshotCreateResponse>;
  cloneSnapshot(
    volume: string,
    snapshotRef: string,
    newVolume: string,
    options?: RequestOptions,
  ): Promise<SnapshotCloneResponse>;
}
export interface VersionClient {
  getVersionPolicy(
    volume: string,
    options?: RequestOptions,
  ): Promise<VersionPolicyResponse>;
  enableVersioning(
    volume: string,
    options?: RequestOptions,
  ): Promise<VersionPolicyResponse>;
  getStatus(
    volume: string,
    request: VersionStatusRequest,
    options?: RequestOptions,
  ): Promise<VersionStatusResponse>;
  commit(
    volume: string,
    request: VersionCommitRequest,
    options?: RequestOptions,
  ): Promise<VersionCommitResponse>;
  getLog(
    volume: string,
    reference: string,
    options?: PageOptions,
  ): Promise<VersionLogResponse>;
  showCommit(
    volume: string,
    commit: string,
    options?: RequestOptions,
  ): Promise<VersionCommitResponse>;
  getRefs(
    volume: string,
    options?: RequestOptions,
  ): Promise<{
    branches: BranchListResponse["branches"];
    tags: TagListResponse["tags"];
  }>;
  getBranches(
    volume: string,
    options?: RequestOptions,
  ): Promise<BranchListResponse>;
  createBranch(
    volume: string,
    request: BranchRequest,
    options?: RequestOptions,
  ): Promise<BranchCreateResponse>;
  getTags(volume: string, options?: RequestOptions): Promise<TagListResponse>;
  createTag(
    volume: string,
    request: TagRequest,
    options?: RequestOptions,
  ): Promise<TagCreateResponse>;
  getDiff(
    volume: string,
    from: string,
    to: string,
    options?: PageOptions,
  ): Promise<VersionDiffResponse>;
  previewRestore(
    volume: string,
    request: RestoreRequest,
    options?: RequestOptions,
  ): Promise<RestorePreviewResponse>;
  applyRestore(
    volume: string,
    request: RestoreRequest & { token: string },
    options?: RequestOptions,
  ): Promise<RestoreApplyResponse>;
}
export interface CollaborationClient {
  previewMerge(
    volume: string,
    request: MergeRequest & { target: string },
    options?: RequestOptions,
  ): Promise<MergePreviewResponse>;
  applyMerge(
    volume: string,
    request: MergeRequest & { target: string },
    options?: RequestOptions,
  ): Promise<MergeApplyResponse>;
  previewCherryPick(
    volume: string,
    request: CherryPickRequest & { target: string },
    options?: RequestOptions,
  ): Promise<CherryPickPreviewResponse>;
  applyCherryPick(
    volume: string,
    request: CherryPickRequest & { target: string },
    options?: RequestOptions,
  ): Promise<CherryPickApplyResponse>;
  getReflog(
    volume: string,
    branch: string,
    options?: PageOptions,
  ): Promise<ReflogResponse>;
  getProtection(
    volume: string,
    branch: string,
    options?: RequestOptions,
  ): Promise<ProtectionResponse>;
  setProtection(
    volume: string,
    branch: string,
    request: ProtectionRequest,
    options?: RequestOptions,
  ): Promise<ProtectionResponse>;
  getAttestations(
    volume: string,
    commit: string,
    options?: RequestOptions,
  ): Promise<{ attestations: unknown[] }>;
  getQuorum(
    volume: string,
    branch: string,
    commit: string,
    options?: RequestOptions,
  ): Promise<QuorumResponse>;
}
export interface RepositoryClient {
  /** Compatibility surface. The demo BFF intentionally does not expose bundle transfer. */
  exportBundle(
    volume: string,
    request: Record<string, unknown>,
    options?: RequestOptions,
  ): Promise<ContentReadResult>;
  /** Compatibility surface. The demo BFF intentionally does not expose bundle transfer. */
  importBundle(
    volume: string,
    body: ReadableStream<Uint8Array> | Blob,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>>;
  /** Compatibility surface. The demo BFF intentionally does not accept arbitrary sync destinations. */
  syncBranch(
    volume: string,
    request: Record<string, unknown>,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>>;
  getRepositoryStats(
    volume: string,
    options?: RequestOptions,
  ): Promise<RepositoryStatsResponse>;
  verifyRepository(
    volume: string,
    options?: RequestOptions,
  ): Promise<RepositoryVerifyResponse>;
}
export interface SlateFsClient
  extends FileSystemClient,
    SnapshotClient,
    VersionClient,
    CollaborationClient,
    RepositoryClient {}
