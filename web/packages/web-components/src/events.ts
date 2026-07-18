import type {
  Entry,
  RestorePreviewResponse,
  VersionCommit,
  ViewSelection,
} from "@slatefs/client";

export interface SlateFsVolumeChangeDetail {
  version: 1;
  volume: string;
}

export interface SlateFsPathChangeDetail {
  version: 1;
  volume: string;
  path: string;
  entryId?: string;
}

export interface SlateFsSelectionChangeDetail {
  version: 1;
  selection: Entry[];
}

export interface SlateFsViewChangeDetail {
  version: 1;
  view: ViewSelection;
}

export interface SlateFsOperationDetailV1 {
  version: 1;
  operation: string;
  requestId?: string;
  entryIds: string[];
}

export interface SlateFsOperationErrorDetail extends SlateFsOperationDetailV1 {
  code: string;
  message: string;
}

export interface SlateFsAuthRequiredDetail {
  version: 1;
  requestId?: string;
}
export interface SlateFsRecursiveDeleteRequestDetail {
  version: 1;
  volume: string;
  entries: Entry[];
  reason: string;
}

export interface SlateFsEntryViewDetail {
  version: 1;
  entry: Entry;
  view: ViewSelection;
}
export interface SlateFsConflictDetail {
  version: 1;
  operation?: string;
  entry?: Entry;
  message: string;
}
export interface SlateFsCommitDetail {
  version: 1;
  commit: VersionCommit;
}
export interface SlateFsRestorePreviewDetail {
  version: 1;
  preview: RestorePreviewResponse["preview"];
}

export type SlateFsBeforeOperationEvent = CustomEvent<SlateFsOperationDetailV1>;

declare global {
  interface HTMLElementEventMap {
    "slatefs-volume-change": CustomEvent<SlateFsVolumeChangeDetail>;
    "slatefs-path-change": CustomEvent<SlateFsPathChangeDetail>;
    "slatefs-selection-change": CustomEvent<SlateFsSelectionChangeDetail>;
    "slatefs-view-change": CustomEvent<SlateFsViewChangeDetail>;
    "slatefs-before-operation": SlateFsBeforeOperationEvent;
    "slatefs-operation-start": CustomEvent<SlateFsOperationDetailV1>;
    "slatefs-operation-complete": CustomEvent<SlateFsOperationDetailV1>;
    "slatefs-operation-error": CustomEvent<SlateFsOperationErrorDetail>;
    "slatefs-auth-required": CustomEvent<SlateFsAuthRequiredDetail>;
    "slatefs-recursive-delete-request": CustomEvent<SlateFsRecursiveDeleteRequestDetail>;
    "slatefs-entry-open": CustomEvent<SlateFsEntryViewDetail>;
    "slatefs-preview-request": CustomEvent<SlateFsEntryViewDetail>;
    "slatefs-download-request": CustomEvent<SlateFsEntryViewDetail>;
    "slatefs-conflict": CustomEvent<SlateFsConflictDetail>;
    "slatefs-save-complete": CustomEvent<{ version: 1; entry: Entry }>;
    "slatefs-properties-change": CustomEvent<{ version: 1; entry: Entry }>;
    "slatefs-version-commit": CustomEvent<SlateFsCommitDetail>;
    "slatefs-commit-select": CustomEvent<{ version: 1; commit: string }>;
    "slatefs-compare-request": CustomEvent<{
      version: 1;
      from: string;
      to: string;
    }>;
    "slatefs-restore-preview": CustomEvent<SlateFsRestorePreviewDetail>;
    "slatefs-restore-complete": CustomEvent<{
      version: 1;
      restored: unknown;
    }>;
  }
}

export function createSlateFsEvent<T>(
  type: string,
  detail: T,
  cancelable = false,
): CustomEvent<T> {
  return new CustomEvent(type, {
    bubbles: true,
    composed: true,
    cancelable,
    detail,
  });
}
