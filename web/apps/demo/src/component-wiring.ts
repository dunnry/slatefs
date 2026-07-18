import type { ViewSelection } from "@slatefs/client";

export interface DiffTarget {
  from: string;
  to: string;
  updateComplete: Promise<unknown>;
  refresh(): Promise<unknown>;
}

export interface RefreshTarget {
  refresh(): Promise<unknown>;
}

export interface ViewTarget {
  view: ViewSelection;
  readonly: boolean;
}

export interface RecoveryLogTarget {
  branch: string;
  updateComplete: Promise<unknown>;
  shadowRoot: ShadowRoot | null;
}

export interface PublishTarget {
  targetBranch: string;
  reference: string;
}

/** Pins version browsing to the immutable commit named by the request. */
export function exactBrowseView(requested: ViewSelection): ViewSelection {
  if (requested.kind !== "version") return { ...requested };
  const resolved =
    requested.resolvedCommit ?? requested.resolved_commit ?? requested.ref;
  return resolved
    ? { ...requested, resolvedCommit: resolved }
    : { ...requested };
}

/** Keeps every component's explicit host mode aligned with its selected view. */
export function applyViewMode(
  targets: Iterable<ViewTarget>,
  selectedView: ViewSelection,
) {
  const readonly = selectedView.kind !== "live";
  for (const target of targets)
    Object.assign(target, { view: selectedView, readonly });
}

export function selectPublishTarget(target: PublishTarget, branch: string) {
  target.targetBranch = branch;
  target.reference = branch;
}

/** Selects and expands the branch recovery log requested from version history. */
export async function revealRecoveryLog(
  target: RecoveryLogTarget,
  reference: string,
) {
  target.branch = reference;
  await target.updateComplete;
  const details =
    target.shadowRoot?.querySelector<HTMLDetailsElement>('[part~="reflog"]');
  if (!details) return;
  details.open = true;
  details.querySelector<HTMLElement>("summary")?.focus();
}

/** Coalesces sibling invalidations raised by one mutation into one refresh per target. */
export function createRefreshScheduler() {
  const queued = new Set<RefreshTarget>();
  let scheduled = false;
  return (...targets: Array<RefreshTarget | undefined>) => {
    for (const target of targets) if (target) queued.add(target);
    if (scheduled) return;
    scheduled = true;
    queueMicrotask(() => {
      scheduled = false;
      const current = [...queued];
      queued.clear();
      void (async () => {
        // Version-store operations may briefly replace the underlying reader
        // after a write. Refresh dependents in order so one screen does not
        // race several repository clients against that handoff.
        for (const target of current) {
          try {
            await target.refresh();
          } catch {
            // Components render and emit their own load errors.
          }
        }
      })();
    });
  };
}

export async function compareInDiff(
  target: DiffTarget,
  comparison: { from: string; to: string },
) {
  target.from = comparison.from;
  target.to = comparison.to;
  await target.updateComplete;
  await target.refresh();
}

export function showHostMessage(container: ParentNode, text: string) {
  const message = container.querySelector<HTMLElement>("#host-message");
  if (!message) return;
  message.hidden = false;
  message.textContent = text;
}
