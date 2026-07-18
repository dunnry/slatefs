import { createSlateFsEvent } from "./events.js";
export type OperationStatus =
  | "queued"
  | "running"
  | "success"
  | "error"
  | "canceled";
export interface SlateFsOperation {
  id: string;
  label: string;
  status: OperationStatus;
  progress: number;
  detail?: string;
  cancel?: () => void;
  retry?: () => Promise<void> | void;
}
export class OperationController extends EventTarget {
  private values = new Map<string, SlateFsOperation>();
  private sequence = 0;
  get operations() {
    return [...this.values.values()].map((value) => ({ ...value }));
  }
  add(value: Omit<SlateFsOperation, "id"> & { id?: string }) {
    let id =
      value.id ??
      globalThis.crypto?.randomUUID?.() ??
      `operation-${Date.now().toString(36)}-${(++this.sequence).toString(36)}-${Math.random().toString(36).slice(2)}`;
    while (this.values.has(id)) id = `${id}-${(++this.sequence).toString(36)}`;
    const operation = {
      ...value,
      id,
    };
    this.values.set(operation.id, operation);
    this.changed();
    return operation.id;
  }
  update(id: string, patch: Partial<SlateFsOperation>) {
    const value = this.values.get(id);
    if (value) {
      this.values.set(id, { ...value, ...patch, id });
      this.changed();
    }
  }
  cancel(id: string) {
    const value = this.values.get(id);
    if (!value) return;
    try {
      value.cancel?.();
      this.update(id, {
        status: "canceled",
        detail: "Cancel requested; refresh to confirm server state",
      });
    } catch (error) {
      this.update(id, {
        status: "error",
        detail: error instanceof Error ? error.message : "Cancel failed",
      });
    }
  }
  async retry(id: string) {
    const value = this.values.get(id);
    if (!value?.retry) return;
    this.update(id, { status: "running", progress: 0 });
    try {
      await value.retry();
      this.update(id, { status: "success", progress: 1 });
    } catch (e) {
      this.update(id, {
        status: "error",
        detail: e instanceof Error ? e.message : "Retry failed",
      });
    }
  }
  dismiss(id: string) {
    this.values.delete(id);
    this.changed();
  }
  clearCompleted() {
    for (const [id, v] of this.values)
      if (["success", "canceled"].includes(v.status)) this.values.delete(id);
    this.changed();
  }
  private changed() {
    this.dispatchEvent(
      createSlateFsEvent("slatefs-operations-change", {
        version: 1 as const,
        operations: this.operations,
      }),
    );
  }
}
