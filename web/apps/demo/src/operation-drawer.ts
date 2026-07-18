import type {
  OperationController,
  SlateFsOperation,
} from "@slatefs/web-components";

function button(label: string, action: () => void): HTMLButtonElement {
  const value = document.createElement("button");
  value.type = "button";
  value.textContent = label;
  value.addEventListener("click", action);
  return value;
}

export class OperationDrawer {
  readonly element = document.createElement("aside");
  private readonly listener = () => this.render();

  constructor(private readonly controller: OperationController) {
    this.element.className = "operation-drawer";
    this.element.setAttribute("aria-label", "Recent file operations");
    controller.addEventListener("slatefs-operations-change", this.listener);
    this.render();
  }

  disconnect() {
    this.controller.removeEventListener(
      "slatefs-operations-change",
      this.listener,
    );
    this.element.remove();
  }

  private actions(operation: SlateFsOperation) {
    const wrapper = document.createElement("span");
    wrapper.className = "operation-actions";
    if (operation.status === "queued" || operation.status === "running")
      wrapper.append(
        button("Cancel", () => this.controller.cancel(operation.id)),
      );
    if (operation.status === "error" && operation.retry)
      wrapper.append(
        button("Retry", () => void this.controller.retry(operation.id)),
      );
    wrapper.append(
      button("Dismiss", () => this.controller.dismiss(operation.id)),
    );
    return wrapper;
  }

  private render() {
    const operations = this.controller.operations;
    this.element.replaceChildren();
    const header = document.createElement("header");
    const title = document.createElement("strong");
    title.textContent = "Operations";
    const active = operations.filter(
      (operation) =>
        operation.status === "queued" || operation.status === "running",
    ).length;
    const status = document.createElement("span");
    status.textContent = `${active} active`;
    header.append(
      title,
      status,
      button("Clear completed", () => this.controller.clearCompleted()),
    );
    this.element.append(header);
    if (!operations.length) {
      const empty = document.createElement("p");
      empty.textContent = "No recent file operations.";
      this.element.append(empty);
      return;
    }
    const list = document.createElement("ul");
    list.setAttribute("aria-live", "polite");
    for (const operation of operations) {
      const item = document.createElement("li");
      const text = document.createElement("span");
      text.textContent = `${operation.label}: ${operation.status}${
        operation.detail ? ` — ${operation.detail}` : ""
      }`;
      const progress = document.createElement("progress");
      progress.max = 1;
      progress.value = operation.progress;
      progress.setAttribute(
        "aria-label",
        `${operation.label} ${Math.round(operation.progress * 100)}%`,
      );
      item.append(text, progress, this.actions(operation));
      list.append(item);
    }
    this.element.append(list);
  }
}
