// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { OperationController } from "@slatefs/web-components";
import { OperationDrawer } from "../src/operation-drawer.js";

describe("demo operation drawer", () => {
  it("renders hostile labels as text and wires cancel/retry/dismiss/clear", async () => {
    const controller = new OperationController();
    const drawer = new OperationDrawer(controller);
    document.body.append(drawer.element);
    const cancel = vi.fn();
    const retry = vi.fn();
    const id = controller.add({
      label: '<img src=x onerror="alert(1)">',
      status: "running",
      progress: 0.5,
      cancel,
      retry,
    });
    expect(drawer.element.querySelector("img")).toBeNull();
    expect(drawer.element.textContent).toContain("<img");
    [...drawer.element.querySelectorAll("button")]
      .find((value) => value.textContent === "Cancel")!
      .click();
    expect(cancel).toHaveBeenCalledOnce();
    controller.update(id, { status: "error" });
    [...drawer.element.querySelectorAll("button")]
      .find((value) => value.textContent === "Retry")!
      .click();
    await Promise.resolve();
    expect(retry).toHaveBeenCalledOnce();
    [...drawer.element.querySelectorAll("button")]
      .find((value) => value.textContent === "Dismiss")!
      .click();
    expect(controller.operations).toHaveLength(0);
    drawer.disconnect();
  });
});
