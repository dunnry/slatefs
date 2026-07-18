// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import {
  applyViewMode,
  compareInDiff,
  createRefreshScheduler,
  exactBrowseView,
  revealRecoveryLog,
  selectPublishTarget,
  showHostMessage,
} from "../src/component-wiring.js";

describe("component wiring", () => {
  it("applies history comparison endpoints and explicitly refreshes the diff", async () => {
    const target = {
      from: "main",
      to: "main",
      updateComplete: Promise.resolve(),
      refresh: vi.fn().mockResolvedValue(undefined),
    };
    await compareInDiff(target, { from: "c1", to: "c2" });
    expect(target).toMatchObject({ from: "c1", to: "c2" });
    expect(target.refresh).toHaveBeenCalledOnce();
  });

  it("pins branch and version browsing to the exact requested commit", () => {
    expect(exactBrowseView({ kind: "version", ref: "abc123" })).toEqual({
      kind: "version",
      ref: "abc123",
      resolvedCommit: "abc123",
    });
    expect(
      exactBrowseView({
        kind: "version",
        ref: "release",
        resolved_commit: "def456",
      }),
    ).toEqual({
      kind: "version",
      ref: "release",
      resolved_commit: "def456",
      resolvedCommit: "def456",
    });
  });

  it("restores writable component state when returning live", () => {
    const targets = [
      { view: { kind: "version" as const, ref: "abc" }, readonly: true },
      { view: { kind: "version" as const, ref: "abc" }, readonly: true },
    ];
    applyViewMode(targets, { kind: "live" });
    expect(targets).toEqual([
      { view: { kind: "live" }, readonly: false },
      { view: { kind: "live" }, readonly: false },
    ]);
  });

  it("propagates the selected branch to new version publishing", () => {
    const status = { targetBranch: "main", reference: "main" };
    selectPublishTarget(status, "release");
    expect(status).toEqual({ targetBranch: "release", reference: "release" });
  });

  it("selects and expands the requested branch recovery log", async () => {
    const target = document.createElement("div") as HTMLDivElement & {
      branch: string;
      updateComplete: Promise<unknown>;
    };
    target.attachShadow({ mode: "open" }).innerHTML =
      '<details part="reflog"><summary tabindex="-1">Recovery log</summary></details>';
    const summary = target.shadowRoot!.querySelector<HTMLElement>("summary")!;
    summary.focus = vi.fn();
    target.branch = "main";
    target.updateComplete = Promise.resolve();
    await revealRecoveryLog(target, "release");
    expect(target.branch).toBe("release");
    expect(target.shadowRoot!.querySelector("details")!.open).toBe(true);
    expect(summary.focus).toHaveBeenCalledOnce();
  });

  it("announces unsupported recursive deletion inline", () => {
    const root = document.createElement("div");
    root.innerHTML = '<p id="host-message" hidden></p>';
    showHostMessage(root, "No files were changed.");
    const message = root.querySelector<HTMLElement>("#host-message")!;
    expect(message.hidden).toBe(false);
    expect(message.textContent).toBe("No files were changed.");
  });

  it("coalesces mutation invalidations without suppressing distinct targets", async () => {
    const order: string[] = [];
    const first = { refresh: vi.fn().mockResolvedValue(undefined) };
    first.refresh.mockImplementation(async () => {
      order.push("first");
    });
    const second = {
      refresh: vi.fn().mockImplementation(async () => {
        order.push("second");
      }),
    };
    const refresh = createRefreshScheduler();
    refresh(first, second);
    refresh(first);
    await Promise.resolve();
    await Promise.resolve();
    expect(first.refresh).toHaveBeenCalledOnce();
    expect(second.refresh).toHaveBeenCalledOnce();
    expect(order).toEqual(["first", "second"]);
  });
});
