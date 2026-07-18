import { describe, expect, it } from "vitest";
import {
  escapeHtml,
  freshWorkspaceState,
  safePath,
  safeSelection,
  safeView,
  safeVolume,
  safeWorkspace,
  workspaceHeading,
} from "../src/url-state.js";

describe("demo URL state", () => {
  it("accepts canonical consumer state", () => {
    expect(safeVolume("documents-1")).toBe("documents-1");
    expect(safePath("/projects/plan.md")).toBe("/projects/plan.md");
    expect(safeWorkspace("snapshots")).toBe("snapshots");
    expect(safeView(new URLSearchParams("view=version&ref=main"))).toEqual({
      kind: "version",
      ref: "main",
    });
  });

  it("round-trips bounded opaque selection IDs without accepting markup", () => {
    const params = new URLSearchParams();
    params.append("selection", "entry-1");
    params.append("selection", "opaque/id+2=");
    params.append("selection", "<img onerror=alert(1)>");
    expect(safeSelection(params)).toEqual(["entry-1", "opaque/id+2="]);
  });

  it.each([
    "/../secret",
    "/a/./b",
    "/a//b",
    "/a\\b",
    "/%2Fetc",
    "/<img onerror=alert(1)>",
    "/a\u0000b",
  ])("rejects hostile or non-canonical path %s", (value) => {
    expect(safePath(value)).toBe("/");
  });

  it("rejects selector and historical-ref injection", () => {
    expect(safeVolume("../tenant")).toBe("");
    expect(safeVolume("alice<script>")).toBe("");
    expect(safeWorkspace("admin")).toBe("files");
    expect(
      safeView(new URLSearchParams("view=snapshot&ref=../../other")),
    ).toEqual({ kind: "live" });
    expect(safeView(new URLSearchParams("view=version&ref=%3Csvg%3E"))).toEqual(
      { kind: "live" },
    );
  });

  it("escapes session display names before shell template insertion", () => {
    expect(escapeHtml(`<img src=x onerror="alert('x')"> & Alice`)).toBe(
      "&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt; &amp; Alice",
    );
  });

  it("resets all tenant-scoped workspace state for account switching", () => {
    expect(freshWorkspaceState()).toEqual({
      volume: "",
      path: "/",
      view: { kind: "live" },
      selection: [],
      workspace: "files",
    });
  });

  it("uses the selected workspace for the main page heading", () => {
    expect(workspaceHeading("versions", { kind: "live" })).toEqual({
      eyebrow: "COMMITS & CHANGES",
      title: "Versions",
    });
    expect(
      workspaceHeading("files", { kind: "snapshot", ref: "release" }),
    ).toEqual({ eyebrow: "SNAPSHOT · READ ONLY", title: "release" });
  });
});
