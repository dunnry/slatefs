import type { ViewSelection } from "@slatefs/client";

export const workspaces = [
  "files",
  "versions",
  "snapshots",
  "branches",
  "health",
] as const;
export type Workspace = (typeof workspaces)[number];

export interface WorkspaceState {
  volume: string;
  path: string;
  view: ViewSelection;
  selection: string[];
  workspace: Workspace;
}

export function freshWorkspaceState(): WorkspaceState {
  return {
    volume: "",
    path: "/",
    view: { kind: "live" },
    selection: [],
    workspace: "files",
  };
}

export function workspaceHeading(
  workspace: Workspace,
  view: ViewSelection,
): { eyebrow: string; title: string } {
  if (workspace === "files")
    return {
      eyebrow:
        view.kind === "live"
          ? "LIVE WORKSPACE"
          : `${view.kind.toUpperCase()} · READ ONLY`,
      title: view.kind === "live" ? "Files" : (view.ref ?? "Files"),
    };
  return {
    versions: { eyebrow: "COMMITS & CHANGES", title: "Versions" },
    snapshots: { eyebrow: "POINT-IN-TIME RECOVERY", title: "Snapshots" },
    branches: { eyebrow: "COLLABORATION", title: "Branches" },
    health: { eyebrow: "INTEGRITY & MAINTENANCE", title: "Health" },
  }[workspace];
}

export const escapeHtml = (value: string | undefined) =>
  (value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character]!,
  );

const segment = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ref = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;

export function safeVolume(value: string | null): string {
  return value && segment.test(value) && value !== "." && value !== ".."
    ? value
    : "";
}

export function safePath(value: string | null): string {
  if (
    !value ||
    !value.startsWith("/") ||
    value.includes("\\") ||
    /%(?:00|2f|5c)/i.test(value) ||
    /[<>]/.test(value) ||
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code <= 31 || code === 127;
    })
  )
    return "/";
  const pieces = value.split("/");
  if (
    pieces.some(
      (piece, index) =>
        index > 0 && (!piece || piece === "." || piece === ".."),
    )
  )
    return "/";
  return `/${pieces.slice(1).join("/")}`;
}

export function safeWorkspace(value: string | null): Workspace {
  return workspaces.includes(value as Workspace)
    ? (value as Workspace)
    : "files";
}

export function safeView(params: URLSearchParams): ViewSelection {
  const kind = params.get("view");
  const value = params.get("ref");
  if (
    (kind === "snapshot" || kind === "version") &&
    value &&
    ref.test(value) &&
    !value.includes("..")
  )
    return { kind, ref: value };
  return { kind: "live" };
}

export function safeSelection(params: URLSearchParams): string[] {
  return params
    .getAll("selection")
    .filter(
      (value) =>
        value.length > 0 &&
        value.length <= 256 &&
        !/[<>]/.test(value) &&
        ![...value].some((character) => {
          const code = character.charCodeAt(0);
          return code <= 31 || code === 127;
        }),
    )
    .slice(0, 100);
}
