import {
  createSlateFsClient,
  type Entry,
  type ViewSelection,
} from "@slatefs/client";
import {
  OperationController,
  type SlateFsFileExplorer,
  type SlateFsFileProperties,
  type SlateFsFilePreview,
  type SlateFsDiffViewer,
} from "@slatefs/web-components";
import "./styles.css";
import {
  escapeHtml,
  freshWorkspaceState,
  safePath,
  safeSelection,
  safeView,
  safeVolume,
  safeWorkspace,
  workspaceHeading,
} from "./url-state.js";
import { OperationDrawer } from "./operation-drawer.js";
import {
  applyViewMode,
  compareInDiff,
  createRefreshScheduler,
  exactBrowseView,
  revealRecoveryLog,
  selectPublishTarget,
  showHostMessage,
  type RecoveryLogTarget,
  type RefreshTarget,
} from "./component-wiring.js";

interface Session {
  authenticated: boolean;
  csrfToken: string;
  user?: { username: string; displayName: string };
  expiresAt?: string;
  capabilities?: {
    snapshots: boolean;
    versions: boolean;
    collaboration: boolean;
    repository: boolean;
  };
}
interface VersionOverview {
  status: { changes: Array<Record<string, unknown>> } & Record<string, unknown>;
  commits: Array<Record<string, unknown>>;
  branches: Array<Record<string, unknown>>;
  entries: Array<Record<string, unknown>>;
  next_page_token?: string | null;
}
interface BranchOverview {
  branches: Array<Record<string, unknown>>;
  entries: Array<Record<string, unknown>>;
}
const root = document.querySelector<HTMLElement>("#app")!;
let session: Session;
let view: ViewSelection = { kind: "live" };
let volume = "";
let path = "/";
let selection: string[] = [];
let operations = new OperationController();
let operationDrawer: OperationDrawer | undefined;
function resetAccountWorkspace() {
  const fresh = freshWorkspaceState();
  volume = fresh.volume;
  path = fresh.path;
  view = fresh.view;
  selection = fresh.selection;
  operations = new OperationController();
  history.replaceState(null, "", location.pathname);
}
function updateUrl(replace = false) {
  const q = new URLSearchParams();
  if (volume) q.set("volume", volume);
  if (path !== "/") q.set("path", path);
  q.set(
    "workspace",
    document.querySelector<HTMLButtonElement>(".tab[aria-selected=true]")
      ?.dataset.tab ?? "files",
  );
  if (view.kind !== "live") {
    q.set("view", view.kind);
    if (view.ref) q.set("ref", view.ref);
  }
  for (const entryId of selection) q.append("selection", entryId);
  history[replace ? "replaceState" : "pushState"](
    null,
    "",
    `${location.pathname}?${q}`,
  );
}
async function raw<T>(url: string, init?: RequestInit) {
  const r = await fetch(url, init);
  if (!r.ok) {
    const failure = await r
      .json()
      .catch(() => ({ error: { message: `Request failed (${r.status})` } }));
    const detail = failure as {
      error?: { code?: string; message?: string; request_id?: string };
    };
    throw Object.assign(
      new Error(detail.error?.message ?? `Request failed (${r.status})`),
      {
        status: r.status,
        code: detail.error?.code,
        requestId: detail.error?.request_id,
      },
    );
  }
  return r.json() as Promise<T>;
}
async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(session?.csrfToken ? { "x-csrf-token": session.csrfToken } : {}),
      ...init.headers,
    },
  });
  if (response.status === 401) {
    session = await raw<Session>("/api/v1/session");
    resetAccountWorkspace();
    render();
    throw new Error("Session expired");
  }
  if (!response.ok)
    throw new Error(
      (
        await response
          .json()
          .catch(() => ({ error: { message: "Request failed" } }))
      ).error?.message,
    );
  return response.status === 204 ? (undefined as T) : response.json();
}
async function login(username: string) {
  const status = root.querySelector<HTMLElement>("[role=status]")!;
  status.textContent = "Signing in…";
  try {
    session = await request<Session>("/api/v1/login", {
      method: "POST",
      body: JSON.stringify({ username, password: "slatefs" }),
    });
    render();
  } catch (e) {
    status.textContent = e instanceof Error ? e.message : "Sign-in failed";
  }
}
async function logout() {
  await request<void>("/api/v1/logout", { method: "POST" });
  session = await raw<Session>("/api/v1/session");
  resetAccountWorkspace();
  render();
}
function loginScreen() {
  root.innerHTML = `<main class="login"><section class="login-card"><div class="brand-mark">S</div><p class="eyebrow">SlateFS Consumer Demo</p><h1>Your files, with a memory.</h1><p class="lede">Browse a familiar filesystem, then step back through snapshots and intentional versions without leaving your workspace.</p><form><fieldset><legend>Choose a demo workspace</legend><button class="account" type="button" value="alice"><span class="avatar alice">A</span><span><strong>Alice</strong><small>Acme workspace · password: slatefs</small></span><span class="go" aria-hidden="true">→</span></button><button class="account" type="button" value="bob"><span class="avatar bob">B</span><span><strong>Bob</strong><small>Globex workspace · password: slatefs</small></span><span class="go" aria-hidden="true">→</span></button></fieldset><p role="status" aria-live="polite"></p></form><p class="privacy">Each account is locked to its own tenant. No tenant selector or SlateFS token reaches this browser.</p></section><aside class="login-art" aria-hidden="true"><div class="strata"><i></i><i></i><i></i><i></i></div><p>Live files<br><span>Snapshots</span><br><span>Version history</span></p></aside></main>`;
  root
    .querySelectorAll<HTMLButtonElement>(".account")
    .forEach((b) => b.addEventListener("click", () => void login(b.value)));
}
function shell() {
  const p = new URLSearchParams(location.search);
  volume = volume || safeVolume(p.get("volume"));
  path = path === "/" ? safePath(p.get("path")) : path;
  if (view.kind === "live") view = safeView(p);
  if (!selection.length) selection = safeSelection(p);
  if (!session.user || !["alice", "bob"].includes(session.user.username)) {
    void logout();
    return;
  }
  const tenant = session.user!.username === "alice" ? "Acme" : "Globex";
  root.innerHTML = `<div class="app"><header class="topbar"><a class="brand" href="/" aria-label="SlateFS home"><span>S</span> SlateFS</a><div class="tenant"><span class="tenant-dot"></span><span><strong>${escapeHtml(session.user.displayName)}</strong><small>${tenant} workspace</small></span></div><button id="switch">Switch account</button></header><nav class="rail" aria-label="Workspace" role="tablist"><button class="tab" role="tab" aria-controls="panel-files" data-tab="files" aria-selected="true"><b>◈</b>Files</button><button class="tab" role="tab" aria-controls="panel-versions" data-tab="versions"><b>⟟</b>Versions</button><button class="tab" role="tab" aria-controls="panel-snapshots" data-tab="snapshots"><b>◉</b>Snapshots</button><button class="tab" role="tab" aria-controls="panel-branches" data-tab="branches"><b>⑂</b>Branches</button><button class="tab" role="tab" aria-controls="panel-health" data-tab="health"><b>♥</b>Health</button><div class="rail-foot"><span>Tenant isolated</span><button id="logout">Sign out</button></div></nav><main class="workspace"><p id="host-message" class="host-message" role="status" aria-live="polite" hidden></p><div class="workspace-head"><div><p class="eyebrow">${view.kind === "live" ? "LIVE WORKSPACE" : `${view.kind.toUpperCase()} · READ ONLY`}</p><h1>${view.kind === "live" ? "Files" : escapeHtml(view.ref)}</h1></div><div class="workspace-actions"><button id="return-live" type="button" hidden>Return to live files</button><slatefs-volume-picker></slatefs-volume-picker></div></div><section id="panel-files" role="tabpanel" class="panel active" data-panel="files"><slatefs-file-explorer></slatefs-file-explorer><aside class="inspector"><div class="inspector-tabs" role="tablist" aria-label="File inspector"><button role="tab" aria-controls="file-preview" data-inspect="preview" aria-selected="true">Preview</button><button role="tab" aria-controls="file-properties" data-inspect="details">Details</button></div><slatefs-file-preview id="file-preview" role="tabpanel" editable></slatefs-file-preview><slatefs-file-properties id="file-properties" role="tabpanel" hidden></slatefs-file-properties></aside></section><section id="panel-versions" role="tabpanel" class="panel" data-panel="versions"><slatefs-version-status></slatefs-version-status><slatefs-version-history></slatefs-version-history><slatefs-diff-viewer></slatefs-diff-viewer><slatefs-restore-dialog></slatefs-restore-dialog></section><section id="panel-snapshots" role="tabpanel" class="panel" data-panel="snapshots"><slatefs-snapshot-manager></slatefs-snapshot-manager></section><section id="panel-branches" role="tabpanel" class="panel" data-panel="branches"><slatefs-branch-manager></slatefs-branch-manager></section><section id="panel-health" role="tabpanel" class="panel" data-panel="health"><slatefs-repository-tools></slatefs-repository-tools></section></main></div>`;
  const client = createSlateFsClient({
    baseUrl: "/api",
    getCsrfToken: () => session.csrfToken,
    onAuthRequired: () =>
      void raw<Session>("/api/v1/session").then((s) => {
        session = s;
        render();
      }),
  });
  const versionOverviewCache = new Map<string, Promise<VersionOverview>>();
  const versionPolicyCache = new Map<string, Promise<boolean>>();
  const repositoryStatsCache = new Map<
    string,
    ReturnType<typeof client.getRepositoryStats>
  >();
  const invalidateVersionOverview = (selectedVolume: string) => {
    versionOverviewCache.delete(selectedVolume);
    repositoryStatsCache.delete(selectedVolume);
  };
  const listInitialVersionPaths = async (selectedVolume: string) => {
    const directories: Array<{
      selector: { entryId?: string; path?: string };
      canonicalPath: string;
    }> = [{ selector: { path: "/" }, canonicalPath: "/" }];
    const paths: string[] = [];
    let visited = 0;
    while (directories.length && visited < 5_000) {
      const directory = directories.shift()!;
      let pageToken: string | undefined;
      do {
        const result = await client.listEntries(
          selectedVolume,
          directory.selector,
          { kind: "live" },
          { limit: 200, pageToken },
        );
        visited += result.entries.length;
        for (const entry of result.entries) {
          const name = entry.name;
          if (!name) continue;
          const entryPath =
            entry.path ??
            `${directory.canonicalPath === "/" ? "" : directory.canonicalPath}/${name}`;
          if (entry.kind === "directory")
            directories.push({
              selector: { entryId: entry.entry_id },
              canonicalPath: entryPath,
            });
          else if (entry.kind === "file") paths.push(entryPath);
        }
        pageToken = result.next_page_token ?? undefined;
      } while (pageToken && visited < 5_000);
    }
    return [...new Set(paths)].sort();
  };
  const seededVersioningEnabled = (selectedVolume: string) =>
    selectedVolume ===
    (session.user!.username === "alice"
      ? "acme-demo-documents"
      : "globex-demo-documents");
  const loadVersioningEnabled = (selectedVolume: string) => {
    if (seededVersioningEnabled(selectedVolume)) return Promise.resolve(true);
    let pending = versionPolicyCache.get(selectedVolume);
    if (!pending) {
      pending = client
        .getVersionPolicy(selectedVolume)
        .then((result) => result.versioning.enabled);
      versionPolicyCache.set(selectedVolume, pending);
      void pending.catch(() => versionPolicyCache.delete(selectedVolume));
    }
    return pending;
  };
  const loadVersionOverview = (selectedVolume: string) => {
    let pending = versionOverviewCache.get(selectedVolume);
    if (!pending) {
      const query = new URLSearchParams({
        reference: "main",
        path: "/",
        branch: "main",
        limit: "50",
      });
      pending = raw<VersionOverview>(
        `/api/v1/volumes/${encodeURIComponent(selectedVolume)}/versioning/overview?${query}`,
      ).catch(async (error) => {
        const value = error as { status?: number; message?: string };
        if (
          value.status === 404 &&
          value.message?.includes(
            'version commit, tag, or branch "main" not found',
          )
        ) {
          const paths = await listInitialVersionPaths(selectedVolume);
          return {
            status: {
              reference: "main",
              commit: "",
              root: "/",
              changes: paths.map((path) => ({ path, change: "added" })),
            },
            commits: [],
            branches: [],
            entries: [],
            next_page_token: null,
          } satisfies VersionOverview;
        }
        throw error;
      });
      versionOverviewCache.set(selectedVolume, pending);
      void pending.catch(() => invalidateVersionOverview(selectedVolume));
    }
    return pending;
  };
  const versionOverviewClient = {
    ...client,
    getVersionPolicy: (selectedVolume: string) =>
      loadVersioningEnabled(selectedVolume).then((enabled) => ({
        versioning: { enabled },
      })),
    getStatus: (selectedVolume: string) =>
      loadVersionOverview(selectedVolume).then((overview) => ({
        status: overview.status,
      })),
    getLog: (selectedVolume: string) =>
      loadVersionOverview(selectedVolume).then((overview) => ({
        commits: overview.commits,
        next_page_token: overview.next_page_token ?? null,
      })),
  };
  const loadRepositoryStats = (selectedVolume: string) => {
    let pending = repositoryStatsCache.get(selectedVolume);
    if (!pending) {
      // Repository open is the expensive part. Let the shared overview warm
      // the daemon's per-volume read repository before scanning statistics.
      pending = loadVersionOverview(selectedVolume).then(() =>
        client.getRepositoryStats(selectedVolume),
      );
      repositoryStatsCache.set(selectedVolume, pending);
      void pending.catch(() => repositoryStatsCache.delete(selectedVolume));
    }
    return pending;
  };
  const repositoryOverviewClient = {
    ...client,
    getRepositoryStats: loadRepositoryStats,
  };
  const branchOverviewCache = new Map<string, Promise<BranchOverview>>();
  const branchOverviewKey = (selectedVolume: string, branch: string) =>
    `${selectedVolume}\n${branch}`;
  const invalidateBranchOverview = (selectedVolume: string) => {
    for (const key of branchOverviewCache.keys())
      if (key.startsWith(`${selectedVolume}\n`))
        branchOverviewCache.delete(key);
  };
  const loadBranchOverview = (selectedVolume: string, branch = "main") => {
    const key = branchOverviewKey(selectedVolume, branch);
    let pending = branchOverviewCache.get(key);
    if (!pending) {
      if (branch === "main") {
        pending = loadVersionOverview(selectedVolume).then((overview) => ({
          branches: overview.branches,
          entries: overview.entries,
        }));
      } else {
        const query = new URLSearchParams({ branch, limit: "50" });
        pending = raw<BranchOverview>(
          `/api/v1/volumes/${encodeURIComponent(selectedVolume)}/versioning/branch-overview?${query}`,
        );
      }
      branchOverviewCache.set(key, pending);
      void pending.catch(() => branchOverviewCache.delete(key));
    }
    return pending;
  };
  const branchOverviewClient = {
    ...client,
    getBranches: (selectedVolume: string) =>
      loadBranchOverview(selectedVolume).then((overview) => ({
        branches: overview.branches,
      })),
    getReflog: (selectedVolume: string, branch = "main") =>
      loadBranchOverview(selectedVolume, branch).then((overview) => ({
        entries: overview.entries,
      })),
    getProtection: async (selectedVolume: string, branch = "main") => {
      const overview = await loadBranchOverview(selectedVolume, branch);
      const selected = overview.branches.find((item) => item.name === branch);
      return {
        protection: {
          protected: selected?.protected === true,
          allowed_committers: selected?.allowed_committers ?? [],
          allowed_managers: selected?.allowed_managers ?? [],
          trusted_attestation_keys: selected?.trusted_attestation_keys ?? [],
          required_attestations: selected?.required_attestations ?? 0,
        },
      };
    },
  };
  const all = root.querySelectorAll<HTMLElement>(
    "slatefs-volume-picker,slatefs-file-explorer,slatefs-file-preview,slatefs-file-properties,slatefs-snapshot-manager,slatefs-version-status,slatefs-version-history,slatefs-diff-viewer,slatefs-branch-manager,slatefs-restore-dialog,slatefs-repository-tools",
  );
  const enabledFor = (element: Element) => {
    const tag = element.localName;
    if (tag === "slatefs-snapshot-manager")
      return session.capabilities?.snapshots !== false;
    if (tag === "slatefs-branch-manager")
      return (
        session.capabilities?.versions !== false &&
        session.capabilities?.collaboration !== false
      );
    if (tag === "slatefs-repository-tools")
      return session.capabilities?.repository !== false;
    if (
      [
        "slatefs-version-status",
        "slatefs-version-history",
        "slatefs-diff-viewer",
        "slatefs-restore-dialog",
      ].includes(tag)
    )
      return session.capabilities?.versions !== false;
    return true;
  };
  const initialWorkspace = safeWorkspace(p.get("workspace"));
  for (const el of all) {
    const usesAggregatedVersionRead =
      el.localName === "slatefs-version-status" ||
      el.localName === "slatefs-version-history" ||
      el.localName === "slatefs-branch-manager" ||
      el.localName === "slatefs-repository-tools";
    Object.assign(el, {
      client:
        enabledFor(el) &&
        !usesAggregatedVersionRead &&
        (!el.closest("[data-panel]") ||
          el.closest<HTMLElement>("[data-panel]")?.dataset.panel ===
            initialWorkspace)
          ? client
          : undefined,
      volume,
      path,
      view,
    });
  }
  const picker = root.querySelector<
    HTMLElement & { autoSelectSingle: boolean }
  >("slatefs-volume-picker");
  if (picker) picker.autoSelectSingle = true;
  const status = root.querySelector<
    HTMLElement & { author: string; versioningEnabled?: boolean }
  >("slatefs-version-status");
  if (status) {
    status.author = session.user.displayName;
    // Seeded consumer-demo volumes are always versioned. Supplying this known
    // state avoids a costly policy round-trip before status can load.
    status.versioningEnabled = seededVersioningEnabled(volume)
      ? true
      : undefined;
  }
  const explorer = root.querySelector<SlateFsFileExplorer>(
    "slatefs-file-explorer",
  )!;
  const preview = root.querySelector<SlateFsFilePreview>(
    "slatefs-file-preview",
  )!;
  const metadata = root.querySelector<SlateFsFileProperties>(
    "slatefs-file-properties",
  )!;
  const refreshTarget = (selector: string) =>
    root.querySelector<HTMLElement & RefreshTarget>(selector) ?? undefined;
  const versionStatus = refreshTarget("slatefs-version-status");
  const versionHistory = refreshTarget("slatefs-version-history");
  const branchManager = refreshTarget("slatefs-branch-manager");
  const repositoryTools = refreshTarget("slatefs-repository-tools");
  const volumePicker = refreshTarget("slatefs-volume-picker");
  const refreshAfterMutation = createRefreshScheduler();
  const waitForVolume = async (name: string) => {
    for (let attempt = 0; attempt < 80; attempt++) {
      try {
        const inventory = await client.listVolumes();
        if (!inventory.volumes.some((candidate) => candidate.name === name))
          throw new Error("Clone is not visible yet");
        // Filesystem reads can succeed before the control plane finishes the
        // Creating -> Active transition. Snapshot listing exercises the same
        // readiness boundary as the destination workspace.
        await client.listSnapshots(name, { limit: 1 });
        return true;
      } catch {
        // A later attempt may succeed while the clone transitions to Active.
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    return false;
  };
  const activeWorkspaceIs = (name: string) =>
    root.querySelector<HTMLElement>(".tab[aria-selected=true]")?.dataset.tab ===
    name;
  const warmVersionWorkspace = () => {
    if (!volume || !versionStatus) return;
    if (
      enabledFor(versionStatus) &&
      !(versionStatus as { client?: object }).client
    )
      Object.assign(versionStatus, {
        client: versionOverviewClient,
        volume,
        path,
        view,
      });
    const selectedVolume = volume;
    void loadVersioningEnabled(selectedVolume).then(
      (enabled) => {
        if (volume !== selectedVolume) return;
        if (status) status.versioningEnabled = enabled;
        if (
          enabled &&
          versionHistory &&
          enabledFor(versionHistory) &&
          !(versionHistory as { client?: object }).client &&
          activeWorkspaceIs("versions")
        )
          Object.assign(versionHistory, {
            client: versionOverviewClient,
            volume,
            path,
            view,
          });
      },
      () => {
        // The status component renders the policy error with request context.
      },
    );
  };
  const warmBranchWorkspace = () => {
    if (!volume || !branchManager) return;
    const selectedVolume = volume;
    void loadVersioningEnabled(selectedVolume).then(
      (enabled) => {
        if (volume !== selectedVolume || !activeWorkspaceIs("branches")) return;
        if (!enabled) {
          showHostMessage(
            root,
            "Versioning is not enabled for this writable copy. Enable it from the Versions tab before using branches.",
          );
          return;
        }
        if (
          enabledFor(branchManager) &&
          !(branchManager as { client?: object }).client
        )
          Object.assign(branchManager, {
            client: branchOverviewClient,
            volume,
            path,
            view,
          });
      },
      (error) =>
        showHostMessage(
          root,
          error instanceof Error
            ? error.message
            : "Unable to determine versioning status.",
        ),
    );
  };
  const warmHealthWorkspace = () => {
    if (!volume || !repositoryTools) return;
    const selectedVolume = volume;
    void loadVersioningEnabled(selectedVolume).then(
      (enabled) => {
        if (volume !== selectedVolume || !activeWorkspaceIs("health")) return;
        if (!enabled) {
          showHostMessage(
            root,
            "Versioning is not enabled for this writable copy, so repository health is unavailable.",
          );
          return;
        }
        if (
          enabledFor(repositoryTools) &&
          !(repositoryTools as { client?: object }).client
        )
          Object.assign(repositoryTools, {
            client: repositoryOverviewClient,
            volume,
            path,
            view,
          });
      },
      (error) =>
        showHostMessage(
          root,
          error instanceof Error
            ? error.message
            : "Unable to determine versioning status.",
        ),
    );
  };
  const activateWorkspace = (name: string) => {
    const selected = safeWorkspace(name);
    for (const element of [
      versionStatus,
      versionHistory,
      branchManager,
      repositoryTools,
    ]) {
      if (!element) continue;
      if (
        element.closest<HTMLElement>("[data-panel]")?.dataset.panel !==
          selected &&
        (element as { client?: object }).client
      )
        Object.assign(element, { client: undefined });
    }
    root
      .querySelectorAll<HTMLElement>(
        `.panel[data-panel="${selected}"] slatefs-file-explorer,
         .panel[data-panel="${selected}"] slatefs-file-preview,
         .panel[data-panel="${selected}"] slatefs-file-properties,
         .panel[data-panel="${selected}"] slatefs-snapshot-manager,
         .panel[data-panel="${selected}"] slatefs-version-status,
         .panel[data-panel="${selected}"] slatefs-version-history,
         .panel[data-panel="${selected}"] slatefs-diff-viewer,
         .panel[data-panel="${selected}"] slatefs-branch-manager,
         .panel[data-panel="${selected}"] slatefs-restore-dialog,
         .panel[data-panel="${selected}"] slatefs-repository-tools`,
      )
      .forEach((element) => {
        if (
          element.localName === "slatefs-version-status" ||
          element.localName === "slatefs-version-history" ||
          element.localName === "slatefs-branch-manager" ||
          element.localName === "slatefs-repository-tools"
        )
          return;
        if (enabledFor(element) && !(element as { client?: object }).client)
          Object.assign(element, { client, volume, path, view });
      });
    if (selected === "versions") warmVersionWorkspace();
    if (selected === "branches") warmBranchWorkspace();
    if (selected === "health") warmHealthWorkspace();
    activate(selected);
  };
  const pendingOperations = new WeakMap<EventTarget, Map<string, string>>();
  const operationDetail = (event: Event) =>
    (
      event as CustomEvent<{
        operation: string;
        entryIds?: readonly string[];
        message?: string;
      }>
    ).detail;
  const rememberOperation = (
    target: EventTarget,
    operation: string,
    id: string,
  ) => {
    const pending = pendingOperations.get(target) ?? new Map<string, string>();
    pending.set(operation, id);
    pendingOperations.set(target, pending);
  };
  const finishOperation = (event: Event, status: "success" | "error") => {
    if (event.target === explorer) return;
    const detail = operationDetail(event);
    // Load errors render in their owning component. They are not user file
    // operations and should not pollute the operations drawer.
    if (!detail?.operation || detail.operation === "load") return;
    const pending = pendingOperations.get(event.target!)?.get(detail.operation);
    if (pending) {
      operations.update(pending, {
        status,
        progress: status === "success" ? 1 : 0,
        ...(detail.message ? { detail: detail.message } : {}),
      });
      pendingOperations.get(event.target!)?.delete(detail.operation);
      return;
    }
    operations.add({
      label: detail.operation,
      status,
      progress: status === "success" ? 1 : 0,
      ...(detail.message ? { detail: detail.message } : {}),
    });
  };
  explorer.operationController = operations;
  explorer.selection = [...selection];
  operationDrawer = new OperationDrawer(operations);
  root.append(operationDrawer.element);
  const sync = () => {
    for (const el of all) Object.assign(el, { volume, path });
    if (status)
      status.versioningEnabled = seededVersioningEnabled(volume)
        ? true
        : undefined;
    applyViewMode(
      all as NodeListOf<
        HTMLElement & { view: ViewSelection; readonly: boolean }
      >,
      view,
    );
    explorer.selection = [...selection];
    preview.entry = undefined;
    metadata.entry = undefined;
  };
  root.addEventListener("slatefs-volume-change", (e) => {
    const nextVolume = (e as CustomEvent<{ volume: string }>).detail.volume;
    if (
      (e.target as Element | null)?.localName === "slatefs-snapshot-manager"
    ) {
      const sourceVolume = volume;
      showHostMessage(
        root,
        `Writable copy ${nextVolume} was created. Waiting for it to become available…`,
      );
      void (async () => {
        if (!(await waitForVolume(nextVolume))) {
          showHostMessage(
            root,
            `Writable copy ${nextVolume} was created, but it is still initializing. Use Refresh volumes to check again.`,
          );
          return;
        }
        if (volume !== sourceVolume) return;
        volume = nextVolume;
        path = "/";
        selection = [];
        sync();
        await volumePicker?.refresh();
        showHostMessage(
          root,
          `Writable copy ${nextVolume} is ready and selected.`,
        );
        updateUrl();
      })();
      return;
    }
    volume = nextVolume;
    path = "/";
    selection = [];
    sync();
    updateUrl();
  });
  root.addEventListener("slatefs-path-change", (e) => {
    path = (e as CustomEvent<{ path: string }>).detail.path;
    selection = [];
    sync();
    // Diff paths are navigation requests too, so make their destination visible.
    activateWorkspace("files");
    updateUrl();
  });
  explorer.addEventListener("slatefs-selection-change", (e) => {
    const selected = (e as CustomEvent<{ selection: Entry[] }>).detail
      .selection[0];
    selection = (e as CustomEvent<{ selection: Entry[] }>).detail.selection.map(
      (entry) => entry.entry_id,
    );
    preview.entry = selected;
    metadata.entry = selected;
    updateUrl(true);
  });
  const acceptChangedEntry = (entry: Entry, updatePreview: boolean) => {
    invalidateVersionOverview(volume);
    selection = [entry.entry_id];
    explorer.selection = [...selection];
    if (updatePreview) preview.entry = entry;
    metadata.entry = entry;
    refreshAfterMutation(explorer, versionStatus);
    updateUrl(true);
  };
  root.addEventListener("slatefs-save-complete", (event) => {
    acceptChangedEntry(
      (event as CustomEvent<{ entry: Entry }>).detail.entry,
      false,
    );
  });
  root.addEventListener("slatefs-before-operation", (event) => {
    if (event.target === explorer) return;
    const detail = operationDetail(event);
    if (!detail?.operation) return;
    const id = operations.add({
      label: detail.operation,
      status: "running",
      progress: 0,
    });
    rememberOperation(event.target!, detail.operation, id);
  });
  root.addEventListener("slatefs-properties-change", (event) => {
    acceptChangedEntry(
      (event as CustomEvent<{ entry: Entry }>).detail.entry,
      true,
    );
  });
  root.addEventListener("slatefs-operation-complete", (event) => {
    finishOperation(event, "success");
    const operation = (event as CustomEvent<{ operation: string }>).detail
      .operation;
    if (event.target === explorer) {
      invalidateVersionOverview(volume);
      refreshAfterMutation(versionStatus);
    }
    if (operation === "merge" || operation === "cherry-pick") {
      invalidateVersionOverview(volume);
      invalidateBranchOverview(volume);
      refreshAfterMutation(versionStatus, versionHistory);
    }
    if (operation === "enable-versioning") {
      versionPolicyCache.set(volume, Promise.resolve(true));
      if (status) status.versioningEnabled = true;
      invalidateVersionOverview(volume);
      if (activeWorkspaceIs("versions")) warmVersionWorkspace();
    }
    if (event.target === branchManager) {
      invalidateVersionOverview(volume);
      invalidateBranchOverview(volume);
    }
  });
  root.addEventListener("slatefs-operation-error", (event) => {
    finishOperation(event, "error");
  });
  root.addEventListener("slatefs-version-commit", () => {
    invalidateVersionOverview(volume);
    invalidateBranchOverview(volume);
    refreshAfterMutation(versionHistory, branchManager);
  });
  root.addEventListener("slatefs-restore-complete", () => {
    invalidateVersionOverview(volume);
    refreshAfterMutation(explorer, versionStatus);
  });
  preview.addEventListener("slatefs-download-request", (event) => {
    const detail = (event as CustomEvent<{ entry: Entry; view: ViewSelection }>)
      .detail;
    const query = new URLSearchParams({
      entry_id: detail.entry.entry_id,
      view: detail.view.kind,
    });
    const reference =
      detail.view.resolvedCommit ??
      detail.view.resolved_commit ??
      detail.view.ref;
    if (reference) query.set("ref", reference);
    const anchor = document.createElement("a");
    anchor.href = `/api/consumer/v1/volumes/${encodeURIComponent(volume)}/content?${query}`;
    anchor.download = detail.entry.name ?? "download";
    anchor.click();
  });
  const browse = (requested: ViewSelection) => {
    view = exactBrowseView(requested);
    path = "/";
    selection = [];
    sync();
    // Browse actions open the selected immutable tree in the file explorer.
    // Returning to live follows the same predictable destination.
    activateWorkspace("files");
    updateUrl();
  };
  root.addEventListener("slatefs-view-change", (e) => {
    browse((e as CustomEvent<{ view: ViewSelection }>).detail.view);
  });
  root.addEventListener("slatefs-publish-target-change", (e) => {
    const branch = (e as CustomEvent<{ branch: string }>).detail.branch;
    const target = root.querySelector<
      HTMLElement & { targetBranch: string; reference: string }
    >("slatefs-version-status");
    if (target) selectPublishTarget(target, branch);
    const history = root.querySelector<HTMLElement & { reference: string }>(
      "slatefs-version-history",
    );
    if (history) history.reference = branch;
  });
  root.addEventListener("slatefs-reflog-request", (e) => {
    const reference = (e as CustomEvent<{ reference: string }>).detail
      .reference;
    activateWorkspace("branches");
    const target = root.querySelector<HTMLElement & RecoveryLogTarget>(
      "slatefs-branch-manager",
    );
    if (target) void revealRecoveryLog(target, reference);
    updateUrl();
  });
  root.addEventListener("slatefs-recursive-delete-request", (event) => {
    event.preventDefault();
    showHostMessage(
      root,
      "Folder deletion is unavailable because this server does not expose a bounded recursive-delete preview. No files were changed.",
    );
  });
  root.addEventListener("slatefs-commit-select", (event) => {
    const commit = (event as CustomEvent<{ commit: string }>).detail.commit;
    const restore = root.querySelector<
      HTMLElement & {
        commit: string;
        paths: readonly string[];
        show(): void;
      }
    >("slatefs-restore-dialog");
    if (!restore) return;
    restore.commit = commit;
    restore.paths = [path];
    restore.show();
    const tools = root.querySelector<HTMLElement & { commit: string }>(
      "slatefs-repository-tools",
    );
    if (tools) tools.commit = commit;
  });
  root.addEventListener("slatefs-compare-request", (e) => {
    const d = (e as CustomEvent<{ from: string; to: string }>).detail;
    const diff = root.querySelector<SlateFsDiffViewer>("slatefs-diff-viewer")!;
    activateWorkspace("versions");
    void compareInDiff(diff, d);
  });
  root.querySelector("#logout")!.addEventListener("click", () => void logout());
  root.querySelector("#switch")!.addEventListener("click", () => void logout());
  root.querySelector("#return-live")!.addEventListener("click", () => {
    browse({ kind: "live" });
  });
  root.querySelectorAll<HTMLButtonElement>(".tab").forEach((b) =>
    b.addEventListener("click", () => {
      activateWorkspace(b.dataset.tab!);
      updateUrl();
    }),
  );
  root.querySelector(".rail")?.addEventListener("keydown", (event) => {
    const keyboard = event as KeyboardEvent;
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(keyboard.key))
      return;
    const tabs = [...root.querySelectorAll<HTMLButtonElement>(".tab")];
    const current = tabs.indexOf(document.activeElement as HTMLButtonElement);
    if (current < 0) return;
    keyboard.preventDefault();
    const next =
      keyboard.key === "Home"
        ? 0
        : keyboard.key === "End"
          ? tabs.length - 1
          : (current + (keyboard.key === "ArrowRight" ? 1 : -1) + tabs.length) %
            tabs.length;
    const tab = tabs[next]!;
    activateWorkspace(tab.dataset.tab!);
    tab.focus();
    updateUrl();
  });
  root.querySelectorAll<HTMLButtonElement>("[data-inspect]").forEach((b) =>
    b.addEventListener("click", () => {
      root
        .querySelectorAll("[data-inspect]")
        .forEach((x) => x.setAttribute("aria-selected", String(x === b)));
      root
        .querySelectorAll<HTMLButtonElement>("[data-inspect]")
        .forEach((x) => (x.tabIndex = x === b ? 0 : -1));
      preview.hidden = b.dataset.inspect !== "preview";
      metadata.hidden = b.dataset.inspect !== "details";
    }),
  );
  activateWorkspace(initialWorkspace);
}
function activate(name: string) {
  if (!["files", "versions", "snapshots", "branches", "health"].includes(name))
    name = "files";
  root
    .querySelectorAll<HTMLElement>(".panel")
    .forEach((p) => p.classList.toggle("active", p.dataset.panel === name));
  root.querySelectorAll<HTMLButtonElement>(".tab").forEach((b) => {
    const selected = b.dataset.tab === name;
    b.setAttribute("aria-selected", String(selected));
    b.tabIndex = selected ? 0 : -1;
  });
  const selected = safeWorkspace(name);
  const heading = workspaceHeading(selected, view);
  const eyebrow = root.querySelector<HTMLElement>(".workspace-head .eyebrow");
  const title = root.querySelector<HTMLElement>(".workspace-head h1");
  const returnLive = root.querySelector<HTMLButtonElement>("#return-live");
  if (eyebrow) eyebrow.textContent = heading.eyebrow;
  if (title) title.textContent = heading.title;
  if (returnLive) returnLive.hidden = view.kind === "live";
}
function render() {
  operationDrawer?.disconnect();
  operationDrawer = undefined;
  if (session.authenticated) shell();
  else loginScreen();
}
window.addEventListener("popstate", () => {
  volume = "";
  path = "/";
  view = { kind: "live" };
  selection = [];
  render();
});
void raw<Session>("/api/v1/session")
  .then((s) => {
    session = s;
    render();
  })
  .catch(() => {
    root.innerHTML = `<main class="fatal"><h1>Demo server unavailable</h1><p>Start the same-origin demo server, then retry.</p><button>Retry</button></main>`;
    root
      .querySelector("button")
      ?.addEventListener("click", () => location.reload());
  });
