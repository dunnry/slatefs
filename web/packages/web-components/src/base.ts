import type { ViewSelection } from "@slatefs/client";
import {
  LitElement,
  css,
  html,
  nothing,
  type CSSResultGroup,
  type PropertyValues,
} from "lit";
import { createSlateFsEvent } from "./events.js";

export type ComponentDensity = "comfortable" | "compact";
export type LoadState =
  | "idle"
  | "loading"
  | "ready"
  | "empty"
  | "error"
  | "unsupported"
  | "denied";

type DialogField = {
  name: string;
  label: string;
  value?: string;
  required?: boolean;
  placeholder?: string;
  pattern?: string;
  type?: "text" | "number";
};

type DialogRequest = {
  title: string;
  description: string;
  submitLabel: string;
  destructive?: boolean;
  fields?: readonly DialogField[];
};

type OpenDialog = DialogRequest & {
  resolve: (value: Record<string, string> | undefined) => void;
};

/** Shared lifecycle, state, and theme contract for SlateFS components. */
export abstract class SlateFsElement<Client extends object> extends LitElement {
  static override properties = {
    client: { attribute: false },
    volume: { type: String },
    path: { type: String },
    view: { attribute: false },
    selection: { attribute: false },
    readonly: { type: Boolean, reflect: true },
    density: { type: String, reflect: true },
    hidden: { type: Boolean, reflect: true },
  };
  static override styles: CSSResultGroup = css`
    :host {
      display: block;
      color: var(--slatefs-color-text, #17212b);
      background: var(--slatefs-color-surface, #fff);
      font: var(--slatefs-font-size, 0.9rem) / 1.45
        var(--slatefs-font-family, Inter, ui-sans-serif, system-ui, sans-serif);
      border-radius: var(--slatefs-radius, 12px);
      --_accent: var(--slatefs-color-accent, #286e61);
      --_border: var(--slatefs-color-border, #d7e0dd);
      --_muted: var(--slatefs-color-muted, #62706d);
      --_control-bg: var(--slatefs-color-control, #fff);
      --_control-text: var(--slatefs-color-text, #17212b);
      --_subtle-bg: var(--slatefs-color-subtle, #f4f7f6);
      --_selected-bg: var(--slatefs-color-selected, #dff1ed);
      --_accent-contrast: var(--slatefs-color-accent-contrast, #fff);
      --_danger: var(--slatefs-color-danger, #9b2c2c);
      --_danger-bg: var(--slatefs-color-danger-bg, #fff2f1);
      --_danger-text: var(--slatefs-color-danger-text, #8b2929);
      --_banner-border: var(--slatefs-color-readonly-border, #ead59d);
    }
    * {
      box-sizing: border-box;
    }
    section {
      border: var(--slatefs-frame, 1px solid var(--_border));
      border-radius: inherit;
      background: inherit;
      min-height: 100%;
    }
    header.toolbar {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      min-height: 3rem;
      padding: 0.55rem 0.75rem;
      border-bottom: 1px solid var(--_border);
      flex-wrap: wrap;
    }
    h2 {
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      margin: 0 auto 0 0;
    }
    button,
    input,
    select,
    textarea {
      font: inherit;
    }
    button,
    .button {
      border: 1px solid var(--_border);
      background: var(--_control-bg);
      color: var(--_control-text);
      border-radius: 9px;
      min-height: 2.25rem;
      padding: 0.4rem 0.75rem;
      cursor: pointer;
      box-shadow: 0 1px 0 rgb(255 255 255 / 0.04) inset;
      transition:
        border-color 0.16s ease,
        background 0.16s ease,
        box-shadow 0.16s ease,
        transform 0.12s ease;
    }
    button:hover {
      border-color: var(--_accent);
      background: color-mix(
        in srgb,
        var(--_control-bg) 82%,
        var(--_accent) 18%
      );
    }
    button:active {
      transform: scale(0.97);
    }
    button:disabled {
      cursor: not-allowed;
      opacity: 0.48;
    }
    button.primary {
      background: linear-gradient(
        135deg,
        var(--_accent),
        color-mix(in srgb, var(--_accent) 72%, #5fe8c0 28%)
      );
      border-color: transparent;
      color: var(--_accent-contrast);
      font-weight: 680;
      box-shadow:
        0 0 0 1px color-mix(in srgb, var(--_accent) 40%, transparent),
        0 6px 18px -8px var(--_accent);
    }
    button.primary:hover {
      box-shadow:
        0 0 0 1px color-mix(in srgb, var(--_accent) 55%, transparent),
        0 8px 22px -6px var(--_accent);
    }
    input,
    select,
    textarea {
      border: 1px solid var(--_border);
      border-radius: 9px;
      padding: 0.45rem 0.6rem;
      min-height: 2.25rem;
      background: var(--_control-bg);
      color: var(--_control-text);
      box-shadow: 0 1px 0 rgb(255 255 255 / 0.03) inset;
      transition:
        border-color 0.16s ease,
        box-shadow 0.16s ease;
    }
    input:hover,
    select:hover,
    textarea:hover {
      border-color: color-mix(in srgb, var(--_border) 55%, var(--_accent) 45%);
    }
    input:focus,
    select:focus,
    textarea:focus {
      border-color: var(--_accent);
      box-shadow: 0 0 0 3px color-mix(in srgb, var(--_accent) 18%, transparent);
    }
    textarea {
      width: 100%;
      min-height: 8rem;
    }
    :focus-visible {
      outline: var(--slatefs-focus-ring, 3px solid #65b6a8);
      outline-offset: 2px;
    }
    .muted {
      color: var(--_muted);
    }
    .banner {
      margin: 0;
      padding: 0.55rem 0.75rem;
      background: var(--slatefs-color-readonly, #fff4d7);
      border-bottom: 1px solid var(--_banner-border);
    }
    .state {
      padding: 1.5rem;
      text-align: center;
      color: var(--_muted);
    }
    .error {
      color: var(--_danger-text);
      background: var(--_danger-bg);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      background: var(--_subtle-bg);
      border: 1px solid color-mix(in srgb, var(--_border) 80%, transparent);
      padding: 0.16rem 0.55rem;
      font-size: 0.76rem;
      font-weight: 620;
      letter-spacing: 0.01em;
    }
    .quota-meter {
      flex: 0 0 auto;
      inline-size: 5.5rem;
      block-size: 0.4rem;
      border-radius: 99px;
      background: color-mix(in srgb, var(--_subtle-bg) 80%, black 20%);
      overflow: hidden;
      box-shadow: 0 0 0 1px color-mix(in srgb, var(--_border) 70%, transparent);
    }
    .quota-meter > i {
      display: block;
      block-size: 100%;
      border-radius: 99px;
      background: linear-gradient(
        90deg,
        color-mix(in srgb, var(--_accent) 70%, #5fe8c0 30%),
        var(--_accent)
      );
      transition: inline-size 0.5s cubic-bezier(0.22, 1, 0.36, 1);
    }
    .body {
      padding: 0.75rem;
    }
    .list {
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .row {
      border-bottom: 1px solid var(--_border);
      padding: 0.6rem 0.7rem;
      min-width: 0;
    }
    .row:last-child {
      border-bottom: 0;
    }
    .split {
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }
    .grow {
      flex: 1;
      min-width: 0;
      overflow-wrap: anywhere;
    }
    [part="parents"] {
      overflow-wrap: anywhere;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
    [hidden] {
      display: none !important;
    }
    .dialog-backdrop {
      position: fixed;
      inset: 0;
      z-index: 1000;
      display: grid;
      place-items: center;
      padding: 1rem;
      background: rgb(16 28 26 / 0.48);
    }
    .action-dialog {
      width: min(30rem, 100%);
      max-height: min(42rem, calc(100vh - 2rem));
      overflow: auto;
      border: 1px solid var(--_border);
      border-radius: var(--slatefs-radius, 12px);
      background: var(
        --slatefs-color-dialog,
        var(--slatefs-color-surface, #fff)
      );
      box-shadow: 0 1rem 3rem rgb(16 28 26 / 0.24);
    }
    .action-dialog h2 {
      font-size: 1.1rem;
      margin: 0;
    }
    .dialog-fields {
      display: grid;
      gap: 0.8rem;
      padding: 1rem;
    }
    .dialog-fields label {
      display: grid;
      gap: 0.3rem;
      font-weight: 600;
    }
    .dialog-actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.5rem;
      padding: 0 1rem 1rem;
    }
    button.destructive {
      color: #fff;
      border-color: var(--_danger);
      background: var(--_danger);
    }
    :host([density="compact"]) .row {
      padding: 0.35rem 0.55rem;
    }
    @media (prefers-reduced-motion: reduce) {
      * {
        scroll-behavior: auto !important;
        transition: none !important;
      }
    }
  `;
  abstract readonly componentLabel: string;
  client?: Client;
  volume = "";
  path = "/";
  view: ViewSelection = { kind: "live" };
  selection: readonly string[] = [];
  readonly = false;
  density: ComponentDensity = "comfortable";
  override hidden = false;
  protected loadState: LoadState = "idle";
  protected errorMessage = "";
  private loadController?: AbortController;
  private loadSerial = 0;
  private actionDialog?: OpenDialog;
  private dialogReturnFocus?: HTMLElement;
  protected get readOnlyView() {
    return this.readonly || this.view.kind !== "live";
  }
  protected beginLoad() {
    this.loadController?.abort();
    this.loadController = new AbortController();
    this.loadSerial++;
    this.loadState = "loading";
    this.errorMessage = "";
    this.requestUpdate();
    return { signal: this.loadController.signal, serial: this.loadSerial };
  }
  protected resetLoad(state: LoadState, requestUpdate = true) {
    this.loadController?.abort();
    this.loadController = undefined;
    this.loadSerial++;
    this.loadState = state;
    this.errorMessage = "";
    if (requestUpdate) this.requestUpdate();
  }
  protected loadCurrent(serial: number) {
    return serial === this.loadSerial && this.isConnected;
  }
  protected finishLoad(serial: number, state: LoadState = "ready") {
    if (this.loadCurrent(serial)) {
      this.loadState = state;
      this.requestUpdate();
    }
  }
  protected failLoad(serial: number, error: unknown) {
    const abortLike = error as { name?: unknown } | null;
    if (
      !this.loadCurrent(serial) ||
      (typeof abortLike === "object" && abortLike?.name === "AbortError")
    )
      return;
    const value = error as {
      status?: number;
      code?: string;
      message?: string;
      requestId?: string;
    };
    this.loadState = value.status === 403 ? "denied" : "error";
    this.errorMessage = value.message ?? "Something went wrong";
    this.dispatchEvent(
      createSlateFsEvent(
        value.status === 401
          ? "slatefs-auth-required"
          : "slatefs-operation-error",
        {
          version: 1,
          operation: "load",
          entryIds: [],
          code: value.code ?? "error",
          message: this.errorMessage,
          requestId: value.requestId,
        },
      ),
    );
    this.requestUpdate();
  }
  protected stateTemplate(retry?: () => void) {
    if (this.loadState === "loading")
      return html`<div class="state" part="loading" role="status">
        Loading…
      </div>`;
    if (this.loadState === "empty")
      return html`<div class="state" part="empty">
        <slot name="empty">Nothing here yet.</slot>
      </div>`;
    if (this.loadState === "denied")
      return html`<div class="state error" part="error" role="alert">
        Permission denied. Ask the volume owner for access.
      </div>`;
    if (this.loadState === "unsupported")
      return html`<div class="state" part="unsupported">
        This capability is not available on the connected server.
      </div>`;
    if (this.loadState === "error")
      return html`<div class="state error" part="error" role="alert">
        ${this.errorMessage}<br />${retry
          ? html`<button @click=${retry}>Retry</button>`
          : nothing}
      </div>`;
    return nothing;
  }
  protected emit<T>(name: string, detail: T, cancelable = false) {
    return this.dispatchEvent(createSlateFsEvent(name, detail, cancelable));
  }
  protected ask(request: DialogRequest) {
    this.cancelDialog();
    const active =
      this.renderRoot instanceof ShadowRoot
        ? this.renderRoot.activeElement
        : document.activeElement;
    this.dialogReturnFocus = active instanceof HTMLElement ? active : undefined;
    return new Promise<Record<string, string> | undefined>((resolve) => {
      this.actionDialog = { ...request, resolve };
      this.requestUpdate();
      void this.updateComplete.then(() =>
        this.renderRoot
          .querySelector<HTMLElement>("[data-dialog-initial]")
          ?.focus(),
      );
    });
  }
  protected confirmAction(
    title: string,
    description: string,
    submitLabel: string,
    destructive = false,
  ) {
    return this.ask({ title, description, submitLabel, destructive }).then(
      Boolean,
    );
  }
  protected cancelDialog(restoreFocus = true) {
    const dialog = this.actionDialog;
    if (!dialog) return;
    this.actionDialog = undefined;
    dialog.resolve(undefined);
    this.requestUpdate();
    if (restoreFocus) this.dialogReturnFocus?.focus();
    this.dialogReturnFocus = undefined;
  }
  private submitDialog(event: SubmitEvent) {
    event.preventDefault();
    const dialog = this.actionDialog;
    if (!dialog) return;
    const data = new FormData(event.currentTarget as HTMLFormElement);
    const result = Object.fromEntries(
      (dialog.fields ?? []).map((field) => [
        field.name,
        String(data.get(field.name) ?? ""),
      ]),
    );
    this.actionDialog = undefined;
    dialog.resolve(result);
    this.requestUpdate();
    this.dialogReturnFocus?.focus();
    this.dialogReturnFocus = undefined;
  }
  private actionDialogKey(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      this.cancelDialog();
      return;
    }
    if (event.key !== "Tab") return;
    event.stopPropagation();
    const controls = [
      ...this.renderRoot.querySelectorAll<HTMLElement>(
        ".action-dialog button:not([disabled]), .action-dialog input:not([disabled]), .action-dialog select:not([disabled]), .action-dialog textarea:not([disabled])",
      ),
    ];
    if (!controls.length) return;
    const current = controls.indexOf(
      (this.renderRoot as ShadowRoot).activeElement as HTMLElement,
    );
    const next = event.shiftKey
      ? current <= 0
        ? controls.length - 1
        : current - 1
      : current < 0 || current === controls.length - 1
        ? 0
        : current + 1;
    event.preventDefault();
    controls[next]?.focus();
  }
  protected actionDialogTemplate() {
    const dialog = this.actionDialog;
    if (!dialog) return nothing;
    const titleId = `${this.localName}-action-title`;
    const descriptionId = `${this.localName}-action-description`;
    return html`<div class="dialog-backdrop">
      <form
        class="action-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby=${titleId}
        aria-describedby=${descriptionId}
        @submit=${this.submitDialog}
        @keydown=${this.actionDialogKey}
      >
        <header class="toolbar">
          <h2 id=${titleId}>${dialog.title}</h2>
        </header>
        <div class="dialog-fields">
          <p id=${descriptionId}>${dialog.description}</p>
          ${(dialog.fields ?? []).map(
            (field, index) =>
              html`<label
                >${field.label}<input
                  data-dialog-initial=${index === 0 ? "" : nothing}
                  name=${field.name}
                  type=${field.type ?? "text"}
                  .value=${field.value ?? ""}
                  placeholder=${field.placeholder ?? nothing}
                  pattern=${field.pattern ?? nothing}
                  ?required=${field.required}
              /></label>`,
          )}
        </div>
        <div class="dialog-actions">
          <button
            data-dialog-initial=${dialog.fields?.length ? nothing : ""}
            type="button"
            @click=${() => this.cancelDialog()}
          >
            Cancel
          </button>
          <button
            class=${dialog.destructive ? "destructive" : "primary"}
            type="submit"
          >
            ${dialog.submitLabel}
          </button>
        </div>
      </form>
    </div>`;
  }
  protected override update(changes: PropertyValues) {
    if (
      this.actionDialog &&
      (changes.has("client") ||
        changes.has("volume") ||
        changes.has("view") ||
        changes.has("path") ||
        changes.has("selection") ||
        (changes.has("hidden") && this.hidden))
    )
      this.cancelDialog(false);
    super.update(changes);
  }
  protected reportActionError(
    operation: string,
    error: unknown,
    entryIds: readonly string[] = [],
  ) {
    const value = error as {
      code?: string;
      message?: string;
      requestId?: string;
    };
    this.emit("slatefs-operation-error", {
      version: 1 as const,
      operation,
      entryIds: [...entryIds],
      code: value.code ?? "error",
      message: value.message ?? "Operation failed",
      requestId: value.requestId,
    });
  }
  override disconnectedCallback() {
    this.cancelDialog(false);
    this.loadController?.abort();
    this.loadSerial++;
    super.disconnectedCallback();
  }
}
