import { randomBytes } from "node:crypto";

export type Tenant = "acme" | "globex";
export interface Account {
  username: "alice" | "bob";
  displayName: string;
  tenant: Tenant;
}
export interface Session {
  id: string;
  csrfToken: string;
  account?: Account;
  expiresAt: number;
  createdAt: number;
}
const opaque = () => randomBytes(32).toString("base64url");
export class SessionStore {
  readonly #sessions = new Map<string, Session>();
  constructor(private readonly ttlMs: number) {}
  create(account?: Account): Session {
    this.sweep();
    const now = Date.now();
    const value = {
      id: opaque(),
      csrfToken: opaque(),
      account,
      createdAt: now,
      expiresAt: now + this.ttlMs,
    };
    this.#sessions.set(value.id, value);
    return value;
  }
  get(id: string | undefined): Session | undefined {
    if (!id) return undefined;
    const value = this.#sessions.get(id);
    if (value && value.expiresAt <= Date.now()) {
      this.#sessions.delete(id);
      return undefined;
    }
    return value;
  }
  rotate(id: string | undefined, account?: Account): Session {
    if (id) this.#sessions.delete(id);
    return this.create(account);
  }
  delete(id: string | undefined): void {
    if (id) this.#sessions.delete(id);
  }
  sweep(): void {
    for (const [id, value] of this.#sessions)
      if (value.expiresAt <= Date.now()) this.#sessions.delete(id);
  }
}
