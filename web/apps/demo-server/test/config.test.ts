import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";

function validEnvironment(): void {
  vi.stubEnv("SLATEFS_ACME_TOKEN", "acme-token");
  vi.stubEnv("SLATEFS_GLOBEX_TOKEN", "globex-token");
  vi.stubEnv("SLATEFS_DEMO_HOST", "127.0.0.1");
}

afterEach(() => vi.unstubAllEnvs());

describe("demo server startup configuration", () => {
  it("rejects empty tenant credentials", () => {
    validEnvironment();
    vi.stubEnv("SLATEFS_ACME_TOKEN", "   ");
    expect(() => loadConfig()).toThrow("required");
  });

  it.each([
    ["SLATEFS_DEMO_PORT", "NaN"],
    ["SLATEFS_DEMO_PORT", "65536"],
    ["SLATEFS_DEMO_SESSION_TTL_MS", "0"],
    ["SLATEFS_DEMO_BODY_LIMIT", "1.5"],
  ])("rejects invalid numeric configuration %s=%s", (name, value) => {
    validEnvironment();
    vi.stubEnv(name, value);
    expect(() => loadConfig()).toThrow("safe integer");
  });

  it.each([
    "not-a-url",
    "file:///tmp/slatefs.sock",
    "http://user:password@127.0.0.1:9400",
    "http://127.0.0.1:9400/admin",
  ])("rejects unsafe upstream URL %s", (value) => {
    validEnvironment();
    vi.stubEnv("SLATEFS_ADMIN_BASE_URL", value);
    expect(() => loadConfig()).toThrow("URL");
  });
});
