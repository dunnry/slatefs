import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { resolve } from "node:path";

export interface DemoServerConfig {
  host: string;
  port: number;
  secureCookie: boolean;
  allowUnsafeDemoBind: boolean;
  consumerBaseUrl: string;
  adminBaseUrl: string;
  tenantTokens: Readonly<Record<"acme" | "globex", string>>;
  sessionTtlMs: number;
  bodyLimit: number;
  allowedOrigins?: readonly string[];
  staticDir?: string;
  logger?: boolean;
}
const token = (tenant: "ACME" | "GLOBEX"): string => {
  const inline = process.env[`SLATEFS_${tenant}_TOKEN`];
  const file = process.env[`SLATEFS_${tenant}_TOKEN_FILE`];
  if (inline && file)
    throw new Error(`Configure only one token source for ${tenant}`);
  if (file) {
    const value = readFileSync(file, "utf8").trim();
    if (!value) throw new Error(`Token file for ${tenant} is empty`);
    return value;
  }
  return inline?.trim() ?? "";
};
function integer(
  name: string,
  fallback: number,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error(
      `${name} must be a safe integer between ${minimum} and ${maximum}`,
    );
  return value;
}
function upstreamUrl(name: string, fallback: string): string {
  const raw = process.env[name] ?? fallback;
  let value: URL;
  try {
    value = new URL(raw);
  } catch {
    throw new Error(`${name} must be a valid absolute HTTP URL`);
  }
  if (
    (value.protocol !== "http:" && value.protocol !== "https:") ||
    value.username ||
    value.password ||
    value.search ||
    value.hash ||
    (value.pathname !== "/" && value.pathname !== "")
  )
    throw new Error(
      `${name} must be an origin-only HTTP URL without credentials, path, query, or fragment`,
    );
  return value.origin;
}
function allowedOrigins(): readonly string[] | undefined {
  const values = process.env.SLATEFS_DEMO_ALLOWED_ORIGINS?.split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (!values?.length) return undefined;
  return values.map((value) => {
    let origin: URL;
    try {
      origin = new URL(value);
    } catch {
      throw new Error(
        "SLATEFS_DEMO_ALLOWED_ORIGINS must contain valid HTTP origins",
      );
    }
    if (
      (origin.protocol !== "http:" && origin.protocol !== "https:") ||
      origin.origin !== value ||
      origin.username ||
      origin.password
    )
      throw new Error(
        "SLATEFS_DEMO_ALLOWED_ORIGINS must contain origin-only HTTP URLs",
      );
    return origin.origin;
  });
}
export function loadConfig(): DemoServerConfig {
  const host = process.env.SLATEFS_DEMO_HOST ?? "127.0.0.1";
  const allowUnsafeDemoBind =
    process.env.SLATEFS_DEMO_ALLOW_UNSAFE_BIND === "true";
  if (
    !allowUnsafeDemoBind &&
    host !== "localhost" &&
    host !== "::1" &&
    !(isIP(host) === 4 && host.startsWith("127."))
  )
    throw new Error(
      "Demo credentials require loopback binding; set SLATEFS_DEMO_ALLOW_UNSAFE_BIND=true only for an isolated development network",
    );
  const tenantTokens = { acme: token("ACME"), globex: token("GLOBEX") };
  if (!tenantTokens.acme || !tenantTokens.globex)
    throw new Error(
      "Both SLATEFS_ACME_TOKEN(_FILE) and SLATEFS_GLOBEX_TOKEN(_FILE) are required",
    );
  return {
    host,
    port: integer("SLATEFS_DEMO_PORT", 4174, 1, 65_535),
    secureCookie:
      process.env.SLATEFS_DEMO_SECURE_COOKIE === "true" ||
      process.env.NODE_ENV === "production",
    allowUnsafeDemoBind,
    consumerBaseUrl: upstreamUrl(
      "SLATEFS_CONSUMER_BASE_URL",
      "http://127.0.0.1:9410",
    ),
    adminBaseUrl: upstreamUrl(
      "SLATEFS_ADMIN_BASE_URL",
      "http://127.0.0.1:9400",
    ),
    tenantTokens,
    sessionTtlMs: integer("SLATEFS_DEMO_SESSION_TTL_MS", 1_800_000, 1_000),
    bodyLimit: integer("SLATEFS_DEMO_BODY_LIMIT", 1_048_576, 1),
    allowedOrigins: allowedOrigins(),
    staticDir:
      process.env.SLATEFS_DEMO_STATIC_DIR ??
      resolve(process.cwd(), "../demo/dist"),
    logger: true,
  };
}
