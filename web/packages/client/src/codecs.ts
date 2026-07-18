import type { Entry, ViewSelection } from "./types.js";

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function displayEntryName(
  entry: Pick<Entry, "name" | "name_bytes_base64">,
): string {
  if (entry.name !== null) return entry.name;
  return `[bytes:${entry.name_bytes_base64}]`;
}

export function decodeU64(value: number | string, field = "value"): bigint {
  if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0))
    throw new RangeError(`${field} is not a lossless u64`);
  if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value))
    throw new RangeError(`${field} is not a u64 decimal string`);
  const decoded = BigInt(value);
  if (decoded > 18_446_744_073_709_551_615n)
    throw new RangeError(`${field} exceeds u64`);
  return decoded;
}

export function encodeU64(value: bigint): string {
  if (value < 0n || value > 18_446_744_073_709_551_615n)
    throw new RangeError("value is outside u64");
  return value.toString(10);
}

export const liveView = (): ViewSelection => ({ kind: "live" });
export const snapshotView = (ref: string): ViewSelection => ({
  kind: "snapshot",
  ref,
});
export const versionView = (
  ref: string,
  resolvedCommit?: string,
): ViewSelection => ({
  kind: "version",
  ref,
  ...(resolvedCommit === undefined
    ? {}
    : { resolved_commit: resolvedCommit, resolvedCommit }),
});
export function pinResolvedView(view: ViewSelection): ViewSelection {
  const resolved = view.resolvedCommit ?? view.resolved_commit;
  return view.kind === "version" && resolved
    ? versionView(resolved, resolved)
    : { ...view };
}
