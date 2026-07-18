import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import type {
  CapabilitiesResponse,
  EntryListResponse,
  ErrorEnvelope,
  VolumeListResponse,
} from "../src/index.js";

interface ContractFixture {
  capabilities: CapabilitiesResponse;
  volumes: VolumeListResponse;
  entries: EntryListResponse;
  error: ErrorEnvelope;
}

describe("shared consumer v1 wire fixture", () => {
  it("round-trips the same shapes consumed by Rust", async () => {
    const source = await readFile(
      new URL(
        "../../../../docs/api/fixtures/consumer-v1.json",
        import.meta.url,
      ),
      "utf8",
    );
    const fixture = JSON.parse(source) as ContractFixture;
    const roundTripped = JSON.parse(JSON.stringify(fixture)) as ContractFixture;

    expect(roundTripped).toEqual(fixture);
    expect(fixture.capabilities.api_version).toBe("consumer/v1");
    expect(fixture.entries.view.resolved_commit).toBeTruthy();
    expect(fixture.entries.entries[0]?.name).toBeNull();
    expect(fixture.entries.entries[0]?.name_bytes_base64).toBe("/2RvYw==");
    expect(fixture.error.error.request_id).toMatch(/^req-/);
  });
});
