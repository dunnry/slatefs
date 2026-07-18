#!/usr/bin/env node

import assert from "node:assert/strict";
import {
  createSlateFsClient,
  SlateFsApiError,
} from "../web/packages/client/dist/index.js";

const bffUrl = process.env.SLATEFS_DEMO_BFF_URL ?? "http://127.0.0.1:4174";
const origin = new URL(bffUrl).origin;
const apiUrl = new URL("/api/", origin).toString();
const acmeVolume =
  process.env.SLATEFS_ACME_DEMO_VOLUME ?? "acme-demo-documents";
const globexVolume =
  process.env.SLATEFS_GLOBEX_DEMO_VOLUME ?? "globex-demo-documents";
const requestTimeoutMs = Number(
  process.env.SLATEFS_DEMO_REQUEST_TIMEOUT_MS ?? 10_000,
);

assert(
  Number.isSafeInteger(requestTimeoutMs) && requestTimeoutMs > 0,
  "SLATEFS_DEMO_REQUEST_TIMEOUT_MS must be a positive integer",
);

function cookieFrom(response) {
  const values = response.headers.getSetCookie?.() ?? [];
  const value = values.at(-1) ?? response.headers.get("set-cookie");
  return value?.split(";", 1)[0];
}

async function responseJson(response, operation) {
  const body = await response.json().catch(() => undefined);
  assert.equal(
    response.ok,
    true,
    `${operation} returned ${response.status}: ${JSON.stringify(body)}`,
  );
  return body;
}

async function login(username) {
  let cookie;
  let csrfToken;

  const session = await fetch(new URL("/api/v1/session", origin), {
    signal: AbortSignal.timeout(requestTimeoutMs),
  });
  cookie = cookieFrom(session);
  assert(cookie, `${username} session did not set a cookie`);
  csrfToken = (await responseJson(session, `${username} session`)).csrfToken;
  assert(csrfToken, `${username} session did not return a CSRF token`);

  const response = await fetch(new URL("/api/v1/login", origin), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie,
      origin,
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify({ username, password: "slatefs" }),
    signal: AbortSignal.timeout(requestTimeoutMs),
  });
  cookie = cookieFrom(response);
  assert(cookie, `${username} login did not rotate the session cookie`);
  const state = await responseJson(response, `${username} login`);
  csrfToken = state.csrfToken;
  assert(csrfToken, `${username} login did not rotate the CSRF token`);

  const sessionFetch = async (input, init = {}) => {
    const headers = new Headers(init.headers);
    headers.set("cookie", cookie);
    const method = (init.method ?? "GET").toUpperCase();
    if (!["GET", "HEAD"].includes(method)) headers.set("origin", origin);
    const timeout = AbortSignal.timeout(requestTimeoutMs);
    const signal = init.signal
      ? AbortSignal.any([init.signal, timeout])
      : timeout;
    const proxied = await fetch(input, { ...init, headers, signal });
    cookie = cookieFrom(proxied) ?? cookie;
    return proxied;
  };

  return {
    username,
    client: createSlateFsClient({
      baseUrl: apiUrl,
      fetch: sessionFetch,
      getCsrfToken: () => csrfToken,
    }),
  };
}

async function expectApiError(operation, expectedStatus, expectedCode) {
  const error = await operation().then(
    () => undefined,
    (reason) => reason,
  );
  assert(error instanceof SlateFsApiError, "expected a SlateFsApiError");
  assert.equal(error.status, expectedStatus);
  assert.equal(error.code, expectedCode);
}

async function readBytes(client, volume, entryId) {
  const result = await client.readContent(
    volume,
    { entryId },
    { kind: "live" },
  );
  return new Uint8Array(await new Response(result.body).arrayBuffer());
}

async function listDirectory(client, volume, selector) {
  const entries = [];
  let directory;
  let pageToken;
  do {
    const page = await client.listEntries(
      volume,
      selector,
      { kind: "live" },
      { limit: 200, ...(pageToken ? { pageToken } : {}) },
    );
    directory ??= page.entry;
    entries.push(...page.entries);
    pageToken = page.next_page_token ?? undefined;
  } while (pageToken);
  return { directory, entries };
}

function keepBothName(name, entries) {
  const names = new Set(entries.map((entry) => entry.name));
  assert(names.has(name), `keep-both source ${name} is not listed`);
  const dot = name.lastIndexOf(".");
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const extension = dot > 0 ? name.slice(dot) : "";
  for (let copy = 2; copy < 10_000; copy += 1) {
    const candidate = `${stem} (${copy})${extension}`;
    if (!names.has(candidate)) return candidate;
  }
  throw new Error(`could not choose a bounded keep-both name for ${name}`);
}

class UploadCollisionError extends Error {}

async function componentStyleUpload(
  client,
  volume,
  directoryId,
  name,
  content,
  collisionPolicy,
) {
  const { entries } = await listDirectory(client, volume, {
    entryId: directoryId,
  });
  const existing = entries.find((entry) => entry.name === name);
  if (existing && collisionPolicy === "fail")
    throw new UploadCollisionError(`${name} already exists`);
  const selectedName =
    existing && collisionPolicy === "keep_both"
      ? keepBothName(name, entries)
      : name;
  return client.uploadContent(
    volume,
    { parentEntryId: directoryId, name: selectedName },
    content,
  );
}

const artifactPrefix = "blob-acceptance-";

async function removeBlobAcceptanceArtifacts(client, volume) {
  // Re-list before every pass: a parent/name upsert can replace an entry and
  // invalidate an ID returned by an earlier upload.
  for (let pass = 1; pass <= 3; pass += 1) {
    const { entries } = await listDirectory(client, volume, { path: "/" });
    const artifacts = entries.filter(
      (entry) =>
        entry.parent_entry_id !== null &&
        entry.name?.startsWith(artifactPrefix),
    );
    if (artifacts.length === 0) return;
    await Promise.allSettled(
      artifacts.map((entry) =>
        client.deleteEntry(volume, entry.entry_id, false),
      ),
    );
  }
  const { entries } = await listDirectory(client, volume, { path: "/" });
  const remaining = entries.filter((entry) =>
    entry.name?.startsWith(artifactPrefix),
  );
  assert.equal(
    remaining.length,
    0,
    `cleanup left ${remaining.length} ${artifactPrefix} artifact(s) in ${volume}`,
  );
}

const alice = await login("alice");
const bob = await login("bob");

try {
  const [aliceVolumes, bobVolumes] = await Promise.all([
    alice.client.listVolumes(),
    bob.client.listVolumes(),
  ]);
  const aliceNames = aliceVolumes.volumes.map(({ name }) => name);
  const bobNames = bobVolumes.volumes.map(({ name }) => name);
  assert(aliceNames.includes(acmeVolume), "Alice cannot list the Acme volume");
  assert(
    !aliceNames.includes(globexVolume),
    "Alice can list the Globex volume",
  );
  assert(bobNames.includes(globexVolume), "Bob cannot list the Globex volume");
  assert(!bobNames.includes(acmeVolume), "Bob can list the Acme volume");

  await Promise.all([
    expectApiError(
      () =>
        alice.client.listEntries(globexVolume, { path: "/" }, { kind: "live" }),
      404,
      "not_found",
    ),
    expectApiError(
      () => bob.client.listEntries(acmeVolume, { path: "/" }, { kind: "live" }),
      404,
      "not_found",
    ),
  ]);

  // Previous interrupted runs are scoped to this prefix in Alice's volume.
  // Never enumerate or mutate Bob's volume during artifact cleanup.
  await removeBlobAcceptanceArtifacts(alice.client, acmeVolume);
  const { directory: root } = await listDirectory(alice.client, acmeVolume, {
    path: "/",
  });
  const suffix = crypto.randomUUID();
  const name = `${artifactPrefix}${suffix}.bin`;
  const bytes = new TextEncoder().encode(`native Blob acceptance ${suffix}`);
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const progress = [];

  const uploaded = await alice.client.uploadContent(
    acmeVolume,
    { parentEntryId: root.entry_id, name },
    blob,
    { onProgress: (event) => progress.push({ ...event }) },
  );
  assert.deepEqual(progress, [
    { transferredBytes: 0, totalBytes: bytes.byteLength },
    { transferredBytes: bytes.byteLength, totalBytes: bytes.byteLength },
  ]);
  assert.deepEqual(
    await readBytes(alice.client, acmeVolume, uploaded.entry_id),
    bytes,
  );

  // A raw parent/name upload is an upsert. It does not implement the file
  // explorer's collision policy and may return a different entry identity.
  const replacementBytes = new TextEncoder().encode(`upsert ${suffix}`);
  const replaced = await alice.client.uploadContent(
    acmeVolume,
    { parentEntryId: root.entry_id, name },
    new Blob([replacementBytes]),
  );
  assert.equal(replaced.name, name);
  assert.deepEqual(
    await readBytes(alice.client, acmeVolume, replaced.entry_id),
    replacementBytes,
  );

  // Entry-targeted replacement supports optimistic concurrency explicitly.
  await expectApiError(
    () =>
      alice.client.uploadContent(
        acmeVolume,
        { entryId: replaced.entry_id },
        new Blob(["must fail"]),
        { ifMatch: '"deliberately-stale-etag"' },
      ),
    412,
    "precondition_failed",
  );
  assert.deepEqual(
    await readBytes(alice.client, acmeVolume, replaced.entry_id),
    replacementBytes,
  );

  // Explorer collision policies are preflight behavior. "fail" stops before
  // calling the upsert route; "keep_both" chooses an unused sibling name.
  const failError = await componentStyleUpload(
    alice.client,
    acmeVolume,
    root.entry_id,
    name,
    new Blob(["must not upload"]),
    "fail",
  ).then(
    () => undefined,
    (reason) => reason,
  );
  assert(
    failError instanceof UploadCollisionError,
    "component-style fail policy did not detect the existing sibling",
  );
  assert.deepEqual(
    await readBytes(alice.client, acmeVolume, replaced.entry_id),
    replacementBytes,
  );

  const copyBytes = new TextEncoder().encode(`keep both ${suffix}`);
  const keptBoth = await componentStyleUpload(
    alice.client,
    acmeVolume,
    root.entry_id,
    name,
    new Blob([copyBytes]),
    "keep_both",
  );
  const copyName = keptBoth.name;
  assert(copyName && copyName !== name);
  assert.deepEqual(
    await readBytes(alice.client, acmeVolume, keptBoth.entry_id),
    copyBytes,
  );

  await expectApiError(
    () =>
      bob.client.readContent(
        acmeVolume,
        { entryId: replaced.entry_id },
        { kind: "live" },
      ),
    404,
    "not_found",
  );

  console.log(
    `web-demo-blob-upload: PASS (${name}, ${copyName}; Blob progress/readback, raw upsert, If-Match conflict, component-style collisions, Alice/Bob isolation)`,
  );
} finally {
  try {
    await removeBlobAcceptanceArtifacts(alice.client, acmeVolume);
  } catch (error) {
    console.error("web-demo-blob-upload: cleanup failed", error);
    process.exitCode = 1;
  }
}
