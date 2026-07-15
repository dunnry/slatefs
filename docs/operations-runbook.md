# SlateFS Operations Runbook

Pre-GA note: there is no deployed compatibility contract yet. Prefer direct repair and clear
operator action over migration shims.

## Fencing And Failover

Signal:

- `SlateFSVolumeFenced` fires, or logs contain `volume fenced; dropping daemon exports`.
- `/metrics` reports `slatefs_volume_dead{tenant="...",volume="..."} 1`.
- The Grafana dashboard's Volume Liveness panel reports `dead`.

Immediate action:

1. Confirm only one `slatefsd` instance is intended to own the affected live volume.
2. Move the floating IP/DNS/service target to the takeover node.
3. Start `slatefsd` on the takeover node with the same object-store root and KMS config.
4. Watch logs until the export-ready line appears for the affected volume.
5. Run a read/write smoke through the client mount, then `slatefs volume scrub <tenant> <volume>`.

Expected behavior: the stale daemon marks the volume dead and drops exports; the takeover daemon
opens the same SlateDB path, advances the writer epoch, replays WAL, and serves with the same fsid.

Automated drill:

```sh
scripts/docker-kernel-mount-test.sh scripts/nfs-failover-drill.sh
```

The drill writes a durable marker through a real kernel NFS client, starts a takeover daemon on a
second port, forces the stale daemon to observe SlateDB fencing, remounts to the takeover export,
checks the measured failover window against `FAILOVER_MAX_SECONDS` (default: `10`), checks
`/metrics`, and runs `slatefs volume scrub`.

To exercise the Phase 6 fio-load target:

```sh
SKIP_SMOKE=1 \
FAILOVER_LOAD_MODE=fio \
FAILOVER_FIO_RUNTIME=30 \
FAILOVER_FIO_SIZE=256m \
FAILOVER_FSX_OPS=50000 \
scripts/docker-kernel-mount-test.sh scripts/nfs-failover-drill.sh
```

On 2026-06-14, a direct Linux run on the `nested-vm` Azure VM completed this
fio-load drill with `FAILOVER_FIO_RUNTIME=30`, `FAILOVER_FIO_SIZE=256m`,
`FAILOVER_FIO_BS=128k`, and `FAILOVER_FSX_OPS=50000`. The measured failover
window was 0.743 seconds against the 10 second gate; post-takeover scrub was
clean and `fsx` completed all 50000 operations.

`FAILOVER_FSX_OPS` is disabled by default for quick local smokes. When set, the drill builds
xfstests inside the container and runs `fsx` on the takeover mount after the timed failover.

## NBD Block Exports

Attach a Linux kernel client with a bounded timeout and, where available,
multiple connections:

```sh
modprobe nbd max_part=8 nbds_max=16
nbd-client 10.0.0.10 12059 /dev/nbd0 -N /t1/b1 -persist off -timeout 60 -C 2
mkfs.ext4 -F /dev/nbd0
mount -t ext4 -o noatime /dev/nbd0 /mnt/slatefs-block
```

Detach cleanly:

```sh
umount /mnt/slatefs-block
nbd-client -d /dev/nbd0
```

Offline grow is metadata-only on the SlateFS side, but the NBD client must be
detached so the device size can be renegotiated:

```sh
umount /mnt/slatefs-block
nbd-client -d /dev/nbd0
slatefs -c /etc/slatefs/slatefs.toml volume resize t1 b1 --size 200G
systemctl restart slatefsd
nbd-client 10.0.0.10 12059 /dev/nbd0 -N /t1/b1 -timeout 60
blockdev --rereadpt /dev/nbd0 || true
resize2fs /dev/nbd0
```

For failover, move the stable endpoint to the takeover daemon. The validated
kernel fallback is explicit detach/reattach of the fixed device after the
primary transport drops:

```sh
nbd-client -d /dev/nbd0
nbd-client 10.0.0.11 12059 /dev/nbd0 -N /t1/b1 -b 4096 -timeout 10
```

Bare `nbd-client -persist` may help on some client/kernel combinations, but
on `nested-vm` (`nbd-client` 3.23, Linux `6.8.0-1052-azure`) it did not
transparently resume the fixed `/dev/nbd0` session within the 10 second gate
after the primary process was killed and the takeover daemon rebound the same
endpoint. QEMU clients should set `reconnect-delay` on the NBD blockdev.
Validate the recovered filesystem with `e2fsck -f -p` after any forced outage
drill. The Phase B3 timing gate remains the same as the filesystem failover
target: resumed I/O in less than 10 seconds with no corruption.

Automated NBD failover drill:

```sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/nbd-failover-drill.sh
```

The drill writes a FLUSHed raw-device marker through the kernel NBD client,
runs verified raw-device load, kills the primary daemon, starts the takeover
daemon on the same NBD endpoint, detaches and reattaches the client, gates the
time to first verified takeover I/O with `SLATEFS_NBD_FAILOVER_MAX_SECONDS`
(default: `10`), verifies post-takeover writes, checks liveness metrics, and
runs offline `slatefs volume fsck`. Set any `FIO_*` variable, or
`SLATEFS_NBD_FAILOVER_LOAD_MODE=fio`, to use fio verify load instead of the
default checksum loop. Set `SLATEFS_NBD_FAILOVER_PERSIST_PROBE=1` to also try
the non-gating `nbd-client -persist` reconnect probe.

On 2026-07-08, three direct runs on `nested-vm` measured 0.742s, 0.683s, and
0.771s to first verified takeover I/O. The largest components were detach
(0.385-0.486s) and takeover open (0.215-0.238s); reattach and first I/O were
each below 0.05s. All three runs passed the 10 second gate and offline block
fsck was clean.

For snapshots and restore drills:

1. Create a live checkpoint through the serving daemon:
   `slatefs -c /etc/slatefs/slatefs.toml snapshot create --live t1 b1 --name before-upgrade`.
2. Export the checkpoint read-only:
   `slatefs -c /etc/slatefs/slatefs.toml export add b1-snap --tenant t1 --volume b1 --snapshot <checkpoint-id> --protocol nbd --listen 10.0.0.10:12060 --read-only`.
3. Attach the snapshot export read-only and verify expected contents without mounting it writable.
4. Create a writable clone when restore work needs mutation:
   `slatefs -c /etc/slatefs/slatefs.toml clone create t1 b1 b1-restore --snapshot <checkpoint-id>`.
5. Export the clone as a normal NBD target, run the application recovery smoke, then validate with `slatefs volume scrub t1 b1-restore`.

Automated smokes:

```sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/nbd-kernel-attach-test.sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/nbd-failover-drill.sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/qemu-nbd-smoke.sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/zfs-over-nbd-smoke.sh
```

## Object Store Outage

Signal:

- Protocol clients see retries or `EIO`.
- Daemon logs show object-store or SlateDB unavailable errors.
- `/metrics` reports `slatefs_volume_degraded{tenant="...",volume="..."} 1` or
  `slatefs_storage_errors_total{tenant="...",volume="..."} > 0`.

Immediate action:

1. Check object-store reachability and credentials from the daemon host.
2. Keep the daemon running if reads are still served from warm caches.
3. Once storage is healthy, run `slatefs volume scrub <tenant> <volume>` on affected volumes.
4. If scrub reports drift, stop serving the volume and run `slatefs volume fsck <tenant> <volume> --recount`.

## Restore From Snapshot

Use snapshots for point-in-time read access first:

1. List available checkpoints: `slatefs snapshot list <tenant> <volume>`.
2. Add an export with `snapshot = "<checkpoint-id>"` and a read-only listen address.
3. Mount the snapshot export and copy out the required data.

The current CLI snapshot-create path takes the writer lease; do not run it
against a volume actively served by `slatefsd`. For served volumes, use the
loopback-only daemon admin endpoint through the CLI:

```sh
slatefs -c /etc/slatefs/slatefs.toml snapshot create --live <tenant> <volume> --name <snapshot-name>
```

The CLI prints the checkpoint id for the snapshot export. The underlying daemon
request is `POST /snapshot/<tenant>/<volume>?name=<snapshot-name>` on
`[admin].listen`.

Automated drill:

```sh
SKIP_SMOKE=1 scripts/docker-kernel-mount-test.sh scripts/live-snapshot-over-nfs.sh
```

The drill writes through a live kernel NFS mount, creates a live snapshot
through the CLI/admin endpoint, serves the checkpoint on a second NFS mount,
verifies read-only point-in-time contents, checks the snapshot decode failure
metric, creates a writable clone from the same checkpoint, mounts the clone,
verifies clone writes do not affect the live volume, and validates the clone
with online `slatefs volume scrub`.

For opt-in file history on a currently served filesystem volume, route commit
and restore through that daemon's configured admin listener:

```sh
slatefs -c /etc/slatefs/slatefs.toml versioning commit <tenant> <volume> <path>... -m <message> --author <content-author> --idempotency-key <retry-key> --live
slatefs -c /etc/slatefs/slatefs.toml versioning restore <tenant> <volume> <commit> <path> --mode overlay --token <preview-token> --yes --live
slatefs -c /etc/slatefs/slatefs.toml versioning log <tenant> <volume> --live
slatefs -c /etc/slatefs/slatefs.toml versioning status <tenant> <volume> /projects --reference main --live
slatefs -c /etc/slatefs/slatefs.toml versioning restore-preview <tenant> <volume> main /projects --mode exact --live
slatefs -c /etc/slatefs/slatefs.toml versioning policy <tenant> <volume> --live
slatefs -c /etc/slatefs/slatefs.toml versioning diff <tenant> <volume> <from-commit> <to-commit> --live
slatefs -c /etc/slatefs/slatefs.toml versioning tag <tenant> <volume> <name> <commit> --live
slatefs -c /etc/slatefs/slatefs.toml versioning tags <tenant> <volume> --live
slatefs -c /etc/slatefs/slatefs.toml versioning untag <tenant> <volume> <name> --live
slatefs -c /etc/slatefs/slatefs.toml versioning branch <tenant> <volume> <name> <commit-or-ref> --live
slatefs -c /etc/slatefs/slatefs.toml versioning branches <tenant> <volume> --live
slatefs -c /etc/slatefs/slatefs.toml versioning protect-branch <tenant> <volume> <name> --allow-committer tenant:<tenant> --allow-manager admin-token --live
slatefs -c /etc/slatefs/slatefs.toml versioning unprotect-branch <tenant> <volume> <name> --yes --live
slatefs -c /etc/slatefs/slatefs.toml versioning reflog <tenant> <volume> <name> --limit 100 --live
slatefs -c /etc/slatefs/slatefs.toml versioning recover-branch <tenant> <volume> <name> <reflog-sequence> --yes --live
slatefs -c /etc/slatefs/slatefs.toml versioning delete-branch <tenant> <volume> <name> --live
slatefs -c /etc/slatefs/slatefs.toml versioning reset-branch <tenant> <volume> <name> <commit-or-ref> --yes --live
slatefs -c /etc/slatefs/slatefs.toml versioning commit <tenant> <volume> <path>... -m <message> --author <content-author> --branch <name> --live
slatefs -c /etc/slatefs/slatefs.toml versioning log <tenant> <volume> --branch <name> --live
slatefs -c /etc/slatefs/slatefs.toml versioning inspect <tenant> <volume> <commit-or-ref> --live
slatefs versioning attestation-keygen --out release.key --public-out release.pub
slatefs -c /etc/slatefs/slatefs.toml versioning attest <tenant> <volume> <commit-or-ref> --key-id release-2026 --key-file release.key --live
slatefs -c /etc/slatefs/slatefs.toml versioning attestations <tenant> <volume> <commit-or-ref> --trusted-public-key release.pub --live
slatefs -c /etc/slatefs/slatefs.toml versioning export-attestations <tenant> <volume> <commit-or-ref> --out release-attestations.json --live
slatefs versioning verify-attestation-bundle --in release-attestations.json --trusted-public-key release.pub
slatefs -c /etc/slatefs/slatefs.toml versioning merge <tenant> <volume> <source> <target> --author <content-author> --live
slatefs -c /etc/slatefs/slatefs.toml versioning merge <tenant> <volume> <source> <target> --conflict-strategy ours --live
slatefs -c /etc/slatefs/slatefs.toml versioning merge-preview <tenant> <volume> <source> <target> --live
slatefs -c /etc/slatefs/slatefs.toml versioning show <tenant> <volume> <commit> <path> --out restored.bin --live
slatefs -c /etc/slatefs/slatefs.toml versioning retention <tenant> <volume> --keep-last 100 --live
slatefs -c /etc/slatefs/slatefs.toml versioning gc <tenant> <volume> --dry-run --live
slatefs -c /etc/slatefs/slatefs.toml versioning stats <tenant> <volume> --live
slatefs -c /etc/slatefs/slatefs.toml versioning verify <tenant> <volume> --live
```

Attestation is optional and client-side: `slatefsd` receives the public key and
signature, never `release.key`. The signed statement binds the stable logical
repository UUID, resolved commit ID, key ID, algorithm, public key, and
timestamp. Tenant and volume names remain local access and storage coordinates.
The `attestations --trusted-public-key` command independently verifies each
returned signature against the resolved commit and fails unless that exact
public key signed it. The exported version-2 JSON bundle carries the repository
UUID, canonical commit ID, and detached attestations. Bundle verification is
standalone: it does not load `/etc/slatefs/slatefs.toml` or contact SlateFS.

To require a signer on a protected branch, first attest its current head, then
configure the trust anchor. One trusted signature is required by default. This
example uses two independent keys and requires both approvals:

```sh
slatefs versioning attestation-keygen --out security.key --public-out security.pub
slatefs -c /etc/slatefs/slatefs.toml versioning attest <tenant> <volume> main --key-id release-2026 --key-file release.key --live
slatefs -c /etc/slatefs/slatefs.toml versioning attest <tenant> <volume> main --key-id security-2026 --key-file security.key --live
slatefs -c /etc/slatefs/slatefs.toml versioning protect-branch <tenant> <volume> main --trust-attestation-key release-2026=release.pub --trust-attestation-key security-2026=security.pub --require-attestations 2 --allow-manager <admin-principal> --live
slatefs -c /etc/slatefs/slatefs.toml versioning branch <tenant> <volume> candidate main --live
slatefs -c /etc/slatefs/slatefs.toml versioning commit <tenant> <volume> <path>... -m <message> --branch candidate --live
slatefs -c /etc/slatefs/slatefs.toml versioning attest <tenant> <volume> candidate --key-id release-2026 --key-file release.key --live
slatefs -c /etc/slatefs/slatefs.toml versioning attest <tenant> <volume> candidate --key-id security-2026 --key-file security.key --live
slatefs -c /etc/slatefs/slatefs.toml versioning quorum-status <tenant> <volume> main candidate --check --live
slatefs -c /etc/slatefs/slatefs.toml versioning merge <tenant> <volume> candidate main --live
```

The final merge must be a fast-forward from the still-current protected head.
Direct commits and candidates below the configured quorum are rejected. A
divergent merge would create a new, unattested merge commit and is therefore
rejected; create a fresh candidate from the new protected head instead.
Changing the key set or quorum requires the current head to satisfy the new
policy. Removing all trusted keys with a zero quorum disables signature
enforcement, while `unprotect-branch` removes the entire destructive-ref guard.
`quorum-status` is read-only and prints the canonical candidate commit, trusted
and matching key IDs, required count, and final `satisfied` result. `--check`
also exits non-zero when the result is false, for use as a release gate.

Merge conflicts fail without moving either branch by default. After reviewing
`merge-preview`, use `--conflict-strategy ours` to keep each conflicting path
from the target or `--conflict-strategy theirs` to keep it from the source.
Resolution is applied to the complete logical path, while non-conflicting
changes from both branches are still merged.

Protect long-lived or release branches before exposing reset, deletion, or
recovery workflows to operators. Protection does not block commits or merges;
those operations preserve the protected head as an ancestor. Repeat
`--allow-committer` to restrict publication to exact server-derived committer
identities such as `tenant:<tenant>`, `admin-token`, or a configured admin
principal. Repeat `--allow-manager` to independently restrict live policy
updates and removal to exact server-derived identities. Omitting either list
leaves that operation unrestricted. Unauthorized live publication or policy
management returns HTTP `403`. Removing the guard requires
`unprotect-branch --yes` and emits a durable maintenance audit record.
Successful changes record the normalized policy, and denied manager attempts
record the requested policy with a `Denied` outcome. Audit records contain
identity names and the server-derived actor, never bearer tokens.
Denied protected-branch publications likewise record a `Denied` commit or
merge event with the branch, selected paths or merge endpoints, author, and
committer. They do not record the commit message or file contents.
Rejected reset, delete, reflog recovery, and protected-history purge attempts
also emit `Denied` maintenance or purge records with the requested target.
Alert on sustained increases in
`slatefs_version_operation_denials_total{tenant,volume,operation}`; the
`operation` label is one of `policy`, `commit`, `merge`, `reset`, `delete`,
`recover`, or `purge`. The starter
`SlateFSProtectedVersionOperationDenied` rule fires on any increase over five
minutes; tune its threshold only after establishing expected administrative
traffic.

Live commit and divergent-merge provenance records the authenticated admin or
tenant principal as committer and the HTTP request ID for audit correlation.
An allowed unauthenticated loopback request records `admin:unauthenticated`
instead. `--author` is optional on live requests and defaults to that committer
identity. It names the content author when supplied but cannot replace the
server-derived committer. Offline commit and divergent merge commands require
`--author`; they record the claimed identity as both author and committer.
Treat offline storage and KMS access as repository-administrator access: an
offline operator can claim an allowed committer identity. Use the authenticated
`--live` path when the allowlist must enforce customer identity.

`restore-preview` prints a token after the plan. Pass it unchanged to
`restore --token`; a `409` means the branch, plan, or live subtree changed and
the preview must be regenerated. Exact mode deletes live-only paths and
therefore requires `--yes`. Multi-path restore is not globally atomic, so
schedule exact subtree restores during a client write quiescence window.

The CLI supplies the matching `[admin.tenant_tokens]` credential when present,
otherwise `admin.token` or `admin.token_file`, as a bearer token. Tenant tokens
cannot access another tenant or global admin routes. All versioning subcommands
accept `--live`; direct repository commands without it must not be run while
`slatefsd` serves that volume.

For an HTTPS admin endpoint, configure `admin.tls_server_ca` and, when the
certificate is issued to a DNS name rather than the listener IP,
`admin.tls_server_name` in the CLI config. Add `admin.tls_client_cert` and
`admin.tls_client_key` when the daemon requires mTLS. A config shared with the
daemon can use `admin.tls_cert` as its trust anchor when `tls_server_ca` is
omitted.

Rotate a customer bearer token without restarting `slatefsd` by configuring
`[admin.tenant_token_files]` and atomically replacing that tenant's file. Files
are newline-delimited: the CLI sends the first token and the daemon accepts all
listed tokens. First write `new-token` followed by `old-token`, migrate clients,
then write only `new-token`. Use a same-directory temporary file plus `mv` so
readers never observe a partial write, and restrict file permissions to the
daemon and authorized operators. A malformed or unreadable source fails tenant
authentication closed; the global operator token remains usable for repair.

Live version commits flush and validate the SlateDB writer lease before file
capture and immediately before publishing history. HTTP `503` means that
daemon was fenced; discover the current primary and retry there. The failed
attempt does not advance the version-history head.

Configure version-history lifecycle offline. A daemon serving the writable
volume enforces count and age limits on its export-control poll; these commands
remain available for previews and immediate collection:

```sh
slatefs -c /etc/slatefs/slatefs.toml versioning retention <tenant> <volume> --keep-last 100 --max-age 2592000 --max-bytes 10737418240
slatefs -c /etc/slatefs/slatefs.toml versioning gc <tenant> <volume> --dry-run
slatefs -c /etc/slatefs/slatefs.toml versioning gc <tenant> <volume>
slatefs -c /etc/slatefs/slatefs.toml versioning stats <tenant> <volume>
slatefs -c /etc/slatefs/slatefs.toml versioning verify <tenant> <volume>
```

`versioning show` and restore stream large files in volume-sized chunks. Admin
API content reads are paged with `offset` and `length` (1 MiB default, 4 MiB
maximum) and return `total_size`, `eof`, and `next_offset`. Show, restore, and
diff accept either a commit ID or an immutable tag name.

`versioning policy <tenant> <volume> [--live]` also reports the current or most
recent repository lease, including owner UUID, operation, expiry, and whether
it is expired. Use this before diagnosing a `409` conflict or removing an
orphaned local lease.

Long histories are newest-first and cursor-paginated. Pass the printed token
back unchanged to continue after the last commit from the previous page:

```sh
slatefs -c /etc/slatefs/slatefs.toml versioning log <tenant> <volume> --limit 100 --page-token <commit-id> --live
```

Path-filtered history uses the same exclusive cursor and returns the next 100
matching commits rather than merely scanning 100 unfiltered commits.

`versioning purge <tenant> <volume> --yes` is irreversible. SlateFS acquires
the same deployment-wide per-volume lease used by repository reads, commits,
verification, and GC, so a concurrent operation returns a conflict instead of
racing the deletion. Any protected branch also returns a conflict; review and
explicitly unprotect every guarded branch before purging. Disabling alone
retains history and is not a purge. For a
served volume, continue to use `--live`; the lease coordinates version history,
not direct access to the live filesystem writer.

On CAS-capable cloud stores, a crashed holder's lease is taken over after its
expiry. The local `file://` store intentionally refuses automatic stale
takeover because it cannot conditionally update objects. After confirming the
owning process is gone and no version operation is active, use the exact owner
reported by status:

```sh
slatefs -c /etc/slatefs/slatefs.toml versioning unlock <tenant> <volume> --owner <owner-uuid> --yes --live
```

Omit `--live` only for an offline deployment. Unlock rejects active leases,
owner mismatches, and missing `--yes`; successful unlocks are durably audited.

For a writable restore workspace:

1. Create a clone: `slatefs clone create <tenant> <source-volume> <clone-volume> --snapshot <checkpoint-id>`.
2. Export the clone as a normal writable volume.
3. Run a read/write smoke through the clone mount.
4. Validate with `slatefs volume scrub <tenant> <clone-volume>`.

## Key Rotation

Rotate a tenant KEK:

```sh
slatefs key rotate-kek <tenant>
```

This rewraps active volume DEKs in the control plane. It does not rewrite volume data blocks.
Already-open daemon volumes keep their in-memory DEK; restart exports on the normal maintenance
cycle if you want every serving process to prove it can unwrap the new envelopes.

After rotation:

1. Reopen or restart one non-critical export for the tenant.
2. Run `slatefs volume scrub <tenant> <volume>`.
3. Keep the old master KMS material recoverable until the new wraps have been verified.

## Clock Discipline

SlateDB fencing, WAL timing, and cache/TTL behavior assume a sane wall clock.
Run the daemon on hosts with NTP or an equivalent time-sync service enabled
(`chrony`, `systemd-timesyncd`, or platform time sync), and alert on sustained
clock drift before serving production exports.

If clock drift is suspected:

1. Drain or stop the affected `slatefsd` process.
2. Repair host time sync and confirm the clock is stable.
3. Restart exports and run `slatefs volume scrub <tenant> <volume>` on affected volumes.

Filesystem timestamps may reflect host skew, but they are not used as ordering
authority for metadata correctness.
