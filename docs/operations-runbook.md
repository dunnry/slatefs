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
nbd-client 10.0.0.10 12059 /dev/nbd0 -N /t1/b1 -persist off -timeout 60
blockdev --rereadpt /dev/nbd0 || true
resize2fs /dev/nbd0
```

For failover, move the stable endpoint to the takeover daemon and use a client
that retries transport drops. Kernel clients can run with `nbd-client
-persist` and a finite `-timeout`; QEMU clients should set `reconnect-delay`
on the NBD blockdev. Validate the recovered filesystem with `e2fsck -f -p`
after any forced outage drill. The Phase B3 timing gate remains the same as
the filesystem failover target: resumed I/O in less than 10 seconds with no
corruption.

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
