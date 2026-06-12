# pjdfstest over NFSv3 — documented exclusions (plan §14 Phase 2 AC)

Run environment: Linux kernel NFS client (privileged container or CI
runner) → `slatefsd`, export `squash = "none"` so per-uid permission
semantics are exercised. Harness: `scripts/pjdfstest-over-nfs.sh`
(suite: github.com/pjd/pjdfstest, master).

Suite size: 238 test files, 8798 assertions.

## Excluded assertions (protocol-inherent, not SlateFS bugs)

### unlink/14.t test 4 — nlink of an open-but-unlinked file
Expects `fstat` to report `nlink == 0` after `unlink` of an open file. The
Linux NFS client implements unlink-of-open-files via **silly rename**
(renames to `.nfsXXXX` and removes it on close), so the file genuinely
still has one link. Every NFS server fails this assertion; the equivalent
server-side behavior (orphan retention until last close) is covered by
`slatefs-nfs/tests/nfs_mount.rs::unlink_orphan_semantics_with_open_handles`
and pjdfstest's other unlink tests pass.

### utimensat/09.t test 5 — year-2106 timestamp
Sets `mtime = 2^32` (epoch seconds). The NFSv3 wire format (RFC 1813)
carries timestamps as **unsigned 32-bit seconds**; 2^32 is unrepresentable
and SlateFS clamps to `u32::MAX` (got `4294967295`). Test 4 (2^31, the
actual y2038 boundary) passes — the on-disk format stores i64 seconds, so
the limitation is purely the NFSv3 wire encoding. NFSv4 lifts this.

## Fixed during the AC run (no longer excluded)

| Test file | Failure | Fix |
|---|---|---|
| mkdir/00.t | created dirs ignored requested mode | vendored trait dropped `MKDIR3args.attributes`; mkdir now receives `sattr3` |
| chown/07.t (19) | non-owner chown to *unchanged* uid/gid returned 0 | EPERM now applies before the same-value short-circuit |
| rename/09.t (24), rename/21.t (4) | cross-parent dir move allowed without write perm on the moved dir | POSIX `..`-rewrite rule: rename now requires W on a directory moved between parents |
