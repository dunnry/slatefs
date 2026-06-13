# pjdfstest — documented exclusions (plan §14 Phase 2 + Phase 4 AC)

Two run environments, one suite (github.com/pjd/pjdfstest, master, 238 test
files / 8798 assertions):

| Protocol | Harness | Result |
|---|---|---|
| NFSv3 (`squash = "none"`) | `scripts/pjdfstest-over-nfs.sh` | 8796/8798 |
| 9P2000.L (`access=user`) | `scripts/pjdfstest-over-9p.sh` | 8796/8798 |

Both are driven by a real Linux kernel client (privileged container or CI
runner) against `slatefsd`. The two failures differ per protocol — each is
a limitation of that protocol's client/wire stack, not a SlateFS bug.

---

# NFSv3 exclusions

Export `squash = "none"` so per-uid permission semantics are exercised.

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

---

# 9P2000.L exclusions

Mount `-o version=9p2000.L,access=user,uname=<token>,aname=/tenant/volume`.
Under `access=user` the Linux v9fs client re-attaches per uid and enforces
DAC **client-side** with the caller's full credentials; the protocol carries
no per-operation gid or supplementary groups (only the attaching `n_uname`).
SlateFS therefore marks the 9P connection *trusted* — it keeps the real
uid/gid for ownership attribution but does not re-run access checks it lacks
the credentials to perform correctly (`Credentials::trusted`,
`crates/slatefs-core/src/vfs.rs`). This is the standard posture for
`access=user` 9P servers (diod, QEMU virtfs). Rules keyed on the caller
being *genuinely* privileged — setuid/setgid clearing on write and on
gid-chown, device-node creation — remain enforced against the real uid.

## Excluded assertions (client/wire-inherent, not SlateFS bugs)

### utimensat/08.t tests 5–6 — sub-second timestamp precision
Sets `atime`/`mtime` with a 0.1 s nanosecond component and expects it back;
over the kernel mount the nanoseconds read as `0`. The truncation is in the
Linux **v9fs client**, not SlateFS: the VFS superblock default
`s_time_gran` is 1 second (`alloc_super`), and v9fs never lowers it, so the
kernel rounds timestamps to whole seconds *before* the `Tsetattr` is sent.
The server carries full nanoseconds end-to-end — proven directly over the
wire by `slatefs-9p/tests/p9_mount.rs::p9_setattr_subsecond_time_roundtrip`
(`Tsetattr` 100_000_000 ns → `Tgetattr` returns 100_000_000 ns). The same
mechanism means whole-second times (every other utimensat test) pass.

## Not excluded — 9P passes where NFSv3 cannot
The two NFSv3 exclusions above do **not** recur over 9P:
- **unlink of an open file** (`unlink/14.t`): 9P has no silly-rename; v9fs
  sends `Tunlinkat` and the file's `nlink` drops to 0 immediately while the
  open fid keeps it alive (SlateFS orphan retention), so `fstat` reports
  `nlink == 0` as POSIX requires.
- **year-2106 timestamp** (`utimensat/09.t`): 9P2000.L carries 64-bit
  seconds, so `2^32` is representable (subject to the `s_time_gran` rounding
  above, which does not affect the whole-second value).
