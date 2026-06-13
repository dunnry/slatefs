//! Functional tests for the Vfs implementation (plan §14 Phase 1) — every
//! operation family, POSIX edge cases, quota exactness, and fsck cleanliness
//! after the workload.

mod common;

use std::sync::Arc;

use common::{TEST_CHUNK, fresh_volume, fresh_volume_on, test_kms};
use slatefs_core::control::ControlPlane;
use slatefs_core::meta::inode::{FileKind, ROOT_INO};
use slatefs_core::vfs::{Credentials, FsError, OpenMode, SetAttrs, TimeSet, Vfs};
use slatefs_core::{store, volume};

fn root() -> Credentials {
    Credentials::root()
}

fn alice() -> Credentials {
    Credentials::user(1000, 1000)
}

fn bob() -> Credentials {
    Credentials::user(1001, 1001)
}

#[tokio::test]
async fn create_lookup_read_write_roundtrip() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"hello.txt", 0o644, true)
        .await
        .unwrap();
    assert_eq!(f.kind, FileKind::File);
    assert_eq!(f.nlink, 1);
    assert_eq!(f.size, 0);

    // Multi-chunk write (3.5 chunks) + readback.
    let data: Vec<u8> = (0..TEST_CHUNK as usize * 7 / 2)
        .map(|i| (i % 251) as u8)
        .collect();
    let written = v.write(&root(), f.ino, 0, &data).await.unwrap();
    assert_eq!(written as usize, data.len());
    let read = v
        .read(&root(), f.ino, 0, data.len() as u32 + 100)
        .await
        .unwrap();
    assert_eq!(&read[..], &data[..]);

    // Unaligned mid-file overwrite.
    let patch = vec![0xAB; 1000];
    v.write(&root(), f.ino, 3000, &patch).await.unwrap();
    let read = v.read(&root(), f.ino, 2990, 1020).await.unwrap();
    assert_eq!(&read[..10], &data[2990..3000]);
    assert_eq!(&read[10..1010], &patch[..]);
    assert_eq!(&read[1010..], &data[4000..4010]);

    let attr = v.lookup(&root(), ROOT_INO, b"hello.txt").await.unwrap();
    assert_eq!(attr.size, data.len() as u64);
    assert_eq!(attr.ino, f.ino);

    // Reads past EOF clamp; reads in holes of sparse files return zeros.
    assert!(
        v.read(&root(), f.ino, attr.size + 10, 50)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(v.fsck().await.unwrap().is_clean());
}

#[tokio::test]
async fn online_scrub_does_not_take_writer_lease() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let v = fresh_volume_on(Arc::clone(&object_store), None, None).await;
    let f = v
        .create(&root(), ROOT_INO, b"scrubbed", 0o644, true)
        .await
        .unwrap();
    v.write(&root(), f.ino, 0, b"still serving").await.unwrap();

    let control = ControlPlane::open(Arc::clone(&object_store), test_kms())
        .await
        .unwrap();
    let report = volume::scrub_volume(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
    control.close().await.unwrap();

    // The original writer was not fenced by the scrub reader.
    v.create(&root(), ROOT_INO, b"after-scrub", 0o644, true)
        .await
        .unwrap();
    assert!(v.fsck().await.unwrap().is_clean());
}

#[tokio::test]
async fn sparse_files_bill_only_allocated_chunks() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"sparse", 0o644, true)
        .await
        .unwrap();
    // Write 100 bytes at a 100-chunk offset: only one chunk allocated.
    let offset = TEST_CHUNK as u64 * 100;
    v.write(&root(), f.ino, offset, &[7u8; 100]).await.unwrap();

    let attr = v.getattr(&root(), f.ino).await.unwrap();
    assert_eq!(attr.size, offset + 100);
    assert_eq!(
        attr.blocks,
        100u64.div_ceil(512),
        "holes must not be billed"
    );

    // Hole reads back as zeros.
    let hole = v
        .read(&root(), f.ino, TEST_CHUNK as u64 * 50, 64)
        .await
        .unwrap();
    assert!(hole.iter().all(|&b| b == 0));
    assert!(v.fsck().await.unwrap().is_clean());
}

#[tokio::test]
async fn exclusive_create_and_unchecked_create() {
    let v = fresh_volume().await;
    v.create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    assert_eq!(
        v.create(&root(), ROOT_INO, b"f", 0o644, true)
            .await
            .unwrap_err(),
        FsError::Exists
    );
    // Non-exclusive create on existing file returns it.
    let again = v
        .create(&root(), ROOT_INO, b"f", 0o600, false)
        .await
        .unwrap();
    assert_eq!(again.mode, 0o644, "non-excl create must not clobber attrs");
}

#[tokio::test]
async fn mkdir_readdir_pagination_and_cookies() {
    let v = fresh_volume().await;
    let d = v.mkdir(&root(), ROOT_INO, b"dir", 0o755).await.unwrap();
    assert_eq!(d.nlink, 2);
    assert_eq!(v.getattr(&root(), ROOT_INO).await.unwrap().nlink, 3);

    for i in 0..25u32 {
        let name = format!("file-{i:02}");
        v.create(&root(), d.ino, name.as_bytes(), 0o644, true)
            .await
            .unwrap();
    }

    // Paginate by 7 using returned cookies; entries must be exhaustive and
    // unique regardless of page size.
    let mut seen = Vec::new();
    let mut cookie = 0;
    loop {
        let page = v.readdir(&root(), d.ino, cookie, 7).await.unwrap();
        for e in &page.entries {
            seen.push(String::from_utf8(e.name.clone()).unwrap());
            cookie = e.cookie;
        }
        if page.eof {
            break;
        }
    }
    let mut expected: Vec<String> = (0..25).map(|i| format!("file-{i:02}")).collect();
    seen.sort();
    expected.sort();
    assert_eq!(seen, expected);

    // "." and ".." resolve via lookup.
    assert_eq!(v.lookup(&root(), d.ino, b".").await.unwrap().ino, d.ino);
    assert_eq!(v.lookup(&root(), d.ino, b"..").await.unwrap().ino, ROOT_INO);
    assert!(v.fsck().await.unwrap().is_clean());
}

#[tokio::test]
async fn unlink_orphan_semantics_with_open_handles() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    v.write(&root(), f.ino, 0, &[1u8; 5000]).await.unwrap();

    let h = v.open(&root(), f.ino, OpenMode::ReadWrite).await.unwrap();
    v.unlink(&root(), ROOT_INO, b"f").await.unwrap();

    // Gone from the namespace…
    assert_eq!(
        v.lookup(&root(), ROOT_INO, b"f").await.unwrap_err(),
        FsError::NotFound
    );
    // …but still readable and writable through the open handle.
    let attr = v.getattr(&root(), f.ino).await.unwrap();
    assert_eq!(attr.nlink, 0);
    assert_eq!(
        &v.read(&root(), f.ino, 0, 16).await.unwrap()[..],
        &[1u8; 16]
    );
    v.write(&root(), f.ino, 5000, &[2u8; 100]).await.unwrap();

    // Last close reaps: the ino is now stale.
    v.close(h).await.unwrap();
    assert_eq!(v.getattr(&root(), f.ino).await.unwrap_err(), FsError::Stale);

    let report = v.fsck().await.unwrap();
    assert!(report.is_clean(), "{:?}", report.problems);
    assert_eq!(report.inodes_counted, 1); // just root
    assert_eq!(report.bytes_counted, 0);
}

#[tokio::test]
async fn hardlinks_and_nlink_accounting() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"a", 0o644, true)
        .await
        .unwrap();
    v.write(&root(), f.ino, 0, b"content").await.unwrap();

    let linked = v.link(&root(), f.ino, ROOT_INO, b"b").await.unwrap();
    assert_eq!(linked.nlink, 2);
    assert_eq!(v.lookup(&root(), ROOT_INO, b"b").await.unwrap().ino, f.ino);

    v.unlink(&root(), ROOT_INO, b"a").await.unwrap();
    let attr = v.getattr(&root(), f.ino).await.unwrap();
    assert_eq!(attr.nlink, 1);
    assert_eq!(&v.read(&root(), f.ino, 0, 7).await.unwrap()[..], b"content");

    // Directories can't be hardlinked.
    let d = v.mkdir(&root(), ROOT_INO, b"dir", 0o755).await.unwrap();
    assert_eq!(
        v.link(&root(), d.ino, ROOT_INO, b"dirlink")
            .await
            .unwrap_err(),
        FsError::NotPermitted
    );
    assert!(v.fsck().await.unwrap().is_clean());
}

#[tokio::test]
async fn symlink_readlink() {
    let v = fresh_volume().await;
    let s = v
        .symlink(&root(), ROOT_INO, b"link", b"../target/path")
        .await
        .unwrap();
    assert_eq!(s.kind, FileKind::Symlink);
    assert_eq!(s.size, 14);
    assert_eq!(v.readlink(&root(), s.ino).await.unwrap(), b"../target/path");
    // readlink on a regular file is EINVAL.
    let f = v
        .create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    assert_eq!(
        v.readlink(&root(), f.ino).await.unwrap_err(),
        FsError::Invalid
    );
}

#[tokio::test]
async fn rename_file_dir_replace_and_cycle() {
    let v = fresh_volume().await;
    let d1 = v.mkdir(&root(), ROOT_INO, b"d1", 0o755).await.unwrap();
    let d2 = v.mkdir(&root(), ROOT_INO, b"d2", 0o755).await.unwrap();
    let f = v.create(&root(), d1.ino, b"f", 0o644, true).await.unwrap();
    v.write(&root(), f.ino, 0, b"payload").await.unwrap();

    // Simple move between directories.
    v.rename(&root(), d1.ino, b"f", d2.ino, b"g").await.unwrap();
    assert_eq!(
        v.lookup(&root(), d1.ino, b"f").await.unwrap_err(),
        FsError::NotFound
    );
    assert_eq!(v.lookup(&root(), d2.ino, b"g").await.unwrap().ino, f.ino);

    // Replace an existing target file; its inode dies.
    let victim = v.create(&root(), d2.ino, b"h", 0o644, true).await.unwrap();
    v.write(&root(), victim.ino, 0, &[9u8; 9000]).await.unwrap();
    v.rename(&root(), d2.ino, b"g", d2.ino, b"h").await.unwrap();
    assert_eq!(
        v.getattr(&root(), victim.ino).await.unwrap_err(),
        FsError::Stale
    );
    assert_eq!(&v.read(&root(), f.ino, 0, 7).await.unwrap()[..], b"payload");

    // Directory move updates parent nlinks and ".." resolution.
    let sub = v.mkdir(&root(), d1.ino, b"sub", 0o755).await.unwrap();
    v.rename(&root(), d1.ino, b"sub", d2.ino, b"sub")
        .await
        .unwrap();
    assert_eq!(v.lookup(&root(), sub.ino, b"..").await.unwrap().ino, d2.ino);
    assert_eq!(v.getattr(&root(), d1.ino).await.unwrap().nlink, 2);
    assert_eq!(v.getattr(&root(), d2.ino).await.unwrap().nlink, 3);

    // Cycle: moving an ancestor into its descendant must fail.
    assert_eq!(
        v.rename(&root(), ROOT_INO, b"d2", sub.ino, b"oops")
            .await
            .unwrap_err(),
        FsError::Invalid
    );

    // Replacing a non-empty dir fails; empty dir succeeds.
    let e1 = v.mkdir(&root(), ROOT_INO, b"e1", 0o755).await.unwrap();
    v.mkdir(&root(), ROOT_INO, b"e2", 0o755).await.unwrap();
    v.create(&root(), e1.ino, b"x", 0o644, true).await.unwrap();
    assert_eq!(
        v.rename(&root(), ROOT_INO, b"e2", ROOT_INO, b"e1")
            .await
            .unwrap_err(),
        FsError::NotEmpty
    );
    v.unlink(&root(), e1.ino, b"x").await.unwrap();
    v.rename(&root(), ROOT_INO, b"e2", ROOT_INO, b"e1")
        .await
        .unwrap();

    let report = v.fsck().await.unwrap();
    assert!(report.is_clean(), "{:?}", report.problems);
}

#[tokio::test]
async fn rmdir_only_empty_dirs() {
    let v = fresh_volume().await;
    let d = v.mkdir(&root(), ROOT_INO, b"d", 0o755).await.unwrap();
    v.create(&root(), d.ino, b"f", 0o644, true).await.unwrap();
    assert_eq!(
        v.rmdir(&root(), ROOT_INO, b"d").await.unwrap_err(),
        FsError::NotEmpty
    );
    v.unlink(&root(), d.ino, b"f").await.unwrap();
    v.rmdir(&root(), ROOT_INO, b"d").await.unwrap();
    assert_eq!(v.getattr(&root(), ROOT_INO).await.unwrap().nlink, 2);
    // rmdir on a file is ENOTDIR; unlink on a dir is EISDIR.
    v.create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    let d2 = v.mkdir(&root(), ROOT_INO, b"d2", 0o755).await.unwrap();
    let _ = d2;
    assert_eq!(
        v.rmdir(&root(), ROOT_INO, b"f").await.unwrap_err(),
        FsError::NotDir
    );
    assert_eq!(
        v.unlink(&root(), ROOT_INO, b"d2").await.unwrap_err(),
        FsError::IsDir
    );
}

#[tokio::test]
async fn truncate_shrink_grow_and_billing() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    let data: Vec<u8> = (0..TEST_CHUNK as usize * 3)
        .map(|i| (i % 199) as u8)
        .collect();
    v.write(&root(), f.ino, 0, &data).await.unwrap();

    // Shrink to mid-chunk.
    let new_size = TEST_CHUNK as u64 + 100;
    let attrs = SetAttrs {
        size: Some(new_size),
        ..Default::default()
    };
    let attr = v.setattr(&root(), f.ino, attrs).await.unwrap();
    assert_eq!(attr.size, new_size);
    assert_eq!(attr.blocks, new_size.div_ceil(512));
    let read = v.read(&root(), f.ino, 0, 3 * TEST_CHUNK).await.unwrap();
    assert_eq!(read.len() as u64, new_size);
    assert_eq!(&read[..], &data[..new_size as usize]);

    // Grow sparsely: size changes, billing doesn't.
    let big = TEST_CHUNK as u64 * 10;
    let attr = v
        .setattr(
            &root(),
            f.ino,
            SetAttrs {
                size: Some(big),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(attr.size, big);
    assert_eq!(
        attr.blocks,
        new_size.div_ceil(512),
        "sparse growth must not bill"
    );
    // The formerly-truncated region reads as zeros now.
    let read = v.read(&root(), f.ino, new_size, 100).await.unwrap();
    assert!(read.iter().all(|&b| b == 0));

    let report = v.fsck().await.unwrap();
    assert!(report.is_clean(), "{:?}", report.problems);
}

#[tokio::test]
async fn permissions_and_sticky_bit() {
    let v = fresh_volume().await;
    // World-writable dir with sticky bit (like /tmp), plus a private dir.
    let tmp = v.mkdir(&root(), ROOT_INO, b"tmp", 0o1777).await.unwrap();
    let priv_d = v.mkdir(&root(), ROOT_INO, b"priv", 0o700).await.unwrap();

    // Non-owner can't create in 0700.
    assert_eq!(
        v.create(&alice(), priv_d.ino, b"f", 0o644, true)
            .await
            .unwrap_err(),
        FsError::AccessDenied
    );

    // Alice creates in tmp; Bob may not delete it (sticky), Alice may.
    let f = v
        .create(&alice(), tmp.ino, b"af", 0o644, true)
        .await
        .unwrap();
    assert_eq!(f.uid, 1000);
    assert_eq!(
        v.unlink(&bob(), tmp.ino, b"af").await.unwrap_err(),
        FsError::NotPermitted
    );
    v.unlink(&alice(), tmp.ino, b"af").await.unwrap();

    // chmod: only owner or root; chown uid: only root.
    let g = v
        .create(&alice(), tmp.ino, b"g", 0o644, true)
        .await
        .unwrap();
    assert_eq!(
        v.setattr(
            &bob(),
            g.ino,
            SetAttrs {
                mode: Some(0o600),
                ..Default::default()
            }
        )
        .await
        .unwrap_err(),
        FsError::NotPermitted
    );
    v.setattr(
        &alice(),
        g.ino,
        SetAttrs {
            mode: Some(0o600),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        v.setattr(
            &alice(),
            g.ino,
            SetAttrs {
                uid: Some(0),
                ..Default::default()
            }
        )
        .await
        .unwrap_err(),
        FsError::NotPermitted
    );

    // Read denied without permission.
    assert_eq!(
        v.read(&bob(), g.ino, 0, 10).await.unwrap_err(),
        FsError::AccessDenied
    );

    // utimens: explicit times need ownership.
    let t = TimeSet::Time(slatefs_core::meta::inode::Timespec { secs: 1, nanos: 2 });
    assert_eq!(
        v.setattr(
            &bob(),
            g.ino,
            SetAttrs {
                mtime: Some(t),
                ..Default::default()
            }
        )
        .await
        .unwrap_err(),
        FsError::NotPermitted
    );
}

#[tokio::test]
async fn quota_enforced_exactly_and_statfs() {
    let object_store = slatefs_core::store::resolve_root("memory:///").unwrap();
    let v = common::fresh_volume_on(object_store, Some(TEST_CHUNK as u64 * 4), Some(5)).await;

    // Inode quota: root counts 1; 4 more fit exactly.
    for i in 0..4 {
        v.create(&root(), ROOT_INO, format!("f{i}").as_bytes(), 0o644, true)
            .await
            .unwrap();
    }
    assert_eq!(
        v.create(&root(), ROOT_INO, b"one-too-many", 0o644, true)
            .await
            .unwrap_err(),
        FsError::QuotaExceeded
    );

    // Byte quota: exactly 4 chunks fit.
    let f = v.lookup(&root(), ROOT_INO, b"f0").await.unwrap();
    v.write(&root(), f.ino, 0, &vec![1u8; TEST_CHUNK as usize * 4])
        .await
        .unwrap();
    assert_eq!(
        v.write(&root(), f.ino, TEST_CHUNK as u64 * 4, &[1u8])
            .await
            .unwrap_err(),
        FsError::QuotaExceeded
    );

    let s = v.statfs(&root()).await.unwrap();
    assert_eq!(s.total_bytes, TEST_CHUNK as u64 * 4);
    assert_eq!(s.free_bytes, 0);
    assert_eq!(s.total_inodes, 5);
    assert_eq!(s.free_inodes, 0);

    // Freeing space by truncate restores headroom exactly.
    v.setattr(
        &root(),
        f.ino,
        SetAttrs {
            size: Some(0),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let s = v.statfs(&root()).await.unwrap();
    assert_eq!(s.free_bytes, TEST_CHUNK as u64 * 4);

    let report = v.fsck().await.unwrap();
    assert!(report.is_clean(), "{:?}", report.problems);
}

#[tokio::test]
async fn xattr_roundtrip() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    assert_eq!(
        v.getxattr(&root(), f.ino, b"user.color").await.unwrap_err(),
        FsError::NoData
    );
    v.setxattr(&root(), f.ino, b"user.color", b"blue")
        .await
        .unwrap();
    v.setxattr(&root(), f.ino, b"user.shape", b"round")
        .await
        .unwrap();
    assert_eq!(
        v.getxattr(&root(), f.ino, b"user.color").await.unwrap(),
        b"blue"
    );
    let mut names = v.listxattr(&root(), f.ino).await.unwrap();
    names.sort();
    assert_eq!(names, vec![b"user.color".to_vec(), b"user.shape".to_vec()]);
    v.removexattr(&root(), f.ino, b"user.color").await.unwrap();
    assert_eq!(
        v.removexattr(&root(), f.ino, b"user.color")
            .await
            .unwrap_err(),
        FsError::NoData
    );
}

#[tokio::test]
async fn advisory_byte_range_locks() {
    let v = fresh_volume().await;
    let f = v
        .create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    let h1 = v.open(&root(), f.ino, OpenMode::ReadWrite).await.unwrap();
    let h2 = v.open(&root(), f.ino, OpenMode::ReadWrite).await.unwrap();

    v.lock(h1, 0, 100, true).await.unwrap();
    assert_eq!(
        v.lock(h2, 50, 60, false).await.unwrap_err(),
        FsError::WouldBlock
    );
    assert_eq!(
        v.testlock(h2, 50, 60, false).await.unwrap(),
        Some((0, 100, true))
    );
    v.unlock(h1, 0, 100).await.unwrap();
    v.lock(h2, 50, 60, false).await.unwrap();

    // Closing a handle drops its locks.
    v.close(h2).await.unwrap();
    v.lock(h1, 0, u64::MAX, true).await.unwrap();
    v.close(h1).await.unwrap();
}

#[tokio::test]
async fn name_edge_cases() {
    let v = fresh_volume().await;
    assert_eq!(
        v.create(&root(), ROOT_INO, &[b'x'; 256], 0o644, true)
            .await
            .unwrap_err(),
        FsError::NameTooLong
    );
    for bad in [&b""[..], &b"."[..], &b".."[..], &b"a/b"[..], &b"a\0b"[..]] {
        assert_eq!(
            v.create(&root(), ROOT_INO, bad, 0o644, true)
                .await
                .unwrap_err(),
            FsError::Invalid,
            "name {bad:?}"
        );
    }
    // 255 bytes and non-UTF8 are fine.
    v.create(&root(), ROOT_INO, &[b'x'; 255], 0o644, true)
        .await
        .unwrap();
    v.create(&root(), ROOT_INO, &[0xff, 0xfe, 0x80], 0o644, true)
        .await
        .unwrap();
    let found = v
        .lookup(&root(), ROOT_INO, &[0xff, 0xfe, 0x80])
        .await
        .unwrap();
    assert_eq!(found.kind, FileKind::File);
}

#[tokio::test]
async fn mknod_kinds_and_privileges() {
    let v = fresh_volume().await;
    let fifo = v
        .mknod(&root(), ROOT_INO, b"pipe", 0o644, FileKind::Fifo, 0)
        .await
        .unwrap();
    assert_eq!(fifo.kind, FileKind::Fifo);
    let dev = v
        .mknod(
            &root(),
            ROOT_INO,
            b"dev",
            0o600,
            FileKind::CharDev,
            (1 << 32) | 3,
        )
        .await
        .unwrap();
    assert_eq!(dev.rdev, (1 << 32) | 3);
    // Device nodes are root-only.
    assert_eq!(
        v.mknod(&alice(), ROOT_INO, b"dev2", 0o600, FileKind::BlockDev, 0)
            .await
            .unwrap_err(),
        FsError::NotPermitted
    );
}

#[tokio::test]
async fn durability_across_reopen() {
    let object_store = slatefs_core::store::resolve_root("memory:///").unwrap();
    let v = common::fresh_volume_on(Arc::clone(&object_store), None, None).await;
    let f = v
        .create(&root(), ROOT_INO, b"f", 0o644, true)
        .await
        .unwrap();
    v.write(&root(), f.ino, 0, b"persist me").await.unwrap();
    v.fsync(&root(), f.ino).await.unwrap();
    v.shutdown().await.unwrap();

    let v2 = common::reopen_volume(object_store).await;
    let attr = v2.lookup(&root(), ROOT_INO, b"f").await.unwrap();
    assert_eq!(
        &v2.read(&root(), attr.ino, 0, 10).await.unwrap()[..],
        b"persist me"
    );
    let report = v2.fsck().await.unwrap();
    assert!(report.is_clean(), "{:?}", report.problems);
}
