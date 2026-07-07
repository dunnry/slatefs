mod common;

use std::sync::Arc;

use bytes::Bytes;
use slatedb::Db;
use slatefs_core::block::{BLOCK_INO, BlockDev, BlockVolume, SnapshotBlockVolume};
use slatefs_core::config::Compression;
use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits, VolumeRecord};
use slatefs_core::crypto::Cipher;
use slatefs_core::crypto::Secret32;
use slatefs_core::meta::keys;
use slatefs_core::meta::superblock::VolumeKind;
use slatefs_core::quota::{billed_chunk_bytes, decode_counter};
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::vfs::FsError;
use slatefs_core::volume::{
    self, CreateBlockVolumeOptions, CreateVolumeOptions, Volume, VolumeCaches,
};

const CHUNK: u32 = common::TEST_CHUNK;

fn quota(bytes: Option<u64>) -> QuotaLimits {
    QuotaLimits {
        bytes: QuotaLimit {
            hard: bytes,
            ..Default::default()
        },
        inodes: QuotaLimit::default(),
    }
}

fn block_opts(size_bytes: u64, quota_bytes: Option<u64>) -> CreateBlockVolumeOptions {
    CreateBlockVolumeOptions {
        cipher: Cipher::Aes256Gcm,
        chunk_size: CHUNK,
        compression: Compression::Lz4,
        quota: quota(quota_bytes),
        note: None,
        size_bytes,
    }
}

async fn fresh_block(
    size_bytes: u64,
    quota_bytes: Option<u64>,
) -> (
    Arc<dyn ObjectStore>,
    VolumeRecord,
    Secret32,
    Arc<BlockVolume>,
) {
    let object_store = store::resolve_root("memory:///").expect("memory store");
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .expect("control");
    control.create_tenant("t", None).await.expect("tenant");
    let record = volume::create_block_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "b",
        block_opts(size_bytes, quota_bytes),
    )
    .await
    .expect("create block volume");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control");
    let block = BlockVolume::open(&record, dek.clone(), Arc::clone(&object_store))
        .await
        .expect("open block volume");
    (object_store, record, dek, block)
}

async fn recount_block(
    object_store: Arc<dyn ObjectStore>,
    record: &VolumeRecord,
    dek: Secret32,
) -> (i64, i64) {
    let VolumeKind::Block { size_bytes } = record.kind else {
        panic!("expected block volume");
    };
    let db = volume::open_volume_db(record, dek, object_store, &VolumeCaches::default())
        .await
        .expect("open db for recount");
    let counter = decode_counter(
        db.get(keys::KEY_QUOTA_BYTES)
            .await
            .expect("qB get")
            .as_deref(),
    );
    let counted = {
        let mut iter = db
            .scan(
                keys::chunk_prefix(BLOCK_INO).to_vec()..keys::chunk_prefix(BLOCK_INO + 1).to_vec(),
            )
            .await
            .expect("chunk scan");
        let mut counted = 0i64;
        while let Some(kv) = iter.next().await.expect("scan next") {
            let Some((ino, idx)) = keys::parse_chunk(&kv.key) else {
                break;
            };
            if ino != BLOCK_INO {
                break;
            }
            counted +=
                billed_chunk_bytes(size_bytes, idx as u64 * CHUNK as u64, kv.value.len()) as i64;
        }
        counted
    };
    db.close().await.expect("close recount db");
    (counter, counted)
}

async fn open_raw_block_db(
    object_store: Arc<dyn ObjectStore>,
    record: &VolumeRecord,
    dek: Secret32,
) -> Db {
    volume::open_volume_db(record, dek, object_store, &VolumeCaches::default())
        .await
        .expect("open raw block db")
}

#[tokio::test]
async fn block_fsck_clean_volume_passes() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
    block
        .write(17, Bytes::from_static(b"allocated"), false)
        .await
        .expect("write");

    let report = block.fsck().await.expect("block fsck");
    assert!(
        report.is_clean(),
        "unexpected fsck report: {:?}",
        report.problems
    );
    assert_eq!(report.inodes_counted, 1);
    assert_eq!(report.counter_inodes, 1);
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn block_fsck_rejects_stray_key() {
    let (store, record, dek, block) = fresh_block(CHUNK as u64, None).await;
    block.shutdown().await.expect("shutdown");

    let db = open_raw_block_db(Arc::clone(&store), &record, dek).await;
    db.put(keys::inode(99), Bytes::from_static(b"not allowed"))
        .await
        .expect("inject stray key");
    db.flush().await.expect("flush corruption");

    let report = slatefs_core::fsck::check_block(&db, CHUNK as u64, CHUNK as u64)
        .await
        .expect("fsck");
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("unexpected block-volume key")),
        "expected stray key problem, got {:?}",
        report.problems
    );
    db.close().await.expect("close db");
}

#[tokio::test]
async fn block_fsck_rejects_oversized_chunk_and_out_of_range_chunk() {
    let (store, record, dek, block) = fresh_block(CHUNK as u64, None).await;
    block.shutdown().await.expect("shutdown");

    let db = open_raw_block_db(Arc::clone(&store), &record, dek).await;
    db.put(
        keys::chunk(BLOCK_INO, 0),
        Bytes::from(vec![0x55; CHUNK as usize + 1]),
    )
    .await
    .expect("inject oversized chunk");
    db.put(
        keys::chunk(BLOCK_INO, 1),
        Bytes::from(vec![0xaa; CHUNK as usize]),
    )
    .await
    .expect("inject out-of-range chunk");
    db.flush().await.expect("flush corruption");

    let report = slatefs_core::fsck::check_block(&db, CHUNK as u64, CHUNK as u64)
        .await
        .expect("fsck");
    assert!(
        report.problems.iter().any(|p| p.contains("oversize")),
        "expected oversized chunk problem, got {:?}",
        report.problems
    );
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("beyond size_bytes")),
        "expected out-of-range chunk problem, got {:?}",
        report.problems
    );
    db.close().await.expect("close db");
}

#[tokio::test]
async fn block_fsck_detects_wrong_counters_and_recount_repairs() {
    let (store, record, dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
    block
        .write(0, Bytes::from(vec![7; CHUNK as usize]), false)
        .await
        .expect("write");
    block.shutdown().await.expect("shutdown");

    let db = open_raw_block_db(Arc::clone(&store), &record, dek).await;
    db.put(keys::KEY_QUOTA_BYTES, 123_i64.to_le_bytes())
        .await
        .expect("corrupt qB");
    db.put(keys::KEY_QUOTA_INODES, 2_i64.to_le_bytes())
        .await
        .expect("corrupt qI");
    db.flush().await.expect("flush counters");

    let report = slatefs_core::fsck::check_block(&db, CHUNK as u64 * 2, CHUNK as u64)
        .await
        .expect("fsck");
    assert!(report.problems.is_empty());
    assert!(!report.counters_match());
    assert_eq!(report.bytes_counted, CHUNK as i64);
    assert_eq!(report.inodes_counted, 1);

    let before = slatefs_core::fsck::recount_block(&db, CHUNK as u64 * 2, CHUNK as u64)
        .await
        .expect("recount");
    assert!(!before.counters_match());
    let after = slatefs_core::fsck::check_block(&db, CHUNK as u64 * 2, CHUNK as u64)
        .await
        .expect("fsck after recount");
    assert!(after.is_clean(), "after recount: {:?}", after);
    db.close().await.expect("close db");
}

#[tokio::test]
async fn resize_block_volume_grows_persists_and_rejects_bad_sizes() {
    let (store, _record, _dek, block) = fresh_block(CHUNK as u64, None).await;
    block.shutdown().await.expect("shutdown");
    let control = ControlPlane::open(Arc::clone(&store), common::test_kms())
        .await
        .expect("control");

    let grown =
        volume::resize_block_volume(&control, Arc::clone(&store), "t", "b", CHUNK as u64 * 3)
            .await
            .expect("resize grow");
    assert!(matches!(
        grown.kind,
        VolumeKind::Block { size_bytes } if size_bytes == CHUNK as u64 * 3
    ));
    let info = volume::volume_info(&control, Arc::clone(&store), "t", "b")
        .await
        .expect("info after resize");
    assert!(matches!(
        info.superblock.kind,
        VolumeKind::Block { size_bytes } if size_bytes == CHUNK as u64 * 3
    ));
    let dek = control.unwrap_volume_dek(&grown).await.expect("dek");
    let reopened = BlockVolume::open(&grown, dek, Arc::clone(&store))
        .await
        .expect("open resized block");
    assert_eq!(reopened.geometry().size_bytes, CHUNK as u64 * 3);
    reopened.shutdown().await.expect("shutdown reopened");

    assert!(
        volume::resize_block_volume(&control, Arc::clone(&store), "t", "b", CHUNK as u64)
            .await
            .is_err(),
        "shrink must be rejected"
    );
    assert!(
        volume::resize_block_volume(&control, Arc::clone(&store), "t", "b", CHUNK as u64 * 4 + 1)
            .await
            .is_err(),
        "misaligned size must be rejected"
    );
    control.close().await.expect("close control");
}

#[tokio::test]
async fn snapshot_helpers_and_clone_preserve_block_kind() {
    let object_store = store::resolve_root("memory:///").expect("memory store");
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .expect("control");
    control.create_tenant("t", None).await.expect("tenant");
    let record = volume::create_block_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "src",
        block_opts(CHUNK as u64 * 2, None),
    )
    .await
    .expect("create block source");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    let block = BlockVolume::open(&record, dek, Arc::clone(&object_store))
        .await
        .expect("open block");
    block
        .write(0, Bytes::from_static(b"snapshot-data"), false)
        .await
        .expect("write source");
    block.flush().await.expect("flush source");
    block.shutdown().await.expect("shutdown source");

    let snapshot = volume::create_snapshot(
        &control,
        Arc::clone(&object_store),
        "t",
        "src",
        Some("snap".to_string()),
    )
    .await
    .expect("create snapshot");
    let snapshots = volume::list_snapshots(&control, Arc::clone(&object_store), "t", "src", None)
        .await
        .expect("list snapshots");
    assert!(snapshots.iter().any(|s| s.id == snapshot.id));

    let clone = volume::clone_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "src",
        "clone",
        volume::CloneVolumeOptions {
            source_snapshot_id: Some(snapshot.id.clone()),
            note: None,
        },
    )
    .await
    .expect("clone block snapshot");
    assert_eq!(clone.kind, record.kind);
    let clone_info = volume::volume_info(&control, Arc::clone(&object_store), "t", "clone")
        .await
        .expect("clone info");
    assert_eq!(clone_info.superblock.kind, record.kind);

    volume::delete_snapshot(
        &control,
        Arc::clone(&object_store),
        "t",
        "src",
        &snapshot.id,
    )
    .await
    .expect("delete snapshot");
    let snapshots = volume::list_snapshots(&control, Arc::clone(&object_store), "t", "src", None)
        .await
        .expect("list after delete");
    assert!(!snapshots.iter().any(|s| s.id == snapshot.id));
    control.close().await.expect("close control");
}

#[tokio::test]
async fn write_read_round_trip_unaligned_spanning_chunks() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 4, None).await;
    let offset = CHUNK as u64 - 17;
    let data: Vec<u8> = (0..80).map(|i| (i * 3) as u8).collect();

    block
        .write(offset, Bytes::from(data.clone()), false)
        .await
        .expect("write");

    assert_eq!(block.read(offset, data.len() as u32).await.unwrap(), data);
    let around = block
        .read(offset - 4, (data.len() + 8) as u32)
        .await
        .unwrap();
    assert_eq!(&around[..4], &[0, 0, 0, 0]);
    assert_eq!(&around[4..4 + data.len()], data.as_slice());
    assert_eq!(&around[4 + data.len()..], &[0, 0, 0, 0]);
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn holes_read_as_zeroes() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
    let bytes = block.read(123, 900).await.expect("hole read");
    assert_eq!(bytes.len(), 900);
    assert!(bytes.iter().all(|b| *b == 0));
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn out_of_bounds_extents_are_rejected() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64, None).await;
    let size = CHUNK as u64;

    assert_eq!(block.read(size - 1, 2).await.unwrap_err(), FsError::Invalid);
    assert_eq!(
        block
            .write(size, Bytes::from_static(b"x"), false)
            .await
            .unwrap_err(),
        FsError::Invalid
    );
    assert_eq!(block.trim(size - 1, 2).await.unwrap_err(), FsError::Invalid);
    assert_eq!(
        block.write_zeroes(size - 1, 2, false).await.unwrap_err(),
        FsError::Invalid
    );
    assert_eq!(block.read(size + 1, 0).await.unwrap_err(), FsError::Invalid);
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn trim_zeroes_partial_edges_and_deletes_full_chunks() {
    let (store, record, dek, block) = fresh_block(CHUNK as u64 * 4, None).await;
    let data = vec![0x5a; CHUNK as usize * 3];
    block
        .write(0, Bytes::from(data), false)
        .await
        .expect("write chunks");
    assert_eq!(block.quota_usage().0, CHUNK as i64 * 3);

    block.trim(1, CHUNK as u64 - 1).await.expect("partial trim");
    assert_eq!(block.quota_usage().0, CHUNK as i64 * 2 + 1);
    let partial = block.read(0, CHUNK).await.expect("read partial trim");
    assert_eq!(partial[0], 0x5a);
    assert!(partial[1..].iter().all(|b| *b == 0));

    block
        .trim(CHUNK as u64, CHUNK as u64)
        .await
        .expect("trim full chunk");
    assert_eq!(block.quota_usage().0, CHUNK as i64 + 1);
    let hole = block.read(CHUNK as u64, CHUNK).await.expect("read hole");
    assert!(hole.iter().all(|b| *b == 0));

    block.shutdown().await.expect("shutdown");
    let (counter, counted) = recount_block(store, &record, dek).await;
    assert_eq!(counter, CHUNK as i64 + 1);
    assert_eq!(counted, counter);
}

#[tokio::test]
async fn write_zeroes_is_exact_at_partial_edges() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
    let data = vec![0x7f; CHUNK as usize * 2];
    block
        .write(0, Bytes::from(data), false)
        .await
        .expect("write");

    let offset = CHUNK as u64 - 10;
    block
        .write_zeroes(offset, 20, false)
        .await
        .expect("write zeroes");

    let read = block.read(0, CHUNK * 2).await.expect("read");
    assert!(read[..CHUNK as usize - 10].iter().all(|b| *b == 0x7f));
    assert!(
        read[CHUNK as usize - 10..CHUNK as usize + 10]
            .iter()
            .all(|b| *b == 0)
    );
    assert!(read[CHUNK as usize + 10..].iter().all(|b| *b == 0x7f));
    assert_eq!(block.quota_usage().0, CHUNK as i64 * 2 - 10);
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn fua_write_and_write_zeroes_flush_paths_succeed() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
    block
        .write(7, Bytes::from_static(b"fua-data"), true)
        .await
        .expect("fua write");
    assert_eq!(
        block.read(7, 8).await.unwrap(),
        Bytes::from_static(b"fua-data")
    );
    block
        .write_zeroes(9, 3, true)
        .await
        .expect("fua write zeroes");
    assert_eq!(
        block.read(7, 8).await.unwrap(),
        Bytes::from_static(b"fu\0\0\0ata")
    );
    block.flush().await.expect("flush");
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn quota_exceeded_leaves_usage_unchanged() {
    let (_store, _record, _dek, block) = fresh_block(CHUNK as u64 * 2, Some(CHUNK as u64)).await;
    block
        .write(0, Bytes::from(vec![1; CHUNK as usize]), false)
        .await
        .expect("first chunk");
    assert_eq!(block.quota_usage().0, CHUNK as i64);

    assert_eq!(
        block
            .write(CHUNK as u64, Bytes::from(vec![2; CHUNK as usize]), false,)
            .await
            .unwrap_err(),
        FsError::QuotaExceeded
    );
    assert_eq!(block.quota_usage().0, CHUNK as i64);
    let second = block.read(CHUNK as u64, CHUNK).await.expect("read second");
    assert!(second.iter().all(|b| *b == 0));
    block.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn kind_mismatch_open_fails() {
    let object_store = store::resolve_root("memory:///").expect("memory store");
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .expect("control");
    control.create_tenant("t", None).await.expect("tenant");

    let fs_record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "fs",
        CreateVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: CHUNK,
            compression: Compression::Lz4,
            quota: quota(None),
            note: None,
        },
    )
    .await
    .expect("create fs");
    let fs_dek = control.unwrap_volume_dek(&fs_record).await.expect("fs dek");
    assert!(
        BlockVolume::open(&fs_record, fs_dek, Arc::clone(&object_store))
            .await
            .is_err()
    );

    let block_record = volume::create_block_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "blk",
        block_opts(CHUNK as u64, None),
    )
    .await
    .expect("create block");
    assert!(matches!(
        block_record.kind,
        VolumeKind::Block { size_bytes } if size_bytes == CHUNK as u64
    ));
    let block_dek = control
        .unwrap_volume_dek(&block_record)
        .await
        .expect("block dek");
    assert!(
        Volume::open(&block_record, block_dek, Arc::clone(&object_store))
            .await
            .is_err()
    );
    control.close().await.expect("close control");
}

#[tokio::test]
async fn snapshot_block_volume_is_frozen_and_read_only() {
    let (store, record, dek, block) = fresh_block(CHUNK as u64 * 2, None).await;
    block
        .write(0, Bytes::from_static(b"before"), false)
        .await
        .expect("write before");
    block.flush().await.expect("flush before snapshot");
    let snapshot = block
        .create_live_snapshot(Some("snap".to_string()))
        .await
        .expect("snapshot");

    let snap = SnapshotBlockVolume::open(
        &record,
        dek.clone(),
        Arc::clone(&store),
        &snapshot.id,
        Vec::new(),
    )
    .await
    .expect("open snapshot block");

    block
        .write(0, Bytes::from_static(b"after!"), false)
        .await
        .expect("write after");
    assert_eq!(
        snap.read(0, 6).await.expect("snapshot read"),
        Bytes::from_static(b"before")
    );
    assert_eq!(
        block.read(0, 6).await.expect("live read"),
        Bytes::from_static(b"after!")
    );
    assert_eq!(
        snap.write(0, Bytes::from_static(b"nope"), false)
            .await
            .unwrap_err(),
        FsError::ReadOnly
    );

    snap.shutdown().await.expect("shutdown snapshot");
    block.shutdown().await.expect("shutdown block");
}
