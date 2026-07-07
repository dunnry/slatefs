//! Model-based property tests for block volumes (docs/block-device-plan.md,
//! Phase B1): random byte-range operations run against both `BlockVolume` and
//! a plain in-memory byte vector. Results, including `FsError`, must match.
//!
//! Scale knobs: `PROPTEST_CASES` (proptest built-in) and
//! `SLATEFS_MODEL_OPS` (maximum operation-sequence length).

mod common;

use std::sync::Arc;

use bytes::Bytes;
use proptest::prelude::*;
use slatefs_core::block::{BlockDev, BlockVolume, SnapshotBlockVolume};
use slatefs_core::config::Compression;
use slatefs_core::control::{ControlPlane, QuotaLimits, VolumeRecord};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::vfs::FsError;
use slatefs_core::volume::{self, CreateBlockVolumeOptions};

const CHUNK: u64 = common::TEST_CHUNK as u64;
const DEVICE_SIZE: u64 = 1024 * 1024;
const MAX_OP_LEN: u32 = 64 * 1024;

#[derive(Debug, Clone)]
enum Op {
    Write { offset: u64, len: u32, seed: u64 },
    Read { offset: u64, len: u32 },
    Trim { offset: u64, len: u32 },
    WriteZeroes { offset: u64, len: u32 },
    Flush,
}

fn model_ops_limit() -> usize {
    std::env::var("SLATEFS_MODEL_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(120)
}

fn ops_range() -> std::ops::Range<usize> {
    1..model_ops_limit().saturating_add(1)
}

fn half_ops_range() -> std::ops::Range<usize> {
    1..(model_ops_limit() / 2).max(1).saturating_add(1)
}

fn valid_extent_strategy() -> BoxedStrategy<(u64, u32)> {
    let random = (0..DEVICE_SIZE, 0..=MAX_OP_LEN).prop_map(|(offset, len)| {
        let max_len = (DEVICE_SIZE - offset).min(u64::from(MAX_OP_LEN)) as u32;
        (offset, len.min(max_len))
    });
    let near_chunk_boundary =
        (0..(DEVICE_SIZE / CHUNK), 0..=MAX_OP_LEN, 0..33u64).prop_map(|(chunk, len, skew)| {
            let base = chunk * CHUNK;
            let skew = skew as i64 - 16;
            let offset = (base as i64 + skew).clamp(0, DEVICE_SIZE as i64) as u64;
            let max_len = (DEVICE_SIZE - offset).min(u64::from(MAX_OP_LEN)) as u32;
            (offset, len.min(max_len))
        });

    prop_oneof![
        12 => random,
        6 => near_chunk_boundary,
        1 => Just((0, DEVICE_SIZE as u32)),
        1 => Just((DEVICE_SIZE - CHUNK, CHUNK as u32)),
        1 => Just((DEVICE_SIZE, 0)),
    ]
    .boxed()
}

fn invalid_extent_strategy() -> BoxedStrategy<(u64, u32)> {
    let past_end = (DEVICE_SIZE + 1..=DEVICE_SIZE + CHUNK, 0..=MAX_OP_LEN)
        .prop_map(|(offset, len)| (offset, len));
    let crosses_end = (0..DEVICE_SIZE, 1..=MAX_OP_LEN).prop_map(|(offset, extra)| {
        let len = (DEVICE_SIZE - offset + u64::from(extra)).min(u64::from(u32::MAX)) as u32;
        (offset, len)
    });

    prop_oneof![
        4 => past_end,
        4 => crosses_end,
        1 => Just((DEVICE_SIZE, 1)),
        1 => Just((u64::MAX - 8, 16)),
    ]
    .boxed()
}

fn extent_strategy() -> BoxedStrategy<(u64, u32)> {
    prop_oneof![
        8 => valid_extent_strategy(),
        1 => invalid_extent_strategy(),
    ]
    .boxed()
}

fn op_strategy() -> BoxedStrategy<Op> {
    let extent = extent_strategy();
    prop_oneof![
        4 => (extent.clone(), any::<u64>()).prop_map(|((offset, len), seed)| {
            Op::Write { offset, len, seed }
        }),
        4 => extent.clone().prop_map(|(offset, len)| Op::Read { offset, len }),
        2 => extent.clone().prop_map(|(offset, len)| Op::Trim { offset, len }),
        2 => extent.prop_map(|(offset, len)| Op::WriteZeroes { offset, len }),
        1 => Just(Op::Flush),
    ]
    .boxed()
}

fn block_opts() -> CreateBlockVolumeOptions {
    CreateBlockVolumeOptions {
        cipher: Cipher::Aes256Gcm,
        chunk_size: common::TEST_CHUNK,
        compression: Compression::Lz4,
        quota: QuotaLimits::default(),
        note: None,
        size_bytes: DEVICE_SIZE,
    }
}

async fn fresh_block() -> (
    Arc<dyn ObjectStore>,
    VolumeRecord,
    Secret32,
    Arc<BlockVolume>,
) {
    let object_store = store::resolve_root("memory:///").expect("memory store");
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .expect("control plane");
    control.create_tenant("t", None).await.expect("tenant");
    let record =
        volume::create_block_volume(&control, Arc::clone(&object_store), "t", "b", block_opts())
            .await
            .expect("create block volume");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control plane");
    let block = BlockVolume::open(&record, dek.clone(), Arc::clone(&object_store))
        .await
        .expect("open block volume");
    (object_store, record, dek, block)
}

fn extent_is_valid(offset: u64, len: u32) -> bool {
    offset <= DEVICE_SIZE
        && offset
            .checked_add(u64::from(len))
            .is_some_and(|end| end <= DEVICE_SIZE)
}

fn data_bytes(seed: u64, offset: u64, len: u32) -> Vec<u8> {
    let mut x = seed ^ offset.rotate_left(17) ^ u64::from(len).rotate_left(33);
    let mut out = Vec::with_capacity(len as usize);
    for i in 0..len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let mixed = x
            .wrapping_mul(0x2545_F491_4F6C_DD1D)
            .wrapping_add(u64::from(i));
        out.push((mixed >> 32) as u8);
    }
    out
}

fn expect_unit(
    context: &str,
    real: Result<(), FsError>,
    expected: Result<(), FsError>,
) -> Result<(), String> {
    match (real, expected) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Err(me)) if e == me => Ok(()),
        (real, expected) => Err(format!("{context}: real {real:?} vs model {expected:?}")),
    }
}

fn apply_trim_model(model: &mut [u8], offset: u64, len: u32) {
    if len == 0 {
        return;
    }
    let end = offset + u64::from(len);
    model[offset as usize..end as usize].fill(0);
}

async fn run_op(block: &BlockVolume, model: &mut [u8], op: &Op) -> Result<(), String> {
    match *op {
        Op::Write { offset, len, seed } => {
            let data = data_bytes(seed, offset, len);
            let real = block.write(offset, Bytes::from(data.clone()), false).await;
            let expected = if extent_is_valid(offset, len) {
                Ok(())
            } else {
                Err(FsError::Invalid)
            };
            expect_unit(&format!("write {op:?}"), real, expected)?;
            if extent_is_valid(offset, len) {
                let end = offset as usize + len as usize;
                model[offset as usize..end].copy_from_slice(&data);
            }
        }
        Op::Read { offset, len } => {
            let real = block.read(offset, len).await;
            if extent_is_valid(offset, len) {
                let end = offset as usize + len as usize;
                let expected = &model[offset as usize..end];
                match real {
                    Ok(bytes) if bytes.as_ref() == expected => {}
                    Ok(bytes) => {
                        return Err(format!(
                            "read {op:?}: byte mismatch len={} expected_len={}",
                            bytes.len(),
                            expected.len()
                        ));
                    }
                    Err(e) => return Err(format!("read {op:?}: real Err({e:?}) vs model Ok")),
                }
            } else {
                match real {
                    Err(FsError::Invalid) => {}
                    other => return Err(format!("read {op:?}: real {other:?} vs model Invalid")),
                }
            }
        }
        Op::Trim { offset, len } => {
            let real = block.trim(offset, u64::from(len)).await;
            let expected = if extent_is_valid(offset, len) {
                Ok(())
            } else {
                Err(FsError::Invalid)
            };
            expect_unit(&format!("trim {op:?}"), real, expected)?;
            if extent_is_valid(offset, len) {
                apply_trim_model(model, offset, len);
            }
        }
        Op::WriteZeroes { offset, len } => {
            let real = block.write_zeroes(offset, u64::from(len), false).await;
            let expected = if extent_is_valid(offset, len) {
                Ok(())
            } else {
                Err(FsError::Invalid)
            };
            expect_unit(&format!("write_zeroes {op:?}"), real, expected)?;
            if extent_is_valid(offset, len) {
                let end = offset as usize + len as usize;
                model[offset as usize..end].fill(0);
            }
        }
        Op::Flush => {
            block
                .flush()
                .await
                .map_err(|e| format!("flush {op:?}: {e:?}"))?;
        }
    }
    Ok(())
}

async fn assert_device_matches(block: &BlockVolume, model: &[u8]) -> Result<(), String> {
    let bytes = block
        .read(0, DEVICE_SIZE as u32)
        .await
        .map_err(|e| format!("final read: {e:?}"))?;
    if bytes.as_ref() != model {
        return Err(format!(
            "final full-device read mismatch: real_len={} model_len={}",
            bytes.len(),
            model.len()
        ));
    }
    Ok(())
}

async fn assert_invariants(block: &BlockVolume) -> Result<(), String> {
    let report = block.fsck().await.map_err(|e| format!("fsck: {e}"))?;
    if !report.is_clean() {
        return Err(format!(
            "fsck dirty: problems={:?} counters real ({}, {}) recount ({}, {})",
            report.problems,
            report.counter_inodes,
            report.counter_bytes,
            report.inodes_counted,
            report.bytes_counted
        ));
    }
    let (tracked_bytes, tracked_inodes) = block.quota_usage();
    if tracked_bytes != report.counter_bytes || tracked_bytes != report.bytes_counted {
        return Err(format!(
            "quota bytes drift: tracker={tracked_bytes} counter={} recount={}",
            report.counter_bytes, report.bytes_counted
        ));
    }
    if tracked_inodes != report.counter_inodes || report.counter_inodes != 1 {
        return Err(format!(
            "quota inode drift: tracker={tracked_inodes} counter={} recount={}",
            report.counter_inodes, report.inodes_counted
        ));
    }
    Ok(())
}

async fn run_case(ops: Vec<Op>) -> Result<(), String> {
    let (_store, _record, _dek, block) = fresh_block().await;
    let mut model = vec![0u8; DEVICE_SIZE as usize];
    for (i, op) in ops.iter().enumerate() {
        run_op(&block, &mut model, op)
            .await
            .map_err(|e| format!("op {i}: {e}"))?;
    }
    assert_device_matches(&block, &model).await?;
    assert_invariants(&block).await?;
    block
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    Ok(())
}

async fn run_snapshot_case(pre: Vec<Op>, post: Vec<Op>) -> Result<(), String> {
    let (store, record, dek, block) = fresh_block().await;
    let mut model = vec![0u8; DEVICE_SIZE as usize];
    for (i, op) in pre.iter().enumerate() {
        run_op(&block, &mut model, op)
            .await
            .map_err(|e| format!("pre op {i}: {e}"))?;
    }

    block
        .flush()
        .await
        .map_err(|e| format!("flush before snapshot: {e:?}"))?;
    let frozen = model.clone();
    let snapshot = block
        .create_live_snapshot(Some("model-snapshot".to_string()))
        .await
        .map_err(|e| format!("create snapshot: {e}"))?;
    let snap = SnapshotBlockVolume::open(
        &record,
        dek.clone(),
        Arc::clone(&store),
        &snapshot.id,
        Vec::new(),
    )
    .await
    .map_err(|e| format!("open snapshot: {e}"))?;

    let forced_mutation = Op::Write {
        offset: CHUNK - 7,
        len: 96,
        seed: 0x51a7_e5f5_b10c_5eed,
    };
    run_op(&block, &mut model, &forced_mutation)
        .await
        .map_err(|e| format!("post forced mutation: {e}"))?;
    for (i, op) in post.iter().enumerate() {
        run_op(&block, &mut model, op)
            .await
            .map_err(|e| format!("post op {i}: {e}"))?;
    }

    let snap_bytes = snap
        .read(0, DEVICE_SIZE as u32)
        .await
        .map_err(|e| format!("snapshot read: {e:?}"))?;
    if snap_bytes.as_ref() != frozen.as_slice() {
        return Err(format!(
            "snapshot full-device read mismatch: snapshot_len={} frozen_len={}",
            snap_bytes.len(),
            frozen.len()
        ));
    }
    assert_device_matches(&block, &model).await?;
    assert_invariants(&block).await?;
    snap.shutdown()
        .await
        .map_err(|e| format!("snapshot shutdown: {e}"))?;
    block
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        max_shrink_iters: 2000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn block_volume_matches_reference_model(ops in proptest::collection::vec(op_strategy(), ops_range())) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        if let Err(e) = rt.block_on(run_case(ops)) {
            return Err(TestCaseError::fail(e));
        }
    }

    #[test]
    fn live_snapshot_reads_frozen_model(
        pre in proptest::collection::vec(op_strategy(), half_ops_range()),
        post in proptest::collection::vec(op_strategy(), half_ops_range()),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        if let Err(e) = rt.block_on(run_snapshot_case(pre, post)) {
            return Err(TestCaseError::fail(e));
        }
    }
}
