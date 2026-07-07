//! Crash-consistency loop for block volumes (docs/block-device-plan.md,
//! Phase B1). A child process mutates a file://-backed block volume, persists
//! the last completed-flush digest state outside the volume, then aborts.
//! The parent reopens the volume, requires clean fsck, and verifies every
//! chunk not dirtied after the last flush still matches that digest.
//!
//! Scale knob: `SLATEFS_CRASH_ITERS`.

mod common;

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use slatefs_core::block::{BlockDev, BlockVolume};
use slatefs_core::config::Compression;
use slatefs_core::control::{ControlPlane, QuotaLimits};
use slatefs_core::crypto::Cipher;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::volume::{self, CreateBlockVolumeOptions};

const CHUNK: usize = common::TEST_CHUNK as usize;
const CHUNK_U64: u64 = common::TEST_CHUNK as u64;
const DEVICE_SIZE: usize = 1024 * 1024;
const DEVICE_SIZE_U64: u64 = DEVICE_SIZE as u64;
const CHUNKS: usize = DEVICE_SIZE / CHUNK;
const MAGIC: &[u8; 8] = b"SFSBCR1\0";

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next() % n
    }
}

#[derive(Clone)]
struct DurableState {
    generation: u64,
    clean: Vec<bool>,
    digests: Vec<[u8; 32]>,
}

impl DurableState {
    fn from_image(generation: u64, image: &[u8]) -> DurableState {
        DurableState {
            generation,
            clean: vec![true; CHUNKS],
            digests: chunk_digests(image),
        }
    }
}

fn block_opts() -> CreateBlockVolumeOptions {
    CreateBlockVolumeOptions {
        cipher: Cipher::Aes256Gcm,
        chunk_size: common::TEST_CHUNK,
        compression: Compression::Lz4,
        quota: QuotaLimits::default(),
        note: None,
        size_bytes: DEVICE_SIZE_U64,
    }
}

async fn fresh_block_on(object_store: Arc<dyn ObjectStore>) -> Arc<BlockVolume> {
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
    BlockVolume::open(&record, dek, object_store)
        .await
        .expect("open block volume")
}

async fn reopen_block(object_store: Arc<dyn ObjectStore>) -> Arc<BlockVolume> {
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .expect("control plane");
    let record = control.get_volume("t", "b").await.expect("volume record");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control plane");
    BlockVolume::open(&record, dek, object_store)
        .await
        .expect("reopen block volume")
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn chunk_digests(image: &[u8]) -> Vec<[u8; 32]> {
    (0..CHUNKS)
        .map(|idx| {
            let start = idx * CHUNK;
            let end = (start + CHUNK).min(image.len());
            digest(&image[start..end])
        })
        .collect()
}

fn encode_state(state: &DurableState) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + state.clean.len() + state.digests.len() * 32);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&DEVICE_SIZE_U64.to_le_bytes());
    out.extend_from_slice(&(common::TEST_CHUNK).to_le_bytes());
    out.extend_from_slice(&state.generation.to_le_bytes());
    out.extend_from_slice(&(state.clean.len() as u32).to_le_bytes());
    out.extend_from_slice(&(state.digests.len() as u32).to_le_bytes());
    for clean in &state.clean {
        out.push(u8::from(*clean));
    }
    for digest in &state.digests {
        out.extend_from_slice(digest);
    }
    out
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u32(data: &[u8], pos: &mut usize) -> io::Result<u32> {
    if data.len().saturating_sub(*pos) < 4 {
        return Err(invalid_data("short u32"));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], pos: &mut usize) -> io::Result<u64> {
    if data.len().saturating_sub(*pos) < 8 {
        return Err(invalid_data("short u64"));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn decode_state(data: &[u8]) -> io::Result<DurableState> {
    if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        return Err(invalid_data("bad magic"));
    }
    let mut pos = MAGIC.len();
    let version = read_u32(data, &mut pos)?;
    let size = read_u64(data, &mut pos)?;
    let chunk_size = read_u32(data, &mut pos)?;
    let generation = read_u64(data, &mut pos)?;
    let clean_len = read_u32(data, &mut pos)? as usize;
    let digest_len = read_u32(data, &mut pos)? as usize;
    if version != 1
        || size != DEVICE_SIZE_U64
        || chunk_size != common::TEST_CHUNK
        || clean_len != CHUNKS
        || digest_len != CHUNKS
    {
        return Err(invalid_data("state header mismatch"));
    }
    if data.len().saturating_sub(pos) < clean_len + digest_len * 32 {
        return Err(invalid_data("short state body"));
    }
    let clean = data[pos..pos + clean_len].iter().map(|b| *b != 0).collect();
    pos += clean_len;
    let mut digests = Vec::with_capacity(digest_len);
    for _ in 0..digest_len {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        digests.push(digest);
    }
    Ok(DurableState {
        generation,
        clean,
        digests,
    })
}

fn persist_state(path: &Path, state: &DurableState) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&encode_state(state))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    let file = File::open(path)?;
    file.sync_all()?;
    Ok(())
}

fn read_state(path: &Path) -> io::Result<DurableState> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    decode_state(&data)
}

fn pending_path(path: &Path) -> PathBuf {
    path.with_extension("pending")
}

fn random_extent(rng: &mut Rng) -> (u64, usize) {
    let offset = match rng.below(10) {
        0 => 0,
        1 => DEVICE_SIZE_U64.saturating_sub(rng.below(CHUNK_U64)),
        2 | 3 => {
            let base = rng.below(CHUNKS as u64) * CHUNK_U64;
            let skew = rng.below(33) as i64 - 16;
            (base as i64 + skew).clamp(0, DEVICE_SIZE_U64 as i64) as u64
        }
        _ => rng.below(DEVICE_SIZE_U64 + 1),
    };
    if offset == DEVICE_SIZE_U64 || rng.below(32) == 0 {
        return (offset, 0);
    }

    let remaining = DEVICE_SIZE_U64 - offset;
    let cap = match rng.below(8) {
        0 => DEVICE_SIZE_U64,
        1 | 2 => 4 * CHUNK_U64,
        _ => 2 * CHUNK_U64,
    };
    let len = 1 + rng.below(remaining.min(cap));
    (offset, len as usize)
}

fn mark_dirty_range(state: &mut DurableState, offset: u64, len: usize) {
    if len == 0 {
        return;
    }
    let end = offset + len as u64;
    let first = (offset / CHUNK_U64) as usize;
    let last = ((end - 1) / CHUNK_U64) as usize;
    for clean in &mut state.clean[first..=last] {
        *clean = false;
    }
}

fn mark_dirty_trim(state: &mut DurableState, offset: u64, len: usize) {
    mark_dirty_range(state, offset, len);
}

fn apply_trim_image(image: &mut [u8], offset: u64, len: usize) {
    if len == 0 {
        return;
    }
    let end = offset + len as u64;
    image[offset as usize..end as usize].fill(0);
}

async fn read_device(block: &BlockVolume) -> Vec<u8> {
    block
        .read(0, DEVICE_SIZE as u32)
        .await
        .expect("read full block device")
        .to_vec()
}

async fn completed_flush(
    block: &BlockVolume,
    image: &[u8],
    state: &mut DurableState,
    state_path: &Path,
) {
    let pending = DurableState::from_image(state.generation + 1, image);
    persist_state(&pending_path(state_path), &pending).expect("persist pending flush digest");
    block.flush().await.expect("block flush");
    *state = pending;
    persist_state(state_path, state).expect("persist completed flush digest");
}

async fn churn(block: &BlockVolume, state_path: &Path, rng: &mut Rng, ops: u64) {
    let mut image = read_device(block).await;
    let mut state = DurableState::from_image(0, &image);
    completed_flush(block, &image, &mut state, state_path).await;

    for _ in 0..ops {
        match rng.below(3) {
            0 => {
                let (offset, len) = random_extent(rng);
                let mut data = vec![0u8; len];
                for byte in &mut data {
                    *byte = (rng.next() >> 24) as u8;
                }
                mark_dirty_range(&mut state, offset, len);
                persist_state(state_path, &state).expect("persist dirty write map");
                block
                    .write(offset, Bytes::from(data.clone()), false)
                    .await
                    .expect("write");
                let end = offset as usize + len;
                image[offset as usize..end].copy_from_slice(&data);
            }
            1 => {
                let (offset, len) = random_extent(rng);
                mark_dirty_trim(&mut state, offset, len);
                persist_state(state_path, &state).expect("persist dirty trim map");
                block.trim(offset, len as u64).await.expect("trim");
                apply_trim_image(&mut image, offset, len);
            }
            2 => {
                let (offset, len) = random_extent(rng);
                mark_dirty_range(&mut state, offset, len);
                persist_state(state_path, &state).expect("persist dirty zero map");
                block
                    .write_zeroes(offset, len as u64, false)
                    .await
                    .expect("write zeroes");
                let end = offset as usize + len;
                image[offset as usize..end].fill(0);
            }
            _ => unreachable!(),
        }

        if rng.below(16) == 0 {
            completed_flush(block, &image, &mut state, state_path).await;
        }
    }
}

async fn verify_durable_chunks(block: &BlockVolume, state_path: &Path, iteration: u64) {
    let state = read_state(state_path).expect("read durability state");
    for idx in 0..CHUNKS {
        if !state.clean[idx] {
            continue;
        }
        let offset = (idx * CHUNK) as u64;
        let len = ((idx + 1) * CHUNK).min(DEVICE_SIZE) - idx * CHUNK;
        let bytes = block
            .read(offset, len as u32)
            .await
            .expect("read durable chunk");
        let actual = digest(bytes.as_ref());
        assert_eq!(
            actual, state.digests[idx],
            "iteration {iteration}: clean flushed chunk {idx} changed after crash"
        );
    }
}

#[tokio::test]
#[ignore = "spawned by block_crash_consistency_loop"]
async fn block_crash_child() {
    let Ok(url) = std::env::var("SLATEFS_BLOCK_CRASH_URL") else {
        return;
    };
    let state_path = PathBuf::from(
        std::env::var("SLATEFS_BLOCK_CRASH_STATE").expect("SLATEFS_BLOCK_CRASH_STATE"),
    );
    let seed: u64 = std::env::var("SLATEFS_BLOCK_CRASH_SEED")
        .expect("SLATEFS_BLOCK_CRASH_SEED")
        .parse()
        .expect("seed");
    let abort_after: u64 = std::env::var("SLATEFS_BLOCK_CRASH_ABORT_AFTER")
        .expect("SLATEFS_BLOCK_CRASH_ABORT_AFTER")
        .parse()
        .expect("abort_after");

    let object_store = store::resolve_root(&url).expect("store");
    let block = reopen_block(object_store).await;
    let mut rng = Rng(seed | 1);
    churn(&block, &state_path, &mut rng, abort_after).await;
    std::process::abort();
}

#[tokio::test]
async fn block_crash_consistency_loop() {
    let iters: u64 = std::env::var("SLATEFS_CRASH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("store");
    fs::create_dir(&store_dir).expect("store dir");
    let url = format!("file://{}", store_dir.display());
    let state_path = dir.path().join("block-durability.bin");
    let object_store = store::resolve_root(&url).expect("store");

    let block = fresh_block_on(Arc::clone(&object_store)).await;
    block.shutdown().await.expect("shutdown after setup");

    let exe = std::env::current_exe().expect("current_exe");
    for i in 0..iters {
        let abort_after = 5 + (i * 13) % 60;
        let status = Command::new(&exe)
            .args([
                "block_crash_child",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("SLATEFS_BLOCK_CRASH_URL", &url)
            .env("SLATEFS_BLOCK_CRASH_STATE", &state_path)
            .env("SLATEFS_BLOCK_CRASH_SEED", i.to_string())
            .env("SLATEFS_BLOCK_CRASH_ABORT_AFTER", abort_after.to_string())
            .status()
            .expect("spawn block crash child");
        assert!(
            !status.success(),
            "iteration {i}: child was supposed to abort, exited cleanly"
        );

        let block = reopen_block(Arc::clone(&object_store)).await;
        let report = block.fsck().await.expect("block fsck");
        assert!(
            report.is_clean(),
            "iteration {i} (abort after {abort_after} ops): fsck dirty:\n  problems: {:?}\n  counters: real ({}, {}) vs recount ({}, {})",
            report.problems,
            report.counter_inodes,
            report.counter_bytes,
            report.inodes_counted,
            report.bytes_counted,
        );
        verify_durable_chunks(&block, &state_path, i).await;
        block.shutdown().await.expect("shutdown");
    }
}
