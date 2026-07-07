//! Block-volume core (BD-1..BD-5, BD-7, BD-9). A block volume is one sparse
//! byte range backed by the existing chunk keyspace at `c/<BLOCK_INO>/<idx>`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use slatedb::config::{CheckpointOptions, CheckpointScope, WriteOptions};
use slatedb::object_store::ObjectStore;
use slatedb::{Db, DbReader, WriteBatch};

use crate::control::{VolumeRecord, VolumeState};
use crate::crypto::Secret32;
use crate::crypto::transformer::SlateBlockTransformer;
use crate::data;
use crate::error::{Error, Result, is_fenced_slatedb_error};
use crate::locks::LockManager;
use crate::meta::keys;
use crate::meta::superblock::{KEY_SUPERBLOCK, Superblock, VolumeKind};
use crate::quota::{self, CounterMergeOperator, QuotaTracker, billed_chunk_bytes};
use crate::store;
use crate::vfs::{FsError, FsResult};
use crate::volume::{
    CreatedSnapshot, VolumeCaches, open_volume_db, validate_block_size,
    verify_superblock_matches_record,
};

pub const BLOCK_INO: u64 = 0;
pub const MIN_BLOCK_SIZE: u32 = 512;
pub const MAX_PAYLOAD: u32 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockGeometry {
    pub size_bytes: u64,
    pub min_block: u32,
    pub preferred_block: u32,
    pub max_payload: u32,
    pub read_only: bool,
}

#[async_trait]
pub trait BlockDev: Send + Sync {
    fn geometry(&self) -> BlockGeometry;
    async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes>;
    async fn write(&self, offset: u64, data: Bytes, fua: bool) -> FsResult<()>;
    async fn flush(&self) -> FsResult<()>;
    async fn trim(&self, offset: u64, len: u64) -> FsResult<()>;
    async fn write_zeroes(&self, offset: u64, len: u64, fua: bool) -> FsResult<()>;
}

pub struct BlockVolume {
    db: Db,
    geometry: BlockGeometry,
    locks: LockManager,
    quota: QuotaTracker,
    dead: AtomicBool,
    fencing_events: AtomicU64,
    degraded: AtomicBool,
    storage_errors: AtomicU64,
    dead_notify: tokio::sync::Notify,
}

impl BlockVolume {
    pub async fn open(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
    ) -> Result<Arc<BlockVolume>> {
        Self::open_with_caches(record, dek, object_store, &VolumeCaches::default()).await
    }

    pub async fn open_with_caches(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
        caches: &VolumeCaches,
    ) -> Result<Arc<BlockVolume>> {
        if record.state != VolumeState::Active {
            return Err(Error::invalid(
                "volume state",
                format!("{:?}, not Active", record.state),
            ));
        }
        let db = open_volume_db(record, dek, object_store, caches).await?;
        let result = async {
            let bytes = db
                .get(KEY_SUPERBLOCK)
                .await?
                .ok_or_else(|| Error::invalid("volume", "no superblock (mkfs incomplete?)"))?;
            let superblock = Superblock::decode(&bytes)?;
            verify_superblock_matches_record(record, &superblock, "superblock")?;
            let VolumeKind::Block { size_bytes } = superblock.kind else {
                return Err(Error::invalid(
                    "volume kind",
                    "filesystem volume cannot be opened as a block volume",
                ));
            };
            validate_block_size(size_bytes, superblock.chunk_size)?;
            let bytes_used = quota::decode_counter(db.get(keys::KEY_QUOTA_BYTES).await?.as_deref());
            let inodes_used =
                quota::decode_counter(db.get(keys::KEY_QUOTA_INODES).await?.as_deref());
            Ok((superblock, size_bytes, bytes_used, inodes_used))
        }
        .await;

        let (superblock, size_bytes, bytes_used, inodes_used) = match result {
            Ok(values) => values,
            Err(error) => {
                db.close().await?;
                return Err(error);
            }
        };
        Ok(Arc::new(BlockVolume {
            db,
            geometry: BlockGeometry {
                size_bytes,
                min_block: MIN_BLOCK_SIZE,
                preferred_block: superblock.chunk_size,
                max_payload: MAX_PAYLOAD,
                read_only: false,
            },
            locks: LockManager::default(),
            quota: QuotaTracker::new(bytes_used, inodes_used, record.quota),
            dead: AtomicBool::new(false),
            fencing_events: AtomicU64::new(0),
            degraded: AtomicBool::new(false),
            storage_errors: AtomicU64::new(0),
            dead_notify: tokio::sync::Notify::new(),
        }))
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    pub fn writer_fencing_events(&self) -> u64 {
        self.fencing_events.load(Ordering::Relaxed)
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub fn storage_errors(&self) -> u64 {
        self.storage_errors.load(Ordering::Relaxed)
    }

    pub fn quota_usage(&self) -> (i64, i64) {
        self.quota.usage()
    }

    pub fn quota_hard_limits(&self) -> (Option<u64>, Option<u64>) {
        self.quota.hard_limits()
    }

    pub fn set_quota_limits(&self, limits: crate::control::QuotaLimits) -> bool {
        self.quota.set_limits(limits)
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.db.close().await.map_err(|error| {
            self.note_storage_error(&error);
            Error::from(error)
        })
    }

    pub async fn fsck(&self) -> Result<crate::fsck::FsckReport> {
        crate::fsck::check_block(&self.db, self.geometry.size_bytes, self.chunk_size()).await
    }

    pub async fn fsck_recount(&self) -> Result<crate::fsck::FsckReport> {
        crate::fsck::recount_block(&self.db, self.geometry.size_bytes, self.chunk_size()).await
    }

    pub async fn create_live_snapshot(&self, name: Option<String>) -> Result<CreatedSnapshot> {
        let created = self
            .db
            .create_checkpoint(
                CheckpointScope::All,
                &CheckpointOptions {
                    name: name.clone(),
                    ..CheckpointOptions::default()
                },
            )
            .await?;
        Ok(CreatedSnapshot {
            id: created.id.to_string(),
            manifest_id: created.manifest_id,
            name,
        })
    }

    fn chunk_size(&self) -> u64 {
        self.geometry.preferred_block as u64
    }

    fn chunk_bounds(&self, idx: u32) -> (u64, u64) {
        let start = idx as u64 * self.chunk_size();
        let end = (start + self.chunk_size()).min(self.geometry.size_bytes);
        (start, end)
    }

    fn chunk_fully_covered(&self, idx: u32, offset: u64, end: u64) -> bool {
        let (chunk_start, chunk_end) = self.chunk_bounds(idx);
        offset <= chunk_start && chunk_end <= end
    }

    fn extent_end(&self, offset: u64, len: u64) -> FsResult<u64> {
        let end = offset.checked_add(len).ok_or(FsError::Invalid)?;
        if offset > self.geometry.size_bytes || end > self.geometry.size_bytes {
            return Err(FsError::Invalid);
        }
        Ok(end)
    }

    fn chunk_range(&self, offset: u64, len: u64) -> FsResult<Option<(u32, u32)>> {
        let end = self.extent_end(offset, len)?;
        if len == 0 {
            return Ok(None);
        }
        Ok(Some((
            data::chunk_of(offset, self.chunk_size()),
            data::chunk_of(end - 1, self.chunk_size()),
        )))
    }

    async fn commit(&self, batch: WriteBatch, billed_delta: i64, fua: bool) -> FsResult<()> {
        self.ensure_live()?;
        self.quota.reserve(billed_delta, 0)?;
        let opts = WriteOptions {
            await_durable: false,
            ..WriteOptions::default()
        };
        if let Err(error) = self.db.write_with_options(batch, &opts).await {
            self.quota.release(billed_delta, 0);
            self.note_storage_error(&error);
            return Err(FsError::from(error));
        }
        if fua {
            self.map_storage(self.db.flush().await)?;
        }
        Ok(())
    }

    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn ensure_live(&self) -> FsResult<()> {
        if self.is_dead() {
            Err(FsError::Io)
        } else {
            Ok(())
        }
    }

    fn mark_fenced(&self) {
        if !self.dead.swap(true, Ordering::AcqRel) {
            self.fencing_events.fetch_add(1, Ordering::Relaxed);
            tracing::error!("block volume fenced by newer SlateDB writer; marking export dead");
            self.dead_notify.notify_waiters();
        }
    }

    fn mark_degraded(&self, error: &str) {
        let errors = self.storage_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.degraded.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                storage_errors = errors,
                error,
                "block volume degraded after storage error"
            );
        } else {
            tracing::debug!(
                storage_errors = errors,
                error,
                "block volume storage error while degraded"
            );
        }
    }

    pub async fn wait_dead(&self) {
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
        while !self.is_dead() {
            tokio::select! {
                _ = self.dead_notify.notified() => {}
                _ = tick.tick() => {}
            }
        }
    }

    fn note_storage_error(&self, error: &slatedb::Error) {
        if is_fenced_slatedb_error(error) {
            self.mark_fenced();
        } else {
            self.mark_degraded(&error.to_string());
        }
    }

    fn note_core_error(&self, error: &Error) {
        match error {
            Error::SlateDb(error) => self.note_storage_error(error),
            Error::ObjectStore(_) | Error::Crypto(_) | Error::Codec(_) | Error::Io(_) => {
                self.mark_degraded(&error.to_string());
            }
            Error::NotFound { .. }
            | Error::AlreadyExists { .. }
            | Error::Invalid { .. }
            | Error::Config(_) => {}
        }
    }

    fn map_storage<T>(&self, result: std::result::Result<T, slatedb::Error>) -> FsResult<T> {
        if self.is_dead() {
            return Err(FsError::Io);
        }
        match result {
            Ok(value) => {
                self.ensure_live()?;
                Ok(value)
            }
            Err(error) => {
                self.note_storage_error(&error);
                Err(FsError::from(error))
            }
        }
    }

    fn map_core<T>(&self, result: Result<T>) -> FsResult<T> {
        if self.is_dead() {
            return Err(FsError::Io);
        }
        match result {
            Ok(value) => {
                self.ensure_live()?;
                Ok(value)
            }
            Err(error) => {
                self.note_core_error(&error);
                Err(FsError::from(error))
            }
        }
    }

    async fn stage_zeroes_for_existing_chunk(
        &self,
        batch: &mut WriteBatch,
        idx: u32,
        zero_from: u64,
        zero_to: u64,
    ) -> FsResult<Option<i64>> {
        let (chunk_start, chunk_end) = self.chunk_bounds(idx);
        let key = keys::chunk(BLOCK_INO, idx);
        let Some(existing) = self.map_storage(self.db.get(key).await)? else {
            return Ok(None);
        };
        let old_billed = billed_chunk_bytes(self.geometry.size_bytes, chunk_start, existing.len());
        if zero_from <= chunk_start && chunk_end <= zero_to {
            batch.delete(key);
            return Ok(Some(-(old_billed as i64)));
        }

        let from = (zero_from.max(chunk_start) - chunk_start) as usize;
        let to = (zero_to.min(chunk_end) - chunk_start).min(existing.len() as u64) as usize;
        if from >= to {
            return Ok(None);
        }

        let mut buf = existing.to_vec();
        buf[from..to].fill(0);
        trim_trailing_zeroes(&mut buf);
        let new_billed = billed_chunk_bytes(self.geometry.size_bytes, chunk_start, buf.len());
        if buf.is_empty() {
            batch.delete(key);
        } else {
            batch.put(key, Bytes::from(buf));
        }
        Ok(Some(new_billed as i64 - old_billed as i64))
    }
}

#[async_trait]
impl BlockDev for BlockVolume {
    fn geometry(&self) -> BlockGeometry {
        self.geometry()
    }

    async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes> {
        self.ensure_live()?;
        self.extent_end(offset, len as u64)?;
        let result = data::read_range(
            &self.db,
            self.chunk_size(),
            BLOCK_INO,
            self.geometry.size_bytes,
            offset,
            len,
        )
        .await;
        self.map_core(result)
    }

    async fn write(&self, offset: u64, data: Bytes, fua: bool) -> FsResult<()> {
        self.ensure_live()?;
        let Some((first, last)) = self.chunk_range(offset, data.len() as u64)? else {
            if fua {
                self.map_storage(self.db.flush().await)?;
            }
            return Ok(());
        };
        let _guards = self.locks.write_range(first as u64, last as u64).await;
        let plan = data::plan_write(
            &self.db,
            self.chunk_size(),
            BLOCK_INO,
            self.geometry.size_bytes,
            offset,
            &data,
        )
        .await?;

        let mut batch = WriteBatch::new();
        for (idx, chunk) in plan.puts {
            batch.put(keys::chunk(BLOCK_INO, idx), chunk);
        }
        if plan.billed_delta != 0 {
            batch.merge(
                keys::KEY_QUOTA_BYTES,
                quota::encode_delta(plan.billed_delta),
            );
        }
        self.commit(batch, plan.billed_delta, fua).await
    }

    async fn flush(&self) -> FsResult<()> {
        self.map_storage(self.db.flush().await)
    }

    async fn trim(&self, offset: u64, len: u64) -> FsResult<()> {
        self.ensure_live()?;
        let Some((first, last)) = self.chunk_range(offset, len)? else {
            return Ok(());
        };
        let end = offset + len;
        let _guards = self.locks.write_range(first as u64, last as u64).await;
        const BATCH: usize = 1024;
        let mut batch = WriteBatch::new();
        let mut batch_delta = 0i64;
        let mut mutations = 0usize;

        // NBD permits trimmed ranges to read back as zero. Linux ext4/fstrim
        // can issue ranges smaller than our SlateFS chunk size, so edge chunks
        // must be zeroed exactly; fully-covered interior chunks keep the sparse
        // delete fast path below.
        for idx in [first, last] {
            if !self.chunk_fully_covered(idx, offset, end)
                && let Some(delta) = self
                    .stage_zeroes_for_existing_chunk(&mut batch, idx, offset, end)
                    .await?
            {
                batch_delta += delta;
                mutations += 1;
            }
            if first == last {
                break;
            }
        }

        let full_first = if self.chunk_fully_covered(first, offset, end) {
            first
        } else {
            first.saturating_add(1)
        };
        let full_last = if self.chunk_fully_covered(last, offset, end) {
            Some(last)
        } else {
            last.checked_sub(1)
        };
        let full_range = full_last
            .filter(|full_last| full_first <= *full_last)
            .map(|full_last| (full_first, full_last));
        let mut full_scan_done = full_range.is_none();

        loop {
            let mut n = 0usize;

            if let Some((scan_first, scan_last)) = full_range {
                let mut iter = self.map_storage(
                    self.db
                        .scan(
                            keys::chunk(BLOCK_INO, scan_first).to_vec()
                                ..keys::chunk_prefix(BLOCK_INO + 1).to_vec(),
                        )
                        .await,
                )?;
                while let Some(kv) = self.map_storage(iter.next().await)? {
                    let Some((ino, idx)) = keys::parse_chunk(&kv.key) else {
                        break;
                    };
                    if ino != BLOCK_INO || idx > scan_last {
                        break;
                    }
                    let (chunk_start, _chunk_end) = self.chunk_bounds(idx);
                    batch.delete(kv.key);
                    batch_delta -=
                        billed_chunk_bytes(self.geometry.size_bytes, chunk_start, kv.value.len())
                            as i64;
                    mutations += 1;
                    n += 1;
                    if n == BATCH {
                        break;
                    }
                }
                if n < BATCH {
                    full_scan_done = true;
                }
            }

            if mutations == 0 {
                break;
            }
            if batch_delta != 0 {
                batch.merge(keys::KEY_QUOTA_BYTES, quota::encode_delta(batch_delta));
            }
            self.commit(batch, batch_delta, false).await?;
            if full_scan_done {
                break;
            }
            batch = WriteBatch::new();
            batch_delta = 0;
            mutations = 0;
        }
        Ok(())
    }

    async fn write_zeroes(&self, offset: u64, len: u64, fua: bool) -> FsResult<()> {
        self.ensure_live()?;
        let Some((first, last)) = self.chunk_range(offset, len)? else {
            if fua {
                self.map_storage(self.db.flush().await)?;
            }
            return Ok(());
        };
        let end = offset + len;
        let _guards = self.locks.write_range(first as u64, last as u64).await;
        let mut batch = WriteBatch::new();
        let mut billed_delta = 0i64;
        let mut mutations = 0usize;

        for idx in first..=last {
            if let Some(delta) = self
                .stage_zeroes_for_existing_chunk(&mut batch, idx, offset, end)
                .await?
            {
                billed_delta += delta;
                mutations += 1;
            }
        }

        if mutations == 0 {
            if fua {
                self.map_storage(self.db.flush().await)?;
            }
            return Ok(());
        }
        if billed_delta != 0 {
            batch.merge(keys::KEY_QUOTA_BYTES, quota::encode_delta(billed_delta));
        }
        self.commit(batch, billed_delta, fua).await
    }
}

pub struct ReadOnlyBlockDev {
    inner: Arc<dyn BlockDev>,
}

impl ReadOnlyBlockDev {
    pub fn new(inner: Arc<dyn BlockDev>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

#[async_trait]
impl BlockDev for ReadOnlyBlockDev {
    fn geometry(&self) -> BlockGeometry {
        let mut geometry = self.inner.geometry();
        geometry.read_only = true;
        geometry
    }

    async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes> {
        self.inner.read(offset, len).await
    }

    async fn write(&self, _offset: u64, _data: Bytes, _fua: bool) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn flush(&self) -> FsResult<()> {
        self.inner.flush().await
    }

    async fn trim(&self, _offset: u64, _len: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn write_zeroes(&self, _offset: u64, _len: u64, _fua: bool) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
}

pub struct StrictSyncBlockDev {
    inner: Arc<dyn BlockDev>,
}

impl StrictSyncBlockDev {
    pub fn new(inner: Arc<dyn BlockDev>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

#[async_trait]
impl BlockDev for StrictSyncBlockDev {
    fn geometry(&self) -> BlockGeometry {
        self.inner.geometry()
    }

    async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes> {
        self.inner.read(offset, len).await
    }

    async fn write(&self, offset: u64, data: Bytes, _fua: bool) -> FsResult<()> {
        self.inner.write(offset, data, true).await
    }

    async fn flush(&self) -> FsResult<()> {
        self.inner.flush().await
    }

    async fn trim(&self, offset: u64, len: u64) -> FsResult<()> {
        self.inner.trim(offset, len).await
    }

    async fn write_zeroes(&self, offset: u64, len: u64, _fua: bool) -> FsResult<()> {
        self.inner.write_zeroes(offset, len, true).await
    }
}

pub struct SnapshotBlockVolume {
    reader: DbReader,
    geometry: BlockGeometry,
}

impl SnapshotBlockVolume {
    pub async fn open(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
        snapshot_id: &str,
        parent_prefixes: Vec<String>,
    ) -> Result<Arc<SnapshotBlockVolume>> {
        if record.state != VolumeState::Active {
            return Err(Error::invalid(
                "volume state",
                format!("{:?}, not Active", record.state),
            ));
        }
        let checkpoint = uuid::Uuid::parse_str(snapshot_id)
            .map_err(|e| Error::invalid("snapshot id", format!("{snapshot_id:?}: {e}")))?;
        let path = store::volume_db_path(&record.tenant, &record.name);
        let reader_store = if parent_prefixes.is_empty() {
            object_store
        } else {
            store::clone_parent_read_fallback_store(
                object_store,
                &record.tenant,
                &record.name,
                parent_prefixes,
            )
        };
        let reader = DbReader::builder(path, reader_store)
            .with_checkpoint_id(checkpoint)
            .with_block_transformer(Arc::new(SlateBlockTransformer::new(record.cipher, dek)))
            .with_merge_operator(Arc::new(CounterMergeOperator))
            .build()
            .await?;

        let result = async {
            let bytes = reader
                .get(KEY_SUPERBLOCK)
                .await?
                .ok_or_else(|| Error::invalid("snapshot", "no superblock"))?;
            let superblock = Superblock::decode(&bytes)?;
            verify_superblock_matches_record(record, &superblock, "snapshot superblock")?;
            let VolumeKind::Block { size_bytes } = superblock.kind else {
                return Err(Error::invalid(
                    "volume kind",
                    "filesystem snapshot cannot be opened as a block snapshot",
                ));
            };
            validate_block_size(size_bytes, superblock.chunk_size)?;
            Ok((superblock, size_bytes))
        }
        .await;

        let (superblock, size_bytes) = match result {
            Ok(values) => values,
            Err(error) => {
                reader.close().await?;
                return Err(error);
            }
        };
        Ok(Arc::new(SnapshotBlockVolume {
            reader,
            geometry: BlockGeometry {
                size_bytes,
                min_block: MIN_BLOCK_SIZE,
                preferred_block: superblock.chunk_size,
                max_payload: MAX_PAYLOAD,
                read_only: true,
            },
        }))
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.reader.close().await.map_err(Error::from)
    }

    fn chunk_size(&self) -> u64 {
        self.geometry.preferred_block as u64
    }

    fn extent_end(&self, offset: u64, len: u64) -> FsResult<u64> {
        let end = offset.checked_add(len).ok_or(FsError::Invalid)?;
        if offset > self.geometry.size_bytes || end > self.geometry.size_bytes {
            return Err(FsError::Invalid);
        }
        Ok(end)
    }
}

#[async_trait]
impl BlockDev for SnapshotBlockVolume {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    async fn read(&self, offset: u64, len: u32) -> FsResult<Bytes> {
        let end = self.extent_end(offset, len as u64)?;
        if len == 0 {
            return Ok(Bytes::new());
        }
        let first = data::chunk_of(offset, self.chunk_size());
        let last = data::chunk_of(end - 1, self.chunk_size());
        let mut out = vec![0u8; (end - offset) as usize];
        for idx in first..=last {
            if let Some(chunk) = self.reader.get(keys::chunk(BLOCK_INO, idx)).await? {
                copy_from_chunk(&mut out, offset, idx, &chunk, self.chunk_size());
            }
        }
        Ok(Bytes::from(out))
    }

    async fn write(&self, _offset: u64, _data: Bytes, _fua: bool) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn flush(&self) -> FsResult<()> {
        Ok(())
    }

    async fn trim(&self, _offset: u64, _len: u64) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn write_zeroes(&self, _offset: u64, _len: u64, _fua: bool) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }
}

fn copy_from_chunk(out: &mut [u8], read_offset: u64, idx: u32, chunk: &[u8], chunk_size: u64) {
    let chunk_start = idx as u64 * chunk_size;
    let from = read_offset.max(chunk_start);
    let to = (read_offset + out.len() as u64).min(chunk_start + chunk.len() as u64);
    if from >= to {
        return;
    }
    let src = (from - chunk_start) as usize..(to - chunk_start) as usize;
    let dst = (from - read_offset) as usize..(to - read_offset) as usize;
    out[dst].copy_from_slice(&chunk[src]);
}

fn trim_trailing_zeroes(buf: &mut Vec<u8>) {
    while buf.last().copied() == Some(0) {
        buf.pop();
    }
}
