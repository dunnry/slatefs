//! Volume lifecycle (DD-1: one SlateDB per volume): create (`mkfs`), open
//! for serving, info. An open [`Volume`] is the object the `Vfs`
//! implementation lives on (see `vfs_impl.rs`): it owns the Db handle, lock
//! manager, quota tracker, inode allocator, name codec, and open-file table.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use slatedb::object_store::ObjectStore;
use slatedb::{Db, DbReader, Settings, WriteBatch};

use crate::config::{Compression, VolumeDefaults};
use crate::control::{ControlPlane, QuotaLimits, TenantState, VolumeRecord, VolumeState, now_unix};
use crate::crypto::kms::contexts;
use crate::crypto::names::NameCodec;
use crate::crypto::transformer::SlateBlockTransformer;
use crate::crypto::{Cipher, Secret32, aead, random_u64};
use crate::error::{Error, Result};
use crate::locks::{LockManager, RangeLockTable};
use crate::meta::alloc::InodeAllocator;
use crate::meta::dirent::Orphan;
use crate::meta::inode::{FileKind, Inode, ROOT_INO, Timespec};
use crate::meta::keys;
use crate::meta::superblock::{KEY_SUPERBLOCK, Superblock};
use crate::quota::{self, CounterMergeOperator, QuotaTracker};
use crate::store;
use crate::vfs::OpenMode;

/// Parameters fixed at volume creation. `cipher` must already be resolved
/// (no `Auto` here): the choice is recorded in the volume format and must not
/// vary by which node happens to open the volume (DD-8).
#[derive(Debug, Clone)]
pub struct CreateVolumeOptions {
    pub cipher: Cipher,
    pub chunk_size: u32,
    pub compression: Compression,
    pub quota: QuotaLimits,
    pub note: Option<String>,
}

impl CreateVolumeOptions {
    pub fn from_defaults(defaults: &VolumeDefaults) -> Self {
        CreateVolumeOptions {
            cipher: defaults.cipher.resolve(),
            chunk_size: defaults.chunk_size,
            compression: defaults.compression,
            quota: QuotaLimits::default(),
            note: None,
        }
    }
}

#[derive(Debug)]
pub struct VolumeInfo {
    pub record: VolumeRecord,
    pub superblock: Superblock,
}

/// Create a volume: commit the control record (state `Creating`), mkfs the
/// volume DB, then flip the record to `Active`.
///
/// Crash-safe by ordering: the DEK is committed to the control DB *before*
/// any volume block is written, so a retry after a crash resumes with the
/// same DEK (a regenerated DEK could never read the first attempt's WAL).
pub async fn create_volume(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    volume_name: &str,
    opts: CreateVolumeOptions,
) -> Result<VolumeRecord> {
    store::validate_name("tenant name", tenant_name)?;
    store::validate_name("volume name", volume_name)?;

    let tenant = control.get_tenant(tenant_name).await?;
    if tenant.state != TenantState::Active {
        return Err(Error::invalid(
            "tenant state",
            format!("tenant {tenant_name:?} is {:?}, not Active", tenant.state),
        ));
    }

    let mut record = match control.try_get_volume(tenant_name, volume_name).await? {
        Some(existing) if existing.state == VolumeState::Creating => {
            tracing::warn!(
                tenant = tenant_name,
                volume = volume_name,
                "resuming interrupted volume creation with the recorded DEK"
            );
            existing
        }
        Some(_) => {
            return Err(Error::already_exists(
                "volume",
                format!("{tenant_name}/{volume_name}"),
            ));
        }
        None => {
            let kek = control.unwrap_tenant_kek(&tenant).await?;
            let dek = Secret32::generate();
            let record = VolumeRecord {
                tenant: tenant_name.to_string(),
                name: volume_name.to_string(),
                state: VolumeState::Creating,
                fsid: random_u64(),
                wrapped_dek: aead::wrap_key(
                    &kek,
                    &contexts::volume_dek(tenant_name, volume_name),
                    &dek,
                )?,
                cipher: opts.cipher,
                chunk_size: opts.chunk_size,
                compression: opts.compression,
                quota: opts.quota,
                note: opts.note,
                created_at: now_unix(),
            };
            control.put_volume(&record).await?;
            record
        }
    };

    let dek = control.unwrap_volume_dek(&record).await?;
    mkfs(&record, dek, object_store).await?;

    record.state = VolumeState::Active;
    control.put_volume(&record).await?;
    tracing::info!(
        tenant = tenant_name,
        volume = volume_name,
        fsid = format_args!("{:016x}", record.fsid),
        cipher = %record.cipher,
        "volume created"
    );
    Ok(record)
}

/// Initialize the volume DB: superblock, root directory inode, inode
/// allocator mark, and the root's inode-quota charge — one atomic batch.
/// Idempotent: an existing superblock is verified against the record instead
/// of rewritten, so a resumed create can't corrupt a half-made volume.
async fn mkfs(
    record: &VolumeRecord,
    dek: Secret32,
    object_store: Arc<dyn ObjectStore>,
) -> Result<()> {
    let db = open_volume_db(record, dek, object_store).await?;

    let result = async {
        match db.get(KEY_SUPERBLOCK).await? {
            Some(bytes) => {
                let existing = Superblock::decode(&bytes)?;
                if existing.fsid != record.fsid {
                    return Err(Error::invalid(
                        "superblock",
                        format!(
                            "fsid {:016x} does not match control record {:016x}",
                            existing.fsid, record.fsid
                        ),
                    ));
                }
            }
            None => {
                let superblock = Superblock {
                    fsid: record.fsid,
                    cipher: record.cipher,
                    chunk_size: record.chunk_size,
                    name_enc: true,
                    created_at: record.created_at,
                };
                let mut root = Inode::new(FileKind::Dir, 0o755, 0, 0, Timespec::now());
                root.parent_dir = ROOT_INO;

                let mut batch = WriteBatch::new();
                batch.put(KEY_SUPERBLOCK, superblock.encode()?);
                batch.put(keys::inode(ROOT_INO), root.encode()?);
                batch.put(keys::KEY_NEXT_INO, (ROOT_INO + 1).to_be_bytes());
                batch.merge(keys::KEY_QUOTA_INODES, quota::encode_delta(1));
                db.write(batch).await?;
                db.flush().await?;
            }
        }
        Ok(())
    }
    .await;

    db.close().await?;
    result
}

/// Open a volume's SlateDB as the (single) writer, with its block
/// transformer, compression, and quota merge operator wired per the control
/// record.
pub async fn open_volume_db(
    record: &VolumeRecord,
    dek: Secret32,
    object_store: Arc<dyn ObjectStore>,
) -> Result<Db> {
    let path = store::volume_db_path(&record.tenant, &record.name);
    Db::builder(path, object_store)
        .with_settings(Settings {
            compression_codec: record.compression.to_slatedb(),
            ..Settings::default()
        })
        .with_block_transformer(Arc::new(SlateBlockTransformer::new(record.cipher, dek)))
        .with_merge_operator(Arc::new(CounterMergeOperator))
        .build()
        .await
        .map_err(Error::from)
}

/// Read the control record plus the superblock. Uses a read-only `DbReader`,
/// so it neither bumps the writer epoch nor fences a daemon serving the
/// volume.
pub async fn volume_info(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    volume_name: &str,
) -> Result<VolumeInfo> {
    let record = control.get_volume(tenant_name, volume_name).await?;
    let dek = control.unwrap_volume_dek(&record).await?;

    let path = store::volume_db_path(&record.tenant, &record.name);
    let reader = DbReader::builder(path, object_store)
        .with_block_transformer(Arc::new(SlateBlockTransformer::new(record.cipher, dek)))
        .with_merge_operator(Arc::new(CounterMergeOperator))
        .build()
        .await?;

    let result = async {
        let bytes = reader
            .get(KEY_SUPERBLOCK)
            .await?
            .ok_or_else(|| Error::invalid("volume", "no superblock (mkfs incomplete?)"))?;
        let superblock = Superblock::decode(&bytes)?;
        if superblock.fsid != record.fsid {
            return Err(Error::invalid(
                "superblock",
                format!(
                    "fsid {:016x} does not match control record {:016x}",
                    superblock.fsid, record.fsid
                ),
            ));
        }
        Ok(superblock)
    }
    .await;

    reader.close().await?;
    Ok(VolumeInfo {
        record,
        superblock: result?,
    })
}

// ---- the mounted volume ----

#[derive(Default)]
pub(crate) struct HandleTable {
    next: u64,
    by_handle: HashMap<u64, (u64, OpenMode)>,
    open_count: HashMap<u64, u32>,
}

impl HandleTable {
    pub(crate) fn open(&mut self, ino: u64, mode: OpenMode) -> u64 {
        self.next += 1;
        self.by_handle.insert(self.next, (ino, mode));
        *self.open_count.entry(ino).or_insert(0) += 1;
        self.next
    }

    /// Returns `(ino, mode, was_last_handle_for_ino)`.
    pub(crate) fn close(&mut self, handle: u64) -> Option<(u64, OpenMode, bool)> {
        let (ino, mode) = self.by_handle.remove(&handle)?;
        let count = self.open_count.get_mut(&ino)?;
        *count -= 1;
        let last = *count == 0;
        if last {
            self.open_count.remove(&ino);
        }
        Some((ino, mode, last))
    }

    pub(crate) fn is_open(&self, ino: u64) -> bool {
        self.open_count.contains_key(&ino)
    }

    pub(crate) fn get(&self, handle: u64) -> Option<(u64, OpenMode)> {
        self.by_handle.get(&handle).copied()
    }
}

/// A mounted, serving volume — the single writer for its SlateDB (DD-5).
pub struct Volume {
    pub(crate) db: Db,
    pub(crate) superblock: Superblock,
    pub(crate) names: NameCodec,
    pub(crate) locks: LockManager,
    pub(crate) range_locks: RangeLockTable,
    pub(crate) quota: QuotaTracker,
    pub(crate) alloc: InodeAllocator,
    pub(crate) handles: Mutex<HandleTable>,
    pub(crate) chunk_size: u64,
}

impl Volume {
    /// Open a volume for serving: wire the encrypted Db, load quota counters
    /// and the allocator, then reap orphans left by a crash (plan §6).
    pub async fn open(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
    ) -> Result<Arc<Volume>> {
        if record.state != VolumeState::Active {
            return Err(Error::invalid(
                "volume state",
                format!("{:?}, not Active", record.state),
            ));
        }
        let db = open_volume_db(record, dek.clone(), object_store).await?;

        let superblock = match db.get(KEY_SUPERBLOCK).await? {
            Some(bytes) => Superblock::decode(&bytes)?,
            None => return Err(Error::invalid("volume", "no superblock (mkfs incomplete?)")),
        };
        if superblock.fsid != record.fsid {
            return Err(Error::invalid(
                "superblock",
                "fsid mismatch with control record",
            ));
        }

        // Reap crash leftovers *before* loading quota counters, so the
        // in-memory tracker starts from settled numbers.
        reap_crashed_orphans(&db).await?;

        let bytes_used = quota::decode_counter(db.get(keys::KEY_QUOTA_BYTES).await?.as_deref());
        let inodes_used = quota::decode_counter(db.get(keys::KEY_QUOTA_INODES).await?.as_deref());
        let alloc = InodeAllocator::load(&db).await?;

        Ok(Arc::new(Volume {
            db,
            chunk_size: superblock.chunk_size as u64,
            superblock,
            names: NameCodec::new(dek),
            locks: LockManager::default(),
            range_locks: RangeLockTable::default(),
            quota: QuotaTracker::new(bytes_used, inodes_used, record.quota),
            alloc,
            handles: Mutex::new(HandleTable::default()),
        }))
    }

    pub fn fsid(&self) -> u64 {
        self.superblock.fsid
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Flush acknowledged writes to durable storage (DD-7).
    pub async fn flush(&self) -> Result<()> {
        self.db.flush().await.map_err(Error::from)
    }

    /// Stop serving and close the underlying Db. Named to avoid colliding
    /// with `Vfs::close(handle)`.
    pub async fn shutdown(&self) -> Result<()> {
        self.db.close().await.map_err(Error::from)
    }

    /// Delete an orphan's data — see [`reap_orphan_data`].
    pub(crate) async fn reap_orphan(&self, ino: u64) -> Result<()> {
        reap_orphan_data(&self.db, ino).await
    }

    /// Structural + counter verification (plan §12). Run on a quiesced
    /// volume; the mount-time reaper has already cleared crash leftovers.
    pub async fn fsck(&self) -> Result<crate::fsck::FsckReport> {
        crate::fsck::check(&self.db, self.chunk_size, &self.names).await
    }

    /// Fsck plus counter rewrite when drift is found (`fsck --recount`).
    pub async fn fsck_recount(&self) -> Result<crate::fsck::FsckReport> {
        crate::fsck::recount(&self.db, self.chunk_size, &self.names).await
    }
}

/// Delete an orphan's data: chunks (in bounded batches), xattrs, symlink
/// target, then the orphan marker itself. Quota was settled when the inode
/// died, so these batches carry no quota merges; a crash here just leaves
/// the orphan for the next mount's reaper.
pub(crate) async fn reap_orphan_data(db: &Db, ino: u64) -> Result<()> {
    const BATCH: usize = 1024;
    loop {
        let mut iter = db
            .scan(keys::chunk_prefix(ino).to_vec()..keys::chunk_prefix(ino + 1).to_vec())
            .await?;
        let mut batch = WriteBatch::new();
        let mut n = 0;
        while let Some(kv) = iter.next().await? {
            batch.delete(kv.key);
            n += 1;
            if n == BATCH {
                break;
            }
        }
        if n == 0 {
            break;
        }
        db.write(batch).await?;
        if n < BATCH {
            break;
        }
    }

    let mut batch = WriteBatch::new();
    let mut iter = db
        .scan(keys::xattr_prefix(ino).to_vec()..keys::xattr_prefix(ino + 1).to_vec())
        .await?;
    while let Some(kv) = iter.next().await? {
        batch.delete(kv.key);
    }
    batch.delete(keys::symlink(ino));
    batch.delete(keys::orphan(ino));
    db.write(batch).await?;
    Ok(())
}

/// Mount-time reaper. Two crash shapes (plan §6):
/// - inode already gone: quota was settled at unlink; just reap data;
/// - inode still present with nlink 0 (died while handles were open): settle
///   quota and drop the inode first.
async fn reap_crashed_orphans(db: &Db) -> Result<()> {
    let mut orphans = Vec::new();
    let mut iter = db.scan_prefix(keys::ORPHAN_PREFIX).await?;
    while let Some(kv) = iter.next().await? {
        if let Some(ino) = keys::parse_ino(&kv.key) {
            let _ = Orphan::decode(&kv.value)?;
            orphans.push(ino);
        }
    }
    for ino in orphans {
        tracing::info!(ino, "reaping orphan left by previous crash");
        if let Some(bytes) = db.get(keys::inode(ino)).await? {
            let inode = Inode::decode(&bytes)?;
            let mut batch = WriteBatch::new();
            batch.delete(keys::inode(ino));
            batch.merge(
                keys::KEY_QUOTA_BYTES,
                quota::encode_delta(-(inode.billed_bytes as i64)),
            );
            batch.merge(keys::KEY_QUOTA_INODES, quota::encode_delta(-1));
            db.write(batch).await?;
        }
        reap_orphan_data(db, ino).await?;
    }
    Ok(())
}
