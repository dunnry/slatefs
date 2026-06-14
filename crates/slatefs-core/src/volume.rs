//! Volume lifecycle (DD-1: one SlateDB per volume): create (`mkfs`), open
//! for serving, info. An open [`Volume`] is the object the `Vfs`
//! implementation lives on (see `vfs_impl.rs`): it owns the Db handle, lock
//! manager, quota tracker, inode allocator, name codec, and open-file table.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use slatedb::admin::AdminBuilder;
use slatedb::config::{CheckpointOptions, CheckpointScope};
use slatedb::object_store::ObjectStore;
use slatedb::{Checkpoint, Db, DbReader, Settings, WriteBatch};
use tokio::sync::Notify;

use crate::attrcache::AttrCache;
use crate::config::{CacheConfig, Compression, SlateDbConfig, VolumeDefaults};
use crate::control::{
    CloneParent, ControlPlane, QuotaLimits, TenantState, VolumeRecord, VolumeState, now_unix,
};
use crate::crypto::kms::contexts;
use crate::crypto::names::NameCodec;
use crate::crypto::transformer::{BlockTransformMetrics, SlateBlockTransformer};
use crate::crypto::{Cipher, Secret32, aead, random_u64};
use crate::error::{Error, Result, is_fenced_slatedb_error};
use crate::locks::{LockManager, RangeLockTable};
use crate::meta::alloc::InodeAllocator;
use crate::meta::dirent::Orphan;
use crate::meta::inode::{FileKind, Inode, ROOT_INO, Timespec};
use crate::meta::keys;
use crate::meta::superblock::{KEY_SUPERBLOCK, Superblock};
use crate::quota::{self, CounterMergeOperator, QuotaTracker};
use crate::store;
use crate::vfs::{FsError, FsResult, OpenMode};

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

#[derive(Debug, Clone, Default)]
pub struct CloneVolumeOptions {
    /// Optional source checkpoint id. If omitted, SlateDB clones the latest
    /// durable source state. The source volume must not be actively served.
    pub source_snapshot_id: Option<String>,
    pub note: Option<String>,
}

/// Cache wiring for one open volume (plan §8). Per-volume by design:
/// sharing a block cache across volumes aliases `SsTableId::Wal` ids
/// (cross-tenant plaintext leak — see docs/threat-model.md).
#[derive(Clone, Default)]
pub struct VolumeCaches {
    /// Tier-1 in-RAM block cache budget for this volume, in bytes.
    pub memory_bytes: Option<u64>,
    /// Tier-2 ciphertext part cache directory for this volume.
    pub disk_root: Option<std::path::PathBuf>,
    /// Tier-2 budget for this volume, in bytes.
    pub disk_bytes: Option<u64>,
    /// SlateDB write-buffer and compaction settings for this volume.
    pub slatedb: SlateDbConfig,
    /// Engine metrics sink (cache hit rates, flush latency, …).
    pub recorder: Option<Arc<crate::metrics::AggregatingRecorder>>,
}

impl VolumeCaches {
    /// Split the deployment-wide budgets across `share_count` open volumes.
    pub fn from_config(
        cache: &CacheConfig,
        slatedb: &SlateDbConfig,
        tenant: &str,
        volume: &str,
        share_count: usize,
    ) -> VolumeCaches {
        let n = share_count.max(1) as u64;
        VolumeCaches {
            memory_bytes: cache.memory_bytes.map(|b| (b / n).max(8 * 1024 * 1024)),
            disk_root: cache
                .disk_path
                .as_ref()
                .map(|root| root.join(tenant).join(volume)),
            disk_bytes: cache.disk_bytes.map(|b| (b / n).max(64 * 1024 * 1024)),
            slatedb: slatedb.clone(),
            recorder: None,
        }
    }
}

#[derive(Debug)]
pub struct VolumeInfo {
    pub record: VolumeRecord,
    pub superblock: Superblock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSnapshot {
    pub id: String,
    pub manifest_id: u64,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub id: String,
    pub manifest_id: u64,
    pub name: Option<String>,
    pub create_time: String,
    pub expire_time: Option<String>,
}

fn snapshot_info(checkpoint: Checkpoint) -> SnapshotInfo {
    SnapshotInfo {
        id: checkpoint.id.to_string(),
        manifest_id: checkpoint.manifest_id,
        name: checkpoint.name,
        create_time: checkpoint.create_time.to_rfc3339(),
        expire_time: checkpoint.expire_time.map(|t| t.to_rfc3339()),
    }
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
                clone_parent: None,
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

/// Create an instant writable clone in the same tenant. The SlateDB clone is
/// shallow and shares source SSTs, so the clone must use the same plaintext DEK
/// as the source. We still wrap that DEK under the destination volume context
/// and rewrite the cloned superblock to give the clone its own fsid.
pub async fn clone_volume(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    source_volume_name: &str,
    clone_volume_name: &str,
    opts: CloneVolumeOptions,
) -> Result<VolumeRecord> {
    store::validate_name("tenant name", tenant_name)?;
    store::validate_name("source volume name", source_volume_name)?;
    store::validate_name("clone volume name", clone_volume_name)?;
    if source_volume_name == clone_volume_name {
        return Err(Error::invalid(
            "clone volume",
            "source and destination names must differ",
        ));
    }

    let tenant = control.get_tenant(tenant_name).await?;
    if tenant.state != TenantState::Active {
        return Err(Error::invalid(
            "tenant state",
            format!("tenant {tenant_name:?} is {:?}, not Active", tenant.state),
        ));
    }

    let source = control.get_volume(tenant_name, source_volume_name).await?;
    if source.state != VolumeState::Active {
        return Err(Error::invalid(
            "source volume state",
            format!(
                "{tenant_name}/{source_volume_name} is {:?}, not Active",
                source.state
            ),
        ));
    }

    let source_dek = control.unwrap_volume_dek(&source).await?;
    let checkpoint = opts
        .source_snapshot_id
        .as_deref()
        .map(|id| {
            uuid::Uuid::parse_str(id)
                .map_err(|e| Error::invalid("snapshot id", format!("{id:?}: {e}")))
        })
        .transpose()?;

    let mut record = match control
        .try_get_volume(tenant_name, clone_volume_name)
        .await?
    {
        Some(existing) if existing.state == VolumeState::Creating => {
            let same_parent = existing.clone_parent.as_ref().is_some_and(|parent| {
                parent.tenant == tenant_name && parent.volume == source_volume_name
            });
            if !same_parent {
                return Err(Error::already_exists(
                    "volume",
                    format!("{tenant_name}/{clone_volume_name}"),
                ));
            }
            if existing.cipher != source.cipher
                || existing.chunk_size != source.chunk_size
                || existing.compression != source.compression
            {
                return Err(Error::invalid(
                    "clone record",
                    "interrupted clone format differs from source volume",
                ));
            }
            let existing_dek = control.unwrap_volume_dek(&existing).await?;
            if existing_dek.expose_secret() != source_dek.expose_secret() {
                return Err(Error::invalid(
                    "clone record",
                    "interrupted clone DEK differs from source volume",
                ));
            }
            tracing::warn!(
                tenant = tenant_name,
                source = source_volume_name,
                clone = clone_volume_name,
                "resuming interrupted clone creation"
            );
            let prefix = store::volume_db_prefix(tenant_name, clone_volume_name);
            let objects_deleted = store::delete_prefix(&object_store, &prefix).await?;
            tracing::info!(
                tenant = tenant_name,
                clone = clone_volume_name,
                objects_deleted,
                "deleted interrupted clone object-store prefix"
            );
            existing
        }
        Some(_) => {
            return Err(Error::already_exists(
                "volume",
                format!("{tenant_name}/{clone_volume_name}"),
            ));
        }
        None => {
            let tenant_kek = control.unwrap_tenant_kek(&tenant).await?;
            let record = VolumeRecord {
                tenant: tenant_name.to_string(),
                name: clone_volume_name.to_string(),
                state: VolumeState::Creating,
                clone_parent: Some(CloneParent {
                    tenant: tenant_name.to_string(),
                    volume: source_volume_name.to_string(),
                }),
                fsid: random_u64(),
                wrapped_dek: aead::wrap_key(
                    &tenant_kek,
                    &contexts::volume_dek(tenant_name, clone_volume_name),
                    &source_dek,
                )?,
                cipher: source.cipher,
                chunk_size: source.chunk_size,
                compression: source.compression,
                quota: source.quota,
                note: opts.note,
                created_at: now_unix(),
            };
            control.put_volume(&record).await?;
            record
        }
    };

    let source_path = store::volume_db_path(tenant_name, source_volume_name);
    let clone_path = store::volume_db_path(tenant_name, clone_volume_name);
    let admin = AdminBuilder::new(clone_path, Arc::clone(&object_store)).build();
    admin
        .create_clone_builder(source_path, checkpoint)
        .build()
        .await
        .map_err(|e| Error::invalid("clone", e.to_string()))?;

    rewrite_cloned_superblock(&record, &source, source_dek, Arc::clone(&object_store)).await?;

    record.state = VolumeState::Active;
    control.put_volume(&record).await?;
    tracing::info!(
        tenant = tenant_name,
        source = source_volume_name,
        clone = clone_volume_name,
        fsid = format_args!("{:016x}", record.fsid),
        "volume clone created"
    );
    Ok(record)
}

async fn rewrite_cloned_superblock(
    clone: &VolumeRecord,
    source: &VolumeRecord,
    dek: Secret32,
    object_store: Arc<dyn ObjectStore>,
) -> Result<()> {
    let db = open_volume_db(clone, dek, object_store, &VolumeCaches::default()).await?;
    let result = async {
        let bytes = db
            .get(KEY_SUPERBLOCK)
            .await?
            .ok_or_else(|| Error::invalid("clone", "no superblock after clone"))?;
        let mut superblock = Superblock::decode(&bytes)?;
        if superblock.fsid != source.fsid {
            return Err(Error::invalid(
                "clone superblock",
                format!(
                    "source fsid {:016x} does not match cloned superblock {:016x}",
                    source.fsid, superblock.fsid
                ),
            ));
        }
        if superblock.chunk_size != clone.chunk_size || superblock.cipher != clone.cipher {
            return Err(Error::invalid(
                "clone superblock",
                "chunk size or cipher differs from clone control record",
            ));
        }
        superblock.fsid = clone.fsid;
        superblock.created_at = clone.created_at;
        db.put(KEY_SUPERBLOCK, superblock.encode()?).await?;
        db.flush().await?;
        Ok(())
    }
    .await;
    db.close().await?;
    result
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
    let db = open_volume_db(record, dek, object_store, &VolumeCaches::default()).await?;

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
    caches: &VolumeCaches,
) -> Result<Db> {
    open_volume_db_with_transform_metrics(record, dek, object_store, caches, None).await
}

async fn open_volume_db_with_transform_metrics(
    record: &VolumeRecord,
    dek: Secret32,
    object_store: Arc<dyn ObjectStore>,
    caches: &VolumeCaches,
    block_metrics: Option<BlockTransformMetrics>,
) -> Result<Db> {
    use slatedb::config::{ObjectStoreCacheOptions, PreloadLevel};
    use slatedb::db_cache::foyer::{FoyerCache, FoyerCacheOptions};

    let path = store::volume_db_path(&record.tenant, &record.name);
    // Tier 2 (DD-4): ciphertext object parts on local disk; preload L0 so a
    // warm restart serves recent data without object-store GETs.
    let object_store_cache_options = match (&caches.disk_root, caches.disk_bytes) {
        (Some(root), _) => ObjectStoreCacheOptions {
            root_folder: Some(root.clone()),
            max_cache_size_bytes: caches.disk_bytes.map(|b| b as usize),
            preload_disk_cache_on_startup: Some(PreloadLevel::L0Sst),
            ..ObjectStoreCacheOptions::default()
        },
        _ => ObjectStoreCacheOptions::default(),
    };

    let transformer = match block_metrics {
        Some(metrics) => SlateBlockTransformer::with_metrics(record.cipher, dek, metrics),
        None => SlateBlockTransformer::new(record.cipher, dek),
    };
    let settings = caches.slatedb.apply_to_settings(Settings {
        compression_codec: record.compression.to_slatedb(),
        object_store_cache_options,
        ..Settings::default()
    });
    let mut builder = Db::builder(path, object_store)
        .with_settings(settings)
        .with_block_transformer(Arc::new(transformer))
        .with_merge_operator(Arc::new(CounterMergeOperator));
    // Tier 1: in-RAM plaintext block cache, byte-weighted.
    if let Some(bytes) = caches.memory_bytes {
        builder = builder.with_db_cache(Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
            max_capacity: bytes,
            ..FoyerCacheOptions::default()
        })));
    }
    if let Some(recorder) = &caches.recorder {
        builder = builder.with_metrics_recorder(Arc::clone(recorder) as _);
    }
    builder.build().await.map_err(Error::from)
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

/// Run the fsck structural checker through a read-only [`DbReader`]. Unlike
/// [`Volume::fsck`], this does not open the volume as the writer, so it can
/// run while `slatefsd` is serving the volume. It reports drift/corruption but
/// never rewrites counters.
pub async fn scrub_volume(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    volume_name: &str,
) -> Result<crate::fsck::FsckReport> {
    let record = control.get_volume(tenant_name, volume_name).await?;
    let dek = control.unwrap_volume_dek(&record).await?;
    let names = NameCodec::new(dek.clone());
    let clone_parent_prefixes = clone_parent_prefixes(control, &record).await?;
    let reader_store = if clone_parent_prefixes.is_empty() {
        Arc::clone(&object_store)
    } else {
        store::clone_parent_read_fallback_store(
            Arc::clone(&object_store),
            &record.tenant,
            &record.name,
            clone_parent_prefixes,
        )
    };

    let path = store::volume_db_path(&record.tenant, &record.name);
    let reader = DbReader::builder(path, reader_store)
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
        crate::fsck::check_reader(&reader, superblock.chunk_size as u64, &names).await
    }
    .await;

    reader.close().await?;
    result
}

/// Return object-store DB prefixes for a clone's parent chain, nearest parent
/// first.
pub async fn clone_parent_prefixes(
    control: &ControlPlane,
    record: &VolumeRecord,
) -> Result<Vec<String>> {
    let mut prefixes = Vec::new();
    let mut next = record.clone_parent.clone();
    for _ in 0..32 {
        let Some(parent) = next else {
            return Ok(prefixes);
        };
        prefixes.push(store::volume_db_path(&parent.tenant, &parent.volume));
        let parent_record = control.get_volume(&parent.tenant, &parent.volume).await?;
        next = parent_record.clone_parent;
    }
    Err(Error::invalid(
        "clone ancestry",
        format!(
            "{}/{} has a cycle or too many ancestors",
            record.tenant, record.name
        ),
    ))
}

/// Create a durable SlateDB checkpoint for a quiesced volume. This opens the
/// volume as writer so SlateDB can flush before checkpointing; do not run it
/// against a volume currently served by `slatefsd`.
pub async fn create_snapshot(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    volume_name: &str,
    name: Option<String>,
) -> Result<SnapshotInfo> {
    let record = control.get_volume(tenant_name, volume_name).await?;
    if record.state != VolumeState::Active {
        return Err(Error::invalid(
            "volume state",
            format!(
                "{tenant_name}/{volume_name} is {:?}, not Active",
                record.state
            ),
        ));
    }
    let dek = control.unwrap_volume_dek(&record).await?;
    let path = store::volume_db_path(&record.tenant, &record.name);
    let volume = Volume::open(&record, dek, Arc::clone(&object_store)).await?;
    let created = volume.create_live_snapshot(name).await?;
    volume.shutdown().await?;

    let admin = AdminBuilder::new(path, object_store).build();
    admin
        .list_checkpoints(None)
        .await?
        .into_iter()
        .find(|checkpoint| checkpoint.id.to_string() == created.id)
        .map(snapshot_info)
        .ok_or_else(|| {
            Error::invalid(
                "snapshot",
                format!("created checkpoint {} was not listed", created.id),
            )
        })
}

pub async fn list_snapshots(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    volume_name: &str,
    name_filter: Option<&str>,
) -> Result<Vec<SnapshotInfo>> {
    let record = control.get_volume(tenant_name, volume_name).await?;
    if record.state != VolumeState::Active {
        return Err(Error::invalid(
            "volume state",
            format!(
                "{tenant_name}/{volume_name} is {:?}, not Active",
                record.state
            ),
        ));
    }
    let path = store::volume_db_path(&record.tenant, &record.name);
    let admin = AdminBuilder::new(path, object_store).build();
    Ok(admin
        .list_checkpoints(name_filter)
        .await?
        .into_iter()
        .map(snapshot_info)
        .collect())
}

pub async fn delete_snapshot(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant_name: &str,
    volume_name: &str,
    id: &str,
) -> Result<()> {
    let record = control.get_volume(tenant_name, volume_name).await?;
    if record.state != VolumeState::Active {
        return Err(Error::invalid(
            "volume state",
            format!(
                "{tenant_name}/{volume_name} is {:?}, not Active",
                record.state
            ),
        ));
    }
    let id = uuid::Uuid::parse_str(id)
        .map_err(|e| Error::invalid("snapshot id", format!("{id:?}: {e}")))?;
    let path = store::volume_db_path(&record.tenant, &record.name);
    let admin = AdminBuilder::new(path, object_store).build();
    admin.delete_checkpoint(id).await.map_err(Error::from)
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
    block_metrics: BlockTransformMetrics,
    dead: AtomicBool,
    degraded: AtomicBool,
    storage_errors: AtomicU64,
    dead_notify: Notify,
    pub(crate) names: NameCodec,
    pub(crate) locks: LockManager,
    pub(crate) range_locks: RangeLockTable,
    pub(crate) quota: QuotaTracker,
    pub(crate) alloc: InodeAllocator,
    pub(crate) handles: Mutex<HandleTable>,
    pub(crate) chunk_size: u64,
    /// Attr + negative-dentry cache (plan §8); see vfs_impl write-through.
    pub(crate) attrs: AttrCache,
    /// Sequential-read detector state for read-ahead: ino → stream state.
    pub(crate) readahead: Mutex<HashMap<u64, ReadAheadState>>,
}

/// Per-ino sequential stream state (plan §8 read-ahead).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ReadAheadState {
    /// Offset the next sequential read would start at.
    pub(crate) expected: u64,
    /// Highest chunk index already queued for prefetch.
    pub(crate) prefetched_to: u32,
}

impl Volume {
    /// Open a volume for serving: wire the encrypted Db, load quota counters
    /// and the allocator, then reap orphans left by a crash (plan §6).
    pub async fn open(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
    ) -> Result<Arc<Volume>> {
        Self::open_with_caches(record, dek, object_store, &VolumeCaches::default()).await
    }

    /// [`Volume::open`] with cache tiers wired (plan §8).
    pub async fn open_with_caches(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
        caches: &VolumeCaches,
    ) -> Result<Arc<Volume>> {
        if record.state != VolumeState::Active {
            return Err(Error::invalid(
                "volume state",
                format!("{:?}, not Active", record.state),
            ));
        }
        let block_metrics = BlockTransformMetrics::default();
        let db = open_volume_db_with_transform_metrics(
            record,
            dek.clone(),
            object_store,
            caches,
            Some(block_metrics.clone()),
        )
        .await?;

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
            block_metrics,
            dead: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            storage_errors: AtomicU64::new(0),
            dead_notify: Notify::new(),
            names: NameCodec::new(dek),
            locks: LockManager::default(),
            range_locks: RangeLockTable::default(),
            quota: QuotaTracker::new(bytes_used, inodes_used, record.quota),
            alloc,
            handles: Mutex::new(HandleTable::default()),
            attrs: AttrCache::default(),
            readahead: Mutex::new(HashMap::new()),
        }))
    }

    pub fn fsid(&self) -> u64 {
        self.superblock.fsid
    }

    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Whether the volume has observed non-fencing storage errors since open.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// Count of non-fencing SlateDB/object-store errors observed since open.
    pub fn storage_errors(&self) -> u64 {
        self.storage_errors.load(Ordering::Relaxed)
    }

    pub fn block_decode_failures(&self) -> u64 {
        self.block_metrics.decode_failures()
    }

    pub(crate) fn ensure_live(&self) -> FsResult<()> {
        if self.is_dead() {
            Err(FsError::Io)
        } else {
            Ok(())
        }
    }

    fn mark_fenced(&self) {
        if !self.dead.swap(true, Ordering::AcqRel) {
            tracing::error!(
                fsid = %format!("{:016x}", self.superblock.fsid),
                "volume fenced by newer SlateDB writer; marking export dead"
            );
            self.dead_notify.notify_waiters();
        }
    }

    fn mark_degraded(&self, error: &str) {
        let errors = self.storage_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.degraded.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                fsid = %format!("{:016x}", self.superblock.fsid),
                storage_errors = errors,
                error = %error,
                "volume degraded after storage error"
            );
        } else {
            tracing::debug!(
                fsid = %format!("{:016x}", self.superblock.fsid),
                storage_errors = errors,
                error = %error,
                "volume storage error while degraded"
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

    pub(crate) fn note_storage_error(&self, error: &slatedb::Error) {
        if is_fenced_slatedb_error(error) {
            self.mark_fenced();
        } else {
            self.mark_degraded(&error.to_string());
        }
    }

    pub(crate) fn note_core_error(&self, error: &Error) {
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

    pub(crate) fn map_storage<T>(
        &self,
        result: std::result::Result<T, slatedb::Error>,
    ) -> FsResult<T> {
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

    pub(crate) fn map_core<T>(&self, result: Result<T>) -> FsResult<T> {
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

    /// Flush acknowledged writes to durable storage (DD-7).
    pub async fn flush(&self) -> Result<()> {
        self.db.flush().await.map_err(|error| {
            self.note_storage_error(&error);
            Error::from(error)
        })
    }

    /// Stop serving and close the underlying Db. Named to avoid colliding
    /// with `Vfs::close(handle)`.
    pub async fn shutdown(&self) -> Result<()> {
        self.db.close().await.map_err(|error| {
            self.note_storage_error(&error);
            Error::from(error)
        })
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

    /// Create a checkpoint from the live writer. This is the online snapshot
    /// primitive: it flushes WALs and freezes the current memtable through the
    /// open `Db`, so all writes issued before the call are included without
    /// taking a second writer lease.
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
            .await
            .map_err(|error| {
                self.note_storage_error(&error);
                Error::from(error)
            })?;
        Ok(CreatedSnapshot {
            id: created.id.to_string(),
            manifest_id: created.manifest_id,
            name,
        })
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
