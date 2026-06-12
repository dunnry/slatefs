//! Volume lifecycle (DD-1: one SlateDB per volume). Phase 0 covers create
//! (`mkfs`) and info; open-for-serving, fencing handling, and caches arrive
//! with Phase 1+.

use std::sync::Arc;

use slatedb::object_store::ObjectStore;
use slatedb::{Db, DbReader, Settings};

use crate::config::{Compression, VolumeDefaults};
use crate::control::{ControlPlane, QuotaLimits, TenantState, VolumeRecord, VolumeState, now_unix};
use crate::crypto::kms::contexts;
use crate::crypto::transformer::SlateBlockTransformer;
use crate::crypto::{Cipher, Secret32, aead, random_u64};
use crate::error::{Error, Result};
use crate::meta::superblock::{KEY_SUPERBLOCK, Superblock};
use crate::store;

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

/// Write the volume's superblock through an encrypted, compressed Db.
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
                db.put(KEY_SUPERBLOCK, superblock.encode()?).await?;
                db.flush().await?;
            }
        }
        Ok(())
    }
    .await;

    db.close().await?;
    result
}

/// Open a volume's SlateDB as the (single) writer, with its block transformer
/// and compression wired per the control record.
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
