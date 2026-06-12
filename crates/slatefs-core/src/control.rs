//! Control-plane DB (plan §5 "Control-plane DB"): tenants, volumes, wrapped
//! keys, quota limits. A small SlateDB at `<root>/control`, block-encrypted
//! with its own DEK; that DEK is wrapped directly by the master KMS and stored
//! as a raw object at `<root>/control.dek` (it can't live inside the DB it
//! unlocks).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use slatedb::object_store::{ObjectStore, PutMode, PutOptions};
use slatedb::{Db, Settings};

use crate::config::Compression;
use crate::crypto::kms::{Kms, contexts};
use crate::crypto::transformer::SlateBlockTransformer;
use crate::crypto::{Cipher, Secret32};
use crate::error::{Error, Result};
use crate::meta::{decode_versioned, encode_versioned};
use crate::store;

const CONTROL_KEYFILE_VERSION: u8 = 1;
const TENANT_RECORD_VERSION: u8 = 1;
const VOLUME_RECORD_VERSION: u8 = 1;

/// Contents of `<root>/control.dek`. The cipher is recorded here (not chosen
/// per process) so every node opens the control DB with the same AEAD.
#[derive(Serialize, Deserialize)]
struct ControlKeyFile {
    cipher: Cipher,
    wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantState {
    Active,
    Suspended,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRecord {
    pub name: String,
    pub display_name: Option<String>,
    pub state: TenantState,
    /// Tenant KEK wrapped by the master KMS, context `tenant_kek(name)`.
    pub wrapped_kek: Vec<u8>,
    /// Unix seconds.
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeState {
    /// Record committed, mkfs not yet completed. A retried create resumes
    /// with the recorded DEK instead of generating a new one (a fresh DEK
    /// could not read blocks written by the failed attempt).
    Creating,
    Active,
    Deleting,
}

/// Soft/hard structure reserved now per plan §12; enforcement of `soft` and
/// `grace_until` is Phase 6.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaLimit {
    pub soft: Option<u64>,
    pub hard: Option<u64>,
    /// Unix seconds.
    pub grace_until: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaLimits {
    pub bytes: QuotaLimit,
    pub inodes: QuotaLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub tenant: String,
    pub name: String,
    pub state: VolumeState,
    pub fsid: u64,
    /// Volume DEK wrapped by the tenant KEK, context `volume_dek(t, v)`.
    pub wrapped_dek: Vec<u8>,
    pub cipher: Cipher,
    pub chunk_size: u32,
    pub compression: Compression,
    pub quota: QuotaLimits,
    /// Free-form operator note. Also exercised by the no-plaintext-at-rest
    /// tests, which write a marker here and scan the bucket for it.
    pub note: Option<String>,
    /// Unix seconds.
    pub created_at: u64,
}

fn tenant_key(name: &str) -> String {
    format!("t/{name}")
}

fn volume_key(tenant: &str, volume: &str) -> String {
    format!("v/{tenant}/{volume}")
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct ControlPlane {
    db: Db,
    kms: Arc<dyn Kms>,
}

impl ControlPlane {
    /// Open (initializing on first use) the control DB.
    ///
    /// Concurrency note: SlateDB's writer fencing means two processes opening
    /// the control DB fence each other; the control plane is effectively
    /// single-admin at a time, which is fine for Phase 0 CLI use.
    pub async fn open(object_store: Arc<dyn ObjectStore>, kms: Arc<dyn Kms>) -> Result<Self> {
        let (cipher, dek) = Self::load_or_init_dek(&object_store, kms.as_ref()).await?;
        let db = Db::builder(store::CONTROL_DB_PATH, object_store)
            .with_settings(Settings {
                compression_codec: Some(slatedb::config::CompressionCodec::Lz4),
                ..Settings::default()
            })
            .with_block_transformer(Arc::new(SlateBlockTransformer::new(cipher, dek)))
            .build()
            .await?;
        Ok(ControlPlane { db, kms })
    }

    /// Fetch the wrapped control DEK, generating it on first run. Uses a
    /// conditional put (`PutMode::Create`) so two racing initializers can't
    /// clobber each other — overwriting an established `control.dek` would
    /// permanently brick the control DB.
    async fn load_or_init_dek(
        object_store: &Arc<dyn ObjectStore>,
        kms: &dyn Kms,
    ) -> Result<(Cipher, Secret32)> {
        let path = store::control_dek_path();

        let read_existing = |bytes: Vec<u8>| -> Result<ControlKeyFile> {
            decode_versioned(CONTROL_KEYFILE_VERSION, &bytes)
        };

        match object_store.get(&path).await {
            Ok(result) => {
                let keyfile = read_existing(result.bytes().await?.to_vec())?;
                let dek = kms
                    .unwrap(&keyfile.wrapped_dek, contexts::CONTROL_DEK)
                    .await?;
                Ok((keyfile.cipher, dek))
            }
            Err(slatedb::object_store::Error::NotFound { .. }) => {
                let cipher = Cipher::auto_select();
                let dek = Secret32::generate();
                let keyfile = ControlKeyFile {
                    cipher,
                    wrapped_dek: kms.wrap(&dek, contexts::CONTROL_DEK).await?,
                };
                let payload = encode_versioned(CONTROL_KEYFILE_VERSION, &keyfile)?;
                let put = object_store
                    .put_opts(&path, payload.into(), PutOptions::from(PutMode::Create))
                    .await;
                match put {
                    Ok(_) => {
                        tracing::info!(cipher = %cipher, kms = kms.name(), "initialized control-plane DEK");
                        Ok((cipher, dek))
                    }
                    Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                        // Lost the race; adopt the winner's keyfile.
                        let bytes = object_store.get(&path).await?.bytes().await?;
                        let keyfile = read_existing(bytes.to_vec())?;
                        let dek = kms
                            .unwrap(&keyfile.wrapped_dek, contexts::CONTROL_DEK)
                            .await?;
                        Ok((keyfile.cipher, dek))
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.db.close().await.map_err(Error::from)
    }

    // ---- tenants ----

    pub async fn create_tenant(
        &self,
        name: &str,
        display_name: Option<String>,
    ) -> Result<TenantRecord> {
        store::validate_name("tenant name", name)?;
        if self.try_get_tenant(name).await?.is_some() {
            return Err(Error::already_exists("tenant", name));
        }
        let kek = Secret32::generate();
        let record = TenantRecord {
            name: name.to_string(),
            display_name,
            state: TenantState::Active,
            wrapped_kek: self.kms.wrap(&kek, &contexts::tenant_kek(name)).await?,
            created_at: now_unix(),
        };
        self.db
            .put(
                tenant_key(name).as_bytes(),
                encode_versioned(TENANT_RECORD_VERSION, &record)?,
            )
            .await?;
        Ok(record)
    }

    pub async fn try_get_tenant(&self, name: &str) -> Result<Option<TenantRecord>> {
        match self.db.get(tenant_key(name).as_bytes()).await? {
            Some(bytes) => Ok(Some(decode_versioned(TENANT_RECORD_VERSION, &bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_tenant(&self, name: &str) -> Result<TenantRecord> {
        self.try_get_tenant(name)
            .await?
            .ok_or_else(|| Error::not_found("tenant", name))
    }

    pub async fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        let mut iter = self.db.scan_prefix(b"t/".as_slice()).await?;
        let mut tenants = Vec::new();
        while let Some(kv) = iter.next().await? {
            tenants.push(decode_versioned(TENANT_RECORD_VERSION, &kv.value)?);
        }
        Ok(tenants)
    }

    /// Unwrap a tenant's KEK via the master KMS.
    pub async fn unwrap_tenant_kek(&self, tenant: &TenantRecord) -> Result<Secret32> {
        self.kms
            .unwrap(&tenant.wrapped_kek, &contexts::tenant_kek(&tenant.name))
            .await
    }

    // ---- volumes (control records; mkfs/open live in volume.rs) ----

    pub async fn put_volume(&self, record: &VolumeRecord) -> Result<()> {
        self.db
            .put(
                volume_key(&record.tenant, &record.name).as_bytes(),
                encode_versioned(VOLUME_RECORD_VERSION, record)?,
            )
            .await?;
        Ok(())
    }

    pub async fn try_get_volume(&self, tenant: &str, volume: &str) -> Result<Option<VolumeRecord>> {
        match self.db.get(volume_key(tenant, volume).as_bytes()).await? {
            Some(bytes) => Ok(Some(decode_versioned(VOLUME_RECORD_VERSION, &bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_volume(&self, tenant: &str, volume: &str) -> Result<VolumeRecord> {
        self.try_get_volume(tenant, volume)
            .await?
            .ok_or_else(|| Error::not_found("volume", format!("{tenant}/{volume}")))
    }

    pub async fn list_volumes(&self, tenant: &str) -> Result<Vec<VolumeRecord>> {
        let prefix = format!("v/{tenant}/");
        let mut iter = self.db.scan_prefix(prefix.as_bytes()).await?;
        let mut volumes = Vec::new();
        while let Some(kv) = iter.next().await? {
            volumes.push(decode_versioned(VOLUME_RECORD_VERSION, &kv.value)?);
        }
        Ok(volumes)
    }

    /// Unwrap a volume's DEK: master KMS → tenant KEK → volume DEK (DD-8).
    pub async fn unwrap_volume_dek(&self, record: &VolumeRecord) -> Result<Secret32> {
        let tenant = self.get_tenant(&record.tenant).await?;
        let kek = self.unwrap_tenant_kek(&tenant).await?;
        crate::crypto::aead::unwrap_key(
            &kek,
            &contexts::volume_dek(&record.tenant, &record.name),
            &record.wrapped_dek,
        )
    }
}
