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
use crate::rate::RateLimits;
use crate::store;

const CONTROL_KEYFILE_VERSION: u8 = 1;
const TENANT_RECORD_VERSION: u8 = 2;
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
    /// Tenant-scoped frontend admission limits (ops/s and request bytes/s).
    pub rate_limits: RateLimits,
    /// Tenant KEK wrapped by the master KMS, context `tenant_kek(name)`.
    pub wrapped_kek: Vec<u8>,
    /// Unix seconds.
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TenantRecordV1 {
    name: String,
    display_name: Option<String>,
    state: TenantState,
    wrapped_kek: Vec<u8>,
    created_at: u64,
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
            rate_limits: RateLimits::default(),
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
            Some(bytes) => Ok(Some(decode_tenant_record(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_tenant(&self, name: &str) -> Result<TenantRecord> {
        self.try_get_tenant(name)
            .await?
            .ok_or_else(|| Error::not_found("tenant", name))
    }

    pub async fn suspend_tenant(&self, name: &str) -> Result<TenantRecord> {
        self.set_tenant_state(name, TenantState::Suspended).await
    }

    pub async fn resume_tenant(&self, name: &str) -> Result<TenantRecord> {
        self.set_tenant_state(name, TenantState::Active).await
    }

    async fn set_tenant_state(&self, name: &str, next_state: TenantState) -> Result<TenantRecord> {
        store::validate_name("tenant name", name)?;
        let mut record = self.get_tenant(name).await?;
        if record.state == TenantState::Deleting && next_state != TenantState::Deleting {
            return Err(Error::invalid(
                "tenant state",
                format!("tenant {name:?} is Deleting and cannot be resumed"),
            ));
        }
        record.state = next_state;
        self.db
            .put(
                tenant_key(name).as_bytes(),
                encode_versioned(TENANT_RECORD_VERSION, &record)?,
            )
            .await?;
        Ok(record)
    }

    pub async fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        let mut iter = self.db.scan_prefix(b"t/".as_slice()).await?;
        let mut tenants = Vec::new();
        while let Some(kv) = iter.next().await? {
            tenants.push(decode_tenant_record(&kv.value)?);
        }
        Ok(tenants)
    }

    /// Unwrap a tenant's KEK via the master KMS.
    pub async fn unwrap_tenant_kek(&self, tenant: &TenantRecord) -> Result<Secret32> {
        if tenant.wrapped_kek.is_empty() {
            return Err(Error::invalid(
                "tenant key",
                format!("tenant {:?} has been crypto-shredded", tenant.name),
            ));
        }
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

    /// Mark one volume deleted and drop its wrapped DEK from the current
    /// control-plane state. Physical object-prefix cleanup is intentionally a
    /// separate storage operation; after this point normal SlateFS open paths
    /// cannot unwrap the volume key.
    pub async fn delete_volume(&self, tenant: &str, volume: &str) -> Result<VolumeRecord> {
        store::validate_name("tenant name", tenant)?;
        store::validate_name("volume name", volume)?;
        let mut record = self.get_volume(tenant, volume).await?;
        record.state = VolumeState::Deleting;
        record.wrapped_dek.clear();
        self.put_volume(&record).await?;
        Ok(record)
    }

    /// Mark a tenant deleted, crypto-shredding every volume DEK and finally
    /// the tenant KEK in the current control-plane state. Idempotent for
    /// already-deleting tenants.
    pub async fn delete_tenant(&self, name: &str) -> Result<TenantRecord> {
        store::validate_name("tenant name", name)?;
        let mut tenant = self.get_tenant(name).await?;
        for mut volume in self.list_volumes(name).await? {
            volume.state = VolumeState::Deleting;
            volume.wrapped_dek.clear();
            self.put_volume(&volume).await?;
        }
        tenant.state = TenantState::Deleting;
        tenant.wrapped_kek.clear();
        self.db
            .put(
                tenant_key(name).as_bytes(),
                encode_versioned(TENANT_RECORD_VERSION, &tenant)?,
            )
            .await?;
        Ok(tenant)
    }

    pub async fn set_tenant_rate_limits(
        &self,
        name: &str,
        rate_limits: RateLimits,
    ) -> Result<TenantRecord> {
        validate_rate_limits(&rate_limits)?;
        let mut record = self.get_tenant(name).await?;
        if record.state == TenantState::Deleting {
            return Err(Error::invalid(
                "tenant state",
                format!("tenant {name:?} is Deleting and cannot be updated"),
            ));
        }
        record.rate_limits = rate_limits;
        self.db
            .put(
                tenant_key(name).as_bytes(),
                encode_versioned(TENANT_RECORD_VERSION, &record)?,
            )
            .await?;
        Ok(record)
    }

    /// Resolve a volume for serving. This is the Phase 5 mount-time tenant
    /// lifecycle gate: suspended tenants keep their metadata and keys, but
    /// new daemon exports refuse to open them.
    pub async fn get_mountable_volume(&self, tenant: &str, volume: &str) -> Result<VolumeRecord> {
        let tenant_record = self.get_tenant(tenant).await?;
        if tenant_record.state != TenantState::Active {
            return Err(Error::invalid(
                "tenant state",
                format!("tenant {tenant:?} is {:?}, not Active", tenant_record.state),
            ));
        }
        let record = self.get_volume(tenant, volume).await?;
        if record.state != VolumeState::Active {
            return Err(Error::invalid(
                "volume state",
                format!("volume {tenant}/{volume} is {:?}, not Active", record.state),
            ));
        }
        Ok(record)
    }

    pub async fn set_volume_quota(
        &self,
        tenant: &str,
        volume: &str,
        quota: QuotaLimits,
    ) -> Result<VolumeRecord> {
        validate_quota_limits(&quota)?;
        let mut record = self.get_volume(tenant, volume).await?;
        record.quota = quota;
        self.put_volume(&record).await?;
        Ok(record)
    }

    /// Unwrap a volume's DEK: master KMS → tenant KEK → volume DEK (DD-8).
    pub async fn unwrap_volume_dek(&self, record: &VolumeRecord) -> Result<Secret32> {
        if record.wrapped_dek.is_empty() {
            return Err(Error::invalid(
                "volume key",
                format!(
                    "volume {}/{} has been crypto-shredded",
                    record.tenant, record.name
                ),
            ));
        }
        let tenant = self.get_tenant(&record.tenant).await?;
        let kek = self.unwrap_tenant_kek(&tenant).await?;
        crate::crypto::aead::unwrap_key(
            &kek,
            &contexts::volume_dek(&record.tenant, &record.name),
            &record.wrapped_dek,
        )
    }

    /// Server key that HMACs NFS file handles (plan §5) so handles can't be
    /// forged across tenants. Created lazily, shared by every node of the
    /// deployment, at rest only inside the encrypted control DB.
    pub async fn server_fh_key(&self) -> Result<Secret32> {
        const KEY: &[u8] = b"k/fhmac";
        if let Some(bytes) = self.db.get(KEY).await? {
            return Secret32::try_from_slice(&bytes);
        }
        let key = Secret32::generate();
        self.db.put(KEY, key.expose_secret()).await?;
        Ok(key)
    }
}

fn validate_limit(kind: &'static str, limit: &QuotaLimit) -> Result<()> {
    if let (Some(soft), Some(hard)) = (limit.soft, limit.hard)
        && soft > hard
    {
        return Err(Error::invalid(
            kind,
            format!("soft limit {soft} exceeds hard limit {hard}"),
        ));
    }
    if limit.grace_until.is_some() && limit.soft.is_none() {
        return Err(Error::invalid(
            kind,
            "grace_until requires a soft limit".to_string(),
        ));
    }
    Ok(())
}

fn validate_quota_limits(quota: &QuotaLimits) -> Result<()> {
    validate_limit("bytes quota", &quota.bytes)?;
    validate_limit("inodes quota", &quota.inodes)
}

fn validate_rate_limit(kind: &'static str, limit: Option<u64>) -> Result<()> {
    if matches!(limit, Some(0)) {
        return Err(Error::invalid(kind, "limit must be positive or none"));
    }
    Ok(())
}

fn validate_rate_limits(limits: &RateLimits) -> Result<()> {
    validate_rate_limit("ops rate limit", limits.ops_per_second)?;
    validate_rate_limit("bytes rate limit", limits.bytes_per_second)
}

fn decode_tenant_record(bytes: &[u8]) -> Result<TenantRecord> {
    match bytes.split_first() {
        Some((&TENANT_RECORD_VERSION, rest)) => Ok(postcard::from_bytes(rest)?),
        Some((&1, rest)) => {
            let old: TenantRecordV1 = postcard::from_bytes(rest)?;
            Ok(TenantRecord {
                name: old.name,
                display_name: old.display_name,
                state: old.state,
                rate_limits: RateLimits::default(),
                wrapped_kek: old.wrapped_kek,
                created_at: old.created_at,
            })
        }
        Some((&version, _)) => Err(Error::invalid(
            "tenant record",
            format!("format version {version}, expected {TENANT_RECORD_VERSION}"),
        )),
        None => Err(Error::invalid("tenant record", "empty value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_v1_records_decode_with_unlimited_rate_limits() {
        let old = TenantRecordV1 {
            name: "t1".to_string(),
            display_name: Some("Tenant One".to_string()),
            state: TenantState::Active,
            wrapped_kek: vec![1, 2, 3],
            created_at: 42,
        };
        let mut bytes = vec![1];
        bytes.extend(postcard::to_allocvec(&old).expect("encode old tenant"));

        let decoded = decode_tenant_record(&bytes).expect("decode old tenant");
        assert_eq!(decoded.name, "t1");
        assert_eq!(decoded.display_name.as_deref(), Some("Tenant One"));
        assert_eq!(decoded.state, TenantState::Active);
        assert_eq!(decoded.rate_limits, RateLimits::default());
        assert_eq!(decoded.wrapped_kek, vec![1, 2, 3]);
        assert_eq!(decoded.created_at, 42);
    }
}
