//! Control-plane DB (plan §5 "Control-plane DB"): tenants, volumes, wrapped
//! keys, quota limits. A small SlateDB at `<root>/control`, block-encrypted
//! with its own DEK; that DEK is wrapped directly by the master KMS and stored
//! as a raw object at `<root>/control.dek` (it can't live inside the DB it
//! unlocks).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};
use slatedb::object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions};
use slatedb::{Db, DbReader, Settings, WriteBatch, config::DbReaderOptions};

use crate::config::{
    AtimeMode, ClientAddrRule, Compression, ExportConfig, ExportProtocol, SquashMode,
    validate_export_config,
};
use crate::crypto::kms::{Kms, contexts};
use crate::crypto::transformer::SlateBlockTransformer;
use crate::crypto::{Cipher, Secret32};
use crate::error::{Error, Result};
use crate::meta::{decode_versioned, encode_versioned};
use crate::rate::RateLimits;
use crate::store;

const CONTROL_KEYFILE_VERSION: u8 = 1;
const TENANT_RECORD_VERSION: u8 = 1;
const VOLUME_RECORD_VERSION: u8 = 1;
const DAEMON_NODE_RECORD_VERSION: u8 = 1;
const VOLUME_PLACEMENT_RECORD_VERSION: u8 = 1;
const EXPORT_RECORD_VERSION: u8 = 1;
const AUDIT_RECORD_VERSION: u8 = 1;
const SNAPSHOT_RETENTION_RECORD_VERSION: u8 = 1;
const MAX_AUDIT_DETAILS_BYTES: usize = 128 * 1024;
const MAX_AUDIT_PAGE_LIMIT: usize = 1_000;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeState {
    /// Record committed, mkfs not yet completed. A retried create resumes
    /// with the recorded DEK instead of generating a new one (a fresh DEK
    /// could not read blocks written by the failed attempt).
    Creating,
    Active,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneParent {
    pub tenant: String,
    pub volume: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRetentionPolicy {
    pub tenant: String,
    pub volume: String,
    pub keep_last: Option<u32>,
    pub max_age_secs: Option<u64>,
    /// Unix seconds.
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub tenant: String,
    pub name: String,
    pub state: VolumeState,
    /// Instant clones share source SSTs; keep this so source deletion can
    /// refuse to orphan active clones.
    pub clone_parent: Option<CloneParent>,
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

/// Health state last reported for a serving daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonNodeState {
    Healthy,
    Draining,
    Unhealthy,
    Offline,
}

impl DaemonNodeState {
    fn is_placeable(self) -> bool {
        matches!(self, DaemonNodeState::Healthy)
    }
}

/// Controller-visible daemon load snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonMetrics {
    pub open_writable_volumes: u32,
    pub open_read_replicas: u32,
    pub open_snapshot_exports: u32,
    pub request_ops_per_second: u64,
    pub request_bytes_per_second: u64,
    pub storage_errors: u64,
    pub degraded_volumes: u32,
}

/// Durable record for one SlateFS daemon that can own writable volumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonNodeRecord {
    pub id: String,
    pub state: DaemonNodeState,
    /// Operator-facing endpoint for this daemon, usually a private address or
    /// service name. Per-volume stable endpoints below point at node ids.
    pub advertise_endpoint: Option<String>,
    /// Optional loopback/admin endpoint as seen by the controller.
    pub admin_endpoint: Option<String>,
    /// Optional Prometheus scrape endpoint.
    pub metrics_endpoint: Option<String>,
    /// Relative capacity for placement. A node with weight 2 can carry about
    /// twice as much balanced load as a node with weight 1.
    pub capacity_weight: u32,
    pub metrics: DaemonMetrics,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_heartbeat_at: Option<u64>,
}

/// Stable client-facing endpoint for a volume. Moving a volume changes only
/// the target node and generation; clients keep using the same address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableEndpointRecord {
    pub name: String,
    pub protocol: ExportProtocol,
    pub address: String,
    pub target_node: Option<String>,
    pub generation: u64,
    pub updated_at: u64,
}

/// Read-only replica placement for read-heavy volumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReplicaRecord {
    pub node_id: String,
    pub lag_seconds: Option<u64>,
    pub updated_at: u64,
}

/// Pool of daemons allowed to serve snapshots for one volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotServingPoolRecord {
    pub name: String,
    pub node_ids: Vec<String>,
    pub max_exports: u32,
    pub updated_at: u64,
}

/// Durable live export definition managed by the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRecord {
    pub id: String,
    pub tenant: String,
    pub volume: String,
    pub snapshot: Option<String>,
    pub protocol: ExportProtocol,
    pub listen: String,
    pub allowed_clients: Vec<ClientAddrRule>,
    pub squash: SquashMode,
    pub atime: AtimeMode,
    pub anon_uid: u32,
    pub anon_gid: u32,
    pub p9_token: Option<String>,
    pub p9_tls_cert: Option<std::path::PathBuf>,
    pub p9_tls_key: Option<std::path::PathBuf>,
    pub enabled: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

impl ExportRecord {
    pub fn from_config(id: impl Into<String>, config: ExportConfig, enabled: bool) -> Self {
        let now = now_unix();
        Self {
            id: id.into(),
            tenant: config.tenant,
            volume: config.volume,
            snapshot: config.snapshot,
            protocol: config.protocol,
            listen: config.listen,
            allowed_clients: config.allowed_clients,
            squash: config.squash,
            atime: config.atime,
            anon_uid: config.anon_uid,
            anon_gid: config.anon_gid,
            p9_token: config.p9_token,
            p9_tls_cert: config.p9_tls_cert,
            p9_tls_key: config.p9_tls_key,
            enabled,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn to_config(&self) -> ExportConfig {
        ExportConfig {
            tenant: self.tenant.clone(),
            volume: self.volume.clone(),
            snapshot: self.snapshot.clone(),
            listen: self.listen.clone(),
            allowed_clients: self.allowed_clients.clone(),
            protocol: self.protocol,
            p9_token: self.p9_token.clone(),
            p9_tls_cert: self.p9_tls_cert.clone(),
            p9_tls_key: self.p9_tls_key.clone(),
            squash: self.squash,
            atime: self.atime,
            anon_uid: self.anon_uid,
            anon_gid: self.anon_gid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumePlacementState {
    Unassigned,
    Active,
    Draining,
}

/// In-progress or recently completed drain/rebalance operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeDrainRecord {
    pub from_node: String,
    pub to_node: String,
    pub started_at: u64,
    pub completed_at: Option<u64>,
}

/// Durable placement state for one volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumePlacementRecord {
    pub tenant: String,
    pub volume: String,
    pub state: VolumePlacementState,
    pub primary_node: Option<String>,
    pub standby_nodes: Vec<String>,
    pub stable_endpoints: Vec<StableEndpointRecord>,
    pub read_replicas: Vec<ReadReplicaRecord>,
    pub snapshot_pools: Vec<SnapshotServingPoolRecord>,
    pub drain: Option<VolumeDrainRecord>,
    pub generation: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Control plane that emitted the audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditPlane {
    Admin,
    Nfs,
    P9,
    Cli,
}

/// Best-effort identity before a real auth system exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActor {
    pub plane: AuditPlane,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub client_agent: Option<String>,
}

/// Typed action name used for audit filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    TenantCreate,
    TenantUpdate,
    TenantDelete,
    VolumeCreate,
    VolumeDelete,
    SnapshotCreate,
    SnapshotDelete,
    SnapshotRetentionDelete,
    PlacementAssign,
    PlacementMove,
    PlacementClaim,
    NodeRegister,
    NodeDrain,
    NodeRemove,
    ExportCreate,
    ExportUpdate,
    ExportDelete,
    QuotaSet,
    TenantRateSet,
    LimitsChange,
    Maintain,
    AuthDenied,
    QuotaRejected,
}

impl AuditAction {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "TenantCreate" => Self::TenantCreate,
            "TenantUpdate" => Self::TenantUpdate,
            "TenantDelete" => Self::TenantDelete,
            "VolumeCreate" => Self::VolumeCreate,
            "VolumeDelete" => Self::VolumeDelete,
            "SnapshotCreate" => Self::SnapshotCreate,
            "SnapshotDelete" => Self::SnapshotDelete,
            "SnapshotRetentionDelete" => Self::SnapshotRetentionDelete,
            "PlacementAssign" => Self::PlacementAssign,
            "PlacementMove" => Self::PlacementMove,
            "PlacementClaim" => Self::PlacementClaim,
            "NodeRegister" => Self::NodeRegister,
            "NodeDrain" => Self::NodeDrain,
            "NodeRemove" => Self::NodeRemove,
            "ExportCreate" => Self::ExportCreate,
            "ExportUpdate" => Self::ExportUpdate,
            "ExportDelete" => Self::ExportDelete,
            "QuotaSet" => Self::QuotaSet,
            "TenantRateSet" => Self::TenantRateSet,
            "LimitsChange" => Self::LimitsChange,
            "Maintain" => Self::Maintain,
            "AuthDenied" => Self::AuthDenied,
            "QuotaRejected" => Self::QuotaRejected,
            _ => return None,
        })
    }
}

/// Audit action outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Denied,
    Failed { reason: String },
}

/// Postcard-friendly JSON-like value used inside audit details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditDetailValue {
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
    Array(Vec<AuditDetailValue>),
    Object(BTreeMap<String, AuditDetailValue>),
}

impl From<serde_json::Value> for AuditDetailValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(value) => Self::Bool(value),
            serde_json::Value::Number(value) => {
                if let Some(value) = value.as_u64() {
                    Self::U64(value)
                } else if let Some(value) = value.as_i64() {
                    Self::I64(value)
                } else if let Some(value) = value.as_f64() {
                    Self::F64(value)
                } else {
                    Self::Null
                }
            }
            serde_json::Value::String(value) => Self::String(value),
            serde_json::Value::Array(values) => {
                Self::Array(values.into_iter().map(Self::from).collect())
            }
            serde_json::Value::Object(values) => Self::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, Self::from(value)))
                    .collect(),
            ),
        }
    }
}

/// Scope attached to an audit event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditScope {
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub volume: Option<String>,
    #[serde(default)]
    pub node: Option<String>,
}

/// Durable audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    /// Unix time in nanoseconds. This is the primary ordering field.
    pub time: u64,
    pub actor: AuditActor,
    pub action: AuditAction,
    pub scope: AuditScope,
    pub request_id: String,
    pub outcome: AuditOutcome,
    #[serde(default)]
    pub details: BTreeMap<String, AuditDetailValue>,
}

impl AuditRecord {
    pub fn new(
        actor: AuditActor,
        action: AuditAction,
        scope: AuditScope,
        request_id: impl Into<String>,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            id: String::new(),
            time: 0,
            actor,
            action,
            scope,
            request_id: request_id.into(),
            outcome,
            details: BTreeMap::new(),
        }
    }
}

/// Audit query filter. `since` and `until` use Unix nanoseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditQuery<'a> {
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub tenant: Option<&'a str>,
    pub volume: Option<&'a str>,
    pub node: Option<&'a str>,
    pub action: Option<AuditAction>,
    pub limit: usize,
    pub page_token: Option<&'a str>,
    pub newest_first: bool,
}

impl VolumePlacementRecord {
    fn unassigned(tenant: &str, volume: &str, now: u64) -> Self {
        Self {
            tenant: tenant.to_string(),
            volume: volume.to_string(),
            state: VolumePlacementState::Unassigned,
            primary_node: None,
            standby_nodes: Vec::new(),
            stable_endpoints: Vec::new(),
            read_replicas: Vec::new(),
            snapshot_pools: Vec::new(),
            drain: None,
            generation: 1,
            created_at: now,
            updated_at: now,
        }
    }
}

fn tenant_key(name: &str) -> String {
    format!("t/{name}")
}

fn volume_key(tenant: &str, volume: &str) -> String {
    format!("v/{tenant}/{volume}")
}

fn daemon_node_key(id: &str) -> String {
    format!("dn/{id}")
}

fn volume_placement_key(tenant: &str, volume: &str) -> String {
    format!("vp/{tenant}/{volume}")
}

fn export_key(id: &str) -> String {
    format!("e/{id}")
}

fn snapshot_retention_key(tenant: &str, volume: &str) -> String {
    format!("sr/{tenant}/{volume}")
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct ControlPlane {
    db: Db,
    object_store: Arc<dyn ObjectStore>,
    kms: Arc<dyn Kms>,
    audit_seq: AtomicU32,
}

/// Read-only control-plane handle for daemon admin inventory and health checks.
pub struct ControlReader {
    db: DbReader,
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
        let db = Db::builder(store::CONTROL_DB_PATH, Arc::clone(&object_store))
            .with_settings(Settings {
                compression_codec: Some(slatedb::config::CompressionCodec::Lz4),
                ..Settings::default()
            })
            .with_block_transformer(Arc::new(SlateBlockTransformer::new(cipher, dek)))
            .build()
            .await?;
        Ok(ControlPlane {
            db,
            object_store,
            kms,
            audit_seq: AtomicU32::new(0),
        })
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

        match object_store.get(&path).await {
            Ok(result) => Self::decode_control_dek(result.bytes().await?.to_vec(), kms).await,
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
                        Self::decode_control_dek(bytes.to_vec(), kms).await
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn load_existing_dek(
        object_store: &Arc<dyn ObjectStore>,
        kms: &dyn Kms,
    ) -> Result<(Cipher, Secret32)> {
        let bytes = object_store
            .get(&store::control_dek_path())
            .await?
            .bytes()
            .await?;
        Self::decode_control_dek(bytes.to_vec(), kms).await
    }

    async fn decode_control_dek(bytes: Vec<u8>, kms: &dyn Kms) -> Result<(Cipher, Secret32)> {
        let keyfile: ControlKeyFile = decode_versioned(CONTROL_KEYFILE_VERSION, &bytes)?;
        let dek = kms
            .unwrap(&keyfile.wrapped_dek, contexts::CONTROL_DEK)
            .await?;
        Ok((keyfile.cipher, dek))
    }

    pub async fn close(&self) -> Result<()> {
        self.db.close().await.map_err(Error::from)
    }

    /// Append one durable audit record under the ordered audit keyspace.
    pub async fn append_audit_record(&self, record: AuditRecord) -> Result<AuditRecord> {
        Ok(self.append_audit_records([record]).await?.remove(0))
    }

    /// Append a batch of durable audit records.
    pub async fn append_audit_records<I>(&self, records: I) -> Result<Vec<AuditRecord>>
    where
        I: IntoIterator<Item = AuditRecord>,
    {
        let mut batch = WriteBatch::new();
        let mut appended = Vec::new();
        for record in records {
            let (timestamp, seq, key) = self.next_audit_key(record.time).await?;
            let mut record = bounded_audit_record(record);
            record.time = timestamp;
            record.id = audit_id(timestamp, seq);
            batch.put(key, encode_versioned(AUDIT_RECORD_VERSION, &record)?);
            appended.push(record);
        }
        if !appended.is_empty() {
            self.db.write(batch).await?;
        }
        Ok(appended)
    }

    /// Query audit records by time range and optional scope/action filters.
    pub async fn list_audit(
        &self,
        query: AuditQuery<'_>,
    ) -> Result<(Vec<AuditRecord>, Option<String>)> {
        list_audit_from_db(&self.db, query).await
    }

    async fn next_audit_key(&self, requested_time: u64) -> Result<(u64, u32, Vec<u8>)> {
        let mut timestamp = if requested_time == 0 {
            now_unix_nanos()
        } else {
            requested_time
        };
        loop {
            let mut seq = self.audit_seq.fetch_add(1, Ordering::Relaxed);
            for _ in 0..1024 {
                let key = audit_key(timestamp, seq);
                if self.db.get(&key).await?.is_none() {
                    return Ok((timestamp, seq, key));
                }
                seq = seq.wrapping_add(1);
            }
            timestamp = now_unix_nanos().max(timestamp.saturating_add(1));
        }
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
        let mut iter = self.db.scan_prefix(b"t/".as_slice(), ..).await?;
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

    /// Rotate one tenant KEK by rewrapping every active volume DEK.
    ///
    /// Data blocks are not rewritten: volume DEKs remain stable, and only the
    /// encrypted DEK envelopes in the control plane change.
    pub async fn rotate_tenant_kek(&self, name: &str) -> Result<usize> {
        store::validate_name("tenant name", name)?;
        let mut tenant = self.get_tenant(name).await?;
        if tenant.state == TenantState::Deleting {
            return Err(Error::invalid(
                "tenant state",
                format!("tenant {name:?} is Deleting and cannot be rotated"),
            ));
        }

        let old_kek = self.unwrap_tenant_kek(&tenant).await?;
        let new_kek = Secret32::generate();
        let mut volumes = self.list_volumes(name).await?;
        let mut rewrapped = 0usize;
        for volume in &mut volumes {
            if volume.state == VolumeState::Deleting {
                continue;
            }
            if volume.wrapped_dek.is_empty() {
                return Err(Error::invalid(
                    "volume key",
                    format!(
                        "volume {}/{} has been crypto-shredded",
                        volume.tenant, volume.name
                    ),
                ));
            }
            let context = contexts::volume_dek(&volume.tenant, &volume.name);
            let dek = crate::crypto::aead::unwrap_key(&old_kek, &context, &volume.wrapped_dek)?;
            volume.wrapped_dek = crate::crypto::aead::wrap_key(&new_kek, &context, &dek)?;
            rewrapped += 1;
        }
        tenant.wrapped_kek = self.kms.wrap(&new_kek, &contexts::tenant_kek(name)).await?;

        let mut batch = WriteBatch::new();
        batch.put(
            tenant_key(name).as_bytes(),
            encode_versioned(TENANT_RECORD_VERSION, &tenant)?,
        );
        for volume in &volumes {
            batch.put(
                volume_key(&volume.tenant, &volume.name).as_bytes(),
                encode_versioned(VOLUME_RECORD_VERSION, volume)?,
            );
        }
        self.db.write(batch).await?;
        Ok(rewrapped)
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
        let mut iter = self.db.scan_prefix(prefix.as_bytes(), ..).await?;
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
        let active_clones: Vec<_> = self
            .list_volumes(tenant)
            .await?
            .into_iter()
            .filter(|candidate| candidate.state != VolumeState::Deleting)
            .filter(|candidate| {
                candidate
                    .clone_parent
                    .as_ref()
                    .is_some_and(|parent| parent.tenant == tenant && parent.volume == volume)
            })
            .map(|candidate| candidate.name)
            .collect();
        if !active_clones.is_empty() {
            return Err(Error::invalid(
                "volume delete",
                format!(
                    "volume {tenant}/{volume} has active clones: {}",
                    active_clones.join(", ")
                ),
            ));
        }
        record.state = VolumeState::Deleting;
        record.wrapped_dek.clear();
        self.put_volume(&record).await?;
        self.clear_snapshot_retention_policy(tenant, volume).await?;
        self.delete_volume_placement(tenant, volume).await?;
        let objects_deleted = self.delete_volume_objects(tenant, volume).await?;
        tracing::info!(
            tenant,
            volume,
            objects_deleted,
            "deleted volume object-store prefix"
        );
        Ok(record)
    }

    /// Mark a tenant deleted, crypto-shredding every volume DEK and finally
    /// the tenant KEK in the current control-plane state. Idempotent for
    /// already-deleting tenants.
    pub async fn delete_tenant(&self, name: &str) -> Result<TenantRecord> {
        store::validate_name("tenant name", name)?;
        let mut tenant = self.get_tenant(name).await?;
        let volumes = self.list_volumes(name).await?;
        for mut volume in volumes.clone() {
            volume.state = VolumeState::Deleting;
            volume.wrapped_dek.clear();
            self.put_volume(&volume).await?;
            self.clear_snapshot_retention_policy(name, &volume.name)
                .await?;
            self.delete_volume_placement(name, &volume.name).await?;
        }
        tenant.state = TenantState::Deleting;
        tenant.wrapped_kek.clear();
        self.db
            .put(
                tenant_key(name).as_bytes(),
                encode_versioned(TENANT_RECORD_VERSION, &tenant)?,
            )
            .await?;
        let mut objects_deleted = 0usize;
        for volume in volumes {
            objects_deleted += self.delete_volume_objects(name, &volume.name).await?;
        }
        tracing::info!(
            tenant = name,
            objects_deleted,
            "deleted tenant volume object-store prefixes"
        );
        Ok(tenant)
    }

    async fn delete_volume_objects(&self, tenant: &str, volume: &str) -> Result<usize> {
        let prefix = store::volume_db_prefix(tenant, volume);
        store::delete_prefix(&self.object_store, &prefix).await
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

    // ---- per-volume snapshot retention ----

    pub async fn put_snapshot_retention_policy(
        &self,
        policy: &SnapshotRetentionPolicy,
    ) -> Result<()> {
        validate_snapshot_retention_policy(policy)?;
        self.get_volume(&policy.tenant, &policy.volume).await?;
        self.db
            .put(
                snapshot_retention_key(&policy.tenant, &policy.volume).as_bytes(),
                encode_versioned(SNAPSHOT_RETENTION_RECORD_VERSION, policy)?,
            )
            .await?;
        Ok(())
    }

    pub async fn set_snapshot_retention_policy(
        &self,
        tenant: &str,
        volume: &str,
        keep_last: Option<u32>,
        max_age_secs: Option<u64>,
    ) -> Result<SnapshotRetentionPolicy> {
        let mut policy = SnapshotRetentionPolicy {
            tenant: tenant.to_string(),
            volume: volume.to_string(),
            keep_last,
            max_age_secs,
            updated_at: now_unix(),
        };
        validate_snapshot_retention_policy(&policy)?;
        self.get_volume(tenant, volume).await?;
        if let Some(existing) = self
            .try_get_snapshot_retention_policy(tenant, volume)
            .await?
        {
            policy.updated_at = now_unix().max(existing.updated_at);
        }
        self.put_snapshot_retention_policy(&policy).await?;
        Ok(policy)
    }

    pub async fn try_get_snapshot_retention_policy(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<SnapshotRetentionPolicy>> {
        match self
            .db
            .get(snapshot_retention_key(tenant, volume).as_bytes())
            .await?
        {
            Some(bytes) => Ok(Some(decode_snapshot_retention_policy(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_snapshot_retention_policy(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<SnapshotRetentionPolicy> {
        self.try_get_snapshot_retention_policy(tenant, volume)
            .await?
            .ok_or_else(|| {
                Error::not_found("snapshot retention policy", format!("{tenant}/{volume}"))
            })
    }

    pub async fn clear_snapshot_retention_policy(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<SnapshotRetentionPolicy>> {
        self.get_volume(tenant, volume).await?;
        let existing = self
            .try_get_snapshot_retention_policy(tenant, volume)
            .await?;
        if existing.is_some() {
            let mut batch = WriteBatch::new();
            batch.delete(snapshot_retention_key(tenant, volume).into_bytes());
            self.db.write(batch).await?;
        }
        Ok(existing)
    }

    pub async fn list_snapshot_retention_policies(&self) -> Result<Vec<SnapshotRetentionPolicy>> {
        let mut iter = self.db.scan_prefix(b"sr/".as_slice(), ..).await?;
        let mut policies = Vec::new();
        while let Some(kv) = iter.next().await? {
            policies.push(decode_snapshot_retention_policy(&kv.value)?);
        }
        policies.sort_by(|a, b| {
            a.tenant
                .cmp(&b.tenant)
                .then_with(|| a.volume.cmp(&b.volume))
        });
        Ok(policies)
    }

    // ---- exports (control-plane managed live export definitions) ----

    pub async fn create_export(&self, mut record: ExportRecord) -> Result<ExportRecord> {
        validate_export_record_fields(&record)?;
        if self.try_get_export(&record.id).await?.is_some() {
            return Err(Error::already_exists("export", &record.id));
        }
        self.get_volume(&record.tenant, &record.volume).await?;
        let now = now_unix();
        record.created_at = now;
        record.updated_at = now;
        self.put_export(&record).await?;
        Ok(record)
    }

    pub async fn update_export(&self, mut record: ExportRecord) -> Result<ExportRecord> {
        validate_export_record_fields(&record)?;
        let existing = self.get_export(&record.id).await?;
        self.get_volume(&record.tenant, &record.volume).await?;
        record.created_at = existing.created_at;
        record.updated_at = now_unix();
        self.put_export(&record).await?;
        Ok(record)
    }

    pub async fn enable_export(&self, id: &str) -> Result<ExportRecord> {
        self.set_export_enabled(id, true).await
    }

    pub async fn disable_export(&self, id: &str) -> Result<ExportRecord> {
        self.set_export_enabled(id, false).await
    }

    async fn set_export_enabled(&self, id: &str, enabled: bool) -> Result<ExportRecord> {
        store::validate_name("export id", id)?;
        let mut record = self.get_export(id).await?;
        record.enabled = enabled;
        record.updated_at = now_unix();
        self.put_export(&record).await?;
        Ok(record)
    }

    pub async fn remove_export(&self, id: &str) -> Result<ExportRecord> {
        store::validate_name("export id", id)?;
        let record = self.get_export(id).await?;
        let mut batch = WriteBatch::new();
        batch.delete(export_key(id).into_bytes());
        self.db.write(batch).await?;
        Ok(record)
    }

    pub async fn put_export(&self, record: &ExportRecord) -> Result<()> {
        validate_export_record_fields(record)?;
        self.db
            .put(
                export_key(&record.id).as_bytes(),
                encode_versioned(EXPORT_RECORD_VERSION, record)?,
            )
            .await?;
        Ok(())
    }

    pub async fn try_get_export(&self, id: &str) -> Result<Option<ExportRecord>> {
        match self.db.get(export_key(id).as_bytes()).await? {
            Some(bytes) => Ok(Some(decode_export_record(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_export(&self, id: &str) -> Result<ExportRecord> {
        self.try_get_export(id)
            .await?
            .ok_or_else(|| Error::not_found("export", id))
    }

    pub async fn list_exports(&self) -> Result<Vec<ExportRecord>> {
        let mut iter = self.db.scan_prefix(b"e/".as_slice(), ..).await?;
        let mut exports = Vec::new();
        while let Some(kv) = iter.next().await? {
            exports.push(decode_export_record(&kv.value)?);
        }
        exports.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(exports)
    }

    // ---- fleet placement (nodes, stable endpoints, failover, drain) ----

    pub async fn register_daemon_node(
        &self,
        id: &str,
        advertise_endpoint: Option<String>,
        admin_endpoint: Option<String>,
        metrics_endpoint: Option<String>,
        capacity_weight: u32,
    ) -> Result<DaemonNodeRecord> {
        store::validate_name("daemon node id", id)?;
        validate_capacity_weight(capacity_weight)?;

        let now = now_unix();
        let record = match self.try_get_daemon_node(id).await? {
            Some(mut record) => {
                record.advertise_endpoint = advertise_endpoint;
                record.admin_endpoint = admin_endpoint;
                record.metrics_endpoint = metrics_endpoint;
                record.capacity_weight = capacity_weight;
                record.updated_at = now;
                record
            }
            None => DaemonNodeRecord {
                id: id.to_string(),
                state: DaemonNodeState::Healthy,
                advertise_endpoint,
                admin_endpoint,
                metrics_endpoint,
                capacity_weight,
                metrics: DaemonMetrics::default(),
                created_at: now,
                updated_at: now,
                last_heartbeat_at: Some(now),
            },
        };
        self.put_daemon_node(&record).await?;
        Ok(record)
    }

    pub async fn try_get_daemon_node(&self, id: &str) -> Result<Option<DaemonNodeRecord>> {
        match self.db.get(daemon_node_key(id).as_bytes()).await? {
            Some(bytes) => Ok(Some(decode_versioned(DAEMON_NODE_RECORD_VERSION, &bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_daemon_node(&self, id: &str) -> Result<DaemonNodeRecord> {
        self.try_get_daemon_node(id)
            .await?
            .ok_or_else(|| Error::not_found("daemon node", id))
    }

    pub async fn put_daemon_node(&self, record: &DaemonNodeRecord) -> Result<()> {
        self.db
            .put(
                daemon_node_key(&record.id).as_bytes(),
                encode_versioned(DAEMON_NODE_RECORD_VERSION, record)?,
            )
            .await?;
        Ok(())
    }

    pub async fn list_daemon_nodes(&self) -> Result<Vec<DaemonNodeRecord>> {
        let mut iter = self.db.scan_prefix(b"dn/".as_slice(), ..).await?;
        let mut nodes: Vec<DaemonNodeRecord> = Vec::new();
        while let Some(kv) = iter.next().await? {
            nodes.push(decode_versioned(DAEMON_NODE_RECORD_VERSION, &kv.value)?);
        }
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(nodes)
    }

    pub async fn record_daemon_health_at(
        &self,
        id: &str,
        state: DaemonNodeState,
        metrics: DaemonMetrics,
        observed_at: u64,
    ) -> Result<DaemonNodeRecord> {
        store::validate_name("daemon node id", id)?;
        let now = now_unix();
        let mut record = self
            .try_get_daemon_node(id)
            .await?
            .unwrap_or_else(|| DaemonNodeRecord {
                id: id.to_string(),
                state,
                advertise_endpoint: None,
                admin_endpoint: None,
                metrics_endpoint: None,
                capacity_weight: 1,
                metrics: DaemonMetrics::default(),
                created_at: now,
                updated_at: now,
                last_heartbeat_at: None,
            });
        record.state = state;
        record.metrics = metrics;
        record.last_heartbeat_at = Some(observed_at);
        record.updated_at = now;
        self.put_daemon_node(&record).await?;
        Ok(record)
    }

    pub async fn heartbeat_daemon_node(
        &self,
        id: &str,
        state: DaemonNodeState,
        metrics: DaemonMetrics,
    ) -> Result<DaemonNodeRecord> {
        self.record_daemon_health_at(id, state, metrics, now_unix())
            .await
    }

    pub async fn mark_stale_daemon_nodes(
        &self,
        heartbeat_timeout_secs: u64,
    ) -> Result<Vec<DaemonNodeRecord>> {
        if heartbeat_timeout_secs == 0 {
            return Err(Error::invalid(
                "heartbeat timeout",
                "timeout must be greater than 0",
            ));
        }

        let now = now_unix();
        let mut stale = Vec::new();
        for mut node in self.list_daemon_nodes().await? {
            if matches!(
                node.state,
                DaemonNodeState::Healthy | DaemonNodeState::Draining
            ) {
                let observed = node.last_heartbeat_at.unwrap_or(node.created_at);
                if now.saturating_sub(observed) > heartbeat_timeout_secs {
                    node.state = DaemonNodeState::Unhealthy;
                    node.updated_at = now;
                    self.put_daemon_node(&node).await?;
                    stale.push(node);
                }
            }
        }
        Ok(stale)
    }

    pub async fn try_get_volume_placement(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<VolumePlacementRecord>> {
        match self
            .db
            .get(volume_placement_key(tenant, volume).as_bytes())
            .await?
        {
            Some(bytes) => Ok(Some(decode_versioned(
                VOLUME_PLACEMENT_RECORD_VERSION,
                &bytes,
            )?)),
            None => Ok(None),
        }
    }

    pub async fn get_volume_placement(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<VolumePlacementRecord> {
        self.try_get_volume_placement(tenant, volume)
            .await?
            .ok_or_else(|| Error::not_found("volume placement", format!("{tenant}/{volume}")))
    }

    pub async fn put_volume_placement(&self, record: &VolumePlacementRecord) -> Result<()> {
        self.db
            .put(
                volume_placement_key(&record.tenant, &record.volume).as_bytes(),
                encode_versioned(VOLUME_PLACEMENT_RECORD_VERSION, record)?,
            )
            .await?;
        Ok(())
    }

    pub async fn list_volume_placements(&self) -> Result<Vec<VolumePlacementRecord>> {
        let mut iter = self.db.scan_prefix(b"vp/".as_slice(), ..).await?;
        let mut placements: Vec<VolumePlacementRecord> = Vec::new();
        while let Some(kv) = iter.next().await? {
            placements.push(decode_versioned(
                VOLUME_PLACEMENT_RECORD_VERSION,
                &kv.value,
            )?);
        }
        placements.sort_by(|a, b| {
            a.tenant
                .cmp(&b.tenant)
                .then_with(|| a.volume.cmp(&b.volume))
        });
        Ok(placements)
    }

    pub async fn delete_volume_placement(&self, tenant: &str, volume: &str) -> Result<()> {
        let mut batch = WriteBatch::new();
        batch.delete(volume_placement_key(tenant, volume).into_bytes());
        self.db.write(batch).await?;
        Ok(())
    }

    pub async fn assign_volume_to_low_load_node(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<VolumePlacementRecord> {
        let node_id = self.choose_low_load_node(&[]).await?;
        self.assign_volume_to_node(tenant, volume, &node_id).await
    }

    pub async fn ensure_volume_placement(
        &self,
        record: &VolumeRecord,
    ) -> Result<Option<VolumePlacementRecord>> {
        if let Some(existing) = self
            .try_get_volume_placement(&record.tenant, &record.name)
            .await?
        {
            return Ok(Some(existing));
        }
        if self.list_daemon_nodes().await?.is_empty() {
            return Ok(None);
        }
        let node_id = match self.choose_low_load_node(&[]).await {
            Ok(node_id) => node_id,
            Err(Error::Invalid { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.assign_volume_to_node(&record.tenant, &record.name, &node_id)
            .await
            .map(Some)
    }

    pub async fn assign_volume_to_node(
        &self,
        tenant: &str,
        volume: &str,
        node_id: &str,
    ) -> Result<VolumePlacementRecord> {
        self.get_mountable_volume(tenant, volume).await?;
        let node = self.get_daemon_node(node_id).await?;
        if !node.state.is_placeable() {
            return Err(Error::invalid(
                "daemon node state",
                format!("node {node_id:?} is {:?}, not Healthy", node.state),
            ));
        }

        let now = now_unix();
        let mut placement = self
            .try_get_volume_placement(tenant, volume)
            .await?
            .unwrap_or_else(|| VolumePlacementRecord::unassigned(tenant, volume, now));
        placement.primary_node = Some(node_id.to_string());
        placement.state = VolumePlacementState::Active;
        placement.drain = None;
        placement.generation = placement.generation.saturating_add(1);
        placement.updated_at = now;
        placement.standby_nodes = self.standby_nodes_for(node_id).await?;
        move_stable_endpoints(&mut placement, Some(node_id), now);
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn set_volume_stable_endpoint(
        &self,
        tenant: &str,
        volume: &str,
        name: &str,
        protocol: ExportProtocol,
        address: String,
    ) -> Result<VolumePlacementRecord> {
        self.get_volume(tenant, volume).await?;
        store::validate_name("endpoint name", name)?;
        if address.trim().is_empty() {
            return Err(Error::invalid(
                "endpoint address",
                "address must not be empty",
            ));
        }

        let now = now_unix();
        let mut placement = self
            .try_get_volume_placement(tenant, volume)
            .await?
            .unwrap_or_else(|| VolumePlacementRecord::unassigned(tenant, volume, now));
        let primary = placement.primary_node.clone();
        match placement
            .stable_endpoints
            .iter_mut()
            .find(|endpoint| endpoint.name == name)
        {
            Some(endpoint) => {
                endpoint.protocol = protocol;
                endpoint.address = address;
                endpoint.target_node = primary;
                endpoint.generation = endpoint.generation.saturating_add(1);
                endpoint.updated_at = now;
            }
            None => placement.stable_endpoints.push(StableEndpointRecord {
                name: name.to_string(),
                protocol,
                address,
                target_node: primary,
                generation: 1,
                updated_at: now,
            }),
        }
        placement.updated_at = now;
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn promote_standby_on_failure(
        &self,
        tenant: &str,
        volume: &str,
        failed_node: &str,
    ) -> Result<VolumePlacementRecord> {
        let now = now_unix();
        let mut placement = self.get_volume_placement(tenant, volume).await?;
        if placement.primary_node.as_deref() != Some(failed_node) {
            return Err(Error::invalid(
                "failed primary",
                format!(
                    "volume {tenant}/{volume} primary is {:?}, not {failed_node:?}",
                    placement.primary_node
                ),
            ));
        }

        if let Some(mut failed) = self.try_get_daemon_node(failed_node).await? {
            failed.state = DaemonNodeState::Unhealthy;
            failed.updated_at = now;
            self.put_daemon_node(&failed).await?;
        }

        let promoted = if let Some(standby) = self.first_healthy_standby(&placement).await? {
            standby
        } else {
            match self.choose_low_load_node(&[failed_node]).await {
                Ok(node_id) => node_id,
                Err(Error::Invalid { .. }) => {
                    return Err(Error::invalid(
                        "standby promotion",
                        format!("no healthy standby or replacement for {tenant}/{volume}"),
                    ));
                }
                Err(error) => return Err(error),
            }
        };
        placement
            .standby_nodes
            .retain(|candidate| candidate != &promoted && candidate != failed_node);
        placement.primary_node = Some(promoted.clone());
        placement.state = VolumePlacementState::Active;
        placement.drain = None;
        placement.generation = placement.generation.saturating_add(1);
        placement.updated_at = now;
        let mut standbys = self.standby_nodes_for(&promoted).await?;
        standbys.retain(|candidate| candidate != failed_node);
        placement.standby_nodes = standbys;
        move_stable_endpoints(&mut placement, Some(&promoted), now);
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn start_volume_drain(
        &self,
        tenant: &str,
        volume: &str,
        target_node: Option<&str>,
    ) -> Result<VolumePlacementRecord> {
        let mut placement = self.get_volume_placement(tenant, volume).await?;
        let from_node = placement.primary_node.clone().ok_or_else(|| {
            Error::invalid(
                "volume placement",
                format!("volume {tenant}/{volume} has no primary node"),
            )
        })?;
        let to_node = match target_node {
            Some(node_id) => {
                let node = self.get_daemon_node(node_id).await?;
                if !node.state.is_placeable() {
                    return Err(Error::invalid(
                        "drain target",
                        format!("node {node_id:?} is {:?}, not Healthy", node.state),
                    ));
                }
                node_id.to_string()
            }
            None => self.choose_low_load_node(&[&from_node]).await?,
        };
        if from_node == to_node {
            return Err(Error::invalid(
                "drain target",
                "target node must differ from current primary",
            ));
        }

        let now = now_unix();
        placement.state = VolumePlacementState::Draining;
        placement.drain = Some(VolumeDrainRecord {
            from_node,
            to_node,
            started_at: now,
            completed_at: None,
        });
        placement.updated_at = now;
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn complete_volume_drain(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<VolumePlacementRecord> {
        let now = now_unix();
        let mut placement = self.get_volume_placement(tenant, volume).await?;
        let mut drain = placement.drain.clone().ok_or_else(|| {
            Error::invalid(
                "volume drain",
                format!("volume {tenant}/{volume} is not draining"),
            )
        })?;
        let target = self.get_daemon_node(&drain.to_node).await?;
        if !target.state.is_placeable() {
            return Err(Error::invalid(
                "drain target",
                format!("node {:?} is {:?}, not Healthy", target.id, target.state),
            ));
        }

        placement.primary_node = Some(drain.to_node.clone());
        placement.state = VolumePlacementState::Active;
        drain.completed_at = Some(now);
        placement.drain = Some(drain.clone());
        placement.generation = placement.generation.saturating_add(1);
        placement.updated_at = now;
        let mut standbys = self.standby_nodes_for(&drain.to_node).await?;
        if !standbys.contains(&drain.from_node) {
            standbys.push(drain.from_node);
        }
        placement.standby_nodes = standbys;
        move_stable_endpoints(&mut placement, Some(&drain.to_node), now);
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn add_read_replica(
        &self,
        tenant: &str,
        volume: &str,
        node_id: &str,
        lag_seconds: Option<u64>,
    ) -> Result<VolumePlacementRecord> {
        self.get_volume(tenant, volume).await?;
        let node = self.get_daemon_node(node_id).await?;
        if !node.state.is_placeable() {
            return Err(Error::invalid(
                "read replica node",
                format!("node {node_id:?} is {:?}, not Healthy", node.state),
            ));
        }

        let now = now_unix();
        let mut placement = self
            .try_get_volume_placement(tenant, volume)
            .await?
            .unwrap_or_else(|| VolumePlacementRecord::unassigned(tenant, volume, now));
        if let Some(replica) = placement
            .read_replicas
            .iter_mut()
            .find(|replica| replica.node_id == node_id)
        {
            replica.lag_seconds = lag_seconds;
            replica.updated_at = now;
        } else {
            placement.read_replicas.push(ReadReplicaRecord {
                node_id: node_id.to_string(),
                lag_seconds,
                updated_at: now,
            });
        }
        placement.updated_at = now;
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn remove_read_replica(
        &self,
        tenant: &str,
        volume: &str,
        node_id: &str,
    ) -> Result<VolumePlacementRecord> {
        let now = now_unix();
        let mut placement = self.get_volume_placement(tenant, volume).await?;
        placement
            .read_replicas
            .retain(|replica| replica.node_id != node_id);
        placement.updated_at = now;
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn set_snapshot_serving_pool(
        &self,
        tenant: &str,
        volume: &str,
        name: &str,
        node_ids: Vec<String>,
        max_exports: u32,
    ) -> Result<VolumePlacementRecord> {
        self.get_volume(tenant, volume).await?;
        store::validate_name("snapshot pool name", name)?;
        if node_ids.is_empty() {
            return Err(Error::invalid(
                "snapshot pool",
                "at least one node is required",
            ));
        }
        if max_exports == 0 {
            return Err(Error::invalid(
                "snapshot pool",
                "max_exports must be greater than 0",
            ));
        }
        let mut unique = HashSet::new();
        for node_id in &node_ids {
            if !unique.insert(node_id.clone()) {
                return Err(Error::invalid(
                    "snapshot pool",
                    format!("duplicate node {node_id:?}"),
                ));
            }
            let node = self.get_daemon_node(node_id).await?;
            if !node.state.is_placeable() {
                return Err(Error::invalid(
                    "snapshot pool node",
                    format!("node {node_id:?} is {:?}, not Healthy", node.state),
                ));
            }
        }

        let now = now_unix();
        let mut placement = self
            .try_get_volume_placement(tenant, volume)
            .await?
            .unwrap_or_else(|| VolumePlacementRecord::unassigned(tenant, volume, now));
        if let Some(pool) = placement
            .snapshot_pools
            .iter_mut()
            .find(|pool| pool.name == name)
        {
            pool.node_ids = node_ids;
            pool.max_exports = max_exports;
            pool.updated_at = now;
        } else {
            placement.snapshot_pools.push(SnapshotServingPoolRecord {
                name: name.to_string(),
                node_ids,
                max_exports,
                updated_at: now,
            });
        }
        placement.updated_at = now;
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    pub async fn remove_snapshot_serving_pool(
        &self,
        tenant: &str,
        volume: &str,
        name: &str,
    ) -> Result<VolumePlacementRecord> {
        let now = now_unix();
        let mut placement = self.get_volume_placement(tenant, volume).await?;
        placement.snapshot_pools.retain(|pool| pool.name != name);
        placement.updated_at = now;
        self.put_volume_placement(&placement).await?;
        Ok(placement)
    }

    async fn choose_low_load_node(&self, excluded: &[&str]) -> Result<String> {
        let nodes = self.list_daemon_nodes().await?;
        let excluded: HashSet<&str> = excluded.iter().copied().collect();
        if nodes.is_empty() {
            return Err(Error::invalid(
                "fleet placement",
                "no daemon nodes are registered",
            ));
        }

        let assignment_counts = self.primary_assignment_counts().await?;
        nodes
            .into_iter()
            .filter(|node| node.state.is_placeable())
            .filter(|node| !excluded.contains(node.id.as_str()))
            .map(|node| {
                let assigned = assignment_counts.get(&node.id).copied().unwrap_or(0);
                let score = node_load_score(&node, assigned);
                (score, node.id)
            })
            .min_by(|(score_a, id_a), (score_b, id_b)| {
                score_a.cmp(score_b).then_with(|| id_a.cmp(id_b))
            })
            .map(|(_, id)| id)
            .ok_or_else(|| Error::invalid("fleet placement", "no healthy daemon nodes available"))
    }

    async fn standby_nodes_for(&self, primary_node: &str) -> Result<Vec<String>> {
        let assignment_counts = self.primary_assignment_counts().await?;
        let mut candidates: Vec<_> = self
            .list_daemon_nodes()
            .await?
            .into_iter()
            .filter(|node| node.state.is_placeable() && node.id != primary_node)
            .map(|node| {
                let assigned = assignment_counts.get(&node.id).copied().unwrap_or(0);
                let score = node_load_score(&node, assigned);
                (score, node.id)
            })
            .collect();
        candidates.sort_by(|(score_a, id_a), (score_b, id_b)| {
            score_a.cmp(score_b).then_with(|| id_a.cmp(id_b))
        });
        Ok(candidates.into_iter().map(|(_, id)| id).collect())
    }

    async fn first_healthy_standby(
        &self,
        placement: &VolumePlacementRecord,
    ) -> Result<Option<String>> {
        for standby in &placement.standby_nodes {
            if self
                .try_get_daemon_node(standby)
                .await?
                .is_some_and(|node| node.state.is_placeable())
            {
                return Ok(Some(standby.clone()));
            }
        }
        Ok(None)
    }

    async fn primary_assignment_counts(&self) -> Result<HashMap<String, u32>> {
        let mut counts = HashMap::new();
        for placement in self.list_volume_placements().await? {
            if !matches!(
                placement.state,
                VolumePlacementState::Active | VolumePlacementState::Draining
            ) {
                continue;
            }
            if let Some(node_id) = placement.primary_node {
                *counts.entry(node_id).or_insert(0) += 1;
            }
        }
        Ok(counts)
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

impl ControlReader {
    /// Open the encrypted control DB in read-only mode.
    pub async fn open(object_store: Arc<dyn ObjectStore>, kms: Arc<dyn Kms>) -> Result<Self> {
        let (cipher, dek) = ControlPlane::load_existing_dek(&object_store, kms.as_ref()).await?;
        let db = DbReader::builder(store::CONTROL_DB_PATH, object_store)
            .with_options(DbReaderOptions {
                manifest_poll_interval: std::time::Duration::from_secs(1),
                checkpoint_lifetime: std::time::Duration::from_secs(60),
                ..DbReaderOptions::default()
            })
            .with_block_transformer(Arc::new(SlateBlockTransformer::new(cipher, dek)))
            .build()
            .await?;
        Ok(Self { db, kms })
    }

    pub async fn close(&self) -> Result<()> {
        self.db.close().await.map_err(Error::from)
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

    pub async fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        let mut iter = self.db.scan_prefix(b"t/".as_slice(), ..).await?;
        let mut tenants = Vec::new();
        while let Some(kv) = iter.next().await? {
            tenants.push(decode_tenant_record(&kv.value)?);
        }
        tenants.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(tenants)
    }

    pub async fn try_get_volume(&self, tenant: &str, volume: &str) -> Result<Option<VolumeRecord>> {
        match self.db.get(volume_key(tenant, volume).as_bytes()).await? {
            Some(bytes) => Ok(Some(decode_volume_record(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_volume(&self, tenant: &str, volume: &str) -> Result<VolumeRecord> {
        self.try_get_volume(tenant, volume)
            .await?
            .ok_or_else(|| Error::not_found("volume", format!("{tenant}/{volume}")))
    }

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

    pub async fn list_volumes(&self, tenant: &str) -> Result<Vec<VolumeRecord>> {
        let prefix = format!("v/{tenant}/");
        let mut iter = self.db.scan_prefix(prefix.as_bytes(), ..).await?;
        let mut volumes = Vec::new();
        while let Some(kv) = iter.next().await? {
            volumes.push(decode_volume_record(&kv.value)?);
        }
        volumes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(volumes)
    }

    pub async fn try_get_snapshot_retention_policy(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<SnapshotRetentionPolicy>> {
        match self
            .db
            .get(snapshot_retention_key(tenant, volume).as_bytes())
            .await?
        {
            Some(bytes) => Ok(Some(decode_snapshot_retention_policy(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn list_snapshot_retention_policies(&self) -> Result<Vec<SnapshotRetentionPolicy>> {
        let mut iter = self.db.scan_prefix(b"sr/".as_slice(), ..).await?;
        let mut policies = Vec::new();
        while let Some(kv) = iter.next().await? {
            policies.push(decode_snapshot_retention_policy(&kv.value)?);
        }
        policies.sort_by(|a, b| {
            a.tenant
                .cmp(&b.tenant)
                .then_with(|| a.volume.cmp(&b.volume))
        });
        Ok(policies)
    }

    pub async fn list_daemon_nodes(&self) -> Result<Vec<DaemonNodeRecord>> {
        let mut iter = self.db.scan_prefix(b"dn/".as_slice(), ..).await?;
        let mut nodes = Vec::new();
        while let Some(kv) = iter.next().await? {
            nodes.push(decode_daemon_node_record(&kv.value)?);
        }
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(nodes)
    }

    pub async fn try_get_volume_placement(
        &self,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<VolumePlacementRecord>> {
        match self
            .db
            .get(volume_placement_key(tenant, volume).as_bytes())
            .await?
        {
            Some(bytes) => Ok(Some(decode_volume_placement_record(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn list_volume_placements(&self) -> Result<Vec<VolumePlacementRecord>> {
        let mut iter = self.db.scan_prefix(b"vp/".as_slice(), ..).await?;
        let mut placements = Vec::new();
        while let Some(kv) = iter.next().await? {
            placements.push(decode_volume_placement_record(&kv.value)?);
        }
        placements.sort_by(|a, b| {
            a.tenant
                .cmp(&b.tenant)
                .then_with(|| a.volume.cmp(&b.volume))
        });
        Ok(placements)
    }

    pub async fn try_get_export(&self, id: &str) -> Result<Option<ExportRecord>> {
        match self.db.get(export_key(id).as_bytes()).await? {
            Some(bytes) => Ok(Some(decode_export_record(&bytes)?)),
            None => Ok(None),
        }
    }

    pub async fn get_export(&self, id: &str) -> Result<ExportRecord> {
        self.try_get_export(id)
            .await?
            .ok_or_else(|| Error::not_found("export", id))
    }

    pub async fn list_exports(&self) -> Result<Vec<ExportRecord>> {
        let mut iter = self.db.scan_prefix(b"e/".as_slice(), ..).await?;
        let mut exports = Vec::new();
        while let Some(kv) = iter.next().await? {
            exports.push(decode_export_record(&kv.value)?);
        }
        exports.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(exports)
    }

    pub async fn list_audit(
        &self,
        query: AuditQuery<'_>,
    ) -> Result<(Vec<AuditRecord>, Option<String>)> {
        list_audit_from_reader(&self.db, query).await
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

fn validate_snapshot_retention_policy(policy: &SnapshotRetentionPolicy) -> Result<()> {
    store::validate_name("tenant name", &policy.tenant)?;
    store::validate_name("volume name", &policy.volume)?;
    if policy.keep_last.is_none() && policy.max_age_secs.is_none() {
        return Err(Error::invalid(
            "snapshot retention policy",
            "keep_last or max_age_secs is required",
        ));
    }
    Ok(())
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

fn validate_capacity_weight(capacity_weight: u32) -> Result<()> {
    if capacity_weight == 0 {
        return Err(Error::invalid(
            "daemon node capacity",
            "capacity_weight must be greater than 0",
        ));
    }
    Ok(())
}

fn validate_export_record_fields(record: &ExportRecord) -> Result<()> {
    store::validate_name("export id", &record.id)?;
    store::validate_name("tenant name", &record.tenant)?;
    store::validate_name("volume name", &record.volume)?;
    if record.snapshot.as_deref().is_some_and(str::is_empty) {
        return Err(Error::invalid(
            "export snapshot",
            "snapshot id must not be empty",
        ));
    }
    if record.listen.trim().is_empty() {
        return Err(Error::invalid(
            "export listen",
            "listen address must not be empty",
        ));
    }
    record
        .listen
        .parse::<std::net::SocketAddr>()
        .map_err(|error| Error::invalid("export listen", error.to_string()))?;
    validate_export_config(&record.to_config()).map_err(|error| match error {
        Error::Config(message) => Error::invalid("export config", message),
        error => error,
    })
}

fn node_load_score(node: &DaemonNodeRecord, assigned_primary_volumes: u32) -> u128 {
    let metrics = node.metrics;
    let writable = assigned_primary_volumes.max(metrics.open_writable_volumes) as u128;
    let read = metrics.open_read_replicas as u128;
    let snapshots = metrics.open_snapshot_exports as u128;
    let request_ops = metrics.request_ops_per_second as u128;
    let request_kib = (metrics.request_bytes_per_second / 1024) as u128;
    let storage_errors = metrics.storage_errors as u128;
    let degraded = metrics.degraded_volumes as u128;
    let raw = writable * 1_000_000
        + read * 250_000
        + snapshots * 100_000
        + request_ops
        + request_kib
        + storage_errors * 10_000
        + degraded * 500_000;
    raw / node.capacity_weight.max(1) as u128
}

fn move_stable_endpoints(
    placement: &mut VolumePlacementRecord,
    target_node: Option<&str>,
    now: u64,
) {
    for endpoint in &mut placement.stable_endpoints {
        endpoint.target_node = target_node.map(str::to_string);
        endpoint.generation = endpoint.generation.saturating_add(1);
        endpoint.updated_at = now;
    }
}

fn decode_tenant_record(bytes: &[u8]) -> Result<TenantRecord> {
    decode_versioned(TENANT_RECORD_VERSION, bytes)
}

fn decode_volume_record(bytes: &[u8]) -> Result<VolumeRecord> {
    decode_versioned(VOLUME_RECORD_VERSION, bytes)
}

fn decode_daemon_node_record(bytes: &[u8]) -> Result<DaemonNodeRecord> {
    decode_versioned(DAEMON_NODE_RECORD_VERSION, bytes)
}

fn decode_volume_placement_record(bytes: &[u8]) -> Result<VolumePlacementRecord> {
    decode_versioned(VOLUME_PLACEMENT_RECORD_VERSION, bytes)
}

fn decode_export_record(bytes: &[u8]) -> Result<ExportRecord> {
    decode_versioned(EXPORT_RECORD_VERSION, bytes)
}

fn decode_snapshot_retention_policy(bytes: &[u8]) -> Result<SnapshotRetentionPolicy> {
    decode_versioned(SNAPSHOT_RETENTION_RECORD_VERSION, bytes)
}

fn decode_audit_record(bytes: &[u8]) -> Result<AuditRecord> {
    decode_versioned(AUDIT_RECORD_VERSION, bytes)
}

fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

async fn list_audit_from_db(
    db: &Db,
    query: AuditQuery<'_>,
) -> Result<(Vec<AuditRecord>, Option<String>)> {
    let mut iter = db.scan_prefix(b"a/".as_slice(), ..).await?;
    let mut records = Vec::new();
    while let Some(kv) = iter.next().await? {
        let Some((time, _)) = parse_audit_key(kv.key.as_ref()) else {
            continue;
        };
        if !audit_time_matches(time, &query) {
            continue;
        }
        let record = decode_audit_record(&kv.value)?;
        if audit_record_matches(&record, &query) {
            records.push(record);
        }
    }
    page_audit_records(records, query)
}

async fn list_audit_from_reader(
    db: &DbReader,
    query: AuditQuery<'_>,
) -> Result<(Vec<AuditRecord>, Option<String>)> {
    let mut iter = db.scan_prefix(b"a/".as_slice(), ..).await?;
    let mut records = Vec::new();
    while let Some(kv) = iter.next().await? {
        let Some((time, _)) = parse_audit_key(kv.key.as_ref()) else {
            continue;
        };
        if !audit_time_matches(time, &query) {
            continue;
        }
        let record = decode_audit_record(&kv.value)?;
        if audit_record_matches(&record, &query) {
            records.push(record);
        }
    }
    page_audit_records(records, query)
}

fn audit_time_matches(time: u64, query: &AuditQuery<'_>) -> bool {
    if query.since.is_some_and(|since| time < since) {
        return false;
    }
    if query.until.is_some_and(|until| time > until) {
        return false;
    }
    true
}

fn audit_record_matches(record: &AuditRecord, query: &AuditQuery<'_>) -> bool {
    if query
        .tenant
        .is_some_and(|tenant| record.scope.tenant.as_deref() != Some(tenant))
    {
        return false;
    }
    if query
        .volume
        .is_some_and(|volume| record.scope.volume.as_deref() != Some(volume))
    {
        return false;
    }
    if query
        .node
        .is_some_and(|node| record.scope.node.as_deref() != Some(node))
    {
        return false;
    }
    if query.action.is_some_and(|action| record.action != action) {
        return false;
    }
    true
}

fn page_audit_records(
    mut records: Vec<AuditRecord>,
    query: AuditQuery<'_>,
) -> Result<(Vec<AuditRecord>, Option<String>)> {
    if query.newest_first {
        records.reverse();
    }
    let limit = if query.limit == 0 {
        100
    } else {
        query.limit.min(MAX_AUDIT_PAGE_LIMIT)
    };
    let mut started = query.page_token.is_none();
    let mut page = Vec::new();
    let mut next = None;
    for record in records {
        if !started {
            if query.page_token == Some(record.id.as_str()) {
                started = true;
            }
            continue;
        }
        if page.len() == limit {
            next = page.last().map(|record: &AuditRecord| record.id.clone());
            break;
        }
        page.push(record);
    }
    Ok((page, next))
}

fn bounded_audit_record(mut record: AuditRecord) -> AuditRecord {
    let Ok(encoded) = postcard::to_allocvec(&record.details) else {
        record.details = audit_truncation_details(0);
        return record;
    };
    if encoded.len() <= MAX_AUDIT_DETAILS_BYTES {
        return record;
    }
    record.details = audit_truncation_details(encoded.len() as u64);
    record
}

fn audit_truncation_details(original_bytes: u64) -> BTreeMap<String, AuditDetailValue> {
    let mut details = BTreeMap::new();
    details.insert("details_truncated".to_owned(), AuditDetailValue::Bool(true));
    details.insert(
        "original_details_bytes".to_owned(),
        AuditDetailValue::U64(original_bytes),
    );
    details
}

fn audit_key(timestamp: u64, seq: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(15);
    key.extend_from_slice(b"a/");
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.push(b'/');
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn parse_audit_key(key: &[u8]) -> Option<(u64, u32)> {
    if key.len() != 15 || &key[..2] != b"a/" || key[10] != b'/' {
        return None;
    }
    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&key[2..10]);
    let mut seq = [0u8; 4];
    seq.copy_from_slice(&key[11..15]);
    Some((u64::from_be_bytes(timestamp), u32::from_be_bytes(seq)))
}

fn audit_id(timestamp: u64, seq: u32) -> String {
    format!("{timestamp:016x}.{seq:08x}")
}
