//! Opt-in, per-volume file versioning backed by Prolly trees.
//!
//! The live filesystem remains the existing mutable SlateDB volume. This
//! module opens a separate encrypted database only for explicit versioning
//! operations, so disabled volumes pay no storage or request-path cost.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bytes::Bytes;
use prolly::{
    AsyncBlobStore, AsyncProlly, AsyncStore, BatchOp, BlobRef, Cid, Config as ProllyConfig, Diff,
    Mutation, RootManifest, Tree, ValueRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slatedb::bytes::Bytes as SlateBytes;
use slatedb::object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, UpdateVersion};
use slatedb::{Db, Settings, WriteBatch};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::config::AtimeMode;
use crate::control::{ControlPlane, ControlReader, VolumeRecord};
use crate::crypto::transformer::SlateBlockTransformer;
use crate::error::{Error, Result};
use crate::meta::inode::{FileKind, ROOT_INO, Timespec};
use crate::store;
use crate::vfs::{Credentials, FileAttr, SetAttrs, TimeSet, Vfs};
use crate::volume::Volume;

const NODE_PREFIX: &[u8] = b"pn/";
const BLOB_PREFIX: &[u8] = b"pb/";
const COMMIT_PREFIX: &[u8] = b"pc/";
const IDEMPOTENCY_PREFIX: &[u8] = b"pi/";
const PRUNED_COMMIT_PREFIX: &[u8] = b"pp/";
const BRANCH_PREFIX: &[u8] = b"pr/heads/";
const HEAD_KEY: &[u8] = b"pr/heads/main";
const TAG_PREFIX: &[u8] = b"pr/tags/";
const ENTRY_META_VERSION: u8 = 1;
const COMMIT_VERSION: u8 = 1;
const IDEMPOTENCY_VERSION: u8 = 1;
const REF_VERSION: u8 = 1;
const TAG_VERSION: u8 = 1;
const MAINTENANCE_LEASE_VERSION: u8 = 1;
const MAINTENANCE_LEASE_TTL_SECS: u64 = 120;
const MAINTENANCE_LEASE_RENEW_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionMaintenanceLeaseInfo {
    tenant: String,
    volume: String,
    owner: String,
    operation: String,
    acquired_at: u64,
    expires_at: u64,
}

impl VersionMaintenanceLeaseInfo {
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn volume(&self) -> &str {
        &self.volume
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn acquired_at(&self) -> u64 {
        self.acquired_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at <= now
    }
}

/// Read the current or most recently released coordination lease without
/// opening the version repository. CAS-capable stores retain expired records;
/// local stores remove them on release.
pub async fn try_get_version_maintenance_lease(
    object_store: Arc<dyn ObjectStore>,
    tenant: &str,
    volume: &str,
) -> Result<Option<VersionMaintenanceLeaseInfo>> {
    store::validate_name("tenant name", tenant)?;
    store::validate_name("volume name", volume)?;
    let path = store::version_lease_path(tenant, volume);
    match object_store.get(&path).await {
        Ok(result) => {
            let bytes = result.bytes().await?;
            decode_versioned(
                MAINTENANCE_LEASE_VERSION,
                &bytes,
                "version maintenance lease",
            )
            .map(Some)
        }
        Err(slatedb::object_store::Error::NotFound { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Force an expired lease to become available again after the operator has
/// verified that its exact owner is no longer running. The expected owner
/// prevents clearing a different observed lease. Returns `false` when no lease
/// exists.
pub async fn force_break_expired_version_maintenance_lease(
    object_store: Arc<dyn ObjectStore>,
    tenant: &str,
    volume: &str,
    expected_owner: &str,
) -> Result<bool> {
    store::validate_name("tenant name", tenant)?;
    store::validate_name("volume name", volume)?;
    if expected_owner.is_empty() {
        return Err(Error::invalid("version lease owner", "must not be empty"));
    }
    let path = store::version_lease_path(tenant, volume);
    let current = match object_store.get(&path).await {
        Ok(current) => current,
        Err(slatedb::object_store::Error::NotFound { .. }) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let revision = UpdateVersion {
        e_tag: current.meta.e_tag.clone(),
        version: current.meta.version.clone(),
    };
    let mut record: VersionMaintenanceLeaseInfo = decode_versioned(
        MAINTENANCE_LEASE_VERSION,
        &current.bytes().await?,
        "version maintenance lease",
    )?;
    if record.owner != expected_owner {
        return Err(Error::invalid(
            "version lease owner",
            format!("expected {expected_owner}, found {}", record.owner),
        ));
    }
    let now = crate::control::now_unix();
    if !record.is_expired_at(now) {
        return Err(Error::invalid(
            "version maintenance lease",
            format!("lease is active until {}", record.expires_at),
        ));
    }
    record.operation = "operator-break".to_string();
    record.expires_at = 0;
    let payload = encode_versioned(MAINTENANCE_LEASE_VERSION, &record)?;
    match object_store
        .put_opts(
            &path,
            payload.into(),
            PutOptions::from(PutMode::Update(revision)),
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(slatedb::object_store::Error::Precondition { .. }) => Err(Error::already_exists(
            "version maintenance lease",
            format!("{tenant}/{volume} changed while breaking the observed lease"),
        )),
        Err(slatedb::object_store::Error::NotImplemented { .. }) => {
            match object_store.delete(&path).await {
                Ok(()) => Ok(true),
                Err(slatedb::object_store::Error::NotFound { .. }) => Ok(false),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone)]
struct VersionMaintenanceLease {
    object_store: Arc<dyn ObjectStore>,
    path: slatedb::object_store::path::Path,
    state: Arc<Mutex<VersionMaintenanceLeaseState>>,
}

struct VersionMaintenanceLeaseState {
    record: VersionMaintenanceLeaseInfo,
    revision: UpdateVersion,
    conditional_updates: bool,
}

impl VersionMaintenanceLease {
    async fn acquire(
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        owner: String,
        operation: &str,
    ) -> Result<Self> {
        let path = store::version_lease_path(tenant, volume);
        let now = crate::control::now_unix();
        let record = VersionMaintenanceLeaseInfo {
            tenant: tenant.to_string(),
            volume: volume.to_string(),
            owner,
            operation: operation.to_string(),
            acquired_at: now,
            expires_at: now.saturating_add(MAINTENANCE_LEASE_TTL_SECS),
        };
        let payload = encode_versioned(MAINTENANCE_LEASE_VERSION, &record)?;
        let result = match object_store
            .put_opts(
                &path,
                payload.clone().into(),
                PutOptions::from(PutMode::Create),
            )
            .await
        {
            Ok(result) => result,
            Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                let current = object_store.get(&path).await?;
                let revision = UpdateVersion {
                    e_tag: current.meta.e_tag.clone(),
                    version: current.meta.version.clone(),
                };
                let current_record: VersionMaintenanceLeaseInfo = decode_versioned(
                    MAINTENANCE_LEASE_VERSION,
                    &current.bytes().await?,
                    "version maintenance lease",
                )?;
                if current_record.expires_at > now {
                    return Err(Error::already_exists(
                        "version maintenance lease",
                        format!(
                            "{tenant}/{volume} held by {} for {} until {}",
                            current_record.owner,
                            current_record.operation,
                            current_record.expires_at
                        ),
                    ));
                }
                object_store
                    .put_opts(
                        &path,
                        payload.into(),
                        PutOptions::from(PutMode::Update(revision)),
                    )
                    .await
                    .map_err(|error| match error {
                        slatedb::object_store::Error::Precondition { .. } => Error::already_exists(
                            "version maintenance lease",
                            format!("{tenant}/{volume} changed during stale-lease takeover"),
                        ),
                        slatedb::object_store::Error::NotImplemented { .. } => {
                            Error::already_exists(
                                "version maintenance lease",
                                format!(
                                    "{tenant}/{volume} is expired, but this object store does not support safe automatic takeover"
                                ),
                            )
                        }
                        other => other.into(),
                    })?
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            object_store,
            path,
            state: Arc::new(Mutex::new(VersionMaintenanceLeaseState {
                record,
                revision: result.into(),
                conditional_updates: true,
            })),
        })
    }

    async fn renew(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        state.record.expires_at =
            crate::control::now_unix().saturating_add(MAINTENANCE_LEASE_TTL_SECS);
        let payload = encode_versioned(MAINTENANCE_LEASE_VERSION, &state.record)?;
        if !state.conditional_updates {
            return Ok(());
        }
        let result = match self
            .object_store
            .put_opts(
                &self.path,
                payload.into(),
                PutOptions::from(PutMode::Update(state.revision.clone())),
            )
            .await
        {
            Ok(result) => result,
            Err(slatedb::object_store::Error::NotImplemented { .. }) => {
                state.conditional_updates = false;
                return Ok(());
            }
            Err(error) => {
                return Err(match error {
                    slatedb::object_store::Error::Precondition { .. } => {
                        Error::Versioning("version maintenance lease was lost".to_string())
                    }
                    other => other.into(),
                });
            }
        };
        state.revision = result.into();
        Ok(())
    }

    async fn release(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if !state.conditional_updates {
            return self
                .object_store
                .delete(&self.path)
                .await
                .map_err(Error::from);
        }
        state.record.expires_at = 0;
        let payload = encode_versioned(MAINTENANCE_LEASE_VERSION, &state.record)?;
        match self
            .object_store
            .put_opts(
                &self.path,
                payload.into(),
                PutOptions::from(PutMode::Update(state.revision.clone())),
            )
            .await
        {
            Ok(result) => {
                state.revision = result.into();
                Ok(())
            }
            Err(slatedb::object_store::Error::Precondition { .. }) => Ok(()),
            Err(slatedb::object_store::Error::NotImplemented { .. }) => {
                state.conditional_updates = false;
                self.object_store
                    .delete(&self.path)
                    .await
                    .map_err(Error::from)
            }
            Err(error) => Err(error.into()),
        }
    }
}

struct VersionMaintenanceGuard {
    stop: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<Result<()>>>>,
}

impl VersionMaintenanceGuard {
    async fn acquire(
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        operation: &str,
    ) -> Result<Self> {
        let owner = uuid::Uuid::new_v4().to_string();
        let lease =
            VersionMaintenanceLease::acquire(object_store, tenant, volume, owner, operation)
                .await?;
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            break;
                        }
                    }
                    () = tokio::time::sleep(std::time::Duration::from_secs(MAINTENANCE_LEASE_RENEW_SECS)) => {
                        if let Err(error) = lease.renew().await {
                            tracing::warn!(%error, "version maintenance lease renewal failed; retrying");
                        }
                    }
                }
            }
            lease.release().await
        });
        Ok(Self {
            stop,
            task: Mutex::new(Some(task)),
        })
    }

    async fn close(&self) -> Result<()> {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.lock().await.take() {
            task.await.map_err(|error| {
                Error::Versioning(format!("lease heartbeat task failed: {error}"))
            })??;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VersionStoreError {
    #[error("storage engine: {0}")]
    SlateDb(#[from] slatedb::Error),
    #[error("invalid version-store data: {0}")]
    Invalid(String),
}

#[derive(Clone)]
struct VersionStore {
    db: Db,
    ref_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionCommitIdempotencyRecord {
    commit_id: [u8; 32],
    request_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct VersionCommitIdempotencyIntent {
    key_hash: [u8; 32],
    request_fingerprint: [u8; 32],
}

enum VersionPublishOutcome {
    Published,
    Replayed(Box<VersionCommit>),
}

struct VersionPublishRequest<'a> {
    branch: &'a str,
    expected: Option<[u8; 32]>,
    required_ref: Option<(&'a str, [u8; 32])>,
    commit: &'a VersionCommit,
    encoded_commit: Vec<u8>,
    idempotency: Option<VersionCommitIdempotencyIntent>,
    max_bytes: Option<u64>,
}

impl VersionStore {
    fn new(db: Db) -> Self {
        Self {
            db,
            ref_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn get_raw(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, VersionStoreError> {
        Ok(self.db.get(key).await?.map(|bytes| bytes.to_vec()))
    }

    async fn get_head(&self) -> Result<Option<VersionRef>> {
        self.get_ref(HEAD_KEY).await
    }

    async fn get_ref(&self, key: &[u8]) -> Result<Option<VersionRef>> {
        self.get_raw(key)
            .await
            .map_err(version_store_error)?
            .map(|bytes| decode_versioned(REF_VERSION, &bytes, "version ref"))
            .transpose()
    }

    async fn get_branch(&self, name: &str) -> Result<Option<VersionRef>> {
        self.get_ref(&branch_key(name)).await
    }

    async fn list_branches(&self) -> Result<Vec<(String, VersionRef)>> {
        let mut iter = self.db.scan_prefix(BRANCH_PREFIX, ..).await?;
        let mut branches = Vec::new();
        while let Some(entry) = iter.next().await? {
            let name =
                std::str::from_utf8(entry.key.strip_prefix(BRANCH_PREFIX).unwrap_or_default())
                    .map_err(|_| Error::Versioning("version branch name is not UTF-8".into()))?
                    .to_string();
            let reference = decode_versioned(REF_VERSION, &entry.value, "version ref")?;
            branches.push((name, reference));
        }
        branches.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(branches)
    }

    async fn get_commit(&self, id: &[u8; 32]) -> Result<VersionCommit> {
        self.try_get_commit(id)
            .await?
            .ok_or_else(|| Error::not_found("version commit", hex::encode(id)))
    }

    async fn try_get_commit(&self, id: &[u8; 32]) -> Result<Option<VersionCommit>> {
        let key = commit_key(id);
        self.get_raw(&key)
            .await
            .map_err(version_store_error)?
            .map(|bytes| decode_versioned(COMMIT_VERSION, &bytes, "version commit"))
            .transpose()
    }

    async fn is_pruned_commit(&self, id: &[u8; 32]) -> Result<bool> {
        self.get_raw(&pruned_commit_key(id))
            .await
            .map(|value| value.is_some())
            .map_err(version_store_error)
    }

    async fn publish_commit(
        &self,
        request: VersionPublishRequest<'_>,
    ) -> Result<VersionPublishOutcome> {
        let VersionPublishRequest {
            branch,
            expected,
            required_ref,
            commit,
            encoded_commit,
            idempotency,
            max_bytes,
        } = request;
        let _guard = self.ref_lock.lock().await;
        if let Some(intent) = idempotency
            && let Some(existing) = self.resolve_idempotency(intent).await?
        {
            return Ok(VersionPublishOutcome::Replayed(Box::new(existing)));
        }
        let ref_key = branch_key(branch);
        let current = self.get_ref(&ref_key).await?;
        if current.as_ref().map(|head| head.commit_id) != expected {
            let subject = if branch == "main" {
                "branch".to_string()
            } else {
                format!("branch {branch}")
            };
            return Err(Error::Versioning(format!(
                "{subject} moved while committing; expected {}, found {}",
                expected
                    .map(hex::encode)
                    .unwrap_or_else(|| "empty".to_string()),
                current
                    .map(|head| hex::encode(head.commit_id))
                    .unwrap_or_else(|| "empty".to_string())
            )));
        }
        if let Some((required_branch, required_commit)) = required_ref {
            let current = self.get_branch(required_branch).await?;
            if current.as_ref().map(|head| head.commit_id) != Some(required_commit) {
                return Err(Error::Versioning(format!(
                    "branch {required_branch} moved while merging"
                )));
            }
        }
        if let Some(max_bytes) = max_bytes {
            let mut bytes = 0u64;
            let mut iter = self.db.scan(..).await?;
            while let Some(entry) = iter.next().await? {
                bytes = bytes.saturating_add((entry.key.len() + entry.value.len()) as u64);
            }
            let projected = bytes.saturating_add(encoded_commit.len() as u64);
            if projected > max_bytes {
                return Err(Error::Versioning(format!(
                    "version history quota exceeded: {projected} bytes projected, {max_bytes} bytes allowed"
                )));
            }
        }

        let head = VersionRef {
            commit_id: commit.id,
            tree: commit.tree.clone(),
        };
        let mut batch = WriteBatch::new();
        batch.put(commit_key(&commit.id), encoded_commit);
        batch.put(ref_key, encode_versioned(REF_VERSION, &head)?);
        if let Some(intent) = idempotency {
            let record = VersionCommitIdempotencyRecord {
                commit_id: commit.id,
                request_fingerprint: intent.request_fingerprint,
            };
            batch.put(
                idempotency_key(&intent.key_hash),
                encode_versioned(IDEMPOTENCY_VERSION, &record)?,
            );
        }
        self.db.write(batch).await?;
        self.db.flush().await?;
        Ok(VersionPublishOutcome::Published)
    }

    async fn resolve_idempotency(
        &self,
        intent: VersionCommitIdempotencyIntent,
    ) -> Result<Option<VersionCommit>> {
        let Some(bytes) = self
            .get_raw(&idempotency_key(&intent.key_hash))
            .await
            .map_err(version_store_error)?
        else {
            return Ok(None);
        };
        let record: VersionCommitIdempotencyRecord = decode_versioned(
            IDEMPOTENCY_VERSION,
            &bytes,
            "version commit idempotency record",
        )?;
        if record.request_fingerprint != intent.request_fingerprint {
            return Err(Error::already_exists(
                "version commit idempotency key",
                hex::encode(intent.key_hash),
            ));
        }
        let commit = self
            .try_get_commit(&record.commit_id)
            .await?
            .ok_or_else(|| {
                Error::Versioning(format!(
                    "idempotency record references missing commit {}",
                    hex::encode(record.commit_id)
                ))
            })?;
        Ok(Some(commit))
    }

    async fn list_tags(&self) -> Result<Vec<VersionTag>> {
        let mut iter = self.db.scan_prefix(TAG_PREFIX, ..).await?;
        let mut tags = Vec::new();
        while let Some(entry) = iter.next().await? {
            tags.push(decode_versioned(TAG_VERSION, &entry.value, "version tag")?);
        }
        tags.sort_by(|left: &VersionTag, right| left.name.cmp(&right.name));
        Ok(tags)
    }

    async fn try_get_tag(&self, name: &str) -> Result<Option<VersionTag>> {
        let tag = self
            .get_raw(&tag_key(name))
            .await
            .map_err(version_store_error)?
            .map(|bytes| decode_versioned(TAG_VERSION, &bytes, "version tag"))
            .transpose()?;
        Ok(tag)
    }

    async fn create_tag(&self, tag: &VersionTag) -> Result<()> {
        let _guard = self.ref_lock.lock().await;
        let key = tag_key(&tag.name);
        if self
            .get_raw(&key)
            .await
            .map_err(version_store_error)?
            .is_some()
        {
            return Err(Error::already_exists("version tag", &tag.name));
        }
        if self.get_branch(&tag.name).await?.is_some() {
            return Err(Error::already_exists("version branch", &tag.name));
        }
        self.db
            .put_bytes(key.into(), encode_versioned(TAG_VERSION, tag)?.into())
            .await?;
        self.db.flush().await?;
        Ok(())
    }

    async fn delete_tag(&self, name: &str) -> Result<VersionTag> {
        let _guard = self.ref_lock.lock().await;
        let key = tag_key(name);
        let tag = self
            .get_raw(&key)
            .await
            .map_err(version_store_error)?
            .map(|bytes| decode_versioned(TAG_VERSION, &bytes, "version tag"))
            .transpose()?
            .ok_or_else(|| Error::not_found("version tag", name))?;
        self.db.delete(key).await?;
        self.db.flush().await?;
        Ok(tag)
    }

    async fn create_branch(&self, name: &str, reference: &VersionRef) -> Result<()> {
        let _guard = self.ref_lock.lock().await;
        let key = branch_key(name);
        if self.get_ref(&key).await?.is_some() {
            return Err(Error::already_exists("version branch", name));
        }
        if self.try_get_tag(name).await?.is_some() {
            return Err(Error::already_exists("version tag", name));
        }
        self.db
            .put_bytes(key.into(), encode_versioned(REF_VERSION, reference)?.into())
            .await?;
        self.db.flush().await?;
        Ok(())
    }

    async fn delete_branch(&self, name: &str) -> Result<VersionRef> {
        let _guard = self.ref_lock.lock().await;
        let key = branch_key(name);
        let reference = self
            .get_ref(&key)
            .await?
            .ok_or_else(|| Error::not_found("version branch", name))?;
        self.db.delete(key).await?;
        self.db.flush().await?;
        Ok(reference)
    }

    async fn fast_forward_branch(
        &self,
        source: &str,
        target: &str,
        expected_source: [u8; 32],
        expected_target: [u8; 32],
    ) -> Result<VersionRef> {
        let _guard = self.ref_lock.lock().await;
        let source_ref = self
            .get_branch(source)
            .await?
            .ok_or_else(|| Error::not_found("version branch", source))?;
        let target_ref = self
            .get_branch(target)
            .await?
            .ok_or_else(|| Error::not_found("version branch", target))?;
        if source_ref.commit_id != expected_source || target_ref.commit_id != expected_target {
            return Err(Error::Versioning(
                "branch moved while preparing fast-forward merge".into(),
            ));
        }
        self.db
            .put_bytes(
                branch_key(target).into(),
                encode_versioned(REF_VERSION, &source_ref)?.into(),
            )
            .await?;
        self.db.flush().await?;
        Ok(source_ref)
    }
}

impl AsyncStore for VersionStore {
    type Error = VersionStoreError;

    async fn get(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        self.get_raw(&prefixed_key(NODE_PREFIX, key)).await
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> std::result::Result<(), Self::Error> {
        self.db
            .put_bytes(
                prefixed_key(NODE_PREFIX, key).into(),
                SlateBytes::copy_from_slice(value),
            )
            .await?;
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> std::result::Result<(), Self::Error> {
        self.db.delete(prefixed_key(NODE_PREFIX, key)).await?;
        Ok(())
    }

    async fn batch(&self, ops: &[BatchOp<'_>]) -> std::result::Result<(), Self::Error> {
        let mut batch = WriteBatch::new();
        for op in ops {
            match op {
                BatchOp::Upsert { key, value } => {
                    batch.put(prefixed_key(NODE_PREFIX, key), *value);
                }
                BatchOp::Delete { key } => batch.delete(prefixed_key(NODE_PREFIX, key)),
            }
        }
        self.db.write(batch).await?;
        Ok(())
    }

    fn read_parallelism(&self) -> usize {
        32
    }
}

impl AsyncBlobStore for VersionStore {
    type Error = VersionStoreError;

    async fn get_blob(
        &self,
        reference: &BlobRef,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let Some(bytes) = self.get_raw(&blob_key(&reference.cid)).await? else {
            return Ok(None);
        };
        reference
            .validate_bytes(&bytes)
            .map_err(|error| VersionStoreError::Invalid(error.to_string()))?;
        Ok(Some(bytes))
    }

    async fn put_blob(&self, bytes: &[u8]) -> std::result::Result<BlobRef, Self::Error> {
        let reference = BlobRef::from_bytes(bytes);
        self.db
            .put_bytes(
                blob_key(&reference.cid).into(),
                SlateBytes::copy_from_slice(bytes),
            )
            .await?;
        Ok(reference)
    }

    async fn delete_blob(&self, reference: &BlobRef) -> std::result::Result<(), Self::Error> {
        self.db.delete(blob_key(&reference.cid)).await?;
        Ok(())
    }

    fn read_parallelism(&self) -> usize {
        32
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum VersionEntryData {
    File { chunk_count: u32 },
    Directory,
    Symlink { target: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionEntry {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime: Timespec,
    mtime: Timespec,
    data: VersionEntryData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionCommit {
    id: [u8; 32],
    parents: Vec<[u8; 32]>,
    tree: RootManifest,
    created_at: u64,
    message: String,
    paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionCommitBody {
    parents: Vec<[u8; 32]>,
    tree: RootManifest,
    created_at: u64,
    message: String,
    paths: Vec<String>,
}

#[derive(Serialize)]
struct VersionCommitRequestFingerprint<'a> {
    version: u8,
    branch: &'a str,
    message: &'a str,
    paths: &'a [String],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionRef {
    commit_id: [u8; 32],
    tree: RootManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionTag {
    name: String,
    commit_id: [u8; 32],
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionCommitInfo {
    pub id: String,
    pub parents: Vec<String>,
    pub created_at: u64,
    pub message: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionTagInfo {
    name: String,
    commit: String,
    created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionBranchInfo {
    name: String,
    commit: String,
}

/// Policy used when both sides of a branch merge changed the same logical path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionMergeConflictStrategy {
    /// Reject the merge without moving either branch.
    #[default]
    Fail,
    /// Keep the target branch's complete value for each conflicting path.
    Ours,
    /// Keep the source branch's complete value for each conflicting path.
    Theirs,
}

impl VersionMergeConflictStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Ours => "ours",
            Self::Theirs => "theirs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionMergeInfo {
    source: String,
    target: String,
    commit: String,
    strategy: VersionMergeConflictStrategy,
    fast_forward: bool,
    already_up_to_date: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionMergePreview {
    source: String,
    target: String,
    source_head: String,
    target_head: String,
    merge_base: String,
    ahead: u64,
    behind: u64,
    fast_forward: bool,
    already_up_to_date: bool,
    conflicts: Vec<String>,
}

impl VersionMergePreview {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn source_head(&self) -> &str {
        &self.source_head
    }

    pub fn target_head(&self) -> &str {
        &self.target_head
    }

    pub fn merge_base(&self) -> &str {
        &self.merge_base
    }

    pub fn ahead(&self) -> u64 {
        self.ahead
    }

    pub fn behind(&self) -> u64 {
        self.behind
    }

    pub fn fast_forward(&self) -> bool {
        self.fast_forward
    }

    pub fn already_up_to_date(&self) -> bool {
        self.already_up_to_date
    }

    pub fn conflicts(&self) -> &[String] {
        &self.conflicts
    }

    pub fn can_merge(&self) -> bool {
        self.conflicts.is_empty()
    }
}

struct ThreeWayMergePlan {
    mutations: Vec<Mutation>,
    conflicts: Vec<String>,
}

impl VersionMergeInfo {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }

    pub fn strategy(&self) -> VersionMergeConflictStrategy {
        self.strategy
    }

    pub fn fast_forward(&self) -> bool {
        self.fast_forward
    }

    pub fn already_up_to_date(&self) -> bool {
        self.already_up_to_date
    }
}

impl VersionBranchInfo {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }
}

impl VersionTagInfo {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }
}

impl From<VersionTag> for VersionTagInfo {
    fn from(tag: VersionTag) -> Self {
        Self {
            name: tag.name,
            commit: hex::encode(tag.commit_id),
            created_at: tag.created_at,
        }
    }
}

/// The result of an idempotent version commit. A replay returns the original
/// commit without capturing or publishing the live paths again.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionCommitResult {
    commit: VersionCommitInfo,
    replayed: bool,
}

impl VersionCommitResult {
    pub fn commit(&self) -> &VersionCommitInfo {
        &self.commit
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn into_commit(self) -> VersionCommitInfo {
        self.commit
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VersionStoreStats {
    pub bytes: u64,
    pub nodes: u64,
    pub blobs: u64,
    pub commits: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VersionGcReport {
    pub retained_commits: u64,
    pub deleted_commits: u64,
    pub deleted_nodes: u64,
    pub deleted_blobs: u64,
    pub reclaimed_bytes: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionVerifyReport {
    pub commits: u64,
    pub nodes: u64,
    pub node_bytes: u64,
    pub blobs: u64,
    pub blob_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionFileRange {
    pub offset: u64,
    pub total_size: u64,
    pub data: Bytes,
    pub eof: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VersionPathChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionPathChange {
    path: String,
    change: VersionPathChangeKind,
}

impl VersionPathChange {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn change(&self) -> VersionPathChangeKind {
        self.change
    }
}

impl From<VersionCommit> for VersionCommitInfo {
    fn from(commit: VersionCommit) -> Self {
        Self {
            id: hex::encode(commit.id),
            parents: commit.parents.into_iter().map(hex::encode).collect(),
            created_at: commit.created_at,
            message: commit.message,
            paths: commit.paths,
        }
    }
}

/// A lazily opened version repository for one enabled filesystem volume.
pub struct VersionRepository {
    store: VersionStore,
    prolly: AsyncProlly<VersionStore>,
    max_bytes: Option<u64>,
    chunk_size: u64,
    maintenance: VersionMaintenanceGuard,
}

/// Permanently delete the physical version-repository prefix. The same lease
/// used by repository opens makes this conflict safely with active work.
pub async fn purge_version_history(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant: &str,
    volume: &str,
) -> Result<usize> {
    control.get_volume(tenant, volume).await?;
    delete_version_history_objects(object_store, tenant, volume).await
}

pub(crate) async fn delete_version_history_objects(
    object_store: Arc<dyn ObjectStore>,
    tenant: &str,
    volume: &str,
) -> Result<usize> {
    let maintenance =
        VersionMaintenanceGuard::acquire(Arc::clone(&object_store), tenant, volume, "purge")
            .await?;
    let result =
        store::delete_prefix(&object_store, &store::version_db_prefix(tenant, volume)).await;
    let close = maintenance.close().await;
    let deleted = result?;
    close?;
    Ok(deleted)
}

impl VersionRepository {
    pub async fn open(
        control: &ControlPlane,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
    ) -> Result<Self> {
        if !control.versioning_enabled(tenant, volume).await? {
            return Err(Error::Versioning(format!(
                "versioning is disabled for {tenant}/{volume}"
            )));
        }
        let max_bytes = control
            .try_get_versioning_retention_policy(tenant, volume)
            .await?
            .and_then(|policy| policy.max_bytes);
        let record = control.get_mountable_volume(tenant, volume).await?;
        let dek = control.unwrap_volume_dek(&record).await?;
        let maintenance = VersionMaintenanceGuard::acquire(
            Arc::clone(&object_store),
            tenant,
            volume,
            "repository",
        )
        .await?;
        Self::open_for_record(&record, dek, object_store, max_bytes, maintenance).await
    }

    /// Open a repository only when history has already been created. The
    /// existence check runs while holding the maintenance lease, so background
    /// maintenance cannot recreate history concurrently with a purge.
    pub async fn open_existing(
        control: &ControlPlane,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<Self>> {
        if !control.versioning_enabled(tenant, volume).await? {
            return Err(Error::Versioning(format!(
                "versioning is disabled for {tenant}/{volume}"
            )));
        }
        let max_bytes = control
            .try_get_versioning_retention_policy(tenant, volume)
            .await?
            .and_then(|policy| policy.max_bytes);
        let record = control.get_mountable_volume(tenant, volume).await?;
        let dek = control.unwrap_volume_dek(&record).await?;
        Self::open_existing_for_record(&record, dek, object_store, max_bytes, tenant, volume).await
    }

    /// Read-only-control-plane variant of [`Self::open_existing`] for daemon
    /// maintenance loops that must not hold a control writer during GC.
    pub async fn open_existing_readonly(
        control: &ControlReader,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<Self>> {
        if !control.versioning_enabled(tenant, volume).await? {
            return Err(Error::Versioning(format!(
                "versioning is disabled for {tenant}/{volume}"
            )));
        }
        let max_bytes = control
            .try_get_versioning_retention_policy(tenant, volume)
            .await?
            .and_then(|policy| policy.max_bytes);
        let record = control.get_mountable_volume(tenant, volume).await?;
        let dek = control.unwrap_volume_dek(&record).await?;
        Self::open_existing_for_record(&record, dek, object_store, max_bytes, tenant, volume).await
    }

    async fn open_existing_for_record(
        record: &VolumeRecord,
        dek: crate::crypto::Secret32,
        object_store: Arc<dyn ObjectStore>,
        max_bytes: Option<u64>,
        tenant: &str,
        volume: &str,
    ) -> Result<Option<Self>> {
        let maintenance = VersionMaintenanceGuard::acquire(
            Arc::clone(&object_store),
            tenant,
            volume,
            "repository",
        )
        .await?;
        let exists =
            store::prefix_exists(&object_store, &store::version_db_prefix(tenant, volume)).await;
        let exists = match exists {
            Ok(exists) => exists,
            Err(error) => {
                let _ = maintenance.close().await;
                return Err(error);
            }
        };
        if !exists {
            maintenance.close().await?;
            return Ok(None);
        }
        Self::open_for_record(record, dek, object_store, max_bytes, maintenance)
            .await
            .map(Some)
    }

    async fn open_for_record(
        record: &VolumeRecord,
        dek: crate::crypto::Secret32,
        object_store: Arc<dyn ObjectStore>,
        max_bytes: Option<u64>,
        maintenance: VersionMaintenanceGuard,
    ) -> Result<Self> {
        if !matches!(record.kind, crate::meta::superblock::VolumeKind::Filesystem) {
            maintenance.close().await?;
            return Err(Error::invalid(
                "versioning volume",
                "file versioning is available only for filesystem volumes",
            ));
        }
        let db = Db::builder(
            store::version_db_path(&record.tenant, &record.name),
            object_store,
        )
        .with_settings(Settings {
            compression_codec: record.compression.to_slatedb(),
            ..Settings::default()
        })
        .with_block_transformer(Arc::new(SlateBlockTransformer::new(record.cipher, dek)))
        .build()
        .await;
        let db = match db {
            Ok(db) => db,
            Err(error) => {
                let _ = maintenance.close().await;
                return Err(error.into());
            }
        };
        let store = VersionStore::new(db);
        let prolly = AsyncProlly::new(store.clone(), ProllyConfig::default());
        Ok(Self {
            store,
            prolly,
            max_bytes,
            chunk_size: u64::from(record.chunk_size),
            maintenance,
        })
    }

    pub async fn close(&self) -> Result<()> {
        let db_close = self.store.db.close().await.map_err(Error::from);
        let lease_close = self.maintenance.close().await;
        db_close?;
        lease_close
    }

    pub async fn stats(&self) -> Result<VersionStoreStats> {
        let mut stats = VersionStoreStats::default();
        let mut iter = self.store.db.scan(..).await?;
        while let Some(entry) = iter.next().await? {
            stats.bytes = stats
                .bytes
                .saturating_add((entry.key.len() + entry.value.len()) as u64);
            if entry.key.starts_with(NODE_PREFIX) {
                stats.nodes += 1;
            } else if entry.key.starts_with(BLOB_PREFIX) {
                stats.blobs += 1;
            } else if entry.key.starts_with(COMMIT_PREFIX) {
                stats.commits += 1;
            }
        }
        Ok(stats)
    }

    /// Verify the reachable commit chain and every referenced Prolly node and
    /// blob. Unreachable objects are intentionally left to garbage collection.
    pub async fn verify(&self) -> Result<VersionVerifyReport> {
        let mut pending = Vec::new();
        for (name, branch) in self.store.list_branches().await? {
            let commit = self
                .store
                .get_commit(&branch.commit_id)
                .await
                .map_err(|_| {
                    Error::Versioning(format!(
                        "version branch {name} references missing commit {}",
                        hex::encode(branch.commit_id)
                    ))
                })?;
            if branch.tree.to_tree() != commit.tree.to_tree() {
                return Err(Error::Versioning(format!(
                    "version branch {name} tree does not match commit {}",
                    hex::encode(branch.commit_id)
                )));
            }
            pending.push(branch.commit_id);
        }
        for tag in self.store.list_tags().await? {
            self.store.get_commit(&tag.commit_id).await.map_err(|_| {
                Error::Versioning(format!(
                    "version tag {} references missing commit {}",
                    tag.name,
                    hex::encode(tag.commit_id)
                ))
            })?;
            pending.push(tag.commit_id);
        }
        let mut seen = HashSet::new();
        let mut trees = Vec::new();
        let mut commits = 0u64;
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                if self.store.is_pruned_commit(&id).await? {
                    continue;
                }
                return Err(Error::not_found("version commit", hex::encode(id)));
            };
            let body = VersionCommitBody {
                parents: commit.parents.clone(),
                tree: commit.tree.clone(),
                created_at: commit.created_at,
                message: commit.message.clone(),
                paths: commit.paths.clone(),
            };
            let expected: [u8; 32] = Sha256::digest(postcard::to_allocvec(&body)?).into();
            if expected != commit.id || commit.id != id {
                return Err(Error::Versioning(format!(
                    "commit {} does not match its content hash",
                    hex::encode(id)
                )));
            }
            trees.push(commit.tree.to_tree());
            pending.extend(commit.parents.iter().copied());
            commits += 1;
        }

        let nodes = self
            .prolly
            .mark_reachable(&trees)
            .await
            .map_err(prolly_error)?;
        let blobs = self
            .prolly
            .mark_reachable_blobs(&trees)
            .await
            .map_err(prolly_error)?;
        for reference in &blobs.live_blobs {
            self.store
                .get_blob(reference)
                .await
                .map_err(version_store_error)?
                .ok_or_else(|| {
                    Error::Versioning(format!(
                        "missing reachable blob {}",
                        hex::encode(reference.cid.as_bytes())
                    ))
                })?;
        }
        Ok(VersionVerifyReport {
            commits,
            nodes: nodes.live_nodes as u64,
            node_bytes: nodes.live_bytes as u64,
            blobs: blobs.live_blob_count as u64,
            blob_bytes: blobs.live_blob_bytes,
        })
    }

    pub async fn garbage_collect(
        &self,
        keep_last: Option<u32>,
        max_age_secs: Option<u64>,
        dry_run: bool,
    ) -> Result<VersionGcReport> {
        let now = crate::control::now_unix();
        let cutoff = max_age_secs.map(|age| now.saturating_sub(age));
        let mut next = self.store.get_head().await?.map(|head| head.commit_id);
        let mut retained = Vec::new();
        let mut chain = Vec::new();
        while let Some(id) = next {
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                break;
            };
            next = commit.parents.first().copied();
            let position = chain.len();
            let within_count = keep_last.is_none_or(|keep| position < keep as usize);
            let within_age = cutoff.is_none_or(|cutoff| commit.created_at >= cutoff);
            if position == 0 || (within_count && within_age) {
                retained.push(commit.clone());
            }
            chain.push(commit);
        }
        let mut retained_commit_ids = retained
            .iter()
            .map(|commit| commit.id)
            .collect::<HashSet<_>>();
        for (name, branch) in self.store.list_branches().await? {
            if name == "main" {
                continue;
            }
            let mut next = Some(branch.commit_id);
            let mut position = 0usize;
            while let Some(id) = next {
                let Some(commit) = self.store.try_get_commit(&id).await? else {
                    if position > 0 && self.store.is_pruned_commit(&id).await? {
                        break;
                    }
                    return Err(Error::Versioning(format!(
                        "version branch {name} references missing commit {}",
                        hex::encode(id)
                    )));
                };
                next = commit.parents.first().copied();
                let within_count = keep_last.is_none_or(|keep| position < keep as usize);
                let within_age = cutoff.is_none_or(|cutoff| commit.created_at >= cutoff);
                if (position == 0 || (within_count && within_age))
                    && retained_commit_ids.insert(commit.id)
                {
                    retained.push(commit);
                }
                position += 1;
            }
        }
        if keep_last.is_none() && cutoff.is_none() {
            let mut pending = retained
                .iter()
                .flat_map(|commit| commit.parents.iter().copied())
                .collect::<Vec<_>>();
            while let Some(id) = pending.pop() {
                if !retained_commit_ids.insert(id) {
                    continue;
                }
                let Some(commit) = self.store.try_get_commit(&id).await? else {
                    continue;
                };
                pending.extend(commit.parents.iter().copied());
                retained.push(commit);
            }
        }
        for tag in self.store.list_tags().await? {
            if retained_commit_ids.insert(tag.commit_id) {
                let commit = if let Some(commit) = chain
                    .iter()
                    .find(|commit| commit.id == tag.commit_id)
                    .cloned()
                {
                    commit
                } else {
                    self.store
                        .try_get_commit(&tag.commit_id)
                        .await?
                        .ok_or_else(|| {
                            Error::Versioning(format!(
                                "version tag {} references missing commit {}",
                                tag.name,
                                hex::encode(tag.commit_id)
                            ))
                        })?
                };
                retained.push(commit);
            }
        }

        let trees = retained
            .iter()
            .map(|commit| commit.tree.to_tree())
            .collect::<Vec<_>>();
        let live_nodes = self
            .prolly
            .mark_reachable(&trees)
            .await
            .map_err(prolly_error)?
            .live_cids
            .into_iter()
            .map(|cid| cid.as_bytes().to_vec())
            .collect::<HashSet<_>>();
        let live_blobs = self
            .prolly
            .mark_reachable_blobs(&trees)
            .await
            .map_err(prolly_error)?
            .live_blobs
            .into_iter()
            .map(|reference| reference.cid.as_bytes().to_vec())
            .collect::<HashSet<_>>();
        let retained_ids = retained
            .iter()
            .map(|commit| commit.id.to_vec())
            .collect::<HashSet<_>>();

        let mut report = VersionGcReport {
            retained_commits: retained.len() as u64,
            dry_run,
            ..VersionGcReport::default()
        };
        let mut deletions = WriteBatch::new();
        let mut iter = self.store.db.scan(..).await?;
        while let Some(entry) = iter.next().await? {
            let key = entry.key.as_ref();
            let delete = if let Some(cid) = key.strip_prefix(NODE_PREFIX) {
                if live_nodes.contains(cid) {
                    false
                } else {
                    report.deleted_nodes += 1;
                    true
                }
            } else if let Some(cid) = key.strip_prefix(BLOB_PREFIX) {
                if live_blobs.contains(cid) {
                    false
                } else {
                    report.deleted_blobs += 1;
                    true
                }
            } else if let Some(id) = key.strip_prefix(COMMIT_PREFIX) {
                if retained_ids.contains(id) {
                    false
                } else {
                    report.deleted_commits += 1;
                    if !dry_run {
                        deletions.put(pruned_commit_key_bytes(id), Vec::<u8>::new());
                    }
                    true
                }
            } else if key.starts_with(IDEMPOTENCY_PREFIX) {
                let record: VersionCommitIdempotencyRecord = decode_versioned(
                    IDEMPOTENCY_VERSION,
                    &entry.value,
                    "version commit idempotency record",
                )?;
                !retained_ids.contains(record.commit_id.as_slice())
            } else {
                false
            };
            if delete {
                report.reclaimed_bytes = report
                    .reclaimed_bytes
                    .saturating_add((entry.key.len() + entry.value.len()) as u64);
                if !dry_run {
                    deletions.delete(entry.key);
                }
            }
        }
        if !dry_run && (report.deleted_nodes + report.deleted_blobs + report.deleted_commits > 0) {
            self.store.db.write(deletions).await?;
            self.store.db.flush().await?;
            self.prolly.clear_cache();
        }
        Ok(report)
    }

    pub async fn commit_file(
        &self,
        live: &dyn Vfs,
        path: &str,
        message: String,
    ) -> Result<VersionCommitInfo> {
        self.commit_paths(live, &[path.to_string()], message).await
    }

    /// Commit multiple selected paths as one immutable tree update. Directory
    /// paths recursively include their descendants. A selected path that no
    /// longer exists removes its previously versioned subtree.
    pub async fn commit_paths(
        &self,
        live: &dyn Vfs,
        paths: &[String],
        message: String,
    ) -> Result<VersionCommitInfo> {
        Ok(self
            .commit_paths_inner(live, None, "main", paths, message, None)
            .await?
            .into_commit())
    }

    /// Commit selected paths to an existing named branch.
    pub async fn commit_paths_on_branch(
        &self,
        live: &dyn Vfs,
        branch: &str,
        paths: &[String],
        message: String,
    ) -> Result<VersionCommitInfo> {
        Ok(self
            .commit_paths_inner(live, None, branch, paths, message, None)
            .await?
            .into_commit())
    }

    /// Commit selected paths with a caller-supplied retry key. Reusing the key
    /// with the same canonical paths and message returns the original commit;
    /// reusing it for a different request is rejected.
    pub async fn commit_paths_idempotent(
        &self,
        live: &dyn Vfs,
        paths: &[String],
        message: String,
        idempotency_key: &str,
    ) -> Result<VersionCommitResult> {
        self.commit_paths_inner(live, None, "main", paths, message, Some(idempotency_key))
            .await
    }

    /// Commit selected paths to an existing named branch with a retry key.
    pub async fn commit_paths_on_branch_idempotent(
        &self,
        live: &dyn Vfs,
        branch: &str,
        paths: &[String],
        message: String,
        idempotency_key: &str,
    ) -> Result<VersionCommitResult> {
        self.commit_paths_inner(live, None, branch, paths, message, Some(idempotency_key))
            .await
    }

    /// Commit from a live SlateFS volume while validating its writer lease
    /// before capture and again immediately before publishing the new head.
    pub async fn commit_volume_paths(
        &self,
        live: &Volume,
        paths: &[String],
        message: String,
    ) -> Result<VersionCommitInfo> {
        live.validate_writer_lease().await?;
        Ok(self
            .commit_paths_inner(live, Some(live), "main", paths, message, None)
            .await?
            .into_commit())
    }

    /// Commit selected paths through a live writer to an existing branch.
    pub async fn commit_volume_paths_on_branch(
        &self,
        live: &Volume,
        branch: &str,
        paths: &[String],
        message: String,
    ) -> Result<VersionCommitInfo> {
        live.validate_writer_lease().await?;
        Ok(self
            .commit_paths_inner(live, Some(live), branch, paths, message, None)
            .await?
            .into_commit())
    }

    /// Commit through a live writer with a caller-supplied retry key. The key,
    /// commit, and branch head are published atomically in the version store.
    pub async fn commit_volume_paths_idempotent(
        &self,
        live: &Volume,
        paths: &[String],
        message: String,
        idempotency_key: &str,
    ) -> Result<VersionCommitResult> {
        live.validate_writer_lease().await?;
        self.commit_paths_inner(
            live,
            Some(live),
            "main",
            paths,
            message,
            Some(idempotency_key),
        )
        .await
    }

    /// Commit through a live writer to an existing branch with a retry key.
    pub async fn commit_volume_paths_on_branch_idempotent(
        &self,
        live: &Volume,
        branch: &str,
        paths: &[String],
        message: String,
        idempotency_key: &str,
    ) -> Result<VersionCommitResult> {
        live.validate_writer_lease().await?;
        self.commit_paths_inner(
            live,
            Some(live),
            branch,
            paths,
            message,
            Some(idempotency_key),
        )
        .await
    }

    async fn commit_paths_inner(
        &self,
        live: &dyn Vfs,
        writer_guard: Option<&Volume>,
        branch: &str,
        paths: &[String],
        message: String,
        idempotency_key: Option<&str>,
    ) -> Result<VersionCommitResult> {
        validate_version_branch_name(branch)?;
        let canonical = canonicalize_path_set(paths)?;
        let idempotency = idempotency_key
            .map(|key| version_commit_idempotency_intent(key, branch, &canonical, &message))
            .transpose()?;
        let head = self.store.get_branch(branch).await?;
        if branch != "main" && head.is_none() {
            return Err(Error::not_found("version branch", branch));
        }
        if let Some(intent) = idempotency
            && let Some(commit) = self.store.resolve_idempotency(intent).await?
        {
            return Ok(VersionCommitResult {
                commit: commit.into(),
                replayed: true,
            });
        }

        let base = head
            .as_ref()
            .map(|head| head.tree.to_tree())
            .unwrap_or_else(|| self.prolly.create());
        let mut changes = BTreeMap::new();
        let mut range = self
            .prolly
            .range(&base, &[], None)
            .await
            .map_err(prolly_error)?;
        while let Some(entry) = range.next().await {
            let (key, _) = entry.map_err(prolly_error)?;
            if version_key_matches_any_path(&key, &canonical) {
                changes.insert(key, None);
            }
        }

        for path in &canonical {
            let Some(attr) = resolve_path_optional(live, path).await? else {
                continue;
            };
            self.capture_subtree(live, path, attr, &mut changes).await?;
        }

        let mutations = changes
            .into_iter()
            .map(|(key, value)| match value {
                Some(val) => Mutation::Upsert { key, val },
                None => Mutation::Delete { key },
            })
            .collect();
        let tree = self
            .prolly
            .batch(&base, mutations)
            .await
            .map_err(prolly_error)?;
        if tree == base {
            return Err(Error::Versioning(format!(
                "{} has no changes to commit",
                canonical.join(", ")
            )));
        }
        let body = VersionCommitBody {
            parents: head
                .as_ref()
                .map(|head| vec![head.commit_id])
                .unwrap_or_default(),
            tree: RootManifest::from_tree(&tree),
            created_at: crate::control::now_unix(),
            message,
            paths: canonical,
        };
        let body_bytes = postcard::to_allocvec(&body)?;
        let id: [u8; 32] = Sha256::digest(&body_bytes).into();
        let commit = VersionCommit {
            id,
            parents: body.parents,
            tree: body.tree,
            created_at: body.created_at,
            message: body.message,
            paths: body.paths,
        };
        let encoded = encode_versioned(COMMIT_VERSION, &commit)?;
        if let Some(writer_guard) = writer_guard {
            writer_guard.validate_writer_lease().await?;
        }
        match self
            .store
            .publish_commit(VersionPublishRequest {
                branch,
                expected: head.map(|head| head.commit_id),
                required_ref: None,
                commit: &commit,
                encoded_commit: encoded,
                idempotency,
                max_bytes: self.max_bytes,
            })
            .await?
        {
            VersionPublishOutcome::Published => Ok(VersionCommitResult {
                commit: commit.into(),
                replayed: false,
            }),
            VersionPublishOutcome::Replayed(commit) => Ok(VersionCommitResult {
                commit: (*commit).into(),
                replayed: true,
            }),
        }
    }

    async fn capture_subtree(
        &self,
        live: &dyn Vfs,
        root_path: &str,
        root_attr: FileAttr,
        changes: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<()> {
        let creds = Credentials::root();
        let mut pending = vec![(root_path.to_string(), root_attr)];
        while let Some((path, attr)) = pending.pop() {
            let data = match attr.kind {
                FileKind::File => {
                    let chunk_size = live.chunk_size().min(u32::MAX as u64) as u32;
                    let chunk_count_u64 = attr.size.div_ceil(chunk_size as u64);
                    let chunk_count = u32::try_from(chunk_count_u64)
                        .map_err(|_| Error::invalid("versioned file", "too many chunks"))?;
                    for index in 0..chunk_count {
                        let offset = index as u64 * chunk_size as u64;
                        let len = (attr.size - offset).min(chunk_size as u64) as u32;
                        let bytes = live
                            .read_with_atime_policy(
                                &creds,
                                attr.ino,
                                offset,
                                len,
                                AtimeMode::Noatime,
                            )
                            .await
                            .map_err(fs_error)?;
                        let reference = self
                            .store
                            .put_blob(&bytes)
                            .await
                            .map_err(version_store_error)?;
                        changes.insert(
                            file_chunk_key(&path, index),
                            Some(ValueRef::Blob(reference).to_bytes()),
                        );
                    }
                    VersionEntryData::File { chunk_count }
                }
                FileKind::Dir => {
                    let mut cookie = 0;
                    loop {
                        let page = live
                            .readdir(&creds, attr.ino, cookie, 1024)
                            .await
                            .map_err(fs_error)?;
                        if page.entries.is_empty() && !page.eof {
                            return Err(Error::Versioning(format!(
                                "directory scan for {path} did not advance"
                            )));
                        }
                        for child in page.entries {
                            cookie = child.cookie;
                            let name = std::str::from_utf8(&child.name).map_err(|_| {
                                Error::invalid(
                                    "versioned path",
                                    format!("{path} contains a non-UTF-8 name"),
                                )
                            })?;
                            let child_path = format!("{path}/{name}");
                            let child_attr =
                                live.getattr(&creds, child.ino).await.map_err(fs_error)?;
                            pending.push((child_path, child_attr));
                        }
                        if page.eof {
                            break;
                        }
                    }
                    VersionEntryData::Directory
                }
                FileKind::Symlink => VersionEntryData::Symlink {
                    target: live.readlink(&creds, attr.ino).await.map_err(fs_error)?,
                },
                kind => {
                    return Err(Error::invalid(
                        "versioned path",
                        format!("unsupported file kind {kind:?} at {path}"),
                    ));
                }
            };
            let metadata = VersionEntry {
                mode: attr.mode,
                uid: attr.uid,
                gid: attr.gid,
                size: attr.size,
                atime: attr.atime,
                mtime: attr.mtime,
                data,
            };
            changes.insert(
                file_meta_key(&path),
                Some(encode_versioned(ENTRY_META_VERSION, &metadata)?),
            );
        }
        Ok(())
    }

    /// Create an immutable name for an existing commit. Tags pin their commit
    /// and tree through retention garbage collection until explicitly deleted.
    pub async fn create_tag(&self, name: &str, commit: &str) -> Result<VersionTagInfo> {
        validate_version_tag_name(name)?;
        let commit_id = parse_commit_id(commit)?;
        self.store.get_commit(&commit_id).await?;
        let tag = VersionTag {
            name: name.to_string(),
            commit_id,
            created_at: crate::control::now_unix(),
        };
        self.store.create_tag(&tag).await?;
        Ok(tag.into())
    }

    pub async fn list_tags(&self) -> Result<Vec<VersionTagInfo>> {
        Ok(self
            .store
            .list_tags()
            .await?
            .into_iter()
            .map(VersionTagInfo::from)
            .collect())
    }

    pub async fn delete_tag(&self, name: &str) -> Result<VersionTagInfo> {
        validate_version_tag_name(name)?;
        Ok(self.store.delete_tag(name).await?.into())
    }

    /// Create a named branch at an existing commit or named reference. The
    /// branch head pins that commit and tree through retention GC.
    pub async fn create_branch(&self, name: &str, commit: &str) -> Result<VersionBranchInfo> {
        validate_version_branch_name(name)?;
        if name == "main" {
            return Err(Error::invalid(
                "version branch",
                "main already exists as the default branch",
            ));
        }
        let commit = self.resolve_commit(commit).await?;
        let reference = VersionRef {
            commit_id: commit.id,
            tree: commit.tree,
        };
        self.store.create_branch(name, &reference).await?;
        Ok(VersionBranchInfo {
            name: name.to_string(),
            commit: hex::encode(reference.commit_id),
        })
    }

    pub async fn list_branches(&self) -> Result<Vec<VersionBranchInfo>> {
        Ok(self
            .store
            .list_branches()
            .await?
            .into_iter()
            .map(|(name, reference)| VersionBranchInfo {
                name,
                commit: hex::encode(reference.commit_id),
            })
            .collect())
    }

    pub async fn delete_branch(&self, name: &str) -> Result<VersionBranchInfo> {
        validate_version_branch_name(name)?;
        if name == "main" {
            return Err(Error::invalid(
                "version branch",
                "the default main branch cannot be deleted",
            ));
        }
        let reference = self.store.delete_branch(name).await?;
        Ok(VersionBranchInfo {
            name: name.to_string(),
            commit: hex::encode(reference.commit_id),
        })
    }

    /// Preview how `source` would merge into `target` without publishing a
    /// commit or moving either branch.
    pub async fn preview_branch_merge(
        &self,
        source: &str,
        target: &str,
    ) -> Result<VersionMergePreview> {
        validate_version_branch_name(source)?;
        validate_version_branch_name(target)?;
        if source == target {
            return Err(Error::invalid(
                "version branch merge",
                "source and target must differ",
            ));
        }
        let source_ref = self
            .store
            .get_branch(source)
            .await?
            .ok_or_else(|| Error::not_found("version branch", source))?;
        let target_ref = self
            .store
            .get_branch(target)
            .await?
            .ok_or_else(|| Error::not_found("version branch", target))?;
        let source_ancestors = self.ancestor_distances(source_ref.commit_id).await?;
        let target_ancestors = self.ancestor_distances(target_ref.commit_id).await?;
        let ahead = source_ancestors
            .keys()
            .filter(|id| !target_ancestors.contains_key(*id))
            .count() as u64;
        let behind = target_ancestors
            .keys()
            .filter(|id| !source_ancestors.contains_key(*id))
            .count() as u64;
        let merge_base = self
            .merge_base(target_ref.commit_id, source_ref.commit_id)
            .await?
            .ok_or_else(|| {
                Error::Versioning(format!(
                    "branches {source} and {target} have no common merge base"
                ))
            })?;
        let already_up_to_date = target_ancestors.contains_key(&source_ref.commit_id);
        let fast_forward =
            !already_up_to_date && source_ancestors.contains_key(&target_ref.commit_id);
        let conflicts = if already_up_to_date || fast_forward {
            Vec::new()
        } else {
            let base = self.store.get_commit(&merge_base).await?;
            let target_commit = self.store.get_commit(&target_ref.commit_id).await?;
            let source_commit = self.store.get_commit(&source_ref.commit_id).await?;
            self.three_way_merge_plan(
                &base.tree.to_tree(),
                &target_commit.tree.to_tree(),
                &source_commit.tree.to_tree(),
            )
            .await?
            .conflicts
        };
        Ok(VersionMergePreview {
            source: source.to_string(),
            target: target.to_string(),
            source_head: hex::encode(source_ref.commit_id),
            target_head: hex::encode(target_ref.commit_id),
            merge_base: hex::encode(merge_base),
            ahead,
            behind,
            fast_forward,
            already_up_to_date,
            conflicts,
        })
    }

    /// Merge `source` into `target`. Descendant sources fast-forward the
    /// target; divergent histories produce a two-parent three-way merge.
    /// Conflict resolution applies to complete logical paths, with `ours`
    /// referring to the target and `theirs` referring to the source.
    pub async fn merge_branch(
        &self,
        source: &str,
        target: &str,
        strategy: VersionMergeConflictStrategy,
    ) -> Result<VersionMergeInfo> {
        validate_version_branch_name(source)?;
        validate_version_branch_name(target)?;
        if source == target {
            return Err(Error::invalid(
                "version branch merge",
                "source and target must differ",
            ));
        }
        let source_ref = self
            .store
            .get_branch(source)
            .await?
            .ok_or_else(|| Error::not_found("version branch", source))?;
        let target_ref = self
            .store
            .get_branch(target)
            .await?
            .ok_or_else(|| Error::not_found("version branch", target))?;
        if source_ref.commit_id == target_ref.commit_id
            || self
                .commit_is_ancestor(source_ref.commit_id, target_ref.commit_id)
                .await?
        {
            return Ok(VersionMergeInfo {
                source: source.to_string(),
                target: target.to_string(),
                commit: hex::encode(target_ref.commit_id),
                strategy,
                fast_forward: false,
                already_up_to_date: true,
            });
        }
        if self
            .commit_is_ancestor(target_ref.commit_id, source_ref.commit_id)
            .await?
        {
            let merged = self
                .store
                .fast_forward_branch(source, target, source_ref.commit_id, target_ref.commit_id)
                .await?;
            return Ok(VersionMergeInfo {
                source: source.to_string(),
                target: target.to_string(),
                commit: hex::encode(merged.commit_id),
                strategy,
                fast_forward: true,
                already_up_to_date: false,
            });
        }
        let base_id = self
            .merge_base(target_ref.commit_id, source_ref.commit_id)
            .await?
            .ok_or_else(|| {
                Error::Versioning(format!(
                    "branches {source} and {target} have no common merge base"
                ))
            })?;
        let base = self.store.get_commit(&base_id).await?;
        let target_commit = self.store.get_commit(&target_ref.commit_id).await?;
        let source_commit = self.store.get_commit(&source_ref.commit_id).await?;
        let merged_tree = self
            .resolve_three_way_merge(
                source,
                target,
                &base.tree.to_tree(),
                &target_commit.tree.to_tree(),
                &source_commit.tree.to_tree(),
                strategy,
            )
            .await?;
        let changes = self
            .diff_trees(&target_commit.tree.to_tree(), &merged_tree)
            .await?;
        let body = VersionCommitBody {
            parents: vec![target_ref.commit_id, source_ref.commit_id],
            tree: RootManifest::from_tree(&merged_tree),
            created_at: crate::control::now_unix(),
            message: format!("Merge {source} into {target} ({})", strategy.as_str()),
            paths: changes
                .into_iter()
                .map(|change| change.path().to_string())
                .collect(),
        };
        let id: [u8; 32] = Sha256::digest(postcard::to_allocvec(&body)?).into();
        let commit = VersionCommit {
            id,
            parents: body.parents,
            tree: body.tree,
            created_at: body.created_at,
            message: body.message,
            paths: body.paths,
        };
        let encoded = encode_versioned(COMMIT_VERSION, &commit)?;
        self.store
            .publish_commit(VersionPublishRequest {
                branch: target,
                expected: Some(target_ref.commit_id),
                required_ref: Some((source, source_ref.commit_id)),
                commit: &commit,
                encoded_commit: encoded,
                idempotency: None,
                max_bytes: self.max_bytes,
            })
            .await?;
        Ok(VersionMergeInfo {
            source: source.to_string(),
            target: target.to_string(),
            commit: hex::encode(commit.id),
            strategy,
            fast_forward: false,
            already_up_to_date: false,
        })
    }

    async fn commit_is_ancestor(&self, ancestor: [u8; 32], descendant: [u8; 32]) -> Result<bool> {
        let mut pending = vec![descendant];
        let mut seen = HashSet::new();
        while let Some(id) = pending.pop() {
            if id == ancestor {
                return Ok(true);
            }
            if !seen.insert(id) {
                continue;
            }
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                continue;
            };
            pending.extend(commit.parents);
        }
        Ok(false)
    }

    async fn merge_base(&self, left: [u8; 32], right: [u8; 32]) -> Result<Option<[u8; 32]>> {
        let left_distances = self.ancestor_distances(left).await?;
        let right_distances = self.ancestor_distances(right).await?;
        Ok(left_distances
            .into_iter()
            .filter_map(|(id, left_distance)| {
                right_distances
                    .get(&id)
                    .map(|right_distance| (id, left_distance + right_distance))
            })
            .min_by(|(left_id, left_distance), (right_id, right_distance)| {
                left_distance
                    .cmp(right_distance)
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(id, _)| id))
    }

    async fn ancestor_distances(&self, start: [u8; 32]) -> Result<HashMap<[u8; 32], usize>> {
        let mut distances = HashMap::new();
        let mut pending = VecDeque::from([(start, 0usize)]);
        while let Some((id, distance)) = pending.pop_front() {
            if distances.contains_key(&id) {
                continue;
            }
            distances.insert(id, distance);
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                continue;
            };
            pending.extend(
                commit
                    .parents
                    .into_iter()
                    .map(|parent| (parent, distance + 1)),
            );
        }
        Ok(distances)
    }

    async fn resolve_three_way_merge(
        &self,
        source: &str,
        target: &str,
        base: &Tree,
        left: &Tree,
        right: &Tree,
        strategy: VersionMergeConflictStrategy,
    ) -> Result<Tree> {
        let plan = self.three_way_merge_plan(base, left, right).await?;
        if strategy == VersionMergeConflictStrategy::Fail
            && let Some(path) = plan.conflicts.first()
        {
            return Err(Error::Versioning(format!(
                "merge conflict between {source} and {target} at {path}"
            )));
        }
        let mut mutations = plan.mutations;
        if strategy == VersionMergeConflictStrategy::Theirs && !plan.conflicts.is_empty() {
            let conflicts = plan.conflicts.into_iter().collect::<BTreeSet<_>>();
            let source_diff = self.prolly.diff(left, right).await.map_err(prolly_error)?;
            for diff in source_diff {
                let key = diff.key().to_vec();
                let path = version_path_from_tree_key(&key)
                    .map(|(path, _)| path)
                    .unwrap_or_else(|_| hex::encode(&key));
                if conflicts.contains(&path) {
                    mutations.push(mutation_from_diff(diff));
                }
            }
        }
        self.prolly
            .batch(left, mutations)
            .await
            .map_err(prolly_error)
    }

    async fn three_way_merge_plan(
        &self,
        base: &Tree,
        left: &Tree,
        right: &Tree,
    ) -> Result<ThreeWayMergePlan> {
        let left_diff = self.prolly.diff(base, left).await.map_err(prolly_error)?;
        let right_diff = self.prolly.diff(base, right).await.map_err(prolly_error)?;
        let left_changes = left_diff
            .into_iter()
            .map(|diff| (diff.key().to_vec(), diff_result_value(diff)))
            .collect::<BTreeMap<_, _>>();
        let right_changes = right_diff
            .into_iter()
            .map(|diff| {
                let key = diff.key().to_vec();
                let path = version_path_from_tree_key(&key)
                    .map(|(path, _)| path)
                    .unwrap_or_else(|_| hex::encode(&key));
                (key, diff_result_value(diff), path)
            })
            .collect::<Vec<_>>();
        let mut conflicts = BTreeSet::new();
        for (key, value, path) in &right_changes {
            if let Some(left_value) = left_changes.get(key)
                && left_value != value
            {
                conflicts.insert(path.clone());
            }
        }
        let mutations = right_changes
            .into_iter()
            .filter(|(key, _, path)| !left_changes.contains_key(key) && !conflicts.contains(path))
            .map(|(key, value, _)| match value {
                Some(val) => Mutation::Upsert { key, val },
                None => Mutation::Delete { key },
            })
            .collect();
        Ok(ThreeWayMergePlan {
            mutations,
            conflicts: conflicts.into_iter().collect(),
        })
    }

    pub async fn history(
        &self,
        path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VersionCommitInfo>> {
        Ok(self.history_page(path, limit, None).await?.0)
    }

    /// Resolve a commit ID, immutable tag, or branch and return the referenced
    /// commit, including every parent of a merge commit.
    pub async fn inspect_commit(&self, reference: &str) -> Result<VersionCommitInfo> {
        Ok(self.resolve_commit(reference).await?.into())
    }

    /// Return newest-first history for a named branch.
    pub async fn history_on_branch(
        &self,
        branch: &str,
        path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VersionCommitInfo>> {
        Ok(self
            .history_page_on_branch(branch, path, limit, None)
            .await?
            .0)
    }

    /// Return newest-first history after an optional exclusive commit cursor.
    /// The cursor is the last commit ID returned by the previous page.
    pub async fn history_page(
        &self,
        path: Option<&str>,
        limit: usize,
        page_token: Option<&str>,
    ) -> Result<(Vec<VersionCommitInfo>, Option<String>)> {
        self.history_page_on_branch("main", path, limit, page_token)
            .await
    }

    /// Return newest-first history for a named branch after an optional
    /// exclusive commit cursor.
    pub async fn history_page_on_branch(
        &self,
        branch: &str,
        path: Option<&str>,
        limit: usize,
        page_token: Option<&str>,
    ) -> Result<(Vec<VersionCommitInfo>, Option<String>)> {
        validate_version_branch_name(branch)?;
        let path = path.map(canonical_path).transpose()?;
        let mut next = match page_token {
            Some(page_token) => {
                let id = parse_commit_id(page_token)?;
                self.store.get_commit(&id).await?.parents.first().copied()
            }
            None => {
                let head = self.store.get_branch(branch).await?;
                if branch != "main" && head.is_none() {
                    return Err(Error::not_found("version branch", branch));
                }
                head.map(|head| head.commit_id)
            }
        };
        let mut history: Vec<VersionCommitInfo> = Vec::new();
        let limit = limit.clamp(1, 10_000);
        while let Some(id) = next {
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                break;
            };
            next = commit.parents.first().copied();
            if path.as_ref().is_none_or(|path| {
                commit
                    .paths
                    .iter()
                    .any(|changed| path_is_within(path, changed) || path_is_within(changed, path))
            }) {
                history.push(commit.into());
                if history.len() > limit {
                    break;
                }
            }
        }
        let next_page_token = (history.len() > limit).then(|| history[limit - 1].id.clone());
        history.truncate(limit);
        Ok((history, next_page_token))
    }

    /// Compare two immutable commits and return one logical change per path.
    /// File chunk changes are folded into their owning file, so callers never
    /// see internal Prolly metadata or chunk keys.
    pub async fn diff_commits(&self, from: &str, to: &str) -> Result<Vec<VersionPathChange>> {
        let from = self.resolve_commit(from).await?;
        let to = self.resolve_commit(to).await?;
        self.diff_trees(&from.tree.to_tree(), &to.tree.to_tree())
            .await
    }

    async fn diff_trees(&self, from: &Tree, to: &Tree) -> Result<Vec<VersionPathChange>> {
        let diffs = self.prolly.diff(from, to).await.map_err(prolly_error)?;
        let mut paths: BTreeMap<String, (Option<VersionPathChangeKind>, bool)> = BTreeMap::new();
        for diff in diffs {
            let (key, raw_change) = match &diff {
                Diff::Added { key, .. } => (key.as_slice(), VersionPathChangeKind::Added),
                Diff::Removed { key, .. } => (key.as_slice(), VersionPathChangeKind::Deleted),
                Diff::Changed { key, .. } => (key.as_slice(), VersionPathChangeKind::Modified),
            };
            let (path, metadata) = version_path_from_tree_key(key)?;
            let entry = paths.entry(path).or_insert((None, false));
            if metadata {
                entry.0 = Some(raw_change);
            } else {
                entry.1 = true;
            }
        }
        Ok(paths
            .into_iter()
            .filter_map(|(path, (metadata_change, content_changed))| {
                metadata_change
                    .or(content_changed.then_some(VersionPathChangeKind::Modified))
                    .map(|change| VersionPathChange { path, change })
            })
            .collect())
    }

    /// Return a lexicographically ordered page from [`Self::diff_commits`].
    /// The page token is the last path returned by the previous page.
    pub async fn diff_commits_page(
        &self,
        from: &str,
        to: &str,
        limit: usize,
        page_token: Option<&str>,
    ) -> Result<(Vec<VersionPathChange>, Option<String>)> {
        let page_token = page_token.map(canonical_path).transpose()?;
        let limit = limit.clamp(1, 10_000);
        let mut changes = self.diff_commits(from, to).await?;
        if let Some(page_token) = page_token {
            changes.retain(|change| change.path > page_token);
        }
        let next_page_token = (changes.len() > limit).then(|| changes[limit - 1].path.clone());
        changes.truncate(limit);
        Ok((changes, next_page_token))
    }

    pub async fn read_file(&self, commit: &str, path: &str) -> Result<Bytes> {
        Ok(self.read_file_range(commit, path, 0, u64::MAX).await?.data)
    }

    /// Read a bounded byte range without materializing the complete versioned
    /// file. The returned range is clipped to EOF.
    pub async fn read_file_range(
        &self,
        commit: &str,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<VersionFileRange> {
        let commit = self.resolve_commit(commit).await?;
        let tree = commit.tree.to_tree();
        let canonical = canonical_path(path)?;
        let metadata = self
            .prolly
            .get(&tree, &file_meta_key(&canonical))
            .await
            .map_err(prolly_error)?
            .ok_or_else(|| Error::not_found("versioned path", &canonical))
            .and_then(|bytes| decode_version_entry(&bytes))?;
        let chunk_count = match &metadata.data {
            VersionEntryData::File { chunk_count } => *chunk_count,
            VersionEntryData::Symlink { target } => {
                let total_size = target.len() as u64;
                let start = offset.min(total_size);
                let end = start.saturating_add(length).min(total_size);
                return Ok(VersionFileRange {
                    offset: start,
                    total_size,
                    data: Bytes::copy_from_slice(&target[start as usize..end as usize]),
                    eof: end == total_size,
                });
            }
            VersionEntryData::Directory => {
                return Err(Error::invalid(
                    "versioned path",
                    format!("{canonical} is a directory"),
                ));
            }
        };
        let start = offset.min(metadata.size);
        let end = start.saturating_add(length).min(metadata.size);
        let expected_size = usize::try_from(end - start).map_err(|_| {
            Error::Versioning(format!("requested range for {canonical} is too large"))
        })?;
        if expected_size == 0 {
            return Ok(VersionFileRange {
                offset: start,
                total_size: metadata.size,
                data: Bytes::new(),
                eof: end == metadata.size,
            });
        }
        let first_chunk = start / self.chunk_size;
        let last_chunk = (end - 1) / self.chunk_size;
        if last_chunk >= u64::from(chunk_count) {
            return Err(Error::Versioning(format!(
                "versioned contents for {canonical} are shorter than its recorded size"
            )));
        }
        let mut output = Vec::with_capacity(expected_size);
        for index in first_chunk..=last_chunk {
            let index = u32::try_from(index)
                .map_err(|_| Error::Versioning(format!("too many chunks for {canonical}")))?;
            let encoded = self
                .prolly
                .get(&tree, &file_chunk_key(&canonical, index))
                .await
                .map_err(prolly_error)?
                .ok_or_else(|| {
                    Error::Versioning(format!("missing chunk {index} for {canonical}"))
                })?;
            let reference = ValueRef::from_stored_bytes(&encoded).map_err(prolly_error)?;
            let ValueRef::Blob(reference) = reference else {
                return Err(Error::Versioning(format!(
                    "chunk {index} for {canonical} is not a blob reference"
                )));
            };
            let chunk = self
                .store
                .get_blob(&reference)
                .await
                .map_err(version_store_error)?
                .ok_or_else(|| {
                    Error::Versioning(format!("missing blob for chunk {index} of {canonical}"))
                })?;
            let chunk_offset = u64::from(index) * self.chunk_size;
            let copy_start = start.saturating_sub(chunk_offset) as usize;
            let copy_end = (end - chunk_offset).min(chunk.len() as u64) as usize;
            if copy_start > copy_end || copy_end > chunk.len() {
                return Err(Error::Versioning(format!(
                    "invalid chunk {index} length for {canonical}"
                )));
            }
            output.extend_from_slice(&chunk[copy_start..copy_end]);
        }
        if output.len() != expected_size {
            return Err(Error::Versioning(format!(
                "versioned contents for {canonical} are shorter than its recorded size"
            )));
        }
        Ok(VersionFileRange {
            offset: start,
            total_size: metadata.size,
            data: Bytes::from(output),
            eof: end == metadata.size,
        })
    }

    pub async fn restore_file(&self, live: &dyn Vfs, commit: &str, path: &str) -> Result<()> {
        let commit = self.resolve_commit(commit).await?;
        let tree = commit.tree.to_tree();
        let canonical = canonical_path(path)?;
        let mut entries = BTreeMap::new();
        let mut range = self
            .prolly
            .prefix(&tree, b"m/")
            .await
            .map_err(prolly_error)?;
        while let Some(entry) = range.next().await {
            let (key, value) = entry.map_err(prolly_error)?;
            let path = std::str::from_utf8(key.strip_prefix(b"m/").unwrap_or_default())
                .map_err(|_| Error::Versioning("version tree contains a non-UTF-8 path".into()))?;
            if path_is_within(path, &canonical) {
                entries.insert(path.to_string(), decode_version_entry(&value)?);
            }
        }
        if !entries.contains_key(&canonical) {
            return Err(Error::not_found("versioned path", canonical));
        }

        let commit_id = commit_id_string(&commit.id);
        for (path, metadata) in entries {
            match &metadata.data {
                VersionEntryData::Directory => {
                    restore_directory_entry(live, &path, &metadata).await?;
                }
                VersionEntryData::File { .. } => {
                    self.restore_regular_file(live, &commit_id, &path, &metadata)
                        .await?;
                }
                VersionEntryData::Symlink { target } => {
                    restore_symlink_entry(live, &path, &metadata, target).await?;
                }
            }
        }
        Ok(())
    }

    async fn restore_regular_file(
        &self,
        live: &dyn Vfs,
        commit: &str,
        canonical: &str,
        metadata: &VersionEntry,
    ) -> Result<()> {
        let (parent, name) = resolve_parent(live, canonical).await?;
        let temp_name = format!(".slatefs-restore-{}", uuid::Uuid::new_v4());
        let creds = Credentials::root();
        let created = live
            .create(&creds, parent, temp_name.as_bytes(), metadata.mode, true)
            .await
            .map_err(fs_error)?;
        let result = async {
            let mut offset = 0;
            while offset < metadata.size {
                let range = self
                    .read_file_range(commit, canonical, offset, self.chunk_size)
                    .await?;
                if range.data.is_empty() {
                    return Err(Error::Versioning(format!(
                        "versioned contents for {canonical} did not advance"
                    )));
                }
                live.write(&creds, created.ino, offset, &range.data)
                    .await
                    .map_err(fs_error)?;
                offset = offset.saturating_add(range.data.len() as u64);
            }
            live.setattr(
                &creds,
                created.ino,
                SetAttrs {
                    mode: Some(metadata.mode),
                    uid: Some(metadata.uid),
                    gid: Some(metadata.gid),
                    size: Some(metadata.size),
                    atime: Some(TimeSet::Time(metadata.atime)),
                    mtime: Some(TimeSet::Time(metadata.mtime)),
                },
            )
            .await
            .map_err(fs_error)?;
            live.fsync(&creds, created.ino).await.map_err(fs_error)?;
            live.rename(&creds, parent, temp_name.as_bytes(), parent, &name)
                .await
                .map_err(fs_error)
        }
        .await;
        if result.is_err() {
            let _ = live.unlink(&creds, parent, temp_name.as_bytes()).await;
        }
        result
    }

    async fn resolve_commit(&self, reference: &str) -> Result<VersionCommit> {
        if let Ok(id) = parse_commit_id(reference) {
            return self.store.get_commit(&id).await;
        }
        validate_version_named_ref("version reference", reference)?;
        if let Some(tag) = self.store.try_get_tag(reference).await? {
            return self.store.get_commit(&tag.commit_id).await.map_err(|_| {
                Error::Versioning(format!(
                    "version tag {} references missing commit {}",
                    tag.name,
                    hex::encode(tag.commit_id)
                ))
            });
        }
        if let Some(branch) = self.store.get_branch(reference).await? {
            return self.store.get_commit(&branch.commit_id).await.map_err(|_| {
                Error::Versioning(format!(
                    "version branch {reference} references missing commit {}",
                    hex::encode(branch.commit_id)
                ))
            });
        }
        Err(Error::not_found(
            "version commit, tag, or branch",
            reference,
        ))
    }
}

async fn restore_directory_entry(
    live: &dyn Vfs,
    canonical: &str,
    metadata: &VersionEntry,
) -> Result<()> {
    let creds = Credentials::root();
    let attr = match resolve_path_optional(live, canonical).await? {
        Some(attr) if attr.kind == FileKind::Dir => attr,
        Some(_) => {
            return Err(Error::invalid(
                "restore path",
                format!("{canonical} exists and is not a directory"),
            ));
        }
        None => {
            let (parent, name) = resolve_parent(live, canonical).await?;
            live.mkdir(&creds, parent, &name, metadata.mode)
                .await
                .map_err(fs_error)?
        }
    };
    live.setattr(
        &creds,
        attr.ino,
        SetAttrs {
            mode: Some(metadata.mode),
            uid: Some(metadata.uid),
            gid: Some(metadata.gid),
            atime: Some(TimeSet::Time(metadata.atime)),
            mtime: Some(TimeSet::Time(metadata.mtime)),
            ..SetAttrs::default()
        },
    )
    .await
    .map_err(fs_error)?;
    Ok(())
}

async fn restore_symlink_entry(
    live: &dyn Vfs,
    canonical: &str,
    metadata: &VersionEntry,
    target: &[u8],
) -> Result<()> {
    let (parent, name) = resolve_parent(live, canonical).await?;
    let temp_name = format!(".slatefs-restore-{}", uuid::Uuid::new_v4());
    let creds = Credentials::root();
    let created = live
        .symlink(&creds, parent, temp_name.as_bytes(), target)
        .await
        .map_err(fs_error)?;
    let result = async {
        live.setattr(
            &creds,
            created.ino,
            SetAttrs {
                uid: Some(metadata.uid),
                gid: Some(metadata.gid),
                atime: Some(TimeSet::Time(metadata.atime)),
                mtime: Some(TimeSet::Time(metadata.mtime)),
                ..SetAttrs::default()
            },
        )
        .await
        .map_err(fs_error)?;
        live.rename(&creds, parent, temp_name.as_bytes(), parent, &name)
            .await
            .map_err(fs_error)
    }
    .await;
    if result.is_err() {
        let _ = live.unlink(&creds, parent, temp_name.as_bytes()).await;
    }
    result
}

async fn resolve_path_optional(vfs: &dyn Vfs, canonical: &str) -> Result<Option<FileAttr>> {
    let creds = Credentials::root();
    let mut current = vfs.getattr(&creds, ROOT_INO).await.map_err(fs_error)?;
    for component in path_components(canonical) {
        current = match vfs.lookup(&creds, current.ino, component.as_bytes()).await {
            Ok(attr) => attr,
            Err(crate::vfs::FsError::NotFound) => return Ok(None),
            Err(error) => return Err(fs_error(error)),
        };
    }
    Ok(Some(current))
}

async fn resolve_parent(vfs: &dyn Vfs, canonical: &str) -> Result<(u64, Vec<u8>)> {
    let components = path_components(canonical);
    let (name, parents) = components
        .split_last()
        .ok_or_else(|| Error::invalid("versioned path", "root cannot be versioned as a file"))?;
    let creds = Credentials::root();
    let mut parent = ROOT_INO;
    for component in parents {
        let attr = vfs
            .lookup(&creds, parent, component.as_bytes())
            .await
            .map_err(fs_error)?;
        if attr.kind != FileKind::Dir {
            return Err(Error::invalid(
                "versioned path",
                "parent is not a directory",
            ));
        }
        parent = attr.ino;
    }
    Ok((parent, name.as_bytes().to_vec()))
}

fn canonical_path(path: &str) -> Result<String> {
    if path.as_bytes().contains(&0) {
        return Err(Error::invalid("versioned path", "contains NUL"));
    }
    let components: Vec<_> = path
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.is_empty() {
        return Err(Error::invalid("versioned path", "must name a file"));
    }
    if components
        .iter()
        .any(|component| *component == "." || *component == "..")
    {
        return Err(Error::invalid(
            "versioned path",
            "dot components are not allowed",
        ));
    }
    Ok(format!("/{}", components.join("/")))
}

fn canonicalize_path_set(paths: &[String]) -> Result<Vec<String>> {
    if paths.is_empty() {
        return Err(Error::invalid(
            "versioned paths",
            "provide at least one path",
        ));
    }
    let mut canonical = paths
        .iter()
        .map(|path| canonical_path(path))
        .collect::<Result<Vec<_>>>()?;
    canonical.sort();
    canonical.dedup();
    let mut roots: Vec<String> = Vec::with_capacity(canonical.len());
    for path in canonical {
        if roots.iter().any(|root| path_is_within(&path, root)) {
            continue;
        }
        roots.push(path);
    }
    Ok(roots)
}

fn path_is_within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn version_key_matches_any_path(key: &[u8], paths: &[String]) -> bool {
    let path = if let Some(path) = key.strip_prefix(b"m/") {
        path
    } else if let Some(chunk) = key.strip_prefix(b"c/") {
        chunk.split(|byte| *byte == 0).next().unwrap_or_default()
    } else {
        return false;
    };
    paths
        .iter()
        .any(|root| std::str::from_utf8(path).is_ok_and(|path| path_is_within(path, root)))
}

fn version_path_from_tree_key(key: &[u8]) -> Result<(String, bool)> {
    let (path, metadata) = if let Some(path) = key.strip_prefix(b"m/") {
        (path, true)
    } else if let Some(chunk) = key.strip_prefix(b"c/") {
        (
            chunk.split(|byte| *byte == 0).next().unwrap_or_default(),
            false,
        )
    } else {
        return Err(Error::Versioning(format!(
            "version tree contains unknown key prefix {}",
            hex::encode(key)
        )));
    };
    let path = std::str::from_utf8(path)
        .map_err(|_| Error::Versioning("version tree contains a non-UTF-8 path".into()))?;
    Ok((canonical_path(path)?, metadata))
}

fn diff_result_value(diff: Diff) -> Option<Vec<u8>> {
    match diff {
        Diff::Added { val, .. } => Some(val),
        Diff::Removed { .. } => None,
        Diff::Changed { new, .. } => Some(new),
    }
}

fn mutation_from_diff(diff: Diff) -> Mutation {
    let key = diff.key().to_vec();
    match diff_result_value(diff) {
        Some(val) => Mutation::Upsert { key, val },
        None => Mutation::Delete { key },
    }
}

fn path_components(path: &str) -> Vec<&str> {
    path.trim_start_matches('/').split('/').collect()
}

fn file_meta_key(path: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(path.len() + 3);
    key.extend_from_slice(b"m/");
    key.extend_from_slice(path.as_bytes());
    key
}

fn file_chunk_key(path: &str, index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(path.len() + 8);
    key.extend_from_slice(b"c/");
    key.extend_from_slice(path.as_bytes());
    key.push(0);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn prefixed_key(prefix: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(prefix.len() + key.len());
    result.extend_from_slice(prefix);
    result.extend_from_slice(key);
    result
}

fn blob_key(cid: &Cid) -> Vec<u8> {
    prefixed_key(BLOB_PREFIX, cid.as_bytes())
}

fn commit_key(id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(COMMIT_PREFIX, id)
}

fn tag_key(name: &str) -> Vec<u8> {
    prefixed_key(TAG_PREFIX, name.as_bytes())
}

fn branch_key(name: &str) -> Vec<u8> {
    prefixed_key(BRANCH_PREFIX, name.as_bytes())
}

fn idempotency_key(key_hash: &[u8; 32]) -> Vec<u8> {
    prefixed_key(IDEMPOTENCY_PREFIX, key_hash)
}

fn pruned_commit_key(id: &[u8; 32]) -> Vec<u8> {
    prefixed_key(PRUNED_COMMIT_PREFIX, id)
}

fn pruned_commit_key_bytes(id: &[u8]) -> Vec<u8> {
    prefixed_key(PRUNED_COMMIT_PREFIX, id)
}

fn parse_commit_id(value: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(value).map_err(|error| Error::invalid("version commit", error.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| Error::invalid("version commit", "expected a 64-character SHA-256 id"))
}

fn commit_id_string(id: &[u8; 32]) -> String {
    hex::encode(id)
}

fn validate_version_tag_name(name: &str) -> Result<()> {
    validate_version_named_ref("version tag", name)
}

fn validate_version_branch_name(name: &str) -> Result<()> {
    validate_version_named_ref("version branch", name)
}

fn validate_version_named_ref(what: &'static str, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(Error::invalid(
            what,
            "must contain 1 to 128 ASCII characters",
        ));
    }
    if name == "."
        || name == ".."
        || (name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::invalid(
            what,
            "use only ASCII letters, digits, '.', '_', or '-' and do not use a SHA-256-shaped name",
        ));
    }
    Ok(())
}

fn version_commit_idempotency_intent(
    key: &str,
    branch: &str,
    canonical_paths: &[String],
    message: &str,
) -> Result<VersionCommitIdempotencyIntent> {
    if key.is_empty() {
        return Err(Error::invalid(
            "version commit idempotency key",
            "must not be empty",
        ));
    }
    if key.len() > 256 {
        return Err(Error::invalid(
            "version commit idempotency key",
            "must not exceed 256 UTF-8 bytes",
        ));
    }
    let request = VersionCommitRequestFingerprint {
        version: 1,
        branch,
        message,
        paths: canonical_paths,
    };
    let request_fingerprint = Sha256::digest(postcard::to_allocvec(&request)?).into();
    Ok(VersionCommitIdempotencyIntent {
        key_hash: Sha256::digest(key.as_bytes()).into(),
        request_fingerprint,
    })
}

fn encode_versioned<T: Serialize>(version: u8, value: &T) -> Result<Vec<u8>> {
    let mut bytes = vec![version];
    bytes.extend(postcard::to_allocvec(value)?);
    Ok(bytes)
}

fn decode_version_entry(bytes: &[u8]) -> Result<VersionEntry> {
    decode_versioned(ENTRY_META_VERSION, bytes, "version entry")
}

fn decode_versioned<T: for<'de> Deserialize<'de>>(
    expected: u8,
    bytes: &[u8],
    kind: &'static str,
) -> Result<T> {
    match bytes.split_first() {
        Some((&version, payload)) if version == expected => Ok(postcard::from_bytes(payload)?),
        Some((&version, _)) => Err(Error::invalid(
            kind,
            format!("format version {version}, expected {expected}"),
        )),
        None => Err(Error::invalid(kind, "empty record")),
    }
}

fn prolly_error(error: prolly::Error) -> Error {
    Error::Versioning(error.to_string())
}

fn version_store_error(error: VersionStoreError) -> Error {
    Error::Versioning(error.to_string())
}

fn fs_error(error: crate::vfs::FsError) -> Error {
    Error::Versioning(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_lease_owner_cannot_release_successor() {
        let object_store: Arc<dyn ObjectStore> = store::resolve_root("memory:///").unwrap();
        let first = VersionMaintenanceLease::acquire(
            Arc::clone(&object_store),
            "t",
            "v",
            "first".to_string(),
            "gc",
        )
        .await
        .unwrap();
        first.release().await.unwrap();
        let successor = VersionMaintenanceLease::acquire(
            Arc::clone(&object_store),
            "t",
            "v",
            "successor".to_string(),
            "purge",
        )
        .await
        .unwrap();

        // This uses the first owner's stale object-store revision. Its
        // conditional update must not expire the successor's active lease.
        first.release().await.unwrap();
        let contender = VersionMaintenanceLease::acquire(
            object_store,
            "t",
            "v",
            "contender".to_string(),
            "verify",
        )
        .await;
        assert!(matches!(contender, Err(Error::AlreadyExists { .. })));
        successor.release().await.unwrap();
    }

    #[tokio::test]
    async fn local_file_lease_releases_without_conditional_update() {
        let directory = tempfile::tempdir().unwrap();
        let object_store: Arc<dyn ObjectStore> =
            store::resolve_root(&format!("file://{}", directory.path().display())).unwrap();
        let first = VersionMaintenanceLease::acquire(
            Arc::clone(&object_store),
            "t",
            "v",
            "first".to_string(),
            "commit",
        )
        .await
        .unwrap();
        first.release().await.unwrap();
        let second = VersionMaintenanceLease::acquire(
            object_store,
            "t",
            "v",
            "second".to_string(),
            "verify",
        )
        .await
        .unwrap();
        second.release().await.unwrap();
    }

    #[tokio::test]
    async fn operator_can_break_exact_expired_local_file_lease() {
        let directory = tempfile::tempdir().unwrap();
        let object_store: Arc<dyn ObjectStore> =
            store::resolve_root(&format!("file://{}", directory.path().display())).unwrap();
        let record = VersionMaintenanceLeaseInfo {
            tenant: "t".to_string(),
            volume: "v".to_string(),
            owner: "crashed-owner".to_string(),
            operation: "repository".to_string(),
            acquired_at: 1,
            expires_at: 2,
        };
        object_store
            .put_opts(
                &store::version_lease_path("t", "v"),
                encode_versioned(MAINTENANCE_LEASE_VERSION, &record)
                    .unwrap()
                    .into(),
                PutOptions::from(PutMode::Create),
            )
            .await
            .unwrap();
        assert!(
            force_break_expired_version_maintenance_lease(
                Arc::clone(&object_store),
                "t",
                "v",
                "crashed-owner",
            )
            .await
            .unwrap()
        );
        assert!(
            try_get_version_maintenance_lease(object_store, "t", "v")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn canonical_paths_reject_ambiguous_components() {
        assert_eq!(canonical_path("a//b").unwrap(), "/a/b");
        assert!(canonical_path("/").is_err());
        assert!(canonical_path("a/../b").is_err());
    }

    #[test]
    fn version_keys_do_not_collide() {
        assert_ne!(file_meta_key("/a"), file_chunk_key("/a", 0));
        assert_ne!(file_chunk_key("/a", 1), file_chunk_key("/a", 2));
        assert_ne!(file_chunk_key("/a", 0), file_chunk_key("/a/0", 0));
    }
}
