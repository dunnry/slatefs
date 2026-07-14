//! Opt-in, per-volume file versioning backed by Prolly trees.
//!
//! The live filesystem remains the existing mutable SlateDB volume. This
//! module opens a separate encrypted database only for explicit versioning
//! operations, so disabled volumes pay no storage or request-path cost.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use bytes::Bytes;
use prolly::{
    AsyncBlobStore, AsyncProlly, AsyncStore, BatchOp, BlobRef, Cid, Config as ProllyConfig,
    Mutation, RootManifest, ValueRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slatedb::bytes::Bytes as SlateBytes;
use slatedb::object_store::ObjectStore;
use slatedb::{Db, Settings, WriteBatch};
use tokio::sync::Mutex;

use crate::config::AtimeMode;
use crate::control::{ControlPlane, VolumeRecord};
use crate::crypto::transformer::SlateBlockTransformer;
use crate::error::{Error, Result};
use crate::meta::inode::{FileKind, ROOT_INO, Timespec};
use crate::store;
use crate::vfs::{Credentials, FileAttr, SetAttrs, TimeSet, Vfs};
use crate::volume::Volume;

const NODE_PREFIX: &[u8] = b"pn/";
const BLOB_PREFIX: &[u8] = b"pb/";
const COMMIT_PREFIX: &[u8] = b"pc/";
const PRUNED_COMMIT_PREFIX: &[u8] = b"pp/";
const HEAD_KEY: &[u8] = b"pr/heads/main";
const LEGACY_FILE_META_VERSION: u8 = 1;
const ENTRY_META_VERSION: u8 = 2;
const COMMIT_VERSION: u8 = 1;
const REF_VERSION: u8 = 1;

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
        self.get_raw(HEAD_KEY)
            .await
            .map_err(version_store_error)?
            .map(|bytes| decode_versioned(REF_VERSION, &bytes, "version ref"))
            .transpose()
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
        expected: Option<[u8; 32]>,
        commit: &VersionCommit,
        encoded_commit: Vec<u8>,
    ) -> Result<()> {
        let _guard = self.ref_lock.lock().await;
        let current = self.get_head().await?;
        if current.as_ref().map(|head| head.commit_id) != expected {
            return Err(Error::Versioning(format!(
                "branch moved while committing; expected {}, found {}",
                expected
                    .map(hex::encode)
                    .unwrap_or_else(|| "empty".to_string()),
                current
                    .map(|head| hex::encode(head.commit_id))
                    .unwrap_or_else(|| "empty".to_string())
            )));
        }

        let head = VersionRef {
            commit_id: commit.id,
            tree: commit.tree.clone(),
        };
        let mut batch = WriteBatch::new();
        batch.put(commit_key(&commit.id), encoded_commit);
        batch.put(HEAD_KEY, encode_versioned(REF_VERSION, &head)?);
        self.db.write(batch).await?;
        self.db.flush().await?;
        Ok(())
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
struct LegacyFileVersion {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime: Timespec,
    mtime: Timespec,
    chunk_count: u32,
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

impl From<LegacyFileVersion> for VersionEntry {
    fn from(file: LegacyFileVersion) -> Self {
        Self {
            mode: file.mode,
            uid: file.uid,
            gid: file.gid,
            size: file.size,
            atime: file.atime,
            mtime: file.mtime,
            data: VersionEntryData::File {
                chunk_count: file.chunk_count,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionCommit {
    id: [u8; 32],
    parent: Option<[u8; 32]>,
    tree: RootManifest,
    created_at: u64,
    message: String,
    paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionCommitBody {
    parent: Option<[u8; 32]>,
    tree: RootManifest,
    created_at: u64,
    message: String,
    paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionRef {
    commit_id: [u8; 32],
    tree: RootManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionCommitInfo {
    pub id: String,
    pub parent: Option<String>,
    pub created_at: u64,
    pub message: String,
    pub paths: Vec<String>,
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

impl From<VersionCommit> for VersionCommitInfo {
    fn from(commit: VersionCommit) -> Self {
        Self {
            id: hex::encode(commit.id),
            parent: commit.parent.map(hex::encode),
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
}

/// Permanently delete the physical version-repository prefix. The caller must
/// ensure no version repository for this volume is open.
pub async fn purge_version_history(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    tenant: &str,
    volume: &str,
) -> Result<usize> {
    control.get_volume(tenant, volume).await?;
    store::delete_prefix(&object_store, &store::version_db_prefix(tenant, volume)).await
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
        Self::open_for_record(&record, dek, object_store, max_bytes).await
    }

    async fn open_for_record(
        record: &VolumeRecord,
        dek: crate::crypto::Secret32,
        object_store: Arc<dyn ObjectStore>,
        max_bytes: Option<u64>,
    ) -> Result<Self> {
        if !matches!(record.kind, crate::meta::superblock::VolumeKind::Filesystem) {
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
        .await?;
        let store = VersionStore::new(db);
        let prolly = AsyncProlly::new(store.clone(), ProllyConfig::default());
        Ok(Self {
            store,
            prolly,
            max_bytes,
            chunk_size: u64::from(record.chunk_size),
        })
    }

    pub async fn close(&self) -> Result<()> {
        self.store.db.close().await.map_err(Error::from)
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
        let head = self.store.get_head().await?;
        let mut next = head.as_ref().map(|head| head.commit_id);
        let mut seen = HashSet::new();
        let mut trees = Vec::new();
        let mut commits = 0u64;
        while let Some(id) = next {
            if !seen.insert(id) {
                return Err(Error::Versioning(format!(
                    "commit chain contains a cycle at {}",
                    hex::encode(id)
                )));
            }
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                if self.store.is_pruned_commit(&id).await? {
                    break;
                }
                return Err(Error::not_found("version commit", hex::encode(id)));
            };
            let body = VersionCommitBody {
                parent: commit.parent,
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
            next = commit.parent;
            commits += 1;
        }
        if let (Some(head), Some(tree)) = (head, trees.first())
            && head.tree.to_tree() != *tree
        {
            return Err(Error::Versioning(
                "head tree does not match the head commit".into(),
            ));
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
            next = commit.parent;
            let position = chain.len();
            let within_count = keep_last.is_none_or(|keep| position < keep as usize);
            let within_age = cutoff.is_none_or(|cutoff| commit.created_at >= cutoff);
            if position == 0 || (within_count && within_age) {
                retained.push(commit.clone());
            }
            chain.push(commit);
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
        self.commit_paths_inner(live, None, paths, message).await
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
        self.commit_paths_inner(live, Some(live), paths, message)
            .await
    }

    async fn commit_paths_inner(
        &self,
        live: &dyn Vfs,
        writer_guard: Option<&Volume>,
        paths: &[String],
        message: String,
    ) -> Result<VersionCommitInfo> {
        let canonical = canonicalize_path_set(paths)?;

        let head = self.store.get_head().await?;
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
            parent: head.as_ref().map(|head| head.commit_id),
            tree: RootManifest::from_tree(&tree),
            created_at: crate::control::now_unix(),
            message,
            paths: canonical,
        };
        let body_bytes = postcard::to_allocvec(&body)?;
        let id: [u8; 32] = Sha256::digest(&body_bytes).into();
        let commit = VersionCommit {
            id,
            parent: body.parent,
            tree: body.tree,
            created_at: body.created_at,
            message: body.message,
            paths: body.paths,
        };
        let encoded = encode_versioned(COMMIT_VERSION, &commit)?;
        if let Some(max_bytes) = self.max_bytes {
            let stats = self.stats().await?;
            let projected = stats.bytes.saturating_add(encoded.len() as u64);
            if projected > max_bytes {
                return Err(Error::Versioning(format!(
                    "version history quota exceeded: {projected} bytes projected, {max_bytes} bytes allowed"
                )));
            }
        }
        if let Some(writer_guard) = writer_guard {
            writer_guard.validate_writer_lease().await?;
        }
        self.store
            .publish_commit(head.map(|head| head.commit_id), &commit, encoded)
            .await?;
        Ok(commit.into())
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

    pub async fn history(
        &self,
        path: Option<&str>,
        limit: usize,
    ) -> Result<Vec<VersionCommitInfo>> {
        let path = path.map(canonical_path).transpose()?;
        let mut next = self.store.get_head().await?.map(|head| head.commit_id);
        let mut history = Vec::new();
        let limit = limit.clamp(1, 10_000);
        while let Some(id) = next {
            let Some(commit) = self.store.try_get_commit(&id).await? else {
                break;
            };
            next = commit.parent;
            if path.as_ref().is_none_or(|path| {
                commit
                    .paths
                    .iter()
                    .any(|changed| path_is_within(path, changed) || path_is_within(changed, path))
            }) {
                history.push(commit.into());
                if history.len() == limit {
                    break;
                }
            }
        }
        Ok(history)
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
        let id = parse_commit_id(commit)?;
        let commit = self.store.get_commit(&id).await?;
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
        let id = parse_commit_id(commit)?;
        let commit = self.store.get_commit(&id).await?;
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

fn encode_versioned<T: Serialize>(version: u8, value: &T) -> Result<Vec<u8>> {
    let mut bytes = vec![version];
    bytes.extend(postcard::to_allocvec(value)?);
    Ok(bytes)
}

fn decode_version_entry(bytes: &[u8]) -> Result<VersionEntry> {
    match bytes.first().copied() {
        Some(LEGACY_FILE_META_VERSION) => decode_versioned::<LegacyFileVersion>(
            LEGACY_FILE_META_VERSION,
            bytes,
            "legacy file version",
        )
        .map(VersionEntry::from),
        Some(ENTRY_META_VERSION) => decode_versioned(ENTRY_META_VERSION, bytes, "version entry"),
        Some(version) => Err(Error::invalid(
            "version entry",
            format!("format version {version}, expected 1 or 2"),
        )),
        None => Err(Error::invalid("version entry", "empty record")),
    }
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

    #[test]
    fn legacy_file_metadata_remains_readable() {
        let legacy = LegacyFileVersion {
            mode: 0o640,
            uid: 1,
            gid: 2,
            size: 3,
            atime: Timespec { secs: 4, nanos: 5 },
            mtime: Timespec { secs: 6, nanos: 7 },
            chunk_count: 8,
        };
        let encoded = encode_versioned(LEGACY_FILE_META_VERSION, &legacy).unwrap();
        let decoded = decode_version_entry(&encoded).unwrap();
        assert_eq!(decoded.mode, legacy.mode);
        assert_eq!(decoded.size, legacy.size);
        assert_eq!(
            decoded.data,
            VersionEntryData::File {
                chunk_count: legacy.chunk_count
            }
        );
    }
}
