//! Opt-in, per-volume file versioning backed by Prolly trees.
//!
//! The live filesystem remains the existing mutable SlateDB volume. This
//! module opens a separate encrypted database only for explicit versioning
//! operations, so disabled volumes pay no storage or request-path cost.

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

const NODE_PREFIX: &[u8] = b"pn/";
const BLOB_PREFIX: &[u8] = b"pb/";
const COMMIT_PREFIX: &[u8] = b"pc/";
const HEAD_KEY: &[u8] = b"pr/heads/main";
const FILE_META_VERSION: u8 = 1;
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
        let key = commit_key(id);
        let bytes = self
            .get_raw(&key)
            .await
            .map_err(version_store_error)?
            .ok_or_else(|| Error::not_found("version commit", hex::encode(id)))?;
        decode_versioned(COMMIT_VERSION, &bytes, "version commit")
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
struct FileVersion {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime: Timespec,
    mtime: Timespec,
    chunk_count: u32,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionCommitInfo {
    pub id: String,
    pub parent: Option<String>,
    pub created_at: u64,
    pub message: String,
    pub paths: Vec<String>,
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
        let record = control.get_mountable_volume(tenant, volume).await?;
        let dek = control.unwrap_volume_dek(&record).await?;
        Self::open_for_record(&record, dek, object_store).await
    }

    async fn open_for_record(
        record: &VolumeRecord,
        dek: crate::crypto::Secret32,
        object_store: Arc<dyn ObjectStore>,
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
        Ok(Self { store, prolly })
    }

    pub async fn close(&self) -> Result<()> {
        self.store.db.close().await.map_err(Error::from)
    }

    pub async fn commit_file(
        &self,
        live: &dyn Vfs,
        path: &str,
        message: String,
    ) -> Result<VersionCommitInfo> {
        let canonical = canonical_path(path)?;
        let attr = resolve_path(live, &canonical).await?;
        if attr.kind != FileKind::File {
            return Err(Error::invalid(
                "versioned path",
                "the first versioning slice supports regular files only",
            ));
        }

        let head = self.store.get_head().await?;
        let base = head
            .as_ref()
            .map(|head| head.tree.to_tree())
            .unwrap_or_else(|| self.prolly.create());
        let meta_key = file_meta_key(&canonical);
        let previous: Option<FileVersion> = self
            .prolly
            .get(&base, &meta_key)
            .await
            .map_err(prolly_error)?
            .map(|bytes| decode_versioned(FILE_META_VERSION, &bytes, "file version"))
            .transpose()?;

        let chunk_size = live.chunk_size().min(u32::MAX as u64) as u32;
        let chunk_count_u64 = attr.size.div_ceil(chunk_size as u64);
        let chunk_count = u32::try_from(chunk_count_u64)
            .map_err(|_| Error::invalid("versioned file", "too many chunks"))?;
        let mut mutations = Vec::with_capacity(chunk_count as usize + 2);
        for index in 0..chunk_count {
            let offset = index as u64 * chunk_size as u64;
            let len = (attr.size - offset).min(chunk_size as u64) as u32;
            let bytes = live
                .read_with_atime_policy(
                    &Credentials::root(),
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
            mutations.push(Mutation::Upsert {
                key: file_chunk_key(&canonical, index),
                val: ValueRef::Blob(reference).to_bytes(),
            });
        }
        if let Some(previous) = previous {
            for index in chunk_count..previous.chunk_count {
                mutations.push(Mutation::Delete {
                    key: file_chunk_key(&canonical, index),
                });
            }
        }
        let metadata = FileVersion {
            mode: attr.mode,
            uid: attr.uid,
            gid: attr.gid,
            size: attr.size,
            atime: attr.atime,
            mtime: attr.mtime,
            chunk_count,
        };
        mutations.push(Mutation::Upsert {
            key: meta_key,
            val: encode_versioned(FILE_META_VERSION, &metadata)?,
        });
        let tree = self
            .prolly
            .batch(&base, mutations)
            .await
            .map_err(prolly_error)?;
        if tree == base {
            return Err(Error::Versioning(format!(
                "{canonical} has no changes to commit"
            )));
        }

        let body = VersionCommitBody {
            parent: head.as_ref().map(|head| head.commit_id),
            tree: RootManifest::from_tree(&tree),
            created_at: crate::control::now_unix(),
            message,
            paths: vec![canonical],
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
        self.store
            .publish_commit(head.map(|head| head.commit_id), &commit, encoded)
            .await?;
        Ok(commit.into())
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
            let commit = self.store.get_commit(&id).await?;
            next = commit.parent;
            if path
                .as_ref()
                .is_none_or(|path| commit.paths.iter().any(|changed| changed == path))
            {
                history.push(commit.into());
                if history.len() == limit {
                    break;
                }
            }
        }
        Ok(history)
    }

    pub async fn read_file(&self, commit: &str, path: &str) -> Result<Bytes> {
        let id = parse_commit_id(commit)?;
        let commit = self.store.get_commit(&id).await?;
        let tree = commit.tree.to_tree();
        let canonical = canonical_path(path)?;
        let metadata: FileVersion = self
            .prolly
            .get(&tree, &file_meta_key(&canonical))
            .await
            .map_err(prolly_error)?
            .ok_or_else(|| Error::not_found("versioned path", &canonical))
            .and_then(|bytes| decode_versioned(FILE_META_VERSION, &bytes, "file version"))?;
        let expected_size = usize::try_from(metadata.size)
            .map_err(|_| Error::Versioning(format!("{canonical} is too large to materialize")))?;
        let mut output = Vec::with_capacity(expected_size);
        for index in 0..metadata.chunk_count {
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
            output.extend_from_slice(&chunk);
        }
        if output.len() < expected_size {
            return Err(Error::Versioning(format!(
                "versioned contents for {canonical} are shorter than its recorded size"
            )));
        }
        output.truncate(expected_size);
        Ok(Bytes::from(output))
    }

    pub async fn restore_file(&self, live: &dyn Vfs, commit: &str, path: &str) -> Result<()> {
        let id = parse_commit_id(commit)?;
        let commit = self.store.get_commit(&id).await?;
        let tree = commit.tree.to_tree();
        let canonical = canonical_path(path)?;
        let metadata: FileVersion = self
            .prolly
            .get(&tree, &file_meta_key(&canonical))
            .await
            .map_err(prolly_error)?
            .ok_or_else(|| Error::not_found("versioned path", &canonical))
            .and_then(|bytes| decode_versioned(FILE_META_VERSION, &bytes, "file version"))?;
        let contents = self
            .read_file(commit_id_string(&commit.id).as_str(), &canonical)
            .await?;
        let (parent, name) = resolve_parent(live, &canonical).await?;
        let temp_name = format!(".slatefs-restore-{}", uuid::Uuid::new_v4());
        let creds = Credentials::root();
        let created = live
            .create(&creds, parent, temp_name.as_bytes(), metadata.mode, true)
            .await
            .map_err(fs_error)?;
        let result = async {
            let chunk_size = live.chunk_size().min(u32::MAX as u64) as usize;
            for (index, chunk) in contents.chunks(chunk_size).enumerate() {
                live.write(&creds, created.ino, index as u64 * chunk_size as u64, chunk)
                    .await
                    .map_err(fs_error)?;
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

async fn resolve_path(vfs: &dyn Vfs, canonical: &str) -> Result<FileAttr> {
    let creds = Credentials::root();
    let mut current = vfs.getattr(&creds, ROOT_INO).await.map_err(fs_error)?;
    for component in path_components(canonical) {
        current = vfs
            .lookup(&creds, current.ino, component.as_bytes())
            .await
            .map_err(fs_error)?;
    }
    Ok(current)
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
}
