//! Read-only filesystem view of one immutable version commit.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use prolly::{
    AsyncBlobStore, AsyncProlly, AsyncStore, BatchOp, BlobRef, Config as ProllyConfig,
    RootManifest, ValueRef,
};
use sha2::{Digest, Sha256};
use slatedb::DbReader;
use slatedb::admin::AdminBuilder;
use slatedb::object_store::ObjectStore;

use crate::control::{ControlPlane, ControlReader, VolumeRecord};
use crate::crypto::Secret32;
use crate::crypto::transformer::SlateBlockTransformer;
use crate::error::{Error, Result};
use crate::locks::{LockRange, RangeLock, RangeLockTable};
use crate::meta::inode::{FileKind, MAX_NAME_LEN, ROOT_INO, Timespec};
use crate::meta::superblock::VolumeKind;
use crate::store;
use crate::versioning::{
    VersionEntry, VersionEntryData, VersionHistoricalExportPlan, VersionRepository,
    VersionStoreError, file_chunk_key,
};
use crate::vfs::{
    Credentials, DirEntry, EntryPermissions, FileAttr, FsError, FsResult, HandleId, OpenMode,
    ReadDir, SetAttrs, StatFs, Vfs,
};
use crate::volume::HandleTable;

const NODE_PREFIX: &[u8] = b"pn/";
const BLOB_PREFIX: &[u8] = b"pb/";
const ACCESS_R: u32 = 4;
const STATFS_BSIZE: u32 = 4096;

#[derive(Clone)]
struct VersionReadStore {
    reader: Arc<DbReader>,
}

impl VersionReadStore {
    async fn get_raw(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, VersionStoreError> {
        Ok(self.reader.get(key).await?.map(|bytes| bytes.to_vec()))
    }
}

impl AsyncStore for VersionReadStore {
    type Error = VersionStoreError;

    async fn get(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        self.get_raw(&prefixed_key(NODE_PREFIX, key)).await
    }

    async fn put(&self, _key: &[u8], _value: &[u8]) -> std::result::Result<(), Self::Error> {
        Err(VersionStoreError::Invalid(
            "historical version store is read-only".into(),
        ))
    }

    async fn delete(&self, _key: &[u8]) -> std::result::Result<(), Self::Error> {
        Err(VersionStoreError::Invalid(
            "historical version store is read-only".into(),
        ))
    }

    async fn batch(&self, _ops: &[BatchOp<'_>]) -> std::result::Result<(), Self::Error> {
        Err(VersionStoreError::Invalid(
            "historical version store is read-only".into(),
        ))
    }

    fn read_parallelism(&self) -> usize {
        32
    }
}

impl AsyncBlobStore for VersionReadStore {
    type Error = VersionStoreError;

    async fn get_blob(
        &self,
        reference: &BlobRef,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let Some(bytes) = self
            .get_raw(&prefixed_key(BLOB_PREFIX, reference.cid.as_bytes()))
            .await?
        else {
            return Ok(None);
        };
        reference
            .validate_bytes(&bytes)
            .map_err(|error| VersionStoreError::Invalid(error.to_string()))?;
        Ok(Some(bytes))
    }

    async fn put_blob(&self, _bytes: &[u8]) -> std::result::Result<BlobRef, Self::Error> {
        Err(VersionStoreError::Invalid(
            "historical version store is read-only".into(),
        ))
    }

    async fn delete_blob(&self, _reference: &BlobRef) -> std::result::Result<(), Self::Error> {
        Err(VersionStoreError::Invalid(
            "historical version store is read-only".into(),
        ))
    }

    fn read_parallelism(&self) -> usize {
        32
    }
}

struct HistoricalNode {
    path: String,
    parent: u64,
    entry: VersionEntry,
    kind: FileKind,
    nlink: u32,
    generation: u32,
}

struct HistoricalChild {
    name: Vec<u8>,
    ino: u64,
    kind: FileKind,
    cookie: u64,
}

struct HistoricalIndex {
    nodes: BTreeMap<u64, HistoricalNode>,
    lookup: BTreeMap<(u64, Vec<u8>), u64>,
    children: BTreeMap<u64, Vec<HistoricalChild>>,
    total_bytes: u64,
}

/// An immutable, read-only filesystem synthesized from one version commit.
pub struct VersionHistoricalVolume {
    reader: Arc<DbReader>,
    object_store: Arc<dyn ObjectStore>,
    db_path: String,
    checkpoint: uuid::Uuid,
    commit: String,
    tree: RootManifest,
    store: VersionReadStore,
    prolly: AsyncProlly<VersionReadStore>,
    fsid: u64,
    chunk_size: u64,
    nodes: BTreeMap<u64, HistoricalNode>,
    lookup: BTreeMap<(u64, Vec<u8>), u64>,
    children: BTreeMap<u64, Vec<HistoricalChild>>,
    total_bytes: u64,
    handles: Mutex<HandleTable>,
    range_locks: RangeLockTable,
}

impl VersionHistoricalVolume {
    /// Resolve a commit, tag, or branch and open an immutable historical view.
    /// An internal SlateDB checkpoint pins the exact version-store state while
    /// the export is active without retaining the repository writer lease.
    pub async fn open(
        control: &ControlPlane,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        reference: &str,
    ) -> Result<Arc<Self>> {
        let record = control.get_mountable_volume(tenant, volume).await?;
        if !matches!(record.kind, VolumeKind::Filesystem) {
            return Err(Error::invalid(
                "version historical export",
                "only filesystem volumes have version history",
            ));
        }
        let dek = control.unwrap_volume_dek(&record).await?;
        let repository =
            VersionRepository::open_existing(control, Arc::clone(&object_store), tenant, volume)
                .await?
                .ok_or_else(|| {
                    Error::not_found("version repository", format!("{tenant}/{volume}"))
                })?;
        Self::open_repository(
            record,
            dek,
            object_store,
            tenant,
            volume,
            reference,
            repository,
        )
        .await
    }

    /// Read-only-control-plane variant used by the daemon export reconciler.
    pub async fn open_readonly(
        control: &ControlReader,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        reference: &str,
    ) -> Result<Arc<Self>> {
        let record = control.get_mountable_volume(tenant, volume).await?;
        if !matches!(record.kind, VolumeKind::Filesystem) {
            return Err(Error::invalid(
                "version historical export",
                "only filesystem volumes have version history",
            ));
        }
        let dek = control.unwrap_volume_dek(&record).await?;
        let repository = VersionRepository::open_existing_readonly(
            control,
            Arc::clone(&object_store),
            tenant,
            volume,
        )
        .await?
        .ok_or_else(|| Error::not_found("version repository", format!("{tenant}/{volume}")))?;
        Self::open_repository(
            record,
            dek,
            object_store,
            tenant,
            volume,
            reference,
            repository,
        )
        .await
    }

    /// Open an immutable historical view using an already-open repository.
    ///
    /// Daemons use this when a read-only administrative repository is cached.
    /// The repository is borrowed only while resolving the reference and
    /// creating the checkpoint; the returned view remains pinned to that
    /// checkpoint and does not retain the repository or its maintenance lease.
    pub async fn open_readonly_with_repository(
        control: &ControlReader,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        reference: &str,
        repository: &VersionRepository,
    ) -> Result<Arc<Self>> {
        let record = control.get_mountable_volume(tenant, volume).await?;
        if !matches!(record.kind, VolumeKind::Filesystem) {
            return Err(Error::invalid(
                "version historical export",
                "only filesystem volumes have version history",
            ));
        }
        let dek = control.unwrap_volume_dek(&record).await?;
        let plan = repository.prepare_historical_export(reference).await?;
        Self::open_plan(record, dek, object_store, tenant, volume, plan).await
    }

    async fn open_repository(
        record: VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        reference: &str,
        repository: VersionRepository,
    ) -> Result<Arc<Self>> {
        let prepared = repository.prepare_historical_export(reference).await;
        let close = repository.close().await;
        let plan = prepared?;
        if let Err(error) = close {
            let _ = delete_checkpoint(
                &store::version_db_path(tenant, volume),
                Arc::clone(&object_store),
                plan.checkpoint,
            )
            .await;
            return Err(error);
        }

        Self::open_plan(record, dek, object_store, tenant, volume, plan).await
    }

    async fn open_plan(
        record: VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
        tenant: &str,
        volume: &str,
        plan: VersionHistoricalExportPlan,
    ) -> Result<Arc<Self>> {
        let db_path = store::version_db_path(tenant, volume);
        let index = match build_index(&plan) {
            Ok(index) => index,
            Err(error) => {
                let _ =
                    delete_checkpoint(&db_path, Arc::clone(&object_store), plan.checkpoint).await;
                return Err(error);
            }
        };
        let reader = DbReader::builder(db_path.clone(), Arc::clone(&object_store))
            .with_checkpoint_id(plan.checkpoint)
            .with_block_transformer(Arc::new(SlateBlockTransformer::new(record.cipher, dek)))
            .build()
            .await;
        let reader = match reader {
            Ok(reader) => Arc::new(reader),
            Err(error) => {
                let _ =
                    delete_checkpoint(&db_path, Arc::clone(&object_store), plan.checkpoint).await;
                return Err(error.into());
            }
        };
        let store = VersionReadStore {
            reader: Arc::clone(&reader),
        };
        let prolly = AsyncProlly::new(store.clone(), ProllyConfig::default());
        Ok(Arc::new(Self {
            reader,
            object_store,
            db_path,
            checkpoint: plan.checkpoint,
            commit: plan.commit.clone(),
            tree: plan.tree,
            store,
            prolly,
            fsid: historical_fsid(record.fsid, &plan.commit),
            chunk_size: u64::from(record.chunk_size),
            nodes: index.nodes,
            lookup: index.lookup,
            children: index.children,
            total_bytes: index.total_bytes,
            handles: Mutex::new(HandleTable::default()),
            range_locks: RangeLockTable::default(),
        }))
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// Close the immutable reader and release its internal checkpoint.
    pub async fn shutdown(&self) -> Result<()> {
        let close = self.reader.close().await.map_err(Error::from);
        let delete = delete_checkpoint(
            &self.db_path,
            Arc::clone(&self.object_store),
            self.checkpoint,
        )
        .await;
        close?;
        delete
    }

    fn node(&self, ino: u64) -> FsResult<&HistoricalNode> {
        self.nodes.get(&ino).ok_or(FsError::Stale)
    }

    fn directory(&self, ino: u64) -> FsResult<&HistoricalNode> {
        let node = self.node(ino)?;
        if node.kind != FileKind::Dir {
            return Err(FsError::NotDir);
        }
        Ok(node)
    }

    fn attr(&self, ino: u64, node: &HistoricalNode) -> FileAttr {
        FileAttr {
            ino,
            kind: node.kind,
            mode: node.entry.mode,
            nlink: node.nlink,
            uid: node.entry.uid,
            gid: node.entry.gid,
            size: node.entry.size,
            atime: node.entry.atime,
            mtime: node.entry.mtime,
            ctime: node.entry.mtime,
            rdev: 0,
            generation: node.generation,
            blocks: if node.kind == FileKind::File {
                node.entry.size.div_ceil(512)
            } else {
                0
            },
        }
    }

    async fn read_file_range(
        &self,
        node: &HistoricalNode,
        offset: u64,
        len: u32,
    ) -> FsResult<Bytes> {
        let VersionEntryData::File { chunk_count } = node.entry.data else {
            return Err(FsError::Invalid);
        };
        let start = offset.min(node.entry.size);
        let end = start.saturating_add(u64::from(len)).min(node.entry.size);
        if start == end {
            return Ok(Bytes::new());
        }
        let first = start / self.chunk_size;
        let last = (end - 1) / self.chunk_size;
        if last >= u64::from(chunk_count) {
            return Err(FsError::Io);
        }
        let mut output = Vec::with_capacity((end - start) as usize);
        let tree = self.tree.to_tree();
        for index in first..=last {
            let index = u32::try_from(index).map_err(|_| FsError::Io)?;
            let encoded = self
                .prolly
                .get(&tree, &file_chunk_key(&node.path, index))
                .await
                .map_err(historical_store_error)?
                .ok_or(FsError::Io)?;
            let ValueRef::Blob(reference) =
                ValueRef::from_stored_bytes(&encoded).map_err(historical_store_error)?
            else {
                return Err(FsError::Io);
            };
            let chunk = self
                .store
                .get_blob(&reference)
                .await
                .map_err(historical_store_error)?
                .ok_or(FsError::Io)?;
            let chunk_offset = u64::from(index) * self.chunk_size;
            let copy_start = start.saturating_sub(chunk_offset) as usize;
            let copy_end = (end - chunk_offset).min(chunk.len() as u64) as usize;
            if copy_start > copy_end || copy_end > chunk.len() {
                return Err(FsError::Io);
            }
            output.extend_from_slice(&chunk[copy_start..copy_end]);
        }
        if output.len() != (end - start) as usize {
            return Err(FsError::Io);
        }
        Ok(Bytes::from(output))
    }
}

#[async_trait]
impl Vfs for VersionHistoricalVolume {
    fn fsid(&self) -> u64 {
        self.fsid
    }

    fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    fn read_only(&self) -> bool {
        true
    }

    async fn permissions(
        &self,
        creds: &Credentials,
        ino: u64,
        _parent: Option<(u64, &[u8])>,
    ) -> FsResult<EntryPermissions> {
        self.getattr(creds, ino).await?;
        Ok(EntryPermissions {
            can_read: true,
            ..EntryPermissions::default()
        })
    }

    async fn lookup(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<FileAttr> {
        let directory = self.directory(parent)?;
        access(creds, directory, ACCESS_R)?;
        if name == b"." {
            return Ok(self.attr(parent, directory));
        }
        if name == b".." {
            let parent = directory.parent;
            return Ok(self.attr(parent, self.node(parent)?));
        }
        validate_name(name)?;
        let ino = self
            .lookup
            .get(&(parent, name.to_vec()))
            .copied()
            .ok_or(FsError::NotFound)?;
        Ok(self.attr(ino, self.node(ino)?))
    }

    async fn getattr(&self, _creds: &Credentials, ino: u64) -> FsResult<FileAttr> {
        Ok(self.attr(ino, self.node(ino)?))
    }

    async fn setattr(
        &self,
        _creds: &Credentials,
        _ino: u64,
        _attrs: SetAttrs,
    ) -> FsResult<FileAttr> {
        read_only()
    }

    async fn read(&self, creds: &Credentials, ino: u64, offset: u64, len: u32) -> FsResult<Bytes> {
        let node = self.node(ino)?;
        match node.kind {
            FileKind::File => {}
            FileKind::Dir => return Err(FsError::IsDir),
            _ => return Err(FsError::Invalid),
        }
        access(creds, node, ACCESS_R)?;
        self.read_file_range(node, offset, len).await
    }

    async fn write(
        &self,
        _creds: &Credentials,
        _ino: u64,
        _offset: u64,
        _data: &[u8],
    ) -> FsResult<u32> {
        read_only()
    }

    async fn create(
        &self,
        _creds: &Credentials,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _exclusive: bool,
    ) -> FsResult<FileAttr> {
        read_only()
    }

    async fn mkdir(
        &self,
        _creds: &Credentials,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
    ) -> FsResult<FileAttr> {
        read_only()
    }

    async fn mknod(
        &self,
        _creds: &Credentials,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _kind: FileKind,
        _rdev: u64,
    ) -> FsResult<FileAttr> {
        read_only()
    }

    async fn symlink(
        &self,
        _creds: &Credentials,
        _parent: u64,
        _name: &[u8],
        _target: &[u8],
    ) -> FsResult<FileAttr> {
        read_only()
    }

    async fn readlink(&self, _creds: &Credentials, ino: u64) -> FsResult<Vec<u8>> {
        let node = self.node(ino)?;
        let VersionEntryData::Symlink { target } = &node.entry.data else {
            return Err(FsError::Invalid);
        };
        Ok(target.clone())
    }

    async fn link(
        &self,
        _creds: &Credentials,
        _ino: u64,
        _new_parent: u64,
        _new_name: &[u8],
    ) -> FsResult<FileAttr> {
        read_only()
    }

    async fn unlink(&self, _creds: &Credentials, _parent: u64, _name: &[u8]) -> FsResult<()> {
        read_only()
    }

    async fn rmdir(&self, _creds: &Credentials, _parent: u64, _name: &[u8]) -> FsResult<()> {
        read_only()
    }

    async fn rename(
        &self,
        _creds: &Credentials,
        _old_parent: u64,
        _old_name: &[u8],
        _new_parent: u64,
        _new_name: &[u8],
    ) -> FsResult<()> {
        read_only()
    }

    async fn readdir(
        &self,
        creds: &Credentials,
        parent: u64,
        cookie: u64,
        max_entries: usize,
    ) -> FsResult<ReadDir> {
        let directory = self.directory(parent)?;
        access(creds, directory, ACCESS_R)?;
        let children = self.children.get(&parent).map(Vec::as_slice).unwrap_or(&[]);
        let mut available = children.iter().filter(|child| child.cookie > cookie);
        let entries = available
            .by_ref()
            .take(max_entries)
            .map(|child| DirEntry {
                name: child.name.clone(),
                ino: child.ino,
                kind: child.kind,
                cookie: child.cookie,
            })
            .collect::<Vec<_>>();
        Ok(ReadDir {
            entries,
            eof: available.next().is_none(),
        })
    }

    async fn getxattr(&self, _creds: &Credentials, ino: u64, name: &[u8]) -> FsResult<Vec<u8>> {
        self.node(ino)?;
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(FsError::Invalid);
        }
        Err(FsError::NoData)
    }

    async fn setxattr(
        &self,
        _creds: &Credentials,
        _ino: u64,
        _name: &[u8],
        _value: &[u8],
    ) -> FsResult<()> {
        read_only()
    }

    async fn listxattr(&self, _creds: &Credentials, ino: u64) -> FsResult<Vec<Vec<u8>>> {
        self.node(ino)?;
        Ok(Vec::new())
    }

    async fn removexattr(&self, _creds: &Credentials, _ino: u64, _name: &[u8]) -> FsResult<()> {
        read_only()
    }

    async fn statfs(&self, _creds: &Credentials) -> FsResult<StatFs> {
        Ok(StatFs {
            block_size: STATFS_BSIZE,
            total_bytes: self.total_bytes,
            free_bytes: 0,
            avail_bytes: 0,
            total_inodes: self.nodes.len() as u64,
            free_inodes: 0,
        })
    }

    async fn fsync(&self, _creds: &Credentials, _ino: u64) -> FsResult<()> {
        Ok(())
    }

    async fn open(&self, creds: &Credentials, ino: u64, mode: OpenMode) -> FsResult<HandleId> {
        if mode != OpenMode::Read {
            return Err(FsError::ReadOnly);
        }
        let node = self.node(ino)?;
        access(creds, node, ACCESS_R)?;
        Ok(self
            .handles
            .lock()
            .expect("historical version handle table poisoned")
            .open(ino, mode))
    }

    async fn close(&self, handle: HandleId) -> FsResult<()> {
        let closed = self
            .handles
            .lock()
            .expect("historical version handle table poisoned")
            .close(handle);
        if closed.is_none() {
            return Err(FsError::BadHandle);
        }
        self.range_locks.unlock_owner(handle);
        Ok(())
    }

    async fn lock(&self, handle: HandleId, start: u64, end: u64, exclusive: bool) -> FsResult<()> {
        if exclusive {
            return Err(FsError::ReadOnly);
        }
        if start >= end {
            return Err(FsError::Invalid);
        }
        let Some((ino, _)) = self
            .handles
            .lock()
            .expect("historical version handle table poisoned")
            .get(handle)
        else {
            return Err(FsError::BadHandle);
        };
        self.range_locks
            .try_lock(
                ino,
                RangeLock {
                    owner: handle,
                    range: LockRange { start, end },
                    exclusive,
                },
            )
            .map_err(|_| FsError::WouldBlock)
    }

    async fn unlock(&self, handle: HandleId, start: u64, end: u64) -> FsResult<()> {
        if start >= end {
            return Err(FsError::Invalid);
        }
        let Some((ino, _)) = self
            .handles
            .lock()
            .expect("historical version handle table poisoned")
            .get(handle)
        else {
            return Err(FsError::BadHandle);
        };
        self.range_locks
            .unlock(ino, handle, LockRange { start, end });
        Ok(())
    }

    async fn testlock(
        &self,
        handle: HandleId,
        start: u64,
        end: u64,
        exclusive: bool,
    ) -> FsResult<Option<(u64, u64, bool)>> {
        if exclusive {
            return Err(FsError::ReadOnly);
        }
        if start >= end {
            return Err(FsError::Invalid);
        }
        let Some((ino, _)) = self
            .handles
            .lock()
            .expect("historical version handle table poisoned")
            .get(handle)
        else {
            return Err(FsError::BadHandle);
        };
        Ok(self
            .range_locks
            .test(
                ino,
                RangeLock {
                    owner: handle,
                    range: LockRange { start, end },
                    exclusive,
                },
            )
            .map(|lock| (lock.range.start, lock.range.end, lock.exclusive)))
    }
}

fn build_index(plan: &VersionHistoricalExportPlan) -> Result<HistoricalIndex> {
    let created_at = Timespec {
        secs: i64::try_from(plan.created_at).unwrap_or(i64::MAX),
        nanos: 0,
    };
    let mut entries = plan.entries.clone();
    let paths = entries.keys().cloned().collect::<Vec<_>>();
    for path in paths {
        let mut parent = parent_path(&path);
        while let Some(path) = parent {
            entries
                .entry(path.to_string())
                .or_insert_with(|| VersionEntry {
                    mode: 0o555,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    atime: created_at,
                    mtime: created_at,
                    data: VersionEntryData::Directory,
                });
            parent = parent_path(path);
        }
    }
    entries.entry("/".into()).or_insert_with(|| VersionEntry {
        mode: 0o555,
        uid: 0,
        gid: 0,
        size: 0,
        atime: created_at,
        mtime: created_at,
        data: VersionEntryData::Directory,
    });
    if !matches!(entries["/"].data, VersionEntryData::Directory) {
        return Err(Error::Versioning(
            "historical version root is not a directory".into(),
        ));
    }
    for path in entries.keys().filter(|path| path.as_str() != "/") {
        let parent = parent_path(path).expect("non-root historical path has a parent");
        if !matches!(entries[parent].data, VersionEntryData::Directory) {
            return Err(Error::Versioning(format!(
                "historical version path {path} has non-directory parent {parent}"
            )));
        }
    }

    let mut inode_by_path = BTreeMap::new();
    inode_by_path.insert("/".to_string(), ROOT_INO);
    let mut next_ino = ROOT_INO + 1;
    for path in entries.keys().filter(|path| path.as_str() != "/") {
        inode_by_path.insert(path.clone(), next_ino);
        next_ino = next_ino
            .checked_add(1)
            .ok_or_else(|| Error::Versioning("historical inode space is exhausted".into()))?;
    }

    let mut directory_links = BTreeMap::<String, u32>::new();
    for (path, entry) in &entries {
        if matches!(entry.data, VersionEntryData::Directory) {
            directory_links.insert(path.clone(), 2);
        }
    }
    for (path, entry) in &entries {
        if path != "/"
            && matches!(entry.data, VersionEntryData::Directory)
            && let Some(parent) = parent_path(path)
            && let Some(links) = directory_links.get_mut(parent)
        {
            *links = links.saturating_add(1);
        }
    }

    let mut nodes = BTreeMap::new();
    let mut lookup = BTreeMap::new();
    let mut child_specs = BTreeMap::<u64, Vec<(Vec<u8>, u64, FileKind)>>::new();
    let mut total_bytes = 0u64;
    for (path, entry) in entries {
        let ino = inode_by_path[&path];
        let parent_path = parent_path(&path).unwrap_or("/");
        let parent = inode_by_path[parent_path];
        let kind = entry_kind(&entry.data);
        if path != "/" {
            let name = path
                .rsplit('/')
                .next()
                .expect("non-root historical path has a basename")
                .as_bytes()
                .to_vec();
            lookup.insert((parent, name.clone()), ino);
            child_specs
                .entry(parent)
                .or_default()
                .push((name, ino, kind));
        }
        if kind == FileKind::File {
            total_bytes = total_bytes.saturating_add(entry.size);
        }
        let nlink = directory_links.get(&path).copied().unwrap_or(1);
        nodes.insert(
            ino,
            HistoricalNode {
                generation: historical_generation(&plan.commit, &path),
                path,
                parent,
                entry,
                kind,
                nlink,
            },
        );
    }
    let mut children = BTreeMap::new();
    for (parent, mut specs) in child_specs {
        specs.sort_by(|left, right| left.0.cmp(&right.0));
        children.insert(
            parent,
            specs
                .into_iter()
                .enumerate()
                .map(|(index, (name, ino, kind))| HistoricalChild {
                    name,
                    ino,
                    kind,
                    cookie: index as u64 + 3,
                })
                .collect(),
        );
    }
    Ok(HistoricalIndex {
        nodes,
        lookup,
        children,
        total_bytes,
    })
}

fn entry_kind(data: &VersionEntryData) -> FileKind {
    match data {
        VersionEntryData::File { .. } => FileKind::File,
        VersionEntryData::Directory => FileKind::Dir,
        VersionEntryData::Symlink { .. } => FileKind::Symlink,
    }
}

fn parent_path(path: &str) -> Option<&str> {
    if path == "/" {
        return None;
    }
    let separator = path.rfind('/').unwrap_or(0);
    Some(if separator == 0 {
        "/"
    } else {
        &path[..separator]
    })
}

fn historical_fsid(source_fsid: u64, commit: &str) -> u64 {
    let digest = Sha256::digest(commit.as_bytes());
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let mut fsid = source_fsid ^ u64::from_be_bytes(prefix);
    if fsid == source_fsid {
        fsid ^= 1 << 63;
    }
    fsid
}

fn historical_generation(commit: &str, path: &str) -> u32 {
    let mut digest = Sha256::new();
    digest.update(commit.as_bytes());
    digest.update([0]);
    digest.update(path.as_bytes());
    u32::from_be_bytes(
        digest.finalize()[..4]
            .try_into()
            .expect("SHA-256 prefix width"),
    )
}

fn prefixed_key(prefix: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(prefix.len() + key.len());
    result.extend_from_slice(prefix);
    result.extend_from_slice(key);
    result
}

fn validate_name(name: &[u8]) -> FsResult<()> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(FsError::Invalid);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(FsError::NameTooLong);
    }
    if name.contains(&b'/') || name.contains(&0) {
        return Err(FsError::Invalid);
    }
    Ok(())
}

fn access(creds: &Credentials, node: &HistoricalNode, want: u32) -> FsResult<()> {
    if creds.is_privileged() {
        return Ok(());
    }
    let bits = if creds.uid == node.entry.uid {
        (node.entry.mode >> 6) & 7
    } else if creds.in_group(node.entry.gid) {
        (node.entry.mode >> 3) & 7
    } else {
        node.entry.mode & 7
    };
    if bits & want == want {
        Ok(())
    } else {
        Err(FsError::AccessDenied)
    }
}

fn historical_store_error(error: impl std::fmt::Display) -> FsError {
    tracing::error!(%error, "historical version store read failed");
    FsError::Io
}

fn read_only<T>() -> FsResult<T> {
    Err(FsError::ReadOnly)
}

async fn delete_checkpoint(
    db_path: &str,
    object_store: Arc<dyn ObjectStore>,
    checkpoint: uuid::Uuid,
) -> Result<()> {
    let admin = AdminBuilder::new(db_path, object_store).build();
    admin
        .delete_checkpoint(checkpoint)
        .await
        .map_err(Error::from)
}
