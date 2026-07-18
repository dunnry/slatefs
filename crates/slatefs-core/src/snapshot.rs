//! Read-only snapshot volume backed by a SlateDB checkpoint reader. This is
//! the Phase 6 export path for `DbReader::with_checkpoint_id`: frontends use
//! the same [`Vfs`] trait as live writable volumes, while every mutating call
//! returns `EROFS`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use slatedb::DbReader;
use slatedb::object_store::ObjectStore;

use crate::control::{QuotaLimits, VolumeRecord, VolumeState};
use crate::crypto::Secret32;
use crate::crypto::names::NameCodec;
use crate::crypto::transformer::{BlockTransformMetrics, SlateBlockTransformer};
use crate::error::{Error, Result};
use crate::locks::{LockRange, RangeLock, RangeLockTable};
use crate::meta::dirent::{Dirent, DirentIdx};
use crate::meta::inode::{FileKind, Inode, MAX_NAME_LEN};
use crate::meta::keys;
use crate::meta::superblock::{KEY_SUPERBLOCK, Superblock, VolumeKind};
use crate::quota::{self, CounterMergeOperator};
use crate::store;
use crate::vfs::{
    Credentials, DirEntry, EntryPermissions, FileAttr, FsError, FsResult, HandleId, OpenMode,
    ReadDir, SetAttrs, StatFs, Vfs,
};
use crate::volume::{HandleTable, verify_superblock_matches_record};

const ACCESS_R: u32 = 4;
const NOMINAL_BYTES: u64 = 1 << 60;
const NOMINAL_INODES: u64 = 1 << 32;
const STATFS_BSIZE: u32 = 4096;

pub struct SnapshotVolume {
    reader: DbReader,
    fsid: u64,
    names: NameCodec,
    chunk_size: u64,
    quota: QuotaLimits,
    block_metrics: BlockTransformMetrics,
    handles: Mutex<HandleTable>,
    range_locks: RangeLockTable,
}

impl SnapshotVolume {
    /// Open a read-only snapshot with explicit clone ancestor prefixes.
    ///
    /// `parent_prefixes` must be ordered from nearest parent to oldest
    /// ancestor. Pass an empty vector for volumes that are not clones.
    pub async fn open(
        record: &VolumeRecord,
        dek: Secret32,
        object_store: Arc<dyn ObjectStore>,
        snapshot_id: &str,
        parent_prefixes: Vec<String>,
    ) -> Result<Arc<SnapshotVolume>> {
        if record.state != VolumeState::Active {
            return Err(Error::invalid(
                "volume state",
                format!("{:?}, not Active", record.state),
            ));
        }
        let checkpoint = uuid::Uuid::parse_str(snapshot_id)
            .map_err(|e| Error::invalid("snapshot id", format!("{snapshot_id:?}: {e}")))?;
        let block_metrics = BlockTransformMetrics::default();
        let path = store::volume_db_path(&record.tenant, &record.name);
        let reader_store = if parent_prefixes.is_empty() {
            object_store
        } else {
            store::clone_parent_read_fallback_store(
                object_store,
                &record.tenant,
                &record.name,
                parent_prefixes,
            )
        };
        let reader = DbReader::builder(path, reader_store)
            .with_checkpoint_id(checkpoint)
            .with_block_transformer(Arc::new(SlateBlockTransformer::with_metrics(
                record.cipher,
                dek.clone(),
                block_metrics.clone(),
            )))
            .with_merge_operator(Arc::new(CounterMergeOperator))
            .build()
            .await?;

        let result = async {
            let bytes = reader
                .get(KEY_SUPERBLOCK)
                .await?
                .ok_or_else(|| Error::invalid("snapshot", "no superblock"))?;
            let superblock = Superblock::decode(&bytes)?;
            verify_superblock_matches_record(record, &superblock, "snapshot superblock")?;
            if !matches!(superblock.kind, VolumeKind::Filesystem) {
                return Err(Error::invalid(
                    "volume kind",
                    "block snapshot cannot be opened as a filesystem snapshot",
                ));
            }
            Ok(superblock)
        }
        .await;

        let superblock = match result {
            Ok(superblock) => superblock,
            Err(e) => {
                reader.close().await?;
                return Err(e);
            }
        };
        Ok(Arc::new(SnapshotVolume {
            reader,
            fsid: snapshot_fsid(record.fsid, checkpoint),
            chunk_size: superblock.chunk_size as u64,
            names: NameCodec::new(dek),
            quota: record.quota,
            block_metrics,
            handles: Mutex::new(HandleTable::default()),
            range_locks: RangeLockTable::default(),
        }))
    }

    pub fn block_decode_failures(&self) -> u64 {
        self.block_metrics.decode_failures()
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.reader.close().await.map_err(Error::from)
    }

    async fn load_inode(&self, ino: u64) -> FsResult<Inode> {
        match self.reader.get(keys::inode(ino)).await? {
            Some(bytes) => Ok(Inode::decode(&bytes)?),
            None => Err(FsError::Stale),
        }
    }

    async fn load_dir(&self, ino: u64) -> FsResult<Inode> {
        let inode = self.load_inode(ino).await?;
        if !inode.kind.is_dir() {
            return Err(FsError::NotDir);
        }
        Ok(inode)
    }

    async fn dirent_of(&self, parent: u64, name: &[u8]) -> FsResult<Option<Dirent>> {
        let enc = self.names.seal_name(parent, name)?;
        match self.reader.get(keys::dirent(parent, &enc)).await? {
            Some(bytes) => Ok(Some(Dirent::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn make_attr(&self, ino: u64, inode: &Inode) -> FileAttr {
        FileAttr {
            ino,
            kind: inode.kind,
            mode: inode.mode,
            nlink: inode.nlink,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            rdev: inode.rdev,
            generation: inode.generation,
            blocks: inode.billed_bytes.div_ceil(512),
        }
    }

    async fn read_range(&self, ino: u64, size: u64, offset: u64, len: u32) -> FsResult<Bytes> {
        if offset >= size || len == 0 {
            return Ok(Bytes::new());
        }
        let end = size.min(offset + len as u64);
        let first = (offset / self.chunk_size) as u32;
        let last = ((end - 1) / self.chunk_size) as u32;

        let mut out = vec![0u8; (end - offset) as usize];
        for idx in first..=last {
            if let Some(chunk) = self.reader.get(keys::chunk(ino, idx)).await? {
                copy_from_chunk(&mut out, offset, idx, &chunk, self.chunk_size);
            }
        }
        Ok(Bytes::from(out))
    }
}

fn snapshot_fsid(source_fsid: u64, checkpoint: uuid::Uuid) -> u64 {
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&checkpoint.as_bytes()[..8]);
    let mut fsid = source_fsid ^ u64::from_be_bytes(prefix);
    if fsid == source_fsid {
        fsid ^= 1 << 63;
    }
    fsid
}

fn copy_from_chunk(out: &mut [u8], read_offset: u64, idx: u32, chunk: &[u8], chunk_size: u64) {
    let chunk_start = idx as u64 * chunk_size;
    let from = read_offset.max(chunk_start);
    let to = (read_offset + out.len() as u64).min(chunk_start + chunk.len() as u64);
    if from >= to {
        return;
    }
    let src = (from - chunk_start) as usize..(to - chunk_start) as usize;
    let dst = (from - read_offset) as usize..(to - read_offset) as usize;
    out[dst].copy_from_slice(&chunk[src]);
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

fn access(creds: &Credentials, inode: &Inode, want: u32) -> FsResult<()> {
    if creds.is_privileged() {
        return Ok(());
    }
    let bits = if creds.uid == inode.uid {
        (inode.mode >> 6) & 7
    } else if creds.in_group(inode.gid) {
        (inode.mode >> 3) & 7
    } else {
        inode.mode & 7
    };
    if bits & want == want {
        Ok(())
    } else {
        Err(FsError::AccessDenied)
    }
}

fn read_only<T>() -> FsResult<T> {
    Err(FsError::ReadOnly)
}

#[async_trait]
impl Vfs for SnapshotVolume {
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
        let dir = self.load_dir(parent).await?;
        access(creds, &dir, ACCESS_R)?;
        if name == b"." {
            return Ok(self.make_attr(parent, &dir));
        }
        if name == b".." {
            let p = self.load_inode(dir.parent_dir).await?;
            return Ok(self.make_attr(dir.parent_dir, &p));
        }
        validate_name(name)?;
        match self.dirent_of(parent, name).await? {
            Some(d) => {
                let inode = self.load_inode(d.child_ino).await?;
                Ok(self.make_attr(d.child_ino, &inode))
            }
            None => Err(FsError::NotFound),
        }
    }

    async fn getattr(&self, _creds: &Credentials, ino: u64) -> FsResult<FileAttr> {
        let inode = self.load_inode(ino).await?;
        Ok(self.make_attr(ino, &inode))
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
        let inode = self.load_inode(ino).await?;
        match inode.kind {
            FileKind::File => {}
            FileKind::Dir => return Err(FsError::IsDir),
            _ => return Err(FsError::Invalid),
        }
        access(creds, &inode, ACCESS_R)?;
        self.read_range(ino, inode.size, offset, len).await
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
        let inode = self.load_inode(ino).await?;
        if inode.kind != FileKind::Symlink {
            return Err(FsError::Invalid);
        }
        match self.reader.get(keys::symlink(ino)).await? {
            Some(bytes) => Ok(bytes.to_vec()),
            None => Err(FsError::Io),
        }
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
        let dir = self.load_dir(parent).await?;
        access(creds, &dir, ACCESS_R)?;

        let start = keys::dirent_idx(parent, cookie.saturating_add(1));
        let end = keys::dirent_idx(parent, u64::MAX);
        let mut iter = self.reader.scan(start.to_vec()..end.to_vec()).await?;

        let mut entries = Vec::new();
        let mut eof = true;
        while let Some(kv) = iter.next().await? {
            if entries.len() == max_entries {
                eof = false;
                break;
            }
            let Some((_, dirent_id)) = keys::parse_dirent_idx(&kv.key) else {
                return Err(FsError::Io);
            };
            let idx = DirentIdx::decode(&kv.value)?;
            let name = self.names.open_name(parent, &idx.enc_name)?;
            entries.push(DirEntry {
                name,
                ino: idx.child_ino,
                kind: idx.kind,
                cookie: dirent_id,
            });
        }
        Ok(ReadDir { entries, eof })
    }

    async fn getxattr(&self, creds: &Credentials, ino: u64, name: &[u8]) -> FsResult<Vec<u8>> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(FsError::Invalid);
        }
        let inode = self.load_inode(ino).await?;
        access(creds, &inode, ACCESS_R)?;
        match self.reader.get(keys::xattr(ino, name)).await? {
            Some(bytes) => Ok(bytes.to_vec()),
            None => Err(FsError::NoData),
        }
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

    async fn listxattr(&self, creds: &Credentials, ino: u64) -> FsResult<Vec<Vec<u8>>> {
        let inode = self.load_inode(ino).await?;
        access(creds, &inode, ACCESS_R)?;
        let mut iter = self
            .reader
            .scan(keys::xattr_prefix(ino).to_vec()..keys::xattr_prefix(ino + 1).to_vec())
            .await?;
        let mut names = Vec::new();
        while let Some(kv) = iter.next().await? {
            names.push(kv.key[9..].to_vec());
        }
        Ok(names)
    }

    async fn removexattr(&self, _creds: &Credentials, _ino: u64, _name: &[u8]) -> FsResult<()> {
        read_only()
    }

    async fn statfs(&self, _creds: &Credentials) -> FsResult<StatFs> {
        let bytes_used =
            quota::decode_counter(self.reader.get(keys::KEY_QUOTA_BYTES).await?.as_deref());
        let inodes_used =
            quota::decode_counter(self.reader.get(keys::KEY_QUOTA_INODES).await?.as_deref());
        let (total_bytes, free_bytes) = match self.quota.bytes.hard {
            Some(limit) => (limit, limit.saturating_sub(bytes_used.max(0) as u64)),
            None => (
                NOMINAL_BYTES,
                NOMINAL_BYTES.saturating_sub(bytes_used.max(0) as u64),
            ),
        };
        let (total_inodes, free_inodes) = match self.quota.inodes.hard {
            Some(limit) => (limit, limit.saturating_sub(inodes_used.max(0) as u64)),
            None => (
                NOMINAL_INODES,
                NOMINAL_INODES.saturating_sub(inodes_used.max(0) as u64),
            ),
        };
        Ok(StatFs {
            block_size: STATFS_BSIZE,
            total_bytes,
            free_bytes,
            avail_bytes: free_bytes,
            total_inodes,
            free_inodes,
        })
    }

    async fn fsync(&self, _creds: &Credentials, _ino: u64) -> FsResult<()> {
        Ok(())
    }

    async fn open(&self, creds: &Credentials, ino: u64, mode: OpenMode) -> FsResult<HandleId> {
        if mode != OpenMode::Read {
            return Err(FsError::ReadOnly);
        }
        let inode = self.load_inode(ino).await?;
        access(creds, &inode, ACCESS_R)?;
        Ok(self
            .handles
            .lock()
            .expect("snapshot handle table poisoned")
            .open(ino, mode))
    }

    async fn close(&self, handle: HandleId) -> FsResult<()> {
        let closed = self
            .handles
            .lock()
            .expect("snapshot handle table poisoned")
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
        let held = self
            .handles
            .lock()
            .expect("snapshot handle table poisoned")
            .get(handle);
        let Some((ino, _)) = held else {
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
        let held = self
            .handles
            .lock()
            .expect("snapshot handle table poisoned")
            .get(handle);
        let Some((ino, _)) = held else {
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
        let held = self
            .handles
            .lock()
            .expect("snapshot handle table poisoned")
            .get(handle);
        let Some((ino, _)) = held else {
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
