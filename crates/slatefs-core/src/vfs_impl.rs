//! `Vfs` implementation on [`Volume`] — the single place POSIX semantics are
//! enforced (plan §9.1, §10). Invariant (plan §6): one logical FS operation
//! is one atomic `WriteBatch` commit; the only multi-commit paths are batched
//! chunk reaping, which the accounting rule makes crash-consistent.

use bytes::Bytes;
use slatedb::WriteBatch;
use slatedb::config::WriteOptions;

use crate::data;
use crate::locks::{LockRange, RangeLock};
use crate::meta::dirent::{Dirent, DirentIdx, Orphan};
use crate::meta::inode::{FileKind, Inode, MAX_NAME_LEN, ROOT_INO, Timespec};
use crate::meta::keys;
use crate::quota::encode_delta;
use crate::vfs::{
    Credentials, DirEntry, FileAttr, FsError, FsResult, HandleId, OpenMode, ReadDir, SetAttrs,
    StatFs, TimeSet, Vfs,
};
use crate::volume::Volume;

const ACCESS_R: u32 = 4;
const ACCESS_W: u32 = 2;
const ACCESS_X: u32 = 1;

/// Nominal statfs numbers for unlimited volumes (plan §10).
const NOMINAL_BYTES: u64 = 1 << 60;
const NOMINAL_INODES: u64 = 1 << 32;
const STATFS_BSIZE: u32 = 4096;

const MAX_XATTR_VALUE: usize = 64 * 1024;

/// Relatime window (plan §10): persist atime on read only if it lags mtime
/// or is older than this.
const RELATIME_SECS: i64 = 24 * 3600;

fn now() -> Timespec {
    Timespec::now()
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
    if creds.is_root() {
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

/// Sticky-bit deletion rule (plan §9.1): in a sticky directory only the
/// entry's owner, the directory's owner, or root may remove/rename it.
fn check_sticky(creds: &Credentials, parent: &Inode, child: &Inode) -> FsResult<()> {
    if parent.mode & 0o1000 != 0
        && !creds.is_root()
        && creds.uid != child.uid
        && creds.uid != parent.uid
    {
        return Err(FsError::NotPermitted);
    }
    Ok(())
}

impl Volume {
    async fn commit(&self, batch: WriteBatch) -> FsResult<()> {
        // DD-7: ack from memtable + WAL buffer; durability comes from the
        // engine's flush_interval, or fsync/COMMIT mapping to flush().
        let opts = WriteOptions {
            await_durable: false,
            ..WriteOptions::default()
        };
        self.db.write_with_options(batch, &opts).await?;
        Ok(())
    }

    /// Read-path inode fetch through the attr cache (plan §8). Mutation
    /// paths use [`Volume::load_inode`] (DB-direct) so a missed
    /// write-through can never feed a read-modify-write.
    async fn load_inode_cached(&self, ino: u64) -> FsResult<Inode> {
        if let Some(inode) = self.attrs.get(ino) {
            return Ok(inode);
        }
        let inode = self.load_inode(ino).await?;
        self.attrs.insert(ino, inode.clone());
        Ok(inode)
    }

    async fn load_dir_cached(&self, ino: u64) -> FsResult<Inode> {
        let inode = self.load_inode_cached(ino).await?;
        if !inode.kind.is_dir() {
            return Err(FsError::NotDir);
        }
        Ok(inode)
    }

    /// Sequential-read detection + chunk prefetch (plan §8). Best-effort:
    /// a background task scans upcoming chunk keys, pulling their blocks
    /// through the (plaintext, tier-1) block cache.
    fn plan_readahead(&self, ino: u64, offset: u64, end: u64, size: u64) {
        const WINDOW_CHUNKS: u32 = 8;
        if end == 0 || end >= size {
            return;
        }
        let mut map = self.readahead.lock().expect("readahead poisoned");
        if map.len() > 4096 {
            map.clear();
        }
        let st = map.entry(ino).or_default();
        let sequential = offset == st.expected;
        st.expected = end;
        let cur_chunk = data::chunk_of(end - 1, self.chunk_size);
        if !sequential {
            st.prefetched_to = cur_chunk;
            return;
        }
        let last_file_chunk = data::chunk_of(size - 1, self.chunk_size);
        let wanted = cur_chunk.saturating_add(WINDOW_CHUNKS).min(last_file_chunk);
        // Refill only when the stream gets near the prefetched horizon.
        if st.prefetched_to >= wanted || st.prefetched_to > cur_chunk.saturating_add(2) {
            return;
        }
        let from = st.prefetched_to.max(cur_chunk) + 1;
        st.prefetched_to = wanted;
        drop(map);

        let db = self.db.clone();
        tokio::spawn(async move {
            let options =
                slatedb::config::ScanOptions::default().with_read_ahead_bytes(1024 * 1024);
            let range = keys::chunk(ino, from).to_vec()
                ..keys::chunk(ino, wanted.saturating_add(1)).to_vec();
            if let Ok(mut iter) = db.scan_with_options::<Vec<u8>, _>(range, &options).await {
                while let Ok(Some(_)) = iter.next().await {}
            }
        });
    }

    async fn load_inode(&self, ino: u64) -> FsResult<Inode> {
        match self.db.get(keys::inode(ino)).await? {
            Some(bytes) => Ok(Inode::decode(&bytes)?),
            // The ino came from a handle/cookie the client kept; the file is
            // gone — stale handle, not ENOENT (plan §5).
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
        match self.db.get(keys::dirent(parent, &enc)).await? {
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

    /// Allocate an inode number, durably renewing the lease when needed
    /// (ordering argument in `meta::alloc`).
    async fn alloc_ino(&self) -> FsResult<u64> {
        let (ino, renew) = self.alloc.allocate();
        if let Some(lease_end) = renew {
            let opts = WriteOptions {
                await_durable: false,
                ..WriteOptions::default()
            };
            self.db
                .put_with_options(
                    keys::KEY_NEXT_INO,
                    lease_end.to_be_bytes(),
                    &Default::default(),
                    &opts,
                )
                .await?;
        }
        Ok(ino)
    }

    /// uid/gid/mode for a new node, honoring setgid directory inheritance.
    fn new_node_ids(
        creds: &Credentials,
        parent: &Inode,
        kind: FileKind,
        mode: u32,
    ) -> (u32, u32, u32) {
        let uid = creds.uid;
        let (gid, mut mode) = if parent.mode & 0o2000 != 0 {
            (parent.gid, mode)
        } else {
            (creds.gid, mode)
        };
        if kind.is_dir() && parent.mode & 0o2000 != 0 {
            mode |= 0o2000;
        }
        (uid, gid, mode)
    }

    /// Shared entry-creation path for create/mkdir/mknod/symlink. Caller
    /// holds the parent write lock and has validated the name is free.
    #[allow(clippy::too_many_arguments)]
    async fn insert_new_node(
        &self,
        parent_ino: u64,
        mut parent: Inode,
        name: &[u8],
        child_ino: u64,
        child: &Inode,
        symlink_target: Option<&[u8]>,
    ) -> FsResult<()> {
        self.quota.reserve(0, 1)?;
        let ts = now();
        let dirent_id = parent.next_dirent_id;
        parent.next_dirent_id += 1;
        parent.touch_mtime(ts);
        if child.kind.is_dir() {
            parent.nlink += 1;
        }

        let enc = self.names.seal_name(parent_ino, name)?;
        let dirent = Dirent {
            name: name.to_vec(),
            child_ino,
            kind: child.kind,
            dirent_id,
        };
        let idx = DirentIdx {
            enc_name: enc.clone(),
            child_ino,
            kind: child.kind,
        };

        let mut batch = WriteBatch::new();
        batch.put(keys::inode(child_ino), child.encode()?);
        batch.put(keys::dirent(parent_ino, &enc), dirent.encode()?);
        batch.put(keys::dirent_idx(parent_ino, dirent_id), idx.encode()?);
        batch.put(keys::inode(parent_ino), parent.encode()?);
        if let Some(target) = symlink_target {
            batch.put(keys::symlink(child_ino), target);
        }
        batch.merge(keys::KEY_QUOTA_INODES, encode_delta(1));

        if let Err(e) = self.commit(batch).await {
            self.quota.release(0, 1);
            return Err(e);
        }
        self.attrs.insert(child_ino, child.clone());
        self.attrs.insert(parent_ino, parent);
        self.attrs.remove_negative(parent_ino, name);
        Ok(())
    }

    /// Record the death of a file inode whose nlink hit zero, inside the
    /// caller's batch. Returns `(reap, bytes_delta, inode_delta)`: `reap` is
    /// set when the caller must reap chunk data after the commit (the file
    /// isn't held open); the quota deltas must be applied to the in-memory
    /// tracker only *after* the commit succeeds.
    fn bury_inode(
        &self,
        batch: &mut WriteBatch,
        ino: u64,
        inode: &Inode,
    ) -> FsResult<(bool, i64, i64)> {
        let orphan = Orphan {
            size: inode.size,
            kind: inode.kind,
        };
        batch.put(keys::orphan(ino), orphan.encode()?);
        let open = self
            .handles
            .lock()
            .expect("handle table poisoned")
            .is_open(ino);
        if open {
            // Keep the inode readable/writable through existing handles;
            // quota stays charged until last close.
            let mut dead = inode.clone();
            dead.nlink = 0;
            dead.ctime = now();
            batch.put(keys::inode(ino), dead.encode()?);
            Ok((false, 0, 0))
        } else {
            batch.delete(keys::inode(ino));
            batch.merge(
                keys::KEY_QUOTA_BYTES,
                encode_delta(-(inode.billed_bytes as i64)),
            );
            batch.merge(keys::KEY_QUOTA_INODES, encode_delta(-1));
            Ok((true, -(inode.billed_bytes as i64), -1))
        }
    }

    /// Finish an orphan whose last handle closed (or that a crash left with
    /// its inode intact): settle quota, drop the inode, reap data.
    pub(crate) async fn finish_orphan(&self, ino: u64) -> FsResult<()> {
        if let Some(bytes) = self.db.get(keys::inode(ino)).await? {
            let inode = Inode::decode(&bytes)?;
            let mut batch = WriteBatch::new();
            batch.delete(keys::inode(ino));
            batch.merge(
                keys::KEY_QUOTA_BYTES,
                encode_delta(-(inode.billed_bytes as i64)),
            );
            batch.merge(keys::KEY_QUOTA_INODES, encode_delta(-1));
            self.commit(batch).await?;
            self.quota.reserve(-(inode.billed_bytes as i64), -1)?;
        }
        self.attrs.remove(ino);
        self.reap_orphan(ino).await?;
        Ok(())
    }

    /// Persist relatime updates without making every read a write
    /// (plan §10): only when atime lags mtime or is older than 24h.
    async fn maybe_update_atime(&self, ino: u64, inode: &Inode) {
        let ts = now();
        let due = inode.atime < inode.mtime || ts.secs - inode.atime.secs > RELATIME_SECS;
        if !due {
            return;
        }
        let _guard = self.locks.write(ino).await;
        let Ok(Some(bytes)) = self.db.get(keys::inode(ino)).await else {
            return;
        };
        let Ok(mut current) = Inode::decode(&bytes) else {
            return;
        };
        if current.atime < current.mtime || ts.secs - current.atime.secs > RELATIME_SECS {
            current.atime = ts;
            let mut batch = WriteBatch::new();
            if let Ok(encoded) = current.encode() {
                batch.put(keys::inode(ino), encoded);
                if self.commit(batch).await.is_ok() {
                    self.attrs.insert(ino, current);
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Vfs for Volume {
    async fn lookup(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<FileAttr> {
        let dir = self.load_dir_cached(parent).await?;
        access(creds, &dir, ACCESS_X)?;
        if name == b"." {
            return Ok(self.make_attr(parent, &dir));
        }
        if name == b".." {
            let up = dir.parent_dir;
            let upnode = self.load_inode_cached(up).await?;
            return Ok(self.make_attr(up, &upnode));
        }
        validate_name(name)?;
        if self.attrs.is_negative(parent, name) {
            return Err(FsError::NotFound);
        }
        match self.dirent_of(parent, name).await? {
            Some(d) => {
                let inode = self
                    .load_inode_cached(d.child_ino)
                    .await
                    .map_err(|_| FsError::NotFound)?;
                Ok(self.make_attr(d.child_ino, &inode))
            }
            None => {
                self.attrs.insert_negative(parent, name);
                Err(FsError::NotFound)
            }
        }
    }

    async fn getattr(&self, _creds: &Credentials, ino: u64) -> FsResult<FileAttr> {
        let inode = self.load_inode_cached(ino).await?;
        Ok(self.make_attr(ino, &inode))
    }

    async fn setattr(&self, creds: &Credentials, ino: u64, attrs: SetAttrs) -> FsResult<FileAttr> {
        let _guard = self.locks.write(ino).await;
        let mut inode = self.load_inode(ino).await?;
        let ts = now();
        let is_owner = creds.uid == inode.uid;

        // Permission gates first, before any mutation is planned.
        if let Some(mode) = attrs.mode {
            if !creds.is_root() && !is_owner {
                return Err(FsError::NotPermitted);
            }
            let mut mode = mode & 0o7777;
            // Non-root setting setgid without membership in the file's group
            // silently loses the bit (POSIX).
            if !creds.is_root() && !creds.in_group(inode.gid) {
                mode &= !0o2000;
            }
            inode.mode = mode;
        }
        // chown permission rules apply even when the requested values equal
        // the current ones — a non-owner's no-op chown is still EPERM
        // (pjdfstest chown/07).
        if let Some(uid) = attrs.uid {
            let allowed = creds.is_root() || (is_owner && uid == inode.uid);
            if !allowed {
                return Err(FsError::NotPermitted);
            }
            inode.uid = uid;
        }
        if let Some(gid) = attrs.gid {
            let owner_with_group = is_owner && (gid == inode.gid || creds.in_group(gid));
            if !creds.is_root() && !owner_with_group {
                return Err(FsError::NotPermitted);
            }
            if !creds.is_root() && gid != inode.gid {
                inode.mode &= !0o6000; // chown clears setuid/setgid
            }
            inode.gid = gid;
        }
        for (slot, time) in [(attrs.atime, true), (attrs.mtime, false)]
            .iter()
            .filter_map(|(s, w)| s.map(|t| (t, *w)))
        {
            match slot {
                TimeSet::Now => {
                    if !creds.is_root() && !is_owner {
                        access(creds, &inode, ACCESS_W)?;
                    }
                    if time {
                        inode.atime = ts;
                    } else {
                        inode.mtime = ts;
                    }
                }
                TimeSet::Time(t) => {
                    if !creds.is_root() && !is_owner {
                        return Err(FsError::NotPermitted);
                    }
                    if time {
                        inode.atime = t;
                    } else {
                        inode.mtime = t;
                    }
                }
            }
        }

        let mut batch = WriteBatch::new();
        let mut quota_delta = 0i64;
        let mut spill_deletes: Vec<u32> = Vec::new();

        if let Some(new_size) = attrs.size {
            match inode.kind {
                FileKind::File => {}
                FileKind::Dir => return Err(FsError::IsDir),
                _ => return Err(FsError::Invalid),
            }
            access(creds, &inode, ACCESS_W)?;
            if new_size != inode.size {
                let plan =
                    data::plan_truncate(&self.db, self.chunk_size, ino, inode.size, new_size)
                        .await?;
                self.quota.reserve(plan.billed_delta, 0)?;
                quota_delta = plan.billed_delta;
                if let Some((idx, bytes)) = plan.tail_put {
                    batch.put(keys::chunk(ino, idx), bytes);
                }
                // Bounded number of deletes inline; the long tail goes to
                // follow-up batches (plan §6 — trailing chunks bill 0 and are
                // unreachable if we crash before deleting them).
                const INLINE_DELETES: usize = 1024;
                for idx in plan.deletes.iter().take(INLINE_DELETES) {
                    batch.delete(keys::chunk(ino, *idx));
                }
                spill_deletes = plan.deletes.iter().skip(INLINE_DELETES).copied().collect();
                if plan.billed_delta != 0 {
                    batch.merge(keys::KEY_QUOTA_BYTES, encode_delta(plan.billed_delta));
                }
                inode.size = new_size;
                inode.billed_bytes = (inode.billed_bytes as i64 + plan.billed_delta) as u64;
                inode.mtime = ts;
            }
        }

        inode.ctime = ts;
        batch.put(keys::inode(ino), inode.encode()?);
        if let Err(e) = self.commit(batch).await {
            self.quota.release(quota_delta, 0);
            return Err(e);
        }
        self.attrs.insert(ino, inode.clone());
        for group in spill_deletes.chunks(1024) {
            let mut batch = WriteBatch::new();
            for idx in group {
                batch.delete(keys::chunk(ino, *idx));
            }
            self.commit(batch).await?;
        }
        Ok(self.make_attr(ino, &inode))
    }

    async fn read(&self, creds: &Credentials, ino: u64, offset: u64, len: u32) -> FsResult<Bytes> {
        let inode = self.load_inode_cached(ino).await?;
        match inode.kind {
            FileKind::File => {}
            FileKind::Dir => return Err(FsError::IsDir),
            _ => return Err(FsError::Invalid),
        }
        access(creds, &inode, ACCESS_R)?;
        let bytes =
            data::read_range(&self.db, self.chunk_size, ino, inode.size, offset, len).await?;
        self.plan_readahead(ino, offset, offset + bytes.len() as u64, inode.size);
        self.maybe_update_atime(ino, &inode).await;
        Ok(bytes)
    }

    async fn write(
        &self,
        creds: &Credentials,
        ino: u64,
        offset: u64,
        data_buf: &[u8],
    ) -> FsResult<u32> {
        if data_buf.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(data_buf.len() as u64)
            .ok_or(FsError::FileTooBig)?;
        if end > self.chunk_size * u32::MAX as u64 {
            return Err(FsError::FileTooBig);
        }

        let _guard = self.locks.write(ino).await;
        let mut inode = self.load_inode(ino).await?;
        if inode.kind != FileKind::File {
            return Err(if inode.kind.is_dir() {
                FsError::IsDir
            } else {
                FsError::Invalid
            });
        }
        access(creds, &inode, ACCESS_W)?;

        let plan =
            data::plan_write(&self.db, self.chunk_size, ino, inode.size, offset, data_buf).await?;
        self.quota.reserve(plan.billed_delta, 0)?;

        let ts = now();
        inode.size = plan.new_size;
        inode.billed_bytes = (inode.billed_bytes as i64 + plan.billed_delta) as u64;
        inode.touch_mtime(ts);
        if !creds.is_root() && inode.mode & 0o6000 != 0 {
            inode.mode &= !0o6000; // write clears setuid/setgid
        }

        let mut batch = WriteBatch::new();
        for (idx, bytes) in plan.puts {
            batch.put(keys::chunk(ino, idx), bytes);
        }
        batch.put(keys::inode(ino), inode.encode()?);
        if plan.billed_delta != 0 {
            batch.merge(keys::KEY_QUOTA_BYTES, encode_delta(plan.billed_delta));
        }
        if let Err(e) = self.commit(batch).await {
            self.quota.release(plan.billed_delta, 0);
            return Err(e);
        }
        self.attrs.insert(ino, inode);
        Ok(data_buf.len() as u32)
    }

    async fn create(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        mode: u32,
        exclusive: bool,
    ) -> FsResult<FileAttr> {
        validate_name(name)?;
        let _guard = self.locks.write(parent).await;
        let dir = self.load_dir(parent).await?;
        access(creds, &dir, ACCESS_W | ACCESS_X)?;

        if let Some(existing) = self.dirent_of(parent, name).await? {
            if exclusive {
                return Err(FsError::Exists);
            }
            let inode = self.load_inode(existing.child_ino).await?;
            if inode.kind.is_dir() {
                return Err(FsError::IsDir);
            }
            access(creds, &inode, ACCESS_W)?;
            return Ok(self.make_attr(existing.child_ino, &inode));
        }

        let (uid, gid, mode) = Self::new_node_ids(creds, &dir, FileKind::File, mode);
        let child_ino = self.alloc_ino().await?;
        let child = Inode::new(FileKind::File, mode, uid, gid, now());
        self.insert_new_node(parent, dir, name, child_ino, &child, None)
            .await?;
        Ok(self.make_attr(child_ino, &child))
    }

    async fn mkdir(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        mode: u32,
    ) -> FsResult<FileAttr> {
        validate_name(name)?;
        let _guard = self.locks.write(parent).await;
        let dir = self.load_dir(parent).await?;
        access(creds, &dir, ACCESS_W | ACCESS_X)?;
        if self.dirent_of(parent, name).await?.is_some() {
            return Err(FsError::Exists);
        }

        let (uid, gid, mode) = Self::new_node_ids(creds, &dir, FileKind::Dir, mode);
        let child_ino = self.alloc_ino().await?;
        let mut child = Inode::new(FileKind::Dir, mode, uid, gid, now());
        child.parent_dir = parent;
        self.insert_new_node(parent, dir, name, child_ino, &child, None)
            .await?;
        Ok(self.make_attr(child_ino, &child))
    }

    async fn mknod(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        mode: u32,
        kind: FileKind,
        rdev: u64,
    ) -> FsResult<FileAttr> {
        validate_name(name)?;
        match kind {
            FileKind::Fifo | FileKind::Socket | FileKind::File => {}
            FileKind::CharDev | FileKind::BlockDev => {
                if !creds.is_root() {
                    return Err(FsError::NotPermitted);
                }
            }
            FileKind::Dir | FileKind::Symlink => return Err(FsError::Invalid),
        }
        let _guard = self.locks.write(parent).await;
        let dir = self.load_dir(parent).await?;
        access(creds, &dir, ACCESS_W | ACCESS_X)?;
        if self.dirent_of(parent, name).await?.is_some() {
            return Err(FsError::Exists);
        }

        let (uid, gid, mode) = Self::new_node_ids(creds, &dir, kind, mode);
        let child_ino = self.alloc_ino().await?;
        let mut child = Inode::new(kind, mode, uid, gid, now());
        child.rdev = rdev;
        self.insert_new_node(parent, dir, name, child_ino, &child, None)
            .await?;
        Ok(self.make_attr(child_ino, &child))
    }

    async fn symlink(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        target: &[u8],
    ) -> FsResult<FileAttr> {
        validate_name(name)?;
        if target.is_empty() || target.len() > 4096 {
            return Err(FsError::Invalid);
        }
        let _guard = self.locks.write(parent).await;
        let dir = self.load_dir(parent).await?;
        access(creds, &dir, ACCESS_W | ACCESS_X)?;
        if self.dirent_of(parent, name).await?.is_some() {
            return Err(FsError::Exists);
        }

        let (uid, gid, _) = Self::new_node_ids(creds, &dir, FileKind::Symlink, 0o777);
        let child_ino = self.alloc_ino().await?;
        let mut child = Inode::new(FileKind::Symlink, 0o777, uid, gid, now());
        child.size = target.len() as u64;
        self.insert_new_node(parent, dir, name, child_ino, &child, Some(target))
            .await?;
        Ok(self.make_attr(child_ino, &child))
    }

    async fn readlink(&self, _creds: &Credentials, ino: u64) -> FsResult<Vec<u8>> {
        let inode = self.load_inode(ino).await?;
        if inode.kind != FileKind::Symlink {
            return Err(FsError::Invalid);
        }
        match self.db.get(keys::symlink(ino)).await? {
            Some(bytes) => Ok(bytes.to_vec()),
            None => Err(FsError::Io),
        }
    }

    async fn link(
        &self,
        creds: &Credentials,
        ino: u64,
        new_parent: u64,
        new_name: &[u8],
    ) -> FsResult<FileAttr> {
        validate_name(new_name)?;
        let _guards = self.locks.write_many(&[ino, new_parent]).await;
        let mut inode = self.load_inode(ino).await?;
        if inode.kind.is_dir() {
            return Err(FsError::NotPermitted); // no hardlinks to directories
        }
        let mut dir = self.load_dir(new_parent).await?;
        access(creds, &dir, ACCESS_W | ACCESS_X)?;
        if self.dirent_of(new_parent, new_name).await?.is_some() {
            return Err(FsError::Exists);
        }

        let ts = now();
        inode.nlink = inode.nlink.checked_add(1).ok_or(FsError::TooManyLinks)?;
        inode.ctime = ts;
        let dirent_id = dir.next_dirent_id;
        dir.next_dirent_id += 1;
        dir.touch_mtime(ts);

        let enc = self.names.seal_name(new_parent, new_name)?;
        let dirent = Dirent {
            name: new_name.to_vec(),
            child_ino: ino,
            kind: inode.kind,
            dirent_id,
        };
        let idx = DirentIdx {
            enc_name: enc.clone(),
            child_ino: ino,
            kind: inode.kind,
        };

        let mut batch = WriteBatch::new();
        batch.put(keys::inode(ino), inode.encode()?);
        batch.put(keys::dirent(new_parent, &enc), dirent.encode()?);
        batch.put(keys::dirent_idx(new_parent, dirent_id), idx.encode()?);
        batch.put(keys::inode(new_parent), dir.encode()?);
        self.commit(batch).await?;
        self.attrs.insert(ino, inode.clone());
        self.attrs.insert(new_parent, dir);
        self.attrs.remove_negative(new_parent, new_name);
        Ok(self.make_attr(ino, &inode))
    }

    async fn unlink(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<()> {
        validate_name(name)?;
        loop {
            let Some(d) = self.dirent_of(parent, name).await? else {
                return Err(FsError::NotFound);
            };
            let _guards = self.locks.write_many(&[parent, d.child_ino]).await;
            // Re-read under locks; retry if the entry changed underneath us.
            let Some(d2) = self.dirent_of(parent, name).await? else {
                return Err(FsError::NotFound);
            };
            if d2.child_ino != d.child_ino || d2.dirent_id != d.dirent_id {
                continue;
            }

            let mut dir = self.load_dir(parent).await?;
            access(creds, &dir, ACCESS_W | ACCESS_X)?;
            let mut child = self
                .load_inode(d.child_ino)
                .await
                .map_err(|_| FsError::Io)?;
            if child.kind.is_dir() {
                return Err(FsError::IsDir);
            }
            check_sticky(creds, &dir, &child)?;

            let ts = now();
            dir.touch_mtime(ts);
            let enc = self.names.seal_name(parent, name)?;

            let mut batch = WriteBatch::new();
            batch.delete(keys::dirent(parent, &enc));
            batch.delete(keys::dirent_idx(parent, d.dirent_id));
            batch.put(keys::inode(parent), dir.encode()?);

            child.nlink -= 1;
            let (reap, qb, qi) = if child.nlink == 0 {
                self.bury_inode(&mut batch, d.child_ino, &child)?
            } else {
                child.ctime = ts;
                batch.put(keys::inode(d.child_ino), child.encode()?);
                (false, 0, 0)
            };

            self.commit(batch).await?;
            self.attrs.insert(parent, dir);
            self.attrs.remove(d.child_ino);
            self.attrs.insert_negative(parent, name);
            // Frees never fail; tracker moves only after the commit landed.
            let _ = self.quota.reserve(qb, qi);
            if reap {
                self.reap_orphan(d.child_ino).await?;
            }
            return Ok(());
        }
    }

    async fn rmdir(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<()> {
        validate_name(name)?;
        loop {
            let Some(d) = self.dirent_of(parent, name).await? else {
                return Err(FsError::NotFound);
            };
            let _guards = self.locks.write_many(&[parent, d.child_ino]).await;
            let Some(d2) = self.dirent_of(parent, name).await? else {
                return Err(FsError::NotFound);
            };
            if d2.child_ino != d.child_ino || d2.dirent_id != d.dirent_id {
                continue;
            }

            let mut dir = self.load_dir(parent).await?;
            access(creds, &dir, ACCESS_W | ACCESS_X)?;
            let child = self
                .load_inode(d.child_ino)
                .await
                .map_err(|_| FsError::Io)?;
            if !child.kind.is_dir() {
                return Err(FsError::NotDir);
            }
            check_sticky(creds, &dir, &child)?;

            // Emptiness: any dirent under the child?
            let mut iter = self
                .db
                .scan(
                    keys::dirent_prefix(d.child_ino).to_vec()
                        ..keys::dirent_prefix(d.child_ino + 1).to_vec(),
                )
                .await
                .map_err(FsError::from)?;
            if iter.next().await.map_err(FsError::from)?.is_some() {
                return Err(FsError::NotEmpty);
            }

            let ts = now();
            dir.touch_mtime(ts);
            dir.nlink -= 1;
            let enc = self.names.seal_name(parent, name)?;

            let mut batch = WriteBatch::new();
            batch.delete(keys::dirent(parent, &enc));
            batch.delete(keys::dirent_idx(parent, d.dirent_id));
            batch.delete(keys::inode(d.child_ino));
            // Directories own no chunks; drop any xattrs inline.
            let mut xiter = self
                .db
                .scan(
                    keys::xattr_prefix(d.child_ino).to_vec()
                        ..keys::xattr_prefix(d.child_ino + 1).to_vec(),
                )
                .await
                .map_err(FsError::from)?;
            while let Some(kv) = xiter.next().await.map_err(FsError::from)? {
                batch.delete(kv.key);
            }
            batch.put(keys::inode(parent), dir.encode()?);
            batch.merge(keys::KEY_QUOTA_INODES, encode_delta(-1));
            self.commit(batch).await?;
            self.attrs.insert(parent, dir);
            self.attrs.remove(d.child_ino);
            self.attrs.insert_negative(parent, name);
            let _ = self.quota.reserve(0, -1); // free, post-commit
            return Ok(());
        }
    }

    async fn rename(
        &self,
        creds: &Credentials,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
    ) -> FsResult<()> {
        validate_name(old_name)?;
        validate_name(new_name)?;

        // Serialize renames volume-wide: the ancestor cycle check must not
        // race another directory move (DD-5, plan §10).
        let _rename_guard = self.locks.rename_guard().await;

        loop {
            let Some(src) = self.dirent_of(old_parent, old_name).await? else {
                return Err(FsError::NotFound);
            };
            let dst = self.dirent_of(new_parent, new_name).await?;

            let mut lock_set = vec![old_parent, new_parent, src.child_ino];
            if let Some(d) = &dst {
                lock_set.push(d.child_ino);
            }
            let _guards = self.locks.write_many(&lock_set).await;

            // Re-validate the snapshot we locked against.
            let src2 = self.dirent_of(old_parent, old_name).await?;
            let dst2 = self.dirent_of(new_parent, new_name).await?;
            if src2.as_ref().map(|d| (d.child_ino, d.dirent_id))
                != Some((src.child_ino, src.dirent_id))
                || dst2.as_ref().map(|d| (d.child_ino, d.dirent_id))
                    != dst.as_ref().map(|d| (d.child_ino, d.dirent_id))
            {
                continue;
            }

            // No-op: renaming a hardlink onto itself succeeds untouched.
            if let Some(d) = &dst
                && d.child_ino == src.child_ino
            {
                return Ok(());
            }
            if old_parent == new_parent && old_name == new_name {
                return Ok(());
            }

            let same_parent = old_parent == new_parent;
            let mut old_dir = self.load_dir(old_parent).await?;
            access(creds, &old_dir, ACCESS_W | ACCESS_X)?;
            let mut new_dir = if same_parent {
                old_dir.clone()
            } else {
                let d = self.load_dir(new_parent).await?;
                access(creds, &d, ACCESS_W | ACCESS_X)?;
                d
            };

            let mut moved = self
                .load_inode(src.child_ino)
                .await
                .map_err(|_| FsError::Io)?;
            check_sticky(creds, &old_dir, &moved)?;

            // Moving a directory to a different parent rewrites its `..`
            // entry, so POSIX requires write permission on the directory
            // being moved (pjdfstest rename/09, rename/21).
            if moved.kind.is_dir() && !same_parent {
                access(creds, &moved, ACCESS_W)?;
            }

            // Directory moves: cycle check — new_parent must not live under
            // the moved directory (walk parent_dir chain to root).
            if moved.kind.is_dir() && !same_parent {
                let mut cursor = new_parent;
                loop {
                    if cursor == src.child_ino {
                        return Err(FsError::Invalid);
                    }
                    if cursor == ROOT_INO {
                        break;
                    }
                    cursor = self
                        .load_inode(cursor)
                        .await
                        .map_err(|_| FsError::Io)?
                        .parent_dir;
                }
            }

            let ts = now();
            let mut batch = WriteBatch::new();
            let mut reap: Option<u64> = None;
            let (mut qb, mut qi) = (0i64, 0i64);

            // Replaced target, if any.
            if let Some(dstd) = &dst {
                let mut target = self
                    .load_inode(dstd.child_ino)
                    .await
                    .map_err(|_| FsError::Io)?;
                check_sticky(creds, &new_dir, &target)?;
                match (moved.kind.is_dir(), target.kind.is_dir()) {
                    (true, false) => return Err(FsError::NotDir),
                    (false, true) => return Err(FsError::IsDir),
                    (true, true) => {
                        let mut iter = self
                            .db
                            .scan(
                                keys::dirent_prefix(dstd.child_ino).to_vec()
                                    ..keys::dirent_prefix(dstd.child_ino + 1).to_vec(),
                            )
                            .await
                            .map_err(FsError::from)?;
                        if iter.next().await.map_err(FsError::from)?.is_some() {
                            return Err(FsError::NotEmpty);
                        }
                        batch.delete(keys::inode(dstd.child_ino));
                        batch.merge(keys::KEY_QUOTA_INODES, encode_delta(-1));
                        qi -= 1;
                        new_dir.nlink -= 1;
                    }
                    (false, false) => {
                        target.nlink -= 1;
                        if target.nlink == 0 {
                            let (do_reap, b, i) =
                                self.bury_inode(&mut batch, dstd.child_ino, &target)?;
                            qb += b;
                            qi += i;
                            if do_reap {
                                reap = Some(dstd.child_ino);
                            }
                        } else {
                            target.ctime = ts;
                            batch.put(keys::inode(dstd.child_ino), target.encode()?);
                        }
                    }
                }
                let dst_enc = self.names.seal_name(new_parent, new_name)?;
                batch.delete(keys::dirent(new_parent, &dst_enc));
                batch.delete(keys::dirent_idx(new_parent, dstd.dirent_id));
            }

            // Remove the source entry, add the destination entry.
            let src_enc = self.names.seal_name(old_parent, old_name)?;
            batch.delete(keys::dirent(old_parent, &src_enc));
            batch.delete(keys::dirent_idx(old_parent, src.dirent_id));

            let new_id = new_dir.next_dirent_id;
            new_dir.next_dirent_id += 1;
            let new_enc = self.names.seal_name(new_parent, new_name)?;
            batch.put(
                keys::dirent(new_parent, &new_enc),
                Dirent {
                    name: new_name.to_vec(),
                    child_ino: src.child_ino,
                    kind: moved.kind,
                    dirent_id: new_id,
                }
                .encode()?,
            );
            batch.put(
                keys::dirent_idx(new_parent, new_id),
                DirentIdx {
                    enc_name: new_enc,
                    child_ino: src.child_ino,
                    kind: moved.kind,
                }
                .encode()?,
            );

            // Parent bookkeeping (nlink moves with directories).
            if moved.kind.is_dir() && !same_parent {
                old_dir.nlink -= 1;
                new_dir.nlink += 1;
                moved.parent_dir = new_parent;
            }
            moved.ctime = ts;
            batch.put(keys::inode(src.child_ino), moved.encode()?);

            if same_parent {
                // new_dir carries both ctime/mtime and dirent-id bumps.
                new_dir.touch_mtime(ts);
                batch.put(keys::inode(new_parent), new_dir.encode()?);
            } else {
                old_dir.touch_mtime(ts);
                new_dir.touch_mtime(ts);
                batch.put(keys::inode(old_parent), old_dir.encode()?);
                batch.put(keys::inode(new_parent), new_dir.encode()?);
            }

            self.commit(batch).await?;
            self.attrs.insert(src.child_ino, moved);
            if same_parent {
                self.attrs.insert(new_parent, new_dir);
            } else {
                self.attrs.insert(old_parent, old_dir);
                self.attrs.insert(new_parent, new_dir);
            }
            if let Some(dstd) = &dst {
                self.attrs.remove(dstd.child_ino);
            }
            self.attrs.insert_negative(old_parent, old_name);
            self.attrs.remove_negative(new_parent, new_name);
            let _ = self.quota.reserve(qb, qi); // frees, post-commit
            if let Some(ino) = reap {
                self.reap_orphan(ino).await?;
            }
            return Ok(());
        }
    }

    async fn readdir(
        &self,
        creds: &Credentials,
        parent: u64,
        cookie: u64,
        max_entries: usize,
    ) -> FsResult<ReadDir> {
        let dir = self.load_dir_cached(parent).await?;
        access(creds, &dir, ACCESS_R)?;

        let start = keys::dirent_idx(parent, cookie.saturating_add(1));
        let end = keys::dirent_idx(parent, u64::MAX);
        let mut iter = self
            .db
            .scan(start.to_vec()..end.to_vec())
            .await
            .map_err(FsError::from)?;

        let mut entries = Vec::new();
        let mut eof = true;
        while let Some(kv) = iter.next().await.map_err(FsError::from)? {
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
        match self.db.get(keys::xattr(ino, name)).await? {
            Some(bytes) => Ok(bytes.to_vec()),
            None => Err(FsError::NoData),
        }
    }

    async fn setxattr(
        &self,
        creds: &Credentials,
        ino: u64,
        name: &[u8],
        value: &[u8],
    ) -> FsResult<()> {
        if name.is_empty() || name.len() > MAX_NAME_LEN || value.len() > MAX_XATTR_VALUE {
            return Err(FsError::Invalid);
        }
        // Quota-gated but not byte-billed (accounting counts chunks only,
        // plan §12).
        self.quota.check_not_over()?;
        let _guard = self.locks.write(ino).await;
        let mut inode = self.load_inode(ino).await?;
        access(creds, &inode, ACCESS_W)?;
        inode.ctime = now();
        let mut batch = WriteBatch::new();
        batch.put(keys::xattr(ino, name), value);
        batch.put(keys::inode(ino), inode.encode()?);
        self.commit(batch).await?;
        self.attrs.insert(ino, inode);
        Ok(())
    }

    async fn listxattr(&self, creds: &Credentials, ino: u64) -> FsResult<Vec<Vec<u8>>> {
        let inode = self.load_inode(ino).await?;
        access(creds, &inode, ACCESS_R)?;
        let mut iter = self
            .db
            .scan(keys::xattr_prefix(ino).to_vec()..keys::xattr_prefix(ino + 1).to_vec())
            .await
            .map_err(FsError::from)?;
        let mut names = Vec::new();
        while let Some(kv) = iter.next().await.map_err(FsError::from)? {
            names.push(kv.key[9..].to_vec());
        }
        Ok(names)
    }

    async fn removexattr(&self, creds: &Credentials, ino: u64, name: &[u8]) -> FsResult<()> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(FsError::Invalid);
        }
        let _guard = self.locks.write(ino).await;
        let mut inode = self.load_inode(ino).await?;
        access(creds, &inode, ACCESS_W)?;
        if self.db.get(keys::xattr(ino, name)).await?.is_none() {
            return Err(FsError::NoData);
        }
        inode.ctime = now();
        let mut batch = WriteBatch::new();
        batch.delete(keys::xattr(ino, name));
        batch.put(keys::inode(ino), inode.encode()?);
        self.commit(batch).await?;
        self.attrs.insert(ino, inode);
        Ok(())
    }

    async fn statfs(&self, _creds: &Credentials) -> FsResult<StatFs> {
        let (bytes_used, inodes_used) = self.quota.usage();
        let limits = self.quota.limits();
        let (total_bytes, free_bytes) = match limits.bytes.hard {
            Some(limit) => (limit, limit.saturating_sub(bytes_used.max(0) as u64)),
            None => (
                NOMINAL_BYTES,
                NOMINAL_BYTES.saturating_sub(bytes_used.max(0) as u64),
            ),
        };
        let (total_inodes, free_inodes) = match limits.inodes.hard {
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
        // DD-7: fsync/COMMIT acks only after the WAL reaches the object store.
        self.db.flush().await?;
        Ok(())
    }

    async fn open(&self, creds: &Credentials, ino: u64, mode: OpenMode) -> FsResult<HandleId> {
        let inode = self.load_inode(ino).await?;
        let want = match mode {
            OpenMode::Read => ACCESS_R,
            OpenMode::Write => ACCESS_W,
            OpenMode::ReadWrite => ACCESS_R | ACCESS_W,
        };
        access(creds, &inode, want)?;
        Ok(self
            .handles
            .lock()
            .expect("handle table poisoned")
            .open(ino, mode))
    }

    async fn close(&self, handle: HandleId) -> FsResult<()> {
        let closed = self
            .handles
            .lock()
            .expect("handle table poisoned")
            .close(handle);
        let Some((ino, _, last)) = closed else {
            return Err(FsError::BadHandle);
        };
        self.range_locks.unlock_owner(handle);
        if last && self.db.get(keys::orphan(ino)).await?.is_some() {
            // Last handle on an unlinked file: settle quota and reap.
            let _guard = self.locks.write(ino).await;
            self.finish_orphan(ino).await?;
        }
        Ok(())
    }

    async fn lock(&self, handle: HandleId, start: u64, end: u64, exclusive: bool) -> FsResult<()> {
        if start >= end {
            return Err(FsError::Invalid);
        }
        let held = self
            .handles
            .lock()
            .expect("handle table poisoned")
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
            .expect("handle table poisoned")
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
        if start >= end {
            return Err(FsError::Invalid);
        }
        let held = self
            .handles
            .lock()
            .expect("handle table poisoned")
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
            .map(|l| (l.range.start, l.range.end, l.exclusive)))
    }
}
