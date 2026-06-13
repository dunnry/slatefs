//! Adapter from the SlateFS [`Vfs`] to `nfs3_server`'s filesystem traits
//! (plan §9.2). `fileid3` = ino; handles per `fh.rs`; DD-7 durability mapping
//! lives in `write`/`commit`.
//!
//! Credentials: the vendored nfs3_server patch exposes each request's
//! AUTH_UNIX identity via `nfs3_server::current_rpc_auth()`; the export's
//! [`SquashPolicy`] maps that unauthenticated assertion (DD-10) to the
//! [`Credentials`] every Vfs call runs under.

use std::collections::VecDeque;
use std::sync::Arc;

use nfs3_server::nfs3_types::nfs3::{
    ACCESS3_DELETE, ACCESS3_EXECUTE, ACCESS3_EXTEND, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ,
    FSF3_CANSETTIME, FSF3_HOMOGENEOUS, FSF3_SYMLINK, FSINFO3resok as fsinfo3,
    FSSTAT3resok as fsstat3, Nfs3Option, createverf3, fattr3, filename3, ftype3, mknoddata3,
    nfspath3, nfsstat3, nfstime3, sattr3, set_atime, set_mtime, specdata3, stable_how,
};
use nfs3_server::vfs::{
    DirEntryPlus, NextResult, NfsFileSystem, NfsReadFileSystem, ReadDirPlusIterator,
    VFSCapabilities,
};
use slatefs_core::config::SquashMode;
use slatefs_core::crypto::Secret32;
use slatefs_core::meta::inode::{FileKind, ROOT_INO, Timespec};
use slatefs_core::vfs::{Credentials, FileAttr, FsError, SetAttrs, TimeSet, Vfs};
use slatefs_core::volume::Volume;

use crate::fh::{FhCodec, SlateFsHandle};

/// Verifier stored at exclusive create so retransmitted CREATE(EXCLUSIVE)
/// calls are idempotent (RFC 1813 §3.3.8).
const EXCL_VERF_XATTR: &[u8] = b"system.slatefs.createverf";

/// Maps the caller's (unauthenticated) AUTH_UNIX assertion to the identity
/// Vfs calls run under (DD-10 squash policy).
#[derive(Debug, Clone)]
pub struct SquashPolicy {
    pub mode: SquashMode,
    pub anon_uid: u32,
    pub anon_gid: u32,
}

impl SquashPolicy {
    pub fn all_squash(anon_uid: u32, anon_gid: u32) -> SquashPolicy {
        SquashPolicy {
            mode: SquashMode::AllSquash,
            anon_uid,
            anon_gid,
        }
    }

    pub fn trust_as_root() -> SquashPolicy {
        SquashPolicy {
            mode: SquashMode::TrustAsRoot,
            anon_uid: 65534,
            anon_gid: 65534,
        }
    }

    pub fn no_squash() -> SquashPolicy {
        SquashPolicy {
            mode: SquashMode::NoSquash,
            anon_uid: 65534,
            anon_gid: 65534,
        }
    }

    fn anon(&self) -> Credentials {
        Credentials::user(self.anon_uid, self.anon_gid)
    }

    /// Credentials for the RPC currently being served.
    fn credentials(&self) -> Credentials {
        let auth = nfs3_server::current_rpc_auth();
        match self.mode {
            SquashMode::AllSquash => self.anon(),
            SquashMode::TrustAsRoot => Credentials::root(),
            SquashMode::NoSquash => match auth {
                Some(a) => Credentials {
                    uid: a.uid,
                    gid: a.gid,
                    groups: a.gids,
                    trusted: false,
                },
                None => self.anon(),
            },
            SquashMode::RootSquash => match auth {
                Some(a) if a.uid != 0 => Credentials {
                    uid: a.uid,
                    gid: a.gid,
                    groups: a.gids,
                    trusted: false,
                },
                _ => self.anon(),
            },
        }
    }
}

pub struct SlateFsNfs {
    volume: Arc<Volume>,
    fh: FhCodec,
    policy: SquashPolicy,
}

impl SlateFsNfs {
    pub fn new(volume: Arc<Volume>, fh_key: Secret32, policy: SquashPolicy) -> SlateFsNfs {
        let fh = FhCodec::new(volume.fsid(), fh_key);
        SlateFsNfs { volume, fh, policy }
    }

    fn creds(&self) -> Credentials {
        self.policy.credentials()
    }

    fn ino_of(&self, handle: &SlateFsHandle) -> Result<u64, nfsstat3> {
        self.fh.verify(handle).ok_or(nfsstat3::NFS3ERR_BADHANDLE)
    }

    fn handle_for(&self, attr: &FileAttr) -> SlateFsHandle {
        self.fh.make(attr.ino, attr.generation)
    }

    fn fattr(&self, attr: &FileAttr) -> fattr3 {
        fattr3 {
            type_: kind_to_ftype(attr.kind),
            mode: attr.mode,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            size: wire_size(attr),
            used: wire_used(attr),
            rdev: specdata3 {
                specdata1: (attr.rdev >> 32) as u32,
                specdata2: attr.rdev as u32,
            },
            fsid: self.volume.fsid(),
            fileid: attr.ino,
            atime: to_nfstime(attr.atime),
            mtime: to_nfstime(attr.mtime),
            ctime: to_nfstime(attr.ctime),
        }
    }

    async fn getattr_checked(&self, handle: &SlateFsHandle) -> Result<FileAttr, nfsstat3> {
        let ino = self.ino_of(handle)?;
        let attr = self
            .volume
            .getattr(&self.creds(), ino)
            .await
            .map_err(map_err)?;
        // Generation mismatch ⇒ the ino was reused since this handle was
        // minted (plan §5).
        if attr.generation != handle.generation() {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        Ok(attr)
    }
}

/// Directories carry no byte size in SlateFS; report the conventional
/// 4 KiB instead of 0. Real filesystems never report size-0 directories,
/// and clients use st_size of directories for heuristics (allocation,
/// du output) — match convention rather than leak the internal 0.
fn wire_size(attr: &FileAttr) -> u64 {
    if attr.kind == FileKind::Dir {
        4096
    } else {
        attr.size
    }
}

fn wire_used(attr: &FileAttr) -> u64 {
    if attr.kind == FileKind::Dir {
        4096
    } else {
        attr.blocks * 512
    }
}

fn kind_to_ftype(kind: FileKind) -> ftype3 {
    match kind {
        FileKind::File => ftype3::NF3REG,
        FileKind::Dir => ftype3::NF3DIR,
        FileKind::Symlink => ftype3::NF3LNK,
        FileKind::Fifo => ftype3::NF3FIFO,
        FileKind::Socket => ftype3::NF3SOCK,
        FileKind::CharDev => ftype3::NF3CHR,
        FileKind::BlockDev => ftype3::NF3BLK,
    }
}

fn to_nfstime(ts: Timespec) -> nfstime3 {
    // NFSv3 times are u32 seconds; clamp pre-epoch and post-2106 values.
    nfstime3 {
        seconds: ts.secs.clamp(0, u32::MAX as i64) as u32,
        nseconds: ts.nanos,
    }
}

fn from_nfstime(t: &nfstime3) -> Timespec {
    Timespec {
        secs: t.seconds as i64,
        nanos: t.nseconds,
    }
}

fn map_err(e: FsError) -> nfsstat3 {
    match e {
        FsError::NotPermitted => nfsstat3::NFS3ERR_PERM,
        FsError::NotFound => nfsstat3::NFS3ERR_NOENT,
        FsError::Io => nfsstat3::NFS3ERR_IO,
        FsError::BadHandle => nfsstat3::NFS3ERR_BADHANDLE,
        FsError::WouldBlock => nfsstat3::NFS3ERR_JUKEBOX,
        FsError::AccessDenied => nfsstat3::NFS3ERR_ACCES,
        FsError::Exists => nfsstat3::NFS3ERR_EXIST,
        FsError::CrossDevice => nfsstat3::NFS3ERR_XDEV,
        FsError::NotDir => nfsstat3::NFS3ERR_NOTDIR,
        FsError::IsDir => nfsstat3::NFS3ERR_ISDIR,
        FsError::Invalid => nfsstat3::NFS3ERR_INVAL,
        FsError::FileTooBig => nfsstat3::NFS3ERR_FBIG,
        FsError::NoSpace => nfsstat3::NFS3ERR_NOSPC,
        FsError::TooManyLinks => nfsstat3::NFS3ERR_MLINK,
        FsError::NameTooLong => nfsstat3::NFS3ERR_NAMETOOLONG,
        FsError::NotEmpty => nfsstat3::NFS3ERR_NOTEMPTY,
        FsError::NoData => nfsstat3::NFS3ERR_NOENT,
        FsError::NotSupported => nfsstat3::NFS3ERR_NOTSUPP,
        FsError::Stale => nfsstat3::NFS3ERR_STALE,
        FsError::QuotaExceeded => nfsstat3::NFS3ERR_DQUOT,
    }
}

fn to_setattrs(sattr: &sattr3) -> SetAttrs {
    SetAttrs {
        mode: match sattr.mode {
            Nfs3Option::Some(m) => Some(m),
            Nfs3Option::None => None,
        },
        uid: match sattr.uid {
            Nfs3Option::Some(u) => Some(u),
            Nfs3Option::None => None,
        },
        gid: match sattr.gid {
            Nfs3Option::Some(g) => Some(g),
            Nfs3Option::None => None,
        },
        size: match sattr.size {
            Nfs3Option::Some(s) => Some(s),
            Nfs3Option::None => None,
        },
        atime: match &sattr.atime {
            set_atime::DONT_CHANGE => None,
            set_atime::SET_TO_SERVER_TIME => Some(TimeSet::Now),
            set_atime::SET_TO_CLIENT_TIME(t) => Some(TimeSet::Time(from_nfstime(t))),
        },
        mtime: match &sattr.mtime {
            set_mtime::DONT_CHANGE => None,
            set_mtime::SET_TO_SERVER_TIME => Some(TimeSet::Now),
            set_mtime::SET_TO_CLIENT_TIME(t) => Some(TimeSet::Time(from_nfstime(t))),
        },
    }
}

impl NfsReadFileSystem for SlateFsNfs {
    type Handle = SlateFsHandle;

    fn root_dir(&self) -> SlateFsHandle {
        // Root never gets a bumped generation (ino 1 is never reused).
        self.fh.make(ROOT_INO, 0)
    }

    async fn lookup(
        &self,
        dirid: &SlateFsHandle,
        filename: &filename3<'_>,
    ) -> Result<SlateFsHandle, nfsstat3> {
        let dir = self.ino_of(dirid)?;
        let attr = self
            .volume
            .lookup(&self.creds(), dir, filename.0.as_ref())
            .await
            .map_err(map_err)?;
        Ok(self.handle_for(&attr))
    }

    async fn getattr(&self, id: &SlateFsHandle) -> Result<fattr3, nfsstat3> {
        let attr = self.getattr_checked(id).await?;
        Ok(self.fattr(&attr))
    }

    async fn read(
        &self,
        id: &SlateFsHandle,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let ino = self.ino_of(id)?;
        let attr = self
            .volume
            .getattr(&self.creds(), ino)
            .await
            .map_err(map_err)?;
        let bytes = self
            .volume
            .read(&self.creds(), ino, offset, count)
            .await
            .map_err(map_err)?;
        let eof = offset + bytes.len() as u64 >= attr.size;
        Ok((bytes.to_vec(), eof))
    }

    #[allow(refining_impl_trait)]
    async fn readdirplus(
        &self,
        dirid: &SlateFsHandle,
        cookie: u64,
    ) -> Result<SlateDirIter, nfsstat3> {
        let dir = self.ino_of(dirid)?;
        // Validate the directory up front so BADHANDLE/NOTDIR surface on the
        // READDIRPLUS call itself.
        let attr = self
            .volume
            .getattr(&self.creds(), dir)
            .await
            .map_err(map_err)?;
        if attr.kind != FileKind::Dir {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }
        Ok(SlateDirIter {
            volume: Arc::clone(&self.volume),
            fh: FhCodec::new(self.volume.fsid(), self.fh_key_clone()),
            creds: self.creds(),
            dir,
            cookie,
            buffer: VecDeque::new(),
            eof: false,
        })
    }

    async fn readlink(&self, id: &SlateFsHandle) -> Result<nfspath3<'_>, nfsstat3> {
        let ino = self.ino_of(id)?;
        let target = self
            .volume
            .readlink(&self.creds(), ino)
            .await
            .map_err(map_err)?;
        Ok(nfspath3::from(target))
    }

    async fn fsinfo(&self, root_fileid: &SlateFsHandle) -> Result<fsinfo3, nfsstat3> {
        let attr = self.getattr_checked(root_fileid).await?;
        const MB: u32 = 1024 * 1024;
        Ok(fsinfo3 {
            obj_attributes: Nfs3Option::Some(self.fattr(&attr)),
            rtmax: MB,
            rtpref: MB,
            rtmult: 4096,
            wtmax: MB,
            wtpref: MB,
            wtmult: 4096,
            dtpref: MB,
            maxfilesize: self.volume.superblock().chunk_size as u64 * u32::MAX as u64,
            time_delta: nfstime3 {
                seconds: 0,
                nseconds: 1,
            },
            properties: FSF3_SYMLINK | FSF3_HOMOGENEOUS | FSF3_CANSETTIME,
        })
    }

    async fn access(&self, id: &SlateFsHandle, requested: u32) -> Result<u32, nfsstat3> {
        let creds = self.creds();
        if creds.is_root() {
            return Ok(requested);
        }
        let ino = self.ino_of(id)?;
        let attr = self.volume.getattr(&creds, ino).await.map_err(map_err)?;
        let rwx = if creds.uid == attr.uid {
            (attr.mode >> 6) & 7
        } else if creds.in_group(attr.gid) {
            (attr.mode >> 3) & 7
        } else {
            attr.mode & 7
        };
        let mut allowed = 0;
        if rwx & 4 != 0 {
            allowed |= ACCESS3_READ;
        }
        if rwx & 2 != 0 {
            // DELETE is really governed by the parent directory, which this
            // proc can't see; granting it with write keeps clients moving and
            // the actual op still enforces the sticky/parent checks.
            allowed |= ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE;
        }
        if rwx & 1 != 0 {
            allowed |= ACCESS3_LOOKUP | ACCESS3_EXECUTE;
        }
        Ok(requested & allowed)
    }

    async fn fsstat(&self, root: &SlateFsHandle) -> Result<fsstat3, nfsstat3> {
        let creds = self.creds();
        let attr = self.getattr_checked(root).await?;
        let stat = self.volume.statfs(&creds).await.map_err(map_err)?;
        Ok(fsstat3 {
            obj_attributes: Nfs3Option::Some(self.fattr(&attr)),
            tbytes: stat.total_bytes,
            fbytes: stat.free_bytes,
            abytes: stat.avail_bytes,
            tfiles: stat.total_inodes,
            ffiles: stat.free_inodes,
            afiles: stat.free_inodes,
            invarsec: 0,
        })
    }
}

impl SlateFsNfs {
    fn fh_key_clone(&self) -> Secret32 {
        self.fh.key_clone()
    }
}

impl NfsFileSystem for SlateFsNfs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    async fn setattr(&self, id: &SlateFsHandle, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let ino = self.ino_of(id)?;
        let attrs = to_setattrs(&setattr);
        if attrs.is_empty() {
            let attr = self
                .volume
                .getattr(&self.creds(), ino)
                .await
                .map_err(map_err)?;
            return Ok(self.fattr(&attr));
        }
        let attr = self
            .volume
            .setattr(&self.creds(), ino, attrs)
            .await
            .map_err(map_err)?;
        Ok(self.fattr(&attr))
    }

    async fn write(
        &self,
        id: &SlateFsHandle,
        offset: u64,
        data: &[u8],
        stable: stable_how,
    ) -> Result<(fattr3, stable_how), nfsstat3> {
        let ino = self.ino_of(id)?;
        self.volume
            .write(&self.creds(), ino, offset, data)
            .await
            .map_err(map_err)?;
        // DD-7: UNSTABLE acks from memtable+WAL buffer; DATA_SYNC/FILE_SYNC
        // only after the WAL reaches the object store.
        let achieved = match stable {
            stable_how::UNSTABLE => stable_how::UNSTABLE,
            stable_how::DATA_SYNC | stable_how::FILE_SYNC => {
                self.volume
                    .fsync(&self.creds(), ino)
                    .await
                    .map_err(map_err)?;
                stable_how::FILE_SYNC
            }
        };
        let attr = self
            .volume
            .getattr(&self.creds(), ino)
            .await
            .map_err(map_err)?;
        Ok((self.fattr(&attr), achieved))
    }

    async fn create(
        &self,
        dirid: &SlateFsHandle,
        filename: &filename3<'_>,
        attr: sattr3,
    ) -> Result<(SlateFsHandle, fattr3), nfsstat3> {
        let dir = self.ino_of(dirid)?;
        let requested = to_setattrs(&attr);
        let mode = requested.mode.unwrap_or(0o644);
        let created = self
            .volume
            .create(&self.creds(), dir, filename.0.as_ref(), mode, false)
            .await
            .map_err(map_err)?;
        // UNCHECKED create may carry attributes (typically size=0 to
        // truncate an existing file).
        let mut post = created;
        let followup = SetAttrs {
            mode: None, // applied at create for new files; don't chmod replays
            ..requested
        };
        if !followup.is_empty() {
            post = self
                .volume
                .setattr(&self.creds(), post.ino, followup)
                .await
                .map_err(map_err)?;
        }
        Ok((self.handle_for(&post), self.fattr(&post)))
    }

    async fn create_exclusive(
        &self,
        dirid: &SlateFsHandle,
        filename: &filename3<'_>,
        createverf: createverf3,
    ) -> Result<SlateFsHandle, nfsstat3> {
        let dir = self.ino_of(dirid)?;
        let name = filename.0.as_ref();
        match self
            .volume
            .create(&self.creds(), dir, name, 0o644, true)
            .await
        {
            Ok(attr) => {
                // Persist the verifier so a retransmit is recognized.
                self.volume
                    .setxattr(&self.creds(), attr.ino, EXCL_VERF_XATTR, &createverf.0)
                    .await
                    .map_err(map_err)?;
                Ok(self.handle_for(&attr))
            }
            Err(FsError::Exists) => {
                let existing = self
                    .volume
                    .lookup(&self.creds(), dir, name)
                    .await
                    .map_err(map_err)?;
                match self
                    .volume
                    .getxattr(&self.creds(), existing.ino, EXCL_VERF_XATTR)
                    .await
                {
                    Ok(verf) if verf == createverf.0 => Ok(self.handle_for(&existing)),
                    _ => Err(nfsstat3::NFS3ERR_EXIST),
                }
            }
            Err(e) => Err(map_err(e)),
        }
    }

    async fn mkdir(
        &self,
        dirid: &SlateFsHandle,
        dirname: &filename3<'_>,
        attr: &sattr3,
    ) -> Result<(SlateFsHandle, fattr3), nfsstat3> {
        let dir = self.ino_of(dirid)?;
        let creds = self.creds();
        let requested = to_setattrs(attr);
        let mode = requested.mode.unwrap_or(0o755);
        let mut made = self
            .volume
            .mkdir(&creds, dir, dirname.0.as_ref(), mode)
            .await
            .map_err(map_err)?;
        // Remaining requested attributes (uid/gid/times) apply post-create,
        // mirroring the CREATE path.
        let followup = SetAttrs {
            mode: None,
            size: None,
            ..requested
        };
        if !followup.is_empty() {
            made = self
                .volume
                .setattr(&creds, made.ino, followup)
                .await
                .map_err(map_err)?;
        }
        Ok((self.handle_for(&made), self.fattr(&made)))
    }

    async fn remove(
        &self,
        dirid: &SlateFsHandle,
        filename: &filename3<'_>,
    ) -> Result<(), nfsstat3> {
        let dir = self.ino_of(dirid)?;
        let name = filename.0.as_ref();
        // REMOVE and RMDIR share this trait method; dispatch on the child.
        let child = self
            .volume
            .lookup(&self.creds(), dir, name)
            .await
            .map_err(map_err)?;
        if child.kind == FileKind::Dir {
            self.volume
                .rmdir(&self.creds(), dir, name)
                .await
                .map_err(map_err)
        } else {
            self.volume
                .unlink(&self.creds(), dir, name)
                .await
                .map_err(map_err)
        }
    }

    async fn rename<'a>(
        &self,
        from_dirid: &SlateFsHandle,
        from_filename: &filename3<'a>,
        to_dirid: &SlateFsHandle,
        to_filename: &filename3<'a>,
    ) -> Result<(), nfsstat3> {
        let from = self.ino_of(from_dirid)?;
        let to = self.ino_of(to_dirid)?;
        self.volume
            .rename(
                &self.creds(),
                from,
                from_filename.0.as_ref(),
                to,
                to_filename.0.as_ref(),
            )
            .await
            .map_err(map_err)
    }

    async fn symlink<'a>(
        &self,
        dirid: &SlateFsHandle,
        linkname: &filename3<'a>,
        symlink: &nfspath3<'a>,
        _attr: &sattr3,
    ) -> Result<(SlateFsHandle, fattr3), nfsstat3> {
        let dir = self.ino_of(dirid)?;
        let attr = self
            .volume
            .symlink(&self.creds(), dir, linkname.0.as_ref(), symlink.0.as_ref())
            .await
            .map_err(map_err)?;
        Ok((self.handle_for(&attr), self.fattr(&attr)))
    }

    async fn link(
        &self,
        file: &SlateFsHandle,
        link_dir: &SlateFsHandle,
        link_name: &filename3<'_>,
    ) -> Result<fattr3, nfsstat3> {
        let ino = self.ino_of(file)?;
        let dir = self.ino_of(link_dir)?;
        let attr = self
            .volume
            .link(&self.creds(), ino, dir, link_name.0.as_ref())
            .await
            .map_err(map_err)?;
        Ok(self.fattr(&attr))
    }

    async fn mknod(
        &self,
        dir: &SlateFsHandle,
        name: &filename3<'_>,
        what: &mknoddata3,
    ) -> Result<(SlateFsHandle, fattr3), nfsstat3> {
        let dir = self.ino_of(dir)?;
        let (kind, rdev, sattr) = match what {
            mknoddata3::NF3CHR(dev) => (
                FileKind::CharDev,
                ((dev.spec.specdata1 as u64) << 32) | dev.spec.specdata2 as u64,
                &dev.dev_attributes,
            ),
            mknoddata3::NF3BLK(dev) => (
                FileKind::BlockDev,
                ((dev.spec.specdata1 as u64) << 32) | dev.spec.specdata2 as u64,
                &dev.dev_attributes,
            ),
            mknoddata3::NF3SOCK(sattr) => (FileKind::Socket, 0, sattr),
            mknoddata3::NF3FIFO(sattr) => (FileKind::Fifo, 0, sattr),
            mknoddata3::default => return Err(nfsstat3::NFS3ERR_BADTYPE),
        };
        let mode = to_setattrs(sattr).mode.unwrap_or(0o644);
        let attr = self
            .volume
            .mknod(&self.creds(), dir, name.0.as_ref(), mode, kind, rdev)
            .await
            .map_err(map_err)?;
        Ok((self.handle_for(&attr), self.fattr(&attr)))
    }

    async fn commit(&self, id: &SlateFsHandle, _offset: u64, _count: u32) -> Result<(), nfsstat3> {
        // COMMIT durability is volume-wide (DD-7): flush the WAL.
        let ino = self.ino_of(id)?;
        self.volume.fsync(&self.creds(), ino).await.map_err(map_err)
    }
}

/// Streaming READDIRPLUS in stable dirent-id cookie order (plan §5).
pub struct SlateDirIter {
    volume: Arc<Volume>,
    fh: FhCodec,
    creds: Credentials,
    dir: u64,
    cookie: u64,
    buffer: VecDeque<slatefs_core::vfs::DirEntry>,
    eof: bool,
}

const READDIR_PAGE: usize = 256;

impl ReadDirPlusIterator<SlateFsHandle> for SlateDirIter {
    async fn next(&mut self) -> NextResult<DirEntryPlus<SlateFsHandle>> {
        loop {
            if let Some(entry) = self.buffer.pop_front() {
                self.cookie = entry.cookie;
                // Attributes + handle per entry (READDIRPLUS). An entry
                // racing a concurrent unlink just gets skipped.
                match self.volume.getattr(&self.creds, entry.ino).await {
                    Ok(attr) => {
                        return NextResult::Ok(DirEntryPlus {
                            fileid: entry.ino,
                            name: filename3::from(entry.name.clone()),
                            cookie: entry.cookie,
                            name_attributes: Some(fattr_for(&self.volume, &attr)),
                            name_handle: Some(self.fh.make(attr.ino, attr.generation)),
                        });
                    }
                    Err(FsError::Stale) => continue,
                    Err(e) => return NextResult::Err(map_err(e)),
                }
            }
            if self.eof {
                return NextResult::Eof;
            }
            match self
                .volume
                .readdir(&self.creds, self.dir, self.cookie, READDIR_PAGE)
                .await
            {
                Ok(page) => {
                    self.eof = page.eof;
                    self.buffer.extend(page.entries);
                    if self.buffer.is_empty() && self.eof {
                        return NextResult::Eof;
                    }
                }
                Err(e) => return NextResult::Err(map_err(e)),
            }
        }
    }
}

fn fattr_for(volume: &Volume, attr: &FileAttr) -> fattr3 {
    fattr3 {
        type_: kind_to_ftype(attr.kind),
        mode: attr.mode,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        size: wire_size(attr),
        used: wire_used(attr),
        rdev: specdata3 {
            specdata1: (attr.rdev >> 32) as u32,
            specdata2: attr.rdev as u32,
        },
        fsid: volume.fsid(),
        fileid: attr.ino,
        atime: to_nfstime(attr.atime),
        mtime: to_nfstime(attr.mtime),
        ctime: to_nfstime(attr.ctime),
    }
}
