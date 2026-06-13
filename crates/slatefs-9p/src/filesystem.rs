//! Adapter from the SlateFS [`Vfs`] to rs9p's `Filesystem` trait
//! (plan §9.3). One instance serves one volume export; fids carry
//! `{ino, creds, open handle, walk provenance}` in interior-mutable aux
//! state (rs9p hands out `&FId` only).
//!
//! Identity model: 9P2000.L carries the user once, at `Tattach`
//! (`n_uname`); every op on fids derived from that attach runs as that
//! identity (Linux v9fs with `access=user` performs one attach per uid).
//! The export's bearer token (DD-10) rides in `uname`
//! (`mount -o uname=<token>`).

use std::sync::{Arc, Mutex};

use rs9p::error::Error as P9Error;
use rs9p::fcall::{
    Data, DirEntry as P9DirEntry, DirEntryData, FCall, Flock, GetAttrMask, Getlock, LockStatus,
    LockType, QId, QIdType, SetAttr, SetAttrMask, Stat, StatFs as P9StatFs, Time,
};
use rs9p::srv::{FId, Filesystem};
use slatefs_core::meta::inode::{FileKind, ROOT_INO, Timespec};
use slatefs_core::vfs::{
    Credentials, FileAttr, FsError, HandleId, OpenMode, SetAttrs, TimeSet, Vfs,
};
use slatefs_core::volume::Volume;

type P9Result = rs9p::Result<FCall>;

/// First real readdir offset; 1 and 2 are the synthesized "." and "..".
const DOT_OFFSET: u64 = 1;
const DOTDOT_OFFSET: u64 = 2;

const IOUNIT: u32 = 1024 * 1024;

// Linux open(2) flag bits used by v9fs in Tlopen/Tlcreate.
const O_ACCMODE: u32 = 0o3;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_TRUNC: u32 = 0o1000;

// AT_REMOVEDIR for Tunlinkat.
const AT_REMOVEDIR: u32 = 0x200;

/// Per-fid state. rs9p only ever hands us `&FId`, so mutation goes through
/// the mutex; contention is per-fid and negligible.
#[derive(Default)]
pub struct P9Fid(Mutex<FidState>);

#[derive(Default, Clone)]
struct FidState {
    ino: u64,
    uid: u32,
    gid: u32,
    /// Open file handle, when `lopen`/`lcreate` happened on this fid.
    handle: Option<HandleId>,
    /// Where this fid was walked from: (parent ino, entry name). Powers
    /// `Tremove`/`Trename`, which address files by fid alone.
    provenance: Option<(u64, Vec<u8>)>,
    /// Set when this fid is an xattr fid (from Txattrwalk/Txattrcreate).
    xattr: Option<XattrFid>,
}

#[derive(Clone)]
enum XattrFid {
    /// Readable buffer (xattrwalk): value bytes, or the name list.
    Read(Arc<Vec<u8>>),
    /// Pending write (xattrcreate): name + accumulated bytes, applied at
    /// clunk per the protocol.
    Write { name: Vec<u8>, buf: Vec<u8> },
}

impl FidState {
    fn creds(&self) -> Credentials {
        // 9P2000.L carries no per-op gid or supplementary groups — only the
        // attaching uid (`n_uname`). Linux v9fs under `access=user` enforces
        // DAC client-side with the caller's full credentials, so we mark the
        // connection trusted: bypass server-side *access* gates (we can't
        // redo them correctly) while keeping uid/gid for ownership. See
        // `Credentials::trusted`.
        Credentials::trusted(self.uid, self.gid)
    }
}

pub struct SlateFs9p {
    volume: Arc<Volume>,
    /// Bearer token required in `uname` at attach (DD-10). `None` ⇒ open
    /// export (dev / network-isolated deployments).
    token: Option<String>,
    /// aname values accepted at attach (e.g. "/t/v", plus "" and "/").
    export_name: String,
    /// Whether THIS connection presented the token. v9fs sends the `uname`
    /// mount option only on the first attach; `access=user` re-attaches
    /// carry an empty uname, so the token authenticates the connection.
    conn_authed: Arc<std::sync::atomic::AtomicBool>,
}

/// rs9p clones the filesystem once per accepted connection — give each
/// connection a fresh auth flag rather than sharing one.
impl Clone for SlateFs9p {
    fn clone(&self) -> Self {
        SlateFs9p {
            volume: Arc::clone(&self.volume),
            token: self.token.clone(),
            export_name: self.export_name.clone(),
            conn_authed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl SlateFs9p {
    pub fn new(volume: Arc<Volume>, export_name: String, token: Option<String>) -> SlateFs9p {
        SlateFs9p {
            volume,
            token,
            export_name,
            conn_authed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

fn errno(e: FsError) -> P9Error {
    use rs9p::error::errno::*;
    P9Error::No(match e {
        FsError::NotPermitted => EPERM,
        FsError::NotFound => ENOENT,
        FsError::Io => EIO,
        FsError::BadHandle => EBADF,
        FsError::WouldBlock => EAGAIN,
        FsError::AccessDenied => EACCES,
        FsError::Exists => EEXIST,
        FsError::CrossDevice => EXDEV,
        FsError::NotDir => ENOTDIR,
        FsError::IsDir => EISDIR,
        FsError::Invalid => EINVAL,
        FsError::FileTooBig => EFBIG,
        FsError::NoSpace => ENOSPC,
        FsError::TooManyLinks => EMLINK,
        FsError::NameTooLong => ENAMETOOLONG,
        FsError::NotEmpty => ENOTEMPTY,
        FsError::NoData => ENODATA,
        FsError::NotSupported => EOPNOTSUPP,
        FsError::Stale => ESTALE,
        FsError::QuotaExceeded => EDQUOT,
    })
}

fn qid_for(attr: &FileAttr) -> QId {
    let typ = match attr.kind {
        FileKind::Dir => QIdType::DIR,
        FileKind::Symlink => QIdType::SYMLINK,
        _ => QIdType::FILE,
    };
    QId {
        typ,
        version: attr.generation,
        path: attr.ino,
    }
}

fn mode_with_type(attr: &FileAttr) -> u32 {
    let type_bits = match attr.kind {
        FileKind::File => 0o100000,
        FileKind::Dir => 0o040000,
        FileKind::Symlink => 0o120000,
        FileKind::Fifo => 0o010000,
        FileKind::Socket => 0o140000,
        FileKind::CharDev => 0o020000,
        FileKind::BlockDev => 0o060000,
    };
    type_bits | attr.mode
}

fn d_type(kind: FileKind) -> u8 {
    match kind {
        FileKind::Fifo => 1,
        FileKind::CharDev => 2,
        FileKind::Dir => 4,
        FileKind::BlockDev => 6,
        FileKind::File => 8,
        FileKind::Symlink => 10,
        FileKind::Socket => 12,
    }
}

fn to_time(ts: Timespec) -> Time {
    Time {
        sec: ts.secs.max(0) as u64,
        nsec: ts.nanos as u64,
    }
}

/// Encode a device number for the 9P2000.L wire. SlateFS stores `rdev`
/// internally as `(major << 32) | minor` (matching the NFS specdata split);
/// Linux v9fs feeds `Rgetattr.st_rdev` through `new_decode_dev`, so the wire
/// must carry the kernel's `new_encode_dev` layout:
/// `(minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)`.
fn encode_rdev(rdev: u64) -> u64 {
    let major = rdev >> 32;
    let minor = rdev & 0xffff_ffff;
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

fn stat_for(attr: &FileAttr) -> Stat {
    Stat {
        mode: mode_with_type(attr),
        uid: attr.uid,
        gid: attr.gid,
        nlink: attr.nlink as u64,
        rdev: encode_rdev(attr.rdev),
        size: attr.size,
        blksize: 4096,
        blocks: attr.blocks,
        atime: to_time(attr.atime),
        mtime: to_time(attr.mtime),
        ctime: to_time(attr.ctime),
    }
}

impl SlateFs9p {
    fn state(fid: &FId<P9Fid>) -> FidState {
        fid.aux.0.lock().expect("fid state poisoned").clone()
    }

    fn set_state(fid: &FId<P9Fid>, state: FidState) {
        *fid.aux.0.lock().expect("fid state poisoned") = state;
    }

    async fn attr_of(&self, ino: u64, creds: &Credentials) -> Result<FileAttr, P9Error> {
        self.volume.getattr(creds, ino).await.map_err(errno)
    }
}

#[async_trait::async_trait]
impl Filesystem for SlateFs9p {
    type FId = P9Fid;

    async fn rattach(
        &self,
        fid: &FId<Self::FId>,
        _afid: Option<&FId<Self::FId>>,
        uname: &str,
        aname: &str,
        n_uname: u32,
    ) -> P9Result {
        use std::sync::atomic::Ordering;
        if let Some(expected) = &self.token {
            if uname == expected {
                self.conn_authed.store(true, Ordering::Relaxed);
            } else if !self.conn_authed.load(Ordering::Relaxed) {
                tracing::warn!(aname, "9p attach rejected: bad bearer token");
                return Err(P9Error::No(rs9p::error::errno::EACCES));
            }
        }
        let normalized = aname.trim_end_matches('/');
        if !(normalized.is_empty() || normalized == self.export_name) {
            tracing::warn!(aname, "9p attach rejected: unknown aname");
            return Err(P9Error::No(rs9p::error::errno::ENOENT));
        }

        // 9P2000.L: n_uname carries the numeric uid; gid arrives per-op
        // where it matters (create/mkdir/...). v9fs sends NONUNAME
        // (u32::MAX) on the initial mount attach ("no uid specified") —
        // treat that as the mount identity (root); per-user attaches
        // (access=user) carry real uids.
        const NONUNAME: u32 = u32::MAX;
        let uid = if n_uname == NONUNAME { 0 } else { n_uname };
        let state = FidState {
            ino: ROOT_INO,
            uid,
            gid: uid,
            ..FidState::default()
        };
        let attr = self.attr_of(ROOT_INO, &state.creds()).await?;
        Self::set_state(fid, state);
        Ok(FCall::RAttach {
            qid: qid_for(&attr),
        })
    }

    async fn rwalk(
        &self,
        fid: &FId<Self::FId>,
        newfid: &FId<Self::FId>,
        wnames: &[String],
    ) -> P9Result {
        let start = Self::state(fid);
        let creds = start.creds();
        let mut cur = start.ino;
        let mut provenance = start.provenance.clone();
        let mut wqids = Vec::with_capacity(wnames.len());

        for name in wnames {
            let attr = self
                .volume
                .lookup(&creds, cur, name.as_bytes())
                .await
                .map_err(|e| {
                    if wqids.is_empty() {
                        errno(e)
                    } else {
                        // Partial walks return the qids collected so far;
                        // rs9p surfaces this via a shortened RWalk.
                        errno(e)
                    }
                })?;
            provenance = Some((cur, name.as_bytes().to_vec()));
            cur = attr.ino;
            wqids.push(qid_for(&attr));
        }

        Self::set_state(
            newfid,
            FidState {
                ino: cur,
                uid: start.uid,
                gid: start.gid,
                handle: None,
                provenance,
                xattr: None,
            },
        );
        Ok(FCall::RWalk { wqids })
    }

    async fn rlopen(&self, fid: &FId<Self::FId>, flags: u32) -> P9Result {
        let mut state = Self::state(fid);
        let creds = state.creds();
        let mode = match flags & O_ACCMODE {
            O_WRONLY => OpenMode::Write,
            O_RDWR => OpenMode::ReadWrite,
            _ => OpenMode::Read,
        };
        let handle = self
            .volume
            .open(&creds, state.ino, mode)
            .await
            .map_err(errno)?;
        if flags & O_TRUNC != 0 && mode != OpenMode::Read {
            let attrs = SetAttrs {
                size: Some(0),
                ..SetAttrs::default()
            };
            self.volume
                .setattr(&creds, state.ino, attrs)
                .await
                .map_err(errno)?;
        }
        let attr = self.attr_of(state.ino, &creds).await?;
        state.handle = Some(handle);
        Self::set_state(fid, state);
        Ok(FCall::RlOpen {
            qid: qid_for(&attr),
            iounit: IOUNIT,
        })
    }

    async fn rlcreate(
        &self,
        fid: &FId<Self::FId>,
        name: &str,
        flags: u32,
        mode: u32,
        gid: u32,
    ) -> P9Result {
        let mut state = Self::state(fid);
        state.gid = gid;
        let creds = state.creds();
        let dir = state.ino;
        let attr = self
            .volume
            .create(&creds, dir, name.as_bytes(), mode & 0o7777, false)
            .await
            .map_err(errno)?;
        let open_mode = match flags & O_ACCMODE {
            O_WRONLY => OpenMode::Write,
            O_RDWR => OpenMode::ReadWrite,
            _ => OpenMode::Read,
        };
        let handle = self
            .volume
            .open(&creds, attr.ino, open_mode)
            .await
            .map_err(errno)?;
        // The fid now represents the created file.
        Self::set_state(
            fid,
            FidState {
                ino: attr.ino,
                uid: state.uid,
                gid: state.gid,
                handle: Some(handle),
                provenance: Some((dir, name.as_bytes().to_vec())),
                xattr: None,
            },
        );
        Ok(FCall::RlCreate {
            qid: qid_for(&attr),
            iounit: IOUNIT,
        })
    }

    async fn rread(&self, fid: &FId<Self::FId>, offset: u64, count: u32) -> P9Result {
        let state = Self::state(fid);
        if let Some(XattrFid::Read(buf)) = &state.xattr {
            let from = (offset as usize).min(buf.len());
            let to = (from + count as usize).min(buf.len());
            return Ok(FCall::RRead {
                data: Data(buf[from..to].to_vec()),
            });
        }
        let bytes = self
            .volume
            .read(&state.creds(), state.ino, offset, count)
            .await
            .map_err(errno)?;
        Ok(FCall::RRead {
            data: Data(bytes.to_vec()),
        })
    }

    async fn rwrite(&self, fid: &FId<Self::FId>, offset: u64, data: &Data) -> P9Result {
        // Xattr fids buffer writes synchronously; the guard never crosses
        // an await.
        let state = {
            let mut guard = fid.aux.0.lock().expect("fid state poisoned");
            if let Some(XattrFid::Write { buf, .. }) = &mut guard.xattr {
                let offset = offset as usize;
                if buf.len() < offset + data.0.len() {
                    buf.resize(offset + data.0.len(), 0);
                }
                buf[offset..offset + data.0.len()].copy_from_slice(&data.0);
                return Ok(FCall::RWrite {
                    count: data.0.len() as u32,
                });
            }
            guard.clone()
        };
        let count = self
            .volume
            .write(&state.creds(), state.ino, offset, &data.0)
            .await
            .map_err(errno)?;
        Ok(FCall::RWrite { count })
    }

    async fn rgetattr(&self, fid: &FId<Self::FId>, _req_mask: GetAttrMask) -> P9Result {
        let state = Self::state(fid);
        let attr = self.attr_of(state.ino, &state.creds()).await?;
        Ok(FCall::RGetAttr {
            valid: GetAttrMask::all(),
            qid: qid_for(&attr),
            stat: stat_for(&attr),
        })
    }

    async fn rsetattr(&self, fid: &FId<Self::FId>, valid: SetAttrMask, stat: &SetAttr) -> P9Result {
        let state = Self::state(fid);
        let creds = state.creds();
        let attrs = SetAttrs {
            mode: valid.contains(SetAttrMask::MODE).then_some(stat.mode),
            uid: valid.contains(SetAttrMask::UID).then_some(stat.uid),
            gid: valid.contains(SetAttrMask::GID).then_some(stat.gid),
            size: valid.contains(SetAttrMask::SIZE).then_some(stat.size),
            atime: valid.contains(SetAttrMask::ATIME).then(|| {
                if valid.contains(SetAttrMask::ATIME_SET) {
                    TimeSet::Time(Timespec {
                        secs: stat.atime.sec as i64,
                        nanos: stat.atime.nsec as u32,
                    })
                } else {
                    TimeSet::Now
                }
            }),
            mtime: valid.contains(SetAttrMask::MTIME).then(|| {
                if valid.contains(SetAttrMask::MTIME_SET) {
                    TimeSet::Time(Timespec {
                        secs: stat.mtime.sec as i64,
                        nanos: stat.mtime.nsec as u32,
                    })
                } else {
                    TimeSet::Now
                }
            }),
        };
        if !attrs.is_empty() {
            self.volume
                .setattr(&creds, state.ino, attrs)
                .await
                .map_err(errno)?;
        }
        Ok(FCall::RSetAttr)
    }

    async fn rreaddir(&self, fid: &FId<Self::FId>, offset: u64, count: u32) -> P9Result {
        let state = Self::state(fid);
        let creds = state.creds();
        let dir_attr = self.attr_of(state.ino, &creds).await?;

        let mut entries = DirEntryData::new();
        let mut used = 0u32;
        let mut push = |entry: P9DirEntry| -> bool {
            let size = entry.size();
            if used + size > count.saturating_sub(16) {
                return false;
            }
            used += size;
            entries.push(entry);
            true
        };

        // Synthesize "." and ".." at reserved offsets 1 and 2 (plan §5
        // reserves dirent ids 1/2 for exactly this).
        if offset < DOT_OFFSET
            && !push(P9DirEntry {
                qid: qid_for(&dir_attr),
                offset: DOT_OFFSET,
                typ: d_type(FileKind::Dir),
                name: ".".to_string(),
            })
        {
            return Ok(FCall::RReadDir { data: entries });
        }
        if offset < DOTDOT_OFFSET {
            let parent = self
                .volume
                .lookup(&creds, state.ino, b"..")
                .await
                .map_err(errno)?;
            if !push(P9DirEntry {
                qid: qid_for(&parent),
                offset: DOTDOT_OFFSET,
                typ: d_type(FileKind::Dir),
                name: "..".to_string(),
            }) {
                return Ok(FCall::RReadDir { data: entries });
            }
        }

        // Real entries: 9P offset == our dirent_id cookie (≥ 3 by design);
        // offsets ≤ 2 mean "start of the real entries".
        let mut next = if offset <= DOTDOT_OFFSET { 0 } else { offset };
        loop {
            let page = self
                .volume
                .readdir(&creds, state.ino, next, 128)
                .await
                .map_err(errno)?;
            for e in &page.entries {
                let kind = e.kind;
                let entry = P9DirEntry {
                    qid: QId {
                        typ: match kind {
                            FileKind::Dir => QIdType::DIR,
                            FileKind::Symlink => QIdType::SYMLINK,
                            _ => QIdType::FILE,
                        },
                        version: 0,
                        path: e.ino,
                    },
                    offset: e.cookie,
                    typ: d_type(kind),
                    name: String::from_utf8_lossy(&e.name).into_owned(),
                };
                if !push(entry) {
                    return Ok(FCall::RReadDir { data: entries });
                }
                next = e.cookie;
            }
            if page.eof {
                break;
            }
        }
        Ok(FCall::RReadDir { data: entries })
    }

    async fn rfsync(&self, fid: &FId<Self::FId>) -> P9Result {
        let state = Self::state(fid);
        self.volume
            .fsync(&state.creds(), state.ino)
            .await
            .map_err(errno)?;
        Ok(FCall::RFSync)
    }

    async fn rlock(&self, fid: &FId<Self::FId>, lock: &Flock) -> P9Result {
        let state = Self::state(fid);
        let Some(handle) = state.handle else {
            return Err(P9Error::No(rs9p::error::errno::EBADF));
        };
        let end = if lock.length == 0 {
            u64::MAX
        } else {
            lock.start.saturating_add(lock.length)
        };
        let status = if lock.typ == LockType::UNLOCK {
            self.volume
                .unlock(handle, lock.start, end)
                .await
                .map_err(errno)?;
            LockStatus::SUCCESS
        } else {
            let exclusive = lock.typ == LockType::WRLOCK;
            match self.volume.lock(handle, lock.start, end, exclusive).await {
                Ok(()) => LockStatus::SUCCESS,
                Err(FsError::WouldBlock) => LockStatus::BLOCKED,
                Err(e) => return Err(errno(e)),
            }
        };
        Ok(FCall::RLock { status })
    }

    async fn rgetlock(&self, fid: &FId<Self::FId>, lock: &Getlock) -> P9Result {
        let state = Self::state(fid);
        let Some(handle) = state.handle else {
            return Err(P9Error::No(rs9p::error::errno::EBADF));
        };
        let end = if lock.length == 0 {
            u64::MAX
        } else {
            lock.start.saturating_add(lock.length)
        };
        let exclusive = lock.typ == LockType::WRLOCK;
        let conflict = self
            .volume
            .testlock(handle, lock.start, end, exclusive)
            .await
            .map_err(errno)?;
        let flock = match conflict {
            Some((start, end, excl)) => Getlock {
                typ: if excl {
                    LockType::WRLOCK
                } else {
                    LockType::RDLOCK
                },
                start,
                length: if end == u64::MAX { 0 } else { end - start },
                proc_id: 0,
                client_id: String::new(),
            },
            None => Getlock {
                typ: LockType::UNLOCK,
                start: lock.start,
                length: lock.length,
                proc_id: lock.proc_id,
                client_id: lock.client_id.clone(),
            },
        };
        Ok(FCall::RGetLock { flock })
    }

    async fn rlink(&self, dfid: &FId<Self::FId>, fid: &FId<Self::FId>, name: &str) -> P9Result {
        let dir = Self::state(dfid);
        let file = Self::state(fid);
        self.volume
            .link(&dir.creds(), file.ino, dir.ino, name.as_bytes())
            .await
            .map_err(errno)?;
        Ok(FCall::RLink)
    }

    async fn rmkdir(&self, dfid: &FId<Self::FId>, name: &str, mode: u32, gid: u32) -> P9Result {
        let mut state = Self::state(dfid);
        state.gid = gid;
        let attr = self
            .volume
            .mkdir(&state.creds(), state.ino, name.as_bytes(), mode & 0o7777)
            .await
            .map_err(errno)?;
        Ok(FCall::RMkDir {
            qid: qid_for(&attr),
        })
    }

    async fn rrenameat(
        &self,
        olddir: &FId<Self::FId>,
        oldname: &str,
        newdir: &FId<Self::FId>,
        newname: &str,
    ) -> P9Result {
        let old = Self::state(olddir);
        let new = Self::state(newdir);
        self.volume
            .rename(
                &old.creds(),
                old.ino,
                oldname.as_bytes(),
                new.ino,
                newname.as_bytes(),
            )
            .await
            .map_err(errno)?;
        Ok(FCall::RRenameAt)
    }

    async fn runlinkat(&self, dfid: &FId<Self::FId>, name: &str, flags: u32) -> P9Result {
        let state = Self::state(dfid);
        let creds = state.creds();
        if flags & AT_REMOVEDIR != 0 {
            self.volume
                .rmdir(&creds, state.ino, name.as_bytes())
                .await
                .map_err(errno)?;
        } else {
            self.volume
                .unlink(&creds, state.ino, name.as_bytes())
                .await
                .map_err(errno)?;
        }
        Ok(FCall::RUnlinkAt)
    }

    async fn rrename(&self, fid: &FId<Self::FId>, dfid: &FId<Self::FId>, name: &str) -> P9Result {
        let state = Self::state(fid);
        let dst = Self::state(dfid);
        let Some((parent, old_name)) = state.provenance.clone() else {
            return Err(P9Error::No(rs9p::error::errno::EOPNOTSUPP));
        };
        self.volume
            .rename(&state.creds(), parent, &old_name, dst.ino, name.as_bytes())
            .await
            .map_err(errno)?;
        Self::set_state(
            fid,
            FidState {
                provenance: Some((dst.ino, name.as_bytes().to_vec())),
                ..Self::state(fid)
            },
        );
        Ok(FCall::RRename)
    }

    async fn rremove(&self, fid: &FId<Self::FId>) -> P9Result {
        let state = Self::state(fid);
        let creds = state.creds();
        let Some((parent, name)) = &state.provenance else {
            return Err(P9Error::No(rs9p::error::errno::EOPNOTSUPP));
        };
        let attr = self.attr_of(state.ino, &creds).await?;
        if let Some(handle) = state.handle {
            let _ = self.volume.close(handle).await;
        }
        if attr.kind == FileKind::Dir {
            self.volume
                .rmdir(&creds, *parent, name)
                .await
                .map_err(errno)?;
        } else {
            self.volume
                .unlink(&creds, *parent, name)
                .await
                .map_err(errno)?;
        }
        Ok(FCall::RRemove)
    }

    async fn rreadlink(&self, fid: &FId<Self::FId>) -> P9Result {
        let state = Self::state(fid);
        let target = self
            .volume
            .readlink(&state.creds(), state.ino)
            .await
            .map_err(errno)?;
        Ok(FCall::RReadLink {
            target: String::from_utf8_lossy(&target).into_owned(),
        })
    }

    async fn rsymlink(&self, fid: &FId<Self::FId>, name: &str, symtgt: &str, gid: u32) -> P9Result {
        let mut state = Self::state(fid);
        state.gid = gid;
        let attr = self
            .volume
            .symlink(
                &state.creds(),
                state.ino,
                name.as_bytes(),
                symtgt.as_bytes(),
            )
            .await
            .map_err(errno)?;
        Ok(FCall::RSymlink {
            qid: qid_for(&attr),
        })
    }

    async fn rmknod(
        &self,
        dfid: &FId<Self::FId>,
        name: &str,
        mode: u32,
        major: u32,
        minor: u32,
        gid: u32,
    ) -> P9Result {
        let mut state = Self::state(dfid);
        state.gid = gid;
        let kind = match mode & 0o170000 {
            0o010000 => FileKind::Fifo,
            0o140000 => FileKind::Socket,
            0o020000 => FileKind::CharDev,
            0o060000 => FileKind::BlockDev,
            _ => return Err(P9Error::No(rs9p::error::errno::EINVAL)),
        };
        let rdev = (u64::from(major) << 32) | u64::from(minor);
        let attr = self
            .volume
            .mknod(
                &state.creds(),
                state.ino,
                name.as_bytes(),
                mode & 0o7777,
                kind,
                rdev,
            )
            .await
            .map_err(errno)?;
        Ok(FCall::RMkNod {
            qid: qid_for(&attr),
        })
    }

    async fn rstatfs(&self, fid: &FId<Self::FId>) -> P9Result {
        let state = Self::state(fid);
        let s = self.volume.statfs(&state.creds()).await.map_err(errno)?;
        Ok(FCall::RStatFs {
            statfs: P9StatFs {
                typ: 0x0102_1997, // V9FS_MAGIC
                bsize: s.block_size,
                blocks: s.total_bytes / u64::from(s.block_size),
                bfree: s.free_bytes / u64::from(s.block_size),
                bavail: s.avail_bytes / u64::from(s.block_size),
                files: s.total_inodes,
                ffree: s.free_inodes,
                fsid: self.volume.fsid(),
                namelen: 255,
            },
        })
    }

    async fn rxattrwalk(
        &self,
        fid: &FId<Self::FId>,
        newfid: &FId<Self::FId>,
        name: &str,
    ) -> P9Result {
        let state = Self::state(fid);
        let creds = state.creds();
        let buf = if name.is_empty() {
            // Null-separated listing per listxattr(2) semantics.
            let names = self
                .volume
                .listxattr(&creds, state.ino)
                .await
                .map_err(errno)?;
            let mut out = Vec::new();
            for n in names {
                out.extend_from_slice(&n);
                out.push(0);
            }
            out
        } else {
            self.volume
                .getxattr(&creds, state.ino, name.as_bytes())
                .await
                .map_err(errno)?
        };
        let size = buf.len() as u64;
        Self::set_state(
            newfid,
            FidState {
                ino: state.ino,
                uid: state.uid,
                gid: state.gid,
                handle: None,
                provenance: None,
                xattr: Some(XattrFid::Read(Arc::new(buf))),
            },
        );
        Ok(FCall::RxAttrWalk { size })
    }

    async fn rxattrcreate(
        &self,
        fid: &FId<Self::FId>,
        name: &str,
        _attr_size: u64,
        _flags: u32,
    ) -> P9Result {
        let mut state = Self::state(fid);
        state.xattr = Some(XattrFid::Write {
            name: name.as_bytes().to_vec(),
            buf: Vec::new(),
        });
        Self::set_state(fid, state);
        Ok(FCall::RxAttrCreate)
    }

    async fn rclunk(&self, fid: &FId<Self::FId>) -> P9Result {
        let state = Self::state(fid);
        // Pending xattr write applies at clunk, per the protocol.
        if let Some(XattrFid::Write { name, buf }) = &state.xattr {
            self.volume
                .setxattr(&state.creds(), state.ino, name, buf)
                .await
                .map_err(errno)?;
        }
        if let Some(handle) = state.handle {
            let _ = self.volume.close(handle).await;
        }
        Ok(FCall::RClunk)
    }

    async fn rversion(&self, msize: u32, ver: &str) -> P9Result {
        // Only 9P2000.L; clients offering anything else get "unknown".
        let (msize, version) = if ver == "9P2000.L" {
            (msize.min(IOUNIT + 32), ver.to_string())
        } else {
            (msize, "unknown".to_string())
        };
        Ok(FCall::RVersion { msize, version })
    }

    async fn rflush(&self, _old: Option<&FCall>) -> P9Result {
        Ok(FCall::RFlush)
    }
}
