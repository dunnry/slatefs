//! The `Vfs` trait (plan §9.1) — the single source of filesystem semantics.
//! Both protocol frontends translate to/from these calls; permission checks,
//! POSIX atomicity, and errno selection all live behind this trait, once.

use bytes::Bytes;

use crate::config::AtimeMode;
use crate::meta::inode::{FileKind, Timespec};

/// errno-style errors. Numeric values are Linux's; frontends map them to
/// NFS status / 9P errno on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    #[error("EPERM: operation not permitted")]
    NotPermitted,
    #[error("ENOENT: no such file or directory")]
    NotFound,
    #[error("EIO: I/O error")]
    Io,
    #[error("EBADF: bad file handle")]
    BadHandle,
    #[error("EAGAIN: lock unavailable")]
    WouldBlock,
    #[error("EACCES: permission denied")]
    AccessDenied,
    #[error("EEXIST: file exists")]
    Exists,
    #[error("EXDEV: cross-device link")]
    CrossDevice,
    #[error("ENOTDIR: not a directory")]
    NotDir,
    #[error("EISDIR: is a directory")]
    IsDir,
    #[error("EINVAL: invalid argument")]
    Invalid,
    #[error("EFBIG: file too large")]
    FileTooBig,
    #[error("ENOSPC: no space left on device")]
    NoSpace,
    #[error("EMLINK: too many links")]
    TooManyLinks,
    #[error("ENAMETOOLONG: file name too long")]
    NameTooLong,
    #[error("ENOTEMPTY: directory not empty")]
    NotEmpty,
    #[error("ENODATA: no such attribute")]
    NoData,
    #[error("ENOTSUP: operation not supported")]
    NotSupported,
    #[error("ESTALE: stale file handle")]
    Stale,
    #[error("EDQUOT: disk quota exceeded")]
    QuotaExceeded,
    #[error("EROFS: read-only filesystem")]
    ReadOnly,
}

impl FsError {
    pub fn errno(self) -> i32 {
        use FsError::*;
        match self {
            NotPermitted => 1,
            NotFound => 2,
            Io => 5,
            BadHandle => 9,
            WouldBlock => 11,
            AccessDenied => 13,
            Exists => 17,
            CrossDevice => 18,
            NotDir => 20,
            IsDir => 21,
            Invalid => 22,
            FileTooBig => 27,
            NoSpace => 28,
            TooManyLinks => 31,
            NameTooLong => 36,
            NotEmpty => 39,
            NoData => 61,
            NotSupported => 95,
            Stale => 116,
            QuotaExceeded => 122,
            ReadOnly => 30,
        }
    }
}

/// Internal errors collapse to EIO at the protocol boundary; details are
/// logged server-side, never leaked to clients.
impl From<crate::error::Error> for FsError {
    fn from(e: crate::error::Error) -> FsError {
        tracing::error!("vfs internal error: {e}");
        FsError::Io
    }
}

impl From<slatedb::Error> for FsError {
    fn from(e: slatedb::Error) -> FsError {
        tracing::error!("vfs storage error: {e}");
        FsError::Io
    }
}

pub type FsResult<T> = Result<T, FsError>;

/// AUTH_SYS-style identity (plan §9.1): uid/gid assertions plus supplementary
/// groups (NFSv3 carries at most 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    /// The frontend vouches that the client already enforced DAC and we
    /// lack the credentials to redo it correctly. Set by the 9P frontend:
    /// 9P2000.L carries no per-op gid/supplementary groups (only the
    /// attaching `n_uname`), and Linux v9fs under `access=user` performs
    /// full permission checks client-side. We therefore bypass *access*
    /// gates (read/write/exec, owner-only chmod/chown/utimes, sticky) while
    /// keeping the real `uid`/`gid` for ownership attribution. This never
    /// confers actual-root semantics: rules keyed on the caller being
    /// genuinely privileged (setuid/setgid clearing on write or gid-chown,
    /// device-node creation) still test `is_root()`, not this flag.
    pub trusted: bool,
}

impl Credentials {
    pub fn root() -> Credentials {
        Credentials {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
            trusted: false,
        }
    }

    pub fn user(uid: u32, gid: u32) -> Credentials {
        Credentials {
            uid,
            gid,
            groups: Vec::new(),
            trusted: false,
        }
    }

    /// A caller whose DAC the frontend has already enforced (sets the
    /// `trusted` flag). `uid`/`gid` are retained for ownership.
    pub fn trusted(uid: u32, gid: u32) -> Credentials {
        Credentials {
            uid,
            gid,
            groups: Vec::new(),
            trusted: true,
        }
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// May bypass DAC *access* gates — genuine root, or a frontend-trusted
    /// connection. Not a claim of root identity (see the `trusted` field).
    pub fn is_privileged(&self) -> bool {
        self.uid == 0 || self.trusted
    }

    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// Stat data returned to frontends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAttr {
    pub ino: u64,
    pub kind: FileKind,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub rdev: u64,
    pub generation: u32,
    /// 512-byte units, from billed (allocated) bytes — sparse-aware.
    pub blocks: u64,
}

/// Set-time argument: client-supplied time or server "now" (utimensat
/// UTIME_NOW), which have different permission rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSet {
    Now,
    Time(Timespec),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetAttrs {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<TimeSet>,
    pub mtime: Option<TimeSet>,
}

impl SetAttrs {
    pub fn is_empty(&self) -> bool {
        *self == SetAttrs::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: u64,
    pub kind: FileKind,
    /// Opaque resume cookie: pass back to `readdir` to continue after this
    /// entry. Stable across modifications (plan §5).
    pub cookie: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadDir {
    pub entries: Vec<DirEntry>,
    pub eof: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFs {
    pub block_size: u32,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryPermissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    pub can_rename: bool,
}

/// Open-handle id from [`Vfs::open`]; required for orphan semantics (an
/// unlinked-but-open file keeps its data until last close).
pub type HandleId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
}

#[async_trait::async_trait]
pub trait Vfs: Send + Sync {
    fn fsid(&self) -> u64;
    fn chunk_size(&self) -> u64;
    fn read_only(&self) -> bool {
        false
    }

    /// Evaluate effective access using the implementation's authoritative DAC
    /// and sticky-directory rules. Parent-dependent flags are false for root.
    async fn permissions(
        &self,
        creds: &Credentials,
        ino: u64,
        parent: Option<(u64, &[u8])>,
    ) -> FsResult<EntryPermissions>;

    async fn lookup(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<FileAttr>;
    async fn getattr(&self, creds: &Credentials, ino: u64) -> FsResult<FileAttr>;
    async fn setattr(&self, creds: &Credentials, ino: u64, attrs: SetAttrs) -> FsResult<FileAttr>;

    async fn read(&self, creds: &Credentials, ino: u64, offset: u64, len: u32) -> FsResult<Bytes>;
    /// Read with an export-scoped atime policy. Implementations that can
    /// update atime should override this; read-only implementations may
    /// ignore the policy and perform a plain read.
    async fn read_with_atime_policy(
        &self,
        creds: &Credentials,
        ino: u64,
        offset: u64,
        len: u32,
        policy: AtimeMode,
    ) -> FsResult<Bytes> {
        let _ = policy;
        self.read(creds, ino, offset, len).await
    }
    async fn write(&self, creds: &Credentials, ino: u64, offset: u64, data: &[u8])
    -> FsResult<u32>;

    async fn create(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        mode: u32,
        exclusive: bool,
    ) -> FsResult<FileAttr>;
    async fn mkdir(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        mode: u32,
    ) -> FsResult<FileAttr>;
    async fn mknod(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        mode: u32,
        kind: FileKind,
        rdev: u64,
    ) -> FsResult<FileAttr>;
    async fn symlink(
        &self,
        creds: &Credentials,
        parent: u64,
        name: &[u8],
        target: &[u8],
    ) -> FsResult<FileAttr>;
    async fn readlink(&self, creds: &Credentials, ino: u64) -> FsResult<Vec<u8>>;
    async fn link(
        &self,
        creds: &Credentials,
        ino: u64,
        new_parent: u64,
        new_name: &[u8],
    ) -> FsResult<FileAttr>;

    async fn unlink(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<()>;
    async fn rmdir(&self, creds: &Credentials, parent: u64, name: &[u8]) -> FsResult<()>;
    async fn rename(
        &self,
        creds: &Credentials,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
    ) -> FsResult<()>;

    /// `cookie` 0 starts from the beginning; otherwise resumes after the
    /// entry that returned it. Frontends synthesize "." / ".." (cookies 1/2
    /// are reserved for them and never returned here).
    async fn readdir(
        &self,
        creds: &Credentials,
        parent: u64,
        cookie: u64,
        max_entries: usize,
    ) -> FsResult<ReadDir>;

    async fn getxattr(&self, creds: &Credentials, ino: u64, name: &[u8]) -> FsResult<Vec<u8>>;
    async fn setxattr(
        &self,
        creds: &Credentials,
        ino: u64,
        name: &[u8],
        value: &[u8],
    ) -> FsResult<()>;
    async fn listxattr(&self, creds: &Credentials, ino: u64) -> FsResult<Vec<Vec<u8>>>;
    async fn removexattr(&self, creds: &Credentials, ino: u64, name: &[u8]) -> FsResult<()>;

    async fn statfs(&self, creds: &Credentials) -> FsResult<StatFs>;

    /// Durability point (DD-7): returns only after everything acknowledged so
    /// far is durable in the object store.
    async fn fsync(&self, creds: &Credentials, ino: u64) -> FsResult<()>;

    async fn open(&self, creds: &Credentials, ino: u64, mode: OpenMode) -> FsResult<HandleId>;
    /// Releases the handle's advisory locks; on the last handle of an
    /// unlinked file, reaps its data.
    async fn close(&self, handle: HandleId) -> FsResult<()>;

    /// Advisory byte-range lock, non-blocking (9P `Tlock` semantics — the
    /// client retries). `end` is exclusive; `u64::MAX` means to-EOF. The
    /// handle is the lock owner. `EAGAIN` on conflict.
    async fn lock(&self, handle: HandleId, start: u64, end: u64, exclusive: bool) -> FsResult<()>;
    async fn unlock(&self, handle: HandleId, start: u64, end: u64) -> FsResult<()>;
    /// First conflicting lock for the probe, as `(start, end, exclusive)`
    /// (9P `Tgetlock`).
    async fn testlock(
        &self,
        handle: HandleId,
        start: u64,
        end: u64,
        exclusive: bool,
    ) -> FsResult<Option<(u64, u64, bool)>>;
}
