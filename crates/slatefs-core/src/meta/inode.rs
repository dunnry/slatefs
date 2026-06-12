//! Inode record (plan §5): key `i/<ino>`, postcard value with leading format
//! version.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::meta::{decode_versioned, encode_versioned};

pub const ROOT_INO: u64 = 1;
pub const INODE_VERSION: u8 = 1;

/// Names are bytes on the wire (NFS/9P) and on disk; only '/' and NUL are
/// forbidden. Maximum length per plan §10.
pub const MAX_NAME_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Fifo,
    Socket,
    CharDev,
    BlockDev,
}

impl FileKind {
    pub fn is_dir(self) -> bool {
        self == FileKind::Dir
    }
}

/// Nanosecond timestamps (plan §10): i64 seconds + nanos, tolerating
/// pre-epoch values NFS clients can legally set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timespec {
    pub secs: i64,
    pub nanos: u32,
}

impl Timespec {
    pub fn now() -> Timespec {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Timespec {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => Timespec {
                secs: -(e.duration().as_secs() as i64),
                nanos: e.duration().subsec_nanos(),
            },
        }
    }

    pub const ZERO: Timespec = Timespec { secs: 0, nanos: 0 };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inode {
    pub kind: FileKind,
    /// Permission + setuid/setgid/sticky bits (low 12 bits of st_mode).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    /// Device number for CharDev/BlockDev, encoded as (major << 32) | minor.
    pub rdev: u64,
    /// Bumped on inode-number reuse so stale NFS handles get ESTALE (plan §5).
    pub generation: u32,
    pub flags: u32,
    /// Directories only: next dirent_id to assign (readdir cookie space,
    /// monotonic, never reused). Kept in the inode because every dirent
    /// mutation rewrites the inode anyway (mtime). Starts at
    /// [`FIRST_DIRENT_ID`]; 1 and 2 stay free for frontends' synthetic
    /// "." / ".." entries.
    pub next_dirent_id: u64,
    /// Σ billed chunk bytes for this file (quota accounting rule, plan §12),
    /// maintained in the same batch as every write/truncate. Gives st_blocks
    /// without a chunk scan; fsck cross-checks it.
    pub billed_bytes: u64,
    /// Directories only: the containing directory (root points at itself).
    /// Resolves `..` and anchors the rename ancestor-cycle walk (plan §10).
    /// Directories can't be hardlinked, so a single parent is exact.
    pub parent_dir: u64,
}

/// First real dirent id (cookies 1/2 reserved for "." and "..").
pub const FIRST_DIRENT_ID: u64 = 3;

impl Inode {
    /// Fresh inode with both link/time bookkeeping initialized for `kind`.
    pub fn new(kind: FileKind, mode: u32, uid: u32, gid: u32, now: Timespec) -> Inode {
        Inode {
            kind,
            mode: mode & 0o7777,
            uid,
            gid,
            nlink: if kind.is_dir() { 2 } else { 1 },
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: 0,
            generation: 0,
            flags: 0,
            next_dirent_id: FIRST_DIRENT_ID,
            billed_bytes: 0,
            parent_dir: 0,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_versioned(INODE_VERSION, self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Inode> {
        decode_versioned(INODE_VERSION, bytes)
    }

    pub fn touch_mtime(&mut self, now: Timespec) {
        self.mtime = now;
        self.ctime = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut ino = Inode::new(FileKind::Dir, 0o40755, 1000, 1000, Timespec::now());
        ino.mode = 0o755; // mask applied in new(); set explicitly for compare
        let bytes = ino.encode().unwrap();
        assert_eq!(Inode::decode(&bytes).unwrap(), ino);
        assert_eq!(ino.nlink, 2);
        assert_eq!(ino.next_dirent_id, FIRST_DIRENT_ID);
    }

    #[test]
    fn mode_is_masked_to_permission_bits() {
        let ino = Inode::new(FileKind::File, 0o100644, 0, 0, Timespec::ZERO);
        assert_eq!(ino.mode, 0o644);
        assert_eq!(ino.nlink, 1);
    }
}
