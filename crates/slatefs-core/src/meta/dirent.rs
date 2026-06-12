//! Dirent records (plan §5).
//!
//! Two records per directory entry, written in the same batch:
//! - `d/<parent>/<enc_name>` → [`Dirent`] — point lookup by (parent, name);
//!   the plaintext name lives in the (block-encrypted) value.
//! - `e/<parent>/<dirent_id>` → [`DirentIdx`] — readdir iteration in stable
//!   cookie order. Carries `enc_name` (decryptable, DD-3) plus denormalized
//!   `child_ino`/`kind` so readdir is a single scan.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::meta::inode::FileKind;
use crate::meta::{decode_versioned, encode_versioned};

pub const DIRENT_VERSION: u8 = 1;
pub const DIRENT_IDX_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dirent {
    /// Plaintext name (bytes; not necessarily UTF-8).
    pub name: Vec<u8>,
    pub child_ino: u64,
    pub kind: FileKind,
    /// Readdir cookie; monotonic per directory, never reused.
    pub dirent_id: u64,
}

impl Dirent {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_versioned(DIRENT_VERSION, self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Dirent> {
        decode_versioned(DIRENT_VERSION, bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirentIdx {
    /// AES-SIV-encrypted name; readdir decrypts it with the directory key.
    pub enc_name: Vec<u8>,
    pub child_ino: u64,
    pub kind: FileKind,
}

impl DirentIdx {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_versioned(DIRENT_IDX_VERSION, self)
    }

    pub fn decode(bytes: &[u8]) -> Result<DirentIdx> {
        decode_versioned(DIRENT_IDX_VERSION, bytes)
    }
}

/// Orphan record (`o/<ino>`): nlink hit zero but data may still need reaping
/// (open handles, or batched chunk deletion in flight). Carries what the
/// reaper needs after the inode record is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Orphan {
    pub size: u64,
    pub kind: FileKind,
}

pub const ORPHAN_VERSION: u8 = 1;

impl Orphan {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_versioned(ORPHAN_VERSION, self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Orphan> {
        decode_versioned(ORPHAN_VERSION, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let d = Dirent {
            name: b"hello.txt".to_vec(),
            child_ino: 42,
            kind: FileKind::File,
            dirent_id: 7,
        };
        assert_eq!(Dirent::decode(&d.encode().unwrap()).unwrap(), d);

        let e = DirentIdx {
            enc_name: vec![0xde, 0xad, 0xbe, 0xef],
            child_ino: 42,
            kind: FileKind::File,
        };
        assert_eq!(DirentIdx::decode(&e.encode().unwrap()).unwrap(), e);

        let o = Orphan {
            size: 1 << 30,
            kind: FileKind::File,
        };
        assert_eq!(Orphan::decode(&o.encode().unwrap()).unwrap(), o);
    }
}
