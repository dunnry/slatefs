//! Volume superblock — key `M`, written by `mkfs` (plan §5). Most fields are
//! immutable after creation; block-volume geometry can grow via resize.

use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::error::{Error, Result};
use crate::meta::encode_versioned;

pub const KEY_SUPERBLOCK: &[u8] = b"M";
pub const SUPERBLOCK_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeKind {
    #[default]
    Filesystem,
    Block {
        size_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Superblock {
    pub fsid: u64,
    pub cipher: Cipher,
    /// Content chunk size in bytes (DD-6). Fixed for the volume's lifetime.
    pub chunk_size: u32,
    /// Whether dirent names are AES-SIV-encrypted in keys (DD-3). Always true
    /// for volumes created by this codebase; the flag exists so a future
    /// `mkfs --no-name-enc` stays representable.
    pub name_enc: bool,
    /// Unix seconds.
    pub created_at: u64,
    /// Volume semantic kind. Missing in v1 superblocks, which decode as
    /// filesystem volumes for backward compatibility.
    pub kind: VolumeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SuperblockV1 {
    fsid: u64,
    cipher: Cipher,
    chunk_size: u32,
    name_enc: bool,
    created_at: u64,
}

impl Superblock {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_versioned(SUPERBLOCK_VERSION, self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Superblock> {
        match bytes.split_first() {
            Some((&1, rest)) => {
                let legacy: SuperblockV1 = postcard::from_bytes(rest)?;
                Ok(Superblock {
                    fsid: legacy.fsid,
                    cipher: legacy.cipher,
                    chunk_size: legacy.chunk_size,
                    name_enc: legacy.name_enc,
                    created_at: legacy.created_at,
                    kind: VolumeKind::Filesystem,
                })
            }
            Some((&SUPERBLOCK_VERSION, rest)) => Ok(postcard::from_bytes(rest)?),
            Some((&version, _)) => Err(Error::invalid(
                "record",
                format!("format version {version}, expected 1 or {SUPERBLOCK_VERSION}"),
            )),
            None => Err(Error::invalid("record", "empty value")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let sb = Superblock {
            fsid: 0xdead_beef_cafe_f00d,
            cipher: Cipher::XChaCha20Poly1305,
            chunk_size: 128 * 1024,
            name_enc: true,
            created_at: 1_780_000_000,
            kind: VolumeKind::Filesystem,
        };
        let bytes = sb.encode().unwrap();
        assert_eq!(bytes[0], SUPERBLOCK_VERSION);
        assert_eq!(Superblock::decode(&bytes).unwrap(), sb);
    }

    #[test]
    fn rejects_unknown_version() {
        let sb = Superblock {
            fsid: 1,
            cipher: Cipher::Aes256Gcm,
            chunk_size: 4096,
            name_enc: true,
            created_at: 0,
            kind: VolumeKind::Filesystem,
        };
        let mut bytes = sb.encode().unwrap();
        bytes[0] = 99;
        assert!(Superblock::decode(&bytes).is_err());
    }

    #[test]
    fn legacy_v1_decodes_as_filesystem() {
        let legacy = SuperblockV1 {
            fsid: 7,
            cipher: Cipher::Aes256Gcm,
            chunk_size: 4096,
            name_enc: true,
            created_at: 123,
        };
        let mut bytes = vec![1];
        bytes.extend(postcard::to_allocvec(&legacy).unwrap());
        let decoded = Superblock::decode(&bytes).unwrap();
        assert_eq!(decoded.kind, VolumeKind::Filesystem);
        assert_eq!(decoded.fsid, legacy.fsid);
    }
}
