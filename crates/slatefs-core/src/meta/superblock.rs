//! Volume superblock — key `M`, written once by `mkfs` (plan §5). Immutable
//! after creation; readers verify it against the control-plane record.

use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::error::Result;
use crate::meta::{decode_versioned, encode_versioned};

pub const KEY_SUPERBLOCK: &[u8] = b"M";
pub const SUPERBLOCK_VERSION: u8 = 1;

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
}

impl Superblock {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_versioned(SUPERBLOCK_VERSION, self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Superblock> {
        decode_versioned(SUPERBLOCK_VERSION, bytes)
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
        };
        let mut bytes = sb.encode().unwrap();
        bytes[0] = 99;
        assert!(Superblock::decode(&bytes).is_err());
    }
}
