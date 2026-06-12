//! Deterministic per-directory filename encryption (DD-3, fscrypt-style).
//!
//! Dirent keys embed names, and SlateDB keys surface in manifests and
//! index/filter structures that the block transformer does not cover — so
//! names are AES-SIV-encrypted *in the key*. Deterministic encryption keeps
//! `lookup()` a point get; the per-directory subkey
//! `HKDF(volume_DEK, "slatefs/dirname/v1" ‖ parent_ino)` stops equal names in
//! different directories from correlating.

use aes_siv::KeyInit;
use aes_siv::siv::Aes256Siv;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::Secret32;
use crate::error::{Error, Result};

const DIR_KEY_INFO: &[u8] = b"slatefs/dirname/v1";

/// AES-SIV adds a 16-byte synthetic IV; max ciphertext length follows from
/// the 255-byte name limit.
pub const NAME_OVERHEAD: usize = 16;

pub struct NameCodec {
    dek: Secret32,
}

impl NameCodec {
    pub fn new(dek: Secret32) -> NameCodec {
        NameCodec { dek }
    }

    /// 64-byte (two AES-256 keys) per-directory SIV key.
    fn dir_key(&self, parent_ino: u64) -> [u8; 64] {
        let hk = Hkdf::<Sha256>::new(None, self.dek.expose());
        let mut okm = [0u8; 64];
        let mut info = [0u8; DIR_KEY_INFO.len() + 8];
        info[..DIR_KEY_INFO.len()].copy_from_slice(DIR_KEY_INFO);
        info[DIR_KEY_INFO.len()..].copy_from_slice(&parent_ino.to_be_bytes());
        hk.expand(&info, &mut okm)
            .expect("64 bytes is a valid HKDF-SHA256 output length");
        okm
    }

    /// Deterministic: same (directory, name) always yields the same bytes,
    /// so exact-match lookup works as a point get.
    pub fn seal_name(&self, parent_ino: u64, name: &[u8]) -> Result<Vec<u8>> {
        let mut key = self.dir_key(parent_ino);
        let result = Aes256Siv::new_from_slice(&key)
            .map_err(|_| Error::crypto("bad SIV key length"))
            .and_then(|mut siv| {
                siv.encrypt([&[]; 0], name)
                    .map_err(|_| Error::crypto("SIV name encrypt failed"))
            });
        key.zeroize();
        result
    }

    pub fn open_name(&self, parent_ino: u64, enc_name: &[u8]) -> Result<Vec<u8>> {
        let mut key = self.dir_key(parent_ino);
        let result = Aes256Siv::new_from_slice(&key)
            .map_err(|_| Error::crypto("bad SIV key length"))
            .and_then(|mut siv| {
                siv.decrypt([&[]; 0], enc_name).map_err(|_| {
                    Error::crypto("SIV name decrypt failed: wrong key or tampered dirent key")
                })
            });
        key.zeroize();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_within_directory() {
        let codec = NameCodec::new(Secret32::from_bytes([3; 32]));
        let a = codec.seal_name(10, b"file.txt").unwrap();
        let b = codec.seal_name(10, b"file.txt").unwrap();
        assert_eq!(a, b, "lookup requires deterministic encryption");
        assert_eq!(codec.open_name(10, &a).unwrap(), b"file.txt");
    }

    #[test]
    fn same_name_differs_across_directories_and_keys() {
        let codec = NameCodec::new(Secret32::from_bytes([3; 32]));
        let in_dir10 = codec.seal_name(10, b"file.txt").unwrap();
        let in_dir11 = codec.seal_name(11, b"file.txt").unwrap();
        assert_ne!(in_dir10, in_dir11, "directory correlation leak");

        let other = NameCodec::new(Secret32::from_bytes([4; 32]));
        assert_ne!(other.seal_name(10, b"file.txt").unwrap(), in_dir10);
        assert!(other.open_name(10, &in_dir10).is_err(), "must fail closed");
    }

    #[test]
    fn ciphertext_hides_name_and_roundtrips_max_len() {
        let codec = NameCodec::new(Secret32::generate());
        let name = vec![b'n'; 255];
        let enc = codec.seal_name(1, &name).unwrap();
        assert_eq!(enc.len(), 255 + NAME_OVERHEAD);
        assert!(!enc.windows(8).any(|w| w == &name[..8]));
        assert_eq!(codec.open_name(1, &enc).unwrap(), name);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let codec = NameCodec::new(Secret32::generate());
        let mut enc = codec.seal_name(1, b"name").unwrap();
        enc[0] ^= 1;
        assert!(codec.open_name(1, &enc).is_err());
    }
}
