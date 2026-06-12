//! Encryption-at-rest building blocks (plan §7, DD-2/DD-3/DD-8).
//!
//! Hierarchy: master KEK (KMS) → tenant KEK → volume DEK. The volume DEK
//! drives the [`transformer::SlateBlockTransformer`], which AEAD-seals every
//! SST/WAL block after SlateDB's compression. Everything here fails closed:
//! a failed unwrap or AEAD open is an error, never a passthrough.

pub mod aead;
pub mod kms;
pub mod names;
pub mod transformer;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;

/// 32 bytes of key material, zeroized on drop and redacted in Debug output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; KEY_LEN]);

impl Secret32 {
    /// Generate a fresh random key from the OS RNG.
    pub fn generate() -> Secret32 {
        use aes_gcm::aead::rand_core::RngCore;
        let mut bytes = [0u8; KEY_LEN];
        aes_gcm::aead::OsRng.fill_bytes(&mut bytes);
        Secret32(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Secret32 {
        Secret32(bytes)
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Secret32> {
        let bytes: [u8; KEY_LEN] = slice.try_into().map_err(|_| {
            Error::crypto(format!("key must be {KEY_LEN} bytes, got {}", slice.len()))
        })?;
        Ok(Secret32(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Random u64 from the OS RNG (fsid generation and the like — not key
/// material, but no reason to use a weaker source).
pub fn random_u64() -> u64 {
    use aes_gcm::aead::rand_core::RngCore;
    aes_gcm::aead::OsRng.next_u64()
}

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}

/// AEAD used by a volume's block transformer (DD-8). Recorded in the volume
/// format (control record + superblock); never reordered — postcard encodes
/// the variant index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cipher {
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl Cipher {
    /// AES-256-GCM where AES hardware acceleration is available, otherwise
    /// XChaCha20-Poly1305 (DD-8).
    pub fn auto_select() -> Cipher {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("aes") {
                return Cipher::Aes256Gcm;
            }
            Cipher::XChaCha20Poly1305
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                return Cipher::Aes256Gcm;
            }
            Cipher::XChaCha20Poly1305
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Cipher::XChaCha20Poly1305
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Cipher::Aes256Gcm => 12,
            Cipher::XChaCha20Poly1305 => 24,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "aes-256-gcm",
            Cipher::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }
}

impl std::fmt::Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
