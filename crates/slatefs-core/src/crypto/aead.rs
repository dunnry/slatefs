//! AEAD seal/open used by both the block transformer and key wrapping.
//!
//! Blob layout (plan §7): `nonce ‖ ciphertext ‖ tag` — nonce length per
//! [`Cipher`], tag appended by the AEAD. The `aad` argument binds a blob to
//! its context (e.g. a wrapped key to its tenant/volume), so a blob copied
//! into another record fails to open.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};

use super::{Cipher, Secret32};
use crate::error::{Error, Result};

pub fn seal(cipher: Cipher, key: &Secret32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    match cipher {
        Cipher::Aes256Gcm => {
            let aead = aes_gcm::Aes256Gcm::new(key.expose().into());
            let nonce = aes_gcm::Aes256Gcm::generate_nonce(&mut OsRng);
            let ct = aead
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Error::crypto("AES-256-GCM seal failed"))?;
            Ok([nonce.as_slice(), &ct].concat())
        }
        Cipher::XChaCha20Poly1305 => {
            let aead = chacha20poly1305::XChaCha20Poly1305::new(key.expose().into());
            let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ct = aead
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Error::crypto("XChaCha20-Poly1305 seal failed"))?;
            Ok([nonce.as_slice(), &ct].concat())
        }
    }
}

pub fn open(cipher: Cipher, key: &Secret32, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let nonce_len = cipher.nonce_len();
    // 16-byte Poly1305/GCM tag must also be present.
    if blob.len() < nonce_len + 16 {
        return Err(Error::crypto(format!(
            "sealed blob too short: {} bytes for {}",
            blob.len(),
            cipher
        )));
    }
    let (nonce, ct) = blob.split_at(nonce_len);
    let fail = || {
        Error::crypto(format!(
            "{cipher} open failed: wrong key, AAD, or tampered data"
        ))
    };
    match cipher {
        Cipher::Aes256Gcm => {
            let aead = aes_gcm::Aes256Gcm::new(key.expose().into());
            aead.decrypt(nonce.into(), Payload { msg: ct, aad })
                .map_err(|_| fail())
        }
        Cipher::XChaCha20Poly1305 => {
            let aead = chacha20poly1305::XChaCha20Poly1305::new(key.expose().into());
            aead.decrypt(nonce.into(), Payload { msg: ct, aad })
                .map_err(|_| fail())
        }
    }
}

/// Wrap a child key under a key-encryption key. Always AES-256-GCM: wrapping
/// happens on the control plane, not the data path, so hardware-acceleration
/// concerns don't apply; one fixed cipher keeps wrapped blobs self-describing.
pub fn wrap_key(kek: &Secret32, context: &str, child: &Secret32) -> Result<Vec<u8>> {
    seal(Cipher::Aes256Gcm, kek, context.as_bytes(), child.expose())
}

pub fn unwrap_key(kek: &Secret32, context: &str, blob: &[u8]) -> Result<Secret32> {
    let bytes = open(Cipher::Aes256Gcm, kek, context.as_bytes(), blob)?;
    Secret32::try_from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_both_ciphers() {
        for cipher in [Cipher::Aes256Gcm, Cipher::XChaCha20Poly1305] {
            let key = Secret32::generate();
            let blob = seal(cipher, &key, b"ctx", b"hello world").unwrap();
            assert!(!blob.windows(11).any(|w| w == b"hello world"));
            let opened = open(cipher, &key, b"ctx", &blob).unwrap();
            assert_eq!(opened, b"hello world");
        }
    }

    #[test]
    fn open_fails_closed_on_wrong_key() {
        for cipher in [Cipher::Aes256Gcm, Cipher::XChaCha20Poly1305] {
            let blob = seal(cipher, &Secret32::generate(), b"ctx", b"secret").unwrap();
            let err = open(cipher, &Secret32::generate(), b"ctx", &blob).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        }
    }

    #[test]
    fn open_fails_closed_on_wrong_aad() {
        let key = Secret32::generate();
        let blob = seal(Cipher::Aes256Gcm, &key, b"tenant-a", b"secret").unwrap();
        assert!(open(Cipher::Aes256Gcm, &key, b"tenant-b", &blob).is_err());
    }

    #[test]
    fn open_fails_closed_on_tamper() {
        let key = Secret32::generate();
        let mut blob = seal(Cipher::XChaCha20Poly1305, &key, b"", b"secret").unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0x01;
        assert!(open(Cipher::XChaCha20Poly1305, &key, b"", &blob).is_err());
    }

    #[test]
    fn open_fails_closed_on_truncation() {
        let key = Secret32::generate();
        let blob = seal(Cipher::Aes256Gcm, &key, b"", b"secret").unwrap();
        assert!(open(Cipher::Aes256Gcm, &key, b"", &blob[..10]).is_err());
        assert!(open(Cipher::Aes256Gcm, &key, b"", &blob[..blob.len() - 1]).is_err());
    }

    #[test]
    fn wrap_unwrap_key_roundtrip_and_context_binding() {
        let kek = Secret32::generate();
        let dek = Secret32::generate();
        let blob = wrap_key(&kek, "slatefs/volume-dek/v1/t1/v1", &dek).unwrap();
        let unwrapped = unwrap_key(&kek, "slatefs/volume-dek/v1/t1/v1", &blob).unwrap();
        assert_eq!(unwrapped.expose(), dek.expose());
        // Same blob presented for a different volume must fail.
        assert!(unwrap_key(&kek, "slatefs/volume-dek/v1/t1/v2", &blob).is_err());
        // Wrong KEK must fail.
        assert!(unwrap_key(&Secret32::generate(), "slatefs/volume-dek/v1/t1/v1", &blob).is_err());
    }
}
