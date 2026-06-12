//! NFS file handles (plan §5): `{fsid, ino, generation}` plus a truncated
//! HMAC-SHA256 under a deployment-wide server key, so a client on one export
//! can't forge a handle into another tenant's volume. 37 bytes, well inside
//! the 56 the server library leaves us; handles survive daemon restarts
//! because both the HMAC key and the listener generation (volume fsid) are
//! stable.

use hmac::{Hmac, Mac};
use nfs3_server::vfs::FileHandle;
use sha2::Sha256;
use slatefs_core::crypto::Secret32;

const VERSION: u8 = 1;
const MAC_LEN: usize = 16;
/// version(1) + fsid(8) + ino(8) + generation(4) + mac(16)
pub const FH_LEN: usize = 1 + 8 + 8 + 4 + MAC_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SlateFsHandle {
    raw: [u8; FH_LEN],
}

impl SlateFsHandle {
    pub fn ino(&self) -> u64 {
        u64::from_be_bytes(self.raw[9..17].try_into().unwrap())
    }

    pub fn fsid(&self) -> u64 {
        u64::from_be_bytes(self.raw[1..9].try_into().unwrap())
    }

    pub fn generation(&self) -> u32 {
        u32::from_be_bytes(self.raw[17..21].try_into().unwrap())
    }
}

impl std::fmt::Debug for SlateFsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlateFsHandle")
            .field("fsid", &format_args!("{:016x}", self.fsid()))
            .field("ino", &self.ino())
            .field("generation", &self.generation())
            .finish()
    }
}

impl FileHandle for SlateFsHandle {
    fn len(&self) -> usize {
        FH_LEN
    }

    fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Parses shape only — MAC and fsid are checked by
    /// [`FhCodec::verify`], which has the key.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let raw: [u8; FH_LEN] = bytes.try_into().ok()?;
        (raw[0] == VERSION).then_some(SlateFsHandle { raw })
    }
}

pub struct FhCodec {
    fsid: u64,
    key: Secret32,
}

impl FhCodec {
    pub fn new(fsid: u64, key: Secret32) -> FhCodec {
        FhCodec { fsid, key }
    }

    /// Clone of the server key, for handing to readdir iterators that mint
    /// per-entry handles.
    pub fn key_clone(&self) -> Secret32 {
        self.key.clone()
    }

    fn mac(&self, payload: &[u8]) -> [u8; MAC_LEN] {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose_secret())
            .expect("HMAC accepts any key length");
        mac.update(payload);
        let full = mac.finalize().into_bytes();
        full[..MAC_LEN].try_into().unwrap()
    }

    pub fn make(&self, ino: u64, generation: u32) -> SlateFsHandle {
        let mut raw = [0u8; FH_LEN];
        raw[0] = VERSION;
        raw[1..9].copy_from_slice(&self.fsid.to_be_bytes());
        raw[9..17].copy_from_slice(&ino.to_be_bytes());
        raw[17..21].copy_from_slice(&generation.to_be_bytes());
        let mac = self.mac(&raw[..21]);
        raw[21..].copy_from_slice(&mac);
        SlateFsHandle { raw }
    }

    /// Returns the ino if the handle is authentic *and* belongs to this
    /// volume. Constant-time MAC comparison.
    pub fn verify(&self, handle: &SlateFsHandle) -> Option<u64> {
        let expected = self.mac(&handle.raw[..21]);
        let ok = subtle_eq::ct_eq(&expected, &handle.raw[21..]);
        (ok && handle.fsid() == self.fsid).then(|| handle.ino())
    }
}

mod subtle_eq {
    /// Constant-time byte-slice equality (no early exit).
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc = 0u8;
        for (x, y) in a.iter().zip(b) {
            acc |= x ^ y;
        }
        acc == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec(fsid: u64, key_byte: u8) -> FhCodec {
        FhCodec::new(fsid, Secret32::from_bytes([key_byte; 32]))
    }

    #[test]
    fn roundtrip_and_verify() {
        let c = codec(7, 1);
        let fh = c.make(42, 3);
        assert_eq!(fh.ino(), 42);
        assert_eq!(fh.fsid(), 7);
        assert_eq!(fh.generation(), 3);
        assert_eq!(c.verify(&fh), Some(42));

        let reparsed = SlateFsHandle::from_bytes(fh.as_bytes()).unwrap();
        assert_eq!(c.verify(&reparsed), Some(42));
    }

    #[test]
    fn forged_or_foreign_handles_rejected() {
        let c = codec(7, 1);
        let fh = c.make(42, 0);

        // Tampered ino.
        let mut raw = *fh.as_bytes().first_chunk::<{ FH_LEN }>().unwrap();
        raw[16] ^= 1;
        let tampered = SlateFsHandle::from_bytes(&raw).unwrap();
        assert_eq!(c.verify(&tampered), None);

        // Handle minted for another volume (different fsid), same key.
        let other_volume = codec(8, 1).make(42, 0);
        assert_eq!(c.verify(&other_volume), None);

        // Handle minted under another deployment's key.
        let other_key = codec(7, 2).make(42, 0);
        assert_eq!(c.verify(&other_key), None);

        // Wrong length / version.
        assert!(SlateFsHandle::from_bytes(&[0u8; 10]).is_none());
        let mut bad_ver = *fh.as_bytes().first_chunk::<{ FH_LEN }>().unwrap();
        bad_ver[0] = 9;
        assert!(SlateFsHandle::from_bytes(&bad_ver).is_none());
    }
}
