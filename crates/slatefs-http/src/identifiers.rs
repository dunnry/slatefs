use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;

#[derive(Clone)]
pub struct TokenSigner(Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryToken {
    pub version: u8,
    /// SHA-256 of the authenticated tenant, volume, view kind, and exact view
    /// identity. This prevents a valid opaque identifier from being replayed
    /// against another immutable view that happens to share the same fsid and
    /// inode generations.
    pub view_binding: [u8; 32],
    pub fsid: u64,
    pub parent_ino: u64,
    pub parent_generation: u32,
    pub ino: u64,
    pub generation: u32,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageToken {
    pub version: u8,
    pub view_binding: [u8; 32],
    pub fsid: u64,
    pub dir_ino: u64,
    pub dir_generation: u32,
    pub cookie: u64,
}

impl TokenSigner {
    #[must_use]
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self(key.as_ref().to_vec())
    }

    pub fn sign<T: Serialize>(&self, value: &T) -> Result<String, postcard::Error> {
        let payload = postcard::to_allocvec(value)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts any key size");
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Option<T> {
        let (payload, signature) = token.split_once('.')?;
        let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).ok()?;
        mac.update(&payload);
        mac.verify_slice(&signature).ok()?;
        postcard::from_bytes(&payload).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_tokens_reject_forgery_and_foreign_keys() {
        let signer = TokenSigner::new([7; 32]);
        let value = EntryToken {
            version: 2,
            view_binding: [9; 32],
            fsid: 42,
            parent_ino: 1,
            parent_generation: 3,
            ino: 9,
            generation: 4,
            name: vec![0xff],
        };
        let token = signer.sign(&value).unwrap();
        let decoded: EntryToken = signer.verify(&token).unwrap();
        assert_eq!(decoded.name, vec![0xff]);
        let mut forged = token.into_bytes();
        forged[2] = if forged[2] == b'A' { b'B' } else { b'A' };
        assert!(
            signer
                .verify::<EntryToken>(std::str::from_utf8(&forged).unwrap())
                .is_none()
        );
        assert!(
            TokenSigner::new([8; 32])
                .verify::<EntryToken>(std::str::from_utf8(&forged).unwrap())
                .is_none()
        );
    }
}
