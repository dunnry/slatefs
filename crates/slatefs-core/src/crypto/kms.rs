//! Master-KEK providers (DD-8). The KMS only ever wraps/unwraps 32-byte keys
//! (tenant KEKs and the control-plane DEK); bulk data never touches it.
//!
//! Implementations: [`StaticKms`] (tests/dev), [`LocalAgeKms`] (age identity
//! file, single-node deployments). `AwsKms`/`GcpKms` arrive in Phase 3.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{Secret32, aead};
use crate::config::KmsConfig;
use crate::error::{Error, Result};

#[async_trait::async_trait]
pub trait Kms: Send + Sync {
    /// Encrypt 32 bytes of key material, cryptographically bound to `context`
    /// (a blob moved to a different record fails to unwrap).
    async fn wrap(&self, key: &Secret32, context: &str) -> Result<Vec<u8>>;

    /// Inverse of [`Kms::wrap`]. Fails closed on wrong key, wrong context, or
    /// tampered blob.
    async fn unwrap(&self, blob: &[u8], context: &str) -> Result<Secret32>;

    fn name(&self) -> &'static str;
}

pub fn from_config(config: &KmsConfig) -> Result<std::sync::Arc<dyn Kms>> {
    match config {
        KmsConfig::Static { key_hex } => Ok(std::sync::Arc::new(StaticKms::from_hex(key_hex)?)),
        KmsConfig::Age { keyfile } => Ok(std::sync::Arc::new(LocalAgeKms::from_file(keyfile)?)),
        #[cfg(feature = "aws-kms")]
        KmsConfig::Aws { key_id } => Ok(std::sync::Arc::new(AwsKms::new(key_id.clone()))),
        #[cfg(not(feature = "aws-kms"))]
        KmsConfig::Aws { .. } => Err(Error::Config(
            "kms.provider = \"aws\" requires building with --features aws-kms".into(),
        )),
    }
}

/// Fixed-key KMS for tests and throwaway environments.
pub struct StaticKms {
    kek: Secret32,
}

impl StaticKms {
    pub fn new(kek: Secret32) -> Self {
        StaticKms { kek }
    }

    pub fn from_hex(key_hex: &str) -> Result<Self> {
        let bytes = hex::decode(key_hex)
            .map_err(|e| Error::crypto(format!("static KMS key is not valid hex: {e}")))?;
        Ok(StaticKms::new(Secret32::try_from_slice(&bytes)?))
    }
}

#[async_trait::async_trait]
impl Kms for StaticKms {
    async fn wrap(&self, key: &Secret32, context: &str) -> Result<Vec<u8>> {
        aead::wrap_key(&self.kek, context, key)
    }

    async fn unwrap(&self, blob: &[u8], context: &str) -> Result<Secret32> {
        aead::unwrap_key(&self.kek, context, blob)
    }

    fn name(&self) -> &'static str {
        "static"
    }
}

/// Payload sealed inside an age blob. age has no AAD, so context binding is
/// enforced by storing the context alongside the key and checking on unwrap.
#[derive(Serialize, Deserialize)]
struct AgePayload {
    context: String,
    key: Vec<u8>,
}

/// Local age identity (X25519) as the master KEK — the dev/single-node
/// provider. Generate a keyfile with `slatefs keygen`.
pub struct LocalAgeKms {
    identity: age::x25519::Identity,
}

impl LocalAgeKms {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading age keyfile {}: {e}", path.display())))?;
        let line = raw
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .ok_or_else(|| {
                Error::Config(format!("no AGE-SECRET-KEY-1 line in {}", path.display()))
            })?;
        let identity: age::x25519::Identity = line
            .parse()
            .map_err(|e| Error::crypto(format!("invalid age identity: {e}")))?;
        Ok(LocalAgeKms { identity })
    }

    /// Returns `(secret_identity_line, public_recipient)` for `slatefs keygen`.
    pub fn generate_identity() -> (String, String) {
        use age::secrecy::ExposeSecret;
        let identity = age::x25519::Identity::generate();
        let secret = identity.to_string().expose_secret().to_string();
        let public = identity.to_public().to_string();
        (secret, public)
    }
}

#[async_trait::async_trait]
impl Kms for LocalAgeKms {
    async fn wrap(&self, key: &Secret32, context: &str) -> Result<Vec<u8>> {
        let payload = postcard::to_allocvec(&AgePayload {
            context: context.to_string(),
            key: key.expose().to_vec(),
        })?;
        age::encrypt(&self.identity.to_public(), &payload)
            .map_err(|e| Error::crypto(format!("age wrap failed: {e}")))
    }

    async fn unwrap(&self, blob: &[u8], context: &str) -> Result<Secret32> {
        let payload = age::decrypt(&self.identity, blob)
            .map_err(|e| Error::crypto(format!("age unwrap failed: {e}")))?;
        let payload: AgePayload = postcard::from_bytes(&payload)?;
        if payload.context != context {
            return Err(Error::crypto(format!(
                "wrapped key context mismatch: blob is for {:?}, requested {:?}",
                payload.context, context
            )));
        }
        Secret32::try_from_slice(&payload.key)
    }

    fn name(&self) -> &'static str {
        "age"
    }
}

/// AWS KMS as the master KEK (DD-8). Encrypt/Decrypt of 32-byte keys with
/// the wrap context bound via KMS `EncryptionContext` — KMS itself refuses
/// to decrypt under a different context, mirroring the local AAD binding.
#[cfg(feature = "aws-kms")]
pub struct AwsKms {
    key_id: String,
    client: tokio::sync::OnceCell<aws_sdk_kms::Client>,
}

#[cfg(feature = "aws-kms")]
impl AwsKms {
    pub fn new(key_id: String) -> AwsKms {
        AwsKms {
            key_id,
            client: tokio::sync::OnceCell::new(),
        }
    }

    async fn client(&self) -> &aws_sdk_kms::Client {
        self.client
            .get_or_init(|| async {
                let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                aws_sdk_kms::Client::new(&config)
            })
            .await
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait::async_trait]
impl Kms for AwsKms {
    async fn wrap(&self, key: &Secret32, context: &str) -> Result<Vec<u8>> {
        let response = self
            .client()
            .await
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(key.expose().to_vec()))
            .encryption_context("slatefs", context)
            .send()
            .await
            .map_err(|e| Error::crypto(format!("KMS Encrypt failed: {e}")))?;
        response
            .ciphertext_blob()
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| Error::crypto("KMS Encrypt returned no ciphertext"))
    }

    async fn unwrap(&self, blob: &[u8], context: &str) -> Result<Secret32> {
        let response = self
            .client()
            .await
            .decrypt()
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(blob.to_vec()))
            .encryption_context("slatefs", context)
            .send()
            .await
            .map_err(|e| Error::crypto(format!("KMS Decrypt failed (fail-closed): {e}")))?;
        let plaintext = response
            .plaintext()
            .ok_or_else(|| Error::crypto("KMS Decrypt returned no plaintext"))?;
        Secret32::try_from_slice(plaintext.as_ref())
    }

    fn name(&self) -> &'static str {
        "aws"
    }
}

/// Standard wrap contexts. Centralized so control-plane code can't drift.
pub mod contexts {
    pub const CONTROL_DEK: &str = "slatefs/control-dek/v1";

    pub fn tenant_kek(tenant: &str) -> String {
        format!("slatefs/tenant-kek/v1/{tenant}")
    }

    pub fn volume_dek(tenant: &str, volume: &str) -> String {
        format!("slatefs/volume-dek/v1/{tenant}/{volume}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_kms_roundtrip_and_fail_closed() {
        let kms = StaticKms::new(Secret32::generate());
        let kek = Secret32::generate();
        let blob = kms.wrap(&kek, contexts::CONTROL_DEK).await.unwrap();
        let out = kms.unwrap(&blob, contexts::CONTROL_DEK).await.unwrap();
        assert_eq!(out.expose(), kek.expose());

        // Wrong context fails.
        assert!(kms.unwrap(&blob, "slatefs/other").await.is_err());
        // Wrong master key fails.
        let other = StaticKms::new(Secret32::generate());
        assert!(other.unwrap(&blob, contexts::CONTROL_DEK).await.is_err());
    }

    #[tokio::test]
    async fn age_kms_roundtrip_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("master.key");
        let (secret, _public) = LocalAgeKms::generate_identity();
        std::fs::write(&keyfile, format!("# slatefs master key\n{secret}\n")).unwrap();

        let kms = LocalAgeKms::from_file(&keyfile).unwrap();
        let kek = Secret32::generate();
        let ctx = contexts::tenant_kek("t1");
        let blob = kms.wrap(&kek, &ctx).await.unwrap();
        assert_eq!(
            kms.unwrap(&blob, &ctx).await.unwrap().expose(),
            kek.expose()
        );

        // Context mismatch fails closed.
        assert!(
            kms.unwrap(&blob, &contexts::tenant_kek("t2"))
                .await
                .is_err()
        );

        // A different identity fails closed.
        let (other_secret, _) = LocalAgeKms::generate_identity();
        std::fs::write(&keyfile, format!("{other_secret}\n")).unwrap();
        let other = LocalAgeKms::from_file(&keyfile).unwrap();
        assert!(other.unwrap(&blob, &ctx).await.is_err());

        // Tampered blob fails closed.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(kms.unwrap(&tampered, &ctx).await.is_err());
    }
}
