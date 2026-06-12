//! TOML configuration (`/etc/slatefs/slatefs.toml`). Secrets never live here:
//! the KMS section points at key *files* or cloud KMS key ids (plan §13).

use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub object_store: ObjectStoreConfig,
    pub kms: KmsConfig,
    #[serde(default)]
    pub volume_defaults: VolumeDefaults,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreConfig {
    /// Root URL for everything this deployment stores, e.g.
    /// `s3://bucket/slatefs`, `file:///var/lib/slatefs`, `memory:///`.
    /// The control DB lives at `<url>/control`, volumes at
    /// `<url>/volumes/<tenant>/<volume>` (plan §5).
    pub url: String,
}

/// Master-KEK provider (DD-8). The master KEK only ever wraps/unwraps tenant
/// KEKs and the control-plane DEK.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum KmsConfig {
    /// Local age identity file (dev/single-node). Generate with
    /// `slatefs keygen`.
    Age { keyfile: std::path::PathBuf },
    /// Fixed 32-byte hex key. Tests and throwaway environments only.
    Static { key_hex: String },
}

impl KmsConfig {
    pub fn provider_name(&self) -> &'static str {
        match self {
            KmsConfig::Age { .. } => "age",
            KmsConfig::Static { .. } => "static",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct VolumeDefaults {
    /// Content chunk size in bytes (DD-6). Fixed per volume at mkfs time.
    pub chunk_size: u32,
    /// SST compression codec, applied by SlateDB before encryption (DD-2).
    pub compression: Compression,
    /// AEAD for the block transformer (DD-8).
    pub cipher: CipherChoice,
}

impl Default for VolumeDefaults {
    fn default() -> Self {
        VolumeDefaults {
            chunk_size: 128 * 1024,
            compression: Compression::Lz4,
            cipher: CipherChoice::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    None,
    Lz4,
    Zstd,
}

impl Compression {
    pub fn to_slatedb(self) -> Option<slatedb::config::CompressionCodec> {
        match self {
            Compression::None => None,
            Compression::Lz4 => Some(slatedb::config::CompressionCodec::Lz4),
            Compression::Zstd => Some(slatedb::config::CompressionCodec::Zstd),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherChoice {
    /// AES-256-GCM where AES hardware acceleration is present, otherwise
    /// XChaCha20-Poly1305 (DD-8). Resolved once at mkfs and recorded in the
    /// volume format.
    Auto,
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl CipherChoice {
    pub fn resolve(self) -> Cipher {
        match self {
            CipherChoice::Auto => Cipher::auto_select(),
            CipherChoice::Aes256Gcm => Cipher::Aes256Gcm,
            CipherChoice::XChaCha20Poly1305 => Cipher::XChaCha20Poly1305,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Config> {
        let config: Config = toml::from_str(raw).map_err(|e| Error::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let chunk = self.volume_defaults.chunk_size;
        if !chunk.is_power_of_two() || !(4 * 1024..=4 * 1024 * 1024).contains(&chunk) {
            return Err(Error::Config(format!(
                "volume_defaults.chunk_size must be a power of two in [4KiB, 4MiB], got {chunk}"
            )));
        }
        if let KmsConfig::Static { key_hex } = &self.kms
            && hex::decode(key_hex).map(|k| k.len()) != Ok(32)
        {
            return Err(Error::Config(
                "kms.key_hex must be 64 hex chars (32 bytes)".into(),
            ));
        }
        Ok(())
    }
}
