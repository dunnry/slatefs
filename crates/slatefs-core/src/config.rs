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
    /// NFS exports served by `slatefsd` (DD-10: one listener per export).
    /// Phase 2 keeps exports in the config file; per-volume export records
    /// in the control DB come with the multi-tenant hardening phase.
    #[serde(default)]
    pub exports: Vec<ExportConfig>,
    /// Cache tiers (plan §8, DD-4). Budgets are deployment-wide and divided
    /// across open volumes — caches are per-volume by design (a shared
    /// block cache would alias WAL ids across volumes; see
    /// docs/threat-model.md).
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Total in-RAM block-cache budget in bytes (tier 1, plaintext blocks).
    /// Unset ⇒ the engine default (64 MiB) per volume.
    pub memory_bytes: Option<u64>,
    /// Root directory for the local disk part cache (tier 2, ciphertext;
    /// safe on untrusted disks). Unset ⇒ tier disabled.
    pub disk_path: Option<std::path::PathBuf>,
    /// Total disk-cache budget in bytes across volumes.
    pub disk_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    pub tenant: String,
    pub volume: String,
    /// `ip:port` for this export's NFS+mount listener, e.g. `127.0.0.1:12049`.
    pub listen: String,
    /// Identity squash policy (DD-10). AUTH_SYS uids are unauthenticated
    /// assertions — pair `none`/`root_squash` with network-level tenant
    /// isolation per the plan.
    #[serde(default)]
    pub squash: SquashMode,
    #[serde(default = "default_anon_id")]
    pub anon_uid: u32,
    #[serde(default = "default_anon_id")]
    pub anon_gid: u32,
}

fn default_anon_id() -> u32 {
    65534
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SquashMode {
    /// Everyone acts as `anon_uid`/`anon_gid` (like `all_squash`).
    #[default]
    AllSquash,
    /// Honor the client's AUTH_UNIX uid/gid/groups as-is (classic
    /// `no_root_squash` trust model).
    #[serde(rename = "none")]
    NoSquash,
    /// Honor client identities except root, which maps to anon (the
    /// traditional NFS default).
    RootSquash,
    /// Everyone acts as root — single-user/dev exports only.
    TrustAsRoot,
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
    /// AWS KMS key (requires the `aws-kms` build feature). Credentials and
    /// region come from the standard AWS environment/profile chain.
    Aws { key_id: String },
}

impl KmsConfig {
    pub fn provider_name(&self) -> &'static str {
        match self {
            KmsConfig::Age { .. } => "age",
            KmsConfig::Static { .. } => "static",
            KmsConfig::Aws { .. } => "aws",
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
