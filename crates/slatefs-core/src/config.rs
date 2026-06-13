//! TOML configuration (`/etc/slatefs/slatefs.toml`). Secrets never live here:
//! the KMS section points at key *files* or cloud KMS key ids (plan §13).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::Error as _;
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
    /// Optional Prometheus text endpoint served by `slatefsd`.
    #[serde(default)]
    pub metrics: MetricsConfig,
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    /// Optional `ip:port` listener for Prometheus text at `/metrics`.
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportProtocol {
    #[default]
    Nfs,
    P9,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    pub tenant: String,
    pub volume: String,
    /// Optional SlateDB checkpoint id to serve as a read-only snapshot export.
    /// Unset means serve the live writable volume.
    #[serde(default)]
    pub snapshot: Option<String>,
    /// `ip:port` for this export's listener, e.g. `127.0.0.1:12049`.
    pub listen: String,
    /// Source IPs/CIDRs allowed to connect to this export. Empty means allow
    /// all clients. This is a Phase 5 defense-in-depth gate for DD-10's
    /// network-isolated tenancy model.
    #[serde(default)]
    pub allowed_clients: Vec<ClientAddrRule>,
    /// Wire protocol for this export (one listener per export, DD-10).
    #[serde(default)]
    pub protocol: ExportProtocol,
    /// 9P only: bearer token clients must present in `uname` at Tattach
    /// (DD-10). Unset ⇒ open export (use network isolation).
    #[serde(default)]
    pub p9_token: Option<String>,
    /// 9P only: PEM certificate chain for TLS-wrapped 9P. Must be paired
    /// with `p9_tls_key`.
    #[serde(default)]
    pub p9_tls_cert: Option<std::path::PathBuf>,
    /// 9P only: PEM private key for TLS-wrapped 9P. Must be paired with
    /// `p9_tls_cert`.
    #[serde(default)]
    pub p9_tls_key: Option<std::path::PathBuf>,
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

/// One source-IP allowlist rule: exact IP (`127.0.0.1`) or CIDR
/// (`10.0.0.0/8`, `2001:db8::/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddrRule {
    addr: IpAddr,
    prefix_len: u8,
}

impl ClientAddrRule {
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(rule), IpAddr::V4(ip)) => prefix_matches(
                u32::from(rule) as u128,
                u32::from(ip) as u128,
                32,
                self.prefix_len,
            ),
            (IpAddr::V6(rule), IpAddr::V6(ip)) => {
                prefix_matches(u128::from(rule), u128::from(ip), 128, self.prefix_len)
            }
            _ => false,
        }
    }
}

fn prefix_matches(rule: u128, ip: u128, bits: u8, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let shift = bits - prefix_len;
    (rule >> shift) == (ip >> shift)
}

impl FromStr for ClientAddrRule {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        let (addr_raw, prefix_raw) = raw
            .split_once('/')
            .map_or((raw, None), |(addr, prefix)| (addr, Some(prefix)));
        let addr: IpAddr = addr_raw
            .parse()
            .map_err(|e| format!("invalid IP address {addr_raw:?}: {e}"))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix_raw {
            Some("") => return Err(format!("missing prefix length in {raw:?}")),
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|e| format!("invalid prefix length {prefix:?}: {e}"))?,
            None => max_prefix,
        };
        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {prefix_len} exceeds {max_prefix} for {addr}"
            ));
        }
        Ok(ClientAddrRule { addr, prefix_len })
    }
}

impl fmt::Display for ClientAddrRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact = match self.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if self.prefix_len == exact {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix_len)
        }
    }
}

impl Serialize for ClientAddrRule {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ClientAddrRule {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(D::Error::custom)
    }
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
        if self.metrics.listen.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Config(
                "metrics.listen must be an ip:port listener or omitted".into(),
            ));
        }
        for export in &self.exports {
            let has_tls_cert = export.p9_tls_cert.is_some();
            let has_tls_key = export.p9_tls_key.is_some();
            if has_tls_cert != has_tls_key {
                return Err(Error::Config(format!(
                    "export {}/{} must set both p9_tls_cert and p9_tls_key, or neither",
                    export.tenant, export.volume
                )));
            }
            if export.protocol != ExportProtocol::P9 && (has_tls_cert || has_tls_key) {
                return Err(Error::Config(format!(
                    "export {}/{} sets 9P TLS fields but protocol is not p9",
                    export.tenant, export.volume
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_addr_rules_match_exact_and_cidr() {
        let loopback: ClientAddrRule = "127.0.0.1".parse().unwrap();
        assert!(loopback.contains("127.0.0.1".parse().unwrap()));
        assert!(!loopback.contains("127.0.0.2".parse().unwrap()));

        let private: ClientAddrRule = "10.0.0.0/8".parse().unwrap();
        assert!(private.contains("10.2.3.4".parse().unwrap()));
        assert!(!private.contains("11.0.0.1".parse().unwrap()));

        let docs_v6: ClientAddrRule = "2001:db8::/32".parse().unwrap();
        assert!(docs_v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!docs_v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!docs_v6.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn client_addr_rules_reject_bad_prefixes() {
        assert!("127.0.0.1/33".parse::<ClientAddrRule>().is_err());
        assert!("2001:db8::/129".parse::<ClientAddrRule>().is_err());
        assert!("127.0.0.1/".parse::<ClientAddrRule>().is_err());
    }

    #[test]
    fn export_allowed_clients_parse_from_toml() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [metrics]
            listen = "127.0.0.1:12080"

            [[exports]]
            tenant = "t"
            volume = "v"
            snapshot = "018f7d79-0354-77a0-a14b-33b863d8999a"
            listen = "127.0.0.1:12049"
            allowed_clients = ["127.0.0.1", "10.0.0.0/8"]
        "#;
        let config = Config::parse(raw).unwrap();
        assert_eq!(
            config.exports[0].snapshot.as_deref(),
            Some("018f7d79-0354-77a0-a14b-33b863d8999a")
        );
        assert_eq!(config.metrics.listen.as_deref(), Some("127.0.0.1:12080"));
        assert_eq!(config.exports[0].allowed_clients.len(), 2);
        assert!(config.exports[0].allowed_clients[1].contains("10.9.8.7".parse().unwrap()));
    }

    #[test]
    fn p9_tls_fields_parse_and_validate_as_a_pair() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [[exports]]
            tenant = "t"
            volume = "v"
            listen = "127.0.0.1:12050"
            protocol = "p9"
            p9_tls_cert = "/tmp/slatefs.crt"
            p9_tls_key = "/tmp/slatefs.key"
        "#;
        let config = Config::parse(raw).unwrap();
        assert_eq!(
            config.exports[0].p9_tls_cert.as_deref(),
            Some(std::path::Path::new("/tmp/slatefs.crt"))
        );
        assert_eq!(
            config.exports[0].p9_tls_key.as_deref(),
            Some(std::path::Path::new("/tmp/slatefs.key"))
        );

        let missing_key = raw
            .lines()
            .filter(|line| !line.contains("p9_tls_key"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(Config::parse(&missing_key).is_err());

        let nfs_tls = raw.replace(r#"protocol = "p9""#, r#"protocol = "nfs""#);
        assert!(Config::parse(&nfs_tls).is_err());
    }
}
