//! TOML configuration (`/etc/slatefs/slatefs.toml`). Secrets never live here:
//! the KMS section points at key *files* or cloud KMS key ids (plan §13).

use std::fmt;
use std::net::{IpAddr, SocketAddr};
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
    /// Live control-plane export reconciliation settings. Static `[[exports]]`
    /// remain a bootstrap/compatibility path; control-plane exports are polled
    /// and converged while the daemon is running.
    #[serde(default)]
    pub export_control: ExportControlConfig,
    /// Cache tiers (plan §8, DD-4). Budgets are deployment-wide and divided
    /// across open volumes — caches are per-volume by design (a shared
    /// block cache would alias WAL ids across volumes; see
    /// docs/threat-model.md).
    #[serde(default)]
    pub cache: CacheConfig,
    /// SlateDB write-buffer and compaction settings for served volume DBs.
    #[serde(default)]
    pub slatedb: SlateDbConfig,
    /// Optional Prometheus text endpoint served by `slatefsd`.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Optional loopback-only daemon admin endpoint.
    #[serde(default)]
    pub admin: AdminConfig,
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
    /// Maximum open files the disk cache may keep per volume.
    /// Unset ⇒ SlateFS uses a conservative per-volume default.
    pub disk_max_open_files: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SlateDbConfig {
    /// Memtable size threshold for flushing immutable L0 SSTs.
    pub l0_sst_size_bytes: usize,
    /// Maximum unflushed WAL/memtable bytes before writer backpressure.
    pub max_unflushed_bytes: usize,
    /// Maximum total L0 SSTs before L0 flush backpressure.
    pub l0_max_ssts: usize,
    /// Maximum overlapping L0 SSTs for any key.
    pub l0_max_ssts_per_key: usize,
    /// Parallel workers for immutable memtable flushes.
    pub l0_flush_parallelism: usize,
    /// Maximum compacted SST size.
    pub compaction_max_sst_size_bytes: usize,
    /// Maximum concurrent compactions.
    pub compaction_max_concurrent: usize,
    /// Maximum concurrent compaction fetch tasks.
    pub compaction_max_fetch_tasks: usize,
}

impl Default for SlateDbConfig {
    fn default() -> Self {
        let settings = slatedb::config::Settings::default();
        let compactor = settings.compactor_options.unwrap_or_default();
        let worker = compactor.worker.unwrap_or_default();
        Self {
            l0_sst_size_bytes: settings.l0_sst_size_bytes,
            max_unflushed_bytes: settings.max_unflushed_bytes,
            l0_max_ssts: settings.l0_max_ssts,
            l0_max_ssts_per_key: settings.l0_max_ssts_per_key,
            l0_flush_parallelism: settings.l0_flush_parallelism,
            compaction_max_sst_size_bytes: worker.max_sst_size,
            compaction_max_concurrent: compactor.max_concurrent_compactions,
            compaction_max_fetch_tasks: worker.max_fetch_tasks,
        }
    }
}

impl SlateDbConfig {
    pub fn apply_to_settings(
        &self,
        mut settings: slatedb::config::Settings,
    ) -> slatedb::config::Settings {
        settings.l0_sst_size_bytes = self.l0_sst_size_bytes;
        settings.max_unflushed_bytes = self.max_unflushed_bytes;
        settings.l0_max_ssts = self.l0_max_ssts;
        settings.l0_max_ssts_per_key = self.l0_max_ssts_per_key;
        settings.l0_flush_parallelism = self.l0_flush_parallelism;
        let mut compactor = settings.compactor_options.unwrap_or_default();
        compactor.max_concurrent_compactions = self.compaction_max_concurrent;
        let worker = compactor.worker.get_or_insert_with(Default::default);
        worker.max_sst_size = self.compaction_max_sst_size_bytes;
        worker.max_fetch_tasks = self.compaction_max_fetch_tasks;
        settings.compactor_options = Some(compactor);
        settings
    }

    fn validate(&self) -> Result<()> {
        if self.l0_sst_size_bytes == 0 {
            return Err(Error::Config(
                "slatedb.l0_sst_size_bytes must be greater than 0".into(),
            ));
        }
        if self.max_unflushed_bytes < self.l0_sst_size_bytes {
            return Err(Error::Config(
                "slatedb.max_unflushed_bytes must be >= slatedb.l0_sst_size_bytes".into(),
            ));
        }
        if self.l0_max_ssts == 0
            || self.l0_max_ssts_per_key == 0
            || self.l0_flush_parallelism == 0
            || self.compaction_max_sst_size_bytes == 0
            || self.compaction_max_concurrent == 0
            || self.compaction_max_fetch_tasks == 0
        {
            return Err(Error::Config(
                "slatedb numeric limits and parallelism values must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    /// Optional `ip:port` listener for Prometheus text at `/metrics`.
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// Optional loopback `ip:port` listener for daemon-local admin actions.
    pub listen: Option<String>,
    /// Optional static bearer token for `/admin/v1` routes.
    pub token: Option<String>,
    /// Optional file containing the static bearer token for `/admin/v1` routes.
    pub token_file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExportControlConfig {
    /// Control-plane export reconciliation interval in seconds.
    pub poll_interval_secs: u64,
}

impl Default for ExportControlConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportProtocol {
    #[default]
    Nfs,
    P9,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    /// NFS atime update policy requested for this export. The current backend
    /// applies relatime globally; this field is persisted now so future export
    /// reconciliation can change policy without changing record shape.
    #[serde(default)]
    pub atime: AtimeMode,
    #[serde(default = "default_anon_id")]
    pub anon_uid: u32,
    #[serde(default = "default_anon_id")]
    pub anon_gid: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AtimeMode {
    #[default]
    Relatime,
    Strict,
    Noatime,
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
        if self.cache.disk_max_open_files == Some(0) {
            return Err(Error::Config(
                "cache.disk_max_open_files must be greater than 0".into(),
            ));
        }
        self.slatedb.validate()?;
        if self.admin.token.is_some() && self.admin.token_file.is_some() {
            return Err(Error::Config(
                "admin.token and admin.token_file are mutually exclusive".into(),
            ));
        }
        if self
            .admin
            .token
            .as_deref()
            .is_some_and(|token| token.is_empty())
        {
            return Err(Error::Config("admin.token must not be empty".into()));
        }
        if let Some(listen) = &self.admin.listen {
            if listen.is_empty() {
                return Err(Error::Config(
                    "admin.listen must be a loopback ip:port listener or omitted".into(),
                ));
            }
            let addr: SocketAddr = listen.parse().map_err(|e| {
                Error::Config(format!("admin.listen must be an ip:port listener: {e}"))
            })?;
            if !addr.ip().is_loopback()
                && self.admin.token.is_none()
                && self.admin.token_file.is_none()
            {
                return Err(Error::Config(
                    "admin.listen must bind a loopback address unless admin.token or admin.token_file is set".into(),
                ));
            }
        }
        if self.export_control.poll_interval_secs == 0 {
            return Err(Error::Config(
                "export_control.poll_interval_secs must be greater than 0".into(),
            ));
        }
        for export in &self.exports {
            validate_export_config(export)?;
        }
        Ok(())
    }
}

pub fn validate_export_config(export: &ExportConfig) -> Result<()> {
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
    Ok(())
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

            [admin]
            listen = "127.0.0.1:12081"

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
        assert_eq!(config.admin.listen.as_deref(), Some("127.0.0.1:12081"));
        assert_eq!(config.exports[0].allowed_clients.len(), 2);
        assert!(config.exports[0].allowed_clients[1].contains("10.9.8.7".parse().unwrap()));
    }

    #[test]
    fn admin_listener_must_be_loopback() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [admin]
            listen = "0.0.0.0:12081"
        "#;
        assert!(Config::parse(raw).is_err());
    }

    #[test]
    fn admin_listener_may_bind_non_loopback_with_token() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [admin]
            listen = "0.0.0.0:12081"
            token = "secret"
        "#;
        let config = Config::parse(raw).unwrap();
        assert_eq!(config.admin.token.as_deref(), Some("secret"));
    }

    #[test]
    fn admin_token_sources_are_mutually_exclusive() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [admin]
            listen = "127.0.0.1:12081"
            token = "secret"
            token_file = "/run/slatefs/admin-token"
        "#;
        assert!(Config::parse(raw).is_err());
    }

    #[test]
    fn slatedb_settings_parse_and_validate() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [slatedb]
            l0_sst_size_bytes = 16777216
            max_unflushed_bytes = 268435456
            l0_max_ssts = 64
            l0_max_ssts_per_key = 16
            l0_flush_parallelism = 2
            compaction_max_sst_size_bytes = 67108864
            compaction_max_concurrent = 2
            compaction_max_fetch_tasks = 2
        "#;
        let config = Config::parse(raw).unwrap();
        assert_eq!(config.slatedb.l0_sst_size_bytes, 16 * 1024 * 1024);
        assert_eq!(config.slatedb.max_unflushed_bytes, 256 * 1024 * 1024);
        assert_eq!(config.slatedb.l0_max_ssts, 64);

        let invalid = raw.replace(
            "max_unflushed_bytes = 268435456",
            "max_unflushed_bytes = 1024",
        );
        assert!(Config::parse(&invalid).is_err());
    }

    #[test]
    fn cache_disk_max_open_files_parse_and_validate() {
        let raw = r#"
            [object_store]
            url = "memory:///"

            [kms]
            provider = "static"
            key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

            [cache]
            disk_max_open_files = 512
        "#;
        let config = Config::parse(raw).unwrap();
        assert_eq!(config.cache.disk_max_open_files, Some(512));

        let invalid = raw.replace("disk_max_open_files = 512", "disk_max_open_files = 0");
        assert!(Config::parse(&invalid).is_err());
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
