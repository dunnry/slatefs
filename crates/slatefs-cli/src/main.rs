//! `slatefs` — management CLI (plan §13): keygen, key rotation, tenant
//! lifecycle, volume create/info/list/fsck, and quota metadata.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use slatefs_core::config::{ClientAddrRule, Config};
use slatefs_core::control::{
    AuditAction, AuditActor, AuditDetailValue, AuditOutcome, AuditPlane, AuditRecord, AuditScope,
    ControlPlane, DaemonMetrics, DaemonNodeRecord, DaemonNodeState, ExportRecord, QuotaLimits,
    SnapshotRetentionPolicy, VolumePlacementRecord,
};
use slatefs_core::crypto::kms::{self, LocalAgeKms};
use slatefs_core::meta::superblock::VolumeKind;
use slatefs_core::rate::RateLimits;
use slatefs_core::versioning::{VersionCommitInfo, VersionRepository, purge_version_history};
use slatefs_core::volume::{self, CreateBlockVolumeOptions, CreateVolumeOptions};
use slatefs_core::{config, store};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(name = "slatefs", version, about = "SlateFS management CLI")]
struct Cli {
    /// Path to the slatefs TOML config file.
    #[arg(
        long,
        short,
        global = true,
        default_value = "/etc/slatefs/slatefs.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a local age master key (dev/single-node KMS).
    Keygen {
        /// Write the secret identity to this file (printed to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    #[command(subcommand)]
    Key(KeyCmd),
    #[command(subcommand)]
    Tenant(TenantCmd),
    #[command(subcommand)]
    Volume(VolumeCmd),
    #[command(subcommand)]
    Quota(QuotaCmd),
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Opt-in, per-volume file version control backed by Prolly trees.
    #[command(subcommand)]
    Versioning(VersioningCmd),
    #[command(subcommand)]
    Clone(CloneCmd),
    #[command(subcommand)]
    Export(ExportCmd),
    #[command(subcommand)]
    Fleet(FleetCmd),
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Rotate a tenant KEK and rewrap its active volume DEKs.
    RotateKek { tenant: String },
}

#[derive(Subcommand)]
enum TenantCmd {
    /// Create a tenant (generates and wraps its KEK).
    Create {
        name: String,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Suspend a tenant; new volume creates and daemon exports are refused.
    Suspend { name: String },
    /// Resume a suspended tenant.
    Resume { name: String },
    /// Mark a tenant deleting and crypto-shred its wrapped keys.
    Delete {
        name: String,
        /// Required confirmation for the destructive key-drop operation.
        #[arg(long)]
        yes: bool,
    },
    /// Show or set tenant frontend rate limits.
    #[command(subcommand)]
    Rate(TenantRateCmd),
    /// List tenants.
    List,
}

#[derive(Subcommand)]
enum TenantRateCmd {
    /// Show tenant rate limits.
    Show { name: String },
    /// Set tenant rate limits. Values are per-second counts, or `none`.
    Set {
        name: String,
        #[arg(long, value_name = "N|none")]
        ops_per_second: Option<String>,
        #[arg(long, value_name = "N|none")]
        bytes_per_second: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VolumeCreateKind {
    Filesystem,
    Block,
}

enum FieldUpdate<T> {
    Leave,
    Clear,
    Set(T),
}

impl<T> FieldUpdate<T> {
    fn from_option(value: Option<T>, clear: bool) -> Self {
        if clear {
            Self::Clear
        } else if let Some(value) = value {
            Self::Set(value)
        } else {
            Self::Leave
        }
    }

    fn apply_option(self, target: &mut Option<T>) {
        match self {
            Self::Leave => {}
            Self::Clear => *target = None,
            Self::Set(value) => *target = Some(value),
        }
    }
}

impl<T> FieldUpdate<Vec<T>> {
    fn from_vec(value: Vec<T>, clear: bool) -> Self {
        if clear {
            Self::Clear
        } else if value.is_empty() {
            Self::Leave
        } else {
            Self::Set(value)
        }
    }

    fn apply_vec(self, target: &mut Vec<T>) {
        match self {
            Self::Leave => {}
            Self::Clear => target.clear(),
            Self::Set(value) => *target = value,
        }
    }
}

#[derive(Subcommand)]
enum VolumeCmd {
    /// Create a volume: control record + encrypted mkfs.
    Create {
        tenant: String,
        volume: String,
        /// Volume kind. Filesystem is the default; block requires --size.
        #[arg(long, default_value = "filesystem", value_parser = parse_volume_create_kind)]
        kind: VolumeCreateKind,
        /// Block volume virtual size in bytes, or K/M/G/T base-2 units.
        #[arg(long, value_name = "BYTES|K|M|G|T", value_parser = parse_size_bytes)]
        size: Option<u64>,
        /// Chunk size in bytes; power of two in [4KiB, 4MiB]. Fixed at mkfs.
        #[arg(long)]
        chunk_size: Option<u32>,
        #[arg(long, value_parser = parse_compression)]
        compression: Option<config::Compression>,
        #[arg(long, value_parser = parse_cipher)]
        cipher: Option<config::CipherChoice>,
        /// Free-form operator note stored in the control record.
        #[arg(long)]
        note: Option<String>,
    },
    /// Show a volume's control record and superblock.
    Info { tenant: String, volume: String },
    /// List a tenant's volumes.
    List { tenant: String },
    /// Verify volume invariants and quota counters (volume must not be
    /// actively served — fsck opens it as the writer).
    Fsck {
        tenant: String,
        volume: String,
        /// Rewrite the persistent counters from the recount on drift.
        #[arg(long)]
        recount: bool,
    },
    /// Read-only online structural scrub. Safe while the volume is served;
    /// reports drift but never rewrites counters.
    Scrub { tenant: String, volume: String },
    /// Grow an offline block volume. Opens the volume writer lease, so do
    /// not run while the volume is served by slatefsd.
    Resize {
        tenant: String,
        volume: String,
        /// New block volume size in bytes, or K/M/G/T base-2 units.
        #[arg(long, value_name = "BYTES|K|M|G|T", value_parser = parse_size_bytes)]
        size: u64,
    },
    /// Mark a volume deleting and crypto-shred its wrapped DEK.
    Delete {
        tenant: String,
        volume: String,
        /// Required confirmation for the destructive key-drop operation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum QuotaCmd {
    /// Show configured quota limits and current usage.
    Show { tenant: String, volume: String },
    /// Set quota limits. Values are bytes/counts, or `none` to clear a limit.
    Set {
        tenant: String,
        volume: String,
        #[arg(long, value_name = "N|none")]
        bytes_hard: Option<String>,
        #[arg(long, value_name = "N|none")]
        bytes_soft: Option<String>,
        #[arg(long, value_name = "UNIX_TS|none")]
        bytes_grace_until: Option<String>,
        #[arg(long, value_name = "N|none")]
        inodes_hard: Option<String>,
        #[arg(long, value_name = "N|none")]
        inodes_soft: Option<String>,
        #[arg(long, value_name = "UNIX_TS|none")]
        inodes_grace_until: Option<String>,
    },
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Create a durable checkpoint. Use --live for a served volume.
    Create {
        tenant: String,
        volume: String,
        /// Optional operator-visible snapshot name.
        #[arg(long)]
        name: Option<String>,
        /// Ask slatefsd's loopback admin endpoint to snapshot the live writer.
        #[arg(long)]
        live: bool,
    },
    /// List volume snapshots.
    List {
        tenant: String,
        volume: String,
        /// Filter by snapshot name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Delete a snapshot by checkpoint id.
    Delete {
        tenant: String,
        volume: String,
        id: String,
    },
    /// Show or set per-volume snapshot retention.
    #[command(subcommand)]
    Retention(SnapshotRetentionCmd),
}

#[derive(Subcommand)]
enum SnapshotRetentionCmd {
    /// Show a volume's snapshot retention policy.
    Show { tenant: String, volume: String },
    /// Set or clear a volume's snapshot retention policy.
    Set {
        tenant: String,
        volume: String,
        /// Keep this many newest checkpoints. Named snapshots are not exempt.
        #[arg(long)]
        keep_last: Option<u32>,
        /// Delete checkpoints older than this age in seconds.
        #[arg(long)]
        max_age: Option<u64>,
        /// Clear the retention policy.
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Subcommand)]
enum VersioningCmd {
    /// Enable explicit file versioning for a filesystem volume.
    Enable { tenant: String, volume: String },
    /// Disable versioning without deleting existing history.
    Disable { tenant: String, volume: String },
    /// Show whether versioning is enabled. This does not open a version store.
    Status { tenant: String, volume: String },
    /// Commit selected files, symlinks, or directory trees.
    Commit {
        tenant: String,
        volume: String,
        /// One or more files or directories. Missing paths record deletions.
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
        #[arg(short, long)]
        message: String,
        /// Ask the serving slatefsd admin endpoint to use its active writer.
        #[arg(long)]
        live: bool,
    },
    /// List commits, optionally restricted to a path.
    Log {
        tenant: String,
        volume: String,
        #[arg(long)]
        path: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Read a file from a commit, writing it to stdout unless --out is given.
    Show {
        tenant: String,
        volume: String,
        commit: String,
        path: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore a file, symlink, or directory tree from a commit.
    Restore {
        tenant: String,
        volume: String,
        commit: String,
        path: String,
        /// Ask the serving slatefsd admin endpoint to use its active writer.
        #[arg(long)]
        live: bool,
    },
    /// Show or update history retention and storage quota.
    Retention {
        tenant: String,
        volume: String,
        #[arg(long)]
        keep_last: Option<u32>,
        #[arg(long)]
        max_age: Option<u64>,
        #[arg(long)]
        max_bytes: Option<u64>,
        #[arg(long)]
        clear: bool,
    },
    /// Show logical version-store usage.
    Stats { tenant: String, volume: String },
    /// Remove commits, nodes, and blobs unreachable under the retention policy.
    Gc {
        tenant: String,
        volume: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Permanently delete all version history while leaving versioning enabled.
    Purge {
        tenant: String,
        volume: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum CloneCmd {
    /// Create an instant writable clone in the same tenant.
    Create {
        tenant: String,
        source_volume: String,
        clone_volume: String,
        /// Clone from this checkpoint id instead of the latest source state.
        #[arg(long)]
        snapshot: Option<String>,
        /// Free-form operator note stored in the clone control record.
        #[arg(long)]
        note: Option<String>,
    },
}

#[derive(Subcommand)]
enum ExportCmd {
    /// Add a control-plane managed export.
    Add {
        id: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        volume: String,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long, default_value = "nfs", value_parser = parse_export_protocol)]
        protocol: config::ExportProtocol,
        /// NBD only: export as read-only. Snapshot exports are always read-only.
        #[arg(long)]
        read_only: bool,
        /// NBD only: strict forces every write/write-zeroes request to use FUA.
        #[arg(long, default_value = "default", value_parser = parse_nbd_sync_mode)]
        sync: config::NbdSyncMode,
        #[arg(long)]
        listen: String,
        #[arg(long = "allowed-client", value_parser = parse_client_addr_rule)]
        allowed_clients: Vec<ClientAddrRule>,
        #[arg(long, default_value = "all_squash", value_parser = parse_squash_mode)]
        squash: config::SquashMode,
        #[arg(long, default_value = "relatime", value_parser = parse_atime_mode)]
        atime: config::AtimeMode,
        #[arg(long, default_value_t = 65534)]
        anon_uid: u32,
        #[arg(long, default_value_t = 65534)]
        anon_gid: u32,
        #[arg(long)]
        p9_token: Option<String>,
        #[arg(long)]
        p9_tls_cert: Option<PathBuf>,
        #[arg(long)]
        p9_tls_key: Option<PathBuf>,
        #[arg(long)]
        nbd_tls_cert: Option<PathBuf>,
        #[arg(long)]
        nbd_tls_key: Option<PathBuf>,
        #[arg(long)]
        nbd_tls_client_ca: Option<PathBuf>,
        #[arg(long)]
        disabled: bool,
    },
    /// List control-plane managed exports.
    List,
    /// Show one control-plane managed export.
    Show { id: String },
    /// Update a control-plane managed export.
    Update {
        id: String,
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        volume: Option<String>,
        #[arg(long, conflicts_with = "clear_snapshot")]
        snapshot: Option<String>,
        #[arg(long, conflicts_with = "snapshot")]
        clear_snapshot: bool,
        #[arg(long, value_parser = parse_export_protocol)]
        protocol: Option<config::ExportProtocol>,
        #[arg(long)]
        read_only: Option<bool>,
        #[arg(long, value_parser = parse_nbd_sync_mode)]
        sync: Option<config::NbdSyncMode>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(
            long = "allowed-client",
            value_parser = parse_client_addr_rule,
            conflicts_with = "clear_allowed_clients"
        )]
        allowed_clients: Vec<ClientAddrRule>,
        #[arg(long, conflicts_with = "allowed_clients")]
        clear_allowed_clients: bool,
        #[arg(long, value_parser = parse_squash_mode)]
        squash: Option<config::SquashMode>,
        #[arg(long, value_parser = parse_atime_mode)]
        atime: Option<config::AtimeMode>,
        #[arg(long)]
        anon_uid: Option<u32>,
        #[arg(long)]
        anon_gid: Option<u32>,
        #[arg(long, conflicts_with = "clear_p9_token")]
        p9_token: Option<String>,
        #[arg(long, conflicts_with = "p9_token")]
        clear_p9_token: bool,
        #[arg(long, conflicts_with = "clear_p9_tls_cert")]
        p9_tls_cert: Option<PathBuf>,
        #[arg(long, conflicts_with = "p9_tls_cert")]
        clear_p9_tls_cert: bool,
        #[arg(long, conflicts_with = "clear_p9_tls_key")]
        p9_tls_key: Option<PathBuf>,
        #[arg(long, conflicts_with = "p9_tls_key")]
        clear_p9_tls_key: bool,
        #[arg(long, conflicts_with = "clear_nbd_tls_cert")]
        nbd_tls_cert: Option<PathBuf>,
        #[arg(long, conflicts_with = "nbd_tls_cert")]
        clear_nbd_tls_cert: bool,
        #[arg(long, conflicts_with = "clear_nbd_tls_key")]
        nbd_tls_key: Option<PathBuf>,
        #[arg(long, conflicts_with = "nbd_tls_key")]
        clear_nbd_tls_key: bool,
        #[arg(long, conflicts_with = "clear_nbd_tls_client_ca")]
        nbd_tls_client_ca: Option<PathBuf>,
        #[arg(long, conflicts_with = "nbd_tls_client_ca")]
        clear_nbd_tls_client_ca: bool,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Remove a control-plane managed export.
    Remove { id: String },
    /// Enable a control-plane managed export.
    Enable { id: String },
    /// Disable a control-plane managed export.
    Disable { id: String },
}

#[derive(Subcommand)]
enum FleetCmd {
    #[command(subcommand)]
    Node(FleetNodeCmd),
    #[command(subcommand)]
    Volume(FleetVolumeCmd),
    /// Mark nodes stale when their last heartbeat is older than the timeout.
    Health {
        #[arg(long, default_value_t = 60)]
        heartbeat_timeout_secs: u64,
    },
}

#[derive(Subcommand)]
enum FleetNodeCmd {
    /// Register or update a daemon node that can own volumes.
    Register {
        id: String,
        #[arg(long)]
        advertise_endpoint: Option<String>,
        #[arg(long)]
        admin_endpoint: Option<String>,
        #[arg(long)]
        metrics_endpoint: Option<String>,
        #[arg(long, default_value_t = 1)]
        capacity_weight: u32,
    },
    /// Record the node's latest health and load snapshot.
    Heartbeat {
        id: String,
        #[arg(long, default_value = "healthy", value_parser = parse_daemon_state)]
        state: DaemonNodeState,
        #[arg(long, default_value_t = 0)]
        writable_volumes: u32,
        #[arg(long, default_value_t = 0)]
        read_replicas: u32,
        #[arg(long, default_value_t = 0)]
        snapshot_exports: u32,
        #[arg(long, default_value_t = 0)]
        request_ops_per_second: u64,
        #[arg(long, default_value_t = 0)]
        request_bytes_per_second: u64,
        #[arg(long, default_value_t = 0)]
        storage_errors: u64,
        #[arg(long, default_value_t = 0)]
        degraded_volumes: u32,
    },
    /// List registered daemon nodes and their last reported load.
    List,
}

#[derive(Subcommand)]
enum FleetVolumeCmd {
    /// Show one volume's placement, stable endpoints, and read pools.
    Placement { tenant: String, volume: String },
    /// List all volume placements.
    List,
    /// Assign or move a volume to a specific node, or the lowest-load node.
    Assign {
        tenant: String,
        volume: String,
        #[arg(long)]
        node: Option<String>,
    },
    #[command(subcommand)]
    Endpoint(FleetEndpointCmd),
    /// Promote a standby after the current primary node failed.
    Promote {
        tenant: String,
        volume: String,
        #[arg(long)]
        failed_node: String,
    },
    /// Start draining a writable volume away from its current primary.
    Drain {
        tenant: String,
        volume: String,
        #[arg(long)]
        target_node: Option<String>,
    },
    /// Complete a previously-started drain and move stable endpoints.
    CompleteDrain { tenant: String, volume: String },
    #[command(subcommand)]
    Replica(FleetReplicaCmd),
    #[command(subcommand)]
    SnapshotPool(FleetSnapshotPoolCmd),
}

#[derive(Subcommand)]
enum FleetEndpointCmd {
    /// Set or update a stable client-facing endpoint for a volume.
    Set {
        tenant: String,
        volume: String,
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "nfs", value_parser = parse_export_protocol)]
        protocol: config::ExportProtocol,
        #[arg(long)]
        address: String,
    },
}

#[derive(Subcommand)]
enum FleetReplicaCmd {
    /// Add or refresh a read replica placement for a volume.
    Add {
        tenant: String,
        volume: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        lag_seconds: Option<u64>,
    },
    /// Remove a read replica placement from a volume.
    Remove {
        tenant: String,
        volume: String,
        #[arg(long)]
        node: String,
    },
}

#[derive(Subcommand)]
enum FleetSnapshotPoolCmd {
    /// Set the pool of nodes allowed to serve snapshots for a volume.
    Set {
        tenant: String,
        volume: String,
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long = "node", required = true)]
        nodes: Vec<String>,
        #[arg(long, default_value_t = 128)]
        max_exports: u32,
    },
    /// Remove a snapshot-serving pool.
    Remove {
        tenant: String,
        volume: String,
        #[arg(long, default_value = "default")]
        name: String,
    },
}

fn parse_compression(s: &str) -> Result<config::Compression, String> {
    match s {
        "none" => Ok(config::Compression::None),
        "lz4" => Ok(config::Compression::Lz4),
        "zstd" => Ok(config::Compression::Zstd),
        _ => Err(format!("unknown compression {s:?} (none|lz4|zstd)")),
    }
}

fn parse_volume_create_kind(s: &str) -> Result<VolumeCreateKind, String> {
    match s {
        "filesystem" | "fs" => Ok(VolumeCreateKind::Filesystem),
        "block" => Ok(VolumeCreateKind::Block),
        _ => Err(format!("unknown volume kind {s:?} (filesystem|block)")),
    }
}

fn parse_size_bytes(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("size must not be empty".to_string());
    }

    let (digits, multiplier) = match raw.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&raw[..raw.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&raw[..raw.len() - 1], 1024u64.pow(2)),
        Some(b'G' | b'g') => (&raw[..raw.len() - 1], 1024u64.pow(3)),
        Some(b'T' | b't') => (&raw[..raw.len() - 1], 1024u64.pow(4)),
        Some(byte) if byte.is_ascii_digit() => (raw, 1),
        Some(_) => {
            return Err(format!(
                "invalid size {raw:?}; expected bytes or K/M/G/T suffix"
            ));
        }
        None => unreachable!("raw is non-empty"),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "invalid size {raw:?}; expected integer bytes or K/M/G/T suffix"
        ));
    }
    let value = digits
        .parse::<u64>()
        .map_err(|_| format!("invalid size {raw:?}; expected u64"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size {raw:?} overflows u64"))
}

fn parse_cipher(s: &str) -> Result<config::CipherChoice, String> {
    match s {
        "auto" => Ok(config::CipherChoice::Auto),
        "aes256gcm" => Ok(config::CipherChoice::Aes256Gcm),
        "xchacha20poly1305" => Ok(config::CipherChoice::XChaCha20Poly1305),
        _ => Err(format!(
            "unknown cipher {s:?} (auto|aes256gcm|xchacha20poly1305)"
        )),
    }
}

fn parse_export_protocol(s: &str) -> Result<config::ExportProtocol, String> {
    match s {
        "nfs" => Ok(config::ExportProtocol::Nfs),
        "p9" => Ok(config::ExportProtocol::P9),
        "nbd" => Ok(config::ExportProtocol::Nbd),
        _ => Err(format!("unknown protocol {s:?} (nfs|p9|nbd)")),
    }
}

fn parse_nbd_sync_mode(s: &str) -> Result<config::NbdSyncMode, String> {
    match s {
        "default" => Ok(config::NbdSyncMode::Default),
        "strict" => Ok(config::NbdSyncMode::Strict),
        _ => Err(format!("unknown NBD sync mode {s:?} (default|strict)")),
    }
}

fn parse_squash_mode(s: &str) -> Result<config::SquashMode, String> {
    match s {
        "all_squash" => Ok(config::SquashMode::AllSquash),
        "none" => Ok(config::SquashMode::NoSquash),
        "root_squash" => Ok(config::SquashMode::RootSquash),
        "trust_as_root" => Ok(config::SquashMode::TrustAsRoot),
        _ => Err(format!(
            "unknown squash mode {s:?} (all_squash|none|root_squash|trust_as_root)"
        )),
    }
}

fn parse_atime_mode(s: &str) -> Result<config::AtimeMode, String> {
    match s {
        "relatime" => Ok(config::AtimeMode::Relatime),
        "strict" => Ok(config::AtimeMode::Strict),
        "noatime" => Ok(config::AtimeMode::Noatime),
        _ => Err(format!(
            "unknown atime mode {s:?} (relatime|strict|noatime)"
        )),
    }
}

fn parse_client_addr_rule(s: &str) -> Result<ClientAddrRule, String> {
    s.parse()
}

fn parse_daemon_state(s: &str) -> Result<DaemonNodeState, String> {
    match s {
        "healthy" => Ok(DaemonNodeState::Healthy),
        "draining" => Ok(DaemonNodeState::Draining),
        "unhealthy" => Ok(DaemonNodeState::Unhealthy),
        "offline" => Ok(DaemonNodeState::Offline),
        _ => Err(format!(
            "unknown daemon state {s:?} (healthy|draining|unhealthy|offline)"
        )),
    }
}

fn parse_optional_u64(raw: &str, kind: &'static str) -> anyhow::Result<Option<u64>> {
    match raw {
        "none" | "unlimited" | "-" => Ok(None),
        _ => raw
            .parse::<u64>()
            .map(Some)
            .with_context(|| format!("invalid {kind} value {raw:?}; expected N or none")),
    }
}

fn parse_quota_value(raw: &str) -> anyhow::Result<Option<u64>> {
    parse_optional_u64(raw, "quota")
}

fn format_limit(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn print_rate_limits(name: &str, limits: RateLimits) {
    println!("rate: {name}");
    println!("ops_per_second:   {}", format_limit(limits.ops_per_second));
    println!(
        "bytes_per_second: {}",
        format_limit(limits.bytes_per_second)
    );
}

fn print_quota(tenant: &str, volume: &str, quota: QuotaLimits) {
    println!("quota: {tenant}/{volume}");
    println!(
        "bytes:  hard={} soft={} grace_until={}",
        format_limit(quota.bytes.hard),
        format_limit(quota.bytes.soft),
        format_limit(quota.bytes.grace_until)
    );
    println!(
        "inodes: hard={} soft={} grace_until={}",
        format_limit(quota.inodes.hard),
        format_limit(quota.inodes.soft),
        format_limit(quota.inodes.grace_until)
    );
}

fn print_quota_usage(report: &slatefs_core::fsck::FsckReport) {
    println!(
        "usage: bytes counter={} recount={}",
        report.counter_bytes, report.bytes_counted
    );
    println!(
        "usage: inodes counter={} recount={}",
        report.counter_inodes, report.inodes_counted
    );
}

fn print_fsck_report(report: &slatefs_core::fsck::FsckReport) {
    println!(
        "inodes: counter={} recount={}",
        report.counter_inodes, report.inodes_counted
    );
    println!(
        "bytes:  counter={} recount={}",
        report.counter_bytes, report.bytes_counted
    );
    for r in &report.reapable {
        println!("reapable: {r}");
    }
    for p in &report.problems {
        println!("PROBLEM: {p}");
    }
}

fn print_snapshot(snapshot: &volume::SnapshotInfo) {
    println!(
        "{}\tmanifest={}\tcreated={}\texpires={}\tname={}",
        snapshot.id,
        snapshot.manifest_id,
        snapshot.create_time,
        snapshot.expire_time.as_deref().unwrap_or("-"),
        snapshot.name.as_deref().unwrap_or("-")
    );
}

fn print_version_commit(commit: &VersionCommitInfo) {
    println!("commit {}", commit.id);
    println!("parent {}", commit.parent.as_deref().unwrap_or("-"));
    println!("created {}", commit.created_at);
    println!("paths {}", commit.paths.join(","));
    println!("message {}", commit.message);
}

async fn append_cli_version_audit(
    control: &ControlPlane,
    action: AuditAction,
    tenant: &str,
    volume: &str,
    details: impl IntoIterator<Item = (String, AuditDetailValue)>,
) -> anyhow::Result<()> {
    let mut record = AuditRecord::new(
        AuditActor {
            plane: AuditPlane::Cli,
            principal: None,
            source_ip: None,
            client_agent: Some(format!("slatefs/{}", env!("CARGO_PKG_VERSION"))),
        },
        action,
        AuditScope {
            tenant: Some(tenant.to_string()),
            volume: Some(volume.to_string()),
            node: None,
        },
        format!("cli-versioning-{}", uuid::Uuid::new_v4()),
        AuditOutcome::Success,
    );
    record.details.extend(details);
    control.append_audit_record(record).await?;
    Ok(())
}

fn print_snapshot_retention(tenant: &str, volume: &str, policy: Option<&SnapshotRetentionPolicy>) {
    println!("snapshot_retention: {tenant}/{volume}");
    match policy {
        Some(policy) => {
            println!(
                "keep_last:    {}",
                format_limit(policy.keep_last.map(u64::from))
            );
            println!("max_age_secs: {}", format_limit(policy.max_age_secs));
            println!("updated_at:   {}", policy.updated_at);
            println!("named_snapshots_exempt: false");
            println!("active_clone_parent_behavior: skip_pinned_checkpoints_or_legacy_volume");
        }
        None => println!("policy:       none"),
    }
}

fn protocol_name(protocol: config::ExportProtocol) -> &'static str {
    match protocol {
        config::ExportProtocol::Nfs => "nfs",
        config::ExportProtocol::P9 => "p9",
        config::ExportProtocol::Nbd => "nbd",
    }
}

fn nbd_sync_name(sync: config::NbdSyncMode) -> &'static str {
    match sync {
        config::NbdSyncMode::Default => "default",
        config::NbdSyncMode::Strict => "strict",
    }
}

fn squash_name(squash: config::SquashMode) -> &'static str {
    match squash {
        config::SquashMode::AllSquash => "all_squash",
        config::SquashMode::NoSquash => "none",
        config::SquashMode::RootSquash => "root_squash",
        config::SquashMode::TrustAsRoot => "trust_as_root",
    }
}

fn atime_name(atime: config::AtimeMode) -> &'static str {
    match atime {
        config::AtimeMode::Relatime => "relatime",
        config::AtimeMode::Strict => "strict",
        config::AtimeMode::Noatime => "noatime",
    }
}

fn print_export(export: &ExportRecord) {
    println!("export:      {}", export.id);
    println!("target:      {}/{}", export.tenant, export.volume);
    println!("snapshot:    {}", export.snapshot.as_deref().unwrap_or("-"));
    println!("protocol:    {}", protocol_name(export.protocol));
    println!("read_only:   {}", export.effective_read_only());
    println!("sync:        {}", nbd_sync_name(export.sync));
    println!("listen:      {}", export.listen);
    println!(
        "allowed:     {}",
        if export.allowed_clients.is_empty() {
            "-".to_string()
        } else {
            export
                .allowed_clients
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    );
    println!("squash:      {}", squash_name(export.squash));
    println!("atime:       {}", atime_name(export.atime));
    println!("anon:        {}:{}", export.anon_uid, export.anon_gid);
    println!(
        "p9_token:    {}",
        export.p9_token.as_ref().map(|_| "set").unwrap_or("-")
    );
    println!(
        "p9_tls_cert: {}",
        export
            .p9_tls_cert
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "p9_tls_key:  {}",
        export
            .p9_tls_key
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "nbd_tls_cert: {}",
        export
            .nbd_tls_cert
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "nbd_tls_key:  {}",
        export
            .nbd_tls_key
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "nbd_tls_client_ca: {}",
        export
            .nbd_tls_client_ca
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("enabled:     {}", export.enabled);
    println!("created_at:  {}", export.created_at);
    println!("updated_at:  {}", export.updated_at);
}

fn print_daemon_node(node: &DaemonNodeRecord) {
    println!(
        "{}\t{:?}\tcapacity={}\theartbeat={}\twritable={}\tread_replicas={}\tsnapshots={}\tops/s={}\tbytes/s={}\tstorage_errors={}\tdegraded={}\tadvertise={}\tadmin={}\tmetrics={}",
        node.id,
        node.state,
        node.capacity_weight,
        node.last_heartbeat_at
            .map(|ts| ts.to_string())
            .unwrap_or_else(|| "-".to_string()),
        node.metrics.open_writable_volumes,
        node.metrics.open_read_replicas,
        node.metrics.open_snapshot_exports,
        node.metrics.request_ops_per_second,
        node.metrics.request_bytes_per_second,
        node.metrics.storage_errors,
        node.metrics.degraded_volumes,
        node.advertise_endpoint.as_deref().unwrap_or("-"),
        node.admin_endpoint.as_deref().unwrap_or("-"),
        node.metrics_endpoint.as_deref().unwrap_or("-")
    );
}

fn print_volume_placement(placement: &VolumePlacementRecord) {
    println!("placement:   {}/{}", placement.tenant, placement.volume);
    println!("state:       {:?}", placement.state);
    println!(
        "primary:     {}",
        placement.primary_node.as_deref().unwrap_or("-")
    );
    println!(
        "standbys:    {}",
        if placement.standby_nodes.is_empty() {
            "-".to_string()
        } else {
            placement.standby_nodes.join(",")
        }
    );
    println!("generation:  {}", placement.generation);
    if let Some(drain) = &placement.drain {
        println!(
            "drain:       {} -> {} started={} completed={}",
            drain.from_node,
            drain.to_node,
            drain.started_at,
            drain
                .completed_at
                .map(|ts| ts.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }
    for endpoint in &placement.stable_endpoints {
        println!(
            "endpoint:    {}\t{}\taddress={}\ttarget={}\tgeneration={}",
            endpoint.name,
            protocol_name(endpoint.protocol),
            endpoint.address,
            endpoint.target_node.as_deref().unwrap_or("-"),
            endpoint.generation
        );
    }
    for replica in &placement.read_replicas {
        println!(
            "replica:     node={}\tlag_seconds={}",
            replica.node_id,
            replica
                .lag_seconds
                .map(|lag| lag.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }
    for pool in &placement.snapshot_pools {
        println!(
            "snapshot_pool: {}\tnodes={}\tmax_exports={}",
            pool.name,
            pool.node_ids.join(","),
            pool.max_exports
        );
    }
}

#[derive(Debug, Clone)]
struct LiveSnapshotResponse {
    id: String,
    manifest_id: u64,
    name: Option<String>,
}

fn percent_encode_query_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        let safe = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

async fn create_live_snapshot_via_admin(
    listen: &str,
    tenant: &str,
    volume: &str,
    name: Option<&str>,
) -> anyhow::Result<LiveSnapshotResponse> {
    let mut path = format!("/snapshot/{tenant}/{volume}");
    if let Some(name) = name {
        path.push_str("?name=");
        path.push_str(&percent_encode_query_value(name));
    }
    let mut stream = TcpStream::connect(listen)
        .await
        .with_context(|| format!("connecting to slatefsd admin endpoint at {listen}"))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {listen}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.shutdown().await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed admin response"))?;
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200 ") {
        let detail = body.trim();
        let detail = if detail.is_empty() { status } else { detail };
        anyhow::bail!("admin snapshot request failed: {detail}");
    }

    let id = body
        .lines()
        .find_map(|line| line.strip_prefix("id="))
        .ok_or_else(|| anyhow::anyhow!("admin response did not include snapshot id"))?
        .to_string();
    let manifest_id = body
        .lines()
        .find_map(|line| line.strip_prefix("manifest="))
        .ok_or_else(|| anyhow::anyhow!("admin response did not include manifest id"))?
        .parse::<u64>()
        .context("parsing admin manifest id")?;
    let name = body
        .lines()
        .find_map(|line| line.strip_prefix("name="))
        .filter(|value| *value != "-")
        .map(str::to_string);
    Ok(LiveSnapshotResponse {
        id,
        manifest_id,
        name,
    })
}

fn admin_bearer_token(config: &Config) -> anyhow::Result<Option<String>> {
    match (&config.admin.token, &config.admin.token_file) {
        (Some(token), None) => Ok(Some(token.clone())),
        (None, Some(path)) => {
            let token = std::fs::read_to_string(path)
                .with_context(|| format!("reading admin token file {}", path.display()))?;
            let token = token.trim().to_string();
            if token.is_empty() {
                anyhow::bail!("admin token file {} is empty", path.display());
            }
            Ok(Some(token))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => {
            anyhow::bail!("admin.token and admin.token_file are mutually exclusive")
        }
    }
}

async fn post_live_versioning_json(
    config: &Config,
    tenant: &str,
    volume: &str,
    operation: &str,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    if config.admin.tls_cert.is_some() {
        anyhow::bail!(
            "live versioning through a TLS admin listener is not yet supported by the CLI"
        );
    }
    let listen = config
        .admin
        .listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--live requires [admin].listen"))?;
    let body = serde_json::to_string(&body)?;
    let path = format!("/admin/v1/tenants/{tenant}/volumes/{volume}/versioning/{operation}");
    let authorization = admin_bearer_token(config)?
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {listen}\r\nContent-Type: application/json\r\n{authorization}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(listen)
        .await
        .with_context(|| format!("connecting to slatefsd admin endpoint at {listen}"))?;
    stream.write_all(request.as_bytes()).await?;
    stream.shutdown().await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed admin response"))?;
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.1 201 ") {
        let detail = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|body| body["error"]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| body.trim().to_string());
        anyhow::bail!("admin versioning request failed: {detail}");
    }
    serde_json::from_str(body).context("parsing admin versioning response")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if let Command::Keygen { out } = &cli.command {
        return keygen(out.as_deref());
    }

    let config = Config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;
    let object_store = store::resolve_root(&config.object_store.url)
        .with_context(|| format!("resolving object store {}", config.object_store.url))?;
    let kms = kms::from_config(&config.kms)?;
    let control = ControlPlane::open(Arc::clone(&object_store), kms)
        .await
        .context("opening control-plane DB")?;

    let result = run(&cli.command, &config, &control, object_store).await;
    let close = control.close().await;
    result?;
    close.context("closing control-plane DB")?;
    Ok(())
}

fn keygen(out: Option<&std::path::Path>) -> anyhow::Result<()> {
    let (secret, public) = LocalAgeKms::generate_identity();
    let contents = format!("# slatefs master key (age identity) — public: {public}\n{secret}\n");
    match out {
        Some(path) => {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("creating {}", path.display()))?;
            f.write_all(contents.as_bytes())?;
            println!(
                "wrote age identity to {} (public: {public})",
                path.display()
            );
        }
        None => print!("{contents}"),
    }
    Ok(())
}

async fn run(
    command: &Command,
    config: &Config,
    control: &ControlPlane,
    object_store: Arc<dyn store::ObjectStore>,
) -> anyhow::Result<()> {
    match command {
        Command::Keygen { .. } => unreachable!("handled before control-plane open"),
        Command::Key(KeyCmd::RotateKek { tenant }) => {
            let count = control.rotate_tenant_kek(tenant).await?;
            println!("rotated tenant KEK for {tenant}; rewrapped {count} volume DEKs");
        }
        Command::Tenant(TenantCmd::Create { name, display_name }) => {
            let record = control.create_tenant(name, display_name.clone()).await?;
            println!(
                "created tenant {} (kms-wrapped KEK, {} bytes)",
                record.name,
                record.wrapped_kek.len()
            );
        }
        Command::Tenant(TenantCmd::Suspend { name }) => {
            let record = control.suspend_tenant(name).await?;
            println!("tenant {} state={:?}", record.name, record.state);
        }
        Command::Tenant(TenantCmd::Resume { name }) => {
            let record = control.resume_tenant(name).await?;
            println!("tenant {} state={:?}", record.name, record.state);
        }
        Command::Tenant(TenantCmd::Delete { name, yes }) => {
            if !yes {
                anyhow::bail!("tenant delete requires --yes");
            }
            let record = control.delete_tenant(name).await?;
            println!(
                "tenant {} state={:?} keys=dropped",
                record.name, record.state
            );
            println!("object-store volume prefixes deleted");
        }
        Command::Tenant(TenantCmd::Rate(command)) => match command {
            TenantRateCmd::Show { name } => {
                let record = control.get_tenant(name).await?;
                print_rate_limits(&record.name, record.rate_limits);
            }
            TenantRateCmd::Set {
                name,
                ops_per_second,
                bytes_per_second,
            } => {
                if ops_per_second.is_none() && bytes_per_second.is_none() {
                    anyhow::bail!("provide at least one rate flag");
                }
                let mut limits = control.get_tenant(name).await?.rate_limits;
                if let Some(raw) = ops_per_second {
                    limits.ops_per_second = parse_optional_u64(raw, "ops-per-second")?;
                }
                if let Some(raw) = bytes_per_second {
                    limits.bytes_per_second = parse_optional_u64(raw, "bytes-per-second")?;
                }
                let record = control.set_tenant_rate_limits(name, limits).await?;
                print_rate_limits(&record.name, record.rate_limits);
                println!(
                    "note: slatefsd reloads tenant rate limits on the export-control poll interval"
                );
            }
        },
        Command::Tenant(TenantCmd::List) => {
            for t in control.list_tenants().await? {
                println!(
                    "{}\t{:?}\tcreated={}\tops/s={}\tbytes/s={}\t{}",
                    t.name,
                    t.state,
                    t.created_at,
                    format_limit(t.rate_limits.ops_per_second),
                    format_limit(t.rate_limits.bytes_per_second),
                    t.display_name.as_deref().unwrap_or("-")
                );
            }
        }
        Command::Volume(VolumeCmd::Create {
            tenant,
            volume,
            kind,
            size,
            chunk_size,
            compression,
            cipher,
            note,
        }) => match kind {
            VolumeCreateKind::Filesystem => {
                if size.is_some() {
                    anyhow::bail!("--size requires --kind block");
                }
                let mut opts = CreateVolumeOptions::from_defaults(&config.volume_defaults);
                if let Some(chunk_size) = chunk_size {
                    opts.chunk_size = *chunk_size;
                }
                if let Some(compression) = compression {
                    opts.compression = *compression;
                }
                if let Some(cipher) = cipher {
                    opts.cipher = cipher.resolve();
                }
                opts.note = note.clone();
                let record =
                    volume::create_volume(control, object_store, tenant, volume, opts).await?;
                println!(
                    "created volume {}/{} fsid={:016x} cipher={} chunk_size={}",
                    record.tenant, record.name, record.fsid, record.cipher, record.chunk_size
                );
            }
            VolumeCreateKind::Block => {
                let size_bytes = size.ok_or_else(|| {
                    anyhow::anyhow!("--kind block requires --size <bytes|K|M|G|T>")
                })?;
                let mut opts =
                    CreateBlockVolumeOptions::from_defaults(&config.volume_defaults, size_bytes);
                if let Some(chunk_size) = chunk_size {
                    opts.chunk_size = *chunk_size;
                }
                if let Some(compression) = compression {
                    opts.compression = *compression;
                }
                if let Some(cipher) = cipher {
                    opts.cipher = cipher.resolve();
                }
                opts.note = note.clone();
                let record =
                    volume::create_block_volume(control, object_store, tenant, volume, opts)
                        .await?;
                let VolumeKind::Block { size_bytes } = record.kind else {
                    unreachable!("create_block_volume returned a non-block volume")
                };
                println!(
                    "created block volume {}/{} fsid={:016x} cipher={} chunk_size={} size_bytes={}",
                    record.tenant,
                    record.name,
                    record.fsid,
                    record.cipher,
                    record.chunk_size,
                    size_bytes
                );
            }
        },
        Command::Volume(VolumeCmd::Info { tenant, volume }) => {
            let info = volume::volume_info(control, object_store, tenant, volume).await?;
            let r = &info.record;
            let sb = &info.superblock;
            println!("volume:      {}/{}", r.tenant, r.name);
            println!("state:       {:?}", r.state);
            println!("fsid:        {:016x}", sb.fsid);
            match sb.kind {
                VolumeKind::Filesystem => println!("kind:        filesystem"),
                VolumeKind::Block { size_bytes } => {
                    println!("kind:        block");
                    println!("size_bytes:  {size_bytes}");
                    println!("allocated:   {}", info.counter_bytes);
                }
            }
            println!("cipher:      {}", sb.cipher);
            println!("chunk_size:  {}", sb.chunk_size);
            println!("compression: {:?}", r.compression);
            println!("name_enc:    {}", sb.name_enc);
            println!("created_at:  {}", sb.created_at);
            println!(
                "quota:       bytes hard={:?} soft={:?}; inodes hard={:?} soft={:?}",
                r.quota.bytes.hard, r.quota.bytes.soft, r.quota.inodes.hard, r.quota.inodes.soft
            );
            if let Some(note) = &r.note {
                println!("note:        {note}");
            }
        }
        Command::Volume(VolumeCmd::List { tenant }) => {
            for v in control.list_volumes(tenant).await? {
                println!(
                    "{}/{}\t{:?}\tfsid={:016x}\tcipher={}\tchunk={}",
                    v.tenant, v.name, v.state, v.fsid, v.cipher, v.chunk_size
                );
            }
        }
        Command::Volume(VolumeCmd::Fsck {
            tenant,
            volume: vol_name,
            recount,
        }) => {
            let record = control.get_volume(tenant, vol_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let report = match record.kind {
                VolumeKind::Filesystem => {
                    let vol = volume::Volume::open(&record, dek, object_store).await?;
                    let report = if *recount {
                        vol.fsck_recount().await?
                    } else {
                        vol.fsck().await?
                    };
                    vol.shutdown().await?;
                    report
                }
                VolumeKind::Block { .. } => {
                    let vol =
                        slatefs_core::block::BlockVolume::open(&record, dek, object_store).await?;
                    let report = if *recount {
                        vol.fsck_recount().await?
                    } else {
                        vol.fsck().await?
                    };
                    vol.shutdown().await?;
                    report
                }
            };

            print_fsck_report(&report);
            if report.is_clean() {
                println!("clean");
            } else if *recount && report.problems.is_empty() {
                println!("counters rewritten from recount");
            } else {
                anyhow::bail!("fsck found problems");
            }
        }
        Command::Volume(VolumeCmd::Scrub { tenant, volume }) => {
            let report = volume::scrub_volume(control, object_store, tenant, volume).await?;
            print_fsck_report(&report);
            if report.is_clean() {
                println!("clean");
            } else {
                anyhow::bail!("scrub found problems or counter drift");
            }
        }
        Command::Volume(VolumeCmd::Resize {
            tenant,
            volume: volume_name,
            size,
        }) => {
            let record =
                volume::resize_block_volume(control, object_store, tenant, volume_name, *size)
                    .await?;
            let VolumeKind::Block { size_bytes } = record.kind else {
                unreachable!("resize_block_volume returned a non-block volume")
            };
            println!(
                "resized block volume {}/{} size_bytes={}",
                record.tenant, record.name, size_bytes
            );
        }
        Command::Volume(VolumeCmd::Delete {
            tenant,
            volume,
            yes,
        }) => {
            if !yes {
                anyhow::bail!("volume delete requires --yes");
            }
            let record = control.delete_volume(tenant, volume).await?;
            println!(
                "volume {}/{} state={:?} key=dropped",
                record.tenant, record.name, record.state
            );
            println!("object-store volume prefix deleted");
        }
        Command::Quota(QuotaCmd::Show { tenant, volume }) => {
            let record = control.get_volume(tenant, volume).await?;
            print_quota(tenant, volume, record.quota);
            let report = volume::scrub_volume(control, object_store, tenant, volume).await?;
            print_quota_usage(&report);
            if !report.counters_match() {
                anyhow::bail!("quota counters differ from recount");
            }
        }
        Command::Quota(QuotaCmd::Set {
            tenant,
            volume,
            bytes_hard,
            bytes_soft,
            bytes_grace_until,
            inodes_hard,
            inodes_soft,
            inodes_grace_until,
        }) => {
            if bytes_hard.is_none()
                && bytes_soft.is_none()
                && bytes_grace_until.is_none()
                && inodes_hard.is_none()
                && inodes_soft.is_none()
                && inodes_grace_until.is_none()
            {
                anyhow::bail!("provide at least one quota flag");
            }

            let mut quota = control.get_volume(tenant, volume).await?.quota;
            if let Some(raw) = bytes_hard {
                quota.bytes.hard = parse_quota_value(raw)?;
            }
            if let Some(raw) = bytes_soft {
                quota.bytes.soft = parse_quota_value(raw)?;
            }
            if let Some(raw) = bytes_grace_until {
                quota.bytes.grace_until = parse_quota_value(raw)?;
            }
            if let Some(raw) = inodes_hard {
                quota.inodes.hard = parse_quota_value(raw)?;
            }
            if let Some(raw) = inodes_soft {
                quota.inodes.soft = parse_quota_value(raw)?;
            }
            if let Some(raw) = inodes_grace_until {
                quota.inodes.grace_until = parse_quota_value(raw)?;
            }
            let record = control.set_volume_quota(tenant, volume, quota).await?;
            print_quota(tenant, volume, record.quota);
            println!(
                "note: slatefsd reloads served-volume quota limits on the export-control poll interval"
            );
        }
        Command::Versioning(VersioningCmd::Enable { tenant, volume }) => {
            let policy = control.set_versioning_enabled(tenant, volume, true).await?;
            println!(
                "versioning enabled for {}/{} (history is created only by explicit commits)",
                policy.tenant, policy.volume
            );
        }
        Command::Versioning(VersioningCmd::Disable { tenant, volume }) => {
            let policy = control
                .set_versioning_enabled(tenant, volume, false)
                .await?;
            println!(
                "versioning disabled for {}/{} (existing history retained)",
                policy.tenant, policy.volume
            );
        }
        Command::Versioning(VersioningCmd::Status { tenant, volume }) => {
            let policy = control.try_get_versioning_policy(tenant, volume).await?;
            println!(
                "versioning:  {}",
                if policy.as_ref().is_some_and(|policy| policy.enabled) {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            if let Some(policy) = policy {
                println!("updated_at:  {}", policy.updated_at);
            }
        }
        Command::Versioning(VersioningCmd::Commit {
            tenant,
            volume: volume_name,
            paths,
            message,
            live,
        }) => {
            if *live {
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume_name,
                    "commits",
                    serde_json::json!({ "paths": paths, "message": message }),
                )
                .await?;
                println!(
                    "commit {}",
                    response["commit"]["id"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("admin response omitted commit id"))?
                );
                return Ok(());
            }
            let repository =
                VersionRepository::open(control, Arc::clone(&object_store), tenant, volume_name)
                    .await?;
            let record = control.get_mountable_volume(tenant, volume_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let live = volume::Volume::open(&record, dek, Arc::clone(&object_store)).await?;
            let commit = repository
                .commit_paths(live.as_ref(), paths, message.clone())
                .await;
            let live_close = live.shutdown().await;
            let repository_close = repository.close().await;
            let commit = commit?;
            live_close?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::VersionCommit,
                tenant,
                volume_name,
                [(
                    "commit".to_string(),
                    AuditDetailValue::String(commit.id.clone()),
                )],
            )
            .await?;
            print_version_commit(&commit);
        }
        Command::Versioning(VersioningCmd::Log {
            tenant,
            volume,
            path,
            limit,
        }) => {
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let history = repository.history(path.as_deref(), *limit).await;
            let repository_close = repository.close().await;
            for commit in history? {
                print_version_commit(&commit);
            }
            repository_close?;
        }
        Command::Versioning(VersioningCmd::Show {
            tenant,
            volume,
            commit,
            path,
            out,
        }) => {
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let contents = repository.read_file(commit, path).await;
            let repository_close = repository.close().await;
            let contents = contents?;
            repository_close?;
            if let Some(out) = out {
                tokio::fs::write(out, &contents)
                    .await
                    .with_context(|| format!("writing {}", out.display()))?;
                println!("wrote {} bytes to {}", contents.len(), out.display());
            } else {
                tokio::io::stdout().write_all(&contents).await?;
            }
        }
        Command::Versioning(VersioningCmd::Restore {
            tenant,
            volume: volume_name,
            commit,
            path,
            live,
        }) => {
            if *live {
                post_live_versioning_json(
                    config,
                    tenant,
                    volume_name,
                    "restore",
                    serde_json::json!({ "commit": commit, "path": path }),
                )
                .await?;
                println!("restored {path} from {commit}");
                return Ok(());
            }
            let repository =
                VersionRepository::open(control, Arc::clone(&object_store), tenant, volume_name)
                    .await?;
            let record = control.get_mountable_volume(tenant, volume_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let live = volume::Volume::open(&record, dek, Arc::clone(&object_store)).await?;
            let restore = repository.restore_file(live.as_ref(), commit, path).await;
            let live_close = live.shutdown().await;
            let repository_close = repository.close().await;
            restore?;
            live_close?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::VersionRestore,
                tenant,
                volume_name,
                [(
                    "commit".to_string(),
                    AuditDetailValue::String(commit.clone()),
                )],
            )
            .await?;
            println!("restored {path} from {commit}");
        }
        Command::Versioning(VersioningCmd::Retention {
            tenant,
            volume,
            keep_last,
            max_age,
            max_bytes,
            clear,
        }) => {
            let mut changed = false;
            if *clear {
                if keep_last.is_some() || max_age.is_some() || max_bytes.is_some() {
                    anyhow::bail!(
                        "--clear cannot be combined with --keep-last, --max-age, or --max-bytes"
                    );
                }
                control
                    .clear_versioning_retention_policy(tenant, volume)
                    .await?;
                changed = true;
            } else if keep_last.is_some() || max_age.is_some() || max_bytes.is_some() {
                control
                    .set_versioning_retention_policy(
                        tenant, volume, *keep_last, *max_age, *max_bytes,
                    )
                    .await?;
                changed = true;
            }
            let policy = control
                .try_get_versioning_retention_policy(tenant, volume)
                .await?;
            println!("versioning_retention: {tenant}/{volume}");
            println!(
                "keep_last: {}",
                format_limit(
                    policy
                        .as_ref()
                        .and_then(|policy| policy.keep_last.map(u64::from))
                )
            );
            println!(
                "max_age_secs: {}",
                format_limit(policy.as_ref().and_then(|policy| policy.max_age_secs))
            );
            println!(
                "max_bytes: {}",
                format_limit(policy.as_ref().and_then(|policy| policy.max_bytes))
            );
            if changed {
                append_cli_version_audit(
                    control,
                    AuditAction::VersionRetentionSet,
                    tenant,
                    volume,
                    std::iter::empty(),
                )
                .await?;
            }
        }
        Command::Versioning(VersioningCmd::Stats { tenant, volume }) => {
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let stats = repository.stats().await;
            let close = repository.close().await;
            let stats = stats?;
            close?;
            println!("bytes: {}", stats.bytes);
            println!("commits: {}", stats.commits);
            println!("nodes: {}", stats.nodes);
            println!("blobs: {}", stats.blobs);
        }
        Command::Versioning(VersioningCmd::Gc {
            tenant,
            volume,
            dry_run,
        }) => {
            let policy = control
                .try_get_versioning_retention_policy(tenant, volume)
                .await?;
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let report = repository
                .garbage_collect(
                    policy.as_ref().and_then(|policy| policy.keep_last),
                    policy.as_ref().and_then(|policy| policy.max_age_secs),
                    *dry_run,
                )
                .await;
            let close = repository.close().await;
            let report = report?;
            close?;
            println!("retained_commits: {}", report.retained_commits);
            println!("deleted_commits: {}", report.deleted_commits);
            println!("deleted_nodes: {}", report.deleted_nodes);
            println!("deleted_blobs: {}", report.deleted_blobs);
            println!("reclaimed_bytes: {}", report.reclaimed_bytes);
            println!("dry_run: {}", report.dry_run);
            if !report.dry_run {
                append_cli_version_audit(
                    control,
                    AuditAction::VersionGc,
                    tenant,
                    volume,
                    [(
                        "reclaimed_bytes".to_string(),
                        AuditDetailValue::U64(report.reclaimed_bytes),
                    )],
                )
                .await?;
            }
        }
        Command::Versioning(VersioningCmd::Purge {
            tenant,
            volume,
            yes,
        }) => {
            if !yes {
                anyhow::bail!("versioning purge requires --yes");
            }
            let deleted = purge_version_history(control, object_store, tenant, volume).await?;
            append_cli_version_audit(
                control,
                AuditAction::VersionPurge,
                tenant,
                volume,
                [(
                    "objects_deleted".to_string(),
                    AuditDetailValue::U64(deleted as u64),
                )],
            )
            .await?;
            println!("purged version history for {tenant}/{volume}: {deleted} objects deleted");
        }
        Command::Snapshot(SnapshotCmd::Create {
            tenant,
            volume: volume_name,
            name,
            live,
        }) => {
            if *live {
                let listen = config.admin.listen.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("snapshot create --live requires [admin].listen")
                })?;
                let created =
                    create_live_snapshot_via_admin(listen, tenant, volume_name, name.as_deref())
                        .await?;
                let snapshot =
                    volume::list_snapshots(control, object_store, tenant, volume_name, None)
                        .await?
                        .into_iter()
                        .find(|snapshot| snapshot.id == created.id)
                        .unwrap_or(volume::SnapshotInfo {
                            id: created.id,
                            manifest_id: created.manifest_id,
                            create_time: "-".to_string(),
                            expire_time: None,
                            name: created.name,
                        });
                print_snapshot(&snapshot);
            } else {
                let snapshot = volume::create_snapshot(
                    control,
                    object_store,
                    tenant,
                    volume_name,
                    name.clone(),
                )
                .await?;
                print_snapshot(&snapshot);
            }
        }
        Command::Snapshot(SnapshotCmd::List {
            tenant,
            volume: volume_name,
            name,
        }) => {
            for snapshot in
                volume::list_snapshots(control, object_store, tenant, volume_name, name.as_deref())
                    .await?
            {
                print_snapshot(&snapshot);
            }
        }
        Command::Snapshot(SnapshotCmd::Delete {
            tenant,
            volume: volume_name,
            id,
        }) => {
            volume::delete_snapshot(control, object_store, tenant, volume_name, id).await?;
            println!("deleted snapshot {id} from {tenant}/{volume_name}");
        }
        Command::Snapshot(SnapshotCmd::Retention(command)) => match command {
            SnapshotRetentionCmd::Show {
                tenant,
                volume: volume_name,
            } => {
                control.get_volume(tenant, volume_name).await?;
                let policy = control
                    .try_get_snapshot_retention_policy(tenant, volume_name)
                    .await?;
                print_snapshot_retention(tenant, volume_name, policy.as_ref());
            }
            SnapshotRetentionCmd::Set {
                tenant,
                volume: volume_name,
                keep_last,
                max_age,
                clear,
            } => {
                if *clear {
                    if keep_last.is_some() || max_age.is_some() {
                        anyhow::bail!("--clear cannot be combined with --keep-last or --max-age");
                    }
                    control
                        .clear_snapshot_retention_policy(tenant, volume_name)
                        .await?;
                    print_snapshot_retention(tenant, volume_name, None);
                } else {
                    if keep_last.is_none() && max_age.is_none() {
                        anyhow::bail!("provide --keep-last, --max-age, or --clear");
                    }
                    let policy = control
                        .set_snapshot_retention_policy(tenant, volume_name, *keep_last, *max_age)
                        .await?;
                    print_snapshot_retention(tenant, volume_name, Some(&policy));
                }
            }
        },
        Command::Clone(CloneCmd::Create {
            tenant,
            source_volume,
            clone_volume,
            snapshot,
            note,
        }) => {
            let record = volume::clone_volume(
                control,
                object_store,
                tenant,
                source_volume,
                clone_volume,
                volume::CloneVolumeOptions {
                    source_snapshot_id: snapshot.clone(),
                    note: note.clone(),
                },
            )
            .await?;
            println!(
                "created clone {}/{} from {}/{} fsid={:016x} cipher={} chunk_size={}",
                record.tenant,
                record.name,
                tenant,
                source_volume,
                record.fsid,
                record.cipher,
                record.chunk_size
            );
        }
        Command::Export(command) => match command {
            ExportCmd::Add {
                id,
                tenant,
                volume,
                snapshot,
                protocol,
                read_only,
                sync,
                listen,
                allowed_clients,
                squash,
                atime,
                anon_uid,
                anon_gid,
                p9_token,
                p9_tls_cert,
                p9_tls_key,
                nbd_tls_cert,
                nbd_tls_key,
                nbd_tls_client_ca,
                disabled,
            } => {
                let record = ExportRecord::from_config(
                    id.clone(),
                    config::ExportConfig {
                        tenant: tenant.clone(),
                        volume: volume.clone(),
                        snapshot: snapshot.clone(),
                        listen: listen.clone(),
                        allowed_clients: allowed_clients.clone(),
                        protocol: *protocol,
                        read_only: *read_only,
                        sync: *sync,
                        nbd_tls_cert: nbd_tls_cert.clone(),
                        nbd_tls_key: nbd_tls_key.clone(),
                        nbd_tls_client_ca: nbd_tls_client_ca.clone(),
                        p9_token: p9_token.clone(),
                        p9_tls_cert: p9_tls_cert.clone(),
                        p9_tls_key: p9_tls_key.clone(),
                        squash: *squash,
                        atime: *atime,
                        anon_uid: *anon_uid,
                        anon_gid: *anon_gid,
                    },
                    !disabled,
                );
                let record = control.create_export(record).await?;
                print_export(&record);
            }
            ExportCmd::List => {
                for export in control.list_exports().await? {
                    println!(
                        "{}\t{}\t{}/{}\tsnapshot={}\tread_only={}\tsync={}\tlisten={}\tenabled={}",
                        export.id,
                        protocol_name(export.protocol),
                        export.tenant,
                        export.volume,
                        export.snapshot.as_deref().unwrap_or("-"),
                        export.effective_read_only(),
                        nbd_sync_name(export.sync),
                        export.listen,
                        export.enabled
                    );
                }
            }
            ExportCmd::Show { id } => {
                let record = control.get_export(id).await?;
                print_export(&record);
            }
            ExportCmd::Update {
                id,
                tenant,
                volume,
                snapshot,
                clear_snapshot,
                protocol,
                read_only,
                sync,
                listen,
                allowed_clients,
                clear_allowed_clients,
                squash,
                atime,
                anon_uid,
                anon_gid,
                p9_token,
                clear_p9_token,
                p9_tls_cert,
                clear_p9_tls_cert,
                p9_tls_key,
                clear_p9_tls_key,
                nbd_tls_cert,
                clear_nbd_tls_cert,
                nbd_tls_key,
                clear_nbd_tls_key,
                nbd_tls_client_ca,
                clear_nbd_tls_client_ca,
                enabled,
            } => {
                let mut record = control.get_export(id).await?;
                if let Some(tenant) = tenant {
                    record.tenant = tenant.clone();
                }
                if let Some(volume) = volume {
                    record.volume = volume.clone();
                }
                FieldUpdate::from_option(snapshot.clone(), *clear_snapshot)
                    .apply_option(&mut record.snapshot);
                if let Some(protocol) = protocol {
                    record.protocol = *protocol;
                }
                if let Some(read_only) = read_only {
                    record.read_only = *read_only;
                }
                if let Some(sync) = sync {
                    record.sync = *sync;
                }
                if let Some(listen) = listen {
                    record.listen = listen.clone();
                }
                FieldUpdate::from_vec(allowed_clients.clone(), *clear_allowed_clients)
                    .apply_vec(&mut record.allowed_clients);
                if let Some(squash) = squash {
                    record.squash = *squash;
                }
                if let Some(atime) = atime {
                    record.atime = *atime;
                }
                if let Some(anon_uid) = anon_uid {
                    record.anon_uid = *anon_uid;
                }
                if let Some(anon_gid) = anon_gid {
                    record.anon_gid = *anon_gid;
                }
                FieldUpdate::from_option(p9_token.clone(), *clear_p9_token)
                    .apply_option(&mut record.p9_token);
                FieldUpdate::from_option(p9_tls_cert.clone(), *clear_p9_tls_cert)
                    .apply_option(&mut record.p9_tls_cert);
                FieldUpdate::from_option(p9_tls_key.clone(), *clear_p9_tls_key)
                    .apply_option(&mut record.p9_tls_key);
                FieldUpdate::from_option(nbd_tls_cert.clone(), *clear_nbd_tls_cert)
                    .apply_option(&mut record.nbd_tls_cert);
                FieldUpdate::from_option(nbd_tls_key.clone(), *clear_nbd_tls_key)
                    .apply_option(&mut record.nbd_tls_key);
                FieldUpdate::from_option(nbd_tls_client_ca.clone(), *clear_nbd_tls_client_ca)
                    .apply_option(&mut record.nbd_tls_client_ca);
                if let Some(enabled) = enabled {
                    record.enabled = *enabled;
                }
                let record = control.update_export(record).await?;
                print_export(&record);
            }
            ExportCmd::Remove { id } => {
                let record = control.remove_export(id).await?;
                println!("removed export {}", record.id);
            }
            ExportCmd::Enable { id } => {
                let record = control.enable_export(id).await?;
                print_export(&record);
            }
            ExportCmd::Disable { id } => {
                let record = control.disable_export(id).await?;
                print_export(&record);
            }
        },
        Command::Fleet(FleetCmd::Node(command)) => match command {
            FleetNodeCmd::Register {
                id,
                advertise_endpoint,
                admin_endpoint,
                metrics_endpoint,
                capacity_weight,
            } => {
                let node = control
                    .register_daemon_node(
                        id,
                        advertise_endpoint.clone(),
                        admin_endpoint.clone(),
                        metrics_endpoint.clone(),
                        *capacity_weight,
                    )
                    .await?;
                print_daemon_node(&node);
            }
            FleetNodeCmd::Heartbeat {
                id,
                state,
                writable_volumes,
                read_replicas,
                snapshot_exports,
                request_ops_per_second,
                request_bytes_per_second,
                storage_errors,
                degraded_volumes,
            } => {
                let node = control
                    .heartbeat_daemon_node(
                        id,
                        *state,
                        DaemonMetrics {
                            open_writable_volumes: *writable_volumes,
                            open_read_replicas: *read_replicas,
                            open_snapshot_exports: *snapshot_exports,
                            request_ops_per_second: *request_ops_per_second,
                            request_bytes_per_second: *request_bytes_per_second,
                            storage_errors: *storage_errors,
                            degraded_volumes: *degraded_volumes,
                        },
                    )
                    .await?;
                print_daemon_node(&node);
            }
            FleetNodeCmd::List => {
                for node in control.list_daemon_nodes().await? {
                    print_daemon_node(&node);
                }
            }
        },
        Command::Fleet(FleetCmd::Volume(command)) => match command {
            FleetVolumeCmd::Placement { tenant, volume } => {
                let placement = control.get_volume_placement(tenant, volume).await?;
                print_volume_placement(&placement);
            }
            FleetVolumeCmd::List => {
                for placement in control.list_volume_placements().await? {
                    println!(
                        "{}/{}\t{:?}\tprimary={}\tstandbys={}\tgeneration={}",
                        placement.tenant,
                        placement.volume,
                        placement.state,
                        placement.primary_node.as_deref().unwrap_or("-"),
                        if placement.standby_nodes.is_empty() {
                            "-".to_string()
                        } else {
                            placement.standby_nodes.join(",")
                        },
                        placement.generation
                    );
                }
            }
            FleetVolumeCmd::Assign {
                tenant,
                volume,
                node,
            } => {
                let placement = match node {
                    Some(node) => control.assign_volume_to_node(tenant, volume, node).await?,
                    None => {
                        control
                            .assign_volume_to_low_load_node(tenant, volume)
                            .await?
                    }
                };
                print_volume_placement(&placement);
            }
            FleetVolumeCmd::Endpoint(FleetEndpointCmd::Set {
                tenant,
                volume,
                name,
                protocol,
                address,
            }) => {
                let placement = control
                    .set_volume_stable_endpoint(tenant, volume, name, *protocol, address.clone())
                    .await?;
                print_volume_placement(&placement);
            }
            FleetVolumeCmd::Promote {
                tenant,
                volume,
                failed_node,
            } => {
                let placement = control
                    .promote_standby_on_failure(tenant, volume, failed_node)
                    .await?;
                print_volume_placement(&placement);
            }
            FleetVolumeCmd::Drain {
                tenant,
                volume,
                target_node,
            } => {
                let placement = control
                    .start_volume_drain(tenant, volume, target_node.as_deref())
                    .await?;
                print_volume_placement(&placement);
                println!("note: start the target daemon/export, then run complete-drain");
            }
            FleetVolumeCmd::CompleteDrain { tenant, volume } => {
                let placement = control.complete_volume_drain(tenant, volume).await?;
                print_volume_placement(&placement);
            }
            FleetVolumeCmd::Replica(command) => match command {
                FleetReplicaCmd::Add {
                    tenant,
                    volume,
                    node,
                    lag_seconds,
                } => {
                    let placement = control
                        .add_read_replica(tenant, volume, node, *lag_seconds)
                        .await?;
                    print_volume_placement(&placement);
                }
                FleetReplicaCmd::Remove {
                    tenant,
                    volume,
                    node,
                } => {
                    let placement = control.remove_read_replica(tenant, volume, node).await?;
                    print_volume_placement(&placement);
                }
            },
            FleetVolumeCmd::SnapshotPool(command) => match command {
                FleetSnapshotPoolCmd::Set {
                    tenant,
                    volume,
                    name,
                    nodes,
                    max_exports,
                } => {
                    let placement = control
                        .set_snapshot_serving_pool(
                            tenant,
                            volume,
                            name,
                            nodes.clone(),
                            *max_exports,
                        )
                        .await?;
                    print_volume_placement(&placement);
                }
                FleetSnapshotPoolCmd::Remove {
                    tenant,
                    volume,
                    name,
                } => {
                    let placement = control
                        .remove_snapshot_serving_pool(tenant, volume, name)
                        .await?;
                    print_volume_placement(&placement);
                }
            },
        },
        Command::Fleet(FleetCmd::Health {
            heartbeat_timeout_secs,
        }) => {
            let stale = control
                .mark_stale_daemon_nodes(*heartbeat_timeout_secs)
                .await?;
            for node in &stale {
                print_daemon_node(node);
            }
            println!("stale_nodes_marked={}", stale.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_bytes_accepts_plain_bytes_and_binary_suffixes() {
        assert_eq!(parse_size_bytes("4096").unwrap(), 4096);
        assert_eq!(parse_size_bytes("1K").unwrap(), 1024);
        assert_eq!(parse_size_bytes("2m").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size_bytes("100G").unwrap(), 100 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_bytes("1T").unwrap(), 1024_u64.pow(4));
    }

    #[test]
    fn parse_size_bytes_rejects_invalid_values() {
        assert!(parse_size_bytes("").is_err());
        assert!(parse_size_bytes("1.5G").is_err());
        assert!(parse_size_bytes("12GB").is_err());
        assert!(parse_size_bytes("K").is_err());
        assert!(parse_size_bytes("18446744073709551615T").is_err());
    }

    #[test]
    fn parses_nbd_export_cli_values() {
        assert_eq!(
            parse_export_protocol("nbd").unwrap(),
            config::ExportProtocol::Nbd
        );
        assert_eq!(
            parse_nbd_sync_mode("strict").unwrap(),
            config::NbdSyncMode::Strict
        );
        assert!(parse_nbd_sync_mode("always").is_err());
    }
}
