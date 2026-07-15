//! `slatefs` — management CLI (plan §13): keygen, key rotation, tenant
//! lifecycle, volume create/info/list/fsck, and quota metadata.

use std::path::PathBuf;
use std::sync::{Arc, Once};

use anyhow::Context;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use slatefs_core::config::{ClientAddrRule, Config};
use slatefs_core::control::{
    AuditAction, AuditActor, AuditDetailValue, AuditOutcome, AuditPlane, AuditRecord, AuditScope,
    ControlPlane, DaemonMetrics, DaemonNodeRecord, DaemonNodeState, ExportRecord, QuotaLimits,
    SnapshotRetentionPolicy, VolumePlacementRecord,
};
use slatefs_core::crypto::kms::{self, LocalAgeKms};
use slatefs_core::meta::superblock::VolumeKind;
use slatefs_core::rate::RateLimits;
use slatefs_core::versioning::{
    VersionAttestationQuorumInfo, VersionBranchInfo, VersionBranchProtectionPolicy,
    VersionBranchRecoveryInfo, VersionBranchResetInfo, VersionCommitAttestation, VersionCommitInfo,
    VersionCommitOrigin, VersionCommitProvenance, VersionMergeConflictStrategy, VersionMergeInfo,
    VersionMergePreview, VersionPathChangeKind, VersionReflogEntry, VersionRepository,
    VersionRepositoryBundleReport, VersionRestoreActionKind, VersionRestoreApplyInfo,
    VersionRestoreMode, VersionRestorePreview, VersionTagInfo, VersionTrustedAttestationKey,
    VersionWorkingTreeChangeKind, VersionWorkingTreeStatus,
    force_break_expired_version_maintenance_lease, purge_version_history,
    try_get_version_maintenance_lease, version_commit_attestation_payload,
};
use slatefs_core::volume::{self, CreateBlockVolumeOptions, CreateVolumeOptions};
use slatefs_core::{config, store};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use zeroize::Zeroizing;

static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionAttestationBundle {
    version: u8,
    repository_id: String,
    commit: String,
    attestations: Vec<VersionCommitAttestation>,
}

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
    Enable {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Disable versioning without deleting existing history.
    Disable {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Show versioning policy and repository lease state.
    Policy {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Export the complete logical version repository to a portable binary bundle.
    ExportRepository {
        tenant: String,
        volume: String,
        /// New bundle file to create.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        live: bool,
    },
    /// Import a portable repository bundle into an uninitialized version repository.
    ImportRepository {
        tenant: String,
        volume: String,
        /// Bundle file to import.
        #[arg(long = "in")]
        input: PathBuf,
        /// Confirm creation of repository history in the destination volume.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        live: bool,
    },
    /// Compare a live subtree with a commit, tag, or branch.
    Status {
        tenant: String,
        volume: String,
        /// Subtree to compare; defaults to all live and versioned paths.
        #[arg(default_value = "/")]
        path: String,
        /// Commit, tag, or branch to compare against.
        #[arg(long, default_value = "main")]
        reference: String,
        #[arg(long)]
        live: bool,
    },
    /// Commit selected files, symlinks, or directory trees.
    Commit {
        tenant: String,
        volume: String,
        /// One or more files or directories. Missing paths record deletions.
        #[arg(required = true, num_args = 1..)]
        paths: Vec<String>,
        #[arg(short, long)]
        message: String,
        /// Claimed content author. Required for offline commits; live commits default to the authenticated principal.
        #[arg(long)]
        author: Option<String>,
        /// Retry key; reuse only for the same branch, canonical paths, message, author, and committer.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Branch to advance.
        #[arg(long, default_value = "main")]
        branch: String,
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
        /// Continue after the last commit ID returned by a previous page.
        #[arg(long)]
        page_token: Option<String>,
        /// Branch whose history to list.
        #[arg(long, default_value = "main")]
        branch: String,
        #[arg(long)]
        live: bool,
    },
    /// Resolve a commit ID, tag, or branch and show the commit and all parents.
    Inspect {
        tenant: String,
        volume: String,
        reference: String,
        #[arg(long)]
        live: bool,
    },
    /// Generate a client-side Ed25519 key for signing version commits.
    AttestationKeygen {
        /// New file that will receive the 32-byte private key with mode 0600.
        #[arg(long)]
        out: PathBuf,
        /// New file that will receive the 32-byte public key.
        #[arg(long)]
        public_out: PathBuf,
    },
    /// Sign a commit with a client-side Ed25519 key and attach the signature.
    Attest {
        tenant: String,
        volume: String,
        reference: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        live: bool,
    },
    /// List commit signatures and optionally require a trusted public key.
    Attestations {
        tenant: String,
        volume: String,
        reference: String,
        /// File containing a trusted 32-byte Ed25519 public key in hex.
        #[arg(long)]
        trusted_public_key: Option<PathBuf>,
        #[arg(long)]
        live: bool,
    },
    /// Export a portable JSON bundle of a commit and its signatures.
    ExportAttestations {
        tenant: String,
        volume: String,
        reference: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        live: bool,
    },
    /// Verify a portable attestation bundle without opening SlateFS.
    VerifyAttestationBundle {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        trusted_public_key: PathBuf,
    },
    /// Compare two commits and list changed paths.
    Diff {
        tenant: String,
        volume: String,
        from: String,
        to: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Continue after the last path returned by a previous page.
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long)]
        live: bool,
    },
    /// Create an immutable tag that pins a commit through retention GC.
    Tag {
        tenant: String,
        volume: String,
        name: String,
        commit: String,
        #[arg(long)]
        live: bool,
    },
    /// List immutable commit tags.
    Tags {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Delete a commit tag so normal retention can reclaim it.
    Untag {
        tenant: String,
        volume: String,
        name: String,
        #[arg(long)]
        live: bool,
    },
    /// Create a movable branch reference at an existing commit, tag, or branch.
    Branch {
        tenant: String,
        volume: String,
        name: String,
        commit: String,
        #[arg(long)]
        live: bool,
    },
    /// List version branches, including the default main branch.
    Branches {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Check whether a commit has enough trusted signatures for a branch.
    QuorumStatus {
        tenant: String,
        volume: String,
        branch: String,
        commit: String,
        /// Exit non-zero when the candidate does not satisfy the branch quorum.
        #[arg(long)]
        check: bool,
        #[arg(long)]
        live: bool,
    },
    /// Protect a branch from reset, deletion, and reflog recovery.
    ProtectBranch {
        tenant: String,
        volume: String,
        name: String,
        /// Authenticated committer identity allowed to publish; repeatable. Empty allows any committer.
        #[arg(long = "allow-committer")]
        allowed_committers: Vec<String>,
        /// Server-derived identity allowed to change protection; repeatable. Empty allows any manager.
        #[arg(long = "allow-manager")]
        allowed_managers: Vec<String>,
        /// Trusted signer as KEY_ID=PUBLIC_KEY_FILE; repeatable. Non-empty requires signed publication.
        #[arg(long = "trust-attestation-key", value_parser = parse_trusted_attestation_key)]
        trusted_attestation_keys: Vec<VersionTrustedAttestationKey>,
        /// Number of distinct trusted signatures required for publication. Defaults to 1 when keys are configured.
        #[arg(long = "require-attestations")]
        required_attestations: Option<u32>,
        #[arg(long)]
        live: bool,
    },
    /// Remove destructive-ref protection from a branch.
    UnprotectBranch {
        tenant: String,
        volume: String,
        name: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        live: bool,
    },
    /// List retained branch-head transitions, including deleted branch history.
    Reflog {
        tenant: String,
        volume: String,
        branch: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        live: bool,
    },
    /// Restore the branch head that preceded one retained reflog entry.
    RecoverBranch {
        tenant: String,
        volume: String,
        name: String,
        sequence: u64,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        live: bool,
    },
    /// Delete a non-main version branch.
    DeleteBranch {
        tenant: String,
        volume: String,
        name: String,
        #[arg(long)]
        live: bool,
    },
    /// Move an existing branch to a commit, tag, or branch without rewriting data.
    ResetBranch {
        tenant: String,
        volume: String,
        name: String,
        commit: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        live: bool,
    },
    /// Merge a source branch into a target branch.
    Merge {
        tenant: String,
        volume: String,
        source: String,
        target: String,
        /// Claimed merge author. Required for offline merges.
        #[arg(long)]
        author: Option<String>,
        /// Resolve conflicts by failing, keeping target paths, or keeping source paths.
        #[arg(long, default_value = "fail", value_parser = parse_version_merge_conflict_strategy)]
        conflict_strategy: VersionMergeConflictStrategy,
        #[arg(long)]
        live: bool,
    },
    /// Preview a branch merge without moving either branch.
    MergePreview {
        tenant: String,
        volume: String,
        source: String,
        target: String,
        #[arg(long)]
        live: bool,
    },
    /// Read a file from a commit, writing it to stdout unless --out is given.
    Show {
        tenant: String,
        volume: String,
        commit: String,
        path: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        live: bool,
    },
    /// Preview an overlay or exact restore without changing the live filesystem.
    RestorePreview {
        tenant: String,
        volume: String,
        commit: String,
        path: String,
        #[arg(long, default_value = "overlay", value_parser = parse_version_restore_mode)]
        mode: VersionRestoreMode,
        #[arg(long)]
        live: bool,
    },
    /// Restore a file, symlink, or directory tree from a commit.
    Restore {
        tenant: String,
        volume: String,
        commit: String,
        path: String,
        #[arg(long, default_value = "overlay", value_parser = parse_version_restore_mode)]
        mode: VersionRestoreMode,
        /// Token returned by `restore-preview` for the same commit, path, and mode.
        #[arg(long)]
        token: String,
        /// Confirm the potentially destructive restore.
        #[arg(long)]
        yes: bool,
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
        #[arg(long)]
        live: bool,
    },
    /// Show logical version-store usage.
    Stats {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Verify the reachable commit chain, Prolly nodes, and content blobs.
    Verify {
        tenant: String,
        volume: String,
        #[arg(long)]
        live: bool,
    },
    /// Remove commits, nodes, and blobs unreachable under the retention policy.
    Gc {
        tenant: String,
        volume: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        live: bool,
    },
    /// Break an expired repository lease after confirming its owner is gone.
    Unlock {
        tenant: String,
        volume: String,
        /// Exact owner UUID reported by `versioning policy`.
        #[arg(long)]
        owner: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        live: bool,
    },
    /// Permanently delete all version history while leaving versioning enabled.
    Purge {
        tenant: String,
        volume: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        live: bool,
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

fn parse_version_merge_conflict_strategy(s: &str) -> Result<VersionMergeConflictStrategy, String> {
    match s {
        "fail" => Ok(VersionMergeConflictStrategy::Fail),
        "ours" => Ok(VersionMergeConflictStrategy::Ours),
        "theirs" => Ok(VersionMergeConflictStrategy::Theirs),
        _ => Err(format!(
            "unknown merge conflict strategy {s:?} (fail|ours|theirs)"
        )),
    }
}

fn parse_version_restore_mode(s: &str) -> Result<VersionRestoreMode, String> {
    match s {
        "overlay" => Ok(VersionRestoreMode::Overlay),
        "exact" => Ok(VersionRestoreMode::Exact),
        _ => Err(format!("unknown restore mode {s:?} (overlay|exact)")),
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
    println!(
        "parents {}",
        if commit.parents.is_empty() {
            "-".to_string()
        } else {
            commit.parents.join(",")
        }
    );
    println!("created {}", commit.created_at);
    println!("author {}", commit.provenance.author());
    println!("committer {}", commit.provenance.committer());
    println!("origin {}", commit.provenance.origin().as_str());
    println!("request {}", commit.provenance.request_id());
    println!("paths {}", commit.paths.join(","));
    println!("message {}", commit.message);
}

fn version_change_label(change: VersionPathChangeKind) -> &'static str {
    match change {
        VersionPathChangeKind::Added => "added",
        VersionPathChangeKind::Modified => "modified",
        VersionPathChangeKind::Deleted => "deleted",
        _ => "unknown",
    }
}

fn working_tree_change_label(change: VersionWorkingTreeChangeKind) -> &'static str {
    match change {
        VersionWorkingTreeChangeKind::Added => "added",
        VersionWorkingTreeChangeKind::Modified => "modified",
        VersionWorkingTreeChangeKind::Deleted => "deleted",
        VersionWorkingTreeChangeKind::TypeChanged => "type-changed",
    }
}

fn print_working_tree_status(status: &VersionWorkingTreeStatus) {
    println!("reference {}\t{}", status.reference(), status.commit());
    println!("root {}", status.root());
    if status.is_clean() {
        println!("clean");
        return;
    }
    for change in status.changes() {
        println!(
            "{}\t{}",
            working_tree_change_label(change.change()),
            change.path()
        );
    }
}

fn restore_action_label(action: VersionRestoreActionKind) -> &'static str {
    match action {
        VersionRestoreActionKind::Create => "create",
        VersionRestoreActionKind::Replace => "replace",
        VersionRestoreActionKind::Delete => "delete",
    }
}

fn print_restore_preview(preview: &VersionRestorePreview) {
    println!("reference {}\t{}", preview.reference(), preview.commit());
    println!("root {}", preview.root());
    println!("mode {}", preview.mode().as_str());
    println!("token {}", preview.token());
    if preview.is_clean() {
        println!("clean");
        return;
    }
    for action in preview.actions() {
        println!(
            "{}\t{}",
            restore_action_label(action.action()),
            action.path()
        );
    }
}

fn print_restore_apply(applied: &VersionRestoreApplyInfo) {
    println!("restored {} from {}", applied.root(), applied.commit());
    println!("reference {}", applied.reference());
    println!("mode {}", applied.mode().as_str());
    println!("actions {}", applied.actions().len());
    println!("atomic {}", applied.atomic());
}

fn print_version_tag(tag: &VersionTagInfo) {
    println!(
        "{}\t{}\tcreated={}",
        tag.name(),
        tag.commit(),
        tag.created_at()
    );
}

fn print_version_branch(branch: &VersionBranchInfo) {
    println!(
        "{}\t{}\tprotected={}",
        branch.name(),
        branch.commit(),
        branch.protected()
    );
    if !branch.allowed_committers().is_empty() {
        println!(
            "allowed_committers {}",
            branch.allowed_committers().join(",")
        );
    }
    if !branch.allowed_managers().is_empty() {
        println!("allowed_managers {}", branch.allowed_managers().join(","));
    }
    for key in branch.trusted_attestation_keys() {
        println!(
            "trusted_attestation_key {}={}",
            key.key_id(),
            hex::encode(key.public_key())
        );
    }
    if branch.protected() {
        println!("required_attestations {}", branch.required_attestations());
    }
}

fn print_attestation_quorum(quorum: &VersionAttestationQuorumInfo) {
    println!("branch {}", quorum.branch());
    println!("commit {}", quorum.commit());
    println!("protected {}", quorum.protected());
    println!("required_attestations {}", quorum.required_attestations());
    println!("matching_attestations {}", quorum.matching_key_ids().len());
    println!("satisfied {}", quorum.satisfied());
    for key_id in quorum.trusted_key_ids() {
        println!("trusted_key {key_id}");
    }
    for key_id in quorum.matching_key_ids() {
        println!("matching_key {key_id}");
    }
}

fn print_version_branch_reset(reset: &VersionBranchResetInfo) {
    println!(
        "{}\t{} -> {}",
        reset.name(),
        reset.previous(),
        reset.commit()
    );
}

fn print_version_reflog_entry(entry: &VersionReflogEntry) {
    println!(
        "{}\t{}\t{}\t{}\t{} -> {}",
        entry.sequence(),
        entry.created_at(),
        entry.action().as_str(),
        entry.branch(),
        entry.previous().unwrap_or("-"),
        entry.commit().unwrap_or("-")
    );
}

fn print_version_branch_recovery(recovery: &VersionBranchRecoveryInfo) {
    println!(
        "{}\treflog={}\t{} -> {}",
        recovery.name(),
        recovery.sequence(),
        recovery.previous().unwrap_or("deleted"),
        recovery.commit()
    );
}

fn print_version_merge(merge: &VersionMergeInfo) {
    println!(
        "{} -> {}\t{}\t{}\tstrategy={}",
        merge.source(),
        merge.target(),
        merge.commit(),
        if merge.fast_forward() {
            "fast-forward"
        } else if merge.already_up_to_date() {
            "already-up-to-date"
        } else {
            "three-way"
        },
        merge.strategy().as_str(),
    );
}

fn print_version_merge_preview(preview: &VersionMergePreview) {
    println!("source {}\t{}", preview.source(), preview.source_head());
    println!("target {}\t{}", preview.target(), preview.target_head());
    println!("merge_base {}", preview.merge_base());
    println!("ahead {}", preview.ahead());
    println!("behind {}", preview.behind());
    println!("fast_forward {}", preview.fast_forward());
    println!("already_up_to_date {}", preview.already_up_to_date());
    println!("can_merge {}", preview.can_merge());
    for conflict in preview.conflicts() {
        println!("conflict {conflict}");
    }
}

async fn stream_version_file<W: AsyncWrite + Unpin>(
    repository: &VersionRepository,
    commit: &str,
    path: &str,
    writer: &mut W,
) -> anyhow::Result<u64> {
    const READ_SIZE: u64 = 4 * 1024 * 1024;
    let mut offset = 0;
    loop {
        let range = repository
            .read_file_range(commit, path, offset, READ_SIZE)
            .await?;
        writer.write_all(&range.data).await?;
        if range.eof {
            writer.flush().await?;
            return Ok(range.total_size);
        }
        if range.data.is_empty() {
            anyhow::bail!("versioned file read did not advance at offset {offset}");
        }
        offset = range.offset + range.data.len() as u64;
    }
}

async fn stream_live_version_file<W: AsyncWrite + Unpin>(
    config: &Config,
    tenant: &str,
    volume: &str,
    commit: &str,
    path: &str,
    writer: &mut W,
) -> anyhow::Result<u64> {
    const READ_SIZE: u64 = 4 * 1024 * 1024;
    let mut offset = 0;
    loop {
        let response = live_versioning_json(
            config,
            tenant,
            volume,
            "GET",
            &format!("commits/{commit}/content"),
            &[
                ("path", path.to_string()),
                ("offset", offset.to_string()),
                ("length", READ_SIZE.to_string()),
            ],
            None,
        )
        .await?;
        let content = &response["content"];
        let returned_offset = content["offset"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("admin response omitted content offset"))?;
        if returned_offset != offset {
            anyhow::bail!(
                "admin content response returned offset {returned_offset}, expected {offset}"
            );
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(
                content["data"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("admin response omitted content data"))?,
            )
            .context("decoding admin version content")?;
        writer.write_all(&data).await?;
        let total_size = content["total_size"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("admin response omitted total_size"))?;
        let eof = content["eof"]
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("admin response omitted eof"))?;
        if eof {
            writer.flush().await?;
            return Ok(total_size);
        }
        if data.is_empty() {
            anyhow::bail!("admin version content did not advance at offset {offset}");
        }
        offset = offset.saturating_add(data.len() as u64);
    }
}

async fn append_cli_version_audit(
    control: &ControlPlane,
    action: AuditAction,
    tenant: &str,
    volume: &str,
    details: impl IntoIterator<Item = (String, AuditDetailValue)>,
) -> anyhow::Result<()> {
    append_cli_version_audit_with_request_id(
        control,
        action,
        tenant,
        volume,
        format!("cli-versioning-{}", uuid::Uuid::new_v4()),
        details,
    )
    .await
}

async fn append_cli_version_audit_with_request_id(
    control: &ControlPlane,
    action: AuditAction,
    tenant: &str,
    volume: &str,
    request_id: String,
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
        request_id,
        AuditOutcome::Success,
    );
    record.details.extend(details);
    control.append_audit_record(record).await?;
    Ok(())
}

fn offline_commit_provenance(
    author: Option<&String>,
    request_id: String,
) -> anyhow::Result<VersionCommitProvenance> {
    let author =
        author.ok_or_else(|| anyhow::anyhow!("offline version commits require --author"))?;
    VersionCommitProvenance::new(
        VersionCommitOrigin::Cli,
        author.clone(),
        author.clone(),
        request_id,
    )
    .map_err(anyhow::Error::from)
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

fn admin_bearer_token(config: &Config, tenant: &str) -> anyhow::Result<Option<String>> {
    if let Some(token) = config.admin.tenant_tokens.get(tenant) {
        return Ok(Some(token.clone()));
    }
    if let Some(path) = config.admin.tenant_token_files.get(tenant) {
        let tokens = config::load_bearer_token_file(path)?;
        return Ok(tokens.into_iter().next());
    }
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

fn load_pem_certificates(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading certificate file {}", path.display()))?;
    rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("parsing certificate file {}", path.display()))
}

fn load_pem_private_key(path: &std::path::Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading private key file {}", path.display()))?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .with_context(|| format!("parsing private key file {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("private key file {} contains no key", path.display()))
}

fn admin_tls_client_config(config: &Config) -> anyhow::Result<Arc<ClientConfig>> {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let custom_trust = config
        .admin
        .tls_server_ca
        .as_deref()
        .or(config.admin.tls_cert.as_deref());
    if let Some(path) = custom_trust {
        for certificate in load_pem_certificates(path)? {
            roots
                .add(certificate)
                .with_context(|| format!("adding admin TLS trust from {}", path.display()))?;
        }
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let client = match (
        config.admin.tls_client_cert.as_deref(),
        config.admin.tls_client_key.as_deref(),
    ) {
        (Some(cert), Some(key)) => builder
            .with_client_auth_cert(load_pem_certificates(cert)?, load_pem_private_key(key)?)
            .context("configuring admin mTLS client identity")?,
        (None, None) => builder.with_no_client_auth(),
        _ => {
            anyhow::bail!("admin.tls_client_cert and admin.tls_client_key must both be configured")
        }
    };
    Ok(Arc::new(client))
}

async fn exchange_admin_stream<S>(mut stream: S, request: &[u8]) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn admin_http_exchange(
    config: &Config,
    listen: &str,
    request: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let stream = TcpStream::connect(listen)
        .await
        .with_context(|| format!("connecting to slatefsd admin endpoint at {listen}"))?;
    let tls_enabled = config.admin.tls_cert.is_some()
        || config.admin.tls_server_ca.is_some()
        || config.admin.tls_server_name.is_some()
        || config.admin.tls_client_cert.is_some();
    if !tls_enabled {
        return exchange_admin_stream(stream, request).await;
    }
    let addr = stream
        .peer_addr()
        .context("reading admin TLS peer address")?;
    let server_name = match &config.admin.tls_server_name {
        Some(name) => ServerName::try_from(name.clone())
            .map_err(|error| anyhow::anyhow!("invalid admin.tls_server_name: {error}"))?,
        None => ServerName::IpAddress(addr.ip().into()),
    };
    let connector = TlsConnector::from(admin_tls_client_config(config)?);
    let stream = connector
        .connect(server_name, stream)
        .await
        .context("establishing admin TLS connection")?;
    exchange_admin_stream(stream, request).await
}

async fn live_versioning_json(
    config: &Config,
    tenant: &str,
    volume: &str,
    method: &str,
    suffix: &str,
    query: &[(&str, String)],
    body: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let listen = config
        .admin
        .listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--live requires [admin].listen"))?;
    let body = body
        .map(|body| serde_json::to_string(&body))
        .transpose()?
        .unwrap_or_default();
    let mut path = format!("/admin/v1/tenants/{tenant}/volumes/{volume}/versioning");
    if !suffix.is_empty() {
        path.push('/');
        path.push_str(suffix);
    }
    if !query.is_empty() {
        path.push('?');
        for (index, (key, value)) in query.iter().enumerate() {
            if index > 0 {
                path.push('&');
            }
            path.push_str(key);
            path.push('=');
            path.push_str(&percent_encode_query_value(value));
        }
    }
    let authorization = admin_bearer_token(config, tenant)?
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {listen}\r\nContent-Type: application/json\r\n{authorization}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = admin_http_exchange(config, listen, request.as_bytes()).await?;
    let (head, body) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| (&response[..position], &response[position + 4..]))
        .ok_or_else(|| anyhow::anyhow!("malformed admin response"))?;
    let head = std::str::from_utf8(head).context("admin response headers are not UTF-8")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.1 201 ") {
        let detail = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|body| body["error"]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string());
        anyhow::bail!("admin versioning request failed: {detail}");
    }
    serde_json::from_slice(body).context("parsing admin versioning response")
}

async fn post_live_versioning_json(
    config: &Config,
    tenant: &str,
    volume: &str,
    operation: &str,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    live_versioning_json(config, tenant, volume, "POST", operation, &[], Some(body)).await
}

async fn live_versioning_bundle(
    config: &Config,
    tenant: &str,
    volume: &str,
    method: &str,
    bundle: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let listen = config
        .admin
        .listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--live requires [admin].listen"))?;
    let authorization = admin_bearer_token(config, tenant)?
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let body = bundle.unwrap_or_default();
    let mut request = format!(
        "{method} /admin/v1/tenants/{tenant}/volumes/{volume}/versioning/bundle HTTP/1.1\r\nHost: {listen}\r\nContent-Type: application/vnd.slatefs.version-repository\r\n{authorization}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    let response = admin_http_exchange(config, listen, &request).await?;
    let (head, body) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| (&response[..position], &response[position + 4..]))
        .ok_or_else(|| anyhow::anyhow!("malformed admin response"))?;
    let head = std::str::from_utf8(head).context("admin response headers are not UTF-8")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.1 201 ") {
        let detail = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|body| body["error"]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string());
        anyhow::bail!("admin versioning request failed: {detail}");
    }
    Ok(body.to_vec())
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
    if let Command::Versioning(VersioningCmd::AttestationKeygen { out, public_out }) = &cli.command
    {
        return version_attestation_keygen(out, public_out);
    }
    if let Command::Versioning(VersioningCmd::VerifyAttestationBundle {
        input,
        trusted_public_key,
    }) = &cli.command
    {
        return verify_attestation_bundle_file(input, trusted_public_key);
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

fn version_attestation_keygen(
    private_path: &std::path::Path,
    public_path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let secret = slatefs_core::crypto::Secret32::generate();
    let signing_key = SigningKey::from_bytes(secret.expose_secret());
    let public_key = signing_key.verifying_key().to_bytes();
    let contents = Zeroizing::new(format!(
        "# slatefs Ed25519 version attestation private key\n# public: {}\n{}\n",
        hex::encode(public_key),
        hex::encode(secret.expose_secret())
    ));
    let mut private_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(private_path)
        .with_context(|| format!("creating {}", private_path.display()))?;
    let public_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(public_path);
    let mut public_file = match public_file {
        Ok(file) => file,
        Err(error) => {
            drop(private_file);
            let _ = std::fs::remove_file(private_path);
            return Err(error).with_context(|| format!("creating {}", public_path.display()));
        }
    };
    private_file.write_all(contents.as_bytes())?;
    public_file.write_all(format!("{}\n", hex::encode(public_key)).as_bytes())?;
    println!("wrote Ed25519 private key to {}", private_path.display());
    println!("wrote Ed25519 public key to {}", public_path.display());
    Ok(())
}

fn read_ed25519_signing_key(path: &std::path::Path) -> anyhow::Result<SigningKey> {
    let contents = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading Ed25519 private key from {}", path.display()))?,
    );
    let value = contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("private key file {} is empty", path.display()))?;
    let decoded = Zeroizing::new(
        hex::decode(value)
            .with_context(|| format!("decoding private key in {} as hex", path.display()))?,
    );
    let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "private key in {} must contain exactly 32 bytes, found {}",
            path.display(),
            decoded.len()
        )
    })?;
    let bytes = Zeroizing::new(bytes);
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_hex_key<const N: usize>(path: &std::path::Path, what: &str) -> anyhow::Result<[u8; N]> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading {what} from {}", path.display()))?;
    let value = contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("{what} file {} is empty", path.display()))?;
    let decoded = hex::decode(value)
        .with_context(|| format!("decoding {what} in {} as hex", path.display()))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "{what} in {} must contain exactly {N} bytes, found {}",
            path.display(),
            bytes.len()
        )
    })
}

fn write_attestation_bundle(
    path: &std::path::Path,
    bundle: &VersionAttestationBundle,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    let json = serde_json::to_vec_pretty(bundle)?;
    file.write_all(&json)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn write_repository_bundle(path: &std::path::Path, bundle: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    if let Err(error) = file.write_all(bundle).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

fn print_repository_bundle_report(report: &VersionRepositoryBundleReport) {
    println!("repository_id: {}", report.identity.id());
    println!("repository_created_at: {}", report.identity.created_at());
    println!("bundle_bytes: {}", report.bundle_bytes);
    println!("logical_bytes: {}", report.logical_bytes);
    println!("objects: {}", report.objects);
    println!("commits: {}", report.commits);
    println!("pruned_commits: {}", report.pruned_commits);
    println!("attestations: {}", report.attestations);
    println!("nodes: {}", report.nodes);
    println!("blobs: {}", report.blobs);
    println!("branches: {}", report.branches);
    println!("tags: {}", report.tags);
    println!("reflogs: {}", report.reflogs);
}

fn read_attestation_bundle(path: &std::path::Path) -> anyhow::Result<VersionAttestationBundle> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening attestation bundle {}", path.display()))?;
    let bundle: VersionAttestationBundle = serde_json::from_reader(file)
        .with_context(|| format!("parsing attestation bundle {}", path.display()))?;
    if bundle.version != 2 {
        anyhow::bail!(
            "attestation bundle {} has unsupported version {}",
            path.display(),
            bundle.version
        );
    }
    Ok(bundle)
}

fn verify_attestation_bundle_file(
    input: &std::path::Path,
    trusted_public_key: &std::path::Path,
) -> anyhow::Result<()> {
    let bundle = read_attestation_bundle(input)?;
    let trusted = read_hex_key::<32>(trusted_public_key, "trusted Ed25519 public key")?;
    print_version_attestations(
        &bundle.repository_id,
        &bundle.commit,
        &bundle.attestations,
        Some(trusted),
    )?;
    println!("bundle: verified");
    println!("repository_id: {}", bundle.repository_id);
    println!("commit: {}", bundle.commit);
    Ok(())
}

fn parse_trusted_attestation_key(value: &str) -> Result<VersionTrustedAttestationKey, String> {
    let (key_id, path) = value
        .split_once('=')
        .ok_or_else(|| "expected KEY_ID=PUBLIC_KEY_FILE".to_string())?;
    let public_key = read_hex_key::<32>(std::path::Path::new(path), "trusted Ed25519 public key")
        .map_err(|error| error.to_string())?;
    VersionTrustedAttestationKey::new_ed25519(key_id, public_key).map_err(|error| error.to_string())
}

fn print_version_attestation(attestation: &VersionCommitAttestation, trusted: Option<bool>) {
    println!("key_id: {}", attestation.key_id());
    println!("algorithm: {}", attestation.algorithm().as_str());
    println!("public_key: {}", hex::encode(attestation.public_key()));
    println!("signature: {}", hex::encode(attestation.signature()));
    println!("created_at: {}", attestation.created_at());
    if let Some(trusted) = trusted {
        println!("trusted: {trusted}");
    }
}

fn create_version_attestation(
    repository_id: &str,
    commit: &str,
    key_id: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<VersionCommitAttestation> {
    let public_key = signing_key.verifying_key().to_bytes();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let payload =
        version_commit_attestation_payload(repository_id, commit, key_id, &public_key, created_at)?;
    VersionCommitAttestation::new_ed25519(
        key_id,
        public_key,
        signing_key.sign(&payload).to_bytes(),
        created_at,
    )
    .map_err(Into::into)
}

fn print_version_attestations(
    repository_id: &str,
    commit: &str,
    attestations: &[VersionCommitAttestation],
    trusted: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    for attestation in attestations {
        verify_version_attestation(repository_id, commit, attestation)?;
    }
    if let Some(trusted) = trusted
        && !attestations
            .iter()
            .any(|attestation| attestation.public_key() == trusted)
    {
        anyhow::bail!("commit {commit} has no attestation from the trusted public key");
    }
    for (index, attestation) in attestations.iter().enumerate() {
        if index > 0 {
            println!();
        }
        print_version_attestation(
            attestation,
            trusted.map(|key| attestation.public_key() == key),
        );
    }
    Ok(())
}

fn verify_version_attestation(
    repository_id: &str,
    commit: &str,
    attestation: &VersionCommitAttestation,
) -> anyhow::Result<()> {
    let public_key: &[u8; 32] = attestation
        .public_key()
        .try_into()
        .context("attestation Ed25519 public key is not 32 bytes")?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .context("attestation contains an invalid Ed25519 public key")?;
    let signature = Signature::from_slice(attestation.signature())
        .context("attestation Ed25519 signature is not 64 bytes")?;
    let payload = version_commit_attestation_payload(
        repository_id,
        commit,
        attestation.key_id(),
        attestation.public_key(),
        attestation.created_at(),
    )?;
    verifying_key
        .verify_strict(&payload, &signature)
        .context("attestation signature verification failed")
}

async fn run(
    command: &Command,
    config: &Config,
    control: &ControlPlane,
    object_store: Arc<dyn store::ObjectStore>,
) -> anyhow::Result<()> {
    match command {
        Command::Keygen { .. } => unreachable!("handled before control-plane open"),
        Command::Versioning(VersioningCmd::AttestationKeygen { .. }) => {
            unreachable!("handled before control-plane open")
        }
        Command::Versioning(VersioningCmd::VerifyAttestationBundle { .. }) => {
            unreachable!("handled before control-plane open")
        }
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
        Command::Versioning(VersioningCmd::Enable {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "PATCH",
                    "",
                    &[],
                    Some(serde_json::json!({ "enabled": true })),
                )
                .await?;
                println!(
                    "versioning enabled for {tenant}/{volume} (history is created only by explicit commits)"
                );
                return Ok(());
            }
            let policy = control.set_versioning_enabled(tenant, volume, true).await?;
            println!(
                "versioning enabled for {}/{} (history is created only by explicit commits)",
                policy.tenant, policy.volume
            );
        }
        Command::Versioning(VersioningCmd::Disable {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "PATCH",
                    "",
                    &[],
                    Some(serde_json::json!({ "enabled": false })),
                )
                .await?;
                println!("versioning disabled for {tenant}/{volume} (existing history retained)");
                return Ok(());
            }
            let policy = control
                .set_versioning_enabled(tenant, volume, false)
                .await?;
            println!(
                "versioning disabled for {}/{} (existing history retained)",
                policy.tenant, policy.volume
            );
        }
        Command::Versioning(VersioningCmd::Policy {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "", &[], None).await?;
                let versioning = &response["versioning"];
                println!(
                    "versioning:  {}",
                    if versioning["enabled"].as_bool().unwrap_or(false) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                if let Some(updated_at) = versioning["updated_at"].as_u64() {
                    println!("updated_at:  {updated_at}");
                }
                if let Some(lease) = versioning["lease"].as_object() {
                    println!(
                        "lease:       {} ({})",
                        if lease["expired"].as_bool().unwrap_or(true) {
                            "expired"
                        } else {
                            "active"
                        },
                        lease["operation"].as_str().unwrap_or("unknown")
                    );
                    println!(
                        "lease_owner: {}",
                        lease["owner"].as_str().unwrap_or("unknown")
                    );
                    if let Some(expires_at) = lease["expires_at"].as_u64() {
                        println!("lease_until: {expires_at}");
                    }
                } else {
                    println!("lease:       none");
                }
                return Ok(());
            }
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
            match try_get_version_maintenance_lease(object_store, tenant, volume).await? {
                Some(lease) => {
                    println!(
                        "lease:       {} ({})",
                        if lease.is_expired_at(slatefs_core::control::now_unix()) {
                            "expired"
                        } else {
                            "active"
                        },
                        lease.operation()
                    );
                    println!("lease_owner: {}", lease.owner());
                    println!("lease_until: {}", lease.expires_at());
                }
                None => println!("lease:       none"),
            }
        }
        Command::Versioning(VersioningCmd::ExportRepository {
            tenant,
            volume,
            out,
            live,
        }) => {
            let (bundle, report) = if *live {
                let bundle = live_versioning_bundle(config, tenant, volume, "GET", None).await?;
                let report = VersionRepository::inspect_bundle(&bundle)?;
                (bundle, report)
            } else {
                let repository =
                    VersionRepository::open(control, object_store, tenant, volume).await?;
                let result = repository.export_bundle().await;
                let close = repository.close().await;
                let exported = result?;
                close?;
                exported
            };
            write_repository_bundle(out, &bundle)?;
            if !*live {
                append_cli_version_audit(
                    control,
                    AuditAction::VersionRepositoryExport,
                    tenant,
                    volume,
                    [
                        (
                            "repository_id".to_string(),
                            AuditDetailValue::String(report.identity.id().to_string()),
                        ),
                        (
                            "bundle_bytes".to_string(),
                            AuditDetailValue::U64(report.bundle_bytes),
                        ),
                    ],
                )
                .await?;
            }
            println!("wrote repository bundle to {}", out.display());
            print_repository_bundle_report(&report);
        }
        Command::Versioning(VersioningCmd::ImportRepository {
            tenant,
            volume,
            input,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!("versioning import-repository requires --yes");
            }
            let bundle = std::fs::read(input)
                .with_context(|| format!("reading repository bundle {}", input.display()))?;
            let inspected = VersionRepository::inspect_bundle(&bundle)?;
            let report = if *live {
                let response =
                    live_versioning_bundle(config, tenant, volume, "POST", Some(&bundle)).await?;
                let response: serde_json::Value = serde_json::from_slice(&response)
                    .context("parsing admin repository import response")?;
                serde_json::from_value(response["repository_bundle"].clone())
                    .context("parsing imported repository bundle report")?
            } else {
                let report = VersionRepository::import_bundle(
                    control,
                    object_store,
                    tenant,
                    volume,
                    &bundle,
                )
                .await?;
                append_cli_version_audit(
                    control,
                    AuditAction::VersionRepositoryImport,
                    tenant,
                    volume,
                    [
                        (
                            "repository_id".to_string(),
                            AuditDetailValue::String(report.identity.id().to_string()),
                        ),
                        (
                            "bundle_bytes".to_string(),
                            AuditDetailValue::U64(report.bundle_bytes),
                        ),
                    ],
                )
                .await?;
                report
            };
            if report != inspected {
                anyhow::bail!("imported repository report does not match the source bundle");
            }
            println!(
                "imported repository bundle from {} into {tenant}/{volume}",
                input.display()
            );
            print_repository_bundle_report(&report);
        }
        Command::Versioning(VersioningCmd::Status {
            tenant,
            volume: volume_name,
            path,
            reference,
            live,
        }) => {
            if *live {
                let query = vec![("reference", reference.clone()), ("path", path.clone())];
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume_name,
                    "GET",
                    "status",
                    &query,
                    None,
                )
                .await?;
                let status: VersionWorkingTreeStatus =
                    serde_json::from_value(response["status"].clone())
                        .context("parsing admin working tree status")?;
                print_working_tree_status(&status);
                return Ok(());
            }
            let repository =
                VersionRepository::open(control, Arc::clone(&object_store), tenant, volume_name)
                    .await?;
            let record = control.get_mountable_volume(tenant, volume_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let live = volume::Volume::open(&record, dek, Arc::clone(&object_store)).await?;
            let result = repository
                .working_tree_status(live.as_ref(), reference, path)
                .await;
            let live_close = live.shutdown().await;
            let repository_close = repository.close().await;
            let status = result?;
            live_close?;
            repository_close?;
            print_working_tree_status(&status);
        }
        Command::Versioning(VersioningCmd::Commit {
            tenant,
            volume: volume_name,
            paths,
            message,
            author,
            idempotency_key,
            branch,
            live,
        }) => {
            if *live {
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume_name,
                    "commits",
                    serde_json::json!({
                        "paths": paths,
                        "message": message,
                        "author": author,
                        "idempotency_key": idempotency_key,
                        "branch": branch,
                    }),
                )
                .await?;
                let commit: VersionCommitInfo = serde_json::from_value(response["commit"].clone())
                    .context("parsing admin version commit")?;
                print_version_commit(&commit);
                if response["replayed"].as_bool().unwrap_or(false) {
                    println!("replayed true");
                }
                return Ok(());
            }
            let repository =
                VersionRepository::open(control, Arc::clone(&object_store), tenant, volume_name)
                    .await?;
            let record = control.get_mountable_volume(tenant, volume_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let live = volume::Volume::open(&record, dek, Arc::clone(&object_store)).await?;
            let request_id = format!("cli-versioning-{}", uuid::Uuid::new_v4());
            let provenance = offline_commit_provenance(author.as_ref(), request_id.clone())?;
            let commit = match idempotency_key.as_deref() {
                Some(key) => repository
                    .commit_volume_paths_on_branch_idempotent(
                        live.as_ref(),
                        branch,
                        paths,
                        message.clone(),
                        provenance,
                        key,
                    )
                    .await
                    .map(|result| {
                        let replayed = result.replayed();
                        (result.into_commit(), replayed)
                    }),
                None => repository
                    .commit_volume_paths_on_branch(
                        live.as_ref(),
                        branch,
                        paths,
                        message.clone(),
                        provenance,
                    )
                    .await
                    .map(|commit| (commit, false)),
            };
            let live_close = live.shutdown().await;
            let repository_close = repository.close().await;
            let (commit, replayed) = commit?;
            live_close?;
            repository_close?;
            append_cli_version_audit_with_request_id(
                control,
                AuditAction::VersionCommit,
                tenant,
                volume_name,
                request_id,
                [
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(commit.id.clone()),
                    ),
                    ("replayed".to_string(), AuditDetailValue::Bool(replayed)),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(branch.clone()),
                    ),
                    (
                        "author".to_string(),
                        AuditDetailValue::String(commit.provenance.author().to_string()),
                    ),
                    (
                        "committer".to_string(),
                        AuditDetailValue::String(commit.provenance.committer().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_commit(&commit);
            if replayed {
                println!("replayed true");
            }
        }
        Command::Versioning(VersioningCmd::Log {
            tenant,
            volume,
            path,
            limit,
            page_token,
            branch,
            live,
        }) => {
            if *live {
                let mut query = vec![("limit", limit.to_string())];
                query.push(("branch", branch.clone()));
                if let Some(path) = path {
                    query.push(("path", path.clone()));
                }
                if let Some(page_token) = page_token {
                    query.push(("page_token", page_token.clone()));
                }
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "commits", &query, None)
                        .await?;
                let commits: Vec<VersionCommitInfo> =
                    serde_json::from_value(response["commits"].clone())
                        .context("parsing admin version history")?;
                for commit in commits {
                    print_version_commit(&commit);
                }
                if let Some(next) = response["next_page_token"].as_str() {
                    println!("next_page_token: {next}");
                }
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let history = repository
                .history_page_on_branch(branch, path.as_deref(), *limit, page_token.as_deref())
                .await;
            let repository_close = repository.close().await;
            let (commits, next_page_token) = history?;
            for commit in commits {
                print_version_commit(&commit);
            }
            if let Some(next) = next_page_token {
                println!("next_page_token: {next}");
            }
            repository_close?;
        }
        Command::Versioning(VersioningCmd::Inspect {
            tenant,
            volume,
            reference,
            live,
        }) => {
            if *live {
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &format!("commits/{reference}"),
                    &[],
                    None,
                )
                .await?;
                let commit: VersionCommitInfo = serde_json::from_value(response["commit"].clone())
                    .context("parsing admin version commit")?;
                print_version_commit(&commit);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.inspect_commit(reference).await;
            let repository_close = repository.close().await;
            let commit = result?;
            repository_close?;
            print_version_commit(&commit);
        }
        Command::Versioning(VersioningCmd::Attest {
            tenant,
            volume,
            reference,
            key_id,
            key_file,
            live,
        }) => {
            let signing_key = read_ed25519_signing_key(key_file)?;
            if *live {
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &format!("commits/{reference}"),
                    &[],
                    None,
                )
                .await?;
                let commit: VersionCommitInfo = serde_json::from_value(response["commit"].clone())
                    .context("parsing admin version commit")?;
                let repository_id = response["repository_id"]
                    .as_str()
                    .context("admin version commit response is missing repository_id")?;
                let attestation =
                    create_version_attestation(repository_id, &commit.id, key_id, &signing_key)?;
                let body = serde_json::to_value(&attestation)?;
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume,
                    &format!("commits/{}/attestations", commit.id),
                    body,
                )
                .await?;
                let attestation: VersionCommitAttestation =
                    serde_json::from_value(response["attestation"].clone())
                        .context("parsing admin version commit attestation")?;
                println!("commit: {}", commit.id);
                print_version_attestation(&attestation, None);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result: anyhow::Result<_> = async {
                let commit = repository.inspect_commit(reference).await?;
                let attestation = create_version_attestation(
                    repository.identity().id(),
                    &commit.id,
                    key_id,
                    &signing_key,
                )?;
                let attestation = repository
                    .add_commit_attestation(&commit.id, attestation)
                    .await?;
                Ok((commit.id, attestation))
            }
            .await;
            let close = repository.close().await;
            let (commit, attestation) = result?;
            close?;
            append_cli_version_audit(
                control,
                AuditAction::VersionAttest,
                tenant,
                volume,
                [
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(commit.clone()),
                    ),
                    (
                        "key_id".to_string(),
                        AuditDetailValue::String(attestation.key_id().to_string()),
                    ),
                ],
            )
            .await?;
            println!("commit: {commit}");
            print_version_attestation(&attestation, None);
        }
        Command::Versioning(VersioningCmd::Attestations {
            tenant,
            volume,
            reference,
            trusted_public_key,
            live,
        }) => {
            let trusted = trusted_public_key
                .as_deref()
                .map(|path| read_hex_key::<32>(path, "trusted Ed25519 public key"))
                .transpose()?;
            if *live {
                let commit_response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &format!("commits/{reference}"),
                    &[],
                    None,
                )
                .await?;
                let commit: VersionCommitInfo =
                    serde_json::from_value(commit_response["commit"].clone())
                        .context("parsing admin version commit")?;
                let repository_id = commit_response["repository_id"]
                    .as_str()
                    .context("admin version commit response is missing repository_id")?;
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &format!("commits/{}/attestations", commit.id),
                    &[],
                    None,
                )
                .await?;
                let attestations: Vec<VersionCommitAttestation> =
                    serde_json::from_value(response["attestations"].clone())
                        .context("parsing admin version commit attestations")?;
                print_version_attestations(repository_id, &commit.id, &attestations, trusted)?;
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result: anyhow::Result<_> = async {
                let commit = repository.inspect_commit(reference).await?;
                let attestations = repository.list_commit_attestations(&commit.id).await?;
                Ok((
                    repository.identity().id().to_string(),
                    commit.id,
                    attestations,
                ))
            }
            .await;
            let close = repository.close().await;
            let (repository_id, commit, attestations) = result?;
            close?;
            print_version_attestations(&repository_id, &commit, &attestations, trusted)?;
        }
        Command::Versioning(VersioningCmd::ExportAttestations {
            tenant,
            volume,
            reference,
            out,
            live,
        }) => {
            let (repository_id, commit, attestations) = if *live {
                let commit_response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &format!("commits/{reference}"),
                    &[],
                    None,
                )
                .await?;
                let commit: VersionCommitInfo =
                    serde_json::from_value(commit_response["commit"].clone())
                        .context("parsing admin version commit")?;
                let repository_id = commit_response["repository_id"]
                    .as_str()
                    .context("admin version commit response is missing repository_id")?
                    .to_string();
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &format!("commits/{}/attestations", commit.id),
                    &[],
                    None,
                )
                .await?;
                let attestations = serde_json::from_value(response["attestations"].clone())
                    .context("parsing admin version commit attestations")?;
                (repository_id, commit.id, attestations)
            } else {
                let repository =
                    VersionRepository::open(control, object_store, tenant, volume).await?;
                let result: anyhow::Result<_> = async {
                    let commit = repository.inspect_commit(reference).await?;
                    let attestations = repository.list_commit_attestations(&commit.id).await?;
                    Ok((
                        repository.identity().id().to_string(),
                        commit.id,
                        attestations,
                    ))
                }
                .await;
                let close = repository.close().await;
                let result = result?;
                close?;
                result
            };
            for attestation in &attestations {
                verify_version_attestation(&repository_id, &commit, attestation)?;
            }
            let bundle = VersionAttestationBundle {
                version: 2,
                repository_id,
                commit: commit.clone(),
                attestations,
            };
            write_attestation_bundle(out, &bundle)?;
            println!("wrote attestation bundle to {}", out.display());
            println!("commit: {commit}");
            println!("attestations: {}", bundle.attestations.len());
        }
        Command::Versioning(VersioningCmd::Diff {
            tenant,
            volume,
            from,
            to,
            limit,
            page_token,
            live,
        }) => {
            if *live {
                let mut query = vec![
                    ("from", from.clone()),
                    ("to", to.clone()),
                    ("limit", limit.to_string()),
                ];
                if let Some(page_token) = page_token {
                    query.push(("page_token", page_token.clone()));
                }
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "diff", &query, None)
                        .await?;
                let changes = response["changes"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("admin response omitted changes"))?;
                for change in changes {
                    println!(
                        "{}\t{}",
                        change["change"].as_str().unwrap_or("unknown"),
                        change["path"].as_str().unwrap_or("-")
                    );
                }
                if let Some(next) = response["next_page_token"].as_str() {
                    println!("next_page_token: {next}");
                }
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let diff = repository
                .diff_commits_page(from, to, *limit, page_token.as_deref())
                .await;
            let repository_close = repository.close().await;
            let (changes, next_page_token) = diff?;
            for change in changes {
                println!(
                    "{}\t{}",
                    version_change_label(change.change()),
                    change.path()
                );
            }
            if let Some(next) = next_page_token {
                println!("next_page_token: {next}");
            }
            repository_close?;
        }
        Command::Versioning(VersioningCmd::Tag {
            tenant,
            volume,
            name,
            commit,
            live,
        }) => {
            if *live {
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "tags",
                    serde_json::json!({ "name": name, "commit": commit }),
                )
                .await?;
                let tag: VersionTagInfo = serde_json::from_value(response["tag"].clone())
                    .context("parsing admin version tag")?;
                print_version_tag(&tag);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.create_tag(name, commit).await;
            let repository_close = repository.close().await;
            let tag = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-tag-create".to_string()),
                    ),
                    (
                        "tag".to_string(),
                        AuditDetailValue::String(tag.name().to_string()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(tag.commit().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_tag(&tag);
        }
        Command::Versioning(VersioningCmd::Tags {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "tags", &[], None).await?;
                let tags: Vec<VersionTagInfo> = serde_json::from_value(response["tags"].clone())
                    .context("parsing admin version tags")?;
                for tag in tags {
                    print_version_tag(&tag);
                }
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.list_tags().await;
            let repository_close = repository.close().await;
            for tag in result? {
                print_version_tag(&tag);
            }
            repository_close?;
        }
        Command::Versioning(VersioningCmd::Untag {
            tenant,
            volume,
            name,
            live,
        }) => {
            if *live {
                let endpoint = format!("tags/{name}");
                let response =
                    live_versioning_json(config, tenant, volume, "DELETE", &endpoint, &[], None)
                        .await?;
                let tag: VersionTagInfo = serde_json::from_value(response["tag"].clone())
                    .context("parsing deleted admin version tag")?;
                print_version_tag(&tag);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.delete_tag(name).await;
            let repository_close = repository.close().await;
            let tag = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-tag-delete".to_string()),
                    ),
                    (
                        "tag".to_string(),
                        AuditDetailValue::String(tag.name().to_string()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(tag.commit().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_tag(&tag);
        }
        Command::Versioning(VersioningCmd::Branch {
            tenant,
            volume,
            name,
            commit,
            live,
        }) => {
            if *live {
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "branches",
                    serde_json::json!({ "name": name, "commit": commit }),
                )
                .await?;
                let branch: VersionBranchInfo = serde_json::from_value(response["branch"].clone())
                    .context("parsing admin version branch")?;
                print_version_branch(&branch);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.create_branch(name, commit).await;
            let repository_close = repository.close().await;
            let branch = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-create".to_string()),
                    ),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(branch.name().to_string()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(branch.commit().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_branch(&branch);
        }
        Command::Versioning(VersioningCmd::Branches {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "branches", &[], None)
                        .await?;
                let branches: Vec<VersionBranchInfo> =
                    serde_json::from_value(response["branches"].clone())
                        .context("parsing admin version branches")?;
                for branch in branches {
                    print_version_branch(&branch);
                }
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.list_branches().await;
            let repository_close = repository.close().await;
            for branch in result? {
                print_version_branch(&branch);
            }
            repository_close?;
        }
        Command::Versioning(VersioningCmd::QuorumStatus {
            tenant,
            volume,
            branch,
            commit,
            check,
            live,
        }) => {
            let quorum = if *live {
                let endpoint = format!("branches/{branch}/attestation-quorum");
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &endpoint,
                    &[("commit", commit.clone())],
                    None,
                )
                .await?;
                serde_json::from_value(response["quorum"].clone())
                    .context("parsing admin version attestation quorum")?
            } else {
                let repository =
                    VersionRepository::open(control, object_store, tenant, volume).await?;
                let result = repository.attestation_quorum(branch, commit).await;
                let repository_close = repository.close().await;
                let quorum = result?;
                repository_close?;
                quorum
            };
            print_attestation_quorum(&quorum);
            if *check && !quorum.satisfied() {
                anyhow::bail!(
                    "commit {} does not satisfy the attestation quorum for branch {}",
                    quorum.commit(),
                    quorum.branch()
                );
            }
        }
        Command::Versioning(VersioningCmd::ProtectBranch {
            tenant,
            volume,
            name,
            allowed_committers,
            allowed_managers,
            trusted_attestation_keys,
            required_attestations,
            live,
        }) => {
            let required_attestations =
                required_attestations.unwrap_or(u32::from(!trusted_attestation_keys.is_empty()));
            if *live {
                let endpoint = format!("branches/{name}/protection");
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "PUT",
                    &endpoint,
                    &[],
                    Some(serde_json::json!({
                        "allowed_committers": allowed_committers,
                        "allowed_managers": allowed_managers,
                        "trusted_attestation_keys": trusted_attestation_keys,
                        "required_attestations": required_attestations,
                    })),
                )
                .await?;
                let branch: VersionBranchInfo = serde_json::from_value(response["branch"].clone())
                    .context("parsing protected admin version branch")?;
                print_version_branch(&branch);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let policy = VersionBranchProtectionPolicy::new(
                allowed_committers,
                allowed_managers,
                trusted_attestation_keys,
                required_attestations,
            )?;
            let result = repository.set_branch_protected(name, true, &policy).await;
            let repository_close = repository.close().await;
            let branch = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-protect".to_string()),
                    ),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(branch.name().to_string()),
                    ),
                    (
                        "trusted_attestation_key_ids".to_string(),
                        AuditDetailValue::Array(
                            branch
                                .trusted_attestation_keys()
                                .iter()
                                .map(|key| AuditDetailValue::String(key.key_id().to_string()))
                                .collect(),
                        ),
                    ),
                    (
                        "required_attestations".to_string(),
                        AuditDetailValue::U64(u64::from(branch.required_attestations())),
                    ),
                ],
            )
            .await?;
            print_version_branch(&branch);
        }
        Command::Versioning(VersioningCmd::UnprotectBranch {
            tenant,
            volume,
            name,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!(
                    "unprotecting version branch {name} requires --yes; destructive ref operations will become available"
                );
            }
            if *live {
                let endpoint = format!("branches/{name}/protection");
                let response =
                    live_versioning_json(config, tenant, volume, "DELETE", &endpoint, &[], None)
                        .await?;
                let branch: VersionBranchInfo = serde_json::from_value(response["branch"].clone())
                    .context("parsing unprotected admin version branch")?;
                print_version_branch(&branch);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository
                .set_branch_protected(name, false, &VersionBranchProtectionPolicy::default())
                .await;
            let repository_close = repository.close().await;
            let branch = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-unprotect".to_string()),
                    ),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(branch.name().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_branch(&branch);
        }
        Command::Versioning(VersioningCmd::Reflog {
            tenant,
            volume,
            branch,
            limit,
            live,
        }) => {
            if *live {
                let endpoint = format!("branches/{branch}/reflog");
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &endpoint,
                    &[("limit", limit.to_string())],
                    None,
                )
                .await?;
                let entries: Vec<VersionReflogEntry> =
                    serde_json::from_value(response["entries"].clone())
                        .context("parsing admin version branch reflog")?;
                for entry in entries {
                    print_version_reflog_entry(&entry);
                }
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.reflog(branch, *limit).await;
            let repository_close = repository.close().await;
            for entry in result? {
                print_version_reflog_entry(&entry);
            }
            repository_close?;
        }
        Command::Versioning(VersioningCmd::RecoverBranch {
            tenant,
            volume,
            name,
            sequence,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!(
                    "recovering version branch {name} requires --yes; this moves or recreates the branch"
                );
            }
            if *live {
                let endpoint = format!("branches/{name}/recover");
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume,
                    &endpoint,
                    serde_json::json!({ "sequence": sequence }),
                )
                .await?;
                let recovery: VersionBranchRecoveryInfo =
                    serde_json::from_value(response["recovery"].clone())
                        .context("parsing recovered admin version branch")?;
                print_version_branch_recovery(&recovery);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.recover_branch(name, *sequence).await;
            let repository_close = repository.close().await;
            let recovery = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-recover".to_string()),
                    ),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(recovery.name().to_string()),
                    ),
                    (
                        "reflog_sequence".to_string(),
                        AuditDetailValue::U64(recovery.sequence()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(recovery.commit().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_branch_recovery(&recovery);
        }
        Command::Versioning(VersioningCmd::DeleteBranch {
            tenant,
            volume,
            name,
            live,
        }) => {
            if *live {
                let endpoint = format!("branches/{name}");
                let response =
                    live_versioning_json(config, tenant, volume, "DELETE", &endpoint, &[], None)
                        .await?;
                let branch: VersionBranchInfo = serde_json::from_value(response["branch"].clone())
                    .context("parsing deleted admin version branch")?;
                print_version_branch(&branch);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.delete_branch(name).await;
            let repository_close = repository.close().await;
            let branch = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-delete".to_string()),
                    ),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(branch.name().to_string()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(branch.commit().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_branch(&branch);
        }
        Command::Versioning(VersioningCmd::ResetBranch {
            tenant,
            volume,
            name,
            commit,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!(
                    "resetting version branch {name} requires --yes; this may abandon reachable history"
                );
            }
            if *live {
                let endpoint = format!("branches/{name}/reset");
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume,
                    &endpoint,
                    serde_json::json!({ "commit": commit }),
                )
                .await?;
                let reset: VersionBranchResetInfo =
                    serde_json::from_value(response["reset"].clone())
                        .context("parsing reset admin version branch")?;
                print_version_branch_reset(&reset);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.reset_branch(name, commit).await;
            let repository_close = repository.close().await;
            let reset = result?;
            repository_close?;
            append_cli_version_audit(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-reset".to_string()),
                    ),
                    (
                        "branch".to_string(),
                        AuditDetailValue::String(reset.name().to_string()),
                    ),
                    (
                        "previous".to_string(),
                        AuditDetailValue::String(reset.previous().to_string()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(reset.commit().to_string()),
                    ),
                ],
            )
            .await?;
            print_version_branch_reset(&reset);
        }
        Command::Versioning(VersioningCmd::Merge {
            tenant,
            volume,
            source,
            target,
            author,
            conflict_strategy,
            live,
        }) => {
            if *live {
                let endpoint = format!("branches/{target}/merge");
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume,
                    &endpoint,
                    serde_json::json!({
                        "source": source,
                        "conflict_strategy": conflict_strategy,
                        "author": author,
                    }),
                )
                .await?;
                let merge: VersionMergeInfo = serde_json::from_value(response["merge"].clone())
                    .context("parsing admin version merge")?;
                print_version_merge(&merge);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let request_id = format!("cli-versioning-{}", uuid::Uuid::new_v4());
            let provenance = offline_commit_provenance(author.as_ref(), request_id.clone())?;
            let result = repository
                .merge_branch(source, target, *conflict_strategy, provenance)
                .await;
            let repository_close = repository.close().await;
            let merge = result?;
            repository_close?;
            append_cli_version_audit_with_request_id(
                control,
                AuditAction::Maintain,
                tenant,
                volume,
                request_id,
                [
                    (
                        "maintenance".to_string(),
                        AuditDetailValue::String("version-branch-merge".to_string()),
                    ),
                    (
                        "source".to_string(),
                        AuditDetailValue::String(merge.source().to_string()),
                    ),
                    (
                        "target".to_string(),
                        AuditDetailValue::String(merge.target().to_string()),
                    ),
                    (
                        "commit".to_string(),
                        AuditDetailValue::String(merge.commit().to_string()),
                    ),
                    (
                        "conflict_strategy".to_string(),
                        AuditDetailValue::String(merge.strategy().as_str().to_string()),
                    ),
                    (
                        "fast_forward".to_string(),
                        AuditDetailValue::Bool(merge.fast_forward()),
                    ),
                ],
            )
            .await?;
            print_version_merge(&merge);
        }
        Command::Versioning(VersioningCmd::MergePreview {
            tenant,
            volume,
            source,
            target,
            live,
        }) => {
            if *live {
                let endpoint = format!("branches/{target}/merge");
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "GET",
                    &endpoint,
                    &[("source", source.clone())],
                    None,
                )
                .await?;
                let preview: VersionMergePreview =
                    serde_json::from_value(response["preview"].clone())
                        .context("parsing admin version merge preview")?;
                print_version_merge_preview(&preview);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let result = repository.preview_branch_merge(source, target).await;
            let repository_close = repository.close().await;
            let preview = result?;
            repository_close?;
            print_version_merge_preview(&preview);
        }
        Command::Versioning(VersioningCmd::Show {
            tenant,
            volume,
            commit,
            path,
            out,
            live,
        }) => {
            if *live {
                let bytes = if let Some(out) = out {
                    let mut file = tokio::fs::File::create(out)
                        .await
                        .with_context(|| format!("creating {}", out.display()))?;
                    stream_live_version_file(config, tenant, volume, commit, path, &mut file)
                        .await?
                } else {
                    stream_live_version_file(
                        config,
                        tenant,
                        volume,
                        commit,
                        path,
                        &mut tokio::io::stdout(),
                    )
                    .await?
                };
                if let Some(out) = out {
                    println!("wrote {bytes} bytes to {}", out.display());
                }
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let streamed = if let Some(out) = out {
                let mut file = tokio::fs::File::create(out)
                    .await
                    .with_context(|| format!("creating {}", out.display()))?;
                stream_version_file(&repository, commit, path, &mut file).await
            } else {
                stream_version_file(&repository, commit, path, &mut tokio::io::stdout()).await
            };
            let repository_close = repository.close().await;
            let bytes = streamed?;
            repository_close?;
            if let Some(out) = out {
                println!("wrote {bytes} bytes to {}", out.display());
            }
        }
        Command::Versioning(VersioningCmd::RestorePreview {
            tenant,
            volume: volume_name,
            commit,
            path,
            mode,
            live,
        }) => {
            if *live {
                let query = vec![
                    ("commit", commit.clone()),
                    ("path", path.clone()),
                    ("mode", mode.as_str().to_string()),
                ];
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume_name,
                    "GET",
                    "restore-preview",
                    &query,
                    None,
                )
                .await?;
                let preview: VersionRestorePreview =
                    serde_json::from_value(response["preview"].clone())
                        .context("parsing admin restore preview")?;
                print_restore_preview(&preview);
                return Ok(());
            }
            let repository =
                VersionRepository::open(control, Arc::clone(&object_store), tenant, volume_name)
                    .await?;
            let record = control.get_mountable_volume(tenant, volume_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let live = volume::Volume::open(&record, dek, Arc::clone(&object_store)).await?;
            let result = repository
                .preview_restore(live.as_ref(), commit, path, *mode)
                .await;
            let live_close = live.shutdown().await;
            let repository_close = repository.close().await;
            let preview = result?;
            live_close?;
            repository_close?;
            print_restore_preview(&preview);
        }
        Command::Versioning(VersioningCmd::Restore {
            tenant,
            volume: volume_name,
            commit,
            path,
            mode,
            token,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!("applying a restore requires --yes");
            }
            if *live {
                let response = post_live_versioning_json(
                    config,
                    tenant,
                    volume_name,
                    "restore",
                    serde_json::json!({
                        "commit": commit,
                        "path": path,
                        "mode": mode,
                        "token": token,
                    }),
                )
                .await?;
                let applied: VersionRestoreApplyInfo =
                    serde_json::from_value(response["restored"].clone())
                        .context("parsing applied restore")?;
                print_restore_apply(&applied);
                return Ok(());
            }
            let repository =
                VersionRepository::open(control, Arc::clone(&object_store), tenant, volume_name)
                    .await?;
            let record = control.get_mountable_volume(tenant, volume_name).await?;
            let dek = control.unwrap_volume_dek(&record).await?;
            let live = volume::Volume::open(&record, dek, Arc::clone(&object_store)).await?;
            let restore = repository
                .apply_restore(live.as_ref(), commit, path, *mode, token)
                .await;
            let live_close = live.shutdown().await;
            let repository_close = repository.close().await;
            let applied = restore?;
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
            print_restore_apply(&applied);
        }
        Command::Versioning(VersioningCmd::Retention {
            tenant,
            volume,
            keep_last,
            max_age,
            max_bytes,
            clear,
            live,
        }) => {
            if *live {
                if *clear && (keep_last.is_some() || max_age.is_some() || max_bytes.is_some()) {
                    anyhow::bail!(
                        "--clear cannot be combined with --keep-last, --max-age, or --max-bytes"
                    );
                }
                let response =
                    if *clear || keep_last.is_some() || max_age.is_some() || max_bytes.is_some() {
                        live_versioning_json(
                            config,
                            tenant,
                            volume,
                            "PATCH",
                            "retention",
                            &[],
                            Some(serde_json::json!({
                                "keep_last": keep_last,
                                "max_age_secs": max_age,
                                "max_bytes": max_bytes,
                                "clear": clear,
                            })),
                        )
                        .await?
                    } else {
                        live_versioning_json(config, tenant, volume, "GET", "retention", &[], None)
                            .await?
                    };
                let policy = &response["retention"];
                println!("versioning_retention: {tenant}/{volume}");
                println!(
                    "keep_last: {}",
                    policy["keep_last"]
                        .as_u64()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unlimited".to_string())
                );
                println!(
                    "max_age_secs: {}",
                    policy["max_age_secs"]
                        .as_u64()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unlimited".to_string())
                );
                println!(
                    "max_bytes: {}",
                    policy["max_bytes"]
                        .as_u64()
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unlimited".to_string())
                );
                return Ok(());
            }
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
        Command::Versioning(VersioningCmd::Stats {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "stats", &[], None).await?;
                let stats = &response["stats"];
                println!("bytes: {}", stats["bytes"]);
                println!("commits: {}", stats["commits"]);
                println!("attestations: {}", stats["attestations"]);
                println!("nodes: {}", stats["nodes"]);
                println!("blobs: {}", stats["blobs"]);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let stats = repository.stats().await;
            let close = repository.close().await;
            let stats = stats?;
            close?;
            println!("bytes: {}", stats.bytes);
            println!("commits: {}", stats.commits);
            println!("attestations: {}", stats.attestations);
            println!("nodes: {}", stats.nodes);
            println!("blobs: {}", stats.blobs);
        }
        Command::Versioning(VersioningCmd::Verify {
            tenant,
            volume,
            live,
        }) => {
            if *live {
                let response =
                    live_versioning_json(config, tenant, volume, "GET", "verify", &[], None)
                        .await?;
                let report = &response["verify"];
                println!("commits: {}", report["commits"]);
                println!("attestations: {}", report["attestations"]);
                println!("nodes: {}", report["nodes"]);
                println!("node_bytes: {}", report["node_bytes"]);
                println!("blobs: {}", report["blobs"]);
                println!("blob_bytes: {}", report["blob_bytes"]);
                return Ok(());
            }
            let repository = VersionRepository::open(control, object_store, tenant, volume).await?;
            let report = repository.verify().await;
            let close = repository.close().await;
            let report = report?;
            close?;
            println!("commits: {}", report.commits);
            println!("attestations: {}", report.attestations);
            println!("nodes: {}", report.nodes);
            println!("node_bytes: {}", report.node_bytes);
            println!("blobs: {}", report.blobs);
            println!("blob_bytes: {}", report.blob_bytes);
        }
        Command::Versioning(VersioningCmd::Gc {
            tenant,
            volume,
            dry_run,
            live,
        }) => {
            if *live {
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "POST",
                    "gc",
                    &[],
                    Some(serde_json::json!({ "dry_run": dry_run })),
                )
                .await?;
                let report = &response["gc"];
                println!("retained_commits: {}", report["retained_commits"]);
                println!("deleted_commits: {}", report["deleted_commits"]);
                println!("deleted_nodes: {}", report["deleted_nodes"]);
                println!("deleted_blobs: {}", report["deleted_blobs"]);
                println!("reclaimed_bytes: {}", report["reclaimed_bytes"]);
                println!("dry_run: {}", report["dry_run"]);
                return Ok(());
            }
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
        Command::Versioning(VersioningCmd::Unlock {
            tenant,
            volume,
            owner,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!("versioning unlock requires --yes");
            }
            let broken = if *live {
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "DELETE",
                    "lease",
                    &[],
                    Some(serde_json::json!({
                        "owner": owner,
                        "confirm": true,
                    })),
                )
                .await?;
                response["lease"]["broken"]
                    .as_bool()
                    .ok_or_else(|| anyhow::anyhow!("admin response omitted lease.broken"))?
            } else {
                let broken = force_break_expired_version_maintenance_lease(
                    object_store,
                    tenant,
                    volume,
                    owner,
                )
                .await?;
                if broken {
                    append_cli_version_audit(
                        control,
                        AuditAction::Maintain,
                        tenant,
                        volume,
                        [
                            (
                                "maintenance".to_string(),
                                AuditDetailValue::String("version-lease-break".to_string()),
                            ),
                            ("owner".to_string(), AuditDetailValue::String(owner.clone())),
                        ],
                    )
                    .await?;
                }
                broken
            };
            if broken {
                println!("broke expired version lease for {tenant}/{volume} owned by {owner}");
            } else {
                println!("no version lease exists for {tenant}/{volume}");
            }
        }
        Command::Versioning(VersioningCmd::Purge {
            tenant,
            volume,
            yes,
            live,
        }) => {
            if !yes {
                anyhow::bail!("versioning purge requires --yes");
            }
            if *live {
                let response = live_versioning_json(
                    config,
                    tenant,
                    volume,
                    "DELETE",
                    "history",
                    &[],
                    Some(serde_json::json!({ "confirm": true })),
                )
                .await?;
                println!(
                    "purged version history for {tenant}/{volume}: {} objects deleted",
                    response["purged"]["deleted_objects"]
                );
                return Ok(());
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
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };

    fn generate_admin_server_certificate(
        directory: &std::path::Path,
    ) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "slatefs-cli-test-ca");
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);

        let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "slatefs-admin");
        server_params.use_authority_key_identifier_extension = true;
        server_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &issuer)?;

        let ca_path = directory.join("ca.pem");
        let cert_path = directory.join("server.pem");
        let key_path = directory.join("server-key.pem");
        std::fs::write(&ca_path, ca_cert.pem())?;
        std::fs::write(&cert_path, server_cert.pem())?;
        std::fs::write(&key_path, server_key.serialize_pem())?;
        Ok((ca_path, cert_path, key_path))
    }

    #[tokio::test]
    async fn live_versioning_client_sends_tenant_auth_and_encoded_query() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 8192];
            let read = stream.read(&mut bytes).await.unwrap();
            let request = String::from_utf8(bytes[..read].to_vec()).unwrap();
            let body = r#"{"commits":[]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            request
        });
        let config = Config::parse(&format!(
            r#"
                [object_store]
                url = "memory:///"

                [kms]
                provider = "static"
                key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

                [admin]
                listen = "{listen}"

                [admin.tenant_tokens]
                tenant-a = "tenant-secret"
            "#
        ))
        .unwrap();
        let response = live_versioning_json(
            &config,
            "tenant-a",
            "docs",
            "GET",
            "commits",
            &[
                ("path", "/docs/a file.txt".to_string()),
                ("limit", "25".to_string()),
            ],
            None,
        )
        .await
        .unwrap();
        assert_eq!(response["commits"], serde_json::json!([]));
        let request = server.await.unwrap();
        assert!(
            request.starts_with(
                "GET /admin/v1/tenants/tenant-a/volumes/docs/versioning/commits?path=%2Fdocs%2Fa%20file.txt&limit=25 HTTP/1.1\r\n"
            ),
            "{request}"
        );
        assert!(
            request.contains("Authorization: Bearer tenant-secret\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn live_versioning_bundle_transport_preserves_binary_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let expected_request_body = vec![0, 0xff, 1, 2, 3, 0x80];
        let expected_response_body = vec![b'S', b'L', 0, 0xff, 0x80, 4, 5];
        let response_body = expected_response_body.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.slatefs.version-repository\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&response_body).await.unwrap();
            request
        });
        let config = Config::parse(&format!(
            r#"
                [object_store]
                url = "memory:///"

                [kms]
                provider = "static"
                key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

                [admin]
                listen = "{listen}"

                [admin.tenant_tokens]
                tenant-a = "tenant-secret"
            "#
        ))
        .unwrap();
        let response = live_versioning_bundle(
            &config,
            "tenant-a",
            "docs",
            "POST",
            Some(&expected_request_body),
        )
        .await
        .unwrap();
        assert_eq!(response, expected_response_body);
        let request = server.await.unwrap();
        let separator = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let head = std::str::from_utf8(&request[..separator]).unwrap();
        assert!(head.contains("Authorization: Bearer tenant-secret\r\n"));
        assert_eq!(&request[separator + 4..], expected_request_body);
    }

    #[tokio::test]
    async fn live_versioning_client_supports_custom_ca_tls() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let (ca_path, cert_path, key_path) = generate_admin_server_certificate(directory.path())?;
        RUSTLS_PROVIDER.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                load_pem_certificates(&cert_path)?,
                load_pem_private_key(&key_path)?,
            )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let listen = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = acceptor.accept(stream).await?;
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 1024];
                let read = stream.read(&mut bytes).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&bytes[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let body = r#"{"commits":[]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.shutdown().await?;
            Ok::<_, anyhow::Error>(String::from_utf8(request)?)
        });
        let config = Config::parse(&format!(
            r#"
                [object_store]
                url = "memory:///"

                [kms]
                provider = "static"
                key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

                [admin]
                listen = "{listen}"
                tls_server_ca = "{}"
                tls_server_name = "localhost"

                [admin.tenant_tokens]
                tenant-a = "tenant-secret"
            "#,
            ca_path.display()
        ))?;
        let response =
            live_versioning_json(&config, "tenant-a", "docs", "GET", "commits", &[], None).await?;
        assert_eq!(response["commits"], serde_json::json!([]));
        let request = server.await??;
        assert!(request.contains("Authorization: Bearer tenant-secret\r\n"));
        Ok(())
    }

    #[test]
    fn parse_size_bytes_accepts_plain_bytes_and_binary_suffixes() {
        assert_eq!(parse_size_bytes("4096").unwrap(), 4096);
        assert_eq!(parse_size_bytes("1K").unwrap(), 1024);
        assert_eq!(parse_size_bytes("2m").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size_bytes("100G").unwrap(), 100 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_bytes("1T").unwrap(), 1024_u64.pow(4));
    }

    #[test]
    fn parses_repository_bundle_commands() {
        let export = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "export-repository",
            "tenant-a",
            "docs",
            "--out",
            "docs.slatevcs",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            export.command,
            Command::Versioning(VersioningCmd::ExportRepository {
                tenant,
                volume,
                out,
                live: true,
            }) if tenant == "tenant-a"
                && volume == "docs"
                && out == std::path::Path::new("docs.slatevcs")
        ));

        let import = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "import-repository",
            "tenant-a",
            "restored",
            "--in",
            "docs.slatevcs",
            "--yes",
        ])
        .unwrap();
        assert!(matches!(
            import.command,
            Command::Versioning(VersioningCmd::ImportRepository {
                tenant,
                volume,
                input,
                yes: true,
                live: false,
            }) if tenant == "tenant-a"
                && volume == "restored"
                && input == std::path::Path::new("docs.slatevcs")
        ));
    }

    #[test]
    fn tenant_token_file_uses_first_rotation_credential() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tenant-a.tokens");
        std::fs::write(&path, "new-secret\nold-secret\n").unwrap();
        let config = Config::parse(&format!(
            r#"
                [object_store]
                url = "memory:///"

                [kms]
                provider = "static"
                key_hex = "0101010101010101010101010101010101010101010101010101010101010101"

                [admin.tenant_token_files]
                tenant-a = "{}"
            "#,
            path.display()
        ))
        .unwrap();
        assert_eq!(
            admin_bearer_token(&config, "tenant-a").unwrap().as_deref(),
            Some("new-secret")
        );
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

    #[test]
    fn parses_version_attestation_commands() {
        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "attestation-keygen",
            "--out",
            "/tmp/release.key",
            "--public-out",
            "/tmp/release.pub",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::AttestationKeygen { .. })
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "attest",
            "tenant-a",
            "docs",
            "main",
            "--key-id",
            "release-2026",
            "--key-file",
            "/tmp/release.key",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Attest {
                key_id,
                live: true,
                ..
            }) if key_id == "release-2026"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "attestations",
            "tenant-a",
            "docs",
            "main",
            "--trusted-public-key",
            "/tmp/release.pub",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Attestations {
                trusted_public_key: Some(_),
                live: true,
                ..
            })
        ));

        let directory = tempfile::tempdir().unwrap();
        let public_path = directory.path().join("release.pub");
        let public_key = SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes();
        std::fs::write(&public_path, format!("{}\n", hex::encode(public_key))).unwrap();
        let trusted = format!("release-2026={}", public_path.display());
        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "protect-branch",
            "tenant-a",
            "docs",
            "release",
            "--trust-attestation-key",
            trusted.as_str(),
            "--require-attestations",
            "1",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::ProtectBranch {
                trusted_attestation_keys,
                required_attestations: Some(1),
                ..
            }) if trusted_attestation_keys.len() == 1
                && trusted_attestation_keys[0].key_id() == "release-2026"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "quorum-status",
            "tenant-a",
            "docs",
            "release",
            "candidate",
            "--check",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::QuorumStatus {
                branch,
                commit,
                check: true,
                live: true,
                ..
            }) if branch == "release" && commit == "candidate"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "export-attestations",
            "tenant-a",
            "docs",
            "main",
            "--out",
            "/tmp/main-attestations.json",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::ExportAttestations { live: true, .. })
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "verify-attestation-bundle",
            "--in",
            "/tmp/main-attestations.json",
            "--trusted-public-key",
            public_path.to_str().unwrap(),
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::VerifyAttestationBundle { .. })
        ));
    }

    #[test]
    fn version_attestation_keygen_creates_private_and_public_files() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let private_path = directory.path().join("release.key");
        let public_path = directory.path().join("release.pub");
        version_attestation_keygen(&private_path, &public_path).unwrap();
        let private_key = read_ed25519_signing_key(&private_path).unwrap();
        assert_ne!(private_key.to_bytes(), [0; 32]);
        assert_eq!(
            std::fs::metadata(&private_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            read_hex_key::<32>(&public_path, "Ed25519 public key").unwrap(),
            private_key.verifying_key().to_bytes()
        );
        assert_eq!(
            std::fs::metadata(&public_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(version_attestation_keygen(&private_path, &public_path).is_err());
    }

    #[test]
    fn trusted_attestation_check_verifies_the_signature_locally() {
        let signing_key = SigningKey::from_bytes(&[41; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let commit = "ab".repeat(32);
        let repository_id = "00000000-0000-4000-8000-000000000001";
        let payload = version_commit_attestation_payload(
            repository_id,
            &commit,
            "release-2026",
            &public_key,
            1_700_000_000,
        )
        .unwrap();
        let attestation = VersionCommitAttestation::new_ed25519(
            "release-2026",
            public_key,
            signing_key.sign(&payload).to_bytes(),
            1_700_000_000,
        )
        .unwrap();
        verify_version_attestation(repository_id, &commit, &attestation).unwrap();
        assert!(
            verify_version_attestation(
                "00000000-0000-4000-8000-000000000002",
                &commit,
                &attestation
            )
            .is_err()
        );

        let forged = VersionCommitAttestation::new_ed25519(
            "release-2026",
            public_key,
            [0; 64],
            1_700_000_000,
        )
        .unwrap();
        assert!(verify_version_attestation(repository_id, &commit, &forged).is_err());

        let directory = tempfile::tempdir().unwrap();
        let bundle_path = directory.path().join("bundle.json");
        let public_path = directory.path().join("release.pub");
        std::fs::write(&public_path, format!("{}\n", hex::encode(public_key))).unwrap();
        write_attestation_bundle(
            &bundle_path,
            &VersionAttestationBundle {
                version: 2,
                repository_id: repository_id.to_string(),
                commit,
                attestations: vec![attestation],
            },
        )
        .unwrap();
        verify_attestation_bundle_file(&bundle_path, &public_path).unwrap();
        assert!(
            write_attestation_bundle(
                &bundle_path,
                &VersionAttestationBundle {
                    version: 2,
                    repository_id: repository_id.to_string(),
                    commit: "ab".repeat(32),
                    attestations: Vec::new(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn parses_live_versioning_lifecycle_flags() {
        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "policy",
            "tenant-a",
            "docs",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Policy { live: true, .. })
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "status",
            "tenant-a",
            "docs",
            "/projects",
            "--reference",
            "draft",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Status {
                path,
                reference,
                live: true,
                ..
            }) if path == "/projects" && reference == "draft"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "restore-preview",
            "tenant-a",
            "docs",
            "baseline",
            "/projects",
            "--mode",
            "exact",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::RestorePreview {
                mode: VersionRestoreMode::Exact,
                live: true,
                ..
            })
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "restore",
            "tenant-a",
            "docs",
            "baseline",
            "/projects",
            "--mode",
            "exact",
            "--token",
            "preview-token",
            "--yes",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Restore {
                mode: VersionRestoreMode::Exact,
                token,
                yes: true,
                live: true,
                ..
            }) if token == "preview-token"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "gc",
            "tenant-a",
            "docs",
            "--dry-run",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Gc {
                dry_run: true,
                live: true,
                ..
            })
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "unlock",
            "tenant-a",
            "docs",
            "--owner",
            "owner-uuid",
            "--yes",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Unlock {
                owner,
                yes: true,
                live: true,
                ..
            }) if owner == "owner-uuid"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "commit",
            "tenant-a",
            "docs",
            "/notes.txt",
            "--message",
            "save notes",
            "--idempotency-key",
            "retry-1",
            "--branch",
            "draft",
            "--author",
            "alice",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Commit {
                idempotency_key: Some(key),
                branch,
                author: Some(author),
                live: true,
                ..
            }) if key == "retry-1" && branch == "draft" && author == "alice"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "inspect",
            "tenant-a",
            "docs",
            "release",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Inspect {
                reference,
                live: true,
                ..
            }) if reference == "release"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "diff",
            "tenant-a",
            "docs",
            "from-id",
            "to-id",
            "--limit",
            "25",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Diff {
                from,
                to,
                limit: 25,
                live: true,
                ..
            }) if from == "from-id" && to == "to-id"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "tag",
            "tenant-a",
            "docs",
            "baseline",
            "commit-id",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Tag {
                name,
                commit,
                live: true,
                ..
            }) if name == "baseline" && commit == "commit-id"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "branch",
            "tenant-a",
            "docs",
            "release",
            "baseline",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Branch {
                name,
                commit,
                live: true,
                ..
            }) if name == "release" && commit == "baseline"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "protect-branch",
            "tenant-a",
            "docs",
            "release",
            "--allow-committer",
            "tenant:tenant-a",
            "--allow-committer",
            "admin-token",
            "--allow-manager",
            "admin-token",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::ProtectBranch {
                name,
                allowed_committers,
                allowed_managers,
                live: true,
                ..
            }) if name == "release"
                && allowed_committers == vec!["tenant:tenant-a", "admin-token"]
                && allowed_managers == vec!["admin-token"]
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "unprotect-branch",
            "tenant-a",
            "docs",
            "release",
            "--yes",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::UnprotectBranch {
                name,
                yes: true,
                live: true,
                ..
            }) if name == "release"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "reflog",
            "tenant-a",
            "docs",
            "release",
            "--limit",
            "25",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Reflog {
                branch,
                limit: 25,
                live: true,
                ..
            }) if branch == "release"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "recover-branch",
            "tenant-a",
            "docs",
            "release",
            "42",
            "--yes",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::RecoverBranch {
                name,
                sequence: 42,
                yes: true,
                live: true,
                ..
            }) if name == "release"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "delete-branch",
            "tenant-a",
            "docs",
            "release",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::DeleteBranch {
                name,
                live: true,
                ..
            }) if name == "release"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "reset-branch",
            "tenant-a",
            "docs",
            "main",
            "baseline",
            "--yes",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::ResetBranch {
                name,
                commit,
                yes: true,
                live: true,
                ..
            }) if name == "main" && commit == "baseline"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "merge",
            "tenant-a",
            "docs",
            "draft",
            "main",
            "--conflict-strategy",
            "theirs",
            "--author",
            "alice",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::Merge {
                source,
                target,
                author: Some(author),
                conflict_strategy: VersionMergeConflictStrategy::Theirs,
                live: true,
                ..
            }) if source == "draft" && target == "main" && author == "alice"
        ));

        let cli = Cli::try_parse_from([
            "slatefs",
            "versioning",
            "merge-preview",
            "tenant-a",
            "docs",
            "draft",
            "main",
            "--live",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Versioning(VersioningCmd::MergePreview {
                source,
                target,
                live: true,
                ..
            }) if source == "draft" && target == "main"
        ));
    }
}
