//! `slatefs` — management CLI (plan §13): keygen, tenant lifecycle, volume
//! create/info/list/fsck, and quota metadata.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use slatefs_core::config::Config;
use slatefs_core::control::{ControlPlane, QuotaLimits};
use slatefs_core::crypto::kms::{self, LocalAgeKms};
use slatefs_core::volume::{self, CreateVolumeOptions};
use slatefs_core::{config, store};

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
    Tenant(TenantCmd),
    #[command(subcommand)]
    Volume(VolumeCmd),
    #[command(subcommand)]
    Quota(QuotaCmd),
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
    /// List tenants.
    List,
}

#[derive(Subcommand)]
enum VolumeCmd {
    /// Create a volume: control record + encrypted mkfs.
    Create {
        tenant: String,
        volume: String,
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
}

#[derive(Subcommand)]
enum QuotaCmd {
    /// Show a volume's configured quota limits.
    Show { tenant: String, volume: String },
    /// Set quota limits. Values are bytes/counts, or `none` to clear a limit.
    Set {
        tenant: String,
        volume: String,
        #[arg(long, value_name = "N|none")]
        bytes_hard: Option<String>,
        #[arg(long, value_name = "N|none")]
        bytes_soft: Option<String>,
        #[arg(long, value_name = "N|none")]
        inodes_hard: Option<String>,
        #[arg(long, value_name = "N|none")]
        inodes_soft: Option<String>,
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

fn parse_quota_value(raw: &str) -> anyhow::Result<Option<u64>> {
    match raw {
        "none" | "unlimited" | "-" => Ok(None),
        _ => raw
            .parse::<u64>()
            .map(Some)
            .with_context(|| format!("invalid quota value {raw:?}; expected N or none")),
    }
}

fn format_limit(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
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
        Command::Tenant(TenantCmd::List) => {
            for t in control.list_tenants().await? {
                println!(
                    "{}\t{:?}\tcreated={}\t{}",
                    t.name,
                    t.state,
                    t.created_at,
                    t.display_name.as_deref().unwrap_or("-")
                );
            }
        }
        Command::Volume(VolumeCmd::Create {
            tenant,
            volume,
            chunk_size,
            compression,
            cipher,
            note,
        }) => {
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
            let record = volume::create_volume(control, object_store, tenant, volume, opts).await?;
            println!(
                "created volume {}/{} fsid={:016x} cipher={} chunk_size={}",
                record.tenant, record.name, record.fsid, record.cipher, record.chunk_size
            );
        }
        Command::Volume(VolumeCmd::Info { tenant, volume }) => {
            let info = volume::volume_info(control, object_store, tenant, volume).await?;
            let r = &info.record;
            let sb = &info.superblock;
            println!("volume:      {}/{}", r.tenant, r.name);
            println!("state:       {:?}", r.state);
            println!("fsid:        {:016x}", sb.fsid);
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
            let vol = volume::Volume::open(&record, dek, object_store).await?;
            let report = if *recount {
                vol.fsck_recount().await?
            } else {
                vol.fsck().await?
            };
            vol.shutdown().await?;

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
        Command::Quota(QuotaCmd::Show { tenant, volume }) => {
            let record = control.get_volume(tenant, volume).await?;
            print_quota(tenant, volume, record.quota);
        }
        Command::Quota(QuotaCmd::Set {
            tenant,
            volume,
            bytes_hard,
            bytes_soft,
            inodes_hard,
            inodes_soft,
        }) => {
            if bytes_hard.is_none()
                && bytes_soft.is_none()
                && inodes_hard.is_none()
                && inodes_soft.is_none()
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
            if let Some(raw) = inodes_hard {
                quota.inodes.hard = parse_quota_value(raw)?;
            }
            if let Some(raw) = inodes_soft {
                quota.inodes.soft = parse_quota_value(raw)?;
            }
            let record = control.set_volume_quota(tenant, volume, quota).await?;
            print_quota(tenant, volume, record.quota);
            println!("note: new limits apply when the volume is next opened for serving");
        }
    }
    Ok(())
}
