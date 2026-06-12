//! slatefsd — serves SlateFS volumes over NFSv3 and 9P2000.L.
//!
//! Phase 0 stub: loads and validates configuration, then exits. Protocol
//! listeners arrive with Phases 2 (NFS) and 4 (9P).

use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(name = "slatefsd", version, about = "SlateFS file server daemon")]
struct Args {
    /// Path to the slatefs TOML config file.
    #[arg(long, short, default_value = "/etc/slatefs/slatefs.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let config = slatefs_core::config::Config::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;

    tracing::info!(
        object_store = %config.object_store.url,
        kms = %config.kms.provider_name(),
        "configuration OK; slatefsd protocol frontends are not implemented yet (Phase 2+)"
    );
    anyhow::bail!("slatefsd is a Phase 0 stub: no protocol frontends yet");
}
