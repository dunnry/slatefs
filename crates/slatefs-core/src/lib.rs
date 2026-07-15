//! slatefs-core — everything protocol-independent in SlateFS.
//!
//! Phase 0 surface: configuration, crypto (block transformer, key hierarchy,
//! KMS), the control-plane DB (tenants/volumes/wrapped keys), and the volume
//! layer (`mkfs`/open/info). The `Vfs` trait and metadata/data paths land in
//! Phase 1 (see `slatefs-plan.md` §14).

pub mod attrcache;
pub mod block;
pub mod config;
pub mod control;
pub mod crypto;
pub mod data;
pub mod error;
pub mod fsck;
pub mod locks;
pub mod meta;
pub mod metrics;
pub mod quota;
pub mod rate;
pub mod snapshot;
pub mod store;
pub mod version_snapshot;
pub mod versioning;
pub mod vfs;
pub mod volume;

mod health;
mod vfs_impl;

pub use error::{Error, Result};
