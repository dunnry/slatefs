//! slatefs-core — everything protocol-independent in SlateFS.
//!
//! Phase 0 surface: configuration, crypto (block transformer, key hierarchy,
//! KMS), the control-plane DB (tenants/volumes/wrapped keys), and the volume
//! layer (`mkfs`/open/info). The `Vfs` trait and metadata/data paths land in
//! Phase 1 (see `slatefs-plan.md` §14).

pub mod config;
pub mod control;
pub mod crypto;
pub mod error;
pub mod meta;
pub mod store;
pub mod volume;

pub use error::{Error, Result};
