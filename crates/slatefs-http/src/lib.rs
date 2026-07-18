//! Public contracts for SlateFS's tenant-scoped consumer HTTP frontend.
//!
//! The frontend is embedded in `slatefsd` and consumes the daemon's exact
//! live [`slatefs_core::volume::Volume`] arcs, preserving the one-writer rule.

pub mod auth;
pub mod config;
pub mod dto;
pub mod errors;
pub mod identifiers;
pub mod metrics;
pub mod paths;
pub mod registry;
pub mod routes;
pub mod streaming;
pub mod views;

pub use config::{ConsumerConfig, ConsumerLimits};
pub use dto::*;
pub use errors::{ApiError, ErrorCode, ErrorEnvelope};
pub use registry::LiveVolumeRegistry;
pub use routes::{ConsumerState, router, serve};
pub use views::{HistoricalView, HistoricalViewError, HistoricalViewProvider};

/// Versioned base path. Tenant identity is deliberately absent from it.
pub const CONSUMER_V1_PREFIX: &str = "/consumer/v1";
