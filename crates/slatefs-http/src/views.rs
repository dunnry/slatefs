use std::sync::Arc;

use async_trait::async_trait;
use slatefs_core::vfs::Vfs;

use crate::dto::ViewKind;

/// An immutable VFS lease. `owner` keeps the daemon cache entry alive for the
/// complete response, including streamed response bodies after routing ends.
#[derive(Clone)]
pub struct HistoricalView {
    pub vfs: Arc<dyn Vfs>,
    pub kind: ViewKind,
    pub exact_id: String,
    owner: Arc<dyn Send + Sync>,
}

impl HistoricalView {
    #[must_use]
    pub fn new(
        vfs: Arc<dyn Vfs>,
        kind: ViewKind,
        exact_id: String,
        owner: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            vfs,
            kind,
            exact_id,
            owner,
        }
    }

    /// Clone the opaque lease for a streaming response.
    #[must_use]
    pub fn lease(&self) -> Arc<dyn Send + Sync> {
        Arc::clone(&self.owner)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HistoricalViewError {
    #[error("historical object was not found")]
    NotFound,
    #[error("invalid historical view selector")]
    Invalid,
    #[error("historical view service is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait HistoricalViewProvider: Send + Sync {
    fn supports(&self, kind: ViewKind) -> bool;

    /// Resolve `reference` once and return a lease pinned to an exact immutable
    /// snapshot or commit identity.
    async fn open(
        &self,
        tenant: &str,
        volume: &str,
        kind: ViewKind,
        reference: &str,
    ) -> Result<HistoricalView, HistoricalViewError>;

    /// Evict all cached handles and close those with no active response lease.
    async fn shutdown(&self);
}

pub struct UnsupportedHistoricalViews;

#[async_trait]
impl HistoricalViewProvider for UnsupportedHistoricalViews {
    fn supports(&self, _kind: ViewKind) -> bool {
        false
    }

    async fn open(
        &self,
        _tenant: &str,
        _volume: &str,
        _kind: ViewKind,
        _reference: &str,
    ) -> Result<HistoricalView, HistoricalViewError> {
        Err(HistoricalViewError::Unavailable)
    }

    async fn shutdown(&self) {}
}
