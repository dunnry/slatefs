//! Object-store layout under the configured root URL (plan §4/§5):
//!
//! ```text
//! <root>/control            control-plane SlateDB
//! <root>/control.dek        wrapped control DEK + cipher (raw object, see control.rs)
//! <root>/volumes/<t>/<v>    one SlateDB per volume (DD-1)
//! ```

use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use futures::stream::BoxStream;
use slatedb::object_store::parse_url_opts;
use slatedb::object_store::path::Path as ObjPath;
use slatedb::object_store::prefix::PrefixStore;
use slatedb::object_store::{
    CopyOptions, Error as ObjectStoreError, GetOptions, GetResult, ListResult, MultipartUpload,
    ObjectMeta, PutMultipartOptions, PutOptions, PutPayload, PutResult,
    Result as ObjectStoreResult,
};
// Re-exported so frontends/CLI don't need a direct slatedb dependency just to
// hold a store handle.
pub use slatedb::object_store::ObjectStore;

use crate::error::{Error, Result};

/// Resolve the deployment root. `s3://bucket/prefix` style URLs are wrapped in
/// a `PrefixStore`, so every path below is relative to the root.
///
/// Note `memory:///` builds a fresh empty store per call — resolve once per
/// process and share the `Arc`.
pub fn resolve_root(url: &str) -> Result<Arc<dyn ObjectStore>> {
    let parsed = url
        .try_into()
        .map_err(|e| Error::Config(format!("invalid object store URL {url:?}: {e}")))?;
    let env_vars = std::env::vars().map(|(key, value)| (key.to_ascii_lowercase(), value));
    let (store, prefix) = parse_url_opts(&parsed, env_vars).map_err(Error::from)?;
    if prefix.as_ref().is_empty() {
        Ok(Arc::from(store))
    } else {
        Ok(Arc::new(PrefixStore::new(store, prefix)))
    }
}

pub const CONTROL_DB_PATH: &str = "control";

pub fn control_dek_path() -> ObjPath {
    ObjPath::from("control.dek")
}

pub fn volume_db_path(tenant: &str, volume: &str) -> String {
    format!("volumes/{tenant}/{volume}")
}

pub fn volume_db_prefix(tenant: &str, volume: &str) -> ObjPath {
    ObjPath::from(volume_db_path(tenant, volume))
}

/// Temporary SlateDB 0.13 reader shim for shallow clones.
///
/// `Db::builder` installs a `PathResolver` with `external_ssts` from the
/// manifest, but `DbReader::builder` currently constructs a plain table store.
/// Until that upstream reader path is fixed, read-only operations on a clone
/// can ask for parent-owned SSTs under the clone prefix. Retry those missing
/// compacted SST reads under ancestor prefixes without affecting writes,
/// manifests, WAL, listings, or non-clone volumes.
pub fn clone_parent_read_fallback_store(
    inner: Arc<dyn ObjectStore>,
    clone_tenant: &str,
    clone_volume: &str,
    parent_prefixes: Vec<String>,
) -> Arc<dyn ObjectStore> {
    Arc::new(CloneParentReadFallbackStore {
        inner,
        clone_prefix: volume_db_path(clone_tenant, clone_volume),
        parent_prefixes,
    })
}

#[derive(Debug)]
struct CloneParentReadFallbackStore {
    inner: Arc<dyn ObjectStore>,
    clone_prefix: String,
    parent_prefixes: Vec<String>,
}

impl CloneParentReadFallbackStore {
    fn remap_compacted_ssts(&self, location: &ObjPath) -> Option<Vec<ObjPath>> {
        let raw: String = location.clone().into();
        let suffix = raw.strip_prefix(&self.clone_prefix)?.strip_prefix('/')?;
        if !suffix.starts_with("compacted/") {
            return None;
        }
        Some(
            self.parent_prefixes
                .iter()
                .map(|prefix| ObjPath::from(format!("{prefix}/{suffix}")))
                .collect(),
        )
    }
}

impl fmt::Display for CloneParentReadFallbackStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "clone-parent-read-fallback({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for CloneParentReadFallbackStore {
    async fn put_opts(
        &self,
        location: &ObjPath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> ObjectStoreResult<PutResult> {
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjPath,
        opts: PutMultipartOptions,
    ) -> ObjectStoreResult<Box<dyn MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &ObjPath,
        options: GetOptions,
    ) -> ObjectStoreResult<GetResult> {
        match self.inner.get_opts(location, options.clone()).await {
            Ok(result) => Ok(result),
            Err(error @ ObjectStoreError::NotFound { .. }) => {
                match self.remap_compacted_ssts(location) {
                    Some(parent_locations) => {
                        let mut last_not_found = error;
                        for parent_location in parent_locations {
                            match self.inner.get_opts(&parent_location, options.clone()).await {
                                Ok(result) => return Ok(result),
                                Err(error @ ObjectStoreError::NotFound { .. }) => {
                                    last_not_found = error;
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(last_not_found)
                    }
                    None => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn get_ranges(
        &self,
        location: &ObjPath,
        ranges: &[Range<u64>],
    ) -> ObjectStoreResult<Vec<Bytes>> {
        let mut out = Vec::with_capacity(ranges.len());
        for range in ranges {
            let options = GetOptions {
                range: Some(range.clone().into()),
                ..Default::default()
            };
            out.push(self.get_opts(location, options).await?.bytes().await?);
        }
        Ok(out)
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, ObjectStoreResult<ObjPath>>,
    ) -> BoxStream<'static, ObjectStoreResult<ObjPath>> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&ObjPath>) -> BoxStream<'static, ObjectStoreResult<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&ObjPath>) -> ObjectStoreResult<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &ObjPath,
        to: &ObjPath,
        options: CopyOptions,
    ) -> ObjectStoreResult<()> {
        self.inner.copy_opts(from, to, options).await
    }
}

pub async fn delete_prefix(object_store: &Arc<dyn ObjectStore>, prefix: &ObjPath) -> Result<usize> {
    let objects: Vec<_> = object_store.list(Some(prefix)).try_collect().await?;
    let count = objects.len();
    if count == 0 {
        return Ok(0);
    }
    let locations = futures::stream::iter(
        objects
            .into_iter()
            .map(|meta| Ok::<_, slatedb::object_store::Error>(meta.location)),
    );
    object_store
        .delete_stream(Box::pin(locations))
        .try_collect::<Vec<_>>()
        .await?;
    Ok(count)
}

/// Tenant and volume names become object-store path segments, wrap contexts,
/// and control-DB key components, so the charset is strict.
pub fn validate_name(kind: &'static str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(
            kind,
            format!("{name:?}: must be [a-z0-9][a-z0-9-_]{{0,63}}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(validate_name("tenant", "t1").is_ok());
        assert!(validate_name("tenant", "acme-corp_2").is_ok());
        assert!(validate_name("tenant", "").is_err());
        assert!(validate_name("tenant", "Upper").is_err());
        assert!(validate_name("tenant", "has/slash").is_err());
        assert!(validate_name("tenant", "-leading").is_err());
        assert!(validate_name("tenant", &"x".repeat(65)).is_err());
    }
}
