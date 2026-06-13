//! Object-store layout under the configured root URL (plan §4/§5):
//!
//! ```text
//! <root>/control            control-plane SlateDB
//! <root>/control.dek        wrapped control DEK + cipher (raw object, see control.rs)
//! <root>/volumes/<t>/<v>    one SlateDB per volume (DD-1)
//! ```

use std::sync::Arc;

// Re-exported so frontends/CLI don't need a direct slatedb dependency just to
// hold a store handle.
pub use slatedb::object_store::ObjectStore;
use slatedb::object_store::path::Path as ObjPath;

use crate::error::{Error, Result};

/// Resolve the deployment root. `s3://bucket/prefix` style URLs are wrapped in
/// a `PrefixStore`, so every path below is relative to the root.
///
/// Note `memory:///` builds a fresh empty store per call — resolve once per
/// process and share the `Arc`.
pub fn resolve_root(url: &str) -> Result<Arc<dyn ObjectStore>> {
    slatedb::Db::resolve_object_store(url).map_err(Error::from)
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
