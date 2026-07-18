//! Opaque-ID-first selectors used at the route boundary.

use serde::{Deserialize, Serialize};
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::vfs::{Credentials, FileAttr, FsError, Vfs};

/// One and only one selector should be supplied by a request. Phase 1 owns
/// validation and safe resolution beneath the volume root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntrySelector {
    pub entry_id: Option<String>,
    pub path: Option<String>,
}

pub fn parse_path(path: &str) -> Result<Vec<&[u8]>, FsError> {
    if path.as_bytes().contains(&0) || path.starts_with('/') {
        return Err(FsError::Invalid);
    }
    if path.is_empty() {
        return Ok(Vec::new());
    }
    path.split('/')
        .map(|component| match component {
            "" | "." | ".." => Err(FsError::Invalid),
            value => Ok(value.as_bytes()),
        })
        .collect()
}

pub async fn resolve_path(
    vfs: &dyn Vfs,
    creds: &Credentials,
    path: &str,
) -> Result<(FileAttr, Option<(u64, Vec<u8>)>), FsError> {
    let components = parse_path(path)?;
    let mut current = vfs.getattr(creds, ROOT_INO).await?;
    let mut parent = None;
    for component in components {
        let next = vfs.lookup(creds, current.ino, component).await?;
        parent = Some((current.ino, component.to_vec()));
        current = next;
    }
    Ok((current, parent))
}
