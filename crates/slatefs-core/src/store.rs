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
    let env_vars = object_store_env_vars();
    let parse_url = azure_compat_url(url, &env_vars).unwrap_or_else(|| url.to_string());
    let parsed = parse_url
        .as_str()
        .try_into()
        .map_err(|e| Error::Config(format!("invalid object store URL {url:?}: {e}")))?;
    let (store, prefix) = parse_url_opts(&parsed, env_vars).map_err(Error::from)?;
    let inner: Arc<dyn ObjectStore> = if prefix.as_ref().is_empty() {
        Arc::from(store)
    } else {
        Arc::new(PrefixStore::new(store, prefix))
    };
    let local_file_system = parse_url.starts_with("file:");
    if local_file_system {
        tracing::info!(
            "SlateDB garbage collection is disabled for the local filesystem object store because conditional updates are unsupported"
        );
    }
    Ok(Arc::new(ResolvedRootStore {
        inner,
        local_file_system,
    }))
}

#[derive(Debug)]
struct ResolvedRootStore {
    inner: Arc<dyn ObjectStore>,
    local_file_system: bool,
}

impl fmt::Display for ResolvedRootStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slatefs-root(local={})", self.local_file_system)
    }
}

#[async_trait]
impl ObjectStore for ResolvedRootStore {
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
        self.inner.get_opts(location, options).await
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

/// SlateDB's local filesystem backend cannot perform the conditional update
/// used to coordinate its internal garbage collector. Leave GC enabled for
/// production object stores, but do not schedule an operation that can only
/// fail for a resolved local root. This retains all durable objects.
pub(crate) fn is_local_file_system(object_store: &Arc<dyn ObjectStore>) -> bool {
    object_store
        .to_string()
        .contains("slatefs-root(local=true)")
}

pub(crate) fn compatible_settings(
    object_store: &Arc<dyn ObjectStore>,
    mut settings: slatedb::config::Settings,
) -> slatedb::config::Settings {
    if is_local_file_system(object_store) {
        settings.garbage_collector_options = None;
    }
    settings
}

fn object_store_env_vars() -> Vec<(String, String)> {
    let mut env_vars: Vec<_> = std::env::vars()
        .map(|(key, value)| (key.to_ascii_lowercase(), value))
        .collect();
    add_azure_connection_string_options(&mut env_vars);
    env_vars
}

fn add_azure_connection_string_options(env_vars: &mut Vec<(String, String)>) {
    let Some(connection_string) = env_value(env_vars, "azure_storage_connection_string") else {
        return;
    };
    let connection_string = connection_string.to_string();
    if !has_env_key(env_vars, "azure_storage_account_name")
        && let Some(account) = connection_string_field(&connection_string, "AccountName")
    {
        env_vars.push(("azure_storage_account_name".to_string(), account));
    }
    if !has_azure_access_key(env_vars)
        && let Some(key) = connection_string_field(&connection_string, "AccountKey")
    {
        env_vars.push(("azure_storage_access_key".to_string(), key));
    }
}

fn has_azure_access_key(env_vars: &[(String, String)]) -> bool {
    [
        "azure_storage_account_key",
        "azure_storage_access_key",
        "azure_storage_master_key",
        "account_key",
        "access_key",
        "master_key",
    ]
    .iter()
    .any(|key| has_env_key(env_vars, key))
}

fn has_env_key(env_vars: &[(String, String)], key: &str) -> bool {
    env_vars
        .iter()
        .any(|(candidate, value)| candidate == key && !value.is_empty())
}

fn env_value<'a>(env_vars: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env_vars.iter().find_map(|(candidate, value)| {
        (candidate == key && !value.is_empty()).then_some(value.as_str())
    })
}

fn connection_string_field(connection_string: &str, field: &str) -> Option<String> {
    connection_string.split(';').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key.eq_ignore_ascii_case(field) && !value.is_empty()).then(|| value.to_string())
    })
}

fn azure_env_account(env_vars: &[(String, String)]) -> Option<String> {
    env_value(env_vars, "azure_storage_account_name")
        .or_else(|| env_value(env_vars, "account_name"))
        .map(str::to_string)
        .or_else(|| {
            env_value(env_vars, "azure_storage_connection_string")
                .and_then(|value| connection_string_field(value, "AccountName"))
        })
}

fn azure_env_container(env_vars: &[(String, String)]) -> Option<&str> {
    env_value(env_vars, "azure_container_name").or_else(|| env_value(env_vars, "container_name"))
}

/// SlateFS historically accepted `az://<account>/<container>/<prefix>` because
/// SlateDB 0.13 used object_store 0.12, whose URL parser removed the first path
/// segment from the returned prefix for `az://`. object_store 0.14's native
/// form is `az://<container>/<prefix>`.
///
/// Precedence:
/// 1. `az://<container>@<account>.blob.core.windows.net/<prefix>` is already
///    explicit and is left alone.
/// 2. If the `az://` host matches the credentialed account from
///    `AZURE_STORAGE_ACCOUNT_NAME`, `account_name`, or `AccountName` in
///    `AZURE_STORAGE_CONNECTION_STRING`, treat the first path segment as the
///    container and the rest as the SlateFS root prefix.
/// 3. Without an account env var, use the legacy interpretation only when the
///    host is shaped like a storage account and either `AZURE_CONTAINER_NAME`
///    matches the first path segment or the URL has both a container segment
///    and at least one prefix segment. Otherwise object_store-native parsing
///    wins, preserving `az://<container>/<prefix>`.
fn azure_compat_url(url: &str, env_vars: &[(String, String)]) -> Option<String> {
    let rest = url.strip_prefix("az://")?;
    let suffix_start = rest.find(&['?', '#'][..]).unwrap_or(rest.len());
    let (before_suffix, suffix) = rest.split_at(suffix_start);
    let (host, path) = before_suffix.split_once('/').unwrap_or((before_suffix, ""));
    if host.is_empty() || host.contains('@') || path.is_empty() {
        return None;
    }

    let (container, prefix) = path.split_once('/').unwrap_or((path, ""));
    if container.is_empty() {
        return None;
    }

    let account = azure_env_account(env_vars);
    let account_matches = account
        .as_deref()
        .is_some_and(|account| account.eq_ignore_ascii_case(host));
    let container_matches = azure_env_container(env_vars)
        .is_some_and(|env_container| env_container.eq_ignore_ascii_case(container));
    let structurally_legacy = account.is_none()
        && !prefix.is_empty()
        && is_plausible_azure_account(host)
        && is_plausible_azure_container(container);
    let env_container_legacy =
        account.is_none() && container_matches && is_plausible_azure_account(host);

    if !account_matches && !env_container_legacy && !structurally_legacy {
        return None;
    }

    Some(format!(
        "az://{container}@{host}.blob.core.windows.net/{prefix}{suffix}"
    ))
}

fn is_plausible_azure_account(value: &str) -> bool {
    (3..=24).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_plausible_azure_container(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !value.contains("--")
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

pub fn version_db_path(tenant: &str, volume: &str) -> String {
    format!("versions/{tenant}/{volume}")
}

pub fn version_db_prefix(tenant: &str, volume: &str) -> ObjPath {
    ObjPath::from(version_db_path(tenant, volume))
}

/// Object-store lease used to serialize version-repository access across
/// daemon processes. It deliberately lives outside the repository prefix so a
/// history purge cannot delete its own coordination record.
pub fn version_lease_path(tenant: &str, volume: &str) -> ObjPath {
    ObjPath::from(format!("version-leases/{tenant}/{volume}"))
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

/// Return whether an object-store prefix contains at least one object without
/// materializing the full listing.
pub async fn prefix_exists(object_store: &Arc<dyn ObjectStore>, prefix: &ObjPath) -> Result<bool> {
    Ok(object_store.list(Some(prefix)).try_next().await?.is_some())
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

    fn env(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

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

    #[test]
    fn disables_unsupported_slatedb_gc_only_for_local_roots() {
        let local = resolve_root("file:///tmp/slatefs-settings-test").unwrap();
        assert!(is_local_file_system(&local));
        let local_settings = compatible_settings(&local, slatedb::config::Settings::default());
        assert!(local_settings.garbage_collector_options.is_none());

        let memory = resolve_root("memory:///").unwrap();
        assert!(!is_local_file_system(&memory));
        let memory_settings = compatible_settings(&memory, slatedb::config::Settings::default());
        assert!(memory_settings.garbage_collector_options.is_some());
    }

    #[test]
    fn azure_compat_uses_env_account_as_url_host() {
        let env = env(&[("azure_storage_account_name", "slatefs06141914b0d7")]);

        let rewritten = azure_compat_url(
            "az://slatefs06141914b0d7/slatefs/prodtest-20260614191441",
            &env,
        )
        .expect("legacy Azure URL should rewrite");

        assert_eq!(
            rewritten,
            "az://slatefs@slatefs06141914b0d7.blob.core.windows.net/prodtest-20260614191441"
        );
    }

    #[test]
    fn azure_compat_uses_connection_string_account_as_url_host() {
        let env = env(&[(
            "azure_storage_connection_string",
            "DefaultEndpointsProtocol=https;AccountName=slatefs06141914b0d7;AccountKey=fake-key;EndpointSuffix=core.windows.net",
        )]);

        let rewritten = azure_compat_url(
            "az://slatefs06141914b0d7/slatefs/prodtest-20260614191441",
            &env,
        )
        .expect("legacy Azure URL should rewrite");

        assert_eq!(
            rewritten,
            "az://slatefs@slatefs06141914b0d7.blob.core.windows.net/prodtest-20260614191441"
        );
    }

    #[test]
    fn azure_native_container_prefix_is_not_rewritten_when_host_is_not_env_account() {
        let env = env(&[("azure_storage_account_name", "slatefs06141914b0d7")]);

        assert_eq!(
            azure_compat_url("az://slatefs/compat-verify-native-123", &env),
            None
        );
        assert_eq!(
            azure_compat_url("az://slatefs/a/multi-segment/prefix", &env),
            None
        );
    }

    #[test]
    fn azure_explicit_container_at_account_form_is_not_rewritten() {
        let env = env(&[("azure_storage_account_name", "slatefs06141914b0d7")]);

        assert_eq!(
            azure_compat_url(
                "az://slatefs@slatefs06141914b0d7.blob.core.windows.net/prodtest",
                &env,
            ),
            None
        );
    }

    #[test]
    fn azure_compat_structural_fallback_requires_prefix_without_env_account() {
        let empty_env = env(&[]);

        let rewritten = azure_compat_url("az://slatefs06141914b0d7/slatefs/prodtest", &empty_env)
            .expect("storage-account-shaped host with container and prefix should rewrite");
        assert_eq!(
            rewritten,
            "az://slatefs@slatefs06141914b0d7.blob.core.windows.net/prodtest"
        );
        assert_eq!(
            azure_compat_url("az://slatefs06141914b0d7/slatefs", &empty_env),
            None
        );
    }

    #[test]
    fn azure_connection_string_expands_account_and_key_options() {
        let mut env = env(&[(
            "azure_storage_connection_string",
            "DefaultEndpointsProtocol=https;AccountName=acct1;AccountKey=fake-key;EndpointSuffix=core.windows.net",
        )]);

        add_azure_connection_string_options(&mut env);

        assert!(env.contains(&(
            "azure_storage_account_name".to_string(),
            "acct1".to_string()
        )));
        assert!(env.contains(&(
            "azure_storage_access_key".to_string(),
            "fake-key".to_string()
        )));
    }
}
