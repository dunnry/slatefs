//! Axum HTTP-to-VFS adapter for the live consumer data plane.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::extract::{Path, Query, State};
use axum::http::header::{
    ACCEPT_RANGES, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
    ETAG, IF_MATCH, RANGE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures::{StreamExt, stream};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use slatefs_core::control::{ControlReader, VolumeState};
use slatefs_core::meta::inode::{FileKind, Timespec};
use slatefs_core::meta::superblock::VolumeKind as CoreVolumeKind;
use slatefs_core::vfs::{Credentials, FileAttr, FsError, OpenMode, SetAttrs, Vfs};
use slatefs_core::volume::Volume;
use uuid::Uuid;

use crate::CONSUMER_V1_PREFIX;
use crate::auth::{AuthError, TenantAuthenticator, TenantPrincipal};
use crate::dto::*;
use crate::errors::{ErrorCode, HttpError};
use crate::identifiers::{EntryToken, PageToken, TokenSigner};
use crate::metrics::ConsumerMetrics;
use crate::registry::LiveVolumeRegistry;
use crate::views::{HistoricalViewError, HistoricalViewProvider, UnsupportedHistoricalViews};

#[derive(Clone)]
pub struct ConsumerState {
    pub registry: LiveVolumeRegistry,
    pub control: Arc<ControlReader>,
    pub auth: TenantAuthenticator,
    pub signer: TokenSigner,
    pub limits: slatefs_core::config::ConsumerConfig,
    pub metrics: ConsumerMetrics,
    pub historical_views: Arc<dyn HistoricalViewProvider>,
    /// Serializes consumer mutations by destination. It cannot serialize an
    /// NFS/9P writer; cross-protocol ETags therefore remain best effort.
    destination_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    operation_idempotency: Arc<Mutex<HashMap<String, (String, OperationResult)>>>,
}

impl ConsumerState {
    #[must_use]
    pub fn new(
        registry: LiveVolumeRegistry,
        control: Arc<ControlReader>,
        auth: TenantAuthenticator,
        signer: TokenSigner,
        limits: slatefs_core::config::ConsumerConfig,
    ) -> Self {
        Self {
            registry,
            control,
            auth,
            signer,
            limits,
            metrics: ConsumerMetrics::default(),
            historical_views: Arc::new(UnsupportedHistoricalViews),
            destination_locks: Arc::default(),
            operation_idempotency: Arc::default(),
        }
    }

    #[must_use]
    pub fn with_historical_views(mut self, provider: Arc<dyn HistoricalViewProvider>) -> Self {
        self.historical_views = provider;
        self
    }
}

pub fn router(state: ConsumerState) -> Router {
    Router::new()
        .route("/consumer/v1/capabilities", get(capabilities))
        .route("/consumer/v1/volumes", get(list_volumes))
        .route("/consumer/v1/volumes/{volume}", get(volume_detail))
        .route(
            "/consumer/v1/volumes/{volume}/entries",
            get(entries)
                .post(create_entry)
                .patch(update_entry)
                .delete(delete_entry),
        )
        .route(
            "/consumer/v1/volumes/{volume}/content",
            get(read_content).put(write_content),
        )
        .route("/consumer/v1/volumes/{volume}/operations", post(operations))
        .route(
            "/consumer/v1/volumes/{volume}/xattrs",
            get(get_xattrs).patch(update_xattrs),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observe_request,
        ))
        .with_state(state)
}

async fn observe_request(
    State(state): State<ConsumerState>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let started = std::time::Instant::now();
    let operation = request.extensions().get::<MatchedPath>().map_or_else(
        || "unmatched".to_owned(),
        |path| format!("{} {}", request.method(), path.as_str()),
    );
    let rid = request_id(request.headers());
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&rid) {
        response.headers_mut().insert("x-request-id", value);
    }
    let bytes = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    state.metrics.record(
        &operation,
        response.status().as_u16(),
        bytes,
        started.elapsed(),
    );
    response
}

pub async fn serve(listen: SocketAddr, state: ConsumerState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "consumer API ready at {CONSUMER_V1_PREFIX}");
    axum::serve(listener, router(state)).await
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn principal(
    state: &ConsumerState,
    headers: &HeaderMap,
    rid: &str,
) -> Result<TenantPrincipal, HttpError> {
    let authorization = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    state
        .auth
        .authenticate(authorization)
        .map_err(|error| match error {
            AuthError::Unauthorized => HttpError::new(
                ErrorCode::AuthenticationRequired,
                rid,
                "tenant authentication required",
            ),
            AuthError::Unavailable => HttpError::new(
                ErrorCode::PrimaryUnavailable,
                rid,
                "tenant authentication is temporarily unavailable",
            ),
        })
}

fn volume_for(
    state: &ConsumerState,
    principal: &TenantPrincipal,
    name: &str,
    rid: &str,
) -> Result<Arc<Volume>, HttpError> {
    state
        .registry
        .get(&principal.tenant, name)
        .ok_or_else(|| HttpError::new(ErrorCode::NotFound, rid, "volume was not found"))
}

fn creds(principal: &TenantPrincipal) -> Credentials {
    Credentials::user(principal.uid, principal.gid)
}
fn fs(error: FsError, rid: &str, volume: &Volume) -> HttpError {
    HttpError::from_fs(error, rid, volume.is_dead())
}
fn fs_state(error: FsError, rid: &str, live_dead: bool) -> HttpError {
    HttpError::from_fs(error, rid, live_dead)
}

#[derive(Default, Deserialize)]
struct MutationViewQuery {
    view: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
}

fn require_live_mutation(query: &MutationViewQuery, rid: &str) -> Result<(), HttpError> {
    match query.view.as_deref().unwrap_or("live") {
        "live" if query.reference.is_none() => Ok(()),
        "snapshot" | "version" => Err(HttpError::new(
            ErrorCode::ReadOnlyView,
            rid,
            "historical views are read-only",
        )),
        _ => Err(HttpError::new(
            ErrorCode::InvalidRequest,
            rid,
            "invalid view selection",
        )),
    }
}

struct ReadView {
    vfs: Arc<dyn Vfs>,
    selection: ViewSelection,
    binding: [u8; 32],
    lease: Option<Arc<dyn Send + Sync>>,
    live_dead: bool,
}

fn view_binding(tenant: &str, volume: &str, kind: ViewKind, exact_id: Option<&str>) -> [u8; 32] {
    let mut hash = Sha256::new();
    for value in [
        tenant,
        volume,
        match kind {
            ViewKind::Live => "live",
            ViewKind::Snapshot => "snapshot",
            ViewKind::Version => "version",
        },
        exact_id.unwrap_or(""),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

async fn read_view(
    state: &ConsumerState,
    principal: &TenantPrincipal,
    volume_name: &str,
    query: &SelectorQuery,
    rid: &str,
) -> Result<ReadView, HttpError> {
    let live = volume_for(state, principal, volume_name, rid)?;
    match query.view.as_deref().unwrap_or("live") {
        "live" if query.reference.is_none() => Ok(ReadView {
            live_dead: live.is_dead(),
            vfs: live,
            binding: view_binding(&principal.tenant, volume_name, ViewKind::Live, None),
            selection: ViewSelection {
                kind: ViewKind::Live,
                reference: None,
                resolved_commit: None,
            },
            lease: None,
        }),
        "snapshot" | "version" => {
            let reference = query
                .reference
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    HttpError::new(
                        ErrorCode::InvalidRequest,
                        rid,
                        "ref is required for historical views",
                    )
                })?;
            let kind = if query.view.as_deref() == Some("snapshot") {
                ViewKind::Snapshot
            } else {
                ViewKind::Version
            };
            let historical = state
                .historical_views
                .open(&principal.tenant, volume_name, kind, reference)
                .await
                .map_err(|error| match error {
                    HistoricalViewError::NotFound => {
                        HttpError::new(ErrorCode::NotFound, rid, "historical view was not found")
                    }
                    HistoricalViewError::Invalid => HttpError::new(
                        ErrorCode::InvalidRequest,
                        rid,
                        "invalid historical view selector",
                    ),
                    HistoricalViewError::Unavailable => HttpError::new(
                        ErrorCode::PrimaryUnavailable,
                        rid,
                        "historical view service is unavailable",
                    ),
                })?;
            let selection = ViewSelection {
                kind: historical.kind.clone(),
                reference: Some(if historical.kind == ViewKind::Snapshot {
                    historical.exact_id.clone()
                } else {
                    reference.to_owned()
                }),
                resolved_commit: (historical.kind == ViewKind::Version)
                    .then(|| historical.exact_id.clone()),
            };
            Ok(ReadView {
                vfs: Arc::clone(&historical.vfs),
                binding: view_binding(
                    &principal.tenant,
                    volume_name,
                    historical.kind.clone(),
                    Some(&historical.exact_id),
                ),
                selection,
                lease: Some(historical.lease()),
                live_dead: false,
            })
        }
        _ => Err(HttpError::new(
            ErrorCode::InvalidRequest,
            rid,
            "invalid view selection",
        )),
    }
}

#[derive(Default, Deserialize)]
struct ListQuery {
    limit: Option<u32>,
    page_token: Option<String>,
}

async fn capabilities(
    State(state): State<ConsumerState>,
    headers: HeaderMap,
) -> Result<Json<CapabilitiesResponse>, HttpError> {
    let rid = request_id(&headers);
    principal(&state, &headers, &rid)?;
    Ok(Json(CapabilitiesResponse {
        api_version: "consumer/v1".into(),
        limits: CapabilityLimits {
            max_page_size: state.limits.max_page_size,
            max_range_bytes: state.limits.max_range_bytes,
            max_recursive_entries: state.limits.max_recursive_entries,
            max_recursive_bytes: state.limits.max_recursive_bytes,
            max_text_edit_bytes: state.limits.max_upload_bytes.min(1024 * 1024),
            max_diff_bytes: 2 * 1024 * 1024,
            max_diff_lines: 50_000,
        },
        features: CapabilityFeatures {
            historical_snapshots: state.historical_views.supports(ViewKind::Snapshot),
            historical_versions: state.historical_views.supports(ViewKind::Version),
            hardlinks: true,
            symlinks: true,
            xattrs: true,
        },
    }))
}

async fn list_volumes(
    State(state): State<ConsumerState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<VolumeListResponse>, HttpError> {
    let rid = request_id(&headers);
    let who = principal(&state, &headers, &rid)?;
    if query.page_token.is_some() {
        return Err(HttpError::new(
            ErrorCode::InvalidRequest,
            rid,
            "volume page tokens are not supported",
        ));
    }
    let limit = query.limit.unwrap_or(100).min(state.limits.max_page_size) as usize;
    let records = state.control.list_volumes(&who.tenant).await.map_err(|_| {
        HttpError::new(
            ErrorCode::PrimaryUnavailable,
            &rid,
            "volume inventory unavailable",
        )
    })?;
    let mut volumes = Vec::new();
    for record in records
        .into_iter()
        .filter(|v| v.state == VolumeState::Active)
        .take(limit)
    {
        let (kind, browsable, used_bytes, used_inodes) = match record.kind {
            CoreVolumeKind::Filesystem => {
                let live = state.registry.get(&who.tenant, &record.name);
                let usage = live.as_ref().map(|v| v.quota_usage()).unwrap_or((0, 0));
                (
                    VolumeKind::Filesystem,
                    live.is_some(),
                    usage.0.max(0) as u64,
                    usage.1.max(0) as u64,
                )
            }
            CoreVolumeKind::Block { .. } => (VolumeKind::Block, false, 0, 0),
        };
        volumes.push(VolumeSummary {
            name: record.name,
            kind,
            browsable,
            readonly: false,
            quota: QuotaUsage {
                used_bytes,
                limit_bytes: record.quota.bytes.hard,
                used_inodes,
                limit_inodes: record.quota.inodes.hard,
            },
        });
    }
    Ok(Json(VolumeListResponse {
        volumes,
        next_page_token: None,
    }))
}

async fn volume_detail(
    State(state): State<ConsumerState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<VolumeDetail>, HttpError> {
    let rid = request_id(&headers);
    let who = principal(&state, &headers, &rid)?;
    let volume = volume_for(&state, &who, &name, &rid)?;
    let c = creds(&who);
    let stat = volume.statfs(&c).await.map_err(|e| fs(e, &rid, &volume))?;
    let usage = volume.quota_usage();
    let limits = volume.quota_hard_limits();
    Ok(Json(VolumeDetail {
        volume: VolumeSummary {
            name,
            kind: VolumeKind::Filesystem,
            browsable: true,
            readonly: false,
            quota: QuotaUsage {
                used_bytes: usage.0.max(0) as u64,
                limit_bytes: limits.0,
                used_inodes: usage.1.max(0) as u64,
                limit_inodes: limits.1,
            },
        },
        allocated_bytes: usage.0.max(0) as u64,
        available_bytes: stat.avail_bytes,
        total_bytes: stat.total_bytes,
    }))
}

#[derive(Default, Deserialize)]
struct SelectorQuery {
    entry_id: Option<String>,
    path: Option<String>,
    view: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    limit: Option<u32>,
    page_token: Option<String>,
    include_symlink_target: Option<bool>,
}

struct Resolved {
    attr: FileAttr,
    parent: Option<(FileAttr, Vec<u8>)>,
    path: Option<String>,
}

async fn resolve(
    state: &ConsumerState,
    volume: &dyn Vfs,
    live_dead: bool,
    binding: &[u8; 32],
    c: &Credentials,
    selector: &SelectorQuery,
    rid: &str,
) -> Result<Resolved, HttpError> {
    if selector.entry_id.is_some() == selector.path.is_some() {
        return Err(HttpError::new(
            ErrorCode::InvalidPath,
            rid,
            "supply exactly one of entry_id or path",
        ));
    }
    if let Some(path) = &selector.path {
        let (attr, parent) = crate::paths::resolve_path(volume, c, path)
            .await
            .map_err(|e| fs_state(e, rid, live_dead))?;
        let parent = if let Some((ino, name)) = parent {
            Some((
                volume
                    .getattr(c, ino)
                    .await
                    .map_err(|e| fs_state(e, rid, live_dead))?,
                name,
            ))
        } else {
            None
        };
        return Ok(Resolved {
            attr,
            parent,
            path: Some(path.clone()),
        });
    }
    let token: EntryToken = state
        .signer
        .verify(selector.entry_id.as_deref().unwrap_or_default())
        .ok_or_else(|| {
            HttpError::new(
                ErrorCode::PreconditionFailed,
                rid,
                "entry identifier is invalid or stale",
            )
        })?;
    if token.version != 2 || &token.view_binding != binding || token.fsid != volume.fsid() {
        return Err(HttpError::new(
            ErrorCode::PreconditionFailed,
            rid,
            "entry identifier is foreign or stale",
        ));
    }
    if token.parent_ino == 0 && token.name.is_empty() {
        let attr = volume
            .getattr(c, token.ino)
            .await
            .map_err(|e| fs_state(e, rid, live_dead))?;
        if attr.generation != token.generation {
            return Err(HttpError::new(
                ErrorCode::PreconditionFailed,
                rid,
                "entry identifier is stale",
            ));
        }
        return Ok(Resolved {
            attr,
            parent: None,
            path: Some(String::new()),
        });
    }
    let parent = volume
        .getattr(c, token.parent_ino)
        .await
        .map_err(|e| fs_state(e, rid, live_dead))?;
    if parent.generation != token.parent_generation {
        return Err(HttpError::new(
            ErrorCode::PreconditionFailed,
            rid,
            "entry identifier is stale",
        ));
    }
    let attr = volume
        .lookup(c, token.parent_ino, &token.name)
        .await
        .map_err(|_| {
            HttpError::new(
                ErrorCode::PreconditionFailed,
                rid,
                "entry identifier is stale",
            )
        })?;
    if attr.ino != token.ino || attr.generation != token.generation {
        return Err(HttpError::new(
            ErrorCode::PreconditionFailed,
            rid,
            "entry identifier is stale",
        ));
    }
    Ok(Resolved {
        attr,
        parent: Some((parent, token.name)),
        path: None,
    })
}

fn timestamp(value: Timespec) -> String {
    format!("{}.{:09}Z", value.secs, value.nanos)
}
fn etag(fsid: u64, attr: &FileAttr) -> String {
    let mut h = Sha256::new();
    for value in [
        fsid,
        attr.ino,
        u64::from(attr.generation),
        attr.size,
        u64::from(attr.mode),
        u64::from(attr.uid),
        u64::from(attr.gid),
        u64::from(attr.nlink),
        attr.mtime.secs as u64,
        u64::from(attr.mtime.nanos),
    ] {
        h.update(value.to_be_bytes());
    }
    format!(
        "W/\"{}\"",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
    )
}

#[derive(Clone, Copy)]
struct EntryContext<'a> {
    state: &'a ConsumerState,
    volume: &'a dyn Vfs,
    live_dead: bool,
    credentials: &'a Credentials,
    request_id: &'a str,
    view_binding: &'a [u8; 32],
}

async fn dto_entry(
    context: EntryContext<'_>,
    attr: FileAttr,
    parent: Option<(FileAttr, Vec<u8>)>,
    path: Option<String>,
    include_target: bool,
) -> Result<Entry, HttpError> {
    let EntryContext {
        state,
        volume,
        live_dead,
        credentials: c,
        request_id: rid,
        view_binding,
    } = context;
    let (parent_entry_id, name) = if let Some((parent_attr, name)) = &parent {
        let pid = state
            .signer
            .sign(&EntryToken {
                version: 2,
                view_binding: *view_binding,
                fsid: volume.fsid(),
                parent_ino: 0,
                parent_generation: 0,
                ino: parent_attr.ino,
                generation: parent_attr.generation,
                name: Vec::new(),
            })
            .map_err(|_| HttpError::new(ErrorCode::Internal, rid, "identifier encoding failed"))?;
        (Some(pid), name.clone())
    } else {
        (None, Vec::new())
    };
    let (pino, pgen) = parent
        .as_ref()
        .map(|(p, _)| (p.ino, p.generation))
        .unwrap_or((0, 0));
    let entry_id = state
        .signer
        .sign(&EntryToken {
            version: 2,
            view_binding: *view_binding,
            fsid: volume.fsid(),
            parent_ino: pino,
            parent_generation: pgen,
            ino: attr.ino,
            generation: attr.generation,
            name: name.clone(),
        })
        .map_err(|_| HttpError::new(ErrorCode::Internal, rid, "identifier encoding failed"))?;
    let permission = volume
        .permissions(
            c,
            attr.ino,
            parent.as_ref().map(|(p, n)| (p.ino, n.as_slice())),
        )
        .await
        .map_err(|e| fs_state(e, rid, live_dead))?;
    let target = if include_target && attr.kind == FileKind::Symlink {
        Some(
            String::from_utf8_lossy(
                &volume
                    .readlink(c, attr.ino)
                    .await
                    .map_err(|e| fs_state(e, rid, live_dead))?,
            )
            .into_owned(),
        )
    } else {
        None
    };
    Ok(Entry {
        entry_id,
        parent_entry_id,
        path,
        name: String::from_utf8(name.clone()).ok(),
        name_bytes_base64: STANDARD.encode(name),
        kind: match attr.kind {
            FileKind::File => EntryKind::File,
            FileKind::Dir => EntryKind::Directory,
            FileKind::Symlink => EntryKind::Symlink,
            _ => EntryKind::Special,
        },
        inode: attr.ino,
        inode_decimal: attr.ino.to_string(),
        generation: u64::from(attr.generation),
        generation_decimal: u64::from(attr.generation).to_string(),
        size: attr.size,
        size_decimal: attr.size.to_string(),
        allocated_bytes: attr.blocks.saturating_mul(512),
        allocated_bytes_decimal: attr.blocks.saturating_mul(512).to_string(),
        mode: attr.mode,
        uid: attr.uid,
        gid: attr.gid,
        link_count: u64::from(attr.nlink),
        link_count_decimal: u64::from(attr.nlink).to_string(),
        created_at: timestamp(attr.ctime),
        modified_at: timestamp(attr.mtime),
        changed_at: timestamp(attr.ctime),
        accessed_at: timestamp(attr.atime),
        readonly: volume.read_only(),
        capabilities: EntryCapabilities {
            can_read: permission.can_read,
            can_write: permission.can_write,
            can_delete: permission.can_delete,
            can_rename: permission.can_rename,
        },
        etag: etag(volume.fsid(), &attr),
        symlink_target: target,
    })
}

async fn entries(
    State(state): State<ConsumerState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SelectorQuery>,
) -> Result<Json<EntryListResponse>, HttpError> {
    let rid = request_id(&headers);
    let who = principal(&state, &headers, &rid)?;
    let view = read_view(&state, &who, &name, &query, &rid).await?;
    let volume = &view.vfs;
    let c = creds(&who);
    let resolved = resolve(
        &state,
        volume.as_ref(),
        view.live_dead,
        &view.binding,
        &c,
        &query,
        &rid,
    )
    .await?;
    let parent_for_children = resolved.attr.clone();
    let entry_context = EntryContext {
        state: &state,
        volume: volume.as_ref(),
        live_dead: view.live_dead,
        credentials: &c,
        request_id: &rid,
        view_binding: &view.binding,
    };
    let entry = dto_entry(
        entry_context,
        resolved.attr.clone(),
        resolved.parent,
        resolved.path,
        query.include_symlink_target.unwrap_or(false),
    )
    .await?;
    let mut children = Vec::new();
    let mut next = None;
    if resolved.attr.kind == FileKind::Dir {
        let cookie = if let Some(token) = &query.page_token {
            let page: PageToken = state.signer.verify(token).ok_or_else(|| {
                HttpError::new(ErrorCode::PreconditionFailed, &rid, "page token is invalid")
            })?;
            if page.version != 2
                || page.view_binding != view.binding
                || page.fsid != volume.fsid()
                || page.dir_ino != resolved.attr.ino
                || page.dir_generation != resolved.attr.generation
            {
                return Err(HttpError::new(
                    ErrorCode::PreconditionFailed,
                    &rid,
                    "page token is stale",
                ));
            }
            page.cookie
        } else {
            0
        };
        let limit = query.limit.unwrap_or(100).min(state.limits.max_page_size) as usize;
        let page = volume
            .readdir(&c, resolved.attr.ino, cookie, limit)
            .await
            .map_err(|e| fs_state(e, &rid, view.live_dead))?;
        for child in &page.entries {
            let attr = volume
                .getattr(&c, child.ino)
                .await
                .map_err(|e| fs_state(e, &rid, view.live_dead))?;
            children.push(
                dto_entry(
                    entry_context,
                    attr,
                    Some((parent_for_children.clone(), child.name.clone())),
                    None,
                    query.include_symlink_target.unwrap_or(false),
                )
                .await?,
            );
        }
        if !page.eof
            && let Some(last) = page.entries.last()
        {
            next = Some(
                state
                    .signer
                    .sign(&PageToken {
                        version: 2,
                        view_binding: view.binding,
                        fsid: volume.fsid(),
                        dir_ino: resolved.attr.ino,
                        dir_generation: resolved.attr.generation,
                        cookie: last.cookie,
                    })
                    .map_err(|_| {
                        HttpError::new(ErrorCode::Internal, &rid, "page token encoding failed")
                    })?,
            );
        }
    }
    Ok(Json(EntryListResponse {
        view: view.selection,
        entry,
        entries: children,
        next_page_token: next,
    }))
}

async fn create_entry(
    State(state): State<ConsumerState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(view): Query<MutationViewQuery>,
    Json(body): Json<CreateEntryRequest>,
) -> Result<(StatusCode, Json<Entry>), HttpError> {
    let rid = request_id(&headers);
    require_live_mutation(&view, &rid)?;
    let who = principal(&state, &headers, &rid)?;
    let volume = volume_for(&state, &who, &name, &rid)?;
    let c = creds(&who);
    let binding = view_binding(&who.tenant, &name, ViewKind::Live, None);
    let selector = SelectorQuery {
        entry_id: Some(body.parent_entry_id),
        ..Default::default()
    };
    let parent = resolve(
        &state,
        volume.as_ref(),
        volume.is_dead(),
        &binding,
        &c,
        &selector,
        &rid,
    )
    .await?;
    if parent.attr.kind != FileKind::Dir {
        return Err(HttpError::new(
            ErrorCode::InvalidRequest,
            rid,
            "parent is not a directory",
        ));
    }
    let mode = body.mode.unwrap_or(match body.kind {
        CreateKind::Directory => 0o755,
        _ => 0o644,
    }) & 0o7777;
    let lock = destination_lock(
        &state,
        &who.tenant,
        &name,
        parent.attr.ino,
        body.name.as_bytes(),
    );
    let _guard = lock.lock().await;
    let attr = match body.kind {
        CreateKind::File => {
            volume
                .create(&c, parent.attr.ino, body.name.as_bytes(), mode, true)
                .await
        }
        CreateKind::Directory => {
            volume
                .mkdir(&c, parent.attr.ino, body.name.as_bytes(), mode)
                .await
        }
        CreateKind::Symlink => {
            volume
                .symlink(
                    &c,
                    parent.attr.ino,
                    body.name.as_bytes(),
                    body.symlink_target
                        .as_deref()
                        .ok_or_else(|| {
                            HttpError::new(
                                ErrorCode::InvalidRequest,
                                &rid,
                                "symlink_target is required",
                            )
                        })?
                        .as_bytes(),
                )
                .await
        }
    }
    .map_err(|e| fs(e, &rid, &volume))?;
    let result = dto_entry(
        EntryContext {
            state: &state,
            volume: volume.as_ref(),
            live_dead: volume.is_dead(),
            credentials: &c,
            request_id: &rid,
            view_binding: &binding,
        },
        attr,
        Some((parent.attr, body.name.into_bytes())),
        None,
        false,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(result)))
}

async fn update_entry(
    State(state): State<ConsumerState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(view): Query<MutationViewQuery>,
    Json(body): Json<UpdateEntryRequest>,
) -> Result<Json<Entry>, HttpError> {
    let rid = request_id(&headers);
    require_live_mutation(&view, &rid)?;
    let who = principal(&state, &headers, &rid)?;
    let volume = volume_for(&state, &who, &name, &rid)?;
    let c = creds(&who);
    let binding = view_binding(&who.tenant, &name, ViewKind::Live, None);
    let source = resolve(
        &state,
        volume.as_ref(),
        volume.is_dead(),
        &binding,
        &c,
        &SelectorQuery {
            entry_id: Some(body.entry_id),
            ..Default::default()
        },
        &rid,
    )
    .await?;
    check_match(&headers, volume.fsid(), &source.attr, &rid)?;
    if body.mode.is_some() && (body.destination_parent_entry_id.is_some() || body.name.is_some()) {
        return Err(HttpError::new(
            ErrorCode::InvalidRequest,
            rid,
            "metadata and rename changes must be separate requests",
        ));
    }
    let mut final_parent = source.parent.clone();
    let mut attr = source.attr;
    if let Some(mode) = body.mode {
        attr = volume
            .setattr(
                &c,
                attr.ino,
                SetAttrs {
                    mode: Some(mode & 0o7777),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
    } else if body.destination_parent_entry_id.is_some() || body.name.is_some() {
        let (old_parent, old_name) = source.parent.ok_or_else(|| {
            HttpError::new(
                ErrorCode::InvalidRequest,
                &rid,
                "the volume root cannot be renamed",
            )
        })?;
        let destination = if let Some(id) = body.destination_parent_entry_id {
            resolve(
                &state,
                volume.as_ref(),
                volume.is_dead(),
                &binding,
                &c,
                &SelectorQuery {
                    entry_id: Some(id),
                    ..Default::default()
                },
                &rid,
            )
            .await?
        } else {
            Resolved {
                attr: old_parent.clone(),
                parent: None,
                path: None,
            }
        };
        let new_name = body
            .name
            .unwrap_or_else(|| String::from_utf8_lossy(&old_name).into_owned());
        let lock = destination_lock(
            &state,
            &who.tenant,
            &name,
            destination.attr.ino,
            new_name.as_bytes(),
        );
        let _guard = lock.lock().await;
        volume
            .rename(
                &c,
                old_parent.ino,
                &old_name,
                destination.attr.ino,
                new_name.as_bytes(),
            )
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        attr = volume
            .lookup(&c, destination.attr.ino, new_name.as_bytes())
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        final_parent = Some((destination.attr, new_name.into_bytes()));
    }
    Ok(Json(
        dto_entry(
            EntryContext {
                state: &state,
                volume: volume.as_ref(),
                live_dead: volume.is_dead(),
                credentials: &c,
                request_id: &rid,
                view_binding: &binding,
            },
            attr,
            final_parent,
            None,
            false,
        )
        .await?,
    ))
}

#[derive(Deserialize)]
struct DeleteQuery {
    entry_id: String,
    recursive: bool,
    view: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
}
async fn delete_entry(
    State(state): State<ConsumerState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, HttpError> {
    let rid = request_id(&headers);
    require_live_mutation(
        &MutationViewQuery {
            view: query.view.clone(),
            reference: query.reference.clone(),
        },
        &rid,
    )?;
    let who = principal(&state, &headers, &rid)?;
    let volume = volume_for(&state, &who, &name, &rid)?;
    let c = creds(&who);
    let binding = view_binding(&who.tenant, &name, ViewKind::Live, None);
    let target = resolve(
        &state,
        volume.as_ref(),
        volume.is_dead(),
        &binding,
        &c,
        &SelectorQuery {
            entry_id: Some(query.entry_id),
            ..Default::default()
        },
        &rid,
    )
    .await?;
    let (parent, basename) = target.parent.ok_or_else(|| {
        HttpError::new(
            ErrorCode::InvalidRequest,
            &rid,
            "the volume root cannot be deleted",
        )
    })?;
    let lock = destination_lock(&state, &who.tenant, &name, parent.ino, &basename);
    let _guard = lock.lock().await;
    let current = volume
        .lookup(&c, parent.ino, &basename)
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
    check_match(&headers, volume.fsid(), &current, &rid)?;
    let mut count = 0;
    let mut bytes = 0;
    if target.attr.kind == FileKind::Dir && query.recursive {
        // Walk the complete tree before changing it. This makes recursive
        // ceilings a precondition instead of a source of partial deletion.
        recursive_measure(
            volume.as_ref(),
            &c,
            target.attr.ino,
            &state.limits,
            &mut count,
            &mut bytes,
        )
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
        recursive_delete(&volume, &c, target.attr.ino, &state.limits)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
    }
    if target.attr.kind == FileKind::Dir {
        volume.rmdir(&c, parent.ino, &basename).await
    } else {
        volume.unlink(&c, parent.ino, &basename).await
    }
    .map_err(|e| fs(e, &rid, &volume))?;
    Ok(StatusCode::NO_CONTENT)
}

fn recursive_measure<'a>(
    volume: &'a Volume,
    c: &'a Credentials,
    ino: u64,
    limits: &'a slatefs_core::config::ConsumerConfig,
    count: &'a mut u64,
    bytes: &'a mut u64,
) -> futures::future::BoxFuture<'a, Result<(), FsError>> {
    Box::pin(async move {
        let mut cookie = 0;
        loop {
            let page = volume
                .readdir(c, ino, cookie, limits.max_page_size as usize)
                .await?;
            for child in page.entries {
                *count += 1;
                let attr = volume.getattr(c, child.ino).await?;
                *bytes = bytes.saturating_add(attr.size);
                if *count > limits.max_recursive_entries || *bytes > limits.max_recursive_bytes {
                    return Err(FsError::FileTooBig);
                }
                if attr.kind == FileKind::Dir {
                    recursive_measure(volume, c, attr.ino, limits, count, bytes).await?;
                }
                cookie = child.cookie;
            }
            if page.eof {
                break;
            }
        }
        Ok(())
    })
}

fn recursive_delete<'a>(
    volume: &'a Volume,
    c: &'a Credentials,
    ino: u64,
    limits: &'a slatefs_core::config::ConsumerConfig,
) -> futures::future::BoxFuture<'a, Result<(), FsError>> {
    Box::pin(async move {
        let mut cookie = 0;
        loop {
            let page = volume
                .readdir(c, ino, cookie, limits.max_page_size as usize)
                .await?;
            for child in page.entries {
                let attr = volume.getattr(c, child.ino).await?;
                if attr.kind == FileKind::Dir {
                    recursive_delete(volume, c, attr.ino, limits).await?;
                    volume.rmdir(c, ino, &child.name).await?;
                } else {
                    // Symlinks are unlinked and are never traversed.
                    volume.unlink(c, ino, &child.name).await?;
                }
                cookie = child.cookie;
            }
            if page.eof {
                break;
            }
        }
        Ok(())
    })
}

fn check_match(
    headers: &HeaderMap,
    fsid: u64,
    attr: &FileAttr,
    rid: &str,
) -> Result<(), HttpError> {
    if let Some(value) = headers.get(IF_MATCH).and_then(|v| v.to_str().ok())
        && value != etag(fsid, attr)
    {
        return Err(HttpError::new(
            ErrorCode::PreconditionFailed,
            rid,
            "If-Match precondition failed",
        ));
    }
    Ok(())
}
fn destination_lock(
    state: &ConsumerState,
    tenant: &str,
    volume: &str,
    parent: u64,
    name: &[u8],
) -> Arc<tokio::sync::Mutex<()>> {
    let key = format!("{tenant}\0{volume}\0{parent}\0{}", STANDARD.encode(name));
    state
        .destination_locks
        .lock()
        .expect("destination locks poisoned")
        .entry(key)
        .or_default()
        .clone()
}

fn parse_range(
    value: Option<&str>,
    size: u64,
    max: u64,
    rid: &str,
) -> Result<Option<(u64, u64)>, HttpError> {
    let Some(value) = value else { return Ok(None) };
    if value.contains(',') || !value.starts_with("bytes=") {
        return Err(HttpError::new(
            ErrorCode::MalformedRange,
            rid,
            "only one byte range is supported",
        ));
    }
    let (start, end) = value[6..]
        .split_once('-')
        .ok_or_else(|| HttpError::new(ErrorCode::MalformedRange, rid, "malformed byte range"))?;
    let (start, end) = if start.is_empty() {
        let suffix: u64 = end
            .parse()
            .map_err(|_| HttpError::new(ErrorCode::MalformedRange, rid, "malformed byte range"))?;
        if suffix == 0 {
            return Err(HttpError::new(
                ErrorCode::RangeNotSatisfiable,
                rid,
                "byte range is unsatisfiable",
            ));
        }
        (size.saturating_sub(suffix), size.saturating_sub(1))
    } else {
        let start: u64 = start
            .parse()
            .map_err(|_| HttpError::new(ErrorCode::MalformedRange, rid, "malformed byte range"))?;
        let end = if end.is_empty() {
            size.saturating_sub(1)
        } else {
            end.parse().map_err(|_| {
                HttpError::new(ErrorCode::MalformedRange, rid, "malformed byte range")
            })?
        };
        (start, end.min(size.saturating_sub(1)))
    };
    if size == 0 || start >= size || start > end || end - start + 1 > max {
        return Err(HttpError::new(
            ErrorCode::RangeNotSatisfiable,
            rid,
            "byte range is unsatisfiable or exceeds the configured limit",
        ));
    }
    Ok(Some((start, end)))
}

async fn read_content(
    State(state): State<ConsumerState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SelectorQuery>,
) -> Result<Response, HttpError> {
    let rid = request_id(&headers);
    let who = principal(&state, &headers, &rid)?;
    let view = read_view(&state, &who, &name, &query, &rid).await?;
    let volume = &view.vfs;
    let c = creds(&who);
    let target = resolve(
        &state,
        volume.as_ref(),
        view.live_dead,
        &view.binding,
        &c,
        &query,
        &rid,
    )
    .await?;
    if !matches!(target.attr.kind, FileKind::File | FileKind::Symlink) {
        return Err(HttpError::new(
            ErrorCode::InvalidRequest,
            rid,
            "content is available only for files and symlinks",
        ));
    }
    let range = parse_range(
        headers.get(RANGE).and_then(|v| v.to_str().ok()),
        target.attr.size,
        state.limits.max_range_bytes,
        &rid,
    )?;
    let (start, end, status) = range
        .map(|(s, e)| (s, e, StatusCode::PARTIAL_CONTENT))
        .unwrap_or((0, target.attr.size.saturating_sub(1), StatusCode::OK));
    let length = if target.attr.size == 0 {
        0
    } else {
        end - start + 1
    };
    let body = if target.attr.kind == FileKind::Symlink {
        let target = volume
            .readlink(&c, target.attr.ino)
            .await
            .map_err(|e| fs_state(e, &rid, view.live_dead))?;
        let start = usize::try_from(start).map_err(|_| {
            HttpError::new(
                ErrorCode::RangeNotSatisfiable,
                &rid,
                "byte range is too large",
            )
        })?;
        let length = usize::try_from(length).map_err(|_| {
            HttpError::new(
                ErrorCode::RangeNotSatisfiable,
                &rid,
                "byte range is too large",
            )
        })?;
        Body::from(target[start..start + length].to_vec())
    } else {
        let chunk = u64::from(state.limits.stream_chunk_bytes);
        let v = Arc::clone(volume);
        let lease = view.lease.clone();
        let ino = target.attr.ino;
        Body::from_stream(stream::unfold(
            (v, c, start, length, lease),
            move |(v, c, offset, left, lease)| async move {
                if left == 0 {
                    None
                } else {
                    let wanted = left.min(chunk).min(u64::from(u32::MAX)) as u32;
                    match v.read(&c, ino, offset, wanted).await {
                        Ok(data) if data.is_empty() => None,
                        Ok(data) => {
                            let got = data.len() as u64;
                            Some((
                                Ok::<_, std::io::Error>(data),
                                (v, c, offset + got, left.saturating_sub(got), lease),
                            ))
                        }
                        Err(_) => Some((
                            Err(std::io::Error::other("content stream failed")),
                            (v, c, offset, 0, lease),
                        )),
                    }
                }
            },
        ))
    };
    let mut response = (status, body).into_response();
    let h = response.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(CONTENT_LENGTH, HeaderValue::from(length));
    h.insert(
        ETAG,
        HeaderValue::from_str(&etag(volume.fsid(), &target.attr)).expect("valid etag"),
    );
    h.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    if status == StatusCode::PARTIAL_CONTENT {
        h.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{}", target.attr.size))
                .expect("valid range"),
        );
    }
    if let Some(commit) = &view.selection.resolved_commit {
        h.insert(
            "x-slatefs-resolved-commit",
            HeaderValue::from_str(commit).expect("commit id is a valid header"),
        );
    }
    Ok(response)
}

#[derive(Default, Deserialize)]
struct WriteQuery {
    entry_id: Option<String>,
    parent_entry_id: Option<String>,
    name: Option<String>,
    view: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
}
async fn write_content(
    State(state): State<ConsumerState>,
    Path(volume_name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<WriteQuery>,
    body: Body,
) -> Result<(StatusCode, Json<Entry>), HttpError> {
    let rid = request_id(&headers);
    require_live_mutation(
        &MutationViewQuery {
            view: query.view.clone(),
            reference: query.reference.clone(),
        },
        &rid,
    )?;
    let who = principal(&state, &headers, &rid)?;
    let declared_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| HttpError::new(ErrorCode::InvalidRequest, &rid, "invalid Content-Length"))?;
    if declared_length.is_some_and(|length| length > state.limits.max_upload_bytes) {
        return Err(HttpError::new(
            ErrorCode::InvalidRequest,
            &rid,
            "upload exceeds configured limit",
        ));
    }
    let volume = volume_for(&state, &who, &volume_name, &rid)?;
    let c = creds(&who);
    let binding = view_binding(&who.tenant, &volume_name, ViewKind::Live, None);
    let (parent, basename, old, mode) = if let Some(id) = query.entry_id {
        let target = resolve(
            &state,
            volume.as_ref(),
            volume.is_dead(),
            &binding,
            &c,
            &SelectorQuery {
                entry_id: Some(id),
                ..Default::default()
            },
            &rid,
        )
        .await?;
        if headers.get(IF_MATCH).is_none() {
            return Err(HttpError::new(
                ErrorCode::PreconditionFailed,
                &rid,
                "If-Match is required when replacing an existing file",
            ));
        }
        if target.attr.kind != FileKind::File {
            return Err(HttpError::new(
                ErrorCode::InvalidRequest,
                &rid,
                "only regular files can be replaced",
            ));
        }
        let (p, n) = target.parent.ok_or_else(|| {
            HttpError::new(ErrorCode::InvalidRequest, &rid, "cannot replace root")
        })?;
        (p, n, Some(target.attr.clone()), target.attr.mode)
    } else {
        let parent_id = query.parent_entry_id.ok_or_else(|| {
            HttpError::new(
                ErrorCode::InvalidRequest,
                &rid,
                "parent_entry_id is required",
            )
        })?;
        let p = resolve(
            &state,
            volume.as_ref(),
            volume.is_dead(),
            &binding,
            &c,
            &SelectorQuery {
                entry_id: Some(parent_id),
                ..Default::default()
            },
            &rid,
        )
        .await?;
        let n = query
            .name
            .ok_or_else(|| HttpError::new(ErrorCode::InvalidRequest, &rid, "name is required"))?
            .into_bytes();
        (p.attr, n, None, 0o644)
    };
    let lock = destination_lock(&state, &who.tenant, &volume_name, parent.ino, &basename);
    let _guard = lock.lock().await;
    if old.is_some() {
        let current = volume
            .lookup(&c, parent.ino, &basename)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        check_match(&headers, volume.fsid(), &current, &rid)?;
    }
    let temp = format!(".slatefs-upload-{}", Uuid::new_v4());
    let staged = volume
        .create(&c, parent.ino, temp.as_bytes(), mode, true)
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
    let handle = volume
        .open(&c, staged.ino, OpenMode::Write)
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
    let mut cleanup = StagedUploadCleanup::new(
        Arc::clone(&volume),
        c.clone(),
        parent.ino,
        temp.as_bytes().to_vec(),
        handle,
    );
    let mut stream = body.into_data_stream();
    let mut offset = 0u64;
    let result: Result<(), HttpError> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                HttpError::new(ErrorCode::InvalidRequest, &rid, "upload stream failed")
            })?;
            if offset.saturating_add(chunk.len() as u64) > state.limits.max_upload_bytes {
                return Err(HttpError::new(
                    ErrorCode::InvalidRequest,
                    &rid,
                    "upload exceeds configured limit",
                ));
            }
            for part in chunk.chunks(state.limits.stream_chunk_bytes as usize) {
                let mut remaining = part;
                while !remaining.is_empty() {
                    let written = volume
                        .write(&c, staged.ino, offset, remaining)
                        .await
                        .map_err(|e| fs(e, &rid, &volume))?;
                    if written == 0 {
                        return Err(HttpError::new(
                            ErrorCode::Internal,
                            &rid,
                            "upload write made no progress",
                        ));
                    }
                    offset += u64::from(written);
                    remaining = &remaining[written as usize..];
                }
            }
        }
        if declared_length.is_some_and(|length| length != offset) {
            return Err(HttpError::new(
                ErrorCode::InvalidRequest,
                &rid,
                "request body length did not match Content-Length",
            ));
        }
        volume
            .fsync(&c, staged.ino)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        volume
            .close(handle)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        cleanup.mark_closed();
        volume
            .rename(&c, parent.ino, temp.as_bytes(), parent.ino, &basename)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        cleanup.disarm();
        Ok(())
    }
    .await;
    if let Err(error) = result {
        cleanup.cleanup_now().await;
        return Err(error);
    }
    let attr = volume
        .lookup(&c, parent.ino, &basename)
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
    let dto = dto_entry(
        EntryContext {
            state: &state,
            volume: volume.as_ref(),
            live_dead: volume.is_dead(),
            credentials: &c,
            request_id: &rid,
            view_binding: &binding,
        },
        attr,
        Some((parent, basename)),
        None,
        false,
    )
    .await?;
    Ok((
        if old.is_some() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(dto),
    ))
}

struct StagedUploadCleanup {
    volume: Arc<Volume>,
    credentials: Credentials,
    parent: u64,
    name: Vec<u8>,
    handle: Option<u64>,
    armed: bool,
}

impl StagedUploadCleanup {
    fn new(
        volume: Arc<Volume>,
        credentials: Credentials,
        parent: u64,
        name: Vec<u8>,
        handle: u64,
    ) -> Self {
        Self {
            volume,
            credentials,
            parent,
            name,
            handle: Some(handle),
            armed: true,
        }
    }

    fn mark_closed(&mut self) {
        self.handle = None;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    async fn cleanup_now(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if let Some(handle) = self.handle.take() {
            let _ = self.volume.close(handle).await;
        }
        let _ = self
            .volume
            .unlink(&self.credentials, self.parent, &self.name)
            .await;
    }
}

impl Drop for StagedUploadCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let volume = Arc::clone(&self.volume);
        let credentials = self.credentials.clone();
        let parent = self.parent;
        let name = self.name.clone();
        let handle = self.handle.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Some(handle) = handle {
                    let _ = volume.close(handle).await;
                }
                let _ = volume.unlink(&credentials, parent, &name).await;
            });
        }
    }
}

async fn operations(
    State(state): State<ConsumerState>,
    Path(volume_name): Path<String>,
    headers: HeaderMap,
    Query(view): Query<MutationViewQuery>,
    Json(body): Json<OperationRequest>,
) -> Result<Json<OperationResult>, HttpError> {
    let rid = request_id(&headers);
    require_live_mutation(&view, &rid)?;
    let who = principal(&state, &headers, &rid)?;
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| {
            HttpError::new(
                ErrorCode::InvalidRequest,
                &rid,
                "Idempotency-Key is required",
            )
        })?;
    let volume = volume_for(&state, &who, &volume_name, &rid)?;
    if body.conflict_policy == ConflictPolicy::Overwrite
        && !matches!(body.operation, OperationKind::Move)
    {
        return Err(HttpError::new(
            ErrorCode::InvalidRequest,
            &rid,
            "overwrite is supported only for atomic move and staged upload",
        ));
    }
    let c = creds(&who);
    let binding = view_binding(&who.tenant, &volume_name, ViewKind::Live, None);
    let request_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&body).map_err(|_| HttpError::new(
            ErrorCode::Internal,
            &rid,
            "operation encoding failed"
        ))?)
    );
    let cache_key = format!("{}\0{}\0{}", who.tenant, volume_name, idempotency_key);
    // Serialize identical keys before consulting the cache so concurrent
    // retries cannot both execute the mutation.
    let idempotency_lock = destination_lock(
        &state,
        &who.tenant,
        &volume_name,
        0,
        format!("idempotency:{idempotency_key}").as_bytes(),
    );
    let _idempotency_guard = idempotency_lock.lock().await;
    if let Some((stored_hash, result)) = state
        .operation_idempotency
        .lock()
        .expect("idempotency cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        if stored_hash != request_hash {
            return Err(HttpError::new(
                ErrorCode::Conflict,
                &rid,
                "Idempotency-Key was reused with a different request",
            ));
        }
        return Ok(Json(result));
    }
    let destination = resolve(
        &state,
        volume.as_ref(),
        volume.is_dead(),
        &binding,
        &c,
        &SelectorQuery {
            entry_id: Some(body.destination_parent_entry_id),
            ..Default::default()
        },
        &rid,
    )
    .await?;
    let mut total_entries = 0u64;
    let mut total_bytes = 0u64;
    let mut sources = Vec::with_capacity(body.source_entry_ids.len());
    for id in &body.source_entry_ids {
        let source = resolve(
            &state,
            volume.as_ref(),
            volume.is_dead(),
            &binding,
            &c,
            &SelectorQuery {
                entry_id: Some(id.clone()),
                ..Default::default()
            },
            &rid,
        )
        .await?;
        if matches!(body.operation, OperationKind::Hardlink) && source.attr.kind != FileKind::File {
            return Err(HttpError::new(
                ErrorCode::InvalidRequest,
                &rid,
                "hardlinks require regular files",
            ));
        }
        let before = total_entries;
        total_entries += 1;
        total_bytes = total_bytes.saturating_add(source.attr.size);
        if source.attr.kind == FileKind::Dir {
            recursive_measure(
                &volume,
                &c,
                source.attr.ino,
                &state.limits,
                &mut total_entries,
                &mut total_bytes,
            )
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        }
        sources.push((source, total_entries - before));
    }
    let mut completed_entries = 0;
    if !body.preview {
        for (source, source_entries) in sources {
            let (_, basename) = source.parent.clone().ok_or_else(|| {
                HttpError::new(
                    ErrorCode::InvalidRequest,
                    &rid,
                    "root cannot be operated on",
                )
            })?;
            let Some(target_name) = conflict_name(
                &volume,
                &c,
                destination.attr.ino,
                &basename,
                &body.conflict_policy,
                &rid,
            )
            .await?
            else {
                continue;
            };
            match body.operation {
                OperationKind::Move => {
                    let (old_parent, old_name) = source.parent.unwrap();
                    volume
                        .rename(
                            &c,
                            old_parent.ino,
                            &old_name,
                            destination.attr.ino,
                            &target_name,
                        )
                        .await
                        .map_err(|e| fs(e, &rid, &volume))?;
                }
                OperationKind::Hardlink => {
                    volume
                        .link(&c, source.attr.ino, destination.attr.ino, &target_name)
                        .await
                        .map_err(|e| fs(e, &rid, &volume))?;
                }
                OperationKind::Copy => {
                    // The complete tree was measured before mutation. Keep the
                    // copy routine's defensive counters separate from the result.
                    let mut copied_entries = 1;
                    let mut copied_bytes = source.attr.size;
                    copy_one(
                        CopyContext {
                            volume: &volume,
                            credentials: &c,
                            limits: &state.limits,
                        },
                        &source,
                        destination.attr.ino,
                        &target_name,
                        &mut copied_entries,
                        &mut copied_bytes,
                    )
                    .await
                    .map_err(|e| fs(e, &rid, &volume))?;
                }
            }
            completed_entries += source_entries;
        }
    }
    let result = OperationResult {
        operation_id: Uuid::new_v4().to_string(),
        preview: body.preview,
        total_entries,
        total_bytes,
        completed_entries,
        failed_entries: 0,
    };
    let mut cache = state
        .operation_idempotency
        .lock()
        .expect("idempotency cache poisoned");
    if cache.len() >= state.limits.idempotency_entries {
        cache.clear();
    }
    cache.insert(cache_key, (request_hash, result.clone()));
    Ok(Json(result))
}

async fn conflict_name(
    volume: &Volume,
    c: &Credentials,
    parent: u64,
    name: &[u8],
    policy: &ConflictPolicy,
    rid: &str,
) -> Result<Option<Vec<u8>>, HttpError> {
    match volume.lookup(c, parent, name).await {
        Err(FsError::NotFound) => Ok(Some(name.to_vec())),
        Err(e) => Err(fs(e, rid, volume)),
        Ok(_) => match policy {
            ConflictPolicy::Fail => Err(HttpError::new(
                ErrorCode::Conflict,
                rid,
                "destination exists",
            )),
            ConflictPolicy::Skip => Ok(None),
            ConflictPolicy::Overwrite => {
                let existing = volume
                    .lookup(c, parent, name)
                    .await
                    .map_err(|e| fs(e, rid, volume))?;
                if existing.kind == FileKind::Dir {
                    volume.rmdir(c, parent, name).await
                } else {
                    volume.unlink(c, parent, name).await
                }
                .map_err(|e| fs(e, rid, volume))?;
                Ok(Some(name.to_vec()))
            }
            ConflictPolicy::KeepBoth => {
                let text = std::str::from_utf8(name).map_err(|_| {
                    HttpError::new(
                        ErrorCode::InvalidRequest,
                        rid,
                        "keep_both is unsupported for byte-only names",
                    )
                })?;
                for n in 1..=9999 {
                    let candidate = format!("{text} (copy {n})").into_bytes();
                    if matches!(
                        volume.lookup(c, parent, &candidate).await,
                        Err(FsError::NotFound)
                    ) {
                        return Ok(Some(candidate));
                    }
                }
                Err(HttpError::new(
                    ErrorCode::Conflict,
                    rid,
                    "no keep_both name is available",
                ))
            }
        },
    }
}

#[derive(Clone, Copy)]
struct CopyContext<'a> {
    volume: &'a Volume,
    credentials: &'a Credentials,
    limits: &'a slatefs_core::config::ConsumerConfig,
}

fn copy_one<'a>(
    context: CopyContext<'a>,
    source: &'a Resolved,
    dest_parent: u64,
    dest_name: &'a [u8],
    count: &'a mut u64,
    bytes: &'a mut u64,
) -> futures::future::BoxFuture<'a, Result<(), FsError>> {
    Box::pin(async move {
        let CopyContext {
            volume,
            credentials: c,
            limits,
        } = context;
        if *count > limits.max_recursive_entries || *bytes > limits.max_recursive_bytes {
            return Err(FsError::FileTooBig);
        }
        match source.attr.kind {
            FileKind::File => {
                let created = volume
                    .create(c, dest_parent, dest_name, source.attr.mode, true)
                    .await?;
                let mut offset = 0;
                while offset < source.attr.size {
                    let data = volume
                        .read(c, source.attr.ino, offset, limits.stream_chunk_bytes)
                        .await?;
                    if data.is_empty() {
                        break;
                    }
                    volume.write(c, created.ino, offset, &data).await?;
                    offset += data.len() as u64;
                }
                for x in volume.listxattr(c, source.attr.ino).await? {
                    if x.starts_with(b"user.")
                        && let Ok(value) = volume.getxattr(c, source.attr.ino, &x).await
                    {
                        let _ = volume.setxattr(c, created.ino, &x, &value).await;
                    }
                }
                volume.fsync(c, created.ino).await?;
            }
            FileKind::Symlink => {
                let target = volume.readlink(c, source.attr.ino).await?;
                volume.symlink(c, dest_parent, dest_name, &target).await?;
            }
            FileKind::Dir => {
                let dir = volume
                    .mkdir(c, dest_parent, dest_name, source.attr.mode)
                    .await?;
                let mut cookie = 0;
                loop {
                    let page = volume
                        .readdir(c, source.attr.ino, cookie, limits.max_page_size as usize)
                        .await?;
                    for child in page.entries {
                        *count += 1;
                        let attr = volume.getattr(c, child.ino).await?;
                        *bytes = bytes.saturating_add(attr.size);
                        let nested = Resolved {
                            attr,
                            parent: None,
                            path: None,
                        };
                        copy_one(context, &nested, dir.ino, &child.name, count, bytes).await?;
                        cookie = child.cookie;
                    }
                    if page.eof {
                        break;
                    }
                }
            }
            _ => return Err(FsError::NotSupported),
        }
        Ok(())
    })
}

#[derive(Deserialize)]
struct XattrQuery {
    entry_id: String,
    view: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    name: Option<String>,
}
async fn get_xattrs(
    State(state): State<ConsumerState>,
    Path(volume_name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<XattrQuery>,
) -> Result<Json<XattrListResponse>, HttpError> {
    let rid = request_id(&headers);
    let who = principal(&state, &headers, &rid)?;
    let selector = SelectorQuery {
        entry_id: Some(query.entry_id.clone()),
        view: query.view,
        reference: query.reference,
        ..Default::default()
    };
    let view = read_view(&state, &who, &volume_name, &selector, &rid).await?;
    let volume = &view.vfs;
    let c = creds(&who);
    let target = resolve(
        &state,
        volume.as_ref(),
        view.live_dead,
        &view.binding,
        &c,
        &selector,
        &rid,
    )
    .await?;
    let names = if let Some(name) = query.name {
        vec![name.into_bytes()]
    } else {
        volume
            .listxattr(&c, target.attr.ino)
            .await
            .map_err(|e| fs_state(e, &rid, view.live_dead))?
    };
    let mut values = Vec::new();
    for name in names {
        if !name.starts_with(b"user.") {
            continue;
        }
        let value = volume
            .getxattr(&c, target.attr.ino, &name)
            .await
            .map_err(|e| fs_state(e, &rid, view.live_dead))?;
        values.push(XattrValue {
            name: String::from_utf8(name.clone()).ok(),
            name_bytes_base64: STANDARD.encode(name),
            value_base64: STANDARD.encode(value),
        });
    }
    Ok(Json(XattrListResponse {
        entry_id: query.entry_id,
        xattrs: values,
        view: Some(view.selection),
    }))
}

async fn update_xattrs(
    State(state): State<ConsumerState>,
    Path(volume_name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<XattrQuery>,
    Json(body): Json<UpdateXattrsRequest>,
) -> Result<Json<XattrListResponse>, HttpError> {
    let rid = request_id(&headers);
    require_live_mutation(
        &MutationViewQuery {
            view: query.view.clone(),
            reference: query.reference.clone(),
        },
        &rid,
    )?;
    let who = principal(&state, &headers, &rid)?;
    let volume = volume_for(&state, &who, &volume_name, &rid)?;
    let c = creds(&who);
    let binding = view_binding(&who.tenant, &volume_name, ViewKind::Live, None);
    let target = resolve(
        &state,
        volume.as_ref(),
        volume.is_dead(),
        &binding,
        &c,
        &SelectorQuery {
            entry_id: Some(query.entry_id.clone()),
            ..Default::default()
        },
        &rid,
    )
    .await?;
    let (lock_parent, lock_name) = target
        .parent
        .as_ref()
        .map(|(parent, name)| (parent.ino, name.clone()))
        .unwrap_or((target.attr.ino, Vec::new()));
    let lock = destination_lock(&state, &who.tenant, &volume_name, lock_parent, &lock_name);
    let _guard = lock.lock().await;
    let current = volume
        .getattr(&c, target.attr.ino)
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
    check_match(&headers, volume.fsid(), &current, &rid)?;
    let mut sets = body
        .set
        .into_iter()
        .map(|(name, value)| Ok((name.into_bytes(), value)))
        .collect::<Result<Vec<_>, HttpError>>()?;
    for item in body.set_bytes {
        let name = STANDARD.decode(item.name_bytes_base64).map_err(|_| {
            HttpError::new(ErrorCode::InvalidRequest, &rid, "xattr name is not base64")
        })?;
        sets.push((name, item.value_base64));
    }
    for (name, value) in sets {
        if !name.starts_with(b"user.") {
            return Err(HttpError::new(
                ErrorCode::PermissionDenied,
                &rid,
                "only user.* xattrs are allowed",
            ));
        }
        let decoded = STANDARD.decode(value).map_err(|_| {
            HttpError::new(ErrorCode::InvalidRequest, &rid, "xattr value is not base64")
        })?;
        volume
            .setxattr(&c, target.attr.ino, &name, &decoded)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
    }
    let mut removals = body
        .remove
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
    for encoded in body.remove_bytes_base64 {
        removals.push(STANDARD.decode(encoded).map_err(|_| {
            HttpError::new(ErrorCode::InvalidRequest, &rid, "xattr name is not base64")
        })?);
    }
    for name in removals {
        if !name.starts_with(b"user.") {
            return Err(HttpError::new(
                ErrorCode::PermissionDenied,
                &rid,
                "only user.* xattrs are allowed",
            ));
        }
        volume
            .removexattr(&c, target.attr.ino, &name)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
    }
    let names = volume
        .listxattr(&c, target.attr.ino)
        .await
        .map_err(|e| fs(e, &rid, &volume))?;
    let mut values = Vec::new();
    for name in names.into_iter().filter(|n| n.starts_with(b"user.")) {
        let value = volume
            .getxattr(&c, target.attr.ino, &name)
            .await
            .map_err(|e| fs(e, &rid, &volume))?;
        values.push(XattrValue {
            name: String::from_utf8(name.clone()).ok(),
            name_bytes_base64: STANDARD.encode(name),
            value_base64: STANDARD.encode(value),
        });
    }
    Ok(Json(XattrListResponse {
        entry_id: query.entry_id,
        xattrs: values,
        view: None,
    }))
}

/// Approval-friendly inventory retained beside the executable router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteContract {
    pub method: &'static str,
    pub path: &'static str,
    pub operation_id: &'static str,
}
pub const ROUTES: &[RouteContract] = &[
    RouteContract {
        method: "GET",
        path: "/consumer/v1/capabilities",
        operation_id: "getCapabilities",
    },
    RouteContract {
        method: "GET",
        path: "/consumer/v1/volumes",
        operation_id: "listVolumes",
    },
    RouteContract {
        method: "GET",
        path: "/consumer/v1/volumes/{volume}",
        operation_id: "getVolume",
    },
    RouteContract {
        method: "GET",
        path: "/consumer/v1/volumes/{volume}/entries",
        operation_id: "listEntries",
    },
    RouteContract {
        method: "POST",
        path: "/consumer/v1/volumes/{volume}/entries",
        operation_id: "createEntry",
    },
    RouteContract {
        method: "PATCH",
        path: "/consumer/v1/volumes/{volume}/entries",
        operation_id: "updateEntry",
    },
    RouteContract {
        method: "DELETE",
        path: "/consumer/v1/volumes/{volume}/entries",
        operation_id: "deleteEntry",
    },
    RouteContract {
        method: "GET",
        path: "/consumer/v1/volumes/{volume}/content",
        operation_id: "readContent",
    },
    RouteContract {
        method: "PUT",
        path: "/consumer/v1/volumes/{volume}/content",
        operation_id: "writeContent",
    },
    RouteContract {
        method: "POST",
        path: "/consumer/v1/volumes/{volume}/operations",
        operation_id: "startOperation",
    },
    RouteContract {
        method: "GET",
        path: "/consumer/v1/volumes/{volume}/xattrs",
        operation_id: "getXattrs",
    },
    RouteContract {
        method: "PATCH",
        path: "/consumer/v1/volumes/{volume}/xattrs",
        operation_id: "updateXattrs",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parser_distinguishes_malformed_and_unsatisfiable() {
        let malformed = parse_range(Some("bytes=0-1,4-5"), 10, 10, "r").unwrap_err();
        assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
        let unsatisfiable = parse_range(Some("bytes=20-"), 10, 10, "r").unwrap_err();
        assert_eq!(unsatisfiable.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            parse_range(Some("bytes=2-5"), 10, 10, "r").unwrap(),
            Some((2, 5))
        );
    }

    #[test]
    fn keep_both_suffix_is_deterministic_ascii() {
        assert_eq!(
            format!("{} (copy {})", "report.txt", 1),
            "report.txt (copy 1)"
        );
    }

    #[test]
    fn opaque_token_binding_separates_tenants_volumes_and_exact_views() {
        let live = view_binding("acme", "documents", ViewKind::Live, None);
        let snapshot = view_binding(
            "acme",
            "documents",
            ViewKind::Snapshot,
            Some("00000000-0000-0000-0000-000000000001"),
        );
        let version_one = view_binding("acme", "documents", ViewKind::Version, Some("a"));
        let version_two = view_binding("acme", "documents", ViewKind::Version, Some("b"));
        assert_ne!(live, snapshot);
        assert_ne!(version_one, version_two);
        assert_ne!(
            version_one,
            view_binding("globex", "documents", ViewKind::Version, Some("a"))
        );
        assert_ne!(
            version_one,
            view_binding("acme", "other", ViewKind::Version, Some("a"))
        );
    }
}
