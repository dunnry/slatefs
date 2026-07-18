use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use slatefs_core::config::{Compression, ConsumerConfig, ConsumerIdentityConfig};
use slatefs_core::control::{ControlPlane, ControlReader, QuotaLimits};
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::store;
use slatefs_core::vfs::{Credentials, SetAttrs, Vfs};
use slatefs_core::volume::{self, CreateVolumeOptions, Volume};
use slatefs_http::auth::TenantAuthenticator;
use slatefs_http::dto::{Entry, EntryListResponse};
use slatefs_http::identifiers::TokenSigner;
use slatefs_http::{ConsumerState, LiveVolumeRegistry, router};
use tower::ServiceExt as _;

async fn fixture_with_config(
    consumer_config: ConsumerConfig,
) -> (axum::Router, Arc<Volume>, Arc<ControlReader>) {
    let object_store = store::resolve_root("memory:///").unwrap();
    let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([42; 32])));
    let control = ControlPlane::open(Arc::clone(&object_store), Arc::clone(&kms))
        .await
        .unwrap();
    control.create_tenant("acme", None).await.unwrap();
    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "acme",
        "documents",
        CreateVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: 4096,
            compression: Compression::Lz4,
            quota: QuotaLimits::default(),
            note: None,
        },
    )
    .await
    .unwrap();
    let dek = control.unwrap_volume_dek(&record).await.unwrap();
    control.close().await.unwrap();
    let volume = Volume::open(&record, dek, Arc::clone(&object_store))
        .await
        .unwrap();
    volume
        .setattr(
            &Credentials::root(),
            ROOT_INO,
            SetAttrs {
                mode: Some(0o777),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let reader = Arc::new(ControlReader::open(object_store, kms).await.unwrap());
    let registry = LiveVolumeRegistry::default();
    registry.insert("acme".into(), "documents".into(), Arc::clone(&volume));
    let auth = TenantAuthenticator::new(
        BTreeMap::from([
            ("acme".into(), "tenant-token".into()),
            ("beta".into(), "beta-token".into()),
        ]),
        BTreeMap::new(),
        BTreeMap::from([
            (
                "acme".into(),
                ConsumerIdentityConfig {
                    uid: 1000,
                    gid: 1000,
                },
            ),
            (
                "beta".into(),
                ConsumerIdentityConfig {
                    uid: 2000,
                    gid: 2000,
                },
            ),
        ]),
    );
    let state = ConsumerState::new(
        registry,
        Arc::clone(&reader),
        auth,
        TokenSigner::new([9; 32]),
        consumer_config,
    );
    (router(state), volume, reader)
}

async fn fixture() -> (axum::Router, Arc<Volume>, Arc<ControlReader>) {
    fixture_with_config(ConsumerConfig::default()).await
}

fn request(method: &str, uri: &str, body: Body) -> Request<Body> {
    request_with_token(method, uri, body, "tenant-token")
}

fn request_with_token(method: &str, uri: &str, body: Body, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("x-request-id", "integration-request")
        .body(body)
        .unwrap()
}

fn with_header(
    mut request: Request<Body>,
    name: &'static str,
    value: &'static str,
) -> Request<Body> {
    request.headers_mut().insert(name, value.parse().unwrap());
    request
}

async fn response_json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn live_create_upload_range_and_delete_matrix() {
    let (app, volume, reader) = fixture().await;
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/consumer/v1/volumes/documents/entries?path=",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-request-id"], "integration-request");
    let root: EntryListResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let create = serde_json::json!({"parent_entry_id":root.entry.entry_id,"name":"hello.txt","kind":"file","mode":420,"symlink_target":null});
    let response = app
        .clone()
        .oneshot(with_header(
            request(
                "POST",
                "/consumer/v1/volumes/documents/entries",
                Body::from(create.to_string()),
            ),
            "content-type",
            "application/json",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Entry =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let uri = format!(
        "/consumer/v1/volumes/documents/content?entry_id={}",
        created.entry_id
    );
    let response = app
        .clone()
        .oneshot(request("PUT", &uri, Body::from("lost update")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let mut upload = with_header(
        request("PUT", &uri, Body::from("hello world")),
        "idempotency-key",
        "upload-1",
    );
    upload
        .headers_mut()
        .insert("if-match", created.etag.parse().unwrap());
    let response = app.clone().oneshot(upload).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let uploaded: Entry =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let uri = format!(
        "/consumer/v1/volumes/documents/content?entry_id={}",
        uploaded.entry_id
    );
    let response = app
        .clone()
        .oneshot(with_header(
            request("GET", &uri, Body::empty()),
            "range",
            "bytes=6-10",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"world"
    );

    let uri = format!(
        "/consumer/v1/volumes/documents/entries?entry_id={}&recursive=false",
        uploaded.entry_id
    );
    let response = app
        .oneshot(request("DELETE", &uri, Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    reader.close().await.unwrap();
    volume.shutdown().await.unwrap();
}

#[tokio::test]
async fn byte_safe_names_stale_ids_symlink_ranges_and_xattrs() {
    let (app, volume, reader) = fixture().await;
    let c = Credentials::user(1000, 1000);
    let byte_name = b"non-utf8-\xff";
    let byte_file = volume
        .create(&c, ROOT_INO, byte_name, 0o644, true)
        .await
        .unwrap();
    volume
        .setxattr(&c, byte_file.ino, b"user.\xff", b"original")
        .await
        .unwrap();

    let root: EntryListResponse = response_json(
        app.clone()
            .oneshot(request(
                "GET",
                "/consumer/v1/volumes/documents/entries?path=",
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let byte_entry = root
        .entries
        .iter()
        .find(|entry| entry.name.is_none())
        .expect("byte-only entry must remain listable");
    assert_eq!(byte_entry.name_bytes_base64, "bm9uLXV0Zjgt/w==");

    let uri = format!(
        "/consumer/v1/volumes/documents/xattrs?entry_id={}",
        byte_entry.entry_id
    );
    let patch = serde_json::json!({
        "set_bytes": [{"name_bytes_base64":"dXNlci7+","value_base64":"dXBkYXRlZA=="}],
        "remove_bytes_base64": ["dXNlci7/"]
    });
    let response = app
        .clone()
        .oneshot(with_header(
            request("PATCH", &uri, Body::from(patch.to_string())),
            "content-type",
            "application/json",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xattrs: serde_json::Value = response_json(response).await;
    assert_eq!(xattrs["xattrs"][0]["name"], serde_json::Value::Null);
    assert_eq!(xattrs["xattrs"][0]["name_bytes_base64"], "dXNlci7+");
    assert_eq!(xattrs["xattrs"][0]["value_base64"], "dXBkYXRlZA==");

    let symlink = serde_json::json!({
        "parent_entry_id": root.entry.entry_id,
        "name": "shortcut",
        "kind": "symlink",
        "mode": null,
        "symlink_target": "abcdefghij"
    });
    let response = app
        .clone()
        .oneshot(with_header(
            request(
                "POST",
                "/consumer/v1/volumes/documents/entries",
                Body::from(symlink.to_string()),
            ),
            "content-type",
            "application/json",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let symlink: Entry = response_json(response).await;
    let uri = format!(
        "/consumer/v1/volumes/documents/content?entry_id={}",
        symlink.entry_id
    );
    let response = app
        .clone()
        .oneshot(with_header(
            request("GET", &uri, Body::empty()),
            "range",
            "bytes=3-6",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()["content-length"], "4");
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"defg"
    );

    volume.unlink(&c, ROOT_INO, byte_name).await.unwrap();
    let uri = format!(
        "/consumer/v1/volumes/documents/entries?entry_id={}",
        byte_entry.entry_id
    );
    let response = app
        .oneshot(request("GET", &uri, Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

    reader.close().await.unwrap();
    volume.shutdown().await.unwrap();
}

#[tokio::test]
async fn recursive_ceiling_is_checked_before_any_deletion() {
    let config = ConsumerConfig {
        max_recursive_entries: 1,
        ..ConsumerConfig::default()
    };
    let (app, volume, reader) = fixture_with_config(config).await;
    let c = Credentials::user(1000, 1000);
    let directory = volume.mkdir(&c, ROOT_INO, b"tree", 0o755).await.unwrap();
    volume
        .create(&c, directory.ino, b"first", 0o644, true)
        .await
        .unwrap();
    volume
        .create(&c, directory.ino, b"second", 0o644, true)
        .await
        .unwrap();

    let root: EntryListResponse = response_json(
        app.clone()
            .oneshot(request(
                "GET",
                "/consumer/v1/volumes/documents/entries?path=",
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let tree = root
        .entries
        .iter()
        .find(|entry| entry.name.as_deref() == Some("tree"))
        .unwrap();
    let uri = format!(
        "/consumer/v1/volumes/documents/entries?entry_id={}&recursive=true",
        tree.entry_id
    );
    let response = app
        .oneshot(request("DELETE", &uri, Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let page = volume
        .readdir(&c, directory.ino, 0, 10)
        .await
        .expect("tree must remain readable");
    assert_eq!(
        page.entries.len(),
        2,
        "ceiling failure must not delete a prefix"
    );
    reader.close().await.unwrap();
    volume.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelled_upload_removes_staged_sibling() {
    use futures::stream::{self, StreamExt as _};

    let (app, volume, reader) = fixture().await;
    let c = Credentials::user(1000, 1000);
    let root: EntryListResponse = response_json(
        app.clone()
            .oneshot(request(
                "GET",
                "/consumer/v1/volumes/documents/entries?path=",
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let body_stream =
        stream::once(async { Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"partial")) })
            .chain(stream::pending());
    let uri = format!(
        "/consumer/v1/volumes/documents/content?parent_entry_id={}&name=cancelled.bin",
        root.entry.entry_id
    );
    let task = tokio::spawn(async move {
        app.oneshot(with_header(
            request("PUT", &uri, Body::from_stream(body_stream)),
            "idempotency-key",
            "cancel-upload",
        ))
        .await
    });

    let mut staged_seen = false;
    for _ in 0..100 {
        let page = volume.readdir(&c, ROOT_INO, 0, 100).await.unwrap();
        if page
            .entries
            .iter()
            .any(|entry| entry.name.starts_with(b".slatefs-upload-"))
        {
            staged_seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(staged_seen, "request must reach the staged upload state");
    task.abort();
    let _ = task.await;

    for _ in 0..100 {
        let page = volume.readdir(&c, ROOT_INO, 0, 100).await.unwrap();
        if !page
            .entries
            .iter()
            .any(|entry| entry.name.starts_with(b".slatefs-upload-"))
        {
            reader.close().await.unwrap();
            volume.shutdown().await.unwrap();
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("cancelled upload left its staged sibling behind");
}

#[tokio::test]
async fn tenant_identity_is_token_derived_and_cross_tenant_guesses_are_hidden() {
    let (app, volume, reader) = fixture().await;
    let mut injected = request(
        "GET",
        "/consumer/v1/volumes/documents/entries?path=",
        Body::empty(),
    );
    injected
        .headers_mut()
        .insert("x-tenant", "beta".parse().unwrap());
    injected.headers_mut().insert("x-uid", "0".parse().unwrap());
    injected.headers_mut().insert("x-gid", "0".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(injected).await.unwrap().status(),
        StatusCode::OK,
        "caller identity headers must not override the acme token"
    );

    let root: EntryListResponse = response_json(
        app.clone()
            .oneshot(request(
                "GET",
                "/consumer/v1/volumes/documents/entries?path=",
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let guessed = format!(
        "/consumer/v1/volumes/documents/entries?entry_id={}",
        root.entry.entry_id
    );
    let response = app
        .clone()
        .oneshot(request_with_token(
            "GET",
            &guessed,
            Body::empty(),
            "beta-token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let error: serde_json::Value = response_json(response).await;
    assert_eq!(error["error"]["code"], "not_found");
    assert_eq!(error["error"]["message"], "volume was not found");
    assert!(error.to_string().find("acme").is_none());

    let response = app
        .oneshot(request_with_token(
            "GET",
            "/consumer/v1/capabilities",
            Body::empty(),
            "global-admin",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    reader.close().await.unwrap();
    volume.shutdown().await.unwrap();
}

#[tokio::test]
async fn recursive_preview_and_concurrent_operation_idempotency_are_exact() {
    let (app, volume, reader) = fixture().await;
    let c = Credentials::user(1000, 1000);
    let source = volume.mkdir(&c, ROOT_INO, b"source", 0o755).await.unwrap();
    volume
        .create(&c, source.ino, b"one", 0o644, true)
        .await
        .unwrap();
    volume
        .create(&c, source.ino, b"two", 0o644, true)
        .await
        .unwrap();
    let destination = volume
        .mkdir(&c, ROOT_INO, b"destination", 0o755)
        .await
        .unwrap();
    let root: EntryListResponse = response_json(
        app.clone()
            .oneshot(request(
                "GET",
                "/consumer/v1/volumes/documents/entries?path=",
                Body::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let source_id = root
        .entries
        .iter()
        .find(|entry| entry.name.as_deref() == Some("source"))
        .unwrap()
        .entry_id
        .clone();
    let destination_id = root
        .entries
        .iter()
        .find(|entry| entry.name.as_deref() == Some("destination"))
        .unwrap()
        .entry_id
        .clone();
    let operation = serde_json::json!({
        "operation":"copy",
        "source_entry_ids":[source_id],
        "destination_parent_entry_id":destination_id,
        "conflict_policy":"fail",
        "preview":false
    });
    let make_request = || {
        with_header(
            with_header(
                request(
                    "POST",
                    "/consumer/v1/volumes/documents/operations",
                    Body::from(operation.to_string()),
                ),
                "content-type",
                "application/json",
            ),
            "idempotency-key",
            "concurrent-copy",
        )
    };
    let mut preview = operation.clone();
    preview["preview"] = serde_json::json!(true);
    let preview_response = app
        .clone()
        .oneshot(with_header(
            with_header(
                request(
                    "POST",
                    "/consumer/v1/volumes/documents/operations",
                    Body::from(preview.to_string()),
                ),
                "content-type",
                "application/json",
            ),
            "idempotency-key",
            "preview-copy",
        ))
        .await
        .unwrap();
    assert_eq!(preview_response.status(), StatusCode::OK);
    let preview_result: serde_json::Value = response_json(preview_response).await;
    assert_eq!(preview_result["total_entries"], 3);
    assert_eq!(preview_result["completed_entries"], 0);

    let (first, second) = tokio::join!(
        app.clone().oneshot(make_request()),
        app.clone().oneshot(make_request())
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    let first: serde_json::Value = response_json(first).await;
    let second: serde_json::Value = response_json(second).await;
    assert_eq!(first["operation_id"], second["operation_id"]);
    assert_eq!(first["total_entries"], 3);
    assert_eq!(first["completed_entries"], 3);
    let destination_page = volume.readdir(&c, destination.ino, 0, 10).await.unwrap();
    assert_eq!(destination_page.entries.len(), 1);

    let mut conflicting = operation;
    conflicting["preview"] = serde_json::json!(true);
    let response = app
        .oneshot(with_header(
            with_header(
                request(
                    "POST",
                    "/consumer/v1/volumes/documents/operations",
                    Body::from(conflicting.to_string()),
                ),
                "content-type",
                "application/json",
            ),
            "idempotency-key",
            "concurrent-copy",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    reader.close().await.unwrap();
    volume.shutdown().await.unwrap();
}
