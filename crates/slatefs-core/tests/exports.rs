mod common;

use std::sync::Arc;

use slatefs_core::config::{ExportConfig, ExportProtocol};
use slatefs_core::control::{ControlPlane, ExportRecord};
use slatefs_core::store;
use slatefs_core::volume;

#[tokio::test]
async fn export_crud_round_trips() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        common::create_opts(None, None),
    )
    .await
    .unwrap();

    let record = ExportRecord::from_config(
        "exp1",
        ExportConfig {
            tenant: "t".to_string(),
            volume: "v".to_string(),
            snapshot: None,
            listen: "127.0.0.1:12049".to_string(),
            allowed_clients: vec!["127.0.0.1".parse().unwrap()],
            protocol: ExportProtocol::Nfs,
            p9_token: None,
            p9_tls_cert: None,
            p9_tls_key: None,
            squash: Default::default(),
            atime: Default::default(),
            anon_uid: 65534,
            anon_gid: 65534,
        },
        true,
    );
    let created = control.create_export(record).await.unwrap();
    assert_eq!(created.id, "exp1");
    assert!(created.enabled);

    let mut updated = created.clone();
    updated.listen = "127.0.0.1:12050".to_string();
    updated.enabled = false;
    let updated = control.update_export(updated).await.unwrap();
    assert_eq!(updated.created_at, created.created_at);
    assert!(updated.updated_at >= created.updated_at);
    assert!(!updated.enabled);

    let listed = control.list_exports().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].listen, "127.0.0.1:12050");

    let enabled = control.enable_export("exp1").await.unwrap();
    assert!(enabled.enabled);
    let removed = control.remove_export("exp1").await.unwrap();
    assert_eq!(removed.id, "exp1");
    assert!(control.try_get_export("exp1").await.unwrap().is_none());
    control.close().await.unwrap();
}

#[tokio::test]
async fn export_validation_rejects_bad_records() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        common::create_opts(None, None),
    )
    .await
    .unwrap();

    let mut invalid_id = ExportRecord::from_config(
        "Bad",
        ExportConfig {
            tenant: "t".to_string(),
            volume: "v".to_string(),
            snapshot: None,
            listen: "127.0.0.1:12049".to_string(),
            allowed_clients: Vec::new(),
            protocol: ExportProtocol::Nfs,
            p9_token: None,
            p9_tls_cert: None,
            p9_tls_key: None,
            squash: Default::default(),
            atime: Default::default(),
            anon_uid: 65534,
            anon_gid: 65534,
        },
        true,
    );
    assert!(control.create_export(invalid_id.clone()).await.is_err());

    invalid_id.id = "exp1".to_string();
    invalid_id.listen = "not-a-listener".to_string();
    assert!(control.create_export(invalid_id.clone()).await.is_err());

    invalid_id.listen = "127.0.0.1:12049".to_string();
    invalid_id.protocol = ExportProtocol::Nfs;
    invalid_id.p9_tls_cert = Some("/tmp/cert.pem".into());
    invalid_id.p9_tls_key = Some("/tmp/key.pem".into());
    assert!(control.create_export(invalid_id).await.is_err());
    control.close().await.unwrap();
}
