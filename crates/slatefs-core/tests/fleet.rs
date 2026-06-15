use std::sync::Arc;

use slatefs_core::config::{Compression, ExportProtocol};
use slatefs_core::control::{
    ControlPlane, DaemonMetrics, DaemonNodeState, QuotaLimits, VolumePlacementState,
};
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::store;
use slatefs_core::volume::{self, CreateVolumeOptions};

fn test_kms() -> Arc<dyn Kms> {
    Arc::new(StaticKms::new(Secret32::from_bytes([11; 32])))
}

fn create_opts() -> CreateVolumeOptions {
    CreateVolumeOptions {
        cipher: Cipher::Aes256Gcm,
        chunk_size: 4096,
        compression: Compression::Lz4,
        quota: QuotaLimits::default(),
        note: None,
    }
}

async fn control_with_tenant() -> (Arc<dyn store::ObjectStore>, ControlPlane) {
    let object_store = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    (object_store, control)
}

#[tokio::test]
async fn new_volumes_are_assigned_to_low_load_nodes() {
    let (object_store, control) = control_with_tenant().await;
    control
        .register_daemon_node("node-a", Some("10.0.0.1:2049".into()), None, None, 1)
        .await
        .unwrap();
    control
        .register_daemon_node("node-b", Some("10.0.0.2:2049".into()), None, None, 1)
        .await
        .unwrap();

    volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v1",
        create_opts(),
    )
    .await
    .unwrap();
    let first = control.get_volume_placement("t", "v1").await.unwrap();
    assert_eq!(first.primary_node.as_deref(), Some("node-a"));
    assert_eq!(first.standby_nodes, vec!["node-b"]);

    volume::create_volume(&control, object_store, "t", "v2", create_opts())
        .await
        .unwrap();
    let second = control.get_volume_placement("t", "v2").await.unwrap();
    assert_eq!(second.primary_node.as_deref(), Some("node-b"));

    control.close().await.unwrap();
}

#[tokio::test]
async fn standby_promotion_moves_stable_endpoints() {
    let (object_store, control) = control_with_tenant().await;
    control
        .register_daemon_node("node-a", Some("10.0.0.1:2049".into()), None, None, 1)
        .await
        .unwrap();
    control
        .register_daemon_node("node-b", Some("10.0.0.2:2049".into()), None, None, 1)
        .await
        .unwrap();
    volume::create_volume(&control, object_store, "t", "v", create_opts())
        .await
        .unwrap();
    let before = control
        .set_volume_stable_endpoint(
            "t",
            "v",
            "default",
            ExportProtocol::Nfs,
            "nfs://volumes.example.com/t/v".to_string(),
        )
        .await
        .unwrap();
    let before_endpoint_generation = before.stable_endpoints[0].generation;
    assert_eq!(
        before.stable_endpoints[0].target_node.as_deref(),
        Some("node-a")
    );

    let promoted = control
        .promote_standby_on_failure("t", "v", "node-a")
        .await
        .unwrap();
    assert_eq!(promoted.primary_node.as_deref(), Some("node-b"));
    assert_eq!(
        promoted.stable_endpoints[0].target_node.as_deref(),
        Some("node-b")
    );
    assert!(promoted.stable_endpoints[0].generation > before_endpoint_generation);
    assert_eq!(
        control.get_daemon_node("node-a").await.unwrap().state,
        DaemonNodeState::Unhealthy
    );

    control.close().await.unwrap();
}

#[tokio::test]
async fn drain_health_and_read_heavy_pools_are_persisted() {
    let (object_store, control) = control_with_tenant().await;
    for node in ["node-a", "node-b", "node-c"] {
        control
            .register_daemon_node(node, None, None, None, 1)
            .await
            .unwrap();
    }
    volume::create_volume(&control, object_store, "t", "v", create_opts())
        .await
        .unwrap();
    control
        .set_volume_stable_endpoint(
            "t",
            "v",
            "default",
            ExportProtocol::P9,
            "p9://volumes.example.com/t/v".to_string(),
        )
        .await
        .unwrap();

    let draining = control
        .start_volume_drain("t", "v", Some("node-b"))
        .await
        .unwrap();
    assert_eq!(draining.state, VolumePlacementState::Draining);
    assert_eq!(draining.primary_node.as_deref(), Some("node-a"));
    assert_eq!(draining.drain.as_ref().unwrap().to_node, "node-b");

    let moved = control.complete_volume_drain("t", "v").await.unwrap();
    assert_eq!(moved.state, VolumePlacementState::Active);
    assert_eq!(moved.primary_node.as_deref(), Some("node-b"));
    assert_eq!(
        moved.stable_endpoints[0].target_node.as_deref(),
        Some("node-b")
    );

    let with_replica = control
        .add_read_replica("t", "v", "node-c", Some(5))
        .await
        .unwrap();
    assert_eq!(with_replica.read_replicas[0].node_id, "node-c");
    assert_eq!(with_replica.read_replicas[0].lag_seconds, Some(5));

    let with_pool = control
        .set_snapshot_serving_pool(
            "t",
            "v",
            "read-mostly",
            vec!["node-a".to_string(), "node-c".to_string()],
            32,
        )
        .await
        .unwrap();
    assert_eq!(with_pool.snapshot_pools[0].name, "read-mostly");
    assert_eq!(with_pool.snapshot_pools[0].node_ids.len(), 2);

    control
        .record_daemon_health_at(
            "node-c",
            DaemonNodeState::Healthy,
            DaemonMetrics::default(),
            1,
        )
        .await
        .unwrap();
    let stale = control.mark_stale_daemon_nodes(60).await.unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].id, "node-c");
    assert_eq!(
        control.get_daemon_node("node-c").await.unwrap().state,
        DaemonNodeState::Unhealthy
    );

    control.close().await.unwrap();
}
