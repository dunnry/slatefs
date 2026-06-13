//! Phase 0 acceptance tests (plan §14):
//! - tenant/volume create + info round-trip through an encrypted control DB
//!   and volume DB;
//! - raw objects at rest contain no plaintext marker strings;
//! - wrong master key fails closed.
//!
//! Tests run against a `file://` store in a tempdir unconditionally; set
//! `SLATEFS_TEST_URL` (e.g. `s3://slatefs-test/it` with MinIO env creds, see
//! `docker-compose.yml`) to run the same harness against a real bucket.

use std::sync::Arc;

use futures::TryStreamExt;
use slatefs_core::config::{Compression, VolumeDefaults};
use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits, TenantState, VolumeState};
use slatefs_core::crypto::Secret32;
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::error::Error;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::volume::{self, CreateVolumeOptions};

const TENANT_MARKER: &str = "SLATEFS_PLAINTEXT_MARKER_TENANT_93b1";
const VOLUME_MARKER: &str = "SLATEFS_PLAINTEXT_MARKER_VOLUME_4c7e";

fn static_kms(byte: u8) -> Arc<dyn Kms> {
    Arc::new(StaticKms::new(Secret32::from_bytes([byte; 32])))
}

fn default_create_opts() -> CreateVolumeOptions {
    let mut opts = CreateVolumeOptions::from_defaults(&VolumeDefaults::default());
    opts.note = Some(VOLUME_MARKER.to_string());
    opts
}

/// Exercise the Phase 0 surface against `object_store`, then scan every raw
/// object for the markers.
async fn phase0_round_trip(object_store: Arc<dyn ObjectStore>) {
    // --- create tenant + volume, info round-trip ---
    let control = ControlPlane::open(Arc::clone(&object_store), static_kms(7))
        .await
        .expect("open control plane");

    let tenant = control
        .create_tenant("t1", Some(TENANT_MARKER.to_string()))
        .await
        .expect("create tenant");
    assert_eq!(tenant.name, "t1");

    // Duplicate tenant is rejected.
    assert!(matches!(
        control.create_tenant("t1", None).await,
        Err(Error::AlreadyExists { .. })
    ));

    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t1",
        "v1",
        default_create_opts(),
    )
    .await
    .expect("create volume");
    assert_eq!(record.state, VolumeState::Active);

    // Duplicate volume is rejected.
    assert!(matches!(
        volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t1",
            "v1",
            default_create_opts(),
        )
        .await,
        Err(Error::AlreadyExists { .. })
    ));

    // Unknown tenant/volume yield NotFound.
    assert!(matches!(
        control.get_tenant("nope").await,
        Err(Error::NotFound { .. })
    ));
    assert!(matches!(
        volume::volume_info(&control, Arc::clone(&object_store), "t1", "nope").await,
        Err(Error::NotFound { .. })
    ));

    let info = volume::volume_info(&control, Arc::clone(&object_store), "t1", "v1")
        .await
        .expect("volume info");
    assert_eq!(info.superblock.fsid, record.fsid);
    assert_eq!(info.superblock.chunk_size, 128 * 1024);
    assert!(info.superblock.name_enc);
    assert_eq!(info.record.compression, Compression::Lz4);
    assert_eq!(info.record.note.as_deref(), Some(VOLUME_MARKER));

    // Phase 5 lifecycle gate: suspended tenants retain records/keys but
    // cannot create new volumes or resolve daemon exports.
    let suspended = control.suspend_tenant("t1").await.expect("suspend tenant");
    assert_eq!(suspended.state, TenantState::Suspended);
    assert!(matches!(
        volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t1",
            "v2",
            default_create_opts(),
        )
        .await,
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        control.get_mountable_volume("t1", "v1").await,
        Err(Error::Invalid { .. })
    ));
    let resumed = control.resume_tenant("t1").await.expect("resume tenant");
    assert_eq!(resumed.state, TenantState::Active);
    assert_eq!(
        control
            .get_mountable_volume("t1", "v1")
            .await
            .expect("mountable after resume")
            .fsid,
        record.fsid
    );

    // Quota UX: control-plane updates validate soft <= hard and persist.
    let quota = QuotaLimits {
        bytes: QuotaLimit {
            soft: Some(512),
            hard: Some(1024),
            grace_until: None,
        },
        inodes: QuotaLimit {
            soft: Some(8),
            hard: Some(16),
            grace_until: None,
        },
    };
    let updated = control
        .set_volume_quota("t1", "v1", quota)
        .await
        .expect("set quota");
    assert_eq!(updated.quota, quota);
    assert!(matches!(
        control
            .set_volume_quota(
                "t1",
                "v1",
                QuotaLimits {
                    bytes: QuotaLimit {
                        soft: Some(2048),
                        hard: Some(1024),
                        grace_until: None,
                    },
                    inodes: QuotaLimit::default(),
                },
            )
            .await,
        Err(Error::Invalid { .. })
    ));
    let info = volume::volume_info(&control, Arc::clone(&object_store), "t1", "v1")
        .await
        .expect("volume info after quota set");
    assert_eq!(info.record.quota, quota);

    control.close().await.expect("close control plane");

    // --- durability: reopen and read back ---
    let control = ControlPlane::open(Arc::clone(&object_store), static_kms(7))
        .await
        .expect("reopen control plane");
    let tenant = control
        .get_tenant("t1")
        .await
        .expect("tenant survives reopen");
    assert_eq!(tenant.display_name.as_deref(), Some(TENANT_MARKER));
    let volumes = control.list_volumes("t1").await.expect("list volumes");
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].state, VolumeState::Active);
    control.close().await.expect("close control plane again");

    // --- wrong master key fails closed ---
    match ControlPlane::open(Arc::clone(&object_store), static_kms(8)).await {
        Err(Error::Crypto(_)) => {}
        Err(other) => panic!("wrong master key must fail with Crypto, got {other:?}"),
        Ok(_) => panic!("wrong master key must fail closed, but open succeeded"),
    }

    // --- no plaintext at rest: scan every raw object for the markers ---
    let objects: Vec<_> = object_store
        .list(None)
        .try_collect()
        .await
        .expect("list objects");
    assert!(
        objects.len() >= 3,
        "expected control DB + control.dek + volume DB objects, got {}",
        objects.len()
    );
    let mut scanned = 0usize;
    for meta in &objects {
        let bytes = object_store
            .get(&meta.location)
            .await
            .expect("get object")
            .bytes()
            .await
            .expect("object bytes");
        for marker in [TENANT_MARKER, VOLUME_MARKER] {
            assert!(
                !contains(&bytes, marker.as_bytes()),
                "plaintext marker {marker} leaked into {}",
                meta.location
            );
        }
        scanned += 1;
    }
    println!("scanned {scanned} objects, no plaintext markers found");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Control test: the harness's marker scan must actually be able to find
/// markers — prove it catches plaintext when encryption is absent.
#[test]
fn marker_scan_detects_plaintext() {
    assert!(contains(
        b"xx SLATEFS_PLAINTEXT_MARKER_TENANT_93b1 yy",
        TENANT_MARKER.as_bytes()
    ));
    assert!(!contains(b"nothing here", TENANT_MARKER.as_bytes()));
}

#[tokio::test]
async fn phase0_file_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("file://{}", dir.path().display());
    let object_store = store::resolve_root(&url).expect("resolve file store");
    phase0_round_trip(object_store).await;
}

/// Same harness against a real bucket (MinIO/S3). Skipped unless
/// `SLATEFS_TEST_URL` is set; the URL must point at an empty prefix.
#[tokio::test]
async fn phase0_bucket_store() {
    let Ok(url) = std::env::var("SLATEFS_TEST_URL") else {
        eprintln!("SLATEFS_TEST_URL not set; skipping bucket integration test");
        return;
    };
    let object_store = store::resolve_root(&url).expect("resolve bucket store");
    phase0_round_trip(object_store).await;
}
