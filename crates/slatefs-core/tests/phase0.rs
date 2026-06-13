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
use slatefs_core::control::{
    ControlPlane, QuotaLimit, QuotaLimits, TenantState, VolumeRecord, VolumeState,
};
use slatefs_core::crypto::Secret32;
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::error::Error;
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::snapshot::SnapshotVolume;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::vfs::{Credentials, FsError, Vfs};
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

async fn volume_object_count(
    object_store: &Arc<dyn ObjectStore>,
    tenant: &str,
    volume: &str,
) -> usize {
    let prefix = store::volume_db_prefix(tenant, volume);
    object_store
        .list(Some(&prefix))
        .try_collect::<Vec<_>>()
        .await
        .expect("list volume objects")
        .len()
}

fn root() -> Credentials {
    Credentials::root()
}

async fn read_root_file(
    control: &ControlPlane,
    object_store: Arc<dyn ObjectStore>,
    record: &VolumeRecord,
    name: &[u8],
) -> Vec<u8> {
    let dek = control.unwrap_volume_dek(record).await.expect("volume dek");
    let vol = volume::Volume::open(record, dek, object_store)
        .await
        .expect("open volume");
    let attr = vol
        .lookup(&root(), ROOT_INO, name)
        .await
        .expect("lookup file");
    let bytes = vol
        .read(&root(), attr.ino, 0, attr.size as u32)
        .await
        .expect("read file")
        .to_vec();
    vol.shutdown().await.expect("close volume");
    bytes
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

    // Phase 6 snapshot CLI foundation: durable checkpoints can be created,
    // listed, name-filtered, and deleted for a quiesced volume.
    let snapshot = volume::create_snapshot(
        &control,
        Arc::clone(&object_store),
        "t1",
        "v1",
        Some("baseline".to_string()),
    )
    .await
    .expect("create snapshot");
    assert_eq!(snapshot.name.as_deref(), Some("baseline"));
    let snapshots = volume::list_snapshots(&control, Arc::clone(&object_store), "t1", "v1", None)
        .await
        .expect("list snapshots");
    assert!(
        snapshots.iter().any(|s| s.id == snapshot.id),
        "created snapshot should be listed"
    );
    let named = volume::list_snapshots(
        &control,
        Arc::clone(&object_store),
        "t1",
        "v1",
        Some("baseline"),
    )
    .await
    .expect("list named snapshots");
    assert_eq!(named.len(), 1);
    assert_eq!(named[0].id, snapshot.id);
    volume::delete_snapshot(
        &control,
        Arc::clone(&object_store),
        "t1",
        "v1",
        &snapshot.id,
    )
    .await
    .expect("delete snapshot");
    assert!(
        volume::list_snapshots(&control, Arc::clone(&object_store), "t1", "v1", None)
            .await
            .expect("list snapshots after delete")
            .is_empty()
    );

    // Phase 6 writable clone foundation: latest-state clones and
    // checkpoint-based clones are writable, independent volumes with their
    // own fsid. Instant clones are same-tenant only because they share source
    // SSTs and therefore the source DEK.
    control
        .create_tenant("tclone", None)
        .await
        .expect("tclone tenant");
    let source = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "tclone",
        "src",
        default_create_opts(),
    )
    .await
    .expect("create clone source");
    let source_dek = control
        .unwrap_volume_dek(&source)
        .await
        .expect("source dek");
    let src_vol = volume::Volume::open(&source, source_dek, Arc::clone(&object_store))
        .await
        .expect("open clone source");
    let file = src_vol
        .create(&root(), ROOT_INO, b"file", 0o644, true)
        .await
        .expect("create source file");
    src_vol
        .write(&root(), file.ino, 0, b"baseline")
        .await
        .expect("write source baseline");
    src_vol.flush().await.expect("flush source baseline");
    src_vol.shutdown().await.expect("close clone source");

    let baseline = volume::create_snapshot(
        &control,
        Arc::clone(&object_store),
        "tclone",
        "src",
        Some("baseline".to_string()),
    )
    .await
    .expect("create clone baseline snapshot");

    let source_dek = control
        .unwrap_volume_dek(&source)
        .await
        .expect("source dek");
    let src_vol = volume::Volume::open(&source, source_dek, Arc::clone(&object_store))
        .await
        .expect("reopen clone source");
    src_vol
        .write(&root(), file.ino, 0, b"latest!!")
        .await
        .expect("write source latest");
    src_vol.flush().await.expect("flush source latest");
    src_vol.shutdown().await.expect("close clone source latest");

    let snapshot_dek = control
        .unwrap_volume_dek(&source)
        .await
        .expect("source dek");
    let snapshot_vol = SnapshotVolume::open(
        &source,
        snapshot_dek,
        Arc::clone(&object_store),
        &baseline.id,
    )
    .await
    .expect("open read-only snapshot");
    assert!(snapshot_vol.read_only());
    assert_ne!(snapshot_vol.fsid(), source.fsid);
    let snapshot_file = snapshot_vol
        .lookup(&root(), ROOT_INO, b"file")
        .await
        .expect("lookup snapshot file");
    assert_eq!(
        snapshot_vol
            .read(&root(), snapshot_file.ino, 0, snapshot_file.size as u32)
            .await
            .expect("read snapshot file"),
        b"baseline".as_slice()
    );
    assert!(matches!(
        snapshot_vol
            .write(&root(), snapshot_file.ino, 0, b"blocked")
            .await,
        Err(FsError::ReadOnly)
    ));
    snapshot_vol
        .shutdown()
        .await
        .expect("close read-only snapshot");

    let latest_clone = volume::clone_volume(
        &control,
        Arc::clone(&object_store),
        "tclone",
        "src",
        "latest",
        volume::CloneVolumeOptions::default(),
    )
    .await
    .expect("clone latest source state");
    assert_eq!(
        latest_clone
            .clone_parent
            .as_ref()
            .expect("clone parent")
            .volume
            .as_str(),
        "src"
    );
    let snapshot_clone = volume::clone_volume(
        &control,
        Arc::clone(&object_store),
        "tclone",
        "src",
        "snap",
        volume::CloneVolumeOptions {
            source_snapshot_id: Some(baseline.id.clone()),
            note: Some("from baseline".to_string()),
        },
    )
    .await
    .expect("clone snapshot source state");

    let latest_info = volume::volume_info(&control, Arc::clone(&object_store), "tclone", "latest")
        .await
        .expect("latest clone info");
    assert_eq!(latest_info.superblock.fsid, latest_clone.fsid);
    assert_ne!(latest_info.superblock.fsid, source.fsid);
    assert_eq!(
        read_root_file(&control, Arc::clone(&object_store), &latest_clone, b"file").await,
        b"latest!!"
    );
    assert_eq!(
        read_root_file(
            &control,
            Arc::clone(&object_store),
            &snapshot_clone,
            b"file"
        )
        .await,
        b"baseline"
    );

    let latest_dek = control
        .unwrap_volume_dek(&latest_clone)
        .await
        .expect("latest clone dek");
    let latest_vol = volume::Volume::open(&latest_clone, latest_dek, Arc::clone(&object_store))
        .await
        .expect("open latest clone");
    let cloned_file = latest_vol
        .lookup(&root(), ROOT_INO, b"file")
        .await
        .expect("lookup latest clone file");
    latest_vol
        .write(&root(), cloned_file.ino, 0, b"clone!!!")
        .await
        .expect("write latest clone");
    latest_vol.flush().await.expect("flush latest clone");
    latest_vol.shutdown().await.expect("close latest clone");
    assert_eq!(
        read_root_file(&control, Arc::clone(&object_store), &latest_clone, b"file").await,
        b"clone!!!"
    );
    assert_eq!(
        read_root_file(&control, Arc::clone(&object_store), &source, b"file").await,
        b"latest!!"
    );
    assert!(matches!(
        control.delete_volume("tclone", "src").await,
        Err(Error::Invalid { .. })
    ));
    control
        .delete_tenant("tclone")
        .await
        .expect("delete clone tenant");

    // Phase 5 delete/crypto-shred: current control-plane state drops wrapped
    // keys and refuses future mount resolution.
    control
        .create_tenant("tdel", None)
        .await
        .expect("tdel tenant");
    volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "tdel",
        "vdel",
        default_create_opts(),
    )
    .await
    .expect("create volume to delete");
    assert!(
        volume_object_count(&object_store, "tdel", "vdel").await > 0,
        "created volume should have object-store state"
    );
    let deleted_volume = control
        .delete_volume("tdel", "vdel")
        .await
        .expect("delete volume");
    assert_eq!(deleted_volume.state, VolumeState::Deleting);
    assert!(deleted_volume.wrapped_dek.is_empty());
    assert_eq!(
        volume_object_count(&object_store, "tdel", "vdel").await,
        0,
        "deleted volume prefix should be empty"
    );
    assert!(matches!(
        control.get_mountable_volume("tdel", "vdel").await,
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        control.unwrap_volume_dek(&deleted_volume).await,
        Err(Error::Invalid { .. })
    ));

    control
        .create_tenant("gone", None)
        .await
        .expect("gone tenant");
    let gone_volume = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "gone",
        "v",
        default_create_opts(),
    )
    .await
    .expect("create gone volume");
    assert!(
        volume_object_count(&object_store, "gone", "v").await > 0,
        "created tenant volume should have object-store state"
    );
    let deleted_tenant = control.delete_tenant("gone").await.expect("delete tenant");
    assert_eq!(deleted_tenant.state, TenantState::Deleting);
    assert!(deleted_tenant.wrapped_kek.is_empty());
    assert_eq!(
        volume_object_count(&object_store, "gone", "v").await,
        0,
        "deleted tenant volume prefix should be empty"
    );
    let gone_volume = control
        .get_volume("gone", &gone_volume.name)
        .await
        .expect("gone volume record");
    assert_eq!(gone_volume.state, VolumeState::Deleting);
    assert!(gone_volume.wrapped_dek.is_empty());
    assert!(matches!(
        control.resume_tenant("gone").await,
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "gone",
            "new",
            default_create_opts(),
        )
        .await,
        Err(Error::Invalid { .. })
    ));

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
