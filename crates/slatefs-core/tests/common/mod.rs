//! Shared test plumbing: spin up an encrypted volume on a given object
//! store, with a small chunk size so multi-chunk paths get exercised by
//! kilobyte-sized test data.
//!
//! Compiled into each test binary separately; not every binary uses every
//! helper.
#![allow(dead_code)]

use std::sync::Arc;

use slatefs_core::config::Compression;
use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits};
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::volume::{self, CreateVolumeOptions, Volume};

pub const TEST_CHUNK: u32 = 4096;

pub fn test_kms() -> Arc<dyn Kms> {
    Arc::new(StaticKms::new(Secret32::from_bytes([42; 32])))
}

pub fn create_opts(quota_bytes: Option<u64>, quota_inodes: Option<u64>) -> CreateVolumeOptions {
    CreateVolumeOptions {
        cipher: Cipher::Aes256Gcm,
        chunk_size: TEST_CHUNK,
        compression: Compression::Lz4,
        quota: QuotaLimits {
            bytes: QuotaLimit {
                hard: quota_bytes,
                ..Default::default()
            },
            inodes: QuotaLimit {
                hard: quota_inodes,
                ..Default::default()
            },
        },
        note: None,
    }
}

/// Create tenant `t`/volume `v` on `store` and open the volume for serving.
pub async fn fresh_volume_on(
    object_store: Arc<dyn ObjectStore>,
    quota_bytes: Option<u64>,
    quota_inodes: Option<u64>,
) -> Arc<Volume> {
    let control = ControlPlane::open(Arc::clone(&object_store), test_kms())
        .await
        .expect("open control plane");
    control.create_tenant("t", None).await.expect("tenant");
    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        create_opts(quota_bytes, quota_inodes),
    )
    .await
    .expect("create volume");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control");
    Volume::open(&record, dek, object_store)
        .await
        .expect("open volume")
}

/// Reopen an existing volume (e.g. after simulated crash); runs the
/// mount-time orphan reaper.
pub async fn reopen_volume(object_store: Arc<dyn ObjectStore>) -> Arc<Volume> {
    let control = ControlPlane::open(Arc::clone(&object_store), test_kms())
        .await
        .expect("open control plane");
    let record = control.get_volume("t", "v").await.expect("volume record");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control");
    Volume::open(&record, dek, object_store)
        .await
        .expect("open volume")
}

pub async fn fresh_volume() -> Arc<Volume> {
    let object_store = store::resolve_root("memory:///").expect("memory store");
    fresh_volume_on(object_store, None, None).await
}
