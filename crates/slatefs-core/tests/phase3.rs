//! Phase 3 acceptance tests (plan §14):
//! - deep no-plaintext scan: markers written through the filesystem (file
//!   content, file/dir names, xattr names+values, symlink targets) never
//!   appear in any raw object — including manifests and SST footers;
//! - wrong-DEK volume open fails closed;
//! - a restart with a warm disk cache serves reads without object-store
//!   GETs (tier-2 verification, DD-4).

mod common;

use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::TryStreamExt;
use futures::stream::BoxStream;
use slatedb::object_store::ObjectStoreExt;
use slatefs_core::crypto::Secret32;
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::vfs::{Credentials, Vfs};
use slatefs_core::volume::{Volume, VolumeCaches};

const CONTENT_MARKER: &[u8] = b"SLATEFS_P3_CONTENT_MARKER_77aa19c2";
const NAME_MARKER: &str = "SLATEFS_P3_NAME_MARKER_4d21";
const DIRNAME_MARKER: &str = "SLATEFS_P3_DIRNAME_MARKER_b3f0";
const XATTR_NAME_MARKER: &str = "user.SLATEFS_P3_XATTR_NAME_5c77";
const XATTR_VALUE_MARKER: &[u8] = b"SLATEFS_P3_XATTR_VALUE_e91d";
const SYMLINK_MARKER: &[u8] = b"SLATEFS_P3_SYMLINK_TARGET_0aa3/path";

fn root() -> Credentials {
    Credentials::root()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn deep_no_plaintext_at_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("file://{}", dir.path().display());
    let object_store = store::resolve_root(&url).expect("store");
    let v = common::fresh_volume_on(Arc::clone(&object_store), None, None).await;

    // Markers through every value-bearing surface of the FS.
    let f = v
        .create(&root(), ROOT_INO, NAME_MARKER.as_bytes(), 0o644, true)
        .await
        .unwrap();
    // Content spanning several chunks so markers land in many data blocks.
    let mut content = Vec::new();
    while content.len() < common::TEST_CHUNK as usize * 3 {
        content.extend_from_slice(CONTENT_MARKER);
    }
    v.write(&root(), f.ino, 0, &content).await.unwrap();
    v.setxattr(
        &root(),
        f.ino,
        XATTR_NAME_MARKER.as_bytes(),
        XATTR_VALUE_MARKER,
    )
    .await
    .unwrap();

    let d = v
        .mkdir(&root(), ROOT_INO, DIRNAME_MARKER.as_bytes(), 0o755)
        .await
        .unwrap();
    v.create(
        &root(),
        d.ino,
        format!("{NAME_MARKER}-nested").as_bytes(),
        0o644,
        true,
    )
    .await
    .unwrap();
    v.symlink(&root(), ROOT_INO, b"p3-link", SYMLINK_MARKER)
        .await
        .unwrap();

    v.fsync(&root(), ROOT_INO).await.unwrap();
    // Close pushes everything (memtable, WAL) into persistent objects.
    v.shutdown().await.unwrap();

    let objects: Vec<_> = object_store
        .list(None)
        .try_collect()
        .await
        .expect("list objects");
    assert!(objects.len() >= 3, "expected several objects");
    // Xattr NAMES are deliberately absent: they are key material
    // (`x/<ino>/<name>`) and SST footers carry first/last keys in
    // plaintext — the documented v1 exception (plan §5 "xattr names not
    // secret-classed in v1", docs/threat-model.md). Xattr VALUES are
    // covered below and must never leak.
    let markers: [&[u8]; 5] = [
        CONTENT_MARKER,
        NAME_MARKER.as_bytes(),
        DIRNAME_MARKER.as_bytes(),
        XATTR_VALUE_MARKER,
        SYMLINK_MARKER,
    ];
    let mut scanned = 0;
    for meta in &objects {
        let bytes = object_store
            .get(&meta.location)
            .await
            .expect("get")
            .bytes()
            .await
            .expect("bytes");
        for marker in markers {
            assert!(
                !contains(&bytes, marker),
                "plaintext marker {:?} leaked into {}",
                String::from_utf8_lossy(marker),
                meta.location
            );
        }
        scanned += 1;
    }
    println!("scanned {scanned} objects (incl. manifests/SSTs): no plaintext");
}

#[tokio::test]
async fn wrong_dek_fails_closed() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let v = common::fresh_volume_on(Arc::clone(&object_store), None, None).await;
    let creds = root();
    let f = v.create(&creds, ROOT_INO, b"f", 0o644, true).await.unwrap();
    v.write(&creds, f.ino, 0, b"sensitive").await.unwrap();
    v.fsync(&creds, f.ino).await.unwrap();
    v.shutdown().await.unwrap();

    // Re-open the same volume DB with a WRONG DEK: every block fails its
    // AEAD tag, so the open must error — never serve garbage.
    let control =
        slatefs_core::control::ControlPlane::open(Arc::clone(&object_store), common::test_kms())
            .await
            .unwrap();
    let record = control.get_volume("t", "v").await.unwrap();
    control.close().await.unwrap();

    let result = Volume::open(&record, Secret32::generate(), Arc::clone(&object_store)).await;
    assert!(result.is_err(), "wrong DEK must fail closed, got Ok");
}

/// Counts GETs that actually reach the backing store, so the warm-cache
/// test can prove reads were served from the local disk tier.
#[derive(Debug)]
struct CountingStore {
    inner: Arc<dyn ObjectStore>,
    gets: AtomicU64,
}

impl Display for CountingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "counting({})", self.inner)
    }
}

#[async_trait::async_trait]
impl ObjectStore for CountingStore {
    async fn put_opts(
        &self,
        location: &slatedb::object_store::path::Path,
        payload: slatedb::object_store::PutPayload,
        opts: slatedb::object_store::PutOptions,
    ) -> slatedb::object_store::Result<slatedb::object_store::PutResult> {
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &slatedb::object_store::path::Path,
        opts: slatedb::object_store::PutMultipartOptions,
    ) -> slatedb::object_store::Result<Box<dyn slatedb::object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &slatedb::object_store::path::Path,
        options: slatedb::object_store::GetOptions,
    ) -> slatedb::object_store::Result<slatedb::object_store::GetResult> {
        self.gets.fetch_add(1, Ordering::Relaxed);
        self.inner.get_opts(location, options).await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<
            'static,
            slatedb::object_store::Result<slatedb::object_store::path::Path>,
        >,
    ) -> BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>> {
        self.inner.delete_stream(locations)
    }

    fn list(
        &self,
        prefix: Option<&slatedb::object_store::path::Path>,
    ) -> BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&slatedb::object_store::path::Path>,
    ) -> slatedb::object_store::Result<slatedb::object_store::ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &slatedb::object_store::path::Path,
        to: &slatedb::object_store::path::Path,
        options: slatedb::object_store::CopyOptions,
    ) -> slatedb::object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}

#[tokio::test]
async fn warm_disk_cache_restart_avoids_store_gets() {
    let store_dir = tempfile::tempdir().expect("store dir");
    let cache_dir = tempfile::tempdir().expect("cache dir");
    let url = format!("file://{}", store_dir.path().display());
    let counting = Arc::new(CountingStore {
        inner: store::resolve_root(&url).expect("store"),
        gets: AtomicU64::new(0),
    });
    let object_store: Arc<dyn ObjectStore> = counting.clone();

    let caches = VolumeCaches {
        memory_bytes: Some(32 * 1024 * 1024),
        disk_root: Some(cache_dir.path().join("t/v")),
        disk_bytes: Some(256 * 1024 * 1024),
        disk_max_open_files: None,
        slatedb: Default::default(),
        recorder: None,
    };

    // Create + populate, then cleanly shut down (data lands in SSTs and the
    // disk cache holds their ciphertext parts).
    let control =
        slatefs_core::control::ControlPlane::open(Arc::clone(&object_store), common::test_kms())
            .await
            .unwrap();
    control.create_tenant("t", None).await.unwrap();
    let record = slatefs_core::volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        common::create_opts(None, None),
    )
    .await
    .unwrap();
    let dek = control.unwrap_volume_dek(&record).await.unwrap();
    control.close().await.unwrap();

    let creds = root();
    let v = Volume::open_with_caches(&record, dek.clone(), Arc::clone(&object_store), &caches)
        .await
        .unwrap();
    let payload: Vec<u8> = (0..common::TEST_CHUNK as usize * 4)
        .map(|i| (i % 233) as u8)
        .collect();
    let f = v
        .create(&creds, ROOT_INO, b"warm.bin", 0o644, true)
        .await
        .unwrap();
    v.write(&creds, f.ino, 0, &payload).await.unwrap();
    v.fsync(&creds, f.ino).await.unwrap();
    // Read once so SST parts populate the disk cache.
    let echo = v
        .read(&creds, f.ino, 0, payload.len() as u32)
        .await
        .unwrap();
    assert_eq!(&echo[..], &payload[..]);
    v.shutdown().await.unwrap();

    // Restart with the SAME cache dir: data reads must come from the warm
    // tier-2 cache, not the object store.
    let v = Volume::open_with_caches(&record, dek, Arc::clone(&object_store), &caches)
        .await
        .unwrap();
    let attr = v.lookup(&creds, ROOT_INO, b"warm.bin").await.unwrap();
    let before = counting.gets.load(Ordering::Relaxed);
    let echo = v
        .read(&creds, attr.ino, 0, payload.len() as u32)
        .await
        .unwrap();
    assert_eq!(&echo[..], &payload[..]);
    let data_gets = counting.gets.load(Ordering::Relaxed) - before;
    assert_eq!(
        data_gets, 0,
        "warm restart read hit the object store {data_gets} times; tier-2 cache not serving"
    );
    v.shutdown().await.unwrap();
}

/// Latency harness toward the Phase 3 AC targets (warm p99 < 1 ms from RAM
/// for 128 KiB reads; NVMe tier < 10 ms; cold = store latency + decode).
/// Ignored by default: numbers are only meaningful on the bench rig — run
/// with `cargo test -p slatefs-core --release --test phase3 -- --ignored
/// bench_read_latency --nocapture` against a real store URL via
/// `SLATEFS_BENCH_URL` (defaults to file://tempdir).
#[tokio::test]
#[ignore = "bench harness; run explicitly on the bench rig"]
async fn bench_read_latency() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let url = std::env::var("SLATEFS_BENCH_URL")
        .unwrap_or_else(|_| format!("file://{}", tmp.path().display()));
    let object_store = store::resolve_root(&url).expect("store");
    let cache_dir = tempfile::tempdir().expect("cache dir");

    let control =
        slatefs_core::control::ControlPlane::open(Arc::clone(&object_store), common::test_kms())
            .await
            .unwrap();
    control.create_tenant("bench", None).await.unwrap();
    let mut opts = common::create_opts(None, None);
    opts.chunk_size = 128 * 1024; // the AC read size
    let record = slatefs_core::volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "bench",
        "v",
        opts,
    )
    .await
    .unwrap();
    let dek = control.unwrap_volume_dek(&record).await.unwrap();
    control.close().await.unwrap();

    let caches = VolumeCaches {
        memory_bytes: Some(256 * 1024 * 1024),
        disk_root: Some(cache_dir.path().join("bench/v")),
        disk_bytes: Some(1024 * 1024 * 1024),
        disk_max_open_files: None,
        slatedb: Default::default(),
        recorder: None,
    };
    let v = Volume::open_with_caches(&record, dek, Arc::clone(&object_store), &caches)
        .await
        .unwrap();
    let creds = root();

    // 64 MiB file = 512 reads of 128 KiB.
    const READ: u32 = 128 * 1024;
    const READS: u64 = 512;
    let f = v
        .create(&creds, ROOT_INO, b"bench.bin", 0o644, true)
        .await
        .unwrap();
    let block: Vec<u8> = (0..READ as usize).map(|i| (i % 251) as u8).collect();
    for i in 0..READS {
        v.write(&creds, f.ino, i * READ as u64, &block)
            .await
            .unwrap();
    }
    v.fsync(&creds, f.ino).await.unwrap();

    let report = |label: &str, mut lat_us: Vec<u128>| {
        lat_us.sort_unstable();
        let pct = |p: f64| lat_us[((lat_us.len() as f64 * p) as usize).min(lat_us.len() - 1)];
        println!(
            "{label}: p50={}us p95={}us p99={}us max={}us",
            pct(0.50),
            pct(0.95),
            pct(0.99),
            pct(1.0),
        );
    };

    for pass in ["cold", "warm", "warm2"] {
        let mut lat = Vec::with_capacity(READS as usize);
        for i in 0..READS {
            let t = std::time::Instant::now();
            let data = v.read(&creds, f.ino, i * READ as u64, READ).await.unwrap();
            lat.push(t.elapsed().as_micros());
            assert_eq!(data.len() as u32, READ);
        }
        report(pass, lat);
    }
    v.shutdown().await.unwrap();
}
