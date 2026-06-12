//! Crash-consistency test (plan §14 Phase 1): a child process runs a
//! deterministic random workload against a `file://`-backed volume and
//! `abort()`s mid-stream (acked-but-unflushed writes are lost — allowed by
//! DD-7); the parent then reopens the volume (which runs the orphan reaper)
//! and requires a clean fsck: no torn operations, no counter drift.
//!
//! Scale knob: `SLATEFS_CRASH_ITERS` (CI nightly runs hundreds per the AC).

mod common;

use std::process::Command;

use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::vfs::{Credentials, SetAttrs, Vfs};

const CHUNK: u64 = common::TEST_CHUNK as u64;

/// Tiny deterministic RNG (xorshift64*) so child workloads replay exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The workload the child runs until it aborts. Root creds: crash testing
/// targets atomicity, not permissions.
async fn churn(v: &slatefs_core::volume::Volume, rng: &mut Rng, ops: u64) {
    let creds = Credentials::root();
    // A small fixed namespace; ops that lose races with prior state just
    // take whatever errno falls out — consistency is checked by fsck.
    for _ in 0..ops {
        let dir_name = format!("d{}", rng.below(3));
        let file_name = format!("f{}", rng.below(8));
        let dir = match v.lookup(&creds, ROOT_INO, dir_name.as_bytes()).await {
            Ok(attr) => attr.ino,
            Err(_) => match v.mkdir(&creds, ROOT_INO, dir_name.as_bytes(), 0o755).await {
                Ok(attr) => attr.ino,
                Err(_) => ROOT_INO,
            },
        };
        match rng.below(7) {
            0 | 1 => {
                let _ = v
                    .create(&creds, dir, file_name.as_bytes(), 0o644, false)
                    .await;
            }
            2 | 3 => {
                if let Ok(attr) = v.lookup(&creds, dir, file_name.as_bytes()).await {
                    let offset = rng.below(3 * CHUNK);
                    let len = (rng.below(2 * CHUNK) + 1) as usize;
                    let data = vec![(rng.next() % 251) as u8; len];
                    let _ = v.write(&creds, attr.ino, offset, &data).await;
                }
            }
            4 => {
                let _ = v.unlink(&creds, dir, file_name.as_bytes()).await;
            }
            5 => {
                if let Ok(attr) = v.lookup(&creds, dir, file_name.as_bytes()).await {
                    let size = rng.below(4 * CHUNK);
                    let _ = v
                        .setattr(
                            &creds,
                            attr.ino,
                            SetAttrs {
                                size: Some(size),
                                ..Default::default()
                            },
                        )
                        .await;
                }
            }
            6 => {
                let other = format!("d{}", rng.below(3));
                if let Ok(o) = v.lookup(&creds, ROOT_INO, other.as_bytes()).await {
                    let _ = v
                        .rename(&creds, dir, file_name.as_bytes(), o.ino, b"renamed")
                        .await;
                }
            }
            _ => unreachable!(),
        }
        if rng.below(16) == 0 {
            let _ = v.fsync(&creds, ROOT_INO).await;
        }
    }
}

/// Child entry point: runs only when the parent set the env contract, then
/// dies via `abort()` — no flush, no clean shutdown.
#[tokio::test]
#[ignore = "spawned by crash_consistency_loop"]
async fn crash_child() {
    let Ok(url) = std::env::var("SLATEFS_CRASH_URL") else {
        return;
    };
    let seed: u64 = std::env::var("SLATEFS_CRASH_SEED")
        .unwrap()
        .parse()
        .unwrap();
    let abort_after: u64 = std::env::var("SLATEFS_CRASH_ABORT_AFTER")
        .unwrap()
        .parse()
        .unwrap();

    let object_store = slatefs_core::store::resolve_root(&url).expect("store");
    let v = common::reopen_volume(object_store).await;
    let mut rng = Rng(seed | 1);
    churn(&v, &mut rng, abort_after).await;
    std::process::abort();
}

#[tokio::test]
async fn crash_consistency_loop() {
    let iters: u64 = std::env::var("SLATEFS_CRASH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("file://{}", dir.path().display());
    let object_store = slatefs_core::store::resolve_root(&url).expect("store");

    // Create the volume once; state accumulates across kill-points.
    let v = common::fresh_volume_on(object_store.clone(), None, None).await;
    v.shutdown().await.expect("shutdown after setup");

    let exe = std::env::current_exe().expect("current_exe");
    for i in 0..iters {
        let abort_after = 5 + (i * 13) % 60;
        let status = Command::new(&exe)
            .args(["crash_child", "--exact", "--ignored", "--test-threads=1"])
            .env("SLATEFS_CRASH_URL", &url)
            .env("SLATEFS_CRASH_SEED", i.to_string())
            .env("SLATEFS_CRASH_ABORT_AFTER", abort_after.to_string())
            .status()
            .expect("spawn crash child");
        assert!(
            !status.success(),
            "iteration {i}: child was supposed to abort, exited cleanly"
        );

        // Reopen (runs the mount-time reaper), then everything must verify.
        let v = common::reopen_volume(object_store.clone()).await;
        let report = v.fsck().await.expect("fsck");
        assert!(
            report.is_clean(),
            "iteration {i} (abort after {abort_after} ops): fsck dirty:\n  problems: {:?}\n  counters: real ({}, {}) vs recount ({}, {})",
            report.problems,
            report.counter_inodes,
            report.counter_bytes,
            report.inodes_counted,
            report.bytes_counted,
        );
        v.shutdown().await.expect("shutdown");
    }
}
