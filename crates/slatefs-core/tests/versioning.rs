//! End-to-end coverage for opt-in Prolly-backed file versioning.

mod common;

use std::sync::Arc;

use futures::TryStreamExt;
use slatefs_core::control::ControlPlane;
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::versioning::{VersionRepository, purge_version_history};
use slatefs_core::vfs::{Credentials, Vfs};
use slatefs_core::volume::{self, Volume};

#[tokio::test]
async fn versioning_is_opt_in_and_restores_committed_files() {
    let object_store: Arc<dyn ObjectStore> = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        common::create_opts(None, None),
    )
    .await
    .unwrap();

    assert!(!control.versioning_enabled("t", "v").await.unwrap());
    assert!(
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
            .await
            .is_err()
    );

    let policy = control
        .set_versioning_enabled("t", "v", true)
        .await
        .unwrap();
    assert!(policy.enabled);
    let version_objects: Vec<_> = object_store
        .list(Some(&store::version_db_prefix("t", "v")))
        .try_collect()
        .await
        .unwrap();
    assert!(
        version_objects.is_empty(),
        "enabling must not create a version repository"
    );

    let dek = control.unwrap_volume_dek(&record).await.unwrap();
    let live = Volume::open(&record, dek, Arc::clone(&object_store))
        .await
        .unwrap();
    let creds = Credentials::root();
    let file = live
        .create(&creds, ROOT_INO, b"notes.txt", 0o640, true)
        .await
        .unwrap();
    let first_contents = b"first version\n";
    live.write(&creds, file.ino, 0, first_contents)
        .await
        .unwrap();

    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let first = repository
        .commit_file(live.as_ref(), "/notes.txt", "initial notes".to_string())
        .await
        .unwrap();
    assert_eq!(first.paths, vec!["/notes.txt"]);

    let second_contents = b"second version\n";
    live.write(&creds, file.ino, 0, second_contents)
        .await
        .unwrap();
    let second = repository
        .commit_file(live.as_ref(), "notes.txt", "update notes".to_string())
        .await
        .unwrap();
    assert_eq!(second.parent.as_deref(), Some(first.id.as_str()));

    let history = repository.history(Some("/notes.txt"), 10).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].id, second.id);
    assert_eq!(history[1].id, first.id);
    assert_eq!(
        repository
            .read_file(&first.id, "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        first_contents
    );

    repository
        .restore_file(live.as_ref(), &first.id, "/notes.txt")
        .await
        .unwrap();
    let restored = live.lookup(&creds, ROOT_INO, b"notes.txt").await.unwrap();
    assert_eq!(
        live.read(&creds, restored.ino, 0, 1024)
            .await
            .unwrap()
            .as_ref(),
        first_contents
    );

    repository.close().await.unwrap();
    let policy = control
        .set_versioning_enabled("t", "v", false)
        .await
        .unwrap();
    assert!(!policy.enabled);
    assert!(
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
            .await
            .is_err()
    );

    // Disabling retains history. Re-enabling makes the same commits available.
    control
        .set_versioning_enabled("t", "v", true)
        .await
        .unwrap();
    let reopened = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    assert_eq!(
        reopened
            .read_file(&first.id, "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        first_contents
    );
    reopened.close().await.unwrap();
    control
        .set_versioning_enabled("t", "v", false)
        .await
        .unwrap();

    // Disabling the optional feature does not alter or block normal SlateFS I/O.
    live.write(&creds, restored.ino, 0, b"ordinary write")
        .await
        .unwrap();
    assert_eq!(
        live.read(&creds, restored.ino, 0, 1024)
            .await
            .unwrap()
            .as_ref(),
        b"ordinary write"
    );

    live.shutdown().await.unwrap();
    control.close().await.unwrap();
}

#[tokio::test]
async fn commits_directories_symlinks_renames_and_deletions_atomically() {
    let object_store: Arc<dyn ObjectStore> = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        common::create_opts(None, None),
    )
    .await
    .unwrap();
    control
        .set_versioning_enabled("t", "v", true)
        .await
        .unwrap();
    let dek = control.unwrap_volume_dek(&record).await.unwrap();
    let live = Volume::open(&record, dek, Arc::clone(&object_store))
        .await
        .unwrap();
    let creds = Credentials::root();
    let docs = live.mkdir(&creds, ROOT_INO, b"docs", 0o750).await.unwrap();
    let first_file = live
        .create(&creds, docs.ino, b"a.txt", 0o640, true)
        .await
        .unwrap();
    live.write(&creds, first_file.ino, 0, b"alpha")
        .await
        .unwrap();
    let second_file = live
        .create(&creds, docs.ino, b"b.txt", 0o644, true)
        .await
        .unwrap();
    live.write(&creds, second_file.ino, 0, b"bravo")
        .await
        .unwrap();
    live.symlink(&creds, docs.ino, b"latest", b"a.txt")
        .await
        .unwrap();

    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let initial = repository
        .commit_paths(live.as_ref(), &["/docs".into()], "capture docs".into())
        .await
        .unwrap();
    assert_eq!(
        repository
            .read_file(&initial.id, "/docs/latest")
            .await
            .unwrap()
            .as_ref(),
        b"a.txt"
    );

    live.rename(&creds, docs.ino, b"a.txt", docs.ino, b"renamed.txt")
        .await
        .unwrap();
    live.unlink(&creds, docs.ino, b"b.txt").await.unwrap();
    let renamed = live.lookup(&creds, docs.ino, b"renamed.txt").await.unwrap();
    live.write(&creds, renamed.ino, 0, b"updated")
        .await
        .unwrap();
    let changed = repository
        .commit_paths(
            live.as_ref(),
            &[
                "/docs/a.txt".into(),
                "/docs/b.txt".into(),
                "/docs/renamed.txt".into(),
            ],
            "rename and delete".into(),
        )
        .await
        .unwrap();
    assert!(
        repository
            .read_file(&changed.id, "/docs/a.txt")
            .await
            .is_err()
    );
    assert!(
        repository
            .read_file(&changed.id, "/docs/b.txt")
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .read_file(&changed.id, "/docs/renamed.txt")
            .await
            .unwrap()
            .as_ref(),
        b"updated"
    );

    live.unlink(&creds, docs.ino, b"latest").await.unwrap();
    repository
        .restore_file(live.as_ref(), &initial.id, "/docs")
        .await
        .unwrap();
    let restored_a = live.lookup(&creds, docs.ino, b"a.txt").await.unwrap();
    assert_eq!(
        live.read(&creds, restored_a.ino, 0, 32)
            .await
            .unwrap()
            .as_ref(),
        b"alpha"
    );
    let restored_link = live.lookup(&creds, docs.ino, b"latest").await.unwrap();
    assert_eq!(
        live.readlink(&creds, restored_link.ino).await.unwrap(),
        b"a.txt"
    );

    repository.close().await.unwrap();
    live.shutdown().await.unwrap();
    control.close().await.unwrap();
}

#[tokio::test]
async fn retention_gc_quota_and_purge_manage_history_lifecycle() {
    let object_store: Arc<dyn ObjectStore> = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        common::create_opts(None, None),
    )
    .await
    .unwrap();
    control
        .set_versioning_enabled("t", "v", true)
        .await
        .unwrap();
    control
        .set_versioning_retention_policy("t", "v", Some(1), None, None)
        .await
        .unwrap();
    let dek = control.unwrap_volume_dek(&record).await.unwrap();
    let live = Volume::open(&record, dek, Arc::clone(&object_store))
        .await
        .unwrap();
    let creds = Credentials::root();
    let file = live
        .create(&creds, ROOT_INO, b"history.txt", 0o644, true)
        .await
        .unwrap();
    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let mut commits = Vec::new();
    for (index, contents) in [b"one".as_slice(), b"two", b"three"]
        .into_iter()
        .enumerate()
    {
        live.write(&creds, file.ino, 0, contents).await.unwrap();
        live.setattr(
            &creds,
            file.ino,
            slatefs_core::vfs::SetAttrs {
                size: Some(contents.len() as u64),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        commits.push(
            repository
                .commit_file(live.as_ref(), "/history.txt", format!("version {index}"))
                .await
                .unwrap(),
        );
    }
    assert_eq!(repository.stats().await.unwrap().commits, 3);
    let dry_run = repository
        .garbage_collect(Some(1), None, true)
        .await
        .unwrap();
    assert_eq!(dry_run.deleted_commits, 2);
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 3);

    let collected = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(collected.retained_commits, 1);
    assert_eq!(collected.deleted_commits, 2);
    assert!(collected.reclaimed_bytes > 0);
    let history = repository.history(None, 10).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, commits[2].id);
    assert!(
        repository
            .read_file(&commits[0].id, "/history.txt")
            .await
            .is_err()
    );
    repository.close().await.unwrap();

    control
        .set_versioning_retention_policy("t", "v", Some(1), None, Some(1))
        .await
        .unwrap();
    let quota_repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    live.write(&creds, file.ino, 0, b"quota").await.unwrap();
    assert!(
        quota_repository
            .commit_file(live.as_ref(), "/history.txt", "over quota".into())
            .await
            .unwrap_err()
            .to_string()
            .contains("quota exceeded")
    );
    quota_repository.close().await.unwrap();
    live.shutdown().await.unwrap();

    let deleted = purge_version_history(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    assert!(deleted > 0);
    let remaining: Vec<_> = object_store
        .list(Some(&store::version_db_prefix("t", "v")))
        .try_collect()
        .await
        .unwrap();
    assert!(remaining.is_empty());
    control.close().await.unwrap();
}
