//! End-to-end coverage for opt-in Prolly-backed file versioning.

mod common;

use std::sync::Arc;

use futures::TryStreamExt;
use slatefs_core::control::ControlPlane;
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::versioning::VersionRepository;
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
