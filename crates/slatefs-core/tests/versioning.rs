//! End-to-end coverage for opt-in Prolly-backed file versioning.

mod common;

use std::sync::Arc;

use futures::TryStreamExt;
use slatefs_core::control::ControlPlane;
use slatefs_core::error::Error;
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::versioning::{
    VersionPathChangeKind, VersionRepository, force_break_expired_version_maintenance_lease,
    purge_version_history, try_get_version_maintenance_lease,
};
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
    assert!(
        VersionRepository::open_existing(&control, Arc::clone(&object_store), "t", "v")
            .await
            .unwrap()
            .is_none()
    );
    let version_objects: Vec<_> = object_store
        .list(Some(&store::version_db_prefix("t", "v")))
        .try_collect()
        .await
        .unwrap();
    assert!(
        version_objects.is_empty(),
        "maintenance probes must preserve lazy repository creation"
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
    assert_eq!(second.parents, vec![first.id.clone()]);
    let diff = repository
        .diff_commits(&first.id, &second.id)
        .await
        .unwrap();
    assert_eq!(diff.len(), 1);
    assert_eq!(diff[0].path(), "/notes.txt");
    assert_eq!(diff[0].change(), VersionPathChangeKind::Modified);

    repository.create_branch("draft", &first.id).await.unwrap();
    let branch_contents = b"branch version\n";
    live.write(&creds, file.ino, 0, branch_contents)
        .await
        .unwrap();
    let branch_result = repository
        .commit_paths_on_branch_idempotent(
            live.as_ref(),
            "draft",
            &["/notes.txt".into()],
            "draft update".into(),
            "draft-retry",
        )
        .await
        .unwrap();
    assert!(!branch_result.replayed());
    let branch_commit = branch_result.commit().clone();
    let branch_replay = repository
        .commit_paths_on_branch_idempotent(
            live.as_ref(),
            "draft",
            &["/notes.txt".into()],
            "draft update".into(),
            "draft-retry",
        )
        .await
        .unwrap();
    assert!(branch_replay.replayed());
    assert_eq!(branch_replay.commit().id, branch_commit.id);
    assert_eq!(branch_commit.parents, vec![first.id.clone()]);
    assert_eq!(
        repository
            .read_file("main", "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        second_contents
    );
    assert_eq!(
        repository
            .read_file("draft", "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        branch_contents
    );

    let history = repository.history(Some("/notes.txt"), 10).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].id, second.id);
    assert_eq!(history[1].id, first.id);
    let branch_history = repository
        .history_on_branch("draft", Some("/notes.txt"), 10)
        .await
        .unwrap();
    assert_eq!(branch_history.len(), 2);
    assert_eq!(branch_history[0].id, branch_commit.id);
    assert_eq!(branch_history[1].id, first.id);
    repository
        .create_branch("release", &first.id)
        .await
        .unwrap();
    let merged = repository.merge_branch("main", "release").await.unwrap();
    assert!(merged.fast_forward());
    assert!(!merged.already_up_to_date());
    assert_eq!(merged.commit(), second.id);
    let unchanged = repository.merge_branch("main", "release").await.unwrap();
    assert!(!unchanged.fast_forward());
    assert!(unchanged.already_up_to_date());
    repository
        .create_branch("feature", &first.id)
        .await
        .unwrap();
    let feature_file = live
        .create(&creds, ROOT_INO, b"feature.txt", 0o640, true)
        .await
        .unwrap();
    live.write(&creds, feature_file.ino, 0, b"feature contents")
        .await
        .unwrap();
    let feature_commit = repository
        .commit_paths_on_branch(
            live.as_ref(),
            "feature",
            &["/feature.txt".into()],
            "add feature file".into(),
        )
        .await
        .unwrap();
    let three_way = repository.merge_branch("feature", "main").await.unwrap();
    assert!(!three_way.fast_forward());
    assert!(!three_way.already_up_to_date());
    let merged_history = repository
        .history_on_branch("main", None, 10)
        .await
        .unwrap();
    assert_eq!(merged_history[0].id, three_way.commit());
    assert_eq!(
        merged_history[0].parents,
        vec![second.id.clone(), feature_commit.id.clone()]
    );
    assert_eq!(
        repository
            .read_file("main", "/feature.txt")
            .await
            .unwrap()
            .as_ref(),
        b"feature contents"
    );
    assert_eq!(
        repository
            .read_file("main", "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        second_contents
    );
    let conflict = repository.merge_branch("draft", "main").await.unwrap_err();
    assert!(conflict.to_string().contains("merge conflict"));
    let branches = repository.list_branches().await.unwrap();
    assert_eq!(
        branches
            .iter()
            .find(|branch| branch.name() == "main")
            .unwrap()
            .commit(),
        three_way.commit()
    );
    assert_eq!(
        branches
            .iter()
            .find(|branch| branch.name() == "draft")
            .unwrap()
            .commit(),
        branch_commit.id
    );
    let verified = repository.verify().await.unwrap();
    assert_eq!(verified.commits, 5);
    assert!(verified.nodes > 0);
    assert!(verified.blobs > 0);
    repository.delete_branch("feature").await.unwrap();
    let complete_dag_gc = repository.garbage_collect(None, None, true).await.unwrap();
    assert_eq!(complete_dag_gc.retained_commits, 5);
    assert_eq!(complete_dag_gc.deleted_commits, 0);
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
async fn idempotent_commit_retries_return_the_original_commit() {
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
    let file = live
        .create(&creds, ROOT_INO, b"notes.txt", 0o640, true)
        .await
        .unwrap();
    live.write(&creds, file.ino, 0, b"first contents")
        .await
        .unwrap();

    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let first = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["notes.txt".into(), "/notes.txt".into()],
            "save notes".into(),
            "retry-1",
        )
        .await
        .unwrap();
    assert!(!first.replayed());
    let first_id = first.commit().id.clone();

    live.write(&creds, file.ino, 0, b"changed after response loss")
        .await
        .unwrap();
    let replay = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "save notes".into(),
            "retry-1",
        )
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.commit().id, first_id);
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 1);
    assert_eq!(
        repository
            .read_file(&first_id, "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        b"first contents"
    );

    let conflict = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "different request".into(),
            "retry-1",
        )
        .await
        .unwrap_err();
    assert!(matches!(conflict, Error::AlreadyExists { .. }));
    let invalid = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "save notes".into(),
            "",
        )
        .await
        .unwrap_err();
    assert!(matches!(invalid, Error::Invalid { .. }));

    let repository = Arc::new(repository);
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let repository = Arc::clone(&repository);
        let live = Arc::clone(&live);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            repository
                .commit_volume_paths_idempotent(
                    live.as_ref(),
                    &["/notes.txt".into()],
                    "save changed notes".into(),
                    "retry-concurrent",
                )
                .await
                .unwrap()
        }));
    }
    barrier.wait().await;
    let left = tasks.remove(0).await.unwrap();
    let right = tasks.remove(0).await.unwrap();
    assert_eq!(left.commit().id, right.commit().id);
    assert_ne!(left.replayed(), right.replayed());
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 2);
    let gc = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(gc.deleted_commits, 1);
    let pruned_retry = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "save notes".into(),
            "retry-1",
        )
        .await
        .unwrap_err();
    assert!(pruned_retry.to_string().contains("no changes"));

    repository.close().await.unwrap();
    live.shutdown().await.unwrap();
    control.close().await.unwrap();
}

#[tokio::test]
async fn version_repository_lease_coordinates_open_and_purge() {
    let object_store: Arc<dyn ObjectStore> = store::resolve_root("memory:///").unwrap();
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
    control
        .set_versioning_enabled("t", "v", true)
        .await
        .unwrap();

    let first = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let active = try_get_version_maintenance_lease(Arc::clone(&object_store), "t", "v")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.tenant(), "t");
    assert_eq!(active.volume(), "v");
    assert_eq!(active.operation(), "repository");
    assert!(!active.owner().is_empty());
    assert!(active.acquired_at() <= active.expires_at());
    assert!(!active.is_expired_at(slatefs_core::control::now_unix()));
    let second = match VersionRepository::open(&control, Arc::clone(&object_store), "t", "v").await
    {
        Ok(_) => panic!("second repository unexpectedly acquired the lease"),
        Err(error) => error,
    };
    assert!(matches!(second, Error::AlreadyExists { .. }));
    let purge = purge_version_history(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap_err();
    assert!(matches!(purge, Error::AlreadyExists { .. }));

    first.close().await.unwrap();
    let released = try_get_version_maintenance_lease(Arc::clone(&object_store), "t", "v")
        .await
        .unwrap()
        .unwrap();
    assert!(released.is_expired_at(slatefs_core::control::now_unix()));
    assert!(
        force_break_expired_version_maintenance_lease(
            Arc::clone(&object_store),
            "t",
            "v",
            "wrong-owner",
        )
        .await
        .is_err()
    );
    assert!(
        force_break_expired_version_maintenance_lease(
            Arc::clone(&object_store),
            "t",
            "v",
            released.owner(),
        )
        .await
        .unwrap()
    );
    let broken = try_get_version_maintenance_lease(Arc::clone(&object_store), "t", "v")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(broken.operation(), "operator-break");
    let second = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    second.close().await.unwrap();
    purge_version_history(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    control.close().await.unwrap();
}

#[tokio::test]
async fn range_reads_and_restore_stream_across_chunks() {
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
    let file = live
        .create(&creds, ROOT_INO, b"large.bin", 0o640, true)
        .await
        .unwrap();
    let contents = (0..(common::TEST_CHUNK as usize * 3 + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    live.write(&creds, file.ino, 0, &contents).await.unwrap();

    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let commit = repository
        .commit_file(live.as_ref(), "/large.bin", "large file".into())
        .await
        .unwrap();
    let offset = common::TEST_CHUNK as u64 - 13;
    let range = repository
        .read_file_range(&commit.id, "/large.bin", offset, 64)
        .await
        .unwrap();
    assert_eq!(range.offset, offset);
    assert_eq!(range.total_size, contents.len() as u64);
    assert!(!range.eof);
    assert_eq!(
        range.data.as_ref(),
        &contents[offset as usize..offset as usize + 64]
    );

    let tail = repository
        .read_file_range(&commit.id, "/large.bin", contents.len() as u64 - 7, 100)
        .await
        .unwrap();
    assert!(tail.eof);
    assert_eq!(tail.data.as_ref(), &contents[contents.len() - 7..]);
    let past_eof = repository
        .read_file_range(&commit.id, "/large.bin", contents.len() as u64 + 10, 100)
        .await
        .unwrap();
    assert!(past_eof.eof);
    assert!(past_eof.data.is_empty());

    live.write(&creds, file.ino, 0, b"overwritten")
        .await
        .unwrap();
    repository
        .restore_file(live.as_ref(), &commit.id, "/large.bin")
        .await
        .unwrap();
    let restored = live.lookup(&creds, ROOT_INO, b"large.bin").await.unwrap();
    assert_eq!(
        live.read(&creds, restored.ino, 0, contents.len() as u32)
            .await
            .unwrap()
            .as_ref(),
        contents
    );

    repository.close().await.unwrap();
    live.shutdown().await.unwrap();
    control.close().await.unwrap();
}

#[tokio::test]
async fn fenced_live_writer_cannot_publish_a_version_commit() {
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
    let stale = Volume::open(&record, dek.clone(), Arc::clone(&object_store))
        .await
        .unwrap();
    let creds = Credentials::root();
    let file = stale
        .create(&creds, ROOT_INO, b"primary.txt", 0o640, true)
        .await
        .unwrap();
    stale
        .write(&creds, file.ino, 0, b"durable primary data")
        .await
        .unwrap();
    stale.flush().await.unwrap();

    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let replacement = Volume::open(&record, dek, Arc::clone(&object_store))
        .await
        .unwrap();
    let replacement_file = replacement
        .lookup(&creds, ROOT_INO, b"primary.txt")
        .await
        .unwrap();
    replacement
        .write(&creds, replacement_file.ino, 0, b"replacement primary")
        .await
        .unwrap();
    replacement.flush().await.unwrap();
    let error = repository
        .commit_volume_paths(
            stale.as_ref(),
            &["/primary.txt".into()],
            "stale primary".into(),
        )
        .await
        .unwrap_err();
    assert!(stale.is_dead());
    assert!(error.to_string().contains("newer DB client"), "{error}");
    assert!(repository.history(None, 10).await.unwrap().is_empty());

    let committed = repository
        .commit_volume_paths(
            replacement.as_ref(),
            &["/primary.txt".into()],
            "replacement primary".into(),
        )
        .await
        .unwrap();
    assert_eq!(committed.paths, vec!["/primary.txt"]);
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 1);

    repository.close().await.unwrap();
    replacement.shutdown().await.unwrap();
    let _ = stale.shutdown().await;
    control.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_commits_preserve_a_linear_complete_history() {
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
    for (name, contents) in [
        (b"a.txt".as_slice(), b"alpha".as_slice()),
        (b"b.txt", b"bravo"),
    ] {
        let file = live
            .create(&creds, ROOT_INO, name, 0o640, true)
            .await
            .unwrap();
        live.write(&creds, file.ino, 0, contents).await.unwrap();
    }
    live.validate_writer_lease().await.unwrap();

    let repository = Arc::new(
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
            .await
            .unwrap(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for (path, message) in [("/a.txt", "commit a"), ("/b.txt", "commit b")] {
        let repository = Arc::clone(&repository);
        let live = Arc::clone(&live);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let result = repository
                .commit_volume_paths(live.as_ref(), &[path.to_string()], message.to_string())
                .await;
            (path.to_string(), message.to_string(), result)
        }));
    }
    barrier.wait().await;

    for task in tasks {
        let (path, message, result) = task.await.unwrap();
        if let Err(error) = result {
            assert!(
                error.to_string().contains("branch moved"),
                "unexpected concurrent commit failure: {error}"
            );
            repository
                .commit_volume_paths(live.as_ref(), &[path], format!("retry {message}"))
                .await
                .unwrap();
        }
    }

    let history = repository.history(None, 10).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].parents, vec![history[1].id.clone()]);
    let (first_page, next_page_token) = repository.history_page(None, 1, None).await.unwrap();
    assert_eq!(first_page, vec![history[0].clone()]);
    assert_eq!(next_page_token.as_deref(), Some(history[0].id.as_str()));
    let (second_page, final_page_token) = repository
        .history_page(None, 1, next_page_token.as_deref())
        .await
        .unwrap();
    assert_eq!(second_page, vec![history[1].clone()]);
    assert!(final_page_token.is_none());
    assert!(
        repository
            .history_page(None, 1, Some("missing"))
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .read_file(&history[0].id, "/a.txt")
            .await
            .unwrap()
            .as_ref(),
        b"alpha"
    );
    assert_eq!(
        repository
            .read_file(&history[0].id, "/b.txt")
            .await
            .unwrap()
            .as_ref(),
        b"bravo"
    );

    let repository = match Arc::try_unwrap(repository) {
        Ok(repository) => repository,
        Err(_) => panic!("repository task references leaked"),
    };
    repository.close().await.unwrap();
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
    let diff = repository
        .diff_commits(&initial.id, &changed.id)
        .await
        .unwrap();
    assert_eq!(diff.len(), 3);
    assert_eq!(diff[0].path(), "/docs/a.txt");
    assert_eq!(diff[0].change(), VersionPathChangeKind::Deleted);
    assert_eq!(diff[1].path(), "/docs/b.txt");
    assert_eq!(diff[1].change(), VersionPathChangeKind::Deleted);
    assert_eq!(diff[2].path(), "/docs/renamed.txt");
    assert_eq!(diff[2].change(), VersionPathChangeKind::Added);
    let (first_page, token) = repository
        .diff_commits_page(&initial.id, &changed.id, 2, None)
        .await
        .unwrap();
    assert_eq!(first_page, diff[..2]);
    let (second_page, final_token) = repository
        .diff_commits_page(&initial.id, &changed.id, 2, token.as_deref())
        .await
        .unwrap();
    assert_eq!(second_page, diff[2..]);
    assert!(final_token.is_none());

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
    let tag = repository
        .create_tag("milestone-1", &commits[0].id)
        .await
        .unwrap();
    assert_eq!(tag.name(), "milestone-1");
    assert_eq!(tag.commit(), commits[0].id);
    let branch = repository
        .create_branch("release", "milestone-1")
        .await
        .unwrap();
    assert_eq!(branch.name(), "release");
    assert_eq!(branch.commit(), commits[0].id);
    assert!(matches!(
        repository.create_tag("milestone-1", &commits[1].id).await,
        Err(Error::AlreadyExists { .. })
    ));
    assert!(matches!(
        repository.create_tag("release", &commits[1].id).await,
        Err(Error::AlreadyExists { .. })
    ));
    assert!(matches!(
        repository
            .create_branch("milestone-1", &commits[1].id)
            .await,
        Err(Error::AlreadyExists { .. })
    ));
    assert!(matches!(
        repository.create_branch("main", &commits[1].id).await,
        Err(Error::Invalid { .. })
    ));
    assert_eq!(repository.list_tags().await.unwrap(), vec![tag.clone()]);
    let branches = repository.list_branches().await.unwrap();
    assert_eq!(branches.len(), 2);
    assert_eq!(branches[0].name(), "main");
    assert_eq!(branches[0].commit(), commits[2].id);
    assert_eq!(branches[1], branch);
    assert!(matches!(
        repository.create_tag(&"a".repeat(64), &commits[0].id).await,
        Err(Error::Invalid { .. })
    ));
    let dry_run = repository
        .garbage_collect(Some(1), None, true)
        .await
        .unwrap();
    assert_eq!(dry_run.deleted_commits, 1);
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 3);

    let collected = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(collected.retained_commits, 2);
    assert_eq!(collected.deleted_commits, 1);
    assert!(collected.reclaimed_bytes > 0);
    let history = repository.history(None, 10).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, commits[2].id);
    assert_eq!(repository.verify().await.unwrap().commits, 2);
    assert_eq!(
        repository
            .read_file("milestone-1", "/history.txt")
            .await
            .unwrap()
            .as_ref(),
        b"one"
    );
    assert_eq!(
        repository
            .read_file("release", "/history.txt")
            .await
            .unwrap()
            .as_ref(),
        b"one"
    );
    let tagged_diff = repository
        .diff_commits("milestone-1", &commits[2].id)
        .await
        .unwrap();
    assert_eq!(tagged_diff.len(), 1);
    assert_eq!(tagged_diff[0].change(), VersionPathChangeKind::Modified);
    assert_eq!(repository.delete_tag("milestone-1").await.unwrap(), tag);
    assert!(repository.list_tags().await.unwrap().is_empty());
    let still_branch_pinned = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(still_branch_pinned.retained_commits, 2);
    assert_eq!(still_branch_pinned.deleted_commits, 0);
    assert_eq!(repository.delete_branch("release").await.unwrap(), branch);
    assert_eq!(repository.list_branches().await.unwrap().len(), 1);
    assert!(matches!(
        repository.delete_branch("main").await,
        Err(Error::Invalid { .. })
    ));
    let unpinned = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(unpinned.retained_commits, 1);
    assert_eq!(unpinned.deleted_commits, 1);
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
    let before_rejected_commit = quota_repository.stats().await.unwrap();
    live.write(&creds, file.ino, 0, b"quota").await.unwrap();
    assert!(
        quota_repository
            .commit_file(live.as_ref(), "/history.txt", "over quota".into())
            .await
            .unwrap_err()
            .to_string()
            .contains("quota exceeded")
    );
    let with_unpublished_objects = quota_repository.stats().await.unwrap();
    assert!(with_unpublished_objects.bytes > before_rejected_commit.bytes);
    assert_eq!(
        with_unpublished_objects.commits,
        before_rejected_commit.commits
    );
    let recovered = quota_repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(recovered.deleted_commits, 0);
    assert!(recovered.deleted_nodes + recovered.deleted_blobs > 0);
    assert!(quota_repository.stats().await.unwrap().bytes < with_unpublished_objects.bytes);
    assert_eq!(quota_repository.history(None, 10).await.unwrap().len(), 1);
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
