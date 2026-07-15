//! End-to-end coverage for opt-in Prolly-backed file versioning.

mod common;

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use futures::TryStreamExt;
use slatefs_core::control::ControlPlane;
use slatefs_core::error::Error;
use slatefs_core::meta::inode::ROOT_INO;
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::version_snapshot::VersionHistoricalVolume;
use slatefs_core::versioning::{
    VersionBranchProtectionPolicy, VersionCommitAttestation, VersionCommitOrigin,
    VersionCommitProvenance, VersionMergeConflictStrategy, VersionPathChangeKind,
    VersionReflogAction, VersionRepository, VersionRepositoryIdentity, VersionRestoreActionKind,
    VersionRestoreMode, VersionTrustedAttestationKey, VersionWorkingTreeChangeKind,
    force_break_expired_version_maintenance_lease, purge_version_history,
    try_get_version_maintenance_lease, version_commit_attestation_payload,
};
use slatefs_core::vfs::{Credentials, FsError, Vfs};
use slatefs_core::volume::{self, Volume};

fn test_provenance() -> VersionCommitProvenance {
    VersionCommitProvenance::new(
        VersionCommitOrigin::Api,
        "test-author",
        "test-committer",
        uuid::Uuid::new_v4().to_string(),
    )
    .unwrap()
}

#[tokio::test]
async fn historical_version_volume_is_immutable_and_synthesizes_ancestors() {
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
    let note = live
        .create(&creds, docs.ino, b"note.txt", 0o640, true)
        .await
        .unwrap();
    live.write(&creds, note.ino, 0, b"historical contents")
        .await
        .unwrap();
    live.symlink(&creds, docs.ino, b"latest", b"note.txt")
        .await
        .unwrap();

    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let first = repository
        .commit_paths(
            live.as_ref(),
            &["/docs/note.txt".into(), "/docs/latest".into()],
            "historical export source".into(),
            test_provenance(),
        )
        .await
        .unwrap();
    repository
        .create_tag("historical-test", &first.id)
        .await
        .unwrap();
    repository.close().await.unwrap();

    let historical = VersionHistoricalVolume::open(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        "historical-test",
    )
    .await
    .unwrap();
    assert_eq!(historical.commit(), first.id);
    assert!(historical.read_only());
    assert_ne!(historical.fsid(), live.fsid());

    let historical_docs = historical.lookup(&creds, ROOT_INO, b"docs").await.unwrap();
    assert_eq!(
        historical_docs.mode, 0o555,
        "missing ancestor is synthesized"
    );
    let page = historical
        .readdir(&creds, historical_docs.ino, 0, 16)
        .await
        .unwrap();
    assert!(page.eof);
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.name.as_slice())
            .collect::<Vec<_>>(),
        vec![b"latest".as_slice(), b"note.txt".as_slice()]
    );
    let historical_note = historical
        .lookup(&creds, historical_docs.ino, b"note.txt")
        .await
        .unwrap();
    assert_eq!(
        historical
            .read(&creds, historical_note.ino, 3, 10)
            .await
            .unwrap()
            .as_ref(),
        b"torical co"
    );
    let historical_link = historical
        .lookup(&creds, historical_docs.ino, b"latest")
        .await
        .unwrap();
    assert_eq!(
        historical
            .readlink(&creds, historical_link.ino)
            .await
            .unwrap(),
        b"note.txt"
    );
    assert_eq!(
        historical
            .create(&creds, historical_docs.ino, b"nope", 0o644, true)
            .await
            .unwrap_err(),
        FsError::ReadOnly
    );

    // The checkpoint-backed view releases the repository lease and remains
    // pinned while the live repository advances.
    live.write(&creds, note.ino, 0, b"current contents   ")
        .await
        .unwrap();
    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let current = repository
        .commit_file(
            live.as_ref(),
            "/docs/note.txt",
            "advance live history".into(),
            test_provenance(),
        )
        .await
        .unwrap();
    assert_ne!(current.id, first.id);
    assert_eq!(
        historical
            .read(&creds, historical_note.ino, 0, 64)
            .await
            .unwrap()
            .as_ref(),
        b"historical contents"
    );

    repository.close().await.unwrap();
    historical.shutdown().await.unwrap();
    live.shutdown().await.unwrap();
    control.close().await.unwrap();
}

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
        .commit_file(
            live.as_ref(),
            "/notes.txt",
            "initial notes".to_string(),
            test_provenance(),
        )
        .await
        .unwrap();
    assert_eq!(first.paths, vec!["/notes.txt"]);
    assert_eq!(first.provenance.origin(), VersionCommitOrigin::Api);
    assert_eq!(first.provenance.author(), "test-author");
    assert_eq!(first.provenance.committer(), "test-committer");
    assert!(!first.provenance.request_id().is_empty());

    let second_contents = b"second version\n";
    live.write(&creds, file.ino, 0, second_contents)
        .await
        .unwrap();
    let second = repository
        .commit_file(
            live.as_ref(),
            "notes.txt",
            "update notes".to_string(),
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(
        repository
            .working_tree_status(live.as_ref(), "main", "/notes.txt")
            .await
            .unwrap()
            .is_clean()
    );
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
    let draft_file = live
        .create(&creds, ROOT_INO, b"draft.txt", 0o640, true)
        .await
        .unwrap();
    live.write(&creds, draft_file.ino, 0, b"draft contents")
        .await
        .unwrap();
    let branch_result = repository
        .commit_paths_on_branch_idempotent(
            live.as_ref(),
            "draft",
            &["/notes.txt".into(), "/draft.txt".into()],
            "draft update".into(),
            test_provenance(),
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
            &["/notes.txt".into(), "/draft.txt".into()],
            "draft update".into(),
            test_provenance(),
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
    let fast_forward_preview = repository
        .preview_branch_merge("main", "release")
        .await
        .unwrap();
    assert!(fast_forward_preview.fast_forward());
    assert!(!fast_forward_preview.already_up_to_date());
    assert_eq!(fast_forward_preview.ahead(), 1);
    assert_eq!(fast_forward_preview.behind(), 0);
    assert_eq!(fast_forward_preview.merge_base(), first.id);
    let merged = repository
        .merge_branch(
            "main",
            "release",
            VersionMergeConflictStrategy::Fail,
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(merged.fast_forward());
    assert!(!merged.already_up_to_date());
    assert_eq!(merged.commit(), second.id);
    let unchanged = repository
        .merge_branch(
            "main",
            "release",
            VersionMergeConflictStrategy::Fail,
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(!unchanged.fast_forward());
    assert!(unchanged.already_up_to_date());
    let reset = repository.reset_branch("release", &first.id).await.unwrap();
    assert_eq!(reset.previous(), second.id);
    assert_eq!(reset.commit(), first.id);
    let reset = repository.reset_branch("release", "main").await.unwrap();
    assert_eq!(reset.previous(), first.id);
    assert_eq!(reset.commit(), second.id);
    let release_reflog = repository.reflog("release", 100).await.unwrap();
    assert_eq!(release_reflog.len(), 4);
    assert_eq!(release_reflog[0].action(), VersionReflogAction::Reset);
    assert_eq!(release_reflog[0].previous(), Some(first.id.as_str()));
    assert_eq!(release_reflog[0].commit(), Some(second.id.as_str()));
    assert_eq!(release_reflog[1].action(), VersionReflogAction::Reset);
    assert_eq!(release_reflog[2].action(), VersionReflogAction::FastForward);
    assert_eq!(release_reflog[3].action(), VersionReflogAction::Create);
    let recovered = repository
        .recover_branch("release", release_reflog[0].sequence())
        .await
        .unwrap();
    assert_eq!(recovered.previous(), Some(second.id.as_str()));
    assert_eq!(recovered.commit(), first.id);
    assert_eq!(
        repository.reflog("release", 1).await.unwrap()[0].action(),
        VersionReflogAction::Recover
    );
    let other_policy = VersionBranchProtectionPolicy::new(
        &["other-committer".into()],
        &["test-manager".into()],
        &[],
        0,
    )
    .unwrap();
    let protected = repository
        .set_branch_protected("release", true, &other_policy)
        .await
        .unwrap();
    assert!(protected.protected());
    assert_eq!(protected.allowed_committers(), &["other-committer"]);
    assert_eq!(protected.allowed_managers(), &["test-manager"]);
    assert!(
        repository
            .list_branches()
            .await
            .unwrap()
            .iter()
            .find(|branch| branch.name() == "release")
            .unwrap()
            .protected()
    );
    assert!(matches!(
        repository
            .merge_branch(
                "main",
                "release",
                VersionMergeConflictStrategy::Fail,
                test_provenance(),
            )
            .await,
        Err(Error::Invalid { .. })
    ));
    let managed_policy = VersionBranchProtectionPolicy::new(
        &["test-committer".into()],
        &["test-manager".into()],
        &[],
        0,
    )
    .unwrap();
    assert!(matches!(
        repository
            .set_branch_protected_as("release", true, &managed_policy, "other-manager")
            .await,
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        repository
            .set_branch_protected_as(
                "release",
                false,
                &VersionBranchProtectionPolicy::default(),
                "other-manager",
            )
            .await,
        Err(Error::Invalid { .. })
    ));
    let protected = repository
        .set_branch_protected_as("release", true, &managed_policy, "test-manager")
        .await
        .unwrap();
    assert_eq!(protected.allowed_committers(), &["test-committer"]);
    assert!(matches!(
        repository.reset_branch("release", "main").await,
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        repository.delete_branch("release").await,
        Err(Error::Invalid { .. })
    ));
    assert!(matches!(
        repository
            .recover_branch("release", release_reflog[0].sequence())
            .await,
        Err(Error::Invalid { .. })
    ));
    let protected_fast_forward = repository
        .merge_branch(
            "main",
            "release",
            VersionMergeConflictStrategy::Fail,
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(protected_fast_forward.fast_forward());
    repository.close().await.unwrap();
    assert!(matches!(
        purge_version_history(&control, Arc::clone(&object_store), "t", "v").await,
        Err(Error::Invalid {
            what: "version history purge",
            ..
        })
    ));
    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let unprotected = repository
        .set_branch_protected_as(
            "release",
            false,
            &VersionBranchProtectionPolicy::default(),
            "test-manager",
        )
        .await
        .unwrap();
    assert!(!unprotected.protected());
    assert_eq!(
        repository.delete_branch("release").await.unwrap().name(),
        "release"
    );
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
            test_provenance(),
        )
        .await
        .unwrap();
    let three_way_preview = repository
        .preview_branch_merge("feature", "main")
        .await
        .unwrap();
    assert!(!three_way_preview.fast_forward());
    assert!(!three_way_preview.already_up_to_date());
    assert!(three_way_preview.can_merge());
    assert_eq!(three_way_preview.ahead(), 1);
    assert_eq!(three_way_preview.behind(), 1);
    assert_eq!(three_way_preview.merge_base(), first.id);
    let three_way = repository
        .merge_branch(
            "feature",
            "main",
            VersionMergeConflictStrategy::Fail,
            test_provenance(),
        )
        .await
        .unwrap();
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
        merged_history[0].provenance.origin(),
        VersionCommitOrigin::Api
    );
    assert_eq!(merged_history[0].provenance.author(), "test-author");
    assert_eq!(merged_history[0].provenance.committer(), "test-committer");
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
    let conflict_preview = repository
        .preview_branch_merge("draft", "main")
        .await
        .unwrap();
    assert!(!conflict_preview.can_merge());
    assert_eq!(conflict_preview.conflicts(), &["/notes.txt".to_string()]);
    let conflict = repository
        .merge_branch(
            "draft",
            "main",
            VersionMergeConflictStrategy::Fail,
            test_provenance(),
        )
        .await
        .unwrap_err();
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
    repository
        .create_branch("theirs-target", three_way.commit())
        .await
        .unwrap();
    let ours = repository
        .merge_branch(
            "draft",
            "main",
            VersionMergeConflictStrategy::Ours,
            test_provenance(),
        )
        .await
        .unwrap();
    assert_eq!(ours.strategy(), VersionMergeConflictStrategy::Ours);
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
            .read_file("main", "/draft.txt")
            .await
            .unwrap()
            .as_ref(),
        b"draft contents"
    );
    assert_eq!(
        repository
            .read_file("main", "/feature.txt")
            .await
            .unwrap()
            .as_ref(),
        b"feature contents"
    );
    let theirs = repository
        .merge_branch(
            "draft",
            "theirs-target",
            VersionMergeConflictStrategy::Theirs,
            test_provenance(),
        )
        .await
        .unwrap();
    assert_eq!(theirs.strategy(), VersionMergeConflictStrategy::Theirs);
    assert_eq!(
        repository
            .read_file("theirs-target", "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        branch_contents
    );
    assert_eq!(
        repository
            .read_file("theirs-target", "/draft.txt")
            .await
            .unwrap()
            .as_ref(),
        b"draft contents"
    );
    assert_eq!(
        repository
            .read_file("theirs-target", "/feature.txt")
            .await
            .unwrap()
            .as_ref(),
        b"feature contents"
    );
    let inspected = repository.inspect_commit("theirs-target").await.unwrap();
    assert_eq!(inspected.id, theirs.commit());
    assert_eq!(
        inspected.parents,
        vec![three_way.commit().to_string(), branch_commit.id.clone()]
    );
    let status = repository
        .working_tree_status(live.as_ref(), "draft", "/")
        .await
        .unwrap();
    assert_eq!(status.commit(), branch_commit.id);
    assert_eq!(status.root(), "/");
    assert_eq!(status.changes().len(), 1);
    assert_eq!(status.changes()[0].path(), "/feature.txt");
    assert_eq!(
        status.changes()[0].change(),
        VersionWorkingTreeChangeKind::Added
    );
    live.write(&creds, file.ino, 0, b"working change\n")
        .await
        .unwrap();
    let status = repository
        .working_tree_status(live.as_ref(), "draft", "/notes.txt")
        .await
        .unwrap();
    assert_eq!(
        status.changes()[0].change(),
        VersionWorkingTreeChangeKind::Modified
    );
    repository
        .restore_file(live.as_ref(), "draft", "/notes.txt")
        .await
        .unwrap();
    live.unlink(&creds, ROOT_INO, b"draft.txt").await.unwrap();
    let status = repository
        .working_tree_status(live.as_ref(), "draft", "/draft.txt")
        .await
        .unwrap();
    assert_eq!(
        status.changes()[0].change(),
        VersionWorkingTreeChangeKind::Deleted
    );
    live.mkdir(&creds, ROOT_INO, b"draft.txt", 0o750)
        .await
        .unwrap();
    let status = repository
        .working_tree_status(live.as_ref(), "draft", "/draft.txt")
        .await
        .unwrap();
    assert_eq!(
        status.changes()[0].change(),
        VersionWorkingTreeChangeKind::TypeChanged
    );
    live.rmdir(&creds, ROOT_INO, b"draft.txt").await.unwrap();
    repository
        .restore_file(live.as_ref(), "draft", "/draft.txt")
        .await
        .unwrap();
    let overlay = repository
        .preview_restore(live.as_ref(), "draft", "/", VersionRestoreMode::Overlay)
        .await
        .unwrap();
    assert!(overlay.is_clean());
    let exact = repository
        .preview_restore(live.as_ref(), "draft", "/", VersionRestoreMode::Exact)
        .await
        .unwrap();
    assert_eq!(exact.actions().len(), 1);
    assert_eq!(exact.actions()[0].path(), "/feature.txt");
    assert_eq!(
        exact.actions()[0].action(),
        VersionRestoreActionKind::Delete
    );
    live.write(&creds, feature_file.ino, 0, b"changed after preview")
        .await
        .unwrap();
    let stale = repository
        .apply_restore(
            live.as_ref(),
            "draft",
            "/",
            VersionRestoreMode::Exact,
            exact.token(),
        )
        .await
        .unwrap_err();
    assert!(stale.to_string().contains("restore preview is stale"));
    let exact = repository
        .preview_restore(live.as_ref(), "draft", "/", VersionRestoreMode::Exact)
        .await
        .unwrap();
    let applied = repository
        .apply_restore(
            live.as_ref(),
            "draft",
            "/",
            VersionRestoreMode::Exact,
            exact.token(),
        )
        .await
        .unwrap();
    assert!(!applied.atomic());
    assert_eq!(applied.actions(), exact.actions());
    assert!(live.lookup(&creds, ROOT_INO, b"feature.txt").await.is_err());
    assert!(
        repository
            .working_tree_status(live.as_ref(), "draft", "/")
            .await
            .unwrap()
            .is_clean()
    );
    let verified = repository.verify().await.unwrap();
    assert_eq!(verified.commits, 7);
    assert!(verified.nodes > 0);
    assert!(verified.blobs > 0);
    repository.delete_branch("feature").await.unwrap();
    let feature_reflog = repository.reflog("feature", 100).await.unwrap();
    assert_eq!(feature_reflog[0].action(), VersionReflogAction::Delete);
    assert_eq!(
        feature_reflog[0].previous(),
        Some(feature_commit.id.as_str())
    );
    assert_eq!(feature_reflog[0].commit(), None);
    let recovered = repository
        .recover_branch("feature", feature_reflog[0].sequence())
        .await
        .unwrap();
    assert_eq!(recovered.previous(), None);
    assert_eq!(recovered.commit(), feature_commit.id);
    assert_eq!(
        repository.reflog("feature", 1).await.unwrap()[0].action(),
        VersionReflogAction::Recover
    );
    let complete_dag_gc = repository.garbage_collect(None, None, true).await.unwrap();
    assert_eq!(complete_dag_gc.retained_commits, 7);
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
async fn detached_commit_attestations_are_optional_immutable_and_verified() {
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
        .create(&creds, ROOT_INO, b"signed.txt", 0o640, true)
        .await
        .unwrap();
    live.write(&creds, file.ino, 0, b"signed contents")
        .await
        .unwrap();
    let repository = VersionRepository::open(&control, Arc::clone(&object_store), "t", "v")
        .await
        .unwrap();
    let repository_identity = repository.identity().clone();
    let repository_id = repository_identity.id().to_string();
    assert!(uuid::Uuid::parse_str(&repository_id).is_ok());
    let commit = repository
        .commit_file(
            live.as_ref(),
            "/signed.txt",
            "content to attest".to_string(),
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(
        repository
            .list_commit_attestations(&commit.id)
            .await
            .unwrap()
            .is_empty()
    );

    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let created_at = 1_700_000_000;
    let payload = version_commit_attestation_payload(
        &repository_id,
        &commit.id,
        "release-2026",
        &public_key,
        created_at,
    )
    .unwrap();
    let attestation = VersionCommitAttestation::new_ed25519(
        "release-2026",
        public_key,
        signing_key.sign(&payload).to_bytes(),
        created_at,
    )
    .unwrap();
    assert_eq!(
        repository
            .add_commit_attestation(&commit.id, attestation.clone())
            .await
            .unwrap(),
        attestation
    );
    repository
        .add_commit_attestation("main", attestation.clone())
        .await
        .unwrap();
    assert_eq!(
        repository.list_commit_attestations("main").await.unwrap(),
        vec![attestation]
    );
    assert_eq!(repository.stats().await.unwrap().attestations, 1);
    assert_eq!(repository.verify().await.unwrap().attestations, 1);

    let replacement_time = created_at + 1;
    let replacement_payload = version_commit_attestation_payload(
        &repository_id,
        &commit.id,
        "release-2026",
        &public_key,
        replacement_time,
    )
    .unwrap();
    let replacement = VersionCommitAttestation::new_ed25519(
        "release-2026",
        public_key,
        signing_key.sign(&replacement_payload).to_bytes(),
        replacement_time,
    )
    .unwrap();
    assert!(matches!(
        repository
            .add_commit_attestation(&commit.id, replacement)
            .await,
        Err(Error::AlreadyExists { .. })
    ));

    let wrong_repository_id = if repository_id == "00000000-0000-4000-8000-000000000001" {
        "00000000-0000-4000-8000-000000000002"
    } else {
        "00000000-0000-4000-8000-000000000001"
    };
    let wrong_payload = version_commit_attestation_payload(
        wrong_repository_id,
        &commit.id,
        "wrong-context",
        &public_key,
        created_at,
    )
    .unwrap();
    let wrong_context = VersionCommitAttestation::new_ed25519(
        "wrong-context",
        public_key,
        signing_key.sign(&wrong_payload).to_bytes(),
        created_at,
    )
    .unwrap();
    assert!(matches!(
        repository
            .add_commit_attestation(&commit.id, wrong_context)
            .await,
        Err(Error::Invalid { .. })
    ));

    let security_signing_key = SigningKey::from_bytes(&[8; 32]);
    let security_public_key = security_signing_key.verifying_key().to_bytes();
    let security_payload = version_commit_attestation_payload(
        &repository_id,
        &commit.id,
        "security-2026",
        &security_public_key,
        created_at,
    )
    .unwrap();
    repository
        .add_commit_attestation(
            &commit.id,
            VersionCommitAttestation::new_ed25519(
                "security-2026",
                security_public_key,
                security_signing_key.sign(&security_payload).to_bytes(),
                created_at,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let trusted_key = VersionTrustedAttestationKey::new_ed25519(
        "release-2026",
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let security_trusted_key = VersionTrustedAttestationKey::new_ed25519(
        "security-2026",
        security_signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let trusted_keys = vec![trusted_key, security_trusted_key];
    repository
        .create_branch("release", &commit.id)
        .await
        .unwrap();
    assert!(matches!(
        VersionBranchProtectionPolicy::new(&[], &[], &trusted_keys, 0),
        Err(Error::Invalid {
            what: "version branch attestation quorum",
            ..
        })
    ));
    assert!(matches!(
        VersionBranchProtectionPolicy::new(&[], &[], &trusted_keys, 3),
        Err(Error::Invalid {
            what: "version branch attestation quorum",
            ..
        })
    ));
    let two_signature_policy =
        VersionBranchProtectionPolicy::new(&[], &[], &trusted_keys, 2).unwrap();
    let protected = repository
        .set_branch_protected("release", true, &two_signature_policy)
        .await
        .unwrap();
    assert_eq!(protected.trusted_attestation_keys(), trusted_keys);
    assert_eq!(protected.required_attestations(), 2);

    repository
        .create_branch("feature", &commit.id)
        .await
        .unwrap();
    live.write(&creds, file.ino, 0, b"new signed contents")
        .await
        .unwrap();
    assert!(matches!(
        repository
            .commit_paths_on_branch(
                live.as_ref(),
                "release",
                &["/signed.txt".to_string()],
                "unsigned direct publication".to_string(),
                test_provenance(),
            )
            .await,
        Err(Error::Invalid {
            what: "version branch attestation authorization",
            ..
        })
    ));
    let feature = repository
        .commit_paths_on_branch(
            live.as_ref(),
            "feature",
            &["/signed.txt".to_string()],
            "candidate release".to_string(),
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(matches!(
        repository
            .set_branch_protected("feature", true, &two_signature_policy)
            .await,
        Err(Error::Invalid {
            what: "version branch protection",
            ..
        })
    ));
    assert!(matches!(
        repository
            .merge_branch(
                "feature",
                "release",
                VersionMergeConflictStrategy::Fail,
                test_provenance(),
            )
            .await,
        Err(Error::Invalid {
            what: "version branch attestation authorization",
            ..
        })
    ));
    let feature_time = created_at + 2;
    let feature_payload = version_commit_attestation_payload(
        &repository_id,
        &feature.id,
        "release-2026",
        &public_key,
        feature_time,
    )
    .unwrap();
    repository
        .add_commit_attestation(
            &feature.id,
            VersionCommitAttestation::new_ed25519(
                "release-2026",
                public_key,
                signing_key.sign(&feature_payload).to_bytes(),
                feature_time,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        repository
            .merge_branch(
                "feature",
                "release",
                VersionMergeConflictStrategy::Fail,
                test_provenance(),
            )
            .await,
        Err(Error::Invalid {
            what: "version branch attestation authorization",
            ..
        })
    ));
    let pending_quorum = repository
        .attestation_quorum("release", "feature")
        .await
        .unwrap();
    assert_eq!(pending_quorum.commit(), feature.id);
    assert_eq!(pending_quorum.required_attestations(), 2);
    assert_eq!(
        pending_quorum.trusted_key_ids(),
        ["release-2026", "security-2026"]
    );
    assert_eq!(pending_quorum.matching_key_ids(), ["release-2026"]);
    assert!(!pending_quorum.satisfied());
    let security_feature_time = feature_time + 1;
    let security_feature_payload = version_commit_attestation_payload(
        &repository_id,
        &feature.id,
        "security-2026",
        &security_public_key,
        security_feature_time,
    )
    .unwrap();
    repository
        .add_commit_attestation(
            &feature.id,
            VersionCommitAttestation::new_ed25519(
                "security-2026",
                security_public_key,
                security_signing_key
                    .sign(&security_feature_payload)
                    .to_bytes(),
                security_feature_time,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let satisfied_quorum = repository
        .attestation_quorum("release", &feature.id)
        .await
        .unwrap();
    assert_eq!(
        satisfied_quorum.matching_key_ids(),
        ["release-2026", "security-2026"]
    );
    assert!(satisfied_quorum.satisfied());
    let promoted = repository
        .merge_branch(
            "feature",
            "release",
            VersionMergeConflictStrategy::Fail,
            test_provenance(),
        )
        .await
        .unwrap();
    assert!(promoted.fast_forward());
    assert_eq!(promoted.commit(), feature.id);
    repository
        .create_tag("release-candidate", &feature.id)
        .await
        .unwrap();
    let (bundle, exported) = repository.export_bundle().await.unwrap();
    assert!(bundle.starts_with(b"SLATEVCS"));
    assert_eq!(exported.identity, repository_identity);
    assert_eq!(exported.commits, 2);
    assert_eq!(exported.attestations, 4);
    assert_eq!(exported.branches, 3);
    assert_eq!(exported.tags, 1);
    assert!(exported.nodes > 0);
    assert!(exported.blobs > 0);
    assert_eq!(exported.bundle_bytes, bundle.len() as u64);

    repository.close().await.unwrap();
    let reopened = VersionRepository::open_with_identity(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        repository_identity.clone(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.identity().id(), repository_id);
    reopened.close().await.unwrap();
    volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "imported-copy",
        common::create_opts(None, None),
    )
    .await
    .unwrap();
    control
        .set_versioning_enabled("t", "imported-copy", true)
        .await
        .unwrap();
    let imported_report = VersionRepository::import_bundle(
        &control,
        Arc::clone(&object_store),
        "t",
        "imported-copy",
        &bundle,
    )
    .await
    .unwrap();
    assert_eq!(imported_report, exported);
    let imported =
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "imported-copy")
            .await
            .unwrap();
    assert_eq!(imported.identity().id(), repository_id);
    assert_eq!(
        imported
            .read_file(&feature.id, "/signed.txt")
            .await
            .unwrap()
            .as_ref(),
        b"new signed contents"
    );
    assert_eq!(
        imported
            .list_commit_attestations(&feature.id)
            .await
            .unwrap()
            .len(),
        2
    );
    let imported_branches = imported.list_branches().await.unwrap();
    assert_eq!(imported_branches.len(), 3);
    assert!(
        imported_branches
            .iter()
            .find(|branch| branch.name() == "release")
            .is_some_and(|branch| !branch.protected())
    );
    assert_eq!(imported.list_tags().await.unwrap().len(), 1);
    imported.verify().await.unwrap();
    imported.close().await.unwrap();
    assert!(matches!(
        VersionRepository::import_bundle(
            &control,
            Arc::clone(&object_store),
            "t",
            "imported-copy",
            &bundle,
        )
        .await,
        Err(Error::Invalid {
            what: "version repository bundle import",
            ..
        })
    ));

    volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "tampered-copy",
        common::create_opts(None, None),
    )
    .await
    .unwrap();
    control
        .set_versioning_enabled("t", "tampered-copy", true)
        .await
        .unwrap();
    let mut tampered_bundle = bundle.clone();
    *tampered_bundle.last_mut().unwrap() ^= 1;
    assert!(matches!(
        VersionRepository::import_bundle(
            &control,
            Arc::clone(&object_store),
            "t",
            "tampered-copy",
            &tampered_bundle,
        )
        .await,
        Err(Error::Invalid {
            what: "version repository bundle",
            ..
        })
    ));
    assert!(
        VersionRepository::open_existing(
            &control,
            Arc::clone(&object_store),
            "t",
            "tampered-copy",
        )
        .await
        .unwrap()
        .is_none()
    );
    let mismatched_identity = VersionRepositoryIdentity::from_parts(
        wrong_repository_id,
        repository_identity.created_at(),
    )
    .unwrap();
    assert!(matches!(
        VersionRepository::open_with_identity(
            &control,
            Arc::clone(&object_store),
            "t",
            "v",
            mismatched_identity,
        )
        .await,
        Err(Error::Invalid {
            what: "version repository identity",
            ..
        })
    ));
    live.shutdown().await.unwrap();
    control.close().await.unwrap();
}

#[tokio::test]
async fn native_sync_is_incremental_atomic_and_force_protected() {
    let object_store: Arc<dyn ObjectStore> = store::resolve_root("memory:///").unwrap();
    let control = ControlPlane::open(Arc::clone(&object_store), common::test_kms())
        .await
        .unwrap();
    control.create_tenant("t", None).await.unwrap();
    for volume_name in ["source", "destination"] {
        volume::create_volume(
            &control,
            Arc::clone(&object_store),
            "t",
            volume_name,
            common::create_opts(None, None),
        )
        .await
        .unwrap();
        control
            .set_versioning_enabled("t", volume_name, true)
            .await
            .unwrap();
    }
    let source_record = control.get_mountable_volume("t", "source").await.unwrap();
    let source_dek = control.unwrap_volume_dek(&source_record).await.unwrap();
    let source_live = Volume::open(&source_record, source_dek, Arc::clone(&object_store))
        .await
        .unwrap();
    let destination_record = control
        .get_mountable_volume("t", "destination")
        .await
        .unwrap();
    let destination_dek = control
        .unwrap_volume_dek(&destination_record)
        .await
        .unwrap();
    let destination_live = Volume::open(
        &destination_record,
        destination_dek,
        Arc::clone(&object_store),
    )
    .await
    .unwrap();
    let creds = Credentials::root();
    let source_file = source_live
        .create(&creds, ROOT_INO, b"sync.txt", 0o640, true)
        .await
        .unwrap();
    source_live
        .write(&creds, source_file.ino, 0, b"source-one")
        .await
        .unwrap();
    let source = VersionRepository::open(&control, Arc::clone(&object_store), "t", "source")
        .await
        .unwrap();
    let first = source
        .commit_file(
            source_live.as_ref(),
            "/sync.txt",
            "first sync commit".into(),
            test_provenance(),
        )
        .await
        .unwrap();
    let (initial_pack, initial_export) = source.export_sync_bundle("main", None).await.unwrap();
    assert!(initial_pack.starts_with(b"SLATESYN"));
    assert_eq!(initial_export.commits, 1);
    let initial_apply = VersionRepository::apply_sync_bundle(
        &control,
        Arc::clone(&object_store),
        "t",
        "destination",
        "main",
        &initial_pack,
        false,
    )
    .await
    .unwrap();
    assert!(initial_apply.fast_forward);
    assert!(initial_apply.updated);
    assert_eq!(initial_apply.target, first.id);

    source_live
        .write(&creds, source_file.ino, 0, b"source-two")
        .await
        .unwrap();
    let second = source
        .commit_file(
            source_live.as_ref(),
            "/sync.txt",
            "second sync commit".into(),
            test_provenance(),
        )
        .await
        .unwrap();
    let (incremental_pack, incremental_export) = source
        .export_sync_bundle("main", Some(&first.id))
        .await
        .unwrap();
    assert_eq!(incremental_export.commits, 1);
    assert!(incremental_pack.len() < initial_pack.len() * 2);
    VersionRepository::apply_sync_bundle(
        &control,
        Arc::clone(&object_store),
        "t",
        "destination",
        "main",
        &incremental_pack,
        false,
    )
    .await
    .unwrap();
    let destination =
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "destination")
            .await
            .unwrap();
    assert_eq!(destination.identity(), source.identity());
    assert_eq!(
        destination.sync_state("main").await.unwrap().head,
        Some(second.id.clone())
    );
    assert_eq!(
        destination
            .read_file(&second.id, "/sync.txt")
            .await
            .unwrap()
            .as_ref(),
        b"source-two"
    );
    assert_eq!(
        destination.reflog("main", 1).await.unwrap()[0].action(),
        VersionReflogAction::Sync
    );
    destination.close().await.unwrap();

    let destination_file = destination_live
        .create(&creds, ROOT_INO, b"sync.txt", 0o640, true)
        .await
        .unwrap();
    destination_live
        .write(&creds, destination_file.ino, 0, b"destination")
        .await
        .unwrap();
    let destination =
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "destination")
            .await
            .unwrap();
    let divergent = destination
        .commit_file(
            destination_live.as_ref(),
            "/sync.txt",
            "destination divergence".into(),
            test_provenance(),
        )
        .await
        .unwrap();
    destination.close().await.unwrap();

    source_live
        .write(&creds, source_file.ino, 0, b"source-three")
        .await
        .unwrap();
    let third = source
        .commit_file(
            source_live.as_ref(),
            "/sync.txt",
            "third sync commit".into(),
            test_provenance(),
        )
        .await
        .unwrap();
    let (divergent_pack, divergent_export) = source
        .export_sync_bundle("main", Some(&divergent.id))
        .await
        .unwrap();
    assert!(!divergent_export.fast_forward);
    assert!(matches!(
        VersionRepository::apply_sync_bundle(
            &control,
            Arc::clone(&object_store),
            "t",
            "destination",
            "main",
            &divergent_pack,
            false,
        )
        .await,
        Err(Error::Invalid {
            what: "version repository sync fast-forward",
            ..
        })
    ));
    let destination =
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "destination")
            .await
            .unwrap();
    destination
        .set_branch_protected("main", true, &VersionBranchProtectionPolicy::default())
        .await
        .unwrap();
    destination.close().await.unwrap();
    assert!(matches!(
        VersionRepository::apply_sync_bundle(
            &control,
            Arc::clone(&object_store),
            "t",
            "destination",
            "main",
            &divergent_pack,
            true,
        )
        .await,
        Err(Error::Invalid {
            what: "version repository sync force",
            ..
        })
    ));
    let destination =
        VersionRepository::open(&control, Arc::clone(&object_store), "t", "destination")
            .await
            .unwrap();
    destination
        .set_branch_protected("main", false, &VersionBranchProtectionPolicy::default())
        .await
        .unwrap();
    destination.close().await.unwrap();
    let forced = VersionRepository::apply_sync_bundle(
        &control,
        Arc::clone(&object_store),
        "t",
        "destination",
        "main",
        &divergent_pack,
        true,
    )
    .await
    .unwrap();
    assert!(forced.forced);
    assert_eq!(forced.target, third.id);
    assert!(matches!(
        VersionRepository::apply_sync_bundle(
            &control,
            Arc::clone(&object_store),
            "t",
            "destination",
            "main",
            &divergent_pack,
            true,
        )
        .await,
        Err(Error::Invalid {
            what: "version repository sync compare-and-swap",
            ..
        })
    ));

    source.close().await.unwrap();
    source_live.shutdown().await.unwrap();
    destination_live.shutdown().await.unwrap();
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
            VersionCommitProvenance::new(
                VersionCommitOrigin::Api,
                "test-author",
                "test-committer",
                "request-first",
            )
            .unwrap(),
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
            test_provenance(),
            "retry-1",
        )
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.commit().id, first_id);
    assert_eq!(replay.commit().provenance.request_id(), "request-first");
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 1);
    assert_eq!(
        repository
            .read_file(&first_id, "/notes.txt")
            .await
            .unwrap()
            .as_ref(),
        b"first contents"
    );

    let changed_author = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "save notes".into(),
            VersionCommitProvenance::new(
                VersionCommitOrigin::Api,
                "other-author",
                "test-committer",
                "request-author-conflict",
            )
            .unwrap(),
            "retry-1",
        )
        .await
        .unwrap_err();
    assert!(matches!(changed_author, Error::AlreadyExists { .. }));

    let conflict = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "different request".into(),
            test_provenance(),
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
            test_provenance(),
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
                    test_provenance(),
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
    let reflog = repository.reflog("main", 100).await.unwrap();
    assert_eq!(reflog.len(), 2);
    assert!(
        reflog
            .iter()
            .all(|entry| entry.action() == VersionReflogAction::Commit)
    );
    let gc = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(gc.deleted_commits, 0);
    let retained_retry = repository
        .commit_volume_paths_idempotent(
            live.as_ref(),
            &["/notes.txt".into()],
            "save notes".into(),
            test_provenance(),
            "retry-1",
        )
        .await
        .unwrap();
    assert!(retained_retry.replayed());
    assert_eq!(retained_retry.commit().id, first_id);

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
        .commit_file(
            live.as_ref(),
            "/large.bin",
            "large file".into(),
            test_provenance(),
        )
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
            test_provenance(),
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
            test_provenance(),
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
                .commit_volume_paths(
                    live.as_ref(),
                    &[path.to_string()],
                    message.to_string(),
                    test_provenance(),
                )
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
                .commit_volume_paths(
                    live.as_ref(),
                    &[path],
                    format!("retry {message}"),
                    test_provenance(),
                )
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
        .commit_paths(
            live.as_ref(),
            &["/docs".into()],
            "capture docs".into(),
            test_provenance(),
        )
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
            test_provenance(),
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
                .commit_file(
                    live.as_ref(),
                    "/history.txt",
                    format!("version {index}"),
                    test_provenance(),
                )
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
    assert_eq!(dry_run.deleted_commits, 0);
    assert_eq!(repository.history(None, 10).await.unwrap().len(), 3);

    let collected = repository
        .garbage_collect(Some(1), None, false)
        .await
        .unwrap();
    assert_eq!(collected.retained_commits, 3);
    assert_eq!(collected.deleted_commits, 0);
    let history = repository.history(None, 10).await.unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].id, commits[2].id);
    assert_eq!(repository.verify().await.unwrap().commits, 3);
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
    assert_eq!(still_branch_pinned.retained_commits, 3);
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
    assert_eq!(unpinned.retained_commits, 3);
    assert_eq!(unpinned.deleted_commits, 0);
    assert_eq!(
        repository
            .read_file(&commits[0].id, "/history.txt")
            .await
            .unwrap()
            .as_ref(),
        b"one"
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
            .commit_file(
                live.as_ref(),
                "/history.txt",
                "over quota".into(),
                test_provenance(),
            )
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
    assert_eq!(quota_repository.history(None, 10).await.unwrap().len(), 3);
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
