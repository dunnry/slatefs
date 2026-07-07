//! Wire tests for the vendored nfs3_server patch set: per-request AUTH_UNIX
//! credentials under squash policies, LINK, MKNOD, and quota-aware FSSTAT.

use std::sync::Arc;

use nfs3_client::Nfs3ConnectionBuilder;
use nfs3_client::nfs3_types::nfs3::{
    ACCESS3_MODIFY, ACCESS3_READ, ACCESS3args, ACCESS3res, CREATE3args, CREATE3res, FSSTAT3args,
    FSSTAT3res, GETATTR3args, GETATTR3res, LINK3args, LINK3res, LOOKUP3args, LOOKUP3res,
    MKNOD3args, MKNOD3res, Nfs3Option, READ3args, READ3res, SETATTR3args, SETATTR3res, WRITE3args,
    WRITE3res, createhow3, diropargs3, ftype3, mknoddata3, nfs_fh3, nfsstat3, sattr3, sattrguard3,
    stable_how,
};
use nfs3_client::nfs3_types::rpc::{auth_unix, opaque_auth};
use nfs3_client::nfs3_types::xdr_codec::Opaque;
use nfs3_client::tokio::TokioConnector;
use slatefs_core::config::{AtimeMode, Compression};
use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits};
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::meta::inode::{ROOT_INO, Timespec};
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::vfs::{Credentials, SetAttrs, TimeSet, Vfs};
use slatefs_core::volume::{self, CreateVolumeOptions, Volume};
use slatefs_nfs::{NFSTcp, SquashPolicy};

const TEST_CHUNK: u32 = 4096;

async fn make_volume(object_store: Arc<dyn ObjectStore>, quota_bytes: Option<u64>) -> Arc<Volume> {
    let kms: Arc<dyn Kms> = Arc::new(StaticKms::new(Secret32::from_bytes([9; 32])));
    let control = ControlPlane::open(Arc::clone(&object_store), kms)
        .await
        .expect("control");
    control.create_tenant("t", None).await.expect("tenant");
    let record = volume::create_volume(
        &control,
        Arc::clone(&object_store),
        "t",
        "v",
        CreateVolumeOptions {
            cipher: Cipher::Aes256Gcm,
            chunk_size: TEST_CHUNK,
            compression: Compression::Lz4,
            quota: QuotaLimits {
                bytes: QuotaLimit {
                    hard: quota_bytes,
                    ..Default::default()
                },
                inodes: QuotaLimit::default(),
            },
            note: None,
        },
    )
    .await
    .expect("create volume");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control");
    Volume::open(&record, dek, object_store)
        .await
        .expect("open volume")
}

async fn serve(volume: Arc<Volume>, policy: SquashPolicy) -> u16 {
    let listener =
        slatefs_nfs::bind_export(volume, Secret32::from_bytes([7; 32]), policy, "127.0.0.1:0")
            .await
            .expect("bind export");
    let port = listener.get_listen_port();
    tokio::spawn(async move {
        let _ = listener.handle_forever().await;
    });
    port
}

async fn serve_with_atime(volume: Arc<Volume>, policy: SquashPolicy, atime: AtimeMode) -> u16 {
    let listener = slatefs_nfs::bind_export_with_atime_policy(
        volume,
        Secret32::from_bytes([7; 32]),
        policy,
        atime,
        "127.0.0.1:0",
    )
    .await
    .expect("bind export");
    let port = listener.get_listen_port();
    tokio::spawn(async move {
        let _ = listener.handle_forever().await;
    });
    port
}

type Conn = nfs3_client::Nfs3Connection<nfs3_client::tokio::TokioIo<tokio::net::TcpStream>>;

/// Connect asserting an AUTH_UNIX identity.
async fn connect_as(port: u16, uid: u32, gid: u32) -> Conn {
    let auth = auth_unix {
        stamp: 0,
        machinename: Opaque::owned(b"testhost".to_vec()),
        uid,
        gid,
        gids: vec![gid],
    };
    Nfs3ConnectionBuilder::new(TokioConnector, "127.0.0.1", "/")
        .connect_from_privileged_port(false)
        .mount_port(port)
        .nfs3_port(port)
        .credential(opaque_auth::auth_unix(&auth))
        .mount()
        .await
        .expect("mount")
}

fn dirop<'a>(dir: &nfs_fh3, name: &'a str) -> diropargs3<'a> {
    diropargs3 {
        dir: nfs_fh3 {
            data: Opaque::owned(dir.data.to_vec()),
        },
        name: name.as_bytes().into(),
    }
}

fn clone_fh(fh: &nfs_fh3) -> nfs_fh3 {
    nfs_fh3 {
        data: Opaque::owned(fh.data.to_vec()),
    }
}

fn old_time() -> Timespec {
    Timespec { secs: 10, nanos: 0 }
}

async fn create_file(conn: &mut Conn, dir: &nfs_fh3, name: &str, mode: u32) -> nfs_fh3 {
    let res = conn
        .nfs3_client
        .create(&CREATE3args {
            where_: dirop(dir, name),
            how: createhow3::UNCHECKED(sattr3 {
                mode: Nfs3Option::Some(mode),
                ..Default::default()
            }),
        })
        .await
        .expect("create rpc");
    match res {
        CREATE3res::Ok(ok) => match ok.obj {
            Nfs3Option::Some(fh) => fh,
            Nfs3Option::None => panic!("create returned no fh"),
        },
        CREATE3res::Err((stat, _)) => panic!("create failed: {stat:?}"),
    }
}

#[tokio::test]
async fn nfs_noatime_export_does_not_update_atime_on_read() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let file = volume
        .create(
            &Credentials::root(),
            ROOT_INO,
            b"nfs-atime.txt",
            0o644,
            true,
        )
        .await
        .unwrap();
    volume
        .write(&Credentials::root(), file.ino, 0, b"payload")
        .await
        .unwrap();
    volume
        .setattr(
            &Credentials::root(),
            file.ino,
            SetAttrs {
                atime: Some(TimeSet::Time(old_time())),
                mtime: Some(TimeSet::Time(Timespec { secs: 20, nanos: 0 })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let before = volume
        .getattr(&Credentials::root(), file.ino)
        .await
        .unwrap();

    let port = serve_with_atime(
        Arc::clone(&volume),
        SquashPolicy::trust_as_root(),
        AtimeMode::Noatime,
    )
    .await;
    let mut conn = connect_as(port, 0, 0).await;
    let root = conn.root_nfs_fh3();
    let fh = match conn
        .nfs3_client
        .lookup(&LOOKUP3args {
            what: dirop(&root, "nfs-atime.txt"),
        })
        .await
        .expect("lookup rpc")
    {
        LOOKUP3res::Ok(ok) => ok.object,
        LOOKUP3res::Err((stat, _)) => panic!("lookup failed: {stat:?}"),
    };
    match conn
        .nfs3_client
        .read(&READ3args {
            file: clone_fh(&fh),
            offset: 0,
            count: 7,
        })
        .await
        .expect("read rpc")
    {
        READ3res::Ok(ok) => assert_eq!(ok.data.as_ref(), b"payload"),
        READ3res::Err((stat, _)) => panic!("read failed: {stat:?}"),
    }
    conn.unmount().await.expect("unmount");

    let after = volume
        .getattr(&Credentials::root(), file.ino)
        .await
        .unwrap();
    assert_eq!(after.atime, before.atime);
    assert_eq!(after.mtime, before.mtime);
}

#[tokio::test]
async fn per_request_credentials_enforced() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let port = serve(Arc::clone(&volume), SquashPolicy::no_squash()).await;

    // Alice (uid 1000) needs a writable root; bootstrap as root creds.
    let mut root_conn = connect_as(port, 0, 0).await;
    let root = root_conn.root_nfs_fh3();
    let res = root_conn
        .nfs3_client
        .setattr(&SETATTR3args {
            object: clone_fh(&root),
            new_attributes: sattr3 {
                mode: Nfs3Option::Some(0o777),
                ..Default::default()
            },
            guard: sattrguard3::default(),
        })
        .await
        .expect("setattr rpc");
    assert!(matches!(res, SETATTR3res::Ok(_)));

    // Alice creates a private file; ownership reflects her AUTH_UNIX uid.
    let mut alice = connect_as(port, 1000, 1000).await;
    let fh = create_file(&mut alice, &root, "secret.txt", 0o600).await;
    let res = alice
        .nfs3_client
        .getattr(&GETATTR3args {
            object: clone_fh(&fh),
        })
        .await
        .expect("getattr rpc");
    match res {
        GETATTR3res::Ok(ok) => {
            assert_eq!(ok.obj_attributes.uid, 1000, "file owner must be the caller");
            assert_eq!(ok.obj_attributes.mode, 0o600);
        }
        GETATTR3res::Err((stat, _)) => panic!("getattr failed: {stat:?}"),
    }
    let written = alice
        .nfs3_client
        .write(&WRITE3args {
            file: clone_fh(&fh),
            offset: 0,
            count: 6,
            stable: stable_how::UNSTABLE,
            data: Opaque::borrowed(b"hidden"),
        })
        .await
        .expect("write rpc");
    assert!(matches!(written, WRITE3res::Ok(_)));

    // Bob (uid 2000) is denied read and write on Alice's 0600 file.
    let mut bob = connect_as(port, 2000, 2000).await;
    let res = bob
        .nfs3_client
        .read(&READ3args {
            file: clone_fh(&fh),
            offset: 0,
            count: 6,
        })
        .await
        .expect("read rpc");
    assert!(
        matches!(res, READ3res::Err((nfsstat3::NFS3ERR_ACCES, _))),
        "bob read must be EACCES, got {res:?}"
    );
    let res = bob
        .nfs3_client
        .write(&WRITE3args {
            file: clone_fh(&fh),
            offset: 0,
            count: 1,
            stable: stable_how::UNSTABLE,
            data: Opaque::borrowed(b"x"),
        })
        .await
        .expect("write rpc");
    assert!(matches!(res, WRITE3res::Err((nfsstat3::NFS3ERR_ACCES, _))));

    // The ACCESS proc reflects the same policy per caller.
    let res = bob
        .nfs3_client
        .access(&ACCESS3args {
            object: clone_fh(&fh),
            access: ACCESS3_READ | ACCESS3_MODIFY,
        })
        .await
        .expect("access rpc");
    match res {
        ACCESS3res::Ok(ok) => assert_eq!(ok.access, 0, "bob must get no access bits"),
        ACCESS3res::Err((stat, _)) => panic!("access failed: {stat:?}"),
    }
    let res = alice
        .nfs3_client
        .access(&ACCESS3args {
            object: clone_fh(&fh),
            access: ACCESS3_READ | ACCESS3_MODIFY,
        })
        .await
        .expect("access rpc");
    match res {
        ACCESS3res::Ok(ok) => assert_eq!(ok.access, ACCESS3_READ | ACCESS3_MODIFY),
        ACCESS3res::Err((stat, _)) => panic!("access failed: {stat:?}"),
    }

    // Owner still reads fine.
    let res = alice
        .nfs3_client
        .read(&READ3args {
            file: clone_fh(&fh),
            offset: 0,
            count: 6,
        })
        .await
        .expect("read rpc");
    match res {
        READ3res::Ok(ok) => assert_eq!(ok.data.as_ref(), b"hidden"),
        READ3res::Err((stat, _)) => panic!("alice read failed: {stat:?}"),
    }

    alice.unmount().await.expect("unmount alice");
    bob.unmount().await.expect("unmount bob");
    root_conn.unmount().await.expect("unmount root");
}

#[tokio::test]
async fn root_squash_maps_root_to_anon() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let policy = SquashPolicy {
        mode: slatefs_core::config::SquashMode::RootSquash,
        anon_uid: 65534,
        anon_gid: 65534,
    };
    let port = serve(Arc::clone(&volume), policy).await;

    // Root's identity is squashed to nobody, so creating in the 0755
    // root directory (owned by real root) is denied.
    let mut conn = connect_as(port, 0, 0).await;
    let root = conn.root_nfs_fh3();
    let res = conn
        .nfs3_client
        .create(&CREATE3args {
            where_: dirop(&root, "f"),
            how: createhow3::UNCHECKED(sattr3::default()),
        })
        .await
        .expect("create rpc");
    assert!(
        matches!(res, CREATE3res::Err((nfsstat3::NFS3ERR_ACCES, _))),
        "squashed root must not write a 0755 root dir, got {res:?}"
    );
    conn.unmount().await.expect("unmount");
}

#[tokio::test]
async fn hardlink_over_the_wire() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let port = serve(Arc::clone(&volume), SquashPolicy::trust_as_root()).await;
    let mut conn = connect_as(port, 0, 0).await;
    let root = conn.root_nfs_fh3();

    let fh = create_file(&mut conn, &root, "original", 0o644).await;
    let written = conn
        .nfs3_client
        .write(&WRITE3args {
            file: clone_fh(&fh),
            offset: 0,
            count: 7,
            stable: stable_how::FILE_SYNC,
            data: Opaque::borrowed(b"payload"),
        })
        .await
        .expect("write rpc");
    assert!(matches!(written, WRITE3res::Ok(_)));

    let res = conn
        .nfs3_client
        .link(&LINK3args {
            file: clone_fh(&fh),
            link: dirop(&root, "alias"),
        })
        .await
        .expect("link rpc");
    match res {
        LINK3res::Ok(ok) => match ok.file_attributes {
            Nfs3Option::Some(attr) => assert_eq!(attr.nlink, 2, "nlink after LINK"),
            Nfs3Option::None => panic!("link returned no attrs"),
        },
        LINK3res::Err((stat, _)) => panic!("link failed: {stat:?}"),
    }

    // Content readable through the new name; same fileid.
    let res = conn
        .nfs3_client
        .lookup(&nfs3_client::nfs3_types::nfs3::LOOKUP3args {
            what: dirop(&root, "alias"),
        })
        .await
        .expect("lookup rpc");
    let alias_fh = match res {
        nfs3_client::nfs3_types::nfs3::LOOKUP3res::Ok(ok) => ok.object,
        nfs3_client::nfs3_types::nfs3::LOOKUP3res::Err((stat, _)) => {
            panic!("lookup failed: {stat:?}")
        }
    };
    assert_eq!(alias_fh.data.to_vec(), fh.data.to_vec(), "same handle");
    let res = conn
        .nfs3_client
        .read(&READ3args {
            file: clone_fh(&alias_fh),
            offset: 0,
            count: 7,
        })
        .await
        .expect("read rpc");
    match res {
        READ3res::Ok(ok) => assert_eq!(ok.data.as_ref(), b"payload"),
        READ3res::Err((stat, _)) => panic!("read via alias failed: {stat:?}"),
    }
    conn.unmount().await.expect("unmount");
}

#[tokio::test]
async fn mknod_fifo_over_the_wire() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let port = serve(Arc::clone(&volume), SquashPolicy::trust_as_root()).await;
    let mut conn = connect_as(port, 0, 0).await;
    let root = conn.root_nfs_fh3();

    let res = conn
        .nfs3_client
        .mknod(&MKNOD3args {
            where_: dirop(&root, "pipe"),
            what: mknoddata3::NF3FIFO(sattr3 {
                mode: Nfs3Option::Some(0o644),
                ..Default::default()
            }),
        })
        .await
        .expect("mknod rpc");
    match res {
        MKNOD3res::Ok(ok) => match ok.obj_attributes {
            Nfs3Option::Some(attr) => assert_eq!(attr.type_, ftype3::NF3FIFO),
            Nfs3Option::None => panic!("mknod returned no attrs"),
        },
        MKNOD3res::Err((stat, _)) => panic!("mknod failed: {stat:?}"),
    }
    conn.unmount().await.expect("unmount");
}

#[tokio::test]
async fn fsstat_reflects_quota() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let limit = TEST_CHUNK as u64 * 8;
    let volume = make_volume(Arc::clone(&object_store), Some(limit)).await;
    let port = serve(Arc::clone(&volume), SquashPolicy::trust_as_root()).await;
    let mut conn = connect_as(port, 0, 0).await;
    let root = conn.root_nfs_fh3();

    let fh = create_file(&mut conn, &root, "f", 0o644).await;
    let written = conn
        .nfs3_client
        .write(&WRITE3args {
            file: clone_fh(&fh),
            offset: 0,
            count: TEST_CHUNK * 2,
            stable: stable_how::UNSTABLE,
            data: Opaque::owned(vec![1u8; TEST_CHUNK as usize * 2]),
        })
        .await
        .expect("write rpc");
    assert!(matches!(written, WRITE3res::Ok(_)));

    let res = conn
        .nfs3_client
        .fsstat(&FSSTAT3args {
            fsroot: clone_fh(&root),
        })
        .await
        .expect("fsstat rpc");
    match res {
        FSSTAT3res::Ok(ok) => {
            assert_eq!(ok.tbytes, limit, "total bytes = quota hard limit");
            assert_eq!(
                ok.fbytes,
                limit - TEST_CHUNK as u64 * 2,
                "free reflects usage"
            );
            assert_eq!(ok.abytes, ok.fbytes);
        }
        FSSTAT3res::Err((stat, _)) => panic!("fsstat failed: {stat:?}"),
    }
    conn.unmount().await.expect("unmount");
}
