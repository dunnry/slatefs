//! In-process NFSv3 integration tests (plan §14 Phase 2): a real RPC client
//! (`nfs3_client`) mounts the served volume over TCP — no root, no kernel
//! mount — and exercises the wire protocol end to end, including the DD-7
//! UNSTABLE/COMMIT durability mapping, readdir cookie pagination, and
//! restart-stable file handles.

use std::sync::Arc;

use nfs3_client::Nfs3ConnectionBuilder;
use nfs3_client::nfs3_types::nfs3::{
    COMMIT3args, COMMIT3res, CREATE3args, CREATE3res, GETATTR3args, GETATTR3res, LOOKUP3args,
    LOOKUP3res, MKDIR3args, MKDIR3res, Nfs3Option, READ3args, READ3res, READDIRPLUS3args,
    READDIRPLUS3res, READLINK3res, REMOVE3args, REMOVE3res, RENAME3args, RENAME3res, RMDIR3args,
    RMDIR3res, SETATTR3args, SETATTR3res, SYMLINK3args, SYMLINK3res, WRITE3args, WRITE3res,
    cookieverf3, createhow3, diropargs3, nfs_fh3, nfsstat3, sattr3, sattrguard3, stable_how,
    symlinkdata3,
};
use nfs3_client::nfs3_types::xdr_codec::Opaque;
use nfs3_client::tokio::TokioConnector;
use slatefs_core::config::Compression;
use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits};
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::volume::{self, CreateVolumeOptions, Volume};
use slatefs_nfs::{ExportIdentity, NFSTcp};

const TEST_CHUNK: u32 = 4096;

fn kms() -> Arc<dyn Kms> {
    Arc::new(StaticKms::new(Secret32::from_bytes([9; 32])))
}

fn fh_key() -> Secret32 {
    Secret32::from_bytes([7; 32])
}

async fn make_volume(object_store: Arc<dyn ObjectStore>, quota_bytes: Option<u64>) -> Arc<Volume> {
    let control = ControlPlane::open(Arc::clone(&object_store), kms())
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

async fn reopen_volume(object_store: Arc<dyn ObjectStore>) -> Arc<Volume> {
    let control = ControlPlane::open(Arc::clone(&object_store), kms())
        .await
        .expect("control");
    let record = control.get_volume("t", "v").await.expect("record");
    let dek = control.unwrap_volume_dek(&record).await.expect("dek");
    control.close().await.expect("close control");
    Volume::open(&record, dek, object_store)
        .await
        .expect("reopen volume")
}

/// Serve `volume` on an ephemeral port; returns (port, server task).
async fn serve(volume: Arc<Volume>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = slatefs_nfs::bind_export(volume, fh_key(), &ExportIdentity::Root, "127.0.0.1:0")
        .await
        .expect("bind export");
    let port = listener.get_listen_port();
    let task = tokio::spawn(async move {
        let _ = listener.handle_forever().await;
    });
    (port, task)
}

type Conn = nfs3_client::Nfs3Connection<nfs3_client::tokio::TokioIo<tokio::net::TcpStream>>;

async fn connect(port: u16) -> Conn {
    Nfs3ConnectionBuilder::new(TokioConnector, "127.0.0.1", "/")
        .connect_from_privileged_port(false)
        .mount_port(port)
        .nfs3_port(port)
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

async fn create_file(conn: &mut Conn, dir: &nfs_fh3, name: &str) -> nfs_fh3 {
    let res = conn
        .nfs3_client
        .create(&CREATE3args {
            where_: dirop(dir, name),
            how: createhow3::UNCHECKED(sattr3::default()),
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

async fn write_all(
    conn: &mut Conn,
    fh: &nfs_fh3,
    offset: u64,
    data: &[u8],
    stable: stable_how,
) -> stable_how {
    let res = conn
        .nfs3_client
        .write(&WRITE3args {
            file: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
            offset,
            count: data.len() as u32,
            stable,
            data: Opaque::borrowed(data),
        })
        .await
        .expect("write rpc");
    match res {
        WRITE3res::Ok(ok) => {
            assert_eq!(ok.count as usize, data.len(), "short write");
            ok.committed
        }
        WRITE3res::Err((stat, _)) => panic!("write failed: {stat:?}"),
    }
}

async fn read_range(conn: &mut Conn, fh: &nfs_fh3, offset: u64, count: u32) -> (Vec<u8>, bool) {
    let res = conn
        .nfs3_client
        .read(&READ3args {
            file: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
            offset,
            count,
        })
        .await
        .expect("read rpc");
    match res {
        READ3res::Ok(ok) => (ok.data.to_vec(), ok.eof),
        READ3res::Err((stat, _)) => panic!("read failed: {stat:?}"),
    }
}

async fn getattr_size(conn: &mut Conn, fh: &nfs_fh3) -> u64 {
    let res = conn
        .nfs3_client
        .getattr(&GETATTR3args {
            object: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
        })
        .await
        .expect("getattr rpc");
    match res {
        GETATTR3res::Ok(ok) => ok.obj_attributes.size,
        GETATTR3res::Err((stat, _)) => panic!("getattr failed: {stat:?}"),
    }
}

#[tokio::test]
async fn nfs_end_to_end() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let (port, _server) = serve(Arc::clone(&volume)).await;
    let mut conn = connect(port).await;
    let root = conn.root_nfs_fh3();

    // CREATE + multi-chunk UNSTABLE WRITE + COMMIT (DD-7).
    let fh = create_file(&mut conn, &root, "hello.txt").await;
    let data: Vec<u8> = (0..25 * TEST_CHUNK as usize)
        .map(|i| (i % 239) as u8)
        .collect();
    let committed = write_all(&mut conn, &fh, 0, &data, stable_how::UNSTABLE).await;
    assert_eq!(
        committed,
        stable_how::UNSTABLE,
        "UNSTABLE must not force a flush"
    );
    let res = conn
        .nfs3_client
        .commit(&COMMIT3args {
            file: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
            offset: 0,
            count: 0,
        })
        .await
        .expect("commit rpc");
    assert!(matches!(res, COMMIT3res::Ok(_)), "commit failed");

    // FILE_SYNC write reports FILE_SYNC.
    let committed = write_all(&mut conn, &fh, 0, &data[..100], stable_how::FILE_SYNC).await;
    assert_eq!(committed, stable_how::FILE_SYNC);

    // READ back, including an unaligned slice.
    let (full, eof) = read_range(&mut conn, &fh, 0, data.len() as u32 + 50).await;
    assert!(eof);
    assert_eq!(full.len(), data.len());
    assert_eq!(&full[..100], &data[..100]);
    assert_eq!(&full[100..], &data[100..]);
    let (slice, _) = read_range(&mut conn, &fh, 5000, 3000).await;
    assert_eq!(&slice[..], &data[5000..8000]);

    // SETATTR truncate.
    let res = conn
        .nfs3_client
        .setattr(&SETATTR3args {
            object: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
            new_attributes: sattr3 {
                size: Nfs3Option::Some(1000),
                ..Default::default()
            },
            guard: sattrguard3::default(),
        })
        .await
        .expect("setattr rpc");
    assert!(matches!(res, SETATTR3res::Ok(_)));
    assert_eq!(getattr_size(&mut conn, &fh).await, 1000);

    // MKDIR + RENAME into it + LOOKUP.
    let res = conn
        .nfs3_client
        .mkdir(&MKDIR3args {
            where_: dirop(&root, "dir"),
            attributes: sattr3::default(),
        })
        .await
        .expect("mkdir rpc");
    let dir_fh = match res {
        MKDIR3res::Ok(ok) => match ok.obj {
            Nfs3Option::Some(fh) => fh,
            Nfs3Option::None => panic!("mkdir returned no fh"),
        },
        MKDIR3res::Err((stat, _)) => panic!("mkdir failed: {stat:?}"),
    };
    let res = conn
        .nfs3_client
        .rename(&RENAME3args {
            from: dirop(&root, "hello.txt"),
            to: dirop(&dir_fh, "renamed.txt"),
        })
        .await
        .expect("rename rpc");
    assert!(matches!(res, RENAME3res::Ok(_)));
    let res = conn
        .nfs3_client
        .lookup(&LOOKUP3args {
            what: dirop(&dir_fh, "renamed.txt"),
        })
        .await
        .expect("lookup rpc");
    match res {
        LOOKUP3res::Ok(ok) => assert_eq!(ok.object.data.to_vec(), fh.data.to_vec()),
        LOOKUP3res::Err((stat, _)) => panic!("lookup failed: {stat:?}"),
    }
    // Lookup of the old name is gone.
    let res = conn
        .nfs3_client
        .lookup(&LOOKUP3args {
            what: dirop(&root, "hello.txt"),
        })
        .await
        .expect("lookup rpc");
    assert!(matches!(res, LOOKUP3res::Err((nfsstat3::NFS3ERR_NOENT, _))));

    // SYMLINK + READLINK.
    let res = conn
        .nfs3_client
        .symlink(&SYMLINK3args {
            where_: dirop(&root, "link"),
            symlink: symlinkdata3 {
                symlink_attributes: sattr3::default(),
                symlink_data: b"dir/renamed.txt".as_slice().into(),
            },
        })
        .await
        .expect("symlink rpc");
    let link_fh = match res {
        SYMLINK3res::Ok(ok) => match ok.obj {
            Nfs3Option::Some(fh) => fh,
            Nfs3Option::None => panic!("symlink returned no fh"),
        },
        SYMLINK3res::Err((stat, _)) => panic!("symlink failed: {stat:?}"),
    };
    let res = conn
        .nfs3_client
        .readlink(&nfs3_client::nfs3_types::nfs3::READLINK3args {
            symlink: nfs_fh3 {
                data: Opaque::owned(link_fh.data.to_vec()),
            },
        })
        .await
        .expect("readlink rpc");
    match res {
        READLINK3res::Ok(ok) => assert_eq!(ok.data.0.as_ref(), b"dir/renamed.txt"),
        READLINK3res::Err((stat, _)) => panic!("readlink failed: {stat:?}"),
    }

    // REMOVE file, RMDIR directory (must be empty first).
    let res = conn
        .nfs3_client
        .remove(&REMOVE3args {
            object: dirop(&dir_fh, "renamed.txt"),
        })
        .await
        .expect("remove rpc");
    assert!(matches!(res, REMOVE3res::Ok(_)));
    let res = conn
        .nfs3_client
        .rmdir(&RMDIR3args {
            object: dirop(&root, "dir"),
        })
        .await
        .expect("rmdir rpc");
    assert!(matches!(res, RMDIR3res::Ok(_)));

    conn.unmount().await.expect("unmount");

    // The volume is intact underneath.
    let report = volume.fsck().await.expect("fsck");
    assert!(report.is_clean(), "{:?}", report.problems);
}

#[tokio::test]
async fn readdirplus_cookie_pagination() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let (port, _server) = serve(Arc::clone(&volume)).await;
    let mut conn = connect(port).await;
    let root = conn.root_nfs_fh3();

    for i in 0..40 {
        create_file(&mut conn, &root, &format!("f{i:02}")).await;
    }

    // Paginate with a small maxcount to force multiple READDIRPLUS calls,
    // resuming from returned cookies (plan §5: cookies are dirent ids).
    let mut names = Vec::new();
    let mut cookie = 0;
    let mut cookieverf = cookieverf3::default();
    loop {
        let res = conn
            .nfs3_client
            .readdirplus(&READDIRPLUS3args {
                dir: nfs_fh3 {
                    data: Opaque::owned(root.data.to_vec()),
                },
                cookie,
                cookieverf,
                dircount: 1024,
                maxcount: 2048,
            })
            .await
            .expect("readdirplus rpc");
        match res {
            READDIRPLUS3res::Ok(ok) => {
                for entry in &ok.reply.entries.0 {
                    names.push(String::from_utf8_lossy(&entry.name.0).to_string());
                    cookie = entry.cookie;
                }
                cookieverf = ok.cookieverf;
                if ok.reply.eof {
                    break;
                }
            }
            READDIRPLUS3res::Err((stat, _)) => panic!("readdirplus failed: {stat:?}"),
        }
    }
    let mut expected: Vec<String> = (0..40).map(|i| format!("f{i:02}")).collect();
    names.sort();
    expected.sort();
    assert_eq!(names, expected);
    conn.unmount().await.expect("unmount");
}

#[tokio::test]
async fn file_handles_survive_restart() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let (port, server) = serve(Arc::clone(&volume)).await;
    let mut conn = connect(port).await;
    let root = conn.root_nfs_fh3();

    let fh = create_file(&mut conn, &root, "persistent.txt").await;
    write_all(&mut conn, &fh, 0, b"survive me", stable_how::FILE_SYNC).await;
    let saved_fh = fh.data.to_vec();
    conn.unmount().await.expect("unmount");

    // "Restart": stop the server, close the volume, reopen everything.
    server.abort();
    volume.shutdown().await.expect("shutdown");
    let volume = reopen_volume(Arc::clone(&object_store)).await;
    let (port, _server) = serve(Arc::clone(&volume)).await;
    let mut conn = connect(port).await;

    // The handle saved before the restart still resolves (generation is the
    // volume fsid, HMAC key from the control plane — plan §5).
    let revived = nfs_fh3 {
        data: Opaque::owned(saved_fh),
    };
    assert_eq!(getattr_size(&mut conn, &revived).await, 10);
    let (data, eof) = read_range(&mut conn, &revived, 0, 100).await;
    assert!(eof);
    assert_eq!(&data[..], b"survive me");
    conn.unmount().await.expect("unmount");
}

#[tokio::test]
async fn quota_surfaces_as_dquot() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), Some(TEST_CHUNK as u64 * 2)).await;
    let (port, _server) = serve(Arc::clone(&volume)).await;
    let mut conn = connect(port).await;
    let root = conn.root_nfs_fh3();

    let fh = create_file(&mut conn, &root, "big").await;
    // Exactly two chunks fit.
    write_all(
        &mut conn,
        &fh,
        0,
        &vec![1u8; TEST_CHUNK as usize * 2],
        stable_how::UNSTABLE,
    )
    .await;
    // One byte more must be NFS3ERR_DQUOT on the wire.
    let res = conn
        .nfs3_client
        .write(&WRITE3args {
            file: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
            offset: TEST_CHUNK as u64 * 2,
            count: 1,
            stable: stable_how::UNSTABLE,
            data: Opaque::borrowed(&[1u8]),
        })
        .await
        .expect("write rpc");
    assert!(
        matches!(res, WRITE3res::Err((nfsstat3::NFS3ERR_DQUOT, _))),
        "expected DQUOT, got {res:?}"
    );
    conn.unmount().await.expect("unmount");
}

#[tokio::test]
async fn forged_handles_rejected() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store), None).await;
    let (port, _server) = serve(Arc::clone(&volume)).await;
    let mut conn = connect(port).await;
    let root = conn.root_nfs_fh3();

    // Flip a bit inside the opaque handle (past the server's 8-byte
    // generation prefix): HMAC verification must reject it.
    let mut forged = root.data.to_vec();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let res = conn
        .nfs3_client
        .getattr(&GETATTR3args {
            object: nfs_fh3 {
                data: Opaque::owned(forged),
            },
        })
        .await
        .expect("getattr rpc");
    assert!(
        matches!(
            res,
            GETATTR3res::Err((nfsstat3::NFS3ERR_BADHANDLE | nfsstat3::NFS3ERR_STALE, _))
        ),
        "forged handle accepted: {res:?}"
    );
    conn.unmount().await.expect("unmount");
}
