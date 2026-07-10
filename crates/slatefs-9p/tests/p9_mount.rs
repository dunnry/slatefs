//! In-process 9P2000.L wire tests (plan §14 Phase 4): a minimal synchronous
//! client built on rs9p's public codec talks to the real server over TCP —
//! attach auth, the full op surface, readdir offsets, xattr fids — plus the
//! cross-protocol AC: the same volume served over NFS and 9P
//! simultaneously stays byte- and attr-coherent.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rs9p::fcall::{Data, FCall, GetAttrMask, Msg, QId, SetAttr, SetAttrMask, Time};
use rs9p::serialize::{read_msg, write_msg};
use slatefs_core::config::{AtimeMode, ClientAddrRule, Compression};
use slatefs_core::control::{ControlPlane, QuotaLimit, QuotaLimits};
use slatefs_core::crypto::kms::{Kms, StaticKms};
use slatefs_core::crypto::{Cipher, Secret32};
use slatefs_core::meta::inode::{ROOT_INO, Timespec};
use slatefs_core::rate::{RateLimiter, RateLimits};
use slatefs_core::store::{self, ObjectStore};
use slatefs_core::vfs::{Credentials, SetAttrs, TimeSet, Vfs};
use slatefs_core::volume::{self, CreateVolumeOptions, Volume};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const TEST_CHUNK: u32 = 4096;
const NOFID: u32 = u32::MAX;
const NOTAG: u16 = u16::MAX;
const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUDi4/bO2zhKfbtePcokUXahFdD4YwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYxNTEyMjc0MVoXDTM2MDYx
MjEyMjc0MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAoSPJgW1sCx77KbsLaI8c0K3vj98ZGvy/dNeHl+MvxjXp
y+GN952MuOOi48RPYKWzgH+e1m9ultemyXcrkN5LEDNgD8ZDCJoRaKcdt15M9z/H
BG8+B07M81zEq8J2K9gAKypieeM8CCkl50c3JvjMhdWmISyTYN2kej4TwQ8YLCaX
+vkqPbG2c0A355EW3YhAq0gvrF8tevAucAY+wFGxdxbMGh7hMY+M0q2aJohx9HSh
Crf01H3ul13VQuYv3qqIPjSUZCw/JMfa0HIblQe7gGaoiHgqxO8IlDqNUi4ah233
VJ7rjU/qqmwuQjPPU3rytFHGj6WHOQgOEH7sRmNA0wIDAQABo4GSMIGPMB0GA1Ud
DgQWBBTId8SWbflEJZ09VaJZGuCqWBg6XTAfBgNVHSMEGDAWgBTId8SWbflEJZ09
VaJZGuCqWBg6XTAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAGc5jxfaoOwTq/PvYKScY/N10G9pd3hU2uS6suUGwFTvcjVb
ChUkebOikQoPYCpUOQ+QJ9XvSOKCGYauELj7/vDCr4t/wE78BaXIpHj8OLdDM1wx
+5wHfaZeCngocFiG/+VSrNpQerdpkaC9uIfZZdd/izv7eXAwuetzl1ihAQgPXEKs
iiMbxvmqMAsKb7AXb8saJfCh6HGVDee7nJgmkV5BpBcppopKYRviXoBjDj45ZINX
0Z7wlo/bKFpTFDPnDwj+KNjuPlAwzpp2FCAgQ3MbwYFQZ5etz3BOnkiOGGn0ZNWQ
eMQ0PEKynvcTBUI6pBIy958oQZFbggpY7yybRFU=
-----END CERTIFICATE-----
"#;
const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChI8mBbWwLHvsp
uwtojxzQre+P3xka/L9014eX4y/GNenL4Y33nYy446LjxE9gpbOAf57Wb26W16bJ
dyuQ3ksQM2APxkMImhFopx23Xkz3P8cEbz4HTszzXMSrwnYr2AArKmJ54zwIKSXn
Rzcm+MyF1aYhLJNg3aR6PhPBDxgsJpf6+So9sbZzQDfnkRbdiECrSC+sXy168C5w
Bj7AUbF3FswaHuExj4zSrZomiHH0dKEKt/TUfe6XXdVC5i/eqog+NJRkLD8kx9rQ
chuVB7uAZqiIeCrE7wiUOo1SLhqHbfdUnuuNT+qqbC5CM89TevK0UcaPpYc5CA4Q
fuxGY0DTAgMBAAECggEACdncu0dbuBBUTXhMWb+KBO3lO9fpOn+iGrwEY5I1fPoV
yWuIGM+uZy0va5o4OhHXN+9VYAme6qTTYvSgmrIkR6DEaiJ2PaPhlZLF28xtix4A
hjJgyeSU3fnZYiC4xbRmSj1EmOv94wfU898kLYM/SZ1Gkzec6OqT4A9EeOR511UJ
zUATwpOI8V47rEgeSWTMrHn975muxc5C6aLKkQ9S0GXYRwHhzUvJJ/WiaSlL4UhD
5bzQ/qbtwpf1QZDbEVP6WaBeApgQJTc78olQtNHB0hA6FMeL+AwRIcjrNYhdYHPa
OYZ1/7JuT5UUOzPOLnaUKKu7xfrX9fUsWfg/I3Zp8QKBgQDWw+IfqNAnC4hWYJgz
RZuba2Y+81f3akIcEVLayZh/nF9AP0j60LW/p1LukQm++ZpSiKAGpzTSLm0izNwu
oUQUfONPTXV7+dY0PyCZsrlS1tI8GvbY/pIVydxz9oLCrWPYNfB0nmvE9zNlBuUC
V5zwwB1tSaPft7oluDPBvBQfsQKBgQDAFB1Vnii9QcCyLeHhzbgutFrONoM95KdA
u7BHUNshtNktK47kOfbgk/9e9Byl2B2sd6H+wo1LNmJo8nASCGU6DNxc9NgiAPjL
7fuluJ3Kd4vJz8TwCieVamyal1f25qT2bQGfuIUiFs+f9/2o9hFngD1kwtojaZcc
4+6zlY0twwKBgBI/6PopvS5kM3yrjqNkudlWIgUdZo82r1F1Q2YmFVhasFlkR05Q
5/DWRhzRpFNfIHb89yQ5lyp5GXsIj3lC6OcYybQWb/JOA57C8oE9B7R7XrgOzoUX
9M/3LE2KWAg09bQMuVcfkybUnsBp+pHdYg+vM5Dy3gMHuMC1y2geFFOxAoGAK1Xe
cGyogFqPYSPc7Jb/UPo76n5+Cb7GxWITGWPyrJ4iyYAkUvWI7440dXXZ6MjjmP+8
ur+mJSv18/uOsWLXg8tXBFnxUWqqt0fQGMmYQA/MqBGKOyXvXFSQgChZHklXOonJ
bgGxd8lxuoO25SHvN0zFjTAxCwBNqaT7O+Un3wUCgYBw3HOZgIJx83D9EQpCKl5L
og4Pq1ova1Q6U+0nl1edh/3+oWXg2eehq756ScecFLAC0hQ9CnCHJRb0IDhTSaym
Y3F2QsxjXRiR/UKBJmP3vTqipLhx0Mm+pZh9TemEUHWZ4rmJJ/Q3+baYWCLZq90/
mScZZTOhGKziOp55PzWo9w==
-----END PRIVATE KEY-----
"#;

async fn make_volume(object_store: Arc<dyn ObjectStore>) -> Arc<Volume> {
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
                bytes: QuotaLimit::default(),
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

/// Reserve an ephemeral port (bind/drop) — rs9p's listener offers no port
/// introspection. The tiny race is acceptable in tests.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

async fn serve_9p(volume: Arc<Volume>, token: Option<String>) -> u16 {
    serve_9p_with_allowlist(volume, token, Vec::new()).await
}

async fn serve_9p_with_atime(volume: Arc<Volume>, token: Option<String>, atime: AtimeMode) -> u16 {
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = slatefs_9p::serve_export(
            volume,
            "/t/v".to_string(),
            &listen,
            slatefs_9p::P9ExportOptions {
                token,
                atime_policy: atime,
                ..slatefs_9p::P9ExportOptions::default()
            },
        )
        .await;
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return port;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("9p server never came up");
}

async fn serve_9p_with_allowlist(
    volume: Arc<Volume>,
    token: Option<String>,
    allowed_clients: Vec<ClientAddrRule>,
) -> u16 {
    serve_9p_with_allowlist_and_rate_limit(volume, token, allowed_clients, None).await
}

async fn serve_9p_with_rate_limit(
    volume: Arc<Volume>,
    token: Option<String>,
    limits: RateLimits,
) -> u16 {
    serve_9p_with_allowlist_and_rate_limit(
        volume,
        token,
        Vec::new(),
        Some(Arc::new(RateLimiter::new(limits))),
    )
    .await
}

async fn serve_9p_with_allowlist_and_rate_limit(
    volume: Arc<Volume>,
    token: Option<String>,
    allowed_clients: Vec<ClientAddrRule>,
    rate_limiter: Option<Arc<RateLimiter>>,
) -> u16 {
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = slatefs_9p::serve_export(
            volume,
            "/t/v".to_string(),
            &listen,
            slatefs_9p::P9ExportOptions {
                token,
                allowed_clients,
                rate_limiter,
                ..slatefs_9p::P9ExportOptions::default()
            },
        )
        .await;
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return port;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("9p server never came up");
}

async fn serve_9p_tls(volume: Arc<Volume>, token: Option<String>) -> (u16, tempfile::TempDir) {
    let cert_dir = tempfile::tempdir().expect("cert tempdir");
    let cert_path = cert_dir.path().join("localhost.crt");
    let key_path = cert_dir.path().join("localhost.key");
    std::fs::write(&cert_path, TEST_CERT).expect("write cert");
    std::fs::write(&key_path, TEST_KEY).expect("write key");

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = slatefs_9p::serve_export_tls(
            volume,
            "/t/v".to_string(),
            &listen,
            slatefs_9p::P9ExportOptions {
                token,
                ..slatefs_9p::P9ExportOptions::default()
            },
            slatefs_9p::TlsIdentity {
                cert_path,
                key_path,
            },
        )
        .await;
    });
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return (port, cert_dir);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("9p TLS server never came up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p9_source_allowlist_rejects_client() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let denied: ClientAddrRule = "192.0.2.0/24".parse().unwrap();
    let port = serve_9p_with_allowlist(Arc::clone(&volume), None, vec![denied]).await;

    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut payload = Vec::new();
        write_msg(
            &mut payload,
            &Msg {
                tag: NOTAG,
                body: FCall::TVersion {
                    msize: 1024 * 1024,
                    version: "9P2000.L".to_string(),
                },
            },
        )
        .expect("encode version");
        let size = (payload.len() as u32 + 4).to_le_bytes();
        let _ = stream.write_all(&size);
        let _ = stream.write_all(&payload);
        let mut size_buf = [0u8; 4];
        assert!(
            stream.read_exact(&mut size_buf).is_err(),
            "disallowed client unexpectedly received a 9P response"
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn byte_rate_limit_rejects_p9_write_payload() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let port = serve_9p_with_rate_limit(
        Arc::clone(&volume),
        None,
        RateLimits {
            ops_per_second: None,
            bytes_per_second: Some(1),
        },
    )
    .await;

    tokio::task::spawn_blocking(move || {
        let mut c = P9c::connect(port);
        c.attach(0, "", "/t/v", 0);
        c.lcreate(0, "limited.txt", 0o2, 0o644);
        let ecode = c.expect_errno(FCall::TWrite {
            fid: 0,
            offset: 0,
            data: Data(b"nope".to_vec()),
        });
        assert_eq!(ecode, rs9p::error::errno::EAGAIN as u32, "expected EAGAIN");
    })
    .await
    .unwrap();
}

fn tls_stream(port: u16) -> StreamOwned<ClientConnection, TcpStream> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(TEST_CERT.as_bytes()))
        .collect::<std::result::Result<_, _>>()
        .expect("parse test cert");
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).expect("trust test cert");
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("localhost").unwrap().to_owned();
    let conn = ClientConnection::new(Arc::new(config), server_name).expect("tls client");
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    StreamOwned::new(conn, stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p9_tls_end_to_end() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let (port, _cert_dir) = serve_9p_tls(Arc::clone(&volume), Some("sekrit".into())).await;

    tokio::task::spawn_blocking(move || {
        let mut c = P9c::from_stream(tls_stream(port));
        c.attach(0, "sekrit", "/t/v", 0);
        c.lcreate(0, "tls.txt", 0o2, 0o644);
        c.write(0, 0, b"hello over tls");
        assert_eq!(c.read(0, 0, 128), b"hello over tls");
        c.clunk(0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p9_strict_export_updates_atime_on_read() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let file = volume
        .create(&Credentials::root(), ROOT_INO, b"p9-atime.txt", 0o644, true)
        .await
        .unwrap();
    volume
        .write(&Credentials::root(), file.ino, 0, b"payload")
        .await
        .unwrap();
    let old = Timespec { secs: 10, nanos: 0 };
    volume
        .setattr(
            &Credentials::root(),
            file.ino,
            SetAttrs {
                atime: Some(TimeSet::Time(old)),
                mtime: Some(TimeSet::Time(old)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let port = serve_9p_with_atime(Arc::clone(&volume), None, AtimeMode::Strict).await;
    tokio::task::spawn_blocking(move || {
        let mut c = P9c::connect(port);
        c.attach(0, "", "/t/v", 0);
        c.walk(0, 1, &["p9-atime.txt"]);
        c.lopen(1, 0);
        assert_eq!(c.read(1, 0, 7), b"payload");
        c.clunk(1);
    })
    .await
    .unwrap();

    let after = volume
        .getattr(&Credentials::root(), file.ino)
        .await
        .unwrap()
        .atime;
    assert!(after > old, "strict 9P read should update atime");
}

/// Minimal synchronous 9P2000.L client.
struct P9c<S> {
    stream: S,
    tag: u16,
}

impl P9c<TcpStream> {
    fn connect(port: u16) -> P9c<TcpStream> {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        P9c::from_stream(stream)
    }
}

impl<S: Read + Write> P9c<S> {
    fn from_stream(stream: S) -> P9c<S> {
        let mut c = P9c { stream, tag: 0 };
        let reply = c.rpc_tagged(
            NOTAG,
            FCall::TVersion {
                msize: 1024 * 1024,
                version: "9P2000.L".to_string(),
            },
        );
        match reply {
            FCall::RVersion { version, .. } => assert_eq!(version, "9P2000.L"),
            other => panic!("bad version reply: {other:?}"),
        }
        c
    }

    fn rpc(&mut self, body: FCall) -> FCall {
        self.tag = self.tag.wrapping_add(1);
        self.rpc_tagged(self.tag, body)
    }

    fn rpc_tagged(&mut self, tag: u16, body: FCall) -> FCall {
        // rs9p's Msg codec covers type+tag+body only; the standard 9P
        // size[4] prefix (little-endian, includes itself) is framing we
        // add/strip here, mirroring the server's LengthDelimitedCodec.
        let mut payload = Vec::new();
        write_msg(&mut payload, &Msg { tag, body }).expect("encode msg");
        let size = (payload.len() as u32 + 4).to_le_bytes();
        self.stream.write_all(&size).expect("write size");
        self.stream.write_all(&payload).expect("write payload");
        self.stream.flush().expect("flush");

        let mut size_buf = [0u8; 4];
        self.stream.read_exact(&mut size_buf).expect("read size");
        let len = u32::from_le_bytes(size_buf) as usize - 4;
        let mut reply = vec![0u8; len];
        self.stream.read_exact(&mut reply).expect("read payload");
        let msg = read_msg(&mut std::io::Cursor::new(reply)).expect("decode msg");
        assert_eq!(msg.tag, tag, "tag mismatch");
        msg.body
    }

    fn expect_errno(&mut self, body: FCall) -> u32 {
        match self.rpc(body) {
            FCall::RlError { ecode } => ecode,
            other => panic!("expected Rlerror, got {other:?}"),
        }
    }

    fn attach(&mut self, fid: u32, uname: &str, aname: &str, uid: u32) -> QId {
        match self.rpc(FCall::TAttach {
            fid,
            afid: NOFID,
            uname: uname.to_string(),
            aname: aname.to_string(),
            n_uname: uid,
        }) {
            FCall::RAttach { qid } => qid,
            other => panic!("attach failed: {other:?}"),
        }
    }

    fn walk(&mut self, fid: u32, newfid: u32, names: &[&str]) -> Vec<QId> {
        match self.rpc(FCall::TWalk {
            fid,
            newfid,
            wnames: names.iter().map(|s| s.to_string()).collect(),
        }) {
            FCall::RWalk { wqids } => wqids,
            other => panic!("walk failed: {other:?}"),
        }
    }

    fn lopen(&mut self, fid: u32, flags: u32) {
        match self.rpc(FCall::TlOpen { fid, flags }) {
            FCall::RlOpen { .. } => {}
            other => panic!("lopen failed: {other:?}"),
        }
    }

    fn lcreate(&mut self, fid: u32, name: &str, flags: u32, mode: u32) {
        match self.rpc(FCall::TlCreate {
            fid,
            name: name.to_string(),
            flags,
            mode,
            gid: 0,
        }) {
            FCall::RlCreate { .. } => {}
            other => panic!("lcreate failed: {other:?}"),
        }
    }

    fn write(&mut self, fid: u32, offset: u64, data: &[u8]) -> u32 {
        match self.rpc(FCall::TWrite {
            fid,
            offset,
            data: Data(data.to_vec()),
        }) {
            FCall::RWrite { count } => count,
            other => panic!("write failed: {other:?}"),
        }
    }

    fn read(&mut self, fid: u32, offset: u64, count: u32) -> Vec<u8> {
        match self.rpc(FCall::TRead { fid, offset, count }) {
            FCall::RRead { data } => data.0,
            other => panic!("read failed: {other:?}"),
        }
    }

    fn getattr(&mut self, fid: u32) -> rs9p::fcall::Stat {
        match self.rpc(FCall::TGetAttr {
            fid,
            req_mask: GetAttrMask::all(),
        }) {
            FCall::RGetAttr { stat, .. } => stat,
            other => panic!("getattr failed: {other:?}"),
        }
    }

    fn clunk(&mut self, fid: u32) {
        match self.rpc(FCall::TClunk { fid }) {
            FCall::RClunk => {}
            other => panic!("clunk failed: {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p9_end_to_end() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let port = serve_9p(Arc::clone(&volume), Some("sekrit".into())).await;

    let volume_check = Arc::clone(&volume);
    tokio::task::spawn_blocking(move || {
        let mut c = P9c::connect(port);
        let root_qid = c.attach(0, "sekrit", "/t/v", 0);
        assert!(root_qid.typ.contains(rs9p::fcall::QIdType::DIR));

        // mkdir + create + write + read (multi-chunk).
        match c.rpc(FCall::TMkDir {
            dfid: 0,
            name: "dir".into(),
            mode: 0o755,
            gid: 0,
        }) {
            FCall::RMkDir { .. } => {}
            other => panic!("mkdir failed: {other:?}"),
        }
        c.walk(0, 1, &["dir"]);
        c.lcreate(1, "file.bin", 0o2 /* O_RDWR */, 0o644);
        let payload: Vec<u8> = (0..TEST_CHUNK as usize * 3)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut off = 0u64;
        for chunk in payload.chunks(64 * 1024) {
            let n = c.write(1, off, chunk);
            assert_eq!(n as usize, chunk.len());
            off += n as u64;
        }
        let stat = c.getattr(1);
        assert_eq!(stat.size, payload.len() as u64);
        assert_eq!(stat.mode & 0o170000, 0o100000, "regular file type bits");

        // Fresh walk for reading.
        c.walk(0, 2, &["dir", "file.bin"]);
        c.lopen(2, 0 /* O_RDONLY */);
        let mut got = Vec::new();
        while (got.len() as u64) < payload.len() as u64 {
            let part = c.read(2, got.len() as u64, 128 * 1024);
            if part.is_empty() {
                break;
            }
            got.extend_from_slice(&part);
        }
        assert_eq!(got, payload);

        // Truncate via setattr.
        match c.rpc(FCall::TSetAttr {
            fid: 2,
            valid: SetAttrMask::SIZE,
            stat: SetAttr {
                mode: 0,
                uid: 0,
                gid: 0,
                size: 100,
                atime: Time { sec: 0, nsec: 0 },
                mtime: Time { sec: 0, nsec: 0 },
            },
        }) {
            FCall::RSetAttr => {}
            other => panic!("setattr failed: {other:?}"),
        }
        assert_eq!(c.getattr(2).size, 100);

        // readdir with synthesized "." / ".." and small counts (pagination).
        for i in 0..10 {
            c.walk(0, 10, &["dir"]);
            c.lcreate(10, &format!("f{i:02}"), 0o2, 0o644);
            c.clunk(10);
        }
        c.walk(0, 3, &["dir"]);
        c.lopen(3, 0);
        let mut names = Vec::new();
        let mut offset = 0u64;
        loop {
            let data = match c.rpc(FCall::TReadDir {
                fid: 3,
                offset,
                count: 512, // small: forces several rounds
            }) {
                FCall::RReadDir { data } => data,
                other => panic!("readdir failed: {other:?}"),
            };
            if data.data.is_empty() {
                break;
            }
            for e in &data.data {
                names.push(e.name.clone());
                offset = e.offset;
            }
        }
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        for i in 0..10 {
            assert!(names.contains(&format!("f{i:02}")), "missing f{i:02}");
        }
        assert!(names.contains(&"file.bin".to_string()));

        // symlink + readlink.
        match c.rpc(FCall::TSymlink {
            fid: 0,
            name: "link".into(),
            symtgt: "dir/file.bin".into(),
            gid: 0,
        }) {
            FCall::RSymlink { qid } => {
                assert!(qid.typ.contains(rs9p::fcall::QIdType::SYMLINK))
            }
            other => panic!("symlink failed: {other:?}"),
        }
        c.walk(0, 4, &["link"]);
        match c.rpc(FCall::TReadLink { fid: 4 }) {
            FCall::RReadLink { target } => assert_eq!(target, "dir/file.bin"),
            other => panic!("readlink failed: {other:?}"),
        }

        // hardlink via Tlink, then unlinkat.
        c.walk(0, 5, &["dir", "file.bin"]);
        match c.rpc(FCall::TLink {
            dfid: 0,
            fid: 5,
            name: "hard".into(),
        }) {
            FCall::RLink => {}
            other => panic!("link failed: {other:?}"),
        }
        c.walk(0, 6, &["hard"]);
        assert_eq!(c.getattr(6).nlink, 2);

        // renameat + unlinkat.
        match c.rpc(FCall::TRenameAt {
            olddirfid: 0,
            oldname: "hard".into(),
            newdirfid: 0,
            newname: "renamed".into(),
        }) {
            FCall::RRenameAt => {}
            other => panic!("renameat failed: {other:?}"),
        }
        match c.rpc(FCall::TUnlinkAt {
            dirfd: 0,
            name: "renamed".into(),
            flags: 0,
        }) {
            FCall::RUnlinkAt => {}
            other => panic!("unlinkat failed: {other:?}"),
        }

        // xattr: create+write+clunk, then walk+read.
        c.walk(0, 7, &["dir", "file.bin"]);
        match c.rpc(FCall::TxAttrCreate {
            fid: 7,
            name: "user.color".into(),
            attr_size: 4,
            flags: 0,
        }) {
            FCall::RxAttrCreate => {}
            other => panic!("xattrcreate failed: {other:?}"),
        }
        assert_eq!(c.write(7, 0, b"blue"), 4);
        c.clunk(7);
        c.walk(0, 8, &["dir", "file.bin"]);
        match c.rpc(FCall::TxAttrWalk {
            fid: 8,
            newfid: 9,
            name: "user.color".into(),
        }) {
            FCall::RxAttrWalk { size } => assert_eq!(size, 4),
            other => panic!("xattrwalk failed: {other:?}"),
        }
        assert_eq!(c.read(9, 0, 100), b"blue");

        // statfs sanity.
        match c.rpc(FCall::TStatFs { fid: 0 }) {
            FCall::RStatFs { statfs } => {
                assert!(statfs.blocks > 0);
                assert_eq!(statfs.namelen, 255);
            }
            other => panic!("statfs failed: {other:?}"),
        }
    })
    .await
    .expect("client thread");

    let report = volume_check.fsck().await.expect("fsck");
    assert!(report.is_clean(), "{:?}", report.problems);
}

/// Sub-second timestamps survive a `Tsetattr` → `Tgetattr` round-trip on
/// the server (plan §10 nanosecond times). This isolates the server from
/// the Linux v9fs client, which truncates timestamps to `s_time_gran`
/// (1 s on many kernels) *before* sending `Tsetattr` — so pjdfstest's
/// `utimensat/08` sub-second check sees `0` over a kernel mount even though
/// the wire protocol and our server both carry full nanoseconds. See
/// docs/pjdfstest-exclusions.md.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p9_setattr_subsecond_time_roundtrip() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let port = serve_9p(Arc::clone(&volume), None).await;

    tokio::task::spawn_blocking(move || {
        let mut c = P9c::connect(port);
        c.attach(0, "", "/t/v", 0);
        c.walk(0, 1, &[]);
        c.lcreate(1, "ts.bin", 0o2 /* O_RDWR */, 0o644);

        // utimensat-style: explicit atime/mtime with sub-second nanos.
        match c.rpc(FCall::TSetAttr {
            fid: 1,
            valid: SetAttrMask::ATIME
                | SetAttrMask::ATIME_SET
                | SetAttrMask::MTIME
                | SetAttrMask::MTIME_SET,
            stat: SetAttr {
                mode: 0,
                uid: 0,
                gid: 0,
                size: 0,
                atime: Time {
                    sec: 100_000_000,
                    nsec: 100_000_000,
                },
                mtime: Time {
                    sec: 200_000_000,
                    nsec: 200_000_000,
                },
            },
        }) {
            FCall::RSetAttr => {}
            other => panic!("setattr failed: {other:?}"),
        }

        let stat = c.getattr(1);
        assert_eq!(stat.atime.sec, 100_000_000, "atime sec");
        assert_eq!(stat.atime.nsec, 100_000_000, "atime nsec (sub-second)");
        assert_eq!(stat.mtime.sec, 200_000_000, "mtime sec");
        assert_eq!(stat.mtime.nsec, 200_000_000, "mtime nsec (sub-second)");
    })
    .await
    .expect("client thread");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p9_attach_auth_enforced() {
    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;
    let port = serve_9p(volume, Some("sekrit".into())).await;

    tokio::task::spawn_blocking(move || {
        let mut c = P9c::connect(port);
        // Wrong token → EACCES.
        let ecode = c.expect_errno(FCall::TAttach {
            fid: 0,
            afid: NOFID,
            uname: "wrong".into(),
            aname: "/t/v".into(),
            n_uname: 0,
        });
        assert_eq!(ecode, 13, "expected EACCES");
        // Right token, wrong volume → ENOENT.
        let ecode = c.expect_errno(FCall::TAttach {
            fid: 0,
            afid: NOFID,
            uname: "sekrit".into(),
            aname: "/t/other".into(),
            n_uname: 0,
        });
        assert_eq!(ecode, 2, "expected ENOENT");
        // Correct attach works.
        c.attach(1, "sekrit", "/t/v", 0);
    })
    .await
    .expect("client thread");
}

/// Cross-protocol coherence (plan §14 Phase 4 AC): one volume served over
/// NFS and 9P at once; writes on one protocol are immediately visible —
/// byte-identical and attr-coherent — on the other (single Volume, single
/// writer, shared attr cache; plan §9.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_protocol_coherence() {
    use nfs3_client::Nfs3ConnectionBuilder;
    use nfs3_client::nfs3_types::nfs3::{
        CREATE3args, CREATE3res, LOOKUP3args, LOOKUP3res, Nfs3Option, READ3args, READ3res,
        WRITE3args, WRITE3res, createhow3, diropargs3, nfs_fh3, sattr3, stable_how,
    };
    use nfs3_client::nfs3_types::xdr_codec::Opaque;
    use nfs3_client::tokio::TokioConnector;

    let object_store = store::resolve_root("memory:///").unwrap();
    let volume = make_volume(Arc::clone(&object_store)).await;

    // Serve BOTH protocols from the same Volume.
    let p9_port = serve_9p(Arc::clone(&volume), None).await;
    let nfs_backend: Arc<dyn slatefs_core::vfs::Vfs> = volume.clone();
    let nfs_listener = slatefs_nfs::bind_export(
        nfs_backend,
        Secret32::from_bytes([7; 32]),
        slatefs_nfs::SquashPolicy::trust_as_root(),
        "127.0.0.1:0",
        slatefs_nfs::NfsExportOptions::default(),
    )
    .await
    .expect("bind nfs");
    let nfs_port = slatefs_nfs::NFSTcp::get_listen_port(&nfs_listener);
    tokio::spawn(async move {
        let _ = slatefs_nfs::NFSTcp::handle_forever(&nfs_listener).await;
    });

    // 1. Write via NFS.
    let nfs_payload = b"written over NFS, read over 9P".to_vec();
    let mut conn = Nfs3ConnectionBuilder::new(TokioConnector, "127.0.0.1", "/")
        .connect_from_privileged_port(false)
        .mount_port(nfs_port)
        .nfs3_port(nfs_port)
        .mount()
        .await
        .expect("nfs mount");
    let root = conn.root_nfs_fh3();
    let res = conn
        .nfs3_client
        .create(&CREATE3args {
            where_: diropargs3 {
                dir: nfs_fh3 {
                    data: Opaque::owned(root.data.to_vec()),
                },
                name: "from-nfs.txt".as_bytes().into(),
            },
            how: createhow3::UNCHECKED(sattr3::default()),
        })
        .await
        .expect("create rpc");
    let fh = match res {
        CREATE3res::Ok(ok) => match ok.obj {
            Nfs3Option::Some(fh) => fh,
            Nfs3Option::None => panic!("no fh"),
        },
        CREATE3res::Err((stat, _)) => panic!("create failed: {stat:?}"),
    };
    let res = conn
        .nfs3_client
        .write(&WRITE3args {
            file: nfs_fh3 {
                data: Opaque::owned(fh.data.to_vec()),
            },
            offset: 0,
            count: nfs_payload.len() as u32,
            stable: stable_how::FILE_SYNC,
            data: Opaque::borrowed(&nfs_payload),
        })
        .await
        .expect("write rpc");
    assert!(matches!(res, WRITE3res::Ok(_)));

    // 2. Read it via 9P and write the reply file via 9P.
    let p9_payload = b"written over 9P, read over NFS".to_vec();
    let nfs_payload_clone = nfs_payload.clone();
    let p9_payload_clone = p9_payload.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = P9c::connect(p9_port);
        c.attach(0, "", "/t/v", 0);
        c.walk(0, 1, &["from-nfs.txt"]);
        c.lopen(1, 0);
        let stat = c.getattr(1);
        assert_eq!(stat.size, nfs_payload_clone.len() as u64, "attr coherence");
        let got = c.read(1, 0, 4096);
        assert_eq!(got, nfs_payload_clone, "NFS write must be visible over 9P");

        c.walk(0, 2, &[]);
        c.lcreate(2, "from-9p.txt", 0o2, 0o644);
        assert_eq!(
            c.write(2, 0, &p9_payload_clone) as usize,
            p9_payload_clone.len()
        );
        c.clunk(2);
    })
    .await
    .expect("9p client");

    // 3. Read the 9P-written file via NFS.
    let res = conn
        .nfs3_client
        .lookup(&LOOKUP3args {
            what: diropargs3 {
                dir: nfs_fh3 {
                    data: Opaque::owned(root.data.to_vec()),
                },
                name: "from-9p.txt".as_bytes().into(),
            },
        })
        .await
        .expect("lookup rpc");
    let fh2 = match res {
        LOOKUP3res::Ok(ok) => {
            match ok.obj_attributes {
                Nfs3Option::Some(attr) => assert_eq!(
                    attr.size,
                    p9_payload.len() as u64,
                    "attr coherence NFS-side"
                ),
                Nfs3Option::None => panic!("lookup returned no attrs"),
            }
            ok.object
        }
        LOOKUP3res::Err((stat, _)) => panic!("lookup failed: {stat:?}"),
    };
    let res = conn
        .nfs3_client
        .read(&READ3args {
            file: nfs_fh3 {
                data: Opaque::owned(fh2.data.to_vec()),
            },
            offset: 0,
            count: 4096,
        })
        .await
        .expect("read rpc");
    match res {
        READ3res::Ok(ok) => assert_eq!(
            ok.data.as_ref(),
            &p9_payload[..],
            "9P write must be visible over NFS"
        ),
        READ3res::Err((stat, _)) => panic!("read failed: {stat:?}"),
    }
    conn.unmount().await.expect("unmount");

    let report = volume.fsck().await.expect("fsck");
    assert!(report.is_clean(), "{:?}", report.problems);
}
