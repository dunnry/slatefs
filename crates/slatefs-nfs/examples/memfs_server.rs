//! Control experiment server: the vendored nfs3_server's own in-memory
//! filesystem, no SlateFS adapter — used to bisect client incompatibilities
//! (is it the library or our adapter?).

use nfs3_server::memfs::{MemFs, MemFsConfig};
use nfs3_server::tcp::{NFSTcp, NFSTcpListener};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MemFsConfig::default();
    config.add_dir("/dir");
    config.add_file("/a.txt", b"hello world\n".as_slice());
    config.add_file("/dir/b.txt", b"nested\n".as_slice());
    let fs = MemFs::new(config).expect("memfs");
    let listener = NFSTcpListener::bind("127.0.0.1:12051", fs).await?;
    eprintln!("memfs ready on 12051");
    listener.handle_forever().await?;
    Ok(())
}
