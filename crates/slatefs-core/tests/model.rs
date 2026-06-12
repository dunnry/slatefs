//! Model-based property test (plan §14 Phase 1): random operation sequences
//! run against both the real `Vfs` (memory:// object store) and an in-memory
//! reference filesystem; every result — including errno — must match, and
//! the volume must pass fsck afterwards.
//!
//! Scale knobs: `PROPTEST_CASES` (proptest built-in; CI nightly runs
//! thousands) and op-sequence length below.

mod common;

use std::collections::{BTreeMap, HashMap};

use proptest::prelude::*;
use slatefs_core::meta::inode::{FileKind, ROOT_INO};
use slatefs_core::vfs::{Credentials, FsError, SetAttrs, Vfs};
use slatefs_core::volume::Volume;

const NAMES: [&[u8]; 8] = [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"];
const CHUNK: u64 = common::TEST_CHUNK as u64;

#[derive(Debug, Clone)]
enum Op {
    Create {
        dir: usize,
        name: usize,
        excl: bool,
    },
    Mkdir {
        dir: usize,
        name: usize,
    },
    Symlink {
        dir: usize,
        name: usize,
    },
    Link {
        sdir: usize,
        sname: usize,
        ddir: usize,
        dname: usize,
    },
    Write {
        dir: usize,
        name: usize,
        offset: u64,
        len: usize,
    },
    Truncate {
        dir: usize,
        name: usize,
        size: u64,
    },
    Read {
        dir: usize,
        name: usize,
        offset: u64,
        len: u32,
    },
    Unlink {
        dir: usize,
        name: usize,
    },
    Rmdir {
        dir: usize,
        name: usize,
    },
    Rename {
        sdir: usize,
        sname: usize,
        ddir: usize,
        dname: usize,
    },
    Readdir {
        dir: usize,
    },
    Getattr {
        dir: usize,
        name: usize,
    },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let d = 0..6usize; // dir selector (mod live-dir count at execution)
    let n = 0..NAMES.len();
    prop_oneof![
        (d.clone(), n.clone(), any::<bool>()).prop_map(|(dir, name, excl)| Op::Create {
            dir,
            name,
            excl
        }),
        (d.clone(), n.clone()).prop_map(|(dir, name)| Op::Mkdir { dir, name }),
        (d.clone(), n.clone()).prop_map(|(dir, name)| Op::Symlink { dir, name }),
        (d.clone(), n.clone(), d.clone(), n.clone()).prop_map(|(sdir, sname, ddir, dname)| {
            Op::Link {
                sdir,
                sname,
                ddir,
                dname,
            }
        }),
        (
            d.clone(),
            n.clone(),
            0..3 * CHUNK,
            0..(5 * CHUNK / 2) as usize
        )
            .prop_map(|(dir, name, offset, len)| Op::Write {
                dir,
                name,
                offset,
                len
            }),
        (d.clone(), n.clone(), 0..4 * CHUNK).prop_map(|(dir, name, size)| Op::Truncate {
            dir,
            name,
            size
        }),
        (d.clone(), n.clone(), 0..4 * CHUNK, 0..2 * CHUNK as u32).prop_map(
            |(dir, name, offset, len)| Op::Read {
                dir,
                name,
                offset,
                len
            }
        ),
        (d.clone(), n.clone()).prop_map(|(dir, name)| Op::Unlink { dir, name }),
        (d.clone(), n.clone()).prop_map(|(dir, name)| Op::Rmdir { dir, name }),
        (d.clone(), n.clone(), d.clone(), n.clone()).prop_map(|(sdir, sname, ddir, dname)| {
            Op::Rename {
                sdir,
                sname,
                ddir,
                dname,
            }
        }),
        d.clone().prop_map(|dir| Op::Readdir { dir }),
        (d, n).prop_map(|(dir, name)| Op::Getattr { dir, name }),
    ]
}

// ---- reference filesystem ----

#[derive(Debug, Clone)]
struct MNode {
    kind: FileKind,
    data: Vec<u8>, // files: logical content (zeros in holes); len == size
    nlink: u32,
    parent: u64,                     // dirs only
    entries: BTreeMap<Vec<u8>, u64>, // dirs only
    symlink_size: u64,               // symlinks only
}

impl MNode {
    fn dir(parent: u64) -> MNode {
        MNode {
            kind: FileKind::Dir,
            data: Vec::new(),
            nlink: 2,
            parent,
            entries: BTreeMap::new(),
            symlink_size: 0,
        }
    }
    fn file() -> MNode {
        MNode {
            kind: FileKind::File,
            data: Vec::new(),
            nlink: 1,
            parent: 0,
            entries: BTreeMap::new(),
            symlink_size: 0,
        }
    }
    fn symlink(target_len: u64) -> MNode {
        MNode {
            kind: FileKind::Symlink,
            data: Vec::new(),
            nlink: 1,
            parent: 0,
            entries: BTreeMap::new(),
            symlink_size: target_len,
        }
    }
    fn size(&self) -> u64 {
        match self.kind {
            FileKind::File => self.data.len() as u64,
            FileKind::Symlink => self.symlink_size,
            _ => 0,
        }
    }
}

/// Reference FS keyed by the *real* volume's inode numbers, so ino-addressed
/// results can be compared directly.
struct Model {
    nodes: HashMap<u64, MNode>,
}

impl Model {
    fn new() -> Model {
        Model {
            nodes: HashMap::from([(ROOT_INO, MNode::dir(ROOT_INO))]),
        }
    }

    /// Live directories in deterministic order — the op selector space.
    fn dirs(&self) -> Vec<u64> {
        let mut d: Vec<u64> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.kind.is_dir())
            .map(|(i, _)| *i)
            .collect();
        d.sort_unstable();
        d
    }

    fn entry(&self, dir: u64, name: &[u8]) -> Option<u64> {
        self.nodes
            .get(&dir)
            .and_then(|d| d.entries.get(name))
            .copied()
    }

    fn unlink_entry(&mut self, dir: u64, name: &[u8]) {
        let ino = self
            .nodes
            .get_mut(&dir)
            .unwrap()
            .entries
            .remove(name)
            .unwrap();
        let node = self.nodes.get_mut(&ino).unwrap();
        node.nlink -= 1;
        if node.nlink == 0 {
            self.nodes.remove(&ino);
        }
    }

    /// Is `anc` an ancestor of (or equal to) dir `ino`?
    fn is_ancestor(&self, anc: u64, mut ino: u64) -> bool {
        loop {
            if ino == anc {
                return true;
            }
            if ino == ROOT_INO {
                return false;
            }
            ino = self.nodes[&ino].parent;
        }
    }
}

// ---- driver: execute one op on both, compare ----

async fn run_op(v: &Volume, m: &mut Model, creds: &Credentials, op: &Op) -> Result<(), String> {
    let dirs = m.dirs();
    let pick_dir = |sel: usize| dirs[sel % dirs.len()];

    match op {
        Op::Create { dir, name, excl } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let real = v.create(creds, dir, name, 0o644, *excl).await;
            let model = match m.entry(dir, name) {
                Some(ino) => {
                    if *excl {
                        Err(FsError::Exists)
                    } else if m.nodes[&ino].kind.is_dir() {
                        Err(FsError::IsDir)
                    } else {
                        Ok(ino)
                    }
                }
                None => Ok(0), // new ino learned from the real result
            };
            match (real, model) {
                (Ok(attr), Ok(0)) => {
                    m.nodes.insert(attr.ino, MNode::file());
                    m.nodes
                        .get_mut(&dir)
                        .unwrap()
                        .entries
                        .insert(name.to_vec(), attr.ino);
                    Ok(())
                }
                (Ok(attr), Ok(ino)) if attr.ino == ino => Ok(()),
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("create {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Mkdir { dir, name } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let real = v.mkdir(creds, dir, name, 0o755).await;
            let exists = m.entry(dir, name).is_some();
            match (real, exists) {
                (Ok(attr), false) => {
                    m.nodes.insert(attr.ino, MNode::dir(dir));
                    let d = m.nodes.get_mut(&dir).unwrap();
                    d.entries.insert(name.to_vec(), attr.ino);
                    d.nlink += 1;
                    Ok(())
                }
                (Err(FsError::Exists), true) => Ok(()),
                (r, e) => Err(format!("mkdir {op:?}: real {r:?} vs exists={e}")),
            }
        }
        Op::Symlink { dir, name } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let real = v.symlink(creds, dir, name, b"/some/target").await;
            let exists = m.entry(dir, name).is_some();
            match (real, exists) {
                (Ok(attr), false) => {
                    m.nodes.insert(attr.ino, MNode::symlink(12));
                    m.nodes
                        .get_mut(&dir)
                        .unwrap()
                        .entries
                        .insert(name.to_vec(), attr.ino);
                    Ok(())
                }
                (Err(FsError::Exists), true) => Ok(()),
                (r, e) => Err(format!("symlink {op:?}: real {r:?} vs exists={e}")),
            }
        }
        Op::Link {
            sdir,
            sname,
            ddir,
            dname,
        } => {
            let (sdir, sname) = (pick_dir(*sdir), NAMES[*sname]);
            let (ddir, dname) = (pick_dir(*ddir), NAMES[*dname]);
            let Some(src_ino) = m.entry(sdir, sname) else {
                // Driver can't address a nonexistent source by ino; skip.
                return Ok(());
            };
            let real = v.link(creds, src_ino, ddir, dname).await;
            let model = if m.nodes[&src_ino].kind.is_dir() {
                Err(FsError::NotPermitted)
            } else if m.entry(ddir, dname).is_some() {
                Err(FsError::Exists)
            } else {
                Ok(())
            };
            match (real, model) {
                (Ok(attr), Ok(())) => {
                    m.nodes.get_mut(&src_ino).unwrap().nlink += 1;
                    m.nodes
                        .get_mut(&ddir)
                        .unwrap()
                        .entries
                        .insert(dname.to_vec(), src_ino);
                    if attr.nlink != m.nodes[&src_ino].nlink {
                        return Err(format!(
                            "link nlink: real {} model {}",
                            attr.nlink, m.nodes[&src_ino].nlink
                        ));
                    }
                    Ok(())
                }
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("link {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Write {
            dir,
            name,
            offset,
            len,
        } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let Some(ino) = m.entry(dir, name) else {
                return Ok(());
            };
            let data: Vec<u8> = (0..*len)
                .map(|i| ((i as u64 + offset) % 241) as u8)
                .collect();
            let real = v.write(creds, ino, *offset, &data).await;
            let node_kind = m.nodes[&ino].kind;
            let model: Result<(), FsError> = match node_kind {
                FileKind::File => Ok(()),
                FileKind::Dir => Err(FsError::IsDir),
                _ => Err(FsError::Invalid),
            };
            match (real, model) {
                (Ok(n), Ok(())) => {
                    if n as usize != data.len() {
                        return Err(format!("short write: {n} != {}", data.len()));
                    }
                    if !data.is_empty() {
                        let node = m.nodes.get_mut(&ino).unwrap();
                        let end = *offset as usize + data.len();
                        if node.data.len() < end {
                            node.data.resize(end, 0);
                        }
                        node.data[*offset as usize..end].copy_from_slice(&data);
                    }
                    Ok(())
                }
                (Ok(0), Err(_)) if data.is_empty() => Ok(()), // empty write short-circuits
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("write {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Truncate { dir, name, size } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let Some(ino) = m.entry(dir, name) else {
                return Ok(());
            };
            let attrs = SetAttrs {
                size: Some(*size),
                ..Default::default()
            };
            let real = v.setattr(creds, ino, attrs).await;
            let model: Result<(), FsError> = match m.nodes[&ino].kind {
                FileKind::File => Ok(()),
                FileKind::Dir => Err(FsError::IsDir),
                _ => Err(FsError::Invalid),
            };
            match (real, model) {
                (Ok(attr), Ok(())) => {
                    m.nodes
                        .get_mut(&ino)
                        .unwrap()
                        .data
                        .resize(*size as usize, 0);
                    if attr.size != *size {
                        return Err(format!("truncate size: real {} expected {size}", attr.size));
                    }
                    Ok(())
                }
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("truncate {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Read {
            dir,
            name,
            offset,
            len,
        } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let Some(ino) = m.entry(dir, name) else {
                return Ok(());
            };
            let real = v.read(creds, ino, *offset, *len).await;
            let node = &m.nodes[&ino];
            let model: Result<Vec<u8>, FsError> = match node.kind {
                FileKind::File => {
                    let size = node.data.len() as u64;
                    if *offset >= size || *len == 0 {
                        Ok(Vec::new())
                    } else {
                        let end = size.min(offset + *len as u64) as usize;
                        Ok(node.data[*offset as usize..end].to_vec())
                    }
                }
                FileKind::Dir => Err(FsError::IsDir),
                _ => Err(FsError::Invalid),
            };
            match (real, model) {
                (Ok(r), Ok(mo)) if r == mo => Ok(()),
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!(
                    "read {op:?}: real {:?} vs model {:?}",
                    r.map(|b| b.len()),
                    mo.map(|b| b.len())
                )),
            }
        }
        Op::Unlink { dir, name } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let real = v.unlink(creds, dir, name).await;
            let model = match m.entry(dir, name) {
                None => Err(FsError::NotFound),
                Some(ino) if m.nodes[&ino].kind.is_dir() => Err(FsError::IsDir),
                Some(_) => Ok(()),
            };
            match (real, model) {
                (Ok(()), Ok(())) => {
                    m.unlink_entry(dir, name);
                    Ok(())
                }
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("unlink {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Rmdir { dir, name } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let real = v.rmdir(creds, dir, name).await;
            let model = match m.entry(dir, name) {
                None => Err(FsError::NotFound),
                Some(ino) if !m.nodes[&ino].kind.is_dir() => Err(FsError::NotDir),
                Some(ino) if !m.nodes[&ino].entries.is_empty() => Err(FsError::NotEmpty),
                Some(_) => Ok(()),
            };
            match (real, model) {
                (Ok(()), Ok(())) => {
                    let ino = m.entry(dir, name).unwrap();
                    m.nodes.remove(&ino);
                    let d = m.nodes.get_mut(&dir).unwrap();
                    d.entries.remove(name);
                    d.nlink -= 1;
                    Ok(())
                }
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("rmdir {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Rename {
            sdir,
            sname,
            ddir,
            dname,
        } => {
            let (sdir, sname) = (pick_dir(*sdir), NAMES[*sname]);
            let (ddir, dname) = (pick_dir(*ddir), NAMES[*dname]);
            let real = v.rename(creds, sdir, sname, ddir, dname).await;

            // Mirror the implementation's check order exactly.
            let model: Result<bool, FsError> = (|| {
                let Some(src_ino) = m.entry(sdir, sname) else {
                    return Err(FsError::NotFound);
                };
                let dst = m.entry(ddir, dname);
                if dst == Some(src_ino) {
                    return Ok(false); // noop
                }
                if sdir == ddir && sname == dname {
                    return Ok(false);
                }
                let src_is_dir = m.nodes[&src_ino].kind.is_dir();
                if src_is_dir && sdir != ddir && m.is_ancestor(src_ino, ddir) {
                    return Err(FsError::Invalid);
                }
                if let Some(dst_ino) = dst {
                    let dst_is_dir = m.nodes[&dst_ino].kind.is_dir();
                    match (src_is_dir, dst_is_dir) {
                        (true, false) => return Err(FsError::NotDir),
                        (false, true) => return Err(FsError::IsDir),
                        (true, true) => {
                            if !m.nodes[&dst_ino].entries.is_empty() {
                                return Err(FsError::NotEmpty);
                            }
                        }
                        (false, false) => {}
                    }
                }
                Ok(true)
            })();

            match (real, model) {
                (Ok(()), Ok(apply)) => {
                    if apply {
                        let src_ino = m.entry(sdir, sname).unwrap();
                        if let Some(dst_ino) = m.entry(ddir, dname) {
                            if m.nodes[&dst_ino].kind.is_dir() {
                                m.nodes.remove(&dst_ino);
                                let d = m.nodes.get_mut(&ddir).unwrap();
                                d.entries.remove(dname);
                                d.nlink -= 1;
                            } else {
                                m.unlink_entry(ddir, dname);
                            }
                        }
                        m.nodes.get_mut(&sdir).unwrap().entries.remove(sname);
                        m.nodes
                            .get_mut(&ddir)
                            .unwrap()
                            .entries
                            .insert(dname.to_vec(), src_ino);
                        let src_is_dir = m.nodes[&src_ino].kind.is_dir();
                        if src_is_dir && sdir != ddir {
                            m.nodes.get_mut(&sdir).unwrap().nlink -= 1;
                            m.nodes.get_mut(&ddir).unwrap().nlink += 1;
                            m.nodes.get_mut(&src_ino).unwrap().parent = ddir;
                        }
                    }
                    Ok(())
                }
                (Err(e), Err(me)) if e == me => Ok(()),
                (r, mo) => Err(format!("rename {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
        Op::Readdir { dir } => {
            let dir = pick_dir(*dir);
            let mut listed = BTreeMap::new();
            let mut cookie = 0;
            loop {
                let page = v
                    .readdir(creds, dir, cookie, 5)
                    .await
                    .map_err(|e| format!("readdir: {e:?}"))?;
                for e in &page.entries {
                    listed.insert(e.name.clone(), e.ino);
                    cookie = e.cookie;
                }
                if page.eof {
                    break;
                }
            }
            let expected: BTreeMap<Vec<u8>, u64> = m.nodes[&dir]
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            if listed != expected {
                return Err(format!(
                    "readdir {dir}: real {listed:?} vs model {expected:?}"
                ));
            }
            Ok(())
        }
        Op::Getattr { dir, name } => {
            let (dir, name) = (pick_dir(*dir), NAMES[*name]);
            let real = v.lookup(creds, dir, name).await;
            match (real, m.entry(dir, name)) {
                (Ok(attr), Some(ino)) => {
                    let node = &m.nodes[&ino];
                    if attr.ino != ino
                        || attr.kind != node.kind
                        || attr.size != node.size()
                        || attr.nlink != node.nlink
                    {
                        return Err(format!(
                            "getattr {op:?}: real (ino {} kind {:?} size {} nlink {}) vs model (ino {ino} kind {:?} size {} nlink {})",
                            attr.ino,
                            attr.kind,
                            attr.size,
                            attr.nlink,
                            node.kind,
                            node.size(),
                            node.nlink
                        ));
                    }
                    Ok(())
                }
                (Err(FsError::NotFound), None) => Ok(()),
                (r, mo) => Err(format!("getattr {op:?}: real {r:?} vs model {mo:?}")),
            }
        }
    }
}

async fn run_case(ops: Vec<Op>) -> Result<(), String> {
    let v = common::fresh_volume().await;
    let mut m = Model::new();
    let creds = Credentials::root();
    for (i, op) in ops.iter().enumerate() {
        run_op(&v, &mut m, &creds, op)
            .await
            .map_err(|e| format!("op {i}: {e}"))?;
    }
    // Final invariants: fsck clean, model node count == real inode count.
    let report = v.fsck().await.map_err(|e| format!("fsck: {e}"))?;
    if !report.is_clean() {
        return Err(format!(
            "fsck dirty: problems={:?} counters real ({}, {}) recount ({}, {})",
            report.problems,
            report.counter_inodes,
            report.counter_bytes,
            report.inodes_counted,
            report.bytes_counted
        ));
    }
    if report.inodes_counted != m.nodes.len() as i64 {
        return Err(format!(
            "inode count: real {} vs model {}",
            report.inodes_counted,
            m.nodes.len()
        ));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48, // local default; override with PROPTEST_CASES in CI
        max_shrink_iters: 2000,
        ..ProptestConfig::default()
    })]
    #[test]
    fn vfs_matches_reference_model(ops in proptest::collection::vec(op_strategy(), 1..120)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        if let Err(e) = rt.block_on(run_case(ops)) {
            return Err(TestCaseError::fail(e));
        }
    }
}
