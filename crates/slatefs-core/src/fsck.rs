//! Offline volume checker (`slatefs fsck`, plan §12): rebuilds quota
//! counters by scan, verifies structural invariants (nlink, dirent pairing,
//! reachability, billed bytes), and reports crash leftovers. Drift between
//! counters and recount "should be impossible (atomic merges) so any drift
//! is a bug" — the crash-consistency tests assert a clean report.

use std::collections::{HashMap, HashSet, VecDeque};

use async_trait::async_trait;
use bytes::Bytes;
use slatedb::{Db, DbIterator, DbReader, WriteBatch};

use crate::crypto::names::NameCodec;
use crate::error::Result;
use crate::meta::dirent::{Dirent, DirentIdx, Orphan};
use crate::meta::inode::{FileKind, Inode, ROOT_INO};
use crate::meta::keys;
use crate::quota::{self, billed_chunk_bytes};

#[derive(Debug, Default)]
pub struct FsckReport {
    /// Structural violations. Empty ⇒ healthy.
    pub problems: Vec<String>,
    /// Benign crash leftovers (orphan markers, truncate-spill chunks) that
    /// reaping will clear; not corruption.
    pub reapable: Vec<String>,
    pub inodes_counted: i64,
    pub bytes_counted: i64,
    pub counter_inodes: i64,
    pub counter_bytes: i64,
}

impl FsckReport {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty() && self.counters_match()
    }

    pub fn counters_match(&self) -> bool {
        self.inodes_counted == self.counter_inodes && self.bytes_counted == self.counter_bytes
    }
}

struct Scanned {
    inodes: HashMap<u64, Inode>,
    /// (parent, enc_name) → Dirent
    dirents: HashMap<(u64, Vec<u8>), Dirent>,
    /// (parent, dirent_id) → DirentIdx
    idx: HashMap<(u64, u64), DirentIdx>,
    /// ino → [(chunk_idx, len)]
    chunks: HashMap<u64, Vec<(u32, usize)>>,
    orphans: HashMap<u64, Orphan>,
    symlinks: HashSet<u64>,
    counter_bytes: i64,
    counter_inodes: i64,
}

#[async_trait]
trait FsckRead {
    async fn scan_all_keys(&self) -> Result<DbIterator>;
    async fn get_key(&self, key: &'static [u8]) -> Result<Option<Bytes>>;
}

#[async_trait]
impl FsckRead for Db {
    async fn scan_all_keys(&self) -> Result<DbIterator> {
        self.scan(..).await.map_err(Into::into)
    }

    async fn get_key(&self, key: &'static [u8]) -> Result<Option<Bytes>> {
        self.get(key).await.map_err(Into::into)
    }
}

#[async_trait]
impl FsckRead for DbReader {
    async fn scan_all_keys(&self) -> Result<DbIterator> {
        self.scan(..).await.map_err(Into::into)
    }

    async fn get_key(&self, key: &'static [u8]) -> Result<Option<Bytes>> {
        self.get(key).await.map_err(Into::into)
    }
}

async fn scan_all(db: &(impl FsckRead + Sync)) -> Result<Scanned> {
    let mut s = Scanned {
        inodes: HashMap::new(),
        dirents: HashMap::new(),
        idx: HashMap::new(),
        chunks: HashMap::new(),
        orphans: HashMap::new(),
        symlinks: HashSet::new(),
        counter_bytes: 0,
        counter_inodes: 0,
    };

    let mut iter = db.scan_all_keys().await?;
    while let Some(kv) = iter.next().await? {
        let key: &[u8] = &kv.key;
        match key.first() {
            Some(b'i') => {
                if let Some(ino) = keys::parse_ino(key) {
                    s.inodes.insert(ino, Inode::decode(&kv.value)?);
                }
            }
            Some(b'd') => {
                if let Some(parent) = keys::parse_ino(key) {
                    s.dirents
                        .insert((parent, key[9..].to_vec()), Dirent::decode(&kv.value)?);
                }
            }
            Some(b'e') => {
                if let Some((parent, id)) = keys::parse_dirent_idx(key) {
                    s.idx.insert((parent, id), DirentIdx::decode(&kv.value)?);
                }
            }
            Some(b'c') => {
                if let Some((ino, idx)) = keys::parse_chunk(key) {
                    s.chunks.entry(ino).or_default().push((idx, kv.value.len()));
                }
            }
            Some(b'o') => {
                if let Some(ino) = keys::parse_ino(key) {
                    s.orphans.insert(ino, Orphan::decode(&kv.value)?);
                }
            }
            Some(b's') => {
                if let Some(ino) = keys::parse_ino(key) {
                    s.symlinks.insert(ino);
                }
            }
            _ => {}
        }
    }
    s.counter_bytes = quota::decode_counter(db.get_key(keys::KEY_QUOTA_BYTES).await?.as_deref());
    s.counter_inodes = quota::decode_counter(db.get_key(keys::KEY_QUOTA_INODES).await?.as_deref());
    Ok(s)
}

/// Verify the volume. `names` decrypts dirent names to cross-check the
/// `d`/`e` records.
pub async fn check(db: &Db, chunk_size: u64, names: &NameCodec) -> Result<FsckReport> {
    check_readable(db, chunk_size, names).await
}

/// Verify the volume through a read-only `DbReader`. This is the online scrub
/// path: it does not take the SlateDB writer lease for the volume.
pub async fn check_reader(
    reader: &DbReader,
    chunk_size: u64,
    names: &NameCodec,
) -> Result<FsckReport> {
    check_readable(reader, chunk_size, names).await
}

async fn check_readable(
    db: &(impl FsckRead + Sync),
    chunk_size: u64,
    names: &NameCodec,
) -> Result<FsckReport> {
    let s = scan_all(db).await?;
    let mut report = FsckReport {
        counter_bytes: s.counter_bytes,
        counter_inodes: s.counter_inodes,
        ..Default::default()
    };
    let problems = &mut report.problems;

    // Root invariants.
    match s.inodes.get(&ROOT_INO) {
        None => problems.push("root inode missing".into()),
        Some(root) => {
            if !root.kind.is_dir() {
                problems.push("root inode is not a directory".into());
            }
            if root.parent_dir != ROOT_INO {
                problems.push("root parent_dir != root".into());
            }
        }
    }

    // Dirent pairing and per-child link counts.
    let mut link_counts: HashMap<u64, u32> = HashMap::new();
    let mut child_dirs: HashMap<u64, u32> = HashMap::new();
    let mut max_dirent_id: HashMap<u64, u64> = HashMap::new();
    let mut children: HashMap<u64, Vec<u64>> = HashMap::new();

    for ((parent, enc_name), d) in &s.dirents {
        let tag = format!(
            "dirent {:?} in dir {parent}",
            String::from_utf8_lossy(&d.name)
        );
        match s.inodes.get(parent) {
            None => problems.push(format!("{tag}: parent inode missing")),
            Some(p) if !p.kind.is_dir() => problems.push(format!("{tag}: parent not a dir")),
            Some(p) => {
                if d.dirent_id >= p.next_dirent_id {
                    problems.push(format!("{tag}: dirent_id beyond parent's next_dirent_id"));
                }
            }
        }
        match s.inodes.get(&d.child_ino) {
            None => problems.push(format!("{tag}: dangling child ino {}", d.child_ino)),
            Some(c) => {
                if c.kind != d.kind {
                    problems.push(format!("{tag}: kind mismatch"));
                }
                if c.kind.is_dir() {
                    *child_dirs.entry(*parent).or_insert(0) += 1;
                    if c.parent_dir != *parent {
                        problems.push(format!("{tag}: child dir parent_dir mismatch"));
                    }
                }
            }
        }
        *link_counts.entry(d.child_ino).or_insert(0) += 1;
        children.entry(*parent).or_default().push(d.child_ino);
        let m = max_dirent_id.entry(*parent).or_insert(0);
        *m = (*m).max(d.dirent_id);

        match s.idx.get(&(*parent, d.dirent_id)) {
            None => problems.push(format!("{tag}: missing e/ index record")),
            Some(e) => {
                if e.enc_name != *enc_name || e.child_ino != d.child_ino || e.kind != d.kind {
                    problems.push(format!("{tag}: e/ index disagrees with d/ record"));
                }
            }
        }
        match names.open_name(*parent, enc_name) {
            Ok(name) if name == d.name => {}
            Ok(_) => problems.push(format!("{tag}: encrypted name decrypts to different name")),
            Err(_) => problems.push(format!("{tag}: encrypted name fails to decrypt")),
        }
    }
    for (parent, id) in s.idx.keys() {
        let paired = s
            .dirents
            .iter()
            .any(|((p, _), d)| p == parent && d.dirent_id == *id);
        if !paired {
            problems.push(format!("e/{parent}/{id}: index record without dirent"));
        }
    }

    // Inode invariants + billing recount.
    let mut bytes_counted: i64 = 0;
    for (ino, inode) in &s.inodes {
        let tag = format!("inode {ino}");
        let links = link_counts.get(ino).copied().unwrap_or(0);
        if inode.kind.is_dir() {
            if links > 1 {
                problems.push(format!("{tag}: directory with multiple dirents"));
            }
            let expected = 2 + child_dirs.get(ino).copied().unwrap_or(0);
            if inode.nlink != expected {
                problems.push(format!(
                    "{tag}: dir nlink {} != expected {expected}",
                    inode.nlink
                ));
            }
            if *ino != ROOT_INO && links == 0 {
                problems.push(format!("{tag}: unreachable directory"));
            }
        } else {
            if inode.nlink != links {
                if inode.nlink == 0 && s.orphans.contains_key(ino) {
                    // Unlinked-but-open file; legitimate.
                } else {
                    problems.push(format!(
                        "{tag}: nlink {} != dirent count {links}",
                        inode.nlink
                    ));
                }
            }
            if inode.kind == FileKind::Symlink && !s.symlinks.contains(ino) {
                problems.push(format!("{tag}: symlink without target record"));
            }
        }

        let billed: u64 = s
            .chunks
            .get(ino)
            .map(|chunks| {
                chunks
                    .iter()
                    .map(|(idx, len)| {
                        if *len as u64 > chunk_size {
                            problems.push(format!("{tag}: chunk {idx} oversize ({len} bytes)"));
                        }
                        billed_chunk_bytes(inode.size, *idx as u64 * chunk_size, *len)
                    })
                    .sum()
            })
            .unwrap_or(0);
        if billed != inode.billed_bytes {
            problems.push(format!(
                "{tag}: billed_bytes {} != recomputed {billed}",
                inode.billed_bytes
            ));
        }
        bytes_counted += billed as i64;
    }

    // Chunks owned by nobody: orphan-reap leftovers are reapable; anything
    // else is corruption.
    for ino in s.chunks.keys() {
        if !s.inodes.contains_key(ino) {
            if s.orphans.contains_key(ino) {
                report
                    .reapable
                    .push(format!("orphan {ino} awaiting chunk reap"));
            } else {
                report
                    .problems
                    .push(format!("chunks for unknown inode {ino}"));
            }
        }
    }
    for ino in s.orphans.keys() {
        report.reapable.push(format!("orphan marker for ino {ino}"));
    }

    // Reachability from root.
    let mut reachable: HashSet<u64> = HashSet::from([ROOT_INO]);
    let mut queue = VecDeque::from([ROOT_INO]);
    while let Some(dir) = queue.pop_front() {
        for child in children.get(&dir).cloned().unwrap_or_default() {
            if reachable.insert(child)
                && s.inodes
                    .get(&child)
                    .map(|i| i.kind.is_dir())
                    .unwrap_or(false)
            {
                queue.push_back(child);
            }
        }
    }
    for (ino, inode) in &s.inodes {
        let legit_orphan = inode.nlink == 0 && s.orphans.contains_key(ino);
        if !reachable.contains(ino) && !legit_orphan {
            report
                .problems
                .push(format!("inode {ino} unreachable from root"));
        }
    }

    report.inodes_counted = s.inodes.len() as i64;
    report.bytes_counted = bytes_counted;
    Ok(report)
}

/// Rewrite the quota counters from a recount (`slatefs fsck --recount`).
/// The volume must not be serving (single writer).
pub async fn recount(db: &Db, chunk_size: u64, names: &NameCodec) -> Result<FsckReport> {
    let report = check(db, chunk_size, names).await?;
    if !report.counters_match() {
        let mut batch = WriteBatch::new();
        batch.put(keys::KEY_QUOTA_BYTES, report.bytes_counted.to_le_bytes());
        batch.put(keys::KEY_QUOTA_INODES, report.inodes_counted.to_le_bytes());
        db.write(batch).await?;
        db.flush().await?;
    }
    Ok(report)
}
