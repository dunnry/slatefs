//! In-process attribute + negative-dentry cache (plan §8).
//!
//! Coherent by construction (DD-5): this process is the volume's only
//! writer, and every mutation write-throughs or invalidates the affected
//! inodes after its batch commits, under the same inode locks the mutation
//! held. The cache serves *read* paths only (getattr storms from NFS
//! clients); mutation paths read the DB directly so a missed write-through
//! can never corrupt a read-modify-write.

use moka::sync::Cache;

use crate::meta::inode::Inode;

/// ~200 B per attr entry ⇒ ~13 MiB at capacity; negative entries are tiny.
const ATTR_CAPACITY: u64 = 64 * 1024;
const NEG_CAPACITY: u64 = 64 * 1024;

pub struct AttrCache {
    attrs: Cache<u64, Inode>,
    /// (parent ino, name) pairs known not to exist.
    negative: Cache<(u64, Vec<u8>), ()>,
}

impl Default for AttrCache {
    fn default() -> Self {
        AttrCache {
            attrs: Cache::new(ATTR_CAPACITY),
            negative: Cache::new(NEG_CAPACITY),
        }
    }
}

impl AttrCache {
    pub fn get(&self, ino: u64) -> Option<Inode> {
        self.attrs.get(&ino)
    }

    /// Write-through after a committed mutation (or a clean read miss).
    pub fn insert(&self, ino: u64, inode: Inode) {
        self.attrs.insert(ino, inode);
    }

    /// The inode is gone (unlinked to zero / reaped).
    pub fn remove(&self, ino: u64) {
        self.attrs.invalidate(&ino);
    }

    pub fn is_negative(&self, parent: u64, name: &[u8]) -> bool {
        self.negative.contains_key(&(parent, name.to_vec()))
    }

    /// Record a confirmed lookup miss (or a just-removed entry).
    pub fn insert_negative(&self, parent: u64, name: &[u8]) {
        self.negative.insert((parent, name.to_vec()), ());
    }

    /// An entry was created under this name.
    pub fn remove_negative(&self, parent: u64, name: &[u8]) {
        self.negative.invalidate(&(parent, name.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::inode::{FileKind, Timespec};

    #[test]
    fn attr_roundtrip_and_invalidation() {
        let c = AttrCache::default();
        let inode = Inode::new(FileKind::File, 0o644, 1, 1, Timespec::ZERO);
        assert!(c.get(5).is_none());
        c.insert(5, inode.clone());
        assert_eq!(c.get(5).as_ref(), Some(&inode));
        c.remove(5);
        assert!(c.get(5).is_none());
    }

    #[test]
    fn negative_dentries() {
        let c = AttrCache::default();
        assert!(!c.is_negative(1, b"missing"));
        c.insert_negative(1, b"missing");
        assert!(c.is_negative(1, b"missing"));
        c.remove_negative(1, b"missing");
        assert!(!c.is_negative(1, b"missing"));
    }
}
