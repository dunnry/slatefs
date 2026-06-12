//! In-process concurrency control (DD-5).
//!
//! Exactly one `slatefsd` owns a volume (SlateDB fencing), so POSIX atomicity
//! is local: striped per-inode async RwLocks order all mutations; directory
//! renames additionally serialize on a per-volume rename mutex (ancestor
//! cycle checks must not race). A separate advisory byte-range table backs 9P
//! `Tlock`/`Tgetlock` and shares state across protocols.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedRwLockWriteGuard, RwLock};

const STRIPES: usize = 1024;

pub struct LockManager {
    stripes: Vec<Arc<RwLock<()>>>,
    rename_mutex: tokio::sync::Mutex<()>,
}

impl Default for LockManager {
    fn default() -> Self {
        LockManager {
            stripes: (0..STRIPES).map(|_| Arc::new(RwLock::new(()))).collect(),
            rename_mutex: tokio::sync::Mutex::new(()),
        }
    }
}

impl LockManager {
    fn stripe_of(&self, ino: u64) -> usize {
        // Mix before reducing: sequential inos otherwise share low-bit
        // patterns with sequential directory workloads.
        (ino.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 52) as usize % STRIPES
    }

    /// Exclusive lock for all mutations touching `ino`.
    pub async fn write(&self, ino: u64) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.stripes[self.stripe_of(ino)])
            .write_owned()
            .await
    }

    /// Exclusive locks for a set of inodes, deduplicated by stripe and taken
    /// in stripe order so concurrent multi-inode ops can't deadlock.
    pub async fn write_many(&self, inos: &[u64]) -> Vec<OwnedRwLockWriteGuard<()>> {
        let mut stripes: Vec<usize> = inos.iter().map(|&i| self.stripe_of(i)).collect();
        stripes.sort_unstable();
        stripes.dedup();
        let mut guards = Vec::with_capacity(stripes.len());
        for s in stripes {
            guards.push(Arc::clone(&self.stripes[s]).write_owned().await);
        }
        guards
    }

    /// Serializes directory renames volume-wide (plan §10: cycle check runs
    /// under this).
    pub async fn rename_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.rename_mutex.lock().await
    }
}

// ---- advisory byte-range locks (plan §9.4) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockRange {
    pub start: u64,
    /// Exclusive; `u64::MAX` means "to EOF".
    pub end: u64,
}

impl LockRange {
    pub fn overlaps(&self, other: &LockRange) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeLock {
    /// Opaque owner id (per protocol session/lock-owner).
    pub owner: u64,
    pub range: LockRange,
    pub exclusive: bool,
}

#[derive(Default)]
pub struct RangeLockTable {
    by_ino: Mutex<HashMap<u64, Vec<RangeLock>>>,
}

impl RangeLockTable {
    /// Non-blocking acquire (9P `Tlock` semantics: the client retries).
    /// Returns the conflicting lock on failure.
    pub fn try_lock(&self, ino: u64, lock: RangeLock) -> Result<(), RangeLock> {
        let mut map = self.by_ino.lock().expect("range lock table poisoned");
        let locks = map.entry(ino).or_default();
        if let Some(conflict) = locks
            .iter()
            .find(|l| {
                l.owner != lock.owner
                    && l.range.overlaps(&lock.range)
                    && (l.exclusive || lock.exclusive)
            })
            .copied()
        {
            return Err(conflict);
        }
        // Same-owner overlaps are replaced within the requested range
        // (POSIX upgrade/downgrade), splitting partial overlaps.
        Self::carve(locks, lock.owner, lock.range);
        locks.push(lock);
        Ok(())
    }

    /// First lock that would block the probe, if any (9P `Tgetlock`).
    pub fn test(&self, ino: u64, probe: RangeLock) -> Option<RangeLock> {
        let map = self.by_ino.lock().expect("range lock table poisoned");
        map.get(&ino).and_then(|locks| {
            locks
                .iter()
                .find(|l| {
                    l.owner != probe.owner
                        && l.range.overlaps(&probe.range)
                        && (l.exclusive || probe.exclusive)
                })
                .copied()
        })
    }

    pub fn unlock(&self, ino: u64, owner: u64, range: LockRange) {
        let mut map = self.by_ino.lock().expect("range lock table poisoned");
        if let Some(locks) = map.get_mut(&ino) {
            Self::carve(locks, owner, range);
            if locks.is_empty() {
                map.remove(&ino);
            }
        }
    }

    /// Drop everything held by `owner` (connection teardown).
    pub fn unlock_owner(&self, owner: u64) {
        let mut map = self.by_ino.lock().expect("range lock table poisoned");
        map.retain(|_, locks| {
            locks.retain(|l| l.owner != owner);
            !locks.is_empty()
        });
    }

    /// Remove `range` from `owner`'s locks, splitting partially-covered
    /// locks into the surviving sub-ranges.
    fn carve(locks: &mut Vec<RangeLock>, owner: u64, range: LockRange) {
        let mut survivors = Vec::new();
        locks.retain(|l| {
            if l.owner != owner || !l.range.overlaps(&range) {
                return true;
            }
            if l.range.start < range.start {
                survivors.push(RangeLock {
                    range: LockRange {
                        start: l.range.start,
                        end: range.start,
                    },
                    ..*l
                });
            }
            if range.end < l.range.end {
                survivors.push(RangeLock {
                    range: LockRange {
                        start: range.end,
                        end: l.range.end,
                    },
                    ..*l
                });
            }
            false
        });
        locks.extend(survivors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(owner: u64, start: u64, end: u64, exclusive: bool) -> RangeLock {
        RangeLock {
            owner,
            range: LockRange { start, end },
            exclusive,
        }
    }

    #[tokio::test]
    async fn write_many_dedups_and_orders() {
        let lm = LockManager::default();
        // Same ino twice (rename within one directory) must not deadlock.
        let guards = lm.write_many(&[7, 7]).await;
        assert_eq!(guards.len(), 1);
        drop(guards);
        let guards = lm.write_many(&[1, 2, 3, 4]).await;
        assert!(!guards.is_empty());
    }

    #[test]
    fn exclusive_conflicts_shared_coexists() {
        let t = RangeLockTable::default();
        t.try_lock(1, rl(1, 0, 100, false)).unwrap();
        t.try_lock(1, rl(2, 0, 100, false)).unwrap();
        let conflict = t.try_lock(1, rl(3, 50, 60, true)).unwrap_err();
        assert!(conflict.owner == 1 || conflict.owner == 2);
        // Disjoint exclusive is fine.
        t.try_lock(1, rl(3, 100, 200, true)).unwrap();
        assert!(t.test(1, rl(4, 150, 151, false)).is_some());
        assert!(t.test(1, rl(4, 90, 95, false)).is_none());
    }

    #[test]
    fn unlock_splits_ranges() {
        let t = RangeLockTable::default();
        t.try_lock(1, rl(1, 0, 100, true)).unwrap();
        t.unlock(1, 1, LockRange { start: 40, end: 60 });
        // Middle is free for others now; edges still held.
        t.try_lock(1, rl(2, 40, 60, true)).unwrap();
        assert!(t.try_lock(1, rl(2, 0, 10, true)).is_err());
        assert!(t.try_lock(1, rl(2, 60, 100, true)).is_err());
    }

    #[test]
    fn same_owner_relock_and_owner_teardown() {
        let t = RangeLockTable::default();
        t.try_lock(1, rl(1, 0, 100, false)).unwrap();
        // Upgrade middle to exclusive: replaces own coverage, no self-conflict.
        t.try_lock(1, rl(1, 25, 75, true)).unwrap();
        assert!(t.try_lock(1, rl(2, 30, 40, false)).is_err());
        t.unlock_owner(1);
        t.try_lock(1, rl(2, 0, 100, true)).unwrap();
    }
}
