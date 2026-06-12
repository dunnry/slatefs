//! Inode-number allocator (plan §5): `a` holds a u64 high-water mark; the
//! single writer leases blocks of [`LEASE_SIZE`] numbers by durably bumping
//! the mark before handing any of them out. A crash burns at most one lease.
//! Inode numbers are never reused within a lease cycle; `generation` in the
//! inode record covers reuse across fsck-style rebuilds.

use std::sync::Mutex;

use slatedb::Db;

use crate::error::{Error, Result};
use crate::meta::keys;

pub const LEASE_SIZE: u64 = 65_536;

pub struct InodeAllocator {
    state: Mutex<AllocState>,
}

struct AllocState {
    next: u64,
    lease_end: u64,
}

impl InodeAllocator {
    /// Read the current high-water mark and take the first lease.
    pub async fn load(db: &Db) -> Result<InodeAllocator> {
        let mark = match db.get(keys::KEY_NEXT_INO).await? {
            Some(bytes) => u64::from_be_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::invalid("allocator", "bad high-water mark width"))?,
            ),
            None => return Err(Error::invalid("allocator", "missing a/next_ino (mkfs bug)")),
        };
        let lease_end = mark
            .checked_add(LEASE_SIZE)
            .ok_or_else(|| Error::invalid("allocator", "inode space exhausted"))?;
        // The lease bump rides the WAL ahead of any inode write that uses it:
        // if a later inode create survives a crash, so did this bump.
        db.put(keys::KEY_NEXT_INO, lease_end.to_be_bytes()).await?;
        Ok(InodeAllocator {
            state: Mutex::new(AllocState {
                next: mark,
                lease_end,
            }),
        })
    }

    /// Allocate one inode number. Returns `(ino, Some(new_lease_end))` when
    /// the caller must durably record a new lease *before* using the number;
    /// the caller owns writing it (see [`InodeAllocator::load`] for why
    /// ordering is safe).
    pub fn allocate(&self) -> (u64, Option<u64>) {
        let mut s = self.state.lock().expect("allocator poisoned");
        let ino = s.next;
        s.next += 1;
        if s.next == s.lease_end {
            s.lease_end += LEASE_SIZE;
            (ino, Some(s.lease_end))
        } else {
            (ino, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequentially_and_renews_lease() {
        let alloc = InodeAllocator {
            state: Mutex::new(AllocState {
                next: 10,
                lease_end: 12,
            }),
        };
        assert_eq!(alloc.allocate(), (10, None));
        // Hitting the lease boundary demands a renewal.
        let (ino, renew) = alloc.allocate();
        assert_eq!(ino, 11);
        assert_eq!(renew, Some(12 + LEASE_SIZE));
        assert_eq!(alloc.allocate(), (12, None));
    }
}
