//! Quota accounting (DD-9, plan §12).
//!
//! Usage counters are SlateDB merge-operator sums of i64 deltas, written in
//! the same `WriteBatch` as the mutation they account for — a crash can never
//! desync them. Enforcement reads an authoritative in-memory counter (loaded
//! at volume mount, updated synchronously; valid because this process is the
//! volume's single writer) and rejects with `EDQUOT` *before* the batch is
//! built.
//!
//! Accounting rule (§12, refined): `bytes_used = Σ` over existing chunks of
//! `min(value_len, max(size − chunk_start, 0))` — actual stored bytes,
//! clamped at EOF. Holes cost nothing; a short tail chunk keeps billing its
//! real length even after sparse growth; chunks orphaned beyond `size` by an
//! interrupted truncate bill zero until reaped.

use std::sync::atomic::{AtomicI64, Ordering};

use bytes::Bytes;
use slatedb::{MergeOperator, MergeOperatorError};

use crate::control::QuotaLimits;
use crate::meta::keys;
use crate::vfs::FsError;

/// Sums little-endian i64 deltas. Registered for the volume DB; only the
/// `qB`/`qI` keys are ever written with merge.
pub struct CounterMergeOperator;

fn decode_i64(bytes: &[u8]) -> Result<i64, MergeOperatorError> {
    Ok(i64::from_le_bytes(bytes.try_into().map_err(|_| {
        MergeOperatorError::Callback {
            message: format!("counter operand must be 8 bytes, got {}", bytes.len()),
        }
    })?))
}

impl MergeOperator for CounterMergeOperator {
    fn merge(
        &self,
        _key: &Bytes,
        existing_value: Option<Bytes>,
        value: Bytes,
    ) -> Result<Bytes, MergeOperatorError> {
        let existing = existing_value.map(|b| decode_i64(&b)).transpose()?;
        let delta = decode_i64(&value)?;
        let sum = existing.unwrap_or(0).wrapping_add(delta);
        Ok(Bytes::copy_from_slice(&sum.to_le_bytes()))
    }
}

pub fn encode_delta(delta: i64) -> [u8; 8] {
    delta.to_le_bytes()
}

pub fn decode_counter(bytes: Option<&[u8]>) -> i64 {
    bytes
        .and_then(|b| b.try_into().ok().map(i64::from_le_bytes))
        .unwrap_or(0)
}

/// Billed bytes a chunk contributes given the file size (accounting rule
/// above).
pub fn billed_chunk_bytes(size: u64, chunk_start: u64, value_len: usize) -> u64 {
    (value_len as u64).min(size.saturating_sub(chunk_start))
}

/// In-memory authoritative usage + limits for one mounted volume.
pub struct QuotaTracker {
    bytes: AtomicI64,
    inodes: AtomicI64,
    limits: QuotaLimits,
}

impl QuotaTracker {
    pub fn new(bytes: i64, inodes: i64, limits: QuotaLimits) -> QuotaTracker {
        QuotaTracker {
            bytes: AtomicI64::new(bytes),
            inodes: AtomicI64::new(inodes),
            limits,
        }
    }

    pub fn usage(&self) -> (i64, i64) {
        (
            self.bytes.load(Ordering::Relaxed),
            self.inodes.load(Ordering::Relaxed),
        )
    }

    pub fn limits(&self) -> &QuotaLimits {
        &self.limits
    }

    /// Reserve usage before building the mutation batch. Returns `EDQUOT` if
    /// a hard limit would be exceeded. Negative deltas (frees) always
    /// succeed. Call [`QuotaTracker::release`] if the commit fails.
    pub fn reserve(&self, bytes_delta: i64, inode_delta: i64) -> Result<(), FsError> {
        let new_bytes = self.bytes.fetch_add(bytes_delta, Ordering::Relaxed) + bytes_delta;
        if bytes_delta > 0
            && let Some(hard) = self.limits.bytes.hard
            && new_bytes > hard as i64
        {
            self.bytes.fetch_sub(bytes_delta, Ordering::Relaxed);
            return Err(FsError::QuotaExceeded);
        }
        let new_inodes = self.inodes.fetch_add(inode_delta, Ordering::Relaxed) + inode_delta;
        if inode_delta > 0
            && let Some(hard) = self.limits.inodes.hard
            && new_inodes > hard as i64
        {
            self.inodes.fetch_sub(inode_delta, Ordering::Relaxed);
            self.bytes.fetch_sub(bytes_delta, Ordering::Relaxed);
            return Err(FsError::QuotaExceeded);
        }
        Ok(())
    }

    /// Roll back a reservation whose batch failed to commit.
    pub fn release(&self, bytes_delta: i64, inode_delta: i64) {
        self.bytes.fetch_sub(bytes_delta, Ordering::Relaxed);
        self.inodes.fetch_sub(inode_delta, Ordering::Relaxed);
    }

    /// Over-limit check for ops that don't change accounted usage but are
    /// still quota-gated (xattr set, plan §12).
    pub fn check_not_over(&self) -> Result<(), FsError> {
        if let Some(hard) = self.limits.bytes.hard
            && self.bytes.load(Ordering::Relaxed) > hard as i64
        {
            return Err(FsError::QuotaExceeded);
        }
        Ok(())
    }
}

/// Keys the merge operator applies to, for fsck and tests.
pub fn quota_keys() -> [&'static [u8]; 2] {
    [keys::KEY_QUOTA_BYTES, keys::KEY_QUOTA_INODES]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::QuotaLimit;

    fn limits(bytes: Option<u64>, inodes: Option<u64>) -> QuotaLimits {
        QuotaLimits {
            bytes: QuotaLimit {
                hard: bytes,
                ..Default::default()
            },
            inodes: QuotaLimit {
                hard: inodes,
                ..Default::default()
            },
        }
    }

    #[test]
    fn merge_sums_deltas() {
        let op = CounterMergeOperator;
        let key = Bytes::from_static(b"qB");
        let a = op
            .merge(&key, None, Bytes::copy_from_slice(&encode_delta(10)))
            .unwrap();
        let b = op
            .merge(&key, Some(a), Bytes::copy_from_slice(&encode_delta(-3)))
            .unwrap();
        assert_eq!(decode_counter(Some(&b)), 7);
    }

    #[test]
    fn billed_bytes_clamp() {
        let cs = 128 * 1024u64;
        // Full chunk below EOF bills its stored length.
        assert_eq!(billed_chunk_bytes(cs + 5, 0, cs as usize), cs);
        // Short tail chunk bills its real length even when the file later
        // grew sparsely past it.
        assert_eq!(billed_chunk_bytes(cs * 100, cs, 100), 100);
        // Chunk straddling EOF clamps at EOF.
        assert_eq!(billed_chunk_bytes(cs + 5, cs, cs as usize), 5);
        // Chunk fully beyond EOF (interrupted-truncate leftover) bills 0.
        assert_eq!(billed_chunk_bytes(10, 3 * cs, cs as usize), 0);
    }

    #[test]
    fn reserve_enforces_hard_limits_exactly() {
        let q = QuotaTracker::new(0, 0, limits(Some(100), Some(2)));
        q.reserve(100, 1).unwrap();
        assert!(matches!(q.reserve(1, 0), Err(FsError::QuotaExceeded)));
        q.reserve(-50, 0).unwrap();
        q.reserve(50, 1).unwrap();
        assert!(matches!(q.reserve(0, 1), Err(FsError::QuotaExceeded)));
        // Failed reservation must not leak usage.
        assert_eq!(q.usage(), (100, 2));
        q.release(100, 2);
        assert_eq!(q.usage(), (0, 0));
    }

    #[test]
    fn frees_always_succeed_even_over_limit() {
        let q = QuotaTracker::new(500, 5, limits(Some(100), Some(2)));
        q.reserve(-400, -3).unwrap();
        assert_eq!(q.usage(), (100, 2));
    }
}
