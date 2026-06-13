//! Tenant-scoped token-bucket rate limits (plan §11 noisy-neighbor control).
//!
//! Limits are checked by protocol frontends before they call into the shared
//! VFS. Buckets are intentionally in-memory: they are admission-control state
//! for the serving daemon, not durable filesystem metadata.

use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::vfs::FsError;

/// Per-tenant admission limits. `None` means unlimited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimits {
    /// Maximum accepted filesystem operations per second.
    pub ops_per_second: Option<u64>,
    /// Maximum accepted request payload bytes per second. Read requests are
    /// charged by requested byte count; writes by submitted payload size.
    pub bytes_per_second: Option<u64>,
}

impl RateLimits {
    pub fn is_unlimited(self) -> bool {
        self.ops_per_second.is_none() && self.bytes_per_second.is_none()
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    limits: RateLimits,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    ops: Bucket,
    bytes: Bucket,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    pub fn new(limits: RateLimits) -> RateLimiter {
        let now = Instant::now();
        RateLimiter {
            limits,
            state: Mutex::new(State {
                ops: Bucket::new(limits.ops_per_second, now),
                bytes: Bucket::new(limits.bytes_per_second, now),
            }),
        }
    }

    pub fn limits(&self) -> RateLimits {
        self.limits
    }

    /// Try to admit one frontend operation carrying `bytes` request bytes.
    /// Returns `EAGAIN`/retry-later semantics when a bucket is empty.
    pub fn check(&self, bytes: u64) -> Result<(), FsError> {
        self.check_at(bytes, Instant::now())
    }

    fn check_at(&self, bytes: u64, now: Instant) -> Result<(), FsError> {
        let mut state = self.state.lock().expect("rate limiter poisoned");
        state.ops.refill(self.limits.ops_per_second, now);
        state.bytes.refill(self.limits.bytes_per_second, now);

        if !state.ops.can_consume(self.limits.ops_per_second, 1) {
            return Err(FsError::WouldBlock);
        }
        if bytes > 0 && !state.bytes.can_consume(self.limits.bytes_per_second, bytes) {
            return Err(FsError::WouldBlock);
        }

        state.ops.consume(self.limits.ops_per_second, 1);
        if bytes > 0 {
            state.bytes.consume(self.limits.bytes_per_second, bytes);
        }
        Ok(())
    }
}

impl Bucket {
    fn new(limit: Option<u64>, now: Instant) -> Bucket {
        Bucket {
            tokens: limit.unwrap_or(0) as f64,
            updated: now,
        }
    }

    fn refill(&mut self, limit: Option<u64>, now: Instant) {
        let Some(limit) = limit else {
            self.updated = now;
            return;
        };
        let capacity = limit as f64;
        let elapsed = now.duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * capacity).min(capacity);
        self.updated = now;
    }

    fn can_consume(&self, limit: Option<u64>, amount: u64) -> bool {
        limit.is_none_or(|_| self.tokens >= amount as f64)
    }

    fn consume(&mut self, limit: Option<u64>, amount: u64) {
        if limit.is_some() {
            self.tokens -= amount as f64;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn ops_limit_rejects_until_refill() {
        let limiter = RateLimiter::new(RateLimits {
            ops_per_second: Some(2),
            bytes_per_second: None,
        });
        let t0 = Instant::now();
        assert!(limiter.check_at(0, t0).is_ok());
        assert!(limiter.check_at(0, t0).is_ok());
        assert!(matches!(limiter.check_at(0, t0), Err(FsError::WouldBlock)));

        assert!(
            limiter.check_at(0, t0 + Duration::from_millis(500)).is_ok(),
            "half a second refills one operation token at 2 ops/s"
        );
    }

    #[test]
    fn byte_limit_rejects_oversized_request() {
        let limiter = RateLimiter::new(RateLimits {
            ops_per_second: None,
            bytes_per_second: Some(8),
        });
        let t0 = Instant::now();
        assert!(limiter.check_at(8, t0).is_ok());
        assert!(matches!(limiter.check_at(1, t0), Err(FsError::WouldBlock)));
        assert!(matches!(limiter.check_at(9, t0), Err(FsError::WouldBlock)));
    }

    #[test]
    fn unlimited_limits_never_consume_tokens() {
        let limiter = RateLimiter::new(RateLimits::default());
        let t0 = Instant::now();
        for _ in 0..100 {
            assert!(limiter.check_at(u64::MAX, t0).is_ok());
        }
    }
}
