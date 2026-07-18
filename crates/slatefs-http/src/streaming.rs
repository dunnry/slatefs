//! Streaming boundary contracts. Transport behavior arrives in Phase 1.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: u64,
    pub end_inclusive: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamingLimits {
    pub chunk_bytes: usize,
    pub max_range_bytes: u64,
}

impl Default for StreamingLimits {
    fn default() -> Self {
        Self {
            chunk_bytes: 64 * 1024,
            max_range_bytes: 8 * 1024 * 1024,
        }
    }
}
