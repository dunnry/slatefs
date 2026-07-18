//! Non-secret consumer listener configuration contract.

use std::net::{Ipv4Addr, SocketAddr};

/// Limits advertised by the capabilities endpoint and enforced in Phase 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerLimits {
    pub max_page_size: u32,
    pub max_range_bytes: u64,
    pub max_recursive_entries: u64,
    pub max_recursive_bytes: u64,
    pub max_text_edit_bytes: u64,
    pub max_diff_bytes: u64,
    pub max_diff_lines: u64,
}

impl Default for ConsumerLimits {
    fn default() -> Self {
        Self {
            max_page_size: 500,
            max_range_bytes: 8 * 1024 * 1024,
            max_recursive_entries: 10_000,
            max_recursive_bytes: 1024 * 1024 * 1024,
            max_text_edit_bytes: 1024 * 1024,
            max_diff_bytes: 2 * 1024 * 1024,
            max_diff_lines: 50_000,
        }
    }
}

/// Consumer frontend configuration. Token sources remain owned by daemon
/// admin configuration and are intentionally not duplicated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerConfig {
    pub listen: SocketAddr,
    pub limits: ConsumerLimits,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8081)),
            limits: ConsumerLimits::default(),
        }
    }
}
