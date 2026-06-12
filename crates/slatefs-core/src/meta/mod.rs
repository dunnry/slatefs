//! Per-volume metadata schema (plan §5).
//!
//! Phase 0 ships only the superblock; inode/dirent/xattr codecs land in
//! Phase 1. All values are postcard-encoded structs prefixed with a one-byte
//! format version.

pub mod superblock;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

pub fn encode_versioned<T: Serialize>(version: u8, value: &T) -> Result<Vec<u8>> {
    let mut buf = vec![version];
    buf.extend(postcard::to_allocvec(value)?);
    Ok(buf)
}

pub fn decode_versioned<T: DeserializeOwned>(expected: u8, bytes: &[u8]) -> Result<T> {
    match bytes.split_first() {
        Some((&version, rest)) if version == expected => Ok(postcard::from_bytes(rest)?),
        Some((&version, _)) => Err(Error::invalid(
            "record",
            format!("format version {version}, expected {expected}"),
        )),
        None => Err(Error::invalid("record", "empty value")),
    }
}
