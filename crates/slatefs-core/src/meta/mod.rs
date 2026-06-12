//! Per-volume metadata schema (plan §5). All values are postcard-encoded
//! structs prefixed with a one-byte format version.

pub mod alloc;
pub mod dirent;
pub mod inode;
pub mod keys;
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
