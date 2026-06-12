//! Per-volume key schema (plan §5). Single-byte record-type tag, then
//! big-endian fixed-width integers so lexicographic key order equals numeric
//! order. No separators: every component is fixed-width except trailing
//! variable-length names, which are always the last component.
//!
//! ```text
//! M                          superblock
//! i <ino:8>                  inode
//! d <parent:8> <enc_name…>   dirent (name AES-SIV-encrypted, DD-3)
//! e <parent:8> <dirent_id:8> readdir index (cookie = dirent_id)
//! c <ino:8> <chunk:4>        content chunk
//! s <ino:8>                  symlink target
//! x <ino:8> <name…>          xattr
//! o <ino:8>                  orphan marker
//! qB / qI                    quota usage counters (merge-operator i64)
//! a                          inode allocator high-water mark
//! ```

pub const KEY_QUOTA_BYTES: &[u8] = b"qB";
pub const KEY_QUOTA_INODES: &[u8] = b"qI";
pub const KEY_NEXT_INO: &[u8] = b"a";

pub fn inode(ino: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'i';
    k[1..].copy_from_slice(&ino.to_be_bytes());
    k
}

pub fn dirent(parent: u64, enc_name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(9 + enc_name.len());
    k.push(b'd');
    k.extend_from_slice(&parent.to_be_bytes());
    k.extend_from_slice(enc_name);
    k
}

pub fn dirent_prefix(parent: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'd';
    k[1..].copy_from_slice(&parent.to_be_bytes());
    k
}

pub fn dirent_idx(parent: u64, dirent_id: u64) -> [u8; 17] {
    let mut k = [0u8; 17];
    k[0] = b'e';
    k[1..9].copy_from_slice(&parent.to_be_bytes());
    k[9..].copy_from_slice(&dirent_id.to_be_bytes());
    k
}

pub fn dirent_idx_prefix(parent: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'e';
    k[1..].copy_from_slice(&parent.to_be_bytes());
    k
}

pub fn chunk(ino: u64, chunk: u32) -> [u8; 13] {
    let mut k = [0u8; 13];
    k[0] = b'c';
    k[1..9].copy_from_slice(&ino.to_be_bytes());
    k[9..].copy_from_slice(&chunk.to_be_bytes());
    k
}

pub fn chunk_prefix(ino: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'c';
    k[1..].copy_from_slice(&ino.to_be_bytes());
    k
}

/// Chunk index from a `c`-tagged key (for scans/fsck).
pub fn parse_chunk(key: &[u8]) -> Option<(u64, u32)> {
    if key.len() == 13 && key[0] == b'c' {
        Some((
            u64::from_be_bytes(key[1..9].try_into().unwrap()),
            u32::from_be_bytes(key[9..13].try_into().unwrap()),
        ))
    } else {
        None
    }
}

/// `dirent_id` from an `e`-tagged key.
pub fn parse_dirent_idx(key: &[u8]) -> Option<(u64, u64)> {
    if key.len() == 17 && key[0] == b'e' {
        Some((
            u64::from_be_bytes(key[1..9].try_into().unwrap()),
            u64::from_be_bytes(key[9..17].try_into().unwrap()),
        ))
    } else {
        None
    }
}

/// Ino from a fixed single-int key (`i`, `s`, `o`, or prefix of `d`/`e`/`c`).
pub fn parse_ino(key: &[u8]) -> Option<u64> {
    if key.len() >= 9 {
        Some(u64::from_be_bytes(key[1..9].try_into().unwrap()))
    } else {
        None
    }
}

pub fn symlink(ino: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b's';
    k[1..].copy_from_slice(&ino.to_be_bytes());
    k
}

pub fn xattr(ino: u64, name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(9 + name.len());
    k.push(b'x');
    k.extend_from_slice(&ino.to_be_bytes());
    k.extend_from_slice(name);
    k
}

pub fn xattr_prefix(ino: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'x';
    k[1..].copy_from_slice(&ino.to_be_bytes());
    k
}

pub fn orphan(ino: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'o';
    k[1..].copy_from_slice(&ino.to_be_bytes());
    k
}

pub const ORPHAN_PREFIX: &[u8] = b"o";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_matches_numeric_order() {
        // Chunk keys for one ino sort by chunk index, and stay inside the
        // ino's prefix.
        assert!(chunk(5, 1) < chunk(5, 2));
        assert!(chunk(5, u32::MAX) < chunk(6, 0));
        assert!(chunk(5, 0).starts_with(&chunk_prefix(5)));

        // Dirent-index keys sort by dirent_id within a parent.
        assert!(dirent_idx(7, 3) < dirent_idx(7, 4));
        assert!(dirent_idx(7, u64::MAX) < dirent_idx(8, 0));
    }

    #[test]
    fn parse_roundtrip() {
        assert_eq!(parse_chunk(&chunk(42, 7)), Some((42, 7)));
        assert_eq!(parse_dirent_idx(&dirent_idx(42, 9)), Some((42, 9)));
        assert_eq!(parse_ino(&inode(42)), Some(42));
        assert_eq!(parse_ino(&orphan(42)), Some(42));
        assert_eq!(parse_chunk(&inode(42)), None);
    }
}
