//! Chunked content paths (DD-6, plan §6). Files are split into fixed-size
//! chunks at `c/<ino>/<idx>`; an absent chunk reads as zeros, so sparse files
//! are free. These helpers *plan* mutations — they read whatever
//! read-modify-write state they need and return the chunk puts/deletes plus
//! the billed-bytes delta; the caller assembles the single atomic batch.

use bytes::Bytes;
use slatedb::Db;

use crate::error::Result;
use crate::meta::keys;
use crate::quota::billed_chunk_bytes;

pub fn chunk_of(offset: u64, chunk_size: u64) -> u32 {
    (offset / chunk_size) as u32
}

/// Read `[offset, offset+len)` clamped to `size`. Multi-chunk reads go
/// through a snapshot so a concurrent write can't tear the result (§6).
pub async fn read_range(
    db: &Db,
    chunk_size: u64,
    ino: u64,
    size: u64,
    offset: u64,
    len: u32,
) -> Result<Bytes> {
    if offset >= size || len == 0 {
        return Ok(Bytes::new());
    }
    let end = size.min(offset + len as u64);
    let first = chunk_of(offset, chunk_size);
    let last = chunk_of(end - 1, chunk_size);

    let mut out = vec![0u8; (end - offset) as usize];
    if first == last {
        if let Some(chunk) = db.get(keys::chunk(ino, first)).await? {
            copy_from_chunk(&mut out, offset, first, &chunk, chunk_size);
        }
        return Ok(Bytes::from(out));
    }

    let snapshot = db.snapshot().await?;
    for idx in first..=last {
        if let Some(chunk) = snapshot.get(keys::chunk(ino, idx)).await? {
            copy_from_chunk(&mut out, offset, idx, &chunk, chunk_size);
        }
    }
    Ok(Bytes::from(out))
}

fn copy_from_chunk(out: &mut [u8], read_offset: u64, idx: u32, chunk: &[u8], chunk_size: u64) {
    let chunk_start = idx as u64 * chunk_size;
    // Overlap of [chunk_start, chunk_start+chunk.len()) with the read window.
    let from = read_offset.max(chunk_start);
    let to = (read_offset + out.len() as u64).min(chunk_start + chunk.len() as u64);
    if from >= to {
        return;
    }
    let src = (from - chunk_start) as usize..(to - chunk_start) as usize;
    let dst = (from - read_offset) as usize..(to - read_offset) as usize;
    out[dst].copy_from_slice(&chunk[src]);
}

pub struct WritePlan {
    /// Full chunk values to put (read-modify-written where partial).
    pub puts: Vec<(u32, Bytes)>,
    pub new_size: u64,
    /// Change in billed bytes (drives the `qB` merge and `billed_bytes`).
    pub billed_delta: i64,
}

/// Plan writing `data` at `offset`. Reads partial first/last chunks (RMW) and
/// probes existence of overwritten chunks below the old size so the billed
/// delta is exact; chunks at/above the old size cannot exist (truncate
/// leftovers bill 0 and are overwritten here anyway).
pub async fn plan_write(
    db: &Db,
    chunk_size: u64,
    ino: u64,
    old_size: u64,
    offset: u64,
    data: &[u8],
) -> Result<WritePlan> {
    debug_assert!(!data.is_empty());
    let end = offset + data.len() as u64;
    let new_size = old_size.max(end);
    let first = chunk_of(offset, chunk_size);
    let last = chunk_of(end - 1, chunk_size);

    let mut puts = Vec::with_capacity((last - first + 1) as usize);
    let mut billed_delta: i64 = 0;

    for idx in first..=last {
        let chunk_start = idx as u64 * chunk_size;
        let chunk_end = chunk_start + chunk_size;
        let write_from = offset.max(chunk_start);
        let write_to = end.min(chunk_end);

        // Existing bytes matter for RMW (partial overwrite) and for billing
        // (was this chunk allocated?). Chunks at/above old_size can't be
        // billed, so skip the read. For fully-covered chunks only existence
        // matters; the value read is the price of exact accounting — a chunk
        // bitmap can optimize this later if profiles demand.
        let old_chunk = if chunk_start >= old_size {
            None
        } else {
            db.get(keys::chunk(ino, idx)).await?
        };
        let existed = old_chunk.is_some();

        let old_len = old_chunk.as_ref().map(|c| c.len()).unwrap_or(0);
        let mut buf = old_chunk.map(|c| c.to_vec()).unwrap_or_default();
        // Chunk length covers through the written range (zero-filling any
        // gap below write_from inside this chunk — sparse-within-chunk).
        let needed = (write_to - chunk_start) as usize;
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let src_from = (write_from - offset) as usize;
        let src_to = (write_to - offset) as usize;
        buf[(write_from - chunk_start) as usize..needed].copy_from_slice(&data[src_from..src_to]);

        let old_billed = if existed {
            billed_chunk_bytes(old_size, chunk_start, old_len)
        } else {
            0
        };
        let new_billed = billed_chunk_bytes(new_size, chunk_start, buf.len());
        billed_delta += new_billed as i64 - old_billed as i64;
        puts.push((idx, Bytes::from(buf)));
    }

    Ok(WritePlan {
        puts,
        new_size,
        billed_delta,
    })
}

pub struct TruncatePlan {
    /// Trimmed tail chunk to rewrite, if the new size splits a chunk.
    pub tail_put: Option<(u32, Bytes)>,
    /// Chunk indexes to delete, ascending. May be large; the caller commits
    /// them in batches *after* the inode/quota batch (crash leaves only
    /// zero-billed trailing chunks for fsck, plan §6).
    pub deletes: Vec<u32>,
    pub billed_delta: i64,
}

/// Plan a truncate to `new_size`. Growing is metadata-only (sparse).
pub async fn plan_truncate(
    db: &Db,
    chunk_size: u64,
    ino: u64,
    old_size: u64,
    new_size: u64,
) -> Result<TruncatePlan> {
    if new_size >= old_size {
        return Ok(TruncatePlan {
            tail_put: None,
            deletes: Vec::new(),
            billed_delta: 0,
        });
    }

    let mut deletes = Vec::new();
    let mut tail_put = None;
    let mut billed_delta: i64 = 0;

    // Scan existing chunks from the first affected one; absent chunks need
    // neither deletion nor billing adjustment.
    let first_affected = chunk_of(new_size, chunk_size);
    let mut iter = db
        .scan(keys::chunk(ino, first_affected).to_vec()..keys::chunk_prefix(ino + 1).to_vec())
        .await?;
    while let Some(kv) = iter.next().await? {
        let Some((_, idx)) = keys::parse_chunk(&kv.key) else {
            break;
        };
        let chunk_start = idx as u64 * chunk_size;
        let old_billed = billed_chunk_bytes(old_size, chunk_start, kv.value.len());

        let new_billed = if chunk_start >= new_size {
            deletes.push(idx);
            0
        } else {
            // Partial tail: keep bytes below new_size, drop the rest.
            let keep = (new_size - chunk_start) as usize;
            let mut buf = kv.value.to_vec();
            if buf.len() > keep {
                buf.truncate(keep);
                let kept = buf.len() as u64;
                tail_put = Some((idx, Bytes::from(buf)));
                kept
            } else {
                buf.len() as u64
            }
        };
        billed_delta += new_billed as i64 - old_billed as i64;
    }

    Ok(TruncatePlan {
        tail_put,
        deletes,
        billed_delta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_math() {
        assert_eq!(chunk_of(0, 128), 0);
        assert_eq!(chunk_of(127, 128), 0);
        assert_eq!(chunk_of(128, 128), 1);
    }
}
