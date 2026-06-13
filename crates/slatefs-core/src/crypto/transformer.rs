//! [`slatedb::BlockTransformer`] implementation (DD-2, plan §7).
//!
//! SlateDB calls `encode` on every SST/WAL block *after* compression and
//! computes checksums over the transformed bytes, so the at-rest pipeline is
//! compress → encrypt → checksum. One transformer instance per volume,
//! constructed from that volume's DEK.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use super::{Cipher, Secret32, aead};

/// AAD versioning the block format; bumping it deliberately breaks decode of
/// blocks written under a different version.
const BLOCK_AAD: &[u8] = b"slatefs/block/v1";

/// Security counters for one block transformer.
#[derive(Debug, Clone, Default)]
pub struct BlockTransformMetrics {
    decode_failures: Arc<AtomicU64>,
}

impl BlockTransformMetrics {
    pub fn decode_failures(&self) -> u64 {
        self.decode_failures.load(Ordering::Relaxed)
    }

    fn note_decode_failure(&self) {
        self.decode_failures.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct SlateBlockTransformer {
    cipher: Cipher,
    dek: Secret32,
    metrics: Option<BlockTransformMetrics>,
}

impl SlateBlockTransformer {
    pub fn new(cipher: Cipher, dek: Secret32) -> Self {
        SlateBlockTransformer {
            cipher,
            dek,
            metrics: None,
        }
    }

    pub fn with_metrics(
        cipher: Cipher,
        dek: Secret32,
        metrics: BlockTransformMetrics,
    ) -> SlateBlockTransformer {
        SlateBlockTransformer {
            cipher,
            dek,
            metrics: Some(metrics),
        }
    }
}

#[async_trait::async_trait]
impl slatedb::BlockTransformer for SlateBlockTransformer {
    async fn encode(&self, data: Bytes) -> Result<Bytes, slatedb::Error> {
        let sealed = aead::seal(self.cipher, &self.dek, BLOCK_AAD, &data)
            .map_err(|e| slatedb::Error::data(format!("block encrypt failed: {e}")))?;
        Ok(Bytes::from(sealed))
    }

    async fn decode(&self, data: Bytes) -> Result<Bytes, slatedb::Error> {
        // Fail closed (plan §7): any AEAD failure is surfaced as corrupted
        // data, never as plaintext-questionable bytes. This is a security
        // signal for alerting.
        let opened = aead::open(self.cipher, &self.dek, BLOCK_AAD, &data).map_err(|e| {
            if let Some(metrics) = &self.metrics {
                metrics.note_decode_failure();
            }
            tracing::error!(cipher = %self.cipher, "block AEAD open failed: {e}");
            slatedb::Error::data(format!("block decrypt failed: {e}"))
        })?;
        Ok(Bytes::from(opened))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slatedb::BlockTransformer;

    #[tokio::test]
    async fn roundtrip_and_fail_closed() {
        for cipher in [Cipher::Aes256Gcm, Cipher::XChaCha20Poly1305] {
            let dek = Secret32::generate();
            let metrics = BlockTransformMetrics::default();
            let t = SlateBlockTransformer::with_metrics(cipher, dek.clone(), metrics.clone());
            let block = Bytes::from_static(b"compressed block bytes");

            let encoded = t.encode(block.clone()).await.unwrap();
            assert_ne!(encoded, block);
            assert_eq!(t.decode(encoded.clone()).await.unwrap(), block);
            assert_eq!(metrics.decode_failures(), 0);

            // Wrong DEK fails closed.
            let other = SlateBlockTransformer::new(cipher, Secret32::generate());
            assert!(other.decode(encoded.clone()).await.is_err());
            assert_eq!(metrics.decode_failures(), 0);

            // Tampered block fails closed.
            let mut tampered = encoded.to_vec();
            tampered[5] ^= 0xff;
            assert!(t.decode(Bytes::from(tampered)).await.is_err());
            assert_eq!(metrics.decode_failures(), 1);
        }
    }

    #[tokio::test]
    async fn nonces_are_fresh_per_block() {
        let t = SlateBlockTransformer::new(Cipher::Aes256Gcm, Secret32::generate());
        let block = Bytes::from_static(b"same plaintext");
        let a = t.encode(block.clone()).await.unwrap();
        let b = t.encode(block).await.unwrap();
        assert_ne!(a, b, "deterministic block encryption would leak equality");
    }
}
