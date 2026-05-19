//! EdDSA Ed25519 / SHA-512 precompile.
//!
//! Single discriminant `verify` (disc 0) — chunk-bodied predicate over a 5-chunk (40-felt) buffer
//! packed `pk[8] || k_digest[16] || sig[16]`. Succeeds iff
//! `pk.verify_with_unchecked_k(k_digest, sig)`.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder, precompile_id,
    },
    serde::Deserializable,
};
use miden_crypto::dsa::eddsa_25519_sha512::{
    PublicKey as EddsaPublicKey, Signature as EddsaSignature,
};

use super::codec::{BYTES_PER_CHUNK, chunks_to_bytes};

/// Zero-sized handle for the `eddsa_ed25519` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct EddsaEd25519Precompile;

impl EddsaEd25519Precompile {
    /// Precompile name — hashed into `id`. Renaming breaks decoding for existing programs.
    pub const NAME: &'static str = "eddsa_ed25519";

    pub const VERIFY_TAG_ID: u32 = 0;

    /// Bytes-per-field-component: pk=32, k_digest=64, sig=64 ⇒ 160 bytes total, 40 felts,
    /// 5 chunks exactly (no padding). `k_digest` is the externally pre-computed
    /// `SHA-512(R || A || message)` (see `verify_with_unchecked_k` docs in miden-crypto).
    pub const PK_BYTES: usize = 32;
    pub const K_DIGEST_BYTES: usize = 64;
    pub const SIG_BYTES: usize = 64;

    pub fn id() -> Felt {
        precompile_id(&EddsaEd25519Precompile)
    }

    pub fn verify_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::VERIFY_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a `verify` chunk-bodied predicate from caller-supplied chunks.
    /// The caller must pack `pk || k_digest || sig` (u32-LE) into exactly 5 chunks.
    pub fn verify_node(chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::verify_tag(), chunks)
    }
}

impl Precompile for EddsaEd25519Precompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let disc = u32::try_from(args[0].as_canonical_u64()).ok()?;
        match disc {
            // pk[8] || k_digest[16] || sig[16] = 40 felts = 5 chunks.
            Self::VERIFY_TAG_ID => {
                Some(NodeType::Chunks(NonZeroU32::new(5).expect("5 is nonzero")))
            },
            _ => None,
        }
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        _witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let disc =
            u32::try_from(args[0].as_canonical_u64()).map_err(|_| PrecompileError::InvalidNode)?;
        match disc {
            Self::VERIFY_TAG_ID => reduce_verify(payload),
            _ => Err(PrecompileError::InvalidNode),
        }
    }
}

/// Reduce a `verify` chunk predicate: unpack pk/k_digest/sig from the chunks and run
/// `PublicKey::verify_with_unchecked_k`. Returns [`Node::TRUE`] on success or `AssertionFailed`
/// on signature mismatch / deserialization failure.
///
/// Chunk layout: 5 chunks = 40 felts = 160 bytes — no padding.
///   bytes[0..32]    = pk       (32 bytes)
///   bytes[32..96]   = k_digest (SHA-512(R || A || message), 64 bytes)
///   bytes[96..160]  = sig      (R || s, 64 bytes)
fn reduce_verify(payload: &Payload) -> Result<Node, PrecompileError> {
    let chunks = payload.as_chunks()?;
    if chunks.len() != 5 {
        return Err(PrecompileError::InvalidNode);
    }
    let total_bytes = 5 * BYTES_PER_CHUNK as usize; // 160
    let bytes = chunks_to_bytes(chunks, total_bytes)?;

    let pk_end = EddsaEd25519Precompile::PK_BYTES;
    let k_digest_end = pk_end + EddsaEd25519Precompile::K_DIGEST_BYTES;
    let sig_end = k_digest_end + EddsaEd25519Precompile::SIG_BYTES;
    debug_assert_eq!(sig_end, total_bytes, "eddsa layout fills all 160 bytes exactly");

    let pk = EddsaPublicKey::read_from_bytes(&bytes[..pk_end])
        .map_err(|_| PrecompileError::AssertionFailed)?;
    let k_digest: [u8; 64] = bytes[pk_end..k_digest_end]
        .try_into()
        .expect("K_DIGEST_BYTES sliced to 64 bytes");
    let sig = EddsaSignature::read_from_bytes(&bytes[k_digest_end..sig_end])
        .map_err(|_| PrecompileError::AssertionFailed)?;

    if pk.verify_with_unchecked_k(k_digest, &sig).is_ok() {
        Ok(Node::TRUE)
    } else {
        Err(PrecompileError::AssertionFailed)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Word,
        deferred::{DeferredState, PrecompileRegistry},
        serde::Serializable,
        utils::bytes_to_packed_u32_elements,
    };

    use super::*;

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(8);
        let mut padded = felts;
        padded.resize(n_chunks * 8, ZERO);
        padded.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn fresh_state() -> (PrecompileRegistry, DeferredState) {
        (
            PrecompileRegistry::default().with_precompile(EddsaEd25519Precompile),
            DeferredState::new(),
        )
    }

    #[test]
    fn decode_verify_is_5_chunk_predicate() {
        let info = EddsaEd25519Precompile
            .decode([Felt::from_u32(EddsaEd25519Precompile::VERIFY_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Chunks(n) if n.get() == 5));
    }

    fn pack_eddsa(pk: &[u8], k_digest: &[u8], sig: &[u8]) -> Vec<[Felt; 8]> {
        assert_eq!(pk.len(), 32);
        assert_eq!(k_digest.len(), 64);
        assert_eq!(sig.len(), 64);
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(pk);
        buf.extend_from_slice(k_digest);
        buf.extend_from_slice(sig);
        assert_eq!(buf.len(), 160);
        pack_chunks(&buf)
    }

    fn eddsa_valid_triple_for_word(message: Word) -> (Vec<u8>, [u8; 64], Vec<u8>) {
        use miden_crypto::dsa::eddsa_25519_sha512::SigningKey as SecretKey;
        let sk = SecretKey::new();
        let pk = sk.public_key();
        let sig = sk.sign(message);
        let k_digest = pk.compute_challenge_k(message, &sig);
        let pk_bytes = pk.to_bytes().to_vec();
        let sig_bytes = sig.to_bytes();
        (pk_bytes, k_digest, sig_bytes)
    }

    fn eddsa_test_word(seed: u32) -> Word {
        Word::new(core::array::from_fn(|i| Felt::from_u32(seed + i as u32)))
    }

    #[test]
    fn verify_succeeds_on_valid_triple() {
        let (schema, mut state) = fresh_state();
        let (pk, k_digest, sig) = eddsa_valid_triple_for_word(eddsa_test_word(1));
        let chunks = pack_eddsa(&pk, &k_digest, &sig);
        let node = EddsaEd25519Precompile::verify_node(chunks);
        let result = state.evaluate(&schema, node).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let (schema, mut state) = fresh_state();
        let (pk, k_digest, mut sig) = eddsa_valid_triple_for_word(eddsa_test_word(11));
        sig[0] ^= 0xff;
        let chunks = pack_eddsa(&pk, &k_digest, &sig);
        let node = EddsaEd25519Precompile::verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn verify_fails_on_tampered_k_digest() {
        let (schema, mut state) = fresh_state();
        let (pk, mut k_digest, sig) = eddsa_valid_triple_for_word(eddsa_test_word(22));
        k_digest[0] ^= 0xff;
        let chunks = pack_eddsa(&pk, &k_digest, &sig);
        let node = EddsaEd25519Precompile::verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }
}
