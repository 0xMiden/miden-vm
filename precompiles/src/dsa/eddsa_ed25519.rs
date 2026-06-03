//! EdDSA Ed25519 / SHA-512 deferred precompile.
//!
//! Single discriminant `verify` (disc 0) — data-bodied predicate over a 5-chunk (40-felt) buffer
//! packed `pk[8] || k_digest[16] || sig[16]`. Succeeds iff
//! `pk.verify_with_unchecked_k(k_digest, sig)`.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DataChunk, DeferredContext, Node, NodeType, Payload, Precompile, PrecompileError, Tag,
        precompile_id,
    },
    serde::Deserializable,
};
use miden_crypto::dsa::eddsa_25519_sha512::{
    PublicKey as EddsaPublicKey, Signature as EddsaSignature,
};

use crate::codec::chunks_to_bytes;

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the `eddsa_ed25519` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct EddsaEd25519Precompile;

impl EddsaEd25519Precompile {
    /// Stable name hashed into the precompile id; renaming changes every tag it owns.
    pub const NAME: &'static str = "eddsa_ed25519";

    /// Local discriminant of the `verify` predicate tag.
    pub const VERIFY_TAG_ID: u32 = 0;

    /// Data chunk count of the `verify` predicate body (40 felts).
    pub const VERIFY_CHUNKS: u32 = 5;

    /// Component byte lengths: pk=32, k_digest=64, sig=64 ⇒ 160 bytes = 40 felts = 5 chunks
    /// exactly (no padding). `k_digest` is the externally precomputed `SHA-512(R || A || message)`
    /// (see `verify_with_unchecked_k` in miden-crypto). The component layout is:
    ///
    /// ```text
    ///   felts[0..8]    pk       → bytes[0..32]
    ///   felts[8..24]   k_digest → bytes[32..96]
    ///   felts[24..40]  sig      → bytes[96..160]
    /// ```
    pub const PK_BYTES: usize = 32;
    pub const K_DIGEST_BYTES: usize = 64;
    pub const SIG_BYTES: usize = 64;

    /// Derives this precompile's id from [`Self::NAME`].
    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    /// Tag for the `verify` predicate node.
    pub fn verify_tag() -> Tag {
        Tag::precompile(Self::id(), [Felt::from_u32(Self::VERIFY_TAG_ID), ZERO, ZERO])
            .expect("eddsa_ed25519 precompile id is not framework-reserved")
    }

    /// Builds a `verify` predicate from caller-supplied data chunks.
    ///
    /// The caller must pack `pk || k_digest || sig` (u32-LE) into exactly 5 chunks.
    pub fn verify_node(chunks: impl Into<Arc<[DataChunk]>>) -> Node {
        Node::try_data(Self::verify_tag(), chunks)
            .expect("verify body carries a fixed nonzero data chunk count")
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
            Self::VERIFY_TAG_ID if args[1] == ZERO && args[2] == ZERO => {
                Some(NodeType::Data(NonZeroU32::new(Self::VERIFY_CHUNKS).expect("5 is nonzero")))
            },
            _ => None,
        }
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        _context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let disc =
            u32::try_from(args[0].as_canonical_u64()).map_err(|_| PrecompileError::InvalidNode)?;
        match disc {
            Self::VERIFY_TAG_ID => evaluate_verify(payload),
            _ => Err(PrecompileError::InvalidNode),
        }
    }
}

/// Evaluates a `verify` predicate: unpack pk/k_digest/sig from the 5-chunk buffer and run
/// [`PublicKey::verify_with_unchecked_k`]. Returns [`Node::TRUE`] on success, or `AssertionFailed`
/// on signature mismatch / deserialization failure.
///
/// [`PublicKey::verify_with_unchecked_k`]: EddsaPublicKey::verify_with_unchecked_k
fn evaluate_verify(payload: &Payload) -> Result<Node, PrecompileError> {
    let chunks = payload.as_data()?;
    if chunks.len() != EddsaEd25519Precompile::VERIFY_CHUNKS as usize {
        return Err(PrecompileError::InvalidNode);
    }
    // `pk || k_digest || sig` fills the 5-chunk buffer exactly (no padding).
    let pk_end = EddsaEd25519Precompile::PK_BYTES; // 32
    let k_digest_end = pk_end + EddsaEd25519Precompile::K_DIGEST_BYTES; // 96
    let sig_end = k_digest_end + EddsaEd25519Precompile::SIG_BYTES; // 160
    let bytes = chunks_to_bytes(chunks, sig_end)?;

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
    use alloc::{sync::Arc, vec::Vec};

    use miden_core::{
        Word,
        deferred::{DeferredState, PrecompileRegistry},
        serde::Serializable,
        utils::bytes_to_packed_u32_elements,
    };

    use super::*;
    use crate::hash::masm_const;

    fn pack_chunks(bytes: &[u8]) -> Vec<DataChunk> {
        let mut felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(8).max(1);
        felts.resize(n_chunks * 8, ZERO);
        felts.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn fresh_state() -> DeferredState {
        DeferredState::new(
            Arc::new(PrecompileRegistry::new().with_precompile(EddsaEd25519Precompile)),
            usize::MAX,
        )
        .expect("eddsa precompile initialization should fit the test budget")
    }

    /// Registers `node` (which evaluates eagerly) and returns its canonical form or the eager
    /// error.
    fn evaluate(state: &mut DeferredState, node: Node) -> Result<Node, PrecompileError> {
        let digest = state.register(node)?;
        let canonical = state.evaluate_digest(digest)?;
        state.get_node(&canonical).cloned().ok_or(PrecompileError::InvalidNode)
    }

    fn pack_eddsa(pk: &[u8], k_digest: &[u8], sig: &[u8]) -> Vec<DataChunk> {
        assert_eq!(pk.len(), 32);
        assert_eq!(k_digest.len(), 64);
        assert_eq!(sig.len(), 64);
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(pk);
        buf.extend_from_slice(k_digest);
        buf.extend_from_slice(sig);
        pack_chunks(&buf)
    }

    fn eddsa_valid_triple(message: Word) -> (Vec<u8>, [u8; 64], Vec<u8>) {
        use miden_crypto::dsa::eddsa_25519_sha512::SigningKey as SecretKey;
        let sk = SecretKey::new();
        let pk = sk.public_key();
        let sig = sk.sign(message);
        let k_digest = pk.compute_challenge_k(message, &sig);
        (pk.to_bytes().to_vec(), k_digest, sig.to_bytes())
    }

    fn eddsa_test_word(seed: u32) -> Word {
        Word::new(core::array::from_fn(|i| Felt::from_u32(seed + i as u32)))
    }

    #[test]
    fn decode_verify_is_5_chunk_predicate() {
        let info = EddsaEd25519Precompile
            .decode([Felt::from_u32(EddsaEd25519Precompile::VERIFY_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Data(n) if n.get() == 5));
    }

    #[test]
    fn decode_rejects_nonzero_unused_args() {
        let one = Felt::from_u32(1);
        assert!(
            EddsaEd25519Precompile
                .decode([Felt::from_u32(EddsaEd25519Precompile::VERIFY_TAG_ID), one, ZERO])
                .is_none()
        );
        assert!(
            EddsaEd25519Precompile
                .decode([Felt::from_u32(EddsaEd25519Precompile::VERIFY_TAG_ID), ZERO, one])
                .is_none()
        );
    }

    #[test]
    fn verify_succeeds_on_valid_triple() {
        let mut state = fresh_state();
        let (pk, k_digest, sig) = eddsa_valid_triple(eddsa_test_word(1));
        let node = EddsaEd25519Precompile::verify_node(pack_eddsa(&pk, &k_digest, &sig));
        assert!(evaluate(&mut state, node).unwrap().is_true());
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let mut state = fresh_state();
        let (pk, k_digest, mut sig) = eddsa_valid_triple(eddsa_test_word(11));
        sig[0] ^= 0xff;
        let node = EddsaEd25519Precompile::verify_node(pack_eddsa(&pk, &k_digest, &sig));
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::AssertionFailed
        ));
    }

    #[test]
    fn verify_fails_on_tampered_k_digest() {
        let mut state = fresh_state();
        let (pk, mut k_digest, sig) = eddsa_valid_triple(eddsa_test_word(22));
        k_digest[0] ^= 0xff;
        let node = EddsaEd25519Precompile::verify_node(pack_eddsa(&pk, &k_digest, &sig));
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::AssertionFailed
        ));
    }

    #[test]
    fn masm_pinned_ids_match_derived_ids() {
        const MASM: &str = include_str!("../../asm/crypto/dsa/eddsa_ed25519.masm");
        assert_eq!(
            masm_const(MASM, "PRECOMPILE_ID"),
            EddsaEd25519Precompile::id().as_canonical_u64(),
        );
        assert_eq!(masm_const(MASM, "VERIFY_TAG_ID"), EddsaEd25519Precompile::VERIFY_TAG_ID as u64);
    }
}
