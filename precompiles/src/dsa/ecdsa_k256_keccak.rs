//! ECDSA secp256k1 / Keccak256 deferred precompile.
//!
//! Single discriminant `verify` (disc 0) — data-bodied predicate over a 5-chunk (40-felt) buffer
//! packing `pk || digest || sig` (130 bytes, zero-padded to the chunk boundary). Succeeds iff
//! `pk.verify_prehash(digest, sig)`.

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
use miden_crypto::dsa::ecdsa_k256_keccak::{
    PublicKey as EcdsaPublicKey, Signature as EcdsaSignature,
};

use crate::codec::chunks_to_bytes;

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the `ecdsa_k256_keccak` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaK256KeccakPrecompile;

impl EcdsaK256KeccakPrecompile {
    /// Stable name hashed into the precompile id; renaming changes every tag it owns.
    pub const NAME: &'static str = "ecdsa_k256_keccak";

    /// Local discriminant of the `verify` predicate tag.
    pub const VERIFY_TAG_ID: u32 = 0;

    /// Data chunk count of the `verify` predicate body (40 felts).
    pub const VERIFY_CHUNKS: u32 = 5;

    /// Component byte lengths, packed tightly as `pk || digest || sig` (130 bytes) and zero-padded
    /// to the 5-chunk (40-felt / 160-byte) buffer:
    ///
    /// ```text
    ///   bytes[0..33]     pk
    ///   bytes[33..65]    digest
    ///   bytes[65..130]   sig
    ///   bytes[130..160]  zero pad (chunk boundary)
    /// ```
    ///
    /// `evaluate` strips and zero-checks the trailing pad through the shared codec, so a prover
    /// cannot smuggle data past the chunk-digest binding.
    pub const PK_BYTES: usize = 33;
    pub const DIGEST_BYTES: usize = 32;
    pub const SIG_BYTES: usize = 65;

    /// Derives this precompile's id from [`Self::NAME`].
    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    /// Tag for the `verify` predicate node.
    pub fn verify_tag() -> Tag {
        Tag::precompile(Self::id(), [Felt::from_u32(Self::VERIFY_TAG_ID), ZERO, ZERO])
            .expect("ecdsa_k256_keccak precompile id is not framework-reserved")
    }

    /// Builds a `verify` predicate from caller-supplied data chunks.
    ///
    /// The caller must pack `pk || digest || sig` (u32-LE) at the component offsets above and
    /// zero-pad to the 5-chunk (40-felt) boundary.
    pub fn verify_node(chunks: impl Into<Arc<[DataChunk]>>) -> Node {
        Node::try_data(Self::verify_tag(), chunks)
            .expect("verify body carries a fixed nonzero data chunk count")
    }
}

impl Precompile for EcdsaK256KeccakPrecompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let disc = u32::try_from(args[0].as_canonical_u64()).ok()?;
        match disc {
            // pk || digest || sig (130 bytes) zero-padded to 40 felts = 5 chunks.
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

/// Evaluates a `verify` predicate: unpack the tightly packed `pk || digest || sig` buffer (the
/// codec zero-checks the trailing pad), deserialize the components via `miden-crypto`, and run
/// [`PublicKey::verify_prehash`].
///
/// [`PublicKey::verify_prehash`]: EcdsaPublicKey::verify_prehash
fn evaluate_verify(payload: &Payload) -> Result<Node, PrecompileError> {
    let chunks = payload.as_data()?;
    if chunks.len() != EcdsaK256KeccakPrecompile::VERIFY_CHUNKS as usize {
        return Err(PrecompileError::InvalidNode);
    }
    // `pk || digest || sig` packed tightly; `chunks_to_bytes` strips and zero-checks the trailing
    // chunk-boundary pad.
    let pk_end = EcdsaK256KeccakPrecompile::PK_BYTES; // 33
    let digest_end = pk_end + EcdsaK256KeccakPrecompile::DIGEST_BYTES; // 65
    let sig_end = digest_end + EcdsaK256KeccakPrecompile::SIG_BYTES; // 130
    let bytes = chunks_to_bytes(chunks, sig_end)?;

    let pk = EcdsaPublicKey::read_from_bytes(&bytes[..pk_end])
        .map_err(|_| PrecompileError::AssertionFailed)?;
    let digest: [u8; 32] =
        bytes[pk_end..digest_end].try_into().expect("DIGEST_BYTES sliced to 32 bytes");
    let sig = EcdsaSignature::read_from_bytes(&bytes[digest_end..sig_end])
        .map_err(|_| PrecompileError::AssertionFailed)?;

    if pk.verify_prehash(digest, &sig) {
        Ok(Node::TRUE)
    } else {
        Err(PrecompileError::AssertionFailed)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};

    use miden_core::{
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
            Arc::new(PrecompileRegistry::new().with_precompile(EcdsaK256KeccakPrecompile)),
            usize::MAX,
        )
        .expect("ecdsa precompile initialization should fit the test budget")
    }

    /// Registers `node` (which evaluates eagerly) and returns its canonical form or the eager
    /// error.
    fn evaluate(state: &mut DeferredState, node: Node) -> Result<Node, PrecompileError> {
        let digest = state.register(node)?;
        let canonical = state.evaluate_digest(digest)?;
        state.get_node(&canonical).cloned().ok_or(PrecompileError::InvalidNode)
    }

    /// Packs a (pk, digest, sig) triple into the precompile's tightly-packed 40-felt buffer.
    fn pack_ecdsa(pk: &[u8], digest: &[u8], sig: &[u8]) -> Vec<DataChunk> {
        assert_eq!(pk.len(), 33);
        assert_eq!(digest.len(), 32);
        assert_eq!(sig.len(), 65);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(pk);
        buf[33..65].copy_from_slice(digest);
        buf[65..130].copy_from_slice(sig);
        pack_chunks(&buf)
    }

    fn ecdsa_keypair_and_sig(digest: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey as SecretKey;
        let sk = SecretKey::new();
        let pk_bytes = sk.public_key().to_bytes().to_vec();
        let sig_bytes = sk.sign_prehash(digest).to_bytes().to_vec();
        (pk_bytes, sig_bytes)
    }

    #[test]
    fn decode_verify_is_5_chunk_predicate() {
        let info = EcdsaK256KeccakPrecompile
            .decode([Felt::from_u32(EcdsaK256KeccakPrecompile::VERIFY_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Data(n) if n.get() == 5));
    }

    #[test]
    fn decode_rejects_nonzero_unused_args() {
        let one = Felt::from_u32(1);
        assert!(
            EcdsaK256KeccakPrecompile
                .decode([Felt::from_u32(EcdsaK256KeccakPrecompile::VERIFY_TAG_ID), one, ZERO])
                .is_none()
        );
        assert!(
            EcdsaK256KeccakPrecompile
                .decode([Felt::from_u32(EcdsaK256KeccakPrecompile::VERIFY_TAG_ID), ZERO, one])
                .is_none()
        );
    }

    #[test]
    fn verify_succeeds_on_valid_signature() {
        let mut state = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let node =
            EcdsaK256KeccakPrecompile::verify_node(pack_ecdsa(&pk_bytes, &digest, &sig_bytes));
        assert!(evaluate(&mut state, node).unwrap().is_true());
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let mut state = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, mut sig_bytes) = ecdsa_keypair_and_sig(digest);
        sig_bytes[0] ^= 0xff;
        let node =
            EcdsaK256KeccakPrecompile::verify_node(pack_ecdsa(&pk_bytes, &digest, &sig_bytes));
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::AssertionFailed
        ));
    }

    #[test]
    fn verify_fails_on_tampered_digest() {
        let mut state = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0xff;
        let node = EcdsaK256KeccakPrecompile::verify_node(pack_ecdsa(
            &pk_bytes,
            &wrong_digest,
            &sig_bytes,
        ));
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::AssertionFailed
        ));
    }

    #[test]
    fn verify_rejects_nonzero_trailing_padding() {
        let mut state = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(&pk_bytes);
        buf[33..65].copy_from_slice(&digest);
        buf[65..130].copy_from_slice(&sig_bytes);
        buf[150] = 0xaa; // trailing pad region
        let node = EcdsaK256KeccakPrecompile::verify_node(pack_chunks(&buf));
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }

    #[test]
    fn masm_pinned_ids_match_derived_ids() {
        const MASM: &str = include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm");
        assert_eq!(
            masm_const(MASM, "PRECOMPILE_ID"),
            EcdsaK256KeccakPrecompile::id().as_canonical_u64(),
        );
        assert_eq!(
            masm_const(MASM, "VERIFY_TAG_ID"),
            EcdsaK256KeccakPrecompile::VERIFY_TAG_ID as u64,
        );
    }
}
