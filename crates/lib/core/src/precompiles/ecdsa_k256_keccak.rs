//! ECDSA secp256k1 / Keccak256 precompile.
//!
//! Single discriminant `verify` (disc 0) — chunk-bodied predicate over a 5-chunk (40-felt) buffer
//! packed `pk[9] || digest[8] || sig[17] || pad[6]`. Succeeds iff `pk.verify_prehash(digest, sig)`.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder, precompile_id,
    },
    serde::Deserializable,
};
use miden_crypto::dsa::ecdsa_k256_keccak::{
    PublicKey as EcdsaPublicKey, Signature as EcdsaSignature,
};

use super::codec::{BYTES_PER_CHUNK, chunks_to_bytes};

/// Zero-sized handle for the `ecdsa_k256_keccak` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaK256KeccakPrecompile;

impl EcdsaK256KeccakPrecompile {
    /// Precompile name — hashed into `id`. Renaming breaks decoding for existing programs.
    pub const NAME: &'static str = "ecdsa_k256_keccak";

    pub const VERIFY_TAG_ID: u32 = 0;

    /// Bytes-per-field-component: pk=33, digest=32, sig=65.
    ///
    /// Each component is placed at a word-aligned felt boundary inside the chunk so MASM can
    /// store each piece with `loc_storew_le.N` (N divisible by 4):
    ///
    /// ```text
    ///   felts[0..9]    pk      → bytes[0..33] real + bytes[33..36] zero pad inside felt[8]
    ///   felts[9..12]   zero    → bytes[36..48] zero pad (aligns digest to felt[12])
    ///   felts[12..20]  digest  → bytes[48..80]
    ///   felts[20..37]  sig     → bytes[80..145] real + bytes[145..148] zero pad inside felt[36]
    ///   felts[37..40]  zero    → bytes[148..160] trailing zero pad
    /// ```
    ///
    /// 40 felts × 4 bytes/felt = 160 bytes total = 5 chunks. The kernel slices by known offsets
    /// and validates all pad regions are zero.
    pub const PK_BYTES: usize = 33;
    pub const DIGEST_BYTES: usize = 32;
    pub const SIG_BYTES: usize = 65;
    /// Byte offset where the digest component starts in the unpacked chunk.
    pub const DIGEST_OFFSET: usize = 48;
    /// Byte offset where the signature component starts in the unpacked chunk.
    pub const SIG_OFFSET: usize = 80;

    pub fn id() -> Felt {
        precompile_id(&EcdsaK256KeccakPrecompile)
    }

    pub fn verify_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::VERIFY_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a `verify` chunk-bodied predicate from caller-supplied chunks.
    /// The caller must pack `pk || digest || sig` (u32-LE) contiguously and zero-pad to the
    /// 5-chunk (40-felt) boundary.
    pub fn verify_node(chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::verify_tag(), chunks)
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
            // pk[9] || digest[8] || sig[17] || pad[6] = 40 felts = 5 chunks.
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

/// Reduce a `verify` chunk predicate. See `EcdsaK256KeccakPrecompile::*_BYTES` constants for the
/// chunk byte layout. Validates all pad regions are zero, deserialises pk/digest/sig via
/// `miden-crypto`, runs `PublicKey::verify_prehash`.
fn reduce_verify(payload: &Payload) -> Result<Node, PrecompileError> {
    let chunks = payload.as_chunks()?;
    if chunks.len() != 5 {
        return Err(PrecompileError::InvalidNode);
    }
    let total_bytes = 5 * BYTES_PER_CHUNK as usize; // 160
    let bytes = chunks_to_bytes(chunks, total_bytes)?;

    let pk_end = EcdsaK256KeccakPrecompile::PK_BYTES; // 33
    let digest_start = EcdsaK256KeccakPrecompile::DIGEST_OFFSET; // 48
    let digest_end = digest_start + EcdsaK256KeccakPrecompile::DIGEST_BYTES; // 80
    let sig_start = EcdsaK256KeccakPrecompile::SIG_OFFSET; // 80
    let sig_end = sig_start + EcdsaK256KeccakPrecompile::SIG_BYTES; // 145

    // Three pad regions must all be zero. A non-zero pad would let the prover smuggle data
    // through the chunk-digest binding without affecting the kernel result.
    if bytes[pk_end..digest_start].iter().any(|&b| b != 0) {
        return Err(PrecompileError::InvalidNode);
    }
    if bytes[sig_end..].iter().any(|&b| b != 0) {
        return Err(PrecompileError::InvalidNode);
    }

    let pk = EcdsaPublicKey::read_from_bytes(&bytes[..pk_end])
        .map_err(|_| PrecompileError::AssertionFailed)?;
    let digest: [u8; 32] = bytes[digest_start..digest_end]
        .try_into()
        .expect("DIGEST_BYTES sliced to 32 bytes");
    let sig = EcdsaSignature::read_from_bytes(&bytes[sig_start..sig_end])
        .map_err(|_| PrecompileError::AssertionFailed)?;

    if pk.verify_prehash(digest, &sig) {
        Ok(Node::TRUE)
    } else {
        Err(PrecompileError::AssertionFailed)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
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
            PrecompileRegistry::default().with_precompile(EcdsaK256KeccakPrecompile),
            DeferredState::new(),
        )
    }

    #[test]
    fn decode_verify_is_5_chunk_predicate() {
        let info = EcdsaK256KeccakPrecompile
            .decode([Felt::from_u32(EcdsaK256KeccakPrecompile::VERIFY_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Chunks(n) if n.get() == 5));
    }

    fn pack_ecdsa(pk: &[u8], digest: &[u8], sig: &[u8]) -> Vec<[Felt; 8]> {
        assert_eq!(pk.len(), 33);
        assert_eq!(digest.len(), 32);
        assert_eq!(sig.len(), 65);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(pk);
        buf[48..80].copy_from_slice(digest);
        buf[80..145].copy_from_slice(sig);
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
    fn verify_succeeds_on_valid_signature() {
        let (precompiles, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let chunks = pack_ecdsa(&pk_bytes, &digest, &sig_bytes);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let result = state.evaluate_node(&precompiles, node).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let (precompiles, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, mut sig_bytes) = ecdsa_keypair_and_sig(digest);
        sig_bytes[0] ^= 0xff;
        let chunks = pack_ecdsa(&pk_bytes, &digest, &sig_bytes);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate_node(&precompiles, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn verify_fails_on_tampered_digest() {
        let (precompiles, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0xff;
        let chunks = pack_ecdsa(&pk_bytes, &wrong_digest, &sig_bytes);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate_node(&precompiles, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn verify_rejects_nonzero_padding_after_pk() {
        let (precompiles, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(&pk_bytes);
        buf[40] = 0xaa; // in the pad region
        buf[48..80].copy_from_slice(&digest);
        buf[80..145].copy_from_slice(&sig_bytes);
        let chunks = pack_chunks(&buf);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate_node(&precompiles, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn verify_rejects_nonzero_trailing_padding() {
        let (precompiles, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(&pk_bytes);
        buf[48..80].copy_from_slice(&digest);
        buf[80..145].copy_from_slice(&sig_bytes);
        buf[150] = 0xaa;
        let chunks = pack_chunks(&buf);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate_node(&precompiles, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }
}
