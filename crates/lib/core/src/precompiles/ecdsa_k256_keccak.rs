//! ECDSA secp256k1 / Keccak256 precompile app.
//!
//! Single discriminant `verify` — chunk-bodied predicate over a 5-chunk (40-felt) buffer
//! packed `pk[9] || digest[8] || sig[17] || pad[6]`. Succeeds iff
//! `pk.verify_prehash(digest, sig)`.

use alloc::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Node, NodePayload, NodeType, Precompile, PrecompileTag, ReduceCtx, SchemaError, TRUE_TAG,
        Tag, TagInfo, true_node,
    },
    serde::Deserializable,
};
use miden_crypto::dsa::ecdsa_k256_keccak::{
    PublicKey as EcdsaPublicKey, Signature as EcdsaSignature,
};

use super::codec::{BYTES_PER_CHUNK, chunks_to_bytes};

/// Zero-sized handle for the `ecdsa_k256_keccak` precompile app.
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaK256KeccakPrecompile;

impl EcdsaK256KeccakPrecompile {
    pub const NAME: &'static str = "ecdsa_k256_keccak";
    pub const VERSION: u32 = 1;

    pub const D_VERIFY: Felt = Felt::new_unchecked(0);

    /// Bytes-per-field-component: pk=33, digest=32, sig=65.
    ///
    /// Each component is placed at a word-aligned felt boundary inside the chunk so MASM can
    /// store each piece with `loc_storew_le.N` (N divisible by 4):
    ///   felts[0..9]    pk      → bytes[0..33] real + bytes[33..36] zero pad inside felt[8]
    ///   felts[9..12]   zero    → bytes[36..48] zero pad (aligns digest to felt[12])
    ///   felts[12..20]  digest  → bytes[48..80]
    ///   felts[20..37]  sig     → bytes[80..145] real + bytes[145..148] zero pad inside felt[36]
    ///   felts[37..40]  zero    → bytes[148..160] trailing zero pad
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

    pub fn app_id() -> Felt {
        Felt::new_unchecked(11_898_598_695_480_032_786)
    }

    pub fn verify_tag() -> Tag {
        [Self::app_id(), Self::D_VERIFY, ZERO, ZERO]
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

    fn version(&self) -> u32 {
        Self::VERSION
    }

    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, sub: PrecompileTag) -> Result<TagInfo, SchemaError> {
        let [disc, imm, reserved] = sub.0;
        if reserved != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        match disc {
            d if d == Self::D_VERIFY => {
                if imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                // pk[9] || digest[8] || sig[17] || pad[6] = 40 felts = 5 chunks.
                Ok(TagInfo { node_type: NodeType::Chunks(5), evaluates_to: TRUE_TAG })
            },
            _ => Err(SchemaError::InvalidNode),
        }
    }

    fn reduce(&self, node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() || node.tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        match node.tag[1] {
            d if d == Self::D_VERIFY => reduce_verify(node),
            _ => Err(SchemaError::InvalidNode),
        }
    }
}

/// Reduce a `verify` chunk predicate. See `EcdsaK256KeccakPrecompile::*_BYTES` constants for the
/// chunk byte layout. Validates all pad regions are zero, deserialises pk/digest/sig via
/// `miden-crypto`, runs `PublicKey::verify_prehash`.
fn reduce_verify(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let chunks = match &node.payload {
        NodePayload::Chunk(c) if c.len() == 5 => c,
        _ => return Err(SchemaError::InvalidNode),
    };
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
        return Err(SchemaError::InvalidNode);
    }
    if bytes[sig_end..].iter().any(|&b| b != 0) {
        return Err(SchemaError::InvalidNode);
    }

    let pk = EcdsaPublicKey::read_from_bytes(&bytes[..pk_end])
        .map_err(|_| SchemaError::AssertionFailed)?;
    let digest: [u8; 32] = bytes[digest_start..digest_end]
        .try_into()
        .expect("DIGEST_BYTES sliced to 32 bytes");
    let sig = EcdsaSignature::read_from_bytes(&bytes[sig_start..sig_end])
        .map_err(|_| SchemaError::AssertionFailed)?;

    if pk.verify_prehash(digest, &sig) {
        Ok(true_node())
    } else {
        Err(SchemaError::AssertionFailed)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        deferred::{DeferredState, PrecompileSchema},
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

    fn fresh_state() -> (PrecompileSchema, DeferredState) {
        (PrecompileSchema::single(EcdsaK256KeccakPrecompile), DeferredState::new())
    }

    #[test]
    fn decode_verify_is_5_chunk_predicate() {
        let info = EcdsaK256KeccakPrecompile
            .decode(PrecompileTag([EcdsaK256KeccakPrecompile::D_VERIFY, ZERO, ZERO]))
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Chunks(5)));
        assert_eq!(info.evaluates_to, TRUE_TAG);
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
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let chunks = pack_ecdsa(&pk_bytes, &digest, &sig_bytes);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let result = state.evaluate(&schema, node).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, mut sig_bytes) = ecdsa_keypair_and_sig(digest);
        sig_bytes[0] ^= 0xff;
        let chunks = pack_ecdsa(&pk_bytes, &digest, &sig_bytes);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn verify_fails_on_tampered_digest() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0xff;
        let chunks = pack_ecdsa(&pk_bytes, &wrong_digest, &sig_bytes);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn verify_rejects_nonzero_padding_after_pk() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(&pk_bytes);
        buf[40] = 0xaa; // in the pad region
        buf[48..80].copy_from_slice(&digest);
        buf[80..145].copy_from_slice(&sig_bytes);
        let chunks = pack_chunks(&buf);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn verify_rejects_nonzero_trailing_padding() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut buf = vec![0u8; 160];
        buf[0..33].copy_from_slice(&pk_bytes);
        buf[48..80].copy_from_slice(&digest);
        buf[80..145].copy_from_slice(&sig_bytes);
        buf[150] = 0xaa;
        let chunks = pack_chunks(&buf);
        let node = EcdsaK256KeccakPrecompile::verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }
}
