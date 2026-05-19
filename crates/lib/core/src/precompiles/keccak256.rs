//! Keccak256 precompile.
//!
//! Tag layout — `Tag { id, args: [node_disc, arg1, ZERO] }`:
//!
//! - `preimage` (disc 0, chunk-bodied): `arg1 = n_bytes`; chunks carry the preimage u32-packed-LE.
//!   Reduces to a `digest` leaf with the actual hash.
//! - `digest` (disc 1, value): self-evaluating 8-felt digest leaf (keccak output, u32-packed-LE).
//! - `eq` (disc 2, binary predicate): two `digest` children, succeeds iff equal.

use alloc::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder,
        precompile_id,
    },
};
use miden_crypto::hash::keccak::Keccak256;

use super::codec::{chunks_to_bytes, n_chunks};

/// Zero-sized handle for the `keccak256` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Keccak256Precompile;

impl Keccak256Precompile {
    /// Precompile name — hashed into `id`. Renaming breaks decoding for existing programs.
    pub const NAME: &'static str = "keccak256";

    pub const PREIMAGE_TAG_ID: u32 = 0;
    pub const DIGEST_TAG_ID: u32 = 1;
    pub const EQ_TAG_ID: u32 = 2;

    /// Derive the precompile id. Pure function over the metadata.
    pub fn id() -> Felt {
        precompile_id(&Keccak256Precompile)
    }

    /// Tag for a `preimage` chunk node for an `n_bytes`-byte payload.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::PREIMAGE_TAG_ID), Felt::from_u32(n_bytes), ZERO],
        }
    }

    /// Tag for the canonical `digest` leaf.
    pub fn digest_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::DIGEST_TAG_ID), ZERO, ZERO],
        }
    }

    /// Tag for an `eq` predicate node.
    pub fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a `preimage` chunk node from caller-supplied 8-felt chunks.
    ///
    /// The caller is responsible for u32-packing the preimage bytes (4 bytes per felt, LE) and
    /// for matching `chunks.len() == ceil(n_bytes / BYTES_PER_CHUNK)`. The reduce strips the
    /// trailing zero-pad bytes back down to `n_bytes` before hashing.
    pub fn preimage_node(n_bytes: u32, chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `digest` leaf from 8 u32-packed felts (the keccak hash output,
    /// little-endian).
    pub fn digest_node(felts: [Felt; 8]) -> Node {
        Node::expression(Self::digest_tag(), Payload::new(felts))
    }

    /// Build an `eq` predicate over two child digests.
    pub fn eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::expression(Self::eq_tag(), Payload::join(lhs, rhs))
    }
}

impl Precompile for Keccak256Precompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let disc = u32::try_from(args[0].as_canonical_u64()).ok()?;
        match disc {
            Self::PREIMAGE_TAG_ID => {
                let n_bytes = u32::try_from(args[1].as_canonical_u64()).ok()?;
                Some(NodeType::Chunks(n_chunks(n_bytes)))
            },
            Self::DIGEST_TAG_ID => Some(NodeType::Value),
            Self::EQ_TAG_ID => Some(NodeType::Join),
            _ => None,
        }
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let disc =
            u32::try_from(args[0].as_canonical_u64()).map_err(|_| PrecompileError::InvalidNode)?;
        match disc {
            Self::PREIMAGE_TAG_ID => reduce_preimage(args, payload),
            Self::DIGEST_TAG_ID => {
                Ok(Node::expression(Tag::new(Self::id(), args), Payload::new(*payload.as_felts()?)))
            },
            Self::EQ_TAG_ID => reduce_eq(payload, witness),
            _ => Err(PrecompileError::InvalidNode),
        }
    }
}

/// Reduce a `preimage` chunk node: unpack chunks to bytes (stripping zero-pad to `n_bytes`
/// carried in `args[1]`), run `Keccak256::hash`, and emit the canonical `digest` leaf with the
/// result u32-packed.
fn reduce_preimage(args: [Felt; 3], payload: &Payload) -> Result<Node, PrecompileError> {
    let n_bytes = u32::try_from(args[1].as_canonical_u64())
        .map_err(|_| PrecompileError::InvalidNode)? as usize;
    let bytes = chunks_to_bytes(payload.as_chunks()?, n_bytes)?;
    let digest_bytes = Keccak256::hash(&bytes);
    Ok(Keccak256Precompile::digest_node(bytes32_to_felts(&digest_bytes)))
}

/// Reduce an `eq` binary predicate: resolve both children to their canonical forms, require both
/// to be `digest` leaves, and assert their payloads match.
fn reduce_eq(payload: &Payload, witness: &mut WitnessBuilder<'_>) -> Result<Node, PrecompileError> {
    let (lhs_digest, rhs_digest) = payload.join_children()?;
    let lhs = witness.resolve(lhs_digest)?;
    let rhs = witness.resolve(rhs_digest)?;
    if lhs.tag != Keccak256Precompile::digest_tag() || rhs.tag != Keccak256Precompile::digest_tag()
    {
        return Err(PrecompileError::InvalidNode);
    }
    if lhs.payload.as_felts()? != rhs.payload.as_felts()? {
        return Err(PrecompileError::AssertionFailed);
    }
    Ok(Node::TRUE)
}

/// Pack 32 contiguous bytes into 8 u32-packed-LE felts. Panics if `bytes.len() != 32` — used
/// for keccak's fixed 256-bit digest.
pub(super) fn bytes32_to_felts(bytes: &[u8]) -> [Felt; 8] {
    assert_eq!(bytes.len(), 32, "keccak digest must be 32 bytes");
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        Word,
        deferred::{DeferredState, PrecompileRegistry},
        utils::bytes_to_packed_u32_elements,
    };

    use super::*;

    #[test]
    fn id_is_stable() {
        let a = Keccak256Precompile::id();
        let b = Keccak256Precompile::id();
        assert_eq!(a, b);
    }

    #[test]
    fn decode_preimage_carries_n_bytes_in_args() {
        let info = Keccak256Precompile
            .decode([
                Felt::from_u32(Keccak256Precompile::PREIMAGE_TAG_ID),
                Felt::from_u32(65),
                ZERO,
            ])
            .unwrap();
        // 65 bytes → ceil(65/32) = 3 chunks.
        assert!(matches!(info, NodeType::Chunks(n) if n.get() == 3));
    }

    #[test]
    fn decode_digest_is_self_evaluating_value() {
        let info = Keccak256Precompile
            .decode([Felt::from_u32(Keccak256Precompile::DIGEST_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Value));
    }

    #[test]
    fn decode_eq_is_binary_predicate() {
        let info = Keccak256Precompile
            .decode([Felt::from_u32(Keccak256Precompile::EQ_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Join));
    }

    #[test]
    fn decode_unknown_discriminant_rejected() {
        let info = Keccak256Precompile.decode([Felt::from_u32(99), ZERO, ZERO]);
        assert!(info.is_none());
    }

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(8);
        let mut padded = felts;
        padded.resize(n_chunks * 8, ZERO);
        padded.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn fresh_state() -> (PrecompileRegistry, DeferredState) {
        (
            PrecompileRegistry::default().with_precompile(Keccak256Precompile),
            DeferredState::new(),
        )
    }

    fn keccak_known(input: &[u8]) -> Node {
        let digest_bytes = Keccak256::hash(input);
        Keccak256Precompile::digest_node(bytes32_to_felts(&digest_bytes))
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_empty() {
        let (schema, mut state) = fresh_state();
        let expected = keccak_known(&[]);
        // Empty input still needs one chunk (empty chunk bodies are banned); a 0-byte preimage is
        // a single zero chunk.
        let node = Keccak256Precompile::preimage_node(0, vec![[ZERO; 8]]);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_short() {
        let (schema, mut state) = fresh_state();
        let bytes = b"hello world";
        let expected = keccak_known(bytes);
        let chunks = pack_chunks(bytes);
        let node = Keccak256Precompile::preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_multi_chunk() {
        let (schema, mut state) = fresh_state();
        let bytes: Vec<u8> = (0u8..70).collect();
        let expected = keccak_known(&bytes);
        let chunks = pack_chunks(&bytes);
        assert_eq!(chunks.len(), 3, "70 bytes should pack into 3 chunks");
        let node = Keccak256Precompile::preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_rejects_oversized_n_bytes_for_chunk_count() {
        let (schema, mut state) = fresh_state();
        let chunks = vec![[Felt::from_u32(0); 8]];
        let node = Keccak256Precompile::preimage_node(100, chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::InvalidNode));
    }

    #[test]
    fn digest_leaf_is_self_evaluating() {
        let (schema, mut state) = fresh_state();
        let leaf = Keccak256Precompile::digest_node([Felt::from_u32(7); 8]);
        let leaf_digest = state.register(&schema, leaf.clone()).unwrap();
        let canonical = state.evaluate(&schema, state.get(&leaf_digest).unwrap().clone()).unwrap();
        assert_eq!(canonical, leaf);
    }

    #[test]
    fn eq_succeeds_on_matching_preimage_and_digest() {
        let (schema, mut state) = fresh_state();
        let bytes = b"test vector for eq";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, Keccak256Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let known_leaf = keccak_known(bytes);
        let leaf_digest = state.register(&schema, known_leaf).unwrap();
        let eq = Keccak256Precompile::eq_node(preimage_digest, leaf_digest);
        let result = state.evaluate(&schema, eq).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn eq_fails_on_mismatched_digest_claim() {
        let (schema, mut state) = fresh_state();
        let bytes = b"data";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, Keccak256Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let wrong_leaf = Keccak256Precompile::digest_node([Felt::from_u32(0xdead); 8]);
        let wrong_digest = state.register(&schema, wrong_leaf).unwrap();
        let eq = Keccak256Precompile::eq_node(preimage_digest, wrong_digest);
        let err = state.evaluate(&schema, eq);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    #[test]
    fn eq_missing_child_surfaces() {
        let (schema, mut state) = fresh_state();
        let bytes = b"x";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, Keccak256Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let dangling = Word::new([Felt::from_u32(0xdead); 4]);
        let eq = Keccak256Precompile::eq_node(preimage_digest, dangling);
        let err = state.evaluate(&schema, eq);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::MissingNode));
    }
}
