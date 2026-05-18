//! Keccak256 precompile app.
//!
//! Tag layout (per the composite [`PrecompileSchema`] convention):
//!
//! ```text
//! [APP_ID, node_disc, imm, ZERO]
//! ```
//!
//! Discriminants:
//! - `preimage` (chunk-bodied): `imm = n_bytes`; chunks carry the preimage u32-packed-LE.
//!   Reduces to a `digest` leaf with the actual hash.
//! - `digest` (value, 8 felts): self-evaluating digest leaf.
//! - `eq` (binary predicate): two `digest` children, succeeds iff equal.

use alloc::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodePayload, NodeType, Payload, Precompile, PrecompileTag, ReduceCtx,
        SchemaError, TRUE_TAG, Tag, TagInfo, true_node,
    },
};
use miden_crypto::hash::keccak::Keccak256;

use super::codec::{chunks_to_bytes, n_chunks};

/// Zero-sized handle for the `keccak256` precompile app.
#[derive(Debug, Default, Clone, Copy)]
pub struct Keccak256Precompile;

impl Keccak256Precompile {
    /// App name — hashed into `app_id`. Don't change without bumping [`Self::VERSION`].
    pub const NAME: &'static str = "keccak256";
    /// App version — bump on incompatible discriminant changes.
    pub const VERSION: u32 = 1;

    pub const D_PREIMAGE: Felt = Felt::new_unchecked(0);
    pub const D_DIGEST: Felt = Felt::new_unchecked(1);
    pub const D_EQ: Felt = Felt::new_unchecked(2);

    /// Derive `app_id`. Pure function over the app's metadata.
    pub fn app_id() -> Felt {
        Felt::new_unchecked(12_495_655_595_326_449_568)
    }

    /// Tag for a `preimage` chunk node for an `n_bytes`-byte payload.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        [Self::app_id(), Self::D_PREIMAGE, Felt::from_u32(n_bytes), ZERO]
    }

    /// Tag for the canonical `digest` leaf.
    pub fn digest_tag() -> Tag {
        [Self::app_id(), Self::D_DIGEST, ZERO, ZERO]
    }

    /// Tag for an `eq` predicate node.
    pub fn eq_tag() -> Tag {
        [Self::app_id(), Self::D_EQ, ZERO, ZERO]
    }

    /// Build a `preimage` chunk node from caller-supplied 8-felt chunks.
    ///
    /// The caller is responsible for u32-packing the preimage bytes (4 bytes per felt, LE) and
    /// for matching `chunks.len() == ceil(n_bytes / BYTES_PER_CHUNK)`. The schema reduce strips
    /// the trailing zero-pad bytes back down to `n_bytes` before hashing.
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
        Node::expression(Self::eq_tag(), Payload::binary_op(lhs, rhs))
    }
}

impl Precompile for Keccak256Precompile {
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
            d if d == Self::D_PREIMAGE => {
                let n_bytes = u32::try_from(imm.as_canonical_u64())
                    .map_err(|_| SchemaError::InvalidNode)?;
                Ok(TagInfo {
                    node_type: NodeType::Chunks(n_chunks(n_bytes)),
                    evaluates_to: Self::digest_tag(),
                })
            },
            d if d == Self::D_DIGEST => {
                if imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo { node_type: NodeType::Value, evaluates_to: Self::digest_tag() })
            },
            d if d == Self::D_EQ => {
                if imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo { node_type: NodeType::Binary, evaluates_to: TRUE_TAG })
            },
            _ => Err(SchemaError::InvalidNode),
        }
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() || node.tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        match node.tag[1] {
            d if d == Self::D_PREIMAGE => reduce_preimage(node),
            d if d == Self::D_DIGEST => reduce_digest(node),
            d if d == Self::D_EQ => reduce_eq(node, ctx),
            _ => Err(SchemaError::InvalidNode),
        }
    }
}

/// Reduce a `preimage` chunk node: unpack chunks to bytes (stripping zero-pad to `n_bytes`
/// carried in `tag[2]`), run `Keccak256::hash`, and emit the canonical `digest` leaf with the
/// result u32-packed.
fn reduce_preimage(node: &Node) -> Result<Node, SchemaError> {
    let n_bytes =
        u32::try_from(node.tag[2].as_canonical_u64()).map_err(|_| SchemaError::InvalidNode)?
            as usize;
    let chunks = match &node.payload {
        NodePayload::Chunk(c) => c,
        NodePayload::Expression(_) => return Err(SchemaError::InvalidNode),
    };
    let bytes = chunks_to_bytes(chunks, n_bytes)?;
    let digest_bytes = Keccak256::hash(&bytes);
    Ok(Keccak256Precompile::digest_node(bytes32_to_felts(&digest_bytes)))
}

/// Reduce a `digest` leaf — self-evaluating. The framework already validated `tag[2] == ZERO`
/// via `decode`; reduce just returns the node as canonical.
fn reduce_digest(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    // Confirm expression body shape — register-time validation already enforces this, but the
    // schema is a defense-in-depth surface.
    match &node.payload {
        NodePayload::Expression(_) => Ok(node.clone()),
        NodePayload::Chunk(_) => Err(SchemaError::InvalidNode),
    }
}

/// Reduce an `eq` binary predicate: resolve both children to their canonical forms, require both
/// to be `digest` leaves, and assert their payloads match.
fn reduce_eq(node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
    let (lhs_digest, rhs_digest) = payload.binary_op_children();
    let lhs = ctx.resolve(lhs_digest)?;
    let rhs = ctx.resolve(rhs_digest)?;
    if lhs.tag != Keccak256Precompile::digest_tag() || rhs.tag != Keccak256Precompile::digest_tag()
    {
        return Err(SchemaError::InvalidNode);
    }
    if lhs.expression_payload() != rhs.expression_payload() {
        return Err(SchemaError::AssertionFailed);
    }
    Ok(true_node())
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
        deferred::{DeferredState, PrecompileSchema},
        utils::bytes_to_packed_u32_elements,
    };

    use super::*;

    #[test]
    fn app_id_is_stable() {
        let a = Keccak256Precompile::app_id();
        let b = Keccak256Precompile::app_id();
        assert_eq!(a, b);
    }

    #[test]
    fn decode_preimage_carries_n_bytes_in_imm() {
        let info = Keccak256Precompile
            .decode(PrecompileTag([Keccak256Precompile::D_PREIMAGE, Felt::from_u32(65), ZERO]))
            .unwrap();
        // 65 bytes → ceil(65/32) = 3 chunks.
        assert!(matches!(info.node_type, NodeType::Chunks(3)));
        assert_eq!(info.evaluates_to, Keccak256Precompile::digest_tag());
    }

    #[test]
    fn decode_digest_is_self_evaluating_value() {
        let info = Keccak256Precompile
            .decode(PrecompileTag([Keccak256Precompile::D_DIGEST, ZERO, ZERO]))
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Value));
        assert_eq!(info.evaluates_to, Keccak256Precompile::digest_tag());
    }

    #[test]
    fn decode_eq_is_binary_predicate() {
        let info = Keccak256Precompile
            .decode(PrecompileTag([Keccak256Precompile::D_EQ, ZERO, ZERO]))
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Binary));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_unknown_discriminant_rejected() {
        let err = Keccak256Precompile
            .decode(PrecompileTag([Felt::from_u32(99), ZERO, ZERO]));
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn decode_rejects_imm_on_non_preimage_discs() {
        for disc in [Keccak256Precompile::D_DIGEST, Keccak256Precompile::D_EQ] {
            let err = Keccak256Precompile
                .decode(PrecompileTag([disc, Felt::from_u32(1), ZERO]));
            assert!(
                matches!(err, Err(SchemaError::InvalidNode)),
                "disc {} must reject non-zero imm",
                disc.as_canonical_u64()
            );
        }
    }

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(8);
        let mut padded = felts;
        padded.resize(n_chunks * 8, ZERO);
        padded.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn fresh_state() -> (PrecompileSchema, DeferredState) {
        (PrecompileSchema::single(Keccak256Precompile), DeferredState::new())
    }

    fn keccak_known(input: &[u8]) -> Node {
        let digest_bytes = Keccak256::hash(input);
        Keccak256Precompile::digest_node(bytes32_to_felts(&digest_bytes))
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_empty() {
        let (schema, mut state) = fresh_state();
        let expected = keccak_known(&[]);
        let node = Keccak256Precompile::preimage_node(0, Vec::new());
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
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn digest_leaf_is_self_evaluating() {
        let (schema, mut state) = fresh_state();
        let leaf = Keccak256Precompile::digest_node([Felt::from_u32(7); 8]);
        let leaf_digest = state.register(&schema, leaf.clone()).unwrap();
        let canonical = state
            .evaluate(&schema, state.get(&leaf_digest).unwrap().clone())
            .unwrap();
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
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
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
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }
}
