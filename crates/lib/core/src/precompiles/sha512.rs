//! SHA-512 precompile app.
//!
//! Discriminants:
//! - `preimage` (chunk-bodied): `imm = n_bytes`; chunks carry the preimage. Reduces to a
//!   `digest` chunk leaf (16 felts = 2 chunks).
//! - `digest` (`Chunks(2)` self-eval): 16-felt digest leaf.
//! - `eq` (binary predicate): compares two `digest` children.

use alloc::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodePayload, NodeType, Payload, Precompile, PrecompileTag, ReduceCtx,
        SchemaError, TRUE_TAG, Tag, TagInfo, true_node,
    },
};
use miden_crypto::hash::sha2::Sha512;

use super::codec::{chunks_to_bytes, n_chunks};

/// Zero-sized handle for the `sha512` precompile app.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512Precompile;

impl Sha512Precompile {
    pub const NAME: &'static str = "sha512";
    pub const VERSION: u32 = 1;

    pub const D_PREIMAGE: Felt = Felt::new_unchecked(0);
    pub const D_DIGEST: Felt = Felt::new_unchecked(1);
    pub const D_EQ: Felt = Felt::new_unchecked(2);

    pub fn app_id() -> Felt {
        Felt::new_unchecked(5_915_489_169_965_270_201)
    }

    pub fn preimage_tag(n_bytes: u32) -> Tag {
        [Self::app_id(), Self::D_PREIMAGE, Felt::from_u32(n_bytes), ZERO]
    }

    pub fn digest_tag() -> Tag {
        [Self::app_id(), Self::D_DIGEST, ZERO, ZERO]
    }

    pub fn eq_tag() -> Tag {
        [Self::app_id(), Self::D_EQ, ZERO, ZERO]
    }

    pub fn preimage_node(n_bytes: u32, chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `digest` chunk leaf from the 16-felt u32-packed digest.
    pub fn digest_node(felts: [Felt; 16]) -> Node {
        let chunks = [
            core::array::from_fn(|i| felts[i]),
            core::array::from_fn(|i| felts[8 + i]),
        ];
        Node::chunk(Self::digest_tag(), chunks.to_vec())
    }

    pub fn eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::expression(Self::eq_tag(), Payload::binary_op(lhs, rhs))
    }
}

impl Precompile for Sha512Precompile {
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
                // 64-byte SHA-512 digest packed as 16 u32 felts → 2 chunks of 8 felts.
                Ok(TagInfo { node_type: NodeType::Chunks(2), evaluates_to: Self::digest_tag() })
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

fn reduce_preimage(node: &Node) -> Result<Node, SchemaError> {
    let n_bytes =
        u32::try_from(node.tag[2].as_canonical_u64()).map_err(|_| SchemaError::InvalidNode)?
            as usize;
    let chunks = match &node.payload {
        NodePayload::Chunk(c) => c,
        NodePayload::Expression(_) => return Err(SchemaError::InvalidNode),
    };
    let bytes = chunks_to_bytes(chunks, n_bytes)?;
    let digest_bytes = Sha512::hash(&bytes);
    Ok(Sha512Precompile::digest_node(bytes64_to_felts(&digest_bytes)))
}

fn reduce_digest(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    match &node.payload {
        NodePayload::Chunk(c) if c.len() == 2 => Ok(node.clone()),
        _ => Err(SchemaError::InvalidNode),
    }
}

fn reduce_eq(node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
    let (lhs_digest, rhs_digest) = payload.binary_op_children();
    let lhs = ctx.resolve(lhs_digest)?;
    let rhs = ctx.resolve(rhs_digest)?;
    if lhs.tag != Sha512Precompile::digest_tag() || rhs.tag != Sha512Precompile::digest_tag() {
        return Err(SchemaError::InvalidNode);
    }
    let (lhs_chunks, rhs_chunks) = match (&lhs.payload, &rhs.payload) {
        (NodePayload::Chunk(l), NodePayload::Chunk(r)) => (l, r),
        _ => return Err(SchemaError::InvalidNode),
    };
    if lhs_chunks.as_ref() != rhs_chunks.as_ref() {
        return Err(SchemaError::AssertionFailed);
    }
    Ok(true_node())
}

/// Pack 64 contiguous bytes into 16 u32-packed-LE felts. Panics if `bytes.len() != 64` — used
/// for sha512's 512-bit digest.
pub(super) fn bytes64_to_felts(bytes: &[u8]) -> [Felt; 16] {
    assert_eq!(bytes.len(), 64, "sha512 digest must be 64 bytes");
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        deferred::{DeferredState, PrecompileSchema},
        utils::bytes_to_packed_u32_elements,
    };

    use super::*;

    #[test]
    fn decode_preimage_carries_n_bytes_in_imm() {
        let info = Sha512Precompile
            .decode(PrecompileTag([Sha512Precompile::D_PREIMAGE, Felt::from_u32(100), ZERO]))
            .unwrap();
        // 100 bytes → ceil(100/32) = 4 chunks.
        assert!(matches!(info.node_type, NodeType::Chunks(4)));
        assert_eq!(info.evaluates_to, Sha512Precompile::digest_tag());
    }

    #[test]
    fn decode_digest_is_2_chunk_self_eval() {
        let info = Sha512Precompile
            .decode(PrecompileTag([Sha512Precompile::D_DIGEST, ZERO, ZERO]))
            .unwrap();
        // 64-byte digest = 16 u32 felts = 2 chunks of 8.
        assert!(matches!(info.node_type, NodeType::Chunks(2)));
        assert_eq!(info.evaluates_to, Sha512Precompile::digest_tag());
    }

    #[test]
    fn decode_eq_is_binary_predicate() {
        let info = Sha512Precompile
            .decode(PrecompileTag([Sha512Precompile::D_EQ, ZERO, ZERO]))
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Binary));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(8);
        let mut padded = felts;
        padded.resize(n_chunks * 8, ZERO);
        padded.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn fresh_state() -> (PrecompileSchema, DeferredState) {
        (PrecompileSchema::single(Sha512Precompile), DeferredState::new())
    }

    fn sha512_known(input: &[u8]) -> Node {
        let digest_bytes = Sha512::hash(input);
        Sha512Precompile::digest_node(bytes64_to_felts(&digest_bytes))
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_empty() {
        let (schema, mut state) = fresh_state();
        let expected = sha512_known(&[]);
        let node = Sha512Precompile::preimage_node(0, Vec::new());
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_short() {
        let (schema, mut state) = fresh_state();
        let bytes = b"hello world";
        let expected = sha512_known(bytes);
        let chunks = pack_chunks(bytes);
        let node = Sha512Precompile::preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_multi_chunk() {
        let (schema, mut state) = fresh_state();
        let bytes: Vec<u8> = (0u8..100).collect();
        let expected = sha512_known(&bytes);
        let chunks = pack_chunks(&bytes);
        let node = Sha512Precompile::preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn digest_leaf_is_self_evaluating() {
        let (schema, mut state) = fresh_state();
        let felts: [Felt; 16] = core::array::from_fn(|i| Felt::from_u32(i as u32));
        let leaf = Sha512Precompile::digest_node(felts);
        let leaf_digest = state.register(&schema, leaf.clone()).unwrap();
        let canonical = state
            .evaluate(&schema, state.get(&leaf_digest).unwrap().clone())
            .unwrap();
        assert_eq!(canonical, leaf);
    }

    #[test]
    fn eq_succeeds_on_matching_preimage_and_digest() {
        let (schema, mut state) = fresh_state();
        let bytes = b"some sha512 input";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, Sha512Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let leaf_digest = state.register(&schema, sha512_known(bytes)).unwrap();
        let eq = Sha512Precompile::eq_node(preimage_digest, leaf_digest);
        let result = state.evaluate(&schema, eq).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn eq_fails_on_mismatched_digest_claim() {
        let (schema, mut state) = fresh_state();
        let bytes = b"a";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, Sha512Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let wrong_leaf = Sha512Precompile::digest_node([Felt::from_u32(0xdead); 16]);
        let wrong_digest = state.register(&schema, wrong_leaf).unwrap();
        let eq = Sha512Precompile::eq_node(preimage_digest, wrong_digest);
        let err = state.evaluate(&schema, eq);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }
}
