//! `MockHash` — chunk-bodied preimage → expression-bodied digest leaf [`App`].
//!
//! Exercises chunk-bodied inputs and the chunk-to-expression reduction shape without
//! introducing a real hash implementation. The "hash" is a coordinate-wise sum of all preimage
//! chunks into an 8-felt accumulator — deterministic, trivially testable, definitely not
//! collision-resistant. A real `Keccak` / `Sha512` app would slot in by swapping the kernel.
//!
//! Tag layout (`MockHash`-specific, opaque to the framework):
//!
//! ```text
//! [app_id, node_disc, imm, ZERO]
//! ```
//!
//! - `preimage` (disc 0) — chunk-bodied; `imm = n_bytes`; body is `Chunk(ceil(n_bytes / 32))`.
//!   Reduces to a `digest` leaf.
//! - `digest`   (disc 1) — expression-bodied (8-felt digest); self-evaluating.
//! - `eq`       (disc 2) — expression-bodied predicate over two child digests.

use crate::{
    Felt, ZERO,
    deferred::{
        DeferredError, Digest, Node, NodePayload, NodeType, Payload, ReduceCtx, SchemaError,
        TRUE_TAG, Tag, TagInfo, true_node,
    },
};

use super::{App, AppTag, app_id_from};

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `MockHash` app.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockHash;

impl MockHash {
    pub const NAME: &'static str = "mock_hash";
    pub const VERSION: u32 = 1;
    pub const DISCS: &'static [&'static str] = &["preimage", "digest", "eq"];

    pub const D_PREIMAGE: Felt = Felt::new_unchecked(0);
    pub const D_DIGEST: Felt = Felt::new_unchecked(1);
    pub const D_EQ: Felt = Felt::new_unchecked(2);

    /// Bytes packed per 8-felt chunk: each felt carries a u32 (4 bytes) little-endian limb.
    pub const BYTES_PER_CHUNK: u32 = 32;

    pub fn app_id() -> Felt {
        app_id_from(Self::NAME, Self::VERSION, &[], Self::DISCS)
    }

    /// Tag of a `preimage` chunk node for a `n_bytes`-byte payload.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        [Self::app_id(), Self::D_PREIMAGE, Felt::from_u32(n_bytes), ZERO]
    }

    /// Tag of a canonical `digest` leaf.
    pub fn digest_tag() -> Tag {
        [Self::app_id(), Self::D_DIGEST, ZERO, ZERO]
    }

    /// Tag of an `eq` predicate node.
    pub fn eq_tag() -> Tag {
        [Self::app_id(), Self::D_EQ, ZERO, ZERO]
    }

    /// Build a `preimage` chunk node from caller-supplied 8-felt chunks. The caller is
    /// responsible for zero-padding the last chunk to `BYTES_PER_CHUNK` and for matching
    /// `chunks.len() == ceil(n_bytes / BYTES_PER_CHUNK)`.
    pub fn preimage_node(n_bytes: u32, chunks: impl Into<alloc::sync::Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `digest` leaf from 8 felts.
    pub fn digest_node(felts: [Felt; 8]) -> Node {
        Node::expression(Self::digest_tag(), Payload::new(felts))
    }

    /// Build an `eq` predicate over two child digests.
    pub fn eq_node(h_lhs: Digest, h_rhs: Digest) -> Node {
        Node::expression(Self::eq_tag(), Payload::binary_op(h_lhs, h_rhs))
    }

    /// Decode `[Felt; 8]` digest contents from a canonical `digest` leaf. Errors if `node`
    /// isn't tagged as a `MockHash` digest leaf.
    pub fn digest_felts(node: &Node) -> Result<[Felt; 8], DeferredError> {
        if node.tag != Self::digest_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(*node.expression_payload().ok_or(DeferredError::InvalidPayload)?.as_felts())
    }

    /// Mock hash kernel: coordinate-wise sum of all chunks. Not collision-resistant; placeholder
    /// for a real non-native hash.
    pub fn hash(chunks: &[[Felt; 8]]) -> [Felt; 8] {
        let mut acc = [ZERO; 8];
        for c in chunks {
            for (a, x) in acc.iter_mut().zip(c.iter()) {
                *a += *x;
            }
        }
        acc
    }

    /// Number of 8-felt chunks needed to encode `n_bytes` of input.
    pub fn n_chunks(n_bytes: u32) -> u32 {
        n_bytes.div_ceil(Self::BYTES_PER_CHUNK)
    }
}

impl App for MockHash {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        match Discriminant::classify(local.node_disc).ok_or(SchemaError::InvalidNode)? {
            Discriminant::Preimage => {
                // `imm` carries n_bytes; the chunk count is derived.
                let n_bytes = u32::try_from(local.imm.as_canonical_u64())
                    .map_err(|_| SchemaError::InvalidNode)?;
                Ok(TagInfo {
                    node_type: NodeType::Chunks(Self::n_chunks(n_bytes)),
                    evaluates_to: Self::digest_tag(),
                })
            },
            Discriminant::Digest => {
                // Self-evaluating leaf carrying 8 raw felts of digest data.
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo { node_type: NodeType::Value, evaluates_to: Self::digest_tag() })
            },
            Discriminant::Eq => {
                // Binary predicate over two child digests.
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo { node_type: NodeType::Binary, evaluates_to: TRUE_TAG })
            },
        }
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() || node.tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let kind = Discriminant::classify(node.tag[1]).ok_or(SchemaError::InvalidNode)?;
        match kind {
            Discriminant::Preimage => match &node.payload {
                NodePayload::Chunk(chunks) => {
                    // Inline hash → canonical digest leaf. No minting needed: the digest IS the
                    // canonical payload.
                    Ok(Self::digest_node(Self::hash(chunks)))
                },
                NodePayload::Expression(_) => Err(SchemaError::InvalidNode),
            },
            Discriminant::Digest => {
                if node.tag[2] != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(node.clone())
            },
            Discriminant::Eq => {
                if node.tag[2] != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
                let (h_lhs, h_rhs) = payload.binary_op_children();
                if ctx.resolve(h_lhs)? != ctx.resolve(h_rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// TYPED DISCRIMINANT
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Preimage,
    Digest,
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Preimage),
            1 => Some(Self::Digest),
            2 => Some(Self::Eq),
            _ => None,
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use super::*;
    use crate::deferred::{DeferredState, PrecompileSchema};

    fn chunk_data(n_chunks: u32) -> Vec<[Felt; 8]> {
        (0..n_chunks)
            .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
            .collect()
    }

    fn fresh() -> (PrecompileSchema, DeferredState) {
        let schema = PrecompileSchema::single(MockHash);
        (schema, DeferredState::new())
    }

    #[test]
    fn n_chunks_rounds_up() {
        assert_eq!(MockHash::n_chunks(0), 0);
        assert_eq!(MockHash::n_chunks(1), 1);
        assert_eq!(MockHash::n_chunks(31), 1);
        assert_eq!(MockHash::n_chunks(32), 1);
        assert_eq!(MockHash::n_chunks(33), 2);
        assert_eq!(MockHash::n_chunks(64), 2);
        assert_eq!(MockHash::n_chunks(65), 3);
    }

    #[test]
    fn decode_preimage_extracts_chunk_count_from_imm() {
        let info = MockHash.decode(AppTag {
            node_disc: MockHash::D_PREIMAGE,
            imm: Felt::from_u32(65),
        }).unwrap();
        assert!(matches!(info.node_type, NodeType::Chunks(3)));
        assert_eq!(info.evaluates_to, MockHash::digest_tag());
    }

    #[test]
    fn decode_digest_is_self_evaluating_value() {
        let info = MockHash
            .decode(AppTag { node_disc: MockHash::D_DIGEST, imm: ZERO })
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Value));
        assert_eq!(info.evaluates_to, MockHash::digest_tag());
    }

    #[test]
    fn decode_eq_is_binary_predicate() {
        let info = MockHash
            .decode(AppTag { node_disc: MockHash::D_EQ, imm: ZERO })
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Binary));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_unknown_discriminant_rejected() {
        let err = MockHash.decode(AppTag { node_disc: Felt::from_u32(99), imm: ZERO });
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn decode_rejects_imm_on_non_preimage() {
        let err = MockHash
            .decode(AppTag { node_disc: MockHash::D_DIGEST, imm: Felt::from_u32(1) });
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
        let err = MockHash
            .decode(AppTag { node_disc: MockHash::D_EQ, imm: Felt::from_u32(1) });
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn preimage_reduces_to_digest_leaf() {
        let (schema, mut state) = fresh();
        let chunks = chunk_data(2);
        let expected = MockHash::digest_node(MockHash::hash(&chunks));
        let node = MockHash::preimage_node(64, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
        assert!(state.contains(&expected.digest()));
    }

    #[test]
    fn digest_leaf_is_self_evaluating() {
        let (schema, mut state) = fresh();
        let leaf = MockHash::digest_node([Felt::from_u32(7); 8]);
        let h = state.register(&schema, leaf.clone()).unwrap();
        let canonical = state.evaluate(&schema, state.get(&h).unwrap().clone()).unwrap();
        assert_eq!(canonical, leaf);
    }

    #[test]
    fn eq_predicate_matches_preimage_against_known_digest() {
        let (schema, mut state) = fresh();
        let chunks = chunk_data(2);
        let known = MockHash::digest_node(MockHash::hash(&chunks));
        let h_known = state.register(&schema, known).unwrap();
        let h_preimage = state.register(&schema, MockHash::preimage_node(64, chunks)).unwrap();
        let result = state.evaluate(&schema, MockHash::eq_node(h_preimage, h_known)).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn eq_predicate_errors_on_mismatch() {
        let (schema, mut state) = fresh();
        let chunks = chunk_data(1);
        let wrong = MockHash::digest_node([Felt::from_u32(0xdead); 8]);
        let h_wrong = state.register(&schema, wrong).unwrap();
        let h_preimage = state.register(&schema, MockHash::preimage_node(32, chunks)).unwrap();
        let err = state.evaluate(&schema, MockHash::eq_node(h_preimage, h_wrong));
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn empty_preimage_reduces_to_zero_digest() {
        // n_bytes=0 means n_chunks=0; mock-hash of zero chunks is the zero accumulator.
        let (schema, mut state) = fresh();
        let node = MockHash::preimage_node(0, Vec::new());
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, MockHash::digest_node([ZERO; 8]));
    }

    #[test]
    fn composite_with_mock_hash_dispatches() {
        // Sanity: app_id-based routing works in a composite holding only MockHash.
        let schema = PrecompileSchema::new([Box::new(MockHash) as Box<dyn App>]);
        let mut state = DeferredState::new();
        let chunks = chunk_data(1);
        let canonical = state.evaluate(&schema, MockHash::preimage_node(32, chunks.clone())).unwrap();
        assert_eq!(canonical, MockHash::digest_node(MockHash::hash(&chunks)));
    }
}
