//! `MockSig` — single chunk-bodied predicate [`App`] that mirrors the legacy "signature is an
//! opaque chunk that evaluates to TRUE" pattern in the smallest possible form.
//!
//! A `verify` node is a chunk-bodied predicate carrying a fixed-size opaque payload
//! (`SIG_CHUNKS = 3` chunks, conceptually `sig || pk || msg`). The chunk count is hardcoded per
//! discriminant — no immediate. Reduce performs a stub check: succeeds iff the very first felt
//! of the first chunk is non-zero, mirroring the shape of "this signature isn't an all-zero
//! placeholder." Real `Ecdsa`/`Eddsa` apps would slot in by swapping the stub for a non-native
//! verification kernel.

use crate::{
    Felt, ZERO,
    deferred::{
        Node, NodePayload, NodeType, ReduceCtx, SchemaError, TRUE_TAG, Tag, TagInfo, true_node,
    },
};

use super::{App, AppTag, app_id_from};

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `MockSig` app.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockSig;

impl MockSig {
    pub const NAME: &'static str = "mock_sig";
    pub const VERSION: u32 = 1;
    pub const DISCS: &'static [&'static str] = &["verify"];

    pub const D_VERIFY: Felt = Felt::new_unchecked(0);

    /// Number of 8-felt chunks in a mock signature blob. Hardcoded — there is no immediate, so
    /// the framework derives the chunk count from this constant at `decode` time.
    pub const SIG_CHUNKS: u32 = 3;

    pub fn app_id() -> Felt {
        app_id_from(Self::NAME, Self::VERSION, &[], Self::DISCS)
    }

    pub fn verify_tag() -> Tag {
        [Self::app_id(), Self::D_VERIFY, ZERO, ZERO]
    }

    /// Build a `verify` predicate node from `SIG_CHUNKS` 8-felt chunks.
    pub fn verify_node(chunks: impl Into<alloc::sync::Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::verify_tag(), chunks)
    }
}

impl App for MockSig {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        if local.imm != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        match Discriminant::classify(local.node_disc).ok_or(SchemaError::InvalidNode)? {
            Discriminant::Verify => Ok(TagInfo {
                node_type: NodeType::Chunks(Self::SIG_CHUNKS),
                evaluates_to: TRUE_TAG,
            }),
        }
    }

    fn reduce(&self, node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag != Self::verify_tag() {
            return Err(SchemaError::InvalidNode);
        }
        match &node.payload {
            NodePayload::Chunk(chunks) => {
                if chunks.len() != Self::SIG_CHUNKS as usize {
                    return Err(SchemaError::InvalidNode);
                }
                // Stub check: signature passes iff the first felt of the first chunk is non-zero.
                // Stand-in for "this isn't a zeroed-out placeholder signature."
                if chunks[0][0] == ZERO {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
            NodePayload::Expression(_) => Err(SchemaError::InvalidNode),
        }
    }
}

// TYPED DISCRIMINANT
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Verify,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Verify),
            _ => None,
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{DeferredState, PrecompileSchema};

    fn non_zero_chunks() -> [[Felt; 8]; 3] {
        [
            [Felt::from_u32(1); 8],
            [Felt::from_u32(2); 8],
            [Felt::from_u32(3); 8],
        ]
    }

    #[test]
    fn decode_verify_is_chunk3_predicate() {
        let info = MockSig
            .decode(AppTag { node_disc: MockSig::D_VERIFY, imm: ZERO })
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Chunks(3)));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_rejects_imm() {
        let err = MockSig
            .decode(AppTag { node_disc: MockSig::D_VERIFY, imm: Felt::from_u32(1) });
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn decode_unknown_discriminant_rejected() {
        let err = MockSig.decode(AppTag { node_disc: Felt::from_u32(1), imm: ZERO });
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn verify_passes_when_first_felt_nonzero() {
        let schema = PrecompileSchema::single(MockSig);
        let mut state = DeferredState::new();
        let node = MockSig::verify_node(non_zero_chunks().to_vec());
        let result = state.evaluate(&schema, node).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn verify_fails_when_first_felt_is_zero() {
        let schema = PrecompileSchema::single(MockSig);
        let mut state = DeferredState::new();
        let mut chunks = non_zero_chunks();
        chunks[0][0] = ZERO;
        let node = MockSig::verify_node(chunks.to_vec());
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn verify_with_wrong_chunk_count_rejected() {
        // Hand-built chunk node with the wrong number of chunks. Register's
        // payload_matches_body check catches this before reduce ever runs.
        let schema = PrecompileSchema::single(MockSig);
        let mut state = DeferredState::new();
        let too_few = vec![[Felt::from_u32(1); 8], [Felt::from_u32(2); 8]];
        let node = Node::chunk(MockSig::verify_tag(), too_few);
        let err = state.register(&schema, node);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }
}
